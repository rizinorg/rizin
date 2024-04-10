// SPDX-FileCopyrightText: 2022-2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define GO_MAX_STRING_SIZE 0x4000
#define GO_MAX_TABLE_SIZE  0x10000

#define GO_1_2  (12)
#define GO_1_16 (116)
#define GO_1_18 (118)
#define GO_1_20 (120)

#define IS_GOPCLNTAB_1_2_LE(x)  (x[0] == 0xfb && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_2_BE(x)  (x[3] == 0xfb && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_16_LE(x) (x[0] == 0xfa && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_16_BE(x) (x[3] == 0xfa && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_18_LE(x) (x[0] == 0xf0 && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_18_BE(x) (x[3] == 0xf0 && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_20_LE(x) (x[0] == 0xf1 && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_20_BE(x) (x[3] == 0xf1 && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)

typedef struct go_pc_line_table_t {
	RzIO *io;
	ut64 vaddr;
	ut32 size;
	ut16 version;
	bool big_endian;
	ut64 text_start;
	// quantum is the min instruction size for the program counter.
	// i386: 1, amd64: 1, wasm: 1, s390x: 2, arm: 4, arm64: 4, mips: 4, mips: 4, ppc: 4, riscv: 4
	ut32 quantum;
	ut32 ptrsize;
	ut32 nfunctab;
	ut32 nfiletab;
	ut32 functabsize;
	// data offsets
	ut64 funcnametab;
	ut64 cutab;
	ut64 filetab;
	ut64 pctab;
	ut64 funcdata;
	ut64 functab;
} GoPcLnTab;

typedef struct go_string_recover_t {
	RzCore *core;
	ut64 pc;
	ut8 *bytes;
	ut32 size;
	ut32 n_recovered;
} GoStrRecover;

typedef struct go_string_info_t {
	ut64 addr;
	ut64 size;
	ut64 xref;
} GoStrInfo;

typedef struct go_asm_pattern_t {
	const ut8 *pattern;
	const ut8 *mask;
	ut32 size;
	bool xrefs;
} GoAsmPattern;

typedef bool (*GoDecodeCb)(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size);

typedef struct go_signature_t {
	GoAsmPattern *pasm;
	GoDecodeCb decode;
} GoSignature;

typedef ut32 (*GoStrRecoverCb)(GoStrRecover *ctx);

ut32 go_func_tab_field_size(GoPcLnTab *pclntab) {
	if (pclntab->version >= GO_1_18) {
		return 4;
	}
	return pclntab->ptrsize;
}

ut64 go_uintptr(GoPcLnTab *pclntab, ut8 *bytes) {
	if (pclntab->ptrsize == 4) {
		return rz_read_ble32(bytes, pclntab->big_endian);
	}
	return rz_read_ble64(bytes, pclntab->big_endian);
}

ut64 go_offset(GoPcLnTab *pclntab, ut32 n_word) {
	ut8 bytes[8];
	ut64 location = pclntab->vaddr + 8 + (n_word * pclntab->ptrsize);
	if (0 > rz_io_nread_at(pclntab->io, location, bytes, sizeof(bytes))) {
		return UT64_MAX;
	}
	return go_uintptr(pclntab, bytes);
}

ut64 go_data(GoPcLnTab *pclntab, ut32 n_word) {
	ut64 offset = go_offset(pclntab, n_word);
	if (offset == UT64_MAX) {
		return UT64_MAX;
	}
	return pclntab->vaddr + offset;
}

static const char *pclntab_version_str(GoPcLnTab *pclntab) {
	switch (pclntab->version) {
	case GO_1_2:
		return "go 1.2";
	case GO_1_16:
		return "go 1.16-1.17";
	case GO_1_18:
		return "go 1.18-1.19";
	case GO_1_20:
		return "go 1.20+";
	default:
		return "go unknown";
	}
}

#define is_addr_outside(x) ((x) <= begin || (x) >= end)
static bool is_pclntab_valid(GoPcLnTab *pclntab) {
	ut64 begin = pclntab->vaddr + 8;
	ut64 end = pclntab->vaddr + pclntab->size;

	if (pclntab->version > GO_1_2) {
		if (is_addr_outside(pclntab->funcnametab)) {
			return false;
		} else if (is_addr_outside(pclntab->cutab)) {
			return false;
		} else if (is_addr_outside(pclntab->pctab)) {
			return false;
		} else if (is_addr_outside(pclntab->funcdata)) {
			return false;
		}
	}

	if (pclntab->version >= GO_1_18 && !pclntab->text_start) {
		return false;
	}

	if (is_addr_outside(pclntab->filetab)) {
		return false;
	} else if (is_addr_outside(pclntab->functab)) {
		return false;
	} else if (pclntab->functabsize >= (pclntab->size - 8)) {
		return false;
	}

	return true;
}
#undef is_addr_outside

static void add_new_func_symbol(RzCore *core, const char *name, ut64 vaddr) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->symbols) {
		return;
	}
	ut64 paddr = rz_io_v2p(core->io, vaddr);
	RzBinSymbol *symbol = rz_bin_symbol_new(name, paddr, vaddr);
	if (!symbol) {
		RZ_LOG_ERROR("Failed allocate new go symbol\n");
		return;
	}

	symbol->bind = RZ_BIN_BIND_GLOBAL_STR;
	symbol->type = RZ_BIN_TYPE_FUNC_STR;
	if (!rz_pvector_push(bf->o->symbols, symbol)) {
		RZ_LOG_ERROR("Failed append new go symbol to symbols list\n");
		rz_bin_symbol_free(symbol);
	}

	if (!strcmp(name, "main.main")) {
		rz_flag_set(core->flags, "main", vaddr, 1);
	}
}

static char *detect_go_package_from_name(const char *string) {
	/**
	 * Ignore names that starts with:
	 * - `main.` because is related to the main package.
	 * - `type..` because is just the definition of a function linked to a defined go `typedef`
	 */
	if (rz_str_startswith(string, "main.") ||
		rz_str_startswith(string, "type:") ||
		rz_str_startswith(string, "type..")) {
		return NULL;
	}

	// remove `vendor/` because is useless.
	if (rz_str_startswith(string, "vendor/")) {
		string += strlen("vendor/");
	}

	size_t length = strlen(string);
	const char *end = NULL;

	for (size_t i = 0; i < length; i++) {
		if (string[i] == '.' && !end) {
			end = string + i;
		} else if (string[i] == '.' && end) {
			break;
		} else if (string[i] == '/') {
			end = NULL;
		} else if (string[i] == '(') {
			if (!end) {
				end = string + i;
			}
			break;
		} else if (string[i] == ':') {
			if (!end) {
				end = string + i;
			}
			break;
		} else if (string[i] == '{') {
			if (!end) {
				end = string + i;
			}
			break;
		}
	}

	if (!end) {
		// a end was not found, so we fail.
		return NULL;
	}

	size_t new_len = end - string;
	char *libname = rz_str_ndup(string, new_len);
	if (!libname) {
		RZ_LOG_ERROR("Failed to duplicate libname\n");
		return NULL;
	}

	return libname;
}

static int compare_string(const char *s1, const char *s2, void *user) {
	return strcmp(s1, s2);
}

static void add_new_library_from_name(RzCore *core, const char *name) {
	char *libname = detect_go_package_from_name(name);
	if (!libname) {
		return;
	}

	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o) {
		return;
	}

	if (!bf->o->libs) {
		bf->o->libs = rz_pvector_new(free);
	}

	if (rz_pvector_find(bf->o->libs, libname, (RzPVectorComparator)compare_string, NULL)) {
		free(libname);
		return;
	}

	if (!rz_pvector_push(bf->o->libs, libname)) {
		RZ_LOG_ERROR("Failed append new go libname to libs list\n");
		free(libname);
	}
}

static ut32 core_recover_golang_functions_go_1_18_plus(RzCore *core, GoPcLnTab *pclntab) {
	const char *go_ver = pclntab_version_str(pclntab);
	rz_core_notify_done(core, "Found %s pclntab data.", go_ver);
	ut8 tmp8[8];
	char name[256];
	char *flag = NULL;
	ut32 num_syms = 0;
	ut64 func_ptr = 0, func_off = 0, name_ptr = 0, name_off = 0;

	pclntab->nfunctab = (ut32)go_offset(pclntab, 0);
	pclntab->nfiletab = (ut32)go_offset(pclntab, 1);
	pclntab->funcnametab = go_data(pclntab, 3);
	pclntab->cutab = go_data(pclntab, 4);
	pclntab->filetab = go_data(pclntab, 5);
	pclntab->pctab = go_data(pclntab, 6);
	pclntab->funcdata = go_data(pclntab, 7);
	pclntab->functab = go_data(pclntab, 7);
	pclntab->functabsize = ((pclntab->nfunctab * 2) + 1) * go_func_tab_field_size(pclntab);
	pclntab->ptrsize = 4; // GO 1.18+ uses ut32 words.

	if (!is_pclntab_valid(pclntab)) {
		rz_core_notify_error(core, "Invalid %s pclntab (invalid table).", go_ver);
		return 0;
	}

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	for (ut32 i = 0, ptr = 0; i < pclntab->nfunctab; ++i, ptr += (pclntab->ptrsize * 2)) {
		ut64 offset = pclntab->functab + ptr;

		// reads the value of the function pointer
		if (0 > rz_io_nread_at(pclntab->io, offset, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_ptr = pclntab->text_start + go_uintptr(pclntab, tmp8);

		// reads the value of the function data offset
		if (0 > rz_io_nread_at(pclntab->io, offset + pclntab->ptrsize, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function data address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_off = go_uintptr(pclntab, tmp8);

		name_ptr = pclntab->functab + func_off + pclntab->ptrsize;
		// reads the location of the function name within funcnametab
		if (0 > rz_io_nread_at(pclntab->io, name_ptr, tmp8, sizeof(ut32))) {
			RZ_LOG_ERROR("Failed to read go function name address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		name_off = pclntab->funcnametab + rz_read_ble32(tmp8, pclntab->big_endian);

		// ignore failures, we can always create a new name.
		memset(name, 0, sizeof(name));
		(void)rz_io_nread_at(pclntab->io, name_off, (ut8 *)name, sizeof(name));
		name[sizeof(name) - 1] = 0;
		RZ_LOG_INFO("Recovered symbol at 0x%08" PFMT64x " with name '%s'\n", func_ptr, name);

		add_new_library_from_name(core, name);
		if (rz_str_len_utf8_ansi(name) > 0) {
			// always add it before filtering the name.
			add_new_func_symbol(core, name, func_ptr);
			rz_name_filter(name, 0, true);
		} else {
			rz_strf(name, "fcn.pclntab.unknown.%08" PFMT64x, func_ptr);
			add_new_func_symbol(core, name, func_ptr);
		}

		flag = rz_str_newf("sym.go.%s", name);
		rz_flag_set(core->flags, flag, func_ptr, 1);
		free(flag);

		num_syms++;
	}
	rz_flag_space_pop(core->flags);

	return num_syms;
}

static ut32 core_recover_golang_functions_go_1_16(RzCore *core, GoPcLnTab *pclntab) {
	const char *go_ver = pclntab_version_str(pclntab);
	rz_core_notify_done(core, "Found %s pclntab data.", go_ver);
	ut8 tmp8[8];
	char name[256];
	char *flag = NULL;
	ut32 num_syms = 0;
	ut64 func_ptr = 0, func_off = 0, name_ptr = 0, name_off = 0;

	pclntab->nfunctab = (ut32)go_offset(pclntab, 0);
	pclntab->nfiletab = (ut32)go_offset(pclntab, 1);
	pclntab->funcnametab = go_data(pclntab, 2);
	pclntab->cutab = go_data(pclntab, 3);
	pclntab->filetab = go_data(pclntab, 4);
	pclntab->pctab = go_data(pclntab, 5);
	pclntab->funcdata = go_data(pclntab, 6);
	pclntab->functab = go_data(pclntab, 6);
	pclntab->functabsize = ((pclntab->nfunctab * 2) + 1) * go_func_tab_field_size(pclntab);

	if (!is_pclntab_valid(pclntab)) {
		rz_core_notify_error(core, "Invalid %s pclntab (invalid table).", go_ver);
		return 0;
	}

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	for (ut32 i = 0, ptr = 0; i < pclntab->nfunctab; ++i, ptr += (pclntab->ptrsize * 2)) {
		ut64 offset = pclntab->functab + ptr;

		// reads the value of the function pointer
		if (0 > rz_io_nread_at(pclntab->io, offset, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_ptr = go_uintptr(pclntab, tmp8);

		// reads the value of the function data offset
		if (0 > rz_io_nread_at(pclntab->io, offset + pclntab->ptrsize, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function data address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_off = go_uintptr(pclntab, tmp8);

		name_ptr = pclntab->functab + func_off + pclntab->ptrsize;
		// reads the location of the function name within funcnametab
		if (0 > rz_io_nread_at(pclntab->io, name_ptr, tmp8, sizeof(ut32))) {
			RZ_LOG_ERROR("Failed to read go function name address at 0x%08" PFMT64x "\n", offset);
			break;
		}

		name_off = pclntab->funcnametab + rz_read_ble32(tmp8, pclntab->big_endian);

		// ignore failures, we can always create a new name.
		memset(name, 0, sizeof(name));
		(void)rz_io_nread_at(pclntab->io, name_off, (ut8 *)name, sizeof(name));
		name[sizeof(name) - 1] = 0;
		RZ_LOG_INFO("Recovered symbol at 0x%08" PFMT64x " with name '%s'\n", func_ptr, name);

		add_new_library_from_name(core, name);
		if (rz_str_len_utf8_ansi(name) > 0) {
			// always add it before filtering the name.
			add_new_func_symbol(core, name, func_ptr);
			rz_name_filter(name, 0, true);
		} else {
			rz_strf(name, "fcn.pclntab.unknown.%08" PFMT64x, func_ptr);
			add_new_func_symbol(core, name, func_ptr);
		}

		flag = rz_str_newf("sym.go.%s", name);
		rz_flag_set(core->flags, flag, func_ptr, 1);
		free(flag);

		num_syms++;
	}
	rz_flag_space_pop(core->flags);

	return num_syms;
}

// Valid for golang 1.2 -> 1.15
static ut32 core_recover_golang_functions_go_1_2(RzCore *core, GoPcLnTab *pclntab) {
	const char *go_ver = pclntab_version_str(pclntab);
	rz_core_notify_done(core, "Found %s pclntab data.", go_ver);
	ut8 tmp8[8];
	char name[256];
	char *flag = NULL;
	ut32 num_syms = 0;
	ut64 func_ptr = 0, func_off = 0, name_ptr = 0, name_off = 0;

	if (0 > rz_io_nread_at(pclntab->io, pclntab->vaddr + 8, tmp8, sizeof(tmp8))) {
		return 0;
	}

	pclntab->nfunctab = (ut32)go_uintptr(pclntab, tmp8);
	pclntab->functab = pclntab->vaddr + 8 + pclntab->ptrsize;
	pclntab->functabsize = ((pclntab->nfunctab * 2) + 1) * go_func_tab_field_size(pclntab);

	if (0 > rz_io_nread_at(pclntab->io, pclntab->functab + pclntab->functabsize, tmp8, sizeof(ut32))) {
		RZ_LOG_ERROR("Failed to read go functab at 0x%08" PFMT64x "\n", pclntab->functab);
		return 0;
	}

	pclntab->filetab = pclntab->vaddr + rz_read_ble32(tmp8, pclntab->big_endian);
	if (0 > rz_io_nread_at(pclntab->io, pclntab->filetab, tmp8, sizeof(ut32))) {
		RZ_LOG_ERROR("Failed to read go filetab at 0x%08" PFMT64x "\n", pclntab->filetab);
		return 0;
	}
	pclntab->nfiletab = rz_read_ble32(tmp8, pclntab->big_endian);

	if (!is_pclntab_valid(pclntab)) {
		rz_core_notify_error(core, "Invalid %s pclntab (invalid table).", go_ver);
		return 0;
	}

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	for (ut32 i = 0, ptr = 0; i < pclntab->nfunctab; ++i, ptr += (pclntab->ptrsize * 2)) {
		ut64 offset = pclntab->functab + ptr;

		// reads the value of the function pointer
		if (0 > rz_io_nread_at(pclntab->io, offset, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_ptr = go_uintptr(pclntab, tmp8);

		// reads the value of the function data offset
		if (0 > rz_io_nread_at(pclntab->io, offset + pclntab->ptrsize, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address data at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_off = go_uintptr(pclntab, tmp8);

		name_ptr = pclntab->vaddr + func_off + pclntab->ptrsize;
		// reads the location of the function name within funcnametab
		if (0 > rz_io_nread_at(pclntab->io, name_ptr, tmp8, sizeof(ut32))) {
			RZ_LOG_ERROR("Failed to read go function name address at 0x%08" PFMT64x "\n", offset);
			break;
		}

		name_off = pclntab->vaddr + rz_read_ble32(tmp8, pclntab->big_endian);

		// ignore failures, we can always create a new name.
		memset(name, 0, sizeof(name));
		(void)rz_io_nread_at(pclntab->io, name_off, (ut8 *)name, sizeof(name));
		name[sizeof(name) - 1] = 0;
		RZ_LOG_INFO("Recovered symbol at 0x%08" PFMT64x " with name '%s'\n", func_ptr, name);

		add_new_library_from_name(core, name);
		if (rz_str_len_utf8_ansi(name) > 0) {
			// always add it before filtering the name.
			add_new_func_symbol(core, name, func_ptr);
			rz_name_filter(name, 0, true);
		} else {
			rz_strf(name, "fcn.pclntab.unknown.%08" PFMT64x, func_ptr);
			add_new_func_symbol(core, name, func_ptr);
		}

		flag = rz_str_newf("sym.go.%s", name);
		rz_flag_set(core->flags, flag, func_ptr, 1);
		free(flag);

		num_syms++;
	}
	rz_flag_space_pop(core->flags);

	return num_syms;
}

static bool analyse_golang_symgo_function(RzFlagItem *fi, void *user) {
	RzCore *core = (RzCore *)user;
	rz_core_analysis_fcn(core, fi->offset, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	return true;
}

/**
 * \brief Analyse Golang symbols matching "sym.go.*"
 * \param core RzCore Pointer
 */
static void analyse_golang_symbols(RzCore *core) {
	const RzSpace *symbols = rz_flag_space_get(core->flags, RZ_FLAGS_FS_SYMBOLS);
	if (!symbols) {
		return;
	}
	rz_flag_foreach_space_glob(core->flags, "sym.go.*", symbols, analyse_golang_symgo_function, core);
}

/**
 * \brief Sorts the recovered libraries.
 *
 * \param core RzCore Pointer
 * \return Number of recovered libraries
 */
static ut32 sort_recovered_library(RzCore *core) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->libs) {
		return 0;
	}
	rz_pvector_sort(bf->o->libs, (RzPVectorComparator)compare_string, NULL);
	return rz_pvector_len(bf->o->libs);
}

/**
 * \brief      reads pclntab table in go binaries and recovers functions.
 * Follows the code https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go#L188
 * \param      core  The RzCore to use
 *
 * \return  Returns true when 1 or more symbols have been recovered.
 */
RZ_API bool rz_core_analysis_recover_golang_functions(RzCore *core) {
	rz_return_val_if_fail(core && core->bin && core->io, false);

	RzBinObject *o = rz_bin_cur_object(core->bin);
	const RzPVector *sections = o ? rz_bin_object_get_sections_all(o) : NULL;
	RzPVector *symbols_vec = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	void **iter;
	RzBinSection *section;
	ut32 num_syms = 0;
	GoPcLnTab pclntab = { 0 };
	ut8 header[8] = { 0 };

	rz_pvector_foreach (sections, iter) {
		section = *iter;
		// on ELF files the pclntab sections is named .gopclntab, but on macho is __gopclntab
		if (section->vsize >= 16 && strstr(section->name, "gopclntab")) {
			pclntab.vaddr = section->vaddr;
			pclntab.size = section->vsize;
		} else if (!pclntab.text_start &&
			(!strcmp(section->name, ".text") || strstr(section->name, "__text"))) {
			pclntab.text_start = section->vaddr;
		}
	}

	if (!pclntab.vaddr) {
		RzBinSymbol *symbol;
		rz_pvector_foreach (symbols_vec, iter) {
			symbol = *iter;
			// on PE files the pclntab sections is inside .rdata, so rizin creates a symbol for it
			if (symbol->size >= 16 && !strcmp(symbol->name, "gopclntab")) {
				pclntab.vaddr = symbol->vaddr;
				pclntab.size = symbol->size;
				break;
			}
		}
	}

	if (!pclntab.vaddr) {
		rz_core_notify_done(core, "Could not find go pclntab section");
		return false;
	} else if (0 > rz_io_nread_at(core->io, pclntab.vaddr, header, sizeof(header))) {
		RZ_LOG_ERROR("Failed to read gopclntab at address %" PFMT64x "\n", pclntab.vaddr);
		return false;
	} else if (header[4] != 0 || header[5] != 0 ||
		(header[6] != 1 && header[6] != 2 && header[6] != 4) || // pc quantum
		(header[7] != 4 && header[7] != 8)) { // pointer size
		rz_core_notify_error(core, "Invalid go pclntab (invalid pc quantum or pointer size).");
		return false;
	}

	pclntab.io = core->io;
	pclntab.quantum = header[6];
	pclntab.ptrsize = header[7];

	if (IS_GOPCLNTAB_1_20_BE(header) || IS_GOPCLNTAB_1_20_LE(header)) {
		pclntab.version = GO_1_20;
		pclntab.big_endian = IS_GOPCLNTAB_1_20_BE(header);
		num_syms = core_recover_golang_functions_go_1_18_plus(core, &pclntab);
	} else if (IS_GOPCLNTAB_1_18_BE(header) || IS_GOPCLNTAB_1_18_LE(header)) {
		pclntab.version = GO_1_18;
		pclntab.big_endian = IS_GOPCLNTAB_1_18_BE(header);
		num_syms = core_recover_golang_functions_go_1_18_plus(core, &pclntab);
	} else if (IS_GOPCLNTAB_1_16_BE(header) || IS_GOPCLNTAB_1_16_LE(header)) {
		pclntab.version = GO_1_16;
		pclntab.big_endian = IS_GOPCLNTAB_1_16_BE(header);
		num_syms = core_recover_golang_functions_go_1_16(core, &pclntab);
	} else if (IS_GOPCLNTAB_1_2_BE(header) || IS_GOPCLNTAB_1_2_LE(header)) {
		pclntab.version = GO_1_2;
		pclntab.big_endian = IS_GOPCLNTAB_1_2_BE(header);
		num_syms = core_recover_golang_functions_go_1_2(core, &pclntab);
	} else {
		ut32 magic = rz_read_be32(header);
		rz_core_notify_error(core, "Invalid go pclntab (unknown version: 0x%x). Please open an issue.", magic);
		return false;
	}

	if (num_syms) {
		ut32 num_libs = sort_recovered_library(core);
		rz_core_notify_done(core, "Recovered %u symbols and saved them at sym.go.*", num_syms);
		rz_core_notify_done(core, "Recovered %u go packages", num_libs);
		rz_core_notify_begin(core, "Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
		analyse_golang_symbols(core);
		rz_core_notify_done(core, "Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
		return true;
	}

	rz_core_notify_error(core, "Could not recover any symbol from the go pclntab.");
	return false;
}

static bool add_new_bin_string(RzCore *core, char *string, ut64 vaddr, ut32 size) {
	ut32 ordinal = 0;
	RzBinString *bstr;
	RzBin *bin = core->bin;
	RzBinFile *bf = rz_bin_cur(bin);
	if (!bf || !bf->o || !bf->o->strings) {
		free(string);
		return false;
	}

	bstr = rz_bin_object_get_string_at(bf->o, vaddr, true);
	if (bstr && bstr->vaddr == vaddr && bstr->size == size) {
		free(string);
		return true;
	}

	const RzPVector *strings = rz_bin_object_get_strings(bf->o);
	ordinal = rz_pvector_len(strings);

	ut64 paddr = rz_io_v2p(core->io, vaddr);

	bstr = RZ_NEW0(RzBinString);
	if (!bstr) {
		RZ_LOG_ERROR("Failed allocate new go string\n");
		free(string);
		return false;
	}
	bstr->paddr = paddr;
	bstr->vaddr = vaddr;
	bstr->ordinal = ordinal;
	bstr->length = bstr->size = size;
	bstr->string = string;
	bstr->type = RZ_STRING_ENC_UTF8;
	if (!rz_bin_string_database_add(bf->o->strings, bstr)) {
		RZ_LOG_ERROR("Failed append new go string to strings database\n");
		rz_bin_string_free(bstr);
		return false;
	}
	return true;
}

static bool recover_string_at(GoStrRecover *ctx, ut64 str_addr, ut64 str_size) {
	// check that the values are acceptable.
	if (str_size < 2 || str_size > GO_MAX_STRING_SIZE || str_addr < 1 || str_addr == UT64_MAX) {
		return false;
	}

	// skip possible pointers that matches to symbols flags, because these are already handled.
	RzFlagItem *fi = rz_flag_get_by_spaces(ctx->core->flags, str_addr, RZ_FLAGS_FS_SYMBOLS, NULL);
	if (fi && !strncmp(fi->name, "sym.", 4)) {
		return false;
	}

	RzBinObject *obj = rz_bin_cur_object(ctx->core->bin);
	if (!obj || !rz_bin_get_section_at(obj, str_addr, true)) {
		// skip any possible string from invalid sections.
		return false;
	}

	const size_t n_prefix = strlen("str.");
	// string size + strlen('str.') + \0
	char *flag = malloc(str_size + n_prefix + 1);
	char *raw = malloc(str_size + 1);
	if (!flag || !raw) {
		RZ_LOG_ERROR("Cannot allocate buffer to read string.");
		free(flag);
		free(raw);
		return false;
	}

	// set prefix and zero-terminator
	flag[0] = 's';
	flag[1] = 't';
	flag[2] = 'r';
	flag[3] = '.';
	flag[str_size + 4] = 0;
	raw[str_size] = 0;

	if (0 > rz_io_nread_at(ctx->core->io, str_addr, (ut8 *)raw, str_size)) {
		RZ_LOG_ERROR("Failed to read string value at address %" PFMT64x "\n", str_addr);
		free(flag);
		free(raw);
		return false;
	} else if (rz_str_len_utf8_ansi(raw) != str_size) {
		free(flag);
		free(raw);
		return false;
	}
	memcpy(flag + n_prefix, raw, str_size);

	// apply any filter to the new flag name
	rz_name_filter(flag + n_prefix, str_size, true);

	// verify is a valid flag.
	if (rz_str_len_utf8_ansi(flag) < 5) {
		free(flag);
		free(raw);
		return false;
	}

	// add new string to string list (raw is freed/owned by add_new_bin_string)
	if (!add_new_bin_string(ctx->core, raw, str_addr, str_size)) {
		free(flag);
		return false;
	}

	// remove any flag already set at this address
	rz_flag_unset_all_off(ctx->core->flags, str_addr);

	// add string to string flag space.
	rz_flag_space_push(ctx->core->flags, RZ_FLAGS_FS_STRINGS);
	rz_flag_set(ctx->core->flags, flag, str_addr, str_size);
	rz_flag_space_pop(ctx->core->flags);
	free(flag);
	ctx->n_recovered++;

	return true;
}

static bool go_is_sign_match(GoStrRecover *ctx, GoStrInfo *info, GoSignature *sigs, const size_t n_sigs) {
	ut8 copy[32]; // big enough to handle any pattern.
	ut32 nlen = 0;
	memset(info, 0, sizeof(GoStrInfo));

	for (size_t i = 0; i < n_sigs; ++i) {
		if (nlen >= ctx->size) {
			return false;
		}

		GoSignature *sig = &sigs[i];
		ut8 *bytes = ctx->bytes + nlen;
		ut32 size = ctx->size - nlen;
		if (sig->pasm->size > size) {
			return false;
		}

		// copy opcodes
		memcpy(copy, bytes, sig->pasm->size);

		// apply mask
		for (ut32 j = 0; j < sig->pasm->size; ++j) {
			copy[j] = copy[j] & sig->pasm->mask[j];
		}

		// verify the masked input matches the pattern
		if (memcmp(copy, sig->pasm->pattern, sig->pasm->size)) {
			return false;
		}

		// decode info
		if (sig->decode && !sig->decode(ctx->core, info, ctx->pc + nlen, bytes, size)) {
			return false;
		}

		// sets from where the xrefs starts.
		if (sig->pasm->xrefs) {
			info->xref = ctx->pc + nlen;
		}

		nlen += sig->pasm->size;
	}

	return true;
}

static ut32 decode_one_opcode_size(GoStrRecover *ctx) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(ctx->core->analysis, &aop, ctx->pc, ctx->bytes, ctx->size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return 0;
	}
	int size = aop.size;
	rz_analysis_op_fini(&aop);
	return size > 0 ? size : 0;
}

#define go_is_sign_match_autosize(ctx, info, sigs) go_is_sign_match(ctx, info, sigs, RZ_ARRAY_SIZE(sigs))
#define go_asm_pattern_name(arch, bits, mnemonic)  go_##arch##_##bits##_##mnemonic
#define go_asm_pattern_define(arch, bits, mnemonic, pattern, mask, set_xref) \
	static GoAsmPattern go_asm_pattern_name(arch, bits, mnemonic) = { (const ut8 *)pattern, (const ut8 *)mask, (sizeof(pattern) - 1), set_xref }

static bool decode_from_table(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysis *analysis = core->analysis;
	ut8 tmp[16];
	if (0 > rz_io_nread_at(core->io, info->addr, tmp, sizeof(tmp))) {
		return false;
	}
	ut32 offset = analysis->bits / 8;
	info->addr = rz_read_ble(tmp, analysis->big_endian, analysis->bits);
	info->size = rz_read_ble(tmp + offset, analysis->big_endian, analysis->bits);
	return true;
}

static bool decode_val_set_size(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->size = aop.val;
	rz_analysis_op_fini(&aop);
	return true;
}

static bool decode_val_set_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->addr = aop.val;
	rz_analysis_op_fini(&aop);
	return true;
}

static bool decode_val_add_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->addr += aop.val;
	rz_analysis_op_fini(&aop);
	return true;
}

static bool decode_ptr_set_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->addr = aop.ptr;
	rz_analysis_op_fini(&aop);
	return true;
}

static bool decode_disp_set_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->addr = aop.disp;
	rz_analysis_op_fini(&aop);
	return true;
}
// 0x004881da      48c7401003000000       mov   qword [rax + 0x10], 3
// 0x004881e2      488d0d8d8c0100         lea   rcx, [0x004a0e76]
go_asm_pattern_define(x86, 64, lea, "\x48\x00\x00\x00\x00\x00\x00", "\xff\x00\x00\x00\x00\x00\x00", true);
go_asm_pattern_define(x86, 64, mov_imm0, "\xb9\x00\x00\x00\x00", "\xff\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 64, mov_imm1, "\x48\xc7\x00\x00\x00\x00\x00\x00", "\xff\xff\x00\x00\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 64, mov_imm2, "\x41\x00\x00\x00\x00\x00", "\xff\x00\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 64, mov_imm3, "\xbb\x00\x00\x00\x00", "\xff\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 64, mov_imm4, "\xbf\x00\x00\x00\x00", "\xff\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 64, mov_reg0, "\x48\x00\x00\x00", "\xff\x00\x00\x00", false);
go_asm_pattern_define(x86, 64, mov_reg1, "\x48\x00\x00\x00\x00", "\xff\x00\x00\x00\x00", false);

static GoSignature go_x64_lea_mov0_mov_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   [esp/rsp + 0x..], reg
	{ &go_asm_pattern_name(x86, 64, mov_reg0), NULL },
	// mov   [esp/rsp + 0x..], string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm1), &decode_val_set_size },
};

static GoSignature go_x64_lea_mov1_mov_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   [esp/rsp + 0x..], reg
	{ &go_asm_pattern_name(x86, 64, mov_reg1), NULL },
	// mov   [esp/rsp + 0x..], string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm1), &decode_val_set_size },
};

static GoSignature go_x64_lea_mov0_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm0), &decode_val_set_size },
};

static GoSignature go_x64_lea_mov1_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm2), &decode_val_set_size },
};

static GoSignature go_x64_lea_mov2_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm3), &decode_val_set_size },
};

static GoSignature go_x64_lea_mov3_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm4), &decode_val_set_size },
};

static GoSignature go_x64_mov0_lea_signature[] = {
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm0), &decode_val_set_size },
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
};

static GoSignature go_x64_mov1_lea_signature[] = {
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm1), &decode_val_set_size },
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
};

static GoSignature go_x64_mov2_lea_signature[] = {
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm3), &decode_val_set_size },
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
};

static GoSignature go_x64_mov3_lea_signature[] = {
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 64, mov_imm4), &decode_val_set_size },
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
};

static GoSignature go_x64_table0_signature[] = {
	// lea   reg, [table_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   reg, reg
	{ &go_asm_pattern_name(x86, 64, mov_reg0), &decode_from_table },
};

static GoSignature go_x64_table1_signature[] = {
	// lea   reg, [table_offset]
	{ &go_asm_pattern_name(x86, 64, lea), &decode_ptr_set_addr },
	// mov   reg, reg
	{ &go_asm_pattern_name(x86, 64, mov_reg1), &decode_from_table },
};

static ut32 golang_recover_string_x64(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	ut32 oplen = decode_one_opcode_size(ctx);
	GoStrInfo info = { 0 };

	if (!go_is_sign_match_autosize(ctx, &info, go_x64_lea_mov0_mov_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_lea_mov1_mov_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_lea_mov0_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_lea_mov1_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_lea_mov2_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_lea_mov3_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_mov0_lea_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_mov1_lea_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_mov2_lea_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_mov3_lea_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_table0_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x64_table1_signature)) {
		return oplen;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return oplen;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return oplen;
}

go_asm_pattern_define(x86, 32, lea, "\x8d\x00\x00\x00\x00\x00", "\xff\x00\x00\x00\x00\x00", true);
go_asm_pattern_define(x86, 32, mov_imm0, "\xc7\x00\x00\x00\x00\x00\x00", "\xff\x00\x00\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 32, mov_imm1, "\xc7\x00\x00\x00\x00\x00\x00\x00", "\xff\x00\x00\x00\x00\x00\x00\x00", false);
go_asm_pattern_define(x86, 32, mov_reg0, "\x89\x00\x00", "\xff\x00\x00", false);
go_asm_pattern_define(x86, 32, mov_reg1, "\x89\x00\x00\x00", "\xff\x00\x00\x00", false);

static GoSignature go_x86_lea_mov0_mov_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 32, lea), &decode_disp_set_addr },
	// mov   [esp/rsp + 0x..], reg
	{ &go_asm_pattern_name(x86, 32, mov_reg0), NULL },
	// mov   [esp/rsp + 0x..], string_size
	{ &go_asm_pattern_name(x86, 32, mov_imm1), &decode_val_set_size },
};

static GoSignature go_x86_lea_mov1_mov_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 32, lea), &decode_disp_set_addr },
	// mov   [esp/rsp + 0x..], reg
	{ &go_asm_pattern_name(x86, 32, mov_reg1), NULL },
	// mov   [esp/rsp + 0x..], string_size
	{ &go_asm_pattern_name(x86, 32, mov_imm1), &decode_val_set_size },
};

static GoSignature go_x86_lea_mov0_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 32, lea), &decode_disp_set_addr },
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 32, mov_imm0), &decode_val_set_size },
};

static GoSignature go_x86_lea_mov1_signature[] = {
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 32, lea), &decode_disp_set_addr },
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 32, mov_imm1), &decode_val_set_size },
};

static GoSignature go_x86_mov_lea_signature[] = {
	// mov   reg, string_size
	{ &go_asm_pattern_name(x86, 32, mov_imm0), &decode_val_set_size },
	// lea   reg, [string_offset]
	{ &go_asm_pattern_name(x86, 32, lea), &decode_disp_set_addr },
};

static GoSignature go_x86_table_signature[] = {
	// lea   reg, [table_offset]
	{ &go_asm_pattern_name(x86, 32, lea), &decode_disp_set_addr },
	// mov   reg, reg
	{ &go_asm_pattern_name(x86, 32, mov_reg0), &decode_from_table },
};

static ut32 golang_recover_string_x86(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	ut32 oplen = decode_one_opcode_size(ctx);
	GoStrInfo info = { 0 };

	if (!go_is_sign_match_autosize(ctx, &info, go_x86_lea_mov0_mov_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x86_lea_mov1_mov_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x86_lea_mov0_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x86_lea_mov1_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x86_mov_lea_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_x86_table_signature)) {
		return oplen;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return oplen;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return oplen;
}

go_asm_pattern_define(arm, 64, adrp, "\x00\x00\x00\x80", "\x00\x00\x00\x8f", true);
go_asm_pattern_define(arm, 64, add, "\x00\x00\x00\x01", "\x00\x00\x00\x6f", false);
go_asm_pattern_define(arm, 64, orr, "\x00\x00\x00\x22", "\x00\x00\x80\x6f", false);
go_asm_pattern_define(arm, 64, movz, "\x00\x00\x80\x42", "\x00\x00\x80\x6f", false);
go_asm_pattern_define(arm, 64, any, "\x00\x00\x00\x00", "\x00\x00\x00\x00", false);

static GoSignature go_arm64_adrp_add_str_orr_signature[] = {
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 64, any), NULL },
	// orr    reg1, 0, string_size
	{ &go_asm_pattern_name(arm, 64, orr), &decode_val_set_size },
};

static GoSignature go_arm64_adrp_add_str_movz_signature[] = {
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 64, any), NULL },
	// movz   reg1, string_size
	{ &go_asm_pattern_name(arm, 64, movz), &decode_val_set_size },
};

static GoSignature go_arm64_orr_str_adrp_add_signature[] = {
	// orr    reg1, 0, string_size
	{ &go_asm_pattern_name(arm, 64, orr), &decode_val_set_size },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 64, any), NULL },
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
};

static GoSignature go_arm64_movz_str_adrp_add_signature[] = {
	// movz   reg1, string_size
	{ &go_asm_pattern_name(arm, 64, movz), &decode_val_set_size },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 64, any), NULL },
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
};

static GoSignature go_arm64_adrp_add_orr_signature[] = {
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
	// orr    reg1, 0, string_size
	{ &go_asm_pattern_name(arm, 64, orr), &decode_val_set_size },
};

static GoSignature go_arm64_adrp_add_movz_signature[] = {
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
	// movz   reg1, string_size
	{ &go_asm_pattern_name(arm, 64, movz), &decode_val_set_size },
};

static GoSignature go_arm64_table_signature[] = {
	// adrp   reg0, base_str
	{ &go_asm_pattern_name(arm, 64, adrp), &decode_ptr_set_addr },
	// add    reg0, reg0, offset_str
	{ &go_asm_pattern_name(arm, 64, add), &decode_val_add_addr },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 64, any), &decode_from_table },
};

static ut32 golang_recover_string_arm64(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	GoStrInfo info = { 0 };

	if (!go_is_sign_match_autosize(ctx, &info, go_arm64_adrp_add_str_orr_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm64_adrp_add_str_movz_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm64_orr_str_adrp_add_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm64_movz_str_adrp_add_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm64_adrp_add_orr_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm64_adrp_add_movz_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm64_table_signature)) {
		return 4;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return 4;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return 4;
}

static bool decode_ldr_set_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	ut8 tmp[4];
	ut64 addr = 0;

	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	addr = aop.ptr;
	rz_analysis_op_fini(&aop);

	if (0 > rz_io_nread_at(core->io, addr, tmp, sizeof(tmp))) {
		return false;
	}
	info->addr = rz_read_ble32(tmp, core->analysis->big_endian);
	return true;
}

go_asm_pattern_define(arm, 32, ldr, "\x00\x00\x9f\xe5", "\x00\x00\x9f\xe5", true);
go_asm_pattern_define(arm, 32, mov, "\x00\x00\xa0\xe3", "\x00\x00\xa0\xe3", false);
go_asm_pattern_define(arm, 32, any, "\x00\x00\x00\x00", "\x00\x00\x00\x00", false);

static GoSignature go_arm32_ldr_str_mov_signature[] = {
	// ldr    reg0, string_offset
	{ &go_asm_pattern_name(arm, 32, ldr), &decode_ldr_set_addr },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 32, any), NULL },
	// mov    reg1, string_size
	{ &go_asm_pattern_name(arm, 32, mov), &decode_val_set_size },
};

static GoSignature go_arm32_mov_str_ldr_signature[] = {
	// mov    reg1, string_size
	{ &go_asm_pattern_name(arm, 32, mov), &decode_val_set_size },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 32, any), NULL },
	// ldr    reg0, string_offset
	{ &go_asm_pattern_name(arm, 32, ldr), &decode_ldr_set_addr },
};

static GoSignature go_arm32_ldr_mov_signature[] = {
	// ldr    reg0, string_offset
	{ &go_asm_pattern_name(arm, 32, ldr), &decode_ldr_set_addr },
	// mov    reg1, string_size
	{ &go_asm_pattern_name(arm, 32, mov), &decode_val_set_size },
};

static GoSignature go_arm32_table_signature[] = {
	// ldr    reg0, string_offset
	{ &go_asm_pattern_name(arm, 32, ldr), &decode_ldr_set_addr },
	// str    reg, [sp, ..]
	{ &go_asm_pattern_name(arm, 32, any), &decode_from_table },
};

static ut32 golang_recover_string_arm32(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	GoStrInfo info = { 0 };

	if (!go_is_sign_match_autosize(ctx, &info, go_arm32_ldr_str_mov_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm32_mov_str_ldr_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm32_ldr_mov_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_arm32_table_signature)) {
		return 4;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return 4;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return 4;
}

static bool decode_lui_set_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->addr = aop.val;
	info->addr <<= 16;
	rz_analysis_op_fini(&aop);
	return true;
}

go_asm_pattern_define(mips, 32, any, "\x00\x00\x00\x00", "\x00\x00\x00\x00", false);
go_asm_pattern_define(mipsbe, 32, addiu, "\x24\x00\x00\x00", "\xff\x00\x00\x00", false);
go_asm_pattern_define(mipsle, 32, addiu, "\x00\x00\x00\x24", "\x00\x00\x00\xff", false);
go_asm_pattern_define(mipsbe, 32, lui, "\x3c\x00\x00\x00", "\xff\x00\x00\x00", true);
go_asm_pattern_define(mipsle, 32, lui, "\x00\x00\x00\x3c", "\x00\x00\x00\xff", true);

// ---- LE ----
static GoSignature go_mipsle32_lui_addiu_sw_addiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_add_addr },
	// sw    v0, 0x08(at)
	{ &go_asm_pattern_name(mips, 32, any), NULL },
	// addiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_set_size },
};

static GoSignature go_mipsle32_addiu_sw_lui_addiu_signature[] = {
	// addiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_set_size },
	// sw    v0, 0x08(at)
	{ &go_asm_pattern_name(mips, 32, any), NULL },
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_add_addr },
};

static GoSignature go_mipsle32_lui_addiu_addiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_add_addr },
	// addiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_set_size },
};

static GoSignature go_mipsle32_table_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 32, addiu), &decode_val_add_addr },
	// sw    v0, 0x08(at)
	{ &go_asm_pattern_name(mips, 32, any), &decode_from_table },
};

// ---- BE ----
static GoSignature go_mipsbe32_lui_addiu_sw_addiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_add_addr },
	// sw    v0, 0x08(at)
	{ &go_asm_pattern_name(mips, 32, any), NULL },
	// addiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_set_size },
};

static GoSignature go_mipsbe32_addiu_sw_lui_addiu_signature[] = {
	// addiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_set_size },
	// sw    v0, 0x08(at)
	{ &go_asm_pattern_name(mips, 32, any), NULL },
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_add_addr },
};

static GoSignature go_mipsbe32_lui_addiu_addiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_add_addr },
	// addiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_set_size },
};

static GoSignature go_mipsbe32_table_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, lui), &decode_lui_set_addr },
	// addiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 32, addiu), &decode_val_add_addr },
	// sw    v0, 0x08(at)
	{ &go_asm_pattern_name(mips, 32, any), &decode_from_table },
};

static ut32 golang_recover_string_mips32(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	GoStrInfo info = { 0 };

	if (analysis->big_endian &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe32_lui_addiu_sw_addiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe32_addiu_sw_lui_addiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe32_lui_addiu_addiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe32_table_signature)) {
		return 4;
	} else if (!analysis->big_endian &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle32_lui_addiu_sw_addiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle32_addiu_sw_lui_addiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle32_lui_addiu_addiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle32_table_signature)) {
		return 4;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return 4;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return 4;
}

go_asm_pattern_define(mips, 64, any, "\x00\x00\x00\x00", "\x00\x00\x00\x00", false);
go_asm_pattern_define(mipsbe, 64, daddu, "\x00\x00\x00\x2d", "\x00\x00\x00\xff", false);
go_asm_pattern_define(mipsle, 64, daddu, "\x2d\x00\x00\x00", "\xff\x00\x00\x00", false);
go_asm_pattern_define(mipsbe, 64, daddiu, "\x64\x00\x00\x00", "\xfc\x00\x00\x00", false);
go_asm_pattern_define(mipsle, 64, daddiu, "\x00\x00\x00\x64", "\x00\x00\x00\xfc", false);
go_asm_pattern_define(mipsbe, 64, move, "\x64\x00\x00\x00", "\xff\xe0\x00\x00", false);
go_asm_pattern_define(mipsle, 64, move, "\x00\x00\x00\x64", "\x00\x00\xe0\xff", false);
go_asm_pattern_define(mipsbe, 64, lui, "\x3c\x00\x00\x00", "\xff\x00\x00\x00", true);
go_asm_pattern_define(mipsle, 64, lui, "\x00\x00\x00\x3c", "\x00\x00\x00\xff", true);

// ---- LE ----
static GoSignature go_mipsle64_lui_daddu_daddiu_sd_daddiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsle, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 64, daddiu), &decode_val_add_addr },
	// sd    v0, 8(at)
	{ &go_asm_pattern_name(mips, 64, any), NULL },
	// daddiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsle, 64, move), &decode_val_set_size },
};

static GoSignature go_mipsle64_daddiu_sd_lui_daddu_daddiu_signature[] = {
	// daddiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsle, 64, move), &decode_val_set_size },
	// sd    v0, 8(at)
	{ &go_asm_pattern_name(mips, 64, any), NULL },
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsle, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 64, daddiu), &decode_val_add_addr },
};

static GoSignature go_mipsle64_lui_daddu_daddiu_daddiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsle, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 64, daddiu), &decode_val_add_addr },
	// daddiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsle, 64, move), &decode_val_set_size },
};

static GoSignature go_mipsle64_table_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsle, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsle, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsle, 64, daddiu), &decode_val_add_addr },
	// sd    v0, 8(at)
	{ &go_asm_pattern_name(mips, 64, any), &decode_from_table },
};

// ---- BE ----
static GoSignature go_mipsbe64_lui_daddu_daddiu_sd_daddiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsbe, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, daddiu), &decode_val_add_addr },
	// sd    v0, 8(at)
	{ &go_asm_pattern_name(mips, 64, any), NULL },
	// daddiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsbe, 64, move), &decode_val_set_size },
};

static GoSignature go_mipsbe64_daddiu_sd_lui_daddu_daddiu_signature[] = {
	// daddiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsbe, 64, move), &decode_val_set_size },
	// sd    v0, 8(at)
	{ &go_asm_pattern_name(mips, 64, any), NULL },
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsbe, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, daddiu), &decode_val_add_addr },
};

static GoSignature go_mipsbe64_lui_daddu_daddiu_daddiu_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsbe, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, daddiu), &decode_val_add_addr },
	// daddiu v0, zero, string_size
	{ &go_asm_pattern_name(mipsbe, 64, move), &decode_val_set_size },
};

static GoSignature go_mipsbe64_table_signature[] = {
	// lui   v0, high_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, lui), &decode_lui_set_addr },
	// daddu v0, v0, gp
	{ &go_asm_pattern_name(mipsbe, 64, daddu), NULL },
	// daddiu v0, v0, low_string_offset
	{ &go_asm_pattern_name(mipsbe, 64, daddiu), &decode_val_add_addr },
	// sd    v0, 8(at)
	{ &go_asm_pattern_name(mips, 64, any), &decode_from_table },
};

static ut32 golang_recover_string_mips64(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	GoStrInfo info = { 0 };

	if (analysis->big_endian &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe64_lui_daddu_daddiu_sd_daddiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe64_daddiu_sd_lui_daddu_daddiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe64_lui_daddu_daddiu_daddiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsbe64_table_signature)) {
		return 4;
	} else if (!analysis->big_endian &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle64_lui_daddu_daddiu_sd_daddiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle64_daddiu_sd_lui_daddu_daddiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle64_lui_daddu_daddiu_daddiu_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_mipsle64_table_signature)) {
		return 4;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return 4;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return 4;
}

go_asm_pattern_define(ppc, 64, any, "\x00\x00\x00\x00", "\x00\x00\x00\x00", false);
go_asm_pattern_define(ppcle, 64, lis, "\x00\x00\x00\x3c", "\x00\x00\x00\xfc", true);
go_asm_pattern_define(ppcbe, 64, lis, "\x3c\x00\x00\x00", "\xfc\x00\x00\x00", true);
go_asm_pattern_define(ppcle, 64, addi, "\x00\x00\x00\x38", "\x00\x00\x00\xfc", false);
go_asm_pattern_define(ppcbe, 64, addi, "\x38\x00\x00\x00", "\xfc\x00\x00\x00", false);
go_asm_pattern_define(ppcle, 64, li, "\x00\x00\x00\x38", "\x00\x00\x1f\xfc", false);
go_asm_pattern_define(ppcbe, 64, li, "\x38\x00\x00\x00", "\xfc\x1f\x00\x00", false);

// ---- LE ----
static GoSignature go_ppcle64_lis_addi_std_li_signature[] = {
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcle, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcle, 64, addi), &decode_val_add_addr },
	// std   r3, 0x20(r1)
	{ &go_asm_pattern_name(ppc, 64, any), NULL },
	// li    r3, string_size
	{ &go_asm_pattern_name(ppcle, 64, li), &decode_val_set_size },
};

static GoSignature go_ppcle64_li_std_lis_addi_signature[] = {
	// li    r3, string_size
	{ &go_asm_pattern_name(ppcle, 64, li), &decode_val_set_size },
	// std   r3, 0x20(r1)
	{ &go_asm_pattern_name(ppc, 64, any), NULL },
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcle, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcle, 64, addi), &decode_val_add_addr },
};

static GoSignature go_ppcle64_lis_addi_li_signature[] = {
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcle, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcle, 64, addi), &decode_val_add_addr },
	// li    r3, string_size
	{ &go_asm_pattern_name(ppcle, 64, li), &decode_val_set_size },
};

static GoSignature go_ppcle64_table_signature[] = {
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcle, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcle, 64, addi), &decode_val_add_addr },
	// std   r3, 0x20(r1)
	{ &go_asm_pattern_name(ppc, 64, any), &decode_from_table },
};

// ---- BE ----
static GoSignature go_ppcbe64_lis_addi_std_li_signature[] = {
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, addi), &decode_val_add_addr },
	// std   r3, 0x20(r1)
	{ &go_asm_pattern_name(ppc, 64, any), NULL },
	// li    r3, string_size
	{ &go_asm_pattern_name(ppcbe, 64, li), &decode_val_set_size },
};

static GoSignature go_ppcbe64_li_std_lis_addi_signature[] = {
	// li    r3, string_size
	{ &go_asm_pattern_name(ppcbe, 64, li), &decode_val_set_size },
	// std   r3, 0x20(r1)
	{ &go_asm_pattern_name(ppc, 64, any), NULL },
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, addi), &decode_val_add_addr },
};

static GoSignature go_ppcbe64_lis_addi_li_signature[] = {
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, addi), &decode_val_add_addr },
	// li    r3, string_size
	{ &go_asm_pattern_name(ppcbe, 64, li), &decode_val_set_size },
};

static GoSignature go_ppcbe64_table_signature[] = {
	// lis   r3, high_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, lis), &decode_val_set_addr },
	// addi  r3, r3, low_string_offset
	{ &go_asm_pattern_name(ppcbe, 64, addi), &decode_val_add_addr },
	// std   r3, 0x20(r1)
	{ &go_asm_pattern_name(ppc, 64, any), &decode_from_table },
};

static ut32 golang_recover_string_ppc64(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	GoStrInfo info = { 0 };

	if (analysis->big_endian &&
		!go_is_sign_match_autosize(ctx, &info, go_ppcbe64_lis_addi_std_li_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_ppcbe64_li_std_lis_addi_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_ppcbe64_table_signature)) {
		return 4;
	} else if (!analysis->big_endian &&
		!go_is_sign_match_autosize(ctx, &info, go_ppcle64_lis_addi_std_li_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_ppcle64_li_std_lis_addi_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_ppcle64_table_signature)) {
		return 4;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		if (analysis->big_endian && !go_is_sign_match_autosize(ctx, &info, go_ppcbe64_lis_addi_li_signature)) {
			return 4;
		} else if (!analysis->big_endian && !go_is_sign_match_autosize(ctx, &info, go_ppcle64_lis_addi_li_signature)) {
			return 4;
		} else if (!recover_string_at(ctx, info.addr, info.size)) {
			return 4;
		}
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return 4;
}

static bool decode_auipc_set_addr(RzCore *core, GoStrInfo *info, ut64 pc, const ut8 *buffer, const ut32 size) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, pc, buffer, size, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
		rz_analysis_op_fini(&aop);
		return false;
	}
	info->addr = pc + aop.val;
	rz_analysis_op_fini(&aop);
	return true;
}

go_asm_pattern_define(riscv, 64, auipc, "\x17\x00\x00\x00", "\x7f\x00\x00\x00", true);
go_asm_pattern_define(riscv, 64, addi, "\x13\x00\x00\x00", "\x7f\x00\x00\x00", false);
go_asm_pattern_define(riscv, 64, addiw, "\x1b\x00\x00\x00", "\x7f\x70\x00\x00", false);
go_asm_pattern_define(riscv, 64, li, "\x13\x00\x00\x00", "\x7f\x80\x0F\x00", false);
go_asm_pattern_define(riscv, 64, any, "\x00\x00\x00\x00", "\x00\x00\x00\x00", false);

static GoSignature go_riscv64_auipc_add_sd_addiw_signature[] = {
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
	// sd    gp, 8(sp)
	{ &go_asm_pattern_name(riscv, 64, any), NULL },
	// addiw gp, zero, string_size
	{ &go_asm_pattern_name(riscv, 64, addiw), &decode_val_set_size },
};

static GoSignature go_riscv64_auipc_add_sd_li_signature[] = {
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
	// sd    gp, 8(sp)
	{ &go_asm_pattern_name(riscv, 64, any), NULL },
	// li    gp, zero, string_size
	{ &go_asm_pattern_name(riscv, 64, li), &decode_val_set_size },
};

static GoSignature go_riscv64_li_sd_auipc_add_signature[] = {
	// li    gp, zero, string_size
	{ &go_asm_pattern_name(riscv, 64, li), &decode_val_set_size },
	// sd    gp, 8(sp)
	{ &go_asm_pattern_name(riscv, 64, any), NULL },
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
};

static GoSignature go_riscv64_addiw_sd_auipc_add_signature[] = {
	// addiw gp, zero, string_size
	{ &go_asm_pattern_name(riscv, 64, addiw), &decode_val_set_size },
	// sd    gp, 8(sp)
	{ &go_asm_pattern_name(riscv, 64, any), NULL },
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
};

static GoSignature go_riscv64_auipc_add_addiw_signature[] = {
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
	// addiw gp, zero, string_size
	{ &go_asm_pattern_name(riscv, 64, addiw), &decode_val_set_size },
};

static GoSignature go_riscv64_auipc_add_li_signature[] = {
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
	// li    gp, zero, string_size
	{ &go_asm_pattern_name(riscv, 64, li), &decode_val_set_size },
};

static GoSignature go_riscv64_table_signature[] = {
	// auipc gp, high_string_offset
	{ &go_asm_pattern_name(riscv, 64, auipc), &decode_auipc_set_addr },
	// addi  gp, gp, low_string_offset
	{ &go_asm_pattern_name(riscv, 64, addi), &decode_val_add_addr },
	// sd    gp, 8(sp)
	{ &go_asm_pattern_name(riscv, 64, any), &decode_from_table },
};

static ut32 golang_recover_string_riscv64(GoStrRecover *ctx) {
	RzAnalysis *analysis = ctx->core->analysis;
	GoStrInfo info = { 0 };

	if (!go_is_sign_match_autosize(ctx, &info, go_riscv64_auipc_add_sd_addiw_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_riscv64_auipc_add_sd_li_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_riscv64_li_sd_auipc_add_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_riscv64_addiw_sd_auipc_add_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_riscv64_auipc_add_addiw_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_riscv64_auipc_add_li_signature) &&
		!go_is_sign_match_autosize(ctx, &info, go_riscv64_table_signature)) {
		return 4;
	}

	// try to recover the string.
	if (!recover_string_at(ctx, info.addr, info.size)) {
		return 4;
	}

	rz_analysis_xrefs_set(analysis, info.xref, info.addr, RZ_ANALYSIS_XREF_TYPE_STRING);
	return 4;
}

// Sometimes the data-structures has strings, but these are stored in tables where
// the first offset is always the pointer to the squashed strings and the next word
// is the size of the string
static void core_recover_golang_strings_from_data_pointers(RzCore *core, GoStrRecover *ctx) {
	rz_core_notify_begin(core, "Recovering go strings from bin maps");

	RzAnalysis *analysis = core->analysis;
	const ut32 word_size = analysis->bits / 8;
	void **iter;
	RzBinMap *map;
	ut8 *buffer = NULL;
	ut64 string_addr, string_size;
	RzBinObject *object = rz_bin_cur_object(core->bin);
	RzPVector *map_vec = object ? rz_bin_object_get_maps(object) : NULL;
	if (!map_vec) {
		RZ_LOG_ERROR("Failed to get the RzBinMap list\n");
		goto end;
	}

	buffer = malloc(GO_MAX_TABLE_SIZE);
	if (!buffer) {
		RZ_LOG_ERROR("Failed to allocate table buffer\n");
		goto end;
	}

	rz_pvector_foreach (map_vec, iter) {
		map = *iter;
		if (!rz_bin_map_is_data(map) || map->psize < (word_size * 2)) {
			continue;
		}

		ut64 current = map->vaddr;
		ut64 end = map->vaddr + map->psize;

		do {
			size_t length = RZ_MIN((end - current), GO_MAX_TABLE_SIZE);
			if (length < (word_size * 2)) {
				break;
			}

			if (rz_io_nread_at(core->io, current, buffer, length) < 0) {
				RZ_LOG_ERROR("Failed to read map at address %" PFMT64x "\n", current);
				break;
			}

			length -= word_size;
			for (size_t i = 0; i < length; i += word_size) {
				string_addr = rz_read_ble(buffer + i, analysis->big_endian, analysis->bits);
				string_size = rz_read_ble(buffer + i + word_size, analysis->big_endian, analysis->bits);
				if (!string_addr || !string_size) {
					continue;
				} else if (word_size == sizeof(ut32) && string_addr == UT32_MAX) {
					continue;
				} else if (word_size == sizeof(ut64) && string_addr == UT64_MAX) {
					continue;
				}
				if (recover_string_at(ctx, string_addr, string_size)) {
					rz_analysis_xrefs_set(analysis, current + i, string_addr, RZ_ANALYSIS_XREF_TYPE_STRING);
				}
			}
			current += length;
		} while (current < end);
	}

end:
	free(buffer);
	rz_core_notify_done(core, "Recovering go strings from bin maps");
}

/**
 * \brief      Attempts to recover all golang string
 *
 * \param      core  The RzCore struct to use
 */
RZ_API void rz_core_analysis_resolve_golang_strings(RzCore *core) {
	rz_return_if_fail(core && core->analysis && core->analysis->fcns && core->io);

	const char *asm_arch = rz_config_get(core->config, "asm.arch");
	ut32 asm_bits = rz_config_get_i(core->config, "asm.bits");
	void **vit, **vit2;
	RzAnalysisFunction *func;
	RzAnalysisBlock *block;
	GoStrRecoverCb recover_cb = NULL;
	ut8 *bytes = NULL;
	ut32 min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	GoStrRecover ctx = { 0 };
	ctx.core = core;

	core_recover_golang_strings_from_data_pointers(core, &ctx);

	rz_core_notify_begin(core, "Analyze all instructions to recover all strings used in sym.go.*");
	if (!strcmp(asm_arch, "x86")) {
		switch (asm_bits) {
		case 32:
			recover_cb = &golang_recover_string_x86;
			break;
		case 64:
			recover_cb = &golang_recover_string_x64;
			break;
		default:
			break;
		}
	} else if (!strcmp(asm_arch, "arm")) {
		switch (asm_bits) {
		case 32:
			recover_cb = &golang_recover_string_arm32;
			break;
		case 64:
			recover_cb = &golang_recover_string_arm64;
			break;
		default:
			break;
		}
	} else if (!strcmp(asm_arch, "mips")) {
		switch (asm_bits) {
		case 32:
			recover_cb = &golang_recover_string_mips32;
			break;
		case 64:
			recover_cb = &golang_recover_string_mips64;
			break;
		default:
			break;
		}
	} else if (!strcmp(asm_arch, "riscv")) {
		switch (asm_bits) {
		case 64:
			recover_cb = &golang_recover_string_riscv64;
			break;
		default:
			break;
		}
	} else if (!strcmp(asm_arch, "ppc")) {
		switch (asm_bits) {
		case 64:
			recover_cb = &golang_recover_string_ppc64;
			break;
		default:
			break;
		}
	} else if (!strcmp(asm_arch, "sysz")) {
		// sysz uses strings that are all null terminated
		// also they are already handled by rizin.
		// example: 'larl  %r0, str.XXXX' with the correct length.
		rz_core_notify_done(core, "Analyze all instructions to recover all strings used in sym.go.*");
		return;
	}

	if (!recover_cb) {
		rz_core_notify_error(core, "Cannot resolve go strings because arch '%s:%u' is not supported.", asm_arch, asm_bits);
		return;
	}

	rz_pvector_foreach (core->analysis->fcns, vit) {
		func = *vit;
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_pvector_foreach (func->bbs, vit2) {
			block = (RzAnalysisBlock *)*vit2;
			bytes = malloc(block->size);
			if (!bytes) {
				RZ_LOG_ERROR("Failed allocate basic block bytes buffer\n");
				return;
			} else if (0 > rz_io_nread_at(core->io, block->addr, bytes, block->size)) {
				free(bytes);
				RZ_LOG_ERROR("Failed to read function basic block at address %" PFMT64x "\n", block->addr);
				return;
			}

			for (ut32 i = 0; i < block->size;) {
				ctx.pc = block->addr + i;
				ctx.bytes = bytes + i;
				ctx.size = block->size - i;

				ut32 nlen = recover_cb(&ctx);
				i += RZ_MAX(nlen, min_op_size);
			}
			free(bytes);
		}
	}

	rz_core_notify_done(core, "Analyze all instructions to recover all strings used in sym.go.*");
	rz_core_notify_done(core, "Recovered %d strings from the sym.go.* functions.", ctx.n_recovered);
}
