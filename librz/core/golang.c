//

#include <rz_core.h>

#define GO_MAX_STRING_SIZE 0x4000

#define GO_1_2  (12)
#define GO_1_16 (116)
#define GO_1_18 (118)

#define IS_GOPCLNTAB_1_2_LE(x)  (x[0] == 0xfb && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_2_BE(x)  (x[3] == 0xfb && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_16_LE(x) (x[0] == 0xfa && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_16_BE(x) (x[3] == 0xfa && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_18_LE(x) (x[0] == 0xf0 && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_18_BE(x) (x[3] == 0xf0 && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)

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
	if (!rz_list_append(bf->o->symbols, symbol)) {
		RZ_LOG_ERROR("Failed append new go symbol to symbols list\n");
		rz_bin_symbol_free(symbol);
	}

	if (!strcmp(name, "main.main")) {
		rz_flag_set(core->flags, "main", vaddr, 1);
	}
}

static ut32 core_recover_golang_functions_go_1_18(RzCore *core, GoPcLnTab *pclntab) {
	rz_core_notify_done(core, "Found go 1.18 pclntab data.");
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
		rz_core_notify_error(core, "Invalid go 1.18 pclntab (invalid table).");
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

		if (strlen(name) > 0) {
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
	rz_core_notify_done(core, "Found go 1.16 pclntab data.");
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
		rz_core_notify_error(core, "Invalid go 1.16 pclntab (invalid table).");
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

		if (strlen(name) > 0) {
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
	rz_core_notify_done(core, "Found go 1.12 pclntab data.");
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
		rz_core_notify_error(core, "Invalid go 1.12 pclntab (invalid table).");
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

		if (strlen(name) > 0) {
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

/**
 * \brief      reads pclntab table in go binaries and recovers functions.
 * Follows the code https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go#L188
 *
 * \param      core  The RzCore to use
 *
 * \return  Returns true when 1 or more symbols have been recovered.
 */
RZ_API bool rz_core_analysis_recover_golang_functions(RzCore *core) {
	rz_return_val_if_fail(core && core->bin && core->io, false);

	RzList *section_list = rz_bin_get_sections(core->bin);
	RzList *symbols_list = rz_bin_get_symbols(core->bin);
	RzListIter *iter;
	RzBinSection *section;
	ut32 num_syms = 0;
	GoPcLnTab pclntab = { 0 };
	ut8 header[8] = { 0 };

	rz_list_foreach (section_list, iter, section) {
		// on ELF files the pclntab sections is named .gopclntab, but on macho is __gopclntab
		if (section->vsize >= 16 && strstr(section->name, "gopclntab")) {
			pclntab.vaddr = section->vaddr;
			pclntab.size = section->vsize;
		} else if (!pclntab.text_start && !strcmp(section->name, ".text")) {
			pclntab.text_start = section->vaddr;
		}
	}

	if (!pclntab.vaddr) {
		RzBinSymbol *symbol;
		rz_list_foreach (symbols_list, iter, symbol) {
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

	if (IS_GOPCLNTAB_1_18_BE(header) || IS_GOPCLNTAB_1_18_LE(header)) {
		pclntab.version = GO_1_18;
		pclntab.big_endian = IS_GOPCLNTAB_1_18_BE(header);
		num_syms = core_recover_golang_functions_go_1_18(core, &pclntab);
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
		rz_core_notify_error(core, "Invalid go pclntab (unknown version: 0x%x).", magic);
		return false;
	}

	if (num_syms) {
		rz_core_notify_done(core, "Recovered %u symbols and saved them at sym.go.*", num_syms);
		rz_core_notify_begin(core, "Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
		rz_core_cmd0(core, "aF @@f:sym.go.*");
		rz_core_notify_done(core, "Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
		return true;
	}

	rz_core_notify_error(core, "Could not recover any symbol from the go pclntab.");
	return false;
}

static void add_new_string(RzCore *core, const char *string, ut64 vaddr, ut32 size) {
	RzListIter *it;
	RzBinString *bstr;
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->strings) {
		return;
	}
	ut64 paddr = rz_io_v2p(core->io, vaddr);

	rz_list_foreach (bf->o->strings, it, bstr) {
		if (bstr->vaddr == vaddr && bstr->size == size) {
			return;
		}
		ut64 end = bstr->vaddr + bstr->size;
		if (vaddr >= bstr->vaddr && (vaddr + size) < end) {
			RzListIter *prev = it->p;
			rz_list_delete(bf->o->strings, it);
			it = prev ? prev : bf->o->strings->head;
			break;
		}
	}

	bstr = RZ_NEW0(RzBinString);
	if (!bstr) {
		RZ_LOG_ERROR("Failed allocate new go string\n");
		return;
	}
	bstr->paddr = paddr;
	bstr->vaddr = vaddr;
	bstr->ordinal = rz_list_length(bf->o->strings);
	bstr->length = bstr->size = size;
	bstr->string = rz_str_ndup(string, size);
	bstr->type = RZ_BIN_STRING_ENC_UTF8;
	if (!rz_list_append(bf->o->strings, bstr)) {
		RZ_LOG_ERROR("Failed append new go string to strings list\n");
		rz_bin_string_free(bstr);
	}
}

// Possible x64/x86 signatures
// -------
// mov   reg, string_size
// lea   reg, [esp/rsp + string_offset]
// -------
// lea   reg, [esp/rsp + string_offset]
// mov   reg, string_size
// -------
// lea   reg, [string_offset]
// mov   [esp/rsp + 0x..], reg
// mov   [esp/rsp + 0x..], string_size
static ut32 golang_recover_string_x86(GoStrRecover *ctx) {
	const ut32 opmask = RZ_ANALYSIS_OP_MASK_DISASM;
	RzAnalysis *analysis = ctx->core->analysis;
	ut8 *bytes = ctx->bytes;
	ut32 size = ctx->size;
	RzAnalysisOp aop0, aop1;
	ut32 nlen = 0;
	ut64 str_addr = 0, str_size = 0, pc = ctx->pc;
	rz_analysis_op_init(&aop0);
	rz_analysis_op_init(&aop1);

	if ((size - nlen) < 1 || rz_analysis_op(analysis, &aop0, pc, bytes, size, opmask) < 1) {
		nlen = 0;
		goto end;
	}
	nlen += aop0.size;

	// check if first op is LEA or MOV, otherwise skip
	if (strncmp(aop0.mnemonic, "lea", 3) && strncmp(aop0.mnemonic, "mov", 3)) {
		goto end;
	} else if (!strncmp(aop0.mnemonic, "mov", 3)) {
		str_size = aop0.val;
	} else { // LEA
		str_addr = aop0.ptr;
	}

	if ((size - nlen) < 1 || rz_analysis_op(analysis, &aop1, pc + nlen, bytes + nlen, size - nlen, opmask) < 1) {
		nlen = 0;
		goto end;
	}
	nlen += aop1.size;

	// check if first op is LEA but second is not MOV
	if (!strncmp(aop0.mnemonic, "lea", 3) && strncmp(aop1.mnemonic, "mov", 3)) {
		nlen = aop0.size;
		goto end;
		// check if first op is MOV but second is not LEA
	} else if (!strncmp(aop0.mnemonic, "mov", 3) && strncmp(aop1.mnemonic, "lea", 3)) {
		nlen = aop0.size;
		goto end;
		// check if first op is LEA but has an invalid pointer
	}

	if (!strncmp(aop1.mnemonic, "mov", 3) && (aop1.val < 2 || aop1.val > GO_MAX_STRING_SIZE)) {
		// so we found another MOV in between LEA and the MOV with the string size (3rd scenario)
		rz_analysis_op_fini(&aop1);
		rz_analysis_op_init(&aop1);
		if ((size - nlen) < 1 || rz_analysis_op(analysis, &aop1, pc + nlen, bytes + nlen, size - nlen, opmask) < 1) {
			goto end;
		}
		nlen += aop1.size;
		if (strncmp(aop1.mnemonic, "mov", 3)) {
			nlen = aop0.size;
			goto end;
		}
		str_size = aop1.val;
	} else if (!strncmp(aop1.mnemonic, "mov", 3)) {
		str_size = aop1.val;
	} else { // LEA
		str_addr = aop1.ptr;
	}

	// check that the values are acceptable.
	if (str_size < 2 || str_size > GO_MAX_STRING_SIZE || str_addr < 1 || str_addr == UT64_MAX) {
		nlen = aop0.size;
		goto end;
	}

	const size_t n_prefix = strlen("str.");
	// string size + strlen('str.') + \0
	char *flag = malloc(str_size + n_prefix + 1);
	if (!flag) {
		RZ_LOG_ERROR("Cannot allocate buffer to read string.");
		goto end;
	} else if (0 > rz_io_nread_at(ctx->core->io, str_addr, (ut8 *)flag + n_prefix, str_size)) {
		free(flag);
		RZ_LOG_ERROR("Failed to read string value at address %" PFMT64x "\n", str_addr);
		goto end;
	} else if (!IS_PRINTABLE(flag[n_prefix]) && !IS_WHITESPACE(flag[n_prefix])) {
		free(flag);
		nlen = aop0.size;
		goto end;
	}

	// set prefix and zero-terminator
	flag[0] = 's';
	flag[1] = 't';
	flag[2] = 'r';
	flag[3] = '.';
	flag[str_size + 4] = 0;

	// add new string to string list
	add_new_string(ctx->core, flag + n_prefix, str_addr, str_size);

	// apply any filter to the new flag name
	rz_name_filter(flag + n_prefix, str_size, true);

	// remove any flag already set at this address
	rz_flag_unset_all_off(ctx->core->flags, str_addr);

	// add string to string flag space.
	rz_flag_space_push(ctx->core->flags, RZ_FLAGS_FS_STRINGS);
	rz_flag_set(ctx->core->flags, flag, str_addr, str_size);
	rz_flag_space_pop(ctx->core->flags);
	free(flag);
	ctx->n_recovered++;

end:
	rz_analysis_op_fini(&aop0);
	rz_analysis_op_fini(&aop1);
	return nlen;
}

/**
 * \brief      Attempts to recover all golang string
 *
 * \param      core  The RzCore struct to use
 */
RZ_API void rz_core_analysis_resolve_golang_strings(RzCore *core) {
	rz_return_if_fail(core && core->analysis && core->analysis->fcns && core->io);
	rz_core_notify_begin(core, "Analyze all instructions to recover all strings used in sym.go.*");

	const char *asm_arch = rz_config_get(core->config, "asm.arch");
	ut64 asm_bits = rz_config_get_i(core->config, "asm.bits");
	RzListIter *it, *it2;
	RzAnalysisFunction *func;
	RzAnalysisBlock *block;
	GoStrRecoverCb recover_cb = NULL;
	ut8 *bytes = NULL;
	ut32 min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	GoStrRecover ctx = { 0 };
	ctx.core = core;

	if (!strcmp(asm_arch, "x86")) {
		recover_cb = &golang_recover_string_x86;
	} else if (!strcmp(asm_arch, "arm")) {
		switch (asm_bits) {
		case 32:
			// recover_cb = &golang_recover_string_arm_32;
			break;
		case 64:
			// recover_cb = &golang_recover_string_arm_64;
			break;
		default:
			break;
		}
	}

	if (!recover_cb) {
		rz_core_notify_error(core, "Cannot resolve go strings because arch '%s' is not supported.", asm_arch);
		return;
	}

	rz_list_foreach (core->analysis->fcns, it, func) {
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_list_foreach (func->bbs, it2, block) {
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