// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_assert.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include <rz_cons.h>
#include "../i/private.h"
#include "elf/elf.h"
#include <rz_analysis.h>
#include <rz_util/ht_uu.h>

#define rz_bin_file_get_elf(bf) ((ELFOBJ *)bf->o->bin_obj)

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

#ifdef RZ_BIN_ELF64
#define rz_buf_append_word rz_buf_append_ut64
#else
#define rz_buf_append_word rz_buf_append_ut32
#endif

typedef struct {
	ut32 cmpMask; // Opcode bits of instruction.
	ut32 relocMask; // Relocation bitmask for patching.
} HexagonRelocMask;

/**
 * \brief Maps instructions of the R_HEX_6_X relocation typ
 * to its bitmask patched during relocation.
 */
static const HexagonRelocMask hex_rel6_x_masks[] = {
	{ 0x38000000, 0x0000201f }, { 0x39000000, 0x0000201f },
	{ 0x3e000000, 0x00001f80 }, { 0x3f000000, 0x00001f80 },
	{ 0x40000000, 0x000020f8 }, { 0x41000000, 0x000007e0 },
	{ 0x42000000, 0x000020f8 }, { 0x43000000, 0x000007e0 },
	{ 0x44000000, 0x000020f8 }, { 0x45000000, 0x000007e0 },
	{ 0x46000000, 0x000020f8 }, { 0x47000000, 0x000007e0 },
	{ 0x6a000000, 0x00001f80 }, { 0x7c000000, 0x001f2000 },
	{ 0x9a000000, 0x00000f60 }, { 0x9b000000, 0x00000f60 },
	{ 0x9c000000, 0x00000f60 }, { 0x9d000000, 0x00000f60 },
	{ 0x9f000000, 0x001f0100 }, { 0xab000000, 0x0000003f },
	{ 0xad000000, 0x0000003f }, { 0xaf000000, 0x00030078 },
	{ 0xd7000000, 0x006020e0 }, { 0xd8000000, 0x006020e0 },
	{ 0xdb000000, 0x006020e0 }, { 0xdf000000, 0x006020e0 }
};

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_6_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r6(ut32 insn) {
	if ((insn & 0xc000) == 0) { // Duplex instruction
		return 0x03f00000;
	}

	for (int i = 0; i < sizeof(hex_rel6_x_masks) / sizeof(HexagonRelocMask); ++i) {
		if ((0xff000000 & insn) == hex_rel6_x_masks[i].cmpMask) {
			return hex_rel6_x_masks[i].relocMask;
		}
	}
	RZ_LOG_ERROR("Unrecognized instruction for 6_X relocation: 0x%x\n", insn);
	return 0;
}

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_8_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r8(ut32 insn) {
	if ((0xff000000 & insn) == 0xde000000) {
		return 0x00e020e8;
	}
	if ((0xff000000 & insn) == 0x3c000000) {
		return 0x0000207f;
	}
	return 0x00001fe0;
}

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_11_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r11(ut32 insn) {
	if ((0xff000000 & insn) == 0xa1000000) {
		return 0x060020ff;
	}
	return 0x06003fe0;
}

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_16_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r16(ut32 insn) {
	if ((0xff000000 & insn) == 0x48000000) {
		return 0x061f20ff;
	}
	if ((0xff000000 & insn) == 0x49000000) {
		return 0x061f3fe0;
	}
	if ((0xff000000 & insn) == 0x78000000) {
		return 0x00df3fe0;
	}
	if ((0xff000000 & insn) == 0xb0000000) {
		return 0x0fe03fe0;
	}
	if ((insn & 0xc000) == 0) { // Duplex instruction
		return 0x03f00000;
	}

	for (int i = 0; i < sizeof(hex_rel6_x_masks) / sizeof(HexagonRelocMask); ++i) {
		if ((0xff000000 & insn) == hex_rel6_x_masks[i].cmpMask) {
			return hex_rel6_x_masks[i].relocMask;
		}
	}

	RZ_LOG_ERROR("Unrecognized instruction for 16_X relocation: 0x%x\n", insn);
	return 0;
}

typedef struct rz_bin_reloc_formular_symbols_t {
	ut64 A; // Appendend
	ut64 B; // Base address
	ut64 G; // Offset into GOT for symbol entry.
	ut64 GOT; // Address of entry zero in GOT.
	ut64 L; // Offset into POT for symbol entry.
	ut64 P; // Place address of the field being relocated. The address of the bytes to patch.
	ut64 S; // Value of symbol.
	ut64 TLS; // Thread-pointer-relative offset to a thread-local symbol.
	ut64 T; // Base address of the static thread-local tmeplate that contains a thread-local symbol.
	ut64 MB; // Base address of all strings consumed by compiler message base optimization (Hexagon specific).
	ut64 GP; // Value of GP register (Hexagon specific).
	ut64 AHL; // Special value used by MIPS to handle R_MIPS_HI16 & R_MIPS_LO16 relocs
} RzBinRelocFormularSymbols;

static RzBinInfo *info(RzBinFile *bf);
static void patch_relocs(RzBinFile *bf, struct Elf_(rz_bin_elf_obj_t) * bin);
static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf);

struct special_symbol_translation {
	RzBinSpecialSymbol symbol;
	ut64 (*get_addr)(ELFOBJ *bin);
};

static struct special_symbol_translation special_symbol_translation_table[] = {
	{ RZ_BIN_SPECIAL_SYMBOL_ENTRY, Elf_(rz_bin_elf_get_entry_offset) },
	{ RZ_BIN_SPECIAL_SYMBOL_MAIN, Elf_(rz_bin_elf_get_main_offset) },
	{ RZ_BIN_SPECIAL_SYMBOL_INIT, Elf_(rz_bin_elf_get_init_offset) },
	{ RZ_BIN_SPECIAL_SYMBOL_FINI, Elf_(rz_bin_elf_get_fini_offset) },
};

static Sdb *get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);
	return bin->kv;
}

#ifndef RZ_BIN_CGC
static int check_buffer_aux(RzBuffer *buf) {
	rz_return_val_if_fail(buf, ELFCLASSNONE);

	ut8 tmp[SELFMAG + 1] = { 0 };

	if (rz_buf_read_at(buf, 0, tmp, SELFMAG + 1) < 0) {
		return ELFCLASSNONE;
	}

	if (memcmp(tmp, ELFMAG, SELFMAG)) {
		return ELFCLASSNONE;
	}

	return tmp[SELFMAG];
}
#endif

static bool load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb) {
	rz_return_val_if_fail(obj, false);

	ELFOBJ *bin = Elf_(rz_bin_elf_new_buf)(buf, &obj->opts);
	if (!bin) {
		return false;
	}

	obj->bin_obj = bin;
	return true;
}

static ut64 baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, UT64_MAX);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);
	return Elf_(rz_bin_elf_get_baddr)(bin);
}

static ut64 boffset(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, UT64_MAX);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);
	return Elf_(rz_bin_elf_get_boffset)(bin);
}

static ut64 binsym_aux(ELFOBJ *bin, RzBinSpecialSymbol sym) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(special_symbol_translation_table); i++) {
		if (sym == special_symbol_translation_table[i].symbol) {
			return special_symbol_translation_table[i].get_addr(bin);
		}
	}

	return UT64_MAX;
}

static RzBinAddr *rz_bin_addr_new_aux(ELFOBJ *bin, ut64 paddr, ut64 vaddr) {
	RzBinAddr *result = RZ_NEW0(RzBinAddr);
	if (!result) {
		return NULL;
	}

	result->paddr = paddr;
	result->vaddr = vaddr;
	result->bits = bin->bits;

	if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin)) {
		rz_bin_elf_fix_arm_thumb_object_dispatch(result);
	}

	return result;
}

static RzBinAddr *rz_bin_addr_new_from_paddr(ELFOBJ *bin, ut64 paddr) {
	ut64 vaddr = Elf_(rz_bin_elf_p2v)(bin, paddr);
	if (vaddr == UT64_MAX) {
		vaddr = paddr;
	}

	return rz_bin_addr_new_aux(bin, paddr, vaddr);
}

static RzBinAddr *rz_bin_addr_new_from_vaddr(ELFOBJ *bin, ut64 vaddr) {
	ut64 paddr = Elf_(rz_bin_elf_v2p)(bin, vaddr);

	return rz_bin_addr_new_aux(bin, paddr, vaddr);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	rz_return_val_if_fail(bf && bf->o && bf->o, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	ut64 paddr = binsym_aux(bin, sym);
	if (paddr == UT64_MAX) {
		return NULL;
	}

	return rz_bin_addr_new_from_paddr(bin, paddr);
}

static void add_constructor(ELFOBJ *bin, ut64 addr, ut64 size, int type, RzPVector /*<RzBinAddr *>*/ *result) {
	ut64 constructor_offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (constructor_offset == UT64_MAX) {
		return;
	}

	ut64 pos = 0;

	while (pos < size) {
		ut64 offset = constructor_offset + pos;

		Elf_(Addr) vaddr;
		if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &vaddr)) {
			break;
		}

		if (!vaddr) {
			pos += sizeof(Elf_(Addr));
			continue;
		}

		RzBinAddr *tmp = rz_bin_addr_new_from_vaddr(bin, vaddr);
		if (!tmp) {
			break;
		}

		tmp->hpaddr = constructor_offset + pos;
		tmp->hvaddr = addr + pos;
		tmp->type = type;

		rz_pvector_push(result, tmp);

		pos += sizeof(Elf_(Addr));
	}
}

static void add_constructors(ELFOBJ *bin, RzPVector /*<RzBinAddr *>*/ *result) {
	ut64 addr, size;

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PREINIT_ARRAY, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_PREINIT_ARRAYSZ, &size)) {
		add_constructor(bin, addr, size, RZ_BIN_ENTRY_TYPE_PREINIT, result);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_INIT_ARRAY, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_INIT_ARRAYSZ, &size)) {
		add_constructor(bin, addr, size, RZ_BIN_ENTRY_TYPE_INIT, result);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_FINI_ARRAY, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_FINI_ARRAYSZ, &size)) {
		add_constructor(bin, addr, size, RZ_BIN_ENTRY_TYPE_FINI, result);
	}
}

static void add_entry_offset(ELFOBJ *bin, RzPVector /*<RzBinAddr *>*/ *result) {
	ut64 paddr = Elf_(rz_bin_elf_get_entry_offset)(bin);
	if (paddr == UT64_MAX) {
		return;
	}

	RzBinAddr *tmp = rz_bin_addr_new_from_paddr(bin, paddr);
	if (!tmp) {
		return;
	}

	tmp->hpaddr = E_ENTRYPOINT_OFFSET;
	tmp->hvaddr = bin->baddr + tmp->hpaddr;

	if (tmp->vaddr != (ut64)bin->ehdr.e_entry && Elf_(rz_bin_elf_is_executable)(bin)) {
		RZ_LOG_ERROR("Cannot determine entrypoint, using 0x%08" PFMT64x ".\n", tmp->vaddr);
	}

	rz_pvector_push(result, tmp);
}

static void add_java_libraries(ELFOBJ *bin, RzPVector /*<RzBinAddr *>*/ *result) {
	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		if (symbol->name && rz_str_startswith(symbol->name, "Java") && rz_str_endswith(symbol->name, "_init")) {
			RzBinAddr *tmp = rz_bin_addr_new_from_paddr(bin, symbol->paddr);
			tmp->type = RZ_BIN_ENTRY_TYPE_INIT;

			rz_pvector_push(result, tmp);
			break;
		}
	}
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	RzPVector *result = rz_pvector_new((RzPVectorFree)free);
	if (!result) {
		return NULL;
	}

	add_entry_offset(bin, result);
	add_java_libraries(bin, result);
	add_constructors(bin, result);

	return result;
}

#ifndef RZ_BIN_CGC
static void headers(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o && bf->o->bin_obj);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	Elf_(rz_bin_elf_print_ehdr)(bin, bf->rbin->cb_printf);
}

static bool create_set_e_ident(RzBuffer *result) {
	return rz_buf_append_bytes(result, (ut8 *)ELFMAG, SELFMAG) &&
#ifdef RZ_BIN_ELF64
		rz_buf_append_bytes(result, (ut8 *)"\x2\x1\x1\x0", 4) &&
#else
		rz_buf_append_bytes(result, (ut8 *)"\x1\x1\x1\x0", 4) &&
#endif
		rz_buf_append_nbytes(result, 8);
}

static bool create_set_e_machine(RzBuffer *result, bool is_arm) {
#ifdef RZ_BIN_ELF64
	return rz_buf_append_ut16(result, EM_X86_64);
#else
	if (is_arm) {
		return rz_buf_append_ut16(result, EM_ARM);
	}

	return rz_buf_append_ut16(result, EM_386);
#endif
}

static bool create_set_ehdr(RzBuffer *result, Elf_(Word) baddr, bool is_arm) {
	return create_set_e_ident(result) &&
		rz_buf_append_ut16(result, ET_EXEC) &&
		create_set_e_machine(result, is_arm) &&
		rz_buf_append_ut32(result, EV_CURRENT) &&
		rz_buf_append_word(result, baddr + sizeof(Elf_(Ehdr)) + sizeof(Elf_(Phdr))) && // e_entry
		rz_buf_append_word(result, sizeof(Elf_(Ehdr))) && // e_phoff
		rz_buf_append_word(result, 0) && // e_shoff
		rz_buf_append_ut32(result, 0) && // e_flags
		rz_buf_append_ut16(result, sizeof(Elf_(Ehdr))) && // e_ehsize
		rz_buf_append_ut16(result, sizeof(Elf_(Phdr))) && // e_phentsize
		rz_buf_append_ut16(result, 1) && // e_phnum
		rz_buf_append_ut16(result, 0) && // e_shentsize
		rz_buf_append_ut16(result, 0) && // e_shnum
		rz_buf_append_ut16(result, 0); // e_shstrndx
}

static bool create_set_phdr(RzBuffer *result, Elf_(Word) baddr, int codelen) {
	ut64 length = sizeof(Elf_(Ehdr)) + sizeof(Elf_(Phdr)) + codelen;

	return rz_buf_append_ut32(result, PT_LOAD) &&
#ifdef RZ_BIN_ELF64
		rz_buf_append_ut32(result, PF_X | PF_R) &&
		rz_buf_append_ut64(result, 0) && // p_offset
		rz_buf_append_ut64(result, baddr) && // p_vaddr
		rz_buf_append_ut64(result, baddr) && // p_paddr
		rz_buf_append_ut64(result, length) && // p_filesz
		rz_buf_append_ut64(result, length) && // p_memsz
		rz_buf_append_ut64(result, 0x200000); // p_align
#else
		rz_buf_append_ut32(result, 0) && // p_offset
		rz_buf_append_ut32(result, baddr) && // p_vaddr
		rz_buf_append_ut32(result, baddr) && // p_paddr
		rz_buf_append_ut32(result, length) && // p_filesz
		rz_buf_append_ut32(result, length) && // p_memsz
		rz_buf_append_ut32(result, PF_X | PF_R) && // p_flags
		rz_buf_append_ut32(result, 0x1000); // p_align
#endif
}

static Elf_(Word) create_get_baddr(bool is_arm) {
#ifdef RZ_BIN_ELF64
	return 0x400000LL;
#else
	if (is_arm) {
		return 0x40000;
	}

	return 0x8048000;
#endif
}

static RzBuffer *create_elf(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	rz_return_val_if_fail(bin && opt && opt->arch, NULL);

	RzBuffer *result = rz_buf_new_with_bytes(NULL, 0);

	bool is_arm = !strcmp(opt->arch, "arm");
	Elf_(Word) baddr = create_get_baddr(is_arm);

	if (!create_set_ehdr(result, baddr, is_arm) ||
		!create_set_phdr(result, baddr, codelen) ||
		!rz_buf_append_bytes(result, code, codelen)) {
		rz_buf_free(result);
		return NULL;
	}

	if (data && datalen > 0) {
		// ut32 data_section = buf->length;
		RZ_LOG_WARN("DATA section not support for ELF yet\n");
		rz_buf_append_bytes(result, data, datalen);
	}

	return result;
}
#endif

static void destroy(RzBinFile *bf) {
	Elf_(rz_bin_elf_free)(bf->o->bin_obj);
}

static RzBinSymbol *convert_symbol(ELFOBJ *bin, RzBinElfSymbol *elf_symbol) {
	RzBinSymbol *result = RZ_NEW0(RzBinSymbol);
	if (!result) {
		return NULL;
	}

	result->paddr = elf_symbol->paddr;
	result->vaddr = elf_symbol->vaddr;
	if (RZ_STR_ISNOTEMPTY(elf_symbol->name)) {
		result->name = rz_str_dup(elf_symbol->name);
	} else {
		result->name = rz_str_newf("unknown_%u", elf_symbol->ordinal);
	}
	result->forwarder = "NONE";
	result->bind = elf_symbol->bind;
	result->type = elf_symbol->type;
	result->size = elf_symbol->size;
	result->ordinal = elf_symbol->ordinal;
	result->bits = bin->bits;

	if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin)) {
		Elf_(rz_bin_elf_fix_arm_thumb_symbol)(result);
	}

	return result;
}

static RzBinSymbol *get_symbol(ELFOBJ *bin, ut32 ordinal) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbol)(bin, ordinal);
	if (!symbol) {
		return NULL;
	}

	return convert_symbol(bin, symbol);
}

static RzBinImport *convert_import(RzBinElfSymbol *symbol) {
	RzBinImport *result = RZ_NEW0(RzBinImport);
	if (!result) {
		return NULL;
	}

	result->name = rz_str_dup(symbol->name);
	result->bind = symbol->bind;
	result->type = symbol->type;
	result->ordinal = symbol->ordinal;

	return result;
}

static RzBinImport *get_import(ELFOBJ *bin, ut32 ordinal) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_import)(bin, ordinal);
	if (!symbol) {
		return NULL;
	}

	return convert_import(symbol);
}

static int get_file_type(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = bf->o->bin_obj;
	char *type = Elf_(rz_bin_elf_get_file_type(obj));
	int res = type ? ((!strncmp(type, "CORE", 4)) ? RZ_BIN_TYPE_CORE : RZ_BIN_TYPE_DEFAULT) : -1;
	free(type);
	return res;
}

static char *regstate(RzBinFile *bf) {
	ELFOBJ *obj = bf->o->bin_obj;

	RzVector *notes;
	rz_bin_elf_foreach_notes_segment(obj, notes) {
		RzBinElfNote *tmp;
		rz_vector_foreach (notes, tmp) {
			if (tmp->type != NT_PRSTATUS) {
				continue;
			}

			RzBinElfNotePrStatus *note = &tmp->prstatus;
			return rz_hex_bin2strdup(note->regstate, note->regstate_size);
		}
	}

	char *machine_name = Elf_(rz_bin_elf_get_machine_name)(obj);
	RZ_LOG_ERROR("Cannot retrieve regstate on: %s (not yet supported)\n", machine_name);
	free(machine_name);
	return NULL;
}

static char *setphname(ut16 mach, Elf_(Word) ptyp) {
	// TODO to complete over time
	if (mach == EM_ARM) {
		if (ptyp == SHT_ARM_EXIDX) {
			return rz_str_dup("EXIDX");
		}
	} else if (mach == EM_MIPS) {
		if (ptyp == PT_MIPS_ABIFLAGS) {
			return rz_str_dup("ABIFLAGS");
		} else if (ptyp == PT_MIPS_REGINFO) {
			return rz_str_dup("REGINFO");
		}
	}

	return rz_str_dup("UNKNOWN");
}

static bool is_wordable_section(const char *name) {
	if (!strcmp(name, ".init_array")) {
		return true;
	}
	if (!strcmp(name, ".fini_array")) {
		return true;
	}
	if (!strcmp(name, ".data.rel.ro")) {
		return true;
	}
	if (!strcmp(name, ".dynamic")) {
		return true;
	}
	if (!strcmp(name, ".got")) {
		return true;
	}
	if (strstr(name, ".rela.")) {
		return true;
	}
	return false;
}

static RzBinElfNoteFile *note_file_for_load_segment(ELFOBJ *obj, Elf_(Phdr) * phdr) {
	if (!Elf_(rz_bin_elf_has_notes)(obj)) {
		return false;
	}

	RzVector *notes;
	rz_bin_elf_foreach_notes_segment(obj, notes) {
		RzBinElfNote *tmp;
		rz_vector_foreach (notes, tmp) {
			if (tmp->type != NT_FILE) {
				continue;
			}

			RzBinElfNoteFile *note = &tmp->file;

			if (note->start_vaddr == phdr->p_vaddr) {
				return note;
			}
		}
	}

	return NULL;
}

static ut32 section_perms_from_flags(ut32 flags) {
	ut32 r = 0;
	if (RZ_BIN_ELF_SCN_IS_EXECUTABLE(flags)) {
		r |= RZ_PERM_X;
	}
	if (RZ_BIN_ELF_SCN_IS_WRITABLE(flags)) {
		r |= RZ_PERM_W;
	}
	if (RZ_BIN_ELF_SCN_IS_READABLE(flags)) {
		r |= RZ_PERM_R;
	}
	return r;
}

static RzPVector /*<RzBinMap *>*/ *maps_unpatched(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	if (Elf_(rz_bin_elf_has_segments)(obj)) {
		ut64 core_sp = Elf_(rz_bin_elf_get_sp_val)(obj);
		int n = 0;

		RzBinElfSegment *iter;
		rz_bin_elf_foreach_segments(obj, iter) {
			if (iter->data.p_type != PT_LOAD) {
				continue;
			}

			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				break;
			}

			map->paddr = iter->data.p_offset;
			map->psize = iter->data.p_filesz;
			map->vsize = iter->data.p_memsz;
			map->vaddr = iter->data.p_vaddr;
			map->perm = iter->data.p_flags | RZ_PERM_R;

			// map names specific to core files...
			if (core_sp != UT64_MAX && core_sp >= iter->data.p_vaddr && core_sp < iter->data.p_vaddr + iter->data.p_memsz) {
				map->name = rz_str_dup("[stack]");
			} else {
				RzBinElfNoteFile *nf = note_file_for_load_segment(obj, &iter->data);
				if (nf && nf->file) {
					map->name = rz_str_dup(nf->file);
				}
			}
			// generic names
			if (!map->name) {
				map->name = rz_str_newf("LOAD%d", n);
			}
			n++;
			rz_pvector_push(ret, map);
		}
	} else {
		// Load sections if there is no PHDR

		RzBinElfSection *section;
		rz_bin_elf_foreach_sections(obj, section) {
			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				break;
			}

			map->name = rz_str_dup(section->name);
			map->paddr = section->offset;
			map->psize = section->type != SHT_NOBITS ? section->size : 0;
			map->vsize = section->size;
			map->vaddr = section->rva;
			map->perm = section_perms_from_flags(section->flags);
			rz_pvector_push(ret, map);
		}
	}

	if (rz_pvector_empty(ret)) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->name = rz_str_dup("uphdr");
		map->paddr = 0;
		map->psize = bf->size;
		map->vaddr = 0x10000;
		map->vsize = bf->size;
		map->perm = RZ_PERM_RWX;
		rz_pvector_push(ret, map);
	}

	if (obj->ehdr.e_type == ET_REL) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		ut64 ehdr_size = sizeof(obj->ehdr);
		if (bf->size < ehdr_size) {
			ehdr_size = bf->size;
		}
		map->name = rz_str_dup("ehdr");
		map->paddr = 0;
		map->psize = ehdr_size;
		map->vaddr = obj->baddr;
		map->vsize = ehdr_size;
		map->perm = RZ_PERM_RW;
		rz_pvector_push(ret, map);
	}
	return ret;
}

static ut64 reloc_target_size(ELFOBJ *obj) {
	if (!obj->bits) {
		return 8;
	}
	return obj->bits / 8;
}

/// size of the artificial reloc target vfile
static ut64 reloc_targets_vfile_size(RzBinFile *bf, ELFOBJ *obj) {
	if (!bf->o || !bf->o->opts.patch_relocs || !Elf_(rz_bin_elf_has_relocs)(obj)) {
		return 0;
	}

	return Elf_(rz_bin_elf_get_relocs_count)(obj) * reloc_target_size(obj);
}

/**
 * \brief Spreads the value bits according to the bitmask and returns the result.
 *
 * The immediated bits in Hexagon opcodes are not sequential.
 * If a relocation value is patched into the opcode, its bits must be aligned with bit locations in the opcode.
 * The parameter \p bitmask indicates where the immediate bits are located.
 *
 * \param mask The bitmask which indicates where the value bits should be placed.
 * \param val The relocation value.
 * \return ut32 New value which can be patched into the opcode.
 */
static ut32 apply_bitmask(const ut32 mask, const ut32 val) {
	ut32 result = 0;
	ut32 off = 0;

	for (ut32 bit = 0; bit != 32; ++bit) {
		ut32 valBit = (val >> off) & 1;
		ut32 maskBit = (mask >> bit) & 1;
		if (maskBit) {
			result |= (valBit << bit);
			++off;
		}
	}
	return result;
}

/**
 * \brief Patches a given value into a Hexagon opcode.
 *
 * \param buf_patched Pointer to buffer.
 * \param addr Address the opcode is located.
 * \param mask The bitmask (patchable bits) of the opcode.
 * \param val The value patched into opcode.
 */
static void patch_val_hexagon(RZ_INOUT RzBuffer *buf_patched, const ut32 addr, const ut32 mask, const ut32 val) {
	rz_return_if_fail(buf_patched);
	ut8 buf[8] = { 0 };

	rz_buf_read_at(buf_patched, addr, buf, 4);
	ut32 opcode = rz_read_le32(buf) | apply_bitmask(mask, val);

	rz_write_le32(buf, opcode);
	rz_buf_write_at(buf_patched, addr, buf, 4);
}

#define UNHANDL(NAME) \
	RZ_LOG_WARN("Unhandled " NAME " reloc\n"); \
	return

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols (e.g. TLS, G) are not yet implemented and are set to 0.
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_hexagon(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	ut64 bitmask = R_HEX_BITMASK_WORD32; // Mask of value and opcode bits.

	switch (rel_type) {
	default:
		RZ_LOG_WARN("Patching for hexagon reloc type %d not implemented.\n", rel_type);
		rz_warn_if_reached();
		// For more implementetations check out the LLVM src:
		// https://github.com/llvm/llvm-project/blob/abc17a67519747be36f1fd03e227c5103da4c677/lld/ELF/Arch/Hexagon.cpp
		return;
	case R_HEX_NONE:
		return;
	case R_HEX_GLOB_DAT:
	case R_HEX_JMP_SLOT:
		val = (fs->S + fs->A);
		break;
	case R_HEX_RELATIVE:
		val = (fs->B + fs->A);
		break;
	case R_HEX_B22_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B15_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B15;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B7_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B7;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_LO16:
		bitmask = R_HEX_BITMASK_WORD32_LO;
		val = (fs->S + fs->A);
		break;
	case R_HEX_HI16:
		bitmask = R_HEX_BITMASK_WORD32_HL;
		val = (fs->S + fs->A) >> 16;
		break;
	case R_HEX_32:
		val = (fs->S + fs->A);
		break;
	case R_HEX_16:
		bitmask = R_HEX_BITMASK_WORD16;
		val = (fs->S + fs->A);
		break;
	case R_HEX_8:
		bitmask = R_HEX_BITMASK_WORD8;
		val = (fs->S + fs->A);
		break;
	case R_HEX_HL16:
		bitmask = R_HEX_BITMASK_WORD32_HL;
		val = (fs->S + fs->A);
		break;
	case R_HEX_B13_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B13;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B9_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B9;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B32_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->P) >> 6;
		break;
	case R_HEX_32_6_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A) >> 6;
		break;
	case R_HEX_B22_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B15_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B15;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B13_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B13;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B9_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B9;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B7_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B7;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_12_X:
		bitmask = R_HEX_BITMASK_WORD32_R6;
		val = (fs->S + fs->A);
		break;
	case R_HEX_32_PCREL:
		val = (fs->S + fs->A - fs->P);
		break;
	case R_HEX_GOTREL_LO16:
		bitmask = R_HEX_BITMASK_WORD32_LO;
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_GOTREL_HI16:
		bitmask = R_HEX_BITMASK_WORD32_HL;
		val = (fs->S + fs->A - fs->GOT) >> 16;
		break;
	case R_HEX_GOTREL_32:
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_GOTREL_32_6_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->GOT) >> 6;
		break;
	case R_HEX_PLT_B22_PCREL:
	case R_HEX_LD_PLT_B22_PCREL:
	case R_HEX_GD_PLT_B22_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->L + fs->A - fs->P) >> 2;
		break;
	case R_HEX_GD_PLT_B22_PCREL_X:
	case R_HEX_LD_PLT_B22_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_GD_PLT_B32_PCREL_X:
	case R_HEX_LD_PLT_B32_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->P) >> 6;
		break;
	case R_HEX_16_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r16(rz_read_le32(buf));
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_11_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r11(rz_read_le32(buf));
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_10_X:
		bitmask = 0x00203fe0;
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_9_X:
		bitmask = 0x00003fe0;
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_8_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r8(rz_read_le32(buf));
		val = (fs->S + fs->A);
		break;
	case R_HEX_6_PCREL_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r6(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->P);
		break;
	case R_HEX_6_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r6(rz_read_le32(buf));
		val = (fs->S + fs->A);
		break;
	case R_HEX_GOTREL_16_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r16(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_GOTREL_11_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r11(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_DTPREL_32_6_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->T) >> 6;
		break;
	case R_HEX_DTPREL_16_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r16(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->T);
		break;
	case R_HEX_DTPREL_11_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r11(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->T);
		break;
	}
	// Patch two opcodes at once.
	if (rel_type == R_HEX_HL16) {
		patch_val_hexagon(buf_patched, patch_addr, bitmask, val & 0xffffffff);
		patch_val_hexagon(buf_patched, patch_addr + 4, bitmask, val >> 32);
	} else {
		patch_val_hexagon(buf_patched, patch_addr, bitmask, val);
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_mips(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;

	switch (rel_type) {
	default:
		RZ_LOG_WARN("Patching for mips reloc type %d not implemented.\n", rel_type);
		return;
	case R_MIPS_NONE:
		return;
	case R_MIPS_16: // S + sign–extend(A)
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		val = rz_read_ble16(buf, big_endian);
		val += fs->S + fs->A;
		rz_write_ble16(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		return;
	case R_MIPS_32: // S + A
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += fs->S + fs->A;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_REL32: // A – EA + S
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += fs->S + fs->A - fs->P;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_26: // (((A << 2) | (P & 0xf0000000) + S) >> 2
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += ((fs->A << 2) | (fs->P & 0xf0000000));
		val += fs->S;
		val >>= 2;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_HI16:
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		fs->AHL = rz_read_ble16(buf, big_endian) << 16;
		return;
	case R_MIPS_LO16:
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		val = rz_read_ble16(buf, big_endian);
		val += fs->AHL;
		val += fs->S;
		return;
	case R_MIPS_GPREL16: UNHANDL("R_MIPS_GPREL16");
	case R_MIPS_LITERAL: UNHANDL("R_MIPS_LITERAL");
	case R_MIPS_GOT16: UNHANDL("R_MIPS_GOT16");
	case R_MIPS_PC16: UNHANDL("R_MIPS_PC16");
	case R_MIPS_CALL16: UNHANDL("R_MIPS_CALL16");
	case R_MIPS_GPREL32: UNHANDL("R_MIPS_GPREL32");
	case R_MIPS_SHIFT5: UNHANDL("R_MIPS_SHIFT5");
	case R_MIPS_SHIFT6: UNHANDL("R_MIPS_SHIFT6");
	case R_MIPS_64: UNHANDL("R_MIPS_64");
	case R_MIPS_GOT_DISP: UNHANDL("R_MIPS_GOT_DISP");
	case R_MIPS_GOT_PAGE: UNHANDL("R_MIPS_GOT_PAGE");
	case R_MIPS_GOT_OFST: UNHANDL("R_MIPS_GOT_OFST");
	case R_MIPS_GOT_HI16: UNHANDL("R_MIPS_GOT_HI16");
	case R_MIPS_GOT_LO16: UNHANDL("R_MIPS_GOT_LO16");
	case R_MIPS_SUB: UNHANDL("R_MIPS_SUB");
	case R_MIPS_INSERT_A: UNHANDL("R_MIPS_INSERT_A");
	case R_MIPS_INSERT_B: UNHANDL("R_MIPS_INSERT_B");
	case R_MIPS_DELETE: UNHANDL("R_MIPS_DELETE");
	case R_MIPS_HIGHER: UNHANDL("R_MIPS_HIGHER");
	case R_MIPS_HIGHEST: UNHANDL("R_MIPS_HIGHEST");
	case R_MIPS_CALL_HI16: UNHANDL("R_MIPS_CALL_HI16");
	case R_MIPS_CALL_LO16: UNHANDL("R_MIPS_CALL_LO16");
	case R_MIPS_SCN_DISP: UNHANDL("R_MIPS_SCN_DISP");
	case R_MIPS_REL16: UNHANDL("R_MIPS_REL16");
	case R_MIPS_ADD_IMMEDIATE: UNHANDL("R_MIPS_ADD_IMMEDIATE");
	case R_MIPS_PJUMP: UNHANDL("R_MIPS_PJUMP");
	case R_MIPS_RELGOT: UNHANDL("R_MIPS_RELGOT");
	case R_MIPS_JALR: UNHANDL("R_MIPS_JALR");
	case R_MIPS_TLS_DTPMOD32: UNHANDL("R_MIPS_TLS_DTPMOD32");
	case R_MIPS_TLS_DTPREL32: UNHANDL("R_MIPS_TLS_DTPREL32");
	case R_MIPS_TLS_DTPMOD64: UNHANDL("R_MIPS_TLS_DTPMOD64");
	case R_MIPS_TLS_DTPREL64: UNHANDL("R_MIPS_TLS_DTPREL64");
	case R_MIPS_TLS_GD: UNHANDL("R_MIPS_TLS_GD");
	case R_MIPS_TLS_LDM: UNHANDL("R_MIPS_TLS_LDM");
	case R_MIPS_TLS_DTPREL_HI16: UNHANDL("R_MIPS_TLS_DTPREL_HI16");
	case R_MIPS_TLS_DTPREL_LO16: UNHANDL("R_MIPS_TLS_DTPREL_LO16");
	case R_MIPS_TLS_GOTTPREL: UNHANDL("R_MIPS_TLS_GOTTPREL");
	case R_MIPS_TLS_TPREL32: UNHANDL("R_MIPS_TLS_TPREL32");
	case R_MIPS_TLS_TPREL64: UNHANDL("R_MIPS_TLS_TPREL64");
	case R_MIPS_TLS_TPREL_HI16: UNHANDL("R_MIPS_TLS_TPREL_HI16");
	case R_MIPS_TLS_TPREL_LO16: UNHANDL("R_MIPS_TLS_TPREL_LO16");
	case R_MIPS_GLOB_DAT: UNHANDL("R_MIPS_GLOB_DAT");
	case R_MIPS_COPY: UNHANDL("R_MIPS_COPY");
	case R_MIPS_JUMP_SLOT: UNHANDL("R_MIPS_JUMP_SLOT");
	case R_MICROMIPS_26_S1: UNHANDL("R_MICROMIPS_26_S1");
	case R_MICROMIPS_HI16: UNHANDL("R_MICROMIPS_HI16");
	case R_MICROMIPS_LO16: UNHANDL("R_MICROMIPS_LO16");
	case R_MICROMIPS_GPREL16: UNHANDL("R_MICROMIPS_GPREL16");
	case R_MICROMIPS_LITERAL: UNHANDL("R_MICROMIPS_LITERAL");
	case R_MICROMIPS_GOT16: UNHANDL("R_MICROMIPS_GOT16");
	case R_MICROMIPS_PC7_S1: UNHANDL("R_MICROMIPS_PC7_S1");
	case R_MICROMIPS_PC10_S1: UNHANDL("R_MICROMIPS_PC10_S1");
	case R_MICROMIPS_PC16_S1: UNHANDL("R_MICROMIPS_PC16_S1");
	case R_MICROMIPS_CALL16: UNHANDL("R_MICROMIPS_CALL16");
	case R_MICROMIPS_GOT_DISP: UNHANDL("R_MICROMIPS_GOT_DISP");
	case R_MICROMIPS_GOT_PAGE: UNHANDL("R_MICROMIPS_GOT_PAGE");
	case R_MICROMIPS_GOT_OFST: UNHANDL("R_MICROMIPS_GOT_OFST");
	case R_MICROMIPS_GOT_HI16: UNHANDL("R_MICROMIPS_GOT_HI16");
	case R_MICROMIPS_GOT_LO16: UNHANDL("R_MICROMIPS_GOT_LO16");
	case R_MICROMIPS_SUB: UNHANDL("R_MICROMIPS_SUB");
	case R_MICROMIPS_HIGHER: UNHANDL("R_MICROMIPS_HIGHER");
	case R_MICROMIPS_HIGHEST: UNHANDL("R_MICROMIPS_HIGHEST");
	case R_MICROMIPS_CALL_HI16: UNHANDL("R_MICROMIPS_CALL_HI16");
	case R_MICROMIPS_CALL_LO16: UNHANDL("R_MICROMIPS_CALL_LO16");
	case R_MICROMIPS_SCN_DISP: UNHANDL("R_MICROMIPS_SCN_DISP");
	case R_MICROMIPS_JALR: UNHANDL("R_MICROMIPS_JALR");
	case R_MICROMIPS_HI0_LO16: UNHANDL("R_MICROMIPS_HI0_LO16");
	case R_MICROMIPS_TLS_GD: UNHANDL("R_MICROMIPS_TLS_GD");
	case R_MICROMIPS_TLS_LDM: UNHANDL("R_MICROMIPS_TLS_LDM");
	case R_MICROMIPS_TLS_DTPREL_HI16: UNHANDL("R_MICROMIPS_TLS_DTPREL_HI16");
	case R_MICROMIPS_TLS_DTPREL_LO16: UNHANDL("R_MICROMIPS_TLS_DTPREL_LO16");
	case R_MICROMIPS_TLS_GOTTPREL: UNHANDL("R_MICROMIPS_TLS_GOTTPREL");
	case R_MICROMIPS_TLS_TPREL_HI16: UNHANDL("R_MICROMIPS_TLS_TPREL_HI16");
	case R_MICROMIPS_TLS_TPREL_LO16: UNHANDL("R_MICROMIPS_TLS_TPREL_LO16");
	case R_MICROMIPS_GPREL7_S2: UNHANDL("R_MICROMIPS_GPREL7_S2");
	case R_MICROMIPS_PC23_S2: UNHANDL("R_MICROMIPS_PC23_S2");
	case R_MIPS_PC32: UNHANDL("R_MIPS_PC32");
	case R_MIPS_EH: UNHANDL("R_MIPS_EH");
	case R_MIPS_GNU_REL16_S2: UNHANDL("R_MIPS_GNU_REL16_S2");
	case R_MIPS_GNU_VTINHERIT: UNHANDL("R_MIPS_GNU_VTINHERIT");
	case R_MIPS_GNU_VTENTRY: UNHANDL("R_MIPS_GNU_VTENTRY");
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel The relocation elf structure.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_arm(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const RzBinElfReloc *rel, bool big_endian, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && rel && fs);
	ut16 keephw1 = 0, keephw2 = 0;
	ut32 nbytes = 4;
	ut8 buf[4] = { 0 };
	ut64 val = 0;

	rz_buf_read_at(buf_patched, patch_addr, buf, 4);
	switch (rel->type) {
	case R_ARM_NONE:
		return;
	case R_ARM_THM_JUMP24:
		/* fall-thru */
	case R_ARM_THM_PC22:
		// Encoding B  T4, BL T1, BLX T2: Val = S:I1:I2:imm10:imm11:0
		// I1 = NOT(J1 EOR S)
		// I2 = NOT(J2 EOR S)
		val = fs->S + fs->A;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);
		rz_write_ble16(&buf[0],
			(keephw1 & 0xF800U) | // opcode
				((val >> 14) & 0x0400U) | // sign
				((val >> 12) & 0x03FFU), // imm 10
			big_endian);
		rz_write_ble16(&buf[2],
			(keephw2 & 0xD000U) | // opcode
				(((~(val >> 10)) ^ (val >> 11)) & 0x2000) | // J1
				(((~(val >> 11)) ^ (val >> 13)) & 0x0800) | // J2
				((val >> 1) & 0x07ff), // imm11
			big_endian);
		break;
	default:
		val = fs->S + fs->A;
		if (!rel->sym && rel->mode == DT_REL) {
			val += rz_read_ble32(buf, big_endian);
		}
		rz_write_ble32(buf, val, big_endian);
		break;
	}
	rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel The relocation elf structure.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_arm64(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const RzBinElfReloc *rel, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && rel && fs);
// AARCH64-specific defines
// Take the PAGE component of an address or offset.
#define PG(x)         ((x) & ~0xFFFULL)
#define PG_OFFSET(x)  ((x)&0xFFFULL)
#define ADR_IMM_MASK1 (((1U << 2) - 1) << 29)
#define ADR_IMM_MASK2 (((1U << 19) - 1) << 5)
#define ADR_IMM_MASK3 (((1U << 19) - 1) << 2)

	ut32 keep = 0;
	ut32 nbytes = 4;
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	rz_buf_read_at(buf_patched, patch_addr, buf, 8);
	switch (rel->type) {
	case R_AARCH64_NONE:
		return;
	case R_AARCH64_ABS16:
		val = fs->S + fs->A;
		rz_write_le16(buf, val);
		nbytes = 2;
		break;
	case R_AARCH64_ABS32:
		val = fs->S + fs->A;
		rz_write_le32(buf, val);
		break;
	case R_AARCH64_GLOB_DAT:
	/* fall-thru */
	case R_AARCH64_ABS64:
	/* fall-thru */
	case R_AARCH64_JUMP_SLOT:
		val = fs->S + fs->A;
		rz_write_le64(buf, val);
		nbytes = 8;
		break;
	case R_AARCH64_PREL16:
		val = fs->S + fs->A - fs->P;
		rz_write_le16(buf, val);
		nbytes = 2;
		break;
	case R_AARCH64_PREL32:
		val = fs->S + fs->A - fs->P;
		rz_write_le32(buf, val);
		break;
	case R_AARCH64_PREL64:
		val = fs->S + fs->A - fs->P;
		rz_write_le64(buf, val);
		nbytes = 8;
		break;
	case R_AARCH64_RELATIVE:
		val = fs->B + fs->A;
		rz_write_le64(buf, val);
		nbytes = 8;
		break;
	case R_AARCH64_ADR_PREL_PG_HI21:
	/* fall-thru */
	case R_AARCH64_ADR_PREL_PG_HI21_NC:
	/* fall-thru */
	case R_AARCH64_ADR_GOT_PAGE:
		// Reencode ADR imm
		keep = rz_read_le32(buf) & ~(ADR_IMM_MASK1 | ADR_IMM_MASK2);
		val = ((st64)(PG(fs->S + fs->A) - PG(fs->P))) >> 12;
		rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(2, 0)) << 29) | ((val & ADR_IMM_MASK3) << 3));
		break;
	case R_AARCH64_JUMP26:
	/* fall-thru */
	case R_AARCH64_CALL26:
		// Reencode 26 bits of the offset
		keep = rz_read_le32(buf) & ~RZ_BIT_MASK32(26, 0);
		val = ((st64)(fs->S + fs->A - fs->P)) >> 2;
		rz_write_le32(buf, keep | (val & RZ_BIT_MASK32(26, 0)));
		break;
	case R_AARCH64_LDST8_ABS_LO12_NC:
	/* fall-thru */
	case R_AARCH64_ADD_ABS_LO12_NC:
		keep = rz_read_le32(buf) & ~(RZ_BIT_MASK32(12, 0) << 10);
		val = PG_OFFSET(fs->S + fs->A);
		rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(12, 0)) << 10));
		break;
	case R_AARCH64_LD64_GOT_LO12_NC:
	/* fall-thru */
	case R_AARCH64_LDST64_ABS_LO12_NC:
		// Reencode LD/ST imm
		keep = rz_read_le32(buf) & ~(RZ_BIT_MASK32(12, 0) << 10);
		val = PG_OFFSET(fs->S + fs->A) >> 3;
		rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(12, 0)) << 10));
		break;
	default:
		RZ_LOG_WARN("Patching for aarch64 reloc type %d not implemented.\n", rel->type);
		return;
	}
	rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);

#undef PG
#undef PG_OFFSET
#undef ADR_IMM_MASK1
#undef ADR_IMM_MASK2
#undef ADR_IMM_MASK3
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_ppc64(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	ut32 low = 0, word = 0;
	switch (rel_type) {
	case R_PPC64_NONE:
		return;
	case R_PPC64_ADDR24:
		low = 24;
		val = (fs->S + fs->A) >> 2;
		break;
	case R_PPC64_ADDR16_HI:
		word = 2;
		val = (fs->S + fs->A) >> 16;
		break;
	case R_PPC64_ADDR16_HA:
		word = 2;
		val = (fs->S + fs->A + 0x8000) >> 16;
		break;
	case R_PPC64_REL16_HA:
		word = 2;
		val = (fs->S + fs->A - fs->P + 0x8000) >> 16;
		break;
	case R_PPC64_ADDR16_LO:
		word = 2;
		val = (fs->S + fs->A) & 0xffff;
		break;
	case R_PPC64_REL16_LO:
		word = 2;
		val = (fs->S + fs->A - fs->P) & 0xffff;
		break;
	case R_PPC64_REL14:
		low = 14;
		val = (st64)(fs->S + fs->A - fs->P) >> 2;
		break;
	case R_PPC64_REL24:
		low = 24;
		val = (st64)(fs->S + fs->A - fs->P) >> 2;
		break;
	case R_PPC64_REL32:
		word = 4;
		val = fs->S + fs->A - fs->P;
		break;
	default:
		RZ_LOG_WARN("Patching for ppc64 reloc type %d not implemented.\n", rel_type);
		return;
	}
	if (low) {
		switch (low) {
		case 14:
			val &= (1 << 14) - 1;
			rz_buf_read_at(buf_patched, patch_addr, buf, 2);
			rz_write_ble32(buf, (rz_read_ble32(buf, big_endian) & ~(RZ_BIT_MASK32(16, 2))) | val << 2, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 2);
			break;
		case 24:
			val &= (1 << 24) - 1;
			rz_buf_read_at(buf_patched, patch_addr, buf, 4);
			rz_write_ble32(buf, (rz_read_ble32(buf, big_endian) & ~(RZ_BIT_MASK32(26, 2))) | val << 2, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 4);
			break;
		default:
			RZ_LOG_WARN("Unhandled ppc64 reloc type %d with low %u bits.\n", rel_type, low);
			return;
		}
	} else if (word) {
		switch (word) {
		case 2:
			rz_write_ble16(buf, val, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 2);
			break;
		case 4:
			rz_write_ble32(buf, val, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 4);
			break;
		default:
			RZ_LOG_WARN("Unhandled ppc64 reloc type %d with word size %u.\n", rel_type, word);
			return;
		}
	} else {
		RZ_LOG_WARN("Unhandled ppc64 reloc type %d.\n", rel_type);
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_intel_80386(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;
	switch (rel_type) {
	case R_386_NONE:
		return;
	case R_386_32:
		/* fall-thru */
	case R_386_PC32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_le32(buf) + fs->S + fs->A;
		if (rel_type == R_386_PC32) {
			val -= fs->P;
		}
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	default:
		RZ_LOG_WARN("Unhandled intel 80386 reloc type %d.\n", rel_type);
		return;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_amd64(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	int word = 0;
	switch (rel_type) {
	case R_X86_64_NONE:
		/* fall-thru */
	case R_X86_64_COPY:
		return;
	case R_X86_64_8:
		word = 1;
		val = fs->S + fs->A;
		break;
	case R_X86_64_16:
		word = 2;
		val = fs->S + fs->A;
		break;
	case R_X86_64_32:
		/* fall-thru */
	case R_X86_64_32S:
		word = 4;
		val = fs->S + fs->A;
		break;
	case R_X86_64_64:
		word = 8;
		val = fs->S + fs->A;
		break;
	case R_X86_64_GLOB_DAT:
		/* fall-thru */
	case R_X86_64_JUMP_SLOT:
		word = 4;
		val = fs->S;
		break;
	case R_X86_64_PC8:
		word = 1;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PC16:
		word = 2;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PC32:
		word = 4;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PC64:
		word = 8;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PLT32:
		word = 4;
		val = fs->L + fs->A - fs->P;
		break;
	case R_X86_64_RELATIVE:
		word = 8;
		val = fs->B + fs->A;
		break;
	default:
		RZ_LOG_WARN("Unhandled x64 reloc type %d.\n", rel_type);
		return;
	}
	switch (word) {
	default:
		break;
	case 1:
		buf[0] = val;
		rz_buf_write_at(buf_patched, patch_addr, buf, 1);
		break;
	case 2:
		rz_write_le16(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		break;
	case 4:
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case 8:
		rz_write_le64(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 8);
		break;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_rx(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;
	// no dynamic for rx-elf program, handle rx elf object reloc type (emulate linkage map)
	// and no GOT/PLT for existed for rx-elf, leave no imports info for extern symbol
	switch (rel_type) {
	// simply use rizin default symbol resolution to map OBJECT variable symbol to vaddr
	case R_RX_NONE:
		return;
	case R_RX_DIR32:
		val = fs->S + fs->A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_RX_DIR24S_PCREL:
		val = fs->S + fs->A - fs->P + 1;
		if (big_endian) {
			buf[2] = val;
			buf[1] = val >> 8;
			buf[0] = val >> 16;
		} else {
			buf[0] = val;
			buf[1] = val >> 8;
			buf[2] = val >> 16;
		}
		// write 3 Bytes
		rz_buf_write_at(buf_patched, patch_addr, buf, 3);
		break;
	default:
		RZ_LOG_WARN("Unhandled renesas rx family reloc type %d.\n", rel_type);
		return;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_alpha(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RzBinRelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;

	switch (rel_type) {
	case R_ALPHA_NONE:
		return;
	case R_ALPHA_REFLONG:
		val = fs->S + fs->A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_ALPHA_REFQUAD:
		val = fs->S + fs->A;
		rz_buf_write_ble64_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_ALPHA_SREL16:
		val = fs->S + fs->A - fs->P + 1;
		if (big_endian) {
			buf[1] = val;
			buf[0] = val >> 8;
		} else {
			buf[0] = val;
			buf[1] = val >> 8;
		}
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		break;
	case R_ALPHA_SREL32:
		val = fs->S + fs->A - fs->P + 1;
		if (big_endian) {
			buf[3] = val;
			buf[2] = val >> 8;
			buf[1] = val >> 16;
			buf[0] = val >> 24;
		} else {
			buf[0] = val;
			buf[1] = val >> 8;
			buf[2] = val >> 16;
			buf[3] = val >> 24;
		}
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	default:
		RZ_LOG_WARN("Unhandled alpha reloc type %d.\n", rel_type);
		return;
	}
}

#undef UNHANDL

#define MISSING(NAME) \
	RZ_LOG_WARN("Unhandled reloc patching for machine " NAME ".\n"); \
	return

static void patch_reloc(struct Elf_(rz_bin_elf_obj_t) * obj, RzBinElfReloc *rel, ut64 S, ut64 B, ut64 L, ut64 GOT, ut64 *AHL) {
	ut16 e_machine = obj->ehdr.e_machine;
	RzBinRelocFormularSymbols formular_sym = {
		.A = rel->addend,
		.B = B,
		.GOT = GOT,
		.L = L,
		.S = S,
		.P = rel->vaddr,
		.MB = 0,
		.G = 0,
		.GP = 0,
		.T = 0,
		.TLS = 0,
		.AHL = *AHL,
	};
	ut64 patch_addr = rel->paddr != UT64_MAX ? rel->paddr : Elf_(rz_bin_elf_v2p)(obj, rel->vaddr);
	bool big_endian = obj->big_endian;
	switch (e_machine) {
	case EM_QDSP6:
		patch_reloc_hexagon(obj->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_ARM:
		patch_reloc_arm(obj->buf_patched, patch_addr, rel, big_endian, &formular_sym);
		break;
	case EM_AARCH64:
		patch_reloc_arm64(obj->buf_patched, patch_addr, rel, &formular_sym);
		break;
	case EM_PPC64:
		patch_reloc_ppc64(obj->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_MIPS_X:
		/* fall-thru */
	case EM_MIPS_RS3_LE:
		/* fall-thru */
	case EM_MIPS:
		patch_reloc_mips(obj->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		// This is a special value used only in mips
		// An R_MIPS_HI16 must be followed immediately by an R_MIPS_LO16 relocation record in a SHT_REL section.
		// The contents of the two fields to be relocated are combined to form a full 32-bit addend AHL.
		*AHL = formular_sym.AHL;
		break;
	case EM_386:
		patch_reloc_intel_80386(obj->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_X86_64:
		patch_reloc_amd64(obj->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_RX:
		patch_reloc_rx(obj->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_ALPHA:
		patch_reloc_alpha(obj->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_M32: MISSING("EM_M32");
	case EM_SPARC: MISSING("EM_SPARC");
	case EM_68K: MISSING("EM_68K");
	case EM_88K: MISSING("EM_88K");
	case EM_IAMCU: MISSING("EM_IAMCU");
	case EM_860: MISSING("EM_860");
	case EM_S370: MISSING("EM_S370");
	case EM_PARISC: MISSING("EM_PARISC");
	case EM_VPP500: MISSING("EM_VPP500");
	case EM_SPARC32PLUS: MISSING("EM_SPARC32PLUS");
	case EM_960: MISSING("EM_960");
	case EM_PPC: MISSING("EM_PPC");
	case EM_S390: MISSING("EM_S390");
	case EM_SPU: MISSING("EM_SPU");
	case EM_V800: MISSING("EM_V800");
	case EM_FR20: MISSING("EM_FR20");
	case EM_RH32: MISSING("EM_RH32");
	case EM_RCE: MISSING("EM_RCE");
	case EM_FAKE_ALPHA: MISSING("EM_FAKE_ALPHA");
	case EM_SH: MISSING("EM_SH");
	case EM_SPARCV9: MISSING("EM_SPARCV9");
	case EM_TRICORE: MISSING("EM_TRICORE");
	case EM_ARC: MISSING("EM_ARC");
	case EM_H8_300: MISSING("EM_H8_300");
	case EM_H8_300H: MISSING("EM_H8_300H");
	case EM_H8S: MISSING("EM_H8S");
	case EM_H8_500: MISSING("EM_H8_500");
	case EM_IA_64: MISSING("EM_IA_64");
	case EM_COLDFIRE: MISSING("EM_COLDFIRE");
	case EM_68HC12: MISSING("EM_68HC12");
	case EM_MMA: MISSING("EM_MMA");
	case EM_PCP: MISSING("EM_PCP");
	case EM_NCPU: MISSING("EM_NCPU");
	case EM_NDR1: MISSING("EM_NDR1");
	case EM_STARCORE: MISSING("EM_STARCORE");
	case EM_ME16: MISSING("EM_ME16");
	case EM_ST100: MISSING("EM_ST100");
	case EM_TINYJ: MISSING("EM_TINYJ");
	case EM_PDSP: MISSING("EM_PDSP");
	case EM_PDP10: MISSING("EM_PDP10");
	case EM_PDP11: MISSING("EM_PDP11");
	case EM_FX66: MISSING("EM_FX66");
	case EM_ST9PLUS: MISSING("EM_ST9PLUS");
	case EM_ST7: MISSING("EM_ST7");
	case EM_68HC16: MISSING("EM_68HC16");
	case EM_68HC11: MISSING("EM_68HC11");
	case EM_68HC08: MISSING("EM_68HC08");
	case EM_68HC05: MISSING("EM_68HC05");
	case EM_SVX: MISSING("EM_SVX");
	case EM_ST19: MISSING("EM_ST19");
	case EM_VAX: MISSING("EM_VAX");
	case EM_CRIS: MISSING("EM_CRIS");
	case EM_JAVELIN: MISSING("EM_JAVELIN");
	case EM_FIREPATH: MISSING("EM_FIREPATH");
	case EM_ZSP: MISSING("EM_ZSP");
	case EM_MMIX: MISSING("EM_MMIX");
	case EM_HUANY: MISSING("EM_HUANY");
	case EM_PRISM: MISSING("EM_PRISM");
	case EM_AVR: MISSING("EM_AVR");
	case EM_FR30: MISSING("EM_FR30");
	case EM_D10V: MISSING("EM_D10V");
	case EM_D30V: MISSING("EM_D30V");
	case EM_V850: MISSING("EM_V850");
	case EM_M32R: MISSING("EM_M32R");
	case EM_MN10300: MISSING("EM_MN10300");
	case EM_MN10200: MISSING("EM_MN10200");
	case EM_PJ: MISSING("EM_PJ");
	case EM_OR1K: MISSING("EM_OR1K");
	case EM_ARC_COMPACT: MISSING("EM_ARC_COMPACT");
	case EM_XTENSA: MISSING("EM_XTENSA");
	case EM_VIDEOCORE: MISSING("EM_VIDEOCORE");
	case EM_TMM_GPP: MISSING("EM_TMM_GPP");
	case EM_NS32K: MISSING("EM_NS32K");
	case EM_TPC: MISSING("EM_TPC");
	case EM_SNP1K: MISSING("EM_SNP1K");
	case EM_ST200: MISSING("EM_ST200");
	case EM_IP2K: MISSING("EM_IP2K");
	case EM_MAX: MISSING("EM_MAX");
	case EM_CR: MISSING("EM_CR");
	case EM_F2MC16: MISSING("EM_F2MC16");
	case EM_MSP430: MISSING("EM_MSP430");
	case EM_BLACKFIN: MISSING("EM_BLACKFIN");
	case EM_SE_C33: MISSING("EM_SE_C33");
	case EM_SEP: MISSING("EM_SEP");
	case EM_ARCA: MISSING("EM_ARCA");
	case EM_UNICORE: MISSING("EM_UNICORE");
	case EM_EXCESS: MISSING("EM_EXCESS");
	case EM_DXP: MISSING("EM_DXP");
	case EM_ALTERA_NIOS2: MISSING("EM_ALTERA_NIOS2");
	case EM_CRX: MISSING("EM_CRX");
	case EM_XGATE: MISSING("EM_XGATE");
	case EM_C166: MISSING("EM_C166");
	case EM_M16C: MISSING("EM_M16C");
	case EM_DSPIC30F: MISSING("EM_DSPIC30F");
	case EM_CE: MISSING("EM_CE");
	case EM_M32C: MISSING("EM_M32C");
	case EM_TSK3000: MISSING("EM_TSK3000");
	case EM_RS08: MISSING("EM_RS08");
	case EM_SHARC: MISSING("EM_SHARC");
	case EM_ECOG2: MISSING("EM_ECOG2");
	case EM_SCORE7: MISSING("EM_SCORE7");
	case EM_DSP24: MISSING("EM_DSP24");
	case EM_VIDEOCORE3: MISSING("EM_VIDEOCORE3");
	case EM_LATTICEMICO32: MISSING("EM_LATTICEMICO32");
	case EM_SE_C17: MISSING("EM_SE_C17");
	case EM_TI_C6000: MISSING("EM_TI_C6000");
	case EM_TI_C2000: MISSING("EM_TI_C2000");
	case EM_TI_C5500: MISSING("EM_TI_C5500");
	case EM_TI_ARP32: MISSING("EM_TI_ARP32");
	case EM_TI_PRU: MISSING("EM_TI_PRU");
	case EM_MMDSP_PLUS: MISSING("EM_MMDSP_PLUS");
	case EM_CYPRESS_M8C: MISSING("EM_CYPRESS_M8C");
	case EM_R32C: MISSING("EM_R32C");
	case EM_TRIMEDIA: MISSING("EM_TRIMEDIA");
	case EM_8051: MISSING("EM_8051");
	case EM_STXP7X: MISSING("EM_STXP7X");
	case EM_NDS32: MISSING("EM_NDS32");
	case EM_ECOG1X: MISSING("EM_ECOG1X");
	case EM_MAXQ30: MISSING("EM_MAXQ30");
	case EM_XIMO16: MISSING("EM_XIMO16");
	case EM_MANIK: MISSING("EM_MANIK");
	case EM_CRAYNV2: MISSING("EM_CRAYNV2");
	case EM_METAG: MISSING("EM_METAG");
	case EM_MCST_ELBRUS: MISSING("EM_MCST_ELBRUS");
	case EM_ECOG16: MISSING("EM_ECOG16");
	case EM_CR16: MISSING("EM_CR16");
	case EM_ETPU: MISSING("EM_ETPU");
	case EM_SLE9X: MISSING("EM_SLE9X");
	case EM_L10M: MISSING("EM_L10M");
	case EM_K10M: MISSING("EM_K10M");
	case EM_AVR32: MISSING("EM_AVR32");
	case EM_STM8: MISSING("EM_STM8");
	case EM_TILE64: MISSING("EM_TILE64");
	case EM_TILEPRO: MISSING("EM_TILEPRO");
	case EM_MICROBLAZE: MISSING("EM_MICROBLAZE");
	case EM_CUDA: MISSING("EM_CUDA");
	case EM_TILEGX: MISSING("EM_TILEGX");
	case EM_CLOUDSHIELD: MISSING("EM_CLOUDSHIELD");
	case EM_COREA_1ST: MISSING("EM_COREA_1ST");
	case EM_COREA_2ND: MISSING("EM_COREA_2ND");
	case EM_ARCV2: MISSING("EM_ARCV2");
	case EM_OPEN8: MISSING("EM_OPEN8");
	case EM_RL78: MISSING("EM_RL78");
	case EM_VIDEOCORE5: MISSING("EM_VIDEOCORE5");
	case EM_78KOR: MISSING("EM_78KOR");
	case EM_56800EX: MISSING("EM_56800EX");
	case EM_BA1: MISSING("EM_BA1");
	case EM_BA2: MISSING("EM_BA2");
	case EM_XCORE: MISSING("EM_XCORE");
	case EM_MCHP_PIC: MISSING("EM_MCHP_PIC");
	case EM_KM32: MISSING("EM_KM32");
	case EM_KMX32: MISSING("EM_KMX32");
	case EM_EMX16: MISSING("EM_EMX16");
	case EM_EMX8: MISSING("EM_EMX8");
	case EM_KVARC: MISSING("EM_KVARC");
	case EM_CDP: MISSING("EM_CDP");
	case EM_COGE: MISSING("EM_COGE");
	case EM_COOL: MISSING("EM_COOL");
	case EM_NORC: MISSING("EM_NORC");
	case EM_CSR_KALIMBA: MISSING("EM_CSR_KALIMBA");
	case EM_Z80: MISSING("EM_Z80");
	case EM_VISIUM: MISSING("EM_VISIUM");
	case EM_FT32: MISSING("EM_FT32");
	case EM_MOXIE: MISSING("EM_MOXIE");
	case EM_AMDGPU: MISSING("EM_AMDGPU");
	case EM_LANAI_OLD: MISSING("EM_LANAI_OLD");
	case EM_CEVA: MISSING("EM_CEVA");
	case EM_CEVA_X2: MISSING("EM_CEVA_X2");
	case EM_BPF: MISSING("EM_BPF");
	case EM_GRAPHCORE_IPU: MISSING("EM_GRAPHCORE_IPU");
	case EM_IMG1: MISSING("EM_IMG1");
	case EM_NFP: MISSING("EM_NFP");
	case EM_VE: MISSING("EM_VE");
	case EM_CSKY: MISSING("EM_CSKY");
	case EM_ARC_COMPACT3_64: MISSING("EM_ARC_COMPACT3_64");
	case EM_MCS6502: MISSING("EM_MCS6502");
	case EM_ARC_COMPACT3: MISSING("EM_ARC_COMPACT3");
	case EM_KVX: MISSING("EM_KVX");
	case EM_65816: MISSING("EM_65816");
	case EM_LOONGARCH: MISSING("EM_LOONGARCH");
	case EM_KF32: MISSING("EM_KF32");
	case EM_U16_U8CORE: MISSING("EM_U16_U8CORE");
	case EM_TACHYUM: MISSING("EM_TACHYUM");
	case EM_56800EF: MISSING("EM_56800EF");
	case EM_AVR_OLD: MISSING("EM_AVR_OLD");
	case EM_MSP430_OLD: MISSING("EM_MSP430_OLD");
	case EM_MT: MISSING("EM_MT");
	case EM_CYGNUS_FR30: MISSING("EM_CYGNUS_FR30");
	case EM_WEBASSEMBLY: MISSING("EM_WEBASSEMBLY");
	case EM_S12Z: MISSING("EM_S12Z");
	case EM_DLX: MISSING("EM_DLX");
	case EM_CYGNUS_FRV: MISSING("EM_CYGNUS_FRV");
	case EM_XC16X: MISSING("EM_XC16X");
	case EM_CYGNUS_D10V: MISSING("EM_CYGNUS_D10V");
	case EM_CYGNUS_D30V: MISSING("EM_CYGNUS_D30V");
	case EM_IP2K_OLD: MISSING("EM_IP2K_OLD");
	case EM_CYGNUS_POWERPC: MISSING("EM_CYGNUS_POWERPC");
	case EM_CYGNUS_M32R: MISSING("EM_CYGNUS_M32R");
	case EM_CYGNUS_V850: MISSING("EM_CYGNUS_V850");
	case EM_S390_OLD: MISSING("EM_S390_OLD");
	case EM_XTENSA_OLD: MISSING("EM_XTENSA_OLD");
	case EM_XSTORMY16: MISSING("EM_XSTORMY16");
	case EM_CYGNUS_MN10300: MISSING("EM_CYGNUS_MN10300");
	case EM_CYGNUS_MN10200: MISSING("EM_CYGNUS_MN10200");
	case EM_M32C_OLD: MISSING("EM_M32C_OLD");
	case EM_IQ2000: MISSING("EM_IQ2000");
	case EM_NIOS32: MISSING("EM_NIOS32");
	case EM_CYGNUS_MEP: MISSING("EM_CYGNUS_MEP");
	case EM_MOXIE_OLD: MISSING("EM_MOXIE_OLD");
	case EM_MICROBLAZE_OLD: MISSING("EM_MICROBLAZE_OLD");
	case EM_ADAPTEVA_EPIPHANY: MISSING("EM_ADAPTEVA_EPIPHANY");
	case EM_V810: MISSING("EM_V810");
	default:
		RZ_LOG_INFO("Unhandled reloc patching for machine %d.\n", (int)e_machine);
	}
}

#undef MISSING

static ut64 get_got_addr(ELFOBJ *bin) {
	if (!Elf_(rz_bin_elf_has_sections)(bin)) {
		return 0;
	}

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".got");
	if (section) {
		return section->offset;
	}

	section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".got.plt");
	if (section) {
		return section->offset;
	}

	return 0;
}

static RzBinReloc *reloc_convert_new(ELFOBJ *bin, RzBinElfReloc *rel) {
	RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
	if (!reloc) {
		return NULL;
	}

	reloc->addend = rel->addend;
	if (rel->sym) {
		reloc->import = get_import(bin, rel->sym);
		if (!reloc->import) {
			reloc->symbol = get_symbol(bin, rel->sym);
		}
	}
	reloc->vaddr = rel->vaddr;
	reloc->paddr = rel->paddr;
	reloc->target_vaddr = rel->target_vaddr;

	RzBinElfSection *section = rel->section > 0 ? Elf_(rz_bin_elf_get_section)(bin, rel->section) : NULL;
	if (section) {
		reloc->section_vaddr = section->rva;
	}
	return reloc;
}

static RzBinReloc *reloc_convert_set(ELFOBJ *bin, RzBinElfReloc *rel, RzBinRelocType type, const char *print_name) {
	RzBinReloc *r = reloc_convert_new(bin, rel);
	if (!r) {
		return NULL;
	}

	r->type = type;
	r->print_name = print_name;
	return r;
}

static RzBinReloc *reloc_convert_add(ELFOBJ *bin, RzBinElfReloc *rel, RzBinRelocType type, st64 addend, const char *print_name) {
	RzBinReloc *r = reloc_convert_new(bin, rel);
	if (!r) {
		return NULL;
	}

	r->addend += addend;
	r->type = type;
	r->print_name = print_name;
	return r;
}

static RzBinReloc *reloc_convert_vaddr(ELFOBJ *bin, RzBinElfReloc *rel, RzBinRelocType type, ut64 vaddr, const char *print_name) {
	RzBinReloc *r = reloc_convert_new(bin, rel);
	if (!r) {
		return NULL;
	}

	r->vaddr = vaddr;
	r->type = type;
	r->print_name = print_name;
	return r;
}

static RzBinReloc *reloc_convert_ifunc(ELFOBJ *bin, RzBinElfReloc *rel, RzBinRelocType type, const char *print_name) {
	RzBinReloc *r = reloc_convert_new(bin, rel);
	if (!r) {
		return NULL;
	}

	r->is_ifunc = true;
	r->type = type;
	r->print_name = print_name;
	return r;
}

#define UNSUPP(ARCH_NAME) \
	RZ_LOG_WARN("Unsupported ELF " ARCH_NAME " reloc %d\n", rel->type); \
	return reloc_convert_new(bin, rel)

#define UNHANDL(RELOC_NAME) \
	return reloc_convert_set(bin, rel, 0, RELOC_NAME)

#define SET(BIT_SIZE, RELOC_NAME) \
	return reloc_convert_set(bin, rel, RZ_BIN_RELOC_##BIT_SIZE, RELOC_NAME)

#define SET(BIT_SIZE, RELOC_NAME) \
	return reloc_convert_set(bin, rel, RZ_BIN_RELOC_##BIT_SIZE, RELOC_NAME)

#define ADD(BIT_SIZE, ADDEND, RELOC_NAME) \
	return reloc_convert_add(bin, rel, RZ_BIN_RELOC_##BIT_SIZE, ADDEND, RELOC_NAME)

#define VADDR(BIT_SIZE, ADDR, RELOC_NAME) \
	return reloc_convert_vaddr(bin, rel, RZ_BIN_RELOC_##BIT_SIZE, ADDR, RELOC_NAME)

#define IFCN(BIT_SIZE, RELOC_NAME) \
	return reloc_convert_ifunc(bin, rel, RZ_BIN_RELOC_##BIT_SIZE, RELOC_NAME)

static RzBinReloc *reloc_convert_intel_80386(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 B = bin->baddr;
	ut64 P = rel->vaddr;

	// FIXME: Quite a few relocatons missing here.
	switch (rel->type) {
	case R_386_NONE: UNHANDL("R_386_NONE");
	case R_386_32: ADD(32, 0, "R_386_32");
	case R_386_PC32: ADD(32, -P, "R_386_PC32");
	case R_386_GLOB_DAT: SET(32, "R_386_GLOB_DAT");
	case R_386_JMP_SLOT: SET(32, "R_386_JMP_SLOT");
	case R_386_RELATIVE: ADD(32, B, "R_386_RELATIVE");
	case R_386_GOTOFF: ADD(32, -GOT, "R_386_GOTOFF");
	case R_386_GOTPC: ADD(32, GOT - P, "R_386_GOTPC");
	case R_386_16: ADD(16, 0, "R_386_16");
	case R_386_PC16: ADD(16, -P, "R_386_PC16");
	case R_386_8: ADD(8, 0, "R_386_8");
	case R_386_PC8: ADD(8, -P, "R_386_PC8");
	case R_386_COPY: ADD(32, 0, "R_386_COPY"); // copy symbol at runtime
	case R_386_IRELATIVE: IFCN(32, "R_386_IRELATIVE");
	case R_386_GOT32: UNHANDL("R_386_GOT32");
	case R_386_PLT32: UNHANDL("R_386_PLT32");
	case R_386_32PLT: UNHANDL("R_386_32PLT");
	case R_386_TLS_TPOFF: UNHANDL("R_386_TLS_TPOFF");
	case R_386_TLS_IE: UNHANDL("R_386_TLS_IE");
	case R_386_TLS_GOTIE: UNHANDL("R_386_TLS_GOTIE");
	case R_386_TLS_LE: UNHANDL("R_386_TLS_LE");
	case R_386_TLS_GD: UNHANDL("R_386_TLS_GD");
	case R_386_TLS_LDM: UNHANDL("R_386_TLS_LDM");
	case R_386_TLS_GD_32: UNHANDL("R_386_TLS_GD_32");
	case R_386_TLS_GD_PUSH: UNHANDL("R_386_TLS_GD_PUSH");
	case R_386_TLS_GD_CALL: UNHANDL("R_386_TLS_GD_CALL");
	case R_386_TLS_GD_POP: UNHANDL("R_386_TLS_GD_POP");
	case R_386_TLS_LDM_32: UNHANDL("R_386_TLS_LDM_32");
	case R_386_TLS_LDM_PUSH: UNHANDL("R_386_TLS_LDM_PUSH");
	case R_386_TLS_LDM_CALL: UNHANDL("R_386_TLS_LDM_CALL");
	case R_386_TLS_LDM_POP: UNHANDL("R_386_TLS_LDM_POP");
	case R_386_TLS_LDO_32: UNHANDL("R_386_TLS_LDO_32");
	case R_386_TLS_IE_32: UNHANDL("R_386_TLS_IE_32");
	case R_386_TLS_LE_32: UNHANDL("R_386_TLS_LE_32");
	case R_386_TLS_DTPMOD32: UNHANDL("R_386_TLS_DTPMOD32");
	case R_386_TLS_DTPOFF32: UNHANDL("R_386_TLS_DTPOFF32");
	case R_386_TLS_TPOFF32: UNHANDL("R_386_TLS_TPOFF32");
	case R_386_SIZE32: UNHANDL("R_386_SIZE32");
	case R_386_TLS_GOTDESC: UNHANDL("R_386_TLS_GOTDESC");
	case R_386_TLS_DESC_CALL: UNHANDL("R_386_TLS_DESC_CALL");
	case R_386_TLS_DESC: UNHANDL("R_386_TLS_DESC");
	case R_386_GOT32X: UNHANDL("R_386_GOT32X");
	default: UNSUPP("X86_32");
	}
}

static RzBinReloc *reloc_convert_amd64(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 B = bin->baddr;
	ut64 P = rel->vaddr;

	// FIXME: Quite a few relocatons missing here.
	switch (rel->type) {
	case R_X86_64_NONE: UNHANDL("R_X86_64_NONE");
	case R_X86_64_64: ADD(64, 0, "R_X86_64_64");
	case R_X86_64_PLT32: ADD(32, -P /* +L */, "R_X86_64_PLT32");
	case R_X86_64_GOT32: ADD(32, GOT, "R_X86_64_GOT32");
	case R_X86_64_PC32: ADD(32, -P, "R_X86_64_PC32");
	case R_X86_64_GLOB_DAT: VADDR(64, P - rel->sto, "R_X86_64_GLOB_DAT");
	case R_X86_64_JUMP_SLOT: VADDR(64, P - rel->sto, "R_X86_64_JUMP_SLOT");
	case R_X86_64_RELATIVE: ADD(64, B, "R_X86_64_RELATIVE");
	case R_X86_64_32: ADD(32, 0, "R_X86_64_32");
	case R_X86_64_32S: ADD(32, 0, "R_X86_64_32S");
	case R_X86_64_16: ADD(16, 0, "R_X86_64_16");
	case R_X86_64_PC16: ADD(16, -P, "R_X86_64_PC16");
	case R_X86_64_8: ADD(8, 0, "R_X86_64_8");
	case R_X86_64_PC8: ADD(8, -P, "R_X86_64_PC8");
	case R_X86_64_GOTPCREL: ADD(64, GOT - P, "R_X86_64_GOTPCREL");
	case R_X86_64_COPY: ADD(64, 0, "R_X86_64_COPY"); // copy symbol at runtime
	case R_X86_64_IRELATIVE: IFCN(64, "R_X86_64_IRELATIVE");
	default: UNSUPP("X86_64");
	}
}

static RzBinReloc *reloc_convert_arm(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 B = bin->baddr;
	ut64 P = rel->vaddr;

	switch (rel->type) {
	case R_ARM_NONE: UNHANDL("R_ARM_NONE");
	case R_ARM_ABS32: ADD(32, 0, "R_ARM_ABS32");
	case R_ARM_REL32: ADD(32, -P, "R_ARM_REL32");
	case R_ARM_ABS16: ADD(16, 0, "R_ARM_ABS16");
	case R_ARM_ABS8: ADD(8, 0, "R_ARM_ABS8");
	case R_ARM_SBREL32: ADD(32, -B, "R_ARM_SBREL32");
	case R_ARM_GLOB_DAT: ADD(32, 0, "R_ARM_GLOB_DAT");
	case R_ARM_JUMP_SLOT: ADD(32, 0, "R_ARM_JUMP_SLOT");
	case R_ARM_COPY: ADD(32, 0, "R_ARM_COPY"); // copy symbol at runtime
	case R_ARM_RELATIVE: ADD(32, B, "R_ARM_RELATIVE");
	case R_ARM_GOTOFF: ADD(32, -GOT, "R_ARM_GOTOFF");
	case R_ARM_GOTPC: ADD(32, GOT - P, "R_ARM_GOTPC");
	case R_ARM_CALL: ADD(24, -P, "R_ARM_CALL");
	case R_ARM_JUMP24: ADD(24, -P, "R_ARM_JUMP24");
	case R_ARM_THM_JUMP24: ADD(24, -P, "R_ARM_THM_JUMP24");
	case R_ARM_THM_PC22: ADD(24, -P, "R_ARM_THM_PC22");
	case R_ARM_PREL31: ADD(32, -P, "R_ARM_PREL31");
	case R_ARM_MOVW_PREL_NC: ADD(16, -P, "R_ARM_MOVW_PREL_NC");
	case R_ARM_MOVT_PREL: ADD(32, -P, "R_ARM_MOVT_PREL");
	case R_ARM_THM_MOVW_PREL_NC: ADD(16, -P, "R_ARM_THM_MOVW_PREL_NC");
	case R_ARM_REL32_NOI: ADD(32, -P, "R_ARM_REL32_NOI");
	case R_ARM_ABS32_NOI: ADD(32, 0, "R_ARM_ABS32_NOI");
	case R_ARM_ALU_PC_G0_NC: ADD(32, -P, "R_ARM_ALU_PC_G0_NC");
	case R_ARM_ALU_PC_G0: ADD(32, -P, "R_ARM_ALU_PC_G0");
	case R_ARM_ALU_PC_G1_NC: ADD(32, -P, "R_ARM_ALU_PC_G1_NC");
	case R_ARM_ALU_PC_G1: ADD(32, -P, "R_ARM_ALU_PC_G1");
	case R_ARM_ALU_PC_G2: ADD(32, -P, "R_ARM_ALU_PC_G2");
	case R_ARM_LDR_PC_G1: ADD(32, -P, "R_ARM_LDR_PC_G1");
	case R_ARM_LDR_PC_G2: ADD(32, -P, "R_ARM_LDR_PC_G2");
	case R_ARM_LDRS_PC_G0: ADD(32, -P, "R_ARM_LDRS_PC_G0");
	case R_ARM_LDRS_PC_G1: ADD(32, -P, "R_ARM_LDRS_PC_G1");
	case R_ARM_LDRS_PC_G2: ADD(32, -P, "R_ARM_LDRS_PC_G2");
	case R_ARM_LDC_PC_G0: ADD(32, -P, "R_ARM_LDC_PC_G0");
	case R_ARM_LDC_PC_G1: ADD(32, -P, "R_ARM_LDC_PC_G1");
	case R_ARM_LDC_PC_G2: ADD(32, -P, "R_ARM_LDC_PC_G2");
	// FIXME: Quite a few relocatons missing here. It's incorrect to place them all under "reg relocations".
	default: ADD(32, GOT, "ARM REG RELOC");
	}
}

static RzBinReloc *reloc_convert_riscv(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 B = bin->baddr;

	switch (rel->type) {
	case R_RISCV_NONE: UNHANDL("R_RISCV_NONE");
	case R_RISCV_JUMP_SLOT: ADD(64, 0, "R_RISCV_JUMP_SLOT");
	case R_RISCV_RELATIVE: ADD(64, B, "R_RISCV_RELATIVE");
	// FIXME: Quite a few relocatons missing here. It's incorrect to place them all under "reg relocations".
	default: ADD(64, GOT, "RISC-V REG RELOC");
	}
}

static RzBinReloc *reloc_convert_aarch64(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 B = bin->baddr;

	switch (rel->type) {
	case R_AARCH64_NONE: UNHANDL("R_AARCH64_NONE");
	case R_AARCH64_ABS64: ADD(64, 0, "R_AARCH64_ABS64");
	case R_AARCH64_ABS32: ADD(32, 0, "R_AARCH64_ABS32");
	case R_AARCH64_ABS16: ADD(16, 0, "R_AARCH64_ABS16");
	case R_AARCH64_PREL64: ADD(64, 0, "R_AARCH64_PREL64");
	case R_AARCH64_PREL32: ADD(32, 0, "R_AARCH64_PREL32");
	case R_AARCH64_PREL16: ADD(16, 0, "R_AARCH64_PREL16");
	case R_AARCH64_GLOB_DAT: SET(64, "R_AARCH64_GLOB_DAT");
	case R_AARCH64_JUMP_SLOT: SET(64, "R_AARCH64_JUMP_SLOT");
	case R_AARCH64_RELATIVE: ADD(64, B, "R_AARCH64_RELATIVE");
	case R_AARCH64_LDST8_ABS_LO12_NC: ADD(16, 0, "R_AARCH64_LDST8_ABS_LO12_NC");
	case R_AARCH64_ADD_ABS_LO12_NC: ADD(16, 0, "R_AARCH64_ADD_ABS_LO12_NC");
	case R_AARCH64_JUMP26: ADD(32, 0, "R_AARCH64_JUMP26");
	case R_AARCH64_CALL26: ADD(32, 0, "R_AARCH64_CALL26");
	case R_AARCH64_LDST64_ABS_LO12_NC: ADD(32, 0, "R_AARCH64_LDST64_ABS_LO12_NC");
	case R_AARCH64_LD64_GOT_LO12_NC: ADD(32, 0, "R_AARCH64_LD64_GOT_LO12_NC");
	// Page-relative relocations
	case R_AARCH64_ADR_GOT_PAGE: ADD(32, 0, "R_AARCH64_ADR_GOT_PAGE");
	case R_AARCH64_ADR_PREL_PG_HI21: ADD(32, 0, "R_AARCH64_ADR_PREL_PG_HI21");
	case R_AARCH64_ADR_PREL_PG_HI21_NC: ADD(32, 0, "R_AARCH64_ADR_PREL_PG_HI21_NC");
	// FIXME: Quite a few relocations missing here
	default: UNSUPP("AArch64");
	}
}

static RzBinReloc *reloc_convert_ppc(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 P = rel->vaddr;

	switch (rel->type) {
	case R_PPC_NONE: UNHANDL("R_PPC_NONE");
	case R_PPC_GLOB_DAT: ADD(32, 0, "R_PPC_GLOB_DAT");
	case R_PPC_JMP_SLOT: ADD(32, 0, "R_PPC_JMP_SLOT");
	case R_PPC_COPY: ADD(32, 0, "R_PPC_COPY"); // copy symbol at runtime
	case R_PPC_REL24: ADD(24, -P, "R_PPC_REL24");
	case R_PPC_REL14: ADD(16, -P, "R_PPC_REL14");
	case R_PPC_REL32: ADD(32, -P, "R_PPC_REL32");
	case R_PPC_RELATIVE: ADD(32, -P, "R_PPC_RELATIVE");
	case R_PPC_PLT32: ADD(32, -P, "R_PPC_PLT32");
	case R_PPC_ADDR16: ADD(16, 0, "R_PPC_ADDR16");
	case R_PPC_ADDR32: ADD(32, 0, "R_PPC_ADDR32");

	// FIXME: Quite a few relocatons missing here.
	default: UNSUPP("PPC");
	}
}

static RzBinReloc *reloc_convert_mips(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 P = rel->vaddr;

	switch (rel->type) {
	case R_MIPS_NONE: UNHANDL("R_MIPS_NONE");
	case R_MIPS_16: ADD(16, 0, "R_MIPS_16");
	case R_MIPS_32: ADD(32, 0, "R_MIPS_32");
	case R_MIPS_REL32: ADD(32, -P, "R_MIPS_REL32");
	case R_MIPS_26: UNHANDL("R_MIPS_26");
	case R_MIPS_HI16: UNHANDL("R_MIPS_HI16");
	case R_MIPS_LO16: UNHANDL("R_MIPS_LO16");
	case R_MIPS_GPREL16: UNHANDL("R_MIPS_GPREL16");
	case R_MIPS_LITERAL: UNHANDL("R_MIPS_LITERAL");
	case R_MIPS_GOT16: UNHANDL("R_MIPS_GOT16");
	case R_MIPS_PC16: UNHANDL("R_MIPS_PC16");
	case R_MIPS_CALL16: UNHANDL("R_MIPS_CALL16");
	case R_MIPS_GPREL32: UNHANDL("R_MIPS_GPREL32");
	case R_MIPS_SHIFT5: UNHANDL("R_MIPS_SHIFT5");
	case R_MIPS_SHIFT6: UNHANDL("R_MIPS_SHIFT6");
	case R_MIPS_64: UNHANDL("R_MIPS_64");
	case R_MIPS_GOT_DISP: UNHANDL("R_MIPS_GOT_DISP");
	case R_MIPS_GOT_PAGE: UNHANDL("R_MIPS_GOT_PAGE");
	case R_MIPS_GOT_OFST: UNHANDL("R_MIPS_GOT_OFST");
	case R_MIPS_GOT_HI16: UNHANDL("R_MIPS_GOT_HI16");
	case R_MIPS_GOT_LO16: UNHANDL("R_MIPS_GOT_LO16");
	case R_MIPS_SUB: UNHANDL("R_MIPS_SUB");
	case R_MIPS_INSERT_A: UNHANDL("R_MIPS_INSERT_A");
	case R_MIPS_INSERT_B: UNHANDL("R_MIPS_INSERT_B");
	case R_MIPS_DELETE: UNHANDL("R_MIPS_DELETE");
	case R_MIPS_HIGHER: UNHANDL("R_MIPS_HIGHER");
	case R_MIPS_HIGHEST: UNHANDL("R_MIPS_HIGHEST");
	case R_MIPS_CALL_HI16: UNHANDL("R_MIPS_CALL_HI16");
	case R_MIPS_CALL_LO16: UNHANDL("R_MIPS_CALL_LO16");
	case R_MIPS_SCN_DISP: UNHANDL("R_MIPS_SCN_DISP");
	case R_MIPS_REL16: UNHANDL("R_MIPS_REL16");
	case R_MIPS_ADD_IMMEDIATE: UNHANDL("R_MIPS_ADD_IMMEDIATE");
	case R_MIPS_PJUMP: UNHANDL("R_MIPS_PJUMP");
	case R_MIPS_RELGOT: UNHANDL("R_MIPS_RELGOT");
	case R_MIPS_JALR: UNHANDL("R_MIPS_JALR");
	case R_MIPS_TLS_DTPMOD32: UNHANDL("R_MIPS_TLS_DTPMOD32");
	case R_MIPS_TLS_DTPREL32: UNHANDL("R_MIPS_TLS_DTPREL32");
	case R_MIPS_TLS_DTPMOD64: UNHANDL("R_MIPS_TLS_DTPMOD64");
	case R_MIPS_TLS_DTPREL64: UNHANDL("R_MIPS_TLS_DTPREL64");
	case R_MIPS_TLS_GD: UNHANDL("R_MIPS_TLS_GD");
	case R_MIPS_TLS_LDM: UNHANDL("R_MIPS_TLS_LDM");
	case R_MIPS_TLS_DTPREL_HI16: UNHANDL("R_MIPS_TLS_DTPREL_HI16");
	case R_MIPS_TLS_DTPREL_LO16: UNHANDL("R_MIPS_TLS_DTPREL_LO16");
	case R_MIPS_TLS_GOTTPREL: UNHANDL("R_MIPS_TLS_GOTTPREL");
	case R_MIPS_TLS_TPREL32: UNHANDL("R_MIPS_TLS_TPREL32");
	case R_MIPS_TLS_TPREL64: UNHANDL("R_MIPS_TLS_TPREL64");
	case R_MIPS_TLS_TPREL_HI16: UNHANDL("R_MIPS_TLS_TPREL_HI16");
	case R_MIPS_TLS_TPREL_LO16: UNHANDL("R_MIPS_TLS_TPREL_LO16");
	case R_MIPS_GLOB_DAT: UNHANDL("R_MIPS_GLOB_DAT");
	case R_MIPS_COPY: ADD(32, 0, "R_MIPS_COPY");
	case R_MIPS_JUMP_SLOT: ADD(32, 0, "R_MIPS_JUMP_SLOT");
	case R_MICROMIPS_26_S1: UNHANDL("R_MICROMIPS_26_S1");
	case R_MICROMIPS_HI16: UNHANDL("R_MICROMIPS_HI16");
	case R_MICROMIPS_LO16: UNHANDL("R_MICROMIPS_LO16");
	case R_MICROMIPS_GPREL16: UNHANDL("R_MICROMIPS_GPREL16");
	case R_MICROMIPS_LITERAL: UNHANDL("R_MICROMIPS_LITERAL");
	case R_MICROMIPS_GOT16: UNHANDL("R_MICROMIPS_GOT16");
	case R_MICROMIPS_PC7_S1: UNHANDL("R_MICROMIPS_PC7_S1");
	case R_MICROMIPS_PC10_S1: UNHANDL("R_MICROMIPS_PC10_S1");
	case R_MICROMIPS_PC16_S1: UNHANDL("R_MICROMIPS_PC16_S1");
	case R_MICROMIPS_CALL16: UNHANDL("R_MICROMIPS_CALL16");
	case R_MICROMIPS_GOT_DISP: UNHANDL("R_MICROMIPS_GOT_DISP");
	case R_MICROMIPS_GOT_PAGE: UNHANDL("R_MICROMIPS_GOT_PAGE");
	case R_MICROMIPS_GOT_OFST: UNHANDL("R_MICROMIPS_GOT_OFST");
	case R_MICROMIPS_GOT_HI16: UNHANDL("R_MICROMIPS_GOT_HI16");
	case R_MICROMIPS_GOT_LO16: UNHANDL("R_MICROMIPS_GOT_LO16");
	case R_MICROMIPS_SUB: UNHANDL("R_MICROMIPS_SUB");
	case R_MICROMIPS_HIGHER: UNHANDL("R_MICROMIPS_HIGHER");
	case R_MICROMIPS_HIGHEST: UNHANDL("R_MICROMIPS_HIGHEST");
	case R_MICROMIPS_CALL_HI16: UNHANDL("R_MICROMIPS_CALL_HI16");
	case R_MICROMIPS_CALL_LO16: UNHANDL("R_MICROMIPS_CALL_LO16");
	case R_MICROMIPS_SCN_DISP: UNHANDL("R_MICROMIPS_SCN_DISP");
	case R_MICROMIPS_JALR: UNHANDL("R_MICROMIPS_JALR");
	case R_MICROMIPS_HI0_LO16: UNHANDL("R_MICROMIPS_HI0_LO16");
	case R_MICROMIPS_TLS_GD: UNHANDL("R_MICROMIPS_TLS_GD");
	case R_MICROMIPS_TLS_LDM: UNHANDL("R_MICROMIPS_TLS_LDM");
	case R_MICROMIPS_TLS_DTPREL_HI16: UNHANDL("R_MICROMIPS_TLS_DTPREL_HI16");
	case R_MICROMIPS_TLS_DTPREL_LO16: UNHANDL("R_MICROMIPS_TLS_DTPREL_LO16");
	case R_MICROMIPS_TLS_GOTTPREL: UNHANDL("R_MICROMIPS_TLS_GOTTPREL");
	case R_MICROMIPS_TLS_TPREL_HI16: UNHANDL("R_MICROMIPS_TLS_TPREL_HI16");
	case R_MICROMIPS_TLS_TPREL_LO16: UNHANDL("R_MICROMIPS_TLS_TPREL_LO16");
	case R_MICROMIPS_GPREL7_S2: UNHANDL("R_MICROMIPS_GPREL7_S2");
	case R_MICROMIPS_PC23_S2: UNHANDL("R_MICROMIPS_PC23_S2");
	case R_MIPS_PC32: UNHANDL("R_MIPS_PC32");
	case R_MIPS_EH: UNHANDL("R_MIPS_EH");
	case R_MIPS_GNU_REL16_S2: UNHANDL("R_MIPS_GNU_REL16_S2");
	case R_MIPS_GNU_VTINHERIT: UNHANDL("R_MIPS_GNU_VTINHERIT");
	case R_MIPS_GNU_VTENTRY: UNHANDL("R_MIPS_GNU_VTENTRY");
	default: UNSUPP("MIPS");
	}
}

static RzBinReloc *reloc_convert_nanomips(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	switch (rel->type) {
	case R_NANOMIPS_NONE: UNHANDL("R_MIPS_NONE");
	case R_NANOMIPS_32: ADD(32, 0, "R_NANOMIPS_32");
	case R_NANOMIPS_64: ADD(64, 0, "R_NANOMIPS_64");
	case R_NANOMIPS_NEG: UNHANDL("R_NANOMIPS_NEG");
	case R_NANOMIPS_ASHIFTR_1: UNHANDL("R_NANOMIPS_ASHIFTR_1");
	case R_NANOMIPS_UNSIGNED_8: UNHANDL("R_NANOMIPS_UNSIGNED_8");
	case R_NANOMIPS_SIGNED_8: UNHANDL("R_NANOMIPS_SIGNED_8");
	case R_NANOMIPS_UNSIGNED_16: UNHANDL("R_NANOMIPS_UNSIGNED_16");
	case R_NANOMIPS_SIGNED_16: UNHANDL("R_NANOMIPS_SIGNED_16");
	case R_NANOMIPS_RELATIVE: UNHANDL("R_NANOMIPS_RELATIVE");
	case R_NANOMIPS_GLOBAL: UNHANDL("R_NANOMIPS_GLOBAL");
	case R_NANOMIPS_JUMP_SLOT: ADD(64, 0, "R_NANOMIPS_JUMP_SLOT");
	case R_NANOMIPS_IRELATIVE: UNHANDL("R_NANOMIPS_IRELATIVE");
	case R_NANOMIPS_PC25_S1: UNHANDL("R_NANOMIPS_PC25_S1");
	case R_NANOMIPS_PC21_S1: UNHANDL("R_NANOMIPS_PC21_S1");
	case R_NANOMIPS_PC14_S1: UNHANDL("R_NANOMIPS_PC14_S1");
	case R_NANOMIPS_PC11_S1: UNHANDL("R_NANOMIPS_PC11_S1");
	case R_NANOMIPS_PC10_S1: UNHANDL("R_NANOMIPS_PC10_S1");
	case R_NANOMIPS_PC7_S1: UNHANDL("R_NANOMIPS_PC7_S1");
	case R_NANOMIPS_PC4_S1: UNHANDL("R_NANOMIPS_PC4_S1");
	case R_NANOMIPS_GPREL19_S2: UNHANDL("R_NANOMIPS_GPREL19_S2");
	case R_NANOMIPS_GPREL18_S3: UNHANDL("R_NANOMIPS_GPREL18_S3");
	case R_NANOMIPS_GPREL18: UNHANDL("R_NANOMIPS_GPREL18");
	case R_NANOMIPS_GPREL17_S1: UNHANDL("R_NANOMIPS_GPREL17_S1");
	case R_NANOMIPS_GPREL16_S2: UNHANDL("R_NANOMIPS_GPREL16_S2");
	case R_NANOMIPS_GPREL7_S2: UNHANDL("R_NANOMIPS_GPREL7_S2");
	case R_NANOMIPS_GPREL_HI20: UNHANDL("R_NANOMIPS_GPREL_HI20");
	case R_NANOMIPS_PC_HI20: UNHANDL("R_NANOMIPS_PC_HI20");
	case R_NANOMIPS_HI20: UNHANDL("R_NANOMIPS_HI20");
	case R_NANOMIPS_LO12: UNHANDL("R_NANOMIPS_LO12");
	case R_NANOMIPS_GPREL_I32: UNHANDL("R_NANOMIPS_GPREL_I32");
	case R_NANOMIPS_PC_I32: UNHANDL("R_NANOMIPS_PC_I32");
	case R_NANOMIPS_I32: UNHANDL("R_NANOMIPS_I32");
	case R_NANOMIPS_GOT_DISP: UNHANDL("R_NANOMIPS_GOT_DISP");
	case R_NANOMIPS_GOTPC_I32: UNHANDL("R_NANOMIPS_GOTPC_I32");
	case R_NANOMIPS_GOTPC_HI20: UNHANDL("R_NANOMIPS_GOTPC_HI20");
	case R_NANOMIPS_GOT_LO12: UNHANDL("R_NANOMIPS_GOT_LO12");
	case R_NANOMIPS_GOT_CALL: UNHANDL("R_NANOMIPS_GOT_CALL");
	case R_NANOMIPS_GOT_PAGE: UNHANDL("R_NANOMIPS_GOT_PAGE");
	case R_NANOMIPS_GOT_OFST: UNHANDL("R_NANOMIPS_GOT_OFST");
	case R_NANOMIPS_LO4_S2: UNHANDL("R_NANOMIPS_LO4_S2");
	case R_NANOMIPS_HI32: UNHANDL("R_NANOMIPS_HI32");
	case R_NANOMIPS_GPREL_LO12: UNHANDL("R_NANOMIPS_GPREL_LO12");
	case R_NANOMIPS_COPY: ADD(64, 0, "R_NANOMIPS_COPY");
	case R_NANOMIPS_ALIGN: UNHANDL("R_NANOMIPS_ALIGN");
	case R_NANOMIPS_FILL: UNHANDL("R_NANOMIPS_FILL");
	case R_NANOMIPS_MAX: UNHANDL("R_NANOMIPS_MAX");
	case R_NANOMIPS_INSN32: UNHANDL("R_NANOMIPS_INSN32");
	case R_NANOMIPS_FIXED: UNHANDL("R_NANOMIPS_FIXED");
	case R_NANOMIPS_NORELAX: UNHANDL("R_NANOMIPS_NORELAX");
	case R_NANOMIPS_RELAX: UNHANDL("R_NANOMIPS_RELAX");
	case R_NANOMIPS_SAVERESTORE: UNHANDL("R_NANOMIPS_SAVERESTORE");
	case R_NANOMIPS_INSN16: UNHANDL("R_NANOMIPS_INSN16");
	case R_NANOMIPS_JALR32: UNHANDL("R_NANOMIPS_JALR32");
	case R_NANOMIPS_JALR16: UNHANDL("R_NANOMIPS_JALR16");
	case R_NANOMIPS_JUMPTABLE_LOAD: UNHANDL("R_NANOMIPS_JUMPTABLE_LOAD");
	case R_NANOMIPS_TLS_DTPMOD: UNHANDL("R_NANOMIPS_TLS_DTPMOD");
	case R_NANOMIPS_TLS_DTPREL: UNHANDL("R_NANOMIPS_TLS_DTPREL");
	case R_NANOMIPS_TLS_TPREL: UNHANDL("R_NANOMIPS_TLS_TPREL");
	case R_NANOMIPS_TLS_GD: UNHANDL("R_NANOMIPS_TLS_GD");
	case R_NANOMIPS_TLS_GD_I32: UNHANDL("R_NANOMIPS_TLS_GD_I32");
	case R_NANOMIPS_TLS_LD: UNHANDL("R_NANOMIPS_TLS_LD");
	case R_NANOMIPS_TLS_LD_I32: UNHANDL("R_NANOMIPS_TLS_LD_I32");
	case R_NANOMIPS_TLS_DTPREL12: UNHANDL("R_NANOMIPS_TLS_DTPREL12");
	case R_NANOMIPS_TLS_DTPREL16: UNHANDL("R_NANOMIPS_TLS_DTPREL16");
	case R_NANOMIPS_TLS_DTPREL_I32: UNHANDL("R_NANOMIPS_TLS_DTPREL_I32");
	case R_NANOMIPS_TLS_GOTTPREL: UNHANDL("R_NANOMIPS_TLS_GOTTPREL");
	case R_NANOMIPS_TLS_GOTTPREL_PC32: UNHANDL("R_NANOMIPS_TLS_GOTTPREL_PC32");
	case R_NANOMIPS_TLS_TPREL12: UNHANDL("R_NANOMIPS_TLS_TPREL12");
	case R_NANOMIPS_TLS_TPREL16: UNHANDL("R_NANOMIPS_TLS_TPREL16");
	case R_NANOMIPS_TLS_TPREL_I32: UNHANDL("R_NANOMIPS_TLS_TPREL_I32");
	default: UNSUPP("nanoMIPS");
	}
}

static RzBinReloc *reloc_convert_rx(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 P = rel->vaddr;

	switch (rel->type) {
	case R_RX_NONE: UNHANDL("R_RX_NONE");
	case R_RX_DIR24S_PCREL: ADD(24, -P, "RX_DIR24S_PCREL");
	case R_RX_DIR32: SET(32, "RX_DIR32");

	// FIXME: Quite a few relocatons missing here.
	default: UNSUPP("RX");
	}
}

static RzBinReloc *reloc_convert_alpha(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 P = rel->vaddr;

	switch (rel->type) {
	case R_ALPHA_NONE: UNHANDL("R_ALPHA_NONE");
	case R_ALPHA_REFLONG: SET(32, "R_ALPHA_REFLONG");
	case R_ALPHA_REFQUAD: SET(64, "R_ALPHA_REFQUAD");
	case R_ALPHA_SREL16: ADD(16, -P, "R_ALPHA_SREL16");
	case R_ALPHA_SREL32: ADD(32, -P, "R_ALPHA_SREL32");
	case R_ALPHA_SREL64: ADD(64, -P, "R_ALPHA_SREL64");
	case R_ALPHA_COPY: ADD(32, 0, "R_ALPHA_COPY"); // copy symbol at runtime
	case R_ALPHA_GLOB_DAT: ADD(32, 0, "R_ALPHA_GLOB_DAT");
	case R_ALPHA_JMP_SLOT: ADD(32, 0, "R_ALPHA_JMP_SLOT");

	// FIXME: Quite a few relocatons missing here.
	default: UNSUPP("ALPHA");
	}
}

static RzBinReloc *reloc_convert_hexagon(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	ut64 P = rel->vaddr;

	switch (rel->type) {
	case R_HEX_B22_PCREL: ADD(32, -P, "R_HEX_B22_PCREL");
	case R_HEX_B15_PCREL: ADD(32, -P, "R_HEX_B15_PCREL");
	case R_HEX_B7_PCREL: ADD(32, -P, "R_HEX_B7_PCREL");
	case R_HEX_LO16: ADD(32, 0, "R_HEX_LO16");
	case R_HEX_HI16: ADD(32, 0, "R_HEX_HI16");
	case R_HEX_32: ADD(32, 0, "R_HEX_32");
	case R_HEX_16: ADD(16, 0, "R_HEX_16");
	case R_HEX_8: ADD(8, 0, "R_HEX_8");
	case R_HEX_HL16: ADD(64, 0, "R_HEX_HL16");
	case R_HEX_B13_PCREL: ADD(32, -P, "R_HEX_B13_PCREL");
	case R_HEX_B9_PCREL: ADD(32, -P, "R_HEX_B9_PCREL");
	case R_HEX_B32_PCREL_X: ADD(32, -P, "R_HEX_B32_PCREL_X");
	case R_HEX_32_6_X: ADD(32, 0, "R_HEX_32_6_X");
	case R_HEX_B22_PCREL_X: ADD(32, -P, "R_HEX_B22_PCREL_X");
	case R_HEX_B15_PCREL_X: ADD(32, -P, "R_HEX_B15_PCREL_X");
	case R_HEX_B13_PCREL_X: ADD(32, -P, "R_HEX_B13_PCREL_X");
	case R_HEX_B9_PCREL_X: ADD(32, -P, "R_HEX_B9_PCREL_X");
	case R_HEX_B7_PCREL_X: ADD(32, -P, "R_HEX_B7_PCREL_X");
	case R_HEX_16_X: ADD(32, 0, "R_HEX_16_X");
	case R_HEX_12_X: ADD(32, 0, "R_HEX_12_X");
	case R_HEX_11_X: ADD(32, 0, "R_HEX_11_X");
	case R_HEX_10_X: ADD(32, 0, "R_HEX_10_X");
	case R_HEX_9_X: ADD(32, 0, "R_HEX_9_X");
	case R_HEX_8_X: ADD(32, 0, "R_HEX_8_X");
	case R_HEX_7_X: ADD(32, 0, "R_HEX_7_X");
	case R_HEX_6_X: ADD(32, 0, "R_HEX_6_X");
	case R_HEX_32_PCREL: ADD(32, -P, "R_HEX_32_PCREL");
	case R_HEX_GLOB_DAT: ADD(32, 0, "R_HEX_GLOB_DAT");
	case R_HEX_JMP_SLOT: ADD(32, 0, "R_HEX_JMP_SLOT");
	case R_HEX_GOTREL_LO16: ADD(32, -GOT, "R_HEX_GOTREL_LO16");
	case R_HEX_GOTREL_HI16: ADD(32, -GOT, "R_HEX_GOTREL_HI16");
	case R_HEX_GOTREL_32: ADD(32, -GOT, "R_HEX_GOTREL_32");
	case R_HEX_6_PCREL_X: ADD(32, -P, "R_HEX_6_PCREL_X");
	case R_HEX_GOTREL_32_6_X: ADD(32, -GOT, "R_HEX_GOTREL_32_6_X");
	case R_HEX_GOTREL_16_X: ADD(32, -GOT, "R_HEX_GOTREL_16_X");
	case R_HEX_GOTREL_11_X: ADD(32, -GOT, "R_HEX_GOTREL_11_X");
	case R_HEX_GD_PLT_B22_PCREL_X: ADD(32, -P, "R_HEX_GD_PLT_B22_PCREL_X");
	case R_HEX_GD_PLT_B32_PCREL_X: ADD(32, -P, "R_HEX_GD_PLT_B32_PCREL_X");
	case R_HEX_LD_PLT_B22_PCREL_X: ADD(32, -P, "R_HEX_LD_PLT_B22_PCREL_X");
	case R_HEX_LD_PLT_B32_PCREL_X: ADD(32, -P, "R_HEX_LD_PLT_B32_PCREL_X");
	case R_HEX_COPY: SET(32, "R_HEX_COPY");
	case R_HEX_NONE: UNHANDL("R_HEX_NONE");
	case R_HEX_RELATIVE: UNHANDL("R_HEX_RELATIVE"); // Preview not supported, patching is implemented
	case R_HEX_PLT_B22_PCREL: UNHANDL("R_HEX_PLT_B22_PCREL"); // Preview not supported, patching is implemented
	case R_HEX_GOT_LO16: UNHANDL("R_HEX_GOT_LO16");
	case R_HEX_GOT_HI16: UNHANDL("R_HEX_GOT_HI16");
	case R_HEX_GOT_32: UNHANDL("R_HEX_GOT_32");
	case R_HEX_GOT_16: UNHANDL("R_HEX_GOT_16");
	case R_HEX_DTPMOD_32: UNHANDL("R_HEX_DTPMOD_32");
	case R_HEX_GD_PLT_B22_PCREL: UNHANDL("R_HEX_GD_PLT_B22_PCREL"); // Preview not supported, patching is implemented
	case R_HEX_GD_GOT_LO16: UNHANDL("R_HEX_GD_GOT_LO16");
	case R_HEX_GD_GOT_HI16: UNHANDL("R_HEX_GD_GOT_HI16");
	case R_HEX_GD_GOT_32: UNHANDL("R_HEX_GD_GOT_32");
	case R_HEX_GD_GOT_16: UNHANDL("R_HEX_GD_GOT_16");
	case R_HEX_IE_LO16: UNHANDL("R_HEX_IE_LO16");
	case R_HEX_IE_HI16: UNHANDL("R_HEX_IE_HI16");
	case R_HEX_IE_32: UNHANDL("R_HEX_IE_32");
	case R_HEX_IE_GOT_LO16: UNHANDL("R_HEX_IE_GOT_LO16");
	case R_HEX_IE_GOT_HI16: UNHANDL("R_HEX_IE_GOT_HI16");
	case R_HEX_IE_GOT_32: UNHANDL("R_HEX_IE_GOT_32");
	case R_HEX_IE_GOT_16: UNHANDL("R_HEX_IE_GOT_16");
	case R_HEX_TPREL_LO16: UNHANDL("R_HEX_TPREL_LO16");
	case R_HEX_TPREL_HI16: UNHANDL("R_HEX_TPREL_HI16");
	case R_HEX_TPREL_32: UNHANDL("R_HEX_TPREL_32");
	case R_HEX_TPREL_16: UNHANDL("R_HEX_TPREL_16");
	case R_HEX_GOT_32_6_X: UNHANDL("R_HEX_GOT_32_6_X");
	case R_HEX_GOT_16_X: UNHANDL("R_HEX_GOT_16_X");
	case R_HEX_GOT_11_X: UNHANDL("R_HEX_GOT_11_X");
	case R_HEX_GD_GOT_32_6_X: UNHANDL("R_HEX_GD_GOT_32_6_X");
	case R_HEX_GD_GOT_16_X: UNHANDL("R_HEX_GD_GOT_16_X");
	case R_HEX_GD_GOT_11_X: UNHANDL("R_HEX_GD_GOT_11_X");
	case R_HEX_IE_32_6_X: UNHANDL("R_HEX_IE_32_6_X");
	case R_HEX_IE_16_X: UNHANDL("R_HEX_IE_16_X");
	case R_HEX_IE_GOT_32_6_X: UNHANDL("R_HEX_IE_GOT_32_6_X");
	case R_HEX_IE_GOT_16_X: UNHANDL("R_HEX_IE_GOT_16_X");
	case R_HEX_IE_GOT_11_X: UNHANDL("R_HEX_IE_GOT_11_X");
	case R_HEX_TPREL_32_6_X: UNHANDL("R_HEX_TPREL_32_6_X");
	case R_HEX_TPREL_16_X: UNHANDL("R_HEX_TPREL_16_X");
	case R_HEX_TPREL_11_X: UNHANDL("R_HEX_TPREL_11_X");
	case R_HEX_LD_PLT_B22_PCREL: UNHANDL("R_HEX_LD_PLT_B22_PCREL"); // Preview not supported, patching is implemented
	case R_HEX_LD_GOT_LO16: UNHANDL("R_HEX_LD_GOT_LO16");
	case R_HEX_LD_GOT_HI16: UNHANDL("R_HEX_LD_GOT_HI16");
	case R_HEX_LD_GOT_32: UNHANDL("R_HEX_LD_GOT_32");
	case R_HEX_LD_GOT_16: UNHANDL("R_HEX_LD_GOT_16");
	case R_HEX_LD_GOT_32_6_X: UNHANDL("R_HEX_LD_GOT_32_6_X");
	case R_HEX_LD_GOT_16_X: UNHANDL("R_HEX_LD_GOT_16_X");
	case R_HEX_LD_GOT_11_X: UNHANDL("R_HEX_LD_GOT_11_X");
	case R_HEX_27_REG: UNHANDL("R_HEX_27_REG");
	case R_HEX_23_REG: UNHANDL("R_HEX_23_REG");
	case R_HEX_DTPREL_32_6_X: UNHANDL("R_HEX_DTPREL_32_6_X"); // Preview not supported, patching is implemented
	case R_HEX_DTPREL_16_X: UNHANDL("R_HEX_DTPREL_16_X"); // Preview not supported, patching is implemented
	case R_HEX_DTPREL_11_X: UNHANDL("R_HEX_DTPREL_11_X"); // Preview not supported, patching is implemented
	case R_HEX_DTPREL_LO16: UNHANDL("R_HEX_DTPREL_LO16");
	case R_HEX_DTPREL_HI16: UNHANDL("R_HEX_DTPREL_HI16");
	case R_HEX_DTPREL_32: UNHANDL("R_HEX_DTPREL_32");
	case R_HEX_DTPREL_16: UNHANDL("R_HEX_DTPREL_16");
	case R_HEX_GPREL16_0: UNHANDL("R_HEX_GPREL16_0");
	case R_HEX_GPREL16_1: UNHANDL("R_HEX_GPREL16_1");
	case R_HEX_GPREL16_2: UNHANDL("R_HEX_GPREL16_2");
	case R_HEX_GPREL16_3: UNHANDL("R_HEX_GPREL16_3");
	default: UNSUPP("Hexagon");
	}
}

#undef UNSUPP
#undef UNHANDL
#undef SET
#undef SET
#undef ADD
#undef VADDR
#undef IFCN

#define MISSING(NAME) \
	RZ_LOG_WARN("Unhandled reloc convert for machine " NAME ".\n"); \
	return NULL

static RzBinReloc *reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	rz_return_val_if_fail(bin && rel, NULL);
	ut16 e_machine = bin->ehdr.e_machine;

	switch (e_machine) {
	case EM_386:
		return reloc_convert_intel_80386(bin, rel, GOT);
	case EM_X86_64:
		return reloc_convert_amd64(bin, rel, GOT);
	case EM_ARM:
		return reloc_convert_arm(bin, rel, GOT);
	case EM_RISCV:
		return reloc_convert_riscv(bin, rel, GOT);
	case EM_AARCH64:
		return reloc_convert_aarch64(bin, rel, GOT);
	case EM_PPC:
		return reloc_convert_ppc(bin, rel, GOT);
	case EM_RX:
		return reloc_convert_rx(bin, rel, GOT);
	case EM_ALPHA:
		return reloc_convert_alpha(bin, rel, GOT);
	case EM_QDSP6:
		return reloc_convert_hexagon(bin, rel, GOT);
	case EM_MIPS_X:
		/* fall-thru */
	case EM_MIPS_RS3_LE:
		/* fall-thru */
	case EM_MIPS:
		return reloc_convert_mips(bin, rel, GOT);
	case EM_IMG1: // nanomips
		return reloc_convert_nanomips(bin, rel, GOT);
	case EM_M32: MISSING("EM_M32");
	case EM_SPARC: MISSING("EM_SPARC");
	case EM_68K: MISSING("EM_68K");
	case EM_88K: MISSING("EM_88K");
	case EM_IAMCU: MISSING("EM_IAMCU");
	case EM_860: MISSING("EM_860");
	case EM_S370: MISSING("EM_S370");
	case EM_PARISC: MISSING("EM_PARISC");
	case EM_VPP500: MISSING("EM_VPP500");
	case EM_SPARC32PLUS: MISSING("EM_SPARC32PLUS");
	case EM_960: MISSING("EM_960");
	case EM_PPC64: MISSING("EM_PPC64");
	case EM_S390: MISSING("EM_S390");
	case EM_SPU: MISSING("EM_SPU");
	case EM_V800: MISSING("EM_V800");
	case EM_FR20: MISSING("EM_FR20");
	case EM_RH32: MISSING("EM_RH32");
	case EM_RCE: MISSING("EM_RCE");
	case EM_FAKE_ALPHA: MISSING("EM_FAKE_ALPHA");
	case EM_SH: MISSING("EM_SH");
	case EM_SPARCV9: MISSING("EM_SPARCV9");
	case EM_TRICORE: MISSING("EM_TRICORE");
	case EM_ARC: MISSING("EM_ARC");
	case EM_H8_300: MISSING("EM_H8_300");
	case EM_H8_300H: MISSING("EM_H8_300H");
	case EM_H8S: MISSING("EM_H8S");
	case EM_H8_500: MISSING("EM_H8_500");
	case EM_IA_64: MISSING("EM_IA_64");
	case EM_COLDFIRE: MISSING("EM_COLDFIRE");
	case EM_68HC12: MISSING("EM_68HC12");
	case EM_MMA: MISSING("EM_MMA");
	case EM_PCP: MISSING("EM_PCP");
	case EM_NCPU: MISSING("EM_NCPU");
	case EM_NDR1: MISSING("EM_NDR1");
	case EM_STARCORE: MISSING("EM_STARCORE");
	case EM_ME16: MISSING("EM_ME16");
	case EM_ST100: MISSING("EM_ST100");
	case EM_TINYJ: MISSING("EM_TINYJ");
	case EM_PDSP: MISSING("EM_PDSP");
	case EM_PDP10: MISSING("EM_PDP10");
	case EM_PDP11: MISSING("EM_PDP11");
	case EM_FX66: MISSING("EM_FX66");
	case EM_ST9PLUS: MISSING("EM_ST9PLUS");
	case EM_ST7: MISSING("EM_ST7");
	case EM_68HC16: MISSING("EM_68HC16");
	case EM_68HC11: MISSING("EM_68HC11");
	case EM_68HC08: MISSING("EM_68HC08");
	case EM_68HC05: MISSING("EM_68HC05");
	case EM_SVX: MISSING("EM_SVX");
	case EM_ST19: MISSING("EM_ST19");
	case EM_VAX: MISSING("EM_VAX");
	case EM_CRIS: MISSING("EM_CRIS");
	case EM_JAVELIN: MISSING("EM_JAVELIN");
	case EM_FIREPATH: MISSING("EM_FIREPATH");
	case EM_ZSP: MISSING("EM_ZSP");
	case EM_MMIX: MISSING("EM_MMIX");
	case EM_HUANY: MISSING("EM_HUANY");
	case EM_PRISM: MISSING("EM_PRISM");
	case EM_AVR: MISSING("EM_AVR");
	case EM_FR30: MISSING("EM_FR30");
	case EM_D10V: MISSING("EM_D10V");
	case EM_D30V: MISSING("EM_D30V");
	case EM_V850: MISSING("EM_V850");
	case EM_M32R: MISSING("EM_M32R");
	case EM_MN10300: MISSING("EM_MN10300");
	case EM_MN10200: MISSING("EM_MN10200");
	case EM_PJ: MISSING("EM_PJ");
	case EM_OR1K: MISSING("EM_OR1K");
	case EM_ARC_COMPACT: MISSING("EM_ARC_COMPACT");
	case EM_XTENSA: MISSING("EM_XTENSA");
	case EM_VIDEOCORE: MISSING("EM_VIDEOCORE");
	case EM_TMM_GPP: MISSING("EM_TMM_GPP");
	case EM_NS32K: MISSING("EM_NS32K");
	case EM_TPC: MISSING("EM_TPC");
	case EM_SNP1K: MISSING("EM_SNP1K");
	case EM_ST200: MISSING("EM_ST200");
	case EM_IP2K: MISSING("EM_IP2K");
	case EM_MAX: MISSING("EM_MAX");
	case EM_CR: MISSING("EM_CR");
	case EM_F2MC16: MISSING("EM_F2MC16");
	case EM_MSP430: MISSING("EM_MSP430");
	case EM_BLACKFIN: MISSING("EM_BLACKFIN");
	case EM_SE_C33: MISSING("EM_SE_C33");
	case EM_SEP: MISSING("EM_SEP");
	case EM_ARCA: MISSING("EM_ARCA");
	case EM_UNICORE: MISSING("EM_UNICORE");
	case EM_EXCESS: MISSING("EM_EXCESS");
	case EM_DXP: MISSING("EM_DXP");
	case EM_ALTERA_NIOS2: MISSING("EM_ALTERA_NIOS2");
	case EM_CRX: MISSING("EM_CRX");
	case EM_XGATE: MISSING("EM_XGATE");
	case EM_C166: MISSING("EM_C166");
	case EM_M16C: MISSING("EM_M16C");
	case EM_DSPIC30F: MISSING("EM_DSPIC30F");
	case EM_CE: MISSING("EM_CE");
	case EM_M32C: MISSING("EM_M32C");
	case EM_TSK3000: MISSING("EM_TSK3000");
	case EM_RS08: MISSING("EM_RS08");
	case EM_SHARC: MISSING("EM_SHARC");
	case EM_ECOG2: MISSING("EM_ECOG2");
	case EM_SCORE7: MISSING("EM_SCORE7");
	case EM_DSP24: MISSING("EM_DSP24");
	case EM_VIDEOCORE3: MISSING("EM_VIDEOCORE3");
	case EM_LATTICEMICO32: MISSING("EM_LATTICEMICO32");
	case EM_SE_C17: MISSING("EM_SE_C17");
	case EM_TI_C6000: MISSING("EM_TI_C6000");
	case EM_TI_C2000: MISSING("EM_TI_C2000");
	case EM_TI_C5500: MISSING("EM_TI_C5500");
	case EM_TI_ARP32: MISSING("EM_TI_ARP32");
	case EM_TI_PRU: MISSING("EM_TI_PRU");
	case EM_MMDSP_PLUS: MISSING("EM_MMDSP_PLUS");
	case EM_CYPRESS_M8C: MISSING("EM_CYPRESS_M8C");
	case EM_R32C: MISSING("EM_R32C");
	case EM_TRIMEDIA: MISSING("EM_TRIMEDIA");
	case EM_8051: MISSING("EM_8051");
	case EM_STXP7X: MISSING("EM_STXP7X");
	case EM_NDS32: MISSING("EM_NDS32");
	case EM_ECOG1X: MISSING("EM_ECOG1X");
	case EM_MAXQ30: MISSING("EM_MAXQ30");
	case EM_XIMO16: MISSING("EM_XIMO16");
	case EM_MANIK: MISSING("EM_MANIK");
	case EM_CRAYNV2: MISSING("EM_CRAYNV2");
	case EM_METAG: MISSING("EM_METAG");
	case EM_MCST_ELBRUS: MISSING("EM_MCST_ELBRUS");
	case EM_ECOG16: MISSING("EM_ECOG16");
	case EM_CR16: MISSING("EM_CR16");
	case EM_ETPU: MISSING("EM_ETPU");
	case EM_SLE9X: MISSING("EM_SLE9X");
	case EM_L10M: MISSING("EM_L10M");
	case EM_K10M: MISSING("EM_K10M");
	case EM_AVR32: MISSING("EM_AVR32");
	case EM_STM8: MISSING("EM_STM8");
	case EM_TILE64: MISSING("EM_TILE64");
	case EM_TILEPRO: MISSING("EM_TILEPRO");
	case EM_MICROBLAZE: MISSING("EM_MICROBLAZE");
	case EM_CUDA: MISSING("EM_CUDA");
	case EM_TILEGX: MISSING("EM_TILEGX");
	case EM_CLOUDSHIELD: MISSING("EM_CLOUDSHIELD");
	case EM_COREA_1ST: MISSING("EM_COREA_1ST");
	case EM_COREA_2ND: MISSING("EM_COREA_2ND");
	case EM_ARCV2: MISSING("EM_ARCV2");
	case EM_OPEN8: MISSING("EM_OPEN8");
	case EM_RL78: MISSING("EM_RL78");
	case EM_VIDEOCORE5: MISSING("EM_VIDEOCORE5");
	case EM_78KOR: MISSING("EM_78KOR");
	case EM_56800EX: MISSING("EM_56800EX");
	case EM_BA1: MISSING("EM_BA1");
	case EM_BA2: MISSING("EM_BA2");
	case EM_XCORE: MISSING("EM_XCORE");
	case EM_MCHP_PIC: MISSING("EM_MCHP_PIC");
	case EM_KM32: MISSING("EM_KM32");
	case EM_KMX32: MISSING("EM_KMX32");
	case EM_EMX16: MISSING("EM_EMX16");
	case EM_EMX8: MISSING("EM_EMX8");
	case EM_KVARC: MISSING("EM_KVARC");
	case EM_CDP: MISSING("EM_CDP");
	case EM_COGE: MISSING("EM_COGE");
	case EM_COOL: MISSING("EM_COOL");
	case EM_NORC: MISSING("EM_NORC");
	case EM_CSR_KALIMBA: MISSING("EM_CSR_KALIMBA");
	case EM_Z80: MISSING("EM_Z80");
	case EM_VISIUM: MISSING("EM_VISIUM");
	case EM_FT32: MISSING("EM_FT32");
	case EM_MOXIE: MISSING("EM_MOXIE");
	case EM_AMDGPU: MISSING("EM_AMDGPU");
	case EM_LANAI_OLD: MISSING("EM_LANAI_OLD");
	case EM_CEVA: MISSING("EM_CEVA");
	case EM_CEVA_X2: MISSING("EM_CEVA_X2");
	case EM_BPF: MISSING("EM_BPF");
	case EM_GRAPHCORE_IPU: MISSING("EM_GRAPHCORE_IPU");
	case EM_NFP: MISSING("EM_NFP");
	case EM_VE: MISSING("EM_VE");
	case EM_CSKY: MISSING("EM_CSKY");
	case EM_ARC_COMPACT3_64: MISSING("EM_ARC_COMPACT3_64");
	case EM_MCS6502: MISSING("EM_MCS6502");
	case EM_ARC_COMPACT3: MISSING("EM_ARC_COMPACT3");
	case EM_KVX: MISSING("EM_KVX");
	case EM_65816: MISSING("EM_65816");
	case EM_LOONGARCH: MISSING("EM_LOONGARCH");
	case EM_KF32: MISSING("EM_KF32");
	case EM_U16_U8CORE: MISSING("EM_U16_U8CORE");
	case EM_TACHYUM: MISSING("EM_TACHYUM");
	case EM_56800EF: MISSING("EM_56800EF");
	case EM_AVR_OLD: MISSING("EM_AVR_OLD");
	case EM_MSP430_OLD: MISSING("EM_MSP430_OLD");
	case EM_MT: MISSING("EM_MT");
	case EM_CYGNUS_FR30: MISSING("EM_CYGNUS_FR30");
	case EM_WEBASSEMBLY: MISSING("EM_WEBASSEMBLY");
	case EM_S12Z: MISSING("EM_S12Z");
	case EM_DLX: MISSING("EM_DLX");
	case EM_CYGNUS_FRV: MISSING("EM_CYGNUS_FRV");
	case EM_XC16X: MISSING("EM_XC16X");
	case EM_CYGNUS_D10V: MISSING("EM_CYGNUS_D10V");
	case EM_CYGNUS_D30V: MISSING("EM_CYGNUS_D30V");
	case EM_IP2K_OLD: MISSING("EM_IP2K_OLD");
	case EM_CYGNUS_POWERPC: MISSING("EM_CYGNUS_POWERPC");
	case EM_CYGNUS_M32R: MISSING("EM_CYGNUS_M32R");
	case EM_CYGNUS_V850: MISSING("EM_CYGNUS_V850");
	case EM_S390_OLD: MISSING("EM_S390_OLD");
	case EM_XTENSA_OLD: MISSING("EM_XTENSA_OLD");
	case EM_XSTORMY16: MISSING("EM_XSTORMY16");
	case EM_CYGNUS_MN10300: MISSING("EM_CYGNUS_MN10300");
	case EM_CYGNUS_MN10200: MISSING("EM_CYGNUS_MN10200");
	case EM_M32C_OLD: MISSING("EM_M32C_OLD");
	case EM_IQ2000: MISSING("EM_IQ2000");
	case EM_NIOS32: MISSING("EM_NIOS32");
	case EM_CYGNUS_MEP: MISSING("EM_CYGNUS_MEP");
	case EM_MOXIE_OLD: MISSING("EM_MOXIE_OLD");
	case EM_MICROBLAZE_OLD: MISSING("EM_MICROBLAZE_OLD");
	case EM_ADAPTEVA_EPIPHANY: MISSING("EM_ADAPTEVA_EPIPHANY");
	case EM_V810: MISSING("EM_V810");

	default:
		RZ_LOG_INFO("Unhandled reloc convert for machine %d.\n", (int)e_machine);
		return NULL;
	}
}

#undef MISSING

static void patch_relocs(RzBinFile *bf, ELFOBJ *bin) {
	rz_return_if_fail(bf && bin);
	if (bin->relocs_patched || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return;
	}
	bin->relocs_patched = true; // run this function just once (lazy relocs patching)
	RzBinObject *obj = bf->o;
	if (!obj || !obj->opts.patch_relocs || (bin->ehdr.e_type != ET_REL && bin->ehdr.e_type != ET_DYN)) {
		return;
	}
	ut64 cdsz = reloc_target_size(bin);
	ut64 size = reloc_targets_vfile_size(bf, bin);
	if (!size) {
		return;
	}
	RzBinRelocTargetBuilder *targets = rz_bin_reloc_target_builder_new(cdsz, bin->reloc_targets_map_base);
	if (!targets) {
		return;
	}
	bin->buf_patched = rz_buf_new_sparse_overlay(bf->buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!bin->buf_patched) {
		rz_bin_reloc_target_builder_free(targets);
		return;
	}
	RzBinElfReloc *reloc;
	ut64 got_addr = get_got_addr(bin);
	ut64 baddr = bf->o->opts.baseaddr;
	ut64 mips_AHL = 0;

	rz_bin_elf_foreach_relocs(bin, reloc) {
		ut64 sym_addr = 0;
		if (reloc->sym) {
			RzBinElfSymbol *import = Elf_(rz_bin_elf_get_import)(bin, reloc->sym);
			if (import) {
				sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
			} else {
				RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbol)(bin, reloc->sym);
				if (symbol) {
					sym_addr = symbol->vaddr;
					if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin) && Elf_(rz_bin_elf_is_thumb_addr)(sym_addr)) {
						Elf_(rz_bin_elf_fix_arm_thumb_addr)(&sym_addr);
					}
				} else {
					sym_addr = rz_bin_reloc_target_builder_get_target(targets, reloc->sym);
				}
			}
		}
		patch_reloc(bin, reloc, sym_addr, baddr, sym_addr, got_addr, &mips_AHL);
		reloc->target_vaddr = sym_addr;
	}
	rz_bin_reloc_target_builder_free(targets);
	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(bin->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzPVector *r = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!r) {
		return NULL;
	}
	RzBinObject *o = bf->o;
	struct Elf_(rz_bin_elf_obj_t) *obj = o ? o->bin_obj : NULL;
	if (!obj) {
		return r;
	}
	patch_relocs(bf, obj);
	// virtual file for reloc targets (where the relocs will point into)
	ut64 rtmsz = reloc_targets_vfile_size(bf, obj);
	if (rtmsz) {
		RzBuffer *buf = rz_buf_new_empty(rtmsz);
		if (!buf) {
			return r;
		}
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			rz_buf_free(buf);
			return r;
		}
		vf->buf = buf;
		vf->buf_owned = true;
		vf->name = rz_str_dup(VFILE_NAME_RELOC_TARGETS);
		rz_pvector_push(r, vf);
	}
	// virtual file mirroring the raw file, but with relocs patched
	if (obj->buf_patched) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return r;
		}
		vf->buf = obj->buf_patched;
		vf->name = rz_str_dup(VFILE_NAME_PATCHED);
		rz_pvector_push(r, vf);
	}
	return r;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	struct Elf_(rz_bin_elf_obj_t) *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	RzPVector *ret = maps_unpatched(bf);
	if (!ret) {
		return NULL;
	}

	// if relocs should be patched, use the patched vfile for everything from the file
	patch_relocs(bf, obj);
	rz_bin_relocs_patch_maps(ret, obj->buf_patched, 0, obj->reloc_targets_map_base,
		reloc_targets_vfile_size(bf, obj),
		VFILE_NAME_PATCHED,
		VFILE_NAME_RELOC_TARGETS);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	ELFOBJ *obj = (bf && bf->o) ? bf->o->bin_obj : NULL;
	RzBinSection *ptr = NULL;
	RzPVector *ret = NULL;

	if (!obj || !(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}

	// there is not leak in section since they are cached by elf.c
	// and freed within Elf_(rz_bin_elf_free)
	size_t i;
	RzBinElfSection *section;
	rz_bin_elf_enumerate_sections(obj, section, i) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		ptr->name = rz_str_dup(section->name);
		if (!ptr->name) {
			ptr->name = rz_str_dup("");
		}
		if (strstr(ptr->name, "data") && !strstr(ptr->name, "rel") && !strstr(ptr->name, "pydata")) {
			ptr->is_data = true;
		} else if (!strcmp(ptr->name, "C")) {
			ptr->is_data = true;
		}
		if (is_wordable_section(ptr->name)) {
			ptr->layout.type = RZ_META_TYPE_DATA;
			ptr->layout.element_size = sizeof(Elf_(Addr));
			ptr->layout.count = section->size / sizeof(Elf_(Addr));
		}
		ptr->size = section->type != SHT_NOBITS ? section->size : 0;
		ptr->vsize = section->size;
		ptr->paddr = section->offset;
		ptr->vaddr = section->rva;
		ptr->type = section->type;
		ptr->flags = section->flags;
		ptr->perm = section_perms_from_flags(section->flags);
		rz_pvector_push(ret, ptr);
	}

	// program headers is another section
	ut16 mach = obj->ehdr.e_machine;

	size_t n = 0;
	RzBinElfSegment *iter;
	rz_bin_elf_foreach_segments(obj, iter) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}

		ptr->size = iter->data.p_filesz;
		ptr->vsize = iter->data.p_memsz;
		ptr->paddr = iter->data.p_offset;
		ptr->vaddr = iter->data.p_vaddr;
		ptr->perm = iter->data.p_flags;
		ptr->align = iter->data.p_align;
		ptr->is_segment = true;

		switch (iter->data.p_type) {
		case PT_DYNAMIC:
			ptr->name = rz_str_dup("DYNAMIC");
			break;
		case PT_LOAD: {
			ptr->name = rz_str_newf("LOAD%zu", n++);
			ptr->perm |= RZ_PERM_R;
			break;
		}
		case PT_INTERP:
			ptr->name = rz_str_dup("INTERP");
			break;
		case PT_GNU_STACK:
			ptr->name = rz_str_dup("GNU_STACK");
			break;
		case PT_GNU_RELRO:
			ptr->name = rz_str_dup("GNU_RELRO");
			break;
		case PT_GNU_EH_FRAME:
			ptr->name = rz_str_dup("GNU_EH_FRAME");
			break;
		case PT_PHDR:
			ptr->name = rz_str_dup("PHDR");
			break;
		case PT_TLS:
			ptr->name = rz_str_dup("TLS");
			break;
		case PT_NOTE:
			ptr->name = rz_str_dup("NOTE");
			break;
		case PT_OPENBSD_RANDOMIZE:
			ptr->name = rz_str_dup("OPENBSD_RANDOMIZE");
			break;
		case PT_OPENBSD_WXNEEDED:
			ptr->name = rz_str_dup("OPENBSD_WXNEEDED");
			break;
		case PT_OPENBSD_BOOTDATA:
			ptr->name = rz_str_dup("OPENBSD_BOOTDATA");
			break;
		case PT_OPENBSD_NOBTCFI:
			ptr->name = rz_str_dup("OPENBSD_NOBTCFI");
			break;
		default:
			if (ptr->size == 0 && ptr->vsize == 0) {
				ptr->name = rz_str_dup("NONE");
			} else {
				ptr->name = setphname(mach, iter->data.p_type);
			}
			break;
		}
		rz_pvector_push(ret, ptr);
	}

	// add entry for ehdr
	ptr = RZ_NEW0(RzBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof(obj->ehdr);
		if (bf->size < ehdr_size) {
			ehdr_size = bf->size;
		}
		ptr->name = rz_str_dup("ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->perm = RZ_PERM_RW;
		ptr->is_segment = true;
		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		RzBinSymbol *tmp = convert_symbol(bin, symbol);
		if (!tmp) {
			rz_pvector_free(ret);
			return NULL;
		}

		rz_pvector_push(ret, tmp);
	}

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		RzBinSymbol *tmp = convert_symbol(bin, import);
		if (!tmp) {
			rz_pvector_free(ret);
			return NULL;
		}

		tmp->is_imported = true;

		rz_pvector_push(ret, tmp);
	}

	return ret;
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	ELFOBJ *bin = bf->o->bin_obj;

	if (!Elf_(rz_bin_elf_has_imports)(bin)) {
		return NULL;
	}

	RzPVector *result = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	if (!result) {
		return NULL;
	}

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		RzBinImport *tmp = convert_import(import);
		if (!tmp) {
			rz_pvector_free(result);
			return NULL;
		}

		rz_pvector_push(result, tmp);
	}

	return result;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	return Elf_(rz_bin_elf_get_libs)(bf->o->bin_obj);
}

static RzPVector /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzPVector *ret = NULL;
	RzBinReloc *ptr = NULL;

	if (!bf->o) {
		return NULL;
	}

	ELFOBJ *bin = bf->o->bin_obj;
	if (!bin || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return NULL;
	}

	patch_relocs(bf, bin);

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free))) {
		return NULL;
	}

	ut64 got_addr = get_got_addr(bin);

	if (!got_addr) {
		got_addr = bin->reloc_targets_map_base;
	}

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (!(ptr = reloc_convert(bin, reloc, got_addr))) {
			continue;
		}

		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static void lookup_symbols(RzBinFile *bf, RzBinInfo *ret) {
	RzPVector *symbols_vec = symbols(bf);
	void **iter;
	RzBinSymbol *symbol;
	bool is_rust = false;
	if (symbols_vec) {
		rz_pvector_foreach (symbols_vec, iter) {
			symbol = *iter;
			if (ret->has_canary && is_rust) {
				break;
			}
			if (!strcmp(symbol->name, "_NSConcreteGlobalBlock")) {
				ret->lang = (ret->lang && !strcmp(ret->lang, "c++")) ? "c++ blocks ext." : "c blocks ext.";
			}
			if (!ret->has_canary) {
				if (strstr(symbol->name, "__stack_chk_fail") || strstr(symbol->name, "__stack_smash_handler")) {
					ret->has_canary = true;
				}
			}
			if (!is_rust && !strcmp(symbol->name, "__rust_oom")) {
				is_rust = true;
				ret->lang = "rust";
			}
		}
		rz_pvector_free(symbols_vec);
	}
}

static void lookup_sections(RzBinFile *bf, RzBinInfo *ret) {
	RzPVector *sections_vec = sections(bf);
	void **iter;
	RzBinSection *section;
	ret->has_retguard = -1;
	rz_pvector_foreach (sections_vec, iter) {
		section = *iter;
		if (ret->has_retguard != -1) {
			break;
		}
#define RZ_BIN_RANDOMDATA_RETGUARD_SZ 48
		if (!strcmp(section->name, ".openbsd.randomdata")) {
			// The retguard cookie adds 8 per return function inst.
			ret->has_retguard = (section->size >= RZ_BIN_RANDOMDATA_RETGUARD_SZ);
			break;
		}
	}
	rz_pvector_free(sections_vec);
}

static bool has_sanitizers(RzBinFile *bf) {
	bool ret = false;
	RzPVector *imports_vec = imports(bf);
	if (!imports_vec) {
		return ret;
	}
	void **iter;
	RzBinImport *import;
	rz_pvector_foreach (imports_vec, iter) {
		import = *iter;
		if (strstr(import->name, "__sanitizer") ||
			strstr(import->name, "__ubsan")) {
			ret = true;
			break;
		}
	}
	rz_pvector_free(imports_vec);
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	char *str;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ELFOBJ *obj = bf->o->bin_obj;
	if ((str = Elf_(rz_bin_elf_get_rpath)(obj))) {
		ret->rpath = rz_str_dup(str);
		free(str);
	} else {
		ret->rpath = rz_str_dup("NONE");
	}
	if (!(str = Elf_(rz_bin_elf_get_file_type)(obj))) {
		free(ret);
		return NULL;
	}
	ret->type = str;
	ret->has_pi = (strstr(str, "DYN")) ? 1 : 0;
	ret->has_sanitizers = has_sanitizers(bf);
	if (!(str = Elf_(rz_bin_elf_get_elf_class)(obj))) {
		free(ret);
		return NULL;
	}
	ret->bclass = str;
	if (!(str = Elf_(rz_bin_elf_get_osabi_name)(obj))) {
		free(ret);
		return NULL;
	}
	ret->os = str;
	if (!(str = Elf_(rz_bin_elf_get_osabi_name)(obj))) {
		free(ret);
		return NULL;
	}
	ret->subsystem = str;
	if (!(str = Elf_(rz_bin_elf_get_machine_name)(obj))) {
		free(ret);
		return NULL;
	}
	ret->machine = str;
	if (!(str = Elf_(rz_bin_elf_get_head_flag)(obj))) {
		free(ret);
		return NULL;
	}
	ret->head_flag = str;
	if (!(str = Elf_(rz_bin_elf_get_arch)(obj))) {
		free(ret);
		return NULL;
	}
	ret->arch = str;

	if ((str = Elf_(rz_bin_elf_get_cpu)(obj))) {
		ret->cpu = str;
	}
	if ((str = Elf_(rz_bin_elf_get_abi)(obj))) {
		ret->features = str;
		if (!ret->has_pi) {
			// Elf MIPS PIE flag is in features.
			ret->has_pi = (strstr(str, "pic ")) ? 1 : 0;
		}
	}

	ret->rclass = rz_str_dup("elf");
	ret->bits = obj->bits;
	if (!strcmp(ret->arch, "avr")) {
		ret->bits = 16;
	}
	ret->big_endian = Elf_(rz_bin_elf_is_big_endian)(obj);
	ret->has_va = Elf_(rz_bin_elf_has_va)(obj);
	ret->has_nx = Elf_(rz_bin_elf_has_nx)(obj);
	ret->has_nobtcfi = Elf_(rz_bin_elf_has_nobtcfi)(obj);
	ret->intrp = Elf_(rz_bin_elf_get_intrp)(obj);
	ret->compiler = Elf_(rz_bin_elf_get_compiler)(obj);
	ret->dbg_info = 0;
	if (!Elf_(rz_bin_elf_is_stripped)(obj)) {
		ret->dbg_info |= RZ_BIN_DBG_LINENUMS | RZ_BIN_DBG_SYMS | RZ_BIN_DBG_RELOCS;
	} else {
		ret->dbg_info |= RZ_BIN_DBG_STRIPPED;
	}
	if (Elf_(rz_bin_elf_is_static)(obj)) {
		ret->dbg_info |= RZ_BIN_DBG_STATIC;
	}
	lookup_sections(bf, ret);
	lookup_symbols(bf, ret);

	return ret;
}

static bool add_fields_aux(ELFOBJ *bin, RzPVector /*<RzBinField *>*/ *result, ut64 offset, size_t size, const char *name, char *(get_value)(ELFOBJ *bin), const char *fmt) {
	char *value = get_value(bin);
	if (!value) {
		return false;
	}

	RzBinField *field = rz_bin_field_new(offset, offset, size, name, value, fmt, false);
	if (!field) {
		free(value);
		return false;
	}

	if (!rz_pvector_push(result, field)) {
		rz_bin_field_free(field);
		free(value);
		return false;
	}

	free(value);
	return true;
}

static bool add_fields(ELFOBJ *bin, RzPVector /*<RzBinField *>*/ *result) {
	size_t size = bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? 8 : 4;

	return add_fields_aux(bin, result, E_IDENT_OFFSET, 16, "MAGIC", Elf_(rz_bin_elf_get_e_indent_as_string), "x") &&
		add_fields_aux(bin, result, E_TYPE_OFFSET, 2, "Type", Elf_(rz_bin_elf_get_e_type_as_string), "x") &&
		add_fields_aux(bin, result, E_MACHINE_OFFSET, 2, "Machine", Elf_(rz_bin_elf_get_e_machine_as_string), "x") &&
		add_fields_aux(bin, result, E_VERSION_OFFSET, 4, "Version", Elf_(rz_bin_elf_get_e_version_as_string), "x") &&
		add_fields_aux(bin, result, E_ENTRYPOINT_OFFSET, size, "Entrypoint", Elf_(rz_bin_elf_get_e_entry_as_string), "x") &&
		add_fields_aux(bin, result, E_PHOFF_OFFSET, size, "PhOff", Elf_(rz_bin_elf_get_e_phoff_as_string), "x") &&
		add_fields_aux(bin, result, E_SHOFF_OFFSET, size, "ShOff", Elf_(rz_bin_elf_get_e_shoff_as_string), "x") &&
		add_fields_aux(bin, result, E_FLAGS_OFFSET, 4, "Flags", Elf_(rz_bin_elf_get_e_flags_as_string), "x") &&
		add_fields_aux(bin, result, E_EHSIZE_OFFSET, 2, "EhSize", Elf_(rz_bin_elf_get_e_ehsize_as_string), "x") &&
		add_fields_aux(bin, result, E_PHENTSIZE_OFFSET, 2, "PhentSize", Elf_(rz_bin_elf_get_e_phentsize_as_string), "d") &&
		add_fields_aux(bin, result, E_PHNUM_OFFSET, 2, "PhNum", Elf_(rz_bin_elf_get_e_phnum_as_string), "d") &&
		add_fields_aux(bin, result, E_SHENTSIZE_OFFSET, 2, "ShentSize", Elf_(rz_bin_elf_get_e_shentsize_as_string), "d") &&
		add_fields_aux(bin, result, E_SHNUM_OFFSET, 2, "ShNum", Elf_(rz_bin_elf_get_e_shnum_as_string), "d") &&
		add_fields_aux(bin, result, E_SHSTRNDX_OFFSET, 2, "ShStrndx", Elf_(rz_bin_elf_get_e_shstrndx_as_string), "d");
}

static RzPVector /*<RzBinField *>*/ *fields(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = rz_bin_file_get_elf(bf);

	RzPVector *result = rz_pvector_new((RzPVectorFree)rz_bin_field_free);
	if (!result) {
		return NULL;
	}

	if (!add_fields(bin, result)) {
		rz_pvector_free(result);
		return NULL;
	}

	return result;
}

static ut64 size(RzBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (!bf->o->sections) {
		void **iter;
		RzBinSection *section;
		bf->o->sections = sections(bf);
		rz_pvector_foreach (bf->o->sections, iter) {
			section = *iter;
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}
