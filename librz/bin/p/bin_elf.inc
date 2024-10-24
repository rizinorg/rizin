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
	result->name = rz_str_dup(elf_symbol->name);
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
		RZ_LOG_WARN("Patching for reloc type %d not implemented.\n", rel_type);
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

// AARCH64-specific defines
// Take the PAGE component of an address or offset.
#define PG(x)         ((x) & ~0xFFFULL)
#define PG_OFFSET(x)  ((x)&0xFFFULL)
#define ADR_IMM_MASK1 (((1U << 2) - 1) << 29)
#define ADR_IMM_MASK2 (((1U << 19) - 1) << 5)
#define ADR_IMM_MASK3 (((1U << 19) - 1) << 2)

static void patch_reloc(struct Elf_(rz_bin_elf_obj_t) * obj, RzBinElfReloc *rel, ut64 S, ut64 B, ut64 L, ut64 GOT) {
	ut16 e_machine = obj->ehdr.e_machine;
	ut64 val = 0;
	ut64 A = rel->addend, P = rel->vaddr;
	RzBinRelocFormularSymbols formular_sym = { .A = A, .B = B, .GOT = GOT, .L = L, .S = S, .P = P, .MB = 0, .G = 0, .GP = 0, .T = 0, .TLS = 0 };
	ut64 patch_addr = rel->paddr != UT64_MAX ? rel->paddr : Elf_(rz_bin_elf_v2p)(obj, rel->vaddr);
	ut8 buf[8];
	bool big_endian = obj->big_endian;
	switch (e_machine) {
	case EM_QDSP6:
		patch_reloc_hexagon(obj->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_ARM: {
		ut16 keephw1, keephw2;
		ut32 nbytes = 4;
		rz_buf_read_at(obj->buf_patched, patch_addr, buf, 4);
		switch (rel->type) {
		case RZ_ARM_THM_JUMP24:
		case RZ_ARM_THM_PC22:
			// Encoding B  T4, BL T1, BLX T2: Val = S:I1:I2:imm10:imm11:0
			// I1 = NOT(J1 EOR S)
			// I2 = NOT(J2 EOR S)
			val = S + A;
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
			val = S + A;
			if (!rel->sym && rel->mode == DT_REL) {
				val += rz_read_ble32(buf, big_endian);
			}
			rz_write_ble32(buf, val, big_endian);
		}
		rz_buf_write_at(obj->buf_patched, patch_addr, buf, nbytes);
		break;
	}
	case EM_AARCH64: {
		ut32 keep;
		ut32 nbytes = 4;
		rz_buf_read_at(obj->buf_patched, patch_addr, buf, 8);
		switch (rel->type) {
		case RZ_AARCH64_ABS16:
			val = S + A;
			rz_write_le16(buf, val);
			nbytes = 2;
			break;
		case RZ_AARCH64_ABS32:
			val = S + A;
			rz_write_le32(buf, val);
			break;
		case RZ_AARCH64_GLOB_DAT:
		case RZ_AARCH64_ABS64:
		case RZ_AARCH64_JUMP_SLOT:
			val = S + A;
			rz_write_le64(buf, val);
			nbytes = 8;
			break;
		case RZ_AARCH64_PREL16:
			val = S + A - P;
			rz_write_le16(buf, val);
			nbytes = 2;
			break;
		case RZ_AARCH64_PREL32:
			val = S + A - P;
			rz_write_le32(buf, val);
			break;
		case RZ_AARCH64_PREL64:
			val = S + A - P;
			rz_write_le64(buf, val);
			nbytes = 8;
			break;
		case RZ_AARCH64_RELATIVE:
			val = B + A;
			rz_write_le64(buf, val);
			nbytes = 8;
			break;
		case RZ_AARCH64_ADR_PREL_PG_HI21:
		case RZ_AARCH64_ADR_PREL_PG_HI21_NC:
		case RZ_AARCH64_ADR_GOT_PAGE:
			// Reencode ADR imm
			keep = rz_read_le32(buf) & ~(ADR_IMM_MASK1 | ADR_IMM_MASK2);
			val = ((st64)(PG(S + A) - PG(P))) >> 12;
			rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(2, 0)) << 29) | ((val & ADR_IMM_MASK3) << 3));
			break;
		case RZ_AARCH64_JUMP26:
		case RZ_AARCH64_CALL26:
			// Reencode 26 bits of the offset
			keep = rz_read_le32(buf) & ~RZ_BIT_MASK32(26, 0);
			val = ((st64)(S + A - P)) >> 2;
			rz_write_le32(buf, keep | (val & RZ_BIT_MASK32(26, 0)));
			break;
		case RZ_AARCH64_LDST8_ABS_LO12_NC:
		case RZ_AARCH64_ADD_ABS_LO12_NC:
			keep = rz_read_le32(buf) & ~(RZ_BIT_MASK32(12, 0) << 10);
			val = PG_OFFSET(S + A);
			rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(12, 0)) << 10));
			break;
		case RZ_AARCH64_LD64_GOT_LO12_NC:
		case RZ_AARCH64_LDST64_ABS_LO12_NC:
			// Reencode LD/ST imm
			keep = rz_read_le32(buf) & ~(RZ_BIT_MASK32(12, 0) << 10);
			val = PG_OFFSET(S + A) >> 3;
			rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(12, 0)) << 10));
			break;
		default:
			nbytes = 0;
			break;
		}
		rz_buf_write_at(obj->buf_patched, patch_addr, buf, nbytes);
		break;
	}
	case EM_PPC64: {
		int low = 0, word = 0;
		switch (rel->type) {
		case RZ_PPC64_ADDR24:
			low = 24;
			val = (S + A) >> 2;
			break;
		case RZ_PPC64_ADDR16_HI:
			word = 2;
			val = (S + A) >> 16;
			break;
		case RZ_PPC64_ADDR16_HA:
			word = 2;
			val = (S + A + 0x8000) >> 16;
			break;
		case RZ_PPC64_REL16_HA:
			word = 2;
			val = (S + A - P + 0x8000) >> 16;
			break;
		case RZ_PPC64_ADDR16_LO:
			word = 2;
			val = (S + A) & 0xffff;
			break;
		case RZ_PPC64_REL16_LO:
			word = 2;
			val = (S + A - P) & 0xffff;
			break;
		case RZ_PPC64_REL14:
			low = 14;
			val = (st64)(S + A - P) >> 2;
			break;
		case RZ_PPC64_REL24:
			low = 24;
			val = (st64)(S + A - P) >> 2;
			break;
		case RZ_PPC64_REL32:
			word = 4;
			val = S + A - P;
			break;
		default:
			RZ_LOG_WARN("Reloc type %d not implemented.\n", rel->type);
			break;
		}
		if (low) {
			switch (low) {
			case 14:
				val &= (1 << 14) - 1;
				rz_buf_read_at(obj->buf_patched, patch_addr, buf, 2);
				rz_write_ble32(buf, (rz_read_ble32(buf, big_endian) & ~(RZ_BIT_MASK32(16, 2))) | val << 2, big_endian);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 2);
				break;
			case 24:
				val &= (1 << 24) - 1;
				rz_buf_read_at(obj->buf_patched, patch_addr, buf, 4);
				rz_write_ble32(buf, (rz_read_ble32(buf, big_endian) & ~(RZ_BIT_MASK32(26, 2))) | val << 2, big_endian);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
				break;
			}
		} else if (word) {
			switch (word) {
			case 2:
				rz_write_ble16(buf, val, big_endian);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 2);
				break;
			case 4:
				rz_write_ble32(buf, val, big_endian);
				rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
				break;
			}
		}
		break;
	}
	case EM_386:
		switch (rel->type) {
		case RZ_386_32:
		case RZ_386_PC32:
			rz_buf_read_at(obj->buf_patched, patch_addr, buf, 4);
			val = rz_read_le32(buf) + S + A;
			if (rel->type == RZ_386_PC32) {
				val -= P;
			}
			rz_write_le32(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
		default:
			break;
		}
		break;
	case EM_X86_64: {
		int word = 0;
		switch (rel->type) {
		case RZ_X86_64_8:
			word = 1;
			val = S + A;
			break;
		case RZ_X86_64_16:
			word = 2;
			val = S + A;
			break;
		case RZ_X86_64_32:
		case RZ_X86_64_32S:
			word = 4;
			val = S + A;
			break;
		case RZ_X86_64_64:
			word = 8;
			val = S + A;
			break;
		case RZ_X86_64_GLOB_DAT:
		case RZ_X86_64_JUMP_SLOT:
			word = 4;
			val = S;
			break;
		case RZ_X86_64_PC8:
			word = 1;
			val = S + A - P;
			break;
		case RZ_X86_64_PC16:
			word = 2;
			val = S + A - P;
			break;
		case RZ_X86_64_PC32:
			word = 4;
			val = S + A - P;
			break;
		case RZ_X86_64_PC64:
			word = 8;
			val = S + A - P;
			break;
		case RZ_X86_64_PLT32:
			word = 4;
			val = L + A - P;
			break;
		case RZ_X86_64_RELATIVE:
			word = 8;
			val = B + A;
			break;
		default:
			// RZ_LOG_ERROR("relocation %d not handle at this time\n", rel->type);
			break;
		}
		switch (word) {
		case 0:
			break;
		case 1:
			buf[0] = val;
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 1);
			break;
		case 2:
			rz_write_le16(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 2);
			break;
		case 4:
			rz_write_le32(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 4);
			break;
		case 8:
			rz_write_le64(buf, val);
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 8);
			break;
		}
		break;
	}
	case EM_RX:
		// no dynamic for rx-elf program, handle rx elf object reloc type (emulate linkage map)
		// and no GOT/PLT for existed for rx-elf, leave no imports info for extern symbol
		switch (rel->type) {
		// simply use rizin default symbol resolution to map OBJECT variable symbol to vaddr
		case R_RX_NONE: break;
		case R_RX_DIR32:
			val = S + A;
			rz_buf_write_ble32_at(obj->buf_patched, patch_addr, val, obj->big_endian);
			break;
		case R_RX_DIR24S_PCREL:
			val = S + A - P + 1;
			if (obj->big_endian) {
				buf[2] = val;
				buf[1] = val >> 8;
				buf[0] = val >> 16;
			} else {
				buf[0] = val;
				buf[1] = val >> 8;
				buf[2] = val >> 16;
			}
			// write 3 Bytes
			rz_buf_write_at(obj->buf_patched, patch_addr, buf, 3);
			break;
		default:
			RZ_LOG_WARN("Reloc type %d for Renesas RX family not implemented yet.\n", rel->type);
			break;
		}
	}
}

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

static RzBinReloc *reloc_convert(ELFOBJ *bin, RzBinElfReloc *rel, ut64 GOT) {
	rz_return_val_if_fail(bin && rel, NULL);

	ut64 B = bin->baddr;
	ut64 P = rel->vaddr; // rva has taken baddr into account
	RzBinReloc *r = RZ_NEW0(RzBinReloc);
	if (!r) {
		return NULL;
	}
	r->import = NULL;
	r->symbol = NULL;
	r->is_ifunc = false;
	r->addend = rel->addend;
	if (rel->sym) {
		r->import = get_import(bin, rel->sym);
		if (!r->import) {
			r->symbol = get_symbol(bin, rel->sym);
		}
	}
	r->vaddr = rel->vaddr;
	r->paddr = rel->paddr;
	r->target_vaddr = rel->target_vaddr;

	RzBinElfSection *section = rel->section > 0 ? Elf_(rz_bin_elf_get_section)(bin, rel->section) : NULL;
	if (section) {
		r->section_vaddr = section->rva;
	}

#define SET(T) \
	r->type = RZ_BIN_RELOC_##T; \
	r->additive = 0; \
	return r
#define ADD(T, A) \
	r->type = RZ_BIN_RELOC_##T; \
	r->addend += (A); \
	r->additive = rel->mode == DT_RELA; \
	return r

	switch (bin->ehdr.e_machine) {
	case EM_386:
		switch (rel->type) {
		case RZ_386_NONE: break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case RZ_386_32: ADD(32, 0);
		case RZ_386_PC32: ADD(32, -P);
		case RZ_386_GLOB_DAT: SET(32);
		case RZ_386_JMP_SLOT: SET(32);
		case RZ_386_RELATIVE: ADD(32, B);
		case RZ_386_GOTOFF: ADD(32, -GOT);
		case RZ_386_GOTPC: ADD(32, GOT - P);
		case RZ_386_16: ADD(16, 0);
		case RZ_386_PC16: ADD(16, -P);
		case RZ_386_8: ADD(8, 0);
		case RZ_386_PC8: ADD(8, -P);
		case RZ_386_COPY: ADD(32, 0); // copy symbol at runtime
		case RZ_386_IRELATIVE: r->is_ifunc = true; SET(32);
		default:
			RZ_LOG_WARN("unimplemented ELF/X86_32 reloc type %d\n", rel->type);
			break;
		}
		break;
	case EM_X86_64:
		switch (rel->type) {
		case RZ_X86_64_NONE: break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case RZ_X86_64_64: ADD(64, 0);
		case RZ_X86_64_PLT32: ADD(32, -P /* +L */);
		case RZ_X86_64_GOT32: ADD(32, GOT);
		case RZ_X86_64_PC32: ADD(32, -P);
		case RZ_X86_64_GLOB_DAT: r->vaddr -= rel->sto; SET(64);
		case RZ_X86_64_JUMP_SLOT: r->vaddr -= rel->sto; SET(64);
		case RZ_X86_64_RELATIVE: ADD(64, B);
		case RZ_X86_64_32: ADD(32, 0);
		case RZ_X86_64_32S: ADD(32, 0);
		case RZ_X86_64_16: ADD(16, 0);
		case RZ_X86_64_PC16: ADD(16, -P);
		case RZ_X86_64_8: ADD(8, 0);
		case RZ_X86_64_PC8: ADD(8, -P);
		case RZ_X86_64_GOTPCREL: ADD(64, GOT - P);
		case RZ_X86_64_COPY: ADD(64, 0); // copy symbol at runtime
		case RZ_X86_64_IRELATIVE: r->is_ifunc = true; SET(64);
		default:
			RZ_LOG_WARN("unimplemented ELF/X86_64 reloc type %d\n", rel->type);
			break;
		}
		break;
	case EM_ARM:
		switch (rel->type) {
		case RZ_ARM_NONE: break;
		case RZ_ARM_ABS32: ADD(32, 0);
		case RZ_ARM_REL32: ADD(32, -P);
		case RZ_ARM_ABS16: ADD(16, 0);
		case RZ_ARM_ABS8: ADD(8, 0);
		case RZ_ARM_SBREL32: ADD(32, -B);
		case RZ_ARM_GLOB_DAT: ADD(32, 0);
		case RZ_ARM_JUMP_SLOT: ADD(32, 0);
		case RZ_ARM_COPY: ADD(32, 0); // copy symbol at runtime
		case RZ_ARM_RELATIVE: ADD(32, B);
		case RZ_ARM_GOTOFF: ADD(32, -GOT);
		case RZ_ARM_GOTPC: ADD(32, GOT - P);
		case RZ_ARM_CALL: ADD(24, -P);
		case RZ_ARM_JUMP24: ADD(24, -P);
		case RZ_ARM_THM_JUMP24: ADD(24, -P);
		case RZ_ARM_THM_PC22: ADD(24, -P);
		case RZ_ARM_PREL31: ADD(32, -P);
		case RZ_ARM_MOVW_PREL_NC: ADD(16, -P);
		case RZ_ARM_MOVT_PREL: ADD(32, -P);
		case RZ_ARM_THM_MOVW_PREL_NC: ADD(16, -P);
		case RZ_ARM_REL32_NOI: ADD(32, -P);
		case RZ_ARM_ABS32_NOI: ADD(32, 0);
		case RZ_ARM_ALU_PC_G0_NC: ADD(32, -P);
		case RZ_ARM_ALU_PC_G0: ADD(32, -P);
		case RZ_ARM_ALU_PC_G1_NC: ADD(32, -P);
		case RZ_ARM_ALU_PC_G1: ADD(32, -P);
		case RZ_ARM_ALU_PC_G2: ADD(32, -P);
		case RZ_ARM_LDR_PC_G1: ADD(32, -P);
		case RZ_ARM_LDR_PC_G2: ADD(32, -P);
		case RZ_ARM_LDRS_PC_G0: ADD(32, -P);
		case RZ_ARM_LDRS_PC_G1: ADD(32, -P);
		case RZ_ARM_LDRS_PC_G2: ADD(32, -P);
		case RZ_ARM_LDC_PC_G0: ADD(32, -P);
		case RZ_ARM_LDC_PC_G1: ADD(32, -P);
		case RZ_ARM_LDC_PC_G2: ADD(32, -P);
		default: ADD(32, GOT); break; // reg relocations
		}
		break;
	case EM_RISCV:
		switch (rel->type) {
		case RZ_RISCV_NONE: break;
		case RZ_RISCV_JUMP_SLOT: ADD(64, 0);
		case RZ_RISCV_RELATIVE: ADD(64, B);
		default: ADD(64, GOT); break; // reg relocations
		}
		break;
	case EM_AARCH64:
		switch (rel->type) {
		case RZ_AARCH64_NONE: break;
		case RZ_AARCH64_ABS64: ADD(64, 0);
		case RZ_AARCH64_ABS32: ADD(32, 0);
		case RZ_AARCH64_ABS16: ADD(16, 0);
		case RZ_AARCH64_PREL64: ADD(64, 0);
		case RZ_AARCH64_PREL32: ADD(32, 0);
		case RZ_AARCH64_PREL16: ADD(16, 0);
		case RZ_AARCH64_GLOB_DAT: SET(64);
		case RZ_AARCH64_JUMP_SLOT: SET(64);
		case RZ_AARCH64_RELATIVE: ADD(64, B);
		case RZ_AARCH64_LDST8_ABS_LO12_NC: ADD(16, 0);
		case RZ_AARCH64_ADD_ABS_LO12_NC: ADD(16, 0);
		case RZ_AARCH64_JUMP26: ADD(32, 0);
		case RZ_AARCH64_CALL26: ADD(32, 0);
		case RZ_AARCH64_LDST64_ABS_LO12_NC: ADD(32, 0);
		case RZ_AARCH64_LD64_GOT_LO12_NC: ADD(32, 0);
		// Page-relative relocations
		case RZ_AARCH64_ADR_GOT_PAGE: ADD(32, 0);
		case RZ_AARCH64_ADR_PREL_PG_HI21: ADD(32, 0);
		case RZ_AARCH64_ADR_PREL_PG_HI21_NC: ADD(32, 0);
		default:
			RZ_LOG_WARN("unimplemented ELF/AARCH64 reloc type %d\n", rel->type);
			break;
		}
		break;
	case EM_PPC:
		switch (rel->type) {
		case RZ_PPC_NONE: break;
		case RZ_PPC_GLOB_DAT: ADD(32, 0);
		case RZ_PPC_JMP_SLOT: ADD(32, 0);
		case RZ_PPC_COPY: ADD(32, 0); // copy symbol at runtime
		case RZ_PPC_REL24: ADD(24, -P);
		case RZ_PPC_REL14: ADD(16, -P);
		case RZ_PPC_REL32: ADD(32, -P);
		case RZ_PPC_RELATIVE: ADD(32, -P);
		case RZ_PPC_PLT32: ADD(32, -P);
		case RZ_PPC_ADDR16: ADD(16, 0);
		case RZ_PPC_ADDR32: ADD(32, 0);
		default:
			RZ_LOG_WARN("unimplemented ELF/PPC reloc type %d\n", rel->type);
			break;
		}
		break;
	case EM_RX:
		switch (rel->type) {
		case R_RX_NONE: break;
		case R_RX_DIR24S_PCREL: ADD(24, -P);
		case R_RX_DIR32: SET(32);
		default:
			RZ_LOG_WARN("unimplemented ELF/RX reloc type %d\n", rel->type);
			break;
		}
	default: break;
	}

#undef SET
#undef ADD

	rz_bin_reloc_free(r);
	return NULL;
}

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
		patch_reloc(bin, reloc, sym_addr, baddr, sym_addr, got_addr);
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
			ptr->format = rz_str_newf("Cd %zu %" PFMT64d, sizeof(Elf_(Addr)), section->size / sizeof(Elf_(Addr)));
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
