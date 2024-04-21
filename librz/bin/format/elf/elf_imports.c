// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define MIPS_PLT_OFFSET                      0x20
#define RISCV_PLT_ENTRY_SIZE                 0x10
#define RISCV_PLT_OFFSET                     0x20
#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR   -0x6
#define X86_PLT_ENTRY_SIZE                   0x10

#define COMPUTE_PLTGOT_POSITION(rel, pltgot_addr, n_initial_unused_entries) \
	((rel->vaddr - pltgot_addr - n_initial_unused_entries * sizeof(Elf_(Addr))) / sizeof(Elf_(Addr)))

static ut64 get_got_entry(ELFOBJ *bin, RzBinElfReloc *rel) {
	Elf_(Addr) addr;

	if (rel->paddr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 paddr = rel->paddr;
	if (!Elf_(rz_bin_elf_read_addr)(bin, &paddr, &addr) || !addr) {
		return UT64_MAX;
	}

	return addr;
}

static ut64 get_import_addr_mips(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 jmprel_addr;
	ut64 got_addr;
	ut64 dt_pltrelsz;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_JMPREL, &jmprel_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_MIPS_PLTGOT, &got_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTRELSZ, &dt_pltrelsz)) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x2);

	ut8 buf[1024];
	ut64 plt_addr = jmprel_addr + dt_pltrelsz;
	ut64 p_plt_addr = Elf_(rz_bin_elf_v2p)(bin, plt_addr);
	int res = rz_buf_read_at(bin->b, p_plt_addr, buf, sizeof(buf));
	if (res != sizeof(buf)) {
		return UT64_MAX;
	}

	const ut8 *base = rz_mem_mem_aligned(buf, sizeof(buf), (const ut8 *)"\x3c\x0f\x00", 3, 4);
	plt_addr += base ? (int)(size_t)(base - buf) : MIPS_PLT_OFFSET + 8; // HARDCODED HACK
	plt_addr += pos * 16;

	return plt_addr;
}

/**
 * \brief Determines and returns the import address for the given relocation
 * for the Hexagon architecture.
 *
 * \param eo The ElfObject.
 * \param rel The Elf relocation to get the address for.
 *
 * \return The import address or UT64_MAX in case of failure.
 */
static ut64 get_import_addr_hexagon(ELFOBJ *eo, RzBinElfReloc *rel) {
	ut64 got_addr = 0;

	if (!Elf_(rz_bin_elf_get_dt_info)(eo, DT_PLTGOT, &got_addr) || got_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(eo, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	const ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);

	switch (rel->type) {
	default:
		RZ_LOG_WARN("Unhandled hexagon reloc type %d\n", rel->type);
		return UT64_MAX;
	case R_HEX_JMP_SLOT:
		return plt_addr + pos * 16 + 32;
	}
}

static ut64 get_import_addr_riscv(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 got_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x2);
	return plt_addr + RISCV_PLT_OFFSET + pos * RISCV_PLT_ENTRY_SIZE;
}

static ut64 get_import_addr_sparc(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (rel->type != RZ_SPARC_JMP_SLOT) {
		RZ_LOG_WARN("Unknown sparc reloc type %d\n", rel->type);
		return UT64_MAX;
	}
	ut64 tmp = get_got_entry(bin, rel);

	return (tmp == UT64_MAX) ? UT64_MAX : tmp + SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_ppc(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 plt_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &plt_addr)) {
		return UT64_MAX;
	}

	ut64 p_plt_addr = Elf_(rz_bin_elf_v2p)(bin, plt_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut32 tmp;
	if (!rz_buf_read_ble32_at(bin->b, p_plt_addr, &tmp, bin->big_endian)) {
		return UT64_MAX;
	}

	ut64 nrel = Elf_(rz_bin_elf_get_num_relocs_dynamic_plt)(bin);
	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, plt_addr, 0x0);

	ut64 base = tmp;

	if (bin->big_endian) {
		base -= (nrel * 16);
		base += (pos * 16);
		return base;
	}

	base -= (nrel * 12) + 20;
	base += (pos * 8);

	return base;
}

static ut64 get_import_addr_x86_manual(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 got_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
		return UT64_MAX;
	}

	ut64 got_offset = Elf_(rz_bin_elf_v2p)(bin, got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	// XXX HACK ALERT!!!! full relro?? try to fix it
	// will there always be .plt.got, what would happen if is .got.plt?
	RzBinElfSection *s = Elf_(rz_bin_elf_get_section_with_name)(bin, ".plt.got");
	if (Elf_(rz_bin_elf_has_relro)(bin) < RZ_BIN_ELF_PART_RELRO || !s) {
		return UT64_MAX;
	}

	ut64 plt_addr = s->offset;
	Elf_(Word) plt_sym_addr;

	while (plt_addr + 2 + 4 < s->offset + s->size) {
		/*we try to locate the plt entry that correspond with the relocation
		  since got does not point back to .plt. In this case it has the following
		  form
		  ff253a152000   JMP QWORD [RIP + 0x20153A]
		  6690		     NOP
		  ----
		  ff25ec9f0408   JMP DWORD [reloc.puts_236]
		  plt_addr + 2 to remove jmp opcode and get the imm reading 4
		  and if RIP (plt_addr + 6) + imm == rel->offset
		  return plt_addr, that will be our sym addr
		  perhaps this hack doesn't work on 32 bits
		  */
		ut64 pos = plt_addr + 2;

		if (!Elf_(rz_bin_elf_read_word)(bin, &pos, &plt_sym_addr)) {
			return UT64_MAX;
		}

		ut64 tmp = Elf_(rz_bin_elf_v2p)(bin, plt_sym_addr);
		if (tmp == UT64_MAX) {
			tmp = plt_sym_addr;
		}

		// relative address
		if ((plt_addr + 6 + tmp) == rel->vaddr) {
			return plt_addr;
		}

		if (plt_sym_addr == rel->vaddr) {
			return plt_addr;
		}

		plt_addr += 8;
	}

	return UT64_MAX;
}

static ut64 get_import_addr_x86(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 tmp = get_got_entry(bin, rel);
	if (tmp == UT64_MAX) {
		return get_import_addr_x86_manual(bin, rel);
	}

	RzBinElfSection *pltsec_section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".plt.sec");

	if (pltsec_section) {
		ut64 got_addr;

		if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
			return UT64_MAX;
		}

		ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);
		return pltsec_section->rva + pos * X86_PLT_ENTRY_SIZE;
	}

	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_arm(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 got_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);

	switch (rel->type) {
	case RZ_ARM_JUMP_SLOT:
		plt_addr += pos * 12 + 20;
		if (Elf_(rz_bin_elf_is_thumb_addr)(plt_addr)) {
			plt_addr--;
		}
		return plt_addr;
	case RZ_AARCH64_RELATIVE:
		RZ_LOG_WARN("Unsupported relocation type for imports %d\n", rel->type);
		return UT64_MAX;
	case RZ_AARCH64_IRELATIVE:
		if (rel->addend > plt_addr) { // start
			return (plt_addr + pos * 16 + 32) + rel->addend;
		}
		// same as fallback to JUMP_SLOT
		return plt_addr + pos * 16 + 32;
	case RZ_AARCH64_JUMP_SLOT:
		return plt_addr + pos * 16 + 32;
	default:
		RZ_LOG_WARN("Unsupported relocation type for imports %d\n", rel->type);
		return UT64_MAX;
	}
	return UT64_MAX;
}

/**
 * \brief Determines and returns the import address for the given relocation.
 *
 * \param eo The Elf object.
 * \param rel The Elf relocation to get the address for.
 *
 * \return The import address or UT64_MAX in case of failure.
 */
static ut64 get_import_addr_aux(ELFOBJ *bin, RzBinElfReloc *reloc) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return get_import_addr_arm(bin, reloc);
	case EM_MIPS: // MIPS32 BIG ENDIAN relocs
		return get_import_addr_mips(bin, reloc);
	case EM_RISCV:
		return get_import_addr_riscv(bin, reloc);
	case EM_SPARC:
	case EM_SPARCV9:
	case EM_SPARC32PLUS:
		return get_import_addr_sparc(bin, reloc);
	case EM_PPC:
	case EM_PPC64:
		return get_import_addr_ppc(bin, reloc);
	case EM_386:
	case EM_X86_64:
		return get_import_addr_x86(bin, reloc);
	case EM_QDSP6:
		return get_import_addr_hexagon(bin, reloc);
	default:
		RZ_LOG_WARN("Unsupported relocs type %" PFMT64u " for arch %d\n",
			(ut64)reloc->type, bin->ehdr.e_machine);
		return UT64_MAX;
	}
}

static ut64 get_import_addr(ELFOBJ *bin, ut64 symbol) {
	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin) || !Elf_(rz_bin_elf_has_relocs)(bin)) {
		return UT64_MAX;
	}

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (reloc->sym != symbol) {
			continue;
		}

		ut64 tmp = get_import_addr_aux(bin, reloc);
		if (tmp != UT64_MAX) {
			return tmp;
		}
	}

	return UT64_MAX;
}

static ut64 get_import_offset(ELFOBJ *bin, RzBinElfSymbol *symbol) {
	return get_import_addr(bin, symbol->ordinal);
}

static void convert_elf_symbol_to_elf_import(ELFOBJ *bin, RzBinElfSymbol *symbol) {
	if (symbol->vaddr && symbol->vaddr != UT64_MAX) {
		return;
	}

	symbol->vaddr = get_import_offset(bin, symbol);
	if (symbol->vaddr == UT64_MAX) {
		return;
	}
	symbol->size = 16;
	symbol->paddr = Elf_(rz_bin_elf_v2p)(bin, symbol->vaddr);
}

static void convert_elf_symbols_to_elf_imports(ELFOBJ *bin, RzVector /*<RzBinElfSymbol>*/ *symbols) {
	RzBinElfSymbol *symbol;
	rz_vector_foreach (symbols, symbol) {
		convert_elf_symbol_to_elf_import(bin, symbol);
	}
}

static bool filter_import(ELFOBJ *bin, Elf_(Sym) * symbol, bool is_dynamic) {
	return symbol->st_shndx == SHT_NULL && (is_dynamic || Elf_(rz_bin_elf_is_relocatable)(bin));
}

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_import)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSymbol *import;
	rz_bin_elf_foreach_imports(bin, import) {
		if (import->ordinal == ordinal) {
			return import;
		}
	}

	return NULL;
}

RZ_OWN RzVector /*<RzBinElfSymbol>*/ *Elf_(rz_bin_elf_analyse_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzVector *result = Elf_(rz_bin_elf_compute_symbols)(bin, filter_import);
	if (!result) {
		return NULL;
	}

	convert_elf_symbols_to_elf_imports(bin, result);

	return result;
}

bool Elf_(rz_bin_elf_has_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->imports;
}
