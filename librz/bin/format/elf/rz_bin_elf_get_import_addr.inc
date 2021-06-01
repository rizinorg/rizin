// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut64 get_got_entry(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (rel->paddr == UT64_MAX) {
		return UT64_MAX;
	}
	ut64 paddr = rel->paddr;
	ut64 addr = RZ_BIN_ELF_BREADWORD(bin->b, paddr);
	return (!addr || addr == RZ_BIN_ELF_WORD_MAX) ? UT64_MAX : addr;
}

static bool is_thumb_symbol(ut64 plt_addr) {
	return plt_addr & 1;
}

static ut64 get_import_addr_arm(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr == RZ_BIN_ELF_ADDR_MAX) {
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
		if (is_thumb_symbol(plt_addr)) {
			plt_addr--;
		}
		return plt_addr;
	case RZ_AARCH64_RELATIVE:
		eprintf("Unsupported relocation type for imports %d\n", rel->type);
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
		bprintf("Unsupported relocation type for imports %d\n", rel->type);
		return UT64_MAX;
	}
	return UT64_MAX;
}

static ut64 get_import_addr_mips(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 jmprel_addr = bin->dyn_info.dt_jmprel;
	ut64 got_addr = bin->dyn_info.dt_mips_pltgot;

	if (jmprel_addr == RZ_BIN_ELF_ADDR_MAX || got_addr == RZ_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x2);

	ut8 buf[1024];
	ut64 plt_addr = jmprel_addr + bin->dyn_info.dt_pltrelsz;
	ut64 p_plt_addr = Elf_(rz_bin_elf_v2p_new)(bin, plt_addr);
	int res = rz_buf_read_at(bin->b, p_plt_addr, buf, sizeof(buf));
	if (res != sizeof(buf)) {
		return UT64_MAX;
	}

	const ut8 *base = rz_mem_mem_aligned(buf, sizeof(buf), (const ut8 *)"\x3c\x0f\x00", 3, 4);
	plt_addr += base ? (int)(size_t)(base - buf) : MIPS_PLT_OFFSET + 8; // HARDCODED HACK
	plt_addr += pos * 16;

	return plt_addr;
}

static size_t get_size_rel_mode(Elf_(Xword) rel_mode) {
	return rel_mode == DT_RELA ? sizeof(Elf_(Rela)) : sizeof(Elf_(Rel));
}

static ut64 get_num_relocs_dynamic_plt(ELFOBJ *bin) {
	if (bin->dyn_info.dt_pltrelsz) {
		const ut64 size = bin->dyn_info.dt_pltrelsz;
		const ut64 relsize = get_size_rel_mode(bin->dyn_info.dt_pltrel);
		return size / relsize;
	}
	return 0;
}

static ut64 get_import_addr_riscv(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr == RZ_BIN_ELF_ADDR_MAX) {
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
		bprintf("Unknown sparc reloc type %d\n", rel->type);
		return UT64_MAX;
	}
	ut64 tmp = get_got_entry(bin, rel);

	return (tmp == UT64_MAX) ? UT64_MAX : tmp + SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_ppc(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 plt_addr = bin->dyn_info.dt_pltgot;
	if (plt_addr == RZ_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}
	ut64 p_plt_addr = Elf_(rz_bin_elf_v2p_new)(bin, plt_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 base = rz_buf_read_ble32_at(bin->b, p_plt_addr, bin->endian);
	if (base == UT32_MAX) {
		return UT64_MAX;
	}

	ut64 nrel = get_num_relocs_dynamic_plt(bin);
	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, plt_addr, 0x0);

	if (bin->endian) {
		base -= (nrel * 16);
		base += (pos * 16);
		return base;
	}

	base -= (nrel * 12) + 20;
	base += (pos * 8);
	return base;
}

static ut64 get_import_addr_x86_manual(ELFOBJ *bin, RzBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr == RZ_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 got_offset = Elf_(rz_bin_elf_v2p_new)(bin, got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	//XXX HACK ALERT!!!! full relro?? try to fix it
	//will there always be .plt.got, what would happen if is .got.plt?
	RzBinElfSection *s = Elf_(rz_bin_elf_get_section)(bin, ".plt.got");
	if (Elf_(rz_bin_elf_has_relro)(bin) < RZ_BIN_ELF_PART_RELRO || !s) {
		return UT64_MAX;
	}

	ut8 buf[sizeof(Elf_(Addr))] = { 0 };

	ut64 plt_addr = s->offset;
	ut64 plt_sym_addr;

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
		int res = rz_buf_read_at(bin->b, plt_addr + 2, buf, sizeof(ut32));
		if (res < 0) {
			return UT64_MAX;
		}

		size_t i = 0;
		plt_sym_addr = RZ_BIN_ELF_READWORD(buf, i);

		//relative address
		if ((plt_addr + 6 + Elf_(rz_bin_elf_v2p)(bin, plt_sym_addr)) == rel->vaddr) {
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

	RzBinElfSection *pltsec_section = Elf_(rz_bin_elf_get_section)(bin, ".plt.sec");

	if (pltsec_section) {
		ut64 got_addr = bin->dyn_info.dt_pltgot;
		ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);
		return pltsec_section->rva + pos * X86_PLT_ENTRY_SIZE;
	}

	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

RZ_IPI ut64 Elf_(rz_bin_elf_get_import_addr)(RZ_NONNULL ELFOBJ *bin, int symbol) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if ((!bin->shdr || !bin->strtab) && !bin->phdr) {
		return UT64_MAX;
	}

	if (!bin->rel_cache) {
		return UT64_MAX;
	}

	// lookup the right rel/rela entry
	RzBinElfReloc *rel = ht_up_find(bin->rel_cache, symbol, NULL);

	if (!rel) {
		return UT64_MAX;
	}

	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return get_import_addr_arm(bin, rel);
	case EM_MIPS: // MIPS32 BIG ENDIAN relocs
		return get_import_addr_mips(bin, rel);
	case EM_RISCV:
		return get_import_addr_riscv(bin, rel);
	case EM_SPARC:
	case EM_SPARCV9:
	case EM_SPARC32PLUS:
		return get_import_addr_sparc(bin, rel);
	case EM_PPC:
	case EM_PPC64:
		return get_import_addr_ppc(bin, rel);
	case EM_386:
	case EM_X86_64:
		return get_import_addr_x86(bin, rel);
	default:
		eprintf("Unsupported relocs type %" PFMT64u " for arch %d\n",
			(ut64)rel->type, bin->ehdr.e_machine);
		return UT64_MAX;
	}
}
