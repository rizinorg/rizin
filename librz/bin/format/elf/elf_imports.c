// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define MIPS_PLT_OFFSET                      0x20
#define LOONGARCH_PLT_OFFSET                 0x20
#define LOONGARCH_PLT_ENTRY_SIZE             0x10
#define RISCV_PLT_OFFSET                     0x20
#define RISCV_PLT_ENTRY_SIZE                 0x10
#define RISCV_PLT_OFFSET                     0x20
#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR   -0x6
#define X86_PLT_ENTRY_SIZE                   0x10

#define UNHANDL_IMPORT(NAME, NUM) \
	RZ_LOG_WARN(NAME ": Unhandled ELF relocation for import %d\n", NUM); \
	return UT64_MAX

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
	if (!bin->elfctx) {
		return UT64_MAX;
	}

	if (bin->elfctx->mips_got_addr == ELF_ADDR_MAX ||
		bin->elfctx->jmprel == ELF_ADDR_MAX ||
		bin->elfctx->pltrelsz == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->mips_got_addr, 0x2);

	ut8 buf[1024];
	ut64 plt_addr = bin->elfctx->jmprel + bin->elfctx->pltrelsz;
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

#define PARISC_ADDIL      0x0a // addil L%x,b,r1
#define PARISC_LDO_R1_R22 0x34360000 // ldo x(r1),r22
#define PARISC_LDW_R1_R21 0x48350000 // ldw x(r1),r21
#define PARISC_LDW_R1_R19 0x48330000 // ldw x(r1),r19
#define PARISC_LDW_R22    0x0ec01095 // ldw 0(r22),r21
#define PARISC_LDW_R22_GP 0x0ec81093 // ldw 4(r22),r19
#define PARISC_BV_R21     0xeaa0c000 // bv r0(r21)
#define PARISC_IM14_MASK  0xffffc000

/// Value of the 21-bit immediate of ADDIL, already shifted into place
static ut32 parisc_im21(ut32 w) {
	ut32 v = w & 1;
	v = (v << 11) | ((w >> 1) & 0x7ff);
	v = (v << 2) | ((w >> 14) & 3);
	v = (v << 5) | ((w >> 16) & 0x1f);
	v = (v << 2) | ((w >> 12) & 3);
	return v << 11;
}

/// Value of the 14-bit displacement, its sign being the lowest bit
static st32 parisc_im14(ut32 w) {
	st32 v = (w & 0x3fff) >> 1;
	return w & 1 ? v - 0x2000 : v;
}

/**
 * \brief Get the PLT slot loaded by a PA-RISC import stub starting at \p w.
 *
 * Stubs load the function address and gp from the slot after addil of its
 * offset to gp, held by dp or r19, through ldo into r22 or directly.
 *
 * \return The slot offset from gp, or UT64_MAX if \p w is no stub.
 */
static ut64 parisc_stub_slot(const ut32 *w, size_t n) {
	if (n < 4 || w[0] >> 26 != PARISC_ADDIL) {
		return UT64_MAX;
	}
	ut32 base = (w[0] >> 21) & 0x1f;
	if (base != 27 && base != 19) {
		return UT64_MAX;
	}
	ut32 off = parisc_im21(w[0]) + (ut32)parisc_im14(w[1]);
	if ((w[1] & PARISC_IM14_MASK) == PARISC_LDO_R1_R22) {
		return n >= 5 && w[2] == PARISC_LDW_R22 && w[3] == PARISC_BV_R21 && w[4] == PARISC_LDW_R22_GP
			? off
			: UT64_MAX;
	}
	if ((w[1] & PARISC_IM14_MASK) == PARISC_LDW_R1_R21 && w[2] == PARISC_BV_R21 &&
		(w[3] & PARISC_IM14_MASK) == PARISC_LDW_R1_R19 && parisc_im14(w[3]) == parisc_im14(w[1]) + 4) {
		return off;
	}
	return UT64_MAX;
}

static bool parisc_add_segment_stubs(ELFOBJ *bin, HtUU *stubs, ut64 offset, ut64 vaddr, ut64 size) {
	size_t n = size / 4;
	ut32 *words = n ? RZ_NEWS(ut32, n) : NULL;
	if (!words) {
		return !n;
	}
	for (size_t i = 0; i < n; i++) {
		if (!rz_buf_read_ble32_at(bin->b, offset + i * 4, &words[i], bin->big_endian)) {
			n = i;
			break;
		}
	}
	for (size_t i = 0; i < n; i++) {
		ut64 slot = parisc_stub_slot(words + i, n - i);
		if (slot != UT64_MAX) {
			// stubs may repeat in distant parts of the text, keep the first
			ht_uu_insert(stubs, (ut32)(bin->elfctx->got_addr + slot), vaddr + i * 4);
		}
	}
	free(words);
	return true;
}

/// Map the PLT slot of every import to the stub its callers branch to.
static HtUU *parisc_import_stubs_new(ELFOBJ *bin) {
	HtUU *stubs = ht_uu_new();
	if (!stubs) {
		return NULL;
	}
	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		if (!segment->is_valid || segment->data.p_type != PT_LOAD || !(segment->data.p_flags & PF_X)) {
			continue;
		}
		ut64 size = RZ_MIN(segment->data.p_filesz, bin->size);
		if (!parisc_add_segment_stubs(bin, stubs, segment->data.p_offset, segment->data.p_vaddr, size)) {
			ht_uu_free(stubs);
			return NULL;
		}
	}
	return stubs;
}

static ut64 get_import_addr_parisc(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (rel->type != R_PARISC_IPLT || !bin->elfctx || bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}
	if (!bin->elfctx->parisc_import_stubs) {
		bin->elfctx->parisc_import_stubs = parisc_import_stubs_new(bin);
		if (!bin->elfctx->parisc_import_stubs) {
			return UT64_MAX;
		}
	}
	bool found = false;
	ut64 stub = ht_uu_find(bin->elfctx->parisc_import_stubs, rel->vaddr, &found);
	return found ? stub : UT64_MAX;
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
static ut64 get_import_addr_hexagon(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	const ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x3);

	switch (rel->type) {
	default: UNHANDL_IMPORT("Hexagon", rel->type);
	case R_HEX_JMP_SLOT:
		return plt_addr + pos * 16 + 32;
	}
}

static ut64 get_import_addr_loongarch(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x2);
	return plt_addr + LOONGARCH_PLT_OFFSET + pos * LOONGARCH_PLT_ENTRY_SIZE;
}

static ut64 get_import_addr_riscv(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x2);
	return plt_addr + RISCV_PLT_OFFSET + pos * RISCV_PLT_ENTRY_SIZE;
}

static ut64 get_import_addr_sparc(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (rel->type != R_SPARC_JMP_SLOT) {
		UNHANDL_IMPORT("SPARC", rel->type);
	}
	ut64 tmp = get_got_entry(bin, rel);

	return (tmp == UT64_MAX) ? UT64_MAX : tmp + SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_ppc(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 p_plt_addr = Elf_(rz_bin_elf_v2p)(bin, bin->elfctx->got_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut32 tmp;
	if (!rz_buf_read_ble32_at(bin->b, p_plt_addr, &tmp, bin->big_endian)) {
		return UT64_MAX;
	}

	ut64 nrel = Elf_(rz_bin_elf_get_num_relocs_dynamic_plt)(bin);
	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x0);

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
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 got_offset = Elf_(rz_bin_elf_v2p)(bin, bin->elfctx->got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	// XXX HACK ALERT!!!! full relro?? try to fix it
	// will there always be .plt.got, what would happen if is .got.plt?
	RzBinElfSection *s = bin->elfctx->plt_got;
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

	RzBinElfSection *pltsec_section = bin->elfctx->plt_sec;
	if (pltsec_section) {
		if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
			return UT64_MAX;
		}

		ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x3);
		return pltsec_section->rva + pos * X86_PLT_ENTRY_SIZE;
	}

	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_arm(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x3);

	switch (rel->type) {
	case R_ARM_JUMP_SLOT:
		plt_addr += pos * 12 + 20;
		if (Elf_(rz_bin_elf_is_thumb_addr)(plt_addr)) {
			plt_addr--;
		}
		return plt_addr;
	case R_ARM_GLOB_DAT:
		/* fall-thru */
	case R_ARM_ABS32:
		/* fall-thru */
	case R_ARM_REL32:
		/* fall-thru */
	case R_ARM_COPY:
		return rel->vaddr;
	default: UNHANDL_IMPORT("ARM", rel->type);
	}
	return UT64_MAX;
}

static ut64 get_import_addr_aarch64(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x3);

	switch (rel->type) {
	case R_ARM_JUMP_SLOT: // AArch64 supports ARM32 relocs.
		plt_addr += pos * 12 + 20;
		if (Elf_(rz_bin_elf_is_thumb_addr)(plt_addr)) {
			plt_addr--;
		}
		return plt_addr;
	case R_AARCH64_IRELATIVE:
		if (rel->addend > plt_addr) { // start
			return (plt_addr + pos * 16 + 32) + rel->addend;
		}
		// same as fallback to JUMP_SLOT
		return plt_addr + pos * 16 + 32;
	case R_AARCH64_JUMP_SLOT:
		return plt_addr + pos * 16 + 32;
	default: UNHANDL_IMPORT("AArch64", rel->type);
	}
	return UT64_MAX;
}

static ut64 get_import_addr_alpha(ELFOBJ *bin, RzBinElfReloc *rel) {
	if (rel->type != R_ALPHA_JMP_SLOT) {
		UNHANDL_IMPORT("Alpha", rel->type);
	}
	if (bin->elfctx && bin->elfctx->got_addr == ELF_ADDR_MAX) {
		return UT64_MAX;
	}
	ut64 plt_addr = get_got_entry(bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	const ut64 pos = COMPUTE_PLTGOT_POSITION(rel, bin->elfctx->got_addr, 0x3);
	return plt_addr + pos * 16 + 32;
}

/**
 * \brief Determines and returns the import address for the given relocation.
 *
 * \param bin The Elf object.
 * \param reloc The Elf relocation to get the address for.
 *
 * \return The import address or UT64_MAX in case of failure.
 */
static ut64 get_import_addr_aux(ELFOBJ *bin, RzBinElfReloc *reloc) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
		return get_import_addr_arm(bin, reloc);
	case EM_AARCH64:
		return get_import_addr_aarch64(bin, reloc);
	case EM_ALPHA:
		return get_import_addr_alpha(bin, reloc);
	case EM_MIPS: // MIPS32 BIG ENDIAN relocs
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
	case EM_IMG1:
		return get_import_addr_mips(bin, reloc);
	case EM_PARISC:
		return get_import_addr_parisc(bin, reloc);
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
	case EM_LOONGARCH:
		return get_import_addr_loongarch(bin, reloc);
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
