// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include "elf_imports.h"

#define MIPS_PLT_OFFSET                      0x20
#define RISCV_PLT_ENTRY_SIZE                 0x10
#define RISCV_PLT_OFFSET                     0x20
#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR   -0x6
#define X86_PLT_ENTRY_SIZE                   0x10

#define COMPUTE_PLTGOT_POSITION(rel, pltgot_addr, n_initial_unused_entries) \
	((rel->vaddr - pltgot_addr - n_initial_unused_entries * sizeof(Elf_(Addr))) / sizeof(Elf_(Addr)))

static bool is_thumb_symbol(ut64 plt_addr) {
	return plt_addr & 1;
}

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

	ut64 p_plt_addr = Elf_(rz_bin_elf_v2p_new)(bin, plt_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 base = rz_buf_read_ble32_at(bin->b, p_plt_addr, bin->endian);
	if (base == UT32_MAX) {
		return UT64_MAX;
	}

	ut64 nrel = Elf_(rz_bin_elf_get_num_relocs_dynamic_plt)(bin);
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
	ut64 got_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
		return UT64_MAX;
	}

	ut64 got_offset = Elf_(rz_bin_elf_v2p_new)(bin, got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	//XXX HACK ALERT!!!! full relro?? try to fix it
	//will there always be .plt.got, what would happen if is .got.plt?
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

		ut64 tmp = Elf_(rz_bin_elf_v2p_new)(bin, plt_sym_addr);
		if (tmp == UT64_MAX) {
			tmp = plt_sym_addr;
		}

		//relative address
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
		if (is_thumb_symbol(plt_addr)) {
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
	default:
		eprintf("Unsupported relocs type %" PFMT64u " for arch %d\n",
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

static ut64 get_import_offset(ELFOBJ *bin, RzBinElfSymbol *symbol, ut64 pos) {
	ut64 tmp = get_import_addr(bin, pos);
	return tmp == -1 ? 0 : tmp;
}

static bool copy_elf_symbol(ELFOBJ *bin, RzBinElfSymbol *dst, RzBinElfSymbol *src) {
	memcpy(dst, src, sizeof(RzBinElfSymbol));
	dst->name = rz_str_new(src->name);
	if (!dst->name) {
		return false;
	}

	return true;
}

static bool convert_elf_symbol_to_elf_import(ELFOBJ *bin, RzBinElfSymbol *import, RzBinElfSymbol *symbol) {
	if (!copy_elf_symbol(bin, import, symbol)) {
		return false;
	}

	import->size = 16;

	if (import->offset) {
		return true;
	}

	import->is_vaddr = false;
	import->offset = get_import_offset(bin, symbol, symbol->ordinal);

	ut64 tmp = Elf_(rz_bin_elf_v2p_new)(bin, import->offset);
	if (tmp == UT64_MAX) {
		import->is_vaddr = true;
	} else {
		import->offset = tmp;
	}

	return true;
}

static void import_free(void *e, RZ_UNUSED void *user) {
	RzBinImport *ptr = e;
	rz_bin_import_free(ptr);
}

static void elf_import_free(void *e, RZ_UNUSED void *user) {
	RzBinElfSymbol *ptr = e;
	free(ptr->name);
}

static RzVector *get_elf_imports(ELFOBJ *bin) {
	RzVector *result = rz_vector_new(sizeof(RzBinElfSymbol), elf_import_free, NULL);
	if (!result) {
		return NULL;
	}

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_elf_import_symbols(bin, symbol) {
		RzBinElfSymbol *import = rz_vector_push(result, NULL);
		if (!import) {
			rz_vector_free(result);
			return NULL;
		}

		if (!convert_elf_symbol_to_elf_import(bin, import, symbol)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	return result;
}

static void convert_import(RzBinImport *import, RzBinElfSymbol *symbol) {
	import->name = strdup(symbol->name);
	import->bind = symbol->bind;
	import->type = symbol->type;
	import->ordinal = symbol->ordinal;
}

static RzVector *get_imports(RzVector *elf_imports) {
	RzVector *result = rz_vector_new(sizeof(RzBinImport), import_free, NULL);
	if (!result) {
		return NULL;
	}

	RzBinElfSymbol *tmp;
	rz_vector_foreach(elf_imports, tmp) {
		RzBinImport import = { 0 };

		convert_import(&import, tmp);

		if (!rz_vector_push(result, &import)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	return result;
}

RZ_BORROW RzBinImport *Elf_(rz_bin_elf_get_import)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal) {
	rz_return_val_if_fail(bin && bin->imports, NULL);

	RzBinImport *import;
	rz_bin_elf_foreach_imports(bin, import) {
		if (import->ordinal == ordinal) {
			return import;
		}
	}

	return NULL;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_elf_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->imports, NULL);
	return bin->imports->elf_imports;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->imports, NULL);
	return bin->imports->imports;
}

RZ_OWN RzBinElfImports *Elf_(rz_bin_elf_imports_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!Elf_(rz_bin_elf_has_symbols)(bin)) {
		return NULL;
	}

	RzBinElfImports *result = RZ_NEW(RzBinElfImports);
	if (!result) {
		return NULL;
	}

	result->elf_imports = get_elf_imports(bin);
	if (!result->elf_imports || !rz_vector_len(result->elf_imports)) {
		free(result);
		return NULL;
	}

	result->imports = get_imports(result->elf_imports);
	if (!result->imports || !rz_vector_len(result->imports)) {
		free(result->elf_imports);
		free(result);
		return NULL;
	}

	return result;
}

/**
 * \brief Convert a RzBinElfSymbol to RzBinImport
 * \param bin symbol
 * \return a ptr to a new allocated RzBinImport
 *
 * ...
 */
RZ_OWN RzBinImport *Elf_(rz_bin_elf_convert_import)(RZ_NONNULL RzBinElfSymbol *symbol) {
	rz_return_val_if_fail(symbol, NULL);

	RzBinImport *ptr = RZ_NEW0(RzBinImport);
	if (!ptr) {
		return NULL;
	}

	convert_import(ptr, symbol);

	return ptr;
}

bool Elf_(rz_bin_elf_has_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->imports;
}

void Elf_(rz_bin_elf_imports_free)(RzBinElfImports *ptr) {
	if (!ptr) {
		return;
	}

	rz_vector_free(ptr->elf_imports);
	rz_vector_free(ptr->imports);
}
