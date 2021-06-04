// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define GROWTH_FACTOR                        2
#define MIPS_PLT_OFFSET                      0x20
#define RISCV_PLT_ENTRY_SIZE                 0x10
#define RISCV_PLT_OFFSET                     0x20
#define RZ_BIN_ELF_ALL_SYMBOLS               (RZ_BIN_ELF_SYMTAB_SYMBOLS | RZ_BIN_ELF_DYNSYM_SYMBOLS)
#define RZ_BIN_ELF_DYNSYM_SYMBOLS            1 << 1
#define RZ_BIN_ELF_IMPORT_SYMBOLS            (1 << 2 | (bin->ehdr.e_type == ET_REL ? RZ_BIN_ELF_SYMTAB_SYMBOLS : RZ_BIN_ELF_DYNSYM_SYMBOLS))
#define RZ_BIN_ELF_SYMTAB_SYMBOLS            1 << 0
#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR   -0x6
#define X86_PLT_ENTRY_SIZE                   0x10

#define COMPUTE_PLTGOT_POSITION(rel, pltgot_addr, n_initial_unused_entries) \
	((rel->vaddr - pltgot_addr - n_initial_unused_entries * RZ_BIN_ELF_WORDSIZE) / RZ_BIN_ELF_WORDSIZE)

#define HASH_NCHAIN_OFFSET(x) ((x) + 4)

#if RZ_BIN_ELF64
#define RZ_BIN_ELF_WORD_MAX UT64_MAX
#else
#define RZ_BIN_ELF_WORD_MAX UT32_MAX
#endif

struct symbol_bind_translation {
	unsigned char bind;
	const char *name;
};

struct symbol_type_translation {
	unsigned char type;
	const char *name;
};

static struct symbol_bind_translation symbol_bind_translation_table[] = {
	{ STB_LOCAL, RZ_BIN_BIND_LOCAL_STR },
	{ STB_GLOBAL, RZ_BIN_BIND_GLOBAL_STR },
	{ STB_WEAK, RZ_BIN_BIND_WEAK_STR },
	{ STB_NUM, RZ_BIN_BIND_NUM_STR },
	{ STB_LOOS, RZ_BIN_BIND_LOOS_STR },
	{ STB_HIOS, RZ_BIN_BIND_HIOS_STR },
	{ STB_LOPROC, RZ_BIN_BIND_LOPROC_STR },
	{ STB_HIPROC, RZ_BIN_BIND_HIPROC_STR }
};

static const struct symbol_type_translation symbol_type_translation_table[] = {
	{ STT_NOTYPE, RZ_BIN_TYPE_NOTYPE_STR },
	{ STT_OBJECT, RZ_BIN_TYPE_OBJECT_STR },
	{ STT_FUNC, RZ_BIN_TYPE_FUNC_STR },
	{ STT_SECTION, RZ_BIN_TYPE_SECTION_STR },
	{ STT_FILE, RZ_BIN_TYPE_FILE_STR },
	{ STT_COMMON, RZ_BIN_TYPE_COMMON_STR },
	{ STT_TLS, RZ_BIN_TYPE_TLS_STR },
	{ STT_NUM, RZ_BIN_TYPE_NUM_STR },
	{ STT_LOOS, RZ_BIN_TYPE_LOOS_STR },
	{ STT_HIOS, RZ_BIN_TYPE_HIOS_STR },
	{ STT_LOPROC, RZ_BIN_TYPE_LOPROC_STR },
	{ STT_HIPROC, RZ_BIN_TYPE_HIPROC_STR }
};

static void set_addr_parameter(ELFOBJ *bin, RzBinElfSymbol *elf_symbol, RzBinSymbol *symbol) {
	if (elf_symbol->is_vaddr) {
		symbol->paddr = UT64_MAX;
		symbol->vaddr = elf_symbol->offset;
	} else {
		symbol->paddr = elf_symbol->offset;
		symbol->vaddr = Elf_(rz_bin_elf_p2v_new)(bin, symbol->paddr);
	}
}

static char *get_symbol_name(RzBinElfSymbol *elf_symbol, const char *namefmt) {
	return elf_symbol->name[0] ? rz_str_newf(namefmt, &elf_symbol->name[0]) : strdup("");
}

static void set_common_parameter(RzBinElfSymbol *elf_symbol, RzBinSymbol *symbol, const char *namefmt) {
	char *symbol_name = get_symbol_name(elf_symbol, namefmt);

	symbol->name = symbol_name;
	symbol->forwarder = "NONE";
	symbol->bind = elf_symbol->bind;
	symbol->type = elf_symbol->type;
	symbol->is_imported = elf_symbol->is_imported;
	symbol->size = elf_symbol->size;
	symbol->ordinal = elf_symbol->ordinal;
}

static bool is_arm_symbol(ELFOBJ *bin, RzBinElfSymbol *elf_symbol) {
	return bin->ehdr.e_machine == EM_ARM && *elf_symbol->name;
}

static void fix_thumb_symbol(RzBinSymbol *symbol) {
	symbol->bits = 16;

	if (symbol->vaddr & 1) {
		symbol->vaddr--;
	}

	if (symbol->paddr & 1) {
		symbol->paddr--;
	}
}

static bool start_a_sequence_of_instruction(const char *name) {
	return strlen(name) > 3 && rz_str_startswith(name, "$a.");
}

static bool start_a_sequence_of_thumb_instruction(const char *name) {
	return strlen(name) > 3 && rz_str_startswith(name, "$t.");
}

static bool start_a_sequence_of_data(const char *name) {
	return strlen(name) > 3 && rz_str_startswith(name, "$d.");
}

static void set_arm_basic_symbol_bits(ELFOBJ *bin, RzBinSymbol *symbol) {
	int bin_bits = Elf_(rz_bin_elf_get_bits)(bin);
	symbol->bits = bin_bits;

	if (bin_bits != 64) {
		symbol->bits = 32;

		if (symbol->paddr != UT64_MAX) {
			if (symbol->vaddr & 1) {
				symbol->vaddr--;
				symbol->bits = 16;
			}
			if (symbol->paddr & 1) {
				symbol->paddr--;
				symbol->bits = 16;
			}
		}
	}
}

static void set_arm_symbol_bits(ELFOBJ *bin, RzBinSymbol *symbol) {
	const char *name = symbol->name;

	if (start_a_sequence_of_instruction(name)) {
		symbol->bits = 32;
	} else if (start_a_sequence_of_thumb_instruction(name)) {
		fix_thumb_symbol(symbol);
	} else if (!start_a_sequence_of_data(name)) {
		set_arm_basic_symbol_bits(bin, symbol);
	}
}

static size_t get_number_of_symbols_from_hash(ELFOBJ *bin) {
	if (bin->dyn_info.dt_hash == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 hash_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_hash);
	if (hash_offset == UT64_MAX) {
		return 0;
	}

	ut64 nchain_offset = HASH_NCHAIN_OFFSET(hash_offset);
	ut64 result = BREAD32(bin->b, nchain_offset);

	return result == UT32_MAX ? 0 : result;
}

static ut64 get_index_from_buckets(ELFOBJ *bin, ut64 *bucket_offset, ut64 number_of_bucket) {
	ut64 index = 0;

	for (size_t i = 0; i < number_of_bucket; i++) {
		ut64 tmp = BREAD32(bin->b, *bucket_offset);
		index = RZ_MAX(index, tmp);
	}

	return index;
}

static ut64 get_index_from_chain(ELFOBJ *bin, ut64 bucket_offset, ut64 symbol_base, ut64 index) {
	ut64 chain_index = index - symbol_base;
	ut64 chain_offset = bucket_offset + chain_index * 4;

	while (1) {
		index++;
		size_t tmp = BREAD32(bin->b, chain_offset);

		if (tmp & 1) {
			break;
		}
	}

	return index;
}

static size_t get_number_of_symbols_from_gnu_hash(ELFOBJ *bin) {
	if (bin->dyn_info.dt_gnu_hash == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 hash_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_gnu_hash);
	if (hash_offset == UT64_MAX) {
		return 0;
	}

	size_t pos = hash_offset;

	ut64 number_of_bucket = BREAD32(bin->b, pos);
	ut64 symbol_base = BREAD32(bin->b, pos);
	ut64 bitmask_nwords = BREAD32(bin->b, pos);
	ut64 bucket_offset = hash_offset + 16 + bitmask_nwords * RZ_BIN_ELF_WORDSIZE;

	ut64 index = get_index_from_buckets(bin, &bucket_offset, number_of_bucket);

	if (!index) {
		return 0;
	}

	return get_index_from_chain(bin, bucket_offset, symbol_base, index);
}

static size_t get_number_of_symbols_from_heuristic(ELFOBJ *bin) {
	if (bin->dyn_info.dt_symtab == RZ_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_strtab == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 symtab_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_symtab);
	ut64 strtab_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_strtab);
	if (symtab_offset == UT64_MAX || strtab_offset == UT64_MAX) {
		return 0;
	}

	if (symtab_offset > strtab_offset) {
		return 0;
	}

	ut64 symtab_size = strtab_offset - symtab_offset;
	return symtab_size / sizeof(Elf_(Sym));
}

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

	RzBinElfSection *pltsec_section = Elf_(rz_bin_elf_get_section)(bin, ".plt.sec");

	if (pltsec_section) {
		ut64 got_addr = bin->dyn_info.dt_pltgot;
		ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);
		return pltsec_section->rva + pos * X86_PLT_ENTRY_SIZE;
	}

	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static bool is_special_arm_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	if (name[0] != '$') {
		return false;
	}

	if (name[1] == 'a' || name[1] == 't' || name[1] == 'd' || name[1] == 'x') {
		return (name[2] == '\0' || name[2] == '.') &&
			ELF_ST_TYPE(sym->st_info) == STT_NOTYPE &&
			ELF_ST_BIND(sym->st_info) == STB_LOCAL &&
			ELF_ST_VISIBILITY(sym->st_info) == STV_DEFAULT;
	}

	return false;
}

static bool is_special_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return is_special_arm_symbol(bin, sym, name);
	default:
		return false;
	}
}

static const char *symbol_type_to_str(ELFOBJ *bin, RzBinElfSymbol *ret, Elf_(Sym) * sym) {
	if (bin && ret && is_special_symbol(bin, sym, ret->name)) {
		return RZ_BIN_TYPE_SPECIAL_SYM_STR;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(symbol_type_translation_table); i++) {
		if (ELF_ST_TYPE(sym->st_info) == symbol_type_translation_table[i].type) {
			return symbol_type_translation_table[i].name;
		}
	}

	return RZ_BIN_TYPE_UNKNOWN_STR;
}

static const char *symbol_bind_to_str(Elf_(Sym) * sym) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(symbol_bind_translation_table); i++) {
		if (ELF_ST_BIND(sym->st_info) == symbol_bind_translation_table[i].bind) {
			return symbol_bind_translation_table[i].name;
		}
	}

	return RZ_BIN_BIND_UNKNOWN_STR;
}

static ut64 get_import_addr(ELFOBJ *bin, int symbol) {
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

static void Elf_(rz_bin_elf_set_import_by_ord)(ELFOBJ *bin, RzBinElfSymbol *symbol) {
	if (!bin->imports_by_ord) {
		return;
	}

	RzBinImport *import = Elf_(rz_bin_elf_convert_import)(bin, symbol);
	if (!import) {
		return;
	}

	if (import->ordinal >= bin->imports_by_ord_size) {
		rz_bin_import_free(import);
		return;
	}

	rz_bin_import_free(bin->imports_by_ord[import->ordinal]);
	bin->imports_by_ord[import->ordinal] = import;
}

static Elf_(Sym) get_symbol_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Sym) symbol;

#if RZ_BIN_ELF64
	symbol.st_name = BREAD32(bin->b, offset);
	symbol.st_info = BREAD8(bin->b, offset);
	symbol.st_other = BREAD8(bin->b, offset);
	symbol.st_shndx = BREAD16(bin->b, offset);
	symbol.st_value = BREAD64(bin->b, offset);
	symbol.st_size = BREAD64(bin->b, offset);
#else
	symbol.st_name = BREAD32(bin->b, offset);
	symbol.st_value = BREAD32(bin->b, offset);
	symbol.st_size = BREAD32(bin->b, offset);
	symbol.st_info = BREAD8(bin->b, offset);
	symbol.st_other = BREAD8(bin->b, offset);
	symbol.st_shndx = BREAD16(bin->b, offset);
#endif

	return symbol;
}

static ut64 get_value_symbol(ELFOBJ *bin, Elf_(Sym) * symbol, size_t pos) {
	if (symbol->st_value) {
		return symbol->st_value;
	}

	ut64 tmp = get_import_addr(bin, pos);
	return tmp == -1 ? 0 : tmp;
}

static bool is_section_local_symbol(ELFOBJ *bin, Elf_(Sym) * symbol) {
	if (symbol->st_name != 0) {
		return false;
	}
	if (ELF_ST_TYPE(symbol->st_info) != STT_SECTION) {
		return false;
	}
	if (ELF_ST_BIND(symbol->st_info) != STB_LOCAL) {
		return false;
	}
	if (!Elf_(rz_bin_elf_is_sh_index_valid)(bin, symbol->st_shndx)) {
		return false;
	}

	return true;
}

static void set_elf_symbol_name(ELFOBJ *bin, RzBinElfSymbol *elf_symbol, Elf_(Sym) * symbol) {
	if (is_section_local_symbol(bin, symbol) && bin->shstrtab && symbol->st_name < bin->shstrtab_size) {
		const char *name = bin->shstrtab + bin->shdr[symbol->st_shndx].sh_name;
		rz_str_ncpy(elf_symbol->name, name, ELF_STRING_LENGTH);
	} else if (bin->strtab && symbol->st_name < bin->strtab_size) {
		rz_str_ncpy(elf_symbol->name, bin->strtab + symbol->st_name, ELF_STRING_LENGTH);
	} else {
		elf_symbol->name[0] = '\0';
	}
}

static void convert_elf_symbol_entry(ELFOBJ *bin, RzBinElfSymbol *elf_symbol, Elf_(Sym) * symbol, int type, size_t ordinal) {
	elf_symbol->offset = symbol->st_value;
	elf_symbol->size = symbol->st_size;
	elf_symbol->ordinal = ordinal;
	elf_symbol->bind = symbol_bind_to_str(symbol);
	elf_symbol->type = symbol_type_to_str(bin, elf_symbol, symbol);
	set_elf_symbol_name(bin, elf_symbol, symbol);
	elf_symbol->libname[0] = '\0';
	elf_symbol->last = 0;
	elf_symbol->in_shdr = false;
	elf_symbol->is_sht_null = false;
	elf_symbol->is_vaddr = false;
	elf_symbol->is_imported = false;

	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
		elf_symbol->offset = get_value_symbol(bin, symbol, ordinal);
		elf_symbol->size = 16;
	} else {
		elf_symbol->is_sht_null = symbol->st_shndx == SHT_NULL;
	}

	if (Elf_(rz_bin_elf_is_relocatable)(bin) && symbol->st_shndx < bin->ehdr.e_shnum) {
		elf_symbol->offset = symbol->st_value + bin->shdr[symbol->st_shndx].sh_offset;
	} else {
		ut64 tmp = Elf_(rz_bin_elf_v2p_new)(bin, elf_symbol->offset);
		if (tmp == UT64_MAX) {
			elf_symbol->is_vaddr = true;
		} else {
			elf_symbol->offset = tmp;
		}
	}
}

static RzVector *compute_symbols_from_segment(ELFOBJ *bin, int type, ut64 offset, size_t num, ut64 entry_size) {
	RzVector *result = rz_vector_new(sizeof(RzBinElfSymbol), NULL, NULL);

	offset += entry_size;

	for (size_t i = 1; i < num; i++) {
		Elf_(Sym) symbol = get_symbol_entry(bin, offset);
		if ((type != RZ_BIN_ELF_IMPORT_SYMBOLS || symbol.st_shndx != SHT_NULL) && type != RZ_BIN_ELF_ALL_SYMBOLS) {
			offset += entry_size;
			continue;
		}

		RzBinElfSymbol *elf_symbol = rz_vector_push(result, NULL);
		if (!elf_symbol) {
			rz_vector_free(result);
			return false;
		}

		convert_elf_symbol_entry(bin, elf_symbol, &symbol, type, i);

		offset += entry_size;
	}

	size_t len = rz_vector_len(result);
	if (len) {
		return result;
	}

	rz_vector_free(result);
	return NULL;
}

static void set_by_ord(ELFOBJ *bin, RzBinElfSymbol *symbols, size_t pos, int type) {
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && !bin->imports_by_ord_size) {
		bin->imports_by_ord_size = pos;

		if (!pos) {
			bin->imports_by_ord = NULL;
			return;
		}

		bin->imports_by_ord = RZ_NEWS0(RzBinImport *, pos);

		for (size_t i = 0; i < pos - 1; i++) {
			Elf_(rz_bin_elf_set_import_by_ord)(bin, symbols + i);
		}
	} else if (type == RZ_BIN_ELF_ALL_SYMBOLS && !bin->symbols_by_ord_size && pos) {
		bin->symbols_by_ord_size = pos;

		if (pos > 0) {
			bin->symbols_by_ord = RZ_NEWS0(RzBinSymbol *, pos);
		} else {
			bin->symbols_by_ord = NULL;
		}
	}
}

static RzBinElfSymbol *compute_symbols_from_phdr(ELFOBJ *bin, int type) {
	ut64 entry_size = bin->dyn_info.dt_syment;
	if (bin->dyn_info.dt_symtab == RZ_BIN_ELF_ADDR_MAX || !entry_size) {
		return NULL;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_symtab);
	if (offset == UT64_MAX) {
		return NULL;
	}

	size_t num = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!num) {
		return NULL;
	}

	RzVector *tmp = compute_symbols_from_segment(bin, type, offset, num, entry_size);
	if (!tmp) {
		return NULL;
	}

	RzBinElfSymbol *end = rz_vector_push(tmp, NULL);
	end->last = 1;

	size_t len = rz_vector_len(tmp);
	RzBinElfSymbol *result = rz_vector_flush(tmp);
	rz_vector_free(tmp);

	set_by_ord(bin, result, len, type);

	return result;
}

static RzBinElfSymbol *get_phdr_symbols(ELFOBJ *bin) {
	if (bin->phdr_symbols) {
		return bin->phdr_symbols;
	}

	bin->phdr_symbols = compute_symbols_from_phdr(bin, RZ_BIN_ELF_ALL_SYMBOLS);

	return bin->phdr_symbols;
}

static RzBinElfSymbol *get_phdr_imports(ELFOBJ *bin) {
	if (bin->phdr_imports) {
		return bin->phdr_imports;
	}

	bin->phdr_imports = compute_symbols_from_phdr(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);

	return bin->phdr_imports;
}

static RzBinElfSymbol *get_symbols_from_phdr(ELFOBJ *bin, int type) {
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
		return get_phdr_imports(bin);
	}

	return get_phdr_symbols(bin);
}

static inline int __strnlen(const char *str, int len) {
	int l = 0;
	while (IS_PRINTABLE(*str) && --len) {
		if (((ut8)*str) == 0xff) {
			break;
		}
		str++;
		l++;
	}
	return l + 1;
}

static void fill_symbol_bind_and_type(ELFOBJ *bin, struct rz_bin_elf_symbol_t *ret, Elf_(Sym) * sym) {
	ret->bind = symbol_bind_to_str(sym);
	ret->type = symbol_type_to_str(bin, ret, sym);
}

static int Elf_(fix_symbols)(ELFOBJ *bin, int nsym, int type, RzBinElfSymbol **sym) {
	int count = 0;
	int result = -1;
	RzBinElfSymbol *ret = *sym;
	RzBinElfSymbol *phdr_symbols = get_symbols_from_phdr(bin, type);
	RzBinElfSymbol *tmp, *p;
	HtUP *phd_offset_map = ht_up_new0();
	HtUP *phd_ordinal_map = ht_up_new0();
	if (phdr_symbols) {
		RzBinElfSymbol *d = ret;
		while (!d->last) {
			ht_up_insert(phd_offset_map, d->offset, d);
			ht_up_insert(phd_ordinal_map, d->ordinal, d);
			d++;
		}
		p = phdr_symbols;
		while (!p->last) {
			/* find match in phdr */
			d = ht_up_find(phd_offset_map, p->offset, NULL);
			if (!d) {
				d = ht_up_find(phd_ordinal_map, p->ordinal, NULL);
			}
			if (d) {
				p->in_shdr = true;
				if (*p->name && *d->name && rz_str_startswith(d->name, "$")) {
					strcpy(d->name, p->name);
				}
			}
			p++;
		}
		p = phdr_symbols;
		while (!p->last) {
			if (!p->in_shdr) {
				count++;
			}
			p++;
		}
		/*Take those symbols that are not present in the shdr but yes in phdr*/
		/*This should only should happen with invalid binaries*/
		if (count > 0) {
			/*what happens if a shdr says it has only one symbol? we should look anyway into phdr*/
			tmp = (RzBinElfSymbol *)realloc(ret, (nsym + count + 1) * sizeof(RzBinElfSymbol));
			if (!tmp) {
				result = -1;
				goto done;
			}
			ret = tmp;
			ret[nsym--].last = 0;
			p = phdr_symbols;
			while (!p->last) {
				if (!p->in_shdr) {
					memcpy(&ret[++nsym], p, sizeof(RzBinElfSymbol));
				}
				p++;
			}
			ret[nsym + 1].last = 1;
		}
		*sym = ret;
		result = nsym + 1;
		goto done;
	}
	result = nsym;
done:
	ht_up_free(phd_offset_map);
	ht_up_free(phd_ordinal_map);
	return result;
}

static bool is_section_local_sym(ELFOBJ *bin, Elf_(Sym) * sym) {
	if (sym->st_name != 0) {
		return false;
	}
	if (ELF_ST_TYPE(sym->st_info) != STT_SECTION) {
		return false;
	}
	if (ELF_ST_BIND(sym->st_info) != STB_LOCAL) {
		return false;
	}
	if (!Elf_(rz_bin_elf_is_sh_index_valid)(bin, sym->st_shndx)) {
		return false;
	}
	Elf_(Word) sh_name = bin->shdr[sym->st_shndx].sh_name;
	return bin->shstrtab && sh_name < bin->shstrtab_size;
}

static bool setsymord(ELFOBJ *eobj, ut32 ord, RzBinSymbol *ptr) {
	if (!eobj->symbols_by_ord || ord >= eobj->symbols_by_ord_size) {
		return false;
	}
	rz_bin_symbol_free(eobj->symbols_by_ord[ord]);
	eobj->symbols_by_ord[ord] = ptr;
	return true;
}

static ut32 hashRzBinElfSymbol(const void *obj) {
	const RzBinElfSymbol *symbol = (const RzBinElfSymbol *)obj;
	int hash = sdb_hash(symbol->name);
	hash ^= sdb_hash(symbol->type);
	hash ^= (symbol->offset >> 32);
	hash ^= (symbol->offset & 0xffffffff);
	return hash;
}

static int cmp_RzBinElfSymbol(const RzBinElfSymbol *a, const RzBinElfSymbol *b) {
	int result = 0;
	if (a->offset != b->offset) {
		return 1;
	}
	result = strcmp(a->name, b->name);
	if (result != 0) {
		return result;
	}
	return strcmp(a->type, b->type);
}

// TODO: return RzList<RzBinSymbol*> .. or run a callback with that symbol constructed, so we don't have to do it twice
static RzBinElfSymbol *get_symbols_with_type(ELFOBJ *bin, int type) {
	ut32 shdr_size;
	int tsize, nsym, ret_ctr = 0, i, j, r, k, newsize;
	ut64 toffset;
	ut32 size = 0;
	RzBinElfSymbol *ret = NULL, *import_ret = NULL;
	RzBinSymbol *import_sym_ptr = NULL;
	size_t ret_size = 0, prev_ret_size = 0, import_ret_ctr = 0;
	Elf_(Shdr) *strtab_section = NULL;
	Elf_(Sym) *sym = NULL;
	ut8 s[sizeof(Elf_(Sym))] = { 0 };
	char *strtab = NULL;
	HtPP *symbol_map = NULL;
	HtPPOptions symbol_map_options = {
		.cmp = (HtPPListComparator)cmp_RzBinElfSymbol,
		.hashfn = hashRzBinElfSymbol,
		.dupkey = NULL,
		.calcsizeK = NULL,
		.calcsizeV = NULL,
		.freefn = NULL,
		.elem_size = sizeof(HtPPKv),
	};

	if (!bin || !bin->shdr || !bin->ehdr.e_shnum || bin->ehdr.e_shnum == 0xffff) {
		return get_symbols_from_phdr(bin, type);
	}
	if (!UT32_MUL(&shdr_size, bin->ehdr.e_shnum, sizeof(Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size + 8 > bin->size) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (((type & RZ_BIN_ELF_SYMTAB_SYMBOLS) && bin->shdr[i].sh_type == SHT_SYMTAB) ||
			((type & RZ_BIN_ELF_DYNSYM_SYMBOLS) && bin->shdr[i].sh_type == SHT_DYNSYM)) {
			if (bin->shdr[i].sh_link < 1) {
				/* oops. fix out of range pointers */
				continue;
			}
			// hack to avoid asan cry
			if ((bin->shdr[i].sh_link * sizeof(Elf_(Shdr))) >= shdr_size) {
				/* oops. fix out of range pointers */
				continue;
			}
			strtab_section = &bin->shdr[bin->shdr[i].sh_link];
			if (strtab_section->sh_size > ST32_MAX || strtab_section->sh_size + 8 > bin->size) {
				bprintf("size (syms strtab)");
				free(ret);
				free(strtab);
				return NULL;
			}
			if (!strtab) {
				if (!(strtab = (char *)calloc(1, 8 + strtab_section->sh_size))) {
					bprintf("malloc (syms strtab)");
					goto beach;
				}
				if (strtab_section->sh_offset > bin->size ||
					strtab_section->sh_offset + strtab_section->sh_size > bin->size) {
					goto beach;
				}
				if (rz_buf_read_at(bin->b, strtab_section->sh_offset,
					    (ut8 *)strtab, strtab_section->sh_size) == -1) {
					bprintf("read (syms strtab)\n");
					goto beach;
				}
			}

			newsize = 1 + bin->shdr[i].sh_size;
			if (newsize < 0 || newsize > bin->size) {
				bprintf("invalid shdr %d size\n", i);
				goto beach;
			}
			nsym = (int)(bin->shdr[i].sh_size / sizeof(Elf_(Sym)));
			if (nsym < 0) {
				goto beach;
			}
			{
				ut64 sh_begin = bin->shdr[i].sh_offset;
				ut64 sh_end = sh_begin + bin->shdr[i].sh_size;
				if (sh_begin > bin->size) {
					goto beach;
				}
				if (sh_end > bin->size) {
					st64 newshsize = bin->size - sh_begin;
					nsym = (int)(newshsize / sizeof(Elf_(Sym)));
				}
			}
			if (!(sym = (Elf_(Sym) *)calloc(nsym, sizeof(Elf_(Sym))))) {
				bprintf("calloc (syms)");
				goto beach;
			}
			if (!UT32_MUL(&size, nsym, sizeof(Elf_(Sym)))) {
				goto beach;
			}
			if (size < 1 || size > bin->size) {
				goto beach;
			}
			if (bin->shdr[i].sh_offset > bin->size) {
				goto beach;
			}
			if (bin->shdr[i].sh_offset + size > bin->size) {
				goto beach;
			}
			for (j = 0; j < nsym; j++) {
				int k = 0;
				r = rz_buf_read_at(bin->b, bin->shdr[i].sh_offset + j * sizeof(Elf_(Sym)), s, sizeof(Elf_(Sym)));
				if (r < 1) {
					bprintf("read (sym)\n");
					goto beach;
				}
#if RZ_BIN_ELF64
				sym[j].st_name = READ32(s, k);
				sym[j].st_info = READ8(s, k);
				sym[j].st_other = READ8(s, k);
				sym[j].st_shndx = READ16(s, k);
				sym[j].st_value = READ64(s, k);
				sym[j].st_size = READ64(s, k);
#else
				sym[j].st_name = READ32(s, k);
				sym[j].st_value = READ32(s, k);
				sym[j].st_size = READ32(s, k);
				sym[j].st_info = READ8(s, k);
				sym[j].st_other = READ8(s, k);
				sym[j].st_shndx = READ16(s, k);
#endif
			}
			ret = realloc(ret, (ret_size + nsym) * sizeof(RzBinElfSymbol));
			if (!ret) {
				bprintf("Cannot allocate %d symbols\n", nsym);
				goto beach;
			}
			memset(ret + ret_size, 0, nsym * sizeof(RzBinElfSymbol));
			prev_ret_size = ret_size;
			ret_size += nsym;
			symbol_map = ht_pp_new_opt(&symbol_map_options);
			for (k = 0; k < prev_ret_size; k++) {
				if (ret[k].name[0]) {
					ht_pp_insert(symbol_map, ret + k, ret + k);
				}
			}
			for (k = 1; k < nsym; k++) {
				bool is_sht_null = false;
				bool is_vaddr = false;
				bool is_imported = false;
				if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
					if (sym[k].st_value) {
						toffset = sym[k].st_value;
					} else if ((toffset = get_import_addr(bin, k)) == -1) {
						toffset = 0;
					}
					tsize = 16;
					is_imported = sym[k].st_shndx == STN_UNDEF;
				} else {
					tsize = sym[k].st_size;
					toffset = (ut64)sym[k].st_value;
					is_sht_null = sym[k].st_shndx == SHT_NULL;
				}
				if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
					if (sym[k].st_shndx < bin->ehdr.e_shnum) {
						ret[ret_ctr].offset = sym[k].st_value + bin->shdr[sym[k].st_shndx].sh_offset;
					}
				} else {
					ret[ret_ctr].offset = Elf_(rz_bin_elf_v2p_new)(bin, toffset);
					if (ret[ret_ctr].offset == UT64_MAX) {
						ret[ret_ctr].offset = toffset;
						is_vaddr = true;
					}
				}
				ret[ret_ctr].size = tsize;
				if (sym[k].st_name + 1 > strtab_section->sh_size) {
					bprintf("index out of strtab range\n");
					continue;
				}
				{
					int st_name = sym[k].st_name;
					int maxsize = RZ_MIN(rz_buf_size(bin->b), strtab_section->sh_size);
					if (is_section_local_sym(bin, &sym[k])) {
						const char *shname = &bin->shstrtab[bin->shdr[sym[k].st_shndx].sh_name];
						rz_str_ncpy(ret[ret_ctr].name, shname, ELF_STRING_LENGTH);
					} else if (st_name <= 0 || st_name >= maxsize) {
						ret[ret_ctr].name[0] = 0;
					} else {
						rz_str_ncpy(ret[ret_ctr].name, &strtab[st_name], ELF_STRING_LENGTH);
						ret[ret_ctr].type = symbol_type_to_str(bin, &ret[ret_ctr], &sym[k]);

						if (ht_pp_find(symbol_map, &ret[ret_ctr], NULL)) {
							memset(ret + ret_ctr, 0, sizeof(RzBinElfSymbol));
							continue;
						}
					}
				}
				ret[ret_ctr].ordinal = k;
				ret[ret_ctr].name[ELF_STRING_LENGTH - 2] = '\0';
				fill_symbol_bind_and_type(bin, &ret[ret_ctr], &sym[k]);
				ret[ret_ctr].is_sht_null = is_sht_null;
				ret[ret_ctr].is_vaddr = is_vaddr;
				ret[ret_ctr].last = 0;
				ret[ret_ctr].is_imported = is_imported;
				ret_ctr++;
				if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && is_imported) {
					import_ret_ctr++;
				}
			}
			RZ_FREE(strtab);
			RZ_FREE(sym);
			ht_pp_free(symbol_map);
			symbol_map = NULL;
			if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
				break;
			}
		}
	}
	if (!ret) {
		return get_symbols_from_phdr(bin, type);
	}
	ret[ret_ctr].last = 1; // ugly dirty hack :D
	int max = -1;
	RzBinElfSymbol *aux = NULL;
	nsym = Elf_(fix_symbols)(bin, ret_ctr, type, &ret);
	if (nsym == -1) {
		goto beach;
	}

	// Elf_(fix_symbols) may find additional symbols, some of which could be
	// imported symbols. Let's reserve additional space for them.
	rz_warn_if_fail(nsym >= ret_ctr);
	import_ret_ctr += nsym - ret_ctr;

	aux = ret;
	while (!aux->last) {
		if ((int)aux->ordinal > max) {
			max = aux->ordinal;
		}
		aux++;
	}
	nsym = max;
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
		RZ_FREE(bin->imports_by_ord);
		bin->imports_by_ord_size = nsym + 1;
		bin->imports_by_ord = (RzBinImport **)calloc(RZ_MAX(1, nsym + 1), sizeof(RzBinImport *));
		RZ_FREE(bin->symbols_by_ord);
		bin->symbols_by_ord_size = nsym + 1;
		bin->symbols_by_ord = (RzBinSymbol **)calloc(RZ_MAX(1, nsym + 1), sizeof(RzBinSymbol *));
		import_ret = calloc(import_ret_ctr + 1, sizeof(RzBinElfSymbol));
		if (!import_ret) {
			bprintf("Cannot allocate %d symbols\n", nsym);
			goto beach;
		}
		import_ret_ctr = 0;
		i = -1;
		while (!ret[++i].last) {
			if (!(import_sym_ptr = Elf_(rz_bin_elf_convert_symbol)(bin, &ret[i], "%s"))) {
				continue;
			}

			if (!setsymord(bin, import_sym_ptr->ordinal, import_sym_ptr)) {
				free(import_sym_ptr);
			}

			if (ret[i].is_imported) {
				Elf_(rz_bin_elf_set_import_by_ord)(bin, &ret[i]);
				memcpy(&import_ret[import_ret_ctr], &ret[i], sizeof(RzBinElfSymbol));
				++import_ret_ctr;
			}
		}
		import_ret[import_ret_ctr].last = 1;
		RZ_FREE(ret);
		return import_ret;
	}
	return ret;
beach:
	free(ret);
	free(sym);
	free(strtab);
	ht_pp_free(symbol_map);
	return NULL;
}

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->g_imports) {
		bin->g_imports = get_symbols_with_type(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);
	}

	return bin->g_imports;
}

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->g_symbols) {
		bin->g_symbols = get_symbols_with_type(bin, RZ_BIN_ELF_ALL_SYMBOLS);
	}

	return bin->g_symbols;
}

/**
 * \brief Convert a RzBinElfSymbol to RzBinImport
 * \param elf binary
 * \param bin symbol
 * \return a ptr to a new allocated RzBinImport
 *
 * ...
 */
RZ_OWN RzBinImport *Elf_(rz_bin_elf_convert_import)(RZ_UNUSED ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol) {
	rz_return_val_if_fail(symbol, NULL);

	RzBinImport *ptr = RZ_NEW0(RzBinImport);
	if (!ptr) {
		return NULL;
	}

	ptr->name = strdup(symbol->name);
	ptr->bind = symbol->bind;
	ptr->type = symbol->type;
	ptr->ordinal = symbol->ordinal;

	return ptr;
}

/**
 * \brief Convert a RzBinElfSymbol to RzBinSymbol
 * \param elf binary
 * \param bin symbol
 * \param name format
 * \return a ptr to a new allocated RzBinSymbol
 *
 * Convert a RzElfBinSymbol to RzBinSymbol, the name can be formatted.
 */
RZ_OWN RzBinSymbol *Elf_(rz_bin_elf_convert_symbol)(RZ_NONNULL ELFOBJ *bin,
	RZ_NONNULL RzBinElfSymbol *elf_symbol,
	const char *namefmt) {
	rz_return_val_if_fail(bin && elf_symbol, NULL);

	RzBinSymbol *symbol = RZ_NEW0(RzBinSymbol);
	if (!symbol) {
		return NULL;
	}

	set_addr_parameter(bin, elf_symbol, symbol);
	set_common_parameter(elf_symbol, symbol, namefmt);

	if (is_arm_symbol(bin, elf_symbol)) {
		set_arm_symbol_bits(bin, symbol);
	}

	return symbol;
}

size_t Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	size_t result = get_number_of_symbols_from_hash(bin);
	if (result) {
		return result;
	}

	result = get_number_of_symbols_from_gnu_hash(bin);
	if (result) {
		return result;
	}

	return get_number_of_symbols_from_heuristic(bin);
}
