// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include "elf_symbols.h"
#include <ht_uu.h>

#define HASH_NCHAIN_OFFSET(x) ((x) + 4)

struct symbols_segment {
	ut64 offset;
	ut64 number;
	ut64 entry_size;
	bool dynamic;
	RZ_BORROW RzBinElfStrtab *strtab;
};

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

static struct symbols_segment symbols_segment_init(ut64 offset, ut64 number, ut64 entry_size, bool dynamic, RzBinElfStrtab *strtab) {
	return (struct symbols_segment){ .offset = offset, .number = number, .entry_size = entry_size, .dynamic = dynamic, .strtab = strtab };
}

static void set_addr_parameter(ELFOBJ *bin, RzBinElfSymbol *elf_symbol, RzBinSymbol *symbol) {
	if (elf_symbol->is_vaddr) {
		symbol->paddr = UT64_MAX;
		symbol->vaddr = elf_symbol->offset;
	} else {
		symbol->paddr = elf_symbol->offset;
		symbol->vaddr = Elf_(rz_bin_elf_p2v_new)(bin, symbol->paddr);
	}
}

static void set_common_parameter(RzBinElfSymbol *elf_symbol, RzBinSymbol *symbol) {
	char *symbol_name = elf_symbol->name ? rz_str_new(elf_symbol->name) : rz_str_new("");

	symbol->name = symbol_name;
	symbol->forwarder = "NONE";
	symbol->bind = elf_symbol->bind;
	symbol->type = elf_symbol->type;
	symbol->size = elf_symbol->size;
	symbol->ordinal = elf_symbol->ordinal;
}

static bool is_arm_symbol(ELFOBJ *bin, RzBinElfSymbol *elf_symbol) {
	return bin->ehdr.e_machine == EM_ARM && elf_symbol->name;
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

static Elf_(Word) get_number_of_symbols_from_hash(ELFOBJ *bin) {
	ut64 addr;
	Elf_(Word) result;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_HASH, &addr)) {
		return 0;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	if (offset == UT64_MAX) {
		return 0;
	}

	ut64 nchain_offset = HASH_NCHAIN_OFFSET(offset);

	if (!Elf_(rz_bin_elf_read_word)(bin, &nchain_offset, &result)) {
		return 0;
	}

	return result;
}

static Elf_(Word) get_index_from_buckets(ELFOBJ *bin, ut64 *bucket_offset, Elf_(Word) number_of_bucket) {
	Elf_(Word) tmp;
	Elf_(Word) index = 0;

	for (Elf_(Word) i = 0; i < number_of_bucket; i++) {
		if (!Elf_(rz_bin_elf_read_word)(bin, bucket_offset, &tmp)) {
			return 0;
		}

		index = RZ_MAX(index, tmp);
	}

	return index;
}

static Elf_(Word) get_index_from_chain(ELFOBJ *bin, ut64 bucket_offset, Elf_(Word) symbol_base, Elf_(Word) index) {
	Elf_(Word) tmp;

	if (index <= symbol_base) {
		return 0;
	}

	Elf_(Word) chain_index = index - symbol_base;
	ut64 chain_offset = bucket_offset + chain_index * 4;

	while (1) {
		index++;
		if (!Elf_(rz_bin_elf_read_word)(bin, &chain_offset, &tmp)) {
			return 0;
		}

		if (tmp & 1) {
			break;
		}
	}

	return index;
}

static Elf_(Word) get_number_of_symbols_from_gnu_hash(ELFOBJ *bin) {
	ut64 hash_addr;
	Elf_(Word) number_of_bucket;
	Elf_(Word) symbol_base;
	Elf_(Word) bitmask_nwords;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_GNU_HASH, &hash_addr)) {
		return 0;
	}

	ut64 hash_offset = Elf_(rz_bin_elf_v2p_new)(bin, hash_addr);
	if (hash_offset == UT64_MAX) {
		return 0;
	}

	ut64 pos = hash_offset;

	if (!Elf_(rz_bin_elf_read_word)(bin, &pos, &number_of_bucket)) {
		return 0;
	}

	if (!Elf_(rz_bin_elf_read_word)(bin, &pos, &symbol_base)) {
		return 0;
	}

	if (!Elf_(rz_bin_elf_read_word)(bin, &pos, &bitmask_nwords)) {
		return 0;
	}

	ut64 bucket_offset = hash_offset + 16 + bitmask_nwords * sizeof(Elf_(Addr));

	Elf_(Word) index = get_index_from_buckets(bin, &bucket_offset, number_of_bucket);

	return get_index_from_chain(bin, bucket_offset, symbol_base, index);
}

static Elf_(Word) get_number_of_symbols_from_heuristic_aux(ELFOBJ *bin, ut64 symtab_offset, ut64 strtab_offset) {
	if (symtab_offset > strtab_offset) {
		return 0;
	}

	ut64 symtab_size = strtab_offset - symtab_offset;
	return symtab_size / sizeof(Elf_(Sym));
}

static Elf_(Word) get_number_of_symbols_from_heuristic(ELFOBJ *bin) {
	RzBinElfSection *dynsym_section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".dynsym");
	RzBinElfSection *strtab_section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".dynstr");

	if (dynsym_section || strtab_section) {
		return get_number_of_symbols_from_heuristic_aux(bin, dynsym_section->offset, strtab_section->offset);
	}

	ut64 symtab_addr;
	ut64 strtab_addr;
	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_SYMTAB, &symtab_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_STRTAB, &strtab_addr)) {
		return 0;
	}

	ut64 symtab_offset = Elf_(rz_bin_elf_v2p_new)(bin, symtab_addr);
	ut64 strtab_offset = Elf_(rz_bin_elf_v2p_new)(bin, strtab_addr);
	if (symtab_offset == UT64_MAX || strtab_offset == UT64_MAX) {
		return 0;
	}

	return get_number_of_symbols_from_heuristic_aux(bin, symtab_offset, strtab_offset);
}

static bool is_special_arm_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	if (!name) {
		return false;
	}

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

static bool get_symbol_entry(ELFOBJ *bin, ut64 offset, Elf_(Sym) * result) {
#if RZ_BIN_ELF64
	if (!Elf_(rz_bin_elf_read_word)(bin, &offset, &result->st_name) ||
		!Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_info) ||
		!Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_other) ||
		!Elf_(rz_bin_elf_read_section)(bin, &offset, &result->st_shndx) ||
		!Elf_(rz_bin_elf_read_addr)(bin, &offset, &result->st_value) ||
		!Elf_(rz_bin_elf_read_xword)(bin, &offset, &result->st_size)) {
		return false;
	}
#else
	if (!Elf_(rz_bin_elf_read_word)(bin, &offset, &result->st_name) ||
		!Elf_(rz_bin_elf_read_addr)(bin, &offset, &result->st_value) ||
		!Elf_(rz_bin_elf_read_word)(bin, &offset, &result->st_size) ||
		!Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_info) ||
		!Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_other) ||
		!Elf_(rz_bin_elf_read_section)(bin, &offset, &result->st_shndx)) {
		return false;
	}
#endif

	return true;
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
	if (symbol->st_shndx >= bin->ehdr.e_shnum) {
		return false;
	}

	return true;
}

static bool set_elf_symbol_name(ELFOBJ *bin, struct symbols_segment *segment, RzBinElfSymbol *elf_symbol, Elf_(Sym) * symbol, RzBinElfSection *section) {
	if (section && is_section_local_symbol(bin, symbol)) {
		elf_symbol->name = rz_str_new(section->name);
		return elf_symbol->name;
	}

	if (!segment->strtab) {
		return false;
	}

	elf_symbol->name = Elf_(rz_bin_elf_strtab_get_dup)(segment->strtab, symbol->st_name);
	if (!elf_symbol->name) {
		return false;
	}

	return true;
}

static bool convert_elf_symbol_entry(ELFOBJ *bin, struct symbols_segment *segment, RzBinElfSymbol *elf_symbol, Elf_(Sym) * symbol, size_t ordinal) {
	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, symbol->st_shndx);

	elf_symbol->offset = symbol->st_value;
	elf_symbol->size = symbol->st_size;
	elf_symbol->ordinal = ordinal;
	elf_symbol->bind = symbol_bind_to_str(symbol);

	if (!set_elf_symbol_name(bin, segment, elf_symbol, symbol, section)) {
		return false;
	}

	elf_symbol->type = symbol_type_to_str(bin, elf_symbol, symbol);

	if (Elf_(rz_bin_elf_is_relocatable)(bin) && section) {
		elf_symbol->offset = symbol->st_value + section->offset;
	} else {
		ut64 tmp = Elf_(rz_bin_elf_v2p_new)(bin, elf_symbol->offset);
		if (tmp == UT64_MAX) {
			elf_symbol->is_vaddr = true;
		} else {
			elf_symbol->offset = tmp;
		}
	}

	return true;
}

static bool is_import_symbol(ELFOBJ *bin, struct symbols_segment *segment, Elf_(Sym) * symbol) {
	return (segment->dynamic || Elf_(rz_bin_elf_is_relocatable)(bin)) && !symbol->st_shndx;
}

static bool add_elf_symbol(ELFOBJ *bin, struct symbols_segment *segment, RzBinElfSymbols *result, Elf_(Sym) * symbol, RzBinElfSymbol *elf_symbol) {
	if (is_import_symbol(bin, segment, symbol)) {
		return rz_vector_push(result->elf_import_symbols, elf_symbol);
	}

	if (!symbol->st_shndx) {
		return true;
	}

	return rz_vector_push(result->elf_symbols, elf_symbol);
}

static bool has_already_been_processed(ELFOBJ *bin, ut64 offset, HtUU *set) {
	bool found;
	ht_uu_find(set, offset, &found);

	return found;
}

static bool compute_symbols_from_segment(ELFOBJ *bin, RzBinElfSymbols *result, struct symbols_segment *segment, HtUU *set) {
	ut64 offset = segment->offset + segment->entry_size;

	for (size_t i = 1; i < segment->number; i++) {
		Elf_(Sym) entry;

		if (!get_symbol_entry(bin, offset, &entry)) {
			return false;
		}

		if (has_already_been_processed(bin, offset, set)) {
			offset += segment->entry_size;
			continue;
		}

		if (!ht_uu_insert(set, offset, offset)) {
			return false;
		}

		RzBinElfSymbol elf_symbol = { 0 };

		if (!convert_elf_symbol_entry(bin, segment, &elf_symbol, &entry, i)) {
			return false;
		}

		if (!add_elf_symbol(bin, segment, result, &entry, &elf_symbol)) {
			return false;
		}

		offset += segment->entry_size;
	}

	return true;
}

static bool get_dynamic_elf_symbols(ELFOBJ *bin, RzBinElfSymbols *result, HtUU *set) {
	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return true;
	}

	ut64 addr;
	ut64 entry_size;
	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_SYMTAB, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_SYMENT, &entry_size)) {
		return true;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	if (offset == UT64_MAX) {
		return true;
	}

	Elf_(Word) number = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!number) {
		return true;
	}

	struct symbols_segment segment = symbols_segment_init(offset, number, entry_size, true, bin->dynstr);

	if (!compute_symbols_from_segment(bin, result, &segment, set)) {
		return false;
	}

	return true;
}

static bool get_section_elf_symbols(ELFOBJ *bin, RzBinElfSymbols *result, HtUU *set) {
	if (!Elf_(rz_bin_elf_has_sections)(bin)) {
		return true;
	}

	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(bin, section) {
		if (!section->is_valid) {
			continue;
		}

		if (section->type != SHT_SYMTAB && section->type != SHT_DYNSYM) {
			continue;
		}

		if (!section->link) {
			RZ_LOG_WARN("section with null link %s", section->name);
			continue;
		}

		RzBinElfSection *strtab_section = Elf_(rz_bin_elf_get_section)(bin, section->link);
		if (!strtab_section) {
			RZ_LOG_WARN("section with invalid link %s", section->name);
			continue;
		}

		RzBinElfStrtab *strtab = Elf_(rz_bin_elf_strtab_new)(bin, strtab_section->offset, strtab_section->size);
		if (!strtab) {
			RZ_LOG_WARN("invalid strtab section %s", strtab_section->name);
			continue;
		}

		ut64 number = (section->size / sizeof(Elf_(Sym)));

		struct symbols_segment segment = symbols_segment_init(section->offset, number, sizeof(Elf_(Sym)), false, strtab);

		if (!compute_symbols_from_segment(bin, result, &segment, set)) {
			Elf_(rz_bin_elf_strtab_free)(strtab);
			return false;
		}

		Elf_(rz_bin_elf_strtab_free)(strtab);
	}

	return true;
}

static void elf_symbol_free(void *e, RZ_UNUSED void *user) {
	RzBinElfSymbol *ptr = e;
	free(ptr->name);
}

static bool get_elf_symbols(ELFOBJ *bin, RzBinElfSymbols *result) {
	HtUU *set = ht_uu_new0();
	if (!set) {
		return NULL;
	}

	result->elf_symbols = rz_vector_new(sizeof(RzBinElfSymbol), elf_symbol_free, NULL);
	if (!result->elf_symbols) {
		return NULL;
	}

	result->elf_import_symbols = rz_vector_new(sizeof(RzBinElfSymbol), elf_symbol_free, NULL);
	if (!result->elf_import_symbols) {
		rz_vector_free(result->elf_symbols);
		return NULL;
	}

	if (!get_dynamic_elf_symbols(bin, result, set)) {
		rz_vector_free(result->elf_symbols);
		rz_vector_free(result->elf_import_symbols);
		return NULL;
	}

	if (!get_section_elf_symbols(bin, result, set)) {
		rz_vector_free(result->elf_symbols);
		rz_vector_free(result->elf_import_symbols);
		return NULL;
	}

	if (!rz_vector_len(result->elf_symbols) && !rz_vector_len(result->elf_import_symbols)) {
		rz_vector_free(result->elf_symbols);
		rz_vector_free(result->elf_import_symbols);
		return NULL;
	}

	return result;
}

static void convert_symbol(ELFOBJ *bin, RzBinSymbol *symbol, RzBinElfSymbol *elf_symbol) {
	set_addr_parameter(bin, elf_symbol, symbol);
	set_common_parameter(elf_symbol, symbol);

	if (is_arm_symbol(bin, elf_symbol)) {
		set_arm_symbol_bits(bin, symbol);
	}
}

static void symbols_free(void *e, RZ_UNUSED void *user) {
	RzBinSymbol *ptr = e;
	rz_bin_symbol_free(ptr);
}

Elf_(Word) Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	Elf_(Word) result = get_number_of_symbols_from_hash(bin);
	if (result) {
		return result;
	}

	result = get_number_of_symbols_from_gnu_hash(bin);
	if (result) {
		return result;
	}

	return get_number_of_symbols_from_heuristic(bin);
}

static RzVector *get_symbols(ELFOBJ *bin, RzVector *elf_symbols) {
	RzVector *result = rz_vector_new(sizeof(RzBinSymbol), symbols_free, NULL);
	if (!result) {
		return NULL;
	}

	RzBinElfSymbol *tmp;
	rz_vector_foreach(elf_symbols, tmp) {
		RzBinSymbol symbol = { 0 };

		convert_symbol(bin, &symbol, tmp);

		if (!rz_vector_push(result, &symbol)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	return result;
}

RZ_BORROW RzBinSymbol *Elf_(rz_bin_elf_get_symbol)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal) {
	rz_return_val_if_fail(bin && bin->symbols, NULL);

	RzBinSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		if (symbol->ordinal == ordinal) {
			return symbol;
		}
	}

	return NULL;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_elf_import_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->symbols, NULL);
	return bin->symbols->elf_import_symbols;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_elf_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->symbols, NULL);
	return bin->symbols->elf_symbols;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->symbols, NULL);
	return bin->symbols->symbols;
}

RZ_OWN RzBinElfSymbols *Elf_(rz_bin_elf_symbols_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSymbols *result = RZ_NEW(RzBinElfSymbols);
	if (!result) {
		return NULL;
	}

	if (!get_elf_symbols(bin, result)) {
		free(result);
		return NULL;
	}

	result->symbols = get_symbols(bin, result->elf_symbols);
	if (!result->symbols) {
		rz_vector_free(result->elf_import_symbols);
		rz_vector_free(result->elf_symbols);
		free(result);
		return NULL;
	}

	return result;
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
	RZ_NONNULL RzBinElfSymbol *elf_symbol) {
	rz_return_val_if_fail(bin && elf_symbol, NULL);

	RzBinSymbol *symbol = RZ_NEW0(RzBinSymbol);
	if (!symbol) {
		return NULL;
	}

	convert_symbol(bin, symbol, elf_symbol);

	return symbol;
}

bool Elf_(rz_bin_elf_has_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->symbols;
}

void Elf_(rz_bin_elf_symbols_free)(RzBinElfSymbols *ptr) {
	if (!ptr) {
		return;
	}

	rz_vector_free(ptr->elf_import_symbols);
	rz_vector_free(ptr->elf_symbols);
	rz_vector_free(ptr->symbols);
	free(ptr);
}
