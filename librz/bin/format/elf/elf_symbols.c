// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include <rz_util/ht_uu.h>

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
	return (struct symbols_segment){
		.offset = offset,
		.number = number,
		.entry_size = entry_size,
		.dynamic = dynamic,
		.strtab = strtab
	};
}

static Elf_(Word) get_number_of_symbols_from_heuristic_aux(ELFOBJ *bin, ut64 symtab_offset, ut64 strtab_offset) {
	if (symtab_offset > strtab_offset) {
		return 0;
	}

	ut64 symtab_size = strtab_offset - symtab_offset;
	return symtab_size / sizeof(Elf_(Sym));
}

static Elf_(Word) get_number_of_symbols_from_heuristic(ELFOBJ *bin) {
	ut64 symtab_addr;
	ut64 strtab_addr;
	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_SYMTAB, &symtab_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_STRTAB, &strtab_addr)) {
		return 0;
	}

	ut64 symtab_offset = Elf_(rz_bin_elf_v2p)(bin, symtab_addr);
	ut64 strtab_offset = Elf_(rz_bin_elf_v2p)(bin, strtab_addr);
	if (symtab_offset == UT64_MAX || strtab_offset == UT64_MAX) {
		return 0;
	}

	return get_number_of_symbols_from_heuristic_aux(bin, symtab_offset, strtab_offset);
}

static Elf_(Word) get_number_of_symbols_from_section(ELFOBJ *bin) {
	RzBinElfSection *section = Elf_(rz_bin_elf_get_section_with_name)(bin, ".dynsym");
	if (!section) {
		return 0;
	}

	return section->size / sizeof(Elf_(Sym));
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

static bool get_symbol_entry_aux(ELFOBJ *bin, ut64 offset, Elf_(Sym) * result) {
#if RZ_BIN_ELF64
	return Elf_(rz_bin_elf_read_word)(bin, &offset, &result->st_name) &&
		Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_info) &&
		Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_other) &&
		Elf_(rz_bin_elf_read_section)(bin, &offset, &result->st_shndx) &&
		Elf_(rz_bin_elf_read_addr)(bin, &offset, &result->st_value) &&
		Elf_(rz_bin_elf_read_xword)(bin, &offset, &result->st_size);
#else
	return Elf_(rz_bin_elf_read_word)(bin, &offset, &result->st_name) &&
		Elf_(rz_bin_elf_read_addr)(bin, &offset, &result->st_value) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &result->st_size) &&
		Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_info) &&
		Elf_(rz_bin_elf_read_char)(bin, &offset, &result->st_other) &&
		Elf_(rz_bin_elf_read_section)(bin, &offset, &result->st_shndx);
#endif
}

static bool get_symbol_entry(ELFOBJ *bin, ut64 offset, Elf_(Sym) * result) {
	if (!get_symbol_entry_aux(bin, offset, result)) {
		RZ_LOG_WARN("Failed to read symbol entry at 0x%" PFMT64x ".\n", offset);
		return false;
	}

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
		elf_symbol->name = rz_str_dup(section->name);
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

	elf_symbol->bind = symbol_bind_to_str(symbol);
	elf_symbol->ordinal = ordinal;
	elf_symbol->size = symbol->st_size;

	if (symbol->st_size == 0 && symbol->st_shndx == SHN_UNDEF && symbol->st_value == 0) {
		elf_symbol->paddr = elf_symbol->vaddr = UT64_MAX;
	} else {
		if (Elf_(rz_bin_elf_is_relocatable)(bin) && section) {
			elf_symbol->paddr = section->offset + symbol->st_value;
			elf_symbol->vaddr = Elf_(rz_bin_elf_p2v)(bin, elf_symbol->paddr);
		} else {
			elf_symbol->vaddr = symbol->st_value;
			elf_symbol->paddr = Elf_(rz_bin_elf_v2p)(bin, elf_symbol->vaddr);
		}
	}

	if (!set_elf_symbol_name(bin, segment, elf_symbol, symbol, section)) {
		return false;
	}

	elf_symbol->type = symbol_type_to_str(bin, elf_symbol, symbol);

	return true;
}

static bool has_already_been_processed(ELFOBJ *bin, ut64 offset, HtUU *set) {
	bool found;
	ht_uu_find(set, offset, &found);

	return found;
}

static void elf_symbol_fini(void *e, RZ_UNUSED void *user) {
	RzBinElfSymbol *ptr = e;
	free(ptr->name);
}

static bool compute_symbols_from_segment(ELFOBJ *bin, RzVector /*<RzBinElfSymbol>*/ *result, struct symbols_segment *segment, RzBinElfSymbolFilter filter, HtUU *set) {
	if (has_already_been_processed(bin, segment->offset, set)) {
		return true;
	}

	if (!ht_uu_insert(set, segment->offset, 1ULL)) {
		return false;
	}

	ut64 offset = segment->offset + segment->entry_size;

	for (size_t i = 1; i < segment->number; i++) {
		Elf_(Sym) entry;
		if (!get_symbol_entry(bin, offset, &entry)) {
			return false;
		}

		if (!filter(bin, &entry, segment->dynamic)) {
			offset += segment->entry_size;
			continue;
		}

		RzBinElfSymbol symbol = { 0 };

		if (!convert_elf_symbol_entry(bin, segment, &symbol, &entry, i)) {
			return false;
		}

		if (!rz_vector_push(result, &symbol)) {
			elf_symbol_fini(&symbol, NULL);
			return false;
		}

		offset += segment->entry_size;
	}

	return true;
}

static bool get_dynamic_elf_symbols(ELFOBJ *bin, RzVector /*<RzBinElfSymbol>*/ *result, RzBinElfSymbolFilter filter, HtUU *set) {
	if (!Elf_(rz_bin_elf_is_executable)(bin)) {
		return true;
	}

	ut64 addr;
	ut64 entry_size;
	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_SYMTAB, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_SYMENT, &entry_size)) {
		return true;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (offset == UT64_MAX) {
		return true;
	}

	Elf_(Word) number = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!number) {
		return true;
	}

	struct symbols_segment segment = symbols_segment_init(offset, number, entry_size, true, bin->dynstr);

	if (!compute_symbols_from_segment(bin, result, &segment, filter, set)) {
		return false;
	}

	return true;
}

static bool get_section_elf_symbols(ELFOBJ *bin, RzVector /*<RzBinElfSymbol>*/ *result, RzBinElfSymbolFilter filter, HtUU *set) {
	size_t i;
	RzBinElfSection *section;
	rz_bin_elf_enumerate_sections(bin, section, i) {
		if (!section->is_valid) {
			continue;
		}

		if (section->type != SHT_SYMTAB && section->type != SHT_DYNSYM) {
			continue;
		}

		if (!section->link) {
			RZ_LOG_WARN("The section %zu has a null link.\n", i);
			continue;
		}

		RzBinElfSection *strtab_section = Elf_(rz_bin_elf_get_section)(bin, section->link);
		if (!strtab_section) {
			continue;
		}

		RzBinElfStrtab *strtab = Elf_(rz_bin_elf_strtab_new)(bin, strtab_section->offset, strtab_section->size);
		if (!strtab) {
			continue;
		}

		ut64 number = (section->size / sizeof(Elf_(Sym)));

		struct symbols_segment segment = symbols_segment_init(section->offset, number, sizeof(Elf_(Sym)), false, strtab);

		if (!compute_symbols_from_segment(bin, result, &segment, filter, set)) {
			Elf_(rz_bin_elf_strtab_free)(strtab);
			return false;
		}

		Elf_(rz_bin_elf_strtab_free)(strtab);
	}

	return true;
}

static bool get_gnu_debugdata_elf_symbols(ELFOBJ *bin, RzVector /*<RzBinElfSymbol>*/ *result, RzBinElfSymbolFilter filter, HtUU *set) {
	// Get symbols from .gnu_debugdata according to https://sourceware.org/gdb/onlinedocs/gdb/MiniDebugInfo.html
	bool res = false;
	const RzBinElfSection *gnu_debugdata = Elf_(rz_bin_elf_get_section_with_name)(bin, ".gnu_debugdata");
	if (!gnu_debugdata) {
		return false;
	}

	RzBuffer *data_buf = rz_buf_new_slice(bin->b, gnu_debugdata->offset, gnu_debugdata->size);
	if (!data_buf) {
		return false;
	}

	RzBuffer *dec_buf = rz_buf_new_empty(0);
	if (!dec_buf) {
		goto data_buf_err;
	}

	if (!rz_lzma_dec_buf(data_buf, dec_buf, 1 << 13, NULL)) {
		goto dec_buf_err;
	}

	RzBinObjectLoadOptions obj_opts = {
		.baseaddr = UT64_MAX,
		.loadaddr = 0,
		.elf_load_sections = true,
	};
	ELFOBJ *debug_data_bin = Elf_(rz_bin_elf_new_buf)(dec_buf, &obj_opts);
	if (!debug_data_bin) {
		goto dec_buf_err;
	}

	RzVector *debug_symbols = Elf_(rz_bin_elf_compute_symbols)(debug_data_bin, filter);
	if (!debug_symbols) {
		goto debug_data_err;
	}

	HtSP *name_set = ht_sp_new(HT_STR_CONST, NULL, NULL);
	if (!name_set) {
		goto debug_symbols_err;
	}

	RzBinElfSymbol *sym;
	rz_vector_foreach (result, sym) {
		ht_sp_insert(name_set, sym->name, sym);
	}

	rz_vector_foreach (debug_symbols, sym) {
		bool found;
		ht_sp_find(name_set, sym->name, &found);
		if (found) {
			continue;
		}

		rz_vector_push(result, sym);
	}
	// The ownership has been moved to `result`, no need to free the elements.
	debug_symbols->len = 0;
	res = true;

	ht_sp_free(name_set);
debug_symbols_err:
	rz_vector_free(debug_symbols);
debug_data_err:
	Elf_(rz_bin_elf_free)(debug_data_bin);
dec_buf_err:
	rz_buf_free(dec_buf);
data_buf_err:
	rz_buf_free(data_buf);
	return res;
}

static bool filter_symbol(RZ_UNUSED ELFOBJ *bin, Elf_(Sym) * symbol, RZ_UNUSED bool is_dynamic) {
	return symbol->st_shndx != SHT_NULL;
}

Elf_(Word) Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	Elf_(Word) result = Elf_(rz_bin_elf_get_number_of_symbols_from_hash_table)(bin);
	if (result) {
		return result;
	}

	result = Elf_(rz_bin_elf_get_number_of_symbols_from_gnu_hash_table)(bin);
	if (result) {
		return result;
	}

	RZ_LOG_WARN("Neither hash nor gnu_hash exist. Falling back to heuristics for deducing the number of dynamic symbols...\n");

	result = get_number_of_symbols_from_section(bin);
	if (result) {
		return result;
	}

	result = get_number_of_symbols_from_heuristic(bin);
	if (result) {
		return result;
	}

	RZ_LOG_ERROR("Failed to determine the number of dynamic symbols from heuristics.\n");

	return 0;
}

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_symbol)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(bin, symbol) {
		if (symbol->ordinal == ordinal) {
			return symbol;
		}
	}

	return NULL;
}

RZ_OWN RzVector /*<RzBinElfSymbol>*/ *Elf_(rz_bin_elf_compute_symbols)(ELFOBJ *bin, RzBinElfSymbolFilter filter) {
	RzVector *result = rz_vector_new(sizeof(RzBinElfSymbol), elf_symbol_fini, NULL);
	if (!result) {
		return NULL;
	}

	HtUU *set = ht_uu_new();
	if (!set) {
		rz_vector_free(result);
		return NULL;
	}

	if (!get_dynamic_elf_symbols(bin, result, filter, set)) {
		rz_vector_free(result);
		ht_uu_free(set);
		return NULL;
	}

	if (!get_section_elf_symbols(bin, result, filter, set)) {
		rz_vector_free(result);
		ht_uu_free(set);
		return NULL;
	}

	// Parsing .gnu_debugdata is completely optional, ignore errors if any and just continue
	(void)get_gnu_debugdata_elf_symbols(bin, result, filter, set);

	ht_uu_free(set);

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		return NULL;
	}

	return result;
}

RZ_OWN RzVector /*<RzBinElfSymbol>*/ *Elf_(rz_bin_elf_symbols_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzVector *result = Elf_(rz_bin_elf_compute_symbols)(bin, filter_symbol);
	if (!result) {
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_has_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->symbols;
}
