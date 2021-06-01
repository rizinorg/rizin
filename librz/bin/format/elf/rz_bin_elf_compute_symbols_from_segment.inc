// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut64 get_value_symbol(ELFOBJ *bin, Elf_(Sym) * symbol, size_t pos) {
	if (symbol->st_value) {
		return symbol->st_value;
	}

	ut64 tmp = Elf_(rz_bin_elf_get_import_addr)(bin, pos);
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
	elf_symbol->bind = Elf_(rz_bin_elf_symbol_bind_to_str)(symbol);
	elf_symbol->type = Elf_(rz_bin_elf_symbol_type_to_str)(bin, elf_symbol, symbol);
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

RZ_IPI RZ_OWN RzVector *Elf_(rz_bin_elf_compute_symbols_from_segment)(RZ_NONNULL ELFOBJ *bin, int type, ut64 offset, size_t num, ut64 entry_size) {
	rz_return_val_if_fail(bin && entry_size, NULL);

	RzVector *result = rz_vector_new(sizeof(RzBinElfSymbol), NULL, NULL);

	offset += entry_size;

	for (size_t i = 1; i < num; i++) {
		Elf_(Sym) symbol = Elf_(rz_bin_elf_get_symbol_entry)(bin, offset);
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
