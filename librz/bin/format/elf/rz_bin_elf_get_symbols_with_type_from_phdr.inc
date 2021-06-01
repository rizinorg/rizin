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

static bool add_elf_symbol_entry(ELFOBJ *bin, Elf_(Sym) * symbol, size_t pos, int type, RzVector *result) {
	bool is_sht_null = false;
	bool is_vaddr = false;

	ut64 value = 0;
	ut64 offset = 0;
	ut32 size = 0;

	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && symbol->st_shndx == SHT_NULL) {
		value = get_value_symbol(bin, symbol, pos);
		size = 16;
	} else if (type == RZ_BIN_ELF_ALL_SYMBOLS) {
		value = symbol->st_value;
		size = symbol->st_size;
		is_sht_null = symbol->st_shndx == SHT_NULL;
	} else {
		return false;
	}

	RzBinElfSymbol *elf_symbol = rz_vector_push(result, NULL);
	if (!elf_symbol) {
		return false;
	}

	if (Elf_(rz_bin_elf_is_relocatable)(bin) && symbol->st_shndx < bin->ehdr.e_shnum) {
		offset = symbol->st_value + bin->shdr[symbol->st_shndx].sh_offset;
	} else {
		offset = Elf_(rz_bin_elf_v2p_new)(bin, value);
		if (offset == UT64_MAX) {
			offset = value;
			is_vaddr = true;
		}
	}

	elf_symbol->bind = Elf_(rz_bin_elf_symbol_bind_to_str)(symbol);
	elf_symbol->in_shdr = false;
	elf_symbol->is_sht_null = is_sht_null;
	elf_symbol->is_vaddr = is_vaddr;
	elf_symbol->last = 0;
	elf_symbol->offset = offset;
	elf_symbol->ordinal = pos;
	elf_symbol->size = size;
	elf_symbol->type = Elf_(rz_bin_elf_symbol_type_to_str)(bin, elf_symbol, symbol);

	if (symbol->st_name > bin->strtab_size) {
		symbol->st_name = '\0';
	} else if (bin->strtab) {
		rz_str_ncpy(elf_symbol->name, bin->strtab + symbol->st_name, ELF_STRING_LENGTH);
	}

	return true;
}

static void set_by_ord(ELFOBJ *bin, RzBinElfSymbol *symbols, size_t pos, int type) {
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && !bin->imports_by_ord_size) {
		bin->imports_by_ord_size = pos + 1;

		if (!pos) {
			bin->imports_by_ord = NULL;
			return;
		}

		bin->imports_by_ord = RZ_NEWS0(RzBinImport *, pos + 1);

		for (size_t i = 0; i < pos; i++) {
			Elf_(rz_bin_elf_set_import_by_ord)(bin, symbols + i);
		}
	} else if (type == RZ_BIN_ELF_ALL_SYMBOLS && !bin->symbols_by_ord_size && pos) {
		bin->symbols_by_ord_size = pos + 1;

		if (pos > 0) {
			bin->symbols_by_ord = RZ_NEWS0(RzBinSymbol *, pos + 1);
		} else {
			bin->symbols_by_ord = NULL;
		}
	}
}

RZ_IPI RZ_OWN RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols_with_type_from_phdr)(RZ_NONNULL ELFOBJ *bin, int type) {
	rz_return_val_if_fail(bin, NULL);

	if (bin->dyn_info.dt_symtab == RZ_BIN_ELF_ADDR_MAX || !bin->dyn_info.dt_syment) {
		return NULL;
	}

	ut64 dynsym_offset = Elf_(rz_bin_elf_v2p)(bin, bin->dyn_info.dt_symtab);

	if (dynsym_offset == UT64_MAX) {
		return NULL;
	}

	size_t number_of_symbols = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!number_of_symbols) {
		return NULL;
	}

	RzVector *tmp = rz_vector_new(sizeof(RzBinElfSymbol), NULL, NULL);

	size_t pos = 0;
	dynsym_offset += bin->dyn_info.dt_syment;

	for (size_t i = 1; i < number_of_symbols; i++) {
		Elf_(Sym) symbol = Elf_(rz_bin_elf_get_symbol_entry)(bin, dynsym_offset);
		if (add_elf_symbol_entry(bin, &symbol, i, type, tmp)) {
			pos++;
		}

		dynsym_offset += bin->dyn_info.dt_syment;
	}

	RzBinElfSymbol *end = rz_vector_push(tmp, NULL);
	end->last = 1;

	RzBinElfSymbol *result = rz_vector_flush(tmp);
	rz_vector_free(tmp);

	set_by_ord(bin, result, pos, type);

	return result;
}
