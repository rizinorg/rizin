// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

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
