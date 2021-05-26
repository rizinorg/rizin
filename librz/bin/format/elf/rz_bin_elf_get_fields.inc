// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static size_t add_fields(RzBinElfField *fields, size_t pos, const char *name, Elf_(Off) offset) {
	rz_str_ncpy(fields[pos].name, name, ELF_STRING_LENGTH);
	fields[pos].offset = offset;
	fields[pos].last = 0;

	return pos + 1;
}

static size_t add_basic_fields(ELFOBJ *bin, RzBinElfField *fields) {
	size_t i = 0;

	i = add_fields(fields, i, "ehdr", 0);
	i = add_fields(fields, i, "shoff", bin->ehdr.e_shoff);
	i = add_fields(fields, i, "phoff", bin->ehdr.e_phoff);

	return i;
}

/**
 * \brief Return the list of elf fields
 * \param elf binary
 * \return a ptr to an array terminated with an item with .last set to 1
 *
 * Generate the elf fields from phdr
 */
RZ_OWN RzBinElfField *Elf_(rz_bin_elf_get_fields)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfField *ret = RZ_NEWS(RzBinElfField, bin->ehdr.e_phnum + 3 + 1);
	if (!ret) {
		return NULL;
	}

	size_t i = add_basic_fields(bin, ret);

	for (size_t j = 0; bin->phdr && j < bin->ehdr.e_phnum; i++, j++) {
		snprintf(ret[i].name, ELF_STRING_LENGTH, "phdr_%zu", j);
		ret[i].offset = bin->phdr[j].p_offset;
		ret[i].last = 0;
	}

	ret[i].last = 1;
	return ret;
}
