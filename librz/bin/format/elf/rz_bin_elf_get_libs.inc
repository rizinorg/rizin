// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static RzBinElfLib *get_libs_from_dt_dynamic(ELFOBJ *bin, RzBinElfLib *libs) {
	size_t i = 0;

	Elf_(Word) *iter = NULL;
	rz_vector_enumerate(&bin->dyn_info.dt_needed, iter, i) {
		if (*iter > bin->strtab_size) {
			free(libs);
			return NULL;
		}

		rz_str_ncpy(libs[i].name, bin->strtab + *iter, ELF_STRING_LENGTH);
		libs[i].last = 0;
	}

	libs[i].last = 1;

	return libs;
}

/**
 * \brief List all imported lib
 * \param elf binary
 * \return a an allocated array of RzBinElfLib
 *
 * Use dynamic information (dt_needed) to generate the list of imported lib
 */
RZ_OWN RzBinElfLib *Elf_(rz_bin_elf_get_libs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin || !bin->phdr || !bin->strtab || bin->strtab[1] == '\0') {
		return NULL;
	}

	RzBinElfLib *ret = RZ_NEWS(RzBinElfLib, rz_vector_len(&bin->dyn_info.dt_needed) + 1);
	if (!ret) {
		return NULL;
	}

	return get_libs_from_dt_dynamic(bin, ret);
}
