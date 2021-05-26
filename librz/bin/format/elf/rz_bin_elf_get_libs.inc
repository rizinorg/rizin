// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief List all imported lib
 * \param elf binary
 * \return a an allocated array of RzBinElfLib
 *
 * Use dynamic information (dt_needed) to generate the list of imported lib
 */
RZ_OWN RzBinElfLib *Elf_(rz_bin_elf_get_libs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfLib *ret = NULL;
	Elf_(Off) *it = NULL;
	size_t k = 0;

	if (!bin || !bin->phdr || !bin->strtab || *(bin->strtab + 1) == '0') {
		return NULL;
	}

	rz_vector_foreach(&bin->dyn_info.dt_needed, it) {
		Elf_(Off) val = *it;

		RzBinElfLib *r = realloc(ret, (k + 1) * sizeof(RzBinElfLib));
		if (!r) {
			perror("realloc (libs)");
			free(ret);
			return NULL;
		}
		ret = r;
		if (val > bin->strtab_size) {
			free(ret);
			return NULL;
		}
		strncpy(ret[k].name, bin->strtab + val, ELF_STRING_LENGTH - 1);
		ret[k].name[ELF_STRING_LENGTH - 1] = '\0';
		ret[k].last = 0;
		if (ret[k].name[0]) {
			k++;
		}
	}

	RzBinElfLib *r = realloc(ret, (k + 1) * sizeof(RzBinElfLib));
	if (!r) {
		perror("realloc (libs)");
		free(ret);
		return NULL;
	}
	ret = r;
	ret[k].last = 1;
	return ret;
}
