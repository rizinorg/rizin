// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Get the rpath
 * \param elf binary
 * \return allocated string
 *
 * Use DT_RPATH or DT_RUNPATH to return the string
 */
RZ_OWN char *Elf_(rz_bin_elf_get_rpath)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *ret;
	Elf_(Xword) val;

	if (!bin->phdr || !bin->strtab) {
		return NULL;
	}

	if (bin->dyn_info.dt_rpath != RZ_BIN_ELF_XWORD_MAX) {
		val = bin->dyn_info.dt_rpath;
	} else if (bin->dyn_info.dt_runpath != RZ_BIN_ELF_XWORD_MAX) {
		val = bin->dyn_info.dt_runpath;
	} else {
		return NULL;
	}

	if (val > bin->strtab_size) {
		return NULL;
	}

	if (!(ret = calloc(1, ELF_STRING_LENGTH))) {
		return NULL;
	}

	rz_str_ncpy(ret, bin->strtab + val, ELF_STRING_LENGTH);

	return ret;
}
