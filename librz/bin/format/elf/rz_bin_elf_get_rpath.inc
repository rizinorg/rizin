// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static Elf_(Xword) get_dt_rpath(ELFOBJ *bin) {
	if (bin->dyn_info.dt_rpath != RZ_BIN_ELF_XWORD_MAX) {
		return bin->dyn_info.dt_rpath;
	} else {
		return bin->dyn_info.dt_runpath;
	}
}

static bool has_dt_rpath_entry(ELFOBJ *bin) {
	return bin->dyn_info.dt_rpath == RZ_BIN_ELF_XWORD_MAX || bin->dyn_info.dt_runpath == RZ_BIN_ELF_XWORD_MAX;
}

/**
 * \brief Get the rpath
 * \param elf binary
 * \return allocated string
 *
 * Use DT_RPATH or DT_RUNPATH to return the string
 */
RZ_OWN char *Elf_(rz_bin_elf_get_rpath)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->phdr || !bin->strtab || !has_dt_rpath_entry(bin)) {
		return NULL;
	}

	Elf_(Xword) val = get_dt_rpath(bin);
	if (val > bin->strtab_size) {
		return NULL;
	}

	return rz_str_ndup(bin->strtab + val, ELF_STRING_LENGTH);
}
