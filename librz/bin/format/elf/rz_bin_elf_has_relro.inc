// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool elf_is_bind_now(ELFOBJ *bin) {
	if (bin->dyn_info.dt_bind_now) {
		return true;
	}

	if (bin->dyn_info.dt_flags_1 != RZ_BIN_ELF_XWORD_MAX) {
		return bin->dyn_info.dt_flags_1 & DF_1_NOW;
	}

	return false;
}

static bool elf_has_gnu_relro(ELFOBJ *bin) {
	if (!bin->phdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_GNU_RELRO) {
			return true;
		}
	}

	return false;
}

/**
 * \brief Analyse if the elf binary has relro or partial relro
 * \param elf binary
 * \return RZ_BIN_ELF_NO_RELRO, RZ_BIN_ELF_PART_RELRO or RZ_BIN_ELF_FULL_RELRO
 *
 * Check if the elf has bind now enable and with PT_GNU_RELRO can deduct the
 * relro type
 */
int Elf_(rz_bin_elf_has_relro)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, RZ_BIN_ELF_NO_RELRO);

	bool is_bind_now = elf_is_bind_now(bin);
	bool has_gnu_relro = elf_has_gnu_relro(bin);

	if (has_gnu_relro) {
		if (is_bind_now) {
			return RZ_BIN_ELF_FULL_RELRO;
		}

		return RZ_BIN_ELF_PART_RELRO;
	}

	return RZ_BIN_ELF_NO_RELRO;
}
