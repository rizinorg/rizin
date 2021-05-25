// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Check if the binary is statically-linked library
 * \param elf binary
 * \return is_static ?
 *
 * Check the presence of PT_INTERP or PT_DYNAMIC in the program header
 */
bool Elf_(rz_bin_elf_is_static)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->phdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP || bin->phdr[i].p_type == PT_DYNAMIC) {
			return false;
		}
	}

	return true;
}
