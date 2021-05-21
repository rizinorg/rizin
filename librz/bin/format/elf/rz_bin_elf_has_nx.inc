// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Check if the stack is not executable
 * \param elf binary
 * \return true, false
 *
 * Check p_flags from the segment PT_GNU_STACK
 */
bool Elf_(rz_bin_elf_has_nx)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->phdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_GNU_STACK) {
			return !(bin->phdr[i].p_flags & PF_X);
		}
	}

	return false;
}
