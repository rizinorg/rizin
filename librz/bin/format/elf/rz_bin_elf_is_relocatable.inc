// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Check if the elf binary is relocatable
 * \param elf binary
 * \return is_relocatable ?
 *
 * Use the elf header entry e_type to deduct if the elf is relocatable.
 */
bool Elf_(rz_bin_elf_is_relocatable)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->ehdr.e_type == ET_REL;
}
