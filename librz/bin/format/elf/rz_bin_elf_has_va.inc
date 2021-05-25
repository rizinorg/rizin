// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Check if the elf use virtual address
 * \param elf binary
 * \return always true
 *
 * Return always true
 */
bool Elf_(rz_bin_elf_has_va)(ELFOBJ *bin) {
	return true;
}
