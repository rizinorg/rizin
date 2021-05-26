// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Check the binary endianness
 * \param elf type
 * \return is_big_endian ?
 *
 * Use the elf header (e_ident[EI_DATA]) to check the binary endianness
 */
int Elf_(rz_bin_elf_is_big_endian)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB;
}
