// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Check if the binary is stripped
 * \param elf binary
 * \param is_stripped ?
 * \return a ptr to a new allocated RzBinSymbol
 *
 * Use the shdr to check if the binary is stripped
 */
bool Elf_(rz_bin_elf_get_stripped)(RZ_NONNULL ELFOBJ *bin) {
	if (!bin->shdr) {
		return false;
	}
	size_t i;
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_type == SHT_SYMTAB) {
			return false;
		}
	}
	return true;
}
