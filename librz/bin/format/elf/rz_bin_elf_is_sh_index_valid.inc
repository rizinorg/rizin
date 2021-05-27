// SPDX-FileCopyrightText: 2009 Nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI bool Elf_(rz_bin_elf_is_sh_index_valid)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index) {
	rz_return_val_if_fail(bin, false);

	return index < bin->ehdr.e_shnum && !RZ_BETWEEN(SHN_LORESERVE, index, SHN_HIRESERVE);
}
