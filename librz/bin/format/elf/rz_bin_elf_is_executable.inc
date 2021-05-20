// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

bool Elf_(rz_bin_elf_is_executable)(ELFOBJ *bin) {
	const Elf_(Half) type = bin->ehdr.e_type;
	return type == ET_EXEC || type == ET_DYN;
}
