// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

ut64 Elf_(rz_bin_elf_get_section_offset)(ELFOBJ *bin, const char *section_name) {
	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, section_name);
	return section ? section->offset : UT64_MAX;
}
