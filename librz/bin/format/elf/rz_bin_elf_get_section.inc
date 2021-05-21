// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RzBinElfSection *Elf_(rz_bin_elf_get_section)(ELFOBJ *bin, const char *section_name) {
	if (bin->g_sections) {
		size_t i;
		for (i = 0; !bin->g_sections[i].last; i++) {
			if (!strncmp(bin->g_sections[i].name, section_name, ELF_STRING_LENGTH - 1)) {
				return &bin->g_sections[i];
			}
		}
	}
	return NULL;
}
