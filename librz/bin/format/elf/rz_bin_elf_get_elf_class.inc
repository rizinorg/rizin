// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

char *Elf_(rz_bin_elf_get_elf_class)(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return strdup("none");
	case ELFCLASS32: return strdup("ELF32");
	case ELFCLASS64: return strdup("ELF64");
	default: return rz_str_newf("<unknown: %x>", bin->ehdr.e_ident[EI_CLASS]);
	}
}
