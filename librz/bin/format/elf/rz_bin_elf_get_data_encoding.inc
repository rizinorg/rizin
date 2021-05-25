// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

char *Elf_(rz_bin_elf_get_data_encoding)(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_DATA]) {
	case ELFDATANONE: return strdup("none");
	case ELFDATA2LSB: return strdup("2's complement, little endian");
	case ELFDATA2MSB: return strdup("2's complement, big endian");
	default: return rz_str_newf("<unknown: %x>", bin->ehdr.e_ident[EI_DATA]);
	}
}

