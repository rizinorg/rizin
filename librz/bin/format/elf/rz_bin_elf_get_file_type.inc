// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

char *Elf_(rz_bin_elf_get_file_type)(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);
	ut32 e_type = (ut32)bin->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
	switch (e_type) {
	case ET_NONE: return strdup("NONE (None)");
	case ET_REL: return strdup("REL (Relocatable file)");
	case ET_EXEC: return strdup("EXEC (Executable file)");
	case ET_DYN: return strdup("DYN (Shared object file)");
	case ET_CORE: return strdup("CORE (Core file)");
	}
	if ((e_type >= ET_LOPROC) && (e_type <= ET_HIPROC)) {
		return rz_str_newf("Processor Specific: %x", e_type);
	}
	if ((e_type >= ET_LOOS) && (e_type <= ET_HIOS)) {
		return rz_str_newf("OS Specific: %x", e_type);
	}
	return rz_str_newf("<unknown>: %x", e_type);
}
