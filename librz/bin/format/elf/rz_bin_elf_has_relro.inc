// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

int Elf_(rz_bin_elf_has_relro)(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, RZ_BIN_ELF_NO_RELRO);

	bool haveBindNow = false;
	bool haveGnuRelro = false;

	if (bin->dyn_info.dt_bind_now) {
		haveBindNow = true;
	} else if (bin->dyn_info.dt_flags != RZ_BIN_ELF_XWORD_MAX && bin->dyn_info.dt_flags != RZ_BIN_ELF_XWORD_MAX) {
		haveBindNow = bin->dyn_info.dt_flags_1 & DF_1_NOW;
	}

	if (bin->phdr) {
		size_t i;
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_GNU_RELRO) {
				haveGnuRelro = true;
				break;
			}
		}
	}
	if (haveGnuRelro) {
		if (haveBindNow) {
			return RZ_BIN_ELF_FULL_RELRO;
		}
		return RZ_BIN_ELF_PART_RELRO;
	}
	return RZ_BIN_ELF_NO_RELRO;
}
