// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define X86      0
#define X86_64   1
#define ARM      2
#define AARCH64  3
#define ARCH_LEN 4

static RzBinElfPrStatusLayout prstatus_layouts[ARCH_LEN] = {
	[X86] = { 160, 0x48, 32, 0x3c },
	[X86_64] = { 216, 0x70, 64, 0x98 },
	[ARM] = { 72, 0x48, 32, 0x34 },
	[AARCH64] = { 272, 0x70, 64, 0xf8 }
};

RZ_IPI RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_prstatus_layout)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	switch (bin->ehdr.e_machine) {
	case EM_AARCH64:
		return prstatus_layouts + AARCH64;
	case EM_ARM:
		return prstatus_layouts + ARM;
	case EM_386:
		return prstatus_layouts + X86;
	case EM_X86_64:
		return prstatus_layouts + X86_64;
	}

	return NULL;
}
