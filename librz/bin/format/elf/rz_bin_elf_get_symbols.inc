// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->g_symbols) {
		bin->g_symbols = Elf_(rz_bin_elf_get_symbols_with_type)(bin, RZ_BIN_ELF_ALL_SYMBOLS);
	}

	return bin->g_symbols;
}
