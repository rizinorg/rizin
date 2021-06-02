// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->g_imports) {
		bin->g_imports = Elf_(rz_bin_elf_get_symbols_with_type)(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);
	}

	return bin->g_imports;
}
