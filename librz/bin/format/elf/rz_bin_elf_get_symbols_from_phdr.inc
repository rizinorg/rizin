// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static RzBinElfSymbol *get_phdr_symbols(ELFOBJ *bin) {
	if (bin->phdr_symbols) {
		return bin->phdr_symbols;
	}

	bin->phdr_symbols = Elf_(rz_bin_elf_compute_symbols_from_phdr)(bin, RZ_BIN_ELF_ALL_SYMBOLS);

	return bin->phdr_symbols;
}

static RzBinElfSymbol *get_phdr_imports(ELFOBJ *bin) {
	if (bin->phdr_imports) {
		return bin->phdr_imports;
	}

	bin->phdr_imports = Elf_(rz_bin_elf_compute_symbols_from_phdr)(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);

	return bin->phdr_imports;
}

RZ_IPI RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols_from_phdr)(RZ_NONNULL ELFOBJ *bin, int type) {
	rz_return_val_if_fail(bin, NULL);

	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS) {
		return get_phdr_imports(bin);
	}

	return get_phdr_symbols(bin);
}
