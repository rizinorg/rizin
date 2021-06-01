// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI void Elf_(rz_bin_elf_set_import_by_ord)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol) {
	rz_return_if_fail(bin && symbol);

	if (!bin->imports_by_ord) {
		return;
	}

	RzBinImport *import = Elf_(rz_bin_elf_convert_import)(bin, symbol);
	if (!import) {
		return;
	}

	if (import->ordinal >= bin->imports_by_ord_size) {
		rz_bin_import_free(import);
		return;
	}

	rz_bin_import_free(bin->imports_by_ord[import->ordinal]);
	bin->imports_by_ord[import->ordinal] = import;
}
