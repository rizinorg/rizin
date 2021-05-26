// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Convert a RzBinElfSymbol to RzBinImport
 * \param elf binary
 * \param bin symbol
 * \return a ptr to a new allocated RzBinImport
 *
 * ...
 */
RZ_OWN RzBinImport *Elf_(rz_bin_elf_convert_import)(RZ_UNUSED ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol) {
	rz_return_val_if_fail(symbol, NULL);

	RzBinImport *ptr = RZ_NEW0(RzBinImport);
	if (!ptr) {
		return NULL;
	}

	ptr->name = strdup(symbol->name);
	ptr->bind = symbol->bind;
	ptr->type = symbol->type;
	ptr->ordinal = symbol->ordinal;

	return ptr;
}
