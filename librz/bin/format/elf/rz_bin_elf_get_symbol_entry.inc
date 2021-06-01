// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI Elf_(Sym) Elf_(rz_bin_elf_get_symbol_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset) {
	Elf_(Sym) symbol = { 0 };

	rz_return_val_if_fail(bin, symbol);

#if RZ_BIN_ELF64
	symbol.st_name = BREAD32(bin->b, offset);
	symbol.st_info = BREAD8(bin->b, offset);
	symbol.st_other = BREAD8(bin->b, offset);
	symbol.st_shndx = BREAD16(bin->b, offset);
	symbol.st_value = BREAD64(bin->b, offset);
	symbol.st_size = BREAD64(bin->b, offset);
#else
	symbol.st_name = BREAD32(bin->b, offset);
	symbol.st_value = BREAD32(bin->b, offset);
	symbol.st_size = BREAD32(bin->b, offset);
	symbol.st_info = BREAD8(bin->b, offset);
	symbol.st_other = BREAD8(bin->b, offset);
	symbol.st_shndx = BREAD16(bin->b, offset);
#endif

	return symbol;
}
