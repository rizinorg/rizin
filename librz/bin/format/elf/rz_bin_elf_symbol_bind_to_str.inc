// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct symbol_bind_translation {
	unsigned char bind;
	const char *name;
};

static struct symbol_bind_translation symbol_bind_translation_table[] = {
	{ STB_LOCAL, RZ_BIN_BIND_LOCAL_STR },
	{ STB_GLOBAL, RZ_BIN_BIND_GLOBAL_STR },
	{ STB_WEAK, RZ_BIN_BIND_WEAK_STR },
	{ STB_NUM, RZ_BIN_BIND_NUM_STR },
	{ STB_LOOS, RZ_BIN_BIND_LOOS_STR },
	{ STB_HIOS, RZ_BIN_BIND_HIOS_STR },
	{ STB_LOPROC, RZ_BIN_BIND_LOPROC_STR },
	{ STB_HIPROC, RZ_BIN_BIND_HIPROC_STR }
};

RZ_IPI RZ_BORROW const char *Elf_(rz_bin_elf_symbol_bind_to_str)(RZ_NONNULL Elf_(Sym) * sym) {
	rz_return_val_if_fail(sym, NULL);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(symbol_bind_translation_table); i++) {
		if (ELF_ST_BIND(sym->st_info) == symbol_bind_translation_table[i].bind) {
			return symbol_bind_translation_table[i].name;
		}
	}

	return RZ_BIN_BIND_UNKNOWN_STR;
}
