// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct ver_flags_translation {
	ut32 flag;
	const char *name;
};

static const struct ver_flags_translation ver_flags_translation_table[] = {
	{ VER_FLG_BASE, "BASE " },
	{ VER_FLG_BASE | VER_FLG_WEAK, "| " },
	{ VER_FLG_WEAK, "WEAK " },
	{ ~(VER_FLG_BASE | VER_FLG_WEAK), "| <unknown>" }
};

RZ_IPI RZ_OWN char *Elf_(rz_bin_elf_get_ver_flags)(ut32 flags) {
	char *result = NULL;

	if (!flags) {
		return strdup("none");
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(ver_flags_translation_table); i++) {
		if (flags & ver_flags_translation_table[i].flag) {
			result = rz_str_append(result, ver_flags_translation_table[i].name);
		}
	}

	return result;
}
