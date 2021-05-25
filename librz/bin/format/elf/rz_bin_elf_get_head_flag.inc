// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return the head flag
 * \return allocated string
 *
 * ...
 */
RZ_OWN char *Elf_(rz_bin_elf_get_head_flag)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *head_flag = NULL;
	char *str = Elf_(rz_bin_elf_get_cpu)(bin);
	if (str) {
		head_flag = rz_str_append(head_flag, str);
		free(str);
	}
	str = Elf_(rz_bin_elf_get_abi)(bin);
	if (str) {
		head_flag = rz_str_appendf(head_flag, " %s", str);
		free(str);
	}
	if (RZ_STR_ISEMPTY(head_flag)) {
		head_flag = rz_str_append(head_flag, "unknown_flag");
	}
	return head_flag;
}
