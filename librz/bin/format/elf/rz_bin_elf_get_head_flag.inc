// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static char *add_abi_info(ELFOBJ *bin, char *head_flag) {
	char *str = Elf_(rz_bin_elf_get_abi)(bin);
	if (str) {
		head_flag = rz_str_appendf(head_flag, " %s", str);
		free(str);
	}

	return head_flag;
}

static char *add_cpu_info(ELFOBJ *bin, char *head_flag) {
	char *str = Elf_(rz_bin_elf_get_cpu)(bin);
	if (str) {
		head_flag = rz_str_append_owned(head_flag, str);
	}

	return head_flag;
}

static char *get_head_flag(ELFOBJ *bin) {
	char *head_flag = NULL;

	head_flag = add_cpu_info(bin, head_flag);
	head_flag = add_abi_info(bin, head_flag);

	return head_flag;
}

/**
 * \brief Return the head flag
 * \return allocated string
 *
 * ...
 */
RZ_OWN char *Elf_(rz_bin_elf_get_head_flag)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *head_flag = get_head_flag(bin);

	if (RZ_STR_ISEMPTY(head_flag)) {
		return strdup("unknown_flag");
	}

	return head_flag;
}
