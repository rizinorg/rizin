// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Get the compiler info from the .comment section
 * \param elf binary
 * \return a ptr to an allocated string
 *
 * ...
 */
RZ_OWN char *Elf_(rz_bin_elf_compiler)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, ".comment");
	if (!section) {
		return NULL;
	}

	ut64 offset = section->offset;
	ut64 size = RZ_MIN(section->size, 128);
	if (size < 1) {
		return NULL;
	}

	char *result = malloc(size + 1);
	if (!result) {
		return NULL;
	}

	if (rz_buf_read_at(bin->b, offset, (ut8 *)result, size) < 1) {
		free(result);
		return NULL;
	}
	result[size] = 0;

	size_t result_len = strlen(result);
	char *end = result + result_len;

	if (result_len != size && end[1]) {
		end[0] = ' ';
	}

	rz_str_trim(result);
	char *res = rz_str_escape(result);

	free(result);
	return res;
}
