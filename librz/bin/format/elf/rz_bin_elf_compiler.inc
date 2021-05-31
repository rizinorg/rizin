// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

char *Elf_(rz_bin_elf_compiler)(ELFOBJ *bin) {
	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, ".comment");
	if (!section) {
		return NULL;
	}
	ut64 off = section->offset;
	ut32 sz = RZ_MIN(section->size, 128);
	if (sz < 1) {
		return NULL;
	}
	char *buf = malloc(sz + 1);
	if (!buf) {
		return NULL;
	}
	if (rz_buf_read_at(bin->b, off, (ut8 *)buf, sz) < 1) {
		free(buf);
		return NULL;
	}
	buf[sz] = 0;
	const size_t buflen = strlen(buf);
	char *nullbyte = buf + buflen;
	if (buflen != sz && nullbyte[1] && buflen < sz) {
		nullbyte[0] = ' ';
	}
	buf[sz] = 0;
	rz_str_trim(buf);
	char *res = rz_str_escape(buf);
	free(buf);
	return res;
}
