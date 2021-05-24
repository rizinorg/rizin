// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

char *Elf_(rz_bin_elf_intrp)(ELFOBJ *bin) {
	int i;
	if (!bin || !bin->phdr) {
		return NULL;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP) {
			ut64 addr = bin->phdr[i].p_offset;
			int sz = bin->phdr[i].p_filesz;
			sdb_num_set(bin->kv, "elf_header.intrp_addr", addr, 0);
			sdb_num_set(bin->kv, "elf_header.intrp_size", sz, 0);
			if (sz < 1 || sz > rz_buf_size(bin->b)) {
				return NULL;
			}
			char *str = malloc(sz + 1);
			if (!str) {
				return NULL;
			}
			if (rz_buf_read_at(bin->b, addr, (ut8 *)str, sz) < 1) {
				bprintf("read (main)\n");
				free(str);
				return 0;
			}
			str[sz] = 0;
			sdb_set(bin->kv, "elf_header.intrp", str, 0);
			return str;
		}
	}
	return NULL;
}
