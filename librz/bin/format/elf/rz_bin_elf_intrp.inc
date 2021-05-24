// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static char *read_elf_intrp(ELFOBJ *bin, ut64 addr, size_t size) {
	char *str = malloc(size + 1);
	if (!str) {
		return NULL;
	}

	if (rz_buf_read_at(bin->b, addr, (ut8 *)str, size) < 0) {
		free(str);
		return NULL;
	}

	str[size] = 0;

	return str;
}

static char *get_elf_intrp(ELFOBJ *bin, size_t i) {
	ut64 addr = bin->phdr[i].p_offset;
	size_t size = bin->phdr[i].p_filesz;

	sdb_num_set(bin->kv, "elf_header.intrp_addr", addr, 0);
	sdb_num_set(bin->kv, "elf_header.intrp_size", size, 0);

	if (size < 1 || size > rz_buf_size(bin->b)) {
		return NULL;
	}

	char *str = read_elf_intrp(bin, addr, size);
	sdb_set(bin->kv, "elf_header.intrp", str, 0);

	return str;
}

/**
 * \brief Get the program interpreter
 * \param elf binary
 * \return an allocated string
 *
 * Get the program interpreter from the phdr
 */
RZ_OWN char *Elf_(rz_bin_elf_intrp)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->phdr) {
		return NULL;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP) {
			return get_elf_intrp(bin, i);
		}
	}

	return NULL;
}
