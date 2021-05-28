// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void init_shstrtab_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_shstrtab.offset", bin->shstrtab_section->sh_offset, 0);
	sdb_num_set(bin->kv, "elf_shstrtab.size", bin->shstrtab_section->sh_size, 0);
}

static bool check_shstrtab(ELFOBJ *bin) {
	return bin->shstrtab_section->sh_offset + bin->shstrtab_section->sh_size < bin->size;
}

static bool check_shstrtab_index(ELFOBJ *bin, Elf_(Half) shstrtab_index) {
	return shstrtab_index != SHN_UNDEF && Elf_(rz_bin_elf_is_sh_index_valid)(bin, shstrtab_index);
}

static bool set_shstrtab(ELFOBJ *bin) {
	bin->shstrtab = calloc(1, bin->shstrtab_size + 1);
	if (!bin->shstrtab) {
		perror("malloc");
		return false;
	}

	int res = rz_buf_read_at(bin->b, bin->shstrtab_section->sh_offset, (ut8 *)bin->shstrtab, bin->shstrtab_section->sh_size);
	if (res < 0) {
		bprintf("read (shstrtab) at 0x%" PFMT64x "\n", (ut64)bin->shstrtab_section->sh_offset);
		RZ_FREE(bin->shstrtab);
		return false;
	}

	bin->shstrtab[bin->shstrtab_section->sh_size] = '\0';

	return true;
}

RZ_IPI bool Elf_(rz_bin_elf_init_shstrtab)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->shdr) {
		return false;
	}

	Elf_(Half) shstrtab_index = bin->ehdr.e_shstrndx;
	if (!check_shstrtab_index(bin, shstrtab_index) || !bin->shdr[shstrtab_index].sh_size) {
		return false;
	}

	bin->shstrtab_section = bin->strtab_section = bin->shdr + shstrtab_index;
	bin->shstrtab_size = bin->shstrtab_section->sh_size;

	init_shstrtab_sdb(bin);

	if (!check_shstrtab(bin)) {
		return false;
	}

	if (!set_shstrtab(bin)) {
		return true;
	}

	return true;
}
