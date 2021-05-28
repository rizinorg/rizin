// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool check_dynstr_size(ELFOBJ *bin, size_t shdr_entry_index) {
	return bin->shdr[shdr_entry_index].sh_offset + bin->shdr[shdr_entry_index].sh_size < bin->size;
}

static bool set_dynstr(ELFOBJ *bin, size_t shdr_entry_index) {
	Elf_(Off) offset = bin->shdr[shdr_entry_index].sh_offset;
	bin->dynstr = RZ_NEWS0(char, bin->shdr[shdr_entry_index].sh_size + 1);
	bin->dynstr_size = bin->shdr[shdr_entry_index].sh_size;

	if (!bin->dynstr) {
		bprintf("Cannot allocate memory for dynamic strings\n");
		return false;
	}

	if (!check_dynstr_size(bin, shdr_entry_index)) {
		return false;
	}

	if (rz_buf_read_at(bin->b, offset, (ut8 *)bin->dynstr, bin->dynstr_size) < 0) {
		RZ_FREE(bin->dynstr);
		bin->dynstr_size = 0;
		return false;
	}

	return true;
}

RZ_IPI bool Elf_(rz_bin_elf_init_dynstr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->shdr || !bin->shstrtab) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_name > bin->shstrtab_size) {
			return false;
		}

		const char *section_name = bin->shstrtab + bin->shdr[i].sh_name;

		if (bin->shdr[i].sh_type == SHT_STRTAB && !strcmp(section_name, ".dynstr")) {
			return set_dynstr(bin, i);
		}
	}

	return false;
}
