// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void init_strtab_sdb(ELFOBJ *bin, ut64 strtab_addr, Elf_(Xword) strtab_size) {
	sdb_num_set(bin->kv, "elf_strtab.offset", strtab_addr, 0);
	sdb_num_set(bin->kv, "elf_strtab.size", strtab_size, 0);
}

static bool read_strtab(ELFOBJ *bin, ut64 strtab_addr, Elf_(Xword) strtab_size) {
	bin->strtab_size = strtab_size;
	bin->strtab = RZ_NEWS0(char, strtab_size + 1);
	if (!bin->strtab) {
		return false;
	}

	if (rz_buf_read_at(bin->b, strtab_addr, (ut8 *)bin->strtab, strtab_size) < 0) {
		free(bin->strtab);
		return false;
	}

	return true;
}

RZ_IPI bool Elf_(rz_bin_elf_init_strtab)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (bin->dyn_info.dt_strtab == RZ_BIN_ELF_ADDR_MAX || !bin->dyn_info.dt_strsz) {
		bprintf("DT_STRTAB not found or invalid\n");
		return false;
	}

	ut64 strtab_addr = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_strtab);
	Elf_(Xword) strtab_size = bin->dyn_info.dt_strsz;

	init_strtab_sdb(bin, strtab_addr, strtab_size);

	if (strtab_addr + strtab_size > bin->size) {
		return false;
	}

	return read_strtab(bin, strtab_addr, strtab_size);
}
