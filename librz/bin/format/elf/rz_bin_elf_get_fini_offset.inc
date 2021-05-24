// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

ut64 Elf_(rz_bin_elf_get_fini_offset)(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);
	ut64 entry = Elf_(rz_bin_elf_get_entry_offset)(bin);
	if (entry == UT64_MAX) {
		return UT64_MAX;
	}
	ut8 buf[512];
	if (rz_buf_read_at(bin->b, entry + 11, buf, sizeof(buf)) == -1) {
		return 0;
	}
	if (*buf == 0x68) { // push // x86/32 only
		memmove(buf, buf + 1, 4);
		ut64 addr = (ut64)rz_read_le32(buf);
		return Elf_(rz_bin_elf_v2p)(bin, addr);
	}
	return 0;
}
