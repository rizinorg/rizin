// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Compute the init offset of the binary
 * \param elf binary
 * \return the init offset
 *
 * ...
 */
ut64 Elf_(rz_bin_elf_get_init_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	ut64 entry = Elf_(rz_bin_elf_get_entry_offset)(bin);
	ut8 buf[128];
	if (!bin || entry == UT64_MAX) {
		return UT64_MAX;
	}
	if (rz_buf_read_at(bin->b, entry + 16, buf, sizeof(buf)) < 1) {
		return 0;
	}
	if (buf[0] == 0x68) { // push // x86 only
		ut64 addr;
		memmove(buf, buf + 1, 4);
		addr = (ut64)rz_read_le32(buf);
		return Elf_(rz_bin_elf_v2p)(bin, addr);
	}
	return 0;
}
