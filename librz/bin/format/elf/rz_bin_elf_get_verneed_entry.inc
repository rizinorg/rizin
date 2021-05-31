// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI Elf_(Verneed) Elf_(rz_bin_elf_get_verneed_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset) {
	Elf_(Verneed) verneed_entry = { 0 };

	rz_return_val_if_fail(bin, verneed_entry);

	verneed_entry.vn_version = BREAD16(bin->b, offset);
	verneed_entry.vn_cnt = BREAD16(bin->b, offset);
	verneed_entry.vn_file = BREAD32(bin->b, offset);
	verneed_entry.vn_aux = BREAD32(bin->b, offset);
	verneed_entry.vn_next = BREAD32(bin->b, offset);

	return verneed_entry;
}
