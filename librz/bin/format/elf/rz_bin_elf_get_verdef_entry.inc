// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI Elf_(Verdef) Elf_(rz_bin_elf_get_verdef_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset) {
	Elf_(Verdef) verdef_entry = { 0 };

	rz_return_val_if_fail(bin, verdef_entry);

	verdef_entry.vd_version = BREAD16(bin->b, offset);
	verdef_entry.vd_flags = BREAD16(bin->b, offset);
	verdef_entry.vd_ndx = BREAD16(bin->b, offset);
	verdef_entry.vd_cnt = BREAD16(bin->b, offset);
	verdef_entry.vd_hash = BREAD32(bin->b, offset);
	verdef_entry.vd_aux = BREAD32(bin->b, offset);
	verdef_entry.vd_next = BREAD32(bin->b, offset);

	return verdef_entry;
}
