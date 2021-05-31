// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI Elf_(Vernaux) Elf_(rz_bin_elf_get_vernaux_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset) {
	Elf_(Vernaux) vernaux_entry = { 0 };

	rz_return_val_if_fail(bin, vernaux_entry);

	vernaux_entry.vna_hash = BREAD32(bin->b, offset);
	vernaux_entry.vna_flags = BREAD16(bin->b, offset);
	vernaux_entry.vna_other = BREAD16(bin->b, offset);
	vernaux_entry.vna_name = BREAD32(bin->b, offset);
	vernaux_entry.vna_next = BREAD32(bin->b, offset);

	return vernaux_entry;
}
