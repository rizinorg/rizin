// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI Elf_(Verdaux) Elf_(rz_bin_elf_get_verdaux_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset) {
	Elf_(Verdaux) verdaux_entry = { 0 };

	rz_return_val_if_fail(bin, verdaux_entry);

	verdaux_entry.vda_name = BREAD32(bin->b, offset);
	verdaux_entry.vda_next = BREAD32(bin->b, offset);

	return verdaux_entry;
}
