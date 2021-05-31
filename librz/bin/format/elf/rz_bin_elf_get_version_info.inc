// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	Sdb *res = sdb_new0();
	if (!res) {
		return NULL;
	}

	Sdb *sdb = Elf_(rz_bin_elf_get_version_info_gnu_verneed)(bin);
	sdb_ns_set(res, "verneed", sdb);
	sdb_free(sdb);

	sdb = Elf_(rz_bin_elf_get_version_info_gnu_verdef)(bin);
	sdb_ns_set(res, "verdef", sdb);
	sdb_free(sdb);

	sdb = Elf_(rz_bin_elf_get_version_info_gnu_versym)(bin);
	sdb_ns_set(res, "versym", sdb);
	sdb_free(sdb);

	return res;
}
