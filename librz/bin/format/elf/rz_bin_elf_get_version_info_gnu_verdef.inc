// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static Sdb *set_verdaux_entry_sdb(ELFOBJ *bin, Elf_(Verdaux) *verdaux_entry, size_t index) {
	if (verdaux_entry->vda_name > bin->dynstr_size) {
		return NULL;
	}

	Sdb *sdb_verdaux = sdb_new0();
	if (!sdb_verdaux) {
		return NULL;
	}

	sdb_num_set(sdb_verdaux, "idx", index, 0);
	sdb_set(sdb_verdaux, "vda_name", bin->dynstr + verdaux_entry->vda_name, 0);

	return sdb_verdaux;
}

static Sdb *set_verdaux_entry(ELFOBJ *bin, Elf_(Verdaux) *verdaux_entry, size_t offset) {
	size_t pos = offset;

	verdaux_entry->vda_name = BREAD32(bin->b, pos);
	verdaux_entry->vda_next = BREAD32(bin->b, pos);

	return set_verdaux_entry_sdb(bin, verdaux_entry, offset);
}

static Sdb *set_verdef_entry_sdb(ELFOBJ *bin, Elf_(Verdef) *verdef_entry, size_t index) {
	Sdb *sdb_verdef = sdb_new0();
	if (!sdb_verdef) {
		return NULL;
	}

	sdb_num_set(sdb_verdef, "idx", index, 0);
	sdb_num_set(sdb_verdef, "vd_cnt", verdef_entry->vd_cnt, 0);
	sdb_num_set(sdb_verdef, "vd_ndx", verdef_entry->vd_ndx, 0);
	sdb_num_set(sdb_verdef, "vd_version", verdef_entry->vd_version, 0);
	char *flags = Elf_(rz_bin_elf_get_ver_flags)(verdef_entry->vd_flags);
	sdb_set(sdb_verdef, "flags", flags, 0);
	free(flags);

	return sdb_verdef;
}

static Sdb *set_verdef_entry(ELFOBJ *bin, Elf_(Verdef) *verdef_entry, size_t offset) {
	size_t pos = offset;

	verdef_entry->vd_version = BREAD16(bin->b, pos);
	verdef_entry->vd_flags = BREAD16(bin->b, pos);
	verdef_entry->vd_ndx = BREAD16(bin->b, pos);
	verdef_entry->vd_cnt = BREAD16(bin->b, pos);
	verdef_entry->vd_hash = BREAD32(bin->b, pos);
	verdef_entry->vd_aux = BREAD32(bin->b, pos);
	verdef_entry->vd_next = BREAD32(bin->b, pos);

	Sdb *sdb_verdef = set_verdef_entry_sdb(bin, verdef_entry, offset);
	if (!sdb_verdef) {
		return NULL;
	}

	ut64 verdaux_entry_offset = offset + verdef_entry->vd_aux;

	for (size_t j = 0; j < verdef_entry->vd_cnt; j++) {
		Elf_(Verdaux) verdaux_entry = { 0 };

		Sdb *sdb_verdaux = set_verdaux_entry(bin, &verdaux_entry, verdaux_entry_offset);
		if (!sdb_verdaux) {
			sdb_free(sdb_verdef);
			return NULL;
		}

		sdb_ns_set(sdb_verdef, sdb_fmt("verdaux%zu", j), sdb_verdaux);
		sdb_free(sdb_verdaux);

		verdaux_entry_offset += verdaux_entry.vda_next;
	}

	return sdb_verdef;
}

RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info_gnu_verdef)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	ut64 verdef_addr = bin->version_info[DT_VERSIONTAGIDX(DT_VERDEF)];
	ut64 verdef_num = bin->version_info[DT_VERSIONTAGIDX(DT_VERDEFNUM)];

	if (!verdef_addr || !verdef_num) {
		return NULL;
	}

	ut64 verdef_offset = Elf_(rz_bin_elf_v2p_new(bin, verdef_addr));

	if (verdef_offset == UT64_MAX) {
		return NULL;
	}

	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}

	sdb_num_set(sdb, "entries", verdef_num, 0);
	sdb_num_set(sdb, "addr", verdef_addr, 0);
	sdb_num_set(sdb, "offset", verdef_offset, 0);

	for (size_t i = 0; i < verdef_num; i++) {
		Elf_(Verdef) verdef_entry = { 0 };

		Sdb *sdb_verdef = set_verdef_entry(bin, &verdef_entry, verdef_offset);
		if (!sdb_verdef) {
			sdb_free(sdb);
			return NULL;
		}

		sdb_ns_set(sdb, sdb_fmt("verdef%zu", i), sdb_verdef);
		sdb_free(sdb_verdef);

		verdef_offset += verdef_entry.vd_next;
	}

	return sdb;
}
