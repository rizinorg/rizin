// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static Sdb *set_vernaux_entry_sdb(ELFOBJ *bin, Elf_(Vernaux) *vernaux_entry, size_t index) {
	if (vernaux_entry->vna_name > bin->dynstr_size) {
		return NULL;
	}

	Sdb *sdb_vernaux = sdb_new0();
	if (!sdb_vernaux) {
		return NULL;
	}

	char *flags = Elf_(rz_bin_elf_get_ver_flags)(vernaux_entry->vna_flags);
	sdb_set(sdb_vernaux, "flags", flags, 0);
	free(flags);

	sdb_num_set(sdb_vernaux, "idx", index, 0);
	sdb_num_set(sdb_vernaux, "version", vernaux_entry->vna_other, 0);
	sdb_set(sdb_vernaux, "name", bin->dynstr + vernaux_entry->vna_name, 0);

	return sdb_vernaux;
}

static Sdb *set_vernaux_entry(ELFOBJ *bin, Elf_(Vernaux) *vernaux_entry, size_t offset) {
	size_t pos = offset;

	vernaux_entry->vna_hash = BREAD32(bin->b, pos);
	vernaux_entry->vna_flags = BREAD16(bin->b, pos);
	vernaux_entry->vna_other = BREAD16(bin->b, pos);
	vernaux_entry->vna_name = BREAD32(bin->b, pos);
	vernaux_entry->vna_next = BREAD32(bin->b, pos);

	return set_vernaux_entry_sdb(bin, vernaux_entry, offset);
}

static Sdb *set_verneed_entry_sdb(ELFOBJ *bin, Elf_(Verneed) *verneed_entry, size_t index) {
	if (verneed_entry->vn_file > bin->dynstr_size) {
		return NULL;
	}

	Sdb *sdb_version = sdb_new0();
	if (!sdb_version) {
		return NULL;
	}

	sdb_num_set(sdb_version, "cnt", verneed_entry->vn_cnt, 0);
	sdb_num_set(sdb_version, "idx", index, 0);
	sdb_num_set(sdb_version, "vn_version", verneed_entry->vn_version, 0);
	sdb_set(sdb_version, "file_name", bin->dynstr + verneed_entry->vn_file, 0);

	return sdb_version;
}

static Sdb *set_verneed_entry(ELFOBJ *bin, Elf_(Verneed) *verneed_entry, size_t offset) {
	size_t pos = offset;

	verneed_entry->vn_version = BREAD16(bin->b, pos);
	verneed_entry->vn_cnt = BREAD16(bin->b, pos);
	verneed_entry->vn_file = BREAD32(bin->b, pos);
	verneed_entry->vn_aux = BREAD32(bin->b, pos);
	verneed_entry->vn_next = BREAD32(bin->b, pos);

	Sdb *sdb_version = set_verneed_entry_sdb(bin, verneed_entry, offset);
	if (!sdb_version) {
		return NULL;
	}

	ut64 vernaux_entry_offset = offset + verneed_entry->vn_aux;

	for (size_t i = 0; i < verneed_entry->vn_cnt; i++) {
		Elf_(Vernaux) vernaux_entry = { 0 };

		Sdb *sdb_vernaux = set_vernaux_entry(bin, &vernaux_entry, vernaux_entry_offset);
		if (!sdb_vernaux) {
			sdb_free(sdb_version);
			return NULL;
		}

		sdb_ns_set(sdb_version, sdb_fmt("vernaux%zu", i), sdb_vernaux);
		sdb_free(sdb_vernaux);

		vernaux_entry_offset += vernaux_entry.vna_next;
	}

	return sdb_version;
}

RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info_gnu_verneed)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	ut64 verneed_addr = bin->version_info[DT_VERSIONTAGIDX(DT_VERNEED)];
	ut64 verneed_num = bin->version_info[DT_VERSIONTAGIDX(DT_VERNEEDNUM)];

	if (!verneed_addr || !verneed_num) {
		return NULL;
	}

	ut64 verneed_offset = Elf_(rz_bin_elf_v2p_new(bin, verneed_addr));

	if (verneed_offset == UT64_MAX) {
		return NULL;
	}

	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}

	sdb_num_set(sdb, "num_entries", verneed_num, 0);
	sdb_num_set(sdb, "addr", verneed_addr, 0);
	sdb_num_set(sdb, "offset", verneed_offset, 0);

	for (size_t i = 0; i < verneed_num; i++) {
		Elf_(Verneed) verneed_entry = { 0 };

		Sdb *sdb_version = set_verneed_entry(bin, &verneed_entry, verneed_offset);
		if (!sdb_version) {
			sdb_free(sdb);
			return NULL;
		}

		sdb_ns_set(sdb, sdb_fmt("version%zu", i), sdb_version);
		sdb_free(sdb_version);

		verneed_offset += verneed_entry.vn_next;
	}

	return sdb;
}
