// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define VERSYM_VERSION 0x7fff

static Elf_(Verneed) get_verneed_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Verneed) verneed_entry;

	verneed_entry.vn_version = BREAD16(bin->b, offset);
	verneed_entry.vn_cnt = BREAD16(bin->b, offset);
	verneed_entry.vn_file = BREAD32(bin->b, offset);
	verneed_entry.vn_aux = BREAD32(bin->b, offset);
	verneed_entry.vn_next = BREAD32(bin->b, offset);

	return verneed_entry;
}

static Elf_(Verdef) get_verdef_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Verdef) verdef_entry;

	verdef_entry.vd_version = BREAD16(bin->b, offset);
	verdef_entry.vd_flags = BREAD16(bin->b, offset);
	verdef_entry.vd_ndx = BREAD16(bin->b, offset);
	verdef_entry.vd_cnt = BREAD16(bin->b, offset);
	verdef_entry.vd_hash = BREAD32(bin->b, offset);
	verdef_entry.vd_aux = BREAD32(bin->b, offset);
	verdef_entry.vd_next = BREAD32(bin->b, offset);

	return verdef_entry;
}

static Elf_(Vernaux) get_vernaux_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Vernaux) vernaux_entry;

	vernaux_entry.vna_hash = BREAD32(bin->b, offset);
	vernaux_entry.vna_flags = BREAD16(bin->b, offset);
	vernaux_entry.vna_other = BREAD16(bin->b, offset);
	vernaux_entry.vna_name = BREAD32(bin->b, offset);
	vernaux_entry.vna_next = BREAD32(bin->b, offset);

	return vernaux_entry;
}

static Elf_(Verdaux) get_verdaux_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Verdaux) verdaux_entry;

	verdaux_entry.vda_name = BREAD32(bin->b, offset);
	verdaux_entry.vda_next = BREAD32(bin->b, offset);

	return verdaux_entry;
}

static bool set_verneed_entry_versym(ELFOBJ *bin, Sdb *sdb, const char *key, Elf_(Versym) versym) {
	ut64 verneed_addr = bin->version_info[DT_VERSIONTAGIDX(DT_VERNEED)];
	ut64 verneed_num = bin->version_info[DT_VERSIONTAGIDX(DT_VERNEEDNUM)];

	if (!verneed_addr || !verneed_num) {
		return false;
	}

	ut64 verneed_offset = Elf_(rz_bin_elf_v2p_new(bin, verneed_addr));

	if (verneed_offset == UT64_MAX) {
		return false;
	}

	ut64 verneed_entry_offset = verneed_offset;

	for (size_t i = 0; i < verneed_num; i++) {
		Elf_(Verneed) verneed_entry = get_verneed_entry(bin, verneed_entry_offset);

		ut64 vernaux_entry_offset = verneed_entry_offset + verneed_entry.vn_aux;

		for (size_t i = 0; i < verneed_entry.vn_cnt; i++) {
			Elf_(Vernaux) vernaux_entry = get_vernaux_entry(bin, vernaux_entry_offset);

			if (vernaux_entry.vna_other != versym) {
				vernaux_entry_offset += vernaux_entry.vna_next;
				continue;
			}

			if (vernaux_entry.vna_name > bin->strtab_size) {
				return false;
			}

			const char *value = sdb_fmt("%u (%s)", versym & VERSYM_VERSION, bin->strtab + vernaux_entry.vna_name);
			sdb_set(sdb, key, value, 0);
			return true;
		}

		verneed_entry_offset += verneed_entry.vn_next;
	}

	return false;
}

static bool set_verdef_entry_versym(ELFOBJ *bin, Sdb *sdb, const char *key, Elf_(Versym) versym) {
	ut64 verdef_addr = bin->version_info[DT_VERSIONTAGIDX(DT_VERDEF)];
	ut64 verdef_num = bin->version_info[DT_VERSIONTAGIDX(DT_VERDEFNUM)];

	if (!verdef_addr || !verdef_num) {
		return false;
	}

	ut64 verdef_offset = Elf_(rz_bin_elf_v2p_new(bin, verdef_addr));

	if (verdef_offset == UT64_MAX) {
		return false;
	}

	ut64 verdef_entry_offset = verdef_offset;

	for (size_t i = 0; i < verdef_num; i++) {
		Elf_(Verdef) verdef_entry = get_verdef_entry(bin, verdef_entry_offset);

		if (!verdef_entry.vd_cnt || verdef_entry.vd_ndx != (versym & VERSYM_VERSION)) {
			verdef_entry_offset += verdef_entry.vd_next;
			continue;
		}

		ut64 verdaux_entry_offset = verdef_entry_offset + verdef_entry.vd_aux;
		Elf_(Verdaux) verdaux_entry = get_verdaux_entry(bin, verdaux_entry_offset);

		if (verdaux_entry.vda_name > bin->strtab_size) {
			return false;
		}

		const char *name = bin->strtab + verdaux_entry.vda_name;
		const char *value = sdb_fmt("%u (%s%-*s)", versym & VERSYM_VERSION, name, (int)(12 - strlen(name)), ")");
		sdb_set(sdb, key, value, 0);

		return true;
	}

	return false;
}

RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info_gnu_versym)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	ut64 versym_addr = bin->version_info[DT_VERSIONTAGIDX(DT_VERSYM)];

	if (!versym_addr) {
		return NULL;
	}

	ut64 versym_offset = Elf_(rz_bin_elf_v2p_new(bin, versym_addr));

	if (versym_offset == UT64_MAX) {
		return NULL;
	}

	ut64 number_of_symbols = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!number_of_symbols) {
		return NULL;
	}

	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}

	sdb_num_set(sdb, "num_entries", number_of_symbols, 0);
	sdb_num_set(sdb, "addr", versym_addr, 0);
	sdb_num_set(sdb, "offset", versym_offset, 0);

	ut64 versym_entry_offset = versym_offset;

	for (size_t i = 0; i < number_of_symbols; i++) {
		const char *key = sdb_fmt("entry%zu", i);
		Elf_(Versym) versym_entry = BREAD16(bin->b, versym_entry_offset);

		switch(versym_entry) {
			case VER_NDX_LOCAL:
				sdb_set(sdb, key, "0 (*local*)", 0);
				break;
			case VER_NDX_GLOBAL:
				sdb_set(sdb, key, "1 (*global*)", 0);
				break;
			default:
				if (set_verneed_entry_versym(bin, sdb, key, versym_entry)) {
					break;
				}

				set_verdef_entry_versym(bin, sdb, key, versym_entry);
		}
	}

	return sdb;
}
