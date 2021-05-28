// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static Sdb *store_versioninfo_gnu_versym(ELFOBJ *bin, Elf_(Shdr) * shdr, int sz) {
	size_t i;
	const ut64 num_entries = sz / sizeof(Elf_(Versym));
	const char *section_name = "";
	const char *link_section_name = "";
	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	if (!bin->version_info[DT_VERSIONTAGIDX(DT_VERSYM)]) {
		sdb_free(sdb);
		return NULL;
	}
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		sdb_free(sdb);
		return NULL;
	}
	Elf_(Shdr) *link_shdr = &bin->shdr[shdr->sh_link];
	ut8 *edata = (ut8 *)calloc(RZ_MAX(1, num_entries), 2 * sizeof(ut8));
	if (!edata) {
		sdb_free(sdb);
		return NULL;
	}
	ut16 *data = (ut16 *)calloc(RZ_MAX(1, num_entries), sizeof(ut16));
	if (!data) {
		free(edata);
		sdb_free(sdb);
		return NULL;
	}
	ut64 off = Elf_(rz_bin_elf_v2p)(bin, bin->version_info[DT_VERSIONTAGIDX(DT_VERSYM)]);
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	rz_buf_read_at(bin->b, off, edata, sizeof(ut16) * num_entries);
	sdb_set(sdb, "section_name", section_name, 0);
	sdb_num_set(sdb, "num_entries", num_entries, 0);
	sdb_num_set(sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set(sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set(sdb, "link", shdr->sh_link, 0);
	sdb_set(sdb, "link_section_name", link_section_name, 0);
	for (i = num_entries; i--;) {
		data[i] = rz_read_ble16(&edata[i * sizeof(ut16)], bin->endian);
	}
	RZ_FREE(edata);
	char *tmp_val = NULL;
	for (i = 0; i < num_entries; i += 4) {
		size_t j;
		int check_def;
		char key[32] = { 0 };

		for (j = 0; (j < 4) && (i + j) < num_entries; j++) {
			int k;
			snprintf(key, sizeof(key), "entry%zd", i + j);
			switch (data[i + j]) {
			case 0:
				sdb_set(sdb, key, "0 (*local*)", 0);
				break;
			case 1:
				sdb_set(sdb, key, "1 (*global*)", 0);
				break;
			default:
				free(tmp_val);
				tmp_val = strdup(sdb_fmt("%x ", data[i + j] & 0x7FFF));
				check_def = true;
				if (bin->version_info[DT_VERSIONTAGIDX(DT_VERNEED)]) {
					Elf_(Verneed) vn;
					ut8 svn[sizeof(Elf_(Verneed))] = { 0 };
					ut64 offset = Elf_(rz_bin_elf_v2p)(bin, bin->version_info[DT_VERSIONTAGIDX(DT_VERNEED)]);
					do {
						Elf_(Vernaux) vna;
						ut8 svna[sizeof(Elf_(Vernaux))] = { 0 };
						ut64 a_off;
						if (offset > bin->size || offset + sizeof(vn) > bin->size) {
							goto beach;
						}
						if (rz_buf_read_at(bin->b, offset, svn, sizeof(svn)) < 0) {
							bprintf("Cannot read Verneed for Versym\n");
							goto beach;
						}
						k = 0;
						vn.vn_version = READ16(svn, k);
						vn.vn_cnt = READ16(svn, k);
						vn.vn_file = READ32(svn, k);
						vn.vn_aux = READ32(svn, k);
						vn.vn_next = READ32(svn, k);
						a_off = offset + vn.vn_aux;
						do {
							if (a_off > bin->size || a_off + sizeof(vna) > bin->size) {
								goto beach;
							}
							if (rz_buf_read_at(bin->b, a_off, svna, sizeof(svna)) < 0) {
								bprintf("Cannot read Vernaux for Versym\n");
								goto beach;
							}
							k = 0;
							vna.vna_hash = READ32(svna, k);
							vna.vna_flags = READ16(svna, k);
							vna.vna_other = READ16(svna, k);
							vna.vna_name = READ32(svna, k);
							vna.vna_next = READ32(svna, k);
							a_off += vna.vna_next;
						} while (vna.vna_other != data[i + j] && vna.vna_next != 0);

						if (vna.vna_other == data[i + j]) {
							if (vna.vna_name > bin->strtab_size) {
								goto beach;
							}
							sdb_set(sdb, key, sdb_fmt("%s(%s)", tmp_val, bin->strtab + vna.vna_name), 0);
							check_def = false;
							break;
						}
						offset += vn.vn_next;
					} while (vn.vn_next);
				}

				ut64 vinfoaddr = bin->version_info[DT_VERSIONTAGIDX(DT_VERDEF)];
				if (check_def && data[i + j] != 0x8001 && vinfoaddr) {
					Elf_(Verdef) vd;
					ut8 svd[sizeof(Elf_(Verdef))] = { 0 };
					ut64 offset = Elf_(rz_bin_elf_v2p)(bin, vinfoaddr);
					if (offset > bin->size || offset + sizeof(vd) > bin->size) {
						goto beach;
					}
					do {
						if (rz_buf_read_at(bin->b, offset, svd, sizeof(svd)) < 0) {
							bprintf("Cannot read Verdef for Versym\n");
							goto beach;
						}
						k = 0;
						vd.vd_version = READ16(svd, k);
						vd.vd_flags = READ16(svd, k);
						vd.vd_ndx = READ16(svd, k);
						vd.vd_cnt = READ16(svd, k);
						vd.vd_hash = READ32(svd, k);
						vd.vd_aux = READ32(svd, k);
						vd.vd_next = READ32(svd, k);
						offset += vd.vd_next;
					} while (vd.vd_ndx != (data[i + j] & 0x7FFF) && vd.vd_next != 0);

					if (vd.vd_ndx == (data[i + j] & 0x7FFF)) {
						Elf_(Verdaux) vda;
						ut8 svda[sizeof(Elf_(Verdaux))] = { 0 };
						ut64 off_vda = offset - vd.vd_next + vd.vd_aux;
						if (off_vda > bin->size || off_vda + sizeof(vda) > bin->size) {
							goto beach;
						}
						if (rz_buf_read_at(bin->b, off_vda, svda, sizeof(svda)) < 0) {
							bprintf("Cannot read Verdaux for Versym\n");
							goto beach;
						}
						k = 0;
						vda.vda_name = READ32(svda, k);
						vda.vda_next = READ32(svda, k);
						if (vda.vda_name > bin->strtab_size) {
							goto beach;
						}
						const char *name = bin->strtab + vda.vda_name;
						if (name) {
							const char *fname = sdb_fmt("%s(%s%-*s)", tmp_val, name, (int)(12 - strlen(name)), ")");
							sdb_set(sdb, key, fname, 0);
						}
					}
				}
			}
		}
		RZ_FREE(tmp_val);
	}
beach:
	RZ_FREE(tmp_val);
	free(data);
	return sdb;
}

static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *bin, Elf_(Shdr) * shdr, int sz) {
	const char *section_name = "";
	const char *link_section_name = "";
	char *end = NULL;
	ut8 dfs[sizeof(Elf_(Verdef))] = { 0 };
	Sdb *sdb;
	ut32 cnt;
	size_t i;
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		return false;
	}
	Elf_(Shdr) *link_shdr = &bin->shdr[shdr->sh_link];
#ifdef RZ_BIN_ELF64
	if ((int)shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
#else
	if ((int)shdr->sh_size < 1) {
#endif
		return false;
	}
	if (shdr->sh_size < sizeof(Elf_(Verdef)) || shdr->sh_size < sizeof(Elf_(Verdaux))) {
		return false;
	}
	Elf_(Verdef) *defs = calloc(shdr->sh_size, 1);
	if (!defs) {
		bprintf("Cannot allocate memory (Check Elf_(Verdef))\n");
		return false;
	}
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	sdb = sdb_new0();
	end = (char *)defs + shdr->sh_size;
	sdb_set(sdb, "section_name", section_name, 0);
	sdb_num_set(sdb, "entries", shdr->sh_info, 0);
	sdb_num_set(sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set(sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set(sdb, "link", shdr->sh_link, 0);
	sdb_set(sdb, "link_section_name", link_section_name, 0);

	for (cnt = 0, i = 0; cnt < shdr->sh_info && i < shdr->sh_size; cnt++) {
		Sdb *sdb_verdef = sdb_new0();
		char *vstart = ((char *)defs) + i;
		size_t vstart_off = i;
		char key[32] = { 0 };
		Elf_(Verdef) *verdef = (Elf_(Verdef) *)vstart;
		Elf_(Verdaux) aux = { 0 };
		int j = 0;
		int isum = 0;

		if (vstart + sizeof(*verdef) > end) {
			break;
		}
		rz_buf_read_at(bin->b, shdr->sh_offset + i, dfs, sizeof(Elf_(Verdef)));
		verdef->vd_version = READ16(dfs, j);
		verdef->vd_flags = READ16(dfs, j);
		verdef->vd_ndx = READ16(dfs, j);
		verdef->vd_cnt = READ16(dfs, j);
		verdef->vd_hash = READ32(dfs, j);
		verdef->vd_aux = READ32(dfs, j);
		verdef->vd_next = READ32(dfs, j);
		int vdaux = verdef->vd_aux;
		if (vdaux < 1 || shdr->sh_size - vstart_off < vdaux) {
			sdb_free(sdb_verdef);
			goto out_error;
		}
		vstart += vdaux;
		vstart_off += vdaux;
		if (vstart > end || shdr->sh_size - sizeof(Elf_(Verdaux)) < vstart_off) {
			sdb_free(sdb_verdef);
			goto out_error;
		}

		j = 0;
		aux.vda_name = READ32(vstart, j);
		aux.vda_next = READ32(vstart, j);

		isum = i + verdef->vd_aux;
		if (aux.vda_name > bin->dynstr_size) {
			sdb_free(sdb_verdef);
			goto out_error;
		}

		sdb_num_set(sdb_verdef, "idx", i, 0);
		sdb_num_set(sdb_verdef, "vd_version", verdef->vd_version, 0);
		sdb_num_set(sdb_verdef, "vd_ndx", verdef->vd_ndx, 0);
		sdb_num_set(sdb_verdef, "vd_cnt", verdef->vd_cnt, 0);
		sdb_set(sdb_verdef, "vda_name", &bin->dynstr[aux.vda_name], 0);
		char *flags = Elf_(rz_bin_elf_get_ver_flags)(verdef->vd_flags);
		sdb_set(sdb_verdef, "flags", flags, 0);
		free(flags);

		for (j = 1; j < verdef->vd_cnt; j++) {
			int k;
			Sdb *sdb_parent = sdb_new0();
			if (shdr->sh_size - vstart_off < aux.vda_next) {
				sdb_free(sdb_verdef);
				sdb_free(sdb_parent);
				goto out_error;
			}
			isum += aux.vda_next;
			vstart += aux.vda_next;
			vstart_off += aux.vda_next;
			if (vstart > end || shdr->sh_size - sizeof(Elf_(Verdaux)) < vstart_off) {
				sdb_free(sdb_verdef);
				sdb_free(sdb_parent);
				goto out_error;
			}
			k = 0;
			aux.vda_name = READ32(vstart, k);
			aux.vda_next = READ32(vstart, k);
			if (aux.vda_name > bin->dynstr_size) {
				sdb_free(sdb_verdef);
				sdb_free(sdb_parent);
				goto out_error;
			}
			sdb_num_set(sdb_parent, "idx", isum, 0);
			sdb_num_set(sdb_parent, "parent", j, 0);
			sdb_set(sdb_parent, "vda_name", &bin->dynstr[aux.vda_name], 0);
			snprintf(key, sizeof(key), "parent%d", j - 1);
			sdb_ns_set(sdb_verdef, key, sdb_parent);
		}

		snprintf(key, sizeof(key), "verdef%u", cnt);
		sdb_ns_set(sdb, key, sdb_verdef);
		if (!verdef->vd_next || shdr->sh_size - i < verdef->vd_next) {
			sdb_free(sdb_verdef);
			goto out_error;
		}
		if ((st32)verdef->vd_next < 1) {
			bprintf("Invalid vd_next in the ELF version\n");
			break;
		}
		i += verdef->vd_next;
	}
	free(defs);
	return sdb;
out_error:
	free(defs);
	sdb_free(sdb);
	return NULL;
}

RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->shdr) {
		return NULL;
	}

	Sdb *res = sdb_new0();
	if (!res) {
		return NULL;
	}

	int num_verdef = 0;
	int num_versym = 0;

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		Sdb *sdb = NULL;
		char key[32] = { 0 };

		size_t size = bin->shdr[i].sh_size;

		switch (bin->shdr[i].sh_type) {
		case SHT_GNU_verdef:
			sdb = store_versioninfo_gnu_verdef(bin, &bin->shdr[i], size);
			snprintf(key, sizeof(key), "verdef%d", num_verdef++);
			sdb_ns_set(res, key, sdb);
			break;
		case SHT_GNU_versym:
			sdb = store_versioninfo_gnu_versym(bin, &bin->shdr[i], size);
			snprintf(key, sizeof(key), "versym%d", num_versym++);
			sdb_ns_set(res, key, sdb);
			break;
		}
	}

	Sdb *sdb = Elf_(rz_bin_elf_get_version_info_gnu_verneed)(bin);
	sdb_ns_set(res, "verneed0", sdb);

	return res;
}
