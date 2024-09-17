// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../i/private.h"
#include "pe/pe.h"

static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	struct PE_(rz_bin_pe_obj_t) * bin;
	if (!o || !o->bin_obj) {
		return NULL;
	}
	bin = (struct PE_(rz_bin_pe_obj_t) *)o->bin_obj;
	return bin ? bin->kv : NULL;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);
	struct PE_(rz_bin_pe_obj_t) *res = PE_(rz_bin_pe_new_buf)(buf, bf->rbin->verbose);
	if (res) {
		sdb_ns_set(sdb, "info", res->kv);
		obj->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RzBinFile *bf) {
	PE_(rz_bin_pe_free)
	((struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return PE_(rz_bin_pe_get_image_base)(bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	struct rz_bin_pe_addr_t *peaddr = NULL;
	RzBinAddr *ret = NULL;
	if (bf && bf->o && bf->o->bin_obj) {
		switch (type) {
		case RZ_BIN_SPECIAL_SYMBOL_MAIN:
			peaddr = PE_(rz_bin_pe_get_main_vaddr)(bf->o->bin_obj);
			break;
		default:
			break;
		}
	}
	if (peaddr && (ret = RZ_NEW0(RzBinAddr))) {
		ret->paddr = peaddr->paddr;
		ret->vaddr = peaddr->vaddr;
	}
	free(peaddr);
	return ret;
}

static void add_tls_callbacks(RzBinFile *bf, RzPVector /*<RzBinAddr *>*/ *vec) {
	PE_DWord paddr, vaddr, haddr;
	int count = 0;
	RzBinAddr *ptr = NULL;
	struct PE_(rz_bin_pe_obj_t) *bin = (struct PE_(rz_bin_pe_obj_t) *)(bf->o->bin_obj);
	char *key;
	char tmpbuf[128];

	do {
		key = rz_strf(tmpbuf, "pe.tls_callback%d_paddr", count);
		paddr = sdb_num_get(bin->kv, key);
		if (!paddr) {
			break;
		}

		key = rz_strf(tmpbuf, "pe.tls_callback%d_vaddr", count);
		vaddr = sdb_num_get(bin->kv, key);
		if (!vaddr) {
			break;
		}

		key = rz_strf(tmpbuf, "pe.tls_callback%d_haddr", count);
		haddr = sdb_num_get(bin->kv, key);
		if (!haddr) {
			break;
		}
		if ((ptr = RZ_NEW0(RzBinAddr))) {
			ptr->paddr = paddr;
			ptr->vaddr = vaddr;
			ptr->hpaddr = haddr;
			ptr->type = RZ_BIN_ENTRY_TYPE_TLS;
			rz_pvector_push(vec, ptr);
		}
		count++;
	} while (vaddr);
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	struct rz_bin_pe_addr_t *entry = NULL;
	RzBinAddr *ptr = NULL;
	RzPVector *ret;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(entry = PE_(rz_bin_pe_get_entrypoint)(bf->o->bin_obj))) {
		return ret;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = entry->paddr;
		ptr->vaddr = entry->vaddr;
		ptr->hpaddr = entry->haddr;
		ptr->type = RZ_BIN_ENTRY_TYPE_PROGRAM;
		rz_pvector_push(ret, ptr);
	}
	free(entry);
	// get TLS callback addresses
	add_tls_callbacks(bf, ret);

	return ret;
}

static ut32 perm_of_section_perm(ut64 perm) {
	ut32 r = 0;
	if (RZ_BIN_PE_SCN_IS_EXECUTABLE(perm)) {
		r |= RZ_PERM_X;
		r |= RZ_PERM_R; // implicit
	}
	if (RZ_BIN_PE_SCN_IS_WRITABLE(perm)) {
		r |= RZ_PERM_W;
	}
	if (RZ_BIN_PE_SCN_IS_READABLE(perm)) {
		r |= RZ_PERM_R;
	}
	if (RZ_BIN_PE_SCN_IS_SHAREABLE(perm)) {
		r |= RZ_PERM_SHAR;
	}
	return r;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	struct PE_(rz_bin_pe_obj_t) *bin = (struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj;
	struct rz_bin_pe_section_t *sections = NULL;
	if (!bin || !(sections = bin->sections)) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	ut64 ba = baddr(bf);
	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		return ret;
	}
	map->name = rz_str_dup("header");
	map->paddr = 0;
	ut32 aligned_hdr_size = UT32_MAX;
	if (bin->nt_headers->optional_header.FileAlignment != 0) {
		aligned_hdr_size = RZ_ROUND(bin->nt_headers->optional_header.SizeOfHeaders, bin->nt_headers->optional_header.FileAlignment);
	}
	map->psize = RZ_MIN(bin->size, aligned_hdr_size);
	map->vaddr = ba;
	map->vsize = RZ_ROUND(map->psize, 4096);
	map->perm = RZ_PERM_R;
	rz_pvector_push(ret, map);
	PE_(rz_bin_pe_check_sections)
	(bin, &sections);
	for (size_t i = 0; !sections[i].last; i++) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			break;
		}
		map->paddr = sections[i].paddr;
		map->name = rz_str_dup((char *)sections[i].name);
		map->psize = sections[i].size;
		if (map->psize > bin->size) {
			if (sections[i].vsize < bin->size) {
				map->psize = sections[i].vsize;
			} else {
				// hack give it page size
				map->psize = 4096;
			}
		}
		map->vsize = sections[i].vsize;
		if (!map->vsize && map->psize) {
			map->vsize = map->psize;
		}
		map->vaddr = sections[i].vaddr + ba;
		map->perm = perm_of_section_perm(sections[i].perm);
		rz_pvector_push(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	struct rz_bin_pe_section_t *sections = NULL;
	struct PE_(rz_bin_pe_obj_t) *bin = (struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj;
	ut64 ba = baddr(bf);
	int n_nonzero = 0;
	int i;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}
	if (!bin || !(sections = bin->sections)) {
		rz_pvector_free(ret);
		return NULL;
	}
	PE_(rz_bin_pe_check_sections)
	(bin, &sections);
	for (i = 0; !sections[i].last; i++) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			break;
		}
		ptr->name = rz_str_dup((char *)sections[i].name);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->flags = sections[i].flags;
		ptr->paddr = sections[i].paddr;
		ptr->vaddr = sections[i].vaddr + ba;
		ptr->perm = perm_of_section_perm(sections[i].perm);
		if ((ptr->perm & RZ_PERM_R) && !(ptr->perm & RZ_PERM_X) && ptr->size > 0) {
			ptr->is_data = true;
		}
		if (ptr->size != 0) {
			n_nonzero++;
		}
		rz_pvector_push(ret, ptr);
	}
	if (n_nonzero == 1 && ptr && ptr->perm & RZ_PERM_R) {
		// if there is only one section, then we expect to have data in here also.
		ptr->is_data = true;
	}
	return ret;
}

static void find_pe_overlay(RzBinFile *bf) {
	ut64 pe_overlay_size;
	ut64 pe_overlay_offset = PE_(bin_pe_get_overlay)(bf->o->bin_obj, &pe_overlay_size);
	if (pe_overlay_offset) {
		sdb_num_set(bf->sdb, "pe_overlay.offset", pe_overlay_offset);
		sdb_num_set(bf->sdb, "pe_overlay.size", pe_overlay_size);
	}
}

static inline bool is_thumb(struct PE_(rz_bin_pe_obj_t) * bin, ut64 address) {
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_ARMNT:
		return address & 1;
	default:
		return false;
	}
}

static bool is_go_pclntab(ut8 *magic) {
#define IS_GOPCLNTAB_1_2_LE(x)  (x[0] == 0xfb && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_2_BE(x)  (x[3] == 0xfb && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_16_LE(x) (x[0] == 0xfa && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_16_BE(x) (x[3] == 0xfa && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_18_LE(x) (x[0] == 0xf0 && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_18_BE(x) (x[3] == 0xf0 && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_20_LE(x) (x[0] == 0xf1 && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff && x[4] == 0x00 && x[5] == 0x00)
#define IS_GOPCLNTAB_1_20_BE(x) (x[3] == 0xf1 && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff && x[4] == 0x00 && x[5] == 0x00)
	return IS_GOPCLNTAB_1_2_LE(magic) || IS_GOPCLNTAB_1_2_BE(magic) ||
		IS_GOPCLNTAB_1_16_LE(magic) || IS_GOPCLNTAB_1_16_BE(magic) ||
		IS_GOPCLNTAB_1_18_LE(magic) || IS_GOPCLNTAB_1_18_BE(magic) ||
		IS_GOPCLNTAB_1_20_LE(magic) || IS_GOPCLNTAB_1_20_BE(magic);
#undef IS_GOPCLNTAB_1_2_LE
#undef IS_GOPCLNTAB_1_2_BE
#undef IS_GOPCLNTAB_1_16_LE
#undef IS_GOPCLNTAB_1_16_BE
#undef IS_GOPCLNTAB_1_18_LE
#undef IS_GOPCLNTAB_1_18_BE
#undef IS_GOPCLNTAB_1_20_LE
#undef IS_GOPCLNTAB_1_20_BE
}

static ut64 find_go_pclntab(RzBinFile *bf, ut32 *size, ut64 *vaddr) {
	ut8 magic[16];
	struct PE_(rz_bin_pe_obj_t) *bin = (struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj;
	struct rz_bin_pe_section_t *sections = bin->sections;
	if (!sections) {
		return 0;
	}
	ut64 ba = baddr(bf);
	for (int i = 0; !sections[i].last; i++) {
		if (!strstr((char *)sections[i].name, "data")) {
			continue;
		}
		ut64 offset = sections[i].paddr;
		ut32 section_size = sections[i].size;
		for (ut32 pos = 0; pos < section_size; pos += 8) {
			if ((section_size - pos) < 16) {
				break;
			}
			rz_buf_read_at(bf->buf, offset + pos, magic, sizeof(magic));
			if ((magic[6] != 1 && magic[6] != 2 && magic[6] != 4) || // pc quantum
				(magic[7] != 4 && magic[7] != 8)) { // pointer size
				continue;
			}
			if (is_go_pclntab(magic)) {
				if (size) {
					*size = section_size - pos;
				}
				if (vaddr) {
					*vaddr = ba + sections[i].vaddr + pos;
				}
				return offset + pos;
			}
		}
	}
	return 0;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret = NULL;
	ut64 go_pclntab_paddr = 0;
	ut64 go_pclntab_vaddr = 0;
	ut32 go_pclntab_size = 0;
	RzBinSymbol *ptr = NULL;
	struct rz_bin_pe_export_t *symbols = NULL;
	struct rz_bin_pe_import_t *imports = NULL;
	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	int i;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}
	int file_bits = PE_(rz_bin_pe_get_bits(bin));
	if ((symbols = PE_(rz_bin_pe_get_exports)(bf->o->bin_obj))) {
		for (i = 0; !symbols[i].last; i++) {
			if (!(ptr = RZ_NEW0(RzBinSymbol))) {
				break;
			}
			ptr->name = rz_str_dup((char *)symbols[i].name);
			ptr->libname = RZ_STR_ISNOTEMPTY(symbols[i].libname) ? rz_str_dup((char *)symbols[i].libname) : NULL;
			ptr->forwarder = rz_str_constpool_get(&bf->rbin->constpool, (char *)symbols[i].forwarder);
			// strncpy (ptr->bind, "NONE", RZ_BIN_SIZEOF_STRINGS);
			ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			if (is_thumb(bin, symbols[i].vaddr)) {
				ptr->bits = 16;
				ptr->vaddr = symbols[i].vaddr - 1;
				ptr->paddr = symbols[i].paddr - 1;
			} else {
				ptr->bits = file_bits;
				ptr->vaddr = symbols[i].vaddr;
				ptr->paddr = symbols[i].paddr;
			}
			ptr->ordinal = symbols[i].ordinal;
			rz_pvector_push(ret, ptr);
		}
		free(symbols);
	}

	if ((go_pclntab_paddr = find_go_pclntab(bf, &go_pclntab_size, &go_pclntab_vaddr))) {
		if (!(ptr = RZ_NEW0(RzBinSymbol))) {
			return ret;
		}
		ptr->name = rz_str_dup("gopclntab");
		ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
		ptr->type = RZ_BIN_TYPE_NOTYPE_STR;
		ptr->size = go_pclntab_size;
		ptr->bits = file_bits;
		ptr->vaddr = go_pclntab_vaddr;
		ptr->paddr = go_pclntab_paddr;
		rz_pvector_push(ret, ptr);
	}

	if ((imports = PE_(rz_bin_pe_get_imports)(bf->o->bin_obj))) {
		for (i = 0; !imports[i].last; i++) {
			if (!(ptr = RZ_NEW0(RzBinSymbol))) {
				break;
			}
			// strncpy (ptr->name, (char*)symbols[i].name, RZ_BIN_SIZEOF_STRINGS);
			ptr->name = rz_str_dup((const char *)imports[i].name);
			ptr->libname = rz_str_dup((const char *)imports[i].libname);
			ptr->is_imported = true;
			// strncpy (ptr->forwarder, (char*)imports[i].forwarder, RZ_BIN_SIZEOF_STRINGS);
			ptr->bind = "NONE";
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			ptr->size = 0;
			ptr->vaddr = imports[i].vaddr;
			ptr->paddr = imports[i].paddr;
			ptr->ordinal = imports[i].ordinal;
			rz_pvector_push(ret, ptr);
		}
		free(imports);
	}

	// CLR symbols
	RzList *clr_symbols = PE_(rz_bin_pe_get_clr_symbols)(bf->o->bin_obj);
	RzListIter *iter;
	RzBinSymbol *sym;
	if (clr_symbols) {
		rz_list_foreach (clr_symbols, iter, sym) {
			rz_pvector_push(ret, sym);
		}
		clr_symbols->length = 0;
		clr_symbols->head = clr_symbols->tail = NULL;
		rz_list_free(clr_symbols);
	}

	find_pe_overlay(bf);
	return ret;
}

static void filter_import(ut8 *n) {
	int I;
	for (I = 0; n[I]; I++) {
		if (n[I] < 30 || n[I] >= 0x7f) {
			n[I] = 0;
			break;
		}
	}
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	RzPVector *relocs = NULL;
	RzBinImport *ptr = NULL;
	RzBinReloc *rel = NULL;
	struct rz_bin_pe_import_t *imports = NULL;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}

	// XXX: has_canary is causing problems! thus we need to check and clean here until it is fixed!
	if (((struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj)->relocs) {
		rz_pvector_free(((struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj)->relocs);
	}

	if (!(relocs = rz_pvector_new(free))) {
		rz_pvector_free(ret);
		return NULL;
	}
	((struct PE_(rz_bin_pe_obj_t) *)bf->o->bin_obj)->relocs = relocs;

	if (!(imports = PE_(rz_bin_pe_get_imports)(bf->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !imports[i].last; i++) {
		if (!(ptr = RZ_NEW0(RzBinImport))) {
			break;
		}
		filter_import(imports[i].name);
		ptr->name = rz_str_dup((char *)imports[i].name);
		ptr->libname = rz_str_dup((char *)imports[i].libname);
		ptr->bind = "NONE";
		ptr->type = "FUNC";
		ptr->ordinal = imports[i].ordinal;
		// NOTE(eddyb) a PE hint is just an optional possible DLL export table
		// index for the import. There is no point in exposing it.
		// ptr->hint = imports[i].hint;
		rz_pvector_push(ret, ptr);

		if (!(rel = RZ_NEW0(RzBinReloc))) {
			break;
		}
#ifdef RZ_BIN_PE64
		rel->type = RZ_BIN_RELOC_64;
#else
		rel->type = RZ_BIN_RELOC_32;
#endif
		rel->additive = 0;
		rel->import = ptr;
		rel->addend = 0;
		{
			ut8 addr[4];
			rz_buf_read_at(bf->buf, imports[i].paddr, addr, 4);
			ut64 newaddr = (ut64)rz_read_le32(&addr);
			rel->vaddr = newaddr;
		}
		rel->paddr = imports[i].paddr;
		rz_pvector_push(relocs, rel);
	}
	free(imports);
	return ret;
}

static RzPVector /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	struct PE_(rz_bin_pe_obj_t) *obj = bf->o->bin_obj;
	if (obj) {
		return obj->relocs;
	}
	return NULL;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	return PE_(rz_bin_pe_get_libs)(bf->o->bin_obj);
}

static RzPVector /*<RzBinResource *>*/ *resources(RzBinFile *bf) {
	struct PE_(rz_bin_pe_obj_t) *obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	RzPVector *res = rz_pvector_new((RzPVectorFree)rz_bin_resource_free);
	if (!res) {
		return NULL;
	}
	rz_pe_resource *rs;
	RzListIter *it;
	size_t index = 0;
	rz_list_foreach (obj->resources, it, rs) {
		RzBinResource *br = RZ_NEW0(RzBinResource);
		if (!br) {
			goto err;
		}

		br->index = index++;
		br->name = rz_str_dup(rs->name);
		if (!br->name) {
			rz_bin_resource_free(br);
			goto err;
		}
		br->time = rz_str_dup(rs->timestr);
		if (!br->time) {
			rz_bin_resource_free(br);
			goto err;
		}
		br->vaddr = PE_(rz_bin_pe_get_image_base)(obj) + rs->data->OffsetToData;
		br->size = rs->data->Size;
		br->type = rz_str_dup(rs->type);
		if (!br->type) {
			rz_bin_resource_free(br);
			goto err;
		}
		br->language = rz_str_dup(rs->language);
		if (!br->language) {
			rz_bin_resource_free(br);
			goto err;
		}

		rz_pvector_push(res, br);
	}
	return res;

err:
	rz_pvector_free(res);
	return NULL;
}

static int has_canary(RzBinFile *bf) {
	// XXX: We only need imports here but this causes leaks, we need to wait for the below. This is a horrible solution!
	// TODO: use O(1) when imports sdbized
	struct PE_(rz_bin_pe_obj_t) *bin = bf->o->bin_obj;
	void **it;
	if (bin) {
		const RzPVector *relocs_vec = bin->relocs;
		RzBinReloc *rel;
		if (relocs_vec) {
			rz_pvector_foreach (relocs_vec, it) {
				rel = *it;
				if (!strcmp(rel->import->name, "__security_init_cookie")) {
					return true;
				}
			}
		}
	} else { // rz_bin needs this as it will not initialise bin
		const RzPVector *imports_vec = imports(bf);
		RzBinImport *imp;
		if (imports_vec) {
			rz_pvector_foreach (imports_vec, it) {
				imp = *it;
				if (!strcmp(imp->name, "__security_init_cookie")) {
					return true;
				}
			}
		}
	}
	return false;
}

static inline bool haschr(const struct PE_(rz_bin_pe_obj_t) * bin, ut16 dllCharacteristic) {
	return bin->nt_headers->optional_header.DllCharacteristics & dllCharacteristic;
}

static int compare_strings(const void *a, const void *b, RZ_UNUSED void *user) {
	return strcmp((const char *)a, (const char *)b);
}

static RzBinInfo *info(RzBinFile *bf) {
	struct PE_(rz_bin_pe_obj_t) * bin;
	SDebugInfo di = { { 0 } };
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	ut32 claimed_checksum, actual_checksum, pe_overlay;

	if (!ret) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	ret->file = rz_str_dup(bf->file);
	ret->bclass = PE_(rz_bin_pe_get_class)(bf->o->bin_obj);
	ret->rclass = rz_str_dup("pe");
	ret->os = PE_(rz_bin_pe_get_os)(bf->o->bin_obj);
	ret->arch = PE_(rz_bin_pe_get_arch)(bf->o->bin_obj);
	ret->machine = PE_(rz_bin_pe_get_machine)(bf->o->bin_obj);
	ret->subsystem = PE_(rz_bin_pe_get_subsystem)(bf->o->bin_obj);
	ret->default_cc = PE_(rz_bin_pe_get_cc)(bf->o->bin_obj);
	ret->compiler = PE_(rz_bin_pe_get_compiler)(bf->o->bin_obj);

	RzPVector *libs = PE_(rz_bin_pe_get_libs)(bf->o->bin_obj);
	if (libs && rz_pvector_find(libs, "mscoree.dll", compare_strings, NULL)) {
		ret->lang = "cil";
	}
	if (libs && rz_pvector_find(libs, "msvbvm60.dll", compare_strings, NULL)) {
		ret->lang = "vb";
	}
	rz_pvector_free(libs);

	if (PE_(rz_bin_pe_is_dll)(bf->o->bin_obj)) {
		ret->type = rz_str_dup("DLL (Dynamic Link Library)");
	} else {
		ret->type = rz_str_dup("EXEC (Executable file)");
	}
	claimed_checksum = PE_(bin_pe_get_claimed_checksum)(bf->o->bin_obj);
	actual_checksum = PE_(bin_pe_get_actual_checksum)(bf->o->bin_obj);
	pe_overlay = sdb_num_get(bf->sdb, "pe_overlay.size");
	ret->bits = PE_(rz_bin_pe_get_bits)(bf->o->bin_obj);
	ret->big_endian = PE_(rz_bin_pe_is_big_endian)(bf->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_canary = has_canary(bf);
	ret->has_nx = haschr(bin, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);
	ret->has_pi = haschr(bin, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
	ret->claimed_checksum = rz_str_newf("0x%08x", claimed_checksum);
	ret->actual_checksum = rz_str_newf("0x%08x", actual_checksum);
	ret->pe_overlay = pe_overlay > 0;
	ret->signature = bin ? bin->is_signed : false;
	Sdb *db = sdb_ns(bf->sdb, "pe", true);
	sdb_bool_set(db, "canary", has_canary(bf));
	sdb_bool_set(db, "highva", haschr(bin, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
	sdb_bool_set(db, "aslr", haschr(bin, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE));
	sdb_bool_set(db, "forceintegrity", haschr(bin, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY));
	sdb_bool_set(db, "nx", haschr(bin, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT));
	sdb_bool_set(db, "isolation", !haschr(bin, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION));
	sdb_bool_set(db, "seh", !haschr(bin, IMAGE_DLLCHARACTERISTICS_NO_SEH));
	sdb_bool_set(db, "bind", !haschr(bin, IMAGE_DLLCHARACTERISTICS_NO_BIND));
	sdb_bool_set(db, "appcontainer", haschr(bin, IMAGE_DLLCHARACTERISTICS_APPCONTAINER));
	sdb_bool_set(db, "wdmdriver", haschr(bin, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER));
	sdb_bool_set(db, "guardcf", haschr(bin, IMAGE_DLLCHARACTERISTICS_GUARD_CF));
	sdb_bool_set(db, "terminalserveraware", haschr(bin, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE));
	sdb_num_set(db, "bits", ret->bits);
	sdb_set(db, "claimed_checksum", ret->claimed_checksum);
	sdb_set(db, "actual_checksum", ret->actual_checksum);
	sdb_bool_set(db, "is_authhash_valid", PE_(bin_pe_is_authhash_valid)(bf->o->bin_obj));

	ret->has_va = true;

	if (PE_(rz_bin_pe_is_stripped_debug)(bf->o->bin_obj)) {
		ret->dbg_info |= RZ_BIN_DBG_STRIPPED;
	}
	if (PE_(rz_bin_pe_is_stripped_line_nums)(bf->o->bin_obj)) {
		ret->dbg_info |= RZ_BIN_DBG_LINENUMS;
	}
	if (PE_(rz_bin_pe_is_stripped_local_syms)(bf->o->bin_obj)) {
		ret->dbg_info |= RZ_BIN_DBG_SYMS;
	}
	if (PE_(rz_bin_pe_is_stripped_relocs)(bf->o->bin_obj)) {
		ret->dbg_info |= RZ_BIN_DBG_RELOCS;
	}
	if (PE_(rz_bin_pe_get_debug_data)(bf->o->bin_obj, &di)) {
		ret->guid = rz_str_ndup(di.guidstr, GUIDSTR_LEN);
		if (ret->guid) {
			ret->debug_file_name = rz_str_ndup(di.file_name, DBG_FILE_NAME_LEN);
			if (!ret->debug_file_name) {
				RZ_FREE(ret->guid);
			}
		}
	}

	return ret;
}

static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return baddr + vaddr;
}

static RzPVector /*<RzBinFileHash *>*/ *compute_hashes(RzBinFile *bf) {
	RzPVector *file_hashes = rz_pvector_new((RzPVectorFree)rz_bin_file_hash_free);
	const char *authentihash = PE_(bin_pe_get_authentihash)(bf->o->bin_obj);
	if (authentihash) {
		RzBinFileHash *authhash = RZ_NEW0(RzBinFileHash);
		if (authhash) {
			authhash->type = rz_str_dup("authentihash");
			authhash->hex = rz_str_dup(authentihash);
			rz_pvector_push(file_hashes, authhash);
		}
	}

	return file_hashes;
}

/**
 * Currently only used by CIL plugin to resolve `call` and `jmp` targets
 * \returns offset on success, UT64_MAX on fail
 */
static ut64 get_offset(RzBinFile *bf, int type, int idx) {
	struct PE_(rz_bin_pe_obj_t) * bin;
	Pe_image_clr *clr;

	if (!bf || !bf->o ||
		!(bin = bf->o->bin_obj) ||
		!(clr = bin->clr)) {
		return UT64_MAX;
	}

	if (type == 'd') { // MethodDef index
		Pe_image_metadata_methoddef *methoddef = rz_pvector_at(clr->methoddefs, idx - 1);
		return PE_(rz_bin_pe_get_clr_methoddef_offset)(bin, methoddef);
	}

	return UT64_MAX;
}
