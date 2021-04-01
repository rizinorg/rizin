// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#ifdef _MSC_VER
typedef struct art_header_t {
#else
typedef struct __packed art_header_t {
#endif
	ut8 magic[4];
	ut8 version[4];
	ut32 image_base;
	ut32 image_size;
	ut32 bitmap_offset;
	ut32 bitmap_size;
	ut32 checksum; /* adler32 */
	ut32 oat_file_begin; // oat_file_begin
	ut32 oat_data_begin;
	ut32 oat_data_end;
	ut32 oat_file_end;
	/* patch_delta is the amount of the base address the image is relocated */
	st32 patch_delta;
	/* image_roots: address of an array of objects needed to initialize */
	ut32 image_roots;
	ut32 compile_pic;
} ARTHeader;

typedef struct {
	Sdb *kv;
	ARTHeader art;
	RzBuffer *buf;
} ArtObj;

static int art_header_load(ArtObj *ao, Sdb *db) {
	/* TODO: handle read errors here */
	if (rz_buf_size(ao->buf) < sizeof(ARTHeader)) {
		return false;
	}
	ARTHeader *art = &ao->art;
	(void)rz_buf_fread_at(ao->buf, 0, (ut8 *)art, "IIiiiiiiiiiiii", 1);
	sdb_set(db, "img.base", sdb_fmt("0x%x", art->image_base), 0);
	sdb_set(db, "img.size", sdb_fmt("0x%x", art->image_size), 0);
	sdb_set(db, "art.checksum", sdb_fmt("0x%x", art->checksum), 0);
	sdb_set(db, "art.version", sdb_fmt("%c%c%c", art->version[0], art->version[1], art->version[2]), 0);
	sdb_set(db, "oat.begin", sdb_fmt("0x%x", art->oat_file_begin), 0);
	sdb_set(db, "oat.end", sdb_fmt("0x%x", art->oat_file_end), 0);
	sdb_set(db, "oat_data.begin", sdb_fmt("0x%x", art->oat_data_begin), 0);
	sdb_set(db, "oat_data.end", sdb_fmt("0x%x", art->oat_data_end), 0);
	sdb_set(db, "patch_delta", sdb_fmt("0x%x", art->patch_delta), 0);
	sdb_set(db, "image_roots", sdb_fmt("0x%x", art->image_roots), 0);
	sdb_set(db, "compile_pic", sdb_fmt("0x%x", art->compile_pic), 0);
	return true;
}

static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	ArtObj *ao = o->bin_obj;
	return ao ? ao->kv : NULL;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	ArtObj *ao = RZ_NEW0(ArtObj);
	if (ao) {
		ao->kv = sdb_new0();
		if (!ao->kv) {
			free(ao);
			return false;
		}
		ao->buf = rz_buf_ref(buf);
		art_header_load(ao, ao->kv);
		sdb_ns_set(sdb, "info", ao->kv);
		*bin_obj = ao;
		return true;
	}
	return false;
}

static void destroy(RzBinFile *bf) {
	ArtObj *obj = bf->o->bin_obj;
	rz_buf_free(obj->buf);
	free(obj);
}

static ut64 baddr(RzBinFile *bf) {
	ArtObj *ao = bf->o->bin_obj;
	return ao ? ao->art.image_base : 0;
}

static RzList *strings(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ArtObj *ao = bf->o->bin_obj;
	ret->lang = NULL;
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("ART");

	ret->bclass = malloc(5);
	memcpy(ret->bclass, &ao->art.version, 4);
	ret->bclass[3] = 0;

	ret->rclass = strdup("program");
	ret->os = strdup("android");
	ret->subsystem = strdup("unknown");
	ret->machine = strdup("arm");
	ret->arch = strdup("arm");
	ret->has_va = 1;
	ret->has_lit = true;
	ret->has_pi = ao->art.compile_pic;
	ret->bits = 16; // 32? 64?
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool check_buffer(RzBuffer *buf) {
	char tmp[4];
	int r = rz_buf_read_at(buf, 0, (ut8 *)tmp, sizeof(tmp));
	return r == 4 && !strncmp(tmp, "art\n", 4);
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_newf(free);
	if (ret) {
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (ptr) {
			ptr->paddr = ptr->vaddr = 0;
			rz_list_append(ret, ptr);
		}
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	ArtObj *ao = bf->o->bin_obj;
	if (!ao) {
		return NULL;
	}
	ARTHeader art = ao->art;
	RzList *ret = NULL;
	RzBinSection *ptr = NULL;

	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("load");
	ptr->size = rz_buf_size(bf->buf);
	ptr->vsize = art.image_size; // TODO: align?
	ptr->paddr = 0;
	ptr->vaddr = art.image_base;
	ptr->perm = RZ_PERM_R; // r--
	ptr->add = true;
	rz_list_append(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("bitmap");
	ptr->size = art.bitmap_size;
	ptr->vsize = art.bitmap_size;
	ptr->paddr = art.bitmap_offset;
	ptr->vaddr = art.image_base + art.bitmap_offset;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->add = true;
	rz_list_append(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("oat");
	ptr->paddr = art.bitmap_offset;
	ptr->vaddr = art.oat_file_begin;
	ptr->size = art.oat_file_end - art.oat_file_begin;
	ptr->vsize = ptr->size;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->add = true;
	rz_list_append(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("oat_data");
	ptr->paddr = art.bitmap_offset;
	ptr->vaddr = art.oat_data_begin;
	ptr->size = art.oat_data_end - art.oat_data_begin;
	ptr->vsize = ptr->size;
	ptr->perm = RZ_PERM_R; // r--
	ptr->add = true;
	rz_list_append(ret, ptr);

	return ret;
}

RzBinPlugin rz_bin_plugin_art = {
	.name = "art",
	.desc = "Android Runtime",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.sections = &sections,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_art,
	.version = RZ_VERSION
};
#endif
