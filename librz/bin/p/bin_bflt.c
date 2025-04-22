// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2016-2019 Oscar Salvador <osalvador.vilardaga@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include "bflt/bflt.h"

#define VFILE_NAME_PATCHED "patched"

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	obj->bin_obj = rz_bflt_new_buf(buf, obj->opts.baseaddr, obj->opts.big_endian, obj->opts.patch_relocs);
	return obj->bin_obj;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzBfltObj *obj = bf->o->bin_obj;
	RzPVector *ret;
	RzBinAddr *ptr;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	ptr = rz_bflt_get_entry(obj);
	if (!ptr) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzBfltObj *obj = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(ret);
		return NULL;
	}
	map->paddr = 0;
	map->vaddr = rz_bflt_get_text_base(obj);
	map->psize = obj->hdr.data_start;
	map->vsize = obj->hdr.data_start;
	map->perm = RZ_PERM_RWX;
	map->name = rz_str_dup("hdr+text");
	map->vfile_name = obj->buf_patched ? rz_str_dup(VFILE_NAME_PATCHED) : NULL;
	rz_pvector_push(ret, map);

	map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(ret);
		return NULL;
	}
	map->paddr = obj->hdr.data_start;
	map->vaddr = rz_bflt_get_data_base(obj);
	map->psize = obj->hdr.data_end - obj->hdr.data_start;
	map->vsize = rz_bflt_get_data_vsize(obj);
	map->perm = RZ_PERM_RWX;
	map->name = rz_str_dup("data+bss");
	map->vfile_name = obj->buf_patched ? rz_str_dup(VFILE_NAME_PATCHED) : NULL;
	rz_pvector_push(ret, map);

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzBfltObj *obj = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	// segments

	RzBinSection *sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		goto beach;
	}
	sec->paddr = 0;
	sec->vaddr = rz_bflt_get_text_base(obj);
	sec->size = obj->hdr.data_start;
	sec->vsize = obj->hdr.data_start;
	sec->perm = RZ_PERM_RWX;
	sec->name = rz_str_dup("TEXT");
	sec->is_segment = true;
	rz_pvector_push(ret, sec);

	sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		goto beach;
	}
	sec->paddr = obj->hdr.data_start;
	sec->vaddr = rz_bflt_get_data_base(obj);
	sec->size = obj->hdr.data_start;
	sec->vsize = rz_bflt_get_data_vsize(obj);
	sec->perm = RZ_PERM_RWX;
	sec->name = rz_str_dup("DATA");
	sec->is_segment = true;
	rz_pvector_push(ret, sec);

	// sections

	sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		goto beach;
	}
	sec->paddr = 0;
	sec->vaddr = rz_bflt_get_text_base(obj);
	sec->size = BFLT_HDR_SIZE;
	sec->vsize = BFLT_HDR_SIZE;
	sec->perm = RZ_PERM_RWX;
	sec->name = rz_str_dup("header");
	rz_pvector_push(ret, sec);

	sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		goto beach;
	}
	sec->paddr = BFLT_HDR_SIZE;
	sec->vaddr = rz_bflt_get_text_base(obj) + BFLT_HDR_SIZE;
	sec->size = obj->hdr.data_start - BFLT_HDR_SIZE;
	sec->vsize = obj->hdr.data_start - BFLT_HDR_SIZE;
	sec->perm = RZ_PERM_RWX;
	sec->name = rz_str_dup("text");
	rz_pvector_push(ret, sec);

	sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		goto beach;
	}
	sec->paddr = obj->hdr.data_start;
	sec->vaddr = rz_bflt_get_data_base(obj);
	sec->size = obj->hdr.data_end - obj->hdr.data_start;
	sec->vsize = obj->hdr.data_end - obj->hdr.data_start;
	sec->perm = RZ_PERM_RWX;
	sec->name = rz_str_dup("data");
	sec->is_data = true;
	rz_pvector_push(ret, sec);

	sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		goto beach;
	}
	sec->paddr = obj->hdr.data_end;
	sec->vaddr = rz_bflt_get_data_base(obj) + obj->hdr.data_end - obj->hdr.data_start;
	sec->size = 0;
	sec->vsize = obj->hdr.bss_end - obj->hdr.data_end;
	sec->perm = RZ_PERM_RWX;
	sec->name = rz_str_dup("bss");
	sec->is_data = true;
	rz_pvector_push(ret, sec);

	return ret;
beach:
	rz_pvector_free(ret);
	return NULL;
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzBfltObj *obj = bf->o->bin_obj;
	RzPVector *r = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!r) {
		return NULL;
	}
	if (obj->buf_patched) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return r;
		}
		vf->buf = obj->buf_patched;
		vf->name = rz_str_dup(VFILE_NAME_PATCHED);
		rz_pvector_push(r, vf);
	}
	return r;
}

static void convert_relocs(RzBfltObj *bin, RzPVector /*<RzBinReloc *>*/ *out, RzVector /*<RzBfltReloc>*/ *relocs) {
	RzBfltReloc *br;
	rz_vector_foreach (relocs, br) {
		RzBinReloc *r = RZ_NEW0(RzBinReloc);
		if (!r) {
			return;
		}
		r->type = RZ_BIN_RELOC_32;
		r->paddr = br->reloc_paddr;
		r->vaddr = rz_bflt_paddr_to_vaddr(bin, r->paddr);

		// 0 preserved, see also patching in bflt.c
		r->target_vaddr = br->value_orig ? rz_bflt_paddr_to_vaddr(bin, br->value_orig) : 0;

		rz_pvector_push(out, r);
	}
}

static RzPVector /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	RzBfltObj *obj = (RzBfltObj *)bf->o->bin_obj;
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free);
	if (!vec || !obj) {
		rz_pvector_free(vec);
		return NULL;
	}
	convert_relocs(obj, vec, &obj->got_relocs);
	convert_relocs(obj, vec, &obj->relocs);
	return vec;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBfltObj *obj = NULL;
	RzBinInfo *info = NULL;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	obj = (RzBfltObj *)bf->o->bin_obj;
	if (!(info = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	info->file = rz_str_dup(bf->file);
	info->rclass = rz_str_dup("bflt");
	info->bclass = rz_str_dup("bflt");
	info->type = rz_str_dup("bFLT (Executable file)");
	info->os = rz_str_dup("Linux");
	info->subsystem = rz_str_dup("uClinux");
	info->arch = rz_str_dup("arm"); // this is a wild guess, the format does not specify any arch, but arm is probably the most popular
	info->big_endian = obj->big_endian;
	info->bits = 32;
	info->has_va = true;
	info->dbg_info = 0;
	info->machine = rz_str_dup("unknown");
	info->has_pi = true;
	return info;
}

static bool check_buffer(RzBuffer *buf) {
	ut8 tmp[4];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	return r == sizeof(tmp) && !memcmp(tmp, "bFLT", 4);
}

static void destroy(RzBinFile *bf) {
	rz_bflt_free(bf->o->bin_obj);
}

RzBinPlugin rz_bin_plugin_bflt = {
	.name = "bflt",
	.desc = "bFLT uClinux executable",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.relocs = &relocs
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bflt,
	.version = RZ_VERSION
};
#endif
