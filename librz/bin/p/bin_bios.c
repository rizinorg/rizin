// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../i/private.h"

static bool check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);

	ut64 sz = rz_buf_size(buf);
	if (sz <= 0xffff) {
		return false;
	}

	ut8 b0;
	if (!rz_buf_read8_at(buf, 0, &b0)) {
		return false;
	}

	if (b0 == 0xcf || b0 == 0x7f) {
		return false;
	}

	const ut32 ep = sz - 0x10000 + 0xfff0; /* F000:FFF0 address */
	/* hacky check to avoid detecting multidex or MZ bins as bios */
	/* need better fix for this */
	ut8 tmp[3];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	if (r <= 0 || !memcmp(tmp, "dex", 3) || !memcmp(tmp, "MZ", 2)) {
		return false;
	}

	/* Check if this a 'jmp' opcode */
	ut8 bep;
	if (!rz_buf_read8_at(buf, ep, &bep)) {
		return false;
	}

	return bep == 0xea || bep == 0xe9;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	if (!check_buffer(buf)) {
		return false;
	}
	obj->bin_obj = rz_buf_ref(buf);
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

/* accelerate binary load */
static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("bios");
	ret->bclass = rz_str_dup("1.0");
	ret->rclass = rz_str_dup("bios");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("unknown");
	ret->machine = rz_str_dup("pc");
	ret->arch = rz_str_dup("x86");
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	RzBuffer *obj = bf->o->bin_obj;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}
	// program headers is another section
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("bootblk"); // Maps to 0xF000:0000 segment
	ptr->vsize = ptr->size = 0x10000;
	ptr->paddr = rz_buf_size(bf->buf) - ptr->size;
	ptr->vaddr = 0xf0000;
	ptr->perm = RZ_PERM_RWX;
	rz_pvector_push(ret, ptr);
	// If image bigger than 128K - add one more section
	if (bf->size >= 0x20000) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("_e000"); // Maps to 0xE000:0000 segment
		ptr->vsize = ptr->size = 0x10000;
		ptr->paddr = rz_buf_size(obj) - 2 * ptr->size;
		ptr->vaddr = 0xe0000;
		ptr->perm = RZ_PERM_RWX;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = 0; // 0x70000;
	ptr->vaddr = 0xffff0;
	rz_pvector_push(ret, ptr);
	return ret;
}

RzBinPlugin rz_bin_plugin_bios = {
	.name = "bios",
	.desc = "BIOS bin plugin",
	.license = "LGPL",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = entries,
	.maps = rz_bin_maps_of_file_sections,
	.sections = sections,
	.strings = &strings,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bios,
	.version = RZ_VERSION
};
#endif
