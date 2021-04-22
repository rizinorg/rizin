// SPDX-FileCopyrightText: 2014-2019 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/nin/gba.h"

static bool check_buffer(RzBuffer *b) {
	ut8 lict[156];
	rz_return_val_if_fail(b, false);
	rz_buf_read_at(b, 4, (ut8 *)lict, sizeof(lict));
	return !memcmp(lict, lic_gba, 156);
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(buf);
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_newf(free);
	RzBinAddr *ptr = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = 0x8000000;
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	ut8 rom_info[16];
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);

	if (!ret) {
		return NULL;
	}

	if (!bf || !bf->buf) {
		free(ret);
		return NULL;
	}

	ret->lang = NULL;
	rz_buf_read_at(bf->buf, 0xa0, rom_info, 16);
	ret->file = rz_str_ndup((const char *)rom_info, 12);
	ret->type = rz_str_ndup((char *)&rom_info[12], 4);
	ret->machine = strdup("GameBoy Advance");
	ret->os = strdup("any");
	ret->arch = strdup("arm");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (!s) {
		return NULL;
	}
	ut64 sz = rz_buf_size(bf->buf);
	if (!(ret = rz_list_newf((RzListFree)rz_bin_section_free))) {
		free(s);
		return NULL;
	}
	s->name = strdup("ROM");
	s->paddr = 0;
	s->vaddr = 0x8000000;
	s->size = sz;
	s->vsize = 0x2000000;
	s->perm = RZ_PERM_RX;

	rz_list_append(ret, s);
	return ret;
}

RzBinPlugin rz_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Game Boy Advance format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.info = &info,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ningba,
	.version = RZ_VERSION
};
#endif
