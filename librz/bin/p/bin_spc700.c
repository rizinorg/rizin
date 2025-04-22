// SPDX-FileCopyrightText: 2015-2019 - maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>
#include "../format/spc700/spc_specs.h"

static bool check_buffer(RzBuffer *b) {
	ut8 buf[27];
	if (rz_buf_read_at(b, 0, buf, sizeof(buf)) == 27) {
		return !memcmp(buf, SPC_MAGIC, 27);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	return check_buffer(b);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	spc_hdr spchdr;
	memset(&spchdr, 0, SPC_HDR_SIZE);
	int reat = rz_buf_read_at(bf->buf, 0, (ut8 *)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf("Truncated Header\n");
		return NULL;
	}
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("Sound File Data");
	ret->machine = rz_str_dup("SPC700");
	ret->os = rz_str_dup("spc700");
	ret->arch = rz_str_dup("spc700");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	spc_hdr spchdr;
	memset(&spchdr, 0, SPC_HDR_SIZE);
	int reat = rz_buf_read_at(bf->buf, 0, (ut8 *)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf("Truncated Header\n");
		return NULL;
	}
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		rz_pvector_free(ret);
		return NULL;
	}
	ptr->name = rz_str_dup("RAM");
	ptr->paddr = RAM_START_ADDRESS;
	ptr->size = RAM_SIZE;
	ptr->vaddr = 0x0;
	ptr->vsize = RAM_SIZE;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new(free);
	if (ret) {
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (ptr) {
			ptr->paddr = RAM_START_ADDRESS;
			ptr->vaddr = 0;
			rz_pvector_push(ret, ptr);
		}
	}
	return ret;
}

RzBinPlugin rz_bin_plugin_spc700 = {
	.name = "spc700",
	.desc = "SNES-SPC700 Sound File Data",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_spc700,
	.version = RZ_VERSION
};
#endif
