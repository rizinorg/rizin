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

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
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
	ret->file = strdup(bf->file);
	ret->type = strdup("Sound File Data");
	ret->machine = strdup("SPC700");
	ret->os = strdup("spc700");
	ret->arch = strdup("spc700");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSection *ptr = NULL;
	spc_hdr spchdr;
	memset(&spchdr, 0, SPC_HDR_SIZE);
	int reat = rz_buf_read_at(bf->buf, 0, (ut8 *)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf("Truncated Header\n");
		return NULL;
	}
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		rz_list_free(ret);
		return NULL;
	}
	ptr->name = strdup("RAM");
	ptr->paddr = RAM_START_ADDRESS;
	ptr->size = RAM_SIZE;
	ptr->vaddr = 0x0;
	ptr->vsize = RAM_SIZE;
	ptr->perm = RZ_PERM_R;
	ptr->add = true;
	rz_list_append(ret, ptr);
	return ret;
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_newf(free);
	if (ret) {
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (ptr) {
			ptr->paddr = RAM_START_ADDRESS;
			ptr->vaddr = 0;
			rz_list_append(ret, ptr);
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
