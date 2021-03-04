// SPDX-FileCopyrightText: 2018-2019 a0rtega
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

#include "nin/n3ds.h"

static struct n3ds_firm_hdr loaded_header;

static bool check_buffer(RzBuffer *b) {
	ut8 magic[4];
	rz_buf_read_at(b, 0, magic, sizeof(magic));
	return (!memcmp(magic, "FIRM", 4));
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	if (rz_buf_read_at(b, 0, (ut8 *)&loaded_header, sizeof(loaded_header)) == sizeof(loaded_header)) {
		*bin_obj = &loaded_header;
		return true;
	}
	return false;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSection *sections[4] = {
		NULL, NULL, NULL, NULL
	};
	int i, corrupt = false;

	if (!(ret = rz_list_new())) {
		return NULL;
	}

	/* FIRM has always 4 sections, normally the 4th section is not used */
	for (i = 0; i < 4; i++) {
		/* Check if section is used */
		if (loaded_header.sections[i].size) {
			sections[i] = RZ_NEW0(RzBinSection);
			/* Firmware Type ('0'=ARM9/'1'=ARM11) */
			if (loaded_header.sections[i].type == 0x0) {
				sections[i]->name = strdup("arm9");
			} else if (loaded_header.sections[i].type == 0x1) {
				sections[i]->name = strdup("arm11");
			} else {
				corrupt = true;
				break;
			}
			sections[i]->size = loaded_header.sections[i].size;
			sections[i]->vsize = loaded_header.sections[i].size;
			sections[i]->paddr = loaded_header.sections[i].offset;
			sections[i]->vaddr = loaded_header.sections[i].address;
			sections[i]->perm = rz_str_rwx("rwx");
			sections[i]->add = true;
		}
	}

	/* Append sections or free them if file is corrupt to avoid memory leaks */
	for (i = 0; i < 4; i++) {
		if (sections[i]) {
			if (corrupt) {
				free(sections[i]);
			} else {
				rz_list_append(ret, sections[i]);
			}
		}
	}
	if (corrupt) {
		rz_list_free(ret);
		return NULL;
	}

	return ret;
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_new();
	RzBinAddr *ptr9 = NULL, *ptr11 = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		ret->free = free;
		if (!(ptr9 = RZ_NEW0(RzBinAddr))) {
			rz_list_free(ret);
			return NULL;
		}
		if (!(ptr11 = RZ_NEW0(RzBinAddr))) {
			rz_list_free(ret);
			free(ptr9);
			return NULL;
		}

		/* ARM9 entry point */
		ptr9->vaddr = loaded_header.arm9_ep;
		rz_list_append(ret, ptr9);

		/* ARM11 entry point */
		ptr11->vaddr = loaded_header.arm11_ep;
		rz_list_append(ret, ptr11);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	if (!bf || !bf->buf) {
		free(ret);
		return NULL;
	}

	ret->type = strdup("FIRM");
	ret->machine = strdup("Nintendo 3DS");
	ret->os = strdup("n3ds");
	ret->arch = strdup("arm");
	ret->has_va = true;
	ret->bits = 32;

	return ret;
}

RzBinPlugin rz_bin_plugin_nin3ds = {
	.name = "nin3ds",
	.desc = "Nintendo 3DS FIRM format rz_bin plugin",
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
	.data = &rz_bin_plugin_nin3ds,
	.version = RZ_VERSION
};
#endif
