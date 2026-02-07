// SPDX-FileCopyrightText: 2011-2019 ninjahacker <wardjm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "zimg/zimg.h"

static Sdb *get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, false);
	struct rz_bin_zimg_obj_t *bin = (struct rz_bin_zimg_obj_t *)bf->o->bin_obj;
	return bin ? bin->kv : NULL;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	obj->bin_obj = rz_bin_zimg_new_buf(b);
	return obj->bin_obj != NULL;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static bool check_buffer(RzBuffer *b) {
	ut8 zimghdr[8];
	if (rz_buf_read_at(b, 0, zimghdr, sizeof(zimghdr))) {
		// Checking ARM zImage kernel
		if (!memcmp(zimghdr, "\x00\x00\xa0\xe1\x00\x00\xa0\xe1", 8)) {
			return true;
		}
	}
	return false;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("Linux zImage Kernel");
	ret->has_va = false;
	ret->bclass = rz_str_dup("Compressed Linux Kernel");
	ret->rclass = rz_str_dup("zimg");
	ret->os = rz_str_dup("linux");
	ret->subsystem = rz_str_dup("linux");
	ret->machine = rz_str_dup("ARM"); // TODO: can be other cpus
	ret->arch = rz_str_dup("arm");
	ret->lang = "C";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; // 1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

static RzStructuredData *zimg_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinZimgObj *zo = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *zimg = rz_structured_data_map_add_map(info, "zimg");
	if (!zimg) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(zimg, "size", zo->size, false);

	RzStructuredData *kernel = rz_structured_data_map_add_map(zimg, "kernel");
	if (!kernel) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *magic = rz_structured_data_map_add_map(zimg, "magic");
	if (!magic) {
		rz_structured_data_free(info);
		return NULL;
	}

	ut32 magic0 = rz_read_le32(&zo->header.magic[0]);
	ut32 magic1 = rz_read_le32(&zo->header.magic[4]);
	ut32 arm_magic = rz_read_le32(zo->header.arm_magic);

	rz_structured_data_map_add_unsigned(magic, "magic0", magic0, true);
	rz_structured_data_map_add_unsigned(magic, "magic1", magic1, true);
	rz_structured_data_map_add_unsigned(magic, "arm_magic", arm_magic, true);

	ut64 kernel_start = zo->header.kernel_start;
	ut64 kernel_end = zo->header.kernel_end;

	rz_structured_data_map_add_unsigned(kernel, "kernel_start", kernel_start, true);
	rz_structured_data_map_add_unsigned(kernel, "kernel_end", kernel_end, true);
	rz_structured_data_map_add_unsigned(kernel, "kernel_size", kernel_end - kernel_start, false);

	return info;
}

RzBinPlugin rz_bin_plugin_zimg = {
	.name = "zimg",
	.desc = "ZIMG format binary",
	.license = "LGPL3",
	.author = "ninjahacker",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.info = &info,
	.bin_structure = &zimg_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_zimg,
	.version = RZ_VERSION
};
#endif
