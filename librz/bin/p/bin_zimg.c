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

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	*bin_obj = rz_bin_zimg_new_buf(b);
	return *bin_obj != NULL;
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
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("Linux zImage Kernel");
	ret->has_va = false;
	ret->bclass = strdup("Compressed Linux Kernel");
	ret->rclass = strdup("zimg");
	ret->os = strdup("linux");
	ret->subsystem = strdup("linux");
	ret->machine = strdup("ARM"); // TODO: can be other cpus
	ret->arch = strdup("arm");
	ret->lang = "C";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; // 1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

RzBinPlugin rz_bin_plugin_zimg = {
	.name = "zimg",
	.desc = "zimg format bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_zimg,
	.version = RZ_VERSION
};
#endif
