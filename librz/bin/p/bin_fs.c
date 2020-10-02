/* radare - LGPL - Copyright 2011-2019 - pancake */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../../fs/types.h"

static char *fsname(RBuffer *b) {
	ut8 buf[1024];
	int i, j;

	for (i = 0; fstypes[i].name; i++) {
		RzFSType *f = &fstypes[i];

		if (rz_buf_read_at (b, f->bufoff, buf, sizeof (buf)) != sizeof (buf)) {
			break;
		}
		if (f->buflen > 0) {
			size_t min = R_MIN (f->buflen, sizeof (buf));
			if (!memcmp (buf, f->buf, min)) {
				bool ret = true;
				min = R_MIN (f->bytelen, sizeof (buf));
				if (rz_buf_read_at (b, f->byteoff, buf, min) != min) {
					break;
				}
				for (j = 0; j < min; j++) {
					if (buf[j] != f->byte) {
						ret = false;
						break;
					}
				}
				if (ret) {
					return strdup (f->name);
				}
			}
		}
	}
	return NULL;
}

static bool check_buffer(RBuffer *b) {
	rz_return_val_if_fail (b, false);
	char *p = fsname (b);
	bool hasFs = p != NULL;
	free (p);
	return hasFs;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static void destroy(RBinFile *bf) {
	//rz_bin_fs_free ((struct rz_bin_fs_obj_t*)bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

/* accelerate binary load */
static RzList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!bf) {
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("fs");
	ret->bclass = fsname (bf->buf);
	ret->rclass = strdup ("fs");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("any");
	// ret->arch = strdup ("any");
	ret->has_va = 0;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

RBinPlugin rz_bin_plugin_fs = {
	.name = "fs",
	.desc = "filesystem bin plugin",
	.author = "pancake",
	.version = "1.0",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.strings = &strings,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_fs,
	.version = RZ_VERSION
};
#endif
