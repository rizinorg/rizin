/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_magic.h>

static char *get_filetype(RBuffer *b) {
	ut8 buf[4096] = { 0 };
	char *res = NULL;
	RzMagic *ck = rz_magic_new (0);
	if (!ck) {
		return NULL;
	}
	const char *tmp = NULL;
	// TODO: dir.magic not honored here
	rz_magic_load (ck, R2_SDB_MAGIC);
	rz_buf_read_at (b, 0, buf, sizeof (buf));
	tmp = rz_magic_buffer (ck, buf, sizeof (buf));
	if (tmp) {
		res = strdup (tmp);
	}
	rz_magic_free (ck);
	return res;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = "";
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = get_filetype (bf->buf);
	ret->has_pi = 0;
	ret->has_canary = 0;
	ret->has_retguard = -1;
	if (R_SYS_BITS & R_SYS_BITS_64) {
		ret->bits = 64;
	} else {
		ret->bits = 32;
	}
	ret->big_endian = 0;
	ret->has_va = 0;
	ret->has_nx = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static void destroy(RBinFile *bf) {
	rz_buf_free (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

RBinPlugin rz_bin_plugin_any = {
	.name = "any",
	.desc = "Dummy format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.baddr = &baddr,
	.info = info,
	.minstrlen = 0,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_any,
	.version = R2_VERSION
};
#endif
