// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_magic.h>

static char *get_filetype(RzBuffer *b) {
	ut8 buf[4096] = { 0 };
	char *res = NULL;
	RzMagic *ck = rz_magic_new(0);
	if (!ck) {
		return NULL;
	}
	const char *tmp = NULL;
	// TODO: dir.magic not honored here
	char *m = rz_str_rz_prefix(RZ_SDB_MAGIC);
	rz_magic_load(ck, m);
	free(m);
	rz_buf_read_at(b, 0, buf, sizeof(buf));
	tmp = rz_magic_buffer(ck, buf, sizeof(buf));
	if (tmp) {
		res = strdup(tmp);
	}
	rz_magic_free(ck);
	return res;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->lang = "";
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = get_filetype(bf->buf);
	ret->has_pi = 0;
	ret->has_canary = 0;
	ret->has_retguard = -1;
	ret->big_endian = 0;
	ret->has_va = 0;
	ret->has_nx = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0LL;
}

RzBinPlugin rz_bin_plugin_any = {
	.name = "any",
	.desc = "Dummy format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.baddr = &baddr,
	.info = info,
	.minstrlen = 0,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_any,
	.version = RZ_VERSION
};
#endif
