// SPDX-FileCopyrightText: 2021 smac89 <noblechuk5[at]web[dot]de>
// SPDX-License-Identifier: LPGL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>
#include <rz_types.h>
#include "librz/bin/format/xex/xex.h"

/**
 * \brief Check the buffer for the existence of the xex magic string
 *
 * \param b
 */
static bool check_buffer(RzBuffer *b) {
    eprintf("[xex] check_buffer");
	if (rz_buf_size(b) >= XEX_MAGIC_SIZE) {
		ut8 buff[XEX_MAGIC_SIZE];
		rz_buf_read_at(b, XEX_MAGIC_OFFSET, buff, XEX_MAGIC_SIZE);
		return (!memcmp(buff, XEX_MAGIC, XEX_MAGIC_SIZE));
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	eprintf("[xex] load_buffer");
    return check_buffer(b);
}

static void destroy(RzBinFile *bf) {
    eprintf("[xex] destroy");
	// rz_bin_free_all_nes_obj(bf->o->bin_obj);
	// bf->o->bin_obj = NULL;
}

// http://meseec.ce.rit.edu/551-projects/fall2016/3-4.pdf
static RzBinInfo *info(RzBinFile *arch) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free(ret);
		return NULL;
	}
	ret->file = strdup(arch->file);
	ret->type = strdup("Xbox 360 XEX file");
	ret->machine = strdup("Xbox system software");
	ret->os = strdup("xex");
	ret->arch = strdup("x86_64");
	ret->bits = 8;

	return ret;
}

struct rz_bin_plugin_t rz_bin_plugin_xex = {
	.name = "xex",
	.desc = "XEX is the executable file format used by the Xbox 360 operating system",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = NULL,
	.sections = NULL,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_xex,
	.version = RZ_VERSION
};
#endif
