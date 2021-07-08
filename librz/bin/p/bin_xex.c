// SPDX-FileCopyrightText: 2021 smac89 <noblechuk5[at]web[dot]de>
// SPDX-License-Identifier: LPGL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include <string.h>
#include "librz/bin/format/xex/xex.h"

/**
 * \brief Check the buffer for the existence of the xex magic string
 *
 * \param b buffer connected to the binary file contents
 */
static bool check_buffer(RzBuffer *b) {
	RZ_LOG_DEBUG("[xex] check_buffer\n");
	if (rz_buf_size(b) >= XEX_MAGIC_SIZE) {
		ut8 buff[XEX_MAGIC_SIZE];
		rz_buf_read_at(b, XEX_MAGIC_OFFSET, buff, XEX_MAGIC_SIZE);
		return !memcmp(buff, XEX_MAGIC, XEX_MAGIC_SIZE);
	}
	return false;
}

static bool load_buffer(RZ_UNUSED RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, RZ_UNUSED Sdb *sdb) {
	RZ_LOG_DEBUG("[xex] load_buffer\n");
	RzBinXex *xex_bin = xex_parse(b);
	if (xex_bin) {
		*bin_obj = xex_bin;
		return true;
	}
	return false;
}

/**
 * \brief Called to initialize the headers of the file
 *
 * \param bf the xex binary file abstraction
 */
static void init_header(RzBinFile *bf) {
	RZ_LOG_DEBUG("[xex] header\n");
	RzBinXex *xex_bin = bf->o->bin_obj;
	construct_header(xex_bin, bf->buf);
}

/**
 * \brief Called to free any data used by this plugin
 *
 * \param bf the xex binary file abstraction
 */
static void destroy(RzBinFile *bf) {
	RZ_LOG_DEBUG("[xex] destroy\n");
	xex_destroy_bin((RzBinXex **)(&bf->o->bin_obj));

	rz_return_if_fail(NULL == bf->o->bin_obj);
}

// http://meseec.ce.rit.edu/551-projects/fall2016/3-4.pdf
static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret)
		return NULL;

	if (!bf || !bf->buf) {
		free(ret);
		return NULL;
	}
	ret->big_endian = 1;
	ret->has_crypto = 1;
	ret->file = strdup(bf->file);
	ret->type = strdup("Xbox 360 XEX file");
	ret->machine = strdup("Xbox system software");
	ret->os = strdup("Xbox 360");
	ret->arch = strdup("ppc");
	ret->bits = 64;

	return ret;
}

struct rz_bin_plugin_t rz_bin_plugin_xex = {
	.name = "xex",
	.desc = "XEX is the executable file format used by the Xbox 360 operating system",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.header = &init_header,
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
