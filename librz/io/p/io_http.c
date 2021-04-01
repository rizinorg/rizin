// SPDX-FileCopyrightText: 2008-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include "../io_memory.h"

static bool __check(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "http://", 7));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (__check(io, pathname, 0)) {
		int rlen, code;
		RzIOMalloc *mal = RZ_NEW0(RzIOMalloc);
		if (!mal) {
			return NULL;
		}
		mal->offset = 0;
		mal->buf = (ut8 *)rz_socket_http_get(pathname, &code, &rlen);
		if (mal->buf && rlen > 0) {
			mal->size = rlen;
			return rz_io_desc_new(io, &rz_io_plugin_malloc, pathname, RZ_PERM_RW | rw, mode, mal);
		}
		eprintf("No HTTP response\n");
		free(mal);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_http = {
	.name = "http",
	.desc = "Make http get requests",
	.uris = "http://",
	.license = "LGPL3",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.lseek = io_memory_lseek,
	.write = io_memory_write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_http,
	.version = RZ_VERSION
};
#endif
