// SPDX-FileCopyrightText: 2008-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include "../io_memory.h"

static bool __check(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "malloc://", 9)) || (!strncmp(pathname, "hex://", 6));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (__check(io, pathname, 0)) {
		RzIOMalloc *mal = RZ_NEW0(RzIOMalloc);
		if (!mal) {
			return NULL;
		}
		if (!strncmp(pathname, "hex://", 6)) {
			mal->size = strlen(pathname);
			mal->buf = calloc(1, mal->size + 1);
			if (!mal->buf) {
				free(mal);
				return NULL;
			}
			mal->offset = 0;
			mal->size = rz_hex_str2bin(pathname + 6, mal->buf);
			if ((int)mal->size < 1) {
				RZ_FREE(mal->buf);
			}
		} else {
			mal->size = rz_num_math(NULL, pathname + 9);
			if (((int)mal->size) <= 0) {
				free(mal);
				eprintf("Cannot allocate (%s) 0 bytes\n", pathname + 9);
				return NULL;
			}
			mal->offset = 0;
			mal->buf = calloc(1, mal->size + 1);
		}
		if (mal->buf) {
			return rz_io_desc_new(io, &rz_io_plugin_malloc, pathname, RZ_PERM_RW | rw, mode, mal);
		}
		eprintf("Cannot allocate (%s) %d byte(s)\n", pathname + 9, mal->size);
		free(mal);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_malloc = {
	.name = "malloc",
	.desc = "Memory allocation plugin",
	.uris = "malloc://,hex://",
	.license = "LGPL3",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.lseek = io_memory_lseek,
	.write = io_memory_write,
	.resize = io_memory_resize,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_malloc,
	.version = RZ_VERSION
};
#endif
