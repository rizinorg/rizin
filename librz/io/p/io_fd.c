// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <rz_cons.h>
#include <sys/types.h>

#if __WINDOWS__
#define FDURI "handle://"
#else
#define FDURI "fd://"
#endif

typedef struct {
	int fd;
} RzIOFdata;

static int __write(RzIO *io, RzIODesc *desc, const ut8 *buf, int count) {
	RzIOFdata *fdd = (RzIOFdata *)desc->data;
	if (fdd) {
		return write(fdd->fd, buf, count);
	}
	return -1;
}

static bool __resize(RzIO *io, RzIODesc *desc, ut64 count) {
	RzIOFdata *fdd = (RzIOFdata *)desc->data;
	if (fdd) {
		return ftruncate(fdd->fd, count) == 0;
	}
	return false;
}

static int __read(RzIO *io, RzIODesc *desc, ut8 *buf, int count) {
	RzIOFdata *fdd = (RzIOFdata *)desc->data;
	if (fdd) {
		rz_cons_break_push(NULL, NULL);
		int res = read(fdd->fd, buf, count);
		rz_cons_break_pop();
		return res;
	}
	return -1;
}

static int __close(RzIODesc *desc) {
	RZ_FREE(desc->data);
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *desc, ut64 offset, int whence) {
	RzIOFdata *fdd = (RzIOFdata *)desc->data;
	if (fdd) {
		return lseek(fdd->fd, offset, whence);
	}
	return 0;
}

static bool __check(RzIO *io, const char *pathname, bool many) {
	return !strncmp(pathname, FDURI, strlen(FDURI));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (!__check(io, pathname, 0)) {
		return NULL;
	}
	RzIOFdata *fdd = RZ_NEW0(RzIOFdata);
	if (fdd) {
		fdd->fd = rz_num_math(NULL, pathname + strlen(FDURI));
#if __WINDOWS__
		fdd->fd = _open_osfhandle(fdd->fd, 0);
#endif
		if (fdd->fd < 0) {
			free(fdd);
			eprintf("Invalid filedescriptor.\n");
			return NULL;
		}
	}
	return rz_io_desc_new(io, &rz_io_plugin_fd, pathname, RZ_PERM_RW | rw, mode, fdd);
}

RzIOPlugin rz_io_plugin_fd = {
#if __WINDOWS__
	.name = "handle",
	.desc = "Local process file handle IO",
#else
	.name = "fd",
	.desc = "Local process filedescriptor IO",
#endif
	.uris = FDURI,
	.license = "MIT",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_fd,
	.version = RZ_VERSION
};
#endif
