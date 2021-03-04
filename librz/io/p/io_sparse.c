// SPDX-FileCopyrightText: 2015-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"
#include "rz_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	RzBuffer *buf;
	ut64 offset;
} RzIOSparse;

#define RzIOSPARSE_FD(x)  (((RzIOSparse *)(x)->data)->fd)
#define RzIOSPARSE_BUF(x) (((RzIOSparse *)(x)->data)->buf)
#define RzIOSPARSE_OFF(x) (((RzIOSparse *)(x)->data)->offset)

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	ut64 o;
	RzBuffer *b;
	if (!fd || !fd->data) {
		return -1;
	}
	b = RzIOSPARSE_BUF(fd);
	o = RzIOSPARSE_OFF(fd);
	int r = rz_buf_write_at(b, o, buf, count);
	if (r >= 0) {
		rz_buf_seek(b, r, RZ_BUF_CUR);
	}
	return r;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	ut64 o;
	RzBuffer *b;
	if (!fd || !fd->data) {
		return -1;
	}
	b = RzIOSPARSE_BUF(fd);
	o = RzIOSPARSE_OFF(fd);
	int r = rz_buf_read_at(b, o, buf, count);
	if (r >= 0) {
		rz_buf_seek(b, count, RZ_BUF_CUR);
	}
	return count;
}

static int __close(RzIODesc *fd) {
	RzIOSparse *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	RZ_FREE(riom->buf);
	RZ_FREE(fd->data);
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	RzBuffer *b;
	ut64 rz_offset = offset;
	if (!fd->data) {
		return offset;
	}
	b = RzIOSPARSE_BUF(fd);
	rz_offset = rz_buf_seek(b, offset, whence);
	//if (rz_offset != UT64_MAX)
	RzIOSPARSE_OFF(fd) = rz_offset;
	return rz_offset;
}

static bool __plugin_open(struct rz_io_t *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "sparse://", 9));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open(io, pathname, 0)) {
		RzIOSparse *mal = RZ_NEW0(RzIOSparse);
		int size = (int)rz_num_math(NULL, pathname + 9);
		mal->buf = rz_buf_new_sparse(io->Oxff);
		if (!mal->buf) {
			free(mal);
			return NULL;
		}
		if (size > 0) {
			ut8 *data = malloc(size);
			if (!data) {
				eprintf("Cannot allocate (%s) %d byte(s)\n",
					pathname + 9, size);
				mal->offset = 0;
			} else {
				memset(data, 0x00, size);
				rz_buf_write_at(mal->buf, 0, data, size);
				free(data);
			}
		}
		if (mal->buf) {
			return rz_io_desc_new(io, &rz_io_plugin_sparse,
				pathname, rw, mode, mal);
		}
		rz_buf_free(mal->buf);
		free(mal);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_sparse = {
	.name = "sparse",
	.desc = "Sparse buffer allocation plugin",
	.uris = "sparse://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = NULL,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_sparse,
	.version = RZ_VERSION
};
#endif
