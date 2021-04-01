// SPDX-FileCopyrightText: 2017 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_cons.h>
#include "ar.h"

static bool rz_io_ar_plugin_open(RzIO *io, const char *file, bool many) {
	return !strncmp("ar://", file, 5) || !strncmp("lib://", file, 6);
}

static RzIODesc *rz_io_ar_open(RzIO *io, const char *file, int perm, int mode) {
	RzIODesc *res = NULL;
	char *url = strdup(file);
	char *arname = strstr(url, "://") + 3;
	char *filename = strstr(arname, "//");
	if (filename) {
		*filename = 0;
		filename += 2;
	}

	RzArFp *arf = ar_open_file(arname, rz_sys_open_perms(perm), filename);
	if (arf) {
		res = rz_io_desc_new(io, &rz_io_plugin_ar, filename, perm, mode, arf);
	}
	free(url);
	return res;
}

static RzList *rz_io_ar_open_many(RzIO *io, const char *file, int rw, int mode) {
	eprintf("Not implemented\n");
	return NULL;
}

static ut64 rz_io_ar_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(io && fd && fd->data, -1);

	RzArFp *arf = (RzArFp *)fd->data;
	ut64 size = arf->end - arf->start;
	switch (whence) {
	case SEEK_SET:
		io->off = RZ_MIN(size, offset);
		break;
	case SEEK_CUR:
		io->off = RZ_MIN(size, io->off + offset);
		break;
	case SEEK_END:
		io->off = size;
		break;
	default:
		return -1;
	}

	return io->off;
}

static int rz_io_ar_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	return ar_read_at((RzArFp *)fd->data, io->off, buf, count);
}

static int rz_io_ar_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	return ar_write_at((RzArFp *)fd->data, io->off, (void *)buf, count);
}

static int rz_io_ar_close(RzIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	return ar_close((RzArFp *)fd->data);
}

RzIOPlugin rz_io_plugin_ar = {
	.name = "ar",
	.desc = "Open ar/lib files",
	.license = "LGPL3",
	.uris = "ar://,lib://",
	.open = rz_io_ar_open,
	.open_many = rz_io_ar_open_many,
	.write = rz_io_ar_write,
	.read = rz_io_ar_read,
	.close = rz_io_ar_close,
	.lseek = rz_io_ar_lseek,
	.check = rz_io_ar_plugin_open
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_ar,
	.version = RZ_VERSION
};
#endif
