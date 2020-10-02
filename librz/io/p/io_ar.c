/* radare - LGPLv3- Copyright 2017 - xarkes */
#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_cons.h>
#include "ar.h"


static bool rz_io_ar_plugin_open(RzIO *io, const char *file, bool many) {
	return !strncmp ("ar://", file, 5) || !strncmp ("lib://", file, 6);
}

static RzIODesc *rz_io_ar_open(RzIO *io, const char *file, int rw, int mode) {
	RzIODesc *res = NULL;
	char *url = strdup (file);
	char *arname = strstr (url, "://") + 3;
	char *filename = strstr (arname, "//");
	if (filename) {
		*filename = 0;
		filename += 2;
	}

	RBuffer *b = ar_open_file (arname, filename);
	if (b) {
		res = rz_io_desc_new (io, &rz_io_plugin_ar, filename, rw, mode, b);
	}
	free (url);
	return res;
}

static RzList *rz_io_ar_open_many(RzIO *io, const char *file, int rw, int mode) {
	eprintf ("Not implemented\n");
	return NULL;
}

static ut64 rz_io_ar_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	RBuffer *b;
	ut64 seek_val = 0;

	if (!fd || !fd->data) {
		return -1;
	}

	b = fd->data;
	seek_val = rz_buf_tell (b);

	switch (whence) {
	case SEEK_SET:
		seek_val = (rz_buf_size (b) < offset)? rz_buf_size (b) : offset;
		io->off = seek_val;
		rz_buf_seek (b, seek_val, RZ_BUF_SET);
		return seek_val;
	case SEEK_CUR:
		seek_val = (rz_buf_size (b) < offset)? rz_buf_size (b) : offset;
		io->off = seek_val;
		rz_buf_seek (b, seek_val, RZ_BUF_SET);
		return seek_val;
	case SEEK_END:
		seek_val = rz_buf_size (b);
		io->off = seek_val;
		rz_buf_seek (b, seek_val, RZ_BUF_SET);
		return seek_val;
	}
	return seek_val;
}

static int rz_io_ar_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	RBuffer *b;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	b = fd->data;
	return ar_read_at (b, io->off, buf, count);
}

static int rz_io_ar_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	RBuffer *b = NULL;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	return ar_write_at (b, io->off, (void *) buf, count);
}

static int rz_io_ar_close(RzIODesc *fd) {
	RBuffer *b = NULL;
	if (!fd || !fd->data) {
		return -1;
	}
	b = fd->data;
	return ar_close (b);
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
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_ar,
	.version = RZ_VERSION
};
#endif
