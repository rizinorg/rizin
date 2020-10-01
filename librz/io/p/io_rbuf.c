/* rizin - LGPL - Copyright 2017 - pancake, condret */

#include "rz_io.h"
#include "rz_lib.h"
#include <rz_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	RBuffer *b = fd->data;
	return rz_buf_write (b, buf, count);
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	RBuffer *b = fd->data;
	return rz_buf_read (b, buf, count);
}

static int __close(RzIODesc *fd) {
	RBuffer *b = fd->data;
	rz_buf_free (b);
	return 0;
}

static ut64 __lseek(RzIO* io, RzIODesc *fd, ut64 offset, int whence) {
	RBuffer *buf = fd->data;
	return rz_buf_seek (buf, offset, whence);
}

static bool __check(RzIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "rbuf://", 7));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	RzIODesc *desc;
	RBuffer *buf = rz_buf_new ();
	if (buf && (desc = rz_io_desc_new (io, &rz_io_plugin_rbuf, pathname, 7, 0, buf))) {
		return desc;
	}
	rz_buf_free (buf);
	return NULL;
}

RzIOPlugin rz_io_plugin_rbuf = {
	.name = "rbuf",
	.desc = "RBuffer IO plugin",
	.uris = "rbuf://",
	.license = "LGPL",
	.open = __open,
	.close = __close,
	.read = __read,
	.lseek = __lseek,
	.write = __write,
	.check = __check
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &rz_io_plugin_rbuf,
	.version = R2_VERSION
};
#endif
