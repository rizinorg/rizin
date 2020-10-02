/* radare - LGPL - Copyright 2008-2020 - pancake */

#include "rz_io.h"
#include "rz_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
} RzIOMalloc;

#define RzIOHTTP_FD(x) (((RzIOMalloc*)(x)->data)->fd)
#define RzIOHTTP_SZ(x) (((RzIOMalloc*)(x)->data)->size)
#define RzIOHTTP_BUF(x) (((RzIOMalloc*)(x)->data)->buf)

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	if (io->off + count > RzIOHTTP_SZ (fd)) {
		return -1;
	}
	memcpy (RzIOHTTP_BUF (fd)+io->off, buf, count);
	return count;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	unsigned int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	sz = RzIOHTTP_SZ (fd);
	if (io->off >= sz) {
		return -1;
	}
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	memcpy (buf, RzIOHTTP_BUF (fd) + io->off, count);
	return count;
}

static int __close(RzIODesc *fd) {
	RzIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RzIOHTTP_SZ (fd);
	}
	return offset;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "http://", 7));
}

static inline int getmalfd (RzIOMalloc *mal) {
	return (UT32_MAX >> 1) & (int)(size_t)mal->buf;
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	char *out;
	int rlen, code;
	if (__plugin_open (io, pathname, 0)) {
		out = rz_socket_http_get (pathname, &code, &rlen);
		if (out) {
			RzIOMalloc *mal = R_NEW0 (RzIOMalloc);
			if (!mal) {
				return NULL;
			}
			mal->size = rlen;
			mal->buf = malloc (mal->size+1);
			if (!mal->buf) {
				free (mal);
				return NULL;
			}
			if (mal->buf != NULL) {
				mal->fd = getmalfd (mal);
				memcpy (mal->buf, out, mal->size);
				free (out);
				return rz_io_desc_new (io, &rz_io_plugin_http,
					pathname, rw, mode, mal);
			}
			eprintf ("Cannot allocate (%s) %d byte(s)\n", pathname+9, mal->size);
			free (mal);
		}
		free (out);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_http = {
	.name = "http",
	.desc = "Make http get requests",
	.uris = "http://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &rz_io_plugin_http,
	.version = RZ_VERSION
};
#endif
