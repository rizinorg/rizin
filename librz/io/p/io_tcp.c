/* radare - LGPL - Copyright 2016 - pancake */

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

#define RzIOTCP_FD(x) (((RzIOMalloc*)(x)->data)->fd)
#define RzIOTCP_SZ(x) (((RzIOMalloc*)(x)->data)->size)
#define RzIOTCP_BUF(x) (((RzIOMalloc*)(x)->data)->buf)

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	if (io->off + count > RzIOTCP_SZ (fd)) {
		return -1;
	}
	memcpy (RzIOTCP_BUF (fd)+io->off, buf, count);
	return count;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	unsigned int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	sz = RzIOTCP_SZ (fd);
	if (io->off >= sz) {
		return -1;
	}
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	memcpy (buf, RzIOTCP_BUF (fd) + io->off, count);
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
	case SEEK_END: return RzIOTCP_SZ (fd);
	}
	return offset;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "tcp://", 6));
}

static inline int getmalfd (RzIOMalloc *mal) {
	return (UT32_MAX >> 1) & (int)(size_t)mal->buf;
}

static ut8 *tcpme (const char *pathname, int *code, int *len) {
	pathname += 6;
	*code = 404;
#if __UNIX__
	rz_sys_signal (SIGINT, SIG_IGN);
#endif
	if (*pathname == ':') {
		/* listen and wait for connection */
		RzSocket *sl = rz_socket_new (false);
		if (!rz_socket_listen (sl, pathname + 1, NULL)) {
			eprintf ("Cannot listen\n");
			rz_socket_free (sl);
			return NULL;
		}
		RzSocket *sc = rz_socket_accept (sl);
		ut8 *res = rz_socket_slurp (sc, len);
		rz_socket_free (sc);
		rz_socket_free (sl);
		if (res) {
			*code = 200;
			return res;
		}
	} else {
		/* connect and slurp the end point */
		char *host = strdup (pathname);
		if (!host) {
			return NULL;
		}
		char *port = strchr (host, ':');
		if (port) {
			*port++ = 0;
			RzSocket *s = rz_socket_new (false);
			if (rz_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
				ut8 *res = rz_socket_slurp (s, len);
				if (*len < 1) {
					R_FREE (res);
				} else {
					*code = 200;
				}
				rz_socket_free (s);
				free (host);
				return res;
			}
			rz_socket_free (s);
		} else {
			eprintf ("Missing port.\n");
		}
		free (host);
	}
	return NULL;
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	ut8 *out;
	int rlen, code;
	if (__plugin_open (io, pathname, 0)) {
		out = tcpme (pathname, &code, &rlen);
		if (out && rlen > 0) {
			RzIOMalloc *mal = R_NEW0 (RzIOMalloc);
			if (!mal) {
				free (out);
				return NULL;
			}
			mal->size = rlen;
			mal->buf = malloc (mal->size + 1);
			if (!mal->buf) {
				free (mal);
				free (out);
				return NULL;
			}
			if (mal->buf != NULL) {
				mal->fd = getmalfd (mal);
				memcpy (mal->buf, out, mal->size);
				free (out);
				rw = 7;
				return rz_io_desc_new (io, &rz_io_plugin_tcp,
					pathname, rw, mode, mal);
			}
			eprintf ("Cannot allocate (%s) %d byte(s)\n", pathname + 9, mal->size);
			free (mal);
		}
		free (out);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_tcp = {
	.name = "tcp",
	.desc = "Load files via TCP (listen or connect)",
	.uris = "tcp://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &rz_io_plugin_tcp,
	.version = R2_VERSION
};
#endif
