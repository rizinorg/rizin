// SPDX-FileCopyrightText: 2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_socket.h>
#include <stdio.h>
#include <stdlib.h>
#include "../io_memory.h"

#include "rz_io_plugins.h"

static bool __check(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "tcp://", 6));
}

static ut8 *tcpme(const char *pathname, int *code, int *len) {
	pathname += 6;
	*code = 404;
#if __UNIX__
	rz_sys_signal(SIGINT, SIG_IGN);
#endif
	if (*pathname == ':') {
		/* listen and wait for connection */
		RzSocket *sl = rz_socket_new(false);
		if (!rz_socket_listen(sl, pathname + 1, NULL)) {
			eprintf("Cannot listen\n");
			rz_socket_free(sl);
			return NULL;
		}
		RzSocket *sc = rz_socket_accept(sl);
		ut8 *res = rz_socket_slurp(sc, len);
		rz_socket_free(sc);
		rz_socket_free(sl);
		if (res) {
			*code = 200;
			return res;
		}
	} else {
		/* connect and slurp the end point */
		char *host = rz_str_dup(pathname);
		if (!host) {
			return NULL;
		}
		char *port = strchr(host, ':');
		if (port) {
			*port++ = 0;
			RzSocket *s = rz_socket_new(false);
			if (rz_socket_connect(s, host, port, RZ_SOCKET_PROTO_TCP, 0)) {
				ut8 *res = rz_socket_slurp(s, len);
				if (*len < 1) {
					RZ_FREE(res);
				} else {
					*code = 200;
				}
				rz_socket_free(s);
				free(host);
				return res;
			}
			rz_socket_free(s);
		} else {
			eprintf("Missing port.\n");
		}
		free(host);
	}
	return NULL;
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (__check(io, pathname, 0)) {
		int rlen, code;
		RzIOMalloc *mal = RZ_NEW0(RzIOMalloc);
		if (!mal) {
			return NULL;
		}
		mal->offset = 0;
		mal->buf = tcpme(pathname, &code, &rlen);
		if (mal->buf && rlen > 0) {
			mal->size = rlen;
			return rz_io_desc_new(io, &rz_io_plugin_tcp, pathname, rw, mode, mal);
		}
		eprintf("No TCP segment\n");
		free(mal);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_tcp = {
	.name = "tcp",
	.desc = "Load files via TCP (listen or connect)",
	.uris = "tcp://",
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
	.data = &rz_io_plugin_tcp,
	.version = RZ_VERSION
};
#endif
