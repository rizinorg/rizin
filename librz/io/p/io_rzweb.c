// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "rz_io_plugins.h"

typedef struct {
	int fd;
	char *url;
} RzIOR2Web;

#define rFD(x)  (((RzIOR2Web *)(x)->data)->fd)
#define rURL(x) (((RzIOR2Web *)(x)->data)->url)

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	int code, rlen;
	char *out, *url, *hexbuf;
	if (!fd || !fd->data) {
		return -1;
	}
	if (count * 3 < count) {
		return -1;
	}
	hexbuf = malloc(count * 3);
	if (!hexbuf) {
		return -1;
	}
	hexbuf[0] = 0;
	rz_hex_bin2str(buf, count, hexbuf);
	url = rz_str_newf("%s/wx%%20%s@%" PFMT64d,
		rURL(fd), hexbuf, io->off);
	out = rz_socket_http_get(url, &code, &rlen);
	free(out);
	free(url);
	free(hexbuf);
	return count;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	int code, rlen;
	char *out, *url;
	int ret = 0;
	if (!fd || !fd->data) {
		return -1;
	}
	url = rz_str_newf("%s/p8%%20%" PFMTSZd "@0x%" PFMT64x,
		rURL(fd), count, io->off);
	out = rz_socket_http_get(url, &code, &rlen);
	if (out && rlen > 0) {
		ut8 *tmp = calloc(1, rlen + 1);
		if (!tmp) {
			goto beach;
		}
		ret = rz_hex_str2bin(out, tmp);
		memcpy(buf, tmp, RZ_MIN(count, rlen));
		free(tmp);
		if (ret < 0) {
			ret = -ret;
		}
	}

beach:
	free(out);
	free(url);
	return ret;
}

static int __close(RzIODesc *fd) {
	RzIOR2Web *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	RZ_FREE(riom->url);
	RZ_FREE(fd->data);
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return UT64_MAX;
	}
	return offset;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	const char *uri = "rzweb://";
	return (!strncmp(pathname, uri, strlen(uri)));
}

static inline int getmalfd(RzIOR2Web *mal) {
	return 0xfffffff & (int)(size_t)mal;
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	char *out;
	int rlen, code;
	if (__plugin_open(io, pathname, 0)) {
		RzIOR2Web *mal = RZ_NEW0(RzIOR2Web);
		if (!mal) {
			return NULL;
		}
		char *path = rz_str_dup(pathname + 8);
		int path_len = strlen(path);
		if (path_len > 0) {
			if (path[path_len - 1] == '/') {
				path[path_len - 1] = 0;
			}
		}
		char *url = rz_str_newf("http://%s/?V", path);
		// eprintf  ("URL:(%s)\n", url);
		out = rz_socket_http_get(url, &code, &rlen);
		// eprintf ("RES %d %d\n", code, rlen);
		// eprintf ("OUT(%s)\n", out);
		if (out && rlen > 0) {
			mal->fd = getmalfd(mal);
			mal->url = rz_str_newf("http://%s", path);
			free(path);
			free(out);
			free(url);
			return rz_io_desc_new(io, &rz_io_plugin_rzweb,
				pathname, rw, mode, mal);
		}
		free(url);
		free(mal);
		free(out);
		free(path);
		eprintf("Error: Try http://localhost:9090/cmd/");
	}
	return NULL;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *command) {
	if (!*command) {
		return NULL;
	}
	int code, rlen;
	char *cmd = rz_str_uri_encode(command);
	char *url = rz_str_newf("%s/%s", rURL(fd), cmd);
	char *out = rz_socket_http_get(url, &code, &rlen);
	if (out && rlen > 0) {
		io->cb_printf("%s", out);
	}
	free(out);
	free(url);
	free(cmd);
	return NULL;
}

RzIOPlugin rz_io_plugin_rzweb = {
	.name = "rzweb",
	.desc = "rzweb io client plugin",
	.uris = "rzweb://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_rzweb,
	.version = RZ_VERSION
};
#endif
