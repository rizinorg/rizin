// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"
#include "rz_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* --------------------------------------------------------- */
#define RZP(x) ((RzPipe *)(x)->data)

// TODO: add rzpipe_assert

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	char fmt[4096];
	char *bufn, bufnum[4096];
	int i, rv, rescount = -1;
	if (!fd || !fd->data) {
		return -1;
	}
	bufn = bufnum;
	*bufn = 0;
	for (i = 0; i < count; i++) {
		int bufn_sz = sizeof(bufnum) - (bufn - bufnum);
		snprintf(bufn, bufn_sz, "%s%d", i ? "," : "", buf[i]);
		bufn += strlen(bufn);
	}
	int len = snprintf(fmt, sizeof(fmt),
		"{\"op\":\"write\",\"address\":%" PFMT64d ",\"data\":[%s]}",
		io->off, bufnum);
	if (len >= sizeof(fmt)) {
		eprintf("rzpipe_write: error, fmt string has been truncated\n");
		return -1;
	}
	rv = rzpipe_write(RZP(fd), fmt);
	if (rv < 1) {
		eprintf("rzpipe_write: error\n");
		return -1;
	}
	rzpipe_read(RZP(fd));

	/* TODO: parse json back */
	return rescount;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	char fmt[4096], num[128];
	int rv, rescount = -1;
	int bufi, numi;
	char *res, *r;
	if (!fd || !fd->data) {
		return -1;
	}
	if (count > 1024) {
		count = 1024;
	}
	snprintf(fmt, sizeof(fmt),
		"{\"op\":\"read\",\"address\":%" PFMT64d ",\"count\":%d}",
		io->off, count);
	rv = rzpipe_write(RZP(fd), fmt);
	if (rv < 1) {
		eprintf("rzpipe_write: error\n");
		return -1;
	}
	res = rzpipe_read(RZP(fd));

	/* TODO: parse json back */
	r = strstr(res, "result");
	if (r) {
		rescount = atoi(r + 6 + 2);
	}
	r = strstr(res, "data");
	if (r) {
		char *arr = strchr(r, ':');
		if (!arr || arr[1] != '[') {
			goto beach;
		}
		arr += 2;
		for (num[0] = numi = bufi = 0; bufi < count && *arr; arr++) {
			switch (*arr) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				num[numi++] = *arr;
				num[numi] = 0;
				break;
			case ' ':
			case ',':
			case ']':
				if (num[0]) {
					buf[bufi++] = atoi(num);
					num[numi = 0] = 0;
				}
				break;
			case 'n':
			case 'u':
			case 'l':
				break;
			default:
				goto beach;
				break;
			}
		}
	}
beach:
	free(res);
	return rescount;
}

static int __close(RzIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	rzpipe_close(fd->data);
	fd->data = NULL;
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

static bool __check(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "rzpipe://", 9));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	RzPipe *rzp = NULL;
	if (__check(io, pathname, 0)) {
		rzp = rzpipe_open(pathname + 9);
	}
	return rzp ? rz_io_desc_new(io, &rz_io_plugin_rzpipe,
			     pathname, rw, mode, rzp)
		   : NULL;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *msg) {
	rz_return_val_if_fail(io && fd && msg, NULL);
	PJ *pj = pj_new();
	pj_o(pj);
	pj_ks(pj, "op", "system");
	pj_ks(pj, "cmd", msg);
	pj_end(pj);
	const char *fmt = pj_string(pj);
	int rv = rzpipe_write(RZP(fd), fmt);
	pj_free(pj);
	if (rv < 1) {
		eprintf("rzpipe_write: error\n");
		return NULL;
	}
	char *res = rzpipe_read(RZP(fd));
	//eprintf ("%s\n", res);
	/* TODO: parse json back */
	char *r = strstr(res, "result");
	if (r) {
		int rescount = atoi(r + 6 + 1);
		eprintf("RESULT %d\n", rescount);
	}
	free(res);
	return NULL;
}

RzIOPlugin rz_io_plugin_rzpipe = {
	.name = "rzpipe",
	.desc = "rzpipe io plugin",
	.license = "MIT",
	.uris = "rzpipe://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.system = __system
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_rzpipe,
	.version = RZ_VERSION
};
#endif
