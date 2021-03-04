// SPDX-FileCopyrightText: 2010-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_socket.h>
#include <rz_util.h>
#define IRAPI static inline
#include <libqnxr.h>

typedef struct {
	libqnxr_t desc;
} RzIOQnx;

static libqnxr_t *desc = NULL;
static RzIODesc *rioqnx = NULL;

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	return (!strncmp(file, "qnx://", 6));
}

/* hacky cache to speedup io a bit */
/* reading in a different place clears the previous cache */
static ut64 c_addr = UT64_MAX;
static ut32 c_size = UT32_MAX;
static ut8 *c_buff = NULL;
#define SILLY_CACHE 0

static int debug_qnx_read_at(ut8 *buf, int sz, ut64 addr) {
	ut32 size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;
	ut32 x;
	if (c_buff && addr != UT64_MAX && addr == c_addr) {
		memcpy(buf, c_buff, sz);
		return sz;
	}
	if (sz < 1 || addr >= UT64_MAX) {
		return -1;
	}
	for (x = 0; x < packets; x++) {
		qnxr_read_memory(desc, addr + x * size_max, (buf + x * size_max), size_max);
	}
	if (last) {
		qnxr_read_memory(desc, addr + x * size_max, (buf + x * size_max), last);
	}
	c_addr = addr;
	c_size = sz;
#if SILLY_CACHE
	free(c_buff);
	c_buff = rz_mem_dup(buf, sz);
#endif
	return sz;
}

static int debug_qnx_write_at(const ut8 *buf, int sz, ut64 addr) {
	ut32 x, size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;

	if (sz < 1 || addr >= UT64_MAX) {
		return -1;
	}
	if (c_addr != UT64_MAX && addr >= c_addr && c_addr + sz < (c_addr + c_size)) {
		RZ_FREE(c_buff);
		c_addr = UT64_MAX;
	}
	for (x = 0; x < packets; x++) {
		qnxr_write_memory(desc, addr + x * size_max,
			(const uint8_t *)(buf + x * size_max), size_max);
	}
	if (last) {
		qnxr_write_memory(desc, addr + x * size_max,
			(buf + x * size_max), last);
	}

	return sz;
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	RzIOQnx *rioq;
	char host[128], *port, *p;

	if (!__plugin_open(io, file, 0)) {
		return NULL;
	}
	if (rioqnx) {
		// FIX: Don't allocate more than one RzIODesc
		return rioqnx;
	}
	strncpy(host, file + 6, sizeof(host) - 1);
	host[sizeof(host) - 1] = '\0';
	port = strchr(host, ':');
	if (!port) {
		eprintf("Port not specified. Please use qnx://[host]:[port]\n");
		return NULL;
	}
	*port = '\0';
	port++;
	p = strchr(port, '/');
	if (p) {
		*p = 0;
	}

	rioq = RZ_NEW0(RzIOQnx);
	qnxr_init(&rioq->desc);
	int i_port = atoi(port);
	if (qnxr_connect(&rioq->desc, host, i_port) == 0) {
		desc = &rioq->desc;
		rioqnx = rz_io_desc_new(io, &rz_io_plugin_qnx, file, rw, mode, rioq);
		return rioqnx;
	}
	eprintf("qnx.io.open: Cannot connect to host.\n");
	free(rioq);
	return NULL;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	ut64 addr = io->off;
	if (!desc) {
		return -1;
	}
	return debug_qnx_write_at(buf, count, addr);
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	memset(buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc) {
		return -1;
	}
	return debug_qnx_read_at(buf, count, addr);
}

static int __close(RzIODesc *fd) {
	// TODO
	return -1;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	return NULL;
}

RzIOPlugin rz_io_plugin_qnx = {
	.name = "qnx",
	.license = "LGPL3",
	.desc = "Attach to QNX pdebug instance",
	.uris = "qnx://",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = true
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_qnx,
	.version = RZ_VERSION
};
#endif
