// SPDX-FileCopyrightText: 2014-2017 LemonBoy
// SPDX-License-Identifier: LGPL-3.0-only

// Copyright (c) 2014-2017, LemonBoy, All rights reserved. LGPLv3

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_socket.h>
#include <rz_util.h>
#include <transport.h>
#include <winkd.h>

typedef struct {
	RzIO *io;
	RzIODesc *fd;
} ReadAtCtx;

static int op_at_phys(void *user, ut64 address, const ut8 *in, ut8 *out, int len, bool write) {
	ReadAtCtx *ctx = user;
	int ret = write ? winkd_write_at_phys(ctx->fd->data, address, in, len) : winkd_read_at_phys(ctx->fd->data, address, out, len);
	return ret;
}

static int read_at_phys(void *user, ut64 address, ut8 *buf, int len) {
	return op_at_phys(user, address, NULL, buf, len, false);
}

static int write_at_phys(void *user, ut64 address, const ut8 *buf, int len) {
	return op_at_phys(user, address, buf, NULL, len, true);
}

static int read_at_kernel_virtual(void *user, ut64 address, ut8 *buf, int len) {
	ReadAtCtx *ctx = user;
	return winkd_read_at(ctx->fd->data, ctx->io->off, buf, len);
}

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	return (!strncmp(file, "winkd://", 8));
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	if (!__plugin_open(io, file, 0)) {
		return NULL;
	}

	// net  - host:ip:key
	// pipe - \\.\pipe\com_1 /tmp/windbg.pipe
	io_backend_t *iob = NULL;
	if (strchr(file + 8, ':')) {
		iob = &iob_net;
	} else {
		iob = &iob_pipe;
	}

	if (!iob) {
		eprintf("Error: Invalid WinDBG path\n");
		return NULL;
	}

	void *io_ctx = iob->open(file + 8);
	if (!io_ctx) {
		eprintf("Error: Could not open the %s\n", iob->name);
		return NULL;
	}
	eprintf("Opened %s %s with fd %p\n", iob->name, file + 8, io_ctx);

	io_desc_t *desc = io_desc_new(iob, io_ctx);
	if (!desc) {
		eprintf("Error: Could not create io_desc_t\n");
		return NULL;
	}

	KdCtx *ctx = winkd_kdctx_new(desc);
	if (!ctx) {
		eprintf("Failed to initialize winkd context\n");
		return NULL;
	}
	ctx->windctx.read_at_physical = read_at_phys;
	ctx->windctx.write_at_physical = write_at_phys;
	ctx->windctx.read_at_kernel_virtual = read_at_kernel_virtual;
	ReadAtCtx *c = RZ_NEW0(ReadAtCtx);
	if (!c) {
		free(ctx);
		return NULL;
	}
	c->io = io;
	c->fd = rz_io_desc_new(io, &rz_io_plugin_winkd, file, rw, mode, ctx);
	if (!c->fd) {
		free(c);
		free(ctx);
		return NULL;
	}
	ctx->windctx.user = c;
	return c->fd;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}
	if (winkd_get_target(fd->data)) {
		return winkd_write_at_uva(fd->data, io->off, buf, count);
	}
	return winkd_write_at(fd->data, io->off, buf, count);
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case RZ_IO_SEEK_SET:
		return io->off = offset;
	case RZ_IO_SEEK_CUR:
		return io->off + offset;
	case RZ_IO_SEEK_END:
		return ST64_MAX;
	default:
		return offset;
	}
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}

	if (winkd_get_target(fd->data)) {
		return winkd_read_at_uva(fd->data, io->off, buf, count);
	}

	return winkd_read_at(fd->data, io->off, buf, count);
}

static int __close(RzIODesc *fd) {
	winkd_kdctx_free((KdCtx **)&fd->data);
	return true;
}

RzIOPlugin rz_io_plugin_winkd = {
	.name = "winkd",
	.desc = "Attach to a KD debugger",
	.uris = "winkd://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.isdbg = true
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_winkd,
	.version = RZ_VERSION
};
#endif
