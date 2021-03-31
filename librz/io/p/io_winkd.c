// SPDX-FileCopyrightText: 2014-2017 The Lemon Man
// SPDX-License-Identifier: LGPL-3.0-only

// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3

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

	WindCtx *ctx = winkd_ctx_new(desc);
	if (!ctx) {
		eprintf("Failed to initialize winkd context\n");
		return NULL;
	}
	return rz_io_desc_new(io, &rz_io_plugin_winkd, file, rw, mode, ctx);
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}
	if (winkd_get_target(fd->data)) {
		return winkd_write_at_uva(fd->data, buf, io->off, count);
	}
	return winkd_write_at(fd->data, buf, io->off, count);
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
		return winkd_read_at_uva(fd->data, buf, io->off, count);
	}

	return winkd_read_at(fd->data, buf, io->off, count);
}

static int __close(RzIODesc *fd) {
	winkd_ctx_free((WindCtx **)&fd->data);
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
