// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <winkd.h>
#include "librz/bin/format/dmp/dmp_specs.h"

static bool dmp_plugin_open(RzIO *io, const char *file, bool many) {
	return (!strncmp(file, "dmp://", 6));
}

typedef struct {
	RzIO *io;
	RzIODesc *fd;
	DmpCtx *ctx;
} ReadAtCtx;

static int read_at_phys(ReadAtCtx *ctx, ut64 address, ut8 *buf, int len) {
	const ut64 saved_target = ctx->ctx->target;
	ctx->ctx->target = TARGET_BACKEND;
	int saved_va = ctx->io->va;
	ctx->io->va = 1;
	int ret = rz_io_nread_at(ctx->io, address, buf, len);
	ctx->io->va = saved_va;
	ctx->ctx->target = saved_target;
	return ret;
}

static int read_at_kernel_virtual(ReadAtCtx *ctx, ut64 address, ut8 *buf, int len) {
	if (ctx->ctx->type == DMP_DUMPTYPE_TRIAGE) {
		int saved_va = ctx->io->va;
		ctx->io->va = 1;
		int ret = rz_io_nread_at(ctx->io, address, buf, len);
		ctx->io->va = saved_va;
		return ret;
	} 
	return rz_io_desc_read_at(ctx->fd, address, buf, len);
}

static RzIODesc *dmp_open(RzIO *io, const char *file, int rw, int mode) {
	if (!dmp_plugin_open(io, file, 0)) {
		return NULL;
	}
	RzIOPlugin *p = rz_io_plugin_resolve(io, file + 6, false);
	if (!p) {
		return NULL;
	}
	DmpCtx *ctx = RZ_NEW0(DmpCtx);
	if (!ctx) {
		return NULL;
	}
	ctx->backend = p->open(io, file + 6, rw, mode);
	if (!ctx->backend) {
		free(ctx);
		return NULL;
	}
	ctx->target = TARGET_BACKEND;
	ctx->windctx.read_at_physical = read_at_phys;
	ctx->windctx.read_at_kernel_virtual = read_at_kernel_virtual;
	ReadAtCtx *c = RZ_NEW0(ReadAtCtx);
	if (!c) {
		free(ctx);
		return NULL;
	}
	c->ctx = ctx;
	c->io = io;
	c->fd = rz_io_desc_new(io, &rz_io_plugin_dmp, file, rw, mode, ctx);
	if (!c->fd) {
		free(c);
		free(ctx);
		return NULL;
	}
	c->fd->name = strdup(file + 6);
	ctx->windctx.user = c;
	return c->fd;
}

static int dmp_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}
	DmpCtx *ctx = fd->data;
	if (ctx->target == TARGET_BACKEND) {
		return rz_io_desc_write_at(ctx->backend, io->off, buf, count);
	}
	int ret;
	ut64 address = io->off;
	if (!ctx->target == TARGET_PHYSICAL) {
		WindProc saved_proc = ctx->windctx.target;
		WindProc kernel_proc = { .dir_base_table = ctx->kernelDirectoryTable };
		if (ctx->target == TARGET_KERNEL) {
			ctx->windctx.target = kernel_proc;
		}
		ret = winkd_write_at_uva(&ctx->windctx, buf, address, count);
		ctx->windctx.target = saved_proc;
		return ret;
	}
	const ut64 saved_target = ctx->target;
	const int saved_io_va = io->va;
	ctx->target = TARGET_BACKEND; // Use RzIOMap maps
	io->va = true;
	ret = rz_io_write_at(io, address, buf, count);
	io->va = saved_io_va;
	ctx->target = saved_target;
	return ret;
}

static ut64 dmp_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	DmpCtx *ctx = fd->data;
	if (ctx->target == TARGET_BACKEND) {
		return rz_io_desc_seek(ctx->backend, offset, whence);
	} else {
		switch (whence) {
		case RZ_IO_SEEK_SET: return io->off = offset;
		case RZ_IO_SEEK_CUR: return io->off += offset;
		case RZ_IO_SEEK_END: return io->off = UT64_MAX - offset;
		default: return offset;
		}
	}
}

static int dmp_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}
	DmpCtx *ctx = fd->data;
	if (ctx->target == TARGET_BACKEND) {
		return rz_io_desc_read_at(ctx->backend, io->off, buf, count);
	}
	int ret;
	ut64 address = io->off;
	if (ctx->target != TARGET_PHYSICAL) {
		WindProc saved_proc = ctx->windctx.target;
		WindProc kernel_proc = { .dir_base_table = ctx->kernelDirectoryTable };
		if (ctx->target == TARGET_KERNEL) {
			ctx->windctx.target = kernel_proc;
		}
		ret = winkd_read_at_uva(&ctx->windctx, buf, address, count);
		ctx->windctx.target = saved_proc;
		return ret;
	}
	const ut64 saved_target = ctx->target;
	const int saved_io_va = io->va;
	ctx->target = TARGET_BACKEND; // Use RzIOMap maps
	io->va = true;
	ret = rz_io_read_at(io, address, buf, count);
	io->va = saved_io_va;
	ctx->target = saved_target;
	return ret;
}

static int dmp_close(RzIODesc *fd) {
	DmpCtx *ctx = fd->data;
	rz_io_desc_close(ctx->backend);
	winkd_ctx_fini(&ctx->windctx);
	free(ctx->context);
	RZ_FREE(fd->data);
	return true;
}

RzIOPlugin rz_io_plugin_dmp = {
	.name = "dmp",
	.desc = "Debug a Windows DMP file",
	.uris = "dmp://",
	.license = "LGPL3",
	.open = dmp_open,
	.close = dmp_close,
	.read = dmp_read,
	.check = dmp_plugin_open,
	.lseek = dmp_lseek,
	.write = dmp_write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_dmp,
	.version = RZ_VERSION
};
#endif
