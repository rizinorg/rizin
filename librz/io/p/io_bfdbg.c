// SPDX-FileCopyrightText: 2011-2013 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#undef RZ_API
#define RZ_API static inline
#include "../debug/p/bfvm.h"
#include "../debug/p/bfvm.c"

typedef struct {
	ut32 magic;
	int fd;
	ut8 *buf;
	ut32 size;
	BfvmCPU *bfvm;
} RzIOBfdbg;

#define RzIOBFDBG_FD(x)  (((RzIOBfdbg *)(x)->data)->fd)
#define RzIOBFDBG_SZ(x)  (((RzIOBfdbg *)(x)->data)->size)
#define RzIOBFDBG_BUF(x) (((RzIOBfdbg *)(x)->data)->buf)

static inline int is_in_screen(ut64 off, BfvmCPU *c) {
	return (off >= c->screen && off < c->screen + c->screen_size);
}

static inline int is_in_input(ut64 off, BfvmCPU *c) {
	return (off >= c->input && off < c->input + c->input_size);
}

static inline int is_in_base(ut64 off, BfvmCPU *c) {
	return (off >= c->base && off < c->base + c->size);
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	RzIOBfdbg *riom;
	int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	/* data base buffer */
	if (is_in_base(io->off, riom->bfvm)) {
		int n = io->off - riom->bfvm->base;
		if (n > count) {
			count = n;
		}
		memcpy(riom->bfvm->mem + n, buf, count);
		return count;
	}
	/* screen buffer */
	if (is_in_screen(io->off, riom->bfvm)) {
		int n = io->off - riom->bfvm->screen;
		if (n > count) {
			count = riom->bfvm->screen_size - n;
		}
		memcpy(riom->bfvm->screen_buf + n, buf, count);
		return count;
	}
	/* input buffer */
	if (is_in_input(io->off, riom->bfvm)) {
		int n = io->off - riom->bfvm->input;
		if (n > count) {
			count = riom->bfvm->input_size - n;
		}
		memcpy(riom->bfvm->input_buf + n, buf, count);
		return count;
	}
	/* read from file */
	sz = RzIOBFDBG_SZ(fd);
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	if (io->off >= sz) {
		return -1;
	}
	memcpy(RzIOBFDBG_BUF(fd) + io->off, buf, count);
	return count;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	RzIOBfdbg *riom;
	int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	/* data base buffer */
	if (is_in_base(io->off, riom->bfvm)) {
		int n = io->off - riom->bfvm->base;
		if (n > count) {
			count = n;
		}
		memcpy(buf, riom->bfvm->mem + n, count);
		return count;
	}
	/* screen buffer */
	if (is_in_screen(io->off, riom->bfvm)) {
		int n = io->off - riom->bfvm->screen;
		if (n > count) {
			count = riom->bfvm->screen_size - n;
		}
		memcpy(buf, riom->bfvm->screen_buf + n, count);
		return count;
	}
	/* input buffer */
	if (is_in_input(io->off, riom->bfvm)) {
		int n = io->off - riom->bfvm->input;
		if (n > count) {
			count = riom->bfvm->input_size - n;
		}
		memcpy(buf, riom->bfvm->input_buf + n, count);
		return count;
	}
	/* read from file */
	sz = RzIOBFDBG_SZ(fd);
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	if (io->off >= sz) {
		return -1;
	}
	memcpy(buf, RzIOBFDBG_BUF(fd) + io->off, count);
	return count;
}

static int __close(RzIODesc *fd) {
	RzIOBfdbg *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	bfvm_free(riom->bfvm);
	RZ_FREE(riom->buf);
	RZ_FREE(fd->data);
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RzIOBFDBG_SZ(fd);
	}
	return offset;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "bfdbg://", 8));
}

static inline int getmalfd(RzIOBfdbg *mal) {
	return 0xffff & (int)(size_t)mal->buf;
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	char *out;
	if (__plugin_open(io, pathname, 0)) {
		RzIOBind iob;
		RzIOBfdbg *mal = RZ_NEW0(RzIOBfdbg);
		if (!mal) {
			return NULL;
		}
		rz_io_bind(io, &iob);
		mal->fd = getmalfd(mal);
		mal->bfvm = bfvm_new(&iob);
		if (!mal->bfvm) {
			free(mal);
			return NULL;
		}
		size_t rlen;
		out = rz_file_slurp(pathname + 8, &rlen);
		if (!out || rlen < 1) {
			free(mal);
			free(out);
			return NULL;
		}
		mal->size = (ut32)rlen;
		mal->buf = malloc(mal->size + 1);
		if (mal->buf != NULL) {
			memcpy(mal->buf, out, rlen);
			free(out);
			return rz_io_desc_new(io, &rz_io_plugin_bfdbg,
				pathname, rw, mode, mal);
		}
		eprintf("Cannot allocate (%s) %" PFMT32u " byte(s)\n",
			pathname + 9, mal->size);
		free(mal);
		free(out);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_bfdbg = {
	.name = "bfdbg",
	.desc = "Attach to brainfuck Debugger instance",
	.license = "LGPL3",
	.uris = "bfdbg://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_bfdbg,
	.version = RZ_VERSION
};
#endif
