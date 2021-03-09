// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"
#include <sys/types.h>

#if __ANDROID__ || EMSCRIPTEN
#undef __UNIX__
#define __UNIX__ 0
#endif

// linux requires -lrt for this, but still it seems to not work as expected
// better not to enable it by default until we get enough time to properly
// make this work across all unixes without adding extra depenencies
#define USE_SHM_OPEN 0

#if __UNIX__ && !defined(__QNX__) && !defined(__HAIKU__)
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>

typedef struct {
	int fd;
	int id;
	ut8 *buf;
	ut32 size;
} RzIOShm;
#define RzIOSHM_FD(x) (((RzIOShm *)(x))->fd)

#define SHMATSZ 0x9000; // 32*1024*1024; /* 32MB : XXX not used correctly? */

static int shm__write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzIOShm *shm = fd->data;
	if (shm->buf) {
		(void)memcpy(shm->buf + io->off, buf, count);
		return count;
	}
	return write(shm->fd, buf, count);
}

static int shm__read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzIOShm *shm = fd->data;
	if (io->off + count >= shm->size) {
		if (io->off > shm->size) {
			return -1;
		}
		count = shm->size - io->off;
	}
	if (shm->buf) {
		memcpy(buf, shm->buf + io->off, count);
		return count;
	}
	return read(shm->fd, buf, count);
}

static int shm__close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);
	int ret;
	RzIOShm *shm = fd->data;
	if (shm->buf) {
		ret = shmdt(((RzIOShm *)(fd->data))->buf);
	} else {
		ret = close(shm->fd);
	}
	RZ_FREE(fd->data);
	return ret;
}

static ut64 shm__lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzIOShm *shm = fd->data;
	switch (whence) {
	case SEEK_SET:
		return io->off = offset;
	case SEEK_CUR:
		if (io->off + offset > shm->size) {
			return io->off = shm->size;
		}
		io->off += offset;
		return io->off;
	case SEEK_END:
		return 0xffffffff;
	}
	return io->off;
}

static bool shm__plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "shm://", 6));
}

static inline int getshmfd(RzIOShm *shm) {
	return (((int)(size_t)shm->buf) >> 4) & 0xfff;
}

static RzIODesc *shm__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp(pathname, "shm://", 6)) {
		RzIOShm *shm = RZ_NEW0(RzIOShm);
		if (!shm) {
			return NULL;
		}
		const char *ptr = pathname + 6;
		shm->id = atoi(ptr);
		if (!shm->id) {
			shm->id = rz_str_hash(ptr);
		}
		shm->buf = shmat(shm->id, 0, 0);
		if (shm->buf == (void *)(size_t)-1) {
#if USE_SHM_OPEN
			shm->buf = NULL;
			shm->fd = shm_open(ptr, O_CREAT | (rw ? O_RDWR : O_RDONLY), 0644);
#else
			shm->fd = -1;
#endif

		} else {
			shm->fd = getshmfd(shm);
		}
		shm->size = SHMATSZ;
		if (shm->fd != -1) {
			eprintf("Connected to shared memory 0x%08x\n", shm->id);
			return rz_io_desc_new(io, &rz_io_plugin_shm, pathname, rw, mode, shm);
		}
		eprintf("Cannot connect to shared memory (%d)\n", shm->id);
		free(shm);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_shm = {
	.name = "shm",
	.desc = "Shared memory resources plugin",
	.uris = "shm://",
	.license = "MIT",
	.open = shm__open,
	.close = shm__close,
	.read = shm__read,
	.check = shm__plugin_open,
	.lseek = shm__lseek,
	.write = shm__write,
};

#else
RzIOPlugin rz_io_plugin_shm = {
	.name = "shm",
	.desc = "shared memory resources (not for w32)",
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_shm,
	.version = RZ_VERSION
};
#endif
