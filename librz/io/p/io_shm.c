// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>

#include "rz_io_plugins.h"

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__

static int shm__write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzShm *shm = fd->data;
	return rz_shm_write(shm, io->off, buf, count);
}

static int shm__read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzShm *shm = fd->data;
	return rz_shm_read(shm, io->off, buf, count);
}

static int shm__close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzShm *shm = fd->data;
	int ret = rz_shm_close(shm);
	rz_shm_free(shm);
	fd->data = NULL;
	return ret;
}

static ut64 shm__lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzShm *shm = fd->data;
	switch (whence) {
	case RZ_IO_SEEK_SET:
		return io->off = offset;
	case RZ_IO_SEEK_CUR:
		if (io->off + offset > shm->size) {
			return io->off = shm->size;
		}
		io->off += offset;
		return io->off;
	case RZ_IO_SEEK_END:
		return io->off = (shm->size ? shm->size : 0xffffffff) + offset;
	}
	return io->off;
}

static bool shm__plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "shm://", 6));
}

static RzIODesc *shm__open(RzIO *io, const char *file, int rw, int mode) {
	if (strncmp(file, "shm://", 6)) {
		return NULL;
	}
	char *uri = rz_str_dup(file);
	if (!uri) {
		return NULL;
	}
	char *name = strstr(uri, "://");
	if (!name) {
		free(uri);
		return NULL;
	}
	name += 3;

	// The shared memory size is an optional parameter
	size_t sz = 0;
	char *size = strstr(name, "/");
	if (size) {
		*size = 0;
		size += 1;
		sz = rz_num_math(NULL, size);
	}

	RzShm *shm = rz_shm_new();
	if (!shm) {
		free(uri);
		return NULL;
	}

	if (!rz_shm_open(shm, name, rw, sz)) {
		rz_shm_free(shm);
		free(uri);
		return NULL;
	}

	RzIODesc *desc = rz_io_desc_new(io, &rz_io_plugin_shm, uri, rw, shm);
	free(uri);
	return desc;
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
	.desc = "shared memory resources",
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_shm,
	.version = RZ_VERSION
};
#endif
