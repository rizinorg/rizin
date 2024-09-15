// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_io.h>
#include <rz_lib.h>
#include <stdio.h>

#include "rz_io_plugins.h"

typedef struct rz_io_mmo_t {
	char *filename;
	int mode;
	int perm;
	bool nocache;
	ut8 modified;
	RzBuffer *buf;
} RzIOMMapFileObj;

static int iowhence2buf(int whence) {
	switch (whence) {
	case RZ_IO_SEEK_CUR:
		return RZ_BUF_CUR;
	case RZ_IO_SEEK_SET:
		return RZ_BUF_SET;
	case RZ_IO_SEEK_END:
		return RZ_BUF_END;
	default:
		rz_warn_if_reached();
		return -1;
	}
}

static ut64 rz_io_def_mmap_seek(RzIO *io, RzIOMMapFileObj *mmo, ut64 offset, int whence) {
	rz_return_val_if_fail(io && mmo, UT64_MAX);
	// NOTE: io->off should not be set here and code outside RzIO should not
	// rely on it to get the current seek. They should use `rz_io_seek` instead.
	// Keep it here until all use cases of io->off are converted.
	st64 val = rz_buf_seek(mmo->buf, offset, iowhence2buf(whence));
	if (val == -1) {
		return -1;
	}
	return io->off = val;
}

static void rz_io_def_mmap_free(RzIOMMapFileObj *mmo) {
	if (!mmo) {
		return;
	}
	free(mmo->filename);
	rz_buf_free(mmo->buf);
	free(mmo);
}

static void disable_fd_cache(int fd) {
#if F_NOCACHE
	fcntl(fd, F_NOCACHE, 1);
#elif O_DIRECT
	int open_flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, open_flags | O_DIRECT);
#endif
}

RzIOMMapFileObj *rz_io_def_mmap_create_new_file(RzIO *io, const char *filename, int perm, int mode) {
	rz_return_val_if_fail(io && filename, NULL);
	RzIOMMapFileObj *mmo = RZ_NEW0(RzIOMMapFileObj);
	if (!mmo) {
		return NULL;
	}
	if (rz_str_startswith(filename, "file://")) {
		filename += strlen("file://");
	}
	mmo->nocache = rz_str_startswith(filename, "nocache://");
	if (mmo->nocache) {
		filename += strlen("nocache://");
	}
	mmo->filename = rz_str_dup(filename);
	mmo->perm = rz_sys_open_perms(perm);
	mmo->mode = mode;
	if (!mmo->nocache) {
		mmo->buf = rz_buf_new_mmap(mmo->filename, mmo->perm, mmo->mode);
	}
	if (!mmo->buf) {
		mmo->buf = rz_buf_new_file(mmo->filename, mmo->perm, mmo->mode);
		if (!mmo->buf) {
			rz_io_def_mmap_free(mmo);
			return NULL;
		}
		if (mmo->nocache) {
			disable_fd_cache(mmo->buf->fd);
		}
	}
	return mmo;
}

static int rz_io_def_mmap_close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);
	rz_io_def_mmap_free((RzIOMMapFileObj *)fd->data);
	fd->data = NULL;
	return 0;
}

static bool rz_io_def_mmap_check_default(const char *filename) {
	rz_return_val_if_fail(filename && *filename, false);
	if (rz_str_startswith(filename, "file://")) {
		filename += strlen("file://");
	}
	const char *peekaboo = (!strncmp(filename, "nocache://", 10))
		? NULL
		: strstr(filename, "://");
	return (!peekaboo || (peekaboo - filename) > 10);
}

static int rz_io_def_mmap_read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data && buf, -1);
	RzIOMMapFileObj *mmo = (RzIOMMapFileObj *)fd->data;
	rz_return_val_if_fail(mmo && mmo->buf, -1);
	return (int)rz_buf_read(mmo->buf, buf, count);
}

static int rz_io_def_mmap_write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(io && fd && fd->data && buf, -1);
	RzIOMMapFileObj *mmo = (RzIOMMapFileObj *)fd->data;
	rz_return_val_if_fail(mmo && mmo->buf, -1);
	return (int)rz_buf_write(mmo->buf, buf, count);
}

static RzIODesc *rz_io_def_mmap_open(RzIO *io, const char *file, int perm, int mode) {
	rz_return_val_if_fail(io && file, NULL);
	RzIOMMapFileObj *mmo = rz_io_def_mmap_create_new_file(io, file, perm, mode);
	if (!mmo) {
		return NULL;
	}
	RzIODesc *d = rz_io_desc_new(io, &rz_io_plugin_default, mmo->filename, perm, mode, mmo);
	if (!d->name) {
		d->name = rz_str_dup(mmo->filename);
	}
	return d;
}

static ut64 rz_io_def_mmap_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(fd && fd->data, UT64_MAX);
	return rz_io_def_mmap_seek(io, (RzIOMMapFileObj *)fd->data, offset, whence);
}

static int rz_io_def_mmap_truncate(RzIOMMapFileObj *mmo, ut64 size) {
	return rz_buf_resize(mmo->buf, size);
}

static bool __plugin_open_default(RzIO *io, const char *file, bool many) {
	return rz_io_def_mmap_check_default(file);
}

// default open should permit opening
static RzIODesc *__open_default(RzIO *io, const char *file, int perm, int mode) {
	if (rz_io_def_mmap_check_default(file)) {
		return rz_io_def_mmap_open(io, file, perm, mode);
	}
	return NULL;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t len) {
	return rz_io_def_mmap_read(io, fd, buf, len);
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t len) {
	return rz_io_def_mmap_write(io, fd, buf, len);
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	return rz_io_def_mmap_lseek(io, fd, offset, whence);
}

static int __close(RzIODesc *fd) {
	return rz_io_def_mmap_close(fd);
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 size) {
	rz_return_val_if_fail(io && fd && fd->data, false);
	RzIOMMapFileObj *mmo = fd->data;
	if (!(mmo->perm & RZ_PERM_W)) {
		return false;
	}
	return rz_io_def_mmap_truncate(mmo, size);
}

#if __UNIX__
static bool __is_blockdevice(RzIODesc *desc) {
	rz_return_val_if_fail(desc && desc->data, false);
	RzIOMMapFileObj *mmo = desc->data;
	struct stat buf;
	if (stat(mmo->filename, &buf) == -1) {
		return false;
	}
	return ((buf.st_mode & S_IFBLK) == S_IFBLK);
}
#endif

static ut8 *io_default_get_buf(RzIODesc *desc, ut64 *size) {
	rz_return_val_if_fail(desc && size, NULL);
	RzIOMMapFileObj *mmo = desc->data;
	return rz_buf_data(mmo->buf, size);
}

RzIOPlugin rz_io_plugin_default = {
	.name = "default",
	.desc = "Open local files",
	.license = "LGPL3",
	.uris = "file://,nocache://",
	.open = __open_default,
	.close = __close,
	.read = __read,
	.check = __plugin_open_default,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
#if __UNIX__
	.is_blockdevice = __is_blockdevice,
#endif
	.get_buf = io_default_get_buf
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_default,
	.version = RZ_VERSION
};
#endif
