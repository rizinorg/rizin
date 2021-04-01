// SPDX-FileCopyrightText: 2017 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>

typedef struct {
	ut64 size;
	ut64 offset;
} RzIONull;

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	RzIONull *null;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	null = (RzIONull *)fd->data;
	if ((null->offset + count) > null->size) {
		int ret = null->size - null->offset;
		return ret;
	}
	null->offset += count;
	return count;
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 count) {
	if (fd && fd->data) {
		RzIONull *null = (RzIONull *)fd->data;
		null->size = count;
		if (null->offset >= count) {
			if (count) {
				null->offset = count - 1;
			} else {
				null->offset = 0LL;
			}
		}
		return true;
	}
	return false;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	RzIONull *null;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	null = (RzIONull *)fd->data;
	if ((null->offset + count) > null->size) {
		int ret = null->size - null->offset;
		memset(buf, 0x00, ret);
		null->offset = null->size;
		return ret;
	}
	memset(buf, 0x00, count);
	null->offset += count;
	return count;
}

static int __close(RzIODesc *fd) {
	RZ_FREE(fd->data);
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	RzIONull *null;
	if (!fd || !fd->data) {
		return offset;
	}
	null = (RzIONull *)fd->data;
	switch (whence) {
	case SEEK_SET:
		if (offset >= null->size) {
			return null->offset = null->size - 1;
		}
		return null->offset = offset;
	case SEEK_CUR:
		if ((null->offset + offset) >= null->size) {
			return null->offset = null->size - 1;
		}
		return null->offset += offset;
	case SEEK_END:
		return null->offset = null->size - 1;
	}
	return offset;
}

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "null://", 7));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	RzIONull *null;
	if (__plugin_open(io, pathname, 0)) {
		if (!strncmp(pathname, "null://", 7) && strlen(pathname + 7)) {
			null = RZ_NEW0(RzIONull);
			null->size = rz_num_math(NULL, pathname + 7) + 1; //???
			null->offset = 0LL;
			return rz_io_desc_new(io, &rz_io_plugin_null, pathname, rw, mode, null);
		}
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_null = {
	.name = "null",
	.desc = "Null plugin",
	.license = "LGPL3",
	.uris = "null://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_null,
	.version = RZ_VERSION
};
#endif
