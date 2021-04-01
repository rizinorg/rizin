// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "io_memory.h"

static inline ut32 _io_malloc_sz(RzIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RzIOMalloc *mal = (RzIOMalloc *)desc->data;
	return mal ? mal->size : 0;
}

static inline void _io_malloc_set_sz(RzIODesc *desc, ut32 sz) {
	if (!desc) {
		return;
	}
	RzIOMalloc *mal = (RzIOMalloc *)desc->data;
	if (mal) {
		mal->size = sz;
	}
}

static inline ut8 *_io_malloc_buf(RzIODesc *desc) {
	if (!desc) {
		return NULL;
	}
	RzIOMalloc *mal = (RzIOMalloc *)desc->data;
	return mal->buf;
}

static inline ut8 *_io_malloc_set_buf(RzIODesc *desc, ut8 *buf) {
	if (!desc) {
		return NULL;
	}
	RzIOMalloc *mal = (RzIOMalloc *)desc->data;
	return mal->buf = buf;
}

static inline ut64 _io_malloc_off(RzIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RzIOMalloc *mal = (RzIOMalloc *)desc->data;
	return mal->offset;
}

static inline void _io_malloc_set_off(RzIODesc *desc, ut64 off) {
	if (!desc) {
		return;
	}
	RzIOMalloc *mal = (RzIOMalloc *)desc->data;
	mal->offset = off;
}

int io_memory_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	if (_io_malloc_off(fd) > _io_malloc_sz(fd)) {
		return -1;
	}
	if (_io_malloc_off(fd) + count > _io_malloc_sz(fd)) {
		count -= (_io_malloc_off(fd) + count - _io_malloc_sz(fd));
	}
	if (count > 0) {
		memcpy(_io_malloc_buf(fd) + _io_malloc_off(fd), buf, count);
		_io_malloc_set_off(fd, _io_malloc_off(fd) + count);
		return count;
	}
	return -1;
}

bool io_memory_resize(RzIO *io, RzIODesc *fd, ut64 count) {
	ut8 *new_buf = NULL;
	if (!fd || !fd->data || count == 0) {
		return false;
	}
	ut32 mallocsz = _io_malloc_sz(fd);
	if (_io_malloc_off(fd) > mallocsz) {
		return false;
	}
	new_buf = malloc(count);
	if (!new_buf) {
		return false;
	}
	memcpy(new_buf, _io_malloc_buf(fd), RZ_MIN(count, mallocsz));
	if (count > mallocsz) {
		memset(new_buf + mallocsz, 0, count - mallocsz);
	}
	free(_io_malloc_buf(fd));
	_io_malloc_set_buf(fd, new_buf);
	_io_malloc_set_sz(fd, count);
	return true;
}

int io_memory_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	memset(buf, 0xff, count);
	if (!fd || !fd->data) {
		return -1;
	}
	ut32 mallocsz = _io_malloc_sz(fd);
	if (_io_malloc_off(fd) > mallocsz) {
		return -1;
	}
	if (_io_malloc_off(fd) + count >= mallocsz) {
		count = mallocsz - _io_malloc_off(fd);
	}
	memcpy(buf, _io_malloc_buf(fd) + _io_malloc_off(fd), count);
	_io_malloc_set_off(fd, _io_malloc_off(fd) + count);
	return count;
}

int io_memory_close(RzIODesc *fd) {
	RzIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	RZ_FREE(riom->buf);
	RZ_FREE(fd->data);
	return 0;
}

ut64 io_memory_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	ut64 rz_offset = offset;
	if (!fd || !fd->data) {
		return offset;
	}
	ut32 mallocsz = _io_malloc_sz(fd);
	switch (whence) {
	case SEEK_SET:
		rz_offset = (offset <= mallocsz) ? offset : mallocsz;
		break;
	case SEEK_CUR:
		rz_offset = (_io_malloc_off(fd) + offset <= mallocsz) ? _io_malloc_off(fd) + offset : mallocsz;
		break;
	case SEEK_END:
		rz_offset = _io_malloc_sz(fd);
		break;
	}
	_io_malloc_set_off(fd, rz_offset);
	return rz_offset;
}
