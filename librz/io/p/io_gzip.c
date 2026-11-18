// SPDX-FileCopyrightText: 2008-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <stdint.h>

#include "rz_io_plugins.h"

#define GZIP_MAX_OUTPUT 5000000000ULL

typedef struct {
	ut8 *buf;
	ut64 size;
	ut64 offset;
} RzIOGzip;

static inline ut64 _io_malloc_sz(RzIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RzIOGzip *mal = (RzIOGzip *)desc->data;
	return mal ? mal->size : 0;
}

static inline void _io_malloc_set_sz(RzIODesc *desc, ut64 sz) {
	if (!desc) {
		return;
	}
	RzIOGzip *mal = (RzIOGzip *)desc->data;
	if (mal) {
		mal->size = sz;
	}
}

static inline ut8 *_io_malloc_buf(RzIODesc *desc) {
	if (!desc) {
		return NULL;
	}
	RzIOGzip *mal = (RzIOGzip *)desc->data;
	return mal->buf;
}

static inline ut8 *_io_malloc_set_buf(RzIODesc *desc, ut8 *buf) {
	if (!desc) {
		return NULL;
	}
	RzIOGzip *mal = (RzIOGzip *)desc->data;
	return mal->buf = buf;
}

static inline ut64 _io_malloc_off(RzIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RzIOGzip *mal = (RzIOGzip *)desc->data;
	return mal->offset;
}

static inline void _io_malloc_set_off(RzIODesc *desc, ut64 off) {
	if (!desc) {
		return;
	}
	RzIOGzip *mal = (RzIOGzip *)desc->data;
	mal->offset = off;
}

static ut8 *__inflate_members(const ut8 *data, size_t len, ut64 *out_len) {
	if (!data || !out_len || len == 0 || len > INT_MAX) {
		return NULL;
	}
	ut8 *result = NULL;
	ut64 total = 0;
	size_t offset = 0;
	unsigned long long member = 0;
	while (offset < len) {
		int chunk_len = 0;
		int consumed = 0;
		ut8 *chunk = rz_inflate(data + offset, (int)(len - offset), &consumed, &chunk_len);
		if (!chunk) {
			eprintf("gzip: failed to decode member %llu at offset %llu\n", member, (unsigned long long)offset);
			goto fail;
		}
		if (consumed <= 0) {
			eprintf("gzip: inflate made no progress for member %llu at offset %llu\n", member, (unsigned long long)offset);
			free(chunk);
			goto fail;
		}
		ut64 chunk_size = (ut64)chunk_len;
		if (chunk_size > GZIP_MAX_OUTPUT - total || chunk_size > (ut64)SIZE_MAX - total) {
			eprintf("gzip: combined output exceeds the maximum allowed size\n");
			free(chunk);
			goto fail;
		}
		if (chunk_size == 0) {
			if (!result) {
				result = malloc(1);
				if (!result) {
					free(chunk);
					goto fail;
				}
			}
		} else {
			ut8 *new_result = realloc(result, (size_t)(total + chunk_size));
			if (!new_result) {
				free(chunk);
				goto fail;
			}
			memcpy(new_result + total, chunk, chunk_len);
			result = new_result;
		}
		free(chunk);
		total += chunk_size;
		offset += (size_t)consumed;
		member++;
	}
	if (!result) {
		result = malloc(1);
		if (!result) {
			goto fail;
		}
	}
	*out_len = total;
	return result;

fail:
	free(result);
	return NULL;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	ut64 mallocsz = _io_malloc_sz(fd);
	if (_io_malloc_off(fd) > mallocsz) {
		return -1;
	}
	if (count > mallocsz - _io_malloc_off(fd)) {
		count = (size_t)(mallocsz - _io_malloc_off(fd));
	}
	if (count > 0) {
		memcpy(_io_malloc_buf(fd) + _io_malloc_off(fd), buf, count);
		_io_malloc_set_off(fd, _io_malloc_off(fd) + count);
		return count;
	}
	return -1;
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 count) {
	ut8 *new_buf = NULL;
	if (!fd || !fd->data || count == 0) {
		return false;
	}
	ut64 mallocsz = _io_malloc_sz(fd);
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

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	memset(buf, 0xff, count);
	if (!fd || !fd->data) {
		return -1;
	}
	ut64 mallocsz = _io_malloc_sz(fd);
	if (_io_malloc_off(fd) > mallocsz) {
		return -1;
	}
	if (count >= mallocsz - _io_malloc_off(fd)) {
		count = (size_t)(mallocsz - _io_malloc_off(fd));
	}
	memcpy(buf, _io_malloc_buf(fd) + _io_malloc_off(fd), count);
	return count;
}

static int __close(RzIODesc *fd) {
	RzIOGzip *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	RZ_FREE(riom->buf);
	RZ_FREE(fd->data);
	eprintf("TODO: Writing changes into gzipped files is not yet supported\n");
	return 0;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	ut64 rz_offset = offset;
	if (!fd || !fd->data) {
		return offset;
	}
	ut64 mallocsz = _io_malloc_sz(fd);
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

static bool __plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "gzip://", 7));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open(io, pathname, 0)) {
		RzIOGzip *mal = RZ_NEW0(RzIOGzip);
		if (!mal) {
			return NULL;
		}
		size_t len;
		ut8 *data = (ut8 *)rz_file_slurp(pathname + 7, &len);
		mal->buf = __inflate_members(data, len, &mal->size);
		if (mal->buf) {
			free(data);
			return rz_io_desc_new(io, &rz_io_plugin_gzip, pathname, rw, mal);
		}
		free(data);
		eprintf("gzip://%s: failed to decode gzip members\n", pathname + 7);
		free(mal);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_gzip = {
	.name = "gzip",
	.desc = "Read/write gzipped files",
	.license = "LGPL3",
	.uris = "gzip://",
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
	.data = &rz_io_plugin_gzip,
	.version = RZ_VERSION
};
#endif
