/* radare - LGPL - Copyright 2008-2017 - pancake */

#include "rz_io.h"
#include "rz_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	ut8 *buf;
	ut32 size;
	ut64 offset;
} RzIOMalloc;

static inline ut32 _io_malloc_sz(RzIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RzIOMalloc *mal = (RzIOMalloc*)desc->data;
	return mal? mal->size: 0;
}

static inline void _io_malloc_set_sz(RzIODesc *desc, ut32 sz) {
	if (!desc) {
		return;
	}
	RzIOMalloc *mal = (RzIOMalloc*)desc->data;
	if (mal) {
		mal->size = sz;
	}
}

static inline ut8* _io_malloc_buf(RzIODesc *desc) {
	if (!desc) {
		return NULL;
	}
	RzIOMalloc *mal = (RzIOMalloc*)desc->data;
	return mal->buf;
}


static inline ut8* _io_malloc_set_buf(RzIODesc *desc, ut8* buf) {
	if (!desc) {
		return NULL;
	}
	RzIOMalloc *mal = (RzIOMalloc*)desc->data;
	return mal->buf = buf;
}

static inline ut64 _io_malloc_off(RzIODesc *desc) {
	if (!desc) {
		return 0;
	}
	RzIOMalloc *mal = (RzIOMalloc*)desc->data;
	return mal->offset;
}

static inline void _io_malloc_set_off(RzIODesc *desc, ut64 off) {
	if (!desc) {
		return;
	}
	RzIOMalloc *mal = (RzIOMalloc*)desc->data;
	mal->offset = off;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !buf || count < 0 || !fd->data) {
		return -1;
	}
	if (_io_malloc_off (fd) > _io_malloc_sz (fd)) {
		return -1;
	}
	if (_io_malloc_off (fd) + count > _io_malloc_sz (fd)) {
		count -= (_io_malloc_off (fd) + count -_io_malloc_sz (fd));
	}
	if (count > 0) {
		memcpy (_io_malloc_buf (fd) + _io_malloc_off (fd), buf, count);
		_io_malloc_set_off (fd, _io_malloc_off (fd) + count);
		return count;
	}
	return -1;
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 count) {
	ut8 * new_buf = NULL;
	if (!fd || !fd->data || count == 0) {
		return false;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	if (_io_malloc_off (fd) > mallocsz) {
		return false;
	}
	new_buf = malloc (count);
	if (!new_buf) {
		return false;
	}
	memcpy (new_buf, _io_malloc_buf (fd), R_MIN (count, mallocsz));
	if (count > mallocsz) {
		memset (new_buf + mallocsz, 0, count - mallocsz);
	}
	free (_io_malloc_buf (fd));
	_io_malloc_set_buf (fd, new_buf);
	_io_malloc_set_sz (fd, count);
	return true;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (!fd || !fd->data) {
		return -1;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	if (_io_malloc_off (fd) > mallocsz) {
		return -1;
	}
	if (_io_malloc_off (fd) + count >= mallocsz) {
		count = mallocsz - _io_malloc_off (fd);
	}
	memcpy (buf, _io_malloc_buf (fd) + _io_malloc_off (fd), count);
	_io_malloc_set_off (fd, _io_malloc_off (fd) + count);
	return count;
}

static int __close(RzIODesc *fd) {
	RzIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return 0;
}

static ut64 __lseek(RzIO* io, RzIODesc *fd, ut64 offset, int whence) {
	ut64 rz_offset = offset;
	if (!fd || !fd->data) {
		return offset;
	}
	ut32 mallocsz = _io_malloc_sz (fd);
	switch (whence) {
	case SEEK_SET:
		rz_offset = (offset <= mallocsz) ? offset : mallocsz;
		break;
	case SEEK_CUR:
		rz_offset = (_io_malloc_off (fd) + offset <= mallocsz ) ? _io_malloc_off (fd) + offset : mallocsz;
		break;
	case SEEK_END:
		rz_offset = _io_malloc_sz (fd);
		break;
	}
	_io_malloc_set_off (fd, rz_offset);
	return rz_offset;
}

static bool __check(RzIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "malloc://", 9)) || (!strncmp (pathname, "hex://", 6));
}

static RzIODesc *__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		RzIOMalloc *mal = R_NEW0 (RzIOMalloc);
		if (!strncmp (pathname, "hex://", 6)) {
			mal->size = strlen (pathname);
			mal->buf = calloc (1, mal->size + 1);
			if (!mal->buf) {
				free (mal);
				return NULL;
			}
			mal->offset = 0;
			mal->size = rz_hex_str2bin (pathname + 6, mal->buf);
			if ((int)mal->size < 1) {
				R_FREE (mal->buf);
			}
		} else {
			mal->size = rz_num_math (NULL, pathname + 9);
			if (((int)mal->size) <= 0) {
				free (mal);
				eprintf ("Cannot allocate (%s) 0 bytes\n", pathname + 9);
				return NULL;
			}
			mal->offset = 0;
			mal->buf = calloc (1, mal->size + 1);
		}
		if (mal->buf) {
			return rz_io_desc_new (io, &rz_io_plugin_malloc, pathname, R_PERM_RW | rw, mode, mal);
		}
		eprintf ("Cannot allocate (%s) %d byte(s)\n", pathname + 9, mal->size);
		free (mal);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_malloc = {
	.name = "malloc",
	.desc = "Memory allocation plugin",
	.uris = "malloc://,hex://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &rz_io_plugin_malloc,
	.version = R2_VERSION
};
#endif
