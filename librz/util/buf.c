// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_io.h>

typedef enum {
	RZ_BUFFER_FILE,
	RZ_BUFFER_IO,
	RZ_BUFFER_BYTES,
	RZ_BUFFER_MMAP,
	RZ_BUFFER_SPARSE,
	RZ_BUFFER_REF,
} RzBufferType;

#include "buf_file.c"
#include "buf_sparse.c"
#include "buf_bytes.c"
#include "buf_mmap.c"
#include "buf_io.c"
#include "buf_ref.c"

static bool buf_init(RzBuffer *b, const void *user) {
	rz_return_val_if_fail(b && b->methods, false);
	return b->methods->init ? b->methods->init(b, user) : true;
}

static bool buf_fini(RzBuffer *b) {
	rz_return_val_if_fail(b && b->methods, false);
	return b->methods->fini ? b->methods->fini(b) : true;
}

static ut64 buf_get_size(RzBuffer *b) {
	rz_return_val_if_fail(b && b->methods, UT64_MAX);
	return b->methods->get_size ? b->methods->get_size(b) : UT64_MAX;
}

static st64 buf_read(RzBuffer *b, ut8 *buf, size_t len) {
	rz_return_val_if_fail(b && b->methods, -1);
	return b->methods->read ? b->methods->read(b, buf, len) : -1;
}

static st64 buf_write(RzBuffer *b, const ut8 *buf, size_t len) {
	rz_return_val_if_fail(b && b->methods, -1);
	RZ_FREE(b->whole_buf);
	return b->methods->write ? b->methods->write(b, buf, len) : -1;
}

static st64 buf_seek(RzBuffer *b, st64 addr, int whence) {
	rz_return_val_if_fail(b && b->methods, -1);
	return b->methods->seek ? b->methods->seek(b, addr, whence) : -1;
}

static bool buf_resize(RzBuffer *b, ut64 newsize) {
	rz_return_val_if_fail(b && b->methods, -1);
	return b->methods->resize ? b->methods->resize(b, newsize) : false;
}

static ut8 *get_whole_buf(RzBuffer *b, ut64 *sz) {
	rz_return_val_if_fail(b && b->methods, NULL);
	if (b->methods->get_whole_buf) {
		return b->methods->get_whole_buf(b, sz);
	}
	ut64 bsz = rz_buf_size(b);
	// bsz = 4096; // FAKE MINIMUM SIZE TO READ THE BIN HEADER
	if (bsz == UT64_MAX) {
		return NULL;
	}
	free(b->whole_buf);
	b->whole_buf = RZ_NEWS(ut8, bsz);
	if (!b->whole_buf) {
		return NULL;
	}
	rz_buf_read_at(b, 0, b->whole_buf, bsz);
	if (sz) {
		*sz = bsz;
	}
	return b->whole_buf;
}

static RzBuffer *new_buffer(RzBufferType type, const void *user) {
	RzBuffer *b = RZ_NEW0(RzBuffer);
	if (!b) {
		return NULL;
	}
	switch (type) {
	case RZ_BUFFER_BYTES:
		b->methods = &buffer_bytes_methods;
		break;
	case RZ_BUFFER_MMAP:
		b->methods = &buffer_mmap_methods;
		break;
	case RZ_BUFFER_SPARSE:
		b->methods = &buffer_sparse_methods;
		break;
	case RZ_BUFFER_FILE:
		b->methods = &buffer_file_methods;
		break;
	case RZ_BUFFER_IO:
		b->methods = &buffer_io_methods;
		break;
	case RZ_BUFFER_REF:
		b->methods = &buffer_ref_methods;
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	if (!buf_init(b, user)) {
		free(b);
		return NULL;
	}
	return b;
}

// TODO: Optimize to use memcpy when buffers are not in range..
// check buf boundaries and offsets and use memcpy or memmove

// copied from librz/io/cache.c:rz_io_cache_read
// ret # of bytes copied
RZ_API RzBuffer *rz_buf_new_with_io(void *iob, int fd) {
	rz_return_val_if_fail(iob && fd >= 0, NULL);
	struct buf_io_user u = { 0 };
	u.iob = (RzIOBind *)iob;
	u.fd = fd;
	return new_buffer(RZ_BUFFER_IO, &u);
}

RZ_API RzBuffer *rz_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal) {
	struct buf_bytes_user u = { 0 };
	u.data_steal = bytes;
	u.length = len;
	u.steal = steal;
	return new_buffer(RZ_BUFFER_BYTES, &u);
}

RZ_API RzBuffer *rz_buf_new_empty(ut64 len) {
	ut8 *buf = RZ_NEWS0(ut8, len);
	if (!buf) {
		return NULL;
	}

	struct buf_bytes_user u = { 0 };
	u.data_steal = buf;
	u.length = len;
	u.steal = true;
	RzBuffer *res = new_buffer(RZ_BUFFER_BYTES, &u);
	if (!res) {
		free(buf);
	}
	return res;
}

RZ_API RzBuffer *rz_buf_new_with_bytes(const ut8 *bytes, ut64 len) {
	struct buf_bytes_user u = { 0 };
	u.data = bytes;
	u.length = len;
	return new_buffer(RZ_BUFFER_BYTES, &u);
}

RZ_API RzBuffer *rz_buf_new_slice(RzBuffer *b, ut64 offset, ut64 size) {
	struct buf_ref_user u = { 0 };
	u.parent = b;
	u.offset = offset;
	u.size = size;
	return new_buffer(RZ_BUFFER_REF, &u);
}

RZ_API RzBuffer *rz_buf_new_with_string(const char *msg) {
	return rz_buf_new_with_bytes((const ut8 *)msg, (ut64)strlen(msg));
}

RZ_API RzBuffer *rz_buf_new_with_buf(RzBuffer *b) {
	ut64 sz = 0;
	const ut8 *tmp = rz_buf_data(b, &sz);
	return rz_buf_new_with_bytes(tmp, sz);
}

RZ_API RzBuffer *rz_buf_new_sparse(ut8 Oxff) {
	RzBuffer *b = new_buffer(RZ_BUFFER_SPARSE, NULL);
	if (b) {
		b->Oxff_priv = Oxff;
	}
	return b;
}

RZ_API RzBuffer *rz_buf_new(void) {
	struct buf_bytes_user u = { 0 };
	u.data = NULL;
	u.length = 0;
	return new_buffer(RZ_BUFFER_BYTES, &u);
}

RZ_DEPRECATE RZ_API const ut8 *rz_buf_data(RzBuffer *b, ut64 *size) {
	rz_return_val_if_fail(b, NULL);
	b->whole_buf = get_whole_buf(b, size);
	return b->whole_buf;
}

RZ_API ut64 rz_buf_size(RzBuffer *b) {
	rz_return_val_if_fail(b, 0);
	return buf_get_size(b);
}

RZ_API RzBuffer *rz_buf_new_mmap(const char *filename, int perm, int mode) {
	rz_return_val_if_fail(filename, NULL);
	struct buf_mmap_user u = { 0 };
	u.filename = filename;
	u.perm = perm;
	u.mode = mode;
	return new_buffer(RZ_BUFFER_MMAP, &u);
}

RZ_API RzBuffer *rz_buf_new_file(const char *file, int perm, int mode) {
	struct buf_file_user u = { 0 };
	u.file = file;
	u.perm = perm;
	u.mode = mode;
	return new_buffer(RZ_BUFFER_FILE, &u);
}

// TODO: rename to new_from_file ?
RZ_API RzBuffer *rz_buf_new_slurp(const char *file) {
	size_t len;
	char *tmp = rz_file_slurp(file, &len);
	if (!tmp) {
		return NULL;
	}

	struct buf_bytes_user u = { 0 };
	u.data_steal = (ut8 *)tmp;
	u.length = (ut64)len;
	u.steal = true;
	return new_buffer(RZ_BUFFER_BYTES, &u);
}

RZ_API bool rz_buf_dump(RzBuffer *b, const char *file) {
	// TODO: need to redo this
	if (!b || !file) {
		return false;
	}
	ut64 tmpsz = 0;
	const ut8 *tmp = rz_buf_data(b, &tmpsz);
	return rz_file_dump(file, tmp, tmpsz, 0);
}

RZ_API st64 rz_buf_seek(RzBuffer *b, st64 addr, int whence) {
	rz_return_val_if_fail(b, -1);
	return buf_seek(b, addr, whence);
}

RZ_API ut64 rz_buf_tell(RzBuffer *b) {
	return rz_buf_seek(b, 0, RZ_BUF_CUR);
}

RZ_API bool rz_buf_set_bytes(RzBuffer *b, const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && buf && !b->readonly, false);
	if (!rz_buf_resize(b, 0)) {
		return false;
	}
	if (rz_buf_seek(b, 0, RZ_BUF_SET) < 0) {
		return false;
	}
	if (!rz_buf_append_bytes(b, buf, length)) {
		return false;
	}
	return rz_buf_seek(b, 0, RZ_BUF_SET) >= 0;
}

RZ_API bool rz_buf_prepend_bytes(RzBuffer *b, const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && buf && !b->readonly, false);
	return rz_buf_insert_bytes(b, 0, buf, length) >= 0;
}

RZ_API char *rz_buf_to_string(RzBuffer *b) {
	ut64 sz = rz_buf_size(b);
	char *s = malloc(sz + 1);
	if (!s) {
		return NULL;
	}
	if (rz_buf_read_at(b, 0, (ut8 *)s, sz) < 0) {
		free(s);
		return NULL;
	}
	s[sz] = '\0';
	return s;
}

RZ_API bool rz_buf_append_bytes(RzBuffer *b, const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && buf && !b->readonly, false);

	if (rz_buf_seek(b, 0, RZ_BUF_END) < 0) {
		return false;
	}

	return rz_buf_write(b, buf, length) >= 0;
}

RZ_API bool rz_buf_append_nbytes(RzBuffer *b, ut64 length) {
	rz_return_val_if_fail(b && !b->readonly, false);
	ut8 *buf = RZ_NEWS0(ut8, length);
	if (!buf) {
		return false;
	}
	bool res = rz_buf_append_bytes(b, buf, length);
	free(buf);
	return res;
}

RZ_API st64 rz_buf_insert_bytes(RzBuffer *b, ut64 addr, const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && !b->readonly, -1);
	st64 pos, r = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (r < 0) {
		return r;
	}
	pos = r;
	r = rz_buf_seek(b, addr, RZ_BUF_SET);
	if (r < 0) {
		goto restore_pos;
	}

	ut64 sz = rz_buf_size(b);
	ut8 *tmp = RZ_NEWS(ut8, sz - addr);
	r = rz_buf_read(b, tmp, sz - addr);
	if (r < 0) {
		goto free_tmp;
	}
	st64 tmp_length = r;
	if (!rz_buf_resize(b, sz + length)) {
		goto free_tmp;
	}
	r = rz_buf_seek(b, addr + length, RZ_BUF_SET);
	if (r < 0) {
		goto free_tmp;
	}
	r = rz_buf_write(b, tmp, tmp_length);
	if (r < 0) {
		goto free_tmp;
	}
	r = rz_buf_seek(b, addr, RZ_BUF_SET);
	if (r < 0) {
		goto free_tmp;
	}
	r = rz_buf_write(b, buf, length);
free_tmp:
	free(tmp);
restore_pos:
	rz_buf_seek(b, pos, RZ_BUF_SET);
	return r;
}

RZ_API bool rz_buf_append_ut16(RzBuffer *b, ut16 n) {
	rz_return_val_if_fail(b && !b->readonly, false);
	return rz_buf_append_bytes(b, (const ut8 *)&n, sizeof(n));
}

RZ_API bool rz_buf_append_ut32(RzBuffer *b, ut32 n) {
	rz_return_val_if_fail(b && !b->readonly, false);
	return rz_buf_append_bytes(b, (const ut8 *)&n, sizeof(n));
}

RZ_API bool rz_buf_append_ut64(RzBuffer *b, ut64 n) {
	rz_return_val_if_fail(b && !b->readonly, false);
	return rz_buf_append_bytes(b, (const ut8 *)&n, sizeof(n));
}

RZ_API bool rz_buf_append_buf(RzBuffer *b, RzBuffer *a) {
	rz_return_val_if_fail(b && a && !b->readonly, false);
	ut64 sz = 0;
	const ut8 *tmp = rz_buf_data(a, &sz);
	return rz_buf_append_bytes(b, tmp, sz);
}

RZ_API bool rz_buf_append_buf_slice(RzBuffer *b, RzBuffer *a, ut64 offset, ut64 size) {
	rz_return_val_if_fail(b && a && !b->readonly, false);
	ut8 *tmp = RZ_NEWS(ut8, size);
	bool res = false;

	if (!tmp) {
		return false;
	}
	st64 r = rz_buf_read_at(a, offset, tmp, size);
	if (r < 0) {
		goto err;
	}
	res = rz_buf_append_bytes(b, tmp, r);
err:
	free(tmp);
	return res;
}

// return an heap-allocated string read from the RzBuffer b at address addr. The
// length depends on the first '\0' found in the buffer. If there is no '\0' in
// the buffer, there is no string, thus NULL is returned.
RZ_API char *rz_buf_get_string(RzBuffer *b, ut64 addr) {
	const int MIN_RES_SZ = 64;
	ut8 *res = RZ_NEWS(ut8, MIN_RES_SZ + 1);
	ut64 sz = 0;
	st64 r = rz_buf_read_at(b, addr, res, MIN_RES_SZ);
	bool null_found = false;
	while (r > 0) {
		const ut8 *needle = rz_mem_mem(res + sz, r, (ut8 *)"\x00", 1);
		if (needle) {
			null_found = true;
			break;
		}
		sz += r;
		addr += r;

		ut8 *restmp = realloc(res, sz + MIN_RES_SZ + 1);
		if (!restmp) {
			free(res);
			return NULL;
		}
		res = restmp;
		r = rz_buf_read_at(b, addr, res + sz, MIN_RES_SZ);
	}
	if (r < 0 || !null_found) {
		free(res);
		return NULL;
	}
	return (char *)res;
}

RZ_API st64 rz_buf_read(RzBuffer *b, ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf, -1);
	st64 r = buf_read(b, buf, len);
	if (r >= 0 && r < len) {
		memset(buf + r, b->Oxff_priv, len - r);
	}
	return r;
}

RZ_API st64 rz_buf_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf && !b->readonly, -1);
	return buf_write(b, buf, len);
}

RZ_API ut8 rz_buf_read8(RzBuffer *b) {
	ut8 res;
	st64 r = rz_buf_read(b, &res, sizeof(res));
	return r == sizeof(res) ? res : b->Oxff_priv;
}

RZ_API ut8 rz_buf_read8_at(RzBuffer *b, ut64 addr) {
	ut8 res;
	st64 r = rz_buf_read_at(b, addr, &res, sizeof(res));
	return r == sizeof(res) ? res : b->Oxff_priv;
}

static st64 buf_format(RzBuffer *dst, RzBuffer *src, const char *fmt, int n) {
	st64 res = 0;
	int i;
	for (i = 0; i < n; i++) {
		int j;
		int m = 1;
		int tsize = 2;
		bool bigendian = true;

		for (j = 0; fmt[j]; j++) {
			switch (fmt[j]) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				if (m == 1) {
					m = rz_num_get(NULL, &fmt[j]);
				}
				continue;
			case 's':
				tsize = 2;
				bigendian = false;
				break;
			case 'S':
				tsize = 2;
				bigendian = true;
				break;
			case 'i':
				tsize = 4;
				bigendian = false;
				break;
			case 'I':
				tsize = 4;
				bigendian = true;
				break;
			case 'l':
				tsize = 8;
				bigendian = false;
				break;
			case 'L':
				tsize = 8;
				bigendian = true;
				break;
			case 'c':
				tsize = 1;
				bigendian = false;
				break;
			default: return -1;
			}

			int k;
			for (k = 0; k < m; k++) {
				ut8 tmp[sizeof(ut64)];
				ut8 d1;
				ut16 d2;
				ut32 d3;
				ut64 d4;
				st64 r = rz_buf_read(src, tmp, tsize);
				if (r < tsize) {
					return -1;
				}

				switch (tsize) {
				case 1:
					d1 = rz_read_ble8(tmp);
					r = rz_buf_write(dst, (ut8 *)&d1, 1);
					break;
				case 2:
					d2 = rz_read_ble16(tmp, bigendian);
					r = rz_buf_write(dst, (ut8 *)&d2, 2);
					break;
				case 4:
					d3 = rz_read_ble32(tmp, bigendian);
					r = rz_buf_write(dst, (ut8 *)&d3, 4);
					break;
				case 8:
					d4 = rz_read_ble64(tmp, bigendian);
					r = rz_buf_write(dst, (ut8 *)&d4, 8);
					break;
				}
				if (r < 0) {
					return -1;
				}
				res += r;
			}

			m = 1;
		}
	}
	return res;
}

RZ_API st64 rz_buf_fread(RzBuffer *b, ut8 *buf, const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt, -1);
	// XXX: we assume the caller knows what he's doing
	RzBuffer *dst = rz_buf_new_with_pointers(buf, UT64_MAX, false);
	st64 res = buf_format(dst, b, fmt, n);
	rz_buf_free(dst);
	return res;
}

RZ_API st64 rz_buf_fread_at(RzBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt, -1);
	st64 o_addr = rz_buf_seek(b, 0, RZ_BUF_CUR);
	int r = rz_buf_seek(b, addr, RZ_BUF_SET);
	if (r < 0) {
		return r;
	}
	r = rz_buf_fread(b, buf, fmt, n);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return r;
}

RZ_API st64 rz_buf_fwrite(RzBuffer *b, const ut8 *buf, const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt && !b->readonly, -1);
	// XXX: we assume the caller knows what he's doing
	RzBuffer *src = rz_buf_new_with_pointers(buf, UT64_MAX, false);
	st64 res = buf_format(b, src, fmt, n);
	rz_buf_free(src);
	return res;
}

RZ_API st64 rz_buf_fwrite_at(RzBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt && !b->readonly, -1);
	st64 o_addr = rz_buf_seek(b, 0, RZ_BUF_CUR);
	st64 r = rz_buf_seek(b, addr, RZ_BUF_SET);
	if (r < 0) {
		return r;
	}
	r = rz_buf_fwrite(b, buf, fmt, n);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return r;
}

RZ_API st64 rz_buf_read_at(RzBuffer *b, ut64 addr, ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf, -1);
	st64 o_addr = rz_buf_seek(b, 0, RZ_BUF_CUR);
	st64 r = rz_buf_seek(b, addr, RZ_BUF_SET);
	if (r < 0) {
		return r;
	}

	r = rz_buf_read(b, buf, len);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return r;
}

RZ_API st64 rz_buf_write_at(RzBuffer *b, ut64 addr, const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf && !b->readonly, -1);
	st64 o_addr = rz_buf_seek(b, 0, RZ_BUF_CUR);
	st64 r = rz_buf_seek(b, addr, RZ_BUF_SET);
	if (r < 0) {
		return r;
	}

	r = rz_buf_write(b, buf, len);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return r;
}

RZ_API bool rz_buf_fini(RzBuffer *b) {
	if (!b) {
		return false;
	}
	if (b->refctr > 0) {
		b->refctr--;
		return false;
	}

	// free the whole_buf only if it was initially allocated by the buf types
	if (b->methods->get_whole_buf) {
		if (b->methods->free_whole_buf) {
			b->methods->free_whole_buf(b);
		}
	} else {
		RZ_FREE(b->whole_buf);
	}
	return buf_fini(b);
}

RZ_API void rz_buf_free(RzBuffer *b) {
	if (rz_buf_fini(b)) {
		free(b);
	}
}

RZ_API st64 rz_buf_append_string(RzBuffer *b, const char *str) {
	rz_return_val_if_fail(b && str && !b->readonly, false);
	return rz_buf_append_bytes(b, (const ut8 *)str, strlen(str));
}

RZ_API bool rz_buf_resize(RzBuffer *b, ut64 newsize) {
	rz_return_val_if_fail(b, false);
	return buf_resize(b, newsize);
}

RZ_API RzBuffer *rz_buf_ref(RzBuffer *b) {
	if (b) {
		b->refctr++;
	}
	return b;
}

RZ_API RzList *rz_buf_nonempty_list(RzBuffer *b) {
	return b->methods->nonempty_list ? b->methods->nonempty_list(b) : NULL;
}

RZ_API st64 rz_buf_uleb128(RzBuffer *b, ut64 *v) {
	ut8 c = 0xff;
	ut64 s = 0, sum = 0, l = 0;
	do {
		ut8 data;
		st64 r = rz_buf_read(b, &data, sizeof(data));
		if (r <= 0) {
			return -1;
		}
		c = data & 0xff;
		if (s < 64) {
			sum |= ((ut64)(c & 0x7f) << s);
			s += 7;
		} else {
			sum = 0;
		}
		l++;
	} while (c & 0x80);
	if (v) {
		*v = sum;
	}
	return l;
}

RZ_API st64 rz_buf_sleb128(RzBuffer *b, st64 *v) {
	st64 result = 0, offset = 0;
	ut8 value;
	do {
		st64 chunk;
		st64 r = rz_buf_read(b, &value, sizeof(value));
		if (r != sizeof(value)) {
			return -1;
		}
		chunk = value & 0x7f;
		if (offset < 64) {
			result |= (chunk << offset);
			offset += 7;
		} else {
			result = 0;
		}
	} while (value & 0x80);

	if ((value & 0x40) != 0) {
		if (offset < 64) {
			result |= ~0ULL << offset;
		}
	}
	if (v) {
		*v = result;
	}
	return offset / 7;
}
