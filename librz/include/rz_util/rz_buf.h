#ifndef RZ_BUF_H
#define RZ_BUF_H
#include <rz_util/rz_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: choose whether the _at operations should preserve the current seek or not

#define RZ_BUF_SET 0
#define RZ_BUF_CUR 1
#define RZ_BUF_END 2

typedef struct rz_buf_t RzBuffer;

typedef bool (*RzBufferInit)(RzBuffer *b, const void *user);
typedef bool (*RzBufferFini)(RzBuffer *b);
typedef st64 (*RzBufferRead)(RzBuffer *b, ut8 *buf, ut64 len);
typedef st64 (*RzBufferWrite)(RzBuffer *b, const ut8 *buf, ut64 len);
typedef ut64 (*RzBufferGetSize)(RzBuffer *b);
typedef bool (*RzBufferResize)(RzBuffer *b, ut64 newsize);
typedef st64 (*RzBufferSeek)(RzBuffer *b, st64 addr, int whence);
typedef ut8 *(*RzBufferGetWholeBuf)(RzBuffer *b, ut64 *sz);
typedef void (*RzBufferFreeWholeBuf)(RzBuffer *b);
typedef RzList *(*RzBufferNonEmptyList)(RzBuffer *b);

typedef struct rz_buffer_methods_t {
	RzBufferInit init;
	RzBufferFini fini;
	RzBufferRead read;
	RzBufferWrite write;
	RzBufferGetSize get_size;
	RzBufferResize resize;
	RzBufferSeek seek;
	RzBufferGetWholeBuf get_whole_buf;
	RzBufferFreeWholeBuf free_whole_buf;
	RzBufferNonEmptyList nonempty_list;
} RzBufferMethods;

struct rz_buf_t {
	const RzBufferMethods *methods;
	void *priv;
	ut8 *whole_buf;
	bool readonly;
	ut8 Oxff_priv;
	int refctr;
	int fd;
};

// XXX: this should not be public
typedef struct rz_buf_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
	int written;
} RzBufferSparse;

/* constructors */
RZ_API RzBuffer *rz_buf_new(void);
RZ_API RzBuffer *rz_buf_new_with_io(void *iob, int fd);
RZ_API RzBuffer *rz_buf_new_with_bytes(const ut8 *bytes, ut64 len);
RZ_API RzBuffer *rz_buf_new_with_string(const char *msg);
RZ_API RzBuffer *rz_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal);
RZ_API RzBuffer *rz_buf_new_file(const char *file, int perm, int mode);
RZ_API RzBuffer *rz_buf_new_with_buf(RzBuffer *b);
RZ_API RzBuffer *rz_buf_new_slurp(const char *file);
RZ_API RzBuffer *rz_buf_new_slice(RzBuffer *b, ut64 offset, ut64 size);
RZ_API RzBuffer *rz_buf_new_empty(ut64 len);
RZ_API RzBuffer *rz_buf_new_mmap(const char *file, int flags, int mode);
RZ_API RzBuffer *rz_buf_new_sparse(ut8 Oxff);

/* methods */
RZ_API bool rz_buf_dump(RzBuffer *buf, const char *file);
RZ_API bool rz_buf_set_bytes(RzBuffer *b, const ut8 *buf, ut64 length);
RZ_API st64 rz_buf_append_string(RzBuffer *b, const char *str);
RZ_API bool rz_buf_append_buf(RzBuffer *b, RzBuffer *a);
RZ_API bool rz_buf_append_bytes(RzBuffer *b, const ut8 *buf, ut64 length);
RZ_API bool rz_buf_append_nbytes(RzBuffer *b, ut64 length);
RZ_API bool rz_buf_append_ut16(RzBuffer *b, ut16 n);
RZ_API bool rz_buf_append_buf_slice(RzBuffer *b, RzBuffer *a, ut64 offset, ut64 size);
RZ_API bool rz_buf_append_ut32(RzBuffer *b, ut32 n);
RZ_API bool rz_buf_append_ut64(RzBuffer *b, ut64 n);
RZ_API bool rz_buf_prepend_bytes(RzBuffer *b, const ut8 *buf, ut64 length);
RZ_API st64 rz_buf_insert_bytes(RzBuffer *b, ut64 addr, const ut8 *buf, ut64 length);
RZ_API char *rz_buf_to_string(RzBuffer *b);
RZ_API char *rz_buf_get_string(RzBuffer *b, ut64 addr);
RZ_API st64 rz_buf_read(RzBuffer *b, ut8 *buf, ut64 len);
RZ_API ut8 rz_buf_read8(RzBuffer *b);
RZ_API st64 rz_buf_fread(RzBuffer *b, ut8 *buf, const char *fmt, int n);
RZ_API st64 rz_buf_read_at(RzBuffer *b, ut64 addr, ut8 *buf, ut64 len);
RZ_API ut8 rz_buf_read8_at(RzBuffer *b, ut64 addr);
RZ_API ut64 rz_buf_tell(RzBuffer *b);
RZ_API st64 rz_buf_seek(RzBuffer *b, st64 addr, int whence);
RZ_API st64 rz_buf_fread_at(RzBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
RZ_API st64 rz_buf_write(RzBuffer *b, const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_fwrite(RzBuffer *b, const ut8 *buf, const char *fmt, int n);
RZ_API st64 rz_buf_write_at(RzBuffer *b, ut64 addr, const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_fwrite_at(RzBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n);
// WARNING: this function should be used with care because it may allocate the
// entire buffer in memory. Consider using the rz_buf_read* APIs instead and read
// only the chunks you need.
RZ_DEPRECATE RZ_API const ut8 *rz_buf_data(RzBuffer *b, ut64 *size);
RZ_API ut64 rz_buf_size(RzBuffer *b);
RZ_API bool rz_buf_resize(RzBuffer *b, ut64 newsize);
RZ_API RzBuffer *rz_buf_ref(RzBuffer *b);
RZ_API void rz_buf_free(RzBuffer *b);
RZ_API bool rz_buf_fini(RzBuffer *b);
RZ_API RzList *rz_buf_nonempty_list(RzBuffer *b);

static inline ut16 rz_buf_read_be16(RzBuffer *b) {
	ut8 buf[sizeof(ut16)];
	int r = (int)rz_buf_read(b, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_be16(buf) : UT16_MAX;
}

static inline ut16 rz_buf_read_be16_at(RzBuffer *b, ut64 addr) {
	ut8 buf[sizeof(ut16)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_be16(buf) : UT16_MAX;
}

static inline ut32 rz_buf_read_be32(RzBuffer *b) {
	ut8 buf[sizeof(ut32)];
	int r = (int)rz_buf_read(b, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_be32(buf) : UT32_MAX;
}

static inline ut32 rz_buf_read_be32_at(RzBuffer *b, ut64 addr) {
	ut8 buf[sizeof(ut32)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_be32(buf) : UT32_MAX;
}

static inline ut64 rz_buf_read_be64(RzBuffer *b) {
	ut8 buf[sizeof(ut64)];
	int r = (int)rz_buf_read(b, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_be64(buf) : UT64_MAX;
}

static inline ut64 rz_buf_read_be64_at(RzBuffer *b, ut64 addr) {
	ut8 buf[sizeof(ut64)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_be64(buf) : UT64_MAX;
}

static inline ut16 rz_buf_read_le16(RzBuffer *b) {
	ut8 buf[sizeof(ut16)];
	int r = (int)rz_buf_read(b, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_le16(buf) : UT16_MAX;
}

static inline ut16 rz_buf_read_le16_at(RzBuffer *b, ut64 addr) {
	ut8 buf[sizeof(ut16)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_le16(buf) : UT16_MAX;
}

static inline ut32 rz_buf_read_le32(RzBuffer *b) {
	ut8 buf[sizeof(ut32)];
	int r = (int)rz_buf_read(b, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_le32(buf) : UT32_MAX;
}

static inline ut32 rz_buf_read_le32_at(RzBuffer *b, ut64 addr) {
	ut8 buf[sizeof(ut32)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_le32(buf) : UT32_MAX;
}

static inline ut64 rz_buf_read_le64(RzBuffer *b) {
	ut8 buf[sizeof(ut64)];
	int r = (int)rz_buf_read(b, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_le64(buf) : UT64_MAX;
}

static inline ut64 rz_buf_read_le64_at(RzBuffer *b, ut64 addr) {
	ut8 buf[sizeof(ut64)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_le64(buf) : UT64_MAX;
}

static inline ut16 rz_buf_read_ble16_at(RzBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof(ut16)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_ble16(buf, big_endian) : UT16_MAX;
}

static inline ut32 rz_buf_read_ble32_at(RzBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof(ut32)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_ble32(buf, big_endian) : UT32_MAX;
}

static inline ut64 rz_buf_read_ble64_at(RzBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof(ut64)];
	int r = (int)rz_buf_read_at(b, addr, buf, sizeof(buf));
	return r == sizeof(buf) ? rz_read_ble64(buf, big_endian) : UT64_MAX;
}

RZ_API st64 rz_buf_uleb128(RzBuffer *b, ut64 *v);
RZ_API st64 rz_buf_sleb128(RzBuffer *b, st64 *v);

static inline st64 rz_buf_uleb128_at(RzBuffer *b, ut64 addr, ut64 *v) {
	rz_buf_seek(b, addr, RZ_BUF_SET);
	return rz_buf_uleb128(b, v);
}
static inline st64 rz_buf_sleb128_at(RzBuffer *b, ut64 addr, st64 *v) {
	rz_buf_seek(b, addr, RZ_BUF_SET);
	return rz_buf_sleb128(b, v);
}

#ifdef __cplusplus
}
#endif

#endif //  RZ_BUF_H
