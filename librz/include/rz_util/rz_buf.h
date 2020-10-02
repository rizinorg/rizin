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

typedef struct rz_buf_t RBuffer;

typedef bool (*RBufferInit)(RBuffer *b, const void *user);
typedef bool (*RBufferFini)(RBuffer *b);
typedef st64 (*RBufferRead)(RBuffer *b, ut8 *buf, ut64 len);
typedef st64 (*RBufferWrite)(RBuffer *b, const ut8 *buf, ut64 len);
typedef ut64 (*RBufferGetSize)(RBuffer *b);
typedef bool (*RBufferResize)(RBuffer *b, ut64 newsize);
typedef st64 (*RBufferSeek)(RBuffer *b, st64 addr, int whence);
typedef ut8 *(*RBufferGetWholeBuf)(RBuffer *b, ut64 *sz);
typedef void (*RBufferFreeWholeBuf)(RBuffer *b);
typedef RzList *(*RBufferNonEmptyList)(RBuffer *b);

typedef struct rz_buffer_methods_t {
	RBufferInit init;
	RBufferFini fini;
	RBufferRead read;
	RBufferWrite write;
	RBufferGetSize get_size;
	RBufferResize resize;
	RBufferSeek seek;
	RBufferGetWholeBuf get_whole_buf;
	RBufferFreeWholeBuf free_whole_buf;
	RBufferNonEmptyList nonempty_list;
} RBufferMethods;

struct rz_buf_t {
	const RBufferMethods *methods;
	void *priv;
	ut8 *whole_buf;
	bool readonly;
	int Oxff_priv;
	int refctr;
};

// XXX: this should not be public
typedef struct rz_buf_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
	int written;
} RBufferSparse;

/* constructors */
RZ_API RBuffer *rz_buf_new(void);
RZ_API RBuffer *rz_buf_new_with_io(void *iob, int fd);
RZ_API RBuffer *rz_buf_new_with_bytes(const ut8* bytes, ut64 len);
RZ_API RBuffer *rz_buf_new_with_string(const char *msg);
RZ_API RBuffer *rz_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal);
RZ_API RBuffer *rz_buf_new_file(const char *file, int perm, int mode);
RZ_API RBuffer *rz_buf_new_with_buf(RBuffer *b);
RZ_API RBuffer *rz_buf_new_slurp(const char *file);
RZ_API RBuffer *rz_buf_new_slice(RBuffer *b, ut64 offset, ut64 size);
RZ_API RBuffer *rz_buf_new_empty(ut64 len);
RZ_API RBuffer *rz_buf_new_mmap(const char *file, int flags);
RZ_API RBuffer *rz_buf_new_sparse(ut8 Oxff);

/* methods */
RZ_API bool rz_buf_dump(RBuffer *buf, const char *file);
RZ_API bool rz_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length);
RZ_API st64 rz_buf_append_string(RBuffer *b, const char *str);
RZ_API bool rz_buf_append_buf(RBuffer *b, RBuffer *a);
RZ_API bool rz_buf_append_bytes(RBuffer *b, const ut8 *buf, ut64 length);
RZ_API bool rz_buf_append_nbytes(RBuffer *b, ut64 length);
RZ_API bool rz_buf_append_ut16(RBuffer *b, ut16 n);
RZ_API bool rz_buf_append_buf_slice(RBuffer *b, RBuffer *a, ut64 offset, ut64 size);
RZ_API bool rz_buf_append_ut32(RBuffer *b, ut32 n);
RZ_API bool rz_buf_append_ut64(RBuffer *b, ut64 n);
RZ_API bool rz_buf_prepend_bytes(RBuffer *b, const ut8 *buf, ut64 length);
RZ_API st64 rz_buf_insert_bytes(RBuffer *b, ut64 addr, const ut8 *buf, ut64 length);
RZ_API char *rz_buf_to_string(RBuffer *b);
RZ_API char *rz_buf_get_string(RBuffer *b, ut64 addr);
RZ_API st64 rz_buf_read(RBuffer *b, ut8 *buf, ut64 len);
RZ_API ut8 rz_buf_read8(RBuffer *b);
RZ_API st64 rz_buf_fread(RBuffer *b, ut8 *buf, const char *fmt, int n);
RZ_API st64 rz_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, ut64 len);
RZ_API ut8 rz_buf_read8_at(RBuffer *b, ut64 addr);
RZ_API ut64 rz_buf_tell(RBuffer *b);
RZ_API st64 rz_buf_seek(RBuffer *b, st64 addr, int whence);
RZ_API st64 rz_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
RZ_API st64 rz_buf_write(RBuffer *b, const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_fwrite(RBuffer *b, const ut8 *buf, const char *fmt, int n);
RZ_API st64 rz_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_fwrite_at(RBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n);
// WARNING: this function should be used with care because it may allocate the
// entire buffer in memory. Consider using the rz_buf_read* APIs instead and read
// only the chunks you need.
RZ_DEPRECATE RZ_API const ut8 *rz_buf_data(RBuffer *b, ut64 *size);
RZ_API ut64 rz_buf_size(RBuffer *b);
RZ_API bool rz_buf_resize(RBuffer *b, ut64 newsize);
RZ_API RBuffer *rz_buf_ref(RBuffer *b);
RZ_API void rz_buf_free(RBuffer *b);
RZ_API bool rz_buf_fini(RBuffer *b);
RZ_API RzList *rz_buf_nonempty_list(RBuffer *b);

static inline ut16 rz_buf_read_be16(RBuffer *b) {
	ut8 buf[sizeof (ut16)];
	int r = (int) rz_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_be16 (buf): UT16_MAX;
}

static inline ut16 rz_buf_read_be16_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut16)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_be16 (buf): UT16_MAX;
}

static inline ut32 rz_buf_read_be32(RBuffer *b) {
	ut8 buf[sizeof (ut32)];
	int r = (int) rz_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_be32 (buf): UT32_MAX;
}

static inline ut32 rz_buf_read_be32_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut32)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_be32 (buf): UT32_MAX;
}

static inline ut64 rz_buf_read_be64(RBuffer *b) {
	ut8 buf[sizeof (ut64)];
	int r = (int) rz_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_be64 (buf): UT64_MAX;
}

static inline ut64 rz_buf_read_be64_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut64)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_be64 (buf): UT64_MAX;
}

static inline ut16 rz_buf_read_le16(RBuffer *b) {
	ut8 buf[sizeof (ut16)];
	int r = (int) rz_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_le16 (buf): UT16_MAX;
}

static inline ut16 rz_buf_read_le16_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut16)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_le16 (buf): UT16_MAX;
}

static inline ut32 rz_buf_read_le32(RBuffer *b) {
	ut8 buf[sizeof (ut32)];
	int r = (int) rz_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_le32 (buf): UT32_MAX;
}

static inline ut32 rz_buf_read_le32_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut32)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_le32 (buf): UT32_MAX;
}

static inline ut64 rz_buf_read_le64(RBuffer *b) {
	ut8 buf[sizeof (ut64)];
	int r = (int) rz_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_le64 (buf): UT64_MAX;
}

static inline ut64 rz_buf_read_le64_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut64)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_le64 (buf): UT64_MAX;
}

static inline ut16 rz_buf_read_ble16_at(RBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof (ut16)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_ble16 (buf, big_endian): UT16_MAX;
}

static inline ut32 rz_buf_read_ble32_at(RBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof (ut32)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_ble32 (buf, big_endian): UT32_MAX;
}

static inline ut64 rz_buf_read_ble64_at(RBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof (ut64)];
	int r = (int) rz_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? rz_read_ble64 (buf, big_endian): UT64_MAX;
}

RZ_API st64 rz_buf_uleb128(RBuffer *b, ut64 *v);
RZ_API st64 rz_buf_sleb128(RBuffer *b, st64 *v);

static inline st64 rz_buf_uleb128_at(RBuffer *b, ut64 addr, ut64 *v) {
	rz_buf_seek (b, addr, RZ_BUF_SET);
	return rz_buf_uleb128 (b, v);
}
static inline st64 rz_buf_sleb128_at(RBuffer *b, ut64 addr, st64 *v) {
	rz_buf_seek (b, addr, RZ_BUF_SET);
	return rz_buf_sleb128 (b, v);
}

#ifdef __cplusplus
}
#endif

#endif //  RZ_BUF_H
