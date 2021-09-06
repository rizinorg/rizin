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

typedef struct rz_buf_sparse_chunk_t {
	ut64 from; ///< inclusive
	ut64 to; ///< inclusive, there can't be chunks with size == 0
	ut8 *data; ///< size == to - from + 1
} RzBufferSparseChunk;

typedef enum {
	RZ_BUF_SPARSE_WRITE_MODE_SPARSE, ///< all writes are performed in the sparse overlay
	RZ_BUF_SPARSE_WRITE_MODE_THROUGH ///< all writes are performed in the underlying base buffer
} RzBufferSparseWriteMode;

/* utils */

/// change cur according to addr and whence (RZ_BUF_SET/RZ_BUF_CUR/RZ_BUF_END)
static inline ut64 rz_seek_offset(ut64 cur, ut64 length, st64 addr, int whence) {
	switch (whence) {
	case RZ_BUF_CUR:
		return cur + (ut64)addr;
	case RZ_BUF_SET:
		return addr;
	case RZ_BUF_END:
		return length + (ut64)addr;
	default:
		rz_warn_if_reached();
		return cur;
	}
}

/* constructors */
RZ_API RZ_OWN RzBuffer *rz_buf_new_empty(ut64 len);
RZ_API RZ_OWN RzBuffer *rz_buf_new_file(const char *file, int perm, int mode);
RZ_API RZ_OWN RzBuffer *rz_buf_new_mmap(const char *file, int flags, int mode);
RZ_API RZ_OWN RzBuffer *rz_buf_new_slice(RzBuffer *b, ut64 offset, ut64 size);
RZ_API RZ_OWN RzBuffer *rz_buf_new_slurp(const char *file);
RZ_API RZ_OWN RzBuffer *rz_buf_new_sparse(ut8 Oxff);
RZ_API RZ_OWN RzBuffer *rz_buf_new_sparse_overlay(RzBuffer *b, RzBufferSparseWriteMode write_mode);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_buf(RzBuffer *b);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_bytes(RZ_NULLABLE RZ_OWN const ut8 *bytes, ut64 len);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_io(RZ_NONNULL void *iob, int fd);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_methods(RZ_NONNULL const RzBufferMethods *methods, void *init_user);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_string(RZ_NONNULL const char *msg);

/* methods */
RZ_API RZ_OWN char *rz_buf_get_nstring(RZ_NONNULL RzBuffer *b, ut64 addr, size_t size);
RZ_API RZ_OWN char *rz_buf_get_string(RZ_NONNULL RzBuffer *b, ut64 addr);
RZ_API RZ_OWN char *rz_buf_to_string(RZ_NONNULL RzBuffer *b);
RZ_API RzBuffer *rz_buf_ref(RzBuffer *b);
RZ_API bool rz_buf_append_buf(RZ_NONNULL RzBuffer *b, RZ_NONNULL RzBuffer *a);
RZ_API bool rz_buf_append_buf_slice(RZ_NONNULL RzBuffer *b, RZ_NONNULL RzBuffer *a, ut64 offset, ut64 size);
RZ_API bool rz_buf_append_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 length);
RZ_API bool rz_buf_append_nbytes(RZ_NONNULL RzBuffer *b, ut64 length);
RZ_API bool rz_buf_append_ut16(RZ_NONNULL RzBuffer *b, ut16 n);
RZ_API bool rz_buf_append_ut32(RZ_NONNULL RzBuffer *b, ut32 n);
RZ_API bool rz_buf_append_ut64(RZ_NONNULL RzBuffer *b, ut64 n);
RZ_API bool rz_buf_dump(RZ_NONNULL RzBuffer *buf, RZ_NONNULL const char *file);
RZ_API bool rz_buf_fini(RzBuffer *b);
RZ_API bool rz_buf_prepend_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 length);
RZ_API bool rz_buf_read8(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut8 *result);
RZ_API bool rz_buf_read8_at(RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut8 *result);
RZ_API bool rz_buf_read_be16(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut16 *result);
RZ_API bool rz_buf_read_be16_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut16 *result);
RZ_API bool rz_buf_read_be32(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut32 *result);
RZ_API bool rz_buf_read_be32_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut32 *result);
RZ_API bool rz_buf_read_be64(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut64 *result);
RZ_API bool rz_buf_read_be64_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut64 *result);
RZ_API bool rz_buf_read_ble16(RZ_NONNULL RzBuffer *b, bool big_endian, RZ_NONNULL RZ_OUT ut16 *result);
RZ_API bool rz_buf_read_ble16_at(RZ_NONNULL RzBuffer *b, ut64 addr, bool big_endian, RZ_NONNULL RZ_OUT ut16 *result);
RZ_API bool rz_buf_read_ble32(RZ_NONNULL RzBuffer *b, RZ_NONNULL bool big_endian, RZ_OUT ut32 *result);
RZ_API bool rz_buf_read_ble32_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL bool big_endian, RZ_OUT ut32 *result);
RZ_API bool rz_buf_read_ble64(RZ_NONNULL RzBuffer *b, bool big_endian, RZ_NONNULL RZ_OUT ut64 *result);
RZ_API bool rz_buf_read_ble64_at(RZ_NONNULL RzBuffer *b, ut64 addr, bool big_endian, RZ_NONNULL RZ_OUT ut64 *result);
RZ_API bool rz_buf_read_le16(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut16 *result);
RZ_API bool rz_buf_read_le16_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut16 *result);
RZ_API bool rz_buf_read_le32(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut32 *result);
RZ_API bool rz_buf_read_le32_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut32 *result);
RZ_API bool rz_buf_read_le64(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut64 *result);
RZ_API bool rz_buf_read_le64_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut64 *result);
RZ_API bool rz_buf_resize(RZ_NONNULL RzBuffer *b, ut64 newsize);
RZ_API bool rz_buf_set_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 length);
RZ_API st64 rz_buf_append_string(RZ_NONNULL RzBuffer *b, RZ_NONNULL const char *str);
RZ_API st64 rz_buf_fread(RZ_NONNULL RzBuffer *b, RZ_NONNULL ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_fread_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_fwrite(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_fwrite_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_insert_bytes(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 length);
RZ_API st64 rz_buf_read(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut8 *buf, ut64 len);
RZ_API st64 rz_buf_read_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut8 *buf, ut64 len);
RZ_API st64 rz_buf_seek(RZ_NONNULL RzBuffer *b, st64 addr, int whence);
RZ_API st64 rz_buf_write(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_write_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API ut64 rz_buf_size(RZ_NONNULL RzBuffer *b);
RZ_API ut64 rz_buf_tell(RZ_NONNULL RzBuffer *b);
RZ_API void rz_buf_free(RzBuffer *b);
RZ_API void rz_buf_set_overflow_byte(RZ_NONNULL RzBuffer *b, ut8 Oxff);

RZ_DEPRECATE RZ_API RZ_BORROW const ut8 *rz_buf_data(RZ_NONNULL RzBuffer *b, ut64 *size);

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

// sparse-specific

RZ_API const RzBufferSparseChunk *rz_buf_sparse_get_chunks(RzBuffer *b, RZ_NONNULL size_t *count);
RZ_API void rz_buf_sparse_set_write_mode(RzBuffer *b, RzBufferSparseWriteMode mode);
RZ_API bool rz_buf_sparse_populated_in(RzBuffer *b, ut64 from, ut64 to);

RZ_API bool rz_deflatew_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed, int wbits);
RZ_API bool rz_deflate_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed);
RZ_API bool rz_inflatew_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed, int wbits);
RZ_API bool rz_inflate_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BUF_H
