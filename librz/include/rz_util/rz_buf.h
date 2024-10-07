#ifndef RZ_BUF_H
#define RZ_BUF_H
#include <rz_util/rz_mem.h>
#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_assert.h>

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
/**
 * \brief Reads \p len bytes from buffer \p b into \p buf.
 * \p buf should have enough space to contain the bytes.
 * The seek of \p b is advanced by \p len bytes.
 * EXCEPT: RZ_BUF_IO_FD, RZ_BUF_FILE.
 * Because they were implemented without seek advancement.
 * And changing it breaks everything. Sorry :/
 *
 * \param b The buffer to read from.
 * \param buf The array to move te bytes into.
 * \param len The number of bytes to read from the buffer.
 *
 * \return The number of bytes read. -1 in case of error and 0 for EOF reached.
 */
typedef st64 (*RzBufferRead)(RZ_BORROW RzBuffer *b, RZ_OUT ut8 *buf, ut64 len);
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

typedef enum {
	RZ_BUFFER_INVALID = 0,
	RZ_BUFFER_FILE,
	RZ_BUFFER_IO_FD,
	RZ_BUFFER_IO, ///< A buffer over RzIO.
	RZ_BUFFER_BYTES, ///< A buffer over raw bytes.
	RZ_BUFFER_MMAP,
	RZ_BUFFER_SPARSE,
	RZ_BUFFER_REF,
	RZ_BUFFER_CUSTOM, ///< A buffer with custom methods.
} RzBufferType;

struct rz_buf_t {
	RzBufferType type;
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
static inline st64 rz_seek_offset(ut64 cur, ut64 length, st64 addr, int whence) {
	switch (whence) {
	case RZ_BUF_CUR:
		if (ST64_ADD_OVFCHK((st64)cur, addr)) {
			return -1;
		}
		return cur + addr;
	case RZ_BUF_SET:
		if ((st64)addr < 0) {
			return -1;
		}
		return addr;
	case RZ_BUF_END:
		if (ST64_ADD_OVFCHK((st64)length, addr)) {
			return -1;
		}
		return length + addr;
	default:
		rz_warn_if_reached();
		return -1;
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
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_bytes(RZ_NULLABLE RZ_BORROW const ut8 *bytes, ut64 len);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_io_fd(RZ_NONNULL void /* RzIOBind */ *iob, int fd);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_io(RZ_NONNULL void /* RzIOBind */ *iob);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_methods(RZ_NONNULL const RzBufferMethods *methods, void *init_user, RzBufferType type);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal);
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_string(RZ_NONNULL const char *msg);

/* methods */

RZ_API RZ_OWN char *rz_buf_get_nstring(RZ_NONNULL RzBuffer *b, ut64 addr, size_t size);
RZ_API RZ_OWN char *rz_buf_get_string(RZ_NONNULL RzBuffer *b, ut64 addr);
RZ_API ut64 rz_buf_read_string(RZ_NONNULL RzBuffer *b, RZ_BORROW RZ_NULLABLE char **s);
RZ_API RZ_OWN char *rz_buf_to_string(RZ_NONNULL RzBuffer *b);
RZ_API RzBuffer *rz_buf_ref(RzBuffer *b);
RZ_API bool rz_buf_append_buf(RZ_NONNULL RzBuffer *b, RZ_NONNULL RzBuffer *a);
RZ_API bool rz_buf_append_buf_slice(RZ_NONNULL RzBuffer *b, RZ_NONNULL RzBuffer *a, ut64 offset, ut64 size);
RZ_API bool rz_buf_append_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API bool rz_buf_append_nbytes(RZ_NONNULL RzBuffer *b, ut64 len);
RZ_API bool rz_buf_append_ut16(RZ_NONNULL RzBuffer *b, ut16 n);
RZ_API bool rz_buf_append_ut32(RZ_NONNULL RzBuffer *b, ut32 n);
RZ_API bool rz_buf_append_ut64(RZ_NONNULL RzBuffer *b, ut64 n);
RZ_API bool rz_buf_dump(RZ_NONNULL RzBuffer *buf, RZ_NONNULL const char *file);
RZ_API bool rz_buf_fini(RzBuffer *b);
RZ_API bool rz_buf_prepend_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API bool rz_buf_read8(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut8 *result);
RZ_API bool rz_buf_read8_at(RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut8 *result);
RZ_API bool rz_buf_resize(RZ_NONNULL RzBuffer *b, ut64 newsize);
RZ_API bool rz_buf_set_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API bool rz_buf_write8(RZ_NONNULL RzBuffer *b, ut8 value);
RZ_API bool rz_buf_write8_at(RZ_NONNULL RzBuffer *b, ut64 addr, ut8 value);
RZ_API st64 rz_buf_append_string(RZ_NONNULL RzBuffer *b, RZ_NONNULL const char *str);
RZ_API st64 rz_buf_fread(RZ_NONNULL RzBuffer *b, RZ_NONNULL ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_fread_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_fwrite(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_fwrite_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, RZ_NONNULL const char *fmt, int n);
RZ_API st64 rz_buf_insert_bytes(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_read(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut8 *buf, ut64 len);
RZ_API st64 rz_buf_read_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut8 *buf, ut64 len);
RZ_API st64 rz_buf_seek(RZ_NONNULL RzBuffer *b, st64 addr, int whence);
RZ_API st64 rz_buf_write(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API st64 rz_buf_write_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API ut64 rz_buf_size(RZ_NONNULL RzBuffer *b);
RZ_API ut64 rz_buf_tell(RZ_NONNULL RzBuffer *b);
RZ_API void rz_buf_free(RzBuffer *b);
RZ_API void rz_buf_set_overflow_byte(RZ_NONNULL RzBuffer *b, ut8 Oxff);
RZ_DEPRECATE RZ_API RZ_BORROW ut8 *rz_buf_data(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut64 *size);

typedef ut64 (*RzBufferFwdScan)(RZ_BORROW RZ_NONNULL const ut8 *buf, ut64 len, RZ_NULLABLE void *user);
RZ_API ut64 rz_buf_fwd_scan(RZ_NONNULL RzBuffer *b, ut64 start, ut64 amount, RZ_NONNULL RzBufferFwdScan fwd_scan, RZ_NULLABLE void *user);

RZ_API st64 rz_buf_uleb128(RZ_NONNULL RzBuffer *buffer, RZ_NONNULL ut64 *value);
RZ_API st64 rz_buf_sleb128(RZ_NONNULL RzBuffer *buffer, RZ_NONNULL st64 *value);

static inline st64 rz_buf_uleb128_at(RzBuffer *b, ut64 addr, ut64 *v) {
	rz_buf_seek(b, addr, RZ_BUF_SET);
	return rz_buf_uleb128(b, v);
}
static inline st64 rz_buf_sleb128_at(RzBuffer *b, ut64 addr, st64 *v) {
	rz_buf_seek(b, addr, RZ_BUF_SET);
	return rz_buf_sleb128(b, v);
}

/* generated methods */

#define DEFINE_RZ_BUF_READ_BLE(size) \
	static inline bool rz_buf_read_ble##size(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut##size *result, bool big_endian) { \
		rz_return_val_if_fail(b &&result, false); \
\
		ut8 tmp[sizeof(ut##size)]; \
		if (rz_buf_read(b, tmp, sizeof(tmp)) != sizeof(tmp)) { \
			return false; \
		} \
\
		*result = rz_read_ble##size(tmp, big_endian); \
		return true; \
	} \
\
	static inline bool rz_buf_read_ble##size##_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut##size *result, bool big_endian) { \
		rz_return_val_if_fail(b &&result, false); \
\
		ut8 tmp[sizeof(ut##size)]; \
		if (rz_buf_read_at(b, addr, tmp, sizeof(tmp)) != sizeof(tmp)) { \
			return false; \
		} \
\
		*result = rz_read_ble##size(tmp, big_endian); \
		return true; \
	}

#define DEFINE_RZ_BUF_WRITE_BLE(size) \
	static inline bool rz_buf_write_ble##size(RZ_NONNULL RzBuffer *b, ut##size value, bool big_endian) { \
		ut8 tmp[sizeof(ut##size)]; \
		rz_write_ble##size(tmp, value, big_endian); \
\
		return rz_buf_write(b, tmp, sizeof(tmp)) == sizeof(tmp); \
	} \
\
	static inline bool rz_buf_write_ble##size##_at(RZ_NONNULL RzBuffer *b, ut64 addr, ut##size value, bool big_endian) { \
		ut8 tmp[sizeof(ut##size)]; \
		rz_write_ble##size(tmp, value, big_endian); \
\
		return rz_buf_write_at(b, addr, tmp, sizeof(tmp)) == sizeof(tmp); \
	}

/**
 * \brief Read a big endian or little endian (ut16, ut32, ut64) at the specified address or cursor in the buffer.
 * \param b ...
 * \param addr (optional)
 * \param result ...
 * \param big_endian ...
 * \return Return the status of the operation.
 */
DEFINE_RZ_BUF_READ_BLE(16)
DEFINE_RZ_BUF_READ_BLE(32)
DEFINE_RZ_BUF_READ_BLE(64)
DEFINE_RZ_BUF_READ_BLE(128)

/**
 * \brief Write a big endian or little endian ut16 at the specified address or cursor in the buffer.
 * \param b ...
 * \param addr (optional)
 * \param result ...
 * \param big_endian ...
 * \return Return the status of the operation.
 */
DEFINE_RZ_BUF_WRITE_BLE(16)
DEFINE_RZ_BUF_WRITE_BLE(32)
DEFINE_RZ_BUF_WRITE_BLE(64)
DEFINE_RZ_BUF_WRITE_BLE(128)

#define DEFINE_RZ_BUF_READ_OFFSET_BLE(size) \
	static inline bool rz_buf_read_ble##size##_offset(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT ut##size *result, bool big_endian) { \
		rz_return_val_if_fail(b &&offset &&result, false); \
		if (!rz_buf_read_ble##size##_at(b, *offset, result, big_endian)) { \
			return false; \
		} \
		*offset += sizeof(*result); \
		return true; \
	}

static inline bool rz_buf_read_offset(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT ut8 *result, size_t size) {
	rz_return_val_if_fail(b && offset && result, false);
	if (rz_buf_read_at(b, *offset, result, size) != (st64)size) {
		return false;
	}
	*offset += size;
	return true;
}

#define DEFINE_RZ_BUF_WRITE_OFFSET_BLE(size) \
	static inline bool rz_buf_write_ble##size##_offset(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_INOUT ut64 *offset, ut##size value, bool big_endian) { \
		rz_return_val_if_fail(b &&offset, false); \
		if (!rz_buf_write_ble##size##_at(b, *offset, value, big_endian)) { \
			return false; \
		} \
		*offset += sizeof(value); \
		return true; \
	}

static inline bool rz_buf_write_offset(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL ut8 *result, size_t size) {
	rz_return_val_if_fail(b && offset && result, false);
	if (rz_buf_write_at(b, *offset, result, size) != (st64)size) {
		return false;
	}
	*offset += size;
	return true;
}

#define rz_buf_read_ble8_at(b, addr, result, endian) ((void)endian, rz_buf_read8_at(b, addr, result))
#define rz_buf_write_ble8_at(b, addr, value, endian) ((void)endian, rz_buf_write8_at(b, addr, value))

/**
 * \brief Read a big endian or little endian (ut16, ut32, ut64) at the specified offset in the buffer and shifts the offset.
 * \param b ...
 * \param offset ...
 * \param result ...
 * \param big_endian ...
 * \return Return the status of the operation.
 */
DEFINE_RZ_BUF_READ_OFFSET_BLE(8)
DEFINE_RZ_BUF_READ_OFFSET_BLE(16)
DEFINE_RZ_BUF_READ_OFFSET_BLE(32)
DEFINE_RZ_BUF_READ_OFFSET_BLE(64)

/**
 * \brief Write a big endian or little endian ut16 at the specified address or cursor in the buffer and shifts the offset.
 * \param b ...
 * \param addr (optional)
 * \param result ...
 * \param big_endian ...
 * \return Return the status of the operation.
 */
DEFINE_RZ_BUF_WRITE_OFFSET_BLE(8)
DEFINE_RZ_BUF_WRITE_OFFSET_BLE(16)
DEFINE_RZ_BUF_WRITE_OFFSET_BLE(32)
DEFINE_RZ_BUF_WRITE_OFFSET_BLE(64)

#define rz_buf_read_le16(b, result) rz_buf_read_ble16(b, result, false)
#define rz_buf_read_le32(b, result) rz_buf_read_ble32(b, result, false)
#define rz_buf_read_le64(b, result) rz_buf_read_ble64(b, result, false)

#define rz_buf_read_le16_at(b, addr, result) rz_buf_read_ble16_at(b, addr, result, false)
#define rz_buf_read_le32_at(b, addr, result) rz_buf_read_ble32_at(b, addr, result, false)
#define rz_buf_read_le64_at(b, addr, result) rz_buf_read_ble64_at(b, addr, result, false)

#define rz_buf_read8_offset(b, offset, result) rz_buf_read_ble8_offset(b, offset, result, false)

#define rz_buf_read_le16_offset(b, offset, result) rz_buf_read_ble16_offset(b, offset, result, false)
#define rz_buf_read_le32_offset(b, offset, result) rz_buf_read_ble32_offset(b, offset, result, false)
#define rz_buf_read_le64_offset(b, offset, result) rz_buf_read_ble64_offset(b, offset, result, false)

#define rz_buf_read_be16(b, result) rz_buf_read_ble16(b, result, true)
#define rz_buf_read_be32(b, result) rz_buf_read_ble32(b, result, true)
#define rz_buf_read_be64(b, result) rz_buf_read_ble64(b, result, true)

#define rz_buf_read_be16_at(b, addr, result) rz_buf_read_ble16_at(b, addr, result, true)
#define rz_buf_read_be32_at(b, addr, result) rz_buf_read_ble32_at(b, addr, result, true)
#define rz_buf_read_be64_at(b, addr, result) rz_buf_read_ble64_at(b, addr, result, true)

#define rz_buf_read_be16_offset(b, offset, result) rz_buf_read_ble16_offset(b, offset, result, true)
#define rz_buf_read_be32_offset(b, offset, result) rz_buf_read_ble32_offset(b, offset, result, true)
#define rz_buf_read_be64_offset(b, offset, result) rz_buf_read_ble64_offset(b, offset, result, true)

#define rz_buf_write_le16(b, value) rz_buf_write_ble16(b, value, false)
#define rz_buf_write_le32(b, value) rz_buf_write_ble32(b, value, false)
#define rz_buf_write_le64(b, value) rz_buf_write_ble64(b, value, false)

#define rz_buf_write_le16_at(b, addr, value) rz_buf_write_ble16_at(b, addr, value, false)
#define rz_buf_write_le32_at(b, addr, value) rz_buf_write_ble32_at(b, addr, value, false)
#define rz_buf_write_le64_at(b, addr, value) rz_buf_write_ble64_at(b, addr, value, false)

#define rz_buf_write8_offset(b, offset, value) rz_buf_write_ble8_offset(b, offset, value, false)

#define rz_buf_write_le16_offset(b, offset, value) rz_buf_write_ble16_offset(b, offset, value, false)
#define rz_buf_write_le32_offset(b, offset, value) rz_buf_write_ble32_offset(b, offset, value, false)
#define rz_buf_write_le64_offset(b, offset, value) rz_buf_write_ble64_offset(b, offset, value, false)

#define rz_buf_write_be16(b, value) rz_buf_write_ble16(b, value, true)
#define rz_buf_write_be32(b, value) rz_buf_write_ble32(b, value, true)
#define rz_buf_write_be64(b, value) rz_buf_write_ble64(b, value, true)

#define rz_buf_write_be16_at(b, addr, value) rz_buf_write_ble16_at(b, addr, value, true)
#define rz_buf_write_be32_at(b, addr, value) rz_buf_write_ble32_at(b, addr, value, true)
#define rz_buf_write_be64_at(b, addr, value) rz_buf_write_ble64_at(b, addr, value, true)

#define rz_buf_write_be16_offset(b, offset, value) rz_buf_write_ble16_offset(b, offset, value, true)
#define rz_buf_write_be32_offset(b, offset, value) rz_buf_write_ble32_offset(b, offset, value, true)
#define rz_buf_write_be64_offset(b, offset, value) rz_buf_write_ble64_offset(b, offset, value, true)

#undef DEFINE_RZ_BUF_READ_BLE
#undef DEFINE_RZ_BUF_WRITE_BLE
#undef DEFINE_RZ_BUF_READ_OFFSET_BLE
#undef DEFINE_RZ_BUF_WRITE_OFFSET_BLE

/**
 * \brief Peeks at the next byte in the buffer without modify the buffer position.
 *
 * It assumes that the buffer contains at least one byte beyond the current position.
 * otherwise, the behavior of the function is undefined.
 * \param b The buffer
 * \return The byte value
 */
static inline ut8 rz_buf_peek(RZ_NONNULL RzBuffer *b) {
	ut8 x = 0;
	rz_buf_read8_at(b, rz_buf_tell(b), &x);
	return x;
}

// sparse-specific

RZ_API const RzBufferSparseChunk *rz_buf_sparse_get_chunks(RzBuffer *b, RZ_NONNULL size_t *count);
RZ_API void rz_buf_sparse_set_write_mode(RzBuffer *b, RzBufferSparseWriteMode mode);
RZ_API bool rz_buf_sparse_populated_in(RzBuffer *b, ut64 from, ut64 to);

RZ_API bool rz_deflatew_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed, int wbits);
RZ_API bool rz_deflate_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed);
RZ_API bool rz_inflatew_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed, int wbits);
RZ_API bool rz_inflate_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed);
RZ_API bool rz_lzma_dec_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed);
RZ_API bool rz_lzma_enc_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BUF_H
