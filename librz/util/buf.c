// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_io.h>

typedef enum {
	RZ_BUFFER_FILE,
	RZ_BUFFER_IO_FD,
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
#include "buf_io_fd.c"
#include "buf_io.c"
#include "buf_ref.c"

#define GET_STRING_BUFFER_SIZE 32

static void buf_whole_buf_free(RzBuffer *b) {
	// free the whole_buf only if it was initially allocated by the buf types
	if (b->methods->get_whole_buf) {
		if (b->methods->free_whole_buf) {
			b->methods->free_whole_buf(b);
		}
	} else {
		RZ_FREE(b->whole_buf);
	}
}

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

	return b->methods->get_size ? b->methods->get_size(b) : 0;
}

static st64 buf_read(RzBuffer *b, ut8 *buf, size_t len) {
	rz_return_val_if_fail(b && b->methods, -1);

	return b->methods->read ? b->methods->read(b, buf, len) : -1;
}

static st64 buf_write(RzBuffer *b, const ut8 *buf, size_t len) {
	rz_return_val_if_fail(b && b->methods, -1);

	buf_whole_buf_free(b);

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

typedef struct {
	ut16 repeat;
	ut8 type_size;
	ut8 big_endian;
} BufFormatToken;

static st64 buf_format(RzBuffer *dst, RzBuffer *src, const char *fmt, int n) {
	RzVector /*<BufFormatToken>*/ tokens;
	rz_vector_init(&tokens, sizeof(BufFormatToken), NULL, NULL);
	unsigned repeat = 1;
	for (size_t j = 0; fmt[j]; j++) {
		unsigned tsize = 0;
		bool bigendian = false;
		switch (fmt[j]) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if (repeat == 1) {
				char *end = (char *)&fmt[j + 1];
				repeat = strtoul(&fmt[j], &end, 10);
				j += (ptrdiff_t)(end - &fmt[j]) - 1;
			}
			continue;
		case 'S':
			bigendian = true;
			/* fall-thru */
		case 's':
			tsize = 2;
			break;
		case 'I':
			bigendian = true;
			/* fall-thru */
		case 'i':
			tsize = 4;
			break;
		case 'L':
			bigendian = true;
			/* fall-thru */
		case 'l':
			tsize = 8;
			break;
		case 'c':
			tsize = 1;
			break;
		default:
			goto err_exit;
		}
		if (!tsize || repeat > UT16_MAX) {
			goto err_exit;
		}
		BufFormatToken tok = {
			.repeat = repeat,
			.type_size = tsize,
			.big_endian = bigendian
		};
		if (!rz_vector_push(&tokens, &tok)) {
			goto err_exit;
		}
		repeat = 1;
	}

	if (rz_vector_empty(&tokens)) {
		goto err_exit;
	}

	st64 res = 0;
	for (int i = 0; i < n; i++) {
		const BufFormatToken *tok;
		rz_vector_foreach (&tokens, tok) {
			if (tok->type_size == 1) {
				ut8 tmp[8];
				size_t nbytes = tok->repeat;
				while (nbytes != 0) {
					size_t block_sz = RZ_MIN(sizeof(tmp), nbytes);
					if (rz_buf_read(src, tmp, block_sz) != block_sz) {
						goto err_exit;
					}
					if (rz_buf_write(dst, tmp, block_sz) != block_sz) {
						goto err_exit;
					}
					res += block_sz;
					nbytes -= block_sz;
				}
				continue;
			}
			for (int k = 0; k < tok->repeat; k++) {
				ut8 tmp[sizeof(ut64)];
				st64 r = rz_buf_read(src, tmp, tok->type_size);
				if (r < tok->type_size) {
					goto err_exit;
				}

				if (tok->big_endian != RZ_SYS_ENDIAN && tok->type_size > 1) {
					// just swap endianness if the host endianness
					// is not the same and is not one byte
					switch (tok->type_size) {
					case 2: {
						ut16 value = rz_read_ble16(tmp, tok->big_endian);
						rz_write_ble16(tmp, value, RZ_SYS_ENDIAN);
						break;
					}
					case 4: {
						ut32 value = rz_read_ble32(tmp, tok->big_endian);
						rz_write_ble32(tmp, value, RZ_SYS_ENDIAN);
						break;
					}
					case 8: {
						ut64 value = rz_read_ble64(tmp, tok->big_endian);
						rz_write_ble64(tmp, value, RZ_SYS_ENDIAN);
						break;
					}
					default:
						goto err_exit;
					}
				}
				r = rz_buf_write(dst, tmp, tok->type_size);

				if (r < tok->type_size) {
					goto err_exit;
				}
				res += r;
			}
		}
	}

	rz_vector_fini(&tokens);
	return res;

err_exit:
	rz_vector_fini(&tokens);
	return -1;
}

static bool buf_move_back(RZ_NONNULL RzBuffer *b, ut64 addr, ut64 length) {
	rz_return_val_if_fail(b, -1);

	ut64 size = rz_buf_size(b);
	if (size < addr) {
		return false;
	}

	ut8 *tmp = RZ_NEWS(ut8, size - addr);
	if (!tmp) {
		return false;
	}

	bool res = false;
	st64 tmp_length = rz_buf_read_at(b, addr, tmp, size - addr);
	if (tmp_length < 0) {
		goto err;
	}

	if (!rz_buf_resize(b, size + length)) {
		goto err;
	}

	if (rz_buf_write_at(b, addr + length, tmp, tmp_length) < 0) {
		goto err;
	}

	res = true;
err:
	free(tmp);
	return res;
}

static ut8 *get_whole_buf(RzBuffer *b, ut64 *size) {
	rz_return_val_if_fail(b && size && b->methods, NULL);

	buf_whole_buf_free(b);

	if (b->methods->get_whole_buf) {
		return b->methods->get_whole_buf(b, size);
	}

	ut64 buf_size = rz_buf_size(b);
	// bsz = 4096; // FAKE MINIMUM SIZE TO READ THE BIN HEADER
	if (buf_size == UT64_MAX) {
		return NULL;
	}

	b->whole_buf = RZ_NEWS(ut8, buf_size);
	if (!b->whole_buf) {
		return NULL;
	}

	if (rz_buf_read_at(b, 0, b->whole_buf, buf_size) < 0) {
		RZ_FREE(b->whole_buf);
		return NULL;
	}

	*size = buf_size;

	return b->whole_buf;
}

static RzBuffer *new_buffer(RzBufferType type, void *user) {
	const RzBufferMethods *methods = NULL;

	switch (type) {
	case RZ_BUFFER_BYTES:
		methods = &buffer_bytes_methods;
		break;
	case RZ_BUFFER_MMAP:
		methods = &buffer_mmap_methods;
		break;
	case RZ_BUFFER_SPARSE:
		methods = &buffer_sparse_methods;
		break;
	case RZ_BUFFER_FILE:
		methods = &buffer_file_methods;
		break;
	case RZ_BUFFER_IO_FD:
		methods = &buffer_io_fd_methods;
		break;
	case RZ_BUFFER_IO:
		methods = &buffer_io_methods;
		break;
	case RZ_BUFFER_REF:
		methods = &buffer_ref_methods;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	return rz_buf_new_with_methods(methods, user);
}

/**
 * \brief Creates a new empty buffer with a predefined size;
 * \param len The length in byte of the new buffer.
 * \return Return the new allocated buffer.
 *
 * The function creates a new buffer of the specified length in memory, filled
 * with \0.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_empty(ut64 len) {
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

/**
 * \brief Creates a new buffer from a file.
 * \param file The filename used to create the new buffer.
 * \param perm Same meaning than the symbolic constants defined in sys/stat.h.
 * \param mode Same meaning than the symbolic constants use with open (fcntl.h).
 * \return Return the new allocated buffer.
 *
 * \see rz_sys_open()
 *
 * The function creates a new buffer synchronized with the file content,
 * opening it with rz_sys_open and using regular read/write operations to
 * change its content.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_file(const char *file, int perm, int mode) {
	struct buf_file_user u = { 0 };

	u.file = file;
	u.perm = perm;
	u.mode = mode;

	return new_buffer(RZ_BUFFER_FILE, &u);
}

/**
 * \brief Creates a new buffer from a file using rz_file_mmap.
 * \param file The filename used to create the new buffer.
 * \param perm Same meaning than the symbolic constants defined in sys/stat.h.
 * \param mode Same meaning than the symbolic constants use with open (fcntl.h).
 * \return Return the new allocated buffer.
 *
 * \see rz_file_mmap()
 *
 * The function creates a new buffer synchronized with the file content, using
 * mmap to access the file.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_mmap(const char *filename, int perm, int mode) {
	rz_return_val_if_fail(filename, NULL);

	struct buf_mmap_user u = { 0 };
	u.filename = filename;
	u.perm = perm;
	u.mode = mode;

	return new_buffer(RZ_BUFFER_MMAP, &u);
}

/**
 * \brief Creates a new buffer from a slice of another buffer.
 * \param b The source buffer used to create the sub buffer.
 * \param offset The starting offset in the source buffer.
 * \param size The number of bytes that will be extract from the source buffer.
 * \return Return the new allocated buffer.
 *
 * \see rz_buf_ref()
 *
 * The function creates a new buffer which shows just a slice of another one,
 * passed as argument. The allocated buffer will reference the source buffer.
 * So both buffer are synchronized.
 *
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_slice(RzBuffer *b, ut64 offset, ut64 size) {
	struct buf_ref_user u = { 0 };

	u.parent = b;
	u.offset = offset;
	u.size = size;

	return new_buffer(RZ_BUFFER_REF, &u);
}

// TODO: rename to new_from_file ?
/**
 * \brief Creates a new buffer from a file.
 * \param file The filename used to create the new buffer.
 * \return Return the new allocated buffer.
 *
 * The function creates a new buffer in memory, initializing it with the whole
 * content of the specified file.
 *
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_slurp(const char *file) {
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

/**
 * \brief Creates a sparse buffer.
 * \param Oxff The byte used to fill unpopulated bytes.
 * \return Return the new allocated buffer.
 *
 * The function creates a new allocated buffer using the RZ_BUFFER_SPARSE back end.
 * Creates a new sparse RzBuffer where unpopulated bytes are filled with Oxff parameter.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_sparse(ut8 Oxff) {
	RzBuffer *b = new_buffer(RZ_BUFFER_SPARSE, NULL);
	if (b) {
		b->Oxff_priv = Oxff;
	}

	return b;
}

/**
 * \brief Creates a sparse buffer from a already populated buffer.
 * \param b The source buffer used to create the sub buffer.
 * \param write_mode Defined how byte are written to the buffer.
 * \return Return the new allocated buffer.
 *
 * The function creates a new allocated buffer using the RZ_BUFFER_SPARSE back end.
 * Creates a new sparse RzBuffer where unpopulated bytes are taken as-is from b
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_sparse_overlay(RzBuffer *b, RzBufferSparseWriteMode write_mode) {
	rz_return_val_if_fail(b, NULL);

	SparseInitConfig cfg = {
		.base = b,
		.write_mode = write_mode
	};

	return new_buffer(RZ_BUFFER_SPARSE, &cfg);
}

/**
 * \brief Creates a new buffer from a source buffer.
 * \param b The source buffer used to create the sub buffer.
 * \return Return the new allocated buffer.
 *
 * \see rz_buf_new_with_bytes()
 *
 * The function creates a new allocated buffer using the RZ_BUFFER_BYTES back end.
 * WARNING: this function doesn't use reference counting, this can lead to a lot
 * of memory overhead.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_buf(RzBuffer *b) {
	ut64 size = 0;
	const ut8 *tmp = get_whole_buf(b, &size);

	return rz_buf_new_with_bytes(tmp, size);
}

/**
 * \brief Creates a new buffer with a bytes array.
 * \param bytes The bytes array used to initialized the buffer.
 * \param len The length of the bytes array.
 * \return Return the new allocated buffer.
 *
 * The function creates a new buffer in memory, initializing it with the bytes
 * passed as argument. The bytes parameter can be NULL, but the length should
 * be set to 0.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_bytes(RZ_NULLABLE RZ_BORROW const ut8 *bytes, ut64 len) {
	rz_return_val_if_fail(bytes || !len, NULL); // if bytes == NULL, then len must be 0

	struct buf_bytes_user u = { 0 };
	u.data = bytes;
	u.length = len;

	return new_buffer(RZ_BUFFER_BYTES, &u);
}

// TODO: Optimize to use memcpy when buffers are not in range..
// check buf boundaries and offsets and use memcpy or memmove

// copied from librz/io/cache.c:rz_io_cache_read
// ret # of bytes copied

/**
 * \brief Creates a new buffer wrapping a file descriptor accessed through RzIOBind.
 * \param iob Pointer to RzIOBind structure.
 * \param fd File descriptor to wrap in the buffer.
 * \return Return the new allocated buffer.
 *
 * The function creates a new buffer wrapping access to a file descriptor
 * through the RzIOBind methods specified in librz/io.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_io_fd(RZ_NONNULL void *iob, int fd) {
	rz_return_val_if_fail(iob && fd >= 0, NULL);

	struct buf_io_fd_user u = { 0 };

	u.iob = (RzIOBind *)iob;
	u.fd = fd;

	return new_buffer(RZ_BUFFER_IO_FD, &u);
}

/**
 * \brief Creates a new buffer wrapping the memory map exposed by RzIOBind.
 * \param iob Pointer to RzIOBind structure.
 * \return Return the new allocated buffer.
 *
 * This buffer will use `rz_io_read_at()`/`rz_io_write_at()` as implemented by
 * the RzIOBind given.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_io(RZ_NONNULL void *iob) {
	rz_return_val_if_fail(iob, NULL);
	return new_buffer(RZ_BUFFER_IO, iob);
}

/**
 * \brief Creates a new buffer with a specific back end.
 * \param methods A struct holding the list of methods to use.
 * \param init_user Some implementation specific information.
 * \return Return the new allocated buffer.
 *
 * \see RzBufferMethods
 *
 * The function creates a new allocated buffer using a custom back end. This function
 * should only be used when no other back end are appropriate.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_methods(RZ_NONNULL const RzBufferMethods *methods, void *init_user) {
	RzBuffer *b = RZ_NEW0(RzBuffer);
	if (!b) {
		return NULL;
	}

	b->methods = methods;

	if (!buf_init(b, init_user)) {
		free(b);
		return NULL;
	}

	return b;
}

/**
 * \brief Creates a new buffer with a bytes array.
 * \param bytes The bytes array used to initialized the buffer.
 * \param len The length of the bytes array.
 * \param steal If the boolean is true the function take the ownership of the data.
 * \return Return the new allocated buffer.
 *
 * The function creates a new buffer in memory. The argument \p bytes is used
 * as the memory backend if \p steal is true, otherwise a new buffer is
 * allocated and its content is initialized with the one from \p bytes.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal) {
	struct buf_bytes_user u = { 0 };

	u.data_steal = bytes;
	u.length = len;
	u.steal = steal;

	return new_buffer(RZ_BUFFER_BYTES, &u);
}

/**
 * \brief Creates a new buffer from a string.
 * \param msg The source string used to create the buffer.
 * \return Return the new allocated buffer.
 *
 * The function creates a new buffer in memory, initializing it with the string
 * passed as argument.
 */
RZ_API RZ_OWN RzBuffer *rz_buf_new_with_string(RZ_NONNULL const char *msg) {
	return rz_buf_new_with_bytes((const ut8 *)msg, (ut64)strlen(msg));
}

/**
 * \brief Get a string with a max length from the buffer
 * \param b RzBuffer pointer
 * \param addr The address of the string
 * \param size The max length authorized
 * \return A string with a length <= size or NULL
 *
 * Return an heap-allocated string read from the RzBuffer b at address addr. The
 * length depends on the first '\0' found and the arguments size in the buffer.
 * If there is no '\0' in the buffer, there is no string, thus NULL is returned.
 */
RZ_API RZ_OWN char *rz_buf_get_nstring(RZ_NONNULL RzBuffer *b, ut64 addr, size_t size) {
	rz_return_val_if_fail(b, NULL);

	RzStrBuf *buf = rz_strbuf_new(NULL);

	while (true) {
		char tmp[GET_STRING_BUFFER_SIZE + 1];
		st64 r = rz_buf_read_at(b, addr, (ut8 *)tmp, sizeof(tmp) - 1);
		if (r < 1) {
			rz_strbuf_free(buf);
			return NULL;
		}

		size_t count = rz_str_nlen(tmp, r);
		rz_strbuf_append_n(buf, tmp, count);

		if (count > size) {
			rz_strbuf_free(buf);
			return NULL;
		}

		if (count != r) {
			break;
		}

		addr += r;
		size -= count;
	}

	char *result = rz_strbuf_drain(buf);
	return result;
}

/**
 * \brief Get a string from the buffer
 * \param b RzBuffer pointer
 * \param addr The address of the string
 * \return A string with a length <= size or NULL
 *
 * Return an heap-allocated string read from the RzBuffer b at address addr. The
 * length depends on the first '\0' found in the buffer. If there is no '\0' in
 * the buffer, there is no string, thus NULL is returned.
 */
RZ_API RZ_OWN char *rz_buf_get_string(RZ_NONNULL RzBuffer *b, ut64 addr) {
	rz_return_val_if_fail(b, NULL);

	return rz_buf_get_nstring(b, addr, rz_buf_size(b));
}

/**
 * \brief Get a string from the buffer
 * \param b RzBuffer pointer
 * \param s The pointer to output the string
 * \return Length of the string
 *
 * Return an heap-allocated string read from \p b. The length depends on
 * the first '\0' found in the buffer. If there is no '\0' in
 * the buffer, there is no string, thus 0 is returned.
 */
RZ_API ut64 rz_buf_read_string(RZ_NONNULL RzBuffer *b, RZ_BORROW RZ_NULLABLE char **s) {
	rz_return_val_if_fail(b, 0);
	char *tmp = rz_buf_get_string(b, rz_buf_tell(b));
	if (!tmp) {
		return 0;
	}
	const ut64 string_len = strlen(tmp) + 1;
	rz_buf_seek(b, string_len, RZ_BUF_CUR);
	if (s) {
		*s = tmp;
	} else {
		free(tmp);
	}
	return string_len;
}

/**
 * \brief Stringify the buffer
 * \param b RzBuffer pointer
 * \return Return an allocated string.
 *
 * The string is guaranteed to be NULL terminated even if the buffer doesn't have
 * any NULL bytes.
 */
RZ_API RZ_OWN char *rz_buf_to_string(RZ_NONNULL RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);

	ut64 size = rz_buf_size(b);
	char *result = RZ_NEWS(char, size + 1);
	if (!result) {
		return NULL;
	}

	if (rz_buf_read_at(b, 0, (ut8 *)result, size) < 0) {
		free(result);
		return NULL;
	}

	result[size] = '\0';

	return result;
}

/**
 * \brief Increment the reference count of the buffer
 * \param b RzBuffer to reference
 * \return Return the same value \p b
 *
 * The function increment the reference count of the buffer
 */
RZ_API RzBuffer *rz_buf_ref(RzBuffer *b) {
	if (b) {
		b->refctr++;
	}

	return b;
}

/**
 * \brief Append the content of the buffer a to the buffer b.
 * \param dst the destination buffer with write permission
 * \param src the source buffer
 * \return Return the status of the operation.
 *
 * The function append the content of the buffer a, the two buffer don't need to
 * have the same back end. WARNING: This function can allocate a lot of memory.
 */
RZ_API bool rz_buf_append_buf(RZ_NONNULL RzBuffer *b, RZ_NONNULL RzBuffer *a) {
	rz_return_val_if_fail(b && a && !b->readonly, false);

	ut64 size = 0;
	const ut8 *tmp = get_whole_buf(a, &size);

	return rz_buf_append_bytes(b, tmp, size);
}

/**
 * \brief Append a slice of the buffer a to the buffer b.
 * \param dst the destination buffer with write permission
 * \param src the source buffer
 * \param offset The starting offset in the buffer a.
 * \param size The number of bytes that will be extract from the buffer a.
 * \return Return the status of the operation.
 *
 * The function append a slice of the buffer a, the two buffer don't need to
 * have the same back end. WARNING: This function can allocate a lot of memory.
 */
RZ_API bool rz_buf_append_buf_slice(RZ_NONNULL RzBuffer *b, RZ_NONNULL RzBuffer *a, ut64 offset, ut64 size) {
	rz_return_val_if_fail(b && a && !b->readonly, false);

	ut8 *tmp = RZ_NEWS(ut8, size);
	if (!tmp) {
		return false;
	}

	st64 r = rz_buf_read_at(a, offset, tmp, size);
	if (r < 0) {
		free(tmp);
		return false;
	}

	bool result = rz_buf_append_bytes(b, tmp, r);

	free(tmp);
	return result;
}

/**
 * \brief Append an array of bytes to the buffer.
 * \param dst the destination buffer with write permission
 * \param src the source buffer
 * \param length ...
 * \return Return the status of the operation.
 */
RZ_API bool rz_buf_append_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && buf && !b->readonly, false);

	if (rz_buf_seek(b, 0, RZ_BUF_END) < 0) {
		return false;
	}

	return rz_buf_write(b, buf, length) == length;
}

/**
 * \brief Extend the size of the buffer.
 * \param b A buffer with write permission.
 * \param length The number of bytes to add at the end of the buffer.
 * \return Return the status of the operation.
 */
RZ_API bool rz_buf_append_nbytes(RZ_NONNULL RzBuffer *b, ut64 length) {
	rz_return_val_if_fail(b && !b->readonly, false);

	return rz_buf_resize(b, rz_buf_size(b) + length);
}

/**
 * \brief Add a ut16 number at the end of the buffer.
 * \param b A buffer with write permission.
 * \param n
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_append_ut16(RZ_NONNULL RzBuffer *b, ut16 n) {
	rz_return_val_if_fail(b && !b->readonly, false);

	return rz_buf_append_bytes(b, (const ut8 *)&n, sizeof(n));
}

/**
 * \brief Add a ut32 number at the end of the buffer.
 * \param b A buffer with write permission.
 * \param n
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_append_ut32(RZ_NONNULL RzBuffer *b, ut32 n) {
	rz_return_val_if_fail(b && !b->readonly, false);

	return rz_buf_append_bytes(b, (const ut8 *)&n, sizeof(n));
}

/**
 * \brief Add a ut64 number at the end of the buffer.
 * \param b A buffer with write permission.
 * \param n
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_append_ut64(RZ_NONNULL RzBuffer *b, ut64 n) {
	rz_return_val_if_fail(b && !b->readonly, false);

	return rz_buf_append_bytes(b, (const ut8 *)&n, sizeof(n));
}

/**
 * \brief Dump the content of the buffer to a file.
 * \param b A buffer with write permission.
 * \param file The output file where the buffer content while be outputted.
 * \return Return the status of the operation.
 *
 * \see rz_file_dump()
 *
 * ...
 */
RZ_API bool rz_buf_dump(RZ_NONNULL RzBuffer *b, RZ_NONNULL const char *file) {
	rz_return_val_if_fail(b && file, false);

	ut64 size = 0;
	const ut8 *tmp = get_whole_buf(b, &size);

	return rz_file_dump(file, tmp, size, 0);
}

/**
 * \brief Free all internal data hold by the buffer.
 * \param b A buffer with write permission.
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_fini(RzBuffer *b) {
	if (!b) {
		return false;
	}

	if (b->refctr > 0) {
		b->refctr--;
		return false;
	}

	buf_whole_buf_free(b);

	return buf_fini(b);
}

/**
 * \brief Prepend an array of bytes to the buffer.
 * \param b A buffer with write permission.
 * \param buf ...
 * \param length ...
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_prepend_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && buf && !b->readonly, false);

	return rz_buf_insert_bytes(b, 0, buf, length) >= 0;
}

/**
 * \brief Read a byte at the cursor in the buffer.
 * \param b ...
 * \param result ...
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_read8(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut8 *result) {
	rz_return_val_if_fail(b && result, false);

	return rz_buf_read(b, result, sizeof(ut8)) == sizeof(ut8);
}

/**
 * \brief Read a byte at the specified address in the buffer.
 * \param b ...
 * \param addr ...
 * \param result ...
 * \return Return the status of the operation.
 *
 * \see rz_buf_read8()
 * ...
 */
RZ_API bool rz_buf_read8_at(RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut8 *result) {
	rz_return_val_if_fail(b && result, false);

	return rz_buf_read_at(b, addr, result, sizeof(ut8)) == sizeof(ut8);
}

/**
 * \brief Resize the buffer size.
 * \param b ...
 * \param newsize ...
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_resize(RZ_NONNULL RzBuffer *b, ut64 newsize) {
	rz_return_val_if_fail(b, false);

	return buf_resize(b, newsize);
}

/**
 * \brief Replace the content of the buffer with the bytes array.
 * \param b A buffer with write permission.
 * \param buf ...
 * \param length ...
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_set_bytes(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 length) {
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

/**
 * \brief Write a byte at the cursor in the buffer.
 * \param b ...
 * \param result ...
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API bool rz_buf_write8(RZ_NONNULL RzBuffer *b, ut8 value) {
	rz_return_val_if_fail(b, false);

	return rz_buf_write(b, &value, sizeof(ut8)) == sizeof(ut8);
}

/**
 * \brief Write a byte at the specified address in the buffer.
 * \param b ...
 * \param addr ...
 * \param value ...
 * \return Return the status of the operation.
 *
 * \see rz_buf_write8()
 *
 * ...
 */
RZ_API bool rz_buf_write8_at(RZ_NONNULL RzBuffer *b, ut64 addr, ut8 value) {
	rz_return_val_if_fail(b, false);

	return rz_buf_write_at(b, addr, &value, sizeof(ut8)) == sizeof(ut8);
}

/**
 * \brief Append a string to the buffer.
 * \param b A buffer with write permission.
 * \param str ...
 * \return Return the status of the operation.
 *
 * ...
 */
RZ_API st64 rz_buf_append_string(RZ_NONNULL RzBuffer *b, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(b && str && !b->readonly, false);

	return rz_buf_append_bytes(b, (const ut8 *)str, strlen(str));
}

/**
 * \brief ...
 * \param b ...
 * \param buf ...
 * \param fmt ...
 * \param n ...
 * \return ...
 *
 * ...
 */
RZ_API st64 rz_buf_fread(RZ_NONNULL RzBuffer *b, RZ_NONNULL ut8 *buf, RZ_NONNULL const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt, -1);

	// XXX: we assume the caller knows what he's doing
	RzBuffer *dst = rz_buf_new_with_pointers(buf, UT64_MAX, false);
	st64 res = buf_format(dst, b, fmt, n);

	rz_buf_free(dst);

	return res;
}

/**
 * \brief ...
 * \param b ...
 * \param addr ...
 * \param buf ...
 * \param fmt ...
 * \param n ...
 * \return ...
 *
 * ...
 */
RZ_API st64 rz_buf_fread_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL ut8 *buf, RZ_NONNULL const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt, -1);

	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	st64 result = rz_buf_fread(b, buf, fmt, n);

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return result;
}

/**
 * \brief ...
 * \param b ...
 * \param addr ...
 * \param buf ...
 * \param fmt ...
 * \param n ...
 * \return ...
 *
 * ...
 */
RZ_API st64 rz_buf_fwrite(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, RZ_NONNULL const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt && !b->readonly, -1);

	// XXX: we assume the caller knows what he's doing
	RzBuffer *src = rz_buf_new_with_pointers(buf, UT64_MAX, false);
	st64 result = buf_format(b, src, fmt, n);

	rz_buf_free(src);

	return result;
}

/**
 * \brief ...
 * \param b ...
 * \param addr ...
 * \param buf ...
 * \param fmt ...
 * \param n ...
 * \return ...
 *
 * ...
 */
RZ_API st64 rz_buf_fwrite_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, RZ_NONNULL const char *fmt, int n) {
	rz_return_val_if_fail(b && buf && fmt && !b->readonly, -1);

	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	st64 result = rz_buf_fwrite(b, buf, fmt, n);

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return result;
}

/**
 * \brief Insert an array of bytes in the buffer.
 * \param b A buffer with write permission.
 * \param addr ...
 * \param buf ...
 * \param length ...
 * \return Return the number of bytes written.
 *
 * ...
 */
RZ_API st64 rz_buf_insert_bytes(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 length) {
	rz_return_val_if_fail(b && !b->readonly, -1);

	if (!buf_move_back(b, addr, length)) {
		return -1;
	}

	st64 result = rz_buf_write_at(b, addr, buf, length);
	if (result < 0) {
		return -1;
	}

	return result;
}

/**
 * \brief Read len bytes of the buffer at the cursor.
 * \param b ...
 * \param buf ...
 * \param len ...
 * \return Return the number of bytes read.
 *
 * ...
 */
RZ_API st64 rz_buf_read(RZ_NONNULL RzBuffer *b, RZ_NONNULL ut8 RZ_OUT *buf, ut64 len) {
	rz_return_val_if_fail(b && buf, -1);

	st64 result = buf_read(b, buf, len);
	if (result < 0) {
		return -1;
	}

	if (len > result) {
		memset(buf + result, b->Oxff_priv, len - result);
	}

	return result;
}

/**
 * \brief Read len bytes of the buffer at the specified address.
 * \param b ...
 * \param addr ...
 * \param buf ...
 * \param len ...
 * \return Return the number of bytes read.
 *
 * ...
 */
RZ_API st64 rz_buf_read_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL RZ_OUT ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf, -1);

	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	st64 result = -1;
	if (rz_buf_seek(b, addr, RZ_BUF_SET) >= 0) {
		result = rz_buf_read(b, buf, len);
	}

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return result;
}

/**
 * \brief Modify the current cursor position in the buffer.
 * \param b ...
 * \param addr ...
 * \param whence The relative position of the address.
 * \return Return the new cursor position
 *
 * ...
 */
RZ_API st64 rz_buf_seek(RZ_NONNULL RzBuffer *b, st64 addr, int whence) {
	rz_return_val_if_fail(b, -1);

	return buf_seek(b, addr, whence);
}

/**
 * \brief Write len bytes of the buffer at the cursor.
 * \param b A buffer with write permission.
 * \param buf ...
 * \param len ...
 * \return Return the number of bytes written.
 *
 * ...
 */
RZ_API st64 rz_buf_write(RZ_NONNULL RzBuffer *b, RZ_NONNULL const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf && !b->readonly, -1);

	return buf_write(b, buf, len);
}

/**
 * \brief Write len bytes of the buffer at the specified address.
 * \param b A buffer with write permission.
 * \param addr ...
 * \param buf ...
 * \param len ...
 * \return Return the number of bytes written.
 *
 * ...
 */
RZ_API st64 rz_buf_write_at(RZ_NONNULL RzBuffer *b, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(b && buf && !b->readonly, -1);

	st64 tmp = rz_buf_tell(b);
	if (tmp < 0) {
		return -1;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	st64 result = rz_buf_write(b, buf, len);

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return -1;
	}

	return result;
}

/**
 * \brief Return the size of the buffer
 * \param b ...
 * \return ...
 *
 * ...
 */
RZ_API ut64 rz_buf_size(RZ_NONNULL RzBuffer *b) {
	rz_return_val_if_fail(b, 0);

	return buf_get_size(b);
}

/**
 * \brief Return the current cursor position.
 * \param b ...
 * \return ...
 *
 * ...
 */
RZ_API ut64 rz_buf_tell(RZ_NONNULL RzBuffer *b) {
	rz_return_val_if_fail(b, 0);

	return rz_buf_seek(b, 0, RZ_BUF_CUR);
}

/**
 * \brief Free all internal data hold by the buffer and the buffer.
 * \param b ...
 * \return Return the status of the operation.
 *
 * \see rz_buf_fini()
 *
 * ...
 */
RZ_API void rz_buf_free(RzBuffer *b) {
	if (!b) {
		return;
	}
	if (rz_buf_fini(b)) {
		free(b);
	}
}

/**
 * \brief Change the overflow byte used in the RZ_BUFFER_SPARSE.
 * \param b ...
 * \param Oxff The new byte filling value.
 *
 * \see rz_buf_new_sparse()
 * \see rz_buf_new_sparse_overlay()
 *
 * Set the content that bytes read outside the buffer bounds should have.
 */
RZ_API void rz_buf_set_overflow_byte(RZ_NONNULL RzBuffer *b, ut8 Oxff) {
	rz_return_if_fail(b);

	b->Oxff_priv = Oxff;
}

/**
 * \brief Return a borrowed array of bytes representing the buffer data.
 * \param b Buffer to get the data from.
 * \param size Size of the returned data.
 *
 * WARNING: this function should be used with care because it may allocate the
 * entire buffer in memory. Consider using the rz_buf_read* APIs or rz_buf_fwd_scan API instead and
 * read only the chunks you need.
 */
RZ_DEPRECATE RZ_API RZ_BORROW ut8 *rz_buf_data(RZ_NONNULL RzBuffer *b, RZ_NONNULL RZ_OUT ut64 *size) {
	rz_return_val_if_fail(b && size, NULL);

	return get_whole_buf(b, size);
}

/**
 * \brief Scans buffer linearly in chunks calling \p fwd_scan for each chunk.
 *
 * \param b RzBuffer to read
 * \param start Start address
 * \param amount Amount of bytes to read
 * \param fwd_scan Function to call for each chunk
 * \param user User data to pass to fwd_scan
 * \return Number of bytes read
 */
RZ_API ut64 rz_buf_fwd_scan(RZ_NONNULL RzBuffer *b, ut64 start, ut64 amount, RZ_NONNULL RzBufferFwdScan fwd_scan, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(b && fwd_scan, 0);
	if (!amount) {
		return 0;
	}
	if (b->methods->get_whole_buf) {
		ut64 sz;
		const ut8 *buf = b->methods->get_whole_buf(b, &sz);
		if (buf) {
			if (sz <= start) {
				return 0;
			}
			return fwd_scan(buf + start, RZ_MIN(sz - start, amount), user);
		}
	}
	const ut64 size = rz_buf_size(b);
	if (size <= start) {
		return 0;
	}
	if (b->whole_buf) {
		return fwd_scan(b->whole_buf + start, RZ_MIN(size - start, amount), user);
	}
	ut64 addr = start;
	const ut64 user_end = UT64_ADD_OVFCHK(start, amount) ? UT64_MAX : start + amount;
	const ut64 end = RZ_MIN(user_end, size);
	const size_t buf_size = RZ_MIN(end - start, 0x1000);
	ut8 *buf = malloc(buf_size);
	if (!buf) {
		return 0;
	}
	while (addr < end) {
		const ut64 read_amount = RZ_MIN(buf_size, end - addr);
		rz_buf_read_at(b, addr, buf, read_amount);
		ut64 read = fwd_scan(buf, read_amount, user);
		if (!read) {
			break;
		}
		addr += read;
	}
	free(buf);
	return addr - start;
}

/**
 * \brief  Decodes ULEB128 from RzBuffer
 *
 * \param  buffer Buffer used to decode the ULEB128.
 * \param  value  Decoded value.
 * \return The number of bytes used.
 */
RZ_API st64 rz_buf_uleb128(RZ_NONNULL RzBuffer *buffer, RZ_NONNULL ut64 *value) {
	rz_return_val_if_fail(buffer && value, -1);

	ut64 sum = 0, used = 0, slice;
	ut32 shift = 0;
	ut8 byte = 0;
	do {
		if (rz_buf_read(buffer, &byte, sizeof(byte)) < 1) {
			// malformed uleb128 due end of buffer
			return -1;
		}
		used++;
		slice = byte & 0x7f;
		if (shift >= 64 || (shift == 63 && slice > 1ULL) || ((slice << shift) >> shift) != slice) {
			// uleb128 too big for ut64
			return -1;
		}
		sum += slice << shift;
		shift += 7;
	} while (byte >= 128);
	*value = sum;
	return used;
}

/**
 * \brief  Decodes SLEB128 from RzBuffer
 *
 * \param  buffer Buffer used to decode the SLEB128.
 * \param  value  Decoded value.
 * \return The number of bytes used.
 */
RZ_API st64 rz_buf_sleb128(RZ_NONNULL RzBuffer *buffer, RZ_NONNULL st64 *value) {
	rz_return_val_if_fail(buffer && value, -1);

	ut64 used = 0, slice;
	st64 sum = 0;
	ut32 shift = 0;
	ut8 byte = 0;
	do {
		if (rz_buf_read(buffer, &byte, sizeof(byte)) < 1) {
			// malformed sleb128 due end of buffer
			return -1;
		}
		used++;
		slice = byte & 0x7f;
		if ((shift >= 64 && slice != (sum < 0 ? 0x7f : 0x00)) ||
			(shift == 63 && slice != 0 && slice != 0x7f)) {
			// sleb128 too big for st64
			return -1;
		}
		sum |= slice << shift;
		shift += 7;
	} while (byte >= 128);

	if (shift < 64 && (byte & 0x40)) {
		// extends negative sign
		sum |= (-1ull) << shift;
	}
	*value = sum;
	return used;
}
