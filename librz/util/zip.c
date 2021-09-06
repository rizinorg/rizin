// SPDX-FileCopyrightText: 2014-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <zlib.h>

// set a maximum output buffer of 50MB
#define MAXOUT 50000000

static const char *gzerr(int n) {
	const char *errors[] = {
		"",
		"file error", /* Z_ERRNO         (-1) */
		"stream error", /* Z_STREAM_ERROR  (-2) */
		"data error", /* Z_DATA_ERROR    (-3) */
		"insufficient memory", /* Z_MEM_ERROR     (-4) */
		"buffer error", /* Z_BUF_ERROR     (-5) */
		"incompatible version", /* Z_VERSION_ERROR (-6) */
	};
	if (n < 1 || n > 6) {
		return "unknown";
	}
	return errors[n];
}

/**
 * \brief inflate zlib compressed or gzipped, automatically accepts either the zlib or gzip format, and use MAX_WBITS as the window size logarithm.
 * \see rz_inflatew()
 */
RZ_API ut8 *rz_inflate(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen) {
	rz_return_val_if_fail(src, NULL);
	rz_return_val_if_fail(srcLen > 0, NULL);
	return rz_inflatew(src, srcLen, srcConsumed, dstLen, MAX_WBITS + 32);
}

/**
 * \brief inflate zlib compressed or gzipped. The input must be a raw stream with no header or trailer.
 * \see rz_inflatew()
 */
RZ_API ut8 *rz_inflate_ignore_header(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen) {
	rz_return_val_if_fail(src, NULL);
	rz_return_val_if_fail(srcLen > 0, NULL);
	return rz_inflatew(src, srcLen, srcConsumed, dstLen, -MAX_WBITS);
}

/**
 * \brief inflate zlib compressed or gzipped.
 * \param src source compressed bytes
 * \param srcLen source bytes length
 * \param srcConsumed consumed source bytes length
 * \param dstLen uncompressed bytes length
 * \param wbits the size of the history buffer (or “window size”), and what header and trailer format is expected.
 * \return ptr to uncompressed
 */
RZ_API ut8 *rz_inflatew(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen, int wbits) {
	rz_return_val_if_fail(src, NULL);
	rz_return_val_if_fail(srcLen > 0, NULL);

	int err = 0;
	int out_size = 0;
	ut8 *dst = NULL;
	ut8 *tmp_ptr;
	z_stream stream;

	memset(&stream, 0, sizeof(z_stream));
	stream.avail_in = srcLen;
	stream.next_in = (Bytef *)src;

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	if (inflateInit2(&stream, wbits) != Z_OK) {
		return NULL;
	}

	do {
		if (stream.avail_out == 0) {
			tmp_ptr = realloc(dst, stream.total_out + srcLen * 2);
			if (!tmp_ptr) {
				goto err_exit;
			}
			dst = tmp_ptr;
			out_size += srcLen * 2;
			if (out_size > MAXOUT) {
				goto err_exit;
			}
			stream.next_out = dst + stream.total_out;
			stream.avail_out = srcLen * 2;
		}
		err = inflate(&stream, Z_NO_FLUSH);
		if (err < 0) {
			RZ_LOG_ERROR("inflate error: %d %s\n", err, gzerr(-err));
			goto err_exit;
		}
	} while (err != Z_STREAM_END);

	if (dstLen) {
		*dstLen = stream.total_out;
	}
	if (srcConsumed) {
		*srcConsumed = (const ut8 *)stream.next_in - (const ut8 *)src;
	}

	inflateEnd(&stream);
	return dst;

err_exit:
	inflateEnd(&stream);
	free(dst);
	return NULL;
}

/**
 * \brief deflate uncompressed data to zlib or gzipped, use MAX_WBITS as the window size logarithm.
 * \see rz_deflatew()
 */
RZ_API ut8 *rz_deflate(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen) {
	rz_return_val_if_fail(src, NULL);
	rz_return_val_if_fail(srcLen > 0, NULL);
	return rz_deflatew(src, srcLen, srcConsumed, dstLen, MAX_WBITS + 16);
}

/**
 * \brief compress/deflate data to zlib or gzip
 * \param src source uncompressed bytes
 * \param srcLen source bytes length
 * \param srcConsumed consumed source bytes length
 * \param dstLen compressed bytes length
 * \param wbits the size of the history buffer (or “window size”), and what header and trailer format is expected.
 * \return ptr to compressed
 */
RZ_API ut8 *rz_deflatew(RZ_NONNULL const ut8 *src, int srcLen, int *srcConsumed, int *dstLen, int wbits) {
	rz_return_val_if_fail(src, NULL);
	rz_return_val_if_fail(srcLen > 0, NULL);

	int err = 0;
	int out_size = 0;
	ut8 *dst = NULL;
	ut8 *tmp_ptr;
	z_stream stream;

	memset(&stream, 0, sizeof(z_stream));

	stream.avail_in = srcLen;
	stream.next_in = (Bytef *)src;
	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		return NULL;
	}

	do {
		if (stream.avail_out == 0) {
			tmp_ptr = realloc(dst, stream.total_out + srcLen);
			if (!tmp_ptr) {
				goto err_exit;
			}
			dst = tmp_ptr;
			out_size += srcLen;
			if (out_size > MAXOUT) {
				goto err_exit;
			}
			stream.next_out = dst + stream.total_out;
			stream.avail_out = srcLen;
		}
		err = deflate(&stream, Z_FINISH);
		if (err < 0) {
			RZ_LOG_ERROR("deflate error: %d %s\n", err, gzerr(-err));
			goto err_exit;
		}
	} while (err != Z_STREAM_END);

	if (dstLen) {
		*dstLen = stream.total_out;
	}
	if (srcConsumed) {
		*srcConsumed = (const ut8 *)stream.next_in - (const ut8 *)src;
	}

	deflateEnd(&stream);
	return dst;

err_exit:
	deflateEnd(&stream);
	free(dst);
	return NULL;
}

/**
 * \brief deflate uncompressed data in RzBbuffer to zlib or gzipped, use MAX_WBITS as the window size logarithm.
 * \see rz_deflatew_buf()
 */
RZ_API bool rz_deflate_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed) {
	rz_return_val_if_fail(src && dst, false);
	rz_return_val_if_fail(block_size > 0, false);
	return rz_deflatew_buf(src, dst, block_size, src_consumed, MAX_WBITS + 16);
}

/**
 * \brief deflate data contained in a RzBuffer using zlib
 * \param src source buffer
 * \param dst destination buffer
 * \param block_size block sizes to use while deflating data
 * \param src_consumed consumed source buffer length
 * \param wbits the size of the history buffer (or “window size”), and what header and trailer format is expected.
 * \return true if successful; false otherwise
 */
RZ_API bool rz_deflatew_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed, int wbits) {
	rz_return_val_if_fail(src && dst, false);
	rz_return_val_if_fail(block_size > 0, false);

	int err = 0, flush = Z_NO_FLUSH;
	bool ret = true;
	ut64 dst_cursor = 0, src_cursor = 0;
	ut64 src_readlen = 0;
	z_stream stream;

	memset(&stream, 0, sizeof(z_stream));

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		return false;
	}

	ut8 *src_tmpbuf = malloc(block_size), *dst_tmpbuf = malloc(block_size);

	while ((src_readlen = rz_buf_read_at(src, src_cursor, src_tmpbuf, block_size)) > 0) {
		src_cursor += src_readlen;
		stream.avail_in = src_readlen;
		stream.next_in = (Bytef *)src_tmpbuf;
		stream.next_out = dst_tmpbuf;
		stream.avail_out = block_size;
		stream.total_out = 0;

		if (src_readlen < block_size) {
			flush = Z_FINISH;
		}
		err = deflate(&stream, flush);
		if (err < 0) {
			RZ_LOG_ERROR("deflate error: %d %s\n", err, gzerr(-err));
			ret = false;
			goto return_goto;
		}

		dst_cursor += rz_buf_write_at(dst, dst_cursor, dst_tmpbuf, stream.total_out);
	}

	if (src_consumed) {
		*src_consumed = src_cursor;
	}
	ret = rz_buf_resize(dst, dst_cursor);

return_goto:
	deflateEnd(&stream);
	free(src_tmpbuf);
	free(dst_tmpbuf);

	return ret;
}

/**
 * \brief inflate compressed data in RzBbuffer, use MAX_WBITS as the window size logarithm.
 * \see rz_inflatew_buf()
 */
RZ_API bool rz_inflate_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed) {
	rz_return_val_if_fail(src && dst, false);
	rz_return_val_if_fail(block_size > 0, false);
	return rz_inflatew_buf(src, dst, block_size, src_consumed, MAX_WBITS + 32);
}

/**
 * \brief inflate data contained in a RzBuffer using zlib
 * \param src source buffer
 * \param dst destination buffer
 * \param block_size block sizes to use while inflating data
 * \param src_consumed consumed source buffer length
 * \param wbits the size of the history buffer (or “window size”), and what header and trailer format is expected.
 * \return true if successful; false otherwise
 */
RZ_API bool rz_inflatew_buf(RZ_NONNULL RzBuffer *src, RZ_NONNULL RzBuffer *dst, ut64 block_size, ut8 *src_consumed, int wbits) {
	rz_return_val_if_fail(src && dst, false);
	rz_return_val_if_fail(block_size > 0, false);

	int err = 0, flush = Z_NO_FLUSH;
	bool ret = true;
	ut64 dst_cursor = 0, src_cursor = 0;
	ut64 src_readlen = 0;
	z_stream stream;

	memset(&stream, 0, sizeof(z_stream));

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	if (inflateInit2(&stream, wbits) != Z_OK) {
		return false;
	}

	int comp_factor = 1032; // maximum compression ratio
	ut8 *src_tmpbuf = malloc(block_size), *dst_tmpbuf = malloc(comp_factor * block_size);

	while ((src_readlen = rz_buf_read_at(src, src_cursor, src_tmpbuf, block_size)) > 0) {
		src_cursor += src_readlen;
		stream.avail_in = src_readlen;
		stream.next_in = (Bytef *)src_tmpbuf;
		stream.next_out = dst_tmpbuf;
		stream.avail_out = comp_factor * block_size;
		stream.total_out = 0;

		if (src_readlen < block_size) {
			flush = Z_FINISH;
		}
		err = inflate(&stream, flush);
		if (err < 0) {
			RZ_LOG_ERROR("inflate error: %d %s\n", err, gzerr(-err));
			ret = false;
			goto return_goto;
		}

		dst_cursor += rz_buf_write_at(dst, dst_cursor, dst_tmpbuf, stream.total_out);
	}

	if (src_consumed) {
		*src_consumed = src_cursor;
	}

return_goto:
	inflateEnd(&stream);
	free(src_tmpbuf);
	free(dst_tmpbuf);

	return ret;
}
