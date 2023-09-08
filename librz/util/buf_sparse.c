// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

typedef struct sparse_init_config_t {
	RzBuffer *base;
	RzBufferSparseWriteMode write_mode;
} SparseInitConfig;

typedef struct buf_sparse_priv {
	RzBuffer *base; ///< If not NULL, unpopulated bytes are taken from this, else Oxff
	RzVector /*<RzBufferSparseChunk>*/ chunks; ///< of RzBufferSparseChunk, non-overlapping, ordered by from addr
	ut64 offset;
	RzBufferSparseWriteMode write_mode;
} SparsePriv;

static void chunk_fini(void *a, void *user) {
	RzBufferSparseChunk *s = (RzBufferSparseChunk *)a;
	free(s->data);
}

static bool sparse_limits(SparsePriv *priv, ut64 *max) {
	if (rz_vector_empty(&priv->chunks)) {
		return false;
	}
	RzBufferSparseChunk *c = rz_vector_index_ptr(&priv->chunks, rz_vector_len(&priv->chunks) - 1);
	*max = c->to + 1;
	return true;
}

static int chunk_cmp(ut64 addr, void *a) {
	RzBufferSparseChunk *c = a;
	return RZ_NUM_CMP(addr, c->from);
}

/**
 * \return index of the chunk AFTER the one that might contain the addr (so 0 means there is none)
 */
static size_t chunk_index_in(SparsePriv *priv, ut64 addr) {
	size_t i;
	rz_vector_upper_bound(&priv->chunks, addr, i, chunk_cmp);
	return i;
}

/**
 * \return -1 if failed; # of bytes copied if success
 */
static st64 sparse_write(SparsePriv *priv, ut64 addr, const ut8 *data, ut64 len) {
	if (!len) {
		return -1;
	}
	if (addr + len < addr) {
		// clamp to UT64_MAX (inclusive)
		len = 0 - addr;
	}
	size_t in_start_index = chunk_index_in(priv, addr);
	size_t in_end_index = chunk_index_in(priv, addr + len < addr ? UT64_MAX : addr + len);
	RzBufferSparseChunk *c = NULL; // the chunk where we will write into
	if (in_start_index) {
		// if we start writing inside an existing chunk, use it.
		c = rz_vector_index_ptr(&priv->chunks, in_start_index - 1);
		if (addr > c->to) {
			// already after it
			c = NULL;
		} else {
			// inside of it, our start index is the index of this chunk
			in_start_index--;
		}
	}
	if (!c) {
		c = rz_vector_insert(&priv->chunks, in_start_index, NULL);
		if (in_end_index) {
			// adjust after insertion
			in_end_index++;
		}
		c->from = addr;
		c->to = c->from;
		c->data = NULL;
	}
	// (re)alloc buffer and fill with appropriate data
	ut64 newto = addr + len - 1;
	RzBufferSparseChunk *in_end_chunk = NULL;
	if (in_end_index) {
		in_end_chunk = rz_vector_index_ptr(&priv->chunks, in_end_index - 1);
		if (in_end_chunk->to > newto) {
			newto = in_end_chunk->to;
		} else {
			// completely swallowed this chunk, nothing to copy
			in_end_chunk = NULL;
		}
	}
	ut8 *newbuf = realloc(c->data, newto - c->from + 1);
	if (!newbuf) {
		return -1;
	}
	c->data = newbuf;
	c->to = newto;
	memcpy(c->data + (addr - c->from), data, len);
	if (in_end_chunk && in_end_chunk != c) {
		memcpy(c->data + (addr - c->from) + len,
			in_end_chunk->data + (addr + len - in_end_chunk->from),
			in_end_chunk->to - (addr + len) + 1);
	}
	// remove all chunks that are now overlapped and overwritten
	if (in_end_index && in_start_index < in_end_index - 1) {
		// remove_range does not free by design
		for (size_t i = in_start_index + 1; i <= in_end_index - 1; i++) {
			chunk_fini(rz_vector_index_ptr(&priv->chunks, i), NULL);
		}
		rz_vector_remove_range(&priv->chunks, in_start_index + 1, in_end_index - (in_start_index + 1), NULL);
	}
	return len;
}

static inline struct buf_sparse_priv *get_priv_sparse(RzBuffer *b) {
	struct buf_sparse_priv *priv = (struct buf_sparse_priv *)b->priv;
	rz_warn_if_fail(priv);
	return priv;
}

static bool buf_sparse_init(RzBuffer *b, const void *user) {
	SparsePriv *priv = RZ_NEW0(struct buf_sparse_priv);
	if (!priv) {
		return false;
	}
	if (user) {
		SparseInitConfig *cfg = (void *)user;
		priv->base = cfg->base;
		if (priv->base) {
			rz_buf_ref(priv->base);
		}
		priv->write_mode = cfg->write_mode;
	} else {
		priv->write_mode = RZ_BUF_SPARSE_WRITE_MODE_SPARSE;
	}
	rz_vector_init(&priv->chunks, sizeof(RzBufferSparseChunk), chunk_fini, NULL);
	priv->offset = 0;
	b->priv = priv;
	return true;
}

static bool buf_sparse_fini(RzBuffer *b) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	rz_vector_fini(&priv->chunks);
	rz_buf_free(priv->base);
	RZ_FREE(b->priv);
	return true;
}

static bool buf_sparse_resize(RzBuffer *b, ut64 newsize) {
	SparsePriv *priv = get_priv_sparse(b);
	size_t n;
	rz_vector_lower_bound(&priv->chunks, newsize, n, chunk_cmp);
	// now n == index of the first chunk to be thrown away entirely
	if (n < rz_vector_len(&priv->chunks)) {
		// remove all excessive chunks if shrinking
		for (size_t i = n; i < rz_vector_len(&priv->chunks); i++) {
			chunk_fini(rz_vector_index_ptr(&priv->chunks, i), NULL);
		}
		rz_vector_remove_range(&priv->chunks, n, rz_vector_len(&priv->chunks) - n, NULL);
	}
	// now n == rz_vector_len(&priv->chunks)
	bool must_extend = false; // whether we must add another artificial chunk to reach exactly the size
	if (n) {
		RzBufferSparseChunk *c = rz_vector_index_ptr(&priv->chunks, n - 1);
		if (newsize <= c->to) {
			// must chop the now-last block
			rz_return_val_if_fail(newsize, false); // newsize > 0 is guaranteed when n > 0, otherwise the lower bound above would have returned 0.
			c->to = newsize - 1;
			ut8 *tmp = realloc(c->data, c->to - c->from + 1);
			if (tmp) {
				c->data = tmp;
			}
		} else {
			must_extend = newsize && c->to < newsize - 1;
		}
	} else {
		must_extend = !!newsize;
	}
	if (must_extend) {
		// if necessary, add a byte to reach exactly the desired size
		return !!sparse_write(priv, newsize - 1, &b->Oxff_priv, 1);
	}
	return true;
}

static ut64 buf_sparse_size(RzBuffer *b) {
	SparsePriv *priv = get_priv_sparse(b);
	ut64 max;
	ut64 r = sparse_limits(priv, &max) ? max : 0;
	if (priv->base) {
		ut64 base_sz = rz_buf_size(priv->base);
		if (base_sz > r) {
			r = base_sz;
		}
	}
	return r;
}

static st64 buf_sparse_read(RzBuffer *b, ut8 *buf, ut64 len) {
	if (!len) {
		return 0;
	}
	SparsePriv *priv = get_priv_sparse(b);
	ut64 max = priv->offset + len - 1;
	if (max < priv->offset) {
		max = UT64_MAX;
		len = max - priv->offset + 1;
	}
	// first inside-chunk is special because we might start inside of it
	size_t r = 0;
	size_t i = chunk_index_in(priv, priv->offset);
	if (i) {
		RzBufferSparseChunk *c = rz_vector_index_ptr(&priv->chunks, i - 1);
		if (priv->offset <= c->to) {
			ut64 to = RZ_MIN(c->to, max);
			ut64 rsz = to - priv->offset + 1;
			memcpy(buf, c->data + (priv->offset - c->from), rsz);
			priv->offset += rsz;
			buf += rsz;
			r += rsz;
		}
	}
	// non-chunk/chunk alternating
	while (priv->offset <= max) {
		// in each iteration, write one part like [0xff, 0xff, 0xff][some chunk]
		ut64 empty_to = max; // inclusive offset to which to fill with 0xff
		ut64 next_off = empty_to + 1; // offset to start at in the next iteration
		if (i < rz_vector_len(&priv->chunks)) {
			RzBufferSparseChunk *c = rz_vector_index_ptr(&priv->chunks, i);
			if (c->from <= empty_to) {
				next_off = RZ_MIN(c->to + 1, next_off);
				empty_to = c->from - 1;
				memcpy(buf + empty_to - priv->offset + 1, c->data, next_off - empty_to - 1);
				r += next_off - priv->offset;
			}
			i++;
		}
		if (empty_to >= priv->offset) {
			// fill non-chunk part with 0xff or base file
			if (priv->base) {
				rz_buf_read_at(priv->base, priv->offset, buf, empty_to - priv->offset + 1);
			} else {
				memset(buf, b->Oxff_priv, empty_to - priv->offset + 1);
			}
		}
		buf += next_off - priv->offset;
		priv->offset = next_off;
	}
	return priv->base ? len : r; // if there is a base file, read always fills the entire buffer (to keep the 0xff of the base)
}

static st64 buf_sparse_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	SparsePriv *priv = get_priv_sparse(b);
	st64 r = -1;
	switch (priv->write_mode) {
	case RZ_BUF_SPARSE_WRITE_MODE_SPARSE:
		r = sparse_write(priv, priv->offset, buf, len);
		break;
	case RZ_BUF_SPARSE_WRITE_MODE_THROUGH:
		if (!priv->base) {
			break;
		}
		r = rz_buf_write_at(priv->base, priv->offset, buf, len);
		break;
	}
	if (r >= 0) {
		priv->offset += r;
	}
	return r;
}

static st64 buf_sparse_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	ut64 max;
	if (addr < 0 && (-addr) > (st64)priv->offset) {
		return -1;
	}

	switch (whence) {
	case RZ_BUF_CUR:
		priv->offset += addr;
		break;
	case RZ_BUF_SET:
		priv->offset = addr;
		break;
	case RZ_BUF_END:
		if (!sparse_limits(priv, &max)) {
			max = 0;
		}
		priv->offset = max + addr;
		break;
	default:
		rz_warn_if_reached();
		return -1;
	}
	return priv->offset;
}

static const RzBufferMethods buffer_sparse_methods = {
	.init = buf_sparse_init,
	.fini = buf_sparse_fini,
	.read = buf_sparse_read,
	.write = buf_sparse_write,
	.get_size = buf_sparse_size,
	.resize = buf_sparse_resize,
	.seek = buf_sparse_seek
};

/// Only for sparse RzBuffers, get all sparse data chunks currently populated.
RZ_API const RzBufferSparseChunk *rz_buf_sparse_get_chunks(RzBuffer *b, RZ_NONNULL size_t *count) {
	rz_return_val_if_fail(b && count, NULL);
	if (b->methods != &buffer_sparse_methods) {
		*count = 0;
		return NULL;
	}
	SparsePriv *priv = get_priv_sparse(b);
	*count = rz_vector_len(&priv->chunks);
	return rz_vector_index_ptr(&priv->chunks, 0);
}

/// Only for sparse RzBuffers
RZ_API void rz_buf_sparse_set_write_mode(RzBuffer *b, RzBufferSparseWriteMode mode) {
	rz_return_if_fail(b);
	if (b->methods != &buffer_sparse_methods) {
		return;
	}
	SparsePriv *priv = get_priv_sparse(b);
	priv->write_mode = mode;
}

/**
 * \param from inclusive
 * \param to inclusive
 * \return whether the given interval contains chunks populated in the sparse buffer
 */
RZ_API bool rz_buf_sparse_populated_in(RzBuffer *b, ut64 from, ut64 to) {
	rz_return_val_if_fail(b, false);
	if (b->methods != &buffer_sparse_methods) {
		return false;
	}
	SparsePriv *priv = get_priv_sparse(b);
	size_t from_i = chunk_index_in(priv, from);
	if (from_i) {
		RzBufferSparseChunk *c = rz_vector_index_ptr(&priv->chunks, from_i - 1);
		if (from <= c->to) {
			return true;
		}
	}
	size_t to_i = chunk_index_in(priv, to);
	return to_i > from_i;
}
