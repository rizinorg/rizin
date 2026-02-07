// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_GLIBC_PARSER_H
#define RZ_GLIBC_PARSER_H

#include <rz_io.h>
#include <rz_util/rz_buf.h>
#include "glibc_types.h"

static inline bool rz_glibc_buf_read_offset(RzBuffer *b, ut64 *offset, ut64 *out, ut8 ptr_size) {
	if (ptr_size == 8) {
		return rz_buf_read_le64_offset(b, offset, out);
	} else {
		ut32 val;
		if (!rz_buf_read_le32_offset(b, offset, &val)) {
			return false;
		}
		*out = val;
		return true;
	}
}

static inline bool rz_glibc_read_chunk(RzIO *io, ut64 addr, RzHeapChunk *out,
	const RzHeapConfig *config) {
	bool ret = false;
	ut8 *buf = NULL;
	RzBuffer *b = NULL;
	ut32 size = config->chunk.struct_size;
	buf = RZ_NEWS0(ut8, size);
	if (!buf) {
		free(buf);
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		free(buf);
		return false;
	}

	b = rz_buf_new_with_pointers(buf, size, true);
	if (!b) {
		free(buf);
		return false;
	}

	ut64 offset = 0;
	ret = rz_glibc_buf_read_offset(b, &offset, &out->prev_size, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->size, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->fd, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->bk, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->fd_nextsize, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->bk_nextsize, config->ptr_size);

	rz_buf_free(b);
	return ret;
}

static inline bool rz_glibc_read_chunk_header(RzIO *io, ut64 addr,
	ut64 *prev_size, ut64 *size, const RzHeapConfig *config) {
	ut32 hdr_size = config->chunk_hdr_size;
	ut8 buf[16];

	if (!rz_io_read_at_mapped(io, addr, buf, hdr_size)) {
		return false;
	}

	if (config->ptr_size == 8) {
		*prev_size = rz_read_le64(buf);
		*size = rz_read_le64(buf + 8);
	} else {
		*prev_size = rz_read_le32(buf);
		*size = rz_read_le32(buf + 4);
	}
	return true;
}

static inline bool rz_glibc_read_malloc_state(RzIO *io, ut64 addr,
	MallocState *out, const RzHeapConfig *config) {
	const MallocStateLayout *layout = &config->malloc_state;
	ut32 size = layout->struct_size;
	ut8 *buf = RZ_NEWS0(ut8, size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		free(buf);
		return false;
	}

	RzBuffer *b = rz_buf_new_with_pointers(buf, size, true);
	if (!b) {
		free(buf);
		return false;
	}

	bool ret = false;
	ut64 offset;

	offset = layout->mutex;
	if (!rz_buf_read_le32_offset(b, &offset, &out->mutex) ||
		!rz_buf_read_le32_offset(b, &offset, &out->flags)) {
		goto cleanup;
	}

	if (layout->has_have_fast_chunks) {
		offset = layout->have_fast_chunks;
		if (!rz_buf_read_le32_offset(b, &offset, &out->have_fast_chunks)) {
			goto cleanup;
		}
	} else {
		out->have_fast_chunks = 0;
	}

	offset = layout->fastbinsY;
	for (int i = 0; i < RZ_GLIBC_NFASTBINS; i++) {
		if (!rz_glibc_buf_read_offset(b, &offset, &out->fastbinsY[i], config->ptr_size)) {
			goto cleanup;
		}
	}

	offset = layout->top;
	if (!rz_glibc_buf_read_offset(b, &offset, &out->top, config->ptr_size) ||
		!rz_glibc_buf_read_offset(b, &offset, &out->last_remainder, config->ptr_size)) {
		goto cleanup;
	}

	offset = layout->bins;
	for (int i = 0; i < RZ_GLIBC_NBINS * 2 - 2; i++) {
		if (!rz_glibc_buf_read_offset(b, &offset, &out->bins[i], config->ptr_size)) {
			goto cleanup;
		}
	}

	offset = layout->binmap;
	for (int i = 0; i < RZ_GLIBC_BINMAPSIZE; i++) {
		if (!rz_buf_read_le32_offset(b, &offset, &out->binmap[i])) {
			goto cleanup;
		}
	}

	offset = layout->next;
	if (!rz_glibc_buf_read_offset(b, &offset, &out->next, config->ptr_size) ||
		!rz_glibc_buf_read_offset(b, &offset, &out->next_free, config->ptr_size)) {
		goto cleanup;
	}

	if (layout->has_attached_threads) {
		offset = layout->attached_threads;
		if (!rz_glibc_buf_read_offset(b, &offset, &out->attached_threads, config->ptr_size)) {
			goto cleanup;
		}
	} else {
		out->attached_threads = 0;
	}

	offset = layout->system_mem;
	if (!rz_glibc_buf_read_offset(b, &offset, &out->system_mem, config->ptr_size) ||
		!rz_glibc_buf_read_offset(b, &offset, &out->max_system_mem, config->ptr_size)) {
		goto cleanup;
	}

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool rz_glibc_read_heap_info(RzIO *io, ut64 addr,
	RzHeapHeapInfo *out, const RzHeapConfig *config) {
	bool ret = false;
	ut8 *buf = NULL;
	RzBuffer *b = NULL;
	const RzHeapHeapInfoLayout *layout = &config->heap_info;
	ut32 size = layout->struct_size;
	buf = RZ_NEWS0(ut8, size);
	if (!buf) {
		goto cleanup;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		goto cleanup;
	}

	b = rz_buf_new_with_pointers(buf, size, true);
	if (!b) {
		goto cleanup;
	}

	ut64 offset = 0;
	ret = rz_glibc_buf_read_offset(b, &offset, &out->ar_ptr, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->prev, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->size, config->ptr_size) &&
		rz_glibc_buf_read_offset(b, &offset, &out->mprotect_size, config->ptr_size);

cleanup:
	rz_buf_free(b);
	if (!b) {
		free(buf);
	}
	return ret;
}

static inline bool rz_glibc_read_tcache(RzIO *io, ut64 addr,
	RzHeapTcache *out, const RzHeapConfig *config) {
	if (!rz_glibc_has_tcache(config->glibc_version)) {
		return false; // tcache not available
	}

	const RzHeapTcacheLayout *layout = &config->tcache;
	ut32 size = layout->struct_size;
	ut8 *buf = RZ_NEWS0(ut8, size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		free(buf);
		return false;
	}

	RzBuffer *b = rz_buf_new_with_pointers(buf, size, true);
	if (!b) {
		free(buf);
		return false;
	}

	bool ret = false;
	ut64 offset;

	memset(out->counts, 0, sizeof(out->counts));
	memset(out->entries, 0, sizeof(out->entries));

	offset = layout->counts;
	for (ut32 i = 0; i < layout->num_bins; i++) {
		if (layout->count_type_size == 1) {
			ut8 count;
			if (!rz_buf_read8_offset(b, &offset, &count)) {
				goto cleanup;
			}
			out->counts[i] = count;
		} else {
			ut16 count;
			if (!rz_buf_read_le16_offset(b, &offset, &count)) {
				goto cleanup;
			}
			out->counts[i] = count;
		}
	}

	offset = layout->entries;
	for (ut32 i = 0; i < layout->num_bins; i++) {
		if (!rz_glibc_buf_read_offset(b, &offset, &out->entries[i], config->ptr_size)) {
			goto cleanup;
		}
	}

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool rz_glibc_read_tcache_entry(RzIO *io, ut64 addr,
	RzHeapTcacheEntry *out, const RzHeapConfig *config) {
	const RzHeapTcacheEntryLayout *layout = &config->tcache_entry;
	ut32 size = layout->struct_size;
	ut8 buf[16];

	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		return false;
	}

	if (config->ptr_size == 8) {
		out->next = rz_read_le64(buf);
		out->key = layout->has_key ? rz_read_le64(buf + 8) : 0;
	} else {
		out->next = rz_read_le32(buf);
		out->key = layout->has_key ? rz_read_le32(buf + 4) : 0;
	}
	return true;
}

static inline ut64 rz_glibc_tcache_next(const RzHeapTcacheEntry *entry,
	ut64 entry_addr, const RzHeapConfig *config) {
	if (rz_glibc_has_safe_linking(config->glibc_version)) {
		return rz_glibc_safe_link_decode(entry->next, entry_addr);
	}
	return entry->next;
}

static inline bool rz_glibc_read_ptr_at(RzIO *io, ut64 addr, ut64 *out,
	const RzHeapConfig *config) {
	ut8 buf[8];
	if (!rz_io_read_at_mapped(io, addr, buf, config->ptr_size)) {
		return false;
	}
	if (config->ptr_size == 8) {
		*out = rz_read_le64(buf);
	} else {
		*out = rz_read_le32(buf);
	}
	return true;
}

static inline bool rz_glibc_read_fastbin_ptr(RzIO *io, ut64 addr, ut64 *out,
	const RzHeapConfig *config) {
	if (!rz_glibc_read_ptr_at(io, addr, out, config)) {
		return false;
	}
	if (rz_glibc_has_safe_linking(config->glibc_version) && *out != 0) {
		*out = rz_glibc_safe_link_decode(*out, addr);
	}
	return true;
}

#endif // RZ_GLIBC_PARSER_H
