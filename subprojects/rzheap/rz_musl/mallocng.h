// SPDX-FileCopyrightText: 2026 musl-libc <https://musl.libc.org/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-FileCopyrightText: 2026 suleif <suleif@proton.me>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef RZ_MUSL_MALLOCNG_H
#define RZ_MUSL_MALLOCNG_H

#include <rz_util.h>
#include <rz_io.h>
#define MMAP_THRESHOLD 131052

#define UNIT 16
#define IB   4

typedef struct group {
	ut64 meta;
	ut64 active_idx : 5;
	ut64 pad;
	ut64 storage;
} mallocng_group;

typedef struct meta {
	ut64 prev;
	ut64 next;
	ut64 mem;
	volatile ut32 avail_mask, freed_mask;
	ut64 last_idx : 5;
	ut64 freeable : 1;
	ut64 sizeclass : 6;
	ut64 maplen : 8 * sizeof(ut64) - 12;
} mallocng_meta;

typedef struct meta_area {
	ut64 check;
	ut64 next;
	ut32 nslots;
	ut64 slots;
} mallocng_meta_area;

typedef struct malloc_context {
	ut64 secret;
#ifndef PAGESIZE
	size_t pagesize;
#endif
	ut32 init_done;
	ut32 mmap_counter;
	ut64 free_meta_head;
	ut64 avail_meta;
	size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
	ut64 meta_area_head;
	ut64 meta_area_tail;
	ut64 avail_meta_areas;
	ut64 active[48];
	size_t usage_by_class[48];
	ut8 unmap_seq[32], bounces[32];
	ut8 seq;
	ut64 brk;
} mallocng_ctx;

static inline bool read_and_parse_ctx(RzIO *io, ut64 addr, mallocng_ctx *out) {
	ut8 *buf = RZ_NEWS0(ut8, sizeof(mallocng_ctx));
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, sizeof(mallocng_ctx))) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, sizeof(mallocng_ctx), true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;

	if (!rz_buf_read_le64_offset(b, &offset, &out->secret) ||
		!rz_buf_read_le32_offset(b, &offset, &out->init_done) ||
		!rz_buf_read_le32_offset(b, &offset, &out->mmap_counter)) {
		goto cleanup;
	}
	// TODO: Add 32 bit support, and error handling in case any of these reads
	//       fails
	rz_buf_read_le64_offset(b, &offset, &out->free_meta_head);
	rz_buf_read_le64_offset(b, &offset, &out->avail_meta);
	rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->avail_meta_count);
	rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->avail_meta_area_count);
	rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->meta_alloc_shift);
	rz_buf_read_le64_offset(b, &offset, &out->meta_area_head);
	rz_buf_read_le64_offset(b, &offset, &out->meta_area_tail);
	rz_buf_read_le64_offset(b, &offset, &out->avail_meta_areas);
	for (int i = 0; i < 48; i++) {
		rz_buf_read_le64_offset(b, &offset, &out->active[i]);
	}
	for (int i = 0; i < 48; i++) {
		rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->usage_by_class[i]);
	}
	for (int i = 0; i < 32; i++) {
		rz_buf_read8_offset(b, &offset, &out->unmap_seq[i]);
	}
	for (int i = 0; i < 32; i++) {
		rz_buf_read8_offset(b, &offset, &out->bounces[i]);
	}
	rz_buf_read8_offset(b, &offset, &out->seq);
	rz_buf_read_le64_offset(b, &offset, &out->brk);

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}
#endif // RZ_MALLOCNG_H
