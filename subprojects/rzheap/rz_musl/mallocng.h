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
	ut32 avail_mask, freed_mask;
	ut64 last_idx : 5;
	ut64 freeable : 1;
	ut64 sizeclass : 6;
	ut64 maplen : 8 * sizeof(ut64) - 12;
} mallocng_meta;

typedef struct meta_area {
	ut64 check;
	ut64 next;
	ut64 nslots;
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

static const uint16_t ng_size_classes[] = {
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	12,
	15,
	18,
	20,
	25,
	31,
	36,
	42,
	50,
	63,
	72,
	84,
	102,
	127,
	146,
	170,
	204,
	255,
	292,
	340,
	409,
	511,
	584,
	682,
	818,
	1023,
	1169,
	1364,
	1637,
	2047,
	2340,
	2730,
	3276,
	4095,
	4680,
	5460,
	6552,
	8191,
};

// TODO: Add 32 bit support to all of the functions below
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
		!rz_buf_read_le32_offset(b, &offset, &out->mmap_counter) ||
		!rz_buf_read_le64_offset(b, &offset, &out->free_meta_head) ||
		!rz_buf_read_le64_offset(b, &offset, &out->avail_meta) ||
		!rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->avail_meta_count) ||
		!rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->avail_meta_area_count) ||
		!rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->meta_alloc_shift) ||
		!rz_buf_read_le64_offset(b, &offset, &out->meta_area_head) ||
		!rz_buf_read_le64_offset(b, &offset, &out->meta_area_tail) ||
		!rz_buf_read_le64_offset(b, &offset, &out->avail_meta_areas)) {
		goto cleanup;
	}

	for (int i = 0; i < 48; i++) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->active[i])) {
			goto cleanup;
		}
	}
	for (int i = 0; i < 48; i++) {
		if (!rz_buf_read_le64_offset(b, &offset, (ut64 *)&out->usage_by_class[i])) {
			goto cleanup;
		}
	}
	for (int i = 0; i < 32; i++) {
		if (!rz_buf_read8_offset(b, &offset, &out->unmap_seq[i])) {
			goto cleanup;
		}
	}
	for (int i = 0; i < 32; i++) {
		if (!rz_buf_read8_offset(b, &offset, &out->bounces[i])) {
			goto cleanup;
		}
	}
	if (!rz_buf_read8_offset(b, &offset, &out->seq) ||
		!rz_buf_read_le64_offset(b, &offset, &out->brk)) {
		goto cleanup;
	}

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_meta_area(RzIO *io, ut64 addr, mallocng_meta_area *out) {
	ut8 *buf = RZ_NEWS0(ut8, sizeof(mallocng_meta_area));
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, sizeof(mallocng_meta_area))) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, sizeof(mallocng_meta_area), true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (!rz_buf_read_le64_offset(b, &offset, &out->check) ||
		!rz_buf_read_le64_offset(b, &offset, &out->next) ||
		!rz_buf_read_le64_offset(b, &offset, &out->nslots) ||
		!rz_buf_read_le64_offset(b, &offset, &out->slots)) {
		goto cleanup;
	}

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_meta(RzIO *io, ut64 addr, mallocng_meta *out) {
	ut8 *buf = RZ_NEWS0(ut8, sizeof(mallocng_meta));
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, sizeof(mallocng_meta))) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, sizeof(mallocng_meta), true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	ut64 packed = 0;
	if (!rz_buf_read_le64_offset(b, &offset, &out->prev) ||
		!rz_buf_read_le64_offset(b, &offset, &out->next) ||
		!rz_buf_read_le64_offset(b, &offset, &out->mem) ||
		!rz_buf_read_le32_offset(b, &offset, &out->avail_mask) ||
		!rz_buf_read_le32_offset(b, &offset, &out->freed_mask) ||
		!rz_buf_read_le64_offset(b, &offset, &packed)) {
		goto cleanup;
	}

	out->last_idx = packed & 0x1f;
	out->freeable = (packed >> 5) & 0x1;
	out->sizeclass = (packed >> 6) & 0x3f;
	out->maplen = packed >> 12;

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_group(RzIO *io, ut64 addr, mallocng_group *out) {
	ut8 *buf = RZ_NEWS0(ut8, sizeof(mallocng_group));
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, sizeof(mallocng_group))) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, sizeof(mallocng_group), true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	ut64 packed = 0;
	if (!rz_buf_read_le64_offset(b, &offset, &out->meta) ||
		!rz_buf_read_le64_offset(b, &offset, &packed) ||
		!rz_buf_read_le64_offset(b, &offset, &out->pad) ||
		!rz_buf_read_le64_offset(b, &offset, &out->storage)) {
		goto cleanup;
	}

	out->active_idx = packed & 0x1f;

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}
#endif // RZ_MALLOCNG_H
