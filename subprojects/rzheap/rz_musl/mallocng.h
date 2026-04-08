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

static const ut16 ng_size_classes[] = {
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

typedef struct group {
	ut64 meta;
	ut64 active_idx : 5;
	ut32 pad;
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
	ut32 init_done;
	ut32 mmap_counter;
	ut64 free_meta_head;
	ut64 avail_meta;
	ut64 avail_meta_count, avail_meta_area_count, meta_alloc_shift;
	ut64 meta_area_head;
	ut64 meta_area_tail;
	ut64 avail_meta_areas;
	ut64 active[48];
	ut64 usage_by_class[48];
	ut8 unmap_seq[32], bounces[32];
	ut8 seq;
	ut64 brk;
} mallocng_ctx;

typedef struct rz_mallocng_group_offsets_t {
	ut32 meta;
	ut32 active_idx;
	ut32 pad;
	ut32 storage;
} RzMallocngGroupOffsets;

typedef struct rz_mallocng_meta_offsets_t {
	ut32 prev;
	ut32 next;
	ut32 mem;
	ut32 avail_mask;
	ut32 freed_mask;
	ut32 bf;
} RzMallocngMetaOffsets;

typedef struct rz_mallocng_meta_area_offsets_t {
	ut32 check;
	ut32 next;
	ut32 nslots;
	ut32 slots;
} RzMallocngMetaAreaOffsets;

typedef struct rz_mallocng_ctx_offsets_t {
	ut32 secret;
	ut32 init_done;
	ut32 mmap_counter;
	ut32 free_meta_head;
	ut32 avail_meta;
	ut32 avail_meta_count;
	ut32 avail_meta_area_count;
	ut32 meta_alloc_shift;
	ut32 meta_area_head;
	ut32 meta_area_tail;
	ut32 avail_meta_areas;
	ut32 active;
	ut32 usage_by_class;
	ut32 unmap_seq;
	ut32 bounces;
	ut32 seq;
	ut32 brk;
} RzMallocngCtxOffsets;

typedef struct rz_mallocng_config_t {
	ut8 ptr_size;
	bool is_big_endian;

	ut32 group_size_min;
	ut32 meta_size;
	ut32 meta_area_size_min;
	ut32 ctx_size;

	RzMallocngGroupOffsets group_offsets;
	RzMallocngMetaOffsets meta_offsets;
	RzMallocngMetaAreaOffsets meta_area_offsets;
	RzMallocngCtxOffsets ctx_offsets;
} RzMallocngConfig;

static const RzMallocngConfig rz_mallocng_config_linux_64bits = {
	.ptr_size = 8,
	.is_big_endian = false,

	.group_size_min = 16,
	.meta_size = 40,
	.meta_area_size_min = 32,
	.ctx_size = 928,

	.group_offsets = {
		.meta = 0,
		.active_idx = 8,
		.pad = 9,
		.storage = UNIT,
	},
	.meta_offsets = {
		.prev = 0,
		.next = 8,
		.mem = 16,
		.avail_mask = 24,
		.freed_mask = 28,
		.bf = 32,
	},
	.meta_area_offsets = {
		.check = 0,
		.next = 8,
		.nslots = 16,
		.slots = 24,
	},
	.ctx_offsets = {
		.secret = 0,
		.init_done = 8,
		.mmap_counter = 12,
		.free_meta_head = 16,
		.avail_meta = 24,
		.avail_meta_count = 32,
		.avail_meta_area_count = 40,
		.meta_alloc_shift = 48,
		.meta_area_head = 56,
		.meta_area_tail = 64,
		.avail_meta_areas = 72,
		.active = 80,
		.usage_by_class = 464,
		.unmap_seq = 848,
		.bounces = 880,
		.seq = 912,
		.brk = 920,
	},
};

static const RzMallocngConfig rz_mallocng_config_linux_32bits = {
	.ptr_size = 4,
	.is_big_endian = false,

	.group_size_min = 16,
	.meta_size = 24,
	.meta_area_size_min = 20,
	.ctx_size = 504,

	.group_offsets = {
		.meta = 0,
		.active_idx = 4,
		.pad = 5,
		.storage = UNIT,
	},
	.meta_offsets = {
		.prev = 0,
		.next = 4,
		.mem = 8,
		.avail_mask = 12,
		.freed_mask = 16,
		.bf = 20,
	},
	.meta_area_offsets = {
		.check = 0,
		.next = 8,
		.nslots = 12,
		.slots = 16,
	},
	.ctx_offsets = {
		.secret = 0,
		.init_done = 8,
		.mmap_counter = 12,
		.free_meta_head = 16,
		.avail_meta = 20,
		.avail_meta_count = 24,
		.avail_meta_area_count = 28,
		.meta_alloc_shift = 32,
		.meta_area_head = 36,
		.meta_area_tail = 40,
		.avail_meta_areas = 44,
		.active = 48,
		.usage_by_class = 240,
		.unmap_seq = 432,
		.bounces = 464,
		.seq = 496,
		.brk = 500,
	},
};

static inline const RzMallocngConfig rz_musl_ng_get_config(int bits) {
	if (bits == 32) {
		return rz_mallocng_config_linux_32bits;
	} else {
		return rz_mallocng_config_linux_64bits;
	}
}

// TODO: Add 32 bit support to all of the functions below
static inline bool read_and_parse_ctx(RzIO *io, ut64 addr, mallocng_ctx *out, RzMallocngConfig config) {
	ut8 *buf = RZ_NEWS0(ut8, config.ctx_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config.ctx_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config.ctx_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (config.ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->secret) ||
			!rz_buf_read_le32_offset(b, &offset, &out->init_done) ||
			!rz_buf_read_le32_offset(b, &offset, &out->mmap_counter) ||
			!rz_buf_read_le64_offset(b, &offset, &out->free_meta_head) ||
			!rz_buf_read_le64_offset(b, &offset, &out->avail_meta) ||
			!rz_buf_read_le64_offset(b, &offset, &out->avail_meta_count) ||
			!rz_buf_read_le64_offset(b, &offset, &out->avail_meta_area_count) ||
			!rz_buf_read_le64_offset(b, &offset, &out->meta_alloc_shift) ||
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
	}

	else {
		ut32 free_meta_head, avail_meta, avail_meta_count, avail_meta_ac, brk,
			meta_alloc_shift, meta_area_head, meta_area_tail, avail_meta_areas;
		if (!rz_buf_read_le64_offset(b, &offset, &out->secret) ||
			!rz_buf_read_le32_offset(b, &offset, &out->init_done) ||
			!rz_buf_read_le32_offset(b, &offset, &out->mmap_counter) ||
			!rz_buf_read_le32_offset(b, &offset, &free_meta_head) ||
			!rz_buf_read_le32_offset(b, &offset, &avail_meta) ||
			!rz_buf_read_le32_offset(b, &offset, &avail_meta_count) ||
			!rz_buf_read_le32_offset(b, &offset, &avail_meta_ac) ||
			!rz_buf_read_le32_offset(b, &offset, &meta_alloc_shift) ||
			!rz_buf_read_le32_offset(b, &offset, &meta_area_head) ||
			!rz_buf_read_le32_offset(b, &offset, &meta_area_tail) ||
			!rz_buf_read_le32_offset(b, &offset, &avail_meta_areas)) {
			goto cleanup;
		}

		for (int i = 0; i < 48; i++) {
			ut32 active = 0;
			if (!rz_buf_read_le32_offset(b, &offset, &active)) {
				goto cleanup;
			}
			out->active[i] = active;
		}
		for (int i = 0; i < 48; i++) {
			ut32 usage_by_class = 0;
			if (!rz_buf_read_le32_offset(b, &offset, &usage_by_class)) {
				goto cleanup;
			}
			out->usage_by_class[i] = usage_by_class;
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
			!rz_buf_read_le32_offset(b, &offset, &brk)) {
			goto cleanup;
		}
		out->free_meta_head = free_meta_head;
		out->avail_meta = avail_meta;
		out->avail_meta_count = avail_meta_count;
		out->avail_meta_area_count = avail_meta_ac;
		out->meta_alloc_shift = meta_alloc_shift;
		out->meta_area_head = meta_area_head;
		out->meta_area_tail = meta_area_tail;
		out->avail_meta_areas = avail_meta_areas;
		out->brk = brk;
	}

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_meta_area(RzIO *io, ut64 addr, mallocng_meta_area *out, RzMallocngConfig config) {
	ut8 *buf = RZ_NEWS0(ut8, config.meta_area_size_min);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config.meta_area_size_min)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config.meta_area_size_min, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (config.ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->check) ||
			!rz_buf_read_le64_offset(b, &offset, &out->next) ||
			!rz_buf_read_le64_offset(b, &offset, &out->nslots) ||
			!rz_buf_read_le64_offset(b, &offset, &out->slots)) {
			goto cleanup;
		}

	} else {
		ut32 next, nslots, slots;
		if (!rz_buf_read_le64_offset(b, &offset, &out->check) ||
			!rz_buf_read_le32_offset(b, &offset, &next) ||
			!rz_buf_read_le32_offset(b, &offset, &nslots) ||
			!rz_buf_read_le32_offset(b, &offset, &slots)) {
			goto cleanup;
		}
		out->next = next;
		out->nslots = nslots;
		out->slots = slots;
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_meta(RzIO *io, ut64 addr, mallocng_meta *out, RzMallocngConfig config) {
	ut8 *buf = RZ_NEWS0(ut8, config.meta_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config.meta_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config.meta_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	ut64 packed = 0;

	if (config.ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->prev) ||
			!rz_buf_read_le64_offset(b, &offset, &out->next) ||
			!rz_buf_read_le64_offset(b, &offset, &out->mem) ||
			!rz_buf_read_le32_offset(b, &offset, &out->avail_mask) ||
			!rz_buf_read_le32_offset(b, &offset, &out->freed_mask) ||
			!rz_buf_read_le64_offset(b, &offset, &packed)) {
			goto cleanup;
		}
	} else {
		ut32 prev, next, mem;
		if (!rz_buf_read_le32_offset(b, &offset, &prev) ||
			!rz_buf_read_le32_offset(b, &offset, &next) ||
			!rz_buf_read_le32_offset(b, &offset, &mem) ||
			!rz_buf_read_le32_offset(b, &offset, &out->avail_mask) ||
			!rz_buf_read_le32_offset(b, &offset, &out->freed_mask) ||
			!rz_buf_read_le32_offset(b, &offset, (ut32 *)&packed)) {
			goto cleanup;
		}
		out->prev = prev;
		out->next = next;
		out->mem = mem;
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

static inline bool read_and_parse_group(RzIO *io, ut64 addr, mallocng_group *out, RzMallocngConfig config) {
	ut8 *buf = RZ_NEWS0(ut8, config.group_size_min);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config.group_size_min)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config.group_size_min, true);
	if (!b) {
		free(buf);
		return false;
	}
	bool ret = false;
	ut64 offset = 0;
	ut8 packed = 0;
	RzMallocngGroupOffsets off = config.group_offsets;
	if (config.ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->meta) ||
			!rz_buf_read8_offset(b, &offset, &packed) ||
			!rz_buf_read_le32_offset(b, &offset, &out->pad)) {
			goto cleanup;
		}
	} else {
		ut32 meta, pad;
		if (!rz_buf_read_le32_offset(b, &offset, &meta) ||
			!rz_buf_read8_offset(b, &offset, &packed) ||
			!rz_buf_read_le32_offset(b, &offset, &pad)) {
			goto cleanup;
		}
		out->meta = meta;
		out->pad = pad;
	}
	out->active_idx = packed & 0x1f;
	out->storage = addr + off.storage;

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}
#endif // RZ_MALLOCNG_H
