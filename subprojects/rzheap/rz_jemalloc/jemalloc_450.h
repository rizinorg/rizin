// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JEMALLOC_450_H
#define RZ_JEMALLOC_450_H

#include <rz_util.h>
#include <rz_io.h>

#define JM_NBINS_450          36
#define NPSIZES_64_450        199
#define NPSIZES_32_450        71
#define SMOOTHSTEP_NSTEPS_450 200
#define BITMAP_MAX_LEVELS_450 5
#define LG_PAGE_450           12

#define EXTENT_NODE_SIZE_64  112
#define EXTENT_NODE_SIZE_32  56
#define EXTENT_NODE_SIZE_MAX 112

#define ARENA_SIZE_64_450  10072
#define ARENA_SIZE_32_450  5748
#define ARENA_SIZE_MAX_450 10072

#define ARENA_BIN_INFO_SIZE_64  64
#define ARENA_BIN_INFO_SIZE_32  56
#define ARENA_BIN_INFO_SIZE_MAX 64

#define ARENA_BIN_SIZE_64  168
#define ARENA_BIN_SIZE_32  116
#define ARENA_BIN_SIZE_MAX 168

#define MALLOC_MUTEX_SIZE_64_450 80
#define MALLOC_MUTEX_SIZE_32_450 44

#define BITMAP_INFO_SIZE_64_450 16
#define BITMAP_INFO_SIZE_32_450 32

#define EXTENT_NODE_EN_ARENA_OFFSET_64     0
#define EXTENT_NODE_EN_ADDR_OFFSET_64      8
#define EXTENT_NODE_EN_SIZE_OFFSET_64      16
#define EXTENT_NODE_EN_SN_OFFSET_64        24
#define EXTENT_NODE_QL_LINK_NEXT_OFFSET_64 80
#define EXTENT_NODE_QL_LINK_PREV_OFFSET_64 88

#define EXTENT_NODE_EN_ARENA_OFFSET_32     0
#define EXTENT_NODE_EN_ADDR_OFFSET_32      4
#define EXTENT_NODE_EN_SIZE_OFFSET_32      8
#define EXTENT_NODE_EN_SN_OFFSET_32        12
#define EXTENT_NODE_QL_LINK_NEXT_OFFSET_32 40
#define EXTENT_NODE_QL_LINK_PREV_OFFSET_32 44

#define ARENA_IND_OFFSET_64_450                  0
#define ARENA_NTHREADS_OFFSET_64_450             4
#define ARENA_LOCK_OFFSET_64_450                 16
#define ARENA_STATS_OFFSET_64_450                96
#define ARENA_TCACHE_QL_OFFSET_64_450            224
#define ARENA_PROF_ACCUMBYTES_OFFSET_64_450      232
#define ARENA_OFFSET_STATE_OFFSET_64_450         240
#define ARENA_DSS_PREC_OFFSET_64_450             248
#define ARENA_ACHUNKS_OFFSET_64_450              256
#define ARENA_EXTENT_SN_NEXT_OFFSET_64_450       264
#define ARENA_SPARE_OFFSET_64_450                272
#define ARENA_LG_DIRTY_MULT_OFFSET_64_450        280
#define ARENA_PURGING_OFFSET_64_450              288
#define ARENA_NACTIVE_OFFSET_64_450              296
#define ARENA_NDIRTY_OFFSET_64_450               304
#define ARENA_RUNS_DIRTY_OFFSET_64_450           312
#define ARENA_CHUNKS_CACHE_OFFSET_64_450         328
#define ARENA_DECAY_OFFSET_64_450                440
#define ARENA_HUGE_OFFSET_64_450                 2088
#define ARENA_HUGE_MTX_OFFSET_64_450             2096
#define ARENA_CHUNKS_SZSNAD_CACHED_OFFSET_64_450 2176
#define ARENA_CHUNKS_AD_CACHED_OFFSET_64_450     2184
#define ARENA_CHUNKS_MTX_OFFSET_64_450           2208
#define ARENA_NODE_CACHE_OFFSET_64_450           2288
#define ARENA_NODE_CACHE_MTX_OFFSET_64_450       2296
#define ARENA_CHUNK_HOOKS_OFFSET_64_450          2376
#define ARENA_BINS_OFFSET_64_450                 2432
#define ARENA_RUNS_AVAIL_OFFSET_64_450           8480

#define ARENA_IND_OFFSET_32_450                  0
#define ARENA_NTHREADS_OFFSET_32_450             4
#define ARENA_LOCK_OFFSET_32_450                 12
#define ARENA_STATS_OFFSET_32_450                56
#define ARENA_TCACHE_QL_OFFSET_32_450            152
#define ARENA_PROF_ACCUMBYTES_OFFSET_32_450      156
#define ARENA_OFFSET_STATE_OFFSET_32_450         164
#define ARENA_DSS_PREC_OFFSET_32_450             168
#define ARENA_ACHUNKS_OFFSET_32_450              172
#define ARENA_EXTENT_SN_NEXT_OFFSET_32_450       176
#define ARENA_SPARE_OFFSET_32_450                180
#define ARENA_LG_DIRTY_MULT_OFFSET_32_450        184
#define ARENA_PURGING_OFFSET_32_450              188
#define ARENA_NACTIVE_OFFSET_32_450              192
#define ARENA_NDIRTY_OFFSET_32_450               196
#define ARENA_RUNS_DIRTY_OFFSET_32_450           200
#define ARENA_CHUNKS_CACHE_OFFSET_32_450         208
#define ARENA_DECAY_OFFSET_32_450                264
#define ARENA_HUGE_OFFSET_32_450                 1104
#define ARENA_HUGE_MTX_OFFSET_32_450             1108
#define ARENA_CHUNKS_SZSNAD_CACHED_OFFSET_32_450 1152
#define ARENA_CHUNKS_AD_CACHED_OFFSET_32_450     1156
#define ARENA_CHUNKS_MTX_OFFSET_32_450           1168
#define ARENA_NODE_CACHE_OFFSET_32_450           1212
#define ARENA_NODE_CACHE_MTX_OFFSET_32_450       1216
#define ARENA_CHUNK_HOOKS_OFFSET_32_450          1260
#define ARENA_BINS_OFFSET_32_450                 1288
#define ARENA_RUNS_AVAIL_OFFSET_32_450           5464

#define ARENA_BIN_INFO_REG_SIZE_OFFSET_64     0
#define ARENA_BIN_INFO_REDZONE_SIZE_OFFSET_64 8
#define ARENA_BIN_INFO_REG_INTERVAL_OFFSET_64 16
#define ARENA_BIN_INFO_RUN_SIZE_OFFSET_64     24
#define ARENA_BIN_INFO_NREGS_OFFSET_64        32
#define ARENA_BIN_INFO_BITMAP_INFO_OFFSET_64  40
#define ARENA_BIN_INFO_REG0_OFFSET_OFFSET_64  56

#define ARENA_BIN_INFO_REG_SIZE_OFFSET_32     0
#define ARENA_BIN_INFO_REDZONE_SIZE_OFFSET_32 4
#define ARENA_BIN_INFO_REG_INTERVAL_OFFSET_32 8
#define ARENA_BIN_INFO_RUN_SIZE_OFFSET_32     12
#define ARENA_BIN_INFO_NREGS_OFFSET_32        16
#define ARENA_BIN_INFO_BITMAP_INFO_OFFSET_32  20
#define ARENA_BIN_INFO_REG0_OFFSET_OFFSET_32  52

/*
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/extent.h
 */
typedef struct extent_node_t_450 {
	ut64 en_arena;
	ut64 en_addr;
	ut64 en_size;
	ut64 en_sn;
	ut64 ql_link_next;
	ut64 ql_link_prev;
} extent_node_t_450;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/bitmap.h
 */
typedef struct bitmap_info_t_450 {
	ut64 nbits;
	// 64 bit dont use tree
	ut64 ngroups;
	// 32 bit uses tree
	ut32 nlevels;
	ut64 levels[BITMAP_MAX_LEVELS_450 + 1];
} bitmap_info_t_450;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
typedef struct arena_bin_info_t_450 {
	ut64 reg_size;
	ut64 redzone_size;
	ut64 reg_interval;
	ut64 run_size;
	ut32 nregs;
	ut32 reg0_offset;
	bitmap_info_t_450 bitmap_info;
} arena_bin_info_t_450;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
typedef struct arena_t_450 {
	ut32 ind;
	ut32 nthreads[2];
	ut64 prof_accumbytes;
	ut64 offset_state;
	ut32 dss_prec;
	ut64 extent_sn_next;
	ut64 spare;
	st64 lg_dirty_mult;
	bool purging;
	ut64 nactive;
	ut64 ndirty;
	ut64 lock_addr;
	ut64 stats_addr;
	ut64 tcache_ql_addr;
	ut64 achunks_addr;
	ut64 runs_dirty_addr;
	ut64 chunks_cache_addr;
	ut64 decay_addr;
	ut64 huge_addr;
	ut64 huge_mtx_addr;
	ut64 chunks_szsnad_cached_addr;
	ut64 chunks_ad_cached_addr;
	ut64 chunks_mtx_addr;
	ut64 node_cache_addr;
	ut64 node_cache_mtx_addr;
	ut64 chunk_hooks_addr;
	ut64 bins_addr;
	ut64 runs_avail_addr;
} arena_t_450;

static inline size_t extent_node_size_450(bool is_64bit) {
	return is_64bit ? EXTENT_NODE_SIZE_64 : EXTENT_NODE_SIZE_32;
}

static inline size_t arena_size_450(bool is_64bit) {
	return is_64bit ? ARENA_SIZE_64_450 : ARENA_SIZE_32_450;
}

static inline size_t arena_bin_info_size_450(bool is_64bit) {
	return is_64bit ? ARENA_BIN_INFO_SIZE_64 : ARENA_BIN_INFO_SIZE_32;
}

static inline size_t arena_bin_size_450(bool is_64bit) {
	return is_64bit ? ARENA_BIN_SIZE_64 : ARENA_BIN_SIZE_32;
}

static inline size_t malloc_mutex_size_450(bool is_64bit) {
	return is_64bit ? MALLOC_MUTEX_SIZE_64_450 : MALLOC_MUTEX_SIZE_32_450;
}

static inline size_t bitmap_info_size_450(bool is_64bit) {
	return is_64bit ? BITMAP_INFO_SIZE_64_450 : BITMAP_INFO_SIZE_32_450;
}

static inline ut64 bins_offset_450(bool is_64bit) {
	return is_64bit ? ARENA_BINS_OFFSET_64_450 : ARENA_BINS_OFFSET_32_450;
}

static inline ut64 achunks_offset_450(bool is_64bit) {
	return is_64bit ? ARENA_ACHUNKS_OFFSET_64_450 : ARENA_ACHUNKS_OFFSET_32_450;
}

static inline ut32 npsizes_450(bool is_64bit) {
	return is_64bit ? NPSIZES_64_450 : NPSIZES_32_450;
}

static inline bool read_and_parse_extent_node_t_450_64(RzIO *io, ut64 addr, extent_node_t_450 *out) {
	bool ret = false;
	ut8 buf[EXTENT_NODE_SIZE_64];
	if (!rz_io_read_at_mapped(io, addr, buf, EXTENT_NODE_SIZE_64)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, EXTENT_NODE_SIZE_64);
	if (!b) {
		return false;
	}
	ut64 offset = 0;

	if (!rz_buf_read_le64_offset(b, &offset, &out->en_arena) ||
		!rz_buf_read_le64_offset(b, &offset, &out->en_addr) ||
		!rz_buf_read_le64_offset(b, &offset, &out->en_size) ||
		!rz_buf_read_le64_offset(b, &offset, &out->en_sn)) {
		goto cleanup;
	}
	offset = EXTENT_NODE_QL_LINK_NEXT_OFFSET_64;
	if (!rz_buf_read_le64_offset(b, &offset, &out->ql_link_next) ||
		!rz_buf_read_le64_offset(b, &offset, &out->ql_link_prev)) {
		goto cleanup;
	}
	ret = true;

cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_extent_node_t_450_32(RzIO *io, ut64 addr, extent_node_t_450 *out) {
	bool ret = false;
	ut8 buf[EXTENT_NODE_SIZE_32];
	if (!rz_io_read_at_mapped(io, addr, buf, EXTENT_NODE_SIZE_32)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, EXTENT_NODE_SIZE_32);
	if (!b) {
		return false;
	}
	ut64 offset = 0;

	ut32 en_arena, en_addr, en_size, en_sn;
	if (!rz_buf_read_le32_offset(b, &offset, &en_arena) ||
		!rz_buf_read_le32_offset(b, &offset, &en_addr) ||
		!rz_buf_read_le32_offset(b, &offset, &en_size) ||
		!rz_buf_read_le32_offset(b, &offset, &en_sn)) {
		goto cleanup;
	}
	out->en_arena = en_arena;
	out->en_addr = en_addr;
	out->en_size = en_size;
	out->en_sn = en_sn;

	offset = EXTENT_NODE_QL_LINK_NEXT_OFFSET_32;
	ut32 ql_next, ql_prev;
	if (!rz_buf_read_le32_offset(b, &offset, &ql_next) ||
		!rz_buf_read_le32_offset(b, &offset, &ql_prev)) {
		goto cleanup;
	}
	out->ql_link_next = ql_next;
	out->ql_link_prev = ql_prev;
	ret = true;

cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_extent_node_t_450(RzIO *io, ut64 addr, extent_node_t_450 *out, bool is_64bit) {
	return is_64bit
		? read_and_parse_extent_node_t_450_64(io, addr, out)
		: read_and_parse_extent_node_t_450_32(io, addr, out);
}

static inline bool read_and_parse_arena_bin_info_t_450_64(RzIO *io, ut64 addr, arena_bin_info_t_450 *out) {
	bool ret = false;
	ut8 buf[ARENA_BIN_INFO_SIZE_64];
	if (!rz_io_read_at_mapped(io, addr, buf, ARENA_BIN_INFO_SIZE_64)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, ARENA_BIN_INFO_SIZE_64);
	if (!b) {
		return false;
	}
	ut64 offset = 0;

	if (!rz_buf_read_le64_offset(b, &offset, &out->reg_size) ||
		!rz_buf_read_le64_offset(b, &offset, &out->redzone_size) ||
		!rz_buf_read_le64_offset(b, &offset, &out->reg_interval) ||
		!rz_buf_read_le64_offset(b, &offset, &out->run_size) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nregs)) {
		goto cleanup;
	}
	offset = ARENA_BIN_INFO_BITMAP_INFO_OFFSET_64;
	if (!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.nbits) ||
		!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.ngroups)) {
		goto cleanup;
	}
	out->bitmap_info.nlevels = 0;
	for (int i = 0; i < BITMAP_MAX_LEVELS_450 + 1; i++) {
		out->bitmap_info.levels[i] = 0;
	}
	offset = ARENA_BIN_INFO_REG0_OFFSET_OFFSET_64;
	if (!rz_buf_read_le32_offset(b, &offset, &out->reg0_offset)) {
		goto cleanup;
	}
	ret = true;

cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_bin_info_t_450_32(RzIO *io, ut64 addr, arena_bin_info_t_450 *out) {
	bool ret = false;
	ut8 buf[ARENA_BIN_INFO_SIZE_32];
	if (!rz_io_read_at_mapped(io, addr, buf, ARENA_BIN_INFO_SIZE_32)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, ARENA_BIN_INFO_SIZE_32);
	if (!b) {
		return false;
	}
	ut64 offset = 0;

	ut32 reg_size, redzone_size, reg_interval, run_size;
	if (!rz_buf_read_le32_offset(b, &offset, &reg_size) ||
		!rz_buf_read_le32_offset(b, &offset, &redzone_size) ||
		!rz_buf_read_le32_offset(b, &offset, &reg_interval) ||
		!rz_buf_read_le32_offset(b, &offset, &run_size) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nregs)) {
		goto cleanup;
	}
	out->reg_size = reg_size;
	out->redzone_size = redzone_size;
	out->reg_interval = reg_interval;
	out->run_size = run_size;

	offset = ARENA_BIN_INFO_BITMAP_INFO_OFFSET_32;
	ut32 nbits;
	if (!rz_buf_read_le32_offset(b, &offset, &nbits) ||
		!rz_buf_read_le32_offset(b, &offset, &out->bitmap_info.nlevels)) {
		goto cleanup;
	}
	out->bitmap_info.nbits = nbits;
	out->bitmap_info.ngroups = 0;
	for (int i = 0; i < BITMAP_MAX_LEVELS_450 + 1; i++) {
		ut32 level;
		if (!rz_buf_read_le32_offset(b, &offset, &level)) {
			goto cleanup;
		}
		out->bitmap_info.levels[i] = level;
	}
	offset = ARENA_BIN_INFO_REG0_OFFSET_OFFSET_32;
	if (!rz_buf_read_le32_offset(b, &offset, &out->reg0_offset)) {
		goto cleanup;
	}
	ret = true;

cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_bin_info_t_450(RzIO *io, ut64 addr, arena_bin_info_t_450 *out, bool is_64bit) {
	return is_64bit
		? read_and_parse_arena_bin_info_t_450_64(io, addr, out)
		: read_and_parse_arena_bin_info_t_450_32(io, addr, out);
}

static inline bool read_and_parse_arena_t_450_64(RzIO *io, ut64 addr, arena_t_450 *out) {
	bool ret = false;
	ut8 *buf = malloc(ARENA_SIZE_64_450);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, ARENA_SIZE_64_450)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, ARENA_SIZE_64_450);
	free(buf);
	if (!b) {
		return false;
	}
	ut64 offset = 0;

	if (!rz_buf_read_le32_offset(b, &offset, &out->ind) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[0]) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[1])) {
		goto cleanup;
	}

	ut64 lg_dirty_mult_raw;
	ut8 purging_byte;

	offset = ARENA_PROF_ACCUMBYTES_OFFSET_64_450;
	if (!rz_buf_read_le64_offset(b, &offset, &out->prof_accumbytes) ||
		!rz_buf_read_le64_offset(b, &offset, &out->offset_state) ||
		!rz_buf_read_le32_offset(b, &offset, &out->dss_prec)) {
		goto cleanup;
	}

	offset = ARENA_EXTENT_SN_NEXT_OFFSET_64_450;
	if (!rz_buf_read_le64_offset(b, &offset, &out->extent_sn_next) ||
		!rz_buf_read_le64_offset(b, &offset, &out->spare)) {
		goto cleanup;
	}

	offset = ARENA_LG_DIRTY_MULT_OFFSET_64_450;
	if (!rz_buf_read_le64_offset(b, &offset, &lg_dirty_mult_raw)) {
		goto cleanup;
	}
	out->lg_dirty_mult = (st64)lg_dirty_mult_raw;

	offset = ARENA_PURGING_OFFSET_64_450;
	if (rz_buf_read_at(b, offset, &purging_byte, 1) != 1) {
		goto cleanup;
	}
	out->purging = purging_byte != 0;

	offset = ARENA_NACTIVE_OFFSET_64_450;
	if (!rz_buf_read_le64_offset(b, &offset, &out->nactive) ||
		!rz_buf_read_le64_offset(b, &offset, &out->ndirty)) {
		goto cleanup;
	}

	out->lock_addr = addr + ARENA_LOCK_OFFSET_64_450;
	out->stats_addr = addr + ARENA_STATS_OFFSET_64_450;
	out->tcache_ql_addr = addr + ARENA_TCACHE_QL_OFFSET_64_450;
	out->achunks_addr = addr + ARENA_ACHUNKS_OFFSET_64_450;
	out->runs_dirty_addr = addr + ARENA_RUNS_DIRTY_OFFSET_64_450;
	out->chunks_cache_addr = addr + ARENA_CHUNKS_CACHE_OFFSET_64_450;
	out->decay_addr = addr + ARENA_DECAY_OFFSET_64_450;
	out->huge_addr = addr + ARENA_HUGE_OFFSET_64_450;
	out->huge_mtx_addr = addr + ARENA_HUGE_MTX_OFFSET_64_450;
	out->chunks_szsnad_cached_addr = addr + ARENA_CHUNKS_SZSNAD_CACHED_OFFSET_64_450;
	out->chunks_ad_cached_addr = addr + ARENA_CHUNKS_AD_CACHED_OFFSET_64_450;
	out->chunks_mtx_addr = addr + ARENA_CHUNKS_MTX_OFFSET_64_450;
	out->node_cache_addr = addr + ARENA_NODE_CACHE_OFFSET_64_450;
	out->node_cache_mtx_addr = addr + ARENA_NODE_CACHE_MTX_OFFSET_64_450;
	out->chunk_hooks_addr = addr + ARENA_CHUNK_HOOKS_OFFSET_64_450;
	out->bins_addr = addr + ARENA_BINS_OFFSET_64_450;
	out->runs_avail_addr = addr + ARENA_RUNS_AVAIL_OFFSET_64_450;
	ret = true;

cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_t_450_32(RzIO *io, ut64 addr, arena_t_450 *out) {
	bool ret = false;
	ut8 *buf = malloc(ARENA_SIZE_32_450);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, ARENA_SIZE_32_450)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, ARENA_SIZE_32_450);
	free(buf);
	if (!b) {
		return false;
	}
	ut64 offset = 0;

	if (!rz_buf_read_le32_offset(b, &offset, &out->ind) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[0]) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[1])) {
		goto cleanup;
	}

	ut32 offset_state, extent_sn_next, spare, lg_dirty_mult_raw, nactive, ndirty;
	ut8 purging_byte;

	offset = ARENA_PROF_ACCUMBYTES_OFFSET_32_450;
	if (!rz_buf_read_le64_offset(b, &offset, &out->prof_accumbytes) ||
		!rz_buf_read_le32_offset(b, &offset, &offset_state) ||
		!rz_buf_read_le32_offset(b, &offset, &out->dss_prec)) {
		goto cleanup;
	}
	out->offset_state = offset_state;

	offset = ARENA_EXTENT_SN_NEXT_OFFSET_32_450;
	if (!rz_buf_read_le32_offset(b, &offset, &extent_sn_next) ||
		!rz_buf_read_le32_offset(b, &offset, &spare)) {
		goto cleanup;
	}
	out->extent_sn_next = extent_sn_next;
	out->spare = spare;

	offset = ARENA_LG_DIRTY_MULT_OFFSET_32_450;
	if (!rz_buf_read_le32_offset(b, &offset, &lg_dirty_mult_raw)) {
		goto cleanup;
	}
	out->lg_dirty_mult = (st32)lg_dirty_mult_raw;

	offset = ARENA_PURGING_OFFSET_32_450;
	if (rz_buf_read_at(b, offset, &purging_byte, 1) != 1) {
		goto cleanup;
	}
	out->purging = purging_byte != 0;

	offset = ARENA_NACTIVE_OFFSET_32_450;
	if (!rz_buf_read_le32_offset(b, &offset, &nactive) ||
		!rz_buf_read_le32_offset(b, &offset, &ndirty)) {
		goto cleanup;
	}
	out->nactive = nactive;
	out->ndirty = ndirty;

	out->lock_addr = addr + ARENA_LOCK_OFFSET_32_450;
	out->stats_addr = addr + ARENA_STATS_OFFSET_32_450;
	out->tcache_ql_addr = addr + ARENA_TCACHE_QL_OFFSET_32_450;
	out->achunks_addr = addr + ARENA_ACHUNKS_OFFSET_32_450;
	out->runs_dirty_addr = addr + ARENA_RUNS_DIRTY_OFFSET_32_450;
	out->chunks_cache_addr = addr + ARENA_CHUNKS_CACHE_OFFSET_32_450;
	out->decay_addr = addr + ARENA_DECAY_OFFSET_32_450;
	out->huge_addr = addr + ARENA_HUGE_OFFSET_32_450;
	out->huge_mtx_addr = addr + ARENA_HUGE_MTX_OFFSET_32_450;
	out->chunks_szsnad_cached_addr = addr + ARENA_CHUNKS_SZSNAD_CACHED_OFFSET_32_450;
	out->chunks_ad_cached_addr = addr + ARENA_CHUNKS_AD_CACHED_OFFSET_32_450;
	out->chunks_mtx_addr = addr + ARENA_CHUNKS_MTX_OFFSET_32_450;
	out->node_cache_addr = addr + ARENA_NODE_CACHE_OFFSET_32_450;
	out->node_cache_mtx_addr = addr + ARENA_NODE_CACHE_MTX_OFFSET_32_450;
	out->chunk_hooks_addr = addr + ARENA_CHUNK_HOOKS_OFFSET_32_450;
	out->bins_addr = addr + ARENA_BINS_OFFSET_32_450;
	out->runs_avail_addr = addr + ARENA_RUNS_AVAIL_OFFSET_32_450;
	ret = true;

cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_t_450(RzIO *io, ut64 addr, arena_t_450 *out, bool is_64bit) {
	return is_64bit
		? read_and_parse_arena_t_450_64(io, addr, out)
		: read_and_parse_arena_t_450_32(io, addr, out);
}

static inline bool read_achunks_first_450(RzIO *io, ut64 achunks_addr, ut64 *first_out, bool is_64bit) {
	if (is_64bit) {
		ut8 buf[8];
		if (!rz_io_read_at_mapped(io, achunks_addr, buf, 8)) {
			return false;
		}
		*first_out = rz_read_le64(buf);
	} else {
		ut8 buf[4];
		if (!rz_io_read_at_mapped(io, achunks_addr, buf, 4)) {
			return false;
		}
		*first_out = rz_read_le32(buf);
	}
	return true;
}

#endif // RZ_JEMALLOC_450_H
