// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JEMALLOC_450_H
#define RZ_JEMALLOC_450_H

#include "jemalloc_arch.h"
#include <rz_util.h>
#include <rz_io.h>

#define NPSIZES_64_450        199
#define NPSIZES_32_450        71
#define SMOOTHSTEP_NSTEPS_450 200
#define BITMAP_MAX_LEVELS_450 5
#define LG_PAGE_450           12

// ============================================================================
// jemalloc 4.5.0 configuration
// ============================================================================

typedef struct rz_jemalloc_arena_offsets_450_t {
	ut32 lock;
	ut32 stats;
	ut32 tcache_ql;
	ut32 prof_accumbytes;
	ut32 achunks;
	ut32 extent_sn_next;
	ut32 lg_dirty_mult;
	ut32 purging;
	ut32 nactive;
	ut32 runs_dirty;
	ut32 chunks_cache;
	ut32 decay;
	ut32 huge;
	ut32 huge_mtx;
	ut32 chunks_szsnad_cached;
	ut32 chunks_ad_cached;
	ut32 chunks_mtx;
	ut32 node_cache;
	ut32 node_cache_mtx;
	ut32 chunk_hooks;
	ut32 bins;
	ut32 runs_avail;
} RzJemallocArenaOffsets450;

typedef struct rz_jemalloc_extent_node_offsets_450_t {
	ut32 ql_link_next;
} RzJemallocExtentNodeOffsets450;

typedef struct rz_jemalloc_bin_info_offsets_450_t {
	ut32 bitmap_info;
	ut32 reg0_offset;
} RzJemallocBinInfoOffsets450;

typedef struct rz_jemalloc_config_450_t {
	RzJemallocArch arch;
	ut8 ptr_size;
	bool is_big_endian;

	ut8 lg_page;

	ut32 sc_nbins;
	ut32 npsizes;

	bool bitmap_use_tree;
	ut32 bitmap_max_levels;

	ut32 extent_node_size;
	ut32 bin_info_size;
	ut32 bin_size;
	ut32 arena_size;
	ut32 bitmap_info_size;
	ut32 malloc_mutex_size;

	RzJemallocArenaOffsets450 arena_offsets;
	RzJemallocExtentNodeOffsets450 extent_node_offsets;
	RzJemallocBinInfoOffsets450 bin_info_offsets;
} RzJemallocConfig450;

static const RzJemallocConfig450 rz_jemalloc_config_amd64_linux_4k_450 = {
	.arch = RZ_JEMALLOC_ARCH_AMD64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.npsizes = 199,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.extent_node_size = 112,
	.bin_info_size = 64,
	.bin_size = 168,
	.arena_size = 10072,
	.bitmap_info_size = 16,
	.malloc_mutex_size = 80,
	.arena_offsets = {
		.lock = 16,
		.stats = 96,
		.tcache_ql = 224,
		.prof_accumbytes = 232,
		.achunks = 256,
		.extent_sn_next = 264,
		.lg_dirty_mult = 280,
		.purging = 288,
		.nactive = 296,
		.runs_dirty = 312,
		.chunks_cache = 328,
		.decay = 440,
		.huge = 2088,
		.huge_mtx = 2096,
		.chunks_szsnad_cached = 2176,
		.chunks_ad_cached = 2184,
		.chunks_mtx = 2208,
		.node_cache = 2288,
		.node_cache_mtx = 2296,
		.chunk_hooks = 2376,
		.bins = 2432,
		.runs_avail = 8480,
	},
	.extent_node_offsets = {
		.ql_link_next = 80,
	},
	.bin_info_offsets = {
		.bitmap_info = 40,
		.reg0_offset = 56,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_amd64_freebsd_4k_450 = {
	.arch = RZ_JEMALLOC_ARCH_AMD64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.npsizes = 199,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.extent_node_size = 112,
	.bin_info_size = 64,
	.bin_size = 144,
	.arena_size = 9112,
	.bitmap_info_size = 16,
	.malloc_mutex_size = 56,
	.arena_offsets = {
		.lock = 16,
		.stats = 72,
		.tcache_ql = 200,
		.prof_accumbytes = 208,
		.achunks = 232,
		.extent_sn_next = 240,
		.lg_dirty_mult = 256,
		.purging = 264,
		.nactive = 272,
		.runs_dirty = 288,
		.chunks_cache = 304,
		.decay = 416,
		.huge = 2064,
		.huge_mtx = 2072,
		.chunks_szsnad_cached = 2128,
		.chunks_ad_cached = 2136,
		.chunks_mtx = 2160,
		.node_cache = 2216,
		.node_cache_mtx = 2224,
		.chunk_hooks = 2280,
		.bins = 2336,
		.runs_avail = 7520,
	},
	.extent_node_offsets = {
		.ql_link_next = 80,
	},
	.bin_info_offsets = {
		.bitmap_info = 40,
		.reg0_offset = 56,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_i386_linux_4k_450 = {
	.arch = RZ_JEMALLOC_ARCH_I386,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.npsizes = 71,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.extent_node_size = 56,
	.bin_info_size = 56,
	.bin_size = 116,
	.arena_size = 5748,
	.bitmap_info_size = 32,
	.malloc_mutex_size = 44,
	.arena_offsets = {
		.lock = 12,
		.stats = 56,
		.tcache_ql = 152,
		.prof_accumbytes = 156,
		.achunks = 172,
		.extent_sn_next = 176,
		.lg_dirty_mult = 184,
		.purging = 188,
		.nactive = 192,
		.runs_dirty = 200,
		.chunks_cache = 208,
		.decay = 264,
		.huge = 1104,
		.huge_mtx = 1108,
		.chunks_szsnad_cached = 1152,
		.chunks_ad_cached = 1156,
		.chunks_mtx = 1168,
		.node_cache = 1212,
		.node_cache_mtx = 1216,
		.chunk_hooks = 1260,
		.bins = 1288,
		.runs_avail = 5464,
	},
	.extent_node_offsets = {
		.ql_link_next = 40,
	},
	.bin_info_offsets = {
		.bitmap_info = 20,
		.reg0_offset = 52,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_i386_freebsd_4k_450 = {
	.arch = RZ_JEMALLOC_ARCH_I386,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.npsizes = 71,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.extent_node_size = 56,
	.bin_info_size = 56,
	.bin_size = 100,
	.arena_size = 5108,
	.bitmap_info_size = 32,
	.malloc_mutex_size = 28,
	.arena_offsets = {
		.lock = 12,
		.stats = 40,
		.tcache_ql = 136,
		.prof_accumbytes = 140,
		.achunks = 156,
		.extent_sn_next = 160,
		.lg_dirty_mult = 168,
		.purging = 172,
		.nactive = 176,
		.runs_dirty = 184,
		.chunks_cache = 192,
		.decay = 248,
		.huge = 1088,
		.huge_mtx = 1092,
		.chunks_szsnad_cached = 1120,
		.chunks_ad_cached = 1124,
		.chunks_mtx = 1136,
		.node_cache = 1164,
		.node_cache_mtx = 1168,
		.chunk_hooks = 1196,
		.bins = 1224,
		.runs_avail = 4824,
	},
	.extent_node_offsets = {
		.ql_link_next = 40,
	},
	.bin_info_offsets = {
		.bitmap_info = 20,
		.reg0_offset = 52,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_aarch64_linux_4k_450 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.npsizes = 199,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.extent_node_size = 112,
	.bin_info_size = 64,
	.bin_size = 176,
	.arena_size = 10392,
	.bitmap_info_size = 16,
	.malloc_mutex_size = 88,
	.arena_offsets = {
		.lock = 16,
		.stats = 104,
		.tcache_ql = 232,
		.prof_accumbytes = 240,
		.achunks = 264,
		.extent_sn_next = 272,
		.lg_dirty_mult = 288,
		.purging = 296,
		.nactive = 304,
		.runs_dirty = 320,
		.chunks_cache = 336,
		.decay = 448,
		.huge = 2096,
		.huge_mtx = 2104,
		.chunks_szsnad_cached = 2192,
		.chunks_ad_cached = 2200,
		.chunks_mtx = 2224,
		.node_cache = 2312,
		.node_cache_mtx = 2320,
		.chunk_hooks = 2408,
		.bins = 2464,
		.runs_avail = 8800,
	},
	.extent_node_offsets = {
		.ql_link_next = 80,
	},
	.bin_info_offsets = {
		.bitmap_info = 40,
		.reg0_offset = 56,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_aarch64_linux_16k_450 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 14,
	.sc_nbins = 44,
	.npsizes = 191,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 4,
	.extent_node_size = 112,
	.bin_info_size = 104,
	.bin_size = 176,
	.arena_size = 11736,
	.bitmap_info_size = 56,
	.malloc_mutex_size = 88,
	.arena_offsets = {
		.lock = 16,
		.stats = 104,
		.tcache_ql = 232,
		.prof_accumbytes = 240,
		.achunks = 264,
		.extent_sn_next = 272,
		.lg_dirty_mult = 288,
		.purging = 296,
		.nactive = 304,
		.runs_dirty = 320,
		.chunks_cache = 336,
		.decay = 448,
		.huge = 2096,
		.huge_mtx = 2104,
		.chunks_szsnad_cached = 2192,
		.chunks_ad_cached = 2200,
		.chunks_mtx = 2224,
		.node_cache = 2312,
		.node_cache_mtx = 2320,
		.chunk_hooks = 2408,
		.bins = 2464,
		.runs_avail = 10208,
	},
	.extent_node_offsets = {
		.ql_link_next = 80,
	},
	.bin_info_offsets = {
		.bitmap_info = 40,
		.reg0_offset = 96,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_aarch64_linux_64k_450 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 16,
	.sc_nbins = 52,
	.npsizes = 183,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.extent_node_size = 112,
	.bin_info_size = 112,
	.bin_size = 176,
	.arena_size = 13080,
	.bitmap_info_size = 64,
	.malloc_mutex_size = 88,
	.arena_offsets = {
		.lock = 16,
		.stats = 104,
		.tcache_ql = 232,
		.prof_accumbytes = 240,
		.achunks = 264,
		.extent_sn_next = 272,
		.lg_dirty_mult = 288,
		.purging = 296,
		.nactive = 304,
		.runs_dirty = 320,
		.chunks_cache = 336,
		.decay = 448,
		.huge = 2096,
		.huge_mtx = 2104,
		.chunks_szsnad_cached = 2192,
		.chunks_ad_cached = 2200,
		.chunks_mtx = 2224,
		.node_cache = 2312,
		.node_cache_mtx = 2320,
		.chunk_hooks = 2408,
		.bins = 2464,
		.runs_avail = 11616,
	},
	.extent_node_offsets = {
		.ql_link_next = 80,
	},
	.bin_info_offsets = {
		.bitmap_info = 40,
		.reg0_offset = 104,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_arm32_linux_4k_450 = {
	.arch = RZ_JEMALLOC_ARCH_ARM32,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 39,
	.npsizes = 71,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.extent_node_size = 56,
	.bin_info_size = 56,
	.bin_size = 128,
	.arena_size = 6592,
	.bitmap_info_size = 32,
	.malloc_mutex_size = 44,
	.arena_offsets = {
		.lock = 12,
		.stats = 56,
		.tcache_ql = 160,
		.prof_accumbytes = 168,
		.achunks = 184,
		.extent_sn_next = 188,
		.lg_dirty_mult = 196,
		.purging = 200,
		.nactive = 204,
		.runs_dirty = 212,
		.chunks_cache = 220,
		.decay = 280,
		.huge = 1128,
		.huge_mtx = 1132,
		.chunks_szsnad_cached = 1176,
		.chunks_ad_cached = 1180,
		.chunks_mtx = 1192,
		.node_cache = 1236,
		.node_cache_mtx = 1240,
		.chunk_hooks = 1284,
		.bins = 1312,
		.runs_avail = 6304,
	},
	.extent_node_offsets = {
		.ql_link_next = 40,
	},
	.bin_info_offsets = {
		.bitmap_info = 20,
		.reg0_offset = 52,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_arm32_linux_64k_450 = {
	.arch = RZ_JEMALLOC_ARCH_ARM32,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 16,
	.sc_nbins = 55,
	.npsizes = 55,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 7,
	.extent_node_size = 56,
	.bin_info_size = 64,
	.bin_size = 128,
	.arena_size = 8576,
	.bitmap_info_size = 40,
	.malloc_mutex_size = 44,
	.arena_offsets = {
		.lock = 12,
		.stats = 56,
		.tcache_ql = 160,
		.prof_accumbytes = 168,
		.achunks = 184,
		.extent_sn_next = 188,
		.lg_dirty_mult = 196,
		.purging = 200,
		.nactive = 204,
		.runs_dirty = 212,
		.chunks_cache = 220,
		.decay = 280,
		.huge = 1128,
		.huge_mtx = 1132,
		.chunks_szsnad_cached = 1176,
		.chunks_ad_cached = 1180,
		.chunks_mtx = 1192,
		.node_cache = 1236,
		.node_cache_mtx = 1240,
		.chunk_hooks = 1284,
		.bins = 1312,
		.runs_avail = 8352,
	},
	.extent_node_offsets = {
		.ql_link_next = 40,
	},
	.bin_info_offsets = {
		.bitmap_info = 20,
		.reg0_offset = 60,
	},
};

static const RzJemallocConfig450 rz_jemalloc_config_aarch64_darwin_16k_450 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 14,
	.sc_nbins = 44,
	.npsizes = 191,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 4,
	.extent_node_size = 112,
	.bin_info_size = 104,
	.bin_size = 136,
	.arena_size = 9816,
	.bitmap_info_size = 56,
	.malloc_mutex_size = 48,
	.arena_offsets = {
		.lock = 16,
		.stats = 64,
		.tcache_ql = 192,
		.prof_accumbytes = 200,
		.achunks = 224,
		.extent_sn_next = 232,
		.lg_dirty_mult = 248,
		.purging = 256,
		.nactive = 264,
		.runs_dirty = 280,
		.chunks_cache = 296,
		.decay = 408,
		.huge = 2056,
		.huge_mtx = 2064,
		.chunks_szsnad_cached = 2112,
		.chunks_ad_cached = 2120,
		.chunks_mtx = 2144,
		.node_cache = 2192,
		.node_cache_mtx = 2200,
		.chunk_hooks = 2248,
		.bins = 2304,
		.runs_avail = 8288,
	},
	.extent_node_offsets = {
		.ql_link_next = 80,
	},
	.bin_info_offsets = {
		.bitmap_info = 40,
		.reg0_offset = 96,
	},
};

static inline const RzJemallocConfig450 *rz_jemalloc_get_config_450(const char *arch, const char *os, int bits, const char *page_size) {
	if (!arch || !os) {
		return NULL;
	}

	bool is_freebsd = !strcmp(os, "freebsd");
	bool is_darwin = !strcmp(os, "darwin") || !strcmp(os, "macos") || !strcmp(os, "ios");
	bool is_x86 = !strcmp(arch, "x86") || !strcmp(arch, "x64");
	bool is_arm = !strcmp(arch, "arm") || !strcmp(arch, "aarch64");

	bool is_16k = page_size && (!strcmp(page_size, "16k") || !strcmp(page_size, "16K"));
	bool is_64k = page_size && (!strcmp(page_size, "64k") || !strcmp(page_size, "64K"));

	if (is_darwin && is_arm && bits == 64) {
		return &rz_jemalloc_config_aarch64_darwin_16k_450;
	}

	if (is_freebsd && is_x86) {
		if (bits == 64) {
			return &rz_jemalloc_config_amd64_freebsd_4k_450;
		} else {
			return &rz_jemalloc_config_i386_freebsd_4k_450;
		}
	}

	if (is_x86) { // by default is linux
		if (bits == 64) {
			return &rz_jemalloc_config_amd64_linux_4k_450;
		} else {
			return &rz_jemalloc_config_i386_linux_4k_450;
		}
	}

	if (is_arm) {
		if (bits == 64) {
			if (is_64k) {
				return &rz_jemalloc_config_aarch64_linux_64k_450;
			} else if (is_16k) {
				return &rz_jemalloc_config_aarch64_linux_16k_450;
			}
			return &rz_jemalloc_config_aarch64_linux_4k_450;
		} else {
			if (is_64k) {
				return &rz_jemalloc_config_arm32_linux_64k_450;
			}
			return &rz_jemalloc_config_arm32_linux_4k_450;
		}
	}

	return NULL;
}

// ============================================================================
// jemalloc 4.5.0 structs
// ============================================================================

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
	ut64 ngroups;
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

// ============================================================================
// jemalloc 4.5.0 parser functions
// ============================================================================

static inline bool read_and_parse_extent_node_t_450(RzIO *io, ut64 addr, extent_node_t_450 *out,
	const RzJemallocConfig450 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->extent_node_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->extent_node_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->extent_node_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;

	const RzJemallocExtentNodeOffsets450 *eno = &config->extent_node_offsets;

	if (config->ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->en_arena) ||
			!rz_buf_read_le64_offset(b, &offset, &out->en_addr) ||
			!rz_buf_read_le64_offset(b, &offset, &out->en_size) ||
			!rz_buf_read_le64_offset(b, &offset, &out->en_sn) ||
			((offset = eno->ql_link_next), !rz_buf_read_le64_offset(b, &offset, &out->ql_link_next)) ||
			!rz_buf_read_le64_offset(b, &offset, &out->ql_link_prev)) {
			goto cleanup;
		}
	} else {
		ut32 en_arena, en_addr, en_size, en_sn, ql_next, ql_prev;
		if (!rz_buf_read_le32_offset(b, &offset, &en_arena) ||
			!rz_buf_read_le32_offset(b, &offset, &en_addr) ||
			!rz_buf_read_le32_offset(b, &offset, &en_size) ||
			!rz_buf_read_le32_offset(b, &offset, &en_sn) ||
			((offset = eno->ql_link_next), !rz_buf_read_le32_offset(b, &offset, &ql_next)) ||
			!rz_buf_read_le32_offset(b, &offset, &ql_prev)) {
			goto cleanup;
		}
		out->en_arena = en_arena;
		out->en_addr = en_addr;
		out->en_size = en_size;
		out->en_sn = en_sn;
		out->ql_link_next = ql_next;
		out->ql_link_prev = ql_prev;
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_bin_info_t_450(RzIO *io, ut64 addr, arena_bin_info_t_450 *out,
	const RzJemallocConfig450 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->bin_info_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->bin_info_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->bin_info_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;

	const RzJemallocBinInfoOffsets450 *bio = &config->bin_info_offsets;

	if (config->ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->reg_size) ||
			!rz_buf_read_le64_offset(b, &offset, &out->redzone_size) ||
			!rz_buf_read_le64_offset(b, &offset, &out->reg_interval) ||
			!rz_buf_read_le64_offset(b, &offset, &out->run_size) ||
			!rz_buf_read_le32_offset(b, &offset, &out->nregs)) {
			goto cleanup;
		}

		offset = bio->bitmap_info;
		if (config->bitmap_use_tree) { // tree format for 64 bit
			if (!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.nbits) ||
				!rz_buf_read_le32_offset(b, &offset, &out->bitmap_info.nlevels)) {
				goto cleanup;
			}
			out->bitmap_info.ngroups = 0;
			for (int i = 0; i < BITMAP_MAX_LEVELS_450 + 1; i++) {
				if (!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.levels[i])) {
					goto cleanup;
				}
			}
		} else { // non-tree format for 64 bit
			if (!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.nbits) ||
				!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.ngroups)) {
				goto cleanup;
			}
			out->bitmap_info.nlevels = 0;
			for (int i = 0; i < BITMAP_MAX_LEVELS_450 + 1; i++) {
				out->bitmap_info.levels[i] = 0;
			}
		}
		if (((offset = bio->reg0_offset), !rz_buf_read_le32_offset(b, &offset, &out->reg0_offset))) {
			goto cleanup;
		}
	} else {
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

		offset = bio->bitmap_info;
		if (config->bitmap_use_tree) { // tree format for 32 bit
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
		} else { // non-tree format for 32 bit
			ut32 nbits, ngroups;
			if (!rz_buf_read_le32_offset(b, &offset, &nbits) ||
				!rz_buf_read_le32_offset(b, &offset, &ngroups)) {
				goto cleanup;
			}
			out->bitmap_info.nbits = nbits;
			out->bitmap_info.ngroups = ngroups;
			out->bitmap_info.nlevels = 0;
			for (int i = 0; i < BITMAP_MAX_LEVELS_450 + 1; i++) {
				out->bitmap_info.levels[i] = 0;
			}
		}
		if (((offset = bio->reg0_offset), !rz_buf_read_le32_offset(b, &offset, &out->reg0_offset))) {
			goto cleanup;
		}
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_t_450(RzIO *io, ut64 addr, arena_t_450 *out,
	const RzJemallocConfig450 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->arena_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->arena_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->arena_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;

	const RzJemallocArenaOffsets450 *ao = &config->arena_offsets;

	if (!rz_buf_read_le32_offset(b, &offset, &out->ind) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[0]) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[1])) {
		goto cleanup;
	}

	if (config->ptr_size == 8) {
		ut64 lg_dirty_mult_tmp;
		ut8 purging_byte;
		if (((offset = ao->prof_accumbytes), !rz_buf_read_le64_offset(b, &offset, &out->prof_accumbytes)) ||
			!rz_buf_read_le64_offset(b, &offset, &out->offset_state) ||
			!rz_buf_read_le32_offset(b, &offset, &out->dss_prec) ||
			((offset = ao->extent_sn_next), !rz_buf_read_le64_offset(b, &offset, &out->extent_sn_next)) ||
			!rz_buf_read_le64_offset(b, &offset, &out->spare) ||
			((offset = ao->lg_dirty_mult), !rz_buf_read_le64_offset(b, &offset, &lg_dirty_mult_tmp)) ||
			((offset = ao->purging), !rz_buf_read8_offset(b, &offset, &purging_byte)) ||
			((offset = ao->nactive), !rz_buf_read_le64_offset(b, &offset, &out->nactive)) ||
			!rz_buf_read_le64_offset(b, &offset, &out->ndirty)) {
			goto cleanup;
		}
		out->lg_dirty_mult = (st64)lg_dirty_mult_tmp;
		out->purging = purging_byte != 0;
	} else {
		ut32 offset_state, extent_sn_next, spare, lg_dirty_mult_tmp, nactive, ndirty;
		ut8 purging_byte;
		if (((offset = ao->prof_accumbytes), !rz_buf_read_le64_offset(b, &offset, &out->prof_accumbytes)) ||
			!rz_buf_read_le32_offset(b, &offset, &offset_state) ||
			!rz_buf_read_le32_offset(b, &offset, &out->dss_prec) ||
			((offset = ao->extent_sn_next), !rz_buf_read_le32_offset(b, &offset, &extent_sn_next)) ||
			!rz_buf_read_le32_offset(b, &offset, &spare) ||
			((offset = ao->lg_dirty_mult), !rz_buf_read_le32_offset(b, &offset, &lg_dirty_mult_tmp)) ||
			((offset = ao->purging), !rz_buf_read8_offset(b, &offset, &purging_byte)) ||
			((offset = ao->nactive), !rz_buf_read_le32_offset(b, &offset, &nactive)) ||
			!rz_buf_read_le32_offset(b, &offset, &ndirty)) {
			goto cleanup;
		}
		out->offset_state = offset_state;
		out->extent_sn_next = extent_sn_next;
		out->spare = spare;
		out->lg_dirty_mult = (st32)lg_dirty_mult_tmp;
		out->purging = purging_byte != 0;
		out->nactive = nactive;
		out->ndirty = ndirty;
	}

	out->lock_addr = addr + ao->lock;
	out->stats_addr = addr + ao->stats;
	out->tcache_ql_addr = addr + ao->tcache_ql;
	out->achunks_addr = addr + ao->achunks;
	out->runs_dirty_addr = addr + ao->runs_dirty;
	out->chunks_cache_addr = addr + ao->chunks_cache;
	out->decay_addr = addr + ao->decay;
	out->huge_addr = addr + ao->huge;
	out->huge_mtx_addr = addr + ao->huge_mtx;
	out->chunks_szsnad_cached_addr = addr + ao->chunks_szsnad_cached;
	out->chunks_ad_cached_addr = addr + ao->chunks_ad_cached;
	out->chunks_mtx_addr = addr + ao->chunks_mtx;
	out->node_cache_addr = addr + ao->node_cache;
	out->node_cache_mtx_addr = addr + ao->node_cache_mtx;
	out->chunk_hooks_addr = addr + ao->chunk_hooks;
	out->bins_addr = addr + ao->bins;
	out->runs_avail_addr = addr + ao->runs_avail;

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_achunks_first_450(RzIO *io, ut64 achunks_addr, ut64 *first_out,
	const RzJemallocConfig450 *config) {
	if (config->ptr_size == 8) {
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
