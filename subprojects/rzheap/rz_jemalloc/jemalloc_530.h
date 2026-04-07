// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JEMALLOC_530_H
#define RZ_JEMALLOC_530_H

#include "jemalloc_arch.h"
#include <rz_util.h>
#include <rz_io.h>
#include <stdio.h>

#define BITMAP_MAX_LEVELS_530 6
#define SC_NSIZES             235
#define SC_LG_SLAB_MAXREGS    9
#define MALLOCX_ARENA_BITS    12
#define EDATA_ALIGNMENT       128

#define MASK(CURRENT_FIELD_WIDTH, CURRENT_FIELD_SHIFT) ((((((ut64)0x1U) << (CURRENT_FIELD_WIDTH)) - 1)) << (CURRENT_FIELD_SHIFT))

#define EDATA_BITS_ARENA_WIDTH MALLOCX_ARENA_BITS
#define EDATA_BITS_ARENA_SHIFT 0
#define EDATA_BITS_ARENA_MASK  MASK(EDATA_BITS_ARENA_WIDTH, EDATA_BITS_ARENA_SHIFT)

#define EDATA_BITS_SLAB_WIDTH 1
#define EDATA_BITS_SLAB_SHIFT (EDATA_BITS_ARENA_WIDTH + EDATA_BITS_ARENA_SHIFT)
#define EDATA_BITS_SLAB_MASK  MASK(EDATA_BITS_SLAB_WIDTH, EDATA_BITS_SLAB_SHIFT)

#define EDATA_BITS_COMMITTED_WIDTH 1
#define EDATA_BITS_COMMITTED_SHIFT (EDATA_BITS_SLAB_WIDTH + EDATA_BITS_SLAB_SHIFT)
#define EDATA_BITS_COMMITTED_MASK  MASK(EDATA_BITS_COMMITTED_WIDTH, EDATA_BITS_COMMITTED_SHIFT)

#define EDATA_BITS_PAI_WIDTH 1
#define EDATA_BITS_PAI_SHIFT (EDATA_BITS_COMMITTED_WIDTH + EDATA_BITS_COMMITTED_SHIFT)
#define EDATA_BITS_PAI_MASK  MASK(EDATA_BITS_PAI_WIDTH, EDATA_BITS_PAI_SHIFT)

#define EDATA_BITS_ZEROED_WIDTH 1
#define EDATA_BITS_ZEROED_SHIFT (EDATA_BITS_PAI_WIDTH + EDATA_BITS_PAI_SHIFT)
#define EDATA_BITS_ZEROED_MASK  MASK(EDATA_BITS_ZEROED_WIDTH, EDATA_BITS_ZEROED_SHIFT)

#define EDATA_BITS_GUARDED_WIDTH 1
#define EDATA_BITS_GUARDED_SHIFT (EDATA_BITS_ZEROED_WIDTH + EDATA_BITS_ZEROED_SHIFT)
#define EDATA_BITS_GUARDED_MASK  MASK(EDATA_BITS_GUARDED_WIDTH, EDATA_BITS_GUARDED_SHIFT)

#define EDATA_BITS_STATE_WIDTH 3
#define EDATA_BITS_STATE_SHIFT (EDATA_BITS_GUARDED_WIDTH + EDATA_BITS_GUARDED_SHIFT)
#define EDATA_BITS_STATE_MASK  MASK(EDATA_BITS_STATE_WIDTH, EDATA_BITS_STATE_SHIFT)

// ============================================================================
// jemalloc 5.3.0 configuration
// ============================================================================

typedef struct rz_jemalloc_arena_offsets_530_t {
	ut32 stats;
	ut32 tcache_ql;
	ut32 cache_bin_arr;
	ut32 tcache_ql_mtx;
	ut32 dss_prec;
	ut32 large;
	ut32 large_mtx;
	ut32 pa_shard;
	ut32 ind;
	ut32 base;
	ut32 create_time;
	ut32 bins;
	ut32 last_thd;
} RzJemallocArenaOffsets530;

typedef struct rz_jemalloc_bin_offsets_530_t {
	ut32 slabcur;
} RzJemallocBinOffsets530;

typedef struct rz_jemalloc_rtree_offsets_530_t {
	ut32 root;
} RzJemallocRtreeOffsets530;

typedef struct rz_jemalloc_config_530_t {
	RzJemallocArch arch;
	ut8 ptr_size;
	bool is_big_endian;

	ut8 lg_page; // Log2 of page size (12=4K, 14=16K, 16=64K)

	ut32 sc_nbins;
	ut32 sc_nsizes;

	bool bitmap_use_tree;
	ut32 bitmap_max_levels;

	ut32 rtree_nsb;
	ut32 rtree_bits_per_level;
	ut32 rtree_height;
	bool rtree_leaf_compact;

	ut32 edata_size;
	ut32 bin_info_size;
	ut32 bin_size;
	ut32 arena_size;
	ut32 bitmap_info_size;
	ut32 rtree_node_elm_size;
	ut32 rtree_leaf_elm_size;

	RzJemallocArenaOffsets530 arena_offsets;
	RzJemallocBinOffsets530 bin_offsets;
	RzJemallocRtreeOffsets530 rtree_offsets;
} RzJemallocConfig530;

static const RzJemallocConfig530 rz_jemalloc_config_amd64_linux_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_AMD64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.sc_nsizes = 232,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.rtree_nsb = 36,
	.rtree_bits_per_level = 18,
	.rtree_height = 2,
	.rtree_leaf_compact = true,
	.edata_size = 128,
	.bin_info_size = 40,
	.bin_size = 224,
	.arena_size = 78952,
	.bitmap_info_size = 16,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 10392,
		.cache_bin_arr = 10400,
		.tcache_ql_mtx = 10408,
		.dss_prec = 10520,
		.large = 10528,
		.large_mtx = 10536,
		.pa_shard = 10648,
		.ind = 78928,
		.base = 78936,
		.create_time = 78944,
		.bins = 78952,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 192,
	},
	.rtree_offsets = {
		.root = 120,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_amd64_freebsd_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_AMD64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.sc_nsizes = 232,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.rtree_nsb = 36,
	.rtree_bits_per_level = 18,
	.rtree_height = 2,
	.rtree_leaf_compact = true,
	.edata_size = 128,
	.bin_info_size = 40,
	.bin_size = 200,
	.arena_size = 78664,
	.bitmap_info_size = 16,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 10392,
		.cache_bin_arr = 10400,
		.tcache_ql_mtx = 10408,
		.dss_prec = 10496,
		.large = 10504,
		.large_mtx = 10512,
		.pa_shard = 10600,
		.ind = 78640,
		.base = 78648,
		.create_time = 78656,
		.bins = 78664,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 168,
	},
	.rtree_offsets = {
		.root = 96,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_i386_linux_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_I386,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.sc_nsizes = 104,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 20,
	.rtree_bits_per_level = 10,
	.rtree_height = 2,
	.rtree_leaf_compact = false,
	.edata_size = 108,
	.bin_info_size = 48,
	.bin_size = 172,
	.arena_size = 22004,
	.bitmap_info_size = 32,
	.rtree_node_elm_size = 4,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 16,
		.tcache_ql = 3960,
		.cache_bin_arr = 3964,
		.tcache_ql_mtx = 3968,
		.dss_prec = 4056,
		.large = 4060,
		.large_mtx = 4064,
		.pa_shard = 4152,
		.ind = 21988,
		.base = 21992,
		.create_time = 21996,
		.bins = 22004,
		.last_thd = 12,
	},
	.bin_offsets = {
		.slabcur = 156,
	},
	.rtree_offsets = {
		.root = 92,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_i386_freebsd_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_I386,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.sc_nsizes = 104,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 20,
	.rtree_bits_per_level = 10,
	.rtree_height = 2,
	.rtree_leaf_compact = false,
	.edata_size = 108,
	.bin_info_size = 48,
	.bin_size = 156,
	.arena_size = 21796,
	.bitmap_info_size = 32,
	.rtree_node_elm_size = 4,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 16,
		.tcache_ql = 3944,
		.cache_bin_arr = 3948,
		.tcache_ql_mtx = 3952,
		.dss_prec = 4024,
		.large = 4028,
		.large_mtx = 4032,
		.pa_shard = 4104,
		.ind = 21780,
		.base = 21784,
		.create_time = 21788,
		.bins = 21796,
		.last_thd = 12,
	},
	.bin_offsets = {
		.slabcur = 140,
	},
	.rtree_offsets = {
		.root = 76,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_aarch64_linux_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.sc_nsizes = 232,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.rtree_nsb = 36,
	.rtree_bits_per_level = 18,
	.rtree_height = 2,
	.rtree_leaf_compact = true,
	.edata_size = 128,
	.bin_info_size = 40,
	.bin_size = 232,
	.arena_size = 79048,
	.bitmap_info_size = 16,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 10392,
		.cache_bin_arr = 10400,
		.tcache_ql_mtx = 10408,
		.dss_prec = 10528,
		.large = 10536,
		.large_mtx = 10544,
		.pa_shard = 10664,
		.ind = 79024,
		.base = 79032,
		.create_time = 79040,
		.bins = 79048,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 200,
	},
	.rtree_offsets = {
		.root = 128,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_aarch64_linux_16k_530 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 14,
	.sc_nbins = 44,
	.sc_nsizes = 232,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 34,
	.rtree_bits_per_level = 17,
	.rtree_height = 2,
	.rtree_leaf_compact = true,
	.edata_size = 328,
	.bin_info_size = 88,
	.bin_size = 232,
	.arena_size = 76312,
	.bitmap_info_size = 64,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 10008,
		.cache_bin_arr = 10016,
		.tcache_ql_mtx = 10024,
		.dss_prec = 10144,
		.large = 10152,
		.large_mtx = 10160,
		.pa_shard = 10280,
		.ind = 76288,
		.base = 76296,
		.create_time = 76304,
		.bins = 76312,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 200,
	},
	.rtree_offsets = {
		.root = 128,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_aarch64_linux_64k_530 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 16,
	.sc_nbins = 52,
	.sc_nsizes = 232,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 32,
	.rtree_bits_per_level = 16,
	.rtree_height = 2,
	.rtree_leaf_compact = true,
	.edata_size = 1112,
	.bin_info_size = 88,
	.bin_size = 232,
	.arena_size = 73624,
	.bitmap_info_size = 64,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 9624,
		.cache_bin_arr = 9632,
		.tcache_ql_mtx = 9640,
		.dss_prec = 9760,
		.large = 9768,
		.large_mtx = 9776,
		.pa_shard = 9896,
		.ind = 73600,
		.base = 73608,
		.create_time = 73616,
		.bins = 73624,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 200,
	},
	.rtree_offsets = {
		.root = 128,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_arm32_linux_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_ARM32,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 39,
	.sc_nsizes = 107,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 20,
	.rtree_bits_per_level = 10,
	.rtree_height = 2,
	.rtree_leaf_compact = false,
	.edata_size = 120,
	.bin_info_size = 48,
	.bin_size = 184,
	.arena_size = 24272,
	.bitmap_info_size = 32,
	.rtree_node_elm_size = 4,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 16,
		.tcache_ql = 4296,
		.cache_bin_arr = 4300,
		.tcache_ql_mtx = 4304,
		.dss_prec = 4400,
		.large = 4404,
		.large_mtx = 4408,
		.pa_shard = 4504,
		.ind = 24256,
		.base = 24260,
		.create_time = 24264,
		.bins = 24272,
		.last_thd = 12,
	},
	.bin_offsets = {
		.slabcur = 168,
	},
	.rtree_offsets = {
		.root = 104,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_arm32_linux_64k_530 = {
	.arch = RZ_JEMALLOC_ARCH_ARM32,
	.ptr_size = 4,
	.is_big_endian = false,
	.lg_page = 16,
	.sc_nbins = 55,
	.sc_nsizes = 107,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 16,
	.rtree_bits_per_level = 8,
	.rtree_height = 2,
	.rtree_leaf_compact = false,
	.edata_size = 1112,
	.bin_info_size = 48,
	.bin_size = 184,
	.arena_size = 20384,
	.bitmap_info_size = 32,
	.rtree_node_elm_size = 4,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 16,
		.tcache_ql = 3528,
		.cache_bin_arr = 3532,
		.tcache_ql_mtx = 3536,
		.dss_prec = 3632,
		.large = 3636,
		.large_mtx = 3640,
		.pa_shard = 3736,
		.ind = 20368,
		.base = 20372,
		.create_time = 20376,
		.bins = 20384,
		.last_thd = 12,
	},
	.bin_offsets = {
		.slabcur = 168,
	},
	.rtree_offsets = {
		.root = 104,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_riscv64_linux_4k_530 = {
	.arch = RZ_JEMALLOC_ARCH_RISCV64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 12,
	.sc_nbins = 36,
	.sc_nsizes = 232,
	.bitmap_use_tree = false,
	.bitmap_max_levels = 0,
	.rtree_nsb = 52,
	.rtree_bits_per_level = 17,
	.rtree_height = 3,
	.rtree_leaf_compact = false,
	.edata_size = 128,
	.bin_info_size = 40,
	.bin_size = 224,
	.arena_size = 78952,
	.bitmap_info_size = 16,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 16,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 10392,
		.cache_bin_arr = 10400,
		.tcache_ql_mtx = 10408,
		.dss_prec = 10520,
		.large = 10528,
		.large_mtx = 10536,
		.pa_shard = 10648,
		.ind = 78928,
		.base = 78936,
		.create_time = 78944,
		.bins = 78952,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 192,
	},
	.rtree_offsets = {
		.root = 120,
	},
};

static const RzJemallocConfig530 rz_jemalloc_config_aarch64_darwin_16k_530 = {
	.arch = RZ_JEMALLOC_ARCH_AARCH64,
	.ptr_size = 8,
	.is_big_endian = false,
	.lg_page = 14,
	.sc_nbins = 44,
	.sc_nsizes = 232,
	.bitmap_use_tree = true,
	.bitmap_max_levels = 5,
	.rtree_nsb = 34,
	.rtree_bits_per_level = 17,
	.rtree_height = 2,
	.rtree_leaf_compact = true,
	.edata_size = 328,
	.bin_info_size = 88,
	.bin_size = 184,
	.arena_size = 75736,
	.bitmap_info_size = 64,
	.rtree_node_elm_size = 8,
	.rtree_leaf_elm_size = 8,
	.arena_offsets = {
		.stats = 24,
		.tcache_ql = 10008,
		.cache_bin_arr = 10016,
		.tcache_ql_mtx = 10024,
		.dss_prec = 10096,
		.large = 10104,
		.large_mtx = 10112,
		.pa_shard = 10184,
		.ind = 75712,
		.base = 75720,
		.create_time = 75728,
		.bins = 75736,
		.last_thd = 16,
	},
	.bin_offsets = {
		.slabcur = 152,
	},
	.rtree_offsets = {
		.root = 80,
	},
};

static inline const RzJemallocConfig530 *rz_jemalloc_get_config_530(const char *arch, const char *os, int bits, const char *page_size) {
	if (!arch || !os) {
		return NULL;
	}

	// default is_linux
	bool is_darwin = !strcmp(os, "darwin") || !strcmp(os, "macos") || !strcmp(os, "ios");
	bool is_freebsd = !strcmp(os, "freebsd");
	bool is_x86 = !strcmp(arch, "x86") || !strcmp(arch, "x64");
	bool is_arm = !strcmp(arch, "arm") || !strcmp(arch, "aarch64");
	bool is_riscv = !strcmp(arch, "riscv");

	bool is_16k = page_size && (!strcmp(page_size, "16k") || !strcmp(page_size, "16K"));
	bool is_64k = page_size && (!strcmp(page_size, "64k") || !strcmp(page_size, "64K"));

	if (is_darwin && is_arm && bits == 64) {
		return &rz_jemalloc_config_aarch64_darwin_16k_530;
	}

	if (is_freebsd && is_x86) {
		if (bits == 64) {
			return &rz_jemalloc_config_amd64_freebsd_4k_530;
		} else {
			return &rz_jemalloc_config_i386_freebsd_4k_530;
		}
	}

	if (is_x86) { // by default is linux
		if (bits == 64) {
			return &rz_jemalloc_config_amd64_linux_4k_530;
		} else {
			return &rz_jemalloc_config_i386_linux_4k_530;
		}
	}

	if (is_arm) {
		if (bits == 64) {
			if (is_64k) {
				return &rz_jemalloc_config_aarch64_linux_64k_530;
			} else if (is_16k) {
				return &rz_jemalloc_config_aarch64_linux_16k_530;
			}
			return &rz_jemalloc_config_aarch64_linux_4k_530;
		} else {
			if (is_64k) {
				return &rz_jemalloc_config_arm32_linux_64k_530;
			}
			return &rz_jemalloc_config_arm32_linux_4k_530;
		}
	}

	if (is_riscv && bits == 64) {
		return &rz_jemalloc_config_riscv64_linux_4k_530;
	}

	return NULL;
}

// ============================================================================
// jemalloc 5.3.0 structs
// ============================================================================

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/ph.h
 */
typedef struct phn_link_t_530 {
	ut64 prev;
	ut64 next;
	ut64 lchild;
} phn_link_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/ph.h
 */
typedef struct ph_t_530 {
	ut64 root;
	ut64 auxcount;
} ph_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/rtree.h
 */
typedef struct rtree_leaf_elm_t_530 {
	ut64 le_bits; // Used for 64-bit compact format
	ut64 le_edata; // Used for 32-bit non-compact format
	ut64 le_metadata; // Used for 32-bit non-compact format
} rtree_leaf_elm_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/rtree.h
 */
typedef struct rtree_node_elm_t_530 {
	ut64 child;
} rtree_node_elm_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/edata.h
 */
typedef struct edata_t_530 {
	ut64 e_bits;
	ut64 e_addr;
	ut64 e_size_esn; // union: e_size_esn or e_bsize
	ut64 e_ps;
	ut64 e_sn;
} edata_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin.h
 */
typedef struct nstime_t_530 {
	ut64 ns;
} nstime_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin_info.h
 */
typedef struct bitmap_info_t_530 {
	ut64 nbits;
	// Non-tree format
	ut64 ngroups;
	// Tree format
	ut32 nlevels;
	ut64 levels[BITMAP_MAX_LEVELS_530 + 1];
} bitmap_info_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin.h
 */
typedef struct bin_info_t_530 {
	ut64 reg_size;
	ut64 slab_size;
	ut32 nregs;
	ut32 n_shards;
	bitmap_info_t_530 bitmap_info;
} bin_info_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin.h
 */
typedef struct bin_t_530 {
	ut64 slabcur;
} bin_t_530;

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/arena_structs.h
 */
typedef struct arena_t_530 {
	ut32 nthreads[2];
	ut32 binshard_next;
	ut64 last_thd;
	ut32 dss_prec;
	ut32 ind;
	ut64 base;
	ut64 create_time_ns;
	ut64 stats_addr;
	ut64 tcache_ql_addr;
	ut64 cache_bin_array_descriptor_ql_addr;
	ut64 tcache_ql_mtx_addr;
	ut64 large_addr;
	ut64 large_mtx_addr;
	ut64 pa_shard_addr;
	ut64 bins_addr;
} arena_t_530;

// ============================================================================
// parser
// ============================================================================

static inline bool read_and_parse_rtree_node_elm_t_530(RzIO *io, ut64 addr, rtree_node_elm_t_530 *out,
	const RzJemallocConfig530 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->rtree_node_elm_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->rtree_node_elm_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->rtree_node_elm_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (config->ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->child)) {
			goto cleanup;
		}
	} else {
		ut32 val;
		if (!rz_buf_read_le32_offset(b, &offset, &val)) {
			goto cleanup;
		}
		out->child = val;
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_rtree_leaf_elm_t_530(RzIO *io, ut64 addr, rtree_leaf_elm_t_530 *out,
	const RzJemallocConfig530 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->rtree_leaf_elm_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->rtree_leaf_elm_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->rtree_leaf_elm_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (config->rtree_leaf_compact) {
		// Compact format with le_bits (used by x86_64, aarch64)
		if (!rz_buf_read_le64_offset(b, &offset, &out->le_bits)) {
			goto cleanup;
		}
		out->le_edata = 0;
		out->le_metadata = 0;
	} else {
		// Non-compact format with separate le_edata and le_metadata
		// Used by i386, arm32, and riscv64
		out->le_bits = 0;
		if (config->ptr_size == 8) {
			// 64-bit non-compact format (riscv64)
			if (!rz_buf_read_le64_offset(b, &offset, &out->le_edata) ||
				!rz_buf_read_le64_offset(b, &offset, &out->le_metadata)) {
				goto cleanup;
			}
		} else {
			// 32-bit non-compact format (i386, arm32)
			ut32 edata, metadata;
			if (!rz_buf_read_le32_offset(b, &offset, &edata) ||
				!rz_buf_read_le32_offset(b, &offset, &metadata)) {
				goto cleanup;
			}
			out->le_edata = edata;
			out->le_metadata = metadata;
		}
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_edata_t_530(RzIO *io, ut64 addr, edata_t_530 *out,
	const RzJemallocConfig530 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->edata_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->edata_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->edata_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = 0;
	bool ret = false;

	if (!rz_buf_read_le64_offset(b, &offset, &out->e_bits)) {
		goto cleanup;
	}

	if (config->ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->e_addr) ||
			!rz_buf_read_le64_offset(b, &offset, &out->e_size_esn) ||
			!rz_buf_read_le64_offset(b, &offset, &out->e_ps) ||
			!rz_buf_read_le64_offset(b, &offset, &out->e_sn)) {
			goto cleanup;
		}
	} else {
		ut32 e_addr, size_esn, ps;
		if (!rz_buf_read_le32_offset(b, &offset, &e_addr) ||
			!rz_buf_read_le32_offset(b, &offset, &size_esn) ||
			!rz_buf_read_le32_offset(b, &offset, &ps) ||
			!rz_buf_read_le64_offset(b, &offset, &out->e_sn)) {
			goto cleanup;
		}
		out->e_addr = e_addr;
		out->e_size_esn = size_esn;
		out->e_ps = ps;
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_bin_info_t_530(RzIO *io, ut64 addr, bin_info_t_530 *out,
	const RzJemallocConfig530 *config) {
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

	if (config->ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->reg_size) ||
			!rz_buf_read_le64_offset(b, &offset, &out->slab_size) ||
			!rz_buf_read_le32_offset(b, &offset, &out->nregs) ||
			!rz_buf_read_le32_offset(b, &offset, &out->n_shards)) {
			goto cleanup;
		}

		if (config->bitmap_use_tree) {
			// Tree format: nbits + nlevels + levels[]
			if (!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.nbits) ||
				!rz_buf_read_le32_offset(b, &offset, &out->bitmap_info.nlevels)) {
				goto cleanup;
			}
			out->bitmap_info.ngroups = 0;
			// Skip levels - we don't need them for basic parsing
			for (ut32 i = 0; i < config->bitmap_max_levels + 1 && i < BITMAP_MAX_LEVELS_530 + 1; i++) {
				out->bitmap_info.levels[i] = 0;
			}
		} else {
			// Non-tree format: nbits + ngroups
			if (!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.nbits) ||
				!rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.ngroups)) {
				goto cleanup;
			}
			out->bitmap_info.nlevels = 0;
		}
	} else {
		ut32 reg_size, slab_size;
		if (!rz_buf_read_le32_offset(b, &offset, &reg_size) ||
			!rz_buf_read_le32_offset(b, &offset, &slab_size) ||
			!rz_buf_read_le32_offset(b, &offset, &out->nregs) ||
			!rz_buf_read_le32_offset(b, &offset, &out->n_shards)) {
			goto cleanup;
		}
		out->reg_size = reg_size;
		out->slab_size = slab_size;

		if (config->bitmap_use_tree) {
			// Tree format for 32-bit
			ut32 nbits;
			if (!rz_buf_read_le32_offset(b, &offset, &nbits) ||
				!rz_buf_read_le32_offset(b, &offset, &out->bitmap_info.nlevels)) {
				goto cleanup;
			}
			out->bitmap_info.nbits = nbits;
			out->bitmap_info.ngroups = 0;
			for (ut32 i = 0; i < config->bitmap_max_levels + 1 && i < BITMAP_MAX_LEVELS_530 + 1; i++) {
				ut32 level;
				if (!rz_buf_read_le32_offset(b, &offset, &level)) {
					goto cleanup;
				}
				out->bitmap_info.levels[i] = level;
			}
		} else {
			// Non-tree format for 32-bit (unlikely but handle it)
			ut32 nbits, ngroups;
			if (!rz_buf_read_le32_offset(b, &offset, &nbits) ||
				!rz_buf_read_le32_offset(b, &offset, &ngroups)) {
				goto cleanup;
			}
			out->bitmap_info.nbits = nbits;
			out->bitmap_info.ngroups = ngroups;
			out->bitmap_info.nlevels = 0;
		}
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_bin_t_530(RzIO *io, ut64 addr, bin_t_530 *out,
	const RzJemallocConfig530 *config) {
	ut8 *buf = RZ_NEWS0(ut8, config->bin_size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, config->bin_size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_pointers(buf, config->bin_size, true);
	if (!b) {
		free(buf);
		return false;
	}
	ut64 offset = config->bin_offsets.slabcur;
	bool ret = false;
	if (config->ptr_size == 8) {
		if (!rz_buf_read_le64_offset(b, &offset, &out->slabcur)) {
			goto cleanup;
		}
	} else {
		ut32 val;
		if (!rz_buf_read_le32_offset(b, &offset, &val)) {
			goto cleanup;
		}
		out->slabcur = val;
	}
	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_t_530(RzIO *io, ut64 addr, arena_t_530 *out,
	const RzJemallocConfig530 *config) {
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

	// Read header fields sequentially
	if (!rz_buf_read_le32_offset(b, &offset, &out->nthreads[0]) ||
		!rz_buf_read_le32_offset(b, &offset, &out->nthreads[1]) ||
		!rz_buf_read_le32_offset(b, &offset, &out->binshard_next)) {
		goto cleanup;
	}

	const RzJemallocArenaOffsets530 *ao = &config->arena_offsets;

	if (config->ptr_size == 8) {
		if (((offset = ao->last_thd), !rz_buf_read_le64_offset(b, &offset, &out->last_thd)) ||
			((offset = ao->dss_prec), !rz_buf_read_le32_offset(b, &offset, &out->dss_prec)) ||
			((offset = ao->ind), !rz_buf_read_le32_offset(b, &offset, &out->ind)) ||
			((offset = ao->base), !rz_buf_read_le64_offset(b, &offset, &out->base)) ||
			!rz_buf_read_le64_offset(b, &offset, &out->create_time_ns)) {
			goto cleanup;
		}
	} else {
		ut32 val;
		if (((offset = ao->last_thd), !rz_buf_read_le32_offset(b, &offset, &val))) {
			goto cleanup;
		}
		out->last_thd = val;
		if (((offset = ao->dss_prec), !rz_buf_read_le32_offset(b, &offset, &out->dss_prec)) ||
			((offset = ao->ind), !rz_buf_read_le32_offset(b, &offset, &out->ind)) ||
			((offset = ao->base), !rz_buf_read_le32_offset(b, &offset, &val))) {
			goto cleanup;
		}
		out->base = val;
		if (!rz_buf_read_le64_offset(b, &offset, &out->create_time_ns)) {
			goto cleanup;
		}
	}

	out->stats_addr = addr + ao->stats;
	out->tcache_ql_addr = addr + ao->tcache_ql;
	out->cache_bin_array_descriptor_ql_addr = addr + ao->cache_bin_arr;
	out->tcache_ql_mtx_addr = addr + ao->tcache_ql_mtx;
	out->large_addr = addr + ao->large;
	out->large_mtx_addr = addr + ao->large_mtx;
	out->pa_shard_addr = addr + ao->pa_shard;
	out->bins_addr = addr + ao->bins;

	ret = true;
cleanup:
	rz_buf_free(b);
	return ret;
}

static inline ut64 rtree_leaf_elm_bits_edata_get_530(ut64 bits) {
	if (bits == 0) {
		return 0;
	}

	ut32 rtree_nhib = 16;

	/* pwndbg algorithm:
	 * ls = (val << RTREE_NHIB) & ((2**64) - 1)
	 * ptr = ((ls >> RTREE_NHIB) >> 1) << 1
	 * ptr = ptr & ~(EDATA_ALIGNMENT - 1)  // align to 128 bytes
	 */
	ut64 ls = bits << rtree_nhib;
	ut64 ptr = ((ls >> rtree_nhib) >> 1) << 1;
	ptr = ptr & ~((ut64)128 - 1);
	return ptr;
}

static inline void rtree_params_530(const RzJemallocConfig530 *config, ut32 *lg_page, ut32 *rtree_nsb,
	ut32 *bits_per_level, ut32 *max_subkeys, ut64 *root_offset) {
	*lg_page = config->lg_page;
	*rtree_nsb = config->rtree_nsb;
	*bits_per_level = config->rtree_bits_per_level;
	*max_subkeys = 1U << config->rtree_bits_per_level;
	*root_offset = config->rtree_offsets.root;
}

#endif // RZ_JEMALLOC_530_H
