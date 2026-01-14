// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JEMALLOC_530_H
#define RZ_JEMALLOC_530_H

#include <rz_util.h>
#include <rz_io.h>

#define EDATA_SIZE_64 128
#define EDATA_SIZE_32 108
#define EDATA_SIZE_MAX 128
#define BIN_INFO_SIZE_64 40
#define BIN_INFO_SIZE_32 48
#define BIN_INFO_SIZE_MAX 48
#define BIN_SIZE_64 224
#define BIN_SIZE_32 172
#define BIN_SIZE_MAX 224
#define ARENA_SIZE_64 78952
#define ARENA_SIZE_32 22004
#define ARENA_SIZE_MAX 78952
#define RTREE_NODE_ELM_SIZE_64 8
#define RTREE_NODE_ELM_SIZE_32 4
#define RTREE_NODE_ELM_SIZE_MAX 8
#define RTREE_LEAF_ELM_SIZE_64 8
#define RTREE_LEAF_ELM_SIZE_32 8
#define RTREE_LEAF_ELM_SIZE_MAX 8
#define PHN_LINK_SIZE_64 24
#define PHN_LINK_SIZE_32 12
#define PH_SIZE_64 16
#define PH_SIZE_32 8
#define NSTIME_SIZE_64 8
#define NSTIME_SIZE_32 8
#define BITMAP_INFO_SIZE_64 16
#define BITMAP_INFO_SIZE_32 32
#define RTREE_SIZE_64 2097272
#define RTREE_SIZE_32 4188
#define SC_NSIZES 235
#define SC_LG_SLAB_MAXREGS 9
#define MALLOC_MUTEX_SIZE_64 112
#define MALLOC_MUTEX_SIZE_32 88
#define BIN_STATS_SIZE_64 80
#define BIN_STATS_SIZE_32 68
#define MALLOCX_ARENA_BITS 12
#define EDATA_ALIGNMENT 128
#define LG_PAGE_530 12
#define JM_NBINS_530 36
#define ARENA_LAST_THD_OFFSET_64       16
#define ARENA_STATS_OFFSET_64          24
#define ARENA_TCACHE_QL_OFFSET_64      10392
#define ARENA_CACHE_BIN_ARR_OFFSET_64  10400
#define ARENA_TCACHE_QL_MTX_OFFSET_64  10408
#define ARENA_DSS_PREC_OFFSET_64       10520
#define ARENA_LARGE_OFFSET_64          10528
#define ARENA_LARGE_MTX_OFFSET_64      10536
#define ARENA_PA_SHARD_OFFSET_64       10648
#define ARENA_IND_OFFSET_64            78928
#define ARENA_BASE_OFFSET_64           78936
#define ARENA_CREATE_TIME_OFFSET_64    78944
#define ARENA_BINS_OFFSET_64           78952
#define ARENA_STATS_OFFSET_32          16
#define ARENA_TCACHE_QL_OFFSET_32      3960
#define ARENA_CACHE_BIN_ARR_OFFSET_32  3964
#define ARENA_TCACHE_QL_MTX_OFFSET_32  3968
#define ARENA_LARGE_OFFSET_32          4032
#define ARENA_LARGE_MTX_OFFSET_32      4036
#define ARENA_PA_SHARD_OFFSET_32       4040
#define ARENA_DSS_PREC_OFFSET_32       4056
#define ARENA_IND_OFFSET_32            21988
#define ARENA_BASE_OFFSET_32           21992
#define ARENA_CREATE_TIME_OFFSET_32    21996
#define ARENA_BINS_OFFSET_32           22004
#define BIN_SLABCUR_OFFSET_64          192
#define BIN_SLABCUR_OFFSET_32          156
#define RTREE_NSB_64                   36
#define RTREE_NSB_32                   20
#define RTREE_BITS_PER_LEVEL_64        18
#define RTREE_BITS_PER_LEVEL_32        10
#define RTREE_MAX_SUBKEYS_64           (1U << RTREE_BITS_PER_LEVEL_64)
#define RTREE_MAX_SUBKEYS_32           (1U << RTREE_BITS_PER_LEVEL_32)
#define RTREE_ROOT_OFFSET_64           120
#define RTREE_ROOT_OFFSET_32           92

#define MASK(CURRENT_FIELD_WIDTH, CURRENT_FIELD_SHIFT) ((((((ut64)0x1U) << (CURRENT_FIELD_WIDTH)) - 1)) << (CURRENT_FIELD_SHIFT))

#define EDATA_BITS_ARENA_WIDTH  MALLOCX_ARENA_BITS
#define EDATA_BITS_ARENA_SHIFT  0
#define EDATA_BITS_ARENA_MASK  MASK(EDATA_BITS_ARENA_WIDTH, EDATA_BITS_ARENA_SHIFT)

#define EDATA_BITS_SLAB_WIDTH  1
#define EDATA_BITS_SLAB_SHIFT  (EDATA_BITS_ARENA_WIDTH + EDATA_BITS_ARENA_SHIFT)
#define EDATA_BITS_SLAB_MASK  MASK(EDATA_BITS_SLAB_WIDTH, EDATA_BITS_SLAB_SHIFT)

#define EDATA_BITS_COMMITTED_WIDTH  1
#define EDATA_BITS_COMMITTED_SHIFT  (EDATA_BITS_SLAB_WIDTH + EDATA_BITS_SLAB_SHIFT)
#define EDATA_BITS_COMMITTED_MASK  MASK(EDATA_BITS_COMMITTED_WIDTH, EDATA_BITS_COMMITTED_SHIFT)

#define EDATA_BITS_PAI_WIDTH  1
#define EDATA_BITS_PAI_SHIFT  (EDATA_BITS_COMMITTED_WIDTH + EDATA_BITS_COMMITTED_SHIFT)
#define EDATA_BITS_PAI_MASK  MASK(EDATA_BITS_PAI_WIDTH, EDATA_BITS_PAI_SHIFT)

#define EDATA_BITS_ZEROED_WIDTH  1
#define EDATA_BITS_ZEROED_SHIFT  (EDATA_BITS_PAI_WIDTH + EDATA_BITS_PAI_SHIFT)
#define EDATA_BITS_ZEROED_MASK  MASK(EDATA_BITS_ZEROED_WIDTH, EDATA_BITS_ZEROED_SHIFT)

#define EDATA_BITS_GUARDED_WIDTH  1
#define EDATA_BITS_GUARDED_SHIFT  (EDATA_BITS_ZEROED_WIDTH + EDATA_BITS_ZEROED_SHIFT)
#define EDATA_BITS_GUARDED_MASK  MASK(EDATA_BITS_GUARDED_WIDTH, EDATA_BITS_GUARDED_SHIFT)

#define EDATA_BITS_STATE_WIDTH  3
#define EDATA_BITS_STATE_SHIFT  (EDATA_BITS_GUARDED_WIDTH + EDATA_BITS_GUARDED_SHIFT)
#define EDATA_BITS_STATE_MASK  MASK(EDATA_BITS_STATE_WIDTH, EDATA_BITS_STATE_SHIFT)

#define EDATA_BITS_SZIND_WIDTH  LG_CEIL(SC_NSIZES)
#define EDATA_BITS_SZIND_SHIFT  (EDATA_BITS_STATE_WIDTH + EDATA_BITS_STATE_SHIFT)
#define EDATA_BITS_SZIND_MASK  MASK(EDATA_BITS_SZIND_WIDTH, EDATA_BITS_SZIND_SHIFT)

#define EDATA_BITS_NFREE_WIDTH  (SC_LG_SLAB_MAXREGS + 1)
#define EDATA_BITS_NFREE_SHIFT  (EDATA_BITS_SZIND_WIDTH + EDATA_BITS_SZIND_SHIFT)
#define EDATA_BITS_NFREE_MASK  MASK(EDATA_BITS_NFREE_WIDTH, EDATA_BITS_NFREE_SHIFT)

#define EDATA_BITS_BINSHARD_WIDTH  6
#define EDATA_BITS_BINSHARD_SHIFT  (EDATA_BITS_NFREE_WIDTH + EDATA_BITS_NFREE_SHIFT)
#define EDATA_BITS_BINSHARD_MASK  MASK(EDATA_BITS_BINSHARD_WIDTH, EDATA_BITS_BINSHARD_SHIFT)

#define EDATA_BITS_IS_HEAD_WIDTH 1
#define EDATA_BITS_IS_HEAD_SHIFT  (EDATA_BITS_BINSHARD_WIDTH + EDATA_BITS_BINSHARD_SHIFT)
#define EDATA_BITS_IS_HEAD_MASK  MASK(EDATA_BITS_IS_HEAD_WIDTH, EDATA_BITS_IS_HEAD_SHIFT)

#define RTREE_LEAF_STATE_WIDTH EDATA_BITS_STATE_WIDTH
#define RTREE_LEAF_STATE_SHIFT 2
#define RTREE_LEAF_STATE_MASK MASK(RTREE_LEAF_STATE_WIDTH, RTREE_LEAF_STATE_SHIFT)


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
	ut64 le_bits;      // Used for 64-bit compact format 
	ut64 le_edata;     // Used for 32-bit non-compact format 
	ut64 le_metadata;  // Used for 32-bit non-compact format 
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
	ut64 e_size_esn;  // union: e_size_esn or e_bsize 
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
 * Unified bitmap_info structure
 * 64-bit: nbits(8) + ngroups(8) = 16 bytes (no BITMAP_USE_TREE)
 * 32-bit: nbits(4) + nlevels(4) + levels[6](24) = 32 bytes (BITMAP_USE_TREE)
 */
typedef struct bitmap_info_t_530 {
	ut64 nbits;
	// Non-tree format (64-bit) 
	ut64 ngroups;
	// Tree format (32-bit) 
	ut32 nlevels;
	ut64 levels[6];  // BITMAP_MAX_LEVELS + 1 
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

static inline size_t rtree_node_elm_size_530(bool is_64bit) {
	return is_64bit ? RTREE_NODE_ELM_SIZE_64 : RTREE_NODE_ELM_SIZE_32;
}

static inline size_t rtree_leaf_elm_size_530(bool is_64bit) {
	return is_64bit ? RTREE_LEAF_ELM_SIZE_64 : RTREE_LEAF_ELM_SIZE_32;
}

static inline size_t edata_size_530(bool is_64bit) {
	return is_64bit ? EDATA_SIZE_64 : EDATA_SIZE_32;
}

static inline size_t bin_info_size_530(bool is_64bit) {
	return is_64bit ? BIN_INFO_SIZE_64 : BIN_INFO_SIZE_32;
}

static inline size_t bin_size_530(bool is_64bit) {
	return is_64bit ? BIN_SIZE_64 : BIN_SIZE_32;
}

static inline size_t arena_size_530(bool is_64bit) {
	return is_64bit ? ARENA_SIZE_64 : ARENA_SIZE_32;
}

static inline ut64 bins_offset_530(bool is_64bit) {
	return is_64bit ? ARENA_BINS_OFFSET_64 : ARENA_BINS_OFFSET_32;
}

static inline bool read_and_parse_rtree_node_elm_t_530(RzIO *io, ut64 addr, rtree_node_elm_t_530 *out, bool is_64bit) {
	size_t size = rtree_node_elm_size_530(is_64bit);
	ut8 buf[RTREE_NODE_ELM_SIZE_MAX];
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, size);
	if (!b) {
		return false;
	}
	ut64 offset = 0;
	bool ret;
	if (is_64bit) {
		ret = rz_buf_read_le64_offset(b, &offset, &out->child);
	} else {
		ut32 val;
		ret = rz_buf_read_le32_offset(b, &offset, &val);
		if (ret) {
			out->child = val;
		}
	}
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_rtree_leaf_elm_t_530(RzIO *io, ut64 addr, rtree_leaf_elm_t_530 *out, bool is_64bit) {
	size_t size = rtree_leaf_elm_size_530(is_64bit);
	ut8 buf[RTREE_LEAF_ELM_SIZE_MAX];
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, size);
	if (!b) {
		return false;
	}
	ut64 offset = 0;
	bool ret;
	if (is_64bit) {
		// 64-bit uses compact format with le_bits
		out->le_edata = 0;
		out->le_metadata = 0;
		ret = rz_buf_read_le64_offset(b, &offset, &out->le_bits);
	} else {
		// 32-bit uses non-compact format
		ut32 edata, metadata;
		out->le_bits = 0;
		ret = rz_buf_read_le32_offset(b, &offset, &edata) &&
		      rz_buf_read_le32_offset(b, &offset, &metadata);
		if (ret) {
			out->le_edata = edata;
			out->le_metadata = metadata;
		}
	}
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_edata_t_530(RzIO *io, ut64 addr, edata_t_530 *out, bool is_64bit) {
	size_t size = edata_size_530(is_64bit);
	ut8 buf[EDATA_SIZE_MAX];
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, size);
	if (!b) {
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (!rz_buf_read_le64_offset(b, &offset, &out->e_bits)) {
		rz_buf_free(b);
		return ret;
	}
	if (is_64bit) {
		ret = rz_buf_read_le64_offset(b, &offset, &out->e_addr) &&
		      rz_buf_read_le64_offset(b, &offset, &out->e_size_esn) &&
		      rz_buf_read_le64_offset(b, &offset, &out->e_ps) &&
		      rz_buf_read_le64_offset(b, &offset, &out->e_sn);
	} else {
		ut32 e_addr, size_esn, ps;
		if (rz_buf_read_le32_offset(b, &offset, &e_addr) &&
		    rz_buf_read_le32_offset(b, &offset, &size_esn) &&
		    rz_buf_read_le32_offset(b, &offset, &ps)) {
			out->e_addr = e_addr;
			out->e_size_esn = size_esn;
			out->e_ps = ps;
			ret = rz_buf_read_le64_offset(b, &offset, &out->e_sn);
		}
	}
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_bin_info_t_530(RzIO *io, ut64 addr, bin_info_t_530 *out, bool is_64bit) {
	size_t size = bin_info_size_530(is_64bit);
	ut8 buf[BIN_INFO_SIZE_MAX];
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, size);
	if (!b) {
		return false;
	}
	ut64 offset = 0;
	bool ret = false;
	if (is_64bit) {
		if (rz_buf_read_le64_offset(b, &offset, &out->reg_size) &&
		    rz_buf_read_le64_offset(b, &offset, &out->slab_size) &&
		    rz_buf_read_le32_offset(b, &offset, &out->nregs) &&
		    rz_buf_read_le32_offset(b, &offset, &out->n_shards) &&
		    // bitmap_info: nbits (8) + ngroups (8) = 16 bytes on 64-bit
		    rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.nbits) &&
		    rz_buf_read_le64_offset(b, &offset, &out->bitmap_info.ngroups)) {
			out->bitmap_info.nlevels = 0;
			ret = true;
		}
	} else {
		ut32 reg_size, slab_size, nbits;
		if (rz_buf_read_le32_offset(b, &offset, &reg_size) &&
		    rz_buf_read_le32_offset(b, &offset, &slab_size) &&
		    rz_buf_read_le32_offset(b, &offset, &out->nregs) &&
		    rz_buf_read_le32_offset(b, &offset, &out->n_shards) &&
		    rz_buf_read_le32_offset(b, &offset, &nbits) &&
		    rz_buf_read_le32_offset(b, &offset, &out->bitmap_info.nlevels)) {
			out->reg_size = reg_size;
			out->slab_size = slab_size;
			out->bitmap_info.nbits = nbits;
			out->bitmap_info.ngroups = 0;
			ret = true;
			for (int i = 0; i < 6; i++) {
				ut32 level;
				if (!rz_buf_read_le32_offset(b, &offset, &level)) {
					ret = false;
					break;
				}
				out->bitmap_info.levels[i] = level;
			}
		}
	}
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_bin_t_530(RzIO *io, ut64 addr, bin_t_530 *out, bool is_64bit) {
	size_t size = bin_size_530(is_64bit);
	ut8 buf[BIN_SIZE_MAX];
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, size);
	if (!b) {
		return false;
	}
	ut64 offset;
	bool ret;
	if (is_64bit) {
		offset = BIN_SLABCUR_OFFSET_64;
		ret = rz_buf_read_le64_offset(b, &offset, &out->slabcur);
	} else {
		offset = BIN_SLABCUR_OFFSET_32;
		ut32 slabcur;
		ret = rz_buf_read_le32_offset(b, &offset, &slabcur);
		if (ret) {
			out->slabcur = slabcur;
		}
	}
	rz_buf_free(b);
	return ret;
}

static inline bool read_and_parse_arena_t_530(RzIO *io, ut64 addr, arena_t_530 *out, bool is_64bit) {
	size_t size = arena_size_530(is_64bit);
	ut8 *buf = malloc(size);
	if (!buf) {
		return false;
	}
	if (!rz_io_read_at_mapped(io, addr, buf, size)) {
		free(buf);
		return false;
	}
	RzBuffer *b = rz_buf_new_with_bytes(buf, size);
	free(buf);
	if (!b) {
		return false;
	}
	ut64 offset = 0;
	bool ret = false;

	if (!rz_buf_read_le32_offset(b, &offset, &out->nthreads[0]) ||
	    !rz_buf_read_le32_offset(b, &offset, &out->nthreads[1]) ||
	    !rz_buf_read_le32_offset(b, &offset, &out->binshard_next)) {
		rz_buf_free(b);
		return ret;
	}

	if (is_64bit) {
		offset = ARENA_LAST_THD_OFFSET_64;
		if (rz_buf_read_le64_offset(b, &offset, &out->last_thd)) {
			offset = ARENA_DSS_PREC_OFFSET_64;
			if (rz_buf_read_le32_offset(b, &offset, &out->dss_prec)) {
				offset = ARENA_IND_OFFSET_64;
				if (rz_buf_read_le32_offset(b, &offset, &out->ind)) {
					offset = ARENA_BASE_OFFSET_64;
					if (rz_buf_read_le64_offset(b, &offset, &out->base) &&
					    rz_buf_read_le64_offset(b, &offset, &out->create_time_ns)) {
						out->stats_addr = addr + ARENA_STATS_OFFSET_64;
						out->tcache_ql_addr = addr + ARENA_TCACHE_QL_OFFSET_64;
						out->cache_bin_array_descriptor_ql_addr = addr + ARENA_CACHE_BIN_ARR_OFFSET_64;
						out->tcache_ql_mtx_addr = addr + ARENA_TCACHE_QL_MTX_OFFSET_64;
						out->large_addr = addr + ARENA_LARGE_OFFSET_64;
						out->large_mtx_addr = addr + ARENA_LARGE_MTX_OFFSET_64;
						out->pa_shard_addr = addr + ARENA_PA_SHARD_OFFSET_64;
						out->bins_addr = addr + ARENA_BINS_OFFSET_64;
						ret = true;
					}
				}
			}
		}
	} else {
		ut32 last_thd;
		if (rz_buf_read_le32_offset(b, &offset, &last_thd)) {
			out->last_thd = last_thd;
			offset = ARENA_DSS_PREC_OFFSET_32;
			if (rz_buf_read_le32_offset(b, &offset, &out->dss_prec)) {
				offset = ARENA_IND_OFFSET_32;
				ut32 base;
				if (rz_buf_read_le32_offset(b, &offset, &out->ind) &&
				    rz_buf_read_le32_offset(b, &offset, &base)) {
					out->base = base;
					if (rz_buf_read_le64_offset(b, &offset, &out->create_time_ns)) {
						out->stats_addr = addr + ARENA_STATS_OFFSET_32;
						out->tcache_ql_addr = addr + ARENA_TCACHE_QL_OFFSET_32;
						out->cache_bin_array_descriptor_ql_addr = addr + ARENA_CACHE_BIN_ARR_OFFSET_32;
						out->tcache_ql_mtx_addr = addr + ARENA_TCACHE_QL_MTX_OFFSET_32;
						out->large_addr = addr + ARENA_LARGE_OFFSET_32;
						out->large_mtx_addr = addr + ARENA_LARGE_MTX_OFFSET_32;
						out->pa_shard_addr = addr + ARENA_PA_SHARD_OFFSET_32;
						out->bins_addr = addr + ARENA_BINS_OFFSET_32;
						ret = true;
					}
				}
			}
		}
	}

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

static inline void rtree_params_530(bool is_64bit, ut32 *lg_page, ut32 *rtree_nsb,
                                       ut32 *bits_per_level, ut32 *max_subkeys,
                                       ut64 *root_offset) {
	*lg_page = LG_PAGE_530;
	if (is_64bit) {
		*rtree_nsb = RTREE_NSB_64;
		*bits_per_level = RTREE_BITS_PER_LEVEL_64;
		*max_subkeys = RTREE_MAX_SUBKEYS_64;
		*root_offset = RTREE_ROOT_OFFSET_64;
	} else {
		*rtree_nsb = RTREE_NSB_32;
		*bits_per_level = RTREE_BITS_PER_LEVEL_32;
		*max_subkeys = RTREE_MAX_SUBKEYS_32;
		*root_offset = RTREE_ROOT_OFFSET_32;
	}
}

#endif // RZ_JEMALLOC_530_H 
