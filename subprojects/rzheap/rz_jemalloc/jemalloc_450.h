// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Minimal jemalloc struct definitions for heap parsing.
 * This file is included twice with different GH/GHT definitions.
 * Based on jemalloc 4.5.0 structure layouts.
 */

#ifndef GH
#error "GH macro must be defined before including this file"
#endif
#ifndef GHT
#error "GHT macro must be defined before including this file"
#endif

/* Constants - only define once */
#ifndef JM_NBINS
#define JM_NBINS 36
#define NPSIZES_64 199
#define NPSIZES_32 71
#define SMOOTHSTEP_NSTEPS 200
#define BITMAP_MAX_LEVELS 5
#endif


/* Alignment macro - ut64 only has 4-byte alignment on 32-bit hosts,
 * so we need explicit alignment for 64-bit structs.
 */
#undef GH_ALIGN
#ifdef GH_IS_64
#define GH_ALIGN RZ_ALIGNED(8)
#else
#define GH_ALIGN RZ_ALIGNED(4)
#endif

/* Queue/list helper macros - pointers become GHT */
#define RZ_JM_QL_HEAD(a_type) struct GH_ALIGN { GHT qlh_first; }
#define RZ_JM_QR(a_type)      struct GH_ALIGN { GHT qre_next; GHT qre_prev; }
#define RZ_JM_RB_TREE(a_type) struct GH_ALIGN { GHT rbt_root; }
#define RZ_JM_PH(a_type)      struct GH_ALIGN { GHT ph_root; }
#define RZ_JM_QL_ELM(a_type)  RZ_JM_QR(a_type)
#define RZ_JM_RB_NODE(a_type) struct GH_ALIGN { GHT rbn_left; GHT rbn_right; }

/* only define once */
#ifndef RZ_JM_DEFINE_ONLY_ONCE_450
#define RZ_JM_DEFINE_ONLY_ONCE_450
typedef enum {
	dss_prec_disabled  = 0,
	dss_prec_primary   = 1,
	dss_prec_secondary = 2,
	dss_prec_limit     = 3
} dss_prec_t;

/* Opaque types - internal layout doesn't matter, only size and alignment
 * 32-bit types: 4-byte alignment (contains ut32 pointers)
 * 64-bit types: 8-byte alignment (contains ut64 pointers)
 * Note: We use __attribute__((aligned(N))) because ut64 only has 4-byte
 * alignment on 32-bit hosts, so we can't rely on natural alignment.
 */
typedef struct RZ_ALIGNED(4) { ut8 data[44]; } malloc_mutex_t_450_32;
typedef struct RZ_ALIGNED(8) { ut8 data[80]; } malloc_mutex_t_450_64;
typedef struct RZ_ALIGNED(4) { ut8 data[8]; } nstime_t_450_32;
typedef struct RZ_ALIGNED(8) { ut8 data[8]; } nstime_t_450_64;
typedef struct RZ_ALIGNED(4) { ut8 data[112]; } prof_tctx_t_450_32;
typedef struct RZ_ALIGNED(8) { ut8 data[128]; } prof_tctx_t_450_64;
typedef struct RZ_ALIGNED(4) { ut8 data[96]; } arena_stats_t_450_32;
typedef struct RZ_ALIGNED(8) { ut8 data[128]; } arena_stats_t_450_64;
typedef struct RZ_ALIGNED(4) { ut8 data[116]; } arena_bin_t_450_32;
typedef struct RZ_ALIGNED(8) { ut8 data[168]; } arena_bin_t_450_64;
#endif

typedef struct GH(arena_runs_dirty_link_s_450) GH(arena_runs_dirty_link_t_450);
typedef struct GH(arena_bin_info_s_450) GH(arena_bin_info_t_450);
typedef struct GH(arena_decay_s_450) GH(arena_decay_t_450);
typedef struct GH(arena_s_450) GH(arena_t_450);
typedef struct GH(extent_node_s_450) GH(extent_node_t_450);
typedef RZ_JM_RB_TREE(extent_node_t_450) GH(extent_tree_t_450);
typedef struct GH(bitmap_info_s_450) GH(bitmap_info_t_450);
typedef struct GH(bitmap_level_s_450) GH(bitmap_level_t_450);

#undef arena_t_450
#undef extent_node_t_450
#undef arena_bin_info_t_450
#define arena_t_450 GH(arena_t_450)
#define extent_node_t_450 GH(extent_node_t_450)
#define arena_bin_info_t_450 GH(arena_bin_info_t_450)

/* chunk_hooks_t 
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/jemalloc_typedefs.h.in
 */
typedef struct GH_ALIGN {
	GHT alloc;
	GHT dalloc;
	GHT commit;
	GHT decommit;
	GHT purge;
	GHT split;
	GHT merge;
} GH(chunk_hooks_t_450);


/* arena_runs_dirty_link_t_450
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
struct GH_ALIGN GH(arena_runs_dirty_link_s_450) {
	RZ_JM_QR(void) rd_link;
};

/* extent_node_t_450 - chunk/extent tracking
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/extent.h
 */
struct GH_ALIGN GH(extent_node_s_450) {
	GHT en_arena;
	GHT en_addr;
	GHT en_size;
	GHT en_sn;
	bool en_zeroed;
	bool en_committed;
	bool en_achunk;
	GHT en_prof_tctx;
	GH(arena_runs_dirty_link_t_450)	rd;
	RZ_JM_QR(GH(extent_node_t_450))	cc_link;
	union {
		RZ_JM_RB_NODE(GH(extent_node_t_450))	szsnad_link;
		RZ_JM_QL_ELM(GH(extent_node_t_450))	ql_link;
	};
	RZ_JM_RB_NODE(GH(extent_node_t_450))	ad_link;
};


/* arena_decay_t_450
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
struct GH_ALIGN GH(arena_decay_s_450) {
	GHST time;
	GH(nstime_t_450) interval;
	GH(nstime_t_450) epoch;
	ut64 jitter_state;
	GH(nstime_t_450) deadline;
	GHT ndirty;
	GHT backlog[SMOOTHSTEP_NSTEPS];
};


/* arena_run_heap_t_450 - pairing heap of runs
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
typedef RZ_JM_PH(void) GH(arena_run_heap_t_450);


/* arena_t_450 - main arena structure
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
struct GH_ALIGN GH(arena_s_450) {
	unsigned ind;
	unsigned nthreads[2];
	GH(malloc_mutex_t_450) lock;
	GH(arena_stats_t_450) stats;
	RZ_JM_QL_HEAD(void) tcache_ql;
	ut64 prof_accumbytes;
	GHT offset_state;
	dss_prec_t dss_prec;
	RZ_JM_QL_HEAD(GH(extent_node_t_450)) achunks;
	GHT extent_sn_next;
	GHT spare;
	GHST lg_dirty_mult;
	bool purging;
	GHT nactive;
	GHT ndirty;
	GH(arena_runs_dirty_link_t_450) runs_dirty;
	GH(extent_node_t_450) chunks_cache;
	GH(arena_decay_t_450) decay;
	RZ_JM_QL_HEAD(GH(extent_node_t_450)) huge;
	GH(malloc_mutex_t_450) huge_mtx;
	GH(extent_tree_t_450) chunks_szsnad_cached;
	GH(extent_tree_t_450) chunks_ad_cached;
	GH(extent_tree_t_450) chunks_szsnad_retained;
	GH(extent_tree_t_450) chunks_ad_retained;
	GH(malloc_mutex_t_450) chunks_mtx;
	RZ_JM_QL_HEAD(GH(extent_node_t_450)) node_cache;
	GH(malloc_mutex_t_450) node_cache_mtx;
	GH(chunk_hooks_t_450) chunk_hooks;
	GH(arena_bin_t_450) bins[JM_NBINS];
	GH(arena_run_heap_t_450) runs_avail[GH(NPSIZES)];
};


/* bitmap_level_t_450
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/bitmap.h
 */
struct GH_ALIGN GH(bitmap_level_s_450) {
	GHT group_offset;
};

/* bitmap_info_t_450
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/bitmap.h
 */
#ifndef GH_IS_64
/* 32-bit uses USE_TREE */
struct GH_ALIGN GH(bitmap_info_s_450) {
	GHT nbits;
	unsigned nlevels;
	GH(bitmap_level_t_450) levels[BITMAP_MAX_LEVELS+1];
};
#else
/* 64-bit does not use USE_TREE */
struct GH_ALIGN GH(bitmap_info_s_450) {
	GHT nbits;
	GHT ngroups;
};
#endif

/* arena_bin_info_t_450
 * source: https://github.com/jemalloc/jemalloc/blob/4.5.0/include/jemalloc/internal/arena.h
 */
struct GH_ALIGN GH(arena_bin_info_s_450) {
	GHT reg_size;
	GHT redzone_size;
	GHT reg_interval;
	GHT run_size;
	ut32 nregs;
	GH(bitmap_info_t_450)		bitmap_info;
	ut32 reg0_offset;
};



