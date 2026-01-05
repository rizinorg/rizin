// SPDX-FileCopyrightText: 2025 bubblepipe <bubblepipe42@gmail.com>
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
#ifdef GH_IS_64
#define GH_ALIGN __attribute__((aligned(8)))
#else
#define GH_ALIGN __attribute__((aligned(4)))
#endif

/* Queue/list helper macros - pointers become GHT */
#define RZ_JM_QL_HEAD(a_type) struct GH_ALIGN { GHT qlh_first; }
#define RZ_JM_QR(a_type)      struct GH_ALIGN { GHT qre_next; GHT qre_prev; }
#define RZ_JM_RB_TREE(a_type) struct GH_ALIGN { GHT rbt_root; }
#define RZ_JM_PH(a_type)      struct GH_ALIGN { GHT ph_root; }
#define RZ_JM_QL_ELM(a_type)  RZ_JM_QR(a_type)
#define RZ_JM_RB_NODE(a_type) struct GH_ALIGN { GHT rbn_left; GHT rbn_right; }

/* DSS precedence enum - only define once */
#ifndef RZ_JM_DEFINE_ONLY_ONCE
#define RZ_JM_DEFINE_ONLY_ONCE
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
typedef struct __attribute__((aligned(4))) { ut8 data[44]; } malloc_mutex_t_32;
typedef struct __attribute__((aligned(8))) { ut8 data[80]; } malloc_mutex_t_64;
typedef struct __attribute__((aligned(4))) { ut8 data[8]; } nstime_t_32;
typedef struct __attribute__((aligned(8))) { ut8 data[8]; } nstime_t_64;
typedef struct __attribute__((aligned(4))) { ut8 data[112]; } prof_tctx_t_32;
typedef struct __attribute__((aligned(8))) { ut8 data[128]; } prof_tctx_t_64;
typedef struct __attribute__((aligned(4))) { ut8 data[96]; } arena_stats_t_32;
typedef struct __attribute__((aligned(8))) { ut8 data[128]; } arena_stats_t_64;
typedef struct __attribute__((aligned(4))) { ut8 data[116]; } arena_bin_t_32;
typedef struct __attribute__((aligned(8))) { ut8 data[168]; } arena_bin_t_64;
#endif

typedef struct GH(arena_runs_dirty_link_s) GH(arena_runs_dirty_link_t);
typedef struct GH(arena_bin_info_s) GH(arena_bin_info_t);
typedef struct GH(arena_decay_s) GH(arena_decay_t);
typedef struct GH(arena_s) GH(arena_t);
typedef struct GH(extent_node_s) GH(extent_node_t);
typedef RZ_JM_RB_TREE(extent_node_t) GH(extent_tree_t);
typedef struct GH(bitmap_info_s) GH(bitmap_info_t);
typedef struct GH(bitmap_level_s) GH(bitmap_level_t);

#undef arena_t
#undef extent_node_t
#undef arena_stats_t
#undef arena_bin_info_t
#define arena_t GH(arena_t)
#define extent_node_t GH(extent_node_t)
#define arena_stats_t GH(arena_stats_t)
#define arena_bin_info_t GH(arena_bin_info_t)

/* chunk_hooks_t */
typedef struct GH_ALIGN {
	GHT alloc;
	GHT dalloc;
	GHT commit;
	GHT decommit;
	GHT purge;
	GHT split;
	GHT merge;
} GH(chunk_hooks_t);


/* arena_runs_dirty_link_t */
struct GH_ALIGN GH(arena_runs_dirty_link_s) {
	RZ_JM_QR(void) rd_link;
};

/* extent_node_t - chunk/extent tracking */
struct GH_ALIGN GH(extent_node_s) {
	GHT en_arena;
	GHT en_addr;
	GHT en_size;
	GHT en_sn;
	bool en_zeroed;
	bool en_committed;
	bool en_achunk;
	GHT en_prof_tctx;
	GH(arena_runs_dirty_link_t)	rd;
	RZ_JM_QR(GH(extent_node_t))	cc_link;
	union {
		RZ_JM_RB_NODE(GH(extent_node_t))	szsnad_link;
		RZ_JM_QL_ELM(GH(extent_node_t))	ql_link;
	};
	RZ_JM_RB_NODE(GH(extent_node_t))	ad_link;
};


/* arena_decay_t */
struct GH_ALIGN GH(arena_decay_s) {
	GHST time;
	GH(nstime_t) interval;
	GH(nstime_t) epoch;
	ut64 jitter_state;
	GH(nstime_t) deadline;
	GHT ndirty;
	GHT backlog[SMOOTHSTEP_NSTEPS];
};


/* arena_run_heap_t - pairing heap of runs */
typedef RZ_JM_PH(void) GH(arena_run_heap_t);


/* arena_t - main arena structure */
struct GH_ALIGN GH(arena_s) {
	unsigned ind;
	unsigned nthreads[2];
	GH(malloc_mutex_t) lock;
	GH(arena_stats_t) stats;
	RZ_JM_QL_HEAD(void) tcache_ql;
	ut64 prof_accumbytes;
	GHT offset_state;
	dss_prec_t dss_prec;
	RZ_JM_QL_HEAD(GH(extent_node_t)) achunks;
	GHT extent_sn_next;
	GHT spare;
	GHST lg_dirty_mult;
	bool purging;
	GHT nactive;
	GHT ndirty;
	GH(arena_runs_dirty_link_t) runs_dirty;
	GH(extent_node_t) chunks_cache;
	GH(arena_decay_t) decay;
	RZ_JM_QL_HEAD(GH(extent_node_t)) huge;
	GH(malloc_mutex_t) huge_mtx;
	GH(extent_tree_t) chunks_szsnad_cached;
	GH(extent_tree_t) chunks_ad_cached;
	GH(extent_tree_t) chunks_szsnad_retained;
	GH(extent_tree_t) chunks_ad_retained;
	GH(malloc_mutex_t) chunks_mtx;
	RZ_JM_QL_HEAD(GH(extent_node_t)) node_cache;
	GH(malloc_mutex_t) node_cache_mtx;
	GH(chunk_hooks_t) chunk_hooks;
	GH(arena_bin_t) bins[JM_NBINS];
	GH(arena_run_heap_t) runs_avail[GH(NPSIZES)];
};


struct GH_ALIGN GH(bitmap_level_s) {
	GHT group_offset;
};

#ifndef GH_IS_64
/* 32-bit uses USE_TREE */
struct GH_ALIGN GH(bitmap_info_s) {
	GHT nbits;
	unsigned nlevels;
	GH(bitmap_level_t) levels[BITMAP_MAX_LEVELS+1];
};
#else
/* 64-bit does not use USE_TREE */
struct GH_ALIGN GH(bitmap_info_s) {
	GHT nbits;
	GHT ngroups;
};
#endif

/* arena_bin_info_t - bin configuration */
struct GH_ALIGN GH(arena_bin_info_s) {
	GHT reg_size;
	GHT redzone_size;
	GHT reg_interval;
	GHT run_size;
	ut32 nregs;
	GH(bitmap_info_t)		bitmap_info;
	ut32 reg0_offset;
};



