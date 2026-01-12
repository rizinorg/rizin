// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef GH
#error "GH macro must be defined before including this file"
#endif
#ifndef GHT
#error "GHT macro must be defined before including this file"
#endif

#undef GH_ALIGN
#undef GH_PACKED
#ifdef GH_IS_64
/* 64-bit: use natural alignment (jemalloc is not packed on 64-bit) */
#define GH_ALIGN RZ_ALIGNED(8)
#define GH_PACKED(decl) decl
#else
#define GH_ALIGN RZ_ALIGNED(4)
#define GH_PACKED(decl) RZ_PACKED(decl)
#endif


#undef LG_VADDR
#undef LG_PAGE
#undef RTREE_NLIB
#undef RTREE_NSB
#undef RTREE_HEIGHT
#undef RTREE_LEAF_COMPACT
#undef MALLOCX_ARENA_BITS
#undef LG_SIZEOF_PTR
#undef RTREE_NHIB
#undef BITMAP_USE_TREE
#undef BITMAP_MAX_LEVELS
#ifdef GH_IS_64
#define LG_VADDR 48
#define LG_PAGE 12
#define RTREE_NLIB LG_PAGE
#define RTREE_NSB (LG_VADDR - RTREE_NLIB)
#define RTREE_HEIGHT 2
#define RTREE_LEAF_COMPACT
#define LG_SIZEOF_PTR 3
#define RTREE_NHIB ((1U << (LG_SIZEOF_PTR+3)) - LG_VADDR)
#undef BITMAP_USE_TREE
#define BITMAP_MAX_LEVELS 5
#else
#define LG_VADDR 32
#define LG_PAGE 12
#define RTREE_NLIB LG_PAGE
#define RTREE_NSB (LG_VADDR - RTREE_NLIB)
#define RTREE_HEIGHT 2
#undef RTREE_LEAF_COMPACT
#define MALLOCX_ARENA_BITS 12
#define LG_SIZEOF_PTR 2
#define RTREE_NHIB ((1U << (LG_SIZEOF_PTR+3)) - LG_VADDR)
#define BITMAP_USE_TREE
#define BITMAP_MAX_LEVELS 5
#endif


typedef struct GH(phn_link_s_530) GH(phn_link_t_530);
typedef struct GH(ph_s_530) GH(ph_t_530);


/* only define once */
#ifndef RZ_JM_DEFINE_ONLY_ONCE_530
#define RZ_JM_DEFINE_ONLY_ONCE_530

#define RZ_JM_QL_HEAD(a_type) GH_PACKED(struct GH_ALIGN { GHT qlh_first; })
#define RZ_JM_QR(a_type)      GH_PACKED(struct GH_ALIGN { GHT qre_next; GHT qre_prev; })
#define RZ_JM_RB_TREE(a_type) GH_PACKED(struct GH_ALIGN { GHT rbt_root; })
#define RZ_JM_PH(a_type)      GH_PACKED(struct GH_ALIGN { GHT ph_root; })
#define RZ_JM_QL_ELM(a_type)  RZ_JM_QR(a_type)
#define RZ_JM_RB_NODE(a_type) GH_PACKED(struct GH_ALIGN { GHT rbn_left; GHT rbn_right; })

#define RZ_JM_PH_STRUCTS(a_prefix, a_type) \
typedef GH_PACKED(struct GH_ALIGN { \
	GH(phn_link_t_530) link; \
}) GH(a_prefix##_link_t_530); \
                          \
typedef GH_PACKED(struct GH_ALIGN { \
	GH(ph_t_530) ph; \
}) GH(a_prefix##_t_530);

#define RZ_JM_TYPED_LIST(list_type, el_type, linkage) \
typedef GH_PACKED(struct GH_ALIGN { \
	RZ_JM_QL_HEAD(el_type) head; \
}) GH(list_type##_t_530); \

/* Opaque types - internal layout doesn't matter, only size and alignment */
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[88]; } malloc_mutex_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[112]; } malloc_mutex_t_530_64);
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[68]; } slab_data_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[64]; } slab_data_t_530_64);
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[20]; } e_prof_info_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[32]; } e_prof_info_t_530_64);
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[68]; } bin_stats_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[80]; } bin_stats_t_530_64);
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[3944]; } arena_stats_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[10368]; } arena_stats_t_530_64);
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[17836]; } pa_shard_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[68280]; } pa_shard_t_530_64);
GH_PACKED(typedef struct RZ_ALIGNED(4) { ut8 data[2064]; } tsdn_t_530_32);
GH_PACKED(typedef struct RZ_ALIGNED(8) { ut8 data[2632]; } tsdn_t_530_64);

#define MALLOCX_ARENA_BITS 12
#define EDATA_ALIGNMENT 128

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

#endif

RZ_JM_TYPED_LIST(edata_list_active, GH(edata_t_530), ql_link_active)

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/ph.h
 * 64 bit size is 24 bytes
 * 32 bit size is 12 bytes
 */
GH_PACKED(struct GH_ALIGN GH(phn_link_s_530) {
	GHT prev;
	GHT next;
	GHT lchild;
});

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/ph.h
 * 64 bit size is 16 bytes
 * 32 bit size is 8 bytes
 */
GH_PACKED(struct GH_ALIGN GH(ph_s_530) {
	GHT root;
	GHT auxcount;
});

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/rtree.h
 * 64 bit size is 8 bytes
 * 32 bit size is 8 bytes
 */
typedef struct GH(rtree_leaf_elm_s_530) GH(rtree_leaf_elm_t_530);
GH_PACKED(struct GH_ALIGN GH(rtree_leaf_elm_s_530) {
#ifdef RTREE_LEAF_COMPACT
    GHT	le_bits;
#else
    GHT	le_edata;
    GHT	le_metadata;
#endif
});

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/rtree.h
 * 64 bit size is 8 bytes
 * 32 bit size is 4 bytes
 */
typedef struct GH(rtree_node_elm_s_530) GH(rtree_node_elm_t_530);
GH_PACKED(struct GH_ALIGN GH(rtree_node_elm_s_530) {
    GHT	child;
});

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/rtree.h
 * 64 bit size is 2097272 bytes
 * 32 bit size is 4188 bytes 
 */
typedef struct GH(rtree_s_530) GH(rtree_t_530);
GH_PACKED(struct GH_ALIGN GH(rtree_s_530) {
	GHT base;
	GH(malloc_mutex_t_530)		init_lock;
	/* Number of elements based on rtree_levels[0].bits. */
	GH(rtree_node_elm_t_530) root[1U << (RTREE_NSB/RTREE_HEIGHT)];
});


/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/edata.h
 * 64 bit size is 128 bytes
 * 32 bit size is 108 bytes
 */
typedef struct GH(edata_s_530) GH(edata_t_530);
RZ_JM_PH_STRUCTS(edata_avail, GH(edata_t_530));
RZ_JM_PH_STRUCTS(edata_heap, GH(edata_t_530));
GH_PACKED(struct GH_ALIGN GH(edata_s_530) {
	ut64 e_bits;
	GHT e_addr;
	union {
		GHT			e_size_esn;
	// #define edata_s_530IZE_MASK ((GHT)~(PAGE-1))
	// #define EDATA_ESN_MASK ((GHT)PAGE-1)
		GHT			e_bsize;
	};
	GHT e_ps;
	ut64 e_sn;

	union {
		RZ_JM_QL_ELM(GH(edata_t_530))	ql_link_active;
		union {
			GH(edata_heap_link_t_530) heap_link;
			GH(edata_avail_link_t_530) avail_link;
		};
	};

	union {
		RZ_JM_QL_ELM(GH(edata_t_530)) ql_link_inactive;
		GH(slab_data_t_530) e_slab_data;
		GH(e_prof_info_t_530) e_prof_info;
	};
});


/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin.h
 * 64 bit size is 8 bytes 
 * 32 bit size is 8 bytes
 */
GH_PACKED(typedef struct GH_ALIGN {
	ut64 ns;
} GH(nstime_t_530));


RZ_JM_PH_STRUCTS(edata_heap_530, GH(edata_t_530));


/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bitmap.h
 * 64 bit size is 16 bytes
 * 32 bit size is 32 bytes
 */
typedef GH_PACKED(struct GH_ALIGN GH(bitmap_info_s_530) {
	GHT nbits;
#ifdef BITMAP_USE_TREE
	ut32 nlevels;
	// GH(bitmap_level_t_530) levels[BITMAP_MAX_LEVELS+1];
	GHT levels[BITMAP_MAX_LEVELS+1];
#else
	GHT ngroups;
#endif
}) GH(bitmap_info_t_530);

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin.h
 * 64 bit size is 40 bytes
 * 32 bit size is 48 bytes
 */
typedef GH_PACKED(struct GH_ALIGN GH(bin_info_s_530) {
	GHT reg_size;
	GHT slab_size;
	ut32 nregs;
	ut32 n_shards;
	GH(bitmap_info_t_530) bitmap_info;
}) GH(bin_info_t_530);

#define JM_NBINS_530 36

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/bin.h
 * 64 bit size is 224 bytes
 * 32 bit size is 172 bytes
 */
typedef struct GH(bin_s_530) GH(bin_t_530);
GH_PACKED(struct GH_ALIGN GH(bin_s_530) {
	GH(malloc_mutex_t_530) lock;
	GH(bin_stats_t_530) stats;
	GHT slabcur;
	GH(edata_heap_t_530) slabs_nonfull;
	GH(edata_list_active_t_530) slabs_full;
});

/*
 * source: https://github.com/jemalloc/jemalloc/blob/5.3.0/include/jemalloc/internal/arena_structs.h
 * 64 bit size is 78952 bytes 
 * 32 bit size is 22004 bytes
 */
typedef struct GH(arena_s_530) GH(arena_t_530);
GH_PACKED(struct GH_ALIGN GH(arena_s_530) {
	ut32 nthreads[2];
	ut32 binshard_next;
	GHT last_thd;  /* pointer - use GHT for correct size on cross-arch */
	GH(arena_stats_t_530) stats;
	RZ_JM_QL_HEAD(tcache_slow_t) tcache_ql;
	RZ_JM_QL_HEAD(cache_bin_array_descriptor_t) cache_bin_array_descriptor_ql;
	GH(malloc_mutex_t_530) tcache_ql_mtx;
	ut32 dss_prec;
	GH(edata_list_active_t_530) large;
	GH(malloc_mutex_t_530) large_mtx;
	GH(pa_shard_t_530) pa_shard;
	ut32 ind;
	GHT base;
	/* Used to determine uptime.  Read-only after initialization. */
	GH(nstime_t_530) create_time;
	GH(bin_t_530) bins[0];
});

