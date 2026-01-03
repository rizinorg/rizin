/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

#define	LARGE_MINCLASS		(ZU(1) << LG_LARGE_MINCLASS)

/* Maximum number of regions in one run. */
#define	LG_RUN_MAXREGS		(LG_PAGE - LG_TINY_MIN)
#define	RUN_MAXREGS		(1U << LG_RUN_MAXREGS)

/*
 * Minimum redzone size.  Redzones may be larger than this if necessary to
 * preserve region alignment.
 */
#define	REDZONE_MINSIZE		16

/*
 * The minimum ratio of active:dirty pages per arena is computed as:
 *
 *   (nactive >> lg_dirty_mult) >= ndirty
 *
 * So, supposing that lg_dirty_mult is 3, there can be no less than 8 times as
 * many active pages as dirty pages.
 */
#define	LG_DIRTY_MULT_DEFAULT	3

typedef enum {
	purge_mode_ratio = 0,
	purge_mode_decay = 1,

	purge_mode_limit = 2
} purge_mode_t;
#define	PURGE_DEFAULT		purge_mode_ratio
/* Default decay time in seconds. */
#define	DECAY_TIME_DEFAULT	10
/* Number of event ticks between time checks. */
#define	DECAY_NTICKS_PER_UPDATE	1000

typedef struct GH(arena_runs_dirty_link_s) GH(arena_runs_dirty_link_t);
typedef struct GH(arena_avail_links_s) GH(arena_avail_links_t);
typedef struct GH(arena_run_s) GH(arena_run_t);
typedef struct GH(arena_chunk_map_bits_s) GH(arena_chunk_map_bits_t);
typedef struct GH(arena_chunk_map_misc_s) GH(arena_chunk_map_misc_t);
typedef struct GH(arena_chunk_s) GH(arena_chunk_t);
typedef struct GH(arena_bin_info_s) GH(arena_bin_info_t);
typedef struct GH(arena_decay_s) GH(arena_decay_t);
typedef struct GH(arena_bin_s) GH(arena_bin_t);
typedef struct GH(arena_s) GH(arena_t);
typedef struct GH(arena_tdata_s) GH(arena_tdata_t);

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

#ifdef JEMALLOC_ARENA_STRUCTS_A
struct GH(arena_run_s) {
	/* Index of bin this run is associated with. */
	szind_t		binind;

	/* Number of free regions in run. */
	unsigned	nfree;

	/* Per region allocated/deallocated bitmap. */
	bitmap_t	bitmap[BITMAP_GROUPS_MAX];
};

/* Each element of the chunk map corresponds to one page within the chunk. */
struct GH(arena_chunk_map_bits_s) {
	/*
	 * Run address (or size) and various flags are stored together.  The bit
	 * layout looks like (assuming 32-bit system):
	 *
	 *   ???????? ???????? ???nnnnn nnndumla
	 *
	 * ? : Unallocated: Run address for first/last pages, unset for internal
	 *                  pages.
	 *     Small: Run page offset.
	 *     Large: Run page count for first page, unset for trailing pages.
	 * n : binind for small size class, BININD_INVALID for large size class.
	 * d : dirty?
	 * u : unzeroed?
	 * m : decommitted?
	 * l : large?
	 * a : allocated?
	 *
	 * Following are example bit patterns for the three types of runs.
	 *
	 * p : run page offset
	 * s : run size
	 * n : binind for size class; large objects set these to BININD_INVALID
	 * x : don't care
	 * - : 0
	 * + : 1
	 * [DUMLA] : bit set
	 * [dumla] : bit unset
	 *
	 *   Unallocated (clean):
	 *     ssssssss ssssssss sss+++++ +++dum-a
	 *     xxxxxxxx xxxxxxxx xxxxxxxx xxx-Uxxx
	 *     ssssssss ssssssss sss+++++ +++dUm-a
	 *
	 *   Unallocated (dirty):
	 *     ssssssss ssssssss sss+++++ +++D-m-a
	 *     xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
	 *     ssssssss ssssssss sss+++++ +++D-m-a
	 *
	 *   Small:
	 *     pppppppp pppppppp pppnnnnn nnnd---A
	 *     pppppppp pppppppp pppnnnnn nnn----A
	 *     pppppppp pppppppp pppnnnnn nnnd---A
	 *
	 *   Large:
	 *     ssssssss ssssssss sss+++++ +++D--LA
	 *     xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
	 *     -------- -------- ---+++++ +++D--LA
	 *
	 *   Large (sampled, size <= LARGE_MINCLASS):
	 *     ssssssss ssssssss sssnnnnn nnnD--LA
	 *     xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
	 *     -------- -------- ---+++++ +++D--LA
	 *
	 *   Large (not sampled, size == LARGE_MINCLASS):
	 *     ssssssss ssssssss sss+++++ +++D--LA
	 *     xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
	 *     -------- -------- ---+++++ +++D--LA
	 */
	GHT				bits;
#define	CHUNK_MAP_ALLOCATED	((GHT)0x01U)
#define	CHUNK_MAP_LARGE		((GHT)0x02U)
#define	CHUNK_MAP_STATE_MASK	((GHT)0x3U)

#define	CHUNK_MAP_DECOMMITTED	((GHT)0x04U)
#define	CHUNK_MAP_UNZEROED	((GHT)0x08U)
#define	CHUNK_MAP_DIRTY		((GHT)0x10U)
#define	CHUNK_MAP_FLAGS_MASK	((GHT)0x1cU)

#define	CHUNK_MAP_BININD_SHIFT	5
#define	BININD_INVALID		((GHT)0xffU)
#define	CHUNK_MAP_BININD_MASK	(BININD_INVALID << CHUNK_MAP_BININD_SHIFT)
#define	CHUNK_MAP_BININD_INVALID CHUNK_MAP_BININD_MASK

#define	CHUNK_MAP_RUNIND_SHIFT	(CHUNK_MAP_BININD_SHIFT + 8)
#define	CHUNK_MAP_SIZE_SHIFT	(CHUNK_MAP_RUNIND_SHIFT - LG_PAGE)
#define	CHUNK_MAP_SIZE_MASK						\
    (~(CHUNK_MAP_BININD_MASK | CHUNK_MAP_FLAGS_MASK | CHUNK_MAP_STATE_MASK))
};

struct GH(arena_runs_dirty_link_s) {
	qr(GH(arena_runs_dirty_link_t))	rd_link;
};

/*
 * Each GH(arena_chunk_map_misc_t) corresponds to one page within the chunk, just
 * like GH(arena_chunk_map_bits_t).  Two separate arrays are stored within each
 * chunk header in order to improve cache locality.
 */
struct GH(arena_chunk_map_misc_s) {
	/*
	 * Linkage for run heaps.  There are two disjoint uses:
	 *
	 * 1) GH(arena_t)'s runs_avail heaps.
	 * 2) GH(arena_run_t) conceptually uses this linkage for in-use non-full
	 *    runs, rather than directly embedding linkage.
	 */
	phn(GH(arena_chunk_map_misc_t))		ph_link;

	union {
		/* Linkage for list of dirty runs. */
		GH(arena_runs_dirty_link_t)		rd;

		/* Profile counters, used for large object runs. */
		union {
			void			*prof_tctx_pun;
			GH(prof_tctx_t)		*prof_tctx;
		};

		/* Small region run metadata. */
		GH(arena_run_t)			run;
	};
};
typedef ph(GH(arena_chunk_map_misc_t)) arena_run_heap_t;
#endif /* JEMALLOC_ARENA_STRUCTS_A */

#ifdef JEMALLOC_ARENA_STRUCTS_B
/* Arena chunk header. */
struct GH(arena_chunk_s) {
	/*
	 * A pointer to the arena that owns the chunk is stored within the node.
	 * This field as a whole is used by chunks_rtree to support both
	 * ivsalloc() and core-based debugging.
	 */
	GH(extent_node_t)		node;

	/*
	 * True if memory could be backed by transparent huge pages.  This is
	 * only directly relevant to Linux, since it is the only supported
	 * platform on which jemalloc interacts with explicit transparent huge
	 * page controls.
	 */
	bool			hugepage;

	/*
	 * Map of pages within chunk that keeps track of free/large/small.  The
	 * first map_bias entries are omitted, since the chunk header does not
	 * need to be tracked in the map.  This omission saves a header page
	 * for common chunk sizes (e.g. 4 MiB).
	 */
	GH(arena_chunk_map_bits_t)	map_bits[1]; /* Dynamically sized. */
};

/*
 * Read-only information associated with each element of GH(arena_t)'s bins array
 * is stored separately, partly to reduce memory usage (only one copy, rather
 * than one per arena), but mainly to avoid false cacheline sharing.
 *
 * Each run has the following layout:
 *
 *               /--------------------\
 *               | pad?               |
 *               |--------------------|
 *               | redzone            |
 *   reg0_offset | region 0           |
 *               | redzone            |
 *               |--------------------| \
 *               | redzone            | |
 *               | region 1           |  > reg_interval
 *               | redzone            | /
 *               |--------------------|
 *               | ...                |
 *               | ...                |
 *               | ...                |
 *               |--------------------|
 *               | redzone            |
 *               | region nregs-1     |
 *               | redzone            |
 *               |--------------------|
 *               | alignment pad?     |
 *               \--------------------/
 *
 * reg_interval has at least the same minimum alignment as reg_size; this
 * preserves the alignment constraint that sa2u() depends on.  Alignment pad is
 * either 0 or redzone_size; it is present only if needed to align reg0_offset.
 */
struct GH(arena_bin_info_s) {
	/* Size of regions in a run for this bin's size class. */
	GHT			reg_size;

	/* Redzone size. */
	GHT			redzone_size;

	/* Interval between regions (reg_size + (redzone_size << 1)). */
	GHT			reg_interval;

	/* Total size of a run for this bin's size class. */
	GHT			run_size;

	/* Total number of regions in a run for this bin's size class. */
	uint32_t		nregs;

	/*
	 * Metadata used to manipulate bitmaps for runs associated with this
	 * bin.
	 */
	GH(bitmap_info_t)		bitmap_info;

	/* Offset of first region in a run for this bin's size class. */
	uint32_t		reg0_offset;
};

struct GH(arena_decay_s) {
	/*
	 * Approximate time in seconds from the creation of a set of unused
	 * dirty pages until an equivalent set of unused dirty pages is purged
	 * and/or reused.
	 */
	GHST			time;
	/* time / SMOOTHSTEP_NSTEPS. */
	GH(nstime_t)		interval;
	/*
	 * Time at which the current decay interval logically started.  We do
	 * not actually advance to a new epoch until sometime after it starts
	 * because of scheduling and computation delays, and it is even possible
	 * to completely skip epochs.  In all cases, during epoch advancement we
	 * merge all relevant activity into the most recently recorded epoch.
	 */
	GH(nstime_t)		epoch;
	/* Deadline randomness generator. */
	uint64_t		jitter_state;
	/*
	 * Deadline for current epoch.  This is the sum of interval and per
	 * epoch jitter which is a uniform random variable in [0..interval).
	 * Epochs always advance by precise multiples of interval, but we
	 * randomize the deadline to reduce the likelihood of arenas purging in
	 * lockstep.
	 */
	GH(nstime_t)		deadline;
	/*
	 * Number of dirty pages at beginning of current epoch.  During epoch
	 * advancement we use the delta between arena->decay.ndirty and
	 * arena->ndirty to determine how many dirty pages, if any, were
	 * generated.
	 */
	GHT			ndirty;
	/*
	 * Trailing log of how many unused dirty pages were generated during
	 * each of the past SMOOTHSTEP_NSTEPS decay epochs, where the last
	 * element is the most recent epoch.  Corresponding epoch times are
	 * relative to epoch.
	 */
	GHT			backlog[SMOOTHSTEP_NSTEPS];
};

struct GH(arena_bin_s) {
	/*
	 * All operations on runcur, runs, and stats require that lock be
	 * locked.  Run allocation/deallocation are protected by the arena lock,
	 * which may be acquired while holding one or more bin locks, but not
	 * vise versa.
	 */
	GH(malloc_mutex_t)		lock;

	/*
	 * Current run being used to service allocations of this bin's size
	 * class.
	 */
	GH(arena_run_t)		*runcur;

	/*
	 * Heap of non-full runs.  This heap is used when looking for an
	 * existing run when runcur is no longer usable.  We choose the
	 * non-full run that is lowest in memory; this policy tends to keep
	 * objects packed well, and it can also help reduce the number of
	 * almost-empty chunks.
	 */
	arena_run_heap_t	runs;

	/* Bin statistics. */
	GH(malloc_bin_stats_t)	stats;
};

struct GH(arena_s) {
	/* This arena's index within the arenas array. */
	unsigned		ind;

	/*
	 * Number of threads currently assigned to this arena, synchronized via
	 * atomic operations.  Each thread has two distinct assignments, one for
	 * application-serving allocation, and the other for internal metadata
	 * allocation.  Internal metadata must not be allocated from arenas
	 * created via the arenas.extend mallctl, because the arena.<i>.reset
	 * mallctl indiscriminately discards all allocations for the affected
	 * arena.
	 *
	 *   0: Application allocation.
	 *   1: Internal metadata allocation.
	 */
	unsigned		nthreads[2];

	/*
	 * There are three classes of arena operations from a locking
	 * perspective:
	 * 1) Thread assignment (modifies nthreads) is synchronized via atomics.
	 * 2) Bin-related operations are protected by bin locks.
	 * 3) Chunk- and run-related operations are protected by this mutex.
	 */
	GH(malloc_mutex_t)		lock;

	GH(arena_stats_t)		stats;
	/*
	 * List of tcaches for extant threads associated with this arena.
	 * Stats from these are merged incrementally, and at exit if
	 * opt_stats_print is enabled.
	 */
	ql_head(GH(tcache_t))	tcache_ql;

	uint64_t		prof_accumbytes;

	/*
	 * PRNG state for cache index randomization of large allocation base
	 * pointers.
	 */
	GHT			offset_state;

	dss_prec_t		dss_prec;

	/* Extant arena chunks. */
	ql_head(GH(extent_node_t))	achunks;

	/* Extent serial number generator state. */
	GHT			extent_sn_next;

	/*
	 * In order to avoid rapid chunk allocation/deallocation when an arena
	 * oscillates right on the cusp of needing a new chunk, cache the most
	 * recently freed chunk.  The spare is left in the arena's chunk trees
	 * until it is deleted.
	 *
	 * There is one spare chunk per arena, rather than one spare total, in
	 * order to avoid interactions between multiple threads that could make
	 * a single spare inadequate.
	 */
	GH(arena_chunk_t)		*spare;

	/* Minimum ratio (log base 2) of nactive:ndirty. */
	GHST			lg_dirty_mult;

	/* True if a thread is currently executing arena_purge_to_limit(). */
	bool			purging;

	/* Number of pages in active runs and huge regions. */
	GHT			nactive;

	/*
	 * Current count of pages within unused runs that are potentially
	 * dirty, and for which madvise(... MADV_DONTNEED) has not been called.
	 * By tracking this, we can institute a limit on how much dirty unused
	 * memory is mapped for each arena.
	 */
	GHT			ndirty;

	/*
	 * Unused dirty memory this arena manages.  Dirty memory is conceptually
	 * tracked as an arbitrarily interleaved LRU of dirty runs and cached
	 * chunks, but the list linkage is actually semi-duplicated in order to
	 * avoid extra GH(arena_chunk_map_misc_t) space overhead.
	 *
	 *   LRU-----------------------------------------------------------MRU
	 *
	 *        /-- arena ---\
	 *        |            |
	 *        |            |
	 *        |------------|                             /- chunk -\
	 *   ...->|chunks_cache|<--------------------------->|  /----\ |<--...
	 *        |------------|                             |  |node| |
	 *        |            |                             |  |    | |
	 *        |            |    /- run -\    /- run -\   |  |    | |
	 *        |            |    |       |    |       |   |  |    | |
	 *        |            |    |       |    |       |   |  |    | |
	 *        |------------|    |-------|    |-------|   |  |----| |
	 *   ...->|runs_dirty  |<-->|rd     |<-->|rd     |<---->|rd  |<----...
	 *        |------------|    |-------|    |-------|   |  |----| |
	 *        |            |    |       |    |       |   |  |    | |
	 *        |            |    |       |    |       |   |  \----/ |
	 *        |            |    \-------/    \-------/   |         |
	 *        |            |                             |         |
	 *        |            |                             |         |
	 *        \------------/                             \---------/
	 */
	GH(arena_runs_dirty_link_t)	runs_dirty;
	GH(extent_node_t)		chunks_cache;

	/* Decay-based purging state. */
	GH(arena_decay_t)		decay;

	/* Extant huge allocations. */
	ql_head(GH(extent_node_t))	huge;
	/* Synchronizes all huge allocation/update/deallocation. */
	GH(malloc_mutex_t)		huge_mtx;

	/*
	 * Trees of chunks that were previously allocated (trees differ only in
	 * node ordering).  These are used when allocating chunks, in an attempt
	 * to re-use address space.  Depending on function, different tree
	 * orderings are needed, which is why there are two trees with the same
	 * contents.
	 */
	extent_tree_t		chunks_szsnad_cached;
	extent_tree_t		chunks_ad_cached;
	extent_tree_t		chunks_szsnad_retained;
	extent_tree_t		chunks_ad_retained;

	GH(malloc_mutex_t)		chunks_mtx;
	/* Cache of nodes that were allocated via base_alloc(). */
	ql_head(GH(extent_node_t))	node_cache;
	GH(malloc_mutex_t)		node_cache_mtx;

	/* User-configurable chunk hook functions. */
	chunk_hooks_t		chunk_hooks;

	/* bins is used to store trees of free regions. */
	GH(arena_bin_t)		bins[JM_NBINS];

	/*
	 * Size-segregated address-ordered heaps of this arena's available runs,
	 * used for first-best-fit run allocation.  Runs are quantized, i.e.
	 * they reside in the last heap which corresponds to a size class less
	 * than or equal to the run size.
	 */
	arena_run_heap_t	runs_avail[NPSIZES];
};

/* Used in conjunction with tsd for fast arena-related context lookup. */
struct GH(arena_tdata_s) {
	GH(ticker_t)		decay_ticker;
};
#endif /* JEMALLOC_ARENA_STRUCTS_B */

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

static const GHT	large_pad =
#ifdef JEMALLOC_CACHE_OBLIVIOUS
    PAGE
#else
    0
#endif
    ;

extern bool		opt_thp;
extern purge_mode_t	opt_purge;
extern const char	*purge_mode_names[];
extern GHST		opt_lg_dirty_mult;
extern GHST		opt_decay_time;

extern GH(arena_bin_info_t)	arena_bin_info[JM_NBINS];

extern GHT		map_bias; /* Number of arena chunk header pages. */
extern GHT		map_misc_offset;
extern GHT		arena_maxrun; /* Max run size for arenas. */
extern GHT		large_maxclass; /* Max large size class. */
extern unsigned		nlclasses; /* Number of large size classes. */
extern unsigned		nhclasses; /* Number of huge size classes. */

#ifdef JEMALLOC_JET
typedef GHT (run_quantize_t)(GHT);
extern run_quantize_t *run_quantize_floor;
extern run_quantize_t *run_quantize_ceil;
#endif
void	arena_chunk_cache_maybe_insert(GH(arena_t) *arena, GH(extent_node_t) *node,
    bool cache);
void	arena_chunk_cache_maybe_remove(GH(arena_t) *arena, GH(extent_node_t) *node,
    bool cache);
GH(extent_node_t)	*arena_node_alloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_node_dalloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GH(extent_node_t) *node);
void	*arena_chunk_alloc_huge(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT usize,
    GHT alignment, GHT *sn, bool *zero);
void	arena_chunk_dalloc_huge(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT chunk,
    GHT usize, GHT sn);
void	arena_chunk_ralloc_huge_similar(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GHT chunk, GHT oldsize, GHT usize);
void	arena_chunk_ralloc_huge_shrink(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GHT chunk, GHT oldsize, GHT usize, GHT sn);
bool	arena_chunk_ralloc_huge_expand(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GHT chunk, GHT oldsize, GHT usize, bool *zero);
GHST	arena_lg_dirty_mult_get(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
bool	arena_lg_dirty_mult_set(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GHST lg_dirty_mult);
GHST	arena_decay_time_get(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
bool	arena_decay_time_set(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHST decay_time);
void	arena_purge(GH(tsdn_t) *tsdn, GH(arena_t) *arena, bool all);
void	arena_maybe_purge(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_reset(GH(tsd_t) *tsd, GH(arena_t) *arena);
void	arena_tcache_fill_small(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GH(tcache_bin_t) *tbin, szind_t binind, uint64_t prof_accumbytes);
void	arena_alloc_junk_small(GHT ptr, GH(arena_bin_info_t) *bin_info,
    bool zero);
#ifdef JEMALLOC_JET
typedef void (arena_redzone_corruption_t)(GHT , GHT, bool, GHT,
    uint8_t);
extern arena_redzone_corruption_t *arena_redzone_corruption;
typedef void (arena_dalloc_junk_small_t)(GHT , GH(arena_bin_info_t) *);
extern arena_dalloc_junk_small_t *arena_dalloc_junk_small;
#else
void	arena_dalloc_junk_small(GHT ptr, GH(arena_bin_info_t) *bin_info);
#endif
void	arena_quarantine_junk_small(GHT ptr, GHT usize);
void	*arena_malloc_large(GH(tsdn_t) *tsdn, GH(arena_t) *arena, szind_t ind,
    bool zero);
void	*arena_malloc_hard(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT size,
    szind_t ind, bool zero);
void	*arena_palloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT usize,
    GHT alignment, bool zero, GH(tcache_t) *tcache);
void	arena_prof_promoted(GH(tsdn_t) *tsdn, const GHT ptr, GHT size);
void	arena_dalloc_bin_junked_locked(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GH(arena_chunk_t) *chunk, GHT ptr, GH(arena_chunk_map_bits_t) *bitselm);
void	arena_dalloc_bin(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GH(arena_chunk_t) *chunk,
    GHT ptr, GHT pageind, GH(arena_chunk_map_bits_t) *bitselm);
void	arena_dalloc_small(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GH(arena_chunk_t) *chunk,
    GHT ptr, GHT pageind);
#ifdef JEMALLOC_JET
typedef void (arena_dalloc_junk_large_t)(GHT , GHT);
extern arena_dalloc_junk_large_t *arena_dalloc_junk_large;
#else
void	arena_dalloc_junk_large(GHT ptr, GHT usize);
#endif
void	arena_dalloc_large_junked_locked(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    GH(arena_chunk_t) *chunk, GHT ptr);
void	arena_dalloc_large(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GH(arena_chunk_t) *chunk,
    GHT ptr);
#ifdef JEMALLOC_JET
typedef void (arena_ralloc_junk_large_t)(GHT , GHT, GHT);
extern arena_ralloc_junk_large_t *arena_ralloc_junk_large;
#endif
bool	arena_ralloc_no_move(GH(tsdn_t) *tsdn, GHT ptr, GHT oldsize,
    GHT size, GHT extra, bool zero);
void	*arena_ralloc(GH(tsd_t) *tsd, GH(arena_t) *arena, GHT ptr, GHT oldsize,
    GHT size, GHT alignment, bool zero, GH(tcache_t) *tcache);
dss_prec_t	arena_dss_prec_get(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
bool	arena_dss_prec_set(GH(tsdn_t) *tsdn, GH(arena_t) *arena, dss_prec_t dss_prec);
GHST	arena_lg_dirty_mult_default_get(void);
bool	arena_lg_dirty_mult_default_set(GHST lg_dirty_mult);
GHST	arena_decay_time_default_get(void);
bool	arena_decay_time_default_set(GHST decay_time);
void	arena_basic_stats_merge(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    unsigned *nthreads, const char **dss, GHST *lg_dirty_mult,
    GHST *decay_time, GHT *nactive, GHT *ndirty);
void	arena_stats_merge(GH(tsdn_t) *tsdn, GH(arena_t) *arena, unsigned *nthreads,
    const char **dss, GHST *lg_dirty_mult, GHST *decay_time,
    GHT *nactive, GHT *ndirty, GH(arena_stats_t) *astats,
    GH(malloc_bin_stats_t) *bstats, GH(malloc_large_stats_t) *lstats,
    GH(malloc_huge_stats_t) *hstats);
unsigned	arena_nthreads_get(GH(arena_t) *arena, bool internal);
void	arena_nthreads_inc(GH(arena_t) *arena, bool internal);
void	arena_nthreads_dec(GH(arena_t) *arena, bool internal);
GHT	arena_extent_sn_next(GH(arena_t) *arena);
GH(arena_t)	*arena_new(GH(tsdn_t) *tsdn, unsigned ind);
void	arena_boot(void);
void	arena_prefork0(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_prefork1(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_prefork2(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_prefork3(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_postfork_parent(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	arena_postfork_child(GH(tsdn_t) *tsdn, GH(arena_t) *arena);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
GH(arena_chunk_map_bits_t)	*arena_bitselm_get_mutable(GH(arena_chunk_t) *chunk,
    GHT pageind);
const GH(arena_chunk_map_bits_t)	*arena_bitselm_get_const(
    const GH(arena_chunk_t) *chunk, GHT pageind);
GH(arena_chunk_map_misc_t)	*arena_miscelm_get_mutable(GH(arena_chunk_t) *chunk,
    GHT pageind);
const GH(arena_chunk_map_misc_t)	*arena_miscelm_get_const(
    const GH(arena_chunk_t) *chunk, GHT pageind);
GHT	arena_miscelm_to_pageind(const GH(arena_chunk_map_misc_t) *miscelm);
void	*arena_miscelm_to_rpages(const GH(arena_chunk_map_misc_t) *miscelm);
GH(arena_chunk_map_misc_t)	*arena_rd_to_miscelm(GH(arena_runs_dirty_link_t) *rd);
GH(arena_chunk_map_misc_t)	*arena_run_to_miscelm(GH(arena_run_t) *run);
GHT	*arena_mapbitsp_get_mutable(GH(arena_chunk_t) *chunk, GHT pageind);
const GHT	*arena_mapbitsp_get_const(const GH(arena_chunk_t) *chunk,
    GHT pageind);
GHT	arena_mapbitsp_read(const GHT *mapbitsp);
GHT	arena_mapbits_get(const GH(arena_chunk_t) *chunk, GHT pageind);
GHT	arena_mapbits_size_decode(GHT mapbits);
GHT	arena_mapbits_unallocated_size_get(const GH(arena_chunk_t) *chunk,
    GHT pageind);
GHT	arena_mapbits_large_size_get(const GH(arena_chunk_t) *chunk,
    GHT pageind);
GHT	arena_mapbits_small_runind_get(const GH(arena_chunk_t) *chunk,
    GHT pageind);
szind_t	arena_mapbits_binind_get(const GH(arena_chunk_t) *chunk, GHT pageind);
GHT	arena_mapbits_dirty_get(const GH(arena_chunk_t) *chunk, GHT pageind);
GHT	arena_mapbits_unzeroed_get(const GH(arena_chunk_t) *chunk, GHT pageind);
GHT	arena_mapbits_decommitted_get(const GH(arena_chunk_t) *chunk,
    GHT pageind);
GHT	arena_mapbits_large_get(const GH(arena_chunk_t) *chunk, GHT pageind);
GHT	arena_mapbits_allocated_get(const GH(arena_chunk_t) *chunk, GHT pageind);
void	arena_mapbitsp_write(GHT *mapbitsp, GHT mapbits);
GHT	arena_mapbits_size_encode(GHT size);
void	arena_mapbits_unallocated_set(GH(arena_chunk_t) *chunk, GHT pageind,
    GHT size, GHT flags);
void	arena_mapbits_unallocated_size_set(GH(arena_chunk_t) *chunk, GHT pageind,
    GHT size);
void	arena_mapbits_internal_set(GH(arena_chunk_t) *chunk, GHT pageind,
    GHT flags);
void	arena_mapbits_large_set(GH(arena_chunk_t) *chunk, GHT pageind,
    GHT size, GHT flags);
void	arena_mapbits_large_binind_set(GH(arena_chunk_t) *chunk, GHT pageind,
    szind_t binind);
void	arena_mapbits_small_set(GH(arena_chunk_t) *chunk, GHT pageind,
    GHT runind, szind_t binind, GHT flags);
void	arena_metadata_allocated_add(GH(arena_t) *arena, GHT size);
void	arena_metadata_allocated_sub(GH(arena_t) *arena, GHT size);
GHT	arena_metadata_allocated_get(GH(arena_t) *arena);
bool	arena_prof_accum_impl(GH(arena_t) *arena, uint64_t accumbytes);
bool	arena_prof_accum_locked(GH(arena_t) *arena, uint64_t accumbytes);
bool	arena_prof_accum(GH(tsdn_t) *tsdn, GH(arena_t) *arena, uint64_t accumbytes);
szind_t	arena_ptr_small_binind_get(const GHT ptr, GHT mapbits);
szind_t	arena_bin_index(GH(arena_t) *arena, GH(arena_bin_t) *bin);
GHT	arena_run_regind(GH(arena_run_t) *run, GH(arena_bin_info_t) *bin_info,
    const GHT ptr);
GH(prof_tctx_t)	*arena_prof_tctx_get(GH(tsdn_t) *tsdn, const GHT ptr);
void	arena_prof_tctx_set(GH(tsdn_t) *tsdn, const GHT ptr, GHT usize,
    GH(prof_tctx_t) *tctx);
void	arena_prof_tctx_reset(GH(tsdn_t) *tsdn, const GHT ptr, GHT usize,
    const GHT old_ptr, GH(prof_tctx_t) *old_tctx);
void	arena_decay_ticks(GH(tsdn_t) *tsdn, GH(arena_t) *arena, unsigned nticks);
void	arena_decay_tick(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	*arena_malloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT size, szind_t ind,
    bool zero, GH(tcache_t) *tcache, bool slow_path);
GH(arena_t)	*arena_aalloc(const GHT ptr);
GHT	arena_salloc(GH(tsdn_t) *tsdn, const GHT ptr, bool demote);
void	arena_dalloc(GH(tsdn_t) *tsdn, GHT ptr, GH(tcache_t) *tcache, bool slow_path);
void	arena_sdalloc(GH(tsdn_t) *tsdn, GHT ptr, GHT size, GH(tcache_t) *tcache,
    bool slow_path);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_ARENA_C_))
#  ifdef JEMALLOC_ARENA_INLINE_A
JEMALLOC_ALWAYS_INLINE GH(arena_chunk_map_bits_t) *
arena_bitselm_get_mutable(GH(arena_chunk_t) *chunk, GHT pageind)
{
	if (unlikely((pageind <= map_bias) || (pageind > chunk_npages)))
		return (NULL);
	return (&chunk->map_bits[pageind-map_bias]);
}

JEMALLOC_ALWAYS_INLINE const GH(arena_chunk_map_bits_t) *
arena_bitselm_get_const(const GH(arena_chunk_t) *chunk, GHT pageind)
{

	return (arena_bitselm_get_mutable((GH(arena_chunk_t) *)chunk, pageind));
}

JEMALLOC_ALWAYS_INLINE GH(arena_chunk_map_misc_t) *
arena_miscelm_get_mutable(GH(arena_chunk_t) *chunk, GHT pageind)
{
	if (unlikely((pageind <= map_bias) || (pageind > chunk_npages)))
		return (NULL);

	return ((GH(arena_chunk_map_misc_t) *)((uintptr_t)chunk +
	    (uintptr_t)map_misc_offset) + pageind-map_bias);
}

JEMALLOC_ALWAYS_INLINE const GH(arena_chunk_map_misc_t) *
arena_miscelm_get_const(const GH(arena_chunk_t) *chunk, GHT pageind)
{

	return (arena_miscelm_get_mutable((GH(arena_chunk_t) *)chunk, pageind));
}

JEMALLOC_ALWAYS_INLINE GHT
arena_miscelm_to_pageind(const GH(arena_chunk_map_misc_t) *miscelm)
{
	GH(arena_chunk_t) *chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(miscelm);
	GHT pageind = ((uintptr_t)miscelm - ((uintptr_t)chunk +
	    map_misc_offset)) / sizeof(GH(arena_chunk_map_misc_t)) + map_bias;

	assert(pageind >= map_bias);
	assert(pageind < chunk_npages);

	return (pageind);
}

JEMALLOC_ALWAYS_INLINE GHT 
arena_miscelm_to_rpages(const GH(arena_chunk_map_misc_t) *miscelm)
{
	GH(arena_chunk_t) *chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(miscelm);
	GHT pageind = arena_miscelm_to_pageind(miscelm);

	return ((GHT )((uintptr_t)chunk + (pageind << LG_PAGE)));
}

JEMALLOC_ALWAYS_INLINE GH(arena_chunk_map_misc_t) *
arena_rd_to_miscelm(GH(arena_runs_dirty_link_t) *rd)
{
	GH(arena_chunk_map_misc_t) *miscelm = (GH(arena_chunk_map_misc_t)
	    *)((uintptr_t)rd - offsetof(GH(arena_chunk_map_misc_t), rd));
	if (unlikely((arena_miscelm_to_pageind (miscelm) <= map_bias)
				|| arena_miscelm_to_pageind (miscelm) > chunk_npages))
				return (NULL);
	return (miscelm);
}

JEMALLOC_ALWAYS_INLINE GH(arena_chunk_map_misc_t) *
arena_run_to_miscelm(GH(arena_run_t) *run)
{
	GH(arena_chunk_map_misc_t) *miscelm = (GH(arena_chunk_map_misc_t)
	    *)((uintptr_t)run - offsetof(GH(arena_chunk_map_misc_t), run));

	if (unlikely((arena_miscelm_to_pageind (miscelm) <= map_bias)
				|| arena_miscelm_to_pageind (miscelm) > chunk_npages))
				return (NULL);

	return (miscelm);
}

JEMALLOC_ALWAYS_INLINE GHT *
arena_mapbitsp_get_mutable(GH(arena_chunk_t) *chunk, GHT pageind)
{

	return (&arena_bitselm_get_mutable(chunk, pageind)->bits);
}

JEMALLOC_ALWAYS_INLINE const GHT *
arena_mapbitsp_get_const(const GH(arena_chunk_t) *chunk, GHT pageind)
{

	return (arena_mapbitsp_get_mutable((GH(arena_chunk_t) *)chunk, pageind));
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbitsp_read(const GHT *mapbitsp)
{

	return (*mapbitsp);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{

	return (arena_mapbitsp_read(arena_mapbitsp_get_const(chunk, pageind)));
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_size_decode(GHT mapbits)
{
	GHT size;

#if CHUNK_MAP_SIZE_SHIFT > 0
	size = (mapbits & CHUNK_MAP_SIZE_MASK) >> CHUNK_MAP_SIZE_SHIFT;
#elif CHUNK_MAP_SIZE_SHIFT == 0
	size = mapbits & CHUNK_MAP_SIZE_MASK;
#else
	size = (mapbits & CHUNK_MAP_SIZE_MASK) << -CHUNK_MAP_SIZE_SHIFT;
#endif

	return (size);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_unallocated_size_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	assert((mapbits & (CHUNK_MAP_LARGE|CHUNK_MAP_ALLOCATED)) == 0);
	return (arena_mapbits_size_decode(mapbits));
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_large_size_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	assert((mapbits & (CHUNK_MAP_LARGE|CHUNK_MAP_ALLOCATED)) ==
	    (CHUNK_MAP_LARGE|CHUNK_MAP_ALLOCATED));
	return (arena_mapbits_size_decode(mapbits));
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_small_runind_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	assert((mapbits & (CHUNK_MAP_LARGE|CHUNK_MAP_ALLOCATED)) ==
	    CHUNK_MAP_ALLOCATED);
	return (mapbits >> CHUNK_MAP_RUNIND_SHIFT);
}

JEMALLOC_ALWAYS_INLINE szind_t
arena_mapbits_binind_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;
	szind_t binind;

	mapbits = arena_mapbits_get(chunk, pageind);
	binind = (mapbits & CHUNK_MAP_BININD_MASK) >> CHUNK_MAP_BININD_SHIFT;
	assert(binind < JM_NBINS || binind == BININD_INVALID);
	return (binind);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_dirty_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	assert((mapbits & CHUNK_MAP_DECOMMITTED) == 0 || (mapbits &
	    (CHUNK_MAP_DIRTY|CHUNK_MAP_UNZEROED)) == 0);
	return (mapbits & CHUNK_MAP_DIRTY);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_unzeroed_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	assert((mapbits & CHUNK_MAP_DECOMMITTED) == 0 || (mapbits &
	    (CHUNK_MAP_DIRTY|CHUNK_MAP_UNZEROED)) == 0);
	return (mapbits & CHUNK_MAP_UNZEROED);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_decommitted_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	assert((mapbits & CHUNK_MAP_DECOMMITTED) == 0 || (mapbits &
	    (CHUNK_MAP_DIRTY|CHUNK_MAP_UNZEROED)) == 0);
	return (mapbits & CHUNK_MAP_DECOMMITTED);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_large_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	return (mapbits & CHUNK_MAP_LARGE);
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_allocated_get(const GH(arena_chunk_t) *chunk, GHT pageind)
{
	GHT mapbits;

	mapbits = arena_mapbits_get(chunk, pageind);
	return (mapbits & CHUNK_MAP_ALLOCATED);
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbitsp_write(GHT *mapbitsp, GHT mapbits)
{

	*mapbitsp = mapbits;
}

JEMALLOC_ALWAYS_INLINE GHT
arena_mapbits_size_encode(GHT size)
{
	GHT mapbits;

#if CHUNK_MAP_SIZE_SHIFT > 0
	mapbits = size << CHUNK_MAP_SIZE_SHIFT;
#elif CHUNK_MAP_SIZE_SHIFT == 0
	mapbits = size;
#else
	mapbits = size >> -CHUNK_MAP_SIZE_SHIFT;
#endif
	assert((mapbits & ~CHUNK_MAP_SIZE_MASK) == 0);
	return (mapbits);
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbits_unallocated_set(GH(arena_chunk_t) *chunk, GHT pageind, GHT size,
    GHT flags)
{
	GHT *mapbitsp = arena_mapbitsp_get_mutable(chunk, pageind);
	assert((size & PAGE_MASK) == 0);
	assert((flags & CHUNK_MAP_FLAGS_MASK) == flags);
	assert((flags & CHUNK_MAP_DECOMMITTED) == 0 || (flags &
	    (CHUNK_MAP_DIRTY|CHUNK_MAP_UNZEROED)) == 0);
	arena_mapbitsp_write(mapbitsp, arena_mapbits_size_encode(size) |
	    CHUNK_MAP_BININD_INVALID | flags);
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbits_unallocated_size_set(GH(arena_chunk_t) *chunk, GHT pageind,
    GHT size)
{
	GHT *mapbitsp = arena_mapbitsp_get_mutable(chunk, pageind);
	GHT mapbits = arena_mapbitsp_read(mapbitsp);
	assert((size & PAGE_MASK) == 0);
	assert((mapbits & (CHUNK_MAP_LARGE|CHUNK_MAP_ALLOCATED)) == 0);
	arena_mapbitsp_write(mapbitsp, arena_mapbits_size_encode(size) |
	    (mapbits & ~CHUNK_MAP_SIZE_MASK));
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbits_internal_set(GH(arena_chunk_t) *chunk, GHT pageind, GHT flags)
{
	GHT *mapbitsp = arena_mapbitsp_get_mutable(chunk, pageind);

	assert((flags & CHUNK_MAP_UNZEROED) == flags);
	arena_mapbitsp_write(mapbitsp, flags);
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbits_large_set(GH(arena_chunk_t) *chunk, GHT pageind, GHT size,
    GHT flags)
{
	GHT *mapbitsp = arena_mapbitsp_get_mutable(chunk, pageind);

	assert((size & PAGE_MASK) == 0);
	assert((flags & CHUNK_MAP_FLAGS_MASK) == flags);
	assert((flags & CHUNK_MAP_DECOMMITTED) == 0 || (flags &
	    (CHUNK_MAP_DIRTY|CHUNK_MAP_UNZEROED)) == 0);
	arena_mapbitsp_write(mapbitsp, arena_mapbits_size_encode(size) |
	    CHUNK_MAP_BININD_INVALID | flags | CHUNK_MAP_LARGE |
	    CHUNK_MAP_ALLOCATED);
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbits_large_binind_set(GH(arena_chunk_t) *chunk, GHT pageind,
    szind_t binind)
{
	GHT *mapbitsp = arena_mapbitsp_get_mutable(chunk, pageind);
	GHT mapbits = arena_mapbitsp_read(mapbitsp);

	assert(binind <= BININD_INVALID);
	assert(arena_mapbits_large_size_get(chunk, pageind) == LARGE_MINCLASS +
	    large_pad);
	arena_mapbitsp_write(mapbitsp, (mapbits & ~CHUNK_MAP_BININD_MASK) |
	    (binind << CHUNK_MAP_BININD_SHIFT));
}

JEMALLOC_ALWAYS_INLINE void
arena_mapbits_small_set(GH(arena_chunk_t) *chunk, GHT pageind, GHT runind,
    szind_t binind, GHT flags)
{
	GHT *mapbitsp = arena_mapbitsp_get_mutable(chunk, pageind);

	assert(binind < BININD_INVALID);
	assert(pageind - runind >= map_bias);
	assert((flags & CHUNK_MAP_UNZEROED) == flags);
	arena_mapbitsp_write(mapbitsp, (runind << CHUNK_MAP_RUNIND_SHIFT) |
	    (binind << CHUNK_MAP_BININD_SHIFT) | flags | CHUNK_MAP_ALLOCATED);
}

JEMALLOC_INLINE void
arena_metadata_allocated_add(GH(arena_t) *arena, GHT size)
{

	atomic_add_z(&arena->stats.metadata_allocated, size);
}

JEMALLOC_INLINE void
arena_metadata_allocated_sub(GH(arena_t) *arena, GHT size)
{

	atomic_sub_z(&arena->stats.metadata_allocated, size);
}

JEMALLOC_INLINE GHT
arena_metadata_allocated_get(GH(arena_t) *arena)
{

	return (atomic_read_z(&arena->stats.metadata_allocated));
}

JEMALLOC_INLINE bool
arena_prof_accum_impl(GH(arena_t) *arena, uint64_t accumbytes)
{
	if (unlikely((!config_prof) || (prof_interval == 0)))
		return (false);

	arena->prof_accumbytes += accumbytes;
	if (arena->prof_accumbytes >= prof_interval) {
		arena->prof_accumbytes -= prof_interval;
		return (true);
	}
	return (false);
}

JEMALLOC_INLINE bool
arena_prof_accum_locked(GH(arena_t) *arena, uint64_t accumbytes)
{

	if (unlikely(!config_prof))
		return (false);

	if (likely(prof_interval == 0))
		return (false);
	return (arena_prof_accum_impl(arena, accumbytes));
}

JEMALLOC_INLINE bool
arena_prof_accum(GH(tsdn_t) *tsdn, GH(arena_t) *arena, uint64_t accumbytes)
{
	if (unlikely(!config_prof))
		return (false);

	if (likely(prof_interval == 0))
		return (false);

	{
		bool ret;

		malloc_mutex_lock(tsdn, &arena->lock);
		ret = arena_prof_accum_impl(arena, accumbytes);
		malloc_mutex_unlock(tsdn, &arena->lock);
		return (ret);
	}
}

JEMALLOC_ALWAYS_INLINE szind_t
arena_ptr_small_binind_get(const GHT ptr, GHT mapbits)
{
	szind_t binind;

	binind = (mapbits & CHUNK_MAP_BININD_MASK) >> CHUNK_MAP_BININD_SHIFT;

	if (config_debug) {
		GH(arena_chunk_t) *chunk;
		GH(arena_t) *arena;
		GHT pageind;
		GHT actual_mapbits;
		GHT rpages_ind;
		const GH(arena_run_t) *run;
		GH(arena_bin_t) *bin;
		szind_t run_binind, actual_binind;
		GH(arena_bin_info_t) *bin_info;
		const GH(arena_chunk_map_misc_t) *miscelm;
		const GHT rpages;

		assert(binind != BININD_INVALID);
		assert(binind < JM_NBINS);
		chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
		arena = extent_node_arena_get(&chunk->node);
		pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >> LG_PAGE;
		actual_mapbits = arena_mapbits_get(chunk, pageind);
		assert(mapbits == actual_mapbits);
		assert(arena_mapbits_large_get(chunk, pageind) == 0);
		assert(arena_mapbits_allocated_get(chunk, pageind) != 0);
		rpages_ind = pageind - arena_mapbits_small_runind_get(chunk,
		    pageind);
		miscelm = arena_miscelm_get_const(chunk, rpages_ind);
		run = &miscelm->run;
		run_binind = run->binind;
		bin = &arena->bins[run_binind];
		actual_binind = (szind_t)(bin - arena->bins);
		assert(run_binind == actual_binind);
		bin_info = &arena_bin_info[actual_binind];
		rpages = arena_miscelm_to_rpages(miscelm);
		assert(((uintptr_t)ptr - ((uintptr_t)rpages +
		    (uintptr_t)bin_info->reg0_offset)) % bin_info->reg_interval
		    == 0);
	}

	return (binind);
}
#  endif /* JEMALLOC_ARENA_INLINE_A */

#  ifdef JEMALLOC_ARENA_INLINE_B
JEMALLOC_INLINE szind_t
arena_bin_index(GH(arena_t) *arena, GH(arena_bin_t) *bin)
{
	szind_t binind = (szind_t)(bin - arena->bins);

	assert(binind < JM_NBINS);
	return (binind);
}

JEMALLOC_INLINE GHT
arena_run_regind(GH(arena_run_t) *run, GH(arena_bin_info_t) *bin_info, const GHT ptr)
{
	GHT diff, interval, shift, regind;
	GH(arena_chunk_map_misc_t) *miscelm = arena_run_to_miscelm(run);
	GHT rpages = arena_miscelm_to_rpages(miscelm);

	/*
	 * Freeing a pointer lower than region zero can cause assertion
	 * failure.
	 */
	assert((uintptr_t)ptr >= (uintptr_t)rpages +
	    (uintptr_t)bin_info->reg0_offset);

	/*
	 * Avoid doing division with a variable divisor if possible.  Using
	 * actual division here can reduce allocator throughput by over 20%!
	 */
	diff = (GHT)((uintptr_t)ptr - (uintptr_t)rpages -
	    bin_info->reg0_offset);

	/* Rescale (factor powers of 2 out of the numerator and denominator). */
	interval = bin_info->reg_interval;
	shift = ffs_zu(interval) - 1;
	diff >>= shift;
	interval >>= shift;

	if (interval == 1) {
		/* The divisor was a power of 2. */
		regind = diff;
	} else {
		/*
		 * To divide by a number D that is not a power of two we
		 * multiply by (2^21 / D) and then right shift by 21 positions.
		 *
		 *   X / D
		 *
		 * becomes
		 *
		 *   (X * interval_invs[D - 3]) >> SIZE_INV_SHIFT
		 *
		 * We can omit the first three elements, because we never
		 * divide by 0, and 1 and 2 are both powers of two, which are
		 * handled above.
		 */
#define	SIZE_INV_SHIFT	((sizeof(GHT) << 3) - LG_RUN_MAXREGS)
#define	SIZE_INV(s)	(((ZU(1) << SIZE_INV_SHIFT) / (s)) + 1)
		static const GHT interval_invs[] = {
		    SIZE_INV(3),
		    SIZE_INV(4), SIZE_INV(5), SIZE_INV(6), SIZE_INV(7),
		    SIZE_INV(8), SIZE_INV(9), SIZE_INV(10), SIZE_INV(11),
		    SIZE_INV(12), SIZE_INV(13), SIZE_INV(14), SIZE_INV(15),
		    SIZE_INV(16), SIZE_INV(17), SIZE_INV(18), SIZE_INV(19),
		    SIZE_INV(20), SIZE_INV(21), SIZE_INV(22), SIZE_INV(23),
		    SIZE_INV(24), SIZE_INV(25), SIZE_INV(26), SIZE_INV(27),
		    SIZE_INV(28), SIZE_INV(29), SIZE_INV(30), SIZE_INV(31)
		};

		if (likely(interval <= ((sizeof(interval_invs) / sizeof(GHT))
		    + 2))) {
			regind = (diff * interval_invs[interval - 3]) >>
			    SIZE_INV_SHIFT;
		} else
			regind = diff / interval;
#undef SIZE_INV
#undef SIZE_INV_SHIFT
	}

	assert(diff == regind * interval);
	assert(regind < bin_info->nregs);

	return (regind);
}

JEMALLOC_INLINE GH(prof_tctx_t) *
arena_prof_tctx_get(GH(tsdn_t) *tsdn, const GHT ptr)
{
	GH(prof_tctx_t) *ret;
	GH(arena_chunk_t) *chunk;

	if (unlikely((!config_prof) || (ptr == NULL)))
		return (NULL);

	chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
	if (likely(chunk != ptr)) {
		GHT pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >> LG_PAGE;
		GHT mapbits = arena_mapbits_get(chunk, pageind);

		if (unlikely(mapbits & CHUNK_MAP_ALLOCATED) == 0)
			return (NULL);

		if (likely((mapbits & CHUNK_MAP_LARGE) == 0))
			ret = (GH(prof_tctx_t) *)(uintptr_t)1U;
		else {
			GH(arena_chunk_map_misc_t) *elm =
			    arena_miscelm_get_mutable(chunk, pageind);
			ret = atomic_read_p(&elm->prof_tctx_pun);
		}
	} else
		ret = huge_prof_tctx_get(tsdn, ptr);

	return (ret);
}

JEMALLOC_INLINE void
arena_prof_tctx_set(GH(tsdn_t) *tsdn, const GHT ptr, GHT usize,
    GH(prof_tctx_t) *tctx)
{
	GH(arena_chunk_t) *chunk;

	cassert(config_prof);
	assert(ptr != NULL);

	chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
	if (likely(chunk != ptr)) {
		GHT pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >> LG_PAGE;

		assert(arena_mapbits_allocated_get(chunk, pageind) != 0);

		if (unlikely(usize > SMALL_MAXCLASS || (uintptr_t)tctx >
		    (uintptr_t)1U)) {
			GH(arena_chunk_map_misc_t) *elm;

			assert(arena_mapbits_large_get(chunk, pageind) != 0);

			elm = arena_miscelm_get_mutable(chunk, pageind);
			atomic_write_p(&elm->prof_tctx_pun, tctx);
		} else {
			/*
			 * tctx must always be initialized for large runs.
			 * Assert that the surrounding conditional logic is
			 * equivalent to checking whether ptr refers to a large
			 * run.
			 */
			assert(arena_mapbits_large_get(chunk, pageind) == 0);
		}
	} else
		huge_prof_tctx_set(tsdn, ptr, tctx);
}

JEMALLOC_INLINE void
arena_prof_tctx_reset(GH(tsdn_t) *tsdn, const GHT ptr, GHT usize,
    const GHT old_ptr, GH(prof_tctx_t) *old_tctx)
{

	cassert(config_prof);
	assert(ptr != NULL);

	if (unlikely(usize > SMALL_MAXCLASS || (ptr == old_ptr &&
	    (uintptr_t)old_tctx > (uintptr_t)1U))) {
		GH(arena_chunk_t) *chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
		if (likely(chunk != ptr)) {
			GHT pageind;
			GH(arena_chunk_map_misc_t) *elm;

			pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >>
			    LG_PAGE;
			assert(arena_mapbits_allocated_get(chunk, pageind) !=
			    0);
			assert(arena_mapbits_large_get(chunk, pageind) != 0);

			elm = arena_miscelm_get_mutable(chunk, pageind);
			atomic_write_p(&elm->prof_tctx_pun,
			    (GH(prof_tctx_t) *)(uintptr_t)1U);
		} else
			huge_prof_tctx_reset(tsdn, ptr);
	}
}

JEMALLOC_ALWAYS_INLINE void
arena_decay_ticks(GH(tsdn_t) *tsdn, GH(arena_t) *arena, unsigned nticks)
{
	GH(tsd_t) *tsd;
	GH(ticker_t) *decay_ticker;

	if (unlikely(tsdn_null(tsdn)))
		return;
	tsd = tsdn_tsd(tsdn);
	decay_ticker = decay_ticker_get(tsd, arena->ind);
	if (unlikely(decay_ticker == NULL))
		return;
	if (unlikely(ticker_ticks(decay_ticker, nticks)))
		arena_purge(tsdn, arena, false);
}

JEMALLOC_ALWAYS_INLINE void
arena_decay_tick(GH(tsdn_t) *tsdn, GH(arena_t) *arena)
{

	arena_decay_ticks(tsdn, arena, 1);
}

JEMALLOC_ALWAYS_INLINE GHT 
arena_malloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT size, szind_t ind, bool zero,
    GH(tcache_t) *tcache, bool slow_path)
{

	if (unlikely(!(!tsdn_null(tsdn) || tcache == NULL) || !(size != 0)))
		return (NULL);

	if (likely(tcache != NULL)) {
		if (likely(size <= SMALL_MAXCLASS)) {
			return (tcache_alloc_small(tsdn_tsd(tsdn), arena,
			    tcache, size, ind, zero, slow_path));
		}
		if (likely(size <= tcache_maxclass)) {
			return (tcache_alloc_large(tsdn_tsd(tsdn), arena,
			    tcache, size, ind, zero, slow_path));
		}
		/* (size > tcache_maxclass) case falls through. */

		if (unlikely(size < tcache_maxclass))
			return (NULL);
	}

	return (arena_malloc_hard(tsdn, arena, size, ind, zero));
}

JEMALLOC_ALWAYS_INLINE GH(arena_t) *
arena_aalloc(const GHT ptr)
{
	GH(arena_chunk_t) *chunk;

	chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
	if (likely(chunk != ptr))
		return (extent_node_arena_get(&chunk->node));
	else
		return (huge_aalloc(ptr));
}

/* Return the size of the allocation pointed to by ptr. */
JEMALLOC_ALWAYS_INLINE GHT
arena_salloc(GH(tsdn_t) *tsdn, const GHT ptr, bool demote)
{
	GHT ret;
	GH(arena_chunk_t) *chunk;
	GHT pageind;
	szind_t binind;

	assert(ptr != NULL);

	chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
	if (likely(chunk != ptr)) {
		pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >> LG_PAGE;
		assert(arena_mapbits_allocated_get(chunk, pageind) != 0);
		binind = arena_mapbits_binind_get(chunk, pageind);
		if (unlikely(binind == BININD_INVALID || (config_prof && !demote
		    && arena_mapbits_large_get(chunk, pageind) != 0))) {
			/*
			 * Large allocation.  In the common case (demote), and
			 * as this is an inline function, most callers will only
			 * end up looking at binind to determine that ptr is a
			 * small allocation.
			 */
			assert(config_cache_oblivious || ((uintptr_t)ptr &
			    PAGE_MASK) == 0);
			ret = arena_mapbits_large_size_get(chunk, pageind) -
			    large_pad;
			assert(ret != 0);
			assert(pageind + ((ret+large_pad)>>LG_PAGE) <=
			    chunk_npages);
			assert(arena_mapbits_dirty_get(chunk, pageind) ==
			    arena_mapbits_dirty_get(chunk,
			    pageind+((ret+large_pad)>>LG_PAGE)-1));
		} else {
			/*
			 * Small allocation (possibly promoted to a large
			 * object).
			 */
			assert(arena_mapbits_large_get(chunk, pageind) != 0 ||
			    arena_ptr_small_binind_get(ptr,
			    arena_mapbits_get(chunk, pageind)) == binind);
			ret = index2size(binind);
		}
	} else
		ret = huge_salloc(tsdn, ptr);

	return (ret);
}

JEMALLOC_ALWAYS_INLINE void
arena_dalloc(GH(tsdn_t) *tsdn, GHT ptr, GH(tcache_t) *tcache, bool slow_path)
{
	GH(arena_chunk_t) *chunk;
	GHT pageind, mapbits;
	assert(!tsdn_null(tsdn) || tcache == NULL);
	assert(ptr != NULL);

	chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
	if (likely(chunk != ptr)) {
		pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >> LG_PAGE;
		mapbits = arena_mapbits_get(chunk, pageind);
		assert(arena_mapbits_allocated_get(chunk, pageind) != 0);
		if (likely((mapbits & CHUNK_MAP_LARGE) == 0)) {
			/* Small allocation. */
			if (likely(tcache != NULL)) {
				szind_t binind = arena_ptr_small_binind_get(ptr,
				    mapbits);
				tcache_dalloc_small(tsdn_tsd(tsdn), tcache, ptr,
				    binind, slow_path);
			} else {
				arena_dalloc_small(tsdn,
				    extent_node_arena_get(&chunk->node), chunk,
				    ptr, pageind);
			}
		} else {
			GHT size = arena_mapbits_large_size_get(chunk,
			    pageind);

			assert(config_cache_oblivious || ((uintptr_t)ptr &
			    PAGE_MASK) == 0);

			if (likely(tcache != NULL) && size - large_pad <=
			    tcache_maxclass) {
				tcache_dalloc_large(tsdn_tsd(tsdn), tcache, ptr,
				    size - large_pad, slow_path);
			} else {
				arena_dalloc_large(tsdn,
				    extent_node_arena_get(&chunk->node), chunk,
				    ptr);
			}
		}
	} else
		huge_dalloc(tsdn, ptr);
}

JEMALLOC_ALWAYS_INLINE void
arena_sdalloc(GH(tsdn_t) *tsdn, GHT ptr, GHT size, GH(tcache_t) *tcache,
    bool slow_path)
{
	GH(arena_chunk_t) *chunk;

	assert(!tsdn_null(tsdn) || tcache == NULL);

	chunk = (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ptr);
	if (likely(chunk != ptr)) {
		if (config_prof && opt_prof) {
			GHT pageind = ((uintptr_t)ptr - (uintptr_t)chunk) >>
			    LG_PAGE;
			assert(arena_mapbits_allocated_get(chunk, pageind) !=
			    0);
			if (arena_mapbits_large_get(chunk, pageind) != 0) {
				/*
				 * Make sure to use promoted size, not request
				 * size.
				 */
				size = arena_mapbits_large_size_get(chunk,
				    pageind) - large_pad;
			}
		}
		assert(s2u(size) == s2u(arena_salloc(tsdn, ptr, false)));

		if (likely(size <= SMALL_MAXCLASS)) {
			/* Small allocation. */
			if (likely(tcache != NULL)) {
				szind_t binind = size2index(size);
				tcache_dalloc_small(tsdn_tsd(tsdn), tcache, ptr,
				    binind, slow_path);
			} else {
				GHT pageind = ((uintptr_t)ptr -
				    (uintptr_t)chunk) >> LG_PAGE;
				arena_dalloc_small(tsdn,
				    extent_node_arena_get(&chunk->node), chunk,
				    ptr, pageind);
			}
		} else {
			assert(config_cache_oblivious || ((uintptr_t)ptr &
			    PAGE_MASK) == 0);

			if (likely(tcache != NULL) && size <= tcache_maxclass) {
				tcache_dalloc_large(tsdn_tsd(tsdn), tcache, ptr,
				    size, slow_path);
			} else {
				arena_dalloc_large(tsdn,
				    extent_node_arena_get(&chunk->node), chunk,
				    ptr);
			}
		}
	} else
		huge_dalloc(tsdn, ptr);
}
#  endif /* JEMALLOC_ARENA_INLINE_B */
#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
