/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct GH(tcache_bin_stats_s) GH(tcache_bin_stats_t);
typedef struct GH(malloc_bin_stats_s) GH(malloc_bin_stats_t);
typedef struct GH(malloc_large_stats_s) GH(malloc_large_stats_t);
typedef struct GH(malloc_huge_stats_s) GH(malloc_huge_stats_t);
typedef struct GH(arena_stats_s) GH(arena_stats_t);
typedef struct GH(chunk_stats_s) GH(chunk_stats_t);

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

struct GH(tcache_bin_stats_s) {
	/*
	 * Number of allocation requests that corresponded to the size of this
	 * bin.
	 */
	uint64_t	nrequests;
};

struct GH(malloc_bin_stats_s) {
	/*
	 * Total number of allocation/deallocation requests served directly by
	 * the bin.  Note that tcache may allocate an object, then recycle it
	 * many times, resulting many increments to nrequests, but only one
	 * each to nmalloc and ndalloc.
	 */
	uint64_t	nmalloc;
	uint64_t	ndalloc;

	/*
	 * Number of allocation requests that correspond to the size of this
	 * bin.  This includes requests served by tcache, though tcache only
	 * periodically merges into this counter.
	 */
	uint64_t	nrequests;

	/*
	 * Current number of regions of this size class, including regions
	 * currently cached by tcache.
	 */
	GHT		curregs;

	/* Number of tcache fills from this bin. */
	uint64_t	nfills;

	/* Number of tcache flushes to this bin. */
	uint64_t	nflushes;

	/* Total number of runs created for this bin's size class. */
	uint64_t	nruns;

	/*
	 * Total number of runs reused by extracting them from the runs tree for
	 * this bin's size class.
	 */
	uint64_t	reruns;

	/* Current number of runs in this bin. */
	GHT		curruns;
};

struct GH(malloc_large_stats_s) {
	/*
	 * Total number of allocation/deallocation requests served directly by
	 * the arena.  Note that tcache may allocate an object, then recycle it
	 * many times, resulting many increments to nrequests, but only one
	 * each to nmalloc and ndalloc.
	 */
	uint64_t	nmalloc;
	uint64_t	ndalloc;

	/*
	 * Number of allocation requests that correspond to this size class.
	 * This includes requests served by tcache, though tcache only
	 * periodically merges into this counter.
	 */
	uint64_t	nrequests;

	/*
	 * Current number of runs of this size class, including runs currently
	 * cached by tcache.
	 */
	GHT		curruns;
};

struct GH(malloc_huge_stats_s) {
	/*
	 * Total number of allocation/deallocation requests served directly by
	 * the arena.
	 */
	uint64_t	nmalloc;
	uint64_t	ndalloc;

	/* Current number of (multi-)chunk allocations of this size class. */
	GHT		curhchunks;
};

struct GH(arena_stats_s) {
	/* Number of bytes currently mapped. */
	GHT		mapped;

	/*
	 * Number of bytes currently retained as a side effect of munmap() being
	 * disabled/bypassed.  Retained bytes are technically mapped (though
	 * always decommitted or purged), but they are excluded from the mapped
	 * statistic (above).
	 */
	GHT		retained;

	/*
	 * Total number of purge sweeps, total number of madvise calls made,
	 * and total pages purged in order to keep dirty unused memory under
	 * control.
	 */
	uint64_t	npurge;
	uint64_t	nmadvise;
	uint64_t	purged;

	/*
	 * Number of bytes currently mapped purely for metadata purposes, and
	 * number of bytes currently allocated for internal metadata.
	 */
	GHT		metadata_mapped;
	GHT		metadata_allocated; /* Protected via atomic_*_z(). */

	/* Per-size-category statistics. */
	GHT		allocated_large;
	uint64_t	nmalloc_large;
	uint64_t	ndalloc_large;
	uint64_t	nrequests_large;

	GHT		allocated_huge;
	uint64_t	nmalloc_huge;
	uint64_t	ndalloc_huge;

	/* One element for each large size class. */
	GH(malloc_large_stats_t)	*lstats;

	/* One element for each huge size class. */
	GH(malloc_huge_stats_t)	*hstats;
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

extern bool	opt_stats_print;

extern GHT	stats_cactive;

void	stats_print(void (*write)(GHT , const char *), GHT cbopaque,
    const char *opts);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
GHT	stats_cactive_get(void);
void	stats_cactive_add(GHT size);
void	stats_cactive_sub(GHT size);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_STATS_C_))
JEMALLOC_INLINE GHT
stats_cactive_get(void)
{

	return (atomic_read_z(&stats_cactive));
}

JEMALLOC_INLINE void
stats_cactive_add(GHT size)
{

	assert(size > 0);
	assert((size & chunksize_mask) == 0);

	atomic_add_z(&stats_cactive, size);
}

JEMALLOC_INLINE void
stats_cactive_sub(GHT size)
{

	assert(size > 0);
	assert((size & chunksize_mask) == 0);

	atomic_sub_z(&stats_cactive, size);
}
#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
