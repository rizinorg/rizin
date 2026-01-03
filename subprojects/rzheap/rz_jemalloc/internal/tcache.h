/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct GH(tcache_bin_info_s) GH(tcache_bin_info_t);
typedef struct GH(tcache_bin_s) GH(tcache_bin_t);
typedef struct GH(tcache_s) GH(tcache_t);
typedef struct GH(tcaches_s) GH(tcaches_t);

/*
 * tcache pointers close to NULL are used to encode state information that is
 * used for two purposes: preventing thread caching on a per thread basis and
 * cleaning up during thread shutdown.
 */
#define	TCACHE_STATE_DISABLED		((GH(tcache_t) *)(uintptr_t)1)
#define	TCACHE_STATE_REINCARNATED	((GH(tcache_t) *)(uintptr_t)2)
#define	TCACHE_STATE_PURGATORY		((GH(tcache_t) *)(uintptr_t)3)
#define	TCACHE_STATE_MAX		TCACHE_STATE_PURGATORY

/*
 * Absolute minimum number of cache slots for each small bin.
 */
#define	TCACHE_NSLOTS_SMALL_MIN		20

/*
 * Absolute maximum number of cache slots for each small bin in the thread
 * cache.  This is an additional constraint beyond that imposed as: twice the
 * number of regions per run for this size class.
 *
 * This constant must be an even number.
 */
#define	TCACHE_NSLOTS_SMALL_MAX		200

/* Number of cache slots for large size classes. */
#define	TCACHE_NSLOTS_LARGE		20

/* (1U << opt_lg_tcache_max) is used to compute tcache_maxclass. */
#define	LG_TCACHE_MAXCLASS_DEFAULT	15

/*
 * TCACHE_GC_SWEEP is the approximate number of allocation events between
 * full GC sweeps.  Integer rounding may cause the actual number to be
 * slightly higher, since GC is performed incrementally.
 */
#define	TCACHE_GC_SWEEP			8192

/* Number of tcache allocation/deallocation events between incremental GCs. */
#define	TCACHE_GC_INCR							\
    ((TCACHE_GC_SWEEP / JM_NBINS) + ((TCACHE_GC_SWEEP / JM_NBINS == 0) ? 0 : 1))

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

typedef enum {
	tcache_enabled_false   = 0, /* Enable cast to/from bool. */
	tcache_enabled_true    = 1,
	tcache_enabled_default = 2
} tcache_enabled_t;

/*
 * Read-only information associated with each element of GH(tcache_t)'s tbins array
 * is stored separately, mainly to reduce memory usage.
 */
struct GH(tcache_bin_info_s) {
	unsigned	ncached_max;	/* Upper limit on ncached. */
};

struct GH(tcache_bin_s) {
	GH(tcache_bin_stats_t) tstats;
	int		low_water;	/* Min # cached since last GC. */
	unsigned	lg_fill_div;	/* Fill (ncached_max >> lg_fill_div). */
	unsigned	ncached;	/* # of cached objects. */
	/*
	 * To make use of adjacent cacheline prefetch, the items in the avail
	 * stack goes to higher address for newer allocations.  avail points
	 * just above the available space, which means that
	 * avail[-ncached, ... -1] are available items and the lowest item will
	 * be allocated first.
	 */
	void		**avail;	/* Stack of available objects. */
};

struct GH(tcache_s) {
	ql_elm(GH(tcache_t)) link;		/* Used for aggregating stats. */
	uint64_t	prof_accumbytes;/* Cleared after arena_prof_accum(). */
	GH(ticker_t)	gc_ticker;	/* Drives incremental GC. */
	szind_t		next_gc_bin;	/* Next bin to GC. */
	GH(tcache_bin_t)	tbins[1];	/* Dynamically sized. */
	/*
	 * The pointer stacks associated with tbins follow as a contiguous
	 * array.  During tcache initialization, the avail pointer in each
	 * element of tbins is initialized to point to the proper offset within
	 * this array.
	 */
};

/* Linkage for list of available (previously used) explicit tcache IDs. */
struct GH(tcaches_s) {
	union {
		GH(tcache_t)	*tcache;
		GH(tcaches_t)	*next;
	};
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

extern bool	opt_tcache;
extern GHST	opt_lg_tcache_max;

extern GH(tcache_bin_info_t)	*tcache_bin_info;

/*
 * Number of tcache bins.  There are JM_NBINS small-object bins, plus 0 or more
 * large-object bins.
 */
extern unsigned	nhbins;

/* Maximum cached size class. */
extern GHT	tcache_maxclass;

/*
 * Explicit tcaches, managed via the tcache.{create,flush,destroy} mallctls and
 * usable via the MALLOCX_TCACHE() flag.  The automatic per thread tcaches are
 * completely disjoint from this data structure.  tcaches starts off as a sparse
 * array, so it has no physical memory footprint until individual pages are
 * touched.  This allows the entire array to be allocated the first time an
 * explicit tcache is created without a disproportionate impact on memory usage.
 */
extern GH(tcaches_t)	*tcaches;

GHT	tcache_salloc(GH(tsdn_t) *tsdn, const GHT ptr);
void	tcache_event_hard(GH(tsd_t) *tsd, GH(tcache_t) *tcache);
void	*tcache_alloc_small_hard(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GH(tcache_t) *tcache,
    GH(tcache_bin_t) *tbin, szind_t binind, bool *tcache_success);
void	tcache_bin_flush_small(GH(tsd_t) *tsd, GH(tcache_t) *tcache, GH(tcache_bin_t) *tbin,
    szind_t binind, unsigned rem);
void	tcache_bin_flush_large(GH(tsd_t) *tsd, GH(tcache_bin_t) *tbin, szind_t binind,
    unsigned rem, GH(tcache_t) *tcache);
void	tcache_arena_reassociate(GH(tsdn_t) *tsdn, GH(tcache_t) *tcache,
    GH(arena_t) *oldarena, GH(arena_t) *newarena);
GH(tcache_t) *tcache_get_hard(GH(tsd_t) *tsd);
GH(tcache_t) *tcache_create(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
void	tcache_cleanup(GH(tsd_t) *tsd);
void	tcache_enabled_cleanup(GH(tsd_t) *tsd);
void	tcache_stats_merge(GH(tsdn_t) *tsdn, GH(tcache_t) *tcache, GH(arena_t) *arena);
bool	tcaches_create(GH(tsd_t) *tsd, unsigned *rz_ind);
void	tcaches_flush(GH(tsd_t) *tsd, unsigned ind);
void	tcaches_destroy(GH(tsd_t) *tsd, unsigned ind);
bool	tcache_boot(GH(tsdn_t) *tsdn);
void tcache_prefork(GH(tsdn_t) *tsdn);
void tcache_postfork_parent(GH(tsdn_t) *tsdn);
void tcache_postfork_child(GH(tsdn_t) *tsdn);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
void	tcache_event(GH(tsd_t) *tsd, GH(tcache_t) *tcache);
void	tcache_flush(void);
bool	tcache_enabled_get(void);
GH(tcache_t) *tcache_get(GH(tsd_t) *tsd, bool create);
void	tcache_enabled_set(bool enabled);
void	*tcache_alloc_easy(GH(tcache_bin_t) *tbin, bool *tcache_success);
void	*tcache_alloc_small(GH(tsd_t) *tsd, GH(arena_t) *arena, GH(tcache_t) *tcache,
    GHT size, szind_t ind, bool zero, bool slow_path);
void	*tcache_alloc_large(GH(tsd_t) *tsd, GH(arena_t) *arena, GH(tcache_t) *tcache,
    GHT size, szind_t ind, bool zero, bool slow_path);
void	tcache_dalloc_small(GH(tsd_t) *tsd, GH(tcache_t) *tcache, GHT ptr,
    szind_t binind, bool slow_path);
void	tcache_dalloc_large(GH(tsd_t) *tsd, GH(tcache_t) *tcache, GHT ptr,
    GHT size, bool slow_path);
GH(tcache_t)	*tcaches_get(GH(tsd_t) *tsd, unsigned ind);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_TCACHE_C_))
JEMALLOC_INLINE void
tcache_flush(void)
{
	GH(tsd_t) *tsd;

	cassert(config_tcache);

	tsd = tsd_fetch();
	tcache_cleanup(tsd);
}

JEMALLOC_INLINE bool
tcache_enabled_get(void)
{
	GH(tsd_t) *tsd;
	tcache_enabled_t tcache_enabled;

	if(unlikely(!config_tcache))
		return false;
	tsd = tsd_fetch();
	tcache_enabled = tsd_tcache_enabled_get(tsd);
	if (tcache_enabled == tcache_enabled_default) {
		tcache_enabled = (tcache_enabled_t)opt_tcache;
		tsd_tcache_enabled_set(tsd, tcache_enabled);
	}

	return ((bool)tcache_enabled);
}

JEMALLOC_INLINE void
tcache_enabled_set(bool enabled)
{
	GH(tsd_t) *tsd;
	tcache_enabled_t tcache_enabled;

	cassert(config_tcache);

	tsd = tsd_fetch();

	tcache_enabled = (tcache_enabled_t)enabled;
	tsd_tcache_enabled_set(tsd, tcache_enabled);

	if (!enabled)
		tcache_cleanup(tsd);
}

JEMALLOC_ALWAYS_INLINE GH(tcache_t) *
tcache_get(GH(tsd_t) *tsd, bool create)
{
	GH(tcache_t) *tcache;

	if (!config_tcache)
		return (NULL);

	tcache = tsd_tcache_get(tsd);
	if (!create)
		return (tcache);
	if (unlikely(tcache == NULL) && tsd_nominal(tsd)) {
		tcache = tcache_get_hard(tsd);
		tsd_tcache_set(tsd, tcache);
	}

	return (tcache);
}

JEMALLOC_ALWAYS_INLINE void
tcache_event(GH(tsd_t) *tsd, GH(tcache_t) *tcache)
{

	if (TCACHE_GC_INCR == 0)
		return;

	if (unlikely(ticker_tick(&tcache->gc_ticker)))
		tcache_event_hard(tsd, tcache);
}

JEMALLOC_ALWAYS_INLINE GHT 
tcache_alloc_easy(GH(tcache_bin_t) *tbin, bool *tcache_success)
{
	GHT ret;

	if (unlikely(tbin->ncached == 0)) {
		tbin->low_water = -1;
		*tcache_success = false;
		return (NULL);
	}
	/*
	 * tcache_success (instead of ret) should be checked upon the return of
	 * this function.  We avoid checking (ret == NULL) because there is
	 * never a null stored on the avail stack (which is unknown to the
	 * compiler), and eagerly checking ret would cause pipeline stall
	 * (waiting for the cacheline).
	 */
	*tcache_success = true;
	ret = *(tbin->avail - tbin->ncached);
	tbin->ncached--;

	if (unlikely((int)tbin->ncached < tbin->low_water))
		tbin->low_water = tbin->ncached;

	return (ret);
}

JEMALLOC_ALWAYS_INLINE GHT 
tcache_alloc_small(GH(tsd_t) *tsd, GH(arena_t) *arena, GH(tcache_t) *tcache, GHT size,
    szind_t binind, bool zero, bool slow_path)
{
	GHT ret;
	GH(tcache_bin_t) *tbin;
	bool tcache_success;
	GHT usize JEMALLOC_CC_SILENCE_INIT(0);

	if (unlikely(binind > JM_NBINS))
		return (NULL);

	tbin = &tcache->tbins[binind];
	ret = tcache_alloc_easy(tbin, &tcache_success);

	if (unlikely(!(tcache_success == (ret != NULL))))
		return (NULL);

	if (unlikely(!tcache_success)) {
		bool tcache_hard_success;
		arena = arena_choose(tsd, arena);
		if (unlikely(arena == NULL))
			return (NULL);

		ret = tcache_alloc_small_hard(tsd_tsdn(tsd), arena, tcache,
		    tbin, binind, &tcache_hard_success);
		if (tcache_hard_success == false)
			return (NULL);
	}

	if (unlikely(!ret))
		return (NULL);

	/*
	 * Only compute usize if required.  The checks in the following if
	 * statement are all static.
	 */
	if (config_prof || (slow_path && config_fill) || unlikely(zero)) {
		usize = index2size(binind);
		assert(tcache_salloc(tsd_tsdn(tsd), ret) == usize);
	}

	if (likely(!zero)) {
		if (slow_path && config_fill) {
			if (unlikely(opt_junk_alloc)) {
				arena_alloc_junk_small(ret,
				    &arena_bin_info[binind], false);
			} else if (unlikely(opt_zero))
				memset(ret, 0, usize);
		}
	} else {
		if (slow_path && config_fill && unlikely(opt_junk_alloc)) {
			arena_alloc_junk_small(ret, &arena_bin_info[binind],
			    true);
		}
		memset(ret, 0, usize);
	}

	if (config_stats)
		tbin->tstats.nrequests++;
	if (config_prof)
		tcache->prof_accumbytes += usize;
	tcache_event(tsd, tcache);
	return (ret);
}

JEMALLOC_ALWAYS_INLINE GHT 
tcache_alloc_large(GH(tsd_t) *tsd, GH(arena_t) *arena, GH(tcache_t) *tcache, GHT size,
    szind_t binind, bool zero, bool slow_path)
{
	GHT ret;
	GH(tcache_bin_t) *tbin;
	bool tcache_success;

	if (unlikely(binind > nhbins))
		return (NULL);
	tbin = &tcache->tbins[binind];
	ret = tcache_alloc_easy(tbin, &tcache_success);

	if (unlikely(!(tcache_success == (ret != NULL))))
		return (NULL);

	if (unlikely(!tcache_success)) {
		/*
		 * Only allocate one large object at a time, because it's quite
		 * expensive to create one and not use it.
		 */
		arena = arena_choose(tsd, arena);
		if (unlikely(arena == NULL))
			return (NULL);

		ret = arena_malloc_large(tsd_tsdn(tsd), arena, binind, zero);
		if (ret == NULL)
			return (NULL);
	} else {
		GHT usize JEMALLOC_CC_SILENCE_INIT(0);

		/* Only compute usize on demand */
		if (config_prof || (slow_path && config_fill) ||
		    unlikely(zero)) {
			usize = index2size(binind);
			assert(usize <= tcache_maxclass);
		}

		if (config_prof && usize == LARGE_MINCLASS) {
			GH(arena_chunk_t) *chunk =
			    (GH(arena_chunk_t) *)CHUNK_ADDR2BASE(ret);
			GHT pageind = (((uintptr_t)ret - (uintptr_t)chunk) >>
			    LG_PAGE);
			arena_mapbits_large_binind_set(chunk, pageind,
			    BININD_INVALID);
		}
		if (likely(!zero)) {
			if (slow_path && config_fill) {
				if (unlikely(opt_junk_alloc)) {
					memset(ret, JEMALLOC_ALLOC_JUNK,
					    usize);
				} else if (unlikely(opt_zero))
					memset(ret, 0, usize);
			}
		} else
			memset(ret, 0, usize);

		if (config_stats)
			tbin->tstats.nrequests++;
		if (config_prof)
			tcache->prof_accumbytes += usize;
	}

	tcache_event(tsd, tcache);
	return (ret);
}

JEMALLOC_ALWAYS_INLINE void
tcache_dalloc_small(GH(tsd_t) *tsd, GH(tcache_t) *tcache, GHT ptr, szind_t binind,
    bool slow_path)
{
	GH(tcache_bin_t) *tbin;
	GH(tcache_bin_info_t) *tbin_info;

	assert(tcache_salloc(tsd_tsdn(tsd), ptr) <= SMALL_MAXCLASS);

	if (slow_path && config_fill && unlikely(opt_junk_free))
		arena_dalloc_junk_small(ptr, &arena_bin_info[binind]);

	tbin = &tcache->tbins[binind];
	tbin_info = &tcache_bin_info[binind];
	if (unlikely(tbin->ncached == tbin_info->ncached_max)) {
		tcache_bin_flush_small(tsd, tcache, tbin, binind,
		    (tbin_info->ncached_max >> 1));
	}
	assert(tbin->ncached < tbin_info->ncached_max);
	tbin->ncached++;
	*(tbin->avail - tbin->ncached) = ptr;

	tcache_event(tsd, tcache);
}

JEMALLOC_ALWAYS_INLINE void
tcache_dalloc_large(GH(tsd_t) *tsd, GH(tcache_t) *tcache, GHT ptr, GHT size,
    bool slow_path)
{
	szind_t binind;
	GH(tcache_bin_t) *tbin;
	GH(tcache_bin_info_t) *tbin_info;

	assert((size & PAGE_MASK) == 0);
	assert(tcache_salloc(tsd_tsdn(tsd), ptr) > SMALL_MAXCLASS);
	assert(tcache_salloc(tsd_tsdn(tsd), ptr) <= tcache_maxclass);

	binind = size2index(size);

	if (slow_path && config_fill && unlikely(opt_junk_free))
		arena_dalloc_junk_large(ptr, size);

	tbin = &tcache->tbins[binind];
	tbin_info = &tcache_bin_info[binind];
	if (unlikely(tbin->ncached == tbin_info->ncached_max)) {
		tcache_bin_flush_large(tsd, tbin, binind,
		    (tbin_info->ncached_max >> 1), tcache);
	}

	assert(tbin->ncached < tbin_info->ncached_max);
	tbin->ncached++;
	*(tbin->avail - tbin->ncached) = ptr;

	tcache_event(tsd, tcache);
}

JEMALLOC_ALWAYS_INLINE GH(tcache_t) *
tcaches_get(GH(tsd_t) *tsd, unsigned ind)
{
	GH(tcaches_t) *elm = &tcaches[ind];
	if (unlikely(elm->tcache == NULL)) {
		elm->tcache = tcache_create(tsd_tsdn(tsd), arena_choose(tsd,
		    NULL));
	}
	return (elm->tcache);
}
#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
