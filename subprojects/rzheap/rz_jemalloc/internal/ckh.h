/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct ckh_s ckh_t;
typedef struct ckhc_s ckhc_t;

/* Typedefs to allow easy function pointer passing. */
typedef void ckh_hash_t (const GHT , GHT[2]);
typedef bool ckh_keycomp_t (const GHT , const GHT );

/* Maintain counters used to get an idea of performance. */
/* #define	CKH_COUNT */
/* Print counter values in ckh_delete() (requires CKH_COUNT). */
/* #define	CKH_VERBOSE */

/*
 * There are 2^LG_CKH_BUCKET_CELLS cells in each hash table bucket.  Try to fit
 * one bucket per L1 cache line.
 */
#define	LG_CKH_BUCKET_CELLS (LG_CACHELINE - LG_SIZEOF_PTR - 1)

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

/* Hash table cell. */
struct ckhc_s {
	const void	*key;
	const void	*data;
};

struct ckh_s {
#ifdef CKH_COUNT
	/* Counters used to get an idea of performance. */
	uint64_t	ngrows;
	uint64_t	nshrinks;
	uint64_t	nshrinkfails;
	uint64_t	ninserts;
	uint64_t	nrelocs;
#endif

	/* Used for pseudo-random number generation. */
	uint64_t	prng_state;

	/* Total number of items. */
	GHT		count;

	/*
	 * Minimum and current number of hash table buckets.  There are
	 * 2^LG_CKH_BUCKET_CELLS cells per bucket.
	 */
	unsigned	lg_minbuckets;
	unsigned	lg_curbuckets;

	/* Hash and comparison functions. */
	ckh_hash_t	*hash;
	ckh_keycomp_t	*keycomp;

	/* Hash table with 2^lg_curbuckets buckets. */
	ckhc_t		*tab;
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

bool	ckh_new(tsd_t *tsd, ckh_t *ckh, GHT minitems, ckh_hash_t *hash,
    ckh_keycomp_t *keycomp);
void	ckh_delete(tsd_t *tsd, ckh_t *ckh);
GHT	ckh_count(ckh_t *ckh);
bool	ckh_iter(ckh_t *ckh, GHT *tabind, GHT *key, GHT *data);
bool	ckh_insert(tsd_t *tsd, ckh_t *ckh, const GHT key, const GHT data);
bool	ckh_remove(tsd_t *tsd, ckh_t *ckh, const GHT searchkey, GHT *key,
    GHT *data);
bool	ckh_search(ckh_t *ckh, const GHT searchkey, GHT *key, GHT *data);
void	ckh_string_hash(const GHT key, GHT rz_hash[2]);
bool	ckh_string_keycomp(const GHT k1, const GHT k2);
void	ckh_pointer_hash(const GHT key, GHT rz_hash[2]);
bool	ckh_pointer_keycomp(const GHT k1, const GHT k2);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
