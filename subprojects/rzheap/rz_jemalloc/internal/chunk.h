/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

/*
 * Size and alignment of memory chunks that are allocated by the OS's virtual
 * memory system.
 */
#define	LG_CHUNK_DEFAULT	21

/* Return the chunk address for allocation address a. */
#define	CHUNK_ADDR2BASE(a)						\
	((GHT )((uintptr_t)(a) & ~chunksize_mask))

/* Return the chunk offset of address a. */
#define	CHUNK_ADDR2OFFSET(a)						\
	((GHT)((uintptr_t)(a) & chunksize_mask))

/* Return the smallest chunk multiple that is >= s. */
#define	CHUNK_CEILING(s)						\
	(((s) + chunksize_mask) & ~chunksize_mask)

#define	CHUNK_HOOKS_INITIALIZER {					\
    NULL,								\
    NULL,								\
    NULL,								\
    NULL,								\
    NULL,								\
    NULL,								\
    NULL								\
}

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

extern GHT		opt_lg_chunk;
extern const char	*opt_dss;

extern GH(rtree_t)		chunks_rtree;

extern GHT		chunksize;
extern GHT		chunksize_mask; /* (chunksize - 1). */
extern GHT		chunk_npages;

extern const chunk_hooks_t	chunk_hooks_default;

chunk_hooks_t	chunk_hooks_get(GH(tsdn_t) *tsdn, GH(arena_t) *arena);
chunk_hooks_t	chunk_hooks_set(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    const chunk_hooks_t *chunk_hooks);

bool	chunk_register(const GHT chunk, const GH(extent_node_t) *node,
    bool *gdump);
void	chunk_deregister(const GHT chunk, const GH(extent_node_t) *node);
void	*chunk_alloc_base(GHT size);
void	*chunk_alloc_cache(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    chunk_hooks_t *chunk_hooks, GHT new_addr, GHT size, GHT alignment,
    GHT *sn, bool *zero, bool *commit, bool dalloc_node);
void	*chunk_alloc_wrapper(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    chunk_hooks_t *chunk_hooks, GHT new_addr, GHT size, GHT alignment,
    GHT *sn, bool *zero, bool *commit);
void	chunk_dalloc_cache(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    chunk_hooks_t *chunk_hooks, GHT chunk, GHT size, GHT sn,
    bool committed);
void	chunk_dalloc_wrapper(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    chunk_hooks_t *chunk_hooks, GHT chunk, GHT size, GHT sn,
    bool zeroed, bool committed);
bool	chunk_purge_wrapper(GH(tsdn_t) *tsdn, GH(arena_t) *arena,
    chunk_hooks_t *chunk_hooks, GHT chunk, GHT size, GHT offset,
    GHT length);
bool	chunk_boot(void);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
GH(extent_node_t)	*chunk_lookup(const GHT chunk, bool dependent);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_CHUNK_C_))
JEMALLOC_INLINE GH(extent_node_t) *
chunk_lookup(const GHT ptr, bool dependent)
{

	return (rtree_get(&chunks_rtree, (uintptr_t)ptr, dependent));
}
#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/

#include "chunk_dss.h"
#include "chunk_mmap.h"
