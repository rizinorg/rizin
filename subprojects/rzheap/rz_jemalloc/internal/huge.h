/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

void	*huge_malloc(tsdn_t *tsdn, arena_t *arena, GHT usize, bool zero);
void	*huge_palloc(tsdn_t *tsdn, arena_t *arena, GHT usize,
    GHT alignment, bool zero);
bool	huge_ralloc_no_move(tsdn_t *tsdn, GHT ptr, GHT oldsize,
    GHT usize_min, GHT usize_max, bool zero);
void	*huge_ralloc(tsd_t *tsd, arena_t *arena, GHT ptr, GHT oldsize,
    GHT usize, GHT alignment, bool zero, tcache_t *tcache);
#ifdef JEMALLOC_JET
typedef void (huge_dalloc_junk_t)(GHT , GHT);
extern huge_dalloc_junk_t *huge_dalloc_junk;
#endif
void	huge_dalloc(tsdn_t *tsdn, GHT ptr);
arena_t	*huge_aalloc(const GHT ptr);
GHT	huge_salloc(tsdn_t *tsdn, const GHT ptr);
prof_tctx_t	*huge_prof_tctx_get(tsdn_t *tsdn, const GHT ptr);
void	huge_prof_tctx_set(tsdn_t *tsdn, const GHT ptr, prof_tctx_t *tctx);
void	huge_prof_tctx_reset(tsdn_t *tsdn, const GHT ptr);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
