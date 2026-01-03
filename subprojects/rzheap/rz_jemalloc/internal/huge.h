/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

void	*huge_malloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT usize, bool zero);
void	*huge_palloc(GH(tsdn_t) *tsdn, GH(arena_t) *arena, GHT usize,
    GHT alignment, bool zero);
bool	huge_ralloc_no_move(GH(tsdn_t) *tsdn, GHT ptr, GHT oldsize,
    GHT usize_min, GHT usize_max, bool zero);
void	*huge_ralloc(GH(tsd_t) *tsd, GH(arena_t) *arena, GHT ptr, GHT oldsize,
    GHT usize, GHT alignment, bool zero, GH(tcache_t) *tcache);
#ifdef JEMALLOC_JET
typedef void (huge_dalloc_junk_t)(GHT , GHT);
extern huge_dalloc_junk_t *huge_dalloc_junk;
#endif
void	huge_dalloc(GH(tsdn_t) *tsdn, GHT ptr);
GH(arena_t)	*huge_aalloc(const GHT ptr);
GHT	huge_salloc(GH(tsdn_t) *tsdn, const GHT ptr);
GH(prof_tctx_t)	*huge_prof_tctx_get(GH(tsdn_t) *tsdn, const GHT ptr);
void	huge_prof_tctx_set(GH(tsdn_t) *tsdn, const GHT ptr, GH(prof_tctx_t) *tctx);
void	huge_prof_tctx_reset(GH(tsdn_t) *tsdn, const GHT ptr);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
