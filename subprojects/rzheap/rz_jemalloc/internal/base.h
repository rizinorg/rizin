/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

void	*base_alloc(GH(tsdn_t) *tsdn, GHT size);
void	base_stats_get(GH(tsdn_t) *tsdn, GHT *allocated, GHT *resident,
    GHT *mapped);
bool	base_boot(void);
void	base_prefork(GH(tsdn_t) *tsdn);
void	base_postfork_parent(GH(tsdn_t) *tsdn);
void	base_postfork_child(GH(tsdn_t) *tsdn);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
