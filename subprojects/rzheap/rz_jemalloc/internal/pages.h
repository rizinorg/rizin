/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

void	*pages_map(GHT addr, GHT size, bool *commit);
void	pages_unmap(GHT addr, GHT size);
void	*pages_trim(GHT addr, GHT alloc_size, GHT leadsize,
    GHT size, bool *commit);
bool	pages_commit(GHT addr, GHT size);
bool	pages_decommit(GHT addr, GHT size);
bool	pages_purge(GHT addr, GHT size);
bool	pages_huge(GHT addr, GHT size);
bool	pages_nohuge(GHT addr, GHT size);
void	pages_boot(void);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/

