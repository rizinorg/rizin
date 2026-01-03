/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct GH(ctl_node_s) GH(ctl_node_t);
typedef struct GH(ctl_named_node_s) GH(ctl_named_node_t);
typedef struct GH(ctl_indexed_node_s) GH(ctl_indexed_node_t);
typedef struct GH(ctl_arena_stats_s) GH(ctl_arena_stats_t);
typedef struct GH(ctl_stats_s) GH(ctl_stats_t);

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

struct GH(ctl_node_s) {
	bool			named;
};

struct GH(ctl_named_node_s) {
	struct GH(ctl_node_s)	node;
	const char		*name;
	/* If (nchildren == 0), this is a terminal node. */
	unsigned		nchildren;
	const			GH(ctl_node_t) *children;
	int			(*ctl)(GH(tsd_t) *, const GHT *, GHT, GHT ,
	    GHT *, GHT , GHT);
};

struct GH(ctl_indexed_node_s) {
	struct GH(ctl_node_s)	node;
	const GH(ctl_named_node_t)	*(*index)(GH(tsdn_t) *, const GHT *, GHT,
	    GHT);
};

struct GH(ctl_arena_stats_s) {
	bool			initialized;
	unsigned		nthreads;
	const char		*dss;
	GHST			lg_dirty_mult;
	GHST			decay_time;
	GHT			pactive;
	GHT			pdirty;

	/* The remainder are only populated if config_stats is true. */

	GH(arena_stats_t)		astats;

	/* Aggregate stats for small size classes, based on bin stats. */
	GHT			allocated_small;
	uint64_t		nmalloc_small;
	uint64_t		ndalloc_small;
	uint64_t		nrequests_small;

	GH(malloc_bin_stats_t)	bstats[JM_NBINS];
	GH(malloc_large_stats_t)	*lstats;	/* nlclasses elements. */
	GH(malloc_huge_stats_t)	*hstats;	/* nhclasses elements. */
};

struct GH(ctl_stats_s) {
	GHT			allocated;
	GHT			active;
	GHT			metadata;
	GHT			resident;
	GHT			mapped;
	GHT			retained;
	unsigned		narenas;
	GH(ctl_arena_stats_t)	*arenas;	/* (narenas + 1) elements. */
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

int	ctl_byname(GH(tsd_t) *tsd, const char *name, GHT oldp, GHT *oldlenp,
    GHT newp, GHT newlen);
int	ctl_nametomib(GH(tsdn_t) *tsdn, const char *name, GHT *mibp,
    GHT *miblenp);

int	ctl_bymib(GH(tsd_t) *tsd, const GHT *mib, GHT miblen, GHT oldp,
    GHT *oldlenp, GHT newp, GHT newlen);
bool	ctl_boot(void);
void	ctl_prefork(GH(tsdn_t) *tsdn);
void	ctl_postfork_parent(GH(tsdn_t) *tsdn);
void	ctl_postfork_child(GH(tsdn_t) *tsdn);

#define	xmallctl(name, oldp, oldlenp, newp, newlen) do {		\
	if (je_mallctl(name, oldp, oldlenp, newp, newlen)		\
	    != 0) {							\
		malloc_printf(						\
		    "<jemalloc>: Failure in xmallctl(\"%s\", ...)\n",	\
		    name);						\
		abort();						\
	}								\
} while (0)

#define	xmallctlnametomib(name, mibp, miblenp) do {			\
	if (je_mallctlnametomib(name, mibp, miblenp) != 0) {		\
		malloc_printf("<jemalloc>: Failure in "			\
		    "xmallctlnametomib(\"%s\", ...)\n", name);		\
		abort();						\
	}								\
} while (0)

#define	xmallctlbymib(mib, miblen, oldp, oldlenp, newp, newlen) do {	\
	if (je_mallctlbymib(mib, miblen, oldp, oldlenp, newp,		\
	    newlen) != 0) {						\
		malloc_write(						\
		    "<jemalloc>: Failure in xmallctlbymib()\n");	\
		abort();						\
	}								\
} while (0)

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/

