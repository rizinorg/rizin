/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct GH(ticker_s) GH(ticker_t);

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

struct GH(ticker_s) {
	int32_t	tick;
	int32_t	nticks;
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
void	ticker_init(GH(ticker_t) *ticker, int32_t nticks);
void	ticker_copy(GH(ticker_t) *ticker, const GH(ticker_t) *other);
int32_t	ticker_read(const GH(ticker_t) *ticker);
bool	ticker_ticks(GH(ticker_t) *ticker, int32_t nticks);
bool	ticker_tick(GH(ticker_t) *ticker);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_TICKER_C_))
JEMALLOC_INLINE void
ticker_init(GH(ticker_t) *ticker, int32_t nticks)
{

	ticker->tick = nticks;
	ticker->nticks = nticks;
}

JEMALLOC_INLINE void
ticker_copy(GH(ticker_t) *ticker, const GH(ticker_t) *other)
{

	*ticker = *other;
}

JEMALLOC_INLINE int32_t
ticker_read(const GH(ticker_t) *ticker)
{

	return (ticker->tick);
}

JEMALLOC_INLINE bool
ticker_ticks(GH(ticker_t) *ticker, int32_t nticks)
{

	if (unlikely(ticker->tick < nticks)) {
		ticker->tick = ticker->nticks;
		return (true);
	}
	ticker->tick -= nticks;
	return(false);
}

JEMALLOC_INLINE bool
ticker_tick(GH(ticker_t) *ticker)
{

	return (ticker_ticks(ticker, 1));
}
#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
