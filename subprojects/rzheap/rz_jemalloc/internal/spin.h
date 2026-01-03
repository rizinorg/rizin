/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct GH(spin_s) GH(spin_t);

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

struct GH(spin_s) {
	unsigned iteration;
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
void	spin_init(GH(spin_t) *spin);
void	spin_adaptive(GH(spin_t) *spin);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_SPIN_C_))
JEMALLOC_INLINE void
spin_init(GH(spin_t) *spin)
{

	spin->iteration = 0;
}

JEMALLOC_INLINE void
spin_adaptive(GH(spin_t) *spin)
{
	volatile uint64_t i;

	for (i = 0; i < (KQU(1) << spin->iteration); i++)
		CPU_SPINWAIT;

	if (spin->iteration < 63)
		spin->iteration++;
}

#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/

