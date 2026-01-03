/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct GH(nstime_s) GH(nstime_t);

/* Maximum supported number of seconds (~584 years). */
#define	NSTIME_SEC_MAX	KQU(18446744072)

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

struct GH(nstime_s) {
	uint64_t	ns;
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

void	nstime_init(GH(nstime_t) *time, uint64_t ns);
void	nstime_init2(GH(nstime_t) *time, uint64_t sec, uint64_t nsec);
uint64_t	nstime_ns(const GH(nstime_t) *time);
uint64_t	nstime_sec(const GH(nstime_t) *time);
uint64_t	nstime_nsec(const GH(nstime_t) *time);
void	nstime_copy(GH(nstime_t) *time, const GH(nstime_t) *source);
int	nstime_compare(const GH(nstime_t) *a, const GH(nstime_t) *b);
void	nstime_add(GH(nstime_t) *time, const GH(nstime_t) *addend);
void	nstime_subtract(GH(nstime_t) *time, const GH(nstime_t) *subtrahend);
void	nstime_imultiply(GH(nstime_t) *time, uint64_t multiplier);
void	nstime_idivide(GH(nstime_t) *time, uint64_t divisor);
uint64_t	nstime_divide(const GH(nstime_t) *time, const GH(nstime_t) *divisor);
#ifdef JEMALLOC_JET
typedef bool (nstime_monotonic_t)(void);
extern nstime_monotonic_t *nstime_monotonic;
typedef bool (nstime_update_t)(GH(nstime_t) *);
extern nstime_update_t *nstime_update;
#else
bool	nstime_monotonic(void);
bool	nstime_update(GH(nstime_t) *time);
#endif

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
