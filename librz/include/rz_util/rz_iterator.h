

#ifndef RIZIN_RZ_ITERATOR_H
#define RIZIN_RZ_ITERATOR_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rz_iterator_t;
typedef void *(*F_RzIterator)(struct rz_iterator_t *);
typedef void (*F_RzIterator_FREE)(void *);

typedef struct rz_iterator_t {
	void *cur;
	void *u;
	F_RzIterator next;
	F_RzIterator_FREE free;
	F_RzIterator_FREE free_u;
} RzIterator;

#define rz_iterator_foreach(T, iter, val) \
	for ((val) = (T)rz_iterator_next(iter); (val) != NULL; (val) = (T)rz_iterator_next(iter))

RZ_API RzIterator *rz_iterator_new(F_RzIterator next, F_RzIterator_FREE free, F_RzIterator_FREE free_u, void *u);
RZ_API void *rz_iterator_next(RzIterator *it);
RZ_API void rz_iterator_free(RzIterator *it);

#ifdef __cplusplus
}
#endif

#endif // RIZIN_RZ_ITERATOR_H
