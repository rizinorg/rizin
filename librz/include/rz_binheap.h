#ifndef RZ_BINHEAP_H
#define RZ_BINHEAP_H

#include "rz_vector.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_binheap_t {
	RzPVector a;
	RzPVectorComparator cmp;
} RzBinHeap;

RZ_API void rz_binheap_clear(RzBinHeap *h);
#define rz_binheap_empty(h) (rz_pvector_empty(&(h)->a))
RZ_API void rz_binheap_init(RzBinHeap *h, RzPVectorComparator cmp);
RZ_API RzBinHeap *rz_binheap_new(RzPVectorComparator cmp);
RZ_API void rz_binheap_free(RzBinHeap *h);
RZ_API bool rz_binheap_push(RzBinHeap *h, void *x);
RZ_API void *rz_binheap_pop(RzBinHeap *h);
#define rz_binheap_top(h) (rz_pvector_at(&((h)->a), 0))

#ifdef __cplusplus
}
#endif

#endif
