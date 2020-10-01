#ifndef R2_BINHEAP_H
#define R2_BINHEAP_H

#include "rz_vector.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_binheap_t {
	RPVector a;
	RPVectorComparator cmp;
} RBinHeap;

RZ_API void rz_binheap_clear(RBinHeap *h);
#define rz_binheap_empty(h) (rz_pvector_empty (&(h)->a))
RZ_API void rz_binheap_init(RBinHeap *h, RPVectorComparator cmp);
RZ_API RBinHeap *rz_binheap_new(RPVectorComparator cmp);
RZ_API void rz_binheap_free(RBinHeap *h);
RZ_API bool rz_binheap_push(RBinHeap *h, void *x);
RZ_API void *rz_binheap_pop(RBinHeap *h);
#define rz_binheap_top(h) (rz_pvector_at(&((h)->a), 0))

#ifdef __cplusplus
}
#endif

#endif
