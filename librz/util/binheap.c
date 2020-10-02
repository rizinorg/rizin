/* rizin - LGPL - Copyright 2017-2018 - maskray */

#include "rz_binheap.h"

static inline void _heap_down(RBinHeap *h, size_t i, void *x) {
	size_t j;
	for (; j = i * 2 + 1, j < h->a.v.len; i = j) {
		if (j + 1 < h->a.v.len && h->cmp (rz_pvector_at (&h->a, j+1), rz_pvector_at (&h->a, j)) < 0) {
			j++;
		}
		if (h->cmp (rz_pvector_at (&h->a, j), x) >= 0) {
			break;
		}
		rz_pvector_set (&h->a, i, rz_pvector_at (&h->a, j));
	}
	if (i < h->a.v.len) {
		rz_pvector_set (&h->a, i, x);
	}
}

static inline void _heap_up(RBinHeap *h, size_t i, void *x) {
	size_t j;
	for (; i && (j = (i-1) >> 1, h->cmp (x, rz_pvector_at (&h->a, j)) < 0); i = j) {
		rz_pvector_set (&h->a, i, rz_pvector_at (&h->a, j));
	}
	rz_pvector_set (&h->a, i, x);
}

RZ_API void rz_binheap_clear(RBinHeap *h) {
	rz_pvector_clear (&h->a);
}

RZ_API void rz_binheap_init(RBinHeap *h, RzPVectorComparator cmp) {
	rz_pvector_init (&h->a, NULL);
	h->cmp = cmp;
}

RZ_API void rz_binheap_free(RBinHeap *h) {
	rz_binheap_clear (h);
	free (h);
}

RZ_API RBinHeap *rz_binheap_new(RzPVectorComparator cmp) {
	RBinHeap *h = RZ_NEW (RBinHeap);
	if (!h) {
		return NULL;
	}
	rz_pvector_init (&h->a, NULL);
	h->cmp = cmp;
	return h;
}

RZ_API void *rz_binheap_pop(RBinHeap *h) {
	void *ret = rz_pvector_at (&h->a, 0);
	_heap_down (h, 0, rz_pvector_pop (&h->a));
	return ret;
}

RZ_API bool rz_binheap_push(RBinHeap *h, void *x) {
	if (!rz_pvector_push (&h->a, NULL)) {
		return false;
	}
	_heap_up (h, h->a.v.len - 1, x);
	return true;
}
