#include <rz_util/rz_iterator.h>
#include <rz_util/rz_assert.h>

RZ_API RzIterator *rz_iterator_new(F_RzIterator next, F_RzIterator_FREE free, F_RzIterator_FREE free_u, void *u) {
	rz_return_val_if_fail(next, NULL);
	RzIterator *it = RZ_NEW0(RzIterator);
	it->next = next;
	it->u = u;
	it->free = free;
	it->free_u = free_u;
	return it;
}

RZ_API void *rz_iterator_next(RzIterator *it) {
	rz_return_val_if_fail(it && it->next, NULL);
	void *cur = it->next(it);
	if (it->free) {
		it->free(it->cur);
	}
	it->cur = cur;
	return cur;
}

RZ_API void rz_iterator_free(RzIterator *it) {
	if (!it) {
		return;
	}
	if (it->free) {
		it->free(it->cur);
	}
	if (it->free_u) {
		it->free_u(it->u);
	}
	free(it);
}