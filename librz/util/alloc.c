// SPDX-FileCopyrightText: 2019-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_alloc.h>

RZ_API void rz_alloc_init(void) {
#if RZ_MALLOC_WRAPPER
	rz_alloc_hooks(malloc, calloc, realloc, free);
#endif
}

#if RZ_MALLOC_WRAPPER

#if RZ_MALLOC_GLOBAL
RZ_API RMalloc *rz_malloc = malloc;
RZ_API RCalloc *rz_calloc = calloc;
RZ_API RRealloc *rz_realloc = realloc;
RZ_API RFree *rz_free = free;

RZ_API void rz_alloc_hooks(RMalloc m, RCalloc c, RRealloc r, RFree f) {
	rz_return_if_fail(m && c && r && f);
	rz_malloc = m;
	rz_calloc = c;
	rz_realloc = r;
	rz_free = f;
}

#else

static RMalloc *_r_malloc = malloc;
static RCalloc *_r_calloc = calloc;
static RRealloc *_r_realloc = realloc;
static RFree *_r_free = free;

RZ_API void rz_alloc_hooks(RMalloc m, RCalloc c, RRealloc r, RFree f) {
	rz_return_if_fail(m && c && r && f);
	_r_malloc = m;
	_r_calloc = c;
	_r_realloc = r;
	_r_free = f;
}

RZ_API void *rz_malloc(size_t sz) {
	return _r_malloc(sz);
}

RZ_API void *rz_calloc(size_t count, size_t sz) {
	return _r_calloc(count, sz);
}

RZ_API void *rz_realloc(void *p, size_t sz) {
	return _r_realloc(p, sz);
}

RZ_API void rz_free(void *p) {
	return _r_free(p);
}
#endif
#endif

RZ_API void *rz_malloc_aligned(size_t size, size_t alignment) {
	int offset = alignment - 1 + sizeof(void *);
	void *p1 = _r_malloc(size + offset);
	if (!p1) {
		return NULL;
	}
	void **p2 = (void **)(((size_t)(p1) + offset) & ~(alignment - 1));
	p2[-1] = p1;
	return p2;
}

RZ_API void rz_free_aligned(void *p) {
	_r_free(((void **)p)[-1]);
}
