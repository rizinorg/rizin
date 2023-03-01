// SPDX-FileCopyrightText: 2019-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_alloc.h>

RZ_API RZ_OWN void *rz_malloc_aligned(size_t size, size_t alignment) {
#if HAVE_POSIX_MEMALIGN
	void *result = NULL;
	if (posix_memalign(&result, alignment, size) != 0) {
		return NULL;
	}
	return result;
#elif HAVE__ALIGNED_MALLOC
	return _aligned_malloc(size, alignment);
#else
	int offset = alignment - 1 + sizeof(void *);
	void *p1 = malloc(size + offset);
	if (!p1) {
		return NULL;
	}
	void **p2 = (void **)(((size_t)(p1) + offset) & ~(alignment - 1));
	p2[-1] = p1;
	return p2;
#endif
}

RZ_API void rz_free_aligned(void *p) {
#if HAVE_POSIX_MEMALIGN
	free(p);
#elif HAVE__ALIGNED_MALLOC
	_aligned_free(p);
#else
	free(((void **)p)[-1]);
#endif
}

RZ_API RZ_OWN void *rz_mem_alloc(size_t sz) {
	return calloc(sz, 1);
}

RZ_API void rz_mem_free(void *p) {
	free(p);
}
