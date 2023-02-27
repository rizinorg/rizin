#ifndef RZ_ALLOC_H
#define RZ_ALLOC_H

#include <rz_types.h>
#include <stdlib.h>
#include <stddef.h>

RZ_API void *rz_malloc_aligned(size_t size, size_t alignment);
RZ_API void rz_free_aligned(void *p);

#endif
