#ifndef RZ_ALLOC_H
#define RZ_ALLOC_H

#include <rz_types.h>
#include <stdlib.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN void *rz_mem_alloc(size_t sz);
RZ_API void rz_mem_free(void *);
RZ_API RZ_OWN void *rz_malloc_aligned(size_t size, size_t alignment);
RZ_API void rz_free_aligned(void *p);

#ifdef __cplusplus
}
#endif
#endif //  RZ_ALLOC_H
