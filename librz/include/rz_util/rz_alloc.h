#ifndef _R_UTIL_ALLOC_H_
#define _R_UTIL_ALLOC_H_ 1

#include <rz_types.h>
#include <stdlib.h>
#include <stddef.h>

#define RZ_MALLOC_WRAPPER 0
#define RZ_MALLOC_GLOBAL  0

typedef void *(RMalloc)(size_t);
typedef void *(RCalloc)(size_t, size_t);
typedef void *(RRealloc)(void *, size_t);
typedef void(RFree)(void *);

RZ_API void *rz_malloc_aligned(size_t size, size_t alignment);
RZ_API void rz_free_aligned(void *p);

#if RZ_MALLOC_WRAPPER

RZ_API void rz_alloc_hooks(RMalloc m, RCalloc c, RRealloc r, RFree f);

#if RZ_MALLOC_GLOBAL
RZ_API RMalloc *rz_malloc;
RZ_API RCalloc *rz_calloc;
RZ_API RRealloc *rz_realloc;
RZ_API RFree *rz_free;
#define _r_malloc  rz_malloc
#define _r_calloc  rz_calloc
#define _r_free    rz_free
#define _r_realloc rz_realloc
#else
RZ_API void *rz_malloc(size_t sz);
RZ_API void *rz_calloc(size_t count, size_t sz);
RZ_API void *rz_realloc(void *p, size_t sz);
RZ_API void rz_free(void *p);
#endif

#else

#define rz_malloc(x)     malloc((x))
#define rz_calloc(x, y)  calloc((x), (y))
#define rz_realloc(x, y) realloc((x), (y))
#define rz_free(x)       free((x))

#define _r_malloc  rz_malloc
#define _r_calloc  rz_calloc
#define _r_free    rz_free
#define _r_realloc rz_realloc

#endif

#endif
