#ifndef RZ_MEM_H
#define RZ_MEM_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_mem_pool_t {
	ut8 **nodes;
	int ncount;
	int npool;
	//
	int nodesize;
	int poolsize;
	int poolcount;
} RMemoryPool;

RZ_API ut64 rz_mem_get_num(const ut8 *b, int size);

/* MEMORY POOL */
RZ_API void *rz_mem_dup(const void *s, int l);
RZ_API void rz_mem_memzero(void *, size_t);
RZ_API void rz_mem_reverse(ut8 *b, int l);
RZ_API int rz_mem_protect(void *ptr, int size, const char *prot);
RZ_API int rz_mem_set_num(ut8 *dest, int dest_size, ut64 num);
RZ_API int rz_mem_eq(const ut8 *a, const ut8 *b, int len);
RZ_API bool rz_mem_eq_masked(const ut8 *a, const ut8 *b, const ut8 *mask, size_t size);
RZ_API void rz_mem_copybits(ut8 *dst, const ut8 *src, int bits);
RZ_API void rz_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits);
RZ_API void rz_mem_copyloop(ut8 *dest, const ut8 *orig, int dsize, int osize);
RZ_API void *rz_mem_copy(void *dest, size_t dmax, const void *src, size_t smax);
RZ_API const ut8 *rz_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen);
RZ_API const ut8 *rz_mem_mem_aligned(const ut8 *haystack, int hlen, const ut8 *needle, int nlen, int align);
RZ_API int rz_mem_count(const ut8 **addr);
RZ_API bool rz_mem_is_printable(const ut8 *a, int la);
RZ_API bool rz_mem_is_zero(const ut8 *b, int l);

#ifdef __cplusplus
}
#endif
#endif //  RZ_MEM_H
