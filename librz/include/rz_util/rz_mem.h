#ifndef RZ_MEM_H
#define RZ_MEM_H

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
RZ_API RMemoryPool *rz_mem_pool_deinit(RMemoryPool *pool);
RZ_API RMemoryPool *rz_mem_pool_new(int nodesize, int poolsize, int poolcount);
RZ_API RMemoryPool *rz_mem_pool_free(RMemoryPool *pool);
RZ_API void *rz_mem_pool_alloc(RMemoryPool *pool);
RZ_API void *rz_mem_dup(const void *s, int l);
RZ_API void *rz_mem_alloc(int sz);
RZ_API void rz_mem_free(void *);
RZ_API void rz_mem_memzero(void *, size_t);
RZ_API void rz_mem_reverse(ut8 *b, int l);
RZ_API int rz_mem_protect(void *ptr, int size, const char *prot);
RZ_API int rz_mem_set_num(ut8 *dest, int dest_size, ut64 num);
RZ_API int rz_mem_eq(ut8 *a, ut8 *b, int len);
RZ_API void rz_mem_copybits(ut8 *dst, const ut8 *src, int bits);
RZ_API void rz_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits);
RZ_API void rz_mem_copyloop(ut8 *dest, const ut8 *orig, int dsize, int osize);
RZ_API void *rz_mem_copy(void *dest, size_t dmax, const void *src, size_t smax);
RZ_API void rz_mem_swaporcopy(ut8 *dest, const ut8 *src, int len, bool big_endian);
RZ_API void rz_mem_swapendian(ut8 *dest, const ut8 *orig, int size);
RZ_API int rz_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len);
RZ_API const ut8 *rz_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen);
RZ_API const ut8 *rz_mem_mem_aligned(const ut8 *haystack, int hlen, const ut8 *needle, int nlen, int align);
RZ_API int rz_mem_count(const ut8 **addr);
RZ_API bool rz_mem_is_printable(const ut8 *a, int la);
RZ_API bool rz_mem_is_zero(const ut8 *b, int l);

#ifdef __cplusplus
}
#endif
#endif //  RZ_MEM_H
