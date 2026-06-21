#ifndef RZ_MEM_H
#define RZ_MEM_H

#include <rz_util/rz_bits.h>
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
RZ_API ut64 rz_mem_align_padding(const ut64 address, ut64 alignment);
RZ_API RZ_OWN ut8 *rz_mem_copy_offset(const ut8 *buf, size_t buf_size, size_t offset);
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_2(RZ_NONNULL const ut8 *buf, size_t buf_size);
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_2_inplace(RZ_OUT RZ_NONNULL ut8 *buf, size_t buf_size);
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_4(RZ_NONNULL const ut8 *buf, size_t buf_size);
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_4_inplace(RZ_OUT RZ_NONNULL ut8 *buf, size_t buf_size);

/**
 * \brief Returns the alignment of the \p ptr.
 *
 * \param ptr The pointer to get the alignment for.
 *
 * \return Returns the pointer alignment or UT64_MAX if \p ptr == NULL or ((utptr) ptr) == 0.
 */
static inline ut64 rz_mem_ptr_alignment(RZ_NONNULL const void *ptr) {
	if (ptr == NULL || ((utptr)ptr) == 0) {
		return UT64_MAX;
	}
	return 1ull << rz_bits_trailing_zeros((utptr)ptr);
}

/**
 * \brief Reverses the byte order of an arbitrary sized byte array. There are no alignment requirements for \p bytes.
 * \param bytes The byte array.
 * \param n Length of the byte array.
 */
static inline RZ_OWN ut8 *rz_mem_swap_bytes_n_inplace(RZ_NONNULL RZ_INOUT ut8 *bytes, ut32 n) {
	rz_return_val_if_fail(bytes, NULL);
	for (ut32 i = 0; i < n / 2; i++) {
		ut32 j = n - i - 1;
		ut8 tmp = bytes[i];
		bytes[i] = bytes[j];
		bytes[j] = tmp;
	}
	return bytes;
}

#ifdef __cplusplus
}
#endif
#endif //  RZ_MEM_H
