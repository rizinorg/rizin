// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#if __UNIX__
#include <sys/mman.h>
#elif __WINDOWS__
#include <rz_windows.h>
#endif

#define SET_BIT(p, n) ((p) |= (1 << (n)))
#define CLR_BIT(p, n) ((p) &= (~(1) << (n)))

// TODO: find better name (rz_mem_length()); is this used somewhere?
RZ_API int rz_mem_count(const ut8 **addr) {
	int i = 0;
	while (*addr++) {
		i++;
	}
	return i;
}

/**
 * \brief Compares memory \p a with \p b over \p len bytes.
 *
 * \param a Pointer to memory \p a.
 * \param b Pointer to memory \p b.
 * \param len Number of bytes to compare.
 * \return bool True if memory bytes in memory \p a and  \p b match over \p len bytes. False otherwise.
 */
RZ_API int rz_mem_eq(const ut8 *a, const ut8 *b, int len) {
	register int i;
	for (i = 0; i < len; i++) {
		if (a[i] != b[i]) {
			return false;
		}
	}
	return true;
}

RZ_API bool rz_mem_eq_masked(const ut8 *a, const ut8 *b, const ut8 *mask, size_t size) {
	for (size_t i = 0; i < size; i++) {
		if ((a[i] & mask[i]) != (b[i] & mask[i])) {
			return false;
		}
	}
	return true;
}

RZ_API void rz_mem_copyloop(ut8 *dest, const ut8 *orig, int dsize, int osize) {
	int i = 0, j;
	while (i < dsize) {
		for (j = 0; j < osize && i < dsize; j++) {
			dest[i++] = orig[j];
		}
	}
}

RZ_API void *rz_mem_copy(void *dest, size_t dmax, const void *src, size_t smax) {
	if (!smax || !dmax) {
		return NULL;
	}
	rz_return_val_if_fail(dest && src, NULL);
	return memcpy(dest, src, (smax < dmax) ? smax : dmax);
}

RZ_API void rz_mem_copybits(ut8 *dst, const ut8 *src, int bits) {
	ut8 srcmask, dstmask;
	int bytes = (int)(bits / 8);
	bits = bits % 8;
	memcpy(dst, src, bytes);
	if (bits) {
		srcmask = dstmask = 0;
		switch (bits) {
		case 1:
			srcmask = 0x80;
			dstmask = 0x7f;
			break;
		case 2:
			srcmask = 0xc0;
			dstmask = 0x3f;
			break;
		case 3:
			srcmask = 0xe0;
			dstmask = 0x1f;
			break;
		case 4:
			srcmask = 0xf0;
			dstmask = 0x0f;
			break;
		case 5:
			srcmask = 0xf8;
			dstmask = 0x07;
			break;
		case 6:
			srcmask = 0xfc;
			dstmask = 0x03;
			break;
		case 7:
			srcmask = 0xfe;
			dstmask = 0x01;
			break;
		}
		dst[bytes] = ((dst[bytes] & dstmask) | (src[bytes] & srcmask));
	}
}

static inline char readbit(const ut8 *src, int bitoffset) {
	const int wholeBytes = bitoffset / 8;
	const int remainingBits = bitoffset % 8;
	// return (src[wholeBytes] >> remainingBits) & 1;
	return (src[wholeBytes] & 1 << remainingBits);
}

static inline void writebit(ut8 *dst, int i, bool c) {
	const int byte = i / 8;
	const int bit = (i % 8);
	// eprintf ("Write %d %d = %d\n", byte, bit, c);
	dst += byte;
	if (c) {
		// dst[byte] |= (1 << bit);
		RZ_BIT_SET(dst, bit);
	} else {
		// dst[byte] &= (1 << bit);
		RZ_BIT_UNSET(dst, bit);
	}
}

RZ_API void rz_mem_copybits_delta(ut8 *dst, int doff, const ut8 *src, int soff, int bits) {
	int i;
	if (doff < 0 || soff < 0 || !dst || !src) {
		return;
	}
	for (i = 0; i < bits; i++) {
		bool c = readbit(src, i + soff);
		writebit(dst, i + doff, c);
	}
}

RZ_API ut64 rz_mem_get_num(const ut8 *b, int size) {
	// LITTLE ENDIAN is the default for streams
	switch (size) {
	case 1:
		return rz_read_le8(b);
	case 2:
		return rz_read_le16(b);
	case 4:
		return rz_read_le32(b);
	case 8:
		return rz_read_le64(b);
	}
	return 0LL;
}

// TODO: SEE: RZ_API ut64 rz_reg_get_value(RzReg *reg, RzRegItem *item) { .. dupped code?
RZ_API int rz_mem_set_num(ut8 *dest, int dest_size, ut64 num) {
	// LITTLE ENDIAN is the default for streams
	switch (dest_size) {
	case 1:
		rz_write_le8(dest, (ut8)(num & UT8_MAX));
		break;
	case 2:
		rz_write_le16(dest, (ut16)(num & UT16_MAX));
		break;
	case 4:
		rz_write_le32(dest, (ut32)(num & UT32_MAX));
		break;
	case 8:
		rz_write_le64(dest, num);
		break;
	default:
		return false;
	}
	return true;
}

/* \brief Finds the \p needle of \p nlen size into the \p haystack of \p hlen size */
RZ_API const ut8 *rz_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen) {
	int i, until = hlen - nlen + 1;
	if (hlen < 1 || nlen < 1) {
		return NULL;
	}
	for (i = 0; i < until; i++) {
		if (!memcmp(haystack + i, needle, nlen)) {
			return haystack + i;
		}
	}
	return NULL;
}

// TODO: rename to rz_mem_mem and refactor all calls to this function
RZ_API const ut8 *rz_mem_mem_aligned(const ut8 *haystack, int hlen, const ut8 *needle, int nlen, int align) {
	int i, until = hlen - nlen + 1;
	if (align < 1) {
		align = 1;
	}
	if (hlen < 1 || nlen < 1) {
		return NULL;
	}
	if (align > 1) {
		until -= (until % align);
	}
	for (i = 0; i < until; i += align) {
		if (!memcmp(haystack + i, needle, nlen)) {
			return haystack + i;
		}
	}
	return NULL;
}

RZ_API int rz_mem_protect(void *ptr, int size, const char *prot) {
#if __UNIX__
	int p = 0;
	if (strchr(prot, 'x')) {
		p |= PROT_EXEC;
	}
	if (strchr(prot, 'r')) {
		p |= PROT_READ;
	}
	if (strchr(prot, 'w')) {
		p |= PROT_WRITE;
	}
	if (mprotect(ptr, size, p) == -1) {
		return false;
	}
#elif __WINDOWS__
	int r, w, x;
	DWORD p = PAGE_NOACCESS;
	r = strchr(prot, 'r') ? 1 : 0;
	w = strchr(prot, 'w') ? 1 : 0;
	x = strchr(prot, 'x') ? 1 : 0;
	if (w && x) {
		return false;
	}
	if (x) {
		p = PAGE_EXECUTE_READ;
	} else if (w) {
		p = PAGE_READWRITE;
	} else if (r) {
		p = PAGE_READONLY;
	}
	if (!VirtualProtect(ptr, size, p, NULL)) {
		return false;
	}
#else
#warning Unknown platform
#endif
	return true;
}

RZ_API void *rz_mem_dup(const void *s, int l) {
	void *d = malloc(l);
	if (d) {
		memcpy(d, s, l);
	}
	return d;
}

RZ_API void rz_mem_reverse(ut8 *b, int l) {
	ut8 tmp;
	int i, end = l / 2;
	for (i = 0; i < end; i++) {
		tmp = b[i];
		b[i] = b[l - i - 1];
		b[l - i - 1] = tmp;
	}
}

RZ_API bool rz_mem_is_printable(const ut8 *a, int la) {
	int i;
	for (i = 0; i < la; i++) {
		if (a[i] != '\n' && a[i] != '\t' && !IS_PRINTABLE(a[i])) {
			return false;
		}
	}
	return true;
}

RZ_API bool rz_mem_is_zero(const ut8 *b, int l) {
	int i;
	for (i = 0; i < l; i++) {
		if (b[i]) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Calculates the required padding to align the given \p address to the
 * given \p alignment.
 *
 * This is only valid for architectures with a defined alignment of n^2.
 *
 * \param address   The address to calculate the required padding for.
 * \param alignment The required alignment. It must be a power of 2 and greater than 0.
 *
 * \return The additional padding to align \p address. If \p alignment
 * is equal 0 or not a power of two it returns UT64_MAX.
 *
 * Examples:
 *
 * ```c
 * ut64 address = 0x59d;
 * ut64 padding = rz_mem_align_padding(address, 4);
 * assert(padding == 3);
 * assert(address + padding == 0x5a0);
 * ```
 */
RZ_API ut64 rz_mem_align_padding(const ut64 address, ut64 alignment) {
	size_t c = rz_bits_count_ones_ut64(alignment);
	if (c != 1) {
		rz_warn_if_reached();
		return UT64_MAX;
	}
	return (alignment - (address % alignment)) % alignment;
}

RZ_API void rz_mem_memzero(void *dst, size_t l) {
#ifdef _MSC_VER
	RtlSecureZeroMemory(dst, l);
#else
#if HAVE_EXPLICIT_BZERO
	explicit_bzero(dst, l);
#elif HAVE_EXPLICIT_MEMSET
	(void)explicit_memset(dst, 0, l);
#else
	memset(dst, 0, l);
	__asm__ volatile("" ::"r"(dst)
		: "memory");
#endif
#endif
}

/**
 * \brief Makes a copy of the buffer \p buf but starts copying data at \p offset.
 * That is: `rz_mem_align_byte(buf, n, i)` will return a copy of `buf[i:n]`.
 * The bytes `[n - i:n]` of the returned buffer are set to 0x00.
 *
 * \param buf The buffer to copy.
 * \param buf_size The size of \p buf in bytes. If 0, this function just performce a memcpy.
 * \param offset The offset to start copying from. If larger than \p buf_size,
 *        it returns a zeroed buffer of size \p buf_size.
 *
 * \return The copied buffer or NULL in case of failure. If \p offset >= \p buf_size
 *         the returned buffer is all zeros.
 *
 * NOTE: This function is useful to align the data in \p buf to a certain offset.
 * E.g. reading ut64 values from \p buf + 3 would be undefined behavior and fail under certain conditions.
 * Instead this function can be used to get a copy of the buffer at this offset:
 *
 * Example:
 * ```c
 * // This is undefined behavior, because the memory access is misaligned for ut64 values.
 * ut64 x = *((ut64 *)buf + 3);
 *
 * // Instead you can align buf with this function:
 * ut8 *out = rz_mem_align_byte(buf, buf_size, 3);
 * ut64 v = *((ut64 *)out);
 * ```
 */
RZ_API RZ_OWN ut8 *rz_mem_copy_offset(const ut8 *buf, size_t buf_size, size_t offset) {
	rz_return_val_if_fail(buf && buf_size > 0, NULL);
	ut8 *dst = RZ_NEWS0(ut8, buf_size);
	if (offset >= buf_size) {
		return dst;
	}
	if (!rz_mem_copy(dst, buf_size + offset, buf + offset, buf_size - offset)) {
		free(dst);
		return NULL;
	}
	return dst;
}

/**
 * \brief Swaps the bytes in 2 byte blocks from the given buffer and returns
 * the result.
 * Remainders of less than 2 bytes at the end of the buffer won't be swapped.
 *
 * \param buf The input buffer.
 * \param buf_size The size of the input buffer. Must be greater than 0.
 *
 * \return A clone of the input buffer with swapped bytes or NULL in case of failure.
 *
 * NOTE: This function can be used to change the endianness of 2 byte values
 * in the given buffer.
 *
 * Examples:
 * ```c
 * const ut8 a[4] = { 0xff, 0x00, 0x99, 0x00 };
 * const ut8 b[4] = { 0x00, 0xff, 0x00, 0x99 };
 * ut8 *swapped = rz_mem_swap_bytes_2(a);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 *
 * ```c
 * const ut8 a[4] = { 0xff, 0x00, 0x99, 0x00, 0x11 };
 * const ut8 b[4] = { 0x00, 0xff, 0x00, 0x99, 0x11 };
 * ut8 *swapped = rz_mem_swap_bytes_2(a);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 */
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_2(RZ_NONNULL const ut8 *buf, size_t buf_size) {
	rz_return_val_if_fail(buf && buf_size != 0, NULL);
	ut8 *dst = RZ_NEWS0(ut8, buf_size);
	if (!dst) {
		return NULL;
	}
	if (!rz_mem_copy(dst, buf_size, buf, buf_size)) {
		free(dst);
		return NULL;
	}
	return rz_mem_swap_bytes_2_inplace(dst, buf_size);
}

/**
 * \brief Swaps the bytes in 2 byte blocks from the given buffer and returns
 * the result.
 * Remainders of less than 2 bytes at the end of the buffer won't be swapped.
 *
 * \param buf The input buffer.
 * \param buf_size The size of the input buffer. Must be greater than 0.
 *
 * \return Returns \p dst or NULL in case of failure.
 *
 * NOTE: This function can be used to change the endianness of 2 byte values
 * in the given buffer.
 *
 * Examples:
 * ```c
 * ut8 a[4] = { 0xff, 0x00, 0x99, 0x00 };
 * const ut8 b[4] = { 0x00, 0xff, 0x00, 0x99 };
 * ut8 *swapped = rz_mem_swap_bytes_2(a);
 * assert(a == swapped);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 *
 * ```c
 * ut8 a[4] = { 0xff, 0x00, 0x99, 0x00, 0x11 };
 * const ut8 b[4] = { 0x00, 0xff, 0x00, 0x99, 0x11 };
 * ut8 *swapped = rz_mem_swap_bytes_2(a);
 * assert(a == swapped);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 */
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_2_inplace(RZ_OUT RZ_NONNULL ut8 *dst, size_t buf_size) {
	rz_return_val_if_fail(dst && buf_size, NULL);
	size_t al = rz_mem_ptr_alignment(dst);
	if (al < 2) {
		// malloc guarantees to return an aligned pointer for all data which fits
		// into the allocated memory.
		// So, if the pointer is only aligned to less than 2 bytes,
		// it means buf_size was == 1.
		// Hence we return simply a clone of the buffer.
		return dst;
	}

	ut64 *dst_64 = (ut64 *)dst;
	while (buf_size >= 8) {
		*dst_64 = rz_swap_2b_ut64(*dst_64);
		dst_64++;
		buf_size -= 8;
	}
	ut32 *dst_32 = (ut32 *)dst_64;
	while (buf_size >= 4) {
		*dst_32 = rz_swap_2b_ut32(*dst_32);
		dst_32++;
		buf_size -= 4;
	}
	ut16 *dst_16 = (ut16 *)dst_32;
	while (buf_size >= 2) {
		*dst_16 = rz_swap_ut16(*dst_16);
		dst_16++;
		buf_size -= 2;
	}
	return dst;
}

/**
 * \brief Swaps the bytes in 4 byte blocks from the given buffer and returns
 * the result.
 * Remainders of less than 4 bytes at the end of the buffer won't be swapped.
 *
 * \param buf The input buffer.
 * \param buf_size The size of the input buffer. Must be greater than 0.
 *
 * \return A clone of the input buffer with swapped bytes or NULL in case of failure.
 *
 * NOTE: This function can be used to change the endianness of 4 byte values
 * in the given buffer.
 *
 * Examples:
 * ```c
 * const ut8 a[4] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
 * const ut8 b[4] = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04 };
 * ut8 *swapped = rz_mem_swap_bytes_4(a);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 *
 * ```c
 * const ut8 a[4] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xfe };
 * const ut8 b[4] = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0xff, 0xfe };
 * ut8 *swapped = rz_mem_swap_bytes_4(a);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 */
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_4(RZ_NONNULL const ut8 *buf, size_t buf_size) {
	rz_return_val_if_fail(buf && buf_size != 0, NULL);
	ut8 *dst = RZ_NEWS0(ut8, buf_size);
	if (!dst) {
		return NULL;
	}
	if (!rz_mem_copy(dst, buf_size, buf, buf_size)) {
		free(dst);
		return NULL;
	}
	return rz_mem_swap_bytes_4_inplace(dst, buf_size);
}

/**
 * \brief Swaps the bytes in 4 byte blocks from the given buffer and returns
 * the result.
 * Remainders of less than 4 bytes at the end of the buffer won't be swapped.
 *
 * \param buf The input buffer.
 * \param buf_size The size of the input buffer. Must be greater than 0.
 *
 * \return Returns \p dst or NULL in case of failure.
 *
 * NOTE: This function can be used to change the endianness of 4 byte values
 * in the given buffer.
 *
 * Examples:
 * ```c
 * ut8 a[4] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
 * const ut8 b[4] = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04 };
 * ut8 *swapped = rz_mem_swap_bytes_4(a);
 * assert(a == swapped);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 *
 * ```c
 * ut8 a[4] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xfe };
 * const ut8 b[4] = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0xff, 0xfe };
 * ut8 *swapped = rz_mem_swap_bytes_4(a);
 * assert(a == swapped);
 * assert(memcmp(swapped, b, sizeof(a)) == 0);
 * ```
 */
RZ_API RZ_OWN ut8 *rz_mem_swap_bytes_4_inplace(RZ_OUT RZ_NONNULL ut8 *dst, size_t buf_size) {
	rz_return_val_if_fail(dst && buf_size, NULL);
	size_t al = rz_mem_ptr_alignment(dst);
	if (al < 4) {
		// malloc guarantees to return an aligned pointer for all data which fits
		// into the allocated memory.
		// So, if the pointer is only aligned to less than 4 bytes,
		// it means buf_size was <= 3.
		// Hence we return simply a clone of the buffer.
		return dst;
	}

	ut64 *dst_64 = (ut64 *)dst;
	while (buf_size >= 8) {
		*dst_64 = rz_swap_4b_ut64(*dst_64);
		dst_64++;
		buf_size -= 8;
	}
	ut32 *dst_32 = (ut32 *)dst_64;
	while (buf_size >= 4) {
		*dst_32 = rz_swap_ut32(*dst_32);
		dst_32++;
		buf_size -= 4;
	}
	return dst;
}
