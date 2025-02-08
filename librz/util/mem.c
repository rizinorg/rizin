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
 * ut64 address = 0x59d;
 * ut64 padding = rz_mem_align_padding(address, 4);
 * assert(padding == 3);
 * assert(address + padding == 0x5a0);
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
