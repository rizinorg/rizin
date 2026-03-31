// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util.h"
#include <stdlib.h>
#include <stdio.h>

#define NELEM(N, ELEMPER) ((N + (ELEMPER) - 1) / (ELEMPER))
#define BV_ELEM_SIZE      8U

// optimization for reversing 8 bits which uses 32 bits
// https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits
#define reverse_byte(x) ((((x) * 0x0802LU & 0x22110LU) | ((x) * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16)

// https://graphics.stanford.edu/~seander/bithacks.html#BitReverseObvious
// With changes.
ut8 reverse_lt_8bits(ut8 x, ut8 w) {
	ut8 m = ~(UT8_MAX << w); // values bitmask
	ut8 v = (x & m); // input bits to be reversed
	ut8 r = v; // r will be reversed bits of v; first get LSB of v
	int s = w - 1; // extra shift needed at end

	for (v >>= 1; v; v >>= 1) {
		r <<= 1;
		r |= v & 1;
		s--;
	}
	r <<= s; // shift when v's highest bits are zero
	return r;
}

/**
 * \brief Resize or allocate bv->large_a to \p new_size bytes.
 */
static void resize_large_a(RzBitVector *bv, size_t n_bytes) {
	if (bv->stack_alloc) {
		bv->bits.large_a = RZ_NEWS0(ut8, n_bytes);
		bv->stack_alloc = false;
	} else if (!bv->bits.large_a) {
		bv->bits.large_a = RZ_NEWS0(ut8, n_bytes);
	} else {
		bv->bits.large_a = realloc(bv->bits.large_a, n_bytes);
	}
	bv->_elem_len = n_bytes;
}

/**
 * \brief Initialize a RzBitVector structure
 * \param bv Pointer to a uninitialized RzBitVector instance
 * \param length int, the length of bitvector
 * \return true if succeed
 */
RZ_API bool rz_bv_init(RZ_NONNULL RzBitVector *bv, ut32 length) {
	rz_return_val_if_fail(bv && length, false);
	memset(bv, 0, sizeof(RzBitVector));
	if (length > 64) {
		// how much ut8 do we need to represent `length` bits ?
		size_t real_elem_cnt = NELEM(length, BV_ELEM_SIZE);
		ut8 *tmp = RZ_NEWS0(ut8, real_elem_cnt);
		if (!tmp) {
			return false;
		}
		bv->bits.large_a = tmp;
		bv->_elem_len = real_elem_cnt;
	}
	bv->len = length;
	return true;
}

/**
 * \brief Clear a RzBitVector structure
 */
RZ_API void rz_bv_fini(RZ_NONNULL RzBitVector *bv) {
	rz_return_if_fail(bv);
	if (bv->bits.large_a && !bv->stack_alloc) {
		free(bv->bits.large_a);
	}
	memset(bv, 0, sizeof(RzBitVector));
}

/**
 * New a `length`-bits bitvector
 * \param length int, the length of bitvector
 * \return bv RzBitVector, pointer to the new bitvector instance
 */
RZ_API RZ_OWN RzBitVector *rz_bv_new(ut32 length) {
	rz_return_val_if_fail(length, NULL);
	RzBitVector *bv = RZ_NEW0(RzBitVector);
	if (!bv || !rz_bv_init(bv, length)) {
		free(bv);
		return NULL;
	}
	return bv;
}

/**
 * Free a bitvector
 * \param bv RzBitVector, pointer to the bitvector you want to free
 */
RZ_API void rz_bv_free(RZ_NULLABLE RzBitVector *bv) {
	if (!bv) {
		return;
	}
	rz_bv_fini(bv);
	free(bv);
}

/**
 * Return bitvector string
 * \param bv RzBitVector, pointer to bitvector
 * \return str char*, bitvector string
 */
RZ_API RZ_OWN char *rz_bv_as_string(RZ_NONNULL const RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	char *str = (char *)malloc(bv->len + 1);
	if (!str) {
		return NULL;
	}

	for (ut32 i = bv->len - 1, j = 0; i > 0; --i, j++) {
		str[j] = rz_bv_get(bv, i) ? '1' : '0';
	}
	str[bv->len - 1] = rz_bv_get(bv, 0) ? '1' : '0';
	str[bv->len] = '\0';

	return str;
}

/**
 * Return bitvector string in hexadecimal format
 * \param bv RzBitVector, pointer to bitvector
 * \param pad whether to prepend leading zeroes to indicate the bitvector size
 * \return str char*, bitvector string in hexadecimal format
 */
RZ_API RZ_OWN char *rz_bv_as_hex_string(RZ_NONNULL const RzBitVector *bv, bool pad) {
	rz_return_val_if_fail(bv, NULL);

	if (bv->len <= 64) {
		if (pad) {
			char format[32] = { 0 };
			rz_strf(format, "0x%%0%d" PFMT64x, (bv->len + 3) / 4);
			return rz_str_newf(format, bv->bits.small_u);
		} else {
			return rz_str_newf("0x%" PFMT64x, bv->bits.small_u);
		}
	}

	const char *hex = "0123456789abcdef";
	size_t str_len = (NELEM(bv->len, BV_ELEM_SIZE) << 1) + 3; // 0x + \0
	char *str = (char *)malloc(str_len);
	if (!str) {
		return NULL;
	}

	str[0] = '0';
	str[1] = 'x';
	ut32 j = 2;
	ut32 n_elem = NELEM(bv->len, BV_ELEM_SIZE);
	for (ut32 i = 0; i < n_elem; i++) {
		ut8 b8 = bv->bits.large_a[n_elem - i - 1];
		ut8 high = b8 >> 4;
		ut8 low = b8 & 15;
		if (pad || high) {
			str[j++] = hex[high];
			pad = true; // pad means "print all" from now on
		}
		if (pad || low || i == n_elem - 1) {
			str[j++] = hex[low];
			pad = true; // pad means "print all" from now on
		}
	}
	str[j] = '\0';

	return str;
}

/**
 * Clone a bitvector
 * \param bv RzBitVector, pointer to the source bitvector
 * \return dup RzBitVector, pointer to a new bitvector, which is a copy of source
 */
RZ_API RZ_OWN RzBitVector *rz_bv_dup(const RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	RzBitVector *new_bv = rz_bv_new(bv->len);
	if (!new_bv || !rz_bv_copy(new_bv, bv)) {
		rz_bv_free(new_bv);
		return NULL;
	}

	return new_bv;
}

/**
 * Copy from source bitvector to destination bitvector.
 * The bitvectors must have the same length.
 *
 * \param dst RzBitVector, the destination bitvector
 * \param src RzBitVector, the source bitvector
 * \return Actual size of copy
 */
RZ_API ut32 rz_bv_copy(RZ_NONNULL RzBitVector *dst, RZ_NONNULL const RzBitVector *src) {
	rz_return_val_if_fail(src && dst, 0);

	if (dst->len != src->len) {
		rz_warn_if_reached();
		return 0;
	} else if (dst->len <= 64) {
		dst->bits.small_u = src->bits.small_u;
		return sizeof(dst->bits.small_u);
	}

	rz_return_val_if_fail(src->bits.large_a && dst->bits.large_a, 0);
	size_t n = RZ_MIN(dst->_elem_len, src->_elem_len);
	memcpy(dst->bits.large_a, src->bits.large_a, n);
	return n;
}

/**
 * \brief Optimized version of rz_bv_copy_nbits() for large bitvectors (more than 64 bits) with bit positions aligned to BV_ELEM_SIZE
 */
static ut32 bv_copy_nbits_large_aligned(RzBitVector *dst, ut32 dst_start_pos, const RzBitVector *src, ut32 src_start_pos, ut32 nbit) {
	// Sanity check performed by caller
	ut8 start_bits = RZ_MIN((BV_ELEM_SIZE - dst_start_pos) % BV_ELEM_SIZE, nbit);
	ut8 trailing_bits = RZ_MIN((src_start_pos + nbit) % BV_ELEM_SIZE, nbit - start_bits);
	ut32 middle_bytes = (nbit - start_bits) / BV_ELEM_SIZE;
	ut32 src_byte = src_start_pos / BV_ELEM_SIZE;
	ut32 dst_byte = dst_start_pos / BV_ELEM_SIZE;

	// Handle starting bits
	if (start_bits > 0) {
		ut8 src_offset = src_start_pos % BV_ELEM_SIZE;
		dst->bits.large_a[dst_byte] = rz_bits_copy_ut8(src->bits.large_a[src_byte], src_offset, dst->bits.large_a[dst_byte], src_offset, start_bits);
		src_byte++;
		dst_byte++;
	}

	// Handle middle bytes
	if (middle_bytes > 0) {
		if (src->bits.large_a == dst->bits.large_a) {
			// Copy within the same vector
			memmove(&dst->bits.large_a[dst_byte], &src->bits.large_a[src_byte], middle_bytes);
		} else {
			memcpy(&dst->bits.large_a[dst_byte], &src->bits.large_a[src_byte], middle_bytes);
		}

		src_byte += middle_bytes;
		dst_byte += middle_bytes;
	}

	// Handle trailing bits
	if (trailing_bits > 0) {
		dst->bits.large_a[dst_byte] = rz_bits_copy_ut8(src->bits.large_a[src_byte], 0, dst->bits.large_a[dst_byte], 0, trailing_bits);
	}

	return nbit;
}

/**
 * \brief Optimized version of rz_bv_copy_nbits() for copying bit range from a large bitvector to a small one
 */
static ut32 bv_copy_nbits_large_to_small(RzBitVector *dst, ut32 dst_start_pos, const RzBitVector *src, ut32 src_start_pos, ut32 nbit) {
	ut64 buffer = 0;
	ut8 start_bits = RZ_MIN((BV_ELEM_SIZE - src_start_pos) % BV_ELEM_SIZE, nbit);
	ut32 byte_index = (src_start_pos + start_bits) / BV_ELEM_SIZE;

	switch ((nbit - start_bits + 7) / BV_ELEM_SIZE) {
	case 8:
		buffer |= ((ut64)src->bits.large_a[byte_index + 7]) << (BV_ELEM_SIZE * 7);
		// fallthrough
	case 7:
		buffer |= ((ut64)src->bits.large_a[byte_index + 6]) << (BV_ELEM_SIZE * 6);
		// fallthrough
	case 6:
		buffer |= ((ut64)src->bits.large_a[byte_index + 5]) << (BV_ELEM_SIZE * 5);
		// fallthrough
	case 5:
		buffer |= ((ut64)src->bits.large_a[byte_index + 4]) << (BV_ELEM_SIZE * 4);
		// fallthrough
	case 4:
		buffer |= ((ut64)src->bits.large_a[byte_index + 3]) << (BV_ELEM_SIZE * 3);
		// fallthrough
	case 3:
		buffer |= ((ut64)src->bits.large_a[byte_index + 2]) << (BV_ELEM_SIZE * 2);
		// fallthrough
	case 2:
		buffer |= ((ut64)src->bits.large_a[byte_index + 1]) << (BV_ELEM_SIZE);
		// fallthrough
	case 1:
		buffer |= ((ut64)src->bits.large_a[byte_index]);
		// fallthrough
	case 0:
		break;
	default:
		rz_warn_if_reached();
		return 0;
	}

	if (start_bits > 0) {
		// Handle start bits
		buffer = rz_bits_copy_ut64(src->bits.large_a[src_start_pos / BV_ELEM_SIZE], (src_start_pos % BV_ELEM_SIZE), buffer << start_bits, 0, start_bits);
	}

	dst->bits.small_u = rz_bits_copy_ut64(buffer, 0, dst->bits.small_u, dst_start_pos, nbit);
	return nbit;
}

/**
 * \brief Optimized version of rz_bv_copy_nbits() for copying bit range from a small bitvector to a large one
 */
static ut32 bv_copy_nbits_small_to_large(RzBitVector *dst, ut32 dst_start_pos, const RzBitVector *src, ut32 src_start_pos, ut32 nbit) {
	ut64 byte_index = dst_start_pos / BV_ELEM_SIZE;
	ut8 start_bits = RZ_MIN((BV_ELEM_SIZE - dst_start_pos) % BV_ELEM_SIZE, nbit);
	ut8 trailing_bits = RZ_MIN((dst_start_pos + nbit) % BV_ELEM_SIZE, nbit - start_bits);
	ut8 middle_bits = nbit - start_bits - trailing_bits;
	ut64 buffer = src->bits.small_u >> src_start_pos;

	// Handle unaligned start bits
	if (start_bits > 0) {
		dst->bits.large_a[byte_index] = rz_bits_copy_ut8(buffer, 0, dst->bits.large_a[byte_index], dst_start_pos % BV_ELEM_SIZE, start_bits);
		byte_index++;
		buffer >>= start_bits;
	}

	// Handle unaligned trailing bits
	if (trailing_bits > 0) {
		ut64 trailing_byte_index = (dst_start_pos + nbit) / BV_ELEM_SIZE;
		dst->bits.large_a[trailing_byte_index] = rz_bits_copy_ut8(buffer >> middle_bits, 0, dst->bits.large_a[trailing_byte_index], 0, trailing_bits);
	}

	// Handle middle bytes
	switch (middle_bits / BV_ELEM_SIZE) {
	case 8:
		dst->bits.large_a[byte_index + 7] = (buffer >> BV_ELEM_SIZE * 7) & UT8_MAX;
		// fallthrough
	case 7:
		dst->bits.large_a[byte_index + 6] = (buffer >> BV_ELEM_SIZE * 6) & UT8_MAX;
		// fallthrough
	case 6:
		dst->bits.large_a[byte_index + 5] = (buffer >> BV_ELEM_SIZE * 5) & UT8_MAX;
		// fallthrough
	case 5:
		dst->bits.large_a[byte_index + 4] = (buffer >> BV_ELEM_SIZE * 4) & UT8_MAX;
		// fallthrough
	case 4:
		dst->bits.large_a[byte_index + 3] = (buffer >> BV_ELEM_SIZE * 3) & UT8_MAX;
		// fallthrough
	case 3:
		dst->bits.large_a[byte_index + 2] = (buffer >> BV_ELEM_SIZE * 2) & UT8_MAX;
		// fallthrough
	case 2:
		dst->bits.large_a[byte_index + 1] = (buffer >> BV_ELEM_SIZE) & UT8_MAX;
		// fallthrough
	case 1:
		dst->bits.large_a[byte_index] = buffer & UT8_MAX;
		// fallthrough
	case 0:
		break;
	default:
		rz_warn_if_reached();
		return 0;
	}

	return nbit;
}

/**
 * \brief Optimized version of rz_bv_copy_nbits() for large bitvectors (more than 64 bits) with unaligned bit positions
 */
static ut32 bv_copy_nbits_large_unaligned(RzBitVector *dst, ut32 dst_start_pos, const RzBitVector *src, ut32 src_start_pos, ut32 nbit) {
	// Sanity check performed by caller
	ut64 bits_remaining = nbit;

	while (bits_remaining > 0) {
		ut32 src_offset = src_start_pos % BV_ELEM_SIZE;
		ut32 src_byte = src_start_pos / BV_ELEM_SIZE;
		ut32 dst_offset = dst_start_pos % BV_ELEM_SIZE;
		ut32 dst_byte = dst_start_pos / BV_ELEM_SIZE;
		ut8 bits_to_write = RZ_MIN(bits_remaining, BV_ELEM_SIZE - dst_offset);

		ut16 buffer;
		if (src_byte < dst->_elem_len - 1 && src_offset + bits_to_write > BV_ELEM_SIZE) {
			// If the bit subset spans across byte boundary, then read two bytes
			buffer = src->bits.large_a[src_byte + 1] << BV_ELEM_SIZE | src->bits.large_a[src_byte];
		} else {
			// Otherwise 1 byte is enough
			buffer = src->bits.large_a[src_byte];
		}

		// Extract bits from the buffer
		dst->bits.large_a[dst_byte] = rz_bits_copy_ut64(buffer, src_offset, dst->bits.large_a[dst_byte], dst_offset, bits_to_write);

		// Move positions
		src_start_pos += bits_to_write;
		dst_start_pos += bits_to_write;
		bits_remaining -= bits_to_write;
	}

	return nbit;
}

/**
 * Copy n bits from start position of source to start position of dest, return num of copied bits
 * NOTE: src and dst can be the same bit vector pointer.
 *
 * \param dst RzBitVector, destination of copy
 * \param dst_start_pos ut32, start position in destination bitvector
 * \param src RzBitVector, data source
 * \param src_start_pos ut32, start position in source bitvector of copy
 * \param nbit ut32, control the size of copy (in bits)
 * \return copied_size ut32, Actual copied size
 */
RZ_API ut32 rz_bv_copy_nbits(RZ_NONNULL RzBitVector *dst, ut32 dst_start_pos, RZ_NONNULL const RzBitVector *src, ut32 src_start_pos, ut32 nbit) {
	rz_return_val_if_fail(src && dst, 0);

	ut32 max_nbit = RZ_MIN((src->len - src_start_pos),
		(dst->len - dst_start_pos));

	// prevent overflow
	if (max_nbit < nbit) {
		return 0;
	}

	if (src->len <= 64 && dst->len <= 64) {
		// Both src and dst are smaller than 64 bits
		dst->bits.small_u = rz_bits_copy_ut64(src->bits.small_u, src_start_pos, dst->bits.small_u, dst_start_pos, nbit);
		return nbit;
	}

	if (src->len > 64 && dst->len > 64) {
		// Both src and dst are larger than 64 bits
		if (src_start_pos % BV_ELEM_SIZE == dst_start_pos % BV_ELEM_SIZE) {
			return bv_copy_nbits_large_aligned(dst, dst_start_pos, src, src_start_pos, nbit);
		}

		if (src->bits.large_a != dst->bits.large_a) {
			return bv_copy_nbits_large_unaligned(dst, dst_start_pos, src, src_start_pos, nbit);
		}

		// Use a temporary bitvector for same-vector copies
		RzBitVector *temp = rz_bv_new(rz_bv_len(dst));
		rz_bv_copy(temp, dst);
		ut32 bits_copied = bv_copy_nbits_large_unaligned(temp, dst_start_pos, src, src_start_pos, nbit);
		rz_bv_copy(dst, temp);
		rz_bv_free(temp);
		return bits_copied;
	}

	if (src->len > 64) {
		// Large to small copy
		return bv_copy_nbits_large_to_small(dst, dst_start_pos, src, src_start_pos, nbit);
	}

	// Small to large
	return bv_copy_nbits_small_to_large(dst, dst_start_pos, src, src_start_pos, nbit);
}

/**
 * Return a new bitvector prepended with bv with n zero bits
 * \param bv RzBitVector, pointer to bitvector instance
 * \param delta_len ut32, the number of zero bits
 * \return ret RzBitVector, pointer to the new bitvector instance
 */
RZ_API RZ_OWN RzBitVector *rz_bv_prepend_zero(RZ_NONNULL RzBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len + delta_len;
	RzBitVector *ret = rz_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	for (ut32 i = 0; i < bv->len; ++i) {
		rz_bv_set(ret, i, rz_bv_get(bv, i));
	}

	return ret;
}

/**
 * Return a new bitvector appended with n zero bits
 * \param bv RzBitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret RzBitVector, pointert to the new btivector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_append_zero(RZ_NONNULL RzBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len + delta_len;
	RzBitVector *ret = rz_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	ut32 pos = delta_len;
	for (ut32 i = 0; i < bv->len; ++i, ++pos) {
		rz_bv_set(ret, pos, rz_bv_get(bv, i));
	}

	return ret;
}

/**
 * Return a new bitvector, cut n zero bits from head
 * \param bv RzBitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret RzBitVector, pointert to the new btivector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_cut_head(RZ_NONNULL RzBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len - delta_len;
	RzBitVector *ret = rz_bv_new(new_len);
	if (!ret) {
		return NULL;
	}

	for (ut32 pos = 0; pos < new_len; ++pos) {
		rz_bv_set(ret, pos, rz_bv_get(bv, pos));
	}

	return ret;
}

/**
 * Return a new bitvector, cut n zero bits from tail
 * \param bv RzBitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret RzBitVector, pointert to the new btivector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_cut_tail(RZ_NONNULL RzBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len - delta_len;
	RzBitVector *ret = rz_bv_new(new_len);
	if (!ret) {
		return NULL;
	}

	ut32 pos, i;
	for (pos = 0, i = delta_len; pos < new_len; ++i, ++pos) {
		rz_bv_set(ret, pos, rz_bv_get(bv, i));
	}

	return ret;
}

/**
 * Append bv2 to bv1 to get new bitvector
 * \param high bitvector to occupy the most significant part of the result
 * \param low bitvector to occupy the least significant part of the result
 * \return ret RzBitVector, the new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_append(RZ_NONNULL RzBitVector *high, RZ_NONNULL RzBitVector *low) {
	rz_return_val_if_fail(high && low, NULL);
	RzBitVector *ret = rz_bv_new(high->len + low->len);
	rz_bv_copy_nbits(ret, 0, low, 0, low->len);
	rz_bv_copy_nbits(ret, low->len, high, 0, high->len);
	return ret;
}

/**
 * Set a bit at position to true or false
 * \param bv RzBitVector, pointer to bv
 * \param pos ut32, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_bv_set(RZ_NONNULL RzBitVector *bv, ut32 pos, bool b) {
	rz_return_val_if_fail(bv && pos < bv->len, false);
	if (bv->len <= 64) {
		if (b) {
			bv->bits.small_u |= (1ull << pos);
		} else {
			bv->bits.small_u &= ~(1ull << pos);
		}
		return b;
	}
	rz_return_val_if_fail(bv->bits.large_a, false);

	if (b) {
		bv->bits.large_a[pos / BV_ELEM_SIZE] |= (1u << (pos % BV_ELEM_SIZE));
	} else {
		bv->bits.large_a[pos / BV_ELEM_SIZE] &= ~(1u << (pos % BV_ELEM_SIZE));
	}
	return b;
}

/**
 * Set all bits to true or false
 * \param bv RzBitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_bv_set_all(RZ_NONNULL RzBitVector *bv, bool b) {
	rz_return_val_if_fail(bv, false);

	if (bv->len <= 64) {
		bv->bits.small_u = b ? UT64_MAX >> (64 - bv->len) : 0;
		return b;
	}

	rz_return_val_if_fail(bv->bits.large_a, false);
	if (b) {
		memset(bv->bits.large_a, 0xff, bv->_elem_len);
		ut32 mod = bv->len % BV_ELEM_SIZE;
		if (mod) {
			bv->bits.large_a[bv->len / BV_ELEM_SIZE] = rz_num_bitmask(mod);
		}
	} else {
		memset(bv->bits.large_a, 0, bv->_elem_len);
	}

	return b;
}

/**
 * Invert a bit at position
 * \param bv RzBitVector, pointer to bv
 * \param pos ut32, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_bv_toggle(RZ_NONNULL RzBitVector *bv, ut32 pos) {
	rz_return_val_if_fail(bv, false);
	bool cur_bit = rz_bv_get(bv, pos);
	bool new_bit = !cur_bit;
	rz_bv_set(bv, pos, new_bit);
	return new_bit;
}

/**
 * Invert all bits
 * \param bv RzBitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_bv_toggle_all(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, false);
	if (bv->len <= 64) {
		bv->bits.small_u = ~(bv->bits.small_u);
		return true;
	}

	rz_return_val_if_fail(bv->bits.large_a, false);
	for (ut32 i = 0; i < NELEM(bv->len, BV_ELEM_SIZE); ++i) {
		bv->bits.large_a[i] = ~(bv->bits.large_a[i]);
	}
	return true;
}

/**
 * Get bit at position from bitvector
 * \param bv RzBitVector, pointer to bv
 * \param pos int, position
 * \return ret bit, bool value of bit
 */
RZ_API bool rz_bv_get(RZ_NONNULL const RzBitVector *bv, ut32 pos) {
	rz_return_val_if_fail(bv && pos < bv->len, false);
	if (bv->len <= 64) {
		return (bv->bits.small_u >> pos) & 1;
	}

	rz_return_val_if_fail(bv->bits.large_a, false);
	return ((bv->bits.large_a)[pos / BV_ELEM_SIZE] & (1u << (pos % BV_ELEM_SIZE)));
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv RzBitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_bv_lshift(RZ_NONNULL RzBitVector *bv, ut32 size) {
	return rz_bv_lshift_fill(bv, size, false);
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv RzBitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_bv_rshift(RZ_NONNULL RzBitVector *bv, ut32 size) {
	return rz_bv_rshift_fill(bv, size, false);
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill the bitvector with `fill_bit`
 * \param bv RzBitVector, pointert to bv
 * \param size int, shift bits
 * \param fill_bit bool, bit used in filling
 * \return flag bool, success or not
 */
RZ_API bool rz_bv_lshift_fill(RZ_NONNULL RzBitVector *bv, ut32 size, bool fill_bit) {
	rz_return_val_if_fail(bv, false);

	// left shift
	if (size == 0) {
		return true;
	}

	if (size >= bv->len) {
		rz_bv_set_all(bv, fill_bit);
		return true;
	}

	RzBitVector tmp;
	if (!rz_bv_init(&tmp, bv->len)) {
		return false;
	}
	rz_bv_set_all(&tmp, fill_bit);

	int copied_size = rz_bv_copy_nbits(&tmp, size, bv, 0, bv->len - size);
	if (copied_size == 0) {
		rz_bv_fini(&tmp);
		return false;
	}

	rz_bv_copy(bv, &tmp);
	rz_bv_fini(&tmp);

	return true;
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill the bitvector with `fill_bit`
 * \param bv RzBitVector, pointert to bv
 * \param size int, shift bits
 * \param fill_bit bool, bit used in filling
 * \return flag bool, success or not
 */
RZ_API bool rz_bv_rshift_fill(RZ_NONNULL RzBitVector *bv, ut32 size, bool fill_bit) {
	rz_return_val_if_fail(bv, false);

	// left shift
	if (size == 0) {
		return true;
	}

	if (size >= bv->len) {
		rz_bv_set_all(bv, fill_bit);
		return true;
	}

	RzBitVector tmp;
	if (!rz_bv_init(&tmp, bv->len)) {
		return false;
	}
	rz_bv_set_all(&tmp, fill_bit);

	int copied_size = rz_bv_copy_nbits(&tmp, 0, bv, size, bv->len - size);
	if (copied_size == 0) {
		rz_bv_fini(&tmp);
		return false;
	}

	rz_bv_copy(bv, &tmp);
	rz_bv_fini(&tmp);

	return true;
}

/**
 * Result of x &= y (`and` operation to every bits)
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return True for success, false otherwise.
 */
RZ_API bool rz_bv_and_inplace(RZ_INOUT RZ_NONNULL RzBitVector *x, RZ_NONNULL const RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return false;
	}

	if (x->len <= 64) {
		x->bits.small_u &= y->bits.small_u;
		return true;
	}

	for (ut32 i = 0; i < NELEM(x->len, BV_ELEM_SIZE); ++i) {
		x->bits.large_a[i] = x->bits.large_a[i] & y->bits.large_a[i];
	}
	return true;
}

/**
 * Result of x AND y (`and` operation to every bits)
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the result of AND
 */
RZ_API RZ_OWN RzBitVector *rz_bv_and(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *ret = rz_bv_dup(x);
	if (!ret) {
		return NULL;
	}
	if (!rz_bv_and_inplace(ret, y)) {
		rz_bv_free(ret);
		return NULL;
	}
	return ret;
}

/**
 * Result of x |= y (`or` operation to every bits)
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return True for success, false otherwise.
 */
RZ_API bool rz_bv_or_inplace(RZ_INOUT RZ_NONNULL RzBitVector *x, RZ_NONNULL const RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return false;
	}

	if (x->len <= 64) {
		x->bits.small_u = x->bits.small_u | y->bits.small_u;
		return true;
	}

	for (ut32 i = 0; i < NELEM(x->len, BV_ELEM_SIZE); ++i) {
		x->bits.large_a[i] = x->bits.large_a[i] | y->bits.large_a[i];
	}
	return true;
}

/**
 * Result of x OR y (`or` operation to every bits)
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the result of OR
 */
RZ_API RZ_OWN RzBitVector *rz_bv_or(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *ret = rz_bv_dup(x);
	if (!ret) {
		return NULL;
	}
	if (!rz_bv_or_inplace(ret, y)) {
		rz_bv_free(ret);
		return NULL;
	}
	return ret;
}

/**
 * Result of x XOR y (`xor` operation to every bits)
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the result of XOR
 */
RZ_API bool rz_bv_xor_inplace(RZ_INOUT RZ_NONNULL RzBitVector *x, RZ_NONNULL const RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return false;
	}

	if (x->len <= 64) {
		x->bits.small_u = x->bits.small_u ^ y->bits.small_u;
		return true;
	}

	for (ut32 i = 0; i < NELEM(x->len, BV_ELEM_SIZE); ++i) {
		x->bits.large_a[i] = x->bits.large_a[i] ^ y->bits.large_a[i];
	}
	return true;
}

/**
 * Result of x XOR y (`xor` operation to every bits)
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the result of XOR
 */
RZ_API RZ_OWN RzBitVector *rz_bv_xor(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *ret = rz_bv_dup(x);
	if (!ret) {
		return NULL;
	}
	if (!rz_bv_xor_inplace(ret, y)) {
		rz_bv_free(ret);
		return NULL;
	}
	return ret;
}

/**
 * Get the 1's complement of bv
 * \param bv RzBitVector, operand
 * \return True for success, false otherwise.
 */
RZ_API bool rz_bv_complement_1_inplace(RZ_INOUT RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, false);
	if (bv->len <= 64) {
		bv->bits.small_u = ~bv->bits.small_u;
		bv->bits.small_u &= UT64_MAX >> (64 - bv->len);
		return true;
	}

	if (!bv->bits.large_a) {
		rz_return_val_if_reached(false);
	}
	for (ut32 i = 0; i < NELEM(bv->len, BV_ELEM_SIZE); ++i) {
		bv->bits.large_a[i] = ~bv->bits.large_a[i];
	}
	return true;
}

/**
 * Get the 1's complement of bv
 * \param bv RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the 1's complement of bv
 */
RZ_API RZ_OWN RzBitVector *rz_bv_complement_1(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	RzBitVector *ret = rz_bv_dup(bv);
	if (!ret) {
		return NULL;
	}
	if (!rz_bv_complement_1_inplace(ret)) {
		rz_bv_free(ret);
		return NULL;
	}
	return ret;
}

/**
 * Get the 2's complement of bv.
 * \param bv RzBitVector, operand
 * \return True for succcess, false otherwise.
 */
RZ_API bool rz_bv_complement_2_inplace(RZ_INOUT RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, false);

	// from right side to left, find the 1st 1 bit
	// flip/toggle every bit before it

	// TODO: Performance
	ut32 i;
	for (i = 0; i < bv->len; ++i) {
		if (rz_bv_get(bv, i) == true) {
			break;
		}
	}

	// assert bv[i] == true now
	i += 1;
	for (; i < bv->len; ++i) {
		rz_bv_toggle(bv, i);
	}

	return true;
}

/**
 * Get the 2's complement of bv
 * \param bv RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the 2's complement of bv
 */
RZ_API RZ_OWN RzBitVector *rz_bv_complement_2(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	// from right side to left, find the 1st 1 bit
	// flip/toggle every bit before it
	RzBitVector *ret = rz_bv_dup(bv);
	if (!rz_bv_complement_2_inplace(ret)) {
		rz_bv_free(ret);
		return false;
	}
	return ret;
}

/**
 * Adds 2 unsigned integers with arbitrary bit size (up to 64). The function allows specifying
 * input carry flag, and produces an output carry flag.
 */
static inline ut64 add_with_carry_ut64(ut64 a, ut64 b, ut8 bit_size, ut8 *carry_inout) {
	const ut64 result = a + b + *carry_inout;

	if (bit_size < 64) {
		*carry_inout = (result >> bit_size) & 1;
		return result & ((1ull << bit_size) - 1);
	}

	*carry_inout = result < a || (result - *carry_inout) < a || result < b || (result - *carry_inout) < b;
	return result;
}

/**
 * Result of x = (x + y) mod 2^length
 * Both operands must have the same length. The length should be greater than zero.
 * \param x The input and output operand of the addition.
 * \param y RzBitVector, Operand
 * \param carry bool*, bool pointer to where to save the carry value.
 * \return True for success, false otherwise.
 */
RZ_API bool rz_bv_add_inplace(
	RZ_INOUT RZ_NONNULL RZ_BORROW RzBitVector *x,
	const RZ_NONNULL RzBitVector *y,
	RZ_NULLABLE bool *carry) {
	rz_return_val_if_fail(x && y, false);

	if (x->len != y->len || x->len == 0) {
		rz_warn_if_reached();
		return false;
	}

	ut8 carry_over = 0;

	// handle small bit vectors
	if (x->len <= 64) {
		x->bits.small_u = add_with_carry_ut64(x->bits.small_u, y->bits.small_u, x->len, &carry_over);
		if (carry) {
			*carry = carry_over;
		}
		return true;
	}

	ut32 bit_offset = 0;

	// handle large bit vectors
	while (bit_offset < x->len) {
		const ut32 remaining_bits = x->len - bit_offset;
		const ut32 byte_offset = bit_offset / 8;

		if (remaining_bits >= 64) {
			const ut64 r = add_with_carry_ut64(rz_read_le64(x->bits.large_a + byte_offset), rz_read_le64(y->bits.large_a + byte_offset), 64, &carry_over);
			rz_write_le64(x->bits.large_a + byte_offset, r);
			bit_offset += 64;
			continue;
		}
		if (remaining_bits >= 32) {
			const ut64 r = add_with_carry_ut64(rz_read_le32(x->bits.large_a + byte_offset), rz_read_le32(y->bits.large_a + byte_offset), 32, &carry_over);
			rz_write_le32(x->bits.large_a + byte_offset, r);
			bit_offset += 32;
			continue;
		}
		if (remaining_bits >= 16) {
			const ut64 r = add_with_carry_ut64(rz_read_le16(x->bits.large_a + byte_offset), rz_read_le16(y->bits.large_a + byte_offset), 16, &carry_over);
			rz_write_le16(x->bits.large_a + byte_offset, r);
			bit_offset += 16;
			continue;
		}
		if (remaining_bits >= 8) {
			const ut64 r = add_with_carry_ut64(rz_read_le8(x->bits.large_a + byte_offset), rz_read_le8(y->bits.large_a + byte_offset), 8, &carry_over);
			rz_write_le8(x->bits.large_a + byte_offset, r);
			bit_offset += 8;
			continue;
		}
		for (ut32 pos = bit_offset; pos < x->len; ++pos) {
			const bool a = rz_bv_get(x, pos);
			const bool b = rz_bv_get(y, pos);
			rz_bv_set(x, pos, a ^ b ^ carry_over);
			carry_over = ((a & b) | (a & carry_over)) | (b & carry_over);
		}
		bit_offset += remaining_bits;
	}

	if (carry) {
		*carry = (bool)carry_over;
	}

	return true;
}

/**
 * Result of (x + y) mod 2^length
 * Both operands must have the same length.
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \param carry bool*, bool pointer to where to save the carry value.
 * \return Pointer to the new bitvector or NULL in case of failure.
 */
RZ_API RZ_OWN RzBitVector *rz_bv_add(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *carry) {
	rz_return_val_if_fail(x && y, NULL);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *ret = rz_bv_dup(x);
	if (!rz_bv_add_inplace(ret, y, carry)) {
		rz_bv_free(ret);
		return NULL;
	}
	return ret;
}

/**
 * Result of y = -y ; x = (x + y) mod 2^length
 * Both operands must have the same length.
 *
 * Note: Operand y is also changed!
 *
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \param borrow bool*, bool pointer to where to save the borrow value.
 * \return True in case of succcess, false otherwise.
 */
RZ_API bool rz_bv_sub_inplace(RZ_INOUT RZ_NONNULL RzBitVector *x, RZ_INOUT RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *borrow) {
	rz_return_val_if_fail(x && y, false);
	if (!rz_bv_neg_inplace(y)) {
		return false;
	}
	if (!rz_bv_add_inplace(x, y, borrow)) {
		return false;
	}
	return true;
}

/**
 * Result of (x - y) mod 2^length
 * Both operands must have the same length.
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \param borrow bool*, bool pointer to where to save the borrow value.
 * \return ret RzBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_sub(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *borrow) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		return NULL;
	}

	RzBitVector *y_cpy = rz_bv_dup(y);
	RzBitVector *ret = rz_bv_dup(x);
	if (!ret || !y_cpy) {
		rz_bv_free(y_cpy);
		rz_bv_free(ret);
		return NULL;
	}
	if (!rz_bv_sub_inplace(ret, y_cpy, borrow)) {
		rz_bv_free(y_cpy);
		rz_bv_free(ret);
		return NULL;
	}
	rz_bv_free(y_cpy);
	return ret;
}

/**
 * Result of x = (x * y) mod 2^length
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \return True for success, false in case of failure.
 */
RZ_API bool rz_bv_mul_inplace(RZ_NONNULL RZ_INOUT RzBitVector *x, const RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	RzBitVector dup;
	rz_bv_init(&dup, x->len);
	rz_bv_copy(&dup, x);
	rz_bv_set_all(x, false);

	bool cur_bit = false;
	for (ut32 i = 0; i < y->len; ++i) {
		cur_bit = rz_bv_get(y, i);
		if (cur_bit) {
			if (!rz_bv_add_inplace(x, &dup, NULL)) {
				rz_bv_fini(&dup);
				return false;
			}
		}
		rz_bv_lshift(&dup, 1);
	}
	rz_bv_fini(&dup);
	return true;
}

/**
 * Result of (x * y) mod 2^length
 * Both operands must have the same length.
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \return ret RzBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_mul(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *result = rz_bv_dup(x);
	if (!result) {
		return NULL;
	}
	if (!rz_bv_mul_inplace(result, y)) {
		rz_bv_free(result);
		return NULL;
	}
	return result;
}

/* Treat x, y as unsigned
 * Both operands must have the same length.
 * if x < y return negtive (-1)
 * if x == y return 0
 * if x > y return positive (+1)
 */
int bv_unsigned_cmp(const RZ_NONNULL RzBitVector *x, const RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, 0);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return 0;
	}

	ut32 len = x->len;
	int pos;
	bool x_bit, y_bit;
	for (ut32 i = 0; i < len; ++i) {
		pos = len - 1 - i;
		x_bit = rz_bv_get(x, pos);
		y_bit = rz_bv_get(y, pos);
		if (x_bit ^ y_bit) {
			return x_bit ? 1 : -1;
		}
	}

	// equal
	return 0;
}

/**
 * Result of x = (x / y) mod 2^length
 * Both operands must have the same length.
 * If \p y is a zero vector, the result defined as a vector of all ones.
 *
 * \param x dividend
 * \param y divisor
 * \return True in case of success, false otherwise.
 */
RZ_API bool rz_bv_div_inplace(RZ_NONNULL RZ_INOUT RzBitVector *x, const RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y && x->len == y->len, false);

	if (rz_bv_is_zero_vector(y)) {
		rz_bv_set_all(x, true);
		return true;
	}

	if (x->len <= 64) {
		rz_bv_set_from_ut64(x, rz_bv_to_ut64(x) / rz_bv_to_ut64(y));
		return true;
	}

	int compare_result = bv_unsigned_cmp(x, y);
	// dividend < divisor
	// remainder = dividend, quotient = 0
	if (compare_result < 0) {
		rz_bv_set_from_ut64(x, 0);
		return true;
	}
	// dividend == divisor
	// remainder = 0, quotient = 1
	if (compare_result == 0) {
		rz_bv_set_from_ut64(x, 1);
		return true;
	}

	// dividend > divisor
	// do typical division by shift and subtract
	RzBitVector dend;
	rz_bv_init(&dend, x->len);
	rz_bv_copy(&dend, x);
	RzBitVector sor;
	rz_bv_init(&sor, y->len);
	rz_bv_copy(&sor, y);

	// shift the divisor left to align both highest bits
	ut32 sorlz = rz_bv_clz(&sor);
	ut32 shift = sorlz - rz_bv_clz(&dend);
	rz_bv_lshift(&sor, shift);

	rz_bv_set_from_ut64(x, 0);
	for (ut32 b = shift + 1; b; b--) {
		if (rz_bv_ule(&sor, &dend)) {
			rz_bv_set(x, b - 1, true);

			// sub_inplace() negates sor_cpy
			RzBitVector sor_cpy;
			rz_bv_init(&sor_cpy, y->len);
			rz_bv_copy(&sor_cpy, &sor);
			rz_bv_sub_inplace(&dend, &sor_cpy, NULL);
			rz_bv_fini(&sor_cpy);
		}
		rz_bv_rshift(&sor, 1);
	}
	rz_bv_fini(&dend);
	rz_bv_fini(&sor);
	return true;
}

/**
 * Result of (x / y) mod 2^length
 * Both operands must have the same length.
 * If \p y is a zero vector, the result defined as a vector of all ones.
 *
 * \param x dividend
 * \param y divisor
 * \return ret quotient, of the same length as the operands
 */
RZ_API RZ_OWN RzBitVector *rz_bv_div(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y && x->len == y->len, NULL);
	RzBitVector *res = rz_bv_dup(x);
	if (!rz_bv_div_inplace(res, y)) {
		rz_bv_free(res);
		return NULL;
	}
	return res;
}

/**
 * Result of x = (x mod y) mod 2^length
 * Both operands must have the same length.
 * If \p y == 0, the result is \p x
 *
 * \param x dividend
 * \param y divisor
 * \return True in case of success, false otherwise.
 */
RZ_API bool rz_bv_mod_inplace(RZ_NONNULL RZ_INOUT RzBitVector *x, const RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y && x->len == y->len, false);
	if (rz_bv_is_zero_vector(y)) {
		return true;
	}
	RzBitVector remul;
	rz_bv_init(&remul, rz_bv_len(x));
	rz_bv_copy(&remul, x);

	if (!rz_bv_div_inplace(&remul, y)) {
		rz_bv_fini(&remul);
		return false;
	}
	if (!rz_bv_mul_inplace(&remul, y)) {
		rz_bv_fini(&remul);
		return false;
	}
	if (!rz_bv_sub_inplace(x, &remul, NULL)) {
		rz_bv_fini(&remul);
		return false;
	}
	rz_bv_fini(&remul);
	return true;
}

/**
 * Result of (x mod y) mod 2^length
 * Both operands must have the same length.
 * If \p y == 0, the result is \p x
 *
 * \param x dividend
 * \param y divisor
 * \return x - ((x / y) * y)
 */
RZ_API RZ_OWN RzBitVector *rz_bv_mod(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y && x->len == y->len, NULL);
	RzBitVector *r = rz_bv_dup(x);
	if (!rz_bv_mod_inplace(r, y)) {
		rz_bv_free(r);
		return NULL;
	}
	return r;
}

/**
 * Result of (x / y) mod 2^length (signed algorithm)
 *                               /
 *                            | div x y : if not mx /\ not my
 *                            | neg (div (neg x) y) if mx /\ not my
 *                x sdiv y = <
 *                            | neg (div x (neg y)) if not mx /\ my
 *                            | div (neg x) (neg y) if mx /\ my
 *                            \
 *
 *             where mx = msb x, and my = msb y.
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \return ret RzBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_sdiv(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	bool mx = rz_bv_msb(x);
	bool my = rz_bv_msb(y);

	RzBitVector *neg_x, *neg_y, *tmp, *ret;

	if ((!mx) && (!my)) {
		return rz_bv_div(x, y);
	}

	if ((mx) && (!my)) {
		neg_x = rz_bv_neg(x);
		tmp = rz_bv_div(neg_x, y);
		ret = rz_bv_neg(tmp);

		rz_bv_free(tmp);
		rz_bv_free(neg_x);
		return ret;
	}

	if ((!mx) && (my)) {
		neg_y = rz_bv_neg(y);
		tmp = rz_bv_div(x, neg_y);
		ret = rz_bv_neg(tmp);

		rz_bv_free(tmp);
		rz_bv_free(neg_y);
		return ret;
	}

	// mx && my
	neg_x = rz_bv_neg(x);
	neg_y = rz_bv_neg(y);

	ret = rz_bv_div(neg_x, neg_y);
	rz_bv_free(neg_x);
	rz_bv_free(neg_y);

	return ret;
}

/**
 * Result of (x mod y) mod 2^length (signed algorithm)
 *                            /
 *                          | x % y : if not mx /\ not my
 *                         | neg (neg x % y) if mx /\ not my
 *           x smodulo y = <
 *                          | neg (x % (neg y)) if not mx /\ my
 *                          | neg (neg x % neg y) mod m if mx /\ my
 *                          \
 *
 *           where mx = msb x  and my = msb y.
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \return ret RzBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_smod(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	bool mx = rz_bv_msb(x);
	bool my = rz_bv_msb(y);

	RzBitVector *neg_x, *neg_y, *tmp, *ret;

	if ((!mx) && (!my)) {
		return rz_bv_mod(x, y);
	}

	if ((mx) && (!my)) {
		neg_x = rz_bv_neg(x);
		tmp = rz_bv_mod(neg_x, y);
		ret = rz_bv_neg(tmp);

		rz_bv_free(tmp);
		rz_bv_free(neg_x);
		return ret;
	}

	if ((!mx) && (my)) {
		neg_y = rz_bv_neg(y);
		tmp = rz_bv_mod(x, neg_y);
		ret = rz_bv_neg(tmp);

		rz_bv_free(tmp);
		rz_bv_free(neg_y);
		return ret;
	}

	// mx && my
	neg_x = rz_bv_neg(x);
	neg_y = rz_bv_neg(y);

	tmp = rz_bv_mod(neg_x, neg_y);
	ret = rz_bv_neg(tmp);
	rz_bv_free(neg_x);
	rz_bv_free(neg_y);
	rz_bv_free(tmp);
	return ret;
}

/**
 * Get the most significant bit of bitvector
 * \param bv RzBitVector, operand
 * \return b bit, bool value of MSB
 */
RZ_API bool rz_bv_msb(RZ_NONNULL const RzBitVector *bv) {
	return rz_bv_get(bv, bv->len - 1);
}

/**
 * Get the least significant bit of bitvector
 * \param bv RzBitVector, operand
 * \return b bit, bool value of LSB
 */
RZ_API bool rz_bv_lsb(RZ_NONNULL const RzBitVector *bv) {
	return rz_bv_get(bv, 0);
}

/**
 * Check if the bitvector is zero
 * \param x RzBitVector, pointer to bv
 * \return ret bool, return true if bv is a zero bitvector, false if not
 */
RZ_API bool rz_bv_is_zero_vector(RZ_NONNULL const RzBitVector *x) {
	rz_return_val_if_fail(x, false);

	if (x->len <= 64) {
		return x->bits.small_u == 0;
	}

	rz_return_val_if_fail(x->bits.large_a, false);

	for (ut32 i = 0; i < NELEM(x->len, BV_ELEM_SIZE); ++i) {
		if (x->bits.large_a[i] != 0) {
			return false;
		}
	}
	return true;
}

/**
 * Check if x == y
 */
RZ_API bool rz_bv_eq(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	return rz_bv_len(x) == rz_bv_len(y) && bv_unsigned_cmp(x, y) == 0;
}

/**
 * Check if x <= y (as unsigned value)
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_bv_ule(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	// x > y ? return false : return true
	return bv_unsigned_cmp(x, y) <= 0;
}

/**
 * Check if x <= y (as signed value)
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_bv_sle(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	bool x_msb = rz_bv_msb(x);
	bool y_msb = rz_bv_msb(y);

	if (x_msb == y_msb) {
		return rz_bv_ule(x, y);
	}

	// if x_msb set, y_msb unset => x < y
	// if x_msb unset, y_msb set => x > y
	// x != y when reaches here
	return x_msb;
}

/**
 * Check if x equals to y
 * Both operands must have the same length.
 * \param x RzBitVector, operand
 * \param y RzBitVector, operand
 * \return ret int, return 1 if x != y, return 0 if x == y
 */
RZ_API bool rz_bv_cmp(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, 0);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return true;
	}

	for (ut32 i = 0; i < x->len; ++i) {
		if (rz_bv_get(x, i) != rz_bv_get(y, i)) {
			return true;
		}
	}

	return false;
}

/**
 * Count leading (most significant) zeroes
 * All bits are considered leading zeroes for a zero bitvector.
 */
RZ_API ut32 rz_bv_clz(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, 0);
	ut32 r = 0;
	for (ut32 i = rz_bv_len(bv); i; i--) {
		if (rz_bv_get(bv, i - 1)) {
			break;
		}
		r++;
	}
	return r;
}

/**
 * Count trailing (least significant) zeroes
 * All bits are considered trailing zeroes for a zero bitvector.
 */
RZ_API ut32 rz_bv_ctz(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, 0);
	ut32 r = 0;
	for (ut32 i = 0; i < rz_bv_len(bv); i++) {
		if (rz_bv_get(bv, i)) {
			break;
		}
		r++;
	}
	return r;
}

/**
 * Get the length of bitvector in bits
 * \param bv RzBitVector
 * \return len ut32, length of bitvector in bits
 */
RZ_API ut32 rz_bv_len(RZ_NONNULL const RzBitVector *bv) {
	rz_return_val_if_fail(bv, 0);
	return bv->len;
}

/**
 * Get the length of bitvector in bytes
 * \param bv RzBitVector
 * \return len ut32, length of bitvector in bytes
 */
RZ_API ut32 rz_bv_len_bytes(RZ_NONNULL const RzBitVector *bv) {
	rz_return_val_if_fail(bv, 0);
	return (bv->len + 7) >> 3;
}

/**
 * Convert ut64 to `length`-bits bitvector
 * \param length ut32, length of bitvector
 * \param value ut64, the value to convert
 * \return bv RzBitVector, pointer to new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_ut64(ut32 length, ut64 value) {
	rz_return_val_if_fail(length > 0, NULL);

	RzBitVector *bv = rz_bv_new(length);
	if (!bv) {
		RZ_LOG_ERROR("RzIL: failed to allocate RzBitVector\n");
		return NULL;
	}
	rz_bv_set_from_ut64(bv, value);
	return bv;
}

/**
 * Convert st64 to `length`-bits bitvector
 * \param length ut32, length of bitvector
 * \param value st64, the value to convert
 * \return bv RzBitVector, pointer to new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_st64(ut32 length, st64 value) {
	rz_return_val_if_fail(length > 0, NULL);

	RzBitVector *bv = rz_bv_new(length);
	if (!bv) {
		RZ_LOG_ERROR("RzIL: failed to allocate RzBitVector\n");
		return NULL;
	}
	rz_bv_set_from_st64(bv, value);
	return bv;
}

/**
 * Create a new bitvector of \p size bits and apply rz_bv_set_from_bytes_le() to it
 */
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_bytes_le(RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size) {
	rz_return_val_if_fail(buf, NULL);
	RzBitVector *bv = rz_bv_new(size);
	if (!bv) {
		return NULL;
	}
	rz_bv_set_from_bytes_le(bv, buf, bit_offset, size);
	return bv;
}

/**
 * Create a new bitvector of \p size bits and apply rz_bv_set_from_bytes_be() to it
 */
RZ_API RZ_OWN RzBitVector *rz_bv_new_from_bytes_be(RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size) {
	rz_return_val_if_fail(buf, NULL);
	RzBitVector *bv = rz_bv_new(size);
	if (!bv) {
		return NULL;
	}
	rz_bv_set_from_bytes_be(bv, buf, bit_offset, size);
	return bv;
}

/**
 * Convert ut64 to N-bits bitvector
 * \param bv RzBitVector, pointer to bitvector
 * \param value ut64, the value to convert
 */
RZ_API bool rz_bv_set_from_ut64(RZ_NONNULL RzBitVector *bv, ut64 value) {
	rz_return_val_if_fail(bv, false);

	if (bv->len <= 64) {
		bv->bits.small_u = value;
		bv->bits.small_u &= (UT64_MAX >> (64 - bv->len));
		return true;
	}

	for (ut32 i = 0; i < bv->len; ++i) {
		rz_bv_set(bv, i, value & 1);
		value >>= 1;
	}
	return true;
}

/**
 * Convert st64 to N-bits bitvector
 * \param bv RzBitVector, pointer to bitvector
 * \param value st64, the value to convert
 */
RZ_API bool rz_bv_set_from_st64(RZ_NONNULL RzBitVector *bv, st64 value) {
	rz_return_val_if_fail(bv, false);
	if (bv->len <= 64) {
		bv->bits.small_u = *((ut64 *)&value);
		bv->bits.small_u &= (UT64_MAX >> (64 - bv->len));
		return true;
	}

	for (ut32 i = 0; i < bv->len; ++i) {
		rz_bv_set(bv, i, value & 1);
		value >>= 1;
	}
	return true;
}

/**
 * Set the bitvector's contents from the given bits. The bitvector's size is unchanged.
 * If bv->len < size, additional bits are cut off, if bv->len > size, the rest is filled up with 0.
 * \param buf little endian buffer of at least (bit_offset + size + 7) / 8 bytes
 * \param bit_offset offset inside buf to start reading from, in bits
 * \param size number of bits to read from buf
 */
RZ_API void rz_bv_set_from_bytes_le(RZ_NONNULL RzBitVector *bv, RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size) {
	rz_return_if_fail(bv && buf && size);
	size = RZ_MIN(size, bv->len);
	if (!bit_offset && size <= 64) {
		ut64 val = 0;
		for (ut32 i = 0; i < (size + 7) / 8; i++) {
			val |= (ut64)buf[i] << (i * 8);
		}
		val &= (UT64_MAX >> (64 - size));
		rz_bv_set_from_ut64(bv, val);
		return;
	}
	for (ut32 i = 0; i < bv->len; i++) {
		bool bit = false;
		if (i < size) {
			ut32 idx = (bit_offset + i) >> 3;
			ut32 sh = (bit_offset + i) & 7;
			bit = (buf[idx] >> sh) & 1;
		}
		rz_bv_set(bv, i, bit);
	}
}

/**
 * \brief Set the bitvector's contents from the given bits. The bitvector's size is unchanged.
 * If bv->len < size, additional bits are cut off, if bv->len > size, the rest is filled up with 0.
 *
 * \param buf big endian buffer of at least (bit_offset + size + 7) / 8 bytes
 * \param bit_offset offset inside buf to start reading from, in bits
 * \param size number of bits to read from buf
 */
RZ_API void rz_bv_set_from_bytes_be(RZ_NONNULL RzBitVector *bv, RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size) {
	rz_return_if_fail(bv && buf && size);
	size = RZ_MIN(size, bv->len);
	// upper bits goes always in the upper bit of the bitv
	for (ut32 i = 0; i < bv->len; i++) {
		bool bit = false;
		if (i < size) {
			ut32 idx = (bit_offset + i) >> 3;
			ut32 sh = ((bit_offset + i) & 7);
			ut8 b8 = buf[idx];
			b8 = (size < 8) ? reverse_lt_8bits(b8, size) : (ut8)reverse_byte(b8);
			bit = (b8 >> sh) & 1;
		}
		rz_bv_set(bv, bv->len - 1 - i, bit);
	}
}

RZ_API void rz_bv_set_from_bytes_ble(RZ_NONNULL RzBitVector *bv, RZ_IN RZ_NONNULL const ut8 *buf, ut32 bit_offset, ut32 size, bool big_endian) {
	if (big_endian) {
		rz_bv_set_from_bytes_be(bv, buf, bit_offset, size);
	} else {
		rz_bv_set_from_bytes_le(bv, buf, bit_offset, size);
	}
}

/**
 * Reads \p bit_size number of bits (assumed in little-endian byte order) from the current position of a RzBuffer \p buf and assigns to the value of the bitvector \p bv.
 * \param bv bitvector to assign the new value to.
 * \param buf RzBuffer containing at least `(bit_size + 7) / 8` bytes at\after the current position.
 * \param bit_size number of bits to read from buf.
 * \return true on success, false if \p bit_size is `0` or \p bv and \p buf are null pointers
 *
 * The buffer position remains changed, so the caller is expected to seek the buffer cursor back if necessary.
 *
 * Similar to `rz_bv_set_from_bytes_le()`:
 *  - The bitvector's size is unchanged.
 *  - If `bv->len` < `bit_size`, additional bits are cut off, if `bv->len` > `bit_size`, the rest is filled up with 0.
 */
RZ_API bool rz_bv_set_from_buffer_le(RZ_NONNULL RZ_OUT RzBitVector *bv, RZ_NONNULL RzBuffer *buf, ut32 bit_size) {
	rz_return_val_if_fail(bv && buf && bit_size, false);

	ut32 len = rz_bv_len(bv);
	bit_size = RZ_MIN(bit_size, len);
	ut32 byte_size = (bit_size + 7) / 8;

	// Handle sub-byte copies
	if (bit_size < 8) {
		ut8 data = 0;
		rz_buf_read(buf, &data, 1);
		rz_bv_set_from_bytes_le(bv, &data, 0, bit_size);
		return true;
	}

	if (len <= 64) {
		rz_buf_read(buf, (ut8 *)&bv->bits.small_u, byte_size);

#if RZ_HOST_IS_BIG_ENDIAN
		bv->bits.small_u = rz_swap_ut64(bv->bits.small_u);
#endif

		bv->bits.small_u &= UT64_MAX >> (64 - bit_size);
		return true;
	}

	rz_buf_read(buf, bv->bits.large_a, byte_size);
	rz_bv_set_range(bv, bit_size, len - 1, false);
	return true;
}

/**
 * Reads \p bit_size number of bits (assumed in big-endian byte order) from the current position of a RzBuffer \p buf and assigns to the value of the bitvector \p bv.
 * \param bv bitvector to assign the new value to.
 * \param buf RzBuffer containing at least `(bit_size + 7) / 8` bytes at\after the current position.
 * \param bit_size number of bits to read from \p buf.
 * \return true on success, false if \p bit_size is `0` or \p bv and \p buf are null pointers
 *
 * The buffer position remains changed, so the caller is expected to seek the buffer cursor back if necessary.
 *
 * Similar to `rz_bv_set_from_bytes_be()`:
 *  - The bitvector's size is unchanged.
 *  - If `bv->len` < `bit_size`, additional bits are cut off, if `bv->len` > `bit_size`, the rest is filled up with 0.
 */
RZ_API bool rz_bv_set_from_buffer_be(RZ_NONNULL RZ_OUT RzBitVector *bv, RZ_NONNULL RzBuffer *buf, ut32 bit_size) {
	rz_return_val_if_fail(bv && buf && bit_size, false);

	ut32 len = rz_bv_len(bv);
	bit_size = RZ_MIN(bit_size, len);
	ut32 byte_size = (bit_size + 7) / 8;

	// Handle sub-byte copies
	if (bit_size < 8) {
		ut8 data = 0;
		rz_buf_read(buf, &data, 1);
		rz_bv_set_from_bytes_be(bv, &data, 0, bit_size);
		return true;
	}

	// Specialized handling for small bitvectors (<= 64 bit)
	if (len <= 64) {
		rz_buf_read(buf, (ut8 *)&bv->bits.small_u, byte_size);

#if RZ_HOST_IS_LITTLE_ENDIAN
		bv->bits.small_u = rz_swap_ut64(bv->bits.small_u);
#endif

		bv->bits.small_u >>= 64 - len;
		bv->bits.small_u &= (UT64_MAX << (len - bit_size));
		return true;
	}

	// Handle large bitvectors (> 64 bit)
	rz_buf_read(buf, bv->bits.large_a, byte_size);
	rz_mem_swap_bytes_n_inplace(bv->bits.large_a, rz_bv_len_bytes(bv));

	if (len % 8) {
		ut32 outstanding_bits = 8 - len % 8;
		ut32 shift = rz_bv_len_bytes(bv) * 8 - len;

		bv->len += outstanding_bits; // temporary extend, so we can access all bits in LSB
		rz_bv_rshift_fill(bv, shift, false);
		bv->len -= outstanding_bits;
	}

	rz_bv_set_range(bv, 0, len - bit_size - 1, false);
	return true;
}

/**
 * \brief Helper function for calling `rz_bv_set_from_buffer_be()` or `rz_bv_set_from_buffer_le()` based on a flag
 * \param bv bitvector to assign the new value to.
 * \param buf RzBuffer containing at least `(bit_size + 7) / 8` bytes at\after the current position.
 * \param bit_size number of bits to read from \p buf
 * \param big_endian control flag for specifying endian type
 * \return true on success, false if \p bit_size is `0` or \p bv and \p buf are null pointers
 */
RZ_API bool rz_bv_set_from_buffer_ble(RZ_NONNULL RZ_OUT RzBitVector *bv, RZ_NONNULL RzBuffer *buf, ut32 bit_size, bool big_endian) {
	if (big_endian) {
		return rz_bv_set_from_buffer_be(bv, buf, bit_size);
	}
	return rz_bv_set_from_buffer_le(bv, buf, bit_size);
}

/**
 * \brief Set the buffer contents from the given bitvector's bits in little endian format.
 * \param bv  BitVector to use as source of the bits
 * \param buf buffer to write little endian data.
 */
RZ_API void rz_bv_set_to_bytes_le(RZ_NONNULL const RzBitVector *bv, RZ_OUT RZ_NONNULL ut8 *buf) {
	rz_return_if_fail(bv && buf);
	ut32 bytes = rz_bv_len_bytes(bv);
	if (bv->len > 64) {
		for (ut32 i = 0; i < bytes; i++) {
			if (i + 1 == bytes && bv->len % 8) {
				buf[i] &= (0xff << (bv->len % 8)) & 0xff;
				buf[i] |= bv->bits.large_a[i];
			} else {
				buf[i] = bv->bits.large_a[i];
			}
		}
		return;
	}
	ut64 val = bv->bits.small_u;
	for (ut32 i = 0; i < bytes; i++) {
		if (i + 1 == bytes && bv->len % 8) {
			buf[i] &= (0xff << (bv->len % 8)) & 0xff;
			buf[i] |= val & 0xff;
		} else {
			buf[i] = val & 0xff;
		}
		val >>= 8;
	}
}

RZ_API void rz_bv_set_to_bytes_ble(RZ_NONNULL const RzBitVector *bv, RZ_OUT RZ_NONNULL ut8 *buf, bool big_endian) {
	if (big_endian) {
		rz_bv_set_to_bytes_be(bv, buf);
	} else {
		rz_bv_set_to_bytes_le(bv, buf);
	}
}

/**
 * \brief Set the buffer contents from the given bitvector's bits in big endian format.
 * \param bv  BitVector to use as source of the bits
 * \param buf buffer to write big endian data.
 */
RZ_API void rz_bv_set_to_bytes_be(RZ_NONNULL const RzBitVector *bv, RZ_OUT RZ_NONNULL ut8 *buf) {
	rz_return_if_fail(bv && buf);
	ut32 bytes = rz_bv_len_bytes(bv);
	if (bv->len > 64) {
		ut32 end = bytes - 1;
		for (ut32 i = 0; i < bytes; i++) {
			buf[end - i] = bv->bits.large_a[i];
		}
		return;
	}
	ut64 val = bv->bits.small_u;
	for (ut32 i = bytes - 1; i; i--) {
		buf[i] = val & 0xFF;
		val >>= 8;
	}
	buf[0] = val & 0xFF;
}

/**
 * Calculates the hash from the bitvector data
 * \param x BitVector
 * \return ut32 bitvector hash
 */
RZ_API ut32 rz_bv_hash(RZ_NULLABLE RzBitVector *x) {
	ut32 h = 5381;
	if (!x) {
		return h;
	}

	ut32 size = (x->len > 64) ? NELEM(x->len, BV_ELEM_SIZE) : sizeof(x->bits.small_u);
	ut8 *bits = (x->len > 64) ? x->bits.large_a : (ut8 *)&x->bits.small_u;
	if (!size || !bits) {
		return h;
	}

	for (ut32 i = 0; i < size; ++i) {
		h = (h + (h << 5)) ^ bits[i];
	}

	h ^= x->len;
	return h;
}

/**
 * Convert bitv to a ut8 value
 * \param x BitVector
 * \return  ut8 value
 */
RZ_API ut8 rz_bv_to_ut8(RZ_NONNULL const RzBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return (ut8)x->bits.small_u & UT8_MAX;
	}
	ut8 ret = 0;
	for (ut32 i = 0; i < x->len && i < 8; ++i) {
		if (rz_bv_get(x, i)) {
			ret |= 1 << i;
		}
	}
	return ret;
}

/**
 * Convert bitv to ut16 value
 * \param x BitVector
 * \return ut16 value
 */
RZ_API ut16 rz_bv_to_ut16(RZ_NONNULL const RzBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return (ut16)x->bits.small_u & UT16_MAX;
	}
	ut16 ret = 0;
	for (ut32 i = 0; i < x->len && i < 16; ++i) {
		if (rz_bv_get(x, i)) {
			ret |= 1 << i;
		}
	}
	return ret;
}

/**
 * Convert bitv to ut32 value
 * \param x BitVector
 * \return ut32 value
 */
RZ_API ut32 rz_bv_to_ut32(RZ_NONNULL const RzBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return (ut32)x->bits.small_u & UT32_MAX;
	}
	ut32 ret = 0;
	for (ut32 i = 0; i < x->len && i < 32; ++i) {
		if (rz_bv_get(x, i)) {
			ret |= 1 << i;
		}
	}
	return ret;
}

/**
 * Convert RzBitVector to ut64
 * \param x RzBitVector, pointer to the bitvector
 * \return ret ut64, num value of bitvector
 */
RZ_API ut64 rz_bv_to_ut64(RZ_NONNULL const RzBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return x->bits.small_u;
	}
	ut64 ret = 0;
	for (ut32 i = 0; i < x->len && i < 64; ++i) {
		if (rz_bv_get(x, i)) {
			ret |= 1ULL << i;
		}
	}
	return ret;
}

/**
 * set a range of bits to bool value `b`, the range is inclusive
 * pos_end element is also included
 * \param bv RzBitVector
 * \param pos_start start index of range
 * \param pos_end end index of range
 * \param b bool value
 * \return return true if success, else return false
 */
RZ_API bool rz_bv_set_range(RZ_NONNULL RzBitVector *bv, ut32 pos_start, ut32 pos_end, bool b) {
	rz_return_val_if_fail(bv, false);
	if (pos_start > bv->len - 1 || pos_end > bv->len - 1) {
		return false;
	}

	if (pos_start > pos_end) {
		return false;
	}

	ut32 nbit = pos_end - pos_start + 1;

	if (bv->len <= 64) {
		ut64 value = b ? UT64_MAX : 0;
		bv->bits.small_u = rz_bits_copy_ut64(value, 0, bv->bits.small_u, pos_start, nbit);
		return true;
	}

	ut8 value = b ? UT8_MAX : 0;
	ut8 start_bits = RZ_MIN((BV_ELEM_SIZE - pos_start) % BV_ELEM_SIZE, nbit);
	ut8 trailing_bits = RZ_MIN((pos_start + nbit) % BV_ELEM_SIZE, nbit - start_bits);
	ut64 middle_bytes = (nbit - start_bits - trailing_bits) / BV_ELEM_SIZE;
	ut64 byte_index = pos_start / BV_ELEM_SIZE;

	if (start_bits > 0) {
		bv->bits.large_a[byte_index] = rz_bits_copy_ut8(value, 0, bv->bits.large_a[byte_index], pos_start % BV_ELEM_SIZE, start_bits);
		byte_index++;
	}

	if (middle_bytes > 0) {
		memset(&bv->bits.large_a[byte_index], value, middle_bytes);
		byte_index += middle_bytes;
	}

	if (trailing_bits > 0) {
		bv->bits.large_a[byte_index] = rz_bits_copy_ut8(value, 0, bv->bits.large_a[byte_index], 0, trailing_bits);
	}

	return true;
}

/**
 * check if bitvector's bits are all set to bit 1
 * \param x RzBitVector
 * \return true if all bits of bv `x` are set to 1
 */
RZ_API bool rz_bv_is_all_one(RZ_NONNULL const RzBitVector *x) {
	rz_return_val_if_fail(x, false);
	// could not use ~0 as full-vector when bits < 64

	for (ut32 i = 0; i < x->len; ++i) {
		if (rz_bv_get(x, i) == 0) {
			return false;
		}
	}
	return true;
}

/**
 * get predecessor of bv (dec 1) in 2^n modulo
 * \param bv
 * \return predecessor of bv
 */
RZ_API RZ_OWN RzBitVector *rz_bv_pred(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	ut32 len = bv->len;
	if (len <= 64) {
		ut64 val = rz_bv_to_ut64(bv);
		val -= 1;
		return rz_bv_new_from_ut64(len, val);
	}

	RzBitVector *one = rz_bv_new_one(len);
	RzBitVector *result = rz_bv_sub(bv, one, NULL);
	rz_bv_free(one);

	return result;
}

/**
 * get successor of bv (inc 1) in 2^n modulo
 * \param bv
 * \return successor of bv
 */
RZ_API RZ_OWN RzBitVector *rz_bv_succ(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	ut32 len = bv->len;
	if (len <= 64) {
		ut64 val = rz_bv_to_ut64(bv);
		val += 1;
		return rz_bv_new_from_ut64(len, val);
	}

	RzBitVector *one = rz_bv_new_one(len);
	RzBitVector *result = rz_bv_sub(bv, one, NULL);
	rz_bv_free(one);

	return result;
}

/**
 * Arithmetic right shift of bv, shift right with (msb bv) bit filled
 * \param bv
 * \param dist shift distance
 * \return true if success
 */
RZ_API bool rz_bv_arshift(RZ_NONNULL RzBitVector *bv, ut32 dist) {
	rz_return_val_if_fail(bv, false);
	bool msb = rz_bv_msb(bv);
	return rz_bv_rshift_fill(bv, dist, msb);
}

/**
 * cast bv to sort (to_size), fill with fill_bit. fill_bit has no effect if it's a narrowing cast
 * If m = size s - size (sort b) > 0 then m bits b are pre-pended to the most significant part of the vector.
 * \param bv The vector which is cast in place. Its length changes.
 * \param to_size new bit vector length.
 * \param fill_bit specify filling bit if extend.
 * \return True if casting succeeded, false in case of failure.
 */
RZ_API bool rz_bv_cast_inplace(RZ_INOUT RZ_NONNULL RzBitVector *bv, ut32 to_size, bool fill_bit) {
	rz_return_val_if_fail(bv, false);
	if (to_size == bv->len) {
		return true;
	}
	if (bv->len <= 64 && to_size <= 64) {
		rz_bv_set_range(bv, to_size, bv->len - 1, fill_bit);
		bv->len = to_size;
		return true;
	}
	if (NELEM(to_size, BV_ELEM_SIZE) > bv->_elem_len) {
		// The bit vector needs a larger buffer.
		resize_large_a(bv, NELEM(to_size, BV_ELEM_SIZE));
	}
	size_t old_size = bv->len;
	if (bv->len <= 64) {
		if (bv_copy_nbits_small_to_large(bv, 0, bv, 0, old_size) != old_size) {
			return false;
		}
	} else if (to_size <= 64) {
		if (bv_copy_nbits_large_to_small(bv, 0, bv, 0, to_size) != to_size) {
			return false;
		}
	} else if (to_size >= old_size) {
		if (bv_copy_nbits_large_aligned(bv, 0, bv, 0, old_size) != old_size) {
			return false;
		}
	} else {
		if (bv_copy_nbits_large_aligned(bv, 0, bv, 0, to_size) != to_size) {
			return false;
		}
	}
	bv->len = to_size;
	rz_bv_set_range(bv, old_size, to_size - 1, fill_bit);
	return true;
}

/**
 * cast bv to sort (to_size), fill with fill_bit. fill_bit has no effect if it's a narrowing cast
 * If m = size s - size (sort b) > 0 then m bits b are prepended to the most significant part of the vector.
 * \param bv
 * \param to_size new bitvector length
 * \param fill_bit specify filling bit if extend
 * \return new bv with length (to_size)
 */
RZ_API RzBitVector *rz_bv_cast(RZ_NONNULL RzBitVector *bv, ut32 to_size, bool fill_bit) {
	rz_return_val_if_fail(bv, NULL);

	RzBitVector *ret = rz_bv_new(to_size);
	rz_bv_set_all(ret, fill_bit);
	rz_bv_copy_nbits(ret, 0, bv, 0, RZ_MIN(bv->len, to_size));

	return ret;
}

/**
 * signed cast of bv, (signed_cast x n) = (cast x n (msb x))
 * \param bv
 * \param to_size cast bitvector length
 * \return new bv with length (to_size)
 */
RZ_API RZ_OWN RzBitVector *rz_bv_signed_cast(RZ_NONNULL RzBitVector *bv, ut32 to_size) {
	return rz_bv_cast(bv, to_size, rz_bv_msb(bv));
}

/**
 * unsigned cast of bv, (unsigned_cast x n) = (cast x n 0)
 * \param bv
 * \param to_size cast bitvector length
 * \return new bv with length (to_size)
 */
RZ_API RZ_OWN RzBitVector *rz_bv_unsigned_cast(RZ_NONNULL RzBitVector *bv, ut32 to_size) {
	return rz_bv_cast(bv, to_size, false);
}

/**
 * strict signed less than, x < y
 * \param x bv as signed value
 * \param y bv as signed value
 * \return compare result as bool value
 */
RZ_API bool rz_bv_slt(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	// x < y === !(x >= y) === !(y <= x)
	return !rz_bv_sle(y, x);
}

/**
 * strict unsigned less than, x < y
 * \param x bv as unsigned
 * \param y bv as unsigned
 * \return
 */
RZ_API bool rz_bv_ult(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	return !rz_bv_ule(y, x);
}

/**
 * strict signed great then, x > y
 * \param x bv as signed
 * \param y bv as signed
 * \return
 */
RZ_API bool rz_bv_sgt(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	return !rz_bv_sle(x, y);
}

/**
 * strict unsigned great than, x > y
 * \param x bv as unsigned
 * \param y bv as unsigned
 * \return
 */
RZ_API bool rz_bv_ugt(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	return !rz_bv_ule(x, y);
}

/**
 * strict signed great than or equal, x >= y
 * \param x bv as signed
 * \param y bv as signed
 * \return
 */
RZ_API bool rz_bv_sge(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	return rz_bv_sle(y, x);
}

/**
 * strict unsigned great than or equal, x >= y
 * \param x bv as unsigned
 * \param y bv as unsigned
 * \return
 */
RZ_API bool rz_bv_uge(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	return rz_bv_ule(y, x);
}
