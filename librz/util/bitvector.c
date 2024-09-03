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
	if (bv->len > 64) {
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
	size_t str_len = (bv->_elem_len << 1) + 3; // 0x + \0
	char *str = (char *)malloc(str_len);
	if (!str) {
		return NULL;
	}

	str[0] = '0';
	str[1] = 'x';
	ut32 j = 2;
	for (ut32 i = 0; i < bv->_elem_len; i++) {
		ut8 b8 = bv->bits.large_a[bv->_elem_len - i - 1];
		ut8 high = b8 >> 4;
		ut8 low = b8 & 15;
		if (pad || high) {
			str[j++] = hex[high];
			pad = true; // pad means "print all" from now on
		}
		if (pad || low || i == bv->_elem_len - 1) {
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
	if (!new_bv || !rz_bv_copy(bv, new_bv)) {
		rz_bv_free(new_bv);
		return NULL;
	}

	return new_bv;
}

/**
 * Copy from source bitvector to destination bitvector
 * the maximum copied size depends on MIN(src_len, dst_len)
 * \param src RzBitVector, the source bitvector
 * \param dst RzBitVector, the destination bitvector
 * \return Actual size of copy
 */
RZ_API ut32 rz_bv_copy(RZ_NONNULL const RzBitVector *src, RZ_NONNULL RzBitVector *dst) {
	rz_return_val_if_fail(src && dst, 0);

	if (dst->len != src->len) {
		rz_warn_if_reached();
		return 0;
	} else if (dst->len <= 64) {
		dst->bits.small_u = src->bits.small_u;
		return sizeof(dst->bits.small_u);
	}

	rz_return_val_if_fail(src->bits.large_a && dst->bits.large_a, 0);
	memcpy(dst->bits.large_a, src->bits.large_a, dst->_elem_len);
	return dst->_elem_len;
}

/**
 * Copy n bits from start position of source to start position of dest, return num of copied bits
 * \param src RzBitVector, data source
 * \param src_start_pos ut32, start position in source bitvector of copy
 * \param dst RzBitVector, destination of copy
 * \param dst_start_pos ut32, start position in destination bitvector
 * \param nbit ut32, control the size of copy (in bits)
 * \return copied_size ut32, Actual copied size
 */
RZ_API ut32 rz_bv_copy_nbits(RZ_NONNULL const RzBitVector *src, ut32 src_start_pos, RZ_NONNULL RzBitVector *dst, ut32 dst_start_pos, ut32 nbit) {
	rz_return_val_if_fail(src && dst, 0);

	ut32 max_nbit = RZ_MIN((src->len - src_start_pos),
		(dst->len - dst_start_pos));

	// prevent overflow
	if (max_nbit < nbit) {
		return 0;
	}

	// normal case here
	for (ut32 i = 0; i < nbit; ++i) {
		bool c = rz_bv_get(src, src_start_pos + i);
		rz_bv_set(dst, dst_start_pos + i, c);
	}

	return nbit;
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
	rz_bv_copy_nbits(low, 0, ret, 0, low->len);
	rz_bv_copy_nbits(high, 0, ret, low->len, high->len);
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
	}

	rz_return_val_if_fail(bv->bits.large_a, false);
	for (ut32 i = 0; i < bv->_elem_len; ++i) {
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
		return false;
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

	int copied_size = rz_bv_copy_nbits(bv, 0, &tmp, size, bv->len - size);
	if (copied_size == 0) {
		rz_bv_fini(&tmp);
		return false;
	}

	rz_bv_copy(&tmp, bv);
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
		return false;
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

	int copied_size = rz_bv_copy_nbits(bv, size, &tmp, 0, bv->len - size);
	if (copied_size == 0) {
		rz_bv_fini(&tmp);
		return false;
	}

	rz_bv_copy(&tmp, bv);
	rz_bv_fini(&tmp);

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

	RzBitVector *ret = rz_bv_new(x->len);
	if (!ret) {
		return NULL;
	} else if (x->len <= 64) {
		ret->bits.small_u = x->bits.small_u & y->bits.small_u;
		return ret;
	}

	for (ut32 i = 0; i < ret->_elem_len; ++i) {
		ret->bits.large_a[i] = x->bits.large_a[i] & y->bits.large_a[i];
	}
	return ret;
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

	RzBitVector *ret = rz_bv_new(x->len);
	if (!ret) {
		return NULL;
	} else if (x->len <= 64) {
		ret->bits.small_u = x->bits.small_u | y->bits.small_u;
		return ret;
	}

	for (ut32 i = 0; i < ret->_elem_len; ++i) {
		ret->bits.large_a[i] = x->bits.large_a[i] | y->bits.large_a[i];
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
RZ_API RZ_OWN RzBitVector *rz_bv_xor(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *ret = rz_bv_new(x->len);
	if (!ret) {
		return NULL;
	} else if (x->len <= 64) {
		ret->bits.small_u = x->bits.small_u ^ y->bits.small_u;
		return ret;
	}

	for (ut32 i = 0; i < ret->_elem_len; ++i) {
		ret->bits.large_a[i] = x->bits.large_a[i] ^ y->bits.large_a[i];
	}
	return ret;
}

/**
 * Get the 1's complement of bv
 * \param bv RzBitVector, operand
 * \return ret RzBitVector, a new bitvector, which is the 1's complement of bv
 */
RZ_API RZ_OWN RzBitVector *rz_bv_complement_1(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	RzBitVector *ret = rz_bv_new(bv->len);
	if (!ret) {
		return NULL;
	} else if (ret->len <= 64) {
		ret->bits.small_u = ~bv->bits.small_u;
		ret->bits.small_u &= UT64_MAX >> (64 - ret->len);
		return ret;
	}

	if (!(ret->bits.large_a && bv->bits.large_a)) {
		rz_bv_free(ret);
		rz_return_val_if_reached(NULL);
	}
	for (ut32 i = 0; i < bv->_elem_len; ++i) {
		ret->bits.large_a[i] = ~bv->bits.large_a[i];
	}
	return ret;
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

	ut32 i;
	for (i = 0; i < bv->len; ++i) {
		if (rz_bv_get(bv, i) == true) {
			break;
		}
	}

	// assert bv[i] == true now
	i += 1;
	for (; i < bv->len; ++i) {
		rz_bv_toggle(ret, i);
	}

	return ret;
}

/**
 * Result of (x + y) mod 2^length
 * Both operands must have the same length.
 * \param x RzBitVector, Operand
 * \param y RzBitVector, Operand
 * \param carry bool*, bool pointer to where to save the carry value.
 * \return ret RzBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzBitVector *rz_bv_add(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *carry) {
	rz_return_val_if_fail(x && y, NULL);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	bool a = false, b = false, _carry = false;
	RzBitVector *ret = rz_bv_new(x->len);

	for (ut32 pos = 0; pos < x->len; ++pos) {
		a = rz_bv_get(x, pos);
		b = rz_bv_get(y, pos);
		rz_bv_set(ret, pos, a ^ b ^ _carry);
		_carry = ((a & b) | (a & _carry)) | (b & _carry);
	}
	if (carry) {
		*carry = _carry;
	}

	return ret;
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

	RzBitVector *ret;
	RzBitVector *neg_y;

	neg_y = rz_bv_neg(y);
	ret = rz_bv_add(x, neg_y, borrow);
	rz_bv_free(neg_y);
	return ret;
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

	RzBitVector dump;
	bool cur_bit = false;

	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	if (!rz_bv_init(&dump, x->len)) {
		return NULL;
	}
	RzBitVector *result = rz_bv_new(x->len);
	if (!result) {
		goto exit;
	}
	rz_bv_copy(x, &dump);

	for (ut32 i = 0; i < y->len; ++i) {
		cur_bit = rz_bv_get(y, i);
		if (cur_bit) {
			RzBitVector *tmp = rz_bv_add(result, &dump, NULL);
			rz_bv_free(result);
			result = tmp;
		}
		rz_bv_lshift(&dump, 1);
	}

exit:
	rz_bv_fini(&dump);
	return result;
}

/* Treat x, y as unsigned
 * Both operands must have the same length.
 * if x < y return negtive (-1)
 * if x == y return 0
 * if x > y return positive (+1)
 */
int bv_unsigned_cmp(RZ_NONNULL RzBitVector *x, RZ_NONNULL RzBitVector *y) {
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

	if (rz_bv_is_zero_vector(y)) {
		RzBitVector *ret = rz_bv_new(y->len);
		rz_bv_set_all(ret, true);
		return ret;
	}

	if (x->len <= 64) {
		return rz_bv_new_from_ut64(x->len, rz_bv_to_ut64(x) / rz_bv_to_ut64(y));
	}

	int compare_result = bv_unsigned_cmp(x, y);
	// dividend < divisor
	// remainder = dividend, quotient = 0
	if (compare_result < 0) {
		return rz_bv_new(x->len);
	}
	// dividend == divisor
	// remainder = 0, quotient = 1
	if (compare_result == 0) {
		return rz_bv_new_one(rz_bv_len(x));
	}

	// dividend > divisor
	// do typical division by shift and subtract
	RzBitVector *dend = rz_bv_dup(x);
	RzBitVector *sor = rz_bv_dup(y);
	// shift the divisor left to align both highest bits
	ut32 sorlz = rz_bv_clz(sor);
	ut32 shift = sorlz - rz_bv_clz(dend);
	rz_bv_lshift(sor, shift);
	RzBitVector *quot = rz_bv_new_zero(rz_bv_len(x));
	for (ut32 b = shift + 1; b; b--) {
		if (rz_bv_ule(sor, dend)) {
			rz_bv_set(quot, b - 1, true);
			RzBitVector *tmp = rz_bv_sub(dend, sor, NULL);
			rz_bv_free(dend);
			dend = tmp;
		}
		rz_bv_rshift(sor, 1);
	}
	rz_bv_free(dend);
	rz_bv_free(sor);
	return quot;
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
	if (rz_bv_is_zero_vector(y)) {
		return rz_bv_dup(x);
	}
	RzBitVector *quot = rz_bv_div(x, y);
	RzBitVector *remul = rz_bv_mul(quot, y);
	RzBitVector *r = rz_bv_sub(x, remul, NULL);
	rz_bv_free(quot);
	rz_bv_free(remul);
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

	if (mx && my) {
		neg_x = rz_bv_neg(x);
		neg_y = rz_bv_neg(y);

		ret = rz_bv_div(neg_x, neg_y);
		rz_bv_free(neg_x);
		rz_bv_free(neg_y);
		return ret;
	}

	return NULL; // something wrong
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

	if (mx && my) {
		neg_x = rz_bv_neg(x);
		neg_y = rz_bv_neg(y);

		tmp = rz_bv_mod(neg_x, neg_y);
		ret = rz_bv_neg(tmp);
		rz_bv_free(neg_x);
		rz_bv_free(neg_y);
		rz_bv_free(tmp);
		return ret;
	}

	return NULL; // something wrong
}

/**
 * Get the most significant bit of bitvector
 * \param bv RzBitVector, operand
 * \return b bit, bool value of MSB
 */
RZ_API bool rz_bv_msb(RZ_NONNULL RzBitVector *bv) {
	return rz_bv_get(bv, bv->len - 1);
}

/**
 * Get the least significant bit of bitvector
 * \param bv RzBitVector, operand
 * \return b bit, bool value of LSB
 */
RZ_API bool rz_bv_lsb(RZ_NONNULL RzBitVector *bv) {
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

	for (ut32 i = 0; i < x->_elem_len; ++i) {
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
	rz_return_if_fail(buf && size);
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
	rz_return_if_fail(buf && size);
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

	ut32 size = (x->len > 64) ? x->_elem_len : sizeof(x->bits.small_u);
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

	for (ut32 i = pos_start; i <= pos_end; ++i) {
		rz_bv_set(bv, i, b);
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
	rz_bv_copy_nbits(bv, 0, ret, 0, RZ_MIN(bv->len, to_size));

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
