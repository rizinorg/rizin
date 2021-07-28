// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bitvector.h"

/**
 * New a `length`-bits bitvector
 * \param length int, the length of bitvector
 * \return bv BitVector, pointer to the new bitvector instance
 */
RZ_API BitVector rz_il_bv_new(int length) {
	BitVector ret = (BitVector)malloc(sizeof(struct bitvector_t));
	if (ret == NULL) {
		return NULL;
	}

	// how much ut8 do we need to represent `length` bits ?
	int real_elem_cnt = NELEM(length, sizeof(ut8));

	ret->bits = (ut8 *)malloc(real_elem_cnt * sizeof(ut8));
	ret->len = length;
	ret->_elem_len = real_elem_cnt;

	if (ret->bits == NULL) {
		free(ret);
		ret = NULL;
		printf("Malloc Failed\n");
		return ret;
	}

	memset(ret->bits, 0, ret->_elem_len);
	return ret;
}

/**
 * Free a bitvector
 * \param bv BitVector, pointer to the bitvector you want to free
 */
RZ_API void rz_il_bv_free(BitVector bv) {
	if (bv && bv->bits) {
		free(bv->bits);
	}

	if (bv) {
		free(bv);
	}
}

/**
 * Dump a bitvector
 * \param bv BitVector, pointer to the source bitvector
 * \return dump BitVector, pointer to a new bitvector, which is a copy of source
 */
RZ_API BitVector rz_il_bv_dump(BitVector bv) {
	// dump bv to a new one
	if (!bv || !(bv->bits)) {
		return NULL;
	}

	BitVector new_bv = rz_il_bv_new(bv->len);
	if (!new_bv || !(new_bv->bits)) {
		return NULL;
	}

	for (int i = 0; i < bv->_elem_len; ++i) {
		new_bv->bits[i] = bv->bits[i];
	}

	return new_bv;
}

/**
 * copy from source bitvector to destination bitvector
 * the maximum copied size depends on MIN(src_len, dst_len)
 * \param src BitVector, the source bitvector
 * \param dst BitVector, the destination bitvector
 * \return Actual size of copy
 */
RZ_API int rz_il_bv_copy(BitVector src, BitVector dst) {
	if (!dst || !(dst->bits) || !src || !(src->bits)) {
		return 0;
	}

	if (dst->len != src->len) {
		return 0;
	}

	for (int i = 0; i < dst->_elem_len; ++i) {
		dst->bits[i] = src->bits[i];
	}

	return dst->_elem_len;
}

/**
 * Copy n bits from start position of source to start position of dest
 * \param src BitVector, data source
 * \param src_start_pos int, start position in source bitvector of copy
 * \param dst BitVector, destination of copy
 * \param dst_start_pos int, start position in destination bitvector
 * \param nbit int, control the size of copy (in bits)
 * \return copied_size int, Actual copied size
 */
RZ_API int rz_il_bv_copy_nbits(
	BitVector src, int src_start_pos,
	BitVector dst, int dst_start_pos,
	int nbit) {
	if (!dst || !(dst->bits) || !src || !(src->bits)) {
		return 0;
	}

	int max_nbit = RZ_MIN((src->len - src_start_pos),
		(dst->len - dst_start_pos));

	// prevent overflow
	if (max_nbit < nbit) {
		return 0;
	}

	// normal case here
	for (int i = 0; i < max_nbit; ++i) {
		bit c = rz_il_bv_get(src, src_start_pos + i);
		rz_il_bv_set(dst, dst_start_pos + i, c);
	}

	return nbit;
}

/**
 * Adjust bitvector to a new length
 * TODO : remove this and replace with append/prepend/cut_head/cut_tail
 * \param bv BitVector, pointer to bv need adjustment
 * \param new_len int, target length
 * \return ret BitVector, pointer to the new bitvector
 */
BitVector bv_adjust(BitVector bv, int new_len) {
	if (!bv || !bv->bits) {
		return NULL;
	}

	BitVector ret = rz_il_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	int max_len = RZ_MIN(ret->_elem_len, bv->_elem_len);
	for (int i = 0; i < max_len; ++i) {
		ret->bits[i] = bv->bits[i];
	}
	return ret;
}

/**
 * Prepend bv with n zero bits
 * \param bv BitVector, pointer to bitvector instance
 * \param delta_len int, the number of zero bits
 * \return ret BitVector, pointer to the new bitvector instance
 */
RZ_API BitVector rz_il_bv_prepend_zero(BitVector bv, int delta_len) {
	if (!bv || !bv->bits) {
		return NULL;
	}

	int new_len = bv->len + delta_len;
	BitVector ret = rz_il_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	int pos = delta_len;
	for (int i = 0; i < bv->len; ++i, ++pos) {
		rz_il_bv_set(ret, pos, rz_il_bv_get(bv, i));
	}
	return ret;
}

/**
 * Append bv with n zero bits
 * \param bv BitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret BitVector, pointert to the new btivector
 */
RZ_API BitVector rz_il_bv_append_zero(BitVector bv, int delta_len) {
	if (!bv || !bv->bits) {
		return NULL;
	}

	int new_len = bv->len + delta_len;
	BitVector ret = rz_il_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	for (int i = 0; i < bv->_elem_len; ++i) {
		ret->bits[i] = bv->bits[i];
	}
	return ret;
}

/**
 * Cut n zero bits from head
 * \param bv BitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret BitVector, pointert to the new btivector
 */
RZ_API BitVector rz_il_bv_cut_head(BitVector bv, int delta_len) {
	int new_len = bv->len - delta_len;
	BitVector ret = rz_il_bv_new(new_len);
	if (!ret) {
		return NULL;
	}

	int pos, i;
	for (pos = 0, i = delta_len; pos < new_len; ++i, ++pos) {
		rz_il_bv_set(ret, pos, rz_il_bv_get(bv, i));
	}

	return ret;
}

/**
 * Cut n zero bits from tail
 * \param bv BitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret BitVector, pointert to the new btivector
 */
RZ_API BitVector rz_il_bv_cut_tail(BitVector bv, int delta_len) {
	int new_len = bv->len - delta_len;
	BitVector ret = rz_il_bv_new(new_len);
	if (!ret) {
		return NULL;
	}

	for (int pos = 0; pos < new_len; ++pos) {
		rz_il_bv_set(ret, pos, rz_il_bv_get(bv, pos));
	}

	return ret;
}

/**
 * Concat bv1 and bv2 to get new bitvector
 * \param bv1 BitVector
 * \param bv2 BitVector
 * \return ret BitVector, the new bitvector
 */
RZ_API BitVector rz_il_bv_concat(BitVector bv1, BitVector bv2) {
	if (!bv1 || !bv2 || !bv1->bits || !bv2->bits) {
		return NULL;
	}

	// 1. create a max length new_bv
	int new_len = bv1->len + bv2->len;

	// 2. adjust two vector to max_len bv
	BitVector ret = bv_adjust(bv1, new_len);

	// 3. shift 2nd bv
	BitVector assistant = bv_adjust(bv2, new_len);
	rz_il_bv_rshift(assistant, bv1->len);

	// 4. `or` two bitvectors to get the final result
	for (int i = 0; i < new_len; ++i) {
		ret->bits[i] |= assistant->bits[i];
	}

	rz_il_bv_free(assistant);
	return ret;
}

/**
 * Set a bit at position to true or false
 * \param bv BitVector, pointer to bv
 * \param pos int, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_il_bv_set(BitVector bv, int pos, bit b) {
	if (b) {
		(bv->bits)[pos / BV_ELEM_SIZE] |= (1u << (pos % BV_ELEM_SIZE));
	} else {
		(bv->bits)[pos / BV_ELEM_SIZE] &= ~(1u << (pos % BV_ELEM_SIZE));
	}

	return b;
}

/**
 * Set all bits to true or false
 * \param bv BitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_il_bv_set_all(BitVector bv, bit b) {
	if (b) {
		for (int i = 0; i < bv->len; ++i) {
			bv->bits[i] = ~((ut8)0);
		}
	} else {
		for (int i = 0; i < bv->len; ++i) {
			bv->bits[i] = 0;
		}
	}

	return b;
}

/**
 * Invert a bit at position
 * \param bv BitVector, pointer to bv
 * \param pos int, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_il_bv_toggle(BitVector bv, int pos) {
	bit cur_bit = rz_il_bv_get(bv, pos);
	bit new_bit = cur_bit ? false : true;
	rz_il_bv_set(bv, pos, new_bit);
	return new_bit;
}

/**
 * Invert every bits
 * \param bv BitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_il_bv_toggle_all(BitVector bv) {
	for (int i = 0; i < bv->_elem_len; ++i) {
		(bv->bits)[i] = ~((bv->bits)[i]);
	}
	return true;
}

/**
 * Get bit at position from bitvector
 * \param bv BitVector, pointer to bv
 * \param pos int, position
 * \return ret bit, bool value of bit
 */
RZ_API bit rz_il_bv_get(BitVector bv, int pos) {
	return ((bv->bits)[pos / BV_ELEM_SIZE] & (1u << (pos % BV_ELEM_SIZE))) ? true : false;
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv BitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_lshift(BitVector bv, int size) {
	return rz_il_bv_lshift_fill(bv, size, false);
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv BitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_rshift(BitVector bv, int size) {
	return rz_il_bv_rshift_fill(bv, size, false);
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill the bitvector with `fill_bit`
 * \param bv BitVector, pointert to bv
 * \param size int, shift bits
 * \param fill_bit bool, bit used in filling
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_lshift_fill(BitVector bv, int size, bool fill_bit) {
	// left shift
	if (size <= 0) {
		return false;
	}

	if (size >= bv->len) {
		rz_il_bv_set_all(bv, fill_bit);
		return true;
	}

	BitVector tmp = rz_il_bv_new(bv->len);
	rz_il_bv_set_all(tmp, fill_bit);

	int copied_size = rz_il_bv_copy_nbits(bv, size, tmp, 0, bv->len - size);
	if (copied_size == 0) {
		rz_il_bv_free(tmp);
		return false;
	}

	for (int i = 0; i < tmp->_elem_len; ++i) {
		bv->bits[i] = tmp->bits[i];
	}
	rz_il_bv_free(tmp);

	return true;
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill the bitvector with `fill_bit`
 * \param bv BitVector, pointert to bv
 * \param size int, shift bits
 * \param fill_bit bool, bit used in filling
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_rshift_fill(BitVector bv, int size, bool fill_bit) {
	// left shift
	if (size <= 0) {
		return false;
	}

	if (size >= bv->len) {
		rz_il_bv_set_all(bv, fill_bit);
		return true;
	}

	BitVector tmp = rz_il_bv_new(bv->len);
	rz_il_bv_set_all(tmp, fill_bit);

	int copied_size = rz_il_bv_copy_nbits(bv, 0, tmp, size, tmp->len - size);
	if (copied_size == 0) {
		rz_il_bv_free(tmp);
		return false;
	}

	for (int i = 0; i < tmp->_elem_len; ++i) {
		bv->bits[i] = tmp->bits[i];
	}
	rz_il_bv_free(tmp);

	return true;
}

/**
 * Result of x AND y (`and` operation to every bits)
 * x and y should have the same length
 * \param x BitVector, operand
 * \param y BitVector, operand
 * \return ret BitVector, a new bitvector, which is the result of AND
 */
RZ_API BitVector rz_il_bv_and(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	BitVector ret = rz_il_bv_new(x->len);
	for (int i = 0; i < ret->_elem_len; ++i) {
		ret->bits[i] = x->bits[i] & y->bits[i];
	}
	return ret;
}

/**
 * Result of x OR y (`or` operation to every bits)
 * x and y should have the same length
 * \param x BitVector, operand
 * \param y BitVector, operand
 * \return ret BitVector, a new bitvector, which is the result of OR
 */
RZ_API BitVector rz_il_bv_or(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	BitVector ret = rz_il_bv_new(x->len);
	for (int i = 0; i < ret->_elem_len; ++i) {
		ret->bits[i] = x->bits[i] | y->bits[i];
	}
	return ret;
}

/**
 * Result of x XOR y (`xor` operation to every bits)
 * x and y should have the same length
 * \param x BitVector, operand
 * \param y BitVector, operand
 * \return ret BitVector, a new bitvector, which is the result of XOR
 */
RZ_API BitVector rz_il_bv_xor(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	BitVector ret = rz_il_bv_new(x->len);
	for (int i = 0; i < ret->_elem_len; ++i) {
		ret->bits[i] = x->bits[i] ^ y->bits[i];
	}
	return ret;
}

/**
 * Get the 1's complement of bv
 * \param bv BitVector, operand
 * \return ret BitVector, a new bitvector, which is the 1's complement of bv
 */
RZ_API BitVector rz_il_bv_complement_1(BitVector bv) {
	BitVector ret = rz_il_bv_new(bv->len);
	int real_elem_cnt = bv->_elem_len;
	for (int i = 0; i < real_elem_cnt; ++i) {
		ret->bits[i] = ~bv->bits[i];
	}
	return ret;
}

/**
 * Get the 2's complement of bv
 * \param bv BitVector, operand
 * \return ret BitVector, a new bitvector, which is the 2's complement of bv
 */
RZ_API BitVector rz_il_bv_complement_2(BitVector bv) {
	// from right side to left, find the 1st 1 bit
	// flip/toggle every bit before it
	BitVector ret = rz_il_bv_dump(bv);

	int i;
	for (i = bv->len - 1; i > 0; --i) {
		if (rz_il_bv_get(bv, i) == true) {
			break;
		}
	}

	if (rz_il_bv_get(bv, i) == true) {
		for (int tmp = 0; tmp < i; ++tmp) {
			rz_il_bv_toggle(ret, tmp);
		}
	}

	return ret;
}

/**
 * Result of (x + y) mod 2^length
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_add(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	bool a, b, carry;
	int len = x->len;
	int pos, i;
	BitVector ret = rz_il_bv_new(len);
	carry = false;

	for (i = 0, pos = len - 1; i < len; ++i, --pos) {
		a = rz_il_bv_get(x, pos);
		b = rz_il_bv_get(y, pos);
		rz_il_bv_set(ret, pos, a ^ b ^ carry);
		carry = ((a & b) | (a & carry)) | (b & carry);
	}

	return ret;
}

/**
 * Result of (x - y) mod 2^length
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_sub(BitVector x, BitVector y) {
	BitVector ret;
	BitVector neg_y;

	neg_y = rz_il_bv_neg(y);
	ret = rz_il_bv_add(x, neg_y);
	rz_il_bv_free(neg_y);
	return ret;
}

/**
 * Result of (x * y) mod 2^length
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_mul(BitVector x, BitVector y) {
	BitVector result, dump, tmp;
	bit cur_bit = false;

	if (x->len != y->len) {
		return NULL;
	}

	result = rz_il_bv_new(x->len);
	dump = rz_il_bv_dump(x);

	int index;

	for (int i = 0; i < y->len; ++i) {
		index = y->len - i - 1;
		cur_bit = rz_il_bv_get(y, index);
		if (cur_bit) {
			tmp = rz_il_bv_add(result, dump);
			rz_il_bv_free(result);
			result = tmp;
		}
		rz_il_bv_lshift(dump, 1);
	}

	rz_il_bv_free(dump);
	return result;
}

// Treat x, y as unsigned
// if x < y return negtive (-1)
// if x == y return 0
// if x > y return positive (+1)
int bv_unsigned_cmp(BitVector x, BitVector y) {
	if (x->len != y->len) {
		printf("[ERROR] : Comparing bitvectors with different length\n");
		return 0;
	}

	int len = x->len;
	bool x_bit, y_bit;
	for (int i = 0; i < len; ++i) {
		x_bit = rz_il_bv_get(x, i);
		y_bit = rz_il_bv_get(y, i);
		if (x_bit ^ y_bit) {
			return x_bit ? 1 : -1;
		}
	}

	// equal
	return 0;
}

/**
 * Result of (x / y) mod 2^length
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_div(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	if (rz_il_bv_is_zero_vector(y)) {
		BitVector ret = rz_il_bv_new(y->len);
		rz_il_bv_set_all(ret, true);
		printf("[DIVIDE ZERO]\n");
		return ret;
	}

	int compare_result = bv_unsigned_cmp(x, y);

	// dividend < divisor
	// remainder = dividend, quotient = 0
	if (compare_result < 0) {
		return rz_il_bv_new(x->len);
	}

	// dividend == divisor
	// remainder = 0, quotient = dividend
	if (compare_result == 0) {
		return rz_il_bv_dump(x);
	}

	// dividend > divisor
	BitVector dividend = rz_il_bv_dump(x);
	BitVector tmp;
	ut32 count = 0;

	while (bv_unsigned_cmp(dividend, y) >= 0) {
		count += 1;
		tmp = rz_il_bv_sub(dividend, y);
		rz_il_bv_free(dividend);
		dividend = tmp;
	}

	BitVector remainder = dividend;
	BitVector quotient = rz_il_bv_new_from_ut32(x->len, count);
	rz_il_bv_free(remainder);
	return quotient;
}

/**
 * Result of (x mod y) mod 2^length
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_mod(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	if (rz_il_bv_is_zero_vector(y)) {
		return rz_il_bv_dump(x);
	}

	int compare_result = bv_unsigned_cmp(x, y);

	// dividend < divisor
	// remainder = dividend, quotient = 0
	if (compare_result < 0) {
		return rz_il_bv_dump(x);
	}

	// dividend == divisor
	// remainder = 0, quotient = dividend
	if (compare_result == 0) {
		return rz_il_bv_new(x->len);
	}

	// dividend > divisor
	BitVector dividend = rz_il_bv_dump(x);
	BitVector tmp;

	while (bv_unsigned_cmp(dividend, y) >= 0) {
		tmp = rz_il_bv_sub(dividend, y);
		rz_il_bv_free(dividend);
		dividend = tmp;
	}

	BitVector remainder = dividend;
	return remainder;
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
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_sdiv(BitVector x, BitVector y) {
	bit mx = rz_il_bv_msb(x);
	bit my = rz_il_bv_msb(y);

	BitVector neg_x, neg_y, tmp, ret;

	if ((!mx) && (!my)) {
		return rz_il_bv_div(x, y);
	}

	if ((mx) && (!my)) {
		neg_x = rz_il_bv_neg(x);
		tmp = rz_il_bv_div(neg_x, y);
		ret = rz_il_bv_neg(tmp);

		rz_il_bv_free(tmp);
		rz_il_bv_free(neg_x);
		return ret;
	}

	if ((!mx) && (my)) {
		neg_y = rz_il_bv_neg(y);
		tmp = rz_il_bv_div(x, neg_y);
		ret = rz_il_bv_neg(tmp);

		rz_il_bv_free(tmp);
		rz_il_bv_free(neg_y);
		return ret;
	}

	if (mx && my) {
		neg_x = rz_il_bv_neg(x);
		neg_y = rz_il_bv_neg(y);

		ret = rz_il_bv_div(neg_x, neg_y);
		rz_il_bv_free(neg_x);
		rz_il_bv_free(neg_y);
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
 * \param x BitVector, Operand
 * \param y BitVector, Operand
 * \return ret BitVector, point to the new bitvector
 */
RZ_API BitVector rz_il_bv_smod(BitVector x, BitVector y) {
	bit mx = rz_il_bv_msb(x);
	bit my = rz_il_bv_msb(y);

	BitVector neg_x, neg_y, tmp, ret;

	if ((!mx) && (!my)) {
		return rz_il_bv_mod(x, y);
	}

	if ((mx) && (!my)) {
		neg_x = rz_il_bv_neg(x);
		tmp = rz_il_bv_mod(neg_x, y);
		ret = rz_il_bv_neg(tmp);

		rz_il_bv_free(tmp);
		rz_il_bv_free(neg_x);
		return ret;
	}

	if ((!mx) && (my)) {
		neg_y = rz_il_bv_neg(y);
		tmp = rz_il_bv_mod(x, neg_y);
		ret = rz_il_bv_neg(tmp);

		rz_il_bv_free(tmp);
		rz_il_bv_free(neg_y);
		return ret;
	}

	if (mx && my) {
		neg_x = rz_il_bv_neg(x);
		neg_y = rz_il_bv_neg(y);

		tmp = rz_il_bv_mod(neg_x, neg_y);
		ret = rz_il_bv_neg(tmp);
		rz_il_bv_free(neg_x);
		rz_il_bv_free(neg_y);
		rz_il_bv_free(tmp);
		return ret;
	}

	return NULL; // something wrong
}

/**
 * Get the most significant bit of bitvector
 * \param bv BitVector, operand
 * \return b bit, bool value of MSB
 */
RZ_API bit rz_il_bv_msb(BitVector bv) {
	return (bv->endian == BIG_ENDIAN ? rz_il_bv_get(bv, 0) : rz_il_bv_get(bv, bv->len - 1));
}

/**
 * Get the least significant bit of bitvector
 * \param bv BitVector, operand
 * \return b bit, bool value of LSB
 */
RZ_API bit rz_il_bv_lsb(BitVector bv) {
	return (bv->endian == BIG_ENDIAN ? rz_il_bv_get(bv, bv->len - 1) : rz_il_bv_get(bv, 0));
}

char *bv_to_string(BitVector bv) {
	char *ret = (char *)malloc(sizeof(char) * bv->len);
	for (int i = 0; i < bv->len; ++i) {
		ret[i] = rz_il_bv_get(bv, i) ? '0' : '1';
	}
	return ret;
}

/**
 * Print bitvector, debug function
 * \param bv BitVector, pointer to bitvector
 */
RZ_API void rz_il_print_bv(BitVector bv) {
	if (!bv) {
		printf("Empty BV\n");
		return;
	}
	for (int i = 0; i < bv->len; ++i) {
		putchar(rz_il_bv_get(bv, i) ? '1' : '0');
	}
	putchar('\n');
}

/**
 * Check if the bitvector is zero
 * \param x BitVector, pointer to bv
 * \return ret bool, return true if bv is a zero bitvector, false if not
 */
RZ_API bool rz_il_bv_is_zero_vector(BitVector x) {
	for (int i = 0; i < x->_elem_len; ++i) {
		if (x->bits[i] != 0) {
			return false;
		}
	}
	return true;
}

/**
 * Check if x <= y (as unsigned value)
 * \param x BitVector, operand
 * \param y BitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_il_bv_ule(BitVector x, BitVector y) {
	// x > y ? return false : return true
	return bv_unsigned_cmp(x, y) > 0 ? false : true;
}

/**
 * Check if x <= y (as signed value)
 * \param x BitVector, operand
 * \param y BitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_il_bv_sle(BitVector x, BitVector y) {
	int x_msb = rz_il_bv_msb(x);
	int y_msb = rz_il_bv_lsb(y);

	if (x_msb && y_msb) {
		return !rz_il_bv_ule(x, y);
	}

	if (!x_msb && !y_msb) {
		return rz_il_bv_ule(x, y);
	}

	// if x_msb set, y_msb unset => x < y
	// if x_msb unset, y_msb set => x > y
	// x != y when reaches here
	return x_msb ? true : false;
}

/**
 * Check if x equals to y
 * \param x BitVector, operand
 * \param y BitVector, operand
 * \return ret int, return 1 if x != y, return 0 if x == y
 */
RZ_API int rz_il_bv_cmp(BitVector x, BitVector y) {
	if (x->len != y->len) {
		return 1;
	}

	for (int i = 0; i < x->_elem_len; ++i) {
		if (x->bits[i] != y->bits[i]) {
			return 1;
		}
	}

	return 0;
}

/**
 * Get the length of bitvector
 * \param bv BitVector
 * \return len int, length of bitvector
 */
RZ_API int rz_il_bv_len(BitVector bv) {
	return bv->len;
}

/**
 * Convert ut32 to `length`-bits bitvector
 * \param length int, length of bitvector
 * \param value ut32, the value to convert
 * \return bv BitVector, pointer to new bitvector
 */
RZ_API BitVector rz_il_bv_new_from_ut32(int length, ut32 value) {
	BitVector bv = rz_il_bv_new(32);
	BitVector ret;
	int type_size = 32;

	ut32 one = 1;
	ut32 mask = one << (type_size - 1);
	for (int i = 0; i < type_size; ++i) {
		rz_il_bv_set(bv, i, (value & mask) ? true : false);
		value <<= 1;
	}

	if (length == type_size) {
		return bv;
	}

	if (length < type_size) {
		// cut
		ret = rz_il_bv_cut_head(bv, type_size - length);
		rz_il_bv_free(bv);
	} else {
		// prepend
		ret = rz_il_bv_prepend_zero(bv, length - type_size);
		rz_il_bv_free(bv);
	}

	return ret;
}

/**
 * Convert ut64 to `length`-bits bitvector
 * \param length int, length of bitvector
 * \param value ut64, the value to convert
 * \return bv BitVector, pointer to new bitvector
 */
RZ_API BitVector rz_il_bv_new_from_ut64(int length, ut64 value) {
	BitVector bv = rz_il_bv_new(length);
	BitVector ret;
	int type_size = 64;

	ut64 one = 1;
	ut64 mask = one << (type_size - 1);
	for (int i = 0; i < type_size; ++i) {
		rz_il_bv_set(bv, i, (value & mask) ? true : false);
		value <<= 1;
	}

	if (length == type_size) {
		return bv;
	}

	if (length < type_size) {
		// cut
		ret = rz_il_bv_cut_head(bv, type_size - length);
		rz_il_bv_free(bv);
	} else {
		// prepend
		ret = rz_il_bv_prepend_zero(bv, length - type_size);
		rz_il_bv_free(bv);
	}

	return ret;
}

ut32 rz_il_bv_hash(BitVector x) {
	ut32 h = 5381;
	ut32 x_len = x->len;

	if (!x->bits || !x->len) {
		return h;
	}
	for (ut32 i = 0; i < x_len; ++i) {
		h = (h + (h << 5)) ^ x->bits[i];
	}
	return h;
}

ut32 rz_il_bv_to_ut32(BitVector x) {
	ut32 ret = 0;
	if (x->len > 32) {
		//		printf("[Warning] Convert to ut32 may loss some bits\n");
	}
	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, x->len - i - 1)) {
			ret += 0x1U << i;
		}
	}

	return ret;
}

/**
 * Convert BitVector to ut64
 * \param x BitVector, pointer to the bitvector
 * \return ret ut64, num value of bitvector
 */
RZ_API ut64 rz_il_bv_to_ut64(BitVector x) {
	ut64 ret = 0;
	ut64 one = 0x1U;
	if (x->len > 64) {
		//		printf("[Warning] Convert to ut32 may loss some bits\n");
	}
	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, x->len - i - 1)) {
			ret += one << i;
		}
	}

	return ret;
}
