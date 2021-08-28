// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/bitvector.h>

/**
 * New a `length`-bits bitvector
 * \param length int, the length of bitvector
 * \return bv RzILBitVector, pointer to the new bitvector instance
 */
RZ_API RzILBitVector rz_il_bv_new0(ut32 length) {
	rz_return_val_if_fail(length, NULL);
	RzILBitVector ret = (RzILBitVector)malloc(sizeof(struct bitvector_t));
	if (ret == NULL) {
		return NULL;
	}

	// how much ut8 do we need to represent `length` bits ?
	int real_elem_cnt = NELEM(length, BV_ELEM_SIZE);

	ret->bits = (ut8 *)calloc(real_elem_cnt, sizeof(ut8));
	ret->len = length;
	ret->_elem_len = real_elem_cnt;

	if (!ret->bits) {
		free(ret);
		printf("Malloc Failed\n");
		return NULL;
	}

	return ret;
}

/**
 * Free a bitvector
 * \param bv RzILBitVector, pointer to the bitvector you want to free
 */
RZ_API void rz_il_bv_free(RzILBitVector bv) {
	if (!bv) {
		return;
	}
	if (bv->bits) {
		free(bv->bits);
	}
	free(bv);
}

/**
 * Clone a bitvector
 * \param bv RzILBitVector, pointer to the source bitvector
 * \return dup RzILBitVector, pointer to a new bitvector, which is a copy of source
 */
RZ_API RzILBitVector rz_il_bv_dup(RzILBitVector bv) {
	rz_return_val_if_fail(bv && bv->bits, NULL);

	RzILBitVector new_bv = rz_il_bv_new0(bv->len);
	if (!new_bv || !(new_bv->bits)) {
		rz_il_bv_free(new_bv);
		return NULL;
	}

	memcpy(new_bv->bits, bv->bits, bv->_elem_len);

	return new_bv;
}

/**
 * Copy from source bitvector to destination bitvector
 * the maximum copied size depends on MIN(src_len, dst_len)
 * \param src RzILBitVector, the source bitvector
 * \param dst RzILBitVector, the destination bitvector
 * \return Actual size of copy
 */
RZ_API int rz_il_bv_copy(RzILBitVector src, RzILBitVector dst) {
	if (!dst || !(dst->bits) || !src || !(src->bits)) {
		return 0;
	}

	if (dst->len != src->len) {
		return 0;
	}

	memcpy(dst, src, dst->_elem_len);
	return dst->_elem_len;
}

/**
 * Copy n bits from start position of source to start position of dest
 * \param src RzILBitVector, data source
 * \param src_start_pos int, start position in source bitvector of copy
 * \param dst RzILBitVector, destination of copy
 * \param dst_start_pos int, start position in destination bitvector
 * \param nbit int, control the size of copy (in bits)
 * \return copied_size int, Actual copied size
 */
RZ_API int rz_il_bv_copy_nbits(
	RzILBitVector src, ut32 src_start_pos,
	RzILBitVector dst, ut32 dst_start_pos,
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
		bool c = rz_il_bv_get(src, src_start_pos + i);
		rz_il_bv_set(dst, dst_start_pos + i, c);
	}

	return nbit;
}

/**
 * Return a new bitvector prepended with bv with n zero bits
 * \param bv RzILBitVector, pointer to bitvector instance
 * \param delta_len int, the number of zero bits
 * \return ret RzILBitVector, pointer to the new bitvector instance
 */
RZ_API RzILBitVector rz_il_bv_prepend_zero(RzILBitVector bv, ut32 delta_len) {
	if (!bv || !bv->bits) {
		return NULL;
	}

	ut32 new_len = bv->len + delta_len;
	RzILBitVector ret = rz_il_bv_new0(new_len);
	if (ret == NULL) {
		return NULL;
	}

	for (int i = 0; i < bv->len; ++i) {
		rz_il_bv_set(ret, i, rz_il_bv_get(bv, i));
	}

	return ret;
}

/**
 * Return a new bitvector appended with n zero bits
 * \param bv RzILBitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret RzILBitVector, pointert to the new btivector
 */
RZ_API RzILBitVector rz_il_bv_append_zero(RzILBitVector bv, ut32 delta_len) {
	if (!bv || !bv->bits) {
		return NULL;
	}

	ut32 new_len = bv->len + delta_len;
	RzILBitVector ret = rz_il_bv_new0(new_len);
	if (ret == NULL) {
		return NULL;
	}

	ut32 pos = delta_len;
	for (int i = 0; i < bv->len; ++i, ++pos) {
		rz_il_bv_set(ret, pos, rz_il_bv_get(bv, i));
	}

	return ret;
}

/**
 * Return a new bitvector, cut n zero bits from head
 * \param bv RzILBitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret RzILBitVector, pointert to the new btivector
 */
RZ_API RzILBitVector rz_il_bv_cut_head(RzILBitVector bv, ut32 delta_len) {
	ut32 new_len = bv->len - delta_len;
	RzILBitVector ret = rz_il_bv_new0(new_len);
	if (!ret) {
		return NULL;
	}

	for (int pos = 0; pos < new_len; ++pos) {
		rz_il_bv_set(ret, pos, rz_il_bv_get(bv, pos));
	}

	return ret;
}

/**
 * Return a new bitvector, cut n zero bits from tail
 * \param bv RzILBitVector, pointer to bitvector
 * \param delta_len, the number of zero bits
 * \return ret RzILBitVector, pointert to the new btivector
 */
RZ_API RzILBitVector rz_il_bv_cut_tail(RzILBitVector bv, ut32 delta_len) {
	ut32 new_len = bv->len - delta_len;
	RzILBitVector ret = rz_il_bv_new0(new_len);
	if (!ret) {
		return NULL;
	}

	ut32 pos, i;
	for (pos = 0, i = delta_len; pos < new_len; ++i, ++pos) {
		rz_il_bv_set(ret, pos, rz_il_bv_get(bv, i));
	}

	return ret;
}

/**
 * Concat bv1 and bv2 to get new bitvector
 * \param bv1 RzILBitVector
 * \param bv2 RzILBitVector
 * \return ret RzILBitVector, the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_concat(RzILBitVector bv1, RzILBitVector bv2) {
	if (!bv1 || !bv2 || !bv1->bits || !bv2->bits) {
		return NULL;
	}

	ut32 new_len = bv1->len + bv2->len;
	RzILBitVector ret = rz_il_bv_new0(new_len);

	// copy n bits from bv1
	rz_il_bv_copy_nbits(bv2, 0, ret, 0, bv2->len);
	rz_il_bv_copy_nbits(bv1, 0, ret, bv2->len, bv1->len);

	return ret;
}

/**
 * Set a bit at position to true or false
 * \param bv RzILBitVector, pointer to bv
 * \param pos int, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_il_bv_set(RzILBitVector bv, ut32 pos, bool b) {
	if (!bv || !bv->bits) {
		RZ_LOG_ERROR("FAIL TO SET BIT : Broken bitvector\n");
		return false;
	}
	pos = bv->len - pos - 1;
	if (b) {
		(bv->bits)[pos / BV_ELEM_SIZE] |= (1u << (pos % BV_ELEM_SIZE));
	} else {
		(bv->bits)[pos / BV_ELEM_SIZE] &= ~(1u << (pos % BV_ELEM_SIZE));
	}

	return b;
}

/**
 * Set all bits to true or false
 * \param bv RzILBitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_il_bv_set_all(RzILBitVector bv, bool b) {
	if (!bv || !bv->bits) {
		RZ_LOG_ERROR("FAIL TO SET BIT : Broken bitvector\n");
		return false;
	}
	if (b) {
		for (int i = 0; i < bv->_elem_len; ++i) {
			bv->bits[i] = 0xff;
		}
	} else {
		for (int i = 0; i < bv->_elem_len; ++i) {
			bv->bits[i] = 0;
		}
	}

	return b;
}

/**
 * Invert a bit at position
 * \param bv RzILBitVector, pointer to bv
 * \param pos int, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_il_bv_toggle(RzILBitVector bv, ut32 pos) {
	if (!bv || !bv->bits) {
		RZ_LOG_ERROR("FAIL TO SET BIT : Broken bitvector\n");
		return false;
	}
	bool cur_bit = rz_il_bv_get(bv, pos);
	bool new_bit = !cur_bit;
	rz_il_bv_set(bv, pos, new_bit);
	return new_bit;
}

/**
 * Invert all bits
 * \param bv RzILBitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_il_bv_toggle_all(RzILBitVector bv) {
	if (!bv || !bv->bits) {
		RZ_LOG_ERROR("FAIL TO SET BIT : Broken bitvector\n");
		return false;
	}
	for (int i = 0; i < bv->_elem_len; ++i) {
		(bv->bits)[i] = ~((bv->bits)[i]);
	}
	return true;
}

/**
 * Get bit at position from bitvector
 * \param bv RzILBitVector, pointer to bv
 * \param pos int, position
 * \return ret bit, bool value of bit
 */
RZ_API bool rz_il_bv_get(RzILBitVector bv, ut32 pos) {
	if (!bv || !bv->bits) {
		RZ_LOG_ERROR("FAIL TO GET BIT : Broken bitvector\n");
		return false;
	}
	pos = bv->len - pos - 1;
	return ((bv->bits)[pos / BV_ELEM_SIZE] & (1u << (pos % BV_ELEM_SIZE))) ? true : false;
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv RzILBitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_lshift(RzILBitVector bv, ut32 size) {
	return rz_il_bv_lshift_fill(bv, size, false);
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv RzILBitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_rshift(RzILBitVector bv, ut32 size) {
	return rz_il_bv_rshift_fill(bv, size, false);
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill the bitvector with `fill_bit`
 * \param bv RzILBitVector, pointert to bv
 * \param size int, shift bits
 * \param fill_bit bool, bit used in filling
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_lshift_fill(RzILBitVector bv, ut32 size, bool fill_bit) {
	// left shift
	if (size == 0) {
		return false;
	}

	if (size >= bv->len) {
		rz_il_bv_set_all(bv, fill_bit);
		return true;
	}

	RzILBitVector tmp = rz_il_bv_new0(bv->len);
	rz_il_bv_set_all(tmp, fill_bit);

	int copied_size = rz_il_bv_copy_nbits(bv, 0, tmp, size, bv->len - size);
	if (copied_size == 0) {
		rz_il_bv_free(tmp);
		return false;
	}

	memcpy(bv->bits, tmp->bits, bv->_elem_len);
	rz_il_bv_free(tmp);

	return true;
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill the bitvector with `fill_bit`
 * \param bv RzILBitVector, pointert to bv
 * \param size int, shift bits
 * \param fill_bit bool, bit used in filling
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_rshift_fill(RzILBitVector bv, ut32 size, bool fill_bit) {
	// left shift
	if (size == 0) {
		return false;
	}

	if (size >= bv->len) {
		rz_il_bv_set_all(bv, fill_bit);
		return true;
	}

	RzILBitVector tmp = rz_il_bv_new0(bv->len);
	rz_il_bv_set_all(tmp, fill_bit);

	int copied_size = rz_il_bv_copy_nbits(bv, size, tmp, 0, tmp->len - size);
	if (copied_size == 0) {
		rz_il_bv_free(tmp);
		return false;
	}

	memcpy(bv->bits, tmp->bits, bv->_elem_len);
	rz_il_bv_free(tmp);

	return true;
}

/**
 * Result of x AND y (`and` operation to every bits)
 * x and y should have the same length
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the result of AND
 */
RZ_API RzILBitVector rz_il_bv_and(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	RzILBitVector ret = rz_il_bv_new0(x->len);
	for (int i = 0; i < ret->_elem_len; ++i) {
		ret->bits[i] = x->bits[i] & y->bits[i];
	}
	return ret;
}

/**
 * Result of x OR y (`or` operation to every bits)
 * x and y should have the same length
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the result of OR
 */
RZ_API RzILBitVector rz_il_bv_or(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	RzILBitVector ret = rz_il_bv_new0(x->len);
	for (int i = 0; i < ret->_elem_len; ++i) {
		ret->bits[i] = x->bits[i] | y->bits[i];
	}
	return ret;
}

/**
 * Result of x XOR y (`xor` operation to every bits)
 * x and y should have the same length
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the result of XOR
 */
RZ_API RzILBitVector rz_il_bv_xor(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	RzILBitVector ret = rz_il_bv_new0(x->len);
	for (int i = 0; i < ret->_elem_len; ++i) {
		ret->bits[i] = x->bits[i] ^ y->bits[i];
	}
	return ret;
}

/**
 * Get the 1's complement of bv
 * \param bv RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the 1's complement of bv
 */
RZ_API RzILBitVector rz_il_bv_complement_1(RzILBitVector bv) {
	RzILBitVector ret = rz_il_bv_new0(bv->len);
	ut32 real_elem_cnt = bv->_elem_len;
	for (int i = 0; i < real_elem_cnt; ++i) {
		ret->bits[i] = ~bv->bits[i];
	}
	return ret;
}

/**
 * Get the 2's complement of bv
 * \param bv RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the 2's complement of bv
 */
RZ_API RzILBitVector rz_il_bv_complement_2(RzILBitVector bv) {
	// from right side to left, find the 1st 1 bit
	// flip/toggle every bit before it
	RzILBitVector ret = rz_il_bv_dup(bv);

	ut32 i;
	for (i = 0; i < bv->len; ++i) {
		if (rz_il_bv_get(bv, i) == true) {
			break;
		}
	}

	// assert bv[i] == true now
	i += 1;
	for (i = i; i < bv->len; ++i) {
		rz_il_bv_toggle(ret, i);
	}

	return ret;
}

/**
 * Result of (x + y) mod 2^length
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_add(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	bool a, b, carry;
	ut32 len = x->len;
	ut32 pos;
	RzILBitVector ret = rz_il_bv_new0(len);
	carry = false;

	for (pos = 0; pos < len; ++pos) {
		a = rz_il_bv_get(x, pos);
		b = rz_il_bv_get(y, pos);
		rz_il_bv_set(ret, pos, a ^ b ^ carry);
		carry = ((a & b) | (a & carry)) | (b & carry);
	}

	return ret;
}

/**
 * Result of (x - y) mod 2^length
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_sub(RzILBitVector x, RzILBitVector y) {
	RzILBitVector ret;
	RzILBitVector neg_y;

	neg_y = rz_il_bv_neg(y);
	ret = rz_il_bv_add(x, neg_y);
	rz_il_bv_free(neg_y);
	return ret;
}

/**
 * Result of (x * y) mod 2^length
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_mul(RzILBitVector x, RzILBitVector y) {
	RzILBitVector result, dump, tmp;
	bool cur_bit = false;

	if (x->len != y->len) {
		return NULL;
	}

	result = rz_il_bv_new0(x->len);
	dump = rz_il_bv_dup(x);

	for (int i = 0; i < y->len; ++i) {
		cur_bit = rz_il_bv_get(y, i);
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
int bv_unsigned_cmp(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		printf("[ERROR] : Comparing bitvectors with different length\n");
		return 0;
	}

	ut32 len = x->len;
	int pos;
	bool x_bit, y_bit;
	for (int i = 0; i < len; ++i) {
		pos = len - 1 - i;
		x_bit = rz_il_bv_get(x, pos);
		y_bit = rz_il_bv_get(y, pos);
		if (x_bit ^ y_bit) {
			return x_bit ? 1 : -1;
		}
	}

	// equal
	return 0;
}

/**
 * Result of (x / y) mod 2^length
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_div(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	if (rz_il_bv_is_zero_vector(y)) {
		RzILBitVector ret = rz_il_bv_new0(y->len);
		rz_il_bv_set_all(ret, true);
		printf("[DIVIDE ZERO]\n");
		return ret;
	}

	int compare_result = bv_unsigned_cmp(x, y);

	// dividend < divisor
	// remainder = dividend, quotient = 0
	if (compare_result < 0) {
		return rz_il_bv_new0(x->len);
	}

	// dividend == divisor
	// remainder = 0, quotient = dividend
	if (compare_result == 0) {
		return rz_il_bv_dup(x);
	}

	// dividend > divisor
	RzILBitVector dividend = rz_il_bv_dup(x);
	RzILBitVector tmp;
	ut32 count = 0;

	while (bv_unsigned_cmp(dividend, y) >= 0) {
		count += 1;
		tmp = rz_il_bv_sub(dividend, y);
		rz_il_bv_free(dividend);
		dividend = tmp;
	}

	RzILBitVector remainder = dividend;
	RzILBitVector quotient = rz_il_bv_new_from_ut32(x->len, count);
	rz_il_bv_free(remainder);
	return quotient;
}

/**
 * Result of (x mod y) mod 2^length
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_mod(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return NULL;
	}

	if (rz_il_bv_is_zero_vector(y)) {
		return rz_il_bv_dup(x);
	}

	int compare_result = bv_unsigned_cmp(x, y);

	// dividend < divisor
	// remainder = dividend, quotient = 0
	if (compare_result < 0) {
		return rz_il_bv_dup(x);
	}

	// dividend == divisor
	// remainder = 0, quotient = dividend
	if (compare_result == 0) {
		return rz_il_bv_new0(x->len);
	}

	// dividend > divisor
	RzILBitVector dividend = rz_il_bv_dup(x);
	RzILBitVector tmp;

	while (bv_unsigned_cmp(dividend, y) >= 0) {
		tmp = rz_il_bv_sub(dividend, y);
		rz_il_bv_free(dividend);
		dividend = tmp;
	}

	RzILBitVector remainder = dividend;
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
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_sdiv(RzILBitVector x, RzILBitVector y) {
	bool mx = rz_il_bv_msb(x);
	bool my = rz_il_bv_msb(y);

	RzILBitVector neg_x, neg_y, tmp, ret;

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
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RzILBitVector rz_il_bv_smod(RzILBitVector x, RzILBitVector y) {
	bool mx = rz_il_bv_msb(x);
	bool my = rz_il_bv_msb(y);

	RzILBitVector neg_x, neg_y, tmp, ret;

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
 * \param bv RzILBitVector, operand
 * \return b bit, bool value of MSB
 */
RZ_API bool rz_il_bv_msb(RzILBitVector bv) {
	return rz_il_bv_get(bv, bv->len - 1);
}

/**
 * Get the least significant bit of bitvector
 * \param bv RzILBitVector, operand
 * \return b bit, bool value of LSB
 */
RZ_API bool rz_il_bv_lsb(RzILBitVector bv) {
	return rz_il_bv_get(bv, 0);
}

char *bv_to_string(RzILBitVector bv) {
	char *ret = (char *)malloc(sizeof(char) * bv->len);
	for (int i = 0; i < bv->len; ++i) {
		ret[i] = rz_il_bv_get(bv, i) ? '0' : '1';
	}
	return ret;
}

/**
 * Print bitvector, debug function
 * \param bv RzILBitVector, pointer to bitvector
 */
RZ_API void rz_il_print_bv(RzILBitVector bv) {
	if (!bv) {
		printf("Empty BV\n");
		return;
	}
	for (int i = bv->len - 1; i >= 0; --i) {
		putchar(rz_il_bv_get(bv, i) ? '1' : '0');
	}
	putchar('\n');
}

/**
 * Check if the bitvector is zero
 * \param x RzILBitVector, pointer to bv
 * \return ret bool, return true if bv is a zero bitvector, false if not
 */
RZ_API bool rz_il_bv_is_zero_vector(RzILBitVector x) {
	for (int i = 0; i < x->_elem_len; ++i) {
		if (x->bits[i] != 0) {
			return false;
		}
	}
	return true;
}

/**
 * Check if x <= y (as unsigned value)
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_il_bv_ule(RzILBitVector x, RzILBitVector y) {
	// x > y ? return false : return true
	return bv_unsigned_cmp(x, y) > 0 ? false : true;
}

/**
 * Check if x <= y (as signed value)
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_il_bv_sle(RzILBitVector x, RzILBitVector y) {
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
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret int, return 1 if x != y, return 0 if x == y
 */
RZ_API int rz_il_bv_cmp(RzILBitVector x, RzILBitVector y) {
	if (x->len != y->len) {
		return 1;
	}

	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, i) != rz_il_bv_get(y, i)) {
			return 1;
		}
	}

	return 0;
}

/**
 * Get the length of bitvector
 * \param bv RzILBitVector
 * \return len int, length of bitvector
 */
RZ_API ut32 rz_il_bv_len(RzILBitVector bv) {
	return bv->len;
}

/**
 * Convert ut32 to `length`-bits bitvector
 * \param length int, length of bitvector
 * \param value ut32, the value to convert
 * \return bv RzILBitVector, pointer to new bitvector
 */
RZ_API RzILBitVector rz_il_bv_new_from_ut32(ut32 length, ut32 value) {
	RzILBitVector bv = rz_il_bv_new0(32);
	RzILBitVector ret;
	int type_size = 32;

	ut32 mask = 0x1;
	for (int i = 0; i < type_size; ++i) {
		rz_il_bv_set(bv, i, (value & mask) ? true : false);
		value >>= 1;
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
 * \return bv RzILBitVector, pointer to new bitvector
 */
RZ_API RzILBitVector rz_il_bv_new_from_ut64(ut32 length, ut64 value) {
	RzILBitVector bv = rz_il_bv_new0(length);
	RzILBitVector ret;
	int type_size = 64;

	ut64 mask = 0x1;
	for (int i = 0; i < type_size; ++i) {
		rz_il_bv_set(bv, i, (value & mask) ? true : false);
		value >>= 1;
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

ut32 rz_il_bv_hash(RzILBitVector x) {
	ut32 h = 5381;
	ut32 x_len = x->len;

	if (!x->bits || !x->len) {
		return h;
	}
	for (ut32 i = 0; i < x_len; ++i) {
		h = (h + (h << 5)) ^ rz_il_bv_get(x, i);
	}
	return h;
}

RZ_API ut8 rz_il_bv_to_ut8(RzILBitVector x) {
	ut8 ret = 0;
	if (x->len > 8) {
		//		printf("[Warning] Convert to ut32 may loss some bits\n");
	}
	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, i)) {
			ret += 0x1U << i;
		}
	}

	return ret;
}

RZ_API ut16 rz_il_bv_to_ut16(RzILBitVector x) {
	ut16 ret = 0;
	if (x->len > 16) {
		//		printf("[Warning] Convert to ut32 may loss some bits\n");
	}
	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, i)) {
			ret += 0x1U << i;
		}
	}

	return ret;
}

RZ_API ut32 rz_il_bv_to_ut32(RzILBitVector x) {
	ut32 ret = 0;
	if (x->len > 32) {
		//		printf("[Warning] Convert to ut32 may loss some bits\n");
	}
	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, i)) {
			ret += 0x1U << i;
		}
	}

	return ret;
}

/**
 * Convert RzILBitVector to ut64
 * \param x RzILBitVector, pointer to the bitvector
 * \return ret ut64, num value of bitvector
 */
RZ_API ut64 rz_il_bv_to_ut64(RzILBitVector x) {
	ut64 ret = 0;
	if (x->len > 64) {
		//		printf("[Warning] Convert to ut32 may loss some bits\n");
	}
	for (int i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, i)) {
			ret += 0x1U << i;
		}
	}

	return ret;
}
