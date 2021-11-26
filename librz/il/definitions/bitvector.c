// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/bitvector.h>

/**
 * New a `length`-bits bitvector
 * \param length int, the length of bitvector
 * \return bv RzILBitVector, pointer to the new bitvector instance
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new(ut32 length) {
	rz_return_val_if_fail(length, NULL);
	RzILBitVector *ret = RZ_NEW0(RzILBitVector);
	if (ret == NULL) {
		return NULL;
	}

	if (length > 64) {
		// how much ut8 do we need to represent `length` bits ?
		size_t real_elem_cnt = NELEM(length, BV_ELEM_SIZE);
		ret->bits.large_a = RZ_NEWS0(ut8, real_elem_cnt);
		if (!ret->bits.large_a) {
			free(ret);
			return NULL;
		}
		ret->_elem_len = real_elem_cnt;
	}
	ret->len = length;

	return ret;
}

/**
 * Free a bitvector
 * \param bv RzILBitVector, pointer to the bitvector you want to free
 */
RZ_API void rz_il_bv_free(RZ_NULLABLE RzILBitVector *bv) {
	if (!bv) {
		return;
	}
	if (bv->len > 64) {
		free(bv->bits.large_a);
	}
	free(bv);
}

/**
 * Return bitvector string
 * \param bv RzILBitVector, pointer to bitvector
 * \return str char*, bitvector string
 */
RZ_API RZ_OWN char *rz_il_bv_as_string(RZ_NONNULL RzILBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	char *str = (char *)malloc(bv->len + 1);
	if (!str) {
		return NULL;
	}

	for (ut32 i = bv->len - 1, j = 0; i > 0; --i, j++) {
		str[j] = rz_il_bv_get(bv, i) ? '1' : '0';
	}
	str[bv->len - 1] = rz_il_bv_get(bv, 0) ? '1' : '0';
	str[bv->len] = '\0';

	return str;
}

/**
 * Return bitvector string in hexadecimal format
 * \param bv RzILBitVector, pointer to bitvector
 * \return str char*, bitvector string in hexadecimal format
 */
RZ_API RZ_OWN char *rz_il_bv_as_hex_string(RZ_NONNULL RzILBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	if (bv->len <= 64) {
		char format[32] = { 0 };
		rz_strf(format, "0x%%0%d" PFMT64x, bv->len / 4);
		return rz_str_newf(format, bv->bits.small_u);
	}

	const char *hex = "0123456789abcdef";
	size_t str_len = (bv->_elem_len << 1) + 3; // 0x + \0
	char *str = (char *)malloc(str_len);
	if (!str) {
		return NULL;
	}

	str[0] = '0';
	str[1] = 'x';
	for (ut32 i = 0, j = 2; i < bv->_elem_len; i++, j += 2) {
		ut8 b8 = bv->bits.large_a[i];
		// optimization for reversing 8 bits which uses 32 bits
		// https://graphics.stanford.edu/~seander/bithacks.html#BitReverseObvious
		b8 = ((b8 * 0x0802LU & 0x22110LU) | (b8 * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
		str[j + 0] = hex[b8 >> 4];
		str[j + 1] = hex[b8 & 15];
	}
	str[str_len - 1] = '\0';

	return str;
}

/**
 * Clone a bitvector
 * \param bv RzILBitVector, pointer to the source bitvector
 * \return dup RzILBitVector, pointer to a new bitvector, which is a copy of source
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_dup(const RZ_NONNULL RzILBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	RzILBitVector *new_bv = rz_il_bv_new(bv->len);
	if (!new_bv || !rz_il_bv_copy(bv, new_bv)) {
		rz_il_bv_free(new_bv);
		return NULL;
	}

	return new_bv;
}

/**
 * Copy from source bitvector to destination bitvector
 * the maximum copied size depends on MIN(src_len, dst_len)
 * \param src RzILBitVector, the source bitvector
 * \param dst RzILBitVector, the destination bitvector
 * \return Actual size of copy
 */
RZ_API ut32 rz_il_bv_copy(RZ_NONNULL const RzILBitVector *src, RZ_NONNULL RzILBitVector *dst) {
	rz_return_val_if_fail(src && dst, 0);

	if (dst->len != src->len) {
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
 * Copy n bits from start position of source to start position of dest
 * \param src RzILBitVector, data source
 * \param src_start_pos ut32, start position in source bitvector of copy
 * \param dst RzILBitVector, destination of copy
 * \param dst_start_pos ut32, start position in destination bitvector
 * \param nbit ut32, control the size of copy (in bits)
 * \return copied_size ut32, Actual copied size
 */
RZ_API ut32 rz_il_bv_copy_nbits(RZ_NONNULL const RzILBitVector *src, ut32 src_start_pos, RZ_NONNULL RzILBitVector *dst, ut32 dst_start_pos, ut32 nbit) {
	rz_return_val_if_fail(src && dst, 0);

	ut32 max_nbit = RZ_MIN((src->len - src_start_pos),
		(dst->len - dst_start_pos));

	// prevent overflow
	if (max_nbit < nbit) {
		return 0;
	}

	// normal case here
	for (ut32 i = 0; i < max_nbit; ++i) {
		bool c = rz_il_bv_get(src, src_start_pos + i);
		rz_il_bv_set(dst, dst_start_pos + i, c);
	}

	return nbit;
}

/**
 * Return a new bitvector prepended with bv with n zero bits
 * \param bv RzILBitVector, pointer to bitvector instance
 * \param delta_len ut32, the number of zero bits
 * \return ret RzILBitVector, pointer to the new bitvector instance
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_prepend_zero(RZ_NONNULL RzILBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len + delta_len;
	RzILBitVector *ret = rz_il_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	for (ut32 i = 0; i < bv->len; ++i) {
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
RZ_API RZ_OWN RzILBitVector *rz_il_bv_append_zero(RZ_NONNULL RzILBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len + delta_len;
	RzILBitVector *ret = rz_il_bv_new(new_len);
	if (ret == NULL) {
		return NULL;
	}

	ut32 pos = delta_len;
	for (ut32 i = 0; i < bv->len; ++i, ++pos) {
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
RZ_API RZ_OWN RzILBitVector *rz_il_bv_cut_head(RZ_NONNULL RzILBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len - delta_len;
	RzILBitVector *ret = rz_il_bv_new(new_len);
	if (!ret) {
		return NULL;
	}

	for (ut32 pos = 0; pos < new_len; ++pos) {
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
RZ_API RZ_OWN RzILBitVector *rz_il_bv_cut_tail(RZ_NONNULL RzILBitVector *bv, ut32 delta_len) {
	rz_return_val_if_fail(bv, NULL);

	ut32 new_len = bv->len - delta_len;
	RzILBitVector *ret = rz_il_bv_new(new_len);
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
 * Append bv2 to bv1 to get new bitvector
 * \param bv1 RzILBitVector
 * \param bv2 RzILBitVector
 * \return ret RzILBitVector, the new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_append(RZ_NONNULL RzILBitVector *bv1, RZ_NONNULL RzILBitVector *bv2) {
	rz_return_val_if_fail(bv1 && bv2, NULL);

	ut32 new_len = bv1->len + bv2->len;
	RzILBitVector *ret = rz_il_bv_new(new_len);

	// copy n bits from bv1
	rz_il_bv_copy_nbits(bv2, 0, ret, 0, bv2->len);
	rz_il_bv_copy_nbits(bv1, 0, ret, bv2->len, bv1->len);

	return ret;
}

/**
 * Set a bit at position to true or false
 * \param bv RzILBitVector, pointer to bv
 * \param pos ut32, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_il_bv_set(RZ_NONNULL RzILBitVector *bv, ut32 pos, bool b) {
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

	pos = bv->len - pos - 1;
	if (b) {
		bv->bits.large_a[pos / BV_ELEM_SIZE] |= (1u << (pos % BV_ELEM_SIZE));
	} else {
		bv->bits.large_a[pos / BV_ELEM_SIZE] &= ~(1u << (pos % BV_ELEM_SIZE));
	}
	return b;
}

/**
 * Set all bits to true or false
 * \param bv RzILBitVector, pointer to bv
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at every positions after this operation
 */
RZ_API bool rz_il_bv_set_all(RZ_NONNULL RzILBitVector *bv, bool b) {
	rz_return_val_if_fail(bv, false);

	if (bv->len <= 64) {
		bv->bits.small_u = b ? UT64_MAX : 0;
		return b;
	}

	rz_return_val_if_fail(bv->bits.large_a, false);
	if (b) {
		for (ut32 i = 0; i < bv->_elem_len; ++i) {
			bv->bits.large_a[i] = 0xff;
		}
	} else {
		for (ut32 i = 0; i < bv->_elem_len; ++i) {
			bv->bits.large_a[i] = 0;
		}
	}

	return b;
}

/**
 * Invert a bit at position
 * \param bv RzILBitVector, pointer to bv
 * \param pos ut32, position
 * \param b bit, true or false (set or unset)
 * \return ret bool, bool value at `pos` after this operation
 */
RZ_API bool rz_il_bv_toggle(RZ_NONNULL RzILBitVector *bv, ut32 pos) {
	rz_return_val_if_fail(bv, false);
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
RZ_API bool rz_il_bv_toggle_all(RZ_NONNULL RzILBitVector *bv) {
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
 * \param bv RzILBitVector, pointer to bv
 * \param pos int, position
 * \return ret bit, bool value of bit
 */
RZ_API bool rz_il_bv_get(RZ_NONNULL const RzILBitVector *bv, ut32 pos) {
	rz_return_val_if_fail(bv && pos < bv->len, false);
	if (bv->len <= 64) {
		return (bv->bits.small_u >> pos) & 1;
	}

	rz_return_val_if_fail(bv->bits.large_a, false);
	pos = bv->len - pos - 1;
	return ((bv->bits.large_a)[pos / BV_ELEM_SIZE] & (1u << (pos % BV_ELEM_SIZE)));
}

/**
 * Left shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv RzILBitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_lshift(RZ_NONNULL RzILBitVector *bv, ut32 size) {
	return rz_il_bv_lshift_fill(bv, size, false);
}

/**
 * Right shift bitvector (WARN : This operation will change the bitvector in argument)
 * Fill with zero bits when shift
 * \param bv RzILBitVector, pointert to bv
 * \param size int, shift bits
 * \return flag bool, success or not
 */
RZ_API bool rz_il_bv_rshift(RZ_NONNULL RzILBitVector *bv, ut32 size) {
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
RZ_API bool rz_il_bv_lshift_fill(RZ_NONNULL RzILBitVector *bv, ut32 size, bool fill_bit) {
	rz_return_val_if_fail(bv, false);

	// left shift
	if (size == 0) {
		return false;
	}

	if (size >= bv->len) {
		rz_il_bv_set_all(bv, fill_bit);
		return true;
	}

	RzILBitVector *tmp = rz_il_bv_new(bv->len);
	rz_il_bv_set_all(tmp, fill_bit);

	int copied_size = rz_il_bv_copy_nbits(bv, 0, tmp, size, bv->len - size);
	if (copied_size == 0) {
		rz_il_bv_free(tmp);
		return false;
	}

	rz_il_bv_copy(tmp, bv);
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
RZ_API bool rz_il_bv_rshift_fill(RZ_NONNULL RzILBitVector *bv, ut32 size, bool fill_bit) {
	rz_return_val_if_fail(bv, false);

	// left shift
	if (size == 0) {
		return false;
	}

	if (size >= bv->len) {
		rz_il_bv_set_all(bv, fill_bit);
		return true;
	}

	RzILBitVector *tmp = rz_il_bv_new(bv->len);
	rz_il_bv_set_all(tmp, fill_bit);

	int copied_size = rz_il_bv_copy_nbits(bv, size, tmp, 0, tmp->len - size);
	if (copied_size == 0) {
		rz_il_bv_free(tmp);
		return false;
	}

	rz_il_bv_copy(tmp, bv);
	rz_il_bv_free(tmp);

	return true;
}

/**
 * Result of x AND y (`and` operation to every bits)
 * Both operands must have the same length.
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the result of AND
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_and(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y && x->bits.large_a && y->bits.large_a, NULL);
	if (x->len != y->len) {
		return NULL;
	}

	RzILBitVector *ret = rz_il_bv_new(x->len);
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
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the result of OR
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_or(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y && x->bits.large_a && y->bits.large_a, NULL);
	if (x->len != y->len) {
		return NULL;
	}

	RzILBitVector *ret = rz_il_bv_new(x->len);
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
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the result of XOR
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_xor(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		return NULL;
	}

	RzILBitVector *ret = rz_il_bv_new(x->len);
	if (!ret) {
		return NULL;
	} else if (x->len <= 64) {
		ret->bits.small_u = x->bits.small_u ^ y->bits.small_u;
		return ret;
	}

	rz_return_val_if_fail(x->bits.large_a && y->bits.large_a, NULL);
	for (ut32 i = 0; i < ret->_elem_len; ++i) {
		ret->bits.large_a[i] = x->bits.large_a[i] ^ y->bits.large_a[i];
	}
	return ret;
}

/**
 * Get the 1's complement of bv
 * \param bv RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the 1's complement of bv
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_complement_1(RZ_NONNULL RzILBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	RzILBitVector *ret = rz_il_bv_new(bv->len);
	if (!ret) {
		return NULL;
	} else if (ret->len <= 64) {
		ret->bits.small_u = ~bv->bits.small_u;
		return ret;
	}

	rz_return_val_if_fail(ret->bits.large_a && bv->bits.large_a, NULL);
	for (ut32 i = 0; i < bv->_elem_len; ++i) {
		ret->bits.large_a[i] = ~bv->bits.large_a[i];
	}
	return ret;
}

/**
 * Get the 2's complement of bv
 * \param bv RzILBitVector, operand
 * \return ret RzILBitVector, a new bitvector, which is the 2's complement of bv
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_complement_2(RZ_NONNULL RzILBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	// from right side to left, find the 1st 1 bit
	// flip/toggle every bit before it
	RzILBitVector *ret = rz_il_bv_dup(bv);

	ut32 i;
	for (i = 0; i < bv->len; ++i) {
		if (rz_il_bv_get(bv, i) == true) {
			break;
		}
	}

	// assert bv[i] == true now
	i += 1;
	for (; i < bv->len; ++i) {
		rz_il_bv_toggle(ret, i);
	}

	return ret;
}

/**
 * Result of (x + y) mod 2^length
 * Both operands must have the same length.
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \param carry bool*, bool pointer to where to save the carry value.
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_add(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y, RZ_NULLABLE bool *carry) {
	rz_return_val_if_fail(x && y, NULL);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	bool a = false, b = false, _carry = false;
	RzILBitVector *ret = rz_il_bv_new(x->len);

	for (ut32 pos = 0; pos < x->len; ++pos) {
		a = rz_il_bv_get(x, pos);
		b = rz_il_bv_get(y, pos);
		rz_il_bv_set(ret, pos, a ^ b ^ _carry);
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
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \param borrow bool*, bool pointer to where to save the borrow value.
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_sub(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y, RZ_NULLABLE bool *borrow) {
	rz_return_val_if_fail(x && y, NULL);

	RzILBitVector *ret;
	RzILBitVector *neg_y;

	neg_y = rz_il_bv_neg(y);
	ret = rz_il_bv_add(x, neg_y, borrow);
	rz_il_bv_free(neg_y);
	return ret;
}

/**
 * Result of (x * y) mod 2^length
 * Both operands must have the same length.
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_mul(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);

	RzILBitVector *result, *dump, *tmp;
	bool cur_bit = false;

	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	result = rz_il_bv_new(x->len);
	dump = rz_il_bv_dup(x);

	for (ut32 i = 0; i < y->len; ++i) {
		cur_bit = rz_il_bv_get(y, i);
		if (cur_bit) {
			tmp = rz_il_bv_add(result, dump, NULL);
			rz_il_bv_free(result);
			result = tmp;
		}
		rz_il_bv_lshift(dump, 1);
	}

	rz_il_bv_free(dump);
	return result;
}

/* Treat x, y as unsigned
 * Both operands must have the same length.
 * if x < y return negtive (-1)
 * if x == y return 0
 * if x > y return positive (+1)
 */
int bv_unsigned_cmp(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
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
 * Both operands must have the same length.
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_div(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		rz_warn_if_reached();
		return NULL;
	}

	if (rz_il_bv_is_zero_vector(y)) {
		RzILBitVector *ret = rz_il_bv_new(y->len);
		rz_il_bv_set_all(ret, true);
		RZ_LOG_ERROR("RzIL: can't divide by zero\n");
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
		return rz_il_bv_dup(x);
	}

	// dividend > divisor
	RzILBitVector *dividend = rz_il_bv_dup(x);
	RzILBitVector *tmp;
	ut32 count = 0;

	while (bv_unsigned_cmp(dividend, y) >= 0) {
		count += 1;
		tmp = rz_il_bv_sub(dividend, y, NULL);
		rz_il_bv_free(dividend);
		dividend = tmp;
	}

	RzILBitVector *remainder = dividend;
	RzILBitVector *quotient = rz_il_bv_new_from_ut64(x->len, count);
	rz_il_bv_free(remainder);
	return quotient;
}

/**
 * Result of (x mod y) mod 2^length
 * Both operands must have the same length.
 * \param x RzILBitVector, Operand
 * \param y RzILBitVector, Operand
 * \return ret RzILBitVector, point to the new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_mod(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	if (x->len != y->len) {
		rz_warn_if_reached();
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
		return rz_il_bv_new(x->len);
	}

	// dividend > divisor
	RzILBitVector *dividend = rz_il_bv_dup(x);
	RzILBitVector *tmp;

	while (bv_unsigned_cmp(dividend, y) >= 0) {
		tmp = rz_il_bv_sub(dividend, y, NULL);
		rz_il_bv_free(dividend);
		dividend = tmp;
	}

	RzILBitVector *remainder = dividend;
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
RZ_API RZ_OWN RzILBitVector *rz_il_bv_sdiv(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	bool mx = rz_il_bv_msb(x);
	bool my = rz_il_bv_msb(y);

	RzILBitVector *neg_x, *neg_y, *tmp, *ret;

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
RZ_API RZ_OWN RzILBitVector *rz_il_bv_smod(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	bool mx = rz_il_bv_msb(x);
	bool my = rz_il_bv_msb(y);

	RzILBitVector *neg_x, *neg_y, *tmp, *ret;

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
RZ_API bool rz_il_bv_msb(RZ_NONNULL RzILBitVector *bv) {
	return rz_il_bv_get(bv, bv->len - 1);
}

/**
 * Get the least significant bit of bitvector
 * \param bv RzILBitVector, operand
 * \return b bit, bool value of LSB
 */
RZ_API bool rz_il_bv_lsb(RZ_NONNULL RzILBitVector *bv) {
	return rz_il_bv_get(bv, 0);
}

/**
 * Check if the bitvector is zero
 * \param x RzILBitVector, pointer to bv
 * \return ret bool, return true if bv is a zero bitvector, false if not
 */
RZ_API bool rz_il_bv_is_zero_vector(RZ_NONNULL RzILBitVector *x) {
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
 * Check if x <= y (as unsigned value)
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_il_bv_ule(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	// x > y ? return false : return true
	return bv_unsigned_cmp(x, y) <= 0;
}

/**
 * Check if x <= y (as signed value)
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret bool, return true if x <= y, else return false
 */
RZ_API bool rz_il_bv_sle(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, false);
	bool x_msb = rz_il_bv_msb(x);
	bool y_msb = rz_il_bv_msb(y);

	if (x_msb && y_msb) {
		return !rz_il_bv_ule(x, y);
	}

	if (!x_msb && !y_msb) {
		return rz_il_bv_ule(x, y);
	}

	// if x_msb set, y_msb unset => x < y
	// if x_msb unset, y_msb set => x > y
	// x != y when reaches here
	return x_msb;
}

/**
 * Check if x equals to y
 * Both operands must have the same length.
 * \param x RzILBitVector, operand
 * \param y RzILBitVector, operand
 * \return ret int, return 1 if x != y, return 0 if x == y
 */
RZ_API int rz_il_bv_cmp(RZ_NONNULL RzILBitVector *x, RZ_NONNULL RzILBitVector *y) {
	rz_return_val_if_fail(x && y, 0);

	if (x->len != y->len) {
		rz_warn_if_reached();
		return 1;
	}

	for (ut32 i = 0; i < x->len; ++i) {
		if (rz_il_bv_get(x, i) != rz_il_bv_get(y, i)) {
			return 1;
		}
	}

	return 0;
}

/**
 * Get the length of bitvector
 * \param bv RzILBitVector
 * \return len ut32, length of bitvector
 */
RZ_API ut32 rz_il_bv_len(RZ_NONNULL RzILBitVector *bv) {
	rz_return_val_if_fail(bv, 0);
	return bv->len;
}

/**
 * Convert ut64 to `length`-bits bitvector
 * \param length ut32, length of bitvector
 * \param value ut64, the value to convert
 * \return bv RzILBitVector, pointer to new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new_from_ut64(ut32 length, ut64 value) {
	rz_return_val_if_fail(length > 0, NULL);

	RzILBitVector *bv = rz_il_bv_new(length);
	if (!bv) {
		RZ_LOG_ERROR("RzIL: failed to allocate RzILBitVector\n");
		return NULL;
	}
	rz_il_bv_set_from_ut64(bv, value);
	return bv;
}

/**
 * Convert st64 to `length`-bits bitvector
 * \param length ut32, length of bitvector
 * \param value st64, the value to convert
 * \return bv RzILBitVector, pointer to new bitvector
 */
RZ_API RZ_OWN RzILBitVector *rz_il_bv_new_from_st64(ut32 length, st64 value) {
	rz_return_val_if_fail(length > 0, NULL);

	RzILBitVector *bv = rz_il_bv_new(length);
	if (!bv) {
		RZ_LOG_ERROR("RzIL: failed to allocate RzILBitVector\n");
		return NULL;
	}
	rz_il_bv_set_from_st64(bv, value);
	return bv;
}

/**
 * Convert ut64 to N-bits bitvector
 * \param bv RzILBitVector, pointer to bitvector
 * \param value ut64, the value to convert
 */
RZ_API bool rz_il_bv_set_from_ut64(RZ_NONNULL RzILBitVector *bv, ut64 value) {
	rz_return_val_if_fail(bv, false);

	if (bv->len <= 64) {
		bv->bits.small_u = value;
		bv->bits.small_u &= (UT64_MAX >> (64 - bv->len));
		return true;
	}

	for (ut32 i = 0; i < bv->len; ++i) {
		rz_il_bv_set(bv, i, value & 1);
		value >>= 1;
	}
	return true;
}

/**
 * Convert st64 to N-bits bitvector
 * \param bv RzILBitVector, pointer to bitvector
 * \param value st64, the value to convert
 */
RZ_API bool rz_il_bv_set_from_st64(RZ_NONNULL RzILBitVector *bv, st64 value) {
	rz_return_val_if_fail(bv, false);
	if (bv->len <= 64) {
		bv->bits.small_u = *((ut64 *)&value);
		bv->bits.small_u &= (UT64_MAX >> (64 - bv->len));
		return true;
	}

	for (ut32 i = 0; i < bv->len; ++i) {
		rz_il_bv_set(bv, i, value & 1);
		value >>= 1;
	}
	return true;
}

/**
 * Calculates the hash from the bitvector data
 * \param x BitVector
 * \return ut32 bitvector hash
 */
ut32 rz_il_bv_hash(RZ_NULLABLE RzILBitVector *x) {
	ut32 h = 5381;
	ut32 size = (x->len > 64) ? x->_elem_len : sizeof(x->bits.small_u);
	ut8 *bits = (x->len > 64) ? x->bits.large_a : (ut8 *)&x->bits.small_u;

	if (!x || !size || !bits) {
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
RZ_API ut8 rz_il_bv_to_ut8(RZ_NONNULL RzILBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return (ut8)x->bits.small_u & UT8_MAX;
	}
	ut8 ret = 0;
	for (ut32 i = 0; i < x->len && i < 8; ++i) {
		if (rz_il_bv_get(x, i)) {
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
RZ_API ut16 rz_il_bv_to_ut16(RZ_NONNULL RzILBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return (ut16)x->bits.small_u & UT16_MAX;
	}
	ut16 ret = 0;
	for (ut32 i = 0; i < x->len && i < 16; ++i) {
		if (rz_il_bv_get(x, i)) {
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
RZ_API ut32 rz_il_bv_to_ut32(RzILBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return (ut32)x->bits.small_u & UT32_MAX;
	}
	ut32 ret = 0;
	for (ut32 i = 0; i < x->len && i < 32; ++i) {
		if (rz_il_bv_get(x, i)) {
			ret |= 1 << i;
		}
	}
	return ret;
}

/**
 * Convert RzILBitVector to ut64
 * \param x RzILBitVector, pointer to the bitvector
 * \return ret ut64, num value of bitvector
 */
RZ_API ut64 rz_il_bv_to_ut64(RZ_NONNULL RzILBitVector *x) {
	rz_return_val_if_fail(x, 0);
	if (x->len <= 64) {
		return x->bits.small_u;
	}
	ut64 ret = 0;
	for (ut32 i = 0; i < x->len && i < 64; ++i) {
		if (rz_il_bv_get(x, i)) {
			ret |= 1 << i;
		}
	}
	return ret;
}
