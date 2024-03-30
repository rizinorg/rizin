// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implements common bit operation perfomed on values.
 */

#include <rz_util/rz_assert.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_types.h>

/**
 * \brief Extracts \p length bits from \p start of \p value and returns them as U32.
 *
 * Performed operation: ((value >> start) & (~0U >> (0x20 - length)));
 *
 * \param value The value to extract the bits from. It must be a bitvector of size 32.
 * \param start The start index of the bits to extract. Passed bitvector can be of any width.
 * \param length Number of bits to extract. Passed bitvector must be 32bits in size.
 *
 * \return A 32bit wide bitvector with the extracted value.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_extract32(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length) {
	rz_return_val_if_fail(value && start && length, NULL);
	RzILOpPure *op_RSHIFT_0 = rz_il_op_new_shiftr(rz_il_op_new_b0(), value, start);
	RzILOpPure *op_SUB_4 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x20), length);
	RzILOpPure *op_RSHIFT_5 = rz_il_op_new_shiftr(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, -1), op_SUB_4);
	RzILOpPure *op_AND_6 = rz_il_op_new_log_and(op_RSHIFT_0, op_RSHIFT_5);
	return op_AND_6;
}

/**
 * \brief Extracts \p length bits from \p start of \p value and returns them as U64.
 *
 * Performed operation: ((value >> start) & (~0ULL >> (0x40 - length)));
 *
 * \param value The value to extract the bits from. It must be a bitvector of size 64.
 * \param start The start index of the bits to extract. Passed bitvector can be of any width.
 * \param length Number of bits to extract. Passed bitvector must be 32bits in size.
 *
 * \return A 64bit wide bitvector with the extracted value.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_extract64(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length) {
	rz_return_val_if_fail(value && start && length, NULL);
	RzILOpPure *op_RSHIFT_0 = rz_il_op_new_shiftr(rz_il_op_new_b0(), value, start);
	RzILOpPure *op_SUB_4 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x40), length);
	RzILOpPure *op_RSHIFT_5 = rz_il_op_new_shiftr(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(64, -1), op_SUB_4);
	RzILOpPure *op_AND_6 = rz_il_op_new_log_and(op_RSHIFT_0, op_RSHIFT_5);
	return op_AND_6;
}

/**
 * \brief Extracts \p length bits from \p start from \p value and returns them as S32. The extracted value is sign extended.
 *
 * Performed operation: (((st32) (value << 0x20 - length - start)) >> 0x20 - length);
 *
 * \param value The value to extract the bits from. It must be a bitvector of size 32.
 * \param start The start index of the bits to extract. Passed bitvector must be 32bits in size.
 * \param length Number of bits to extract. Passed bitvector must be 32bits in size.
 *
 * \return A 32bit wide sign extended bitvector with the extracted value.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_sextract32(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length) {
	rz_return_val_if_fail(value && start && length, NULL);
	RzILOpPure *op_SUB_1 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x20), length);
	RzILOpPure *op_SUB_2 = rz_il_op_new_sub(op_SUB_1, start);
	RzILOpPure *op_LSHIFT_3 = rz_il_op_new_shiftl(rz_il_op_new_b0(), value, op_SUB_2);
	RzILOpPure *op_SUB_6 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x20), rz_il_op_pure_dup(length));
	RzILOpPure *op_RSHIFT_7 = rz_il_op_new_shiftr_arith(rz_il_op_new_cast(32, rz_il_op_new_b0(), op_LSHIFT_3), op_SUB_6);
	return op_RSHIFT_7;
}

/**
 * \brief Extracts \p length bits from \p start from \p value and returns them as S64. The extracted value is sign extended.
 *
 * Performed operation: (((st64) (value << 0x40 - length - start)) >> 0x40 - length);
 *
 * \param value The value to extract the bits from. It must be a bitvector of size 64.
 * \param start The start index of the bits to extract. Passed bitvector must be 32bits in size.
 * \param length Number of bits to extract. Passed bitvector must be 32bits in size.
 *
 * \return A 64bit wide sign extended bitvector with the extracted value.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_sextract64(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length) {
	rz_return_val_if_fail(value && start && length, NULL);
	RzILOpPure *op_SUB_1 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x40), length);
	RzILOpPure *op_SUB_2 = rz_il_op_new_sub(op_SUB_1, start);
	RzILOpPure *op_LSHIFT_3 = rz_il_op_new_shiftl(rz_il_op_new_b0(), value, op_SUB_2);
	RzILOpPure *op_SUB_6 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x40), rz_il_op_pure_dup(length));
	RzILOpPure *op_RSHIFT_7 = rz_il_op_new_shiftr_arith(rz_il_op_new_cast(64, rz_il_op_new_b0(), op_LSHIFT_3), op_SUB_6);
	return op_RSHIFT_7;
}

/**
 * \brief Deposits \p fieldval in \p value. The \p fieldval is inserted at \p start until \p start + \p length.
 *
 * Performed operation: ((value & (~((~0ULL >> (0x40 - length)) << start))) | ((fieldval << start) & ((~0ULL >> (0x40 - length)) << start)));
 *
 * \param value The value to deposit \p fieldval into. It must be a bitvector of size 64.
 * \param start The start index to deposit \p fieldval into. Passed bitvector can be of any width.
 * \param length Number of bits to deposit. Passed bitvector must be 32bits in size.
 * \param fieldval The bits to deposit into \p value into. It must be a bitvector of size 64.
 *
 * \return \p value where bits[start:length] are replaced with \p fieldval
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_deposit64(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length, RZ_BORROW RzILOpBitVector *fieldval) {
	rz_return_val_if_fail(value && start && length && fieldval, NULL);
	RzILOpPure *op_SUB_4 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x40), length);
	RzILOpPure *op_RSHIFT_5 = rz_il_op_new_shiftr(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(64, -1), op_SUB_4);
	RzILOpPure *op_LSHIFT_6 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_RSHIFT_5, start);
	RzILOpPure *op_NOT_8 = rz_il_op_new_log_not(op_LSHIFT_6);
	RzILOpPure *op_AND_9 = rz_il_op_new_log_and(value, op_NOT_8);
	RzILOpPure *op_LSHIFT_10 = rz_il_op_new_shiftl(rz_il_op_new_b0(), fieldval, rz_il_op_pure_dup(start));
	RzILOpPure *op_AND_11 = rz_il_op_new_log_and(op_LSHIFT_10, rz_il_op_pure_dup(op_LSHIFT_6));
	RzILOpPure *op_OR_12 = rz_il_op_new_log_or(op_AND_9, op_AND_11);
	return op_OR_12;
}

/**
 * \brief Deposits \p fieldval in \p value. The \p fieldval is inserted at \p start until \p start + \p length.
 *
 * Performed operation: ((value & (~((~0U >> (0x20 - length)) << start))) | ((fieldval << start) & ((~0U >> (0x20 - length)) << start)));
 *
 * \param value The value to deposit \p fieldval into. It must be a bitvector of size 32.
 * \param start The start index to deposit \p fieldval into. Passed bitvector can be of any width.
 * \param length Number of bits to deposit. Passed bitvector must be 32bits in size.
 * \param fieldval The bits to deposit into \p value into. It must be a bitvector of size 32.
 *
 * \return \p value where bits[start:length] are replaced with \p fieldval.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_deposit32(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length, RZ_BORROW RzILOpBitVector *fieldval) {
	rz_return_val_if_fail(value && start && length && fieldval, NULL);
	RzILOpPure *op_SUB_4 = rz_il_op_new_sub(rz_il_op_new_bitv_from_st64(32, 0x20), length);
	RzILOpPure *op_RSHIFT_5 = rz_il_op_new_shiftr(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, -1), op_SUB_4);
	RzILOpPure *op_LSHIFT_6 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_RSHIFT_5, start);
	RzILOpPure *op_NOT_8 = rz_il_op_new_log_not(op_LSHIFT_6);
	RzILOpPure *op_AND_9 = rz_il_op_new_log_and(value, op_NOT_8);
	RzILOpPure *op_LSHIFT_10 = rz_il_op_new_shiftl(rz_il_op_new_b0(), fieldval, rz_il_op_pure_dup(start));
	RzILOpPure *op_AND_11 = rz_il_op_new_log_and(op_LSHIFT_10, rz_il_op_pure_dup(op_LSHIFT_6));
	RzILOpPure *op_OR_12 = rz_il_op_new_log_or(op_AND_9, op_AND_11);
	return op_OR_12;
}

/**
 * \brief Performes a byte swap of \p t.
 *
 * Perfomed operation: (((((st32) t) & 0xff00) >> 0x8) | ((((st32) t) & 0xff) << 0x8));
 *
 * \param t A 16bit wide bitvector for which to swap the bytes.
 *
 * \return The bitvector \p t with swapped bytes.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_bswap16(RZ_BORROW RzILOpBitVector *t) {
	rz_return_val_if_fail(t, NULL);
	RzILOpPure *op_AND_2 = rz_il_op_new_log_and(rz_il_op_new_cast(32, rz_il_op_new_b0(), t), rz_il_op_new_bitv_from_st64(32, 0xff00));
	RzILOpPure *op_RSHIFT_4 = rz_il_op_new_shiftr_arith(op_AND_2, rz_il_op_new_bitv_from_st64(32, 8));
	RzILOpPure *op_AND_7 = rz_il_op_new_log_and(rz_il_op_new_cast(32, rz_il_op_new_b0(), rz_il_op_pure_dup(t)), rz_il_op_new_bitv_from_st64(32, 0xff));
	RzILOpPure *op_LSHIFT_9 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_7, rz_il_op_new_bitv_from_st64(32, 8));
	RzILOpPure *op_OR_10 = rz_il_op_new_log_or(op_RSHIFT_4, op_LSHIFT_9);
	return rz_il_op_new_cast(16, rz_il_op_new_b0(), op_OR_10);
}

/**
 * \brief Performes a byte swap of \p t.
 *
 * Perfomed operation:
 *   ((t & ((ut32) 0xff)) << 0x18)
 * | ((t & ((ut32) 0xff00)) << 0x8))
 * | ((t & ((ut32) 0xff0000)) >> 0x8))
 * | ((t & ((ut32) 0xff000000)) >> 0x18));
 *
 * \param t A 32bit wide bitvector for which to swap the bytes.
 *
 * \return The bitvector \p t with swapped bytes.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_bswap32(RZ_BORROW RzILOpBitVector *t) {
	rz_return_val_if_fail(t, NULL);
	RzILOpPure *op_AND_2 = rz_il_op_new_log_and(t, rz_il_op_new_cast(32, rz_il_op_new_b0(), rz_il_op_new_bitv_from_st64(32, 0xff)));
	RzILOpPure *op_LSHIFT_4 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_2, rz_il_op_new_bitv_from_st64(32, 24));
	RzILOpPure *op_AND_7 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_cast(32, rz_il_op_new_b0(), rz_il_op_new_bitv_from_st64(32, 0xff00)));
	RzILOpPure *op_LSHIFT_9 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_7, rz_il_op_new_bitv_from_st64(32, 8));
	RzILOpPure *op_OR_10 = rz_il_op_new_log_or(op_LSHIFT_4, op_LSHIFT_9);
	RzILOpPure *op_AND_13 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_cast(32, rz_il_op_new_b0(), rz_il_op_new_bitv_from_st64(32, 0xff0000)));
	RzILOpPure *op_RSHIFT_15 = rz_il_op_new_shiftr(rz_il_op_new_b0(), op_AND_13, rz_il_op_new_bitv_from_st64(32, 8));
	RzILOpPure *op_OR_16 = rz_il_op_new_log_or(op_OR_10, op_RSHIFT_15);
	RzILOpPure *op_AND_19 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_cast(32, rz_il_op_new_b0(), rz_il_op_new_bitv_from_st64(32, 0xff000000)));
	RzILOpPure *op_RSHIFT_21 = rz_il_op_new_shiftr(rz_il_op_new_b0(), op_AND_19, rz_il_op_new_bitv_from_st64(32, 24));
	RzILOpPure *op_OR_22 = rz_il_op_new_log_or(op_OR_16, op_RSHIFT_21);
	return op_OR_22;
}

/**
 * \brief Performs a byte swap of \p t.
 *
 * Perfomed operation:
 *   ((t & 0xff) << 0x38)
 * | ((t & 0xff00) << 0x28))
 * | ((t & 0xff0000) << 0x18))
 * | ((t & 0xff000000) << 0x8))
 * | ((t & 0xff00000000) >> 0x8))
 * | ((t & 0xff0000000000) >> 0x18))
 * | ((t & 0xff000000000000) >> 0x28))
 * | ((t & 0xff00000000000000) >> 0x38));
 *
 * \param t A 64bit wide bitvector for which to swap the bytes.
 *
 * \return The bitvector \p t with swapped bytes.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_bswap64(RZ_BORROW RzILOpBitVector *t) {
	RzILOpPure *op_AND_1 = rz_il_op_new_log_and(t, rz_il_op_new_bitv_from_ut64(64, 0xff));
	RzILOpPure *op_LSHIFT_3 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_1, rz_il_op_new_bitv_from_st64(32, 0x38));
	RzILOpPure *op_AND_5 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff00));
	RzILOpPure *op_LSHIFT_7 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_5, rz_il_op_new_bitv_from_st64(32, 0x28));
	RzILOpPure *op_OR_8 = rz_il_op_new_log_or(op_LSHIFT_3, op_LSHIFT_7);
	RzILOpPure *op_AND_10 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff0000));
	RzILOpPure *op_LSHIFT_12 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_10, rz_il_op_new_bitv_from_st64(32, 24));
	RzILOpPure *op_OR_13 = rz_il_op_new_log_or(op_OR_8, op_LSHIFT_12);
	RzILOpPure *op_AND_15 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff000000));
	RzILOpPure *op_LSHIFT_17 = rz_il_op_new_shiftl(rz_il_op_new_b0(), op_AND_15, rz_il_op_new_bitv_from_st64(32, 8));
	RzILOpPure *op_OR_18 = rz_il_op_new_log_or(op_OR_13, op_LSHIFT_17);
	RzILOpPure *op_AND_20 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff00000000));
	RzILOpPure *op_RSHIFT_22 = rz_il_op_new_shiftr(rz_il_op_new_b0(), op_AND_20, rz_il_op_new_bitv_from_st64(32, 8));
	RzILOpPure *op_OR_23 = rz_il_op_new_log_or(op_OR_18, op_RSHIFT_22);
	RzILOpPure *op_AND_25 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff0000000000));
	RzILOpPure *op_RSHIFT_27 = rz_il_op_new_shiftr(rz_il_op_new_b0(), op_AND_25, rz_il_op_new_bitv_from_st64(32, 24));
	RzILOpPure *op_OR_28 = rz_il_op_new_log_or(op_OR_23, op_RSHIFT_27);
	RzILOpPure *op_AND_30 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff000000000000));
	RzILOpPure *op_RSHIFT_32 = rz_il_op_new_shiftr(rz_il_op_new_b0(), op_AND_30, rz_il_op_new_bitv_from_st64(32, 0x28));
	RzILOpPure *op_OR_33 = rz_il_op_new_log_or(op_OR_28, op_RSHIFT_32);
	RzILOpPure *op_AND_35 = rz_il_op_new_log_and(rz_il_op_pure_dup(t), rz_il_op_new_bitv_from_ut64(64, 0xff00000000000000));
	RzILOpPure *op_RSHIFT_37 = rz_il_op_new_shiftr(rz_il_op_new_b0(), op_AND_35, rz_il_op_new_bitv_from_st64(32, 0x38));
	RzILOpPure *op_OR_38 = rz_il_op_new_log_or(op_OR_33, op_RSHIFT_37);
	return op_OR_38;
}

/**
 *  \brief [NE] not eq x y binary predicate for bitwise equality
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_ne(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *result = rz_il_op_new_eq(x, y);
	if (!result) {
		return NULL;
	}
	return rz_il_op_new_bool_inv(result);
}

static inline RZ_OWN RzILOpBool *_any_fl_is_nan(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y) {
	return rz_il_op_new_bool_or(rz_il_op_new_is_nan(x), rz_il_op_new_is_nan(y));
}

static inline RZ_OWN RzILOpBool *_fl_is_less(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	RzILOpFloat *x_dup = rz_il_op_pure_dup(x);
	RzILOpFloat *y_dup = rz_il_op_pure_dup(y);
	return rz_il_op_new_forder(x_dup, y_dup);
}

RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fneq(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *is_nan = _any_fl_is_nan(x, y);
	RzILOpBool *not_equal = rz_il_op_new_bool_or(_fl_is_less(x, y), _fl_is_less(y, x));
	return rz_il_op_new_bool_or(is_nan, not_equal);
}

RZ_API RZ_OWN RzILOpBool *rz_il_op_new_feq(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	rz_return_val_if_fail(x && y, NULL);
	return rz_il_op_new_bool_inv(rz_il_op_new_fneq(x, y));
}

RZ_API RZ_OWN RzILOpBool *rz_il_op_new_flt(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *not_nan = rz_il_op_new_bool_inv(_any_fl_is_nan(x, y));
	RzILOpBool *is_less = _fl_is_less(x, y);
	return rz_il_op_new_bool_and(not_nan, is_less);
}

RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fle(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *not_nan = rz_il_op_new_bool_inv(_any_fl_is_nan(x, y));
	RzILOpBool *is_great = _fl_is_less(y, x);
	return rz_il_op_new_bool_and(not_nan, rz_il_op_new_bool_inv(is_great));
}

RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fgt(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *not_nan = rz_il_op_new_bool_inv(_any_fl_is_nan(x, y));
	RzILOpBool *is_great = _fl_is_less(y, x);
	return rz_il_op_new_bool_and(not_nan, is_great);
}

RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fge(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *not_nan = rz_il_op_new_bool_inv(_any_fl_is_nan(x, y));
	RzILOpBool *is_less = _fl_is_less(x, y);
	return rz_il_op_new_bool_and(not_nan, rz_il_op_new_bool_inv(is_less));
}
