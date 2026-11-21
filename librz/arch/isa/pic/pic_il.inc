// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

static inline RzILOpPure *pure_slice(RzILOpPure *x, ut8 l, ut8 r) {
	rz_return_val_if_fail(l < r, NULL);
	return UNSIGNED(r - l, SHIFTR0(x, U16(l)));
}

#define BITN(x, n) IS_ZERO(UNSIGNED(1, SHIFTR0(x, U32(n))))

// overflow is not used in status register but just keeping this for future "maybe" use
/** \brief Computes signed overflow flag from operand MSBs and result MSB. */
static inline RZ_UNUSED RzILOpBool *pic_il_check_overflow(RzILOpPure *x, RzILOpPure *y, RzILOpPure *res) {
	return AND(XOR(MSB(x), MSB(res)), XOR(MSB(y), MSB(DUP(res))));
}

/** \brief Computes carry-out flag for 8-bit addition. */
static inline RZ_UNUSED RzILOpBool *pic_il_check_carry(RzILOpPure *x, RzILOpPure *y, RzILOpPure *res) {
	return OR(AND(MSB(x), MSB(y)), AND(OR(MSB(DUP(x)), MSB(DUP(y))), INV(MSB(res))));
}

/** \brief Computes borrow (inverted carry) flag for 8-bit subtraction. */
static inline RZ_UNUSED RzILOpBool *pic_il_check_borrow(RzILOpPure *x, RzILOpPure *y, RzILOpPure *res) {
	return OR(
		OR(AND(INV(MSB(x)), MSB(y)), AND(INV(MSB(DUP(x))), MSB(res))),
		AND(MSB(DUP(x)), AND(MSB(DUP(y)), MSB(DUP(res)))));
}

/** \brief Computes digit carry-out flag (bit 3) for 8-bit addition. */
static inline RZ_UNUSED RzILOpBool *pic_il_check_digit_carry(RzILOpPure *x, RzILOpPure *y, RzILOpPure *res) {
	return OR(
		AND(BITN(x, 3), BITN(y, 3)),
		AND(OR(BITN(DUP(x), 3), BITN(DUP(y), 3)), INV(BITN(res, 3))));
}

/** \brief Computes digit borrow (bit 3) flag for 8-bit subtraction. */
static inline RZ_UNUSED RzILOpBool *pic_il_check_digit_borrow(RzILOpPure *x, RzILOpPure *y, RzILOpPure *res) {
	return OR(
		OR(AND(INV(BITN(x, 3)), BITN(y, 3)), AND(INV(BITN(DUP(x), 3)), BITN(res, 3))),
		AND(BITN(DUP(x), 3), AND(BITN(DUP(y), 3), BITN(DUP(res), 3))));
}

#define CHECK_OVERFLOW(x, y, res)     pic_il_check_overflow(x, y, res)
#define CHECK_CARRY(x, y, res)        pic_il_check_carry(x, y, res)
#define CHECK_BORROW(x, y, res)       pic_il_check_borrow(x, y, res)
#define CHECK_DIGIT_CARRY(x, y, res)  pic_il_check_digit_carry(x, y, res)
#define CHECK_DIGIT_BORROW(x, y, res) pic_il_check_digit_borrow(x, y, res)

static inline RzILOpPure *bit_set(RzILOpPure *v, ut32 b, bool x) {
	if (x) {
		return LOGOR(v, U8(1 << b));
	}
	return LOGAND(v, U8(~(1 << b)));
}

static inline RzILOpPure *bit_set1(RzILOpPure *v, ut32 b, RzILOpBool *x) {
	return ITE(x, LOGOR(v, U8(1 << b)), LOGAND(DUP(v), U8(~(1 << b))));
}

static inline RzILOpPure *bit_get(RzILOpPure *v, ut32 b) {
	return NON_ZERO(LOGAND(v, U8(1 << b)));
}

#define regbit_set(reg, b, x)  SETG(reg, bit_set(VARG(reg), b, x))
#define regbit_set1(reg, b, x) SETG(reg, bit_set1(VARG(reg), b, x))
