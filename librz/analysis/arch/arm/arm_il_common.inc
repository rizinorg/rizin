// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Carry resulting from a + b (+ cf)
 */
static RZ_OWN RzILOpBool *add_carry(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, bool with_carry) {
	RzILOpBitVector *r = ADD(UNSIGNED(33, a), UNSIGNED(33, b));
	if (with_carry) {
		r = ADD(r, ITE(VARG("cf"), UN(33, 1), UN(33, 0)));
	}
	return MSB(r);
}

/**
 * Carry resulting from a - b
 */
static RZ_OWN RzILOpBool *sub_carry(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, bool with_carry) {
	if (with_carry) {
		return add_carry(a, LOGNOT(b), true);
	}
	return ULE(b, a);
}

/**
 * Overflow (V) resulting from a + b
 */
static RZ_OWN RzILOpBool *add_overflow(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RzILOpBitVector *res) {
	return AND(INV(XOR(MSB(a), MSB(b))), XOR(MSB(DUP(a)), MSB(res)));
}

/**
 * Overflow (V) resulting from a - b
 */
static RZ_OWN RzILOpBool *sub_overflow(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RzILOpBitVector *res) {
	return AND(XOR(MSB(a), MSB(b)), XOR(MSB(DUP(a)), MSB(res)));
}
