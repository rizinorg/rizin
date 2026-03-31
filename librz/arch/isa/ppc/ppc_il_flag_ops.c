// SPDX-FileCopyrightText: 2022 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include "rz_il/rz_il_opcodes.h"
#include <rz_types.h>

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \brief Set "ca" bit if, after an add operation on \p a and \p b , the M+1 bit is set.
 * If \p c is given the ca bit is set if the result of ( \p b + \p c ) or ( \p a + ( \p b + \p c )) has bit M+1 set.
 *
 * \param a Value a.
 * \param b Value b.
 * \param c Value c. Is optional and can be NULL
 * \param mode Capstone mode.
 * \return RzILOpEffect* Effect which sets the carry bits.
 */
RZ_IPI RZ_OWN RzILOpEffect *ppc_set_carry_add_sub(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, RZ_OWN RZ_NULLABLE RzILOpBitVector *c, cs_mode mode) {
	rz_return_val_if_fail(a && b, NULL);
	ut32 bits = PPC_ARCH_BITS;
	RzILOpPure *r0, *r2;
	if (c) {
		r2 = ADD(UNSIGNED(bits + 1, a), VARLP("r1"));
		r0 = LET("r1", ADD(UNSIGNED(bits + 1, b), UNSIGNED(bits + 1, c)), OR(MSB(VARLP("r1")), MSB(r2)));
	} else {
		r0 = MSB(ADD(UNSIGNED(bits + 1, a), UNSIGNED(bits + 1, b)));
	}
	// For ISA v3 CPU register ca32 should be handled here as well.
	return SETG("ca", r0);
}

/**
 * \brief Compares two values and sets the given cr field.
 *
 * \param left The left operand of the comparison.
 * \param right The right operand of the comparison.
 * \param signed_cmp True: Signed comparison. False: Unsigned comparison.
 * \param crX The cr field to set.
 * \param mode Capstone mode.
 * \return RzILOpEffect* Sequence of effects which set the cr field accordingly.
 */
RZ_IPI RZ_OWN RzILOpEffect *ppc_cmp_set_cr(RZ_BORROW RzILOpPure *left, RZ_BORROW RzILOpPure *right, const bool signed_cmp, const char *crX, const cs_mode mode) {
	rz_return_val_if_fail(left && right && crX, NULL);

	RzILOpEffect *set_so = SETL("so_flag", BOOL_TO_BV(VARG("so"), 1));
	RzILOpEffect *set_left = SETL("l", DUP(left));
	RzILOpEffect *set_right = SETL("r", DUP(right));
	RzILOpPure *cmp_gt = signed_cmp ? SGT(VARL("l"), VARL("r")) : UGT(VARL("l"), VARL("r"));
	RzILOpPure *cmp_lt = signed_cmp ? SLT(VARL("l"), VARL("r")) : ULT(VARL("l"), VARL("r"));

	RzILOpEffect *cond_geq = BRANCH(cmp_gt,
		SETG(crX, APPEND(UN(3, 0b010), VARL("so_flag"))), // left > right
		SETG(crX, APPEND(UN(3, 0b001), VARL("so_flag"))) // left == right
	);
	RzILOpEffect *cond_l = BRANCH(cmp_lt,
		SETG(crX, APPEND(UN(3, 0b100), VARL("so_flag"))), // left < right
		cond_geq);
	return SEQ4(set_left, set_right, set_so, cond_l);
}

#include <rz_il/rz_il_opbuilder_end.h>
