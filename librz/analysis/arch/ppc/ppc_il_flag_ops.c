// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include "rz_il/rz_il_opcodes.h"
#include <rz_types.h>

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \brief Set "ca" bit if, after an add or sub operation on \p a and \p b , the M+1 bit is set
 *
 * NOTE: In 32bit mode the "ca32" bit is set as well.
 *
 * \param a Value a.
 * \param b Value b.
 * \param mode Capstone mode.
 * \param add True: \p a + \p b False: \p a - \p b
 * \return RZ_OWN* Effect which sets the carry bits.
 */
RZ_OWN RzILOpEffect *set_carry_add_sub(RZ_OWN RzILOpBitVector *a, RZ_OWN RzILOpBitVector *b, cs_mode mode, bool add) {
	rz_return_val_if_fail(a && b, NULL);
	ut32 bits = PPC_ARCH_BITS;
	RzILOpBitVector *r;
	if (add) {
		r = ADD(UNSIGNED(bits + 1, DUP(a)), UNSIGNED(bits + 1, DUP(b)));
	} else {
		r = SUB(UNSIGNED(bits + 1, DUP(a)), UNSIGNED(bits + 1, DUP(b)));
	}

	RzILOpEffect *set_ca = SETL("carry", ITE(MSB(r), IL_TRUE, IL_FALSE));
	return IN_64BIT_MODE ? SEQ3(set_ca, SETG("ca", VARL("carry")), SETG("ca32", VARL("carry"))) : SEQ2(set_ca, SETG("ca", VARL("carry")));
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
RZ_OWN RzILOpEffect *cmp_set_cr(RZ_BORROW RzILOpPure *left, RZ_BORROW RzILOpPure *right, const bool signed_cmp, const char *crX, const cs_mode mode) {
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
