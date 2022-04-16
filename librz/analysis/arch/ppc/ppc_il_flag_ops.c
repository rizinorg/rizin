// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
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
	return IN_64BIT_MODE ? SEQ2(set_ca, SETG("ca", VARL("carry"))) : SEQ3(set_ca, SETG("ca", VARL("carry")), SETG("ca32", VARL("carry")));
}

/**
 * \brief Set the cr0 register depending how \p val compares to 0.
 *
 * \param val Value which is compared to 0.
 * \return RzILOpEffect* Set cr0 effect.
 */
RZ_OWN RzILOpEffect *set_cr0(RZ_NONNULL RZ_BORROW RzILOpPure *val) {
	rz_return_val_if_fail(val, NULL);

	RzILOpEffect *cond_geq = BRANCH(SGT(DUP(val), U64(0)),
		SETG("cr0", LOGOR(SHIFTL0(VARG("so"), U8(3)), UN(4, 0b010))), // val > 0
		SETG("cr0", LOGOR(SHIFTL0(VARG("so"), U8(3)), UN(4, 0b100))) // val == 0
	);
	RzILOpEffect *cond_l = BRANCH(SLT(DUP(val), U64(0)),
		SETG("cr0", LOGOR(SHIFTL0(VARG("so"), U8(3)), UN(4, 0b001))), // val < 0
		cond_geq);
	return cond_l;
}

#include <rz_il/rz_il_opbuilder_end.h>
