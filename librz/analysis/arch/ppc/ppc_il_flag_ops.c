// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include "ppc_analysis.h"
#include <rz_types.h>

#include <rz_il/rz_il_opbuilder_begin.h>

#define EXTEND(n, v) ITE(MSB(v), SIGNED(n, v), UNSIGNED(n, v))

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
	ut32 bits = IN_64BIT_MODE ? 64 : 32;
	RzILOpBitVector *r;
	if (add) {
		r = ADD(EXTEND(bits + 1, a), EXTEND(bits + 1, b));
	} else {
		r = SUB(EXTEND(bits + 1, a), EXTEND(bits + 1, b));
	}
	RzILOpBool *c = ITE(MSB(r), IL_TRUE, IL_FALSE);
	return IN_64BIT_MODE ? SETG("ca", c) : SEQ2(SETG("ca", c), SETG("ca32", c));
}

/**
 * \brief Set the cr0 register depending how \p val compares to 0.
 *
 * \param val Value which is compared to 0.
 * \return RzILOpEffect* Set cr0 effect.
 */
RZ_OWN RzILOpEffect *set_cr0(RZ_NONNULL RzILOpPure *val) {
	rz_return_val_if_fail(val, NULL);
	RzILOpBool *so_bit = VARG("so");
	RzILOpPure *n = U64(0);
	RzILOpEffect *cond_geq = BRANCH(SGT(val, n),
		SETG("cr0", LOGOR(SHIFTL0(so_bit, U8(3)), UN(4, 0b010))), // val > 0
		SETG("cr0", LOGOR(SHIFTL0(so_bit, U8(3)), UN(4, 0b100))) // val == 0
	);
	RzILOpEffect *cond_l = BRANCH(SLT(val, n),
		SETG("cr0", LOGOR(SHIFTL0(so_bit, U8(3)), UN(4, 0b001))), // val < 0
		cond_geq);
	return cond_l;
}

#include <rz_il/rz_il_opbuilder_end.h>
