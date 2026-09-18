// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Internal interface of the C28x RzIL lifter.
 */

#ifndef C28X_IL_H
#define C28X_IL_H

#include "c28x.h"

#include <rz_il/rz_il_opcodes.h>

/**
 * \brief Name of the local holding a memory operand's latched effective
 * address.
 */
#define C28X_EA_LOCAL "_ea"

RZ_IPI RzILOpPure *c28x_byte(RzILOpPure *word_addr);
RZ_IPI bool c28x_is_mem(const C28xOperand *o);
RZ_IPI const char *c28x_reg32(const C28xOperand *o);
RZ_IPI RzILOpPure *c28x_ea_load(ut32 bits);
RZ_IPI RzILOpEffect *c28x_ea_store(RzILOpPure *val);
RZ_IPI RzILOpEffect *c28x_with_ea(const C28xOperand *m, RzILOpEffect *body);
/**
 * \brief Run \p body with the latched address of memory operand \p m, as a
 * 32-bit access when \p wide: rows render mem16 and mem32 as dis2000 does,
 * which isn't always the width they access.
 */
static inline RzILOpEffect *c28x_with_mem(const C28xOperand *m, bool wide, RzILOpEffect *body) {
	C28xOperand acc = *m;
	acc.wide = wide;
	return c28x_with_ea(&acc, body);
}

RZ_IPI RzILOpEffect *c28x_lift_vcu(const C28xInsn *insn, ut64 pc);

#endif // C28X_IL_H
