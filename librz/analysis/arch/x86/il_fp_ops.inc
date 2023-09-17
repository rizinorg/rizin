// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file il_fp_ops.c
 *
 * Contains the IL implementations for x86 floating point instructions.
 *
 * References:
 *  - https://docs.oracle.com/cd/E18752_01/html/817-5477/eoizy.html
 *  - https://eng.libretexts.org/Bookshelves/Computer_Science/Programming_Languages/x86-64_Assembly_Language_Programming_with_Ubuntu_(Jorgensen)/18%3A_Floating-Point_Instructions
 *  - https://en.wikibooks.org/wiki/X86_Assembly/Floating_Point#Floating-Point_Instruction_Set
 *  - https://github.com/avast/retdec/wiki/x86-FPU-semantic-model
 */

#include "common.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * FINIT/FNINIT
 * Initialize x87 FPU
 */
IL_LIFTER(fninit) {
	RzILOpEffect *set_cw = SETG(X86_REG_FPU_CW, UN(16, 0x37f));
    RzILOpEffect *set_sw = x86_il_set_reg(X86_REG_FPSW, UN(16, 0x0));
	RzILOpEffect *set_tw = SETG(X86_REG_FPU_TW, UN(16, 0xffff));
	RzILOpEffect *set_ip = SETG(X86_REG_FPU_IP, UN(32, 0x0));
	RzILOpEffect *set_dp = SETG(X86_REG_FPU_DP, UN(32, 0x0));

    return SEQ5(set_cw, set_sw, set_tw, set_ip, set_dp);
}

/**
 * FLDCW m16
 * Load x87 FPU Control Word 
 */
IL_LIFTER(fldcw) {
    return SETG(X86_REG_FPU_CW, x86_il_get_op(0));
}

/**
 * FSTCW/FNSTCW m2byte
 * Store x87 FPU Control Word
 */
IL_LIFTER(fnstcw) {
    return x86_il_set_op(0, VARG(X86_REG_FPU_CW));
}

/**
 * FSTSW/FNSTSW {m2byte | AX}
 * Store x87 FPU Status Word
 */
IL_LIFTER(fnstsw) {
    return x86_il_set_op(0, x86_il_get_reg(X86_REG_FPSW));
}

/* Arithmetic instructions */

/**
 * FABS
 * Clears the sign bit of st(0) to create absolute value
 */
IL_LIFTER(fabs) {
	RzILOpFloat *abs_value = FABS(x86_il_get_st_reg(X86_REG_ST0));
	return x86_il_set_st_reg(X86_REG_ST0, abs_value);
}
