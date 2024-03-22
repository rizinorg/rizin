// SPDX-FileCopyrightText: 2024 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <msp430/msp430_disas.h>

#include <rz_il/rz_il_opbuilder_begin.h>

RZ_OWN RzILOpBitVector *abs_addr_from_rel_addr(RzILOpBitVector *curr_pc, st16 rel_addr) {
	return ADD(curr_pc, S16(rel_addr));
}

RzILOpBool *mk_jne_cond(RzILOpBitVector *curr_sr) {
	// test if the Z bit in the SR register is 0
	return IS_ZERO(LOGAND(curr_sr, U16(2)));
}

RzILOpBool *mk_jnc_cond(RzILOpBitVector *curr_sr) {
	// test if the C bit in the SR register is 0
	return IS_ZERO(LOGAND(curr_sr, U16(1)));
}

RzILOpBool *mk_jn_cond(RzILOpBitVector *curr_sr) {
	// test if the N flag in the SR register is 1
	return EQ(LOGAND(curr_sr, U16(4)), U16(4));
}

RzILOpBool *mk_jge_cond(RzILOpBitVector *curr_sr) {
	int mask = 4 | (1 << 8);
	RzILOpBitVector *nv = LOGAND(curr_sr, U16(mask));
	// test if both the N and V flags are set or reset
	return OR(IS_ZERO(nv), EQ(DUP(nv), U16(mask)));
}

#include <rz_il/rz_il_opbuilder_end.h>

typedef RzILOpBool *(*JmpConditionConstructor)(RzILOpBitVector *curr_sr);

JmpConditionConstructor jmp_condition_constructors[] = {
	[MSP430_JNE] = mk_jne_cond,
	[MSP430_JEQ] = mk_jne_cond, // invert by switching the THEN and ELSE
	[MSP430_JNC] = mk_jnc_cond,
	[MSP430_JC] = mk_jnc_cond, // invert by switching the THEN and ELSE
	[MSP430_JN] = mk_jn_cond,
	[MSP430_JGE] = mk_jge_cond,
	[MSP430_JL] = mk_jge_cond // invert by switching the THEN and ELSE
};

enum jmp_trigger {
	JMP_THEN,
	JMP_ELSE
};

enum jmp_trigger jmp_condition_triggers[] = {
	[MSP430_JNE] = JMP_THEN,
	[MSP430_JEQ] = JMP_ELSE,
	[MSP430_JNC] = JMP_THEN,
	[MSP430_JC] = JMP_ELSE,
	[MSP430_JN] = JMP_THEN,
	[MSP430_JGE] = JMP_THEN,
	[MSP430_JL] = JMP_ELSE
};
