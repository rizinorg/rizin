// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file il_ops.c
 *
 * Contains the IL implementations for x86 instructions.
 *
 * References:
 *  - https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
 */

#include "common.h"
#include "x86/x86_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * ======== INSTRUCTION DOCUMENTATION FORMAT ========
 *
 * Instruction mnemonic
 * Description
 * | Opcode | 64-bit | Compat/Leg mode
 */

/**
 * \brief Invalid instruction
 */
IL_LIFTER(invalid) {
	return NULL;
}

/**
 * \brief Unimplemented instruction
 */
IL_LIFTER(unimpl) {
	return EMPTY();
}

/* 8086/8088/80186/80286/80386/80486 instructions*/

/**
 * AAA
 * ASCII adjust AL after addition
 * 37 | Invalid | Valid
 */
IL_LIFTER(aaa) {
	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, VARG(EFLAGS(AF)));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, ADD(x86_il_get_reg(X86_REG_AX), U16(0x106)));
	RzILOpEffect *set_af = SETG(EFLAGS(AF), IL_TRUE);
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), IL_TRUE);
	RzILOpEffect *true_cond = SEQ3(set_ax, set_af, set_cf);

	set_af = SETG(EFLAGS(AF), IL_FALSE);
	set_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *false_cond = SEQ2(set_af, set_cf);

	RzILOpEffect *final_cond = BRANCH(cond, true_cond, false_cond);
	RzILOpEffect *set_al = x86_il_set_reg(X86_REG_AL, LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f)));

	return SEQ2(final_cond, set_al);
}

/**
 * AAD  imm8
 * Adjust AX before division to number base imm8
 * D5 ib | Invalid | Valid
 */
IL_LIFTER(aad) {

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *temp_ah = SETL("temp_ah", x86_il_get_reg(X86_REG_AH));

	RzILOpPure *imm;
	if (ins->structure->op_count == 0) {
		// Use base 10 if none specified
		imm = SN(8, 0x0a);
	} else {
		imm = x86_il_get_op(0);
	}

	RzILOpPure *adjusted = ADD(VARL("temp_al"), MUL(VARL("temp_ah"), imm));
	adjusted = LOGAND(adjusted, U8(0xff));
	RzILOpEffect *adjusted_set = SETL("adjusted", adjusted);

	RzILOpEffect *set_flags = x86_il_set_result_flags(VARL("adjusted"));

	return SEQ6(temp_al, temp_ah, adjusted_set, x86_il_set_reg(X86_REG_AL, VARL("adjusted")), x86_il_set_reg(X86_REG_AH, U8(0)), set_flags);
}

/**
 * AAM  imm8
 * Adjust AX after multiply to number base imm8
 * D4 ib | Invalid | Valid
 */
IL_LIFTER(aam) {

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));

	RzILOpPure *imm;
	if (ins->structure->op_count == 0) {
		imm = SN(8, 0xa);
	} else {
		imm = x86_il_get_op(0);
	}

	RzILOpEffect *ah = x86_il_set_reg(X86_REG_AH, DIV(VARL("temp_al"), imm));
	RzILOpEffect *adjusted = SETL("adjusted", MOD(VARL("temp_al"), DUP(imm)));
	RzILOpEffect *al = x86_il_set_reg(X86_REG_AL, VARL("adjusted"));
	RzILOpEffect *set_flags = x86_il_set_result_flags(VARL("adjusted"));

	return SEQ5(temp_al, ah, adjusted, al, set_flags);
}

/**
 * AAS
 * ASCII adjust AL after subtraction
 * 3F | Invalid | Valid
 */
IL_LIFTER(aas) {

	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, VARG(EFLAGS(AF)));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, SUB(x86_il_get_reg(X86_REG_AX), U16(0x6)));
	RzILOpEffect *set_ah = x86_il_set_reg(X86_REG_AH, SUB(x86_il_get_reg(X86_REG_AH), U8(0x1)));
	RzILOpEffect *set_af = SETG(EFLAGS(AF), IL_TRUE);
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), IL_TRUE);
	RzILOpEffect *true_cond = SEQ4(set_ax, set_ah, set_af, set_cf);

	set_af = SETG(EFLAGS(AF), IL_FALSE);
	set_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *false_cond = SEQ2(set_af, set_cf);

	RzILOpEffect *final_cond = BRANCH(cond, true_cond, false_cond);
	RzILOpEffect *set_al = x86_il_set_reg(X86_REG_AL, LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f)));

	return SEQ2(final_cond, set_al);
}

/**
 * ADC  dest, src
 * (ADC family of instructions)
 * Add with carry
 * dest = dest + src + CF
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(adc) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_op(1));
	RzILOpPure *cf = VARG(EFLAGS(CF));

	RzILOpEffect *sum = SETL("sum", ADD(ADD(VARL("op1"), VARL("op2")), BOOL_TO_BV(cf, ins->structure->operands[0].size * BITS_PER_BYTE)));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("sum"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("sum"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("sum"), VARL("op1"), VARL("op2"), true);

	return SEQ6(op1, op2, sum, set_dest, set_res_flags, set_arith_flags);
}

/**
 * ADD  dest, src
 * (ADD family of instructions)
 * Add
 * dest = dest + src
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(add) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_op(1));
	RzILOpEffect *sum = SETL("sum", ADD(VARL("op1"), VARL("op2")));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("sum"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("sum"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("sum"), VARL("op1"), VARL("op2"), true);

	return SEQ6(op1, op2, sum, set_dest, set_res_flags, set_arith_flags);
}

/**
 * AND  dest, src
 * (AND family of instructions)
 * Logical and
 * dest = dest & src
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(and) {
	RzILOpPure *op1 = x86_il_get_op(0);
	RzILOpPure *op2 = x86_il_get_op(1);
	RzILOpEffect *and = SETL("and_", LOGAND(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("and_"));
	RzILOpEffect *clear_of = SETG(EFLAGS(OF), IL_FALSE);
	RzILOpEffect *clear_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("and_"));

	return SEQ5(and, set_dest, clear_of, clear_cf, set_res_flags);
}

/**
 * BSF
 * Bit scan forward
 * Encoding: RM
 */
IL_LIFTER(bsf) {
	RzILOpPure *src = x86_il_get_op(1);

	RzILOpEffect *set_zf = SETG(EFLAGS(ZF), IL_FALSE);

	uint8_t op_size = ins->structure->operands[0].size * BITS_PER_BYTE;
	RzILOpEffect *tmp_var = SETL("tmpvar", UN(op_size, 0));

	RzILOpEffect *calc = REPEAT(INV(LSB(SHIFTR0(src, VARL("tmpvar")))), SETL("tmpvar", ADD(VARL("tmpvar"), UN(op_size, 1))));

	RzILOpEffect *calc_res = SEQ3(set_zf, tmp_var, calc);
	RzILOpPure *res = VARL("tmpvar");

	return BRANCH(IS_ZERO(DUP(src)), SETG(EFLAGS(ZF), IL_TRUE), SEQ2(calc_res, x86_il_set_op(0, res)));
}

/**
 * CBW
 * Convert byte to word
 * 98 | Valid | Valid
 */
IL_LIFTER(cbw) {
	/* The UNSIGNED(16, ...) cast is useless in case of 32 bits,
	but removing it will cause issues for 16-bit */
	return x86_il_set_reg(X86_REG_AX, UNSIGNED(16, x86_il_get_reg(X86_REG_AL)));
}

/**
 * CLC
 * Clear carry flag
 * F8 | Valid | Valid
 */
IL_LIFTER(clc) {
	return SETG(EFLAGS(CF), IL_FALSE);
}

/**
 * CLD
 * Clear direction flag
 * FC | Valid | Valid
 */
IL_LIFTER(cld) {
	return SETG(EFLAGS(DF), IL_FALSE);
}

/**
 * CLI
 * Clear interrupt flag
 * FA | Valid | Valid
 */
IL_LIFTER(cli) {
	return SETG(EFLAGS(IF), IL_FALSE);
}

/**
 * CMC
 * Complement carry flag
 * F5 | Valid | Valid
 */
IL_LIFTER(cmc) {
	return SETG(EFLAGS(CF), INV(VARG(EFLAGS(CF))));
}

/**
 * CMP
 * (CMP family of instructions)
 * Compare two operands
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(cmp) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));

	RzILOpPure *second = x86_il_get_op(1);
	RzILOpEffect *op2 = SETL("op2", second);

	RzILOpEffect *sub = SETL("sub", SUB(VARL("op1"), VARL("op2")));
	RzILOpEffect *arith = x86_il_set_arithmetic_flags(VARL("sub"), VARL("op1"), VARL("op2"), false);
	RzILOpEffect *res = x86_il_set_result_flags(VARL("sub"));

	return SEQ5(op1, op2, sub, arith, res);
}

RzILOpEffect *x86_il_cmp_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	if (analysis->bits == 64) {
		X86Reg mem_reg1 = X86_REG_RSI;
		X86Reg mem_reg2 = X86_REG_RDI;
		ut8 mem_size = 64;

		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg1 = X86_REG_ESI;
			mem_reg2 = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpEffect *src1 = SETL("_src1", LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg1) : UNSIGNED(64, x86_il_get_reg(mem_reg1)))));
		RzILOpEffect *src2 = SETL("_src2", LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg2) : UNSIGNED(64, x86_il_get_reg(mem_reg2)))));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_src1"), VARL("_src2")));

		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_src1"), VARL("_src2"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = SEQ2(x86_il_set_reg(mem_reg1, ADD(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, ADD(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *decrement = SEQ2(x86_il_set_reg(mem_reg1, SUB(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, SUB(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));

		return SEQ6(src1, src2, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	} else {
		X86Reg mem_reg1 = X86_REG_ESI;
		X86Reg mem_reg2 = X86_REG_EDI;
		ut8 mem_size = 32;

		/* Address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg1 = X86_REG_SI;
			mem_reg2 = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem1 = {
			.base = mem_reg1,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_DS
		};
		X86Mem src_mem2 = {
			.base = mem_reg2,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_ES
		};

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpEffect *src1 = SETL("_src1", LOADW(size, x86_il_get_memaddr(src_mem1)));
		RzILOpEffect *src2 = SETL("_src2", LOADW(size, x86_il_get_memaddr(src_mem2)));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_src1"), VARL("_src2")));

		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_src1"), VARL("_src2"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = SEQ2(x86_il_set_reg(mem_reg1, ADD(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, ADD(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *decrement = SEQ2(x86_il_set_reg(mem_reg1, SUB(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, SUB(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));

		return SEQ6(src1, src2, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), increment, decrement));
	}
}

RzILOpPure *get_cmov_cond(X86InsMnem ins) {
	switch (ins) {
	case X86_INS_CMOVA:
		/* Same as CMOVNBE */
		/* CF = 0 and ZF = 0 */
		return AND(INV(VARG(EFLAGS(CF))), INV(VARG(EFLAGS(ZF))));
	case X86_INS_CMOVAE:
		/* Same as CMOVNB, CMOVNC */
		/* CF = 0 */
		return INV(VARG(EFLAGS(CF)));
	case X86_INS_CMOVB:
		/* Same as CMOVC, CMOVNAE */
		/* CF = 1 */
		return VARG(EFLAGS(CF));
	case X86_INS_CMOVBE:
		/* Same as CMOVNA */
		/* CF = 1 or ZF = 1*/
		return OR(VARG(EFLAGS(CF)), VARG(EFLAGS(ZF)));
	case X86_INS_CMOVE:
		/* Same as CMOVZ */
		/* ZF = 1 */
		return VARG(EFLAGS(ZF));
	case X86_INS_CMOVG:
		/* Same as CMOVNLE */
		/* ZF = 0 and SF = OF */
		return AND(INV(VARG(EFLAGS(ZF))), INV(XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF)))));
	case X86_INS_CMOVGE:
		/* Same CMOVNL */
		/* SF = OF */
		return INV(XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF))));
	case X86_INS_CMOVL:
		/* SF != OF */
		return XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF)));
	case X86_INS_CMOVLE:
		/* Same as CMOVNG */
		/* ZF = 1 or SF != OF */
		return OR(VARG(EFLAGS(ZF)), XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF))));
	case X86_INS_CMOVNE:
		/* Same as CMOVNZ */
		/* ZF = 0 */
		return INV(VARG(EFLAGS(ZF)));
	case X86_INS_CMOVNO:
		/* OF = 0 */
		return INV(VARG(EFLAGS(OF)));
	case X86_INS_CMOVNP:
		/* Same as CMOVPO */
		/* PF = 0 */
		return INV(VARG(EFLAGS(PF)));
	case X86_INS_CMOVNS:
		/* SF = 0 */
		return INV(VARG(EFLAGS(SF)));
	case X86_INS_CMOVO:
		/* OF = 1 */
		return VARG(EFLAGS(OF));
	case X86_INS_CMOVP:
		/* Same as CMOVPE */
		/* PF = 1 */
		return VARG(EFLAGS(PF));
	case X86_INS_CMOVS:
		/* SF = 1 */
		return VARG(EFLAGS(SF));
	default:
		rz_warn_if_reached();
	}

	return NULL;
}

/**
 * CMOVcc
 * (Conditional move family of instructions)
 * Conditional move (based on flags)
 * Encoding: RM
 */
IL_LIFTER(cmov) {
	RzILOpPure *cond = get_cmov_cond(ins->mnem);

	return BRANCH(cond, x86_il_set_op(0, x86_il_get_op(1)), NOP());
}

/**
 * CMPSB
 * Compare byte
 * A6 | Valid | Valid
 */
IL_LIFTER(cmpsb) {
	return x86_il_cmp_helper(ins, pc, analysis, 8);
}

/**
 * CMPSW
 * Compare word
 * A7 | Valid | Valid
 */
IL_LIFTER(cmpsw) {
	return x86_il_cmp_helper(ins, pc, analysis, 16);
}

/**
 * CMPSD
 * Compare dword
 * ZO
 */
IL_LIFTER(cmpsd) {
	return x86_il_cmp_helper(ins, pc, analysis, 32);
}

/**
 * CMPSQ
 * Compare quadword
 * ZO
 */
IL_LIFTER(cmpsq) {
	return x86_il_cmp_helper(ins, pc, analysis, 64);
}

/**
 * DAA
 * Decimal adjust AL after addition
 * 27 | Invalid | Valid
 */
IL_LIFTER(daa) {

	RzILOpEffect *old_al = SETL("old_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *old_cf = SETL("old_cf", VARG(EFLAGS(CF)));

	RzILOpEffect *set_cf = SETL(EFLAGS(CF), IL_FALSE);

	RzILOpBool *cond = UGT(LOGAND(x86_il_get_reg(X86_REG_AL), UN(8, 0xf)), UN(8, 9));
	cond = OR(cond, VARG(EFLAGS(AF)));

	RzILOpEffect *set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *sum = SETL("_sum", ADD(VARL("_al"), UN(8, 6)));
	RzILOpEffect *true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));
	RzILOpPure *new_cf = OR(VARL("old_cf"), x86_il_is_sub_borrow(VARL("_sum"), VARL("_al"), UN(8, 6)));

	RzILOpEffect *ret = SEQ4(old_al, old_cf, set_cf, BRANCH(cond, SEQ3(true_cond, SETG(EFLAGS(CF), new_cf), SETG(EFLAGS(AF), IL_TRUE)), SETG(EFLAGS(AF), IL_FALSE)));

	cond = OR(UGT(VARL("old_al"), UN(8, 0x99)), VARL("old_cf"));

	set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	sum = SETL("_sum", ADD(VARL("_al"), UN(8, 0x60)));
	true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));

	ret = SEQ3(ret, BRANCH(cond, SEQ2(true_cond, SETG(EFLAGS(CF), IL_TRUE)), SETG(EFLAGS(CF), IL_FALSE)), x86_il_set_result_flags(x86_il_get_reg(X86_REG_AL)));

	return ret;
}

/**
 * DAS
 * Decimal adjust AL after subtraction
 * 2F | Invalid | Valid
 */
IL_LIFTER(das) {

	RzILOpEffect *old_al = SETL("old_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *old_cf = SETL("old_cf", VARG(EFLAGS(CF)));

	RzILOpEffect *set_cf = SETL(EFLAGS(CF), IL_FALSE);

	RzILOpBool *cond = UGT(LOGAND(x86_il_get_reg(X86_REG_AL), UN(8, 0xf)), UN(8, 9));
	cond = OR(cond, VARG(EFLAGS(AF)));

	RzILOpEffect *set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *sum = SETL("_sum", SUB(VARL("_al"), UN(8, 6)));
	RzILOpEffect *true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));
	RzILOpPure *new_cf = OR(VARL("old_cf"), x86_il_is_sub_borrow(VARL("_sum"), VARL("_al"), UN(8, 6)));

	RzILOpEffect *ret = SEQ4(old_al, old_cf, set_cf, BRANCH(cond, SEQ3(true_cond, SETG(EFLAGS(CF), new_cf), SETG(EFLAGS(AF), IL_TRUE)), SETG(EFLAGS(AF), IL_FALSE)));

	cond = OR(UGT(VARL("old_al"), UN(8, 0x99)), VARL("old_cf"));

	set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	sum = SETL("_sum", SUB(VARL("_al"), UN(8, 0x60)));
	true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));

	ret = SEQ3(ret, BRANCH(cond, SEQ2(true_cond, SETG(EFLAGS(CF), IL_TRUE)), NOP()), x86_il_set_result_flags(x86_il_get_reg(X86_REG_AL)));

	return ret;
}

/**
 * DEC
 * Decrement by 1
 * Operand can be a memory address or a register
 */
IL_LIFTER(dec) {
	RzILOpEffect *op = SETL("_op", x86_il_get_op(0));
	RzILOpEffect *dec = SETL("_dec", SUB(VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1)));

	RzILOpEffect *set_result = x86_il_set_op(0, VARL("_dec"));
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_dec"));

	RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags_except_cf(VARL("_dec"), VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1), false);

	return SEQ5(op, dec, set_result, res_flags, arith_flags);
}

/**
 * DIV
 * Unsigned division
 * One operand (memory address), used as the divisor
 */
IL_LIFTER(div) {
	RzILOpEffect *ret = NULL;

	switch (ins->structure->operands[0].size) {
	case 1: {
		/* Word/Byte operation */
		RzILOpEffect *ax = SETL("_ax", x86_il_get_reg(X86_REG_AX));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(8, DIV(VARL("_ax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(8, 0xff));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AL, VARL("_temp")), x86_il_set_reg(X86_REG_AH, MOD(VARL("_ax"), VARL("_src"))));

		ret = SEQ3(ax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 2: {
		/* Doubleword/Word operation */
		RzILOpEffect *dxax = SETL("_dxax", LOGOR(SHIFTL0(UNSIGNED(32, x86_il_get_reg(X86_REG_DX)), UN(8, 16)), UNSIGNED(32, x86_il_get_reg(X86_REG_AX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(16, DIV(VARL("_dxax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(16, 0xffff));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, MOD(VARL("_dxax"), VARL("_src"))));

		ret = SEQ3(dxax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 4: {
		/* Quadword/Doubleword operation */
		RzILOpEffect *edxeax = SETL("_edxeax", LOGOR(SHIFTL0(UNSIGNED(64, x86_il_get_reg(X86_REG_EDX)), UN(8, 32)), UNSIGNED(64, x86_il_get_reg(X86_REG_EAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(32, DIV(VARL("_edxeax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(32, 0xffffffffULL));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, MOD(VARL("_edxeax"), VARL("_src"))));

		ret = SEQ3(edxeax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 8: {
		/* Doublequadword/Quadword operation */
		RzILOpEffect *rdxrax = SETL("_rdxrax", LOGOR(SHIFTL0(UNSIGNED(128, x86_il_get_reg(X86_REG_RDX)), UN(8, 64)), UNSIGNED(128, x86_il_get_reg(X86_REG_RAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(64, DIV(VARL("_rdxrax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(64, 0xffffffffffffffffULL));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, MOD(VARL("_rdxrax"), VARL("_src"))));

		ret = SEQ3(rdxrax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	default:
		RZ_LOG_ERROR("RzIL: x86: DIV: Invalid operand size\n");
		return NULL;
	}

	/* We need the divisor to be as wide as the operand, since the sizes of the dividend and the divisor need to match */
	RzILOpEffect *op = SETL("_src", UNSIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_op(0)));

	/* Check if the operand is zero, return NULL if it is (to avoid divide by zero) */
	return SEQ2(op, BRANCH(IS_ZERO(VARL("_src")), NULL, ret));
}

/**
 * ESC
 * Escape to coprocessor instruction set
 * To be used with floating-point unit
 * Not necessary to implement for binary analysis
 */

/**
 * HLT
 * Enter HALT state
 */
IL_LIFTER(hlt) {
	/* It just jumps to an empty goto label "halt" */
	return GOTO("halt");
}

void label_halt(RzILVM *vm, RzILOpEffect *op) {
	// empty "halt" label
	return;
}

/**
 * IDIV
 * Signed division
 * One operand (memory address), used as the divisor
 */
IL_LIFTER(idiv) {
	RzILOpEffect *ret = NULL;

	switch (ins->structure->operands[0].size) {
	case 1: {
		/* Word/Byte operation */
		RzILOpEffect *ax = SETL("_ax", x86_il_get_reg(X86_REG_AX));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(8, SDIV(VARL("_ax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(8, 0x7f)), SLT(VARL("_temp"), UN(8, 0x80)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AL, VARL("_temp")), x86_il_set_reg(X86_REG_AH, SMOD(VARL("_ax"), VARL("_src"))));

		ret = SEQ3(ax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 2: {
		/* Doubleword/Word operation */
		RzILOpEffect *dxax = SETL("_dxax", LOGOR(SHIFTL0(UNSIGNED(32, x86_il_get_reg(X86_REG_DX)), UN(8, 16)), UNSIGNED(32, x86_il_get_reg(X86_REG_AX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(16, SDIV(VARL("_dxax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(16, 0x7fff)), SLT(VARL("_temp"), UN(16, 0x8000)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, SMOD(VARL("_dxax"), VARL("_src"))));

		ret = SEQ3(dxax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 4: {
		/* Quadword/Doubleword operation */
		RzILOpEffect *edxeax = SETL("_edxeax", LOGOR(SHIFTL0(UNSIGNED(64, x86_il_get_reg(X86_REG_EDX)), UN(8, 32)), UNSIGNED(64, x86_il_get_reg(X86_REG_EAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(32, SDIV(VARL("_edxeax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(32, 0x7fffffffULL)), SLT(VARL("_temp"), UN(32, 0x80000000ULL)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, SMOD(VARL("_edxeax"), VARL("_src"))));

		ret = SEQ3(edxeax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 8: {
		/* Doublequadword/Quadword operation */
		RzILOpEffect *rdxrax = SETL("_rdxrax", LOGOR(SHIFTL0(UNSIGNED(128, x86_il_get_reg(X86_REG_EDX)), UN(8, 64)), UNSIGNED(128, x86_il_get_reg(X86_REG_EAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(64, SDIV(VARL("_rdxrax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(64, 0x7fffffffffffffffULL)), SLT(VARL("_temp"), UN(64, 0x8000000000000000ULL)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, SMOD(VARL("_rdxrax"), VARL("_src"))));

		ret = SEQ3(rdxrax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	default:
		RZ_LOG_ERROR("RzIL: x86: IDIV: Invalid operand size\n");
		return NULL;
	}

	/* We need the divisor to be as wide as the operand, since the sizes of the dividend and the divisor need to match */
	RzILOpEffect *op = SETL("_src", UNSIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_op(0)));

	/* Check if the operand is zero, return NULL if it is (to avoid divide by zero) */
	return SEQ2(op, BRANCH(IS_ZERO(VARL("_src")), NULL, ret));
}

/**
 * IMUL
 * Signed multiply
 * Three different operand number:
 *  - One operand (Encoding: M)
 *  - Two operands (Encoding: RM)
 *  - Three operands (Encoding: RMI)
 */
IL_LIFTER(imul) {
	switch (ins->structure->op_count) {
	case 1: {
		switch (ins->structure->operands[0].size) {
		case 1: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(16, x86_il_get_reg(X86_REG_AL)), SIGNED(16, x86_il_get_op(0))));
			RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, VARL("_tmp_xp"));

			/* Check if the result fits in a byte */
			RzILOpPure *cond = EQ(SIGNED(16, UNSIGNED(8, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ3(tmp_xp, set_ax, BRANCH(cond, true_branch, false_branch));
		}
		case 2: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(32, x86_il_get_reg(X86_REG_AX)), SIGNED(32, x86_il_get_op(0))));
			RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, UNSIGNED(16, VARL("_tmp_xp")));
			RzILOpEffect *set_dx = x86_il_set_reg(X86_REG_DX, UNSIGNED(32, SHIFTR0(VARL("_tmp_xp"), UN(8, 16))));

			/* Check if the result fits in a word */
			RzILOpPure *cond = EQ(SIGNED(32, UNSIGNED(16, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ4(tmp_xp, set_ax, set_dx, BRANCH(cond, true_branch, false_branch));
		}
		case 4: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(64, x86_il_get_reg(X86_REG_EAX)), SIGNED(64, x86_il_get_op(0))));
			RzILOpEffect *set_eax = x86_il_set_reg(X86_REG_EAX, UNSIGNED(32, VARL("_tmp_xp")));
			RzILOpEffect *set_edx = x86_il_set_reg(X86_REG_EDX, UNSIGNED(32, SHIFTR0(VARL("_tmp_xp"), UN(8, 32))));

			/* Check if the result fits in a doubleword */
			RzILOpPure *cond = EQ(SIGNED(64, UNSIGNED(32, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ4(tmp_xp, set_eax, set_edx, BRANCH(cond, true_branch, false_branch));
		}
		case 8: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(128, x86_il_get_reg(X86_REG_RAX)), SIGNED(128, x86_il_get_op(0))));
			RzILOpEffect *set_rax = x86_il_set_reg(X86_REG_RAX, UNSIGNED(64, VARL("_tmp_xp")));
			RzILOpEffect *set_rdx = x86_il_set_reg(X86_REG_RDX, UNSIGNED(64, SHIFTR0(VARL("_tmp_xp"), UN(8, 64))));

			/* Check if the result fits in a quadword */
			RzILOpPure *cond = EQ(SIGNED(128, UNSIGNED(64, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ4(tmp_xp, set_rax, set_rdx, BRANCH(cond, true_branch, false_branch));
		}
		default:
			RZ_LOG_ERROR("RzIL: x86: IMUL: Invalid operand size\n");
			return NULL;
		}
	}
	case 2: {
		RzILOpEffect *dest = SETL("_dest", x86_il_get_op(0));
		RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, VARL("_dest")), SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_op(1))));
		RzILOpEffect *set_dest = SETL("_dest", UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE, VARL("_tmp_xp")));
		RzILOpEffect *set_operand = x86_il_set_op(0, VARL("_dest"));

		/* Check if the result fits in the destination */
		RzILOpPure *cond = EQ(SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, VARL("_dest")), VARL("_tmp_xp"));
		RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
		RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

		return SEQ5(dest, tmp_xp, set_dest, set_operand, BRANCH(cond, true_branch, false_branch));
	}
	case 3: {
		RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(ins->structure->operands[1].size * 2 * BITS_PER_BYTE, x86_il_get_op(1)), SIGNED(ins->structure->operands[1].size * 2 * BITS_PER_BYTE, x86_il_get_op(2))));
		RzILOpEffect *set_dest = SETL("_dest", UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE, VARL("_tmp_xp")));
		RzILOpEffect *set_operand = x86_il_set_op(0, VARL("_dest"));

		/* Check if the result fits in the destination */
		RzILOpPure *cond = EQ(SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, VARL("_dest")), VARL("_tmp_xp"));
		RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
		RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

		return SEQ4(tmp_xp, set_dest, set_operand, BRANCH(cond, true_branch, false_branch));
	}
	default:
		RZ_LOG_ERROR("RzIL: x86: IMUL: Invalid operand count\n");
		return NULL;
	}

	return NULL;
}

/**
 * IN
 * Input from port
 * Encodings: I, ZO
 */
IL_LIFTER(in) {
	/* It just jumps to an empty goto label "port" */
	return GOTO("port");
}

void label_port(RzILVM *vm, RzILOpEffect *op) {
	// empty "port" label
	return;
}

/**
 * INC
 * Increment by 1
 * Encodings: M, O
 */
IL_LIFTER(inc) {
	RzILOpEffect *op = SETL("_op", x86_il_get_op(0));
	RzILOpEffect *result = SETL("_result", ADD(VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1)));
	RzILOpEffect *set_result = x86_il_set_op(0, VARL("_result"));

	RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags_except_cf(VARL("_result"), VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1), true);
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_result"));

	return SEQ5(op, result, set_result, arith_flags, res_flags);
}

/**
 * INT
 * Call to interrupt procedure
 * Encodings: I, ZO
 */
IL_LIFTER(int) {
	/* For now, it just jumps to an empty goto label "int" */
	return GOTO("int");
}

void label_int(RzILVM *vm, RzILOpEffect *op) {
	// empty "int" label
	return;
}

/**
 * INTO
 * Call to interrupt if overflow flag set
 */
IL_LIFTER(into) {
	return BRANCH(VARG(EFLAGS(OF)), GOTO("int"), NOP());
}

// TODO: Implement IRET
/**
 * IRET
 * Return from interrupt
 */

#define JUMP_IL() \
	do { \
		RzILOpPure *jmp_addr = UN(analysis->bits, ins->structure->operands[0].imm); \
		if (ins->structure->operands[0].size == 16 && analysis->bits != 64) { \
			jmp_addr = LOGAND(jmp_addr, UN(analysis->bits, 0x0000ffff)); \
		} \
		return BRANCH(cond, JMP(jmp_addr), NOP()); \
	} while (0)

/**
 * JA
 * Jump if above (CF = 0 and ZF = 0)
 * Encoding: D
 */
IL_LIFTER(ja) {
	RzILOpBool *cond = AND(INV(VARG(EFLAGS(CF))), INV(VARG(EFLAGS(ZF))));
	JUMP_IL();
}

/**
 * JAE
 * Jump if above or equal (CF = 0)
 * Encoding: D
 */
IL_LIFTER(jae) {
	RzILOpBool *cond = INV(VARG(EFLAGS(CF)));
	JUMP_IL();
}

/**
 * JB
 * Jump if below (CF = 1)
 * Encoding: D
 */
IL_LIFTER(jb) {
	RzILOpBool *cond = VARG(EFLAGS(CF));
	JUMP_IL();
}

/**
 * JBE
 * Jump if below or equal (CF = 1 or ZF = 1)
 * Encoding: D
 */
IL_LIFTER(jbe) {
	RzILOpBool *cond = OR(VARG(EFLAGS(CF)), VARG(EFLAGS(ZF)));
	JUMP_IL();
}

/**
 * JCXZ
 * Jump if CX register is zero (CX = 0)
 * Encoding: D
 */
IL_LIFTER(jcxz) {
	RzILOpBool *cond = IS_ZERO(x86_il_get_reg(X86_REG_CX));
	JUMP_IL();
}

/**
 * JECXZ
 * Jump if ECX register is zero (ECX = 0)
 * Encoding: D
 */
IL_LIFTER(jecxz) {
	RzILOpBool *cond = IS_ZERO(x86_il_get_reg(X86_REG_ECX));
	JUMP_IL();
}

/**
 * JRCXZ
 * Jump if RCX register is zero (RCX = 0)
 * Encoding: D
 */
IL_LIFTER(jrcxz) {
	RzILOpBool *cond = IS_ZERO(x86_il_get_reg(X86_REG_RCX));
	JUMP_IL();
}

/**
 * JE
 * Jump if equal (ZF = 1)
 * Encoding: D
 */
IL_LIFTER(je) {
	RzILOpBool *cond = VARG(EFLAGS(ZF));
	JUMP_IL();
}

/**
 * JG
 * Jump if greater (ZF = 0 and SF = OF)
 * Encoding: D
 */
IL_LIFTER(jg) {
	RzILOpBool *cond = AND(INV(VARG(EFLAGS(ZF))), INV(XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF)))));
	JUMP_IL();
}

/**
 * JGE
 * Jump if greater or equal (SF = OF)
 * Encoding: D
 */
IL_LIFTER(jge) {
	RzILOpBool *cond = INV(XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF))));
	JUMP_IL();
}

/**
 * JL
 * Jump if less or equal (SF != OF)
 * Encoding: D
 */
IL_LIFTER(jl) {
	RzILOpBool *cond = XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF)));
	JUMP_IL();
}

/**
 * JLE
 * Jump if less or equal (ZF = 1 or SF != OF)
 * Encoding: D
 */
IL_LIFTER(jle) {
	RzILOpBool *cond = OR(VARG(EFLAGS(ZF)), XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF))));
	JUMP_IL();
}

/**
 * JNE
 * Jump if not equal (ZF = 0)
 * Encoding: D
 */
IL_LIFTER(jne) {
	RzILOpBool *cond = INV(VARG(EFLAGS(ZF)));
	JUMP_IL();
}

/**
 * JNO
 * Jump if not overflow (OF = 0)
 * Encoding: D
 */
IL_LIFTER(jno) {
	RzILOpBool *cond = INV(VARG(EFLAGS(OF)));
	JUMP_IL();
}

/**
 * JNP
 * Jump if not parity (PF = 0)
 * Encoding: D
 */
IL_LIFTER(jnp) {
	RzILOpBool *cond = INV(VARG(EFLAGS(PF)));
	JUMP_IL();
}

/**
 * JNS
 * Jump if not sign (SF = 0)
 * Encoding: D
 */
IL_LIFTER(jns) {
	RzILOpBool *cond = INV(VARG(EFLAGS(SF)));
	JUMP_IL();
}

/**
 * JO
 * Jump if overflow (OF = 1)
 * Encoding: D
 */
IL_LIFTER(jo) {
	RzILOpBool *cond = VARG(EFLAGS(OF));
	JUMP_IL();
}

/**
 * JP
 * Jump if parity (PF = 1)
 * Encoding: D
 */
IL_LIFTER(jp) {
	RzILOpBool *cond = VARG(EFLAGS(PF));
	JUMP_IL();
}

/**
 * JS
 * Jump if sign (SF = 1)
 * Encoding: D
 */
IL_LIFTER(js) {
	RzILOpBool *cond = VARG(EFLAGS(SF));
	JUMP_IL();
}

#undef JUMP_IL

/**
 * JMP
 * Jump
 * Relative jump or absolute jump decided by the encoding of the operands
 * Possible encodings:
 *  - S (Segment + absolute address)
 *  - D (Offset/Displacement)
 *  - M
 */
IL_LIFTER(jmp) {
	return JMP(UNSIGNED(analysis->bits, x86_il_get_op(0)));
}

/**
 * LAHF
 * Load status flags in the AH register
 * No operands
 */
IL_LIFTER(lahf) {
	return x86_il_set_reg(X86_REG_AH, x86_il_get_flags(8));
}

/**
 * LDS
 * Load pointer using DS
 * Encoding: RM
 */
IL_LIFTER(lds) {
	return x86_il_set_op(0, x86_il_get_memaddr_segment(ins->structure->operands[1].mem, X86_REG_DS));
}

/**
 * LEA
 * Load effective address
 * Encoding: RM
 * Cast the M to R in an unsigned cast
 */
IL_LIFTER(lea) {
	return x86_il_set_op(0, UNSIGNED(ins->structure->operands[1].size * BITS_PER_BYTE, x86_il_get_memaddr(ins->structure->operands[1].mem)));
}

/**
 * LES
 * Load pointer using ES
 * Encoding: RM
 */
IL_LIFTER(les) {
	return x86_il_set_op(0, x86_il_get_memaddr_segment(ins->structure->operands[1].mem, X86_REG_ES));
}

RzILOpEffect *x86_il_lods_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	X86Reg reg;
	switch (size) {
	case 8:
		reg = X86_REG_AL;
		break;
	case 16:
		reg = X86_REG_AX;
		break;
	case 32:
		reg = X86_REG_EAX;
		break;
	case 64:
		reg = X86_REG_RAX;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	if (analysis->bits == 64) {
		X86Reg mem_reg = X86_REG_RSI;
		ut8 mem_size = 64;
		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg = X86_REG_ESI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpPure *val = LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg) : UNSIGNED(64, x86_il_get_reg(mem_reg))));
		RzILOpEffect *inc = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *dec = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *update_rsi = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		return SEQ2(x86_il_set_reg(reg, val), update_rsi);

	} else {
		X86Reg mem_reg = X86_REG_ESI;
		ut8 mem_size = 32;
		/* Address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg = X86_REG_SI;
			mem_size = 16;
		}

		X86Mem src_mem;
		src_mem.base = mem_reg;
		src_mem.disp = 0;
		src_mem.index = X86_REG_INVALID;
		src_mem.scale = 1;
		src_mem.segment = X86_REG_DS;

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpPure *val = LOADW(size, x86_il_get_memaddr(src_mem));

		RzILOpEffect *inc = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *dec = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *update_si = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		return SEQ2(x86_il_set_reg(reg, val), update_si);
	}
}

/**
 * LODSB
 * Load string byte
 * No operands
 */
IL_LIFTER(lodsb) {
	return x86_il_lods_helper(ins, pc, analysis, 8);
}

/**
 * LODSW
 * Load string word
 * No operands
 */
IL_LIFTER(lodsw) {
	return x86_il_lods_helper(ins, pc, analysis, 16);
}

/**
 * LODSD
 * Load string dword
 * No operands
 */
IL_LIFTER(lodsd) {
	return x86_il_lods_helper(ins, pc, analysis, 32);
}

/**
 * LODSQ
 * Load string quadword
 * No operands
 */
IL_LIFTER(lodsq) {
	return x86_il_lods_helper(ins, pc, analysis, 64);
}

#define LOOP_HELPER(cond) \
	do { \
		/* Will automatically be resolved to the widest CX register */ \
		X86Reg count_reg = X86_REG_RCX; \
\
		uint8_t addr_size = analysis->bits; \
		/* Check address override prefix (67H) */ \
		if (analysis->bits == 64 && ins->structure->prefix[3]) { \
			addr_size >>= 1; \
			count_reg = X86_REG_ECX; \
		} \
\
		RzILOpEffect *dec_counter = x86_il_set_reg(count_reg, SUB(x86_il_get_reg(count_reg), UN(addr_size, 1))); \
		RzILOpEffect *true_cond = JMP(UN(analysis->bits, pc + ins->structure->operands[0].imm)); \
		RzILOpEffect *branch = BRANCH(cond, true_cond, NOP()); \
\
		return SEQ2(dec_counter, branch); \
	} while (0)

/**
 * LOOP
 * Loop the following instruction
 * Encoding: D
 * Decrement count ; jump if count != 0
 */
IL_LIFTER(loop) {
	LOOP_HELPER(NON_ZERO(x86_il_get_reg(count_reg)));
}

/**
 * LOOPE
 * Loop the following instruction
 * Encoding: D
 * Decrement count ; jump if count != 0 and ZF = 1
 */
IL_LIFTER(loope) {
	LOOP_HELPER(AND(NON_ZERO(x86_il_get_reg(count_reg)), VARG(EFLAGS(ZF))));
}

/**
 * LOOPNE
 * Loop the following instruction
 * Encoding: D
 * Decrement count ; jump if count != 0 and ZF = 0
 */
IL_LIFTER(loopne) {
	LOOP_HELPER(AND(NON_ZERO(x86_il_get_reg(count_reg)), INV(VARG(EFLAGS(ZF)))));
}

/**
 * MOV
 * Move
 * Encodings:
 *  - MR
 *  - RM
 *  - FD
 *  - TD
 *  - OI
 *  - MI
 */
IL_LIFTER(mov) {
	return x86_il_set_op(0, x86_il_get_op(1));
}

RzILOpEffect *x86_il_movs_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	if (analysis->bits == 64) {
		X86Reg mem_reg1 = X86_REG_RSI;
		X86Reg mem_reg2 = X86_REG_RDI;
		ut8 mem_size = 64;

		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg1 = X86_REG_ESI;
			mem_reg2 = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpPure *val = LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg1) : UNSIGNED(64, x86_il_get_reg(mem_reg1))));
		RzILOpEffect *inc = SEQ2(x86_il_set_reg(mem_reg1, ADD(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, ADD(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *dec = SEQ2(x86_il_set_reg(mem_reg1, SUB(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, SUB(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *update = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		return SEQ2(STOREW((mem_size == 64 ? x86_il_get_reg(mem_reg2) : UNSIGNED(64, x86_il_get_reg(mem_reg2))), val), update);

	} else {
		X86Reg src_reg = X86_REG_ESI;
		X86Reg dst_reg = X86_REG_EDI;
		ut8 mem_size = 32;

		/* Address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			src_reg = X86_REG_SI;
			dst_reg = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem = {
			.base = src_reg,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_DS
		};
		X86Mem dst_mem = {
			.base = dst_reg,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_ES
		};

		RzILOpEffect *inc = SEQ2(x86_il_set_reg(src_reg, ADD(x86_il_get_reg(src_reg), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(dst_reg, ADD(x86_il_get_reg(dst_reg), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *dec = SEQ2(x86_il_set_reg(src_reg, SUB(x86_il_get_reg(src_reg), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(dst_reg, SUB(x86_il_get_reg(dst_reg), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *update = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		return SEQ2(x86_il_set_mem(dst_mem, LOADW(size, x86_il_get_memaddr(src_mem))), update);
	}
}

/**
 * MOVSB
 * Move string byte
 * No operands
 */
IL_LIFTER(movsb) {
	return x86_il_movs_helper(ins, pc, analysis, 8);
}

/**
 * MOVSW
 * Move string word
 * No operands
 */
IL_LIFTER(movsw) {
	return x86_il_movs_helper(ins, pc, analysis, 16);
}

/**
 * MOVSD
 * Move string dword
 * No operands
 */
IL_LIFTER(movsd) {
	return x86_il_movs_helper(ins, pc, analysis, 32);
}

/**
 * MOVSQ
 * Move string quadword
 * No operands
 */
IL_LIFTER(movsq) {
	return x86_il_movs_helper(ins, pc, analysis, 64);
}

/**
 * MOVSX, MOVSXD
 * Move with sign extension
 *
 * Encoding: RM
 */
IL_LIFTER(movsx) {
	return x86_il_set_op(0, SIGNED(ins->structure->operands[0].size * BITS_PER_BYTE, x86_il_get_op(1)));
}

/**
 * MOVZX
 * Move with zero extension
 * Encoding: RM
 */
IL_LIFTER(movzx) {
	return x86_il_set_op(0, UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE, x86_il_get_op(1)));
}

/**
 * MUL
 * Unsigned multiply
 * Encoding: M
 */
IL_LIFTER(mul) {
	RzILOpPure *op = UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE * 2, x86_il_get_op(0));
	RzILOpEffect *true_cond = SEQ2(SETG(EFLAGS(OF), IL_FALSE), SETG(EFLAGS(CF), IL_FALSE));
	RzILOpEffect *false_cond = SEQ2(SETG(EFLAGS(OF), IL_TRUE), SETG(EFLAGS(CF), IL_TRUE));

	switch (ins->structure->operands[0].size) {
	case 1: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(16, x86_il_get_reg(X86_REG_AL)), op));
		RzILOpEffect *ax = x86_il_set_reg(X86_REG_AX, VARL("_mul"));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(8))), true_cond, false_cond);

		return SEQ3(set, ax, flags);
	}
	case 2: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(32, x86_il_get_reg(X86_REG_AX)), op));
		RzILOpEffect *dx = x86_il_set_reg(X86_REG_DX, UNSIGNED(16, SHIFTR0(VARL("_mul"), U8(16))));
		RzILOpEffect *ax = x86_il_set_reg(X86_REG_AX, UNSIGNED(16, VARL("_mul")));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(16))), true_cond, false_cond);

		return SEQ4(set, dx, ax, flags);
	}
	case 4: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(64, x86_il_get_reg(X86_REG_EAX)), op));
		RzILOpEffect *edx = x86_il_set_reg(X86_REG_EDX, UNSIGNED(32, SHIFTR0(VARL("_mul"), U8(32))));
		RzILOpEffect *eax = x86_il_set_reg(X86_REG_EAX, UNSIGNED(32, VARL("_mul")));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(32))), true_cond, false_cond);

		return SEQ4(set, edx, eax, flags);
	}
	case 8: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(128, x86_il_get_reg(X86_REG_RAX)), op));
		RzILOpEffect *rdx = x86_il_set_reg(X86_REG_RDX, UNSIGNED(64, SHIFTR0(VARL("_mul"), U8(64))));
		RzILOpEffect *rax = x86_il_set_reg(X86_REG_RAX, UNSIGNED(64, VARL("_mul")));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(64))), true_cond, false_cond);

		return SEQ4(set, rdx, rax, flags);
	}
	}

	rz_warn_if_reached();
	rz_il_op_pure_free(op);
	rz_il_op_effect_free(true_cond);
	rz_il_op_effect_free(false_cond);
	return NULL;
}

/**
 * NEG
 * Two's complement negation
 * Encoding: M
 */
IL_LIFTER(neg) {
	RzILOpEffect *op = SETL("_op", x86_il_get_op(0));
	RzILOpEffect *cf = BRANCH(IS_ZERO(VARL("_op")), SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(CF), IL_TRUE));
	RzILOpEffect *neg = x86_il_set_op(0, NEG(VARL("_op")));

	return SEQ3(op, cf, neg);
}

/**
 * NOP
 * No operation
 * Encoding:
 *  - ZO (zero operands)
 *  - M (multi-byte nop)
 */
IL_LIFTER(nop) {
	return NOP();
}

/**
 * NOT
 * One's complement negation
 * Encoding: M
 */
IL_LIFTER(not ) {
	return x86_il_set_op(0, LOGNOT(x86_il_get_op(0)));
}

/**
 * OR
 * Logical inclusive or
 * Encoding:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(or) {
	RzILOpPure *op1 = x86_il_get_op(0);
	RzILOpPure *op2 = x86_il_get_op(1);
	RzILOpEffect * or = SETL("_or", LOGOR(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_or"));
	RzILOpEffect *clear_of = SETG(EFLAGS(OF), IL_FALSE);
	RzILOpEffect *clear_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("_or"));

	return SEQ5(or, set_dest, clear_of, clear_cf, set_res_flags);
}

/**
 * OUT
 * Output to port
 * Encodings: I, ZO
 */
IL_LIFTER(out) {
	/* It just jumps to an empty goto label "port" */
	return GOTO("port");
}

typedef struct pop_helper_t {
	RzILOpPure *val;
	RzILOpEffect *eff;
} PopHelper;

PopHelper x86_pop_helper_bits(unsigned int op_size, unsigned int bitness, ut64 pc) {
	X86Mem stack_mem;
	/* The correct register will automatically be chosen if we use RSP */
	stack_mem.base = X86_REG_RSP;
	stack_mem.disp = 0;
	stack_mem.index = X86_REG_INVALID;
	stack_mem.scale = 1;
	stack_mem.segment = X86_REG_SS;

	PopHelper ret;

	ret.val = LOADW(op_size * BITS_PER_BYTE, x86_il_get_memaddr_bits(stack_mem, bitness, pc));
	ret.eff = x86_il_set_reg_bits(X86_REG_RSP, ADD(x86_il_get_reg_bits(X86_REG_RSP, bitness, pc), UN(bitness, op_size)), bitness);

	return ret;
}

#define x86_pop_helper(op_size) x86_pop_helper_bits(op_size, analysis->bits, pc)

/**
 * POP
 * Pop a value from the stack
 * Encoding:
 *  - M
 *  - O
 *  - ZO
 */
IL_LIFTER(pop) {
	/* Ideally, we should use the stack size instead of the address size (analysis->bits),
	but there seems to be no way to do that using Capstone */
	/* Also, it is very rare to use have a different stack size and address size */
	PopHelper pop = x86_pop_helper(ins->structure->operands[0].size);
	RzILOpEffect *copy = x86_il_set_op(0, pop.val);

	return SEQ2(copy, pop.eff);
}

/**
 * POPF
 * Pop stack into FLAGS register (16 bits)
 * Encoding: ZO
 */
IL_LIFTER(popf) {
	/* This is not _completely_ accurate, but it is good enough for our purposes */
	PopHelper pop = x86_pop_helper(2 /* BYTES */);
	return SEQ2(x86_il_set_flags(pop.val, 16), pop.eff);
}

/**
 * POPFD
 * Pop stack into EFLAGS register (32 bits)
 * Encoding: ZO
 */
IL_LIFTER(popfd) {
	/* Functionally the same as POPF IL */
	PopHelper pop = x86_pop_helper(4 /* BYTES */);
	return SEQ2(x86_il_set_flags(pop.val, 32), pop.eff);
}

/**
 * POPFQ
 * Pop stack into RFLAGS register (64 bits)
 * Encoding: ZO
 */
IL_LIFTER(popfq) {
	/* Functionally the same as POPF IL */
	PopHelper pop = x86_pop_helper(8 /* BYTES */);
	return SEQ2(x86_il_set_flags(pop.val, 64), pop.eff);
}

RzILOpEffect *x86_push_helper_impl(RzILOpPure *val, unsigned int user_op_size, unsigned int bitness, const X86ILIns *ins, ut64 pc) {
	unsigned int dflag = user_op_size;
	unsigned int op_size;
	unsigned int stack_size = bitness / BITS_PER_BYTE;

	if (ins) {
		if (bitness == 64) {
			dflag = ins->structure->rex ? 8 : ins->structure->prefix[2] ? 2
										    : 4; /* in bytes */
			stack_size = 8; /* in bytes */
		} else {
			/* We use the other operand and address size if the prefix is set */
			if ((bitness == 32) ^ ins->structure->prefix[2]) {
				dflag = 4;
			} else {
				dflag = 2;
			}

			stack_size = 4;
		}
	}

	if (bitness == 64) {
		op_size = (dflag == 2) ? 2 : 8;
	} else {
		op_size = dflag;
	}

	RzILOpEffect *final_stack = SETL("final", SUB(x86_il_get_reg_bits(X86_REG_RSP, bitness, pc), UN(bitness, stack_size)));

	RzILOpEffect *ret = STOREW(VARL("final"), UNSIGNED(op_size * BITS_PER_BYTE, val));
	ret = SEQ3(final_stack, ret, x86_il_set_reg_bits(X86_REG_RSP, VARL("final"), bitness));

	return ret;
}

#define x86_push_helper(val, op_size) x86_push_helper_impl(val, op_size, analysis->bits, NULL, pc)

/**
 * CALL
 * Perform a function call
 * Encoding: D, M
 */
IL_LIFTER(call) {
	/*
	 * The following implementation is not accurate, since there are many nitty-gritties involved.
	 * Like whether the call is a near or far call, absolute or relative call, etc.
	 * Implementing it accurately will require exceptions, task switching,
	 * shadow stack, CPU internal flags, segmentation support
	 * Just pushing the current program counter is a good approximation for now
	 * shadow stack, CPU internal flags, segmentation support
	 * Just pushing the current program counter is a good approcimation for now
	 * We also need to push the code segment register in case 16 and 32 bit modes.
	 */

	RzILOpEffect *push_pc = x86_push_helper(UN(analysis->bits, pc), analysis->bits / BITS_PER_BYTE);
	return SEQ2(push_pc, JMP(x86_il_get_op(0)));
}

/**
 * PUSH
 * Push value on the stack
 * Encoding:
 *  - M
 *  - O
 *  - I
 *  - ZO
 */
IL_LIFTER(push) {
	return x86_push_helper_impl(x86_il_get_op(0), ins->structure->operands->size, analysis->bits, ins, pc);
}

/**
 * PUSHF
 * Push FLAGS register onto the stack (16 bits)
 * Encoding: ZO
 */
IL_LIFTER(pushf) {
	return x86_push_helper(x86_il_get_flags(16), 2);
}

/**
 * PUSHFD
 * Push EFLAGS register onto the stack (32 bits)
 * Encoding: ZO
 */
IL_LIFTER(pushfd) {
	return x86_push_helper(x86_il_get_flags(32), 4);
}

/**
 * PUSHFQ
 * Push RFLAGS register onto the stack (64 bits)
 * Encoding: ZO
 */
IL_LIFTER(pushfq) {
	return x86_push_helper(x86_il_get_flags(64), 8);
}

/**
 * PUSHA
 * Push all general-purpose registers (16-bits)
 * Encoding: ZO
 */
IL_LIFTER(pushaw) {
	if (analysis->bits != 16) {
		return NULL;
	}

	RzILOpEffect *temp = SETL("_sp", x86_il_get_reg(X86_REG_SP));
	RzILOpEffect *push = x86_push_helper(x86_il_get_reg(X86_REG_AX), 2);
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_CX), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_DX), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_BX), 2));
	push = SEQ2(push, x86_push_helper(VARL("_sp"), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_BP), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_SI), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_DI), 2));

	return SEQ2(temp, push);
}

/**
 * PUSHAD
 * Push all general-purpose registers (32-bits)
 * Encoding: ZO
 */
IL_LIFTER(pushal) {
	if (analysis->bits != 32) {
		return NULL;
	}

	RzILOpEffect *temp = SETL("_esp", x86_il_get_reg(X86_REG_ESP));
	RzILOpEffect *push = x86_push_helper(x86_il_get_reg(X86_REG_EAX), 4);
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_ECX), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EDX), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EBX), 4));
	push = SEQ2(push, x86_push_helper(VARL("_esp"), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EBP), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_ESI), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EDI), 4));

	return SEQ2(temp, push);
}

#define RCX_MACRO() \
	ut8 size_in_bytes = ins->structure->operands[0].size; \
	ut8 size = size_in_bytes * BITS_PER_BYTE; \
	ut8 shift_size = (size_in_bytes == 8 || (analysis->bits == 64 && ins->structure->rex)) ? 6 : 5; \
	ut8 shift_max = size + 1; \
	RzILOpEffect *pre_dest = SETL("_pre_dest", x86_il_get_op(0)); \
	RzILOpEffect *shift = NULL; \
	switch (size_in_bytes) { \
	case 1: \
		/* fall-thru */ \
	case 2: \
		shift = SETL("_shift", MOD(UNSIGNED(shift_size, x86_il_get_op_implicit(1, size_in_bytes)), UN(shift_size, shift_max))); \
		break; \
	case 4: \
		/* fall-thru */ \
	case 8: \
		shift = SETL("_shift", UNSIGNED(shift_size, x86_il_get_op_implicit(1, size_in_bytes))); \
		break; \
	default: \
		rz_warn_if_reached(); \
	}

/**
 * RCL
 * Rotate left, with carry
 * Encoding: MI, M1, MC
 */
IL_LIFTER(rcl) {
	RCX_MACRO();

	RzILOpEffect *rotated = SETL("_rotated",
		LET("_cf_dest", APPEND(BOOL_TO_BV(VARG(EFLAGS(CF)), 1), VARL("_pre_dest")),
			LOGOR(
				SHIFTL0(VARLP("_cf_dest"), VARL("_shift")),
				SHIFTR0(VARLP("_cf_dest"), SUB(UN(shift_size, shift_max), VARL("_shift"))))));

	RzILOpEffect *result = SETL("_dest", CAST(size, IL_FALSE, VARL("_rotated")));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), MSB(VARL("_rotated")));

	// if _shift == 1, OF is set to 'CF xor MSB (after rotation)'.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), XOR(VARG(EFLAGS(CF)), MSB(VARL("_dest"))));

	return SEQ7(pre_dest, shift, rotated, result, set_cf, set_of, set_dest);
}

/**
 * RCR
 * Rotate right, with carry
 * Encoding: MI, M1, MC
 */
IL_LIFTER(rcr) {
	RCX_MACRO();
	RzILOpEffect *rotated = SETL("_rotated",
		LET("_cf_dest", APPEND(BOOL_TO_BV(VARG(EFLAGS(CF)), 1), VARL("_pre_dest")),
			LOGOR(
				SHIFTR0(VARLP("_cf_dest"), VARL("_shift")),
				SHIFTL0(VARLP("_cf_dest"), SUB(UN(shift_size, shift_max), VARL("_shift"))))));

	RzILOpEffect *result = SETL("_dest", CAST(size, IL_FALSE, VARL("_rotated")));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), MSB(VARL("_rotated")));

	// if _shift == 1, OF is set to 'CF xor MSB (before rotation)'.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), XOR(VARG(EFLAGS(CF)), MSB(VARL("_pre_dest"))));

	return SEQ7(pre_dest, shift, rotated, result, set_of, set_cf, set_dest);
}

#undef RCX_MACRO

#define ROX_MACRO() \
	ut8 size_in_bytes = ins->structure->operands[0].size; \
	ut8 size = size_in_bytes * BITS_PER_BYTE; \
	ut8 shift_size = (size_in_bytes == 8 || (analysis->bits == 64 && ins->structure->rex)) ? 6 : 5; \
	ut8 shift_max = size; \
	RzILOpEffect *pre_dest = SETL("_pre_dest", x86_il_get_op(0)); \
	RzILOpEffect *shift = SETL("_shift", MOD(UNSIGNED(shift_size, x86_il_get_op_implicit(1, size_in_bytes)), UN(shift_size, shift_max)));

/**
 * ROL
 * Rotate left
 * Encoding: MI, M1, MC
 */
IL_LIFTER(rol) {
	ROX_MACRO();

	RzILOpEffect *rotated = SETL("_rotated",
		LOGOR(
			SHIFTL0(VARL("_pre_dest"), VARL("_shift")),
			SHIFTR0(VARL("_pre_dest"), SUB(UN(shift_size, shift_max), VARL("_shift")))));

	RzILOpEffect *result = SETL("_dest", CAST(size, IL_FALSE, VARL("_rotated")));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), ITE(IS_ZERO(VARL("_shift")), VARG(EFLAGS(CF)), LSB(VARL("_rotated"))));

	// if _shift == 1, OF is set to 'CF xor MSB (after rotation)'.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), XOR(VARG(EFLAGS(CF)), MSB(VARL("_dest"))));

	return SEQ7(pre_dest, shift, rotated, result, set_cf, set_of, set_dest);
}

/**
 * ROR
 * Rotate right
 * Encoding: MI, M1, MC
 */
IL_LIFTER(ror) {
	ROX_MACRO();

	RzILOpEffect *rotated = SETL("_rotated",
		LOGOR(
			SHIFTR0(VARL("_pre_dest"), VARL("_shift")),
			SHIFTL0(VARL("_pre_dest"), SUB(UN(shift_size, shift_max), VARL("_shift")))));

	RzILOpEffect *result = SETL("_dest", CAST(size, IL_FALSE, VARL("_rotated")));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), ITE(IS_ZERO(VARL("_shift")), VARG(EFLAGS(CF)), MSB(VARL("_rotated"))));

	// if _shift == 1, OF is set to 'CF xor MSB (before rotation)'.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), XOR(VARG(EFLAGS(CF)), MSB(VARL("_pre_dest"))));

	return SEQ7(pre_dest, shift, rotated, result, set_of, set_cf, set_dest);
}

#undef ROX_MACRO

/**
 * RET
 * Return (near pointer)
 * Encoding: ZO, I
 * Most modern x86-32 and x86-64 programs use this return instruction
 */
IL_LIFTER(ret) {
	PopHelper ph = x86_pop_helper(analysis->bits / BITS_PER_BYTE /* BYTES */);

	RzILOpEffect *ret = SEQ2(SETL("tgt", ph.val), ph.eff);

	if (ins->structure->op_count == 1) {
		/* Immediate operand (Encoding: I)
		 * Reduce RSP by that many bytes. */
		ret = SEQ2(ret, x86_il_set_reg(X86_REG_RSP, ADD(x86_il_get_reg(X86_REG_RSP), UN(analysis->bits, ins->structure->operands[0].imm))));
	}

	return SEQ2(ret, JMP(VARL("tgt")));
}

/**
 * RETF
 * Return far pointer
 * Encoding: ZO, I
 * Rarely found in modern programs
 */

/**
 * RETFQ
 * Return far pointer (size: qword)
 * Encoding: ZO, I
 * Rarely found in modern programs
 */

/**
 * SAHF
 * Store AH into FLAGS
 * Encoding: ZO
 */
IL_LIFTER(sahf) {
	return x86_il_set_flags(x86_il_get_reg(X86_REG_AH), 8);
}

#define SHIFT_MACRO() \
	ut8 size = ins->structure->operands[0].size * BITS_PER_BYTE; \
	ut8 shift_size = ins->structure->operands[1].size * BITS_PER_BYTE; \
	ut8 shift_mask = (analysis->bits == 64 && ins->structure->rex) ? 0x3f : 0x1f; \
	RzILOpEffect *pre_dest = SETL("_pre_dest", x86_il_get_op(0)); \
	RzILOpEffect *shift = SETL("_shift", LOGAND(x86_il_get_op(1), UN(shift_size, shift_mask))); \
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest")); \
	RzILOpEffect *set_flags = BRANCH(IS_ZERO(VARL("_shift")), NULL, x86_il_set_result_flags(VARL("_dest")));

/**
 * SAL
 * Shift arithmetically left (signed shift left)
 * Encoding: M1, MC, MI
 * (Functionally the same as SHL)
 */
IL_LIFTER(sal) {
	SHIFT_MACRO();

	RzILOpEffect *shifted = SETL("_shifted", SHIFTL0(UNSIGNED(size + 1, VARL("_pre_dest")), VARL("_shift")));

	RzILOpEffect *result = SETL("_dest", UNSIGNED(size, VARL("_shifted")));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), MSB(VARL("_shifted")));

	// if _shift == 1, OF is set to 'CF xor MSB (after shift)'.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), XOR(VARG(EFLAGS(CF)), MSB(VARL("_dest"))));

	return SEQ8(pre_dest, shift, shifted, result, set_cf, set_of, set_flags, set_dest);
}

/**
 * SAR
 * Shift arithmetically right (signed shift right)
 * Encoding: M1, MC, MI
 */
IL_LIFTER(sar) {
	SHIFT_MACRO();

	RzILOpEffect *shifted = SETL("_shifted",
		SHIFTR(MSB(VARL("_pre_dest")), APPEND(VARL("_pre_dest"), BOOL_TO_BV(VARG(EFLAGS(CF)), 1)), VARL("_shift")));

	RzILOpEffect *result = SETL("_dest", UNSIGNED(size, SHIFTR0(VARL("_shifted"), U8(1))));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), LSB(VARL("_shifted")));

	// if _shift == 1, OF is set to false.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), IL_FALSE);

	return SEQ8(pre_dest, shift, shifted, result, set_cf, set_of, set_flags, set_dest);
}

/**
 * SHL
 * Shift left (unsigned shift left)
 * Encoding: M1, MC, MI
 * (Functionally the same as SAL)
 */
IL_LIFTER(shl) {
	SHIFT_MACRO();

	RzILOpEffect *shifted = SETL("_shifted", SHIFTL0(UNSIGNED(size + 1, VARL("_pre_dest")), VARL("_shift")));

	RzILOpEffect *result = SETL("_dest", UNSIGNED(size, VARL("_shifted")));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), MSB(VARL("_shifted")));

	// if _shift == 1, OF is set to 'CF xor MSB (after shift)'.
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), XOR(VARG(EFLAGS(CF)), MSB(VARL("_dest"))));

	return SEQ8(pre_dest, shift, shifted, result, set_cf, set_of, set_flags, set_dest);
}

/**
 * SHR
 * Shift right (unsigned shift left)
 * Encoding: M1, MC, MI
 */
IL_LIFTER(shr) {
	SHIFT_MACRO();

	RzILOpEffect *shifted = SETL("_shifted",
		SHIFTR0(APPEND(VARL("_pre_dest"), BOOL_TO_BV(VARG(EFLAGS(CF)), 1)), VARL("_shift")));

	RzILOpEffect *result = SETL("_dest", UNSIGNED(size, SHIFTR0(VARL("_shifted"), U8(1))));

	// if _shift == 0, CF is unaffected.
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), LSB(VARL("_shifted")));

	// if _shift == 1, OF is set to MSB (before shift).
	// otherwise, OF is undefined.
	RzILOpEffect *set_of = SETG(EFLAGS(OF), MSB(VARL("_pre_dest")));

	return SEQ8(pre_dest, shift, shifted, result, set_cf, set_of, set_flags, set_dest);
}

/**
 * SBB
 * Subtraction with borrow
 * DEST = DEST - (SRC + CF)
 * Encoding: I, MI, MR, RM
 */
IL_LIFTER(sbb) {
	RzILOpEffect *op1 = SETL("_op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("_op2", x86_il_get_op(1));
	RzILOpPure *cf = VARG(EFLAGS(CF));

	RzILOpEffect *diff = SETL("_diff", SUB(SUB(VARL("_op1"), VARL("_op2")), BOOL_TO_BV(cf, ins->structure->operands[0].size * BITS_PER_BYTE)));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_diff"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("_diff"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("_diff"), VARL("_op1"), VARL("_op2"), false);

	return SEQ6(op1, op2, diff, set_dest, set_res_flags, set_arith_flags);
}

RzILOpEffect *x86_il_scas_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	X86Reg sub_reg;

	switch (size) {
	case 8:
		sub_reg = X86_REG_AL;
		break;
	case 16:
		sub_reg = X86_REG_AX;
		break;
	case 32:
		sub_reg = X86_REG_EAX;
		break;
	case 64:
		sub_reg = X86_REG_RAX;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	if (analysis->bits == 64) {
		X86Reg mem_reg = X86_REG_RDI;
		ut8 mem_size = 64;
		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpEffect *src = SETL("_src", LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg) : UNSIGNED(64, x86_il_get_reg(mem_reg)))));
		RzILOpEffect *reg = SETL("_reg", x86_il_get_reg(sub_reg));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_reg"), VARL("_src")));
		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_reg"), VARL("_src"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ6(reg, src, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	} else {
		RzILOpEffect *reg = SETL("_reg", x86_il_get_reg(sub_reg));

		X86Reg mem_reg = X86_REG_EDI;
		ut8 mem_size = 32;
		/* Check bitness and address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem;
		src_mem.base = mem_reg;
		src_mem.disp = 0;
		src_mem.index = X86_REG_INVALID;
		src_mem.scale = 1;
		src_mem.segment = X86_REG_ES;

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpEffect *src = SETL("_src", LOADW(size, x86_il_get_memaddr(src_mem)));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_reg"), VARL("_src")));
		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_reg"), VARL("_src"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ6(reg, src, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	}
}

/**
 * SCASB
 * Compare byte string
 * ZO
 */
IL_LIFTER(scasb) {
	return x86_il_scas_helper(ins, pc, analysis, 8);
}

/**
 * SCASW
 * Compare word string
 * ZO
 */
IL_LIFTER(scasw) {
	return x86_il_scas_helper(ins, pc, analysis, 16);
}

/**
 * SCASD
 * Compare dword string
 * ZO
 */
IL_LIFTER(scasd) {
	return x86_il_scas_helper(ins, pc, analysis, 32);
}

/**
 * SCASQ
 * Compare quadword string (only for x86-64)
 * ZO
 */
IL_LIFTER(scasq) {
	return x86_il_scas_helper(ins, pc, analysis, 64);
}

/**
 * STAC
 * Set AC flag
 * ZO
 */
IL_LIFTER(stac) {
	return SETG(EFLAGS(AC), IL_TRUE);
}

/**
 * STC
 * Set carry flag (CF)
 * ZO
 */
IL_LIFTER(stc) {
	return SETG(EFLAGS(CF), IL_TRUE);
}

/**
 * STD
 * Set direction flag (DF)
 * ZO
 */
IL_LIFTER(std) {
	return SETG(EFLAGS(DF), IL_TRUE);
}

/**
 * STI
 * Set interrupt flag (IF)
 * ZO
 */
IL_LIFTER(sti) {
	return SETG(EFLAGS(IF), IL_TRUE);
}

RzILOpEffect *x86_il_stos_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	X86Reg store_reg;

	switch (size) {
	case 8:
		store_reg = X86_REG_AL;
		break;
	case 16:
		store_reg = X86_REG_AX;
		break;
	case 32:
		store_reg = X86_REG_EAX;
		break;
	case 64:
		store_reg = X86_REG_RAX;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	if (analysis->bits == 64) {
		X86Reg mem_reg = X86_REG_RDI;
		ut8 mem_size = 64;
		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpEffect *store = STOREW((mem_size == 64 ? x86_il_get_reg(mem_reg) : UNSIGNED(64, x86_il_get_reg(mem_reg))), x86_il_get_reg(store_reg));

		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ2(store, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	} else {
		X86Reg mem_reg = X86_REG_EDI;
		ut8 mem_size = 32;
		/* Check bitness and address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem;
		src_mem.base = mem_reg;
		src_mem.disp = 0;
		src_mem.index = X86_REG_INVALID;
		src_mem.scale = 1;
		src_mem.segment = X86_REG_ES;

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpEffect *store = x86_il_set_mem(src_mem, x86_il_get_reg(store_reg));
		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ2(store, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	}
}

/**
 * STOSB
 * Store byte in a string
 * ZO
 */
IL_LIFTER(stosb) {
	return x86_il_stos_helper(ins, pc, analysis, 8);
}

/**
 * STOSW
 * Store word in a string
 * ZO
 */
IL_LIFTER(stosw) {

	return x86_il_stos_helper(ins, pc, analysis, 16);
}

/**
 * STOSD
 * Store dword in a string
 * ZO
 */
IL_LIFTER(stosd) {
	return x86_il_stos_helper(ins, pc, analysis, 32);
}

/**
 * STOSQ
 * Store quadword in a string
 * ZO
 */
IL_LIFTER(stosq) {
	return x86_il_stos_helper(ins, pc, analysis, 64);
}

/**
 * SUB
 * (SUB family of instructions)
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(sub) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_op(1));
	RzILOpEffect *sub = SETL("sub", SUB(VARL("op1"), VARL("op2")));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("sub"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("sub"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("sub"), VARL("op1"), VARL("op2"), false);

	return SEQ6(op1, op2, sub, set_dest, set_res_flags, set_arith_flags);
}

/**
 * TEST
 * Logical compare (AND)
 * Encoding: I, MI, MR
 */
IL_LIFTER(test) {
	RzILOpEffect *res_flags = x86_il_set_result_flags(LOGAND(x86_il_get_op(0), x86_il_get_op(1)));
	RzILOpEffect *arith_flags = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));

	return SEQ2(res_flags, arith_flags);
}

/**
 * WAIT
 * Wait until not busy
 * ZO
 */
IL_LIFTER(wait) {
	/* NOP seems to be a reasonable implementation */
	return NOP();
}

/**
 * XCHG
 * Exchange data
 * Encoding: O, MR, RM
 */
IL_LIFTER(xchg) {
	RzILOpEffect *temp = SETL("_temp", x86_il_get_op(0));
	RzILOpEffect *xchg = x86_il_set_op(0, x86_il_get_op(1));
	RzILOpEffect *set_src = x86_il_set_op(1, VARL("_temp"));

	return SEQ3(temp, xchg, set_src);
}

/**
 * XLATB
 * Table look-up translation
 * Encoding: ZO
 */
IL_LIFTER(xlatb) {
	X86Mem mem;
	mem.disp = 0;
	mem.index = X86_REG_INVALID;
	mem.scale = 1;
	mem.segment = X86_REG_DS;
	mem.base = X86_REG_EBX;

	if (analysis->bits == 64) {
		mem.segment = X86_REG_INVALID;
		mem.base = X86_REG_RBX;
	} else if (analysis->bits == 16) {
		mem.base = X86_REG_BX;
	}

	return x86_il_set_reg(X86_REG_AL, LOADW(8, ADD(x86_il_get_memaddr(mem), UNSIGNED(analysis->bits, x86_il_get_reg(X86_REG_AL)))));
}

/**
 * XOR
 * Logical exclusive OR
 * Encodings: I, MI, MR, RM
 */
IL_LIFTER(xor) {
	RzILOpPure *op1 = x86_il_get_op(0);
	RzILOpPure *op2 = x86_il_get_op(1);
	RzILOpEffect * xor = SETL("_xor", LOGXOR(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_xor"));
	RzILOpEffect *clear_of = SETG(EFLAGS(OF), IL_FALSE);
	RzILOpEffect *clear_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("_xor"));

	return SEQ5(xor, set_dest, clear_of, clear_cf, set_res_flags);
}

/**
 * BOUND
 * Check array index against bounds
 * Encoding: RM
 */

IL_LIFTER(bound) {
	RzILOpEffect *index = SETL("_index", x86_il_get_op(0));

	X86Mem mem = ins->structure->operands[1].mem;
	RzILOpEffect *lower = SETL("_lower", LOADW(ins->structure->operands[0].size * BITS_PER_BYTE, x86_il_get_memaddr(mem)));
	mem.disp += ins->structure->operands[1].size / mem.scale;
	RzILOpEffect *upper = SETL("_upper", LOADW(ins->structure->operands[0].size * BITS_PER_BYTE, x86_il_get_memaddr(mem)));

	RzILOpBool *cond = OR(ULT(VARL("_index"), VARL("_lower")), UGT(VARL("_index"), VARL("_upper")));

	/* Interrupt if out of bounds, NOP otherwise */
	return SEQ4(index, lower, upper, BRANCH(cond, GOTO("int"), NOP()));
}

/**
 * ENTER
 * Make a stack frame for procedure parameters
 * Encoding: II
 */
IL_LIFTER(enter) {
	RzILOpEffect *alloc_size = SETL("_alloc_sz", UNSIGNED(16, x86_il_get_op(0)));
	RzILOpEffect *nesting_level = SETL("_nest_lvl", MOD(UNSIGNED(8, x86_il_get_op(1)), U8(32)));

	/* Will get resolved correctly to the largest SP reg */
	X86Reg sp_reg = X86_REG_RSP;

	/* Default value initialization (useless, but need to avoid warnings) */
	X86Reg bp_reg = X86_REG_RBP;
	unsigned short bp_size = analysis->bits / BITS_PER_BYTE;

	switch (analysis->bits) {
	case 64:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		} else {
			bp_reg = X86_REG_RBP;
			bp_size = 8;
		}
		break;
	case 32:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_BP;
			bp_size = 2;
		} else {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		}
		break;
	case 16:
		bp_reg = X86_REG_BP;
		bp_size = 2;
		break;
	default:
		rz_warn_if_reached();
	}

	RzILOpEffect *push = x86_push_helper(x86_il_get_reg(bp_reg), bp_size);
	RzILOpEffect *frame_temp = SETL("_frame_tmp", x86_il_get_reg(sp_reg));

	RzILOpEffect *itr = SETL("_itr", U8(1));

	/* RBP will be dynamically resolved to the correct BP register */
	RzILOpEffect *loop_body = SEQ3(x86_il_set_reg(X86_REG_RBP, SUB(x86_il_get_reg(X86_REG_RBP), UN(analysis->bits, bp_size))), x86_push_helper(LOADW(bp_size * BITS_PER_BYTE, x86_il_get_reg(X86_REG_RBP)), bp_size), SETL("_itr", ADD(VARL("_itr"), U8(1))));
	RzILOpEffect *loop = REPEAT(ULT(VARL("_itr"), VARL("_nest_lvl")), loop_body);

	RzILOpEffect *nesting_lvl1 = x86_push_helper(VARL("_frame_tmp"), bp_size);

	RzILOpEffect *continue_eff = x86_il_set_reg(sp_reg, SUB(x86_il_get_reg(sp_reg), UNSIGNED(analysis->bits, VARL("_alloc_sz"))));
	if (bp_size == 2) {
		continue_eff = SEQ2(continue_eff, x86_il_set_reg(bp_reg, UNSIGNED(16, UNSIGNED(15, VARL("_frame_tmp")))));
	} else {
		continue_eff = SEQ2(continue_eff, x86_il_set_reg(bp_reg, VARL("_frame_tmp")));
	}

	return SEQ6(alloc_size, nesting_level, push, frame_temp, BRANCH(IS_ZERO(VARL("_nest_lvl")), NOP(), SEQ2(BRANCH(UGT(VARL("_nest_lvl"), U8(1)), SEQ2(itr, loop), NOP()), nesting_lvl1)), continue_eff);
}

/**
 * LEAVE
 * High level procedure exit
 * Encoding: ZO
 */
IL_LIFTER(leave) {
	RzILOpEffect *set_sp = x86_il_set_reg(X86_REG_RSP, x86_il_get_reg(X86_REG_RBP));

	/* Default value initialization (useless, but need to avoid warnings) */
	X86Reg bp_reg = X86_REG_RBP;
	unsigned short bp_size = analysis->bits / BITS_PER_BYTE;

	switch (analysis->bits) {
	case 64:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		} else {
			bp_reg = X86_REG_RBP;
			bp_size = 8;
		}
		break;
	case 32:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_BP;
			bp_size = 2;
		} else {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		}
		break;
	case 16:
		bp_reg = X86_REG_BP;
		bp_size = 2;
		break;
	default:
		rz_warn_if_reached();
	}

	PopHelper pop = x86_pop_helper(bp_size /* BYTES */);
	RzILOpEffect *set_bp = x86_il_set_reg(bp_reg, pop.val);

	return SEQ3(set_sp, pop.eff, set_bp);
}

#include <rz_il/rz_il_opbuilder_end.h>
