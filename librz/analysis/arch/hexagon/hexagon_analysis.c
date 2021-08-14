// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <stdio.h>
#include <stdbool.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include "hexagon.h"
#include "hexagon_insn.h"

static inline bool is_endloop01_instr(const HexInsn *hi) {
	return (hi->pkt_info.loop_attr & HEX_ENDS_LOOP_0) && (hi->pkt_info.loop_attr & HEX_ENDS_LOOP_1);
}

static inline bool is_endloop0_instr(const HexInsn *hi) {
	return (hi->pkt_info.loop_attr & HEX_ENDS_LOOP_0);
}

static inline bool is_endloop1_instr(const HexInsn *hi) {
	return (hi->pkt_info.loop_attr & HEX_ENDS_LOOP_1);
}

static inline bool is_loop0_begin(const HexInsn *hi) {
	return ((hi->pkt_info.loop_attr & HEX_LOOP_0) && !(hi->pkt_info.loop_attr & 0xc));
}

static inline bool is_loop1_begin(const HexInsn *hi) {
	return ((hi->pkt_info.loop_attr & HEX_LOOP_1) && !(hi->pkt_info.loop_attr & 0xc));
}

int hexagon_analysis_instruction(HexInsn *hi, RzAnalysisOp *op) {
	static ut32 hw_loop0_start = 0;
	static ut32 hw_loop1_start = 0;

	switch (hi->instruction) {
	default:
		if (is_endloop01_instr(hi) && hi->pkt_info.last_insn) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = hw_loop0_start;
			op->jump = hw_loop1_start;
			hw_loop1_start = 0;
			hw_loop0_start = 0;
		} else if (is_endloop0_instr(hi) && hi->pkt_info.last_insn) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = hw_loop0_start;
			hw_loop0_start = 0;
		} else if (is_endloop1_instr(hi) && hi->pkt_info.last_insn) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = hw_loop1_start;
			hw_loop1_start = 0;
		}
		break;
	case HEX_INS_A2_NOP:
		// nop
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case HEX_INS_A2_PADDF:
		// if (!Pu) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDFNEW:
		// if (!Pu.new) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDIF:
		// if (!Pu) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDIFNEW:
		// if (!Pu.new) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDIT:
		// if (Pu) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDITNEW:
		// if (Pu.new) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDT:
		// if (Pu) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PADDTNEW:
		// if (Pu.new) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PANDF:
		// if (!Pu) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PANDFNEW:
		// if (!Pu.new) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PANDT:
		// if (Pu) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PANDTNEW:
		// if (Pu.new) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PORF:
		// if (!Pu) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PORFNEW:
		// if (!Pu.new) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PORT:
		// if (Pu) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PORTNEW:
		// if (Pu.new) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PSUBF:
		// if (!Pu) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PSUBFNEW:
		// if (!Pu.new) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PSUBT:
		// if (Pu) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PSUBTNEW:
		// if (Pu.new) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PXORF:
		// if (!Pu) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PXORFNEW:
		// if (!Pu.new) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PXORT:
		// if (Pu) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A2_PXORTNEW:
		// if (Pu.new) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASLHF:
		// if (!Pu) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASLHFNEW:
		// if (!Pu.new) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASLHT:
		// if (Pu) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASLHTNEW:
		// if (Pu.new) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASRHF:
		// if (!Pu) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASRHFNEW:
		// if (!Pu.new) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASRHT:
		// if (Pu) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PASRHTNEW:
		// if (Pu.new) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTBF:
		// if (!Pu) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTBFNEW:
		// if (!Pu.new) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTBT:
		// if (Pu) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTBTNEW:
		// if (Pu.new) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTHF:
		// if (!Pu) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTHFNEW:
		// if (!Pu.new) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTHT:
		// if (Pu) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PSXTHTNEW:
		// if (Pu.new) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTBF:
		// if (!Pu) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTBFNEW:
		// if (!Pu.new) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTBT:
		// if (Pu) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTBTNEW:
		// if (Pu.new) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTHF:
		// if (!Pu) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTHFNEW:
		// if (!Pu.new) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTHT:
		// if (Pu) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_A4_PZXTHTNEW:
		// if (Pu.new) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CCOMBINEWF:
		// if (!Pu) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CCOMBINEWNEWF:
		// if (!Pu.new) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CCOMBINEWNEWT:
		// if (Pu.new) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CCOMBINEWT:
		// if (Pu) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CMOVEIF:
		// if (!Pu) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CMOVEIT:
		// if (Pu) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CMOVENEWIF:
		// if (!Pu.new) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_C2_CMOVENEWIT:
		// if (Pu.new) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_J2_CALL:
		// call Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		break;
	case HEX_INS_J2_CALLF:
		// if (!Pu) call Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_CALLR:
		// callr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case HEX_INS_J2_CALLRF:
		// if (!Pu) callr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		break;
	case HEX_INS_J2_CALLRT:
		// if (Pu) callr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		break;
	case HEX_INS_J2_CALLT:
		// if (Pu) call Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMP:
		// jump Ii
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		break;
	case HEX_INS_J2_JUMPF:
		// if (!Pu) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPFNEW:
		// if (!Pu.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPFNEWPT:
		// if (!Pu.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPFPT:
		// if (!Pu) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPR:
		// jumpr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		break;
	case HEX_INS_J2_JUMPRF:
		// if (!Pu) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRFNEW:
		// if (!Pu.new) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRFNEWPT:
		// if (!Pu.new) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRFPT:
		// if (!Pu) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRGTEZ:
		// if (Rs>=#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRGTEZPT:
		// if (Rs>=#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRLTEZ:
		// if (Rs<=#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRLTEZPT:
		// if (Rs<=#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRNZ:
		// if (Rs==#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRNZPT:
		// if (Rs==#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRT:
		// if (Pu) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRTNEW:
		// if (Pu.new) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRTNEWPT:
		// if (Pu.new) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRTPT:
		// if (Pu) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		break;
	case HEX_INS_J2_JUMPRZ:
		// if (Rs!=#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPRZPT:
		// if (Rs!=#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPT:
		// if (Pu) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPTNEW:
		// if (Pu.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPTNEWPT:
		// if (Pu.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_JUMPTPT:
		// if (Pu) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J2_LOOP0I:
		// loop0(Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_LOOP0R:
		// loop0(Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_LOOP1I:
		// loop1(Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_LOOP1R:
		// loop1(Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_PLOOP1SI:
		// p3 = sp1loop0(Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_PLOOP1SR:
		// p3 = sp1loop0(Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_PLOOP2SI:
		// p3 = sp2loop0(Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_PLOOP2SR:
		// p3 = sp2loop0(Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_PLOOP3SI:
		// p3 = sp3loop0(Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_PLOOP3SR:
		// p3 = sp3loop0(Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		if (is_loop0_begin(hi)) {
			hw_loop0_start = op->jump;
		} else if (is_loop1_begin(hi)) {
			hw_loop1_start = op->jump;
		}
		break;
	case HEX_INS_J2_TRAP0:
		// trap0(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case HEX_INS_J2_TRAP1:
		// trap1(Rx,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case HEX_INS_J4_CMPEQ_F_JUMPNV_NT:
		// if (!cmp.eq(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_F_JUMPNV_T:
		// if (!cmp.eq(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_FP0_JUMP_NT:
		// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_FP0_JUMP_T:
		// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_FP1_JUMP_NT:
		// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_FP1_JUMP_T:
		// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_T_JUMPNV_NT:
		// if (cmp.eq(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_T_JUMPNV_T:
		// if (cmp.eq(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_TP0_JUMP_NT:
		// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_TP0_JUMP_T:
		// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_TP1_JUMP_NT:
		// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQ_TP1_JUMP_T:
		// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_F_JUMPNV_NT:
		// if (!cmp.eq(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_F_JUMPNV_T:
		// if (!cmp.eq(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_FP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#II); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_FP0_JUMP_T:
		// p0 = cmp.eq(Rs,#II); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_FP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#II); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_FP1_JUMP_T:
		// p1 = cmp.eq(Rs,#II); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_T_JUMPNV_NT:
		// if (cmp.eq(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_T_JUMPNV_T:
		// if (cmp.eq(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_TP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#II); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_TP0_JUMP_T:
		// p0 = cmp.eq(Rs,#II); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_TP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#II); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQI_TP1_JUMP_T:
		// p1 = cmp.eq(Rs,#II); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_F_JUMPNV_NT:
		// if (!cmp.eq(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_F_JUMPNV_T:
		// if (!cmp.eq(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_FP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#n1); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_FP0_JUMP_T:
		// p0 = cmp.eq(Rs,#n1); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_FP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#n1); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_FP1_JUMP_T:
		// p1 = cmp.eq(Rs,#n1); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_T_JUMPNV_NT:
		// if (cmp.eq(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_T_JUMPNV_T:
		// if (cmp.eq(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_TP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#n1); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_TP0_JUMP_T:
		// p0 = cmp.eq(Rs,#n1); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_TP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#n1); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPEQN1_TP1_JUMP_T:
		// p1 = cmp.eq(Rs,#n1); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_F_JUMPNV_NT:
		// if (!cmp.gt(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_F_JUMPNV_T:
		// if (!cmp.gt(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_FP0_JUMP_NT:
		// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_FP0_JUMP_T:
		// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_FP1_JUMP_NT:
		// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_FP1_JUMP_T:
		// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_T_JUMPNV_NT:
		// if (cmp.gt(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_T_JUMPNV_T:
		// if (cmp.gt(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_TP0_JUMP_NT:
		// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_TP0_JUMP_T:
		// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_TP1_JUMP_NT:
		// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGT_TP1_JUMP_T:
		// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_F_JUMPNV_NT:
		// if (!cmp.gt(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_F_JUMPNV_T:
		// if (!cmp.gt(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_FP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#II); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_FP0_JUMP_T:
		// p0 = cmp.gt(Rs,#II); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_FP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#II); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_FP1_JUMP_T:
		// p1 = cmp.gt(Rs,#II); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_T_JUMPNV_NT:
		// if (cmp.gt(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_T_JUMPNV_T:
		// if (cmp.gt(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_TP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#II); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_TP0_JUMP_T:
		// p0 = cmp.gt(Rs,#II); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_TP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#II); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTI_TP1_JUMP_T:
		// p1 = cmp.gt(Rs,#II); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_F_JUMPNV_NT:
		// if (!cmp.gt(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_F_JUMPNV_T:
		// if (!cmp.gt(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_FP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#n1); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_FP0_JUMP_T:
		// p0 = cmp.gt(Rs,#n1); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_FP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#n1); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_FP1_JUMP_T:
		// p1 = cmp.gt(Rs,#n1); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_T_JUMPNV_NT:
		// if (cmp.gt(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_T_JUMPNV_T:
		// if (cmp.gt(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_TP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#n1); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_TP0_JUMP_T:
		// p0 = cmp.gt(Rs,#n1); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_TP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#n1); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTN1_TP1_JUMP_T:
		// p1 = cmp.gt(Rs,#n1); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_F_JUMPNV_NT:
		// if (!cmp.gtu(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_F_JUMPNV_T:
		// if (!cmp.gtu(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_FP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_FP0_JUMP_T:
		// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_FP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_FP1_JUMP_T:
		// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_T_JUMPNV_NT:
		// if (cmp.gtu(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_T_JUMPNV_T:
		// if (cmp.gtu(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_TP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_TP0_JUMP_T:
		// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_TP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTU_TP1_JUMP_T:
		// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_F_JUMPNV_NT:
		// if (!cmp.gtu(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_F_JUMPNV_T:
		// if (!cmp.gtu(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_FP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,#II); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_FP0_JUMP_T:
		// p0 = cmp.gtu(Rs,#II); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_FP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,#II); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_FP1_JUMP_T:
		// p1 = cmp.gtu(Rs,#II); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_T_JUMPNV_NT:
		// if (cmp.gtu(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_T_JUMPNV_T:
		// if (cmp.gtu(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_TP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,#II); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_TP0_JUMP_T:
		// p0 = cmp.gtu(Rs,#II); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_TP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,#II); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPGTUI_TP1_JUMP_T:
		// p1 = cmp.gtu(Rs,#II); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLT_F_JUMPNV_NT:
		// if (!cmp.gt(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLT_F_JUMPNV_T:
		// if (!cmp.gt(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLT_T_JUMPNV_NT:
		// if (cmp.gt(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLT_T_JUMPNV_T:
		// if (cmp.gt(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLTU_F_JUMPNV_NT:
		// if (!cmp.gtu(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLTU_F_JUMPNV_T:
		// if (!cmp.gtu(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLTU_T_JUMPNV_NT:
		// if (cmp.gtu(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_CMPLTU_T_JUMPNV_T:
		// if (cmp.gtu(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_HINTJUMPR:
		// hintjr(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		break;
	case HEX_INS_J4_JUMPSETI:
		// Rd = #II ; jump Ii
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		break;
	case HEX_INS_J4_JUMPSETR:
		// Rd = Rs ; jump Ii
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		break;
	case HEX_INS_J4_TSTBIT0_F_JUMPNV_NT:
		// if (!tstbit(Ns.new,#0)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_F_JUMPNV_T:
		// if (!tstbit(Ns.new,#0)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_FP0_JUMP_NT:
		// p0 = tstbit(Rs,#0); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_FP0_JUMP_T:
		// p0 = tstbit(Rs,#0); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_FP1_JUMP_NT:
		// p1 = tstbit(Rs,#0); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_FP1_JUMP_T:
		// p1 = tstbit(Rs,#0); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_T_JUMPNV_NT:
		// if (tstbit(Ns.new,#0)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_T_JUMPNV_T:
		// if (tstbit(Ns.new,#0)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_TP0_JUMP_NT:
		// p0 = tstbit(Rs,#0); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_TP0_JUMP_T:
		// p0 = tstbit(Rs,#0); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_TP1_JUMP_NT:
		// p1 = tstbit(Rs,#0); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_J4_TSTBIT0_TP1_JUMP_T:
		// p1 = tstbit(Rs,#0); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		break;
	case HEX_INS_L2_PLOADRBF_IO:
		// if (!Pt) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBF_PI:
		// if (!Pt) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBFNEW_IO:
		// if (!Pt.new) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBFNEW_PI:
		// if (!Pt.new) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBT_IO:
		// if (Pt) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBT_PI:
		// if (Pt) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBTNEW_IO:
		// if (Pt.new) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRBTNEW_PI:
		// if (Pt.new) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDF_IO:
		// if (!Pt) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDF_PI:
		// if (!Pt) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDFNEW_IO:
		// if (!Pt.new) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDFNEW_PI:
		// if (!Pt.new) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDT_IO:
		// if (Pt) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDT_PI:
		// if (Pt) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDTNEW_IO:
		// if (Pt.new) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRDTNEW_PI:
		// if (Pt.new) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHF_IO:
		// if (!Pt) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHF_PI:
		// if (!Pt) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHFNEW_IO:
		// if (!Pt.new) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHFNEW_PI:
		// if (!Pt.new) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHT_IO:
		// if (Pt) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHT_PI:
		// if (Pt) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHTNEW_IO:
		// if (Pt.new) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRHTNEW_PI:
		// if (Pt.new) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRIF_IO:
		// if (!Pt) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRIF_PI:
		// if (!Pt) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRIFNEW_IO:
		// if (!Pt.new) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRIFNEW_PI:
		// if (!Pt.new) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRIT_IO:
		// if (Pt) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRIT_PI:
		// if (Pt) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRITNEW_IO:
		// if (Pt.new) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRITNEW_PI:
		// if (Pt.new) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBF_IO:
		// if (!Pt) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBF_PI:
		// if (!Pt) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBFNEW_IO:
		// if (!Pt.new) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBFNEW_PI:
		// if (!Pt.new) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBT_IO:
		// if (Pt) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBT_PI:
		// if (Pt) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBTNEW_IO:
		// if (Pt.new) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUBTNEW_PI:
		// if (Pt.new) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHF_IO:
		// if (!Pt) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHF_PI:
		// if (!Pt) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHFNEW_IO:
		// if (!Pt.new) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHFNEW_PI:
		// if (!Pt.new) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHT_IO:
		// if (Pt) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHT_PI:
		// if (Pt) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHTNEW_IO:
		// if (Pt.new) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L2_PLOADRUHTNEW_PI:
		// if (Pt.new) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBF_ABS:
		// if (!Pt) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBF_RR:
		// if (!Pv) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBFNEW_ABS:
		// if (!Pt.new) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBFNEW_RR:
		// if (!Pv.new) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBT_ABS:
		// if (Pt) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBT_RR:
		// if (Pv) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBTNEW_ABS:
		// if (Pt.new) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRBTNEW_RR:
		// if (Pv.new) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDF_ABS:
		// if (!Pt) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDF_RR:
		// if (!Pv) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDFNEW_ABS:
		// if (!Pt.new) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDFNEW_RR:
		// if (!Pv.new) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDT_ABS:
		// if (Pt) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDT_RR:
		// if (Pv) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDTNEW_ABS:
		// if (Pt.new) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRDTNEW_RR:
		// if (Pv.new) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHF_ABS:
		// if (!Pt) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHF_RR:
		// if (!Pv) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHFNEW_ABS:
		// if (!Pt.new) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHFNEW_RR:
		// if (!Pv.new) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHT_ABS:
		// if (Pt) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHT_RR:
		// if (Pv) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHTNEW_ABS:
		// if (Pt.new) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRHTNEW_RR:
		// if (Pv.new) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRIF_ABS:
		// if (!Pt) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRIF_RR:
		// if (!Pv) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRIFNEW_ABS:
		// if (!Pt.new) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRIFNEW_RR:
		// if (!Pv.new) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRIT_ABS:
		// if (Pt) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRIT_RR:
		// if (Pv) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRITNEW_ABS:
		// if (Pt.new) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRITNEW_RR:
		// if (Pv.new) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBF_ABS:
		// if (!Pt) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBF_RR:
		// if (!Pv) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBFNEW_ABS:
		// if (!Pt.new) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBFNEW_RR:
		// if (!Pv.new) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBT_ABS:
		// if (Pt) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBT_RR:
		// if (Pv) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBTNEW_ABS:
		// if (Pt.new) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUBTNEW_RR:
		// if (Pv.new) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHF_ABS:
		// if (!Pt) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHF_RR:
		// if (!Pv) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHFNEW_ABS:
		// if (!Pt.new) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHFNEW_RR:
		// if (!Pv.new) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHT_ABS:
		// if (Pt) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHT_RR:
		// if (Pv) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHTNEW_ABS:
		// if (Pt.new) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_PLOADRUHTNEW_RR:
		// if (Pv.new) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_L4_RETURN:
		// Rdd = dealloc_return(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case HEX_INS_L4_RETURN_F:
		// if (!Pv) Rdd = dealloc_return(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case HEX_INS_L4_RETURN_FNEW_PNT:
		// if (!Pv.new) Rdd = dealloc_return(Rs):nt:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case HEX_INS_L4_RETURN_FNEW_PT:
		// if (!Pv.new) Rdd = dealloc_return(Rs):t:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case HEX_INS_L4_RETURN_T:
		// if (Pv) Rdd = dealloc_return(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case HEX_INS_L4_RETURN_TNEW_PNT:
		// if (Pv.new) Rdd = dealloc_return(Rs):nt:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case HEX_INS_L4_RETURN_TNEW_PT:
		// if (Pv.new) Rdd = dealloc_return(Rs):t:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case HEX_INS_PS_TRAP1:
		// trap1(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case HEX_INS_S2_PSTORERBF_IO:
		// if (!Pv) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBF_PI:
		// if (!Pv) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBFNEW_PI:
		// if (!Pv.new) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBNEWF_IO:
		// if (!Pv) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBNEWF_PI:
		// if (!Pv) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBNEWFNEW_PI:
		// if (!Pv.new) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBNEWT_IO:
		// if (Pv) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBNEWT_PI:
		// if (Pv) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBNEWTNEW_PI:
		// if (Pv.new) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBT_IO:
		// if (Pv) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBT_PI:
		// if (Pv) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERBTNEW_PI:
		// if (Pv.new) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERDF_IO:
		// if (!Pv) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERDF_PI:
		// if (!Pv) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERDFNEW_PI:
		// if (!Pv.new) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERDT_IO:
		// if (Pv) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERDT_PI:
		// if (Pv) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERDTNEW_PI:
		// if (Pv.new) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERFF_IO:
		// if (!Pv) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERFF_PI:
		// if (!Pv) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERFFNEW_PI:
		// if (!Pv.new) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERFT_IO:
		// if (Pv) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERFT_PI:
		// if (Pv) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERFTNEW_PI:
		// if (Pv.new) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHF_IO:
		// if (!Pv) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHF_PI:
		// if (!Pv) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHFNEW_PI:
		// if (!Pv.new) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHNEWF_IO:
		// if (!Pv) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHNEWF_PI:
		// if (!Pv) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHNEWFNEW_PI:
		// if (!Pv.new) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHNEWT_IO:
		// if (Pv) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHNEWT_PI:
		// if (Pv) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHNEWTNEW_PI:
		// if (Pv.new) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHT_IO:
		// if (Pv) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHT_PI:
		// if (Pv) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERHTNEW_PI:
		// if (Pv.new) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERIF_IO:
		// if (!Pv) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERIF_PI:
		// if (!Pv) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERIFNEW_PI:
		// if (!Pv.new) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERINEWF_IO:
		// if (!Pv) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERINEWF_PI:
		// if (!Pv) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERINEWFNEW_PI:
		// if (!Pv.new) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERINEWT_IO:
		// if (Pv) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERINEWT_PI:
		// if (Pv) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERINEWTNEW_PI:
		// if (Pv.new) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERIT_IO:
		// if (Pv) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERIT_PI:
		// if (Pv) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S2_PSTORERITNEW_PI:
		// if (Pv.new) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBF_ABS:
		// if (!Pv) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBF_RR:
		// if (!Pv) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBFNEW_ABS:
		// if (!Pv.new) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBFNEW_IO:
		// if (!Pv.new) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBFNEW_RR:
		// if (!Pv.new) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWF_ABS:
		// if (!Pv) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWF_RR:
		// if (!Pv) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWFNEW_ABS:
		// if (!Pv.new) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWFNEW_IO:
		// if (!Pv.new) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWFNEW_RR:
		// if (!Pv.new) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWT_ABS:
		// if (Pv) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWT_RR:
		// if (Pv) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWTNEW_ABS:
		// if (Pv.new) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWTNEW_IO:
		// if (Pv.new) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBNEWTNEW_RR:
		// if (Pv.new) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBT_ABS:
		// if (Pv) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBT_RR:
		// if (Pv) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBTNEW_ABS:
		// if (Pv.new) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBTNEW_IO:
		// if (Pv.new) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERBTNEW_RR:
		// if (Pv.new) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDF_ABS:
		// if (!Pv) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDF_RR:
		// if (!Pv) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDFNEW_ABS:
		// if (!Pv.new) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDFNEW_IO:
		// if (!Pv.new) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDFNEW_RR:
		// if (!Pv.new) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDT_ABS:
		// if (Pv) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDT_RR:
		// if (Pv) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDTNEW_ABS:
		// if (Pv.new) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDTNEW_IO:
		// if (Pv.new) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERDTNEW_RR:
		// if (Pv.new) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFF_ABS:
		// if (!Pv) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFF_RR:
		// if (!Pv) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFFNEW_ABS:
		// if (!Pv.new) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFFNEW_RR:
		// if (!Pv.new) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFT_ABS:
		// if (Pv) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFT_RR:
		// if (Pv) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFTNEW_ABS:
		// if (Pv.new) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERFTNEW_RR:
		// if (Pv.new) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHF_ABS:
		// if (!Pv) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHF_RR:
		// if (!Pv) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHFNEW_ABS:
		// if (!Pv.new) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHFNEW_RR:
		// if (!Pv.new) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWF_ABS:
		// if (!Pv) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWF_RR:
		// if (!Pv) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWFNEW_ABS:
		// if (!Pv.new) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWFNEW_RR:
		// if (!Pv.new) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWT_ABS:
		// if (Pv) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWT_RR:
		// if (Pv) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWTNEW_ABS:
		// if (Pv.new) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHNEWTNEW_RR:
		// if (Pv.new) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHT_ABS:
		// if (Pv) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHT_RR:
		// if (Pv) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHTNEW_ABS:
		// if (Pv.new) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERHTNEW_RR:
		// if (Pv.new) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIF_ABS:
		// if (!Pv) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIF_RR:
		// if (!Pv) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIFNEW_ABS:
		// if (!Pv.new) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIFNEW_IO:
		// if (!Pv.new) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIFNEW_RR:
		// if (!Pv.new) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWF_ABS:
		// if (!Pv) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWF_RR:
		// if (!Pv) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWFNEW_ABS:
		// if (!Pv.new) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWFNEW_IO:
		// if (!Pv.new) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWFNEW_RR:
		// if (!Pv.new) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWT_ABS:
		// if (Pv) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWT_RR:
		// if (Pv) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWTNEW_ABS:
		// if (Pv.new) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWTNEW_IO:
		// if (Pv.new) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERINEWTNEW_RR:
		// if (Pv.new) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIT_ABS:
		// if (Pv) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERIT_RR:
		// if (Pv) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERITNEW_ABS:
		// if (Pv.new) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERITNEW_IO:
		// if (Pv.new) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_PSTORERITNEW_RR:
		// if (Pv.new) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRBF_IO:
		// if (!Pv) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRBFNEW_IO:
		// if (!Pv.new) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRBT_IO:
		// if (Pv) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRBTNEW_IO:
		// if (Pv.new) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRHF_IO:
		// if (!Pv) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRHFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRHT_IO:
		// if (Pv) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRHTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRIF_IO:
		// if (!Pv) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRIFNEW_IO:
		// if (!Pv.new) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRIT_IO:
		// if (Pv) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_S4_STOREIRITNEW_IO:
		// if (Pv.new) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_CUR_NPRED_AI:
		// if (!Pv) Vd.cur = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_CUR_NPRED_PI:
		// if (!Pv) Vd.cur = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_CUR_NPRED_PPU:
		// if (!Pv) Vd.cur = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_CUR_PRED_AI:
		// if (Pv) Vd.cur = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_CUR_PRED_PI:
		// if (Pv) Vd.cur = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_CUR_PRED_PPU:
		// if (Pv) Vd.cur = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NPRED_AI:
		// if (!Pv) Vd = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NPRED_PI:
		// if (!Pv) Vd = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NPRED_PPU:
		// if (!Pv) Vd = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_NPRED_AI:
		// if (!Pv) Vd.cur = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_NPRED_PI:
		// if (!Pv) Vd.cur = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_NPRED_PPU:
		// if (!Pv) Vd.cur = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PRED_AI:
		// if (Pv) Vd.cur = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PRED_PI:
		// if (Pv) Vd.cur = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PRED_PPU:
		// if (Pv) Vd.cur = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_NPRED_AI:
		// if (!Pv) Vd = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_NPRED_PI:
		// if (!Pv) Vd = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_NPRED_PPU:
		// if (!Pv) Vd = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_PRED_AI:
		// if (Pv) Vd = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_PRED_PI:
		// if (Pv) Vd = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_PRED_PPU:
		// if (Pv) Vd = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_NPRED_AI:
		// if (!Pv) Vd.tmp = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_NPRED_PI:
		// if (!Pv) Vd.tmp = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_NPRED_PPU:
		// if (!Pv) Vd.tmp = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PRED_AI:
		// if (Pv) Vd.tmp = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PRED_PI:
		// if (Pv) Vd.tmp = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PRED_PPU:
		// if (Pv) Vd.tmp = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_PRED_AI:
		// if (Pv) Vd = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_PRED_PI:
		// if (Pv) Vd = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_PRED_PPU:
		// if (Pv) Vd = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_TMP_NPRED_AI:
		// if (!Pv) Vd.tmp = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_TMP_NPRED_PI:
		// if (!Pv) Vd.tmp = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_TMP_NPRED_PPU:
		// if (!Pv) Vd.tmp = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_TMP_PRED_AI:
		// if (Pv) Vd.tmp = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_TMP_PRED_PI:
		// if (Pv) Vd.tmp = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VL32B_TMP_PRED_PPU:
		// if (Pv) Vd.tmp = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32UB_NPRED_AI:
		// if (!Pv) vmemu(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32UB_NPRED_PI:
		// if (!Pv) vmemu(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32UB_NPRED_PPU:
		// if (!Pv) vmemu(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32UB_PRED_AI:
		// if (Pv) vmemu(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32UB_PRED_PI:
		// if (Pv) vmemu(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32UB_PRED_PPU:
		// if (Pv) vmemu(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NEW_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NEW_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NEW_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NEW_PRED_AI:
		// if (Pv) vmem(Rt+#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NEW_PRED_PI:
		// if (Pv) vmem(Rx++#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NEW_PRED_PPU:
		// if (Pv) vmem(Rx++Mu) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PRED_AI:
		// if (Pv) vmem(Rt+#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PRED_PI:
		// if (Pv) vmem(Rx++#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PRED_PPU:
		// if (Pv) vmem(Rx++Mu):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_PRED_AI:
		// if (Pv) vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_PRED_PI:
		// if (Pv) vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_NT_PRED_PPU:
		// if (Pv) vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_PRED_AI:
		// if (Pv) vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_PRED_PI:
		// if (Pv) vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VS32B_PRED_PPU:
		// if (Pv) vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VCCOMBINE:
		// if (Ps) Vdd = vcombine(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VCMOV:
		// if (Ps) Vd = Vu
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VNCCOMBINE:
		// if (!Ps) Vdd = vcombine(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_VNCMOV:
		// if (!Ps) Vd = Vu
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_ZLD_PRED_AI:
		// if (Pv) z = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_ZLD_PRED_PI:
		// if (Pv) z = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case HEX_INS_V6_ZLD_PRED_PPU:
		// if (Pv) z = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	}
	return op->size;
}