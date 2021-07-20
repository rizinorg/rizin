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
	}
	return op->size;
}