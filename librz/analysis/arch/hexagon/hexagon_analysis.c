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
	case HEX_INS_A2_ABS:
		// Rd = abs(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ABSP:
		// Rdd = abs(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ABSSAT:
		// Rd = abs(Rs):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADD:
		// Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_HH:
		// Rd = add(Rt.h,Rs.h):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_HL:
		// Rd = add(Rt.h,Rs.l):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_LH:
		// Rd = add(Rt.l,Rs.h):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_LL:
		// Rd = add(Rt.l,Rs.l):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_SAT_HH:
		// Rd = add(Rt.h,Rs.h):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_SAT_HL:
		// Rd = add(Rt.h,Rs.l):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_SAT_LH:
		// Rd = add(Rt.l,Rs.h):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_H16_SAT_LL:
		// Rd = add(Rt.l,Rs.l):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_L16_HL:
		// Rd = add(Rt.l,Rs.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_L16_LL:
		// Rd = add(Rt.l,Rs.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_L16_SAT_HL:
		// Rd = add(Rt.l,Rs.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDH_L16_SAT_LL:
		// Rd = add(Rt.l,Rs.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDI:
		// Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_ADDP:
		// Rdd = add(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDPSAT:
		// Rdd = add(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDSAT:
		// Rd = add(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDSPH:
		// Rdd = add(Rss,Rtt):raw:hi
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ADDSPL:
		// Rdd = add(Rss,Rtt):raw:lo
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_AND:
		// Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ANDIR:
		// Rd = and(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_ANDP:
		// Rdd = and(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ASLH:
		// Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ASRH:
		// Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_COMBINE_HH:
		// Rd = combine(Rt.h,Rs.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_COMBINE_HL:
		// Rd = combine(Rt.h,Rs.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_COMBINE_LH:
		// Rd = combine(Rt.l,Rs.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_COMBINE_LL:
		// Rd = combine(Rt.l,Rs.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_COMBINEII:
		// Rdd = combine(#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_COMBINEW:
		// Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MAX:
		// Rd = max(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MAXP:
		// Rdd = max(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MAXU:
		// Rd = maxu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MAXUP:
		// Rdd = maxu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MIN:
		// Rd = min(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MINP:
		// Rdd = min(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MINU:
		// Rd = minu(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_MINUP:
		// Rdd = minu(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_NEGP:
		// Rdd = neg(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_NEGSAT:
		// Rd = neg(Rs):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_NOP:
		// nop
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_NOTP:
		// Rdd = not(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_OR:
		// Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ORIR:
		// Rd = or(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_ORP:
		// Rdd = or(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PADDF:
		// if (!Pu) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PADDFNEW:
		// if (!Pu.new) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PADDIF:
		// if (!Pu) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_PADDIFNEW:
		// if (!Pu.new) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_PADDIT:
		// if (Pu) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_PADDITNEW:
		// if (Pu.new) Rd = add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_PADDT:
		// if (Pu) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PADDTNEW:
		// if (Pu.new) Rd = add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PANDF:
		// if (!Pu) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PANDFNEW:
		// if (!Pu.new) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PANDT:
		// if (Pu) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PANDTNEW:
		// if (Pu.new) Rd = and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PORF:
		// if (!Pu) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PORFNEW:
		// if (!Pu.new) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PORT:
		// if (Pu) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PORTNEW:
		// if (Pu.new) Rd = or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PSUBF:
		// if (!Pu) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PSUBFNEW:
		// if (!Pu.new) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PSUBT:
		// if (Pu) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PSUBTNEW:
		// if (Pu.new) Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PXORF:
		// if (!Pu) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PXORFNEW:
		// if (!Pu.new) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PXORT:
		// if (Pu) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_PXORTNEW:
		// if (Pu.new) Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ROUNDSAT:
		// Rd = round(Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SAT:
		// Rd = sat(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SATB:
		// Rd = satb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SATH:
		// Rd = sath(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SATUB:
		// Rd = satub(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SATUH:
		// Rd = satuh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUB:
		// Rd = sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_HH:
		// Rd = sub(Rt.h,Rs.h):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_HL:
		// Rd = sub(Rt.h,Rs.l):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_LH:
		// Rd = sub(Rt.l,Rs.h):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_LL:
		// Rd = sub(Rt.l,Rs.l):<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_SAT_HH:
		// Rd = sub(Rt.h,Rs.h):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_SAT_HL:
		// Rd = sub(Rt.h,Rs.l):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_SAT_LH:
		// Rd = sub(Rt.l,Rs.h):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_H16_SAT_LL:
		// Rd = sub(Rt.l,Rs.l):sat:<<16
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_L16_HL:
		// Rd = sub(Rt.l,Rs.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_L16_LL:
		// Rd = sub(Rt.l,Rs.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_L16_SAT_HL:
		// Rd = sub(Rt.l,Rs.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBH_L16_SAT_LL:
		// Rd = sub(Rt.l,Rs.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBP:
		// Rdd = sub(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SUBRI:
		// Rd = sub(#Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_SUBSAT:
		// Rd = sub(Rt,Rs):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVADDH:
		// Rd = vaddh(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVADDHS:
		// Rd = vaddh(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVADDUHS:
		// Rd = vadduh(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVAVGH:
		// Rd = vavgh(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVAVGHS:
		// Rd = vavgh(Rs,Rt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVNAVGH:
		// Rd = vnavgh(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVSUBH:
		// Rd = vsubh(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVSUBHS:
		// Rd = vsubh(Rt,Rs):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SVSUBUHS:
		// Rd = vsubuh(Rt,Rs):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SWIZ:
		// Rd = swiz(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SXTB:
		// Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SXTH:
		// Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_SXTW:
		// Rdd = sxtw(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_TFR:
		// Rd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_TFRCRR:
		// Rd = Cs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_TFRIH:
		// Rx.h = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_TFRIL:
		// Rx.l = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_TFRRCR:
		// Cd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_TFRSI:
		// Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A2_VABSH:
		// Rdd = vabsh(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VABSHSAT:
		// Rdd = vabsh(Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VABSW:
		// Rdd = vabsw(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VABSWSAT:
		// Rdd = vabsw(Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDH:
		// Rdd = vaddh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDHS:
		// Rdd = vaddh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDUB:
		// Rdd = vaddub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDUBS:
		// Rdd = vaddub(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDUHS:
		// Rdd = vadduh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDW:
		// Rdd = vaddw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VADDWS:
		// Rdd = vaddw(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGH:
		// Rdd = vavgh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGHCR:
		// Rdd = vavgh(Rss,Rtt):crnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGHR:
		// Rdd = vavgh(Rss,Rtt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGUB:
		// Rdd = vavgub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGUBR:
		// Rdd = vavgub(Rss,Rtt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGUH:
		// Rdd = vavguh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGUHR:
		// Rdd = vavguh(Rss,Rtt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGUW:
		// Rdd = vavguw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGUWR:
		// Rdd = vavguw(Rss,Rtt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGW:
		// Rdd = vavgw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGWCR:
		// Rdd = vavgw(Rss,Rtt):crnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VAVGWR:
		// Rdd = vavgw(Rss,Rtt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPBEQ:
		// Pd = vcmpb.eq(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPBGTU:
		// Pd = vcmpb.gtu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPHEQ:
		// Pd = vcmph.eq(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPHGT:
		// Pd = vcmph.gt(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPHGTU:
		// Pd = vcmph.gtu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPWEQ:
		// Pd = vcmpw.eq(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPWGT:
		// Pd = vcmpw.gt(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCMPWGTU:
		// Pd = vcmpw.gtu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VCONJ:
		// Rdd = vconj(Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMAXB:
		// Rdd = vmaxb(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMAXH:
		// Rdd = vmaxh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMAXUB:
		// Rdd = vmaxub(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMAXUH:
		// Rdd = vmaxuh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMAXUW:
		// Rdd = vmaxuw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMAXW:
		// Rdd = vmaxw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMINB:
		// Rdd = vminb(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMINH:
		// Rdd = vminh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMINUB:
		// Rdd = vminub(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMINUH:
		// Rdd = vminuh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMINUW:
		// Rdd = vminuw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VMINW:
		// Rdd = vminw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VNAVGH:
		// Rdd = vnavgh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VNAVGHCR:
		// Rdd = vnavgh(Rtt,Rss):crnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VNAVGHR:
		// Rdd = vnavgh(Rtt,Rss):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VNAVGW:
		// Rdd = vnavgw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VNAVGWCR:
		// Rdd = vnavgw(Rtt,Rss):crnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VNAVGWR:
		// Rdd = vnavgw(Rtt,Rss):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VRADDUB:
		// Rdd = vraddub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VRADDUB_ACC:
		// Rxx += vraddub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VRSADUB:
		// Rdd = vrsadub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VRSADUB_ACC:
		// Rxx += vrsadub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBH:
		// Rdd = vsubh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBHS:
		// Rdd = vsubh(Rtt,Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBUB:
		// Rdd = vsubub(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBUBS:
		// Rdd = vsubub(Rtt,Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBUHS:
		// Rdd = vsubuh(Rtt,Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBW:
		// Rdd = vsubw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_VSUBWS:
		// Rdd = vsubw(Rtt,Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_XOR:
		// Rd = xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_XORP:
		// Rdd = xor(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A2_ZXTH:
		// Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_ADDP_C:
		// Rdd = add(Rss,Rtt,Px):carry
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_ANDN:
		// Rd = and(Rt,~Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_ANDNP:
		// Rdd = and(Rtt,~Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_BITSPLIT:
		// Rdd = bitsplit(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_BITSPLITI:
		// Rdd = bitsplit(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_BOUNDSCHECK_HI:
		// Pd = boundscheck(Rss,Rtt):raw:hi
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_BOUNDSCHECK_LO:
		// Pd = boundscheck(Rss,Rtt):raw:lo
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPBEQ:
		// Pd = cmpb.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPBEQI:
		// Pd = cmpb.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CMPBGT:
		// Pd = cmpb.gt(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPBGTI:
		// Pd = cmpb.gt(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CMPBGTU:
		// Pd = cmpb.gtu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPBGTUI:
		// Pd = cmpb.gtu(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CMPHEQ:
		// Pd = cmph.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPHEQI:
		// Pd = cmph.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CMPHGT:
		// Pd = cmph.gt(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPHGTI:
		// Pd = cmph.gt(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CMPHGTU:
		// Pd = cmph.gtu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_CMPHGTUI:
		// Pd = cmph.gtu(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_COMBINEII:
		// Rdd = combine(#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_COMBINEIR:
		// Rdd = combine(#Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_COMBINERI:
		// Rdd = combine(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CROUND_RI:
		// Rd = cround(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_CROUND_RR:
		// Rd = cround(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_EXT:
		// immext(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_MODWRAPU:
		// Rd = modwrap(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_ORN:
		// Rd = or(Rt,~Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_ORNP:
		// Rdd = or(Rtt,~Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASLHF:
		// if (!Pu) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASLHFNEW:
		// if (!Pu.new) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASLHT:
		// if (Pu) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASLHTNEW:
		// if (Pu.new) Rd = aslh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASRHF:
		// if (!Pu) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASRHFNEW:
		// if (!Pu.new) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASRHT:
		// if (Pu) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PASRHTNEW:
		// if (Pu.new) Rd = asrh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTBF:
		// if (!Pu) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTBFNEW:
		// if (!Pu.new) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTBT:
		// if (Pu) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTBTNEW:
		// if (Pu.new) Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTHF:
		// if (!Pu) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTHFNEW:
		// if (!Pu.new) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTHT:
		// if (Pu) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PSXTHTNEW:
		// if (Pu.new) Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTBF:
		// if (!Pu) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTBFNEW:
		// if (!Pu.new) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTBT:
		// if (Pu) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTBTNEW:
		// if (Pu.new) Rd = zxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTHF:
		// if (!Pu) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTHFNEW:
		// if (!Pu.new) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTHT:
		// if (Pu) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_PZXTHTNEW:
		// if (Pu.new) Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_RCMPEQ:
		// Rd = cmp.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_RCMPEQI:
		// Rd = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_RCMPNEQ:
		// Rd = !cmp.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_RCMPNEQI:
		// Rd = !cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_ROUND_RI:
		// Rd = round(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_ROUND_RI_SAT:
		// Rd = round(Rs,#Ii):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_ROUND_RR:
		// Rd = round(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_ROUND_RR_SAT:
		// Rd = round(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_SUBP_C:
		// Rdd = sub(Rss,Rtt,Px):carry
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_TFRCPP:
		// Rdd = Css
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_TFRPCP:
		// Cdd = Rss
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_TLBMATCH:
		// Pd = tlbmatch(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VCMPBEQ_ANY:
		// Pd = any8(vcmpb.eq(Rss,Rtt))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VCMPBEQI:
		// Pd = vcmpb.eq(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPBGT:
		// Pd = vcmpb.gt(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VCMPBGTI:
		// Pd = vcmpb.gt(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPBGTUI:
		// Pd = vcmpb.gtu(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPHEQI:
		// Pd = vcmph.eq(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPHGTI:
		// Pd = vcmph.gt(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPHGTUI:
		// Pd = vcmph.gtu(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPWEQI:
		// Pd = vcmpw.eq(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPWGTI:
		// Pd = vcmpw.gt(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VCMPWGTUI:
		// Pd = vcmpw.gtu(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A4_VRMAXH:
		// Rxx = vrmaxh(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMAXUH:
		// Rxx = vrmaxuh(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMAXUW:
		// Rxx = vrmaxuw(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMAXW:
		// Rxx = vrmaxw(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMINH:
		// Rxx = vrminh(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMINUH:
		// Rxx = vrminuh(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMINUW:
		// Rxx = vrminuw(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A4_VRMINW:
		// Rxx = vrminw(Rss,Ru)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A5_ACS:
		// Rxx,Pe = vacsh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A5_VADDHUBS:
		// Rd = vaddhub(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A6_VCMPBEQ_NOTANY:
		// Pd = !any8(vcmpb.eq(Rss,Rtt))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A6_VMINUB_RDP:
		// Rdd,Pe = vminub(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A7_CLIP:
		// Rd = clip(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A7_CROUNDD_RI:
		// Rdd = cround(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_A7_CROUNDD_RR:
		// Rdd = cround(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_A7_VCLIP:
		// Rdd = vclip(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_ALL8:
		// Pd = all8(Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_AND:
		// Pd = and(Pt,Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_ANDN:
		// Pd = and(Pt,!Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_ANY8:
		// Pd = any8(Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_BITSCLR:
		// Pd = bitsclr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_BITSCLRI:
		// Pd = bitsclr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_BITSSET:
		// Pd = bitsset(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CCOMBINEWF:
		// if (!Pu) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CCOMBINEWNEWF:
		// if (!Pu.new) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CCOMBINEWNEWT:
		// if (Pu.new) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CCOMBINEWT:
		// if (Pu) Rdd = combine(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CMOVEIF:
		// if (!Pu) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMOVEIT:
		// if (Pu) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMOVENEWIF:
		// if (!Pu.new) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMOVENEWIT:
		// if (Pu.new) Rd = #Ii
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMPEQ:
		// Pd = cmp.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CMPEQI:
		// Pd = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMPEQP:
		// Pd = cmp.eq(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CMPGT:
		// Pd = cmp.gt(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CMPGTI:
		// Pd = cmp.gt(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMPGTP:
		// Pd = cmp.gt(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CMPGTU:
		// Pd = cmp.gtu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_CMPGTUI:
		// Pd = cmp.gtu(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_CMPGTUP:
		// Pd = cmp.gtu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_MASK:
		// Rdd = mask(Pt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_MUX:
		// Rd = mux(Pu,Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_MUXII:
		// Rd = mux(Pu,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_MUXIR:
		// Rd = mux(Pu,Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_MUXRI:
		// Rd = mux(Pu,#Ii,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C2_NOT:
		// Pd = not(Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_OR:
		// Pd = or(Pt,Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_ORN:
		// Pd = or(Pt,!Ps)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_TFRPR:
		// Rd = Ps
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_TFRRP:
		// Pd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_VITPACK:
		// Rd = vitpack(Ps,Pt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_VMUX:
		// Rdd = vmux(Pu,Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C2_XOR:
		// Pd = xor(Ps,Pt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_ADDIPC:
		// Rd = add(pc,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C4_AND_AND:
		// Pd = and(Ps,and(Pt,Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_AND_ANDN:
		// Pd = and(Ps,and(Pt,!Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_AND_OR:
		// Pd = and(Ps,or(Pt,Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_AND_ORN:
		// Pd = and(Ps,or(Pt,!Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_CMPLTE:
		// Pd = !cmp.gt(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_CMPLTEI:
		// Pd = !cmp.gt(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C4_CMPLTEU:
		// Pd = !cmp.gtu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_CMPLTEUI:
		// Pd = !cmp.gtu(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C4_CMPNEQ:
		// Pd = !cmp.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_CMPNEQI:
		// Pd = !cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C4_FASTCORNER9:
		// Pd = fastcorner9(Ps,Pt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_FASTCORNER9_NOT:
		// Pd = !fastcorner9(Ps,Pt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_NBITSCLR:
		// Pd = !bitsclr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_NBITSCLRI:
		// Pd = !bitsclr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_C4_NBITSSET:
		// Pd = !bitsset(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_OR_AND:
		// Pd = or(Ps,and(Pt,Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_OR_ANDN:
		// Pd = or(Ps,and(Pt,!Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_OR_OR:
		// Pd = or(Ps,or(Pt,Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_C4_OR_ORN:
		// Pd = or(Ps,or(Pt,!Pu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_D2DF:
		// Rdd = convert_d2df(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_D2SF:
		// Rd = convert_d2sf(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2D:
		// Rdd = convert_df2d(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2D_CHOP:
		// Rdd = convert_df2d(Rss):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2SF:
		// Rd = convert_df2sf(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2UD:
		// Rdd = convert_df2ud(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2UD_CHOP:
		// Rdd = convert_df2ud(Rss):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2UW:
		// Rd = convert_df2uw(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2UW_CHOP:
		// Rd = convert_df2uw(Rss):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2W:
		// Rd = convert_df2w(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_DF2W_CHOP:
		// Rd = convert_df2w(Rss):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2D:
		// Rdd = convert_sf2d(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2D_CHOP:
		// Rdd = convert_sf2d(Rs):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2DF:
		// Rdd = convert_sf2df(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2UD:
		// Rdd = convert_sf2ud(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2UD_CHOP:
		// Rdd = convert_sf2ud(Rs):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2UW:
		// Rd = convert_sf2uw(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2UW_CHOP:
		// Rd = convert_sf2uw(Rs):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2W:
		// Rd = convert_sf2w(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_SF2W_CHOP:
		// Rd = convert_sf2w(Rs):chop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_UD2DF:
		// Rdd = convert_ud2df(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_UD2SF:
		// Rd = convert_ud2sf(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_UW2DF:
		// Rdd = convert_uw2df(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_UW2SF:
		// Rd = convert_uw2sf(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_W2DF:
		// Rdd = convert_w2df(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_CONV_W2SF:
		// Rd = convert_w2sf(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFADD:
		// Rdd = dfadd(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFCLASS:
		// Pd = dfclass(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_F2_DFCMPEQ:
		// Pd = dfcmp.eq(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFCMPGE:
		// Pd = dfcmp.ge(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFCMPGT:
		// Pd = dfcmp.gt(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFCMPUO:
		// Pd = dfcmp.uo(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFIMM_N:
		// Rdd = dfmake(#Ii):neg
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_F2_DFIMM_P:
		// Rdd = dfmake(#Ii):pos
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_F2_DFMAX:
		// Rdd = dfmax(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFMIN:
		// Rdd = dfmin(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFMPYFIX:
		// Rdd = dfmpyfix(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFMPYHH:
		// Rxx += dfmpyhh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFMPYLH:
		// Rxx += dfmpylh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFMPYLL:
		// Rdd = dfmpyll(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_DFSUB:
		// Rdd = dfsub(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFADD:
		// Rd = sfadd(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFCLASS:
		// Pd = sfclass(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_F2_SFCMPEQ:
		// Pd = sfcmp.eq(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFCMPGE:
		// Pd = sfcmp.ge(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFCMPGT:
		// Pd = sfcmp.gt(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFCMPUO:
		// Pd = sfcmp.uo(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFIXUPD:
		// Rd = sffixupd(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFIXUPN:
		// Rd = sffixupn(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFIXUPR:
		// Rd = sffixupr(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFMA:
		// Rx += sfmpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFMA_LIB:
		// Rx += sfmpy(Rs,Rt):lib
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFMA_SC:
		// Rx += sfmpy(Rs,Rt,Pu):scale
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFMS:
		// Rx -= sfmpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFFMS_LIB:
		// Rx -= sfmpy(Rs,Rt):lib
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFIMM_N:
		// Rd = sfmake(#Ii):neg
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_F2_SFIMM_P:
		// Rd = sfmake(#Ii):pos
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_F2_SFINVSQRTA:
		// Rd,Pe = sfinvsqrta(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFMAX:
		// Rd = sfmax(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFMIN:
		// Rd = sfmin(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFMPY:
		// Rd = sfmpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFRECIPA:
		// Rd,Pe = sfrecipa(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_F2_SFSUB:
		// Rd = sfsub(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_G4_TFRGCPP:
		// Rdd = Gss
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_G4_TFRGCRR:
		// Rd = Gs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_G4_TFRGPCP:
		// Gdd = Rss
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_G4_TFRGRCR:
		// Gd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_CALL:
		// call Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_CALLF:
		// if (!Pu) call Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_CALLR:
		// callr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_CALLRF:
		// if (!Pu) callr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_CALLRT:
		// if (Pu) callr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_CALLT:
		// if (Pu) call Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMP:
		// jump Ii
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[0].op.imm;
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPF:
		// if (!Pu) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPFNEW:
		// if (!Pu.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPFNEWPT:
		// if (!Pu.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPFPT:
		// if (!Pu) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPR:
		// jumpr Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRF:
		// if (!Pu) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRFNEW:
		// if (!Pu.new) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRFNEWPT:
		// if (!Pu.new) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRFPT:
		// if (!Pu) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRGTEZ:
		// if (Rs>=#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRGTEZPT:
		// if (Rs>=#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRLTEZ:
		// if (Rs<=#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRLTEZPT:
		// if (Rs<=#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRNZ:
		// if (Rs==#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRNZPT:
		// if (Rs==#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRT:
		// if (Pu) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRTNEW:
		// if (Pu.new) jumpr:nt Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRTNEWPT:
		// if (Pu.new) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRTPT:
		// if (Pu) jumpr:t Rs
		op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J2_JUMPRZ:
		// if (Rs!=#0) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPRZPT:
		// if (Rs!=#0) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPT:
		// if (Pu) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPTNEW:
		// if (Pu.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPTNEWPT:
		// if (Pu.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_JUMPTPT:
		// if (Pu) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_PAUSE:
		// pause(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
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
		op->val = op->jump;
		op->analysis_vals[0].imm = op->jump;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_TRAP0:
		// trap0(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J2_TRAP1:
		// trap1(Rx,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_F_JUMPNV_NT:
		// if (!cmp.eq(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_F_JUMPNV_T:
		// if (!cmp.eq(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_FP0_JUMP_NT:
		// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_FP0_JUMP_T:
		// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_FP1_JUMP_NT:
		// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_FP1_JUMP_T:
		// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_T_JUMPNV_NT:
		// if (cmp.eq(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_T_JUMPNV_T:
		// if (cmp.eq(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_TP0_JUMP_NT:
		// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_TP0_JUMP_T:
		// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_TP1_JUMP_NT:
		// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQ_TP1_JUMP_T:
		// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_F_JUMPNV_NT:
		// if (!cmp.eq(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_F_JUMPNV_T:
		// if (!cmp.eq(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_FP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#II); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_FP0_JUMP_T:
		// p0 = cmp.eq(Rs,#II); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_FP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#II); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_FP1_JUMP_T:
		// p1 = cmp.eq(Rs,#II); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_T_JUMPNV_NT:
		// if (cmp.eq(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_T_JUMPNV_T:
		// if (cmp.eq(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_TP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#II); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_TP0_JUMP_T:
		// p0 = cmp.eq(Rs,#II); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_TP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#II); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQI_TP1_JUMP_T:
		// p1 = cmp.eq(Rs,#II); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_F_JUMPNV_NT:
		// if (!cmp.eq(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_F_JUMPNV_T:
		// if (!cmp.eq(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_FP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#n1); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_FP0_JUMP_T:
		// p0 = cmp.eq(Rs,#n1); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_FP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#n1); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_FP1_JUMP_T:
		// p1 = cmp.eq(Rs,#n1); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_T_JUMPNV_NT:
		// if (cmp.eq(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_T_JUMPNV_T:
		// if (cmp.eq(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_TP0_JUMP_NT:
		// p0 = cmp.eq(Rs,#n1); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_TP0_JUMP_T:
		// p0 = cmp.eq(Rs,#n1); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_TP1_JUMP_NT:
		// p1 = cmp.eq(Rs,#n1); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPEQN1_TP1_JUMP_T:
		// p1 = cmp.eq(Rs,#n1); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_F_JUMPNV_NT:
		// if (!cmp.gt(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_F_JUMPNV_T:
		// if (!cmp.gt(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_FP0_JUMP_NT:
		// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_FP0_JUMP_T:
		// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_FP1_JUMP_NT:
		// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_FP1_JUMP_T:
		// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_T_JUMPNV_NT:
		// if (cmp.gt(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_T_JUMPNV_T:
		// if (cmp.gt(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_TP0_JUMP_NT:
		// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_TP0_JUMP_T:
		// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_TP1_JUMP_NT:
		// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGT_TP1_JUMP_T:
		// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_F_JUMPNV_NT:
		// if (!cmp.gt(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_F_JUMPNV_T:
		// if (!cmp.gt(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_FP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#II); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_FP0_JUMP_T:
		// p0 = cmp.gt(Rs,#II); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_FP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#II); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_FP1_JUMP_T:
		// p1 = cmp.gt(Rs,#II); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_T_JUMPNV_NT:
		// if (cmp.gt(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_T_JUMPNV_T:
		// if (cmp.gt(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_TP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#II); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_TP0_JUMP_T:
		// p0 = cmp.gt(Rs,#II); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_TP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#II); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTI_TP1_JUMP_T:
		// p1 = cmp.gt(Rs,#II); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_F_JUMPNV_NT:
		// if (!cmp.gt(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_F_JUMPNV_T:
		// if (!cmp.gt(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_FP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#n1); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_FP0_JUMP_T:
		// p0 = cmp.gt(Rs,#n1); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_FP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#n1); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_FP1_JUMP_T:
		// p1 = cmp.gt(Rs,#n1); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_T_JUMPNV_NT:
		// if (cmp.gt(Ns.new,#n1)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_T_JUMPNV_T:
		// if (cmp.gt(Ns.new,#n1)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_TP0_JUMP_NT:
		// p0 = cmp.gt(Rs,#n1); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_TP0_JUMP_T:
		// p0 = cmp.gt(Rs,#n1); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_TP1_JUMP_NT:
		// p1 = cmp.gt(Rs,#n1); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTN1_TP1_JUMP_T:
		// p1 = cmp.gt(Rs,#n1); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_F_JUMPNV_NT:
		// if (!cmp.gtu(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_F_JUMPNV_T:
		// if (!cmp.gtu(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_FP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_FP0_JUMP_T:
		// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_FP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_FP1_JUMP_T:
		// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_T_JUMPNV_NT:
		// if (cmp.gtu(Ns.new,Rt)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_T_JUMPNV_T:
		// if (cmp.gtu(Ns.new,Rt)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_TP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_TP0_JUMP_T:
		// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_TP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTU_TP1_JUMP_T:
		// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_F_JUMPNV_NT:
		// if (!cmp.gtu(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_F_JUMPNV_T:
		// if (!cmp.gtu(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_FP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,#II); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_FP0_JUMP_T:
		// p0 = cmp.gtu(Rs,#II); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_FP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,#II); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_FP1_JUMP_T:
		// p1 = cmp.gtu(Rs,#II); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_T_JUMPNV_NT:
		// if (cmp.gtu(Ns.new,#II)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_T_JUMPNV_T:
		// if (cmp.gtu(Ns.new,#II)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_TP0_JUMP_NT:
		// p0 = cmp.gtu(Rs,#II); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_TP0_JUMP_T:
		// p0 = cmp.gtu(Rs,#II); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_TP1_JUMP_NT:
		// p1 = cmp.gtu(Rs,#II); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPGTUI_TP1_JUMP_T:
		// p1 = cmp.gtu(Rs,#II); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLT_F_JUMPNV_NT:
		// if (!cmp.gt(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLT_F_JUMPNV_T:
		// if (!cmp.gt(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLT_T_JUMPNV_NT:
		// if (cmp.gt(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLT_T_JUMPNV_T:
		// if (cmp.gt(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLTU_F_JUMPNV_NT:
		// if (!cmp.gtu(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLTU_F_JUMPNV_T:
		// if (!cmp.gtu(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLTU_T_JUMPNV_NT:
		// if (cmp.gtu(Rt,Ns.new)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_CMPLTU_T_JUMPNV_T:
		// if (cmp.gtu(Rt,Ns.new)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_HINTJUMPR:
		// hintjr(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->val = UT64_MAX;
		break;
	case HEX_INS_J4_JUMPSETI:
		// Rd = #II ; jump Ii
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_JUMPSETR:
		// Rd = Rs ; jump Ii
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + (st32)hi->ops[2].op.imm;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = op->jump;
		op->analysis_vals[2].imm = op->jump;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_F_JUMPNV_NT:
		// if (!tstbit(Ns.new,#0)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_F_JUMPNV_T:
		// if (!tstbit(Ns.new,#0)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_FP0_JUMP_NT:
		// p0 = tstbit(Rs,#0); if (!p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_FP0_JUMP_T:
		// p0 = tstbit(Rs,#0); if (!p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_FP1_JUMP_NT:
		// p1 = tstbit(Rs,#0); if (!p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_FP1_JUMP_T:
		// p1 = tstbit(Rs,#0); if (!p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_T_JUMPNV_NT:
		// if (tstbit(Ns.new,#0)) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_T_JUMPNV_T:
		// if (tstbit(Ns.new,#0)) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_TP0_JUMP_NT:
		// p0 = tstbit(Rs,#0); if (p0.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_TP0_JUMP_T:
		// p0 = tstbit(Rs,#0); if (p0.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_TP1_JUMP_NT:
		// p1 = tstbit(Rs,#0); if (p1.new) jump:nt Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_J4_TSTBIT0_TP1_JUMP_T:
		// p1 = tstbit(Rs,#0); if (p1.new) jump:t Ii
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)hi->ops[1].op.imm;
		op->fail = op->addr + op->size;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = op->jump;
		op->analysis_vals[1].imm = op->jump;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_DEALLOCFRAME:
		// Rdd = deallocframe(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNB_IO:
		// Ryy = memb_fifo(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNB_PBR:
		// Ryy = memb_fifo(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNB_PCI:
		// Ryy = memb_fifo(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNB_PCR:
		// Ryy = memb_fifo(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNB_PI:
		// Ryy = memb_fifo(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNB_PR:
		// Ryy = memb_fifo(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNH_IO:
		// Ryy = memh_fifo(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNH_PBR:
		// Ryy = memh_fifo(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNH_PCI:
		// Ryy = memh_fifo(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNH_PCR:
		// Ryy = memh_fifo(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNH_PI:
		// Ryy = memh_fifo(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADALIGNH_PR:
		// Ryy = memh_fifo(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBSW2_IO:
		// Rd = membh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBSW2_PBR:
		// Rd = membh(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBSW2_PCI:
		// Rd = membh(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBSW2_PCR:
		// Rd = membh(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBSW2_PI:
		// Rd = membh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBSW2_PR:
		// Rd = membh(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBSW4_IO:
		// Rdd = membh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBSW4_PBR:
		// Rdd = membh(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBSW4_PCI:
		// Rdd = membh(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBSW4_PCR:
		// Rdd = membh(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBSW4_PI:
		// Rdd = membh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBSW4_PR:
		// Rdd = membh(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBZW2_IO:
		// Rd = memubh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBZW2_PBR:
		// Rd = memubh(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBZW2_PCI:
		// Rd = memubh(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBZW2_PCR:
		// Rd = memubh(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBZW2_PI:
		// Rd = memubh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBZW2_PR:
		// Rd = memubh(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBZW4_IO:
		// Rdd = memubh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBZW4_PBR:
		// Rdd = memubh(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBZW4_PCI:
		// Rdd = memubh(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBZW4_PCR:
		// Rdd = memubh(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADBZW4_PI:
		// Rdd = memubh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADBZW4_PR:
		// Rdd = memubh(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRB_IO:
		// Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRB_PBR:
		// Rd = memb(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRB_PCI:
		// Rd = memb(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRB_PCR:
		// Rd = memb(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRB_PI:
		// Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRB_PR:
		// Rd = memb(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRBGP:
		// Rd = memb(gp+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRD_IO:
		// Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRD_PBR:
		// Rdd = memd(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRD_PCI:
		// Rdd = memd(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRD_PCR:
		// Rdd = memd(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRD_PI:
		// Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRD_PR:
		// Rdd = memd(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRDGP:
		// Rdd = memd(gp+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRH_IO:
		// Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRH_PBR:
		// Rd = memh(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRH_PCI:
		// Rd = memh(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRH_PCR:
		// Rd = memh(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRH_PI:
		// Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRH_PR:
		// Rd = memh(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRHGP:
		// Rd = memh(gp+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRI_IO:
		// Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRI_PBR:
		// Rd = memw(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRI_PCI:
		// Rd = memw(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRI_PCR:
		// Rd = memw(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRI_PI:
		// Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRI_PR:
		// Rd = memw(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRIGP:
		// Rd = memw(gp+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUB_IO:
		// Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUB_PBR:
		// Rd = memub(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRUB_PCI:
		// Rd = memub(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUB_PCR:
		// Rd = memub(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRUB_PI:
		// Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUB_PR:
		// Rd = memub(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRUBGP:
		// Rd = memub(gp+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUH_IO:
		// Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUH_PBR:
		// Rd = memuh(Rx++Mu:brev)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRUH_PCI:
		// Rd = memuh(Rx++#Ii:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUH_PCR:
		// Rd = memuh(Rx++I:circ(Mu))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRUH_PI:
		// Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADRUH_PR:
		// Rd = memuh(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADRUHGP:
		// Rd = memuh(gp+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_LOADW_AQ:
		// Rd = memw_aq(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_LOADW_LOCKED:
		// Rd = memw_locked(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L2_PLOADRBF_IO:
		// if (!Pt) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBF_PI:
		// if (!Pt) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBFNEW_IO:
		// if (!Pt.new) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBFNEW_PI:
		// if (!Pt.new) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBT_IO:
		// if (Pt) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBT_PI:
		// if (Pt) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBTNEW_IO:
		// if (Pt.new) Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRBTNEW_PI:
		// if (Pt.new) Rd = memb(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDF_IO:
		// if (!Pt) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDF_PI:
		// if (!Pt) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDFNEW_IO:
		// if (!Pt.new) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDFNEW_PI:
		// if (!Pt.new) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDT_IO:
		// if (Pt) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDT_PI:
		// if (Pt) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDTNEW_IO:
		// if (Pt.new) Rdd = memd(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRDTNEW_PI:
		// if (Pt.new) Rdd = memd(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHF_IO:
		// if (!Pt) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHF_PI:
		// if (!Pt) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHFNEW_IO:
		// if (!Pt.new) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHFNEW_PI:
		// if (!Pt.new) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHT_IO:
		// if (Pt) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHT_PI:
		// if (Pt) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHTNEW_IO:
		// if (Pt.new) Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRHTNEW_PI:
		// if (Pt.new) Rd = memh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRIF_IO:
		// if (!Pt) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRIF_PI:
		// if (!Pt) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRIFNEW_IO:
		// if (!Pt.new) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRIFNEW_PI:
		// if (!Pt.new) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRIT_IO:
		// if (Pt) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRIT_PI:
		// if (Pt) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRITNEW_IO:
		// if (Pt.new) Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRITNEW_PI:
		// if (Pt.new) Rd = memw(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBF_IO:
		// if (!Pt) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBF_PI:
		// if (!Pt) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBFNEW_IO:
		// if (!Pt.new) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBFNEW_PI:
		// if (!Pt.new) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBT_IO:
		// if (Pt) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBT_PI:
		// if (Pt) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBTNEW_IO:
		// if (Pt.new) Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUBTNEW_PI:
		// if (Pt.new) Rd = memub(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHF_IO:
		// if (!Pt) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHF_PI:
		// if (!Pt) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHFNEW_IO:
		// if (!Pt.new) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHFNEW_PI:
		// if (!Pt.new) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHT_IO:
		// if (Pt) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHT_PI:
		// if (Pt) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHTNEW_IO:
		// if (Pt.new) Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L2_PLOADRUHTNEW_PI:
		// if (Pt.new) Rd = memuh(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_ADD_MEMOPB_IO:
		// memb(Rs+#Ii) += Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_ADD_MEMOPH_IO:
		// memh(Rs+#Ii) += Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_ADD_MEMOPW_IO:
		// memw(Rs+#Ii) += Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_AND_MEMOPB_IO:
		// memb(Rs+#Ii) &= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_AND_MEMOPH_IO:
		// memh(Rs+#Ii) &= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_AND_MEMOPW_IO:
		// memw(Rs+#Ii) &= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IADD_MEMOPB_IO:
		// memb(Rs+#Ii) += #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IADD_MEMOPH_IO:
		// memh(Rs+#Ii) += #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IADD_MEMOPW_IO:
		// memw(Rs+#Ii) += #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IAND_MEMOPB_IO:
		// memb(Rs+#Ii) = clrbit(#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IAND_MEMOPH_IO:
		// memh(Rs+#Ii) = clrbit(#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IAND_MEMOPW_IO:
		// memw(Rs+#Ii) = clrbit(#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IOR_MEMOPB_IO:
		// memb(Rs+#Ii) = setbit(#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IOR_MEMOPH_IO:
		// memh(Rs+#Ii) = setbit(#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_IOR_MEMOPW_IO:
		// memw(Rs+#Ii) = setbit(#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_ISUB_MEMOPB_IO:
		// memb(Rs+#Ii) -= #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_ISUB_MEMOPH_IO:
		// memh(Rs+#Ii) -= #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_ISUB_MEMOPW_IO:
		// memw(Rs+#Ii) -= #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADALIGNB_AP:
		// Ryy = memb_fifo(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADALIGNB_UR:
		// Ryy = memb_fifo(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADALIGNH_AP:
		// Ryy = memh_fifo(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADALIGNH_UR:
		// Ryy = memh_fifo(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBSW2_AP:
		// Rd = membh(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBSW2_UR:
		// Rd = membh(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBSW4_AP:
		// Rdd = membh(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBSW4_UR:
		// Rdd = membh(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBZW2_AP:
		// Rd = memubh(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBZW2_UR:
		// Rd = memubh(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBZW4_AP:
		// Rdd = memubh(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADBZW4_UR:
		// Rdd = memubh(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADD_AQ:
		// Rdd = memd_aq(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_LOADD_LOCKED:
		// Rdd = memd_locked(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_LOADRB_AP:
		// Rd = memb(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRB_RR:
		// Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRB_UR:
		// Rd = memb(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRD_AP:
		// Rdd = memd(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRD_RR:
		// Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRD_UR:
		// Rdd = memd(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRH_AP:
		// Rd = memh(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRH_RR:
		// Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRH_UR:
		// Rd = memh(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRI_AP:
		// Rd = memw(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRI_RR:
		// Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRI_UR:
		// Rd = memw(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRUB_AP:
		// Rd = memub(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRUB_RR:
		// Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRUB_UR:
		// Rd = memub(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRUH_AP:
		// Rd = memuh(Re=#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRUH_RR:
		// Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_LOADRUH_UR:
		// Rd = memuh(Rt<<#Ii+#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_OR_MEMOPB_IO:
		// memb(Rs+#Ii) |= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_OR_MEMOPH_IO:
		// memh(Rs+#Ii) |= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_OR_MEMOPW_IO:
		// memw(Rs+#Ii) |= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBF_ABS:
		// if (!Pt) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBF_RR:
		// if (!Pv) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBFNEW_ABS:
		// if (!Pt.new) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBFNEW_RR:
		// if (!Pv.new) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBT_ABS:
		// if (Pt) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBT_RR:
		// if (Pv) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBTNEW_ABS:
		// if (Pt.new) Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRBTNEW_RR:
		// if (Pv.new) Rd = memb(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDF_ABS:
		// if (!Pt) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDF_RR:
		// if (!Pv) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDFNEW_ABS:
		// if (!Pt.new) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDFNEW_RR:
		// if (!Pv.new) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDT_ABS:
		// if (Pt) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDT_RR:
		// if (Pv) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDTNEW_ABS:
		// if (Pt.new) Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRDTNEW_RR:
		// if (Pv.new) Rdd = memd(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHF_ABS:
		// if (!Pt) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHF_RR:
		// if (!Pv) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHFNEW_ABS:
		// if (!Pt.new) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHFNEW_RR:
		// if (!Pv.new) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHT_ABS:
		// if (Pt) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHT_RR:
		// if (Pv) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHTNEW_ABS:
		// if (Pt.new) Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRHTNEW_RR:
		// if (Pv.new) Rd = memh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRIF_ABS:
		// if (!Pt) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRIF_RR:
		// if (!Pv) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRIFNEW_ABS:
		// if (!Pt.new) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRIFNEW_RR:
		// if (!Pv.new) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRIT_ABS:
		// if (Pt) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRIT_RR:
		// if (Pv) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRITNEW_ABS:
		// if (Pt.new) Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRITNEW_RR:
		// if (Pv.new) Rd = memw(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBF_ABS:
		// if (!Pt) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBF_RR:
		// if (!Pv) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBFNEW_ABS:
		// if (!Pt.new) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBFNEW_RR:
		// if (!Pv.new) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBT_ABS:
		// if (Pt) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBT_RR:
		// if (Pv) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBTNEW_ABS:
		// if (Pt.new) Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUBTNEW_RR:
		// if (Pv.new) Rd = memub(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHF_ABS:
		// if (!Pt) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHF_RR:
		// if (!Pv) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHFNEW_ABS:
		// if (!Pt.new) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHFNEW_RR:
		// if (!Pv.new) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHT_ABS:
		// if (Pt) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHT_RR:
		// if (Pv) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHTNEW_ABS:
		// if (Pt.new) Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_PLOADRUHTNEW_RR:
		// if (Pv.new) Rd = memuh(Rs+Rt<<#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_RETURN:
		// Rdd = dealloc_return(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_RETURN_F:
		// if (!Pv) Rdd = dealloc_return(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_RETURN_FNEW_PNT:
		// if (!Pv.new) Rdd = dealloc_return(Rs):nt:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_RETURN_FNEW_PT:
		// if (!Pv.new) Rdd = dealloc_return(Rs):t:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_RETURN_T:
		// if (Pv) Rdd = dealloc_return(Rs):raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_RETURN_TNEW_PNT:
		// if (Pv.new) Rdd = dealloc_return(Rs):nt:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_RETURN_TNEW_PT:
		// if (Pv.new) Rdd = dealloc_return(Rs):t:raw
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		op->val = UT64_MAX;
		break;
	case HEX_INS_L4_SUB_MEMOPB_IO:
		// memb(Rs+#Ii) -= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_SUB_MEMOPH_IO:
		// memh(Rs+#Ii) -= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L4_SUB_MEMOPW_IO:
		// memw(Rs+#Ii) -= Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_L6_MEMCPY:
		// memcpy(Rs,Rt,Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_ACCI:
		// Rx += add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_ACCII:
		// Rx += add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M2_CMACI_S0:
		// Rxx += cmpyi(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMACR_S0:
		// Rxx += cmpyr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMACS_S0:
		// Rxx += cmpy(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMACS_S1:
		// Rxx += cmpy(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMACSC_S0:
		// Rxx += cmpy(Rs,Rt*):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMACSC_S1:
		// Rxx += cmpy(Rs,Rt*):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYI_S0:
		// Rdd = cmpyi(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYR_S0:
		// Rdd = cmpyr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYRS_S0:
		// Rd = cmpy(Rs,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYRS_S1:
		// Rd = cmpy(Rs,Rt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYRSC_S0:
		// Rd = cmpy(Rs,Rt*):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYRSC_S1:
		// Rd = cmpy(Rs,Rt*):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYS_S0:
		// Rdd = cmpy(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYS_S1:
		// Rdd = cmpy(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYSC_S0:
		// Rdd = cmpy(Rs,Rt*):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CMPYSC_S1:
		// Rdd = cmpy(Rs,Rt*):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CNACS_S0:
		// Rxx -= cmpy(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CNACS_S1:
		// Rxx -= cmpy(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CNACSC_S0:
		// Rxx -= cmpy(Rs,Rt*):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_CNACSC_S1:
		// Rxx -= cmpy(Rs,Rt*):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYSS_ACC_S0:
		// Rxx += mpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYSS_NAC_S0:
		// Rxx -= mpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYSS_RND_S0:
		// Rd = mpy(Rs,Rt):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYSS_S0:
		// Rdd = mpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYUU_ACC_S0:
		// Rxx += mpyu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYUU_NAC_S0:
		// Rxx -= mpyu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_DPMPYUU_S0:
		// Rdd = mpyu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_HMMPYH_RS1:
		// Rd = mpy(Rs,Rt.h):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_HMMPYH_S1:
		// Rd = mpy(Rs,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_HMMPYL_RS1:
		// Rd = mpy(Rs,Rt.l):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_HMMPYL_S1:
		// Rd = mpy(Rs,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MACI:
		// Rx += mpyi(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MACSIN:
		// Rx -= mpyi(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M2_MACSIP:
		// Rx += mpyi(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M2_MMACHS_RS0:
		// Rxx += vmpywoh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACHS_RS1:
		// Rxx += vmpywoh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACHS_S0:
		// Rxx += vmpywoh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACHS_S1:
		// Rxx += vmpywoh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACLS_RS0:
		// Rxx += vmpyweh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACLS_RS1:
		// Rxx += vmpyweh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACLS_S0:
		// Rxx += vmpyweh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACLS_S1:
		// Rxx += vmpyweh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACUHS_RS0:
		// Rxx += vmpywouh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACUHS_RS1:
		// Rxx += vmpywouh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACUHS_S0:
		// Rxx += vmpywouh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACUHS_S1:
		// Rxx += vmpywouh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACULS_RS0:
		// Rxx += vmpyweuh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACULS_RS1:
		// Rxx += vmpyweuh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACULS_S0:
		// Rxx += vmpyweuh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMACULS_S1:
		// Rxx += vmpyweuh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYH_RS0:
		// Rdd = vmpywoh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYH_RS1:
		// Rdd = vmpywoh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYH_S0:
		// Rdd = vmpywoh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYH_S1:
		// Rdd = vmpywoh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYL_RS0:
		// Rdd = vmpyweh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYL_RS1:
		// Rdd = vmpyweh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYL_S0:
		// Rdd = vmpyweh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYL_S1:
		// Rdd = vmpyweh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUH_RS0:
		// Rdd = vmpywouh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUH_RS1:
		// Rdd = vmpywouh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUH_S0:
		// Rdd = vmpywouh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUH_S1:
		// Rdd = vmpywouh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUL_RS0:
		// Rdd = vmpyweuh(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUL_RS1:
		// Rdd = vmpyweuh(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUL_S0:
		// Rdd = vmpyweuh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MMPYUL_S1:
		// Rdd = vmpyweuh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MNACI:
		// Rx -= mpyi(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_HH_S0:
		// Rx += mpy(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_HH_S1:
		// Rx += mpy(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_HL_S0:
		// Rx += mpy(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_HL_S1:
		// Rx += mpy(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_LH_S0:
		// Rx += mpy(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_LH_S1:
		// Rx += mpy(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_LL_S0:
		// Rx += mpy(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_LL_S1:
		// Rx += mpy(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_HH_S0:
		// Rx += mpy(Rs.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_HH_S1:
		// Rx += mpy(Rs.h,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_HL_S0:
		// Rx += mpy(Rs.h,Rt.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_HL_S1:
		// Rx += mpy(Rs.h,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_LH_S0:
		// Rx += mpy(Rs.l,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_LH_S1:
		// Rx += mpy(Rs.l,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_LL_S0:
		// Rx += mpy(Rs.l,Rt.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_ACC_SAT_LL_S1:
		// Rx += mpy(Rs.l,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_HH_S0:
		// Rd = mpy(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_HH_S1:
		// Rd = mpy(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_HL_S0:
		// Rd = mpy(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_HL_S1:
		// Rd = mpy(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_LH_S0:
		// Rd = mpy(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_LH_S1:
		// Rd = mpy(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_LL_S0:
		// Rd = mpy(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_LL_S1:
		// Rd = mpy(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_HH_S0:
		// Rx -= mpy(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_HH_S1:
		// Rx -= mpy(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_HL_S0:
		// Rx -= mpy(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_HL_S1:
		// Rx -= mpy(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_LH_S0:
		// Rx -= mpy(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_LH_S1:
		// Rx -= mpy(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_LL_S0:
		// Rx -= mpy(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_LL_S1:
		// Rx -= mpy(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_HH_S0:
		// Rx -= mpy(Rs.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_HH_S1:
		// Rx -= mpy(Rs.h,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_HL_S0:
		// Rx -= mpy(Rs.h,Rt.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_HL_S1:
		// Rx -= mpy(Rs.h,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_LH_S0:
		// Rx -= mpy(Rs.l,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_LH_S1:
		// Rx -= mpy(Rs.l,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_LL_S0:
		// Rx -= mpy(Rs.l,Rt.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_NAC_SAT_LL_S1:
		// Rx -= mpy(Rs.l,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_HH_S0:
		// Rd = mpy(Rs.h,Rt.h):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_HH_S1:
		// Rd = mpy(Rs.h,Rt.h):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_HL_S0:
		// Rd = mpy(Rs.h,Rt.l):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_HL_S1:
		// Rd = mpy(Rs.h,Rt.l):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_LH_S0:
		// Rd = mpy(Rs.l,Rt.h):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_LH_S1:
		// Rd = mpy(Rs.l,Rt.h):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_LL_S0:
		// Rd = mpy(Rs.l,Rt.l):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_RND_LL_S1:
		// Rd = mpy(Rs.l,Rt.l):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_HH_S0:
		// Rd = mpy(Rs.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_HH_S1:
		// Rd = mpy(Rs.h,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_HL_S0:
		// Rd = mpy(Rs.h,Rt.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_HL_S1:
		// Rd = mpy(Rs.h,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_LH_S0:
		// Rd = mpy(Rs.l,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_LH_S1:
		// Rd = mpy(Rs.l,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_LL_S0:
		// Rd = mpy(Rs.l,Rt.l):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_LL_S1:
		// Rd = mpy(Rs.l,Rt.l):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_HH_S0:
		// Rd = mpy(Rs.h,Rt.h):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_HH_S1:
		// Rd = mpy(Rs.h,Rt.h):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_HL_S0:
		// Rd = mpy(Rs.h,Rt.l):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_HL_S1:
		// Rd = mpy(Rs.h,Rt.l):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_LH_S0:
		// Rd = mpy(Rs.l,Rt.h):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_LH_S1:
		// Rd = mpy(Rs.l,Rt.h):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_LL_S0:
		// Rd = mpy(Rs.l,Rt.l):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_SAT_RND_LL_S1:
		// Rd = mpy(Rs.l,Rt.l):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_UP:
		// Rd = mpy(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_UP_S1:
		// Rd = mpy(Rs,Rt):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPY_UP_S1_SAT:
		// Rd = mpy(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_HH_S0:
		// Rxx += mpy(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_HH_S1:
		// Rxx += mpy(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_HL_S0:
		// Rxx += mpy(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_HL_S1:
		// Rxx += mpy(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_LH_S0:
		// Rxx += mpy(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_LH_S1:
		// Rxx += mpy(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_LL_S0:
		// Rxx += mpy(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_ACC_LL_S1:
		// Rxx += mpy(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_HH_S0:
		// Rdd = mpy(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_HH_S1:
		// Rdd = mpy(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_HL_S0:
		// Rdd = mpy(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_HL_S1:
		// Rdd = mpy(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_LH_S0:
		// Rdd = mpy(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_LH_S1:
		// Rdd = mpy(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_LL_S0:
		// Rdd = mpy(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_LL_S1:
		// Rdd = mpy(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_HH_S0:
		// Rxx -= mpy(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_HH_S1:
		// Rxx -= mpy(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_HL_S0:
		// Rxx -= mpy(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_HL_S1:
		// Rxx -= mpy(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_LH_S0:
		// Rxx -= mpy(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_LH_S1:
		// Rxx -= mpy(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_LL_S0:
		// Rxx -= mpy(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_NAC_LL_S1:
		// Rxx -= mpy(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_HH_S0:
		// Rdd = mpy(Rs.h,Rt.h):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_HH_S1:
		// Rdd = mpy(Rs.h,Rt.h):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_HL_S0:
		// Rdd = mpy(Rs.h,Rt.l):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_HL_S1:
		// Rdd = mpy(Rs.h,Rt.l):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_LH_S0:
		// Rdd = mpy(Rs.l,Rt.h):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_LH_S1:
		// Rdd = mpy(Rs.l,Rt.h):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_LL_S0:
		// Rdd = mpy(Rs.l,Rt.l):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYD_RND_LL_S1:
		// Rdd = mpy(Rs.l,Rt.l):<<1:rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYI:
		// Rd = mpyi(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYSIN:
		// Rd = -mpyi(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M2_MPYSIP:
		// Rd = +mpyi(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M2_MPYSU_UP:
		// Rd = mpysu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_HH_S0:
		// Rx += mpyu(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_HH_S1:
		// Rx += mpyu(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_HL_S0:
		// Rx += mpyu(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_HL_S1:
		// Rx += mpyu(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_LH_S0:
		// Rx += mpyu(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_LH_S1:
		// Rx += mpyu(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_LL_S0:
		// Rx += mpyu(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_ACC_LL_S1:
		// Rx += mpyu(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_HH_S0:
		// Rd = mpyu(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_HH_S1:
		// Rd = mpyu(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_HL_S0:
		// Rd = mpyu(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_HL_S1:
		// Rd = mpyu(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_LH_S0:
		// Rd = mpyu(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_LH_S1:
		// Rd = mpyu(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_LL_S0:
		// Rd = mpyu(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_LL_S1:
		// Rd = mpyu(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_HH_S0:
		// Rx -= mpyu(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_HH_S1:
		// Rx -= mpyu(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_HL_S0:
		// Rx -= mpyu(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_HL_S1:
		// Rx -= mpyu(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_LH_S0:
		// Rx -= mpyu(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_LH_S1:
		// Rx -= mpyu(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_LL_S0:
		// Rx -= mpyu(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_NAC_LL_S1:
		// Rx -= mpyu(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYU_UP:
		// Rd = mpyu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_HH_S0:
		// Rxx += mpyu(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_HH_S1:
		// Rxx += mpyu(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_HL_S0:
		// Rxx += mpyu(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_HL_S1:
		// Rxx += mpyu(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_LH_S0:
		// Rxx += mpyu(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_LH_S1:
		// Rxx += mpyu(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_LL_S0:
		// Rxx += mpyu(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_ACC_LL_S1:
		// Rxx += mpyu(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_HH_S0:
		// Rdd = mpyu(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_HH_S1:
		// Rdd = mpyu(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_HL_S0:
		// Rdd = mpyu(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_HL_S1:
		// Rdd = mpyu(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_LH_S0:
		// Rdd = mpyu(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_LH_S1:
		// Rdd = mpyu(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_LL_S0:
		// Rdd = mpyu(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_LL_S1:
		// Rdd = mpyu(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_HH_S0:
		// Rxx -= mpyu(Rs.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_HH_S1:
		// Rxx -= mpyu(Rs.h,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_HL_S0:
		// Rxx -= mpyu(Rs.h,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_HL_S1:
		// Rxx -= mpyu(Rs.h,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_LH_S0:
		// Rxx -= mpyu(Rs.l,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_LH_S1:
		// Rxx -= mpyu(Rs.l,Rt.h):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_LL_S0:
		// Rxx -= mpyu(Rs.l,Rt.l)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_MPYUD_NAC_LL_S1:
		// Rxx -= mpyu(Rs.l,Rt.l):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_NACCI:
		// Rx -= add(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_NACCII:
		// Rx -= add(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M2_SUBACC:
		// Rx += sub(Rt,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VABSDIFFH:
		// Rdd = vabsdiffh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VABSDIFFW:
		// Rdd = vabsdiffw(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VCMAC_S0_SAT_I:
		// Rxx += vcmpyi(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VCMAC_S0_SAT_R:
		// Rxx += vcmpyr(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VCMPY_S0_SAT_I:
		// Rdd = vcmpyi(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VCMPY_S0_SAT_R:
		// Rdd = vcmpyr(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VCMPY_S1_SAT_I:
		// Rdd = vcmpyi(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VCMPY_S1_SAT_R:
		// Rdd = vcmpyr(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VDMACS_S0:
		// Rxx += vdmpy(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VDMACS_S1:
		// Rxx += vdmpy(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VDMPYRS_S0:
		// Rd = vdmpy(Rss,Rtt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VDMPYRS_S1:
		// Rd = vdmpy(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VDMPYS_S0:
		// Rdd = vdmpy(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VDMPYS_S1:
		// Rdd = vdmpy(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2:
		// Rxx += vmpyh(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2ES:
		// Rxx += vmpyeh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2ES_S0:
		// Rxx += vmpyeh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2ES_S1:
		// Rxx += vmpyeh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2S_S0:
		// Rxx += vmpyh(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2S_S1:
		// Rxx += vmpyh(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2SU_S0:
		// Rxx += vmpyhsu(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMAC2SU_S1:
		// Rxx += vmpyhsu(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2ES_S0:
		// Rdd = vmpyeh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2ES_S1:
		// Rdd = vmpyeh(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2S_S0:
		// Rdd = vmpyh(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2S_S0PACK:
		// Rd = vmpyh(Rs,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2S_S1:
		// Rdd = vmpyh(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2S_S1PACK:
		// Rd = vmpyh(Rs,Rt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2SU_S0:
		// Rdd = vmpyhsu(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VMPY2SU_S1:
		// Rdd = vmpyhsu(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRADDH:
		// Rd = vraddh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRADDUH:
		// Rd = vradduh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMACI_S0:
		// Rxx += vrcmpyi(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMACI_S0C:
		// Rxx += vrcmpyi(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMACR_S0:
		// Rxx += vrcmpyr(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMACR_S0C:
		// Rxx += vrcmpyr(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYI_S0:
		// Rdd = vrcmpyi(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYI_S0C:
		// Rdd = vrcmpyi(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYR_S0:
		// Rdd = vrcmpyr(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYR_S0C:
		// Rdd = vrcmpyr(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYS_ACC_S1_H:
		// Rxx += vrcmpys(Rss,Rtt):<<1:sat:raw:hi
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYS_ACC_S1_L:
		// Rxx += vrcmpys(Rss,Rtt):<<1:sat:raw:lo
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYS_S1_H:
		// Rdd = vrcmpys(Rss,Rtt):<<1:sat:raw:hi
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYS_S1_L:
		// Rdd = vrcmpys(Rss,Rtt):<<1:sat:raw:lo
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYS_S1RP_H:
		// Rd = vrcmpys(Rss,Rtt):<<1:rnd:sat:raw:hi
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRCMPYS_S1RP_L:
		// Rd = vrcmpys(Rss,Rtt):<<1:rnd:sat:raw:lo
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRMAC_S0:
		// Rxx += vrmpyh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_VRMPY_S0:
		// Rdd = vrmpyh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M2_XOR_XACC:
		// Rx ^= xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_AND_AND:
		// Rx &= and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_AND_ANDN:
		// Rx &= and(Rs,~Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_AND_OR:
		// Rx &= or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_AND_XOR:
		// Rx &= xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_CMPYI_WH:
		// Rd = cmpyiwh(Rss,Rt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_CMPYI_WHC:
		// Rd = cmpyiwh(Rss,Rt*):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_CMPYR_WH:
		// Rd = cmpyrwh(Rss,Rt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_CMPYR_WHC:
		// Rd = cmpyrwh(Rss,Rt*):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_MAC_UP_S1_SAT:
		// Rx += mpy(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_MPYRI_ADDI:
		// Rd = add(#Ii,mpyi(Rs,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M4_MPYRI_ADDR:
		// Rd = add(Ru,mpyi(Rs,#Ii))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M4_MPYRI_ADDR_U2:
		// Rd = add(Ru,mpyi(#Ii,Rs))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M4_MPYRR_ADDI:
		// Rd = add(#Ii,mpyi(Rs,Rt))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_M4_MPYRR_ADDR:
		// Ry = add(Ru,mpyi(Ryin,Rs))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_NAC_UP_S1_SAT:
		// Rx -= mpy(Rs,Rt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_OR_AND:
		// Rx |= and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_OR_ANDN:
		// Rx |= and(Rs,~Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_OR_OR:
		// Rx |= or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_OR_XOR:
		// Rx |= xor(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_PMPYW:
		// Rdd = pmpyw(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_PMPYW_ACC:
		// Rxx ^= pmpyw(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VPMPYH:
		// Rdd = vpmpyh(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VPMPYH_ACC:
		// Rxx ^= vpmpyh(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYEH_ACC_S0:
		// Rxx += vrmpyweh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYEH_ACC_S1:
		// Rxx += vrmpyweh(Rss,Rtt):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYEH_S0:
		// Rdd = vrmpyweh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYEH_S1:
		// Rdd = vrmpyweh(Rss,Rtt):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYOH_ACC_S0:
		// Rxx += vrmpywoh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYOH_ACC_S1:
		// Rxx += vrmpywoh(Rss,Rtt):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYOH_S0:
		// Rdd = vrmpywoh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_VRMPYOH_S1:
		// Rdd = vrmpywoh(Rss,Rtt):<<1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_XOR_AND:
		// Rx ^= and(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_XOR_ANDN:
		// Rx ^= and(Rs,~Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_XOR_OR:
		// Rx ^= or(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M4_XOR_XACC:
		// Rxx ^= xor(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VDMACBSU:
		// Rxx += vdmpybsu(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VDMPYBSU:
		// Rdd = vdmpybsu(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VMACBSU:
		// Rxx += vmpybsu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VMACBUU:
		// Rxx += vmpybu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VMPYBSU:
		// Rdd = vmpybsu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VMPYBUU:
		// Rdd = vmpybu(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VRMACBSU:
		// Rxx += vrmpybsu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VRMACBUU:
		// Rxx += vrmpybu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VRMPYBSU:
		// Rdd = vrmpybsu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M5_VRMPYBUU:
		// Rdd = vrmpybu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M6_VABSDIFFB:
		// Rdd = vabsdiffb(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M6_VABSDIFFUB:
		// Rdd = vabsdiffub(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYIW:
		// Rdd = cmpyiw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYIW_ACC:
		// Rxx += cmpyiw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYIWC:
		// Rdd = cmpyiw(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYIWC_ACC:
		// Rxx += cmpyiw(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYRW:
		// Rdd = cmpyrw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYRW_ACC:
		// Rxx += cmpyrw(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYRWC:
		// Rdd = cmpyrw(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_DCMPYRWC_ACC:
		// Rxx += cmpyrw(Rss,Rtt*)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYIW:
		// Rd = cmpyiw(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYIW_RND:
		// Rd = cmpyiw(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYIWC:
		// Rd = cmpyiw(Rss,Rtt*):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYIWC_RND:
		// Rd = cmpyiw(Rss,Rtt*):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYRW:
		// Rd = cmpyrw(Rss,Rtt):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYRW_RND:
		// Rd = cmpyrw(Rss,Rtt):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYRWC:
		// Rd = cmpyrw(Rss,Rtt*):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_M7_WCMPYRWC_RND:
		// Rd = cmpyrw(Rss,Rtt*):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_PS_LOADRBABS:
		// Rd = memb(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_LOADRDABS:
		// Rdd = memd(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_LOADRHABS:
		// Rd = memh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_LOADRIABS:
		// Rd = memw(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_LOADRUBABS:
		// Rd = memub(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_LOADRUHABS:
		// Rd = memuh(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERBABS:
		// memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERBNEWABS:
		// memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERDABS:
		// memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERFABS:
		// memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERHABS:
		// memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERHNEWABS:
		// memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERIABS:
		// memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_STORERINEWABS:
		// memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_PS_TRAP1:
		// trap1(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_R6_RELEASE_AT_VI:
		// release(Rs):at
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_R6_RELEASE_ST_VI:
		// release(Rs):st
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ADDASL_RRRI:
		// Rd = addasl(Rt,Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ALLOCFRAME:
		// allocframe(Rx,#Ii):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_P:
		// Rdd = asl(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_P_ACC:
		// Rxx += asl(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_P_AND:
		// Rxx &= asl(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_P_NAC:
		// Rxx -= asl(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_P_OR:
		// Rxx |= asl(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_P_XACC:
		// Rxx ^= asl(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R:
		// Rd = asl(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R_ACC:
		// Rx += asl(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R_AND:
		// Rx &= asl(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R_NAC:
		// Rx -= asl(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R_OR:
		// Rx |= asl(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R_SAT:
		// Rd = asl(Rs,#Ii):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_R_XACC:
		// Rx ^= asl(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_VH:
		// Rdd = vaslh(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_I_VW:
		// Rdd = vaslw(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASL_R_P:
		// Rdd = asl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_P_ACC:
		// Rxx += asl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_P_AND:
		// Rxx &= asl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_P_NAC:
		// Rxx -= asl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_P_OR:
		// Rxx |= asl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_P_XOR:
		// Rxx ^= asl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_R:
		// Rd = asl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_R_ACC:
		// Rx += asl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_R_AND:
		// Rx &= asl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_R_NAC:
		// Rx -= asl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_R_OR:
		// Rx |= asl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_R_SAT:
		// Rd = asl(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_VH:
		// Rdd = vaslh(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASL_R_VW:
		// Rdd = vaslw(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_I_P:
		// Rdd = asr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_P_ACC:
		// Rxx += asr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_P_AND:
		// Rxx &= asr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_P_NAC:
		// Rxx -= asr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_P_OR:
		// Rxx |= asr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_P_RND:
		// Rdd = asr(Rss,#Ii):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_R:
		// Rd = asr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_R_ACC:
		// Rx += asr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_R_AND:
		// Rx &= asr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_R_NAC:
		// Rx -= asr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_R_OR:
		// Rx |= asr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_R_RND:
		// Rd = asr(Rs,#Ii):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_SVW_TRUN:
		// Rd = vasrw(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_VH:
		// Rdd = vasrh(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_I_VW:
		// Rdd = vasrw(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_ASR_R_P:
		// Rdd = asr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_P_ACC:
		// Rxx += asr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_P_AND:
		// Rxx &= asr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_P_NAC:
		// Rxx -= asr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_P_OR:
		// Rxx |= asr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_P_XOR:
		// Rxx ^= asr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_R:
		// Rd = asr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_R_ACC:
		// Rx += asr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_R_AND:
		// Rx &= asr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_R_NAC:
		// Rx -= asr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_R_OR:
		// Rx |= asr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_R_SAT:
		// Rd = asr(Rs,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_SVW_TRUN:
		// Rd = vasrw(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_VH:
		// Rdd = vasrh(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_ASR_R_VW:
		// Rdd = vasrw(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_BREV:
		// Rd = brev(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_BREVP:
		// Rdd = brev(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CABACDECBIN:
		// Rdd = decbin(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CL0:
		// Rd = cl0(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CL0P:
		// Rd = cl0(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CL1:
		// Rd = cl1(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CL1P:
		// Rd = cl1(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CLB:
		// Rd = clb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CLBNORM:
		// Rd = normamt(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CLBP:
		// Rd = clb(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CLRBIT_I:
		// Rd = clrbit(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_CLRBIT_R:
		// Rd = clrbit(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CT0:
		// Rd = ct0(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CT0P:
		// Rd = ct0(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CT1:
		// Rd = ct1(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_CT1P:
		// Rd = ct1(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_DEINTERLEAVE:
		// Rdd = deinterleave(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_EXTRACTU:
		// Rd = extractu(Rs,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_EXTRACTU_RP:
		// Rd = extractu(Rs,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_EXTRACTUP:
		// Rdd = extractu(Rss,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_EXTRACTUP_RP:
		// Rdd = extractu(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_INSERT:
		// Rx = insert(Rs,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_INSERT_RP:
		// Rx = insert(Rs,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_INSERTP:
		// Rxx = insert(Rss,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_INSERTP_RP:
		// Rxx = insert(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_INTERLEAVE:
		// Rdd = interleave(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LFSP:
		// Rdd = lfs(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_P:
		// Rdd = lsl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_P_ACC:
		// Rxx += lsl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_P_AND:
		// Rxx &= lsl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_P_NAC:
		// Rxx -= lsl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_P_OR:
		// Rxx |= lsl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_P_XOR:
		// Rxx ^= lsl(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_R:
		// Rd = lsl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_R_ACC:
		// Rx += lsl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_R_AND:
		// Rx &= lsl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_R_NAC:
		// Rx -= lsl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_R_OR:
		// Rx |= lsl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_VH:
		// Rdd = vlslh(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSL_R_VW:
		// Rdd = vlslw(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_I_P:
		// Rdd = lsr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_P_ACC:
		// Rxx += lsr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_P_AND:
		// Rxx &= lsr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_P_NAC:
		// Rxx -= lsr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_P_OR:
		// Rxx |= lsr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_P_XACC:
		// Rxx ^= lsr(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_R:
		// Rd = lsr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_R_ACC:
		// Rx += lsr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_R_AND:
		// Rx &= lsr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_R_NAC:
		// Rx -= lsr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_R_OR:
		// Rx |= lsr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_R_XACC:
		// Rx ^= lsr(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_VH:
		// Rdd = vlsrh(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_I_VW:
		// Rdd = vlsrw(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_LSR_R_P:
		// Rdd = lsr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_P_ACC:
		// Rxx += lsr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_P_AND:
		// Rxx &= lsr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_P_NAC:
		// Rxx -= lsr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_P_OR:
		// Rxx |= lsr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_P_XOR:
		// Rxx ^= lsr(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_R:
		// Rd = lsr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_R_ACC:
		// Rx += lsr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_R_AND:
		// Rx &= lsr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_R_NAC:
		// Rx -= lsr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_R_OR:
		// Rx |= lsr(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_VH:
		// Rdd = vlsrh(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_LSR_R_VW:
		// Rdd = vlsrw(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_MASK:
		// Rd = mask(#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PACKHL:
		// Rdd = packhl(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_PARITYP:
		// Rd = parity(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_PSTORERBF_IO:
		// if (!Pv) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBF_PI:
		// if (!Pv) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBFNEW_PI:
		// if (!Pv.new) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBNEWF_IO:
		// if (!Pv) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBNEWF_PI:
		// if (!Pv) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBNEWFNEW_PI:
		// if (!Pv.new) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBNEWT_IO:
		// if (Pv) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBNEWT_PI:
		// if (Pv) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBNEWTNEW_PI:
		// if (Pv.new) memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBT_IO:
		// if (Pv) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBT_PI:
		// if (Pv) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERBTNEW_PI:
		// if (Pv.new) memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERDF_IO:
		// if (!Pv) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERDF_PI:
		// if (!Pv) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERDFNEW_PI:
		// if (!Pv.new) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERDT_IO:
		// if (Pv) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERDT_PI:
		// if (Pv) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERDTNEW_PI:
		// if (Pv.new) memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERFF_IO:
		// if (!Pv) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERFF_PI:
		// if (!Pv) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERFFNEW_PI:
		// if (!Pv.new) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERFT_IO:
		// if (Pv) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERFT_PI:
		// if (Pv) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERFTNEW_PI:
		// if (Pv.new) memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHF_IO:
		// if (!Pv) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHF_PI:
		// if (!Pv) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHFNEW_PI:
		// if (!Pv.new) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHNEWF_IO:
		// if (!Pv) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHNEWF_PI:
		// if (!Pv) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHNEWFNEW_PI:
		// if (!Pv.new) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHNEWT_IO:
		// if (Pv) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHNEWT_PI:
		// if (Pv) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHNEWTNEW_PI:
		// if (Pv.new) memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHT_IO:
		// if (Pv) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHT_PI:
		// if (Pv) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERHTNEW_PI:
		// if (Pv.new) memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERIF_IO:
		// if (!Pv) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERIF_PI:
		// if (!Pv) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERIFNEW_PI:
		// if (!Pv.new) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERINEWF_IO:
		// if (!Pv) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERINEWF_PI:
		// if (!Pv) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERINEWFNEW_PI:
		// if (!Pv.new) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERINEWT_IO:
		// if (Pv) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERINEWT_PI:
		// if (Pv) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERINEWTNEW_PI:
		// if (Pv.new) memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERIT_IO:
		// if (Pv) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERIT_PI:
		// if (Pv) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_PSTORERITNEW_PI:
		// if (Pv.new) memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_SETBIT_I:
		// Rd = setbit(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_SETBIT_R:
		// Rd = setbit(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_SHUFFEB:
		// Rdd = shuffeb(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_SHUFFEH:
		// Rdd = shuffeh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_SHUFFOB:
		// Rdd = shuffob(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_SHUFFOH:
		// Rdd = shuffoh(Rtt,Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERB_IO:
		// memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERB_PBR:
		// memb(Rx++Mu:brev) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERB_PCI:
		// memb(Rx++#Ii:circ(Mu)) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERB_PCR:
		// memb(Rx++I:circ(Mu)) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERB_PI:
		// memb(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERB_PR:
		// memb(Rx++Mu) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERBGP:
		// memb(gp+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERBNEW_IO:
		// memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERBNEW_PBR:
		// memb(Rx++Mu:brev) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERBNEW_PCI:
		// memb(Rx++#Ii:circ(Mu)) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERBNEW_PCR:
		// memb(Rx++I:circ(Mu)) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERBNEW_PI:
		// memb(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERBNEW_PR:
		// memb(Rx++Mu) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERBNEWGP:
		// memb(gp+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERD_IO:
		// memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERD_PBR:
		// memd(Rx++Mu:brev) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERD_PCI:
		// memd(Rx++#Ii:circ(Mu)) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERD_PCR:
		// memd(Rx++I:circ(Mu)) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERD_PI:
		// memd(Rx++#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERD_PR:
		// memd(Rx++Mu) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERDGP:
		// memd(gp+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERF_IO:
		// memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERF_PBR:
		// memh(Rx++Mu:brev) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERF_PCI:
		// memh(Rx++#Ii:circ(Mu)) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERF_PCR:
		// memh(Rx++I:circ(Mu)) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERF_PI:
		// memh(Rx++#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERF_PR:
		// memh(Rx++Mu) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERFGP:
		// memh(gp+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERH_IO:
		// memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERH_PBR:
		// memh(Rx++Mu:brev) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERH_PCI:
		// memh(Rx++#Ii:circ(Mu)) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERH_PCR:
		// memh(Rx++I:circ(Mu)) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERH_PI:
		// memh(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERH_PR:
		// memh(Rx++Mu) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERHGP:
		// memh(gp+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERHNEW_IO:
		// memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERHNEW_PBR:
		// memh(Rx++Mu:brev) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERHNEW_PCI:
		// memh(Rx++#Ii:circ(Mu)) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERHNEW_PCR:
		// memh(Rx++I:circ(Mu)) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERHNEW_PI:
		// memh(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERHNEW_PR:
		// memh(Rx++Mu) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERHNEWGP:
		// memh(gp+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERI_IO:
		// memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERI_PBR:
		// memw(Rx++Mu:brev) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERI_PCI:
		// memw(Rx++#Ii:circ(Mu)) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERI_PCR:
		// memw(Rx++I:circ(Mu)) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERI_PI:
		// memw(Rx++#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERI_PR:
		// memw(Rx++Mu) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERIGP:
		// memw(gp+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERINEW_IO:
		// memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERINEW_PBR:
		// memw(Rx++Mu:brev) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERINEW_PCI:
		// memw(Rx++#Ii:circ(Mu)) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERINEW_PCR:
		// memw(Rx++I:circ(Mu)) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERINEW_PI:
		// memw(Rx++#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STORERINEW_PR:
		// memw(Rx++Mu) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STORERINEWGP:
		// memw(gp+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_STOREW_LOCKED:
		// memw_locked(Rs,Pd) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STOREW_RL_AT_VI:
		// memw_rl(Rs):at = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_STOREW_RL_ST_VI:
		// memw_rl(Rs):st = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_SVSATHB:
		// Rd = vsathb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_SVSATHUB:
		// Rd = vsathub(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_TABLEIDXB:
		// Rx = tableidxb(Rs,#Ii,#II):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_TABLEIDXD:
		// Rx = tableidxd(Rs,#Ii,#II):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_TABLEIDXH:
		// Rx = tableidxh(Rs,#Ii,#II):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_TABLEIDXW:
		// Rx = tableidxw(Rs,#Ii,#II):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_TOGGLEBIT_I:
		// Rd = togglebit(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_TOGGLEBIT_R:
		// Rd = togglebit(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_TSTBIT_I:
		// Pd = tstbit(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_TSTBIT_R:
		// Pd = tstbit(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VALIGNIB:
		// Rdd = valignb(Rtt,Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_VALIGNRB:
		// Rdd = valignb(Rtt,Rss,Pu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VCNEGH:
		// Rdd = vcnegh(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VCROTATE:
		// Rdd = vcrotate(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VRCNEGH:
		// Rxx += vrcnegh(Rss,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VRNDPACKWH:
		// Rd = vrndwh(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VRNDPACKWHS:
		// Rd = vrndwh(Rss):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATHB:
		// Rd = vsathb(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATHB_NOPACK:
		// Rdd = vsathb(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATHUB:
		// Rd = vsathub(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATHUB_NOPACK:
		// Rdd = vsathub(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATWH:
		// Rd = vsatwh(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATWH_NOPACK:
		// Rdd = vsatwh(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATWUH:
		// Rd = vsatwuh(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSATWUH_NOPACK:
		// Rdd = vsatwuh(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSPLATRB:
		// Rd = vsplatb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSPLATRH:
		// Rdd = vsplath(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSPLICEIB:
		// Rdd = vspliceb(Rss,Rtt,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S2_VSPLICERB:
		// Rdd = vspliceb(Rss,Rtt,Pu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSXTBH:
		// Rdd = vsxtbh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VSXTHW:
		// Rdd = vsxthw(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VTRUNEHB:
		// Rd = vtrunehb(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VTRUNEWH:
		// Rdd = vtrunewh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VTRUNOHB:
		// Rd = vtrunohb(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VTRUNOWH:
		// Rdd = vtrunowh(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VZXTBH:
		// Rdd = vzxtbh(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S2_VZXTHW:
		// Rdd = vzxthw(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_ADDADDI:
		// Rd = add(Rs,add(Ru,#Ii))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_ADDI_ASL_RI:
		// Rx = add(#Ii,asl(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_ADDI_LSR_RI:
		// Rx = add(#Ii,lsr(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_ANDI_ASL_RI:
		// Rx = and(#Ii,asl(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_ANDI_LSR_RI:
		// Rx = and(#Ii,lsr(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_CLBADDI:
		// Rd = add(clb(Rs),#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_CLBPADDI:
		// Rd = add(clb(Rss),#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_CLBPNORM:
		// Rd = normamt(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_EXTRACT:
		// Rd = extract(Rs,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_EXTRACT_RP:
		// Rd = extract(Rs,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_EXTRACTP:
		// Rdd = extract(Rss,#Ii,#II)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_EXTRACTP_RP:
		// Rdd = extract(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_LSLI:
		// Rd = lsl(#Ii,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_NTSTBIT_I:
		// Pd = !tstbit(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_NTSTBIT_R:
		// Pd = !tstbit(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_OR_ANDI:
		// Rx |= and(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_OR_ANDIX:
		// Rx = or(Ru,and(Rxin,#Ii))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_OR_ORI:
		// Rx |= or(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_ORI_ASL_RI:
		// Rx = or(#Ii,asl(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_ORI_LSR_RI:
		// Rx = or(#Ii,lsr(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PARITY:
		// Rd = parity(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_PSTORERBF_ABS:
		// if (!Pv) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBF_RR:
		// if (!Pv) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBFNEW_ABS:
		// if (!Pv.new) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBFNEW_IO:
		// if (!Pv.new) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBFNEW_RR:
		// if (!Pv.new) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWF_ABS:
		// if (!Pv) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWF_RR:
		// if (!Pv) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWFNEW_ABS:
		// if (!Pv.new) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWFNEW_IO:
		// if (!Pv.new) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWFNEW_RR:
		// if (!Pv.new) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWT_ABS:
		// if (Pv) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWT_RR:
		// if (Pv) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWTNEW_ABS:
		// if (Pv.new) memb(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWTNEW_IO:
		// if (Pv.new) memb(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBNEWTNEW_RR:
		// if (Pv.new) memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBT_ABS:
		// if (Pv) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBT_RR:
		// if (Pv) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBTNEW_ABS:
		// if (Pv.new) memb(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBTNEW_IO:
		// if (Pv.new) memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERBTNEW_RR:
		// if (Pv.new) memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDF_ABS:
		// if (!Pv) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDF_RR:
		// if (!Pv) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDFNEW_ABS:
		// if (!Pv.new) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDFNEW_IO:
		// if (!Pv.new) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDFNEW_RR:
		// if (!Pv.new) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDT_ABS:
		// if (Pv) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDT_RR:
		// if (Pv) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDTNEW_ABS:
		// if (Pv.new) memd(#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDTNEW_IO:
		// if (Pv.new) memd(Rs+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERDTNEW_RR:
		// if (Pv.new) memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFF_ABS:
		// if (!Pv) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFF_RR:
		// if (!Pv) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFFNEW_ABS:
		// if (!Pv.new) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFFNEW_RR:
		// if (!Pv.new) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFT_ABS:
		// if (Pv) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFT_RR:
		// if (Pv) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFTNEW_ABS:
		// if (Pv.new) memh(#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERFTNEW_RR:
		// if (Pv.new) memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHF_ABS:
		// if (!Pv) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHF_RR:
		// if (!Pv) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHFNEW_ABS:
		// if (!Pv.new) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHFNEW_RR:
		// if (!Pv.new) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWF_ABS:
		// if (!Pv) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWF_RR:
		// if (!Pv) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWFNEW_ABS:
		// if (!Pv.new) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWFNEW_RR:
		// if (!Pv.new) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWT_ABS:
		// if (Pv) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWT_RR:
		// if (Pv) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWTNEW_ABS:
		// if (Pv.new) memh(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHNEWTNEW_RR:
		// if (Pv.new) memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHT_ABS:
		// if (Pv) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHT_RR:
		// if (Pv) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHTNEW_ABS:
		// if (Pv.new) memh(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERHTNEW_RR:
		// if (Pv.new) memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIF_ABS:
		// if (!Pv) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIF_RR:
		// if (!Pv) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIFNEW_ABS:
		// if (!Pv.new) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIFNEW_IO:
		// if (!Pv.new) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIFNEW_RR:
		// if (!Pv.new) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWF_ABS:
		// if (!Pv) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWF_RR:
		// if (!Pv) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWFNEW_ABS:
		// if (!Pv.new) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWFNEW_IO:
		// if (!Pv.new) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWFNEW_RR:
		// if (!Pv.new) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWT_ABS:
		// if (Pv) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWT_RR:
		// if (Pv) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWTNEW_ABS:
		// if (Pv.new) memw(#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWTNEW_IO:
		// if (Pv.new) memw(Rs+#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERINEWTNEW_RR:
		// if (Pv.new) memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIT_ABS:
		// if (Pv) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERIT_RR:
		// if (Pv) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERITNEW_ABS:
		// if (Pv.new) memw(#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERITNEW_IO:
		// if (Pv.new) memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_PSTORERITNEW_RR:
		// if (Pv.new) memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORED_LOCKED:
		// memd_locked(Rs,Pd) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_STORED_RL_AT_VI:
		// memd_rl(Rs):at = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_STORED_RL_ST_VI:
		// memd_rl(Rs):st = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_STOREIRB_IO:
		// memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRBF_IO:
		// if (!Pv) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRBFNEW_IO:
		// if (!Pv.new) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRBT_IO:
		// if (Pv) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRBTNEW_IO:
		// if (Pv.new) memb(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRH_IO:
		// memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRHF_IO:
		// if (!Pv) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRHFNEW_IO:
		// if (!Pv.new) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRHT_IO:
		// if (Pv) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRHTNEW_IO:
		// if (Pv.new) memh(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRI_IO:
		// memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRIF_IO:
		// if (!Pv) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRIFNEW_IO:
		// if (!Pv.new) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRIT_IO:
		// if (Pv) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STOREIRITNEW_IO:
		// if (Pv.new) memw(Rs+#Ii) = #II
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERB_AP:
		// memb(Re=#II) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERB_RR:
		// memb(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERB_UR:
		// memb(Ru<<#Ii+#II) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERBNEW_AP:
		// memb(Re=#II) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERBNEW_RR:
		// memb(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERBNEW_UR:
		// memb(Ru<<#Ii+#II) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERD_AP:
		// memd(Re=#II) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERD_RR:
		// memd(Rs+Ru<<#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERD_UR:
		// memd(Ru<<#Ii+#II) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERF_AP:
		// memh(Re=#II) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERF_RR:
		// memh(Rs+Ru<<#Ii) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERF_UR:
		// memh(Ru<<#Ii+#II) = Rt.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERH_AP:
		// memh(Re=#II) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERH_RR:
		// memh(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERH_UR:
		// memh(Ru<<#Ii+#II) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERHNEW_AP:
		// memh(Re=#II) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERHNEW_RR:
		// memh(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERHNEW_UR:
		// memh(Ru<<#Ii+#II) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERI_AP:
		// memw(Re=#II) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERI_RR:
		// memw(Rs+Ru<<#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERI_UR:
		// memw(Ru<<#Ii+#II) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERINEW_AP:
		// memw(Re=#II) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERINEW_RR:
		// memw(Rs+Ru<<#Ii) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_STORERINEW_UR:
		// memw(Ru<<#Ii+#II) = Nt.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_SUBADDI:
		// Rd = add(Rs,sub(#Ii,Ru))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_SUBI_ASL_RI:
		// Rx = sub(#Ii,asl(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_SUBI_LSR_RI:
		// Rx = sub(#Ii,lsr(Rxin,#II))
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_VRCROTATE:
		// Rdd = vrcrotate(Rss,Rt,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_VRCROTATE_ACC:
		// Rxx += vrcrotate(Rss,Rt,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S4_VXADDSUBH:
		// Rdd = vxaddsubh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_VXADDSUBHR:
		// Rdd = vxaddsubh(Rss,Rtt):rnd:>>1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_VXADDSUBW:
		// Rdd = vxaddsubw(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_VXSUBADDH:
		// Rdd = vxsubaddh(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_VXSUBADDHR:
		// Rdd = vxsubaddh(Rss,Rtt):rnd:>>1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S4_VXSUBADDW:
		// Rdd = vxsubaddw(Rss,Rtt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S5_ASRHUB_RND_SAT:
		// Rd = vasrhub(Rss,#Ii):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S5_ASRHUB_SAT:
		// Rd = vasrhub(Rss,#Ii):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S5_POPCOUNTP:
		// Rd = popcount(Rss)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S5_VASRHRND:
		// Rdd = vasrh(Rss,#Ii):raw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_P:
		// Rdd = rol(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_P_ACC:
		// Rxx += rol(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_P_AND:
		// Rxx &= rol(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_P_NAC:
		// Rxx -= rol(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_P_OR:
		// Rxx |= rol(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_P_XACC:
		// Rxx ^= rol(Rss,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_R:
		// Rd = rol(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_R_ACC:
		// Rx += rol(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_R_AND:
		// Rx &= rol(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_R_NAC:
		// Rx -= rol(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_R_OR:
		// Rx |= rol(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_ROL_I_R_XACC:
		// Rx ^= rol(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_S6_VSPLATRBP:
		// Rdd = vsplatb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S6_VTRUNEHB_PPP:
		// Rdd = vtrunehb(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_S6_VTRUNOHB_PPP:
		// Rdd = vtrunohb(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_EXTRACTW:
		// Rd = vextract(Vu,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_LVSPLATB:
		// Vd.b = vsplat(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_LVSPLATH:
		// Vd.h = vsplat(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_LVSPLATW:
		// Vd = vsplat(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_AND:
		// Qd = and(Qs,Qt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_AND_N:
		// Qd = and(Qs,!Qt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_NOT:
		// Qd = not(Qs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_OR:
		// Qd = or(Qs,Qt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_OR_N:
		// Qd = or(Qs,!Qt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_SCALAR2:
		// Qd = vsetq(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_SCALAR2V2:
		// Qd = vsetq2(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_PRED_XOR:
		// Qd = xor(Qs,Qt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_SHUFFEQH:
		// Qd.b = vshuffe(Qs.h,Qt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_SHUFFEQW:
		// Qd.h = vshuffe(Qs.w,Qt.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_V6MPYHUBS10:
		// Vdd.w = v6mpy(Vuu.ub,Vvv.b,#Ii):h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_V6MPYHUBS10_VXX:
		// Vxx.w += v6mpy(Vuu.ub,Vvv.b,#Ii):h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_V6MPYVUBS10:
		// Vdd.w = v6mpy(Vuu.ub,Vvv.b,#Ii):v
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_V6MPYVUBS10_VXX:
		// Vxx.w += v6mpy(Vuu.ub,Vvv.b,#Ii):v
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32UB_AI:
		// Vd = vmemu(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32UB_PI:
		// Vd = vmemu(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32UB_PPU:
		// Vd = vmemu(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_AI:
		// Vd = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_AI:
		// Vd.cur = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_NPRED_AI:
		// if (!Pv) Vd.cur = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_NPRED_PI:
		// if (!Pv) Vd.cur = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_NPRED_PPU:
		// if (!Pv) Vd.cur = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_PI:
		// Vd.cur = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_PPU:
		// Vd.cur = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_PRED_AI:
		// if (Pv) Vd.cur = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_PRED_PI:
		// if (Pv) Vd.cur = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_CUR_PRED_PPU:
		// if (Pv) Vd.cur = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NPRED_AI:
		// if (!Pv) Vd = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NPRED_PI:
		// if (!Pv) Vd = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NPRED_PPU:
		// if (!Pv) Vd = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_AI:
		// Vd = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_AI:
		// Vd.cur = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_NPRED_AI:
		// if (!Pv) Vd.cur = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_NPRED_PI:
		// if (!Pv) Vd.cur = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_NPRED_PPU:
		// if (!Pv) Vd.cur = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PI:
		// Vd.cur = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PPU:
		// Vd.cur = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PRED_AI:
		// if (Pv) Vd.cur = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PRED_PI:
		// if (Pv) Vd.cur = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_CUR_PRED_PPU:
		// if (Pv) Vd.cur = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_NPRED_AI:
		// if (!Pv) Vd = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_NPRED_PI:
		// if (!Pv) Vd = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_NPRED_PPU:
		// if (!Pv) Vd = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_PI:
		// Vd = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_PPU:
		// Vd = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_PRED_AI:
		// if (Pv) Vd = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_PRED_PI:
		// if (Pv) Vd = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_PRED_PPU:
		// if (Pv) Vd = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_AI:
		// Vd.tmp = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_NPRED_AI:
		// if (!Pv) Vd.tmp = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_NPRED_PI:
		// if (!Pv) Vd.tmp = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_NPRED_PPU:
		// if (!Pv) Vd.tmp = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PI:
		// Vd.tmp = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PPU:
		// Vd.tmp = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PRED_AI:
		// if (Pv) Vd.tmp = vmem(Rt+#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PRED_PI:
		// if (Pv) Vd.tmp = vmem(Rx++#Ii):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_NT_TMP_PRED_PPU:
		// if (Pv) Vd.tmp = vmem(Rx++Mu):nt
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_PI:
		// Vd = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_PPU:
		// Vd = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_PRED_AI:
		// if (Pv) Vd = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_PRED_PI:
		// if (Pv) Vd = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_PRED_PPU:
		// if (Pv) Vd = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_AI:
		// Vd.tmp = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_NPRED_AI:
		// if (!Pv) Vd.tmp = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_NPRED_PI:
		// if (!Pv) Vd.tmp = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_NPRED_PPU:
		// if (!Pv) Vd.tmp = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_PI:
		// Vd.tmp = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_PPU:
		// Vd.tmp = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_PRED_AI:
		// if (Pv) Vd.tmp = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_PRED_PI:
		// if (Pv) Vd.tmp = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VL32B_TMP_PRED_PPU:
		// if (Pv) Vd.tmp = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32UB_AI:
		// vmemu(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32UB_NPRED_AI:
		// if (!Pv) vmemu(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32UB_NPRED_PI:
		// if (!Pv) vmemu(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32UB_NPRED_PPU:
		// if (!Pv) vmemu(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32UB_PI:
		// vmemu(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32UB_PPU:
		// vmemu(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32UB_PRED_AI:
		// if (Pv) vmemu(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32UB_PRED_PI:
		// if (Pv) vmemu(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32UB_PRED_PPU:
		// if (Pv) vmemu(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_AI:
		// vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_AI:
		// vmem(Rt+#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_PI:
		// vmem(Rx++#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_PPU:
		// vmem(Rx++Mu) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_PRED_AI:
		// if (Pv) vmem(Rt+#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_PRED_PI:
		// if (Pv) vmem(Rx++#Ii) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NEW_PRED_PPU:
		// if (Pv) vmem(Rx++Mu) = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NQPRED_AI:
		// if (!Qv) vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NQPRED_PI:
		// if (!Qv) vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NQPRED_PPU:
		// if (!Qv) vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_AI:
		// vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_AI:
		// vmem(Rt+#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PI:
		// vmem(Rx++#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PPU:
		// vmem(Rx++Mu):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PRED_AI:
		// if (Pv) vmem(Rt+#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PRED_PI:
		// if (Pv) vmem(Rx++#Ii):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NEW_PRED_PPU:
		// if (Pv) vmem(Rx++Mu):nt = Os.new
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NPRED_AI:
		// if (!Pv) vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NPRED_PI:
		// if (!Pv) vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NPRED_PPU:
		// if (!Pv) vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NQPRED_AI:
		// if (!Qv) vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NQPRED_PI:
		// if (!Qv) vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_NQPRED_PPU:
		// if (!Qv) vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_PI:
		// vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_PPU:
		// vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_PRED_AI:
		// if (Pv) vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_PRED_PI:
		// if (Pv) vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_PRED_PPU:
		// if (Pv) vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_QPRED_AI:
		// if (Qv) vmem(Rt+#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_QPRED_PI:
		// if (Qv) vmem(Rx++#Ii):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_NT_QPRED_PPU:
		// if (Qv) vmem(Rx++Mu):nt = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_PI:
		// vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_PPU:
		// vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_PRED_AI:
		// if (Pv) vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_PRED_PI:
		// if (Pv) vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_PRED_PPU:
		// if (Pv) vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_QPRED_AI:
		// if (Qv) vmem(Rt+#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_QPRED_PI:
		// if (Qv) vmem(Rx++#Ii) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_QPRED_PPU:
		// if (Qv) vmem(Rx++Mu) = Vs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VS32B_SRLS_AI:
		// vmem(Rt+#Ii):scatter_release
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_SRLS_PI:
		// vmem(Rx++#Ii):scatter_release
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VS32B_SRLS_PPU:
		// vmem(Rx++Mu):scatter_release
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSB:
		// Vd.b = vabs(Vu.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSB_SAT:
		// Vd.b = vabs(Vu.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSDIFFH:
		// Vd.uh = vabsdiff(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSDIFFUB:
		// Vd.ub = vabsdiff(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSDIFFUH:
		// Vd.uh = vabsdiff(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSDIFFW:
		// Vd.uw = vabsdiff(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSH:
		// Vd.h = vabs(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSH_SAT:
		// Vd.h = vabs(Vu.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSW:
		// Vd.w = vabs(Vu.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VABSW_SAT:
		// Vd.w = vabs(Vu.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDB:
		// Vd.b = vadd(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDB_DV:
		// Vdd.b = vadd(Vuu.b,Vvv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDBNQ:
		// if (!Qv) Vx.b += Vu.b
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDBQ:
		// if (Qv) Vx.b += Vu.b
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDBSAT:
		// Vd.b = vadd(Vu.b,Vv.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDBSAT_DV:
		// Vdd.b = vadd(Vuu.b,Vvv.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDCARRY:
		// Vd.w = vadd(Vu.w,Vv.w,Qx):carry
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDCARRYO:
		// Vd.w,Qe = vadd(Vu.w,Vv.w):carry
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDCARRYSAT:
		// Vd.w = vadd(Vu.w,Vv.w,Qs):carry:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDCLBH:
		// Vd.h = vadd(vclb(Vu.h),Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDCLBW:
		// Vd.w = vadd(vclb(Vu.w),Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDH:
		// Vd.h = vadd(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDH_DV:
		// Vdd.h = vadd(Vuu.h,Vvv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDHNQ:
		// if (!Qv) Vx.h += Vu.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDHQ:
		// if (Qv) Vx.h += Vu.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDHSAT:
		// Vd.h = vadd(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDHSAT_DV:
		// Vdd.h = vadd(Vuu.h,Vvv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDHW:
		// Vdd.w = vadd(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDHW_ACC:
		// Vxx.w += vadd(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUBH:
		// Vdd.h = vadd(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUBH_ACC:
		// Vxx.h += vadd(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUBSAT:
		// Vd.ub = vadd(Vu.ub,Vv.ub):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUBSAT_DV:
		// Vdd.ub = vadd(Vuu.ub,Vvv.ub):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUBUBB_SAT:
		// Vd.ub = vadd(Vu.ub,Vv.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUHSAT:
		// Vd.uh = vadd(Vu.uh,Vv.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUHSAT_DV:
		// Vdd.uh = vadd(Vuu.uh,Vvv.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUHW:
		// Vdd.w = vadd(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUHW_ACC:
		// Vxx.w += vadd(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUWSAT:
		// Vd.uw = vadd(Vu.uw,Vv.uw):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDUWSAT_DV:
		// Vdd.uw = vadd(Vuu.uw,Vvv.uw):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDW:
		// Vd.w = vadd(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDW_DV:
		// Vdd.w = vadd(Vuu.w,Vvv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDWNQ:
		// if (!Qv) Vx.w += Vu.w
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDWQ:
		// if (Qv) Vx.w += Vu.w
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDWSAT:
		// Vd.w = vadd(Vu.w,Vv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VADDWSAT_DV:
		// Vdd.w = vadd(Vuu.w,Vvv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VALIGNB:
		// Vd = valign(Vu,Vv,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VALIGNBI:
		// Vd = valign(Vu,Vv,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VAND:
		// Vd = vand(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDNQRT:
		// Vd = vand(!Qu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDNQRT_ACC:
		// Vx |= vand(!Qu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDQRT:
		// Vd = vand(Qu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDQRT_ACC:
		// Vx |= vand(Qu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDVNQV:
		// Vd = vand(!Qv,Vu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDVQV:
		// Vd = vand(Qv,Vu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDVRT:
		// Qd = vand(Vu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VANDVRT_ACC:
		// Qx |= vand(Vu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASLH:
		// Vd.h = vasl(Vu.h,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASLH_ACC:
		// Vx.h += vasl(Vu.h,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASLHV:
		// Vd.h = vasl(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASLW:
		// Vd.w = vasl(Vu.w,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASLW_ACC:
		// Vx.w += vasl(Vu.w,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASLWV:
		// Vd.w = vasl(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASR_INTO:
		// Vxx.w = vasrinto(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRH:
		// Vd.h = vasr(Vu.h,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRH_ACC:
		// Vx.h += vasr(Vu.h,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRHBRNDSAT:
		// Vd.b = vasr(Vu.h,Vv.h,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRHBSAT:
		// Vd.b = vasr(Vu.h,Vv.h,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRHUBRNDSAT:
		// Vd.ub = vasr(Vu.h,Vv.h,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRHUBSAT:
		// Vd.ub = vasr(Vu.h,Vv.h,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRHV:
		// Vd.h = vasr(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRUHUBRNDSAT:
		// Vd.ub = vasr(Vu.uh,Vv.uh,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRUHUBSAT:
		// Vd.ub = vasr(Vu.uh,Vv.uh,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRUWUHRNDSAT:
		// Vd.uh = vasr(Vu.uw,Vv.uw,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRUWUHSAT:
		// Vd.uh = vasr(Vu.uw,Vv.uw,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRW:
		// Vd.w = vasr(Vu.w,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRW_ACC:
		// Vx.w += vasr(Vu.w,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRWH:
		// Vd.h = vasr(Vu.w,Vv.w,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRWHRNDSAT:
		// Vd.h = vasr(Vu.w,Vv.w,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRWHSAT:
		// Vd.h = vasr(Vu.w,Vv.w,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRWUHRNDSAT:
		// Vd.uh = vasr(Vu.w,Vv.w,Rt):rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRWUHSAT:
		// Vd.uh = vasr(Vu.w,Vv.w,Rt):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASRWV:
		// Vd.w = vasr(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VASSIGN:
		// Vd = Vu
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGB:
		// Vd.b = vavg(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGBRND:
		// Vd.b = vavg(Vu.b,Vv.b):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGH:
		// Vd.h = vavg(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGHRND:
		// Vd.h = vavg(Vu.h,Vv.h):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGUB:
		// Vd.ub = vavg(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGUBRND:
		// Vd.ub = vavg(Vu.ub,Vv.ub):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGUH:
		// Vd.uh = vavg(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGUHRND:
		// Vd.uh = vavg(Vu.uh,Vv.uh):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGUW:
		// Vd.uw = vavg(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGUWRND:
		// Vd.uw = vavg(Vu.uw,Vv.uw):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGW:
		// Vd.w = vavg(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VAVGWRND:
		// Vd.w = vavg(Vu.w,Vv.w):rnd
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VCCOMBINE:
		// if (Ps) Vdd = vcombine(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VCL0H:
		// Vd.uh = vcl0(Vu.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VCL0W:
		// Vd.uw = vcl0(Vu.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VCMOV:
		// if (Ps) Vd = Vu
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VCOMBINE:
		// Vdd = vcombine(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDEAL:
		// vdeal(Vy,Vx,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDEALB:
		// Vd.b = vdeal(Vu.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDEALB4W:
		// Vd.b = vdeale(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDEALH:
		// Vd.h = vdeal(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDEALVDD:
		// Vdd = vdeal(Vu,Vv,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDELTA:
		// Vd = vdelta(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYBUS:
		// Vd.h = vdmpy(Vu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYBUS_ACC:
		// Vx.h += vdmpy(Vu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYBUS_DV:
		// Vdd.h = vdmpy(Vuu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYBUS_DV_ACC:
		// Vxx.h += vdmpy(Vuu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHB:
		// Vd.w = vdmpy(Vu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHB_ACC:
		// Vx.w += vdmpy(Vu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHB_DV:
		// Vdd.w = vdmpy(Vuu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHB_DV_ACC:
		// Vxx.w += vdmpy(Vuu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHISAT:
		// Vd.w = vdmpy(Vuu.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHISAT_ACC:
		// Vx.w += vdmpy(Vuu.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHSAT:
		// Vd.w = vdmpy(Vu.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHSAT_ACC:
		// Vx.w += vdmpy(Vu.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHSUISAT:
		// Vd.w = vdmpy(Vuu.h,Rt.uh,#1):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHSUISAT_ACC:
		// Vx.w += vdmpy(Vuu.h,Rt.uh,#1):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHSUSAT:
		// Vd.w = vdmpy(Vu.h,Rt.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHSUSAT_ACC:
		// Vx.w += vdmpy(Vu.h,Rt.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHVSAT:
		// Vd.w = vdmpy(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDMPYHVSAT_ACC:
		// Vx.w += vdmpy(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDSADUH:
		// Vdd.uw = vdsad(Vuu.uh,Rt.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VDSADUH_ACC:
		// Vxx.uw += vdsad(Vuu.uh,Rt.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQB:
		// Qd = vcmp.eq(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQB_AND:
		// Qx &= vcmp.eq(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQB_OR:
		// Qx |= vcmp.eq(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQB_XOR:
		// Qx ^= vcmp.eq(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQH:
		// Qd = vcmp.eq(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQH_AND:
		// Qx &= vcmp.eq(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQH_OR:
		// Qx |= vcmp.eq(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQH_XOR:
		// Qx ^= vcmp.eq(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQW:
		// Qd = vcmp.eq(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQW_AND:
		// Qx &= vcmp.eq(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQW_OR:
		// Qx |= vcmp.eq(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VEQW_XOR:
		// Qx ^= vcmp.eq(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGATHERMH:
		// vtmp.h = vgather(Rt,Mu,Vv.h).h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGATHERMHQ:
		// if (Qs) vtmp.h = vgather(Rt,Mu,Vv.h).h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGATHERMHW:
		// vtmp.h = vgather(Rt,Mu,Vvv.w).h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGATHERMHWQ:
		// if (Qs) vtmp.h = vgather(Rt,Mu,Vvv.w).h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGATHERMW:
		// vtmp.w = vgather(Rt,Mu,Vv.w).w
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGATHERMWQ:
		// if (Qs) vtmp.w = vgather(Rt,Mu,Vv.w).w
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTB:
		// Qd = vcmp.gt(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTB_AND:
		// Qx &= vcmp.gt(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTB_OR:
		// Qx |= vcmp.gt(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTB_XOR:
		// Qx ^= vcmp.gt(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTH:
		// Qd = vcmp.gt(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTH_AND:
		// Qx &= vcmp.gt(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTH_OR:
		// Qx |= vcmp.gt(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTH_XOR:
		// Qx ^= vcmp.gt(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUB:
		// Qd = vcmp.gt(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUB_AND:
		// Qx &= vcmp.gt(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUB_OR:
		// Qx |= vcmp.gt(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUB_XOR:
		// Qx ^= vcmp.gt(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUH:
		// Qd = vcmp.gt(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUH_AND:
		// Qx &= vcmp.gt(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUH_OR:
		// Qx |= vcmp.gt(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUH_XOR:
		// Qx ^= vcmp.gt(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUW:
		// Qd = vcmp.gt(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUW_AND:
		// Qx &= vcmp.gt(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUW_OR:
		// Qx |= vcmp.gt(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTUW_XOR:
		// Qx ^= vcmp.gt(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTW:
		// Qd = vcmp.gt(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTW_AND:
		// Qx &= vcmp.gt(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTW_OR:
		// Qx |= vcmp.gt(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VGTW_XOR:
		// Qx ^= vcmp.gt(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VHIST:
		// vhist
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VHISTQ:
		// vhist(Qv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VINSERTWR:
		// Vx.w = vinsert(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLALIGNB:
		// Vd = vlalign(Vu,Vv,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLALIGNBI:
		// Vd = vlalign(Vu,Vv,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VLSRB:
		// Vd.ub = vlsr(Vu.ub,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLSRH:
		// Vd.uh = vlsr(Vu.uh,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLSRHV:
		// Vd.h = vlsr(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLSRW:
		// Vd.uw = vlsr(Vu.uw,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLSRWV:
		// Vd.w = vlsr(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUT4:
		// Vd.h = vlut4(Vu.uh,Rtt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVVB:
		// Vd.b = vlut32(Vu.b,Vv.b,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVVB_NM:
		// Vd.b = vlut32(Vu.b,Vv.b,Rt):nomatch
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVVB_ORACC:
		// Vx.b |= vlut32(Vu.b,Vv.b,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVVB_ORACCI:
		// Vx.b |= vlut32(Vu.b,Vv.b,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VLUTVVBI:
		// Vd.b = vlut32(Vu.b,Vv.b,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VLUTVWH:
		// Vdd.h = vlut16(Vu.b,Vv.h,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVWH_NM:
		// Vdd.h = vlut16(Vu.b,Vv.h,Rt):nomatch
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVWH_ORACC:
		// Vxx.h |= vlut16(Vu.b,Vv.h,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VLUTVWH_ORACCI:
		// Vxx.h |= vlut16(Vu.b,Vv.h,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VLUTVWHI:
		// Vdd.h = vlut16(Vu.b,Vv.h,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VMAXB:
		// Vd.b = vmax(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMAXH:
		// Vd.h = vmax(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMAXUB:
		// Vd.ub = vmax(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMAXUH:
		// Vd.uh = vmax(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMAXW:
		// Vd.w = vmax(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMINB:
		// Vd.b = vmin(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMINH:
		// Vd.h = vmin(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMINUB:
		// Vd.ub = vmin(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMINUH:
		// Vd.uh = vmin(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMINW:
		// Vd.w = vmin(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPABUS:
		// Vdd.h = vmpa(Vuu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPABUS_ACC:
		// Vxx.h += vmpa(Vuu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPABUSV:
		// Vdd.h = vmpa(Vuu.ub,Vvv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPABUU:
		// Vdd.h = vmpa(Vuu.ub,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPABUU_ACC:
		// Vxx.h += vmpa(Vuu.ub,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPABUUV:
		// Vdd.h = vmpa(Vuu.ub,Vvv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPAHB:
		// Vdd.w = vmpa(Vuu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPAHB_ACC:
		// Vxx.w += vmpa(Vuu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPAHHSAT:
		// Vx.h = vmpa(Vxin.h,Vu.h,Rtt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPAUHB:
		// Vdd.w = vmpa(Vuu.uh,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPAUHB_ACC:
		// Vxx.w += vmpa(Vuu.uh,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPAUHUHSAT:
		// Vx.h = vmpa(Vxin.h,Vu.uh,Rtt.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPSUHUHSAT:
		// Vx.h = vmps(Vxin.h,Vu.uh,Rtt.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYBUS:
		// Vdd.h = vmpy(Vu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYBUS_ACC:
		// Vxx.h += vmpy(Vu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYBUSV:
		// Vdd.h = vmpy(Vu.ub,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYBUSV_ACC:
		// Vxx.h += vmpy(Vu.ub,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYBV:
		// Vdd.h = vmpy(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYBV_ACC:
		// Vxx.h += vmpy(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYEWUH:
		// Vd.w = vmpye(Vu.w,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYEWUH_64:
		// Vdd = vmpye(Vu.w,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYH:
		// Vdd.w = vmpy(Vu.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYH_ACC:
		// Vxx.w += vmpy(Vu.h,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHSAT_ACC:
		// Vxx.w += vmpy(Vu.h,Rt.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHSRS:
		// Vd.h = vmpy(Vu.h,Rt.h):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHSS:
		// Vd.h = vmpy(Vu.h,Rt.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHUS:
		// Vdd.w = vmpy(Vu.h,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHUS_ACC:
		// Vxx.w += vmpy(Vu.h,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHV:
		// Vdd.w = vmpy(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHV_ACC:
		// Vxx.w += vmpy(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYHVSRS:
		// Vd.h = vmpy(Vu.h,Vv.h):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIEOH:
		// Vd.w = vmpyieo(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIEWH_ACC:
		// Vx.w += vmpyie(Vu.w,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIEWUH:
		// Vd.w = vmpyie(Vu.w,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIEWUH_ACC:
		// Vx.w += vmpyie(Vu.w,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIH:
		// Vd.h = vmpyi(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIH_ACC:
		// Vx.h += vmpyi(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIHB:
		// Vd.h = vmpyi(Vu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIHB_ACC:
		// Vx.h += vmpyi(Vu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIOWH:
		// Vd.w = vmpyio(Vu.w,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIWB:
		// Vd.w = vmpyi(Vu.w,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIWB_ACC:
		// Vx.w += vmpyi(Vu.w,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIWH:
		// Vd.w = vmpyi(Vu.w,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIWH_ACC:
		// Vx.w += vmpyi(Vu.w,Rt.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIWUB:
		// Vd.w = vmpyi(Vu.w,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYIWUB_ACC:
		// Vx.w += vmpyi(Vu.w,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYOWH:
		// Vd.w = vmpyo(Vu.w,Vv.h):<<1:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYOWH_64_ACC:
		// Vxx += vmpyo(Vu.w,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYOWH_RND:
		// Vd.w = vmpyo(Vu.w,Vv.h):<<1:rnd:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYOWH_RND_SACC:
		// Vx.w += vmpyo(Vu.w,Vv.h):<<1:rnd:sat:shift
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYOWH_SACC:
		// Vx.w += vmpyo(Vu.w,Vv.h):<<1:sat:shift
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUB:
		// Vdd.uh = vmpy(Vu.ub,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUB_ACC:
		// Vxx.uh += vmpy(Vu.ub,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUBV:
		// Vdd.uh = vmpy(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUBV_ACC:
		// Vxx.uh += vmpy(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUH:
		// Vdd.uw = vmpy(Vu.uh,Rt.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUH_ACC:
		// Vxx.uw += vmpy(Vu.uh,Rt.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUHE:
		// Vd.uw = vmpye(Vu.uh,Rt.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUHE_ACC:
		// Vx.uw += vmpye(Vu.uh,Rt.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUHV:
		// Vdd.uw = vmpy(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMPYUHV_ACC:
		// Vxx.uw += vmpy(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VMUX:
		// Vd = vmux(Qt,Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNAVGB:
		// Vd.b = vnavg(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNAVGH:
		// Vd.h = vnavg(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNAVGUB:
		// Vd.b = vnavg(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNAVGW:
		// Vd.w = vnavg(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNCCOMBINE:
		// if (!Ps) Vdd = vcombine(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNCMOV:
		// if (!Ps) Vd = Vu
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNORMAMTH:
		// Vd.h = vnormamt(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNORMAMTW:
		// Vd.w = vnormamt(Vu.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VNOT:
		// Vd = vnot(Vu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VOR:
		// Vd = vor(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKEB:
		// Vd.b = vpacke(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKEH:
		// Vd.h = vpacke(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKHB_SAT:
		// Vd.b = vpack(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKHUB_SAT:
		// Vd.ub = vpack(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKOB:
		// Vd.b = vpacko(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKOH:
		// Vd.h = vpacko(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKWH_SAT:
		// Vd.h = vpack(Vu.w,Vv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPACKWUH_SAT:
		// Vd.uh = vpack(Vu.w,Vv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPOPCOUNTH:
		// Vd.h = vpopcount(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPREFIXQB:
		// Vd.b = prefixsum(Qv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPREFIXQH:
		// Vd.h = prefixsum(Qv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VPREFIXQW:
		// Vd.w = prefixsum(Qv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRDELTA:
		// Vd = vrdelta(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUB_RTT:
		// Vdd.w = vrmpy(Vu.b,Rtt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUB_RTT_ACC:
		// Vxx.w += vrmpy(Vu.b,Rtt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUS:
		// Vd.w = vrmpy(Vu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUS_ACC:
		// Vx.w += vrmpy(Vu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUSI:
		// Vdd.w = vrmpy(Vuu.ub,Rt.b,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUSI_ACC:
		// Vxx.w += vrmpy(Vuu.ub,Rt.b,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUSV:
		// Vd.w = vrmpy(Vu.ub,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBUSV_ACC:
		// Vx.w += vrmpy(Vu.ub,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBV:
		// Vd.w = vrmpy(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYBV_ACC:
		// Vx.w += vrmpy(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYUB:
		// Vd.uw = vrmpy(Vu.ub,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYUB_ACC:
		// Vx.uw += vrmpy(Vu.ub,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYUB_RTT:
		// Vdd.uw = vrmpy(Vu.ub,Rtt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYUB_RTT_ACC:
		// Vxx.uw += vrmpy(Vu.ub,Rtt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYUBI:
		// Vdd.uw = vrmpy(Vuu.ub,Rt.ub,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VRMPYUBI_ACC:
		// Vxx.uw += vrmpy(Vuu.ub,Rt.ub,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VRMPYUBV:
		// Vd.uw = vrmpy(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYUBV_ACC:
		// Vx.uw += vrmpy(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBB_RT:
		// Vdddd.w = vrmpyz(Vu.b,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBB_RT_ACC:
		// Vyyyy.w += vrmpyz(Vu.b,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBB_RX:
		// Vdddd.w = vrmpyz(Vu.b,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBB_RX_ACC:
		// Vyyyy.w += vrmpyz(Vu.b,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBUB_RT:
		// Vdddd.w = vrmpyz(Vu.b,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBUB_RT_ACC:
		// Vyyyy.w += vrmpyz(Vu.b,Rt.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBUB_RX:
		// Vdddd.w = vrmpyz(Vu.b,Rx.ub++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZBUB_RX_ACC:
		// Vyyyy.w += vrmpyz(Vu.b,Rx.ub++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCB_RT:
		// Vdddd.w = vr16mpyz(Vu.c,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCB_RT_ACC:
		// Vyyyy.w += vr16mpyz(Vu.c,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCB_RX:
		// Vdddd.w = vr16mpyz(Vu.c,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCB_RX_ACC:
		// Vyyyy.w += vr16mpyz(Vu.c,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCBS_RT:
		// Vdddd.w = vr16mpyzs(Vu.c,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCBS_RT_ACC:
		// Vyyyy.w += vr16mpyzs(Vu.c,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCBS_RX:
		// Vdddd.w = vr16mpyzs(Vu.c,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZCBS_RX_ACC:
		// Vyyyy.w += vr16mpyzs(Vu.c,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZNB_RT:
		// Vdddd.w = vr8mpyz(Vu.n,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZNB_RT_ACC:
		// Vyyyy.w += vr8mpyz(Vu.n,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZNB_RX:
		// Vdddd.w = vr8mpyz(Vu.n,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRMPYZNB_RX_ACC:
		// Vyyyy.w += vr8mpyz(Vu.n,Rx.b++)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROR:
		// Vd = vror(Vu,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROTR:
		// Vd.uw = vrotr(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROUNDHB:
		// Vd.b = vround(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROUNDHUB:
		// Vd.ub = vround(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROUNDUHUB:
		// Vd.ub = vround(Vu.uh,Vv.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROUNDUWUH:
		// Vd.uh = vround(Vu.uw,Vv.uw):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROUNDWH:
		// Vd.h = vround(Vu.w,Vv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VROUNDWUH:
		// Vd.uh = vround(Vu.w,Vv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VRSADUBI:
		// Vdd.uw = vrsad(Vuu.ub,Rt.ub,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VRSADUBI_ACC:
		// Vxx.uw += vrsad(Vuu.ub,Rt.ub,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VSATDW:
		// Vd.w = vsatdw(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSATHUB:
		// Vd.ub = vsat(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSATUWUH:
		// Vd.uh = vsat(Vu.uw,Vv.uw)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSATWH:
		// Vd.h = vsat(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSB:
		// Vdd.h = vsxt(Vu.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMH:
		// vscatter(Rt,Mu,Vv.h).h = Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMH_ADD:
		// vscatter(Rt,Mu,Vv.h).h += Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMHQ:
		// if (Qs) vscatter(Rt,Mu,Vv.h).h = Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMHW:
		// vscatter(Rt,Mu,Vvv.w).h = Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMHW_ADD:
		// vscatter(Rt,Mu,Vvv.w).h += Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMHWQ:
		// if (Qs) vscatter(Rt,Mu,Vvv.w).h = Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMW:
		// vscatter(Rt,Mu,Vv.w).w = Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMW_ADD:
		// vscatter(Rt,Mu,Vv.w).w += Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSCATTERMWQ:
		// if (Qs) vscatter(Rt,Mu,Vv.w).w = Vw
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSH:
		// Vdd.w = vsxt(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFEH:
		// Vd.h = vshuffe(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFF:
		// vshuff(Vy,Vx,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFFB:
		// Vd.b = vshuff(Vu.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFFEB:
		// Vd.b = vshuffe(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFFH:
		// Vd.h = vshuff(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFFOB:
		// Vd.b = vshuffo(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFFVDD:
		// Vdd = vshuff(Vu,Vv,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFOEB:
		// Vdd.b = vshuffoe(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFOEH:
		// Vdd.h = vshuffoe(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSHUFOH:
		// Vd.h = vshuffo(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBB:
		// Vd.b = vsub(Vu.b,Vv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBB_DV:
		// Vdd.b = vsub(Vuu.b,Vvv.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBBNQ:
		// if (!Qv) Vx.b -= Vu.b
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBBQ:
		// if (Qv) Vx.b -= Vu.b
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBBSAT:
		// Vd.b = vsub(Vu.b,Vv.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBBSAT_DV:
		// Vdd.b = vsub(Vuu.b,Vvv.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBCARRY:
		// Vd.w = vsub(Vu.w,Vv.w,Qx):carry
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBCARRYO:
		// Vd.w,Qe = vsub(Vu.w,Vv.w):carry
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBH:
		// Vd.h = vsub(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBH_DV:
		// Vdd.h = vsub(Vuu.h,Vvv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBHNQ:
		// if (!Qv) Vx.h -= Vu.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBHQ:
		// if (Qv) Vx.h -= Vu.h
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBHSAT:
		// Vd.h = vsub(Vu.h,Vv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBHSAT_DV:
		// Vdd.h = vsub(Vuu.h,Vvv.h):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBHW:
		// Vdd.w = vsub(Vu.h,Vv.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUBH:
		// Vdd.h = vsub(Vu.ub,Vv.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUBSAT:
		// Vd.ub = vsub(Vu.ub,Vv.ub):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUBSAT_DV:
		// Vdd.ub = vsub(Vuu.ub,Vvv.ub):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUBUBB_SAT:
		// Vd.ub = vsub(Vu.ub,Vv.b):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUHSAT:
		// Vd.uh = vsub(Vu.uh,Vv.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUHSAT_DV:
		// Vdd.uh = vsub(Vuu.uh,Vvv.uh):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUHW:
		// Vdd.w = vsub(Vu.uh,Vv.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUWSAT:
		// Vd.uw = vsub(Vu.uw,Vv.uw):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBUWSAT_DV:
		// Vdd.uw = vsub(Vuu.uw,Vvv.uw):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBW:
		// Vd.w = vsub(Vu.w,Vv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBW_DV:
		// Vdd.w = vsub(Vuu.w,Vvv.w)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBWNQ:
		// if (!Qv) Vx.w -= Vu.w
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBWQ:
		// if (Qv) Vx.w -= Vu.w
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBWSAT:
		// Vd.w = vsub(Vu.w,Vv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSUBWSAT_DV:
		// Vdd.w = vsub(Vuu.w,Vvv.w):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VSWAP:
		// Vdd = vswap(Qt,Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VTMPYB:
		// Vdd.h = vtmpy(Vuu.b,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VTMPYB_ACC:
		// Vxx.h += vtmpy(Vuu.b,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VTMPYBUS:
		// Vdd.h = vtmpy(Vuu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VTMPYBUS_ACC:
		// Vxx.h += vtmpy(Vuu.ub,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VTMPYHB:
		// Vdd.w = vtmpy(Vuu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VTMPYHB_ACC:
		// Vxx.w += vtmpy(Vuu.h,Rt.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VUNPACKB:
		// Vdd.h = vunpack(Vu.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VUNPACKH:
		// Vdd.w = vunpack(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VUNPACKOB:
		// Vxx.h |= vunpacko(Vu.b)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VUNPACKOH:
		// Vxx.w |= vunpacko(Vu.h)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VUNPACKUB:
		// Vdd.uh = vunpack(Vu.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VUNPACKUH:
		// Vdd.uw = vunpack(Vu.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VWHIST128:
		// vwhist128
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VWHIST128M:
		// vwhist128(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VWHIST128Q:
		// vwhist128(Qv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VWHIST128QM:
		// vwhist128(Qv,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_VWHIST256:
		// vwhist256
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VWHIST256_SAT:
		// vwhist256:sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VWHIST256Q:
		// vwhist256(Qv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VWHIST256Q_SAT:
		// vwhist256(Qv):sat
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VXOR:
		// Vd = vxor(Vu,Vv)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VZB:
		// Vdd.uh = vzxt(Vu.ub)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_VZH:
		// Vdd.uw = vzxt(Vu.uh)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_ZLD_AI:
		// z = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_ZLD_PI:
		// z = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_ZLD_PPU:
		// z = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_ZLD_PRED_AI:
		// if (Pv) z = vmem(Rt+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_ZLD_PRED_PI:
		// if (Pv) z = vmem(Rx++#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_V6_ZLD_PRED_PPU:
		// if (Pv) z = vmem(Rx++Mu)
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		op->val = UT64_MAX;
		break;
	case HEX_INS_V6_ZEXTRACT:
		// Vd = zextract(Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_BARRIER:
		// barrier
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_BREAK:
		// brkpt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_DCCLEANA:
		// dccleana(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_DCCLEANINVA:
		// dccleaninva(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_DCFETCHBO:
		// dcfetch(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_Y2_DCINVA:
		// dcinva(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_DCZEROA:
		// dczeroa(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_ICINVA:
		// icinva(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_ISYNC:
		// isync
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_SYNCHT:
		// syncht
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y2_WAIT:
		// wait(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y4_L2FETCH:
		// l2fetch(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y4_TRACE:
		// trace(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y5_L2FETCH:
		// l2fetch(Rs,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DIAG:
		// diag(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DIAG0:
		// diag0(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DIAG1:
		// diag1(Rss,Rtt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DMLINK:
		// dmlink(Rs,Rt)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DMPAUSE:
		// Rd = dmpause
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DMPOLL:
		// Rd = dmpoll
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DMRESUME:
		// dmresume(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DMSTART:
		// dmstart(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_Y6_DMWAIT:
		// Rd = dmwait
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_DEP_A2_ADDSAT:
		// Rd = add(Rs,Rt):sat:deprecated
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_DEP_A2_SUBSAT:
		// Rd = sub(Rt,Rs):sat:deprecated
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_DEP_S2_PACKHL:
		// Rdd = packhl(Rs,Rt):deprecated
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_INVALID_DECODE:
		// <invalid>
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_ADDRX:
		// RX = add(RXin,#Ii) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_ADDRX:
		// RX = add(RXin,RS) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_ADDRX:
		// Rd = add(r29,#Ii) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_ADDRX:
		// Rd = and(RS,#1) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_ADDRX:
		// Rd = add(RS,#n1) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_ADDRX:
		// Rd = add(RS,#1) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_ADDRX:
		// Rd = #Ii ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_ADDRX:
		// Rd = sxtb(RS) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_ADDRX:
		// Rd = sxth(RS) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_ADDRX:
		// Rd = RS ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_ADDRX:
		// Rd = and(RS,#255) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_ADDRX:
		// Rd = zxth(RS) ; Rx = add(Rxin,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_ADDSP:
		// Rx = add(Rxin,#II) ; Rd = add(r29,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_ADDSP:
		// RD = add(r29,#II) ; Rd = add(r29,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_ADDSP:
		// RD = #II ; Rd = add(r29,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_AND1:
		// Rx = add(Rxin,#Ii) ; Rd = and(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_AND1:
		// RD = add(r29,#Ii) ; Rd = and(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_AND1:
		// RD = and(RS,#1) ; Rd = and(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_AND1:
		// RD = add(RS,#1) ; Rd = and(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_AND1:
		// RD = #Ii ; Rd = and(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_AND1:
		// RD = RS ; Rd = and(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_CLRF:
		// Rx = add(Rxin,#Ii) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_CLRF:
		// Rx = add(Rxin,Rs) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_CLRF:
		// RD = add(r29,#Ii) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_CLRF:
		// RD = and(Rs,#1) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_CLRF:
		// if (!p0) RD = #0 ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_CLRF:
		// if (!p0.new) RD = #0 ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_CLRF:
		// if (p0) RD = #0 ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_CLRF:
		// if (p0.new) RD = #0 ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_CLRF:
		// p0 = cmp.eq(Rs,#Ii) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_CLRF:
		// RD = add(Rs,#n1) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_CLRF:
		// RD = add(Rs,#1) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_CLRF:
		// RD = #Ii ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_CLRF:
		// RD = #n1 ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_CLRF:
		// RD = sxtb(Rs) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_CLRF:
		// RD = sxth(Rs) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_CLRF:
		// RD = Rs ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_CLRF:
		// RD = and(Rs,#255) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_CLRF:
		// RD = zxth(Rs) ; if (!p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_CLRFNEW:
		// Rx = add(Rxin,#Ii) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_CLRFNEW:
		// Rx = add(Rxin,Rs) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_CLRFNEW:
		// RD = add(r29,#Ii) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_CLRFNEW:
		// RD = and(Rs,#1) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_CLRFNEW:
		// if (!p0.new) RD = #0 ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_CLRFNEW:
		// if (p0.new) RD = #0 ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_CLRFNEW:
		// p0 = cmp.eq(Rs,#Ii) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_CLRFNEW:
		// RD = add(Rs,#n1) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_CLRFNEW:
		// RD = add(Rs,#1) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_CLRFNEW:
		// RD = #Ii ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_CLRFNEW:
		// RD = #n1 ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_CLRFNEW:
		// RD = sxtb(Rs) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_CLRFNEW:
		// RD = sxth(Rs) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_CLRFNEW:
		// RD = Rs ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_CLRFNEW:
		// RD = and(Rs,#255) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_CLRFNEW:
		// RD = zxth(Rs) ; if (!p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_CLRT:
		// Rx = add(Rxin,#Ii) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_CLRT:
		// Rx = add(Rxin,Rs) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_CLRT:
		// RD = add(r29,#Ii) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_CLRT:
		// RD = and(Rs,#1) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_CLRT:
		// if (!p0.new) RD = #0 ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_CLRT:
		// if (p0) RD = #0 ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_CLRT:
		// if (p0.new) RD = #0 ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_CLRT:
		// p0 = cmp.eq(Rs,#Ii) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_CLRT:
		// RD = add(Rs,#n1) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_CLRT:
		// RD = add(Rs,#1) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_CLRT:
		// RD = #Ii ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_CLRT:
		// RD = #n1 ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_CLRT:
		// RD = sxtb(Rs) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_CLRT:
		// RD = sxth(Rs) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_CLRT:
		// RD = Rs ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_CLRT:
		// RD = and(Rs,#255) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_CLRT:
		// RD = zxth(Rs) ; if (p0) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_CLRTNEW:
		// Rx = add(Rxin,#Ii) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_CLRTNEW:
		// Rx = add(Rxin,Rs) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_CLRTNEW:
		// RD = add(r29,#Ii) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_CLRTNEW:
		// RD = and(Rs,#1) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_CLRTNEW:
		// if (p0.new) RD = #0 ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_CLRTNEW:
		// p0 = cmp.eq(Rs,#Ii) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_CLRTNEW:
		// RD = add(Rs,#n1) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_CLRTNEW:
		// RD = add(Rs,#1) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_CLRTNEW:
		// RD = #Ii ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_CLRTNEW:
		// RD = #n1 ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_CLRTNEW:
		// RD = sxtb(Rs) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_CLRTNEW:
		// RD = sxth(Rs) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_CLRTNEW:
		// RD = Rs ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_CLRTNEW:
		// RD = and(Rs,#255) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_CLRTNEW:
		// RD = zxth(Rs) ; if (p0.new) Rd = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_CMPEQI:
		// Rx = add(Rxin,#II) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_CMPEQI:
		// Rx = add(Rxin,RS) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_CMPEQI:
		// Rd = add(r29,#II) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_CMPEQI:
		// Rd = and(RS,#1) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_CMPEQI:
		// p0 = cmp.eq(RS,#II) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_CMPEQI:
		// Rd = add(RS,#n1) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_CMPEQI:
		// Rd = add(RS,#1) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_CMPEQI:
		// Rd = #II ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_CMPEQI:
		// Rd = sxtb(RS) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_CMPEQI:
		// Rd = sxth(RS) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_CMPEQI:
		// Rd = RS ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_CMPEQI:
		// Rd = and(RS,#255) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_CMPEQI:
		// Rd = zxth(RS) ; p0 = cmp.eq(Rs,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_COMBINE0I:
		// Rx = add(Rxin,#II) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_COMBINE0I:
		// Rx = add(Rxin,Rs) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_COMBINE0I:
		// RD = add(r29,#II) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_COMBINE0I:
		// RD = and(Rs,#1) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_COMBINE0I:
		// if (!p0) RD = #0 ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_COMBINE0I:
		// if (!p0.new) RD = #0 ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_COMBINE0I:
		// if (p0) RD = #0 ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_COMBINE0I:
		// if (p0.new) RD = #0 ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_COMBINE0I:
		// p0 = cmp.eq(Rs,#II) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SA1_COMBINE0I:
		// RDD = combine(#0,#II) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_COMBINE0I:
		// RD = add(Rs,#n1) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_COMBINE0I:
		// RD = add(Rs,#1) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_COMBINE0I:
		// RD = #II ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_COMBINE0I:
		// RD = #n1 ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_COMBINE0I:
		// RD = sxtb(Rs) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_COMBINE0I:
		// RD = sxth(Rs) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_COMBINE0I:
		// RD = Rs ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_COMBINE0I:
		// RD = and(Rs,#255) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_COMBINE0I:
		// RD = zxth(Rs) ; Rdd = combine(#0,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_COMBINE1I:
		// Rx = add(Rxin,#II) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_COMBINE1I:
		// Rx = add(Rxin,Rs) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_COMBINE1I:
		// RD = add(r29,#II) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_COMBINE1I:
		// RD = and(Rs,#1) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_COMBINE1I:
		// if (!p0) RD = #0 ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_COMBINE1I:
		// if (!p0.new) RD = #0 ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_COMBINE1I:
		// if (p0) RD = #0 ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_COMBINE1I:
		// if (p0.new) RD = #0 ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_COMBINE1I:
		// p0 = cmp.eq(Rs,#II) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SA1_COMBINE1I:
		// RDD = combine(#0,#II) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SA1_COMBINE1I:
		// RDD = combine(#1,#II) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_COMBINE1I:
		// RD = add(Rs,#n1) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_COMBINE1I:
		// RD = add(Rs,#1) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_COMBINE1I:
		// RD = #II ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_COMBINE1I:
		// RD = #n1 ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_COMBINE1I:
		// RD = sxtb(Rs) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_COMBINE1I:
		// RD = sxth(Rs) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_COMBINE1I:
		// RD = Rs ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_COMBINE1I:
		// RD = and(Rs,#255) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_COMBINE1I:
		// RD = zxth(Rs) ; Rdd = combine(#1,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_COMBINE2I:
		// Rx = add(Rxin,#II) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_COMBINE2I:
		// Rx = add(Rxin,Rs) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_COMBINE2I:
		// RD = add(r29,#II) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_COMBINE2I:
		// RD = and(Rs,#1) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_COMBINE2I:
		// if (!p0) RD = #0 ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_COMBINE2I:
		// if (!p0.new) RD = #0 ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_COMBINE2I:
		// if (p0) RD = #0 ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_COMBINE2I:
		// if (p0.new) RD = #0 ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_COMBINE2I:
		// p0 = cmp.eq(Rs,#II) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SA1_COMBINE2I:
		// RDD = combine(#0,#II) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SA1_COMBINE2I:
		// RDD = combine(#1,#II) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SA1_COMBINE2I:
		// RDD = combine(#2,#II) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_COMBINE2I:
		// RD = add(Rs,#n1) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_COMBINE2I:
		// RD = add(Rs,#1) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_COMBINE2I:
		// RD = #II ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_COMBINE2I:
		// RD = #n1 ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_COMBINE2I:
		// RD = sxtb(Rs) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_COMBINE2I:
		// RD = sxth(Rs) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_COMBINE2I:
		// RD = Rs ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_COMBINE2I:
		// RD = and(Rs,#255) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_COMBINE2I:
		// RD = zxth(Rs) ; Rdd = combine(#2,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_COMBINE3I:
		// Rx = add(Rxin,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_COMBINE3I:
		// Rx = add(Rxin,Rs) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_COMBINE3I:
		// RD = add(r29,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_COMBINE3I:
		// RD = and(Rs,#1) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_COMBINE3I:
		// if (!p0) RD = #0 ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_COMBINE3I:
		// if (!p0.new) RD = #0 ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_COMBINE3I:
		// if (p0) RD = #0 ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_COMBINE3I:
		// if (p0.new) RD = #0 ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_COMBINE3I:
		// p0 = cmp.eq(Rs,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SA1_COMBINE3I:
		// RDD = combine(#0,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SA1_COMBINE3I:
		// RDD = combine(#1,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SA1_COMBINE3I:
		// RDD = combine(#2,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SA1_COMBINE3I:
		// RDD = combine(#3,#II) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_COMBINE3I:
		// RD = add(Rs,#n1) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_COMBINE3I:
		// RD = add(Rs,#1) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_COMBINE3I:
		// RD = #II ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_COMBINE3I:
		// RD = #n1 ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_COMBINE3I:
		// RD = sxtb(Rs) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_COMBINE3I:
		// RD = sxth(Rs) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_COMBINE3I:
		// RD = Rs ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_COMBINE3I:
		// RD = and(Rs,#255) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_COMBINE3I:
		// RD = zxth(Rs) ; Rdd = combine(#3,#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_COMBINERZ:
		// Rx = add(Rxin,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_COMBINERZ:
		// Rx = add(Rxin,RS) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_COMBINERZ:
		// RD = add(r29,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_COMBINERZ:
		// RD = and(RS,#1) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_COMBINERZ:
		// if (!p0) RD = #0 ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_COMBINERZ:
		// if (!p0.new) RD = #0 ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_COMBINERZ:
		// if (p0) RD = #0 ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_COMBINERZ:
		// if (p0.new) RD = #0 ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_COMBINERZ:
		// p0 = cmp.eq(RS,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SA1_COMBINERZ:
		// RDD = combine(#0,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SA1_COMBINERZ:
		// RDD = combine(#1,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SA1_COMBINERZ:
		// RDD = combine(#2,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SA1_COMBINERZ:
		// RDD = combine(#3,#Ii) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SA1_COMBINERZ:
		// RDD = combine(RS,#0) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SA1_COMBINERZ:
		// RDD = combine(#0,RS) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_COMBINERZ:
		// RD = add(RS,#n1) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_COMBINERZ:
		// RD = add(RS,#1) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_COMBINERZ:
		// RD = #Ii ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_COMBINERZ:
		// RD = #n1 ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_COMBINERZ:
		// RD = sxtb(RS) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_COMBINERZ:
		// RD = sxth(RS) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_COMBINERZ:
		// RD = RS ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_COMBINERZ:
		// RD = and(RS,#255) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_COMBINERZ:
		// RD = zxth(RS) ; Rdd = combine(Rs,#0)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_COMBINEZR:
		// Rx = add(Rxin,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_COMBINEZR:
		// Rx = add(Rxin,RS) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_COMBINEZR:
		// RD = add(r29,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_COMBINEZR:
		// RD = and(RS,#1) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SA1_COMBINEZR:
		// if (!p0) RD = #0 ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SA1_COMBINEZR:
		// if (!p0.new) RD = #0 ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SA1_COMBINEZR:
		// if (p0) RD = #0 ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SA1_COMBINEZR:
		// if (p0.new) RD = #0 ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_COMBINEZR:
		// p0 = cmp.eq(RS,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SA1_COMBINEZR:
		// RDD = combine(#0,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SA1_COMBINEZR:
		// RDD = combine(#1,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SA1_COMBINEZR:
		// RDD = combine(#2,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SA1_COMBINEZR:
		// RDD = combine(#3,#Ii) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SA1_COMBINEZR:
		// RDD = combine(#0,RS) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_COMBINEZR:
		// RD = add(RS,#n1) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_COMBINEZR:
		// RD = add(RS,#1) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_COMBINEZR:
		// RD = #Ii ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_COMBINEZR:
		// RD = #n1 ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_COMBINEZR:
		// RD = sxtb(RS) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_COMBINEZR:
		// RD = sxth(RS) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_COMBINEZR:
		// RD = RS ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_COMBINEZR:
		// RD = and(RS,#255) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_COMBINEZR:
		// RD = zxth(RS) ; Rdd = combine(#0,Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_DEC:
		// Rx = add(Rxin,#Ii) ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_DEC:
		// RD = add(r29,#Ii) ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_DEC:
		// RD = and(RS,#1) ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_DEC:
		// RD = add(RS,#N1) ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_DEC:
		// RD = add(RS,#1) ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_DEC:
		// RD = #Ii ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_DEC:
		// RD = RS ; Rd = add(Rs,#n1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_INC:
		// Rx = add(Rxin,#Ii) ; Rd = add(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_INC:
		// RD = add(r29,#Ii) ; Rd = add(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_INC:
		// RD = add(RS,#1) ; Rd = add(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_INC:
		// RD = #Ii ; Rd = add(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_INC:
		// RD = RS ; Rd = add(Rs,#1)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_SETIN1:
		// Rx = add(Rxin,#Ii) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SA1_SETIN1:
		// Rx = add(Rxin,Rs) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_SETIN1:
		// RD = add(r29,#Ii) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_SETIN1:
		// RD = and(Rs,#1) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SA1_SETIN1:
		// p0 = cmp.eq(Rs,#Ii) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_SETIN1:
		// RD = add(Rs,#N1) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_SETIN1:
		// RD = add(Rs,#1) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_SETIN1:
		// RD = #Ii ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SA1_SETIN1:
		// RD = #N1 ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_SETIN1:
		// RD = sxtb(Rs) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_SETIN1:
		// RD = sxth(Rs) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_SETIN1:
		// RD = Rs ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_SETIN1:
		// RD = and(Rs,#255) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_SETIN1:
		// RD = zxth(Rs) ; Rd = #n1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_SXTB:
		// Rx = add(Rxin,#Ii) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_SXTB:
		// RD = add(r29,#Ii) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_SXTB:
		// RD = and(RS,#1) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_SXTB:
		// RD = add(RS,#n1) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_SXTB:
		// RD = add(RS,#1) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_SXTB:
		// RD = #Ii ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_SXTB:
		// RD = sxtb(RS) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_SXTB:
		// RD = sxth(RS) ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_SXTB:
		// RD = RS ; Rd = sxtb(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_SXTH:
		// Rx = add(Rxin,#Ii) ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_SXTH:
		// RD = add(r29,#Ii) ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_SXTH:
		// RD = and(RS,#1) ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_SXTH:
		// RD = add(RS,#n1) ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_SXTH:
		// RD = add(RS,#1) ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_SXTH:
		// RD = #Ii ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_SXTH:
		// RD = sxth(RS) ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_SXTH:
		// RD = RS ; Rd = sxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_TFR:
		// Rx = add(Rxin,#Ii) ; Rd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_TFR:
		// RD = add(r29,#Ii) ; Rd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_TFR:
		// RD = #Ii ; Rd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_TFR:
		// RD = RS ; Rd = Rs
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_ZXTB:
		// Rx = add(Rxin,#Ii) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_ZXTB:
		// RD = add(r29,#Ii) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_ZXTB:
		// RD = and(RS,#1) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_ZXTB:
		// RD = add(RS,#n1) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_ZXTB:
		// RD = add(RS,#1) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_ZXTB:
		// RD = #Ii ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_ZXTB:
		// RD = sxtb(RS) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_ZXTB:
		// RD = sxth(RS) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_ZXTB:
		// RD = RS ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SA1_ZXTB:
		// RD = and(RS,#255) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_ZXTB:
		// RD = zxth(RS) ; Rd = and(Rs,#255)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SA1_ZXTH:
		// Rx = add(Rxin,#Ii) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SA1_ZXTH:
		// RD = add(r29,#Ii) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SA1_ZXTH:
		// RD = and(RS,#1) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SA1_ZXTH:
		// RD = add(RS,#n1) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SA1_ZXTH:
		// RD = add(RS,#1) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SA1_ZXTH:
		// RD = #Ii ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SA1_ZXTH:
		// RD = sxtb(RS) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SA1_ZXTH:
		// RD = sxth(RS) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SA1_ZXTH:
		// RD = RS ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SA1_ZXTH:
		// RD = zxth(RS) ; Rd = zxth(Rs)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL1_LOADRI_IO:
		// Rx = add(Rxin,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL1_LOADRI_IO:
		// Rx = add(Rxin,RS) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL1_LOADRI_IO:
		// RD = add(r29,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL1_LOADRI_IO:
		// RD = and(RS,#1) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL1_LOADRI_IO:
		// if (!p0) RD = #0 ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL1_LOADRI_IO:
		// if (!p0.new) RD = #0 ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL1_LOADRI_IO:
		// if (p0) RD = #0 ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL1_LOADRI_IO:
		// if (p0.new) RD = #0 ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL1_LOADRI_IO:
		// p0 = cmp.eq(RS,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL1_LOADRI_IO:
		// RDD = combine(#0,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL1_LOADRI_IO:
		// RDD = combine(#1,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL1_LOADRI_IO:
		// RDD = combine(#2,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL1_LOADRI_IO:
		// RDD = combine(#3,#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL1_LOADRI_IO:
		// RDD = combine(RS,#0) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL1_LOADRI_IO:
		// RDD = combine(#0,RS) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL1_LOADRI_IO:
		// RD = add(RS,#n1) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL1_LOADRI_IO:
		// RD = add(RS,#1) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL1_LOADRI_IO:
		// RD = #II ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL1_LOADRI_IO:
		// RD = #n1 ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL1_LOADRI_IO:
		// RD = sxtb(RS) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL1_LOADRI_IO:
		// RD = sxth(RS) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL1_LOADRI_IO:
		// RD = RS ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL1_LOADRI_IO:
		// RD = and(RS,#255) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL1_LOADRI_IO:
		// RD = zxth(RS) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL1_LOADRI_IO:
		// RD = memw(RS+#II) ; Rd = memw(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL1_LOADRUB_IO:
		// Rx = add(Rxin,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL1_LOADRUB_IO:
		// Rx = add(Rxin,RS) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL1_LOADRUB_IO:
		// RD = add(r29,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL1_LOADRUB_IO:
		// RD = and(RS,#1) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL1_LOADRUB_IO:
		// if (!p0) RD = #0 ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL1_LOADRUB_IO:
		// if (!p0.new) RD = #0 ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL1_LOADRUB_IO:
		// if (p0) RD = #0 ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL1_LOADRUB_IO:
		// if (p0.new) RD = #0 ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL1_LOADRUB_IO:
		// p0 = cmp.eq(RS,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL1_LOADRUB_IO:
		// RDD = combine(#0,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL1_LOADRUB_IO:
		// RDD = combine(#1,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL1_LOADRUB_IO:
		// RDD = combine(#2,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL1_LOADRUB_IO:
		// RDD = combine(#3,#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL1_LOADRUB_IO:
		// RDD = combine(RS,#0) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL1_LOADRUB_IO:
		// RDD = combine(#0,RS) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL1_LOADRUB_IO:
		// RD = add(RS,#n1) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL1_LOADRUB_IO:
		// RD = add(RS,#1) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL1_LOADRUB_IO:
		// RD = #II ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL1_LOADRUB_IO:
		// RD = #n1 ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL1_LOADRUB_IO:
		// RD = sxtb(RS) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL1_LOADRUB_IO:
		// RD = sxth(RS) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL1_LOADRUB_IO:
		// RD = RS ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL1_LOADRUB_IO:
		// RD = and(RS,#255) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL1_LOADRUB_IO:
		// RD = zxth(RS) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL1_LOADRUB_IO:
		// RD = memw(RS+#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL1_LOADRUB_IO:
		// RD = memub(RS+#II) ; Rd = memub(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_DEALLOCFRAME:
		// Rx = add(Rxin,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_DEALLOCFRAME:
		// Rx = add(Rxin,Rs) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_DEALLOCFRAME:
		// Rd = add(r29,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_DEALLOCFRAME:
		// Rd = and(Rs,#1) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_DEALLOCFRAME:
		// if (!p0) Rd = #0 ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_DEALLOCFRAME:
		// if (!p0.new) Rd = #0 ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_DEALLOCFRAME:
		// if (p0) Rd = #0 ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_DEALLOCFRAME:
		// if (p0.new) Rd = #0 ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_DEALLOCFRAME:
		// p0 = cmp.eq(Rs,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_DEALLOCFRAME:
		// Rdd = combine(#0,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_DEALLOCFRAME:
		// Rdd = combine(#1,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_DEALLOCFRAME:
		// Rdd = combine(#2,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_DEALLOCFRAME:
		// Rdd = combine(#3,#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_DEALLOCFRAME:
		// Rdd = combine(Rs,#0) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_DEALLOCFRAME:
		// Rdd = combine(#0,Rs) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_DEALLOCFRAME:
		// Rd = add(Rs,#n1) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_DEALLOCFRAME:
		// Rd = add(Rs,#1) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_DEALLOCFRAME:
		// Rd = #Ii ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_DEALLOCFRAME:
		// Rd = #n1 ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_DEALLOCFRAME:
		// Rd = sxtb(Rs) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_DEALLOCFRAME:
		// Rd = sxth(Rs) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_DEALLOCFRAME:
		// Rd = Rs ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_DEALLOCFRAME:
		// Rd = and(Rs,#255) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_DEALLOCFRAME:
		// Rd = zxth(Rs) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_DEALLOCFRAME:
		// Rd = memw(Rs+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_DEALLOCFRAME:
		// Rd = memub(Rs+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_DEALLOCFRAME:
		// deallocframe ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_DEALLOCFRAME:
		// Rd = memb(Rs+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_DEALLOCFRAME:
		// Rdd = memd(r29+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_DEALLOCFRAME:
		// Rd = memh(Rs+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_DEALLOCFRAME:
		// Rd = memw(r29+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_DEALLOCFRAME:
		// Rd = memuh(Rs+#Ii) ; deallocframe
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_JUMPR31:
		// Rx = add(Rxin,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_JUMPR31:
		// Rx = add(Rxin,Rs) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_JUMPR31:
		// Rd = add(r29,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_JUMPR31:
		// Rd = and(Rs,#1) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_JUMPR31:
		// if (!p0) Rd = #0 ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_JUMPR31:
		// if (!p0.new) Rd = #0 ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_JUMPR31:
		// if (p0) Rd = #0 ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_JUMPR31:
		// if (p0.new) Rd = #0 ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_JUMPR31:
		// p0 = cmp.eq(Rs,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_JUMPR31:
		// Rdd = combine(#0,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_JUMPR31:
		// Rdd = combine(#1,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_JUMPR31:
		// Rdd = combine(#2,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_JUMPR31:
		// Rdd = combine(#3,#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_JUMPR31:
		// Rdd = combine(Rs,#0) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_JUMPR31:
		// Rdd = combine(#0,Rs) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_JUMPR31:
		// Rd = add(Rs,#n1) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_JUMPR31:
		// Rd = add(Rs,#1) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_JUMPR31:
		// Rd = #Ii ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_JUMPR31:
		// Rd = #n1 ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_JUMPR31:
		// Rd = sxtb(Rs) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_JUMPR31:
		// Rd = sxth(Rs) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_JUMPR31:
		// Rd = Rs ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_JUMPR31:
		// Rd = and(Rs,#255) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_JUMPR31:
		// Rd = zxth(Rs) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_JUMPR31:
		// Rd = memw(Rs+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_JUMPR31:
		// Rd = memub(Rs+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_JUMPR31:
		// deallocframe ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_JUMPR31:
		// Rd = memb(Rs+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_JUMPR31:
		// Rdd = memd(r29+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_JUMPR31:
		// Rd = memh(Rs+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_JUMPR31:
		// Rd = memw(r29+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_JUMPR31:
		// Rd = memuh(Rs+#Ii) ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_JUMPR31:
		// dealloc_return ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_JUMPR31:
		// if (!p0) dealloc_return ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SL2_JUMPR31:
		// if (!p0.new) dealloc_return:nt ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_JUMPR31:
		// if (p0) dealloc_return ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_JUMPR31:
		// if (p0.new) dealloc_return:nt ; jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_JUMPR31_F:
		// Rx = add(Rxin,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_JUMPR31_F:
		// Rx = add(Rxin,Rs) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_JUMPR31_F:
		// Rd = add(r29,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_JUMPR31_F:
		// Rd = and(Rs,#1) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_JUMPR31_F:
		// if (!p0) Rd = #0 ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_JUMPR31_F:
		// if (!p0.new) Rd = #0 ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_JUMPR31_F:
		// if (p0) Rd = #0 ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_JUMPR31_F:
		// if (p0.new) Rd = #0 ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_JUMPR31_F:
		// p0 = cmp.eq(Rs,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_JUMPR31_F:
		// Rdd = combine(#0,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_JUMPR31_F:
		// Rdd = combine(#1,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_JUMPR31_F:
		// Rdd = combine(#2,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_JUMPR31_F:
		// Rdd = combine(#3,#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_JUMPR31_F:
		// Rdd = combine(Rs,#0) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_JUMPR31_F:
		// Rdd = combine(#0,Rs) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_JUMPR31_F:
		// Rd = add(Rs,#n1) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_JUMPR31_F:
		// Rd = add(Rs,#1) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_JUMPR31_F:
		// Rd = #Ii ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_JUMPR31_F:
		// Rd = #n1 ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_JUMPR31_F:
		// Rd = sxtb(Rs) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_JUMPR31_F:
		// Rd = sxth(Rs) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_JUMPR31_F:
		// Rd = Rs ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_JUMPR31_F:
		// Rd = and(Rs,#255) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_JUMPR31_F:
		// Rd = zxth(Rs) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_JUMPR31_F:
		// Rd = memw(Rs+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_JUMPR31_F:
		// Rd = memub(Rs+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_JUMPR31_F:
		// deallocframe ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_JUMPR31_F:
		// Rd = memb(Rs+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_JUMPR31_F:
		// Rdd = memd(r29+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_JUMPR31_F:
		// Rd = memh(Rs+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_JUMPR31_F:
		// Rd = memw(r29+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_JUMPR31_F:
		// Rd = memuh(Rs+#Ii) ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_JUMPR31_F:
		// dealloc_return ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_JUMPR31_F:
		// if (!p0) dealloc_return ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SL2_JUMPR31_F:
		// if (!p0.new) dealloc_return:nt ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_JUMPR31_F:
		// if (p0) dealloc_return ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_JUMPR31_F:
		// if (p0.new) dealloc_return:nt ; if (!p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_JUMPR31_FNEW:
		// Rx = add(Rxin,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_JUMPR31_FNEW:
		// Rx = add(Rxin,Rs) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_JUMPR31_FNEW:
		// Rd = add(r29,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_JUMPR31_FNEW:
		// Rd = and(Rs,#1) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_JUMPR31_FNEW:
		// if (!p0) Rd = #0 ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_JUMPR31_FNEW:
		// if (!p0.new) Rd = #0 ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_JUMPR31_FNEW:
		// if (p0) Rd = #0 ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_JUMPR31_FNEW:
		// if (p0.new) Rd = #0 ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_JUMPR31_FNEW:
		// p0 = cmp.eq(Rs,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_JUMPR31_FNEW:
		// Rdd = combine(#0,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_JUMPR31_FNEW:
		// Rdd = combine(#1,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_JUMPR31_FNEW:
		// Rdd = combine(#2,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_JUMPR31_FNEW:
		// Rdd = combine(#3,#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_JUMPR31_FNEW:
		// Rdd = combine(Rs,#0) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_JUMPR31_FNEW:
		// Rdd = combine(#0,Rs) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_JUMPR31_FNEW:
		// Rd = add(Rs,#n1) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_JUMPR31_FNEW:
		// Rd = add(Rs,#1) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_JUMPR31_FNEW:
		// Rd = #Ii ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_JUMPR31_FNEW:
		// Rd = #n1 ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_JUMPR31_FNEW:
		// Rd = sxtb(Rs) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_JUMPR31_FNEW:
		// Rd = sxth(Rs) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_JUMPR31_FNEW:
		// Rd = Rs ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_JUMPR31_FNEW:
		// Rd = and(Rs,#255) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_JUMPR31_FNEW:
		// Rd = zxth(Rs) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_JUMPR31_FNEW:
		// Rd = memw(Rs+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_JUMPR31_FNEW:
		// Rd = memub(Rs+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_JUMPR31_FNEW:
		// deallocframe ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_JUMPR31_FNEW:
		// Rd = memb(Rs+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_JUMPR31_FNEW:
		// Rdd = memd(r29+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_JUMPR31_FNEW:
		// Rd = memh(Rs+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_JUMPR31_FNEW:
		// Rd = memw(r29+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_JUMPR31_FNEW:
		// Rd = memuh(Rs+#Ii) ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_JUMPR31_FNEW:
		// dealloc_return ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_JUMPR31_FNEW:
		// if (!p0) dealloc_return ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SL2_JUMPR31_FNEW:
		// if (!p0.new) dealloc_return:nt ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_JUMPR31_FNEW:
		// if (p0) dealloc_return ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_JUMPR31_FNEW:
		// if (p0.new) dealloc_return:nt ; if (!p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_JUMPR31_T:
		// Rx = add(Rxin,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_JUMPR31_T:
		// Rx = add(Rxin,Rs) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_JUMPR31_T:
		// Rd = add(r29,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_JUMPR31_T:
		// Rd = and(Rs,#1) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_JUMPR31_T:
		// if (!p0) Rd = #0 ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_JUMPR31_T:
		// if (!p0.new) Rd = #0 ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_JUMPR31_T:
		// if (p0) Rd = #0 ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_JUMPR31_T:
		// if (p0.new) Rd = #0 ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_JUMPR31_T:
		// p0 = cmp.eq(Rs,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_JUMPR31_T:
		// Rdd = combine(#0,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_JUMPR31_T:
		// Rdd = combine(#1,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_JUMPR31_T:
		// Rdd = combine(#2,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_JUMPR31_T:
		// Rdd = combine(#3,#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_JUMPR31_T:
		// Rdd = combine(Rs,#0) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_JUMPR31_T:
		// Rdd = combine(#0,Rs) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_JUMPR31_T:
		// Rd = add(Rs,#n1) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_JUMPR31_T:
		// Rd = add(Rs,#1) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_JUMPR31_T:
		// Rd = #Ii ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_JUMPR31_T:
		// Rd = #n1 ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_JUMPR31_T:
		// Rd = sxtb(Rs) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_JUMPR31_T:
		// Rd = sxth(Rs) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_JUMPR31_T:
		// Rd = Rs ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_JUMPR31_T:
		// Rd = and(Rs,#255) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_JUMPR31_T:
		// Rd = zxth(Rs) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_JUMPR31_T:
		// Rd = memw(Rs+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_JUMPR31_T:
		// Rd = memub(Rs+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_JUMPR31_T:
		// deallocframe ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_JUMPR31_T:
		// Rd = memb(Rs+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_JUMPR31_T:
		// Rdd = memd(r29+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_JUMPR31_T:
		// Rd = memh(Rs+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_JUMPR31_T:
		// Rd = memw(r29+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_JUMPR31_T:
		// Rd = memuh(Rs+#Ii) ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_JUMPR31_T:
		// dealloc_return ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_JUMPR31_T:
		// if (!p0) dealloc_return ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SL2_JUMPR31_T:
		// if (!p0.new) dealloc_return:nt ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_JUMPR31_T:
		// if (p0) dealloc_return ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_JUMPR31_T:
		// if (p0.new) dealloc_return:nt ; if (p0) jumpr r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_JUMPR31_TNEW:
		// Rx = add(Rxin,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_JUMPR31_TNEW:
		// Rx = add(Rxin,Rs) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_JUMPR31_TNEW:
		// Rd = add(r29,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_JUMPR31_TNEW:
		// Rd = and(Rs,#1) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_JUMPR31_TNEW:
		// if (!p0) Rd = #0 ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_JUMPR31_TNEW:
		// if (!p0.new) Rd = #0 ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_JUMPR31_TNEW:
		// if (p0) Rd = #0 ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_JUMPR31_TNEW:
		// if (p0.new) Rd = #0 ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_JUMPR31_TNEW:
		// p0 = cmp.eq(Rs,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_JUMPR31_TNEW:
		// Rdd = combine(#0,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_JUMPR31_TNEW:
		// Rdd = combine(#1,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_JUMPR31_TNEW:
		// Rdd = combine(#2,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_JUMPR31_TNEW:
		// Rdd = combine(#3,#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_JUMPR31_TNEW:
		// Rdd = combine(Rs,#0) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_JUMPR31_TNEW:
		// Rdd = combine(#0,Rs) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_JUMPR31_TNEW:
		// Rd = add(Rs,#n1) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_JUMPR31_TNEW:
		// Rd = add(Rs,#1) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_JUMPR31_TNEW:
		// Rd = #Ii ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_JUMPR31_TNEW:
		// Rd = #n1 ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_JUMPR31_TNEW:
		// Rd = sxtb(Rs) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_JUMPR31_TNEW:
		// Rd = sxth(Rs) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_JUMPR31_TNEW:
		// Rd = Rs ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_JUMPR31_TNEW:
		// Rd = and(Rs,#255) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_JUMPR31_TNEW:
		// Rd = zxth(Rs) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_JUMPR31_TNEW:
		// Rd = memw(Rs+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_JUMPR31_TNEW:
		// Rd = memub(Rs+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_JUMPR31_TNEW:
		// deallocframe ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_JUMPR31_TNEW:
		// Rd = memb(Rs+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_JUMPR31_TNEW:
		// Rdd = memd(r29+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_JUMPR31_TNEW:
		// Rd = memh(Rs+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_JUMPR31_TNEW:
		// Rd = memw(r29+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_JUMPR31_TNEW:
		// Rd = memuh(Rs+#Ii) ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_JUMPR31_TNEW:
		// dealloc_return ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_JUMPR31_TNEW:
		// if (!p0) dealloc_return ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SL2_JUMPR31_TNEW:
		// if (!p0.new) dealloc_return:nt ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_JUMPR31_TNEW:
		// if (p0) dealloc_return ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_JUMPR31_TNEW:
		// if (p0.new) dealloc_return:nt ; if (p0.new) jumpr:nt r31
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_LOADRB_IO:
		// Rx = add(Rxin,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_LOADRB_IO:
		// Rx = add(Rxin,RS) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_LOADRB_IO:
		// RD = add(r29,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_LOADRB_IO:
		// RD = and(RS,#1) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_LOADRB_IO:
		// if (!p0) RD = #0 ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_LOADRB_IO:
		// if (!p0.new) RD = #0 ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_LOADRB_IO:
		// if (p0) RD = #0 ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_LOADRB_IO:
		// if (p0.new) RD = #0 ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_LOADRB_IO:
		// p0 = cmp.eq(RS,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_LOADRB_IO:
		// RDD = combine(#0,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_LOADRB_IO:
		// RDD = combine(#1,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_LOADRB_IO:
		// RDD = combine(#2,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_LOADRB_IO:
		// RDD = combine(#3,#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_LOADRB_IO:
		// RDD = combine(RS,#0) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_LOADRB_IO:
		// RDD = combine(#0,RS) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_LOADRB_IO:
		// RD = add(RS,#n1) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_LOADRB_IO:
		// RD = add(RS,#1) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_LOADRB_IO:
		// RD = #II ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_LOADRB_IO:
		// RD = #n1 ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_LOADRB_IO:
		// RD = sxtb(RS) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_LOADRB_IO:
		// RD = sxth(RS) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_LOADRB_IO:
		// RD = RS ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_LOADRB_IO:
		// RD = and(RS,#255) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_LOADRB_IO:
		// RD = zxth(RS) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_LOADRB_IO:
		// RD = memw(RS+#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_LOADRB_IO:
		// RD = memub(RS+#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_LOADRB_IO:
		// RD = memb(RS+#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_LOADRB_IO:
		// RD = memh(RS+#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_LOADRB_IO:
		// RD = memuh(RS+#II) ; Rd = memb(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_LOADRD_SP:
		// Rx = add(Rxin,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_LOADRD_SP:
		// Rx = add(Rxin,Rs) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_LOADRD_SP:
		// RD = add(r29,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_LOADRD_SP:
		// RD = and(Rs,#1) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_LOADRD_SP:
		// if (!p0) RD = #0 ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_LOADRD_SP:
		// if (!p0.new) RD = #0 ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_LOADRD_SP:
		// if (p0) RD = #0 ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_LOADRD_SP:
		// if (p0.new) RD = #0 ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_LOADRD_SP:
		// p0 = cmp.eq(Rs,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_LOADRD_SP:
		// RDD = combine(#0,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_LOADRD_SP:
		// RDD = combine(#1,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_LOADRD_SP:
		// RDD = combine(#2,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_LOADRD_SP:
		// RDD = combine(#3,#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_LOADRD_SP:
		// RDD = combine(Rs,#0) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_LOADRD_SP:
		// RDD = combine(#0,Rs) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_LOADRD_SP:
		// RD = add(Rs,#n1) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_LOADRD_SP:
		// RD = add(Rs,#1) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_LOADRD_SP:
		// RD = #II ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_LOADRD_SP:
		// RD = #n1 ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_LOADRD_SP:
		// RD = sxtb(Rs) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_LOADRD_SP:
		// RD = sxth(Rs) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_LOADRD_SP:
		// RD = Rs ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_LOADRD_SP:
		// RD = and(Rs,#255) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_LOADRD_SP:
		// RD = zxth(Rs) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_LOADRD_SP:
		// RD = memw(Rs+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_LOADRD_SP:
		// RD = memub(Rs+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_LOADRD_SP:
		// RD = memb(Rs+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_LOADRD_SP:
		// RDD = memd(r29+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_LOADRD_SP:
		// RD = memh(Rs+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_LOADRD_SP:
		// RD = memw(r29+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_LOADRD_SP:
		// RD = memuh(Rs+#II) ; Rdd = memd(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_LOADRH_IO:
		// Rx = add(Rxin,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_LOADRH_IO:
		// Rx = add(Rxin,RS) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_LOADRH_IO:
		// RD = add(r29,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_LOADRH_IO:
		// RD = and(RS,#1) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_LOADRH_IO:
		// if (!p0) RD = #0 ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_LOADRH_IO:
		// if (!p0.new) RD = #0 ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_LOADRH_IO:
		// if (p0) RD = #0 ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_LOADRH_IO:
		// if (p0.new) RD = #0 ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_LOADRH_IO:
		// p0 = cmp.eq(RS,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_LOADRH_IO:
		// RDD = combine(#0,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_LOADRH_IO:
		// RDD = combine(#1,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_LOADRH_IO:
		// RDD = combine(#2,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_LOADRH_IO:
		// RDD = combine(#3,#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_LOADRH_IO:
		// RDD = combine(RS,#0) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_LOADRH_IO:
		// RDD = combine(#0,RS) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_LOADRH_IO:
		// RD = add(RS,#n1) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_LOADRH_IO:
		// RD = add(RS,#1) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_LOADRH_IO:
		// RD = #II ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_LOADRH_IO:
		// RD = #n1 ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_LOADRH_IO:
		// RD = sxtb(RS) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_LOADRH_IO:
		// RD = sxth(RS) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_LOADRH_IO:
		// RD = RS ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_LOADRH_IO:
		// RD = and(RS,#255) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_LOADRH_IO:
		// RD = zxth(RS) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_LOADRH_IO:
		// RD = memw(RS+#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_LOADRH_IO:
		// RD = memub(RS+#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_LOADRH_IO:
		// RD = memh(RS+#II) ; Rd = memh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_LOADRI_SP:
		// Rx = add(Rxin,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_LOADRI_SP:
		// Rx = add(Rxin,Rs) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_LOADRI_SP:
		// RD = add(r29,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_LOADRI_SP:
		// RD = and(Rs,#1) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_LOADRI_SP:
		// if (!p0) RD = #0 ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_LOADRI_SP:
		// if (!p0.new) RD = #0 ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_LOADRI_SP:
		// if (p0) RD = #0 ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_LOADRI_SP:
		// if (p0.new) RD = #0 ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_LOADRI_SP:
		// p0 = cmp.eq(Rs,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_LOADRI_SP:
		// RDD = combine(#0,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_LOADRI_SP:
		// RDD = combine(#1,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_LOADRI_SP:
		// RDD = combine(#2,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_LOADRI_SP:
		// RDD = combine(#3,#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_LOADRI_SP:
		// RDD = combine(Rs,#0) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_LOADRI_SP:
		// RDD = combine(#0,Rs) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_LOADRI_SP:
		// RD = add(Rs,#n1) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_LOADRI_SP:
		// RD = add(Rs,#1) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_LOADRI_SP:
		// RD = #II ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_LOADRI_SP:
		// RD = #n1 ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_LOADRI_SP:
		// RD = sxtb(Rs) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_LOADRI_SP:
		// RD = sxth(Rs) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_LOADRI_SP:
		// RD = Rs ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_LOADRI_SP:
		// RD = and(Rs,#255) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_LOADRI_SP:
		// RD = zxth(Rs) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_LOADRI_SP:
		// RD = memw(Rs+#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_LOADRI_SP:
		// RD = memub(Rs+#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_LOADRI_SP:
		// RD = memb(Rs+#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_LOADRI_SP:
		// RD = memh(Rs+#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_LOADRI_SP:
		// RD = memw(r29+#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_LOADRI_SP:
		// RD = memuh(Rs+#II) ; Rd = memw(r29+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_LOADRUH_IO:
		// Rx = add(Rxin,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_LOADRUH_IO:
		// Rx = add(Rxin,RS) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_LOADRUH_IO:
		// RD = add(r29,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_LOADRUH_IO:
		// RD = and(RS,#1) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_LOADRUH_IO:
		// if (!p0) RD = #0 ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_LOADRUH_IO:
		// if (!p0.new) RD = #0 ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_LOADRUH_IO:
		// if (p0) RD = #0 ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_LOADRUH_IO:
		// if (p0.new) RD = #0 ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_LOADRUH_IO:
		// p0 = cmp.eq(RS,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_LOADRUH_IO:
		// RDD = combine(#0,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_LOADRUH_IO:
		// RDD = combine(#1,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_LOADRUH_IO:
		// RDD = combine(#2,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_LOADRUH_IO:
		// RDD = combine(#3,#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_LOADRUH_IO:
		// RDD = combine(RS,#0) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_LOADRUH_IO:
		// RDD = combine(#0,RS) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_LOADRUH_IO:
		// RD = add(RS,#n1) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_LOADRUH_IO:
		// RD = add(RS,#1) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_LOADRUH_IO:
		// RD = #II ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_LOADRUH_IO:
		// RD = #n1 ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_LOADRUH_IO:
		// RD = sxtb(RS) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_LOADRUH_IO:
		// RD = sxth(RS) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_LOADRUH_IO:
		// RD = RS ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_LOADRUH_IO:
		// RD = and(RS,#255) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_LOADRUH_IO:
		// RD = zxth(RS) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_LOADRUH_IO:
		// RD = memw(RS+#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_LOADRUH_IO:
		// RD = memub(RS+#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_LOADRUH_IO:
		// RD = memh(RS+#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_LOADRUH_IO:
		// RD = memuh(RS+#II) ; Rd = memuh(Rs+#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->val = hi->vals[5];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_RETURN:
		// Rx = add(Rxin,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_RETURN:
		// Rx = add(Rxin,Rs) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_RETURN:
		// Rd = add(r29,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_RETURN:
		// Rd = and(Rs,#1) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_RETURN:
		// if (!p0) Rd = #0 ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_RETURN:
		// if (!p0.new) Rd = #0 ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_RETURN:
		// if (p0) Rd = #0 ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_RETURN:
		// if (p0.new) Rd = #0 ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_RETURN:
		// p0 = cmp.eq(Rs,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_RETURN:
		// Rdd = combine(#0,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_RETURN:
		// Rdd = combine(#1,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_RETURN:
		// Rdd = combine(#2,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_RETURN:
		// Rdd = combine(#3,#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_RETURN:
		// Rdd = combine(Rs,#0) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_RETURN:
		// Rdd = combine(#0,Rs) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_RETURN:
		// Rd = add(Rs,#n1) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_RETURN:
		// Rd = add(Rs,#1) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_RETURN:
		// Rd = #Ii ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_RETURN:
		// Rd = #n1 ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_RETURN:
		// Rd = sxtb(Rs) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_RETURN:
		// Rd = sxth(Rs) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_RETURN:
		// Rd = Rs ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_RETURN:
		// Rd = and(Rs,#255) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_RETURN:
		// Rd = zxth(Rs) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_RETURN:
		// Rd = memw(Rs+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_RETURN:
		// Rd = memub(Rs+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_RETURN:
		// deallocframe ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_RETURN:
		// Rd = memb(Rs+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_RETURN:
		// Rdd = memd(r29+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_RETURN:
		// Rd = memh(Rs+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_RETURN:
		// Rd = memw(r29+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_RETURN:
		// Rd = memuh(Rs+#Ii) ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_RETURN:
		// dealloc_return ; dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_RETURN_F:
		// Rx = add(Rxin,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_RETURN_F:
		// Rx = add(Rxin,Rs) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_RETURN_F:
		// Rd = add(r29,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_RETURN_F:
		// Rd = and(Rs,#1) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_RETURN_F:
		// if (!p0) Rd = #0 ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_RETURN_F:
		// if (!p0.new) Rd = #0 ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_RETURN_F:
		// if (p0) Rd = #0 ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_RETURN_F:
		// if (p0.new) Rd = #0 ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_RETURN_F:
		// p0 = cmp.eq(Rs,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_RETURN_F:
		// Rdd = combine(#0,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_RETURN_F:
		// Rdd = combine(#1,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_RETURN_F:
		// Rdd = combine(#2,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_RETURN_F:
		// Rdd = combine(#3,#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_RETURN_F:
		// Rdd = combine(Rs,#0) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_RETURN_F:
		// Rdd = combine(#0,Rs) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_RETURN_F:
		// Rd = add(Rs,#n1) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_RETURN_F:
		// Rd = add(Rs,#1) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_RETURN_F:
		// Rd = #Ii ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_RETURN_F:
		// Rd = #n1 ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_RETURN_F:
		// Rd = sxtb(Rs) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_RETURN_F:
		// Rd = sxth(Rs) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_RETURN_F:
		// Rd = Rs ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_RETURN_F:
		// Rd = and(Rs,#255) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_RETURN_F:
		// Rd = zxth(Rs) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_RETURN_F:
		// Rd = memw(Rs+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_RETURN_F:
		// Rd = memub(Rs+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_RETURN_F:
		// deallocframe ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_RETURN_F:
		// Rd = memb(Rs+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_RETURN_F:
		// Rdd = memd(r29+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_RETURN_F:
		// Rd = memh(Rs+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_RETURN_F:
		// Rd = memw(r29+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_RETURN_F:
		// Rd = memuh(Rs+#Ii) ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_RETURN_F:
		// dealloc_return ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_RETURN_F:
		// if (!p0) dealloc_return ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_RETURN_F:
		// if (p0) dealloc_return ; if (!p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_RETURN_FNEW:
		// Rx = add(Rxin,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_RETURN_FNEW:
		// Rx = add(Rxin,Rs) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_RETURN_FNEW:
		// Rd = add(r29,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_RETURN_FNEW:
		// Rd = and(Rs,#1) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_RETURN_FNEW:
		// if (!p0) Rd = #0 ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_RETURN_FNEW:
		// if (!p0.new) Rd = #0 ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_RETURN_FNEW:
		// if (p0) Rd = #0 ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_RETURN_FNEW:
		// if (p0.new) Rd = #0 ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_RETURN_FNEW:
		// p0 = cmp.eq(Rs,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_RETURN_FNEW:
		// Rdd = combine(#0,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_RETURN_FNEW:
		// Rdd = combine(#1,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_RETURN_FNEW:
		// Rdd = combine(#2,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_RETURN_FNEW:
		// Rdd = combine(#3,#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_RETURN_FNEW:
		// Rdd = combine(Rs,#0) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_RETURN_FNEW:
		// Rdd = combine(#0,Rs) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_RETURN_FNEW:
		// Rd = add(Rs,#n1) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_RETURN_FNEW:
		// Rd = add(Rs,#1) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_RETURN_FNEW:
		// Rd = #Ii ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_RETURN_FNEW:
		// Rd = #n1 ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_RETURN_FNEW:
		// Rd = sxtb(Rs) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_RETURN_FNEW:
		// Rd = sxth(Rs) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_RETURN_FNEW:
		// Rd = Rs ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_RETURN_FNEW:
		// Rd = and(Rs,#255) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_RETURN_FNEW:
		// Rd = zxth(Rs) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_RETURN_FNEW:
		// Rd = memw(Rs+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_RETURN_FNEW:
		// Rd = memub(Rs+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_RETURN_FNEW:
		// deallocframe ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_RETURN_FNEW:
		// Rd = memb(Rs+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_RETURN_FNEW:
		// Rdd = memd(r29+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_RETURN_FNEW:
		// Rd = memh(Rs+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_RETURN_FNEW:
		// Rd = memw(r29+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_RETURN_FNEW:
		// Rd = memuh(Rs+#Ii) ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_RETURN_FNEW:
		// dealloc_return ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_RETURN_FNEW:
		// if (!p0) dealloc_return ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SL2_RETURN_FNEW:
		// if (!p0.new) dealloc_return:nt ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_RETURN_FNEW:
		// if (p0) dealloc_return ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_RETURN_FNEW:
		// if (p0.new) dealloc_return:nt ; if (!p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_RETURN_T:
		// Rx = add(Rxin,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_RETURN_T:
		// Rx = add(Rxin,Rs) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_RETURN_T:
		// Rd = add(r29,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_RETURN_T:
		// Rd = and(Rs,#1) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_RETURN_T:
		// if (!p0) Rd = #0 ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_RETURN_T:
		// if (!p0.new) Rd = #0 ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_RETURN_T:
		// if (p0) Rd = #0 ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_RETURN_T:
		// if (p0.new) Rd = #0 ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_RETURN_T:
		// p0 = cmp.eq(Rs,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_RETURN_T:
		// Rdd = combine(#0,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_RETURN_T:
		// Rdd = combine(#1,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_RETURN_T:
		// Rdd = combine(#2,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_RETURN_T:
		// Rdd = combine(#3,#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_RETURN_T:
		// Rdd = combine(Rs,#0) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_RETURN_T:
		// Rdd = combine(#0,Rs) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_RETURN_T:
		// Rd = add(Rs,#n1) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_RETURN_T:
		// Rd = add(Rs,#1) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_RETURN_T:
		// Rd = #Ii ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_RETURN_T:
		// Rd = #n1 ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_RETURN_T:
		// Rd = sxtb(Rs) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_RETURN_T:
		// Rd = sxth(Rs) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_RETURN_T:
		// Rd = Rs ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_RETURN_T:
		// Rd = and(Rs,#255) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_RETURN_T:
		// Rd = zxth(Rs) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_RETURN_T:
		// Rd = memw(Rs+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_RETURN_T:
		// Rd = memub(Rs+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_RETURN_T:
		// deallocframe ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_RETURN_T:
		// Rd = memb(Rs+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_RETURN_T:
		// Rdd = memd(r29+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_RETURN_T:
		// Rd = memh(Rs+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_RETURN_T:
		// Rd = memw(r29+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_RETURN_T:
		// Rd = memuh(Rs+#Ii) ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_RETURN_T:
		// dealloc_return ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_RETURN_T:
		// if (p0) dealloc_return ; if (p0) dealloc_return
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SL2_RETURN_TNEW:
		// Rx = add(Rxin,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SL2_RETURN_TNEW:
		// Rx = add(Rxin,Rs) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SL2_RETURN_TNEW:
		// Rd = add(r29,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SL2_RETURN_TNEW:
		// Rd = and(Rs,#1) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SL2_RETURN_TNEW:
		// if (!p0) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SL2_RETURN_TNEW:
		// if (!p0.new) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SL2_RETURN_TNEW:
		// if (p0) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SL2_RETURN_TNEW:
		// if (p0.new) Rd = #0 ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SL2_RETURN_TNEW:
		// p0 = cmp.eq(Rs,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SL2_RETURN_TNEW:
		// Rdd = combine(#0,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SL2_RETURN_TNEW:
		// Rdd = combine(#1,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SL2_RETURN_TNEW:
		// Rdd = combine(#2,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SL2_RETURN_TNEW:
		// Rdd = combine(#3,#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SL2_RETURN_TNEW:
		// Rdd = combine(Rs,#0) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SL2_RETURN_TNEW:
		// Rdd = combine(#0,Rs) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SL2_RETURN_TNEW:
		// Rd = add(Rs,#n1) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SL2_RETURN_TNEW:
		// Rd = add(Rs,#1) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SL2_RETURN_TNEW:
		// Rd = #Ii ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SL2_RETURN_TNEW:
		// Rd = #n1 ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SL2_RETURN_TNEW:
		// Rd = sxtb(Rs) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SL2_RETURN_TNEW:
		// Rd = sxth(Rs) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SL2_RETURN_TNEW:
		// Rd = Rs ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SL2_RETURN_TNEW:
		// Rd = and(Rs,#255) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SL2_RETURN_TNEW:
		// Rd = zxth(Rs) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SL2_RETURN_TNEW:
		// Rd = memw(Rs+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SL2_RETURN_TNEW:
		// Rd = memub(Rs+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SL2_RETURN_TNEW:
		// deallocframe ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SL2_RETURN_TNEW:
		// Rd = memb(Rs+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SL2_RETURN_TNEW:
		// Rdd = memd(r29+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SL2_RETURN_TNEW:
		// Rd = memh(Rs+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SL2_RETURN_TNEW:
		// Rd = memw(r29+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SL2_RETURN_TNEW:
		// Rd = memuh(Rs+#Ii) ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SL2_RETURN_TNEW:
		// dealloc_return ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SL2_RETURN_TNEW:
		// if (!p0) dealloc_return ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SL2_RETURN_TNEW:
		// if (p0) dealloc_return ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SL2_RETURN_TNEW:
		// if (p0.new) dealloc_return:nt ; if (p0.new) dealloc_return:nt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = UT64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS1_STOREB_IO:
		// Rx = add(Rxin,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS1_STOREB_IO:
		// Rx = add(Rxin,RS) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS1_STOREB_IO:
		// Rd = add(r29,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS1_STOREB_IO:
		// Rd = and(RS,#1) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS1_STOREB_IO:
		// if (!p0) Rd = #0 ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS1_STOREB_IO:
		// if (!p0.new) Rd = #0 ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS1_STOREB_IO:
		// if (p0) Rd = #0 ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS1_STOREB_IO:
		// if (p0.new) Rd = #0 ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS1_STOREB_IO:
		// p0 = cmp.eq(RS,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS1_STOREB_IO:
		// Rdd = combine(#0,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS1_STOREB_IO:
		// Rdd = combine(#1,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS1_STOREB_IO:
		// Rdd = combine(#2,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS1_STOREB_IO:
		// Rdd = combine(#3,#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS1_STOREB_IO:
		// Rdd = combine(RS,#0) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS1_STOREB_IO:
		// Rdd = combine(#0,RS) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS1_STOREB_IO:
		// Rd = add(RS,#n1) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS1_STOREB_IO:
		// Rd = add(RS,#1) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS1_STOREB_IO:
		// Rd = #II ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS1_STOREB_IO:
		// Rd = #n1 ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS1_STOREB_IO:
		// Rd = sxtb(RS) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS1_STOREB_IO:
		// Rd = sxth(RS) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS1_STOREB_IO:
		// Rd = RS ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS1_STOREB_IO:
		// Rd = and(RS,#255) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS1_STOREB_IO:
		// Rd = zxth(RS) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS1_STOREB_IO:
		// Rd = memw(RS+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS1_STOREB_IO:
		// Rd = memub(RS+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS1_STOREB_IO:
		// deallocframe ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS1_STOREB_IO:
		// Rd = memb(RS+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS1_STOREB_IO:
		// Rdd = memd(r29+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS1_STOREB_IO:
		// Rd = memh(RS+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS1_STOREB_IO:
		// Rd = memw(r29+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS1_STOREB_IO:
		// Rd = memuh(RS+#II) ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS1_STOREB_IO:
		// dealloc_return ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS1_STOREB_IO:
		// if (!p0) dealloc_return ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS1_STOREB_IO:
		// if (!p0.new) dealloc_return:nt ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS1_STOREB_IO:
		// if (p0) dealloc_return ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS1_STOREB_IO:
		// if (p0.new) dealloc_return:nt ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS1_STOREB_IO:
		// memb(RS+#II) = RT ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS1_STOREB_IO:
		// memw(RS+#II) = RT ; memb(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS1_STOREW_IO:
		// Rx = add(Rxin,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS1_STOREW_IO:
		// Rx = add(Rxin,RS) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS1_STOREW_IO:
		// Rd = add(r29,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS1_STOREW_IO:
		// Rd = and(RS,#1) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS1_STOREW_IO:
		// if (!p0) Rd = #0 ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS1_STOREW_IO:
		// if (!p0.new) Rd = #0 ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS1_STOREW_IO:
		// if (p0) Rd = #0 ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS1_STOREW_IO:
		// if (p0.new) Rd = #0 ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS1_STOREW_IO:
		// p0 = cmp.eq(RS,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS1_STOREW_IO:
		// Rdd = combine(#0,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS1_STOREW_IO:
		// Rdd = combine(#1,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS1_STOREW_IO:
		// Rdd = combine(#2,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS1_STOREW_IO:
		// Rdd = combine(#3,#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS1_STOREW_IO:
		// Rdd = combine(RS,#0) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS1_STOREW_IO:
		// Rdd = combine(#0,RS) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS1_STOREW_IO:
		// Rd = add(RS,#n1) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS1_STOREW_IO:
		// Rd = add(RS,#1) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS1_STOREW_IO:
		// Rd = #II ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS1_STOREW_IO:
		// Rd = #n1 ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS1_STOREW_IO:
		// Rd = sxtb(RS) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS1_STOREW_IO:
		// Rd = sxth(RS) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS1_STOREW_IO:
		// Rd = RS ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS1_STOREW_IO:
		// Rd = and(RS,#255) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS1_STOREW_IO:
		// Rd = zxth(RS) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS1_STOREW_IO:
		// Rd = memw(RS+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS1_STOREW_IO:
		// Rd = memub(RS+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS1_STOREW_IO:
		// deallocframe ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS1_STOREW_IO:
		// Rd = memb(RS+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS1_STOREW_IO:
		// Rdd = memd(r29+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS1_STOREW_IO:
		// Rd = memh(RS+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS1_STOREW_IO:
		// Rd = memw(r29+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS1_STOREW_IO:
		// Rd = memuh(RS+#II) ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS1_STOREW_IO:
		// dealloc_return ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS1_STOREW_IO:
		// if (!p0) dealloc_return ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS1_STOREW_IO:
		// if (!p0.new) dealloc_return:nt ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS1_STOREW_IO:
		// if (p0) dealloc_return ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS1_STOREW_IO:
		// if (p0.new) dealloc_return:nt ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS1_STOREW_IO:
		// memw(RS+#II) = RT ; memw(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_ALLOCFRAME:
		// Rx = add(Rxin,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_ALLOCFRAME:
		// Rx = add(Rxin,Rs) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_ALLOCFRAME:
		// Rd = add(r29,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_ALLOCFRAME:
		// Rd = and(Rs,#1) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_ALLOCFRAME:
		// if (!p0) Rd = #0 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_ALLOCFRAME:
		// if (!p0.new) Rd = #0 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_ALLOCFRAME:
		// if (p0) Rd = #0 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_ALLOCFRAME:
		// if (p0.new) Rd = #0 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_ALLOCFRAME:
		// p0 = cmp.eq(Rs,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_ALLOCFRAME:
		// Rdd = combine(#0,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_ALLOCFRAME:
		// Rdd = combine(#1,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_ALLOCFRAME:
		// Rdd = combine(#2,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_ALLOCFRAME:
		// Rdd = combine(#3,#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_ALLOCFRAME:
		// Rdd = combine(Rs,#0) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_ALLOCFRAME:
		// Rdd = combine(#0,Rs) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_ALLOCFRAME:
		// Rd = add(Rs,#n1) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_ALLOCFRAME:
		// Rd = add(Rs,#1) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_ALLOCFRAME:
		// Rd = #II ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_ALLOCFRAME:
		// Rd = #n1 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_ALLOCFRAME:
		// Rd = sxtb(Rs) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_ALLOCFRAME:
		// Rd = sxth(Rs) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_ALLOCFRAME:
		// Rd = Rs ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_ALLOCFRAME:
		// Rd = and(Rs,#255) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_ALLOCFRAME:
		// Rd = zxth(Rs) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_ALLOCFRAME:
		// Rd = memw(Rs+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_ALLOCFRAME:
		// Rd = memub(Rs+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_ALLOCFRAME:
		// deallocframe ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_ALLOCFRAME:
		// Rd = memb(Rs+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_ALLOCFRAME:
		// Rdd = memd(r29+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_ALLOCFRAME:
		// Rd = memh(Rs+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_ALLOCFRAME:
		// Rd = memw(r29+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_ALLOCFRAME:
		// Rd = memuh(Rs+#II) ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_ALLOCFRAME:
		// dealloc_return ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_ALLOCFRAME:
		// if (!p0) dealloc_return ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_ALLOCFRAME:
		// if (!p0.new) dealloc_return:nt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_ALLOCFRAME:
		// if (p0) dealloc_return ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_ALLOCFRAME:
		// if (p0.new) dealloc_return:nt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = ST64_MAX;
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_ALLOCFRAME:
		// memb(Rs+#II) = Rt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_ALLOCFRAME:
		// memw(Rs+#II) = Rt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREBI0_SS2_ALLOCFRAME:
		// memb(Rs+#II) = #0 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREBI1_SS2_ALLOCFRAME:
		// memb(Rs+#II) = #1 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STORED_SP_SS2_ALLOCFRAME:
		// memd(r29+#II) = Rtt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_ALLOCFRAME:
		// memh(Rs+#II) = Rt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_ALLOCFRAME:
		// memw(r29+#II) = Rt ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI0_SS2_ALLOCFRAME:
		// memw(Rs+#II) = #0 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI1_SS2_ALLOCFRAME:
		// memw(Rs+#II) = #1 ; allocframe(#Ii)
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STOREBI0:
		// Rx = add(Rxin,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STOREBI0:
		// Rx = add(Rxin,RS) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STOREBI0:
		// Rd = add(r29,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STOREBI0:
		// Rd = and(RS,#1) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STOREBI0:
		// if (!p0) Rd = #0 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STOREBI0:
		// if (!p0.new) Rd = #0 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STOREBI0:
		// if (p0) Rd = #0 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STOREBI0:
		// if (p0.new) Rd = #0 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STOREBI0:
		// p0 = cmp.eq(RS,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STOREBI0:
		// Rdd = combine(#0,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STOREBI0:
		// Rdd = combine(#1,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STOREBI0:
		// Rdd = combine(#2,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STOREBI0:
		// Rdd = combine(#3,#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STOREBI0:
		// Rdd = combine(RS,#0) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STOREBI0:
		// Rdd = combine(#0,RS) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STOREBI0:
		// Rd = add(RS,#n1) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STOREBI0:
		// Rd = add(RS,#1) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STOREBI0:
		// Rd = #II ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STOREBI0:
		// Rd = #n1 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STOREBI0:
		// Rd = sxtb(RS) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STOREBI0:
		// Rd = sxth(RS) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STOREBI0:
		// Rd = RS ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STOREBI0:
		// Rd = and(RS,#255) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STOREBI0:
		// Rd = zxth(RS) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STOREBI0:
		// Rd = memw(RS+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STOREBI0:
		// Rd = memub(RS+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STOREBI0:
		// deallocframe ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STOREBI0:
		// Rd = memb(RS+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STOREBI0:
		// Rdd = memd(r29+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STOREBI0:
		// Rd = memh(RS+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STOREBI0:
		// Rd = memw(r29+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STOREBI0:
		// Rd = memuh(RS+#II) ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STOREBI0:
		// dealloc_return ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STOREBI0:
		// if (!p0) dealloc_return ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STOREBI0:
		// if (!p0.new) dealloc_return:nt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STOREBI0:
		// if (p0) dealloc_return ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STOREBI0:
		// if (p0.new) dealloc_return:nt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STOREBI0:
		// memb(RS+#II) = Rt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STOREBI0:
		// memw(RS+#II) = Rt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREBI0_SS2_STOREBI0:
		// memb(RS+#II) = #0 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STORED_SP_SS2_STOREBI0:
		// memd(r29+#II) = Rtt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STOREBI0:
		// memh(RS+#II) = Rt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_STOREBI0:
		// memw(r29+#II) = Rt ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI0_SS2_STOREBI0:
		// memw(RS+#II) = #0 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI1_SS2_STOREBI0:
		// memw(RS+#II) = #1 ; memb(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STOREBI1:
		// Rx = add(Rxin,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STOREBI1:
		// Rx = add(Rxin,RS) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STOREBI1:
		// Rd = add(r29,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STOREBI1:
		// Rd = and(RS,#1) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STOREBI1:
		// if (!p0) Rd = #0 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STOREBI1:
		// if (!p0.new) Rd = #0 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STOREBI1:
		// if (p0) Rd = #0 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STOREBI1:
		// if (p0.new) Rd = #0 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STOREBI1:
		// p0 = cmp.eq(RS,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STOREBI1:
		// Rdd = combine(#0,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STOREBI1:
		// Rdd = combine(#1,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STOREBI1:
		// Rdd = combine(#2,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STOREBI1:
		// Rdd = combine(#3,#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STOREBI1:
		// Rdd = combine(RS,#0) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STOREBI1:
		// Rdd = combine(#0,RS) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STOREBI1:
		// Rd = add(RS,#n1) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STOREBI1:
		// Rd = add(RS,#1) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STOREBI1:
		// Rd = #II ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STOREBI1:
		// Rd = #n1 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STOREBI1:
		// Rd = sxtb(RS) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STOREBI1:
		// Rd = sxth(RS) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STOREBI1:
		// Rd = RS ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STOREBI1:
		// Rd = and(RS,#255) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STOREBI1:
		// Rd = zxth(RS) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STOREBI1:
		// Rd = memw(RS+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STOREBI1:
		// Rd = memub(RS+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STOREBI1:
		// deallocframe ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STOREBI1:
		// Rd = memb(RS+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STOREBI1:
		// Rdd = memd(r29+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STOREBI1:
		// Rd = memh(RS+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STOREBI1:
		// Rd = memw(r29+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STOREBI1:
		// Rd = memuh(RS+#II) ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STOREBI1:
		// dealloc_return ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STOREBI1:
		// if (!p0) dealloc_return ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STOREBI1:
		// if (!p0.new) dealloc_return:nt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STOREBI1:
		// if (p0) dealloc_return ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STOREBI1:
		// if (p0.new) dealloc_return:nt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STOREBI1:
		// memb(RS+#II) = Rt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STOREBI1:
		// memw(RS+#II) = Rt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREBI0_SS2_STOREBI1:
		// memb(RS+#II) = #0 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREBI1_SS2_STOREBI1:
		// memb(RS+#II) = #1 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STORED_SP_SS2_STOREBI1:
		// memd(r29+#II) = Rtt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STOREBI1:
		// memh(RS+#II) = Rt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_STOREBI1:
		// memw(r29+#II) = Rt ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI0_SS2_STOREBI1:
		// memw(RS+#II) = #0 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI1_SS2_STOREBI1:
		// memw(RS+#II) = #1 ; memb(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STORED_SP:
		// Rx = add(Rxin,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STORED_SP:
		// Rx = add(Rxin,Rs) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STORED_SP:
		// Rd = add(r29,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STORED_SP:
		// Rd = and(Rs,#1) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STORED_SP:
		// if (!p0) Rd = #0 ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STORED_SP:
		// if (!p0.new) Rd = #0 ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STORED_SP:
		// if (p0) Rd = #0 ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STORED_SP:
		// if (p0.new) Rd = #0 ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STORED_SP:
		// p0 = cmp.eq(Rs,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STORED_SP:
		// Rdd = combine(#0,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STORED_SP:
		// Rdd = combine(#1,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STORED_SP:
		// Rdd = combine(#2,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STORED_SP:
		// Rdd = combine(#3,#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STORED_SP:
		// Rdd = combine(Rs,#0) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STORED_SP:
		// Rdd = combine(#0,Rs) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STORED_SP:
		// Rd = add(Rs,#n1) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STORED_SP:
		// Rd = add(Rs,#1) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STORED_SP:
		// Rd = #II ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STORED_SP:
		// Rd = #n1 ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STORED_SP:
		// Rd = sxtb(Rs) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STORED_SP:
		// Rd = sxth(Rs) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STORED_SP:
		// Rd = Rs ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STORED_SP:
		// Rd = and(Rs,#255) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STORED_SP:
		// Rd = zxth(Rs) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STORED_SP:
		// Rd = memw(Rs+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STORED_SP:
		// Rd = memub(Rs+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STORED_SP:
		// deallocframe ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STORED_SP:
		// Rd = memb(Rs+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STORED_SP:
		// Rdd = memd(r29+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STORED_SP:
		// Rd = memh(Rs+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STORED_SP:
		// Rd = memw(r29+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STORED_SP:
		// Rd = memuh(Rs+#II) ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STORED_SP:
		// dealloc_return ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STORED_SP:
		// if (!p0) dealloc_return ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STORED_SP:
		// if (!p0.new) dealloc_return:nt ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STORED_SP:
		// if (p0) dealloc_return ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STORED_SP:
		// if (p0.new) dealloc_return:nt ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STORED_SP:
		// memb(Rs+#II) = RT ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STORED_SP:
		// memw(Rs+#II) = RT ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STORED_SP_SS2_STORED_SP:
		// memd(r29+#II) = RTT ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STORED_SP:
		// memh(Rs+#II) = RT ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_STORED_SP:
		// memw(r29+#II) = RT ; memd(r29+#Ii) = Rtt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STOREH_IO:
		// Rx = add(Rxin,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STOREH_IO:
		// Rx = add(Rxin,RS) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STOREH_IO:
		// Rd = add(r29,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STOREH_IO:
		// Rd = and(RS,#1) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STOREH_IO:
		// if (!p0) Rd = #0 ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STOREH_IO:
		// if (!p0.new) Rd = #0 ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STOREH_IO:
		// if (p0) Rd = #0 ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STOREH_IO:
		// if (p0.new) Rd = #0 ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STOREH_IO:
		// p0 = cmp.eq(RS,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STOREH_IO:
		// Rdd = combine(#0,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STOREH_IO:
		// Rdd = combine(#1,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STOREH_IO:
		// Rdd = combine(#2,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STOREH_IO:
		// Rdd = combine(#3,#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STOREH_IO:
		// Rdd = combine(RS,#0) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STOREH_IO:
		// Rdd = combine(#0,RS) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STOREH_IO:
		// Rd = add(RS,#n1) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STOREH_IO:
		// Rd = add(RS,#1) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STOREH_IO:
		// Rd = #II ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STOREH_IO:
		// Rd = #n1 ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STOREH_IO:
		// Rd = sxtb(RS) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STOREH_IO:
		// Rd = sxth(RS) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STOREH_IO:
		// Rd = RS ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STOREH_IO:
		// Rd = and(RS,#255) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STOREH_IO:
		// Rd = zxth(RS) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STOREH_IO:
		// Rd = memw(RS+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STOREH_IO:
		// Rd = memub(RS+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STOREH_IO:
		// deallocframe ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STOREH_IO:
		// Rd = memb(RS+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STOREH_IO:
		// Rdd = memd(r29+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STOREH_IO:
		// Rd = memh(RS+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STOREH_IO:
		// Rd = memw(r29+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STOREH_IO:
		// Rd = memuh(RS+#II) ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STOREH_IO:
		// dealloc_return ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STOREH_IO:
		// if (!p0) dealloc_return ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STOREH_IO:
		// if (!p0.new) dealloc_return:nt ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STOREH_IO:
		// if (p0) dealloc_return ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STOREH_IO:
		// if (p0.new) dealloc_return:nt ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STOREH_IO:
		// memb(RS+#II) = RT ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STOREH_IO:
		// memw(RS+#II) = RT ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STOREH_IO:
		// memh(RS+#II) = RT ; memh(Rs+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = hi->vals[5];
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STOREW_SP:
		// Rx = add(Rxin,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STOREW_SP:
		// Rx = add(Rxin,Rs) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STOREW_SP:
		// Rd = add(r29,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STOREW_SP:
		// Rd = and(Rs,#1) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STOREW_SP:
		// if (!p0) Rd = #0 ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STOREW_SP:
		// if (!p0.new) Rd = #0 ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STOREW_SP:
		// if (p0) Rd = #0 ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STOREW_SP:
		// if (p0.new) Rd = #0 ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STOREW_SP:
		// p0 = cmp.eq(Rs,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STOREW_SP:
		// Rdd = combine(#0,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STOREW_SP:
		// Rdd = combine(#1,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STOREW_SP:
		// Rdd = combine(#2,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STOREW_SP:
		// Rdd = combine(#3,#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STOREW_SP:
		// Rdd = combine(Rs,#0) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STOREW_SP:
		// Rdd = combine(#0,Rs) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STOREW_SP:
		// Rd = add(Rs,#n1) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STOREW_SP:
		// Rd = add(Rs,#1) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STOREW_SP:
		// Rd = #II ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STOREW_SP:
		// Rd = #n1 ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STOREW_SP:
		// Rd = sxtb(Rs) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STOREW_SP:
		// Rd = sxth(Rs) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STOREW_SP:
		// Rd = Rs ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STOREW_SP:
		// Rd = and(Rs,#255) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STOREW_SP:
		// Rd = zxth(Rs) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STOREW_SP:
		// Rd = memw(Rs+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STOREW_SP:
		// Rd = memub(Rs+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STOREW_SP:
		// deallocframe ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STOREW_SP:
		// Rd = memb(Rs+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STOREW_SP:
		// Rdd = memd(r29+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STOREW_SP:
		// Rd = memh(Rs+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STOREW_SP:
		// Rd = memw(r29+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STOREW_SP:
		// Rd = memuh(Rs+#II) ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STOREW_SP:
		// dealloc_return ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STOREW_SP:
		// if (!p0) dealloc_return ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STOREW_SP:
		// if (!p0.new) dealloc_return:nt ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STOREW_SP:
		// if (p0) dealloc_return ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STOREW_SP:
		// if (p0.new) dealloc_return:nt ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STOREW_SP:
		// memb(Rs+#II) = RT ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STOREW_SP:
		// memw(Rs+#II) = RT ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STOREW_SP:
		// memh(Rs+#II) = RT ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_STOREW_SP:
		// memw(r29+#II) = RT ; memw(r29+#Ii) = Rt
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STOREWI0:
		// Rx = add(Rxin,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STOREWI0:
		// Rx = add(Rxin,RS) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STOREWI0:
		// Rd = add(r29,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STOREWI0:
		// Rd = and(RS,#1) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STOREWI0:
		// if (!p0) Rd = #0 ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STOREWI0:
		// if (!p0.new) Rd = #0 ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STOREWI0:
		// if (p0) Rd = #0 ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STOREWI0:
		// if (p0.new) Rd = #0 ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STOREWI0:
		// p0 = cmp.eq(RS,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STOREWI0:
		// Rdd = combine(#0,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STOREWI0:
		// Rdd = combine(#1,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STOREWI0:
		// Rdd = combine(#2,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STOREWI0:
		// Rdd = combine(#3,#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STOREWI0:
		// Rdd = combine(RS,#0) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STOREWI0:
		// Rdd = combine(#0,RS) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STOREWI0:
		// Rd = add(RS,#n1) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STOREWI0:
		// Rd = add(RS,#1) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STOREWI0:
		// Rd = #II ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STOREWI0:
		// Rd = #n1 ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STOREWI0:
		// Rd = sxtb(RS) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STOREWI0:
		// Rd = sxth(RS) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STOREWI0:
		// Rd = RS ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STOREWI0:
		// Rd = and(RS,#255) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STOREWI0:
		// Rd = zxth(RS) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STOREWI0:
		// Rd = memw(RS+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STOREWI0:
		// Rd = memub(RS+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STOREWI0:
		// deallocframe ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STOREWI0:
		// Rd = memb(RS+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STOREWI0:
		// Rdd = memd(r29+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STOREWI0:
		// Rd = memh(RS+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STOREWI0:
		// Rd = memw(r29+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STOREWI0:
		// Rd = memuh(RS+#II) ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STOREWI0:
		// dealloc_return ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STOREWI0:
		// if (!p0) dealloc_return ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STOREWI0:
		// if (!p0.new) dealloc_return:nt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STOREWI0:
		// if (p0) dealloc_return ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STOREWI0:
		// if (p0.new) dealloc_return:nt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STOREWI0:
		// memb(RS+#II) = Rt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STOREWI0:
		// memw(RS+#II) = Rt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STORED_SP_SS2_STOREWI0:
		// memd(r29+#II) = Rtt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STOREWI0:
		// memh(RS+#II) = Rt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_STOREWI0:
		// memw(r29+#II) = Rt ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI0_SS2_STOREWI0:
		// memw(RS+#II) = #0 ; memw(Rs+#Ii) = #0
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDI_SS2_STOREWI1:
		// Rx = add(Rxin,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDRX_SS2_STOREWI1:
		// Rx = add(Rxin,RS) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ADDSP_SS2_STOREWI1:
		// Rd = add(r29,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_AND1_SS2_STOREWI1:
		// Rd = and(RS,#1) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRF_SS2_STOREWI1:
		// if (!p0) Rd = #0 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRFNEW_SS2_STOREWI1:
		// if (!p0.new) Rd = #0 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRT_SS2_STOREWI1:
		// if (p0) Rd = #0 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CLRTNEW_SS2_STOREWI1:
		// if (p0.new) Rd = #0 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_CMPEQI_SS2_STOREWI1:
		// p0 = cmp.eq(RS,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE0I_SS2_STOREWI1:
		// Rdd = combine(#0,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE1I_SS2_STOREWI1:
		// Rdd = combine(#1,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE2I_SS2_STOREWI1:
		// Rdd = combine(#2,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINE3I_SS2_STOREWI1:
		// Rdd = combine(#3,#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINERZ_SS2_STOREWI1:
		// Rdd = combine(RS,#0) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_COMBINEZR_SS2_STOREWI1:
		// Rdd = combine(#0,RS) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_DEC_SS2_STOREWI1:
		// Rd = add(RS,#n1) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_INC_SS2_STOREWI1:
		// Rd = add(RS,#1) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETI_SS2_STOREWI1:
		// Rd = #II ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SETIN1_SS2_STOREWI1:
		// Rd = #n1 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTB_SS2_STOREWI1:
		// Rd = sxtb(RS) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_SXTH_SS2_STOREWI1:
		// Rd = sxth(RS) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_TFR_SS2_STOREWI1:
		// Rd = RS ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTB_SS2_STOREWI1:
		// Rd = and(RS,#255) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SA1_ZXTH_SS2_STOREWI1:
		// Rd = zxth(RS) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRI_IO_SS2_STOREWI1:
		// Rd = memw(RS+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL1_LOADRUB_IO_SS2_STOREWI1:
		// Rd = memub(RS+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_DEALLOCFRAME_SS2_STOREWI1:
		// deallocframe ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRB_IO_SS2_STOREWI1:
		// Rd = memb(RS+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRD_SP_SS2_STOREWI1:
		// Rdd = memd(r29+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRH_IO_SS2_STOREWI1:
		// Rd = memh(RS+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRI_SP_SS2_STOREWI1:
		// Rd = memw(r29+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_LOADRUH_IO_SS2_STOREWI1:
		// Rd = memuh(RS+#II) ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->val = hi->vals[2];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_SS2_STOREWI1:
		// dealloc_return ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_F_SS2_STOREWI1:
		// if (!p0) dealloc_return ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_FNEW_SS2_STOREWI1:
		// if (!p0.new) dealloc_return:nt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_T_SS2_STOREWI1:
		// if (p0) dealloc_return ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SL2_RETURN_TNEW_SS2_STOREWI1:
		// if (p0.new) dealloc_return:nt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = ST64_MAX;
		op->analysis_vals[3].imm = ST64_MAX;
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREB_IO_SS2_STOREWI1:
		// memb(RS+#II) = Rt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS1_STOREW_IO_SS2_STOREWI1:
		// memw(RS+#II) = Rt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STORED_SP_SS2_STOREWI1:
		// memd(r29+#II) = Rtt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREH_IO_SS2_STOREWI1:
		// memh(RS+#II) = Rt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->analysis_vals[3].imm = hi->vals[3];
		op->val = hi->vals[4];
		op->analysis_vals[4].imm = hi->vals[4];
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREW_SP_SS2_STOREWI1:
		// memw(r29+#II) = Rt ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->val = hi->vals[0];
		op->analysis_vals[0].imm = hi->vals[0];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI0_SS2_STOREWI1:
		// memw(RS+#II) = #0 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	case HEX_INS_X2_AUTOJOIN_SS2_STOREWI1_SS2_STOREWI1:
		// memw(RS+#II) = #1 ; memw(Rs+#Ii) = #1
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		op->analysis_vals[0].imm = hi->vals[0];
		op->val = hi->vals[1];
		op->analysis_vals[1].imm = hi->vals[1];
		op->analysis_vals[2].imm = hi->vals[2];
		op->val = hi->vals[3];
		op->analysis_vals[3].imm = hi->vals[3];
		op->analysis_vals[4].imm = ST64_MAX;
		op->analysis_vals[5].imm = ST64_MAX;
		break;
	}
	return op->size;
}