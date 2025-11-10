// SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_il/rz_il_opbuilder_begin.h>
#include "../hexagon_il.h"
#include <hexagon/hexagon.h>
#include <rz_il/rz_il_opcodes.h>

// Rd = abs(Rs)
RzILOpEffect *hex_il_op_a2_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((Rs < 0x0) ? (-Rs) : Rs);
	RzILOpPure *op_LT_3 = SLT(Rs, SN(32, 0));
	RzILOpPure *op_NEG_4 = NEG(DUP(Rs));
	RzILOpPure *cond_5 = ITE(op_LT_3, op_NEG_4, DUP(Rs));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, cond_5);

	RzILOpEffect *instruction_sequence = op_ASSIGN_6;
	return instruction_sequence;
}

// Rdd = abs(Rss)
RzILOpEffect *hex_il_op_a2_absp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((Rss < ((st64) 0x0)) ? (-Rss) : Rss);
	RzILOpPure *op_LT_4 = SLT(Rss, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_5 = NEG(DUP(Rss));
	RzILOpPure *cond_6 = ITE(op_LT_4, op_NEG_5, DUP(Rss));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, cond_6);

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Rd = abs(Rs):sat
RzILOpEffect *hex_il_op_a2_abssat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_37 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs))), 0x0, 0x20) == ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs)) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_LT_8 = SLT(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_10 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_12 = ITE(op_LT_8, op_NEG_10, CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_21 = SLT(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_23 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_25 = ITE(op_LT_21, op_NEG_23, CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_EQ_26 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_12), SN(32, 0), SN(32, 0x20)), cond_25);
	RzILOpPure *op_LT_41 = SLT(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_43 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_45 = ITE(op_LT_41, op_NEG_43, CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_48 = SLT(cond_45, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_54 = NEG(op_LSHIFT_53);
	RzILOpPure *op_LSHIFT_59 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_62 = SUB(op_LSHIFT_59, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_63 = ITE(op_LT_48, op_NEG_54, op_SUB_62);
	RzILOpEffect *gcc_expr_64 = BRANCH(op_EQ_26, EMPTY(), set_usr_field_call_37);

	// h_tmp0 = HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs))), 0x0, 0x20) == ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs)) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_66 = SETL("h_tmp0", cond_63);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) < ((st64) ...;
	RzILOpEffect *seq_67 = SEQN(2, gcc_expr_64, op_ASSIGN_hybrid_tmp_66);

	// Rd = ((st32) ((sextract64(((ut64) ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs))), 0x0, 0x20) == ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs))) ? ((((st64) Rs) < ((st64) 0x0)) ? (-((st64) Rs)) : ((st64) Rs)) : h_tmp0));
	RzILOpPure *op_LT_30 = SLT(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_32 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_34 = ITE(op_LT_30, op_NEG_32, CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_68 = ITE(DUP(op_EQ_26), cond_34, VARL("h_tmp0"));
	RzILOpEffect *op_ASSIGN_70 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_68), DUP(cond_68)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) < ((s ...;
	RzILOpEffect *seq_71 = SEQN(2, seq_67, op_ASSIGN_70);

	RzILOpEffect *instruction_sequence = seq_71;
	return instruction_sequence;
}

// Rd = add(Rs,Rt)
RzILOpEffect *hex_il_op_a2_add(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = Rs + Rt;
	RzILOpPure *op_ADD_3 = ADD(Rs, Rt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_ADD_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = add(Rt.h,Rs.h):<<16
RzILOpEffect *hex_il_op_a2_addh_h16_hh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_ADD_19 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_ADD_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = add(Rt.h,Rs.l):<<16
RzILOpEffect *hex_il_op_a2_addh_h16_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_ADD_19 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_ADD_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.h):<<16
RzILOpEffect *hex_il_op_a2_addh_h16_lh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_ADD_19 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_ADD_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.l):<<16
RzILOpEffect *hex_il_op_a2_addh_h16_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_ADD_19 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_ADD_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = add(Rt.h,Rs.h):sat:<<16
RzILOpEffect *hex_il_op_a2_addh_h16_sat_hh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_ADD_44 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_44), DUP(op_ADD_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_ADD_83 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_ADD_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp1 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp1", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))) : h_tmp1) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_ADD_63 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_ADD_63), DUP(op_ADD_63)), VARL("h_tmp1"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = add(Rt.h,Rs.l):sat:<<16
RzILOpEffect *hex_il_op_a2_addh_h16_sat_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_ADD_44 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_44), DUP(op_ADD_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_ADD_83 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_ADD_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp2 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp2", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))) : h_tmp2) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_ADD_63 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_ADD_63), DUP(op_ADD_63)), VARL("h_tmp2"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.h):sat:<<16
RzILOpEffect *hex_il_op_a2_addh_h16_sat_lh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_ADD_44 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_44), DUP(op_ADD_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_ADD_83 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_ADD_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp3 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp3", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))) : h_tmp3) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_ADD_63 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_ADD_63), DUP(op_ADD_63)), VARL("h_tmp3"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.l):sat:<<16
RzILOpEffect *hex_il_op_a2_addh_h16_sat_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_ADD_44 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_44), DUP(op_ADD_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_ADD_83 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_ADD_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp4 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp4", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))) : h_tmp4) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_ADD_63 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_ADD_63), DUP(op_ADD_63)), VARL("h_tmp4"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.h)
RzILOpEffect *hex_il_op_a2_addh_l16_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(op_ADD_22)), SN(32, 0), SN(32, 16))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_29;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.l)
RzILOpEffect *hex_il_op_a2_addh_l16_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(op_ADD_22)), SN(32, 0), SN(32, 16))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_29;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.h):sat
RzILOpEffect *hex_il_op_a2_addh_l16_sat_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_ADD_44 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_44), DUP(op_ADD_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_ADD_83 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_ADD_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp5 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp5", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))) : h_tmp5));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_ADD_63 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_ADD_63), DUP(op_ADD_63)), VARL("h_tmp5"));
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_106), DUP(cond_106)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_109 = SEQN(2, seq_104, op_ASSIGN_108);

	RzILOpEffect *instruction_sequence = seq_109;
	return instruction_sequence;
}

// Rd = add(Rt.l,Rs.l):sat
RzILOpEffect *hex_il_op_a2_addh_l16_sat_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_ADD_22 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_ADD_44 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_44), DUP(op_ADD_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_ADD_83 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_ADD_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp6 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp6", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) + ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))) : h_tmp6));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_ADD_63 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_ADD_63), DUP(op_ADD_63)), VARL("h_tmp6"));
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_106), DUP(cond_106)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_109 = SEQN(2, seq_104, op_ASSIGN_108);

	RzILOpEffect *instruction_sequence = seq_109;
	return instruction_sequence;
}

// Rd = add(Rs,Ii)
RzILOpEffect *hex_il_op_a2_addi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = Rs + s;
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_ADD_4);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_5);
	return instruction_sequence;
}

// Rdd = add(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_addp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = Rss + Rtt;
	RzILOpPure *op_ADD_3 = ADD(Rss, Rtt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, op_ADD_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rdd = add(Rss,Rtt):sat
RzILOpEffect *hex_il_op_a2_addpsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	// Declare: ut64 __a;
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: ut64 __b;
	// Declare: ut64 __sum;
	// Declare: ut64 __xor;
	// Declare: ut64 __mask;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// __a = ((ut64) Rss);
	RzILOpEffect *op_ASSIGN_3 = SETL("__a", CAST(64, IL_FALSE, Rss));

	// __b = ((ut64) Rtt);
	RzILOpEffect *op_ASSIGN_7 = SETL("__b", CAST(64, IL_FALSE, Rtt));

	// __sum = __a + __b;
	RzILOpPure *op_ADD_8 = ADD(VARL("__a"), VARL("__b"));
	RzILOpEffect *op_ASSIGN_10 = SETL("__sum", op_ADD_8);

	// __xor = (__a ^ __b);
	RzILOpPure *op_XOR_11 = LOGXOR(VARL("__a"), VARL("__b"));
	RzILOpEffect *op_ASSIGN_13 = SETL("__xor", op_XOR_11);

	// __mask = 0x8000000000000000;
	RzILOpEffect *op_ASSIGN_16 = SETL("__mask", UN(64, 0x8000000000000000));

	// Rdd = ((st64) __sum);
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, VARL("__sum")));

	// Rdd = 0x7fffffffffffffff;
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rdd_op, SN(64, 0x7fffffffffffffff));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_28 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// Rdd = 0x8000000000000000;
	RzILOpEffect *op_ASSIGN_30 = WRITE_REG(bundle, Rdd_op, SN(64, 0x8000000000000000));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_33 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// seq(Rdd = 0x7fffffffffffffff; set_usr_field(bundle, HEX_REG_FIEL ...;
	RzILOpEffect *seq_then_34 = SEQN(2, op_ASSIGN_25, set_usr_field_call_28);

	// seq(Rdd = 0x8000000000000000; set_usr_field(bundle, HEX_REG_FIEL ...;
	RzILOpEffect *seq_else_35 = SEQN(2, op_ASSIGN_30, set_usr_field_call_33);

	// if ((__sum & __mask)) {seq(Rdd = 0x7fffffffffffffff; set_usr_field(bundle, HEX_REG_FIEL ...} else {seq(Rdd = 0x8000000000000000; set_usr_field(bundle, HEX_REG_FIEL ...};
	RzILOpPure *op_AND_23 = LOGAND(VARL("__sum"), VARL("__mask"));
	RzILOpEffect *branch_36 = BRANCH(NON_ZERO(op_AND_23), seq_then_34, seq_else_35);

	// Rdd = ((st64) __sum);
	RzILOpEffect *op_ASSIGN_38 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, VARL("__sum")));

	// seq(if ((__sum & __mask)) {seq(Rdd = 0x7fffffffffffffff; set_usr ...;
	RzILOpEffect *seq_then_39 = branch_36;

	// seq(Rdd = ((st64) __sum));
	RzILOpEffect *seq_else_40 = op_ASSIGN_38;

	// if (((__a ^ __sum) & __mask)) {seq(if ((__sum & __mask)) {seq(Rdd = 0x7fffffffffffffff; set_usr ...} else {seq(Rdd = ((st64) __sum))};
	RzILOpPure *op_XOR_21 = LOGXOR(VARL("__a"), VARL("__sum"));
	RzILOpPure *op_AND_22 = LOGAND(op_XOR_21, VARL("__mask"));
	RzILOpEffect *branch_41 = BRANCH(NON_ZERO(op_AND_22), seq_then_39, seq_else_40);

	// seq(Rdd = ((st64) __sum));
	RzILOpEffect *seq_then_42 = op_ASSIGN_20;

	// seq(if (((__a ^ __sum) & __mask)) {seq(if ((__sum & __mask)) {se ...;
	RzILOpEffect *seq_else_43 = branch_41;

	// if ((__xor & __mask)) {seq(Rdd = ((st64) __sum))} else {seq(if (((__a ^ __sum) & __mask)) {seq(if ((__sum & __mask)) {se ...};
	RzILOpPure *op_AND_17 = LOGAND(VARL("__xor"), VARL("__mask"));
	RzILOpEffect *branch_44 = BRANCH(NON_ZERO(op_AND_17), seq_then_42, seq_else_43);

	RzILOpEffect *instruction_sequence = SEQN(6, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_10, op_ASSIGN_13, op_ASSIGN_16, branch_44);
	return instruction_sequence;
}

// Rd = add(Rs,Rt):sat
RzILOpEffect *hex_il_op_a2_addsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_23 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rs) + ((st64) Rt)), 0x0, 0x20) == ((st64) Rs) + ((st64) Rt))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rs) + ((st64) Rt) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_ADD_8 = ADD(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(Rt), DUP(Rt)));
	RzILOpPure *op_ADD_16 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_EQ_17 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_8), SN(32, 0), SN(32, 0x20)), op_ADD_16);
	RzILOpPure *op_ADD_26 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_LT_29 = SLT(op_ADD_26, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_35 = NEG(op_LSHIFT_34);
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_43 = SUB(op_LSHIFT_40, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_44 = ITE(op_LT_29, op_NEG_35, op_SUB_43);
	RzILOpEffect *gcc_expr_45 = BRANCH(op_EQ_17, EMPTY(), set_usr_field_call_23);

	// h_tmp7 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rs) + ((st64) Rt)), 0x0, 0x20) == ((st64) Rs) + ((st64) Rt))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rs) + ((st64) Rt) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_47 = SETL("h_tmp7", cond_44);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rs) + ((st64) R ...;
	RzILOpEffect *seq_48 = SEQN(2, gcc_expr_45, op_ASSIGN_hybrid_tmp_47);

	// Rd = ((st32) ((sextract64(((ut64) ((st64) Rs) + ((st64) Rt)), 0x0, 0x20) == ((st64) Rs) + ((st64) Rt)) ? ((st64) Rs) + ((st64) Rt) : h_tmp7));
	RzILOpPure *op_ADD_20 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *cond_49 = ITE(DUP(op_EQ_17), op_ADD_20, VARL("h_tmp7"));
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_49), DUP(cond_49)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rs) + ((st6 ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_48, op_ASSIGN_51);

	RzILOpEffect *instruction_sequence = seq_52;
	return instruction_sequence;
}

// Rdd = add(Rss,Rtt):raw:hi
RzILOpEffect *hex_il_op_a2_addsph(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = Rtt + sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff)))), 0x0, 0x20);
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_19 = ADD(Rtt, SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_11), DUP(op_AND_11))), CAST(32, MSB(DUP(op_AND_11)), DUP(op_AND_11)))), SN(32, 0), SN(32, 0x20)));
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rdd_op, op_ADD_19);

	RzILOpEffect *instruction_sequence = op_ASSIGN_20;
	return instruction_sequence;
}

// Rdd = add(Rss,Rtt):raw:lo
RzILOpEffect *hex_il_op_a2_addspl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = Rtt + sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff)))), 0x0, 0x20);
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_19 = ADD(Rtt, SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_11), DUP(op_AND_11))), CAST(32, MSB(DUP(op_AND_11)), DUP(op_AND_11)))), SN(32, 0), SN(32, 0x20)));
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rdd_op, op_ADD_19);

	RzILOpEffect *instruction_sequence = op_ASSIGN_20;
	return instruction_sequence;
}

// Rd = and(Rs,Rt)
RzILOpEffect *hex_il_op_a2_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs & Rt);
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_AND_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = and(Rs,Ii)
RzILOpEffect *hex_il_op_a2_andir(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = (Rs & s);
	RzILOpPure *op_AND_4 = LOGAND(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_AND_4);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_5);
	return instruction_sequence;
}

// Rdd = and(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_andp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (Rss & Rtt);
	RzILOpPure *op_AND_3 = LOGAND(Rss, Rtt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, op_AND_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = aslh(Rs)
RzILOpEffect *hex_il_op_a2_aslh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs << 0x10);
	RzILOpPure *op_LSHIFT_3 = SHIFTL0(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_LSHIFT_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = asrh(Rs)
RzILOpEffect *hex_il_op_a2_asrh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs >> 0x10);
	RzILOpPure *op_RSHIFT_3 = SHIFTRA(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_RSHIFT_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = combine(Rt.h,Rs.h)
RzILOpEffect *hex_il_op_a2_combine_hh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) (((ut16) ((Rt >> 0x10) & 0xffff)) << 0x10)) | ((st32) ((ut16) ((Rs >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(CAST(16, IL_FALSE, op_AND_7), SN(32, 16));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpPure *op_OR_21 = LOGOR(CAST(32, IL_FALSE, op_LSHIFT_10), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_17)));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_OR_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = combine(Rt.h,Rs.l)
RzILOpEffect *hex_il_op_a2_combine_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) (((ut16) ((Rt >> 0x10) & 0xffff)) << 0x10)) | ((st32) ((ut16) ((Rs >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(CAST(16, IL_FALSE, op_AND_7), SN(32, 16));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpPure *op_OR_21 = LOGOR(CAST(32, IL_FALSE, op_LSHIFT_10), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_17)));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_OR_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = combine(Rt.l,Rs.h)
RzILOpEffect *hex_il_op_a2_combine_lh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) (((ut16) ((Rt >> 0x0) & 0xffff)) << 0x10)) | ((st32) ((ut16) ((Rs >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(CAST(16, IL_FALSE, op_AND_7), SN(32, 16));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpPure *op_OR_21 = LOGOR(CAST(32, IL_FALSE, op_LSHIFT_10), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_17)));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_OR_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = combine(Rt.l,Rs.l)
RzILOpEffect *hex_il_op_a2_combine_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) (((ut16) ((Rt >> 0x0) & 0xffff)) << 0x10)) | ((st32) ((ut16) ((Rs >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(CAST(16, IL_FALSE, op_AND_7), SN(32, 16));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpPure *op_OR_21 = LOGOR(CAST(32, IL_FALSE, op_LSHIFT_10), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_17)));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_OR_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rdd = combine(Ii,II)
RzILOpEffect *hex_il_op_a2_combineii(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// S = S;
	RzILOpEffect *imm_assign_10 = SETL("S", S);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) S) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_7 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_8 = LOGNOT(op_LSHIFT_7);
	RzILOpPure *op_AND_9 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_8);
	RzILOpPure *op_AND_14 = LOGAND(CAST(64, MSB(VARL("S")), VARL("S")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(op_AND_14, SN(32, 0));
	RzILOpPure *op_OR_19 = LOGOR(op_AND_9, op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rdd_op, op_OR_19);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) s) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_27 = LOGNOT(op_LSHIFT_26);
	RzILOpPure *op_AND_28 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_27);
	RzILOpPure *op_AND_31 = LOGAND(CAST(64, MSB(VARL("s")), VARL("s")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_35 = SHIFTL0(op_AND_31, SN(32, 0x20));
	RzILOpPure *op_OR_36 = LOGOR(op_AND_28, op_LSHIFT_35);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Rdd_op, op_OR_36);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_10, op_ASSIGN_20, op_ASSIGN_37);
	return instruction_sequence;
}

// Rdd = combine(Rs,Rt)
RzILOpEffect *hex_il_op_a2_combinew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_11 = LOGAND(CAST(64, MSB(Rt), DUP(Rt)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(op_AND_11, SN(32, 0));
	RzILOpPure *op_OR_16 = LOGOR(op_AND_7, op_LSHIFT_15);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rdd_op, op_OR_16);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) Rs) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_24 = LOGNOT(op_LSHIFT_23);
	RzILOpPure *op_AND_25 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_24);
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(op_AND_29, SN(32, 0x20));
	RzILOpPure *op_OR_34 = LOGOR(op_AND_25, op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_35 = WRITE_REG(bundle, Rdd_op, op_OR_34);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_17, op_ASSIGN_35);
	return instruction_sequence;
}

// Rd = max(Rs,Rt)
RzILOpEffect *hex_il_op_a2_max(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((Rs > Rt) ? Rs : Rt);
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_4 = ITE(op_GT_3, DUP(Rs), DUP(Rt));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, cond_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rdd = max(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_maxp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((Rss > Rtt) ? Rss : Rtt);
	RzILOpPure *op_GT_3 = SGT(Rss, Rtt);
	RzILOpPure *cond_4 = ITE(op_GT_3, DUP(Rss), DUP(Rtt));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rdd_op, cond_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rd = maxu(Rs,Rt)
RzILOpEffect *hex_il_op_a2_maxu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) ((((ut32) Rs) > ((ut32) Rt)) ? ((ut32) Rs) : ((ut32) Rt)));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, CAST(32, IL_FALSE, DUP(Rs)), CAST(32, IL_FALSE, DUP(Rt)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_8));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rdd = maxu(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_maxup(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) ((((ut64) Rss) > ((ut64) Rtt)) ? ((ut64) Rss) : ((ut64) Rtt)));
	RzILOpPure *op_GT_5 = UGT(CAST(64, IL_FALSE, Rss), CAST(64, IL_FALSE, Rtt));
	RzILOpPure *cond_8 = ITE(op_GT_5, CAST(64, IL_FALSE, DUP(Rss)), CAST(64, IL_FALSE, DUP(Rtt)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_8));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rd = min(Rt,Rs)
RzILOpEffect *hex_il_op_a2_min(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((Rt < Rs) ? Rt : Rs);
	RzILOpPure *op_LT_3 = SLT(Rt, Rs);
	RzILOpPure *cond_4 = ITE(op_LT_3, DUP(Rt), DUP(Rs));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, cond_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rdd = min(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_minp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((Rtt < Rss) ? Rtt : Rss);
	RzILOpPure *op_LT_3 = SLT(Rtt, Rss);
	RzILOpPure *cond_4 = ITE(op_LT_3, DUP(Rtt), DUP(Rss));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rdd_op, cond_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rd = minu(Rt,Rs)
RzILOpEffect *hex_il_op_a2_minu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) ((((ut32) Rt) < ((ut32) Rs)) ? ((ut32) Rt) : ((ut32) Rs)));
	RzILOpPure *op_LT_5 = ULT(CAST(32, IL_FALSE, Rt), CAST(32, IL_FALSE, Rs));
	RzILOpPure *cond_8 = ITE(op_LT_5, CAST(32, IL_FALSE, DUP(Rt)), CAST(32, IL_FALSE, DUP(Rs)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_8));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rdd = minu(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_minup(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) ((((ut64) Rtt) < ((ut64) Rss)) ? ((ut64) Rtt) : ((ut64) Rss)));
	RzILOpPure *op_LT_5 = ULT(CAST(64, IL_FALSE, Rtt), CAST(64, IL_FALSE, Rss));
	RzILOpPure *cond_8 = ITE(op_LT_5, CAST(64, IL_FALSE, DUP(Rtt)), CAST(64, IL_FALSE, DUP(Rss)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_8));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rdd = neg(Rss)
RzILOpEffect *hex_il_op_a2_negp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = (-Rss);
	RzILOpPure *op_NEG_2 = NEG(Rss);
	RzILOpEffect *op_ASSIGN_3 = WRITE_REG(bundle, Rdd_op, op_NEG_2);

	RzILOpEffect *instruction_sequence = op_ASSIGN_3;
	return instruction_sequence;
}

// Rd = neg(Rs):sat
RzILOpEffect *hex_il_op_a2_negsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st64) Rs))), 0x0, 0x20) == (-((st64) Rs)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st64) Rs)) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_NEG_6 = NEG(CAST(64, MSB(Rs), DUP(Rs)));
	RzILOpPure *op_NEG_13 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_EQ_14 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_6), SN(32, 0), SN(32, 0x20)), op_NEG_13);
	RzILOpPure *op_NEG_21 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_24 = SLT(op_NEG_21, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_30 = NEG(op_LSHIFT_29);
	RzILOpPure *op_LSHIFT_35 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_38 = SUB(op_LSHIFT_35, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_39 = ITE(op_LT_24, op_NEG_30, op_SUB_38);
	RzILOpEffect *gcc_expr_40 = BRANCH(op_EQ_14, EMPTY(), set_usr_field_call_19);

	// h_tmp8 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st64) Rs))), 0x0, 0x20) == (-((st64) Rs)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st64) Rs)) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_42 = SETL("h_tmp8", cond_39);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st64) Rs))), 0x0, 0 ...;
	RzILOpEffect *seq_43 = SEQN(2, gcc_expr_40, op_ASSIGN_hybrid_tmp_42);

	// Rd = ((st32) ((sextract64(((ut64) (-((st64) Rs))), 0x0, 0x20) == (-((st64) Rs))) ? (-((st64) Rs)) : h_tmp8));
	RzILOpPure *op_NEG_16 = NEG(CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_44 = ITE(DUP(op_EQ_14), op_NEG_16, VARL("h_tmp8"));
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_44), DUP(cond_44)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st64) Rs))), 0x ...;
	RzILOpEffect *seq_47 = SEQN(2, seq_43, op_ASSIGN_46);

	RzILOpEffect *instruction_sequence = seq_47;
	return instruction_sequence;
}

// nop
RzILOpEffect *hex_il_op_a2_nop(HexInsnPktBundle *bundle) {
	// READ

	RzILOpEffect *instruction_sequence = EMPTY();
	return instruction_sequence;
}

// Rdd = not(Rss)
RzILOpEffect *hex_il_op_a2_notp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = (~Rss);
	RzILOpPure *op_NOT_2 = LOGNOT(Rss);
	RzILOpEffect *op_ASSIGN_3 = WRITE_REG(bundle, Rdd_op, op_NOT_2);

	RzILOpEffect *instruction_sequence = op_ASSIGN_3;
	return instruction_sequence;
}

// Rd = or(Rs,Rt)
RzILOpEffect *hex_il_op_a2_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs | Rt);
	RzILOpPure *op_OR_3 = LOGOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_OR_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = or(Rs,Ii)
RzILOpEffect *hex_il_op_a2_orir(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = (Rs | s);
	RzILOpPure *op_OR_4 = LOGOR(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_OR_4);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_5);
	return instruction_sequence;
}

// Rdd = or(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_orp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (Rss | Rtt);
	RzILOpPure *op_OR_3 = LOGOR(Rss, Rtt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, op_OR_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// if (!Pu) Rd = add(Rs,Rt)
RzILOpEffect *hex_il_op_a2_paddf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = Rs + Rt;
	RzILOpPure *op_ADD_8 = ADD(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_ADD_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = Rs + Rt);
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = Rs + Rt)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = add(Rs,Rt)
RzILOpEffect *hex_il_op_a2_paddfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = Rs + Rt;
	RzILOpPure *op_ADD_8 = ADD(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_ADD_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = Rs + Rt);
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = Rs + Rt)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu) Rd = add(Rs,Ii)
RzILOpEffect *hex_il_op_a2_paddif(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rd = Rs + s;
	RzILOpPure *op_ADD_9 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, op_ADD_9);

	// nop;
	RzILOpEffect *nop_11 = NOP();

	// seq(s; Rd = Rs + s);
	RzILOpEffect *seq_then_12 = op_ASSIGN_10;

	// seq(nop);
	RzILOpEffect *seq_else_13 = nop_11;

	// if (! (((st32) Pu) & 0x1)) {seq(s; Rd = Rs + s)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_14 = BRANCH(op_INV_4, seq_then_12, seq_else_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_14);
	return instruction_sequence;
}

// if (!Pu.new) Rd = add(Rs,Ii)
RzILOpEffect *hex_il_op_a2_paddifnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rd = Rs + s;
	RzILOpPure *op_ADD_9 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, op_ADD_9);

	// nop;
	RzILOpEffect *nop_11 = NOP();

	// seq(s; Rd = Rs + s);
	RzILOpEffect *seq_then_12 = op_ASSIGN_10;

	// seq(nop);
	RzILOpEffect *seq_else_13 = nop_11;

	// if (! (((st32) Pu_new) & 0x1)) {seq(s; Rd = Rs + s)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_14 = BRANCH(op_INV_4, seq_then_12, seq_else_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_14);
	return instruction_sequence;
}

// if (Pu) Rd = add(Rs,Ii)
RzILOpEffect *hex_il_op_a2_paddit(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_4 = SETL("s", s);

	// Rd = Rs + s;
	RzILOpPure *op_ADD_8 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_ADD_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(s; Rd = Rs + s);
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if ((((st32) Pu) & 0x1)) {seq(s; Rd = Rs + s)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_13 = BRANCH(NON_ZERO(op_AND_3), seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_13);
	return instruction_sequence;
}

// if (Pu.new) Rd = add(Rs,Ii)
RzILOpEffect *hex_il_op_a2_padditnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_4 = SETL("s", s);

	// Rd = Rs + s;
	RzILOpPure *op_ADD_8 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_ADD_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(s; Rd = Rs + s);
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if ((((st32) Pu_new) & 0x1)) {seq(s; Rd = Rs + s)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_13 = BRANCH(NON_ZERO(op_AND_3), seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_13);
	return instruction_sequence;
}

// if (Pu) Rd = add(Rs,Rt)
RzILOpEffect *hex_il_op_a2_paddt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = Rs + Rt;
	RzILOpPure *op_ADD_7 = ADD(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_ADD_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = Rs + Rt);
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = Rs + Rt)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = add(Rs,Rt)
RzILOpEffect *hex_il_op_a2_paddtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = Rs + Rt;
	RzILOpPure *op_ADD_7 = ADD(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_ADD_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = Rs + Rt);
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = Rs + Rt)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (!Pu) Rd = and(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pandf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs & Rt);
	RzILOpPure *op_AND_8 = LOGAND(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_AND_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs & Rt));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = (Rs & Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = and(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pandfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs & Rt);
	RzILOpPure *op_AND_8 = LOGAND(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_AND_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs & Rt));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = (Rs & Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (Pu) Rd = and(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pandt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs & Rt);
	RzILOpPure *op_AND_7 = LOGAND(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_AND_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs & Rt));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = (Rs & Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = and(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pandtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs & Rt);
	RzILOpPure *op_AND_7 = LOGAND(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_AND_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs & Rt));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = (Rs & Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (!Pu) Rd = or(Rs,Rt)
RzILOpEffect *hex_il_op_a2_porf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs | Rt);
	RzILOpPure *op_OR_8 = LOGOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_OR_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs | Rt));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = (Rs | Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = or(Rs,Rt)
RzILOpEffect *hex_il_op_a2_porfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs | Rt);
	RzILOpPure *op_OR_8 = LOGOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_OR_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs | Rt));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = (Rs | Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (Pu) Rd = or(Rs,Rt)
RzILOpEffect *hex_il_op_a2_port(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs | Rt);
	RzILOpPure *op_OR_7 = LOGOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_OR_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs | Rt));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = (Rs | Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = or(Rs,Rt)
RzILOpEffect *hex_il_op_a2_portnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs | Rt);
	RzILOpPure *op_OR_7 = LOGOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_OR_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs | Rt));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = (Rs | Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (!Pu) Rd = sub(Rt,Rs)
RzILOpEffect *hex_il_op_a2_psubf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rt - Rs;
	RzILOpPure *op_SUB_8 = SUB(Rt, Rs);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_SUB_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = Rt - Rs);
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = Rt - Rs)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = sub(Rt,Rs)
RzILOpEffect *hex_il_op_a2_psubfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rt - Rs;
	RzILOpPure *op_SUB_8 = SUB(Rt, Rs);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_SUB_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = Rt - Rs);
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = Rt - Rs)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (Pu) Rd = sub(Rt,Rs)
RzILOpEffect *hex_il_op_a2_psubt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rt - Rs;
	RzILOpPure *op_SUB_7 = SUB(Rt, Rs);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_SUB_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = Rt - Rs);
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = Rt - Rs)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = sub(Rt,Rs)
RzILOpEffect *hex_il_op_a2_psubtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rt - Rs;
	RzILOpPure *op_SUB_7 = SUB(Rt, Rs);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_SUB_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = Rt - Rs);
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = Rt - Rs)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (!Pu) Rd = xor(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pxorf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs ^ Rt);
	RzILOpPure *op_XOR_8 = LOGXOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_XOR_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs ^ Rt));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = (Rs ^ Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = xor(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pxorfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs ^ Rt);
	RzILOpPure *op_XOR_8 = LOGXOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_XOR_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs ^ Rt));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = (Rs ^ Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (Pu) Rd = xor(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pxort(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs ^ Rt);
	RzILOpPure *op_XOR_7 = LOGXOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_XOR_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs ^ Rt));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = (Rs ^ Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = xor(Rs,Rt)
RzILOpEffect *hex_il_op_a2_pxortnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs ^ Rt);
	RzILOpPure *op_XOR_7 = LOGXOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_XOR_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs ^ Rt));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = (Rs ^ Rt))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// Rd = round(Rss):sat
RzILOpEffect *hex_il_op_a2_roundsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st64 tmp;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	// Declare: ut64 __a;
	// Declare: ut64 __b;
	// Declare: ut64 __sum;
	// Declare: ut64 __xor;
	// Declare: ut64 __mask;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// __a = ((ut64) Rss);
	RzILOpEffect *op_ASSIGN_4 = SETL("__a", CAST(64, IL_FALSE, Rss));

	// __b = 0x80000000;
	RzILOpEffect *op_ASSIGN_7 = SETL("__b", UN(64, 0x80000000));

	// __sum = __a + __b;
	RzILOpPure *op_ADD_8 = ADD(VARL("__a"), VARL("__b"));
	RzILOpEffect *op_ASSIGN_10 = SETL("__sum", op_ADD_8);

	// __xor = (__a ^ __b);
	RzILOpPure *op_XOR_11 = LOGXOR(VARL("__a"), VARL("__b"));
	RzILOpEffect *op_ASSIGN_13 = SETL("__xor", op_XOR_11);

	// __mask = 0x8000000000000000;
	RzILOpEffect *op_ASSIGN_16 = SETL("__mask", UN(64, 0x8000000000000000));

	// tmp = ((st64) __sum);
	RzILOpEffect *op_ASSIGN_19 = SETL("tmp", CAST(64, IL_FALSE, VARL("__sum")));

	// tmp = 0x7fffffffffffffff;
	RzILOpEffect *op_ASSIGN_24 = SETL("tmp", SN(64, 0x7fffffffffffffff));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_27 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// tmp = 0x8000000000000000;
	RzILOpEffect *op_ASSIGN_29 = SETL("tmp", SN(64, 0x8000000000000000));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_32 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// seq(tmp = 0x7fffffffffffffff; set_usr_field(bundle, HEX_REG_FIEL ...;
	RzILOpEffect *seq_then_33 = SEQN(2, op_ASSIGN_24, set_usr_field_call_27);

	// seq(tmp = 0x8000000000000000; set_usr_field(bundle, HEX_REG_FIEL ...;
	RzILOpEffect *seq_else_34 = SEQN(2, op_ASSIGN_29, set_usr_field_call_32);

	// if ((__sum & __mask)) {seq(tmp = 0x7fffffffffffffff; set_usr_field(bundle, HEX_REG_FIEL ...} else {seq(tmp = 0x8000000000000000; set_usr_field(bundle, HEX_REG_FIEL ...};
	RzILOpPure *op_AND_22 = LOGAND(VARL("__sum"), VARL("__mask"));
	RzILOpEffect *branch_35 = BRANCH(NON_ZERO(op_AND_22), seq_then_33, seq_else_34);

	// tmp = ((st64) __sum);
	RzILOpEffect *op_ASSIGN_37 = SETL("tmp", CAST(64, IL_FALSE, VARL("__sum")));

	// seq(if ((__sum & __mask)) {seq(tmp = 0x7fffffffffffffff; set_usr ...;
	RzILOpEffect *seq_then_38 = branch_35;

	// seq(tmp = ((st64) __sum));
	RzILOpEffect *seq_else_39 = op_ASSIGN_37;

	// if (((__a ^ __sum) & __mask)) {seq(if ((__sum & __mask)) {seq(tmp = 0x7fffffffffffffff; set_usr ...} else {seq(tmp = ((st64) __sum))};
	RzILOpPure *op_XOR_20 = LOGXOR(VARL("__a"), VARL("__sum"));
	RzILOpPure *op_AND_21 = LOGAND(op_XOR_20, VARL("__mask"));
	RzILOpEffect *branch_40 = BRANCH(NON_ZERO(op_AND_21), seq_then_38, seq_else_39);

	// seq(tmp = ((st64) __sum));
	RzILOpEffect *seq_then_41 = op_ASSIGN_19;

	// seq(if (((__a ^ __sum) & __mask)) {seq(if ((__sum & __mask)) {se ...;
	RzILOpEffect *seq_else_42 = branch_40;

	// if ((__xor & __mask)) {seq(tmp = ((st64) __sum))} else {seq(if (((__a ^ __sum) & __mask)) {seq(if ((__sum & __mask)) {se ...};
	RzILOpPure *op_AND_17 = LOGAND(VARL("__xor"), VARL("__mask"));
	RzILOpEffect *branch_43 = BRANCH(NON_ZERO(op_AND_17), seq_then_41, seq_else_42);

	// Rd = ((st32) ((st64) ((st32) ((tmp >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_50 = LOGAND(op_RSHIFT_48, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_54 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_50), DUP(op_AND_50))), CAST(32, MSB(DUP(op_AND_50)), DUP(op_AND_50)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_50)), DUP(op_AND_50))), CAST(32, MSB(DUP(op_AND_50)), DUP(op_AND_50)))));

	RzILOpEffect *instruction_sequence = SEQN(7, op_ASSIGN_4, op_ASSIGN_7, op_ASSIGN_10, op_ASSIGN_13, op_ASSIGN_16, branch_43, op_ASSIGN_54);
	return instruction_sequence;
}

// Rd = sat(Rss)
RzILOpEffect *hex_il_op_a2_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_13 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) Rss), 0x0, 0x20) == Rss)) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rss < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_EQ_10 = EQ(SEXTRACT64(CAST(64, IL_FALSE, Rss), SN(32, 0), SN(32, 0x20)), DUP(Rss));
	RzILOpPure *op_LT_16 = SLT(DUP(Rss), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_22 = NEG(op_LSHIFT_21);
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_30 = SUB(op_LSHIFT_27, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_31 = ITE(op_LT_16, op_NEG_22, op_SUB_30);
	RzILOpEffect *gcc_expr_32 = BRANCH(op_EQ_10, EMPTY(), set_usr_field_call_13);

	// h_tmp9 = HYB(gcc_expr_if ((sextract64(((ut64) Rss), 0x0, 0x20) == Rss)) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rss < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_34 = SETL("h_tmp9", cond_31);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) Rss), 0x0, 0x20) == Rss ...;
	RzILOpEffect *seq_35 = SEQN(2, gcc_expr_32, op_ASSIGN_hybrid_tmp_34);

	// Rd = ((st32) ((sextract64(((ut64) Rss), 0x0, 0x20) == Rss) ? Rss : h_tmp9));
	RzILOpPure *cond_36 = ITE(DUP(op_EQ_10), DUP(Rss), VARL("h_tmp9"));
	RzILOpEffect *op_ASSIGN_38 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_36), DUP(cond_36)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) Rss), 0x0, 0x20) == ...;
	RzILOpEffect *seq_39 = SEQN(2, seq_35, op_ASSIGN_38);

	RzILOpEffect *instruction_sequence = seq_39;
	return instruction_sequence;
}

// Rd = satb(Rs)
RzILOpEffect *hex_il_op_a2_satb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_14 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x8) == ((st64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpPure *op_EQ_11 = EQ(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8)), CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_16 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_NEG_22 = NEG(op_LSHIFT_21);
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_SUB_30 = SUB(op_LSHIFT_27, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_31 = ITE(op_LT_16, op_NEG_22, op_SUB_30);
	RzILOpEffect *gcc_expr_32 = BRANCH(op_EQ_11, EMPTY(), set_usr_field_call_14);

	// h_tmp10 = HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x8) == ((st64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_34 = SETL("h_tmp10", cond_31);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x8) == ((st6 ...;
	RzILOpEffect *seq_35 = SEQN(2, gcc_expr_32, op_ASSIGN_hybrid_tmp_34);

	// Rd = ((st32) ((sextract64(((ut64) Rs), 0x0, 0x8) == ((st64) Rs)) ? ((st64) Rs) : h_tmp10));
	RzILOpPure *cond_37 = ITE(DUP(op_EQ_11), CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("h_tmp10"));
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_37), DUP(cond_37)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x8) == ( ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_35, op_ASSIGN_39);

	RzILOpEffect *instruction_sequence = seq_40;
	return instruction_sequence;
}

// Rd = sath(Rs)
RzILOpEffect *hex_il_op_a2_sath(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_14 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x10) == ((st64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_EQ_11 = EQ(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16)), CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_16 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_22 = NEG(op_LSHIFT_21);
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_30 = SUB(op_LSHIFT_27, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_31 = ITE(op_LT_16, op_NEG_22, op_SUB_30);
	RzILOpEffect *gcc_expr_32 = BRANCH(op_EQ_11, EMPTY(), set_usr_field_call_14);

	// h_tmp11 = HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x10) == ((st64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_34 = SETL("h_tmp11", cond_31);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x10) == ((st ...;
	RzILOpEffect *seq_35 = SEQN(2, gcc_expr_32, op_ASSIGN_hybrid_tmp_34);

	// Rd = ((st32) ((sextract64(((ut64) Rs), 0x0, 0x10) == ((st64) Rs)) ? ((st64) Rs) : h_tmp11));
	RzILOpPure *cond_37 = ITE(DUP(op_EQ_11), CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("h_tmp11"));
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_37), DUP(cond_37)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) Rs), 0x0, 0x10) ==  ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_35, op_ASSIGN_39);

	RzILOpEffect *instruction_sequence = seq_40;
	return instruction_sequence;
}

// Rd = satub(Rs)
RzILOpEffect *hex_il_op_a2_satub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_14 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x8) == ((ut64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_EQ_11 = EQ(EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, DUP(Rs)));
	RzILOpPure *op_LT_16 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_23 = SUB(op_LSHIFT_20, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_25 = ITE(op_LT_16, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_23);
	RzILOpEffect *gcc_expr_26 = BRANCH(op_EQ_11, EMPTY(), set_usr_field_call_14);

	// h_tmp12 = HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x8) == ((ut64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_28 = SETL("h_tmp12", cond_25);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x8) == ((ut64 ...;
	RzILOpEffect *seq_29 = SEQN(2, gcc_expr_26, op_ASSIGN_hybrid_tmp_28);

	// Rd = ((st32) ((extract64(((ut64) Rs), 0x0, 0x8) == ((ut64) Rs)) ? ((st64) Rs) : h_tmp12));
	RzILOpPure *cond_31 = ITE(DUP(op_EQ_11), CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("h_tmp12"));
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_31), DUP(cond_31)));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x8) == (( ...;
	RzILOpEffect *seq_34 = SEQN(2, seq_29, op_ASSIGN_33);

	RzILOpEffect *instruction_sequence = seq_34;
	return instruction_sequence;
}

// Rd = satuh(Rs)
RzILOpEffect *hex_il_op_a2_satuh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_14 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x10) == ((ut64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_EQ_11 = EQ(EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, DUP(Rs)));
	RzILOpPure *op_LT_16 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_23 = SUB(op_LSHIFT_20, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_25 = ITE(op_LT_16, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_23);
	RzILOpEffect *gcc_expr_26 = BRANCH(op_EQ_11, EMPTY(), set_usr_field_call_14);

	// h_tmp13 = HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x10) == ((ut64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((Rs < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_28 = SETL("h_tmp13", cond_25);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x10) == ((ut6 ...;
	RzILOpEffect *seq_29 = SEQN(2, gcc_expr_26, op_ASSIGN_hybrid_tmp_28);

	// Rd = ((st32) ((extract64(((ut64) Rs), 0x0, 0x10) == ((ut64) Rs)) ? ((st64) Rs) : h_tmp13));
	RzILOpPure *cond_31 = ITE(DUP(op_EQ_11), CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("h_tmp13"));
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_31), DUP(cond_31)));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) Rs), 0x0, 0x10) == ( ...;
	RzILOpEffect *seq_34 = SEQN(2, seq_29, op_ASSIGN_33);

	RzILOpEffect *instruction_sequence = seq_34;
	return instruction_sequence;
}

// Rd = sub(Rt,Rs)
RzILOpEffect *hex_il_op_a2_sub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rt - Rs;
	RzILOpPure *op_SUB_3 = SUB(Rt, Rs);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_SUB_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = sub(Rt.h,Rs.h):<<16
RzILOpEffect *hex_il_op_a2_subh_h16_hh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_SUB_19 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_SUB_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = sub(Rt.h,Rs.l):<<16
RzILOpEffect *hex_il_op_a2_subh_h16_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_SUB_19 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_SUB_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.h):<<16
RzILOpEffect *hex_il_op_a2_subh_h16_lh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_SUB_19 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_SUB_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.l):<<16
RzILOpEffect *hex_il_op_a2_subh_h16_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) << 0x10);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_SUB_19 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_7), DUP(op_AND_7))), CAST(16, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_SUB_19, SN(32, 16));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, op_LSHIFT_21);

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Rd = sub(Rt.h,Rs.h):sat:<<16
RzILOpEffect *hex_il_op_a2_subh_h16_sat_hh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_SUB_44 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_44), DUP(op_SUB_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_SUB_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp14 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp14", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))) : h_tmp14) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_SUB_63), DUP(op_SUB_63)), VARL("h_tmp14"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = sub(Rt.h,Rs.l):sat:<<16
RzILOpEffect *hex_il_op_a2_subh_h16_sat_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_SUB_44 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_44), DUP(op_SUB_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_SUB_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp15 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp15", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))) : h_tmp15) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_SUB_63), DUP(op_SUB_63)), VARL("h_tmp15"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.h):sat:<<16
RzILOpEffect *hex_il_op_a2_subh_h16_sat_lh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_SUB_44 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_44), DUP(op_SUB_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_SUB_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp16 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp16", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))) : h_tmp16) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_SUB_63), DUP(op_SUB_63)), VARL("h_tmp16"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.l):sat:<<16
RzILOpEffect *hex_il_op_a2_subh_h16_sat_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_SUB_44 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_44), DUP(op_SUB_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_SUB_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp17 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp17", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))) : h_tmp17) << 0x10));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_SUB_63), DUP(op_SUB_63)), VARL("h_tmp17"));
	RzILOpPure *op_LSHIFT_108 = SHIFTL0(cond_106, SN(32, 16));
	RzILOpEffect *op_ASSIGN_110 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_LSHIFT_108), DUP(op_LSHIFT_108)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_104, op_ASSIGN_110);

	RzILOpEffect *instruction_sequence = seq_111;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.h)
RzILOpEffect *hex_il_op_a2_subh_l16_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(op_SUB_22)), SN(32, 0), SN(32, 16))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_29;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.l)
RzILOpEffect *hex_il_op_a2_subh_l16_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(op_SUB_22)), SN(32, 0), SN(32, 16))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_29;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.h):sat
RzILOpEffect *hex_il_op_a2_subh_l16_sat_hl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_SUB_44 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_44), DUP(op_SUB_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_SUB_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp18 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp18", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x10) & 0xffff)))) : h_tmp18));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_SUB_63), DUP(op_SUB_63)), VARL("h_tmp18"));
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_106), DUP(cond_106)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_109 = SEQN(2, seq_104, op_ASSIGN_108);

	RzILOpEffect *instruction_sequence = seq_109;
	return instruction_sequence;
}

// Rd = sub(Rt.l,Rs.l):sat
RzILOpEffect *hex_il_op_a2_subh_l16_sat_ll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_66 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_SUB_22 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_SUB_44 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(CAST(16, MSB(op_AND_40), DUP(op_AND_40))), CAST(16, MSB(DUP(op_AND_40)), DUP(op_AND_40))));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_22), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_44), DUP(op_SUB_44)));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))));
	RzILOpPure *op_LT_85 = SLT(op_SUB_83, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_91 = NEG(op_LSHIFT_90);
	RzILOpPure *op_LSHIFT_96 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_99 = SUB(op_LSHIFT_96, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_100 = ITE(op_LT_85, op_NEG_91, op_SUB_99);
	RzILOpEffect *gcc_expr_101 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_66);

	// h_tmp19 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp19", cond_100);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_104 = SEQN(2, gcc_expr_101, op_ASSIGN_hybrid_tmp_103);

	// Rd = ((st32) ((sextract64(((ut64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> 0x0) & 0xffff))) - ((st32) ((st16) ((Rs >> 0x0) & 0xffff)))) : h_tmp19));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(32, 0xffff));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *cond_106 = ITE(DUP(op_EQ_46), CAST(64, MSB(op_SUB_63), DUP(op_SUB_63)), VARL("h_tmp19"));
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_106), DUP(cond_106)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_109 = SEQN(2, seq_104, op_ASSIGN_108);

	RzILOpEffect *instruction_sequence = seq_109;
	return instruction_sequence;
}

// Rdd = sub(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_subp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = Rtt - Rss;
	RzILOpPure *op_SUB_3 = SUB(Rtt, Rss);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, op_SUB_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = sub(Ii,Rs)
RzILOpEffect *hex_il_op_a2_subri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = s - Rs;
	RzILOpPure *op_SUB_4 = SUB(VARL("s"), Rs);
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_SUB_4);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_5);
	return instruction_sequence;
}

// Rd = sub(Rt,Rs):sat
RzILOpEffect *hex_il_op_a2_subsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_23 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rt) - ((st64) Rs)), 0x0, 0x20) == ((st64) Rt) - ((st64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rt) - ((st64) Rs) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_SUB_8 = SUB(CAST(64, MSB(Rt), DUP(Rt)), CAST(64, MSB(Rs), DUP(Rs)));
	RzILOpPure *op_SUB_16 = SUB(CAST(64, MSB(DUP(Rt)), DUP(Rt)), CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_EQ_17 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_8), SN(32, 0), SN(32, 0x20)), op_SUB_16);
	RzILOpPure *op_SUB_26 = SUB(CAST(64, MSB(DUP(Rt)), DUP(Rt)), CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_29 = SLT(op_SUB_26, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_35 = NEG(op_LSHIFT_34);
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_43 = SUB(op_LSHIFT_40, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_44 = ITE(op_LT_29, op_NEG_35, op_SUB_43);
	RzILOpEffect *gcc_expr_45 = BRANCH(op_EQ_17, EMPTY(), set_usr_field_call_23);

	// h_tmp20 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rt) - ((st64) Rs)), 0x0, 0x20) == ((st64) Rt) - ((st64) Rs))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rt) - ((st64) Rs) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_47 = SETL("h_tmp20", cond_44);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rt) - ((st64) R ...;
	RzILOpEffect *seq_48 = SEQN(2, gcc_expr_45, op_ASSIGN_hybrid_tmp_47);

	// Rd = ((st32) ((sextract64(((ut64) ((st64) Rt) - ((st64) Rs)), 0x0, 0x20) == ((st64) Rt) - ((st64) Rs)) ? ((st64) Rt) - ((st64) Rs) : h_tmp20));
	RzILOpPure *op_SUB_20 = SUB(CAST(64, MSB(DUP(Rt)), DUP(Rt)), CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *cond_49 = ITE(DUP(op_EQ_17), op_SUB_20, VARL("h_tmp20"));
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_49), DUP(cond_49)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rt) - ((st6 ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_48, op_ASSIGN_51);

	RzILOpEffect *instruction_sequence = seq_52;
	return instruction_sequence;
}

// Rd = vaddh(Rs,Rt)
RzILOpEffect *hex_il_op_a2_svaddh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp21 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp21", VARL("i"));

	// seq(h_tmp21 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rt, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(32, 0xffff));
	RzILOpPure *op_ADD_33 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_29), DUP(op_AND_29))), CAST(16, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_AND_35 = LOGAND(op_ADD_33, SN(32, 0xffff));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(CAST(64, IL_FALSE, op_AND_35), op_MUL_38);
	RzILOpPure *op_OR_41 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_39);
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_41));

	// seq(h_tmp21; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i ...;
	RzILOpEffect *seq_45 = op_ASSIGN_43;

	// seq(seq(h_tmp21; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ...;
	RzILOpEffect *seq_46 = SEQN(2, seq_45, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp21; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_47 = REPEAT(op_LT_4, seq_46);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp21; Rd = ((st32) ( ...;
	RzILOpEffect *seq_48 = SEQN(2, op_ASSIGN_2, for_47);

	RzILOpEffect *instruction_sequence = seq_48;
	return instruction_sequence;
}

// Rd = vaddh(Rs,Rt):sat
RzILOpEffect *hex_il_op_a2_svaddhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp22 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp22", VARL("i"));

	// seq(h_tmp22 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_76 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rs, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(32, 0xffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rt, op_MUL_29);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xffff));
	RzILOpPure *op_ADD_36 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(32, MSB(CAST(16, MSB(op_AND_32), DUP(op_AND_32))), CAST(16, MSB(DUP(op_AND_32)), DUP(op_AND_32))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rs), op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(32, 0xffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), op_MUL_49);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_ADD_56 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_46), DUP(op_AND_46))), CAST(16, MSB(DUP(op_AND_46)), DUP(op_AND_46))), CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))));
	RzILOpPure *op_EQ_58 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_36), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_56), DUP(op_ADD_56)));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_79 = SHIFTRA(DUP(Rs), op_MUL_78);
	RzILOpPure *op_AND_81 = LOGAND(op_RSHIFT_79, SN(32, 0xffff));
	RzILOpPure *op_MUL_84 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rt), op_MUL_84);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_ADD_91 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_81), DUP(op_AND_81))), CAST(16, MSB(DUP(op_AND_81)), DUP(op_AND_81))), CAST(32, MSB(CAST(16, MSB(op_AND_87), DUP(op_AND_87))), CAST(16, MSB(DUP(op_AND_87)), DUP(op_AND_87))));
	RzILOpPure *op_LT_93 = SLT(op_ADD_91, SN(32, 0));
	RzILOpPure *op_LSHIFT_98 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_99 = NEG(op_LSHIFT_98);
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_107 = SUB(op_LSHIFT_104, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_108 = ITE(op_LT_93, op_NEG_99, op_SUB_107);
	RzILOpEffect *gcc_expr_109 = BRANCH(op_EQ_58, EMPTY(), set_usr_field_call_76);

	// h_tmp23 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_111 = SETL("h_tmp23", cond_108);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rs >> ...;
	RzILOpEffect *seq_112 = SEQN(2, gcc_expr_109, op_ASSIGN_hybrid_tmp_111);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff)))) : h_tmp23) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_60 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rs), op_MUL_60);
	RzILOpPure *op_AND_63 = LOGAND(op_RSHIFT_61, SN(32, 0xffff));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rt), op_MUL_66);
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_67, SN(32, 0xffff));
	RzILOpPure *op_ADD_73 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_63), DUP(op_AND_63))), CAST(16, MSB(DUP(op_AND_63)), DUP(op_AND_63))), CAST(32, MSB(CAST(16, MSB(op_AND_69), DUP(op_AND_69))), CAST(16, MSB(DUP(op_AND_69)), DUP(op_AND_69))));
	RzILOpPure *cond_114 = ITE(DUP(op_EQ_58), CAST(64, MSB(op_ADD_73), DUP(op_ADD_73)), VARL("h_tmp23"));
	RzILOpPure *op_AND_117 = LOGAND(cond_114, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_120 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(CAST(64, IL_FALSE, op_AND_117), op_MUL_120);
	RzILOpPure *op_OR_123 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_121);
	RzILOpEffect *op_ASSIGN_125 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_123));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_126 = SEQN(2, seq_112, op_ASSIGN_125);

	// seq(h_tmp22; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32 ...;
	RzILOpEffect *seq_128 = seq_126;

	// seq(seq(h_tmp22; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_129 = SEQN(2, seq_128, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp22; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_130 = REPEAT(op_LT_4, seq_129);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp22; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_131 = SEQN(2, op_ASSIGN_2, for_130);

	RzILOpEffect *instruction_sequence = seq_131;
	return instruction_sequence;
}

// Rd = vadduh(Rs,Rt):sat
RzILOpEffect *hex_il_op_a2_svadduhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp24 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp24", VARL("i"));

	// seq(h_tmp24 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_76 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rs, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(32, 0xffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rt, op_MUL_29);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xffff));
	RzILOpPure *op_ADD_36 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_25)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_32)));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rs), op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(32, 0xffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rt), op_MUL_49);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_ADD_56 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_46)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_52)));
	RzILOpPure *op_EQ_58 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_ADD_36), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, op_ADD_56));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_79 = SHIFTRA(DUP(Rs), op_MUL_78);
	RzILOpPure *op_AND_81 = LOGAND(op_RSHIFT_79, SN(32, 0xffff));
	RzILOpPure *op_MUL_84 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rt), op_MUL_84);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_ADD_91 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_81)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_87)));
	RzILOpPure *op_LT_93 = SLT(op_ADD_91, SN(32, 0));
	RzILOpPure *op_LSHIFT_97 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_100 = SUB(op_LSHIFT_97, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_102 = ITE(op_LT_93, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_100);
	RzILOpEffect *gcc_expr_103 = BRANCH(op_EQ_58, EMPTY(), set_usr_field_call_76);

	// h_tmp25 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_105 = SETL("h_tmp25", cond_102);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rs >>  ...;
	RzILOpEffect *seq_106 = SEQN(2, gcc_expr_103, op_ASSIGN_hybrid_tmp_105);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((extract64(((ut64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))))) ? ((st64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff)))) : h_tmp25) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_60 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rs), op_MUL_60);
	RzILOpPure *op_AND_63 = LOGAND(op_RSHIFT_61, SN(32, 0xffff));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rt), op_MUL_66);
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_67, SN(32, 0xffff));
	RzILOpPure *op_ADD_73 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_63)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_69)));
	RzILOpPure *cond_108 = ITE(DUP(op_EQ_58), CAST(64, MSB(op_ADD_73), DUP(op_ADD_73)), VARL("h_tmp25"));
	RzILOpPure *op_AND_111 = LOGAND(cond_108, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_114 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_115 = SHIFTL0(CAST(64, IL_FALSE, op_AND_111), op_MUL_114);
	RzILOpPure *op_OR_117 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_115);
	RzILOpEffect *op_ASSIGN_119 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_117));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rs ...;
	RzILOpEffect *seq_120 = SEQN(2, seq_106, op_ASSIGN_119);

	// seq(h_tmp24; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ...;
	RzILOpEffect *seq_122 = seq_120;

	// seq(seq(h_tmp24; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ...;
	RzILOpEffect *seq_123 = SEQN(2, seq_122, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp24; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_124 = REPEAT(op_LT_4, seq_123);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp24; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_125 = SEQN(2, op_ASSIGN_2, for_124);

	RzILOpEffect *instruction_sequence = seq_125;
	return instruction_sequence;
}

// Rd = vavgh(Rs,Rt)
RzILOpEffect *hex_il_op_a2_svavgh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp26 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp26", VARL("i"));

	// seq(h_tmp26 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rt, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(32, 0xffff));
	RzILOpPure *op_ADD_33 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_29), DUP(op_AND_29))), CAST(16, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(op_ADD_33, SN(32, 1));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(32, 0xffff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(CAST(64, IL_FALSE, op_AND_37), op_MUL_40);
	RzILOpPure *op_OR_43 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_41);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_43));

	// seq(h_tmp26; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i ...;
	RzILOpEffect *seq_47 = op_ASSIGN_45;

	// seq(seq(h_tmp26; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ...;
	RzILOpEffect *seq_48 = SEQN(2, seq_47, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp26; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_49 = REPEAT(op_LT_4, seq_48);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp26; Rd = ((st32) ( ...;
	RzILOpEffect *seq_50 = SEQN(2, op_ASSIGN_2, for_49);

	RzILOpEffect *instruction_sequence = seq_50;
	return instruction_sequence;
}

// Rd = vavgh(Rs,Rt):rnd
RzILOpEffect *hex_il_op_a2_svavghs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp27 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp27", VARL("i"));

	// seq(h_tmp27 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) + ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) + 0x1 >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rt, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(32, 0xffff));
	RzILOpPure *op_ADD_33 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_29), DUP(op_AND_29))), CAST(16, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_ADD_35 = ADD(op_ADD_33, SN(32, 1));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(op_ADD_35, SN(32, 1));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(32, 0xffff));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, op_AND_39), op_MUL_42);
	RzILOpPure *op_OR_45 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_43);
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_45));

	// seq(h_tmp27; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i ...;
	RzILOpEffect *seq_49 = op_ASSIGN_47;

	// seq(seq(h_tmp27; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ...;
	RzILOpEffect *seq_50 = SEQN(2, seq_49, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp27; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_51 = REPEAT(op_LT_4, seq_50);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp27; Rd = ((st32) ( ...;
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_2, for_51);

	RzILOpEffect *instruction_sequence = seq_52;
	return instruction_sequence;
}

// Rd = vnavgh(Rt,Rs)
RzILOpEffect *hex_il_op_a2_svnavgh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp28 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp28", VARL("i"));

	// seq(h_tmp28 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rt, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rs, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(32, 0xffff));
	RzILOpPure *op_SUB_33 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_29), DUP(op_AND_29))), CAST(16, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(op_SUB_33, SN(32, 1));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(32, 0xffff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(CAST(64, IL_FALSE, op_AND_37), op_MUL_40);
	RzILOpPure *op_OR_43 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_41);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_43));

	// seq(h_tmp28; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i ...;
	RzILOpEffect *seq_47 = op_ASSIGN_45;

	// seq(seq(h_tmp28; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ...;
	RzILOpEffect *seq_48 = SEQN(2, seq_47, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp28; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_49 = REPEAT(op_LT_4, seq_48);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp28; Rd = ((st32) ( ...;
	RzILOpEffect *seq_50 = SEQN(2, op_ASSIGN_2, for_49);

	RzILOpEffect *instruction_sequence = seq_50;
	return instruction_sequence;
}

// Rd = vsubh(Rt,Rs)
RzILOpEffect *hex_il_op_a2_svsubh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp29 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp29", VARL("i"));

	// seq(h_tmp29 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rt, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rs, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(32, 0xffff));
	RzILOpPure *op_SUB_33 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_29), DUP(op_AND_29))), CAST(16, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_AND_35 = LOGAND(op_SUB_33, SN(32, 0xffff));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(CAST(64, IL_FALSE, op_AND_35), op_MUL_38);
	RzILOpPure *op_OR_41 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_39);
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_41));

	// seq(h_tmp29; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i ...;
	RzILOpEffect *seq_45 = op_ASSIGN_43;

	// seq(seq(h_tmp29; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ...;
	RzILOpEffect *seq_46 = SEQN(2, seq_45, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp29; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_47 = REPEAT(op_LT_4, seq_46);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp29; Rd = ((st32) ( ...;
	RzILOpEffect *seq_48 = SEQN(2, op_ASSIGN_2, for_47);

	RzILOpEffect *instruction_sequence = seq_48;
	return instruction_sequence;
}

// Rd = vsubh(Rt,Rs):sat
RzILOpEffect *hex_il_op_a2_svsubhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp30 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp30", VARL("i"));

	// seq(h_tmp30 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_76 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rt, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(32, 0xffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rs, op_MUL_29);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xffff));
	RzILOpPure *op_SUB_36 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(32, MSB(CAST(16, MSB(op_AND_32), DUP(op_AND_32))), CAST(16, MSB(DUP(op_AND_32)), DUP(op_AND_32))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rt), op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(32, 0xffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rs), op_MUL_49);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_SUB_56 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_46), DUP(op_AND_46))), CAST(16, MSB(DUP(op_AND_46)), DUP(op_AND_46))), CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))));
	RzILOpPure *op_EQ_58 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_36), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_56), DUP(op_SUB_56)));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_79 = SHIFTRA(DUP(Rt), op_MUL_78);
	RzILOpPure *op_AND_81 = LOGAND(op_RSHIFT_79, SN(32, 0xffff));
	RzILOpPure *op_MUL_84 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rs), op_MUL_84);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_SUB_91 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_81), DUP(op_AND_81))), CAST(16, MSB(DUP(op_AND_81)), DUP(op_AND_81))), CAST(32, MSB(CAST(16, MSB(op_AND_87), DUP(op_AND_87))), CAST(16, MSB(DUP(op_AND_87)), DUP(op_AND_87))));
	RzILOpPure *op_LT_93 = SLT(op_SUB_91, SN(32, 0));
	RzILOpPure *op_LSHIFT_98 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_99 = NEG(op_LSHIFT_98);
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_107 = SUB(op_LSHIFT_104, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_108 = ITE(op_LT_93, op_NEG_99, op_SUB_107);
	RzILOpEffect *gcc_expr_109 = BRANCH(op_EQ_58, EMPTY(), set_usr_field_call_76);

	// h_tmp31 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_111 = SETL("h_tmp31", cond_108);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rt >> ...;
	RzILOpEffect *seq_112 = SEQN(2, gcc_expr_109, op_ASSIGN_hybrid_tmp_111);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff))))) ? ((st64) ((st32) ((st16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))) : h_tmp31) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_60 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rt), op_MUL_60);
	RzILOpPure *op_AND_63 = LOGAND(op_RSHIFT_61, SN(32, 0xffff));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rs), op_MUL_66);
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_67, SN(32, 0xffff));
	RzILOpPure *op_SUB_73 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_63), DUP(op_AND_63))), CAST(16, MSB(DUP(op_AND_63)), DUP(op_AND_63))), CAST(32, MSB(CAST(16, MSB(op_AND_69), DUP(op_AND_69))), CAST(16, MSB(DUP(op_AND_69)), DUP(op_AND_69))));
	RzILOpPure *cond_114 = ITE(DUP(op_EQ_58), CAST(64, MSB(op_SUB_73), DUP(op_SUB_73)), VARL("h_tmp31"));
	RzILOpPure *op_AND_117 = LOGAND(cond_114, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_120 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(CAST(64, IL_FALSE, op_AND_117), op_MUL_120);
	RzILOpPure *op_OR_123 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_121);
	RzILOpEffect *op_ASSIGN_125 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_123));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_126 = SEQN(2, seq_112, op_ASSIGN_125);

	// seq(h_tmp30; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32 ...;
	RzILOpEffect *seq_128 = seq_126;

	// seq(seq(h_tmp30; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_129 = SEQN(2, seq_128, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp30; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_130 = REPEAT(op_LT_4, seq_129);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp30; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_131 = SEQN(2, op_ASSIGN_2, for_130);

	RzILOpEffect *instruction_sequence = seq_131;
	return instruction_sequence;
}

// Rd = vsubuh(Rt,Rs):sat
RzILOpEffect *hex_il_op_a2_svsubuhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp32 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp32", VARL("i"));

	// seq(h_tmp32 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_76 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rt, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(32, 0xffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rs, op_MUL_29);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xffff));
	RzILOpPure *op_SUB_36 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_25)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_32)));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rt), op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(32, 0xffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rs), op_MUL_49);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(32, 0xffff));
	RzILOpPure *op_SUB_56 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_46)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_52)));
	RzILOpPure *op_EQ_58 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_SUB_36), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, op_SUB_56));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_79 = SHIFTRA(DUP(Rt), op_MUL_78);
	RzILOpPure *op_AND_81 = LOGAND(op_RSHIFT_79, SN(32, 0xffff));
	RzILOpPure *op_MUL_84 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rs), op_MUL_84);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_SUB_91 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_81)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_87)));
	RzILOpPure *op_LT_93 = SLT(op_SUB_91, SN(32, 0));
	RzILOpPure *op_LSHIFT_97 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_100 = SUB(op_LSHIFT_97, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_102 = ITE(op_LT_93, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_100);
	RzILOpEffect *gcc_expr_103 = BRANCH(op_EQ_58, EMPTY(), set_usr_field_call_76);

	// h_tmp33 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_105 = SETL("h_tmp33", cond_102);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rt >>  ...;
	RzILOpEffect *seq_106 = SEQN(2, gcc_expr_103, op_ASSIGN_hybrid_tmp_105);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((extract64(((ut64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff))))) ? ((st64) ((st32) ((ut16) ((Rt >> i * 0x10) & 0xffff))) - ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))) : h_tmp33) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_60 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rt), op_MUL_60);
	RzILOpPure *op_AND_63 = LOGAND(op_RSHIFT_61, SN(32, 0xffff));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rs), op_MUL_66);
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_67, SN(32, 0xffff));
	RzILOpPure *op_SUB_73 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_63)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_69)));
	RzILOpPure *cond_108 = ITE(DUP(op_EQ_58), CAST(64, MSB(op_SUB_73), DUP(op_SUB_73)), VARL("h_tmp33"));
	RzILOpPure *op_AND_111 = LOGAND(cond_108, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_114 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_115 = SHIFTL0(CAST(64, IL_FALSE, op_AND_111), op_MUL_114);
	RzILOpPure *op_OR_117 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_115);
	RzILOpEffect *op_ASSIGN_119 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_117));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rt ...;
	RzILOpEffect *seq_120 = SEQN(2, seq_106, op_ASSIGN_119);

	// seq(h_tmp32; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ...;
	RzILOpEffect *seq_122 = seq_120;

	// seq(seq(h_tmp32; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ...;
	RzILOpEffect *seq_123 = SEQN(2, seq_122, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp32; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_124 = REPEAT(op_LT_4, seq_123);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp32; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_125 = SEQN(2, op_ASSIGN_2, for_124);

	RzILOpEffect *instruction_sequence = seq_125;
	return instruction_sequence;
}

// Rd = swiz(Rs)
RzILOpEffect *hex_il_op_a2_swiz(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x0)))) | (((ut64) (((st64) ((st32) ((st8) ((Rs >> 0x18) & 0xff)))) & 0xff)) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_8 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_6);
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rs, SN(32, 24));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpPure *op_AND_20 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_15), DUP(op_AND_15))), CAST(8, MSB(DUP(op_AND_15)), DUP(op_AND_15)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_15)), DUP(op_AND_15))), CAST(8, MSB(DUP(op_AND_15)), DUP(op_AND_15)))), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(CAST(64, IL_FALSE, op_AND_20), SN(32, 0));
	RzILOpPure *op_OR_27 = LOGOR(CAST(64, IL_FALSE, op_AND_8), op_LSHIFT_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_27));

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rs >> 0x10) & 0xff)))) & 0xff)) << 0x8)));
	RzILOpPure *op_LSHIFT_35 = SHIFTL0(SN(64, 0xff), SN(32, 8));
	RzILOpPure *op_NOT_36 = LOGNOT(op_LSHIFT_35);
	RzILOpPure *op_AND_38 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_36);
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(32, 0xff));
	RzILOpPure *op_AND_49 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_44), DUP(op_AND_44))), CAST(8, MSB(DUP(op_AND_44)), DUP(op_AND_44)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_44)), DUP(op_AND_44))), CAST(8, MSB(DUP(op_AND_44)), DUP(op_AND_44)))), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(CAST(64, IL_FALSE, op_AND_49), SN(32, 8));
	RzILOpPure *op_OR_56 = LOGOR(CAST(64, IL_FALSE, op_AND_38), op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_58 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_56));

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x10)))) | (((ut64) (((st64) ((st32) ((st8) ((Rs >> 0x8) & 0xff)))) & 0xff)) << 0x10)));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(SN(64, 0xff), SN(32, 16));
	RzILOpPure *op_NOT_65 = LOGNOT(op_LSHIFT_64);
	RzILOpPure *op_AND_67 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_65);
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rs), SN(32, 8));
	RzILOpPure *op_AND_73 = LOGAND(op_RSHIFT_71, SN(32, 0xff));
	RzILOpPure *op_AND_78 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_73), DUP(op_AND_73))), CAST(8, MSB(DUP(op_AND_73)), DUP(op_AND_73)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_73)), DUP(op_AND_73))), CAST(8, MSB(DUP(op_AND_73)), DUP(op_AND_73)))), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_83 = SHIFTL0(CAST(64, IL_FALSE, op_AND_78), SN(32, 16));
	RzILOpPure *op_OR_85 = LOGOR(CAST(64, IL_FALSE, op_AND_67), op_LSHIFT_83);
	RzILOpEffect *op_ASSIGN_87 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_85));

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x18)))) | (((ut64) (((st64) ((st32) ((st8) ((Rs >> 0x0) & 0xff)))) & 0xff)) << 0x18)));
	RzILOpPure *op_LSHIFT_93 = SHIFTL0(SN(64, 0xff), SN(32, 24));
	RzILOpPure *op_NOT_94 = LOGNOT(op_LSHIFT_93);
	RzILOpPure *op_AND_96 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_94);
	RzILOpPure *op_RSHIFT_100 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_102 = LOGAND(op_RSHIFT_100, SN(32, 0xff));
	RzILOpPure *op_AND_107 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_102), DUP(op_AND_102))), CAST(8, MSB(DUP(op_AND_102)), DUP(op_AND_102)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_102)), DUP(op_AND_102))), CAST(8, MSB(DUP(op_AND_102)), DUP(op_AND_102)))), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_112 = SHIFTL0(CAST(64, IL_FALSE, op_AND_107), SN(32, 24));
	RzILOpPure *op_OR_114 = LOGOR(CAST(64, IL_FALSE, op_AND_96), op_LSHIFT_112);
	RzILOpEffect *op_ASSIGN_116 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_114));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_29, op_ASSIGN_58, op_ASSIGN_87, op_ASSIGN_116);
	return instruction_sequence;
}

// Rd = sxtb(Rs)
RzILOpEffect *hex_il_op_a2_sxtb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 8))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Rd = sxth(Rs)
RzILOpEffect *hex_il_op_a2_sxth(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 16))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Rdd = sxtw(Rs)
RzILOpEffect *hex_il_op_a2_sxtw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((st64) Rs);
	RzILOpEffect *op_ASSIGN_3 = WRITE_REG(bundle, Rdd_op, CAST(64, MSB(Rs), DUP(Rs)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_3;
	return instruction_sequence;
}

// Rd = Rs
RzILOpEffect *hex_il_op_a2_tfr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rs;
	RzILOpEffect *op_ASSIGN_2 = WRITE_REG(bundle, Rd_op, Rs);

	RzILOpEffect *instruction_sequence = op_ASSIGN_2;
	return instruction_sequence;
}

// Rd = Cs
RzILOpEffect *hex_il_op_a2_tfrcrr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Cs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Cs = READ_REG(pkt, Cs_op, false);

	// Rd = Cs;
	RzILOpEffect *op_ASSIGN_2 = WRITE_REG(bundle, Rd_op, Cs);

	RzILOpEffect *instruction_sequence = op_ASSIGN_2;
	return instruction_sequence;
}

// Rx.h = Ii
RzILOpEffect *hex_il_op_a2_tfrih(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_9 = SETL("u", u);

	// Rx = ((st32) (((ut64) (((st64) Rx) & (~(0xffff << 0x10)))) | (((ut64) (u & ((ut32) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_8 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_NOT_6);
	RzILOpPure *op_AND_13 = LOGAND(VARL("u"), CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, op_AND_13), SN(32, 16));
	RzILOpPure *op_OR_20 = LOGOR(CAST(64, IL_FALSE, op_AND_8), op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_9, op_ASSIGN_22);
	return instruction_sequence;
}

// Rx.l = Ii
RzILOpEffect *hex_il_op_a2_tfril(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_9 = SETL("u", u);

	// Rx = ((st32) (((ut64) (((st64) Rx) & (~(0xffff << 0x0)))) | (((ut64) (u & ((ut32) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_8 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_NOT_6);
	RzILOpPure *op_AND_13 = LOGAND(VARL("u"), CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, op_AND_13), SN(32, 0));
	RzILOpPure *op_OR_20 = LOGOR(CAST(64, IL_FALSE, op_AND_8), op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_9, op_ASSIGN_22);
	return instruction_sequence;
}

// Cd = Rs
RzILOpEffect *hex_il_op_a2_tfrrcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Cd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Cd = Rs;
	RzILOpEffect *op_ASSIGN_2 = WRITE_REG(bundle, Cd_op, Rs);

	RzILOpEffect *instruction_sequence = op_ASSIGN_2;
	return instruction_sequence;
}

// Rd = Ii
RzILOpEffect *hex_il_op_a2_tfrsi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = s;
	RzILOpEffect *op_ASSIGN_3 = WRITE_REG(bundle, Rd_op, VARL("s"));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_3);
	return instruction_sequence;
}

// Rdd = vabsh(Rss)
RzILOpEffect *hex_il_op_a2_vabsh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp34 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp34", VARL("i"));

	// seq(h_tmp34 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_26 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), SN(32, 0));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(DUP(Rss), op_MUL_28);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_35 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_32), DUP(op_AND_32))), CAST(16, MSB(DUP(op_AND_32)), DUP(op_AND_32))));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rss), op_MUL_37);
	RzILOpPure *op_AND_41 = LOGAND(op_RSHIFT_38, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_44 = ITE(op_LT_26, op_NEG_35, CAST(32, MSB(CAST(16, MSB(op_AND_41), DUP(op_AND_41))), CAST(16, MSB(DUP(op_AND_41)), DUP(op_AND_41))));
	RzILOpPure *op_AND_46 = LOGAND(cond_44, SN(32, 0xffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(CAST(64, IL_FALSE, op_AND_46), op_MUL_49);
	RzILOpPure *op_OR_52 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_50);
	RzILOpEffect *op_ASSIGN_54 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_52));

	// seq(h_tmp34; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_56 = op_ASSIGN_54;

	// seq(seq(h_tmp34; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_57 = SEQN(2, seq_56, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp34; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_58 = REPEAT(op_LT_4, seq_57);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp34; Rdd = ((st64)  ...;
	RzILOpEffect *seq_59 = SEQN(2, op_ASSIGN_2, for_58);

	RzILOpEffect *instruction_sequence = seq_59;
	return instruction_sequence;
}

// Rdd = vabsh(Rss):sat
RzILOpEffect *hex_il_op_a2_vabshsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp35 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp35", VARL("i"));

	// seq(h_tmp35 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_113 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_29 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), SN(32, 0));
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_32 = SHIFTRA(DUP(Rss), op_MUL_31);
	RzILOpPure *op_AND_35 = LOGAND(op_RSHIFT_32, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_38 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_35), DUP(op_AND_35))), CAST(16, MSB(DUP(op_AND_35)), DUP(op_AND_35))));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(DUP(Rss), op_MUL_40);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_41, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_47 = ITE(op_LT_29, op_NEG_38, CAST(32, MSB(CAST(16, MSB(op_AND_44), DUP(op_AND_44))), CAST(16, MSB(DUP(op_AND_44)), DUP(op_AND_44))));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_62 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_58), DUP(op_AND_58))), CAST(16, MSB(DUP(op_AND_58)), DUP(op_AND_58))), SN(32, 0));
	RzILOpPure *op_MUL_64 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_65 = SHIFTRA(DUP(Rss), op_MUL_64);
	RzILOpPure *op_AND_68 = LOGAND(op_RSHIFT_65, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_71 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_68), DUP(op_AND_68))), CAST(16, MSB(DUP(op_AND_68)), DUP(op_AND_68))));
	RzILOpPure *op_MUL_73 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_74 = SHIFTRA(DUP(Rss), op_MUL_73);
	RzILOpPure *op_AND_77 = LOGAND(op_RSHIFT_74, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_80 = ITE(op_LT_62, op_NEG_71, CAST(32, MSB(CAST(16, MSB(op_AND_77), DUP(op_AND_77))), CAST(16, MSB(DUP(op_AND_77)), DUP(op_AND_77))));
	RzILOpPure *op_EQ_82 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_47), SN(32, 0), SN(32, 16)), CAST(64, MSB(cond_80), DUP(cond_80)));
	RzILOpPure *op_MUL_115 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_116 = SHIFTRA(DUP(Rss), op_MUL_115);
	RzILOpPure *op_AND_119 = LOGAND(op_RSHIFT_116, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_123 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_119), DUP(op_AND_119))), CAST(16, MSB(DUP(op_AND_119)), DUP(op_AND_119))), SN(32, 0));
	RzILOpPure *op_MUL_125 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_126 = SHIFTRA(DUP(Rss), op_MUL_125);
	RzILOpPure *op_AND_129 = LOGAND(op_RSHIFT_126, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_132 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_129), DUP(op_AND_129))), CAST(16, MSB(DUP(op_AND_129)), DUP(op_AND_129))));
	RzILOpPure *op_MUL_134 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_135 = SHIFTRA(DUP(Rss), op_MUL_134);
	RzILOpPure *op_AND_138 = LOGAND(op_RSHIFT_135, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_141 = ITE(op_LT_123, op_NEG_132, CAST(32, MSB(CAST(16, MSB(op_AND_138), DUP(op_AND_138))), CAST(16, MSB(DUP(op_AND_138)), DUP(op_AND_138))));
	RzILOpPure *op_LT_143 = SLT(cond_141, SN(32, 0));
	RzILOpPure *op_LSHIFT_148 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_149 = NEG(op_LSHIFT_148);
	RzILOpPure *op_LSHIFT_154 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_157 = SUB(op_LSHIFT_154, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_158 = ITE(op_LT_143, op_NEG_149, op_SUB_157);
	RzILOpEffect *gcc_expr_159 = BRANCH(op_EQ_82, EMPTY(), set_usr_field_call_113);

	// h_tmp36 = HYB(gcc_expr_if ((sextract64(((ut64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_161 = SETL("h_tmp36", cond_158);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_162 = SEQN(2, gcc_expr_159, op_ASSIGN_hybrid_tmp_161);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))))) ? ((st64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) : h_tmp36) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_84 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rss), op_MUL_84);
	RzILOpPure *op_AND_88 = LOGAND(op_RSHIFT_85, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_92 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_88), DUP(op_AND_88))), CAST(16, MSB(DUP(op_AND_88)), DUP(op_AND_88))), SN(32, 0));
	RzILOpPure *op_MUL_94 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_95 = SHIFTRA(DUP(Rss), op_MUL_94);
	RzILOpPure *op_AND_98 = LOGAND(op_RSHIFT_95, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_101 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_98), DUP(op_AND_98))), CAST(16, MSB(DUP(op_AND_98)), DUP(op_AND_98))));
	RzILOpPure *op_MUL_103 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_104 = SHIFTRA(DUP(Rss), op_MUL_103);
	RzILOpPure *op_AND_107 = LOGAND(op_RSHIFT_104, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_110 = ITE(op_LT_92, op_NEG_101, CAST(32, MSB(CAST(16, MSB(op_AND_107), DUP(op_AND_107))), CAST(16, MSB(DUP(op_AND_107)), DUP(op_AND_107))));
	RzILOpPure *cond_164 = ITE(DUP(op_EQ_82), CAST(64, MSB(cond_110), DUP(cond_110)), VARL("h_tmp36"));
	RzILOpPure *op_AND_167 = LOGAND(cond_164, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_170 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_171 = SHIFTL0(CAST(64, IL_FALSE, op_AND_167), op_MUL_170);
	RzILOpPure *op_OR_173 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_171);
	RzILOpEffect *op_ASSIGN_175 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_173));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st32) ((st16) ( ...;
	RzILOpEffect *seq_176 = SEQN(2, seq_162, op_ASSIGN_175);

	// seq(h_tmp35; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st ...;
	RzILOpEffect *seq_178 = seq_176;

	// seq(seq(h_tmp35; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_179 = SEQN(2, seq_178, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp35; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_180 = REPEAT(op_LT_4, seq_179);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp35; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_181 = SEQN(2, op_ASSIGN_2, for_180);

	RzILOpEffect *instruction_sequence = seq_181;
	return instruction_sequence;
}

// Rdd = vabsw(Rss)
RzILOpEffect *hex_il_op_a2_vabsw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp37 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp37", VARL("i"));

	// seq(h_tmp37 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_LT_26 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(DUP(Rss), op_MUL_28);
	RzILOpPure *op_AND_31 = LOGAND(op_RSHIFT_29, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_34 = NEG(CAST(64, MSB(CAST(32, MSB(op_AND_31), DUP(op_AND_31))), CAST(32, MSB(DUP(op_AND_31)), DUP(op_AND_31))));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rss), op_MUL_36);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *cond_42 = ITE(op_LT_26, op_NEG_34, CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))));
	RzILOpPure *op_AND_44 = LOGAND(cond_42, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_46 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(op_AND_44, op_MUL_46);
	RzILOpPure *op_OR_48 = LOGOR(op_AND_15, op_LSHIFT_47);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rdd_op, op_OR_48);

	// seq(h_tmp37; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((((( ...;
	RzILOpEffect *seq_51 = op_ASSIGN_49;

	// seq(seq(h_tmp37; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_51, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp37; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_53 = REPEAT(op_LT_4, seq_52);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp37; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_54 = SEQN(2, op_ASSIGN_2, for_53);

	RzILOpEffect *instruction_sequence = seq_54;
	return instruction_sequence;
}

// Rdd = vabsw(Rss):sat
RzILOpEffect *hex_il_op_a2_vabswsat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp38 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp38", VARL("i"));

	// seq(h_tmp38 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_106 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))), 0x0, 0x20) == ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_LT_29 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_32 = SHIFTRA(DUP(Rss), op_MUL_31);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_32, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_37 = NEG(CAST(64, MSB(CAST(32, MSB(op_AND_34), DUP(op_AND_34))), CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34))));
	RzILOpPure *op_MUL_39 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rss), op_MUL_39);
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_40, SN(64, 0xffffffff));
	RzILOpPure *cond_45 = ITE(op_LT_29, op_NEG_37, CAST(64, MSB(CAST(32, MSB(op_AND_42), DUP(op_AND_42))), CAST(32, MSB(DUP(op_AND_42)), DUP(op_AND_42))));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rss), op_MUL_52);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_53, SN(64, 0xffffffff));
	RzILOpPure *op_LT_60 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_55), DUP(op_AND_55))), CAST(32, MSB(DUP(op_AND_55)), DUP(op_AND_55))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_62 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rss), op_MUL_62);
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_63, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_68 = NEG(CAST(64, MSB(CAST(32, MSB(op_AND_65), DUP(op_AND_65))), CAST(32, MSB(DUP(op_AND_65)), DUP(op_AND_65))));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rss), op_MUL_70);
	RzILOpPure *op_AND_73 = LOGAND(op_RSHIFT_71, SN(64, 0xffffffff));
	RzILOpPure *cond_76 = ITE(op_LT_60, op_NEG_68, CAST(64, MSB(CAST(32, MSB(op_AND_73), DUP(op_AND_73))), CAST(32, MSB(DUP(op_AND_73)), DUP(op_AND_73))));
	RzILOpPure *op_EQ_77 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_45), SN(32, 0), SN(32, 0x20)), cond_76);
	RzILOpPure *op_MUL_108 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_109 = SHIFTRA(DUP(Rss), op_MUL_108);
	RzILOpPure *op_AND_111 = LOGAND(op_RSHIFT_109, SN(64, 0xffffffff));
	RzILOpPure *op_LT_116 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_111), DUP(op_AND_111))), CAST(32, MSB(DUP(op_AND_111)), DUP(op_AND_111))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_118 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_119 = SHIFTRA(DUP(Rss), op_MUL_118);
	RzILOpPure *op_AND_121 = LOGAND(op_RSHIFT_119, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_124 = NEG(CAST(64, MSB(CAST(32, MSB(op_AND_121), DUP(op_AND_121))), CAST(32, MSB(DUP(op_AND_121)), DUP(op_AND_121))));
	RzILOpPure *op_MUL_126 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_127 = SHIFTRA(DUP(Rss), op_MUL_126);
	RzILOpPure *op_AND_129 = LOGAND(op_RSHIFT_127, SN(64, 0xffffffff));
	RzILOpPure *cond_132 = ITE(op_LT_116, op_NEG_124, CAST(64, MSB(CAST(32, MSB(op_AND_129), DUP(op_AND_129))), CAST(32, MSB(DUP(op_AND_129)), DUP(op_AND_129))));
	RzILOpPure *op_LT_135 = SLT(cond_132, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_140 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_141 = NEG(op_LSHIFT_140);
	RzILOpPure *op_LSHIFT_146 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_149 = SUB(op_LSHIFT_146, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_150 = ITE(op_LT_135, op_NEG_141, op_SUB_149);
	RzILOpEffect *gcc_expr_151 = BRANCH(op_EQ_77, EMPTY(), set_usr_field_call_106);

	// h_tmp39 = HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))), 0x0, 0x20) == ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_153 = SETL("h_tmp39", cond_150);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) ((st32) ((Rss ...;
	RzILOpEffect *seq_154 = SEQN(2, gcc_expr_151, op_ASSIGN_hybrid_tmp_153);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))), 0x0, 0x20) == ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) ? ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) : h_tmp39) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_79 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_80 = SHIFTRA(DUP(Rss), op_MUL_79);
	RzILOpPure *op_AND_82 = LOGAND(op_RSHIFT_80, SN(64, 0xffffffff));
	RzILOpPure *op_LT_87 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_82), DUP(op_AND_82))), CAST(32, MSB(DUP(op_AND_82)), DUP(op_AND_82))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_89 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_90 = SHIFTRA(DUP(Rss), op_MUL_89);
	RzILOpPure *op_AND_92 = LOGAND(op_RSHIFT_90, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_95 = NEG(CAST(64, MSB(CAST(32, MSB(op_AND_92), DUP(op_AND_92))), CAST(32, MSB(DUP(op_AND_92)), DUP(op_AND_92))));
	RzILOpPure *op_MUL_97 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_98 = SHIFTRA(DUP(Rss), op_MUL_97);
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_98, SN(64, 0xffffffff));
	RzILOpPure *cond_103 = ITE(op_LT_87, op_NEG_95, CAST(64, MSB(CAST(32, MSB(op_AND_100), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))));
	RzILOpPure *cond_155 = ITE(DUP(op_EQ_77), cond_103, VARL("h_tmp39"));
	RzILOpPure *op_AND_157 = LOGAND(cond_155, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_159 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_160 = SHIFTL0(op_AND_157, op_MUL_159);
	RzILOpPure *op_OR_161 = LOGOR(op_AND_15, op_LSHIFT_160);
	RzILOpEffect *op_ASSIGN_162 = WRITE_REG(bundle, Rdd_op, op_OR_161);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) ((st32) ( ...;
	RzILOpEffect *seq_163 = SEQN(2, seq_154, op_ASSIGN_162);

	// seq(h_tmp38; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st ...;
	RzILOpEffect *seq_165 = seq_163;

	// seq(seq(h_tmp38; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_166 = SEQN(2, seq_165, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp38; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_167 = REPEAT(op_LT_4, seq_166);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp38; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_168 = SEQN(2, op_ASSIGN_2, for_167);

	RzILOpEffect *instruction_sequence = seq_168;
	return instruction_sequence;
}

// Rdd = vaddh(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vaddh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp40 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp40", VARL("i"));

	// seq(h_tmp40 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_AND_36 = LOGAND(op_ADD_34, SN(32, 0xffff));
	RzILOpPure *op_MUL_39 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(CAST(64, IL_FALSE, op_AND_36), op_MUL_39);
	RzILOpPure *op_OR_42 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_40);
	RzILOpEffect *op_ASSIGN_44 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_42));

	// seq(h_tmp40; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_46 = op_ASSIGN_44;

	// seq(seq(h_tmp40; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_47 = SEQN(2, seq_46, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp40; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_48 = REPEAT(op_LT_4, seq_47);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp40; Rdd = ((st64)  ...;
	RzILOpEffect *seq_49 = SEQN(2, op_ASSIGN_2, for_48);

	RzILOpEffect *instruction_sequence = seq_49;
	return instruction_sequence;
}

// Rdd = vaddh(Rss,Rtt):sat
RzILOpEffect *hex_il_op_a2_vaddhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp41 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp41", VARL("i"));

	// seq(h_tmp41 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_81 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rtt, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_37 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rss), op_MUL_44);
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rtt), op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_59 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_48), DUP(op_AND_48))), CAST(16, MSB(DUP(op_AND_48)), DUP(op_AND_48))), CAST(32, MSB(CAST(16, MSB(op_AND_55), DUP(op_AND_55))), CAST(16, MSB(DUP(op_AND_55)), DUP(op_AND_55))));
	RzILOpPure *op_EQ_61 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_37), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_59), DUP(op_ADD_59)));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rss), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_98 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_87), DUP(op_AND_87))), CAST(16, MSB(DUP(op_AND_87)), DUP(op_AND_87))), CAST(32, MSB(CAST(16, MSB(op_AND_94), DUP(op_AND_94))), CAST(16, MSB(DUP(op_AND_94)), DUP(op_AND_94))));
	RzILOpPure *op_LT_100 = SLT(op_ADD_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_105 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_106 = NEG(op_LSHIFT_105);
	RzILOpPure *op_LSHIFT_111 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_114 = SUB(op_LSHIFT_111, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_115 = ITE(op_LT_100, op_NEG_106, op_SUB_114);
	RzILOpEffect *gcc_expr_116 = BRANCH(op_EQ_61, EMPTY(), set_usr_field_call_81);

	// h_tmp42 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_118 = SETL("h_tmp42", cond_115);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_119 = SEQN(2, gcc_expr_116, op_ASSIGN_hybrid_tmp_118);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))) : h_tmp42) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rss), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rtt), op_MUL_70);
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_71, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_78 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_67), DUP(op_AND_67))), CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67))), CAST(32, MSB(CAST(16, MSB(op_AND_74), DUP(op_AND_74))), CAST(16, MSB(DUP(op_AND_74)), DUP(op_AND_74))));
	RzILOpPure *cond_121 = ITE(DUP(op_EQ_61), CAST(64, MSB(op_ADD_78), DUP(op_ADD_78)), VARL("h_tmp42"));
	RzILOpPure *op_AND_124 = LOGAND(cond_121, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_127 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_128 = SHIFTL0(CAST(64, IL_FALSE, op_AND_124), op_MUL_127);
	RzILOpPure *op_OR_130 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_128);
	RzILOpEffect *op_ASSIGN_132 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_130));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_133 = SEQN(2, seq_119, op_ASSIGN_132);

	// seq(h_tmp41; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32 ...;
	RzILOpEffect *seq_135 = seq_133;

	// seq(seq(h_tmp41; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_136 = SEQN(2, seq_135, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp41; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_137 = REPEAT(op_LT_4, seq_136);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp41; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_138 = SEQN(2, op_ASSIGN_2, for_137);

	RzILOpEffect *instruction_sequence = seq_138;
	return instruction_sequence;
}

// Rdd = vaddub(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vaddub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp43 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp43", VARL("i"));

	// seq(h_tmp43 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_30)));
	RzILOpPure *op_AND_37 = LOGAND(CAST(64, MSB(op_ADD_34), DUP(op_ADD_34)), SN(64, 0xff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(CAST(64, IL_FALSE, op_AND_37), op_MUL_40);
	RzILOpPure *op_OR_43 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_41);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_43));

	// seq(h_tmp43; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_47 = op_ASSIGN_45;

	// seq(seq(h_tmp43; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_48 = SEQN(2, seq_47, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp43; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_49 = REPEAT(op_LT_4, seq_48);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp43; Rdd = ((st64)  ...;
	RzILOpEffect *seq_50 = SEQN(2, op_ASSIGN_2, for_49);

	RzILOpEffect *instruction_sequence = seq_50;
	return instruction_sequence;
}

// Rdd = vaddub(Rss,Rtt):sat
RzILOpEffect *hex_il_op_a2_vaddubs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp44 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp44", VARL("i"));

	// seq(h_tmp44 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_81 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))), 0x0, 0x8) == ((ut64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rtt, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_37 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_25)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_33)));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rss), op_MUL_44);
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rtt), op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_59 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_48)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_55)));
	RzILOpPure *op_EQ_61 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_ADD_37), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, op_ADD_59));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rss), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_98 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_87)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_94)));
	RzILOpPure *op_LT_100 = SLT(op_ADD_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_107 = SUB(op_LSHIFT_104, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_109 = ITE(op_LT_100, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_107);
	RzILOpEffect *gcc_expr_110 = BRANCH(op_EQ_61, EMPTY(), set_usr_field_call_81);

	// h_tmp45 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))), 0x0, 0x8) == ((ut64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_112 = SETL("h_tmp45", cond_109);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rss >>  ...;
	RzILOpEffect *seq_113 = SEQN(2, gcc_expr_110, op_ASSIGN_hybrid_tmp_112);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((extract64(((ut64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))), 0x0, 0x8) == ((ut64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))))) ? ((st64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) : h_tmp45) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rss), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rtt), op_MUL_70);
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_71, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_78 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_67)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_74)));
	RzILOpPure *cond_115 = ITE(DUP(op_EQ_61), CAST(64, MSB(op_ADD_78), DUP(op_ADD_78)), VARL("h_tmp45"));
	RzILOpPure *op_AND_117 = LOGAND(cond_115, SN(64, 0xff));
	RzILOpPure *op_MUL_120 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(CAST(64, IL_FALSE, op_AND_117), op_MUL_120);
	RzILOpPure *op_OR_123 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_121);
	RzILOpEffect *op_ASSIGN_125 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_123));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rss ...;
	RzILOpEffect *seq_126 = SEQN(2, seq_113, op_ASSIGN_125);

	// seq(h_tmp44; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ...;
	RzILOpEffect *seq_128 = seq_126;

	// seq(seq(h_tmp44; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ...;
	RzILOpEffect *seq_129 = SEQN(2, seq_128, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp44; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_130 = REPEAT(op_LT_4, seq_129);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp44; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_131 = SEQN(2, op_ASSIGN_2, for_130);

	RzILOpEffect *instruction_sequence = seq_131;
	return instruction_sequence;
}

// Rdd = vadduh(Rss,Rtt):sat
RzILOpEffect *hex_il_op_a2_vadduhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp46 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp46", VARL("i"));

	// seq(h_tmp46 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_81 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rtt, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_37 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_25)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_33)));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rss), op_MUL_44);
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rtt), op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_59 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_48)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_55)));
	RzILOpPure *op_EQ_61 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_ADD_37), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, op_ADD_59));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rss), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_98 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_87)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_94)));
	RzILOpPure *op_LT_100 = SLT(op_ADD_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_107 = SUB(op_LSHIFT_104, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_109 = ITE(op_LT_100, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_107);
	RzILOpEffect *gcc_expr_110 = BRANCH(op_EQ_61, EMPTY(), set_usr_field_call_81);

	// h_tmp47 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_112 = SETL("h_tmp47", cond_109);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rss >> ...;
	RzILOpEffect *seq_113 = SEQN(2, gcc_expr_110, op_ASSIGN_hybrid_tmp_112);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((extract64(((ut64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))) : h_tmp47) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rss), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rtt), op_MUL_70);
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_71, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_78 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_67)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_74)));
	RzILOpPure *cond_115 = ITE(DUP(op_EQ_61), CAST(64, MSB(op_ADD_78), DUP(op_ADD_78)), VARL("h_tmp47"));
	RzILOpPure *op_AND_118 = LOGAND(cond_115, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_121 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_122 = SHIFTL0(CAST(64, IL_FALSE, op_AND_118), op_MUL_121);
	RzILOpPure *op_OR_124 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_122);
	RzILOpEffect *op_ASSIGN_126 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_124));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rs ...;
	RzILOpEffect *seq_127 = SEQN(2, seq_113, op_ASSIGN_126);

	// seq(h_tmp46; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ...;
	RzILOpEffect *seq_129 = seq_127;

	// seq(seq(h_tmp46; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ...;
	RzILOpEffect *seq_130 = SEQN(2, seq_129, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp46; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((s ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_131 = REPEAT(op_LT_4, seq_130);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp46; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_132 = SEQN(2, op_ASSIGN_2, for_131);

	RzILOpEffect *instruction_sequence = seq_132;
	return instruction_sequence;
}

// Rdd = vaddw(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vaddw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp48 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp48", VARL("i"));

	// seq(h_tmp48 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_32 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_AND_34 = LOGAND(op_ADD_32, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(op_AND_34, op_MUL_36);
	RzILOpPure *op_OR_38 = LOGOR(op_AND_15, op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rdd_op, op_OR_38);

	// seq(h_tmp48; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((st ...;
	RzILOpEffect *seq_41 = op_ASSIGN_39;

	// seq(seq(h_tmp48; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_41, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp48; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_43 = REPEAT(op_LT_4, seq_42);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp48; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_2, for_43);

	RzILOpEffect *instruction_sequence = seq_44;
	return instruction_sequence;
}

// Rdd = vaddw(Rss,Rtt):sat
RzILOpEffect *hex_il_op_a2_vaddws(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp49 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp49", VARL("i"));

	// seq(h_tmp49 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_74 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rtt, op_MUL_29);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_35 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24))), CAST(64, MSB(CAST(32, MSB(op_AND_32), DUP(op_AND_32))), CAST(32, MSB(DUP(op_AND_32)), DUP(op_AND_32))));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rss), op_MUL_42);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_43, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rtt), op_MUL_49);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_55 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_45), DUP(op_AND_45))), CAST(32, MSB(DUP(op_AND_45)), DUP(op_AND_45))), CAST(64, MSB(CAST(32, MSB(op_AND_52), DUP(op_AND_52))), CAST(32, MSB(DUP(op_AND_52)), DUP(op_AND_52))));
	RzILOpPure *op_EQ_56 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_35), SN(32, 0), SN(32, 0x20)), op_ADD_55);
	RzILOpPure *op_MUL_76 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rss), op_MUL_76);
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rtt), op_MUL_83);
	RzILOpPure *op_AND_86 = LOGAND(op_RSHIFT_84, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_89 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_79), DUP(op_AND_79))), CAST(32, MSB(DUP(op_AND_79)), DUP(op_AND_79))), CAST(64, MSB(CAST(32, MSB(op_AND_86), DUP(op_AND_86))), CAST(32, MSB(DUP(op_AND_86)), DUP(op_AND_86))));
	RzILOpPure *op_LT_92 = SLT(op_ADD_89, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_97 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_98 = NEG(op_LSHIFT_97);
	RzILOpPure *op_LSHIFT_103 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_106 = SUB(op_LSHIFT_103, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_107 = ITE(op_LT_92, op_NEG_98, op_SUB_106);
	RzILOpEffect *gcc_expr_108 = BRANCH(op_EQ_56, EMPTY(), set_usr_field_call_74);

	// h_tmp50 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_110 = SETL("h_tmp50", cond_107);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_111 = SEQN(2, gcc_expr_108, op_ASSIGN_hybrid_tmp_110);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) : h_tmp50) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_58 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_59 = SHIFTRA(DUP(Rss), op_MUL_58);
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_59, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_65 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_66 = SHIFTRA(DUP(Rtt), op_MUL_65);
	RzILOpPure *op_AND_68 = LOGAND(op_RSHIFT_66, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_71 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_61), DUP(op_AND_61))), CAST(32, MSB(DUP(op_AND_61)), DUP(op_AND_61))), CAST(64, MSB(CAST(32, MSB(op_AND_68), DUP(op_AND_68))), CAST(32, MSB(DUP(op_AND_68)), DUP(op_AND_68))));
	RzILOpPure *cond_112 = ITE(DUP(op_EQ_56), op_ADD_71, VARL("h_tmp50"));
	RzILOpPure *op_AND_114 = LOGAND(cond_112, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_116 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_117 = SHIFTL0(op_AND_114, op_MUL_116);
	RzILOpPure *op_OR_118 = LOGOR(op_AND_15, op_LSHIFT_117);
	RzILOpEffect *op_ASSIGN_119 = WRITE_REG(bundle, Rdd_op, op_OR_118);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_120 = SEQN(2, seq_111, op_ASSIGN_119);

	// seq(h_tmp49; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64 ...;
	RzILOpEffect *seq_122 = seq_120;

	// seq(seq(h_tmp49; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_123 = SEQN(2, seq_122, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp49; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_124 = REPEAT(op_LT_4, seq_123);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp49; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_125 = SEQN(2, op_ASSIGN_2, for_124);

	RzILOpEffect *instruction_sequence = seq_125;
	return instruction_sequence;
}

// Rdd = vavgh(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vavgh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp51 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp51", VARL("i"));

	// seq(h_tmp51 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(op_ADD_34, SN(32, 1));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_44));

	// seq(h_tmp51; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp51; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp51; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_50 = REPEAT(op_LT_4, seq_49);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp51; Rdd = ((st64)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_2, for_50);

	RzILOpEffect *instruction_sequence = seq_51;
	return instruction_sequence;
}

// Rdd = vavgh(Rss,Rtt):crnd
RzILOpEffect *hex_il_op_a2_vavghcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp52 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp52", VARL("i"));

	// seq(h_tmp52 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))) >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_AND_36 = LOGAND(op_ADD_34, SN(32, 3));
	RzILOpPure *op_EQ_38 = EQ(op_AND_36, SN(32, 3));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(DUP(Rss), op_MUL_40);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_41, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), op_MUL_47);
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_55 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_44), DUP(op_AND_44))), CAST(16, MSB(DUP(op_AND_44)), DUP(op_AND_44))), CAST(32, MSB(CAST(16, MSB(op_AND_51), DUP(op_AND_51))), CAST(16, MSB(DUP(op_AND_51)), DUP(op_AND_51))));
	RzILOpPure *op_ADD_57 = ADD(op_ADD_55, SN(32, 1));
	RzILOpPure *op_MUL_59 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_60 = SHIFTRA(DUP(Rss), op_MUL_59);
	RzILOpPure *op_AND_63 = LOGAND(op_RSHIFT_60, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rtt), op_MUL_66);
	RzILOpPure *op_AND_70 = LOGAND(op_RSHIFT_67, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_74 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_63), DUP(op_AND_63))), CAST(16, MSB(DUP(op_AND_63)), DUP(op_AND_63))), CAST(32, MSB(CAST(16, MSB(op_AND_70), DUP(op_AND_70))), CAST(16, MSB(DUP(op_AND_70)), DUP(op_AND_70))));
	RzILOpPure *cond_75 = ITE(op_EQ_38, op_ADD_57, op_ADD_74);
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(cond_75, SN(32, 1));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(32, 0xffff));
	RzILOpPure *op_MUL_82 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_83 = SHIFTL0(CAST(64, IL_FALSE, op_AND_79), op_MUL_82);
	RzILOpPure *op_OR_85 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_83);
	RzILOpEffect *op_ASSIGN_87 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_85));

	// seq(h_tmp52; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_89 = op_ASSIGN_87;

	// seq(seq(h_tmp52; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_90 = SEQN(2, seq_89, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp52; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_91 = REPEAT(op_LT_4, seq_90);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp52; Rdd = ((st64)  ...;
	RzILOpEffect *seq_92 = SEQN(2, op_ASSIGN_2, for_91);

	RzILOpEffect *instruction_sequence = seq_92;
	return instruction_sequence;
}

// Rdd = vavgh(Rss,Rtt):rnd
RzILOpEffect *hex_il_op_a2_vavghr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp53 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp53", VARL("i"));

	// seq(h_tmp53 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_ADD_36 = ADD(op_ADD_34, SN(32, 1));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(op_ADD_36, SN(32, 1));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), op_MUL_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_46));

	// seq(h_tmp53; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_50 = op_ASSIGN_48;

	// seq(seq(h_tmp53; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_50, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp53; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_52 = REPEAT(op_LT_4, seq_51);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp53; Rdd = ((st64)  ...;
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_2, for_52);

	RzILOpEffect *instruction_sequence = seq_53;
	return instruction_sequence;
}

// Rdd = vavgub(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vavgub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp54 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp54", VARL("i"));

	// seq(h_tmp54 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) (((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) >> 0x1)) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_30)));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(op_ADD_34, SN(32, 1));
	RzILOpPure *op_AND_39 = LOGAND(CAST(64, MSB(op_RSHIFT_36), DUP(op_RSHIFT_36)), SN(64, 0xff));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, op_AND_39), op_MUL_42);
	RzILOpPure *op_OR_45 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_43);
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_45));

	// seq(h_tmp54; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_49 = op_ASSIGN_47;

	// seq(seq(h_tmp54; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_50 = SEQN(2, seq_49, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp54; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_51 = REPEAT(op_LT_4, seq_50);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp54; Rdd = ((st64)  ...;
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_2, for_51);

	RzILOpEffect *instruction_sequence = seq_52;
	return instruction_sequence;
}

// Rdd = vavgub(Rss,Rtt):rnd
RzILOpEffect *hex_il_op_a2_vavgubr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp55 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp55", VARL("i"));

	// seq(h_tmp55 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) (((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) + 0x1 >> 0x1)) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_30)));
	RzILOpPure *op_ADD_36 = ADD(op_ADD_34, SN(32, 1));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(op_ADD_36, SN(32, 1));
	RzILOpPure *op_AND_41 = LOGAND(CAST(64, MSB(op_RSHIFT_38), DUP(op_RSHIFT_38)), SN(64, 0xff));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, op_AND_41), op_MUL_44);
	RzILOpPure *op_OR_47 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_45);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_47));

	// seq(h_tmp55; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_51 = op_ASSIGN_49;

	// seq(seq(h_tmp55; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_51, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp55; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_53 = REPEAT(op_LT_4, seq_52);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp55; Rdd = ((st64)  ...;
	RzILOpEffect *seq_54 = SEQN(2, op_ASSIGN_2, for_53);

	RzILOpEffect *instruction_sequence = seq_54;
	return instruction_sequence;
}

// Rdd = vavguh(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vavguh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp56 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp56", VARL("i"));

	// seq(h_tmp56 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_30)));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(op_ADD_34, SN(32, 1));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_44));

	// seq(h_tmp56; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp56; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp56; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_50 = REPEAT(op_LT_4, seq_49);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp56; Rdd = ((st64)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_2, for_50);

	RzILOpEffect *instruction_sequence = seq_51;
	return instruction_sequence;
}

// Rdd = vavguh(Rss,Rtt):rnd
RzILOpEffect *hex_il_op_a2_vavguhr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp57 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp57", VARL("i"));

	// seq(h_tmp57 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_34 = ADD(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_30)));
	RzILOpPure *op_ADD_36 = ADD(op_ADD_34, SN(32, 1));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(op_ADD_36, SN(32, 1));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(32, 0xffff));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), op_MUL_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_46));

	// seq(h_tmp57; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_50 = op_ASSIGN_48;

	// seq(seq(h_tmp57; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_50, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp57; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_52 = REPEAT(op_LT_4, seq_51);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp57; Rdd = ((st64)  ...;
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_2, for_52);

	RzILOpEffect *instruction_sequence = seq_53;
	return instruction_sequence;
}

// Rdd = vavguw(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vavguw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp58 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp58", VARL("i"));

	// seq(h_tmp58 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | (((extract64(((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))), 0x0, 0x20) + extract64(((ut64) ((ut32) ((Rtt >> i * 0x20) & 0xffffffff))), 0x0, 0x20) >> 0x1) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(Rtt, op_MUL_36);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_46 = ADD(EXTRACT64(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_24)), SN(32, 0), SN(32, 0x20)), EXTRACT64(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_39)), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_48 = SHIFTR0(op_ADD_46, SN(32, 1));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(op_AND_51, op_MUL_53);
	RzILOpPure *op_OR_56 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_58 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_56));

	// seq(h_tmp58; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i *  ...;
	RzILOpEffect *seq_60 = op_ASSIGN_58;

	// seq(seq(h_tmp58; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ...;
	RzILOpEffect *seq_61 = SEQN(2, seq_60, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp58; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_62 = REPEAT(op_LT_4, seq_61);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp58; Rdd = ((st64)  ...;
	RzILOpEffect *seq_63 = SEQN(2, op_ASSIGN_2, for_62);

	RzILOpEffect *instruction_sequence = seq_63;
	return instruction_sequence;
}

// Rdd = vavguw(Rss,Rtt):rnd
RzILOpEffect *hex_il_op_a2_vavguwr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp59 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp59", VARL("i"));

	// seq(h_tmp59 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | (((extract64(((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))), 0x0, 0x20) + extract64(((ut64) ((ut32) ((Rtt >> i * 0x20) & 0xffffffff))), 0x0, 0x20) + ((ut64) 0x1) >> 0x1) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(Rtt, op_MUL_36);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_46 = ADD(EXTRACT64(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_24)), SN(32, 0), SN(32, 0x20)), EXTRACT64(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_39)), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_49 = ADD(op_ADD_46, CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_RSHIFT_51 = SHIFTR0(op_ADD_49, SN(32, 1));
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_51, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_56 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_57 = SHIFTL0(op_AND_54, op_MUL_56);
	RzILOpPure *op_OR_59 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_57);
	RzILOpEffect *op_ASSIGN_61 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_59));

	// seq(h_tmp59; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i *  ...;
	RzILOpEffect *seq_63 = op_ASSIGN_61;

	// seq(seq(h_tmp59; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ...;
	RzILOpEffect *seq_64 = SEQN(2, seq_63, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp59; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_65 = REPEAT(op_LT_4, seq_64);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp59; Rdd = ((st64)  ...;
	RzILOpEffect *seq_66 = SEQN(2, op_ASSIGN_2, for_65);

	RzILOpEffect *instruction_sequence = seq_66;
	return instruction_sequence;
}

// Rdd = vavgw(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vavgw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp60 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp60", VARL("i"));

	// seq(h_tmp60 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) >> 0x1) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(Rtt, op_MUL_37);
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_48 = ADD(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(op_ADD_48, SN(32, 1));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(op_AND_52, op_MUL_54);
	RzILOpPure *op_OR_56 = LOGOR(op_AND_15, op_LSHIFT_55);
	RzILOpEffect *op_ASSIGN_57 = WRITE_REG(bundle, Rdd_op, op_OR_56);

	// seq(h_tmp60; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((sex ...;
	RzILOpEffect *seq_59 = op_ASSIGN_57;

	// seq(seq(h_tmp60; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_60 = SEQN(2, seq_59, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp60; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_61 = REPEAT(op_LT_4, seq_60);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp60; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_62 = SEQN(2, op_ASSIGN_2, for_61);

	RzILOpEffect *instruction_sequence = seq_62;
	return instruction_sequence;
}

// Rdd = vavgw(Rss,Rtt):crnd
RzILOpEffect *hex_il_op_a2_vavgwcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp61 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp61", VARL("i"));

	// seq(h_tmp61 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(Rtt, op_MUL_37);
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_48 = ADD(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_AND_51 = LOGAND(op_ADD_48, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_EQ_54 = EQ(op_AND_51, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_MUL_59 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_60 = SHIFTRA(DUP(Rss), op_MUL_59);
	RzILOpPure *op_AND_62 = LOGAND(op_RSHIFT_60, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_74 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_75 = SHIFTRA(DUP(Rtt), op_MUL_74);
	RzILOpPure *op_AND_77 = LOGAND(op_RSHIFT_75, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_85 = ADD(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_62), DUP(op_AND_62))), CAST(32, MSB(DUP(op_AND_62)), DUP(op_AND_62)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_77), DUP(op_AND_77))), CAST(32, MSB(DUP(op_AND_77)), DUP(op_AND_77)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_88 = ADD(op_ADD_85, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_MUL_93 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_94 = SHIFTRA(DUP(Rss), op_MUL_93);
	RzILOpPure *op_AND_96 = LOGAND(op_RSHIFT_94, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_108 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_109 = SHIFTRA(DUP(Rtt), op_MUL_108);
	RzILOpPure *op_AND_111 = LOGAND(op_RSHIFT_109, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_119 = ADD(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_96), DUP(op_AND_96))), CAST(32, MSB(DUP(op_AND_96)), DUP(op_AND_96)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_111), DUP(op_AND_111))), CAST(32, MSB(DUP(op_AND_111)), DUP(op_AND_111)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *cond_120 = ITE(op_EQ_54, op_ADD_88, op_ADD_119);
	RzILOpPure *op_RSHIFT_122 = SHIFTRA(cond_120, SN(32, 1));
	RzILOpPure *op_AND_124 = LOGAND(op_RSHIFT_122, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_126 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(op_AND_124, op_MUL_126);
	RzILOpPure *op_OR_128 = LOGOR(op_AND_15, op_LSHIFT_127);
	RzILOpEffect *op_ASSIGN_129 = WRITE_REG(bundle, Rdd_op, op_OR_128);

	// seq(h_tmp61; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((((( ...;
	RzILOpEffect *seq_131 = op_ASSIGN_129;

	// seq(seq(h_tmp61; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_132 = SEQN(2, seq_131, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp61; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_133 = REPEAT(op_LT_4, seq_132);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp61; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_134 = SEQN(2, op_ASSIGN_2, for_133);

	RzILOpEffect *instruction_sequence = seq_134;
	return instruction_sequence;
}

// Rdd = vavgw(Rss,Rtt):rnd
RzILOpEffect *hex_il_op_a2_vavgwr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp62 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp62", VARL("i"));

	// seq(h_tmp62 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(Rtt, op_MUL_37);
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_48 = ADD(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_51 = ADD(op_ADD_48, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(op_ADD_51, SN(32, 1));
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_53, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_57 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_58 = SHIFTL0(op_AND_55, op_MUL_57);
	RzILOpPure *op_OR_59 = LOGOR(op_AND_15, op_LSHIFT_58);
	RzILOpEffect *op_ASSIGN_60 = WRITE_REG(bundle, Rdd_op, op_OR_59);

	// seq(h_tmp62; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((sex ...;
	RzILOpEffect *seq_62 = op_ASSIGN_60;

	// seq(seq(h_tmp62; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_63 = SEQN(2, seq_62, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp62; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_64 = REPEAT(op_LT_4, seq_63);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp62; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_65 = SEQN(2, op_ASSIGN_2, for_64);

	RzILOpEffect *instruction_sequence = seq_65;
	return instruction_sequence;
}

// Pd = vcmpb.eq(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmpbeq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp63 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp63", VARL("i"));

	// seq(h_tmp63 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) | (((((st8) ((Rss >> i * 0x8) & ((st64) 0xff))) == ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_EQ_32 = EQ(CAST(8, MSB(op_AND_22), DUP(op_AND_22)), CAST(8, MSB(op_AND_30), DUP(op_AND_30)));
	RzILOpPure *ite_cast_ut64_33 = ITE(op_EQ_32, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(ite_cast_ut64_33, VARL("i"));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_15, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_35));

	// seq(h_tmp63; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) ...;
	RzILOpEffect *seq_39 = op_ASSIGN_37;

	// seq(seq(h_tmp63; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_39, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp63; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_41 = REPEAT(op_LT_4, seq_40);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp63; Pd = ((st8) (( ...;
	RzILOpEffect *seq_42 = SEQN(2, op_ASSIGN_2, for_41);

	RzILOpEffect *instruction_sequence = seq_42;
	return instruction_sequence;
}

// Pd = vcmpb.gtu(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmpbgtu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp64 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp64", VARL("i"));

	// seq(h_tmp64 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) | (((((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))) > ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_32 = UGT(CAST(8, IL_FALSE, op_AND_22), CAST(8, IL_FALSE, op_AND_30));
	RzILOpPure *ite_cast_ut64_33 = ITE(op_GT_32, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(ite_cast_ut64_33, VARL("i"));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_15, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_35));

	// seq(h_tmp64; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) ...;
	RzILOpEffect *seq_39 = op_ASSIGN_37;

	// seq(seq(h_tmp64; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_39, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp64; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_41 = REPEAT(op_LT_4, seq_40);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp64; Pd = ((st8) (( ...;
	RzILOpEffect *seq_42 = SEQN(2, op_ASSIGN_2, for_41);

	RzILOpEffect *instruction_sequence = seq_42;
	return instruction_sequence;
}

// Pd = vcmph.eq(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmpheq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp65 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp65", VARL("i"));

	// seq(h_tmp65 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2))) | (((((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) == ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(UN(64, 1), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_17 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_14);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rss, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(Rtt, op_MUL_28);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_34 = EQ(CAST(16, MSB(op_AND_24), DUP(op_AND_24)), CAST(16, MSB(op_AND_32), DUP(op_AND_32)));
	RzILOpPure *ite_cast_ut64_35 = ITE(op_EQ_34, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(ite_cast_ut64_35, op_MUL_37);
	RzILOpPure *op_OR_39 = LOGOR(op_AND_17, op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_39));

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2 + 0x1))) | (((((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) == ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_47 = ADD(op_MUL_45, SN(32, 1));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(UN(64, 1), op_ADD_47);
	RzILOpPure *op_NOT_49 = LOGNOT(op_LSHIFT_48);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_49);
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_61 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rtt), op_MUL_61);
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_62, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_67 = EQ(CAST(16, MSB(op_AND_58), DUP(op_AND_58)), CAST(16, MSB(op_AND_65), DUP(op_AND_65)));
	RzILOpPure *ite_cast_ut64_68 = ITE(op_EQ_67, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_72 = ADD(op_MUL_70, SN(32, 1));
	RzILOpPure *op_LSHIFT_73 = SHIFTL0(ite_cast_ut64_68, op_ADD_72);
	RzILOpPure *op_OR_74 = LOGOR(op_AND_52, op_LSHIFT_73);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_74));

	// seq(h_tmp65; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i *  ...;
	RzILOpEffect *seq_78 = SEQN(2, op_ASSIGN_41, op_ASSIGN_76);

	// seq(seq(h_tmp65; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_79 = SEQN(2, seq_78, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp65; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_80 = REPEAT(op_LT_4, seq_79);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp65; Pd = ((st8) (( ...;
	RzILOpEffect *seq_81 = SEQN(2, op_ASSIGN_2, for_80);

	RzILOpEffect *instruction_sequence = seq_81;
	return instruction_sequence;
}

// Pd = vcmph.gt(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmphgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp66 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp66", VARL("i"));

	// seq(h_tmp66 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2))) | (((((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) > ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(UN(64, 1), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_17 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_14);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rss, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(Rtt, op_MUL_28);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_34 = SGT(CAST(16, MSB(op_AND_24), DUP(op_AND_24)), CAST(16, MSB(op_AND_32), DUP(op_AND_32)));
	RzILOpPure *ite_cast_ut64_35 = ITE(op_GT_34, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(ite_cast_ut64_35, op_MUL_37);
	RzILOpPure *op_OR_39 = LOGOR(op_AND_17, op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_39));

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2 + 0x1))) | (((((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) > ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_47 = ADD(op_MUL_45, SN(32, 1));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(UN(64, 1), op_ADD_47);
	RzILOpPure *op_NOT_49 = LOGNOT(op_LSHIFT_48);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_49);
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_61 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rtt), op_MUL_61);
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_62, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_67 = SGT(CAST(16, MSB(op_AND_58), DUP(op_AND_58)), CAST(16, MSB(op_AND_65), DUP(op_AND_65)));
	RzILOpPure *ite_cast_ut64_68 = ITE(op_GT_67, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_72 = ADD(op_MUL_70, SN(32, 1));
	RzILOpPure *op_LSHIFT_73 = SHIFTL0(ite_cast_ut64_68, op_ADD_72);
	RzILOpPure *op_OR_74 = LOGOR(op_AND_52, op_LSHIFT_73);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_74));

	// seq(h_tmp66; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i *  ...;
	RzILOpEffect *seq_78 = SEQN(2, op_ASSIGN_41, op_ASSIGN_76);

	// seq(seq(h_tmp66; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_79 = SEQN(2, seq_78, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp66; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_80 = REPEAT(op_LT_4, seq_79);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp66; Pd = ((st8) (( ...;
	RzILOpEffect *seq_81 = SEQN(2, op_ASSIGN_2, for_80);

	RzILOpEffect *instruction_sequence = seq_81;
	return instruction_sequence;
}

// Pd = vcmph.gtu(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmphgtu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp67 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp67", VARL("i"));

	// seq(h_tmp67 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2))) | (((((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) > ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(UN(64, 1), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_17 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_14);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rss, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(Rtt, op_MUL_28);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_34 = UGT(CAST(16, IL_FALSE, op_AND_24), CAST(16, IL_FALSE, op_AND_32));
	RzILOpPure *ite_cast_ut64_35 = ITE(op_GT_34, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(ite_cast_ut64_35, op_MUL_37);
	RzILOpPure *op_OR_39 = LOGOR(op_AND_17, op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_39));

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2 + 0x1))) | (((((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) > ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_47 = ADD(op_MUL_45, SN(32, 1));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(UN(64, 1), op_ADD_47);
	RzILOpPure *op_NOT_49 = LOGNOT(op_LSHIFT_48);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_49);
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_61 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rtt), op_MUL_61);
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_62, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_67 = UGT(CAST(16, IL_FALSE, op_AND_58), CAST(16, IL_FALSE, op_AND_65));
	RzILOpPure *ite_cast_ut64_68 = ITE(op_GT_67, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_72 = ADD(op_MUL_70, SN(32, 1));
	RzILOpPure *op_LSHIFT_73 = SHIFTL0(ite_cast_ut64_68, op_ADD_72);
	RzILOpPure *op_OR_74 = LOGOR(op_AND_52, op_LSHIFT_73);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_74));

	// seq(h_tmp67; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i *  ...;
	RzILOpEffect *seq_78 = SEQN(2, op_ASSIGN_41, op_ASSIGN_76);

	// seq(seq(h_tmp67; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_79 = SEQN(2, seq_78, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp67; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_80 = REPEAT(op_LT_4, seq_79);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp67; Pd = ((st8) (( ...;
	RzILOpEffect *seq_81 = SEQN(2, op_ASSIGN_2, for_80);

	RzILOpEffect *instruction_sequence = seq_81;
	return instruction_sequence;
}

// Pd = vcmpw.eq(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmpweq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 j;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// j = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("j", SN(32, 0));

	// HYB(++j);
	RzILOpEffect *op_INC_5 = SETL("j", INC(VARL("j"), 32));

	// h_tmp68 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp68", VARL("j"));

	// seq(h_tmp68 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) == ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_31 = LOGAND(op_RSHIFT_29, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_34 = EQ(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(CAST(32, MSB(op_AND_31), DUP(op_AND_31))), CAST(32, MSB(DUP(op_AND_31)), DUP(op_AND_31))));
	RzILOpPure *ite_cast_ut64_35 = ITE(op_EQ_34, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(ite_cast_ut64_35, VARL("j"));
	RzILOpPure *op_OR_37 = LOGOR(op_AND_15, op_LSHIFT_36);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_37));

	// seq(h_tmp68; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) ...;
	RzILOpEffect *seq_41 = op_ASSIGN_39;

	// seq(seq(h_tmp68; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_41, seq_8);

	// while ((j <= 0x3)) { seq(seq(h_tmp68; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LE_4 = SLE(VARL("j"), SN(32, 3));
	RzILOpEffect *for_43 = REPEAT(op_LE_4, seq_42);

	// seq(j = 0x0; while ((j <= 0x3)) { seq(seq(h_tmp68; Pd = ((st8) ( ...;
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_2, for_43);

	// j = 0x4;
	RzILOpEffect *op_ASSIGN_47 = SETL("j", SN(32, 4));

	// HYB(++j);
	RzILOpEffect *op_INC_50 = SETL("j", INC(VARL("j"), 32));

	// h_tmp69 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_52 = SETL("h_tmp69", VARL("j"));

	// seq(h_tmp69 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_hybrid_tmp_52, op_INC_50);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) == ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_56 = LOGNOT(op_LSHIFT_55);
	RzILOpPure *op_AND_59 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_56);
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_63, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_73 = LOGAND(op_RSHIFT_71, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_76 = EQ(CAST(64, MSB(CAST(32, MSB(op_AND_65), DUP(op_AND_65))), CAST(32, MSB(DUP(op_AND_65)), DUP(op_AND_65))), CAST(64, MSB(CAST(32, MSB(op_AND_73), DUP(op_AND_73))), CAST(32, MSB(DUP(op_AND_73)), DUP(op_AND_73))));
	RzILOpPure *ite_cast_ut64_77 = ITE(op_EQ_76, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_78 = SHIFTL0(ite_cast_ut64_77, VARL("j"));
	RzILOpPure *op_OR_79 = LOGOR(op_AND_59, op_LSHIFT_78);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_79));

	// seq(h_tmp69; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) ...;
	RzILOpEffect *seq_83 = op_ASSIGN_81;

	// seq(seq(h_tmp69; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_84 = SEQN(2, seq_83, seq_53);

	// while ((j <= 0x7)) { seq(seq(h_tmp69; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LE_49 = SLE(VARL("j"), SN(32, 7));
	RzILOpEffect *for_85 = REPEAT(op_LE_49, seq_84);

	// seq(j = 0x4; while ((j <= 0x7)) { seq(seq(h_tmp69; Pd = ((st8) ( ...;
	RzILOpEffect *seq_86 = SEQN(2, op_ASSIGN_47, for_85);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_44, seq_86);
	return instruction_sequence;
}

// Pd = vcmpw.gt(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmpwgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 j;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// j = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("j", SN(32, 0));

	// HYB(++j);
	RzILOpEffect *op_INC_5 = SETL("j", INC(VARL("j"), 32));

	// h_tmp70 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp70", VARL("j"));

	// seq(h_tmp70 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) > ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_31 = LOGAND(op_RSHIFT_29, SN(64, 0xffffffff));
	RzILOpPure *op_GT_34 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(CAST(32, MSB(op_AND_31), DUP(op_AND_31))), CAST(32, MSB(DUP(op_AND_31)), DUP(op_AND_31))));
	RzILOpPure *ite_cast_ut64_35 = ITE(op_GT_34, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(ite_cast_ut64_35, VARL("j"));
	RzILOpPure *op_OR_37 = LOGOR(op_AND_15, op_LSHIFT_36);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_37));

	// seq(h_tmp70; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) ...;
	RzILOpEffect *seq_41 = op_ASSIGN_39;

	// seq(seq(h_tmp70; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_41, seq_8);

	// while ((j <= 0x3)) { seq(seq(h_tmp70; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LE_4 = SLE(VARL("j"), SN(32, 3));
	RzILOpEffect *for_43 = REPEAT(op_LE_4, seq_42);

	// seq(j = 0x0; while ((j <= 0x3)) { seq(seq(h_tmp70; Pd = ((st8) ( ...;
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_2, for_43);

	// j = 0x4;
	RzILOpEffect *op_ASSIGN_46 = SETL("j", SN(32, 4));

	// HYB(++j);
	RzILOpEffect *op_INC_49 = SETL("j", INC(VARL("j"), 32));

	// h_tmp71 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_51 = SETL("h_tmp71", VARL("j"));

	// seq(h_tmp71 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_hybrid_tmp_51, op_INC_49);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) > ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_55 = LOGNOT(op_LSHIFT_54);
	RzILOpPure *op_AND_58 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_55);
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_62, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_70, SN(64, 0xffffffff));
	RzILOpPure *op_GT_75 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_64), DUP(op_AND_64))), CAST(32, MSB(DUP(op_AND_64)), DUP(op_AND_64))), CAST(64, MSB(CAST(32, MSB(op_AND_72), DUP(op_AND_72))), CAST(32, MSB(DUP(op_AND_72)), DUP(op_AND_72))));
	RzILOpPure *ite_cast_ut64_76 = ITE(op_GT_75, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_77 = SHIFTL0(ite_cast_ut64_76, VARL("j"));
	RzILOpPure *op_OR_78 = LOGOR(op_AND_58, op_LSHIFT_77);
	RzILOpEffect *op_ASSIGN_80 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_78));

	// seq(h_tmp71; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) ...;
	RzILOpEffect *seq_82 = op_ASSIGN_80;

	// seq(seq(h_tmp71; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_83 = SEQN(2, seq_82, seq_52);

	// while ((j <= 0x7)) { seq(seq(h_tmp71; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LE_48 = SLE(VARL("j"), SN(32, 7));
	RzILOpEffect *for_84 = REPEAT(op_LE_48, seq_83);

	// seq(j = 0x4; while ((j <= 0x7)) { seq(seq(h_tmp71; Pd = ((st8) ( ...;
	RzILOpEffect *seq_85 = SEQN(2, op_ASSIGN_46, for_84);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_44, seq_85);
	return instruction_sequence;
}

// Pd = vcmpw.gtu(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vcmpwgtu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 j;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// j = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("j", SN(32, 0));

	// HYB(++j);
	RzILOpEffect *op_INC_5 = SETL("j", INC(VARL("j"), 32));

	// h_tmp72 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp72", VARL("j"));

	// seq(h_tmp72 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((ut64) ((ut32) ((Rss >> 0x0) & 0xffffffff))) > ((ut64) ((ut32) ((Rtt >> 0x0) & 0xffffffff)))) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_31 = LOGAND(op_RSHIFT_29, SN(64, 0xffffffff));
	RzILOpPure *op_GT_34 = UGT(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_22)), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_31)));
	RzILOpPure *ite_cast_ut64_35 = ITE(op_GT_34, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(ite_cast_ut64_35, VARL("j"));
	RzILOpPure *op_OR_37 = LOGOR(op_AND_15, op_LSHIFT_36);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_37));

	// seq(h_tmp72; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) ...;
	RzILOpEffect *seq_41 = op_ASSIGN_39;

	// seq(seq(h_tmp72; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_41, seq_8);

	// while ((j <= 0x3)) { seq(seq(h_tmp72; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LE_4 = SLE(VARL("j"), SN(32, 3));
	RzILOpEffect *for_43 = REPEAT(op_LE_4, seq_42);

	// seq(j = 0x0; while ((j <= 0x3)) { seq(seq(h_tmp72; Pd = ((st8) ( ...;
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_2, for_43);

	// j = 0x4;
	RzILOpEffect *op_ASSIGN_47 = SETL("j", SN(32, 4));

	// HYB(++j);
	RzILOpEffect *op_INC_50 = SETL("j", INC(VARL("j"), 32));

	// h_tmp73 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_52 = SETL("h_tmp73", VARL("j"));

	// seq(h_tmp73 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_hybrid_tmp_52, op_INC_50);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((ut64) ((ut32) ((Rss >> 0x20) & 0xffffffff))) > ((ut64) ((ut32) ((Rtt >> 0x20) & 0xffffffff)))) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_56 = LOGNOT(op_LSHIFT_55);
	RzILOpPure *op_AND_59 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_56);
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_63, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_73 = LOGAND(op_RSHIFT_71, SN(64, 0xffffffff));
	RzILOpPure *op_GT_76 = UGT(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_65)), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_73)));
	RzILOpPure *ite_cast_ut64_77 = ITE(op_GT_76, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_78 = SHIFTL0(ite_cast_ut64_77, VARL("j"));
	RzILOpPure *op_OR_79 = LOGOR(op_AND_59, op_LSHIFT_78);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_79));

	// seq(h_tmp73; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) ...;
	RzILOpEffect *seq_83 = op_ASSIGN_81;

	// seq(seq(h_tmp73; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ...;
	RzILOpEffect *seq_84 = SEQN(2, seq_83, seq_53);

	// while ((j <= 0x7)) { seq(seq(h_tmp73; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 <<  ... };
	RzILOpPure *op_LE_49 = SLE(VARL("j"), SN(32, 7));
	RzILOpEffect *for_85 = REPEAT(op_LE_49, seq_84);

	// seq(j = 0x4; while ((j <= 0x7)) { seq(seq(h_tmp73; Pd = ((st8) ( ...;
	RzILOpEffect *seq_86 = SEQN(2, op_ASSIGN_47, for_85);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_44, seq_86);
	return instruction_sequence;
}

// Rdd = vconj(Rss):sat
RzILOpEffect *hex_il_op_a2_vconj(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_51 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_21 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_36 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))));
	RzILOpPure *op_EQ_38 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_21), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_36), DUP(op_NEG_36)));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_61 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_58), DUP(op_AND_58))), CAST(16, MSB(DUP(op_AND_58)), DUP(op_AND_58))));
	RzILOpPure *op_LT_63 = SLT(op_NEG_61, SN(32, 0));
	RzILOpPure *op_LSHIFT_68 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_69 = NEG(op_LSHIFT_68);
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_77 = SUB(op_LSHIFT_74, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_78 = ITE(op_LT_63, op_NEG_69, op_SUB_77);
	RzILOpEffect *gcc_expr_79 = BRANCH(op_EQ_38, EMPTY(), set_usr_field_call_51);

	// h_tmp74 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_81 = SETL("h_tmp74", cond_78);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_82 = SEQN(2, gcc_expr_79, op_ASSIGN_hybrid_tmp_81);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))) : h_tmp74) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_48 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_45), DUP(op_AND_45))), CAST(16, MSB(DUP(op_AND_45)), DUP(op_AND_45))));
	RzILOpPure *cond_84 = ITE(DUP(op_EQ_38), CAST(64, MSB(op_NEG_48), DUP(op_NEG_48)), VARL("h_tmp74"));
	RzILOpPure *op_AND_87 = LOGAND(cond_84, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_92 = SHIFTL0(CAST(64, IL_FALSE, op_AND_87), SN(32, 16));
	RzILOpPure *op_OR_94 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_92);
	RzILOpEffect *op_ASSIGN_96 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_94));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_97 = SEQN(2, seq_82, op_ASSIGN_96);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_103 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_104 = LOGNOT(op_LSHIFT_103);
	RzILOpPure *op_AND_105 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_104);
	RzILOpPure *op_RSHIFT_109 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_112 = LOGAND(op_RSHIFT_109, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_116 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_112), DUP(op_AND_112))), CAST(16, MSB(DUP(op_AND_112)), DUP(op_AND_112))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(CAST(64, IL_FALSE, op_AND_116), SN(32, 0));
	RzILOpPure *op_OR_123 = LOGOR(CAST(64, IL_FALSE, op_AND_105), op_LSHIFT_121);
	RzILOpEffect *op_ASSIGN_125 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_123));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_176 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_140 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_143 = LOGAND(op_RSHIFT_140, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_146 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_143), DUP(op_AND_143))), CAST(16, MSB(DUP(op_AND_143)), DUP(op_AND_143))));
	RzILOpPure *op_RSHIFT_155 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_158 = LOGAND(op_RSHIFT_155, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_161 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_158), DUP(op_AND_158))), CAST(16, MSB(DUP(op_AND_158)), DUP(op_AND_158))));
	RzILOpPure *op_EQ_163 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_146), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_161), DUP(op_NEG_161)));
	RzILOpPure *op_RSHIFT_180 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_183 = LOGAND(op_RSHIFT_180, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_186 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_183), DUP(op_AND_183))), CAST(16, MSB(DUP(op_AND_183)), DUP(op_AND_183))));
	RzILOpPure *op_LT_188 = SLT(op_NEG_186, SN(32, 0));
	RzILOpPure *op_LSHIFT_193 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_194 = NEG(op_LSHIFT_193);
	RzILOpPure *op_LSHIFT_199 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_202 = SUB(op_LSHIFT_199, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_203 = ITE(op_LT_188, op_NEG_194, op_SUB_202);
	RzILOpEffect *gcc_expr_204 = BRANCH(op_EQ_163, EMPTY(), set_usr_field_call_176);

	// h_tmp75 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_206 = SETL("h_tmp75", cond_203);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_207 = SEQN(2, gcc_expr_204, op_ASSIGN_hybrid_tmp_206);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))) : h_tmp75) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_131 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_132 = LOGNOT(op_LSHIFT_131);
	RzILOpPure *op_AND_133 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_132);
	RzILOpPure *op_RSHIFT_167 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_170 = LOGAND(op_RSHIFT_167, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_173 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_170), DUP(op_AND_170))), CAST(16, MSB(DUP(op_AND_170)), DUP(op_AND_170))));
	RzILOpPure *cond_209 = ITE(DUP(op_EQ_163), CAST(64, MSB(op_NEG_173), DUP(op_NEG_173)), VARL("h_tmp75"));
	RzILOpPure *op_AND_212 = LOGAND(cond_209, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_217 = SHIFTL0(CAST(64, IL_FALSE, op_AND_212), SN(32, 0x30));
	RzILOpPure *op_OR_219 = LOGOR(CAST(64, IL_FALSE, op_AND_133), op_LSHIFT_217);
	RzILOpEffect *op_ASSIGN_221 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_219));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_222 = SEQN(2, seq_207, op_ASSIGN_221);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_228 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_229 = LOGNOT(op_LSHIFT_228);
	RzILOpPure *op_AND_230 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_229);
	RzILOpPure *op_RSHIFT_234 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_237 = LOGAND(op_RSHIFT_234, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_241 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_237), DUP(op_AND_237))), CAST(16, MSB(DUP(op_AND_237)), DUP(op_AND_237))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_246 = SHIFTL0(CAST(64, IL_FALSE, op_AND_241), SN(32, 0x20));
	RzILOpPure *op_OR_248 = LOGOR(CAST(64, IL_FALSE, op_AND_230), op_LSHIFT_246);
	RzILOpEffect *op_ASSIGN_250 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_248));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_97, op_ASSIGN_125, seq_222, op_ASSIGN_250);
	return instruction_sequence;
}

// Rdd = vmaxb(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vmaxb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp76 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp76", VARL("i"));

	// seq(h_tmp76 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((((st8) ((Rtt >> i * 0x8) & ((st64) 0xff))) > ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))) ? ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff))) : ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_32 = SGT(CAST(8, MSB(op_AND_22), DUP(op_AND_22)), CAST(8, MSB(op_AND_30), DUP(op_AND_30)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *cond_47 = ITE(op_GT_32, CAST(8, MSB(op_AND_38), DUP(op_AND_38)), CAST(8, MSB(op_AND_45), DUP(op_AND_45)));
	RzILOpPure *op_AND_51 = LOGAND(CAST(64, MSB(CAST(32, MSB(cond_47), DUP(cond_47))), CAST(32, MSB(DUP(cond_47)), DUP(cond_47))), SN(64, 0xff));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(CAST(64, IL_FALSE, op_AND_51), op_MUL_54);
	RzILOpPure *op_OR_57 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_55);
	RzILOpEffect *op_ASSIGN_59 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_57));

	// seq(h_tmp76; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_61 = op_ASSIGN_59;

	// seq(seq(h_tmp76; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_62 = SEQN(2, seq_61, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp76; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_63 = REPEAT(op_LT_4, seq_62);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp76; Rdd = ((st64)  ...;
	RzILOpEffect *seq_64 = SEQN(2, op_ASSIGN_2, for_63);

	RzILOpEffect *instruction_sequence = seq_64;
	return instruction_sequence;
}

// Rdd = vmaxh(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vmaxh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp77 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp77", VARL("i"));

	// seq(h_tmp77 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) > ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) ? ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) : ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_32 = SGT(CAST(16, MSB(op_AND_22), DUP(op_AND_22)), CAST(16, MSB(op_AND_30), DUP(op_AND_30)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_47 = ITE(op_GT_32, CAST(16, MSB(op_AND_38), DUP(op_AND_38)), CAST(16, MSB(op_AND_45), DUP(op_AND_45)));
	RzILOpPure *op_AND_50 = LOGAND(CAST(32, MSB(cond_47), DUP(cond_47)), SN(32, 0xffff));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(CAST(64, IL_FALSE, op_AND_50), op_MUL_53);
	RzILOpPure *op_OR_56 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_58 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_56));

	// seq(h_tmp77; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_60 = op_ASSIGN_58;

	// seq(seq(h_tmp77; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_61 = SEQN(2, seq_60, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp77; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_62 = REPEAT(op_LT_4, seq_61);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp77; Rdd = ((st64)  ...;
	RzILOpEffect *seq_63 = SEQN(2, op_ASSIGN_2, for_62);

	RzILOpEffect *instruction_sequence = seq_63;
	return instruction_sequence;
}

// Rdd = vmaxub(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vmaxub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp78 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp78", VARL("i"));

	// seq(h_tmp78 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) > ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) ? ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) : ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_32 = UGT(CAST(8, IL_FALSE, op_AND_22), CAST(8, IL_FALSE, op_AND_30));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *cond_47 = ITE(op_GT_32, CAST(8, IL_FALSE, op_AND_38), CAST(8, IL_FALSE, op_AND_45));
	RzILOpPure *op_AND_51 = LOGAND(CAST(64, MSB(CAST(32, IL_FALSE, cond_47)), CAST(32, IL_FALSE, DUP(cond_47))), SN(64, 0xff));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(CAST(64, IL_FALSE, op_AND_51), op_MUL_54);
	RzILOpPure *op_OR_57 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_55);
	RzILOpEffect *op_ASSIGN_59 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_57));

	// seq(h_tmp78; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_61 = op_ASSIGN_59;

	// seq(seq(h_tmp78; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_62 = SEQN(2, seq_61, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp78; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_63 = REPEAT(op_LT_4, seq_62);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp78; Rdd = ((st64)  ...;
	RzILOpEffect *seq_64 = SEQN(2, op_ASSIGN_2, for_63);

	RzILOpEffect *instruction_sequence = seq_64;
	return instruction_sequence;
}

// Rdd = vmaxuh(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vmaxuh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp79 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp79", VARL("i"));

	// seq(h_tmp79 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) > ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) ? ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) : ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_32 = UGT(CAST(16, IL_FALSE, op_AND_22), CAST(16, IL_FALSE, op_AND_30));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_47 = ITE(op_GT_32, CAST(16, IL_FALSE, op_AND_38), CAST(16, IL_FALSE, op_AND_45));
	RzILOpPure *op_AND_50 = LOGAND(CAST(32, IL_FALSE, cond_47), SN(32, 0xffff));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(CAST(64, IL_FALSE, op_AND_50), op_MUL_53);
	RzILOpPure *op_OR_56 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_58 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_56));

	// seq(h_tmp79; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_60 = op_ASSIGN_58;

	// seq(seq(h_tmp79; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_61 = SEQN(2, seq_60, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp79; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_62 = REPEAT(op_LT_4, seq_61);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp79; Rdd = ((st64)  ...;
	RzILOpEffect *seq_63 = SEQN(2, op_ASSIGN_2, for_62);

	RzILOpEffect *instruction_sequence = seq_63;
	return instruction_sequence;
}

// Rdd = vmaxuw(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vmaxuw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp80 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp80", VARL("i"));

	// seq(h_tmp80 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | ((((((ut64) ((ut32) ((Rtt >> i * 0x20) & 0xffffffff))) > ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((ut64) ((ut32) ((Rtt >> i * 0x20) & 0xffffffff))) : ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff)))) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_GT_32 = UGT(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_21)), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_29)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpPure *cond_47 = ITE(op_GT_32, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_37)), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_44)));
	RzILOpPure *op_AND_50 = LOGAND(cond_47, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(op_AND_50, op_MUL_52);
	RzILOpPure *op_OR_55 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_57 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_55));

	// seq(h_tmp80; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i *  ...;
	RzILOpEffect *seq_59 = op_ASSIGN_57;

	// seq(seq(h_tmp80; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ...;
	RzILOpEffect *seq_60 = SEQN(2, seq_59, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp80; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_61 = REPEAT(op_LT_4, seq_60);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp80; Rdd = ((st64)  ...;
	RzILOpEffect *seq_62 = SEQN(2, op_ASSIGN_2, for_61);

	RzILOpEffect *instruction_sequence = seq_62;
	return instruction_sequence;
}

// Rdd = vmaxw(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vmaxw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp81 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp81", VARL("i"));

	// seq(h_tmp81 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) > ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_GT_32 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpPure *cond_47 = ITE(op_GT_32, CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(64, MSB(CAST(32, MSB(op_AND_44), DUP(op_AND_44))), CAST(32, MSB(DUP(op_AND_44)), DUP(op_AND_44))));
	RzILOpPure *op_AND_49 = LOGAND(cond_47, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(op_AND_49, op_MUL_51);
	RzILOpPure *op_OR_53 = LOGOR(op_AND_15, op_LSHIFT_52);
	RzILOpEffect *op_ASSIGN_54 = WRITE_REG(bundle, Rdd_op, op_OR_53);

	// seq(h_tmp81; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((((( ...;
	RzILOpEffect *seq_56 = op_ASSIGN_54;

	// seq(seq(h_tmp81; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_57 = SEQN(2, seq_56, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp81; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_58 = REPEAT(op_LT_4, seq_57);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp81; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_59 = SEQN(2, op_ASSIGN_2, for_58);

	RzILOpEffect *instruction_sequence = seq_59;
	return instruction_sequence;
}

// Rdd = vminb(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vminb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp82 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp82", VARL("i"));

	// seq(h_tmp82 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((((st8) ((Rtt >> i * 0x8) & ((st64) 0xff))) < ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))) ? ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff))) : ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_LT_32 = SLT(CAST(8, MSB(op_AND_22), DUP(op_AND_22)), CAST(8, MSB(op_AND_30), DUP(op_AND_30)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *cond_47 = ITE(op_LT_32, CAST(8, MSB(op_AND_38), DUP(op_AND_38)), CAST(8, MSB(op_AND_45), DUP(op_AND_45)));
	RzILOpPure *op_AND_51 = LOGAND(CAST(64, MSB(CAST(32, MSB(cond_47), DUP(cond_47))), CAST(32, MSB(DUP(cond_47)), DUP(cond_47))), SN(64, 0xff));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(CAST(64, IL_FALSE, op_AND_51), op_MUL_54);
	RzILOpPure *op_OR_57 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_55);
	RzILOpEffect *op_ASSIGN_59 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_57));

	// seq(h_tmp82; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_61 = op_ASSIGN_59;

	// seq(seq(h_tmp82; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_62 = SEQN(2, seq_61, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp82; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_63 = REPEAT(op_LT_4, seq_62);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp82; Rdd = ((st64)  ...;
	RzILOpEffect *seq_64 = SEQN(2, op_ASSIGN_2, for_63);

	RzILOpEffect *instruction_sequence = seq_64;
	return instruction_sequence;
}

// Rdd = vminh(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vminh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp83 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp83", VARL("i"));

	// seq(h_tmp83 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) < ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) ? ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) : ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_32 = SLT(CAST(16, MSB(op_AND_22), DUP(op_AND_22)), CAST(16, MSB(op_AND_30), DUP(op_AND_30)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_47 = ITE(op_LT_32, CAST(16, MSB(op_AND_38), DUP(op_AND_38)), CAST(16, MSB(op_AND_45), DUP(op_AND_45)));
	RzILOpPure *op_AND_50 = LOGAND(CAST(32, MSB(cond_47), DUP(cond_47)), SN(32, 0xffff));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(CAST(64, IL_FALSE, op_AND_50), op_MUL_53);
	RzILOpPure *op_OR_56 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_58 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_56));

	// seq(h_tmp83; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_60 = op_ASSIGN_58;

	// seq(seq(h_tmp83; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_61 = SEQN(2, seq_60, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp83; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_62 = REPEAT(op_LT_4, seq_61);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp83; Rdd = ((st64)  ...;
	RzILOpEffect *seq_63 = SEQN(2, op_ASSIGN_2, for_62);

	RzILOpEffect *instruction_sequence = seq_63;
	return instruction_sequence;
}

// Rdd = vminub(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vminub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp84 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp84", VARL("i"));

	// seq(h_tmp84 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) < ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) ? ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) : ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_LT_32 = ULT(CAST(8, IL_FALSE, op_AND_22), CAST(8, IL_FALSE, op_AND_30));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *cond_47 = ITE(op_LT_32, CAST(8, IL_FALSE, op_AND_38), CAST(8, IL_FALSE, op_AND_45));
	RzILOpPure *op_AND_51 = LOGAND(CAST(64, MSB(CAST(32, IL_FALSE, cond_47)), CAST(32, IL_FALSE, DUP(cond_47))), SN(64, 0xff));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(CAST(64, IL_FALSE, op_AND_51), op_MUL_54);
	RzILOpPure *op_OR_57 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_55);
	RzILOpEffect *op_ASSIGN_59 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_57));

	// seq(h_tmp84; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8))) ...;
	RzILOpEffect *seq_61 = op_ASSIGN_59;

	// seq(seq(h_tmp84; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ...;
	RzILOpEffect *seq_62 = SEQN(2, seq_61, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp84; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_63 = REPEAT(op_LT_4, seq_62);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp84; Rdd = ((st64)  ...;
	RzILOpEffect *seq_64 = SEQN(2, op_ASSIGN_2, for_63);

	RzILOpEffect *instruction_sequence = seq_64;
	return instruction_sequence;
}

// Rdd = vminuh(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vminuh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp85 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp85", VARL("i"));

	// seq(h_tmp85 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) < ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) ? ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff))) : ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_32 = ULT(CAST(16, IL_FALSE, op_AND_22), CAST(16, IL_FALSE, op_AND_30));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_42, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_47 = ITE(op_LT_32, CAST(16, IL_FALSE, op_AND_38), CAST(16, IL_FALSE, op_AND_45));
	RzILOpPure *op_AND_50 = LOGAND(CAST(32, IL_FALSE, cond_47), SN(32, 0xffff));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(CAST(64, IL_FALSE, op_AND_50), op_MUL_53);
	RzILOpPure *op_OR_56 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_58 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_56));

	// seq(h_tmp85; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_60 = op_ASSIGN_58;

	// seq(seq(h_tmp85; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_61 = SEQN(2, seq_60, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp85; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_62 = REPEAT(op_LT_4, seq_61);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp85; Rdd = ((st64)  ...;
	RzILOpEffect *seq_63 = SEQN(2, op_ASSIGN_2, for_62);

	RzILOpEffect *instruction_sequence = seq_63;
	return instruction_sequence;
}

// Rdd = vminuw(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vminuw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp86 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp86", VARL("i"));

	// seq(h_tmp86 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | ((((((ut64) ((ut32) ((Rtt >> i * 0x20) & 0xffffffff))) < ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((ut64) ((ut32) ((Rtt >> i * 0x20) & 0xffffffff))) : ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff)))) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_LT_32 = ULT(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_21)), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_29)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpPure *cond_47 = ITE(op_LT_32, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_37)), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_44)));
	RzILOpPure *op_AND_50 = LOGAND(cond_47, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(op_AND_50, op_MUL_52);
	RzILOpPure *op_OR_55 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_57 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_55));

	// seq(h_tmp86; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i *  ...;
	RzILOpEffect *seq_59 = op_ASSIGN_57;

	// seq(seq(h_tmp86; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ...;
	RzILOpEffect *seq_60 = SEQN(2, seq_59, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp86; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff <<  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_61 = REPEAT(op_LT_4, seq_60);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp86; Rdd = ((st64)  ...;
	RzILOpEffect *seq_62 = SEQN(2, op_ASSIGN_2, for_61);

	RzILOpEffect *instruction_sequence = seq_62;
	return instruction_sequence;
}

// Rdd = vminw(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vminw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp87 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp87", VARL("i"));

	// seq(h_tmp87 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) < ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) : ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_LT_32 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rtt), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpPure *cond_47 = ITE(op_LT_32, CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(64, MSB(CAST(32, MSB(op_AND_44), DUP(op_AND_44))), CAST(32, MSB(DUP(op_AND_44)), DUP(op_AND_44))));
	RzILOpPure *op_AND_49 = LOGAND(cond_47, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(op_AND_49, op_MUL_51);
	RzILOpPure *op_OR_53 = LOGOR(op_AND_15, op_LSHIFT_52);
	RzILOpEffect *op_ASSIGN_54 = WRITE_REG(bundle, Rdd_op, op_OR_53);

	// seq(h_tmp87; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((((( ...;
	RzILOpEffect *seq_56 = op_ASSIGN_54;

	// seq(seq(h_tmp87; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_57 = SEQN(2, seq_56, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp87; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_58 = REPEAT(op_LT_4, seq_57);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp87; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_59 = SEQN(2, op_ASSIGN_2, for_58);

	RzILOpEffect *instruction_sequence = seq_59;
	return instruction_sequence;
}

// Rdd = vnavgh(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vnavgh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp88 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp88", VARL("i"));

	// seq(h_tmp88 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_34 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(op_SUB_34, SN(32, 1));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_44));

	// seq(h_tmp88; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10 ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp88; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp88; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i *  ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_50 = REPEAT(op_LT_4, seq_49);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp88; Rdd = ((st64)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_2, for_50);

	RzILOpEffect *instruction_sequence = seq_51;
	return instruction_sequence;
}

// Rdd = vnavgh(Rtt,Rss):crnd:sat
RzILOpEffect *hex_il_op_a2_vnavghcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp89 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp89", VARL("i"));

	// seq(h_tmp89 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_210 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1)), 0x0, 0x10) == ((st64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rss, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_37 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))));
	RzILOpPure *op_AND_39 = LOGAND(op_SUB_37, SN(32, 3));
	RzILOpPure *op_EQ_41 = EQ(op_AND_39, SN(32, 3));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rtt), op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_50 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_51 = SHIFTRA(DUP(Rss), op_MUL_50);
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_51, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_58 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))), CAST(32, MSB(CAST(16, MSB(op_AND_54), DUP(op_AND_54))), CAST(16, MSB(DUP(op_AND_54)), DUP(op_AND_54))));
	RzILOpPure *op_ADD_60 = ADD(op_SUB_58, SN(32, 1));
	RzILOpPure *op_MUL_62 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rtt), op_MUL_62);
	RzILOpPure *op_AND_66 = LOGAND(op_RSHIFT_63, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_69 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rss), op_MUL_69);
	RzILOpPure *op_AND_73 = LOGAND(op_RSHIFT_70, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_77 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_66), DUP(op_AND_66))), CAST(16, MSB(DUP(op_AND_66)), DUP(op_AND_66))), CAST(32, MSB(CAST(16, MSB(op_AND_73), DUP(op_AND_73))), CAST(16, MSB(DUP(op_AND_73)), DUP(op_AND_73))));
	RzILOpPure *cond_78 = ITE(op_EQ_41, op_ADD_60, op_SUB_77);
	RzILOpPure *op_RSHIFT_80 = SHIFTRA(cond_78, SN(32, 1));
	RzILOpPure *op_MUL_87 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_88 = SHIFTRA(DUP(Rtt), op_MUL_87);
	RzILOpPure *op_AND_91 = LOGAND(op_RSHIFT_88, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_94 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_95 = SHIFTRA(DUP(Rss), op_MUL_94);
	RzILOpPure *op_AND_98 = LOGAND(op_RSHIFT_95, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_102 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_91), DUP(op_AND_91))), CAST(16, MSB(DUP(op_AND_91)), DUP(op_AND_91))), CAST(32, MSB(CAST(16, MSB(op_AND_98), DUP(op_AND_98))), CAST(16, MSB(DUP(op_AND_98)), DUP(op_AND_98))));
	RzILOpPure *op_AND_104 = LOGAND(op_SUB_102, SN(32, 3));
	RzILOpPure *op_EQ_106 = EQ(op_AND_104, SN(32, 3));
	RzILOpPure *op_MUL_108 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_109 = SHIFTRA(DUP(Rtt), op_MUL_108);
	RzILOpPure *op_AND_112 = LOGAND(op_RSHIFT_109, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_115 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_116 = SHIFTRA(DUP(Rss), op_MUL_115);
	RzILOpPure *op_AND_119 = LOGAND(op_RSHIFT_116, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_123 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_112), DUP(op_AND_112))), CAST(16, MSB(DUP(op_AND_112)), DUP(op_AND_112))), CAST(32, MSB(CAST(16, MSB(op_AND_119), DUP(op_AND_119))), CAST(16, MSB(DUP(op_AND_119)), DUP(op_AND_119))));
	RzILOpPure *op_ADD_125 = ADD(op_SUB_123, SN(32, 1));
	RzILOpPure *op_MUL_127 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_128 = SHIFTRA(DUP(Rtt), op_MUL_127);
	RzILOpPure *op_AND_131 = LOGAND(op_RSHIFT_128, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_134 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_135 = SHIFTRA(DUP(Rss), op_MUL_134);
	RzILOpPure *op_AND_138 = LOGAND(op_RSHIFT_135, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_142 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_131), DUP(op_AND_131))), CAST(16, MSB(DUP(op_AND_131)), DUP(op_AND_131))), CAST(32, MSB(CAST(16, MSB(op_AND_138), DUP(op_AND_138))), CAST(16, MSB(DUP(op_AND_138)), DUP(op_AND_138))));
	RzILOpPure *cond_143 = ITE(op_EQ_106, op_ADD_125, op_SUB_142);
	RzILOpPure *op_RSHIFT_145 = SHIFTRA(cond_143, SN(32, 1));
	RzILOpPure *op_EQ_147 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_80), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_145), DUP(op_RSHIFT_145)));
	RzILOpPure *op_MUL_212 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_213 = SHIFTRA(DUP(Rtt), op_MUL_212);
	RzILOpPure *op_AND_216 = LOGAND(op_RSHIFT_213, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_219 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_220 = SHIFTRA(DUP(Rss), op_MUL_219);
	RzILOpPure *op_AND_223 = LOGAND(op_RSHIFT_220, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_227 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_216), DUP(op_AND_216))), CAST(16, MSB(DUP(op_AND_216)), DUP(op_AND_216))), CAST(32, MSB(CAST(16, MSB(op_AND_223), DUP(op_AND_223))), CAST(16, MSB(DUP(op_AND_223)), DUP(op_AND_223))));
	RzILOpPure *op_AND_229 = LOGAND(op_SUB_227, SN(32, 3));
	RzILOpPure *op_EQ_231 = EQ(op_AND_229, SN(32, 3));
	RzILOpPure *op_MUL_233 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_234 = SHIFTRA(DUP(Rtt), op_MUL_233);
	RzILOpPure *op_AND_237 = LOGAND(op_RSHIFT_234, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_240 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_241 = SHIFTRA(DUP(Rss), op_MUL_240);
	RzILOpPure *op_AND_244 = LOGAND(op_RSHIFT_241, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_248 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_237), DUP(op_AND_237))), CAST(16, MSB(DUP(op_AND_237)), DUP(op_AND_237))), CAST(32, MSB(CAST(16, MSB(op_AND_244), DUP(op_AND_244))), CAST(16, MSB(DUP(op_AND_244)), DUP(op_AND_244))));
	RzILOpPure *op_ADD_250 = ADD(op_SUB_248, SN(32, 1));
	RzILOpPure *op_MUL_252 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_253 = SHIFTRA(DUP(Rtt), op_MUL_252);
	RzILOpPure *op_AND_256 = LOGAND(op_RSHIFT_253, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_259 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_260 = SHIFTRA(DUP(Rss), op_MUL_259);
	RzILOpPure *op_AND_263 = LOGAND(op_RSHIFT_260, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_267 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_256), DUP(op_AND_256))), CAST(16, MSB(DUP(op_AND_256)), DUP(op_AND_256))), CAST(32, MSB(CAST(16, MSB(op_AND_263), DUP(op_AND_263))), CAST(16, MSB(DUP(op_AND_263)), DUP(op_AND_263))));
	RzILOpPure *cond_268 = ITE(op_EQ_231, op_ADD_250, op_SUB_267);
	RzILOpPure *op_RSHIFT_270 = SHIFTRA(cond_268, SN(32, 1));
	RzILOpPure *op_LT_272 = SLT(op_RSHIFT_270, SN(32, 0));
	RzILOpPure *op_LSHIFT_277 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_278 = NEG(op_LSHIFT_277);
	RzILOpPure *op_LSHIFT_283 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_286 = SUB(op_LSHIFT_283, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_287 = ITE(op_LT_272, op_NEG_278, op_SUB_286);
	RzILOpEffect *gcc_expr_288 = BRANCH(op_EQ_147, EMPTY(), set_usr_field_call_210);

	// h_tmp90 = HYB(gcc_expr_if ((sextract64(((ut64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1)), 0x0, 0x10) == ((st64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_290 = SETL("h_tmp90", cond_287);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((((st32) ((st16) ((R ...;
	RzILOpEffect *seq_291 = SEQN(2, gcc_expr_288, op_ASSIGN_hybrid_tmp_290);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1)), 0x0, 0x10) == ((st64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1))) ? ((st64) ((((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0x3) == 0x3) ? ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 : ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) >> 0x1)) : h_tmp90) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_149 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_150 = SHIFTRA(DUP(Rtt), op_MUL_149);
	RzILOpPure *op_AND_153 = LOGAND(op_RSHIFT_150, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_156 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rss), op_MUL_156);
	RzILOpPure *op_AND_160 = LOGAND(op_RSHIFT_157, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_164 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_153), DUP(op_AND_153))), CAST(16, MSB(DUP(op_AND_153)), DUP(op_AND_153))), CAST(32, MSB(CAST(16, MSB(op_AND_160), DUP(op_AND_160))), CAST(16, MSB(DUP(op_AND_160)), DUP(op_AND_160))));
	RzILOpPure *op_AND_166 = LOGAND(op_SUB_164, SN(32, 3));
	RzILOpPure *op_EQ_168 = EQ(op_AND_166, SN(32, 3));
	RzILOpPure *op_MUL_170 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_171 = SHIFTRA(DUP(Rtt), op_MUL_170);
	RzILOpPure *op_AND_174 = LOGAND(op_RSHIFT_171, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_177 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_178 = SHIFTRA(DUP(Rss), op_MUL_177);
	RzILOpPure *op_AND_181 = LOGAND(op_RSHIFT_178, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_185 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_174), DUP(op_AND_174))), CAST(16, MSB(DUP(op_AND_174)), DUP(op_AND_174))), CAST(32, MSB(CAST(16, MSB(op_AND_181), DUP(op_AND_181))), CAST(16, MSB(DUP(op_AND_181)), DUP(op_AND_181))));
	RzILOpPure *op_ADD_187 = ADD(op_SUB_185, SN(32, 1));
	RzILOpPure *op_MUL_189 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_190 = SHIFTRA(DUP(Rtt), op_MUL_189);
	RzILOpPure *op_AND_193 = LOGAND(op_RSHIFT_190, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_196 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_197 = SHIFTRA(DUP(Rss), op_MUL_196);
	RzILOpPure *op_AND_200 = LOGAND(op_RSHIFT_197, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_204 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_193), DUP(op_AND_193))), CAST(16, MSB(DUP(op_AND_193)), DUP(op_AND_193))), CAST(32, MSB(CAST(16, MSB(op_AND_200), DUP(op_AND_200))), CAST(16, MSB(DUP(op_AND_200)), DUP(op_AND_200))));
	RzILOpPure *cond_205 = ITE(op_EQ_168, op_ADD_187, op_SUB_204);
	RzILOpPure *op_RSHIFT_207 = SHIFTRA(cond_205, SN(32, 1));
	RzILOpPure *cond_293 = ITE(DUP(op_EQ_147), CAST(64, MSB(op_RSHIFT_207), DUP(op_RSHIFT_207)), VARL("h_tmp90"));
	RzILOpPure *op_AND_296 = LOGAND(cond_293, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_299 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_300 = SHIFTL0(CAST(64, IL_FALSE, op_AND_296), op_MUL_299);
	RzILOpPure *op_OR_302 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_300);
	RzILOpEffect *op_ASSIGN_304 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_302));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((((st32) ((st16) ...;
	RzILOpEffect *seq_305 = SEQN(2, seq_291, op_ASSIGN_304);

	// seq(h_tmp89; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((((( ...;
	RzILOpEffect *seq_307 = seq_305;

	// seq(seq(h_tmp89; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_308 = SEQN(2, seq_307, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp89; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_309 = REPEAT(op_LT_4, seq_308);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp89; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_310 = SEQN(2, op_ASSIGN_2, for_309);

	RzILOpEffect *instruction_sequence = seq_310;
	return instruction_sequence;
}

// Rdd = vnavgh(Rtt,Rss):rnd:sat
RzILOpEffect *hex_il_op_a2_vnavghr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp91 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp91", VARL("i"));

	// seq(h_tmp91 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_93 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rss, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_37 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))));
	RzILOpPure *op_ADD_39 = ADD(op_SUB_37, SN(32, 1));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(op_ADD_39, SN(32, 1));
	RzILOpPure *op_MUL_48 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_49 = SHIFTRA(DUP(Rtt), op_MUL_48);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_49, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_55 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(DUP(Rss), op_MUL_55);
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_56, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_63 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_52), DUP(op_AND_52))), CAST(16, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(32, MSB(CAST(16, MSB(op_AND_59), DUP(op_AND_59))), CAST(16, MSB(DUP(op_AND_59)), DUP(op_AND_59))));
	RzILOpPure *op_ADD_65 = ADD(op_SUB_63, SN(32, 1));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(op_ADD_65, SN(32, 1));
	RzILOpPure *op_EQ_69 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_41), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_67), DUP(op_RSHIFT_67)));
	RzILOpPure *op_MUL_95 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_96 = SHIFTRA(DUP(Rtt), op_MUL_95);
	RzILOpPure *op_AND_99 = LOGAND(op_RSHIFT_96, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_102 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_103 = SHIFTRA(DUP(Rss), op_MUL_102);
	RzILOpPure *op_AND_106 = LOGAND(op_RSHIFT_103, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_110 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_99), DUP(op_AND_99))), CAST(16, MSB(DUP(op_AND_99)), DUP(op_AND_99))), CAST(32, MSB(CAST(16, MSB(op_AND_106), DUP(op_AND_106))), CAST(16, MSB(DUP(op_AND_106)), DUP(op_AND_106))));
	RzILOpPure *op_ADD_112 = ADD(op_SUB_110, SN(32, 1));
	RzILOpPure *op_RSHIFT_114 = SHIFTRA(op_ADD_112, SN(32, 1));
	RzILOpPure *op_LT_116 = SLT(op_RSHIFT_114, SN(32, 0));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_122 = NEG(op_LSHIFT_121);
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_130 = SUB(op_LSHIFT_127, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_131 = ITE(op_LT_116, op_NEG_122, op_SUB_130);
	RzILOpEffect *gcc_expr_132 = BRANCH(op_EQ_69, EMPTY(), set_usr_field_call_93);

	// h_tmp92 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_134 = SETL("h_tmp92", cond_131);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rtt  ...;
	RzILOpEffect *seq_135 = SEQN(2, gcc_expr_132, op_ASSIGN_hybrid_tmp_134);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp92) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_71 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rtt), op_MUL_71);
	RzILOpPure *op_AND_75 = LOGAND(op_RSHIFT_72, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_79 = SHIFTRA(DUP(Rss), op_MUL_78);
	RzILOpPure *op_AND_82 = LOGAND(op_RSHIFT_79, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_86 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_75), DUP(op_AND_75))), CAST(16, MSB(DUP(op_AND_75)), DUP(op_AND_75))), CAST(32, MSB(CAST(16, MSB(op_AND_82), DUP(op_AND_82))), CAST(16, MSB(DUP(op_AND_82)), DUP(op_AND_82))));
	RzILOpPure *op_ADD_88 = ADD(op_SUB_86, SN(32, 1));
	RzILOpPure *op_RSHIFT_90 = SHIFTRA(op_ADD_88, SN(32, 1));
	RzILOpPure *cond_137 = ITE(DUP(op_EQ_69), CAST(64, MSB(op_RSHIFT_90), DUP(op_RSHIFT_90)), VARL("h_tmp92"));
	RzILOpPure *op_AND_140 = LOGAND(cond_137, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_143 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_144 = SHIFTL0(CAST(64, IL_FALSE, op_AND_140), op_MUL_143);
	RzILOpPure *op_OR_146 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_144);
	RzILOpEffect *op_ASSIGN_148 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_146));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_149 = SEQN(2, seq_135, op_ASSIGN_148);

	// seq(h_tmp91; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st3 ...;
	RzILOpEffect *seq_151 = seq_149;

	// seq(seq(h_tmp91; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_152 = SEQN(2, seq_151, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp91; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_153 = REPEAT(op_LT_4, seq_152);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp91; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_154 = SEQN(2, op_ASSIGN_2, for_153);

	RzILOpEffect *instruction_sequence = seq_154;
	return instruction_sequence;
}

// Rdd = vnavgw(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vnavgw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp93 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp93", VARL("i"));

	// seq(h_tmp93 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) >> 0x1) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(Rss, op_MUL_37);
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_48 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(op_SUB_48, SN(32, 1));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(op_AND_52, op_MUL_54);
	RzILOpPure *op_OR_56 = LOGOR(op_AND_15, op_LSHIFT_55);
	RzILOpEffect *op_ASSIGN_57 = WRITE_REG(bundle, Rdd_op, op_OR_56);

	// seq(h_tmp93; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((sex ...;
	RzILOpEffect *seq_59 = op_ASSIGN_57;

	// seq(seq(h_tmp93; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ...;
	RzILOpEffect *seq_60 = SEQN(2, seq_59, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp93; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_61 = REPEAT(op_LT_4, seq_60);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp93; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_62 = SEQN(2, op_ASSIGN_2, for_61);

	RzILOpEffect *instruction_sequence = seq_62;
	return instruction_sequence;
}

// Rdd = vnavgw(Rtt,Rss):crnd:sat
RzILOpEffect *hex_il_op_a2_vnavgwcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp94 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp94", VARL("i"));

	// seq(h_tmp94 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_344 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1)), 0x0, 0x20) == ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_25 = SHIFTRA(Rtt, op_MUL_24);
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_25, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(Rss, op_MUL_40);
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_41, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_51 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_27), DUP(op_AND_27))), CAST(32, MSB(DUP(op_AND_27)), DUP(op_AND_27)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_43), DUP(op_AND_43))), CAST(32, MSB(DUP(op_AND_43)), DUP(op_AND_43)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_AND_54 = LOGAND(op_SUB_51, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_EQ_57 = EQ(op_AND_54, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_MUL_62 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rtt), op_MUL_62);
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_63, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_77 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_78 = SHIFTRA(DUP(Rss), op_MUL_77);
	RzILOpPure *op_AND_80 = LOGAND(op_RSHIFT_78, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_88 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_65), DUP(op_AND_65))), CAST(32, MSB(DUP(op_AND_65)), DUP(op_AND_65)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_80), DUP(op_AND_80))), CAST(32, MSB(DUP(op_AND_80)), DUP(op_AND_80)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_91 = ADD(op_SUB_88, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_MUL_96 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_97 = SHIFTRA(DUP(Rtt), op_MUL_96);
	RzILOpPure *op_AND_99 = LOGAND(op_RSHIFT_97, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_111 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_112 = SHIFTRA(DUP(Rss), op_MUL_111);
	RzILOpPure *op_AND_114 = LOGAND(op_RSHIFT_112, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_122 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_99), DUP(op_AND_99))), CAST(32, MSB(DUP(op_AND_99)), DUP(op_AND_99)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_114), DUP(op_AND_114))), CAST(32, MSB(DUP(op_AND_114)), DUP(op_AND_114)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *cond_123 = ITE(op_EQ_57, op_ADD_91, op_SUB_122);
	RzILOpPure *op_RSHIFT_125 = SHIFTRA(cond_123, SN(32, 1));
	RzILOpPure *op_MUL_135 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_136 = SHIFTRA(DUP(Rtt), op_MUL_135);
	RzILOpPure *op_AND_138 = LOGAND(op_RSHIFT_136, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_150 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_151 = SHIFTRA(DUP(Rss), op_MUL_150);
	RzILOpPure *op_AND_153 = LOGAND(op_RSHIFT_151, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_161 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_138), DUP(op_AND_138))), CAST(32, MSB(DUP(op_AND_138)), DUP(op_AND_138)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_153), DUP(op_AND_153))), CAST(32, MSB(DUP(op_AND_153)), DUP(op_AND_153)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_AND_164 = LOGAND(op_SUB_161, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_EQ_167 = EQ(op_AND_164, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_MUL_172 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_173 = SHIFTRA(DUP(Rtt), op_MUL_172);
	RzILOpPure *op_AND_175 = LOGAND(op_RSHIFT_173, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_187 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_188 = SHIFTRA(DUP(Rss), op_MUL_187);
	RzILOpPure *op_AND_190 = LOGAND(op_RSHIFT_188, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_198 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_175), DUP(op_AND_175))), CAST(32, MSB(DUP(op_AND_175)), DUP(op_AND_175)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_190), DUP(op_AND_190))), CAST(32, MSB(DUP(op_AND_190)), DUP(op_AND_190)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_201 = ADD(op_SUB_198, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_MUL_206 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_207 = SHIFTRA(DUP(Rtt), op_MUL_206);
	RzILOpPure *op_AND_209 = LOGAND(op_RSHIFT_207, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_221 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_222 = SHIFTRA(DUP(Rss), op_MUL_221);
	RzILOpPure *op_AND_224 = LOGAND(op_RSHIFT_222, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_232 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_209), DUP(op_AND_209))), CAST(32, MSB(DUP(op_AND_209)), DUP(op_AND_209)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_224), DUP(op_AND_224))), CAST(32, MSB(DUP(op_AND_224)), DUP(op_AND_224)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *cond_233 = ITE(op_EQ_167, op_ADD_201, op_SUB_232);
	RzILOpPure *op_RSHIFT_235 = SHIFTRA(cond_233, SN(32, 1));
	RzILOpPure *op_EQ_236 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_125), SN(32, 0), SN(32, 0x20)), op_RSHIFT_235);
	RzILOpPure *op_MUL_349 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_350 = SHIFTRA(DUP(Rtt), op_MUL_349);
	RzILOpPure *op_AND_352 = LOGAND(op_RSHIFT_350, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_364 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_365 = SHIFTRA(DUP(Rss), op_MUL_364);
	RzILOpPure *op_AND_367 = LOGAND(op_RSHIFT_365, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_375 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_352), DUP(op_AND_352))), CAST(32, MSB(DUP(op_AND_352)), DUP(op_AND_352)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_367), DUP(op_AND_367))), CAST(32, MSB(DUP(op_AND_367)), DUP(op_AND_367)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_AND_378 = LOGAND(op_SUB_375, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_EQ_381 = EQ(op_AND_378, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_MUL_386 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_387 = SHIFTRA(DUP(Rtt), op_MUL_386);
	RzILOpPure *op_AND_389 = LOGAND(op_RSHIFT_387, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_401 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_402 = SHIFTRA(DUP(Rss), op_MUL_401);
	RzILOpPure *op_AND_404 = LOGAND(op_RSHIFT_402, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_412 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_389), DUP(op_AND_389))), CAST(32, MSB(DUP(op_AND_389)), DUP(op_AND_389)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_404), DUP(op_AND_404))), CAST(32, MSB(DUP(op_AND_404)), DUP(op_AND_404)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_415 = ADD(op_SUB_412, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_MUL_420 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_421 = SHIFTRA(DUP(Rtt), op_MUL_420);
	RzILOpPure *op_AND_423 = LOGAND(op_RSHIFT_421, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_435 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_436 = SHIFTRA(DUP(Rss), op_MUL_435);
	RzILOpPure *op_AND_438 = LOGAND(op_RSHIFT_436, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_446 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_423), DUP(op_AND_423))), CAST(32, MSB(DUP(op_AND_423)), DUP(op_AND_423)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_438), DUP(op_AND_438))), CAST(32, MSB(DUP(op_AND_438)), DUP(op_AND_438)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *cond_447 = ITE(op_EQ_381, op_ADD_415, op_SUB_446);
	RzILOpPure *op_RSHIFT_449 = SHIFTRA(cond_447, SN(32, 1));
	RzILOpPure *op_LT_452 = SLT(op_RSHIFT_449, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_457 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_458 = NEG(op_LSHIFT_457);
	RzILOpPure *op_LSHIFT_463 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_466 = SUB(op_LSHIFT_463, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_467 = ITE(op_LT_452, op_NEG_458, op_SUB_466);
	RzILOpEffect *gcc_expr_468 = BRANCH(op_EQ_236, EMPTY(), set_usr_field_call_344);

	// h_tmp95 = HYB(gcc_expr_if ((sextract64(((ut64) ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1)), 0x0, 0x20) == ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_470 = SETL("h_tmp95", cond_467);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((sextract64(((ut64)  ...;
	RzILOpEffect *seq_471 = SEQN(2, gcc_expr_468, op_ASSIGN_hybrid_tmp_470);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1)), 0x0, 0x20) == ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1)) ? ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) & ((st64) 0x3)) == ((st64) 0x3)) ? sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) : sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20)) >> 0x1) : h_tmp95) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_241 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_242 = SHIFTRA(DUP(Rtt), op_MUL_241);
	RzILOpPure *op_AND_244 = LOGAND(op_RSHIFT_242, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_256 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_257 = SHIFTRA(DUP(Rss), op_MUL_256);
	RzILOpPure *op_AND_259 = LOGAND(op_RSHIFT_257, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_267 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_244), DUP(op_AND_244))), CAST(32, MSB(DUP(op_AND_244)), DUP(op_AND_244)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_259), DUP(op_AND_259))), CAST(32, MSB(DUP(op_AND_259)), DUP(op_AND_259)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_AND_270 = LOGAND(op_SUB_267, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_EQ_273 = EQ(op_AND_270, CAST(64, MSB(SN(32, 3)), SN(32, 3)));
	RzILOpPure *op_MUL_278 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_279 = SHIFTRA(DUP(Rtt), op_MUL_278);
	RzILOpPure *op_AND_281 = LOGAND(op_RSHIFT_279, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_293 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_294 = SHIFTRA(DUP(Rss), op_MUL_293);
	RzILOpPure *op_AND_296 = LOGAND(op_RSHIFT_294, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_304 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_281), DUP(op_AND_281))), CAST(32, MSB(DUP(op_AND_281)), DUP(op_AND_281)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_296), DUP(op_AND_296))), CAST(32, MSB(DUP(op_AND_296)), DUP(op_AND_296)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_307 = ADD(op_SUB_304, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_MUL_312 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_313 = SHIFTRA(DUP(Rtt), op_MUL_312);
	RzILOpPure *op_AND_315 = LOGAND(op_RSHIFT_313, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_327 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_328 = SHIFTRA(DUP(Rss), op_MUL_327);
	RzILOpPure *op_AND_330 = LOGAND(op_RSHIFT_328, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_338 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_315), DUP(op_AND_315))), CAST(32, MSB(DUP(op_AND_315)), DUP(op_AND_315)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_330), DUP(op_AND_330))), CAST(32, MSB(DUP(op_AND_330)), DUP(op_AND_330)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *cond_339 = ITE(op_EQ_273, op_ADD_307, op_SUB_338);
	RzILOpPure *op_RSHIFT_341 = SHIFTRA(cond_339, SN(32, 1));
	RzILOpPure *cond_472 = ITE(DUP(op_EQ_236), op_RSHIFT_341, VARL("h_tmp95"));
	RzILOpPure *op_AND_474 = LOGAND(cond_472, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_476 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_477 = SHIFTL0(op_AND_474, op_MUL_476);
	RzILOpPure *op_OR_478 = LOGOR(op_AND_15, op_LSHIFT_477);
	RzILOpEffect *op_ASSIGN_479 = WRITE_REG(bundle, Rdd_op, op_OR_478);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((sextract64(((ut ...;
	RzILOpEffect *seq_480 = SEQN(2, seq_471, op_ASSIGN_479);

	// seq(h_tmp94; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((se ...;
	RzILOpEffect *seq_482 = seq_480;

	// seq(seq(h_tmp94; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ...;
	RzILOpEffect *seq_483 = SEQN(2, seq_482, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp94; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_484 = REPEAT(op_LT_4, seq_483);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp94; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_485 = SEQN(2, op_ASSIGN_2, for_484);

	RzILOpEffect *instruction_sequence = seq_485;
	return instruction_sequence;
}

// Rdd = vnavgw(Rtt,Rss):rnd:sat
RzILOpEffect *hex_il_op_a2_vnavgwr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp96 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp96", VARL("i"));

	// seq(h_tmp96 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_137 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1)), 0x0, 0x20) == (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_25 = SHIFTRA(Rtt, op_MUL_24);
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_25, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(Rss, op_MUL_40);
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_41, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_51 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_27), DUP(op_AND_27))), CAST(32, MSB(DUP(op_AND_27)), DUP(op_AND_27)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_43), DUP(op_AND_43))), CAST(32, MSB(DUP(op_AND_43)), DUP(op_AND_43)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_54 = ADD(op_SUB_51, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(op_ADD_54, SN(32, 1));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rtt), op_MUL_66);
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_67, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_81 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_82 = SHIFTRA(DUP(Rss), op_MUL_81);
	RzILOpPure *op_AND_84 = LOGAND(op_RSHIFT_82, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_92 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_69), DUP(op_AND_69))), CAST(32, MSB(DUP(op_AND_69)), DUP(op_AND_69)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_84), DUP(op_AND_84))), CAST(32, MSB(DUP(op_AND_84)), DUP(op_AND_84)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_95 = ADD(op_SUB_92, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_97 = SHIFTRA(op_ADD_95, SN(32, 1));
	RzILOpPure *op_EQ_98 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_56), SN(32, 0), SN(32, 0x20)), op_RSHIFT_97);
	RzILOpPure *op_MUL_142 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_143 = SHIFTRA(DUP(Rtt), op_MUL_142);
	RzILOpPure *op_AND_145 = LOGAND(op_RSHIFT_143, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_157 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_158 = SHIFTRA(DUP(Rss), op_MUL_157);
	RzILOpPure *op_AND_160 = LOGAND(op_RSHIFT_158, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_168 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_145), DUP(op_AND_145))), CAST(32, MSB(DUP(op_AND_145)), DUP(op_AND_145)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_160), DUP(op_AND_160))), CAST(32, MSB(DUP(op_AND_160)), DUP(op_AND_160)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_171 = ADD(op_SUB_168, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_173 = SHIFTRA(op_ADD_171, SN(32, 1));
	RzILOpPure *op_LT_176 = SLT(op_RSHIFT_173, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_181 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_182 = NEG(op_LSHIFT_181);
	RzILOpPure *op_LSHIFT_187 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_190 = SUB(op_LSHIFT_187, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_191 = ITE(op_LT_176, op_NEG_182, op_SUB_190);
	RzILOpEffect *gcc_expr_192 = BRANCH(op_EQ_98, EMPTY(), set_usr_field_call_137);

	// h_tmp97 = HYB(gcc_expr_if ((sextract64(((ut64) (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1)), 0x0, 0x20) == (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_194 = SETL("h_tmp97", cond_191);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (sextract64(((ut64) ((s ...;
	RzILOpEffect *seq_195 = SEQN(2, gcc_expr_192, op_ASSIGN_hybrid_tmp_194);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1)), 0x0, 0x20) == (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1)) ? (sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) - sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) + ((st64) 0x1) >> 0x1) : h_tmp97) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_103 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_104 = SHIFTRA(DUP(Rtt), op_MUL_103);
	RzILOpPure *op_AND_106 = LOGAND(op_RSHIFT_104, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_118 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_119 = SHIFTRA(DUP(Rss), op_MUL_118);
	RzILOpPure *op_AND_121 = LOGAND(op_RSHIFT_119, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_129 = SUB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_106), DUP(op_AND_106))), CAST(32, MSB(DUP(op_AND_106)), DUP(op_AND_106)))), SN(32, 0), SN(32, 0x20)), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_121), DUP(op_AND_121))), CAST(32, MSB(DUP(op_AND_121)), DUP(op_AND_121)))), SN(32, 0), SN(32, 0x20)));
	RzILOpPure *op_ADD_132 = ADD(op_SUB_129, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_134 = SHIFTRA(op_ADD_132, SN(32, 1));
	RzILOpPure *cond_196 = ITE(DUP(op_EQ_98), op_RSHIFT_134, VARL("h_tmp97"));
	RzILOpPure *op_AND_198 = LOGAND(cond_196, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_200 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_201 = SHIFTL0(op_AND_198, op_MUL_200);
	RzILOpPure *op_OR_202 = LOGOR(op_AND_15, op_LSHIFT_201);
	RzILOpEffect *op_ASSIGN_203 = WRITE_REG(bundle, Rdd_op, op_OR_202);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (sextract64(((ut64) ...;
	RzILOpEffect *seq_204 = SEQN(2, seq_195, op_ASSIGN_203);

	// seq(h_tmp96; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (sextr ...;
	RzILOpEffect *seq_206 = seq_204;

	// seq(seq(h_tmp96; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (s ...;
	RzILOpEffect *seq_207 = SEQN(2, seq_206, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp96; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (s ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_208 = REPEAT(op_LT_4, seq_207);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp96; seq(seq(HYB(gc ...;
	RzILOpEffect *seq_209 = SEQN(2, op_ASSIGN_2, for_208);

	RzILOpEffect *instruction_sequence = seq_209;
	return instruction_sequence;
}

// Rdd = vraddub(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vraddub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) 0x0);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, CAST(64, MSB(SN(32, 0)), SN(32, 0)));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_6 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_9 = SETL("i", INC(VARL("i"), 32));

	// h_tmp98 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp98", VARL("i"));

	// seq(h_tmp98 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_12 = SEQN(2, op_ASSIGN_hybrid_tmp_11, op_INC_9);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((Rdd >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_18 = LOGNOT(op_LSHIFT_17);
	RzILOpPure *op_AND_19 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_18);
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0));
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_39 = SHIFTRA(Rtt, op_MUL_38);
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_39, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_46 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_34)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_42)));
	RzILOpPure *op_ADD_48 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_25), DUP(op_AND_25))), CAST(32, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(64, MSB(op_ADD_46), DUP(op_ADD_46)));
	RzILOpPure *op_AND_50 = LOGAND(op_ADD_48, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(op_AND_50, SN(32, 0));
	RzILOpPure *op_OR_55 = LOGOR(op_AND_19, op_LSHIFT_54);
	RzILOpEffect *op_ASSIGN_56 = WRITE_REG(bundle, Rdd_op, op_OR_55);

	// seq(h_tmp98; Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) ( ...;
	RzILOpEffect *seq_58 = op_ASSIGN_56;

	// seq(seq(h_tmp98; Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st6 ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_12);

	// while ((i < 0x4)) { seq(seq(h_tmp98; Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st6 ... };
	RzILOpPure *op_LT_8 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_60 = REPEAT(op_LT_8, seq_59);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp98; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_6, for_60);

	// i = 0x4;
	RzILOpEffect *op_ASSIGN_63 = SETL("i", SN(32, 4));

	// HYB(++i);
	RzILOpEffect *op_INC_66 = SETL("i", INC(VARL("i"), 32));

	// h_tmp99 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_68 = SETL("h_tmp99", VARL("i"));

	// seq(h_tmp99 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_69 = SEQN(2, op_ASSIGN_hybrid_tmp_68, op_INC_66);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_75 = LOGNOT(op_LSHIFT_74);
	RzILOpPure *op_AND_76 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_75);
	RzILOpPure *op_RSHIFT_80 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_82 = LOGAND(op_RSHIFT_80, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_86 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_87 = SHIFTRA(DUP(Rss), op_MUL_86);
	RzILOpPure *op_AND_90 = LOGAND(op_RSHIFT_87, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_93 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_94 = SHIFTRA(DUP(Rtt), op_MUL_93);
	RzILOpPure *op_AND_97 = LOGAND(op_RSHIFT_94, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_101 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_90)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_97)));
	RzILOpPure *op_ADD_103 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_82), DUP(op_AND_82))), CAST(32, MSB(DUP(op_AND_82)), DUP(op_AND_82))), CAST(64, MSB(op_ADD_101), DUP(op_ADD_101)));
	RzILOpPure *op_AND_105 = LOGAND(op_ADD_103, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(op_AND_105, SN(32, 0x20));
	RzILOpPure *op_OR_110 = LOGOR(op_AND_76, op_LSHIFT_109);
	RzILOpEffect *op_ASSIGN_111 = WRITE_REG(bundle, Rdd_op, op_OR_110);

	// seq(h_tmp99; Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64)  ...;
	RzILOpEffect *seq_113 = op_ASSIGN_111;

	// seq(seq(h_tmp99; Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st ...;
	RzILOpEffect *seq_114 = SEQN(2, seq_113, seq_69);

	// while ((i < 0x8)) { seq(seq(h_tmp99; Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st ... };
	RzILOpPure *op_LT_65 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_115 = REPEAT(op_LT_65, seq_114);

	// seq(i = 0x4; while ((i < 0x8)) { seq(seq(h_tmp99; Rdd = ((Rdd &  ...;
	RzILOpEffect *seq_116 = SEQN(2, op_ASSIGN_63, for_115);

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_4, seq_61, seq_116);
	return instruction_sequence;
}

// Rxx += vraddub(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vraddub_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp100 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp100", VARL("i"));

	// seq(h_tmp100 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((Rxx >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_14 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_15 = LOGNOT(op_LSHIFT_14);
	RzILOpPure *op_AND_16 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_15);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_28 = SHIFTRA(Rss, op_MUL_27);
	RzILOpPure *op_AND_31 = LOGAND(op_RSHIFT_28, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Rtt, op_MUL_35);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_36, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_43 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_31)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_39)));
	RzILOpPure *op_ADD_45 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(op_ADD_43), DUP(op_ADD_43)));
	RzILOpPure *op_AND_47 = LOGAND(op_ADD_45, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(op_AND_47, SN(32, 0));
	RzILOpPure *op_OR_52 = LOGOR(op_AND_16, op_LSHIFT_51);
	RzILOpEffect *op_ASSIGN_53 = WRITE_REG(bundle, Rxx_op, op_OR_52);

	// seq(h_tmp100; Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st64)  ...;
	RzILOpEffect *seq_55 = op_ASSIGN_53;

	// seq(seq(h_tmp100; Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st ...;
	RzILOpEffect *seq_56 = SEQN(2, seq_55, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp100; Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_57 = REPEAT(op_LT_4, seq_56);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp100; Rxx = ((Rxx & ...;
	RzILOpEffect *seq_58 = SEQN(2, op_ASSIGN_2, for_57);

	// i = 0x4;
	RzILOpEffect *op_ASSIGN_60 = SETL("i", SN(32, 4));

	// HYB(++i);
	RzILOpEffect *op_INC_63 = SETL("i", INC(VARL("i"), 32));

	// h_tmp101 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_65 = SETL("h_tmp101", VARL("i"));

	// seq(h_tmp101 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_66 = SEQN(2, op_ASSIGN_hybrid_tmp_65, op_INC_63);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) + ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_72 = LOGNOT(op_LSHIFT_71);
	RzILOpPure *op_AND_73 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_72);
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rss), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_ADD_98 = ADD(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_87)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_94)));
	RzILOpPure *op_ADD_100 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_79), DUP(op_AND_79))), CAST(32, MSB(DUP(op_AND_79)), DUP(op_AND_79))), CAST(64, MSB(op_ADD_98), DUP(op_ADD_98)));
	RzILOpPure *op_AND_102 = LOGAND(op_ADD_100, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_106 = SHIFTL0(op_AND_102, SN(32, 0x20));
	RzILOpPure *op_OR_107 = LOGOR(op_AND_73, op_LSHIFT_106);
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rxx_op, op_OR_107);

	// seq(h_tmp101; Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) ...;
	RzILOpEffect *seq_110 = op_ASSIGN_108;

	// seq(seq(h_tmp101; Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((s ...;
	RzILOpEffect *seq_111 = SEQN(2, seq_110, seq_66);

	// while ((i < 0x8)) { seq(seq(h_tmp101; Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((s ... };
	RzILOpPure *op_LT_62 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_112 = REPEAT(op_LT_62, seq_111);

	// seq(i = 0x4; while ((i < 0x8)) { seq(seq(h_tmp101; Rxx = ((Rxx & ...;
	RzILOpEffect *seq_113 = SEQN(2, op_ASSIGN_60, for_112);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_58, seq_113);
	return instruction_sequence;
}

// Rdd = vrsadub(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vrsadub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) 0x0);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, CAST(64, MSB(SN(32, 0)), SN(32, 0)));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_6 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_9 = SETL("i", INC(VARL("i"), 32));

	// h_tmp102 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp102", VARL("i"));

	// seq(h_tmp102 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_12 = SEQN(2, op_ASSIGN_hybrid_tmp_11, op_INC_9);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((Rdd >> 0x0) & 0xffffffff))) + ((st64) ((((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? (-((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) : ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_18 = LOGNOT(op_LSHIFT_17);
	RzILOpPure *op_AND_19 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_18);
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0));
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_39 = SHIFTRA(Rtt, op_MUL_38);
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_39, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_46 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_34)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_42)));
	RzILOpPure *op_LT_48 = SLT(op_SUB_46, SN(32, 0));
	RzILOpPure *op_MUL_50 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_51 = SHIFTRA(DUP(Rss), op_MUL_50);
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_51, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_57 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_58 = SHIFTRA(DUP(Rtt), op_MUL_57);
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_65 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_54)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_61)));
	RzILOpPure *op_NEG_66 = NEG(op_SUB_65);
	RzILOpPure *op_MUL_68 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(DUP(Rss), op_MUL_68);
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_75 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_76 = SHIFTRA(DUP(Rtt), op_MUL_75);
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_76, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_83 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_72)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_79)));
	RzILOpPure *cond_84 = ITE(op_LT_48, op_NEG_66, op_SUB_83);
	RzILOpPure *op_ADD_86 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_25), DUP(op_AND_25))), CAST(32, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(64, MSB(cond_84), DUP(cond_84)));
	RzILOpPure *op_AND_88 = LOGAND(op_ADD_86, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_92 = SHIFTL0(op_AND_88, SN(32, 0));
	RzILOpPure *op_OR_93 = LOGOR(op_AND_19, op_LSHIFT_92);
	RzILOpEffect *op_ASSIGN_94 = WRITE_REG(bundle, Rdd_op, op_OR_93);

	// seq(h_tmp102; Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64)  ...;
	RzILOpEffect *seq_96 = op_ASSIGN_94;

	// seq(seq(h_tmp102; Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st ...;
	RzILOpEffect *seq_97 = SEQN(2, seq_96, seq_12);

	// while ((i < 0x4)) { seq(seq(h_tmp102; Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st ... };
	RzILOpPure *op_LT_8 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_98 = REPEAT(op_LT_8, seq_97);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp102; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_99 = SEQN(2, op_ASSIGN_6, for_98);

	// i = 0x4;
	RzILOpEffect *op_ASSIGN_101 = SETL("i", SN(32, 4));

	// HYB(++i);
	RzILOpEffect *op_INC_104 = SETL("i", INC(VARL("i"), 32));

	// h_tmp103 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_106 = SETL("h_tmp103", VARL("i"));

	// seq(h_tmp103 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_107 = SEQN(2, op_ASSIGN_hybrid_tmp_106, op_INC_104);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff))) + ((st64) ((((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? (-((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) : ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_112 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_113 = LOGNOT(op_LSHIFT_112);
	RzILOpPure *op_AND_114 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_113);
	RzILOpPure *op_RSHIFT_118 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_120 = LOGAND(op_RSHIFT_118, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_124 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_125 = SHIFTRA(DUP(Rss), op_MUL_124);
	RzILOpPure *op_AND_128 = LOGAND(op_RSHIFT_125, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_131 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_132 = SHIFTRA(DUP(Rtt), op_MUL_131);
	RzILOpPure *op_AND_135 = LOGAND(op_RSHIFT_132, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_139 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_128)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_135)));
	RzILOpPure *op_LT_141 = SLT(op_SUB_139, SN(32, 0));
	RzILOpPure *op_MUL_143 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rss), op_MUL_143);
	RzILOpPure *op_AND_147 = LOGAND(op_RSHIFT_144, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_150 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_151 = SHIFTRA(DUP(Rtt), op_MUL_150);
	RzILOpPure *op_AND_154 = LOGAND(op_RSHIFT_151, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_158 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_147)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_154)));
	RzILOpPure *op_NEG_159 = NEG(op_SUB_158);
	RzILOpPure *op_MUL_161 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_162 = SHIFTRA(DUP(Rss), op_MUL_161);
	RzILOpPure *op_AND_165 = LOGAND(op_RSHIFT_162, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_168 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_169 = SHIFTRA(DUP(Rtt), op_MUL_168);
	RzILOpPure *op_AND_172 = LOGAND(op_RSHIFT_169, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_176 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_165)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_172)));
	RzILOpPure *cond_177 = ITE(op_LT_141, op_NEG_159, op_SUB_176);
	RzILOpPure *op_ADD_179 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_120), DUP(op_AND_120))), CAST(32, MSB(DUP(op_AND_120)), DUP(op_AND_120))), CAST(64, MSB(cond_177), DUP(cond_177)));
	RzILOpPure *op_AND_181 = LOGAND(op_ADD_179, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_185 = SHIFTL0(op_AND_181, SN(32, 0x20));
	RzILOpPure *op_OR_186 = LOGOR(op_AND_114, op_LSHIFT_185);
	RzILOpEffect *op_ASSIGN_187 = WRITE_REG(bundle, Rdd_op, op_OR_186);

	// seq(h_tmp103; Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) ...;
	RzILOpEffect *seq_189 = op_ASSIGN_187;

	// seq(seq(h_tmp103; Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((s ...;
	RzILOpEffect *seq_190 = SEQN(2, seq_189, seq_107);

	// while ((i < 0x8)) { seq(seq(h_tmp103; Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((s ... };
	RzILOpPure *op_LT_103 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_191 = REPEAT(op_LT_103, seq_190);

	// seq(i = 0x4; while ((i < 0x8)) { seq(seq(h_tmp103; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_192 = SEQN(2, op_ASSIGN_101, for_191);

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_4, seq_99, seq_192);
	return instruction_sequence;
}

// Rxx += vrsadub(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_vrsadub_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp104 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp104", VARL("i"));

	// seq(h_tmp104 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((Rxx >> 0x0) & 0xffffffff))) + ((st64) ((((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? (-((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) : ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_14 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_15 = LOGNOT(op_LSHIFT_14);
	RzILOpPure *op_AND_16 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_15);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_28 = SHIFTRA(Rss, op_MUL_27);
	RzILOpPure *op_AND_31 = LOGAND(op_RSHIFT_28, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Rtt, op_MUL_35);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_36, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_43 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_31)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_39)));
	RzILOpPure *op_LT_45 = SLT(op_SUB_43, SN(32, 0));
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rss), op_MUL_47);
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rtt), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_62 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_51)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_58)));
	RzILOpPure *op_NEG_63 = NEG(op_SUB_62);
	RzILOpPure *op_MUL_65 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_66 = SHIFTRA(DUP(Rss), op_MUL_65);
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_66, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_72 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_73 = SHIFTRA(DUP(Rtt), op_MUL_72);
	RzILOpPure *op_AND_76 = LOGAND(op_RSHIFT_73, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_80 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_69)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_76)));
	RzILOpPure *cond_81 = ITE(op_LT_45, op_NEG_63, op_SUB_80);
	RzILOpPure *op_ADD_83 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(cond_81), DUP(cond_81)));
	RzILOpPure *op_AND_85 = LOGAND(op_ADD_83, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_89 = SHIFTL0(op_AND_85, SN(32, 0));
	RzILOpPure *op_OR_90 = LOGOR(op_AND_16, op_LSHIFT_89);
	RzILOpEffect *op_ASSIGN_91 = WRITE_REG(bundle, Rxx_op, op_OR_90);

	// seq(h_tmp104; Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st64)  ...;
	RzILOpEffect *seq_93 = op_ASSIGN_91;

	// seq(seq(h_tmp104; Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st ...;
	RzILOpEffect *seq_94 = SEQN(2, seq_93, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp104; Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_95 = REPEAT(op_LT_4, seq_94);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp104; Rxx = ((Rxx & ...;
	RzILOpEffect *seq_96 = SEQN(2, op_ASSIGN_2, for_95);

	// i = 0x4;
	RzILOpEffect *op_ASSIGN_98 = SETL("i", SN(32, 4));

	// HYB(++i);
	RzILOpEffect *op_INC_101 = SETL("i", INC(VARL("i"), 32));

	// h_tmp105 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_103 = SETL("h_tmp105", VARL("i"));

	// seq(h_tmp105 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_104 = SEQN(2, op_ASSIGN_hybrid_tmp_103, op_INC_101);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))) + ((st64) ((((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? (-((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) : ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_110 = LOGNOT(op_LSHIFT_109);
	RzILOpPure *op_AND_111 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_110);
	RzILOpPure *op_RSHIFT_115 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_117 = LOGAND(op_RSHIFT_115, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_121 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_122 = SHIFTRA(DUP(Rss), op_MUL_121);
	RzILOpPure *op_AND_125 = LOGAND(op_RSHIFT_122, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_128 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_129 = SHIFTRA(DUP(Rtt), op_MUL_128);
	RzILOpPure *op_AND_132 = LOGAND(op_RSHIFT_129, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_136 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_125)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_132)));
	RzILOpPure *op_LT_138 = SLT(op_SUB_136, SN(32, 0));
	RzILOpPure *op_MUL_140 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_141 = SHIFTRA(DUP(Rss), op_MUL_140);
	RzILOpPure *op_AND_144 = LOGAND(op_RSHIFT_141, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_147 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_148 = SHIFTRA(DUP(Rtt), op_MUL_147);
	RzILOpPure *op_AND_151 = LOGAND(op_RSHIFT_148, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_155 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_144)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_151)));
	RzILOpPure *op_NEG_156 = NEG(op_SUB_155);
	RzILOpPure *op_MUL_158 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_159 = SHIFTRA(DUP(Rss), op_MUL_158);
	RzILOpPure *op_AND_162 = LOGAND(op_RSHIFT_159, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_165 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_166 = SHIFTRA(DUP(Rtt), op_MUL_165);
	RzILOpPure *op_AND_169 = LOGAND(op_RSHIFT_166, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_173 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_162)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_169)));
	RzILOpPure *cond_174 = ITE(op_LT_138, op_NEG_156, op_SUB_173);
	RzILOpPure *op_ADD_176 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_117), DUP(op_AND_117))), CAST(32, MSB(DUP(op_AND_117)), DUP(op_AND_117))), CAST(64, MSB(cond_174), DUP(cond_174)));
	RzILOpPure *op_AND_178 = LOGAND(op_ADD_176, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_182 = SHIFTL0(op_AND_178, SN(32, 0x20));
	RzILOpPure *op_OR_183 = LOGOR(op_AND_111, op_LSHIFT_182);
	RzILOpEffect *op_ASSIGN_184 = WRITE_REG(bundle, Rxx_op, op_OR_183);

	// seq(h_tmp105; Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) ...;
	RzILOpEffect *seq_186 = op_ASSIGN_184;

	// seq(seq(h_tmp105; Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((s ...;
	RzILOpEffect *seq_187 = SEQN(2, seq_186, seq_104);

	// while ((i < 0x8)) { seq(seq(h_tmp105; Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((s ... };
	RzILOpPure *op_LT_100 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_188 = REPEAT(op_LT_100, seq_187);

	// seq(i = 0x4; while ((i < 0x8)) { seq(seq(h_tmp105; Rxx = ((Rxx & ...;
	RzILOpEffect *seq_189 = SEQN(2, op_ASSIGN_98, for_188);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_96, seq_189);
	return instruction_sequence;
}

// Rdd = vsubh(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vsubh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp106 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp106", VARL("i"));

	// seq(h_tmp106 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_34 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_AND_36 = LOGAND(op_SUB_34, SN(32, 0xffff));
	RzILOpPure *op_MUL_39 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(CAST(64, IL_FALSE, op_AND_36), op_MUL_39);
	RzILOpPure *op_OR_42 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_40);
	RzILOpEffect *op_ASSIGN_44 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_42));

	// seq(h_tmp106; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_46 = op_ASSIGN_44;

	// seq(seq(h_tmp106; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_47 = SEQN(2, seq_46, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp106; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_48 = REPEAT(op_LT_4, seq_47);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp106; Rdd = ((st64) ...;
	RzILOpEffect *seq_49 = SEQN(2, op_ASSIGN_2, for_48);

	RzILOpEffect *instruction_sequence = seq_49;
	return instruction_sequence;
}

// Rdd = vsubh(Rtt,Rss):sat
RzILOpEffect *hex_il_op_a2_vsubhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp107 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp107", VARL("i"));

	// seq(h_tmp107 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_81 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rss, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_37 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_25), DUP(op_AND_25))), CAST(16, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(32, MSB(CAST(16, MSB(op_AND_33), DUP(op_AND_33))), CAST(16, MSB(DUP(op_AND_33)), DUP(op_AND_33))));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rtt), op_MUL_44);
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rss), op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_59 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_48), DUP(op_AND_48))), CAST(16, MSB(DUP(op_AND_48)), DUP(op_AND_48))), CAST(32, MSB(CAST(16, MSB(op_AND_55), DUP(op_AND_55))), CAST(16, MSB(DUP(op_AND_55)), DUP(op_AND_55))));
	RzILOpPure *op_EQ_61 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_37), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_59), DUP(op_SUB_59)));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rtt), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rss), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_98 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_87), DUP(op_AND_87))), CAST(16, MSB(DUP(op_AND_87)), DUP(op_AND_87))), CAST(32, MSB(CAST(16, MSB(op_AND_94), DUP(op_AND_94))), CAST(16, MSB(DUP(op_AND_94)), DUP(op_AND_94))));
	RzILOpPure *op_LT_100 = SLT(op_SUB_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_105 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_106 = NEG(op_LSHIFT_105);
	RzILOpPure *op_LSHIFT_111 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_114 = SUB(op_LSHIFT_111, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_115 = ITE(op_LT_100, op_NEG_106, op_SUB_114);
	RzILOpEffect *gcc_expr_116 = BRANCH(op_EQ_61, EMPTY(), set_usr_field_call_81);

	// h_tmp108 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_118 = SETL("h_tmp108", cond_115);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rtt > ...;
	RzILOpEffect *seq_119 = SEQN(2, gcc_expr_116, op_ASSIGN_hybrid_tmp_118);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : h_tmp108) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rtt), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rss), op_MUL_70);
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_71, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_78 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_67), DUP(op_AND_67))), CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67))), CAST(32, MSB(CAST(16, MSB(op_AND_74), DUP(op_AND_74))), CAST(16, MSB(DUP(op_AND_74)), DUP(op_AND_74))));
	RzILOpPure *cond_121 = ITE(DUP(op_EQ_61), CAST(64, MSB(op_SUB_78), DUP(op_SUB_78)), VARL("h_tmp108"));
	RzILOpPure *op_AND_124 = LOGAND(cond_121, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_127 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_128 = SHIFTL0(CAST(64, IL_FALSE, op_AND_124), op_MUL_127);
	RzILOpPure *op_OR_130 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_128);
	RzILOpEffect *op_ASSIGN_132 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_130));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_133 = SEQN(2, seq_119, op_ASSIGN_132);

	// seq(h_tmp107; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st3 ...;
	RzILOpEffect *seq_135 = seq_133;

	// seq(seq(h_tmp107; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_136 = SEQN(2, seq_135, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp107; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_137 = REPEAT(op_LT_4, seq_136);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp107; seq(seq(HYB(g ...;
	RzILOpEffect *seq_138 = SEQN(2, op_ASSIGN_2, for_137);

	RzILOpEffect *instruction_sequence = seq_138;
	return instruction_sequence;
}

// Rdd = vsubub(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vsubub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp109 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp109", VARL("i"));

	// seq(h_tmp109 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_34 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_30)));
	RzILOpPure *op_AND_37 = LOGAND(CAST(64, MSB(op_SUB_34), DUP(op_SUB_34)), SN(64, 0xff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(CAST(64, IL_FALSE, op_AND_37), op_MUL_40);
	RzILOpPure *op_OR_43 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_41);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_43));

	// seq(h_tmp109; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_47 = op_ASSIGN_45;

	// seq(seq(h_tmp109; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_48 = SEQN(2, seq_47, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp109; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_49 = REPEAT(op_LT_4, seq_48);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp109; Rdd = ((st64) ...;
	RzILOpEffect *seq_50 = SEQN(2, op_ASSIGN_2, for_49);

	RzILOpEffect *instruction_sequence = seq_50;
	return instruction_sequence;
}

// Rdd = vsubub(Rtt,Rss):sat
RzILOpEffect *hex_il_op_a2_vsububs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp110 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp110", VARL("i"));

	// seq(h_tmp110 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_81 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))), 0x0, 0x8) == ((ut64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rss, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_37 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_25)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_33)));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rtt), op_MUL_44);
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rss), op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_59 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_48)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_55)));
	RzILOpPure *op_EQ_61 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_SUB_37), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, op_SUB_59));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rtt), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rss), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_98 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_87)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_94)));
	RzILOpPure *op_LT_100 = SLT(op_SUB_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_107 = SUB(op_LSHIFT_104, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_109 = ITE(op_LT_100, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_107);
	RzILOpEffect *gcc_expr_110 = BRANCH(op_EQ_61, EMPTY(), set_usr_field_call_81);

	// h_tmp111 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))), 0x0, 0x8) == ((ut64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_112 = SETL("h_tmp111", cond_109);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rtt >>  ...;
	RzILOpEffect *seq_113 = SEQN(2, gcc_expr_110, op_ASSIGN_hybrid_tmp_112);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((extract64(((ut64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))), 0x0, 0x8) == ((ut64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) ? ((st64) ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))) : h_tmp111) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rtt), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rss), op_MUL_70);
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_71, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_78 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_67)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_74)));
	RzILOpPure *cond_115 = ITE(DUP(op_EQ_61), CAST(64, MSB(op_SUB_78), DUP(op_SUB_78)), VARL("h_tmp111"));
	RzILOpPure *op_AND_117 = LOGAND(cond_115, SN(64, 0xff));
	RzILOpPure *op_MUL_120 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(CAST(64, IL_FALSE, op_AND_117), op_MUL_120);
	RzILOpPure *op_OR_123 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_121);
	RzILOpEffect *op_ASSIGN_125 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_123));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut8) ((Rtt ...;
	RzILOpEffect *seq_126 = SEQN(2, seq_113, op_ASSIGN_125);

	// seq(h_tmp110; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32 ...;
	RzILOpEffect *seq_128 = seq_126;

	// seq(seq(h_tmp110; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_129 = SEQN(2, seq_128, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp110; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_130 = REPEAT(op_LT_4, seq_129);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp110; seq(seq(HYB(g ...;
	RzILOpEffect *seq_131 = SEQN(2, op_ASSIGN_2, for_130);

	RzILOpEffect *instruction_sequence = seq_131;
	return instruction_sequence;
}

// Rdd = vsubuh(Rtt,Rss):sat
RzILOpEffect *hex_il_op_a2_vsubuhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp112 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp112", VARL("i"));

	// seq(h_tmp112 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_81 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rss, op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_37 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_25)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_33)));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rtt), op_MUL_44);
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rss), op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_59 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_48)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_55)));
	RzILOpPure *op_EQ_61 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_SUB_37), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, op_SUB_59));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rtt), op_MUL_83);
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_84, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_90 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rss), op_MUL_90);
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_98 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_87)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_94)));
	RzILOpPure *op_LT_100 = SLT(op_SUB_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_107 = SUB(op_LSHIFT_104, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_109 = ITE(op_LT_100, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_107);
	RzILOpEffect *gcc_expr_110 = BRANCH(op_EQ_61, EMPTY(), set_usr_field_call_81);

	// h_tmp113 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_112 = SETL("h_tmp113", cond_109);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rtt >> ...;
	RzILOpEffect *seq_113 = SEQN(2, gcc_expr_110, op_ASSIGN_hybrid_tmp_112);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((extract64(((ut64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((ut64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((ut16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) - ((st32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) : h_tmp113) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rtt), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_70 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(DUP(Rss), op_MUL_70);
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_71, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_78 = SUB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_67)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_74)));
	RzILOpPure *cond_115 = ITE(DUP(op_EQ_61), CAST(64, MSB(op_SUB_78), DUP(op_SUB_78)), VARL("h_tmp113"));
	RzILOpPure *op_AND_118 = LOGAND(cond_115, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_121 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_122 = SHIFTL0(CAST(64, IL_FALSE, op_AND_118), op_MUL_121);
	RzILOpPure *op_OR_124 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_122);
	RzILOpEffect *op_ASSIGN_126 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_124));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((ut16) ((Rt ...;
	RzILOpEffect *seq_127 = SEQN(2, seq_113, op_ASSIGN_126);

	// seq(h_tmp112; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32 ...;
	RzILOpEffect *seq_129 = seq_127;

	// seq(seq(h_tmp112; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_130 = SEQN(2, seq_129, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp112; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_131 = REPEAT(op_LT_4, seq_130);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp112; seq(seq(HYB(g ...;
	RzILOpEffect *seq_132 = SEQN(2, op_ASSIGN_2, for_131);

	RzILOpEffect *instruction_sequence = seq_132;
	return instruction_sequence;
}

// Rdd = vsubw(Rtt,Rss)
RzILOpEffect *hex_il_op_a2_vsubw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp114 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp114", VARL("i"));

	// seq(h_tmp114 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_32 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_AND_34 = LOGAND(op_SUB_32, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(op_AND_34, op_MUL_36);
	RzILOpPure *op_OR_38 = LOGOR(op_AND_15, op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rdd_op, op_OR_38);

	// seq(h_tmp114; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((s ...;
	RzILOpEffect *seq_41 = op_ASSIGN_39;

	// seq(seq(h_tmp114; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_41, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp114; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_43 = REPEAT(op_LT_4, seq_42);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp114; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_2, for_43);

	RzILOpEffect *instruction_sequence = seq_44;
	return instruction_sequence;
}

// Rdd = vsubw(Rtt,Rss):sat
RzILOpEffect *hex_il_op_a2_vsubws(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp115 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp115", VARL("i"));

	// seq(h_tmp115 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_74 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rtt, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rss, op_MUL_29);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_35 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24))), CAST(64, MSB(CAST(32, MSB(op_AND_32), DUP(op_AND_32))), CAST(32, MSB(DUP(op_AND_32)), DUP(op_AND_32))));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rtt), op_MUL_42);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_43, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rss), op_MUL_49);
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_55 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_45), DUP(op_AND_45))), CAST(32, MSB(DUP(op_AND_45)), DUP(op_AND_45))), CAST(64, MSB(CAST(32, MSB(op_AND_52), DUP(op_AND_52))), CAST(32, MSB(DUP(op_AND_52)), DUP(op_AND_52))));
	RzILOpPure *op_EQ_56 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_35), SN(32, 0), SN(32, 0x20)), op_SUB_55);
	RzILOpPure *op_MUL_76 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rtt), op_MUL_76);
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_77, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rss), op_MUL_83);
	RzILOpPure *op_AND_86 = LOGAND(op_RSHIFT_84, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_89 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_79), DUP(op_AND_79))), CAST(32, MSB(DUP(op_AND_79)), DUP(op_AND_79))), CAST(64, MSB(CAST(32, MSB(op_AND_86), DUP(op_AND_86))), CAST(32, MSB(DUP(op_AND_86)), DUP(op_AND_86))));
	RzILOpPure *op_LT_92 = SLT(op_SUB_89, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_97 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_98 = NEG(op_LSHIFT_97);
	RzILOpPure *op_LSHIFT_103 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_106 = SUB(op_LSHIFT_103, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_107 = ITE(op_LT_92, op_NEG_98, op_SUB_106);
	RzILOpEffect *gcc_expr_108 = BRANCH(op_EQ_56, EMPTY(), set_usr_field_call_74);

	// h_tmp116 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_110 = SETL("h_tmp116", cond_107);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rtt > ...;
	RzILOpEffect *seq_111 = SEQN(2, gcc_expr_108, op_ASSIGN_hybrid_tmp_110);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rtt >> i * 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) : h_tmp116) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_58 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_59 = SHIFTRA(DUP(Rtt), op_MUL_58);
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_59, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_65 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_66 = SHIFTRA(DUP(Rss), op_MUL_65);
	RzILOpPure *op_AND_68 = LOGAND(op_RSHIFT_66, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_71 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_61), DUP(op_AND_61))), CAST(32, MSB(DUP(op_AND_61)), DUP(op_AND_61))), CAST(64, MSB(CAST(32, MSB(op_AND_68), DUP(op_AND_68))), CAST(32, MSB(DUP(op_AND_68)), DUP(op_AND_68))));
	RzILOpPure *cond_112 = ITE(DUP(op_EQ_56), op_SUB_71, VARL("h_tmp116"));
	RzILOpPure *op_AND_114 = LOGAND(cond_112, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_116 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_117 = SHIFTL0(op_AND_114, op_MUL_116);
	RzILOpPure *op_OR_118 = LOGOR(op_AND_15, op_LSHIFT_117);
	RzILOpEffect *op_ASSIGN_119 = WRITE_REG(bundle, Rdd_op, op_OR_118);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_120 = SEQN(2, seq_111, op_ASSIGN_119);

	// seq(h_tmp115; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st6 ...;
	RzILOpEffect *seq_122 = seq_120;

	// seq(seq(h_tmp115; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_123 = SEQN(2, seq_122, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp115; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_124 = REPEAT(op_LT_4, seq_123);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp115; seq(seq(HYB(g ...;
	RzILOpEffect *seq_125 = SEQN(2, op_ASSIGN_2, for_124);

	RzILOpEffect *instruction_sequence = seq_125;
	return instruction_sequence;
}

// Rd = xor(Rs,Rt)
RzILOpEffect *hex_il_op_a2_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = (Rs ^ Rt);
	RzILOpPure *op_XOR_3 = LOGXOR(Rs, Rt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_XOR_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rdd = xor(Rss,Rtt)
RzILOpEffect *hex_il_op_a2_xorp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (Rss ^ Rtt);
	RzILOpPure *op_XOR_3 = LOGXOR(Rss, Rtt);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rdd_op, op_XOR_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = zxth(Rs)
RzILOpEffect *hex_il_op_a2_zxth(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>