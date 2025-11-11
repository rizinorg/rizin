// SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: c2b89fc9e45d325282b8eb6536f6145282dc3fdf
// LLVM commit date: 2024-12-23 13:36:28 -0600 (ISO 8601 format)
// Date of code generation: 2025-02-22 07:05:24-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_il/rz_il_opbuilder_begin.h>
#include "../hexagon_il.h"
#include <hexagon/hexagon.h>
#include <rz_il/rz_il_opcodes.h>

// Rd = addasl(Rt,Rs,Ii)
RzILOpEffect *hex_il_op_s2_addasl_rrri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rd = Rt + ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u));
	RzILOpPure *op_GE_9 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_9, SN(32, 0), op_LSHIFT_11);
	RzILOpPure *op_ADD_13 = ADD(Rt, cond_12);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, op_ADD_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_14);
	return instruction_sequence;
}

// allocframe(Rx,Ii):raw
RzILOpEffect *hex_il_op_s2_allocframe(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// EA = ((ut32) Rx + -0x8);
	RzILOpPure *op_ADD_4 = ADD(READ_REG(pkt, Rx_op, false), SN(32, -8));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut64(EA, ((ut64) (((((ut64) lr) << 0x20) | ((ut64) fp)) ^ (((ut64) framekey) << 0x20))));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(CAST(64, IL_FALSE, lr), SN(32, 0x20));
	RzILOpPure *op_OR_14 = LOGOR(op_LSHIFT_11, CAST(64, IL_FALSE, READ_REG(pkt, &fp_op, true)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_19 = LOGXOR(op_OR_14, op_LSHIFT_18);
	RzILOpEffect *ms_cast_ut64_20_21 = STOREW(VARL("EA"), CAST(64, IL_FALSE, op_XOR_19));

	// fp = EA;
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, &fp_op, VARL("EA"));

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rx = ((st32) EA - u);
	RzILOpPure *op_SUB_26 = SUB(VARL("EA"), VARL("u"));
	RzILOpEffect *op_ASSIGN_28 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_26));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_24, op_ASSIGN_6, ms_cast_ut64_20_21, op_ASSIGN_22, op_ASSIGN_28);
	return instruction_sequence;
}

// Rdd = asl(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rdd = ((u >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rss << u));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rss, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_8, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_10);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rdd_op, cond_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_13);
	return instruction_sequence;
}

// Rxx += asl(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = Rxx + ((u >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rss << u));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rss, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_8, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_10);
	RzILOpPure *op_ADD_13 = ADD(READ_REG(pkt, Rxx_op, false), cond_12);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rxx_op, op_ADD_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_14);
	return instruction_sequence;
}

// Rxx &= asl(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = (Rxx & ((u >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rss << u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rss, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_8, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_10);
	RzILOpPure *op_AND_13 = LOGAND(READ_REG(pkt, Rxx_op, false), cond_12);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rxx_op, op_AND_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_14);
	return instruction_sequence;
}

// Rxx -= asl(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = Rxx - ((u >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rss << u));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rss, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_8, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_10);
	RzILOpPure *op_SUB_13 = SUB(READ_REG(pkt, Rxx_op, false), cond_12);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rxx_op, op_SUB_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_14);
	return instruction_sequence;
}

// Rxx |= asl(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = (Rxx | ((u >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rss << u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rss, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_8, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_10);
	RzILOpPure *op_OR_13 = LOGOR(READ_REG(pkt, Rxx_op, false), cond_12);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rxx_op, op_OR_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_14);
	return instruction_sequence;
}

// Rxx ^= asl(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_p_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = (Rxx ^ ((u >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rss << u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rss, VARL("u"));
	RzILOpPure *cond_12 = ITE(op_GE_8, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_10);
	RzILOpPure *op_XOR_13 = LOGXOR(READ_REG(pkt, Rxx_op, false), cond_12);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rxx_op, op_XOR_13);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = asl(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rd = ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_11 = ITE(op_GE_8, SN(32, 0), op_LSHIFT_10);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, cond_11);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_12);
	return instruction_sequence;
}

// Rx += asl(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = Rx + ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_11 = ITE(op_GE_8, SN(32, 0), op_LSHIFT_10);
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), cond_11);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_13);
	return instruction_sequence;
}

// Rx &= asl(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = (Rx & ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_11 = ITE(op_GE_8, SN(32, 0), op_LSHIFT_10);
	RzILOpPure *op_AND_12 = LOGAND(READ_REG(pkt, Rx_op, false), cond_11);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_AND_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_13);
	return instruction_sequence;
}

// Rx -= asl(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = Rx - ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_11 = ITE(op_GE_8, SN(32, 0), op_LSHIFT_10);
	RzILOpPure *op_SUB_12 = SUB(READ_REG(pkt, Rx_op, false), cond_11);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_SUB_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_13);
	return instruction_sequence;
}

// Rx |= asl(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = (Rx | ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_11 = ITE(op_GE_8, SN(32, 0), op_LSHIFT_10);
	RzILOpPure *op_OR_12 = LOGOR(READ_REG(pkt, Rx_op, false), cond_11);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_OR_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_13);
	return instruction_sequence;
}

// Rd = asl(Rs,Ii):sat
RzILOpEffect *hex_il_op_s2_asl_i_r_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_45 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u))), 0x0, 0x20) == ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u)) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_GE_11 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_14 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), VARL("u"));
	RzILOpPure *cond_16 = ITE(op_GE_11, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_14);
	RzILOpPure *op_GE_26 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("u"));
	RzILOpPure *cond_31 = ITE(op_GE_26, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_29);
	RzILOpPure *op_EQ_32 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_16), SN(32, 0), SN(32, 0x20)), cond_31);
	RzILOpPure *op_GE_50 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("u"));
	RzILOpPure *cond_55 = ITE(op_GE_50, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_53);
	RzILOpPure *op_LT_58 = SLT(cond_55, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_63 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_64 = NEG(op_LSHIFT_63);
	RzILOpPure *op_LSHIFT_69 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_72 = SUB(op_LSHIFT_69, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_73 = ITE(op_LT_58, op_NEG_64, op_SUB_72);
	RzILOpEffect *gcc_expr_74 = BRANCH(op_EQ_32, EMPTY(), set_usr_field_call_45);

	// h_tmp451 = HYB(gcc_expr_if ((sextract64(((ut64) ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u))), 0x0, 0x20) == ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u)) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_76 = SETL("h_tmp451", cond_73);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((u >= ((ut32) 0x20)) ? ...;
	RzILOpEffect *seq_77 = SEQN(2, gcc_expr_74, op_ASSIGN_hybrid_tmp_76);

	// Rd = ((st32) ((sextract64(((ut64) ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u))), 0x0, 0x20) == ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u))) ? ((u >= ((ut32) 0x20)) ? ((st64) 0x0) : (((st64) Rs) << u)) : h_tmp451));
	RzILOpPure *op_GE_37 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("u"));
	RzILOpPure *cond_42 = ITE(op_GE_37, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_40);
	RzILOpPure *cond_78 = ITE(DUP(op_EQ_32), cond_42, VARL("h_tmp451"));
	RzILOpEffect *op_ASSIGN_80 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_78), DUP(cond_78)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((u >= ((ut32) 0x20 ...;
	RzILOpEffect *seq_81 = SEQN(2, seq_77, op_ASSIGN_80);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, seq_81);
	return instruction_sequence;
}

// Rx ^= asl(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_r_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = (Rx ^ ((u >= ((ut32) 0x20)) ? 0x0 : (Rs << u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(Rs, VARL("u"));
	RzILOpPure *cond_11 = ITE(op_GE_8, SN(32, 0), op_LSHIFT_10);
	RzILOpPure *op_XOR_12 = LOGXOR(READ_REG(pkt, Rx_op, false), cond_11);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_XOR_12);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_13);
	return instruction_sequence;
}

// Rdd = vaslh(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp452 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp452", VARL("i"));

	// seq(h_tmp452 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) << u)) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(16, MSB(op_AND_22), DUP(op_AND_22)), VARL("u"));
	RzILOpPure *op_AND_29 = LOGAND(CAST(32, MSB(op_LSHIFT_26), DUP(op_LSHIFT_26)), SN(32, 0xffff));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(CAST(64, IL_FALSE, op_AND_29), op_MUL_32);
	RzILOpPure *op_OR_35 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_35));

	// seq(h_tmp452; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_39 = op_ASSIGN_37;

	// seq(seq(h_tmp452; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_39, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp452; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_41 = REPEAT(op_LT_4, seq_40);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp452; Rdd = ((st64) ...;
	RzILOpEffect *seq_42 = SEQN(2, op_ASSIGN_2, for_41);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_42);
	return instruction_sequence;
}

// Rdd = vaslw(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asl_i_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp453 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp453", VARL("i"));

	// seq(h_tmp453 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) << u) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), VARL("u"));
	RzILOpPure *op_AND_28 = LOGAND(op_LSHIFT_26, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_AND_28, op_MUL_30);
	RzILOpPure *op_OR_32 = LOGOR(op_AND_15, op_LSHIFT_31);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Rdd_op, op_OR_32);

	// seq(h_tmp453; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((( ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp453; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp453; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_37 = REPEAT(op_LT_4, seq_36);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp453; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_38);
	return instruction_sequence;
}

// Rdd = asl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rdd = ((shamt < 0x0) ? ((Rss >> (-shamt) - 0x1) >> 0x1) : (Rss << shamt));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_SUB_18);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(op_RSHIFT_19, SN(32, 1));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_RSHIFT_21, op_LSHIFT_22);
	RzILOpEffect *op_ASSIGN_24 = WRITE_REG(bundle, Rdd_op, cond_23);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_24);
	return instruction_sequence;
}

// Rxx += asl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = Rxx + ((shamt < 0x0) ? ((Rss >> (-shamt) - 0x1) >> 0x1) : (Rss << shamt));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_SUB_18);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(op_RSHIFT_19, SN(32, 1));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_RSHIFT_21, op_LSHIFT_22);
	RzILOpPure *op_ADD_24 = ADD(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_ADD_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx &= asl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = (Rxx & ((shamt < 0x0) ? ((Rss >> (-shamt) - 0x1) >> 0x1) : (Rss << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_SUB_18);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(op_RSHIFT_19, SN(32, 1));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_RSHIFT_21, op_LSHIFT_22);
	RzILOpPure *op_AND_24 = LOGAND(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_AND_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx -= asl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = Rxx - ((shamt < 0x0) ? ((Rss >> (-shamt) - 0x1) >> 0x1) : (Rss << shamt));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_SUB_18);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(op_RSHIFT_19, SN(32, 1));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_RSHIFT_21, op_LSHIFT_22);
	RzILOpPure *op_SUB_24 = SUB(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_SUB_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx |= asl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = (Rxx | ((shamt < 0x0) ? ((Rss >> (-shamt) - 0x1) >> 0x1) : (Rss << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_SUB_18);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(op_RSHIFT_19, SN(32, 1));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_RSHIFT_21, op_LSHIFT_22);
	RzILOpPure *op_OR_24 = LOGOR(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_OR_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx ^= asl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_p_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = (Rxx ^ ((shamt < 0x0) ? ((Rss >> (-shamt) - 0x1) >> 0x1) : (Rss << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_SUB_18);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(op_RSHIFT_19, SN(32, 1));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_RSHIFT_21, op_LSHIFT_22);
	RzILOpPure *op_XOR_24 = LOGXOR(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_XOR_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rd = asl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rd = ((st32) ((shamt < 0x0) ? ((((st64) Rs) >> (-shamt) - 0x1) >> 0x1) : (((st64) Rs) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_25), DUP(cond_25)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_27);
	return instruction_sequence;
}

// Rx += asl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((st64) Rx) + ((shamt < 0x0) ? ((((st64) Rs) >> (-shamt) - 0x1) >> 0x1) : (((st64) Rs) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_ADD_27 = ADD(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_ADD_27), DUP(op_ADD_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx &= asl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((st64) Rx) & ((shamt < 0x0) ? ((((st64) Rs) >> (-shamt) - 0x1) >> 0x1) : (((st64) Rs) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_AND_27 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_AND_27), DUP(op_AND_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx -= asl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((st64) Rx) - ((shamt < 0x0) ? ((((st64) Rs) >> (-shamt) - 0x1) >> 0x1) : (((st64) Rs) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_SUB_27 = SUB(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_SUB_27), DUP(op_SUB_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx |= asl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((st64) Rx) | ((shamt < 0x0) ? ((((st64) Rs) >> (-shamt) - 0x1) >> 0x1) : (((st64) Rs) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_OR_27 = LOGOR(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_OR_27), DUP(op_OR_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rd = asl(Rs,Rt):sat
RzILOpEffect *hex_il_op_s2_asl_r_r_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_40 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) Rs) << shamt) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_EQ_35 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_LSHIFT_27), SN(32, 0), SN(32, 0x20)), op_LSHIFT_34);
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_LT_45 = SLT(op_LSHIFT_42, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_51 = NEG(op_LSHIFT_50);
	RzILOpPure *op_LSHIFT_56 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_59 = SUB(op_LSHIFT_56, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_60 = ITE(op_LT_45, op_NEG_51, op_SUB_59);
	RzILOpEffect *gcc_expr_61 = BRANCH(op_EQ_35, EMPTY(), set_usr_field_call_40);

	// h_tmp454 = HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) Rs) << shamt) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_63 = SETL("h_tmp454", cond_60);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << shamt)) ...;
	RzILOpEffect *seq_64 = SEQN(2, gcc_expr_61, op_ASSIGN_hybrid_tmp_63);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_73 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((((st32) (((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt)) ? (((st64) Rs) << shamt) : h_tmp454) ^ ((st64) Rs))) < 0x0)) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_65 = ITE(DUP(op_EQ_35), op_LSHIFT_37, VARL("h_tmp454"));
	RzILOpPure *op_XOR_67 = LOGXOR(cond_65, CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_70 = SLT(CAST(32, MSB(op_XOR_67), DUP(op_XOR_67)), SN(32, 0));
	RzILOpPure *op_LT_75 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_80 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_81 = NEG(op_LSHIFT_80);
	RzILOpPure *op_LSHIFT_86 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_89 = SUB(op_LSHIFT_86, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_90 = ITE(op_LT_75, op_NEG_81, op_SUB_89);
	RzILOpEffect *gcc_expr_91 = BRANCH(op_LT_70, set_usr_field_call_73, EMPTY());

	// h_tmp455 = HYB(gcc_expr_if ((((st32) (((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt)) ? (((st64) Rs) << shamt) : h_tmp454) ^ ((st64) Rs))) < 0x0)) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_93 = SETL("h_tmp455", cond_90);

	// seq(HYB(gcc_expr_if ((((st32) (((sextract64(((ut64) (((st64) Rs) ...;
	RzILOpEffect *seq_94 = SEQN(2, gcc_expr_91, op_ASSIGN_hybrid_tmp_93);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_105 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if (((Rs > 0x0) && ((((st64) Rs) << shamt) == ((st64) 0x0)))) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_GT_96 = SGT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_98 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_EQ_101 = EQ(op_LSHIFT_98, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_AND_102 = AND(op_GT_96, op_EQ_101);
	RzILOpPure *op_LT_107 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_112 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_113 = NEG(op_LSHIFT_112);
	RzILOpPure *op_LSHIFT_118 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_121 = SUB(op_LSHIFT_118, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_122 = ITE(op_LT_107, op_NEG_113, op_SUB_121);
	RzILOpEffect *gcc_expr_123 = BRANCH(op_AND_102, set_usr_field_call_105, EMPTY());

	// h_tmp456 = HYB(gcc_expr_if (((Rs > 0x0) && ((((st64) Rs) << shamt) == ((st64) 0x0)))) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_125 = SETL("h_tmp456", cond_122);

	// seq(HYB(gcc_expr_if (((Rs > 0x0) && ((((st64) Rs) << shamt) == ( ...;
	RzILOpEffect *seq_126 = SEQN(2, gcc_expr_123, op_ASSIGN_hybrid_tmp_125);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_144 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) Rs) << shamt) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_LSHIFT_131 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_LSHIFT_138 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_EQ_139 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_LSHIFT_131), SN(32, 0), SN(32, 0x20)), op_LSHIFT_138);
	RzILOpPure *op_LSHIFT_146 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *op_LT_149 = SLT(op_LSHIFT_146, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_154 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_155 = NEG(op_LSHIFT_154);
	RzILOpPure *op_LSHIFT_160 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_163 = SUB(op_LSHIFT_160, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_164 = ITE(op_LT_149, op_NEG_155, op_SUB_163);
	RzILOpEffect *gcc_expr_165 = BRANCH(op_EQ_139, EMPTY(), set_usr_field_call_144);

	// h_tmp457 = HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) Rs) << shamt) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_167 = SETL("h_tmp457", cond_164);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << shamt)) ...;
	RzILOpEffect *seq_168 = SEQN(2, gcc_expr_165, op_ASSIGN_hybrid_tmp_167);

	// Rd = ((st32) ((shamt < 0x0) ? ((((st64) Rs) >> (-shamt) - 0x1) >> 0x1) : ((((st32) (((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt)) ? (((st64) Rs) << shamt) : h_tmp454) ^ ((st64) Rs))) < 0x0) ? h_tmp455 : (((Rs > 0x0) && ((((st64) Rs) << shamt) == ((st64) 0x0))) ? h_tmp456 : ((sextract64(((ut64) (((st64) Rs) << shamt)), 0x0, 0x20) == (((st64) Rs) << shamt)) ? (((st64) Rs) << shamt) : h_tmp457)))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_141 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_169 = ITE(DUP(op_EQ_139), op_LSHIFT_141, VARL("h_tmp457"));
	RzILOpPure *cond_170 = ITE(DUP(op_AND_102), VARL("h_tmp456"), cond_169);
	RzILOpPure *cond_171 = ITE(DUP(op_LT_70), VARL("h_tmp455"), cond_170);
	RzILOpPure *cond_172 = ITE(op_LT_14, op_RSHIFT_22, cond_171);
	RzILOpEffect *op_ASSIGN_174 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_172), DUP(cond_172)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) Rs) << sha ...;
	RzILOpEffect *seq_175 = SEQN(5, seq_64, seq_94, seq_126, seq_168, op_ASSIGN_174);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, seq_175);
	return instruction_sequence;
}

// Rdd = vaslh(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp458 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp458", VARL("i"));

	// seq(h_tmp458 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) << sextract64(((ut64) Rt), 0x0, 0x7))) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_45 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_48 = SUB(op_NEG_45, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_49 = SHIFTRA(CAST(64, MSB(CAST(16, MSB(op_AND_34), DUP(op_AND_34))), CAST(16, MSB(DUP(op_AND_34)), DUP(op_AND_34))), op_SUB_48);
	RzILOpPure *op_RSHIFT_51 = SHIFTRA(op_RSHIFT_49, SN(32, 1));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_68 = SHIFTL0(CAST(64, MSB(CAST(16, MSB(op_AND_57), DUP(op_AND_57))), CAST(16, MSB(DUP(op_AND_57)), DUP(op_AND_57))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_69 = ITE(op_LT_27, op_RSHIFT_51, op_LSHIFT_68);
	RzILOpPure *op_AND_72 = LOGAND(cond_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_75 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(CAST(64, IL_FALSE, op_AND_72), op_MUL_75);
	RzILOpPure *op_OR_78 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_76);
	RzILOpEffect *op_ASSIGN_80 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_78));

	// seq(h_tmp458; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_82 = op_ASSIGN_80;

	// seq(seq(h_tmp458; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_83 = SEQN(2, seq_82, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp458; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_84 = REPEAT(op_LT_4, seq_83);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp458; Rdd = ((st64) ...;
	RzILOpEffect *seq_85 = SEQN(2, op_ASSIGN_2, for_84);

	RzILOpEffect *instruction_sequence = seq_85;
	return instruction_sequence;
}

// Rdd = vaslw(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asl_r_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp459 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp459", VARL("i"));

	// seq(h_tmp459 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((st64) ((st32) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((st64) ((st32) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) << sextract64(((ut64) Rt), 0x0, 0x7))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_46 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_49 = SUB(op_NEG_46, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_33), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))), op_SUB_49);
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(op_RSHIFT_50, SN(32, 1));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_55, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_70 = SHIFTL0(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_57), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_71 = ITE(op_LT_27, op_RSHIFT_52, op_LSHIFT_70);
	RzILOpPure *op_AND_73 = LOGAND(cond_71, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_75 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(op_AND_73, op_MUL_75);
	RzILOpPure *op_OR_77 = LOGOR(op_AND_15, op_LSHIFT_76);
	RzILOpEffect *op_ASSIGN_78 = WRITE_REG(bundle, Rdd_op, op_OR_77);

	// seq(h_tmp459; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((s ...;
	RzILOpEffect *seq_80 = op_ASSIGN_78;

	// seq(seq(h_tmp459; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_81 = SEQN(2, seq_80, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp459; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_82 = REPEAT(op_LT_4, seq_81);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp459; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_83 = SEQN(2, op_ASSIGN_2, for_82);

	RzILOpEffect *instruction_sequence = seq_83;
	return instruction_sequence;
}

// Rdd = asr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rdd = (Rss >> u);
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rss, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rdd_op, op_RSHIFT_4);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_5);
	return instruction_sequence;
}

// Rxx += asr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rxx = Rxx + (Rss >> u);
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rss, VARL("u"));
	RzILOpPure *op_ADD_5 = ADD(READ_REG(pkt, Rxx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rxx_op, op_ADD_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rxx &= asr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rxx = (Rxx & (Rss >> u));
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rss, VARL("u"));
	RzILOpPure *op_AND_5 = LOGAND(READ_REG(pkt, Rxx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rxx_op, op_AND_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rxx -= asr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rxx = Rxx - (Rss >> u);
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rss, VARL("u"));
	RzILOpPure *op_SUB_5 = SUB(READ_REG(pkt, Rxx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rxx_op, op_SUB_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rxx |= asr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rxx = (Rxx | (Rss >> u));
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rss, VARL("u"));
	RzILOpPure *op_OR_5 = LOGOR(READ_REG(pkt, Rxx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rxx_op, op_OR_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rdd = asr(Rss,Ii):rnd
RzILOpEffect *hex_il_op_s2_asr_i_p_rnd(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut64 rnd;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// tmp = ((ut64) (Rss >> u));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, VARL("u"));
	RzILOpEffect *op_ASSIGN_7 = SETL("tmp", CAST(64, IL_FALSE, op_RSHIFT_5));

	// rnd = (tmp & ((ut64) 0x1));
	RzILOpPure *op_AND_10 = LOGAND(VARL("tmp"), CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_11 = SETL("rnd", op_AND_10);

	// Rdd = ((st64) ((ut64) (((st64) tmp) >> 0x1)) + rnd);
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(CAST(64, IL_FALSE, VARL("tmp")), SN(32, 1));
	RzILOpPure *op_ADD_17 = ADD(CAST(64, IL_FALSE, op_RSHIFT_15), VARL("rnd"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_ADD_17));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_3, op_ASSIGN_7, op_ASSIGN_11, op_ASSIGN_19);
	return instruction_sequence;
}

// Rd = asr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rd = (Rs >> u);
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rs, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_RSHIFT_4);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_5);
	return instruction_sequence;
}

// Rx += asr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rx = Rx + (Rs >> u);
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rs, VARL("u"));
	RzILOpPure *op_ADD_5 = ADD(READ_REG(pkt, Rx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_ADD_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rx &= asr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rx = (Rx & (Rs >> u));
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rs, VARL("u"));
	RzILOpPure *op_AND_5 = LOGAND(READ_REG(pkt, Rx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_AND_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rx -= asr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rx = Rx - (Rs >> u);
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rs, VARL("u"));
	RzILOpPure *op_SUB_5 = SUB(READ_REG(pkt, Rx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_SUB_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rx |= asr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rx = (Rx | (Rs >> u));
	RzILOpPure *op_RSHIFT_4 = SHIFTRA(Rs, VARL("u"));
	RzILOpPure *op_OR_5 = LOGOR(READ_REG(pkt, Rx_op, false), op_RSHIFT_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_OR_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rd = asr(Rs,Ii):rnd
RzILOpEffect *hex_il_op_s2_asr_i_r_rnd(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Rd = ((st32) ((((st64) Rs) >> u) + ((st64) 0x1) >> 0x1));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(CAST(64, MSB(Rs), DUP(Rs)), VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(op_RSHIFT_5, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_10 = SHIFTRA(op_ADD_8, SN(32, 1));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_RSHIFT_10), DUP(op_RSHIFT_10)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = vasrw(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_svw_trun(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp460 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp460", VARL("i"));

	// seq(h_tmp460 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_25 = SETL("u", u);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) (((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) >> u) >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), VARL("u"));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(op_RSHIFT_27, SN(32, 0));
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_34), DUP(op_AND_34))), CAST(16, MSB(DUP(op_AND_34)), DUP(op_AND_34))), SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_44));

	// seq(h_tmp460; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp460; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp460; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_50 = REPEAT(op_LT_4, seq_49);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp460; Rd = ((st32)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_2, for_50);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_25, seq_51);
	return instruction_sequence;
}

// Rdd = vasrh(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp461 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp461", VARL("i"));

	// seq(h_tmp461 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(CAST(16, MSB(op_AND_22), DUP(op_AND_22)), VARL("u"));
	RzILOpPure *op_AND_29 = LOGAND(CAST(32, MSB(op_RSHIFT_26), DUP(op_RSHIFT_26)), SN(32, 0xffff));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(CAST(64, IL_FALSE, op_AND_29), op_MUL_32);
	RzILOpPure *op_OR_35 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_35));

	// seq(h_tmp461; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_39 = op_ASSIGN_37;

	// seq(seq(h_tmp461; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_39, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp461; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_41 = REPEAT(op_LT_4, seq_40);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp461; Rdd = ((st64) ...;
	RzILOpEffect *seq_42 = SEQN(2, op_ASSIGN_2, for_41);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_42);
	return instruction_sequence;
}

// Rdd = vasrw(Rss,Ii)
RzILOpEffect *hex_il_op_s2_asr_i_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp462 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp462", VARL("i"));

	// seq(h_tmp462 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | (((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) >> u) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(CAST(64, MSB(CAST(32, MSB(op_AND_21), DUP(op_AND_21))), CAST(32, MSB(DUP(op_AND_21)), DUP(op_AND_21))), VARL("u"));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_AND_28, op_MUL_30);
	RzILOpPure *op_OR_32 = LOGOR(op_AND_15, op_LSHIFT_31);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Rdd_op, op_OR_32);

	// seq(h_tmp462; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((( ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp462; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp462; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_37 = REPEAT(op_LT_4, seq_36);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp462; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_38);
	return instruction_sequence;
}

// Rdd = asr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rdd = ((shamt < 0x0) ? ((Rss << (-shamt) - 0x1) << 0x1) : (Rss >> shamt));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(Rss, op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_LSHIFT_21, op_RSHIFT_22);
	RzILOpEffect *op_ASSIGN_24 = WRITE_REG(bundle, Rdd_op, cond_23);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_24);
	return instruction_sequence;
}

// Rxx += asr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = Rxx + ((shamt < 0x0) ? ((Rss << (-shamt) - 0x1) << 0x1) : (Rss >> shamt));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(Rss, op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_LSHIFT_21, op_RSHIFT_22);
	RzILOpPure *op_ADD_24 = ADD(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_ADD_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx &= asr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = (Rxx & ((shamt < 0x0) ? ((Rss << (-shamt) - 0x1) << 0x1) : (Rss >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(Rss, op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_LSHIFT_21, op_RSHIFT_22);
	RzILOpPure *op_AND_24 = LOGAND(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_AND_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx -= asr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = Rxx - ((shamt < 0x0) ? ((Rss << (-shamt) - 0x1) << 0x1) : (Rss >> shamt));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(Rss, op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_LSHIFT_21, op_RSHIFT_22);
	RzILOpPure *op_SUB_24 = SUB(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_SUB_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx |= asr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = (Rxx | ((shamt < 0x0) ? ((Rss << (-shamt) - 0x1) << 0x1) : (Rss >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(Rss, op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_LSHIFT_21, op_RSHIFT_22);
	RzILOpPure *op_OR_24 = LOGOR(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_OR_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rxx ^= asr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_p_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = (Rxx ^ ((shamt < 0x0) ? ((Rss << (-shamt) - 0x1) << 0x1) : (Rss >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(Rss, op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(DUP(Rss), VARL("shamt"));
	RzILOpPure *cond_23 = ITE(op_LT_14, op_LSHIFT_21, op_RSHIFT_22);
	RzILOpPure *op_XOR_24 = LOGXOR(READ_REG(pkt, Rxx_op, false), cond_23);
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, Rxx_op, op_XOR_24);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_25);
	return instruction_sequence;
}

// Rd = asr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rd = ((st32) ((shamt < 0x0) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : (((st64) Rs) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_25), DUP(cond_25)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_27);
	return instruction_sequence;
}

// Rx += asr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((st64) Rx) + ((shamt < 0x0) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : (((st64) Rs) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_ADD_27 = ADD(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_ADD_27), DUP(op_ADD_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx &= asr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((st64) Rx) & ((shamt < 0x0) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : (((st64) Rs) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_AND_27 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_AND_27), DUP(op_AND_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx -= asr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((st64) Rx) - ((shamt < 0x0) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : (((st64) Rs) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_SUB_27 = SUB(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_SUB_27), DUP(op_SUB_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx |= asr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((st64) Rx) | ((shamt < 0x0) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : (((st64) Rs) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_OR_27 = LOGOR(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(op_OR_27), DUP(op_OR_27)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rd = asr(Rs,Rt):sat
RzILOpEffect *hex_il_op_s2_asr_r_r_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_48 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) Rs) << (-shamt) - 0x1) << 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_NEG_20 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_22 = SUB(op_NEG_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_22);
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(op_LSHIFT_23, SN(32, 1));
	RzILOpPure *op_NEG_32 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_34 = SUB(op_NEG_32, SN(32, 1));
	RzILOpPure *op_LSHIFT_35 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_34);
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(op_LSHIFT_35, SN(32, 1));
	RzILOpPure *op_EQ_38 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_LSHIFT_25), SN(32, 0), SN(32, 0x20)), op_LSHIFT_37);
	RzILOpPure *op_NEG_50 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_52 = SUB(op_NEG_50, SN(32, 1));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_52);
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(op_LSHIFT_53, SN(32, 1));
	RzILOpPure *op_LT_58 = SLT(op_LSHIFT_55, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_63 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_64 = NEG(op_LSHIFT_63);
	RzILOpPure *op_LSHIFT_69 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_72 = SUB(op_LSHIFT_69, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_73 = ITE(op_LT_58, op_NEG_64, op_SUB_72);
	RzILOpEffect *gcc_expr_74 = BRANCH(op_EQ_38, EMPTY(), set_usr_field_call_48);

	// h_tmp463 = HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) Rs) << (-shamt) - 0x1) << 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_76 = SETL("h_tmp463", cond_73);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (-sham ...;
	RzILOpEffect *seq_77 = SEQN(2, gcc_expr_74, op_ASSIGN_hybrid_tmp_76);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_86 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((((st32) (((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1)) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : h_tmp463) ^ ((st64) Rs))) < 0x0)) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_NEG_40 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_42 = SUB(op_NEG_40, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_42);
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(op_LSHIFT_43, SN(32, 1));
	RzILOpPure *cond_78 = ITE(DUP(op_EQ_38), op_LSHIFT_45, VARL("h_tmp463"));
	RzILOpPure *op_XOR_80 = LOGXOR(cond_78, CAST(64, MSB(DUP(Rs)), DUP(Rs)));
	RzILOpPure *op_LT_83 = SLT(CAST(32, MSB(op_XOR_80), DUP(op_XOR_80)), SN(32, 0));
	RzILOpPure *op_LT_88 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_93 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_94 = NEG(op_LSHIFT_93);
	RzILOpPure *op_LSHIFT_99 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_102 = SUB(op_LSHIFT_99, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_103 = ITE(op_LT_88, op_NEG_94, op_SUB_102);
	RzILOpEffect *gcc_expr_104 = BRANCH(op_LT_83, set_usr_field_call_86, EMPTY());

	// h_tmp464 = HYB(gcc_expr_if ((((st32) (((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1)) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : h_tmp463) ^ ((st64) Rs))) < 0x0)) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_106 = SETL("h_tmp464", cond_103);

	// seq(HYB(gcc_expr_if ((((st32) (((sextract64(((ut64) ((((st64) Rs ...;
	RzILOpEffect *seq_107 = SEQN(2, gcc_expr_104, op_ASSIGN_hybrid_tmp_106);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_123 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if (((Rs > 0x0) && (((((st64) Rs) << (-shamt) - 0x1) << 0x1) == ((st64) 0x0)))) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_GT_109 = SGT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_NEG_111 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_113 = SUB(op_NEG_111, SN(32, 1));
	RzILOpPure *op_LSHIFT_114 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_113);
	RzILOpPure *op_LSHIFT_116 = SHIFTL0(op_LSHIFT_114, SN(32, 1));
	RzILOpPure *op_EQ_119 = EQ(op_LSHIFT_116, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_AND_120 = AND(op_GT_109, op_EQ_119);
	RzILOpPure *op_LT_125 = SLT(DUP(Rs), SN(32, 0));
	RzILOpPure *op_LSHIFT_130 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_131 = NEG(op_LSHIFT_130);
	RzILOpPure *op_LSHIFT_136 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_139 = SUB(op_LSHIFT_136, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_140 = ITE(op_LT_125, op_NEG_131, op_SUB_139);
	RzILOpEffect *gcc_expr_141 = BRANCH(op_AND_120, set_usr_field_call_123, EMPTY());

	// h_tmp465 = HYB(gcc_expr_if (((Rs > 0x0) && (((((st64) Rs) << (-shamt) - 0x1) << 0x1) == ((st64) 0x0)))) {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))} else {{}}, ((Rs < 0x0) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_143 = SETL("h_tmp465", cond_140);

	// seq(HYB(gcc_expr_if (((Rs > 0x0) && (((((st64) Rs) << (-shamt) - ...;
	RzILOpEffect *seq_144 = SEQN(2, gcc_expr_141, op_ASSIGN_hybrid_tmp_143);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_177 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) Rs) << (-shamt) - 0x1) << 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_NEG_149 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_151 = SUB(op_NEG_149, SN(32, 1));
	RzILOpPure *op_LSHIFT_152 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_151);
	RzILOpPure *op_LSHIFT_154 = SHIFTL0(op_LSHIFT_152, SN(32, 1));
	RzILOpPure *op_NEG_161 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_163 = SUB(op_NEG_161, SN(32, 1));
	RzILOpPure *op_LSHIFT_164 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_163);
	RzILOpPure *op_LSHIFT_166 = SHIFTL0(op_LSHIFT_164, SN(32, 1));
	RzILOpPure *op_EQ_167 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_LSHIFT_154), SN(32, 0), SN(32, 0x20)), op_LSHIFT_166);
	RzILOpPure *op_NEG_179 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_181 = SUB(op_NEG_179, SN(32, 1));
	RzILOpPure *op_LSHIFT_182 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_181);
	RzILOpPure *op_LSHIFT_184 = SHIFTL0(op_LSHIFT_182, SN(32, 1));
	RzILOpPure *op_LT_187 = SLT(op_LSHIFT_184, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_192 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_193 = NEG(op_LSHIFT_192);
	RzILOpPure *op_LSHIFT_198 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_201 = SUB(op_LSHIFT_198, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_202 = ITE(op_LT_187, op_NEG_193, op_SUB_201);
	RzILOpEffect *gcc_expr_203 = BRANCH(op_EQ_167, EMPTY(), set_usr_field_call_177);

	// h_tmp466 = HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((((st64) Rs) << (-shamt) - 0x1) << 0x1) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_205 = SETL("h_tmp466", cond_202);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (-sham ...;
	RzILOpEffect *seq_206 = SEQN(2, gcc_expr_203, op_ASSIGN_hybrid_tmp_205);

	// Rd = ((st32) ((shamt < 0x0) ? ((((st32) (((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1)) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : h_tmp463) ^ ((st64) Rs))) < 0x0) ? h_tmp464 : (((Rs > 0x0) && (((((st64) Rs) << (-shamt) - 0x1) << 0x1) == ((st64) 0x0))) ? h_tmp465 : ((sextract64(((ut64) ((((st64) Rs) << (-shamt) - 0x1) << 0x1)), 0x0, 0x20) == ((((st64) Rs) << (-shamt) - 0x1) << 0x1)) ? ((((st64) Rs) << (-shamt) - 0x1) << 0x1) : h_tmp466))) : (((st64) Rs) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_169 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_171 = SUB(op_NEG_169, SN(32, 1));
	RzILOpPure *op_LSHIFT_172 = SHIFTL0(CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_SUB_171);
	RzILOpPure *op_LSHIFT_174 = SHIFTL0(op_LSHIFT_172, SN(32, 1));
	RzILOpPure *cond_207 = ITE(DUP(op_EQ_167), op_LSHIFT_174, VARL("h_tmp466"));
	RzILOpPure *cond_208 = ITE(DUP(op_AND_120), VARL("h_tmp465"), cond_207);
	RzILOpPure *cond_209 = ITE(DUP(op_LT_83), VARL("h_tmp464"), cond_208);
	RzILOpPure *op_RSHIFT_211 = SHIFTRA(CAST(64, MSB(DUP(Rs)), DUP(Rs)), VARL("shamt"));
	RzILOpPure *cond_212 = ITE(op_LT_14, cond_209, op_RSHIFT_211);
	RzILOpEffect *op_ASSIGN_214 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_212), DUP(cond_212)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((((st64) Rs) << (- ...;
	RzILOpEffect *seq_215 = SEQN(5, seq_77, seq_107, seq_144, seq_206, op_ASSIGN_214);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, seq_215);
	return instruction_sequence;
}

// Rd = vasrw(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_svw_trun(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp467 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp467", VARL("i"));

	// seq(h_tmp467 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((st64) ((st32) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) << (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) << 0x1) : (((st64) ((st32) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) >> sextract64(((ut64) Rt), 0x0, 0x7))) >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_LT_28 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_32 = SHIFTRA(Rss, op_MUL_31);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_32, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_47 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_50 = SUB(op_NEG_47, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_34), DUP(op_AND_34))), CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34))), CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34))), CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34))), CAST(32, MSB(DUP(op_AND_34)), DUP(op_AND_34))))), op_SUB_50);
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(op_LSHIFT_51, SN(32, 1));
	RzILOpPure *op_MUL_55 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(DUP(Rss), op_MUL_55);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_56, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_71 = SHIFTRA(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_58), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_72 = ITE(op_LT_28, op_LSHIFT_53, op_RSHIFT_71);
	RzILOpPure *op_RSHIFT_76 = SHIFTRA(cond_72, SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_76, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_83 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_79), DUP(op_AND_79))), CAST(16, MSB(DUP(op_AND_79)), DUP(op_AND_79))), SN(32, 0xffff));
	RzILOpPure *op_MUL_86 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_87 = SHIFTL0(CAST(64, IL_FALSE, op_AND_83), op_MUL_86);
	RzILOpPure *op_OR_89 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_87);
	RzILOpEffect *op_ASSIGN_91 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_89));

	// seq(h_tmp467; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_93 = op_ASSIGN_91;

	// seq(seq(h_tmp467; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_94 = SEQN(2, seq_93, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp467; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_95 = REPEAT(op_LT_4, seq_94);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp467; Rd = ((st32)  ...;
	RzILOpEffect *seq_96 = SEQN(2, op_ASSIGN_2, for_95);

	RzILOpEffect *instruction_sequence = seq_96;
	return instruction_sequence;
}

// Rdd = vasrh(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp468 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp468", VARL("i"));

	// seq(h_tmp468 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) << (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) << 0x1) : (((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) >> sextract64(((ut64) Rt), 0x0, 0x7))) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_45 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_48 = SUB(op_NEG_45, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(CAST(64, MSB(CAST(16, MSB(op_AND_34), DUP(op_AND_34))), CAST(16, MSB(DUP(op_AND_34)), DUP(op_AND_34))), op_SUB_48);
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(op_LSHIFT_49, SN(32, 1));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_68 = SHIFTRA(CAST(64, MSB(CAST(16, MSB(op_AND_57), DUP(op_AND_57))), CAST(16, MSB(DUP(op_AND_57)), DUP(op_AND_57))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_69 = ITE(op_LT_27, op_LSHIFT_51, op_RSHIFT_68);
	RzILOpPure *op_AND_72 = LOGAND(cond_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_75 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(CAST(64, IL_FALSE, op_AND_72), op_MUL_75);
	RzILOpPure *op_OR_78 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_76);
	RzILOpEffect *op_ASSIGN_80 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_78));

	// seq(h_tmp468; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_82 = op_ASSIGN_80;

	// seq(seq(h_tmp468; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_83 = SEQN(2, seq_82, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp468; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_84 = REPEAT(op_LT_4, seq_83);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp468; Rdd = ((st64) ...;
	RzILOpEffect *seq_85 = SEQN(2, op_ASSIGN_2, for_84);

	RzILOpEffect *instruction_sequence = seq_85;
	return instruction_sequence;
}

// Rdd = vasrw(Rss,Rt)
RzILOpEffect *hex_il_op_s2_asr_r_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp469 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp469", VARL("i"));

	// seq(h_tmp469 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((st64) ((st32) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) << (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) << 0x1) : (((st64) ((st32) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) >> sextract64(((ut64) Rt), 0x0, 0x7))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_46 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_49 = SUB(op_NEG_46, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_33), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))), op_SUB_49);
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(op_LSHIFT_50, SN(32, 1));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_55, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_57), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))), CAST(32, MSB(DUP(op_AND_57)), DUP(op_AND_57))))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_71 = ITE(op_LT_27, op_LSHIFT_52, op_RSHIFT_70);
	RzILOpPure *op_AND_73 = LOGAND(cond_71, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_75 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(op_AND_73, op_MUL_75);
	RzILOpPure *op_OR_77 = LOGOR(op_AND_15, op_LSHIFT_76);
	RzILOpEffect *op_ASSIGN_78 = WRITE_REG(bundle, Rdd_op, op_OR_77);

	// seq(h_tmp469; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((s ...;
	RzILOpEffect *seq_80 = op_ASSIGN_78;

	// seq(seq(h_tmp469; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_81 = SEQN(2, seq_80, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp469; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_82 = REPEAT(op_LT_4, seq_81);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp469; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_83 = SEQN(2, op_ASSIGN_2, for_82);

	RzILOpEffect *instruction_sequence = seq_83;
	return instruction_sequence;
}

// Rd = brev(Rs)
RzILOpEffect *hex_il_op_s2_brev(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// revbit32(((ut32) Rs));
	RzILOpEffect *revbit32_call_3 = hex_revbit32(CAST(32, IL_FALSE, Rs));

	// h_tmp470 = revbit32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp470", UNSIGNED(32, VARL("ret_val")));

	// seq(revbit32(((ut32) Rs)); h_tmp470 = revbit32(((ut32) Rs)));
	RzILOpEffect *seq_6 = SEQN(2, revbit32_call_3, op_ASSIGN_hybrid_tmp_5);

	// Rd = ((st32) h_tmp470);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp470")));

	// seq(seq(revbit32(((ut32) Rs)); h_tmp470 = revbit32(((ut32) Rs))) ...;
	RzILOpEffect *seq_9 = SEQN(2, seq_6, op_ASSIGN_8);

	RzILOpEffect *instruction_sequence = seq_9;
	return instruction_sequence;
}

// Rdd = brev(Rss)
RzILOpEffect *hex_il_op_s2_brevp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// revbit64(((ut64) Rss));
	RzILOpEffect *revbit64_call_3 = hex_revbit64(CAST(64, IL_FALSE, Rss));

	// h_tmp471 = revbit64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp471", UNSIGNED(64, VARL("ret_val")));

	// seq(revbit64(((ut64) Rss)); h_tmp471 = revbit64(((ut64) Rss)));
	RzILOpEffect *seq_6 = SEQN(2, revbit64_call_3, op_ASSIGN_hybrid_tmp_5);

	// Rdd = ((st64) h_tmp471);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, VARL("h_tmp471")));

	// seq(seq(revbit64(((ut64) Rss)); h_tmp471 = revbit64(((ut64) Rss) ...;
	RzILOpEffect *seq_9 = SEQN(2, seq_6, op_ASSIGN_8);

	RzILOpEffect *instruction_sequence = seq_9;
	return instruction_sequence;
}

// Rdd = decbin(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_cabacdecbin(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cl0(Rs)
RzILOpEffect *hex_il_op_s2_cl0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_2 = LOGNOT(Rs);
	RzILOpEffect *clo32_call_4 = hex_clo32(CAST(32, IL_FALSE, op_NOT_2));

	// h_tmp472 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_6 = SETL("h_tmp472", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp472 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_7 = SEQN(2, clo32_call_4, op_ASSIGN_hybrid_tmp_6);

	// Rd = ((st32) h_tmp472);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp472")));

	// seq(seq(clo32(((ut32) (~Rs))); h_tmp472 = clo32(((ut32) (~Rs)))) ...;
	RzILOpEffect *seq_10 = SEQN(2, seq_7, op_ASSIGN_9);

	RzILOpEffect *instruction_sequence = seq_10;
	return instruction_sequence;
}

// Rd = cl0(Rss)
RzILOpEffect *hex_il_op_s2_cl0p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_2 = LOGNOT(Rss);
	RzILOpEffect *clo64_call_4 = hex_clo64(CAST(64, IL_FALSE, op_NOT_2));

	// h_tmp473 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_6 = SETL("h_tmp473", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp473 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_7 = SEQN(2, clo64_call_4, op_ASSIGN_hybrid_tmp_6);

	// Rd = ((st32) h_tmp473);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp473")));

	// seq(seq(clo64(((ut64) (~Rss))); h_tmp473 = clo64(((ut64) (~Rss)) ...;
	RzILOpEffect *seq_10 = SEQN(2, seq_7, op_ASSIGN_9);

	RzILOpEffect *instruction_sequence = seq_10;
	return instruction_sequence;
}

// Rd = cl1(Rs)
RzILOpEffect *hex_il_op_s2_cl1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_3 = hex_clo32(CAST(32, IL_FALSE, Rs));

	// h_tmp474 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp474", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp474 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_6 = SEQN(2, clo32_call_3, op_ASSIGN_hybrid_tmp_5);

	// Rd = ((st32) h_tmp474);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp474")));

	// seq(seq(clo32(((ut32) Rs)); h_tmp474 = clo32(((ut32) Rs))); Rd = ...;
	RzILOpEffect *seq_9 = SEQN(2, seq_6, op_ASSIGN_8);

	RzILOpEffect *instruction_sequence = seq_9;
	return instruction_sequence;
}

// Rd = cl1(Rss)
RzILOpEffect *hex_il_op_s2_cl1p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_3 = hex_clo64(CAST(64, IL_FALSE, Rss));

	// h_tmp475 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp475", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp475 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_6 = SEQN(2, clo64_call_3, op_ASSIGN_hybrid_tmp_5);

	// Rd = ((st32) h_tmp475);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp475")));

	// seq(seq(clo64(((ut64) Rss)); h_tmp475 = clo64(((ut64) Rss))); Rd ...;
	RzILOpEffect *seq_9 = SEQN(2, seq_6, op_ASSIGN_8);

	RzILOpEffect *instruction_sequence = seq_9;
	return instruction_sequence;
}

// Rd = clb(Rs)
RzILOpEffect *hex_il_op_s2_clb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_3 = hex_clo32(CAST(32, IL_FALSE, Rs));

	// h_tmp476 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp476", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp476 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_6 = SEQN(2, clo32_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_7 = LOGNOT(DUP(Rs));
	RzILOpEffect *clo32_call_9 = hex_clo32(CAST(32, IL_FALSE, op_NOT_7));

	// h_tmp477 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp477", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp477 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_12 = SEQN(2, clo32_call_9, op_ASSIGN_hybrid_tmp_11);

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_15 = hex_clo32(CAST(32, IL_FALSE, DUP(Rs)));

	// h_tmp478 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_17 = SETL("h_tmp478", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp478 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_18 = SEQN(2, clo32_call_15, op_ASSIGN_hybrid_tmp_17);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_19 = LOGNOT(DUP(Rs));
	RzILOpEffect *clo32_call_21 = hex_clo32(CAST(32, IL_FALSE, op_NOT_19));

	// h_tmp479 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_23 = SETL("h_tmp479", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp479 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_24 = SEQN(2, clo32_call_21, op_ASSIGN_hybrid_tmp_23);

	// Rd = ((st32) ((h_tmp476 > h_tmp477) ? h_tmp478 : h_tmp479));
	RzILOpPure *op_GT_13 = UGT(VARL("h_tmp476"), VARL("h_tmp477"));
	RzILOpPure *cond_25 = ITE(op_GT_13, VARL("h_tmp478"), VARL("h_tmp479"));
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_25));

	// seq(seq(clo32(((ut32) Rs)); h_tmp476 = clo32(((ut32) Rs))); seq( ...;
	RzILOpEffect *seq_28 = SEQN(5, seq_6, seq_12, seq_18, seq_24, op_ASSIGN_27);

	RzILOpEffect *instruction_sequence = seq_28;
	return instruction_sequence;
}

// Rd = normamt(Rs)
RzILOpEffect *hex_il_op_s2_clbnorm(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = 0x0;
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, SN(32, 0));

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_7 = hex_clo32(CAST(32, IL_FALSE, Rs));

	// h_tmp480 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_9 = SETL("h_tmp480", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp480 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_10 = SEQN(2, clo32_call_7, op_ASSIGN_hybrid_tmp_9);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_11 = LOGNOT(DUP(Rs));
	RzILOpEffect *clo32_call_13 = hex_clo32(CAST(32, IL_FALSE, op_NOT_11));

	// h_tmp481 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_15 = SETL("h_tmp481", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp481 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_16 = SEQN(2, clo32_call_13, op_ASSIGN_hybrid_tmp_15);

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_19 = hex_clo32(CAST(32, IL_FALSE, DUP(Rs)));

	// h_tmp482 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_21 = SETL("h_tmp482", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp482 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_22 = SEQN(2, clo32_call_19, op_ASSIGN_hybrid_tmp_21);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_23 = LOGNOT(DUP(Rs));
	RzILOpEffect *clo32_call_25 = hex_clo32(CAST(32, IL_FALSE, op_NOT_23));

	// h_tmp483 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_27 = SETL("h_tmp483", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp483 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_28 = SEQN(2, clo32_call_25, op_ASSIGN_hybrid_tmp_27);

	// Rd = ((st32) ((h_tmp480 > h_tmp481) ? h_tmp482 : h_tmp483) - ((ut32) 0x1));
	RzILOpPure *op_GT_17 = UGT(VARL("h_tmp480"), VARL("h_tmp481"));
	RzILOpPure *cond_29 = ITE(op_GT_17, VARL("h_tmp482"), VARL("h_tmp483"));
	RzILOpPure *op_SUB_32 = SUB(cond_29, CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_34 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_SUB_32));

	// seq(seq(clo32(((ut32) Rs)); h_tmp480 = clo32(((ut32) Rs))); seq( ...;
	RzILOpEffect *seq_35 = SEQN(5, seq_10, seq_16, seq_22, seq_28, op_ASSIGN_34);

	// seq(Rd = 0x0);
	RzILOpEffect *seq_then_36 = op_ASSIGN_5;

	// seq(seq(seq(clo32(((ut32) Rs)); h_tmp480 = clo32(((ut32) Rs)));  ...;
	RzILOpEffect *seq_else_37 = seq_35;

	// if ((Rs == 0x0)) {seq(Rd = 0x0)} else {seq(seq(seq(clo32(((ut32) Rs)); h_tmp480 = clo32(((ut32) Rs)));  ...};
	RzILOpPure *op_EQ_2 = EQ(DUP(Rs), SN(32, 0));
	RzILOpEffect *branch_38 = BRANCH(op_EQ_2, seq_then_36, seq_else_37);

	RzILOpEffect *instruction_sequence = branch_38;
	return instruction_sequence;
}

// Rd = clb(Rss)
RzILOpEffect *hex_il_op_s2_clbp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_3 = hex_clo64(CAST(64, IL_FALSE, Rss));

	// h_tmp484 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp484", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp484 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_6 = SEQN(2, clo64_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_7 = LOGNOT(DUP(Rss));
	RzILOpEffect *clo64_call_9 = hex_clo64(CAST(64, IL_FALSE, op_NOT_7));

	// h_tmp485 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp485", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp485 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_12 = SEQN(2, clo64_call_9, op_ASSIGN_hybrid_tmp_11);

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_15 = hex_clo64(CAST(64, IL_FALSE, DUP(Rss)));

	// h_tmp486 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_17 = SETL("h_tmp486", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp486 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_18 = SEQN(2, clo64_call_15, op_ASSIGN_hybrid_tmp_17);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_19 = LOGNOT(DUP(Rss));
	RzILOpEffect *clo64_call_21 = hex_clo64(CAST(64, IL_FALSE, op_NOT_19));

	// h_tmp487 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_23 = SETL("h_tmp487", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp487 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_24 = SEQN(2, clo64_call_21, op_ASSIGN_hybrid_tmp_23);

	// Rd = ((st32) ((h_tmp484 > h_tmp485) ? h_tmp486 : h_tmp487));
	RzILOpPure *op_GT_13 = UGT(VARL("h_tmp484"), VARL("h_tmp485"));
	RzILOpPure *cond_25 = ITE(op_GT_13, VARL("h_tmp486"), VARL("h_tmp487"));
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_25));

	// seq(seq(clo64(((ut64) Rss)); h_tmp484 = clo64(((ut64) Rss))); se ...;
	RzILOpEffect *seq_28 = SEQN(5, seq_6, seq_12, seq_18, seq_24, op_ASSIGN_27);

	RzILOpEffect *instruction_sequence = seq_28;
	return instruction_sequence;
}

// Rd = clrbit(Rs,Ii)
RzILOpEffect *hex_il_op_s2_clrbit_i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Rd = (Rs & (~(0x1 << u)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(Rs, op_NOT_6);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_AND_7);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_8);
	return instruction_sequence;
}

// Rd = clrbit(Rs,Rt)
RzILOpEffect *hex_il_op_s2_clrbit_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) (((ut64) Rs) & (~((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) 0x1)) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut32) 0x1)) << sextract64(((ut64) Rt), 0x0, 0x7))))));
	RzILOpPure *op_LT_13 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_25 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_28 = SUB(op_NEG_25, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_29 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), op_SUB_28);
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(op_RSHIFT_29, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_44 = ITE(op_LT_13, op_RSHIFT_31, op_LSHIFT_43);
	RzILOpPure *op_NOT_45 = LOGNOT(cond_44);
	RzILOpPure *op_AND_47 = LOGAND(CAST(64, IL_FALSE, Rs), op_NOT_45);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_AND_47));

	RzILOpEffect *instruction_sequence = op_ASSIGN_49;
	return instruction_sequence;
}

// Rd = ct0(Rs)
RzILOpEffect *hex_il_op_s2_ct0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// revbit32(((ut32) Rs));
	RzILOpEffect *revbit32_call_3 = hex_revbit32(CAST(32, IL_FALSE, Rs));

	// h_tmp488 = revbit32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp488", UNSIGNED(32, VARL("ret_val")));

	// seq(revbit32(((ut32) Rs)); h_tmp488 = revbit32(((ut32) Rs)));
	RzILOpEffect *seq_6 = SEQN(2, revbit32_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo32((~h_tmp488));
	RzILOpPure *op_NOT_7 = LOGNOT(VARL("h_tmp488"));
	RzILOpEffect *clo32_call_8 = hex_clo32(op_NOT_7);

	// h_tmp489 = clo32((~h_tmp488));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_10 = SETL("h_tmp489", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32((~h_tmp488)); h_tmp489 = clo32((~h_tmp488)));
	RzILOpEffect *seq_11 = SEQN(2, clo32_call_8, op_ASSIGN_hybrid_tmp_10);

	// seq(seq(revbit32(((ut32) Rs)); h_tmp488 = revbit32(((ut32) Rs))) ...;
	RzILOpEffect *seq_12 = SEQN(2, seq_6, seq_11);

	// Rd = ((st32) h_tmp489);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp489")));

	// seq(seq(seq(revbit32(((ut32) Rs)); h_tmp488 = revbit32(((ut32) R ...;
	RzILOpEffect *seq_15 = SEQN(2, seq_12, op_ASSIGN_14);

	RzILOpEffect *instruction_sequence = seq_15;
	return instruction_sequence;
}

// Rd = ct0(Rss)
RzILOpEffect *hex_il_op_s2_ct0p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// revbit64(((ut64) Rss));
	RzILOpEffect *revbit64_call_3 = hex_revbit64(CAST(64, IL_FALSE, Rss));

	// h_tmp490 = revbit64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp490", UNSIGNED(64, VARL("ret_val")));

	// seq(revbit64(((ut64) Rss)); h_tmp490 = revbit64(((ut64) Rss)));
	RzILOpEffect *seq_6 = SEQN(2, revbit64_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo64((~h_tmp490));
	RzILOpPure *op_NOT_7 = LOGNOT(VARL("h_tmp490"));
	RzILOpEffect *clo64_call_8 = hex_clo64(op_NOT_7);

	// h_tmp491 = clo64((~h_tmp490));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_10 = SETL("h_tmp491", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64((~h_tmp490)); h_tmp491 = clo64((~h_tmp490)));
	RzILOpEffect *seq_11 = SEQN(2, clo64_call_8, op_ASSIGN_hybrid_tmp_10);

	// seq(seq(revbit64(((ut64) Rss)); h_tmp490 = revbit64(((ut64) Rss) ...;
	RzILOpEffect *seq_12 = SEQN(2, seq_6, seq_11);

	// Rd = ((st32) h_tmp491);
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp491")));

	// seq(seq(seq(revbit64(((ut64) Rss)); h_tmp490 = revbit64(((ut64)  ...;
	RzILOpEffect *seq_15 = SEQN(2, seq_12, op_ASSIGN_14);

	RzILOpEffect *instruction_sequence = seq_15;
	return instruction_sequence;
}

// Rd = ct1(Rs)
RzILOpEffect *hex_il_op_s2_ct1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// revbit32(((ut32) Rs));
	RzILOpEffect *revbit32_call_3 = hex_revbit32(CAST(32, IL_FALSE, Rs));

	// h_tmp492 = revbit32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp492", UNSIGNED(32, VARL("ret_val")));

	// seq(revbit32(((ut32) Rs)); h_tmp492 = revbit32(((ut32) Rs)));
	RzILOpEffect *seq_6 = SEQN(2, revbit32_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo32(h_tmp492);
	RzILOpEffect *clo32_call_7 = hex_clo32(VARL("h_tmp492"));

	// h_tmp493 = clo32(h_tmp492);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_9 = SETL("h_tmp493", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(h_tmp492); h_tmp493 = clo32(h_tmp492));
	RzILOpEffect *seq_10 = SEQN(2, clo32_call_7, op_ASSIGN_hybrid_tmp_9);

	// seq(seq(revbit32(((ut32) Rs)); h_tmp492 = revbit32(((ut32) Rs))) ...;
	RzILOpEffect *seq_11 = SEQN(2, seq_6, seq_10);

	// Rd = ((st32) h_tmp493);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp493")));

	// seq(seq(seq(revbit32(((ut32) Rs)); h_tmp492 = revbit32(((ut32) R ...;
	RzILOpEffect *seq_14 = SEQN(2, seq_11, op_ASSIGN_13);

	RzILOpEffect *instruction_sequence = seq_14;
	return instruction_sequence;
}

// Rd = ct1(Rss)
RzILOpEffect *hex_il_op_s2_ct1p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// revbit64(((ut64) Rss));
	RzILOpEffect *revbit64_call_3 = hex_revbit64(CAST(64, IL_FALSE, Rss));

	// h_tmp494 = revbit64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp494", UNSIGNED(64, VARL("ret_val")));

	// seq(revbit64(((ut64) Rss)); h_tmp494 = revbit64(((ut64) Rss)));
	RzILOpEffect *seq_6 = SEQN(2, revbit64_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo64(h_tmp494);
	RzILOpEffect *clo64_call_7 = hex_clo64(VARL("h_tmp494"));

	// h_tmp495 = clo64(h_tmp494);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_9 = SETL("h_tmp495", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(h_tmp494); h_tmp495 = clo64(h_tmp494));
	RzILOpEffect *seq_10 = SEQN(2, clo64_call_7, op_ASSIGN_hybrid_tmp_9);

	// seq(seq(revbit64(((ut64) Rss)); h_tmp494 = revbit64(((ut64) Rss) ...;
	RzILOpEffect *seq_11 = SEQN(2, seq_6, seq_10);

	// Rd = ((st32) h_tmp495);
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("h_tmp495")));

	// seq(seq(seq(revbit64(((ut64) Rss)); h_tmp494 = revbit64(((ut64)  ...;
	RzILOpEffect *seq_14 = SEQN(2, seq_11, op_ASSIGN_13);

	RzILOpEffect *instruction_sequence = seq_14;
	return instruction_sequence;
}

// Rdd = deinterleave(Rss)
RzILOpEffect *hex_il_op_s2_deinterleave(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = extractu(Rs,Ii,II)
RzILOpEffect *hex_il_op_s2_extractu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: st32 offset;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// U = U;
	RzILOpEffect *imm_assign_5 = SETL("U", U);

	// offset = ((st32) U);
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", CAST(32, IL_FALSE, VARL("U")));

	// Rd = ((st32) ((width != 0x0) ? extract64(((ut64) (((ut32) Rs) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("offset"));
	RzILOpPure *cond_21 = ITE(op_NE_12, EXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_15), SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_21));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_23);
	return instruction_sequence;
}

// Rd = extractu(Rs,Rtt)
RzILOpEffect *hex_il_op_s2_extractu_rp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: st32 width;
	// Declare: st32 offset;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// width = ((st32) extract64(((ut64) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x6));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_18 = SETL("width", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9)))), SN(32, 0), SN(32, 6))));

	// offset = ((st32) sextract64(((ut64) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x7));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_37 = SETL("offset", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_28), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))));

	// Rd = ((st32) ((width != 0x0) ? extract64(((offset < 0x0) ? ((((ut64) ((ut32) ((ut64) ((ut32) Rs)))) << (-offset) - 0x1) << 0x1) : (((ut64) ((ut32) ((ut64) ((ut32) Rs)))) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_41 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_43 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_49 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_51 = SUB(op_NEG_49, SN(32, 1));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)))), op_SUB_51);
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(op_LSHIFT_52, SN(32, 1));
	RzILOpPure *op_RSHIFT_59 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))))), VARL("offset"));
	RzILOpPure *cond_60 = ITE(op_LT_43, op_LSHIFT_54, op_RSHIFT_59);
	RzILOpPure *cond_65 = ITE(op_NE_41, EXTRACT64(cond_60, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_67 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_65));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_18, op_ASSIGN_37, op_ASSIGN_67);
	return instruction_sequence;
}

// Rdd = extractu(Rss,Ii,II)
RzILOpEffect *hex_il_op_s2_extractup(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: st32 offset;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// U = U;
	RzILOpEffect *imm_assign_5 = SETL("U", U);

	// offset = ((st32) U);
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", CAST(32, IL_FALSE, VARL("U")));

	// Rdd = ((st64) ((width != 0x0) ? extract64((((ut64) Rss) >> offset), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("offset"));
	RzILOpPure *cond_20 = ITE(op_NE_12, EXTRACT64(op_RSHIFT_15, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_20));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_22);
	return instruction_sequence;
}

// Rdd = extractu(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_extractup_rp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: st32 width;
	// Declare: st32 offset;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// width = ((st32) extract64(((ut64) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x6));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_18 = SETL("width", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9)))), SN(32, 0), SN(32, 6))));

	// offset = ((st32) sextract64(((ut64) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x7));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_37 = SETL("offset", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_28), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))));

	// Rdd = ((st64) ((width != 0x0) ? extract64(((offset < 0x0) ? ((((ut64) Rss) << (-offset) - 0x1) << 0x1) : (((ut64) Rss) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_41 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_43 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_46 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_48 = SUB(op_NEG_46, SN(32, 1));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_48);
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(op_LSHIFT_49, SN(32, 1));
	RzILOpPure *op_RSHIFT_53 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("offset"));
	RzILOpPure *cond_54 = ITE(op_LT_43, op_LSHIFT_51, op_RSHIFT_53);
	RzILOpPure *cond_59 = ITE(op_NE_41, EXTRACT64(cond_54, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_61 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_59));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_18, op_ASSIGN_37, op_ASSIGN_61);
	return instruction_sequence;
}

// Rx = insert(Rs,Ii,II)
RzILOpEffect *hex_il_op_s2_insert(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: st32 offset;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// U = U;
	RzILOpEffect *imm_assign_5 = SETL("U", U);

	// offset = ((st32) U);
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", CAST(32, IL_FALSE, VARL("U")));

	// Rx = (Rx & ((st32) (~((0x1 << width) - ((st64) 0x1) << offset))));
	RzILOpPure *op_LSHIFT_12 = SHIFTL0(SN(64, 1), VARL("width"));
	RzILOpPure *op_SUB_15 = SUB(op_LSHIFT_12, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_SUB_15, VARL("offset"));
	RzILOpPure *op_NOT_17 = LOGNOT(op_LSHIFT_16);
	RzILOpPure *op_AND_19 = LOGAND(READ_REG(pkt, Rx_op, false), CAST(32, MSB(op_NOT_17), DUP(op_NOT_17)));
	RzILOpEffect *op_ASSIGN_AND_20 = WRITE_REG(bundle, Rx_op, op_AND_19);

	// Rx = (Rx | ((st32) ((((st64) Rs) & (0x1 << width) - ((st64) 0x1)) << offset)));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(SN(64, 1), VARL("width"));
	RzILOpPure *op_SUB_26 = SUB(op_LSHIFT_23, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_AND_28 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), op_SUB_26);
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(op_AND_28, VARL("offset"));
	RzILOpPure *op_OR_31 = LOGOR(READ_REG(pkt, Rx_op, false), CAST(32, MSB(op_LSHIFT_29), DUP(op_LSHIFT_29)));
	RzILOpEffect *op_ASSIGN_OR_32 = WRITE_REG(bundle, Rx_op, op_OR_31);

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_AND_20, op_ASSIGN_OR_32);
	return instruction_sequence;
}

// Rx = insert(Rs,Rtt)
RzILOpEffect *hex_il_op_s2_insert_rp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: st32 width;
	// Declare: st32 offset;
	// Declare: ut64 mask;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// width = ((st32) extract64(((ut64) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x6));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_18 = SETL("width", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9)))), SN(32, 0), SN(32, 6))));

	// offset = ((st32) sextract64(((ut64) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x7));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_37 = SETL("offset", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_28), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))));

	// mask = ((ut64) (0x1 << width) - ((st64) 0x1));
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(SN(64, 1), VARL("width"));
	RzILOpPure *op_SUB_43 = SUB(op_LSHIFT_40, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpEffect *op_ASSIGN_45 = SETL("mask", CAST(64, IL_FALSE, op_SUB_43));

	// Rx = 0x0;
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rx_op, SN(32, 0));

	// Rx = (Rx & ((st32) (~(mask << offset))));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(VARL("mask"), VARL("offset"));
	RzILOpPure *op_NOT_53 = LOGNOT(op_LSHIFT_52);
	RzILOpPure *op_AND_55 = LOGAND(READ_REG(pkt, Rx_op, false), CAST(32, IL_FALSE, op_NOT_53));
	RzILOpEffect *op_ASSIGN_AND_56 = WRITE_REG(bundle, Rx_op, op_AND_55);

	// Rx = (Rx | ((st32) ((((ut64) Rs) & mask) << offset)));
	RzILOpPure *op_AND_59 = LOGAND(CAST(64, IL_FALSE, Rs), VARL("mask"));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_AND_59, VARL("offset"));
	RzILOpPure *op_OR_62 = LOGOR(READ_REG(pkt, Rx_op, false), CAST(32, IL_FALSE, op_LSHIFT_60));
	RzILOpEffect *op_ASSIGN_OR_63 = WRITE_REG(bundle, Rx_op, op_OR_62);

	// seq(Rx = 0x0);
	RzILOpEffect *seq_then_64 = op_ASSIGN_51;

	// seq(Rx = (Rx & ((st32) (~(mask << offset)))); Rx = (Rx | ((st32) ...;
	RzILOpEffect *seq_else_65 = SEQN(2, op_ASSIGN_AND_56, op_ASSIGN_OR_63);

	// if ((offset < 0x0)) {seq(Rx = 0x0)} else {seq(Rx = (Rx & ((st32) (~(mask << offset)))); Rx = (Rx | ((st32) ...};
	RzILOpPure *op_LT_48 = SLT(VARL("offset"), SN(32, 0));
	RzILOpEffect *branch_66 = BRANCH(op_LT_48, seq_then_64, seq_else_65);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_18, op_ASSIGN_37, op_ASSIGN_45, branch_66);
	return instruction_sequence;
}

// Rxx = insert(Rss,Ii,II)
RzILOpEffect *hex_il_op_s2_insertp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: st32 offset;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// U = U;
	RzILOpEffect *imm_assign_5 = SETL("U", U);

	// offset = ((st32) U);
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", CAST(32, IL_FALSE, VARL("U")));

	// Rxx = (Rxx & (~((0x1 << width) - ((st64) 0x1) << offset)));
	RzILOpPure *op_LSHIFT_12 = SHIFTL0(SN(64, 1), VARL("width"));
	RzILOpPure *op_SUB_15 = SUB(op_LSHIFT_12, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_SUB_15, VARL("offset"));
	RzILOpPure *op_NOT_17 = LOGNOT(op_LSHIFT_16);
	RzILOpPure *op_AND_18 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_17);
	RzILOpEffect *op_ASSIGN_AND_19 = WRITE_REG(bundle, Rxx_op, op_AND_18);

	// Rxx = (Rxx | ((Rss & (0x1 << width) - ((st64) 0x1)) << offset));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(SN(64, 1), VARL("width"));
	RzILOpPure *op_SUB_25 = SUB(op_LSHIFT_22, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_AND_26 = LOGAND(Rss, op_SUB_25);
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(op_AND_26, VARL("offset"));
	RzILOpPure *op_OR_28 = LOGOR(READ_REG(pkt, Rxx_op, false), op_LSHIFT_27);
	RzILOpEffect *op_ASSIGN_OR_29 = WRITE_REG(bundle, Rxx_op, op_OR_28);

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_AND_19, op_ASSIGN_OR_29);
	return instruction_sequence;
}

// Rxx = insert(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_insertp_rp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: st32 width;
	// Declare: st32 offset;
	// Declare: ut64 mask;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// width = ((st32) extract64(((ut64) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x6));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_18 = SETL("width", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9)))), SN(32, 0), SN(32, 6))));

	// offset = ((st32) sextract64(((ut64) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x7));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_37 = SETL("offset", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_28), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))));

	// mask = ((ut64) (0x1 << width) - ((st64) 0x1));
	RzILOpPure *op_LSHIFT_40 = SHIFTL0(SN(64, 1), VARL("width"));
	RzILOpPure *op_SUB_43 = SUB(op_LSHIFT_40, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpEffect *op_ASSIGN_45 = SETL("mask", CAST(64, IL_FALSE, op_SUB_43));

	// Rxx = ((st64) 0x0);
	RzILOpEffect *op_ASSIGN_52 = WRITE_REG(bundle, Rxx_op, CAST(64, MSB(SN(32, 0)), SN(32, 0)));

	// Rxx = (Rxx & ((st64) (~(mask << offset))));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("mask"), VARL("offset"));
	RzILOpPure *op_NOT_54 = LOGNOT(op_LSHIFT_53);
	RzILOpPure *op_AND_56 = LOGAND(READ_REG(pkt, Rxx_op, false), CAST(64, IL_FALSE, op_NOT_54));
	RzILOpEffect *op_ASSIGN_AND_57 = WRITE_REG(bundle, Rxx_op, op_AND_56);

	// Rxx = (Rxx | ((st64) ((((ut64) Rss) & mask) << offset)));
	RzILOpPure *op_AND_60 = LOGAND(CAST(64, IL_FALSE, Rss), VARL("mask"));
	RzILOpPure *op_LSHIFT_61 = SHIFTL0(op_AND_60, VARL("offset"));
	RzILOpPure *op_OR_63 = LOGOR(READ_REG(pkt, Rxx_op, false), CAST(64, IL_FALSE, op_LSHIFT_61));
	RzILOpEffect *op_ASSIGN_OR_64 = WRITE_REG(bundle, Rxx_op, op_OR_63);

	// seq(Rxx = ((st64) 0x0));
	RzILOpEffect *seq_then_65 = op_ASSIGN_52;

	// seq(Rxx = (Rxx & ((st64) (~(mask << offset)))); Rxx = (Rxx | ((s ...;
	RzILOpEffect *seq_else_66 = SEQN(2, op_ASSIGN_AND_57, op_ASSIGN_OR_64);

	// if ((offset < 0x0)) {seq(Rxx = ((st64) 0x0))} else {seq(Rxx = (Rxx & ((st64) (~(mask << offset)))); Rxx = (Rxx | ((s ...};
	RzILOpPure *op_LT_48 = SLT(VARL("offset"), SN(32, 0));
	RzILOpEffect *branch_67 = BRANCH(op_LT_48, seq_then_65, seq_else_66);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_18, op_ASSIGN_37, op_ASSIGN_45, branch_67);
	return instruction_sequence;
}

// Rdd = interleave(Rss)
RzILOpEffect *hex_il_op_s2_interleave(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = lfs(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_lfsp(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = lsl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rdd = ((st64) ((shamt < 0x0) ? ((((ut64) Rss) >> (-shamt) - 0x1) >> 0x1) : (((ut64) Rss) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_25));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_27);
	return instruction_sequence;
}

// Rxx += lsl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) ((ut64) Rxx) + ((shamt < 0x0) ? ((((ut64) Rss) >> (-shamt) - 0x1) >> 0x1) : (((ut64) Rss) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_ADD_27 = ADD(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_ADD_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx &= lsl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) (((ut64) Rxx) & ((shamt < 0x0) ? ((((ut64) Rss) >> (-shamt) - 0x1) >> 0x1) : (((ut64) Rss) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_AND_27 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_AND_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx -= lsl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) ((ut64) Rxx) - ((shamt < 0x0) ? ((((ut64) Rss) >> (-shamt) - 0x1) >> 0x1) : (((ut64) Rss) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_SUB_27 = SUB(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_SUB_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx |= lsl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) (((ut64) Rxx) | ((shamt < 0x0) ? ((((ut64) Rss) >> (-shamt) - 0x1) >> 0x1) : (((ut64) Rss) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_OR_27 = LOGOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx ^= lsl(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_p_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) (((ut64) Rxx) ^ ((shamt < 0x0) ? ((((ut64) Rss) >> (-shamt) - 0x1) >> 0x1) : (((ut64) Rss) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(op_RSHIFT_20, SN(32, 1));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_RSHIFT_22, op_LSHIFT_24);
	RzILOpPure *op_XOR_27 = LOGXOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_XOR_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rd = lsl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rd = ((st32) ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) >> (-shamt) - 0x1) >> 0x1) : (((ut64) ((ut32) Rs)) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_RSHIFT_23 = SHIFTR0(op_RSHIFT_21, SN(32, 1));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_RSHIFT_23, op_LSHIFT_26);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx += lsl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((ut64) Rx) + ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) >> (-shamt) - 0x1) >> 0x1) : (((ut64) ((ut32) Rs)) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_RSHIFT_23 = SHIFTR0(op_RSHIFT_21, SN(32, 1));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_RSHIFT_23, op_LSHIFT_26);
	RzILOpPure *op_ADD_29 = ADD(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_ADD_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rx &= lsl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((ut64) Rx) & ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) >> (-shamt) - 0x1) >> 0x1) : (((ut64) ((ut32) Rs)) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_RSHIFT_23 = SHIFTR0(op_RSHIFT_21, SN(32, 1));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_RSHIFT_23, op_LSHIFT_26);
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_AND_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rx -= lsl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((ut64) Rx) - ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) >> (-shamt) - 0x1) >> 0x1) : (((ut64) ((ut32) Rs)) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_RSHIFT_23 = SHIFTR0(op_RSHIFT_21, SN(32, 1));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_RSHIFT_23, op_LSHIFT_26);
	RzILOpPure *op_SUB_29 = SUB(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rx |= lsl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((ut64) Rx) | ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) >> (-shamt) - 0x1) >> 0x1) : (((ut64) ((ut32) Rs)) << shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_RSHIFT_23 = SHIFTR0(op_RSHIFT_21, SN(32, 1));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_RSHIFT_23, op_LSHIFT_26);
	RzILOpPure *op_OR_29 = LOGOR(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rdd = vlslh(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp496 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp496", VARL("i"));

	// seq(h_tmp496 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) << sextract64(((ut64) Rt), 0x0, 0x7))) & ((ut64) 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_45 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_48 = SUB(op_NEG_45, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_49 = SHIFTR0(CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_34)), op_SUB_48);
	RzILOpPure *op_RSHIFT_51 = SHIFTR0(op_RSHIFT_49, SN(32, 1));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_68 = SHIFTL0(CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_57)), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_69 = ITE(op_LT_27, op_RSHIFT_51, op_LSHIFT_68);
	RzILOpPure *op_AND_72 = LOGAND(cond_69, CAST(64, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_MUL_74 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_75 = SHIFTL0(op_AND_72, op_MUL_74);
	RzILOpPure *op_OR_77 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_75);
	RzILOpEffect *op_ASSIGN_79 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_77));

	// seq(h_tmp496; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_81 = op_ASSIGN_79;

	// seq(seq(h_tmp496; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_82 = SEQN(2, seq_81, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp496; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_83 = REPEAT(op_LT_4, seq_82);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp496; Rdd = ((st64) ...;
	RzILOpEffect *seq_84 = SEQN(2, op_ASSIGN_2, for_83);

	RzILOpEffect *instruction_sequence = seq_84;
	return instruction_sequence;
}

// Rdd = vlslw(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsl_r_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp497 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp497", VARL("i"));

	// seq(h_tmp497 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))))) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut32) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))))) << sextract64(((ut64) Rt), 0x0, 0x7))) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_46 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_49 = SUB(op_NEG_46, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_50 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_33)))), op_SUB_49);
	RzILOpPure *op_RSHIFT_52 = SHIFTR0(op_RSHIFT_50, SN(32, 1));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_55, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_70 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_57)))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_71 = ITE(op_LT_27, op_RSHIFT_52, op_LSHIFT_70);
	RzILOpPure *op_AND_74 = LOGAND(cond_71, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_76 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_77 = SHIFTL0(op_AND_74, op_MUL_76);
	RzILOpPure *op_OR_79 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_77);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_79));

	// seq(h_tmp497; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * ...;
	RzILOpEffect *seq_83 = op_ASSIGN_81;

	// seq(seq(h_tmp497; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << ...;
	RzILOpEffect *seq_84 = SEQN(2, seq_83, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp497; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_85 = REPEAT(op_LT_4, seq_84);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp497; Rdd = ((st64) ...;
	RzILOpEffect *seq_86 = SEQN(2, op_ASSIGN_2, for_85);

	RzILOpEffect *instruction_sequence = seq_86;
	return instruction_sequence;
}

// Rdd = lsr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rdd = ((st64) ((u >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_13));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_15);
	return instruction_sequence;
}

// Rxx += lsr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) ((ut64) Rxx) + ((u >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_ADD_15 = ADD(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_ADD_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rxx &= lsr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) (((ut64) Rxx) & ((u >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u))));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_AND_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rxx -= lsr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) ((ut64) Rxx) - ((u >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_SUB_15 = SUB(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_SUB_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rxx |= lsr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) (((ut64) Rxx) | ((u >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u))));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_OR_15 = LOGOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rxx ^= lsr(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_p_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) (((ut64) Rxx) ^ ((u >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u))));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_XOR_15 = LOGXOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_XOR_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rd = lsr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rd = ((st32) ((u >= ((ut32) 0x20)) ? ((ut32) 0x0) : (((ut32) Rs) >> u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(32, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_13));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_15);
	return instruction_sequence;
}

// Rx += lsr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) ((ut32) Rx) + ((u >= ((ut32) 0x20)) ? ((ut32) 0x0) : (((ut32) Rs) >> u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(32, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_ADD_15 = ADD(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_ADD_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rx &= lsr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) (((ut32) Rx) & ((u >= ((ut32) 0x20)) ? ((ut32) 0x0) : (((ut32) Rs) >> u))));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(32, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_AND_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rx -= lsr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) ((ut32) Rx) - ((u >= ((ut32) 0x20)) ? ((ut32) 0x0) : (((ut32) Rs) >> u)));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(32, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_SUB_15 = SUB(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rx |= lsr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) (((ut32) Rx) | ((u >= ((ut32) 0x20)) ? ((ut32) 0x0) : (((ut32) Rs) >> u))));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(32, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_OR_15 = LOGOR(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rx ^= lsr(Rs,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_r_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) (((ut32) Rx) ^ ((u >= ((ut32) 0x20)) ? ((ut32) 0x0) : (((ut32) Rs) >> u))));
	RzILOpPure *op_GE_8 = UGE(VARL("u"), CAST(32, IL_FALSE, SN(32, 0x20)));
	RzILOpPure *op_RSHIFT_11 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_13 = ITE(op_GE_8, CAST(32, IL_FALSE, SN(32, 0)), op_RSHIFT_11);
	RzILOpPure *op_XOR_15 = LOGXOR(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_13);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_XOR_15));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_17);
	return instruction_sequence;
}

// Rdd = vlsrh(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp498 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp498", VARL("i"));

	// seq(h_tmp498 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) (((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(16, IL_FALSE, op_AND_22), VARL("u"));
	RzILOpPure *op_AND_29 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_26), SN(32, 0xffff));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(CAST(64, IL_FALSE, op_AND_29), op_MUL_32);
	RzILOpPure *op_OR_35 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_35));

	// seq(h_tmp498; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_39 = op_ASSIGN_37;

	// seq(seq(h_tmp498; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_39, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp498; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_41 = REPEAT(op_LT_4, seq_40);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp498; Rdd = ((st64) ...;
	RzILOpEffect *seq_42 = SEQN(2, op_ASSIGN_2, for_41);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_42);
	return instruction_sequence;
}

// Rdd = vlsrw(Rss,Ii)
RzILOpEffect *hex_il_op_s2_lsr_i_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp499 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp499", VARL("i"));

	// seq(h_tmp499 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | (((((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))) >> u) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_21)), VARL("u"));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_26, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_32 = SHIFTL0(op_AND_29, op_MUL_31);
	RzILOpPure *op_OR_34 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_32);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_34));

	// seq(h_tmp499; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * ...;
	RzILOpEffect *seq_38 = op_ASSIGN_36;

	// seq(seq(h_tmp499; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << ...;
	RzILOpEffect *seq_39 = SEQN(2, seq_38, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp499; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_40 = REPEAT(op_LT_4, seq_39);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp499; Rdd = ((st64) ...;
	RzILOpEffect *seq_41 = SEQN(2, op_ASSIGN_2, for_40);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_41);
	return instruction_sequence;
}

// Rdd = lsr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rdd = ((st64) ((shamt < 0x0) ? ((((ut64) Rss) << (-shamt) - 0x1) << 0x1) : (((ut64) Rss) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_25));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_27);
	return instruction_sequence;
}

// Rxx += lsr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) ((ut64) Rxx) + ((shamt < 0x0) ? ((((ut64) Rss) << (-shamt) - 0x1) << 0x1) : (((ut64) Rss) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_ADD_27 = ADD(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_ADD_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx &= lsr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) (((ut64) Rxx) & ((shamt < 0x0) ? ((((ut64) Rss) << (-shamt) - 0x1) << 0x1) : (((ut64) Rss) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_AND_27 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_AND_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx -= lsr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) ((ut64) Rxx) - ((shamt < 0x0) ? ((((ut64) Rss) << (-shamt) - 0x1) << 0x1) : (((ut64) Rss) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_SUB_27 = SUB(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_SUB_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx |= lsr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) (((ut64) Rxx) | ((shamt < 0x0) ? ((((ut64) Rss) << (-shamt) - 0x1) << 0x1) : (((ut64) Rss) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_OR_27 = LOGOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rxx ^= lsr(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_p_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rxx = ((st64) (((ut64) Rxx) ^ ((shamt < 0x0) ? ((((ut64) Rss) << (-shamt) - 0x1) << 0x1) : (((ut64) Rss) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_17 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_19 = SUB(op_NEG_17, SN(32, 1));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_19);
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(op_LSHIFT_20, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("shamt"));
	RzILOpPure *cond_25 = ITE(op_LT_14, op_LSHIFT_22, op_RSHIFT_24);
	RzILOpPure *op_XOR_27 = LOGXOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_25);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_XOR_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rd = lsr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rd = ((st32) ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) << (-shamt) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpEffect *op_ASSIGN_29 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_27));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_29);
	return instruction_sequence;
}

// Rx += lsr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((ut64) Rx) + ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) << (-shamt) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *op_ADD_29 = ADD(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_ADD_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rx &= lsr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((ut64) Rx) & ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) << (-shamt) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_AND_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rx -= lsr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) ((ut64) Rx) - ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) << (-shamt) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *op_SUB_29 = SUB(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rx |= lsr(Rs,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// Rx = ((st32) (((ut64) Rx) | ((shamt < 0x0) ? ((((ut64) ((ut32) Rs)) << (-shamt) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> shamt))));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("shamt"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *op_OR_29 = LOGOR(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_27);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_29));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_10, op_ASSIGN_31);
	return instruction_sequence;
}

// Rdd = vlsrh(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_vh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp500 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp500", VARL("i"));

	// seq(h_tmp500 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) << (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) << 0x1) : (((ut64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) >> sextract64(((ut64) Rt), 0x0, 0x7))) & ((ut64) 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_45 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_48 = SUB(op_NEG_45, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_34)), op_SUB_48);
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(op_LSHIFT_49, SN(32, 1));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_68 = SHIFTR0(CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_57)), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_69 = ITE(op_LT_27, op_LSHIFT_51, op_RSHIFT_68);
	RzILOpPure *op_AND_72 = LOGAND(cond_69, CAST(64, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_MUL_74 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_75 = SHIFTL0(op_AND_72, op_MUL_74);
	RzILOpPure *op_OR_77 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_75);
	RzILOpEffect *op_ASSIGN_79 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_77));

	// seq(h_tmp500; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_81 = op_ASSIGN_79;

	// seq(seq(h_tmp500; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_82 = SEQN(2, seq_81, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp500; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_83 = REPEAT(op_LT_4, seq_82);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp500; Rdd = ((st64) ...;
	RzILOpEffect *seq_84 = SEQN(2, op_ASSIGN_2, for_83);

	RzILOpEffect *instruction_sequence = seq_84;
	return instruction_sequence;
}

// Rdd = vlsrw(Rss,Rt)
RzILOpEffect *hex_il_op_s2_lsr_r_vw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp501 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp501", VARL("i"));

	// seq(h_tmp501 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * 0x20)))) | ((((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))))) << (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) << 0x1) : (((ut64) ((ut32) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))))) >> sextract64(((ut64) Rt), 0x0, 0x7))) & ((ut64) 0xffffffff)) << i * 0x20)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_LT_27 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rss, op_MUL_30);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpPure *op_NEG_46 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_49 = SUB(op_NEG_46, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_33)))), op_SUB_49);
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(op_LSHIFT_50, SN(32, 1));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_55, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_70 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_57)))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_71 = ITE(op_LT_27, op_LSHIFT_52, op_RSHIFT_70);
	RzILOpPure *op_AND_74 = LOGAND(cond_71, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_MUL_76 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_77 = SHIFTL0(op_AND_74, op_MUL_76);
	RzILOpPure *op_OR_79 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_77);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_79));

	// seq(h_tmp501; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << i * ...;
	RzILOpEffect *seq_83 = op_ASSIGN_81;

	// seq(seq(h_tmp501; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << ...;
	RzILOpEffect *seq_84 = SEQN(2, seq_83, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp501; Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_85 = REPEAT(op_LT_4, seq_84);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp501; Rdd = ((st64) ...;
	RzILOpEffect *seq_86 = SEQN(2, op_ASSIGN_2, for_85);

	RzILOpEffect *instruction_sequence = seq_86;
	return instruction_sequence;
}

// Rd = mask(Ii,II)
RzILOpEffect *hex_il_op_s2_mask(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_7 = SETL("U", U);

	// Rd = ((0x1 << u) - 0x1 << U);
	RzILOpPure *op_LSHIFT_4 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_SUB_6 = SUB(op_LSHIFT_4, SN(32, 1));
	RzILOpPure *op_LSHIFT_9 = SHIFTL0(op_SUB_6, VARL("U"));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, op_LSHIFT_9);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_7, op_ASSIGN_10);
	return instruction_sequence;
}

// Rdd = packhl(Rs,Rt)
RzILOpEffect *hex_il_op_s2_packhl(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((st16) ((Rt >> 0x0) & 0xffff))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xffff));
	RzILOpPure *op_AND_18 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_14), DUP(op_AND_14))), CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(CAST(64, IL_FALSE, op_AND_18), SN(32, 0));
	RzILOpPure *op_OR_25 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_23);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_25));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st32) ((st16) ((Rs >> 0x0) & 0xffff))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_34 = LOGNOT(op_LSHIFT_33);
	RzILOpPure *op_AND_35 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_34);
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_40, SN(32, 0xffff));
	RzILOpPure *op_AND_46 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_42), DUP(op_AND_42))), CAST(16, MSB(DUP(op_AND_42)), DUP(op_AND_42))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(CAST(64, IL_FALSE, op_AND_46), SN(32, 16));
	RzILOpPure *op_OR_53 = LOGOR(CAST(64, IL_FALSE, op_AND_35), op_LSHIFT_51);
	RzILOpEffect *op_ASSIGN_55 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_53));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((st16) ((Rt >> 0x10) & 0xffff))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_61 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_62 = LOGNOT(op_LSHIFT_61);
	RzILOpPure *op_AND_63 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_62);
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_67, SN(32, 0xffff));
	RzILOpPure *op_AND_73 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_69), DUP(op_AND_69))), CAST(16, MSB(DUP(op_AND_69)), DUP(op_AND_69))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_78 = SHIFTL0(CAST(64, IL_FALSE, op_AND_73), SN(32, 0x20));
	RzILOpPure *op_OR_80 = LOGOR(CAST(64, IL_FALSE, op_AND_63), op_LSHIFT_78);
	RzILOpEffect *op_ASSIGN_82 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_80));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st32) ((st16) ((Rs >> 0x10) & 0xffff))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_89 = LOGNOT(op_LSHIFT_88);
	RzILOpPure *op_AND_90 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_89);
	RzILOpPure *op_RSHIFT_94 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_96 = LOGAND(op_RSHIFT_94, SN(32, 0xffff));
	RzILOpPure *op_AND_100 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_96), DUP(op_AND_96))), CAST(16, MSB(DUP(op_AND_96)), DUP(op_AND_96))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_105 = SHIFTL0(CAST(64, IL_FALSE, op_AND_100), SN(32, 0x30));
	RzILOpPure *op_OR_107 = LOGOR(CAST(64, IL_FALSE, op_AND_90), op_LSHIFT_105);
	RzILOpEffect *op_ASSIGN_109 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_107));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_27, op_ASSIGN_55, op_ASSIGN_82, op_ASSIGN_109);
	return instruction_sequence;
}

// Rd = parity(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_parityp(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) memb(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerbf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_21_22 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_24 = ms_cast_ut8_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv) memb(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerbf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut8_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerbfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut8_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv) memb(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerbnewf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_21_22 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_24 = ms_cast_ut8_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv) memb(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerbnewf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut8_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerbnewfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut8_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (Pv) memb(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerbnewt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_20_21 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_23 = ms_cast_ut8_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv) memb(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerbnewt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut8_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memb(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerbnewtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut8_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv) memb(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerbt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_20_21 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_23 = ms_cast_ut8_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv) memb(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerbt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut8_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memb(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerbtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut8_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) &  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (!Pv) memd(Rs+Ii) = Rtt
RzILOpEffect *hex_il_op_s2_pstorerdf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_14_15 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_17 = ms_cast_ut64_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_19 = BRANCH(op_INV_12, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (!Pv) memd(Rx++Ii) = Rtt
RzILOpEffect *hex_il_op_s2_pstorerdf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_16_17 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, ms_cast_ut64_16_17);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_21 = BRANCH(op_INV_9, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_21);
	return instruction_sequence;
}

// if (!Pv.new) memd(Rx++Ii) = Rtt
RzILOpEffect *hex_il_op_s2_pstorerdfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_16_17 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, ms_cast_ut64_16_17);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_21 = BRANCH(op_INV_9, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_21);
	return instruction_sequence;
}

// if (Pv) memd(Rs+Ii) = Rtt
RzILOpEffect *hex_il_op_s2_pstorerdt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_13_14 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_15 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_16 = ms_cast_ut64_13_14;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_17 = c_call_15;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_11), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_18);
	return instruction_sequence;
}

// if (Pv) memd(Rx++Ii) = Rtt
RzILOpEffect *hex_il_op_s2_pstorerdt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_15_16 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, ms_cast_ut64_15_16);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_8), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_20);
	return instruction_sequence;
}

// if (Pv.new) memd(Rx++Ii) = Rtt
RzILOpEffect *hex_il_op_s2_pstorerdtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_15_16 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, ms_cast_ut64_15_16);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_8), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_20);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_pstorerff_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_24 = ms_cast_ut16_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv) memh(Rx++Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_pstorerff_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut16_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rx++Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_pstorerffnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut16_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_pstorerft_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_23 = ms_cast_ut16_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv) memh(Rx++Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_pstorerft_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut16_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memh(Rx++Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_pstorerftnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut16_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10 ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerhf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_24 = ms_cast_ut16_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv) memh(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerhf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut16_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerhfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut16_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerhnewf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_24 = ms_cast_ut16_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv) memh(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerhnewf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut16_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerhnewfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...;
	RzILOpEffect *seq_then_26 = SEQN(2, op_ASSIGN_13, ms_cast_ut16_23_24);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_28 = BRANCH(op_INV_9, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_28);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerhnewt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_23 = ms_cast_ut16_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv) memh(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerhnewt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut16_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memh(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerhnewtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut16_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >>  ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerht_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_23 = ms_cast_ut16_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv) memh(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerht_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut16_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memh(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerhtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...;
	RzILOpEffect *seq_then_25 = SEQN(2, op_ASSIGN_12, ms_cast_ut16_22_23);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_8), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_27);
	return instruction_sequence;
}

// if (!Pv) memw(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerif_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_17 = ms_cast_ut32_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_19 = BRANCH(op_INV_12, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (!Pv) memw(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerif_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, ms_cast_ut32_16_17);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_21 = BRANCH(op_INV_9, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_21);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerifnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, ms_cast_ut32_16_17);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_21 = BRANCH(op_INV_9, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_21);
	return instruction_sequence;
}

// if (!Pv) memw(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerinewf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_17 = ms_cast_ut32_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_19 = BRANCH(op_INV_12, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (!Pv) memw(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerinewf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, ms_cast_ut32_16_17);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_21 = BRANCH(op_INV_9, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_21);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerinewfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, ms_cast_ut32_16_17);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_21 = BRANCH(op_INV_9, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_21);
	return instruction_sequence;
}

// if (Pv) memw(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerinewt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_13_14 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_15 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_16 = ms_cast_ut32_13_14;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_17 = c_call_15;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_11), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_18);
	return instruction_sequence;
}

// if (Pv) memw(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerinewt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, ms_cast_ut32_15_16);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_8), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_20);
	return instruction_sequence;
}

// if (Pv.new) memw(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_pstorerinewtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, ms_cast_ut32_15_16);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_8), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_20);
	return instruction_sequence;
}

// if (Pv) memw(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerit_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_13_14 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_15 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_16 = ms_cast_ut32_13_14;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_17 = c_call_15;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_11), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_18);
	return instruction_sequence;
}

// if (Pv) memw(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstorerit_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, ms_cast_ut32_15_16);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_8), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_20);
	return instruction_sequence;
}

// if (Pv.new) memw(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_pstoreritnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, ms_cast_ut32_15_16);

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rx = Rx + s; mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_8), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_20);
	return instruction_sequence;
}

// Rd = setbit(Rs,Ii)
RzILOpEffect *hex_il_op_s2_setbit_i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Rd = (Rs | (0x1 << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_OR_6 = LOGOR(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, op_OR_6);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_7);
	return instruction_sequence;
}

// Rd = setbit(Rs,Rt)
RzILOpEffect *hex_il_op_s2_setbit_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) (((ut64) Rs) | ((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) 0x1)) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut32) 0x1)) << sextract64(((ut64) Rt), 0x0, 0x7)))));
	RzILOpPure *op_LT_13 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_25 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_28 = SUB(op_NEG_25, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_29 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), op_SUB_28);
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(op_RSHIFT_29, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_44 = ITE(op_LT_13, op_RSHIFT_31, op_LSHIFT_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, Rs), cond_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_46));

	RzILOpEffect *instruction_sequence = op_ASSIGN_48;
	return instruction_sequence;
}

// Rdd = shuffeb(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_shuffeb(HexInsnPktBundle *bundle) {
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

	// h_tmp502 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp502", VARL("i"));

	// seq(h_tmp502 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x2 * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rtt >> i * 0x2 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x2 * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_14 = MUL(op_MUL_12, SN(32, 8));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(64, 0xff), op_MUL_14);
	RzILOpPure *op_NOT_16 = LOGNOT(op_LSHIFT_15);
	RzILOpPure *op_AND_17 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_16);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_22 = MUL(op_MUL_20, SN(32, 8));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rtt, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_31 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_26), DUP(op_AND_26))), CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26))), CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26)))), SN(64, 0xff));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_36 = MUL(op_MUL_34, SN(32, 8));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(CAST(64, IL_FALSE, op_AND_31), op_MUL_36);
	RzILOpPure *op_OR_39 = LOGOR(CAST(64, IL_FALSE, op_AND_17), op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_39));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x2 + 0x1 * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rss >> i * 0x2 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x2 + 0x1 * 0x8)));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_47 = ADD(op_MUL_45, SN(32, 1));
	RzILOpPure *op_MUL_49 = MUL(op_ADD_47, SN(32, 8));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(SN(64, 0xff), op_MUL_49);
	RzILOpPure *op_NOT_51 = LOGNOT(op_LSHIFT_50);
	RzILOpPure *op_AND_52 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_51);
	RzILOpPure *op_MUL_55 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_57 = MUL(op_MUL_55, SN(32, 8));
	RzILOpPure *op_RSHIFT_58 = SHIFTRA(Rss, op_MUL_57);
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_66 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_61), DUP(op_AND_61))), CAST(8, MSB(DUP(op_AND_61)), DUP(op_AND_61)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_61)), DUP(op_AND_61))), CAST(8, MSB(DUP(op_AND_61)), DUP(op_AND_61)))), SN(64, 0xff));
	RzILOpPure *op_MUL_69 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_71 = ADD(op_MUL_69, SN(32, 1));
	RzILOpPure *op_MUL_73 = MUL(op_ADD_71, SN(32, 8));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(CAST(64, IL_FALSE, op_AND_66), op_MUL_73);
	RzILOpPure *op_OR_76 = LOGOR(CAST(64, IL_FALSE, op_AND_52), op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_78 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_76));

	// seq(h_tmp502; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x2 * ...;
	RzILOpEffect *seq_80 = SEQN(2, op_ASSIGN_41, op_ASSIGN_78);

	// seq(seq(h_tmp502; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_81 = SEQN(2, seq_80, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp502; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_82 = REPEAT(op_LT_4, seq_81);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp502; Rdd = ((st64) ...;
	RzILOpEffect *seq_83 = SEQN(2, op_ASSIGN_2, for_82);

	RzILOpEffect *instruction_sequence = seq_83;
	return instruction_sequence;
}

// Rdd = shuffeh(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_shuffeh(HexInsnPktBundle *bundle) {
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

	// h_tmp503 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp503", VARL("i"));

	// seq(h_tmp503 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x2 * 0x10)))) | (((ut64) (((st32) ((st16) ((Rtt >> i * 0x2 * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x2 * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_14 = MUL(op_MUL_12, SN(32, 16));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(64, 0xffff), op_MUL_14);
	RzILOpPure *op_NOT_16 = LOGNOT(op_LSHIFT_15);
	RzILOpPure *op_AND_17 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_16);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_22 = MUL(op_MUL_20, SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rtt, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_30 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_26), DUP(op_AND_26))), CAST(16, MSB(DUP(op_AND_26)), DUP(op_AND_26))), SN(32, 0xffff));
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_35 = MUL(op_MUL_33, SN(32, 16));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(CAST(64, IL_FALSE, op_AND_30), op_MUL_35);
	RzILOpPure *op_OR_38 = LOGOR(CAST(64, IL_FALSE, op_AND_17), op_LSHIFT_36);
	RzILOpEffect *op_ASSIGN_40 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_38));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x2 + 0x1 * 0x10)))) | (((ut64) (((st32) ((st16) ((Rss >> i * 0x2 * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x2 + 0x1 * 0x10)));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_46 = ADD(op_MUL_44, SN(32, 1));
	RzILOpPure *op_MUL_48 = MUL(op_ADD_46, SN(32, 16));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(SN(64, 0xffff), op_MUL_48);
	RzILOpPure *op_NOT_50 = LOGNOT(op_LSHIFT_49);
	RzILOpPure *op_AND_51 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_50);
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_56 = MUL(op_MUL_54, SN(32, 16));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(Rss, op_MUL_56);
	RzILOpPure *op_AND_60 = LOGAND(op_RSHIFT_57, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_64 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_60), DUP(op_AND_60))), CAST(16, MSB(DUP(op_AND_60)), DUP(op_AND_60))), SN(32, 0xffff));
	RzILOpPure *op_MUL_67 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_69 = ADD(op_MUL_67, SN(32, 1));
	RzILOpPure *op_MUL_71 = MUL(op_ADD_69, SN(32, 16));
	RzILOpPure *op_LSHIFT_72 = SHIFTL0(CAST(64, IL_FALSE, op_AND_64), op_MUL_71);
	RzILOpPure *op_OR_74 = LOGOR(CAST(64, IL_FALSE, op_AND_51), op_LSHIFT_72);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_74));

	// seq(h_tmp503; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x2 ...;
	RzILOpEffect *seq_78 = SEQN(2, op_ASSIGN_40, op_ASSIGN_76);

	// seq(seq(h_tmp503; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_79 = SEQN(2, seq_78, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp503; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_80 = REPEAT(op_LT_4, seq_79);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp503; Rdd = ((st64) ...;
	RzILOpEffect *seq_81 = SEQN(2, op_ASSIGN_2, for_80);

	RzILOpEffect *instruction_sequence = seq_81;
	return instruction_sequence;
}

// Rdd = shuffob(Rtt,Rss)
RzILOpEffect *hex_il_op_s2_shuffob(HexInsnPktBundle *bundle) {
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

	// h_tmp504 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp504", VARL("i"));

	// seq(h_tmp504 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x2 * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rss >> i * 0x2 + 0x1 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x2 * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_14 = MUL(op_MUL_12, SN(32, 8));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(64, 0xff), op_MUL_14);
	RzILOpPure *op_NOT_16 = LOGNOT(op_LSHIFT_15);
	RzILOpPure *op_AND_17 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_16);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_22 = ADD(op_MUL_20, SN(32, 1));
	RzILOpPure *op_MUL_24 = MUL(op_ADD_22, SN(32, 8));
	RzILOpPure *op_RSHIFT_25 = SHIFTRA(Rss, op_MUL_24);
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_25, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_33 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_28), DUP(op_AND_28))), CAST(8, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(8, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(64, 0xff));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_38 = MUL(op_MUL_36, SN(32, 8));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(CAST(64, IL_FALSE, op_AND_33), op_MUL_38);
	RzILOpPure *op_OR_41 = LOGOR(CAST(64, IL_FALSE, op_AND_17), op_LSHIFT_39);
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_41));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x2 + 0x1 * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rtt >> i * 0x2 + 0x1 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x2 + 0x1 * 0x8)));
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_49 = ADD(op_MUL_47, SN(32, 1));
	RzILOpPure *op_MUL_51 = MUL(op_ADD_49, SN(32, 8));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(SN(64, 0xff), op_MUL_51);
	RzILOpPure *op_NOT_53 = LOGNOT(op_LSHIFT_52);
	RzILOpPure *op_AND_54 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_53);
	RzILOpPure *op_MUL_57 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_59 = ADD(op_MUL_57, SN(32, 1));
	RzILOpPure *op_MUL_61 = MUL(op_ADD_59, SN(32, 8));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(Rtt, op_MUL_61);
	RzILOpPure *op_AND_65 = LOGAND(op_RSHIFT_62, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_70 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_65), DUP(op_AND_65))), CAST(8, MSB(DUP(op_AND_65)), DUP(op_AND_65)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_65)), DUP(op_AND_65))), CAST(8, MSB(DUP(op_AND_65)), DUP(op_AND_65)))), SN(64, 0xff));
	RzILOpPure *op_MUL_73 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_75 = ADD(op_MUL_73, SN(32, 1));
	RzILOpPure *op_MUL_77 = MUL(op_ADD_75, SN(32, 8));
	RzILOpPure *op_LSHIFT_78 = SHIFTL0(CAST(64, IL_FALSE, op_AND_70), op_MUL_77);
	RzILOpPure *op_OR_80 = LOGOR(CAST(64, IL_FALSE, op_AND_54), op_LSHIFT_78);
	RzILOpEffect *op_ASSIGN_82 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_80));

	// seq(h_tmp504; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x2 * ...;
	RzILOpEffect *seq_84 = SEQN(2, op_ASSIGN_43, op_ASSIGN_82);

	// seq(seq(h_tmp504; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_85 = SEQN(2, seq_84, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp504; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_86 = REPEAT(op_LT_4, seq_85);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp504; Rdd = ((st64) ...;
	RzILOpEffect *seq_87 = SEQN(2, op_ASSIGN_2, for_86);

	RzILOpEffect *instruction_sequence = seq_87;
	return instruction_sequence;
}

// Rdd = shuffoh(Rtt,Rss)
RzILOpEffect *hex_il_op_s2_shuffoh(HexInsnPktBundle *bundle) {
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

	// h_tmp505 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp505", VARL("i"));

	// seq(h_tmp505 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x2 * 0x10)))) | (((ut64) (((st32) ((st16) ((Rss >> i * 0x2 + 0x1 * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x2 * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_14 = MUL(op_MUL_12, SN(32, 16));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(64, 0xffff), op_MUL_14);
	RzILOpPure *op_NOT_16 = LOGNOT(op_LSHIFT_15);
	RzILOpPure *op_AND_17 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_16);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_22 = ADD(op_MUL_20, SN(32, 1));
	RzILOpPure *op_MUL_24 = MUL(op_ADD_22, SN(32, 16));
	RzILOpPure *op_RSHIFT_25 = SHIFTRA(Rss, op_MUL_24);
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_25, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_32 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_28), DUP(op_AND_28))), CAST(16, MSB(DUP(op_AND_28)), DUP(op_AND_28))), SN(32, 0xffff));
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_37 = MUL(op_MUL_35, SN(32, 16));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(CAST(64, IL_FALSE, op_AND_32), op_MUL_37);
	RzILOpPure *op_OR_40 = LOGOR(CAST(64, IL_FALSE, op_AND_17), op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_40));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x2 + 0x1 * 0x10)))) | (((ut64) (((st32) ((st16) ((Rtt >> i * 0x2 + 0x1 * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x2 + 0x1 * 0x10)));
	RzILOpPure *op_MUL_46 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_48 = ADD(op_MUL_46, SN(32, 1));
	RzILOpPure *op_MUL_50 = MUL(op_ADD_48, SN(32, 16));
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(SN(64, 0xffff), op_MUL_50);
	RzILOpPure *op_NOT_52 = LOGNOT(op_LSHIFT_51);
	RzILOpPure *op_AND_53 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_52);
	RzILOpPure *op_MUL_56 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_58 = ADD(op_MUL_56, SN(32, 1));
	RzILOpPure *op_MUL_60 = MUL(op_ADD_58, SN(32, 16));
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(Rtt, op_MUL_60);
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_61, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_68 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_64), DUP(op_AND_64))), CAST(16, MSB(DUP(op_AND_64)), DUP(op_AND_64))), SN(32, 0xffff));
	RzILOpPure *op_MUL_71 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_73 = ADD(op_MUL_71, SN(32, 1));
	RzILOpPure *op_MUL_75 = MUL(op_ADD_73, SN(32, 16));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(CAST(64, IL_FALSE, op_AND_68), op_MUL_75);
	RzILOpPure *op_OR_78 = LOGOR(CAST(64, IL_FALSE, op_AND_53), op_LSHIFT_76);
	RzILOpEffect *op_ASSIGN_80 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_78));

	// seq(h_tmp505; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x2 ...;
	RzILOpEffect *seq_82 = SEQN(2, op_ASSIGN_42, op_ASSIGN_80);

	// seq(seq(h_tmp505; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_83 = SEQN(2, seq_82, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp505; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_84 = REPEAT(op_LT_4, seq_83);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp505; Rdd = ((st64) ...;
	RzILOpEffect *seq_85 = SEQN(2, op_ASSIGN_2, for_84);

	RzILOpEffect *instruction_sequence = seq_85;
	return instruction_sequence;
}

// memb(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memb(Rx++Mu:brev) = Rt
RzILOpEffect *hex_il_op_s2_storerb_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp506 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp506", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp506 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp506;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp506"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp506 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_21_22 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_19), DUP(op_AND_19))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut8_21_22);
	return instruction_sequence;
}

// memb(Rx++Ii:circ(Mu)) = Rt
RzILOpEffect *hex_il_op_s2_storerb_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp507 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp507", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut8_22_23);
	return instruction_sequence;
}

// memb(Rx++I:circ(Mu)) = Rt
RzILOpEffect *hex_il_op_s2_storerb_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 0));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp508 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp508", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_40_41 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_38), DUP(op_AND_38))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut8_40_41);
	return instruction_sequence;
}

// memb(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerb_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut8_18_19);
	return instruction_sequence;
}

// memb(Rx++Mu) = Rt
RzILOpEffect *hex_il_op_s2_storerb_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_17_18 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_15), DUP(op_AND_15))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut8_17_18);
	return instruction_sequence;
}

// memb(gp+Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerbgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_15_16 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_13), DUP(op_AND_13))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut8_15_16);
	return instruction_sequence;
}

// memb(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memb(Rx++Mu:brev) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnew_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp509 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp509", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp509 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp509;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp509"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp509 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_21_22 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_19), DUP(op_AND_19))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut8_21_22);
	return instruction_sequence;
}

// memb(Rx++Ii:circ(Mu)) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnew_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp510 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp510", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut8_22_23);
	return instruction_sequence;
}

// memb(Rx++I:circ(Mu)) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnew_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 0));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp511 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp511", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_40_41 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_38), DUP(op_AND_38))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut8_40_41);
	return instruction_sequence;
}

// memb(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut8_18_19);
	return instruction_sequence;
}

// memb(Rx++Mu) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnew_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_17_18 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_15), DUP(op_AND_15))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut8_17_18);
	return instruction_sequence;
}

// memb(gp+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerbnewgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_15_16 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_13), DUP(op_AND_13))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut8_15_16);
	return instruction_sequence;
}

// memd(Rs+Ii) = Rtt
RzILOpEffect *hex_il_op_s2_storerd_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_9_10 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut64_9_10);
	return instruction_sequence;
}

// memd(Rx++Mu:brev) = Rtt
RzILOpEffect *hex_il_op_s2_storerd_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp512 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp512", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp512 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp512;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp512"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp512 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_14_15 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut64_14_15);
	return instruction_sequence;
}

// memd(Rx++Ii:circ(Mu)) = Rtt
RzILOpEffect *hex_il_op_s2_storerd_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp513 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp513", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_15_16 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut64_15_16);
	return instruction_sequence;
}

// memd(Rx++I:circ(Mu)) = Rtt
RzILOpEffect *hex_il_op_s2_storerd_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x3)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 3));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp514 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x3)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp514", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_33_34 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut64_33_34);
	return instruction_sequence;
}

// memd(Rx++Ii) = Rtt
RzILOpEffect *hex_il_op_s2_storerd_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_11_12 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut64_11_12);
	return instruction_sequence;
}

// memd(Rx++Mu) = Rtt
RzILOpEffect *hex_il_op_s2_storerd_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_10_11 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut64_10_11);
	return instruction_sequence;
}

// memd(gp+Ii) = Rtt
RzILOpEffect *hex_il_op_s2_storerdgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_8_9 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut64_8_9);
	return instruction_sequence;
}

// memh(Rs+Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_storerf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memh(Rx++Mu:brev) = Rt.h
RzILOpEffect *hex_il_op_s2_storerf_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp515 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp515", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp515 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp515;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp515"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp515 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut16_21_22);
	return instruction_sequence;
}

// memh(Rx++Ii:circ(Mu)) = Rt.h
RzILOpEffect *hex_il_op_s2_storerf_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp516 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp516", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut16_22_23);
	return instruction_sequence;
}

// memh(Rx++I:circ(Mu)) = Rt.h
RzILOpEffect *hex_il_op_s2_storerf_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp517 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp517", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_40_41 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_38), DUP(op_AND_38))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut16_40_41);
	return instruction_sequence;
}

// memh(Rx++Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_storerf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memh(Rx++Mu) = Rt.h
RzILOpEffect *hex_il_op_s2_storerf_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut16_17_18);
	return instruction_sequence;
}

// memh(gp+Ii) = Rt.h
RzILOpEffect *hex_il_op_s2_storerfgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_15_16 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_13), DUP(op_AND_13))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut16_15_16);
	return instruction_sequence;
}

// memh(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memh(Rx++Mu:brev) = Rt
RzILOpEffect *hex_il_op_s2_storerh_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp518 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp518", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp518 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp518;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp518"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp518 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut16_21_22);
	return instruction_sequence;
}

// memh(Rx++Ii:circ(Mu)) = Rt
RzILOpEffect *hex_il_op_s2_storerh_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp519 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp519", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut16_22_23);
	return instruction_sequence;
}

// memh(Rx++I:circ(Mu)) = Rt
RzILOpEffect *hex_il_op_s2_storerh_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp520 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp520", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_40_41 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_38), DUP(op_AND_38))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut16_40_41);
	return instruction_sequence;
}

// memh(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerh_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memh(Rx++Mu) = Rt
RzILOpEffect *hex_il_op_s2_storerh_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut16_17_18);
	return instruction_sequence;
}

// memh(gp+Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerhgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_15_16 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_13), DUP(op_AND_13))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut16_15_16);
	return instruction_sequence;
}

// memh(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memh(Rx++Mu:brev) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnew_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp521 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp521", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp521 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp521;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp521"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp521 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut16_21_22);
	return instruction_sequence;
}

// memh(Rx++Ii:circ(Mu)) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnew_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp522 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp522", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut16_22_23);
	return instruction_sequence;
}

// memh(Rx++I:circ(Mu)) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnew_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp523 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp523", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_36 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_36, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_40_41 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_38), DUP(op_AND_38))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut16_40_41);
	return instruction_sequence;
}

// memh(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memh(Rx++Mu) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnew_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut16_17_18);
	return instruction_sequence;
}

// memh(gp+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerhnewgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_15_16 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_13), DUP(op_AND_13))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut16_15_16);
	return instruction_sequence;
}

// memw(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s2_storeri_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_9_10 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut32_9_10);
	return instruction_sequence;
}

// memw(Rx++Mu:brev) = Rt
RzILOpEffect *hex_il_op_s2_storeri_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp524 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp524", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp524 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp524;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp524"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp524 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut32_14_15);
	return instruction_sequence;
}

// memw(Rx++Ii:circ(Mu)) = Rt
RzILOpEffect *hex_il_op_s2_storeri_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp525 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp525", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut32_15_16);
	return instruction_sequence;
}

// memw(Rx++I:circ(Mu)) = Rt
RzILOpEffect *hex_il_op_s2_storeri_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 2));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp526 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp526", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_33_34 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut32_33_34);
	return instruction_sequence;
}

// memw(Rx++Ii) = Rt
RzILOpEffect *hex_il_op_s2_storeri_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut32_11_12);
	return instruction_sequence;
}

// memw(Rx++Mu) = Rt
RzILOpEffect *hex_il_op_s2_storeri_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut32_10_11);
	return instruction_sequence;
}

// memw(gp+Ii) = Rt
RzILOpEffect *hex_il_op_s2_storerigp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_8_9 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut32_8_9);
	return instruction_sequence;
}

// memw(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_9_10 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, ms_cast_ut32_9_10);
	return instruction_sequence;
}

// memw(Rx++Mu:brev) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinew_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp527 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp527", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp527 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp527;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp527"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp527 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, ms_cast_ut32_14_15);
	return instruction_sequence;
}

// memw(Rx++Ii:circ(Mu)) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinew_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp528 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp528", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, ms_cast_ut32_15_16);
	return instruction_sequence;
}

// memw(Rx++I:circ(Mu)) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinew_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 2));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp529 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp529", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_33_34 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, ms_cast_ut32_33_34);
	return instruction_sequence;
}

// memw(Rx++Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, ms_cast_ut32_11_12);
	return instruction_sequence;
}

// memw(Rx++Mu) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinew_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, ms_cast_ut32_10_11);
	return instruction_sequence;
}

// memw(gp+Ii) = Nt.new
RzILOpEffect *hex_il_op_s2_storerinewgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_8_9 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, ms_cast_ut32_8_9);
	return instruction_sequence;
}

// memw_locked(Rs,Pd) = Rt
RzILOpEffect *hex_il_op_s2_storew_locked(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// memw_rl(Rs):at = Rt
RzILOpEffect *hex_il_op_s2_storew_rl_at_vi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_6_7 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_3, ms_cast_ut32_6_7);
	return instruction_sequence;
}

// memw_rl(Rs):st = Rt
RzILOpEffect *hex_il_op_s2_storew_rl_st_vi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_6_7 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_3, ms_cast_ut32_6_7);
	return instruction_sequence;
}

// Rd = vsathb(Rs)
RzILOpEffect *hex_il_op_s2_svsathb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_43 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x0) & 0xffff))), 0x0, 0x8) == ((st64) ((st16) ((Rs >> 0x0) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_28 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_28, SN(32, 0xffff));
	RzILOpPure *op_EQ_33 = EQ(SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))), SN(32, 0), SN(32, 8)), CAST(64, MSB(CAST(16, MSB(op_AND_30), DUP(op_AND_30))), CAST(16, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_RSHIFT_47 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_49 = LOGAND(op_RSHIFT_47, SN(32, 0xffff));
	RzILOpPure *op_LT_53 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_49), DUP(op_AND_49))), CAST(16, MSB(DUP(op_AND_49)), DUP(op_AND_49))), SN(32, 0));
	RzILOpPure *op_LSHIFT_58 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_NEG_59 = NEG(op_LSHIFT_58);
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_SUB_67 = SUB(op_LSHIFT_64, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_68 = ITE(op_LT_53, op_NEG_59, op_SUB_67);
	RzILOpEffect *gcc_expr_69 = BRANCH(op_EQ_33, EMPTY(), set_usr_field_call_43);

	// h_tmp530 = HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x0) & 0xffff))), 0x0, 0x8) == ((st64) ((st16) ((Rs >> 0x0) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_71 = SETL("h_tmp530", cond_68);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x0) &  ...;
	RzILOpEffect *seq_72 = SEQN(2, gcc_expr_69, op_ASSIGN_hybrid_tmp_71);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x0)))) | (((ut64) (((sextract64(((ut64) ((st16) ((Rs >> 0x0) & 0xffff))), 0x0, 0x8) == ((st64) ((st16) ((Rs >> 0x0) & 0xffff)))) ? ((st64) ((st16) ((Rs >> 0x0) & 0xffff))) : h_tmp530) & 0xff)) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_8 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_6);
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(32, 0xffff));
	RzILOpPure *cond_74 = ITE(DUP(op_EQ_33), CAST(64, MSB(CAST(16, MSB(op_AND_39), DUP(op_AND_39))), CAST(16, MSB(DUP(op_AND_39)), DUP(op_AND_39))), VARL("h_tmp530"));
	RzILOpPure *op_AND_76 = LOGAND(cond_74, SN(64, 0xff));
	RzILOpPure *op_LSHIFT_81 = SHIFTL0(CAST(64, IL_FALSE, op_AND_76), SN(32, 0));
	RzILOpPure *op_OR_83 = LOGOR(CAST(64, IL_FALSE, op_AND_8), op_LSHIFT_81);
	RzILOpEffect *op_ASSIGN_85 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_83));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x0 ...;
	RzILOpEffect *seq_86 = SEQN(2, seq_72, op_ASSIGN_85);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_129 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x10) & 0xffff))), 0x0, 0x8) == ((st64) ((st16) ((Rs >> 0x10) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_102 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_104 = LOGAND(op_RSHIFT_102, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_114 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_116 = LOGAND(op_RSHIFT_114, SN(32, 0xffff));
	RzILOpPure *op_EQ_119 = EQ(SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_104), DUP(op_AND_104))), SN(32, 0), SN(32, 8)), CAST(64, MSB(CAST(16, MSB(op_AND_116), DUP(op_AND_116))), CAST(16, MSB(DUP(op_AND_116)), DUP(op_AND_116))));
	RzILOpPure *op_RSHIFT_133 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_135 = LOGAND(op_RSHIFT_133, SN(32, 0xffff));
	RzILOpPure *op_LT_139 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_135), DUP(op_AND_135))), CAST(16, MSB(DUP(op_AND_135)), DUP(op_AND_135))), SN(32, 0));
	RzILOpPure *op_LSHIFT_144 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_NEG_145 = NEG(op_LSHIFT_144);
	RzILOpPure *op_LSHIFT_150 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_SUB_153 = SUB(op_LSHIFT_150, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_154 = ITE(op_LT_139, op_NEG_145, op_SUB_153);
	RzILOpEffect *gcc_expr_155 = BRANCH(op_EQ_119, EMPTY(), set_usr_field_call_129);

	// h_tmp531 = HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x10) & 0xffff))), 0x0, 0x8) == ((st64) ((st16) ((Rs >> 0x10) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_157 = SETL("h_tmp531", cond_154);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x10) & ...;
	RzILOpEffect *seq_158 = SEQN(2, gcc_expr_155, op_ASSIGN_hybrid_tmp_157);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x8)))) | (((ut64) (((sextract64(((ut64) ((st16) ((Rs >> 0x10) & 0xffff))), 0x0, 0x8) == ((st64) ((st16) ((Rs >> 0x10) & 0xffff)))) ? ((st64) ((st16) ((Rs >> 0x10) & 0xffff))) : h_tmp531) & 0xff)) << 0x8)));
	RzILOpPure *op_LSHIFT_92 = SHIFTL0(SN(64, 0xff), SN(32, 8));
	RzILOpPure *op_NOT_93 = LOGNOT(op_LSHIFT_92);
	RzILOpPure *op_AND_95 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_93);
	RzILOpPure *op_RSHIFT_123 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_125 = LOGAND(op_RSHIFT_123, SN(32, 0xffff));
	RzILOpPure *cond_160 = ITE(DUP(op_EQ_119), CAST(64, MSB(CAST(16, MSB(op_AND_125), DUP(op_AND_125))), CAST(16, MSB(DUP(op_AND_125)), DUP(op_AND_125))), VARL("h_tmp531"));
	RzILOpPure *op_AND_162 = LOGAND(cond_160, SN(64, 0xff));
	RzILOpPure *op_LSHIFT_167 = SHIFTL0(CAST(64, IL_FALSE, op_AND_162), SN(32, 8));
	RzILOpPure *op_OR_169 = LOGOR(CAST(64, IL_FALSE, op_AND_95), op_LSHIFT_167);
	RzILOpEffect *op_ASSIGN_171 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_169));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rs >> 0x1 ...;
	RzILOpEffect *seq_172 = SEQN(2, seq_158, op_ASSIGN_171);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x10)))) | (((ut64) (((st64) 0x0) & 0xff)) << 0x10)));
	RzILOpPure *op_LSHIFT_178 = SHIFTL0(SN(64, 0xff), SN(32, 16));
	RzILOpPure *op_NOT_179 = LOGNOT(op_LSHIFT_178);
	RzILOpPure *op_AND_181 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_179);
	RzILOpPure *op_AND_185 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_190 = SHIFTL0(CAST(64, IL_FALSE, op_AND_185), SN(32, 16));
	RzILOpPure *op_OR_192 = LOGOR(CAST(64, IL_FALSE, op_AND_181), op_LSHIFT_190);
	RzILOpEffect *op_ASSIGN_194 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_192));

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x18)))) | (((ut64) (((st64) 0x0) & 0xff)) << 0x18)));
	RzILOpPure *op_LSHIFT_200 = SHIFTL0(SN(64, 0xff), SN(32, 24));
	RzILOpPure *op_NOT_201 = LOGNOT(op_LSHIFT_200);
	RzILOpPure *op_AND_203 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_201);
	RzILOpPure *op_AND_207 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_212 = SHIFTL0(CAST(64, IL_FALSE, op_AND_207), SN(32, 24));
	RzILOpPure *op_OR_214 = LOGOR(CAST(64, IL_FALSE, op_AND_203), op_LSHIFT_212);
	RzILOpEffect *op_ASSIGN_216 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_214));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_86, seq_172, op_ASSIGN_194, op_ASSIGN_216);
	return instruction_sequence;
}

// Rd = vsathub(Rs)
RzILOpEffect *hex_il_op_s2_svsathub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_43 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x0) & 0xffff))), 0x0, 0x8) == ((ut64) ((st16) ((Rs >> 0x0) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_28 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_28, SN(32, 0xffff));
	RzILOpPure *op_EQ_33 = EQ(EXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, CAST(16, MSB(op_AND_30), DUP(op_AND_30))));
	RzILOpPure *op_RSHIFT_47 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_49 = LOGAND(op_RSHIFT_47, SN(32, 0xffff));
	RzILOpPure *op_LT_53 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_49), DUP(op_AND_49))), CAST(16, MSB(DUP(op_AND_49)), DUP(op_AND_49))), SN(32, 0));
	RzILOpPure *op_LSHIFT_57 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_60 = SUB(op_LSHIFT_57, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_62 = ITE(op_LT_53, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_60);
	RzILOpEffect *gcc_expr_63 = BRANCH(op_EQ_33, EMPTY(), set_usr_field_call_43);

	// h_tmp532 = HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x0) & 0xffff))), 0x0, 0x8) == ((ut64) ((st16) ((Rs >> 0x0) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x0) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_65 = SETL("h_tmp532", cond_62);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x0) & 0 ...;
	RzILOpEffect *seq_66 = SEQN(2, gcc_expr_63, op_ASSIGN_hybrid_tmp_65);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x0)))) | (((ut64) (((extract64(((ut64) ((st16) ((Rs >> 0x0) & 0xffff))), 0x0, 0x8) == ((ut64) ((st16) ((Rs >> 0x0) & 0xffff)))) ? ((st64) ((st16) ((Rs >> 0x0) & 0xffff))) : h_tmp532) & 0xff)) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_8 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_6);
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rs), SN(32, 0));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(32, 0xffff));
	RzILOpPure *cond_68 = ITE(DUP(op_EQ_33), CAST(64, MSB(CAST(16, MSB(op_AND_39), DUP(op_AND_39))), CAST(16, MSB(DUP(op_AND_39)), DUP(op_AND_39))), VARL("h_tmp532"));
	RzILOpPure *op_AND_70 = LOGAND(cond_68, SN(64, 0xff));
	RzILOpPure *op_LSHIFT_75 = SHIFTL0(CAST(64, IL_FALSE, op_AND_70), SN(32, 0));
	RzILOpPure *op_OR_77 = LOGOR(CAST(64, IL_FALSE, op_AND_8), op_LSHIFT_75);
	RzILOpEffect *op_ASSIGN_79 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_77));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x0) ...;
	RzILOpEffect *seq_80 = SEQN(2, seq_66, op_ASSIGN_79);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_123 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x10) & 0xffff))), 0x0, 0x8) == ((ut64) ((st16) ((Rs >> 0x10) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_96 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_98 = LOGAND(op_RSHIFT_96, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_108 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_110 = LOGAND(op_RSHIFT_108, SN(32, 0xffff));
	RzILOpPure *op_EQ_113 = EQ(EXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_98), DUP(op_AND_98))), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, CAST(16, MSB(op_AND_110), DUP(op_AND_110))));
	RzILOpPure *op_RSHIFT_127 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_129 = LOGAND(op_RSHIFT_127, SN(32, 0xffff));
	RzILOpPure *op_LT_133 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_129), DUP(op_AND_129))), CAST(16, MSB(DUP(op_AND_129)), DUP(op_AND_129))), SN(32, 0));
	RzILOpPure *op_LSHIFT_137 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_140 = SUB(op_LSHIFT_137, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_142 = ITE(op_LT_133, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_140);
	RzILOpEffect *gcc_expr_143 = BRANCH(op_EQ_113, EMPTY(), set_usr_field_call_123);

	// h_tmp533 = HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x10) & 0xffff))), 0x0, 0x8) == ((ut64) ((st16) ((Rs >> 0x10) & 0xffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rs >> 0x10) & 0xffff))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_145 = SETL("h_tmp533", cond_142);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x10) &  ...;
	RzILOpEffect *seq_146 = SEQN(2, gcc_expr_143, op_ASSIGN_hybrid_tmp_145);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x8)))) | (((ut64) (((extract64(((ut64) ((st16) ((Rs >> 0x10) & 0xffff))), 0x0, 0x8) == ((ut64) ((st16) ((Rs >> 0x10) & 0xffff)))) ? ((st64) ((st16) ((Rs >> 0x10) & 0xffff))) : h_tmp533) & 0xff)) << 0x8)));
	RzILOpPure *op_LSHIFT_86 = SHIFTL0(SN(64, 0xff), SN(32, 8));
	RzILOpPure *op_NOT_87 = LOGNOT(op_LSHIFT_86);
	RzILOpPure *op_AND_89 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_87);
	RzILOpPure *op_RSHIFT_117 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_119 = LOGAND(op_RSHIFT_117, SN(32, 0xffff));
	RzILOpPure *cond_148 = ITE(DUP(op_EQ_113), CAST(64, MSB(CAST(16, MSB(op_AND_119), DUP(op_AND_119))), CAST(16, MSB(DUP(op_AND_119)), DUP(op_AND_119))), VARL("h_tmp533"));
	RzILOpPure *op_AND_150 = LOGAND(cond_148, SN(64, 0xff));
	RzILOpPure *op_LSHIFT_155 = SHIFTL0(CAST(64, IL_FALSE, op_AND_150), SN(32, 8));
	RzILOpPure *op_OR_157 = LOGOR(CAST(64, IL_FALSE, op_AND_89), op_LSHIFT_155);
	RzILOpEffect *op_ASSIGN_159 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_157));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rs >> 0x10 ...;
	RzILOpEffect *seq_160 = SEQN(2, seq_146, op_ASSIGN_159);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x10)))) | (((ut64) (((st64) 0x0) & 0xff)) << 0x10)));
	RzILOpPure *op_LSHIFT_166 = SHIFTL0(SN(64, 0xff), SN(32, 16));
	RzILOpPure *op_NOT_167 = LOGNOT(op_LSHIFT_166);
	RzILOpPure *op_AND_169 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_167);
	RzILOpPure *op_AND_173 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_178 = SHIFTL0(CAST(64, IL_FALSE, op_AND_173), SN(32, 16));
	RzILOpPure *op_OR_180 = LOGOR(CAST(64, IL_FALSE, op_AND_169), op_LSHIFT_178);
	RzILOpEffect *op_ASSIGN_182 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_180));

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << 0x18)))) | (((ut64) (((st64) 0x0) & 0xff)) << 0x18)));
	RzILOpPure *op_LSHIFT_188 = SHIFTL0(SN(64, 0xff), SN(32, 24));
	RzILOpPure *op_NOT_189 = LOGNOT(op_LSHIFT_188);
	RzILOpPure *op_AND_191 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_189);
	RzILOpPure *op_AND_195 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xff));
	RzILOpPure *op_LSHIFT_200 = SHIFTL0(CAST(64, IL_FALSE, op_AND_195), SN(32, 24));
	RzILOpPure *op_OR_202 = LOGOR(CAST(64, IL_FALSE, op_AND_191), op_LSHIFT_200);
	RzILOpEffect *op_ASSIGN_204 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_202));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_80, seq_160, op_ASSIGN_182, op_ASSIGN_204);
	return instruction_sequence;
}

// Rx = tableidxb(Rs,Ii,II):raw
RzILOpEffect *hex_il_op_s2_tableidxb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));
	// Declare: st32 offset;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 field;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// S = S;
	RzILOpEffect *imm_assign_5 = SETL("S", S);

	// offset = S;
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", VARL("S"));

	// field = ((st32) ((width != 0x0) ? extract64(((offset < 0x0) ? ((((ut64) ((ut32) Rs)) << (-offset) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_10 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_12 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_16 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_18 = SUB(op_NEG_16, SN(32, 1));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_18);
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(op_LSHIFT_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("offset"));
	RzILOpPure *cond_25 = ITE(op_LT_12, op_LSHIFT_21, op_RSHIFT_24);
	RzILOpPure *cond_30 = ITE(op_NE_10, EXTRACT64(cond_25, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_32 = SETL("field", CAST(32, IL_FALSE, cond_30));

	// Rx = ((st32) (width ? deposit64(((ut64) Rx), 0x0, width, ((ut64) field)) : ((ut64) Rx)));
	RzILOpPure *cond_40 = ITE(NON_ZERO(VARL("width")), DEPOSIT64(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), SN(32, 0), VARL("width"), CAST(64, IL_FALSE, VARL("field"))), CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)));
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, cond_40));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_32, op_ASSIGN_42);
	return instruction_sequence;
}

// Rx = tableidxd(Rs,Ii,II):raw
RzILOpEffect *hex_il_op_s2_tableidxd(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));
	// Declare: st32 offset;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 field;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// S = S;
	RzILOpEffect *imm_assign_5 = SETL("S", S);

	// offset = S + 0x3;
	RzILOpPure *op_ADD_8 = ADD(VARL("S"), SN(32, 3));
	RzILOpEffect *op_ASSIGN_10 = SETL("offset", op_ADD_8);

	// field = ((st32) ((width != 0x0) ? extract64(((offset < 0x0) ? ((((ut64) ((ut32) Rs)) << (-offset) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_14 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("offset"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *cond_32 = ITE(op_NE_12, EXTRACT64(cond_27, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_34 = SETL("field", CAST(32, IL_FALSE, cond_32));

	// Rx = ((st32) (width ? deposit64(((ut64) Rx), 0x3, width, ((ut64) field)) : ((ut64) Rx)));
	RzILOpPure *cond_42 = ITE(NON_ZERO(VARL("width")), DEPOSIT64(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), SN(32, 3), VARL("width"), CAST(64, IL_FALSE, VARL("field"))), CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)));
	RzILOpEffect *op_ASSIGN_44 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, cond_42));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_10, op_ASSIGN_34, op_ASSIGN_44);
	return instruction_sequence;
}

// Rx = tableidxh(Rs,Ii,II):raw
RzILOpEffect *hex_il_op_s2_tableidxh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));
	// Declare: st32 offset;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 field;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// S = S;
	RzILOpEffect *imm_assign_5 = SETL("S", S);

	// offset = S + 0x1;
	RzILOpPure *op_ADD_8 = ADD(VARL("S"), SN(32, 1));
	RzILOpEffect *op_ASSIGN_10 = SETL("offset", op_ADD_8);

	// field = ((st32) ((width != 0x0) ? extract64(((offset < 0x0) ? ((((ut64) ((ut32) Rs)) << (-offset) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_14 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("offset"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *cond_32 = ITE(op_NE_12, EXTRACT64(cond_27, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_34 = SETL("field", CAST(32, IL_FALSE, cond_32));

	// Rx = ((st32) (width ? deposit64(((ut64) Rx), 0x1, width, ((ut64) field)) : ((ut64) Rx)));
	RzILOpPure *cond_42 = ITE(NON_ZERO(VARL("width")), DEPOSIT64(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), SN(32, 1), VARL("width"), CAST(64, IL_FALSE, VARL("field"))), CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)));
	RzILOpEffect *op_ASSIGN_44 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, cond_42));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_10, op_ASSIGN_34, op_ASSIGN_44);
	return instruction_sequence;
}

// Rx = tableidxw(Rs,Ii,II):raw
RzILOpEffect *hex_il_op_s2_tableidxw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));
	// Declare: st32 offset;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 field;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// S = S;
	RzILOpEffect *imm_assign_5 = SETL("S", S);

	// offset = S + 0x2;
	RzILOpPure *op_ADD_8 = ADD(VARL("S"), SN(32, 2));
	RzILOpEffect *op_ASSIGN_10 = SETL("offset", op_ADD_8);

	// field = ((st32) ((width != 0x0) ? extract64(((offset < 0x0) ? ((((ut64) ((ut32) Rs)) << (-offset) - 0x1) << 0x1) : (((ut64) ((ut32) Rs)) >> offset)), 0x0, width) : ((ut64) 0x0)));
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_14 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_18 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_20 = SUB(op_NEG_18, SN(32, 1));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), op_SUB_20);
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(op_LSHIFT_21, SN(32, 1));
	RzILOpPure *op_RSHIFT_26 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))), VARL("offset"));
	RzILOpPure *cond_27 = ITE(op_LT_14, op_LSHIFT_23, op_RSHIFT_26);
	RzILOpPure *cond_32 = ITE(op_NE_12, EXTRACT64(cond_27, SN(32, 0), VARL("width")), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *op_ASSIGN_34 = SETL("field", CAST(32, IL_FALSE, cond_32));

	// Rx = ((st32) (width ? deposit64(((ut64) Rx), 0x2, width, ((ut64) field)) : ((ut64) Rx)));
	RzILOpPure *cond_42 = ITE(NON_ZERO(VARL("width")), DEPOSIT64(CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)), SN(32, 2), VARL("width"), CAST(64, IL_FALSE, VARL("field"))), CAST(64, IL_FALSE, READ_REG(pkt, Rx_op, false)));
	RzILOpEffect *op_ASSIGN_44 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, cond_42));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_10, op_ASSIGN_34, op_ASSIGN_44);
	return instruction_sequence;
}

// Rd = togglebit(Rs,Ii)
RzILOpEffect *hex_il_op_s2_togglebit_i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Rd = (Rs ^ (0x1 << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_XOR_6 = LOGXOR(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, op_XOR_6);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_7);
	return instruction_sequence;
}

// Rd = togglebit(Rs,Rt)
RzILOpEffect *hex_il_op_s2_togglebit_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) (((ut64) Rs) ^ ((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) 0x1)) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut32) 0x1)) << sextract64(((ut64) Rt), 0x0, 0x7)))));
	RzILOpPure *op_LT_13 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_25 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_28 = SUB(op_NEG_25, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_29 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), op_SUB_28);
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(op_RSHIFT_29, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_44 = ITE(op_LT_13, op_RSHIFT_31, op_LSHIFT_43);
	RzILOpPure *op_XOR_46 = LOGXOR(CAST(64, IL_FALSE, Rs), cond_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_XOR_46));

	RzILOpEffect *instruction_sequence = op_ASSIGN_48;
	return instruction_sequence;
}

// Pd = tstbit(Rs,Ii)
RzILOpEffect *hex_il_op_s2_tstbit_i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Pd = ((st8) (((Rs & (0x1 << u)) != 0x0) ? 0xff : 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_AND_6 = LOGAND(Rs, op_LSHIFT_5);
	RzILOpPure *op_NE_8 = INV(EQ(op_AND_6, SN(32, 0)));
	RzILOpPure *cond_11 = ITE(op_NE_8, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_11), DUP(cond_11)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_13);
	return instruction_sequence;
}

// Pd = tstbit(Rs,Rt)
RzILOpEffect *hex_il_op_s2_tstbit_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) (((((ut64) ((ut32) Rs)) & ((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) 0x1)) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut32) 0x1)) << sextract64(((ut64) Rt), 0x0, 0x7)))) != ((ut64) 0x0)) ? 0xff : 0x0));
	RzILOpPure *op_LT_15 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_27 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_30 = SUB(op_NEG_27, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), op_SUB_30);
	RzILOpPure *op_RSHIFT_33 = SHIFTR0(op_RSHIFT_31, SN(32, 1));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_46 = ITE(op_LT_15, op_RSHIFT_33, op_LSHIFT_45);
	RzILOpPure *op_AND_47 = LOGAND(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), cond_46);
	RzILOpPure *op_NE_50 = INV(EQ(op_AND_47, CAST(64, IL_FALSE, SN(32, 0))));
	RzILOpPure *cond_53 = ITE(op_NE_50, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_55 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_53), DUP(cond_53)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_55;
	return instruction_sequence;
}

// Rdd = valignb(Rtt,Rss,Ii)
RzILOpEffect *hex_il_op_s2_valignib(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rdd = ((st64) (((u * ((ut32) 0x8) >= ((ut32) 0x40)) ? ((ut64) 0x0) : (((ut64) Rss) >> u * ((ut32) 0x8))) | ((ut64) ((((ut32) 0x8) - u * ((ut32) 0x8) >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rtt << ((ut32) 0x8) - u * ((ut32) 0x8))))));
	RzILOpPure *op_MUL_5 = MUL(VARL("u"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_GE_11 = UGE(op_MUL_5, CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_MUL_16 = MUL(VARL("u"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_RSHIFT_17 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_MUL_16);
	RzILOpPure *cond_19 = ITE(op_GE_11, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_17);
	RzILOpPure *op_SUB_22 = SUB(CAST(32, IL_FALSE, SN(32, 8)), VARL("u"));
	RzILOpPure *op_MUL_25 = MUL(op_SUB_22, CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_GE_31 = UGE(op_MUL_25, CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_SUB_35 = SUB(CAST(32, IL_FALSE, SN(32, 8)), VARL("u"));
	RzILOpPure *op_MUL_38 = MUL(op_SUB_35, CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(Rtt, op_MUL_38);
	RzILOpPure *cond_41 = ITE(op_GE_31, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_39);
	RzILOpPure *op_OR_43 = LOGOR(cond_19, CAST(64, IL_FALSE, cond_41));
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_43));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_45);
	return instruction_sequence;
}

// Rdd = valignb(Rtt,Rss,Pu)
RzILOpEffect *hex_il_op_s2_valignrb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) ((((((st32) Pu) & 0x7) * 0x8 >= 0x40) ? ((ut64) 0x0) : (((ut64) Rss) >> (((st32) Pu) & 0x7) * 0x8)) | ((ut64) ((0x8 - (((st32) Pu) & 0x7) * 0x8 >= 0x40) ? ((st64) 0x0) : (Rtt << 0x8 - (((st32) Pu) & 0x7) * 0x8)))));
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_MUL_6 = MUL(op_AND_4, SN(32, 8));
	RzILOpPure *op_GE_11 = SGE(op_MUL_6, SN(32, 0x40));
	RzILOpPure *op_AND_16 = LOGAND(CAST(32, MSB(DUP(Pu)), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_MUL_18 = MUL(op_AND_16, SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTR0(CAST(64, IL_FALSE, Rss), op_MUL_18);
	RzILOpPure *cond_21 = ITE(op_GE_11, CAST(64, IL_FALSE, SN(32, 0)), op_RSHIFT_19);
	RzILOpPure *op_AND_25 = LOGAND(CAST(32, MSB(DUP(Pu)), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_SUB_26 = SUB(SN(32, 8), op_AND_25);
	RzILOpPure *op_MUL_28 = MUL(op_SUB_26, SN(32, 8));
	RzILOpPure *op_GE_33 = SGE(op_MUL_28, SN(32, 0x40));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, MSB(DUP(Pu)), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_SUB_39 = SUB(SN(32, 8), op_AND_38);
	RzILOpPure *op_MUL_41 = MUL(op_SUB_39, SN(32, 8));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(Rtt, op_MUL_41);
	RzILOpPure *cond_44 = ITE(op_GE_33, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_42);
	RzILOpPure *op_OR_46 = LOGOR(cond_21, CAST(64, IL_FALSE, cond_44));
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_46));

	RzILOpEffect *instruction_sequence = op_ASSIGN_48;
	return instruction_sequence;
}

// Rdd = vcnegh(Rss,Rt)
RzILOpEffect *hex_il_op_s2_vcnegh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp534 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp534", VARL("i"));

	// seq(h_tmp534 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_60 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_25 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(Rss, op_MUL_25);
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_26, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_32 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_29), DUP(op_AND_29))), CAST(16, MSB(DUP(op_AND_29)), DUP(op_AND_29))));
	RzILOpPure *op_MUL_39 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rss), op_MUL_39);
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_46 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_43), DUP(op_AND_43))), CAST(16, MSB(DUP(op_AND_43)), DUP(op_AND_43))));
	RzILOpPure *op_EQ_48 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_32), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_46), DUP(op_NEG_46)));
	RzILOpPure *op_MUL_62 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rss), op_MUL_62);
	RzILOpPure *op_AND_66 = LOGAND(op_RSHIFT_63, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_69 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_66), DUP(op_AND_66))), CAST(16, MSB(DUP(op_AND_66)), DUP(op_AND_66))));
	RzILOpPure *op_LT_71 = SLT(op_NEG_69, SN(32, 0));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_77 = NEG(op_LSHIFT_76);
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_85 = SUB(op_LSHIFT_82, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_86 = ITE(op_LT_71, op_NEG_77, op_SUB_85);
	RzILOpEffect *gcc_expr_87 = BRANCH(op_EQ_48, EMPTY(), set_usr_field_call_60);

	// h_tmp535 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_89 = SETL("h_tmp535", cond_86);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_90 = SEQN(2, gcc_expr_87, op_ASSIGN_hybrid_tmp_89);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) : h_tmp535) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_16 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(SN(64, 0xffff), op_MUL_16);
	RzILOpPure *op_NOT_18 = LOGNOT(op_LSHIFT_17);
	RzILOpPure *op_AND_19 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_18);
	RzILOpPure *op_MUL_50 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_51 = SHIFTRA(DUP(Rss), op_MUL_50);
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_51, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_57 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_54), DUP(op_AND_54))), CAST(16, MSB(DUP(op_AND_54)), DUP(op_AND_54))));
	RzILOpPure *cond_92 = ITE(DUP(op_EQ_48), CAST(64, MSB(op_NEG_57), DUP(op_NEG_57)), VARL("h_tmp535"));
	RzILOpPure *op_AND_95 = LOGAND(cond_92, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_98 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_99 = SHIFTL0(CAST(64, IL_FALSE, op_AND_95), op_MUL_98);
	RzILOpPure *op_OR_101 = LOGOR(CAST(64, IL_FALSE, op_AND_19), op_LSHIFT_99);
	RzILOpEffect *op_ASSIGN_103 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_101));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_104 = SEQN(2, seq_90, op_ASSIGN_103);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_108 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(SN(64, 0xffff), op_MUL_108);
	RzILOpPure *op_NOT_110 = LOGNOT(op_LSHIFT_109);
	RzILOpPure *op_AND_111 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_110);
	RzILOpPure *op_MUL_113 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_114 = SHIFTRA(DUP(Rss), op_MUL_113);
	RzILOpPure *op_AND_117 = LOGAND(op_RSHIFT_114, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_121 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_117), DUP(op_AND_117))), CAST(16, MSB(DUP(op_AND_117)), DUP(op_AND_117))), SN(32, 0xffff));
	RzILOpPure *op_MUL_124 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_125 = SHIFTL0(CAST(64, IL_FALSE, op_AND_121), op_MUL_124);
	RzILOpPure *op_OR_127 = LOGOR(CAST(64, IL_FALSE, op_AND_111), op_LSHIFT_125);
	RzILOpEffect *op_ASSIGN_129 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_127));

	// seq(seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st1 ...;
	RzILOpEffect *seq_then_131 = seq_104;

	// seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (( ...;
	RzILOpEffect *seq_else_132 = op_ASSIGN_129;

	// if (((Rt >> i) & 0x1)) {seq(seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st1 ...} else {seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (( ...};
	RzILOpPure *op_RSHIFT_10 = SHIFTRA(Rt, VARL("i"));
	RzILOpPure *op_AND_12 = LOGAND(op_RSHIFT_10, SN(32, 1));
	RzILOpEffect *branch_133 = BRANCH(NON_ZERO(op_AND_12), seq_then_131, seq_else_132);

	// seq(h_tmp534; if (((Rt >> i) & 0x1)) {seq(seq(seq(HYB(gcc_expr_i ...;
	RzILOpEffect *seq_134 = branch_133;

	// seq(seq(h_tmp534; if (((Rt >> i) & 0x1)) {seq(seq(seq(HYB(gcc_ex ...;
	RzILOpEffect *seq_135 = SEQN(2, seq_134, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp534; if (((Rt >> i) & 0x1)) {seq(seq(seq(HYB(gcc_ex ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_136 = REPEAT(op_LT_4, seq_135);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp534; if (((Rt >> i ...;
	RzILOpEffect *seq_137 = SEQN(2, op_ASSIGN_2, for_136);

	RzILOpEffect *instruction_sequence = seq_137;
	return instruction_sequence;
}

// Rdd = vcrotate(Rss,Rt)
RzILOpEffect *hex_il_op_s2_vcrotate(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut8 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// tmp = ((ut8) extract64(((ut64) Rt), 0x0, 0x2));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmp", CAST(8, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 2))));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_27 = LOGNOT(op_LSHIFT_26);
	RzILOpPure *op_AND_28 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_27);
	RzILOpPure *op_RSHIFT_33 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_33, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_36), DUP(op_AND_36))), CAST(16, MSB(DUP(op_AND_36)), DUP(op_AND_36))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), SN(32, 0));
	RzILOpPure *op_OR_47 = LOGOR(CAST(64, IL_FALSE, op_AND_28), op_LSHIFT_45);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_47));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_55 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_56 = LOGNOT(op_LSHIFT_55);
	RzILOpPure *op_AND_57 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_56);
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_61, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_68 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_64), DUP(op_AND_64))), CAST(16, MSB(DUP(op_AND_64)), DUP(op_AND_64))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_73 = SHIFTL0(CAST(64, IL_FALSE, op_AND_68), SN(32, 16));
	RzILOpPure *op_OR_75 = LOGOR(CAST(64, IL_FALSE, op_AND_57), op_LSHIFT_73);
	RzILOpEffect *op_ASSIGN_77 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_75));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_86 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_87 = LOGNOT(op_LSHIFT_86);
	RzILOpPure *op_AND_88 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_87);
	RzILOpPure *op_RSHIFT_92 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_95 = LOGAND(op_RSHIFT_92, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_99 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_95), DUP(op_AND_95))), CAST(16, MSB(DUP(op_AND_95)), DUP(op_AND_95))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_104 = SHIFTL0(CAST(64, IL_FALSE, op_AND_99), SN(32, 0));
	RzILOpPure *op_OR_106 = LOGOR(CAST(64, IL_FALSE, op_AND_88), op_LSHIFT_104);
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_106));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_159 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_123 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_126 = LOGAND(op_RSHIFT_123, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_129 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_126), DUP(op_AND_126))), CAST(16, MSB(DUP(op_AND_126)), DUP(op_AND_126))));
	RzILOpPure *op_RSHIFT_138 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_141 = LOGAND(op_RSHIFT_138, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_144 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_141), DUP(op_AND_141))), CAST(16, MSB(DUP(op_AND_141)), DUP(op_AND_141))));
	RzILOpPure *op_EQ_146 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_129), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_144), DUP(op_NEG_144)));
	RzILOpPure *op_RSHIFT_163 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_166 = LOGAND(op_RSHIFT_163, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_169 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_166), DUP(op_AND_166))), CAST(16, MSB(DUP(op_AND_166)), DUP(op_AND_166))));
	RzILOpPure *op_LT_171 = SLT(op_NEG_169, SN(32, 0));
	RzILOpPure *op_LSHIFT_176 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_177 = NEG(op_LSHIFT_176);
	RzILOpPure *op_LSHIFT_182 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_185 = SUB(op_LSHIFT_182, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_186 = ITE(op_LT_171, op_NEG_177, op_SUB_185);
	RzILOpEffect *gcc_expr_187 = BRANCH(op_EQ_146, EMPTY(), set_usr_field_call_159);

	// h_tmp536 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_189 = SETL("h_tmp536", cond_186);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_190 = SEQN(2, gcc_expr_187, op_ASSIGN_hybrid_tmp_189);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))) : h_tmp536) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_114 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_115 = LOGNOT(op_LSHIFT_114);
	RzILOpPure *op_AND_116 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_115);
	RzILOpPure *op_RSHIFT_150 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_153 = LOGAND(op_RSHIFT_150, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_156 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_153), DUP(op_AND_153))), CAST(16, MSB(DUP(op_AND_153)), DUP(op_AND_153))));
	RzILOpPure *cond_192 = ITE(DUP(op_EQ_146), CAST(64, MSB(op_NEG_156), DUP(op_NEG_156)), VARL("h_tmp536"));
	RzILOpPure *op_AND_195 = LOGAND(cond_192, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_200 = SHIFTL0(CAST(64, IL_FALSE, op_AND_195), SN(32, 16));
	RzILOpPure *op_OR_202 = LOGOR(CAST(64, IL_FALSE, op_AND_116), op_LSHIFT_200);
	RzILOpEffect *op_ASSIGN_204 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_202));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_205 = SEQN(2, seq_190, op_ASSIGN_204);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_259 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_223 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_226 = LOGAND(op_RSHIFT_223, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_229 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_226), DUP(op_AND_226))), CAST(16, MSB(DUP(op_AND_226)), DUP(op_AND_226))));
	RzILOpPure *op_RSHIFT_238 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_241 = LOGAND(op_RSHIFT_238, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_244 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_241), DUP(op_AND_241))), CAST(16, MSB(DUP(op_AND_241)), DUP(op_AND_241))));
	RzILOpPure *op_EQ_246 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_229), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_244), DUP(op_NEG_244)));
	RzILOpPure *op_RSHIFT_263 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_266 = LOGAND(op_RSHIFT_263, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_269 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_266), DUP(op_AND_266))), CAST(16, MSB(DUP(op_AND_266)), DUP(op_AND_266))));
	RzILOpPure *op_LT_271 = SLT(op_NEG_269, SN(32, 0));
	RzILOpPure *op_LSHIFT_276 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_277 = NEG(op_LSHIFT_276);
	RzILOpPure *op_LSHIFT_282 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_285 = SUB(op_LSHIFT_282, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_286 = ITE(op_LT_271, op_NEG_277, op_SUB_285);
	RzILOpEffect *gcc_expr_287 = BRANCH(op_EQ_246, EMPTY(), set_usr_field_call_259);

	// h_tmp537 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_289 = SETL("h_tmp537", cond_286);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_290 = SEQN(2, gcc_expr_287, op_ASSIGN_hybrid_tmp_289);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))) : h_tmp537) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_214 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_215 = LOGNOT(op_LSHIFT_214);
	RzILOpPure *op_AND_216 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_215);
	RzILOpPure *op_RSHIFT_250 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_253 = LOGAND(op_RSHIFT_250, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_256 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_253), DUP(op_AND_253))), CAST(16, MSB(DUP(op_AND_253)), DUP(op_AND_253))));
	RzILOpPure *cond_292 = ITE(DUP(op_EQ_246), CAST(64, MSB(op_NEG_256), DUP(op_NEG_256)), VARL("h_tmp537"));
	RzILOpPure *op_AND_295 = LOGAND(cond_292, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_300 = SHIFTL0(CAST(64, IL_FALSE, op_AND_295), SN(32, 0));
	RzILOpPure *op_OR_302 = LOGOR(CAST(64, IL_FALSE, op_AND_216), op_LSHIFT_300);
	RzILOpEffect *op_ASSIGN_304 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_302));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_305 = SEQN(2, seq_290, op_ASSIGN_304);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_311 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_312 = LOGNOT(op_LSHIFT_311);
	RzILOpPure *op_AND_313 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_312);
	RzILOpPure *op_RSHIFT_317 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_320 = LOGAND(op_RSHIFT_317, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_324 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_320), DUP(op_AND_320))), CAST(16, MSB(DUP(op_AND_320)), DUP(op_AND_320))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_329 = SHIFTL0(CAST(64, IL_FALSE, op_AND_324), SN(32, 16));
	RzILOpPure *op_OR_331 = LOGOR(CAST(64, IL_FALSE, op_AND_313), op_LSHIFT_329);
	RzILOpEffect *op_ASSIGN_333 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_331));

	// seq({});
	RzILOpEffect *seq_then_338 = EMPTY();

	// if ((((st32) tmp) != 0x3)) {seq({})} else {{}};
	RzILOpPure *op_NE_337 = INV(EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 3)));
	RzILOpEffect *branch_339 = BRANCH(op_NE_337, seq_then_338, EMPTY());

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_389 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_353 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_356 = LOGAND(op_RSHIFT_353, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_359 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_356), DUP(op_AND_356))), CAST(16, MSB(DUP(op_AND_356)), DUP(op_AND_356))));
	RzILOpPure *op_RSHIFT_368 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_371 = LOGAND(op_RSHIFT_368, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_374 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_371), DUP(op_AND_371))), CAST(16, MSB(DUP(op_AND_371)), DUP(op_AND_371))));
	RzILOpPure *op_EQ_376 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_359), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_374), DUP(op_NEG_374)));
	RzILOpPure *op_RSHIFT_393 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_396 = LOGAND(op_RSHIFT_393, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_399 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_396), DUP(op_AND_396))), CAST(16, MSB(DUP(op_AND_396)), DUP(op_AND_396))));
	RzILOpPure *op_LT_401 = SLT(op_NEG_399, SN(32, 0));
	RzILOpPure *op_LSHIFT_406 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_407 = NEG(op_LSHIFT_406);
	RzILOpPure *op_LSHIFT_412 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_415 = SUB(op_LSHIFT_412, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_416 = ITE(op_LT_401, op_NEG_407, op_SUB_415);
	RzILOpEffect *gcc_expr_417 = BRANCH(op_EQ_376, EMPTY(), set_usr_field_call_389);

	// h_tmp538 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_419 = SETL("h_tmp538", cond_416);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_420 = SEQN(2, gcc_expr_417, op_ASSIGN_hybrid_tmp_419);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))))) : h_tmp538) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_344 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_345 = LOGNOT(op_LSHIFT_344);
	RzILOpPure *op_AND_346 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_345);
	RzILOpPure *op_RSHIFT_380 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_383 = LOGAND(op_RSHIFT_380, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_386 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_383), DUP(op_AND_383))), CAST(16, MSB(DUP(op_AND_383)), DUP(op_AND_383))));
	RzILOpPure *cond_422 = ITE(DUP(op_EQ_376), CAST(64, MSB(op_NEG_386), DUP(op_NEG_386)), VARL("h_tmp538"));
	RzILOpPure *op_AND_425 = LOGAND(cond_422, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_430 = SHIFTL0(CAST(64, IL_FALSE, op_AND_425), SN(32, 0));
	RzILOpPure *op_OR_432 = LOGOR(CAST(64, IL_FALSE, op_AND_346), op_LSHIFT_430);
	RzILOpEffect *op_ASSIGN_434 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_432));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_435 = SEQN(2, seq_420, op_ASSIGN_434);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_486 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_450 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_453 = LOGAND(op_RSHIFT_450, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_456 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_453), DUP(op_AND_453))), CAST(16, MSB(DUP(op_AND_453)), DUP(op_AND_453))));
	RzILOpPure *op_RSHIFT_465 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_468 = LOGAND(op_RSHIFT_465, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_471 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_468), DUP(op_AND_468))), CAST(16, MSB(DUP(op_AND_468)), DUP(op_AND_468))));
	RzILOpPure *op_EQ_473 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_456), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_471), DUP(op_NEG_471)));
	RzILOpPure *op_RSHIFT_490 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_493 = LOGAND(op_RSHIFT_490, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_496 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_493), DUP(op_AND_493))), CAST(16, MSB(DUP(op_AND_493)), DUP(op_AND_493))));
	RzILOpPure *op_LT_498 = SLT(op_NEG_496, SN(32, 0));
	RzILOpPure *op_LSHIFT_503 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_504 = NEG(op_LSHIFT_503);
	RzILOpPure *op_LSHIFT_509 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_512 = SUB(op_LSHIFT_509, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_513 = ITE(op_LT_498, op_NEG_504, op_SUB_512);
	RzILOpEffect *gcc_expr_514 = BRANCH(op_EQ_473, EMPTY(), set_usr_field_call_486);

	// h_tmp539 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_516 = SETL("h_tmp539", cond_513);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_517 = SEQN(2, gcc_expr_514, op_ASSIGN_hybrid_tmp_516);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))))) : h_tmp539) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_441 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_442 = LOGNOT(op_LSHIFT_441);
	RzILOpPure *op_AND_443 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_442);
	RzILOpPure *op_RSHIFT_477 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_480 = LOGAND(op_RSHIFT_477, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_483 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_480), DUP(op_AND_480))), CAST(16, MSB(DUP(op_AND_480)), DUP(op_AND_480))));
	RzILOpPure *cond_519 = ITE(DUP(op_EQ_473), CAST(64, MSB(op_NEG_483), DUP(op_NEG_483)), VARL("h_tmp539"));
	RzILOpPure *op_AND_522 = LOGAND(cond_519, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_527 = SHIFTL0(CAST(64, IL_FALSE, op_AND_522), SN(32, 16));
	RzILOpPure *op_OR_529 = LOGOR(CAST(64, IL_FALSE, op_AND_443), op_LSHIFT_527);
	RzILOpEffect *op_ASSIGN_531 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_529));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_532 = SEQN(2, seq_517, op_ASSIGN_531);

	// seq(seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st1 ...;
	RzILOpEffect *seq_then_534 = SEQN(2, seq_305, op_ASSIGN_333);

	// seq(if ((((st32) tmp) != 0x3)) {seq({})} else {{}}; seq(seq(HYB( ...;
	RzILOpEffect *seq_else_535 = SEQN(3, branch_339, seq_435, seq_532);

	// if ((((st32) tmp) == 0x2)) {seq(seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st1 ...} else {seq(if ((((st32) tmp) != 0x3)) {seq({})} else {{}}; seq(seq(HYB( ...};
	RzILOpPure *op_EQ_209 = EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 2));
	RzILOpEffect *branch_536 = BRANCH(op_EQ_209, seq_then_534, seq_else_535);

	// seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64 ...;
	RzILOpEffect *seq_then_537 = SEQN(2, op_ASSIGN_108, seq_205);

	// seq(if ((((st32) tmp) == 0x2)) {seq(seq(seq(HYB(gcc_expr_if ((se ...;
	RzILOpEffect *seq_else_538 = branch_536;

	// if ((((st32) tmp) == 0x1)) {seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64 ...} else {seq(if ((((st32) tmp) == 0x2)) {seq(seq(seq(HYB(gcc_expr_if ((se ...};
	RzILOpPure *op_EQ_81 = EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 1));
	RzILOpEffect *branch_539 = BRANCH(op_EQ_81, seq_then_537, seq_else_538);

	// seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64 ...;
	RzILOpEffect *seq_then_540 = SEQN(2, op_ASSIGN_49, op_ASSIGN_77);

	// seq(if ((((st32) tmp) == 0x1)) {seq(Rdd = ((st64) (((ut64) (Rdd  ...;
	RzILOpEffect *seq_else_541 = branch_539;

	// if ((((st32) tmp) == 0x0)) {seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64 ...} else {seq(if ((((st32) tmp) == 0x1)) {seq(Rdd = ((st64) (((ut64) (Rdd  ...};
	RzILOpPure *op_EQ_20 = EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 0));
	RzILOpEffect *branch_542 = BRANCH(op_EQ_20, seq_then_540, seq_else_541);

	// tmp = ((ut8) extract64(((ut64) Rt), 0x2, 0x2));
	RzILOpEffect *op_ASSIGN_558 = SETL("tmp", CAST(8, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 2), SN(32, 2))));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_566 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_567 = LOGNOT(op_LSHIFT_566);
	RzILOpPure *op_AND_568 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_567);
	RzILOpPure *op_RSHIFT_572 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_575 = LOGAND(op_RSHIFT_572, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_579 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_575), DUP(op_AND_575))), CAST(16, MSB(DUP(op_AND_575)), DUP(op_AND_575))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_584 = SHIFTL0(CAST(64, IL_FALSE, op_AND_579), SN(32, 0x20));
	RzILOpPure *op_OR_586 = LOGOR(CAST(64, IL_FALSE, op_AND_568), op_LSHIFT_584);
	RzILOpEffect *op_ASSIGN_588 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_586));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_594 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_595 = LOGNOT(op_LSHIFT_594);
	RzILOpPure *op_AND_596 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_595);
	RzILOpPure *op_RSHIFT_600 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_603 = LOGAND(op_RSHIFT_600, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_607 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_603), DUP(op_AND_603))), CAST(16, MSB(DUP(op_AND_603)), DUP(op_AND_603))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_612 = SHIFTL0(CAST(64, IL_FALSE, op_AND_607), SN(32, 0x30));
	RzILOpPure *op_OR_614 = LOGOR(CAST(64, IL_FALSE, op_AND_596), op_LSHIFT_612);
	RzILOpEffect *op_ASSIGN_616 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_614));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_625 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_626 = LOGNOT(op_LSHIFT_625);
	RzILOpPure *op_AND_627 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_626);
	RzILOpPure *op_RSHIFT_631 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_634 = LOGAND(op_RSHIFT_631, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_638 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_634), DUP(op_AND_634))), CAST(16, MSB(DUP(op_AND_634)), DUP(op_AND_634))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_643 = SHIFTL0(CAST(64, IL_FALSE, op_AND_638), SN(32, 0x20));
	RzILOpPure *op_OR_645 = LOGOR(CAST(64, IL_FALSE, op_AND_627), op_LSHIFT_643);
	RzILOpEffect *op_ASSIGN_647 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_645));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_698 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_662 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_665 = LOGAND(op_RSHIFT_662, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_668 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_665), DUP(op_AND_665))), CAST(16, MSB(DUP(op_AND_665)), DUP(op_AND_665))));
	RzILOpPure *op_RSHIFT_677 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_680 = LOGAND(op_RSHIFT_677, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_683 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_680), DUP(op_AND_680))), CAST(16, MSB(DUP(op_AND_680)), DUP(op_AND_680))));
	RzILOpPure *op_EQ_685 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_668), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_683), DUP(op_NEG_683)));
	RzILOpPure *op_RSHIFT_702 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_705 = LOGAND(op_RSHIFT_702, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_708 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_705), DUP(op_AND_705))), CAST(16, MSB(DUP(op_AND_705)), DUP(op_AND_705))));
	RzILOpPure *op_LT_710 = SLT(op_NEG_708, SN(32, 0));
	RzILOpPure *op_LSHIFT_715 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_716 = NEG(op_LSHIFT_715);
	RzILOpPure *op_LSHIFT_721 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_724 = SUB(op_LSHIFT_721, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_725 = ITE(op_LT_710, op_NEG_716, op_SUB_724);
	RzILOpEffect *gcc_expr_726 = BRANCH(op_EQ_685, EMPTY(), set_usr_field_call_698);

	// h_tmp540 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_728 = SETL("h_tmp540", cond_725);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_729 = SEQN(2, gcc_expr_726, op_ASSIGN_hybrid_tmp_728);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))) : h_tmp540) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_653 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_654 = LOGNOT(op_LSHIFT_653);
	RzILOpPure *op_AND_655 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_654);
	RzILOpPure *op_RSHIFT_689 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_692 = LOGAND(op_RSHIFT_689, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_695 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_692), DUP(op_AND_692))), CAST(16, MSB(DUP(op_AND_692)), DUP(op_AND_692))));
	RzILOpPure *cond_731 = ITE(DUP(op_EQ_685), CAST(64, MSB(op_NEG_695), DUP(op_NEG_695)), VARL("h_tmp540"));
	RzILOpPure *op_AND_734 = LOGAND(cond_731, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_739 = SHIFTL0(CAST(64, IL_FALSE, op_AND_734), SN(32, 0x30));
	RzILOpPure *op_OR_741 = LOGOR(CAST(64, IL_FALSE, op_AND_655), op_LSHIFT_739);
	RzILOpEffect *op_ASSIGN_743 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_741));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_744 = SEQN(2, seq_729, op_ASSIGN_743);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_798 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_762 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_765 = LOGAND(op_RSHIFT_762, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_768 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_765), DUP(op_AND_765))), CAST(16, MSB(DUP(op_AND_765)), DUP(op_AND_765))));
	RzILOpPure *op_RSHIFT_777 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_780 = LOGAND(op_RSHIFT_777, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_783 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_780), DUP(op_AND_780))), CAST(16, MSB(DUP(op_AND_780)), DUP(op_AND_780))));
	RzILOpPure *op_EQ_785 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_768), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_783), DUP(op_NEG_783)));
	RzILOpPure *op_RSHIFT_802 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_805 = LOGAND(op_RSHIFT_802, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_808 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_805), DUP(op_AND_805))), CAST(16, MSB(DUP(op_AND_805)), DUP(op_AND_805))));
	RzILOpPure *op_LT_810 = SLT(op_NEG_808, SN(32, 0));
	RzILOpPure *op_LSHIFT_815 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_816 = NEG(op_LSHIFT_815);
	RzILOpPure *op_LSHIFT_821 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_824 = SUB(op_LSHIFT_821, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_825 = ITE(op_LT_810, op_NEG_816, op_SUB_824);
	RzILOpEffect *gcc_expr_826 = BRANCH(op_EQ_785, EMPTY(), set_usr_field_call_798);

	// h_tmp541 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_828 = SETL("h_tmp541", cond_825);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_829 = SEQN(2, gcc_expr_826, op_ASSIGN_hybrid_tmp_828);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))) : h_tmp541) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_753 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_754 = LOGNOT(op_LSHIFT_753);
	RzILOpPure *op_AND_755 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_754);
	RzILOpPure *op_RSHIFT_789 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_792 = LOGAND(op_RSHIFT_789, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_795 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_792), DUP(op_AND_792))), CAST(16, MSB(DUP(op_AND_792)), DUP(op_AND_792))));
	RzILOpPure *cond_831 = ITE(DUP(op_EQ_785), CAST(64, MSB(op_NEG_795), DUP(op_NEG_795)), VARL("h_tmp541"));
	RzILOpPure *op_AND_834 = LOGAND(cond_831, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_839 = SHIFTL0(CAST(64, IL_FALSE, op_AND_834), SN(32, 0x20));
	RzILOpPure *op_OR_841 = LOGOR(CAST(64, IL_FALSE, op_AND_755), op_LSHIFT_839);
	RzILOpEffect *op_ASSIGN_843 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_841));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_844 = SEQN(2, seq_829, op_ASSIGN_843);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_850 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_851 = LOGNOT(op_LSHIFT_850);
	RzILOpPure *op_AND_852 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_851);
	RzILOpPure *op_RSHIFT_856 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_859 = LOGAND(op_RSHIFT_856, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_863 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_859), DUP(op_AND_859))), CAST(16, MSB(DUP(op_AND_859)), DUP(op_AND_859))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_868 = SHIFTL0(CAST(64, IL_FALSE, op_AND_863), SN(32, 0x30));
	RzILOpPure *op_OR_870 = LOGOR(CAST(64, IL_FALSE, op_AND_852), op_LSHIFT_868);
	RzILOpEffect *op_ASSIGN_872 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_870));

	// seq({});
	RzILOpEffect *seq_then_877 = EMPTY();

	// if ((((st32) tmp) != 0x3)) {seq({})} else {{}};
	RzILOpPure *op_NE_876 = INV(EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 3)));
	RzILOpEffect *branch_878 = BRANCH(op_NE_876, seq_then_877, EMPTY());

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_928 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_892 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_895 = LOGAND(op_RSHIFT_892, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_898 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_895), DUP(op_AND_895))), CAST(16, MSB(DUP(op_AND_895)), DUP(op_AND_895))));
	RzILOpPure *op_RSHIFT_907 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_910 = LOGAND(op_RSHIFT_907, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_913 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_910), DUP(op_AND_910))), CAST(16, MSB(DUP(op_AND_910)), DUP(op_AND_910))));
	RzILOpPure *op_EQ_915 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_898), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_913), DUP(op_NEG_913)));
	RzILOpPure *op_RSHIFT_932 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_935 = LOGAND(op_RSHIFT_932, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_938 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_935), DUP(op_AND_935))), CAST(16, MSB(DUP(op_AND_935)), DUP(op_AND_935))));
	RzILOpPure *op_LT_940 = SLT(op_NEG_938, SN(32, 0));
	RzILOpPure *op_LSHIFT_945 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_946 = NEG(op_LSHIFT_945);
	RzILOpPure *op_LSHIFT_951 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_954 = SUB(op_LSHIFT_951, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_955 = ITE(op_LT_940, op_NEG_946, op_SUB_954);
	RzILOpEffect *gcc_expr_956 = BRANCH(op_EQ_915, EMPTY(), set_usr_field_call_928);

	// h_tmp542 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_958 = SETL("h_tmp542", cond_955);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_959 = SEQN(2, gcc_expr_956, op_ASSIGN_hybrid_tmp_958);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))))) : h_tmp542) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_883 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_884 = LOGNOT(op_LSHIFT_883);
	RzILOpPure *op_AND_885 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_884);
	RzILOpPure *op_RSHIFT_919 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_922 = LOGAND(op_RSHIFT_919, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_925 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_922), DUP(op_AND_922))), CAST(16, MSB(DUP(op_AND_922)), DUP(op_AND_922))));
	RzILOpPure *cond_961 = ITE(DUP(op_EQ_915), CAST(64, MSB(op_NEG_925), DUP(op_NEG_925)), VARL("h_tmp542"));
	RzILOpPure *op_AND_964 = LOGAND(cond_961, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_969 = SHIFTL0(CAST(64, IL_FALSE, op_AND_964), SN(32, 0x20));
	RzILOpPure *op_OR_971 = LOGOR(CAST(64, IL_FALSE, op_AND_885), op_LSHIFT_969);
	RzILOpEffect *op_ASSIGN_973 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_971));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_974 = SEQN(2, seq_959, op_ASSIGN_973);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_1025 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_989 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_992 = LOGAND(op_RSHIFT_989, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_995 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_992), DUP(op_AND_992))), CAST(16, MSB(DUP(op_AND_992)), DUP(op_AND_992))));
	RzILOpPure *op_RSHIFT_1004 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_1007 = LOGAND(op_RSHIFT_1004, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_1010 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_1007), DUP(op_AND_1007))), CAST(16, MSB(DUP(op_AND_1007)), DUP(op_AND_1007))));
	RzILOpPure *op_EQ_1012 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_NEG_995), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_NEG_1010), DUP(op_NEG_1010)));
	RzILOpPure *op_RSHIFT_1029 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_1032 = LOGAND(op_RSHIFT_1029, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_1035 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_1032), DUP(op_AND_1032))), CAST(16, MSB(DUP(op_AND_1032)), DUP(op_AND_1032))));
	RzILOpPure *op_LT_1037 = SLT(op_NEG_1035, SN(32, 0));
	RzILOpPure *op_LSHIFT_1042 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_1043 = NEG(op_LSHIFT_1042);
	RzILOpPure *op_LSHIFT_1048 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_1051 = SUB(op_LSHIFT_1048, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_1052 = ITE(op_LT_1037, op_NEG_1043, op_SUB_1051);
	RzILOpEffect *gcc_expr_1053 = BRANCH(op_EQ_1012, EMPTY(), set_usr_field_call_1025);

	// h_tmp543 = HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_1055 = SETL("h_tmp543", cond_1052);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ((Rss ...;
	RzILOpEffect *seq_1056 = SEQN(2, gcc_expr_1053, op_ASSIGN_hybrid_tmp_1055);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))), 0x0, 0x10) == ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff))))))) ? ((st64) (-((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))))) : h_tmp543) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_980 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_981 = LOGNOT(op_LSHIFT_980);
	RzILOpPure *op_AND_982 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_981);
	RzILOpPure *op_RSHIFT_1016 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_1019 = LOGAND(op_RSHIFT_1016, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_1022 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_1019), DUP(op_AND_1019))), CAST(16, MSB(DUP(op_AND_1019)), DUP(op_AND_1019))));
	RzILOpPure *cond_1058 = ITE(DUP(op_EQ_1012), CAST(64, MSB(op_NEG_1022), DUP(op_NEG_1022)), VARL("h_tmp543"));
	RzILOpPure *op_AND_1061 = LOGAND(cond_1058, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_1066 = SHIFTL0(CAST(64, IL_FALSE, op_AND_1061), SN(32, 0x30));
	RzILOpPure *op_OR_1068 = LOGOR(CAST(64, IL_FALSE, op_AND_982), op_LSHIFT_1066);
	RzILOpEffect *op_ASSIGN_1070 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_1068));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st16) ( ...;
	RzILOpEffect *seq_1071 = SEQN(2, seq_1056, op_ASSIGN_1070);

	// seq(seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st1 ...;
	RzILOpEffect *seq_then_1073 = SEQN(2, seq_844, op_ASSIGN_872);

	// seq(if ((((st32) tmp) != 0x3)) {seq({})} else {{}}; seq(seq(HYB( ...;
	RzILOpEffect *seq_else_1074 = SEQN(3, branch_878, seq_974, seq_1071);

	// if ((((st32) tmp) == 0x2)) {seq(seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (-((st32) ((st1 ...} else {seq(if ((((st32) tmp) != 0x3)) {seq({})} else {{}}; seq(seq(HYB( ...};
	RzILOpPure *op_EQ_748 = EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 2));
	RzILOpEffect *branch_1075 = BRANCH(op_EQ_748, seq_then_1073, seq_else_1074);

	// seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut6 ...;
	RzILOpEffect *seq_then_1076 = SEQN(2, op_ASSIGN_647, seq_744);

	// seq(if ((((st32) tmp) == 0x2)) {seq(seq(seq(HYB(gcc_expr_if ((se ...;
	RzILOpEffect *seq_else_1077 = branch_1075;

	// if ((((st32) tmp) == 0x1)) {seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut6 ...} else {seq(if ((((st32) tmp) == 0x2)) {seq(seq(seq(HYB(gcc_expr_if ((se ...};
	RzILOpPure *op_EQ_620 = EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 1));
	RzILOpEffect *branch_1078 = BRANCH(op_EQ_620, seq_then_1076, seq_else_1077);

	// seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut6 ...;
	RzILOpEffect *seq_then_1079 = SEQN(2, op_ASSIGN_588, op_ASSIGN_616);

	// seq(if ((((st32) tmp) == 0x1)) {seq(Rdd = ((st64) (((ut64) (Rdd  ...;
	RzILOpEffect *seq_else_1080 = branch_1078;

	// if ((((st32) tmp) == 0x0)) {seq(Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut6 ...} else {seq(if ((((st32) tmp) == 0x1)) {seq(Rdd = ((st64) (((ut64) (Rdd  ...};
	RzILOpPure *op_EQ_561 = EQ(CAST(32, IL_FALSE, VARL("tmp")), SN(32, 0));
	RzILOpEffect *branch_1081 = BRANCH(op_EQ_561, seq_then_1079, seq_else_1080);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_17, branch_542, op_ASSIGN_558, branch_1081);
	return instruction_sequence;
}

// Rxx += vrcnegh(Rss,Rt)
RzILOpEffect *hex_il_op_s2_vrcnegh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp544 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp544", VARL("i"));

	// seq(h_tmp544 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rxx = Rxx + ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))));
	RzILOpPure *op_MUL_16 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rss, op_MUL_16);
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_17, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_NEG_23 = NEG(CAST(32, MSB(CAST(16, MSB(op_AND_20), DUP(op_AND_20))), CAST(16, MSB(DUP(op_AND_20)), DUP(op_AND_20))));
	RzILOpPure *op_ADD_25 = ADD(READ_REG(pkt, Rxx_op, false), CAST(64, MSB(op_NEG_23), DUP(op_NEG_23)));
	RzILOpEffect *op_ASSIGN_ADD_26 = WRITE_REG(bundle, Rxx_op, op_ADD_25);

	// Rxx = Rxx + ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_29 = SHIFTRA(DUP(Rss), op_MUL_28);
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_35 = ADD(READ_REG(pkt, Rxx_op, false), CAST(64, MSB(CAST(16, MSB(op_AND_32), DUP(op_AND_32))), CAST(16, MSB(DUP(op_AND_32)), DUP(op_AND_32))));
	RzILOpEffect *op_ASSIGN_ADD_36 = WRITE_REG(bundle, Rxx_op, op_ADD_35);

	// seq(Rxx = Rxx + ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ( ...;
	RzILOpEffect *seq_then_37 = op_ASSIGN_ADD_26;

	// seq(Rxx = Rxx + ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xf ...;
	RzILOpEffect *seq_else_38 = op_ASSIGN_ADD_36;

	// if (((Rt >> i) & 0x1)) {seq(Rxx = Rxx + ((st64) (-((st32) ((st16) ((Rss >> i * 0x10) & ( ...} else {seq(Rxx = Rxx + ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xf ...};
	RzILOpPure *op_RSHIFT_10 = SHIFTRA(Rt, VARL("i"));
	RzILOpPure *op_AND_12 = LOGAND(op_RSHIFT_10, SN(32, 1));
	RzILOpEffect *branch_39 = BRANCH(NON_ZERO(op_AND_12), seq_then_37, seq_else_38);

	// seq(h_tmp544; if (((Rt >> i) & 0x1)) {seq(Rxx = Rxx + ((st64) (- ...;
	RzILOpEffect *seq_40 = branch_39;

	// seq(seq(h_tmp544; if (((Rt >> i) & 0x1)) {seq(Rxx = Rxx + ((st64 ...;
	RzILOpEffect *seq_41 = SEQN(2, seq_40, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp544; if (((Rt >> i) & 0x1)) {seq(Rxx = Rxx + ((st64 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_42 = REPEAT(op_LT_4, seq_41);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp544; if (((Rt >> i ...;
	RzILOpEffect *seq_43 = SEQN(2, op_ASSIGN_2, for_42);

	RzILOpEffect *instruction_sequence = seq_43;
	return instruction_sequence;
}

// Rd = vrndwh(Rss)
RzILOpEffect *hex_il_op_s2_vrndpackwh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp545 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp545", VARL("i"));

	// seq(h_tmp545 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000) >> 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, op_MUL_19);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_27 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(SN(32, 0x8000)), SN(32, 0x8000)));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(op_ADD_27, SN(32, 16));
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_34), DUP(op_AND_34))), CAST(16, MSB(DUP(op_AND_34)), DUP(op_AND_34))), SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_44));

	// seq(h_tmp545; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp545; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp545; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_50 = REPEAT(op_LT_4, seq_49);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp545; Rd = ((st32)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_2, for_50);

	RzILOpEffect *instruction_sequence = seq_51;
	return instruction_sequence;
}

// Rd = vrndwh(Rss):sat
RzILOpEffect *hex_il_op_s2_vrndpackwhs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp546 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp546", VARL("i"));

	// seq(h_tmp546 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_59 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000)), 0x0, 0x20) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_30 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_25), DUP(op_AND_25))), CAST(32, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(64, MSB(SN(32, 0x8000)), SN(32, 0x8000)));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rss), op_MUL_37);
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_45 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40))), CAST(64, MSB(SN(32, 0x8000)), SN(32, 0x8000)));
	RzILOpPure *op_EQ_46 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_30), SN(32, 0), SN(32, 0x20)), op_ADD_45);
	RzILOpPure *op_MUL_61 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rss), op_MUL_61);
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_62, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_69 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_64), DUP(op_AND_64))), CAST(32, MSB(DUP(op_AND_64)), DUP(op_AND_64))), CAST(64, MSB(SN(32, 0x8000)), SN(32, 0x8000)));
	RzILOpPure *op_LT_72 = SLT(op_ADD_69, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_77 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_78 = NEG(op_LSHIFT_77);
	RzILOpPure *op_LSHIFT_83 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_86 = SUB(op_LSHIFT_83, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_87 = ITE(op_LT_72, op_NEG_78, op_SUB_86);
	RzILOpEffect *gcc_expr_88 = BRANCH(op_EQ_46, EMPTY(), set_usr_field_call_59);

	// h_tmp547 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000)), 0x0, 0x20) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_90 = SETL("h_tmp547", cond_87);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_91 = SEQN(2, gcc_expr_88, op_ASSIGN_hybrid_tmp_90);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000)), 0x0, 0x20) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000)) ? ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) + ((st64) 0x8000) : h_tmp547) >> 0x10) & ((st64) 0xffff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_48 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_49 = SHIFTRA(DUP(Rss), op_MUL_48);
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_49, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_56 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_51), DUP(op_AND_51))), CAST(32, MSB(DUP(op_AND_51)), DUP(op_AND_51))), CAST(64, MSB(SN(32, 0x8000)), SN(32, 0x8000)));
	RzILOpPure *cond_92 = ITE(DUP(op_EQ_46), op_ADD_56, VARL("h_tmp547"));
	RzILOpPure *op_RSHIFT_96 = SHIFTRA(cond_92, SN(32, 16));
	RzILOpPure *op_AND_99 = LOGAND(op_RSHIFT_96, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_103 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_99), DUP(op_AND_99))), CAST(16, MSB(DUP(op_AND_99)), DUP(op_AND_99))), SN(32, 0xffff));
	RzILOpPure *op_MUL_106 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_107 = SHIFTL0(CAST(64, IL_FALSE, op_AND_103), op_MUL_106);
	RzILOpPure *op_OR_109 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_107);
	RzILOpEffect *op_ASSIGN_111 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_109));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_112 = SEQN(2, seq_91, op_ASSIGN_111);

	// seq(h_tmp546; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st6 ...;
	RzILOpEffect *seq_114 = seq_112;

	// seq(seq(h_tmp546; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_115 = SEQN(2, seq_114, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp546; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_116 = REPEAT(op_LT_4, seq_115);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp546; seq(seq(HYB(g ...;
	RzILOpEffect *seq_117 = SEQN(2, op_ASSIGN_2, for_116);

	RzILOpEffect *instruction_sequence = seq_117;
	return instruction_sequence;
}

// Rd = vsathb(Rss)
RzILOpEffect *hex_il_op_s2_vsathb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp548 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp548", VARL("i"));

	// seq(h_tmp548 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_51 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_41 = EQ(SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_26), DUP(op_AND_26))), SN(32, 0), SN(32, 8)), CAST(64, MSB(CAST(16, MSB(op_AND_38), DUP(op_AND_38))), CAST(16, MSB(DUP(op_AND_38)), DUP(op_AND_38))));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_61 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_57), DUP(op_AND_57))), CAST(16, MSB(DUP(op_AND_57)), DUP(op_AND_57))), SN(32, 0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_NEG_67 = NEG(op_LSHIFT_66);
	RzILOpPure *op_LSHIFT_72 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_SUB_75 = SUB(op_LSHIFT_72, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_76 = ITE(op_LT_61, op_NEG_67, op_SUB_75);
	RzILOpEffect *gcc_expr_77 = BRANCH(op_EQ_41, EMPTY(), set_usr_field_call_51);

	// h_tmp549 = HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_79 = SETL("h_tmp549", cond_76);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i * 0x ...;
	RzILOpEffect *seq_80 = SEQN(2, gcc_expr_77, op_ASSIGN_hybrid_tmp_79);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((sextract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) ? ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) : h_tmp549) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_82 = ITE(DUP(op_EQ_41), CAST(64, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))), VARL("h_tmp549"));
	RzILOpPure *op_AND_84 = LOGAND(cond_82, SN(64, 0xff));
	RzILOpPure *op_MUL_87 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(CAST(64, IL_FALSE, op_AND_84), op_MUL_87);
	RzILOpPure *op_OR_90 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_88);
	RzILOpEffect *op_ASSIGN_92 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_90));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i  ...;
	RzILOpEffect *seq_93 = SEQN(2, seq_80, op_ASSIGN_92);

	// seq(h_tmp548; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st1 ...;
	RzILOpEffect *seq_95 = seq_93;

	// seq(seq(h_tmp548; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_96 = SEQN(2, seq_95, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp548; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_97 = REPEAT(op_LT_4, seq_96);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp548; seq(seq(HYB(g ...;
	RzILOpEffect *seq_98 = SEQN(2, op_ASSIGN_2, for_97);

	RzILOpEffect *instruction_sequence = seq_98;
	return instruction_sequence;
}

// Rdd = vsathb(Rss)
RzILOpEffect *hex_il_op_s2_vsathb_nopack(HexInsnPktBundle *bundle) {
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

	// h_tmp550 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp550", VARL("i"));

	// seq(h_tmp550 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_50 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(DUP(Rss), op_MUL_33);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_34, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_40 = EQ(SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_25), DUP(op_AND_25))), SN(32, 0), SN(32, 8)), CAST(64, MSB(CAST(16, MSB(op_AND_37), DUP(op_AND_37))), CAST(16, MSB(DUP(op_AND_37)), DUP(op_AND_37))));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rss), op_MUL_52);
	RzILOpPure *op_AND_56 = LOGAND(op_RSHIFT_53, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_60 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_56), DUP(op_AND_56))), CAST(16, MSB(DUP(op_AND_56)), DUP(op_AND_56))), SN(32, 0));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_NEG_66 = NEG(op_LSHIFT_65);
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(SN(64, 1), SN(32, 7));
	RzILOpPure *op_SUB_74 = SUB(op_LSHIFT_71, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_75 = ITE(op_LT_60, op_NEG_66, op_SUB_74);
	RzILOpEffect *gcc_expr_76 = BRANCH(op_EQ_40, EMPTY(), set_usr_field_call_50);

	// h_tmp551 = HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0x7)) : (0x1 << 0x7) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_78 = SETL("h_tmp551", cond_75);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i * 0x ...;
	RzILOpEffect *seq_79 = SEQN(2, gcc_expr_76, op_ASSIGN_hybrid_tmp_78);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) ? ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) : h_tmp551) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rss), op_MUL_42);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_43, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_81 = ITE(DUP(op_EQ_40), CAST(64, MSB(CAST(16, MSB(op_AND_46), DUP(op_AND_46))), CAST(16, MSB(DUP(op_AND_46)), DUP(op_AND_46))), VARL("h_tmp551"));
	RzILOpPure *op_AND_84 = LOGAND(cond_81, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_87 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(CAST(64, IL_FALSE, op_AND_84), op_MUL_87);
	RzILOpPure *op_OR_90 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_88);
	RzILOpEffect *op_ASSIGN_92 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_90));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st16) ((Rss >> i  ...;
	RzILOpEffect *seq_93 = SEQN(2, seq_79, op_ASSIGN_92);

	// seq(h_tmp550; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st1 ...;
	RzILOpEffect *seq_95 = seq_93;

	// seq(seq(h_tmp550; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_96 = SEQN(2, seq_95, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp550; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_97 = REPEAT(op_LT_4, seq_96);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp550; seq(seq(HYB(g ...;
	RzILOpEffect *seq_98 = SEQN(2, op_ASSIGN_2, for_97);

	RzILOpEffect *instruction_sequence = seq_98;
	return instruction_sequence;
}

// Rd = vsathub(Rss)
RzILOpEffect *hex_il_op_s2_vsathub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp552 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp552", VARL("i"));

	// seq(h_tmp552 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_51 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_41 = EQ(EXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_26), DUP(op_AND_26))), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, CAST(16, MSB(op_AND_38), DUP(op_AND_38))));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_61 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_57), DUP(op_AND_57))), CAST(16, MSB(DUP(op_AND_57)), DUP(op_AND_57))), SN(32, 0));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_68 = SUB(op_LSHIFT_65, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_70 = ITE(op_LT_61, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_68);
	RzILOpEffect *gcc_expr_71 = BRANCH(op_EQ_41, EMPTY(), set_usr_field_call_51);

	// h_tmp553 = HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_73 = SETL("h_tmp553", cond_70);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * 0x1 ...;
	RzILOpEffect *seq_74 = SEQN(2, gcc_expr_71, op_ASSIGN_hybrid_tmp_73);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((extract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) ? ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) : h_tmp553) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_76 = ITE(DUP(op_EQ_41), CAST(64, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))), VARL("h_tmp553"));
	RzILOpPure *op_AND_78 = LOGAND(cond_76, SN(64, 0xff));
	RzILOpPure *op_MUL_81 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(CAST(64, IL_FALSE, op_AND_78), op_MUL_81);
	RzILOpPure *op_OR_84 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_82);
	RzILOpEffect *op_ASSIGN_86 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_84));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * ...;
	RzILOpEffect *seq_87 = SEQN(2, seq_74, op_ASSIGN_86);

	// seq(h_tmp552; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16 ...;
	RzILOpEffect *seq_89 = seq_87;

	// seq(seq(h_tmp552; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_90 = SEQN(2, seq_89, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp552; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_91 = REPEAT(op_LT_4, seq_90);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp552; seq(seq(HYB(g ...;
	RzILOpEffect *seq_92 = SEQN(2, op_ASSIGN_2, for_91);

	RzILOpEffect *instruction_sequence = seq_92;
	return instruction_sequence;
}

// Rdd = vsathub(Rss)
RzILOpEffect *hex_il_op_s2_vsathub_nopack(HexInsnPktBundle *bundle) {
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

	// h_tmp554 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp554", VARL("i"));

	// seq(h_tmp554 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_50 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(DUP(Rss), op_MUL_33);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_34, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_40 = EQ(EXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_25), DUP(op_AND_25))), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, CAST(16, MSB(op_AND_37), DUP(op_AND_37))));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rss), op_MUL_52);
	RzILOpPure *op_AND_56 = LOGAND(op_RSHIFT_53, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_60 = SLT(CAST(32, MSB(CAST(16, MSB(op_AND_56), DUP(op_AND_56))), CAST(16, MSB(DUP(op_AND_56)), DUP(op_AND_56))), SN(32, 0));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_67 = SUB(op_LSHIFT_64, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_69 = ITE(op_LT_60, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_67);
	RzILOpEffect *gcc_expr_70 = BRANCH(op_EQ_40, EMPTY(), set_usr_field_call_50);

	// h_tmp555 = HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_72 = SETL("h_tmp555", cond_69);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * 0x1 ...;
	RzILOpEffect *seq_73 = SEQN(2, gcc_expr_70, op_ASSIGN_hybrid_tmp_72);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((extract64(((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))), 0x0, 0x8) == ((ut64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))))) ? ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) : h_tmp555) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rss), op_MUL_42);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_43, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *cond_75 = ITE(DUP(op_EQ_40), CAST(64, MSB(CAST(16, MSB(op_AND_46), DUP(op_AND_46))), CAST(16, MSB(DUP(op_AND_46)), DUP(op_AND_46))), VARL("h_tmp555"));
	RzILOpPure *op_AND_78 = LOGAND(cond_75, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_81 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(CAST(64, IL_FALSE, op_AND_78), op_MUL_81);
	RzILOpPure *op_OR_84 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_82);
	RzILOpEffect *op_ASSIGN_86 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_84));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16) ((Rss >> i * ...;
	RzILOpEffect *seq_87 = SEQN(2, seq_73, op_ASSIGN_86);

	// seq(h_tmp554; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st16 ...;
	RzILOpEffect *seq_89 = seq_87;

	// seq(seq(h_tmp554; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_90 = SEQN(2, seq_89, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp554; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_91 = REPEAT(op_LT_4, seq_90);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp554; seq(seq(HYB(g ...;
	RzILOpEffect *seq_92 = SEQN(2, op_ASSIGN_2, for_91);

	RzILOpEffect *instruction_sequence = seq_92;
	return instruction_sequence;
}

// Rd = vsatwh(Rss)
RzILOpEffect *hex_il_op_s2_vsatwh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp556 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp556", VARL("i"));

	// seq(h_tmp556 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_50 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_40 = EQ(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_25), DUP(op_AND_25))), CAST(32, MSB(DUP(op_AND_25)), DUP(op_AND_25)))), SN(32, 0), SN(32, 16)), CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rss), op_MUL_52);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_53, SN(64, 0xffffffff));
	RzILOpPure *op_LT_60 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_55), DUP(op_AND_55))), CAST(32, MSB(DUP(op_AND_55)), DUP(op_AND_55))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_66 = NEG(op_LSHIFT_65);
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_74 = SUB(op_LSHIFT_71, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_75 = ITE(op_LT_60, op_NEG_66, op_SUB_74);
	RzILOpEffect *gcc_expr_76 = BRANCH(op_EQ_40, EMPTY(), set_usr_field_call_50);

	// h_tmp557 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_78 = SETL("h_tmp557", cond_75);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_79 = SEQN(2, gcc_expr_76, op_ASSIGN_hybrid_tmp_78);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) : h_tmp557) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rss), op_MUL_42);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_43, SN(64, 0xffffffff));
	RzILOpPure *cond_80 = ITE(DUP(op_EQ_40), CAST(64, MSB(CAST(32, MSB(op_AND_45), DUP(op_AND_45))), CAST(32, MSB(DUP(op_AND_45)), DUP(op_AND_45))), VARL("h_tmp557"));
	RzILOpPure *op_AND_83 = LOGAND(cond_80, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_86 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_87 = SHIFTL0(CAST(64, IL_FALSE, op_AND_83), op_MUL_86);
	RzILOpPure *op_OR_89 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_87);
	RzILOpEffect *op_ASSIGN_91 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_89));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_92 = SEQN(2, seq_79, op_ASSIGN_91);

	// seq(h_tmp556; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st6 ...;
	RzILOpEffect *seq_94 = seq_92;

	// seq(seq(h_tmp556; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_95 = SEQN(2, seq_94, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp556; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_96 = REPEAT(op_LT_4, seq_95);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp556; seq(seq(HYB(g ...;
	RzILOpEffect *seq_97 = SEQN(2, op_ASSIGN_2, for_96);

	RzILOpEffect *instruction_sequence = seq_97;
	return instruction_sequence;
}

// Rdd = vsatwh(Rss)
RzILOpEffect *hex_il_op_s2_vsatwh_nopack(HexInsnPktBundle *bundle) {
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

	// h_tmp558 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp558", VARL("i"));

	// seq(h_tmp558 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_49 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(DUP(Rss), op_MUL_33);
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_34, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_39 = EQ(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(32, 0), SN(32, 16)), CAST(64, MSB(CAST(32, MSB(op_AND_36), DUP(op_AND_36))), CAST(32, MSB(DUP(op_AND_36)), DUP(op_AND_36))));
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rss), op_MUL_51);
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_52, SN(64, 0xffffffff));
	RzILOpPure *op_LT_59 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_54), DUP(op_AND_54))), CAST(32, MSB(DUP(op_AND_54)), DUP(op_AND_54))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_65 = NEG(op_LSHIFT_64);
	RzILOpPure *op_LSHIFT_70 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_73 = SUB(op_LSHIFT_70, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_74 = ITE(op_LT_59, op_NEG_65, op_SUB_73);
	RzILOpEffect *gcc_expr_75 = BRANCH(op_EQ_39, EMPTY(), set_usr_field_call_49);

	// h_tmp559 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_77 = SETL("h_tmp559", cond_74);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_78 = SEQN(2, gcc_expr_75, op_ASSIGN_hybrid_tmp_77);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) : h_tmp559) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(DUP(Rss), op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpPure *cond_79 = ITE(DUP(op_EQ_39), CAST(64, MSB(CAST(32, MSB(op_AND_44), DUP(op_AND_44))), CAST(32, MSB(DUP(op_AND_44)), DUP(op_AND_44))), VARL("h_tmp559"));
	RzILOpPure *op_AND_81 = LOGAND(cond_79, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_83 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_84 = SHIFTL0(op_AND_81, op_MUL_83);
	RzILOpPure *op_OR_85 = LOGOR(op_AND_15, op_LSHIFT_84);
	RzILOpEffect *op_ASSIGN_86 = WRITE_REG(bundle, Rdd_op, op_OR_85);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_87 = SEQN(2, seq_78, op_ASSIGN_86);

	// seq(h_tmp558; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st6 ...;
	RzILOpEffect *seq_89 = seq_87;

	// seq(seq(h_tmp558; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ...;
	RzILOpEffect *seq_90 = SEQN(2, seq_89, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp558; seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_91 = REPEAT(op_LT_4, seq_90);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp558; seq(seq(HYB(g ...;
	RzILOpEffect *seq_92 = SEQN(2, op_ASSIGN_2, for_91);

	RzILOpEffect *instruction_sequence = seq_92;
	return instruction_sequence;
}

// Rd = vsatwuh(Rss)
RzILOpEffect *hex_il_op_s2_vsatwuh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp560 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp560", VARL("i"));

	// seq(h_tmp560 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_51 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_23, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_41 = EQ(EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_25), DUP(op_AND_25))), CAST(32, MSB(DUP(op_AND_25)), DUP(op_AND_25)))), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))));
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rss), op_MUL_53);
	RzILOpPure *op_AND_56 = LOGAND(op_RSHIFT_54, SN(64, 0xffffffff));
	RzILOpPure *op_LT_61 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_56), DUP(op_AND_56))), CAST(32, MSB(DUP(op_AND_56)), DUP(op_AND_56))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_68 = SUB(op_LSHIFT_65, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_70 = ITE(op_LT_61, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_68);
	RzILOpEffect *gcc_expr_71 = BRANCH(op_EQ_41, EMPTY(), set_usr_field_call_51);

	// h_tmp561 = HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_73 = SETL("h_tmp561", cond_70);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rss >> ...;
	RzILOpEffect *seq_74 = SEQN(2, gcc_expr_71, op_ASSIGN_hybrid_tmp_73);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((extract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) ? ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) : h_tmp561) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(64, 0xffffffff));
	RzILOpPure *cond_75 = ITE(DUP(op_EQ_41), CAST(64, MSB(CAST(32, MSB(op_AND_46), DUP(op_AND_46))), CAST(32, MSB(DUP(op_AND_46)), DUP(op_AND_46))), VARL("h_tmp561"));
	RzILOpPure *op_AND_78 = LOGAND(cond_75, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_81 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(CAST(64, IL_FALSE, op_AND_78), op_MUL_81);
	RzILOpPure *op_OR_84 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_82);
	RzILOpEffect *op_ASSIGN_86 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_84));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rs ...;
	RzILOpEffect *seq_87 = SEQN(2, seq_74, op_ASSIGN_86);

	// seq(h_tmp560; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st64 ...;
	RzILOpEffect *seq_89 = seq_87;

	// seq(seq(h_tmp560; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_90 = SEQN(2, seq_89, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp560; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_91 = REPEAT(op_LT_4, seq_90);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp560; seq(seq(HYB(g ...;
	RzILOpEffect *seq_92 = SEQN(2, op_ASSIGN_2, for_91);

	RzILOpEffect *instruction_sequence = seq_92;
	return instruction_sequence;
}

// Rdd = vsatwuh(Rss)
RzILOpEffect *hex_il_op_s2_vsatwuh_nopack(HexInsnPktBundle *bundle) {
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

	// h_tmp562 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp562", VARL("i"));

	// seq(h_tmp562 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_50 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(DUP(Rss), op_MUL_33);
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_34, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_40 = EQ(EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_24), DUP(op_AND_24))), CAST(32, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(32, 0), SN(32, 16)), CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_36), DUP(op_AND_36))), CAST(32, MSB(DUP(op_AND_36)), DUP(op_AND_36)))));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rss), op_MUL_52);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_53, SN(64, 0xffffffff));
	RzILOpPure *op_LT_60 = SLT(CAST(64, MSB(CAST(32, MSB(op_AND_55), DUP(op_AND_55))), CAST(32, MSB(DUP(op_AND_55)), DUP(op_AND_55))), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(SN(64, 1), SN(32, 16));
	RzILOpPure *op_SUB_67 = SUB(op_LSHIFT_64, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_69 = ITE(op_LT_60, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_67);
	RzILOpEffect *gcc_expr_70 = BRANCH(op_EQ_40, EMPTY(), set_usr_field_call_50);

	// h_tmp563 = HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) < ((st64) 0x0)) ? ((st64) 0x0) : (0x1 << 0x10) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_72 = SETL("h_tmp563", cond_69);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rss >> ...;
	RzILOpEffect *seq_73 = SEQN(2, gcc_expr_70, op_ASSIGN_hybrid_tmp_72);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((extract64(((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)))), 0x0, 0x10) == ((ut64) ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) ? ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))) : h_tmp563) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rss), op_MUL_42);
	RzILOpPure *op_AND_45 = LOGAND(op_RSHIFT_43, SN(64, 0xffffffff));
	RzILOpPure *cond_74 = ITE(DUP(op_EQ_40), CAST(64, MSB(CAST(32, MSB(op_AND_45), DUP(op_AND_45))), CAST(32, MSB(DUP(op_AND_45)), DUP(op_AND_45))), VARL("h_tmp563"));
	RzILOpPure *op_AND_76 = LOGAND(cond_74, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_79 = SHIFTL0(op_AND_76, op_MUL_78);
	RzILOpPure *op_OR_80 = LOGOR(op_AND_15, op_LSHIFT_79);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Rdd_op, op_OR_80);

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st64) ((st32) ((Rs ...;
	RzILOpEffect *seq_82 = SEQN(2, seq_73, op_ASSIGN_81);

	// seq(h_tmp562; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st64 ...;
	RzILOpEffect *seq_84 = seq_82;

	// seq(seq(h_tmp562; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_85 = SEQN(2, seq_84, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp562; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_86 = REPEAT(op_LT_4, seq_85);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp562; seq(seq(HYB(g ...;
	RzILOpEffect *seq_87 = SEQN(2, op_ASSIGN_2, for_86);

	RzILOpEffect *instruction_sequence = seq_87;
	return instruction_sequence;
}

// Rd = vsplatb(Rs)
RzILOpEffect *hex_il_op_s2_vsplatrb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp564 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp564", VARL("i"));

	// seq(h_tmp564 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rs >> 0x0) & 0xff)))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_23 = LOGAND(op_RSHIFT_21, SN(32, 0xff));
	RzILOpPure *op_AND_28 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_23), DUP(op_AND_23))), CAST(8, MSB(DUP(op_AND_23)), DUP(op_AND_23)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_23)), DUP(op_AND_23))), CAST(8, MSB(DUP(op_AND_23)), DUP(op_AND_23)))), SN(64, 0xff));
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_32 = SHIFTL0(CAST(64, IL_FALSE, op_AND_28), op_MUL_31);
	RzILOpPure *op_OR_34 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_32);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_34));

	// seq(h_tmp564; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i  ...;
	RzILOpEffect *seq_38 = op_ASSIGN_36;

	// seq(seq(h_tmp564; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff < ...;
	RzILOpEffect *seq_39 = SEQN(2, seq_38, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp564; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff < ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_40 = REPEAT(op_LT_4, seq_39);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp564; Rd = ((st32)  ...;
	RzILOpEffect *seq_41 = SEQN(2, op_ASSIGN_2, for_40);

	RzILOpEffect *instruction_sequence = seq_41;
	return instruction_sequence;
}

// Rdd = vsplath(Rs)
RzILOpEffect *hex_il_op_s2_vsplatrh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp565 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp565", VARL("i"));

	// seq(h_tmp565 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st16) ((Rs >> 0x0) & 0xffff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpPure *op_AND_26 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_22), DUP(op_AND_22))), CAST(16, MSB(DUP(op_AND_22)), DUP(op_AND_22))), SN(32, 0xffff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(CAST(64, IL_FALSE, op_AND_26), op_MUL_29);
	RzILOpPure *op_OR_32 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_34 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_32));

	// seq(h_tmp565; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_36 = op_ASSIGN_34;

	// seq(seq(h_tmp565; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_37 = SEQN(2, seq_36, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp565; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_38 = REPEAT(op_LT_4, seq_37);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp565; Rdd = ((st64) ...;
	RzILOpEffect *seq_39 = SEQN(2, op_ASSIGN_2, for_38);

	RzILOpEffect *instruction_sequence = seq_39;
	return instruction_sequence;
}

// Rdd = vspliceb(Rss,Rtt,Ii)
RzILOpEffect *hex_il_op_s2_vspliceib(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rdd = ((st64) (((ut64) ((u * ((ut32) 0x8) >= ((ut32) 0x40)) ? ((st64) 0x0) : (Rtt << u * ((ut32) 0x8)))) | ((u * ((ut32) 0x8) != ((ut32) 0x0)) ? extract64(((ut64) Rss), 0x0, ((st32) u * ((ut32) 0x8))) : ((ut64) 0x0))));
	RzILOpPure *op_MUL_5 = MUL(VARL("u"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_GE_11 = UGE(op_MUL_5, CAST(32, IL_FALSE, SN(32, 0x40)));
	RzILOpPure *op_MUL_15 = MUL(VARL("u"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(Rtt, op_MUL_15);
	RzILOpPure *cond_18 = ITE(op_GE_11, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_16);
	RzILOpPure *op_MUL_21 = MUL(VARL("u"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *op_NE_24 = INV(EQ(op_MUL_21, CAST(32, IL_FALSE, SN(32, 0))));
	RzILOpPure *op_MUL_29 = MUL(VARL("u"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpPure *cond_35 = ITE(op_NE_24, EXTRACT64(CAST(64, IL_FALSE, Rss), SN(32, 0), CAST(32, IL_FALSE, op_MUL_29)), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpPure *op_OR_37 = LOGOR(CAST(64, IL_FALSE, cond_18), cond_35);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_37));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_39);
	return instruction_sequence;
}

// Rdd = vspliceb(Rss,Rtt,Pu)
RzILOpEffect *hex_il_op_s2_vsplicerb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) (((ut64) (((((st32) Pu) & 0x7) * 0x8 >= 0x40) ? ((st64) 0x0) : (Rtt << (((st32) Pu) & 0x7) * 0x8))) | (((((st32) Pu) & 0x7) * 0x8 != 0x0) ? extract64(((ut64) Rss), 0x0, (((st32) Pu) & 0x7) * 0x8) : ((ut64) 0x0))));
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_MUL_6 = MUL(op_AND_4, SN(32, 8));
	RzILOpPure *op_GE_11 = SGE(op_MUL_6, SN(32, 0x40));
	RzILOpPure *op_AND_15 = LOGAND(CAST(32, MSB(DUP(Pu)), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_MUL_17 = MUL(op_AND_15, SN(32, 8));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(Rtt, op_MUL_17);
	RzILOpPure *cond_20 = ITE(op_GE_11, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_LSHIFT_18);
	RzILOpPure *op_AND_23 = LOGAND(CAST(32, MSB(DUP(Pu)), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_MUL_25 = MUL(op_AND_23, SN(32, 8));
	RzILOpPure *op_NE_27 = INV(EQ(op_MUL_25, SN(32, 0)));
	RzILOpPure *op_AND_32 = LOGAND(CAST(32, MSB(DUP(Pu)), DUP(Pu)), SN(32, 7));
	RzILOpPure *op_MUL_34 = MUL(op_AND_32, SN(32, 8));
	RzILOpPure *cond_39 = ITE(op_NE_27, EXTRACT64(CAST(64, IL_FALSE, Rss), SN(32, 0), op_MUL_34), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpPure *op_OR_41 = LOGOR(CAST(64, IL_FALSE, cond_20), cond_39);
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_41));

	RzILOpEffect *instruction_sequence = op_ASSIGN_43;
	return instruction_sequence;
}

// Rdd = vsxtbh(Rs)
RzILOpEffect *hex_il_op_s2_vsxtbh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp566 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp566", VARL("i"));

	// seq(h_tmp566 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((Rs >> i * 0x8) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rs, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpPure *op_AND_25 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_21), DUP(op_AND_21))), CAST(8, MSB(DUP(op_AND_21)), DUP(op_AND_21))), SN(32, 0xffff));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(CAST(64, IL_FALSE, op_AND_25), op_MUL_28);
	RzILOpPure *op_OR_31 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_31));

	// seq(h_tmp566; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp566; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp566; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_37 = REPEAT(op_LT_4, seq_36);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp566; Rdd = ((st64) ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	RzILOpEffect *instruction_sequence = seq_38;
	return instruction_sequence;
}

// Rdd = vsxthw(Rs)
RzILOpEffect *hex_il_op_s2_vsxthw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp567 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp567", VARL("i"));

	// seq(h_tmp567 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((st64) ((st32) ((st16) ((Rs >> i * 0x10) & 0xffff)))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rs, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpPure *op_AND_26 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_21), DUP(op_AND_21))), CAST(16, MSB(DUP(op_AND_21)), DUP(op_AND_21)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_21)), DUP(op_AND_21))), CAST(16, MSB(DUP(op_AND_21)), DUP(op_AND_21)))), SN(64, 0xffffffff));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(op_AND_26, op_MUL_28);
	RzILOpPure *op_OR_30 = LOGOR(op_AND_15, op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rdd_op, op_OR_30);

	// seq(h_tmp567; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((s ...;
	RzILOpEffect *seq_33 = op_ASSIGN_31;

	// seq(seq(h_tmp567; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_34 = SEQN(2, seq_33, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp567; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_35 = REPEAT(op_LT_4, seq_34);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp567; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_36 = SEQN(2, op_ASSIGN_2, for_35);

	RzILOpEffect *instruction_sequence = seq_36;
	return instruction_sequence;
}

// Rd = vtrunehb(Rss)
RzILOpEffect *hex_il_op_s2_vtrunehb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp568 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp568", VARL("i"));

	// seq(h_tmp568 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rss >> i * 0x2 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_21 = MUL(op_MUL_19, SN(32, 8));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rss, op_MUL_21);
	RzILOpPure *op_AND_25 = LOGAND(op_RSHIFT_22, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_25), DUP(op_AND_25))), CAST(8, MSB(DUP(op_AND_25)), DUP(op_AND_25)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_25)), DUP(op_AND_25))), CAST(8, MSB(DUP(op_AND_25)), DUP(op_AND_25)))), SN(64, 0xff));
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(CAST(64, IL_FALSE, op_AND_30), op_MUL_33);
	RzILOpPure *op_OR_36 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_38 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_36));

	// seq(h_tmp568; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i  ...;
	RzILOpEffect *seq_40 = op_ASSIGN_38;

	// seq(seq(h_tmp568; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff < ...;
	RzILOpEffect *seq_41 = SEQN(2, seq_40, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp568; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff < ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_42 = REPEAT(op_LT_4, seq_41);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp568; Rd = ((st32)  ...;
	RzILOpEffect *seq_43 = SEQN(2, op_ASSIGN_2, for_42);

	RzILOpEffect *instruction_sequence = seq_43;
	return instruction_sequence;
}

// Rdd = vtrunewh(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_vtrunewh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_12, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_19 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, op_AND_19), SN(32, 0));
	RzILOpPure *op_OR_26 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_24);
	RzILOpEffect *op_ASSIGN_28 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_26));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_35 = LOGNOT(op_LSHIFT_34);
	RzILOpPure *op_AND_36 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_35);
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_47 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_43), DUP(op_AND_43))), CAST(16, MSB(DUP(op_AND_43)), DUP(op_AND_43))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(CAST(64, IL_FALSE, op_AND_47), SN(32, 16));
	RzILOpPure *op_OR_54 = LOGOR(CAST(64, IL_FALSE, op_AND_36), op_LSHIFT_52);
	RzILOpEffect *op_ASSIGN_56 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_54));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_63 = LOGNOT(op_LSHIFT_62);
	RzILOpPure *op_AND_64 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_63);
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_76 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_81 = SHIFTL0(CAST(64, IL_FALSE, op_AND_76), SN(32, 0x20));
	RzILOpPure *op_OR_83 = LOGOR(CAST(64, IL_FALSE, op_AND_64), op_LSHIFT_81);
	RzILOpEffect *op_ASSIGN_85 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_83));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_92 = LOGNOT(op_LSHIFT_91);
	RzILOpPure *op_AND_93 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_92);
	RzILOpPure *op_RSHIFT_97 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_97, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_104 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_100), DUP(op_AND_100))), CAST(16, MSB(DUP(op_AND_100)), DUP(op_AND_100))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(CAST(64, IL_FALSE, op_AND_104), SN(32, 0x30));
	RzILOpPure *op_OR_111 = LOGOR(CAST(64, IL_FALSE, op_AND_93), op_LSHIFT_109);
	RzILOpEffect *op_ASSIGN_113 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_111));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_28, op_ASSIGN_56, op_ASSIGN_85, op_ASSIGN_113);
	return instruction_sequence;
}

// Rd = vtrunohb(Rss)
RzILOpEffect *hex_il_op_s2_vtrunohb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp569 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp569", VARL("i"));

	// seq(h_tmp569 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rss >> i * 0x2 + 0x1 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_19 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_21 = ADD(op_MUL_19, SN(32, 1));
	RzILOpPure *op_MUL_23 = MUL(op_ADD_21, SN(32, 8));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rss, op_MUL_23);
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_32 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_27), DUP(op_AND_27))), CAST(8, MSB(DUP(op_AND_27)), DUP(op_AND_27)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_27)), DUP(op_AND_27))), CAST(8, MSB(DUP(op_AND_27)), DUP(op_AND_27)))), SN(64, 0xff));
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(CAST(64, IL_FALSE, op_AND_32), op_MUL_35);
	RzILOpPure *op_OR_38 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_36);
	RzILOpEffect *op_ASSIGN_40 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_38));

	// seq(h_tmp569; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i  ...;
	RzILOpEffect *seq_42 = op_ASSIGN_40;

	// seq(seq(h_tmp569; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff < ...;
	RzILOpEffect *seq_43 = SEQN(2, seq_42, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp569; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff < ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_44 = REPEAT(op_LT_4, seq_43);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp569; Rd = ((st32)  ...;
	RzILOpEffect *seq_45 = SEQN(2, op_ASSIGN_2, for_44);

	RzILOpEffect *instruction_sequence = seq_45;
	return instruction_sequence;
}

// Rdd = vtrunowh(Rss,Rtt)
RzILOpEffect *hex_il_op_s2_vtrunowh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rtt, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_12, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_19 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_15), DUP(op_AND_15))), CAST(16, MSB(DUP(op_AND_15)), DUP(op_AND_15))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(CAST(64, IL_FALSE, op_AND_19), SN(32, 0));
	RzILOpPure *op_OR_26 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_24);
	RzILOpEffect *op_ASSIGN_28 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_26));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_35 = LOGNOT(op_LSHIFT_34);
	RzILOpPure *op_AND_36 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_35);
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_47 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_43), DUP(op_AND_43))), CAST(16, MSB(DUP(op_AND_43)), DUP(op_AND_43))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(CAST(64, IL_FALSE, op_AND_47), SN(32, 16));
	RzILOpPure *op_OR_54 = LOGOR(CAST(64, IL_FALSE, op_AND_36), op_LSHIFT_52);
	RzILOpEffect *op_ASSIGN_56 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_54));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_63 = LOGNOT(op_LSHIFT_62);
	RzILOpPure *op_AND_64 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_63);
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(Rss, SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_76 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_81 = SHIFTL0(CAST(64, IL_FALSE, op_AND_76), SN(32, 0x20));
	RzILOpPure *op_OR_83 = LOGOR(CAST(64, IL_FALSE, op_AND_64), op_LSHIFT_81);
	RzILOpEffect *op_ASSIGN_85 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_83));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_92 = LOGNOT(op_LSHIFT_91);
	RzILOpPure *op_AND_93 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_92);
	RzILOpPure *op_RSHIFT_97 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_97, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_AND_104 = LOGAND(CAST(32, MSB(CAST(16, MSB(op_AND_100), DUP(op_AND_100))), CAST(16, MSB(DUP(op_AND_100)), DUP(op_AND_100))), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(CAST(64, IL_FALSE, op_AND_104), SN(32, 0x30));
	RzILOpPure *op_OR_111 = LOGOR(CAST(64, IL_FALSE, op_AND_93), op_LSHIFT_109);
	RzILOpEffect *op_ASSIGN_113 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_111));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_28, op_ASSIGN_56, op_ASSIGN_85, op_ASSIGN_113);
	return instruction_sequence;
}

// Rdd = vzxtbh(Rs)
RzILOpEffect *hex_il_op_s2_vzxtbh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp570 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp570", VARL("i"));

	// seq(h_tmp570 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((Rs >> i * 0x8) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rs, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpPure *op_AND_25 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_21)), SN(32, 0xffff));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(CAST(64, IL_FALSE, op_AND_25), op_MUL_28);
	RzILOpPure *op_OR_31 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_31));

	// seq(h_tmp570; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp570; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp570; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_37 = REPEAT(op_LT_4, seq_36);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp570; Rdd = ((st64) ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	RzILOpEffect *instruction_sequence = seq_38;
	return instruction_sequence;
}

// Rdd = vzxthw(Rs)
RzILOpEffect *hex_il_op_s2_vzxthw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp571 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp571", VARL("i"));

	// seq(h_tmp571 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((st64) ((st32) ((ut16) ((Rs >> i * 0x10) & 0xffff)))) & 0xffffffff) << i * 0x20));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffffffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rs, op_MUL_18);
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpPure *op_AND_26 = LOGAND(CAST(64, MSB(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_21))), CAST(32, IL_FALSE, CAST(16, IL_FALSE, DUP(op_AND_21)))), SN(64, 0xffffffff));
	RzILOpPure *op_MUL_28 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(op_AND_26, op_MUL_28);
	RzILOpPure *op_OR_30 = LOGOR(op_AND_15, op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rdd_op, op_OR_30);

	// seq(h_tmp571; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ((((s ...;
	RzILOpEffect *seq_33 = op_ASSIGN_31;

	// seq(seq(h_tmp571; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ...;
	RzILOpEffect *seq_34 = SEQN(2, seq_33, seq_8);

	// while ((i < 0x2)) { seq(seq(h_tmp571; Rdd = ((Rdd & (~(0xffffffff << i * 0x20))) | ( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_35 = REPEAT(op_LT_4, seq_34);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp571; Rdd = ((Rdd & ...;
	RzILOpEffect *seq_36 = SEQN(2, op_ASSIGN_2, for_35);

	RzILOpEffect *instruction_sequence = seq_36;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>