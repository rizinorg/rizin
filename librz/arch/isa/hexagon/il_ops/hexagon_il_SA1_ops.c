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

// Rx = add(Rxin,Ii)
RzILOpEffect *hex_il_op_sa1_addi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_3 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rx_op, op_ADD_3);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_4);
	return instruction_sequence;
}

// Rx = add(Rxin,Rs)
RzILOpEffect *hex_il_op_sa1_addrx(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rx = Rx + Rs;
	RzILOpPure *op_ADD_2 = ADD(READ_REG(pkt, Rx_op, false), Rs);
	RzILOpEffect *op_ASSIGN_3 = WRITE_REG(bundle, Rx_op, op_ADD_2);

	RzILOpEffect *instruction_sequence = op_ASSIGN_3;
	return instruction_sequence;
}

// Rd = add(r29,Ii)
RzILOpEffect *hex_il_op_sa1_addsp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);
	RzILOpPure *sp = READ_REG(pkt, &sp_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rd = ((st32) sp + u);
	RzILOpPure *op_ADD_4 = ADD(sp, VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_4));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rd = and(Rs,#1)
RzILOpEffect *hex_il_op_sa1_and1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs & 0x1);
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_AND_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// if (!p0) Rd = #0
RzILOpEffect *hex_il_op_sa1_clrf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	RzILOpPure *P0 = READ_REG(pkt, &P0_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = 0x0;
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, SN(32, 0));

	// nop;
	RzILOpEffect *nop_8 = NOP();

	// seq(Rd = 0x0);
	RzILOpEffect *seq_then_9 = op_ASSIGN_7;

	// seq(nop);
	RzILOpEffect *seq_else_10 = nop_8;

	// if (! (((st32) P0) & 0x1)) {seq(Rd = 0x0)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0), DUP(P0)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_11 = BRANCH(op_INV_4, seq_then_9, seq_else_10);

	RzILOpEffect *instruction_sequence = branch_11;
	return instruction_sequence;
}

// if (!p0.new) Rd = #0
RzILOpEffect *hex_il_op_sa1_clrfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = 0x0;
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, SN(32, 0));

	// nop;
	RzILOpEffect *nop_8 = NOP();

	// seq(Rd = 0x0);
	RzILOpEffect *seq_then_9 = op_ASSIGN_7;

	// seq(nop);
	RzILOpEffect *seq_else_10 = nop_8;

	// if (! (((st32) P0_new) & 0x1)) {seq(Rd = 0x0)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_11 = BRANCH(op_INV_4, seq_then_9, seq_else_10);

	RzILOpEffect *instruction_sequence = branch_11;
	return instruction_sequence;
}

// if (p0) Rd = #0
RzILOpEffect *hex_il_op_sa1_clrt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	RzILOpPure *P0 = READ_REG(pkt, &P0_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = 0x0;
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, SN(32, 0));

	// nop;
	RzILOpEffect *nop_7 = NOP();

	// seq(Rd = 0x0);
	RzILOpEffect *seq_then_8 = op_ASSIGN_6;

	// seq(nop);
	RzILOpEffect *seq_else_9 = nop_7;

	// if ((((st32) P0) & 0x1)) {seq(Rd = 0x0)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0), DUP(P0)), SN(32, 1));
	RzILOpEffect *branch_10 = BRANCH(NON_ZERO(op_AND_3), seq_then_8, seq_else_9);

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (p0.new) Rd = #0
RzILOpEffect *hex_il_op_sa1_clrtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = 0x0;
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, SN(32, 0));

	// nop;
	RzILOpEffect *nop_7 = NOP();

	// seq(Rd = 0x0);
	RzILOpEffect *seq_then_8 = op_ASSIGN_6;

	// seq(nop);
	RzILOpEffect *seq_else_9 = nop_7;

	// if ((((st32) P0_new) & 0x1)) {seq(Rd = 0x0)} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_10 = BRANCH(NON_ZERO(op_AND_3), seq_then_8, seq_else_9);

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Ii)
RzILOpEffect *hex_il_op_sa1_cmpeqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// P0 = ((st8) ((((ut32) Rs) == u) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// Rdd = combine(#0,Ii)
RzILOpEffect *hex_il_op_sa1_combine0i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_8 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) u) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("u")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_AND_12, SN(32, 0));
	RzILOpPure *op_OR_17 = LOGOR(op_AND_7, op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, op_OR_17);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) 0x0) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_25 = LOGNOT(op_LSHIFT_24);
	RzILOpPure *op_AND_26 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_25);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(op_AND_30, SN(32, 0x20));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_26, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, op_OR_35);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_8, op_ASSIGN_18, op_ASSIGN_36);
	return instruction_sequence;
}

// Rdd = combine(#1,Ii)
RzILOpEffect *hex_il_op_sa1_combine1i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_8 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) u) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("u")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_AND_12, SN(32, 0));
	RzILOpPure *op_OR_17 = LOGOR(op_AND_7, op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, op_OR_17);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) 0x1) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_25 = LOGNOT(op_LSHIFT_24);
	RzILOpPure *op_AND_26 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_25);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(SN(32, 1)), SN(32, 1)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(op_AND_30, SN(32, 0x20));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_26, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, op_OR_35);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_8, op_ASSIGN_18, op_ASSIGN_36);
	return instruction_sequence;
}

// Rdd = combine(#2,Ii)
RzILOpEffect *hex_il_op_sa1_combine2i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_8 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) u) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("u")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_AND_12, SN(32, 0));
	RzILOpPure *op_OR_17 = LOGOR(op_AND_7, op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, op_OR_17);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) 0x2) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_25 = LOGNOT(op_LSHIFT_24);
	RzILOpPure *op_AND_26 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_25);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(SN(32, 2)), SN(32, 2)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(op_AND_30, SN(32, 0x20));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_26, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, op_OR_35);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_8, op_ASSIGN_18, op_ASSIGN_36);
	return instruction_sequence;
}

// Rdd = combine(#3,Ii)
RzILOpEffect *hex_il_op_sa1_combine3i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_8 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) u) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("u")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_AND_12, SN(32, 0));
	RzILOpPure *op_OR_17 = LOGOR(op_AND_7, op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, op_OR_17);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) 0x3) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_25 = LOGNOT(op_LSHIFT_24);
	RzILOpPure *op_AND_26 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_25);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(SN(32, 3)), SN(32, 3)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(op_AND_30, SN(32, 0x20));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_26, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, op_OR_35);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_8, op_ASSIGN_18, op_ASSIGN_36);
	return instruction_sequence;
}

// Rdd = combine(Rs,#0)
RzILOpEffect *hex_il_op_sa1_combinerz(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) 0x0) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_11 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xffffffff));
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

// Rdd = combine(#0,Rs)
RzILOpEffect *hex_il_op_sa1_combinezr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rs) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_AND_11 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(op_AND_11, SN(32, 0));
	RzILOpPure *op_OR_16 = LOGOR(op_AND_7, op_LSHIFT_15);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rdd_op, op_OR_16);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) 0x0) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_24 = LOGNOT(op_LSHIFT_23);
	RzILOpPure *op_AND_25 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_24);
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, MSB(SN(32, 0)), SN(32, 0)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(op_AND_29, SN(32, 0x20));
	RzILOpPure *op_OR_34 = LOGOR(op_AND_25, op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_35 = WRITE_REG(bundle, Rdd_op, op_OR_34);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_17, op_ASSIGN_35);
	return instruction_sequence;
}

// Rd = add(Rs,n1)
RzILOpEffect *hex_il_op_sa1_dec(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rs - 0x1;
	RzILOpPure *op_SUB_3 = SUB(Rs, SN(32, 1));
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_SUB_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = add(Rs,#1)
RzILOpEffect *hex_il_op_sa1_inc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = Rs + 0x1;
	RzILOpPure *op_ADD_3 = ADD(Rs, SN(32, 1));
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, op_ADD_3);

	RzILOpEffect *instruction_sequence = op_ASSIGN_4;
	return instruction_sequence;
}

// Rd = Ii
RzILOpEffect *hex_il_op_sa1_seti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Rd = ((st32) u);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("u")));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_4);
	return instruction_sequence;
}

// Rd = n1
RzILOpEffect *hex_il_op_sa1_setin1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = -0x1;
	RzILOpEffect *op_ASSIGN_3 = WRITE_REG(bundle, Rd_op, SN(32, -1));

	RzILOpEffect *instruction_sequence = op_ASSIGN_3;
	return instruction_sequence;
}

// Rd = sxtb(Rs)
RzILOpEffect *hex_il_op_sa1_sxtb(HexInsnPktBundle *bundle) {
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
RzILOpEffect *hex_il_op_sa1_sxth(HexInsnPktBundle *bundle) {
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

// Rd = Rs
RzILOpEffect *hex_il_op_sa1_tfr(HexInsnPktBundle *bundle) {
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

// Rd = and(Rs,#255)
RzILOpEffect *hex_il_op_sa1_zxtb(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Rd = zxth(Rs)
RzILOpEffect *hex_il_op_sa1_zxth(HexInsnPktBundle *bundle) {
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