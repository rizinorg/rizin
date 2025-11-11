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

// Pd = all8(Ps)
RzILOpEffect *hex_il_op_c2_all8(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);

	// Pd = ((st8) ((((st32) Ps) == 0xff) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(CAST(32, MSB(Ps), DUP(Ps)), SN(32, 0xff));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// Pd = and(Pt,Ps)
RzILOpEffect *hex_il_op_c2_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);

	// Pd = ((st8) (((st32) Ps) & ((st32) Pt)));
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_AND_5), DUP(op_AND_5)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Pd = and(Pt,!Ps)
RzILOpEffect *hex_il_op_c2_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);

	// Pd = ((st8) (((st32) Pt) & (~((st32) Ps))));
	RzILOpPure *op_NOT_4 = LOGNOT(CAST(32, MSB(Ps), DUP(Ps)));
	RzILOpPure *op_AND_6 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), op_NOT_4);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_AND_6), DUP(op_AND_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = any8(Ps)
RzILOpEffect *hex_il_op_c2_any8(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);

	// Pd = ((st8) (Ps ? 0xff : 0x0));
	RzILOpPure *cond_4 = ITE(NON_ZERO(Ps), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_4), DUP(cond_4)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_6;
	return instruction_sequence;
}

// Pd = bitsclr(Rs,Rt)
RzILOpEffect *hex_il_op_c2_bitsclr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) (((Rs & Rt) == 0x0) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_EQ_5 = EQ(op_AND_3, SN(32, 0));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = bitsclr(Rs,Ii)
RzILOpEffect *hex_il_op_c2_bitsclri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Pd = ((st8) (((((ut32) Rs) & u) == ((ut32) 0x0)) ? 0xff : 0x0));
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_EQ_8 = EQ(op_AND_5, CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *cond_11 = ITE(op_EQ_8, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_11), DUP(cond_11)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_13);
	return instruction_sequence;
}

// Pd = bitsset(Rs,Rt)
RzILOpEffect *hex_il_op_c2_bitsset(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) (((Rs & Rt) == Rt) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_EQ_4 = EQ(op_AND_3, DUP(Rt));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// if (!Pu) Rdd = combine(Rs,Rt)
RzILOpEffect *hex_il_op_c2_ccombinewf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_11 = LOGNOT(op_LSHIFT_10);
	RzILOpPure *op_AND_12 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_11);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(Rt), DUP(Rt)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(op_AND_16, SN(32, 0));
	RzILOpPure *op_OR_21 = LOGOR(op_AND_12, op_LSHIFT_20);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rdd_op, op_OR_21);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) Rs) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_29 = LOGNOT(op_LSHIFT_28);
	RzILOpPure *op_AND_30 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_29);
	RzILOpPure *op_AND_34 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(op_AND_34, SN(32, 0x20));
	RzILOpPure *op_OR_39 = LOGOR(op_AND_30, op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_40 = WRITE_REG(bundle, Rdd_op, op_OR_39);

	// nop;
	RzILOpEffect *nop_42 = NOP();

	// seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...;
	RzILOpEffect *seq_then_43 = SEQN(2, op_ASSIGN_22, op_ASSIGN_40);

	// seq(nop);
	RzILOpEffect *seq_else_44 = nop_42;

	// if (! (((st32) Pu) & 0x1)) {seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_45 = BRANCH(op_INV_4, seq_then_43, seq_else_44);

	RzILOpEffect *instruction_sequence = branch_45;
	return instruction_sequence;
}

// if (!Pu.new) Rdd = combine(Rs,Rt)
RzILOpEffect *hex_il_op_c2_ccombinewnewf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_11 = LOGNOT(op_LSHIFT_10);
	RzILOpPure *op_AND_12 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_11);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(Rt), DUP(Rt)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(op_AND_16, SN(32, 0));
	RzILOpPure *op_OR_21 = LOGOR(op_AND_12, op_LSHIFT_20);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rdd_op, op_OR_21);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) Rs) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_29 = LOGNOT(op_LSHIFT_28);
	RzILOpPure *op_AND_30 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_29);
	RzILOpPure *op_AND_34 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(op_AND_34, SN(32, 0x20));
	RzILOpPure *op_OR_39 = LOGOR(op_AND_30, op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_40 = WRITE_REG(bundle, Rdd_op, op_OR_39);

	// nop;
	RzILOpEffect *nop_42 = NOP();

	// seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...;
	RzILOpEffect *seq_then_43 = SEQN(2, op_ASSIGN_22, op_ASSIGN_40);

	// seq(nop);
	RzILOpEffect *seq_else_44 = nop_42;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_45 = BRANCH(op_INV_4, seq_then_43, seq_else_44);

	RzILOpEffect *instruction_sequence = branch_45;
	return instruction_sequence;
}

// if (Pu.new) Rdd = combine(Rs,Rt)
RzILOpEffect *hex_il_op_c2_ccombinewnewt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_9 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_10 = LOGNOT(op_LSHIFT_9);
	RzILOpPure *op_AND_11 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_10);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, MSB(Rt), DUP(Rt)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(op_AND_15, SN(32, 0));
	RzILOpPure *op_OR_20 = LOGOR(op_AND_11, op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rdd_op, op_OR_20);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) Rs) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_29 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_28);
	RzILOpPure *op_AND_33 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(op_AND_33, SN(32, 0x20));
	RzILOpPure *op_OR_38 = LOGOR(op_AND_29, op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rdd_op, op_OR_38);

	// nop;
	RzILOpEffect *nop_41 = NOP();

	// seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...;
	RzILOpEffect *seq_then_42 = SEQN(2, op_ASSIGN_21, op_ASSIGN_39);

	// seq(nop);
	RzILOpEffect *seq_else_43 = nop_41;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_44 = BRANCH(NON_ZERO(op_AND_3), seq_then_42, seq_else_43);

	RzILOpEffect *instruction_sequence = branch_44;
	return instruction_sequence;
}

// if (Pu) Rdd = combine(Rs,Rt)
RzILOpEffect *hex_il_op_c2_ccombinewt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_9 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_10 = LOGNOT(op_LSHIFT_9);
	RzILOpPure *op_AND_11 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_10);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, MSB(Rt), DUP(Rt)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(op_AND_15, SN(32, 0));
	RzILOpPure *op_OR_20 = LOGOR(op_AND_11, op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rdd_op, op_OR_20);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) Rs) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_29 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_28);
	RzILOpPure *op_AND_33 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(op_AND_33, SN(32, 0x20));
	RzILOpPure *op_OR_38 = LOGOR(op_AND_29, op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rdd_op, op_OR_38);

	// nop;
	RzILOpEffect *nop_41 = NOP();

	// seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...;
	RzILOpEffect *seq_then_42 = SEQN(2, op_ASSIGN_21, op_ASSIGN_39);

	// seq(nop);
	RzILOpEffect *seq_else_43 = nop_41;

	// if ((((st32) Pu) & 0x1)) {seq(Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rt) & 0xff ...} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_44 = BRANCH(NON_ZERO(op_AND_3), seq_then_42, seq_else_43);

	RzILOpEffect *instruction_sequence = branch_44;
	return instruction_sequence;
}

// if (!Pu) Rd = Ii
RzILOpEffect *hex_il_op_c2_cmoveif(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = s;
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, VARL("s"));

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = s);
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = s)} else {seq(nop)};
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_6 = INV(NON_ZERO(op_AND_5));
	RzILOpEffect *branch_12 = BRANCH(op_INV_6, seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, branch_12);
	return instruction_sequence;
}

// if (Pu) Rd = Ii
RzILOpEffect *hex_il_op_c2_cmoveit(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = s;
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, VARL("s"));

	// nop;
	RzILOpEffect *nop_8 = NOP();

	// seq(Rd = s);
	RzILOpEffect *seq_then_9 = op_ASSIGN_7;

	// seq(nop);
	RzILOpEffect *seq_else_10 = nop_8;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = s)} else {seq(nop)};
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_11 = BRANCH(NON_ZERO(op_AND_5), seq_then_9, seq_else_10);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, branch_11);
	return instruction_sequence;
}

// if (!Pu.new) Rd = Ii
RzILOpEffect *hex_il_op_c2_cmovenewif(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = s;
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, VARL("s"));

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = s);
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = s)} else {seq(nop)};
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_6 = INV(NON_ZERO(op_AND_5));
	RzILOpEffect *branch_12 = BRANCH(op_INV_6, seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, branch_12);
	return instruction_sequence;
}

// if (Pu.new) Rd = Ii
RzILOpEffect *hex_il_op_c2_cmovenewit(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = s;
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, VARL("s"));

	// nop;
	RzILOpEffect *nop_8 = NOP();

	// seq(Rd = s);
	RzILOpEffect *seq_then_9 = op_ASSIGN_7;

	// seq(nop);
	RzILOpEffect *seq_else_10 = nop_8;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = s)} else {seq(nop)};
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_11 = BRANCH(NON_ZERO(op_AND_5), seq_then_9, seq_else_10);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, branch_11);
	return instruction_sequence;
}

// Pd = cmp.eq(Rs,Rt)
RzILOpEffect *hex_il_op_c2_cmpeq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = cmp.eq(Rs,Ii)
RzILOpEffect *hex_il_op_c2_cmpeqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Pd = ((st8) ((Rs == s) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, VARL("s"));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Pd = cmp.eq(Rss,Rtt)
RzILOpEffect *hex_il_op_c2_cmpeqp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) ((Rss == Rtt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rss, Rtt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = cmp.gt(Rs,Rt)
RzILOpEffect *hex_il_op_c2_cmpgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = cmp.gt(Rs,Ii)
RzILOpEffect *hex_il_op_c2_cmpgti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Pd = ((st8) ((Rs > s) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, VARL("s"));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Pd = cmp.gt(Rss,Rtt)
RzILOpEffect *hex_il_op_c2_cmpgtp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) ((Rss > Rtt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rss, Rtt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = cmp.gtu(Rs,Rt)
RzILOpEffect *hex_il_op_c2_cmpgtu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = cmp.gtu(Rs,Ii)
RzILOpEffect *hex_il_op_c2_cmpgtui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Pd = ((st8) ((((ut32) Rs) > u) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_10);
	return instruction_sequence;
}

// Pd = cmp.gtu(Rss,Rtt)
RzILOpEffect *hex_il_op_c2_cmpgtup(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) ((((ut64) Rss) > ((ut64) Rtt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(64, IL_FALSE, Rss), CAST(64, IL_FALSE, Rtt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rdd = mask(Pt)
RzILOpEffect *hex_il_op_c2_mask(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp153 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp153", VARL("i"));

	// seq(h_tmp153 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((((st32) (Pt >> i)) & 0x1) ? 0xff : 0x0)) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Pt, VARL("i"));
	RzILOpPure *op_AND_20 = LOGAND(CAST(32, MSB(op_RSHIFT_17), DUP(op_RSHIFT_17)), SN(32, 1));
	RzILOpPure *cond_23 = ITE(NON_ZERO(op_AND_20), SN(32, 0xff), SN(32, 0));
	RzILOpPure *op_AND_26 = LOGAND(CAST(64, MSB(cond_23), DUP(cond_23)), SN(64, 0xff));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(CAST(64, IL_FALSE, op_AND_26), op_MUL_29);
	RzILOpPure *op_OR_32 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_34 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_32));

	// seq(h_tmp153; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_36 = op_ASSIGN_34;

	// seq(seq(h_tmp153; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_37 = SEQN(2, seq_36, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp153; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_38 = REPEAT(op_LT_4, seq_37);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp153; Rdd = ((st64) ...;
	RzILOpEffect *seq_39 = SEQN(2, op_ASSIGN_2, for_38);

	RzILOpEffect *instruction_sequence = seq_39;
	return instruction_sequence;
}

// Rd = mux(Pu,Rs,Rt)
RzILOpEffect *hex_il_op_c2_mux(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((((st32) Pu) & 0x1) ? Rs : Rt);
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *cond_7 = ITE(NON_ZERO(op_AND_4), Rs, Rt);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, cond_7);

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rd = mux(Pu,Ii,II)
RzILOpEffect *hex_il_op_c2_muxii(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// S = S;
	RzILOpEffect *imm_assign_7 = SETL("S", S);

	// Rd = ((((st32) Pu) & 0x1) ? s : S);
	RzILOpPure *op_AND_6 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *cond_9 = ITE(NON_ZERO(op_AND_6), VARL("s"), VARL("S"));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, cond_9);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, imm_assign_7, op_ASSIGN_10);
	return instruction_sequence;
}

// Rd = mux(Pu,Rs,Ii)
RzILOpEffect *hex_il_op_c2_muxir(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = ((((st32) Pu) & 0x1) ? Rs : s);
	RzILOpPure *op_AND_6 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *cond_8 = ITE(NON_ZERO(op_AND_6), Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, cond_8);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Rd = mux(Pu,Ii,Rs)
RzILOpEffect *hex_il_op_c2_muxri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = ((((st32) Pu) & 0x1) ? s : Rs);
	RzILOpPure *op_AND_6 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *cond_8 = ITE(NON_ZERO(op_AND_6), VARL("s"), Rs);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, cond_8);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Pd = not(Ps)
RzILOpEffect *hex_il_op_c2_not(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);

	// Pd = ((st8) (~((st32) Ps)));
	RzILOpPure *op_NOT_3 = LOGNOT(CAST(32, MSB(Ps), DUP(Ps)));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_NOT_3), DUP(op_NOT_3)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Pd = or(Pt,Ps)
RzILOpEffect *hex_il_op_c2_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);

	// Pd = ((st8) (((st32) Ps) | ((st32) Pt)));
	RzILOpPure *op_OR_5 = LOGOR(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_OR_5), DUP(op_OR_5)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Pd = or(Pt,!Ps)
RzILOpEffect *hex_il_op_c2_orn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);

	// Pd = ((st8) (((st32) Pt) | (~((st32) Ps))));
	RzILOpPure *op_NOT_4 = LOGNOT(CAST(32, MSB(Ps), DUP(Ps)));
	RzILOpPure *op_OR_6 = LOGOR(CAST(32, MSB(Pt), DUP(Pt)), op_NOT_4);
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_OR_6), DUP(op_OR_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rd = Ps
RzILOpEffect *hex_il_op_c2_tfrpr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);

	// Rd = ((st32) extract64(((ut64) Ps), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Ps), SN(32, 0), SN(32, 8))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Pd = Rs
RzILOpEffect *hex_il_op_c2_tfrrp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Pd = ((st8) ((ut8) ((Rs >> 0x0) & 0xff)));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xff));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, CAST(8, IL_FALSE, op_AND_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rd = vitpack(Ps,Pt)
RzILOpEffect *hex_il_op_c2_vitpack(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);

	// Rd = ((((st32) Ps) & 0x55) | (((st32) Pt) & 0xaa));
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Ps), DUP(Ps)), SN(32, 0x55));
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 0xaa));
	RzILOpPure *op_OR_9 = LOGOR(op_AND_4, op_AND_8);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, op_OR_9);

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rdd = vmux(Pu,Rss,Rtt)
RzILOpEffect *hex_il_op_c2_vmux(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp154 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp154", VARL("i"));

	// seq(h_tmp154 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((((st32) (Pu >> i)) & 0x1) ? ((st8) ((Rss >> i * 0x8) & ((st64) 0xff))) : ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Pu, VARL("i"));
	RzILOpPure *op_AND_20 = LOGAND(CAST(32, MSB(op_RSHIFT_17), DUP(op_RSHIFT_17)), SN(32, 1));
	RzILOpPure *op_MUL_23 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rss, op_MUL_23);
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_32 = SHIFTRA(Rtt, op_MUL_31);
	RzILOpPure *op_AND_35 = LOGAND(op_RSHIFT_32, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *cond_37 = ITE(NON_ZERO(op_AND_20), CAST(8, MSB(op_AND_27), DUP(op_AND_27)), CAST(8, MSB(op_AND_35), DUP(op_AND_35)));
	RzILOpPure *op_AND_41 = LOGAND(CAST(64, MSB(CAST(32, MSB(cond_37), DUP(cond_37))), CAST(32, MSB(DUP(cond_37)), DUP(cond_37))), SN(64, 0xff));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, op_AND_41), op_MUL_44);
	RzILOpPure *op_OR_47 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_45);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_47));

	// seq(h_tmp154; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_51 = op_ASSIGN_49;

	// seq(seq(h_tmp154; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_51, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp154; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_53 = REPEAT(op_LT_4, seq_52);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp154; Rdd = ((st64) ...;
	RzILOpEffect *seq_54 = SEQN(2, op_ASSIGN_2, for_53);

	RzILOpEffect *instruction_sequence = seq_54;
	return instruction_sequence;
}

// Pd = xor(Ps,Pt)
RzILOpEffect *hex_il_op_c2_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);

	// Pd = ((st8) (((st32) Ps) ^ ((st32) Pt)));
	RzILOpPure *op_XOR_5 = LOGXOR(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_XOR_5), DUP(op_XOR_5)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>