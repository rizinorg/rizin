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

// Rd = add(pc,Ii)
RzILOpEffect *hex_il_op_c4_addipc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Rd = ((st32) pc + u);
	RzILOpPure *op_ADD_4 = ADD(pc, VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_4));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Pd = and(Ps,and(Pt,Pu))
RzILOpEffect *hex_il_op_c4_and_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) ((((st32) Ps) & ((st32) Pt)) & ((st32) Pu)));
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpPure *op_AND_8 = LOGAND(op_AND_5, CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_AND_8), DUP(op_AND_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = and(Ps,and(Pt,!Pu))
RzILOpEffect *hex_il_op_c4_and_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) ((((st32) Ps) & ((st32) Pt)) & (~((st32) Pu))));
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpPure *op_NOT_8 = LOGNOT(CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpPure *op_AND_9 = LOGAND(op_AND_5, op_NOT_8);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_AND_9), DUP(op_AND_9)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Pd = and(Ps,or(Pt,Pu))
RzILOpEffect *hex_il_op_c4_and_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) (((st32) Ps) & (((st32) Pt) | ((st32) Pu))));
	RzILOpPure *op_OR_6 = LOGOR(CAST(32, MSB(Pt), DUP(Pt)), CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Ps), DUP(Ps)), op_OR_6);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_AND_8), DUP(op_AND_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = and(Ps,or(Pt,!Pu))
RzILOpEffect *hex_il_op_c4_and_orn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) (((st32) Ps) & (((st32) Pt) | (~((st32) Pu)))));
	RzILOpPure *op_NOT_5 = LOGNOT(CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpPure *op_OR_7 = LOGOR(CAST(32, MSB(Pt), DUP(Pt)), op_NOT_5);
	RzILOpPure *op_AND_9 = LOGAND(CAST(32, MSB(Ps), DUP(Ps)), op_OR_7);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_AND_9), DUP(op_AND_9)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Pd = !cmp.gt(Rs,Rt)
RzILOpEffect *hex_il_op_c4_cmplte(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((Rs <= Rt) ? 0xff : 0x0));
	RzILOpPure *op_LE_3 = SLE(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_LE_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = !cmp.gt(Rs,Ii)
RzILOpEffect *hex_il_op_c4_cmpltei(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Pd = ((st8) ((Rs <= s) ? 0xff : 0x0));
	RzILOpPure *op_LE_4 = SLE(Rs, VARL("s"));
	RzILOpPure *cond_7 = ITE(op_LE_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Pd = !cmp.gtu(Rs,Rt)
RzILOpEffect *hex_il_op_c4_cmplteu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((ut32) Rs) <= ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_LE_5 = ULE(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_LE_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = !cmp.gtu(Rs,Ii)
RzILOpEffect *hex_il_op_c4_cmplteui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Pd = ((st8) ((((ut32) Rs) <= u) ? 0xff : 0x0));
	RzILOpPure *op_LE_5 = ULE(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *cond_8 = ITE(op_LE_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_10);
	return instruction_sequence;
}

// Pd = !cmp.eq(Rs,Rt)
RzILOpEffect *hex_il_op_c4_cmpneq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((Rs != Rt) ? 0xff : 0x0));
	RzILOpPure *op_NE_3 = INV(EQ(Rs, Rt));
	RzILOpPure *cond_6 = ITE(op_NE_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Pd = !cmp.eq(Rs,Ii)
RzILOpEffect *hex_il_op_c4_cmpneqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Pd = ((st8) ((Rs != s) ? 0xff : 0x0));
	RzILOpPure *op_NE_4 = INV(EQ(Rs, VARL("s")));
	RzILOpPure *cond_7 = ITE(op_NE_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Pd = fastcorner9(Ps,Pt)
RzILOpEffect *hex_il_op_c4_fastcorner9(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 tmp;
	// Declare: ut32 i;
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);

	// tmp = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_2 = SETL("tmp", CAST(32, IL_FALSE, SN(32, 0)));

	// tmp = ((ut32) (((ut64) (((st64) tmp) & (~(0xffff << 0x0)))) | (((ut64) ((((st32) (Ps << 0x8)) | ((st32) Pt)) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_9 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_10 = LOGNOT(op_LSHIFT_9);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("tmp")), op_NOT_10);
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(Ps, SN(32, 8));
	RzILOpPure *op_OR_19 = LOGOR(CAST(32, MSB(op_LSHIFT_15), DUP(op_LSHIFT_15)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpPure *op_AND_21 = LOGAND(op_OR_19, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, op_AND_21), SN(32, 0));
	RzILOpPure *op_OR_28 = LOGOR(CAST(64, IL_FALSE, op_AND_12), op_LSHIFT_26);
	RzILOpEffect *op_ASSIGN_30 = SETL("tmp", CAST(32, IL_FALSE, op_OR_28));

	// tmp = ((ut32) (((ut64) (((st64) tmp) & (~(0xffff << 0x10)))) | (((ut64) ((((st32) (Ps << 0x8)) | ((st32) Pt)) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_37 = LOGNOT(op_LSHIFT_36);
	RzILOpPure *op_AND_39 = LOGAND(CAST(64, IL_FALSE, VARL("tmp")), op_NOT_37);
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(DUP(Ps), SN(32, 8));
	RzILOpPure *op_OR_44 = LOGOR(CAST(32, MSB(op_LSHIFT_41), DUP(op_LSHIFT_41)), CAST(32, MSB(DUP(Pt)), DUP(Pt)));
	RzILOpPure *op_AND_46 = LOGAND(op_OR_44, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(CAST(64, IL_FALSE, op_AND_46), SN(32, 16));
	RzILOpPure *op_OR_53 = LOGOR(CAST(64, IL_FALSE, op_AND_39), op_LSHIFT_51);
	RzILOpEffect *op_ASSIGN_55 = SETL("tmp", CAST(32, IL_FALSE, op_OR_53));

	// i = ((ut32) 0x1);
	RzILOpEffect *op_ASSIGN_59 = SETL("i", CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(++i);
	RzILOpEffect *op_INC_63 = SETL("i", INC(VARL("i"), 32));

	// h_tmp155 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_65 = SETL("h_tmp155", VARL("i"));

	// seq(h_tmp155 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_66 = SEQN(2, op_ASSIGN_hybrid_tmp_65, op_INC_63);

	// tmp = (tmp & (tmp >> 0x1));
	RzILOpPure *op_RSHIFT_68 = SHIFTR0(VARL("tmp"), SN(32, 1));
	RzILOpPure *op_AND_69 = LOGAND(VARL("tmp"), op_RSHIFT_68);
	RzILOpEffect *op_ASSIGN_AND_70 = SETL("tmp", op_AND_69);

	// seq(h_tmp155; tmp = (tmp & (tmp >> 0x1)));
	RzILOpEffect *seq_71 = op_ASSIGN_AND_70;

	// seq(seq(h_tmp155; tmp = (tmp & (tmp >> 0x1))); seq(h_tmp155 = HY ...;
	RzILOpEffect *seq_72 = SEQN(2, seq_71, seq_66);

	// while ((i < ((ut32) 0x9))) { seq(seq(h_tmp155; tmp = (tmp & (tmp >> 0x1))); seq(h_tmp155 = HY ... };
	RzILOpPure *op_LT_62 = ULT(VARL("i"), CAST(32, IL_FALSE, SN(32, 9)));
	RzILOpEffect *for_73 = REPEAT(op_LT_62, seq_72);

	// seq(i = ((ut32) 0x1); while ((i < ((ut32) 0x9))) { seq(seq(h_tmp ...;
	RzILOpEffect *seq_74 = SEQN(2, op_ASSIGN_59, for_73);

	// Pd = ((st8) ((tmp != ((ut32) 0x0)) ? 0xff : 0x0));
	RzILOpPure *op_NE_78 = INV(EQ(VARL("tmp"), CAST(32, IL_FALSE, SN(32, 0))));
	RzILOpPure *cond_81 = ITE(op_NE_78, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_83 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_81), DUP(cond_81)));

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_2, op_ASSIGN_30, op_ASSIGN_55, seq_74, op_ASSIGN_83);
	return instruction_sequence;
}

// Pd = !fastcorner9(Ps,Pt)
RzILOpEffect *hex_il_op_c4_fastcorner9_not(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 tmp;
	// Declare: ut32 i;
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);

	// tmp = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_2 = SETL("tmp", CAST(32, IL_FALSE, SN(32, 0)));

	// tmp = ((ut32) (((ut64) (((st64) tmp) & (~(0xffff << 0x0)))) | (((ut64) ((((st32) (Ps << 0x8)) | ((st32) Pt)) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_9 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_10 = LOGNOT(op_LSHIFT_9);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("tmp")), op_NOT_10);
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(Ps, SN(32, 8));
	RzILOpPure *op_OR_19 = LOGOR(CAST(32, MSB(op_LSHIFT_15), DUP(op_LSHIFT_15)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpPure *op_AND_21 = LOGAND(op_OR_19, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(CAST(64, IL_FALSE, op_AND_21), SN(32, 0));
	RzILOpPure *op_OR_28 = LOGOR(CAST(64, IL_FALSE, op_AND_12), op_LSHIFT_26);
	RzILOpEffect *op_ASSIGN_30 = SETL("tmp", CAST(32, IL_FALSE, op_OR_28));

	// tmp = ((ut32) (((ut64) (((st64) tmp) & (~(0xffff << 0x10)))) | (((ut64) ((((st32) (Ps << 0x8)) | ((st32) Pt)) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_36 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_37 = LOGNOT(op_LSHIFT_36);
	RzILOpPure *op_AND_39 = LOGAND(CAST(64, IL_FALSE, VARL("tmp")), op_NOT_37);
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(DUP(Ps), SN(32, 8));
	RzILOpPure *op_OR_44 = LOGOR(CAST(32, MSB(op_LSHIFT_41), DUP(op_LSHIFT_41)), CAST(32, MSB(DUP(Pt)), DUP(Pt)));
	RzILOpPure *op_AND_46 = LOGAND(op_OR_44, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(CAST(64, IL_FALSE, op_AND_46), SN(32, 16));
	RzILOpPure *op_OR_53 = LOGOR(CAST(64, IL_FALSE, op_AND_39), op_LSHIFT_51);
	RzILOpEffect *op_ASSIGN_55 = SETL("tmp", CAST(32, IL_FALSE, op_OR_53));

	// i = ((ut32) 0x1);
	RzILOpEffect *op_ASSIGN_59 = SETL("i", CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(++i);
	RzILOpEffect *op_INC_63 = SETL("i", INC(VARL("i"), 32));

	// h_tmp156 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_65 = SETL("h_tmp156", VARL("i"));

	// seq(h_tmp156 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_66 = SEQN(2, op_ASSIGN_hybrid_tmp_65, op_INC_63);

	// tmp = (tmp & (tmp >> 0x1));
	RzILOpPure *op_RSHIFT_68 = SHIFTR0(VARL("tmp"), SN(32, 1));
	RzILOpPure *op_AND_69 = LOGAND(VARL("tmp"), op_RSHIFT_68);
	RzILOpEffect *op_ASSIGN_AND_70 = SETL("tmp", op_AND_69);

	// seq(h_tmp156; tmp = (tmp & (tmp >> 0x1)));
	RzILOpEffect *seq_71 = op_ASSIGN_AND_70;

	// seq(seq(h_tmp156; tmp = (tmp & (tmp >> 0x1))); seq(h_tmp156 = HY ...;
	RzILOpEffect *seq_72 = SEQN(2, seq_71, seq_66);

	// while ((i < ((ut32) 0x9))) { seq(seq(h_tmp156; tmp = (tmp & (tmp >> 0x1))); seq(h_tmp156 = HY ... };
	RzILOpPure *op_LT_62 = ULT(VARL("i"), CAST(32, IL_FALSE, SN(32, 9)));
	RzILOpEffect *for_73 = REPEAT(op_LT_62, seq_72);

	// seq(i = ((ut32) 0x1); while ((i < ((ut32) 0x9))) { seq(seq(h_tmp ...;
	RzILOpEffect *seq_74 = SEQN(2, op_ASSIGN_59, for_73);

	// Pd = ((st8) ((tmp == ((ut32) 0x0)) ? 0xff : 0x0));
	RzILOpPure *op_EQ_78 = EQ(VARL("tmp"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *cond_81 = ITE(op_EQ_78, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_83 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_81), DUP(cond_81)));

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_2, op_ASSIGN_30, op_ASSIGN_55, seq_74, op_ASSIGN_83);
	return instruction_sequence;
}

// Pd = !bitsclr(Rs,Rt)
RzILOpEffect *hex_il_op_c4_nbitsclr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) (((Rs & Rt) != 0x0) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_NE_5 = INV(EQ(op_AND_3, SN(32, 0)));
	RzILOpPure *cond_8 = ITE(op_NE_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = !bitsclr(Rs,Ii)
RzILOpEffect *hex_il_op_c4_nbitsclri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// Pd = ((st8) (((((ut32) Rs) & u) != ((ut32) 0x0)) ? 0xff : 0x0));
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_NE_8 = INV(EQ(op_AND_5, CAST(32, IL_FALSE, SN(32, 0))));
	RzILOpPure *cond_11 = ITE(op_NE_8, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_11), DUP(cond_11)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_13);
	return instruction_sequence;
}

// Pd = !bitsset(Rs,Rt)
RzILOpEffect *hex_il_op_c4_nbitsset(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) (((Rs & Rt) != Rt) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_NE_4 = INV(EQ(op_AND_3, DUP(Rt)));
	RzILOpPure *cond_7 = ITE(op_NE_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// Pd = or(Ps,and(Pt,Pu))
RzILOpEffect *hex_il_op_c4_or_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) (((st32) Ps) | (((st32) Pt) & ((st32) Pu))));
	RzILOpPure *op_AND_6 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpPure *op_OR_8 = LOGOR(CAST(32, MSB(Ps), DUP(Ps)), op_AND_6);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_OR_8), DUP(op_OR_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = or(Ps,and(Pt,!Pu))
RzILOpEffect *hex_il_op_c4_or_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) (((st32) Ps) | (((st32) Pt) & (~((st32) Pu)))));
	RzILOpPure *op_NOT_5 = LOGNOT(CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpPure *op_AND_7 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), op_NOT_5);
	RzILOpPure *op_OR_9 = LOGOR(CAST(32, MSB(Ps), DUP(Ps)), op_AND_7);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_OR_9), DUP(op_OR_9)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

// Pd = or(Ps,or(Pt,Pu))
RzILOpEffect *hex_il_op_c4_or_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) ((((st32) Ps) | ((st32) Pt)) | ((st32) Pu)));
	RzILOpPure *op_OR_5 = LOGOR(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpPure *op_OR_8 = LOGOR(op_OR_5, CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_OR_8), DUP(op_OR_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = or(Ps,or(Pt,!Pu))
RzILOpEffect *hex_il_op_c4_or_orn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ps_op = ISA2REG(hi, 's', false);
	RzILOpPure *Ps = READ_REG(pkt, Ps_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);

	// Pd = ((st8) ((((st32) Ps) | ((st32) Pt)) | (~((st32) Pu))));
	RzILOpPure *op_OR_5 = LOGOR(CAST(32, MSB(Ps), DUP(Ps)), CAST(32, MSB(Pt), DUP(Pt)));
	RzILOpPure *op_NOT_8 = LOGNOT(CAST(32, MSB(Pu), DUP(Pu)));
	RzILOpPure *op_OR_9 = LOGOR(op_OR_5, op_NOT_8);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_OR_9), DUP(op_OR_9)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_11;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>