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

// if (!cmp.eq(Ns.new,Rt)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new != Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_3 = INV(EQ(Ns_new, Rt));
	RzILOpEffect *branch_18 = BRANCH(op_NE_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.eq(Ns.new,Rt)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new != Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_3 = INV(EQ(Ns_new, Rt));
	RzILOpEffect *branch_18 = BRANCH(op_NE_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.eq(Ns.new,Rt)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new == Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_3 = EQ(Ns_new, Rt);
	RzILOpEffect *branch_18 = BRANCH(op_EQ_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (cmp.eq(Ns.new,Rt)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new == Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_3 = EQ(Ns_new, Rt);
	RzILOpEffect *branch_18 = BRANCH(op_EQ_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,Rt); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs == Rt) ? 0xff : 0x0));
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_EQ_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,Rt); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeq_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.eq(Ns.new,II)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) != U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_5 = INV(EQ(CAST(32, IL_FALSE, Ns_new), VARL("U")));
	RzILOpEffect *branch_20 = BRANCH(op_NE_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (!cmp.eq(Ns.new,II)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) != U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_5 = INV(EQ(CAST(32, IL_FALSE, Ns_new), VARL("U")));
	RzILOpEffect *branch_20 = BRANCH(op_NE_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.eq(Ns.new,II)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) == U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpEffect *branch_20 = BRANCH(op_EQ_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (cmp.eq(Ns.new,II)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) == U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpEffect *branch_20 = BRANCH(op_EQ_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,II); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) == U) ? 0xff : 0x0));
	RzILOpPure *op_EQ_5 = EQ(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_EQ_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,II); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqi_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.eq(Ns.new,n1)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((Ns_new != -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_4 = INV(EQ(Ns_new, SN(32, -1)));
	RzILOpEffect *branch_19 = BRANCH(op_NE_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (!cmp.eq(Ns.new,n1)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((Ns_new != -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_4 = INV(EQ(Ns_new, SN(32, -1)));
	RzILOpEffect *branch_19 = BRANCH(op_NE_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.eq(Ns.new,n1)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((Ns_new == -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_4 = EQ(Ns_new, SN(32, -1));
	RzILOpEffect *branch_19 = BRANCH(op_EQ_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.eq(Ns.new,n1)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((Ns_new == -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_4 = EQ(Ns_new, SN(32, -1));
	RzILOpEffect *branch_19 = BRANCH(op_EQ_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.eq(Rs,n1); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs == -0x1) ? 0xff : 0x0));
	RzILOpPure *op_EQ_4 = EQ(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_EQ_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.eq(Rs,n1); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpeqn1_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gt(Ns.new,Rt)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (Ns_new > Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Ns_new, Rt);
	RzILOpPure *op_INV_4 = INV(op_GT_3);
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (!cmp.gt(Ns.new,Rt)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (Ns_new > Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Ns_new, Rt);
	RzILOpPure *op_INV_4 = INV(op_GT_3);
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gt(Ns.new,Rt)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new > Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Ns_new, Rt);
	RzILOpEffect *branch_18 = BRANCH(op_GT_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (cmp.gt(Ns.new,Rt)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new > Rt)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Ns_new, Rt);
	RzILOpEffect *branch_18 = BRANCH(op_GT_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,Rt); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((Rs > Rt) ? 0xff : 0x0));
	RzILOpPure *op_GT_3 = SGT(Rs, Rt);
	RzILOpPure *cond_6 = ITE(op_GT_3, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,Rt); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgt_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gt(Ns.new,II)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_7, branch_21);
	return instruction_sequence;
}

// if (!cmp.gt(Ns.new,II)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_7, branch_21);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gt(Ns.new,II)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (cmp.gt(Ns.new,II)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,II); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_2 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,II); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgti_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gt(Ns.new,n1)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if (! (Ns_new > -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_4 = SGT(Ns_new, SN(32, -1));
	RzILOpPure *op_INV_5 = INV(op_GT_4);
	RzILOpEffect *branch_20 = BRANCH(op_INV_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (!cmp.gt(Ns.new,n1)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if (! (Ns_new > -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_4 = SGT(Ns_new, SN(32, -1));
	RzILOpPure *op_INV_5 = INV(op_GT_4);
	RzILOpEffect *branch_20 = BRANCH(op_INV_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gt(Ns.new,n1)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((Ns_new > -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_4 = SGT(Ns_new, SN(32, -1));
	RzILOpEffect *branch_19 = BRANCH(op_GT_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gt(Ns.new,n1)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((Ns_new > -0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_4 = SGT(Ns_new, SN(32, -1));
	RzILOpEffect *branch_19 = BRANCH(op_GT_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p0 = cmp.gt(Rs,n1); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs > -0x1) ? 0xff : 0x0));
	RzILOpPure *op_GT_4 = SGT(Rs, SN(32, -1));
	RzILOpPure *cond_7 = ITE(op_GT_4, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_7), DUP(cond_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// p1 = cmp.gt(Rs,n1); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtn1_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gtu(Ns.new,Rt)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Ns_new) > ((ut32) Rt))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), CAST(32, IL_FALSE, Rt));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_7, branch_21);
	return instruction_sequence;
}

// if (!cmp.gtu(Ns.new,Rt)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Ns_new) > ((ut32) Rt))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), CAST(32, IL_FALSE, Rt));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_7, branch_21);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gtu(Ns.new,Rt)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) > ((ut32) Rt))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), CAST(32, IL_FALSE, Rt));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (cmp.gtu(Ns.new,Rt)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) > ((ut32) Rt))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), CAST(32, IL_FALSE, Rt));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P0 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,Rt); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// P1 = ((st8) ((((ut32) Rs) > ((ut32) Rt)) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,Rt); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtu_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gtu(Ns.new,II)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, imm_assign_7, branch_21);
	return instruction_sequence;
}

// if (!cmp.gtu(Ns.new,II)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, imm_assign_7, branch_21);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gtu(Ns.new,II)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (cmp.gtu(Ns.new,II)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Ns_new) > U)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Ns_new), VARL("U"));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, imm_assign_6, branch_20);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P0 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p0 = cmp.gtu(Rs,II); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// P1 = ((st8) ((((ut32) Rs) > U) ? 0xff : 0x0));
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *cond_8 = ITE(op_GT_5, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_8), DUP(cond_8)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// p1 = cmp.gtu(Rs,II); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpgtui_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gt(Rt,Ns.new)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmplt_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (Rt > Ns_new)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Rt, Ns_new);
	RzILOpPure *op_INV_4 = INV(op_GT_3);
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (!cmp.gt(Rt,Ns.new)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmplt_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (Rt > Ns_new)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Rt, Ns_new);
	RzILOpPure *op_INV_4 = INV(op_GT_3);
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (cmp.gt(Rt,Ns.new)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmplt_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Rt > Ns_new)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Rt, Ns_new);
	RzILOpEffect *branch_18 = BRANCH(op_GT_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (cmp.gt(Rt,Ns.new)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmplt_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Rt > Ns_new)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_3 = SGT(Rt, Ns_new);
	RzILOpEffect *branch_18 = BRANCH(op_GT_3, seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (!cmp.gtu(Rt,Ns.new)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpltu_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Rt) > ((ut32) Ns_new))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rt), CAST(32, IL_FALSE, Ns_new));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_7, branch_21);
	return instruction_sequence;
}

// if (!cmp.gtu(Rt,Ns.new)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpltu_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_7 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_13 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_14 = SETL("r", op_AND_13);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_17 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_17_18 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_17));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_14, jump_op_ADD_17_18);

	// if (! (((ut32) Rt) > ((ut32) Ns_new))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rt), CAST(32, IL_FALSE, Ns_new));
	RzILOpPure *op_INV_6 = INV(op_GT_5);
	RzILOpEffect *branch_21 = BRANCH(op_INV_6, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_7, branch_21);
	return instruction_sequence;
}

// if (cmp.gtu(Rt,Ns.new)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_cmpltu_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Rt) > ((ut32) Ns_new))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rt), CAST(32, IL_FALSE, Ns_new));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// if (cmp.gtu(Rt,Ns.new)) jump:t Ii
RzILOpEffect *hex_il_op_j4_cmpltu_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_6 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_12 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_13 = SETL("r", op_AND_12);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_16 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_16_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_16));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if ((((ut32) Rt) > ((ut32) Ns_new))) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GT_5 = UGT(CAST(32, IL_FALSE, Rt), CAST(32, IL_FALSE, Ns_new));
	RzILOpEffect *branch_20 = BRANCH(op_GT_5, seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_20);
	return instruction_sequence;
}

// hintjr(Rs)
RzILOpEffect *hex_il_op_j4_hintjumpr(HexInsnPktBundle *bundle) {
	// READ

	RzILOpEffect *instruction_sequence = EMPTY();
	return instruction_sequence;
}

// Rd = II ; jump Ii
RzILOpEffect *hex_il_op_j4_jumpseti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// U = U;
	RzILOpEffect *imm_assign_9 = SETL("U", U);

	// Rd = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, VARL("U")));

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_9, op_ASSIGN_7, op_ASSIGN_12, jump_op_ADD_15_16);
	return instruction_sequence;
}

// Rd = Rs ; jump Ii
RzILOpEffect *hex_il_op_j4_jumpsetr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// Rd = Rs;
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, Rs);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_13 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_13_14 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_13));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_7, op_ASSIGN_10, jump_op_ADD_13_14);
	return instruction_sequence;
}

// if (!tstbit(Ns.new,#0)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_f_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (Ns_new & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(Ns_new, SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (!tstbit(Ns.new,#0)) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_f_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (Ns_new & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(Ns_new, SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (!p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (!p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (!p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (!p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_fp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_5 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_11 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_12 = SETL("r", op_AND_11);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_15 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_15_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_15));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_18 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if (! (((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_19 = BRANCH(op_INV_4, seq_then_18, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_19);
	return instruction_sequence;
}

// if (tstbit(Ns.new,#0)) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_t_jumpnv_nt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(Ns_new, SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// if (tstbit(Ns.new,#0)) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_t_jumpnv_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp Ns_new_op = NREG2OP(bundle, 's');
	RzILOpPure *Ns_new = READ_REG(pkt, &Ns_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((Ns_new & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(Ns_new, SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp0_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (p0.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp0_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp0_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P0 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P0_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p0 = tstbit(Rs,#0); if (p0.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp0_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P0_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp1_jump_nt_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (p1.new) jump:nt Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp1_jump_nt_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp1_jump_t_part0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// P1 = ((st8) ((Rs & 0x1) ? 0xff : 0x0));
	RzILOpPure *op_AND_3 = LOGAND(Rs, SN(32, 1));
	RzILOpPure *cond_6 = ITE(NON_ZERO(op_AND_3), SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &P1_op, CAST(8, MSB(cond_6), DUP(cond_6)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// p1 = tstbit(Rs,#0); if (p1.new) jump:t Ii
RzILOpEffect *hex_il_op_j4_tstbit0_tp1_jump_t_part1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P1_new_op = EXPLICIT2OP(1, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P1_new = READ_REG(pkt, &P1_new_op, true);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_10 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_11 = SETL("r", op_AND_10);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_14 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_14_15 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_14));

	// seq(r; r = (r & -0x4); jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_17 = SEQN(2, op_ASSIGN_11, jump_op_ADD_14_15);

	// if ((((st32) P1_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(P1_new), DUP(P1_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_18);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>