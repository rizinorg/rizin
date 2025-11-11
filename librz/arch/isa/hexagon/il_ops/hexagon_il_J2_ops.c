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

// call Ii
RzILOpEffect *hex_il_op_j2_call(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// HYB(call_pkt);
	RzILOpEffect *c_call_9 = HEX_GET_NPC(pkt);

	// h_tmp157 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp157", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp157 = HYB(call_pkt));
	RzILOpEffect *seq_12 = SEQN(2, c_call_9, op_ASSIGN_hybrid_tmp_11);

	// lr = (h_tmp157 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_15 = LOGAND(VARL("h_tmp157"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lr_op, op_AND_15);

	// seq(seq(HYB(call_pkt); h_tmp157 = HYB(call_pkt)); lr = (h_tmp157 ...;
	RzILOpEffect *seq_17 = SEQN(2, seq_12, op_ASSIGN_16);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_20 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_20_21 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_20));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_7, seq_17, jump_op_ADD_20_21);
	return instruction_sequence;
}

// if (!Pu) call Ii
RzILOpEffect *hex_il_op_j2_callf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// HYB(call_pkt);
	RzILOpEffect *c_call_15 = HEX_GET_NPC(pkt);

	// h_tmp158 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_17 = SETL("h_tmp158", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp158 = HYB(call_pkt));
	RzILOpEffect *seq_18 = SEQN(2, c_call_15, op_ASSIGN_hybrid_tmp_17);

	// lr = (h_tmp158 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_21 = LOGAND(VARL("h_tmp158"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, &lr_op, op_AND_21);

	// seq(seq(HYB(call_pkt); h_tmp158 = HYB(call_pkt)); lr = (h_tmp158 ...;
	RzILOpEffect *seq_23 = SEQN(2, seq_18, op_ASSIGN_22);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_26 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_26_27 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_26));

	// seq(seq(seq(HYB(call_pkt); h_tmp158 = HYB(call_pkt)); lr = (h_tm ...;
	RzILOpEffect *seq_then_30 = SEQN(2, seq_23, jump_op_ADD_26_27);

	// if (! (((st32) Pu) & 0x1)) {seq(seq(seq(HYB(call_pkt); h_tmp158 = HYB(call_pkt)); lr = (h_tm ...} else {{}};
	RzILOpPure *op_AND_12 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_13 = INV(NON_ZERO(op_AND_12));
	RzILOpEffect *branch_31 = BRANCH(op_INV_13, seq_then_30, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_7, branch_31);
	return instruction_sequence;
}

// callr Rs
RzILOpEffect *hex_il_op_j2_callr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// HYB(call_pkt);
	RzILOpEffect *c_call_1 = HEX_GET_NPC(pkt);

	// h_tmp159 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_3 = SETL("h_tmp159", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp159 = HYB(call_pkt));
	RzILOpEffect *seq_4 = SEQN(2, c_call_1, op_ASSIGN_hybrid_tmp_3);

	// lr = (h_tmp159 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_7 = LOGAND(VARL("h_tmp159"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &lr_op, op_AND_7);

	// seq(seq(HYB(call_pkt); h_tmp159 = HYB(call_pkt)); lr = (h_tmp159 ...;
	RzILOpEffect *seq_9 = SEQN(2, seq_4, op_ASSIGN_8);

	// jump(Rs);
	RzILOpEffect *jump_Rs_11 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	RzILOpEffect *instruction_sequence = SEQN(2, seq_9, jump_Rs_11);
	return instruction_sequence;
}

// if (!Pu) callr Rs
RzILOpEffect *hex_il_op_j2_callrf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// HYB(call_pkt);
	RzILOpEffect *c_call_7 = HEX_GET_NPC(pkt);

	// h_tmp160 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_9 = SETL("h_tmp160", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp160 = HYB(call_pkt));
	RzILOpEffect *seq_10 = SEQN(2, c_call_7, op_ASSIGN_hybrid_tmp_9);

	// lr = (h_tmp160 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_13 = LOGAND(VARL("h_tmp160"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, &lr_op, op_AND_13);

	// seq(seq(HYB(call_pkt); h_tmp160 = HYB(call_pkt)); lr = (h_tmp160 ...;
	RzILOpEffect *seq_15 = SEQN(2, seq_10, op_ASSIGN_14);

	// jump(Rs);
	RzILOpEffect *jump_Rs_17 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(seq(seq(HYB(call_pkt); h_tmp160 = HYB(call_pkt)); lr = (h_tm ...;
	RzILOpEffect *seq_then_20 = SEQN(2, seq_15, jump_Rs_17);

	// if (! (((st32) Pu) & 0x1)) {seq(seq(seq(HYB(call_pkt); h_tmp160 = HYB(call_pkt)); lr = (h_tm ...} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_21 = BRANCH(op_INV_5, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = branch_21;
	return instruction_sequence;
}

// callrh Rs
RzILOpEffect *hex_il_op_j2_callrh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// HYB(call_pkt);
	RzILOpEffect *c_call_1 = HEX_GET_NPC(pkt);

	// h_tmp161 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_3 = SETL("h_tmp161", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp161 = HYB(call_pkt));
	RzILOpEffect *seq_4 = SEQN(2, c_call_1, op_ASSIGN_hybrid_tmp_3);

	// lr = (h_tmp161 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_7 = LOGAND(VARL("h_tmp161"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, &lr_op, op_AND_7);

	// seq(seq(HYB(call_pkt); h_tmp161 = HYB(call_pkt)); lr = (h_tmp161 ...;
	RzILOpEffect *seq_9 = SEQN(2, seq_4, op_ASSIGN_8);

	// jump(Rs);
	RzILOpEffect *jump_Rs_11 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	RzILOpEffect *instruction_sequence = SEQN(2, seq_9, jump_Rs_11);
	return instruction_sequence;
}

// if (Pu) callr Rs
RzILOpEffect *hex_il_op_j2_callrt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// HYB(call_pkt);
	RzILOpEffect *c_call_6 = HEX_GET_NPC(pkt);

	// h_tmp162 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_8 = SETL("h_tmp162", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp162 = HYB(call_pkt));
	RzILOpEffect *seq_9 = SEQN(2, c_call_6, op_ASSIGN_hybrid_tmp_8);

	// lr = (h_tmp162 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_12 = LOGAND(VARL("h_tmp162"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, &lr_op, op_AND_12);

	// seq(seq(HYB(call_pkt); h_tmp162 = HYB(call_pkt)); lr = (h_tmp162 ...;
	RzILOpEffect *seq_14 = SEQN(2, seq_9, op_ASSIGN_13);

	// jump(Rs);
	RzILOpEffect *jump_Rs_16 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(seq(seq(HYB(call_pkt); h_tmp162 = HYB(call_pkt)); lr = (h_tm ...;
	RzILOpEffect *seq_then_19 = SEQN(2, seq_14, jump_Rs_16);

	// if ((((st32) Pu) & 0x1)) {seq(seq(seq(HYB(call_pkt); h_tmp162 = HYB(call_pkt)); lr = (h_tm ...} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_4), seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (Pu) call Ii
RzILOpEffect *hex_il_op_j2_callt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// HYB(call_pkt);
	RzILOpEffect *c_call_14 = HEX_GET_NPC(pkt);

	// h_tmp163 = HYB(call_pkt);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_16 = SETL("h_tmp163", UNSIGNED(32, VARL("ret_val")));

	// seq(HYB(call_pkt); h_tmp163 = HYB(call_pkt));
	RzILOpEffect *seq_17 = SEQN(2, c_call_14, op_ASSIGN_hybrid_tmp_16);

	// lr = (h_tmp163 & ((ut32) 0xfffffffe));
	RzILOpPure *op_AND_20 = LOGAND(VARL("h_tmp163"), CAST(32, IL_FALSE, SN(32, 0xfffffffe)));
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, &lr_op, op_AND_20);

	// seq(seq(HYB(call_pkt); h_tmp163 = HYB(call_pkt)); lr = (h_tmp163 ...;
	RzILOpEffect *seq_22 = SEQN(2, seq_17, op_ASSIGN_21);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_25 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_25_26 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_25));

	// seq(seq(seq(HYB(call_pkt); h_tmp163 = HYB(call_pkt)); lr = (h_tm ...;
	RzILOpEffect *seq_then_29 = SEQN(2, seq_22, jump_op_ADD_25_26);

	// if ((((st32) Pu) & 0x1)) {seq(seq(seq(HYB(call_pkt); h_tmp163 = HYB(call_pkt)); lr = (h_tm ...} else {{}};
	RzILOpPure *op_AND_12 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_30 = BRANCH(NON_ZERO(op_AND_12), seq_then_29, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_7, branch_30);
	return instruction_sequence;
}

// jump Ii
RzILOpEffect *hex_il_op_j2_jump(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	RzILOpPure *pc = U32(pkt->pkt_addr);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_10 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_10_11 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_10));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_7, jump_op_ADD_10_11);
	return instruction_sequence;
}

// if (!Pu) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumpf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
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
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if (! (((st32) Pu) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_21 = BRANCH(op_INV_5, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_21);
	return instruction_sequence;
}

// if (!Pu.new) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumpfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
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
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if (! (((st32) Pu_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_21 = BRANCH(op_INV_5, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_21);
	return instruction_sequence;
}

// if (!Pu.new) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumpfnewpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
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
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if (! (((st32) Pu_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_21 = BRANCH(op_INV_5, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_21);
	return instruction_sequence;
}

// if (!Pu) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumpfpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
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
	RzILOpEffect *seq_then_20 = SEQN(2, op_ASSIGN_13, jump_op_ADD_16_17);

	// if (! (((st32) Pu) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_21 = BRANCH(op_INV_5, seq_then_20, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_6, branch_21);
	return instruction_sequence;
}

// jumpr Rs
RzILOpEffect *hex_il_op_j2_jumpr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_1 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	RzILOpEffect *instruction_sequence = jump_Rs_1;
	return instruction_sequence;
}

// if (!Pu) jumpr:nt Rs
RzILOpEffect *hex_il_op_j2_jumprf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_7 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_10 = jump_Rs_7;

	// if (! (((st32) Pu) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_11 = BRANCH(op_INV_5, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = branch_11;
	return instruction_sequence;
}

// if (!Pu.new) jumpr:nt Rs
RzILOpEffect *hex_il_op_j2_jumprfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_7 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_10 = jump_Rs_7;

	// if (! (((st32) Pu_new) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_11 = BRANCH(op_INV_5, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = branch_11;
	return instruction_sequence;
}

// if (!Pu.new) jumpr:t Rs
RzILOpEffect *hex_il_op_j2_jumprfnewpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_7 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_10 = jump_Rs_7;

	// if (! (((st32) Pu_new) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_11 = BRANCH(op_INV_5, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = branch_11;
	return instruction_sequence;
}

// if (!Pu) jumpr:t Rs
RzILOpEffect *hex_il_op_j2_jumprfpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_7 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_10 = jump_Rs_7;

	// if (! (((st32) Pu) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_11 = BRANCH(op_INV_5, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = branch_11;
	return instruction_sequence;
}

// if (Rs>=#0) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumprgtez(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs >= 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GE_2 = SGE(Rs, SN(32, 0));
	RzILOpEffect *branch_11 = BRANCH(op_GE_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Rs>=#0) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumprgtezpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs >= 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_GE_2 = SGE(Rs, SN(32, 0));
	RzILOpEffect *branch_11 = BRANCH(op_GE_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// jumprh Rs
RzILOpEffect *hex_il_op_j2_jumprh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_1 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	RzILOpEffect *instruction_sequence = jump_Rs_1;
	return instruction_sequence;
}

// if (Rs<=#0) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumprltez(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs <= 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_LE_2 = SLE(Rs, SN(32, 0));
	RzILOpEffect *branch_11 = BRANCH(op_LE_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Rs<=#0) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumprltezpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs <= 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_LE_2 = SLE(Rs, SN(32, 0));
	RzILOpEffect *branch_11 = BRANCH(op_LE_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Rs==#0) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumprnz(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs == 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_2 = EQ(Rs, SN(32, 0));
	RzILOpEffect *branch_11 = BRANCH(op_EQ_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Rs==#0) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumprnzpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs == 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_EQ_2 = EQ(Rs, SN(32, 0));
	RzILOpEffect *branch_11 = BRANCH(op_EQ_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Pu) jumpr:nt Rs
RzILOpEffect *hex_il_op_j2_jumprt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_6 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_9 = jump_Rs_6;

	// if ((((st32) Pu) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_10 = BRANCH(NON_ZERO(op_AND_4), seq_then_9, EMPTY());

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (Pu.new) jumpr:nt Rs
RzILOpEffect *hex_il_op_j2_jumprtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_6 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_9 = jump_Rs_6;

	// if ((((st32) Pu_new) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_10 = BRANCH(NON_ZERO(op_AND_4), seq_then_9, EMPTY());

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (Pu.new) jumpr:t Rs
RzILOpEffect *hex_il_op_j2_jumprtnewpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_6 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_9 = jump_Rs_6;

	// if ((((st32) Pu_new) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_10 = BRANCH(NON_ZERO(op_AND_4), seq_then_9, EMPTY());

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (Pu) jumpr:t Rs
RzILOpEffect *hex_il_op_j2_jumprtpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// jump(Rs);
	RzILOpEffect *jump_Rs_6 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", Rs));

	// seq(jump(Rs));
	RzILOpEffect *seq_then_9 = jump_Rs_6;

	// if ((((st32) Pu) & 0x1)) {seq(jump(Rs))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_10 = BRANCH(NON_ZERO(op_AND_4), seq_then_9, EMPTY());

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (Rs!=#0) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumprz(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs != 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_2 = INV(EQ(Rs, SN(32, 0)));
	RzILOpEffect *branch_11 = BRANCH(op_NE_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Rs!=#0) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumprzpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));

	// r = r;
	RzILOpEffect *imm_assign_4 = SETL("r", r);

	// jump(pc + ((ut32) r));
	RzILOpPure *op_ADD_7 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *jump_op_ADD_7_8 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", op_ADD_7));

	// seq(jump(pc + ((ut32) r)));
	RzILOpEffect *seq_then_10 = jump_op_ADD_7_8;

	// if ((Rs != 0x0)) {seq(jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_NE_2 = INV(EQ(Rs, SN(32, 0)));
	RzILOpEffect *branch_11 = BRANCH(op_NE_2, seq_then_10, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, branch_11);
	return instruction_sequence;
}

// if (Pu) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
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
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((((st32) Pu) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_4), seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_20);
	return instruction_sequence;
}

// if (Pu.new) jump:nt Ii
RzILOpEffect *hex_il_op_j2_jumptnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
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
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((((st32) Pu_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_4), seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_20);
	return instruction_sequence;
}

// if (Pu.new) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumptnewpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
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
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((((st32) Pu_new) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_4), seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_20);
	return instruction_sequence;
}

// if (Pu) jump:t Ii
RzILOpEffect *hex_il_op_j2_jumptpt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
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
	RzILOpEffect *seq_then_19 = SEQN(2, op_ASSIGN_12, jump_op_ADD_15_16);

	// if ((((st32) Pu) & 0x1)) {seq(r; r = (r & -0x4); jump(pc + ((ut32) r)))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_4), seq_then_19, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_5, branch_20);
	return instruction_sequence;
}

// loop0(Ii,II)
RzILOpEffect *hex_il_op_j2_loop0i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// lc0 = U;
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, VARL("U"));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x0));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_14, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19);
	return instruction_sequence;
}

// loop0(Ii,Rs)
RzILOpEffect *hex_il_op_j2_loop0r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// lc0 = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, CAST(32, IL_FALSE, Rs));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x0));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19);
	return instruction_sequence;
}

// loop1(Ii,II)
RzILOpEffect *hex_il_op_j2_loop1i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa1_op = ALIAS2OP(HEX_REG_ALIAS_SA1, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc1_op = ALIAS2OP(HEX_REG_ALIAS_LC1, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa1 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa1_op, op_ADD_11);

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// lc1 = U;
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc1_op, VARL("U"));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_14, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16);
	return instruction_sequence;
}

// loop1(Ii,Rs)
RzILOpEffect *hex_il_op_j2_loop1r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa1_op = ALIAS2OP(HEX_REG_ALIAS_SA1, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc1_op = ALIAS2OP(HEX_REG_ALIAS_LC1, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa1 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa1_op, op_ADD_11);

	// lc1 = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc1_op, CAST(32, IL_FALSE, Rs));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16);
	return instruction_sequence;
}

// pause(Ii)
RzILOpEffect *hex_il_op_j2_pause(HexInsnPktBundle *bundle) {
	// READ

	RzILOpEffect *instruction_sequence = EMPTY();
	return instruction_sequence;
}

// p3 = sp1loop0(Ii,II)
RzILOpEffect *hex_il_op_j2_ploop1si(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// lc0 = U;
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, VARL("U"));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 1)));

	// P3 = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(7, imm_assign_0, imm_assign_14, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19, op_ASSIGN_23);
	return instruction_sequence;
}

// p3 = sp1loop0(Ii,Rs)
RzILOpEffect *hex_il_op_j2_ploop1sr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// lc0 = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, CAST(32, IL_FALSE, Rs));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 1)));

	// P3 = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19, op_ASSIGN_23);
	return instruction_sequence;
}

// p3 = sp2loop0(Ii,II)
RzILOpEffect *hex_il_op_j2_ploop2si(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// lc0 = U;
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, VARL("U"));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x2));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 2)));

	// P3 = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(7, imm_assign_0, imm_assign_14, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19, op_ASSIGN_23);
	return instruction_sequence;
}

// p3 = sp2loop0(Ii,Rs)
RzILOpEffect *hex_il_op_j2_ploop2sr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// lc0 = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, CAST(32, IL_FALSE, Rs));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x2));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 2)));

	// P3 = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19, op_ASSIGN_23);
	return instruction_sequence;
}

// p3 = sp3loop0(Ii,II)
RzILOpEffect *hex_il_op_j2_ploop3si(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// lc0 = U;
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, VARL("U"));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x3));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 3)));

	// P3 = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(7, imm_assign_0, imm_assign_14, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19, op_ASSIGN_23);
	return instruction_sequence;
}

// p3 = sp3loop0(Ii,Rs)
RzILOpEffect *hex_il_op_j2_ploop3sr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *r = SN(32, (st32)ISA2IMM(hi, 'r'));
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *pc = U32(pkt->pkt_addr);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);

	// r = r;
	RzILOpEffect *imm_assign_0 = SETL("r", r);

	// r = (r & -0x4);
	RzILOpPure *op_AND_6 = LOGAND(VARL("r"), SN(32, -4));
	RzILOpEffect *op_ASSIGN_7 = SETL("r", op_AND_6);

	// sa0 = pc + ((ut32) r);
	RzILOpPure *op_ADD_11 = ADD(pc, CAST(32, IL_FALSE, VARL("r")));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &sa0_op, op_ADD_11);

	// lc0 = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, &lc0_op, CAST(32, IL_FALSE, Rs));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, ((ut32) 0x3));
	RzILOpEffect *set_usr_field_call_19 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, CAST(32, IL_FALSE, SN(32, 3)));

	// P3 = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_16, set_usr_field_call_19, op_ASSIGN_23);
	return instruction_sequence;
}

// rte
RzILOpEffect *hex_il_op_j2_rte(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// trap0(Ii)
RzILOpEffect *hex_il_op_j2_trap0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// trap(0x0, u);
	RzILOpEffect *trap_call_3 = hex_trap(SN(32, 0), VARL("u"));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, trap_call_3);
	return instruction_sequence;
}

// trap1(Rx,Ii)
RzILOpEffect *hex_il_op_j2_trap1(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// unpause
RzILOpEffect *hex_il_op_j2_unpause(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

#include <rz_il/rz_il_opbuilder_end.h>