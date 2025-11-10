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

// deallocframe
RzILOpEffect *hex_il_op_sl2_deallocframe(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = fp;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", READ_REG(pkt, &fp_op, true));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_5 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_7 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_5));

	// tmp = (tmp ^ (((ut64) framekey) << 0x20));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_12 = LOGXOR(VARL("tmp"), op_LSHIFT_11);
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", op_XOR_12);

	// lr = ((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_18 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_18, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, &lr_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_21)), CAST(32, IL_FALSE, DUP(op_AND_21)))));

	// fp = ((ut32) ((st64) ((st32) ((tmp >> 0x0) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_29 = SHIFTR0(VARL("tmp"), SN(32, 0));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, &fp_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_32)), CAST(32, IL_FALSE, DUP(op_AND_32)))));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_40 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, &sp_op, op_ADD_40);

	RzILOpEffect *instruction_sequence = SEQN(6, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, op_ASSIGN_25, op_ASSIGN_36, op_ASSIGN_41);
	return instruction_sequence;
}

// jumpr r31
RzILOpEffect *hex_il_op_sl2_jumpr31(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);

	// jump(lr);
	RzILOpEffect *jump_lr_1 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", lr));

	RzILOpEffect *instruction_sequence = jump_lr_1;
	return instruction_sequence;
}

// if (!p0) jumpr r31
RzILOpEffect *hex_il_op_sl2_jumpr31_f(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	RzILOpPure *P0 = READ_REG(pkt, &P0_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);

	// jump(lr);
	RzILOpEffect *jump_lr_7 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", lr));

	// seq(jump(lr));
	RzILOpEffect *seq_then_9 = jump_lr_7;

	// if (! (((st32) P0) & 0x1)) {seq(jump(lr))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(P0), DUP(P0)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_10 = BRANCH(op_INV_5, seq_then_9, EMPTY());

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (!p0.new) jumpr:nt r31
RzILOpEffect *hex_il_op_sl2_jumpr31_fnew(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);

	// jump(lr);
	RzILOpEffect *jump_lr_7 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", lr));

	// seq(jump(lr));
	RzILOpEffect *seq_then_9 = jump_lr_7;

	// if (! (((st32) P0_new) & 0x1)) {seq(jump(lr))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_5 = INV(NON_ZERO(op_AND_4));
	RzILOpEffect *branch_10 = BRANCH(op_INV_5, seq_then_9, EMPTY());

	RzILOpEffect *instruction_sequence = branch_10;
	return instruction_sequence;
}

// if (p0) jumpr r31
RzILOpEffect *hex_il_op_sl2_jumpr31_t(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	RzILOpPure *P0 = READ_REG(pkt, &P0_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);

	// jump(lr);
	RzILOpEffect *jump_lr_6 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", lr));

	// seq(jump(lr));
	RzILOpEffect *seq_then_8 = jump_lr_6;

	// if ((((st32) P0) & 0x1)) {seq(jump(lr))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(P0), DUP(P0)), SN(32, 1));
	RzILOpEffect *branch_9 = BRANCH(NON_ZERO(op_AND_4), seq_then_8, EMPTY());

	RzILOpEffect *instruction_sequence = branch_9;
	return instruction_sequence;
}

// if (p0.new) jumpr:nt r31
RzILOpEffect *hex_il_op_sl2_jumpr31_tnew(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);

	// jump(lr);
	RzILOpEffect *jump_lr_6 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", lr));

	// seq(jump(lr));
	RzILOpEffect *seq_then_8 = jump_lr_6;

	// if ((((st32) P0_new) & 0x1)) {seq(jump(lr))} else {{}};
	RzILOpPure *op_AND_4 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_9 = BRANCH(NON_ZERO(op_AND_4), seq_then_8, EMPTY());

	RzILOpEffect *instruction_sequence = branch_9;
	return instruction_sequence;
}

// Rd = memb(Rs+Ii)
RzILOpEffect *hex_il_op_sl2_loadrb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rdd = memd(r29+Ii)
RzILOpEffect *hex_il_op_sl2_loadrd_sp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);
	RzILOpPure *sp = READ_REG(pkt, &sp_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = sp + u;
	RzILOpPure *op_ADD_4 = ADD(sp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_8 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_8)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memh(Rs+Ii)
RzILOpEffect *hex_il_op_sl2_loadrh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memw(r29+Ii)
RzILOpEffect *hex_il_op_sl2_loadri_sp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);
	RzILOpPure *sp = READ_REG(pkt, &sp_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = sp + u;
	RzILOpPure *op_ADD_4 = ADD(sp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_8 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_8)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memuh(Rs+Ii)
RzILOpEffect *hex_il_op_sl2_loadruh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// dealloc_return
RzILOpEffect *hex_il_op_sl2_return(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = fp;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", READ_REG(pkt, &fp_op, true));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_5 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_7 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_5));

	// tmp = (tmp ^ (((ut64) framekey) << 0x20));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_12 = LOGXOR(VARL("tmp"), op_LSHIFT_11);
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", op_XOR_12);

	// lr = ((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_18 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_18, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_25 = WRITE_REG(bundle, &lr_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_21)), CAST(32, IL_FALSE, DUP(op_AND_21)))));

	// fp = ((ut32) ((st64) ((st32) ((tmp >> 0x0) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_29 = SHIFTR0(VARL("tmp"), SN(32, 0));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_29, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, &fp_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_32)), CAST(32, IL_FALSE, DUP(op_AND_32)))));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_40 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, &sp_op, op_ADD_40);

	// jump(((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff))))));
	RzILOpPure *op_RSHIFT_45 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *jump_cast_ut32_51_52 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_48)), CAST(32, IL_FALSE, DUP(op_AND_48))))));

	RzILOpEffect *instruction_sequence = SEQN(7, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, op_ASSIGN_25, op_ASSIGN_36, op_ASSIGN_41, jump_cast_ut32_51_52);
	return instruction_sequence;
}

// if (!p0) dealloc_return
RzILOpEffect *hex_il_op_sl2_return_f(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	RzILOpPure *P0 = READ_REG(pkt, &P0_op, false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = fp;
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", READ_REG(pkt, &fp_op, true));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_12 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_12));

	// tmp = (tmp ^ (((ut64) framekey) << 0x20));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_19 = LOGXOR(VARL("tmp"), op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_20 = SETL("tmp", op_XOR_19);

	// lr = ((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_25 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_25, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_32 = WRITE_REG(bundle, &lr_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_28)), CAST(32, IL_FALSE, DUP(op_AND_28)))));

	// fp = ((ut32) ((st64) ((st32) ((tmp >> 0x0) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_36 = SHIFTR0(VARL("tmp"), SN(32, 0));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_36, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, &fp_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_39)), CAST(32, IL_FALSE, DUP(op_AND_39)))));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_47 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, &sp_op, op_ADD_47);

	// jump(((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff))))));
	RzILOpPure *op_RSHIFT_52 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *jump_cast_ut32_58_59 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_55)), CAST(32, IL_FALSE, DUP(op_AND_55))))));

	// nop;
	RzILOpEffect *nop_61 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...;
	RzILOpEffect *seq_then_63 = SEQN(6, op_ASSIGN_14, op_ASSIGN_20, op_ASSIGN_32, op_ASSIGN_43, op_ASSIGN_48, jump_cast_ut32_58_59);

	// seq(nop);
	RzILOpEffect *seq_else_64 = nop_61;

	// if (! (((st32) P0) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(P0), DUP(P0)), SN(32, 1));
	RzILOpPure *op_INV_11 = INV(NON_ZERO(op_AND_10));
	RzILOpEffect *branch_65 = BRANCH(op_INV_11, seq_then_63, seq_else_64);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_65);
	return instruction_sequence;
}

// if (!p0.new) dealloc_return:nt
RzILOpEffect *hex_il_op_sl2_return_fnew(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = fp;
	RzILOpEffect *op_ASSIGN_4 = SETL("EA", READ_REG(pkt, &fp_op, true));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_11));

	// tmp = (tmp ^ (((ut64) framekey) << 0x20));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_18 = LOGXOR(VARL("tmp"), op_LSHIFT_17);
	RzILOpEffect *op_ASSIGN_19 = SETL("tmp", op_XOR_18);

	// lr = ((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, &lr_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_27)), CAST(32, IL_FALSE, DUP(op_AND_27)))));

	// fp = ((ut32) ((st64) ((st32) ((tmp >> 0x0) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_35 = SHIFTR0(VARL("tmp"), SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, &fp_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_38)), CAST(32, IL_FALSE, DUP(op_AND_38)))));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_46 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, &sp_op, op_ADD_46);

	// jump(((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff))))));
	RzILOpPure *op_RSHIFT_51 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_51, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *jump_cast_ut32_57_58 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_54)), CAST(32, IL_FALSE, DUP(op_AND_54))))));

	// nop;
	RzILOpEffect *nop_60 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...;
	RzILOpEffect *seq_then_62 = SEQN(6, op_ASSIGN_13, op_ASSIGN_19, op_ASSIGN_31, op_ASSIGN_42, op_ASSIGN_47, jump_cast_ut32_57_58);

	// seq(nop);
	RzILOpEffect *seq_else_63 = nop_60;

	// if (! (((st32) P0_new) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...} else {seq(nop)};
	RzILOpPure *op_AND_9 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpPure *op_INV_10 = INV(NON_ZERO(op_AND_9));
	RzILOpEffect *branch_64 = BRANCH(op_INV_10, seq_then_62, seq_else_63);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_4, branch_64);
	return instruction_sequence;
}

// if (p0) dealloc_return
RzILOpEffect *hex_il_op_sl2_return_t(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp P0_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, false);
	RzILOpPure *P0 = READ_REG(pkt, &P0_op, false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = fp;
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", READ_REG(pkt, &fp_op, true));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_11));

	// tmp = (tmp ^ (((ut64) framekey) << 0x20));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_18 = LOGXOR(VARL("tmp"), op_LSHIFT_17);
	RzILOpEffect *op_ASSIGN_19 = SETL("tmp", op_XOR_18);

	// lr = ((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, &lr_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_27)), CAST(32, IL_FALSE, DUP(op_AND_27)))));

	// fp = ((ut32) ((st64) ((st32) ((tmp >> 0x0) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_35 = SHIFTR0(VARL("tmp"), SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, &fp_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_38)), CAST(32, IL_FALSE, DUP(op_AND_38)))));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_46 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, &sp_op, op_ADD_46);

	// jump(((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff))))));
	RzILOpPure *op_RSHIFT_51 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_54 = LOGAND(op_RSHIFT_51, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *jump_cast_ut32_57_58 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_54)), CAST(32, IL_FALSE, DUP(op_AND_54))))));

	// nop;
	RzILOpEffect *nop_60 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...;
	RzILOpEffect *seq_then_62 = SEQN(6, op_ASSIGN_13, op_ASSIGN_19, op_ASSIGN_31, op_ASSIGN_42, op_ASSIGN_47, jump_cast_ut32_57_58);

	// seq(nop);
	RzILOpEffect *seq_else_63 = nop_60;

	// if ((((st32) P0) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(P0), DUP(P0)), SN(32, 1));
	RzILOpEffect *branch_64 = BRANCH(NON_ZERO(op_AND_10), seq_then_62, seq_else_63);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_64);
	return instruction_sequence;
}

// if (p0.new) dealloc_return:nt
RzILOpEffect *hex_il_op_sl2_return_tnew(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp P0_new_op = EXPLICIT2OP(0, HEX_REG_CLASS_PRED_REGS, true);
	RzILOpPure *P0_new = READ_REG(pkt, &P0_new_op, true);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = fp;
	RzILOpEffect *op_ASSIGN_4 = SETL("EA", READ_REG(pkt, &fp_op, true));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_10 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_10));

	// tmp = (tmp ^ (((ut64) framekey) << 0x20));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_17 = LOGXOR(VARL("tmp"), op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = SETL("tmp", op_XOR_17);

	// lr = ((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_23 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_30 = WRITE_REG(bundle, &lr_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_26)), CAST(32, IL_FALSE, DUP(op_AND_26)))));

	// fp = ((ut32) ((st64) ((st32) ((tmp >> 0x0) & ((ut64) 0xffffffff)))));
	RzILOpPure *op_RSHIFT_34 = SHIFTR0(VARL("tmp"), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_34, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, &fp_op, CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_37)), CAST(32, IL_FALSE, DUP(op_AND_37)))));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_45 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, &sp_op, op_ADD_45);

	// jump(((ut32) ((st64) ((st32) ((tmp >> 0x20) & ((ut64) 0xffffffff))))));
	RzILOpPure *op_RSHIFT_50 = SHIFTR0(VARL("tmp"), SN(32, 0x20));
	RzILOpPure *op_AND_53 = LOGAND(op_RSHIFT_50, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpEffect *jump_cast_ut32_56_57 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, IL_FALSE, op_AND_53)), CAST(32, IL_FALSE, DUP(op_AND_53))))));

	// nop;
	RzILOpEffect *nop_59 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...;
	RzILOpEffect *seq_then_61 = SEQN(6, op_ASSIGN_12, op_ASSIGN_18, op_ASSIGN_30, op_ASSIGN_41, op_ASSIGN_46, jump_cast_ut32_56_57);

	// seq(nop);
	RzILOpEffect *seq_else_62 = nop_59;

	// if ((((st32) P0_new) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); tmp = (tmp ^ (((ut64) framek ...} else {seq(nop)};
	RzILOpPure *op_AND_9 = LOGAND(CAST(32, MSB(P0_new), DUP(P0_new)), SN(32, 1));
	RzILOpEffect *branch_63 = BRANCH(NON_ZERO(op_AND_9), seq_then_61, seq_else_62);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_4, branch_63);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>