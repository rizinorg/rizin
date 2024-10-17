// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
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

// No syntax
RzILOpEffect *hex_il_op_j2_endloop01(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *sa0 = READ_REG(pkt, &sa0_op, false);
	const HexOp lc1_op = ALIAS2OP(HEX_REG_ALIAS_LC1, false);
	const HexOp sa1_op = ALIAS2OP(HEX_REG_ALIAS_SA1, false);
	RzILOpPure *sa1 = READ_REG(pkt, &sa1_op, false);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_0 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp620 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_2 = SETL("h_tmp620", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp620 = g ...;
	RzILOpEffect *seq_3 = SEQN(2, get_usr_field_call_0, op_ASSIGN_hybrid_tmp_2);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_4 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp621 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_6 = SETL("h_tmp621", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp621 = g ...;
	RzILOpEffect *seq_7 = SEQN(2, get_usr_field_call_4, op_ASSIGN_hybrid_tmp_6);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_12 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp622 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_14 = SETL("h_tmp622", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp622 = g ...;
	RzILOpEffect *seq_15 = SEQN(2, get_usr_field_call_12, op_ASSIGN_hybrid_tmp_14);

	// P3 = ((st8) 0xff);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0xff)), SN(32, 0xff)));

	// seq(P3 = ((st8) 0xff));
	RzILOpEffect *seq_then_24 = op_ASSIGN_22;

	// if ((h_tmp622 == ((ut32) 0x1))) {seq(P3 = ((st8) 0xff))} else {{}};
	RzILOpPure *op_EQ_18 = EQ(VARL("h_tmp622"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_25 = BRANCH(op_EQ_18, seq_then_24, EMPTY());

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp622 ...;
	RzILOpEffect *seq_26 = SEQN(2, seq_15, branch_25);

	// seq({});
	RzILOpEffect *seq_then_27 = EMPTY();

	// seq(seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tm ...;
	RzILOpEffect *seq_else_28 = seq_26;

	// if ((h_tmp621 >= ((ut32) 0x2))) {seq({})} else {seq(seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tm ...};
	RzILOpPure *op_GE_10 = UGE(VARL("h_tmp621"), CAST(32, IL_FALSE, SN(32, 2)));
	RzILOpEffect *branch_29 = BRANCH(op_GE_10, seq_then_27, seq_else_28);

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp621 ...;
	RzILOpEffect *seq_30 = SEQN(2, seq_7, branch_29);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_31 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp623 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_33 = SETL("h_tmp623", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp623 = g ...;
	RzILOpEffect *seq_34 = SEQN(2, get_usr_field_call_31, op_ASSIGN_hybrid_tmp_33);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, h_tmp623 - ((ut32) 0x1));
	RzILOpPure *op_SUB_37 = SUB(VARL("h_tmp623"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *set_usr_field_call_38 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, op_SUB_37);

	// seq(seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tm ...;
	RzILOpEffect *seq_then_39 = SEQN(2, seq_30, set_usr_field_call_38);

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp623 ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_34, seq_then_39);

	// if (h_tmp620) {seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp623 ...} else {{}};
	RzILOpEffect *branch_41 = BRANCH(NON_ZERO(VARL("h_tmp620")), seq_40, EMPTY());

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp620 ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_3, branch_41);

	// jump(sa0);
	RzILOpEffect *jump_sa0_48 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", sa0));

	// lc0 = lc0 - ((ut32) 0x1);
	RzILOpPure *op_SUB_52 = SUB(READ_REG(pkt, &lc0_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_53 = WRITE_REG(bundle, &lc0_op, op_SUB_52);

	// jump(sa1);
	RzILOpEffect *jump_sa1_59 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", sa1));

	// lc1 = lc1 - ((ut32) 0x1);
	RzILOpPure *op_SUB_63 = SUB(READ_REG(pkt, &lc1_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_64 = WRITE_REG(bundle, &lc1_op, op_SUB_63);

	// seq(jump(sa1); lc1 = lc1 - ((ut32) 0x1));
	RzILOpEffect *seq_then_65 = SEQN(2, jump_sa1_59, op_ASSIGN_64);

	// if ((lc1 > ((ut32) 0x1))) {seq(jump(sa1); lc1 = lc1 - ((ut32) 0x1))} else {{}};
	RzILOpPure *op_GT_57 = UGT(READ_REG(pkt, &lc1_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_66 = BRANCH(op_GT_57, seq_then_65, EMPTY());

	// seq(jump(sa0); lc0 = lc0 - ((ut32) 0x1));
	RzILOpEffect *seq_then_67 = SEQN(2, jump_sa0_48, op_ASSIGN_53);

	// seq(if ((lc1 > ((ut32) 0x1))) {seq(jump(sa1); lc1 = lc1 - ((ut32 ...;
	RzILOpEffect *seq_else_68 = branch_66;

	// if ((lc0 > ((ut32) 0x1))) {seq(jump(sa0); lc0 = lc0 - ((ut32) 0x1))} else {seq(if ((lc1 > ((ut32) 0x1))) {seq(jump(sa1); lc1 = lc1 - ((ut32 ...};
	RzILOpPure *op_GT_46 = UGT(READ_REG(pkt, &lc0_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_69 = BRANCH(op_GT_46, seq_then_67, seq_else_68);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_42, branch_69);
	return instruction_sequence;
}

// No syntax
RzILOpEffect *hex_il_op_j2_endloop1(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp lc1_op = ALIAS2OP(HEX_REG_ALIAS_LC1, false);
	const HexOp sa1_op = ALIAS2OP(HEX_REG_ALIAS_SA1, false);
	RzILOpPure *sa1 = READ_REG(pkt, &sa1_op, false);

	// jump(sa1);
	RzILOpEffect *jump_sa1_5 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", sa1));

	// lc1 = lc1 - ((ut32) 0x1);
	RzILOpPure *op_SUB_9 = SUB(READ_REG(pkt, &lc1_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, &lc1_op, op_SUB_9);

	// seq(jump(sa1); lc1 = lc1 - ((ut32) 0x1));
	RzILOpEffect *seq_then_11 = SEQN(2, jump_sa1_5, op_ASSIGN_10);

	// if ((lc1 > ((ut32) 0x1))) {seq(jump(sa1); lc1 = lc1 - ((ut32) 0x1))} else {{}};
	RzILOpPure *op_GT_3 = UGT(READ_REG(pkt, &lc1_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_12 = BRANCH(op_GT_3, seq_then_11, EMPTY());

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// No syntax
RzILOpEffect *hex_il_op_j2_endloop0(HexInsnPktBundle *bundle) {
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp P3_op = EXPLICIT2OP(3, HEX_REG_CLASS_PRED_REGS, false);
	const HexOp lc0_op = ALIAS2OP(HEX_REG_ALIAS_LC0, false);
	const HexOp sa0_op = ALIAS2OP(HEX_REG_ALIAS_SA0, false);
	RzILOpPure *sa0 = READ_REG(pkt, &sa0_op, false);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_0 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp624 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_2 = SETL("h_tmp624", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp624 = g ...;
	RzILOpEffect *seq_3 = SEQN(2, get_usr_field_call_0, op_ASSIGN_hybrid_tmp_2);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_4 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp625 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_6 = SETL("h_tmp625", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp625 = g ...;
	RzILOpEffect *seq_7 = SEQN(2, get_usr_field_call_4, op_ASSIGN_hybrid_tmp_6);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_12 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp626 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_14 = SETL("h_tmp626", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp626 = g ...;
	RzILOpEffect *seq_15 = SEQN(2, get_usr_field_call_12, op_ASSIGN_hybrid_tmp_14);

	// P3 = ((st8) 0xff);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, &P3_op, CAST(8, MSB(SN(32, 0xff)), SN(32, 0xff)));

	// seq(P3 = ((st8) 0xff));
	RzILOpEffect *seq_then_24 = op_ASSIGN_22;

	// if ((h_tmp626 == ((ut32) 0x1))) {seq(P3 = ((st8) 0xff))} else {{}};
	RzILOpPure *op_EQ_18 = EQ(VARL("h_tmp626"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_25 = BRANCH(op_EQ_18, seq_then_24, EMPTY());

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp626 ...;
	RzILOpEffect *seq_26 = SEQN(2, seq_15, branch_25);

	// seq({});
	RzILOpEffect *seq_then_27 = EMPTY();

	// seq(seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tm ...;
	RzILOpEffect *seq_else_28 = seq_26;

	// if ((h_tmp625 >= ((ut32) 0x2))) {seq({})} else {seq(seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tm ...};
	RzILOpPure *op_GE_10 = UGE(VARL("h_tmp625"), CAST(32, IL_FALSE, SN(32, 2)));
	RzILOpEffect *branch_29 = BRANCH(op_GE_10, seq_then_27, seq_else_28);

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp625 ...;
	RzILOpEffect *seq_30 = SEQN(2, seq_7, branch_29);

	// get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *get_usr_field_call_31 = hex_get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);

	// h_tmp627 = get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_33 = SETL("h_tmp627", UNSIGNED(32, VARL("ret_val")));

	// seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp627 = g ...;
	RzILOpEffect *seq_34 = SEQN(2, get_usr_field_call_31, op_ASSIGN_hybrid_tmp_33);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, h_tmp627 - ((ut32) 0x1));
	RzILOpPure *op_SUB_37 = SUB(VARL("h_tmp627"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *set_usr_field_call_38 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG, op_SUB_37);

	// seq(seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tm ...;
	RzILOpEffect *seq_then_39 = SEQN(2, seq_30, set_usr_field_call_38);

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp627 ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_34, seq_then_39);

	// if (h_tmp624) {seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp627 ...} else {{}};
	RzILOpEffect *branch_41 = BRANCH(NON_ZERO(VARL("h_tmp624")), seq_40, EMPTY());

	// seq(seq(get_usr_field(bundle, HEX_REG_FIELD_USR_LPCFG); h_tmp624 ...;
	RzILOpEffect *seq_42 = SEQN(2, seq_3, branch_41);

	// jump(sa0);
	RzILOpEffect *jump_sa0_48 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", sa0));

	// lc0 = lc0 - ((ut32) 0x1);
	RzILOpPure *op_SUB_52 = SUB(READ_REG(pkt, &lc0_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_53 = WRITE_REG(bundle, &lc0_op, op_SUB_52);

	// seq(jump(sa0); lc0 = lc0 - ((ut32) 0x1));
	RzILOpEffect *seq_then_54 = SEQN(2, jump_sa0_48, op_ASSIGN_53);

	// if ((lc0 > ((ut32) 0x1))) {seq(jump(sa0); lc0 = lc0 - ((ut32) 0x1))} else {{}};
	RzILOpPure *op_GT_46 = UGT(READ_REG(pkt, &lc0_op, true), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_55 = BRANCH(op_GT_46, seq_then_54, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(2, seq_42, branch_55);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_fcirc_add(HexInsnPktBundle *bundle, const HexOp *RxV, RZ_BORROW RzILOpPure *offset, RZ_BORROW RzILOpPure *M, RZ_BORROW RzILOpPure *CS) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;

	// READ
	// Declare: ut32 K_const;
	// Declare: ut32 length;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	// Declare: ut32 new_ptr;
	// Declare: ut32 start_addr;
	// Declare: ut32 end_addr;
	// Declare: st32 mask;

	// K_const = extract32(((ut32) M), 0x18, 0x4);
	RzILOpEffect *op_ASSIGN_5 = SETL("K_const", EXTRACT32(CAST(32, IL_FALSE, M), SN(32, 24), SN(32, 4)));

	// length = extract32(((ut32) M), 0x0, 0x11);
	RzILOpEffect *op_ASSIGN_11 = SETL("length", EXTRACT32(CAST(32, IL_FALSE, DUP(M)), SN(32, 0), SN(32, 17)));

	// new_ptr = ((ut32) Rx + offset);
	RzILOpPure *op_ADD_13 = ADD(READ_REG(pkt, Rx_op, false), offset);
	RzILOpEffect *op_ASSIGN_15 = SETL("new_ptr", CAST(32, IL_FALSE, op_ADD_13));

	// start_addr = ((ut32) CS);
	RzILOpEffect *op_ASSIGN_27 = SETL("start_addr", CAST(32, IL_FALSE, CS));

	// end_addr = start_addr + length;
	RzILOpPure *op_ADD_28 = ADD(VARL("start_addr"), VARL("length"));
	RzILOpEffect *op_ASSIGN_29 = SETL("end_addr", op_ADD_28);

	// mask = (0x1 << K_const + ((ut32) 0x2)) - 0x1;
	RzILOpPure *op_ADD_33 = ADD(VARL("K_const"), CAST(32, IL_FALSE, SN(32, 2)));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(SN(32, 1), op_ADD_33);
	RzILOpPure *op_SUB_36 = SUB(op_LSHIFT_34, SN(32, 1));
	RzILOpEffect *op_ASSIGN_38 = SETL("mask", op_SUB_36);

	// start_addr = ((ut32) (Rx & (~mask)));
	RzILOpPure *op_NOT_39 = LOGNOT(VARL("mask"));
	RzILOpPure *op_AND_40 = LOGAND(READ_REG(pkt, Rx_op, false), op_NOT_39);
	RzILOpEffect *op_ASSIGN_42 = SETL("start_addr", CAST(32, IL_FALSE, op_AND_40));

	// end_addr = (start_addr | length);
	RzILOpPure *op_OR_43 = LOGOR(VARL("start_addr"), VARL("length"));
	RzILOpEffect *op_ASSIGN_44 = SETL("end_addr", op_OR_43);

	// seq(start_addr = ((ut32) CS); end_addr = start_addr + length);
	RzILOpEffect *seq_then_45 = SEQN(2, op_ASSIGN_27, op_ASSIGN_29);

	// seq(mask = (0x1 << K_const + ((ut32) 0x2)) - 0x1; start_addr = ( ...;
	RzILOpEffect *seq_else_46 = SEQN(3, op_ASSIGN_38, op_ASSIGN_42, op_ASSIGN_44);

	// if (((K_const == ((ut32) 0x0)) && (length >= ((ut32) 0x4)))) {seq(start_addr = ((ut32) CS); end_addr = start_addr + length)} else {seq(mask = (0x1 << K_const + ((ut32) 0x2)) - 0x1; start_addr = ( ...};
	RzILOpPure *op_EQ_21 = EQ(VARL("K_const"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_GE_24 = UGE(VARL("length"), CAST(32, IL_FALSE, SN(32, 4)));
	RzILOpPure *op_AND_25 = AND(op_EQ_21, op_GE_24);
	RzILOpEffect *branch_47 = BRANCH(op_AND_25, seq_then_45, seq_else_46);

	// new_ptr = new_ptr - length;
	RzILOpPure *op_SUB_49 = SUB(VARL("new_ptr"), VARL("length"));
	RzILOpEffect *op_ASSIGN_SUB_50 = SETL("new_ptr", op_SUB_49);

	// new_ptr = new_ptr + length;
	RzILOpPure *op_ADD_52 = ADD(VARL("new_ptr"), VARL("length"));
	RzILOpEffect *op_ASSIGN_ADD_53 = SETL("new_ptr", op_ADD_52);

	// seq(new_ptr = new_ptr + length);
	RzILOpEffect *seq_then_54 = op_ASSIGN_ADD_53;

	// if ((new_ptr < start_addr)) {seq(new_ptr = new_ptr + length)} else {{}};
	RzILOpPure *op_LT_51 = ULT(VARL("new_ptr"), VARL("start_addr"));
	RzILOpEffect *branch_55 = BRANCH(op_LT_51, seq_then_54, EMPTY());

	// seq(new_ptr = new_ptr - length);
	RzILOpEffect *seq_then_56 = op_ASSIGN_SUB_50;

	// seq(if ((new_ptr < start_addr)) {seq(new_ptr = new_ptr + length) ...;
	RzILOpEffect *seq_else_57 = branch_55;

	// if ((new_ptr >= end_addr)) {seq(new_ptr = new_ptr - length)} else {seq(if ((new_ptr < start_addr)) {seq(new_ptr = new_ptr + length) ...};
	RzILOpPure *op_GE_48 = UGE(VARL("new_ptr"), VARL("end_addr"));
	RzILOpEffect *branch_58 = BRANCH(op_GE_48, seq_then_56, seq_else_57);

	// Rx = ((st32) new_ptr);
	RzILOpEffect *op_ASSIGN_60 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, VARL("new_ptr")));

	// ret_val_st32 = ((ut64) new_ptr);
	RzILOpEffect *set_return_val_63 = SETL("ret_val", CAST(64, IL_FALSE, VARL("new_ptr")));

	RzILOpEffect *instruction_sequence = SEQN(7, op_ASSIGN_5, op_ASSIGN_11, op_ASSIGN_15, branch_47, branch_58, op_ASSIGN_60, set_return_val_63);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_trap(RZ_BORROW RzILOpPure *trap_type, RZ_BORROW RzILOpPure *imm) {

	// READ
	// Declare: ut32 dummy;

	// dummy = ((ut32) trap_type) + imm;
	RzILOpPure *op_ADD_1 = ADD(CAST(32, IL_FALSE, trap_type), imm);
	RzILOpEffect *op_ASSIGN_3 = SETL("dummy", op_ADD_1);

	RzILOpEffect *instruction_sequence = op_ASSIGN_3;
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_clz32(RZ_BORROW RzILOpPure *t) {

	// READ
	// Declare: ut32 clz32_x;
	// Declare: ut32 clz32_n;

	// clz32_x = t;
	RzILOpEffect *op_ASSIGN_1 = SETL("clz32_x", t);

	// ret_val_ut32 = ((ut64) 0x20);
	RzILOpEffect *set_return_val_8 = SETL("ret_val", CAST(64, IL_FALSE, SN(32, 0x20)));

	// clz32_n = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_11 = SETL("clz32_n", CAST(32, IL_FALSE, SN(32, 0)));

	// clz32_n = clz32_n + ((ut32) 0x10);
	RzILOpPure *op_ADD_17 = ADD(VARL("clz32_n"), CAST(32, IL_FALSE, SN(32, 16)));
	RzILOpEffect *op_ASSIGN_ADD_18 = SETL("clz32_n", op_ADD_17);

	// clz32_x = (clz32_x << 0x10);
	RzILOpPure *op_SHIFTL_20 = SHIFTL0(VARL("clz32_x"), SN(32, 16));
	RzILOpEffect *op_ASSIGN_LEFT_21 = SETL("clz32_x", op_SHIFTL_20);

	// seq(clz32_n = clz32_n + ((ut32) 0x10); clz32_x = (clz32_x << 0x1 ...;
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_ADD_18, op_ASSIGN_LEFT_21);

	// if ((clz32_x <= 0xffff)) {seq(clz32_n = clz32_n + ((ut32) 0x10); clz32_x = (clz32_x << 0x1 ...} else {{}};
	RzILOpPure *op_LE_14 = ULE(VARL("clz32_x"), UN(32, 0xffff));
	RzILOpEffect *branch_23 = BRANCH(op_LE_14, seq_then_22, EMPTY());

	// clz32_n = clz32_n + ((ut32) 0x8);
	RzILOpPure *op_ADD_28 = ADD(VARL("clz32_n"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_ADD_29 = SETL("clz32_n", op_ADD_28);

	// clz32_x = (clz32_x << 0x8);
	RzILOpPure *op_SHIFTL_31 = SHIFTL0(VARL("clz32_x"), SN(32, 8));
	RzILOpEffect *op_ASSIGN_LEFT_32 = SETL("clz32_x", op_SHIFTL_31);

	// seq(clz32_n = clz32_n + ((ut32) 0x8); clz32_x = (clz32_x << 0x8));
	RzILOpEffect *seq_then_33 = SEQN(2, op_ASSIGN_ADD_29, op_ASSIGN_LEFT_32);

	// if ((clz32_x <= 0xffffff)) {seq(clz32_n = clz32_n + ((ut32) 0x8); clz32_x = (clz32_x << 0x8))} else {{}};
	RzILOpPure *op_LE_25 = ULE(VARL("clz32_x"), UN(32, 0xffffff));
	RzILOpEffect *branch_34 = BRANCH(op_LE_25, seq_then_33, EMPTY());

	// clz32_n = clz32_n + ((ut32) 0x4);
	RzILOpPure *op_ADD_39 = ADD(VARL("clz32_n"), CAST(32, IL_FALSE, SN(32, 4)));
	RzILOpEffect *op_ASSIGN_ADD_40 = SETL("clz32_n", op_ADD_39);

	// clz32_x = (clz32_x << 0x4);
	RzILOpPure *op_SHIFTL_42 = SHIFTL0(VARL("clz32_x"), SN(32, 4));
	RzILOpEffect *op_ASSIGN_LEFT_43 = SETL("clz32_x", op_SHIFTL_42);

	// seq(clz32_n = clz32_n + ((ut32) 0x4); clz32_x = (clz32_x << 0x4));
	RzILOpEffect *seq_then_44 = SEQN(2, op_ASSIGN_ADD_40, op_ASSIGN_LEFT_43);

	// if ((clz32_x <= 0xfffffff)) {seq(clz32_n = clz32_n + ((ut32) 0x4); clz32_x = (clz32_x << 0x4))} else {{}};
	RzILOpPure *op_LE_36 = ULE(VARL("clz32_x"), UN(32, 0xfffffff));
	RzILOpEffect *branch_45 = BRANCH(op_LE_36, seq_then_44, EMPTY());

	// clz32_n = clz32_n + ((ut32) 0x2);
	RzILOpPure *op_ADD_50 = ADD(VARL("clz32_n"), CAST(32, IL_FALSE, SN(32, 2)));
	RzILOpEffect *op_ASSIGN_ADD_51 = SETL("clz32_n", op_ADD_50);

	// clz32_x = (clz32_x << 0x2);
	RzILOpPure *op_SHIFTL_53 = SHIFTL0(VARL("clz32_x"), SN(32, 2));
	RzILOpEffect *op_ASSIGN_LEFT_54 = SETL("clz32_x", op_SHIFTL_53);

	// seq(clz32_n = clz32_n + ((ut32) 0x2); clz32_x = (clz32_x << 0x2));
	RzILOpEffect *seq_then_55 = SEQN(2, op_ASSIGN_ADD_51, op_ASSIGN_LEFT_54);

	// if ((clz32_x <= 0x3fffffff)) {seq(clz32_n = clz32_n + ((ut32) 0x2); clz32_x = (clz32_x << 0x2))} else {{}};
	RzILOpPure *op_LE_47 = ULE(VARL("clz32_x"), UN(32, 0x3fffffff));
	RzILOpEffect *branch_56 = BRANCH(op_LE_47, seq_then_55, EMPTY());

	// HYB(++clz32_n);
	RzILOpEffect *op_INC_59 = SETL("clz32_n", INC(VARL("clz32_n"), 32));

	// h_tmp0 = HYB(++clz32_n);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_61 = SETL("h_tmp0", VARL("clz32_n"));

	// seq(h_tmp0 = HYB(++clz32_n); HYB(++clz32_n));
	RzILOpEffect *seq_62 = SEQN(2, op_ASSIGN_hybrid_tmp_61, op_INC_59);

	// seq(h_tmp0; {});
	RzILOpEffect *seq_then_63 = EMPTY();

	// seq(seq(h_tmp0 = HYB(++clz32_n); HYB(++clz32_n)); seq(h_tmp0; {} ...;
	RzILOpEffect *seq_64 = SEQN(2, seq_62, seq_then_63);

	// if ((clz32_x <= 0x7fffffff)) {seq(seq(h_tmp0 = HYB(++clz32_n); HYB(++clz32_n)); seq(h_tmp0; {} ...} else {{}};
	RzILOpPure *op_LE_58 = ULE(VARL("clz32_x"), UN(32, 0x7fffffff));
	RzILOpEffect *branch_65 = BRANCH(op_LE_58, seq_64, EMPTY());

	// ret_val_ut32 = ((ut64) clz32_n);
	RzILOpEffect *set_return_val_67 = SETL("ret_val", CAST(64, IL_FALSE, VARL("clz32_n")));

	// seq(ret_val_ut32 = ((ut64) 0x20));
	RzILOpEffect *seq_then_68 = set_return_val_8;

	// seq(clz32_n = ((ut32) 0x0); if ((clz32_x <= 0xffff)) {seq(clz32_ ...;
	RzILOpEffect *seq_else_69 = SEQN(7, op_ASSIGN_11, branch_23, branch_34, branch_45, branch_56, branch_65, set_return_val_67);

	// if ((clz32_x == ((ut32) 0x0))) {seq(ret_val_ut32 = ((ut64) 0x20))} else {seq(clz32_n = ((ut32) 0x0); if ((clz32_x <= 0xffff)) {seq(clz32_ ...};
	RzILOpPure *op_EQ_4 = EQ(VARL("clz32_x"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpEffect *branch_70 = BRANCH(op_EQ_4, seq_then_68, seq_else_69);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_1, branch_70);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_clz64(RZ_BORROW RzILOpPure *t) {

	// READ
	// Declare: ut64 clz64_x;
	// Declare: ut64 clz64_n;

	// clz64_x = t;
	RzILOpEffect *op_ASSIGN_1 = SETL("clz64_x", t);

	// ret_val_ut64 = ((ut64) 0x40);
	RzILOpEffect *set_return_val_8 = SETL("ret_val", CAST(64, IL_FALSE, SN(32, 0x40)));

	// clz64_n = ((ut64) 0x0);
	RzILOpEffect *op_ASSIGN_11 = SETL("clz64_n", CAST(64, IL_FALSE, SN(32, 0)));

	// clz64_n = clz64_n + ((ut64) 0x20);
	RzILOpPure *op_ADD_17 = ADD(VARL("clz64_n"), CAST(64, IL_FALSE, SN(32, 0x20)));
	RzILOpEffect *op_ASSIGN_ADD_18 = SETL("clz64_n", op_ADD_17);

	// clz64_x = (clz64_x << 0x20);
	RzILOpPure *op_SHIFTL_20 = SHIFTL0(VARL("clz64_x"), SN(32, 0x20));
	RzILOpEffect *op_ASSIGN_LEFT_21 = SETL("clz64_x", op_SHIFTL_20);

	// seq(clz64_n = clz64_n + ((ut64) 0x20); clz64_x = (clz64_x << 0x2 ...;
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_ADD_18, op_ASSIGN_LEFT_21);

	// if ((clz64_x <= 0xffffffff)) {seq(clz64_n = clz64_n + ((ut64) 0x20); clz64_x = (clz64_x << 0x2 ...} else {{}};
	RzILOpPure *op_LE_14 = ULE(VARL("clz64_x"), UN(64, 0xffffffff));
	RzILOpEffect *branch_23 = BRANCH(op_LE_14, seq_then_22, EMPTY());

	// clz64_n = clz64_n + ((ut64) 0x10);
	RzILOpPure *op_ADD_28 = ADD(VARL("clz64_n"), CAST(64, IL_FALSE, SN(32, 16)));
	RzILOpEffect *op_ASSIGN_ADD_29 = SETL("clz64_n", op_ADD_28);

	// clz64_x = (clz64_x << 0x10);
	RzILOpPure *op_SHIFTL_31 = SHIFTL0(VARL("clz64_x"), SN(32, 16));
	RzILOpEffect *op_ASSIGN_LEFT_32 = SETL("clz64_x", op_SHIFTL_31);

	// seq(clz64_n = clz64_n + ((ut64) 0x10); clz64_x = (clz64_x << 0x1 ...;
	RzILOpEffect *seq_then_33 = SEQN(2, op_ASSIGN_ADD_29, op_ASSIGN_LEFT_32);

	// if ((clz64_x <= 0xffffffffffff)) {seq(clz64_n = clz64_n + ((ut64) 0x10); clz64_x = (clz64_x << 0x1 ...} else {{}};
	RzILOpPure *op_LE_25 = ULE(VARL("clz64_x"), UN(64, 0xffffffffffff));
	RzILOpEffect *branch_34 = BRANCH(op_LE_25, seq_then_33, EMPTY());

	// clz64_n = clz64_n + ((ut64) 0x8);
	RzILOpPure *op_ADD_39 = ADD(VARL("clz64_n"), CAST(64, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_ADD_40 = SETL("clz64_n", op_ADD_39);

	// clz64_x = (clz64_x << 0x8);
	RzILOpPure *op_SHIFTL_42 = SHIFTL0(VARL("clz64_x"), SN(32, 8));
	RzILOpEffect *op_ASSIGN_LEFT_43 = SETL("clz64_x", op_SHIFTL_42);

	// seq(clz64_n = clz64_n + ((ut64) 0x8); clz64_x = (clz64_x << 0x8));
	RzILOpEffect *seq_then_44 = SEQN(2, op_ASSIGN_ADD_40, op_ASSIGN_LEFT_43);

	// if ((clz64_x <= 0xffffffffffffff)) {seq(clz64_n = clz64_n + ((ut64) 0x8); clz64_x = (clz64_x << 0x8))} else {{}};
	RzILOpPure *op_LE_36 = ULE(VARL("clz64_x"), UN(64, 0xffffffffffffff));
	RzILOpEffect *branch_45 = BRANCH(op_LE_36, seq_then_44, EMPTY());

	// clz64_n = clz64_n + ((ut64) 0x4);
	RzILOpPure *op_ADD_50 = ADD(VARL("clz64_n"), CAST(64, IL_FALSE, SN(32, 4)));
	RzILOpEffect *op_ASSIGN_ADD_51 = SETL("clz64_n", op_ADD_50);

	// clz64_x = (clz64_x << 0x4);
	RzILOpPure *op_SHIFTL_53 = SHIFTL0(VARL("clz64_x"), SN(32, 4));
	RzILOpEffect *op_ASSIGN_LEFT_54 = SETL("clz64_x", op_SHIFTL_53);

	// seq(clz64_n = clz64_n + ((ut64) 0x4); clz64_x = (clz64_x << 0x4));
	RzILOpEffect *seq_then_55 = SEQN(2, op_ASSIGN_ADD_51, op_ASSIGN_LEFT_54);

	// if ((clz64_x <= 0xfffffffffffffff)) {seq(clz64_n = clz64_n + ((ut64) 0x4); clz64_x = (clz64_x << 0x4))} else {{}};
	RzILOpPure *op_LE_47 = ULE(VARL("clz64_x"), UN(64, 0xfffffffffffffff));
	RzILOpEffect *branch_56 = BRANCH(op_LE_47, seq_then_55, EMPTY());

	// clz64_n = clz64_n + ((ut64) 0x2);
	RzILOpPure *op_ADD_61 = ADD(VARL("clz64_n"), CAST(64, IL_FALSE, SN(32, 2)));
	RzILOpEffect *op_ASSIGN_ADD_62 = SETL("clz64_n", op_ADD_61);

	// clz64_x = (clz64_x << 0x2);
	RzILOpPure *op_SHIFTL_64 = SHIFTL0(VARL("clz64_x"), SN(32, 2));
	RzILOpEffect *op_ASSIGN_LEFT_65 = SETL("clz64_x", op_SHIFTL_64);

	// seq(clz64_n = clz64_n + ((ut64) 0x2); clz64_x = (clz64_x << 0x2));
	RzILOpEffect *seq_then_66 = SEQN(2, op_ASSIGN_ADD_62, op_ASSIGN_LEFT_65);

	// if ((clz64_x <= 0x3fffffffffffffff)) {seq(clz64_n = clz64_n + ((ut64) 0x2); clz64_x = (clz64_x << 0x2))} else {{}};
	RzILOpPure *op_LE_58 = ULE(VARL("clz64_x"), UN(64, 0x3fffffffffffffff));
	RzILOpEffect *branch_67 = BRANCH(op_LE_58, seq_then_66, EMPTY());

	// HYB(++clz64_n);
	RzILOpEffect *op_INC_70 = SETL("clz64_n", INC(VARL("clz64_n"), 64));

	// h_tmp0 = HYB(++clz64_n);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_72 = SETL("h_tmp0", VARL("clz64_n"));

	// seq(h_tmp0 = HYB(++clz64_n); HYB(++clz64_n));
	RzILOpEffect *seq_73 = SEQN(2, op_ASSIGN_hybrid_tmp_72, op_INC_70);

	// seq(h_tmp0; {});
	RzILOpEffect *seq_then_74 = EMPTY();

	// seq(seq(h_tmp0 = HYB(++clz64_n); HYB(++clz64_n)); seq(h_tmp0; {} ...;
	RzILOpEffect *seq_75 = SEQN(2, seq_73, seq_then_74);

	// if ((clz64_x <= 0x7fffffffffffffff)) {seq(seq(h_tmp0 = HYB(++clz64_n); HYB(++clz64_n)); seq(h_tmp0; {} ...} else {{}};
	RzILOpPure *op_LE_69 = ULE(VARL("clz64_x"), UN(64, 0x7fffffffffffffff));
	RzILOpEffect *branch_76 = BRANCH(op_LE_69, seq_75, EMPTY());

	// ret_val_ut64 = clz64_n;
	RzILOpEffect *set_return_val_77 = SETL("ret_val", VARL("clz64_n"));

	// seq(ret_val_ut64 = ((ut64) 0x40));
	RzILOpEffect *seq_then_78 = set_return_val_8;

	// seq(clz64_n = ((ut64) 0x0); if ((clz64_x <= 0xffffffff)) {seq(cl ...;
	RzILOpEffect *seq_else_79 = SEQN(8, op_ASSIGN_11, branch_23, branch_34, branch_45, branch_56, branch_67, branch_76, set_return_val_77);

	// if ((clz64_x == ((ut64) 0x0))) {seq(ret_val_ut64 = ((ut64) 0x40))} else {seq(clz64_n = ((ut64) 0x0); if ((clz64_x <= 0xffffffff)) {seq(cl ...};
	RzILOpPure *op_EQ_4 = EQ(VARL("clz64_x"), CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpEffect *branch_80 = BRANCH(op_EQ_4, seq_then_78, seq_else_79);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_1, branch_80);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_clo32(RZ_BORROW RzILOpPure *x) {

	// READ

	// clz32((~x));
	RzILOpPure *op_NOT_0 = LOGNOT(x);
	RzILOpEffect *clz32_call_1 = hex_clz32(op_NOT_0);

	// h_tmp0 = clz32((~x));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_3 = SETL("h_tmp0", UNSIGNED(32, VARL("ret_val")));

	// seq(clz32((~x)); h_tmp0 = clz32((~x)));
	RzILOpEffect *seq_4 = SEQN(2, clz32_call_1, op_ASSIGN_hybrid_tmp_3);

	// ret_val_ut32 = ((ut64) h_tmp0);
	RzILOpEffect *set_return_val_7 = SETL("ret_val", CAST(64, IL_FALSE, VARL("h_tmp0")));

	RzILOpEffect *instruction_sequence = SEQN(2, seq_4, set_return_val_7);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_clo64(RZ_BORROW RzILOpPure *x) {

	// READ

	// clz64((~x));
	RzILOpPure *op_NOT_0 = LOGNOT(x);
	RzILOpEffect *clz64_call_1 = hex_clz64(op_NOT_0);

	// h_tmp0 = clz64((~x));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_3 = SETL("h_tmp0", UNSIGNED(64, VARL("ret_val")));

	// seq(clz64((~x)); h_tmp0 = clz64((~x)));
	RzILOpEffect *seq_4 = SEQN(2, clz64_call_1, op_ASSIGN_hybrid_tmp_3);

	// ret_val_ut64 = h_tmp0;
	RzILOpEffect *set_return_val_6 = SETL("ret_val", VARL("h_tmp0"));

	RzILOpEffect *instruction_sequence = SEQN(2, seq_4, set_return_val_6);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_revbit16(RZ_BORROW RzILOpPure *t) {

	// READ
	// Declare: ut16 revbit16_x;

	// revbit16_x = bswap16(t);
	RzILOpEffect *op_ASSIGN_2 = SETL("revbit16_x", BSWAP16(t));

	// revbit16_x = ((ut16) (((st32) ((ut16) ((((st32) revbit16_x) & 0xf0f0) >> 0x4))) | ((st32) ((ut16) ((((st32) revbit16_x) & 0xf0f) << 0x4)))));
	RzILOpPure *op_AND_5 = LOGAND(CAST(32, IL_FALSE, VARL("revbit16_x")), SN(32, 0xf0f0));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(op_AND_5, SN(32, 4));
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, IL_FALSE, VARL("revbit16_x")), SN(32, 0xf0f));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(op_AND_11, SN(32, 4));
	RzILOpPure *op_OR_17 = LOGOR(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_RSHIFT_7)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_LSHIFT_13)));
	RzILOpEffect *op_ASSIGN_19 = SETL("revbit16_x", CAST(16, IL_FALSE, op_OR_17));

	// revbit16_x = ((ut16) (((((st32) ((ut16) ((((st32) revbit16_x) & 0x8888) >> 0x3))) | ((st32) ((ut16) ((((st32) revbit16_x) & 0x4444) >> 0x1)))) | ((st32) ((ut16) ((((st32) revbit16_x) & 0x2222) << 0x1)))) | ((st32) ((ut16) ((((st32) revbit16_x) & 0x1111) << 0x3)))));
	RzILOpPure *op_AND_22 = LOGAND(CAST(32, IL_FALSE, VARL("revbit16_x")), SN(32, 0x8888));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(op_AND_22, SN(32, 3));
	RzILOpPure *op_AND_28 = LOGAND(CAST(32, IL_FALSE, VARL("revbit16_x")), SN(32, 0x4444));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(op_AND_28, SN(32, 1));
	RzILOpPure *op_OR_34 = LOGOR(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_RSHIFT_24)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_RSHIFT_30)));
	RzILOpPure *op_AND_37 = LOGAND(CAST(32, IL_FALSE, VARL("revbit16_x")), SN(32, 0x2222));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(op_AND_37, SN(32, 1));
	RzILOpPure *op_OR_42 = LOGOR(op_OR_34, CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_LSHIFT_39)));
	RzILOpPure *op_AND_45 = LOGAND(CAST(32, IL_FALSE, VARL("revbit16_x")), SN(32, 0x1111));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(op_AND_45, SN(32, 3));
	RzILOpPure *op_OR_50 = LOGOR(op_OR_42, CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_LSHIFT_47)));
	RzILOpEffect *op_ASSIGN_52 = SETL("revbit16_x", CAST(16, IL_FALSE, op_OR_50));

	// ret_val_ut16 = ((ut64) revbit16_x);
	RzILOpEffect *set_return_val_55 = SETL("ret_val", CAST(64, IL_FALSE, VARL("revbit16_x")));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_2, op_ASSIGN_19, op_ASSIGN_52, set_return_val_55);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_revbit32(RZ_BORROW RzILOpPure *t) {

	// READ
	// Declare: ut32 revbit32_x;

	// revbit32_x = bswap32(t);
	RzILOpEffect *op_ASSIGN_2 = SETL("revbit32_x", BSWAP32(t));

	// revbit32_x = (((revbit32_x & 0xf0f0f0f0) >> 0x4) | ((revbit32_x & 0xf0f0f0f) << 0x4));
	RzILOpPure *op_AND_4 = LOGAND(VARL("revbit32_x"), UN(32, 0xf0f0f0f0));
	RzILOpPure *op_RSHIFT_6 = SHIFTR0(op_AND_4, SN(32, 4));
	RzILOpPure *op_AND_8 = LOGAND(VARL("revbit32_x"), UN(32, 0xf0f0f0f));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(op_AND_8, SN(32, 4));
	RzILOpPure *op_OR_11 = LOGOR(op_RSHIFT_6, op_LSHIFT_10);
	RzILOpEffect *op_ASSIGN_12 = SETL("revbit32_x", op_OR_11);

	// revbit32_x = (((((revbit32_x & 0x88888888) >> 0x3) | ((revbit32_x & 0x44444444) >> 0x1)) | ((revbit32_x & 0x22222222) << 0x1)) | ((revbit32_x & 0x11111111) << 0x3));
	RzILOpPure *op_AND_14 = LOGAND(VARL("revbit32_x"), UN(32, 0x88888888));
	RzILOpPure *op_RSHIFT_16 = SHIFTR0(op_AND_14, SN(32, 3));
	RzILOpPure *op_AND_18 = LOGAND(VARL("revbit32_x"), UN(32, 0x44444444));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(op_AND_18, SN(32, 1));
	RzILOpPure *op_OR_21 = LOGOR(op_RSHIFT_16, op_RSHIFT_20);
	RzILOpPure *op_AND_23 = LOGAND(VARL("revbit32_x"), UN(32, 0x22222222));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(op_AND_23, SN(32, 1));
	RzILOpPure *op_OR_26 = LOGOR(op_OR_21, op_LSHIFT_25);
	RzILOpPure *op_AND_28 = LOGAND(VARL("revbit32_x"), UN(32, 0x11111111));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(op_AND_28, SN(32, 3));
	RzILOpPure *op_OR_31 = LOGOR(op_OR_26, op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_32 = SETL("revbit32_x", op_OR_31);

	// ret_val_ut32 = ((ut64) revbit32_x);
	RzILOpEffect *set_return_val_35 = SETL("ret_val", CAST(64, IL_FALSE, VARL("revbit32_x")));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_2, op_ASSIGN_12, op_ASSIGN_32, set_return_val_35);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_revbit64(RZ_BORROW RzILOpPure *t) {

	// READ
	// Declare: ut64 revbit64_x;

	// revbit64_x = bswap64(t);
	RzILOpEffect *op_ASSIGN_2 = SETL("revbit64_x", BSWAP64(t));

	// revbit64_x = (((revbit64_x & 0xf0f0f0f0f0f0f0f0) >> 0x4) | ((revbit64_x & 0xf0f0f0f0f0f0f0f) << 0x4));
	RzILOpPure *op_AND_4 = LOGAND(VARL("revbit64_x"), UN(64, 0xf0f0f0f0f0f0f0f0));
	RzILOpPure *op_RSHIFT_6 = SHIFTR0(op_AND_4, SN(32, 4));
	RzILOpPure *op_AND_8 = LOGAND(VARL("revbit64_x"), UN(64, 0xf0f0f0f0f0f0f0f));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(op_AND_8, SN(32, 4));
	RzILOpPure *op_OR_11 = LOGOR(op_RSHIFT_6, op_LSHIFT_10);
	RzILOpEffect *op_ASSIGN_12 = SETL("revbit64_x", op_OR_11);

	// revbit64_x = (((((revbit64_x & 0x8888888888888888) >> 0x3) | ((revbit64_x & 0x4444444444444444) >> 0x1)) | ((revbit64_x & 0x2222222222222222) << 0x1)) | ((revbit64_x & 0x1111111111111111) << 0x3));
	RzILOpPure *op_AND_14 = LOGAND(VARL("revbit64_x"), UN(64, 0x8888888888888888));
	RzILOpPure *op_RSHIFT_16 = SHIFTR0(op_AND_14, SN(32, 3));
	RzILOpPure *op_AND_18 = LOGAND(VARL("revbit64_x"), UN(64, 0x4444444444444444));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(op_AND_18, SN(32, 1));
	RzILOpPure *op_OR_21 = LOGOR(op_RSHIFT_16, op_RSHIFT_20);
	RzILOpPure *op_AND_23 = LOGAND(VARL("revbit64_x"), UN(64, 0x2222222222222222));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(op_AND_23, SN(32, 1));
	RzILOpPure *op_OR_26 = LOGOR(op_OR_21, op_LSHIFT_25);
	RzILOpPure *op_AND_28 = LOGAND(VARL("revbit64_x"), UN(64, 0x1111111111111111));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(op_AND_28, SN(32, 3));
	RzILOpPure *op_OR_31 = LOGOR(op_OR_26, op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_32 = SETL("revbit64_x", op_OR_31);

	// ret_val_ut64 = revbit64_x;
	RzILOpEffect *set_return_val_34 = SETL("ret_val", VARL("revbit64_x"));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_2, op_ASSIGN_12, op_ASSIGN_32, set_return_val_34);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_fbrev(RZ_BORROW RzILOpPure *addr) {

	// READ

	// revbit16(((ut16) addr));
	RzILOpEffect *revbit16_call_3 = hex_revbit16(CAST(16, IL_FALSE, addr));

	// h_tmp0 = revbit16(((ut16) addr));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp0", UNSIGNED(16, VARL("ret_val")));

	// seq(revbit16(((ut16) addr)); h_tmp0 = revbit16(((ut16) addr)));
	RzILOpEffect *seq_6 = SEQN(2, revbit16_call_3, op_ASSIGN_hybrid_tmp_5);

	// ret_val_ut32 = ((ut64) deposit32(addr, 0x0, 0x10, ((ut32) h_tmp0)));
	RzILOpEffect *set_return_val_11 = SETL("ret_val", CAST(64, IL_FALSE, DEPOSIT32(DUP(addr), SN(32, 0), SN(32, 16), CAST(32, IL_FALSE, VARL("h_tmp0")))));

	RzILOpEffect *instruction_sequence = SEQN(2, seq_6, set_return_val_11);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_conv_round(RZ_BORROW RzILOpPure *a, RZ_BORROW RzILOpPure *n) {

	// READ
	// Declare: st64 conv_val;

	// conv_val = ((st64) a);
	RzILOpEffect *op_ASSIGN_4 = SETL("conv_val", CAST(64, MSB(a), DUP(a)));

	// conv_val = ((st64) a) + ((st64) (((ut32) ((0x1 << n) & a)) >> 0x1));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(SN(32, 1), n);
	RzILOpPure *op_AND_17 = LOGAND(op_LSHIFT_16, DUP(a));
	RzILOpPure *op_RSHIFT_20 = SHIFTR0(CAST(32, IL_FALSE, op_AND_17), SN(32, 1));
	RzILOpPure *op_ADD_22 = ADD(CAST(64, MSB(DUP(a)), DUP(a)), CAST(64, IL_FALSE, op_RSHIFT_20));
	RzILOpEffect *op_ASSIGN_23 = SETL("conv_val", op_ADD_22);

	// conv_val = ((st64) a) + ((st64) (0x1 << n - 0x1));
	RzILOpPure *op_SUB_27 = SUB(DUP(n), SN(32, 1));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(32, 1), op_SUB_27);
	RzILOpPure *op_ADD_30 = ADD(CAST(64, MSB(DUP(a)), DUP(a)), CAST(64, MSB(op_LSHIFT_28), DUP(op_LSHIFT_28)));
	RzILOpEffect *op_ASSIGN_31 = SETL("conv_val", op_ADD_30);

	// seq(conv_val = ((st64) a) + ((st64) (((ut32) ((0x1 << n) & a)) > ...;
	RzILOpEffect *seq_then_32 = op_ASSIGN_23;

	// seq(conv_val = ((st64) a) + ((st64) (0x1 << n - 0x1)));
	RzILOpEffect *seq_else_33 = op_ASSIGN_31;

	// if (((a & (0x1 << n - 0x1) - 0x1) == 0x0)) {seq(conv_val = ((st64) a) + ((st64) (((ut32) ((0x1 << n) & a)) > ...} else {seq(conv_val = ((st64) a) + ((st64) (0x1 << n - 0x1)))};
	RzILOpPure *op_SUB_7 = SUB(DUP(n), SN(32, 1));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(SN(32, 1), op_SUB_7);
	RzILOpPure *op_SUB_10 = SUB(op_LSHIFT_8, SN(32, 1));
	RzILOpPure *op_AND_11 = LOGAND(DUP(a), op_SUB_10);
	RzILOpPure *op_EQ_13 = EQ(op_AND_11, SN(32, 0));
	RzILOpEffect *branch_34 = BRANCH(op_EQ_13, seq_then_32, seq_else_33);

	// seq(conv_val = ((st64) a));
	RzILOpEffect *seq_then_35 = op_ASSIGN_4;

	// seq(if (((a & (0x1 << n - 0x1) - 0x1) == 0x0)) {seq(conv_val = ( ...;
	RzILOpEffect *seq_else_36 = branch_34;

	// if ((n == 0x0)) {seq(conv_val = ((st64) a))} else {seq(if (((a & (0x1 << n - 0x1) - 0x1) == 0x0)) {seq(conv_val = ( ...};
	RzILOpPure *op_EQ_2 = EQ(DUP(n), SN(32, 0));
	RzILOpEffect *branch_37 = BRANCH(op_EQ_2, seq_then_35, seq_else_36);

	// conv_val = (conv_val >> n);
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(VARL("conv_val"), DUP(n));
	RzILOpEffect *op_ASSIGN_39 = SETL("conv_val", op_RSHIFT_38);

	// ret_val_st32 = ((ut64) ((st32) conv_val));
	RzILOpEffect *set_return_val_43 = SETL("ret_val", CAST(64, IL_FALSE, CAST(32, MSB(VARL("conv_val")), VARL("conv_val"))));

	RzILOpEffect *instruction_sequence = SEQN(3, branch_37, op_ASSIGN_39, set_return_val_43);
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_set_usr_field(HexInsnPktBundle *bundle, HexRegField field, RZ_BORROW RzILOpPure *val) {
	HexPkt *pkt = bundle->pkt;

	// READ
	const HexOp usr_op = ALIAS2OP(HEX_REG_ALIAS_USR, false);

	// usr = ((ut32) (REGFIELD(HEX_RF_WIDTH, field) ? deposit64(((ut64) usr), ((st32) REGFIELD(HEX_RF_OFFSET, field)), ((st32) REGFIELD(HEX_RF_WIDTH, field)), ((ut64) val)) : ((ut64) usr)));
	RzILOpPure *cond_10 = ITE(NON_ZERO(HEX_REGFIELD(HEX_RF_WIDTH, field)), DEPOSIT64(CAST(64, IL_FALSE, READ_REG(pkt, &usr_op, true)), CAST(32, IL_FALSE, HEX_REGFIELD(HEX_RF_OFFSET, field)), CAST(32, IL_FALSE, HEX_REGFIELD(HEX_RF_WIDTH, field)), CAST(64, IL_FALSE, val)), CAST(64, IL_FALSE, READ_REG(pkt, &usr_op, true)));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, &usr_op, CAST(32, IL_FALSE, cond_10));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

RZ_OWN RzILOpEffect *hex_get_usr_field(HexInsnPktBundle *bundle, HexRegField field) {
	HexPkt *pkt = bundle->pkt;

	// READ
	const HexOp usr_op = ALIAS2OP(HEX_REG_ALIAS_USR, false);
	RzILOpPure *usr = READ_REG(pkt, &usr_op, false);

	// ret_val_ut32 = (REGFIELD(HEX_RF_WIDTH, field) ? extract64(((ut64) usr), ((st32) REGFIELD(HEX_RF_OFFSET, field)), ((st32) REGFIELD(HEX_RF_WIDTH, field))) : ((ut64) 0x0));
	RzILOpPure *cond_10 = ITE(NON_ZERO(HEX_REGFIELD(HEX_RF_WIDTH, field)), EXTRACT64(CAST(64, IL_FALSE, usr), CAST(32, IL_FALSE, HEX_REGFIELD(HEX_RF_OFFSET, field)), CAST(32, IL_FALSE, HEX_REGFIELD(HEX_RF_WIDTH, field))), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpEffect *set_return_val_12 = SETL("ret_val", cond_10);

	RzILOpEffect *instruction_sequence = set_return_val_12;
	return instruction_sequence;
}

/**
 * \brief Returns the value of an register field property.
 *
 * \param property The property to get the value for.
 * \param field The register field.
 * \return RzILOpPure The value as integer as U32 or U32_MAX on failure.
 */
RZ_IPI RZ_OWN RzILOpPure *hex_get_rf_property_val(const HexRegFieldProperty property, const HexRegField field) {
	RzILOpPure *r = NULL;
	switch (field) {
	default:
		RZ_LOG_WARN("Register field not implemented.\n");
		break;
	case HEX_REG_FIELD_USR_LPCFG:
		if (property == HEX_RF_WIDTH) {
			r = U32(2);
		} else if (property == HEX_RF_OFFSET) {
			r = U32(8);
		}
		break;
	case HEX_REG_FIELD_USR_OVF:
		if (property == HEX_RF_WIDTH) {
			r = U32(1);
		} else if (property == HEX_RF_OFFSET) {
			r = U32(0);
		}
		break;
	}
	return r;
}

/**
 * \brief Returns the next PC as pure.
 *
 * \param pkt The instruction packet.
 * \return RzILOpPure* The next PC as pure.
 */
RZ_IPI RZ_OWN RzILOpEffect *hex_get_npc(const HexPkt *pkt) {
	rz_return_val_if_fail(pkt, NULL);
	RzILOpPure *r;
	r = U64(pkt->pkt_addr + (rz_list_length(pkt->bin) * HEX_INSN_SIZE));
	return SETL("ret_val", r);
}

RZ_IPI RZ_OWN RzILOpEffect *hex_commit_packet(HexInsnPktBundle *bundle) {
	HexILExecData *stats = &bundle->pkt->il_op_stats;
	RzILOpEffect *commit_seq = EMPTY();
	for (ut8 i = 0; i <= HEX_REG_CTR_REGS_C31; ++i) {
		if (!(rz_bv_get(stats->ctr_written, i))) {
			continue;
		}
		const char *dest_reg = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, i, false, false, false);
		const char *src_reg = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, i, false, true, false);
		commit_seq = SEQ2(commit_seq, SETG(dest_reg, VARG(src_reg)));
	}

	for (ut8 i = 0; i <= HEX_REG_INT_REGS_R31; ++i) {
		if (!(rz_bv_get(stats->gpr_written, i))) {
			continue;
		}
		const char *dest_reg = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, i, false, false, false);
		const char *src_reg = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, i, false, true, false);
		commit_seq = SEQ2(commit_seq, SETG(dest_reg, VARG(src_reg)));
	}

	for (ut8 i = 0; i <= HEX_REG_PRED_REGS_P3; ++i) {
		if (!(rz_bv_get(stats->pred_written, i))) {
			continue;
		}
		const char *dest_reg = hex_get_reg_in_class(HEX_REG_CLASS_PRED_REGS, i, false, false, false);
		const char *src_reg = hex_get_reg_in_class(HEX_REG_CLASS_PRED_REGS, i, false, true, false);
		commit_seq = SEQ2(commit_seq, SETG(dest_reg, VARG(src_reg)));
	}

	hex_il_pkt_stats_reset(stats);
	return commit_seq;
}

RZ_IPI RZ_OWN RzILOpEffect *hex_il_op_jump_flag_init(HexInsnPktBundle *bundle) {
	return SEQ2(SETL("jump_flag", IL_FALSE), SETL("jump_target", U32(0xffffffff)));
}

RZ_IPI RZ_OWN RzILOpEffect *hex_il_op_next_pkt_jmp(HexInsnPktBundle *bundle) {
	return BRANCH(VARL("jump_flag"), JMP(VARL("jump_target")), JMP(U32(bundle->pkt->pkt_addr + (HEX_INSN_SIZE * rz_list_length(bundle->pkt->bin)))));
}

#include <rz_il/rz_il_opbuilder_end.h>
