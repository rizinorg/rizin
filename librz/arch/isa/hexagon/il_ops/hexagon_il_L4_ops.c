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

// memb(Rs+Ii) += Rt
RzILOpEffect *hex_il_op_l4_add_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = tmp + Rt;
	RzILOpPure *op_ADD_14 = ADD(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_ADD_15 = SETL("tmp", op_ADD_14);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_ADD_15, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memh(Rs+Ii) += Rt
RzILOpEffect *hex_il_op_l4_add_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = tmp + Rt;
	RzILOpPure *op_ADD_14 = ADD(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_ADD_15 = SETL("tmp", op_ADD_14);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_ADD_15, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memw(Rs+Ii) += Rt
RzILOpEffect *hex_il_op_l4_add_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// tmp = tmp + Rt;
	RzILOpPure *op_ADD_13 = ADD(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_ADD_14 = SETL("tmp", op_ADD_13);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_ADD_14, ms_cast_ut32_15_16);
	return instruction_sequence;
}

// memb(Rs+Ii) &= Rt
RzILOpEffect *hex_il_op_l4_and_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = (tmp & Rt);
	RzILOpPure *op_AND_14 = LOGAND(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_AND_15 = SETL("tmp", op_AND_14);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_AND_15, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memh(Rs+Ii) &= Rt
RzILOpEffect *hex_il_op_l4_and_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = (tmp & Rt);
	RzILOpPure *op_AND_14 = LOGAND(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_AND_15 = SETL("tmp", op_AND_14);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_AND_15, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memw(Rs+Ii) &= Rt
RzILOpEffect *hex_il_op_l4_and_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// tmp = (tmp & Rt);
	RzILOpPure *op_AND_13 = LOGAND(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_AND_14 = SETL("tmp", op_AND_13);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_AND_14, ms_cast_ut32_15_16);
	return instruction_sequence;
}

// memb(Rs+Ii) += II
RzILOpEffect *hex_il_op_l4_iadd_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_13 = SETL("U", U);

	// tmp = tmp + ((st32) U);
	RzILOpPure *op_ADD_16 = ADD(VARL("tmp"), CAST(32, IL_FALSE, VARL("U")));
	RzILOpEffect *op_ASSIGN_ADD_17 = SETL("tmp", op_ADD_16);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_13, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_ADD_17, ms_cast_ut8_18_19);
	return instruction_sequence;
}

// memh(Rs+Ii) += II
RzILOpEffect *hex_il_op_l4_iadd_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_13 = SETL("U", U);

	// tmp = tmp + ((st32) U);
	RzILOpPure *op_ADD_16 = ADD(VARL("tmp"), CAST(32, IL_FALSE, VARL("U")));
	RzILOpEffect *op_ASSIGN_ADD_17 = SETL("tmp", op_ADD_16);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_13, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_ADD_17, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memw(Rs+Ii) += II
RzILOpEffect *hex_il_op_l4_iadd_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// U = U;
	RzILOpEffect *imm_assign_12 = SETL("U", U);

	// tmp = tmp + ((st32) U);
	RzILOpPure *op_ADD_15 = ADD(VARL("tmp"), CAST(32, IL_FALSE, VARL("U")));
	RzILOpEffect *op_ASSIGN_ADD_16 = SETL("tmp", op_ADD_15);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_17_18 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_12, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_ADD_16, ms_cast_ut32_17_18);
	return instruction_sequence;
}

// memb(Rs+Ii) = clrbit(II)
RzILOpEffect *hex_il_op_l4_iand_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// tmp = (tmp & (~(0x1 << U)));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(SN(32, 1), VARL("U"));
	RzILOpPure *op_NOT_17 = LOGNOT(op_LSHIFT_16);
	RzILOpPure *op_AND_18 = LOGAND(VARL("tmp"), op_NOT_17);
	RzILOpEffect *op_ASSIGN_AND_19 = SETL("tmp", op_AND_18);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_20_21 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_14, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_AND_19, ms_cast_ut8_20_21);
	return instruction_sequence;
}

// memh(Rs+Ii) = clrbit(II)
RzILOpEffect *hex_il_op_l4_iand_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// tmp = (tmp & (~(0x1 << U)));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(SN(32, 1), VARL("U"));
	RzILOpPure *op_NOT_17 = LOGNOT(op_LSHIFT_16);
	RzILOpPure *op_AND_18 = LOGAND(VARL("tmp"), op_NOT_17);
	RzILOpEffect *op_ASSIGN_AND_19 = SETL("tmp", op_AND_18);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_14, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_AND_19, ms_cast_ut16_20_21);
	return instruction_sequence;
}

// memw(Rs+Ii) = clrbit(II)
RzILOpEffect *hex_il_op_l4_iand_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// U = U;
	RzILOpEffect *imm_assign_13 = SETL("U", U);

	// tmp = (tmp & (~(0x1 << U)));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(32, 1), VARL("U"));
	RzILOpPure *op_NOT_16 = LOGNOT(op_LSHIFT_15);
	RzILOpPure *op_AND_17 = LOGAND(VARL("tmp"), op_NOT_16);
	RzILOpEffect *op_ASSIGN_AND_18 = SETL("tmp", op_AND_17);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_19_20 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_13, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_AND_18, ms_cast_ut32_19_20);
	return instruction_sequence;
}

// memb(Rs+Ii) = setbit(II)
RzILOpEffect *hex_il_op_l4_ior_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// tmp = (tmp | (0x1 << U));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(SN(32, 1), VARL("U"));
	RzILOpPure *op_OR_17 = LOGOR(VARL("tmp"), op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_OR_18 = SETL("tmp", op_OR_17);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_19_20 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_14, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_OR_18, ms_cast_ut8_19_20);
	return instruction_sequence;
}

// memh(Rs+Ii) = setbit(II)
RzILOpEffect *hex_il_op_l4_ior_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_14 = SETL("U", U);

	// tmp = (tmp | (0x1 << U));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(SN(32, 1), VARL("U"));
	RzILOpPure *op_OR_17 = LOGOR(VARL("tmp"), op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_OR_18 = SETL("tmp", op_OR_17);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_19_20 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_14, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_OR_18, ms_cast_ut16_19_20);
	return instruction_sequence;
}

// memw(Rs+Ii) = setbit(II)
RzILOpEffect *hex_il_op_l4_ior_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// U = U;
	RzILOpEffect *imm_assign_13 = SETL("U", U);

	// tmp = (tmp | (0x1 << U));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(32, 1), VARL("U"));
	RzILOpPure *op_OR_16 = LOGOR(VARL("tmp"), op_LSHIFT_15);
	RzILOpEffect *op_ASSIGN_OR_17 = SETL("tmp", op_OR_16);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_18_19 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_13, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_OR_17, ms_cast_ut32_18_19);
	return instruction_sequence;
}

// memb(Rs+Ii) -= II
RzILOpEffect *hex_il_op_l4_isub_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_13 = SETL("U", U);

	// tmp = tmp - ((st32) U);
	RzILOpPure *op_SUB_16 = SUB(VARL("tmp"), CAST(32, IL_FALSE, VARL("U")));
	RzILOpEffect *op_ASSIGN_SUB_17 = SETL("tmp", op_SUB_16);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_13, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_SUB_17, ms_cast_ut8_18_19);
	return instruction_sequence;
}

// memh(Rs+Ii) -= II
RzILOpEffect *hex_il_op_l4_isub_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// U = U;
	RzILOpEffect *imm_assign_13 = SETL("U", U);

	// tmp = tmp - ((st32) U);
	RzILOpPure *op_SUB_16 = SUB(VARL("tmp"), CAST(32, IL_FALSE, VARL("U")));
	RzILOpEffect *op_ASSIGN_SUB_17 = SETL("tmp", op_SUB_16);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_13, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_SUB_17, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memw(Rs+Ii) -= II
RzILOpEffect *hex_il_op_l4_isub_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// U = U;
	RzILOpEffect *imm_assign_12 = SETL("U", U);

	// tmp = tmp - ((st32) U);
	RzILOpPure *op_SUB_15 = SUB(VARL("tmp"), CAST(32, IL_FALSE, VARL("U")));
	RzILOpEffect *op_ASSIGN_SUB_16 = SETL("tmp", op_SUB_15);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_17_18 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(6, imm_assign_0, imm_assign_12, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_SUB_16, ms_cast_ut32_17_18);
	return instruction_sequence;
}

// Ryy = memb_fifo(Re=II)
RzILOpEffect *hex_il_op_l4_loadalignb_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_6 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_6)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_13 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_16 = LOGOR(op_RSHIFT_13, op_LSHIFT_15);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_16));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_18, op_ASSIGN_21);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadalignb_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_12 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_12)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_19 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_22 = LOGOR(op_RSHIFT_19, op_LSHIFT_21);
	RzILOpEffect *op_ASSIGN_24 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_22));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15, op_ASSIGN_24);
	return instruction_sequence;
}

// Ryy = memh_fifo(Re=II)
RzILOpEffect *hex_il_op_l4_loadalignh_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_6 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_6)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_13 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_16 = LOGOR(op_RSHIFT_13, op_LSHIFT_15);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_16));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_18, op_ASSIGN_21);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadalignh_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_12 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_12)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_19 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_21 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_22 = LOGOR(op_RSHIFT_19, op_LSHIFT_21);
	RzILOpEffect *op_ASSIGN_24 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_22));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15, op_ASSIGN_24);
	return instruction_sequence;
}

// Rd = membh(Re=II)
RzILOpEffect *hex_il_op_l4_loadbsw2_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_7 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_7));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_11 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_14 = SETL("i", INC(VARL("i"), 32));

	// h_tmp224 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_16 = SETL("h_tmp224", VARL("i"));

	// seq(h_tmp224 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_17 = SEQN(2, op_ASSIGN_hybrid_tmp_16, op_INC_14);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(SN(64, 0xffff), op_MUL_21);
	RzILOpPure *op_NOT_23 = LOGNOT(op_LSHIFT_22);
	RzILOpPure *op_AND_25 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_23);
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_28 = SHIFTR0(VARL("tmpV"), op_MUL_27);
	RzILOpPure *op_AND_31 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_28), SN(32, 0xff));
	RzILOpPure *op_AND_35 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_31), DUP(op_AND_31))), CAST(8, MSB(DUP(op_AND_31)), DUP(op_AND_31))), SN(32, 0xffff));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(CAST(64, IL_FALSE, op_AND_35), op_MUL_38);
	RzILOpPure *op_OR_41 = LOGOR(CAST(64, IL_FALSE, op_AND_25), op_LSHIFT_39);
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_41));

	// seq(h_tmp224; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_45 = op_ASSIGN_43;

	// seq(seq(h_tmp224; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_46 = SEQN(2, seq_45, seq_17);

	// while ((i < 0x2)) { seq(seq(h_tmp224; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_13 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_47 = REPEAT(op_LT_13, seq_46);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp224; Rd = ((st32)  ...;
	RzILOpEffect *seq_48 = SEQN(2, op_ASSIGN_11, for_47);

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_52 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, seq_48, op_ASSIGN_52);
	return instruction_sequence;
}

// Rd = membh(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadbsw2_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_13 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_13));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_17 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_20 = SETL("i", INC(VARL("i"), 32));

	// h_tmp225 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_22 = SETL("h_tmp225", VARL("i"));

	// seq(h_tmp225 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_23 = SEQN(2, op_ASSIGN_hybrid_tmp_22, op_INC_20);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(64, 0xffff), op_MUL_27);
	RzILOpPure *op_NOT_29 = LOGNOT(op_LSHIFT_28);
	RzILOpPure *op_AND_31 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_29);
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_34 = SHIFTR0(VARL("tmpV"), op_MUL_33);
	RzILOpPure *op_AND_37 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_34), SN(32, 0xff));
	RzILOpPure *op_AND_41 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_37), DUP(op_AND_37))), CAST(8, MSB(DUP(op_AND_37)), DUP(op_AND_37))), SN(32, 0xffff));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, op_AND_41), op_MUL_44);
	RzILOpPure *op_OR_47 = LOGOR(CAST(64, IL_FALSE, op_AND_31), op_LSHIFT_45);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_47));

	// seq(h_tmp225; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_51 = op_ASSIGN_49;

	// seq(seq(h_tmp225; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_51, seq_23);

	// while ((i < 0x2)) { seq(seq(h_tmp225; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_19 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_53 = REPEAT(op_LT_19, seq_52);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp225; Rd = ((st32)  ...;
	RzILOpEffect *seq_54 = SEQN(2, op_ASSIGN_17, for_53);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15, seq_54);
	return instruction_sequence;
}

// Rdd = membh(Re=II)
RzILOpEffect *hex_il_op_l4_loadbsw4_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_7 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_7));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_11 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_14 = SETL("i", INC(VARL("i"), 32));

	// h_tmp226 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_16 = SETL("h_tmp226", VARL("i"));

	// seq(h_tmp226 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_17 = SEQN(2, op_ASSIGN_hybrid_tmp_16, op_INC_14);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(SN(64, 0xffff), op_MUL_21);
	RzILOpPure *op_NOT_23 = LOGNOT(op_LSHIFT_22);
	RzILOpPure *op_AND_24 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_23);
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTR0(VARL("tmpV"), op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_34 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_30)), CAST(8, IL_FALSE, DUP(op_AND_30))), SN(32, 0xffff));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(CAST(64, IL_FALSE, op_AND_34), op_MUL_37);
	RzILOpPure *op_OR_40 = LOGOR(CAST(64, IL_FALSE, op_AND_24), op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_40));

	// seq(h_tmp226; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_44 = op_ASSIGN_42;

	// seq(seq(h_tmp226; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_45 = SEQN(2, seq_44, seq_17);

	// while ((i < 0x4)) { seq(seq(h_tmp226; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_13 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_46 = REPEAT(op_LT_13, seq_45);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp226; Rdd = ((st64) ...;
	RzILOpEffect *seq_47 = SEQN(2, op_ASSIGN_11, for_46);

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_50 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, seq_47, op_ASSIGN_50);
	return instruction_sequence;
}

// Rdd = membh(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadbsw4_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_13 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_13));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_17 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_20 = SETL("i", INC(VARL("i"), 32));

	// h_tmp227 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_22 = SETL("h_tmp227", VARL("i"));

	// seq(h_tmp227 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_23 = SEQN(2, op_ASSIGN_hybrid_tmp_22, op_INC_20);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(64, 0xffff), op_MUL_27);
	RzILOpPure *op_NOT_29 = LOGNOT(op_LSHIFT_28);
	RzILOpPure *op_AND_30 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_29);
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_33 = SHIFTR0(VARL("tmpV"), op_MUL_32);
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_33, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_36)), CAST(8, IL_FALSE, DUP(op_AND_36))), SN(32, 0xffff));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), op_MUL_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, op_AND_30), op_LSHIFT_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_46));

	// seq(h_tmp227; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_50 = op_ASSIGN_48;

	// seq(seq(h_tmp227; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_50, seq_23);

	// while ((i < 0x4)) { seq(seq(h_tmp227; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_19 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_52 = REPEAT(op_LT_19, seq_51);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp227; Rdd = ((st64) ...;
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_17, for_52);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15, seq_53);
	return instruction_sequence;
}

// Rd = memubh(Re=II)
RzILOpEffect *hex_il_op_l4_loadbzw2_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_7 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_7));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_11 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_14 = SETL("i", INC(VARL("i"), 32));

	// h_tmp228 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_16 = SETL("h_tmp228", VARL("i"));

	// seq(h_tmp228 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_17 = SEQN(2, op_ASSIGN_hybrid_tmp_16, op_INC_14);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(SN(64, 0xffff), op_MUL_21);
	RzILOpPure *op_NOT_23 = LOGNOT(op_LSHIFT_22);
	RzILOpPure *op_AND_25 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_23);
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_28 = SHIFTR0(VARL("tmpV"), op_MUL_27);
	RzILOpPure *op_AND_31 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_28), SN(32, 0xff));
	RzILOpPure *op_AND_35 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_31)), SN(32, 0xffff));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_39 = SHIFTL0(CAST(64, IL_FALSE, op_AND_35), op_MUL_38);
	RzILOpPure *op_OR_41 = LOGOR(CAST(64, IL_FALSE, op_AND_25), op_LSHIFT_39);
	RzILOpEffect *op_ASSIGN_43 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_41));

	// seq(h_tmp228; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_45 = op_ASSIGN_43;

	// seq(seq(h_tmp228; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_46 = SEQN(2, seq_45, seq_17);

	// while ((i < 0x2)) { seq(seq(h_tmp228; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_13 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_47 = REPEAT(op_LT_13, seq_46);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp228; Rd = ((st32)  ...;
	RzILOpEffect *seq_48 = SEQN(2, op_ASSIGN_11, for_47);

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, seq_48, op_ASSIGN_51);
	return instruction_sequence;
}

// Rd = memubh(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadbzw2_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_13 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_13));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_17 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_20 = SETL("i", INC(VARL("i"), 32));

	// h_tmp229 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_22 = SETL("h_tmp229", VARL("i"));

	// seq(h_tmp229 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_23 = SEQN(2, op_ASSIGN_hybrid_tmp_22, op_INC_20);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(64, 0xffff), op_MUL_27);
	RzILOpPure *op_NOT_29 = LOGNOT(op_LSHIFT_28);
	RzILOpPure *op_AND_31 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_29);
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_34 = SHIFTR0(VARL("tmpV"), op_MUL_33);
	RzILOpPure *op_AND_37 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_34), SN(32, 0xff));
	RzILOpPure *op_AND_41 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_37)), SN(32, 0xffff));
	RzILOpPure *op_MUL_44 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, op_AND_41), op_MUL_44);
	RzILOpPure *op_OR_47 = LOGOR(CAST(64, IL_FALSE, op_AND_31), op_LSHIFT_45);
	RzILOpEffect *op_ASSIGN_49 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_47));

	// seq(h_tmp229; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_51 = op_ASSIGN_49;

	// seq(seq(h_tmp229; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_52 = SEQN(2, seq_51, seq_23);

	// while ((i < 0x2)) { seq(seq(h_tmp229; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_19 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_53 = REPEAT(op_LT_19, seq_52);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp229; Rd = ((st32)  ...;
	RzILOpEffect *seq_54 = SEQN(2, op_ASSIGN_17, for_53);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15, seq_54);
	return instruction_sequence;
}

// Rdd = memubh(Re=II)
RzILOpEffect *hex_il_op_l4_loadbzw4_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_7 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_7));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_11 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_14 = SETL("i", INC(VARL("i"), 32));

	// h_tmp230 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_16 = SETL("h_tmp230", VARL("i"));

	// seq(h_tmp230 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_17 = SEQN(2, op_ASSIGN_hybrid_tmp_16, op_INC_14);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_21 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_22 = SHIFTL0(SN(64, 0xffff), op_MUL_21);
	RzILOpPure *op_NOT_23 = LOGNOT(op_LSHIFT_22);
	RzILOpPure *op_AND_24 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_23);
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTR0(VARL("tmpV"), op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_34 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_30)), SN(32, 0xffff));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_38 = SHIFTL0(CAST(64, IL_FALSE, op_AND_34), op_MUL_37);
	RzILOpPure *op_OR_40 = LOGOR(CAST(64, IL_FALSE, op_AND_24), op_LSHIFT_38);
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_40));

	// seq(h_tmp230; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_44 = op_ASSIGN_42;

	// seq(seq(h_tmp230; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_45 = SEQN(2, seq_44, seq_17);

	// while ((i < 0x4)) { seq(seq(h_tmp230; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_13 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_46 = REPEAT(op_LT_13, seq_45);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp230; Rdd = ((st64) ...;
	RzILOpEffect *seq_47 = SEQN(2, op_ASSIGN_11, for_46);

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_50 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, seq_47, op_ASSIGN_50);
	return instruction_sequence;
}

// Rdd = memubh(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadbzw4_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_13 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_13));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_17 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_20 = SETL("i", INC(VARL("i"), 32));

	// h_tmp231 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_22 = SETL("h_tmp231", VARL("i"));

	// seq(h_tmp231 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_23 = SEQN(2, op_ASSIGN_hybrid_tmp_22, op_INC_20);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_27 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_28 = SHIFTL0(SN(64, 0xffff), op_MUL_27);
	RzILOpPure *op_NOT_29 = LOGNOT(op_LSHIFT_28);
	RzILOpPure *op_AND_30 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_29);
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_33 = SHIFTR0(VARL("tmpV"), op_MUL_32);
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_33, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_36)), SN(32, 0xffff));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), op_MUL_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, op_AND_30), op_LSHIFT_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_46));

	// seq(h_tmp231; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_50 = op_ASSIGN_48;

	// seq(seq(h_tmp231; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_50, seq_23);

	// while ((i < 0x4)) { seq(seq(h_tmp231; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_19 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_52 = REPEAT(op_LT_19, seq_51);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp231; Rdd = ((st64) ...;
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_17, for_52);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15, seq_53);
	return instruction_sequence;
}

// Rdd = memd_aq(Rs)
RzILOpEffect *hex_il_op_l4_loadd_aq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_6 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_6)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_3, op_ASSIGN_9);
	return instruction_sequence;
}

// Rdd = memd_locked(Rs)
RzILOpEffect *hex_il_op_l4_loadd_locked(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = memb(Re=II)
RzILOpEffect *hex_il_op_l4_loadrb_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_6 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_6), DUP(ml_EA_6))), CAST(8, MSB(DUP(ml_EA_6)), DUP(ml_EA_6))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memb(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_loadrb_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(8, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memb(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadrb_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_12 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_12), DUP(ml_EA_12))), CAST(8, MSB(DUP(ml_EA_12)), DUP(ml_EA_12))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15);
	return instruction_sequence;
}

// Rdd = memd(Re=II)
RzILOpEffect *hex_il_op_l4_loadrd_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_6 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_6)));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_12);
	return instruction_sequence;
}

// Rdd = memd(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_loadrd_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rdd = memd(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadrd_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_12 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_12)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15);
	return instruction_sequence;
}

// Rd = memh(Re=II)
RzILOpEffect *hex_il_op_l4_loadrh_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_6 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_6), DUP(ml_EA_6))), CAST(16, MSB(DUP(ml_EA_6)), DUP(ml_EA_6))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_loadrh_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(16, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memh(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadrh_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_12 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_12), DUP(ml_EA_12))), CAST(16, MSB(DUP(ml_EA_12)), DUP(ml_EA_12))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15);
	return instruction_sequence;
}

// Rd = memw(Re=II)
RzILOpEffect *hex_il_op_l4_loadri_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_6 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_6)));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memw(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_loadri_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_11 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memw(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadri_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_12 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_12)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15);
	return instruction_sequence;
}

// Rd = memub(Re=II)
RzILOpEffect *hex_il_op_l4_loadrub_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_6 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_6)));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memub(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_loadrub_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memub(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadrub_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_12 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_12)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15);
	return instruction_sequence;
}

// Rd = memuh(Re=II)
RzILOpEffect *hex_il_op_l4_loadruh_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_6 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_6)));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, op_ASSIGN_9, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memuh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_loadruh_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memuh(Rt<<Ii+II)
RzILOpEffect *hex_il_op_l4_loadruh_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Rt << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_12 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_12)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, op_ASSIGN_15);
	return instruction_sequence;
}

// Rd = memw_phys(Rs,Rt)
RzILOpEffect *hex_il_op_l4_loadw_phys(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// memb(Rs+Ii) |= Rt
RzILOpEffect *hex_il_op_l4_or_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = (tmp | Rt);
	RzILOpPure *op_OR_14 = LOGOR(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_OR_15 = SETL("tmp", op_OR_14);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_OR_15, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memh(Rs+Ii) |= Rt
RzILOpEffect *hex_il_op_l4_or_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = (tmp | Rt);
	RzILOpPure *op_OR_14 = LOGOR(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_OR_15 = SETL("tmp", op_OR_14);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_OR_15, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memw(Rs+Ii) |= Rt
RzILOpEffect *hex_il_op_l4_or_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// tmp = (tmp | Rt);
	RzILOpPure *op_OR_13 = LOGOR(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_OR_14 = SETL("tmp", op_OR_13);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_OR_14, ms_cast_ut32_15_16);
	return instruction_sequence;
}

// if (!Pt) Rd = memb(Ii)
RzILOpEffect *hex_il_op_l4_ploadrbf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(8, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv) Rd = memb(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrbf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(8, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memb(Ii)
RzILOpEffect *hex_il_op_l4_ploadrbfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(8, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) Rd = memb(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrbfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(8, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memb(Ii)
RzILOpEffect *hex_il_op_l4_ploadrbt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_10), DUP(ml_EA_10))), CAST(8, MSB(DUP(ml_EA_10)), DUP(ml_EA_10))));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv) Rd = memb(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrbt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(8, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memb(Ii)
RzILOpEffect *hex_il_op_l4_ploadrbtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_10), DUP(ml_EA_10))), CAST(8, MSB(DUP(ml_EA_10)), DUP(ml_EA_10))));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv.new) Rd = memb(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrbtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(8, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rdd = memd(Ii)
RzILOpEffect *hex_il_op_l4_ploadrdf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv) Rdd = memd(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrdf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_16 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rdd = memd(Ii)
RzILOpEffect *hex_il_op_l4_ploadrdfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) Rdd = memd(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrdfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_16 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (Pt) Rdd = memd(Ii)
RzILOpEffect *hex_il_op_l4_ploadrdt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_10 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv) Rdd = memd(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrdt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_15 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rdd = memd(Ii)
RzILOpEffect *hex_il_op_l4_ploadrdtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_10 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv.new) Rdd = memd(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrdtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_15 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memh(Ii)
RzILOpEffect *hex_il_op_l4_ploadrhf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(16, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv) Rd = memh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrhf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(16, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memh(Ii)
RzILOpEffect *hex_il_op_l4_ploadrhfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(16, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) Rd = memh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrhfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(16, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memh(Ii)
RzILOpEffect *hex_il_op_l4_ploadrht_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_10), DUP(ml_EA_10))), CAST(16, MSB(DUP(ml_EA_10)), DUP(ml_EA_10))));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv) Rd = memh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrht_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(16, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memh(Ii)
RzILOpEffect *hex_il_op_l4_ploadrhtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_10), DUP(ml_EA_10))), CAST(16, MSB(DUP(ml_EA_10)), DUP(ml_EA_10))));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv.new) Rd = memh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrhtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(16, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memw(Ii)
RzILOpEffect *hex_il_op_l4_ploadrif_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_11 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv) Rd = memw(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrif_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_16 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memw(Ii)
RzILOpEffect *hex_il_op_l4_ploadrifnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_11 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) Rd = memw(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrifnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_16 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memw(Ii)
RzILOpEffect *hex_il_op_l4_ploadrit_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_10 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv) Rd = memw(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrit_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memw(Ii)
RzILOpEffect *hex_il_op_l4_ploadritnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_10 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv.new) Rd = memw(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadritnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memub(Ii)
RzILOpEffect *hex_il_op_l4_ploadrubf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv) Rd = memub(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrubf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memub(Ii)
RzILOpEffect *hex_il_op_l4_ploadrubfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) Rd = memub(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrubfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memub(Ii)
RzILOpEffect *hex_il_op_l4_ploadrubt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv) Rd = memub(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrubt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memub(Ii)
RzILOpEffect *hex_il_op_l4_ploadrubtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv.new) Rd = memub(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadrubtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memuh(Ii)
RzILOpEffect *hex_il_op_l4_ploadruhf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv) Rd = memuh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadruhf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memuh(Ii)
RzILOpEffect *hex_il_op_l4_ploadruhfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_11)));

	// nop;
	RzILOpEffect *nop_15 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_17 = op_ASSIGN_14;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_15;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_19 = BRANCH(op_INV_9, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) Rd = memuh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadruhfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = op_ASSIGN_19;

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_24 = BRANCH(op_INV_14, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memuh(Ii)
RzILOpEffect *hex_il_op_l4_ploadruht_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv) Rd = memuh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadruht_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memuh(Ii)
RzILOpEffect *hex_il_op_l4_ploadruhtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_10)));

	// nop;
	RzILOpEffect *nop_14 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_16 = op_ASSIGN_13;

	// seq(nop);
	RzILOpEffect *seq_else_17 = nop_14;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_8), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_18);
	return instruction_sequence;
}

// if (Pv.new) Rd = memuh(Rs+Rt<<Ii)
RzILOpEffect *hex_il_op_l4_ploadruhtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Rt << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Rt, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = op_ASSIGN_18;

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_13), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_23);
	return instruction_sequence;
}

// Rdd = dealloc_return(Rs):raw
RzILOpEffect *hex_il_op_l4_return(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_4 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_6 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_8 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_6));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_14 = LOGXOR(VARL("tmp"), op_LSHIFT_13);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_14));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_20 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, &sp_op, op_ADD_20);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_25 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_25, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_30_31 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_27), DUP(op_AND_27))), CAST(32, MSB(DUP(op_AND_27)), DUP(op_AND_27))))));

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_4, op_ASSIGN_8, op_ASSIGN_16, op_ASSIGN_21, jump_cast_ut32_30_31);
	return instruction_sequence;
}

// if (!Pv) Rdd = dealloc_return(Rs):raw
RzILOpEffect *hex_il_op_l4_return_f(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_12 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_12));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_20 = LOGXOR(VARL("tmp"), op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_20));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_26 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, &sp_op, op_ADD_26);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_36_37 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_33), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))));

	// nop;
	RzILOpEffect *nop_39 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...;
	RzILOpEffect *seq_then_41 = SEQN(4, op_ASSIGN_14, op_ASSIGN_22, op_ASSIGN_27, jump_cast_ut32_36_37);

	// seq(nop);
	RzILOpEffect *seq_else_42 = nop_39;

	// if (! (((st32) Pv) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_11 = INV(NON_ZERO(op_AND_10));
	RzILOpEffect *branch_43 = BRANCH(op_INV_11, seq_then_41, seq_else_42);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_43);
	return instruction_sequence;
}

// if (!Pv.new) Rdd = dealloc_return(Rs):nt:raw
RzILOpEffect *hex_il_op_l4_return_fnew_pnt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_12 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_12));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_20 = LOGXOR(VARL("tmp"), op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_20));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_26 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, &sp_op, op_ADD_26);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_36_37 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_33), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))));

	// nop;
	RzILOpEffect *nop_39 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...;
	RzILOpEffect *seq_then_41 = SEQN(4, op_ASSIGN_14, op_ASSIGN_22, op_ASSIGN_27, jump_cast_ut32_36_37);

	// seq(nop);
	RzILOpEffect *seq_else_42 = nop_39;

	// if (! (((st32) Pv_new) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_11 = INV(NON_ZERO(op_AND_10));
	RzILOpEffect *branch_43 = BRANCH(op_INV_11, seq_then_41, seq_else_42);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_43);
	return instruction_sequence;
}

// if (!Pv.new) Rdd = dealloc_return(Rs):t:raw
RzILOpEffect *hex_il_op_l4_return_fnew_pt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_12 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_12));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_20 = LOGXOR(VARL("tmp"), op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_20));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_26 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, &sp_op, op_ADD_26);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_36_37 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_33), DUP(op_AND_33))), CAST(32, MSB(DUP(op_AND_33)), DUP(op_AND_33))))));

	// nop;
	RzILOpEffect *nop_39 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...;
	RzILOpEffect *seq_then_41 = SEQN(4, op_ASSIGN_14, op_ASSIGN_22, op_ASSIGN_27, jump_cast_ut32_36_37);

	// seq(nop);
	RzILOpEffect *seq_else_42 = nop_39;

	// if (! (((st32) Pv_new) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_11 = INV(NON_ZERO(op_AND_10));
	RzILOpEffect *branch_43 = BRANCH(op_INV_11, seq_then_41, seq_else_42);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_43);
	return instruction_sequence;
}

// if (Pv) Rdd = dealloc_return(Rs):raw
RzILOpEffect *hex_il_op_l4_return_t(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_11));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_19 = LOGXOR(VARL("tmp"), op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_19));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_25 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_26 = WRITE_REG(bundle, &sp_op, op_ADD_25);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_35_36 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_32), DUP(op_AND_32))), CAST(32, MSB(DUP(op_AND_32)), DUP(op_AND_32))))));

	// nop;
	RzILOpEffect *nop_38 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...;
	RzILOpEffect *seq_then_40 = SEQN(4, op_ASSIGN_13, op_ASSIGN_21, op_ASSIGN_26, jump_cast_ut32_35_36);

	// seq(nop);
	RzILOpEffect *seq_else_41 = nop_38;

	// if ((((st32) Pv) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_42 = BRANCH(NON_ZERO(op_AND_10), seq_then_40, seq_else_41);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_42);
	return instruction_sequence;
}

// if (Pv.new) Rdd = dealloc_return(Rs):nt:raw
RzILOpEffect *hex_il_op_l4_return_tnew_pnt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_11));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_19 = LOGXOR(VARL("tmp"), op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_19));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_25 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_26 = WRITE_REG(bundle, &sp_op, op_ADD_25);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_35_36 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_32), DUP(op_AND_32))), CAST(32, MSB(DUP(op_AND_32)), DUP(op_AND_32))))));

	// nop;
	RzILOpEffect *nop_38 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...;
	RzILOpEffect *seq_then_40 = SEQN(4, op_ASSIGN_13, op_ASSIGN_21, op_ASSIGN_26, jump_cast_ut32_35_36);

	// seq(nop);
	RzILOpEffect *seq_else_41 = nop_38;

	// if ((((st32) Pv_new) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_42 = BRANCH(NON_ZERO(op_AND_10), seq_then_40, seq_else_41);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_42);
	return instruction_sequence;
}

// if (Pv.new) Rdd = dealloc_return(Rs):t:raw
RzILOpEffect *hex_il_op_l4_return_tnew_pt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_11));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_19 = LOGXOR(VARL("tmp"), op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_19));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_25 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_26 = WRITE_REG(bundle, &sp_op, op_ADD_25);

	// jump(((ut32) ((st64) ((st32) ((Rdd >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(READ_REG(pkt, Rdd_op, true), SN(32, 0x20));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(64, 0xffffffff));
	RzILOpEffect *jump_cast_ut32_35_36 = SEQ2(SETL("jump_flag", IL_TRUE), SETL("jump_target", CAST(32, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_32), DUP(op_AND_32))), CAST(32, MSB(DUP(op_AND_32)), DUP(op_AND_32))))));

	// nop;
	RzILOpEffect *nop_38 = NOP();

	// seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...;
	RzILOpEffect *seq_then_40 = SEQN(4, op_ASSIGN_13, op_ASSIGN_21, op_ASSIGN_26, jump_cast_ut32_35_36);

	// seq(nop);
	RzILOpEffect *seq_else_41 = nop_38;

	// if ((((st32) Pv_new) & 0x1)) {seq(tmp = ((ut64) mem_load_64(EA)); Rdd = ((st64) (tmp ^ (((ut64 ...} else {seq(nop)};
	RzILOpPure *op_AND_10 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_42 = BRANCH(NON_ZERO(op_AND_10), seq_then_40, seq_else_41);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_5, branch_42);
	return instruction_sequence;
}

// memb(Rs+Ii) -= Rt
RzILOpEffect *hex_il_op_l4_sub_memopb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = tmp - Rt;
	RzILOpPure *op_SUB_14 = SUB(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_SUB_15 = SETL("tmp", op_SUB_14);

	// mem_store_ut8(EA, ((ut8) tmp));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_SUB_15, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memh(Rs+Ii) -= Rt
RzILOpEffect *hex_il_op_l4_sub_memoph_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmp", CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	// tmp = tmp - Rt;
	RzILOpPure *op_SUB_14 = SUB(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_SUB_15 = SETL("tmp", op_SUB_14);

	// mem_store_ut16(EA, ((ut16) tmp));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_SUB_15, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memw(Rs+Ii) -= Rt
RzILOpEffect *hex_il_op_l4_sub_memopw_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: st32 tmp;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// tmp = ((st32) mem_load_32(EA));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = SETL("tmp", CAST(32, MSB(ml_EA_9), DUP(ml_EA_9)));

	// tmp = tmp - Rt;
	RzILOpPure *op_SUB_13 = SUB(VARL("tmp"), Rt);
	RzILOpEffect *op_ASSIGN_SUB_14 = SETL("tmp", op_SUB_13);

	// mem_store_ut32(EA, ((ut32) tmp));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("tmp")));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, op_ASSIGN_6, op_ASSIGN_11, op_ASSIGN_SUB_14, ms_cast_ut32_15_16);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>