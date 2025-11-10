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

// allocframe(Ii)
RzILOpEffect *hex_il_op_ss2_allocframe(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);
	const HexOp lr_op = ALIAS2OP(HEX_REG_ALIAS_LR, false);
	RzILOpPure *lr = READ_REG(pkt, &lr_op, false);
	const HexOp fp_op = ALIAS2OP(HEX_REG_ALIAS_FP, false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// EA = sp + ((ut32) -0x8);
	RzILOpPure *op_ADD_5 = ADD(READ_REG(pkt, &sp_op, true), CAST(32, IL_FALSE, SN(32, -8)));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

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

	// sp = EA - u;
	RzILOpPure *op_SUB_26 = SUB(VARL("EA"), VARL("u"));
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, &sp_op, op_SUB_26);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_24, op_ASSIGN_6, ms_cast_ut64_20_21, op_ASSIGN_22, op_ASSIGN_27);
	return instruction_sequence;
}

// memb(Rs+Ii) = #0
RzILOpEffect *hex_il_op_ss2_storebi0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) 0x0));
	RzILOpEffect *ms_cast_ut8_9_10 = STOREW(VARL("EA"), CAST(8, IL_FALSE, SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut8_9_10);
	return instruction_sequence;
}

// memb(Rs+Ii) = #1
RzILOpEffect *hex_il_op_ss2_storebi1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) 0x1));
	RzILOpEffect *ms_cast_ut8_9_10 = STOREW(VARL("EA"), CAST(8, IL_FALSE, SN(32, 1)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut8_9_10);
	return instruction_sequence;
}

// memd(r29+Ii) = Rtt
RzILOpEffect *hex_il_op_ss2_stored_sp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);
	RzILOpPure *sp = READ_REG(pkt, &sp_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// s = s;
	RzILOpEffect *imm_assign_2 = SETL("s", s);

	// EA = sp + ((ut32) s);
	RzILOpPure *op_ADD_5 = ADD(sp, CAST(32, IL_FALSE, VARL("s")));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_9_10 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut64_9_10);
	return instruction_sequence;
}

// memh(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_ss2_storeh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_16_17 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut16_16_17);
	return instruction_sequence;
}

// memw(r29+Ii) = Rt
RzILOpEffect *hex_il_op_ss2_storew_sp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);
	RzILOpPure *sp = READ_REG(pkt, &sp_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = sp + u;
	RzILOpPure *op_ADD_4 = ADD(sp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_8_9 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_5, ms_cast_ut32_8_9);
	return instruction_sequence;
}

// memw(Rs+Ii) = #0
RzILOpEffect *hex_il_op_ss2_storewi0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) 0x0));
	RzILOpEffect *ms_cast_ut32_9_10 = STOREW(VARL("EA"), CAST(32, IL_FALSE, SN(32, 0)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut32_9_10);
	return instruction_sequence;
}

// memw(Rs+Ii) = #1
RzILOpEffect *hex_il_op_ss2_storewi1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) 0x1));
	RzILOpEffect *ms_cast_ut32_9_10 = STOREW(VARL("EA"), CAST(32, IL_FALSE, SN(32, 1)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut32_9_10);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>