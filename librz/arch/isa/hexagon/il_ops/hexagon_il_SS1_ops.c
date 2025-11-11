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

// memb(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_ss1_storeb_io(HexInsnPktBundle *bundle) {
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

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_16_17 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_14), DUP(op_AND_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut8_16_17);
	return instruction_sequence;
}

// memw(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_ss1_storew_io(HexInsnPktBundle *bundle) {
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

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_9_10 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, ms_cast_ut32_9_10);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>