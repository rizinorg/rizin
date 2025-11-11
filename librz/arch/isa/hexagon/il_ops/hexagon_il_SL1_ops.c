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

// Rd = memw(Rs+Ii)
RzILOpEffect *hex_il_op_sl1_loadri_io(HexInsnPktBundle *bundle) {
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

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memub(Rs+Ii)
RzILOpEffect *hex_il_op_sl1_loadrub_io(HexInsnPktBundle *bundle) {
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

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_2, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>