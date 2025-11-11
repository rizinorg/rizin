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

// Rdd = rol(Rss,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rdd = ((st64) ((u == ((ut32) 0x0)) ? ((ut64) Rss) : ((((ut64) Rss) << u) | (((ut64) Rss) >> ((ut32) 0x40) - u))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x40)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(64, IL_FALSE, DUP(Rss)), op_OR_16);
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, cond_18));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_20);
	return instruction_sequence;
}

// Rxx += rol(Rss,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_p_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) ((ut64) Rxx) + ((u == ((ut32) 0x0)) ? ((ut64) Rss) : ((((ut64) Rss) << u) | (((ut64) Rss) >> ((ut32) 0x40) - u))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x40)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(64, IL_FALSE, DUP(Rss)), op_OR_16);
	RzILOpPure *op_ADD_20 = ADD(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_ADD_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rxx &= rol(Rss,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_p_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) (((ut64) Rxx) & ((u == ((ut32) 0x0)) ? ((ut64) Rss) : ((((ut64) Rss) << u) | (((ut64) Rss) >> ((ut32) 0x40) - u)))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x40)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(64, IL_FALSE, DUP(Rss)), op_OR_16);
	RzILOpPure *op_AND_20 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_AND_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rxx -= rol(Rss,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_p_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) ((ut64) Rxx) - ((u == ((ut32) 0x0)) ? ((ut64) Rss) : ((((ut64) Rss) << u) | (((ut64) Rss) >> ((ut32) 0x40) - u))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x40)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(64, IL_FALSE, DUP(Rss)), op_OR_16);
	RzILOpPure *op_SUB_20 = SUB(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_SUB_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rxx |= rol(Rss,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_p_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) (((ut64) Rxx) | ((u == ((ut32) 0x0)) ? ((ut64) Rss) : ((((ut64) Rss) << u) | (((ut64) Rss) >> ((ut32) 0x40) - u)))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x40)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(64, IL_FALSE, DUP(Rss)), op_OR_16);
	RzILOpPure *op_OR_20 = LOGOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rxx ^= rol(Rss,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_p_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rxx = ((st64) (((ut64) Rxx) ^ ((u == ((ut32) 0x0)) ? ((ut64) Rss) : ((((ut64) Rss) << u) | (((ut64) Rss) >> ((ut32) 0x40) - u)))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(64, IL_FALSE, Rss), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x40)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(64, IL_FALSE, DUP(Rss)), op_OR_16);
	RzILOpPure *op_XOR_20 = LOGXOR(CAST(64, IL_FALSE, READ_REG(pkt, Rxx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_XOR_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rd = rol(Rs,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rd = ((st32) ((u == ((ut32) 0x0)) ? ((ut32) Rs) : ((((ut32) Rs) << u) | (((ut32) Rs) >> ((ut32) 0x20) - u))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x20)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, DUP(Rs)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(32, IL_FALSE, DUP(Rs)), op_OR_16);
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_18));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_20);
	return instruction_sequence;
}

// Rx += rol(Rs,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_r_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) ((ut32) Rx) + ((u == ((ut32) 0x0)) ? ((ut32) Rs) : ((((ut32) Rs) << u) | (((ut32) Rs) >> ((ut32) 0x20) - u))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x20)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, DUP(Rs)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(32, IL_FALSE, DUP(Rs)), op_OR_16);
	RzILOpPure *op_ADD_20 = ADD(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_ADD_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rx &= rol(Rs,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_r_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) (((ut32) Rx) & ((u == ((ut32) 0x0)) ? ((ut32) Rs) : ((((ut32) Rs) << u) | (((ut32) Rs) >> ((ut32) 0x20) - u)))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x20)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, DUP(Rs)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(32, IL_FALSE, DUP(Rs)), op_OR_16);
	RzILOpPure *op_AND_20 = LOGAND(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_AND_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rx -= rol(Rs,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_r_nac(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) ((ut32) Rx) - ((u == ((ut32) 0x0)) ? ((ut32) Rs) : ((((ut32) Rs) << u) | (((ut32) Rs) >> ((ut32) 0x20) - u))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x20)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, DUP(Rs)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(32, IL_FALSE, DUP(Rs)), op_OR_16);
	RzILOpPure *op_SUB_20 = SUB(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rx |= rol(Rs,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_r_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) (((ut32) Rx) | ((u == ((ut32) 0x0)) ? ((ut32) Rs) : ((((ut32) Rs) << u) | (((ut32) Rs) >> ((ut32) 0x20) - u)))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x20)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, DUP(Rs)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(32, IL_FALSE, DUP(Rs)), op_OR_16);
	RzILOpPure *op_OR_20 = LOGOR(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rx ^= rol(Rs,Ii)
RzILOpEffect *hex_il_op_s6_rol_i_r_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rx = ((st32) (((ut32) Rx) ^ ((u == ((ut32) 0x0)) ? ((ut32) Rs) : ((((ut32) Rs) << u) | (((ut32) Rs) >> ((ut32) 0x20) - u)))));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_SUB_14 = SUB(CAST(32, IL_FALSE, SN(32, 0x20)), VARL("u"));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, DUP(Rs)), op_SUB_14);
	RzILOpPure *op_OR_16 = LOGOR(op_LSHIFT_8, op_RSHIFT_15);
	RzILOpPure *cond_18 = ITE(op_EQ_5, CAST(32, IL_FALSE, DUP(Rs)), op_OR_16);
	RzILOpPure *op_XOR_20 = LOGXOR(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), cond_18);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_XOR_20));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_22);
	return instruction_sequence;
}

// Rdd = vsplatb(Rs)
RzILOpEffect *hex_il_op_s6_vsplatrbp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp609 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp609", VARL("i"));

	// seq(h_tmp609 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rs >> 0x0) & 0xff)))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xff));
	RzILOpPure *op_AND_27 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_22), DUP(op_AND_22))), CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22)))), SN(64, 0xff));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(CAST(64, IL_FALSE, op_AND_27), op_MUL_30);
	RzILOpPure *op_OR_33 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_31);
	RzILOpEffect *op_ASSIGN_35 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_33));

	// seq(h_tmp609; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_37 = op_ASSIGN_35;

	// seq(seq(h_tmp609; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_38 = SEQN(2, seq_37, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp609; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_39 = REPEAT(op_LT_4, seq_38);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp609; Rdd = ((st64) ...;
	RzILOpEffect *seq_40 = SEQN(2, op_ASSIGN_2, for_39);

	RzILOpEffect *instruction_sequence = seq_40;
	return instruction_sequence;
}

// Rdd = vtrunehb(Rss,Rtt)
RzILOpEffect *hex_il_op_s6_vtrunehb_ppp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp610 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp610", VARL("i"));

	// seq(h_tmp610 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rtt >> i * 0x2 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_20 = MUL(op_MUL_18, SN(32, 8));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rtt, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_24), DUP(op_AND_24))), CAST(8, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_24)), DUP(op_AND_24))), CAST(8, MSB(DUP(op_AND_24)), DUP(op_AND_24)))), SN(64, 0xff));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(CAST(64, IL_FALSE, op_AND_29), op_MUL_32);
	RzILOpPure *op_OR_35 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_35));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i + 0x4 * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rss >> i * 0x2 * 0x8) & ((st64) 0xff))))) & 0xff)) << i + 0x4 * 0x8)));
	RzILOpPure *op_ADD_41 = ADD(VARL("i"), SN(32, 4));
	RzILOpPure *op_MUL_43 = MUL(op_ADD_41, SN(32, 8));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(SN(64, 0xff), op_MUL_43);
	RzILOpPure *op_NOT_45 = LOGNOT(op_LSHIFT_44);
	RzILOpPure *op_AND_46 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_45);
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_MUL_51 = MUL(op_MUL_49, SN(32, 8));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(Rss, op_MUL_51);
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_60 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_55), DUP(op_AND_55))), CAST(8, MSB(DUP(op_AND_55)), DUP(op_AND_55)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_55)), DUP(op_AND_55))), CAST(8, MSB(DUP(op_AND_55)), DUP(op_AND_55)))), SN(64, 0xff));
	RzILOpPure *op_ADD_63 = ADD(VARL("i"), SN(32, 4));
	RzILOpPure *op_MUL_65 = MUL(op_ADD_63, SN(32, 8));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(CAST(64, IL_FALSE, op_AND_60), op_MUL_65);
	RzILOpPure *op_OR_68 = LOGOR(CAST(64, IL_FALSE, op_AND_46), op_LSHIFT_66);
	RzILOpEffect *op_ASSIGN_70 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_68));

	// seq(h_tmp610; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_72 = SEQN(2, op_ASSIGN_37, op_ASSIGN_70);

	// seq(seq(h_tmp610; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_73 = SEQN(2, seq_72, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp610; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_74 = REPEAT(op_LT_4, seq_73);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp610; Rdd = ((st64) ...;
	RzILOpEffect *seq_75 = SEQN(2, op_ASSIGN_2, for_74);

	RzILOpEffect *instruction_sequence = seq_75;
	return instruction_sequence;
}

// Rdd = vtrunohb(Rss,Rtt)
RzILOpEffect *hex_il_op_s6_vtrunohb_ppp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp611 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp611", VARL("i"));

	// seq(h_tmp611 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rtt >> i * 0x2 + 0x1 * 0x8) & ((st64) 0xff))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_20 = ADD(op_MUL_18, SN(32, 1));
	RzILOpPure *op_MUL_22 = MUL(op_ADD_20, SN(32, 8));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rtt, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_31 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_26), DUP(op_AND_26))), CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26))), CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26)))), SN(64, 0xff));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_35 = SHIFTL0(CAST(64, IL_FALSE, op_AND_31), op_MUL_34);
	RzILOpPure *op_OR_37 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_35);
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_37));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i + 0x4 * 0x8)))) | (((ut64) (((st64) ((st32) ((st8) ((Rss >> i * 0x2 + 0x1 * 0x8) & ((st64) 0xff))))) & 0xff)) << i + 0x4 * 0x8)));
	RzILOpPure *op_ADD_43 = ADD(VARL("i"), SN(32, 4));
	RzILOpPure *op_MUL_45 = MUL(op_ADD_43, SN(32, 8));
	RzILOpPure *op_LSHIFT_46 = SHIFTL0(SN(64, 0xff), op_MUL_45);
	RzILOpPure *op_NOT_47 = LOGNOT(op_LSHIFT_46);
	RzILOpPure *op_AND_48 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_47);
	RzILOpPure *op_MUL_51 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_53 = ADD(op_MUL_51, SN(32, 1));
	RzILOpPure *op_MUL_55 = MUL(op_ADD_53, SN(32, 8));
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(Rss, op_MUL_55);
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_56, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_AND_64 = LOGAND(CAST(64, MSB(CAST(32, MSB(CAST(8, MSB(op_AND_59), DUP(op_AND_59))), CAST(8, MSB(DUP(op_AND_59)), DUP(op_AND_59)))), CAST(32, MSB(CAST(8, MSB(DUP(op_AND_59)), DUP(op_AND_59))), CAST(8, MSB(DUP(op_AND_59)), DUP(op_AND_59)))), SN(64, 0xff));
	RzILOpPure *op_ADD_67 = ADD(VARL("i"), SN(32, 4));
	RzILOpPure *op_MUL_69 = MUL(op_ADD_67, SN(32, 8));
	RzILOpPure *op_LSHIFT_70 = SHIFTL0(CAST(64, IL_FALSE, op_AND_64), op_MUL_69);
	RzILOpPure *op_OR_72 = LOGOR(CAST(64, IL_FALSE, op_AND_48), op_LSHIFT_70);
	RzILOpEffect *op_ASSIGN_74 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_72));

	// seq(h_tmp611; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_76 = SEQN(2, op_ASSIGN_39, op_ASSIGN_74);

	// seq(seq(h_tmp611; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_77 = SEQN(2, seq_76, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp611; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_78 = REPEAT(op_LT_4, seq_77);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp611; Rdd = ((st64) ...;
	RzILOpEffect *seq_79 = SEQN(2, op_ASSIGN_2, for_78);

	RzILOpEffect *instruction_sequence = seq_79;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>