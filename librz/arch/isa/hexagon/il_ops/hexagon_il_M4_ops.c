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

// Rx &= and(Rs,Rt)
RzILOpEffect *hex_il_op_m4_and_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx & (Rs & Rt));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_AND_4 = LOGAND(READ_REG(pkt, Rx_op, false), op_AND_3);
	RzILOpEffect *op_ASSIGN_AND_5 = WRITE_REG(bundle, Rx_op, op_AND_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_AND_5;
	return instruction_sequence;
}

// Rx &= and(Rs,~Rt)
RzILOpEffect *hex_il_op_m4_and_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx & (Rs & (~Rt)));
	RzILOpPure *op_NOT_3 = LOGNOT(Rt);
	RzILOpPure *op_AND_4 = LOGAND(Rs, op_NOT_3);
	RzILOpPure *op_AND_5 = LOGAND(READ_REG(pkt, Rx_op, false), op_AND_4);
	RzILOpEffect *op_ASSIGN_AND_6 = WRITE_REG(bundle, Rx_op, op_AND_5);

	RzILOpEffect *instruction_sequence = op_ASSIGN_AND_6;
	return instruction_sequence;
}

// Rx &= or(Rs,Rt)
RzILOpEffect *hex_il_op_m4_and_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx & (Rs | Rt));
	RzILOpPure *op_OR_3 = LOGOR(Rs, Rt);
	RzILOpPure *op_AND_4 = LOGAND(READ_REG(pkt, Rx_op, false), op_OR_3);
	RzILOpEffect *op_ASSIGN_AND_5 = WRITE_REG(bundle, Rx_op, op_AND_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_AND_5;
	return instruction_sequence;
}

// Rx &= xor(Rs,Rt)
RzILOpEffect *hex_il_op_m4_and_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx & (Rs ^ Rt));
	RzILOpPure *op_XOR_3 = LOGXOR(Rs, Rt);
	RzILOpPure *op_AND_4 = LOGAND(READ_REG(pkt, Rx_op, false), op_XOR_3);
	RzILOpEffect *op_ASSIGN_AND_5 = WRITE_REG(bundle, Rx_op, op_AND_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_AND_5;
	return instruction_sequence;
}

// Rd = cmpyiwh(Rss,Rt):<<1:rnd:sat
RzILOpEffect *hex_il_op_m4_cmpyi_wh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_188 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(32, 0xffff));
	RzILOpPure *op_MUL_31 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_10), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_24), DUP(op_AND_24))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_50 = LOGAND(op_RSHIFT_48, SN(32, 0xffff));
	RzILOpPure *op_MUL_57 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_50), DUP(op_AND_50))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_58 = ADD(op_MUL_31, op_MUL_57);
	RzILOpPure *op_ADD_61 = ADD(op_ADD_58, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(op_ADD_61, SN(32, 15));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_72, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_MUL_94 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_74), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_87), DUP(op_AND_87))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_98 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_98, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_111 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_113 = LOGAND(op_RSHIFT_111, SN(32, 0xffff));
	RzILOpPure *op_MUL_120 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_100), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_113), DUP(op_AND_113))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_121 = ADD(op_MUL_94, op_MUL_120);
	RzILOpPure *op_ADD_124 = ADD(op_ADD_121, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_126 = SHIFTRA(op_ADD_124, SN(32, 15));
	RzILOpPure *op_EQ_127 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_63), SN(32, 0), SN(32, 0x20)), op_RSHIFT_126);
	RzILOpPure *op_RSHIFT_192 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_194 = LOGAND(op_RSHIFT_192, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_205 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_207 = LOGAND(op_RSHIFT_205, SN(32, 0xffff));
	RzILOpPure *op_MUL_214 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_194), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_207), DUP(op_AND_207))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_218 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_220 = LOGAND(op_RSHIFT_218, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_231 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_233 = LOGAND(op_RSHIFT_231, SN(32, 0xffff));
	RzILOpPure *op_MUL_240 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_220), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_233), DUP(op_AND_233))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_241 = ADD(op_MUL_214, op_MUL_240);
	RzILOpPure *op_ADD_244 = ADD(op_ADD_241, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_246 = SHIFTRA(op_ADD_244, SN(32, 15));
	RzILOpPure *op_LT_249 = SLT(op_RSHIFT_246, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_254 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_255 = NEG(op_LSHIFT_254);
	RzILOpPure *op_LSHIFT_260 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_263 = SUB(op_LSHIFT_260, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_264 = ITE(op_LT_249, op_NEG_255, op_SUB_263);
	RzILOpEffect *gcc_expr_265 = BRANCH(op_EQ_127, EMPTY(), set_usr_field_call_188);

	// h_tmp433 = HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_267 = SETL("h_tmp433", cond_264);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64 ...;
	RzILOpEffect *seq_268 = SEQN(2, gcc_expr_265, op_ASSIGN_hybrid_tmp_267);

	// Rd = ((st32) ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)) ? (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) : h_tmp433));
	RzILOpPure *op_RSHIFT_131 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_133 = LOGAND(op_RSHIFT_131, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_146 = LOGAND(op_RSHIFT_144, SN(32, 0xffff));
	RzILOpPure *op_MUL_153 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_133), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_146), DUP(op_AND_146))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_159 = LOGAND(op_RSHIFT_157, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_172 = LOGAND(op_RSHIFT_170, SN(32, 0xffff));
	RzILOpPure *op_MUL_179 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_159), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_172), DUP(op_AND_172))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_180 = ADD(op_MUL_153, op_MUL_179);
	RzILOpPure *op_ADD_183 = ADD(op_ADD_180, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_185 = SHIFTRA(op_ADD_183, SN(32, 15));
	RzILOpPure *cond_269 = ITE(DUP(op_EQ_127), op_RSHIFT_185, VARL("h_tmp433"));
	RzILOpEffect *op_ASSIGN_271 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_269), DUP(cond_269)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) (( ...;
	RzILOpEffect *seq_272 = SEQN(2, seq_268, op_ASSIGN_271);

	RzILOpEffect *instruction_sequence = seq_272;
	return instruction_sequence;
}

// Rd = cmpyiwh(Rss,Rt*):<<1:rnd:sat
RzILOpEffect *hex_il_op_m4_cmpyi_whc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_188 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(32, 0xffff));
	RzILOpPure *op_MUL_31 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_10), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_24), DUP(op_AND_24))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_50 = LOGAND(op_RSHIFT_48, SN(32, 0xffff));
	RzILOpPure *op_MUL_57 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_50), DUP(op_AND_50))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_58 = SUB(op_MUL_31, op_MUL_57);
	RzILOpPure *op_ADD_61 = ADD(op_SUB_58, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(op_ADD_61, SN(32, 15));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_72, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_MUL_94 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_74), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_87), DUP(op_AND_87))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_98 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_98, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_111 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_113 = LOGAND(op_RSHIFT_111, SN(32, 0xffff));
	RzILOpPure *op_MUL_120 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_100), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_113), DUP(op_AND_113))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_121 = SUB(op_MUL_94, op_MUL_120);
	RzILOpPure *op_ADD_124 = ADD(op_SUB_121, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_126 = SHIFTRA(op_ADD_124, SN(32, 15));
	RzILOpPure *op_EQ_127 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_63), SN(32, 0), SN(32, 0x20)), op_RSHIFT_126);
	RzILOpPure *op_RSHIFT_192 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_194 = LOGAND(op_RSHIFT_192, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_205 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_207 = LOGAND(op_RSHIFT_205, SN(32, 0xffff));
	RzILOpPure *op_MUL_214 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_194), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_207), DUP(op_AND_207))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_218 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_220 = LOGAND(op_RSHIFT_218, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_231 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_233 = LOGAND(op_RSHIFT_231, SN(32, 0xffff));
	RzILOpPure *op_MUL_240 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_220), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_233), DUP(op_AND_233))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_241 = SUB(op_MUL_214, op_MUL_240);
	RzILOpPure *op_ADD_244 = ADD(op_SUB_241, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_246 = SHIFTRA(op_ADD_244, SN(32, 15));
	RzILOpPure *op_LT_249 = SLT(op_RSHIFT_246, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_254 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_255 = NEG(op_LSHIFT_254);
	RzILOpPure *op_LSHIFT_260 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_263 = SUB(op_LSHIFT_260, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_264 = ITE(op_LT_249, op_NEG_255, op_SUB_263);
	RzILOpEffect *gcc_expr_265 = BRANCH(op_EQ_127, EMPTY(), set_usr_field_call_188);

	// h_tmp434 = HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_267 = SETL("h_tmp434", cond_264);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64 ...;
	RzILOpEffect *seq_268 = SEQN(2, gcc_expr_265, op_ASSIGN_hybrid_tmp_267);

	// Rd = ((st32) ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)) ? (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) : h_tmp434));
	RzILOpPure *op_RSHIFT_131 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_133 = LOGAND(op_RSHIFT_131, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_146 = LOGAND(op_RSHIFT_144, SN(32, 0xffff));
	RzILOpPure *op_MUL_153 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_133), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_146), DUP(op_AND_146))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_159 = LOGAND(op_RSHIFT_157, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_172 = LOGAND(op_RSHIFT_170, SN(32, 0xffff));
	RzILOpPure *op_MUL_179 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_159), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_172), DUP(op_AND_172))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_180 = SUB(op_MUL_153, op_MUL_179);
	RzILOpPure *op_ADD_183 = ADD(op_SUB_180, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_185 = SHIFTRA(op_ADD_183, SN(32, 15));
	RzILOpPure *cond_269 = ITE(DUP(op_EQ_127), op_RSHIFT_185, VARL("h_tmp434"));
	RzILOpEffect *op_ASSIGN_271 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_269), DUP(cond_269)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) (( ...;
	RzILOpEffect *seq_272 = SEQN(2, seq_268, op_ASSIGN_271);

	RzILOpEffect *instruction_sequence = seq_272;
	return instruction_sequence;
}

// Rd = cmpyrwh(Rss,Rt):<<1:rnd:sat
RzILOpEffect *hex_il_op_m4_cmpyr_wh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_188 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(32, 0xffff));
	RzILOpPure *op_MUL_31 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_10), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_24), DUP(op_AND_24))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_50 = LOGAND(op_RSHIFT_48, SN(32, 0xffff));
	RzILOpPure *op_MUL_57 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_50), DUP(op_AND_50))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_58 = SUB(op_MUL_31, op_MUL_57);
	RzILOpPure *op_ADD_61 = ADD(op_SUB_58, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(op_ADD_61, SN(32, 15));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_72, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_MUL_94 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_74), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_87), DUP(op_AND_87))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_98 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_98, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_111 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_113 = LOGAND(op_RSHIFT_111, SN(32, 0xffff));
	RzILOpPure *op_MUL_120 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_100), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_113), DUP(op_AND_113))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_121 = SUB(op_MUL_94, op_MUL_120);
	RzILOpPure *op_ADD_124 = ADD(op_SUB_121, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_126 = SHIFTRA(op_ADD_124, SN(32, 15));
	RzILOpPure *op_EQ_127 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_63), SN(32, 0), SN(32, 0x20)), op_RSHIFT_126);
	RzILOpPure *op_RSHIFT_192 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_194 = LOGAND(op_RSHIFT_192, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_205 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_207 = LOGAND(op_RSHIFT_205, SN(32, 0xffff));
	RzILOpPure *op_MUL_214 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_194), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_207), DUP(op_AND_207))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_218 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_220 = LOGAND(op_RSHIFT_218, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_231 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_233 = LOGAND(op_RSHIFT_231, SN(32, 0xffff));
	RzILOpPure *op_MUL_240 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_220), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_233), DUP(op_AND_233))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_241 = SUB(op_MUL_214, op_MUL_240);
	RzILOpPure *op_ADD_244 = ADD(op_SUB_241, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_246 = SHIFTRA(op_ADD_244, SN(32, 15));
	RzILOpPure *op_LT_249 = SLT(op_RSHIFT_246, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_254 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_255 = NEG(op_LSHIFT_254);
	RzILOpPure *op_LSHIFT_260 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_263 = SUB(op_LSHIFT_260, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_264 = ITE(op_LT_249, op_NEG_255, op_SUB_263);
	RzILOpEffect *gcc_expr_265 = BRANCH(op_EQ_127, EMPTY(), set_usr_field_call_188);

	// h_tmp435 = HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_267 = SETL("h_tmp435", cond_264);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64 ...;
	RzILOpEffect *seq_268 = SEQN(2, gcc_expr_265, op_ASSIGN_hybrid_tmp_267);

	// Rd = ((st32) ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)) ? (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) : h_tmp435));
	RzILOpPure *op_RSHIFT_131 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_133 = LOGAND(op_RSHIFT_131, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_146 = LOGAND(op_RSHIFT_144, SN(32, 0xffff));
	RzILOpPure *op_MUL_153 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_133), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_146), DUP(op_AND_146))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_159 = LOGAND(op_RSHIFT_157, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_172 = LOGAND(op_RSHIFT_170, SN(32, 0xffff));
	RzILOpPure *op_MUL_179 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_159), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_172), DUP(op_AND_172))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_SUB_180 = SUB(op_MUL_153, op_MUL_179);
	RzILOpPure *op_ADD_183 = ADD(op_SUB_180, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_185 = SHIFTRA(op_ADD_183, SN(32, 15));
	RzILOpPure *cond_269 = ITE(DUP(op_EQ_127), op_RSHIFT_185, VARL("h_tmp435"));
	RzILOpEffect *op_ASSIGN_271 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_269), DUP(cond_269)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) (( ...;
	RzILOpEffect *seq_272 = SEQN(2, seq_268, op_ASSIGN_271);

	RzILOpEffect *instruction_sequence = seq_272;
	return instruction_sequence;
}

// Rd = cmpyrwh(Rss,Rt*):<<1:rnd:sat
RzILOpEffect *hex_il_op_m4_cmpyr_whc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_188 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_8, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(32, 0xffff));
	RzILOpPure *op_MUL_31 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_10), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))), CAST(32, MSB(DUP(op_AND_10)), DUP(op_AND_10))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_24), DUP(op_AND_24))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_50 = LOGAND(op_RSHIFT_48, SN(32, 0xffff));
	RzILOpPure *op_MUL_57 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_50), DUP(op_AND_50))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_58 = ADD(op_MUL_31, op_MUL_57);
	RzILOpPure *op_ADD_61 = ADD(op_ADD_58, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(op_ADD_61, SN(32, 15));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_72, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_87 = LOGAND(op_RSHIFT_85, SN(32, 0xffff));
	RzILOpPure *op_MUL_94 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_74), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(32, MSB(DUP(op_AND_74)), DUP(op_AND_74))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_87), DUP(op_AND_87))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_98 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_100 = LOGAND(op_RSHIFT_98, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_111 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_113 = LOGAND(op_RSHIFT_111, SN(32, 0xffff));
	RzILOpPure *op_MUL_120 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_100), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))), CAST(32, MSB(DUP(op_AND_100)), DUP(op_AND_100))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_113), DUP(op_AND_113))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_121 = ADD(op_MUL_94, op_MUL_120);
	RzILOpPure *op_ADD_124 = ADD(op_ADD_121, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_126 = SHIFTRA(op_ADD_124, SN(32, 15));
	RzILOpPure *op_EQ_127 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_63), SN(32, 0), SN(32, 0x20)), op_RSHIFT_126);
	RzILOpPure *op_RSHIFT_192 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_194 = LOGAND(op_RSHIFT_192, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_205 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_207 = LOGAND(op_RSHIFT_205, SN(32, 0xffff));
	RzILOpPure *op_MUL_214 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_194), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))), CAST(32, MSB(DUP(op_AND_194)), DUP(op_AND_194))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_207), DUP(op_AND_207))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_218 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_220 = LOGAND(op_RSHIFT_218, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_231 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_233 = LOGAND(op_RSHIFT_231, SN(32, 0xffff));
	RzILOpPure *op_MUL_240 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_220), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))), CAST(32, MSB(DUP(op_AND_220)), DUP(op_AND_220))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_233), DUP(op_AND_233))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_241 = ADD(op_MUL_214, op_MUL_240);
	RzILOpPure *op_ADD_244 = ADD(op_ADD_241, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_246 = SHIFTRA(op_ADD_244, SN(32, 15));
	RzILOpPure *op_LT_249 = SLT(op_RSHIFT_246, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_254 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_255 = NEG(op_LSHIFT_254);
	RzILOpPure *op_LSHIFT_260 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_263 = SUB(op_LSHIFT_260, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_264 = ITE(op_LT_249, op_NEG_255, op_SUB_263);
	RzILOpEffect *gcc_expr_265 = BRANCH(op_EQ_127, EMPTY(), set_usr_field_call_188);

	// h_tmp436 = HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_267 = SETL("h_tmp436", cond_264);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) ((st64 ...;
	RzILOpEffect *seq_268 = SEQN(2, gcc_expr_265, op_ASSIGN_hybrid_tmp_267);

	// Rd = ((st32) ((sextract64(((ut64) (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)), 0x0, 0x20) == (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf)) ? (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x0) & 0xffff))), 0x0, 0x10) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rt >> 0x10) & 0xffff))), 0x0, 0x10) + ((st64) 0x4000) >> 0xf) : h_tmp436));
	RzILOpPure *op_RSHIFT_131 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_133 = LOGAND(op_RSHIFT_131, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rt), SN(32, 0));
	RzILOpPure *op_AND_146 = LOGAND(op_RSHIFT_144, SN(32, 0xffff));
	RzILOpPure *op_MUL_153 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_133), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))), CAST(32, MSB(DUP(op_AND_133)), DUP(op_AND_133))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_146), DUP(op_AND_146))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_159 = LOGAND(op_RSHIFT_157, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_172 = LOGAND(op_RSHIFT_170, SN(32, 0xffff));
	RzILOpPure *op_MUL_179 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_159), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))), CAST(32, MSB(DUP(op_AND_159)), DUP(op_AND_159))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_172), DUP(op_AND_172))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_ADD_180 = ADD(op_MUL_153, op_MUL_179);
	RzILOpPure *op_ADD_183 = ADD(op_ADD_180, CAST(64, MSB(SN(32, 0x4000)), SN(32, 0x4000)));
	RzILOpPure *op_RSHIFT_185 = SHIFTRA(op_ADD_183, SN(32, 15));
	RzILOpPure *cond_269 = ITE(DUP(op_EQ_127), op_RSHIFT_185, VARL("h_tmp436"));
	RzILOpEffect *op_ASSIGN_271 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_269), DUP(cond_269)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st64) ((st32) (( ...;
	RzILOpEffect *seq_272 = SEQN(2, seq_268, op_ASSIGN_271);

	RzILOpEffect *instruction_sequence = seq_272;
	return instruction_sequence;
}

// Rx += mpy(Rs,Rt):<<1:sat
RzILOpEffect *hex_il_op_m4_mac_up_s1_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_35 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f)), 0x0, 0x20) == ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_9 = MUL(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(Rt), DUP(Rt)));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(op_MUL_9, SN(32, 31));
	RzILOpPure *op_ADD_12 = ADD(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_11);
	RzILOpPure *op_MUL_21 = MUL(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(op_MUL_21, SN(32, 31));
	RzILOpPure *op_ADD_24 = ADD(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_23);
	RzILOpPure *op_EQ_25 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_12), SN(32, 0), SN(32, 0x20)), op_ADD_24);
	RzILOpPure *op_MUL_39 = MUL(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(op_MUL_39, SN(32, 31));
	RzILOpPure *op_ADD_42 = ADD(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_41);
	RzILOpPure *op_LT_45 = SLT(op_ADD_42, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_51 = NEG(op_LSHIFT_50);
	RzILOpPure *op_LSHIFT_56 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_59 = SUB(op_LSHIFT_56, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_60 = ITE(op_LT_45, op_NEG_51, op_SUB_59);
	RzILOpEffect *gcc_expr_61 = BRANCH(op_EQ_25, EMPTY(), set_usr_field_call_35);

	// h_tmp437 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f)), 0x0, 0x20) == ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_63 = SETL("h_tmp437", cond_60);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) + (((st64)  ...;
	RzILOpEffect *seq_64 = SEQN(2, gcc_expr_61, op_ASSIGN_hybrid_tmp_63);

	// Rx = ((st32) ((sextract64(((ut64) ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f)), 0x0, 0x20) == ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f)) ? ((st64) Rx) + (((st64) Rs) * ((st64) Rt) >> 0x1f) : h_tmp437));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(op_MUL_29, SN(32, 31));
	RzILOpPure *op_ADD_32 = ADD(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_31);
	RzILOpPure *cond_65 = ITE(DUP(op_EQ_25), op_ADD_32, VARL("h_tmp437"));
	RzILOpEffect *op_ASSIGN_67 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(cond_65), DUP(cond_65)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) + (((st ...;
	RzILOpEffect *seq_68 = SEQN(2, seq_64, op_ASSIGN_67);

	RzILOpEffect *instruction_sequence = seq_68;
	return instruction_sequence;
}

// Rd = add(Ii,mpyi(Rs,II))
RzILOpEffect *hex_il_op_m4_mpyri_addi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_4 = SETL("U", U);

	// Rd = ((st32) u + ((ut32) Rs) * U);
	RzILOpPure *op_MUL_7 = MUL(CAST(32, IL_FALSE, Rs), VARL("U"));
	RzILOpPure *op_ADD_8 = ADD(VARL("u"), op_MUL_7);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_8));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, imm_assign_4, op_ASSIGN_10);
	return instruction_sequence;
}

// Rd = add(Ru,mpyi(Rs,Ii))
RzILOpEffect *hex_il_op_m4_mpyri_addr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Rd = ((st32) ((ut32) Ru) + ((ut32) Rs) * u);
	RzILOpPure *op_MUL_6 = MUL(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(CAST(32, IL_FALSE, Ru), op_MUL_6);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_8));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_10);
	return instruction_sequence;
}

// Rd = add(Ru,mpyi(Ii,Rs))
RzILOpEffect *hex_il_op_m4_mpyri_addr_u2(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Rd = ((st32) ((ut32) Ru) + ((ut32) Rs) * u);
	RzILOpPure *op_MUL_6 = MUL(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(CAST(32, IL_FALSE, Ru), op_MUL_6);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_8));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_10);
	return instruction_sequence;
}

// Rd = add(Ii,mpyi(Rs,Rt))
RzILOpEffect *hex_il_op_m4_mpyrr_addi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Rd = ((st32) u + ((ut32) Rs * Rt));
	RzILOpPure *op_MUL_5 = MUL(Rs, Rt);
	RzILOpPure *op_ADD_7 = ADD(VARL("u"), CAST(32, IL_FALSE, op_MUL_5));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_7));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_9);
	return instruction_sequence;
}

// Ry = add(Ru,mpyi(Ryin,Rs))
RzILOpEffect *hex_il_op_m4_mpyrr_addr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Ry_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ry = READ_REG(pkt, Ry_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Ry = Ru + Rs * Ry;
	RzILOpPure *op_MUL_3 = MUL(Rs, Ry);
	RzILOpPure *op_ADD_4 = ADD(Ru, op_MUL_3);
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Ry_op, op_ADD_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rx -= mpy(Rs,Rt):<<1:sat
RzILOpEffect *hex_il_op_m4_nac_up_s1_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_35 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f)), 0x0, 0x20) == ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_MUL_9 = MUL(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(Rt), DUP(Rt)));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(op_MUL_9, SN(32, 31));
	RzILOpPure *op_SUB_12 = SUB(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_11);
	RzILOpPure *op_MUL_21 = MUL(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(op_MUL_21, SN(32, 31));
	RzILOpPure *op_SUB_24 = SUB(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_23);
	RzILOpPure *op_EQ_25 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_12), SN(32, 0), SN(32, 0x20)), op_SUB_24);
	RzILOpPure *op_MUL_39 = MUL(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_RSHIFT_41 = SHIFTRA(op_MUL_39, SN(32, 31));
	RzILOpPure *op_SUB_42 = SUB(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_41);
	RzILOpPure *op_LT_45 = SLT(op_SUB_42, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_51 = NEG(op_LSHIFT_50);
	RzILOpPure *op_LSHIFT_56 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_59 = SUB(op_LSHIFT_56, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_60 = ITE(op_LT_45, op_NEG_51, op_SUB_59);
	RzILOpEffect *gcc_expr_61 = BRANCH(op_EQ_25, EMPTY(), set_usr_field_call_35);

	// h_tmp438 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f)), 0x0, 0x20) == ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_63 = SETL("h_tmp438", cond_60);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) - (((st64)  ...;
	RzILOpEffect *seq_64 = SEQN(2, gcc_expr_61, op_ASSIGN_hybrid_tmp_63);

	// Rx = ((st32) ((sextract64(((ut64) ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f)), 0x0, 0x20) == ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f)) ? ((st64) Rx) - (((st64) Rs) * ((st64) Rt) >> 0x1f) : h_tmp438));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(DUP(Rt)), DUP(Rt)));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(op_MUL_29, SN(32, 31));
	RzILOpPure *op_SUB_32 = SUB(CAST(64, MSB(READ_REG(pkt, Rx_op, false)), READ_REG(pkt, Rx_op, false)), op_RSHIFT_31);
	RzILOpPure *cond_65 = ITE(DUP(op_EQ_25), op_SUB_32, VARL("h_tmp438"));
	RzILOpEffect *op_ASSIGN_67 = WRITE_REG(bundle, Rx_op, CAST(32, MSB(cond_65), DUP(cond_65)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) Rx) - (((st ...;
	RzILOpEffect *seq_68 = SEQN(2, seq_64, op_ASSIGN_67);

	RzILOpEffect *instruction_sequence = seq_68;
	return instruction_sequence;
}

// Rx |= and(Rs,Rt)
RzILOpEffect *hex_il_op_m4_or_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx | (Rs & Rt));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_OR_4 = LOGOR(READ_REG(pkt, Rx_op, false), op_AND_3);
	RzILOpEffect *op_ASSIGN_OR_5 = WRITE_REG(bundle, Rx_op, op_OR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_OR_5;
	return instruction_sequence;
}

// Rx |= and(Rs,~Rt)
RzILOpEffect *hex_il_op_m4_or_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx | (Rs & (~Rt)));
	RzILOpPure *op_NOT_3 = LOGNOT(Rt);
	RzILOpPure *op_AND_4 = LOGAND(Rs, op_NOT_3);
	RzILOpPure *op_OR_5 = LOGOR(READ_REG(pkt, Rx_op, false), op_AND_4);
	RzILOpEffect *op_ASSIGN_OR_6 = WRITE_REG(bundle, Rx_op, op_OR_5);

	RzILOpEffect *instruction_sequence = op_ASSIGN_OR_6;
	return instruction_sequence;
}

// Rx |= or(Rs,Rt)
RzILOpEffect *hex_il_op_m4_or_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx | (Rs | Rt));
	RzILOpPure *op_OR_3 = LOGOR(Rs, Rt);
	RzILOpPure *op_OR_4 = LOGOR(READ_REG(pkt, Rx_op, false), op_OR_3);
	RzILOpEffect *op_ASSIGN_OR_5 = WRITE_REG(bundle, Rx_op, op_OR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_OR_5;
	return instruction_sequence;
}

// Rx |= xor(Rs,Rt)
RzILOpEffect *hex_il_op_m4_or_xor(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx | (Rs ^ Rt));
	RzILOpPure *op_XOR_3 = LOGXOR(Rs, Rt);
	RzILOpPure *op_OR_4 = LOGOR(READ_REG(pkt, Rx_op, false), op_XOR_3);
	RzILOpEffect *op_ASSIGN_OR_5 = WRITE_REG(bundle, Rx_op, op_OR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_OR_5;
	return instruction_sequence;
}

// Rdd = pmpyw(Rs,Rt)
RzILOpEffect *hex_il_op_m4_pmpyw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rxx ^= pmpyw(Rs,Rt)
RzILOpEffect *hex_il_op_m4_pmpyw_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = vpmpyh(Rs,Rt)
RzILOpEffect *hex_il_op_m4_vpmpyh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: ut32 x0;
	// Declare: ut32 x1;
	// Declare: ut32 y0;
	// Declare: ut32 y1;
	// Declare: ut32 prod0;
	// Declare: ut32 prod1;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// x0 = ((ut32) ((ut16) ((Rs >> 0x0) & 0xffff)));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_16 = SETL("x0", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_13)));

	// x1 = ((ut32) ((ut16) ((Rs >> 0x10) & 0xffff)));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_25 = SETL("x1", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_22)));

	// y0 = ((ut32) ((ut16) ((Rt >> 0x0) & 0xffff)));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_35 = SETL("y0", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_32)));

	// y1 = ((ut32) ((ut16) ((Rt >> 0x10) & 0xffff)));
	RzILOpPure *op_RSHIFT_39 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_41 = LOGAND(op_RSHIFT_39, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_44 = SETL("y1", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_41)));

	// prod1 = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_47 = SETL("prod1", CAST(32, IL_FALSE, SN(32, 0)));

	// prod0 = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_48 = SETL("prod0", CAST(32, IL_FALSE, SN(32, 0)));

	// seq(prod0 = ((ut32) 0x0); prod1 = ((ut32) 0x0));
	RzILOpEffect *seq_49 = SEQN(2, op_ASSIGN_48, op_ASSIGN_47);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_51 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_54 = SETL("i", INC(VARL("i"), 32));

	// h_tmp439 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_56 = SETL("h_tmp439", VARL("i"));

	// seq(h_tmp439 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_57 = SEQN(2, op_ASSIGN_hybrid_tmp_56, op_INC_54);

	// prod0 = (prod0 ^ (x0 << i));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(VARL("x0"), VARL("i"));
	RzILOpPure *op_XOR_63 = LOGXOR(VARL("prod0"), op_LSHIFT_62);
	RzILOpEffect *op_ASSIGN_XOR_64 = SETL("prod0", op_XOR_63);

	// seq(prod0 = (prod0 ^ (x0 << i)));
	RzILOpEffect *seq_then_65 = op_ASSIGN_XOR_64;

	// if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = (prod0 ^ (x0 << i)))} else {{}};
	RzILOpPure *op_RSHIFT_58 = SHIFTR0(VARL("y0"), VARL("i"));
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_66 = BRANCH(NON_ZERO(op_AND_61), seq_then_65, EMPTY());

	// prod1 = (prod1 ^ (x1 << i));
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(VARL("x1"), VARL("i"));
	RzILOpPure *op_XOR_72 = LOGXOR(VARL("prod1"), op_LSHIFT_71);
	RzILOpEffect *op_ASSIGN_XOR_73 = SETL("prod1", op_XOR_72);

	// seq(prod1 = (prod1 ^ (x1 << i)));
	RzILOpEffect *seq_then_74 = op_ASSIGN_XOR_73;

	// if (((y1 >> i) & ((ut32) 0x1))) {seq(prod1 = (prod1 ^ (x1 << i)))} else {{}};
	RzILOpPure *op_RSHIFT_67 = SHIFTR0(VARL("y1"), VARL("i"));
	RzILOpPure *op_AND_70 = LOGAND(op_RSHIFT_67, CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_75 = BRANCH(NON_ZERO(op_AND_70), seq_then_74, EMPTY());

	// seq(h_tmp439; if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = (prod ...;
	RzILOpEffect *seq_76 = SEQN(2, branch_66, branch_75);

	// seq(seq(h_tmp439; if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = ( ...;
	RzILOpEffect *seq_77 = SEQN(2, seq_76, seq_57);

	// while ((i < 0x10)) { seq(seq(h_tmp439; if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = ( ... };
	RzILOpPure *op_LT_53 = SLT(VARL("i"), SN(32, 16));
	RzILOpEffect *for_78 = REPEAT(op_LT_53, seq_77);

	// seq(i = 0x0; while ((i < 0x10)) { seq(seq(h_tmp439; if (((y0 >>  ...;
	RzILOpEffect *seq_79 = SEQN(2, op_ASSIGN_51, for_78);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st32) ((ut16) ((prod0 >> 0x0) & ((ut32) 0xffff)))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_85 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_86 = LOGNOT(op_LSHIFT_85);
	RzILOpPure *op_AND_87 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_86);
	RzILOpPure *op_RSHIFT_91 = SHIFTR0(VARL("prod0"), SN(32, 0));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_AND_98 = LOGAND(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_94)), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_103 = SHIFTL0(CAST(64, IL_FALSE, op_AND_98), SN(32, 0));
	RzILOpPure *op_OR_105 = LOGOR(CAST(64, IL_FALSE, op_AND_87), op_LSHIFT_103);
	RzILOpEffect *op_ASSIGN_107 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_105));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st32) ((ut16) ((prod1 >> 0x0) & ((ut32) 0xffff)))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_113 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_114 = LOGNOT(op_LSHIFT_113);
	RzILOpPure *op_AND_115 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_114);
	RzILOpPure *op_RSHIFT_119 = SHIFTR0(VARL("prod1"), SN(32, 0));
	RzILOpPure *op_AND_122 = LOGAND(op_RSHIFT_119, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_AND_126 = LOGAND(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_122)), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_131 = SHIFTL0(CAST(64, IL_FALSE, op_AND_126), SN(32, 16));
	RzILOpPure *op_OR_133 = LOGOR(CAST(64, IL_FALSE, op_AND_115), op_LSHIFT_131);
	RzILOpEffect *op_ASSIGN_135 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_133));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st32) ((ut16) ((prod0 >> 0x10) & ((ut32) 0xffff)))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_141 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_142 = LOGNOT(op_LSHIFT_141);
	RzILOpPure *op_AND_143 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_142);
	RzILOpPure *op_RSHIFT_147 = SHIFTR0(VARL("prod0"), SN(32, 16));
	RzILOpPure *op_AND_150 = LOGAND(op_RSHIFT_147, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_AND_154 = LOGAND(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_150)), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_159 = SHIFTL0(CAST(64, IL_FALSE, op_AND_154), SN(32, 0x20));
	RzILOpPure *op_OR_161 = LOGOR(CAST(64, IL_FALSE, op_AND_143), op_LSHIFT_159);
	RzILOpEffect *op_ASSIGN_163 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_161));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st32) ((ut16) ((prod1 >> 0x10) & ((ut32) 0xffff)))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_169 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_170 = LOGNOT(op_LSHIFT_169);
	RzILOpPure *op_AND_171 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_170);
	RzILOpPure *op_RSHIFT_175 = SHIFTR0(VARL("prod1"), SN(32, 16));
	RzILOpPure *op_AND_178 = LOGAND(op_RSHIFT_175, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_AND_182 = LOGAND(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_178)), SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_187 = SHIFTL0(CAST(64, IL_FALSE, op_AND_182), SN(32, 0x30));
	RzILOpPure *op_OR_189 = LOGOR(CAST(64, IL_FALSE, op_AND_171), op_LSHIFT_187);
	RzILOpEffect *op_ASSIGN_191 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_189));

	RzILOpEffect *instruction_sequence = SEQN(10, op_ASSIGN_16, op_ASSIGN_25, op_ASSIGN_35, op_ASSIGN_44, seq_49, seq_79, op_ASSIGN_107, op_ASSIGN_135, op_ASSIGN_163, op_ASSIGN_191);
	return instruction_sequence;
}

// Rxx ^= vpmpyh(Rs,Rt)
RzILOpEffect *hex_il_op_m4_vpmpyh_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: ut32 x0;
	// Declare: ut32 x1;
	// Declare: ut32 y0;
	// Declare: ut32 y1;
	// Declare: ut32 prod0;
	// Declare: ut32 prod1;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	// x0 = ((ut32) ((ut16) ((Rs >> 0x0) & 0xffff)));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_16 = SETL("x0", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_13)));

	// x1 = ((ut32) ((ut16) ((Rs >> 0x10) & 0xffff)));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_25 = SETL("x1", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_22)));

	// y0 = ((ut32) ((ut16) ((Rt >> 0x0) & 0xffff)));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_35 = SETL("y0", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_32)));

	// y1 = ((ut32) ((ut16) ((Rt >> 0x10) & 0xffff)));
	RzILOpPure *op_RSHIFT_39 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_41 = LOGAND(op_RSHIFT_39, SN(32, 0xffff));
	RzILOpEffect *op_ASSIGN_44 = SETL("y1", CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_41)));

	// prod1 = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_47 = SETL("prod1", CAST(32, IL_FALSE, SN(32, 0)));

	// prod0 = ((ut32) 0x0);
	RzILOpEffect *op_ASSIGN_48 = SETL("prod0", CAST(32, IL_FALSE, SN(32, 0)));

	// seq(prod0 = ((ut32) 0x0); prod1 = ((ut32) 0x0));
	RzILOpEffect *seq_49 = SEQN(2, op_ASSIGN_48, op_ASSIGN_47);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_51 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_54 = SETL("i", INC(VARL("i"), 32));

	// h_tmp440 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_56 = SETL("h_tmp440", VARL("i"));

	// seq(h_tmp440 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_57 = SEQN(2, op_ASSIGN_hybrid_tmp_56, op_INC_54);

	// prod0 = (prod0 ^ (x0 << i));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(VARL("x0"), VARL("i"));
	RzILOpPure *op_XOR_63 = LOGXOR(VARL("prod0"), op_LSHIFT_62);
	RzILOpEffect *op_ASSIGN_XOR_64 = SETL("prod0", op_XOR_63);

	// seq(prod0 = (prod0 ^ (x0 << i)));
	RzILOpEffect *seq_then_65 = op_ASSIGN_XOR_64;

	// if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = (prod0 ^ (x0 << i)))} else {{}};
	RzILOpPure *op_RSHIFT_58 = SHIFTR0(VARL("y0"), VARL("i"));
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_66 = BRANCH(NON_ZERO(op_AND_61), seq_then_65, EMPTY());

	// prod1 = (prod1 ^ (x1 << i));
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(VARL("x1"), VARL("i"));
	RzILOpPure *op_XOR_72 = LOGXOR(VARL("prod1"), op_LSHIFT_71);
	RzILOpEffect *op_ASSIGN_XOR_73 = SETL("prod1", op_XOR_72);

	// seq(prod1 = (prod1 ^ (x1 << i)));
	RzILOpEffect *seq_then_74 = op_ASSIGN_XOR_73;

	// if (((y1 >> i) & ((ut32) 0x1))) {seq(prod1 = (prod1 ^ (x1 << i)))} else {{}};
	RzILOpPure *op_RSHIFT_67 = SHIFTR0(VARL("y1"), VARL("i"));
	RzILOpPure *op_AND_70 = LOGAND(op_RSHIFT_67, CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpEffect *branch_75 = BRANCH(NON_ZERO(op_AND_70), seq_then_74, EMPTY());

	// seq(h_tmp440; if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = (prod ...;
	RzILOpEffect *seq_76 = SEQN(2, branch_66, branch_75);

	// seq(seq(h_tmp440; if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = ( ...;
	RzILOpEffect *seq_77 = SEQN(2, seq_76, seq_57);

	// while ((i < 0x10)) { seq(seq(h_tmp440; if (((y0 >> i) & ((ut32) 0x1))) {seq(prod0 = ( ... };
	RzILOpPure *op_LT_53 = SLT(VARL("i"), SN(32, 16));
	RzILOpEffect *for_78 = REPEAT(op_LT_53, seq_77);

	// seq(i = 0x0; while ((i < 0x10)) { seq(seq(h_tmp440; if (((y0 >>  ...;
	RzILOpEffect *seq_79 = SEQN(2, op_ASSIGN_51, for_78);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x0)))) | (((ut64) ((((st32) ((ut16) ((Rxx >> 0x0) & ((st64) 0xffff)))) ^ ((st32) ((ut16) ((prod0 >> 0x0) & ((ut32) 0xffff))))) & 0xffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_85 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_86 = LOGNOT(op_LSHIFT_85);
	RzILOpPure *op_AND_87 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_86);
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_99 = SHIFTR0(VARL("prod0"), SN(32, 0));
	RzILOpPure *op_AND_102 = LOGAND(op_RSHIFT_99, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_XOR_106 = LOGXOR(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_94)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_102)));
	RzILOpPure *op_AND_108 = LOGAND(op_XOR_106, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_113 = SHIFTL0(CAST(64, IL_FALSE, op_AND_108), SN(32, 0));
	RzILOpPure *op_OR_115 = LOGOR(CAST(64, IL_FALSE, op_AND_87), op_LSHIFT_113);
	RzILOpEffect *op_ASSIGN_117 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_115));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x10)))) | (((ut64) ((((st32) ((ut16) ((Rxx >> 0x10) & ((st64) 0xffff)))) ^ ((st32) ((ut16) ((prod1 >> 0x0) & ((ut32) 0xffff))))) & 0xffff)) << 0x10)));
	RzILOpPure *op_LSHIFT_123 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_124 = LOGNOT(op_LSHIFT_123);
	RzILOpPure *op_AND_125 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_124);
	RzILOpPure *op_RSHIFT_129 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_132 = LOGAND(op_RSHIFT_129, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_137 = SHIFTR0(VARL("prod1"), SN(32, 0));
	RzILOpPure *op_AND_140 = LOGAND(op_RSHIFT_137, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_XOR_144 = LOGXOR(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_132)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_140)));
	RzILOpPure *op_AND_146 = LOGAND(op_XOR_144, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_151 = SHIFTL0(CAST(64, IL_FALSE, op_AND_146), SN(32, 16));
	RzILOpPure *op_OR_153 = LOGOR(CAST(64, IL_FALSE, op_AND_125), op_LSHIFT_151);
	RzILOpEffect *op_ASSIGN_155 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_153));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x20)))) | (((ut64) ((((st32) ((ut16) ((Rxx >> 0x20) & ((st64) 0xffff)))) ^ ((st32) ((ut16) ((prod0 >> 0x10) & ((ut32) 0xffff))))) & 0xffff)) << 0x20)));
	RzILOpPure *op_LSHIFT_161 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_162 = LOGNOT(op_LSHIFT_161);
	RzILOpPure *op_AND_163 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_162);
	RzILOpPure *op_RSHIFT_167 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_170 = LOGAND(op_RSHIFT_167, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_175 = SHIFTR0(VARL("prod0"), SN(32, 16));
	RzILOpPure *op_AND_178 = LOGAND(op_RSHIFT_175, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_XOR_182 = LOGXOR(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_170)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_178)));
	RzILOpPure *op_AND_184 = LOGAND(op_XOR_182, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_189 = SHIFTL0(CAST(64, IL_FALSE, op_AND_184), SN(32, 0x20));
	RzILOpPure *op_OR_191 = LOGOR(CAST(64, IL_FALSE, op_AND_163), op_LSHIFT_189);
	RzILOpEffect *op_ASSIGN_193 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_191));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x30)))) | (((ut64) ((((st32) ((ut16) ((Rxx >> 0x30) & ((st64) 0xffff)))) ^ ((st32) ((ut16) ((prod1 >> 0x10) & ((ut32) 0xffff))))) & 0xffff)) << 0x30)));
	RzILOpPure *op_LSHIFT_199 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_200 = LOGNOT(op_LSHIFT_199);
	RzILOpPure *op_AND_201 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_200);
	RzILOpPure *op_RSHIFT_205 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_208 = LOGAND(op_RSHIFT_205, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_213 = SHIFTR0(VARL("prod1"), SN(32, 16));
	RzILOpPure *op_AND_216 = LOGAND(op_RSHIFT_213, CAST(32, IL_FALSE, SN(32, 0xffff)));
	RzILOpPure *op_XOR_220 = LOGXOR(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_208)), CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_216)));
	RzILOpPure *op_AND_222 = LOGAND(op_XOR_220, SN(32, 0xffff));
	RzILOpPure *op_LSHIFT_227 = SHIFTL0(CAST(64, IL_FALSE, op_AND_222), SN(32, 0x30));
	RzILOpPure *op_OR_229 = LOGOR(CAST(64, IL_FALSE, op_AND_201), op_LSHIFT_227);
	RzILOpEffect *op_ASSIGN_231 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_229));

	RzILOpEffect *instruction_sequence = SEQN(10, op_ASSIGN_16, op_ASSIGN_25, op_ASSIGN_35, op_ASSIGN_44, seq_49, seq_79, op_ASSIGN_117, op_ASSIGN_155, op_ASSIGN_193, op_ASSIGN_231);
	return instruction_sequence;
}

// Rxx += vrmpyweh(Rss,Rtt)
RzILOpEffect *hex_il_op_m4_vrmpyeh_acc_s0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 0));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 0));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpPure *op_ADD_62 = ADD(READ_REG(pkt, Rxx_op, false), op_ADD_61);
	RzILOpEffect *op_ASSIGN_ADD_63 = WRITE_REG(bundle, Rxx_op, op_ADD_62);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_63;
	return instruction_sequence;
}

// Rxx += vrmpyweh(Rss,Rtt):<<1
RzILOpEffect *hex_il_op_m4_vrmpyeh_acc_s1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 1));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpPure *op_ADD_62 = ADD(READ_REG(pkt, Rxx_op, false), op_ADD_61);
	RzILOpEffect *op_ASSIGN_ADD_63 = WRITE_REG(bundle, Rxx_op, op_ADD_62);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_63;
	return instruction_sequence;
}

// Rdd = vrmpyweh(Rss,Rtt)
RzILOpEffect *hex_il_op_m4_vrmpyeh_s0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 0));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 0));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpEffect *op_ASSIGN_62 = WRITE_REG(bundle, Rdd_op, op_ADD_61);

	RzILOpEffect *instruction_sequence = op_ASSIGN_62;
	return instruction_sequence;
}

// Rdd = vrmpyweh(Rss,Rtt):<<1
RzILOpEffect *hex_il_op_m4_vrmpyeh_s1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 1));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpEffect *op_ASSIGN_62 = WRITE_REG(bundle, Rdd_op, op_ADD_61);

	RzILOpEffect *instruction_sequence = op_ASSIGN_62;
	return instruction_sequence;
}

// Rxx += vrmpywoh(Rss,Rtt)
RzILOpEffect *hex_il_op_m4_vrmpyoh_acc_s0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x30));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 0));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 0));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpPure *op_ADD_62 = ADD(READ_REG(pkt, Rxx_op, false), op_ADD_61);
	RzILOpEffect *op_ASSIGN_ADD_63 = WRITE_REG(bundle, Rxx_op, op_ADD_62);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_63;
	return instruction_sequence;
}

// Rxx += vrmpywoh(Rss,Rtt):<<1
RzILOpEffect *hex_il_op_m4_vrmpyoh_acc_s1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x30));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 1));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpPure *op_ADD_62 = ADD(READ_REG(pkt, Rxx_op, false), op_ADD_61);
	RzILOpEffect *op_ASSIGN_ADD_63 = WRITE_REG(bundle, Rxx_op, op_ADD_62);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_63;
	return instruction_sequence;
}

// Rdd = vrmpywoh(Rss,Rtt)
RzILOpEffect *hex_il_op_m4_vrmpyoh_s0(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))), 0x0, 0x10) << 0x0);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x30));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 0));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 0));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpEffect *op_ASSIGN_62 = WRITE_REG(bundle, Rdd_op, op_ADD_61);

	RzILOpEffect *instruction_sequence = op_ASSIGN_62;
	return instruction_sequence;
}

// Rdd = vrmpywoh(Rss,Rtt):<<1
RzILOpEffect *hex_il_op_m4_vrmpyoh_s1(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1) + (((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * sextract64(((ut64) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))), 0x0, 0x10) << 0x1);
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, SN(32, 0x30));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_22), DUP(op_AND_22))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_58 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_37), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))), CAST(32, MSB(DUP(op_AND_37)), DUP(op_AND_37))))), SEXTRACT64(CAST(64, IL_FALSE, CAST(16, MSB(op_AND_51), DUP(op_AND_51))), SN(32, 0), SN(32, 16)));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(op_MUL_58, SN(32, 1));
	RzILOpPure *op_ADD_61 = ADD(op_LSHIFT_31, op_LSHIFT_60);
	RzILOpEffect *op_ASSIGN_62 = WRITE_REG(bundle, Rdd_op, op_ADD_61);

	RzILOpEffect *instruction_sequence = op_ASSIGN_62;
	return instruction_sequence;
}

// Rx ^= and(Rs,Rt)
RzILOpEffect *hex_il_op_m4_xor_and(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx ^ (Rs & Rt));
	RzILOpPure *op_AND_3 = LOGAND(Rs, Rt);
	RzILOpPure *op_XOR_4 = LOGXOR(READ_REG(pkt, Rx_op, false), op_AND_3);
	RzILOpEffect *op_ASSIGN_XOR_5 = WRITE_REG(bundle, Rx_op, op_XOR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_XOR_5;
	return instruction_sequence;
}

// Rx ^= and(Rs,~Rt)
RzILOpEffect *hex_il_op_m4_xor_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx ^ (Rs & (~Rt)));
	RzILOpPure *op_NOT_3 = LOGNOT(Rt);
	RzILOpPure *op_AND_4 = LOGAND(Rs, op_NOT_3);
	RzILOpPure *op_XOR_5 = LOGXOR(READ_REG(pkt, Rx_op, false), op_AND_4);
	RzILOpEffect *op_ASSIGN_XOR_6 = WRITE_REG(bundle, Rx_op, op_XOR_5);

	RzILOpEffect *instruction_sequence = op_ASSIGN_XOR_6;
	return instruction_sequence;
}

// Rx ^= or(Rs,Rt)
RzILOpEffect *hex_il_op_m4_xor_or(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rx = (Rx ^ (Rs | Rt));
	RzILOpPure *op_OR_3 = LOGOR(Rs, Rt);
	RzILOpPure *op_XOR_4 = LOGXOR(READ_REG(pkt, Rx_op, false), op_OR_3);
	RzILOpEffect *op_ASSIGN_XOR_5 = WRITE_REG(bundle, Rx_op, op_XOR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_XOR_5;
	return instruction_sequence;
}

// Rxx ^= xor(Rss,Rtt)
RzILOpEffect *hex_il_op_m4_xor_xacc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = (Rxx ^ (Rss ^ Rtt));
	RzILOpPure *op_XOR_3 = LOGXOR(Rss, Rtt);
	RzILOpPure *op_XOR_4 = LOGXOR(READ_REG(pkt, Rxx_op, false), op_XOR_3);
	RzILOpEffect *op_ASSIGN_XOR_5 = WRITE_REG(bundle, Rxx_op, op_XOR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_XOR_5;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>