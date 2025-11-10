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

// Rdd = vabsdiffb(Rtt,Rss)
RzILOpEffect *hex_il_op_m6_vabsdiffb(HexInsnPktBundle *bundle) {
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

	// h_tmp449 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp449", VARL("i"));

	// seq(h_tmp449 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((((st32) ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? (-((st32) ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((st8) ((Rss >> i * 0x8) & ((st64) 0xff))))) : ((st32) ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_34 = SUB(CAST(32, MSB(CAST(8, MSB(op_AND_22), DUP(op_AND_22))), CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(32, MSB(CAST(8, MSB(op_AND_30), DUP(op_AND_30))), CAST(8, MSB(DUP(op_AND_30)), DUP(op_AND_30))));
	RzILOpPure *op_LT_36 = SLT(op_SUB_34, SN(32, 0));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_39 = SHIFTRA(DUP(Rtt), op_MUL_38);
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_39, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_46 = SHIFTRA(DUP(Rss), op_MUL_45);
	RzILOpPure *op_AND_49 = LOGAND(op_RSHIFT_46, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_53 = SUB(CAST(32, MSB(CAST(8, MSB(op_AND_42), DUP(op_AND_42))), CAST(8, MSB(DUP(op_AND_42)), DUP(op_AND_42))), CAST(32, MSB(CAST(8, MSB(op_AND_49), DUP(op_AND_49))), CAST(8, MSB(DUP(op_AND_49)), DUP(op_AND_49))));
	RzILOpPure *op_NEG_54 = NEG(op_SUB_53);
	RzILOpPure *op_MUL_56 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rtt), op_MUL_56);
	RzILOpPure *op_AND_60 = LOGAND(op_RSHIFT_57, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rss), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_71 = SUB(CAST(32, MSB(CAST(8, MSB(op_AND_60), DUP(op_AND_60))), CAST(8, MSB(DUP(op_AND_60)), DUP(op_AND_60))), CAST(32, MSB(CAST(8, MSB(op_AND_67), DUP(op_AND_67))), CAST(8, MSB(DUP(op_AND_67)), DUP(op_AND_67))));
	RzILOpPure *cond_72 = ITE(op_LT_36, op_NEG_54, op_SUB_71);
	RzILOpPure *op_AND_75 = LOGAND(CAST(64, MSB(cond_72), DUP(cond_72)), SN(64, 0xff));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_79 = SHIFTL0(CAST(64, IL_FALSE, op_AND_75), op_MUL_78);
	RzILOpPure *op_OR_81 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_79);
	RzILOpEffect *op_ASSIGN_83 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_81));

	// seq(h_tmp449; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_85 = op_ASSIGN_83;

	// seq(seq(h_tmp449; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_86 = SEQN(2, seq_85, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp449; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_87 = REPEAT(op_LT_4, seq_86);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp449; Rdd = ((st64) ...;
	RzILOpEffect *seq_88 = SEQN(2, op_ASSIGN_2, for_87);

	RzILOpEffect *instruction_sequence = seq_88;
	return instruction_sequence;
}

// Rdd = vabsdiffub(Rtt,Rss)
RzILOpEffect *hex_il_op_m6_vabsdiffub(HexInsnPktBundle *bundle) {
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

	// h_tmp450 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp450", VARL("i"));

	// seq(h_tmp450 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) < 0x0) ? (-((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff))))) : ((st32) ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) - ((st32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_34 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_30)));
	RzILOpPure *op_LT_36 = SLT(op_SUB_34, SN(32, 0));
	RzILOpPure *op_MUL_38 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_39 = SHIFTRA(DUP(Rtt), op_MUL_38);
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_39, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_46 = SHIFTRA(DUP(Rss), op_MUL_45);
	RzILOpPure *op_AND_49 = LOGAND(op_RSHIFT_46, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_53 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_42)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_49)));
	RzILOpPure *op_NEG_54 = NEG(op_SUB_53);
	RzILOpPure *op_MUL_56 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rtt), op_MUL_56);
	RzILOpPure *op_AND_60 = LOGAND(op_RSHIFT_57, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_63 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rss), op_MUL_63);
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_SUB_71 = SUB(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_60)), CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_67)));
	RzILOpPure *cond_72 = ITE(op_LT_36, op_NEG_54, op_SUB_71);
	RzILOpPure *op_AND_75 = LOGAND(CAST(64, MSB(cond_72), DUP(cond_72)), SN(64, 0xff));
	RzILOpPure *op_MUL_78 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_79 = SHIFTL0(CAST(64, IL_FALSE, op_AND_75), op_MUL_78);
	RzILOpPure *op_OR_81 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_79);
	RzILOpEffect *op_ASSIGN_83 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_81));

	// seq(h_tmp450; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)) ...;
	RzILOpEffect *seq_85 = op_ASSIGN_83;

	// seq(seq(h_tmp450; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ...;
	RzILOpEffect *seq_86 = SEQN(2, seq_85, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp450; Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0 ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_87 = REPEAT(op_LT_4, seq_86);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp450; Rdd = ((st64) ...;
	RzILOpEffect *seq_88 = SEQN(2, op_ASSIGN_2, for_87);

	RzILOpEffect *instruction_sequence = seq_88;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>