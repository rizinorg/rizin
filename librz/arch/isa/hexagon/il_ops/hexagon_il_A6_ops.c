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

// Pd = !any8(vcmpb.eq(Rss,Rtt))
RzILOpEffect *hex_il_op_a6_vcmpbeq_notany(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) 0x0);
	RzILOpEffect *op_ASSIGN_4 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(SN(32, 0)), SN(32, 0)));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_6 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_9 = SETL("i", INC(VARL("i"), 32));

	// h_tmp151 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp151", VARL("i"));

	// seq(h_tmp151 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_12 = SEQN(2, op_ASSIGN_hybrid_tmp_11, op_INC_9);

	// Pd = ((st8) 0xff);
	RzILOpEffect *op_ASSIGN_32 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(SN(32, 0xff)), SN(32, 0xff)));

	// seq(Pd = ((st8) 0xff));
	RzILOpEffect *seq_then_33 = op_ASSIGN_32;

	// if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff))) == ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff))))) {seq(Pd = ((st8) 0xff))} else {{}};
	RzILOpPure *op_MUL_15 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rss, op_MUL_15);
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_16, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_23 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, op_MUL_23);
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_EQ_29 = EQ(CAST(8, MSB(op_AND_19), DUP(op_AND_19)), CAST(8, MSB(op_AND_27), DUP(op_AND_27)));
	RzILOpEffect *branch_34 = BRANCH(op_EQ_29, seq_then_33, EMPTY());

	// seq(h_tmp151; if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff))) == ...;
	RzILOpEffect *seq_35 = branch_34;

	// seq(seq(h_tmp151; if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff)) ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_12);

	// while ((i < 0x8)) { seq(seq(h_tmp151; if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff)) ... };
	RzILOpPure *op_LT_8 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_37 = REPEAT(op_LT_8, seq_36);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp151; if ((((st8) ( ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_6, for_37);

	// Pd = ((st8) (~((st32) Pd)));
	RzILOpPure *op_NOT_40 = LOGNOT(CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true)));
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(op_NOT_40), DUP(op_NOT_40)));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_4, seq_38, op_ASSIGN_42);
	return instruction_sequence;
}

// Rdd,Pe = vminub(Rtt,Rss)
RzILOpEffect *hex_il_op_a6_vminub_rdp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pe_op = ISA2REG(hi, 'e', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp152 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp152", VARL("i"));

	// seq(h_tmp152 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pe = ((st8) ((((ut64) ((st32) Pe)) & (~(0x1 << i))) | (((((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) > ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pe_op, true)), READ_REG(pkt, Pe_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rtt, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rss, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_32 = UGT(CAST(8, IL_FALSE, op_AND_22), CAST(8, IL_FALSE, op_AND_30));
	RzILOpPure *ite_cast_ut64_33 = ITE(op_GT_32, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(ite_cast_ut64_33, VARL("i"));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_15, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Pe_op, CAST(8, IL_FALSE, op_OR_35));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xff << i * 0x8)))) | (((ut64) (((st64) ((st32) ((((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) < ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) ? ((ut8) ((Rtt >> i * 0x8) & ((st64) 0xff))) : ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))))) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(SN(64, 0xff), op_MUL_42);
	RzILOpPure *op_NOT_44 = LOGNOT(op_LSHIFT_43);
	RzILOpPure *op_AND_45 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_44);
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), op_MUL_47);
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_55 = SHIFTRA(DUP(Rss), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_55, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_LT_60 = ULT(CAST(8, IL_FALSE, op_AND_51), CAST(8, IL_FALSE, op_AND_58));
	RzILOpPure *op_MUL_62 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(DUP(Rtt), op_MUL_62);
	RzILOpPure *op_AND_66 = LOGAND(op_RSHIFT_63, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_69 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_70 = SHIFTRA(DUP(Rss), op_MUL_69);
	RzILOpPure *op_AND_73 = LOGAND(op_RSHIFT_70, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *cond_75 = ITE(op_LT_60, CAST(8, IL_FALSE, op_AND_66), CAST(8, IL_FALSE, op_AND_73));
	RzILOpPure *op_AND_79 = LOGAND(CAST(64, MSB(CAST(32, IL_FALSE, cond_75)), CAST(32, IL_FALSE, DUP(cond_75))), SN(64, 0xff));
	RzILOpPure *op_MUL_82 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_83 = SHIFTL0(CAST(64, IL_FALSE, op_AND_79), op_MUL_82);
	RzILOpPure *op_OR_85 = LOGOR(CAST(64, IL_FALSE, op_AND_45), op_LSHIFT_83);
	RzILOpEffect *op_ASSIGN_87 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_85));

	// seq(h_tmp152; Pe = ((st8) ((((ut64) ((st32) Pe)) & (~(0x1 << i)) ...;
	RzILOpEffect *seq_89 = SEQN(2, op_ASSIGN_37, op_ASSIGN_87);

	// seq(seq(h_tmp152; Pe = ((st8) ((((ut64) ((st32) Pe)) & (~(0x1 << ...;
	RzILOpEffect *seq_90 = SEQN(2, seq_89, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp152; Pe = ((st8) ((((ut64) ((st32) Pe)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_91 = REPEAT(op_LT_4, seq_90);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp152; Pe = ((st8) ( ...;
	RzILOpEffect *seq_92 = SEQN(2, op_ASSIGN_2, for_91);

	RzILOpEffect *instruction_sequence = seq_92;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>