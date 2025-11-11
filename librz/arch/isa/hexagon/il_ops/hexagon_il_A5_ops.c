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

// Rxx,Pe = vacsh(Rss,Rtt)
RzILOpEffect *hex_il_op_a5_acs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st32 xv;
	// Declare: st32 sv;
	// Declare: st32 tv;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Pe_op = ISA2REG(hi, 'e', false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_5 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_8 = SETL("i", INC(VARL("i"), 32));

	// h_tmp147 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_10 = SETL("h_tmp147", VARL("i"));

	// seq(h_tmp147 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_11 = SEQN(2, op_ASSIGN_hybrid_tmp_10, op_INC_8);

	// xv = ((st32) ((st16) ((Rxx >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_14 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(READ_REG(pkt, Rxx_op, false), op_MUL_14);
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_21 = SETL("xv", CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))));

	// sv = ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_25 = SHIFTRA(Rss, op_MUL_24);
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_25, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_31 = SETL("sv", CAST(32, MSB(CAST(16, MSB(op_AND_28), DUP(op_AND_28))), CAST(16, MSB(DUP(op_AND_28)), DUP(op_AND_28))));

	// tv = ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(Rtt, op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_41 = SETL("tv", CAST(32, MSB(CAST(16, MSB(op_AND_38), DUP(op_AND_38))), CAST(16, MSB(DUP(op_AND_38)), DUP(op_AND_38))));

	// xv = xv + tv;
	RzILOpPure *op_ADD_42 = ADD(VARL("xv"), VARL("tv"));
	RzILOpEffect *op_ASSIGN_43 = SETL("xv", op_ADD_42);

	// sv = sv - tv;
	RzILOpPure *op_SUB_44 = SUB(VARL("sv"), VARL("tv"));
	RzILOpEffect *op_ASSIGN_45 = SETL("sv", op_SUB_44);

	// Pe = ((st8) ((((ut64) ((st32) Pe)) & (~(0x1 << i * 0x2))) | (((xv > sv) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(UN(64, 1), op_MUL_49);
	RzILOpPure *op_NOT_51 = LOGNOT(op_LSHIFT_50);
	RzILOpPure *op_AND_54 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pe_op, true)), READ_REG(pkt, Pe_op, true))), op_NOT_51);
	RzILOpPure *op_GT_55 = SGT(VARL("xv"), VARL("sv"));
	RzILOpPure *ite_cast_ut64_56 = ITE(op_GT_55, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_58 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_59 = SHIFTL0(ite_cast_ut64_56, op_MUL_58);
	RzILOpPure *op_OR_60 = LOGOR(op_AND_54, op_LSHIFT_59);
	RzILOpEffect *op_ASSIGN_62 = WRITE_REG(bundle, Pe_op, CAST(8, IL_FALSE, op_OR_60));

	// Pe = ((st8) ((((ut64) ((st32) Pe)) & (~(0x1 << i * 0x2 + 0x1))) | (((xv > sv) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_66 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_68 = ADD(op_MUL_66, SN(32, 1));
	RzILOpPure *op_LSHIFT_69 = SHIFTL0(UN(64, 1), op_ADD_68);
	RzILOpPure *op_NOT_70 = LOGNOT(op_LSHIFT_69);
	RzILOpPure *op_AND_73 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pe_op, true)), READ_REG(pkt, Pe_op, true))), op_NOT_70);
	RzILOpPure *op_GT_74 = SGT(VARL("xv"), VARL("sv"));
	RzILOpPure *ite_cast_ut64_75 = ITE(op_GT_74, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_77 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_79 = ADD(op_MUL_77, SN(32, 1));
	RzILOpPure *op_LSHIFT_80 = SHIFTL0(ite_cast_ut64_75, op_ADD_79);
	RzILOpPure *op_OR_81 = LOGOR(op_AND_73, op_LSHIFT_80);
	RzILOpEffect *op_ASSIGN_83 = WRITE_REG(bundle, Pe_op, CAST(8, IL_FALSE, op_OR_81));

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_109 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((xv > sv) ? xv : sv)), 0x0, 0x10) == ((st64) ((xv > sv) ? xv : sv)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((xv > sv) ? xv : sv) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_GT_94 = SGT(VARL("xv"), VARL("sv"));
	RzILOpPure *cond_95 = ITE(op_GT_94, VARL("xv"), VARL("sv"));
	RzILOpPure *op_GT_101 = SGT(VARL("xv"), VARL("sv"));
	RzILOpPure *cond_102 = ITE(op_GT_101, VARL("xv"), VARL("sv"));
	RzILOpPure *op_EQ_104 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_95), SN(32, 0), SN(32, 16)), CAST(64, MSB(cond_102), DUP(cond_102)));
	RzILOpPure *op_GT_110 = SGT(VARL("xv"), VARL("sv"));
	RzILOpPure *cond_111 = ITE(op_GT_110, VARL("xv"), VARL("sv"));
	RzILOpPure *op_LT_113 = SLT(cond_111, SN(32, 0));
	RzILOpPure *op_LSHIFT_118 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_119 = NEG(op_LSHIFT_118);
	RzILOpPure *op_LSHIFT_124 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_127 = SUB(op_LSHIFT_124, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_128 = ITE(op_LT_113, op_NEG_119, op_SUB_127);
	RzILOpEffect *gcc_expr_129 = BRANCH(op_EQ_104, EMPTY(), set_usr_field_call_109);

	// h_tmp148 = HYB(gcc_expr_if ((sextract64(((ut64) ((xv > sv) ? xv : sv)), 0x0, 0x10) == ((st64) ((xv > sv) ? xv : sv)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((xv > sv) ? xv : sv) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_131 = SETL("h_tmp148", cond_128);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((xv > sv) ? xv : sv)), ...;
	RzILOpEffect *seq_132 = SEQN(2, gcc_expr_129, op_ASSIGN_hybrid_tmp_131);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << i * 0x10)))) | (((ut64) (((sextract64(((ut64) ((xv > sv) ? xv : sv)), 0x0, 0x10) == ((st64) ((xv > sv) ? xv : sv))) ? ((st64) ((xv > sv) ? xv : sv)) : h_tmp148) & ((st64) 0xffff))) << i * 0x10)));
	RzILOpPure *op_MUL_87 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(SN(64, 0xffff), op_MUL_87);
	RzILOpPure *op_NOT_89 = LOGNOT(op_LSHIFT_88);
	RzILOpPure *op_AND_90 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_89);
	RzILOpPure *op_GT_105 = SGT(VARL("xv"), VARL("sv"));
	RzILOpPure *cond_106 = ITE(op_GT_105, VARL("xv"), VARL("sv"));
	RzILOpPure *cond_134 = ITE(DUP(op_EQ_104), CAST(64, MSB(cond_106), DUP(cond_106)), VARL("h_tmp148"));
	RzILOpPure *op_AND_137 = LOGAND(cond_134, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_140 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_141 = SHIFTL0(CAST(64, IL_FALSE, op_AND_137), op_MUL_140);
	RzILOpPure *op_OR_143 = LOGOR(CAST(64, IL_FALSE, op_AND_90), op_LSHIFT_141);
	RzILOpEffect *op_ASSIGN_145 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_143));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((xv > sv) ? xv : s ...;
	RzILOpEffect *seq_146 = SEQN(2, seq_132, op_ASSIGN_145);

	// seq(h_tmp147; xv = ((st32) ((st16) ((Rxx >> i * 0x10) & ((st64)  ...;
	RzILOpEffect *seq_148 = SEQN(8, op_ASSIGN_21, op_ASSIGN_31, op_ASSIGN_41, op_ASSIGN_43, op_ASSIGN_45, op_ASSIGN_62, op_ASSIGN_83, seq_146);

	// seq(seq(h_tmp147; xv = ((st32) ((st16) ((Rxx >> i * 0x10) & ((st ...;
	RzILOpEffect *seq_149 = SEQN(2, seq_148, seq_11);

	// while ((i < 0x4)) { seq(seq(h_tmp147; xv = ((st32) ((st16) ((Rxx >> i * 0x10) & ((st ... };
	RzILOpPure *op_LT_7 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_150 = REPEAT(op_LT_7, seq_149);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp147; xv = ((st32)  ...;
	RzILOpEffect *seq_151 = SEQN(2, op_ASSIGN_5, for_150);

	RzILOpEffect *instruction_sequence = seq_151;
	return instruction_sequence;
}

// Rd = vaddhub(Rss,Rtt):sat
RzILOpEffect *hex_il_op_a5_vaddhubs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp149 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp149", VARL("i"));

	// seq(h_tmp149 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_82 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x8) == ((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rtt, op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_38 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_26), DUP(op_AND_26))), CAST(16, MSB(DUP(op_AND_26)), DUP(op_AND_26))), CAST(32, MSB(CAST(16, MSB(op_AND_34), DUP(op_AND_34))), CAST(16, MSB(DUP(op_AND_34)), DUP(op_AND_34))));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_46 = SHIFTRA(DUP(Rss), op_MUL_45);
	RzILOpPure *op_AND_49 = LOGAND(op_RSHIFT_46, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_52 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rtt), op_MUL_52);
	RzILOpPure *op_AND_56 = LOGAND(op_RSHIFT_53, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_60 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_49), DUP(op_AND_49))), CAST(16, MSB(DUP(op_AND_49)), DUP(op_AND_49))), CAST(32, MSB(CAST(16, MSB(op_AND_56), DUP(op_AND_56))), CAST(16, MSB(DUP(op_AND_56)), DUP(op_AND_56))));
	RzILOpPure *op_EQ_62 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_ADD_38), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, op_ADD_60));
	RzILOpPure *op_MUL_84 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rss), op_MUL_84);
	RzILOpPure *op_AND_88 = LOGAND(op_RSHIFT_85, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_91 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_92 = SHIFTRA(DUP(Rtt), op_MUL_91);
	RzILOpPure *op_AND_95 = LOGAND(op_RSHIFT_92, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_99 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_88), DUP(op_AND_88))), CAST(16, MSB(DUP(op_AND_88)), DUP(op_AND_88))), CAST(32, MSB(CAST(16, MSB(op_AND_95), DUP(op_AND_95))), CAST(16, MSB(DUP(op_AND_95)), DUP(op_AND_95))));
	RzILOpPure *op_LT_101 = SLT(op_ADD_99, SN(32, 0));
	RzILOpPure *op_LSHIFT_105 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_108 = SUB(op_LSHIFT_105, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_110 = ITE(op_LT_101, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_108);
	RzILOpEffect *gcc_expr_111 = BRANCH(op_EQ_62, EMPTY(), set_usr_field_call_82);

	// h_tmp150 = HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x8) == ((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_113 = SETL("h_tmp150", cond_110);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((st16) ((Rss >> ...;
	RzILOpEffect *seq_114 = SEQN(2, gcc_expr_111, op_ASSIGN_hybrid_tmp_113);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((extract64(((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))), 0x0, 0x8) == ((ut64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> i * 0x10) & ((st64) 0xffff))))) : h_tmp150) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_64 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_65 = SHIFTRA(DUP(Rss), op_MUL_64);
	RzILOpPure *op_AND_68 = LOGAND(op_RSHIFT_65, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_MUL_71 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rtt), op_MUL_71);
	RzILOpPure *op_AND_75 = LOGAND(op_RSHIFT_72, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_79 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_68), DUP(op_AND_68))), CAST(16, MSB(DUP(op_AND_68)), DUP(op_AND_68))), CAST(32, MSB(CAST(16, MSB(op_AND_75), DUP(op_AND_75))), CAST(16, MSB(DUP(op_AND_75)), DUP(op_AND_75))));
	RzILOpPure *cond_116 = ITE(DUP(op_EQ_62), CAST(64, MSB(op_ADD_79), DUP(op_ADD_79)), VARL("h_tmp150"));
	RzILOpPure *op_AND_118 = LOGAND(cond_116, SN(64, 0xff));
	RzILOpPure *op_MUL_121 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_122 = SHIFTL0(CAST(64, IL_FALSE, op_AND_118), op_MUL_121);
	RzILOpPure *op_OR_124 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_122);
	RzILOpEffect *op_ASSIGN_126 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_124));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32) ((st16) ((Rs ...;
	RzILOpEffect *seq_127 = SEQN(2, seq_114, op_ASSIGN_126);

	// seq(h_tmp149; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) ((st32 ...;
	RzILOpEffect *seq_129 = seq_127;

	// seq(seq(h_tmp149; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_130 = SEQN(2, seq_129, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp149; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_131 = REPEAT(op_LT_4, seq_130);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp149; seq(seq(HYB(g ...;
	RzILOpEffect *seq_132 = SEQN(2, op_ASSIGN_2, for_131);

	RzILOpEffect *instruction_sequence = seq_132;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>