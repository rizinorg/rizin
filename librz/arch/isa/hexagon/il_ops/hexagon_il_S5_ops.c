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

// Rd = vasrhub(Rss,Ii):raw
RzILOpEffect *hex_il_op_s5_asrhub_rnd_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp604 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp604", VARL("i"));

	// seq(h_tmp604 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_28 = SETL("u", u);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_71 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1)), 0x0, 0x8) == ((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(CAST(16, MSB(op_AND_26), DUP(op_AND_26)), VARL("u"));
	RzILOpPure *op_ADD_33 = ADD(CAST(32, MSB(op_RSHIFT_30), DUP(op_RSHIFT_30)), SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(op_ADD_33, SN(32, 1));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(DUP(Rss), op_MUL_42);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_43, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(CAST(16, MSB(op_AND_46), DUP(op_AND_46)), VARL("u"));
	RzILOpPure *op_ADD_51 = ADD(CAST(32, MSB(op_RSHIFT_48), DUP(op_RSHIFT_48)), SN(32, 1));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(op_ADD_51, SN(32, 1));
	RzILOpPure *op_EQ_55 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_35), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, op_RSHIFT_53));
	RzILOpPure *op_MUL_73 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_74 = SHIFTRA(DUP(Rss), op_MUL_73);
	RzILOpPure *op_AND_77 = LOGAND(op_RSHIFT_74, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_79 = SHIFTRA(CAST(16, MSB(op_AND_77), DUP(op_AND_77)), VARL("u"));
	RzILOpPure *op_ADD_82 = ADD(CAST(32, MSB(op_RSHIFT_79), DUP(op_RSHIFT_79)), SN(32, 1));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(op_ADD_82, SN(32, 1));
	RzILOpPure *op_LT_86 = SLT(op_RSHIFT_84, SN(32, 0));
	RzILOpPure *op_LSHIFT_90 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_93 = SUB(op_LSHIFT_90, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_95 = ITE(op_LT_86, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_93);
	RzILOpEffect *gcc_expr_96 = BRANCH(op_EQ_55, EMPTY(), set_usr_field_call_71);

	// h_tmp605 = HYB(gcc_expr_if ((extract64(((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1)), 0x0, 0x8) == ((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_98 = SETL("h_tmp605", cond_95);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) (((st32) (((st16) ((Rss  ...;
	RzILOpEffect *seq_99 = SEQN(2, gcc_expr_96, op_ASSIGN_hybrid_tmp_98);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((extract64(((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1)), 0x0, 0x8) == ((ut64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1))) ? ((st64) (((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1)) : h_tmp605) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_57 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_58 = SHIFTRA(DUP(Rss), op_MUL_57);
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(CAST(16, MSB(op_AND_61), DUP(op_AND_61)), VARL("u"));
	RzILOpPure *op_ADD_66 = ADD(CAST(32, MSB(op_RSHIFT_63), DUP(op_RSHIFT_63)), SN(32, 1));
	RzILOpPure *op_RSHIFT_68 = SHIFTRA(op_ADD_66, SN(32, 1));
	RzILOpPure *cond_101 = ITE(DUP(op_EQ_55), CAST(64, MSB(op_RSHIFT_68), DUP(op_RSHIFT_68)), VARL("h_tmp605"));
	RzILOpPure *op_AND_103 = LOGAND(cond_101, SN(64, 0xff));
	RzILOpPure *op_MUL_106 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_107 = SHIFTL0(CAST(64, IL_FALSE, op_AND_103), op_MUL_106);
	RzILOpPure *op_OR_109 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_107);
	RzILOpEffect *op_ASSIGN_111 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_109));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (((st32) (((st16) (( ...;
	RzILOpEffect *seq_112 = SEQN(2, seq_99, op_ASSIGN_111);

	// seq(h_tmp604; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (((st3 ...;
	RzILOpEffect *seq_114 = seq_112;

	// seq(seq(h_tmp604; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_115 = SEQN(2, seq_114, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp604; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_116 = REPEAT(op_LT_4, seq_115);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp604; seq(seq(HYB(g ...;
	RzILOpEffect *seq_117 = SEQN(2, op_ASSIGN_2, for_116);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_28, seq_117);
	return instruction_sequence;
}

// Rd = vasrhub(Rss,Ii):sat
RzILOpEffect *hex_il_op_s5_asrhub_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp606 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp606", VARL("i"));

	// seq(h_tmp606 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_28 = SETL("u", u);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_56 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((extract64(((ut64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)), 0x0, 0x8) == ((ut64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpPure *op_MUL_22 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, op_MUL_22);
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(CAST(16, MSB(op_AND_26), DUP(op_AND_26)), VARL("u"));
	RzILOpPure *op_MUL_37 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rss), op_MUL_37);
	RzILOpPure *op_AND_41 = LOGAND(op_RSHIFT_38, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_43 = SHIFTRA(CAST(16, MSB(op_AND_41), DUP(op_AND_41)), VARL("u"));
	RzILOpPure *op_EQ_45 = EQ(EXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_30), SN(32, 0), SN(32, 8)), CAST(64, IL_FALSE, op_RSHIFT_43));
	RzILOpPure *op_MUL_58 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_59 = SHIFTRA(DUP(Rss), op_MUL_58);
	RzILOpPure *op_AND_62 = LOGAND(op_RSHIFT_59, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(CAST(16, MSB(op_AND_62), DUP(op_AND_62)), VARL("u"));
	RzILOpPure *op_LT_67 = SLT(CAST(32, MSB(op_RSHIFT_64), DUP(op_RSHIFT_64)), SN(32, 0));
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(SN(64, 1), SN(32, 8));
	RzILOpPure *op_SUB_74 = SUB(op_LSHIFT_71, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_76 = ITE(op_LT_67, CAST(64, MSB(SN(32, 0)), SN(32, 0)), op_SUB_74);
	RzILOpEffect *gcc_expr_77 = BRANCH(op_EQ_45, EMPTY(), set_usr_field_call_56);

	// h_tmp607 = HYB(gcc_expr_if ((extract64(((ut64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)), 0x0, 0x8) == ((ut64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) < 0x0) ? ((st64) 0x0) : (0x1 << 0x8) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_79 = SETL("h_tmp607", cond_76);

	// seq(HYB(gcc_expr_if ((extract64(((ut64) (((st16) ((Rss >> i * 0x ...;
	RzILOpEffect *seq_80 = SEQN(2, gcc_expr_77, op_ASSIGN_hybrid_tmp_79);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xff << i * 0x8)))) | (((ut64) (((extract64(((ut64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)), 0x0, 0x8) == ((ut64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u))) ? ((st64) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) : h_tmp607) & 0xff)) << i * 0x8)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_16 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_14);
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rss), op_MUL_47);
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(CAST(16, MSB(op_AND_51), DUP(op_AND_51)), VARL("u"));
	RzILOpPure *cond_82 = ITE(DUP(op_EQ_45), CAST(64, MSB(op_RSHIFT_53), DUP(op_RSHIFT_53)), VARL("h_tmp607"));
	RzILOpPure *op_AND_84 = LOGAND(cond_82, SN(64, 0xff));
	RzILOpPure *op_MUL_87 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(CAST(64, IL_FALSE, op_AND_84), op_MUL_87);
	RzILOpPure *op_OR_90 = LOGOR(CAST(64, IL_FALSE, op_AND_16), op_LSHIFT_88);
	RzILOpEffect *op_ASSIGN_92 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_90));

	// seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (((st16) ((Rss >> i  ...;
	RzILOpEffect *seq_93 = SEQN(2, seq_80, op_ASSIGN_92);

	// seq(h_tmp606; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (((st1 ...;
	RzILOpEffect *seq_95 = seq_93;

	// seq(seq(h_tmp606; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ...;
	RzILOpEffect *seq_96 = SEQN(2, seq_95, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp606; seq(seq(HYB(gcc_expr_if ((extract64(((ut64) (( ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_97 = REPEAT(op_LT_4, seq_96);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp606; seq(seq(HYB(g ...;
	RzILOpEffect *seq_98 = SEQN(2, op_ASSIGN_2, for_97);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_28, seq_98);
	return instruction_sequence;
}

// Rd = popcount(Rss)
RzILOpEffect *hex_il_op_s5_popcountp(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = vasrh(Rss,Ii):raw
RzILOpEffect *hex_il_op_s5_vasrhrnd(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp608 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp608", VARL("i"));

	// seq(h_tmp608 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) ((((st32) (((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) >> u)) + 0x1 >> 0x1) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(SN(64, 0xffff), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_15 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_14);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(CAST(16, MSB(op_AND_22), DUP(op_AND_22)), VARL("u"));
	RzILOpPure *op_ADD_29 = ADD(CAST(32, MSB(op_RSHIFT_26), DUP(op_RSHIFT_26)), SN(32, 1));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(op_ADD_29, SN(32, 1));
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_31, SN(32, 0xffff));
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(CAST(64, IL_FALSE, op_AND_33), op_MUL_36);
	RzILOpPure *op_OR_39 = LOGOR(CAST(64, IL_FALSE, op_AND_15), op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_39));

	// seq(h_tmp608; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_43 = op_ASSIGN_41;

	// seq(seq(h_tmp608; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_44 = SEQN(2, seq_43, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp608; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_45 = REPEAT(op_LT_4, seq_44);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp608; Rdd = ((st64) ...;
	RzILOpEffect *seq_46 = SEQN(2, op_ASSIGN_2, for_45);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_46);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>