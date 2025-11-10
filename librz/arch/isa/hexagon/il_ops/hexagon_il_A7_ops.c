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

// Rd = clip(Rs,Ii)
RzILOpEffect *hex_il_op_a7_clip(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 maxv;
	// Declare: st32 minv;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// maxv = (0x1 << u) - 0x1;
	RzILOpPure *op_LSHIFT_3 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_SUB_5 = SUB(op_LSHIFT_3, SN(32, 1));
	RzILOpEffect *op_ASSIGN_7 = SETL("maxv", op_SUB_5);

	// minv = (-(0x1 << u));
	RzILOpPure *op_LSHIFT_9 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_NEG_10 = NEG(op_LSHIFT_9);
	RzILOpEffect *op_ASSIGN_12 = SETL("minv", op_NEG_10);

	// Rd = ((maxv < ((Rs > minv) ? Rs : minv)) ? maxv : ((Rs > minv) ? Rs : minv));
	RzILOpPure *op_GT_15 = SGT(Rs, VARL("minv"));
	RzILOpPure *cond_16 = ITE(op_GT_15, DUP(Rs), VARL("minv"));
	RzILOpPure *op_LT_17 = SLT(VARL("maxv"), cond_16);
	RzILOpPure *op_GT_18 = SGT(DUP(Rs), VARL("minv"));
	RzILOpPure *cond_19 = ITE(op_GT_18, DUP(Rs), VARL("minv"));
	RzILOpPure *cond_20 = ITE(op_LT_17, VARL("maxv"), cond_19);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rd_op, cond_20);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_1, op_ASSIGN_7, op_ASSIGN_12, op_ASSIGN_21);
	return instruction_sequence;
}

// Rdd = cround(Rss,Ii)
RzILOpEffect *hex_il_op_a7_croundd_ri(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = cround(Rss,Rt)
RzILOpEffect *hex_il_op_a7_croundd_rr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = vclip(Rss,Ii)
RzILOpEffect *hex_il_op_a7_vclip(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 tmp;
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 maxv;
	// Declare: st32 minv;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// maxv = (0x1 << u) - 0x1;
	RzILOpPure *op_LSHIFT_4 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_SUB_6 = SUB(op_LSHIFT_4, SN(32, 1));
	RzILOpEffect *op_ASSIGN_8 = SETL("maxv", op_SUB_6);

	// minv = (-(0x1 << u));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_NEG_11 = NEG(op_LSHIFT_10);
	RzILOpEffect *op_ASSIGN_13 = SETL("minv", op_NEG_11);

	// tmp = ((st32) ((((st64) maxv) < ((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) > ((st64) minv)) ? ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) : ((st64) minv))) ? ((st64) maxv) : ((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) > ((st64) minv)) ? ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) : ((st64) minv))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(64, 0xffffffff));
	RzILOpPure *op_GT_24 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_20), DUP(op_AND_20))), CAST(32, MSB(DUP(op_AND_20)), DUP(op_AND_20))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *op_RSHIFT_28 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_28, SN(64, 0xffffffff));
	RzILOpPure *cond_34 = ITE(op_GT_24, CAST(64, MSB(CAST(32, MSB(op_AND_30), DUP(op_AND_30))), CAST(32, MSB(DUP(op_AND_30)), DUP(op_AND_30))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *op_LT_36 = SLT(CAST(64, MSB(VARL("maxv")), VARL("maxv")), cond_34);
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_42 = LOGAND(op_RSHIFT_40, SN(64, 0xffffffff));
	RzILOpPure *op_GT_46 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_42), DUP(op_AND_42))), CAST(32, MSB(DUP(op_AND_42)), DUP(op_AND_42))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_50, SN(64, 0xffffffff));
	RzILOpPure *cond_56 = ITE(op_GT_46, CAST(64, MSB(CAST(32, MSB(op_AND_52), DUP(op_AND_52))), CAST(32, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *cond_58 = ITE(op_LT_36, CAST(64, MSB(VARL("maxv")), VARL("maxv")), cond_56);
	RzILOpEffect *op_ASSIGN_60 = SETL("tmp", CAST(32, MSB(cond_58), DUP(cond_58)));

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) tmp) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_67 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_68 = LOGNOT(op_LSHIFT_67);
	RzILOpPure *op_AND_69 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_68);
	RzILOpPure *op_AND_72 = LOGAND(CAST(64, MSB(VARL("tmp")), VARL("tmp")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_76 = SHIFTL0(op_AND_72, SN(32, 0));
	RzILOpPure *op_OR_77 = LOGOR(op_AND_69, op_LSHIFT_76);
	RzILOpEffect *op_ASSIGN_78 = WRITE_REG(bundle, Rdd_op, op_OR_77);

	// maxv = (0x1 << u) - 0x1;
	RzILOpPure *op_LSHIFT_81 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_SUB_83 = SUB(op_LSHIFT_81, SN(32, 1));
	RzILOpEffect *op_ASSIGN_84 = SETL("maxv", op_SUB_83);

	// minv = (-(0x1 << u));
	RzILOpPure *op_LSHIFT_86 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_NEG_87 = NEG(op_LSHIFT_86);
	RzILOpEffect *op_ASSIGN_88 = SETL("minv", op_NEG_87);

	// tmp = ((st32) ((((st64) maxv) < ((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) > ((st64) minv)) ? ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) : ((st64) minv))) ? ((st64) maxv) : ((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) > ((st64) minv)) ? ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) : ((st64) minv))));
	RzILOpPure *op_RSHIFT_92 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_92, SN(64, 0xffffffff));
	RzILOpPure *op_GT_98 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_94), DUP(op_AND_94))), CAST(32, MSB(DUP(op_AND_94)), DUP(op_AND_94))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *op_RSHIFT_102 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_104 = LOGAND(op_RSHIFT_102, SN(64, 0xffffffff));
	RzILOpPure *cond_108 = ITE(op_GT_98, CAST(64, MSB(CAST(32, MSB(op_AND_104), DUP(op_AND_104))), CAST(32, MSB(DUP(op_AND_104)), DUP(op_AND_104))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *op_LT_110 = SLT(CAST(64, MSB(VARL("maxv")), VARL("maxv")), cond_108);
	RzILOpPure *op_RSHIFT_114 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_116 = LOGAND(op_RSHIFT_114, SN(64, 0xffffffff));
	RzILOpPure *op_GT_120 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_116), DUP(op_AND_116))), CAST(32, MSB(DUP(op_AND_116)), DUP(op_AND_116))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *op_RSHIFT_124 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_126 = LOGAND(op_RSHIFT_124, SN(64, 0xffffffff));
	RzILOpPure *cond_130 = ITE(op_GT_120, CAST(64, MSB(CAST(32, MSB(op_AND_126), DUP(op_AND_126))), CAST(32, MSB(DUP(op_AND_126)), DUP(op_AND_126))), CAST(64, MSB(VARL("minv")), VARL("minv")));
	RzILOpPure *cond_132 = ITE(op_LT_110, CAST(64, MSB(VARL("maxv")), VARL("maxv")), cond_130);
	RzILOpEffect *op_ASSIGN_134 = SETL("tmp", CAST(32, MSB(cond_132), DUP(cond_132)));

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) tmp) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_140 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_141 = LOGNOT(op_LSHIFT_140);
	RzILOpPure *op_AND_142 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_141);
	RzILOpPure *op_AND_145 = LOGAND(CAST(64, MSB(VARL("tmp")), VARL("tmp")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_149 = SHIFTL0(op_AND_145, SN(32, 0x20));
	RzILOpPure *op_OR_150 = LOGOR(op_AND_142, op_LSHIFT_149);
	RzILOpEffect *op_ASSIGN_151 = WRITE_REG(bundle, Rdd_op, op_OR_150);

	RzILOpEffect *instruction_sequence = SEQN(9, imm_assign_2, op_ASSIGN_8, op_ASSIGN_13, op_ASSIGN_60, op_ASSIGN_78, op_ASSIGN_84, op_ASSIGN_88, op_ASSIGN_134, op_ASSIGN_151);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>