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

// Rxx += vdmpybsu(Rss,Rtt):sat
RzILOpEffect *hex_il_op_m5_vdmacbsu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_189 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_14, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_34, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_41 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_26), DUP(op_AND_26))), CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26))), CAST(8, MSB(DUP(op_AND_26)), DUP(op_AND_26)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_37))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_37)))));
	RzILOpPure *op_ADD_45 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_17), DUP(op_AND_17))), CAST(16, MSB(DUP(op_AND_17)), DUP(op_AND_17)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_17)), DUP(op_AND_17))), CAST(16, MSB(DUP(op_AND_17)), DUP(op_AND_17)))), CAST(64, MSB(op_MUL_41), DUP(op_MUL_41)));
	RzILOpPure *op_RSHIFT_49 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_52 = LOGAND(op_RSHIFT_49, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_59 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_62 = LOGAND(op_RSHIFT_59, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_66 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_52), DUP(op_AND_52))), CAST(8, MSB(DUP(op_AND_52)), DUP(op_AND_52)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_52)), DUP(op_AND_52))), CAST(8, MSB(DUP(op_AND_52)), DUP(op_AND_52)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_62))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_62)))));
	RzILOpPure *op_ADD_68 = ADD(op_ADD_45, CAST(64, MSB(op_MUL_66), DUP(op_MUL_66)));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_80 = LOGAND(op_RSHIFT_77, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_85 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_88 = LOGAND(op_RSHIFT_85, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_95 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_98 = LOGAND(op_RSHIFT_95, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_102 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_88), DUP(op_AND_88))), CAST(8, MSB(DUP(op_AND_88)), DUP(op_AND_88)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_88)), DUP(op_AND_88))), CAST(8, MSB(DUP(op_AND_88)), DUP(op_AND_88)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_98))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_98)))));
	RzILOpPure *op_ADD_106 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_80), DUP(op_AND_80))), CAST(16, MSB(DUP(op_AND_80)), DUP(op_AND_80)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_80)), DUP(op_AND_80))), CAST(16, MSB(DUP(op_AND_80)), DUP(op_AND_80)))), CAST(64, MSB(op_MUL_102), DUP(op_MUL_102)));
	RzILOpPure *op_RSHIFT_110 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_113 = LOGAND(op_RSHIFT_110, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_120 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_123 = LOGAND(op_RSHIFT_120, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_127 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_113), DUP(op_AND_113))), CAST(8, MSB(DUP(op_AND_113)), DUP(op_AND_113)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_113)), DUP(op_AND_113))), CAST(8, MSB(DUP(op_AND_113)), DUP(op_AND_113)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_123))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_123)))));
	RzILOpPure *op_ADD_129 = ADD(op_ADD_106, CAST(64, MSB(op_MUL_127), DUP(op_MUL_127)));
	RzILOpPure *op_EQ_130 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_68), SN(32, 0), SN(32, 16)), op_ADD_129);
	RzILOpPure *op_RSHIFT_193 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_196 = LOGAND(op_RSHIFT_193, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_201 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_204 = LOGAND(op_RSHIFT_201, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_211 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_214 = LOGAND(op_RSHIFT_211, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_218 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_204), DUP(op_AND_204))), CAST(8, MSB(DUP(op_AND_204)), DUP(op_AND_204)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_204)), DUP(op_AND_204))), CAST(8, MSB(DUP(op_AND_204)), DUP(op_AND_204)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_214))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_214)))));
	RzILOpPure *op_ADD_222 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_196), DUP(op_AND_196))), CAST(16, MSB(DUP(op_AND_196)), DUP(op_AND_196)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_196)), DUP(op_AND_196))), CAST(16, MSB(DUP(op_AND_196)), DUP(op_AND_196)))), CAST(64, MSB(op_MUL_218), DUP(op_MUL_218)));
	RzILOpPure *op_RSHIFT_226 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_229 = LOGAND(op_RSHIFT_226, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_236 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_239 = LOGAND(op_RSHIFT_236, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_243 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_229), DUP(op_AND_229))), CAST(8, MSB(DUP(op_AND_229)), DUP(op_AND_229)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_229)), DUP(op_AND_229))), CAST(8, MSB(DUP(op_AND_229)), DUP(op_AND_229)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_239))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_239)))));
	RzILOpPure *op_ADD_245 = ADD(op_ADD_222, CAST(64, MSB(op_MUL_243), DUP(op_MUL_243)));
	RzILOpPure *op_LT_248 = SLT(op_ADD_245, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_253 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_254 = NEG(op_LSHIFT_253);
	RzILOpPure *op_LSHIFT_259 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_262 = SUB(op_LSHIFT_259, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_263 = ITE(op_LT_248, op_NEG_254, op_SUB_262);
	RzILOpEffect *gcc_expr_264 = BRANCH(op_EQ_130, EMPTY(), set_usr_field_call_189);

	// h_tmp441 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_266 = SETL("h_tmp441", cond_263);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_267 = SEQN(2, gcc_expr_264, op_ASSIGN_hybrid_tmp_266);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) : h_tmp441) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_6);
	RzILOpPure *op_RSHIFT_134 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_137 = LOGAND(op_RSHIFT_134, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_142 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_145 = LOGAND(op_RSHIFT_142, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_152 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_155 = LOGAND(op_RSHIFT_152, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_159 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_145), DUP(op_AND_145))), CAST(8, MSB(DUP(op_AND_145)), DUP(op_AND_145)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_145)), DUP(op_AND_145))), CAST(8, MSB(DUP(op_AND_145)), DUP(op_AND_145)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_155))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_155)))));
	RzILOpPure *op_ADD_163 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_137), DUP(op_AND_137))), CAST(16, MSB(DUP(op_AND_137)), DUP(op_AND_137)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_137)), DUP(op_AND_137))), CAST(16, MSB(DUP(op_AND_137)), DUP(op_AND_137)))), CAST(64, MSB(op_MUL_159), DUP(op_MUL_159)));
	RzILOpPure *op_RSHIFT_167 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_170 = LOGAND(op_RSHIFT_167, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_177 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_180 = LOGAND(op_RSHIFT_177, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_184 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_170), DUP(op_AND_170))), CAST(8, MSB(DUP(op_AND_170)), DUP(op_AND_170)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_170)), DUP(op_AND_170))), CAST(8, MSB(DUP(op_AND_170)), DUP(op_AND_170)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_180))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_180)))));
	RzILOpPure *op_ADD_186 = ADD(op_ADD_163, CAST(64, MSB(op_MUL_184), DUP(op_MUL_184)));
	RzILOpPure *cond_268 = ITE(DUP(op_EQ_130), op_ADD_186, VARL("h_tmp441"));
	RzILOpPure *op_AND_271 = LOGAND(cond_268, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_276 = SHIFTL0(CAST(64, IL_FALSE, op_AND_271), SN(32, 0));
	RzILOpPure *op_OR_278 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_276);
	RzILOpEffect *op_ASSIGN_280 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_278));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_281 = SEQN(2, seq_267, op_ASSIGN_280);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_469 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_296 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_299 = LOGAND(op_RSHIFT_296, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_304 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_307 = LOGAND(op_RSHIFT_304, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_314 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_317 = LOGAND(op_RSHIFT_314, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_321 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_307), DUP(op_AND_307))), CAST(8, MSB(DUP(op_AND_307)), DUP(op_AND_307)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_307)), DUP(op_AND_307))), CAST(8, MSB(DUP(op_AND_307)), DUP(op_AND_307)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_317))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_317)))));
	RzILOpPure *op_ADD_325 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_299), DUP(op_AND_299))), CAST(16, MSB(DUP(op_AND_299)), DUP(op_AND_299)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_299)), DUP(op_AND_299))), CAST(16, MSB(DUP(op_AND_299)), DUP(op_AND_299)))), CAST(64, MSB(op_MUL_321), DUP(op_MUL_321)));
	RzILOpPure *op_RSHIFT_329 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_332 = LOGAND(op_RSHIFT_329, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_339 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_342 = LOGAND(op_RSHIFT_339, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_346 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_332), DUP(op_AND_332))), CAST(8, MSB(DUP(op_AND_332)), DUP(op_AND_332)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_332)), DUP(op_AND_332))), CAST(8, MSB(DUP(op_AND_332)), DUP(op_AND_332)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_342))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_342)))));
	RzILOpPure *op_ADD_348 = ADD(op_ADD_325, CAST(64, MSB(op_MUL_346), DUP(op_MUL_346)));
	RzILOpPure *op_RSHIFT_357 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_360 = LOGAND(op_RSHIFT_357, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_365 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_368 = LOGAND(op_RSHIFT_365, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_375 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_378 = LOGAND(op_RSHIFT_375, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_382 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_368), DUP(op_AND_368))), CAST(8, MSB(DUP(op_AND_368)), DUP(op_AND_368)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_368)), DUP(op_AND_368))), CAST(8, MSB(DUP(op_AND_368)), DUP(op_AND_368)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_378))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_378)))));
	RzILOpPure *op_ADD_386 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_360), DUP(op_AND_360))), CAST(16, MSB(DUP(op_AND_360)), DUP(op_AND_360)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_360)), DUP(op_AND_360))), CAST(16, MSB(DUP(op_AND_360)), DUP(op_AND_360)))), CAST(64, MSB(op_MUL_382), DUP(op_MUL_382)));
	RzILOpPure *op_RSHIFT_390 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_393 = LOGAND(op_RSHIFT_390, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_400 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_403 = LOGAND(op_RSHIFT_400, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_407 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_393), DUP(op_AND_393))), CAST(8, MSB(DUP(op_AND_393)), DUP(op_AND_393)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_393)), DUP(op_AND_393))), CAST(8, MSB(DUP(op_AND_393)), DUP(op_AND_393)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_403))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_403)))));
	RzILOpPure *op_ADD_409 = ADD(op_ADD_386, CAST(64, MSB(op_MUL_407), DUP(op_MUL_407)));
	RzILOpPure *op_EQ_410 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_348), SN(32, 0), SN(32, 16)), op_ADD_409);
	RzILOpPure *op_RSHIFT_473 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_476 = LOGAND(op_RSHIFT_473, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_481 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_484 = LOGAND(op_RSHIFT_481, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_491 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_494 = LOGAND(op_RSHIFT_491, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_498 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_484), DUP(op_AND_484))), CAST(8, MSB(DUP(op_AND_484)), DUP(op_AND_484)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_484)), DUP(op_AND_484))), CAST(8, MSB(DUP(op_AND_484)), DUP(op_AND_484)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_494))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_494)))));
	RzILOpPure *op_ADD_502 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_476), DUP(op_AND_476))), CAST(16, MSB(DUP(op_AND_476)), DUP(op_AND_476)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_476)), DUP(op_AND_476))), CAST(16, MSB(DUP(op_AND_476)), DUP(op_AND_476)))), CAST(64, MSB(op_MUL_498), DUP(op_MUL_498)));
	RzILOpPure *op_RSHIFT_506 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_509 = LOGAND(op_RSHIFT_506, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_516 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_519 = LOGAND(op_RSHIFT_516, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_523 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_509), DUP(op_AND_509))), CAST(8, MSB(DUP(op_AND_509)), DUP(op_AND_509)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_509)), DUP(op_AND_509))), CAST(8, MSB(DUP(op_AND_509)), DUP(op_AND_509)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_519))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_519)))));
	RzILOpPure *op_ADD_525 = ADD(op_ADD_502, CAST(64, MSB(op_MUL_523), DUP(op_MUL_523)));
	RzILOpPure *op_LT_528 = SLT(op_ADD_525, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_533 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_534 = NEG(op_LSHIFT_533);
	RzILOpPure *op_LSHIFT_539 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_542 = SUB(op_LSHIFT_539, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_543 = ITE(op_LT_528, op_NEG_534, op_SUB_542);
	RzILOpEffect *gcc_expr_544 = BRANCH(op_EQ_410, EMPTY(), set_usr_field_call_469);

	// h_tmp442 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_546 = SETL("h_tmp442", cond_543);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_547 = SEQN(2, gcc_expr_544, op_ASSIGN_hybrid_tmp_546);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) : h_tmp442) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_287 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_288 = LOGNOT(op_LSHIFT_287);
	RzILOpPure *op_AND_289 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_288);
	RzILOpPure *op_RSHIFT_414 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_417 = LOGAND(op_RSHIFT_414, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_422 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_425 = LOGAND(op_RSHIFT_422, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_432 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_435 = LOGAND(op_RSHIFT_432, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_439 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_425), DUP(op_AND_425))), CAST(8, MSB(DUP(op_AND_425)), DUP(op_AND_425)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_425)), DUP(op_AND_425))), CAST(8, MSB(DUP(op_AND_425)), DUP(op_AND_425)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_435))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_435)))));
	RzILOpPure *op_ADD_443 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_417), DUP(op_AND_417))), CAST(16, MSB(DUP(op_AND_417)), DUP(op_AND_417)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_417)), DUP(op_AND_417))), CAST(16, MSB(DUP(op_AND_417)), DUP(op_AND_417)))), CAST(64, MSB(op_MUL_439), DUP(op_MUL_439)));
	RzILOpPure *op_RSHIFT_447 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_450 = LOGAND(op_RSHIFT_447, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_457 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_460 = LOGAND(op_RSHIFT_457, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_464 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_450), DUP(op_AND_450))), CAST(8, MSB(DUP(op_AND_450)), DUP(op_AND_450)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_450)), DUP(op_AND_450))), CAST(8, MSB(DUP(op_AND_450)), DUP(op_AND_450)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_460))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_460)))));
	RzILOpPure *op_ADD_466 = ADD(op_ADD_443, CAST(64, MSB(op_MUL_464), DUP(op_MUL_464)));
	RzILOpPure *cond_548 = ITE(DUP(op_EQ_410), op_ADD_466, VARL("h_tmp442"));
	RzILOpPure *op_AND_551 = LOGAND(cond_548, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_556 = SHIFTL0(CAST(64, IL_FALSE, op_AND_551), SN(32, 16));
	RzILOpPure *op_OR_558 = LOGOR(CAST(64, IL_FALSE, op_AND_289), op_LSHIFT_556);
	RzILOpEffect *op_ASSIGN_560 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_558));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_561 = SEQN(2, seq_547, op_ASSIGN_560);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_749 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_576 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_579 = LOGAND(op_RSHIFT_576, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_584 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_587 = LOGAND(op_RSHIFT_584, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_594 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_597 = LOGAND(op_RSHIFT_594, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_601 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_587), DUP(op_AND_587))), CAST(8, MSB(DUP(op_AND_587)), DUP(op_AND_587)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_587)), DUP(op_AND_587))), CAST(8, MSB(DUP(op_AND_587)), DUP(op_AND_587)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_597))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_597)))));
	RzILOpPure *op_ADD_605 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_579), DUP(op_AND_579))), CAST(16, MSB(DUP(op_AND_579)), DUP(op_AND_579)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_579)), DUP(op_AND_579))), CAST(16, MSB(DUP(op_AND_579)), DUP(op_AND_579)))), CAST(64, MSB(op_MUL_601), DUP(op_MUL_601)));
	RzILOpPure *op_RSHIFT_609 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_612 = LOGAND(op_RSHIFT_609, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_619 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_622 = LOGAND(op_RSHIFT_619, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_626 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_612), DUP(op_AND_612))), CAST(8, MSB(DUP(op_AND_612)), DUP(op_AND_612)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_612)), DUP(op_AND_612))), CAST(8, MSB(DUP(op_AND_612)), DUP(op_AND_612)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_622))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_622)))));
	RzILOpPure *op_ADD_628 = ADD(op_ADD_605, CAST(64, MSB(op_MUL_626), DUP(op_MUL_626)));
	RzILOpPure *op_RSHIFT_637 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_640 = LOGAND(op_RSHIFT_637, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_645 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_648 = LOGAND(op_RSHIFT_645, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_655 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_658 = LOGAND(op_RSHIFT_655, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_662 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_648), DUP(op_AND_648))), CAST(8, MSB(DUP(op_AND_648)), DUP(op_AND_648)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_648)), DUP(op_AND_648))), CAST(8, MSB(DUP(op_AND_648)), DUP(op_AND_648)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_658))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_658)))));
	RzILOpPure *op_ADD_666 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_640), DUP(op_AND_640))), CAST(16, MSB(DUP(op_AND_640)), DUP(op_AND_640)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_640)), DUP(op_AND_640))), CAST(16, MSB(DUP(op_AND_640)), DUP(op_AND_640)))), CAST(64, MSB(op_MUL_662), DUP(op_MUL_662)));
	RzILOpPure *op_RSHIFT_670 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_673 = LOGAND(op_RSHIFT_670, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_680 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_683 = LOGAND(op_RSHIFT_680, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_687 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_673), DUP(op_AND_673))), CAST(8, MSB(DUP(op_AND_673)), DUP(op_AND_673)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_673)), DUP(op_AND_673))), CAST(8, MSB(DUP(op_AND_673)), DUP(op_AND_673)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_683))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_683)))));
	RzILOpPure *op_ADD_689 = ADD(op_ADD_666, CAST(64, MSB(op_MUL_687), DUP(op_MUL_687)));
	RzILOpPure *op_EQ_690 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_628), SN(32, 0), SN(32, 16)), op_ADD_689);
	RzILOpPure *op_RSHIFT_753 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_756 = LOGAND(op_RSHIFT_753, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_761 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_764 = LOGAND(op_RSHIFT_761, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_771 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_774 = LOGAND(op_RSHIFT_771, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_778 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_764), DUP(op_AND_764))), CAST(8, MSB(DUP(op_AND_764)), DUP(op_AND_764)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_764)), DUP(op_AND_764))), CAST(8, MSB(DUP(op_AND_764)), DUP(op_AND_764)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_774))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_774)))));
	RzILOpPure *op_ADD_782 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_756), DUP(op_AND_756))), CAST(16, MSB(DUP(op_AND_756)), DUP(op_AND_756)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_756)), DUP(op_AND_756))), CAST(16, MSB(DUP(op_AND_756)), DUP(op_AND_756)))), CAST(64, MSB(op_MUL_778), DUP(op_MUL_778)));
	RzILOpPure *op_RSHIFT_786 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_789 = LOGAND(op_RSHIFT_786, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_796 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_799 = LOGAND(op_RSHIFT_796, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_803 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_789), DUP(op_AND_789))), CAST(8, MSB(DUP(op_AND_789)), DUP(op_AND_789)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_789)), DUP(op_AND_789))), CAST(8, MSB(DUP(op_AND_789)), DUP(op_AND_789)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_799))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_799)))));
	RzILOpPure *op_ADD_805 = ADD(op_ADD_782, CAST(64, MSB(op_MUL_803), DUP(op_MUL_803)));
	RzILOpPure *op_LT_808 = SLT(op_ADD_805, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_813 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_814 = NEG(op_LSHIFT_813);
	RzILOpPure *op_LSHIFT_819 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_822 = SUB(op_LSHIFT_819, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_823 = ITE(op_LT_808, op_NEG_814, op_SUB_822);
	RzILOpEffect *gcc_expr_824 = BRANCH(op_EQ_690, EMPTY(), set_usr_field_call_749);

	// h_tmp443 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_826 = SETL("h_tmp443", cond_823);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_827 = SEQN(2, gcc_expr_824, op_ASSIGN_hybrid_tmp_826);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) : h_tmp443) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_567 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_568 = LOGNOT(op_LSHIFT_567);
	RzILOpPure *op_AND_569 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_568);
	RzILOpPure *op_RSHIFT_694 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_697 = LOGAND(op_RSHIFT_694, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_702 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_705 = LOGAND(op_RSHIFT_702, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_712 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_715 = LOGAND(op_RSHIFT_712, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_719 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_705), DUP(op_AND_705))), CAST(8, MSB(DUP(op_AND_705)), DUP(op_AND_705)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_705)), DUP(op_AND_705))), CAST(8, MSB(DUP(op_AND_705)), DUP(op_AND_705)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_715))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_715)))));
	RzILOpPure *op_ADD_723 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_697), DUP(op_AND_697))), CAST(16, MSB(DUP(op_AND_697)), DUP(op_AND_697)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_697)), DUP(op_AND_697))), CAST(16, MSB(DUP(op_AND_697)), DUP(op_AND_697)))), CAST(64, MSB(op_MUL_719), DUP(op_MUL_719)));
	RzILOpPure *op_RSHIFT_727 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_730 = LOGAND(op_RSHIFT_727, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_737 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_740 = LOGAND(op_RSHIFT_737, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_744 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_730), DUP(op_AND_730))), CAST(8, MSB(DUP(op_AND_730)), DUP(op_AND_730)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_730)), DUP(op_AND_730))), CAST(8, MSB(DUP(op_AND_730)), DUP(op_AND_730)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_740))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_740)))));
	RzILOpPure *op_ADD_746 = ADD(op_ADD_723, CAST(64, MSB(op_MUL_744), DUP(op_MUL_744)));
	RzILOpPure *cond_828 = ITE(DUP(op_EQ_690), op_ADD_746, VARL("h_tmp443"));
	RzILOpPure *op_AND_831 = LOGAND(cond_828, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_836 = SHIFTL0(CAST(64, IL_FALSE, op_AND_831), SN(32, 0x20));
	RzILOpPure *op_OR_838 = LOGOR(CAST(64, IL_FALSE, op_AND_569), op_LSHIFT_836);
	RzILOpEffect *op_ASSIGN_840 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_838));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_841 = SEQN(2, seq_827, op_ASSIGN_840);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_1029 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_856 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_859 = LOGAND(op_RSHIFT_856, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_864 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_867 = LOGAND(op_RSHIFT_864, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_874 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_877 = LOGAND(op_RSHIFT_874, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_881 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_867), DUP(op_AND_867))), CAST(8, MSB(DUP(op_AND_867)), DUP(op_AND_867)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_867)), DUP(op_AND_867))), CAST(8, MSB(DUP(op_AND_867)), DUP(op_AND_867)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_877))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_877)))));
	RzILOpPure *op_ADD_885 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_859), DUP(op_AND_859))), CAST(16, MSB(DUP(op_AND_859)), DUP(op_AND_859)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_859)), DUP(op_AND_859))), CAST(16, MSB(DUP(op_AND_859)), DUP(op_AND_859)))), CAST(64, MSB(op_MUL_881), DUP(op_MUL_881)));
	RzILOpPure *op_RSHIFT_889 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_892 = LOGAND(op_RSHIFT_889, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_899 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_902 = LOGAND(op_RSHIFT_899, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_906 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_892), DUP(op_AND_892))), CAST(8, MSB(DUP(op_AND_892)), DUP(op_AND_892)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_892)), DUP(op_AND_892))), CAST(8, MSB(DUP(op_AND_892)), DUP(op_AND_892)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_902))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_902)))));
	RzILOpPure *op_ADD_908 = ADD(op_ADD_885, CAST(64, MSB(op_MUL_906), DUP(op_MUL_906)));
	RzILOpPure *op_RSHIFT_917 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_920 = LOGAND(op_RSHIFT_917, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_925 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_928 = LOGAND(op_RSHIFT_925, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_935 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_938 = LOGAND(op_RSHIFT_935, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_942 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_928), DUP(op_AND_928))), CAST(8, MSB(DUP(op_AND_928)), DUP(op_AND_928)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_928)), DUP(op_AND_928))), CAST(8, MSB(DUP(op_AND_928)), DUP(op_AND_928)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_938))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_938)))));
	RzILOpPure *op_ADD_946 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_920), DUP(op_AND_920))), CAST(16, MSB(DUP(op_AND_920)), DUP(op_AND_920)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_920)), DUP(op_AND_920))), CAST(16, MSB(DUP(op_AND_920)), DUP(op_AND_920)))), CAST(64, MSB(op_MUL_942), DUP(op_MUL_942)));
	RzILOpPure *op_RSHIFT_950 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_953 = LOGAND(op_RSHIFT_950, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_960 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_963 = LOGAND(op_RSHIFT_960, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_967 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_953), DUP(op_AND_953))), CAST(8, MSB(DUP(op_AND_953)), DUP(op_AND_953)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_953)), DUP(op_AND_953))), CAST(8, MSB(DUP(op_AND_953)), DUP(op_AND_953)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_963))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_963)))));
	RzILOpPure *op_ADD_969 = ADD(op_ADD_946, CAST(64, MSB(op_MUL_967), DUP(op_MUL_967)));
	RzILOpPure *op_EQ_970 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_908), SN(32, 0), SN(32, 16)), op_ADD_969);
	RzILOpPure *op_RSHIFT_1033 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_1036 = LOGAND(op_RSHIFT_1033, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_1041 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_1044 = LOGAND(op_RSHIFT_1041, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_1051 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_1054 = LOGAND(op_RSHIFT_1051, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_1058 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_1044), DUP(op_AND_1044))), CAST(8, MSB(DUP(op_AND_1044)), DUP(op_AND_1044)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_1044)), DUP(op_AND_1044))), CAST(8, MSB(DUP(op_AND_1044)), DUP(op_AND_1044)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_1054))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_1054)))));
	RzILOpPure *op_ADD_1062 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_1036), DUP(op_AND_1036))), CAST(16, MSB(DUP(op_AND_1036)), DUP(op_AND_1036)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_1036)), DUP(op_AND_1036))), CAST(16, MSB(DUP(op_AND_1036)), DUP(op_AND_1036)))), CAST(64, MSB(op_MUL_1058), DUP(op_MUL_1058)));
	RzILOpPure *op_RSHIFT_1066 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_1069 = LOGAND(op_RSHIFT_1066, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_1076 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_1079 = LOGAND(op_RSHIFT_1076, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_1083 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_1069), DUP(op_AND_1069))), CAST(8, MSB(DUP(op_AND_1069)), DUP(op_AND_1069)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_1069)), DUP(op_AND_1069))), CAST(8, MSB(DUP(op_AND_1069)), DUP(op_AND_1069)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_1079))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_1079)))));
	RzILOpPure *op_ADD_1085 = ADD(op_ADD_1062, CAST(64, MSB(op_MUL_1083), DUP(op_MUL_1083)));
	RzILOpPure *op_LT_1088 = SLT(op_ADD_1085, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_1093 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_1094 = NEG(op_LSHIFT_1093);
	RzILOpPure *op_LSHIFT_1099 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_1102 = SUB(op_LSHIFT_1099, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_1103 = ITE(op_LT_1088, op_NEG_1094, op_SUB_1102);
	RzILOpEffect *gcc_expr_1104 = BRANCH(op_EQ_970, EMPTY(), set_usr_field_call_1029);

	// h_tmp444 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_1106 = SETL("h_tmp444", cond_1103);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_1107 = SEQN(2, gcc_expr_1104, op_ASSIGN_hybrid_tmp_1106);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) : h_tmp444) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_847 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_848 = LOGNOT(op_LSHIFT_847);
	RzILOpPure *op_AND_849 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_848);
	RzILOpPure *op_RSHIFT_974 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_977 = LOGAND(op_RSHIFT_974, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_982 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_985 = LOGAND(op_RSHIFT_982, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_992 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_995 = LOGAND(op_RSHIFT_992, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_999 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_985), DUP(op_AND_985))), CAST(8, MSB(DUP(op_AND_985)), DUP(op_AND_985)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_985)), DUP(op_AND_985))), CAST(8, MSB(DUP(op_AND_985)), DUP(op_AND_985)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_995))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_995)))));
	RzILOpPure *op_ADD_1003 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_977), DUP(op_AND_977))), CAST(16, MSB(DUP(op_AND_977)), DUP(op_AND_977)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_977)), DUP(op_AND_977))), CAST(16, MSB(DUP(op_AND_977)), DUP(op_AND_977)))), CAST(64, MSB(op_MUL_999), DUP(op_MUL_999)));
	RzILOpPure *op_RSHIFT_1007 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_1010 = LOGAND(op_RSHIFT_1007, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_1017 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_1020 = LOGAND(op_RSHIFT_1017, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_1024 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_1010), DUP(op_AND_1010))), CAST(8, MSB(DUP(op_AND_1010)), DUP(op_AND_1010)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_1010)), DUP(op_AND_1010))), CAST(8, MSB(DUP(op_AND_1010)), DUP(op_AND_1010)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_1020))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_1020)))));
	RzILOpPure *op_ADD_1026 = ADD(op_ADD_1003, CAST(64, MSB(op_MUL_1024), DUP(op_MUL_1024)));
	RzILOpPure *cond_1108 = ITE(DUP(op_EQ_970), op_ADD_1026, VARL("h_tmp444"));
	RzILOpPure *op_AND_1111 = LOGAND(cond_1108, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_1116 = SHIFTL0(CAST(64, IL_FALSE, op_AND_1111), SN(32, 0x30));
	RzILOpPure *op_OR_1118 = LOGOR(CAST(64, IL_FALSE, op_AND_849), op_LSHIFT_1116);
	RzILOpEffect *op_ASSIGN_1120 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_1118));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_1121 = SEQN(2, seq_1107, op_ASSIGN_1120);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_281, seq_561, seq_841, seq_1121);
	return instruction_sequence;
}

// Rdd = vdmpybsu(Rss,Rtt):sat
RzILOpEffect *hex_il_op_m5_vdmpybsu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_156 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_26, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_33 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_18), DUP(op_AND_18))), CAST(8, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(8, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_29))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_29)))));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_41 = LOGAND(op_RSHIFT_38, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_55 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_41), DUP(op_AND_41))), CAST(8, MSB(DUP(op_AND_41)), DUP(op_AND_41)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_41)), DUP(op_AND_41))), CAST(8, MSB(DUP(op_AND_41)), DUP(op_AND_41)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_51))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_51)))));
	RzILOpPure *op_ADD_57 = ADD(CAST(64, MSB(op_MUL_33), DUP(op_MUL_33)), CAST(64, MSB(op_MUL_55), DUP(op_MUL_55)));
	RzILOpPure *op_RSHIFT_66 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_66, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_76 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_79 = LOGAND(op_RSHIFT_76, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_83 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_69), DUP(op_AND_69))), CAST(8, MSB(DUP(op_AND_69)), DUP(op_AND_69)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_69)), DUP(op_AND_69))), CAST(8, MSB(DUP(op_AND_69)), DUP(op_AND_69)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_79))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_79)))));
	RzILOpPure *op_RSHIFT_88 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_91 = LOGAND(op_RSHIFT_88, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_98 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_101 = LOGAND(op_RSHIFT_98, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_105 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_91), DUP(op_AND_91))), CAST(8, MSB(DUP(op_AND_91)), DUP(op_AND_91)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_91)), DUP(op_AND_91))), CAST(8, MSB(DUP(op_AND_91)), DUP(op_AND_91)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_101))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_101)))));
	RzILOpPure *op_ADD_107 = ADD(CAST(64, MSB(op_MUL_83), DUP(op_MUL_83)), CAST(64, MSB(op_MUL_105), DUP(op_MUL_105)));
	RzILOpPure *op_EQ_108 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_57), SN(32, 0), SN(32, 16)), op_ADD_107);
	RzILOpPure *op_RSHIFT_160 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_163 = LOGAND(op_RSHIFT_160, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_173 = LOGAND(op_RSHIFT_170, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_177 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_163), DUP(op_AND_163))), CAST(8, MSB(DUP(op_AND_163)), DUP(op_AND_163)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_163)), DUP(op_AND_163))), CAST(8, MSB(DUP(op_AND_163)), DUP(op_AND_163)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_173))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_173)))));
	RzILOpPure *op_RSHIFT_182 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_185 = LOGAND(op_RSHIFT_182, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_192 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_195 = LOGAND(op_RSHIFT_192, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_199 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_185), DUP(op_AND_185))), CAST(8, MSB(DUP(op_AND_185)), DUP(op_AND_185)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_185)), DUP(op_AND_185))), CAST(8, MSB(DUP(op_AND_185)), DUP(op_AND_185)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_195))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_195)))));
	RzILOpPure *op_ADD_201 = ADD(CAST(64, MSB(op_MUL_177), DUP(op_MUL_177)), CAST(64, MSB(op_MUL_199), DUP(op_MUL_199)));
	RzILOpPure *op_LT_204 = SLT(op_ADD_201, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_209 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_210 = NEG(op_LSHIFT_209);
	RzILOpPure *op_LSHIFT_215 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_218 = SUB(op_LSHIFT_215, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_219 = ITE(op_LT_204, op_NEG_210, op_SUB_218);
	RzILOpEffect *gcc_expr_220 = BRANCH(op_EQ_108, EMPTY(), set_usr_field_call_156);

	// h_tmp445 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_222 = SETL("h_tmp445", cond_219);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_223 = SEQN(2, gcc_expr_220, op_ASSIGN_hybrid_tmp_222);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) : h_tmp445) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_112 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_115 = LOGAND(op_RSHIFT_112, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_122 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_125 = LOGAND(op_RSHIFT_122, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_129 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_115), DUP(op_AND_115))), CAST(8, MSB(DUP(op_AND_115)), DUP(op_AND_115)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_115)), DUP(op_AND_115))), CAST(8, MSB(DUP(op_AND_115)), DUP(op_AND_115)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_125))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_125)))));
	RzILOpPure *op_RSHIFT_134 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_137 = LOGAND(op_RSHIFT_134, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_147 = LOGAND(op_RSHIFT_144, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_151 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_137), DUP(op_AND_137))), CAST(8, MSB(DUP(op_AND_137)), DUP(op_AND_137)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_137)), DUP(op_AND_137))), CAST(8, MSB(DUP(op_AND_137)), DUP(op_AND_137)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_147))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_147)))));
	RzILOpPure *op_ADD_153 = ADD(CAST(64, MSB(op_MUL_129), DUP(op_MUL_129)), CAST(64, MSB(op_MUL_151), DUP(op_MUL_151)));
	RzILOpPure *cond_224 = ITE(DUP(op_EQ_108), op_ADD_153, VARL("h_tmp445"));
	RzILOpPure *op_AND_227 = LOGAND(cond_224, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_232 = SHIFTL0(CAST(64, IL_FALSE, op_AND_227), SN(32, 0));
	RzILOpPure *op_OR_234 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_232);
	RzILOpEffect *op_ASSIGN_236 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_234));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_237 = SEQN(2, seq_223, op_ASSIGN_236);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_392 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_252 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_255 = LOGAND(op_RSHIFT_252, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_262 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_265 = LOGAND(op_RSHIFT_262, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_269 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_255), DUP(op_AND_255))), CAST(8, MSB(DUP(op_AND_255)), DUP(op_AND_255)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_255)), DUP(op_AND_255))), CAST(8, MSB(DUP(op_AND_255)), DUP(op_AND_255)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_265))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_265)))));
	RzILOpPure *op_RSHIFT_274 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_277 = LOGAND(op_RSHIFT_274, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_284 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_287 = LOGAND(op_RSHIFT_284, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_291 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_277), DUP(op_AND_277))), CAST(8, MSB(DUP(op_AND_277)), DUP(op_AND_277)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_277)), DUP(op_AND_277))), CAST(8, MSB(DUP(op_AND_277)), DUP(op_AND_277)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_287))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_287)))));
	RzILOpPure *op_ADD_293 = ADD(CAST(64, MSB(op_MUL_269), DUP(op_MUL_269)), CAST(64, MSB(op_MUL_291), DUP(op_MUL_291)));
	RzILOpPure *op_RSHIFT_302 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_305 = LOGAND(op_RSHIFT_302, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_312 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_315 = LOGAND(op_RSHIFT_312, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_319 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_305), DUP(op_AND_305))), CAST(8, MSB(DUP(op_AND_305)), DUP(op_AND_305)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_305)), DUP(op_AND_305))), CAST(8, MSB(DUP(op_AND_305)), DUP(op_AND_305)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_315))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_315)))));
	RzILOpPure *op_RSHIFT_324 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_327 = LOGAND(op_RSHIFT_324, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_334 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_337 = LOGAND(op_RSHIFT_334, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_341 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_327), DUP(op_AND_327))), CAST(8, MSB(DUP(op_AND_327)), DUP(op_AND_327)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_327)), DUP(op_AND_327))), CAST(8, MSB(DUP(op_AND_327)), DUP(op_AND_327)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_337))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_337)))));
	RzILOpPure *op_ADD_343 = ADD(CAST(64, MSB(op_MUL_319), DUP(op_MUL_319)), CAST(64, MSB(op_MUL_341), DUP(op_MUL_341)));
	RzILOpPure *op_EQ_344 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_293), SN(32, 0), SN(32, 16)), op_ADD_343);
	RzILOpPure *op_RSHIFT_396 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_399 = LOGAND(op_RSHIFT_396, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_406 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_409 = LOGAND(op_RSHIFT_406, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_413 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_399), DUP(op_AND_399))), CAST(8, MSB(DUP(op_AND_399)), DUP(op_AND_399)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_399)), DUP(op_AND_399))), CAST(8, MSB(DUP(op_AND_399)), DUP(op_AND_399)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_409))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_409)))));
	RzILOpPure *op_RSHIFT_418 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_421 = LOGAND(op_RSHIFT_418, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_428 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_431 = LOGAND(op_RSHIFT_428, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_435 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_421), DUP(op_AND_421))), CAST(8, MSB(DUP(op_AND_421)), DUP(op_AND_421)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_421)), DUP(op_AND_421))), CAST(8, MSB(DUP(op_AND_421)), DUP(op_AND_421)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_431))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_431)))));
	RzILOpPure *op_ADD_437 = ADD(CAST(64, MSB(op_MUL_413), DUP(op_MUL_413)), CAST(64, MSB(op_MUL_435), DUP(op_MUL_435)));
	RzILOpPure *op_LT_440 = SLT(op_ADD_437, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_445 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_446 = NEG(op_LSHIFT_445);
	RzILOpPure *op_LSHIFT_451 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_454 = SUB(op_LSHIFT_451, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_455 = ITE(op_LT_440, op_NEG_446, op_SUB_454);
	RzILOpEffect *gcc_expr_456 = BRANCH(op_EQ_344, EMPTY(), set_usr_field_call_392);

	// h_tmp446 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_458 = SETL("h_tmp446", cond_455);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_459 = SEQN(2, gcc_expr_456, op_ASSIGN_hybrid_tmp_458);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) : h_tmp446) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_243 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_244 = LOGNOT(op_LSHIFT_243);
	RzILOpPure *op_AND_245 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_244);
	RzILOpPure *op_RSHIFT_348 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_351 = LOGAND(op_RSHIFT_348, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_358 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_361 = LOGAND(op_RSHIFT_358, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_365 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_351), DUP(op_AND_351))), CAST(8, MSB(DUP(op_AND_351)), DUP(op_AND_351)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_351)), DUP(op_AND_351))), CAST(8, MSB(DUP(op_AND_351)), DUP(op_AND_351)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_361))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_361)))));
	RzILOpPure *op_RSHIFT_370 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_373 = LOGAND(op_RSHIFT_370, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_380 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_383 = LOGAND(op_RSHIFT_380, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_387 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_373), DUP(op_AND_373))), CAST(8, MSB(DUP(op_AND_373)), DUP(op_AND_373)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_373)), DUP(op_AND_373))), CAST(8, MSB(DUP(op_AND_373)), DUP(op_AND_373)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_383))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_383)))));
	RzILOpPure *op_ADD_389 = ADD(CAST(64, MSB(op_MUL_365), DUP(op_MUL_365)), CAST(64, MSB(op_MUL_387), DUP(op_MUL_387)));
	RzILOpPure *cond_460 = ITE(DUP(op_EQ_344), op_ADD_389, VARL("h_tmp446"));
	RzILOpPure *op_AND_463 = LOGAND(cond_460, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_468 = SHIFTL0(CAST(64, IL_FALSE, op_AND_463), SN(32, 16));
	RzILOpPure *op_OR_470 = LOGOR(CAST(64, IL_FALSE, op_AND_245), op_LSHIFT_468);
	RzILOpEffect *op_ASSIGN_472 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_470));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_473 = SEQN(2, seq_459, op_ASSIGN_472);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_628 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_488 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_491 = LOGAND(op_RSHIFT_488, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_498 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_501 = LOGAND(op_RSHIFT_498, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_505 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_491), DUP(op_AND_491))), CAST(8, MSB(DUP(op_AND_491)), DUP(op_AND_491)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_491)), DUP(op_AND_491))), CAST(8, MSB(DUP(op_AND_491)), DUP(op_AND_491)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_501))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_501)))));
	RzILOpPure *op_RSHIFT_510 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_513 = LOGAND(op_RSHIFT_510, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_520 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_523 = LOGAND(op_RSHIFT_520, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_527 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_513), DUP(op_AND_513))), CAST(8, MSB(DUP(op_AND_513)), DUP(op_AND_513)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_513)), DUP(op_AND_513))), CAST(8, MSB(DUP(op_AND_513)), DUP(op_AND_513)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_523))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_523)))));
	RzILOpPure *op_ADD_529 = ADD(CAST(64, MSB(op_MUL_505), DUP(op_MUL_505)), CAST(64, MSB(op_MUL_527), DUP(op_MUL_527)));
	RzILOpPure *op_RSHIFT_538 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_541 = LOGAND(op_RSHIFT_538, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_548 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_551 = LOGAND(op_RSHIFT_548, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_555 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_541), DUP(op_AND_541))), CAST(8, MSB(DUP(op_AND_541)), DUP(op_AND_541)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_541)), DUP(op_AND_541))), CAST(8, MSB(DUP(op_AND_541)), DUP(op_AND_541)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_551))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_551)))));
	RzILOpPure *op_RSHIFT_560 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_563 = LOGAND(op_RSHIFT_560, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_570 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_573 = LOGAND(op_RSHIFT_570, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_577 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_563), DUP(op_AND_563))), CAST(8, MSB(DUP(op_AND_563)), DUP(op_AND_563)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_563)), DUP(op_AND_563))), CAST(8, MSB(DUP(op_AND_563)), DUP(op_AND_563)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_573))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_573)))));
	RzILOpPure *op_ADD_579 = ADD(CAST(64, MSB(op_MUL_555), DUP(op_MUL_555)), CAST(64, MSB(op_MUL_577), DUP(op_MUL_577)));
	RzILOpPure *op_EQ_580 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_529), SN(32, 0), SN(32, 16)), op_ADD_579);
	RzILOpPure *op_RSHIFT_632 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_635 = LOGAND(op_RSHIFT_632, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_642 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_645 = LOGAND(op_RSHIFT_642, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_649 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_635), DUP(op_AND_635))), CAST(8, MSB(DUP(op_AND_635)), DUP(op_AND_635)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_635)), DUP(op_AND_635))), CAST(8, MSB(DUP(op_AND_635)), DUP(op_AND_635)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_645))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_645)))));
	RzILOpPure *op_RSHIFT_654 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_657 = LOGAND(op_RSHIFT_654, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_664 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_667 = LOGAND(op_RSHIFT_664, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_671 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_657), DUP(op_AND_657))), CAST(8, MSB(DUP(op_AND_657)), DUP(op_AND_657)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_657)), DUP(op_AND_657))), CAST(8, MSB(DUP(op_AND_657)), DUP(op_AND_657)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_667))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_667)))));
	RzILOpPure *op_ADD_673 = ADD(CAST(64, MSB(op_MUL_649), DUP(op_MUL_649)), CAST(64, MSB(op_MUL_671), DUP(op_MUL_671)));
	RzILOpPure *op_LT_676 = SLT(op_ADD_673, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_681 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_682 = NEG(op_LSHIFT_681);
	RzILOpPure *op_LSHIFT_687 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_690 = SUB(op_LSHIFT_687, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_691 = ITE(op_LT_676, op_NEG_682, op_SUB_690);
	RzILOpEffect *gcc_expr_692 = BRANCH(op_EQ_580, EMPTY(), set_usr_field_call_628);

	// h_tmp447 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_694 = SETL("h_tmp447", cond_691);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_695 = SEQN(2, gcc_expr_692, op_ASSIGN_hybrid_tmp_694);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) : h_tmp447) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_479 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_480 = LOGNOT(op_LSHIFT_479);
	RzILOpPure *op_AND_481 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_480);
	RzILOpPure *op_RSHIFT_584 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_587 = LOGAND(op_RSHIFT_584, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_594 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_597 = LOGAND(op_RSHIFT_594, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_601 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_587), DUP(op_AND_587))), CAST(8, MSB(DUP(op_AND_587)), DUP(op_AND_587)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_587)), DUP(op_AND_587))), CAST(8, MSB(DUP(op_AND_587)), DUP(op_AND_587)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_597))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_597)))));
	RzILOpPure *op_RSHIFT_606 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_609 = LOGAND(op_RSHIFT_606, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_616 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_619 = LOGAND(op_RSHIFT_616, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_623 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_609), DUP(op_AND_609))), CAST(8, MSB(DUP(op_AND_609)), DUP(op_AND_609)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_609)), DUP(op_AND_609))), CAST(8, MSB(DUP(op_AND_609)), DUP(op_AND_609)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_619))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_619)))));
	RzILOpPure *op_ADD_625 = ADD(CAST(64, MSB(op_MUL_601), DUP(op_MUL_601)), CAST(64, MSB(op_MUL_623), DUP(op_MUL_623)));
	RzILOpPure *cond_696 = ITE(DUP(op_EQ_580), op_ADD_625, VARL("h_tmp447"));
	RzILOpPure *op_AND_699 = LOGAND(cond_696, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_704 = SHIFTL0(CAST(64, IL_FALSE, op_AND_699), SN(32, 0x20));
	RzILOpPure *op_OR_706 = LOGOR(CAST(64, IL_FALSE, op_AND_481), op_LSHIFT_704);
	RzILOpEffect *op_ASSIGN_708 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_706));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_709 = SEQN(2, seq_695, op_ASSIGN_708);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_864 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_724 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_727 = LOGAND(op_RSHIFT_724, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_734 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_737 = LOGAND(op_RSHIFT_734, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_741 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_727), DUP(op_AND_727))), CAST(8, MSB(DUP(op_AND_727)), DUP(op_AND_727)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_727)), DUP(op_AND_727))), CAST(8, MSB(DUP(op_AND_727)), DUP(op_AND_727)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_737))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_737)))));
	RzILOpPure *op_RSHIFT_746 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_749 = LOGAND(op_RSHIFT_746, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_756 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_759 = LOGAND(op_RSHIFT_756, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_763 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_749), DUP(op_AND_749))), CAST(8, MSB(DUP(op_AND_749)), DUP(op_AND_749)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_749)), DUP(op_AND_749))), CAST(8, MSB(DUP(op_AND_749)), DUP(op_AND_749)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_759))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_759)))));
	RzILOpPure *op_ADD_765 = ADD(CAST(64, MSB(op_MUL_741), DUP(op_MUL_741)), CAST(64, MSB(op_MUL_763), DUP(op_MUL_763)));
	RzILOpPure *op_RSHIFT_774 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_777 = LOGAND(op_RSHIFT_774, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_784 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_787 = LOGAND(op_RSHIFT_784, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_791 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_777), DUP(op_AND_777))), CAST(8, MSB(DUP(op_AND_777)), DUP(op_AND_777)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_777)), DUP(op_AND_777))), CAST(8, MSB(DUP(op_AND_777)), DUP(op_AND_777)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_787))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_787)))));
	RzILOpPure *op_RSHIFT_796 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_799 = LOGAND(op_RSHIFT_796, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_806 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_809 = LOGAND(op_RSHIFT_806, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_813 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_799), DUP(op_AND_799))), CAST(8, MSB(DUP(op_AND_799)), DUP(op_AND_799)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_799)), DUP(op_AND_799))), CAST(8, MSB(DUP(op_AND_799)), DUP(op_AND_799)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_809))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_809)))));
	RzILOpPure *op_ADD_815 = ADD(CAST(64, MSB(op_MUL_791), DUP(op_MUL_791)), CAST(64, MSB(op_MUL_813), DUP(op_MUL_813)));
	RzILOpPure *op_EQ_816 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_765), SN(32, 0), SN(32, 16)), op_ADD_815);
	RzILOpPure *op_RSHIFT_868 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_871 = LOGAND(op_RSHIFT_868, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_878 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_881 = LOGAND(op_RSHIFT_878, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_885 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_871), DUP(op_AND_871))), CAST(8, MSB(DUP(op_AND_871)), DUP(op_AND_871)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_871)), DUP(op_AND_871))), CAST(8, MSB(DUP(op_AND_871)), DUP(op_AND_871)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_881))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_881)))));
	RzILOpPure *op_RSHIFT_890 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_893 = LOGAND(op_RSHIFT_890, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_900 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_903 = LOGAND(op_RSHIFT_900, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_907 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_893), DUP(op_AND_893))), CAST(8, MSB(DUP(op_AND_893)), DUP(op_AND_893)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_893)), DUP(op_AND_893))), CAST(8, MSB(DUP(op_AND_893)), DUP(op_AND_893)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_903))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_903)))));
	RzILOpPure *op_ADD_909 = ADD(CAST(64, MSB(op_MUL_885), DUP(op_MUL_885)), CAST(64, MSB(op_MUL_907), DUP(op_MUL_907)));
	RzILOpPure *op_LT_912 = SLT(op_ADD_909, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_917 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_918 = NEG(op_LSHIFT_917);
	RzILOpPure *op_LSHIFT_923 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_926 = SUB(op_LSHIFT_923, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_927 = ITE(op_LT_912, op_NEG_918, op_SUB_926);
	RzILOpEffect *gcc_expr_928 = BRANCH(op_EQ_816, EMPTY(), set_usr_field_call_864);

	// h_tmp448 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) < ((st64) 0x0)) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_930 = SETL("h_tmp448", cond_927);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((st16) ...;
	RzILOpEffect *seq_931 = SEQN(2, gcc_expr_928, op_ASSIGN_hybrid_tmp_930);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff))))))) ? ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) : h_tmp448) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_715 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_716 = LOGNOT(op_LSHIFT_715);
	RzILOpPure *op_AND_717 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_716);
	RzILOpPure *op_RSHIFT_820 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_823 = LOGAND(op_RSHIFT_820, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_830 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_833 = LOGAND(op_RSHIFT_830, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_837 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_823), DUP(op_AND_823))), CAST(8, MSB(DUP(op_AND_823)), DUP(op_AND_823)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_823)), DUP(op_AND_823))), CAST(8, MSB(DUP(op_AND_823)), DUP(op_AND_823)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_833))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_833)))));
	RzILOpPure *op_RSHIFT_842 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_845 = LOGAND(op_RSHIFT_842, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_852 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_855 = LOGAND(op_RSHIFT_852, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_859 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_845), DUP(op_AND_845))), CAST(8, MSB(DUP(op_AND_845)), DUP(op_AND_845)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_845)), DUP(op_AND_845))), CAST(8, MSB(DUP(op_AND_845)), DUP(op_AND_845)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_855))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_855)))));
	RzILOpPure *op_ADD_861 = ADD(CAST(64, MSB(op_MUL_837), DUP(op_MUL_837)), CAST(64, MSB(op_MUL_859), DUP(op_MUL_859)));
	RzILOpPure *cond_932 = ITE(DUP(op_EQ_816), op_ADD_861, VARL("h_tmp448"));
	RzILOpPure *op_AND_935 = LOGAND(cond_932, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_940 = SHIFTL0(CAST(64, IL_FALSE, op_AND_935), SN(32, 0x30));
	RzILOpPure *op_OR_942 = LOGOR(CAST(64, IL_FALSE, op_AND_717), op_LSHIFT_940);
	RzILOpEffect *op_ASSIGN_944 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_942));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((s ...;
	RzILOpEffect *seq_945 = SEQN(2, seq_931, op_ASSIGN_944);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_237, seq_473, seq_709, seq_945);
	return instruction_sequence;
}

// Rxx += vmpybsu(Rs,Rt)
RzILOpEffect *hex_il_op_m5_vmacbsu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x0)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rs >> 0x0) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x0) & 0xff))))) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_6);
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_11, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xff));
	RzILOpPure *op_MUL_36 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_22), DUP(op_AND_22))), CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_32))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_32)))));
	RzILOpPure *op_ADD_40 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_14), DUP(op_AND_14))), CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14))), CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14)))), CAST(64, MSB(op_MUL_36), DUP(op_MUL_36)));
	RzILOpPure *op_AND_43 = LOGAND(op_ADD_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(CAST(64, IL_FALSE, op_AND_43), SN(32, 0));
	RzILOpPure *op_OR_50 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_48);
	RzILOpEffect *op_ASSIGN_52 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_50));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x10)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rs >> 0x8) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x8) & 0xff))))) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_58 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_59 = LOGNOT(op_LSHIFT_58);
	RzILOpPure *op_AND_60 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_59);
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rs), SN(32, 8));
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_72, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_81 = SHIFTRA(DUP(Rt), SN(32, 8));
	RzILOpPure *op_AND_83 = LOGAND(op_RSHIFT_81, SN(32, 0xff));
	RzILOpPure *op_MUL_87 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_74), DUP(op_AND_74))), CAST(8, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_74)), DUP(op_AND_74))), CAST(8, MSB(DUP(op_AND_74)), DUP(op_AND_74)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_83))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_83)))));
	RzILOpPure *op_ADD_91 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_67), DUP(op_AND_67))), CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67))), CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67)))), CAST(64, MSB(op_MUL_87), DUP(op_MUL_87)));
	RzILOpPure *op_AND_94 = LOGAND(op_ADD_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_99 = SHIFTL0(CAST(64, IL_FALSE, op_AND_94), SN(32, 16));
	RzILOpPure *op_OR_101 = LOGOR(CAST(64, IL_FALSE, op_AND_60), op_LSHIFT_99);
	RzILOpEffect *op_ASSIGN_103 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_101));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x20)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rs >> 0x10) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x10) & 0xff))))) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_110 = LOGNOT(op_LSHIFT_109);
	RzILOpPure *op_AND_111 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_110);
	RzILOpPure *op_RSHIFT_115 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_118 = LOGAND(op_RSHIFT_115, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_123 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_125 = LOGAND(op_RSHIFT_123, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_132 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_134 = LOGAND(op_RSHIFT_132, SN(32, 0xff));
	RzILOpPure *op_MUL_138 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_125), DUP(op_AND_125))), CAST(8, MSB(DUP(op_AND_125)), DUP(op_AND_125)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_125)), DUP(op_AND_125))), CAST(8, MSB(DUP(op_AND_125)), DUP(op_AND_125)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_134))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_134)))));
	RzILOpPure *op_ADD_142 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_118), DUP(op_AND_118))), CAST(16, MSB(DUP(op_AND_118)), DUP(op_AND_118)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_118)), DUP(op_AND_118))), CAST(16, MSB(DUP(op_AND_118)), DUP(op_AND_118)))), CAST(64, MSB(op_MUL_138), DUP(op_MUL_138)));
	RzILOpPure *op_AND_145 = LOGAND(op_ADD_142, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_150 = SHIFTL0(CAST(64, IL_FALSE, op_AND_145), SN(32, 0x20));
	RzILOpPure *op_OR_152 = LOGOR(CAST(64, IL_FALSE, op_AND_111), op_LSHIFT_150);
	RzILOpEffect *op_ASSIGN_154 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_152));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x30)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((st8) ((Rs >> 0x18) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x18) & 0xff))))) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_160 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_161 = LOGNOT(op_LSHIFT_160);
	RzILOpPure *op_AND_162 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_161);
	RzILOpPure *op_RSHIFT_166 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_169 = LOGAND(op_RSHIFT_166, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_174 = SHIFTRA(DUP(Rs), SN(32, 24));
	RzILOpPure *op_AND_176 = LOGAND(op_RSHIFT_174, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_183 = SHIFTRA(DUP(Rt), SN(32, 24));
	RzILOpPure *op_AND_185 = LOGAND(op_RSHIFT_183, SN(32, 0xff));
	RzILOpPure *op_MUL_189 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_176), DUP(op_AND_176))), CAST(8, MSB(DUP(op_AND_176)), DUP(op_AND_176)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_176)), DUP(op_AND_176))), CAST(8, MSB(DUP(op_AND_176)), DUP(op_AND_176)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_185))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_185)))));
	RzILOpPure *op_ADD_193 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_169), DUP(op_AND_169))), CAST(16, MSB(DUP(op_AND_169)), DUP(op_AND_169)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_169)), DUP(op_AND_169))), CAST(16, MSB(DUP(op_AND_169)), DUP(op_AND_169)))), CAST(64, MSB(op_MUL_189), DUP(op_MUL_189)));
	RzILOpPure *op_AND_196 = LOGAND(op_ADD_193, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_201 = SHIFTL0(CAST(64, IL_FALSE, op_AND_196), SN(32, 0x30));
	RzILOpPure *op_OR_203 = LOGOR(CAST(64, IL_FALSE, op_AND_162), op_LSHIFT_201);
	RzILOpEffect *op_ASSIGN_205 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_203));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_52, op_ASSIGN_103, op_ASSIGN_154, op_ASSIGN_205);
	return instruction_sequence;
}

// Rxx += vmpybu(Rs,Rt)
RzILOpEffect *hex_il_op_m5_vmacbuu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x0)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x0) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x0) & 0xff))))) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_6);
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_11, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_30 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_32 = LOGAND(op_RSHIFT_30, SN(32, 0xff));
	RzILOpPure *op_MUL_36 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_22))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_22)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_32))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_32)))));
	RzILOpPure *op_ADD_40 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_14), DUP(op_AND_14))), CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14))), CAST(16, MSB(DUP(op_AND_14)), DUP(op_AND_14)))), CAST(64, MSB(op_MUL_36), DUP(op_MUL_36)));
	RzILOpPure *op_AND_43 = LOGAND(op_ADD_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(CAST(64, IL_FALSE, op_AND_43), SN(32, 0));
	RzILOpPure *op_OR_50 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_48);
	RzILOpEffect *op_ASSIGN_52 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_50));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x10)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x10) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x8) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x8) & 0xff))))) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_58 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_59 = LOGNOT(op_LSHIFT_58);
	RzILOpPure *op_AND_60 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_59);
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 16));
	RzILOpPure *op_AND_67 = LOGAND(op_RSHIFT_64, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_72 = SHIFTRA(DUP(Rs), SN(32, 8));
	RzILOpPure *op_AND_74 = LOGAND(op_RSHIFT_72, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_81 = SHIFTRA(DUP(Rt), SN(32, 8));
	RzILOpPure *op_AND_83 = LOGAND(op_RSHIFT_81, SN(32, 0xff));
	RzILOpPure *op_MUL_87 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_74))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_74)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_83))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_83)))));
	RzILOpPure *op_ADD_91 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_67), DUP(op_AND_67))), CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67))), CAST(16, MSB(DUP(op_AND_67)), DUP(op_AND_67)))), CAST(64, MSB(op_MUL_87), DUP(op_MUL_87)));
	RzILOpPure *op_AND_94 = LOGAND(op_ADD_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_99 = SHIFTL0(CAST(64, IL_FALSE, op_AND_94), SN(32, 16));
	RzILOpPure *op_OR_101 = LOGOR(CAST(64, IL_FALSE, op_AND_60), op_LSHIFT_99);
	RzILOpEffect *op_ASSIGN_103 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_101));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x20)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x20) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x10) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x10) & 0xff))))) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_109 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_110 = LOGNOT(op_LSHIFT_109);
	RzILOpPure *op_AND_111 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_110);
	RzILOpPure *op_RSHIFT_115 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_118 = LOGAND(op_RSHIFT_115, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_123 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_125 = LOGAND(op_RSHIFT_123, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_132 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_134 = LOGAND(op_RSHIFT_132, SN(32, 0xff));
	RzILOpPure *op_MUL_138 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_125))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_125)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_134))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_134)))));
	RzILOpPure *op_ADD_142 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_118), DUP(op_AND_118))), CAST(16, MSB(DUP(op_AND_118)), DUP(op_AND_118)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_118)), DUP(op_AND_118))), CAST(16, MSB(DUP(op_AND_118)), DUP(op_AND_118)))), CAST(64, MSB(op_MUL_138), DUP(op_MUL_138)));
	RzILOpPure *op_AND_145 = LOGAND(op_ADD_142, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_150 = SHIFTL0(CAST(64, IL_FALSE, op_AND_145), SN(32, 0x20));
	RzILOpPure *op_OR_152 = LOGOR(CAST(64, IL_FALSE, op_AND_111), op_LSHIFT_150);
	RzILOpEffect *op_ASSIGN_154 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_152));

	// Rxx = ((st64) (((ut64) (Rxx & (~(0xffff << 0x30)))) | (((ut64) (((st64) ((st32) ((st16) ((Rxx >> 0x30) & ((st64) 0xffff))))) + ((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x18) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x18) & 0xff))))) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_160 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_161 = LOGNOT(op_LSHIFT_160);
	RzILOpPure *op_AND_162 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_161);
	RzILOpPure *op_RSHIFT_166 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x30));
	RzILOpPure *op_AND_169 = LOGAND(op_RSHIFT_166, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_174 = SHIFTRA(DUP(Rs), SN(32, 24));
	RzILOpPure *op_AND_176 = LOGAND(op_RSHIFT_174, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_183 = SHIFTRA(DUP(Rt), SN(32, 24));
	RzILOpPure *op_AND_185 = LOGAND(op_RSHIFT_183, SN(32, 0xff));
	RzILOpPure *op_MUL_189 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_176))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_176)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_185))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_185)))));
	RzILOpPure *op_ADD_193 = ADD(CAST(64, MSB(CAST(32, MSB(CAST(16, MSB(op_AND_169), DUP(op_AND_169))), CAST(16, MSB(DUP(op_AND_169)), DUP(op_AND_169)))), CAST(32, MSB(CAST(16, MSB(DUP(op_AND_169)), DUP(op_AND_169))), CAST(16, MSB(DUP(op_AND_169)), DUP(op_AND_169)))), CAST(64, MSB(op_MUL_189), DUP(op_MUL_189)));
	RzILOpPure *op_AND_196 = LOGAND(op_ADD_193, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_201 = SHIFTL0(CAST(64, IL_FALSE, op_AND_196), SN(32, 0x30));
	RzILOpPure *op_OR_203 = LOGOR(CAST(64, IL_FALSE, op_AND_162), op_LSHIFT_201);
	RzILOpEffect *op_ASSIGN_205 = WRITE_REG(bundle, Rxx_op, CAST(64, IL_FALSE, op_OR_203));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_52, op_ASSIGN_103, op_ASSIGN_154, op_ASSIGN_205);
	return instruction_sequence;
}

// Rdd = vmpybsu(Rs,Rt)
RzILOpEffect *hex_il_op_m5_vmpybsu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st64) ((st32) ((st16) ((st8) ((Rs >> 0x0) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x0) & 0xff))))) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(32, 0xff));
	RzILOpPure *op_MUL_28 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_14), DUP(op_AND_14))), CAST(8, MSB(DUP(op_AND_14)), DUP(op_AND_14)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_14)), DUP(op_AND_14))), CAST(8, MSB(DUP(op_AND_14)), DUP(op_AND_14)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_24))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_24)))));
	RzILOpPure *op_AND_32 = LOGAND(CAST(64, MSB(op_MUL_28), DUP(op_MUL_28)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(CAST(64, IL_FALSE, op_AND_32), SN(32, 0));
	RzILOpPure *op_OR_39 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_39));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st64) ((st32) ((st16) ((st8) ((Rs >> 0x8) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x8) & 0xff))))) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_48 = LOGNOT(op_LSHIFT_47);
	RzILOpPure *op_AND_49 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_48);
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rs), SN(32, 8));
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_53, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rt), SN(32, 8));
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_62, SN(32, 0xff));
	RzILOpPure *op_MUL_68 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_55), DUP(op_AND_55))), CAST(8, MSB(DUP(op_AND_55)), DUP(op_AND_55)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_55)), DUP(op_AND_55))), CAST(8, MSB(DUP(op_AND_55)), DUP(op_AND_55)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_64))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_64)))));
	RzILOpPure *op_AND_72 = LOGAND(CAST(64, MSB(op_MUL_68), DUP(op_MUL_68)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_77 = SHIFTL0(CAST(64, IL_FALSE, op_AND_72), SN(32, 16));
	RzILOpPure *op_OR_79 = LOGOR(CAST(64, IL_FALSE, op_AND_49), op_LSHIFT_77);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_79));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st64) ((st32) ((st16) ((st8) ((Rs >> 0x10) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x10) & 0xff))))) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_87 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_88 = LOGNOT(op_LSHIFT_87);
	RzILOpPure *op_AND_89 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_88);
	RzILOpPure *op_RSHIFT_93 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_95 = LOGAND(op_RSHIFT_93, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_102 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_104 = LOGAND(op_RSHIFT_102, SN(32, 0xff));
	RzILOpPure *op_MUL_108 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_95), DUP(op_AND_95))), CAST(8, MSB(DUP(op_AND_95)), DUP(op_AND_95)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_95)), DUP(op_AND_95))), CAST(8, MSB(DUP(op_AND_95)), DUP(op_AND_95)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_104))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_104)))));
	RzILOpPure *op_AND_112 = LOGAND(CAST(64, MSB(op_MUL_108), DUP(op_MUL_108)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_117 = SHIFTL0(CAST(64, IL_FALSE, op_AND_112), SN(32, 0x20));
	RzILOpPure *op_OR_119 = LOGOR(CAST(64, IL_FALSE, op_AND_89), op_LSHIFT_117);
	RzILOpEffect *op_ASSIGN_121 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_119));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st64) ((st32) ((st16) ((st8) ((Rs >> 0x18) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x18) & 0xff))))) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_128 = LOGNOT(op_LSHIFT_127);
	RzILOpPure *op_AND_129 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_128);
	RzILOpPure *op_RSHIFT_133 = SHIFTRA(DUP(Rs), SN(32, 24));
	RzILOpPure *op_AND_135 = LOGAND(op_RSHIFT_133, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_142 = SHIFTRA(DUP(Rt), SN(32, 24));
	RzILOpPure *op_AND_144 = LOGAND(op_RSHIFT_142, SN(32, 0xff));
	RzILOpPure *op_MUL_148 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_135), DUP(op_AND_135))), CAST(8, MSB(DUP(op_AND_135)), DUP(op_AND_135)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_135)), DUP(op_AND_135))), CAST(8, MSB(DUP(op_AND_135)), DUP(op_AND_135)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_144))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_144)))));
	RzILOpPure *op_AND_152 = LOGAND(CAST(64, MSB(op_MUL_148), DUP(op_MUL_148)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_157 = SHIFTL0(CAST(64, IL_FALSE, op_AND_152), SN(32, 0x30));
	RzILOpPure *op_OR_159 = LOGOR(CAST(64, IL_FALSE, op_AND_129), op_LSHIFT_157);
	RzILOpEffect *op_ASSIGN_161 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_159));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_41, op_ASSIGN_81, op_ASSIGN_121, op_ASSIGN_161);
	return instruction_sequence;
}

// Rdd = vmpybu(Rs,Rt)
RzILOpEffect *hex_il_op_m5_vmpybuu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x0) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x0) & 0xff))))) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_14 = LOGAND(op_RSHIFT_12, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_22 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_22, SN(32, 0xff));
	RzILOpPure *op_MUL_28 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_14))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_14)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_24))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_24)))));
	RzILOpPure *op_AND_32 = LOGAND(CAST(64, MSB(op_MUL_28), DUP(op_MUL_28)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(CAST(64, IL_FALSE, op_AND_32), SN(32, 0));
	RzILOpPure *op_OR_39 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_37);
	RzILOpEffect *op_ASSIGN_41 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_39));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x8) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x8) & 0xff))))) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_48 = LOGNOT(op_LSHIFT_47);
	RzILOpPure *op_AND_49 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_48);
	RzILOpPure *op_RSHIFT_53 = SHIFTRA(DUP(Rs), SN(32, 8));
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_53, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_62 = SHIFTRA(DUP(Rt), SN(32, 8));
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_62, SN(32, 0xff));
	RzILOpPure *op_MUL_68 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_55))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_55)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_64))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_64)))));
	RzILOpPure *op_AND_72 = LOGAND(CAST(64, MSB(op_MUL_68), DUP(op_MUL_68)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_77 = SHIFTL0(CAST(64, IL_FALSE, op_AND_72), SN(32, 16));
	RzILOpPure *op_OR_79 = LOGOR(CAST(64, IL_FALSE, op_AND_49), op_LSHIFT_77);
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_79));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x10) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x10) & 0xff))))) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_87 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_88 = LOGNOT(op_LSHIFT_87);
	RzILOpPure *op_AND_89 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_88);
	RzILOpPure *op_RSHIFT_93 = SHIFTRA(DUP(Rs), SN(32, 16));
	RzILOpPure *op_AND_95 = LOGAND(op_RSHIFT_93, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_102 = SHIFTRA(DUP(Rt), SN(32, 16));
	RzILOpPure *op_AND_104 = LOGAND(op_RSHIFT_102, SN(32, 0xff));
	RzILOpPure *op_MUL_108 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_95))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_95)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_104))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_104)))));
	RzILOpPure *op_AND_112 = LOGAND(CAST(64, MSB(op_MUL_108), DUP(op_MUL_108)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_117 = SHIFTL0(CAST(64, IL_FALSE, op_AND_112), SN(32, 0x20));
	RzILOpPure *op_OR_119 = LOGOR(CAST(64, IL_FALSE, op_AND_89), op_LSHIFT_117);
	RzILOpEffect *op_ASSIGN_121 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_119));

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((st64) ((st32) ((st16) ((ut8) ((Rs >> 0x18) & 0xff)))) * ((st32) ((st16) ((ut8) ((Rt >> 0x18) & 0xff))))) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_128 = LOGNOT(op_LSHIFT_127);
	RzILOpPure *op_AND_129 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_128);
	RzILOpPure *op_RSHIFT_133 = SHIFTRA(DUP(Rs), SN(32, 24));
	RzILOpPure *op_AND_135 = LOGAND(op_RSHIFT_133, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_142 = SHIFTRA(DUP(Rt), SN(32, 24));
	RzILOpPure *op_AND_144 = LOGAND(op_RSHIFT_142, SN(32, 0xff));
	RzILOpPure *op_MUL_148 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_135))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_135)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_144))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_144)))));
	RzILOpPure *op_AND_152 = LOGAND(CAST(64, MSB(op_MUL_148), DUP(op_MUL_148)), CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_157 = SHIFTL0(CAST(64, IL_FALSE, op_AND_152), SN(32, 0x30));
	RzILOpPure *op_OR_159 = LOGOR(CAST(64, IL_FALSE, op_AND_129), op_LSHIFT_157);
	RzILOpEffect *op_ASSIGN_161 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_159));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_41, op_ASSIGN_81, op_ASSIGN_121, op_ASSIGN_161);
	return instruction_sequence;
}

// Rxx += vrmpybsu(Rss,Rtt)
RzILOpEffect *hex_il_op_m5_vrmacbsu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((Rxx >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_6);
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_23 = LOGAND(op_RSHIFT_20, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_38 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_23), DUP(op_AND_23))), CAST(8, MSB(DUP(op_AND_23)), DUP(op_AND_23)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_23)), DUP(op_AND_23))), CAST(8, MSB(DUP(op_AND_23)), DUP(op_AND_23)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_34))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_34)))));
	RzILOpPure *op_ADD_40 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_13), DUP(op_AND_13))), CAST(32, MSB(DUP(op_AND_13)), DUP(op_AND_13))), CAST(64, MSB(op_MUL_38), DUP(op_MUL_38)));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_61 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_47), DUP(op_AND_47))), CAST(8, MSB(DUP(op_AND_47)), DUP(op_AND_47)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_47)), DUP(op_AND_47))), CAST(8, MSB(DUP(op_AND_47)), DUP(op_AND_47)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_57))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_57)))));
	RzILOpPure *op_ADD_63 = ADD(op_ADD_40, CAST(64, MSB(op_MUL_61), DUP(op_MUL_61)));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_70 = LOGAND(op_RSHIFT_67, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_80 = LOGAND(op_RSHIFT_77, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_84 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_70), DUP(op_AND_70))), CAST(8, MSB(DUP(op_AND_70)), DUP(op_AND_70)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_70)), DUP(op_AND_70))), CAST(8, MSB(DUP(op_AND_70)), DUP(op_AND_70)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_80))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_80)))));
	RzILOpPure *op_ADD_86 = ADD(op_ADD_63, CAST(64, MSB(op_MUL_84), DUP(op_MUL_84)));
	RzILOpPure *op_RSHIFT_90 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_93 = LOGAND(op_RSHIFT_90, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_100 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_103 = LOGAND(op_RSHIFT_100, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_107 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_93), DUP(op_AND_93))), CAST(8, MSB(DUP(op_AND_93)), DUP(op_AND_93)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_93)), DUP(op_AND_93))), CAST(8, MSB(DUP(op_AND_93)), DUP(op_AND_93)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_103))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_103)))));
	RzILOpPure *op_ADD_109 = ADD(op_ADD_86, CAST(64, MSB(op_MUL_107), DUP(op_MUL_107)));
	RzILOpPure *op_AND_111 = LOGAND(op_ADD_109, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_115 = SHIFTL0(op_AND_111, SN(32, 0));
	RzILOpPure *op_OR_116 = LOGOR(op_AND_7, op_LSHIFT_115);
	RzILOpEffect *op_ASSIGN_117 = WRITE_REG(bundle, Rxx_op, op_OR_116);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_123 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_124 = LOGNOT(op_LSHIFT_123);
	RzILOpPure *op_AND_125 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_124);
	RzILOpPure *op_RSHIFT_129 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_131 = LOGAND(op_RSHIFT_129, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_137 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_140 = LOGAND(op_RSHIFT_137, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_147 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_150 = LOGAND(op_RSHIFT_147, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_154 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_140), DUP(op_AND_140))), CAST(8, MSB(DUP(op_AND_140)), DUP(op_AND_140)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_140)), DUP(op_AND_140))), CAST(8, MSB(DUP(op_AND_140)), DUP(op_AND_140)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_150))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_150)))));
	RzILOpPure *op_ADD_156 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_131), DUP(op_AND_131))), CAST(32, MSB(DUP(op_AND_131)), DUP(op_AND_131))), CAST(64, MSB(op_MUL_154), DUP(op_MUL_154)));
	RzILOpPure *op_RSHIFT_160 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_163 = LOGAND(op_RSHIFT_160, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_173 = LOGAND(op_RSHIFT_170, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_177 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_163), DUP(op_AND_163))), CAST(8, MSB(DUP(op_AND_163)), DUP(op_AND_163)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_163)), DUP(op_AND_163))), CAST(8, MSB(DUP(op_AND_163)), DUP(op_AND_163)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_173))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_173)))));
	RzILOpPure *op_ADD_179 = ADD(op_ADD_156, CAST(64, MSB(op_MUL_177), DUP(op_MUL_177)));
	RzILOpPure *op_RSHIFT_183 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_186 = LOGAND(op_RSHIFT_183, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_193 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_196 = LOGAND(op_RSHIFT_193, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_200 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_186), DUP(op_AND_186))), CAST(8, MSB(DUP(op_AND_186)), DUP(op_AND_186)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_186)), DUP(op_AND_186))), CAST(8, MSB(DUP(op_AND_186)), DUP(op_AND_186)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_196))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_196)))));
	RzILOpPure *op_ADD_202 = ADD(op_ADD_179, CAST(64, MSB(op_MUL_200), DUP(op_MUL_200)));
	RzILOpPure *op_RSHIFT_206 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_209 = LOGAND(op_RSHIFT_206, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_216 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_219 = LOGAND(op_RSHIFT_216, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_223 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_209), DUP(op_AND_209))), CAST(8, MSB(DUP(op_AND_209)), DUP(op_AND_209)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_209)), DUP(op_AND_209))), CAST(8, MSB(DUP(op_AND_209)), DUP(op_AND_209)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_219))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_219)))));
	RzILOpPure *op_ADD_225 = ADD(op_ADD_202, CAST(64, MSB(op_MUL_223), DUP(op_MUL_223)));
	RzILOpPure *op_AND_227 = LOGAND(op_ADD_225, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_231 = SHIFTL0(op_AND_227, SN(32, 0x20));
	RzILOpPure *op_OR_232 = LOGOR(op_AND_125, op_LSHIFT_231);
	RzILOpEffect *op_ASSIGN_233 = WRITE_REG(bundle, Rxx_op, op_OR_232);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_117, op_ASSIGN_233);
	return instruction_sequence;
}

// Rxx += vrmpybu(Rss,Rtt)
RzILOpEffect *hex_il_op_m5_vrmacbuu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((Rxx >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_6);
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_23 = LOGAND(op_RSHIFT_20, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_31 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_38 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_23))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_23)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_34))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_34)))));
	RzILOpPure *op_ADD_40 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_13), DUP(op_AND_13))), CAST(32, MSB(DUP(op_AND_13)), DUP(op_AND_13))), CAST(64, MSB(op_MUL_38), DUP(op_MUL_38)));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_54 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_61 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_47))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_47)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_57))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_57)))));
	RzILOpPure *op_ADD_63 = ADD(op_ADD_40, CAST(64, MSB(op_MUL_61), DUP(op_MUL_61)));
	RzILOpPure *op_RSHIFT_67 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_70 = LOGAND(op_RSHIFT_67, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_80 = LOGAND(op_RSHIFT_77, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_84 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_70))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_70)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_80))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_80)))));
	RzILOpPure *op_ADD_86 = ADD(op_ADD_63, CAST(64, MSB(op_MUL_84), DUP(op_MUL_84)));
	RzILOpPure *op_RSHIFT_90 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_93 = LOGAND(op_RSHIFT_90, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_100 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_103 = LOGAND(op_RSHIFT_100, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_107 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_93))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_93)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_103))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_103)))));
	RzILOpPure *op_ADD_109 = ADD(op_ADD_86, CAST(64, MSB(op_MUL_107), DUP(op_MUL_107)));
	RzILOpPure *op_AND_111 = LOGAND(op_ADD_109, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_115 = SHIFTL0(op_AND_111, SN(32, 0));
	RzILOpPure *op_OR_116 = LOGOR(op_AND_7, op_LSHIFT_115);
	RzILOpEffect *op_ASSIGN_117 = WRITE_REG(bundle, Rxx_op, op_OR_116);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_123 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_124 = LOGNOT(op_LSHIFT_123);
	RzILOpPure *op_AND_125 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_124);
	RzILOpPure *op_RSHIFT_129 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_131 = LOGAND(op_RSHIFT_129, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_137 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_140 = LOGAND(op_RSHIFT_137, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_147 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_150 = LOGAND(op_RSHIFT_147, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_154 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_140))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_140)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_150))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_150)))));
	RzILOpPure *op_ADD_156 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_131), DUP(op_AND_131))), CAST(32, MSB(DUP(op_AND_131)), DUP(op_AND_131))), CAST(64, MSB(op_MUL_154), DUP(op_MUL_154)));
	RzILOpPure *op_RSHIFT_160 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_163 = LOGAND(op_RSHIFT_160, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_170 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_173 = LOGAND(op_RSHIFT_170, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_177 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_163))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_163)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_173))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_173)))));
	RzILOpPure *op_ADD_179 = ADD(op_ADD_156, CAST(64, MSB(op_MUL_177), DUP(op_MUL_177)));
	RzILOpPure *op_RSHIFT_183 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_186 = LOGAND(op_RSHIFT_183, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_193 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_196 = LOGAND(op_RSHIFT_193, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_200 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_186))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_186)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_196))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_196)))));
	RzILOpPure *op_ADD_202 = ADD(op_ADD_179, CAST(64, MSB(op_MUL_200), DUP(op_MUL_200)));
	RzILOpPure *op_RSHIFT_206 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_209 = LOGAND(op_RSHIFT_206, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_216 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_219 = LOGAND(op_RSHIFT_216, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_223 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_209))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_209)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_219))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_219)))));
	RzILOpPure *op_ADD_225 = ADD(op_ADD_202, CAST(64, MSB(op_MUL_223), DUP(op_MUL_223)));
	RzILOpPure *op_AND_227 = LOGAND(op_ADD_225, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_231 = SHIFTL0(op_AND_227, SN(32, 0x20));
	RzILOpPure *op_OR_232 = LOGOR(op_AND_125, op_LSHIFT_231);
	RzILOpEffect *op_ASSIGN_233 = WRITE_REG(bundle, Rxx_op, op_OR_232);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_117, op_ASSIGN_233);
	return instruction_sequence;
}

// Rdd = vrmpybsu(Rss,Rtt)
RzILOpEffect *hex_il_op_m5_vrmpybsu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_12, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_30 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_15), DUP(op_AND_15))), CAST(8, MSB(DUP(op_AND_15)), DUP(op_AND_15)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_15)), DUP(op_AND_15))), CAST(8, MSB(DUP(op_AND_15)), DUP(op_AND_15)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_26))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_26)))));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_52 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_38), DUP(op_AND_38))), CAST(8, MSB(DUP(op_AND_38)), DUP(op_AND_38)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_38)), DUP(op_AND_38))), CAST(8, MSB(DUP(op_AND_38)), DUP(op_AND_38)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_48))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_48)))));
	RzILOpPure *op_ADD_54 = ADD(CAST(64, MSB(op_MUL_30), DUP(op_MUL_30)), CAST(64, MSB(op_MUL_52), DUP(op_MUL_52)));
	RzILOpPure *op_RSHIFT_58 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_68 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_71 = LOGAND(op_RSHIFT_68, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_75 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_61), DUP(op_AND_61))), CAST(8, MSB(DUP(op_AND_61)), DUP(op_AND_61)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_61)), DUP(op_AND_61))), CAST(8, MSB(DUP(op_AND_61)), DUP(op_AND_61)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_71))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_71)))));
	RzILOpPure *op_ADD_77 = ADD(op_ADD_54, CAST(64, MSB(op_MUL_75), DUP(op_MUL_75)));
	RzILOpPure *op_RSHIFT_81 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_84 = LOGAND(op_RSHIFT_81, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_98 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_84), DUP(op_AND_84))), CAST(8, MSB(DUP(op_AND_84)), DUP(op_AND_84)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_84)), DUP(op_AND_84))), CAST(8, MSB(DUP(op_AND_84)), DUP(op_AND_84)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_94))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_94)))));
	RzILOpPure *op_ADD_100 = ADD(op_ADD_77, CAST(64, MSB(op_MUL_98), DUP(op_MUL_98)));
	RzILOpPure *op_AND_102 = LOGAND(op_ADD_100, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_106 = SHIFTL0(op_AND_102, SN(32, 0));
	RzILOpPure *op_OR_107 = LOGOR(op_AND_7, op_LSHIFT_106);
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rdd_op, op_OR_107);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((st16) ((st8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((st8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_114 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_115 = LOGNOT(op_LSHIFT_114);
	RzILOpPure *op_AND_116 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_115);
	RzILOpPure *op_RSHIFT_120 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_123 = LOGAND(op_RSHIFT_120, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_130 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_133 = LOGAND(op_RSHIFT_130, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_137 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_123), DUP(op_AND_123))), CAST(8, MSB(DUP(op_AND_123)), DUP(op_AND_123)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_123)), DUP(op_AND_123))), CAST(8, MSB(DUP(op_AND_123)), DUP(op_AND_123)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_133))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_133)))));
	RzILOpPure *op_RSHIFT_142 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_145 = LOGAND(op_RSHIFT_142, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_152 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_155 = LOGAND(op_RSHIFT_152, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_159 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_145), DUP(op_AND_145))), CAST(8, MSB(DUP(op_AND_145)), DUP(op_AND_145)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_145)), DUP(op_AND_145))), CAST(8, MSB(DUP(op_AND_145)), DUP(op_AND_145)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_155))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_155)))));
	RzILOpPure *op_ADD_161 = ADD(CAST(64, MSB(op_MUL_137), DUP(op_MUL_137)), CAST(64, MSB(op_MUL_159), DUP(op_MUL_159)));
	RzILOpPure *op_RSHIFT_165 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_168 = LOGAND(op_RSHIFT_165, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_175 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_178 = LOGAND(op_RSHIFT_175, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_182 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_168), DUP(op_AND_168))), CAST(8, MSB(DUP(op_AND_168)), DUP(op_AND_168)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_168)), DUP(op_AND_168))), CAST(8, MSB(DUP(op_AND_168)), DUP(op_AND_168)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_178))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_178)))));
	RzILOpPure *op_ADD_184 = ADD(op_ADD_161, CAST(64, MSB(op_MUL_182), DUP(op_MUL_182)));
	RzILOpPure *op_RSHIFT_188 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_191 = LOGAND(op_RSHIFT_188, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_198 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_201 = LOGAND(op_RSHIFT_198, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_205 = MUL(CAST(32, MSB(CAST(16, MSB(CAST(8, MSB(op_AND_191), DUP(op_AND_191))), CAST(8, MSB(DUP(op_AND_191)), DUP(op_AND_191)))), CAST(16, MSB(CAST(8, MSB(DUP(op_AND_191)), DUP(op_AND_191))), CAST(8, MSB(DUP(op_AND_191)), DUP(op_AND_191)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_201))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_201)))));
	RzILOpPure *op_ADD_207 = ADD(op_ADD_184, CAST(64, MSB(op_MUL_205), DUP(op_MUL_205)));
	RzILOpPure *op_AND_209 = LOGAND(op_ADD_207, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_213 = SHIFTL0(op_AND_209, SN(32, 0x20));
	RzILOpPure *op_OR_214 = LOGOR(op_AND_116, op_LSHIFT_213);
	RzILOpEffect *op_ASSIGN_215 = WRITE_REG(bundle, Rdd_op, op_OR_214);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_108, op_ASSIGN_215);
	return instruction_sequence;
}

// Rdd = vrmpybu(Rss,Rtt)
RzILOpEffect *hex_il_op_m5_vrmpybuu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x0) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x0) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x8) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x8) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x10) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x10) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x18) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x18) & ((st64) 0xff)))))) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_12, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_23 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_23, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_30 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_15))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_15)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_26))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_26)))));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), SN(32, 8));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_45 = SHIFTRA(DUP(Rtt), SN(32, 8));
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_45, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_52 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_38))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_38)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_48))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_48)))));
	RzILOpPure *op_ADD_54 = ADD(CAST(64, MSB(op_MUL_30), DUP(op_MUL_30)), CAST(64, MSB(op_MUL_52), DUP(op_MUL_52)));
	RzILOpPure *op_RSHIFT_58 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_61 = LOGAND(op_RSHIFT_58, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_68 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_71 = LOGAND(op_RSHIFT_68, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_75 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_61))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_61)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_71))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_71)))));
	RzILOpPure *op_ADD_77 = ADD(op_ADD_54, CAST(64, MSB(op_MUL_75), DUP(op_MUL_75)));
	RzILOpPure *op_RSHIFT_81 = SHIFTRA(DUP(Rss), SN(32, 24));
	RzILOpPure *op_AND_84 = LOGAND(op_RSHIFT_81, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), SN(32, 24));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_98 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_84))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_84)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_94))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_94)))));
	RzILOpPure *op_ADD_100 = ADD(op_ADD_77, CAST(64, MSB(op_MUL_98), DUP(op_MUL_98)));
	RzILOpPure *op_AND_102 = LOGAND(op_ADD_100, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_106 = SHIFTL0(op_AND_102, SN(32, 0));
	RzILOpPure *op_OR_107 = LOGOR(op_AND_7, op_LSHIFT_106);
	RzILOpEffect *op_ASSIGN_108 = WRITE_REG(bundle, Rdd_op, op_OR_107);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x20) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x20) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x28) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x28) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x30) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x30) & ((st64) 0xff)))))) + ((st64) ((st32) ((st16) ((ut8) ((Rss >> 0x38) & ((st64) 0xff))))) * ((st32) ((st16) ((ut8) ((Rtt >> 0x38) & ((st64) 0xff)))))) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_114 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_115 = LOGNOT(op_LSHIFT_114);
	RzILOpPure *op_AND_116 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_115);
	RzILOpPure *op_RSHIFT_120 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_123 = LOGAND(op_RSHIFT_120, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_130 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_133 = LOGAND(op_RSHIFT_130, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_137 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_123))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_123)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_133))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_133)))));
	RzILOpPure *op_RSHIFT_142 = SHIFTRA(DUP(Rss), SN(32, 0x28));
	RzILOpPure *op_AND_145 = LOGAND(op_RSHIFT_142, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_152 = SHIFTRA(DUP(Rtt), SN(32, 0x28));
	RzILOpPure *op_AND_155 = LOGAND(op_RSHIFT_152, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_159 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_145))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_145)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_155))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_155)))));
	RzILOpPure *op_ADD_161 = ADD(CAST(64, MSB(op_MUL_137), DUP(op_MUL_137)), CAST(64, MSB(op_MUL_159), DUP(op_MUL_159)));
	RzILOpPure *op_RSHIFT_165 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_168 = LOGAND(op_RSHIFT_165, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_175 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_178 = LOGAND(op_RSHIFT_175, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_182 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_168))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_168)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_178))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_178)))));
	RzILOpPure *op_ADD_184 = ADD(op_ADD_161, CAST(64, MSB(op_MUL_182), DUP(op_MUL_182)));
	RzILOpPure *op_RSHIFT_188 = SHIFTRA(DUP(Rss), SN(32, 0x38));
	RzILOpPure *op_AND_191 = LOGAND(op_RSHIFT_188, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_RSHIFT_198 = SHIFTRA(DUP(Rtt), SN(32, 0x38));
	RzILOpPure *op_AND_201 = LOGAND(op_RSHIFT_198, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_205 = MUL(CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_191))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_191)))), CAST(32, MSB(CAST(16, IL_FALSE, CAST(8, IL_FALSE, op_AND_201))), CAST(16, IL_FALSE, CAST(8, IL_FALSE, DUP(op_AND_201)))));
	RzILOpPure *op_ADD_207 = ADD(op_ADD_184, CAST(64, MSB(op_MUL_205), DUP(op_MUL_205)));
	RzILOpPure *op_AND_209 = LOGAND(op_ADD_207, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_213 = SHIFTL0(op_AND_209, SN(32, 0x20));
	RzILOpPure *op_OR_214 = LOGOR(op_AND_116, op_LSHIFT_213);
	RzILOpEffect *op_ASSIGN_215 = WRITE_REG(bundle, Rdd_op, op_OR_214);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_108, op_ASSIGN_215);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>