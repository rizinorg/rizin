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

// Rdd = convert_d2df(Rss)
RzILOpEffect *hex_il_op_f2_conv_d2df(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) fUNDOUBLE(HEX_SINT_TO_D(HEX_GET_INSN_RMODE(hi), Rss)));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, F2BV(HEX_SINT_TO_D(HEX_GET_INSN_RMODE(hi), Rss))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_6;
	return instruction_sequence;
}

// Rd = convert_d2sf(Rss)
RzILOpEffect *hex_il_op_f2_conv_d2sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_df2d(Rss)
RzILOpEffect *hex_il_op_f2_conv_df2d(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Rdd = convert_df2d(Rss):chop
RzILOpEffect *hex_il_op_f2_conv_df2d_chop(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rd = convert_df2sf(Rss)
RzILOpEffect *hex_il_op_f2_conv_df2sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_df2ud(Rss)
RzILOpEffect *hex_il_op_f2_conv_df2ud(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Rdd = convert_df2ud(Rss):chop
RzILOpEffect *hex_il_op_f2_conv_df2ud_chop(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rd = convert_df2uw(Rss)
RzILOpEffect *hex_il_op_f2_conv_df2uw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rd = ((st32) ((ut32) HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)))));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss))))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rd = convert_df2uw(Rss):chop
RzILOpEffect *hex_il_op_f2_conv_df2uw_chop(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rd = ((st32) ((ut32) HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)))));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, HEX_D_TO_INT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss))))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_9;
	return instruction_sequence;
}

// Rd = convert_df2w(Rss)
RzILOpEffect *hex_il_op_f2_conv_df2w(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rd = ((st32) HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Rd = convert_df2w(Rss):chop
RzILOpEffect *hex_il_op_f2_conv_df2w_chop(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rd = ((st32) HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, HEX_D_TO_SINT(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rdd = convert_sf2d(Rs)
RzILOpEffect *hex_il_op_f2_conv_sf2d(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_sf2d(Rs):chop
RzILOpEffect *hex_il_op_f2_conv_sf2d_chop(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_sf2df(Rs)
RzILOpEffect *hex_il_op_f2_conv_sf2df(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_sf2ud(Rs)
RzILOpEffect *hex_il_op_f2_conv_sf2ud(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_sf2ud(Rs):chop
RzILOpEffect *hex_il_op_f2_conv_sf2ud_chop(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = convert_sf2uw(Rs)
RzILOpEffect *hex_il_op_f2_conv_sf2uw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = convert_sf2uw(Rs):chop
RzILOpEffect *hex_il_op_f2_conv_sf2uw_chop(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = convert_sf2w(Rs)
RzILOpEffect *hex_il_op_f2_conv_sf2w(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = convert_sf2w(Rs):chop
RzILOpEffect *hex_il_op_f2_conv_sf2w_chop(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_ud2df(Rss)
RzILOpEffect *hex_il_op_f2_conv_ud2df(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = ((st64) fUNDOUBLE(HEX_INT_TO_D(HEX_GET_INSN_RMODE(hi), ((ut64) Rss))));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, F2BV(HEX_INT_TO_D(HEX_GET_INSN_RMODE(hi), CAST(64, IL_FALSE, Rss)))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Rd = convert_ud2sf(Rss)
RzILOpEffect *hex_il_op_f2_conv_ud2sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_uw2df(Rs)
RzILOpEffect *hex_il_op_f2_conv_uw2df(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((st64) fUNDOUBLE(HEX_INT_TO_D(HEX_GET_INSN_RMODE(hi), ((ut64) ((ut32) Rs)))));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, F2BV(HEX_INT_TO_D(HEX_GET_INSN_RMODE(hi), CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs))))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_8;
	return instruction_sequence;
}

// Rd = convert_uw2sf(Rs)
RzILOpEffect *hex_il_op_f2_conv_uw2sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = convert_w2df(Rs)
RzILOpEffect *hex_il_op_f2_conv_w2df(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rdd = ((st64) fUNDOUBLE(HEX_SINT_TO_D(HEX_GET_INSN_RMODE(hi), ((st64) Rs))));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, F2BV(HEX_SINT_TO_D(HEX_GET_INSN_RMODE(hi), CAST(64, MSB(Rs), DUP(Rs))))));

	RzILOpEffect *instruction_sequence = op_ASSIGN_7;
	return instruction_sequence;
}

// Rd = convert_w2sf(Rs)
RzILOpEffect *hex_il_op_f2_conv_w2sf(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = dfadd(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfadd(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) fUNDOUBLE(DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)) + DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rtt))));
	RzILOpPure *op_ADD_7 = FADD(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rtt)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, F2BV(op_ADD_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = dfclass(Rss,Ii)
RzILOpEffect *hex_il_op_f2_dfclass(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Pd = dfcmp.eq(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfcmpeq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) ((DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)) == DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rtt))) ? 0xff : 0x0));
	RzILOpPure *op_EQ_7 = FEQ(BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rtt)));
	RzILOpPure *cond_10 = ITE(op_EQ_7, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_10), DUP(cond_10)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

// Pd = dfcmp.ge(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfcmpge(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) ((DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)) >= DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rtt))) ? 0xff : 0x0));
	RzILOpPure *op_GE_7 = FGE(BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rtt)));
	RzILOpPure *cond_10 = ITE(op_GE_7, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_10), DUP(cond_10)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

// Pd = dfcmp.gt(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfcmpgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Pd = ((st8) ((DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)) > DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rtt))) ? 0xff : 0x0));
	RzILOpPure *op_GT_7 = FGT(BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rtt)));
	RzILOpPure *cond_10 = ITE(op_GT_7, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_10), DUP(cond_10)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

// Pd = dfcmp.uo(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfcmpuo(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = dfmake(Ii):neg
RzILOpEffect *hex_il_op_f2_dfimm_n(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// Rdd = ((st64) (0x3f9 << 0x34));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(UN(64, 0x3f9), SN(32, 0x34));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_LSHIFT_5));

	// u = u;
	RzILOpEffect *imm_assign_8 = SETL("u", u);

	// Rdd = Rdd + ((st64) (((ut64) u) << 0x2e));
	RzILOpPure *op_LSHIFT_12 = SHIFTL0(CAST(64, IL_FALSE, VARL("u")), SN(32, 0x2e));
	RzILOpPure *op_ADD_14 = ADD(READ_REG(pkt, Rdd_op, true), CAST(64, IL_FALSE, op_LSHIFT_12));
	RzILOpEffect *op_ASSIGN_ADD_15 = WRITE_REG(bundle, Rdd_op, op_ADD_14);

	// Rdd = (Rdd | ((st64) (0x1 << 0x3f)));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(UN(64, 1), SN(32, 0x3f));
	RzILOpPure *op_OR_20 = LOGOR(READ_REG(pkt, Rdd_op, true), CAST(64, IL_FALSE, op_LSHIFT_18));
	RzILOpEffect *op_ASSIGN_OR_21 = WRITE_REG(bundle, Rdd_op, op_OR_20);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_8, op_ASSIGN_7, op_ASSIGN_ADD_15, op_ASSIGN_OR_21);
	return instruction_sequence;
}

// Rdd = dfmake(Ii):pos
RzILOpEffect *hex_il_op_f2_dfimm_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// Rdd = ((st64) (0x3f9 << 0x34));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(UN(64, 0x3f9), SN(32, 0x34));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_LSHIFT_5));

	// u = u;
	RzILOpEffect *imm_assign_8 = SETL("u", u);

	// Rdd = Rdd + ((st64) (((ut64) u) << 0x2e));
	RzILOpPure *op_LSHIFT_12 = SHIFTL0(CAST(64, IL_FALSE, VARL("u")), SN(32, 0x2e));
	RzILOpPure *op_ADD_14 = ADD(READ_REG(pkt, Rdd_op, true), CAST(64, IL_FALSE, op_LSHIFT_12));
	RzILOpEffect *op_ASSIGN_ADD_15 = WRITE_REG(bundle, Rdd_op, op_ADD_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_8, op_ASSIGN_7, op_ASSIGN_ADD_15);
	return instruction_sequence;
}

// Rdd = dfmax(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfmax(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = dfmin(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfmin(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rxx += dfmpyhh(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfmpyhh(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rxx += dfmpylh(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfmpylh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + ((st64) (((ut64) ((ut32) ((Rss >> 0x0) & 0xffffffff))) * (((ut64) 0x100000) | extract64(((ut64) ((ut32) ((Rtt >> 0x20) & 0xffffffff))), 0x0, 0x14)) << 0x1));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(64, 0xffffffff));
	RzILOpPure *op_OR_28 = LOGOR(CAST(64, IL_FALSE, SN(32, 0x100000)), EXTRACT64(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_20)), SN(32, 0), SN(32, 20)));
	RzILOpPure *op_MUL_29 = MUL(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_7)), op_OR_28);
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(op_MUL_29, SN(32, 1));
	RzILOpPure *op_ADD_33 = ADD(READ_REG(pkt, Rxx_op, false), CAST(64, IL_FALSE, op_LSHIFT_31));
	RzILOpEffect *op_ASSIGN_ADD_34 = WRITE_REG(bundle, Rxx_op, op_ADD_33);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_34;
	return instruction_sequence;
}

// Rdd = dfmpyll(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfmpyll(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 prod;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// prod = ((ut64) ((ut32) ((ut64) ((ut32) ((Rss >> 0x0) & 0xffffffff))))) * ((ut64) ((ut32) ((ut64) ((ut32) ((Rtt >> 0x0) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_7)))), CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_18)))));
	RzILOpEffect *op_ASSIGN_24 = SETL("prod", op_MUL_23);

	// Rdd = ((st64) ((prod >> 0x20) << 0x1));
	RzILOpPure *op_RSHIFT_27 = SHIFTR0(VARL("prod"), SN(32, 0x20));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(op_RSHIFT_27, SN(32, 1));
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_LSHIFT_29));

	// Rdd = ((st64) ((((ut64) Rdd) & (~(0x1 << 0x0))) | (((ut64) 0x1) << 0x0)));
	RzILOpPure *op_LSHIFT_46 = SHIFTL0(UN(64, 1), SN(32, 0));
	RzILOpPure *op_NOT_47 = LOGNOT(op_LSHIFT_46);
	RzILOpPure *op_AND_49 = LOGAND(CAST(64, IL_FALSE, READ_REG(pkt, Rdd_op, true)), op_NOT_47);
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(CAST(64, IL_FALSE, SN(32, 1)), SN(32, 0));
	RzILOpPure *op_OR_54 = LOGOR(op_AND_49, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_56 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_54));

	// seq(Rdd = ((st64) ((((ut64) Rdd) & (~(0x1 << 0x0))) | (((ut64) 0 ...;
	RzILOpEffect *seq_then_57 = op_ASSIGN_56;

	// if ((((ut64) ((ut32) ((prod >> 0x0) & ((ut64) 0xffffffff)))) != ((ut64) 0x0))) {seq(Rdd = ((st64) ((((ut64) Rdd) & (~(0x1 << 0x0))) | (((ut64) 0 ...} else {{}};
	RzILOpPure *op_RSHIFT_35 = SHIFTR0(VARL("prod"), SN(32, 0));
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_NE_43 = INV(EQ(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_38)), CAST(64, IL_FALSE, SN(32, 0))));
	RzILOpEffect *branch_58 = BRANCH(op_NE_43, seq_then_57, EMPTY());

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_24, op_ASSIGN_31, branch_58);
	return instruction_sequence;
}

// Rdd = dfsub(Rss,Rtt)
RzILOpEffect *hex_il_op_f2_dfsub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) fUNDOUBLE(DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rss)) - DOUBLE(RZ_FLOAT_IEEE754_BIN_64, ((ut64) Rtt))));
	RzILOpPure *op_SUB_7 = FSUB(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rss)), BV2F(RZ_FLOAT_IEEE754_BIN_64, CAST(64, IL_FALSE, Rtt)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, F2BV(op_SUB_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Rd = sfadd(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfadd(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) fUNFLOAT(FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rs)) + FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rt))));
	RzILOpPure *op_ADD_7 = FADD(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rs)), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rt)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, F2BV(op_ADD_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

// Pd = sfclass(Rs,Ii)
RzILOpEffect *hex_il_op_f2_sfclass(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Pd = sfcmp.eq(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfcmpeq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rs)) == FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rt))) ? 0xff : 0x0));
	RzILOpPure *op_EQ_7 = FEQ(BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rs)), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rt)));
	RzILOpPure *cond_10 = ITE(op_EQ_7, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_10), DUP(cond_10)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

// Pd = sfcmp.ge(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfcmpge(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rs)) >= FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rt))) ? 0xff : 0x0));
	RzILOpPure *op_GE_7 = FGE(BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rs)), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rt)));
	RzILOpPure *cond_10 = ITE(op_GE_7, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_10), DUP(cond_10)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

// Pd = sfcmp.gt(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfcmpgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rs)) > FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rt))) ? 0xff : 0x0));
	RzILOpPure *op_GT_7 = FGT(BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rs)), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rt)));
	RzILOpPure *cond_10 = ITE(op_GT_7, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_10), DUP(cond_10)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_12;
	return instruction_sequence;
}

// Pd = sfcmp.uo(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfcmpuo(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sffixupd(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sffixupd(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sffixupn(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sffixupn(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sffixupr(Rs)
RzILOpEffect *hex_il_op_f2_sffixupr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rx += sfmpy(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sffma(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rx += sfmpy(Rs,Rt):lib
RzILOpEffect *hex_il_op_f2_sffma_lib(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rx += sfmpy(Rs,Rt,Pu):scale
RzILOpEffect *hex_il_op_f2_sffma_sc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rx -= sfmpy(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sffms(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rx -= sfmpy(Rs,Rt):lib
RzILOpEffect *hex_il_op_f2_sffms_lib(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sfmake(Ii):neg
RzILOpEffect *hex_il_op_f2_sfimm_n(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// Rd = (0x79 << 0x17);
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 0x79), SN(32, 23));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, op_LSHIFT_5);

	// u = u;
	RzILOpEffect *imm_assign_7 = SETL("u", u);

	// Rd = Rd + ((st32) (u << 0x11));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(VARL("u"), SN(32, 17));
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rd_op, true), CAST(32, IL_FALSE, op_LSHIFT_10));
	RzILOpEffect *op_ASSIGN_ADD_13 = WRITE_REG(bundle, Rd_op, op_ADD_12);

	// Rd = (Rd | (0x1 << 0x1f));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(SN(32, 1), SN(32, 31));
	RzILOpPure *op_OR_17 = LOGOR(READ_REG(pkt, Rd_op, true), op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_OR_18 = WRITE_REG(bundle, Rd_op, op_OR_17);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_7, op_ASSIGN_6, op_ASSIGN_ADD_13, op_ASSIGN_OR_18);
	return instruction_sequence;
}

// Rd = sfmake(Ii):pos
RzILOpEffect *hex_il_op_f2_sfimm_p(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// Rd = (0x79 << 0x17);
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 0x79), SN(32, 23));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, op_LSHIFT_5);

	// u = u;
	RzILOpEffect *imm_assign_7 = SETL("u", u);

	// Rd = Rd + ((st32) (u << 0x11));
	RzILOpPure *op_LSHIFT_10 = SHIFTL0(VARL("u"), SN(32, 17));
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rd_op, true), CAST(32, IL_FALSE, op_LSHIFT_10));
	RzILOpEffect *op_ASSIGN_ADD_13 = WRITE_REG(bundle, Rd_op, op_ADD_12);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_7, op_ASSIGN_6, op_ASSIGN_ADD_13);
	return instruction_sequence;
}

// Rd,Pe = sfinvsqrta(Rs)
RzILOpEffect *hex_il_op_f2_sfinvsqrta(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sfmax(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfmax(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sfmin(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfmin(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sfmpy(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfmpy(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd,Pe = sfrecipa(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfrecipa(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = sfsub(Rs,Rt)
RzILOpEffect *hex_il_op_f2_sfsub(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) fUNFLOAT(FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rs)) - FLOAT(RZ_FLOAT_IEEE754_BIN_32, ((ut32) Rt))));
	RzILOpPure *op_SUB_7 = FSUB(HEX_GET_INSN_RMODE(hi), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rs)), BV2F(RZ_FLOAT_IEEE754_BIN_32, CAST(32, IL_FALSE, Rt)));
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, F2BV(op_SUB_7)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_10;
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>