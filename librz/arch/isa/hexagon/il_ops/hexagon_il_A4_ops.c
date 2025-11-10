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

// Rdd = add(Rss,Rtt,Px):carry
RzILOpEffect *hex_il_op_a4_addp_c(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = and(Rt,~Rs)
RzILOpEffect *hex_il_op_a4_andn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rt & (~Rs));
	RzILOpPure *op_NOT_3 = LOGNOT(Rs);
	RzILOpPure *op_AND_4 = LOGAND(Rt, op_NOT_3);
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_AND_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rdd = and(Rtt,~Rss)
RzILOpEffect *hex_il_op_a4_andnp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = (Rtt & (~Rss));
	RzILOpPure *op_NOT_3 = LOGNOT(Rss);
	RzILOpPure *op_AND_4 = LOGAND(Rtt, op_NOT_3);
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rdd_op, op_AND_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rdd = bitsplit(Rs,Rt)
RzILOpEffect *hex_il_op_a4_bitsplit(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: ut32 shamt;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// shamt = ((ut32) extract64(((ut64) Rt), 0x0, 0x5));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 5))));

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) (((ut32) Rs) >> shamt)) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_18 = LOGNOT(op_LSHIFT_17);
	RzILOpPure *op_AND_19 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_18);
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("shamt"));
	RzILOpPure *op_AND_25 = LOGAND(CAST(64, IL_FALSE, op_RSHIFT_22), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(op_AND_25, SN(32, 0x20));
	RzILOpPure *op_OR_30 = LOGOR(op_AND_19, op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rdd_op, op_OR_30);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << 0x0)))) | ((((shamt != ((ut32) 0x0)) ? extract64(((ut64) Rs), 0x0, ((st32) shamt)) : ((ut64) 0x0)) & ((ut64) 0xffffffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_37 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_38 = LOGNOT(op_LSHIFT_37);
	RzILOpPure *op_AND_39 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_38);
	RzILOpPure *op_NE_42 = INV(EQ(VARL("shamt"), CAST(32, IL_FALSE, SN(32, 0))));
	RzILOpPure *cond_49 = ITE(op_NE_42, EXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), CAST(32, IL_FALSE, VARL("shamt"))), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpPure *op_AND_52 = LOGAND(cond_49, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_LSHIFT_56 = SHIFTL0(op_AND_52, SN(32, 0));
	RzILOpPure *op_OR_58 = LOGOR(CAST(64, IL_FALSE, op_AND_39), op_LSHIFT_56);
	RzILOpEffect *op_ASSIGN_60 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_58));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_10, op_ASSIGN_31, op_ASSIGN_60);
	return instruction_sequence;
}

// Rdd = bitsplit(Rs,Ii)
RzILOpEffect *hex_il_op_a4_bitspliti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_10 = SETL("u", u);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) (((ut32) Rs) >> u)) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_12 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, op_RSHIFT_12), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(op_AND_15, SN(32, 0x20));
	RzILOpPure *op_OR_20 = LOGOR(op_AND_7, op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Rdd_op, op_OR_20);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffffffff << 0x0)))) | ((((u != ((ut32) 0x0)) ? extract64(((ut64) Rs), 0x0, ((st32) u)) : ((ut64) 0x0)) & ((ut64) 0xffffffff)) << 0x0)));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_29 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_28);
	RzILOpPure *op_NE_32 = INV(EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0))));
	RzILOpPure *cond_39 = ITE(op_NE_32, EXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), CAST(32, IL_FALSE, VARL("u"))), CAST(64, IL_FALSE, SN(64, 0)));
	RzILOpPure *op_AND_42 = LOGAND(cond_39, CAST(64, IL_FALSE, SN(64, 0xffffffff)));
	RzILOpPure *op_LSHIFT_46 = SHIFTL0(op_AND_42, SN(32, 0));
	RzILOpPure *op_OR_48 = LOGOR(CAST(64, IL_FALSE, op_AND_29), op_LSHIFT_46);
	RzILOpEffect *op_ASSIGN_50 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_48));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_21, op_ASSIGN_50);
	return instruction_sequence;
}

// Pd = boundscheck(Rss,Rtt):raw:hi
RzILOpEffect *hex_il_op_a4_boundscheck_hi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 src;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// src = ((ut32) ((ut64) ((ut32) ((Rss >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_11 = SETL("src", CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_7))));

	// Pd = ((st8) (((((ut64) src) >= ((ut64) ((ut32) ((Rtt >> 0x0) & 0xffffffff)))) && (((ut64) src) < ((ut64) ((ut32) ((Rtt >> 0x20) & 0xffffffff))))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpPure *op_GE_23 = UGE(CAST(64, IL_FALSE, VARL("src")), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_19)));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_LT_33 = ULT(CAST(64, IL_FALSE, VARL("src")), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_29)));
	RzILOpPure *op_AND_34 = AND(op_GE_23, op_LT_33);
	RzILOpPure *cond_37 = ITE(op_AND_34, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_37), DUP(cond_37)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_11, op_ASSIGN_39);
	return instruction_sequence;
}

// Pd = boundscheck(Rss,Rtt):raw:lo
RzILOpEffect *hex_il_op_a4_boundscheck_lo(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 src;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// src = ((ut32) ((ut64) ((ut32) ((Rss >> 0x0) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_11 = SETL("src", CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_7))));

	// Pd = ((st8) (((((ut64) src) >= ((ut64) ((ut32) ((Rtt >> 0x0) & 0xffffffff)))) && (((ut64) src) < ((ut64) ((ut32) ((Rtt >> 0x20) & 0xffffffff))))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpPure *op_GE_23 = UGE(CAST(64, IL_FALSE, VARL("src")), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_19)));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_LT_33 = ULT(CAST(64, IL_FALSE, VARL("src")), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_29)));
	RzILOpPure *op_AND_34 = AND(op_GE_23, op_LT_33);
	RzILOpPure *cond_37 = ITE(op_AND_34, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_39 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_37), DUP(cond_37)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_11, op_ASSIGN_39);
	return instruction_sequence;
}

// Pd = cmpb.eq(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cmpbeq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((st8) ((Rs >> 0x0) & 0xff)) == ((st8) ((Rt >> 0x0) & 0xff))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpPure *op_EQ_17 = EQ(CAST(8, MSB(op_AND_7), DUP(op_AND_7)), CAST(8, MSB(op_AND_15), DUP(op_AND_15)));
	RzILOpPure *cond_20 = ITE(op_EQ_17, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Pd = cmpb.eq(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cmpbeqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_9 = SETL("u", u);

	// Pd = ((st8) ((((ut32) ((ut8) ((Rs >> 0x0) & 0xff))) == u) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xff));
	RzILOpPure *op_EQ_12 = EQ(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_7)), VARL("u"));
	RzILOpPure *cond_15 = ITE(op_EQ_12, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_15), DUP(cond_15)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_9, op_ASSIGN_17);
	return instruction_sequence;
}

// Pd = cmpb.gt(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cmpbgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((st8) ((Rs >> 0x0) & 0xff)) > ((st8) ((Rt >> 0x0) & 0xff))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpPure *op_GT_17 = SGT(CAST(8, MSB(op_AND_7), DUP(op_AND_7)), CAST(8, MSB(op_AND_15), DUP(op_AND_15)));
	RzILOpPure *cond_20 = ITE(op_GT_17, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Pd = cmpb.gt(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cmpbgti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Pd = ((st8) ((((st32) ((st8) ((Rs >> 0x0) & 0xff))) > s) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xff));
	RzILOpPure *op_GT_12 = SGT(CAST(32, MSB(CAST(8, MSB(op_AND_7), DUP(op_AND_7))), CAST(8, MSB(DUP(op_AND_7)), DUP(op_AND_7))), VARL("s"));
	RzILOpPure *cond_15 = ITE(op_GT_12, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_15), DUP(cond_15)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_9, op_ASSIGN_17);
	return instruction_sequence;
}

// Pd = cmpb.gtu(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cmpbgtu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((ut8) ((Rs >> 0x0) & 0xff)) > ((ut8) ((Rt >> 0x0) & 0xff))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpPure *op_GT_17 = UGT(CAST(8, IL_FALSE, op_AND_7), CAST(8, IL_FALSE, op_AND_15));
	RzILOpPure *cond_20 = ITE(op_GT_17, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Pd = cmpb.gtu(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cmpbgtui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Pd = ((st8) ((((ut32) ((ut8) ((Rs >> 0x0) & 0xff))) > u) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(32, 0xff));
	RzILOpPure *op_GT_12 = UGT(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_9)), VARL("u"));
	RzILOpPure *cond_15 = ITE(op_GT_12, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_15), DUP(cond_15)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_17);
	return instruction_sequence;
}

// Pd = cmph.eq(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cmpheq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((st16) ((Rs >> 0x0) & 0xffff)) == ((st16) ((Rt >> 0x0) & 0xffff))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_EQ_17 = EQ(CAST(16, MSB(op_AND_7), DUP(op_AND_7)), CAST(16, MSB(op_AND_15), DUP(op_AND_15)));
	RzILOpPure *cond_20 = ITE(op_EQ_17, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Pd = cmph.eq(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cmpheqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Pd = ((st8) ((((st32) ((st16) ((Rs >> 0x0) & 0xffff))) == s) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(32, 0xffff));
	RzILOpPure *op_EQ_12 = EQ(CAST(32, MSB(CAST(16, MSB(op_AND_9), DUP(op_AND_9))), CAST(16, MSB(DUP(op_AND_9)), DUP(op_AND_9))), VARL("s"));
	RzILOpPure *cond_15 = ITE(op_EQ_12, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_15), DUP(cond_15)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_17);
	return instruction_sequence;
}

// Pd = cmph.gt(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cmphgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((st16) ((Rs >> 0x0) & 0xffff)) > ((st16) ((Rt >> 0x0) & 0xffff))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_GT_17 = SGT(CAST(16, MSB(op_AND_7), DUP(op_AND_7)), CAST(16, MSB(op_AND_15), DUP(op_AND_15)));
	RzILOpPure *cond_20 = ITE(op_GT_17, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Pd = cmph.gt(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cmphgti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Pd = ((st8) ((((st32) ((st16) ((Rs >> 0x0) & 0xffff))) > s) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(32, 0xffff));
	RzILOpPure *op_GT_12 = SGT(CAST(32, MSB(CAST(16, MSB(op_AND_9), DUP(op_AND_9))), CAST(16, MSB(DUP(op_AND_9)), DUP(op_AND_9))), VARL("s"));
	RzILOpPure *cond_15 = ITE(op_GT_12, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_15), DUP(cond_15)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_17);
	return instruction_sequence;
}

// Pd = cmph.gtu(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cmphgtu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) ((((ut16) ((Rs >> 0x0) & 0xffff)) > ((ut16) ((Rt >> 0x0) & 0xffff))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(32, 0xffff));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpPure *op_GT_17 = UGT(CAST(16, IL_FALSE, op_AND_7), CAST(16, IL_FALSE, op_AND_15));
	RzILOpPure *cond_20 = ITE(op_GT_17, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_22;
	return instruction_sequence;
}

// Pd = cmph.gtu(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cmphgtui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// Pd = ((st8) ((((ut32) ((ut16) ((Rs >> 0x0) & 0xffff))) > u) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rs, SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(32, 0xffff));
	RzILOpPure *op_GT_12 = UGT(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_9)), VARL("u"));
	RzILOpPure *cond_15 = ITE(op_GT_12, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_15), DUP(cond_15)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_17);
	return instruction_sequence;
}

// Rdd = combine(Ii,II)
RzILOpEffect *hex_il_op_a4_combineii(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) U) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_7 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_8 = LOGNOT(op_LSHIFT_7);
	RzILOpPure *op_AND_9 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_8);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, IL_FALSE, VARL("U")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_AND_12, SN(32, 0));
	RzILOpPure *op_OR_17 = LOGOR(op_AND_9, op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, op_OR_17);

	// s = s;
	RzILOpEffect *imm_assign_27 = SETL("s", s);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) s) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_25 = LOGNOT(op_LSHIFT_24);
	RzILOpPure *op_AND_26 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_25);
	RzILOpPure *op_AND_31 = LOGAND(CAST(64, MSB(VARL("s")), VARL("s")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_35 = SHIFTL0(op_AND_31, SN(32, 0x20));
	RzILOpPure *op_OR_36 = LOGOR(op_AND_26, op_LSHIFT_35);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Rdd_op, op_OR_36);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_27, op_ASSIGN_18, op_ASSIGN_37);
	return instruction_sequence;
}

// Rdd = combine(Ii,Rs)
RzILOpEffect *hex_il_op_a4_combineir(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) Rs) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_7 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_8 = LOGNOT(op_LSHIFT_7);
	RzILOpPure *op_AND_9 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_8);
	RzILOpPure *op_AND_13 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_17 = SHIFTL0(op_AND_13, SN(32, 0));
	RzILOpPure *op_OR_18 = LOGOR(op_AND_9, op_LSHIFT_17);
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rdd_op, op_OR_18);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) s) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_26 = LOGNOT(op_LSHIFT_25);
	RzILOpPure *op_AND_27 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_26);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(VARL("s")), VARL("s")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(op_AND_30, SN(32, 0x20));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_27, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, op_OR_35);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_19, op_ASSIGN_36);
	return instruction_sequence;
}

// Rdd = combine(Rs,Ii)
RzILOpEffect *hex_il_op_a4_combineri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((st64) s) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_7 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_8 = LOGNOT(op_LSHIFT_7);
	RzILOpPure *op_AND_9 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_8);
	RzILOpPure *op_AND_12 = LOGAND(CAST(64, MSB(VARL("s")), VARL("s")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_16 = SHIFTL0(op_AND_12, SN(32, 0));
	RzILOpPure *op_OR_17 = LOGOR(op_AND_9, op_LSHIFT_16);
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, op_OR_17);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((st64) Rs) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_25 = LOGNOT(op_LSHIFT_24);
	RzILOpPure *op_AND_26 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_25);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(Rs), DUP(Rs)), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(op_AND_30, SN(32, 0x20));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_26, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, op_OR_35);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_18, op_ASSIGN_36);
	return instruction_sequence;
}

// Rd = cround(Rs,Ii)
RzILOpEffect *hex_il_op_a4_cround_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// conv_round(Rs, ((st32) u));
	RzILOpEffect *conv_round_call_5 = hex_conv_round(Rs, CAST(32, IL_FALSE, VARL("u")));

	// h_tmp117 = conv_round(Rs, ((st32) u));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp117", SIGNED(32, VARL("ret_val")));

	// seq(conv_round(Rs, ((st32) u)); h_tmp117 = conv_round(Rs, ((st32 ...;
	RzILOpEffect *seq_8 = SEQN(2, conv_round_call_5, op_ASSIGN_hybrid_tmp_7);

	// Rd = h_tmp117;
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, VARL("h_tmp117"));

	// seq(seq(conv_round(Rs, ((st32) u)); h_tmp117 = conv_round(Rs, (( ...;
	RzILOpEffect *seq_10 = SEQN(2, seq_8, op_ASSIGN_9);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, seq_10);
	return instruction_sequence;
}

// Rd = cround(Rs,Rt)
RzILOpEffect *hex_il_op_a4_cround_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// conv_round(Rs, ((st32) extract64(((ut64) Rt), 0x0, 0x5)));
	RzILOpEffect *conv_round_call_12 = hex_conv_round(Rs, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 5))));

	// h_tmp118 = conv_round(Rs, ((st32) extract64(((ut64) Rt), 0x0, 0x5)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_14 = SETL("h_tmp118", SIGNED(32, VARL("ret_val")));

	// seq(conv_round(Rs, ((st32) extract64(((ut64) Rt), 0x0, 0x5))); h ...;
	RzILOpEffect *seq_15 = SEQN(2, conv_round_call_12, op_ASSIGN_hybrid_tmp_14);

	// Rd = h_tmp118;
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, VARL("h_tmp118"));

	// seq(seq(conv_round(Rs, ((st32) extract64(((ut64) Rt), 0x0, 0x5)) ...;
	RzILOpEffect *seq_17 = SEQN(2, seq_15, op_ASSIGN_16);

	RzILOpEffect *instruction_sequence = seq_17;
	return instruction_sequence;
}

// immext(Ii)
RzILOpEffect *hex_il_op_a4_ext(HexInsnPktBundle *bundle) {
	// READ

	RzILOpEffect *instruction_sequence = EMPTY();
	return instruction_sequence;
}

// Rd = modwrap(Rs,Rt)
RzILOpEffect *hex_il_op_a4_modwrapu(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((st32) ((ut32) Rs) + ((ut32) Rt));
	RzILOpPure *op_ADD_7 = ADD(CAST(32, IL_FALSE, Rs), CAST(32, IL_FALSE, Rt));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_7));

	// Rd = ((st32) ((ut32) Rs) - ((ut32) Rt));
	RzILOpPure *op_SUB_15 = SUB(CAST(32, IL_FALSE, DUP(Rs)), CAST(32, IL_FALSE, DUP(Rt)));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_SUB_15));

	// Rd = Rs;
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, DUP(Rs));

	// seq(Rd = ((st32) ((ut32) Rs) - ((ut32) Rt)));
	RzILOpEffect *seq_then_19 = op_ASSIGN_17;

	// seq(Rd = Rs);
	RzILOpEffect *seq_else_20 = op_ASSIGN_18;

	// if ((((ut32) Rs) >= ((ut32) Rt))) {seq(Rd = ((st32) ((ut32) Rs) - ((ut32) Rt)))} else {seq(Rd = Rs)};
	RzILOpPure *op_GE_12 = UGE(CAST(32, IL_FALSE, DUP(Rs)), CAST(32, IL_FALSE, DUP(Rt)));
	RzILOpEffect *branch_21 = BRANCH(op_GE_12, seq_then_19, seq_else_20);

	// seq(Rd = ((st32) ((ut32) Rs) + ((ut32) Rt)));
	RzILOpEffect *seq_then_22 = op_ASSIGN_9;

	// seq(if ((((ut32) Rs) >= ((ut32) Rt))) {seq(Rd = ((st32) ((ut32)  ...;
	RzILOpEffect *seq_else_23 = branch_21;

	// if ((Rs < 0x0)) {seq(Rd = ((st32) ((ut32) Rs) + ((ut32) Rt)))} else {seq(if ((((ut32) Rs) >= ((ut32) Rt))) {seq(Rd = ((st32) ((ut32)  ...};
	RzILOpPure *op_LT_2 = SLT(DUP(Rs), SN(32, 0));
	RzILOpEffect *branch_24 = BRANCH(op_LT_2, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = branch_24;
	return instruction_sequence;
}

// Rd = or(Rt,~Rs)
RzILOpEffect *hex_il_op_a4_orn(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rt | (~Rs));
	RzILOpPure *op_NOT_3 = LOGNOT(Rs);
	RzILOpPure *op_OR_4 = LOGOR(Rt, op_NOT_3);
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, op_OR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rdd = or(Rtt,~Rss)
RzILOpEffect *hex_il_op_a4_ornp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Rdd = (Rtt | (~Rss));
	RzILOpPure *op_NOT_3 = LOGNOT(Rss);
	RzILOpPure *op_OR_4 = LOGOR(Rtt, op_NOT_3);
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rdd_op, op_OR_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// if (!Pu) Rd = aslh(Rs)
RzILOpEffect *hex_il_op_a4_paslhf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs << 0x10);
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_LSHIFT_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs << 0x10));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = (Rs << 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = aslh(Rs)
RzILOpEffect *hex_il_op_a4_paslhfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs << 0x10);
	RzILOpPure *op_LSHIFT_8 = SHIFTL0(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_LSHIFT_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs << 0x10));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = (Rs << 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (Pu) Rd = aslh(Rs)
RzILOpEffect *hex_il_op_a4_paslht(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs << 0x10);
	RzILOpPure *op_LSHIFT_7 = SHIFTL0(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_LSHIFT_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs << 0x10));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = (Rs << 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = aslh(Rs)
RzILOpEffect *hex_il_op_a4_paslhtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs << 0x10);
	RzILOpPure *op_LSHIFT_7 = SHIFTL0(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_LSHIFT_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs << 0x10));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = (Rs << 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (!Pu) Rd = asrh(Rs)
RzILOpEffect *hex_il_op_a4_pasrhf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs >> 0x10);
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_RSHIFT_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs >> 0x10));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = (Rs >> 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (!Pu.new) Rd = asrh(Rs)
RzILOpEffect *hex_il_op_a4_pasrhfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs >> 0x10);
	RzILOpPure *op_RSHIFT_8 = SHIFTRA(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, op_RSHIFT_8);

	// nop;
	RzILOpEffect *nop_10 = NOP();

	// seq(Rd = (Rs >> 0x10));
	RzILOpEffect *seq_then_11 = op_ASSIGN_9;

	// seq(nop);
	RzILOpEffect *seq_else_12 = nop_10;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = (Rs >> 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_13 = BRANCH(op_INV_4, seq_then_11, seq_else_12);

	RzILOpEffect *instruction_sequence = branch_13;
	return instruction_sequence;
}

// if (Pu) Rd = asrh(Rs)
RzILOpEffect *hex_il_op_a4_pasrht(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs >> 0x10);
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_RSHIFT_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs >> 0x10));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = (Rs >> 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (Pu.new) Rd = asrh(Rs)
RzILOpEffect *hex_il_op_a4_pasrhtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = (Rs >> 0x10);
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rs, SN(32, 16));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rd_op, op_RSHIFT_7);

	// nop;
	RzILOpEffect *nop_9 = NOP();

	// seq(Rd = (Rs >> 0x10));
	RzILOpEffect *seq_then_10 = op_ASSIGN_8;

	// seq(nop);
	RzILOpEffect *seq_else_11 = nop_9;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = (Rs >> 0x10))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_12 = BRANCH(NON_ZERO(op_AND_3), seq_then_10, seq_else_11);

	RzILOpEffect *instruction_sequence = branch_12;
	return instruction_sequence;
}

// if (!Pu) Rd = sxtb(Rs)
RzILOpEffect *hex_il_op_a4_psxtbf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (!Pu.new) Rd = sxtb(Rs)
RzILOpEffect *hex_il_op_a4_psxtbfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (Pu) Rd = sxtb(Rs)
RzILOpEffect *hex_il_op_a4_psxtbt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (Pu.new) Rd = sxtb(Rs)
RzILOpEffect *hex_il_op_a4_psxtbtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (!Pu) Rd = sxth(Rs)
RzILOpEffect *hex_il_op_a4_psxthf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (!Pu.new) Rd = sxth(Rs)
RzILOpEffect *hex_il_op_a4_psxthfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (Pu) Rd = sxth(Rs)
RzILOpEffect *hex_il_op_a4_psxtht(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (Pu.new) Rd = sxth(Rs)
RzILOpEffect *hex_il_op_a4_psxthtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rs)), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) sextract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (!Pu) Rd = zxtb(Rs)
RzILOpEffect *hex_il_op_a4_pzxtbf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (!Pu.new) Rd = zxtb(Rs)
RzILOpEffect *hex_il_op_a4_pzxtbfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (Pu) Rd = zxtb(Rs)
RzILOpEffect *hex_il_op_a4_pzxtbt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (Pu.new) Rd = zxtb(Rs)
RzILOpEffect *hex_il_op_a4_pzxtbtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 8))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x8)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (!Pu) Rd = zxth(Rs)
RzILOpEffect *hex_il_op_a4_pzxthf(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (!Pu.new) Rd = zxth(Rs)
RzILOpEffect *hex_il_op_a4_pzxthfnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_18 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_19 = nop_17;

	// if (! (((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpPure *op_INV_4 = INV(NON_ZERO(op_AND_3));
	RzILOpEffect *branch_20 = BRANCH(op_INV_4, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = branch_20;
	return instruction_sequence;
}

// if (Pu) Rd = zxth(Rs)
RzILOpEffect *hex_il_op_a4_pzxtht(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Pu = READ_REG(pkt, Pu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu), DUP(Pu)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// if (Pu.new) Rd = zxth(Rs)
RzILOpEffect *hex_il_op_a4_pzxthtnew(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pu_new_op = ISA2REG(hi, 'u', true);
	RzILOpPure *Pu_new = READ_REG(pkt, Pu_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10));
	RzILOpEffect *op_ASSIGN_15 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, Rs), SN(32, 0), SN(32, 16))));

	// nop;
	RzILOpEffect *nop_16 = NOP();

	// seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)));
	RzILOpEffect *seq_then_17 = op_ASSIGN_15;

	// seq(nop);
	RzILOpEffect *seq_else_18 = nop_16;

	// if ((((st32) Pu_new) & 0x1)) {seq(Rd = ((st32) extract64(((ut64) Rs), 0x0, 0x10)))} else {seq(nop)};
	RzILOpPure *op_AND_3 = LOGAND(CAST(32, MSB(Pu_new), DUP(Pu_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_3), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = branch_19;
	return instruction_sequence;
}

// Rd = cmp.eq(Rs,Rt)
RzILOpEffect *hex_il_op_a4_rcmpeq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((Rs == Rt) ? 0x1 : 0x0);
	RzILOpPure *op_EQ_3 = EQ(Rs, Rt);
	RzILOpPure *ite_cast_st32_4 = ITE(op_EQ_3, SN(32, 1), SN(32, 0));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, ite_cast_st32_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rd = cmp.eq(Rs,Ii)
RzILOpEffect *hex_il_op_a4_rcmpeqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = ((Rs == s) ? 0x1 : 0x0);
	RzILOpPure *op_EQ_4 = EQ(Rs, VARL("s"));
	RzILOpPure *ite_cast_st32_5 = ITE(op_EQ_4, SN(32, 1), SN(32, 0));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, ite_cast_st32_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_6);
	return instruction_sequence;
}

// Rd = !cmp.eq(Rs,Rt)
RzILOpEffect *hex_il_op_a4_rcmpneq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Rd = ((Rs != Rt) ? 0x1 : 0x0);
	RzILOpPure *op_NE_3 = INV(EQ(Rs, Rt));
	RzILOpPure *ite_cast_st32_4 = ITE(op_NE_3, SN(32, 1), SN(32, 0));
	RzILOpEffect *op_ASSIGN_5 = WRITE_REG(bundle, Rd_op, ite_cast_st32_4);

	RzILOpEffect *instruction_sequence = op_ASSIGN_5;
	return instruction_sequence;
}

// Rd = !cmp.eq(Rs,Ii)
RzILOpEffect *hex_il_op_a4_rcmpneqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// Rd = ((Rs != s) ? 0x1 : 0x0);
	RzILOpPure *op_NE_4 = INV(EQ(Rs, VARL("s")));
	RzILOpPure *ite_cast_st32_5 = ITE(op_NE_4, SN(32, 1), SN(32, 0));
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, ite_cast_st32_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_0, op_ASSIGN_6);
	return instruction_sequence;
}

// Rd = round(Rs,Ii)
RzILOpEffect *hex_il_op_a4_round_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// Rd = ((st32) (((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1)))) >> u));
	RzILOpPure *op_EQ_5 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_11 = SUB(VARL("u"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_12 = SHIFTL0(SN(32, 1), op_SUB_11);
	RzILOpPure *op_ADD_14 = ADD(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(op_LSHIFT_12), DUP(op_LSHIFT_12)));
	RzILOpPure *cond_16 = ITE(op_EQ_5, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_14);
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(cond_16, VARL("u"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_RSHIFT_17), DUP(op_RSHIFT_17)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_1, op_ASSIGN_19);
	return instruction_sequence;
}

// Rd = round(Rs,Ii):sat
RzILOpEffect *hex_il_op_a4_round_ri_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_54 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1))))), 0x0, 0x20) == ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1)))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_EQ_8 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_14 = SUB(VARL("u"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_15 = SHIFTL0(SN(32, 1), op_SUB_14);
	RzILOpPure *op_ADD_17 = ADD(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(op_LSHIFT_15), DUP(op_LSHIFT_15)));
	RzILOpPure *cond_19 = ITE(op_EQ_8, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_17);
	RzILOpPure *op_EQ_27 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_32 = SUB(VARL("u"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(SN(32, 1), op_SUB_32);
	RzILOpPure *op_ADD_35 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(op_LSHIFT_33), DUP(op_LSHIFT_33)));
	RzILOpPure *cond_37 = ITE(op_EQ_27, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_35);
	RzILOpPure *op_EQ_38 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_19), SN(32, 0), SN(32, 0x20)), cond_37);
	RzILOpPure *op_EQ_57 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_62 = SUB(VARL("u"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_63 = SHIFTL0(SN(32, 1), op_SUB_62);
	RzILOpPure *op_ADD_65 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(op_LSHIFT_63), DUP(op_LSHIFT_63)));
	RzILOpPure *cond_67 = ITE(op_EQ_57, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_65);
	RzILOpPure *op_LT_70 = SLT(cond_67, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_75 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_76 = NEG(op_LSHIFT_75);
	RzILOpPure *op_LSHIFT_81 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_84 = SUB(op_LSHIFT_81, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_85 = ITE(op_LT_70, op_NEG_76, op_SUB_84);
	RzILOpEffect *gcc_expr_86 = BRANCH(op_EQ_38, EMPTY(), set_usr_field_call_54);

	// h_tmp119 = HYB(gcc_expr_if ((sextract64(((ut64) ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1))))), 0x0, 0x20) == ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1)))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_88 = SETL("h_tmp119", cond_85);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((u == ((ut32) 0x0)) ?  ...;
	RzILOpEffect *seq_89 = SEQN(2, gcc_expr_86, op_ASSIGN_hybrid_tmp_88);

	// Rd = ((st32) (((sextract64(((ut64) ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1))))), 0x0, 0x20) == ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1))))) ? ((u == ((ut32) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << u - ((ut32) 0x1)))) : h_tmp119) >> u));
	RzILOpPure *op_EQ_41 = EQ(VARL("u"), CAST(32, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_46 = SUB(VARL("u"), CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(SN(32, 1), op_SUB_46);
	RzILOpPure *op_ADD_49 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(op_LSHIFT_47), DUP(op_LSHIFT_47)));
	RzILOpPure *cond_51 = ITE(op_EQ_41, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_49);
	RzILOpPure *cond_90 = ITE(DUP(op_EQ_38), cond_51, VARL("h_tmp119"));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(cond_90, VARL("u"));
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_RSHIFT_91), DUP(op_RSHIFT_91)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((u == ((ut32) 0x0) ...;
	RzILOpEffect *seq_94 = SEQN(2, seq_89, op_ASSIGN_93);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, seq_94);
	return instruction_sequence;
}

// Rd = round(Rs,Rt)
RzILOpEffect *hex_il_op_a4_round_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// Rd = ((st32) (((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1)))) >> extract64(((ut64) Rt), 0x0, 0x5)));
	RzILOpPure *op_EQ_12 = EQ(EXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_26 = SUB(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(32, 1), op_SUB_26);
	RzILOpPure *op_ADD_29 = ADD(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(op_LSHIFT_27), DUP(op_LSHIFT_27)));
	RzILOpPure *cond_31 = ITE(op_EQ_12, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_29);
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(cond_31, EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)));
	RzILOpEffect *op_ASSIGN_42 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_RSHIFT_40), DUP(op_RSHIFT_40)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_42;
	return instruction_sequence;
}

// Rd = round(Rs,Rt):sat
RzILOpEffect *hex_il_op_a4_round_rr_sat(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_101 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1))))), 0x0, 0x20) == ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1)))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_EQ_15 = EQ(EXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_29 = SUB(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(SN(32, 1), op_SUB_29);
	RzILOpPure *op_ADD_32 = ADD(CAST(64, MSB(Rs), DUP(Rs)), CAST(64, MSB(op_LSHIFT_30), DUP(op_LSHIFT_30)));
	RzILOpPure *cond_34 = ITE(op_EQ_15, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_32);
	RzILOpPure *op_EQ_50 = EQ(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_63 = SUB(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(SN(32, 1), op_SUB_63);
	RzILOpPure *op_ADD_66 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(op_LSHIFT_64), DUP(op_LSHIFT_64)));
	RzILOpPure *cond_68 = ITE(op_EQ_50, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_66);
	RzILOpPure *op_EQ_69 = EQ(SEXTRACT64(CAST(64, IL_FALSE, cond_34), SN(32, 0), SN(32, 0x20)), cond_68);
	RzILOpPure *op_EQ_112 = EQ(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_125 = SUB(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_126 = SHIFTL0(SN(32, 1), op_SUB_125);
	RzILOpPure *op_ADD_128 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(op_LSHIFT_126), DUP(op_LSHIFT_126)));
	RzILOpPure *cond_130 = ITE(op_EQ_112, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_128);
	RzILOpPure *op_LT_133 = SLT(cond_130, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_138 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_139 = NEG(op_LSHIFT_138);
	RzILOpPure *op_LSHIFT_144 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_147 = SUB(op_LSHIFT_144, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_148 = ITE(op_LT_133, op_NEG_139, op_SUB_147);
	RzILOpEffect *gcc_expr_149 = BRANCH(op_EQ_69, EMPTY(), set_usr_field_call_101);

	// h_tmp120 = HYB(gcc_expr_if ((sextract64(((ut64) ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1))))), 0x0, 0x20) == ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1)))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1)))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_151 = SETL("h_tmp120", cond_148);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((extract64(((ut64) Rt) ...;
	RzILOpEffect *seq_152 = SEQN(2, gcc_expr_149, op_ASSIGN_hybrid_tmp_151);

	// Rd = ((st32) (((sextract64(((ut64) ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1))))), 0x0, 0x20) == ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1))))) ? ((extract64(((ut64) Rt), 0x0, 0x5) == ((ut64) 0x0)) ? ((st64) Rs) : ((st64) Rs) + ((st64) (0x1 << extract64(((ut64) Rt), 0x0, 0x5) - ((ut64) 0x1)))) : h_tmp120) >> extract64(((ut64) Rt), 0x0, 0x5)));
	RzILOpPure *op_EQ_80 = EQ(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpPure *op_SUB_93 = SUB(EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)), CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_LSHIFT_94 = SHIFTL0(SN(32, 1), op_SUB_93);
	RzILOpPure *op_ADD_96 = ADD(CAST(64, MSB(DUP(Rs)), DUP(Rs)), CAST(64, MSB(op_LSHIFT_94), DUP(op_LSHIFT_94)));
	RzILOpPure *cond_98 = ITE(op_EQ_80, CAST(64, MSB(DUP(Rs)), DUP(Rs)), op_ADD_96);
	RzILOpPure *cond_153 = ITE(DUP(op_EQ_69), cond_98, VARL("h_tmp120"));
	RzILOpPure *op_RSHIFT_162 = SHIFTRA(cond_153, EXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 5)));
	RzILOpEffect *op_ASSIGN_164 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(op_RSHIFT_162), DUP(op_RSHIFT_162)));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((extract64(((ut64) ...;
	RzILOpEffect *seq_165 = SEQN(2, seq_152, op_ASSIGN_164);

	RzILOpEffect *instruction_sequence = seq_165;
	return instruction_sequence;
}

// Rdd = sub(Rss,Rtt,Px):carry
RzILOpEffect *hex_il_op_a4_subp_c(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = Css
RzILOpEffect *hex_il_op_a4_tfrcpp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Css_op = ISA2REG(hi, 's', false);
	RzILOpPure *Css = READ_REG(pkt, Css_op, false);

	// Rdd = Css;
	RzILOpEffect *op_ASSIGN_2 = WRITE_REG(bundle, Rdd_op, Css);

	RzILOpEffect *instruction_sequence = op_ASSIGN_2;
	return instruction_sequence;
}

// Cdd = Rss
RzILOpEffect *hex_il_op_a4_tfrpcp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Cdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// Cdd = Rss;
	RzILOpEffect *op_ASSIGN_2 = WRITE_REG(bundle, Cdd_op, Rss);

	RzILOpEffect *instruction_sequence = op_ASSIGN_2;
	return instruction_sequence;
}

// Pd = tlbmatch(Rss,Rt)
RzILOpEffect *hex_il_op_a4_tlbmatch(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 TLBHI;
	// Declare: ut32 TLBLO;
	// Declare: ut32 MASK;
	// Declare: ut32 SIZE;
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// MASK = ((ut32) 0x7ffffff);
	RzILOpEffect *op_ASSIGN_6 = SETL("MASK", CAST(32, IL_FALSE, SN(32, 0x7ffffff)));

	// TLBLO = ((ut32) ((ut64) ((ut32) ((Rss >> 0x0) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_11 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_13 = LOGAND(op_RSHIFT_11, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_17 = SETL("TLBLO", CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_13))));

	// TLBHI = ((ut32) ((ut64) ((ut32) ((Rss >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_23 = LOGAND(op_RSHIFT_21, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_27 = SETL("TLBHI", CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_23))));

	// revbit32(TLBLO);
	RzILOpEffect *revbit32_call_29 = hex_revbit32(VARL("TLBLO"));

	// h_tmp121 = revbit32(TLBLO);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_31 = SETL("h_tmp121", UNSIGNED(32, VARL("ret_val")));

	// seq(revbit32(TLBLO); h_tmp121 = revbit32(TLBLO));
	RzILOpEffect *seq_32 = SEQN(2, revbit32_call_29, op_ASSIGN_hybrid_tmp_31);

	// clo32((~h_tmp121));
	RzILOpPure *op_NOT_33 = LOGNOT(VARL("h_tmp121"));
	RzILOpEffect *clo32_call_34 = hex_clo32(op_NOT_33);

	// h_tmp122 = clo32((~h_tmp121));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_36 = SETL("h_tmp122", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32((~h_tmp121)); h_tmp122 = clo32((~h_tmp121)));
	RzILOpEffect *seq_37 = SEQN(2, clo32_call_34, op_ASSIGN_hybrid_tmp_36);

	// seq(seq(revbit32(TLBLO); h_tmp121 = revbit32(TLBLO)); seq(clo32( ...;
	RzILOpEffect *seq_38 = SEQN(2, seq_32, seq_37);

	// revbit32(TLBLO);
	RzILOpEffect *revbit32_call_42 = hex_revbit32(VARL("TLBLO"));

	// h_tmp123 = revbit32(TLBLO);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_44 = SETL("h_tmp123", UNSIGNED(32, VARL("ret_val")));

	// seq(revbit32(TLBLO); h_tmp123 = revbit32(TLBLO));
	RzILOpEffect *seq_45 = SEQN(2, revbit32_call_42, op_ASSIGN_hybrid_tmp_44);

	// clo32((~h_tmp123));
	RzILOpPure *op_NOT_46 = LOGNOT(VARL("h_tmp123"));
	RzILOpEffect *clo32_call_47 = hex_clo32(op_NOT_46);

	// h_tmp124 = clo32((~h_tmp123));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_49 = SETL("h_tmp124", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32((~h_tmp123)); h_tmp124 = clo32((~h_tmp123)));
	RzILOpEffect *seq_50 = SEQN(2, clo32_call_47, op_ASSIGN_hybrid_tmp_49);

	// seq(seq(revbit32(TLBLO); h_tmp123 = revbit32(TLBLO)); seq(clo32( ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_45, seq_50);

	// SIZE = ((((ut32) 0x6) < h_tmp122) ? ((ut32) 0x6) : h_tmp124);
	RzILOpPure *op_LT_40 = ULT(CAST(32, IL_FALSE, SN(32, 6)), VARL("h_tmp122"));
	RzILOpPure *cond_53 = ITE(op_LT_40, CAST(32, IL_FALSE, SN(32, 6)), VARL("h_tmp124"));
	RzILOpEffect *op_ASSIGN_54 = SETL("SIZE", cond_53);

	// seq(seq(seq(revbit32(TLBLO); h_tmp121 = revbit32(TLBLO)); seq(cl ...;
	RzILOpEffect *seq_55 = SEQN(3, seq_38, seq_51, op_ASSIGN_54);

	// MASK = (MASK & ((ut32) (0xffffffff << ((ut32) 0x2) * SIZE)));
	RzILOpPure *op_MUL_59 = MUL(CAST(32, IL_FALSE, SN(32, 2)), VARL("SIZE"));
	RzILOpPure *op_LSHIFT_60 = SHIFTL0(SN(32, 0xffffffff), op_MUL_59);
	RzILOpPure *op_AND_62 = LOGAND(VARL("MASK"), CAST(32, IL_FALSE, op_LSHIFT_60));
	RzILOpEffect *op_ASSIGN_AND_63 = SETL("MASK", op_AND_62);

	// Pd = ((st8) ((((TLBHI >> 0x1f) & ((ut32) 0x1)) && ((ut32) ((TLBHI & MASK) == (((ut32) Rt) & MASK)))) ? 0xff : 0x0));
	RzILOpPure *op_RSHIFT_66 = SHIFTR0(VARL("TLBHI"), SN(32, 31));
	RzILOpPure *op_AND_69 = LOGAND(op_RSHIFT_66, CAST(32, IL_FALSE, SN(32, 1)));
	RzILOpPure *op_AND_70 = LOGAND(VARL("TLBHI"), VARL("MASK"));
	RzILOpPure *op_AND_73 = LOGAND(CAST(32, IL_FALSE, Rt), VARL("MASK"));
	RzILOpPure *op_EQ_74 = EQ(op_AND_70, op_AND_73);
	RzILOpPure *op_AND_76 = AND(NON_ZERO(op_AND_69), NON_ZERO(CAST(32, IL_FALSE, op_EQ_74)));
	RzILOpPure *cond_79 = ITE(op_AND_76, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_81 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_79), DUP(cond_79)));

	RzILOpEffect *instruction_sequence = SEQN(6, op_ASSIGN_6, op_ASSIGN_17, op_ASSIGN_27, seq_55, op_ASSIGN_AND_63, op_ASSIGN_81);
	return instruction_sequence;
}

// Pd = any8(vcmpb.eq(Rss,Rtt))
RzILOpEffect *hex_il_op_a4_vcmpbeq_any(HexInsnPktBundle *bundle) {
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

	// h_tmp125 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp125", VARL("i"));

	// seq(h_tmp125 = HYB(++i); HYB(++i));
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

	// seq(h_tmp125; if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff))) == ...;
	RzILOpEffect *seq_35 = branch_34;

	// seq(seq(h_tmp125; if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff)) ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_12);

	// while ((i < 0x8)) { seq(seq(h_tmp125; if ((((st8) ((Rss >> i * 0x8) & ((st64) 0xff)) ... };
	RzILOpPure *op_LT_8 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_37 = REPEAT(op_LT_8, seq_36);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp125; if ((((st8) ( ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_6, for_37);

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_4, seq_38);
	return instruction_sequence;
}

// Pd = vcmpb.eq(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpbeqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp126 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp126", VARL("i"));

	// seq(h_tmp126 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) | (((((ut32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) == u) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_EQ_27 = EQ(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), VARL("u"));
	RzILOpPure *ite_cast_ut64_28 = ITE(op_EQ_27, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(ite_cast_ut64_28, VARL("i"));
	RzILOpPure *op_OR_30 = LOGOR(op_AND_15, op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_32 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_30));

	// seq(h_tmp126; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i)) ...;
	RzILOpEffect *seq_34 = op_ASSIGN_32;

	// seq(seq(h_tmp126; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_35 = SEQN(2, seq_34, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp126; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_36 = REPEAT(op_LT_4, seq_35);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp126; Pd = ((st8) ( ...;
	RzILOpEffect *seq_37 = SEQN(2, op_ASSIGN_2, for_36);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_37);
	return instruction_sequence;
}

// Pd = vcmpb.gt(Rss,Rtt)
RzILOpEffect *hex_il_op_a4_vcmpbgt(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp127 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp127", VARL("i"));

	// seq(h_tmp127 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) | (((((st8) ((Rss >> i * 0x8) & ((st64) 0xff))) > ((st8) ((Rtt >> i * 0x8) & ((st64) 0xff)))) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(Rtt, op_MUL_26);
	RzILOpPure *op_AND_30 = LOGAND(op_RSHIFT_27, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_32 = SGT(CAST(8, MSB(op_AND_22), DUP(op_AND_22)), CAST(8, MSB(op_AND_30), DUP(op_AND_30)));
	RzILOpPure *ite_cast_ut64_33 = ITE(op_GT_32, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_34 = SHIFTL0(ite_cast_ut64_33, VARL("i"));
	RzILOpPure *op_OR_35 = LOGOR(op_AND_15, op_LSHIFT_34);
	RzILOpEffect *op_ASSIGN_37 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_35));

	// seq(h_tmp127; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i)) ...;
	RzILOpEffect *seq_39 = op_ASSIGN_37;

	// seq(seq(h_tmp127; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_40 = SEQN(2, seq_39, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp127; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_41 = REPEAT(op_LT_4, seq_40);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp127; Pd = ((st8) ( ...;
	RzILOpEffect *seq_42 = SEQN(2, op_ASSIGN_2, for_41);

	RzILOpEffect *instruction_sequence = seq_42;
	return instruction_sequence;
}

// Pd = vcmpb.gt(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpbgti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp128 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp128", VARL("i"));

	// seq(h_tmp128 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// s = s;
	RzILOpEffect *imm_assign_24 = SETL("s", s);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) | (((((st32) ((st8) ((Rss >> i * 0x8) & ((st64) 0xff)))) > s) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_27 = SGT(CAST(32, MSB(CAST(8, MSB(op_AND_22), DUP(op_AND_22))), CAST(8, MSB(DUP(op_AND_22)), DUP(op_AND_22))), VARL("s"));
	RzILOpPure *ite_cast_ut64_28 = ITE(op_GT_27, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(ite_cast_ut64_28, VARL("i"));
	RzILOpPure *op_OR_30 = LOGOR(op_AND_15, op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_32 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_30));

	// seq(h_tmp128; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i)) ...;
	RzILOpEffect *seq_34 = op_ASSIGN_32;

	// seq(seq(h_tmp128; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_35 = SEQN(2, seq_34, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp128; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_36 = REPEAT(op_LT_4, seq_35);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp128; Pd = ((st8) ( ...;
	RzILOpEffect *seq_37 = SEQN(2, op_ASSIGN_2, for_36);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_37);
	return instruction_sequence;
}

// Pd = vcmpb.gtu(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpbgtui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp129 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp129", VARL("i"));

	// seq(h_tmp129 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_24 = SETL("u", u);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i))) | (((((ut32) ((ut8) ((Rss >> i * 0x8) & ((st64) 0xff)))) > u) ? 0x1 : 0x0) << i)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("i"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_MUL_18 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rss, op_MUL_18);
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_19, CAST(64, MSB(SN(32, 0xff)), SN(32, 0xff)));
	RzILOpPure *op_GT_27 = UGT(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_22)), VARL("u"));
	RzILOpPure *ite_cast_ut64_28 = ITE(op_GT_27, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_29 = SHIFTL0(ite_cast_ut64_28, VARL("i"));
	RzILOpPure *op_OR_30 = LOGOR(op_AND_15, op_LSHIFT_29);
	RzILOpEffect *op_ASSIGN_32 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_30));

	// seq(h_tmp129; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i)) ...;
	RzILOpEffect *seq_34 = op_ASSIGN_32;

	// seq(seq(h_tmp129; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_35 = SEQN(2, seq_34, seq_8);

	// while ((i < 0x8)) { seq(seq(h_tmp129; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 8));
	RzILOpEffect *for_36 = REPEAT(op_LT_4, seq_35);

	// seq(i = 0x0; while ((i < 0x8)) { seq(seq(h_tmp129; Pd = ((st8) ( ...;
	RzILOpEffect *seq_37 = SEQN(2, op_ASSIGN_2, for_36);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_24, seq_37);
	return instruction_sequence;
}

// Pd = vcmph.eq(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpheqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp130 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp130", VARL("i"));

	// seq(h_tmp130 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// s = s;
	RzILOpEffect *imm_assign_26 = SETL("s", s);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2))) | (((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) == s) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(UN(64, 1), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_17 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_14);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rss, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_29 = EQ(CAST(32, MSB(CAST(16, MSB(op_AND_24), DUP(op_AND_24))), CAST(16, MSB(DUP(op_AND_24)), DUP(op_AND_24))), VARL("s"));
	RzILOpPure *ite_cast_ut64_30 = ITE(op_EQ_29, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(ite_cast_ut64_30, op_MUL_32);
	RzILOpPure *op_OR_34 = LOGOR(op_AND_17, op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_34));

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2 + 0x1))) | (((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) == s) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_42 = ADD(op_MUL_40, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(UN(64, 1), op_ADD_42);
	RzILOpPure *op_NOT_44 = LOGNOT(op_LSHIFT_43);
	RzILOpPure *op_AND_47 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_44);
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rss), op_MUL_49);
	RzILOpPure *op_AND_53 = LOGAND(op_RSHIFT_50, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_EQ_56 = EQ(CAST(32, MSB(CAST(16, MSB(op_AND_53), DUP(op_AND_53))), CAST(16, MSB(DUP(op_AND_53)), DUP(op_AND_53))), VARL("s"));
	RzILOpPure *ite_cast_ut64_57 = ITE(op_EQ_56, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_59 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_61 = ADD(op_MUL_59, SN(32, 1));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(ite_cast_ut64_57, op_ADD_61);
	RzILOpPure *op_OR_63 = LOGOR(op_AND_47, op_LSHIFT_62);
	RzILOpEffect *op_ASSIGN_65 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_63));

	// seq(h_tmp130; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * ...;
	RzILOpEffect *seq_67 = SEQN(2, op_ASSIGN_36, op_ASSIGN_65);

	// seq(seq(h_tmp130; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_68 = SEQN(2, seq_67, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp130; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_69 = REPEAT(op_LT_4, seq_68);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp130; Pd = ((st8) ( ...;
	RzILOpEffect *seq_70 = SEQN(2, op_ASSIGN_2, for_69);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_26, seq_70);
	return instruction_sequence;
}

// Pd = vcmph.gt(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmphgti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp131 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp131", VARL("i"));

	// seq(h_tmp131 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// s = s;
	RzILOpEffect *imm_assign_26 = SETL("s", s);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2))) | (((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) > s) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(UN(64, 1), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_17 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_14);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rss, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_29 = SGT(CAST(32, MSB(CAST(16, MSB(op_AND_24), DUP(op_AND_24))), CAST(16, MSB(DUP(op_AND_24)), DUP(op_AND_24))), VARL("s"));
	RzILOpPure *ite_cast_ut64_30 = ITE(op_GT_29, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(ite_cast_ut64_30, op_MUL_32);
	RzILOpPure *op_OR_34 = LOGOR(op_AND_17, op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_34));

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2 + 0x1))) | (((((st32) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) > s) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_42 = ADD(op_MUL_40, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(UN(64, 1), op_ADD_42);
	RzILOpPure *op_NOT_44 = LOGNOT(op_LSHIFT_43);
	RzILOpPure *op_AND_47 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_44);
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rss), op_MUL_49);
	RzILOpPure *op_AND_53 = LOGAND(op_RSHIFT_50, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_56 = SGT(CAST(32, MSB(CAST(16, MSB(op_AND_53), DUP(op_AND_53))), CAST(16, MSB(DUP(op_AND_53)), DUP(op_AND_53))), VARL("s"));
	RzILOpPure *ite_cast_ut64_57 = ITE(op_GT_56, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_59 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_61 = ADD(op_MUL_59, SN(32, 1));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(ite_cast_ut64_57, op_ADD_61);
	RzILOpPure *op_OR_63 = LOGOR(op_AND_47, op_LSHIFT_62);
	RzILOpEffect *op_ASSIGN_65 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_63));

	// seq(h_tmp131; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * ...;
	RzILOpEffect *seq_67 = SEQN(2, op_ASSIGN_36, op_ASSIGN_65);

	// seq(seq(h_tmp131; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_68 = SEQN(2, seq_67, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp131; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_69 = REPEAT(op_LT_4, seq_68);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp131; Pd = ((st8) ( ...;
	RzILOpEffect *seq_70 = SEQN(2, op_ASSIGN_2, for_69);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_26, seq_70);
	return instruction_sequence;
}

// Pd = vcmph.gtu(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmphgtui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_5 = SETL("i", INC(VARL("i"), 32));

	// h_tmp132 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp132", VARL("i"));

	// seq(h_tmp132 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_26 = SETL("u", u);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2))) | (((((ut32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) > u) ? 0x1 : 0x0) << i * 0x2)));
	RzILOpPure *op_MUL_12 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(UN(64, 1), op_MUL_12);
	RzILOpPure *op_NOT_14 = LOGNOT(op_LSHIFT_13);
	RzILOpPure *op_AND_17 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_14);
	RzILOpPure *op_MUL_20 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_21 = SHIFTRA(Rss, op_MUL_20);
	RzILOpPure *op_AND_24 = LOGAND(op_RSHIFT_21, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_29 = UGT(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_24)), VARL("u"));
	RzILOpPure *ite_cast_ut64_30 = ITE(op_GT_29, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_LSHIFT_33 = SHIFTL0(ite_cast_ut64_30, op_MUL_32);
	RzILOpPure *op_OR_34 = LOGOR(op_AND_17, op_LSHIFT_33);
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_34));

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * 0x2 + 0x1))) | (((((ut32) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))) > u) ? 0x1 : 0x0) << i * 0x2 + 0x1)));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_42 = ADD(op_MUL_40, SN(32, 1));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(UN(64, 1), op_ADD_42);
	RzILOpPure *op_NOT_44 = LOGNOT(op_LSHIFT_43);
	RzILOpPure *op_AND_47 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_44);
	RzILOpPure *op_MUL_49 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_50 = SHIFTRA(DUP(Rss), op_MUL_49);
	RzILOpPure *op_AND_53 = LOGAND(op_RSHIFT_50, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_56 = UGT(CAST(32, IL_FALSE, CAST(16, IL_FALSE, op_AND_53)), VARL("u"));
	RzILOpPure *ite_cast_ut64_57 = ITE(op_GT_56, UN(64, 1), UN(64, 0));
	RzILOpPure *op_MUL_59 = MUL(VARL("i"), SN(32, 2));
	RzILOpPure *op_ADD_61 = ADD(op_MUL_59, SN(32, 1));
	RzILOpPure *op_LSHIFT_62 = SHIFTL0(ite_cast_ut64_57, op_ADD_61);
	RzILOpPure *op_OR_63 = LOGOR(op_AND_47, op_LSHIFT_62);
	RzILOpEffect *op_ASSIGN_65 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_63));

	// seq(h_tmp132; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << i * ...;
	RzILOpEffect *seq_67 = SEQN(2, op_ASSIGN_36, op_ASSIGN_65);

	// seq(seq(h_tmp132; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_68 = SEQN(2, seq_67, seq_8);

	// while ((i < 0x4)) { seq(seq(h_tmp132; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LT_4 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_69 = REPEAT(op_LT_4, seq_68);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp132; Pd = ((st8) ( ...;
	RzILOpEffect *seq_70 = SEQN(2, op_ASSIGN_2, for_69);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_26, seq_70);
	return instruction_sequence;
}

// Pd = vcmpw.eq(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpweqi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 j;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// j = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("j", SN(32, 0));

	// HYB(++j);
	RzILOpEffect *op_INC_5 = SETL("j", INC(VARL("j"), 32));

	// h_tmp133 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp133", VARL("j"));

	// seq(h_tmp133 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// s = s;
	RzILOpEffect *imm_assign_25 = SETL("s", s);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) == ((st64) s)) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_28 = EQ(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(VARL("s")), VARL("s")));
	RzILOpPure *ite_cast_ut64_29 = ITE(op_EQ_28, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(ite_cast_ut64_29, VARL("j"));
	RzILOpPure *op_OR_31 = LOGOR(op_AND_15, op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_31));

	// seq(h_tmp133; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j)) ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp133; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((j <= 0x3)) { seq(seq(h_tmp133; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LE_4 = SLE(VARL("j"), SN(32, 3));
	RzILOpEffect *for_37 = REPEAT(op_LE_4, seq_36);

	// seq(j = 0x0; while ((j <= 0x3)) { seq(seq(h_tmp133; Pd = ((st8)  ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	// j = 0x4;
	RzILOpEffect *op_ASSIGN_41 = SETL("j", SN(32, 4));

	// HYB(++j);
	RzILOpEffect *op_INC_44 = SETL("j", INC(VARL("j"), 32));

	// h_tmp134 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_46 = SETL("h_tmp134", VARL("j"));

	// seq(h_tmp134 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_47 = SEQN(2, op_ASSIGN_hybrid_tmp_46, op_INC_44);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) == ((st64) s)) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_50 = LOGNOT(op_LSHIFT_49);
	RzILOpPure *op_AND_53 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_50);
	RzILOpPure *op_RSHIFT_57 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_59 = LOGAND(op_RSHIFT_57, SN(64, 0xffffffff));
	RzILOpPure *op_EQ_63 = EQ(CAST(64, MSB(CAST(32, MSB(op_AND_59), DUP(op_AND_59))), CAST(32, MSB(DUP(op_AND_59)), DUP(op_AND_59))), CAST(64, MSB(VARL("s")), VARL("s")));
	RzILOpPure *ite_cast_ut64_64 = ITE(op_EQ_63, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(ite_cast_ut64_64, VARL("j"));
	RzILOpPure *op_OR_66 = LOGOR(op_AND_53, op_LSHIFT_65);
	RzILOpEffect *op_ASSIGN_68 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_66));

	// seq(h_tmp134; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j)) ...;
	RzILOpEffect *seq_70 = op_ASSIGN_68;

	// seq(seq(h_tmp134; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_71 = SEQN(2, seq_70, seq_47);

	// while ((j <= 0x7)) { seq(seq(h_tmp134; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LE_43 = SLE(VARL("j"), SN(32, 7));
	RzILOpEffect *for_72 = REPEAT(op_LE_43, seq_71);

	// seq(j = 0x4; while ((j <= 0x7)) { seq(seq(h_tmp134; Pd = ((st8)  ...;
	RzILOpEffect *seq_73 = SEQN(2, op_ASSIGN_41, for_72);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_25, seq_38, seq_73);
	return instruction_sequence;
}

// Pd = vcmpw.gt(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpwgti(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 j;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// j = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("j", SN(32, 0));

	// HYB(++j);
	RzILOpEffect *op_INC_5 = SETL("j", INC(VARL("j"), 32));

	// h_tmp135 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp135", VARL("j"));

	// seq(h_tmp135 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// s = s;
	RzILOpEffect *imm_assign_25 = SETL("s", s);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) > ((st64) s)) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_GT_28 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_22), DUP(op_AND_22))), CAST(32, MSB(DUP(op_AND_22)), DUP(op_AND_22))), CAST(64, MSB(VARL("s")), VARL("s")));
	RzILOpPure *ite_cast_ut64_29 = ITE(op_GT_28, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(ite_cast_ut64_29, VARL("j"));
	RzILOpPure *op_OR_31 = LOGOR(op_AND_15, op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_31));

	// seq(h_tmp135; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j)) ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp135; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((j <= 0x3)) { seq(seq(h_tmp135; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LE_4 = SLE(VARL("j"), SN(32, 3));
	RzILOpEffect *for_37 = REPEAT(op_LE_4, seq_36);

	// seq(j = 0x0; while ((j <= 0x3)) { seq(seq(h_tmp135; Pd = ((st8)  ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	// j = 0x4;
	RzILOpEffect *op_ASSIGN_40 = SETL("j", SN(32, 4));

	// HYB(++j);
	RzILOpEffect *op_INC_43 = SETL("j", INC(VARL("j"), 32));

	// h_tmp136 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_45 = SETL("h_tmp136", VARL("j"));

	// seq(h_tmp136 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_46 = SEQN(2, op_ASSIGN_hybrid_tmp_45, op_INC_43);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) > ((st64) s)) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_49 = LOGNOT(op_LSHIFT_48);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_49);
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_56, SN(64, 0xffffffff));
	RzILOpPure *op_GT_62 = SGT(CAST(64, MSB(CAST(32, MSB(op_AND_58), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))), CAST(64, MSB(VARL("s")), VARL("s")));
	RzILOpPure *ite_cast_ut64_63 = ITE(op_GT_62, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(ite_cast_ut64_63, VARL("j"));
	RzILOpPure *op_OR_65 = LOGOR(op_AND_52, op_LSHIFT_64);
	RzILOpEffect *op_ASSIGN_67 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_65));

	// seq(h_tmp136; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j)) ...;
	RzILOpEffect *seq_69 = op_ASSIGN_67;

	// seq(seq(h_tmp136; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_70 = SEQN(2, seq_69, seq_46);

	// while ((j <= 0x7)) { seq(seq(h_tmp136; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LE_42 = SLE(VARL("j"), SN(32, 7));
	RzILOpEffect *for_71 = REPEAT(op_LE_42, seq_70);

	// seq(j = 0x4; while ((j <= 0x7)) { seq(seq(h_tmp136; Pd = ((st8)  ...;
	RzILOpEffect *seq_72 = SEQN(2, op_ASSIGN_40, for_71);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_25, seq_38, seq_72);
	return instruction_sequence;
}

// Pd = vcmpw.gtu(Rss,Ii)
RzILOpEffect *hex_il_op_a4_vcmpwgtui(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 j;
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// j = 0x0;
	RzILOpEffect *op_ASSIGN_2 = SETL("j", SN(32, 0));

	// HYB(++j);
	RzILOpEffect *op_INC_5 = SETL("j", INC(VARL("j"), 32));

	// h_tmp137 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_7 = SETL("h_tmp137", VARL("j"));

	// seq(h_tmp137 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_8 = SEQN(2, op_ASSIGN_hybrid_tmp_7, op_INC_5);

	// u = u;
	RzILOpEffect *imm_assign_25 = SETL("u", u);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((ut64) ((ut32) ((Rss >> 0x0) & 0xffffffff))) > ((ut64) u)) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_11 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_12 = LOGNOT(op_LSHIFT_11);
	RzILOpPure *op_AND_15 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_12);
	RzILOpPure *op_RSHIFT_20 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_22 = LOGAND(op_RSHIFT_20, SN(64, 0xffffffff));
	RzILOpPure *op_GT_28 = UGT(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_22)), CAST(64, IL_FALSE, VARL("u")));
	RzILOpPure *ite_cast_ut64_29 = ITE(op_GT_28, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(ite_cast_ut64_29, VARL("j"));
	RzILOpPure *op_OR_31 = LOGOR(op_AND_15, op_LSHIFT_30);
	RzILOpEffect *op_ASSIGN_33 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_31));

	// seq(h_tmp137; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j)) ...;
	RzILOpEffect *seq_35 = op_ASSIGN_33;

	// seq(seq(h_tmp137; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_36 = SEQN(2, seq_35, seq_8);

	// while ((j <= 0x3)) { seq(seq(h_tmp137; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LE_4 = SLE(VARL("j"), SN(32, 3));
	RzILOpEffect *for_37 = REPEAT(op_LE_4, seq_36);

	// seq(j = 0x0; while ((j <= 0x3)) { seq(seq(h_tmp137; Pd = ((st8)  ...;
	RzILOpEffect *seq_38 = SEQN(2, op_ASSIGN_2, for_37);

	// j = 0x4;
	RzILOpEffect *op_ASSIGN_40 = SETL("j", SN(32, 4));

	// HYB(++j);
	RzILOpEffect *op_INC_43 = SETL("j", INC(VARL("j"), 32));

	// h_tmp138 = HYB(++j);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_45 = SETL("h_tmp138", VARL("j"));

	// seq(h_tmp138 = HYB(++j); HYB(++j));
	RzILOpEffect *seq_46 = SEQN(2, op_ASSIGN_hybrid_tmp_45, op_INC_43);

	// Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j))) | (((((ut64) ((ut32) ((Rss >> 0x20) & 0xffffffff))) > ((ut64) u)) ? 0x1 : 0x0) << j)));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(UN(64, 1), VARL("j"));
	RzILOpPure *op_NOT_49 = LOGNOT(op_LSHIFT_48);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, IL_FALSE, CAST(32, MSB(READ_REG(pkt, Pd_op, true)), READ_REG(pkt, Pd_op, true))), op_NOT_49);
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_56, SN(64, 0xffffffff));
	RzILOpPure *op_GT_62 = UGT(CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_58)), CAST(64, IL_FALSE, VARL("u")));
	RzILOpPure *ite_cast_ut64_63 = ITE(op_GT_62, UN(64, 1), UN(64, 0));
	RzILOpPure *op_LSHIFT_64 = SHIFTL0(ite_cast_ut64_63, VARL("j"));
	RzILOpPure *op_OR_65 = LOGOR(op_AND_52, op_LSHIFT_64);
	RzILOpEffect *op_ASSIGN_67 = WRITE_REG(bundle, Pd_op, CAST(8, IL_FALSE, op_OR_65));

	// seq(h_tmp138; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << j)) ...;
	RzILOpEffect *seq_69 = op_ASSIGN_67;

	// seq(seq(h_tmp138; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ...;
	RzILOpEffect *seq_70 = SEQN(2, seq_69, seq_46);

	// while ((j <= 0x7)) { seq(seq(h_tmp138; Pd = ((st8) ((((ut64) ((st32) Pd)) & (~(0x1 << ... };
	RzILOpPure *op_LE_42 = SLE(VARL("j"), SN(32, 7));
	RzILOpEffect *for_71 = REPEAT(op_LE_42, seq_70);

	// seq(j = 0x4; while ((j <= 0x7)) { seq(seq(h_tmp138; Pd = ((st8)  ...;
	RzILOpEffect *seq_72 = SEQN(2, op_ASSIGN_40, for_71);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_25, seq_38, seq_72);
	return instruction_sequence;
}

// Rxx = vrmaxh(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrmaxh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 max;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// max = ((st64) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_7, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_13 = SETL("max", CAST(64, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_23 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_19), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_25 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_28 = SETL("i", INC(VARL("i"), 32));

	// h_tmp139 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_30 = SETL("h_tmp139", VARL("i"));

	// seq(h_tmp139 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_31 = SEQN(2, op_ASSIGN_hybrid_tmp_30, op_INC_28);

	// max = ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(Rss, op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_50 = SETL("max", CAST(64, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))));

	// addr = (Ru | (i << 0x1));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("i"), SN(32, 1));
	RzILOpPure *op_OR_54 = LOGOR(Ru, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_55 = SETL("addr", op_OR_54);

	// seq(max = ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...;
	RzILOpEffect *seq_then_56 = SEQN(2, op_ASSIGN_50, op_ASSIGN_55);

	// if ((max < ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {seq(max = ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...} else {{}};
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_41 = SLT(VARL("max"), CAST(64, MSB(CAST(16, MSB(op_AND_38), DUP(op_AND_38))), CAST(16, MSB(DUP(op_AND_38)), DUP(op_AND_38))));
	RzILOpEffect *branch_57 = BRANCH(op_LT_41, seq_then_56, EMPTY());

	// seq(h_tmp139; if ((max < ((st64) ((st16) ((Rss >> i * 0x10) & (( ...;
	RzILOpEffect *seq_58 = branch_57;

	// seq(seq(h_tmp139; if ((max < ((st64) ((st16) ((Rss >> i * 0x10)  ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_31);

	// while ((i < 0x4)) { seq(seq(h_tmp139; if ((max < ((st64) ((st16) ((Rss >> i * 0x10)  ... };
	RzILOpPure *op_LT_27 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_60 = REPEAT(op_LT_27, seq_59);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp139; if ((max < (( ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_25, for_60);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((max & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_67 = LOGNOT(op_LSHIFT_66);
	RzILOpPure *op_AND_68 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_67);
	RzILOpPure *op_AND_70 = LOGAND(VARL("max"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(op_AND_70, SN(32, 0));
	RzILOpPure *op_OR_75 = LOGOR(op_AND_68, op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rxx_op, op_OR_75);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_83 = LOGNOT(op_LSHIFT_82);
	RzILOpPure *op_AND_84 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_83);
	RzILOpPure *op_AND_87 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(op_AND_87, SN(32, 0x20));
	RzILOpPure *op_OR_92 = LOGOR(op_AND_84, op_LSHIFT_91);
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rxx_op, op_OR_92);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_13, op_ASSIGN_23, seq_61, op_ASSIGN_76, op_ASSIGN_93);
	return instruction_sequence;
}

// Rxx = vrmaxuh(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrmaxuh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 max;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// max = ((st64) ((ut16) ((Rxx >> 0x0) & ((st64) 0xffff))));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_7, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_13 = SETL("max", CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_10)));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_23 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_19), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_25 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_28 = SETL("i", INC(VARL("i"), 32));

	// h_tmp140 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_30 = SETL("h_tmp140", VARL("i"));

	// seq(h_tmp140 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_31 = SEQN(2, op_ASSIGN_hybrid_tmp_30, op_INC_28);

	// max = ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(Rss, op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_50 = SETL("max", CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_47)));

	// addr = (Ru | (i << 0x1));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("i"), SN(32, 1));
	RzILOpPure *op_OR_54 = LOGOR(Ru, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_55 = SETL("addr", op_OR_54);

	// seq(max = ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...;
	RzILOpEffect *seq_then_56 = SEQN(2, op_ASSIGN_50, op_ASSIGN_55);

	// if ((max < ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {seq(max = ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...} else {{}};
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LT_41 = SLT(VARL("max"), CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_38)));
	RzILOpEffect *branch_57 = BRANCH(op_LT_41, seq_then_56, EMPTY());

	// seq(h_tmp140; if ((max < ((st64) ((ut16) ((Rss >> i * 0x10) & (( ...;
	RzILOpEffect *seq_58 = branch_57;

	// seq(seq(h_tmp140; if ((max < ((st64) ((ut16) ((Rss >> i * 0x10)  ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_31);

	// while ((i < 0x4)) { seq(seq(h_tmp140; if ((max < ((st64) ((ut16) ((Rss >> i * 0x10)  ... };
	RzILOpPure *op_LT_27 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_60 = REPEAT(op_LT_27, seq_59);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp140; if ((max < (( ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_25, for_60);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((max & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_67 = LOGNOT(op_LSHIFT_66);
	RzILOpPure *op_AND_68 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_67);
	RzILOpPure *op_AND_70 = LOGAND(VARL("max"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(op_AND_70, SN(32, 0));
	RzILOpPure *op_OR_75 = LOGOR(op_AND_68, op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rxx_op, op_OR_75);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_83 = LOGNOT(op_LSHIFT_82);
	RzILOpPure *op_AND_84 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_83);
	RzILOpPure *op_AND_87 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(op_AND_87, SN(32, 0x20));
	RzILOpPure *op_OR_92 = LOGOR(op_AND_84, op_LSHIFT_91);
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rxx_op, op_OR_92);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_13, op_ASSIGN_23, seq_61, op_ASSIGN_76, op_ASSIGN_93);
	return instruction_sequence;
}

// Rxx = vrmaxuw(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrmaxuw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 max;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// max = ((st64) ((ut64) ((ut32) ((Rxx >> 0x0) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_13 = SETL("max", CAST(64, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_9))));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_23 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_19), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_25 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_28 = SETL("i", INC(VARL("i"), 32));

	// h_tmp141 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_30 = SETL("h_tmp141", VARL("i"));

	// seq(h_tmp141 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_31 = SEQN(2, op_ASSIGN_hybrid_tmp_30, op_INC_28);

	// max = ((st64) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(Rss, op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_50 = SETL("max", CAST(64, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_46))));

	// addr = (Ru | (i << 0x2));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("i"), SN(32, 2));
	RzILOpPure *op_OR_54 = LOGOR(Ru, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_55 = SETL("addr", op_OR_54);

	// seq(max = ((st64) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xfffffff ...;
	RzILOpEffect *seq_then_56 = SEQN(2, op_ASSIGN_50, op_ASSIGN_55);

	// if ((((ut64) max) < ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))))) {seq(max = ((st64) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xfffffff ...} else {{}};
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_LT_41 = ULT(CAST(64, IL_FALSE, VARL("max")), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_37)));
	RzILOpEffect *branch_57 = BRANCH(op_LT_41, seq_then_56, EMPTY());

	// seq(h_tmp141; if ((((ut64) max) < ((ut64) ((ut32) ((Rss >> i * 0 ...;
	RzILOpEffect *seq_58 = branch_57;

	// seq(seq(h_tmp141; if ((((ut64) max) < ((ut64) ((ut32) ((Rss >> i ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_31);

	// while ((i < 0x2)) { seq(seq(h_tmp141; if ((((ut64) max) < ((ut64) ((ut32) ((Rss >> i ... };
	RzILOpPure *op_LT_27 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_60 = REPEAT(op_LT_27, seq_59);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp141; if ((((ut64)  ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_25, for_60);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((max & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_67 = LOGNOT(op_LSHIFT_66);
	RzILOpPure *op_AND_68 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_67);
	RzILOpPure *op_AND_70 = LOGAND(VARL("max"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(op_AND_70, SN(32, 0));
	RzILOpPure *op_OR_75 = LOGOR(op_AND_68, op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rxx_op, op_OR_75);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_83 = LOGNOT(op_LSHIFT_82);
	RzILOpPure *op_AND_84 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_83);
	RzILOpPure *op_AND_87 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(op_AND_87, SN(32, 0x20));
	RzILOpPure *op_OR_92 = LOGOR(op_AND_84, op_LSHIFT_91);
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rxx_op, op_OR_92);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_13, op_ASSIGN_23, seq_61, op_ASSIGN_76, op_ASSIGN_93);
	return instruction_sequence;
}

// Rxx = vrmaxw(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrmaxw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 max;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// max = ((st64) ((st32) ((Rxx >> 0x0) & 0xffffffff)));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_12 = SETL("max", CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9))));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_22 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_24 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_27 = SETL("i", INC(VARL("i"), 32));

	// h_tmp142 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp142", VARL("i"));

	// seq(h_tmp142 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_30 = SEQN(2, op_ASSIGN_hybrid_tmp_29, op_INC_27);

	// max = ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(Rss, op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_47 = SETL("max", CAST(64, MSB(CAST(32, MSB(op_AND_44), DUP(op_AND_44))), CAST(32, MSB(DUP(op_AND_44)), DUP(op_AND_44))));

	// addr = (Ru | (i << 0x2));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(VARL("i"), SN(32, 2));
	RzILOpPure *op_OR_51 = LOGOR(Ru, op_LSHIFT_50);
	RzILOpEffect *op_ASSIGN_52 = SETL("addr", op_OR_51);

	// seq(max = ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))); ad ...;
	RzILOpEffect *seq_then_53 = SEQN(2, op_ASSIGN_47, op_ASSIGN_52);

	// if ((max < ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {seq(max = ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))); ad ...} else {{}};
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(DUP(Rss), op_MUL_33);
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_34, SN(64, 0xffffffff));
	RzILOpPure *op_LT_39 = SLT(VARL("max"), CAST(64, MSB(CAST(32, MSB(op_AND_36), DUP(op_AND_36))), CAST(32, MSB(DUP(op_AND_36)), DUP(op_AND_36))));
	RzILOpEffect *branch_54 = BRANCH(op_LT_39, seq_then_53, EMPTY());

	// seq(h_tmp142; if ((max < ((st64) ((st32) ((Rss >> i * 0x20) & 0x ...;
	RzILOpEffect *seq_55 = branch_54;

	// seq(seq(h_tmp142; if ((max < ((st64) ((st32) ((Rss >> i * 0x20)  ...;
	RzILOpEffect *seq_56 = SEQN(2, seq_55, seq_30);

	// while ((i < 0x2)) { seq(seq(h_tmp142; if ((max < ((st64) ((st32) ((Rss >> i * 0x20)  ... };
	RzILOpPure *op_LT_26 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_57 = REPEAT(op_LT_26, seq_56);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp142; if ((max < (( ...;
	RzILOpEffect *seq_58 = SEQN(2, op_ASSIGN_24, for_57);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((max & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_63 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_64 = LOGNOT(op_LSHIFT_63);
	RzILOpPure *op_AND_65 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_64);
	RzILOpPure *op_AND_67 = LOGAND(VARL("max"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(op_AND_67, SN(32, 0));
	RzILOpPure *op_OR_72 = LOGOR(op_AND_65, op_LSHIFT_71);
	RzILOpEffect *op_ASSIGN_73 = WRITE_REG(bundle, Rxx_op, op_OR_72);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_79 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_80 = LOGNOT(op_LSHIFT_79);
	RzILOpPure *op_AND_81 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_80);
	RzILOpPure *op_AND_84 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(op_AND_84, SN(32, 0x20));
	RzILOpPure *op_OR_89 = LOGOR(op_AND_81, op_LSHIFT_88);
	RzILOpEffect *op_ASSIGN_90 = WRITE_REG(bundle, Rxx_op, op_OR_89);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_12, op_ASSIGN_22, seq_58, op_ASSIGN_73, op_ASSIGN_90);
	return instruction_sequence;
}

// Rxx = vrminh(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrminh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 min;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// min = ((st64) ((st16) ((Rxx >> 0x0) & ((st64) 0xffff))));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_7, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_13 = SETL("min", CAST(64, MSB(CAST(16, MSB(op_AND_10), DUP(op_AND_10))), CAST(16, MSB(DUP(op_AND_10)), DUP(op_AND_10))));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_23 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_19), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_25 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_28 = SETL("i", INC(VARL("i"), 32));

	// h_tmp143 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_30 = SETL("h_tmp143", VARL("i"));

	// seq(h_tmp143 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_31 = SEQN(2, op_ASSIGN_hybrid_tmp_30, op_INC_28);

	// min = ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(Rss, op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_50 = SETL("min", CAST(64, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))));

	// addr = (Ru | (i << 0x1));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("i"), SN(32, 1));
	RzILOpPure *op_OR_54 = LOGOR(Ru, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_55 = SETL("addr", op_OR_54);

	// seq(min = ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...;
	RzILOpEffect *seq_then_56 = SEQN(2, op_ASSIGN_50, op_ASSIGN_55);

	// if ((min > ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {seq(min = ((st64) ((st16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...} else {{}};
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_41 = SGT(VARL("min"), CAST(64, MSB(CAST(16, MSB(op_AND_38), DUP(op_AND_38))), CAST(16, MSB(DUP(op_AND_38)), DUP(op_AND_38))));
	RzILOpEffect *branch_57 = BRANCH(op_GT_41, seq_then_56, EMPTY());

	// seq(h_tmp143; if ((min > ((st64) ((st16) ((Rss >> i * 0x10) & (( ...;
	RzILOpEffect *seq_58 = branch_57;

	// seq(seq(h_tmp143; if ((min > ((st64) ((st16) ((Rss >> i * 0x10)  ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_31);

	// while ((i < 0x4)) { seq(seq(h_tmp143; if ((min > ((st64) ((st16) ((Rss >> i * 0x10)  ... };
	RzILOpPure *op_LT_27 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_60 = REPEAT(op_LT_27, seq_59);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp143; if ((min > (( ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_25, for_60);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((min & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_67 = LOGNOT(op_LSHIFT_66);
	RzILOpPure *op_AND_68 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_67);
	RzILOpPure *op_AND_70 = LOGAND(VARL("min"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(op_AND_70, SN(32, 0));
	RzILOpPure *op_OR_75 = LOGOR(op_AND_68, op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rxx_op, op_OR_75);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_83 = LOGNOT(op_LSHIFT_82);
	RzILOpPure *op_AND_84 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_83);
	RzILOpPure *op_AND_87 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(op_AND_87, SN(32, 0x20));
	RzILOpPure *op_OR_92 = LOGOR(op_AND_84, op_LSHIFT_91);
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rxx_op, op_OR_92);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_13, op_ASSIGN_23, seq_61, op_ASSIGN_76, op_ASSIGN_93);
	return instruction_sequence;
}

// Rxx = vrminuh(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrminuh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 min;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// min = ((st64) ((ut16) ((Rxx >> 0x0) & ((st64) 0xffff))));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_10 = LOGAND(op_RSHIFT_7, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_13 = SETL("min", CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_10)));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_23 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_19), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_25 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_28 = SETL("i", INC(VARL("i"), 32));

	// h_tmp144 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_30 = SETL("h_tmp144", VARL("i"));

	// seq(h_tmp144 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_31 = SEQN(2, op_ASSIGN_hybrid_tmp_30, op_INC_28);

	// min = ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(Rss, op_MUL_43);
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpEffect *op_ASSIGN_50 = SETL("min", CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_47)));

	// addr = (Ru | (i << 0x1));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("i"), SN(32, 1));
	RzILOpPure *op_OR_54 = LOGOR(Ru, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_55 = SETL("addr", op_OR_54);

	// seq(min = ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...;
	RzILOpEffect *seq_then_56 = SEQN(2, op_ASSIGN_50, op_ASSIGN_55);

	// if ((min > ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff)))))) {seq(min = ((st64) ((ut16) ((Rss >> i * 0x10) & ((st64) 0xffff))) ...} else {{}};
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_GT_41 = SGT(VARL("min"), CAST(64, IL_FALSE, CAST(16, IL_FALSE, op_AND_38)));
	RzILOpEffect *branch_57 = BRANCH(op_GT_41, seq_then_56, EMPTY());

	// seq(h_tmp144; if ((min > ((st64) ((ut16) ((Rss >> i * 0x10) & (( ...;
	RzILOpEffect *seq_58 = branch_57;

	// seq(seq(h_tmp144; if ((min > ((st64) ((ut16) ((Rss >> i * 0x10)  ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_31);

	// while ((i < 0x4)) { seq(seq(h_tmp144; if ((min > ((st64) ((ut16) ((Rss >> i * 0x10)  ... };
	RzILOpPure *op_LT_27 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_60 = REPEAT(op_LT_27, seq_59);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp144; if ((min > (( ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_25, for_60);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((min & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_67 = LOGNOT(op_LSHIFT_66);
	RzILOpPure *op_AND_68 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_67);
	RzILOpPure *op_AND_70 = LOGAND(VARL("min"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(op_AND_70, SN(32, 0));
	RzILOpPure *op_OR_75 = LOGOR(op_AND_68, op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rxx_op, op_OR_75);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_83 = LOGNOT(op_LSHIFT_82);
	RzILOpPure *op_AND_84 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_83);
	RzILOpPure *op_AND_87 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(op_AND_87, SN(32, 0x20));
	RzILOpPure *op_OR_92 = LOGOR(op_AND_84, op_LSHIFT_91);
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rxx_op, op_OR_92);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_13, op_ASSIGN_23, seq_61, op_ASSIGN_76, op_ASSIGN_93);
	return instruction_sequence;
}

// Rxx = vrminuw(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrminuw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 min;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// min = ((st64) ((ut64) ((ut32) ((Rxx >> 0x0) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_13 = SETL("min", CAST(64, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_9))));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_23 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_19), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19))), CAST(32, MSB(DUP(op_AND_19)), DUP(op_AND_19)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_25 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_28 = SETL("i", INC(VARL("i"), 32));

	// h_tmp145 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_30 = SETL("h_tmp145", VARL("i"));

	// seq(h_tmp145 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_31 = SEQN(2, op_ASSIGN_hybrid_tmp_30, op_INC_28);

	// min = ((st64) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(Rss, op_MUL_43);
	RzILOpPure *op_AND_46 = LOGAND(op_RSHIFT_44, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_50 = SETL("min", CAST(64, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_46))));

	// addr = (Ru | (i << 0x2));
	RzILOpPure *op_LSHIFT_53 = SHIFTL0(VARL("i"), SN(32, 2));
	RzILOpPure *op_OR_54 = LOGOR(Ru, op_LSHIFT_53);
	RzILOpEffect *op_ASSIGN_55 = SETL("addr", op_OR_54);

	// seq(min = ((st64) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xfffffff ...;
	RzILOpEffect *seq_then_56 = SEQN(2, op_ASSIGN_50, op_ASSIGN_55);

	// if ((((ut64) min) > ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xffffffff))))) {seq(min = ((st64) ((ut64) ((ut32) ((Rss >> i * 0x20) & 0xfffffff ...} else {{}};
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(DUP(Rss), op_MUL_34);
	RzILOpPure *op_AND_37 = LOGAND(op_RSHIFT_35, SN(64, 0xffffffff));
	RzILOpPure *op_GT_41 = UGT(CAST(64, IL_FALSE, VARL("min")), CAST(64, IL_FALSE, CAST(32, IL_FALSE, op_AND_37)));
	RzILOpEffect *branch_57 = BRANCH(op_GT_41, seq_then_56, EMPTY());

	// seq(h_tmp145; if ((((ut64) min) > ((ut64) ((ut32) ((Rss >> i * 0 ...;
	RzILOpEffect *seq_58 = branch_57;

	// seq(seq(h_tmp145; if ((((ut64) min) > ((ut64) ((ut32) ((Rss >> i ...;
	RzILOpEffect *seq_59 = SEQN(2, seq_58, seq_31);

	// while ((i < 0x2)) { seq(seq(h_tmp145; if ((((ut64) min) > ((ut64) ((ut32) ((Rss >> i ... };
	RzILOpPure *op_LT_27 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_60 = REPEAT(op_LT_27, seq_59);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp145; if ((((ut64)  ...;
	RzILOpEffect *seq_61 = SEQN(2, op_ASSIGN_25, for_60);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((min & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_67 = LOGNOT(op_LSHIFT_66);
	RzILOpPure *op_AND_68 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_67);
	RzILOpPure *op_AND_70 = LOGAND(VARL("min"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_74 = SHIFTL0(op_AND_70, SN(32, 0));
	RzILOpPure *op_OR_75 = LOGOR(op_AND_68, op_LSHIFT_74);
	RzILOpEffect *op_ASSIGN_76 = WRITE_REG(bundle, Rxx_op, op_OR_75);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_82 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_83 = LOGNOT(op_LSHIFT_82);
	RzILOpPure *op_AND_84 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_83);
	RzILOpPure *op_AND_87 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_91 = SHIFTL0(op_AND_87, SN(32, 0x20));
	RzILOpPure *op_OR_92 = LOGOR(op_AND_84, op_LSHIFT_91);
	RzILOpEffect *op_ASSIGN_93 = WRITE_REG(bundle, Rxx_op, op_OR_92);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_13, op_ASSIGN_23, seq_61, op_ASSIGN_76, op_ASSIGN_93);
	return instruction_sequence;
}

// Rxx = vrminw(Rss,Ru)
RzILOpEffect *hex_il_op_a4_vrminw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: st32 i;
	// Declare: st64 min;
	// Declare: st32 addr;
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);

	// min = ((st64) ((st32) ((Rxx >> 0x0) & 0xffffffff)));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_12 = SETL("min", CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9))));

	// addr = ((st32) ((st64) ((st32) ((Rxx >> 0x20) & 0xffffffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(READ_REG(pkt, Rxx_op, false), SN(32, 0x20));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_22 = SETL("addr", CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_24 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_27 = SETL("i", INC(VARL("i"), 32));

	// h_tmp146 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp146", VARL("i"));

	// seq(h_tmp146 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_30 = SEQN(2, op_ASSIGN_hybrid_tmp_29, op_INC_27);

	// min = ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff)));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_42 = SHIFTRA(Rss, op_MUL_41);
	RzILOpPure *op_AND_44 = LOGAND(op_RSHIFT_42, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_47 = SETL("min", CAST(64, MSB(CAST(32, MSB(op_AND_44), DUP(op_AND_44))), CAST(32, MSB(DUP(op_AND_44)), DUP(op_AND_44))));

	// addr = (Ru | (i << 0x2));
	RzILOpPure *op_LSHIFT_50 = SHIFTL0(VARL("i"), SN(32, 2));
	RzILOpPure *op_OR_51 = LOGOR(Ru, op_LSHIFT_50);
	RzILOpEffect *op_ASSIGN_52 = SETL("addr", op_OR_51);

	// seq(min = ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))); ad ...;
	RzILOpEffect *seq_then_53 = SEQN(2, op_ASSIGN_47, op_ASSIGN_52);

	// if ((min > ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))))) {seq(min = ((st64) ((st32) ((Rss >> i * 0x20) & 0xffffffff))); ad ...} else {{}};
	RzILOpPure *op_MUL_33 = MUL(VARL("i"), SN(32, 0x20));
	RzILOpPure *op_RSHIFT_34 = SHIFTRA(DUP(Rss), op_MUL_33);
	RzILOpPure *op_AND_36 = LOGAND(op_RSHIFT_34, SN(64, 0xffffffff));
	RzILOpPure *op_GT_39 = SGT(VARL("min"), CAST(64, MSB(CAST(32, MSB(op_AND_36), DUP(op_AND_36))), CAST(32, MSB(DUP(op_AND_36)), DUP(op_AND_36))));
	RzILOpEffect *branch_54 = BRANCH(op_GT_39, seq_then_53, EMPTY());

	// seq(h_tmp146; if ((min > ((st64) ((st32) ((Rss >> i * 0x20) & 0x ...;
	RzILOpEffect *seq_55 = branch_54;

	// seq(seq(h_tmp146; if ((min > ((st64) ((st32) ((Rss >> i * 0x20)  ...;
	RzILOpEffect *seq_56 = SEQN(2, seq_55, seq_30);

	// while ((i < 0x2)) { seq(seq(h_tmp146; if ((min > ((st64) ((st32) ((Rss >> i * 0x20)  ... };
	RzILOpPure *op_LT_26 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_57 = REPEAT(op_LT_26, seq_56);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp146; if ((min > (( ...;
	RzILOpEffect *seq_58 = SEQN(2, op_ASSIGN_24, for_57);

	// Rxx = ((Rxx & (~(0xffffffff << 0x0))) | ((min & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_63 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_64 = LOGNOT(op_LSHIFT_63);
	RzILOpPure *op_AND_65 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_64);
	RzILOpPure *op_AND_67 = LOGAND(VARL("min"), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_71 = SHIFTL0(op_AND_67, SN(32, 0));
	RzILOpPure *op_OR_72 = LOGOR(op_AND_65, op_LSHIFT_71);
	RzILOpEffect *op_ASSIGN_73 = WRITE_REG(bundle, Rxx_op, op_OR_72);

	// Rxx = ((Rxx & (~(0xffffffff << 0x20))) | ((((st64) addr) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_79 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_80 = LOGNOT(op_LSHIFT_79);
	RzILOpPure *op_AND_81 = LOGAND(READ_REG(pkt, Rxx_op, false), op_NOT_80);
	RzILOpPure *op_AND_84 = LOGAND(CAST(64, MSB(VARL("addr")), VARL("addr")), SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_88 = SHIFTL0(op_AND_84, SN(32, 0x20));
	RzILOpPure *op_OR_89 = LOGOR(op_AND_81, op_LSHIFT_88);
	RzILOpEffect *op_ASSIGN_90 = WRITE_REG(bundle, Rxx_op, op_OR_89);

	RzILOpEffect *instruction_sequence = SEQN(5, op_ASSIGN_12, op_ASSIGN_22, seq_58, op_ASSIGN_73, op_ASSIGN_90);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>