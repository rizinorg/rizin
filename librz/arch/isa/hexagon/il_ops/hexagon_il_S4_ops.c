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

// Rd = add(Rs,add(Ru,Ii))
RzILOpEffect *hex_il_op_s4_addaddi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// s = s;
	RzILOpEffect *imm_assign_4 = SETL("s", s);

	// Rd = Rs + Ru + s;
	RzILOpPure *op_ADD_3 = ADD(Rs, Ru);
	RzILOpPure *op_ADD_6 = ADD(op_ADD_3, VARL("s"));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, op_ADD_6);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, op_ASSIGN_7);
	return instruction_sequence;
}

// Rx = add(Ii,asl(Rxin,II))
RzILOpEffect *hex_il_op_s4_addi_asl_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// Rx = ((st32) u + ((ut32) (Rx << U)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(READ_REG(pkt, Rx_op, false), VARL("U"));
	RzILOpPure *op_ADD_7 = ADD(VARL("u"), CAST(32, IL_FALSE, op_LSHIFT_5));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_ADD_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_3, op_ASSIGN_9);
	return instruction_sequence;
}

// Rx = add(Ii,lsr(Rxin,II))
RzILOpEffect *hex_il_op_s4_addi_lsr_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_4 = SETL("U", U);

	// Rx = ((st32) u + (((ut32) Rx) >> U));
	RzILOpPure *op_RSHIFT_6 = SHIFTR0(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), VARL("U"));
	RzILOpPure *op_ADD_7 = ADD(VARL("u"), op_RSHIFT_6);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_ADD_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_4, op_ASSIGN_9);
	return instruction_sequence;
}

// Rx = and(Ii,asl(Rxin,II))
RzILOpEffect *hex_il_op_s4_andi_asl_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// Rx = ((st32) (u & ((ut32) (Rx << U))));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(READ_REG(pkt, Rx_op, false), VARL("U"));
	RzILOpPure *op_AND_7 = LOGAND(VARL("u"), CAST(32, IL_FALSE, op_LSHIFT_5));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_AND_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_3, op_ASSIGN_9);
	return instruction_sequence;
}

// Rx = and(Ii,lsr(Rxin,II))
RzILOpEffect *hex_il_op_s4_andi_lsr_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_4 = SETL("U", U);

	// Rx = ((st32) (u & (((ut32) Rx) >> U)));
	RzILOpPure *op_RSHIFT_6 = SHIFTR0(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), VARL("U"));
	RzILOpPure *op_AND_7 = LOGAND(VARL("u"), op_RSHIFT_6);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_AND_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_4, op_ASSIGN_9);
	return instruction_sequence;
}

// Rd = add(clb(Rs),Ii)
RzILOpEffect *hex_il_op_s4_clbaddi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_3 = hex_clo32(CAST(32, IL_FALSE, Rs));

	// h_tmp572 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp572", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp572 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_6 = SEQN(2, clo32_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_7 = LOGNOT(DUP(Rs));
	RzILOpEffect *clo32_call_9 = hex_clo32(CAST(32, IL_FALSE, op_NOT_7));

	// h_tmp573 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp573", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp573 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_12 = SEQN(2, clo32_call_9, op_ASSIGN_hybrid_tmp_11);

	// clo32(((ut32) Rs));
	RzILOpEffect *clo32_call_15 = hex_clo32(CAST(32, IL_FALSE, DUP(Rs)));

	// h_tmp574 = clo32(((ut32) Rs));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_17 = SETL("h_tmp574", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) Rs)); h_tmp574 = clo32(((ut32) Rs)));
	RzILOpEffect *seq_18 = SEQN(2, clo32_call_15, op_ASSIGN_hybrid_tmp_17);

	// clo32(((ut32) (~Rs)));
	RzILOpPure *op_NOT_19 = LOGNOT(DUP(Rs));
	RzILOpEffect *clo32_call_21 = hex_clo32(CAST(32, IL_FALSE, op_NOT_19));

	// h_tmp575 = clo32(((ut32) (~Rs)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_23 = SETL("h_tmp575", UNSIGNED(32, VARL("ret_val")));

	// seq(clo32(((ut32) (~Rs))); h_tmp575 = clo32(((ut32) (~Rs))));
	RzILOpEffect *seq_24 = SEQN(2, clo32_call_21, op_ASSIGN_hybrid_tmp_23);

	// s = s;
	RzILOpEffect *imm_assign_26 = SETL("s", s);

	// Rd = ((st32) ((h_tmp572 > h_tmp573) ? h_tmp574 : h_tmp575) + ((ut32) s));
	RzILOpPure *op_GT_13 = UGT(VARL("h_tmp572"), VARL("h_tmp573"));
	RzILOpPure *cond_25 = ITE(op_GT_13, VARL("h_tmp574"), VARL("h_tmp575"));
	RzILOpPure *op_ADD_29 = ADD(cond_25, CAST(32, IL_FALSE, VARL("s")));
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_29));

	// seq(seq(clo32(((ut32) Rs)); h_tmp572 = clo32(((ut32) Rs))); seq( ...;
	RzILOpEffect *seq_32 = SEQN(5, seq_6, seq_12, seq_18, seq_24, op_ASSIGN_31);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_26, seq_32);
	return instruction_sequence;
}

// Rd = add(clb(Rss),Ii)
RzILOpEffect *hex_il_op_s4_clbpaddi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_3 = hex_clo64(CAST(64, IL_FALSE, Rss));

	// h_tmp576 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp576", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp576 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_6 = SEQN(2, clo64_call_3, op_ASSIGN_hybrid_tmp_5);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_7 = LOGNOT(DUP(Rss));
	RzILOpEffect *clo64_call_9 = hex_clo64(CAST(64, IL_FALSE, op_NOT_7));

	// h_tmp577 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp577", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp577 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_12 = SEQN(2, clo64_call_9, op_ASSIGN_hybrid_tmp_11);

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_15 = hex_clo64(CAST(64, IL_FALSE, DUP(Rss)));

	// h_tmp578 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_17 = SETL("h_tmp578", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp578 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_18 = SEQN(2, clo64_call_15, op_ASSIGN_hybrid_tmp_17);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_19 = LOGNOT(DUP(Rss));
	RzILOpEffect *clo64_call_21 = hex_clo64(CAST(64, IL_FALSE, op_NOT_19));

	// h_tmp579 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_23 = SETL("h_tmp579", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp579 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_24 = SEQN(2, clo64_call_21, op_ASSIGN_hybrid_tmp_23);

	// s = s;
	RzILOpEffect *imm_assign_26 = SETL("s", s);

	// Rd = ((st32) ((h_tmp576 > h_tmp577) ? h_tmp578 : h_tmp579) + ((ut64) s));
	RzILOpPure *op_GT_13 = UGT(VARL("h_tmp576"), VARL("h_tmp577"));
	RzILOpPure *cond_25 = ITE(op_GT_13, VARL("h_tmp578"), VARL("h_tmp579"));
	RzILOpPure *op_ADD_29 = ADD(cond_25, CAST(64, IL_FALSE, VARL("s")));
	RzILOpEffect *op_ASSIGN_31 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_ADD_29));

	// seq(seq(clo64(((ut64) Rss)); h_tmp576 = clo64(((ut64) Rss))); se ...;
	RzILOpEffect *seq_32 = SEQN(5, seq_6, seq_12, seq_18, seq_24, op_ASSIGN_31);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_26, seq_32);
	return instruction_sequence;
}

// Rd = normamt(Rss)
RzILOpEffect *hex_il_op_s4_clbpnorm(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// Rd = 0x0;
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rd_op, SN(32, 0));

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_8 = hex_clo64(CAST(64, IL_FALSE, Rss));

	// h_tmp580 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_10 = SETL("h_tmp580", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp580 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_11 = SEQN(2, clo64_call_8, op_ASSIGN_hybrid_tmp_10);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_12 = LOGNOT(DUP(Rss));
	RzILOpEffect *clo64_call_14 = hex_clo64(CAST(64, IL_FALSE, op_NOT_12));

	// h_tmp581 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_16 = SETL("h_tmp581", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp581 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_17 = SEQN(2, clo64_call_14, op_ASSIGN_hybrid_tmp_16);

	// clo64(((ut64) Rss));
	RzILOpEffect *clo64_call_20 = hex_clo64(CAST(64, IL_FALSE, DUP(Rss)));

	// h_tmp582 = clo64(((ut64) Rss));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_22 = SETL("h_tmp582", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) Rss)); h_tmp582 = clo64(((ut64) Rss)));
	RzILOpEffect *seq_23 = SEQN(2, clo64_call_20, op_ASSIGN_hybrid_tmp_22);

	// clo64(((ut64) (~Rss)));
	RzILOpPure *op_NOT_24 = LOGNOT(DUP(Rss));
	RzILOpEffect *clo64_call_26 = hex_clo64(CAST(64, IL_FALSE, op_NOT_24));

	// h_tmp583 = clo64(((ut64) (~Rss)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_28 = SETL("h_tmp583", UNSIGNED(64, VARL("ret_val")));

	// seq(clo64(((ut64) (~Rss))); h_tmp583 = clo64(((ut64) (~Rss))));
	RzILOpEffect *seq_29 = SEQN(2, clo64_call_26, op_ASSIGN_hybrid_tmp_28);

	// Rd = ((st32) ((h_tmp580 > h_tmp581) ? h_tmp582 : h_tmp583) - ((ut64) 0x1));
	RzILOpPure *op_GT_18 = UGT(VARL("h_tmp580"), VARL("h_tmp581"));
	RzILOpPure *cond_30 = ITE(op_GT_18, VARL("h_tmp582"), VARL("h_tmp583"));
	RzILOpPure *op_SUB_33 = SUB(cond_30, CAST(64, IL_FALSE, SN(32, 1)));
	RzILOpEffect *op_ASSIGN_35 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_SUB_33));

	// seq(seq(clo64(((ut64) Rss)); h_tmp580 = clo64(((ut64) Rss))); se ...;
	RzILOpEffect *seq_36 = SEQN(5, seq_11, seq_17, seq_23, seq_29, op_ASSIGN_35);

	// seq(Rd = 0x0);
	RzILOpEffect *seq_then_37 = op_ASSIGN_6;

	// seq(seq(seq(clo64(((ut64) Rss)); h_tmp580 = clo64(((ut64) Rss))) ...;
	RzILOpEffect *seq_else_38 = seq_36;

	// if ((Rss == ((st64) 0x0))) {seq(Rd = 0x0)} else {seq(seq(seq(clo64(((ut64) Rss)); h_tmp580 = clo64(((ut64) Rss))) ...};
	RzILOpPure *op_EQ_3 = EQ(DUP(Rss), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpEffect *branch_39 = BRANCH(op_EQ_3, seq_then_37, seq_else_38);

	RzILOpEffect *instruction_sequence = branch_39;
	return instruction_sequence;
}

// Rd = extract(Rs,Ii,II)
RzILOpEffect *hex_il_op_s4_extract(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: st32 offset;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// U = U;
	RzILOpEffect *imm_assign_5 = SETL("U", U);

	// offset = ((st32) U);
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", CAST(32, IL_FALSE, VARL("U")));

	// Rd = ((st32) ((width != 0x0) ? sextract64(((ut64) (((ut32) Rs) >> offset)), 0x0, width) : 0x0));
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(32, IL_FALSE, Rs), VARL("offset"));
	RzILOpPure *cond_20 = ITE(op_NE_12, SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_15), SN(32, 0), VARL("width")), SN(64, 0));
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_20), DUP(cond_20)));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_22);
	return instruction_sequence;
}

// Rd = extract(Rs,Rtt)
RzILOpEffect *hex_il_op_s4_extract_rp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: st32 width;
	// Declare: st32 offset;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);

	// width = ((st32) extract64(((ut64) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x6));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_18 = SETL("width", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9)))), SN(32, 0), SN(32, 6))));

	// offset = ((st32) sextract64(((ut64) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x7));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_37 = SETL("offset", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_28), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))));

	// Rd = ((st32) ((width != 0x0) ? sextract64(((offset < 0x0) ? ((((ut64) ((ut32) ((ut64) ((ut32) Rs)))) << (-offset) - 0x1) << 0x1) : (((ut64) ((ut32) ((ut64) ((ut32) Rs)))) >> offset)), 0x0, width) : 0x0));
	RzILOpPure *op_NE_41 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_43 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_49 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_51 = SUB(op_NEG_49, SN(32, 1));
	RzILOpPure *op_LSHIFT_52 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)))), op_SUB_51);
	RzILOpPure *op_LSHIFT_54 = SHIFTL0(op_LSHIFT_52, SN(32, 1));
	RzILOpPure *op_RSHIFT_59 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, CAST(64, IL_FALSE, CAST(32, IL_FALSE, DUP(Rs))))), VARL("offset"));
	RzILOpPure *cond_60 = ITE(op_LT_43, op_LSHIFT_54, op_RSHIFT_59);
	RzILOpPure *cond_64 = ITE(op_NE_41, SEXTRACT64(cond_60, SN(32, 0), VARL("width")), SN(64, 0));
	RzILOpEffect *op_ASSIGN_66 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(cond_64), DUP(cond_64)));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_18, op_ASSIGN_37, op_ASSIGN_66);
	return instruction_sequence;
}

// Rdd = extract(Rss,Ii,II)
RzILOpEffect *hex_il_op_s4_extractp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: st32 width;
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: st32 offset;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// width = ((st32) u);
	RzILOpEffect *op_ASSIGN_3 = SETL("width", CAST(32, IL_FALSE, VARL("u")));

	// U = U;
	RzILOpEffect *imm_assign_5 = SETL("U", U);

	// offset = ((st32) U);
	RzILOpEffect *op_ASSIGN_8 = SETL("offset", CAST(32, IL_FALSE, VARL("U")));

	// Rdd = ((width != 0x0) ? sextract64((((ut64) Rss) >> offset), 0x0, width) : 0x0);
	RzILOpPure *op_NE_12 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_RSHIFT_15 = SHIFTR0(CAST(64, IL_FALSE, Rss), VARL("offset"));
	RzILOpPure *cond_19 = ITE(op_NE_12, SEXTRACT64(op_RSHIFT_15, SN(32, 0), VARL("width")), SN(64, 0));
	RzILOpEffect *op_ASSIGN_20 = WRITE_REG(bundle, Rdd_op, cond_19);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_0, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_20);
	return instruction_sequence;
}

// Rdd = extract(Rss,Rtt)
RzILOpEffect *hex_il_op_s4_extractp_rp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	// Declare: st32 width;
	// Declare: st32 offset;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);

	// width = ((st32) extract64(((ut64) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x6));
	RzILOpPure *op_RSHIFT_7 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_9 = LOGAND(op_RSHIFT_7, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_18 = SETL("width", CAST(32, IL_FALSE, EXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_9), DUP(op_AND_9))), CAST(32, MSB(DUP(op_AND_9)), DUP(op_AND_9)))), SN(32, 0), SN(32, 6))));

	// offset = ((st32) sextract64(((ut64) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x7));
	RzILOpPure *op_RSHIFT_26 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_28 = LOGAND(op_RSHIFT_26, SN(64, 0xffffffff));
	RzILOpEffect *op_ASSIGN_37 = SETL("offset", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(op_AND_28), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, CAST(64, MSB(CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28))), CAST(32, MSB(DUP(op_AND_28)), DUP(op_AND_28)))), SN(32, 0), SN(32, 7))));

	// Rdd = ((width != 0x0) ? sextract64(((offset < 0x0) ? ((((ut64) Rss) << (-offset) - 0x1) << 0x1) : (((ut64) Rss) >> offset)), 0x0, width) : 0x0);
	RzILOpPure *op_NE_41 = INV(EQ(VARL("width"), SN(32, 0)));
	RzILOpPure *op_LT_43 = SLT(VARL("offset"), SN(32, 0));
	RzILOpPure *op_NEG_46 = NEG(VARL("offset"));
	RzILOpPure *op_SUB_48 = SUB(op_NEG_46, SN(32, 1));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(CAST(64, IL_FALSE, Rss), op_SUB_48);
	RzILOpPure *op_LSHIFT_51 = SHIFTL0(op_LSHIFT_49, SN(32, 1));
	RzILOpPure *op_RSHIFT_53 = SHIFTR0(CAST(64, IL_FALSE, DUP(Rss)), VARL("offset"));
	RzILOpPure *cond_54 = ITE(op_LT_43, op_LSHIFT_51, op_RSHIFT_53);
	RzILOpPure *cond_58 = ITE(op_NE_41, SEXTRACT64(cond_54, SN(32, 0), VARL("width")), SN(64, 0));
	RzILOpEffect *op_ASSIGN_59 = WRITE_REG(bundle, Rdd_op, cond_58);

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_18, op_ASSIGN_37, op_ASSIGN_59);
	return instruction_sequence;
}

// Rd = lsl(Ii,Rt)
RzILOpEffect *hex_il_op_s4_lsli(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	// Declare: st32 shamt;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// shamt = ((st32) sextract64(((ut64) Rt), 0x0, 0x7));
	RzILOpEffect *op_ASSIGN_10 = SETL("shamt", CAST(32, MSB(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7))));

	// s = s;
	RzILOpEffect *imm_assign_15 = SETL("s", s);

	// Rd = ((st32) ((shamt < 0x0) ? ((((ut64) ((ut32) s)) >> (-shamt) - 0x1) >> 0x1) : (((ut64) ((ut32) s)) << shamt)));
	RzILOpPure *op_LT_14 = SLT(VARL("shamt"), SN(32, 0));
	RzILOpPure *op_NEG_19 = NEG(VARL("shamt"));
	RzILOpPure *op_SUB_21 = SUB(op_NEG_19, SN(32, 1));
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, VARL("s"))), op_SUB_21);
	RzILOpPure *op_RSHIFT_24 = SHIFTR0(op_RSHIFT_22, SN(32, 1));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, VARL("s"))), VARL("shamt"));
	RzILOpPure *cond_28 = ITE(op_LT_14, op_RSHIFT_24, op_LSHIFT_27);
	RzILOpEffect *op_ASSIGN_30 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, cond_28));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_15, op_ASSIGN_10, op_ASSIGN_30);
	return instruction_sequence;
}

// Pd = !tstbit(Rs,Ii)
RzILOpEffect *hex_il_op_s4_ntstbit_i(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// Pd = ((st8) (((Rs & (0x1 << u)) == 0x0) ? 0xff : 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(32, 1), VARL("u"));
	RzILOpPure *op_AND_6 = LOGAND(Rs, op_LSHIFT_5);
	RzILOpPure *op_EQ_8 = EQ(op_AND_6, SN(32, 0));
	RzILOpPure *cond_11 = ITE(op_EQ_8, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_11), DUP(cond_11)));

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_3, op_ASSIGN_13);
	return instruction_sequence;
}

// Pd = !tstbit(Rs,Rt)
RzILOpEffect *hex_il_op_s4_ntstbit_r(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Pd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// Pd = ((st8) (((((ut64) ((ut32) Rs)) & ((sextract64(((ut64) Rt), 0x0, 0x7) < ((st64) 0x0)) ? ((((ut64) ((ut32) 0x1)) >> (-sextract64(((ut64) Rt), 0x0, 0x7)) - ((st64) 0x1)) >> 0x1) : (((ut64) ((ut32) 0x1)) << sextract64(((ut64) Rt), 0x0, 0x7)))) == ((ut64) 0x0)) ? 0xff : 0x0));
	RzILOpPure *op_LT_15 = SLT(SEXTRACT64(CAST(64, IL_FALSE, Rt), SN(32, 0), SN(32, 7)), CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_NEG_27 = NEG(SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *op_SUB_30 = SUB(op_NEG_27, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), op_SUB_30);
	RzILOpPure *op_RSHIFT_33 = SHIFTR0(op_RSHIFT_31, SN(32, 1));
	RzILOpPure *op_LSHIFT_45 = SHIFTL0(CAST(64, IL_FALSE, CAST(32, IL_FALSE, SN(32, 1))), SEXTRACT64(CAST(64, IL_FALSE, DUP(Rt)), SN(32, 0), SN(32, 7)));
	RzILOpPure *cond_46 = ITE(op_LT_15, op_RSHIFT_33, op_LSHIFT_45);
	RzILOpPure *op_AND_47 = LOGAND(CAST(64, IL_FALSE, CAST(32, IL_FALSE, Rs)), cond_46);
	RzILOpPure *op_EQ_50 = EQ(op_AND_47, CAST(64, IL_FALSE, SN(32, 0)));
	RzILOpPure *cond_53 = ITE(op_EQ_50, SN(32, 0xff), SN(32, 0));
	RzILOpEffect *op_ASSIGN_55 = WRITE_REG(bundle, Pd_op, CAST(8, MSB(cond_53), DUP(cond_53)));

	RzILOpEffect *instruction_sequence = op_ASSIGN_55;
	return instruction_sequence;
}

// Rx |= and(Rs,Ii)
RzILOpEffect *hex_il_op_s4_or_andi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// s = s;
	RzILOpEffect *imm_assign_2 = SETL("s", s);

	// Rx = (Rx | (Rs & s));
	RzILOpPure *op_AND_4 = LOGAND(Rs, VARL("s"));
	RzILOpPure *op_OR_5 = LOGOR(READ_REG(pkt, Rx_op, false), op_AND_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_OR_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rx = or(Ru,and(Rxin,Ii))
RzILOpEffect *hex_il_op_s4_or_andix(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// s = s;
	RzILOpEffect *imm_assign_2 = SETL("s", s);

	// Rx = (Ru | (Rx & s));
	RzILOpPure *op_AND_4 = LOGAND(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpPure *op_OR_5 = LOGOR(Ru, op_AND_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_OR_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rx |= or(Rs,Ii)
RzILOpEffect *hex_il_op_s4_or_ori(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// s = s;
	RzILOpEffect *imm_assign_2 = SETL("s", s);

	// Rx = (Rx | (Rs | s));
	RzILOpPure *op_OR_4 = LOGOR(Rs, VARL("s"));
	RzILOpPure *op_OR_5 = LOGOR(READ_REG(pkt, Rx_op, false), op_OR_4);
	RzILOpEffect *op_ASSIGN_6 = WRITE_REG(bundle, Rx_op, op_OR_5);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_2, op_ASSIGN_6);
	return instruction_sequence;
}

// Rx = or(Ii,asl(Rxin,II))
RzILOpEffect *hex_il_op_s4_ori_asl_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// Rx = ((st32) (u | ((ut32) (Rx << U))));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(READ_REG(pkt, Rx_op, false), VARL("U"));
	RzILOpPure *op_OR_7 = LOGOR(VARL("u"), CAST(32, IL_FALSE, op_LSHIFT_5));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_3, op_ASSIGN_9);
	return instruction_sequence;
}

// Rx = or(Ii,lsr(Rxin,II))
RzILOpEffect *hex_il_op_s4_ori_lsr_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_4 = SETL("U", U);

	// Rx = ((st32) (u | (((ut32) Rx) >> U)));
	RzILOpPure *op_RSHIFT_6 = SHIFTR0(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), VARL("U"));
	RzILOpPure *op_OR_7 = LOGOR(VARL("u"), op_RSHIFT_6);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_OR_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_4, op_ASSIGN_9);
	return instruction_sequence;
}

// Rd = parity(Rs,Rt)
RzILOpEffect *hex_il_op_s4_parity(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pv) memb(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_21 = ms_cast_ut8_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv) memb(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_26 = ms_cast_ut8_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memb(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_21 = ms_cast_ut8_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_21_22 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_24 = ms_cast_ut8_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_26 = ms_cast_ut8_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv) memb(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_21 = ms_cast_ut8_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv) memb(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_26 = ms_cast_ut8_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memb(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_21 = ms_cast_ut8_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_21_22 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_24 = ms_cast_ut8_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_23_24 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_26 = ms_cast_ut8_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (Pv) memb(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_17_18 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_20 = ms_cast_ut8_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv) memb(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_25 = ms_cast_ut8_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memb(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_17_18 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_20 = ms_cast_ut8_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv.new) memb(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_20_21 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_23 = ms_cast_ut8_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv.new) memb(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerbnewtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_25 = ms_cast_ut8_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv) memb(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_17_18 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_20 = ms_cast_ut8_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv) memb(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_25 = ms_cast_ut8_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memb(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_17_18 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_20 = ms_cast_ut8_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv.new) memb(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_20_21 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_23 = ms_cast_ut8_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv.new) memb(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerbtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_22_23 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))));
	RzILOpEffect *seq_then_25 = ms_cast_ut8_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (!Pv) memd(Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_11_12 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_13 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_14 = ms_cast_ut64_11_12;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_15 = c_call_13;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_16 = BRANCH(op_INV_9, seq_then_14, seq_else_15);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_16);
	return instruction_sequence;
}

// if (!Pv) memd(Rs+Ru<<Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_16_17 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_19 = ms_cast_ut64_16_17;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_21 = BRANCH(op_INV_14, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_21);
	return instruction_sequence;
}

// if (!Pv.new) memd(Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_11_12 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_13 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_14 = ms_cast_ut64_11_12;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_15 = c_call_13;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_16 = BRANCH(op_INV_9, seq_then_14, seq_else_15);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_16);
	return instruction_sequence;
}

// if (!Pv.new) memd(Rs+Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_14_15 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_17 = ms_cast_ut64_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_19 = BRANCH(op_INV_12, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) memd(Rs+Ru<<Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_16_17 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_19 = ms_cast_ut64_16_17;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_21 = BRANCH(op_INV_14, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_21);
	return instruction_sequence;
}

// if (Pv) memd(Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_10_11 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_12 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_13 = ms_cast_ut64_10_11;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_14 = c_call_12;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_15 = BRANCH(NON_ZERO(op_AND_8), seq_then_13, seq_else_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_15);
	return instruction_sequence;
}

// if (Pv) memd(Rs+Ru<<Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_15_16 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_18 = ms_cast_ut64_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_13), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_20);
	return instruction_sequence;
}

// if (Pv.new) memd(Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_10_11 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_12 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_13 = ms_cast_ut64_10_11;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_14 = c_call_12;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_15 = BRANCH(NON_ZERO(op_AND_8), seq_then_13, seq_else_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_15);
	return instruction_sequence;
}

// if (Pv.new) memd(Rs+Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_13_14 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_15 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_16 = ms_cast_ut64_13_14;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_17 = c_call_15;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_11), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_18);
	return instruction_sequence;
}

// if (Pv.new) memd(Rs+Ru<<Ii) = Rtt
RzILOpEffect *hex_il_op_s4_pstorerdtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_15_16 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut64(EA, ((ut64) Rtt)));
	RzILOpEffect *seq_then_18 = ms_cast_ut64_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut64(EA, ((ut64) Rtt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_13), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_20);
	return instruction_sequence;
}

// if (!Pv) memh(Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerff_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_21 = ms_cast_ut16_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ru<<Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerff_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_26 = ms_cast_ut16_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memh(Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerffnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_21 = ms_cast_ut16_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerffnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_24 = ms_cast_ut16_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ru<<Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerffnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_26 = ms_cast_ut16_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (Pv) memh(Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerft_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_20 = ms_cast_ut16_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ru<<Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerft_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_25 = ms_cast_ut16_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memh(Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerftnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_20 = ms_cast_ut16_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerftnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_23 = ms_cast_ut16_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ru<<Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_pstorerftnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...;
	RzILOpEffect *seq_then_25 = ms_cast_ut16_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))) ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (!Pv) memh(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_21 = ms_cast_ut16_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_26 = ms_cast_ut16_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memh(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_21 = ms_cast_ut16_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_24 = ms_cast_ut16_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_26 = ms_cast_ut16_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv) memh(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_21 = ms_cast_ut16_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_26 = ms_cast_ut16_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (!Pv.new) memh(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_20 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_21 = ms_cast_ut16_18_19;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_22 = c_call_20;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_23 = BRANCH(op_INV_9, seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_17 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_19 = LOGAND(op_RSHIFT_17, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_21_22 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_19), DUP(op_AND_19))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_23 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_24 = ms_cast_ut16_21_22;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_25 = c_call_23;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_26 = BRANCH(op_INV_12, seq_then_24, seq_else_25);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_26);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_19 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_21 = LOGAND(op_RSHIFT_19, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_23_24 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_21), DUP(op_AND_21))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_25 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_26 = ms_cast_ut16_23_24;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_27 = c_call_25;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_28 = BRANCH(op_INV_14, seq_then_26, seq_else_27);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_28);
	return instruction_sequence;
}

// if (Pv) memh(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_20 = ms_cast_ut16_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_25 = ms_cast_ut16_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memh(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_20 = ms_cast_ut16_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_23 = ms_cast_ut16_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerhnewtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...;
	RzILOpEffect *seq_then_25 = ms_cast_ut16_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff ...} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv) memh(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerht_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_20 = ms_cast_ut16_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerht_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_25 = ms_cast_ut16_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (Pv.new) memh(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_13 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_15 = LOGAND(op_RSHIFT_13, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_17_18 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_15), DUP(op_AND_15))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_19 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_20 = ms_cast_ut16_17_18;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_21 = c_call_19;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_22 = BRANCH(NON_ZERO(op_AND_8), seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_22);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_20_21 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_18), DUP(op_AND_18))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_22 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_23 = ms_cast_ut16_20_21;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_24 = c_call_22;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_25 = BRANCH(NON_ZERO(op_AND_11), seq_then_23, seq_else_24);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_25);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerhtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_18 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_20 = LOGAND(op_RSHIFT_18, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_22_23 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_20), DUP(op_AND_20))));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_24 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))));
	RzILOpEffect *seq_then_25 = ms_cast_ut16_22_23;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_26 = c_call_24;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff)))))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_27 = BRANCH(NON_ZERO(op_AND_13), seq_then_25, seq_else_26);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_27);
	return instruction_sequence;
}

// if (!Pv) memw(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerif_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_13 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_14 = ms_cast_ut32_11_12;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_15 = c_call_13;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_16 = BRANCH(op_INV_9, seq_then_14, seq_else_15);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_16);
	return instruction_sequence;
}

// if (!Pv) memw(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerif_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_19 = ms_cast_ut32_16_17;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_21 = BRANCH(op_INV_14, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_21);
	return instruction_sequence;
}

// if (!Pv.new) memw(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerifnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_13 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_14 = ms_cast_ut32_11_12;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_15 = c_call_13;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_16 = BRANCH(op_INV_9, seq_then_14, seq_else_15);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_16);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerifnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_17 = ms_cast_ut32_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_19 = BRANCH(op_INV_12, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerifnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_19 = ms_cast_ut32_16_17;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_21 = BRANCH(op_INV_14, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_21);
	return instruction_sequence;
}

// if (!Pv) memw(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewf_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_13 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_14 = ms_cast_ut32_11_12;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_15 = c_call_13;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_16 = BRANCH(op_INV_9, seq_then_14, seq_else_15);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_16);
	return instruction_sequence;
}

// if (!Pv) memw(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_19 = ms_cast_ut32_16_17;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_21 = BRANCH(op_INV_14, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_21);
	return instruction_sequence;
}

// if (!Pv.new) memw(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewfnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_13 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_14 = ms_cast_ut32_11_12;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_15 = c_call_13;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_16 = BRANCH(op_INV_9, seq_then_14, seq_else_15);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_16);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_17 = ms_cast_ut32_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_19 = BRANCH(op_INV_12, seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewfnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_16_17 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_18 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_19 = ms_cast_ut32_16_17;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_20 = c_call_18;

	// if (! (((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_14 = INV(NON_ZERO(op_AND_13));
	RzILOpEffect *branch_21 = BRANCH(op_INV_14, seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_21);
	return instruction_sequence;
}

// if (Pv) memw(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewt_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_12 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_13 = ms_cast_ut32_10_11;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_14 = c_call_12;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_15 = BRANCH(NON_ZERO(op_AND_8), seq_then_13, seq_else_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_15);
	return instruction_sequence;
}

// if (Pv) memw(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewt_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_18 = ms_cast_ut32_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_13), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_20);
	return instruction_sequence;
}

// if (Pv.new) memw(Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewtnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_12 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_13 = ms_cast_ut32_10_11;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_14 = c_call_12;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_15 = BRANCH(NON_ZERO(op_AND_8), seq_then_13, seq_else_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_15);
	return instruction_sequence;
}

// if (Pv.new) memw(Rs+Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_13_14 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_15 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_16 = ms_cast_ut32_13_14;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_17 = c_call_15;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_11), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_18);
	return instruction_sequence;
}

// if (Pv.new) memw(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_pstorerinewtnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Nt_new)));
	RzILOpEffect *seq_then_18 = ms_cast_ut32_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Nt_new)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_13), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_20);
	return instruction_sequence;
}

// if (Pv) memw(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerit_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_12 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_13 = ms_cast_ut32_10_11;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_14 = c_call_12;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_15 = BRANCH(NON_ZERO(op_AND_8), seq_then_13, seq_else_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_15);
	return instruction_sequence;
}

// if (Pv) memw(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstorerit_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_18 = ms_cast_ut32_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_13), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_20);
	return instruction_sequence;
}

// if (Pv.new) memw(Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstoreritnew_abs(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = u;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("u"));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_12 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_13 = ms_cast_ut32_10_11;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_14 = c_call_12;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_15 = BRANCH(NON_ZERO(op_AND_8), seq_then_13, seq_else_14);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_3, branch_15);
	return instruction_sequence;
}

// if (Pv.new) memw(Rs+Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstoreritnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_13_14 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_15 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_16 = ms_cast_ut32_13_14;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_17 = c_call_15;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_18 = BRANCH(NON_ZERO(op_AND_11), seq_then_16, seq_else_17);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_18);
	return instruction_sequence;
}

// if (Pv.new) memw(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_pstoreritnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(mem_store_ut32(EA, ((ut32) Rt)));
	RzILOpEffect *seq_then_18 = ms_cast_ut32_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if ((((st32) Pv_new) & 0x1)) {seq(mem_store_ut32(EA, ((ut32) Rt)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_13 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_20 = BRANCH(NON_ZERO(op_AND_13), seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, branch_20);
	return instruction_sequence;
}

// memd_locked(Rs,Pd) = Rtt
RzILOpEffect *hex_il_op_s4_stored_locked(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// memd_rl(Rs):at = Rtt
RzILOpEffect *hex_il_op_s4_stored_rl_at_vi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_6_7 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_3, ms_cast_ut64_6_7);
	return instruction_sequence;
}

// memd_rl(Rs):st = Rtt
RzILOpEffect *hex_il_op_s4_stored_rl_st_vi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_6_7 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_3, ms_cast_ut64_6_7);
	return instruction_sequence;
}

// memb(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_8 = SETL("S", S);

	// mem_store_ut8(EA, ((ut8) S));
	RzILOpEffect *ms_cast_ut8_10_11 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("S")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_8, op_ASSIGN_6, ms_cast_ut8_10_11);
	return instruction_sequence;
}

// if (!Pv) memb(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirbf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_13 = SETL("S", S);

	// mem_store_ut8(EA, ((ut8) S));
	RzILOpEffect *ms_cast_ut8_15_16 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut8(EA, ((ut8) S)));
	RzILOpEffect *seq_then_18 = ms_cast_ut8_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if (! (((st32) Pv) & 0x1)) {seq(S; mem_store_ut8(EA, ((ut8) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_20 = BRANCH(op_INV_12, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_13, op_ASSIGN_6, branch_20);
	return instruction_sequence;
}

// if (!Pv.new) memb(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirbfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_13 = SETL("S", S);

	// mem_store_ut8(EA, ((ut8) S));
	RzILOpEffect *ms_cast_ut8_15_16 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut8(EA, ((ut8) S)));
	RzILOpEffect *seq_then_18 = ms_cast_ut8_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if (! (((st32) Pv_new) & 0x1)) {seq(S; mem_store_ut8(EA, ((ut8) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_20 = BRANCH(op_INV_12, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_13, op_ASSIGN_6, branch_20);
	return instruction_sequence;
}

// if (Pv) memb(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirbt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_12 = SETL("S", S);

	// mem_store_ut8(EA, ((ut8) S));
	RzILOpEffect *ms_cast_ut8_14_15 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut8(EA, ((ut8) S)));
	RzILOpEffect *seq_then_17 = ms_cast_ut8_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if ((((st32) Pv) & 0x1)) {seq(S; mem_store_ut8(EA, ((ut8) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_11), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_12, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (Pv.new) memb(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirbtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_12 = SETL("S", S);

	// mem_store_ut8(EA, ((ut8) S));
	RzILOpEffect *ms_cast_ut8_14_15 = STOREW(VARL("EA"), CAST(8, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut8(EA, ((ut8) S)));
	RzILOpEffect *seq_then_17 = ms_cast_ut8_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if ((((st32) Pv_new) & 0x1)) {seq(S; mem_store_ut8(EA, ((ut8) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_11), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_12, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// memh(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_8 = SETL("S", S);

	// mem_store_ut16(EA, ((ut16) S));
	RzILOpEffect *ms_cast_ut16_10_11 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("S")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_8, op_ASSIGN_6, ms_cast_ut16_10_11);
	return instruction_sequence;
}

// if (!Pv) memh(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirhf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_13 = SETL("S", S);

	// mem_store_ut16(EA, ((ut16) S));
	RzILOpEffect *ms_cast_ut16_15_16 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut16(EA, ((ut16) S)));
	RzILOpEffect *seq_then_18 = ms_cast_ut16_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if (! (((st32) Pv) & 0x1)) {seq(S; mem_store_ut16(EA, ((ut16) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_20 = BRANCH(op_INV_12, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_13, op_ASSIGN_6, branch_20);
	return instruction_sequence;
}

// if (!Pv.new) memh(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirhfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_13 = SETL("S", S);

	// mem_store_ut16(EA, ((ut16) S));
	RzILOpEffect *ms_cast_ut16_15_16 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut16(EA, ((ut16) S)));
	RzILOpEffect *seq_then_18 = ms_cast_ut16_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if (! (((st32) Pv_new) & 0x1)) {seq(S; mem_store_ut16(EA, ((ut16) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_20 = BRANCH(op_INV_12, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_13, op_ASSIGN_6, branch_20);
	return instruction_sequence;
}

// if (Pv) memh(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirht_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_12 = SETL("S", S);

	// mem_store_ut16(EA, ((ut16) S));
	RzILOpEffect *ms_cast_ut16_14_15 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut16(EA, ((ut16) S)));
	RzILOpEffect *seq_then_17 = ms_cast_ut16_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if ((((st32) Pv) & 0x1)) {seq(S; mem_store_ut16(EA, ((ut16) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_11), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_12, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (Pv.new) memh(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirhtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_12 = SETL("S", S);

	// mem_store_ut16(EA, ((ut16) S));
	RzILOpEffect *ms_cast_ut16_14_15 = STOREW(VARL("EA"), CAST(16, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut16(EA, ((ut16) S)));
	RzILOpEffect *seq_then_17 = ms_cast_ut16_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if ((((st32) Pv_new) & 0x1)) {seq(S; mem_store_ut16(EA, ((ut16) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_11), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_12, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// memw(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeiri_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_8 = SETL("S", S);

	// mem_store_ut32(EA, ((ut32) S));
	RzILOpEffect *ms_cast_ut32_10_11 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("S")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_8, op_ASSIGN_6, ms_cast_ut32_10_11);
	return instruction_sequence;
}

// if (!Pv) memw(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirif_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_13 = SETL("S", S);

	// mem_store_ut32(EA, ((ut32) S));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut32(EA, ((ut32) S)));
	RzILOpEffect *seq_then_18 = ms_cast_ut32_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if (! (((st32) Pv) & 0x1)) {seq(S; mem_store_ut32(EA, ((ut32) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_20 = BRANCH(op_INV_12, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_13, op_ASSIGN_6, branch_20);
	return instruction_sequence;
}

// if (!Pv.new) memw(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirifnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_13 = SETL("S", S);

	// mem_store_ut32(EA, ((ut32) S));
	RzILOpEffect *ms_cast_ut32_15_16 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_17 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut32(EA, ((ut32) S)));
	RzILOpEffect *seq_then_18 = ms_cast_ut32_15_16;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_19 = c_call_17;

	// if (! (((st32) Pv_new) & 0x1)) {seq(S; mem_store_ut32(EA, ((ut32) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_20 = BRANCH(op_INV_12, seq_then_18, seq_else_19);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_13, op_ASSIGN_6, branch_20);
	return instruction_sequence;
}

// if (Pv) memw(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeirit_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_op = ISA2REG(hi, 'v', false);
	RzILOpPure *Pv = READ_REG(pkt, Pv_op, false);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_12 = SETL("S", S);

	// mem_store_ut32(EA, ((ut32) S));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut32(EA, ((ut32) S)));
	RzILOpEffect *seq_then_17 = ms_cast_ut32_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if ((((st32) Pv) & 0x1)) {seq(S; mem_store_ut32(EA, ((ut32) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv), DUP(Pv)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_11), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_12, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// if (Pv.new) memw(Rs+Ii) = II
RzILOpEffect *hex_il_op_s4_storeiritnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Pv_new_op = ISA2REG(hi, 'v', true);
	RzILOpPure *Pv_new = READ_REG(pkt, Pv_new_op, true);
	RzILOpPure *S = SN(32, (st32)ISA2IMM(hi, 'S'));

	// u = u;
	RzILOpEffect *imm_assign_2 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// S = S;
	RzILOpEffect *imm_assign_12 = SETL("S", S);

	// mem_store_ut32(EA, ((ut32) S));
	RzILOpEffect *ms_cast_ut32_14_15 = STOREW(VARL("EA"), CAST(32, IL_FALSE, VARL("S")));

	// HYB(call_pkt, slot);
	RzILOpEffect *c_call_16 = HEX_STORE_SLOT_CANCELLED(pkt, hi->slot);

	// seq(S; mem_store_ut32(EA, ((ut32) S)));
	RzILOpEffect *seq_then_17 = ms_cast_ut32_14_15;

	// seq(HYB(call_pkt, slot));
	RzILOpEffect *seq_else_18 = c_call_16;

	// if ((((st32) Pv_new) & 0x1)) {seq(S; mem_store_ut32(EA, ((ut32) S)))} else {seq(HYB(call_pkt, slot))};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pv_new), DUP(Pv_new)), SN(32, 1));
	RzILOpEffect *branch_19 = BRANCH(NON_ZERO(op_AND_11), seq_then_17, seq_else_18);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_2, imm_assign_12, op_ASSIGN_6, branch_19);
	return instruction_sequence;
}

// memb(Re=II) = Rt
RzILOpEffect *hex_il_op_s4_storerb_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_13_14 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_11), DUP(op_AND_11))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut8_13_14, op_ASSIGN_17);
	return instruction_sequence;
}

// memb(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_storerb_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut8_18_19);
	return instruction_sequence;
}

// memb(Ru<<Ii+II) = Rt
RzILOpEffect *hex_il_op_s4_storerb_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Rt >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_19_20 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_17), DUP(op_AND_17))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut8_19_20);
	return instruction_sequence;
}

// memb(Re=II) = Nt.new
RzILOpEffect *hex_il_op_s4_storerbnew_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_13_14 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_11), DUP(op_AND_11))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut8_13_14, op_ASSIGN_17);
	return instruction_sequence;
}

// memb(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_storerbnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_18_19 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut8_18_19);
	return instruction_sequence;
}

// memb(Ru<<Ii+II) = Nt.new
RzILOpEffect *hex_il_op_s4_storerbnew_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut8(EA, ((ut8) ((st8) ((Nt_new >> 0x0) & 0xff))));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xff));
	RzILOpEffect *ms_cast_ut8_19_20 = STOREW(VARL("EA"), CAST(8, IL_FALSE, CAST(8, MSB(op_AND_17), DUP(op_AND_17))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut8_19_20);
	return instruction_sequence;
}

// memd(Re=II) = Rtt
RzILOpEffect *hex_il_op_s4_storerd_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_6_7 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut64_6_7, op_ASSIGN_10);
	return instruction_sequence;
}

// memd(Rs+Ru<<Ii) = Rtt
RzILOpEffect *hex_il_op_s4_storerd_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_11_12 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut64_11_12);
	return instruction_sequence;
}

// memd(Ru<<Ii+II) = Rtt
RzILOpEffect *hex_il_op_s4_storerd_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut64(EA, ((ut64) Rtt));
	RzILOpEffect *ms_cast_ut64_12_13 = STOREW(VARL("EA"), CAST(64, IL_FALSE, Rtt));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut64_12_13);
	return instruction_sequence;
}

// memh(Re=II) = Rt.h
RzILOpEffect *hex_il_op_s4_storerf_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_13_14 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_11), DUP(op_AND_11))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut16_13_14, op_ASSIGN_17);
	return instruction_sequence;
}

// memh(Rs+Ru<<Ii) = Rt.h
RzILOpEffect *hex_il_op_s4_storerf_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memh(Ru<<Ii+II) = Rt.h
RzILOpEffect *hex_il_op_s4_storerf_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x10) & 0xffff))));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rt, SN(32, 16));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_19_20 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_17), DUP(op_AND_17))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut16_19_20);
	return instruction_sequence;
}

// memh(Re=II) = Rt
RzILOpEffect *hex_il_op_s4_storerh_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_13_14 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_11), DUP(op_AND_11))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut16_13_14, op_ASSIGN_17);
	return instruction_sequence;
}

// memh(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_storerh_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memh(Ru<<Ii+II) = Rt
RzILOpEffect *hex_il_op_s4_storerh_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Rt >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rt, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_19_20 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_17), DUP(op_AND_17))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut16_19_20);
	return instruction_sequence;
}

// memh(Re=II) = Nt.new
RzILOpEffect *hex_il_op_s4_storerhnew_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_9 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_11 = LOGAND(op_RSHIFT_9, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_13_14 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_11), DUP(op_AND_11))));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut16_13_14, op_ASSIGN_17);
	return instruction_sequence;
}

// memh(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_storerhnew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_18_19 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_16), DUP(op_AND_16))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut16_18_19);
	return instruction_sequence;
}

// memh(Ru<<Ii+II) = Nt.new
RzILOpEffect *hex_il_op_s4_storerhnew_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut16(EA, ((ut16) ((st16) ((Nt_new >> 0x0) & 0xffff))));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Nt_new, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(32, 0xffff));
	RzILOpEffect *ms_cast_ut16_19_20 = STOREW(VARL("EA"), CAST(16, IL_FALSE, CAST(16, MSB(op_AND_17), DUP(op_AND_17))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut16_19_20);
	return instruction_sequence;
}

// memw(Re=II) = Rt
RzILOpEffect *hex_il_op_s4_storeri_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_6_7 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut32_6_7, op_ASSIGN_10);
	return instruction_sequence;
}

// memw(Rs+Ru<<Ii) = Rt
RzILOpEffect *hex_il_op_s4_storeri_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut32_11_12);
	return instruction_sequence;
}

// memw(Ru<<Ii+II) = Rt
RzILOpEffect *hex_il_op_s4_storeri_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp *Rt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rt = READ_REG(pkt, Rt_op, false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut32(EA, ((ut32) Rt));
	RzILOpEffect *ms_cast_ut32_12_13 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Rt));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut32_12_13);
	return instruction_sequence;
}

// memw(Re=II) = Nt.new
RzILOpEffect *hex_il_op_s4_storerinew_ap(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);
	const HexOp *Re_op = ISA2REG(hi, 'e', false);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// EA = U;
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", VARL("U"));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_6_7 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	// Re = ((st32) U);
	RzILOpEffect *op_ASSIGN_10 = WRITE_REG(bundle, Re_op, CAST(32, IL_FALSE, VARL("U")));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_3, ms_cast_ut32_6_7, op_ASSIGN_10);
	return instruction_sequence;
}

// memw(Rs+Ru<<Ii) = Nt.new
RzILOpEffect *hex_il_op_s4_storerinew_rr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// u = u;
	RzILOpEffect *imm_assign_3 = SETL("u", u);

	// EA = ((ut32) Rs + (Ru << u));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_6 = ADD(Rs, op_LSHIFT_5);
	RzILOpEffect *op_ASSIGN_8 = SETL("EA", CAST(32, IL_FALSE, op_ADD_6));

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_11_12 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_3, op_ASSIGN_8, ms_cast_ut32_11_12);
	return instruction_sequence;
}

// memw(Ru<<Ii+II) = Nt.new
RzILOpEffect *hex_il_op_s4_storerinew_ur(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));
	// Declare: ut32 EA;
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	const HexOp Nt_new_op = NREG2OP(bundle, 't');
	RzILOpPure *Nt_new = READ_REG(pkt, &Nt_new_op, true);

	// U = U;
	RzILOpEffect *imm_assign_0 = SETL("U", U);

	// u = u;
	RzILOpEffect *imm_assign_4 = SETL("u", u);

	// EA = U + ((ut32) (Ru << u));
	RzILOpPure *op_LSHIFT_6 = SHIFTL0(Ru, VARL("u"));
	RzILOpPure *op_ADD_8 = ADD(VARL("U"), CAST(32, IL_FALSE, op_LSHIFT_6));
	RzILOpEffect *op_ASSIGN_9 = SETL("EA", op_ADD_8);

	// mem_store_ut32(EA, ((ut32) Nt_new));
	RzILOpEffect *ms_cast_ut32_12_13 = STOREW(VARL("EA"), CAST(32, IL_FALSE, Nt_new));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, imm_assign_4, op_ASSIGN_9, ms_cast_ut32_12_13);
	return instruction_sequence;
}

// Rd = add(Rs,sub(Ii,Ru))
RzILOpEffect *hex_il_op_s4_subaddi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Ru_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Ru = READ_REG(pkt, Ru_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));

	// s = s;
	RzILOpEffect *imm_assign_4 = SETL("s", s);

	// Rd = Rs - Ru + s;
	RzILOpPure *op_SUB_3 = SUB(Rs, Ru);
	RzILOpPure *op_ADD_6 = ADD(op_SUB_3, VARL("s"));
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rd_op, op_ADD_6);

	RzILOpEffect *instruction_sequence = SEQN(2, imm_assign_4, op_ASSIGN_7);
	return instruction_sequence;
}

// Rx = sub(Ii,asl(Rxin,II))
RzILOpEffect *hex_il_op_s4_subi_asl_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_3 = SETL("U", U);

	// Rx = ((st32) u - ((ut32) (Rx << U)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(READ_REG(pkt, Rx_op, false), VARL("U"));
	RzILOpPure *op_SUB_7 = SUB(VARL("u"), CAST(32, IL_FALSE, op_LSHIFT_5));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_3, op_ASSIGN_9);
	return instruction_sequence;
}

// Rx = sub(Ii,lsr(Rxin,II))
RzILOpEffect *hex_il_op_s4_subi_lsr_ri(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	RzILOpPure *U = UN(32, (ut32)ISA2IMM(hi, 'U'));

	// u = u;
	RzILOpEffect *imm_assign_1 = SETL("u", u);

	// U = U;
	RzILOpEffect *imm_assign_4 = SETL("U", U);

	// Rx = ((st32) u - (((ut32) Rx) >> U));
	RzILOpPure *op_RSHIFT_6 = SHIFTR0(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)), VARL("U"));
	RzILOpPure *op_SUB_7 = SUB(VARL("u"), op_RSHIFT_6);
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rx_op, CAST(32, IL_FALSE, op_SUB_7));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_1, imm_assign_4, op_ASSIGN_9);
	return instruction_sequence;
}

// Rdd = vrcrotate(Rss,Rt,Ii)
RzILOpEffect *hex_il_op_s4_vrcrotate(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rxx += vrcrotate(Rss,Rt,Ii)
RzILOpEffect *hex_il_op_s4_vrcrotate_acc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = vxaddsubh(Rss,Rtt):sat
RzILOpEffect *hex_il_op_s4_vxaddsubh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_79 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, SN(32, 16));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_31 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(CAST(16, MSB(op_AND_27), DUP(op_AND_27))), CAST(16, MSB(DUP(op_AND_27)), DUP(op_AND_27))));
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_55 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_43), DUP(op_AND_43))), CAST(16, MSB(DUP(op_AND_43)), DUP(op_AND_43))), CAST(32, MSB(CAST(16, MSB(op_AND_51), DUP(op_AND_51))), CAST(16, MSB(DUP(op_AND_51)), DUP(op_AND_51))));
	RzILOpPure *op_EQ_57 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_31), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_55), DUP(op_ADD_55)));
	RzILOpPure *op_RSHIFT_83 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_86 = LOGAND(op_RSHIFT_83, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_98 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_86), DUP(op_AND_86))), CAST(16, MSB(DUP(op_AND_86)), DUP(op_AND_86))), CAST(32, MSB(CAST(16, MSB(op_AND_94), DUP(op_AND_94))), CAST(16, MSB(DUP(op_AND_94)), DUP(op_AND_94))));
	RzILOpPure *op_LT_100 = SLT(op_ADD_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_105 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_106 = NEG(op_LSHIFT_105);
	RzILOpPure *op_LSHIFT_111 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_114 = SUB(op_LSHIFT_111, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_115 = ITE(op_LT_100, op_NEG_106, op_SUB_114);
	RzILOpEffect *gcc_expr_116 = BRANCH(op_EQ_57, EMPTY(), set_usr_field_call_79);

	// h_tmp584 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_118 = SETL("h_tmp584", cond_115);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_119 = SEQN(2, gcc_expr_116, op_ASSIGN_hybrid_tmp_118);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))) : h_tmp584) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_61, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_76 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_64), DUP(op_AND_64))), CAST(16, MSB(DUP(op_AND_64)), DUP(op_AND_64))), CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))));
	RzILOpPure *cond_121 = ITE(DUP(op_EQ_57), CAST(64, MSB(op_ADD_76), DUP(op_ADD_76)), VARL("h_tmp584"));
	RzILOpPure *op_AND_124 = LOGAND(cond_121, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_129 = SHIFTL0(CAST(64, IL_FALSE, op_AND_124), SN(32, 0));
	RzILOpPure *op_OR_131 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_129);
	RzILOpEffect *op_ASSIGN_133 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_131));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_134 = SEQN(2, seq_119, op_ASSIGN_133);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_212 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_149 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_152 = LOGAND(op_RSHIFT_149, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_160 = LOGAND(op_RSHIFT_157, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_164 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_152), DUP(op_AND_152))), CAST(16, MSB(DUP(op_AND_152)), DUP(op_AND_152))), CAST(32, MSB(CAST(16, MSB(op_AND_160), DUP(op_AND_160))), CAST(16, MSB(DUP(op_AND_160)), DUP(op_AND_160))));
	RzILOpPure *op_RSHIFT_173 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_176 = LOGAND(op_RSHIFT_173, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_181 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_184 = LOGAND(op_RSHIFT_181, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_188 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_176), DUP(op_AND_176))), CAST(16, MSB(DUP(op_AND_176)), DUP(op_AND_176))), CAST(32, MSB(CAST(16, MSB(op_AND_184), DUP(op_AND_184))), CAST(16, MSB(DUP(op_AND_184)), DUP(op_AND_184))));
	RzILOpPure *op_EQ_190 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_164), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_188), DUP(op_SUB_188)));
	RzILOpPure *op_RSHIFT_216 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_219 = LOGAND(op_RSHIFT_216, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_224 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_227 = LOGAND(op_RSHIFT_224, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_231 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_219), DUP(op_AND_219))), CAST(16, MSB(DUP(op_AND_219)), DUP(op_AND_219))), CAST(32, MSB(CAST(16, MSB(op_AND_227), DUP(op_AND_227))), CAST(16, MSB(DUP(op_AND_227)), DUP(op_AND_227))));
	RzILOpPure *op_LT_233 = SLT(op_SUB_231, SN(32, 0));
	RzILOpPure *op_LSHIFT_238 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_239 = NEG(op_LSHIFT_238);
	RzILOpPure *op_LSHIFT_244 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_247 = SUB(op_LSHIFT_244, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_248 = ITE(op_LT_233, op_NEG_239, op_SUB_247);
	RzILOpEffect *gcc_expr_249 = BRANCH(op_EQ_190, EMPTY(), set_usr_field_call_212);

	// h_tmp585 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_251 = SETL("h_tmp585", cond_248);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_252 = SEQN(2, gcc_expr_249, op_ASSIGN_hybrid_tmp_251);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))) : h_tmp585) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_140 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_141 = LOGNOT(op_LSHIFT_140);
	RzILOpPure *op_AND_142 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_141);
	RzILOpPure *op_RSHIFT_194 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_197 = LOGAND(op_RSHIFT_194, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_202 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_205 = LOGAND(op_RSHIFT_202, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_209 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_197), DUP(op_AND_197))), CAST(16, MSB(DUP(op_AND_197)), DUP(op_AND_197))), CAST(32, MSB(CAST(16, MSB(op_AND_205), DUP(op_AND_205))), CAST(16, MSB(DUP(op_AND_205)), DUP(op_AND_205))));
	RzILOpPure *cond_254 = ITE(DUP(op_EQ_190), CAST(64, MSB(op_SUB_209), DUP(op_SUB_209)), VARL("h_tmp585"));
	RzILOpPure *op_AND_257 = LOGAND(cond_254, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_262 = SHIFTL0(CAST(64, IL_FALSE, op_AND_257), SN(32, 16));
	RzILOpPure *op_OR_264 = LOGOR(CAST(64, IL_FALSE, op_AND_142), op_LSHIFT_262);
	RzILOpEffect *op_ASSIGN_266 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_264));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_267 = SEQN(2, seq_252, op_ASSIGN_266);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_345 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_282 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_285 = LOGAND(op_RSHIFT_282, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_290 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_293 = LOGAND(op_RSHIFT_290, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_297 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_285), DUP(op_AND_285))), CAST(16, MSB(DUP(op_AND_285)), DUP(op_AND_285))), CAST(32, MSB(CAST(16, MSB(op_AND_293), DUP(op_AND_293))), CAST(16, MSB(DUP(op_AND_293)), DUP(op_AND_293))));
	RzILOpPure *op_RSHIFT_306 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_309 = LOGAND(op_RSHIFT_306, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_314 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_317 = LOGAND(op_RSHIFT_314, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_321 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_309), DUP(op_AND_309))), CAST(16, MSB(DUP(op_AND_309)), DUP(op_AND_309))), CAST(32, MSB(CAST(16, MSB(op_AND_317), DUP(op_AND_317))), CAST(16, MSB(DUP(op_AND_317)), DUP(op_AND_317))));
	RzILOpPure *op_EQ_323 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_297), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_321), DUP(op_ADD_321)));
	RzILOpPure *op_RSHIFT_349 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_352 = LOGAND(op_RSHIFT_349, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_357 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_360 = LOGAND(op_RSHIFT_357, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_364 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_352), DUP(op_AND_352))), CAST(16, MSB(DUP(op_AND_352)), DUP(op_AND_352))), CAST(32, MSB(CAST(16, MSB(op_AND_360), DUP(op_AND_360))), CAST(16, MSB(DUP(op_AND_360)), DUP(op_AND_360))));
	RzILOpPure *op_LT_366 = SLT(op_ADD_364, SN(32, 0));
	RzILOpPure *op_LSHIFT_371 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_372 = NEG(op_LSHIFT_371);
	RzILOpPure *op_LSHIFT_377 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_380 = SUB(op_LSHIFT_377, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_381 = ITE(op_LT_366, op_NEG_372, op_SUB_380);
	RzILOpEffect *gcc_expr_382 = BRANCH(op_EQ_323, EMPTY(), set_usr_field_call_345);

	// h_tmp586 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_384 = SETL("h_tmp586", cond_381);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_385 = SEQN(2, gcc_expr_382, op_ASSIGN_hybrid_tmp_384);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))) : h_tmp586) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_273 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_274 = LOGNOT(op_LSHIFT_273);
	RzILOpPure *op_AND_275 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_274);
	RzILOpPure *op_RSHIFT_327 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_330 = LOGAND(op_RSHIFT_327, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_335 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_338 = LOGAND(op_RSHIFT_335, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_342 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_330), DUP(op_AND_330))), CAST(16, MSB(DUP(op_AND_330)), DUP(op_AND_330))), CAST(32, MSB(CAST(16, MSB(op_AND_338), DUP(op_AND_338))), CAST(16, MSB(DUP(op_AND_338)), DUP(op_AND_338))));
	RzILOpPure *cond_387 = ITE(DUP(op_EQ_323), CAST(64, MSB(op_ADD_342), DUP(op_ADD_342)), VARL("h_tmp586"));
	RzILOpPure *op_AND_390 = LOGAND(cond_387, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_395 = SHIFTL0(CAST(64, IL_FALSE, op_AND_390), SN(32, 0x20));
	RzILOpPure *op_OR_397 = LOGOR(CAST(64, IL_FALSE, op_AND_275), op_LSHIFT_395);
	RzILOpEffect *op_ASSIGN_399 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_397));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_400 = SEQN(2, seq_385, op_ASSIGN_399);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_478 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_415 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_418 = LOGAND(op_RSHIFT_415, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_423 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_426 = LOGAND(op_RSHIFT_423, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_430 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_418), DUP(op_AND_418))), CAST(16, MSB(DUP(op_AND_418)), DUP(op_AND_418))), CAST(32, MSB(CAST(16, MSB(op_AND_426), DUP(op_AND_426))), CAST(16, MSB(DUP(op_AND_426)), DUP(op_AND_426))));
	RzILOpPure *op_RSHIFT_439 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_442 = LOGAND(op_RSHIFT_439, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_447 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_450 = LOGAND(op_RSHIFT_447, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_454 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_442), DUP(op_AND_442))), CAST(16, MSB(DUP(op_AND_442)), DUP(op_AND_442))), CAST(32, MSB(CAST(16, MSB(op_AND_450), DUP(op_AND_450))), CAST(16, MSB(DUP(op_AND_450)), DUP(op_AND_450))));
	RzILOpPure *op_EQ_456 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_430), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_454), DUP(op_SUB_454)));
	RzILOpPure *op_RSHIFT_482 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_485 = LOGAND(op_RSHIFT_482, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_490 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_493 = LOGAND(op_RSHIFT_490, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_497 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_485), DUP(op_AND_485))), CAST(16, MSB(DUP(op_AND_485)), DUP(op_AND_485))), CAST(32, MSB(CAST(16, MSB(op_AND_493), DUP(op_AND_493))), CAST(16, MSB(DUP(op_AND_493)), DUP(op_AND_493))));
	RzILOpPure *op_LT_499 = SLT(op_SUB_497, SN(32, 0));
	RzILOpPure *op_LSHIFT_504 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_505 = NEG(op_LSHIFT_504);
	RzILOpPure *op_LSHIFT_510 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_513 = SUB(op_LSHIFT_510, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_514 = ITE(op_LT_499, op_NEG_505, op_SUB_513);
	RzILOpEffect *gcc_expr_515 = BRANCH(op_EQ_456, EMPTY(), set_usr_field_call_478);

	// h_tmp587 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_517 = SETL("h_tmp587", cond_514);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_518 = SEQN(2, gcc_expr_515, op_ASSIGN_hybrid_tmp_517);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))) : h_tmp587) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_406 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_407 = LOGNOT(op_LSHIFT_406);
	RzILOpPure *op_AND_408 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_407);
	RzILOpPure *op_RSHIFT_460 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_463 = LOGAND(op_RSHIFT_460, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_468 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_471 = LOGAND(op_RSHIFT_468, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_475 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_463), DUP(op_AND_463))), CAST(16, MSB(DUP(op_AND_463)), DUP(op_AND_463))), CAST(32, MSB(CAST(16, MSB(op_AND_471), DUP(op_AND_471))), CAST(16, MSB(DUP(op_AND_471)), DUP(op_AND_471))));
	RzILOpPure *cond_520 = ITE(DUP(op_EQ_456), CAST(64, MSB(op_SUB_475), DUP(op_SUB_475)), VARL("h_tmp587"));
	RzILOpPure *op_AND_523 = LOGAND(cond_520, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_528 = SHIFTL0(CAST(64, IL_FALSE, op_AND_523), SN(32, 0x30));
	RzILOpPure *op_OR_530 = LOGOR(CAST(64, IL_FALSE, op_AND_408), op_LSHIFT_528);
	RzILOpEffect *op_ASSIGN_532 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_530));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_533 = SEQN(2, seq_518, op_ASSIGN_532);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_134, seq_267, seq_400, seq_533);
	return instruction_sequence;
}

// Rdd = vxaddsubh(Rss,Rtt):rnd:>>1:sat
RzILOpEffect *hex_il_op_s4_vxaddsubhr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_91 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, SN(32, 16));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_31 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(CAST(16, MSB(op_AND_27), DUP(op_AND_27))), CAST(16, MSB(DUP(op_AND_27)), DUP(op_AND_27))));
	RzILOpPure *op_ADD_33 = ADD(op_ADD_31, SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(op_ADD_33, SN(32, 1));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_59 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))), CAST(32, MSB(CAST(16, MSB(op_AND_55), DUP(op_AND_55))), CAST(16, MSB(DUP(op_AND_55)), DUP(op_AND_55))));
	RzILOpPure *op_ADD_61 = ADD(op_ADD_59, SN(32, 1));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(op_ADD_61, SN(32, 1));
	RzILOpPure *op_EQ_65 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_35), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_63), DUP(op_RSHIFT_63)));
	RzILOpPure *op_RSHIFT_95 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_98 = LOGAND(op_RSHIFT_95, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_103 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_106 = LOGAND(op_RSHIFT_103, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_110 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_98), DUP(op_AND_98))), CAST(16, MSB(DUP(op_AND_98)), DUP(op_AND_98))), CAST(32, MSB(CAST(16, MSB(op_AND_106), DUP(op_AND_106))), CAST(16, MSB(DUP(op_AND_106)), DUP(op_AND_106))));
	RzILOpPure *op_ADD_112 = ADD(op_ADD_110, SN(32, 1));
	RzILOpPure *op_RSHIFT_114 = SHIFTRA(op_ADD_112, SN(32, 1));
	RzILOpPure *op_LT_116 = SLT(op_RSHIFT_114, SN(32, 0));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_122 = NEG(op_LSHIFT_121);
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_130 = SUB(op_LSHIFT_127, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_131 = ITE(op_LT_116, op_NEG_122, op_SUB_130);
	RzILOpEffect *gcc_expr_132 = BRANCH(op_EQ_65, EMPTY(), set_usr_field_call_91);

	// h_tmp588 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_134 = SETL("h_tmp588", cond_131);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_135 = SEQN(2, gcc_expr_132, op_ASSIGN_hybrid_tmp_134);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp588) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_80 = LOGAND(op_RSHIFT_77, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_84 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_80), DUP(op_AND_80))), CAST(16, MSB(DUP(op_AND_80)), DUP(op_AND_80))));
	RzILOpPure *op_ADD_86 = ADD(op_ADD_84, SN(32, 1));
	RzILOpPure *op_RSHIFT_88 = SHIFTRA(op_ADD_86, SN(32, 1));
	RzILOpPure *cond_137 = ITE(DUP(op_EQ_65), CAST(64, MSB(op_RSHIFT_88), DUP(op_RSHIFT_88)), VARL("h_tmp588"));
	RzILOpPure *op_AND_140 = LOGAND(cond_137, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_145 = SHIFTL0(CAST(64, IL_FALSE, op_AND_140), SN(32, 0));
	RzILOpPure *op_OR_147 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_145);
	RzILOpEffect *op_ASSIGN_149 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_147));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_150 = SEQN(2, seq_135, op_ASSIGN_149);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_240 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_165 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_168 = LOGAND(op_RSHIFT_165, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_173 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_176 = LOGAND(op_RSHIFT_173, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_180 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_168), DUP(op_AND_168))), CAST(16, MSB(DUP(op_AND_168)), DUP(op_AND_168))), CAST(32, MSB(CAST(16, MSB(op_AND_176), DUP(op_AND_176))), CAST(16, MSB(DUP(op_AND_176)), DUP(op_AND_176))));
	RzILOpPure *op_ADD_182 = ADD(op_SUB_180, SN(32, 1));
	RzILOpPure *op_RSHIFT_184 = SHIFTRA(op_ADD_182, SN(32, 1));
	RzILOpPure *op_RSHIFT_193 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_196 = LOGAND(op_RSHIFT_193, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_201 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_204 = LOGAND(op_RSHIFT_201, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_208 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_196), DUP(op_AND_196))), CAST(16, MSB(DUP(op_AND_196)), DUP(op_AND_196))), CAST(32, MSB(CAST(16, MSB(op_AND_204), DUP(op_AND_204))), CAST(16, MSB(DUP(op_AND_204)), DUP(op_AND_204))));
	RzILOpPure *op_ADD_210 = ADD(op_SUB_208, SN(32, 1));
	RzILOpPure *op_RSHIFT_212 = SHIFTRA(op_ADD_210, SN(32, 1));
	RzILOpPure *op_EQ_214 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_184), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_212), DUP(op_RSHIFT_212)));
	RzILOpPure *op_RSHIFT_244 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_247 = LOGAND(op_RSHIFT_244, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_252 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_255 = LOGAND(op_RSHIFT_252, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_259 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_247), DUP(op_AND_247))), CAST(16, MSB(DUP(op_AND_247)), DUP(op_AND_247))), CAST(32, MSB(CAST(16, MSB(op_AND_255), DUP(op_AND_255))), CAST(16, MSB(DUP(op_AND_255)), DUP(op_AND_255))));
	RzILOpPure *op_ADD_261 = ADD(op_SUB_259, SN(32, 1));
	RzILOpPure *op_RSHIFT_263 = SHIFTRA(op_ADD_261, SN(32, 1));
	RzILOpPure *op_LT_265 = SLT(op_RSHIFT_263, SN(32, 0));
	RzILOpPure *op_LSHIFT_270 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_271 = NEG(op_LSHIFT_270);
	RzILOpPure *op_LSHIFT_276 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_279 = SUB(op_LSHIFT_276, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_280 = ITE(op_LT_265, op_NEG_271, op_SUB_279);
	RzILOpEffect *gcc_expr_281 = BRANCH(op_EQ_214, EMPTY(), set_usr_field_call_240);

	// h_tmp589 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_283 = SETL("h_tmp589", cond_280);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_284 = SEQN(2, gcc_expr_281, op_ASSIGN_hybrid_tmp_283);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp589) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_156 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_157 = LOGNOT(op_LSHIFT_156);
	RzILOpPure *op_AND_158 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_157);
	RzILOpPure *op_RSHIFT_218 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_221 = LOGAND(op_RSHIFT_218, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_226 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_229 = LOGAND(op_RSHIFT_226, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_233 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_221), DUP(op_AND_221))), CAST(16, MSB(DUP(op_AND_221)), DUP(op_AND_221))), CAST(32, MSB(CAST(16, MSB(op_AND_229), DUP(op_AND_229))), CAST(16, MSB(DUP(op_AND_229)), DUP(op_AND_229))));
	RzILOpPure *op_ADD_235 = ADD(op_SUB_233, SN(32, 1));
	RzILOpPure *op_RSHIFT_237 = SHIFTRA(op_ADD_235, SN(32, 1));
	RzILOpPure *cond_286 = ITE(DUP(op_EQ_214), CAST(64, MSB(op_RSHIFT_237), DUP(op_RSHIFT_237)), VARL("h_tmp589"));
	RzILOpPure *op_AND_289 = LOGAND(cond_286, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_294 = SHIFTL0(CAST(64, IL_FALSE, op_AND_289), SN(32, 16));
	RzILOpPure *op_OR_296 = LOGOR(CAST(64, IL_FALSE, op_AND_158), op_LSHIFT_294);
	RzILOpEffect *op_ASSIGN_298 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_296));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_299 = SEQN(2, seq_284, op_ASSIGN_298);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_389 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_314 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_317 = LOGAND(op_RSHIFT_314, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_322 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_325 = LOGAND(op_RSHIFT_322, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_329 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_317), DUP(op_AND_317))), CAST(16, MSB(DUP(op_AND_317)), DUP(op_AND_317))), CAST(32, MSB(CAST(16, MSB(op_AND_325), DUP(op_AND_325))), CAST(16, MSB(DUP(op_AND_325)), DUP(op_AND_325))));
	RzILOpPure *op_ADD_331 = ADD(op_ADD_329, SN(32, 1));
	RzILOpPure *op_RSHIFT_333 = SHIFTRA(op_ADD_331, SN(32, 1));
	RzILOpPure *op_RSHIFT_342 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_345 = LOGAND(op_RSHIFT_342, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_350 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_353 = LOGAND(op_RSHIFT_350, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_357 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_345), DUP(op_AND_345))), CAST(16, MSB(DUP(op_AND_345)), DUP(op_AND_345))), CAST(32, MSB(CAST(16, MSB(op_AND_353), DUP(op_AND_353))), CAST(16, MSB(DUP(op_AND_353)), DUP(op_AND_353))));
	RzILOpPure *op_ADD_359 = ADD(op_ADD_357, SN(32, 1));
	RzILOpPure *op_RSHIFT_361 = SHIFTRA(op_ADD_359, SN(32, 1));
	RzILOpPure *op_EQ_363 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_333), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_361), DUP(op_RSHIFT_361)));
	RzILOpPure *op_RSHIFT_393 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_396 = LOGAND(op_RSHIFT_393, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_401 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_404 = LOGAND(op_RSHIFT_401, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_408 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_396), DUP(op_AND_396))), CAST(16, MSB(DUP(op_AND_396)), DUP(op_AND_396))), CAST(32, MSB(CAST(16, MSB(op_AND_404), DUP(op_AND_404))), CAST(16, MSB(DUP(op_AND_404)), DUP(op_AND_404))));
	RzILOpPure *op_ADD_410 = ADD(op_ADD_408, SN(32, 1));
	RzILOpPure *op_RSHIFT_412 = SHIFTRA(op_ADD_410, SN(32, 1));
	RzILOpPure *op_LT_414 = SLT(op_RSHIFT_412, SN(32, 0));
	RzILOpPure *op_LSHIFT_419 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_420 = NEG(op_LSHIFT_419);
	RzILOpPure *op_LSHIFT_425 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_428 = SUB(op_LSHIFT_425, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_429 = ITE(op_LT_414, op_NEG_420, op_SUB_428);
	RzILOpEffect *gcc_expr_430 = BRANCH(op_EQ_363, EMPTY(), set_usr_field_call_389);

	// h_tmp590 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_432 = SETL("h_tmp590", cond_429);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_433 = SEQN(2, gcc_expr_430, op_ASSIGN_hybrid_tmp_432);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp590) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_305 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_306 = LOGNOT(op_LSHIFT_305);
	RzILOpPure *op_AND_307 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_306);
	RzILOpPure *op_RSHIFT_367 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_370 = LOGAND(op_RSHIFT_367, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_375 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_378 = LOGAND(op_RSHIFT_375, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_382 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_370), DUP(op_AND_370))), CAST(16, MSB(DUP(op_AND_370)), DUP(op_AND_370))), CAST(32, MSB(CAST(16, MSB(op_AND_378), DUP(op_AND_378))), CAST(16, MSB(DUP(op_AND_378)), DUP(op_AND_378))));
	RzILOpPure *op_ADD_384 = ADD(op_ADD_382, SN(32, 1));
	RzILOpPure *op_RSHIFT_386 = SHIFTRA(op_ADD_384, SN(32, 1));
	RzILOpPure *cond_435 = ITE(DUP(op_EQ_363), CAST(64, MSB(op_RSHIFT_386), DUP(op_RSHIFT_386)), VARL("h_tmp590"));
	RzILOpPure *op_AND_438 = LOGAND(cond_435, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_443 = SHIFTL0(CAST(64, IL_FALSE, op_AND_438), SN(32, 0x20));
	RzILOpPure *op_OR_445 = LOGOR(CAST(64, IL_FALSE, op_AND_307), op_LSHIFT_443);
	RzILOpEffect *op_ASSIGN_447 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_445));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_448 = SEQN(2, seq_433, op_ASSIGN_447);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_538 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_463 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_466 = LOGAND(op_RSHIFT_463, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_471 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_474 = LOGAND(op_RSHIFT_471, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_478 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_466), DUP(op_AND_466))), CAST(16, MSB(DUP(op_AND_466)), DUP(op_AND_466))), CAST(32, MSB(CAST(16, MSB(op_AND_474), DUP(op_AND_474))), CAST(16, MSB(DUP(op_AND_474)), DUP(op_AND_474))));
	RzILOpPure *op_ADD_480 = ADD(op_SUB_478, SN(32, 1));
	RzILOpPure *op_RSHIFT_482 = SHIFTRA(op_ADD_480, SN(32, 1));
	RzILOpPure *op_RSHIFT_491 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_494 = LOGAND(op_RSHIFT_491, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_499 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_502 = LOGAND(op_RSHIFT_499, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_506 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_494), DUP(op_AND_494))), CAST(16, MSB(DUP(op_AND_494)), DUP(op_AND_494))), CAST(32, MSB(CAST(16, MSB(op_AND_502), DUP(op_AND_502))), CAST(16, MSB(DUP(op_AND_502)), DUP(op_AND_502))));
	RzILOpPure *op_ADD_508 = ADD(op_SUB_506, SN(32, 1));
	RzILOpPure *op_RSHIFT_510 = SHIFTRA(op_ADD_508, SN(32, 1));
	RzILOpPure *op_EQ_512 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_482), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_510), DUP(op_RSHIFT_510)));
	RzILOpPure *op_RSHIFT_542 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_545 = LOGAND(op_RSHIFT_542, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_550 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_553 = LOGAND(op_RSHIFT_550, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_557 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_545), DUP(op_AND_545))), CAST(16, MSB(DUP(op_AND_545)), DUP(op_AND_545))), CAST(32, MSB(CAST(16, MSB(op_AND_553), DUP(op_AND_553))), CAST(16, MSB(DUP(op_AND_553)), DUP(op_AND_553))));
	RzILOpPure *op_ADD_559 = ADD(op_SUB_557, SN(32, 1));
	RzILOpPure *op_RSHIFT_561 = SHIFTRA(op_ADD_559, SN(32, 1));
	RzILOpPure *op_LT_563 = SLT(op_RSHIFT_561, SN(32, 0));
	RzILOpPure *op_LSHIFT_568 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_569 = NEG(op_LSHIFT_568);
	RzILOpPure *op_LSHIFT_574 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_577 = SUB(op_LSHIFT_574, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_578 = ITE(op_LT_563, op_NEG_569, op_SUB_577);
	RzILOpEffect *gcc_expr_579 = BRANCH(op_EQ_512, EMPTY(), set_usr_field_call_538);

	// h_tmp591 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_581 = SETL("h_tmp591", cond_578);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_582 = SEQN(2, gcc_expr_579, op_ASSIGN_hybrid_tmp_581);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp591) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_454 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_455 = LOGNOT(op_LSHIFT_454);
	RzILOpPure *op_AND_456 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_455);
	RzILOpPure *op_RSHIFT_516 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_519 = LOGAND(op_RSHIFT_516, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_524 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_527 = LOGAND(op_RSHIFT_524, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_531 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_519), DUP(op_AND_519))), CAST(16, MSB(DUP(op_AND_519)), DUP(op_AND_519))), CAST(32, MSB(CAST(16, MSB(op_AND_527), DUP(op_AND_527))), CAST(16, MSB(DUP(op_AND_527)), DUP(op_AND_527))));
	RzILOpPure *op_ADD_533 = ADD(op_SUB_531, SN(32, 1));
	RzILOpPure *op_RSHIFT_535 = SHIFTRA(op_ADD_533, SN(32, 1));
	RzILOpPure *cond_584 = ITE(DUP(op_EQ_512), CAST(64, MSB(op_RSHIFT_535), DUP(op_RSHIFT_535)), VARL("h_tmp591"));
	RzILOpPure *op_AND_587 = LOGAND(cond_584, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_592 = SHIFTL0(CAST(64, IL_FALSE, op_AND_587), SN(32, 0x30));
	RzILOpPure *op_OR_594 = LOGOR(CAST(64, IL_FALSE, op_AND_456), op_LSHIFT_592);
	RzILOpEffect *op_ASSIGN_596 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_594));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_597 = SEQN(2, seq_582, op_ASSIGN_596);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_150, seq_299, seq_448, seq_597);
	return instruction_sequence;
}

// Rdd = vxaddsubw(Rss,Rtt):sat
RzILOpEffect *hex_il_op_s4_vxaddsubw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_72 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_24, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_29 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_17), DUP(op_AND_17))), CAST(32, MSB(DUP(op_AND_17)), DUP(op_AND_17))), CAST(64, MSB(CAST(32, MSB(op_AND_26), DUP(op_AND_26))), CAST(32, MSB(DUP(op_AND_26)), DUP(op_AND_26))));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_46 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_46, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_51 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40))), CAST(64, MSB(CAST(32, MSB(op_AND_48), DUP(op_AND_48))), CAST(32, MSB(DUP(op_AND_48)), DUP(op_AND_48))));
	RzILOpPure *op_EQ_52 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_29), SN(32, 0), SN(32, 0x20)), op_ADD_51);
	RzILOpPure *op_RSHIFT_76 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_78 = LOGAND(op_RSHIFT_76, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_86 = LOGAND(op_RSHIFT_84, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_89 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_78), DUP(op_AND_78))), CAST(32, MSB(DUP(op_AND_78)), DUP(op_AND_78))), CAST(64, MSB(CAST(32, MSB(op_AND_86), DUP(op_AND_86))), CAST(32, MSB(DUP(op_AND_86)), DUP(op_AND_86))));
	RzILOpPure *op_LT_92 = SLT(op_ADD_89, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_97 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_98 = NEG(op_LSHIFT_97);
	RzILOpPure *op_LSHIFT_103 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_106 = SUB(op_LSHIFT_103, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_107 = ITE(op_LT_92, op_NEG_98, op_SUB_106);
	RzILOpEffect *gcc_expr_108 = BRANCH(op_EQ_52, EMPTY(), set_usr_field_call_72);

	// h_tmp592 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_110 = SETL("h_tmp592", cond_107);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_111 = SEQN(2, gcc_expr_108, op_ASSIGN_hybrid_tmp_110);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))) : h_tmp592) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_56, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_66 = LOGAND(op_RSHIFT_64, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_69 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_58), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))), CAST(64, MSB(CAST(32, MSB(op_AND_66), DUP(op_AND_66))), CAST(32, MSB(DUP(op_AND_66)), DUP(op_AND_66))));
	RzILOpPure *cond_112 = ITE(DUP(op_EQ_52), op_ADD_69, VARL("h_tmp592"));
	RzILOpPure *op_AND_114 = LOGAND(cond_112, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_118 = SHIFTL0(op_AND_114, SN(32, 0));
	RzILOpPure *op_OR_119 = LOGOR(op_AND_7, op_LSHIFT_118);
	RzILOpEffect *op_ASSIGN_120 = WRITE_REG(bundle, Rdd_op, op_OR_119);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_121 = SEQN(2, seq_111, op_ASSIGN_120);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_192 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_136 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_138 = LOGAND(op_RSHIFT_136, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_146 = LOGAND(op_RSHIFT_144, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_149 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_138), DUP(op_AND_138))), CAST(32, MSB(DUP(op_AND_138)), DUP(op_AND_138))), CAST(64, MSB(CAST(32, MSB(op_AND_146), DUP(op_AND_146))), CAST(32, MSB(DUP(op_AND_146)), DUP(op_AND_146))));
	RzILOpPure *op_RSHIFT_158 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_160 = LOGAND(op_RSHIFT_158, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_166 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_168 = LOGAND(op_RSHIFT_166, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_171 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_160), DUP(op_AND_160))), CAST(32, MSB(DUP(op_AND_160)), DUP(op_AND_160))), CAST(64, MSB(CAST(32, MSB(op_AND_168), DUP(op_AND_168))), CAST(32, MSB(DUP(op_AND_168)), DUP(op_AND_168))));
	RzILOpPure *op_EQ_172 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_149), SN(32, 0), SN(32, 0x20)), op_SUB_171);
	RzILOpPure *op_RSHIFT_196 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_198 = LOGAND(op_RSHIFT_196, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_204 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_206 = LOGAND(op_RSHIFT_204, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_209 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_198), DUP(op_AND_198))), CAST(32, MSB(DUP(op_AND_198)), DUP(op_AND_198))), CAST(64, MSB(CAST(32, MSB(op_AND_206), DUP(op_AND_206))), CAST(32, MSB(DUP(op_AND_206)), DUP(op_AND_206))));
	RzILOpPure *op_LT_212 = SLT(op_SUB_209, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_217 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_218 = NEG(op_LSHIFT_217);
	RzILOpPure *op_LSHIFT_223 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_226 = SUB(op_LSHIFT_223, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_227 = ITE(op_LT_212, op_NEG_218, op_SUB_226);
	RzILOpEffect *gcc_expr_228 = BRANCH(op_EQ_172, EMPTY(), set_usr_field_call_192);

	// h_tmp593 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_230 = SETL("h_tmp593", cond_227);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_231 = SEQN(2, gcc_expr_228, op_ASSIGN_hybrid_tmp_230);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))) : h_tmp593) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_128 = LOGNOT(op_LSHIFT_127);
	RzILOpPure *op_AND_129 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_128);
	RzILOpPure *op_RSHIFT_176 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_178 = LOGAND(op_RSHIFT_176, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_184 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_186 = LOGAND(op_RSHIFT_184, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_189 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_178), DUP(op_AND_178))), CAST(32, MSB(DUP(op_AND_178)), DUP(op_AND_178))), CAST(64, MSB(CAST(32, MSB(op_AND_186), DUP(op_AND_186))), CAST(32, MSB(DUP(op_AND_186)), DUP(op_AND_186))));
	RzILOpPure *cond_232 = ITE(DUP(op_EQ_172), op_SUB_189, VARL("h_tmp593"));
	RzILOpPure *op_AND_234 = LOGAND(cond_232, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_238 = SHIFTL0(op_AND_234, SN(32, 0x20));
	RzILOpPure *op_OR_239 = LOGOR(op_AND_129, op_LSHIFT_238);
	RzILOpEffect *op_ASSIGN_240 = WRITE_REG(bundle, Rdd_op, op_OR_239);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_241 = SEQN(2, seq_231, op_ASSIGN_240);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_121, seq_241);
	return instruction_sequence;
}

// Rdd = vxsubaddh(Rss,Rtt):sat
RzILOpEffect *hex_il_op_s4_vxsubaddh(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_79 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, SN(32, 16));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_31 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(CAST(16, MSB(op_AND_27), DUP(op_AND_27))), CAST(16, MSB(DUP(op_AND_27)), DUP(op_AND_27))));
	RzILOpPure *op_RSHIFT_40 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_43 = LOGAND(op_RSHIFT_40, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_48 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_51 = LOGAND(op_RSHIFT_48, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_55 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_43), DUP(op_AND_43))), CAST(16, MSB(DUP(op_AND_43)), DUP(op_AND_43))), CAST(32, MSB(CAST(16, MSB(op_AND_51), DUP(op_AND_51))), CAST(16, MSB(DUP(op_AND_51)), DUP(op_AND_51))));
	RzILOpPure *op_EQ_57 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_31), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_55), DUP(op_SUB_55)));
	RzILOpPure *op_RSHIFT_83 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_86 = LOGAND(op_RSHIFT_83, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_91 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_94 = LOGAND(op_RSHIFT_91, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_98 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_86), DUP(op_AND_86))), CAST(16, MSB(DUP(op_AND_86)), DUP(op_AND_86))), CAST(32, MSB(CAST(16, MSB(op_AND_94), DUP(op_AND_94))), CAST(16, MSB(DUP(op_AND_94)), DUP(op_AND_94))));
	RzILOpPure *op_LT_100 = SLT(op_SUB_98, SN(32, 0));
	RzILOpPure *op_LSHIFT_105 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_106 = NEG(op_LSHIFT_105);
	RzILOpPure *op_LSHIFT_111 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_114 = SUB(op_LSHIFT_111, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_115 = ITE(op_LT_100, op_NEG_106, op_SUB_114);
	RzILOpEffect *gcc_expr_116 = BRANCH(op_EQ_57, EMPTY(), set_usr_field_call_79);

	// h_tmp594 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_118 = SETL("h_tmp594", cond_115);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_119 = SEQN(2, gcc_expr_116, op_ASSIGN_hybrid_tmp_118);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff))))) : h_tmp594) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_61 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_64 = LOGAND(op_RSHIFT_61, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_76 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_64), DUP(op_AND_64))), CAST(16, MSB(DUP(op_AND_64)), DUP(op_AND_64))), CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))));
	RzILOpPure *cond_121 = ITE(DUP(op_EQ_57), CAST(64, MSB(op_SUB_76), DUP(op_SUB_76)), VARL("h_tmp594"));
	RzILOpPure *op_AND_124 = LOGAND(cond_121, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_129 = SHIFTL0(CAST(64, IL_FALSE, op_AND_124), SN(32, 0));
	RzILOpPure *op_OR_131 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_129);
	RzILOpEffect *op_ASSIGN_133 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_131));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_134 = SEQN(2, seq_119, op_ASSIGN_133);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_212 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_149 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_152 = LOGAND(op_RSHIFT_149, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_157 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_160 = LOGAND(op_RSHIFT_157, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_164 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_152), DUP(op_AND_152))), CAST(16, MSB(DUP(op_AND_152)), DUP(op_AND_152))), CAST(32, MSB(CAST(16, MSB(op_AND_160), DUP(op_AND_160))), CAST(16, MSB(DUP(op_AND_160)), DUP(op_AND_160))));
	RzILOpPure *op_RSHIFT_173 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_176 = LOGAND(op_RSHIFT_173, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_181 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_184 = LOGAND(op_RSHIFT_181, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_188 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_176), DUP(op_AND_176))), CAST(16, MSB(DUP(op_AND_176)), DUP(op_AND_176))), CAST(32, MSB(CAST(16, MSB(op_AND_184), DUP(op_AND_184))), CAST(16, MSB(DUP(op_AND_184)), DUP(op_AND_184))));
	RzILOpPure *op_EQ_190 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_164), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_188), DUP(op_ADD_188)));
	RzILOpPure *op_RSHIFT_216 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_219 = LOGAND(op_RSHIFT_216, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_224 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_227 = LOGAND(op_RSHIFT_224, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_231 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_219), DUP(op_AND_219))), CAST(16, MSB(DUP(op_AND_219)), DUP(op_AND_219))), CAST(32, MSB(CAST(16, MSB(op_AND_227), DUP(op_AND_227))), CAST(16, MSB(DUP(op_AND_227)), DUP(op_AND_227))));
	RzILOpPure *op_LT_233 = SLT(op_ADD_231, SN(32, 0));
	RzILOpPure *op_LSHIFT_238 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_239 = NEG(op_LSHIFT_238);
	RzILOpPure *op_LSHIFT_244 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_247 = SUB(op_LSHIFT_244, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_248 = ITE(op_LT_233, op_NEG_239, op_SUB_247);
	RzILOpEffect *gcc_expr_249 = BRANCH(op_EQ_190, EMPTY(), set_usr_field_call_212);

	// h_tmp595 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_251 = SETL("h_tmp595", cond_248);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_252 = SEQN(2, gcc_expr_249, op_ASSIGN_hybrid_tmp_251);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff))))) : h_tmp595) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_140 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_141 = LOGNOT(op_LSHIFT_140);
	RzILOpPure *op_AND_142 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_141);
	RzILOpPure *op_RSHIFT_194 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_197 = LOGAND(op_RSHIFT_194, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_202 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_205 = LOGAND(op_RSHIFT_202, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_209 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_197), DUP(op_AND_197))), CAST(16, MSB(DUP(op_AND_197)), DUP(op_AND_197))), CAST(32, MSB(CAST(16, MSB(op_AND_205), DUP(op_AND_205))), CAST(16, MSB(DUP(op_AND_205)), DUP(op_AND_205))));
	RzILOpPure *cond_254 = ITE(DUP(op_EQ_190), CAST(64, MSB(op_ADD_209), DUP(op_ADD_209)), VARL("h_tmp595"));
	RzILOpPure *op_AND_257 = LOGAND(cond_254, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_262 = SHIFTL0(CAST(64, IL_FALSE, op_AND_257), SN(32, 16));
	RzILOpPure *op_OR_264 = LOGOR(CAST(64, IL_FALSE, op_AND_142), op_LSHIFT_262);
	RzILOpEffect *op_ASSIGN_266 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_264));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_267 = SEQN(2, seq_252, op_ASSIGN_266);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_345 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_282 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_285 = LOGAND(op_RSHIFT_282, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_290 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_293 = LOGAND(op_RSHIFT_290, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_297 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_285), DUP(op_AND_285))), CAST(16, MSB(DUP(op_AND_285)), DUP(op_AND_285))), CAST(32, MSB(CAST(16, MSB(op_AND_293), DUP(op_AND_293))), CAST(16, MSB(DUP(op_AND_293)), DUP(op_AND_293))));
	RzILOpPure *op_RSHIFT_306 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_309 = LOGAND(op_RSHIFT_306, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_314 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_317 = LOGAND(op_RSHIFT_314, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_321 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_309), DUP(op_AND_309))), CAST(16, MSB(DUP(op_AND_309)), DUP(op_AND_309))), CAST(32, MSB(CAST(16, MSB(op_AND_317), DUP(op_AND_317))), CAST(16, MSB(DUP(op_AND_317)), DUP(op_AND_317))));
	RzILOpPure *op_EQ_323 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_297), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_SUB_321), DUP(op_SUB_321)));
	RzILOpPure *op_RSHIFT_349 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_352 = LOGAND(op_RSHIFT_349, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_357 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_360 = LOGAND(op_RSHIFT_357, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_364 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_352), DUP(op_AND_352))), CAST(16, MSB(DUP(op_AND_352)), DUP(op_AND_352))), CAST(32, MSB(CAST(16, MSB(op_AND_360), DUP(op_AND_360))), CAST(16, MSB(DUP(op_AND_360)), DUP(op_AND_360))));
	RzILOpPure *op_LT_366 = SLT(op_SUB_364, SN(32, 0));
	RzILOpPure *op_LSHIFT_371 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_372 = NEG(op_LSHIFT_371);
	RzILOpPure *op_LSHIFT_377 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_380 = SUB(op_LSHIFT_377, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_381 = ITE(op_LT_366, op_NEG_372, op_SUB_380);
	RzILOpEffect *gcc_expr_382 = BRANCH(op_EQ_323, EMPTY(), set_usr_field_call_345);

	// h_tmp596 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_384 = SETL("h_tmp596", cond_381);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_385 = SEQN(2, gcc_expr_382, op_ASSIGN_hybrid_tmp_384);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff))))) : h_tmp596) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_273 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_274 = LOGNOT(op_LSHIFT_273);
	RzILOpPure *op_AND_275 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_274);
	RzILOpPure *op_RSHIFT_327 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_330 = LOGAND(op_RSHIFT_327, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_335 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_338 = LOGAND(op_RSHIFT_335, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_342 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_330), DUP(op_AND_330))), CAST(16, MSB(DUP(op_AND_330)), DUP(op_AND_330))), CAST(32, MSB(CAST(16, MSB(op_AND_338), DUP(op_AND_338))), CAST(16, MSB(DUP(op_AND_338)), DUP(op_AND_338))));
	RzILOpPure *cond_387 = ITE(DUP(op_EQ_323), CAST(64, MSB(op_SUB_342), DUP(op_SUB_342)), VARL("h_tmp596"));
	RzILOpPure *op_AND_390 = LOGAND(cond_387, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_395 = SHIFTL0(CAST(64, IL_FALSE, op_AND_390), SN(32, 0x20));
	RzILOpPure *op_OR_397 = LOGOR(CAST(64, IL_FALSE, op_AND_275), op_LSHIFT_395);
	RzILOpEffect *op_ASSIGN_399 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_397));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_400 = SEQN(2, seq_385, op_ASSIGN_399);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_478 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_415 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_418 = LOGAND(op_RSHIFT_415, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_423 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_426 = LOGAND(op_RSHIFT_423, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_430 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_418), DUP(op_AND_418))), CAST(16, MSB(DUP(op_AND_418)), DUP(op_AND_418))), CAST(32, MSB(CAST(16, MSB(op_AND_426), DUP(op_AND_426))), CAST(16, MSB(DUP(op_AND_426)), DUP(op_AND_426))));
	RzILOpPure *op_RSHIFT_439 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_442 = LOGAND(op_RSHIFT_439, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_447 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_450 = LOGAND(op_RSHIFT_447, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_454 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_442), DUP(op_AND_442))), CAST(16, MSB(DUP(op_AND_442)), DUP(op_AND_442))), CAST(32, MSB(CAST(16, MSB(op_AND_450), DUP(op_AND_450))), CAST(16, MSB(DUP(op_AND_450)), DUP(op_AND_450))));
	RzILOpPure *op_EQ_456 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_430), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_ADD_454), DUP(op_ADD_454)));
	RzILOpPure *op_RSHIFT_482 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_485 = LOGAND(op_RSHIFT_482, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_490 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_493 = LOGAND(op_RSHIFT_490, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_497 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_485), DUP(op_AND_485))), CAST(16, MSB(DUP(op_AND_485)), DUP(op_AND_485))), CAST(32, MSB(CAST(16, MSB(op_AND_493), DUP(op_AND_493))), CAST(16, MSB(DUP(op_AND_493)), DUP(op_AND_493))));
	RzILOpPure *op_LT_499 = SLT(op_ADD_497, SN(32, 0));
	RzILOpPure *op_LSHIFT_504 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_505 = NEG(op_LSHIFT_504);
	RzILOpPure *op_LSHIFT_510 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_513 = SUB(op_LSHIFT_510, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_514 = ITE(op_LT_499, op_NEG_505, op_SUB_513);
	RzILOpEffect *gcc_expr_515 = BRANCH(op_EQ_456, EMPTY(), set_usr_field_call_478);

	// h_tmp597 = HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_517 = SETL("h_tmp597", cond_514);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((Rss > ...;
	RzILOpEffect *seq_518 = SEQN(2, gcc_expr_515, op_ASSIGN_hybrid_tmp_517);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))), 0x0, 0x10) == ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))))) ? ((st64) ((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff))))) : h_tmp597) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_406 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_407 = LOGNOT(op_LSHIFT_406);
	RzILOpPure *op_AND_408 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_407);
	RzILOpPure *op_RSHIFT_460 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_463 = LOGAND(op_RSHIFT_460, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_468 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_471 = LOGAND(op_RSHIFT_468, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_475 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_463), DUP(op_AND_463))), CAST(16, MSB(DUP(op_AND_463)), DUP(op_AND_463))), CAST(32, MSB(CAST(16, MSB(op_AND_471), DUP(op_AND_471))), CAST(16, MSB(DUP(op_AND_471)), DUP(op_AND_471))));
	RzILOpPure *cond_520 = ITE(DUP(op_EQ_456), CAST(64, MSB(op_ADD_475), DUP(op_ADD_475)), VARL("h_tmp597"));
	RzILOpPure *op_AND_523 = LOGAND(cond_520, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_528 = SHIFTL0(CAST(64, IL_FALSE, op_AND_523), SN(32, 0x30));
	RzILOpPure *op_OR_530 = LOGOR(CAST(64, IL_FALSE, op_AND_408), op_LSHIFT_528);
	RzILOpEffect *op_ASSIGN_532 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_530));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st32) ((st16) ((R ...;
	RzILOpEffect *seq_533 = SEQN(2, seq_518, op_ASSIGN_532);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_134, seq_267, seq_400, seq_533);
	return instruction_sequence;
}

// Rdd = vxsubaddh(Rss,Rtt):rnd:>>1:sat
RzILOpEffect *hex_il_op_s4_vxsubaddhr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_91 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_15, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, SN(32, 16));
	RzILOpPure *op_AND_27 = LOGAND(op_RSHIFT_24, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_31 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_18), DUP(op_AND_18))), CAST(16, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(CAST(16, MSB(op_AND_27), DUP(op_AND_27))), CAST(16, MSB(DUP(op_AND_27)), DUP(op_AND_27))));
	RzILOpPure *op_ADD_33 = ADD(op_SUB_31, SN(32, 1));
	RzILOpPure *op_RSHIFT_35 = SHIFTRA(op_ADD_33, SN(32, 1));
	RzILOpPure *op_RSHIFT_44 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_47 = LOGAND(op_RSHIFT_44, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_52 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_55 = LOGAND(op_RSHIFT_52, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_59 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_47), DUP(op_AND_47))), CAST(16, MSB(DUP(op_AND_47)), DUP(op_AND_47))), CAST(32, MSB(CAST(16, MSB(op_AND_55), DUP(op_AND_55))), CAST(16, MSB(DUP(op_AND_55)), DUP(op_AND_55))));
	RzILOpPure *op_ADD_61 = ADD(op_SUB_59, SN(32, 1));
	RzILOpPure *op_RSHIFT_63 = SHIFTRA(op_ADD_61, SN(32, 1));
	RzILOpPure *op_EQ_65 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_35), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_63), DUP(op_RSHIFT_63)));
	RzILOpPure *op_RSHIFT_95 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_98 = LOGAND(op_RSHIFT_95, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_103 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_106 = LOGAND(op_RSHIFT_103, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_110 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_98), DUP(op_AND_98))), CAST(16, MSB(DUP(op_AND_98)), DUP(op_AND_98))), CAST(32, MSB(CAST(16, MSB(op_AND_106), DUP(op_AND_106))), CAST(16, MSB(DUP(op_AND_106)), DUP(op_AND_106))));
	RzILOpPure *op_ADD_112 = ADD(op_SUB_110, SN(32, 1));
	RzILOpPure *op_RSHIFT_114 = SHIFTRA(op_ADD_112, SN(32, 1));
	RzILOpPure *op_LT_116 = SLT(op_RSHIFT_114, SN(32, 0));
	RzILOpPure *op_LSHIFT_121 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_122 = NEG(op_LSHIFT_121);
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_130 = SUB(op_LSHIFT_127, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_131 = ITE(op_LT_116, op_NEG_122, op_SUB_130);
	RzILOpEffect *gcc_expr_132 = BRANCH(op_EQ_65, EMPTY(), set_usr_field_call_91);

	// h_tmp598 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_134 = SETL("h_tmp598", cond_131);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_135 = SEQN(2, gcc_expr_132, op_ASSIGN_hybrid_tmp_134);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x0)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x0) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x10) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp598) & ((st64) 0xffff))) << 0x0)));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_69 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_72 = LOGAND(op_RSHIFT_69, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_77 = SHIFTRA(DUP(Rtt), SN(32, 16));
	RzILOpPure *op_AND_80 = LOGAND(op_RSHIFT_77, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_84 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_72), DUP(op_AND_72))), CAST(16, MSB(DUP(op_AND_72)), DUP(op_AND_72))), CAST(32, MSB(CAST(16, MSB(op_AND_80), DUP(op_AND_80))), CAST(16, MSB(DUP(op_AND_80)), DUP(op_AND_80))));
	RzILOpPure *op_ADD_86 = ADD(op_SUB_84, SN(32, 1));
	RzILOpPure *op_RSHIFT_88 = SHIFTRA(op_ADD_86, SN(32, 1));
	RzILOpPure *cond_137 = ITE(DUP(op_EQ_65), CAST(64, MSB(op_RSHIFT_88), DUP(op_RSHIFT_88)), VARL("h_tmp598"));
	RzILOpPure *op_AND_140 = LOGAND(cond_137, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_145 = SHIFTL0(CAST(64, IL_FALSE, op_AND_140), SN(32, 0));
	RzILOpPure *op_OR_147 = LOGOR(CAST(64, IL_FALSE, op_AND_7), op_LSHIFT_145);
	RzILOpEffect *op_ASSIGN_149 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_147));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_150 = SEQN(2, seq_135, op_ASSIGN_149);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_240 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_165 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_168 = LOGAND(op_RSHIFT_165, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_173 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_176 = LOGAND(op_RSHIFT_173, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_180 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_168), DUP(op_AND_168))), CAST(16, MSB(DUP(op_AND_168)), DUP(op_AND_168))), CAST(32, MSB(CAST(16, MSB(op_AND_176), DUP(op_AND_176))), CAST(16, MSB(DUP(op_AND_176)), DUP(op_AND_176))));
	RzILOpPure *op_ADD_182 = ADD(op_ADD_180, SN(32, 1));
	RzILOpPure *op_RSHIFT_184 = SHIFTRA(op_ADD_182, SN(32, 1));
	RzILOpPure *op_RSHIFT_193 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_196 = LOGAND(op_RSHIFT_193, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_201 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_204 = LOGAND(op_RSHIFT_201, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_208 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_196), DUP(op_AND_196))), CAST(16, MSB(DUP(op_AND_196)), DUP(op_AND_196))), CAST(32, MSB(CAST(16, MSB(op_AND_204), DUP(op_AND_204))), CAST(16, MSB(DUP(op_AND_204)), DUP(op_AND_204))));
	RzILOpPure *op_ADD_210 = ADD(op_ADD_208, SN(32, 1));
	RzILOpPure *op_RSHIFT_212 = SHIFTRA(op_ADD_210, SN(32, 1));
	RzILOpPure *op_EQ_214 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_184), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_212), DUP(op_RSHIFT_212)));
	RzILOpPure *op_RSHIFT_244 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_247 = LOGAND(op_RSHIFT_244, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_252 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_255 = LOGAND(op_RSHIFT_252, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_259 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_247), DUP(op_AND_247))), CAST(16, MSB(DUP(op_AND_247)), DUP(op_AND_247))), CAST(32, MSB(CAST(16, MSB(op_AND_255), DUP(op_AND_255))), CAST(16, MSB(DUP(op_AND_255)), DUP(op_AND_255))));
	RzILOpPure *op_ADD_261 = ADD(op_ADD_259, SN(32, 1));
	RzILOpPure *op_RSHIFT_263 = SHIFTRA(op_ADD_261, SN(32, 1));
	RzILOpPure *op_LT_265 = SLT(op_RSHIFT_263, SN(32, 0));
	RzILOpPure *op_LSHIFT_270 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_271 = NEG(op_LSHIFT_270);
	RzILOpPure *op_LSHIFT_276 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_279 = SUB(op_LSHIFT_276, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_280 = ITE(op_LT_265, op_NEG_271, op_SUB_279);
	RzILOpEffect *gcc_expr_281 = BRANCH(op_EQ_214, EMPTY(), set_usr_field_call_240);

	// h_tmp599 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_283 = SETL("h_tmp599", cond_280);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_284 = SEQN(2, gcc_expr_281, op_ASSIGN_hybrid_tmp_283);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x10)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x10) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x0) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp599) & ((st64) 0xffff))) << 0x10)));
	RzILOpPure *op_LSHIFT_156 = SHIFTL0(SN(64, 0xffff), SN(32, 16));
	RzILOpPure *op_NOT_157 = LOGNOT(op_LSHIFT_156);
	RzILOpPure *op_AND_158 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_157);
	RzILOpPure *op_RSHIFT_218 = SHIFTRA(DUP(Rss), SN(32, 16));
	RzILOpPure *op_AND_221 = LOGAND(op_RSHIFT_218, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_226 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_229 = LOGAND(op_RSHIFT_226, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_233 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_221), DUP(op_AND_221))), CAST(16, MSB(DUP(op_AND_221)), DUP(op_AND_221))), CAST(32, MSB(CAST(16, MSB(op_AND_229), DUP(op_AND_229))), CAST(16, MSB(DUP(op_AND_229)), DUP(op_AND_229))));
	RzILOpPure *op_ADD_235 = ADD(op_ADD_233, SN(32, 1));
	RzILOpPure *op_RSHIFT_237 = SHIFTRA(op_ADD_235, SN(32, 1));
	RzILOpPure *cond_286 = ITE(DUP(op_EQ_214), CAST(64, MSB(op_RSHIFT_237), DUP(op_RSHIFT_237)), VARL("h_tmp599"));
	RzILOpPure *op_AND_289 = LOGAND(cond_286, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_294 = SHIFTL0(CAST(64, IL_FALSE, op_AND_289), SN(32, 16));
	RzILOpPure *op_OR_296 = LOGOR(CAST(64, IL_FALSE, op_AND_158), op_LSHIFT_294);
	RzILOpEffect *op_ASSIGN_298 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_296));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_299 = SEQN(2, seq_284, op_ASSIGN_298);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_389 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_314 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_317 = LOGAND(op_RSHIFT_314, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_322 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_325 = LOGAND(op_RSHIFT_322, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_329 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_317), DUP(op_AND_317))), CAST(16, MSB(DUP(op_AND_317)), DUP(op_AND_317))), CAST(32, MSB(CAST(16, MSB(op_AND_325), DUP(op_AND_325))), CAST(16, MSB(DUP(op_AND_325)), DUP(op_AND_325))));
	RzILOpPure *op_ADD_331 = ADD(op_SUB_329, SN(32, 1));
	RzILOpPure *op_RSHIFT_333 = SHIFTRA(op_ADD_331, SN(32, 1));
	RzILOpPure *op_RSHIFT_342 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_345 = LOGAND(op_RSHIFT_342, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_350 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_353 = LOGAND(op_RSHIFT_350, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_357 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_345), DUP(op_AND_345))), CAST(16, MSB(DUP(op_AND_345)), DUP(op_AND_345))), CAST(32, MSB(CAST(16, MSB(op_AND_353), DUP(op_AND_353))), CAST(16, MSB(DUP(op_AND_353)), DUP(op_AND_353))));
	RzILOpPure *op_ADD_359 = ADD(op_SUB_357, SN(32, 1));
	RzILOpPure *op_RSHIFT_361 = SHIFTRA(op_ADD_359, SN(32, 1));
	RzILOpPure *op_EQ_363 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_333), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_361), DUP(op_RSHIFT_361)));
	RzILOpPure *op_RSHIFT_393 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_396 = LOGAND(op_RSHIFT_393, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_401 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_404 = LOGAND(op_RSHIFT_401, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_408 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_396), DUP(op_AND_396))), CAST(16, MSB(DUP(op_AND_396)), DUP(op_AND_396))), CAST(32, MSB(CAST(16, MSB(op_AND_404), DUP(op_AND_404))), CAST(16, MSB(DUP(op_AND_404)), DUP(op_AND_404))));
	RzILOpPure *op_ADD_410 = ADD(op_SUB_408, SN(32, 1));
	RzILOpPure *op_RSHIFT_412 = SHIFTRA(op_ADD_410, SN(32, 1));
	RzILOpPure *op_LT_414 = SLT(op_RSHIFT_412, SN(32, 0));
	RzILOpPure *op_LSHIFT_419 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_420 = NEG(op_LSHIFT_419);
	RzILOpPure *op_LSHIFT_425 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_428 = SUB(op_LSHIFT_425, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_429 = ITE(op_LT_414, op_NEG_420, op_SUB_428);
	RzILOpEffect *gcc_expr_430 = BRANCH(op_EQ_363, EMPTY(), set_usr_field_call_389);

	// h_tmp600 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_432 = SETL("h_tmp600", cond_429);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_433 = SEQN(2, gcc_expr_430, op_ASSIGN_hybrid_tmp_432);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x20)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x20) & ((st64) 0xffff)))) - ((st32) ((st16) ((Rtt >> 0x30) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp600) & ((st64) 0xffff))) << 0x20)));
	RzILOpPure *op_LSHIFT_305 = SHIFTL0(SN(64, 0xffff), SN(32, 0x20));
	RzILOpPure *op_NOT_306 = LOGNOT(op_LSHIFT_305);
	RzILOpPure *op_AND_307 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_306);
	RzILOpPure *op_RSHIFT_367 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_370 = LOGAND(op_RSHIFT_367, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_375 = SHIFTRA(DUP(Rtt), SN(32, 0x30));
	RzILOpPure *op_AND_378 = LOGAND(op_RSHIFT_375, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_SUB_382 = SUB(CAST(32, MSB(CAST(16, MSB(op_AND_370), DUP(op_AND_370))), CAST(16, MSB(DUP(op_AND_370)), DUP(op_AND_370))), CAST(32, MSB(CAST(16, MSB(op_AND_378), DUP(op_AND_378))), CAST(16, MSB(DUP(op_AND_378)), DUP(op_AND_378))));
	RzILOpPure *op_ADD_384 = ADD(op_SUB_382, SN(32, 1));
	RzILOpPure *op_RSHIFT_386 = SHIFTRA(op_ADD_384, SN(32, 1));
	RzILOpPure *cond_435 = ITE(DUP(op_EQ_363), CAST(64, MSB(op_RSHIFT_386), DUP(op_RSHIFT_386)), VARL("h_tmp600"));
	RzILOpPure *op_AND_438 = LOGAND(cond_435, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_443 = SHIFTL0(CAST(64, IL_FALSE, op_AND_438), SN(32, 0x20));
	RzILOpPure *op_OR_445 = LOGOR(CAST(64, IL_FALSE, op_AND_307), op_LSHIFT_443);
	RzILOpEffect *op_ASSIGN_447 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_445));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_448 = SEQN(2, seq_433, op_ASSIGN_447);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_538 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_463 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_466 = LOGAND(op_RSHIFT_463, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_471 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_474 = LOGAND(op_RSHIFT_471, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_478 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_466), DUP(op_AND_466))), CAST(16, MSB(DUP(op_AND_466)), DUP(op_AND_466))), CAST(32, MSB(CAST(16, MSB(op_AND_474), DUP(op_AND_474))), CAST(16, MSB(DUP(op_AND_474)), DUP(op_AND_474))));
	RzILOpPure *op_ADD_480 = ADD(op_ADD_478, SN(32, 1));
	RzILOpPure *op_RSHIFT_482 = SHIFTRA(op_ADD_480, SN(32, 1));
	RzILOpPure *op_RSHIFT_491 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_494 = LOGAND(op_RSHIFT_491, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_499 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_502 = LOGAND(op_RSHIFT_499, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_506 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_494), DUP(op_AND_494))), CAST(16, MSB(DUP(op_AND_494)), DUP(op_AND_494))), CAST(32, MSB(CAST(16, MSB(op_AND_502), DUP(op_AND_502))), CAST(16, MSB(DUP(op_AND_502)), DUP(op_AND_502))));
	RzILOpPure *op_ADD_508 = ADD(op_ADD_506, SN(32, 1));
	RzILOpPure *op_RSHIFT_510 = SHIFTRA(op_ADD_508, SN(32, 1));
	RzILOpPure *op_EQ_512 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_RSHIFT_482), SN(32, 0), SN(32, 16)), CAST(64, MSB(op_RSHIFT_510), DUP(op_RSHIFT_510)));
	RzILOpPure *op_RSHIFT_542 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_545 = LOGAND(op_RSHIFT_542, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_550 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_553 = LOGAND(op_RSHIFT_550, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_557 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_545), DUP(op_AND_545))), CAST(16, MSB(DUP(op_AND_545)), DUP(op_AND_545))), CAST(32, MSB(CAST(16, MSB(op_AND_553), DUP(op_AND_553))), CAST(16, MSB(DUP(op_AND_553)), DUP(op_AND_553))));
	RzILOpPure *op_ADD_559 = ADD(op_ADD_557, SN(32, 1));
	RzILOpPure *op_RSHIFT_561 = SHIFTRA(op_ADD_559, SN(32, 1));
	RzILOpPure *op_LT_563 = SLT(op_RSHIFT_561, SN(32, 0));
	RzILOpPure *op_LSHIFT_568 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_NEG_569 = NEG(op_LSHIFT_568);
	RzILOpPure *op_LSHIFT_574 = SHIFTL0(SN(64, 1), SN(32, 15));
	RzILOpPure *op_SUB_577 = SUB(op_LSHIFT_574, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_578 = ITE(op_LT_563, op_NEG_569, op_SUB_577);
	RzILOpEffect *gcc_expr_579 = BRANCH(op_EQ_512, EMPTY(), set_usr_field_call_538);

	// h_tmp601 = HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, (((((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1) < 0x0) ? (-(0x1 << 0xf)) : (0x1 << 0xf) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_581 = SETL("h_tmp601", cond_578);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) ((Rss  ...;
	RzILOpEffect *seq_582 = SEQN(2, gcc_expr_579, op_ASSIGN_hybrid_tmp_581);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << 0x30)))) | (((ut64) (((sextract64(((ut64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)), 0x0, 0x10) == ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1))) ? ((st64) (((st32) ((st16) ((Rss >> 0x30) & ((st64) 0xffff)))) + ((st32) ((st16) ((Rtt >> 0x20) & ((st64) 0xffff)))) + 0x1 >> 0x1)) : h_tmp601) & ((st64) 0xffff))) << 0x30)));
	RzILOpPure *op_LSHIFT_454 = SHIFTL0(SN(64, 0xffff), SN(32, 0x30));
	RzILOpPure *op_NOT_455 = LOGNOT(op_LSHIFT_454);
	RzILOpPure *op_AND_456 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_455);
	RzILOpPure *op_RSHIFT_516 = SHIFTRA(DUP(Rss), SN(32, 0x30));
	RzILOpPure *op_AND_519 = LOGAND(op_RSHIFT_516, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_RSHIFT_524 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_527 = LOGAND(op_RSHIFT_524, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_ADD_531 = ADD(CAST(32, MSB(CAST(16, MSB(op_AND_519), DUP(op_AND_519))), CAST(16, MSB(DUP(op_AND_519)), DUP(op_AND_519))), CAST(32, MSB(CAST(16, MSB(op_AND_527), DUP(op_AND_527))), CAST(16, MSB(DUP(op_AND_527)), DUP(op_AND_527))));
	RzILOpPure *op_ADD_533 = ADD(op_ADD_531, SN(32, 1));
	RzILOpPure *op_RSHIFT_535 = SHIFTRA(op_ADD_533, SN(32, 1));
	RzILOpPure *cond_584 = ITE(DUP(op_EQ_512), CAST(64, MSB(op_RSHIFT_535), DUP(op_RSHIFT_535)), VARL("h_tmp601"));
	RzILOpPure *op_AND_587 = LOGAND(cond_584, CAST(64, MSB(SN(32, 0xffff)), SN(32, 0xffff)));
	RzILOpPure *op_LSHIFT_592 = SHIFTL0(CAST(64, IL_FALSE, op_AND_587), SN(32, 0x30));
	RzILOpPure *op_OR_594 = LOGOR(CAST(64, IL_FALSE, op_AND_456), op_LSHIFT_592);
	RzILOpEffect *op_ASSIGN_596 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_594));

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) (((st32) ((st16) (( ...;
	RzILOpEffect *seq_597 = SEQN(2, seq_582, op_ASSIGN_596);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_150, seq_299, seq_448, seq_597);
	return instruction_sequence;
}

// Rdd = vxsubaddw(Rss,Rtt):sat
RzILOpEffect *hex_il_op_s4_vxsubaddw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_72 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_15 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_17 = LOGAND(op_RSHIFT_15, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_24 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_26 = LOGAND(op_RSHIFT_24, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_29 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_17), DUP(op_AND_17))), CAST(32, MSB(DUP(op_AND_17)), DUP(op_AND_17))), CAST(64, MSB(CAST(32, MSB(op_AND_26), DUP(op_AND_26))), CAST(32, MSB(DUP(op_AND_26)), DUP(op_AND_26))));
	RzILOpPure *op_RSHIFT_38 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_40 = LOGAND(op_RSHIFT_38, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_46 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_48 = LOGAND(op_RSHIFT_46, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_51 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_40), DUP(op_AND_40))), CAST(32, MSB(DUP(op_AND_40)), DUP(op_AND_40))), CAST(64, MSB(CAST(32, MSB(op_AND_48), DUP(op_AND_48))), CAST(32, MSB(DUP(op_AND_48)), DUP(op_AND_48))));
	RzILOpPure *op_EQ_52 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_SUB_29), SN(32, 0), SN(32, 0x20)), op_SUB_51);
	RzILOpPure *op_RSHIFT_76 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_78 = LOGAND(op_RSHIFT_76, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_84 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_86 = LOGAND(op_RSHIFT_84, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_89 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_78), DUP(op_AND_78))), CAST(32, MSB(DUP(op_AND_78)), DUP(op_AND_78))), CAST(64, MSB(CAST(32, MSB(op_AND_86), DUP(op_AND_86))), CAST(32, MSB(DUP(op_AND_86)), DUP(op_AND_86))));
	RzILOpPure *op_LT_92 = SLT(op_SUB_89, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_97 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_98 = NEG(op_LSHIFT_97);
	RzILOpPure *op_LSHIFT_103 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_106 = SUB(op_LSHIFT_103, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_107 = ITE(op_LT_92, op_NEG_98, op_SUB_106);
	RzILOpEffect *gcc_expr_108 = BRANCH(op_EQ_52, EMPTY(), set_usr_field_call_72);

	// h_tmp602 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_110 = SETL("h_tmp602", cond_107);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_111 = SEQN(2, gcc_expr_108, op_ASSIGN_hybrid_tmp_110);

	// Rdd = ((Rdd & (~(0xffffffff << 0x0))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))) - ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))) : h_tmp602) & 0xffffffff) << 0x0));
	RzILOpPure *op_LSHIFT_5 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0));
	RzILOpPure *op_NOT_6 = LOGNOT(op_LSHIFT_5);
	RzILOpPure *op_AND_7 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_6);
	RzILOpPure *op_RSHIFT_56 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_58 = LOGAND(op_RSHIFT_56, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_64 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_66 = LOGAND(op_RSHIFT_64, SN(64, 0xffffffff));
	RzILOpPure *op_SUB_69 = SUB(CAST(64, MSB(CAST(32, MSB(op_AND_58), DUP(op_AND_58))), CAST(32, MSB(DUP(op_AND_58)), DUP(op_AND_58))), CAST(64, MSB(CAST(32, MSB(op_AND_66), DUP(op_AND_66))), CAST(32, MSB(DUP(op_AND_66)), DUP(op_AND_66))));
	RzILOpPure *cond_112 = ITE(DUP(op_EQ_52), op_SUB_69, VARL("h_tmp602"));
	RzILOpPure *op_AND_114 = LOGAND(cond_112, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_118 = SHIFTL0(op_AND_114, SN(32, 0));
	RzILOpPure *op_OR_119 = LOGOR(op_AND_7, op_LSHIFT_118);
	RzILOpEffect *op_ASSIGN_120 = WRITE_REG(bundle, Rdd_op, op_OR_119);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_121 = SEQN(2, seq_111, op_ASSIGN_120);

	// set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1));
	RzILOpEffect *set_usr_field_call_192 = hex_set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, CAST(32, IL_FALSE, SN(32, 1)));

	// HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpPure *op_RSHIFT_136 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_138 = LOGAND(op_RSHIFT_136, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_144 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_146 = LOGAND(op_RSHIFT_144, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_149 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_138), DUP(op_AND_138))), CAST(32, MSB(DUP(op_AND_138)), DUP(op_AND_138))), CAST(64, MSB(CAST(32, MSB(op_AND_146), DUP(op_AND_146))), CAST(32, MSB(DUP(op_AND_146)), DUP(op_AND_146))));
	RzILOpPure *op_RSHIFT_158 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_160 = LOGAND(op_RSHIFT_158, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_166 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_168 = LOGAND(op_RSHIFT_166, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_171 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_160), DUP(op_AND_160))), CAST(32, MSB(DUP(op_AND_160)), DUP(op_AND_160))), CAST(64, MSB(CAST(32, MSB(op_AND_168), DUP(op_AND_168))), CAST(32, MSB(DUP(op_AND_168)), DUP(op_AND_168))));
	RzILOpPure *op_EQ_172 = EQ(SEXTRACT64(CAST(64, IL_FALSE, op_ADD_149), SN(32, 0), SN(32, 0x20)), op_ADD_171);
	RzILOpPure *op_RSHIFT_196 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_198 = LOGAND(op_RSHIFT_196, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_204 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_206 = LOGAND(op_RSHIFT_204, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_209 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_198), DUP(op_AND_198))), CAST(32, MSB(DUP(op_AND_198)), DUP(op_AND_198))), CAST(64, MSB(CAST(32, MSB(op_AND_206), DUP(op_AND_206))), CAST(32, MSB(DUP(op_AND_206)), DUP(op_AND_206))));
	RzILOpPure *op_LT_212 = SLT(op_ADD_209, CAST(64, MSB(SN(32, 0)), SN(32, 0)));
	RzILOpPure *op_LSHIFT_217 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_NEG_218 = NEG(op_LSHIFT_217);
	RzILOpPure *op_LSHIFT_223 = SHIFTL0(SN(64, 1), SN(32, 31));
	RzILOpPure *op_SUB_226 = SUB(op_LSHIFT_223, CAST(64, MSB(SN(32, 1)), SN(32, 1)));
	RzILOpPure *cond_227 = ITE(op_LT_212, op_NEG_218, op_SUB_226);
	RzILOpEffect *gcc_expr_228 = BRANCH(op_EQ_172, EMPTY(), set_usr_field_call_192);

	// h_tmp603 = HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) {{}} else {set_usr_field(bundle, HEX_REG_FIELD_USR_OVF, ((ut32) 0x1))}, ((((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))) < ((st64) 0x0)) ? (-(0x1 << 0x1f)) : (0x1 << 0x1f) - ((st64) 0x1)));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_230 = SETL("h_tmp603", cond_227);

	// seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((Rss > ...;
	RzILOpEffect *seq_231 = SEQN(2, gcc_expr_228, op_ASSIGN_hybrid_tmp_230);

	// Rdd = ((Rdd & (~(0xffffffff << 0x20))) | ((((sextract64(((ut64) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))), 0x0, 0x20) == ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))) ? ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))) + ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))) : h_tmp603) & 0xffffffff) << 0x20));
	RzILOpPure *op_LSHIFT_127 = SHIFTL0(SN(64, 0xffffffff), SN(32, 0x20));
	RzILOpPure *op_NOT_128 = LOGNOT(op_LSHIFT_127);
	RzILOpPure *op_AND_129 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_128);
	RzILOpPure *op_RSHIFT_176 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_178 = LOGAND(op_RSHIFT_176, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_184 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_186 = LOGAND(op_RSHIFT_184, SN(64, 0xffffffff));
	RzILOpPure *op_ADD_189 = ADD(CAST(64, MSB(CAST(32, MSB(op_AND_178), DUP(op_AND_178))), CAST(32, MSB(DUP(op_AND_178)), DUP(op_AND_178))), CAST(64, MSB(CAST(32, MSB(op_AND_186), DUP(op_AND_186))), CAST(32, MSB(DUP(op_AND_186)), DUP(op_AND_186))));
	RzILOpPure *cond_232 = ITE(DUP(op_EQ_172), op_ADD_189, VARL("h_tmp603"));
	RzILOpPure *op_AND_234 = LOGAND(cond_232, SN(64, 0xffffffff));
	RzILOpPure *op_LSHIFT_238 = SHIFTL0(op_AND_234, SN(32, 0x20));
	RzILOpPure *op_OR_239 = LOGOR(op_AND_129, op_LSHIFT_238);
	RzILOpEffect *op_ASSIGN_240 = WRITE_REG(bundle, Rdd_op, op_OR_239);

	// seq(seq(HYB(gcc_expr_if ((sextract64(((ut64) ((st64) ((st32) ((R ...;
	RzILOpEffect *seq_241 = SEQN(2, seq_231, op_ASSIGN_240);

	RzILOpEffect *instruction_sequence = SEQN(2, seq_121, seq_241);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>