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

// Rdd = deallocframe(Rs):raw
RzILOpEffect *hex_il_op_l2_deallocframe(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut64 tmp;
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp framekey_op = ALIAS2OP(HEX_REG_ALIAS_FRAMEKEY, false);
	RzILOpPure *framekey = READ_REG(pkt, &framekey_op, false);
	const HexOp sp_op = ALIAS2OP(HEX_REG_ALIAS_SP, false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_4 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// tmp = ((ut64) mem_load_64(EA));
	RzILOpPure *ml_EA_6 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_8 = SETL("tmp", CAST(64, IL_FALSE, ml_EA_6));

	// Rdd = ((st64) (tmp ^ (((ut64) framekey) << 0x20)));
	RzILOpPure *op_LSHIFT_13 = SHIFTL0(CAST(64, IL_FALSE, framekey), SN(32, 0x20));
	RzILOpPure *op_XOR_14 = LOGXOR(VARL("tmp"), op_LSHIFT_13);
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_XOR_14));

	// sp = EA + ((ut32) 0x8);
	RzILOpPure *op_ADD_20 = ADD(VARL("EA"), CAST(32, IL_FALSE, SN(32, 8)));
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, &sp_op, op_ADD_20);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_4, op_ASSIGN_8, op_ASSIGN_16, op_ASSIGN_21);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadalignb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_9)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_16 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_19 = LOGOR(op_RSHIFT_16, op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_19));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_21);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadalignb_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp164 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp164", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp164 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp164;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp164"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp164 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_14)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_24 = LOGOR(op_RSHIFT_21, op_LSHIFT_23);
	RzILOpEffect *op_ASSIGN_26 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_24));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_8, op_ASSIGN_11, op_ASSIGN_17, op_ASSIGN_26);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadalignb_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp165 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp165", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_15)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_25 = LOGOR(op_RSHIFT_22, op_LSHIFT_24);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_25));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18, op_ASSIGN_27);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadalignb_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 0));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp166 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp166", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_33 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_33)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_40 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_43 = LOGOR(op_RSHIFT_40, op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_43));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_30, op_ASSIGN_3, op_ASSIGN_36, op_ASSIGN_45);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadalignb_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_11)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_18 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_21 = LOGOR(op_RSHIFT_18, op_LSHIFT_20);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_21));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14, op_ASSIGN_23);
	return instruction_sequence;
}

// Ryy = memb_fifo(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadalignb_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// tmpV = ((ut64) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmpV", CAST(64, IL_FALSE, CAST(8, IL_FALSE, ml_EA_10)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x8) | (tmpV << 0x38)));
	RzILOpPure *op_RSHIFT_17 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 8));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(VARL("tmpV"), SN(32, 0x38));
	RzILOpPure *op_OR_20 = LOGOR(op_RSHIFT_17, op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_20));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, op_ASSIGN_22);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadalignh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_9)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_16 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_18 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_19 = LOGOR(op_RSHIFT_16, op_LSHIFT_18);
	RzILOpEffect *op_ASSIGN_21 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_19));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, op_ASSIGN_21);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadalignh_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp167 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp167", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp167 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp167;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp167"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp167 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_14)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_21 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_23 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_24 = LOGOR(op_RSHIFT_21, op_LSHIFT_23);
	RzILOpEffect *op_ASSIGN_26 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_24));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_8, op_ASSIGN_11, op_ASSIGN_17, op_ASSIGN_26);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadalignh_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp168 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp168", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_15)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_22 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_25 = LOGOR(op_RSHIFT_22, op_LSHIFT_24);
	RzILOpEffect *op_ASSIGN_27 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_25));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18, op_ASSIGN_27);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadalignh_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp169 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp169", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_33 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_33)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_40 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_43 = LOGOR(op_RSHIFT_40, op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_43));

	RzILOpEffect *instruction_sequence = SEQN(4, seq_30, op_ASSIGN_3, op_ASSIGN_36, op_ASSIGN_45);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadalignh_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_11)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_18 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_20 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_21 = LOGOR(op_RSHIFT_18, op_LSHIFT_20);
	RzILOpEffect *op_ASSIGN_23 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_21));

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14, op_ASSIGN_23);
	return instruction_sequence;
}

// Ryy = memh_fifo(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadalignh_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut64 tmpV;
	const HexOp *Ryy_op = ISA2REG(hi, 'y', false);
	RzILOpPure *Ryy = READ_REG(pkt, Ryy_op, false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// tmpV = ((ut64) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmpV", CAST(64, IL_FALSE, CAST(16, IL_FALSE, ml_EA_10)));

	// Ryy = ((st64) ((((ut64) Ryy) >> 0x10) | (tmpV << 0x30)));
	RzILOpPure *op_RSHIFT_17 = SHIFTR0(CAST(64, IL_FALSE, Ryy), SN(32, 16));
	RzILOpPure *op_LSHIFT_19 = SHIFTL0(VARL("tmpV"), SN(32, 0x30));
	RzILOpPure *op_OR_20 = LOGOR(op_RSHIFT_17, op_LSHIFT_19);
	RzILOpEffect *op_ASSIGN_22 = WRITE_REG(bundle, Ryy_op, CAST(64, IL_FALSE, op_OR_20));

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, op_ASSIGN_22);
	return instruction_sequence;
}

// Rd = membh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadbsw2_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_10));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_14 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_17 = SETL("i", INC(VARL("i"), 32));

	// h_tmp170 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_19 = SETL("h_tmp170", VARL("i"));

	// seq(h_tmp170 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_20 = SEQN(2, op_ASSIGN_hybrid_tmp_19, op_INC_17);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(SN(64, 0xffff), op_MUL_24);
	RzILOpPure *op_NOT_26 = LOGNOT(op_LSHIFT_25);
	RzILOpPure *op_AND_28 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_26);
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(VARL("tmpV"), op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_31), SN(32, 0xff));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_34), DUP(op_AND_34))), CAST(8, MSB(DUP(op_AND_34)), DUP(op_AND_34))), SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_28), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_44));

	// seq(h_tmp170; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp170; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_20);

	// while ((i < 0x2)) { seq(seq(h_tmp170; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_16 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_50 = REPEAT(op_LT_16, seq_49);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp170; Rd = ((st32)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_14, for_50);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, seq_51);
	return instruction_sequence;
}

// Rd = membh(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadbsw2_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp171 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp171", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp171 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp171;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp171"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp171 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_15));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_19 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_22 = SETL("i", INC(VARL("i"), 32));

	// h_tmp172 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_24 = SETL("h_tmp172", VARL("i"));

	// seq(h_tmp172 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_25 = SEQN(2, op_ASSIGN_hybrid_tmp_24, op_INC_22);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(SN(64, 0xffff), op_MUL_29);
	RzILOpPure *op_NOT_31 = LOGNOT(op_LSHIFT_30);
	RzILOpPure *op_AND_33 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_31);
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_36 = SHIFTR0(VARL("tmpV"), op_MUL_35);
	RzILOpPure *op_AND_39 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_36), SN(32, 0xff));
	RzILOpPure *op_AND_43 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_39), DUP(op_AND_39))), CAST(8, MSB(DUP(op_AND_39)), DUP(op_AND_39))), SN(32, 0xffff));
	RzILOpPure *op_MUL_46 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(CAST(64, IL_FALSE, op_AND_43), op_MUL_46);
	RzILOpPure *op_OR_49 = LOGOR(CAST(64, IL_FALSE, op_AND_33), op_LSHIFT_47);
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_49));

	// seq(h_tmp172; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_53 = op_ASSIGN_51;

	// seq(seq(h_tmp172; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_54 = SEQN(2, seq_53, seq_25);

	// while ((i < 0x2)) { seq(seq(h_tmp172; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_21 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_55 = REPEAT(op_LT_21, seq_54);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp172; Rd = ((st32)  ...;
	RzILOpEffect *seq_56 = SEQN(2, op_ASSIGN_19, for_55);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_8, op_ASSIGN_11, op_ASSIGN_17, seq_56);
	return instruction_sequence;
}

// Rd = membh(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbsw2_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp173 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp173", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_16));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_20 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_23 = SETL("i", INC(VARL("i"), 32));

	// h_tmp174 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_25 = SETL("h_tmp174", VARL("i"));

	// seq(h_tmp174 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_26 = SEQN(2, op_ASSIGN_hybrid_tmp_25, op_INC_23);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(SN(64, 0xffff), op_MUL_30);
	RzILOpPure *op_NOT_32 = LOGNOT(op_LSHIFT_31);
	RzILOpPure *op_AND_34 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_32);
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_37 = SHIFTR0(VARL("tmpV"), op_MUL_36);
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_37), SN(32, 0xff));
	RzILOpPure *op_AND_44 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_40), DUP(op_AND_40))), CAST(8, MSB(DUP(op_AND_40)), DUP(op_AND_40))), SN(32, 0xffff));
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(CAST(64, IL_FALSE, op_AND_44), op_MUL_47);
	RzILOpPure *op_OR_50 = LOGOR(CAST(64, IL_FALSE, op_AND_34), op_LSHIFT_48);
	RzILOpEffect *op_ASSIGN_52 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_50));

	// seq(h_tmp174; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_54 = op_ASSIGN_52;

	// seq(seq(h_tmp174; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_55 = SEQN(2, seq_54, seq_26);

	// while ((i < 0x2)) { seq(seq(h_tmp174; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_22 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_56 = REPEAT(op_LT_22, seq_55);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp174; Rd = ((st32)  ...;
	RzILOpEffect *seq_57 = SEQN(2, op_ASSIGN_20, for_56);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18, seq_57);
	return instruction_sequence;
}

// Rd = membh(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbsw2_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp175 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp175", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_34 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_34));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_38 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_41 = SETL("i", INC(VARL("i"), 32));

	// h_tmp176 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_43 = SETL("h_tmp176", VARL("i"));

	// seq(h_tmp176 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_hybrid_tmp_43, op_INC_41);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_48 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(SN(64, 0xffff), op_MUL_48);
	RzILOpPure *op_NOT_50 = LOGNOT(op_LSHIFT_49);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_50);
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_55 = SHIFTR0(VARL("tmpV"), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_55), SN(32, 0xff));
	RzILOpPure *op_AND_62 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_58), DUP(op_AND_58))), CAST(8, MSB(DUP(op_AND_58)), DUP(op_AND_58))), SN(32, 0xffff));
	RzILOpPure *op_MUL_65 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(CAST(64, IL_FALSE, op_AND_62), op_MUL_65);
	RzILOpPure *op_OR_68 = LOGOR(CAST(64, IL_FALSE, op_AND_52), op_LSHIFT_66);
	RzILOpEffect *op_ASSIGN_70 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_68));

	// seq(h_tmp176; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_72 = op_ASSIGN_70;

	// seq(seq(h_tmp176; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_73 = SEQN(2, seq_72, seq_44);

	// while ((i < 0x2)) { seq(seq(h_tmp176; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_40 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_74 = REPEAT(op_LT_40, seq_73);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp176; Rd = ((st32)  ...;
	RzILOpEffect *seq_75 = SEQN(2, op_ASSIGN_38, for_74);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_30, op_ASSIGN_3, op_ASSIGN_36, seq_75);
	return instruction_sequence;
}

// Rd = membh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadbsw2_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_12 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_12));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_16 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_19 = SETL("i", INC(VARL("i"), 32));

	// h_tmp177 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_21 = SETL("h_tmp177", VARL("i"));

	// seq(h_tmp177 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_22 = SEQN(2, op_ASSIGN_hybrid_tmp_21, op_INC_19);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffff), op_MUL_26);
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_28);
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_33 = SHIFTR0(VARL("tmpV"), op_MUL_32);
	RzILOpPure *op_AND_36 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_33), SN(32, 0xff));
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_36), DUP(op_AND_36))), CAST(8, MSB(DUP(op_AND_36)), DUP(op_AND_36))), SN(32, 0xffff));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), op_MUL_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, op_AND_30), op_LSHIFT_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_46));

	// seq(h_tmp177; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_50 = op_ASSIGN_48;

	// seq(seq(h_tmp177; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_50, seq_22);

	// while ((i < 0x2)) { seq(seq(h_tmp177; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_18 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_52 = REPEAT(op_LT_18, seq_51);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp177; Rd = ((st32)  ...;
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_16, for_52);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14, seq_53);
	return instruction_sequence;
}

// Rd = membh(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadbsw2_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_11));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_15 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_18 = SETL("i", INC(VARL("i"), 32));

	// h_tmp178 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_20 = SETL("h_tmp178", VARL("i"));

	// seq(h_tmp178 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_21 = SEQN(2, op_ASSIGN_hybrid_tmp_20, op_INC_18);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_25 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(SN(64, 0xffff), op_MUL_25);
	RzILOpPure *op_NOT_27 = LOGNOT(op_LSHIFT_26);
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_27);
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_32 = SHIFTR0(VARL("tmpV"), op_MUL_31);
	RzILOpPure *op_AND_35 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_32), SN(32, 0xff));
	RzILOpPure *op_AND_39 = LOGAND(CAST(32, MSB(CAST(8, MSB(op_AND_35), DUP(op_AND_35))), CAST(8, MSB(DUP(op_AND_35)), DUP(op_AND_35))), SN(32, 0xffff));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, op_AND_39), op_MUL_42);
	RzILOpPure *op_OR_45 = LOGOR(CAST(64, IL_FALSE, op_AND_29), op_LSHIFT_43);
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_45));

	// seq(h_tmp178; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_49 = op_ASSIGN_47;

	// seq(seq(h_tmp178; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_50 = SEQN(2, seq_49, seq_21);

	// while ((i < 0x2)) { seq(seq(h_tmp178; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_17 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_51 = REPEAT(op_LT_17, seq_50);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp178; Rd = ((st32)  ...;
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_15, for_51);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, seq_52);
	return instruction_sequence;
}

// Rdd = membh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadbsw4_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_10 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_10));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_14 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_17 = SETL("i", INC(VARL("i"), 32));

	// h_tmp179 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_19 = SETL("h_tmp179", VARL("i"));

	// seq(h_tmp179 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_20 = SEQN(2, op_ASSIGN_hybrid_tmp_19, op_INC_17);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(SN(64, 0xffff), op_MUL_24);
	RzILOpPure *op_NOT_26 = LOGNOT(op_LSHIFT_25);
	RzILOpPure *op_AND_27 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_26);
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_30 = SHIFTR0(VARL("tmpV"), op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_37 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_33)), CAST(8, IL_FALSE, DUP(op_AND_33))), SN(32, 0xffff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(CAST(64, IL_FALSE, op_AND_37), op_MUL_40);
	RzILOpPure *op_OR_43 = LOGOR(CAST(64, IL_FALSE, op_AND_27), op_LSHIFT_41);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_43));

	// seq(h_tmp179; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_47 = op_ASSIGN_45;

	// seq(seq(h_tmp179; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_48 = SEQN(2, seq_47, seq_20);

	// while ((i < 0x4)) { seq(seq(h_tmp179; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_16 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_49 = REPEAT(op_LT_16, seq_48);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp179; Rdd = ((st64) ...;
	RzILOpEffect *seq_50 = SEQN(2, op_ASSIGN_14, for_49);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, seq_50);
	return instruction_sequence;
}

// Rdd = membh(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadbsw4_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp180 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp180", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp180 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp180;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp180"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp180 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_15));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_19 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_22 = SETL("i", INC(VARL("i"), 32));

	// h_tmp181 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_24 = SETL("h_tmp181", VARL("i"));

	// seq(h_tmp181 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_25 = SEQN(2, op_ASSIGN_hybrid_tmp_24, op_INC_22);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(SN(64, 0xffff), op_MUL_29);
	RzILOpPure *op_NOT_31 = LOGNOT(op_LSHIFT_30);
	RzILOpPure *op_AND_32 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_31);
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_35 = SHIFTR0(VARL("tmpV"), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_42 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_38)), CAST(8, IL_FALSE, DUP(op_AND_38))), SN(32, 0xffff));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_46 = SHIFTL0(CAST(64, IL_FALSE, op_AND_42), op_MUL_45);
	RzILOpPure *op_OR_48 = LOGOR(CAST(64, IL_FALSE, op_AND_32), op_LSHIFT_46);
	RzILOpEffect *op_ASSIGN_50 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_48));

	// seq(h_tmp181; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_52 = op_ASSIGN_50;

	// seq(seq(h_tmp181; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_53 = SEQN(2, seq_52, seq_25);

	// while ((i < 0x4)) { seq(seq(h_tmp181; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_21 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_54 = REPEAT(op_LT_21, seq_53);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp181; Rdd = ((st64) ...;
	RzILOpEffect *seq_55 = SEQN(2, op_ASSIGN_19, for_54);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_8, op_ASSIGN_11, op_ASSIGN_17, seq_55);
	return instruction_sequence;
}

// Rdd = membh(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbsw4_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp182 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp182", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_16 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_16));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_20 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_23 = SETL("i", INC(VARL("i"), 32));

	// h_tmp183 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_25 = SETL("h_tmp183", VARL("i"));

	// seq(h_tmp183 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_26 = SEQN(2, op_ASSIGN_hybrid_tmp_25, op_INC_23);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(SN(64, 0xffff), op_MUL_30);
	RzILOpPure *op_NOT_32 = LOGNOT(op_LSHIFT_31);
	RzILOpPure *op_AND_33 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_32);
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_36 = SHIFTR0(VARL("tmpV"), op_MUL_35);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_36, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_43 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_39)), CAST(8, IL_FALSE, DUP(op_AND_39))), SN(32, 0xffff));
	RzILOpPure *op_MUL_46 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(CAST(64, IL_FALSE, op_AND_43), op_MUL_46);
	RzILOpPure *op_OR_49 = LOGOR(CAST(64, IL_FALSE, op_AND_33), op_LSHIFT_47);
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_49));

	// seq(h_tmp183; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_53 = op_ASSIGN_51;

	// seq(seq(h_tmp183; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_54 = SEQN(2, seq_53, seq_26);

	// while ((i < 0x4)) { seq(seq(h_tmp183; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_22 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_55 = REPEAT(op_LT_22, seq_54);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp183; Rdd = ((st64) ...;
	RzILOpEffect *seq_56 = SEQN(2, op_ASSIGN_20, for_55);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18, seq_56);
	return instruction_sequence;
}

// Rdd = membh(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbsw4_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 2));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp184 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp184", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_34 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_34));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_38 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_41 = SETL("i", INC(VARL("i"), 32));

	// h_tmp185 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_43 = SETL("h_tmp185", VARL("i"));

	// seq(h_tmp185 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_hybrid_tmp_43, op_INC_41);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_48 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(SN(64, 0xffff), op_MUL_48);
	RzILOpPure *op_NOT_50 = LOGNOT(op_LSHIFT_49);
	RzILOpPure *op_AND_51 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_50);
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_54 = SHIFTR0(VARL("tmpV"), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_61 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_57)), CAST(8, IL_FALSE, DUP(op_AND_57))), SN(32, 0xffff));
	RzILOpPure *op_MUL_64 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(CAST(64, IL_FALSE, op_AND_61), op_MUL_64);
	RzILOpPure *op_OR_67 = LOGOR(CAST(64, IL_FALSE, op_AND_51), op_LSHIFT_65);
	RzILOpEffect *op_ASSIGN_69 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_67));

	// seq(h_tmp185; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_71 = op_ASSIGN_69;

	// seq(seq(h_tmp185; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_72 = SEQN(2, seq_71, seq_44);

	// while ((i < 0x4)) { seq(seq(h_tmp185; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_40 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_73 = REPEAT(op_LT_40, seq_72);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp185; Rdd = ((st64) ...;
	RzILOpEffect *seq_74 = SEQN(2, op_ASSIGN_38, for_73);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_30, op_ASSIGN_3, op_ASSIGN_36, seq_74);
	return instruction_sequence;
}

// Rdd = membh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadbsw4_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_12 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_12));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_16 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_19 = SETL("i", INC(VARL("i"), 32));

	// h_tmp186 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_21 = SETL("h_tmp186", VARL("i"));

	// seq(h_tmp186 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_22 = SEQN(2, op_ASSIGN_hybrid_tmp_21, op_INC_19);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffff), op_MUL_26);
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_29 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_28);
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_32 = SHIFTR0(VARL("tmpV"), op_MUL_31);
	RzILOpPure *op_AND_35 = LOGAND(op_RSHIFT_32, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_39 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_35)), CAST(8, IL_FALSE, DUP(op_AND_35))), SN(32, 0xffff));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, op_AND_39), op_MUL_42);
	RzILOpPure *op_OR_45 = LOGOR(CAST(64, IL_FALSE, op_AND_29), op_LSHIFT_43);
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_45));

	// seq(h_tmp186; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_49 = op_ASSIGN_47;

	// seq(seq(h_tmp186; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_50 = SEQN(2, seq_49, seq_22);

	// while ((i < 0x4)) { seq(seq(h_tmp186; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_18 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_51 = REPEAT(op_LT_18, seq_50);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp186; Rdd = ((st64) ...;
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_16, for_51);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14, seq_52);
	return instruction_sequence;
}

// Rdd = membh(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadbsw4_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_11 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_11));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_15 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_18 = SETL("i", INC(VARL("i"), 32));

	// h_tmp187 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_20 = SETL("h_tmp187", VARL("i"));

	// seq(h_tmp187 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_21 = SEQN(2, op_ASSIGN_hybrid_tmp_20, op_INC_18);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((st8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_25 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(SN(64, 0xffff), op_MUL_25);
	RzILOpPure *op_NOT_27 = LOGNOT(op_LSHIFT_26);
	RzILOpPure *op_AND_28 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_27);
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(VARL("tmpV"), op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, MSB(CAST(8, IL_FALSE, op_AND_34)), CAST(8, IL_FALSE, DUP(op_AND_34))), SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_28), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_44));

	// seq(h_tmp187; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp187; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_21);

	// while ((i < 0x4)) { seq(seq(h_tmp187; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_17 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_50 = REPEAT(op_LT_17, seq_49);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp187; Rdd = ((st64) ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_15, for_50);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, seq_51);
	return instruction_sequence;
}

// Rd = memubh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadbzw2_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_10));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_14 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_17 = SETL("i", INC(VARL("i"), 32));

	// h_tmp188 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_19 = SETL("h_tmp188", VARL("i"));

	// seq(h_tmp188 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_20 = SEQN(2, op_ASSIGN_hybrid_tmp_19, op_INC_17);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(SN(64, 0xffff), op_MUL_24);
	RzILOpPure *op_NOT_26 = LOGNOT(op_LSHIFT_25);
	RzILOpPure *op_AND_28 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_26);
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(VARL("tmpV"), op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_31), SN(32, 0xff));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_34)), SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_28), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_44));

	// seq(h_tmp188; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp188; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_20);

	// while ((i < 0x2)) { seq(seq(h_tmp188; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_16 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_50 = REPEAT(op_LT_16, seq_49);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp188; Rd = ((st32)  ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_14, for_50);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, seq_51);
	return instruction_sequence;
}

// Rd = memubh(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadbzw2_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp189 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp189", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp189 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp189;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp189"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp189 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_15));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_19 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_22 = SETL("i", INC(VARL("i"), 32));

	// h_tmp190 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_24 = SETL("h_tmp190", VARL("i"));

	// seq(h_tmp190 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_25 = SEQN(2, op_ASSIGN_hybrid_tmp_24, op_INC_22);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(SN(64, 0xffff), op_MUL_29);
	RzILOpPure *op_NOT_31 = LOGNOT(op_LSHIFT_30);
	RzILOpPure *op_AND_33 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_31);
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_36 = SHIFTR0(VARL("tmpV"), op_MUL_35);
	RzILOpPure *op_AND_39 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_36), SN(32, 0xff));
	RzILOpPure *op_AND_43 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_39)), SN(32, 0xffff));
	RzILOpPure *op_MUL_46 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(CAST(64, IL_FALSE, op_AND_43), op_MUL_46);
	RzILOpPure *op_OR_49 = LOGOR(CAST(64, IL_FALSE, op_AND_33), op_LSHIFT_47);
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_49));

	// seq(h_tmp190; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_53 = op_ASSIGN_51;

	// seq(seq(h_tmp190; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_54 = SEQN(2, seq_53, seq_25);

	// while ((i < 0x2)) { seq(seq(h_tmp190; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_21 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_55 = REPEAT(op_LT_21, seq_54);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp190; Rd = ((st32)  ...;
	RzILOpEffect *seq_56 = SEQN(2, op_ASSIGN_19, for_55);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_8, op_ASSIGN_11, op_ASSIGN_17, seq_56);
	return instruction_sequence;
}

// Rd = memubh(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbzw2_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp191 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp191", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_16));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_20 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_23 = SETL("i", INC(VARL("i"), 32));

	// h_tmp192 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_25 = SETL("h_tmp192", VARL("i"));

	// seq(h_tmp192 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_26 = SEQN(2, op_ASSIGN_hybrid_tmp_25, op_INC_23);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(SN(64, 0xffff), op_MUL_30);
	RzILOpPure *op_NOT_32 = LOGNOT(op_LSHIFT_31);
	RzILOpPure *op_AND_34 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_32);
	RzILOpPure *op_MUL_36 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_37 = SHIFTR0(VARL("tmpV"), op_MUL_36);
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_37), SN(32, 0xff));
	RzILOpPure *op_AND_44 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_40)), SN(32, 0xffff));
	RzILOpPure *op_MUL_47 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_48 = SHIFTL0(CAST(64, IL_FALSE, op_AND_44), op_MUL_47);
	RzILOpPure *op_OR_50 = LOGOR(CAST(64, IL_FALSE, op_AND_34), op_LSHIFT_48);
	RzILOpEffect *op_ASSIGN_52 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_50));

	// seq(h_tmp192; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_54 = op_ASSIGN_52;

	// seq(seq(h_tmp192; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_55 = SEQN(2, seq_54, seq_26);

	// while ((i < 0x2)) { seq(seq(h_tmp192; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_22 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_56 = REPEAT(op_LT_22, seq_55);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp192; Rd = ((st32)  ...;
	RzILOpEffect *seq_57 = SEQN(2, op_ASSIGN_20, for_56);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18, seq_57);
	return instruction_sequence;
}

// Rd = memubh(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbzw2_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp193 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp193", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_34 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_34));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_38 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_41 = SETL("i", INC(VARL("i"), 32));

	// h_tmp194 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_43 = SETL("h_tmp194", VARL("i"));

	// seq(h_tmp194 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_hybrid_tmp_43, op_INC_41);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_48 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(SN(64, 0xffff), op_MUL_48);
	RzILOpPure *op_NOT_50 = LOGNOT(op_LSHIFT_49);
	RzILOpPure *op_AND_52 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_50);
	RzILOpPure *op_MUL_54 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_55 = SHIFTR0(VARL("tmpV"), op_MUL_54);
	RzILOpPure *op_AND_58 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_55), SN(32, 0xff));
	RzILOpPure *op_AND_62 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_58)), SN(32, 0xffff));
	RzILOpPure *op_MUL_65 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_66 = SHIFTL0(CAST(64, IL_FALSE, op_AND_62), op_MUL_65);
	RzILOpPure *op_OR_68 = LOGOR(CAST(64, IL_FALSE, op_AND_52), op_LSHIFT_66);
	RzILOpEffect *op_ASSIGN_70 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_68));

	// seq(h_tmp194; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_72 = op_ASSIGN_70;

	// seq(seq(h_tmp194; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_73 = SEQN(2, seq_72, seq_44);

	// while ((i < 0x2)) { seq(seq(h_tmp194; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_40 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_74 = REPEAT(op_LT_40, seq_73);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp194; Rd = ((st32)  ...;
	RzILOpEffect *seq_75 = SEQN(2, op_ASSIGN_38, for_74);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_30, op_ASSIGN_3, op_ASSIGN_36, seq_75);
	return instruction_sequence;
}

// Rd = memubh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadbzw2_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_12 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_12));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_16 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_19 = SETL("i", INC(VARL("i"), 32));

	// h_tmp195 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_21 = SETL("h_tmp195", VARL("i"));

	// seq(h_tmp195 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_22 = SEQN(2, op_ASSIGN_hybrid_tmp_21, op_INC_19);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffff), op_MUL_26);
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_30 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_28);
	RzILOpPure *op_MUL_32 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_33 = SHIFTR0(VARL("tmpV"), op_MUL_32);
	RzILOpPure *op_AND_36 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_33), SN(32, 0xff));
	RzILOpPure *op_AND_40 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_36)), SN(32, 0xffff));
	RzILOpPure *op_MUL_43 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_44 = SHIFTL0(CAST(64, IL_FALSE, op_AND_40), op_MUL_43);
	RzILOpPure *op_OR_46 = LOGOR(CAST(64, IL_FALSE, op_AND_30), op_LSHIFT_44);
	RzILOpEffect *op_ASSIGN_48 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_46));

	// seq(h_tmp195; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_50 = op_ASSIGN_48;

	// seq(seq(h_tmp195; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_51 = SEQN(2, seq_50, seq_22);

	// while ((i < 0x2)) { seq(seq(h_tmp195; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_18 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_52 = REPEAT(op_LT_18, seq_51);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp195; Rd = ((st32)  ...;
	RzILOpEffect *seq_53 = SEQN(2, op_ASSIGN_16, for_52);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14, seq_53);
	return instruction_sequence;
}

// Rd = memubh(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadbzw2_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut16 tmpV;
	// Declare: st32 i;
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// tmpV = ((ut16) mem_load_16(EA));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmpV", CAST(16, IL_FALSE, ml_EA_11));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_15 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_18 = SETL("i", INC(VARL("i"), 32));

	// h_tmp196 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_20 = SETL("h_tmp196", VARL("i"));

	// seq(h_tmp196 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_21 = SEQN(2, op_ASSIGN_hybrid_tmp_20, op_INC_18);

	// Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) (((st32) (tmpV >> i * 0x8)) & 0xff))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_25 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(SN(64, 0xffff), op_MUL_25);
	RzILOpPure *op_NOT_27 = LOGNOT(op_LSHIFT_26);
	RzILOpPure *op_AND_29 = LOGAND(CAST(64, MSB(READ_REG(pkt, Rd_op, true)), READ_REG(pkt, Rd_op, true)), op_NOT_27);
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_32 = SHIFTR0(VARL("tmpV"), op_MUL_31);
	RzILOpPure *op_AND_35 = LOGAND(CAST(32, IL_FALSE, op_RSHIFT_32), SN(32, 0xff));
	RzILOpPure *op_AND_39 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_35)), SN(32, 0xffff));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, op_AND_39), op_MUL_42);
	RzILOpPure *op_OR_45 = LOGOR(CAST(64, IL_FALSE, op_AND_29), op_LSHIFT_43);
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, op_OR_45));

	// seq(h_tmp196; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff <<  ...;
	RzILOpEffect *seq_49 = op_ASSIGN_47;

	// seq(seq(h_tmp196; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ...;
	RzILOpEffect *seq_50 = SEQN(2, seq_49, seq_21);

	// while ((i < 0x2)) { seq(seq(h_tmp196; Rd = ((st32) (((ut64) (((st64) Rd) & (~(0xffff ... };
	RzILOpPure *op_LT_17 = SLT(VARL("i"), SN(32, 2));
	RzILOpEffect *for_51 = REPEAT(op_LT_17, seq_50);

	// seq(i = 0x0; while ((i < 0x2)) { seq(seq(h_tmp196; Rd = ((st32)  ...;
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_15, for_51);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, seq_52);
	return instruction_sequence;
}

// Rdd = memubh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadbzw4_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_10 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_10));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_14 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_17 = SETL("i", INC(VARL("i"), 32));

	// h_tmp197 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_19 = SETL("h_tmp197", VARL("i"));

	// seq(h_tmp197 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_20 = SEQN(2, op_ASSIGN_hybrid_tmp_19, op_INC_17);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_24 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_25 = SHIFTL0(SN(64, 0xffff), op_MUL_24);
	RzILOpPure *op_NOT_26 = LOGNOT(op_LSHIFT_25);
	RzILOpPure *op_AND_27 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_26);
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_30 = SHIFTR0(VARL("tmpV"), op_MUL_29);
	RzILOpPure *op_AND_33 = LOGAND(op_RSHIFT_30, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_37 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_33)), SN(32, 0xffff));
	RzILOpPure *op_MUL_40 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_41 = SHIFTL0(CAST(64, IL_FALSE, op_AND_37), op_MUL_40);
	RzILOpPure *op_OR_43 = LOGOR(CAST(64, IL_FALSE, op_AND_27), op_LSHIFT_41);
	RzILOpEffect *op_ASSIGN_45 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_43));

	// seq(h_tmp197; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_47 = op_ASSIGN_45;

	// seq(seq(h_tmp197; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_48 = SEQN(2, seq_47, seq_20);

	// while ((i < 0x4)) { seq(seq(h_tmp197; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_16 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_49 = REPEAT(op_LT_16, seq_48);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp197; Rdd = ((st64) ...;
	RzILOpEffect *seq_50 = SEQN(2, op_ASSIGN_14, for_49);

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12, seq_50);
	return instruction_sequence;
}

// Rdd = memubh(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadbzw4_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp198 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp198", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp198 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp198;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp198"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp198 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_15));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_19 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_22 = SETL("i", INC(VARL("i"), 32));

	// h_tmp199 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_24 = SETL("h_tmp199", VARL("i"));

	// seq(h_tmp199 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_25 = SEQN(2, op_ASSIGN_hybrid_tmp_24, op_INC_22);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_29 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_30 = SHIFTL0(SN(64, 0xffff), op_MUL_29);
	RzILOpPure *op_NOT_31 = LOGNOT(op_LSHIFT_30);
	RzILOpPure *op_AND_32 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_31);
	RzILOpPure *op_MUL_34 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_35 = SHIFTR0(VARL("tmpV"), op_MUL_34);
	RzILOpPure *op_AND_38 = LOGAND(op_RSHIFT_35, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_42 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_38)), SN(32, 0xffff));
	RzILOpPure *op_MUL_45 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_46 = SHIFTL0(CAST(64, IL_FALSE, op_AND_42), op_MUL_45);
	RzILOpPure *op_OR_48 = LOGOR(CAST(64, IL_FALSE, op_AND_32), op_LSHIFT_46);
	RzILOpEffect *op_ASSIGN_50 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_48));

	// seq(h_tmp199; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_52 = op_ASSIGN_50;

	// seq(seq(h_tmp199; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_53 = SEQN(2, seq_52, seq_25);

	// while ((i < 0x4)) { seq(seq(h_tmp199; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_21 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_54 = REPEAT(op_LT_21, seq_53);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp199; Rdd = ((st64) ...;
	RzILOpEffect *seq_55 = SEQN(2, op_ASSIGN_19, for_54);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_8, op_ASSIGN_11, op_ASSIGN_17, seq_55);
	return instruction_sequence;
}

// Rdd = memubh(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbzw4_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp200 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp200", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_16 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_16));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_20 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_23 = SETL("i", INC(VARL("i"), 32));

	// h_tmp201 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_25 = SETL("h_tmp201", VARL("i"));

	// seq(h_tmp201 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_26 = SEQN(2, op_ASSIGN_hybrid_tmp_25, op_INC_23);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_31 = SHIFTL0(SN(64, 0xffff), op_MUL_30);
	RzILOpPure *op_NOT_32 = LOGNOT(op_LSHIFT_31);
	RzILOpPure *op_AND_33 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_32);
	RzILOpPure *op_MUL_35 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_36 = SHIFTR0(VARL("tmpV"), op_MUL_35);
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_36, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_43 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_39)), SN(32, 0xffff));
	RzILOpPure *op_MUL_46 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_47 = SHIFTL0(CAST(64, IL_FALSE, op_AND_43), op_MUL_46);
	RzILOpPure *op_OR_49 = LOGOR(CAST(64, IL_FALSE, op_AND_33), op_LSHIFT_47);
	RzILOpEffect *op_ASSIGN_51 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_49));

	// seq(h_tmp201; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_53 = op_ASSIGN_51;

	// seq(seq(h_tmp201; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_54 = SEQN(2, seq_53, seq_26);

	// while ((i < 0x4)) { seq(seq(h_tmp201; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_22 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_55 = REPEAT(op_LT_22, seq_54);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp201; Rdd = ((st64) ...;
	RzILOpEffect *seq_56 = SEQN(2, op_ASSIGN_20, for_55);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18, seq_56);
	return instruction_sequence;
}

// Rdd = memubh(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadbzw4_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 2));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp202 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp202", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_34 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_34));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_38 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_41 = SETL("i", INC(VARL("i"), 32));

	// h_tmp203 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_43 = SETL("h_tmp203", VARL("i"));

	// seq(h_tmp203 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_44 = SEQN(2, op_ASSIGN_hybrid_tmp_43, op_INC_41);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_48 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_49 = SHIFTL0(SN(64, 0xffff), op_MUL_48);
	RzILOpPure *op_NOT_50 = LOGNOT(op_LSHIFT_49);
	RzILOpPure *op_AND_51 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_50);
	RzILOpPure *op_MUL_53 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_54 = SHIFTR0(VARL("tmpV"), op_MUL_53);
	RzILOpPure *op_AND_57 = LOGAND(op_RSHIFT_54, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_61 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_57)), SN(32, 0xffff));
	RzILOpPure *op_MUL_64 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_65 = SHIFTL0(CAST(64, IL_FALSE, op_AND_61), op_MUL_64);
	RzILOpPure *op_OR_67 = LOGOR(CAST(64, IL_FALSE, op_AND_51), op_LSHIFT_65);
	RzILOpEffect *op_ASSIGN_69 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_67));

	// seq(h_tmp203; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_71 = op_ASSIGN_69;

	// seq(seq(h_tmp203; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_72 = SEQN(2, seq_71, seq_44);

	// while ((i < 0x4)) { seq(seq(h_tmp203; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_40 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_73 = REPEAT(op_LT_40, seq_72);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp203; Rdd = ((st64) ...;
	RzILOpEffect *seq_74 = SEQN(2, op_ASSIGN_38, for_73);

	RzILOpEffect *instruction_sequence = SEQN(4, seq_30, op_ASSIGN_3, op_ASSIGN_36, seq_74);
	return instruction_sequence;
}

// Rdd = memubh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadbzw4_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_12 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_12));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_16 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_19 = SETL("i", INC(VARL("i"), 32));

	// h_tmp204 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_21 = SETL("h_tmp204", VARL("i"));

	// seq(h_tmp204 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_22 = SEQN(2, op_ASSIGN_hybrid_tmp_21, op_INC_19);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_26 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_27 = SHIFTL0(SN(64, 0xffff), op_MUL_26);
	RzILOpPure *op_NOT_28 = LOGNOT(op_LSHIFT_27);
	RzILOpPure *op_AND_29 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_28);
	RzILOpPure *op_MUL_31 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_32 = SHIFTR0(VARL("tmpV"), op_MUL_31);
	RzILOpPure *op_AND_35 = LOGAND(op_RSHIFT_32, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_39 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_35)), SN(32, 0xffff));
	RzILOpPure *op_MUL_42 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_43 = SHIFTL0(CAST(64, IL_FALSE, op_AND_39), op_MUL_42);
	RzILOpPure *op_OR_45 = LOGOR(CAST(64, IL_FALSE, op_AND_29), op_LSHIFT_43);
	RzILOpEffect *op_ASSIGN_47 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_45));

	// seq(h_tmp204; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_49 = op_ASSIGN_47;

	// seq(seq(h_tmp204; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_50 = SEQN(2, seq_49, seq_22);

	// while ((i < 0x4)) { seq(seq(h_tmp204; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_18 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_51 = REPEAT(op_LT_18, seq_50);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp204; Rdd = ((st64) ...;
	RzILOpEffect *seq_52 = SEQN(2, op_ASSIGN_16, for_51);

	RzILOpEffect *instruction_sequence = SEQN(5, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14, seq_52);
	return instruction_sequence;
}

// Rdd = memubh(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadbzw4_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	// Declare: ut32 tmpV;
	// Declare: st32 i;
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// tmpV = ((ut32) mem_load_32(EA));
	RzILOpPure *ml_EA_11 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = SETL("tmpV", CAST(32, IL_FALSE, ml_EA_11));

	// i = 0x0;
	RzILOpEffect *op_ASSIGN_15 = SETL("i", SN(32, 0));

	// HYB(++i);
	RzILOpEffect *op_INC_18 = SETL("i", INC(VARL("i"), 32));

	// h_tmp205 = HYB(++i);
	RzILOpEffect *op_ASSIGN_hybrid_tmp_20 = SETL("h_tmp205", VARL("i"));

	// seq(h_tmp205 = HYB(++i); HYB(++i));
	RzILOpEffect *seq_21 = SEQN(2, op_ASSIGN_hybrid_tmp_20, op_INC_18);

	// Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x10)))) | (((ut64) (((st32) ((ut8) ((tmpV >> i * 0x8) & ((ut32) 0xff)))) & 0xffff)) << i * 0x10)));
	RzILOpPure *op_MUL_25 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_26 = SHIFTL0(SN(64, 0xffff), op_MUL_25);
	RzILOpPure *op_NOT_27 = LOGNOT(op_LSHIFT_26);
	RzILOpPure *op_AND_28 = LOGAND(READ_REG(pkt, Rdd_op, true), op_NOT_27);
	RzILOpPure *op_MUL_30 = MUL(VARL("i"), SN(32, 8));
	RzILOpPure *op_RSHIFT_31 = SHIFTR0(VARL("tmpV"), op_MUL_30);
	RzILOpPure *op_AND_34 = LOGAND(op_RSHIFT_31, CAST(32, IL_FALSE, SN(32, 0xff)));
	RzILOpPure *op_AND_38 = LOGAND(CAST(32, IL_FALSE, CAST(8, IL_FALSE, op_AND_34)), SN(32, 0xffff));
	RzILOpPure *op_MUL_41 = MUL(VARL("i"), SN(32, 16));
	RzILOpPure *op_LSHIFT_42 = SHIFTL0(CAST(64, IL_FALSE, op_AND_38), op_MUL_41);
	RzILOpPure *op_OR_44 = LOGOR(CAST(64, IL_FALSE, op_AND_28), op_LSHIFT_42);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, op_OR_44));

	// seq(h_tmp205; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * 0x1 ...;
	RzILOpEffect *seq_48 = op_ASSIGN_46;

	// seq(seq(h_tmp205; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ...;
	RzILOpEffect *seq_49 = SEQN(2, seq_48, seq_21);

	// while ((i < 0x4)) { seq(seq(h_tmp205; Rdd = ((st64) (((ut64) (Rdd & (~(0xffff << i * ... };
	RzILOpPure *op_LT_17 = SLT(VARL("i"), SN(32, 4));
	RzILOpEffect *for_50 = REPEAT(op_LT_17, seq_49);

	// seq(i = 0x0; while ((i < 0x4)) { seq(seq(h_tmp205; Rdd = ((st64) ...;
	RzILOpEffect *seq_51 = SEQN(2, op_ASSIGN_15, for_50);

	RzILOpEffect *instruction_sequence = SEQN(4, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13, seq_51);
	return instruction_sequence;
}

// Rd = memb(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadrb_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(8, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memb(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadrb_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp206 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp206", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp206 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp206;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp206"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp206 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_14), DUP(ml_EA_14))), CAST(8, MSB(DUP(ml_EA_14)), DUP(ml_EA_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, op_ASSIGN_17);
	return instruction_sequence;
}

// Rd = memb(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrb_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp207 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp207", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(8, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18);
	return instruction_sequence;
}

// Rd = memb(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrb_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 0));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp208 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp208", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_33 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_33), DUP(ml_EA_33))), CAST(8, MSB(DUP(ml_EA_33)), DUP(ml_EA_33))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, op_ASSIGN_36);
	return instruction_sequence;
}

// Rd = memb(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadrb_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(8, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memb(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadrb_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_10), DUP(ml_EA_10))), CAST(8, MSB(DUP(ml_EA_10)), DUP(ml_EA_10))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13);
	return instruction_sequence;
}

// Rd = memb(gp+Ii)
RzILOpEffect *hex_il_op_l2_loadrbgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_8 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_8), DUP(ml_EA_8))), CAST(8, MSB(DUP(ml_EA_8)), DUP(ml_EA_8))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rdd = memd(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadrd_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_9 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rdd = memd(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadrd_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp209 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp209", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp209 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp209;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp209"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp209 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_14 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_14)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, op_ASSIGN_17);
	return instruction_sequence;
}

// Rdd = memd(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrd_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp210 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp210", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_15 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_15)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18);
	return instruction_sequence;
}

// Rdd = memd(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrd_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x3)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 3));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp211 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x3)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp211", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_33 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_33)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, op_ASSIGN_36);
	return instruction_sequence;
}

// Rdd = memd(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadrd_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_11 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rdd = memd(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadrd_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_10 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_10)));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13);
	return instruction_sequence;
}

// Rdd = memd(gp+Ii)
RzILOpEffect *hex_il_op_l2_loadrdgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_8 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_8)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadrh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_9), DUP(ml_EA_9))), CAST(16, MSB(DUP(ml_EA_9)), DUP(ml_EA_9))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memh(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadrh_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp212 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp212", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp212 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp212;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp212"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp212 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_14), DUP(ml_EA_14))), CAST(16, MSB(DUP(ml_EA_14)), DUP(ml_EA_14))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, op_ASSIGN_17);
	return instruction_sequence;
}

// Rd = memh(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrh_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp213 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp213", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(16, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18);
	return instruction_sequence;
}

// Rd = memh(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrh_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp214 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp214", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_33 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_33), DUP(ml_EA_33))), CAST(16, MSB(DUP(ml_EA_33)), DUP(ml_EA_33))));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, op_ASSIGN_36);
	return instruction_sequence;
}

// Rd = memh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadrh_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_11), DUP(ml_EA_11))), CAST(16, MSB(DUP(ml_EA_11)), DUP(ml_EA_11))));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memh(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadrh_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_10), DUP(ml_EA_10))), CAST(16, MSB(DUP(ml_EA_10)), DUP(ml_EA_10))));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13);
	return instruction_sequence;
}

// Rd = memh(gp+Ii)
RzILOpEffect *hex_il_op_l2_loadrhgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_8 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_8), DUP(ml_EA_8))), CAST(16, MSB(DUP(ml_EA_8)), DUP(ml_EA_8))));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memw(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadri_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_9 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memw(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadri_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp215 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp215", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp215 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp215;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp215"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp215 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_14 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_14)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, op_ASSIGN_17);
	return instruction_sequence;
}

// Rd = memw(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadri_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp216 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp216", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_15)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18);
	return instruction_sequence;
}

// Rd = memw(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadri_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 2));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp217 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x2)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp217", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_33 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_33)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, op_ASSIGN_36);
	return instruction_sequence;
}

// Rd = memw(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadri_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_11 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memw(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadri_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_10 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_10)));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13);
	return instruction_sequence;
}

// Rd = memw(gp+Ii)
RzILOpEffect *hex_il_op_l2_loadrigp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_8 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_8)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memub(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadrub_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_9 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memub(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadrub_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp218 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp218", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp218 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp218;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp218"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp218 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_14)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, op_ASSIGN_17);
	return instruction_sequence;
}

// Rd = memub(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrub_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp219 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp219", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_15)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18);
	return instruction_sequence;
}

// Rd = memub(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadrub_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 0));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp220 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x0)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp220", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_33 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_33)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, op_ASSIGN_36);
	return instruction_sequence;
}

// Rd = memub(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadrub_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_11 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memub(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadrub_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_10 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_10)));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13);
	return instruction_sequence;
}

// Rd = memub(gp+Ii)
RzILOpEffect *hex_il_op_l2_loadrubgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_8 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_8)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memuh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_loadruh_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// s = s;
	RzILOpEffect *imm_assign_0 = SETL("s", s);

	// EA = ((ut32) Rs + s);
	RzILOpPure *op_ADD_4 = ADD(Rs, VARL("s"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", CAST(32, IL_FALSE, op_ADD_4));

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_9 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_9)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, op_ASSIGN_12);
	return instruction_sequence;
}

// Rd = memuh(Rx++Mu:brev)
RzILOpEffect *hex_il_op_l2_loadruh_pbr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// fbrev(((ut32) Rx));
	RzILOpEffect *fbrev_call_3 = hex_fbrev(CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// h_tmp221 = fbrev(((ut32) Rx));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_5 = SETL("h_tmp221", UNSIGNED(32, VARL("ret_val")));

	// seq(fbrev(((ut32) Rx)); h_tmp221 = fbrev(((ut32) Rx)));
	RzILOpEffect *seq_6 = SEQN(2, fbrev_call_3, op_ASSIGN_hybrid_tmp_5);

	// EA = h_tmp221;
	RzILOpEffect *op_ASSIGN_7 = SETL("EA", VARL("h_tmp221"));

	// seq(seq(fbrev(((ut32) Rx)); h_tmp221 = fbrev(((ut32) Rx))); EA = ...;
	RzILOpEffect *seq_8 = SEQN(2, seq_6, op_ASSIGN_7);

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_10 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rx_op, op_ADD_10);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_14)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_8, op_ASSIGN_11, op_ASSIGN_17);
	return instruction_sequence;
}

// Rd = memuh(Rx++Ii:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadruh_pci(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *fcirc_add_call_9 = hex_fcirc_add(bundle, Rx_op, VARL("s"), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp222 = fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_11 = SETL("h_tmp222", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, s, Mu, get_corresponding_CS(pkt, Mu)); ...;
	RzILOpEffect *seq_12 = SEQN(2, fcirc_add_call_9, op_ASSIGN_hybrid_tmp_11);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_15)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, seq_12, op_ASSIGN_3, op_ASSIGN_18);
	return instruction_sequence;
}

// Rd = memuh(Rx++I:circ(Mu))
RzILOpEffect *hex_il_op_l2_loadruh_pcr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpPure *op_AND_10 = LOGAND(DUP(Mu), SN(32, 0xf0000000));
	RzILOpPure *op_RSHIFT_12 = SHIFTRA(op_AND_10, SN(32, 21));
	RzILOpPure *op_RSHIFT_14 = SHIFTRA(DUP(Mu), SN(32, 17));
	RzILOpPure *op_AND_16 = LOGAND(op_RSHIFT_14, SN(32, 0x7f));
	RzILOpPure *op_OR_17 = LOGOR(op_RSHIFT_12, op_AND_16);
	RzILOpPure *op_LSHIFT_24 = SHIFTL0(SEXTRACT64(CAST(64, IL_FALSE, op_OR_17), SN(32, 0), SN(32, 11)), SN(32, 1));
	RzILOpEffect *fcirc_add_call_27 = hex_fcirc_add(bundle, Rx_op, CAST(32, MSB(op_LSHIFT_24), DUP(op_LSHIFT_24)), Mu, HEX_GET_CORRESPONDING_CS(pkt, Mu_op));

	// h_tmp223 = fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0xf0000000) >> 0x15) | ((Mu >> 0x11) & 0x7f))), 0x0, 0xb) << 0x1)), Mu, get_corresponding_CS(pkt, Mu));
	RzILOpEffect *op_ASSIGN_hybrid_tmp_29 = SETL("h_tmp223", SIGNED(32, VARL("ret_val")));

	// seq(fcirc_add(bundle, Rx, ((st32) (sextract64(((ut64) (((Mu & 0x ...;
	RzILOpEffect *seq_30 = SEQN(2, fcirc_add_call_27, op_ASSIGN_hybrid_tmp_29);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_33 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_36 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_33)));

	RzILOpEffect *instruction_sequence = SEQN(3, seq_30, op_ASSIGN_3, op_ASSIGN_36);
	return instruction_sequence;
}

// Rd = memuh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_loadruh_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_5 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_7 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_8 = WRITE_REG(bundle, Rx_op, op_ADD_7);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_11 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_14 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_11)));

	RzILOpEffect *instruction_sequence = SEQN(4, imm_assign_5, op_ASSIGN_3, op_ASSIGN_8, op_ASSIGN_14);
	return instruction_sequence;
}

// Rd = memuh(Rx++Mu)
RzILOpEffect *hex_il_op_l2_loadruh_pr(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Mu_op = ISA2REG(hi, 'u', false);
	RzILOpPure *Mu = READ_REG(pkt, Mu_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// Rx = Rx + Mu;
	RzILOpPure *op_ADD_6 = ADD(READ_REG(pkt, Rx_op, false), Mu);
	RzILOpEffect *op_ASSIGN_7 = WRITE_REG(bundle, Rx_op, op_ADD_6);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_10 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_10)));

	RzILOpEffect *instruction_sequence = SEQN(3, op_ASSIGN_3, op_ASSIGN_7, op_ASSIGN_13);
	return instruction_sequence;
}

// Rd = memuh(gp+Ii)
RzILOpEffect *hex_il_op_l2_loadruhgp(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp gp_op = ALIAS2OP(HEX_REG_ALIAS_GP, false);
	RzILOpPure *gp = READ_REG(pkt, &gp_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = gp + u;
	RzILOpPure *op_ADD_4 = ADD(gp, VARL("u"));
	RzILOpEffect *op_ASSIGN_5 = SETL("EA", op_ADD_4);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_8 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_11 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_8)));

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_5, op_ASSIGN_11);
	return instruction_sequence;
}

// Rd = memw_aq(Rs)
RzILOpEffect *hex_il_op_l2_loadw_aq(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rs);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, Rs));

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_6 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_9 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_6)));

	RzILOpEffect *instruction_sequence = SEQN(2, op_ASSIGN_3, op_ASSIGN_9);
	return instruction_sequence;
}

// Rd = memw_locked(Rs)
RzILOpEffect *hex_il_op_l2_loadw_locked(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// if (!Pt) Rd = memb(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrbf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_14), DUP(ml_EA_14))), CAST(8, MSB(DUP(ml_EA_14)), DUP(ml_EA_14))));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt) Rd = memb(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrbf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(8, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memb(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrbfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_14), DUP(ml_EA_14))), CAST(8, MSB(DUP(ml_EA_14)), DUP(ml_EA_14))));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memb(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrbfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(8, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memb(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrbt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_13 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_13), DUP(ml_EA_13))), CAST(8, MSB(DUP(ml_EA_13)), DUP(ml_EA_13))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt) Rd = memb(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrbt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(8, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memb(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrbtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_13 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_13), DUP(ml_EA_13))), CAST(8, MSB(DUP(ml_EA_13)), DUP(ml_EA_13))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt.new) Rd = memb(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrbtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((st8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(8, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(8, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rdd = memd(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrdf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_14 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt) Rdd = memd(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrdf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_16 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rdd = memd(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrdfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_14 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt.new) Rdd = memd(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrdfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_16 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (Pt) Rdd = memd(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrdt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_13 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt) Rdd = memd(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrdt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_15 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rdd = memd(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrdtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_13 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt.new) Rdd = memd(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrdtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rdd = ((st64) ((ut64) mem_load_64(EA)));
	RzILOpPure *ml_EA_15 = LOADW(64, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rdd_op, CAST(64, IL_FALSE, CAST(64, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rdd = ((st64) ((ut64) mem_load_64(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrhf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_14), DUP(ml_EA_14))), CAST(16, MSB(DUP(ml_EA_14)), DUP(ml_EA_14))));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt) Rd = memh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrhf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(16, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrhfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_14), DUP(ml_EA_14))), CAST(16, MSB(DUP(ml_EA_14)), DUP(ml_EA_14))));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrhfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_16), DUP(ml_EA_16))), CAST(16, MSB(DUP(ml_EA_16)), DUP(ml_EA_16))));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrht_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_13 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_13), DUP(ml_EA_13))), CAST(16, MSB(DUP(ml_EA_13)), DUP(ml_EA_13))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt) Rd = memh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrht_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(16, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrhtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_13 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_13), DUP(ml_EA_13))), CAST(16, MSB(DUP(ml_EA_13)), DUP(ml_EA_13))));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt.new) Rd = memh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrhtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((st16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, MSB(CAST(16, MSB(ml_EA_15), DUP(ml_EA_15))), CAST(16, MSB(DUP(ml_EA_15)), DUP(ml_EA_15))));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((st16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memw(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrif_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_14 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt) Rd = memw(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrif_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_16 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memw(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrifnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_14 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memw(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrifnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_16 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memw(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrit_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_13 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt) Rd = memw(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrit_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memw(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadritnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_13 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt.new) Rd = memw(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadritnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((ut32) mem_load_32(EA)));
	RzILOpPure *ml_EA_15 = LOADW(32, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(32, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut32) mem_load_32(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memub(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrubf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt) Rd = memub(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrubf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memub(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrubfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_14 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memub(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrubfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_16 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memub(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrubt_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_13 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt) Rd = memub(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrubt_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memub(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadrubtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_13 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt.new) Rd = memub(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadrubtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((ut8) mem_load_8(EA)));
	RzILOpPure *ml_EA_15 = LOADW(8, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(8, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut8) mem_load_8(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (!Pt) Rd = memuh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadruhf_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt) Rd = memuh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadruhf_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memuh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadruhfnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_14 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_17 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_14)));

	// nop;
	RzILOpEffect *nop_18 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_20 = op_ASSIGN_17;

	// seq(nop);
	RzILOpEffect *seq_else_21 = nop_18;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_12 = INV(NON_ZERO(op_AND_11));
	RzILOpEffect *branch_22 = BRANCH(op_INV_12, seq_then_20, seq_else_21);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_22);
	return instruction_sequence;
}

// if (!Pt.new) Rd = memuh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadruhfnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_10 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_12 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_13 = WRITE_REG(bundle, Rx_op, op_ADD_12);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_16 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_19 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_16)));

	// nop;
	RzILOpEffect *nop_20 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_22 = SEQN(2, op_ASSIGN_13, op_ASSIGN_19);

	// seq(nop);
	RzILOpEffect *seq_else_23 = nop_20;

	// if (! (((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpPure *op_INV_9 = INV(NON_ZERO(op_AND_8));
	RzILOpEffect *branch_24 = BRANCH(op_INV_9, seq_then_22, seq_else_23);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_10, op_ASSIGN_3, branch_24);
	return instruction_sequence;
}

// if (Pt) Rd = memuh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadruht_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_13 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt) Rd = memuh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadruht_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Pt = READ_REG(pkt, Pt_op, false);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt), DUP(Pt)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

// if (Pt.new) Rd = memuh(Rs+Ii)
RzILOpEffect *hex_il_op_l2_ploadruhtnew_io(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	RzILOpPure *u = UN(32, (ut32)ISA2IMM(hi, 'u'));
	// Declare: ut32 EA;
	const HexOp *Rs_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rs = READ_REG(pkt, Rs_op, false);
	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// u = u;
	RzILOpEffect *imm_assign_0 = SETL("u", u);

	// EA = ((ut32) Rs) + u;
	RzILOpPure *op_ADD_5 = ADD(CAST(32, IL_FALSE, Rs), VARL("u"));
	RzILOpEffect *op_ASSIGN_6 = SETL("EA", op_ADD_5);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_13 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_16 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_13)));

	// nop;
	RzILOpEffect *nop_17 = NOP();

	// seq(Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_19 = op_ASSIGN_16;

	// seq(nop);
	RzILOpEffect *seq_else_20 = nop_17;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_11 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_21 = BRANCH(NON_ZERO(op_AND_11), seq_then_19, seq_else_20);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_0, op_ASSIGN_6, branch_21);
	return instruction_sequence;
}

// if (Pt.new) Rd = memuh(Rx++Ii)
RzILOpEffect *hex_il_op_l2_ploadruhtnew_pi(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	// Declare: ut32 EA;
	const HexOp *Rx_op = ISA2REG(hi, 'x', false);

	const HexOp *Pt_new_op = ISA2REG(hi, 't', true);
	RzILOpPure *Pt_new = READ_REG(pkt, Pt_new_op, true);
	RzILOpPure *s = SN(32, (st32)ISA2IMM(hi, 's'));
	const HexOp *Rd_op = ISA2REG(hi, 'd', false);

	// EA = ((ut32) Rx);
	RzILOpEffect *op_ASSIGN_3 = SETL("EA", CAST(32, IL_FALSE, READ_REG(pkt, Rx_op, false)));

	// s = s;
	RzILOpEffect *imm_assign_9 = SETL("s", s);

	// Rx = Rx + s;
	RzILOpPure *op_ADD_11 = ADD(READ_REG(pkt, Rx_op, false), VARL("s"));
	RzILOpEffect *op_ASSIGN_12 = WRITE_REG(bundle, Rx_op, op_ADD_11);

	// Rd = ((st32) ((ut16) mem_load_16(EA)));
	RzILOpPure *ml_EA_15 = LOADW(16, VARL("EA"));
	RzILOpEffect *op_ASSIGN_18 = WRITE_REG(bundle, Rd_op, CAST(32, IL_FALSE, CAST(16, IL_FALSE, ml_EA_15)));

	// nop;
	RzILOpEffect *nop_19 = NOP();

	// seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))));
	RzILOpEffect *seq_then_21 = SEQN(2, op_ASSIGN_12, op_ASSIGN_18);

	// seq(nop);
	RzILOpEffect *seq_else_22 = nop_19;

	// if ((((st32) Pt_new) & 0x1)) {seq(Rx = Rx + s; Rd = ((st32) ((ut16) mem_load_16(EA))))} else {seq(nop)};
	RzILOpPure *op_AND_8 = LOGAND(CAST(32, MSB(Pt_new), DUP(Pt_new)), SN(32, 1));
	RzILOpEffect *branch_23 = BRANCH(NON_ZERO(op_AND_8), seq_then_21, seq_else_22);

	RzILOpEffect *instruction_sequence = SEQN(3, imm_assign_9, op_ASSIGN_3, branch_23);
	return instruction_sequence;
}

#include <rz_il/rz_il_opbuilder_end.h>