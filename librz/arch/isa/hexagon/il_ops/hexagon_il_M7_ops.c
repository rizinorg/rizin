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

// Rdd = cmpyiw(Rss,Rtt)
RzILOpEffect *hex_il_op_m7_dcmpyiw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))))) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_ADD_45 = ADD(op_MUL_23, op_MUL_44);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, op_ADD_45);

	RzILOpEffect *instruction_sequence = op_ASSIGN_46;
	return instruction_sequence;
}

// Rxx += cmpyiw(Rss,Rtt)
RzILOpEffect *hex_il_op_m7_dcmpyiw_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff))))) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0x20));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_ADD_45 = ADD(op_MUL_23, op_MUL_44);
	RzILOpPure *op_ADD_46 = ADD(READ_REG(pkt, Rxx_op, false), op_ADD_45);
	RzILOpEffect *op_ASSIGN_ADD_47 = WRITE_REG(bundle, Rxx_op, op_ADD_46);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_47;
	return instruction_sequence;
}

// Rdd = cmpyiw(Rss,Rtt*)
RzILOpEffect *hex_il_op_m7_dcmpyiwc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_SUB_45 = SUB(op_MUL_23, op_MUL_44);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, op_SUB_45);

	RzILOpEffect *instruction_sequence = op_ASSIGN_46;
	return instruction_sequence;
}

// Rxx += cmpyiw(Rss,Rtt*)
RzILOpEffect *hex_il_op_m7_dcmpyiwc_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0x20));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_SUB_45 = SUB(op_MUL_23, op_MUL_44);
	RzILOpPure *op_ADD_46 = ADD(READ_REG(pkt, Rxx_op, false), op_SUB_45);
	RzILOpEffect *op_ASSIGN_ADD_47 = WRITE_REG(bundle, Rxx_op, op_ADD_46);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_47;
	return instruction_sequence;
}

// Rdd = cmpyrw(Rss,Rtt)
RzILOpEffect *hex_il_op_m7_dcmpyrw(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_SUB_45 = SUB(op_MUL_23, op_MUL_44);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, op_SUB_45);

	RzILOpEffect *instruction_sequence = op_ASSIGN_46;
	return instruction_sequence;
}

// Rxx += cmpyrw(Rss,Rtt)
RzILOpEffect *hex_il_op_m7_dcmpyrw_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) - ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_SUB_45 = SUB(op_MUL_23, op_MUL_44);
	RzILOpPure *op_ADD_46 = ADD(READ_REG(pkt, Rxx_op, false), op_SUB_45);
	RzILOpEffect *op_ASSIGN_ADD_47 = WRITE_REG(bundle, Rxx_op, op_ADD_46);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_47;
	return instruction_sequence;
}

// Rdd = cmpyrw(Rss,Rtt*)
RzILOpEffect *hex_il_op_m7_dcmpyrwc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rdd_op = ISA2REG(hi, 'd', false);
	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rdd = ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_ADD_45 = ADD(op_MUL_23, op_MUL_44);
	RzILOpEffect *op_ASSIGN_46 = WRITE_REG(bundle, Rdd_op, op_ADD_45);

	RzILOpEffect *instruction_sequence = op_ASSIGN_46;
	return instruction_sequence;
}

// Rxx += cmpyrw(Rss,Rtt*)
RzILOpEffect *hex_il_op_m7_dcmpyrwc_acc(HexInsnPktBundle *bundle) {
	const HexInsn *hi = bundle->insn;
	HexPkt *pkt = bundle->pkt;
	// READ
	const HexOp *Rxx_op = ISA2REG(hi, 'x', false);

	const HexOp *Rss_op = ISA2REG(hi, 's', false);
	RzILOpPure *Rss = READ_REG(pkt, Rss_op, false);
	const HexOp *Rtt_op = ISA2REG(hi, 't', false);
	RzILOpPure *Rtt = READ_REG(pkt, Rtt_op, false);

	// Rxx = Rxx + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x0) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x0) & 0xffffffff))))) + ((st64) ((st32) ((st64) ((st32) ((Rss >> 0x20) & 0xffffffff))))) * ((st64) ((st32) ((st64) ((st32) ((Rtt >> 0x20) & 0xffffffff)))));
	RzILOpPure *op_RSHIFT_5 = SHIFTRA(Rss, SN(32, 0));
	RzILOpPure *op_AND_7 = LOGAND(op_RSHIFT_5, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_16 = SHIFTRA(Rtt, SN(32, 0));
	RzILOpPure *op_AND_18 = LOGAND(op_RSHIFT_16, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_23 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_7), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))), CAST(32, MSB(DUP(op_AND_7)), DUP(op_AND_7))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_18), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))), CAST(32, MSB(DUP(op_AND_18)), DUP(op_AND_18))))));
	RzILOpPure *op_RSHIFT_27 = SHIFTRA(DUP(Rss), SN(32, 0x20));
	RzILOpPure *op_AND_29 = LOGAND(op_RSHIFT_27, SN(64, 0xffffffff));
	RzILOpPure *op_RSHIFT_37 = SHIFTRA(DUP(Rtt), SN(32, 0x20));
	RzILOpPure *op_AND_39 = LOGAND(op_RSHIFT_37, SN(64, 0xffffffff));
	RzILOpPure *op_MUL_44 = MUL(CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_29), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))), CAST(32, MSB(DUP(op_AND_29)), DUP(op_AND_29))))), CAST(64, MSB(CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(op_AND_39), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))), CAST(32, MSB(CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39)))), CAST(64, MSB(CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))), CAST(32, MSB(DUP(op_AND_39)), DUP(op_AND_39))))));
	RzILOpPure *op_ADD_45 = ADD(op_MUL_23, op_MUL_44);
	RzILOpPure *op_ADD_46 = ADD(READ_REG(pkt, Rxx_op, false), op_ADD_45);
	RzILOpEffect *op_ASSIGN_ADD_47 = WRITE_REG(bundle, Rxx_op, op_ADD_46);

	RzILOpEffect *instruction_sequence = op_ASSIGN_ADD_47;
	return instruction_sequence;
}

// Rd = cmpyiw(Rss,Rtt):<<1:sat
RzILOpEffect *hex_il_op_m7_wcmpyiw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyiw(Rss,Rtt):<<1:rnd:sat
RzILOpEffect *hex_il_op_m7_wcmpyiw_rnd(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyiw(Rss,Rtt*):<<1:sat
RzILOpEffect *hex_il_op_m7_wcmpyiwc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyiw(Rss,Rtt*):<<1:rnd:sat
RzILOpEffect *hex_il_op_m7_wcmpyiwc_rnd(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyrw(Rss,Rtt):<<1:sat
RzILOpEffect *hex_il_op_m7_wcmpyrw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyrw(Rss,Rtt):<<1:rnd:sat
RzILOpEffect *hex_il_op_m7_wcmpyrw_rnd(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyrw(Rss,Rtt*):<<1:sat
RzILOpEffect *hex_il_op_m7_wcmpyrwc(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = cmpyrw(Rss,Rtt*):<<1:rnd:sat
RzILOpEffect *hex_il_op_m7_wcmpyrwc_rnd(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

#include <rz_il/rz_il_opbuilder_end.h>