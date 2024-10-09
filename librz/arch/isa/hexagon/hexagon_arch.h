// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon
#ifndef HEXAGON_ARCH_H
#define HEXAGON_ARCH_H

#include <hexagon/hexagon.h>

// The packet position indicators added to the instruction text.
typedef enum {
	SINGLE_IN_PKT,
	FIRST_IN_PKT,
	MID_IN_PKT,
	LAST_IN_PKT,
	ELOOP_0_PKT,
	ELOOP_1_PKT,
	ELOOP_01_PKT,
} HexPktSyntaxIndicator;

// The type of opcode reversing which is be done on the opcode.
typedef enum {
	HEXAGON_ANALYSIS,
	HEXAGON_DISAS,
} HexReverseAction;

/**
 * \brief Pointer to the rizin structs for disassembled and analysed instructions.
 *
 */
typedef struct {
	HexReverseAction action; // Whether ana_op, asm_op or both should be filled.
	RzAnalysisOp *ana_op;
	RzAsmOp *asm_op;
	HexState *state;
	bool pkt_fully_decoded;
} HexReversedOpcode;

#define HEX_PKT_UNK           "?   "
#define HEX_PKT_SINGLE        "[   "
#define HEX_PKT_SINGLE_UTF8   "[   "
#define HEX_PKT_FIRST_UTF8    "┌   "
#define HEX_PKT_MID_UTF8      "│   "
#define HEX_PKT_LAST_UTF8     "└   "
#define HEX_PKT_FIRST_SDK     "{   "
#define HEX_PKT_SDK_PADDING   "    "
#define HEX_PKT_LAST_SDK      " }"
#define HEX_PKT_FIRST         "/   "
#define HEX_PKT_MID           "|   "
#define HEX_PKT_LAST          "\\   "
#define HEX_PKT_ELOOP_01_UTF8 "     ∎ endloop01"
#define HEX_PKT_ELOOP_1_UTF8  "     ∎ endloop1"
#define HEX_PKT_ELOOP_0_UTF8  "     ∎ endloop0"
#define HEX_PKT_ELOOP_01      "     < endloop01"
#define HEX_PKT_ELOOP_1       "     < endloop1"
#define HEX_PKT_ELOOP_0       "     < endloop0"
#define HEX_PKT_ELOOP_01_SDK  ":endloop01"
#define HEX_PKT_ELOOP_1_SDK   ":endloop1"
#define HEX_PKT_ELOOP_0_SDK   ":endloop0"

#define HEX_PARSE_BITS_FROM_UT32(data) ((data & HEX_PARSE_BITS_MASK) >> 14)

RZ_API HexInsn *hexagon_alloc_instr();
RZ_API void hex_insn_free(RZ_NULLABLE HexInsn *i);
RZ_API HexInsnContainer *hexagon_alloc_instr_container();
RZ_API void hex_insn_container_free(RZ_NULLABLE HexInsnContainer *c);
RZ_API void hex_const_ext_free(RZ_NULLABLE HexConstExt *ce);
RZ_API HexState *hexagon_state_new();
RZ_IPI void hexagon_state_fini(RZ_NULLABLE HexState *state);
RZ_API void hexagon_reverse_opcode(HexReversedOpcode *rz_reverse, const ut64 addr, RzAsm *rz_asm, RzAnalysis *rz_analysis);
RZ_API ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p);
RZ_API HexLoopAttr hex_get_loop_flag(const HexPkt *p);
RZ_API const HexOp *hex_isa_to_reg(const HexInsn *hi, const char isa_id, bool new_reg);
RZ_API ut64 hex_isa_to_imm(const HexInsn *hi, const char isa_id);
void hex_set_hic_text(RZ_INOUT HexInsnContainer *hic);
RZ_API void hex_move_insn_container(RZ_OUT HexInsnContainer *dest, const HexInsnContainer *src);
RZ_API HexPkt *hex_get_pkt(RZ_BORROW HexState *state, const ut32 addr);
RZ_API HexInsnContainer *hex_get_hic_at_addr(HexState *state, const ut32 addr);
RZ_API const HexOp hex_nreg_to_op(const HexInsnPktBundle *bundle, const char isa_id);
RZ_IPI void hexagon_pkt_mark_tail_calls(HexPkt *pkt);
#endif
