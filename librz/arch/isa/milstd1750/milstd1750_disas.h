// SPDX-FileCopyrightText: 2026 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MILSTD1750_DISAS_H
#define RZ_MILSTD1750_DISAS_H

#include <rz_asm.h>

typedef enum {
	MIL_FMT_NONE, // no operands
	MIL_FMT_R, // ra, rb
	MIL_FMT_SR, // ra
	MIL_FMT_IMM_R, // imm (N as-is), rb
	MIL_FMT_R_IMM, // rb, imm (N+1)
	MIL_FMT_IS, // ra, imm (N+1)
	MIL_FMT_BX, // br (12+BR), rx
	MIL_FMT_B, // br (12+BR), disp (8-bit unsigned in disas; signed for branch targets)
	MIL_FMT_ICR, // disp (8-bit; signed for branch target)
	MIL_FMT_S, // BEX (4-bit N) or BIF (8-bit OE) — selected by `special`
	MIL_FMT_XIO, // ra, rx, xio_cmd (16-bit)
	MIL_FMT_MEM, // ra, rx, addr (16-bit)
	MIL_FMT_IM_OCX, // ra, opex (4-bit), imm16
	MIL_FMT_IM_0_15, // imm (N as-is), rx, addr
	MIL_FMT_IM_1_16, // imm (N+1), rx, addr
	MIL_FMT_ADDR, // rx, addr
	MIL_FMT_JUMP, // cond, rx, addr
} MilStd1750Format;

typedef struct {
	const char *mnemonic;
	MilStd1750Format format;
	ut8 size; // 2 or 4 (bytes)
	ut16 raw_w1;
	ut16 raw_w2;

	// Decoded operand fields. Only those relevant to `format` are valid.
	ut8 ra; // R, SR, IS, XIO, MEM, IM_OCX
	ut8 rb; // R, IMM_R, R_IMM
	ut8 rx; // BX, XIO, MEM, IM_0_15, IM_1_16, ADDR, JUMP
	ut8 br; // BX, B (already 12+BR)
	ut8 cond; // JUMP
	ut8 opex; // IM_OCX (selects which immediate op)
	ut8 imm8; // 8-bit immediate / displacement
	ut16 imm16; // 16-bit immediate (IM_OCX)
	ut16 addr; // 16-bit address (MEM, IM_0_15, IM_1_16, ADDR, JUMP)
	ut16 xio_cmd; // 16-bit XIO command
	ut8 special; // S format: raw opcode high byte (0x77 = BEX, 0x4F = BIF)
} MilStd1750Instruction;

// Decode `len` bytes at `buf` into `out`. Returns false if invalid or truncated.
bool rz_milstd1750_decode(const ut8 *buf, int len, MilStd1750Instruction *out);

// Render the instruction as "MNEMONIC(operands)". Caller frees.
char *rz_milstd1750_stringify(const MilStd1750Instruction *insn);

int rz_milstd1750_disasm(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len);
int rz_milstd1750_op_size(const ut8 *buf, int len);

#endif