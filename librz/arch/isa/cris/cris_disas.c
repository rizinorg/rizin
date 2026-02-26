// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cris_disas.c
 * \brief Clean-room CRIS disassembler for CRISv10 and CRISv32.
 *
 * Uses a match/lose bitmask table to decode instructions.
 * An instruction word `w` matches when: (w & (match | lose)) == match
 */

#include <rz_types.h>
#include <rz_util.h>
#include "cris.h"

/* Operand format codes:
 * "m r,R"  = sized reg,reg            (size in [5:4])
 * "z r,R"  = sized reg,reg            (size in [4] only, byte/word)
 * "m s,R"  = sized [mem],reg          (indirect, autoincr determined by [11:10])
 * "m S,D"  = sized [mem],reg          (prefix variant)
 * "r,R"    = reg,reg (fixed size)
 * "r,P"    = reg,preg
 * "P,r"    = preg,reg
 * "I,R"    = 6-bit unsigned imm,reg
 * "i,R"    = 6-bit signed imm,reg
 * "c,R"    = 5-bit unsigned imm,reg (shift count)
 * "Q,A"    = 8-bit signed offset to ACR
 * "N"      = 32-bit absolute (following dword)
 * "n"      = 32-bit relative offset
 * "b"      = 16-bit relative offset (following word)
 * "f"      = flag bits
 * "C"      = 4-bit break number
 */

/**
 * Opcode table entry for match/lose decoding.
 */
typedef struct {
	const char *name;
	ut16 match;
	ut16 lose;
	CrisInsnType type;
	ut8 flags; ///< 0=both, 1=v10 only, 2=v32 only
#define CRIS_OP_BOTH 0
#define CRIS_OP_V10  1
#define CRIS_OP_V32  2
	ut8 extra_bytes; ///< 0, 2, or 4 extra bytes to read
#define CRIS_EXT_NONE     0
#define CRIS_EXT_FIELD    1 ///< size depends on size field
#define CRIS_EXT_FIX32    4 ///< always 4 extra bytes
#define CRIS_EXT_FIX16    2 ///< always 2 extra bytes (Bcc 16-bit)
} CrisOpcodeEntry;

/**
 * Opcode table. Order matters — first match wins.
 * More specific patterns (higher match+lose mask) should come before general ones.
 */
static const CrisOpcodeEntry cris_opcodes[] = {
	// Special instructions — most specific first
	{ "halt",   0xF930, 0x06CF, CRIS_INSN_HALT,   CRIS_OP_V32, 0 },
	{ "rfe",    0x2930, 0xD6CF, CRIS_INSN_RFE,    CRIS_OP_V32, 0 },
	{ "rfg",    0x4930, 0xB6CF, CRIS_INSN_RFG,    CRIS_OP_V32, 0 },
	{ "rfn",    0x5930, 0xA6CF, CRIS_INSN_RFN,    CRIS_OP_V32, 0 },
	{ "sfe",    0x3930, 0xC6CF, CRIS_INSN_SFE,    CRIS_OP_V32, 0 },
	{ "ret",    0xB67F, 0x4980, CRIS_INSN_RET,    CRIS_OP_V10, 0 },
	{ "ret",    0xB9F0, 0x460F, CRIS_INSN_RET,    CRIS_OP_V32, 0 },
	{ "retb",   0xE67F, 0x1980, CRIS_INSN_RETB,   CRIS_OP_V10, 0 },
	{ "reti",   0xA67F, 0x5980, CRIS_INSN_RETI,   CRIS_OP_V10, 0 },
	{ "rete",   0xA9F0, 0x560F, CRIS_INSN_RETE,   CRIS_OP_V32, 0 },
	{ "retn",   0xC9F0, 0x360F, CRIS_INSN_RETN,   CRIS_OP_V32, 0 },
	{ "break",  0xE930, 0x16C0, CRIS_INSN_BREAK,  CRIS_OP_BOTH, 0 },
	{ "nop",    0x050F, 0xFAF0, CRIS_INSN_NOP,    CRIS_OP_V10, 0 },
	{ "nop",    0x05B0, 0xFA4F, CRIS_INSN_NOP,    CRIS_OP_V32, 0 },
	{ "ax",     0x15B0, 0xEA4F, CRIS_INSN_AX,     CRIS_OP_BOTH, 0 },
	{ "ei",     0x25B0, 0xDA4F, CRIS_INSN_EI,     CRIS_OP_BOTH, 0 },
	{ "di",     0x25F0, 0xDA0F, CRIS_INSN_DI,     CRIS_OP_BOTH, 0 },

	// v32 jumps with 32-bit immediate — very specific
	{ "bsr",    0xBEBF, 0x4140, CRIS_INSN_BSR,    CRIS_OP_V32, CRIS_EXT_FIX32 },
	{ "bas",    0x0EBF, 0x0140, CRIS_INSN_BAS,    CRIS_OP_V32, CRIS_EXT_FIX32 },
	{ "jsr",    0xBDBF, 0x4240, CRIS_INSN_JSR_N,  CRIS_OP_V32, CRIS_EXT_FIX32 },
	{ "jas",    0x0DBF, 0x0240, CRIS_INSN_JAS,    CRIS_OP_V32, CRIS_EXT_FIX32 },
	{ "jasc",   0x0F3F, 0x00C0, CRIS_INSN_JASC,   CRIS_OP_V32, CRIS_EXT_FIX32 },
	{ "lapc",   0x0D7F, 0x0280, CRIS_INSN_LAPC,   CRIS_OP_V32, CRIS_EXT_FIX32 },

	// Bcc 16-bit displacement
	{ "b",      0x0DFF, 0x0200, CRIS_INSN_BCC_16, CRIS_OP_BOTH, CRIS_EXT_FIX16 },

	// jump/jsr register — most specific first (stricter lose masks first)
	{ "jump",   0x09B0, 0xF640, CRIS_INSN_JUMP_R, CRIS_OP_BOTH, 0 },
	{ "jsr",    0xB9B0, 0x4640, CRIS_INSN_JSR_R,  CRIS_OP_BOTH, 0 },
	{ "jump",   0x09F0, 0x060F, CRIS_INSN_JUMP_P, CRIS_OP_V32, 0 },
	{ "jas",    0x09B0, 0x0640, CRIS_INSN_JAS,    CRIS_OP_V32, 0 },
	{ "jasc",   0x0B30, 0x04C0, CRIS_INSN_JASC,   CRIS_OP_V32, 0 },

	// NOT / SWAP — very specific patterns
	{ "not",    0x8770, 0x7880, CRIS_INSN_NOT,    CRIS_OP_BOTH, 0 },
	{ "swapnwbr",0xF770,0x0880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapnwb",0xE770, 0x1880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapnwr",0xD770, 0x2880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapnw", 0xC770, 0x3880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapnbr",0xB770, 0x4880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapnb", 0xA770, 0x5880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapnr", 0x9770, 0x6880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapn",  0x8770, 0x7880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapwbr",0x7770, 0x8880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapwb", 0x6770, 0x9880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapwr", 0x5770, 0xA880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapw",  0x4770, 0xB880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapbr", 0x3770, 0xC880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapb",  0x2770, 0xD880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },
	{ "swapr",  0x1770, 0xE880, CRIS_INSN_SWAP,  CRIS_OP_BOTH, 0 },

	// Special register moves — before generic moves
	{ "move",   0x0630, 0x09C0, CRIS_INSN_MOVE_RP, CRIS_OP_BOTH, 0 }, // r,P
	{ "move",   0x0670, 0x0980, CRIS_INSN_MOVE_PR, CRIS_OP_BOTH, 0 }, // P,r
	{ "mcp",    0x07F0, 0x0800, CRIS_INSN_MCP,     CRIS_OP_V32, 0 },

	// abs, dstep, lz — very specific
	{ "abs",    0x06B0, 0x0940, CRIS_INSN_ABS,    CRIS_OP_BOTH, 0 },
	{ "dstep",  0x06F0, 0x0900, CRIS_INSN_DSTEP,  CRIS_OP_BOTH, 0 },
	{ "lz",     0x0730, 0x08C0, CRIS_INSN_LZ,     CRIS_OP_V32, 0 },
	{ "xor",    0x07B0, 0x0840, CRIS_INSN_XOR,    CRIS_OP_BOTH, 0 },
	{ "btst",   0x04F0, 0x0B00, CRIS_INSN_BTST,   CRIS_OP_BOTH, 0 },
	{ "addc",   0x0570, 0x0A80, CRIS_INSN_ADDC,   CRIS_OP_V32, 0 },
	{ "muls",   0x0D00, 0x02C0, CRIS_INSN_MULS,   CRIS_OP_BOTH, 0 },
	{ "mulu",   0x0900, 0x06C0, CRIS_INSN_MULU,   CRIS_OP_BOTH, 0 },

	// LAPCQ (v32)
	{ "lapcq",  0x0970, 0x0680, CRIS_INSN_LAPCQ,  CRIS_OP_V32, 0 },

	// SETF/CLEARF — must come before register ops (size=11 overlaps with reg ops)
	{ "setf",   0x05B0, 0x0A40, CRIS_INSN_SETF,    CRIS_OP_BOTH, 0 },
	{ "clearf", 0x05F0, 0x0A00, CRIS_INSN_CLEARF,  CRIS_OP_BOTH, 0 },

	// ADDI — before generic register ops
	{ "addi",   0x0540, 0x0A80, CRIS_INSN_ADDI,   CRIS_OP_V32, 0 },
	{ "addi",   0x0500, 0x0AC0, CRIS_INSN_ADDI,   CRIS_OP_V10, 0 },

	// Register-register operations (sized: m r,R)
	{ "add",    0x0600, 0x09C0, CRIS_INSN_ADD,    CRIS_OP_BOTH, 0 },
	{ "move",   0x0640, 0x0980, CRIS_INSN_MOVE_R, CRIS_OP_BOTH, 0 },
	{ "sub",    0x0680, 0x0940, CRIS_INSN_SUB,    CRIS_OP_BOTH, 0 },
	{ "cmp",    0x06C0, 0x0900, CRIS_INSN_CMP,    CRIS_OP_BOTH, 0 },
	{ "and",    0x0700, 0x08C0, CRIS_INSN_AND,    CRIS_OP_BOTH, 0 },
	{ "or",     0x0740, 0x0880, CRIS_INSN_OR,     CRIS_OP_BOTH, 0 },
	{ "asr",    0x0780, 0x0840, CRIS_INSN_ASR,    CRIS_OP_BOTH, 0 },
	{ "lsl",    0x04C0, 0x0B00, CRIS_INSN_LSL,    CRIS_OP_BOTH, 0 },
	{ "lsr",    0x07C0, 0x0800, CRIS_INSN_LSR,    CRIS_OP_BOTH, 0 },
	{ "bound",  0x05C0, 0x0A00, CRIS_INSN_BOUND,  CRIS_OP_BOTH, 0 },
	{ "neg",    0x0580, 0x0A40, CRIS_INSN_NEG,    CRIS_OP_BOTH, 0 },

	// Sized register ops (z r,R — byte/word only)
	{ "adds",   0x0420, 0x0BC0, CRIS_INSN_ADDS,   CRIS_OP_BOTH, 0 },
	{ "addu",   0x0400, 0x0BE0, CRIS_INSN_ADDU,   CRIS_OP_BOTH, 0 },
	{ "subs",   0x04A0, 0x0B40, CRIS_INSN_SUBS,   CRIS_OP_BOTH, 0 },
	{ "subu",   0x0480, 0x0B60, CRIS_INSN_SUBU,   CRIS_OP_BOTH, 0 },
	{ "movs",   0x0460, 0x0B80, CRIS_INSN_MOVS,   CRIS_OP_BOTH, 0 },
	{ "movu",   0x0440, 0x0BA0, CRIS_INSN_MOVU,   CRIS_OP_BOTH, 0 },

	// Memory operations (m s,R — indirect)
	{ "add",    0x0A00, 0x01C0, CRIS_INSN_ADD_M,    CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "move",   0x0A40, 0x0180, CRIS_INSN_MOVE_MR,  CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "sub",    0x0A80, 0x0140, CRIS_INSN_SUB_M,    CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "cmp",    0x0AC0, 0x0100, CRIS_INSN_CMP_M,    CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "and",    0x0B00, 0x00C0, CRIS_INSN_AND_M,    CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "or",     0x0B40, 0x0080, CRIS_INSN_OR_M,     CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "test",   0x0B80, 0xF040, CRIS_INSN_TEST_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	// MOVEM — must come before MOVE_RM (MOVEM_RM is more specific)
	{ "movem",  0x0BF0, 0x0000, CRIS_INSN_MOVEM_RM, CRIS_OP_BOTH, 0 }, // R,[mem]
	{ "movem",  0x0BB0, 0x0040, CRIS_INSN_MOVEM_MR, CRIS_OP_BOTH, 0 }, // [mem],R
	{ "move",   0x0BC0, 0x0000, CRIS_INSN_MOVE_RM,  CRIS_OP_BOTH, CRIS_EXT_FIELD }, // R,[mem]
	{ "bound",  0x09C0, 0x0200, CRIS_INSN_BOUND_M,  CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "adds",   0x0820, 0x03C0, CRIS_INSN_ADDS_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "addu",   0x0800, 0x03E0, CRIS_INSN_ADDU_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "subs",   0x08A0, 0x0340, CRIS_INSN_SUBS_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "subu",   0x0880, 0x0360, CRIS_INSN_SUBU_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "cmps",   0x08E0, 0x0300, CRIS_INSN_CMPS_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "cmpu",   0x08C0, 0x0320, CRIS_INSN_CMPU_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "movs",   0x0860, 0x0380, CRIS_INSN_MOVS_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },
	{ "movu",   0x0840, 0x03A0, CRIS_INSN_MOVU_M,   CRIS_OP_BOTH, CRIS_EXT_FIELD },

	// Special register moves with memory
	{ "move",   0x0A30, 0x01C0, CRIS_INSN_MOVE_MP,  CRIS_OP_BOTH, CRIS_EXT_FIELD }, // [mem],P
	{ "move",   0x0A70, 0x0180, CRIS_INSN_MOVE_PM,  CRIS_OP_BOTH, CRIS_EXT_FIELD }, // P,[mem]

	// Clear
	{ "clear",  0x0670, 0x3980, CRIS_INSN_CLEAR_R,  CRIS_OP_BOTH, 0 },
	{ "clear",  0x0A70, 0x3180, CRIS_INSN_CLEAR_M,  CRIS_OP_BOTH, 0 },

	// ADDO (v32) — memory ops with ACR
	{ "addo",   0x0940, 0x0280, CRIS_INSN_ADDO,     CRIS_OP_V32, CRIS_EXT_FIELD },
	{ "addc",   0x09A0, 0x0250, CRIS_INSN_ADDC_M,   CRIS_OP_V32, CRIS_EXT_FIELD },

	// JSR [mem] (v10)
	{ "jsr",    0xB930, 0x42C0, CRIS_INSN_JSR_M,    CRIS_OP_BOTH, CRIS_EXT_FIELD },

	// DIV (v10+)
	{ "div",    0x0980, 0x0640, CRIS_INSN_DSTEP,    CRIS_OP_BOTH, CRIS_EXT_FIELD },

	// Quick immediates — must come after more specific patterns
	{ "addq",   0x0200, 0x0DC0, CRIS_INSN_ADDQ,    CRIS_OP_BOTH, 0 },
	{ "subq",   0x0280, 0x0D40, CRIS_INSN_SUBQ,    CRIS_OP_BOTH, 0 },
	{ "moveq",  0x0240, 0x0D80, CRIS_INSN_MOVEQ,   CRIS_OP_BOTH, 0 },
	{ "cmpq",   0x02C0, 0x0D00, CRIS_INSN_CMPQ,    CRIS_OP_BOTH, 0 },
	{ "andq",   0x0300, 0x0CC0, CRIS_INSN_ANDQ,    CRIS_OP_BOTH, 0 },
	{ "orq",    0x0340, 0x0C80, CRIS_INSN_ORQ,     CRIS_OP_BOTH, 0 },
	{ "btstq",  0x0380, 0x0C60, CRIS_INSN_BTSTQ,   CRIS_OP_BOTH, 0 },
	{ "asrq",   0x03A0, 0x0C40, CRIS_INSN_ASRQ,    CRIS_OP_BOTH, 0 },
	{ "lslq",   0x03C0, 0x0C20, CRIS_INSN_LSLQ,    CRIS_OP_BOTH, 0 },
	{ "lsrq",   0x03E0, 0x0C00, CRIS_INSN_LSRQ,    CRIS_OP_BOTH, 0 },

	// ADDOQ / BDAP quick
	{ "addoq",  0x0100, 0x0E00, CRIS_INSN_ADDOQ,   CRIS_OP_V32, 0 },
	{ "bdap",   0x0100, 0x0E00, CRIS_INSN_BDAP_Q,  CRIS_OP_V10, 0 },

	// Scc (set on condition) — needs to be checked more carefully
	// Encoding overlaps with other patterns; usually 0x0X30 patterns
	// For now skip Scc as it has complex encoding

	// Branch quick — must come LAST as it's the most general
	{ "b",      0x0000, 0x0F00, CRIS_INSN_BCC_8,   CRIS_OP_BOTH, 0 },

	{ NULL, 0, 0, CRIS_INSN_UNKNOWN, 0, 0 },
};

/**
 * Check if an opcode entry version is compatible with current ISA version.
 */
static bool version_ok(ut8 opflags, CrisIsaVersion ver) {
	if (opflags == CRIS_OP_BOTH) return true;
	if (opflags == CRIS_OP_V10 && ver == CRIS_ISA_V10) return true;
	if (opflags == CRIS_OP_V32 && ver == CRIS_ISA_V32) return true;
	return false;
}

/**
 * Read an extension word/dword based on size field.
 */
static int read_extension(const ut8 *buf, int len, CrisSizeModifier sz, st32 *val) {
	switch (sz) {
	case CRIS_SIZE_BYTE:
	case CRIS_SIZE_WORD:
		if (len < 2) return -1;
		if (sz == CRIS_SIZE_BYTE) {
			*val = (st32)(st8)(rz_read_le16(buf) & 0xFF);
		} else {
			*val = (st32)(st16)rz_read_le16(buf);
		}
		return 2;
	case CRIS_SIZE_DWORD:
	case CRIS_SIZE_FIXED:
		if (len < 4) return -1;
		*val = (st32)rz_read_le32(buf);
		return 4;
	}
	return -1;
}

static int read_extension_unsigned(const ut8 *buf, int len, CrisSizeModifier sz, st32 *val) {
	switch (sz) {
	case CRIS_SIZE_BYTE:
	case CRIS_SIZE_WORD:
		if (len < 2) return -1;
		if (sz == CRIS_SIZE_BYTE) {
			*val = rz_read_le16(buf) & 0xFF;
		} else {
			*val = rz_read_le16(buf);
		}
		return 2;
	case CRIS_SIZE_DWORD:
	case CRIS_SIZE_FIXED:
		if (len < 4) return -1;
		*val = (st32)rz_read_le32(buf);
		return 4;
	}
	return -1;
}

int cris_decode(const ut8 *buf, int len, CrisInsn *insn, CrisIsaVersion ver) {
	if (len < 2) {
		return -1;
	}

	memset(insn, 0, sizeof(CrisInsn));
	ut16 w = rz_read_le16(buf);
	insn->raw = w;
	insn->size = 2;
	insn->reg1 = CRIS_REG1(w);
	insn->reg2 = CRIS_REG2(w);
	insn->sz = CRIS_SIZE(w);

	// Try each opcode entry
	for (const CrisOpcodeEntry *op = cris_opcodes; op->name != NULL; op++) {
		// Match: all match bits must be set, all lose bits must be clear
		if ((w & (op->match | op->lose)) != op->match) {
			continue;
		}
		if (!version_ok(op->flags, ver)) {
			continue;
		}

		insn->type = op->type;

		// Decode based on instruction type
		switch (insn->type) {
		// Quick immediates (6-bit)
		case CRIS_INSN_ADDQ:
		case CRIS_INSN_SUBQ:
			insn->immediate = w & 0x3F;
			break;
		case CRIS_INSN_MOVEQ:
		case CRIS_INSN_CMPQ:
		case CRIS_INSN_ANDQ:
		case CRIS_INSN_ORQ:
			insn->immediate = cris_sign_ext6(w & 0x3F);
			break;

		// Shift quick (5-bit count)
		case CRIS_INSN_ASRQ:
		case CRIS_INSN_LSLQ:
		case CRIS_INSN_LSRQ:
		case CRIS_INSN_BTSTQ:
			insn->immediate = w & 0x1F;
			break;

		// Branch quick (8-bit signed displacement)
		case CRIS_INSN_BCC_8:
			insn->cond = CRIS_REG2(w);
			insn->immediate = cris_sign_ext8(w & 0xFF);
			break;

		// Branch 16-bit
		case CRIS_INSN_BCC_16:
			insn->cond = CRIS_REG2(w);
			if (len >= 4) {
				insn->immediate = (st16)rz_read_le16(buf + 2);
				insn->size = 4;
			}
			break;

		// 32-bit immediate/displacement
		case CRIS_INSN_BSR:
		case CRIS_INSN_BAS:
		case CRIS_INSN_BA_DWORD:
		case CRIS_INSN_JSR_N:
		case CRIS_INSN_JUMP_N:
		case CRIS_INSN_LAPC:
			if (len >= 6) {
				insn->immediate = (st32)rz_read_le32(buf + 2);
				insn->size = 6;
			}
			if (insn->type == CRIS_INSN_BAS) {
				insn->spec_reg = CRIS_REG2(w);
			}
			break;

		case CRIS_INSN_JAS:
		case CRIS_INSN_JASC:
			insn->spec_reg = CRIS_REG2(w);
			if (op->extra_bytes == CRIS_EXT_FIX32) {
				// [PC+] form: dword immediate
				if (len >= 6) {
					insn->immediate = (st32)rz_read_le32(buf + 2);
					insn->size = 6;
				}
			}
			break;

		// Register-register (sized)
		case CRIS_INSN_ADD:
		case CRIS_INSN_SUB:
		case CRIS_INSN_CMP:
		case CRIS_INSN_AND:
		case CRIS_INSN_OR:
		case CRIS_INSN_ASR:
		case CRIS_INSN_LSL:
		case CRIS_INSN_LSR:
		case CRIS_INSN_BOUND:
		case CRIS_INSN_NEG:
		case CRIS_INSN_MOVE_R:
		case CRIS_INSN_MULS:
		case CRIS_INSN_MULU:
			// sz already set from CRIS_SIZE(w)
			break;

		// Register ops (byte/word only)
		case CRIS_INSN_ADDS:
		case CRIS_INSN_ADDU:
		case CRIS_INSN_SUBS:
		case CRIS_INSN_SUBU:
		case CRIS_INSN_MOVS:
		case CRIS_INSN_MOVU:
			// Size is bit[4] only: 0=byte, 1=word
			insn->sz = (w & 0x10) ? CRIS_SIZE_WORD : CRIS_SIZE_BYTE;
			break;

		// Jump/JSR register — register in bits[3:0]
		case CRIS_INSN_JUMP_R:
		case CRIS_INSN_JSR_R:
			insn->reg1 = CRIS_REG1(w);
			break;

		case CRIS_INSN_JUMP_P:
			insn->spec_reg = (w >> 4) & 0xF;
			break;

		// Special register move
		case CRIS_INSN_MOVE_RP: // r,P
			insn->spec_reg = CRIS_REG2(w);
			insn->reg1 = CRIS_REG1(w);
			break;
		case CRIS_INSN_MOVE_PR: // P,r
			insn->spec_reg = CRIS_REG2(w);
			insn->reg1 = CRIS_REG1(w);
			break;
		case CRIS_INSN_MCP:
			insn->spec_reg = CRIS_REG2(w);
			insn->reg1 = CRIS_REG1(w);
			break;

		// Memory operations — determine addressing mode
		case CRIS_INSN_ADD_M:
		case CRIS_INSN_MOVE_MR:
		case CRIS_INSN_SUB_M:
		case CRIS_INSN_CMP_M:
		case CRIS_INSN_AND_M:
		case CRIS_INSN_OR_M:
		case CRIS_INSN_MOVE_RM:
		case CRIS_INSN_BOUND_M:
		case CRIS_INSN_ADDS_M:
		case CRIS_INSN_ADDU_M:
		case CRIS_INSN_SUBS_M:
		case CRIS_INSN_SUBU_M:
		case CRIS_INSN_CMPS_M:
		case CRIS_INSN_CMPU_M:
		case CRIS_INSN_MOVS_M:
		case CRIS_INSN_MOVU_M:
		case CRIS_INSN_TEST_M:
		case CRIS_INSN_MOVE_MP:
		case CRIS_INSN_MOVE_PM:
		case CRIS_INSN_ADDO:
		case CRIS_INSN_ADDC_M:
		case CRIS_INSN_JSR_M:
		case CRIS_INSN_CLEAR_M: {
			// Addressing mode from bits [11:10]
			ut8 mode = CRIS_MODE(w);
			insn->autoincr = (mode == 3);
			if (mode >= 2) {
				insn->addr_mode = insn->autoincr ? CRIS_ADDR_IND_POST : CRIS_ADDR_IND;
			}

			// For byte/word sub-operations
			if (insn->type == CRIS_INSN_ADDS_M || insn->type == CRIS_INSN_ADDU_M ||
				insn->type == CRIS_INSN_SUBS_M || insn->type == CRIS_INSN_SUBU_M ||
				insn->type == CRIS_INSN_CMPS_M || insn->type == CRIS_INSN_CMPU_M ||
				insn->type == CRIS_INSN_MOVS_M || insn->type == CRIS_INSN_MOVU_M) {
				insn->sz = (w & 0x20) ? CRIS_SIZE_WORD : CRIS_SIZE_BYTE;
			}

			// Read extension if [PC+] (autoincr with Rs=15)
			if (insn->autoincr && insn->reg1 == 0xF && op->extra_bytes == CRIS_EXT_FIELD) {
				int ext = read_extension_unsigned(buf + 2, len - 2, insn->sz, &insn->immediate);
				if (ext > 0) {
					insn->size += ext;
				}
			}
			break;
		}

		// MOVEM
		case CRIS_INSN_MOVEM_MR:
		case CRIS_INSN_MOVEM_RM: {
			ut8 mode = CRIS_MODE(w);
			insn->autoincr = (mode == 3);
			insn->addr_mode = insn->autoincr ? CRIS_ADDR_IND_POST : CRIS_ADDR_IND;
			insn->sz = CRIS_SIZE_FIXED;
			break;
		}

		// NOT / SWAP — register in bits[3:0]
		case CRIS_INSN_NOT:
			insn->reg1 = CRIS_REG1(w);
			break;
		case CRIS_INSN_SWAP:
			insn->reg1 = CRIS_REG1(w);
			// swap type bits from match pattern: [15:12] determines n/w/b/r combo
			insn->swap_bits = CRIS_REG2(w);
			break;

		// BREAK — break number in bits[3:0]
		case CRIS_INSN_BREAK:
			insn->immediate = CRIS_REG1(w);
			break;

		// SETF/CLEARF
		case CRIS_INSN_SETF:
		case CRIS_INSN_CLEARF:
			insn->flags_bits = ((w >> 12) & 0xF) | ((w & 0xF) << 4);
			break;

		// Clear register
		case CRIS_INSN_CLEAR_R:
			break;

		// ADDOQ / BDAP quick
		case CRIS_INSN_ADDOQ:
		case CRIS_INSN_BDAP_Q:
			insn->immediate = cris_sign_ext8(w & 0xFF);
			break;

		// LAPCQ
		case CRIS_INSN_LAPCQ:
			insn->immediate = (w & 0xF) * 2;
			break;

		// ABS / DSTEP / LZ / XOR / BTST / ADDC
		case CRIS_INSN_ABS:
		case CRIS_INSN_DSTEP:
		case CRIS_INSN_LZ:
		case CRIS_INSN_XOR:
		case CRIS_INSN_BTST:
		case CRIS_INSN_ADDC:
		case CRIS_INSN_ADDI:
			break;

		// Everything else
		default:
			break;
		}

		return insn->size;
	}

	// No match — unknown instruction
	insn->type = CRIS_INSN_UNKNOWN;
	insn->size = 2;
	return 2;
}

/**
 * Get the name of a special register.
 */
static const char *spec_reg_name(ut8 num, CrisIsaVersion ver) {
	if (num > 15) {
		return "p?";
	}
	return (ver == CRIS_ISA_V32) ? cris_spec_reg_names_v32[num] : cris_spec_reg_names_v10[num];
}

/**
 * Get the name of a general register.
 */
static const char *gpr_name(ut8 num, CrisIsaVersion ver) {
	if (num > 15) {
		return "r?";
	}
	return (ver == CRIS_ISA_V32) ? cris_gpr_names_v32[num] : cris_gpr_names[num];
}

/**
 * Format flags string for SETF/CLEARF.
 */
static void format_flags(RzStrBuf *out, ut8 bits) {
	if (bits & 0x01) rz_strbuf_append(out, "c");
	if (bits & 0x02) rz_strbuf_append(out, "v");
	if (bits & 0x04) rz_strbuf_append(out, "z");
	if (bits & 0x08) rz_strbuf_append(out, "n");
	if (bits & 0x10) rz_strbuf_append(out, "x");
	if (bits & 0x20) rz_strbuf_append(out, "i");
	if (bits & 0x40) rz_strbuf_append(out, "u");
	if (bits & 0x80) rz_strbuf_append(out, "b");
}

/**
 * Swap instruction name from swap_bits.
 */
static const char *swap_name(ut8 bits) {
	static const char *names[] = {
		"swap", "swapr", "swapb", "swapbr",
		"swapw", "swapwr", "swapwb", "swapwbr",
		"swapn", "swapnr", "swapnb", "swapnbr",
		"swapnw", "swapnwr", "swapnwb", "swapnwbr",
	};
	return (bits < 16) ? names[bits] : "swap?";
}

int cris_disassemble(const CrisInsn *insn, RzStrBuf *out, CrisIsaVersion ver) {
	const char *r1 = gpr_name(insn->reg1, ver);
	const char *r2 = gpr_name(insn->reg2, ver);
	const char *szs = cris_size_suffix[insn->sz];

	switch (insn->type) {
	// Quick immediates
	case CRIS_INSN_ADDQ:
		rz_strbuf_setf(out, "addq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_SUBQ:
		rz_strbuf_setf(out, "subq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_MOVEQ:
		rz_strbuf_setf(out, "moveq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_CMPQ:
		rz_strbuf_setf(out, "cmpq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_ANDQ:
		rz_strbuf_setf(out, "andq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_ORQ:
		rz_strbuf_setf(out, "orq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_BTSTQ:
		rz_strbuf_setf(out, "btstq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_ASRQ:
		rz_strbuf_setf(out, "asrq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_LSLQ:
		rz_strbuf_setf(out, "lslq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_LSRQ:
		rz_strbuf_setf(out, "lsrq %d,%s", insn->immediate, r2);
		break;

	// Register-register ops
	case CRIS_INSN_ADD:
		rz_strbuf_setf(out, "add%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_SUB:
		rz_strbuf_setf(out, "sub%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_CMP:
		rz_strbuf_setf(out, "cmp%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_AND:
		rz_strbuf_setf(out, "and%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_OR:
		rz_strbuf_setf(out, "or%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_XOR:
		rz_strbuf_setf(out, "xor %s,%s", r1, r2);
		break;
	case CRIS_INSN_MOVE_R:
		rz_strbuf_setf(out, "move%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_ABS:
		rz_strbuf_setf(out, "abs %s,%s", r1, r2);
		break;
	case CRIS_INSN_NEG:
		rz_strbuf_setf(out, "neg%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_NOT:
		rz_strbuf_setf(out, "not %s", gpr_name(insn->reg1, ver));
		break;
	case CRIS_INSN_BTST:
		rz_strbuf_setf(out, "btst %s,%s", r1, r2);
		break;
	case CRIS_INSN_BOUND:
		rz_strbuf_setf(out, "bound%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_DSTEP:
		rz_strbuf_setf(out, "dstep %s,%s", r1, r2);
		break;
	case CRIS_INSN_LZ:
		rz_strbuf_setf(out, "lz %s,%s", r1, r2);
		break;
	case CRIS_INSN_MULS:
		rz_strbuf_setf(out, "muls%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_MULU:
		rz_strbuf_setf(out, "mulu%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_ASR:
		rz_strbuf_setf(out, "asr%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_LSL:
		rz_strbuf_setf(out, "lsl%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_LSR:
		rz_strbuf_setf(out, "lsr%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_ADDC:
		rz_strbuf_setf(out, "addc %s,%s", r1, r2);
		break;
	case CRIS_INSN_MCP:
		rz_strbuf_setf(out, "mcp %s,%s", spec_reg_name(insn->spec_reg, ver), r1);
		break;
	case CRIS_INSN_ADDS:
		rz_strbuf_setf(out, "adds%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_ADDU:
		rz_strbuf_setf(out, "addu%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_SUBS:
		rz_strbuf_setf(out, "subs%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_SUBU:
		rz_strbuf_setf(out, "subu%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_MOVS:
		rz_strbuf_setf(out, "movs%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_MOVU:
		rz_strbuf_setf(out, "movu%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_CMPS:
		rz_strbuf_setf(out, "cmps%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_CMPU:
		rz_strbuf_setf(out, "cmpu%s %s,%s", szs, r1, r2);
		break;
	case CRIS_INSN_SWAP:
		rz_strbuf_setf(out, "%s %s", swap_name(insn->swap_bits), gpr_name(insn->reg1, ver));
		break;
	case CRIS_INSN_ADDI:
		if (ver == CRIS_ISA_V32) {
			rz_strbuf_setf(out, "addi %s.%c,%s,acr", r2,
				(insn->sz == CRIS_SIZE_BYTE) ? 'b' : (insn->sz == CRIS_SIZE_WORD) ? 'w' : 'd', r1);
		} else {
			rz_strbuf_setf(out, "addi %s.%c,%s", r2,
				(insn->sz == CRIS_SIZE_BYTE) ? 'b' : (insn->sz == CRIS_SIZE_WORD) ? 'w' : 'd', r1);
		}
		break;

	// Memory operations
	case CRIS_INSN_ADD_M:
	case CRIS_INSN_SUB_M:
	case CRIS_INSN_CMP_M:
	case CRIS_INSN_AND_M:
	case CRIS_INSN_OR_M: {
		const char *mnem = "add";
		if (insn->type == CRIS_INSN_SUB_M) mnem = "sub";
		else if (insn->type == CRIS_INSN_CMP_M) mnem = "cmp";
		else if (insn->type == CRIS_INSN_AND_M) mnem = "and";
		else if (insn->type == CRIS_INSN_OR_M) mnem = "or";

		if (insn->autoincr && insn->reg1 == 0xF) {
			rz_strbuf_setf(out, "%s%s 0x%x,%s", mnem, szs, (ut32)insn->immediate, r2);
		} else if (insn->autoincr) {
			rz_strbuf_setf(out, "%s%s [%s+],%s", mnem, szs, r1, r2);
		} else {
			rz_strbuf_setf(out, "%s%s [%s],%s", mnem, szs, r1, r2);
		}
		break;
	}
	case CRIS_INSN_MOVE_MR:
		if (insn->autoincr && insn->reg1 == 0xF) {
			rz_strbuf_setf(out, "move%s 0x%x,%s", szs, (ut32)insn->immediate, r2);
		} else if (insn->autoincr) {
			rz_strbuf_setf(out, "move%s [%s+],%s", szs, r1, r2);
		} else {
			rz_strbuf_setf(out, "move%s [%s],%s", szs, r1, r2);
		}
		break;
	case CRIS_INSN_MOVE_RM:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "move%s %s,[%s+]", szs, r2, r1);
		} else {
			rz_strbuf_setf(out, "move%s %s,[%s]", szs, r2, r1);
		}
		break;
	case CRIS_INSN_MOVEM_MR:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "movem [%s+],%s", r1, r2);
		} else {
			rz_strbuf_setf(out, "movem [%s],%s", r1, r2);
		}
		break;
	case CRIS_INSN_MOVEM_RM:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "movem %s,[%s+]", r2, r1);
		} else {
			rz_strbuf_setf(out, "movem %s,[%s]", r2, r1);
		}
		break;
	case CRIS_INSN_MOVE_MP:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "move [%s+],%s", r1, spec_reg_name(insn->spec_reg, ver));
		} else {
			rz_strbuf_setf(out, "move [%s],%s", r1, spec_reg_name(insn->spec_reg, ver));
		}
		break;
	case CRIS_INSN_MOVE_PM:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "move %s,[%s+]", spec_reg_name(insn->spec_reg, ver), r1);
		} else {
			rz_strbuf_setf(out, "move %s,[%s]", spec_reg_name(insn->spec_reg, ver), r1);
		}
		break;
	case CRIS_INSN_MOVE_RP:
		rz_strbuf_setf(out, "move %s,%s", gpr_name(insn->reg1, ver), spec_reg_name(insn->spec_reg, ver));
		break;
	case CRIS_INSN_MOVE_PR:
		rz_strbuf_setf(out, "move %s,%s", spec_reg_name(insn->spec_reg, ver), gpr_name(insn->reg1, ver));
		break;
	case CRIS_INSN_TEST_M:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "test%s [%s+]", szs, r1);
		} else {
			rz_strbuf_setf(out, "test%s [%s]", szs, r1);
		}
		break;
	case CRIS_INSN_CLEAR_R:
		rz_strbuf_setf(out, "clear%s %s", szs, r2);
		break;
	case CRIS_INSN_CLEAR_M:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "clear%s [%s+]", szs, r1);
		} else {
			rz_strbuf_setf(out, "clear%s [%s]", szs, r1);
		}
		break;
	case CRIS_INSN_BOUND_M:
		if (insn->autoincr && insn->reg1 == 0xF) {
			rz_strbuf_setf(out, "bound%s 0x%x,%s", szs, (ut32)insn->immediate, r2);
		} else if (insn->autoincr) {
			rz_strbuf_setf(out, "bound%s [%s+],%s", szs, r1, r2);
		} else {
			rz_strbuf_setf(out, "bound%s [%s],%s", szs, r1, r2);
		}
		break;
	case CRIS_INSN_ADDS_M:
	case CRIS_INSN_ADDU_M:
	case CRIS_INSN_SUBS_M:
	case CRIS_INSN_SUBU_M:
	case CRIS_INSN_CMPS_M:
	case CRIS_INSN_CMPU_M:
	case CRIS_INSN_MOVS_M:
	case CRIS_INSN_MOVU_M: {
		const char *mnem = "adds";
		if (insn->type == CRIS_INSN_ADDU_M) mnem = "addu";
		else if (insn->type == CRIS_INSN_SUBS_M) mnem = "subs";
		else if (insn->type == CRIS_INSN_SUBU_M) mnem = "subu";
		else if (insn->type == CRIS_INSN_CMPS_M) mnem = "cmps";
		else if (insn->type == CRIS_INSN_CMPU_M) mnem = "cmpu";
		else if (insn->type == CRIS_INSN_MOVS_M) mnem = "movs";
		else if (insn->type == CRIS_INSN_MOVU_M) mnem = "movu";

		if (insn->autoincr) {
			rz_strbuf_setf(out, "%s%s [%s+],%s", mnem, szs, r1, r2);
		} else {
			rz_strbuf_setf(out, "%s%s [%s],%s", mnem, szs, r1, r2);
		}
		break;
	}

	// Branch and jump
	case CRIS_INSN_BCC_8:
	case CRIS_INSN_BCC_16: {
		const char **names = (ver == CRIS_ISA_V32) ? cris_cc_names_v32 : cris_cc_names;
		if (insn->cond == CRIS_CC_A) {
			rz_strbuf_setf(out, "ba %d", insn->immediate);
		} else {
			rz_strbuf_setf(out, "b%s %d", names[insn->cond], insn->immediate);
		}
		break;
	}
	case CRIS_INSN_BA_DWORD:
		rz_strbuf_setf(out, "ba 0x%x", (ut32)insn->immediate);
		break;
	case CRIS_INSN_BAS:
		rz_strbuf_setf(out, "bas 0x%x,%s",
			(ut32)insn->immediate, spec_reg_name(insn->spec_reg, ver));
		break;
	case CRIS_INSN_BSR:
		rz_strbuf_setf(out, "bsr 0x%x", (ut32)insn->immediate);
		break;
	case CRIS_INSN_JUMP_R:
		rz_strbuf_setf(out, "jump %s", gpr_name(insn->reg1, ver));
		break;
	case CRIS_INSN_JUMP_P:
		rz_strbuf_setf(out, "jump %s", spec_reg_name(insn->spec_reg, ver));
		break;
	case CRIS_INSN_JUMP_N:
		rz_strbuf_setf(out, "jump 0x%x", (ut32)insn->immediate);
		break;
	case CRIS_INSN_JSR_R:
		rz_strbuf_setf(out, "jsr %s", gpr_name(insn->reg1, ver));
		break;
	case CRIS_INSN_JSR_M:
		if (insn->autoincr) {
			rz_strbuf_setf(out, "jsr [%s+]", r1);
		} else {
			rz_strbuf_setf(out, "jsr [%s]", r1);
		}
		break;
	case CRIS_INSN_JSR_N:
		rz_strbuf_setf(out, "jsr 0x%x", (ut32)insn->immediate);
		break;
	case CRIS_INSN_JAS:
		if (insn->size > 2) {
			rz_strbuf_setf(out, "jas 0x%x,%s",
				(ut32)insn->immediate, spec_reg_name(insn->spec_reg, ver));
		} else {
			rz_strbuf_setf(out, "jas %s,%s",
				r1, spec_reg_name(insn->spec_reg, ver));
		}
		break;
	case CRIS_INSN_JASC:
		if (insn->size > 2) {
			rz_strbuf_setf(out, "jasc 0x%x,%s",
				(ut32)insn->immediate, spec_reg_name(insn->spec_reg, ver));
		} else {
			rz_strbuf_setf(out, "jasc %s,%s",
				r1, spec_reg_name(insn->spec_reg, ver));
		}
		break;
	case CRIS_INSN_LAPC:
		rz_strbuf_setf(out, "lapc 0x%x,%s", (ut32)insn->immediate, r2);
		break;
	case CRIS_INSN_LAPCQ:
		rz_strbuf_setf(out, "lapcq %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_RET:
		rz_strbuf_set(out, "ret");
		break;
	case CRIS_INSN_RETI:
		rz_strbuf_set(out, "reti");
		break;
	case CRIS_INSN_RETE:
		rz_strbuf_set(out, "rete");
		break;
	case CRIS_INSN_RETN:
		rz_strbuf_set(out, "retn");
		break;
	case CRIS_INSN_RETB:
		rz_strbuf_set(out, "retb");
		break;

	// Prefix
	case CRIS_INSN_BDAP_Q:
		rz_strbuf_setf(out, "bdap %d,%s", insn->immediate, r2);
		break;
	case CRIS_INSN_ADDOQ:
		rz_strbuf_setf(out, "addoq %d,%s,acr", insn->immediate, r2);
		break;
	case CRIS_INSN_ADDO:
		rz_strbuf_setf(out, "addo%s [%s],%s,acr", szs, r1, r2);
		break;

	// Special
	case CRIS_INSN_NOP:
		rz_strbuf_set(out, "nop");
		break;
	case CRIS_INSN_BREAK:
		rz_strbuf_setf(out, "break %d", insn->immediate);
		break;
	case CRIS_INSN_HALT:
		rz_strbuf_set(out, "halt");
		break;
	case CRIS_INSN_SETF:
		rz_strbuf_set(out, "setf ");
		format_flags(out, insn->flags_bits);
		break;
	case CRIS_INSN_CLEARF:
		rz_strbuf_set(out, "clearf ");
		format_flags(out, insn->flags_bits);
		break;
	case CRIS_INSN_EI:
		rz_strbuf_set(out, "ei");
		break;
	case CRIS_INSN_DI:
		rz_strbuf_set(out, "di");
		break;
	case CRIS_INSN_AX:
		rz_strbuf_set(out, "ax");
		break;
	case CRIS_INSN_RFE:
		rz_strbuf_set(out, "rfe");
		break;
	case CRIS_INSN_RFG:
		rz_strbuf_set(out, "rfg");
		break;
	case CRIS_INSN_RFN:
		rz_strbuf_set(out, "rfn");
		break;
	case CRIS_INSN_SFE:
		rz_strbuf_set(out, "sfe");
		break;

	case CRIS_INSN_UNKNOWN:
	default:
		rz_strbuf_set(out, "invalid");
		return -1;
	}

	return insn->size;
}

int cris_disas(const ut8 *buf, int len, RzStrBuf *out, CrisIsaVersion ver, CrisInsn *insn_out) {
	CrisInsn insn;
	int ret = cris_decode(buf, len, &insn, ver);
	if (ret < 0) {
		rz_strbuf_set(out, "invalid");
		return -1;
	}
	if (insn_out) {
		*insn_out = insn;
	}
	return cris_disassemble(&insn, out, ver);
}
