// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRIS_H
#define CRIS_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_analysis.h>

/**
 * CRIS ISA versions.
 *
 * CRIS (Code Reduced Instruction Set) is used in Axis Communications ETRAX
 * series of embedded processors.
 *
 * v10: ETRAX 100LX and predecessors
 * v32: ETRAX FS (also called "CRIS v32" or "CRISv32")
 */
typedef enum {
	CRIS_ISA_V10 = 0, ///< CRISv10 and earlier (v0-v10)
	CRIS_ISA_V32 = 1, ///< CRISv32 (ETRAX FS)
} CrisIsaVersion;

/**
 * Size modifiers encoded in bits [5:4] of the instruction word.
 */
typedef enum {
	CRIS_SIZE_BYTE = 0, ///< .b (8-bit)
	CRIS_SIZE_WORD = 1, ///< .w (16-bit)
	CRIS_SIZE_DWORD = 2, ///< .d (32-bit)
	CRIS_SIZE_FIXED = 3, ///< special / not applicable
} CrisSizeModifier;

/**
 * Condition codes for Bcc and Scc instructions.
 * Encoded in bits [15:12] of the instruction word.
 */
typedef enum {
	CRIS_CC_CC = 0x0, ///< carry clear (HS = higher or same, unsigned)
	CRIS_CC_CS = 0x1, ///< carry set (LO = lower, unsigned)
	CRIS_CC_NE = 0x2, ///< not equal (Z=0)
	CRIS_CC_EQ = 0x3, ///< equal (Z=1)
	CRIS_CC_VC = 0x4, ///< overflow clear
	CRIS_CC_VS = 0x5, ///< overflow set
	CRIS_CC_PL = 0x6, ///< plus (N=0)
	CRIS_CC_MI = 0x7, ///< minus (N=1)
	CRIS_CC_LS = 0x8, ///< lower or same (unsigned)
	CRIS_CC_HI = 0x9, ///< higher (unsigned)
	CRIS_CC_GE = 0xA, ///< greater or equal (signed)
	CRIS_CC_LT = 0xB, ///< less than (signed)
	CRIS_CC_GT = 0xC, ///< greater than (signed)
	CRIS_CC_LE = 0xD, ///< less or equal (signed)
	CRIS_CC_A = 0xE, ///< always
	CRIS_CC_EXT = 0xF, ///< extended (v0-v3: ext, v10: wf, v32: sb/bsb)
} CrisCondCode;

static const char *cris_cc_names[] = {
	[CRIS_CC_CC] = "cc",
	[CRIS_CC_CS] = "cs",
	[CRIS_CC_NE] = "ne",
	[CRIS_CC_EQ] = "eq",
	[CRIS_CC_VC] = "vc",
	[CRIS_CC_VS] = "vs",
	[CRIS_CC_PL] = "pl",
	[CRIS_CC_MI] = "mi",
	[CRIS_CC_LS] = "ls",
	[CRIS_CC_HI] = "hi",
	[CRIS_CC_GE] = "ge",
	[CRIS_CC_LT] = "lt",
	[CRIS_CC_GT] = "gt",
	[CRIS_CC_LE] = "le",
	[CRIS_CC_A] = "a",
	[CRIS_CC_EXT] = "ext",
};

static const char *cris_cc_names_v32[] = {
	[CRIS_CC_CC] = "cc",
	[CRIS_CC_CS] = "cs",
	[CRIS_CC_NE] = "ne",
	[CRIS_CC_EQ] = "eq",
	[CRIS_CC_VC] = "vc",
	[CRIS_CC_VS] = "vs",
	[CRIS_CC_PL] = "pl",
	[CRIS_CC_MI] = "mi",
	[CRIS_CC_LS] = "ls",
	[CRIS_CC_HI] = "hi",
	[CRIS_CC_GE] = "ge",
	[CRIS_CC_LT] = "lt",
	[CRIS_CC_GT] = "gt",
	[CRIS_CC_LE] = "le",
	[CRIS_CC_A] = "a",
	[CRIS_CC_EXT] = "sb",
};

/**
 * General register names.
 * r14 = SP, r15 = PC (v10) or ACR (v32).
 */
static const char *cris_gpr_names[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "sp", "pc",
};

static const char *cris_gpr_names_v32[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "sp", "acr",
};

/**
 * Special register names for v10.
 * Indexed by special register number (0-15).
 */
static const char *cris_spec_reg_names_v10[] = {
	"bz", "vr", "p2", "p3", "p4", "ccr", "p6", "mof",
	"p8", "ibr", "irp", "srp", "bar", "dccr", "brp", "usp",
};

/**
 * Special register names for v32.
 * Indexed by special register number (0-15).
 */
static const char *cris_spec_reg_names_v32[] = {
	"bz", "vr", "pid", "srs", "wz", "exs", "eda", "mof",
	"dz", "ebp", "erp", "srp", "nrp", "ccs", "usp", "spc",
};

static const char *cris_size_suffix[] = {
	[CRIS_SIZE_BYTE] = ".b",
	[CRIS_SIZE_WORD] = ".w",
	[CRIS_SIZE_DWORD] = ".d",
	[CRIS_SIZE_FIXED] = "",
};

/**
 * Instruction types for the decoder/analysis.
 */
typedef enum {
	CRIS_INSN_UNKNOWN = 0,

	// Quick immediate operations
	CRIS_INSN_ADDQ,
	CRIS_INSN_SUBQ,
	CRIS_INSN_MOVEQ,
	CRIS_INSN_CMPQ,
	CRIS_INSN_ANDQ,
	CRIS_INSN_ORQ,
	CRIS_INSN_BTSTQ,
	CRIS_INSN_ASRQ,
	CRIS_INSN_LSLQ,
	CRIS_INSN_LSRQ,

	// Register-register operations
	CRIS_INSN_ADD,
	CRIS_INSN_SUB,
	CRIS_INSN_CMP,
	CRIS_INSN_AND,
	CRIS_INSN_OR,
	CRIS_INSN_XOR,
	CRIS_INSN_MOVE_R,
	CRIS_INSN_MOVS,
	CRIS_INSN_MOVU,
	CRIS_INSN_ADDS,
	CRIS_INSN_ADDU,
	CRIS_INSN_SUBS,
	CRIS_INSN_SUBU,
	CRIS_INSN_CMPS,
	CRIS_INSN_CMPU,
	CRIS_INSN_ABS,
	CRIS_INSN_NEG,
	CRIS_INSN_NOT,
	CRIS_INSN_BTST,
	CRIS_INSN_BOUND,
	CRIS_INSN_DSTEP,
	CRIS_INSN_LZ,
	CRIS_INSN_MULS,
	CRIS_INSN_MULU,
	CRIS_INSN_ASR,
	CRIS_INSN_LSL,
	CRIS_INSN_LSR,
	CRIS_INSN_SWAP,
	CRIS_INSN_ADDC,
	CRIS_INSN_MCP,

	// Memory operations
	CRIS_INSN_MOVE_MR, ///< move [mem], reg
	CRIS_INSN_MOVE_RM, ///< move reg, [mem]
	CRIS_INSN_MOVEM_MR, ///< movem [mem], reg
	CRIS_INSN_MOVEM_RM, ///< movem reg, [mem]
	CRIS_INSN_MOVE_MP, ///< move [mem], preg
	CRIS_INSN_MOVE_PM, ///< move preg, [mem]
	CRIS_INSN_MOVE_RP, ///< move reg, preg
	CRIS_INSN_MOVE_PR, ///< move preg, reg
	CRIS_INSN_MOVE_RS, ///< move reg, sreg (v32)
	CRIS_INSN_MOVE_SR, ///< move sreg, reg (v32)
	CRIS_INSN_ADD_M,
	CRIS_INSN_SUB_M,
	CRIS_INSN_CMP_M,
	CRIS_INSN_AND_M,
	CRIS_INSN_OR_M,
	CRIS_INSN_BOUND_M,
	CRIS_INSN_ADDS_M,
	CRIS_INSN_ADDU_M,
	CRIS_INSN_SUBS_M,
	CRIS_INSN_SUBU_M,
	CRIS_INSN_CMPS_M,
	CRIS_INSN_CMPU_M,
	CRIS_INSN_MOVS_M,
	CRIS_INSN_MOVU_M,
	CRIS_INSN_TEST_M,
	CRIS_INSN_CLEAR_M,
	CRIS_INSN_ADDC_M,

	// Branch and jump
	CRIS_INSN_BCC_8, ///< Bcc with 8-bit displacement
	CRIS_INSN_BCC_16, ///< Bcc with 16-bit displacement (extension word)
	CRIS_INSN_BA_DWORD, ///< BA with 32-bit displacement (v32)
	CRIS_INSN_BAS, ///< BAS (v32) — branch and save
	CRIS_INSN_BSR, ///< BSR (v32)
	CRIS_INSN_JUMP_R, ///< jump reg
	CRIS_INSN_JUMP_M, ///< jump [mem]
	CRIS_INSN_JUMP_P, ///< jump preg (v32)
	CRIS_INSN_JUMP_N, ///< jump [pc+] (v32 absolute)
	CRIS_INSN_JSR_R, ///< jsr reg
	CRIS_INSN_JSR_M, ///< jsr [mem]
	CRIS_INSN_JSR_N, ///< jsr [pc+] (v32)
	CRIS_INSN_JAS, ///< jas (v32)
	CRIS_INSN_JASC, ///< jasc (v32)
	CRIS_INSN_RET, ///< ret (= jump srp)
	CRIS_INSN_RETI, ///< reti
	CRIS_INSN_RETE, ///< rete (v32)
	CRIS_INSN_RETN, ///< retn (v32)
	CRIS_INSN_RETB, ///< retb (v10)

	// Prefix (v10 only)
	CRIS_INSN_BDAP_Q, ///< BDAP quick prefix
	CRIS_INSN_BDAP, ///< BDAP indirect prefix
	CRIS_INSN_BIAP, ///< BIAP prefix
	CRIS_INSN_DIP, ///< DIP prefix

	// v32 addressing
	CRIS_INSN_ADDO, ///< addo (v32 address offset)
	CRIS_INSN_ADDOQ, ///< addoq (v32 quick address offset)
	CRIS_INSN_LAPC, ///< lapc (v32)
	CRIS_INSN_LAPCQ, ///< lapcq (v32)

	// Scc (set condition)
	CRIS_INSN_SCC,

	// Special
	CRIS_INSN_NOP,
	CRIS_INSN_BREAK,
	CRIS_INSN_HALT,
	CRIS_INSN_SETF,
	CRIS_INSN_CLEARF,
	CRIS_INSN_EI,
	CRIS_INSN_DI,
	CRIS_INSN_AX,
	CRIS_INSN_MOVE_R_TEST, ///< test Rd (encoded as move Rd,Rd in v10)
	CRIS_INSN_CLEAR_R,
	CRIS_INSN_ADDI,

	// v32 special
	CRIS_INSN_RFE,
	CRIS_INSN_RFG,
	CRIS_INSN_RFN,
	CRIS_INSN_SFE,
	CRIS_INSN_FIDXI,
	CRIS_INSN_FIDXD,
	CRIS_INSN_FTAGD,
	CRIS_INSN_FTAGI,
} CrisInsnType;

/**
 * Addressing modes for memory operands.
 */
typedef enum {
	CRIS_ADDR_REG = 0, ///< register direct: Rd
	CRIS_ADDR_IND, ///< indirect: [Rs]
	CRIS_ADDR_IND_POST, ///< indirect with post-increment: [Rs+]
	CRIS_ADDR_NONE,
} CrisAddrMode;

/**
 * Decoded CRIS instruction.
 */
typedef struct {
	CrisInsnType type;
	ut8 size; ///< Total instruction size in bytes (2, 4, or 6)
	ut8 reg1; ///< Source register (bits [3:0])
	ut8 reg2; ///< Destination register (bits [15:12])
	CrisSizeModifier sz; ///< Size modifier (.b/.w/.d)
	CrisAddrMode addr_mode; ///< Addressing mode for memory operand
	ut8 cond; ///< Condition code for Bcc/Scc
	bool autoincr; ///< Post-increment flag
	st32 immediate; ///< Immediate value or displacement
	ut8 spec_reg; ///< Special register number
	ut8 swap_bits; ///< Swap combination bits (for swap* instructions)
	ut8 flags_bits; ///< Flag bits for setf/clearf
	ut16 raw; ///< Raw instruction word
} CrisInsn;

/**
 * Decode a CRIS instruction.
 *
 * \param buf Pointer to instruction bytes (little-endian)
 * \param len Number of available bytes
 * \param insn Output: decoded instruction
 * \param ver ISA version to decode for
 * \return Instruction size in bytes (2, 4, or 6) or -1 on failure
 */
int cris_decode(const ut8 *buf, int len, CrisInsn *insn, CrisIsaVersion ver);

/**
 * Format a decoded instruction as disassembly text.
 *
 * \param insn Decoded instruction
 * \param out Output string buffer
 * \param ver ISA version
 * \return Instruction size or -1 on failure
 */
int cris_disassemble(const CrisInsn *insn, RzStrBuf *out, CrisIsaVersion ver);

/**
 * Decode and disassemble in one step.
 *
 * \param buf Instruction bytes
 * \param len Available bytes
 * \param out Output string buffer
 * \param ver ISA version
 * \param insn_out Optional: store decoded instruction
 * \return Instruction size or -1 on failure
 */
int cris_disas(const ut8 *buf, int len, RzStrBuf *out, CrisIsaVersion ver, CrisInsn *insn_out);

// ESIL
void cris_esil(const CrisInsn *insn, RzStrBuf *out, ut64 addr, CrisIsaVersion ver);

// RzIL
typedef struct {
	RzAnalysis *a;
	CrisInsn insn;
	ut64 pc;
	CrisIsaVersion ver;
} CrisILContext;

RzAnalysisILConfig *cris_il_config(RzAnalysis *a);
RzAnalysisLiftedILOp cris_il_op(const CrisILContext *ctx);

// Helper macros for bit extraction
#define CRIS_REG1(w) ((w) & 0xF)
#define CRIS_REG2(w) (((w) >> 12) & 0xF)
#define CRIS_SIZE(w) (((w) >> 4) & 0x3)
#define CRIS_OPCODE(w) (((w) >> 6) & 0xF)
#define CRIS_MODE(w) (((w) >> 10) & 0x3)

// Convenience: sign-extend helpers
static inline st32 cris_sign_ext8(ut8 val) {
	return (st32)(st8)val;
}

static inline st32 cris_sign_ext16(ut16 val) {
	return (st32)(st16)val;
}

static inline st32 cris_sign_ext6(ut8 val) {
	return (val & 0x20) ? (st32)(val | 0xFFFFFFC0) : (st32)val;
}

#endif /* CRIS_H */
