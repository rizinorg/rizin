// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c166_ops.h
 * \brief Defines operations, addressing modes, and opcode information for C166 architecture
 *
 * This header defines the core structures and enumerations used by the C166 disassembler
 * and analyzer, including register definitions, addressing modes, operation types, and
 * condition codes. It also provides opcode tables and helper functions for address calculations.
 */

#ifndef _C166_OPS_H
#define _C166_OPS_H

#include <rz_types.h>

/**
 * C166 Register definitions
 * Defines all general-purpose and special registers for the C166 architecture
 */
typedef enum {
	C166_R0, C166_R1, C166_R2, C166_R3, 
	C166_R4, C166_R5, C166_R6, C166_R7, 
	C166_R8, C166_R9, C166_R10, C166_R11, 
	C166_R12, C166_R13, C166_R14, C166_R15,
	C166_RL0, C166_RH0, C166_RL1, C166_RH1,
	C166_RL2, C166_RH2, C166_RL3, C166_RH3,
	C166_RL4, C166_RH4, C166_RL5, C166_RH5,
	C166_RL6, C166_RH6, C166_RL7, C166_RH7,
	C166_IP, C166_SP, C166_PSW, C166_CSP,
	C166_MDL, C166_MDH, C166_MDC,
	C166_STKOV, C166_STKUN, C166_CPUCON1, C166_CPUCON2,
	C166_VECSEG, C166_SPSEG, C166_CP
} C166Register;

/**
 * C166 Addressing Modes
 * Defines all addressing modes supported by the C166 architecture
 */
typedef enum {
	C166_ADDR_REG,        // Register addressing
	C166_ADDR_IMM,        // Immediate addressing
	C166_ADDR_DIR,        // Direct addressing
	C166_ADDR_IND,        // Indirect addressing
	C166_ADDR_INDIRECT,   // @R addressing
	C166_ADDR_POSTINC,    // [R+] addressing
	C166_ADDR_PREDEC,     // [-R] addressing
	C166_ADDR_OFFSET,     // [R + #data16] addressing
	C166_ADDR_RELATIVE,   // rel addressing for branch instructions
	C166_ADDR_BITADDR,    // bit addressing
	C166_ADDR_BITOFF,     // bit offset addressing
	C166_ADDR_SEG,        // segment addressing
	C166_ADDR_CADDR,      // code address
	C166_ADDR_NONE        // No addressing
} C166AddrMode;

/**
 * C166 Operation Types
 * Defines all instruction types supported by the C166 architecture
 */
typedef enum {
	C166_OP_INVALID = 0,
	C166_OP_ADD,
	C166_OP_ADDB,
	C166_OP_ADDC,
	C166_OP_ADDCB,
	C166_OP_SUB,
	C166_OP_SUBB,
	C166_OP_SUBC,
	C166_OP_SUBCB,
	C166_OP_MUL,
	C166_OP_MULU,
	C166_OP_DIV,
	C166_OP_DIVL,
	C166_OP_DIVLU,
	C166_OP_DIVU,
	C166_OP_AND,
	C166_OP_ANDB,
	C166_OP_OR,
	C166_OP_ORB,
	C166_OP_XOR,
	C166_OP_XORB,
	C166_OP_CMP,
	C166_OP_CMPB,
	C166_OP_CMPD1,
	C166_OP_CMPD2,
	C166_OP_CMPI1,
	C166_OP_CMPI2,
	C166_OP_PRIOR,
	C166_OP_MOV,
	C166_OP_MOVB,
	C166_OP_MOVBS,
	C166_OP_MOVBZ,
	C166_OP_PUSH,
	C166_OP_POP,
	C166_OP_SCXT,
	C166_OP_SHL,
	C166_OP_SHR,
	C166_OP_ROL,
	C166_OP_ROR,
	C166_OP_ASHR,
	C166_OP_NEG,
	C166_OP_NEGB,
	C166_OP_CPL,
	C166_OP_CPLB,
	C166_OP_BCLR,
	C166_OP_BSET,
	C166_OP_BMOV,
	C166_OP_BMOVN,
	C166_OP_BAND,
	C166_OP_BOR,
	C166_OP_BXOR,
	C166_OP_BCMP,
	C166_OP_BFLDH,
	C166_OP_BFLDL,
	C166_OP_JMP,
	C166_OP_JMPA,
	C166_OP_JMPI,
	C166_OP_JMPR,
	C166_OP_JMPS,
	C166_OP_JB,
	C166_OP_JBC,
	C166_OP_JNB,
	C166_OP_JNBS,
	C166_OP_CALL,
	C166_OP_CALLA,
	C166_OP_CALLI,
	C166_OP_CALLR,
	C166_OP_CALLS,
	C166_OP_PCALL,
	C166_OP_TRAP,
	C166_OP_RET,
	C166_OP_RETS,
	C166_OP_RETP,
	C166_OP_RETI,
	C166_OP_SRST,
	C166_OP_SBRK,
	C166_OP_IDLE,
	C166_OP_PWRDN,
	C166_OP_EXTP,
	C166_OP_EXTPR,
	C166_OP_EXTS,
	C166_OP_EXTSR,
	C166_OP_EXTR,
	C166_OP_ATOMIC,
	C166_OP_NOP,
	C166_OP_Co  
} C166OpType;

/**
 * C166 Branch Condition Codes
 * Defines condition codes used for conditional branching instructions
 */
typedef enum {
	C166_CC_UC,     // Unconditional
	C166_CC_Z,      // Zero
	C166_CC_NZ,     // Not Zero
	C166_CC_V,      // Overflow
	C166_CC_NV,     // No Overflow
	C166_CC_N,      // Negative
	C166_CC_NN,     // Not Negative
	C166_CC_C,      // Carry
	C166_CC_NC,     // No Carry
	C166_CC_EQ,     // Equal
	C166_CC_NE,     // Not Equal
	C166_CC_ULT,    // Unsigned Less Than
	C166_CC_ULE,    // Unsigned Less Than or Equal
	C166_CC_UGE,    // Unsigned Greater Than or Equal
	C166_CC_UGT,    // Unsigned Greater Than
	C166_CC_SLT,    // Signed Less Than
	C166_CC_SLE,    // Signed Less Than or Equal
	C166_CC_SGE,    // Signed Greater Than or Equal
	C166_CC_SGT,    // Signed Greater Than
	C166_CC_NET     // Not Equal and Not End-of-Table
} C166CondCode;

/**
 * Structure for C166 opcode definitions
 * Contains information about each instruction including opcode, type, size, cycles,
 * mnemonic, addressing modes, and masks for opcode matching.
 */
typedef struct {
	ut8 opcode;
	C166OpType type;
	int size;
	int cycles;
	const char *mnemonic;
	C166AddrMode addr_mode1;
	C166AddrMode addr_mode2;
	C166AddrMode addr_mode3;
	ut8 mask;
	ut8 opcode_mask;
} C166OpInfo;

/**
 * Maps hexcodes to condition codes for JMPR instructions
 * Used to determine the condition code for conditional jump instructions
 */
static const C166CondCode c166_cc_jmpr_map[] = {
	C166_CC_UC,  // 0x0D
	C166_CC_NET, // 0x1D
	C166_CC_EQ,  // 0x2D (or C166_CC_Z)
	C166_CC_NE,  // 0x3D (or C166_CC_NZ)
	C166_CC_V,   // 0x4D
	C166_CC_NV,  // 0x5D
	C166_CC_N,   // 0x6D
	C166_CC_NN,  // 0x7D
	C166_CC_C,   // 0x8D (or C166_CC_ULT)
	C166_CC_NC,  // 0x9D (or C166_CC_UGE)
	C166_CC_SGT, // 0xAD
	C166_CC_SLE, // 0xBD
	C166_CC_SLT, // 0xCD
	C166_CC_SGE, // 0xDD
	C166_CC_UGT, // 0xED
	C166_CC_ULE  // 0xFD
};

/**
 * Basic opcode table (partial implementation)
 * Defines the opcodes for C166 instructions with their types, sizes, mnemonics, and address modes
 * This will need to be expanded with all opcodes from the manual
 */
static const C166OpInfo c166_opcodes[] = {
	{0x00, C166_OP_ADD, 2, 1, "add", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x01, C166_OP_ADDB, 2, 1, "addb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x06, C166_OP_ADD, 4, 1, "add", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x07, C166_OP_ADDB, 4, 1, "addb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x08, C166_OP_ADD, 2, 1, "add", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x09, C166_OP_ADDB, 2, 1, "addb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x0A, C166_OP_BFLDL, 4, 1, "bfldl", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x0B, C166_OP_MUL, 2, 1, "mul", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x0C, C166_OP_ROL, 2, 1, "rol", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x0D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x0E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x0F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x10, C166_OP_ADDC, 2, 1, "addc", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x11, C166_OP_ADDCB, 2, 1, "addcb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x16, C166_OP_ADDC, 4, 1, "addc", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x17, C166_OP_ADDCB, 4, 1, "addcb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x18, C166_OP_ADDC, 2, 1, "addc", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x19, C166_OP_ADDCB, 2, 1, "addcb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x1A, C166_OP_BFLDH, 4, 1, "bfldh", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x1B, C166_OP_MULU, 2, 1, "mulu", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x1C, C166_OP_ROL, 2, 1, "rol", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x1D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x1E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x1F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x20, C166_OP_SUB, 2, 1, "sub", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x21, C166_OP_SUBB, 2, 1, "subb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x2A, C166_OP_BCMP, 4, 1, "bcmp", C166_ADDR_BITADDR, C166_ADDR_BITADDR, C166_ADDR_NONE, 0, 0},
	{0x2B, C166_OP_PRIOR, 2, 1, "prior", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x2C, C166_OP_ROR, 2, 1, "ror", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x2D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x2E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x2F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x30, C166_OP_SUBC, 2, 1, "subc", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x31, C166_OP_SUBCB, 2, 1, "subcb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x36, C166_OP_SUBC, 4, 1, "subc", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x37, C166_OP_SUBCB, 4, 1, "subcb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x38, C166_OP_SUBC, 2, 1, "subc", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x39, C166_OP_SUBCB, 2, 1, "subcb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x3C, C166_OP_ROR, 2, 1, "ror", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x3D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x3E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x3F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x40, C166_OP_CMP, 2, 1, "cmp", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x41, C166_OP_CMPB, 2, 1, "cmpb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x46, C166_OP_CMP, 4, 1, "cmp", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x47, C166_OP_CMPB, 4, 1, "cmpb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x48, C166_OP_CMP, 2, 1, "cmp", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x49, C166_OP_CMPB, 2, 1, "cmpb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x4C, C166_OP_SHL, 2, 1, "shl", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x4D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x4E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x4F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x50, C166_OP_XOR, 2, 1, "xor", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x51, C166_OP_XORB, 2, 1, "xorb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x56, C166_OP_XOR, 4, 1, "xor", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x57, C166_OP_XORB, 4, 1, "xorb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x58, C166_OP_XOR, 2, 1, "xor", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x59, C166_OP_XORB, 2, 1, "xorb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x5C, C166_OP_SHL, 2, 1, "shl", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x5D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x5E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x5F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x60, C166_OP_AND, 2, 1, "and", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x61, C166_OP_ANDB, 2, 1, "andb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x66, C166_OP_AND, 4, 1, "and", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x67, C166_OP_ANDB, 4, 1, "andb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x68, C166_OP_AND, 2, 1, "and", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x69, C166_OP_ANDB, 2, 1, "andb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x6C, C166_OP_SHR, 2, 1, "shr", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x6D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x6E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x6F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x70, C166_OP_OR, 2, 1, "or", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x71, C166_OP_ORB, 2, 1, "orb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x76, C166_OP_OR, 4, 1, "or", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x77, C166_OP_ORB, 4, 1, "orb", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x78, C166_OP_OR, 2, 1, "or", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x79, C166_OP_ORB, 2, 1, "orb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x7C, C166_OP_SHR, 2, 1, "shr", C166_ADDR_REG, C166_ADDR_IMM, C166_ADDR_NONE, 0, 0},
	{0x7D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x7E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x7F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x81, C166_OP_NEG, 2, 1, "neg", C166_ADDR_REG, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x84, C166_OP_MOV, 4, 1, "mov", C166_ADDR_REG, C166_ADDR_DIR, C166_ADDR_NONE, 0, 0},
	{0x88, C166_OP_MOV, 2, 1, "mov", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x89, C166_OP_MOVB, 2, 1, "movb", C166_ADDR_REG, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0x8A, C166_OP_JB, 4, 1, "jb", C166_ADDR_BITADDR, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x8D, C166_OP_JMPR, 2, 1, "jmpr", C166_ADDR_NONE, C166_ADDR_RELATIVE, C166_ADDR_NONE, 0, 0},
	{0x8E, C166_OP_BCLR, 2, 1, "bclr", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x8F, C166_OP_BSET, 2, 1, "bset", C166_ADDR_BITOFF, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x91, C166_OP_CPL, 2, 1, "cpl", C166_ADDR_REG, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0},
	{0x94, C166_OP_MOV, 4, 1, "mov", C166_ADDR_DIR, C166_ADDR_REG, C166_ADDR_NONE, 0, 0},
	{0, C166_OP_INVALID, 0, 0, NULL, C166_ADDR_NONE, C166_ADDR_NONE, C166_ADDR_NONE, 0, 0}
};

/**
 * \brief Helper function for relative address calculation
 * \param pc Current program counter value
 * \param offset Signed 8-bit offset value
 * \return Calculated target address
 *
 * Calculates the target address for a relative jump or call instruction
 * by adding the signed offset to the program counter.
 */
static inline ut64 c166_addr_relative(ut64 pc, ut8 offset) {
	if (offset & 0x80) {
		return pc - (0x100 - offset);
	} else {
		return pc + offset;
	}
}

#endif /* _C166_OPS_H */
