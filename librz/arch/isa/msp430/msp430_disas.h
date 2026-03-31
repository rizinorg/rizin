// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2015 Mauro Matteo Cascella <mauromatteo.cascella@gmail.com>
// SPDX-FileCopyrightText: 2016 Mitchell Johnson <ehntoo@gmail.com>
// SPDX-FileCopyrightText: 2018 Neven Sajko <nsajko@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MSP430_DISAS_H
#define MSP430_DISAS_H

typedef enum msp430_oneop_opcodes {
	MSP430_RRC,
	MSP430_SWPB,
	MSP430_RRA,
	MSP430_SXT,
	MSP430_PUSH,
	MSP430_CALL,
	MSP430_RETI,
	MSP430_UNUSED,
} Msp430OneopOpcodes;

typedef enum msp430_jumps {
	MSP430_JNE,
	MSP430_JEQ,
	MSP430_JNC,
	MSP430_JC,
	MSP430_JN,
	MSP430_JGE,
	MSP430_JL,
	MSP430_JMP,
} Msp430Jumps;

typedef enum msp430_twoop_opcodes {
	MSP430_MOV = 0x4,
	MSP430_ADD,
	MSP430_ADDC,
	MSP430_SUBC,
	MSP430_SUB,
	MSP430_CMP,
	MSP430_DADD,
	MSP430_BIT,
	MSP430_BIC,
	MSP430_BIS,
	MSP430_XOR,
	MSP430_AND,
} Msp430TwoopOpcodes;

typedef enum msp430_emulated_opcodes {
	MSP430_ADC,
	MSP430_BR,
	MSP430_CLR,
	MSP430_CLRC,
	MSP430_CLRN,
	MSP430_CLRZ,
	MSP430_DADC,
	MSP430_DEC,
	MSP430_DECD,
	MSP430_DINT,
	MSP430_EINT,
	MSP430_INC,
	MSP430_INCD,
	MSP430_INV,
	MSP430_NOP,
	MSP430_POP,
	MSP430_RET,
	MSP430_RLA,
	MSP430_RLC,
	MSP430_SBC,
	MSP430_SETC,
	MSP430_SETN,
	MSP430_SETZ,
	MSP430_TST
} Msp430EmulatedOpcodes;

typedef enum msp430_cmd_type {
	MSP430_ONEOP,
	MSP430_TWOOP,
	MSP430_JUMP,
	MSP430_EMULATE,
	MSP430_INVALID,
} Msp430CmdType;

typedef enum msp430_registers {
	MSP430_PC,
	MSP430_SP,
	MSP430_SR,
	MSP430_R3,
	MSP430_R4,
	MSP430_R5,
	MSP430_R6,
	MSP430_R7,
	MSP430_R8,
	MSP430_R9,
	MSP430_R10,
	MSP430_R11,
	MSP430_R12,
	MSP430_R13,
	MSP430_R14,
	MSP430_R15,
} Msp430Registers;

typedef enum Msp430AddressingMode {
	MSP430_REG, ///< register: Rn, contents of Rn
	MSP430_INDX, ///< indexed: offset(Rn), contents of Memory[offset + Rn]
	MSP430_SYM, ///< symbolic: offset, contents of Memory[offset + PC] (as if indexed with Rn = PC)
	MSP430_ABS, ///< absolute: &addr, contents of Memory[addr] (as if indexed with a zeroed Rn)
	MSP430_IND_REG, ///< indirect register: @Rn, contents of Memory[Rn] (as if indexed with offset = 0)
	MSP430_IND_AUTOINC, ///< indirect register auto-increment: @Rn+, same as with indirect register but automatically increments Rn
	MSP430_IMM ///< immediate: #literal, the literal value itself is the argument
} Msp430AddressingMode;

/**
 *  \brief represents a disassembled instructions, also used for lifting
 * */
typedef struct msp430_cmd {
	ut8 type; ///< whether it's a one-operand, two-operand, emulated, jump or invalid
	ut8 opcode; ///< which kind of operation

	st16 jmp_addr; ///< for jumps, what's the address to jump to
	ut8 jmp_cond; ///< for jumps, when will the jump be taken

	// Length of array: 'i', 'n', 'v', 'a', 'l', 'i', 'd', '\0'
	// (This is longer than any real assembly mnemonic.)
	char instr[7 + 1]; ///< Null-delimited string representation of an assembly operation mnemonic.

	bool is_byte; ///< does it have a .b suffix ? (i.e. whether it's a byte instruction or word instruction )

	// Length of array: 2 * ('0', 'x', 4-digit hexadecimal numeral, '(', 'r', 2-digit
	// decimal numeral, ')'), ',', ' ', '\0'
	char operands[2 * (2 + 4 + 2 + 3) + 2 + 1]; ///< Null-delimited string representation of assembly operands.

	// The source and the dst of the operands, along with their modes
	// This info is contained in the strings above, but parsing strings to obtain it is ugly so we replicate it here
	ut32 src; ///< src, doesn't get overwritten for eumlated instructions
	ut32 dst; ///< dst, doesn't get overwritten for eumlated instructions
	Msp430AddressingMode src_mode; ///< the addressing mode used by src, will determine how to interpret its 32 bits
	Msp430AddressingMode dst_mode; ///< the addressing mode used by dst, will determine how to interpret its 32 bits
} Msp430Cmd;

int msp430_decode_command(const ut8 *instr, int len, Msp430Cmd *cmd);
#endif /* MSP430_DISAS_H */
