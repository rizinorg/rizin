// SPDX-FileCopyrightText: 2022 imbillow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _8051_OP_H_
#define _8051_OP_H_

#include <rz_types.h>

typedef enum {
	I_UNDEFINED = 0,
	I_ACALL, /// Absolute Call
	I_ADD, /// Add Accumulator
	I_ADDC, /// Add Accumulator (With Carry)
	I_AJMP, /// Absolute Jump
	I_ANL, /// Bitwise AND
	I_CJNE, /// Compare and Jump if Not Equal
	I_CLR, /// Clear Register
	I_CPL, /// Complement Register
	I_DA, /// Decimal Adjust
	I_DEC, /// Decrement Register
	I_DIV, /// Divide Accumulator by B
	I_DJNZ, /// Decrement Register and Jump if Not Zero
	I_INC, /// Increment Register
	I_JB, /// Jump if Bit Set
	I_JBC, /// Jump if Bit Set and Clear Bit
	I_JC, /// Jump if Carry Set
	I_JMP, /// Jump to Address
	I_JNB, /// Jump if Bit Not Set
	I_JNC, /// Jump if Carry Not Set
	I_JNZ, /// Jump if Accumulator Not Zero
	I_JZ, /// Jump if Accumulator Zero
	I_LCALL, /// Long Call
	I_LJMP, /// Long Jump
	I_MOV, /// Move Memory
	I_MOVC, /// Move Code Memory
	I_MOVX, /// Move Extended Memory
	I_MUL, /// Multiply Accumulator by B
	I_NOP, /// No Operation
	I_ORL, /// Bitwise OR
	I_POP, /// Pop Value From Stack
	I_PUSH, /// Push Value Onto Stack
	I_RET, /// Return From Subroutine
	I_RETI, /// Return From Interrupt
	I_RL, /// Rotate Accumulator Left
	I_RLC, /// Rotate Accumulator Left Through Carry
	I_RR, /// Rotate Accumulator Right
	I_RRC, /// Rotate Accumulator Right Through Carry
	I_SETB, /// Set Bit
	I_SJMP, /// Short Jump
	I_SUBB, /// Subtract From Accumulator With Borrow
	I_SWAP, /// Swap Accumulator Nibbles
	I_XCH, /// Exchange Bytes
	I_XCHD, /// Exchange Digits
	I_XRL, /// Bitwise Exclusive OR
} I8051OpInst;

/// https://www.win.tue.nl/~aeb/comp/8051/set8051.html

// clang-format off
static const I8051OpInst i8051_inst_tbl[256] = {
         /* 0x00,  0x01,  0x02,   0x03,   0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,  0x0c,  0x0d,  0x0e,  0x0f */
 /* 0x00 */ I_NOP, I_AJMP, I_LJMP, I_RR,  I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC,
 /* 0x10 */ I_JBC, I_ACALL,I_LCALL,I_RRC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC,
 /* 0x20 */ I_JB,  I_AJMP, I_RET,  I_RL,  I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD,
 /* 0x30 */ I_JNB, I_ACALL,I_RETI, I_RLC, I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,
 /* 0x40 */ I_JC,  I_AJMP, I_ORL,  I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL,
 /* 0x50 */ I_JNC, I_ACALL,I_ANL,  I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL,
 /* 0x60 */ I_JZ,  I_AJMP, I_XRL,  I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL,
 /* 0x70 */ I_JNZ, I_ACALL,I_ORL,  I_JMP, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0x80 */ I_SJMP,I_AJMP, I_ANL,  I_MOVC,I_DIV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0x90 */ I_MOV, I_ACALL,I_MOV,  I_MOVC,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,
 /* 0xa0 */ I_ORL, I_AJMP, I_MOV,  I_INC, I_MUL, 0,     I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0xb0 */ I_ANL, I_ACALL,I_CPL,  I_CPL, I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,
 /* 0xc0 */ I_PUSH,I_AJMP, I_CLR,  I_CLR, I_SWAP,I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH,
 /* 0xd0 */ I_POP, I_ACALL,I_SETB, I_SETB,I_DA,  I_DJNZ,I_XCHD,I_XCHD,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,
 /* 0xe0 */ I_MOVX,I_AJMP, I_MOVX, I_MOVX,I_CLR, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0xf0 */ I_MOVX,I_ACALL,I_MOVX, I_MOVX,I_CPL, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
};
// clang-format on

typedef enum {
	I8051_ADDRESSING_REGISTER = 0,
	I8051_ADDRESSING_DIRECT,
	I8051_ADDRESSING_INDIRECT,
	I8051_ADDRESSING_IMMEDIATE,
	I8051_ADDRESSING_IMMEDIATE16,
	I8051_ADDRESSING_RELATIVE,
	I8051_ADDRESSING_ABSOLUTE,
	I8051_ADDRESSING_LONG,
	I8051_ADDRESSING_INDEXED,
	I8051_ADDRESSING_BIT,
} I8051AddressingMode;

typedef enum {
	I8051_R0 = 0,
	I8051_R1,
	I8051_R2,
	I8051_R3,
	I8051_R4,
	I8051_R5,
	I8051_R6,
	I8051_R7,
	I8051_SP = 0x81,
	I8051_DPTR,
	I8051_PCON = 0x87,
	I8051_TCON,
	I8051_TMOD,
	I8051_TL0,
	I8051_TL1,
	I8051_TH0,
	I8051_TH1,
	I8051_PC,
	I8051_PSW = 0xD0,
	I8051_Z = 0xD1,
	I8051_OV = 0xD2,
	I8051_RS0 = 0xD3,
	I8051_RS1 = 0xD4,
	I8051_N = 0xD5,
	I8051_AC = 0xD6,
	I8051_CY = 0xD7,
	I8051_A = 0xE0,
	I8051_B = 0xF0
} I8051Registers;

typedef struct i8051_op_addressing_t {
	ut64 pc;
	I8051AddressingMode mode;
	union {
		I8051Registers reg;
		ut8 addr;
		ut16 addr16;
		ut16 constant;
		struct i8051_op_addressing_t *indirect;
	} d;
} I8051OpAddressing;

typedef struct i8051_op_t {
	ut64 pc;
	ut8 opcode;
	ut8 len;
	I8051OpInst inst;
	ut8 argc;
	I8051OpAddressing **argv;
} I8051Op;

static I8051OpAddressing *addressing_addr(I8051AddressingMode mode, ut16 addr) {
	I8051OpAddressing *a = RZ_NEW0(I8051OpAddressing);
	if (!a) {
		return NULL;
	}
	a->mode = mode;
	a->d.addr16 = addr;
	return a;
}

static I8051OpAddressing *addressing_direct(ut8 addr) {
	return addressing_addr(I8051_ADDRESSING_DIRECT, addr);
}

static I8051OpAddressing *addressing_indirect(I8051OpAddressing *addr) {
	I8051OpAddressing *a = RZ_NEW0(I8051OpAddressing);
	if (!a) {
		return NULL;
	}
	a->mode = I8051_ADDRESSING_INDIRECT;
	a->d.indirect = addr;
	return a;
}

static I8051OpAddressing *addressing_relative(ut8 addr) {
	return addressing_addr(I8051_ADDRESSING_RELATIVE, addr);
}

static I8051OpAddressing *addressing_immediate(ut8 imm) {
	return addressing_addr(I8051_ADDRESSING_IMMEDIATE, imm);
}

static I8051OpAddressing *addressing_bit(ut8 addr) {
	return addressing_addr(I8051_ADDRESSING_BIT, addr);
}

static I8051OpAddressing *addressing_register(I8051Registers reg) {
	I8051OpAddressing *a = RZ_NEW0(I8051OpAddressing);
	if (!a) {
		return NULL;
	}
	a->mode = I8051_ADDRESSING_REGISTER;
	a->d.reg = reg;
	return a;
}

static inline I8051OpAddressing *addressing_register_a() {
	return addressing_register(I8051_A);
}

static inline I8051OpAddressing *addressing_indexed(I8051Registers reg) {
	I8051OpAddressing *a = RZ_NEW0(I8051OpAddressing);
	if (!a) {
		return NULL;
	}
	a->mode = I8051_ADDRESSING_INDEXED;
	a->d.reg = reg;
	return a;
}

static inline I8051OpAddressing *addressing_register_b() {
	return addressing_register(I8051_B);
}

/**
 * 0x05 iram addr
 * 0x06-0x07 @(R0-R1)
 * 0x08-0x0f, R0-R7
 */
static I8051OpAddressing *addressing_pattern1(const ut8 *buf) {
	ut8 lo = buf[0] & 0x0f;
	if (lo == 0x5) {
		return addressing_direct(buf[1]);
	} else if (lo == 0x6 || lo == 0x7) {
		return addressing_indirect(addressing_register(I8051_R0 + lo - 0x6));
	} else if (lo >= 0x8 && lo <= 0xf) {
		return addressing_register(I8051_R0 + lo - 0x8);
	}
	RZ_LOG_DEBUG("invalid addressing pattern 1")
	return NULL;
}

/**
 * \brief 0x00 \@DPTR
 *        0x02-0x03 @(R0|R1)
 */
static I8051OpAddressing *addressing_pattern11(const ut8 *buf) {
	ut8 lo = buf[0] & 0x0f;
	switch (lo) {
	case 0x0:
		return addressing_indirect(addressing_register(I8051_DPTR));
	case 0x2:
	case 0x3:
		return addressing_indirect(addressing_register(I8051_R0 + lo - 0x2));
	default:
		RZ_LOG_DEBUG("invalid addressing pattern 11")
		return NULL;
	}
}

/**
 * \brief 0x04 #data
 *        0x05 iram addr
 *        0x06-0x07 @(R0|R1)
 *        0x08-0x0f, R0-R7
 */
static I8051OpAddressing *addressing_pattern1_imm(const ut8 *buf) {
	ut8 lo = buf[0] & 0x0f;
	if (lo == 0x4) {
		return addressing_immediate(buf[1]);
	} else if (lo >= 0x5 && lo <= 0xf) {
		return addressing_pattern1(buf);
	}
	RZ_LOG_DEBUG("invalid addressing pattern 1_imm")
	return NULL;
}

/**
 * \brief 0x02      iram addr, A
 *        0x03      iram addr, #data
 *        0x04      A, #data
 *        0x05      A, iram addr
 *        0x06-0x07 A, @R0/@R1
 *        0x08-0x0f A, R0-R7
 */
static bool addressing_pattern2(I8051Op *op, const ut8 *buf) {
	op->argc = 2;
	op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);

	ut8 lo = buf[0] & 0x0f;
	if (lo < 0x2) {
		return false;
	}

	if (lo >= 0x02 && lo <= 0x03) {
		op->argv[0] = addressing_direct(buf[1]);
		if (lo == 0x02) {
			op->len = 2;
			op->argv[1] = addressing_register_a();
		} else {
			op->len = 3;
			op->argv[1] = addressing_immediate(buf[2]);
		}
	} else {
		op->argv[0] = addressing_register_a();
		op->argv[1] = addressing_pattern1_imm(buf);
		op->len = lo >= 0x6 ? 1 : 2;
	}
	return true;
}

static I8051Op *rz_analysis_8051_op_parse(const ut8 *buf, ut64 len, ut64 pc) {
	if (!buf || len < 1) {
		return NULL;
	}
	I8051Op *op = RZ_NEW0(I8051Op);
	if (!op) {
		return NULL;
	}
	op->pc = pc;
	op->opcode = buf[0];
	op->inst = i8051_inst_tbl[op->opcode];

	ut8 lo = op->opcode & 0x0f;
	ut8 hi = op->opcode & 0xf0;
	switch (op->inst) {
	case I_ACALL:
	case I_AJMP: {
		/* absolute addressing */
		op->len = 2;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = RZ_NEW0(I8051OpAddressing);
		op->argv[0]->mode = I8051_ADDRESSING_ABSOLUTE;
		op->argv[0]->d.addr16 = (((buf[0] >> 4) / 2) << 8) | buf[1];
		break;
	}
	case I_LCALL:
	case I_LJMP: {
		/* long addressing */
		op->len = 3;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = RZ_NEW0(I8051OpAddressing);
		op->argv[0]->mode = I8051_ADDRESSING_LONG;
		op->argv[0]->d.addr16 = (buf[1] << 8) | buf[2];
		break;
	}
	case I_MOVC: {
		/* indexed addressing */
		op->len = 1;
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_register_a();
		op->argv[1] = addressing_indexed(hi == 0x90 ? I8051_DPTR : I8051_PC);
		break;
	}
	case I_JMP: {
		/* indexed addressing */
		op->len = 1;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_indexed(I8051_DPTR);
		break;
	}
	case I_SJMP:
	case I_JZ:
	case I_JNZ:
	case I_JC:
	case I_JNC: {
		/* relative addressing */
		op->len = 2;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, 1);
		op->argv[0] = addressing_relative(buf[1]);
		break;
	}
	case I_ADD:
	case I_ADDC:
	case I_SUBB: {
		op->len = lo <= 0x5 ? 2 : 1;
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_register_a();
		op->argv[1] = addressing_pattern1_imm(buf);
		break;
	}
	case I_INC:
	case I_DEC: {
		op->len = lo == 0x5 ? 2 : 1;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		switch (lo) {
		case 0x3: {
			op->argv[0] = addressing_register(I8051_DPTR);
			break;
		}
		case 0x4: {
			op->argv[0] = addressing_register_a();
			break;
		}
		default: {
			op->argv[0] = addressing_pattern1(buf);
			break;
		}
		}
		break;
	}
	case I_MUL:
	case I_DIV: {
		op->len = 1;
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_register_a();
		op->argv[1] = addressing_register_b();
		break;
	}
	case I_ANL:
	case I_ORL: {
		// 0x72 0xa0 0x82 0xb0
		if (op->opcode == 0x72 || op->opcode == 0xa0 || op->opcode == 0x82 || op->opcode == 0xb0) {
			// TODO: (ANL|ORL) C,/?bit addr
			op->len = 2;
			op->argc = 2;
			op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
			op->argv[0] = addressing_register(I8051_CY);
			op->argv[1] = addressing_bit(buf[1]);
		} else {
			addressing_pattern2(op, buf);
		}
		break;
	}
	case I_POP:
	case I_PUSH: {
		op->len = 2;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_direct(buf[1]);
		break;
	}
	case I_DJNZ: {
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		if (lo == 0x5) {
			op->len = 3;
			op->argv[0] = addressing_direct(buf[1]);
			op->argv[1] = addressing_relative(buf[2]);
		} else {
			op->len = 2;
			op->argv[0] = addressing_pattern1(buf);
			op->argv[1] = addressing_relative(buf[1]);
		}
		break;
	}
	case I_CJNE: {
		op->len = 3;
		op->argc = 3;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = lo > 0x5 ? addressing_pattern1(buf) : addressing_register_a();
		op->argv[1] = lo == 0x5 ? addressing_direct(buf[1]) : addressing_immediate(buf[1]);
		op->argv[2] = addressing_relative(buf[2]);
		break;
	}
	case I_CLR:
	case I_CPL:
	case I_DA: {
		op->len = lo == 2 ? 2 : 1;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		switch (lo) {
		case 0x2:
			op->argv[0] = addressing_bit(buf[1]);
			break;
		case 0x3:
			op->argv[0] = addressing_register(I8051_CY);
			break;
		case 0x4:
			op->argv[0] = addressing_register_a();
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	}
	case I_SETB: {
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		if (lo == 2) {
			op->argv[0] = addressing_bit(buf[1]);
			op->len = 2;
		} else {
			op->argv[0] = addressing_register(I8051_CY);
			op->len = 1;
		}
		break;
	}
	case I_XCH:
	case I_XCHD:
	case I_XRL: {
		addressing_pattern2(op, buf);
		break;
	}
	case I_MOV: {
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		switch (hi) {
		case 0x70: {
			op->argv[0] = lo == 0x4 ? addressing_register_a()
						: addressing_pattern1(buf);
			op->argv[1] = addressing_immediate(buf[1]);
			op->len = lo == 0x5 ? 3 : 2;
			break;
		}
		case 0x80: {
			op->argv[0] = addressing_direct(buf[1]);
			op->argv[1] = lo == 0x5 ? addressing_direct(buf[2]) : addressing_pattern1(buf);
			op->len = lo == 0x5 ? 3 : 2;
			break;
		}
		case 0x90: {
			switch (lo) {
			case 0x0: {
				op->argv[0] = addressing_register(I8051_DPTR);
				op->argv[1] = addressing_addr(I8051_ADDRESSING_IMMEDIATE16, (buf[1] << 8) | buf[2]);
				op->len = 3;
				break;
			}
			case 0x2: {
				op->argv[0] = addressing_bit(buf[1]);
				op->argv[1] = addressing_register(I8051_CY);
				op->len = 2;
				break;
			}
			default: {
				op->argv[0] = addressing_direct(buf[1]);
				op->argv[1] = addressing_register(I8051_CY);
				op->len = 2;
				break;
			}
			}
			break;
		}
		case 0xa0: {
			if (lo >= 0x5) {
				op->argv[0] = addressing_pattern1(buf);
				op->argv[1] = addressing_direct(buf[1]);
			} else if (lo == 0x2) {
				op->argv[0] = addressing_register(I8051_CY);
				op->argv[1] = addressing_bit(buf[1]);
			}
			op->len = 2;
			break;
		}
		case 0xe0: {
			op->argv[0] = addressing_register_a();
			op->argv[1] = addressing_pattern1(buf);
			op->len = lo == 0x5 ? 2 : 1;
			break;
		}
		case 0xf0: {
			op->argv[0] = addressing_pattern1(buf);
			op->argv[1] = addressing_register_a();
			op->len = lo == 0x5 ? 2 : 1;
			break;
		}
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	}
	case I_MOVX: {
		op->len = 1;
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		if (hi == 0xf) {
			op->argv[0] = addressing_pattern11(buf);
			op->argv[1] = addressing_register_a();
		} else {
			op->argv[0] = addressing_register_a();
			op->argv[1] = addressing_pattern11(buf);
		}
		break;
	}
	case I_JB:
	case I_JBC:
	case I_JNB: {
		op->len = 3;
		op->argc = 2;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_bit(buf[1]);
		op->argv[1] = addressing_relative(buf[2]);
		break;
	}
	case I_RL:
	case I_RLC:
	case I_RR:
	case I_RRC:
	case I_SWAP: {
		op->len = 1;
		op->argc = 1;
		op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);
		op->argv[0] = addressing_register_a();
		break;
	}
	case I_RET:
	case I_RETI:
	case I_NOP: {
		op->len = 1;
		op->argc = 0;
		break;
	}
	case I_UNDEFINED:
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	for (int i = 0; i < op->argc; ++i) {
		op->argv[i]->pc = pc;
	}

	return op;
}

#endif //_8051_OP_H_
