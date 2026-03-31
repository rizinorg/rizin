// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "8051_il.h"
#include <rz_util.h>
#include <rz_endian.h>

static I8051OpAddressing *addressing_addr(I8051AddressingMode mode, ut8 addr) {
	I8051OpAddressing *a = RZ_NEW0(I8051OpAddressing);
	if (!a) {
		return NULL;
	}
	a->mode = mode;
	a->d.addr = addr;
	return a;
}

static I8051OpAddressing *addressing_addr16(I8051AddressingMode mode, ut16 addr) {
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

static I8051OpAddressing *addressing_immediate16(ut16 imm) {
	return addressing_addr16(I8051_ADDRESSING_IMMEDIATE16, imm);
}

static I8051OpAddressing *addressing_bit(ut8 addr) {
	return addressing_addr(I8051_ADDRESSING_BIT, addr);
}

static I8051OpAddressing *addressing_register(I8051Register reg) {
	I8051OpAddressing *a = RZ_NEW0(I8051OpAddressing);
	if (!a) {
		return NULL;
	}
	a->mode = I8051_ADDRESSING_REGISTER;
	a->d.reg = reg;
	return a;
}

static inline I8051OpAddressing *addressing_register_a() {
	return addressing_register(I8051_ACC);
}

static inline I8051OpAddressing *addressing_indexed(I8051Register reg) {
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
 * \brief Parse some of the patterns commonly found in the 8051 Instruction Set,
 * get the parameters and addressing mode of the instruction by (opcode & 0x0f).
 * Only used in rz_8051_op_parse.
 *
 * 0x05 iram addr
 * 0x06-0x07 @(R0-R1)
 * 0x08-0x0f R0-R7
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
	RZ_LOG_DEBUG("invalid addressing pattern 1\n")
	return NULL;
}

/**
 * \brief Parse some of the patterns commonly found in the 8051 Instruction Set,
 * get the parameters and addressing mode of the instruction by (opcode & 0x0f).
 * Only used in rz_8051_op_parse.
 *
 * 0x00 \@DPTR
 * 0x02-0x03 @(R0|R1)
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
		RZ_LOG_DEBUG("invalid addressing pattern 11\n")
		return NULL;
	}
}

/**
 * \brief Parse some of the patterns commonly found in the 8051 Instruction Set,
 * get the parameters and addressing mode of the instruction by (opcode & 0x0f).
 * Only used in rz_8051_op_parse.
 *
 * 0x04 #data
 * 0x05 iram addr
 * 0x06-0x07 \@(R0|R1)
 * 0x08-0x0f R0-R7
 */
static I8051OpAddressing *addressing_pattern1_imm(const ut8 *buf) {
	ut8 lo = buf[0] & 0x0f;
	if (lo == 0x4) {
		return addressing_immediate(buf[1]);
	} else if (lo >= 0x5) {
		return addressing_pattern1(buf);
	}
	RZ_LOG_DEBUG("invalid addressing pattern 1_imm\n")
	return NULL;
}

/**
 * \brief Parse some of the patterns commonly found in the 8051 Instruction Set,
 * get the parameters and addressing mode of the instruction by (opcode & 0x0f).
 * Only used in rz_8051_op_parse.
 *
 * 0x02      iram addr, A
 * 0x03      iram addr, #data
 * 0x04      A, #data
 * 0x05      A, iram addr
 * 0x06-0x07 A, \@R0/\@R1
 * 0x08-0x0f A, R0-R7
 */
static bool addressing_pattern2(I8051Op *op, const ut8 *buf) {
	op->argc = 2;
	op->argv = RZ_NEWS0(I8051OpAddressing *, op->argc);

	ut8 lo = buf[0] & 0x0f;
	if (lo < 0x2) {
		return false;
	}
	switch (lo) {
	case 0x2: {
		op->argv[0] = addressing_direct(buf[1]);
		op->argv[1] = addressing_register_a();
		op->len = 2;
		break;
	}
	case 0x3: {
		op->argv[0] = addressing_direct(buf[1]);
		op->argv[1] = addressing_immediate(buf[2]);
		op->len = 3;
		break;
	}
	default: {
		op->argv[0] = addressing_register_a();
		op->argv[1] = addressing_pattern1_imm(buf);
		op->len = lo >= 0x6 ? 1 : 2;
		break;
	}
	}
	return true;
}

RZ_IPI I8051Op *rz_8051_op_parse(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const ut8 *buf, int len, ut64 pc) {
	rz_return_val_if_fail(analysis && buf && len > 0, NULL);
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
			switch (lo) {
			case 4: {
				op->argv[0] = addressing_register_a();
				op->argv[1] = addressing_immediate(buf[1]);
				op->len = 2;
				break;
			}
			case 5: {
				op->argv[0] = addressing_direct(buf[1]);
				op->argv[1] = addressing_immediate(buf[2]);
				op->len = 3;
				break;
			}
			default: {
				op->argv[0] = addressing_pattern1(buf);
				op->argv[1] = addressing_immediate(buf[1]);
				op->len = 2;
				break;
			}
			}
			break;
		}
		case 0x80: {
			op->argv[0] = addressing_direct(buf[1]);
			if (lo == 0x5) {
				op->argv[1] = addressing_direct(buf[2]);
				op->len = 3;
			} else {
				op->argv[1] = addressing_pattern1(buf);
				op->len = 2;
			}
			break;
		}
		case 0x90: {
			switch (lo) {
			case 0x0: {
				op->argv[0] = addressing_register(I8051_DPTR);
				ut16 imm = ((ut16)buf[1] << 8) | ((ut16)buf[2]);
				op->argv[1] = addressing_immediate16(imm);
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
			if (lo == 0x2) {
				op->argv[0] = addressing_register(I8051_CY);
				op->argv[1] = addressing_bit(buf[1]);
			} else if (lo >= 0x6) {
				op->argv[0] = addressing_pattern1(buf);
				op->argv[1] = addressing_direct(buf[1]);
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
		op->argv[i]->op = op;
		op->argv[i]->ctx = (i8051_plugin_context *)analysis->plugin_data;
	}

	return op;
}
