// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rl78.h"
#include "rl78_maps.h"
#include <stdio.h>

#define CHECK_BOUNDS(p, len) \
	if (*p >= len) { \
		return false; \
	}

static bool parse_operand(RL78Operand RZ_INOUT *operand, size_t RZ_INOUT *next_byte_p,
	const ut8 RZ_BORROW *buf, size_t buf_len);

static inline bool optype_es_applies(RL78OperandType type);

// used to decide whether an operand could resolve to a symbol
static inline bool final_value_known(RL78OperandType type);
static inline RL78Label addr_to_symbol(int addr);

/**
 * \brief Disassemble a byte sequence into an rl78_instr
 * \param instr Resulting instruction
 * \param byte_read Number of bytes disassembled
 * \param buf Byte buffer
 * \param buf_len Length of the buffer
 * \return false if byte sequence does not represent a valid instruction
 */
bool rl78_dis(RL78Instr RZ_OUT *instr, size_t RZ_OUT *bytes_read,
	const ut8 *buf, size_t buf_len) {
	if (buf_len == 0) {
		*bytes_read = 0;
		return false;
	}

	size_t next_byte_p = 0;
	int byte = buf[next_byte_p++];

	bool extension_addressing = false;
	if (byte == 0x11) {
		extension_addressing = true;
		if (next_byte_p >= buf_len) {
			*bytes_read = next_byte_p;
			return false;
		}

		byte = buf[next_byte_p++];
	}

	if (next_byte_p + 1 < buf_len) {
		// MULHU, MULH...
		if (byte == 0xCE && buf[next_byte_p] == 0xFB) {
			switch (buf[next_byte_p + 1]) {
			case 0x01: instr->operation = RL78_OPERATION_MULHU; break;
			case 0x02: instr->operation = RL78_OPERATION_MULH; break;
			case 0x03: instr->operation = RL78_OPERATION_DIVHU; break;
			case 0x0B: instr->operation = RL78_OPERATION_DIVWU; break;
			case 0x05: instr->operation = RL78_OPERATION_MACHU; break;
			case 0x06: instr->operation = RL78_OPERATION_MACH; break;
			default: break;
			}
		}

		// EI/DI aliases for set1 psw.7/clr1 psw.7
		if (byte == 0x71 && buf[next_byte_p + 1] == 0xFA) {
			switch (buf[next_byte_p]) {
			case 0x7A: instr->operation = RL78_OPERATION_EI; break;
			case 0x7B: instr->operation = RL78_OPERATION_DI; break;
			default: break;
			}
		}

		if (instr->operation != RL78_OPERATION_NONE) {
			*bytes_read = next_byte_p + 2;
			return true;
		}
	}

	// regular processing (get correct map, extract instruction and parse operands)
	int map = 0;
	switch (byte) {
	case 0x31:
		// 4th map
		map = 3;
		break;
	case 0x61:
		// 2nd map
		map = 1;
		break;
	case 0x71:
		// 3rd map
		map = 2;
		break;
	default:
		break;
	}

	// get next byte if other map was chosen
	if (map > 0) {
		if (next_byte_p >= buf_len) {
			*bytes_read = next_byte_p;
			return false;
		}

		byte = buf[next_byte_p++];
	}

	*instr = rl78_instr_maps[(map * 256) + byte];

	// an empty slot was indexed
	if (instr->operation == RL78_OPERATION_NONE) {
		*bytes_read = next_byte_p;
		return false;
	}

	if (!parse_operand(&instr->op0, &next_byte_p, buf, buf_len) ||
		!parse_operand(&instr->op1, &next_byte_p, buf, buf_len)) {
		*bytes_read = next_byte_p;
		return false;
	}

	if (extension_addressing) {
		if (optype_es_applies(instr->op0.type)) {
			instr->op0.flags |= RL78_OP_FLAG_ES;
		} else if (optype_es_applies(instr->op1.type)) {
			instr->op1.flags |= RL78_OP_FLAG_ES;
		}
	}

	*bytes_read = next_byte_p;
	return true;
}

static bool parse_operand(RL78Operand RZ_INOUT *operand, size_t RZ_INOUT *next_byte_p,
	const ut8 RZ_BORROW *buf, size_t buf_len) {
	switch (operand->type) {
	// byte-sized operands
	case RL78_OP_TYPE_IMMEDIATE_8:
	case RL78_OP_TYPE_RELATIVE_ADDR_8:
	case RL78_OP_TYPE_BASED_ADDR_8:
		// already has value
		if (operand->v1 != 0) {
			return true;
		}

		CHECK_BOUNDS(next_byte_p, buf_len);

		if (operand->type == RL78_OP_TYPE_BASED_ADDR_8) {
			// write to v1 since v0 already has base register
			operand->v1 = buf[*next_byte_p];
		} else {
			operand->v0 = buf[*next_byte_p];
		}
		(*next_byte_p)++;

		break;

	case RL78_OP_TYPE_SFR:
		if (operand->v0 != 0) {
			// already has value
			return true;
		}

		CHECK_BOUNDS(next_byte_p, buf_len);

		operand->v0 = 0xFFF00 + buf[*next_byte_p];
		(*next_byte_p)++;

		break;

	case RL78_OP_TYPE_SADDR:
		CHECK_BOUNDS(next_byte_p, buf_len);

		operand->v0 = 0xFFE20 + buf[*next_byte_p];
		(*next_byte_p)++;

		break;

		// word-sized operands
	case RL78_OP_TYPE_IMMEDIATE_16:
	case RL78_OP_TYPE_ABSOLUTE_ADDR_16:
	case RL78_OP_TYPE_RELATIVE_ADDR_16:
	case RL78_OP_TYPE_BASED_ADDR_16:
		CHECK_BOUNDS(next_byte_p, buf_len);

		int word = buf[*next_byte_p];
		(*next_byte_p)++;

		CHECK_BOUNDS(next_byte_p, buf_len);

		word |= (int)buf[*next_byte_p] << 8;
		(*next_byte_p)++;

		if (operand->type == RL78_OP_TYPE_BASED_ADDR_16) {
			// write to v1 since v0 already has base register
			operand->v1 = word;
		} else {
			operand->v0 = word;
		}

		break;

		// 20 bit
	case RL78_OP_TYPE_ABSOLUTE_ADDR_20:
		CHECK_BOUNDS(next_byte_p, buf_len);

		int val = buf[*next_byte_p];
		(*next_byte_p)++;

		CHECK_BOUNDS(next_byte_p, buf_len);

		val |= (int)buf[*next_byte_p] << 8;
		(*next_byte_p)++;

		CHECK_BOUNDS(next_byte_p, buf_len);

		val |= (int)(buf[*next_byte_p] & 0xf) << 16;
		(*next_byte_p)++;

		operand->v0 = val;

		break;

	default: // no need to get additional data (NONE, SYMBOL, ...)
		break;
	}

	if (final_value_known(operand->type)) {
		// try resolving address to symbol for known fixed addresses
		RL78Label symbol = addr_to_symbol(operand->v0);
		if (rl78_symbol_valid(symbol)) {
			operand->v0 = symbol;
		}
	}

	return true;
}

static inline bool optype_es_applies(RL78OperandType type) {
	return type == RL78_OP_TYPE_INDIRECT_ADDR ||
		type == RL78_OP_TYPE_BASED_ADDR_8 ||
		type == RL78_OP_TYPE_BASED_ADDR_16 ||
		type == RL78_OP_TYPE_ABSOLUTE_ADDR_16 ||
		type == RL78_OP_TYPE_BASED_INDEX_ADDR;
}

static inline bool final_value_known(RL78OperandType type) {
	return type == RL78_OP_TYPE_ABSOLUTE_ADDR_16 ||
		type == RL78_OP_TYPE_ABSOLUTE_ADDR_20 ||
		type == RL78_OP_TYPE_SFR ||
		type == RL78_OP_TYPE_SADDR;
}

static inline RL78Label addr_to_symbol(int addr) {
	switch (addr) {
	// TODO add general-purpose registers
	case 0xFFFF8: return RL78_SFR_SPL;
	case 0xFFFF9: return RL78_SFR_SPH;
	case 0xFFFFA:
		return RL78_SFR_PSW;
		// case 0xFB: (reserved)
	case 0xFFFFC: return RL78_SFR_CS;
	case 0xFFFFD: return RL78_SFR_ES;
	case 0xFFFFE: return RL78_SFR_PMC;
	case 0xFFFFF: return RL78_SFR_MEM;
	default:
		// invalid
		return _RL78_SYMBOL_COUNT;
	}
}
