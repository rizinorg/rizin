// SPDX-FileCopyrightText: 2024 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <msp430/msp430_il.h>
#include <msp430/msp430_register_names.h>

#include <rz_il/rz_il_opbuilder_begin.h>

#define MSP430_GETR(r)    VARG(msp430_register_names[r])
#define MSP430_SETR(r, v) SETG(msp430_register_names[r], v)

#define WORD_SIZED_READ  1
#define WORD_SIZED_WRITE 2

static inline ut8 word_sizedness(const Msp430Instruction *op);

static inline RZ_OWN RzILOpBitVector *calculate_mem_address(Msp430AddressingMode mode, ut32 operand, ut64 current_addr) {
	switch (mode) {
	case MSP430_INDX: return ADD(U16(operand >> 8), MSP430_GETR(operand & 0x000000FF));
	case MSP430_SYM: return ADD(U16(operand), U16(current_addr));
	case MSP430_ABS: return U16(operand);
	case MSP430_IND_REG:
	case MSP430_IND_AUTOINC:
		return MSP430_GETR(operand);

	default: return NULL;
	}
}

static inline RZ_OWN RzILOpBitVector *decode_operand(const Msp430Instruction *op, Msp430AddressingMode mode, ut32 operand, ut64 current_addr) {
	switch (mode) {
	case MSP430_REG: {
		RzILOpBitVector *reg = MSP430_GETR(operand);
		if (word_sizedness(op) & WORD_SIZED_READ) {
			return reg;
		}
		return CAST(8, IL_FALSE, reg);
	}

	case MSP430_IMM: {
		if (word_sizedness(op) & WORD_SIZED_READ) {
			return U16(operand);
		}
		return U8(operand);
	}

	default: {
		RzILOpBitVector *address = calculate_mem_address(mode, operand, current_addr);
		if (address != NULL) {
			if (word_sizedness(op) & WORD_SIZED_READ) {
				return LOADW(16, address);
			}
			return LOADW(8, address);
		}

		rz_warn_if_reached();
		return U8(0);
	}
	}
}

static inline RZ_OWN RzILOpBitVector *get_source(const Msp430Instruction *op, ut64 current_addr) {
	return decode_operand(op, op->src_mode, op->src, current_addr);
}

static inline RZ_OWN RzILOpBitVector *get_destination(const Msp430Instruction *op, ut64 current_addr) {
	return decode_operand(op, op->dst_mode, op->dst, current_addr);
}

typedef struct {
	RzILOpBitVector *first;
	RzILOpBitVector *second;
} BVPair;

// special getter for swpb
// returns the destination as a "destructured" pair of bytes
static inline RZ_OWN BVPair get_destination_destructured(const Msp430Instruction *op, ut64 current_addr) {
	switch (op->dst_mode) {
	case MSP430_REG: {
		RzILOpBitVector *reg = MSP430_GETR(op->dst);
		BVPair res;
		res.first = CAST(8, IL_FALSE, reg);
		res.second = CAST(8, IL_FALSE, SHIFTR0(DUP(reg), U8(8)));
		return res;
	}
	default: {
		RzILOpBitVector *address = calculate_mem_address(op->dst_mode, op->dst, current_addr);
		if (address != NULL) {
			BVPair res;
			res.first = LOAD(address);
			res.second = LOAD(ADD(address, U16(1)));
			return res;
		}

		rz_warn_if_reached();
		BVPair dummy = { .first = U8(0), .second = U8(0) };
		return dummy;
	}
	}
}

static inline RZ_OWN RzILOpEffect *set_destination(const Msp430Instruction *op, RzILOpBitVector *new_value, ut64 current_addr) {
	switch (op->dst_mode) {
	case MSP430_REG: {
		if (word_sizedness(op) & WORD_SIZED_WRITE) {
			return MSP430_SETR(op->dst, new_value);
		}
		// the general idea is: First we zero the lower byte through ANDing with 0xFF00
		//                      Then we assign the lower byte to the (byte-length) result through ORing with 0x00<result>
		// the overall effect is that only the lower byte is assigned, which is what byte-sized operations do
		return MSP430_SETR(op->dst, UNSIGNED(16, new_value));
	}

	default: {
		RzILOpBitVector *address = calculate_mem_address(op->dst_mode, op->dst, current_addr);
		if (address != NULL) {
			if (word_sizedness(op) & WORD_SIZED_WRITE) {
				return STOREW(address, new_value);
			}
			return STORE(address, new_value);
		}

		rz_warn_if_reached();
		return NOP();
	}
	}
}

static inline ut8 word_sizedness(const Msp430Instruction *op) {
	// the sign extend is special: it always reads a byte but writes a word
	// this is the only reason there are 2 flags for the sizedness of a read and the sizedness of a write
	if (op->opcode == MSP430_SXT) {
		return WORD_SIZED_WRITE;
	}

	// otherwise, all instructions read and write with the same sizedness
	// 0 means the read and write are both byte-sized
	// 3 = 1|2 means the read and the write are both word-sized
	return (op->is_byte) ? 0 : (WORD_SIZED_READ | WORD_SIZED_WRITE);
}

#include <rz_il/rz_il_opbuilder_end.h>
