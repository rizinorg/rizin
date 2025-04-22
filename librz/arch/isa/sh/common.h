// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SH_COMMON_H
#define RZ_SH_COMMON_H

#include "disassembler.h"

struct sh_param_builder_addr_t {
	ut8 start; ///< start bit of the param (assuming little-endian)
	st8 bits; ///< bits to be read (-1, if you want this to be inferred from mode)
	SHAddrMode mode; ///< addressing mode being used
};

typedef struct sh_param_builder_t {
	// either find the param using param builder or use an already provided param
	union {
		struct sh_param_builder_addr_t addr;
		SHParam param;
	};
	bool is_param; ///< whether a param was directly passed
} SHParamBuilder;

typedef struct sh_op_raw_t {
	const char *str_mnem; ///< string mnemonic
	SHOpMnem mnemonic; ///< enum mnemonic
	ut16 opcode; ///< opcode
	ut16 mask; ///< mask for opcode to mask out param bits
	SHScaling scaling; ///< scaling for the opcode
	SHParamBuilder param_builder[2]; ///< param builders for the params
} SHOpRaw;

// xxxx used to denote param fields in the opcode
#define I f
#define N f
#define D f
#define M f

// to form opcode in nibbles
#define OPCODE_(a, b, c, d) 0x##a##b##c##d
#define OPCODE(a, b, c, d)  OPCODE_(a, b, c, d)

// nibble position
#define NIB0 0
#define NIB1 4
#define NIB2 8
#define NIB3 12

// return a param builder struct
#define ADDR(nib, addrmode) \
	{ \
		{ .addr = { .start = nib, .bits = -1, .mode = addrmode } }, .is_param = false \
	}

// return a param builder struct with custom bit read length
#define ADDRBITS(nib, addrmode, b) \
	{ \
		{ .addr = { .start = nib, .bits = b, .mode = addrmode } }, .is_param = false \
	}

// return a param
#define PARAM(reg, addrmode) \
	{ { .param = { .param = { \
			       SH_REG_IND_##reg, \
		       }, \
		    .mode = addrmode } }, \
		.is_param = true }

// opcode for "weird" movl
#define MOVL 0x1fff

#define NOPARAM ADDR(NIB0, SH_ADDR_INVALID)

#endif // RZ_SH_COMMON_H
