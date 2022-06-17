// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "disassembler.h"

struct sh_param_builder_addr_t {
	ut8 start; ///< start bit of the param (assuming little-endian)
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

/**
 * \brief Get SHParam from opcode
 * Make sure the opcode is passed in little-endian form
 *
 * \param opcode instruction opcode (assumed to be in little-endian)
 * \param shb SHParamBuilder instance which contains the necessary info to find the param
 */
SHParam sh_op_get_param(ut16 opcode, SHParamBuilder shb) {
	if (shb.is_param) {
		return shb.param;
	}
	if (shb.addr.mode == SH_ADDR_INVALID) {
		SHParam invalid;
		invalid.mode = SH_ADDR_INVALID;
		return invalid;
	}

	ut16 nibble = opcode >> shb.addr.start;
	ut8 len = 0;

	switch (shb.addr.mode) {
	case SH_REG_DIRECT:
	case SH_REG_INDIRECT:
	case SH_REG_INDIRECT_I:
	case SH_REG_INDIRECT_D:
	case SH_REG_INDIRECT_INDEXED:
	case SH_PC_RELATIVE_REG:
		len = 4;
		break;
	case SH_REG_INDIRECT_DISP:
	case SH_GBR_INDIRECT_DISP:
	case SH_PC_RELATIVE_DISP:
		len = 8;
		break;
	case SH_PC_RELATIVE:
		len = 12;
		break;
	case SH_IMM_S:
	case SH_IMM_U:
		len = 8;
		break;
	default:
		break;
	}

	nibble &= 0xffff >> (16 - len);

	SHParam ret_param;
	ret_param.mode = shb.addr.mode;
	switch (shb.addr.mode) {
	case SH_REG_DIRECT:
	case SH_REG_INDIRECT:
	case SH_REG_INDIRECT_I:
	case SH_REG_INDIRECT_D:
	case SH_REG_INDIRECT_INDEXED:
	case SH_GBR_INDIRECT_DISP:
	case SH_PC_RELATIVE_DISP:
	case SH_PC_RELATIVE:
	case SH_PC_RELATIVE_REG:
	case SH_IMM_S:
	case SH_IMM_U:
		ret_param.param[0] = nibble;
		break;
	case SH_REG_INDIRECT_DISP:
		ret_param.param[0] = nibble >> 4;
		ret_param.param[1] = nibble & 0b1111;
		break;
	case SH_GBR_INDIRECT_INDEXED:
		break;
	default:
		break;
	}

	return ret_param;
}

typedef struct sh_op_raw_t {
	const char *str_mnem; ///< string mnemonic
	SHOpMnem mnemonic; ///< enum mnemonic
	ut16 opcode; ///< opcode
	ut16 mask; ///< mask for opcode to mask out param bits
	SHScaling scaling; ///< scaling for the opcode
	SHParamBuilder param_builder[2]; ///< param builders for the params
} SHOpRaw;

// xxxx used to denote param fields in the opcode
#define iiii 1111
#define nnnn 1111
#define dddd 1111
#define mmmm 1111

// to form opcode in nibbles
#define OPCODE_(a, b, c, d) 0b##a##b##c##d
#define OPCODE(a, b, c, d)  OPCODE_(a, b, c, d)

// nibble position
#define NIB0 0
#define NIB1 4
#define NIB2 8
#define NIB3 12

// return a param builder struct
#define ADDR(nib, addrmode) \
	{ \
		{ .addr = { .start = nib, .mode = addrmode } }, .is_param = false \
	}

// return a param
#define PARAM(reg, addrmode) \
	{ { .param = { .param = { \
			       SH_REG_IND_##reg, \
		       }, \
		    .mode = addrmode } }, \
		.is_param = true }

// opcode for "weird" movl
#define MOVL 0b000111111111

/**
 * @brief Get params for mov.l instruction (0001nnnnmmmmdddd)
 * A special function is required because the nibbles for the second param (@(disp:Rn)) (i.e. nnnn and dddd)
 * are separated by the nibble for the first param (Rm) (i.e. mmmm), so sh_op_get_param cannot be used
 *
 * \param opcode opcode
 * \param m if true, get Rm ; otherwise get @(disp:Rn)
 * \return SHParam return appropriate param
 */
static SHParam sh_op_get_param_movl(ut16 opcode, bool m) {
	if (m) {
		ut16 reg = (opcode >> 4) & 0xf;
		return (SHParam){ .param = {
					  reg,
				  },
			.mode = SH_REG_DIRECT };
	} else {
		ut16 d = opcode & 0xf;
		ut16 n = (opcode >> 8) & 0xf;
		return (SHParam){ .param = { n, d }, .mode = SH_REG_INDIRECT_DISP };
	}
}

// Opcode lookup list
const SHOpRaw sh_op_lookup[] = {
	{ "mov", SH_OP_MOV, OPCODE(1110, nnnn, iiii, iiii), 0x0fff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_U), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(1001, nnnn, dddd, dddd), 0x0fff, SH_SCALING_W, { ADDR(NIB0, SH_PC_RELATIVE_DISP), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(1101, nnnn, dddd, dddd), 0x0fff, SH_SCALING_L, { ADDR(NIB0, SH_PC_RELATIVE_DISP), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0011), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0010, nnnn, mmmm, 0000), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0010, nnnn, mmmm, 0001), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0010, nnnn, mmmm, 0010), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0000), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_INDIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0001), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0010), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0010, nnnn, mmmm, 0100), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_D) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0010, nnnn, mmmm, 0101), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_D) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0010, nnnn, mmmm, 0110), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_D) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0100), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0101), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0110, nnnn, mmmm, 0110), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(1000, 0000, nnnn, dddd), 0x00ff, SH_SCALING_B, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_REG_INDIRECT_DISP) } },
	{ "mov.w", SH_OP_MOV, OPCODE(1000, 0001, nnnn, dddd), 0x00ff, SH_SCALING_W, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_REG_INDIRECT_DISP) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0001, nnnn, mmmm, dddd), 0x0fff, SH_SCALING_L, { /*dummy values*/ ADDR(NIB0, SH_ADDR_INVALID), ADDR(NIB0, SH_ADDR_INVALID) } },
	// ^ Just this instruction is kinda weird, so needs to be taken care by sh_op_get_param_movl
	{ "mov.b", SH_OP_MOV, OPCODE(1000, 0100, mmmm, dddd), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_REG_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(1000, 0101, mmmm, dddd), 0x00ff, SH_SCALING_W, { ADDR(NIB0, SH_REG_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0101, nnnn, mmmm, dddd), 0x0fff, SH_SCALING_L, { ADDR(NIB0, SH_REG_INDIRECT_DISP), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0000, nnnn, mmmm, 0100), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_INDEXED) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0000, nnnn, mmmm, 0101), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_INDEXED) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0000, nnnn, mmmm, 0110), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_INDEXED) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0000, nnnn, mmmm, 1100), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_INDIRECT_INDEXED), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0000, nnnn, mmmm, 1101), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT_INDEXED), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0000, nnnn, mmmm, 1110), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT_INDEXED), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(1100, 0000, dddd, dddd), 0x00ff, SH_SCALING_B, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_GBR_INDIRECT_DISP) } },
	{ "mov.w", SH_OP_MOV, OPCODE(1100, 0001, dddd, dddd), 0x00ff, SH_SCALING_W, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_GBR_INDIRECT_DISP) } },
	{ "mov.l", SH_OP_MOV, OPCODE(1100, 0010, dddd, dddd), 0x00ff, SH_SCALING_L, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_GBR_INDIRECT_DISP) } },
	{ "mov.b", SH_OP_MOV, OPCODE(1100, 0100, dddd, dddd), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_GBR_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(1100, 0101, dddd, dddd), 0x00ff, SH_SCALING_W, { ADDR(NIB0, SH_GBR_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(1100, 0110, dddd, dddd), 0x00ff, SH_SCALING_L, { ADDR(NIB0, SH_GBR_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mova", SH_OP_MOV, OPCODE(1100, 0111, dddd, dddd), 0x00ff, SH_SCALING_L, { ADDR(NIB0, SH_PC_RELATIVE_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "movt", SH_OP_MOVT, OPCODE(0000, nnnn, 0010, 1001), 0x0f00, SH_SCALING_INVALID, {
												  ADDR(NIB2, SH_REG_DIRECT),
											  } }
};

#undef PARAM
#undef ADDR
#undef OPCODE
#undef OPCODE_
#undef mmmm
#undef dddd
#undef nnnn
#undef iiii

/**
 * \brief Disassemble \p opcode and return a SHOp
 *
 * \param opcode 16 bit wide opcode
 * \return SHOp object corresponding to the opcode
 */
SHOp *sh_disassembler(ut16 opcode) {
	ut32 opcode_num = sizeof(sh_op_lookup) / sizeof(SHOpRaw);

	for (ut16 i = 0; i < opcode_num; i++) {
		if ((opcode | sh_op_lookup[i].mask) == sh_op_lookup[i].opcode) {
			SHOpRaw raw = sh_op_lookup[i];
			SHOp *op = RZ_NEW(SHOp);
			op->opcode = opcode;
			op->mnemonic = raw.mnemonic;
			op->scaling = raw.scaling;
			op->str_mnem = raw.str_mnem;
			// check for "weird" mov.l
			if (raw.opcode == MOVL) {
				op->param[0] = sh_op_get_param_movl(opcode, true);
				op->param[1] = sh_op_get_param_movl(opcode, false);
				return op;
			}
			op->param[0] = sh_op_get_param(opcode, raw.param_builder[0]);
			op->param[1] = sh_op_get_param(opcode, raw.param_builder[1]);
			return op;
		}
	}

	RZ_LOG_WARN("SuperH: Invalid opcode encountered by disassembler")
	return NULL;
}
