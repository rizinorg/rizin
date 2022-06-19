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
	case SH_PC_RELATIVE8:
	case SH_IMM_S:
	case SH_IMM_U:
		len = 8;
		break;
	case SH_PC_RELATIVE12:
		len = 12;
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
	case SH_PC_RELATIVE8:
	case SH_PC_RELATIVE12:
	case SH_PC_RELATIVE_REG:
	case SH_IMM_S:
	case SH_IMM_U:
		ret_param.param[0] = nibble;
		break;
	case SH_REG_INDIRECT_DISP:
		ret_param.param[0] = nibble >> 4;
		ret_param.param[1] = nibble & 0xf;
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
#define MOVL 0x1fff

#define NOPARAM ADDR(NIB0, SH_ADDR_INVALID)

/**
 * @brief Get params for mov.l instruction (0001NMD)
 * A special function is required because the nibbles for the second param (@(disp:Rn)) (i.e. N and D)
 * are separated by the nibble for the first param (Rm) (i.e. M), so sh_op_get_param cannot be used
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
	/* fixed-point transfer instructions */
	{ "mov", SH_OP_MOV, OPCODE(e, N, I, I), 0x0fff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_U), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(9, N, D, D), 0x0fff, SH_SCALING_W, { ADDR(NIB0, SH_PC_RELATIVE_DISP), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(d, N, D, D), 0x0fff, SH_SCALING_L, { ADDR(NIB0, SH_PC_RELATIVE_DISP), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov", SH_OP_MOV, OPCODE(6, N, M, 3), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(2, N, M, 0), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(2, N, M, 1), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(2, N, M, 2), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(6, N, M, 0), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_INDIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(6, N, M, 1), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(6, N, M, 2), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(2, N, M, 4), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_D) } },
	{ "mov.w", SH_OP_MOV, OPCODE(2, N, M, 5), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_D) } },
	{ "mov.l", SH_OP_MOV, OPCODE(2, N, M, 6), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_D) } },
	{ "mov.b", SH_OP_MOV, OPCODE(6, N, M, 4), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(6, N, M, 5), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(6, N, M, 6), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(8, 0, N, D), 0x00ff, SH_SCALING_B, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_REG_INDIRECT_DISP) } },
	{ "mov.w", SH_OP_MOV, OPCODE(8, 1, N, D), 0x00ff, SH_SCALING_W, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_REG_INDIRECT_DISP) } },
	{ "mov.l", SH_OP_MOV, OPCODE(1, N, M, D), 0x0fff, SH_SCALING_L, { /*dummy values*/ ADDR(NIB0, SH_ADDR_INVALID), ADDR(NIB0, SH_ADDR_INVALID) } },
	// ^ Just this instruction is kinda weird, so needs to be taken care by sh_op_get_param_movl
	{ "mov.b", SH_OP_MOV, OPCODE(8, 4, M, D), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_REG_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(8, 5, M, D), 0x00ff, SH_SCALING_W, { ADDR(NIB0, SH_REG_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(5, N, M, D), 0x0fff, SH_SCALING_L, { ADDR(NIB0, SH_REG_INDIRECT_DISP), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0, N, M, 4), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_INDEXED) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0, N, M, 5), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_INDEXED) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0, N, M, 6), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_INDIRECT_INDEXED) } },
	{ "mov.b", SH_OP_MOV, OPCODE(0, N, M, c), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_INDIRECT_INDEXED), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(0, N, M, d), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT_INDEXED), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(0, N, M, e), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT_INDEXED), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mov.b", SH_OP_MOV, OPCODE(c, 0, D, D), 0x00ff, SH_SCALING_B, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_GBR_INDIRECT_DISP) } },
	{ "mov.w", SH_OP_MOV, OPCODE(c, 1, D, D), 0x00ff, SH_SCALING_W, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_GBR_INDIRECT_DISP) } },
	{ "mov.l", SH_OP_MOV, OPCODE(c, 2, D, D), 0x00ff, SH_SCALING_L, { PARAM(R0, SH_REG_DIRECT), ADDR(NIB0, SH_GBR_INDIRECT_DISP) } },
	{ "mov.b", SH_OP_MOV, OPCODE(c, 4, D, D), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_GBR_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.w", SH_OP_MOV, OPCODE(c, 5, D, D), 0x00ff, SH_SCALING_W, { ADDR(NIB0, SH_GBR_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mov.l", SH_OP_MOV, OPCODE(c, 6, D, D), 0x00ff, SH_SCALING_L, { ADDR(NIB0, SH_GBR_INDIRECT_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "mova", SH_OP_MOV, OPCODE(c, 7, D, D), 0x00ff, SH_SCALING_L, { ADDR(NIB0, SH_PC_RELATIVE_DISP), PARAM(R0, SH_REG_DIRECT) } },
	{ "movt", SH_OP_MOVT, OPCODE(0, N, 2, 9), 0x0f00, SH_SCALING_INVALID, { ADDR(NIB2, SH_REG_DIRECT), NOPARAM } },
	{ "swap.b", SH_OP_SWAP, OPCODE(6, N, M, 8), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "swap.w", SH_OP_SWAP, OPCODE(6, N, M, 9), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "xtrct", SH_OP_XTRCT, OPCODE(2, N, M, d), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },

	/* arithmetic operation instructions */
	{ "add", SH_OP_ADD, OPCODE(3, N, M, c), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "add", SH_OP_ADD, OPCODE(7, N, I, I), 0x0fff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_S), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "addc", SH_OP_ADDC, OPCODE(3, N, M, e), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "addv", SH_OP_ADDV, OPCODE(3, N, M, f), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "cmp/eq", SH_OP_CMP_EQ, OPCODE(8, 8, I, I), 0x00ff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_S), PARAM(R0, SH_REG_DIRECT) } },
	{ "cmp/eq", SH_OP_CMP_EQ, OPCODE(3, N, M, 0), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "cmp/hs", SH_OP_CMP_HS, OPCODE(3, N, M, 2), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "cmp/ge", SH_OP_CMP_GE, OPCODE(3, N, M, 3), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "cmp/hi", SH_OP_CMP_HI, OPCODE(3, N, M, 6), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "cmp/gt", SH_OP_CMP_GT, OPCODE(3, N, M, 7), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "cmp/pz", SH_OP_CMP_PZ, OPCODE(4, N, 1, 1), 0x0f00, SH_SCALING_INVALID, { ADDR(NIB2, SH_REG_DIRECT), NOPARAM } },
	{ "cmp/pl", SH_OP_CMP_PL, OPCODE(4, N, 1, 5), 0x0f00, SH_SCALING_INVALID, { ADDR(NIB2, SH_REG_DIRECT), NOPARAM } },
	{ "cmp/str", SH_OP_CMP_STR, OPCODE(2, N, M, c), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "div1", SH_OP_DIV1, OPCODE(3, N, M, 4), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "div0s", SH_OP_DIV0S, OPCODE(2, N, M, 7), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "div0u", SH_OP_DIV0U, OPCODE(0, 0, 1, 9), 0x0000, SH_SCALING_INVALID, { NOPARAM, NOPARAM } },
	{ "dmuls.l", SH_OP_DMULS, OPCODE(3, N, M, d), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "dmulu.l", SH_OP_DMULU, OPCODE(3, N, M, 5), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "dt", SH_OP_DT, OPCODE(4, N, 1, 0), 0x0f00, SH_SCALING_INVALID, { ADDR(NIB2, SH_REG_DIRECT), NOPARAM } },
	{ "exts.b", SH_OP_EXTS, OPCODE(6, N, M, e), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "exts.w", SH_OP_EXTS, OPCODE(6, N, M, f), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "extu.b", SH_OP_EXTU, OPCODE(6, N, M, c), 0x0ff0, SH_SCALING_B, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "extu.w", SH_OP_EXTU, OPCODE(6, N, M, d), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mac.l", SH_OP_MAC, OPCODE(0, N, M, f), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_INDIRECT_I) } },
	{ "mac.w", SH_OP_MAC, OPCODE(4, N, M, f), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_INDIRECT_I), ADDR(NIB2, SH_REG_INDIRECT_I) } },
	{ "mul.l", SH_OP_MUL, OPCODE(0, N, M, 7), 0x0ff0, SH_SCALING_L, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "muls.w", SH_OP_MULS, OPCODE(2, N, M, f), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "mulu.w", SH_OP_MULU, OPCODE(2, N, M, e), 0x0ff0, SH_SCALING_W, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "neg", SH_OP_NEG, OPCODE(6, N, M, b), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "negc", SH_OP_NEGC, OPCODE(6, N, M, a), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "sub", SH_OP_SUB, OPCODE(3, N, M, 8), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "subc", SH_OP_SUBC, OPCODE(3, N, M, a), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "subv", SH_OP_SUBV, OPCODE(3, N, M, b), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },

	/* logic operation instructions */
	{ "and", SH_OP_AND, OPCODE(2, N, M, 9), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "and", SH_OP_AND, OPCODE(c, 9, I, I), 0x00ff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_REG_DIRECT) } },
	{ "and.b", SH_OP_AND, OPCODE(c, d, I, I), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_GBR_INDIRECT_INDEXED) } },
	{ "not", SH_OP_NOT, OPCODE(6, N, M, 7), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "or", SH_OP_OR, OPCODE(2, N, M, b), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "or", SH_OP_OR, OPCODE(c, b, I, I), 0x00ff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_REG_DIRECT) } },
	{ "or.b", SH_OP_OR, OPCODE(c, f, I, I), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_GBR_INDIRECT_INDEXED) } },
	{ "tas.b", SH_OP_TAS, OPCODE(4, N, 1, a), 0x0f00, SH_SCALING_B, { ADDR(NIB2, SH_REG_INDIRECT), NOPARAM } },
	{ "tst", SH_OP_TST, OPCODE(2, N, M, 8), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "tst", SH_OP_TST, OPCODE(c, 8, I, I), 0x00ff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_REG_DIRECT) } },
	{ "tst.b", SH_OP_TST, OPCODE(c, c, I, I), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_GBR_INDIRECT_INDEXED) } },
	{ "xor", SH_OP_XOR, OPCODE(2, N, M, a), 0x0ff0, SH_SCALING_INVALID, { ADDR(NIB1, SH_REG_DIRECT), ADDR(NIB2, SH_REG_DIRECT) } },
	{ "xor", SH_OP_XOR, OPCODE(c, a, I, I), 0x00ff, SH_SCALING_INVALID, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_REG_DIRECT) } },
	{ "xor.b", SH_OP_XOR, OPCODE(c, e, I, I), 0x00ff, SH_SCALING_B, { ADDR(NIB0, SH_IMM_U), PARAM(R0, SH_GBR_INDIRECT_INDEXED) } },
};

#undef NOPARAM
#undef PARAM
#undef ADDR
#undef OPCODE
#undef OPCODE_
#undef M
#undef D
#undef N
#undef I

/**
 * \brief Disassemble \p opcode and return a SHOp
 *
 * \param opcode 16 bit wide opcode
 * \return SHOp object corresponding to the opcode
 */
RZ_API RZ_OWN SHOp *sh_disassembler(ut16 opcode) {
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

RZ_API RZ_OWN char *sh_op_param_to_str(SHParam param) {
	if (param.mode == SH_ADDR_INVALID) {
		return NULL;
	}

	RzStrBuf *buf = rz_strbuf_new(NULL);
	switch (param.mode) {
	case SH_REG_DIRECT:
		rz_strbuf_appendf(buf, "%s", sh_registers[param.param[0]]);
		break;
	case SH_REG_INDIRECT:
		rz_strbuf_appendf(buf, "@%s", sh_registers[param.param[0]]);
		break;
	case SH_REG_INDIRECT_I:
		rz_strbuf_appendf(buf, "@%s+", sh_registers[param.param[0]]);
		break;
	case SH_REG_INDIRECT_D:
		rz_strbuf_appendf(buf, "@-%s", sh_registers[param.param[0]]);
		break;
	case SH_REG_INDIRECT_DISP:
		rz_strbuf_appendf(buf, "@(%#03x,%s)", param.param[1], sh_registers[param.param[0]]);
		break;
	case SH_REG_INDIRECT_INDEXED:
		rz_strbuf_appendf(buf, "@(r0,%s)", sh_registers[param.param[0]]);
		break;
	case SH_GBR_INDIRECT_DISP:
		rz_strbuf_appendf(buf, "@(%#04x,gbr)", param.param[0]);
		break;
	case SH_GBR_INDIRECT_INDEXED:
		rz_strbuf_append(buf, "@(r0,gbr)");
		break;
	case SH_PC_RELATIVE_DISP:
		rz_strbuf_appendf(buf, "@(%#04x,pc)", param.param[0]);
		break;
	case SH_PC_RELATIVE8:
		rz_strbuf_appendf(buf, "@(%#04x:pc)", param.param[0]);
		break;
	case SH_PC_RELATIVE12:
		rz_strbuf_appendf(buf, "@(%#05x:pc)", param.param[0]);
		break;
	case SH_PC_RELATIVE_REG:
		rz_strbuf_appendf(buf, "@(%s:pc)", sh_registers[param.param[0]]);
		break;
	case SH_IMM_U:
	case SH_IMM_S:
		rz_strbuf_appendf(buf, "%#04x", param.param[0]);
		break;
	default:
		rz_warn_if_reached();
	}

	return rz_strbuf_drain(buf);
}

RZ_API RZ_OWN char *sh_op_to_str(const SHOp *op) {
	RzStrBuf *buf = rz_strbuf_new(op->str_mnem);

	char *param = NULL;
	if ((param = sh_op_param_to_str(op->param[0]))) {
		rz_strbuf_appendf(buf, "  %s", param);
		free(param);
		if ((param = sh_op_param_to_str(op->param[1]))) {
			rz_strbuf_appendf(buf, ", %s", param);
			free(param);
		}
	}

	return rz_strbuf_drain(buf);
}
