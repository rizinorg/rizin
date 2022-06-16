// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "disassembler.h"

/**
 * \brief Get SHParam from opcode, start bit and addressing mode
 * Make sure the opcode is passed in little-endian form
 *
 * \param opcode instruction opcode (assumed to be in little-endian)
 * \param start start bit (in little-endian)
 * \param mode addressing mode used
 * \return SHParam
 */
SHParam sh_op_get_param(ut16 opcode, ut8 start, SHAddrMode mode) {
	ut16 nibble = opcode >> start;
	ut8 len = 0;

	switch (mode) {
	case SH_REG_DIRECT:
	case SH_REG_INDIRECT:
	case SH_REG_INDIRECT_I:
	case SH_REG_INDIRECT_D:
	case SH_REG_INDIRECT_INDEXED:
	case SH_REG_INDIRECT_DISP:
	case SH_PC_RELATIVE_REG:
		len = 4;
		break;
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
	ret_param.mode = mode;
	switch (mode) {
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
		RZ_LOG_ERROR("SuperH: Invalid addressing mode encountered in assembler")
	}

	return ret_param;
}

typedef struct sh_op_raw_t {
	const char *str_mnem;
	SHOpMnem mnemonic;
	ut16 opcode;
	SHScaling scaling;
} SHOpRaw;

SHOp *sh_disassembler(ut16 opcode, bool be) {

	return NULL;
}
