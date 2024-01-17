// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "disassembler.h"
#include "common.h"
#include "regs.h"

extern const SHOpRaw sh_op_lookup[];
extern const ut32 OPCODE_NUM;

/**
 * \brief Get SHParam from opcode
 * Make sure the opcode is passed in little-endian form
 *
 * \param opcode instruction opcode (assumed to be in little-endian)
 * \param shb SHParamBuilder instance which contains the necessary info to find the param
 */
static SHParam sh_op_get_param(ut16 opcode, SHParamBuilder shb) {
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

	if (shb.addr.bits != -1) {
		// do not infer the bit length from mode
		len = shb.addr.bits;
		goto extract;
	}

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

extract:

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

	/* For the special case of banked registers in `LDC` and `STC`, the bit length is 3
	In such case, we can modify the param found to correspond to its banked counterpart */
	if (len == 3) {
		ret_param.param[0] += SH_REG_IND_R0B;
	}

	return ret_param;
}

/**
 * \brief Get params for mov.l instruction (0001NMD)
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

/**
 * \brief Disassemble \p opcode and return a SHOp
 *
 * \param opcode 16 bit wide opcode
 * \return SHOp object corresponding to the opcode
 */
RZ_IPI RZ_OWN SHOp *sh_disassembler(ut16 opcode) {
	for (ut16 i = 0; i < OPCODE_NUM; i++) {
		if ((opcode | sh_op_lookup[i].mask) != sh_op_lookup[i].opcode) {
			continue;
		}

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

	RZ_LOG_DEBUG("SuperH: Invalid opcode encountered by disassembler: 0x%06x\n", opcode);
	return NULL;
}

#undef MOVL

/**
 * \brief Return string representation of disassembled \p param
 *
 * \param SHParam to be disassembled
 * \param SHScaling of the instruction associated with the param
 * \return char *, owned by the caller
 */
RZ_IPI RZ_OWN char *sh_op_param_to_str(SHParam param, SHScaling scaling, ut64 pc) {
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
		rz_strbuf_appendf(buf, "@(0x%02x,%s)", param.param[1] * sh_scaling_size[scaling], sh_registers[param.param[0]]);
		break;
	case SH_REG_INDIRECT_INDEXED:
		rz_strbuf_appendf(buf, "@(r0,%s)", sh_registers[param.param[0]]);
		break;
	case SH_GBR_INDIRECT_DISP:
		rz_strbuf_appendf(buf, "@(0x%03x,gbr)", param.param[0] * sh_scaling_size[scaling]);
		break;
	case SH_GBR_INDIRECT_INDEXED:
		rz_strbuf_append(buf, "@(r0,gbr)");
		break;
	case SH_PC_RELATIVE_DISP:
		rz_strbuf_appendf(buf, "@(0x%03x,pc)", param.param[0] * sh_scaling_size[scaling]);
		break;
	case SH_PC_RELATIVE8:
	case SH_PC_RELATIVE12:
		rz_strbuf_appendf(buf, "0x%08x", (ut32)pc + 4 + (st32)((st8)param.param[0]) * 2);
		break;
	case SH_PC_RELATIVE_REG:
		rz_strbuf_appendf(buf, "%s", sh_registers[param.param[0]]);
		break;
	case SH_IMM_U:
	case SH_IMM_S:
		rz_strbuf_appendf(buf, "0x%02x", param.param[0]);
		break;
	default:
		rz_warn_if_reached();
	}

	return rz_strbuf_drain(buf);
}

/**
 * \brief Return string representation of disassembled \p op
 *
 * \param SHOp to be disassembled
 * \return char *, owned by the caller
 */
RZ_IPI RZ_OWN char *sh_op_to_str(RZ_NONNULL const SHOp *op, ut64 pc) {
	rz_return_val_if_fail(op, NULL);
	if (!op->str_mnem) {
		return NULL;
	}
	RzStrBuf *buf = rz_strbuf_new(op->str_mnem);

	char *param = NULL;
	if ((param = sh_op_param_to_str(op->param[0], op->scaling, pc))) {
		rz_strbuf_appendf(buf, " %s", param);
		free(param);
		if ((param = sh_op_param_to_str(op->param[1], op->scaling, pc))) {
			rz_strbuf_appendf(buf, ", %s", param);
			free(param);
		}
	}

	return rz_strbuf_drain(buf);
}
