// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "assembler.h"
#include "regs.h"

static char *sh_op_space_params(const char *buffer) {
	char *spaced = strdup(buffer);
	bool inside_paren = false;

	for (ut8 i = 0; spaced[i] != '\0'; i++) {
		switch (spaced[i]) {
		// there won't be nested parens so the logic is trivial
		case '(':
			inside_paren = true;
			break;
		case ')':
			inside_paren = false;
			break;
		case ',':
			if (!inside_paren) {
				spaced[i] = ' ';
			}
			break;
		default:
			break;
		}
	}
	return spaced;
}

static ut32 sh_op_reg_bits(const char *param, ut8 offset) {
	for (ut8 i = 0; i < SH_GPR_COUNT; i++) {
		if (strcmp(sh_registers[i], param) == 0) {
			return ((ut32)i) << offset;
		}
	}
	RZ_LOG_ERROR("SuperH: Invalid register encountered by the assembler");
	return 0;
}

static ut32 sh_op_param_bits(SHParamBuilder shb, const char *param, SHScaling scaling, ut64 pc) {
	if (!shb.is_param) {
		return 0;
	}

	ut32 opcode = 0;
	struct sh_param_builder_addr_t shba = shb.addr;
	char *reg = strdup(param);
	char *disp = strdup(param);
	ut8 d;

	switch (shba.mode) {
	case SH_REG_DIRECT:
	case SH_PC_RELATIVE_REG:
		sscanf(param, "%s", reg);
		opcode = sh_op_reg_bits(reg, shba.start);
		break;
	case SH_REG_INDIRECT:
		sscanf(param, "@%s", reg);
		opcode = sh_op_reg_bits(param, shba.start);
		break;
	case SH_REG_INDIRECT_I:
		sscanf(param, "@%s+", reg);
		opcode = sh_op_reg_bits(param, shba.start);
		break;
	case SH_REG_INDIRECT_D:
		sscanf(param, "@%s+", reg);
		opcode = sh_op_reg_bits(param, shba.start);
		break;
	case SH_REG_INDIRECT_DISP: {
		sscanf(param, "@(%s,%s)", disp, reg);
		d = (rz_num_get(NULL, disp) / sh_scaling_size[scaling]) & 0xf;
		opcode = d << shba.start;
		opcode |= sh_op_reg_bits(param, shba.start + 4);
		break;
	}
	case SH_REG_INDIRECT_INDEXED:
		sscanf(param, "@(r0,%s)", reg);
		opcode = sh_op_reg_bits(param, shba.start);
		break;
	case SH_GBR_INDIRECT_DISP:
		sscanf(param, "@(%s,gbr)", disp);
		d = rz_num_get(NULL, disp) / sh_scaling_size[scaling];
		opcode = d << shba.start;
		break;
	case SH_PC_RELATIVE_DISP:
		sscanf(param, "@(%s,pc)", disp);
		d = rz_num_get(NULL, disp) / sh_scaling_size[scaling];
		opcode = d << shba.start;
		break;
	case SH_PC_RELATIVE8:
		sscanf(param, "%s", disp);
		d = (st16)((st64)rz_num_get(NULL, disp) - (st64)pc - 4) / 2;
		opcode = d << shba.start;
		break;
	case SH_PC_RELATIVE12:
		sscanf(param, "%s", disp);
		ut16 dd = ((st16)((st64)rz_num_get(NULL, disp) - (st64)pc - 4) / 2) & 0xfff;
		opcode = dd << shba.start;
		break;
	case SH_IMM_U:
	case SH_IMM_S:
		sscanf(param, "%s", disp);
		d = rz_num_get(NULL, disp);
		opcode = d << shba.start;
		break;
	default:
		RZ_LOG_ERROR("SuperH: Invalid addressing mode encountered by the assembler");
	}

	free(reg);
	free(disp);
	return opcode;
}

RZ_API ut16 sh_assembler(RZ_NONNULL const char *buffer, ut64 pc) {
	rz_return_val_if_fail(buffer, -1);

	ut16 opcode = 0;
	char *spaced = sh_op_space_params(buffer);
	RzList *tokens = rz_str_split_list(spaced, " ", true);
	if (!tokens) {
		goto bye;
	}
	ut32 token_num = rz_list_length(tokens);
	if (token_num == 0 || token_num > 3) {
		goto bye;
	}

	char *mnem = (char *)rz_list_pop_head(tokens);
	for (ut16 i = 0; i < OPCODE_NUM; i++) {
		if (strcmp(mnem, sh_op_lookup[i].str_mnem) == 0) {
			SHOpRaw raw = sh_op_lookup[i];
			opcode = raw.opcode ^ raw.mask;
			ut8 expected_params = 0;

			if (raw.param_builder[0].is_param && raw.param_builder[0].param.mode != SH_ADDR_INVALID) {
				expected_params += 1;
			}
			if (raw.param_builder[1].is_param && raw.param_builder[1].param.mode != SH_ADDR_INVALID) {
				expected_params += 1;
			}
			if (token_num - 1 != expected_params) {
				goto bye;
			}

			RzListIter *itr;
			char *param;
			ut8 j = 0;
			rz_list_foreach (tokens, itr, param) {
				opcode |= sh_op_param_bits(raw.param_builder[j], param, raw.scaling, pc);
				j++;
			}
			return opcode;
		}
	}

	RZ_LOG_ERROR("SuperH: Failed to assemble: \"%s\"", buffer);
	return 0;

bye:
	RZ_LOG_ERROR("SuperH: Invalid number of arguments in the instruction")
	return opcode;
}
