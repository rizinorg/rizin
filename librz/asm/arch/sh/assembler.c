// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "assembler.h"
#include "regs.h"

static SHAddrMode sh_pb_get_addrmode(SHParamBuilder pb) {
	return pb.is_param ? pb.param.mode : pb.addr.mode;
}

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
	RZ_LOG_ERROR("SuperH: Invalid register encountered by the assembler\n");
	return 0;
}

static ut32 sh_op_param_bits(SHParamBuilder shb, const char *param, SHScaling scaling, ut64 pc) {
	if (shb.is_param) {
		return 0;
	}

	ut32 opcode = 0;
	struct sh_param_builder_addr_t shba = shb.addr;
	char *const reg = strdup(param);
	char *const dup = strdup(param);
	char *const disp = strdup(param);
	ut8 d;

	switch (shba.mode) {
	case SH_REG_DIRECT:
	case SH_PC_RELATIVE_REG:
		// %s
		opcode = sh_op_reg_bits(reg, shba.start);
		break;
	case SH_REG_INDIRECT:
		// @%s
		sscanf(param, "@%s", reg);
		opcode = sh_op_reg_bits(reg, shba.start);
		break;
	case SH_REG_INDIRECT_I: {
		// @%s+
		char *plus = strchr(dup, '+');
		*plus = '\0';
		sscanf(dup, "@%s", reg);
		opcode = sh_op_reg_bits(reg, shba.start);
		break;
	}
	case SH_REG_INDIRECT_D:
		// @-%s
		sscanf(param, "@-%s", reg);
		opcode = sh_op_reg_bits(param, shba.start);
		break;
	case SH_REG_INDIRECT_DISP: {
		// @(%s,%s)
		char *comma = strchr(dup, ',');
		*comma = '\0';
		sscanf(dup, "@(%s", disp);

		comma++;
		char *paren = strchr(comma, ')');
		*paren = '\0';

		d = (rz_num_get(NULL, disp) / sh_scaling_size[scaling]) & 0xf;
		opcode = d << shba.start;
		opcode |= sh_op_reg_bits(comma, shba.start + 4);
		break;
	}
	case SH_REG_INDIRECT_INDEXED: {
		// @(r0,%s)
		char *paren = strchr(dup, ')');
		*paren = '\0';
		paren = dup + strlen("@(r0,");
		opcode = sh_op_reg_bits(paren, shba.start);
		break;
	}
	case SH_GBR_INDIRECT_DISP: {
		// @(%s,gbr)
		char *comma = strchr(dup, ',');
		*comma = '\0';
		sscanf(dup, "@(%s", disp);
		d = rz_num_get(NULL, disp) / sh_scaling_size[scaling];
		opcode = d << shba.start;
		break;
	}
	case SH_PC_RELATIVE_DISP: {
		// @(%s,pc)
		char *comma = strchr(dup, ',');
		*comma = '\0';
		sscanf(dup, "@(%s,pc)", disp);
		d = rz_num_get(NULL, disp) / sh_scaling_size[scaling];
		opcode = d << shba.start;
		break;
	}
	case SH_PC_RELATIVE8:
		d = (st16)((st64)rz_num_get(NULL, disp) - (st64)pc - 4) / 2;
		opcode = d << shba.start;
		break;
	case SH_PC_RELATIVE12: {
		ut16 dd = ((st16)((st64)rz_num_get(NULL, disp) - (st64)pc - 4) / 2) & 0xfff;
		opcode = dd << shba.start;
		break;
	}
	case SH_IMM_U:
	case SH_IMM_S:
		d = rz_num_get(NULL, disp);
		opcode = d << shba.start;
		break;
	default:
		RZ_LOG_ERROR("SuperH: Invalid addressing mode encountered by the assembler\n");
	}

	free(reg);
	free(disp);
	free(dup);
	return opcode;
}

static ut64 sh_op_movl_param_bits(const char *reg_direct, const char *reg_disp_indirect) {
	ut64 opcode = sh_op_reg_bits(reg_direct, NIB1);

	char *const dup = strdup(reg_disp_indirect);
	char *comma = strchr(dup, ',');
	*comma = '\0';
	char *reg = comma + 1;
	char *paren = strchr(reg, ')');
	*paren = '\0';

	char *const disp = strdup(reg_disp_indirect);
	sscanf(dup, "@(%s", disp);
	ut8 d = (rz_num_get(NULL, disp) / sh_scaling_size[SH_SCALING_L]) & 0xf;
	opcode |= d << NIB0;
	opcode |= sh_op_reg_bits(reg, NIB2);

	free(dup);
	free(disp);
	return opcode;
}

/* This function is NOT robust. It is incapable of detecting invalid operand inputs.
If you provide an invalid operand, the behavior is, for all practical purposes, undefined.
The resulting assembled instruction will be complete gibberish and should not be used. */
static SHAddrMode sh_op_get_addr_mode(const char *param) {
	switch (param[0]) {
	case 'r':
		/* This could also have been SH_PC_RELATIVE_REG, and we have no way to know
		But we can take care of this case in sh_op_compare, since no instruction
		can have both SH_REG_DIRECT and SH_PC_RELATIVE_REG as its addressing modes */
		return SH_REG_DIRECT;
	case '@':
		switch (param[1]) {
		case 'r':
			if (rz_str_endswith(param, "+")) {
				return SH_REG_INDIRECT_I;
			} else {
				return SH_REG_INDIRECT;
			}
		case '-':
			return SH_REG_INDIRECT_I;
		case '(':
			if (strcmp(param, "@(r0,gbr)") == 0) {
				return SH_GBR_INDIRECT_INDEXED;
			} else if (rz_str_startswith(param, "@(r0,")) {
				return SH_REG_INDIRECT_INDEXED;
			} else if (rz_str_endswith(param, ",gbr)")) {
				return SH_GBR_INDIRECT_DISP;
			} else if (rz_str_endswith(param, ",pc)")) {
				return SH_PC_RELATIVE_DISP;
			} else {
				return SH_REG_INDIRECT_DISP;
			}
		}
		// unreachable
		break;
	default:
		/* If none of the above checks pass, we can assume it is a number
		In this case, it could be any one of the following:
		  - SH_PC_RELATIVE8
		  - SH_PC_RELATIVE12
		  - SH_IMM_U
		  - SH_IMM_S
		Again, we will just return SH_IMM_U, and take care of it in sh_op_compare
		by considering all the above addressing modes to be equal
		*/
		return SH_IMM_U;
	}

	// unreachable
	return SH_ADDR_INVALID;
}

static bool sh_op_compare(SHOpRaw raw, const char *mnem, SHAddrMode modes[]) {
	bool x = true;
	x &= (strcmp(mnem, raw.str_mnem) == 0);

	for (ut8 i = 0; i < 2; i++) {
		SHAddrMode md = sh_pb_get_addrmode(raw.param_builder[i]);
		switch (md) {
		case SH_REG_DIRECT:
		case SH_PC_RELATIVE_REG:
			md = SH_REG_DIRECT;
			break;
		case SH_PC_RELATIVE8:
		case SH_PC_RELATIVE12:
		case SH_IMM_U:
		case SH_IMM_S:
			md = SH_IMM_U;
			break;
		default:
			break;
		}

		x &= (modes[i] == md);
	}

	return x;
}

RZ_API ut16 sh_assembler(RZ_NONNULL const char *buffer, ut64 pc, RZ_NULLABLE bool *success) {
	rz_return_val_if_fail(buffer, -1);
	if (success) {
		*success = true;
	}

	char *mnem = NULL;
	ut16 opcode = 0;
	char *spaced = sh_op_space_params(buffer);
	RzList *tokens = rz_str_split_duplist(spaced, " ", true);
	free(spaced);
	if (!tokens) {
		goto bye;
	}
	RzListIter *itr, *tmp;
	char *tok;
	rz_list_foreach_safe (tokens, itr, tmp, tok) {
		if (rz_str_is_whitespace(tok)) {
			rz_list_delete(tokens, itr);
		}
	}
	ut32 token_num = rz_list_length(tokens);
	if (token_num == 0 || token_num > 3) {
		RZ_LOG_ERROR("SuperH: Invalid number of operands in the instruction\n")
		goto bye;
	}

	mnem = (char *)rz_list_pop_head(tokens);
	SHAddrMode sham[2] = { SH_ADDR_INVALID, SH_ADDR_INVALID };
	ut8 j = 0;
	rz_list_foreach (tokens, itr, tok) {
		sham[j] = sh_op_get_addr_mode(tok);
		j++;
	}

	for (ut16 i = 0; i < OPCODE_NUM; i++) {
		if (sh_op_compare(sh_op_lookup[i], mnem, sham)) {
			SHOpRaw raw = sh_op_lookup[i];
			opcode = raw.opcode ^ raw.mask;
			/* Now opcode only has the bits corresponding to the instruction
			The bits corresponding to the operands are supposed to be calculated */

			// check for "weird" MOVL
			if (raw.opcode == MOVL) {
				char *reg_direct = rz_list_pop_head(tokens);
				char *reg_disp_indirect = rz_list_pop_head(tokens);

				opcode |= sh_op_movl_param_bits(reg_direct, reg_disp_indirect);

				free(reg_direct);
				free(reg_disp_indirect);
				goto return_opcode;
			}

			RzListIter *itr;
			char *param;
			j = 0;
			rz_list_foreach (tokens, itr, param) {
				opcode |= sh_op_param_bits(raw.param_builder[j], param, raw.scaling, pc);
				j++;
			}

		return_opcode:
			rz_list_free(tokens);
			free(mnem);
			return opcode;
		}
	}

	RZ_LOG_ERROR("SuperH: Failed to assemble: \"%s\"\n", buffer);

bye:
	if (success) {
		success = false;
	}
	rz_list_free(tokens);
	free(mnem);
	return 0;
}
