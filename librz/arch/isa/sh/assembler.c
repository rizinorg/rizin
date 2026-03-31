// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "assembler.h"
#include "regs.h"

extern const SHOpRaw sh_op_lookup[];
extern const ut32 OPCODE_NUM;

/**
 * \brief Get the addressing mode for \p pb
 *
 * \param pb SHParamBuilder
 * \return SHAddrMode
 */
static SHAddrMode sh_pb_get_addrmode(SHParamBuilder pb) {
	return pb.is_param ? pb.param.mode : pb.addr.mode;
}

/**
 * \brief Replace all the commas outside operands with spaces (i.e. "space out" the operands)
 *
 * \param buffer Input instruction string
 * \return char* Duplicated output "spaced out" string
 */
static char *sh_op_space_params(const char *buffer) {
	char *spaced = rz_str_dup(buffer);
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

/**
 * \brief Get the bits corresponding to the register \p param (i.e. register number shifted at \p offset)
 *
 * \param param Register param string
 * \param offset Offset to shift the register number to (a.k.a. nibble position)
 * \return ut32 Opcode bits for the given register \p param
 */
static ut32 sh_op_reg_bits(const char *param, ut8 offset) {
	const int reg_num = sizeof(sh_registers) / sizeof(char *);
	for (ut8 i = 0; i < reg_num; i++) {
		if (!strcmp(sh_registers[i], param)) {
			if (i >= SH_REG_IND_R0B) {
				/* In case we encounter a banked register, we should just decode it as it's un-banked counterpart */
				i -= SH_REG_IND_R0B;
			}
			return ((ut32)i) << offset;
		}
	}
	RZ_LOG_ERROR("SuperH: Invalid register encountered by the assembler\n");
	return 0;
}

/**
 * \brief Get the opcode bits corresponding to \p param, \p scaling, \p pc and addressing mode (shb.mode)
 * This function does nothing if shb.is_param == true (i.e. there are no bits corresponding to it in the instruction opcode)
 *
 * \param shb SHParamBuilder instance to use for addressing modes
 * \param param Param string to be assembled
 * \param scaling Instruction scaling
 * \param pc Program counter
 * \return ut32 Opcode bits corresponding to the given \p param
 */
static ut32 sh_op_param_bits(SHParamBuilder shb, const char *param, SHScaling scaling, ut64 pc) {
	if (shb.is_param) {
		return 0;
	}

	ut32 opcode = 0;
	struct sh_param_builder_addr_t shba = shb.addr;
	char *const reg = rz_str_dup(param);
	char *const dup = rz_str_dup(param);
	char *const disp = rz_str_dup(param);
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
		if (!plus) {
			break;
		}
		*plus = '\0';
		sscanf(dup, "@%s", reg);
		opcode = sh_op_reg_bits(reg, shba.start);
		break;
	}
	case SH_REG_INDIRECT_D:
		// @-%s
		sscanf(param, "@-%s", reg);
		opcode = sh_op_reg_bits(reg, shba.start);
		break;
	case SH_REG_INDIRECT_DISP: {
		// @(%s,%s)
		char *comma = strchr(dup, ',');
		if (!comma) {
			break;
		}
		*comma = '\0';
		sscanf(dup, "@(%s", disp);

		comma++;
		char *paren = strchr(comma, ')');
		if (!paren) {
			break;
		}
		*paren = '\0';

		d = (rz_num_get(NULL, disp) / sh_scaling_size[scaling]) & 0xf;
		opcode = d << shba.start;
		opcode |= sh_op_reg_bits(comma, shba.start + 4);
		break;
	}
	case SH_REG_INDIRECT_INDEXED: {
		// @(r0,%s)
		char *paren = strchr(dup, ')');
		if (!paren) {
			break;
		}
		*paren = '\0';
		paren = dup + strlen("@(r0,");
		opcode = sh_op_reg_bits(paren, shba.start);
		break;
	}
	case SH_GBR_INDIRECT_DISP: {
		// @(%s,gbr)
		char *comma = strchr(dup, ',');
		if (!comma) {
			break;
		}
		*comma = '\0';
		sscanf(dup, "@(%s", disp);
		d = rz_num_get(NULL, disp) / sh_scaling_size[scaling];
		opcode = d << shba.start;
		break;
	}
	case SH_PC_RELATIVE_DISP: {
		// @(%s,pc)
		char *comma = strchr(dup, ',');
		if (!comma) {
			break;
		}
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

/**
 * \brief Special assembler functions for the operands of "weird" MOVL instruction
 *
 * \param reg_direct Operand string for direct register addressing mode
 * \param reg_disp_indirect Operand string for register indirect addressing mode
 * \return ut64 Opcode bits corresponding to the operands
 */
static ut64 sh_op_movl_param_bits(const char *reg_direct, const char *reg_disp_indirect) {
	ut64 opcode = sh_op_reg_bits(reg_direct, NIB1);

	char *const dup = rz_str_dup(reg_disp_indirect);
	char *comma = strchr(dup, ',');
	if (!comma) {
		goto fail;
	}
	*comma = '\0';
	char *reg = comma + 1;
	char *paren = strchr(reg, ')');
	if (!paren) {
		goto fail;
	}
	*paren = '\0';

	char *const disp = rz_str_dup(reg_disp_indirect);
	sscanf(dup, "@(%s", disp);
	ut8 d = (rz_num_get(NULL, disp) / sh_scaling_size[SH_SCALING_L]) & 0xf;
	opcode |= d << NIB0;
	opcode |= sh_op_reg_bits(reg, NIB2);

	free(disp);
fail:
	free(dup);
	return opcode;
}

typedef struct sh_addr_dissassembler_helper_t {
	SHAddrMode mode;
	SHRegisterIndex reg;
} SHAddrHelper;

/* This function is NOT robust. It is incapable of detecting invalid operand inputs.
If you provide an invalid operand, the behavior is, for all practical purposes, undefined.
The resulting assembled instruction will be complete gibberish and should not be used. */
/**
 * \brief Get the addressing mode being used in \p param
 *
 * \param param Param string
 * \return SHAddrHelper
 */
static SHAddrHelper sh_op_get_addr_mode(const char *param) {
	SHAddrHelper ret;
	// Assume that we don't care about the register index
	ret.reg = SH_REG_IND_SIZE;

	const ut8 reg_num = sizeof(sh_registers) / sizeof(char *);
	/* Check if it is a register or not by iterating through all the register names.
	This could also have been SH_PC_RELATIVE_REG, and we have no way to know.
	But we can take care of this case in sh_op_compare, since no instruction
	can have both SH_REG_DIRECT and SH_PC_RELATIVE_REG as its addressing modes */
	for (ut8 i = 0; i < reg_num; i++) {
		if (!strcmp(param, sh_registers[i])) {
			ret.mode = SH_REG_DIRECT;
			/* Well in case of `SH_REG_DIRECT` addressing mode, we do care about the register index.
			This is because there are instructions (like `LDC` and `STC`) which have different
			opcodes for the same addressing mode but different registers.
			But, such ambiguous instructions have different opcodes only for non-gpr registers
			(like sr, gbr, vbr, ssr, spc, dbr), hence we will only set ret.reg if the index is really non-gpr.
			We will also store if we found a banked register, since we can that way find the correct instruction
			which corresponds to banked register as a param */
			if ((i > SH_REG_IND_PC && i < SH_REG_IND_FR0) || i >= SH_REG_IND_R0B) {
				ret.reg = i;
			}
			return ret;
		}
	}

	switch (param[0]) {
	case '@':
		switch (param[1]) {
		case 'r':
			if (rz_str_endswith(param, "+")) {
				ret.mode = SH_REG_INDIRECT_I;
			} else {
				ret.mode = SH_REG_INDIRECT;
			}
			break;
		case '-':
			ret.mode = SH_REG_INDIRECT_D;
			break;
		case '(':
			if (strcmp(param, "@(r0,gbr)") == 0) {
				ret.mode = SH_GBR_INDIRECT_INDEXED;
			} else if (rz_str_startswith(param, "@(r0,")) {
				ret.mode = SH_REG_INDIRECT_INDEXED;
			} else if (rz_str_endswith(param, ",gbr)")) {
				ret.mode = SH_GBR_INDIRECT_DISP;
			} else if (rz_str_endswith(param, ",pc)")) {
				ret.mode = SH_PC_RELATIVE_DISP;
			} else {
				ret.mode = SH_REG_INDIRECT_DISP;
			}
			break;
		default:
			// unreachable
			rz_warn_if_reached();
		}
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
		ret.mode = SH_IMM_U;
	}

	return ret;
}

/**
 * \brief Check whether \p raw and instruction to be formed using \p mnem and \p modes will be equivalent
 *
 * \param raw SHOpRaw
 * \param mnem Mnemonic for the instruction to be formed
 * \param modes Addressing modes and register to be used
 * \return bool True if equivalent; false otherwise
 */
static bool sh_op_compare(SHOpRaw raw, const char *mnem, SHAddrHelper modes[]) {
	bool x = true;
	x &= (strcmp(mnem, raw.str_mnem) == 0);

	// Quick return
	if (!x) {
		return x;
	}

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

		x &= (modes[i].mode == md);

		/* We also need to make sure that we got the instruction corresponding
		to the correct register by checking the register index in the SHAddrHelper
		and the register in the SHOpRaw */
		if (modes[i].reg < SH_REG_IND_R0B) {
			/* We can only compare the registers if the param_builder is a param, and not an an addr
			Also, the addressing mode has to be SH_REG_DIRECT, since the ambiguous instructions (`LDC` and `STC`)
			are only ambiguous for params with direct register addressing */
			if (raw.param_builder[i].is_param && raw.param_builder[i].param.mode == SH_REG_DIRECT) {
				x &= (modes[i].reg == raw.param_builder[i].param.param[0]);
			} else {
				/* In any other case, we did not get what we expected, so we can conclude that the instructions are not the same */
				x &= false;
			}
		}

		/* Check whether this instruction really has banked register as its param */
		if (modes[i].reg >= SH_REG_IND_R0B && modes[i].reg != SH_REG_IND_SIZE) {
			/* If it has a banked register, then it must be a addr
			(at least in case of all implemented instructions) */
			if (!raw.param_builder[i].is_param) {
				/* The number of bits to be used for a banked register must be 3
				(at least in case of all implemented instructions) */
				x &= (raw.param_builder[i].addr.bits == 3);
			} else {
				x &= false;
			}
		}
	}

	return x;
}

/**
 * \brief Assemble instruction from SuperH-4 ISA
 * FPU instructions not implemented yet
 *
 * \param buffer Instruction string buffer
 * \param pc Current value of program counter
 * \param success Store bool whether the assembler succeeded or not (RZ_NULLABLE)
 * \return ut16 Opcode for the given instruction
 */
RZ_IPI ut16 sh_assembler(RZ_NONNULL const char *buffer, ut64 pc, RZ_NULLABLE bool *success) {
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
	SHAddrHelper sham[2] = { { SH_ADDR_INVALID, SH_REG_IND_SIZE }, { SH_ADDR_INVALID, SH_REG_IND_SIZE } };
	ut8 j = 0;
	rz_list_foreach (tokens, itr, tok) {
		sham[j] = sh_op_get_addr_mode(tok);
		j++;
	}

	for (ut16 i = 0; i < OPCODE_NUM; i++) {
		if (!sh_op_compare(sh_op_lookup[i], mnem, sham)) {
			continue;
		}

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

	RZ_LOG_ERROR("SuperH: Failed to assemble: \"%s\"\n", buffer);

bye:
	if (success) {
		*success = false;
	}
	rz_list_free(tokens);
	free(mnem);
	return 0;
}
