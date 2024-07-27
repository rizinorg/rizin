// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-FileCopyrightText: 2009-2016 Alexandru Caciulescu <alex.darredevil@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>

#include "rz_core.h"
#include "rz_list.h"
#include "rz_types_base.h"
#include "rz_rop.h"

static void skip_whitespace(const char *str, ut64 *idx) {
	while (IS_WHITECHAR(str[*idx])) {
		(*idx)++;
	}
}

static bool parse_eof(const char *str, ut64 idx) {
	skip_whitespace(str, &idx);
	return str[idx] == '\0';
}

static bool parse_il_equal(const char *str, ut64 *idx) {
	skip_whitespace(str, idx);
	if (*idx >= strlen(str)) {
		return false;
	}
	if (str[*idx] == '=') {
		(*idx)++;
		return true;
	}
	return false;
}

static char *parse_register(const RzCore *core, const char *str, ut64 *idx) {
	char reg[256] = { 0 };
	ut64 reg_idx = 0;

	skip_whitespace(str, idx);

	while (isalnum(str[*idx]) || str[*idx] == '_') {
		reg[reg_idx++] = str[*idx];
		(*idx)++;
	}

	if (reg_idx == 0) {
		return NULL;
	}

	// Check if the register is correct for the given architecture.
	if (rz_analysis_is_reg_in_profile(core->analysis, reg)) {
		return strdup(reg);
	}

	return NULL;
}

static bool parse_constant(const char *str, RZ_NONNULL ut64 *idx, unsigned long long *value) {
	rz_return_val_if_fail(idx, false);
	int neg = 0;
	int len = strlen(str);

	skip_whitespace(str, idx);

	if (*idx < len && str[*idx] == '-') {
		neg = 1;
		(*idx)++;
	}

	skip_whitespace(str, idx);

	int base = 10;
	if (*idx + 1 < len && str[*idx] == '0' && (str[*idx + 1] == 'x' || str[*idx + 1] == 'X')) {
		base = 16;
		*idx += 2;
	}

	int num_idx = 0;
	char num_str[256] = { 0 };
	while (isdigit(str[*idx]) || (base == 16 && isxdigit(str[*idx]))) {
		num_str[num_idx++] = str[*idx];
		(*idx)++;
	}

	if (num_idx == 0) {
		return false;
	}

	*value = strtoull(num_str, NULL, base);
	if (neg) {
		*value = -*value;
	}

	return true;
}

static bool parse_reg_to_const(const RzCore *core, const char *str, RzRopConstraint *rop_constraint) {
	ut64 idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	ut64 const_value;
	if (!parse_constant(str, &idx, &const_value)) {
		free(dst_reg);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		return false;
	}

	rop_constraint->type = MOV_CONST;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = NULL;
	rop_constraint->args[SRC_CONST] = rz_str_newf("%" PFMT64u, const_value);
	return true;
}

static bool parse_reg_to_reg(const RzCore *core, const char *str, RzRopConstraint *rop_constraint) {
	ut64 idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	char *src_reg = parse_register(core, str, &idx);
	if (!src_reg) {
		free(dst_reg);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		return false;
	}

	rop_constraint->type = MOV_REG;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = src_reg;
	return true;
}

static bool parse_il_op(RzList /*<RzILOpPureCode *>*/ *args, const char *str, ut64 *idx) {
	RzILOpPureCode res = RZ_IL_OP_VAR;

	skip_whitespace(str, idx);
	if (*idx >= strlen(str)) {
		return false;
	}

	switch (str[*idx]) {
	case '+':
		(*idx)++;
		res = RZ_IL_OP_ADD;
		break;
	case '/':
		(*idx)++;
		res = RZ_IL_OP_DIV;
		break;
	case '*':
		(*idx)++;
		res = RZ_IL_OP_MUL;
		break;
	case '^':
		(*idx)++;
		res = RZ_IL_OP_XOR;
		break;
	case '&':
		(*idx)++;
		res = RZ_IL_OP_AND;
		break;
	case '|':
		(*idx)++;
		res = RZ_IL_OP_OR;
		break;
	case '%':
		(*idx)++;
		res = RZ_IL_OP_MOD;
		break;
	case '-':
		(*idx)++;
		res = RZ_IL_OP_SUB;
	default: break;
	}
	if (res == RZ_IL_OP_VAR) {
		if (strncmp(&str[*idx], "<<", 2) == 0) {
			*idx += 2;
			res = RZ_IL_OP_SHIFTL;
		} else if (strncmp(&str[*idx], ">>", 2) == 0) {
			*idx += 2;
			res = RZ_IL_OP_SHIFTR;
		} else {
			return false;
		}
	}

	RzILOpPureCode *op_ptr = RZ_NEW0(RzILOpPureCode);
	if (!op_ptr) {
		return false;
	}
	*op_ptr = res;
	rz_list_append(args, op_ptr);

	return true;
}

static bool parse_reg_op_const(const RzCore *core, const char *str, RzRopConstraint *rop_constraint) {
	ut64 idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	char *src_reg = parse_register(core, str, &idx);
	if (!src_reg) {
		free(dst_reg);
		return false;
	}
	RzList *args = rz_list_new();
	if (!parse_il_op(args, str, &idx)) {
		free(dst_reg);
		free(src_reg);
		rz_list_free(args);
		return false;
	}

	ut64 const_value;
	if (!parse_constant(str, &idx, &const_value)) {
		free(dst_reg);
		free(src_reg);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		free(src_reg);
		rz_list_free(args);
		return false;
	}

	rop_constraint->type = MOV_OP_CONST;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = src_reg;
	RzILOpPureCode *op = rz_list_get_n(args, 0);
	if (!op) {
		free(dst_reg);
		free(src_reg);
		rz_list_free(args);
		return false;
	}

	char op_str[16];
	rz_strf(op_str, "%" PFMT64u, const_value);
	rop_constraint->args[SRC_CONST] = strdup(op_str);
	const char *value_str = rz_il_op_pure_code_stringify(*op);
	rop_constraint->args[OP] = rz_str_dup(value_str);
	return true;
}

/**
 * \brief Create a new RzRopSearchContext object.
 * \param core RZ_NONNULL Pointer to the RzCore structure containing configuration settings.
 * \param greparg RZ_NULLABLE Pointer to a string containing the grep argument.
 * \param regexp Flag specifying whether regular expressions should be used.
 * \param mask ROP request mask specifying the ROP request parameters.
 * \param state RZ_BORROW Pointer to the command state output structure.
 * \return RZ_OUT A pointer to the newly created RzRopSearchContext object, or NULL if memory allocation fails.
 *
 * This function allocates and initializes a new RzRopSearchContext object.
 */
RZ_OWN RZ_API RzRopSearchContext *rz_core_rop_search_context_new(RZ_NONNULL const RzCore *core, RZ_NULLABLE const char *greparg, const bool regexp,
	const RzRopRequestMask mask, RZ_BORROW RzCmdStateOutput *state) {

	rz_return_val_if_fail(core, NULL);
	rz_return_val_if_fail(state, NULL);

	RzRopSearchContext *context = RZ_NEW0(RzRopSearchContext);
	if (!context) {
		return NULL;
	}

	context->greparg = greparg ? strdup(greparg) : NULL;
	context->mode_str = rz_config_get(core->config, "search.in");
	context->arch = rz_config_get(core->config, "asm.arch");
	context->regexp = regexp;
	context->mask = mask;
	context->state = state;
	context->max_instr = rz_config_get_i(core->config, "rop.len");
	context->max_count = rz_config_get_i(core->config, "search.maxhits");
	context->increment = 1;
	context->from = 0;
	context->to = 0;
	context->end_list = NULL;
	context->unique_hitlists = NULL;
	context->crop = rz_config_get_i(core->config, "rop.conditional");
	context->subchain = rz_config_get_i(core->config, "rop.subchain");
	context->cache = rz_config_get_i(core->config, "rop.cache");

	return context;
}

/**
 * \brief Free an RzRopSearchContext object.
 * \param context RZ_NULLABLE Pointer to the RzRopSearchContext object to free.
 *
 * Frees the memory allocated for an RzRopSearchContext object.
 * Note: Other elements must be freed by the caller/callee.
 */
RZ_API void rz_core_rop_search_context_free(RZ_NULLABLE RzRopSearchContext *context) {
	if (!context) {
		return;
	}

	free(context->greparg);
	free(context);
}

static bool parse_reg_op_reg(const RzCore *core, const char *str, RzRopConstraint *rop_constraint) {
	ut64 idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	char *src_reg1 = parse_register(core, str, &idx);
	if (!src_reg1) {
		free(dst_reg);
		return false;
	}

	RzList *args = rz_list_new();
	if (!args || !parse_il_op(args, str, &idx)) {
		free(dst_reg);
		free(src_reg1);
		rz_list_free(args);
		return false;
	}

	char *dst_reg2 = parse_register(core, str, &idx);
	if (!dst_reg2) {
		free(dst_reg);
		free(src_reg1);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		free(src_reg1);
		free(dst_reg2);
		rz_list_free(args);
		return false;
	}

	rop_constraint->type = MOV_OP_REG;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = src_reg1;
	RzILOpPureCode *op = rz_list_get_n(args, 0);
	if (!op) {
		free(dst_reg);
		free(src_reg1);
		free(dst_reg2);
		rz_list_free(args);
		return false;
	}

	const char *op_str = rz_il_op_pure_code_stringify(*op);
	rop_constraint->args[OP] = rz_str_dup(op_str);
	rop_constraint->args[SRC_CONST] = dst_reg2;
	return true;
}

/**
 * \brief Analyze and parse a constraint string.
 * \param core Pointer to the RzCore object.
 * \param str The constraint string to analyze.
 * \param rop_constraint Pointer to the RzRopConstraint object to store the parsed result.
 * \return true if the constraint string is successfully parsed, false otherwise.
 *
 * This function analyzes a given constraint string and attempts to parse it into
 * the provided RzRopConstraint. It tries four different parsing methods:
 *
 * The function returns true if any of these parsing methods succeed.
 */
RZ_API bool rz_core_rop_analyze_constraint(RzCore *core, const char *str, RzRopConstraint *rop_constraint) {
	rz_return_val_if_fail(core, false);
	return parse_reg_to_const(core, str, rop_constraint) ||
		parse_reg_to_reg(core, str, rop_constraint) ||
		parse_reg_op_const(core, str, rop_constraint) ||
		parse_reg_op_reg(core, str, rop_constraint);
}

static RzRopConstraint *rop_constraint_parse_args(RzCore *core, char *token) {
	RzRopConstraint *rop_constraint = RZ_NEW0(RzRopConstraint);
	RzList *l = rz_str_split_duplist_n(token, "=", 1, false);
	char *key = rz_list_get_n(l, 0);
	char *value = rz_list_get_n(l, 1);
	if (RZ_STR_ISEMPTY(key) || RZ_STR_ISEMPTY(value)) {
		RZ_LOG_ERROR("core: Make sure to use the format <key>=<value> without spaces.\n");
		rz_list_free(l);
		return NULL;
	}
	if (!rop_constraint) {
		rz_list_free(l);
		return NULL;
	}
	if (!rz_core_rop_analyze_constraint(core, token, rop_constraint)) {
		free(rop_constraint);
		rz_list_free(l);
		return NULL;
	}

	rz_list_free(l);
	return rop_constraint;
}

RZ_API RzList /*<RzRopConstraint *>*/ *rop_constraint_list_parse(RzCore *core, const int argc, const char **argv) {
	RzList *constr_list = rz_rop_constraint_list_new();
	for (int i = 1; i < argc; i++) {
		RzList *l = rz_str_split_duplist_n(argv[i], ",", 1, false);
		if (!l) {
			return constr_list;
		}
		size_t llen = rz_list_length(l);
		if (!llen) {
			return constr_list;
		}
		RzListIter *it;
		char *token;
		rz_list_foreach (l, it, token) {
			RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, token);
			if (!rop_constraint) {
				continue;
			}
			rz_list_append(constr_list, rop_constraint);
		}
		rz_list_free(l);
	}
	return constr_list;
}