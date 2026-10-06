// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-FileCopyrightText: 2009-2016 Alexandru Caciulescu <alex.darredevil@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>

#include "rz_core.h"
#include "rz_list.h"
#include "rz_types_base.h"
#include "rz_gadget.h"

static void skip_whitespace(const char *str, ut64 *idx) {
	if (*idx >= strlen(str)) {
		return;
	}
	while (IS_WHITECHAR(str[*idx])) {
		(*idx)++;
	}
}

static inline bool is_compound_operator(char x, char y) {
	return ((x == '+' && y == '+') ||
		(x == '-' && y == '-') ||
		(x == '+' && y == '=') ||
		(x == '-' && y == '=') ||
		(x == '*' && y == '=') ||
		(x == '/' && y == '=') ||
		(x == '%' && y == '=') ||
		(x == '&' && y == '=') ||
		(x == '|' && y == '=') ||
		(x == '^' && y == '='));
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

static const RzRegItem *parse_register(const RzCore *core, const char *str, ut64 *idx) {
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
	RzReg *areg = rz_analysis_get_reg(core->analysis);
	return rz_reg_get(areg, reg, RZ_REG_TYPE_ANY);
}

static bool parse_constant(const char *str, RZ_NONNULL ut64 *idx, ut64 *value) {
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

static bool parse_il_op(const char *str, ut64 *idx, bool *is_compound_op, RzILOpPureCode *op) {
	skip_whitespace(str, idx);
	if (*idx >= strlen(str)) {
		return false;
	}

	switch (str[*idx]) {
	case '+':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_ADD;
		return true;
	case '/':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_DIV;
		return true;
	case '*':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_MUL;
		return true;
	case '^':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_XOR;
		return true;
	case '&':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_AND;
		return true;
	case '|':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_OR;
		return true;
	case '%':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_MOD;
		return true;
	case '-':
		(*idx)++;
		if (is_compound_operator(str[*idx - 1], str[*idx]) && is_compound_op) {
			(*idx)++;
			*is_compound_op = true;
		}
		*op = RZ_IL_OP_SUB;
		return true;
	default: break;
	}

	if (strncmp(&str[*idx], "<<", 2) == 0) {
		*idx += 2;
		*op = RZ_IL_OP_SHIFTL;
		return true;
	} else if (strncmp(&str[*idx], ">>", 2) == 0) {
		*idx += 2;
		*op = RZ_IL_OP_SHIFTR;
		return true;
	}

	return false;
}

static bool gadget_constraint_set_regs(RzGadgetConstraint *rc,
	RzGadgetILInstructionType il_type,
	RZ_NONNULL const RzRegItem *dst,
	RZ_NONNULL const RzRegItem *src0,
	RZ_NULLABLE const RzRegItem *src1) {

	if (!dst || !src0) {
		return false;
	}

	rc->type = il_type;
	rc->args[RZ_GADGET_ARG_DST_REG] = rz_str_dup(dst->name);
	rc->args[RZ_GADGET_ARG_SRC_REG] = rz_str_dup(src0->name);
	if (src1) {
		rc->args[RZ_GADGET_ARG_SRC_REG_SECOND] = rz_str_dup(src1->name);
	}
	return true;
}

static bool gadget_constraint_set_op(RzGadgetConstraint *rc, RzILOpPureCode op) {
	if (op >= RZ_IL_OP_PURE_MAX) {
		return false;
	}

	const char *op_str = rz_il_op_pure_code_stringify(op);
	if (!op_str) {
		return false;
	}
	rc->args[RZ_GADGET_ARG_OP] = rz_str_dup(op_str);
	return true;
}

static bool gadget_constraint_set_const(RzGadgetConstraint *rc,
	RzGadgetILInstructionType il_type,
	RZ_NONNULL const RzRegItem *dst,
	RZ_NULLABLE const RzRegItem *src0,
	ut64 const_value) {

	if (!dst) {
		return false;
	}

	rc->type = il_type;
	rc->args[RZ_GADGET_ARG_DST_REG] = rz_str_dup(dst->name);
	if (src0) {
		rc->args[RZ_GADGET_ARG_SRC_REG] = rz_str_dup(src0->name);
	}
	rc->args[RZ_GADGET_ARG_SRC_CONST] = rz_str_newf("%" PFMT64u, const_value);
	return true;
}

static bool parse_compound_op(const RzCore *core, const char *str, RzGadgetConstraint *gadget_constraint) {
	ut64 idx = 0;
	ut64 const_value = 0;
	bool inc_dec = false;
	bool is_compound_op = false;
	bool constant_status = false;
	RzILOpPureCode op = RZ_IL_OP_PURE_MAX;
	const RzRegItem *src_reg = NULL;
	const RzRegItem *dst_reg = parse_register(core, str, &idx);

	if (!dst_reg) {
		return false;
	}

	skip_whitespace(str, &idx);

	if (!parse_il_op(str, &idx, &is_compound_op, &op)) {
		return false;
	}

	// idx - 2 and idx - 1 as we would have skipped it during parse_il_op
	if ((str[idx - 2] == '+' && str[idx - 1] == '+') || (str[idx - 2] == '-' && str[idx - 1] == '-')) {
		inc_dec = true;
	}

	// Now parse the constant after the operator
	if (!inc_dec) {
		constant_status = parse_constant(str, &idx, &const_value);
		src_reg = parse_register(core, str, &idx);
	}

	if (!constant_status && !src_reg && !is_compound_op) {
		return false;
	} else if (!parse_eof(str, idx)) {
		return false;
	}

	if (constant_status && is_compound_op) {
		// dst = dst (math op) num
		return gadget_constraint_set_const(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_OP_CONST, dst_reg, dst_reg, const_value) &&
			gadget_constraint_set_op(gadget_constraint, op);
	}

	if (src_reg && is_compound_op) {
		// dst = dst (math op) src
		return gadget_constraint_set_regs(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_OP_REG, dst_reg, dst_reg, src_reg) &&
			gadget_constraint_set_op(gadget_constraint, op);
	}

	if (!inc_dec) {
		return false;
	}

	const_value = 1;
	// dst (math op)= 1

	return gadget_constraint_set_const(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_OP_CONST, dst_reg, dst_reg, const_value) &&
		gadget_constraint_set_op(gadget_constraint, op);
}

static bool parse_reg_to_const(const RzCore *core, const char *str, RzGadgetConstraint *gadget_constraint) {
	ut64 idx = 0;
	ut64 const_value = 0;
	const RzRegItem *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx) || !parse_constant(str, &idx, &const_value) || !parse_eof(str, idx)) {
		return false;
	}

	return gadget_constraint_set_const(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_CONST, dst_reg, NULL, const_value);
}

static bool parse_reg_to_reg(const RzCore *core, const char *str, RzGadgetConstraint *gadget_constraint) {
	ut64 idx = 0;
	const RzRegItem *src_reg = NULL;
	const RzRegItem *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		return false;
	}

	src_reg = parse_register(core, str, &idx);
	if (!src_reg) {
		return false;
	}

	if (!parse_eof(str, idx)) {
		return false;
	}

	return gadget_constraint_set_regs(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_REG, dst_reg, src_reg, NULL);
}

static bool parse_reg_op_const(const RzCore *core, const char *str, RzGadgetConstraint *gadget_constraint) {
	ut64 idx = 0;
	ut64 const_value = 0;
	RzILOpPureCode op = RZ_IL_OP_PURE_MAX;
	const RzRegItem *src_reg = NULL;
	const RzRegItem *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg || !parse_il_equal(str, &idx)) {
		goto compound;
	}

	src_reg = parse_register(core, str, &idx);
	if (!src_reg || !parse_il_op(str, &idx, NULL, &op) ||
		!parse_constant(str, &idx, &const_value) || !parse_eof(str, idx)) {
		goto compound;
	}

	return gadget_constraint_set_const(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_OP_CONST, dst_reg, src_reg, const_value) &&
		gadget_constraint_set_op(gadget_constraint, op);

compound:
	return parse_compound_op(core, str, gadget_constraint);
}

static bool parse_reg_op_reg(const RzCore *core, const char *str, RzGadgetConstraint *gadget_constraint) {
	ut64 idx = 0;
	RzILOpPureCode op = RZ_IL_OP_PURE_MAX;
	const RzRegItem *src_reg0 = NULL;
	const RzRegItem *src_reg1 = NULL;
	const RzRegItem *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		goto compound;
	}

	if (!parse_il_equal(str, &idx)) {
		goto compound;
	}

	src_reg0 = parse_register(core, str, &idx);
	if (!src_reg0 || !parse_il_op(str, &idx, NULL, &op)) {
		goto compound;
	}

	src_reg1 = parse_register(core, str, &idx);
	if (!src_reg1 || !parse_eof(str, idx)) {
		goto compound;
	}

	return gadget_constraint_set_regs(gadget_constraint, RZ_GADGET_IL_INSTR_MOV_OP_REG, dst_reg, src_reg0, src_reg1) &&
		gadget_constraint_set_op(gadget_constraint, op);

compound:
	return parse_compound_op(core, str, gadget_constraint);
}

static void gadget_reg_filter_free(RzGadgetRegFilter *filter) {
	if (!filter) {
		return;
	}
	free(filter->name);
	free(filter);
}

/**
 * \brief Find the widest GPR sharing the offset of \p item.
 *
 * The gadget analysis records register events with the widest name of the register
 * profile, for example \c rax and \c rsp instead of \c eax and \c sp. Sub-registers
 * are normalized to that name, so conditions like \c /Rw eax match what the user
 * expects. If there is no wider register, \p item is returned unchanged.
 *
 * Only candidates whose type is \c RZ_REG_TYPE_GPR are considered. The GPR regset
 * also holds flag registers, because flags share the GPR arena, and widening a GPR
 * to one of them would produce a name the gadget analysis never records.
 *
 * \param reg RZ_NONNULL Pointer to the RzReg object.
 * \param item RZ_NONNULL Register to normalize.
 * \return The widest GPR with the same offset, or \p item itself.
 */
static const RzRegItem *gadget_reg_filter_canonical(RZ_NONNULL RzReg *reg, RZ_NONNULL const RzRegItem *item) {
	const RzList /*<RzRegItem *>*/ *gprs = rz_reg_get_list(reg, RZ_REG_TYPE_GPR);
	if (!gprs) {
		return item;
	}

	const RzRegItem *widest = item;
	RzListIter *iter;
	RzRegItem *candidate;
	rz_list_foreach (gprs, iter, candidate) {
		if (candidate->type == RZ_REG_TYPE_GPR &&
			candidate->offset == item->offset && candidate->size > widest->size) {
			widest = candidate;
		}
	}
	return widest;
}

/**
 * \brief Parse a comma separated list of register conditions.
 *
 * Every condition is a register name, optionally prefixed with '!' to negate it,
 * for example \c "rax,!rbx,!rcx". Register roles such as \c SP or \c PC are
 * resolved to the name used by the current register profile, and sub-registers
 * are normalized to the widest register sharing their offset, so that \c eax
 * refers to \c rax. Only general purpose registers are accepted, because gadgets
 * are analyzed for those only.
 *
 * \param core RZ_NONNULL Pointer to the RzCore structure.
 * \param str RZ_NONNULL Comma separated list of register conditions.
 * \return RZ_OUT A newly allocated vector of RzGadgetRegFilter, or NULL on error.
 */
static RZ_OWN RzPVector /*<RzGadgetRegFilter *>*/ *gadget_reg_filter_parse(RZ_NONNULL const RzCore *core, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(core && core->analysis, NULL);

	RzReg *reg = rz_analysis_get_reg(core->analysis);
	if (!reg || RZ_STR_ISEMPTY(str)) {
		RZ_LOG_ERROR("No register given to filter gadgets by\n");
		return NULL;
	}

	RzPVector *filters = rz_pvector_new((RzPVectorFree)gadget_reg_filter_free);
	if (!filters) {
		return NULL;
	}

	RzList *tokens = rz_str_split_duplist(str, ",", true);
	RzListIter *it;
	char *token;
	rz_list_foreach (tokens, it, token) {
		if (RZ_STR_ISEMPTY(token)) {
			RZ_LOG_ERROR("Empty register condition in \"%s\"\n", str);
			goto fail;
		}

		bool negate = false;
		const char *name = token;
		if (name[0] == '!') {
			negate = true;
			name = rz_str_trim_head_ro(name + 1);
		}
		if (RZ_STR_ISEMPTY(name)) {
			RZ_LOG_ERROR("Missing register name after '!' in \"%s\"\n", str);
			goto fail;
		}

		RzRegItem *item = rz_reg_get(reg, name, RZ_REG_TYPE_ANY);
		if (!item || item->type != RZ_REG_TYPE_GPR) {
			RZ_LOG_ERROR("Unknown general purpose register \"%s\"\n", name);
			goto fail;
		}
		const char *canonical = gadget_reg_filter_canonical(reg, item)->name;

		RzGadgetRegFilter *filter = RZ_NEW0(RzGadgetRegFilter);
		if (!filter) {
			goto fail;
		}
		filter->name = rz_str_dup(canonical);
		filter->negate = negate;
		rz_pvector_push(filters, filter);
	}

	rz_list_free(tokens);
	return filters;

fail:
	rz_list_free(tokens);
	rz_pvector_free(filters);
	return NULL;
}

/**
 * \brief Create a new RzGadgetSearchContext object.
 * \param core RZ_NONNULL Pointer to the RzCore structure containing configuration settings.
 * \param gadget_type Kind of gadget to search for.
 * \param greparg RZ_NULLABLE Pointer to a string containing the grep argument.
 * \param regexp Flag specifying whether regular expressions should be used.
 * \param mask Gadget request mask specifying the Gadget request parameters.
 * \param detail_mask search gadgets given details.
 * \param state RZ_BORROW Pointer to the command state output structure.
 * \return RZ_OUT A pointer to the newly created RzGadgetSearchContext object, or NULL if memory allocation fails.
 *
 * This function allocates and initializes a new RzGadgetSearchContext object.
 */
RZ_API RZ_OWN RzGadgetSearchContext *rz_core_gadget_search_context_new(RZ_NONNULL const RzCore *core, const RzGadgetType gadget_type, RZ_NULLABLE const char *greparg, const bool regexp,
	const RzGadgetRequestMask mask, const RzGadgetDetailSearchMask detail_mask, RZ_NULLABLE RZ_BORROW RzCmdStateOutput *state) {

	rz_return_val_if_fail(core, NULL);
	RzGadgetSearchContext *context = RZ_NEW0(RzGadgetSearchContext);
	if (!context) {
		return NULL;
	}

	context->type = gadget_type;
	context->greparg = rz_str_dup(greparg);
	context->arch = rz_config_get(core->config, "asm.arch");
	context->regexp = regexp;
	context->mask = mask;
	context->detail_mask = detail_mask;
	context->state = state;
	context->max_instr = rz_config_get_i(core->config, "gadget.len");
	context->max_count = rz_config_get_i(core->config, "search.maxhits");
	context->increment = 1;
	context->from = 0;
	context->to = 0;
	context->end_list = NULL;
	context->unique_hitlists = NULL;
	context->allow_conditional = rz_config_get_b(core->config, "gadget.conditional");
	context->comments = rz_config_get_b(core->config, "gadget.comments");
	context->subchains = rz_config_get_b(core->config, "gadget.subchains");
	context->cache = rz_config_get_b(core->config, "gadget.cache");
	context->ret_val = false;
	context->buf = NULL;
	if (detail_mask & (RZ_GADGET_DETAIL_SEARCH_WRITE | RZ_GADGET_DETAIL_SEARCH_READ)) {
		context->reg_filters = gadget_reg_filter_parse(core, greparg);
		if (!context->reg_filters) {
			rz_core_gadget_search_context_free(context);
			return NULL;
		}
	}
	return context;
}

/**
 * \brief Free an RzGadgetSearchContext object.
 * \param context RZ_NULLABLE Pointer to the RzGadgetSearchContext object to free.
 *
 * Frees the memory allocated for an RzGadgetSearchContext object.
 * Note: Other elements must be freed by the caller/callee.
 */
RZ_API void rz_core_gadget_search_context_free(RZ_NULLABLE RzGadgetSearchContext *context) {
	if (!context) {
		return;
	}

	free(context->greparg);
	rz_strbuf_free(context->buf);
	rz_pvector_free(context->constraints);
	rz_pvector_free(context->reg_filters);
	free(context);
}

/**
 * \brief Analyze and parse a constraint string.
 * \param core Pointer to the RzCore object.
 * \param str The constraint string to analyze.
 * \param gadget_constraint Pointer to the RzGadgetConstraint object to store the parsed result.
 * \return true if the constraint string is successfully parsed, false otherwise.
 *
 * This function analyzes a given constraint string and attempts to parse it into
 * the provided RzGadgetConstraint. It tries four different parsing methods:
 *
 * The function returns true if any of these parsing methods succeed.
 */
RZ_API bool rz_core_gadget_analyze_constraint(const RZ_NONNULL RzCore *core, const RZ_NONNULL char *str,
	RZ_NULLABLE RZ_OUT RzGadgetConstraint *gadget_constraint) {
	rz_return_val_if_fail(core && str, false);
	if (!gadget_constraint) {
		return false;
	}
	return parse_reg_to_const(core, str, gadget_constraint) ||
		parse_reg_to_reg(core, str, gadget_constraint) ||
		parse_reg_op_const(core, str, gadget_constraint) ||
		parse_reg_op_reg(core, str, gadget_constraint);
}

/**
 * \brief Parse the given token into a gadget constraint
 * \param core Pointer to the RzCore object.
 * \param token Input string in the form `key=value`(Eg: rbx=rdx, r12=1)`
 * \return \p RzGadgetConstraint if parsing is successful else NULL
 *

 * The function parses the given token and parses according to the predefined gadget constraint type
 */
RZ_API RZ_OWN RzGadgetConstraint *rz_core_gadget_constraint_parse_args(const RZ_NONNULL RzCore *core, const RZ_NONNULL char *token) {
	rz_return_val_if_fail(core && token, NULL);

	if (RZ_STR_ISEMPTY(token)) {
		return NULL;
	}

	RzGadgetConstraint *gadget_constraint = RZ_NEW0(RzGadgetConstraint);
	if (!gadget_constraint) {
		free(gadget_constraint);
		return NULL;
	}

	RzList *l = rz_str_split_duplist(token, "=", true);
	if (rz_list_empty(l)) {
		rz_list_free(l);
		free(gadget_constraint);
		return NULL;
	}

	if (!rz_core_gadget_analyze_constraint(core, token, gadget_constraint)) {
		free(gadget_constraint);
		rz_list_free(l);
		return NULL;
	}

	rz_list_free(l);
	return gadget_constraint;
}

/**
 * \brief Parse gadget constraint map
 * \param core Pointer to the RzCore object.
 * \param argc Number of arguments.
 * \param argv Array of arguments.
 * \return RzPVector of RzGadgetConstraint objects.
 *
 * This function parses a list of arguments into a RzPVector of RzGadgetConstraint objects.
 */
RZ_API RZ_OWN RzPVector /*<RzGadgetConstraint *>*/ *rz_core_gadget_constraint_map_parse(const RZ_NONNULL RzCore *core, const int argc, const char **argv) {
	rz_return_val_if_fail(core && argv && RZ_STR_ISNOTEMPTY(argv[0]), false);
	RzPVector *constr_map = rz_pvector_new((RzPVectorFree)rz_core_gadget_constraint_free);
	if (!constr_map) {
		return NULL;
	}
	for (int i = 1; i < argc; i++) {
		RzList *l = rz_str_split_duplist_n(argv[i], ",", 1, false);
		if (!l) {
			return constr_map;
		}
		const ut32 llen = rz_list_length(l);
		if (!llen) {
			return constr_map;
		}
		RzListIter *it;
		char *token;
		rz_list_foreach (l, it, token) {
			RzGadgetConstraint *gadget_constraint = rz_core_gadget_constraint_parse_args(core, token);
			if (!gadget_constraint) {
				continue;
			}
			rz_pvector_push(constr_map, gadget_constraint);
		}
		rz_list_free(l);
	}
	return constr_map;
}
