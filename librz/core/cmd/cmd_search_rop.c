// SPDX-FileCopyrightText: 2009-2016 Alexandru Caciulescu <alex.darredevil@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>

#include "rz_core.h"
#include "rz_list.h"
#include "rz_types_base.h"
#include "rz_rop.h"

static void skip_whitespace(const char *str, int *idx) {
	while (str[*idx] == ' ' || str[*idx] == '\t' || str[*idx] == '\n' || str[*idx] == '\r') {
		(*idx)++;
	}
}

static bool parse_eof(const char *str, int idx) {
	skip_whitespace(str, &idx);
	return str[idx] == '\0';
}

static bool parse_il_equal(char *str, int *idx) {
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

static char *parse_register(RzCore *core, char *str, int *idx) {
	char reg[256] = { 0 };
	int reg_idx = 0;

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

static bool parse_constant(const char *str, int *idx, unsigned long long *value) {
	int base = 10;
	int neg = 0;
	char num_str[256] = { 0 };
	int num_idx = 0;

	skip_whitespace(str, idx);

	if (str[*idx] == '-') {
		neg = 1;
		(*idx)++;
	}

	skip_whitespace(str, idx);

	if (str[*idx] == '0' && (str[*idx + 1] == 'x' || str[*idx + 1] == 'X')) {
		base = 16;
		*idx += 2;
	}

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

static bool parse_reg_to_const(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	unsigned long long const_value;
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
	char value_str[256];
	snprintf(value_str, sizeof(value_str), "%llu", const_value);
	rop_constraint->args[SRC_CONST] = strdup(value_str);
	return true;
}

static bool parse_reg_to_reg(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
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

static bool parse_il_op(RzList *args, const char *str, int *idx) {
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

	RzILOpPureCode *op_ptr = malloc(sizeof(RzILOpPureCode));
	if (!op_ptr) {
		return false;
	}
	*op_ptr = res;
	rz_list_append(args, op_ptr);

	return true;
}

static bool parse_reg_op_const(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
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
	snprintf(op_str, sizeof(op_str), "%s", rz_il_op_pure_code_stringify(*op));
	rop_constraint->args[OP] = strdup(op_str);
	char value_str[256];
	snprintf(value_str, sizeof(value_str), "%llu", const_value);
	rop_constraint->args[SRC_CONST] = strdup(value_str);
	return true;
}

static bool parse_reg_op_reg(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
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
	if (!parse_il_op(args, str, &idx)) {
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

	char op_str[16];
	snprintf(op_str, sizeof(op_str), "%s", rz_il_op_pure_code_stringify(*op));
	rop_constraint->args[OP] = strdup(op_str);
	rop_constraint->args[SRC_CONST] = dst_reg2;
	return true;
}

RZ_API bool analyze_constraint(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	rz_return_val_if_fail(core, NULL);
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
	if (!analyze_constraint(core, token, rop_constraint)) {
		free(rop_constraint);
		rz_list_free(l);
		return NULL;
	}

	rz_list_free(l);
	return rop_constraint;
}

static RzList *rop_constraint_list_parse(RzCore *core, int argc, const char **argv) {
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