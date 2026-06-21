// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

typedef enum rz_il_unicode_colorify_state_t {
	UNICODE_COLORIFY_STATE_DEFAULT,
	UNICODE_COLORIFY_STATE_VARNAME,
	UNICODE_COLORIFY_STATE_NUMBER,
	UNICODE_COLORIFY_STATE_IL_OP,
	UNICODE_COLORIFY_STATE_PARENTHESIS
} RzILUnicodeColorifyState;

typedef struct il_print_t {
	RzOutputMode mode;
	const char *name;
	void *ptr;
} ILPrint;

#define p_sb(x)  ((RzStrBuf *)x)
#define p_tbl(x) ((RzTable *)x)
#define p_pj(x)  ((PJ *)x)

static void rzil_print_register_bool(bool value, ILPrint *p) {
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: %s", p->name, rz_str_bool(value));
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "bool", rz_str_bool(value));
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_kb(p_pj(p->ptr), p->name, value);
		break;
	default:
		rz_cons_printf("%s\n", rz_str_bool(value));
		break;
	}
}

static void rzil_print_register_bitv(RzBitVector *number, ILPrint *p) {
	char *hex = rz_bv_as_hex_string(number, true);
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: %s", p->name, hex);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "bitv", hex);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_ks(p_pj(p->ptr), p->name, hex);
		break;
	default:
		rz_cons_printf("%s\n", hex);
		break;
	}
	free(hex);
}

static void rzil_print_register_float(RzFloat *number, ILPrint *p) {
	char *hex = rz_float_as_hex_string(number, true);
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: %s", p->name, hex);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "float", hex);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_ks(p_pj(p->ptr), p->name, hex);
		break;
	default:
		rz_cons_printf("%s\n", hex);
		break;
	}
	free(hex);
}

static int compare_strings(const RzILVar *v1, const RzILVar *v2, RZ_UNUSED void *user) {
	return strcmp(v1->name, v2->name);
}

RZ_IPI void rz_core_analysis_il_vm_status(RzCore *core, const char *var_name, RzOutputMode mode) {
	RzAnalysisILVM *vm = rz_analysis_get_il_vm(core->analysis);
	if (!vm) {
		RZ_LOG_ERROR("RzIL: Run 'aezi' first to initialize the VM\n");
		return;
	}

	ILPrint p = { 0 };
	p.mode = mode;

	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		p.ptr = rz_strbuf_new("");
		break;
	case RZ_OUTPUT_MODE_TABLE:
		p.ptr = rz_table_new();
		rz_table_set_columnsf(p_tbl(p.ptr), "sss", "variable", "type", "value");
		break;
	case RZ_OUTPUT_MODE_JSON:
		p.ptr = pj_new();
		pj_o(p_pj(p.ptr));
		break;
	default:
		break;
	}

	if (!var_name || !strcmp(var_name, "PC")) {
		p.name = "PC";
		rzil_print_register_bitv(vm->vm->pc, &p);
	}

	RzPVector *global_vars = rz_il_vm_get_all_vars(vm->vm, RZ_IL_VAR_KIND_GLOBAL);
	rz_pvector_sort(global_vars, (RzPVectorComparator)compare_strings, NULL);
	if (global_vars) {
		void **it;
		rz_pvector_foreach (global_vars, it) {
			RzILVar *var = *it;
			if (var_name && strcmp(var_name, var->name)) {
				continue;
			}
			p.name = var->name;
			RzILVal *val = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, var->name);
			if (!val) {
				continue;
			}
			switch (val->type) {
			case RZ_IL_TYPE_PURE_BITVECTOR:
				rzil_print_register_bitv(val->data.bv, &p);
				break;
			case RZ_IL_TYPE_PURE_BOOL:
				rzil_print_register_bool(val->data.b->b, &p);
				break;
			case RZ_IL_TYPE_PURE_FLOAT:
				rzil_print_register_float(val->data.f, &p);
				break;
			default:
				rz_warn_if_reached();
				break;
			}
			if (var_name) {
				break;
			}
			if (rz_strbuf_length(p_sb(p.ptr)) > 95) {
				rz_cons_printf("%s\n", rz_strbuf_get(p_sb(p.ptr)));
				rz_strbuf_fini(p_sb(p.ptr));
			}
		}
		rz_pvector_free(global_vars);
	}

	char *out = NULL;
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		if (rz_strbuf_length(p_sb(p.ptr)) > 0) {
			out = rz_strbuf_drain(p_sb(p.ptr));
		} else {
			rz_strbuf_free(p_sb(p.ptr));
			return;
		}
		break;
	case RZ_OUTPUT_MODE_TABLE:
		out = rz_table_tostring((RzTable *)p.ptr);
		rz_table_free(p_tbl(p.ptr));
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_end(p_pj(p.ptr));
		out = pj_drain(p_pj(p.ptr));
		break;
	default:
		return;
	}

	rz_cons_printf("%s\n", out);
	free(out);
}
#undef p_sb
#undef p_tbl
#undef p_pj

static bool step_assert_vm(RzCore *core) {
	RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
	if (!il_vm) {
		RZ_LOG_ERROR("RzIL: Run 'aezi' first to initialize the VM\n");
		return false;
	}
	return true;
}

static bool step_handle_result(RzCore *core, RzAnalysisILStepResult r) {
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	switch (r) {
	case RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS:
		rz_core_reg_update_flags(core);
		return true;
	case RZ_ANALYSIS_IL_STEP_UNIMPLEMENTED_IL: {
		ut64 reg_pc = rz_reg_get_value_by_role(rreg, RZ_REG_NAME_PC);
		RZ_LOG_ERROR("RzIL: lifting not implemented at address 0x%08" PFMT64x "\n", reg_pc);
	} break;
	case RZ_ANALYSIS_IL_STEP_INVALID_OP: {
		ut64 reg_pc = rz_reg_get_value_by_role(rreg, RZ_REG_NAME_PC);
		RZ_LOG_ERROR("RzIL: invalid instruction at address 0x%08" PFMT64x "\n", reg_pc);
	} break;
	default: {
		RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
		ut64 vm_pc = rz_bv_to_ut64(il_vm->vm->pc);
		RZ_LOG_ERROR("RzIL: stepping failed with PC at 0x%" PFMT64x ".\n", vm_pc);
	} break;
	}
	return false;
}

static bool step_cond_n(RzAnalysisILVM *vm, void *user) {
	if (rz_cons_is_breaked()) {
		rz_cons_printf("Stepping was interrupted.\n");
		return false;
	}
	ut64 *n = user;
	if (!*n) {
		return false;
	}
	(*n)--;
	return true;
}

/**
 * Perform \p n steps starting at the PC given by analysis->reg in RzIL
 * \return false if an error occured (e.g. invalid op)
 */
RZ_API bool rz_core_il_step(RZ_NONNULL RzCore *core, ut64 n) {
	rz_return_val_if_fail(core && n, false);
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while(core->analysis, il_vm, rreg,
		step_cond_n, &n);
	return step_handle_result(core, r);
}

static bool step_cond_until(RzAnalysisILVM *vm, void *user) {
	if (rz_cons_is_breaked()) {
		rz_cons_printf("Stepping was interrupted.\n");
		return false;
	}
	ut64 *until = user;
	ut64 pc = rz_bv_to_ut64(vm->vm->pc);
	return pc != *until;
}

/**
 * Perform zero or more steps starting at the PC given by analysis->reg in RzIL
 * until reaching the given PC
 * \param until destination address where to stop
 * \return false if an error occured (e.g. invalid op)
 */
RZ_API bool rz_core_il_step_until(RZ_NONNULL RzCore *core, ut64 until) {
	rz_return_val_if_fail(core && until, false);
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while(core->analysis, il_vm, rreg,
		step_cond_until, &until);
	return step_handle_result(core, r);
}

/**
 * Perform zero or more steps starting at the PC given by analysis->reg in RzIL
 * until reaching the given PC and output VM changes (read & write)
 * \param until destination address where to stop
 * \return false if an error occured (e.g. invalid op)
 */
RZ_API bool rz_core_il_step_until_with_events(RZ_NONNULL RzCore *core, ut64 until) {
	rz_return_val_if_fail(core && until, false);
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while_with_events(
		core->analysis, il_vm, rreg,
		step_cond_until, &until);
	return step_handle_result(core, r);
}

/**
 * Perform a single step at the PC given by analysis->reg in RzIL and print any events that happened
 * \return false if an error occured (e.g. invalid op)
 */
RZ_IPI bool rz_core_analysis_il_step_with_events(RzCore *core, PJ *pj) {
	RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
	if (!il_vm) {
		return false;
	}

	if (!rz_core_il_step(core, 1)) {
		return false;
	}

	RzILVM *vm = il_vm->vm;

	RzStrBuf *sb = NULL;
	void **it;
	RzILEvent *evt;

	bool evt_read = rz_config_get_b(core->config, "rzil.step.events.read");
	bool evt_write = rz_config_get_b(core->config, "rzil.step.events.write");

	if (!evt_read && !evt_write) {
		RZ_LOG_ERROR("RzIL: cannot print events when all the events are disabled.\n");
		RZ_LOG_ERROR("RzIL: please set 'rzil.step.events.read' or/and 'rzil.step.events.write' to true and try again.\n");
		return false;
	}

	if (!pj) {
		sb = rz_strbuf_new("");
	}
	rz_pvector_foreach (vm->events, it) {
		evt = *it;
		if (!evt_read && (evt->type == RZ_IL_EVENT_MEM_READ || evt->type == RZ_IL_EVENT_VAR_READ)) {
			continue;
		} else if (!evt_write && (evt->type != RZ_IL_EVENT_MEM_READ && evt->type != RZ_IL_EVENT_VAR_READ)) {
			continue;
		}
		if (!pj) {
			rz_il_event_stringify(evt, sb);
			rz_strbuf_append(sb, "\n");
		} else {
			rz_il_event_json(evt, pj);
		}
	}
	if (!pj) {
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}
	return true;
}

static inline void emit_span(const char *s, size_t n, const char *color) {
	if (n < 1) {
		return;
	}
	if (color) {
		rz_cons_printf("%s%.*s" Color_RESET, color, (int)n, s);
	} else {
		rz_cons_printf("%.*s", (int)n, s);
	}
}

static inline void emit_span_to_strbuf(const char *s, size_t n, const char *color, RzStrBuf *sb) {
	if (n < 1) {
		return;
	}
	if (color) {
		rz_strbuf_appendf(sb, "%s%.*s" Color_RESET, color, (int)n, s);
	} else {
		rz_strbuf_append_n(sb, s, n);
	}
}

/**
 * \brief Colorize a stringified RzIL effect body to the cons buffer.
 *
 * Emits only the body (no address prefix, no newline) with the same palette
 * as \c plf. A NULL or empty \p il_stmt emits nothing.
 */
RZ_IPI void rz_core_il_colorize_body(RZ_NONNULL RzConsContext *ctx, RZ_NULLABLE const char *il_stmt) {
	rz_return_if_fail(ctx);
	if (RZ_STR_ISEMPTY(il_stmt)) {
		return;
	}

	const char *color = NULL;
	size_t prev = 0, len = strlen(il_stmt);

	for (size_t i = 0; i < len; ++i) {
		const char ch = il_stmt[i];

		if (ch == '(' || ch == ')') {
			emit_span(il_stmt + prev, i - prev, color);
			rz_cons_printf("%s%c" Color_RESET, ctx->pal.meta, ch);
			prev = i + 1;
			color = (ch == '(') ? ctx->pal.flow : NULL;
		} else if (ch == ' ') {
			emit_span(il_stmt + prev, i - prev, color);
			rz_cons_printf(" ");
			prev = i + 1;
			color = NULL;
		} else if (i == prev && prev > 0 && il_stmt[prev - 1] == ' ') {
			color = IS_DIGIT(ch) ? ctx->pal.num : ctx->pal.comment;
		}
	}

	emit_span(il_stmt + prev, len - prev, color);
}

static void core_colorify_il_statement(RzConsContext *ctx, const char *il_stmt, const char delim, ut64 addr) {
	rz_cons_printf("%s0x%" PFMT64x Color_RESET "%c", ctx->pal.label, addr, delim);
	rz_core_il_colorize_body(ctx, il_stmt);
	rz_cons_newline();
}

static void core_colorify_il_statement_to_strbuf(RzConsContext *ctx, const char *il_stmt, const char delim, ut64 addr, RzStrBuf *sb) {
	rz_strbuf_appendf(sb, "%s0x%" PFMT64x Color_RESET "%c", ctx->pal.label, addr, delim);
	if (RZ_STR_ISEMPTY(il_stmt)) {
		rz_strbuf_appendf(sb, "\n");
		return;
	}

	const char *color = NULL;
	size_t prev = 0, len = strlen(il_stmt);

	for (size_t i = 0; i < len; ++i) {
		const char ch = il_stmt[i];

		if (ch == '(' || ch == ')') {
			emit_span_to_strbuf(il_stmt + prev, i - prev, color, sb);
			rz_strbuf_appendf(sb, "%s%c" Color_RESET, ctx->pal.meta, ch);
			prev = i + 1;
			color = (ch == '(') ? ctx->pal.flow : NULL;
		} else if (ch == ' ') {
			emit_span_to_strbuf(il_stmt + prev, i - prev, color, sb);
			rz_strbuf_appendf(sb, " ");
			prev = i + 1;
			color = NULL;
		} else if (i == prev && prev > 0 && il_stmt[prev - 1] == ' ') {
			color = IS_DIGIT(ch) ? ctx->pal.num : ctx->pal.comment;
		}
	}

	emit_span_to_strbuf(il_stmt + prev, len - prev, color, sb);
}

static bool unicode_colorify_state_is_varname(RzILUnicodeColorifyState state) {
	return state == UNICODE_COLORIFY_STATE_VARNAME;
}

static bool unicode_colorify_state_is_number(RzILUnicodeColorifyState state) {
	return state == UNICODE_COLORIFY_STATE_NUMBER;
}

static bool is_varname(RzILUnicodeColorifyState state, RzCodePoint c) {
	const bool is_varname = unicode_colorify_state_is_varname(state);
	return (c == '_') || IS_ALPHA(c) || (is_varname && IS_DIGIT(c));
}

static bool is_number(RzILUnicodeColorifyState state, RzCodePoint c) {
	const RzCodePoint subscript_0 = 0x2080;
	const RzCodePoint subscript_9 = 0x2089;
	const bool is_subscript_num = RZ_BETWEEN(subscript_0, c, subscript_9);
	const bool is_varname = unicode_colorify_state_is_varname(state);
	const bool is_num = unicode_colorify_state_is_number(state);
	return (IS_DIGIT(c) && !is_varname) || (is_num && (IS_HEXCHAR(c) || c == 'x' || c == 'X' || c == '.' || is_subscript_num));
}

RzILUnicodeColorifyState unicode_colorify_state_next(RzILUnicodeColorifyState state, RzCodePoint c) {
	if (is_number(state, c)) {
		return UNICODE_COLORIFY_STATE_NUMBER;
	}
	if (is_varname(state, c)) {
		return UNICODE_COLORIFY_STATE_VARNAME;
	}
	if (IS_PARANTHESIS(c)) {
		return UNICODE_COLORIFY_STATE_PARENTHESIS;
	}
	if (IS_WHITECHAR(c)) {
		return UNICODE_COLORIFY_STATE_DEFAULT;
	}
	return UNICODE_COLORIFY_STATE_IL_OP;
}

static const char *core_il_get_token_color(RzILUnicodeColorifyState state, const char *prev_color, RZ_NONNULL RzConsContext *ctx) {
	rz_return_val_if_fail(ctx, NULL);
	const char *color = prev_color;
	switch (state) {
	default: break;
	case UNICODE_COLORIFY_STATE_DEFAULT:
		color = NULL;
		break;
	case UNICODE_COLORIFY_STATE_PARENTHESIS:
		color = ctx->pal.meta;
		break;
	case UNICODE_COLORIFY_STATE_VARNAME:
		color = ctx->pal.comment;
		break;
	case UNICODE_COLORIFY_STATE_NUMBER:
		color = ctx->pal.num;
		break;
	case UNICODE_COLORIFY_STATE_IL_OP:
		color = ctx->pal.flow;
		break;
	}
	return color;
}

static void core_colorify_il_statement_unicode(RzConsContext *ctx, const char *il_stmt, const char delim, ut64 addr) {
	rz_cons_printf("%s0x%" PFMT64x Color_RESET "%c", ctx->pal.label, addr, delim);
	if (RZ_STR_ISEMPTY(il_stmt)) {
		rz_cons_newline();
		return;
	}

	size_t prev_i = 0;
	const size_t len = strlen(il_stmt);
	const char *color = NULL;
	RzILUnicodeColorifyState prev_state = UNICODE_COLORIFY_STATE_DEFAULT;
	for (size_t i = 0; i < len;) {
		RzCodePoint cp = 0;
		const size_t utf_size = rz_utf8_decode((const ut8 *)il_stmt + i, len - i, &cp, false);
		RzILUnicodeColorifyState state = unicode_colorify_state_next(prev_state, cp);
		if (state != prev_state) {
			const int plen = i - prev_i;
			if (color) {
				rz_cons_printf("%s%.*s" Color_RESET, color, plen, il_stmt + prev_i);
			} else {
				rz_cons_printf("%.*s", plen, il_stmt + prev_i);
			}

			color = core_il_get_token_color(state, color, ctx);

			prev_state = state;
			prev_i = i;
		}
		i += utf_size > 0 ? utf_size : 1;
	}
	if (prev_i < len) {
		const int plen = len - prev_i;
		if (color) {
			rz_cons_printf("%s%.*s" Color_RESET, color, plen, il_stmt + prev_i);
		} else {
			rz_cons_printf("%.*s", plen, il_stmt + prev_i);
		}
	}
	rz_cons_newline();
}

static void core_colorify_il_statement_unicode_to_strbuf(RzConsContext *ctx, const char *il_stmt, const char delim, ut64 addr, RzStrBuf *sb) {
	rz_return_if_fail(sb);
	rz_strbuf_appendf(sb, "%s0x%" PFMT64x Color_RESET "%c", ctx->pal.label, addr, delim);
	if (RZ_STR_ISEMPTY(il_stmt)) {
		rz_strbuf_appendf(sb, "\n");
		return;
	}
	size_t prev_i = 0;
	const size_t len = strlen(il_stmt);
	const char *color = NULL;
	RzILUnicodeColorifyState prev_state = UNICODE_COLORIFY_STATE_DEFAULT;
	for (size_t i = 0; i < len;) {
		RzCodePoint cp = 0;
		const size_t utf_size = rz_utf8_decode((const ut8 *)il_stmt + i, len - i, &cp, false);
		RzILUnicodeColorifyState state = unicode_colorify_state_next(prev_state, cp);
		if (state == prev_state) {
			i += utf_size > 0 ? utf_size : 1;
			continue;
		}
		const int plen = i - prev_i;
		if (color) {
			rz_strbuf_appendf(sb, "%s%.*s" Color_RESET, color, plen, il_stmt + prev_i);
		} else {
			rz_strbuf_appendf(sb, "%.*s", plen, il_stmt + prev_i);
		}

		color = core_il_get_token_color(state, color, ctx);

		prev_state = state;
		prev_i = i;
		i += utf_size > 0 ? utf_size : 1;
	}
	if (prev_i >= len) {
		rz_strbuf_appendf(sb, "\n");
		return;
	}
	const int plen = len - prev_i;
	if (color) {
		rz_strbuf_appendf(sb, "%s%.*s" Color_RESET, color, plen, il_stmt + prev_i);
	} else {
		rz_strbuf_appendf(sb, "%.*s", plen, il_stmt + prev_i);
	}
	rz_strbuf_appendf(sb, "\n");
}

static ut64 core_il_get_refline_at(ut64 vat, RZ_NONNULL RzPVector /*<RzAnalysisRefline *>*/ *reflines) {
	rz_return_val_if_fail(reflines, UT64_MAX);
	void **iter;
	rz_pvector_foreach (reflines, iter) {
		RzAnalysisRefline *ref = *iter;
		if (ref->from == vat) {
			return ref->to;
		}
	}
	return UT64_MAX;
}

static void init_asmqjmps(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core);
	if (core->keep_asmqjmps) {
		return;
	}
	core->asmqjmps_count = 0;
	ut64 *p = realloc(core->asmqjmps, RZ_CORE_ASMQJMPS_NUM * sizeof(ut64));
	if (p) {
		core->asmqjmps_size = RZ_CORE_ASMQJMPS_NUM;
		core->asmqjmps = p;
		memset(core->asmqjmps, 0xff, RZ_CORE_ASMQJMPS_NUM * sizeof(ut64));
	}
}

typedef struct il_state_t {
	RzCore *core;
	RzCoreILPrintOptions *options;

	ut64 addr;
	ut64 current;
	ut64 vat;

	ut8 *buf;
	ut8 *addbuf;
	size_t len;

	size_t idx;
	size_t inc;
	size_t ops_count;
	size_t n_lines;
	ut8 min_op_size;

	RzStrBuf *sb;
	RzAnalysisDisasmText *dst;

	RzPVector /*<RzAnalysisRefline *>*/ *reflines;
} RzILState;

static RzILState *il_state_init(RZ_NONNULL RzCore *core) {
	RzILState *ils = RZ_NEW0(RzILState);
	ils->core = core;
	ils->sb = RZ_NEW0(RzStrBuf);
	rz_strbuf_init(ils->sb);
	return ils;
}

static void il_state_reflines_init(RzILState *ils) {
	rz_return_if_fail(ils && ils->core && ils->buf && (ils->len || ils->n_lines));
	ils->reflines = rz_analysis_reflines_get(ils->core->analysis,
		ils->addr, ils->buf, ils->len, ils->n_lines,
		rz_config_get_i(ils->core->config, "asm.lines.out"),
		rz_config_get_b(ils->core->config, "asm.lines") ? rz_config_get_b(ils->core->config, "asm.lines.call") : false);
	rz_analysis_set_reflines(ils->core->analysis, ils->reflines);
}

static void core_il_stringify_single_il(RzILState *ils) {
	const char *il_stmt = NULL;
	const char delim = ils->options->pretty ? '\n' : ' ';
	RzAnalysisOp op;

	ils->current = ils->addr + ils->idx;
	ils->vat = rz_core_pava(ils->core, ils->current);

	ils->dst = RZ_NEW0(RzAnalysisDisasmText);
	ils->dst->arrow = UT64_MAX;

	rz_strbuf_fini(ils->sb);
	rz_strbuf_init(ils->sb);
	if (ils->core->print->flags & RZ_PRINT_FLAGS_UNALLOC) {
		if (!rz_io_is_valid_offset(ils->core->io, ils->current, 0)) {
			rz_strbuf_appendf(ils->sb, "0x%" PFMT64x "%cunmapped", ils->current, delim);
			ils->inc = 1;
			goto finish_str;
		}
	}
	rz_core_seek_arch_bits(ils->core, ils->current);
	rz_analysis_op_init(&op);
	if (rz_analysis_op(ils->core->analysis, &op, ils->current, ils->buf + ils->idx, (int)(ils->len - ils->idx), RZ_ANALYSIS_OP_MASK_IL) < 1) {
		rz_strbuf_appendf(ils->sb, "0x%" PFMT64x "%cinvalid", ils->current, delim);
		ils->inc = 1;
		goto finalize;
	}
	ils->inc = op.size;
	if (!op.il_op) {
		RZ_LOG_DEBUG("Empty IL at 0x%08" PFMT64x "...", op.addr);
		rz_strbuf_appendf(ils->sb, "0x%" PFMT64x "%cempty il", op.addr, delim);
		goto finalize;
	}
	if (ils->options->unicode) {
		const int addr_len = snprintf(NULL, 0, "0x%" PFMT64x, op.addr);
		RzILStringifyCtx ctx = { .indent = addr_len + 1, .indent_inc = 2 };
		if (!rz_il_op_effect_stringify_unicode(&ctx, op.il_op, ils->sb)) {
			RZ_LOG_ERROR("Failed to stringify unicode IL at 0x%08" PFMT64x "\n", op.addr);
			rz_strbuf_appendf(ils->sb, "0x%" PFMT64x "%c ustringify failed", op.addr, delim);
			goto finalize;
		}
	} else {
		rz_il_op_effect_stringify(op.il_op, ils->sb, ils->options->pretty);
	}

	il_stmt = rz_strbuf_drain_nofree(ils->sb);
	rz_strbuf_init(ils->sb);
	if (ils->options->colorize) {
		if (ils->options->unicode) {
			core_colorify_il_statement_unicode_to_strbuf(ils->core->cons->context, il_stmt, delim, op.addr, ils->sb);
		} else {
			core_colorify_il_statement_to_strbuf(ils->core->cons->context, il_stmt, delim, op.addr, ils->sb);
		}
	} else {
		rz_strbuf_appendf(ils->sb, "0x%" PFMT64x "%c%s", op.addr, delim, il_stmt);
	}
	RZ_FREE(il_stmt);
	ils->dst->arrow = core_il_get_refline_at(ils->vat, ils->reflines);
finalize:
	rz_analysis_op_fini(&op);
finish_str:
	ils->dst->offset = ils->vat;
	ils->dst->text = rz_strbuf_drain_nofree(ils->sb);
	if (!ils->inc)
		ils->inc = RZ_MAX(1, ils->min_op_size);
}

static void il_state_reflines_fini(RzILState *ils) {
	if (ils) {
		rz_analysis_set_reflines(ils->core->analysis, NULL);
		rz_pvector_free(ils->reflines);
		ils->reflines = NULL;
	}
}

static void il_state_free(RzILState *ils) {
	rz_strbuf_free(ils->sb);
	il_state_reflines_fini(ils);
	RZ_FREE(ils->addbuf);
	free(ils);
}

static bool il_state_complete(RzILState *ils) {
	if (!ils->options->cbytes && ils->ops_count < ils->n_lines) {
		ils->addr = ils->current + ils->inc;
		if (ils->len < 16) {
			ils->len = 16;
		}
		free(ils->addbuf);
		ils->buf = ils->addbuf = malloc(ils->len);
		if (ils->addbuf) {
			rz_io_read_at_mapped(ils->core->io, ils->addr, ils->buf, ils->len);
			return false;
		}
	}
	return true;
}

/* \brief Format instructions and add generated RzIL code to an analysis text vector.
 *
 * Decode instructions starting at the specified address, format their
 * RzIL equivalents into printable strings, using optional pretty printing,
 * unicode conversion and syntax highlighting, then store the strings as
 * RzAnalysisDisasmText entries in the vector provided.
 *
 * \param core      Pointer to the current RzCore instance.
 * \param addr      Starting address for instruction decoding.
 * \param buf       Pointer to memory buffer that contains instructions.
 * \param len       Length of \p buf in bytes.
 * \param n_lines   Maximum number of instructions to decode. Uses
 *                  core->blocksize if value is 0.
 * \param options   Formatting parameters and vector for storing results.
 *
 * \return Number of instructions decoded successfully.
 */
RZ_API int rz_core_il_print_rzil(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL ut8 *buf, size_t len, size_t n_lines, RZ_NULLABLE RzCoreILPrintOptions *options) {
	rz_return_val_if_fail(core && buf && (n_lines || len), 0);

	if (!options->vec) {
		return 0;
	}
	if (!n_lines) {
		n_lines = core->blocksize;
	}

	RzILState *ils = il_state_init(core);
	ils->addr = addr;
	ils->buf = buf;
	ils->len = len;
	ils->n_lines = n_lines;
	ils->options = options;
	ils->min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);

	do {
		il_state_reflines_init(ils);
		init_asmqjmps(core);

		for (ils->idx = 0; ils->ops_count < ils->n_lines && ils->idx < ils->len; ils->ops_count++, ils->idx += ils->inc) {

			core_il_stringify_single_il(ils);

			if (!rz_pvector_push(ils->options->vec, ils->dst)) {
				free(ils->dst->text);
				free(ils->dst);
				ils->dst = NULL;
			}
		}
		il_state_reflines_fini(ils);
	} while (!il_state_complete(ils));

	const int ops_count = ils->ops_count;

	il_state_free(ils);
	return ops_count;
}

RZ_IPI void rz_core_il_cons_print(RZ_NONNULL RzCore *core, RZ_NONNULL RZ_BORROW RzIterator *iter, bool pretty, bool unicode) {
	rz_return_if_fail(core && iter);
	bool colorize = rz_config_get_i(core->config, "scr.color") > 0;
	const char *il_stmt = NULL;
	const char delim = pretty ? '\n' : ' ';
	RzStrBuf sb;

	RzAnalysisILVM *vm = rz_analysis_il_vm_new(core->analysis, NULL);
	RzILValidateGlobalContext *ctx = vm ? rz_il_validate_global_context_new_from_vm(vm->vm)
					    : NULL;

	RzAnalysisOp *op = NULL;
	rz_iterator_foreach(iter, op) {
		if (!op->il_op) {
			RZ_LOG_DEBUG("Empty IL at 0x%08" PFMT64x "...\n", op->addr);
			break;
		}

		rz_strbuf_init(&sb);
		if (unicode) {
			const int addr_len = snprintf(NULL, 0, "0x%" PFMT64x, op->addr);
			RzILStringifyCtx ctx = { .indent = addr_len + 1, .indent_inc = 2 };
			if (!rz_il_op_effect_stringify_unicode(&ctx, op->il_op, &sb)) {
				RZ_LOG_ERROR("Failed to stringify IL at 0x%08" PFMT64x "\n", op->addr);
				rz_strbuf_fini(&sb);
				break;
			}
		} else {
			rz_il_op_effect_stringify(op->il_op, &sb, pretty);
		}

		il_stmt = rz_strbuf_get(&sb);
		if (colorize) {
			if (unicode) {
				core_colorify_il_statement_unicode(core->cons->context, il_stmt, delim, op->addr);
			} else {
				core_colorify_il_statement(core->cons->context, il_stmt, delim, op->addr);
			}
		} else {
			rz_cons_printf("0x%" PFMT64x "%c%s\n", op->addr, delim, il_stmt);
		}

		if (ctx) {
			RzILTypeEffect t;
			char *report;
			rz_il_validate_effect(op->il_op, ctx, NULL, &t, &report);
			if (report) {
				rz_cons_println(report);
				free(report);
			}
		}
		rz_strbuf_fini(&sb);
	}
	rz_analysis_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);
}