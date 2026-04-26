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
		rz_strbuf_appendf(sb, "%.*s", (int)n, s);
	}
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
	rz_strbuf_appendf(sb, "\n");
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
		if (state != prev_state) {
			const int plen = i - prev_i;
			if (color) {
				rz_strbuf_appendf(sb, "%s%.*s" Color_RESET, color, plen, il_stmt + prev_i);
			} else {
				rz_strbuf_appendf(sb, "%.*s", plen, il_stmt + prev_i);
			}
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

			prev_state = state;
			prev_i = i;
		}
		i += utf_size > 0 ? utf_size : 1;
	}
	if (prev_i < len) {
		const int plen = len - prev_i;
		if (color) {
			rz_strbuf_appendf(sb, "%s%.*s" Color_RESET, color, plen, il_stmt + prev_i);
		} else {
			rz_strbuf_appendf(sb, "%.*s", plen, il_stmt + prev_i);
		}
	}
	rz_strbuf_appendf(sb, "\n");
}

/* \brief formatted rzil from a starting RVA to a RzPVector of DisasmTexts
 * \param core - rz core
 * \param vec - allocated rzpvector pointer with free function for disasm_text
 * \param addr - starting address of instructions
 * \param n_lines - number of lines to be represented as rzil
 * \param pretty - whether add delimitter or not
 * \param unicode - whether enable unicode formatting or not
 * \param colorize - color the text
 */
RZ_API int rz_core_il_print_rzil(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL ut8 *buf, int len, int n_lines, RZ_NULLABLE RzCoreILPrintOptions *options) {
	rz_return_val_if_fail(core && buf && (n_lines || len), 0);
	RzPVector *vec = NULL;
	bool pretty = false;
	bool unicode = false;
	bool colorize = false;
	if (options) {
		pretty = options->pretty;
		colorize = options->colorize;
		unicode = options->unicode;
		vec = options->vec;
	}
	if (!vec) {
		return 0;
	}
	if (!n_lines) {
		n_lines = core->blocksize;
	}
	const char *il_stmt = NULL;
	const char delim = pretty ? '\n' : ' ';
	RzStrBuf sb;
	RzPVector *reflines;
	RzAnalysisOp op;
	int ops_count = 0, inc = 0, idx;
	ut64 current = addr, vat;
	ut8 *nbuf = NULL;
	ut8 min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
complete:
	reflines = rz_analysis_reflines_get(core->analysis,
		addr, buf, len, n_lines,
		rz_config_get_i(core->config, "asm.lines.out"),
		rz_config_get_b(core->config, "asm.lines") ? rz_config_get_b(core->config, "asm.lines.call") : false);
	rz_analysis_set_reflines(core->analysis, reflines);
	if (!core->keep_asmqjmps) { // hack
		core->asmqjmps_count = 0;
		ut64 *p = realloc(core->asmqjmps, RZ_CORE_ASMQJMPS_NUM * sizeof(ut64));
		if (p) {
			core->asmqjmps_size = RZ_CORE_ASMQJMPS_NUM;
			core->asmqjmps = p;
			for (int i = 0; i < RZ_CORE_ASMQJMPS_NUM; i++) {
				core->asmqjmps[i] = UT64_MAX;
			}
		}
	}
	for (idx = 0; ops_count < n_lines && idx < len; ops_count++, idx += inc) {
		current = addr + idx;
		RzAnalysisDisasmText *dst = RZ_NEW0(RzAnalysisDisasmText);
		dst->arrow = UT64_MAX;
		vat = rz_core_pava(core, current);
		rz_strbuf_init(&sb);
		if (core->print->flags & RZ_PRINT_FLAGS_UNALLOC) {
			if (!rz_io_is_valid_offset(core->io, current, 0)) {
				rz_strbuf_appendf(&sb, "0x%" PFMT64x "%cunmapped", current, delim);
				inc = 1;
				goto finish_str;
			}
		}
		rz_core_seek_arch_bits(core, current);
		rz_analysis_op_init(&op);
		if (rz_analysis_op(core->analysis, &op, current, buf + idx, (int)(len - idx), RZ_ANALYSIS_OP_MASK_IL) < 1) {
			rz_strbuf_appendf(&sb, "0x%" PFMT64x "%cinvalid", current, delim);
			inc = 1;
			goto finalize;
		}
		inc = op.size;
		if (!op.il_op) {
			RZ_LOG_DEBUG("Empty IL at 0x%08" PFMT64x "...", op.addr);
			rz_strbuf_appendf(&sb, "0x%" PFMT64x "%cempty il", op.addr, delim);
			goto finalize;
		}
		if (unicode) {
			const int addr_len = snprintf(NULL, 0, "0x%" PFMT64x, op.addr);
			RzILStringifyCtx ctx = { .indent = addr_len + 1, .indent_inc = 2 };
			if (!rz_il_op_effect_stringify_unicode(&ctx, op.il_op, &sb)) {
				RZ_LOG_ERROR("Failed to stringify IL at 0x%08" PFMT64x "\n", op.addr);
				rz_strbuf_appendf(&sb, "0x%" PFMT64x "%cstringify failed", op.addr, delim);
				goto finalize;
			}
		} else {
			rz_il_op_effect_stringify(op.il_op, &sb, pretty);
		}

		il_stmt = rz_str_dup(rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
		rz_strbuf_init(&sb);
		if (colorize) {
			if (unicode) {
				core_colorify_il_statement_unicode_to_strbuf(core->cons->context, il_stmt, delim, op.addr, &sb);
			} else {
				core_colorify_il_statement_to_strbuf(core->cons->context, il_stmt, delim, op.addr, &sb);
			}
		} else {
			rz_strbuf_appendf(&sb, "0x%" PFMT64x "%c%s", op.addr, delim, il_stmt);
		}
		RZ_FREE(il_stmt)
		if (reflines) {
			void **iter;
			rz_pvector_foreach (reflines, iter) {
				RzAnalysisRefline *ref = *iter;
				if (ref->from == vat) {
					dst->arrow = ref->to;
					break;
				}
			}
		}
	finalize:
		rz_analysis_op_fini(&op);
	finish_str:
		dst->offset = rz_core_pava(core, current);
		dst->text = rz_str_dup(rz_strbuf_get(&sb));
		inc = inc ? inc : RZ_MAX(1, min_op_size);
		if (!rz_pvector_push(vec, dst)) {
			free(dst->text);
			free(dst);
		}
		rz_strbuf_fini(&sb);
	}
	rz_analysis_set_reflines(core->analysis, NULL);
	rz_pvector_free(reflines);
	if (!options->cbytes && ops_count < n_lines) {
		addr = current + inc;
		if (len < 16) {
			len = 16;
		}
		free(nbuf);
		buf = nbuf = malloc(len);
		if (nbuf) {
			rz_io_read_at_mapped(core->io, addr, buf, len);
			goto complete;
		}
	}
	RZ_FREE(nbuf);
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
