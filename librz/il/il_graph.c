// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file il_graph.c
 * Outputs the IL statements in a graph format.
 */

#include <rz_il/rz_il_vm.h>
#include <rz_util.h>
#include <rz_util/rz_graph_drawable.h>

static void il_op_pure_graph_resolve(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from);
static void il_op_effect_graph_resolve(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from);

#define graph_add_node_il(g, d) \
	rz_graph_add_node_info(g, d, NULL, UT64_MAX)

#define il_op_graph_add_edge_s(g, from, string) \
	do { \
		RzGraphNode *to = graph_add_node_il(g, string); \
		rz_graph_add_edge(g, from, to); \
	} while (0)

#define il_op_graph_add_edge_f(g, from, ...) \
	do { \
		char *value = rz_str_newf(__VA_ARGS__); \
		RzGraphNode *to = graph_add_node_il(g, value); \
		free(value); \
		rz_graph_add_edge(g, from, to); \
	} while (0)

#define il_op_param_0(name) \
	il_op_graph_add_edge_s(g, from, name)

#define il_op_param_1(name, opx, v0) \
	do { \
		RzGraphNode *to = graph_add_node_il(g, name); \
		rz_graph_add_edge(g, from, to); \
		il_op_pure_graph_resolve(opx.v0, g, to); \
	} while (0)

#define il_op_param_2(name, opx, sort0, v0, sort1, v1) \
	do { \
		RzGraphNode *to = graph_add_node_il(g, name); \
		rz_graph_add_edge(g, from, to); \
		il_op_##sort0##_graph_resolve(opx.v0, g, to); \
		il_op_##sort1##_graph_resolve(opx.v1, g, to); \
	} while (0)

#define il_op_param_3(name, opx, sort0, v0, sort1, v1, sort2, v2) \
	do { \
		RzGraphNode *to = graph_add_node_il(g, name); \
		rz_graph_add_edge(g, from, to); \
		il_op_##sort0##_graph_resolve(opx.v0, g, to); \
		il_op_##sort1##_graph_resolve(opx.v1, g, to); \
		il_op_##sort2##_graph_resolve(opx.v2, g, to); \
	} while (0)

#define il_op_param_1_with_rmode(name, opx, v0, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		char *value = rz_str_newf(name " %s", rmode_str); \
		RzGraphNode *to = graph_add_node_il(g, value); \
		free(value); \
		rz_graph_add_edge(g, from, to); \
		il_op_pure_graph_resolve(opx.v0, g, to); \
	} while (0)

#define il_op_param_2_with_rmode(name, opx, sort0, v0, sort1, v1, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		char *value = rz_str_newf(name " %s", rmode_str); \
		RzGraphNode *to = graph_add_node_il(g, value); \
		free(value); \
		rz_graph_add_edge(g, from, to); \
		il_op_##sort0##_graph_resolve(opx.v0, g, to); \
		il_op_##sort1##_graph_resolve(opx.v1, g, to); \
	} while (0)

#define il_op_param_3_with_rmode(name, opx, sort0, v0, sort1, v1, sort2, v2, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		char *value = rz_str_newf(name " %s", rmode_str); \
		RzGraphNode *to = graph_add_node_il(g, value); \
		free(value); \
		rz_graph_add_edge(g, from, to); \
		il_op_##sort0##_graph_resolve(opx.v0, g, to); \
		il_op_##sort1##_graph_resolve(opx.v1, g, to); \
		il_op_##sort2##_graph_resolve(opx.v2, g, to); \
	} while (0)

static void il_op_graph_var(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsVar *opx = &op->op.var;
	char *value = rz_str_newf("var: %s", opx->v);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
}

static void il_op_graph_ite(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_3("ite", op->op.ite, pure, condition, pure, x, pure, y);
}

static void il_op_graph_let(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsLet *opx = &op->op.let;
	char *value = rz_str_newf("let: %s", opx->name);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->exp, g, to);
	il_op_pure_graph_resolve(opx->body, g, to);
}

static void il_op_graph_bool_false(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_graph_add_edge_s(g, from, "false");
}

static void il_op_graph_bool_true(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_graph_add_edge_s(g, from, "true");
}

static void il_op_graph_bool_inv(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("inv", op->op.boolinv, x);
}

static void il_op_graph_bool_and(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("and", op->op.booland, pure, x, pure, y);
}

static void il_op_graph_bool_or(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("or", op->op.boolor, pure, x, pure, y);
}

static void il_op_graph_bool_xor(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("xor", op->op.boolxor, pure, x, pure, y);
}

static void il_op_graph_bitv(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsBv *opx = &op->op.bitv;
	char *num = rz_bv_as_hex_string(opx->value, false);
	il_op_graph_add_edge_f(g, from, "bv: %u %s", opx->value->len, num);
	free(num);
}

static void il_op_graph_msb(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("msb", op->op.msb, bv);
}

static void il_op_graph_lsb(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("lsb", op->op.lsb, bv);
}

static void il_op_graph_is_zero(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_zero", op->op.lsb, bv);
}

static void il_op_graph_neg(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("neg", op->op.neg, bv);
}

static void il_op_graph_lognot(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("not", op->op.lognot, bv);
}

static void il_op_graph_add(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("add", op->op.add, pure, x, pure, y);
}

static void il_op_graph_sub(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("sub", op->op.sub, pure, x, pure, y);
}

static void il_op_graph_mul(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("mul", op->op.mul, pure, x, pure, y);
}

static void il_op_graph_div(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("div", op->op.div, pure, x, pure, y);
}

static void il_op_graph_sdiv(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("sdiv", op->op.sdiv, pure, x, pure, y);
}

static void il_op_graph_mod(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("mod", op->op.mod, pure, x, pure, y);
}

static void il_op_graph_smod(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("smod", op->op.smod, pure, x, pure, y);
}

static void il_op_graph_logand(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("and", op->op.logand, pure, x, pure, y);
}

static void il_op_graph_logor(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("or", op->op.logor, pure, x, pure, y);
}

static void il_op_graph_logxor(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("xor", op->op.logxor, pure, x, pure, y);
}

static void il_op_graph_shiftr(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_3("shift right", op->op.shiftr, pure, x, pure, y, pure, fill_bit);
}

static void il_op_graph_shiftl(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_3("shift left", op->op.shiftl, pure, x, pure, y, pure, fill_bit);
}

static void il_op_graph_eq(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("eq", op->op.ule, pure, x, pure, y);
}

static void il_op_graph_sle(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("sle", op->op.sle, pure, x, pure, y);
}

static void il_op_graph_ule(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("ule", op->op.ule, pure, x, pure, y);
}

static void il_op_graph_cast(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsCast *opx = &op->op.cast;
	char *value = rz_str_newf("cast: %u", opx->length);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->fill, g, to);
	il_op_pure_graph_resolve(opx->val, g, to);
}

static void il_op_graph_append(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("append", op->op.append, pure, high, pure, low);
}

static void il_op_graph_float(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFloat *opx = &op->op.float_;
	char *value = rz_str_newf("float: %d", opx->r);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->bv, g, to);
}

static void il_op_graph_fbits(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("fbits", op->op.fbits, f);
}

static void il_op_graph_is_finite(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_finite", op->op.is_finite, f);
}

static void il_op_graph_is_nan(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_nan", op->op.is_nan, f);
}

static void il_op_graph_is_inf(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_inf", op->op.is_inf, f);
}

static void il_op_graph_is_fzero(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_fzero", op->op.is_fzero, f);
}

static void il_op_graph_is_fneg(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_fneg", op->op.is_fneg, f);
}

static void il_op_graph_is_fpos(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("is_fpos", op->op.is_fpos, f);
}

static void il_op_graph_fneg(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("fneg", op->op.fneg, f);
}

static void il_op_graph_fabs(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("fpos", op->op.fabs, f);
}

static void il_op_graph_fcast_int(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFCastint *opx = &op->op.fcast_int;
	const char *rmode_str = rz_il_float_stringify_rmode(opx->mode);
	char *value = rz_str_newf("fcast_int: %u %s", opx->length, rmode_str);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->f, g, to);
}

static void il_op_graph_fcast_sint(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFCastsint *opx = &op->op.fcast_sint;
	const char *rmode_str = rz_il_float_stringify_rmode(opx->mode);
	char *value = rz_str_newf("fcast_sint: %u %s", opx->length, rmode_str);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->f, g, to);
}

static void il_op_graph_fcast_float(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFCastfloat *opx = &op->op.fcast_float;
	const char *format_str = rz_il_float_stringify_format(opx->format);
	const char *rmode_str = rz_il_float_stringify_rmode(opx->mode);
	char *value = rz_str_newf("fcast_float: %s %s", format_str, rmode_str);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->bv, g, to);
}

static void il_op_graph_fcast_sfloat(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFCastsfloat *opx = &op->op.fcast_sfloat;
	const char *format_str = rz_il_float_stringify_format(opx->format);
	const char *rmode_str = rz_il_float_stringify_rmode(opx->mode);
	char *value = rz_str_newf("fcast_sfloat: %s %s", format_str, rmode_str);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->bv, g, to);
}

static void il_op_graph_fconvert(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFconvert *opx = &op->op.fconvert;
	const char *format_str = rz_il_float_stringify_format(opx->format);
	const char *rmode_str = rz_il_float_stringify_rmode(opx->mode);
	char *value = rz_str_newf("fconvert: %s %s", format_str, rmode_str);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->f, g, to);
}

static void il_op_graph_fround(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFround *opx = &op->op.fround;
	const char *rmode_str = rz_il_float_stringify_rmode(opx->rmode);
	char *value = rz_str_newf("fround: %s", rmode_str);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->f, g, to);
}

static void il_op_graph_frequal(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsFrequal *opx = &op->op.frequal;
	const char *rmode_x = rz_il_float_stringify_rmode(opx->x);
	const char *rmode_y = rz_il_float_stringify_rmode(opx->y);
	char *value = rz_str_newf("frequal: %s %s", rmode_x, rmode_y);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
}

static void il_op_graph_fsucc(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("fsucc", op->op.fsucc, f);
}
static void il_op_graph_fpred(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("fpred", op->op.fpred, f);
}

static void il_op_graph_forder(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("<.", op->op.forder, pure, x, pure, y);
}

static void il_op_graph_fsqrt(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1_with_rmode("fsqrt", op->op.fsqrt, f, rmode);
}

static void il_op_graph_frsqrt(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1_with_rmode("frsqrt", op->op.frsqrt, f, rmode);
}

static void il_op_graph_fadd(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fadd", op->op.fadd, pure, x, pure, y, rmode);
}

static void il_op_graph_fsub(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fsub", op->op.fsub, pure, x, pure, y, rmode);
}

static void il_op_graph_fmul(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fmul", op->op.fmul, pure, x, pure, y, rmode);
}

static void il_op_graph_fdiv(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fdiv", op->op.fdiv, pure, x, pure, y, rmode);
}

static void il_op_graph_fmod(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fmod", op->op.fmod, pure, x, pure, y, rmode);
}

static void il_op_graph_fhypot(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("hypot", op->op.fhypot, pure, x, pure, y, rmode);
}

static void il_op_graph_fpow(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("pow", op->op.fpow, pure, x, pure, y, rmode);
}

static void il_op_graph_fmad(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_3_with_rmode("fmad", op->op.fmad, pure, x, pure, y, pure, z, rmode);
}

static void il_op_graph_fpown(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fpown", op->op.fpown, pure, f, pure, n, rmode);
}

static void il_op_graph_frootn(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("frootn", op->op.frootn, pure, f, pure, n, rmode);
}

static void il_op_graph_fcompound(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2_with_rmode("fcompound", op->op.fcompound, pure, f, pure, n, rmode);
}

static void il_op_graph_load(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsLoad *opx = &op->op.load;
	char *value = rz_str_newf("load: %u", opx->mem);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->key, g, to);
}

static void il_op_graph_loadw(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsLoadW *opx = &op->op.loadw;
	char *value = rz_str_newf("loadw: %u %u", (ut32)opx->mem, (ut32)opx->n_bits);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->key, g, to);
}

static void il_op_graph_store(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsStore *opx = &op->op.store;
	char *value = rz_str_newf("store: %u", (ut32)opx->mem);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->key, g, to);
	il_op_pure_graph_resolve(opx->value, g, to);
}

static void il_op_graph_storew(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsStore *opx = &op->op.store;
	char *value = rz_str_newf("storew: %u", (ut32)opx->mem);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->key, g, to);
	il_op_pure_graph_resolve(opx->value, g, to);
}

static void il_op_graph_nop(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_0("nop");
}

static void il_op_graph_empty(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_0("empty");
}

static void il_op_graph_set(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsSet *opx = &op->op.set;
	char *value = rz_str_newf("set: %s", opx->v);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_pure_graph_resolve(opx->x, g, to);
}

static void il_op_graph_jmp(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_1("jmp", op->op.jmp, dst);
}

static void il_op_graph_goto(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsGoto *opx = &op->op.goto_;
	char *value = rz_str_newf("goto: %s", opx->lbl);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
}

static void il_op_graph_seq(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsSeq *seq = &op->op.seq;
	if (seq->x->code == RZ_IL_OP_SEQ) {
		il_op_graph_seq(seq->x, g, from);
	} else {
		il_op_effect_graph_resolve(seq->x, g, from);
	}
	if (seq->y->code == RZ_IL_OP_SEQ) {
		il_op_graph_seq(seq->y, g, from);
	} else {
		il_op_effect_graph_resolve(seq->y, g, from);
	}
}

static void il_op_graph_blk(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	RzILOpArgsBlk *opx = &op->op.blk;
	char *value = rz_str_newf("blk: %s", opx->label);
	RzGraphNode *to = graph_add_node_il(g, value);
	free(value);
	rz_graph_add_edge(g, from, to);
	il_op_effect_graph_resolve(opx->data_eff, g, to);
	il_op_effect_graph_resolve(opx->ctrl_eff, g, to);
}

static void il_op_graph_repeat(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_2("repeat", op->op.repeat, pure, condition, effect, data_eff);
}

static void il_op_graph_branch(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	il_op_param_3("branch", op->op.branch, pure, condition, effect, true_eff, effect, false_eff);
}

static void il_op_pure_graph_resolve(RzILOpPure *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	if (!op) {
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_VAR:
		il_op_graph_var(op, g, from);
		return;
	case RZ_IL_OP_ITE:
		il_op_graph_ite(op, g, from);
		return;
	case RZ_IL_OP_LET:
		il_op_graph_let(op, g, from);
		return;
	case RZ_IL_OP_B0:
		il_op_graph_bool_false(op, g, from);
		return;
	case RZ_IL_OP_B1:
		il_op_graph_bool_true(op, g, from);
		return;
	case RZ_IL_OP_INV:
		il_op_graph_bool_inv(op, g, from);
		return;
	case RZ_IL_OP_AND:
		il_op_graph_bool_and(op, g, from);
		return;
	case RZ_IL_OP_OR:
		il_op_graph_bool_or(op, g, from);
		return;
	case RZ_IL_OP_XOR:
		il_op_graph_bool_xor(op, g, from);
		return;
	case RZ_IL_OP_BITV:
		il_op_graph_bitv(op, g, from);
		return;
	case RZ_IL_OP_MSB:
		il_op_graph_msb(op, g, from);
		return;
	case RZ_IL_OP_LSB:
		il_op_graph_lsb(op, g, from);
		return;
	case RZ_IL_OP_IS_ZERO:
		il_op_graph_is_zero(op, g, from);
		return;
	case RZ_IL_OP_NEG:
		il_op_graph_neg(op, g, from);
		return;
	case RZ_IL_OP_LOGNOT:
		il_op_graph_lognot(op, g, from);
		return;
	case RZ_IL_OP_ADD:
		il_op_graph_add(op, g, from);
		return;
	case RZ_IL_OP_SUB:
		il_op_graph_sub(op, g, from);
		return;
	case RZ_IL_OP_MUL:
		il_op_graph_mul(op, g, from);
		return;
	case RZ_IL_OP_DIV:
		il_op_graph_div(op, g, from);
		return;
	case RZ_IL_OP_SDIV:
		il_op_graph_sdiv(op, g, from);
		return;
	case RZ_IL_OP_MOD:
		il_op_graph_mod(op, g, from);
		return;
	case RZ_IL_OP_SMOD:
		il_op_graph_smod(op, g, from);
		return;
	case RZ_IL_OP_LOGAND:
		il_op_graph_logand(op, g, from);
		return;
	case RZ_IL_OP_LOGOR:
		il_op_graph_logor(op, g, from);
		return;
	case RZ_IL_OP_LOGXOR:
		il_op_graph_logxor(op, g, from);
		return;
	case RZ_IL_OP_SHIFTR:
		il_op_graph_shiftr(op, g, from);
		return;
	case RZ_IL_OP_SHIFTL:
		il_op_graph_shiftl(op, g, from);
		return;
	case RZ_IL_OP_EQ:
		il_op_graph_eq(op, g, from);
		return;
	case RZ_IL_OP_SLE:
		il_op_graph_sle(op, g, from);
		return;
	case RZ_IL_OP_ULE:
		il_op_graph_ule(op, g, from);
		return;
	case RZ_IL_OP_CAST:
		il_op_graph_cast(op, g, from);
		return;
	case RZ_IL_OP_APPEND:
		il_op_graph_append(op, g, from);
		return;
	case RZ_IL_OP_LOAD:
		il_op_graph_load(op, g, from);
		return;
	case RZ_IL_OP_LOADW:
		il_op_graph_loadw(op, g, from);
		return;
	case RZ_IL_OP_FLOAT:
		il_op_graph_float(op, g, from);
		return;
	case RZ_IL_OP_FBITS:
		il_op_graph_fbits(op, g, from);
		return;
	case RZ_IL_OP_IS_FINITE:
		il_op_graph_is_finite(op, g, from);
		return;
	case RZ_IL_OP_IS_NAN:
		il_op_graph_is_nan(op, g, from);
		return;
	case RZ_IL_OP_IS_INF:
		il_op_graph_is_inf(op, g, from);
		return;
	case RZ_IL_OP_IS_FZERO:
		il_op_graph_is_fzero(op, g, from);
		return;
	case RZ_IL_OP_IS_FNEG:
		il_op_graph_is_fneg(op, g, from);
		return;
	case RZ_IL_OP_IS_FPOS:
		il_op_graph_is_fpos(op, g, from);
		return;
	case RZ_IL_OP_FNEG:
		il_op_graph_fneg(op, g, from);
		return;
	case RZ_IL_OP_FABS:
		il_op_graph_fabs(op, g, from);
		return;
	case RZ_IL_OP_FCAST_INT:
		il_op_graph_fcast_int(op, g, from);
		return;
	case RZ_IL_OP_FCAST_SINT:
		il_op_graph_fcast_sint(op, g, from);
		return;
	case RZ_IL_OP_FCAST_FLOAT:
		il_op_graph_fcast_float(op, g, from);
		return;
	case RZ_IL_OP_FCAST_SFLOAT:
		il_op_graph_fcast_sfloat(op, g, from);
		return;
	case RZ_IL_OP_FCONVERT:
		il_op_graph_fconvert(op, g, from);
		return;
	case RZ_IL_OP_FREQUAL:
		il_op_graph_frequal(op, g, from);
		return;
	case RZ_IL_OP_FSUCC:
		il_op_graph_fsucc(op, g, from);
		return;
	case RZ_IL_OP_FPRED:
		il_op_graph_fpred(op, g, from);
		return;
	case RZ_IL_OP_FORDER:
		il_op_graph_forder(op, g, from);
		return;
	case RZ_IL_OP_FROUND:
		il_op_graph_fround(op, g, from);
		return;
	case RZ_IL_OP_FSQRT:
		il_op_graph_fsqrt(op, g, from);
		return;
	case RZ_IL_OP_FRSQRT:
		il_op_graph_frsqrt(op, g, from);
		return;
	case RZ_IL_OP_FADD:
		il_op_graph_fadd(op, g, from);
		return;
	case RZ_IL_OP_FSUB:
		il_op_graph_fsub(op, g, from);
		return;
	case RZ_IL_OP_FMUL:
		il_op_graph_fmul(op, g, from);
		return;
	case RZ_IL_OP_FDIV:
		il_op_graph_fdiv(op, g, from);
		return;
	case RZ_IL_OP_FMOD:
		il_op_graph_fmod(op, g, from);
		return;
	case RZ_IL_OP_FHYPOT:
		il_op_graph_fhypot(op, g, from);
		return;
	case RZ_IL_OP_FPOW:
		il_op_graph_fpow(op, g, from);
		return;
	case RZ_IL_OP_FMAD:
		il_op_graph_fmad(op, g, from);
		return;
	case RZ_IL_OP_FPOWN:
		il_op_graph_fpown(op, g, from);
		return;
	case RZ_IL_OP_FROOTN:
		il_op_graph_frootn(op, g, from);
		return;
	case RZ_IL_OP_FCOMPOUND:
		il_op_graph_fcompound(op, g, from);
		return;

	default:
		rz_warn_if_reached();
		il_op_graph_add_edge_f(g, from, "unk_%u", op->code);
		return;
	}
}

static void il_op_effect_graph_resolve(RzILOpEffect *op, RzGraph /*<RzGraphNodeInfo *>*/ *g, RzGraphNode *from) {
	if (!op) {
		il_op_graph_add_edge_s(g, from, "nop");
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_EMPTY:
		il_op_graph_empty(op, g, from);
		break;
	case RZ_IL_OP_STORE:
		il_op_graph_store(op, g, from);
		return;
	case RZ_IL_OP_STOREW:
		il_op_graph_storew(op, g, from);
		return;
	case RZ_IL_OP_NOP:
		il_op_graph_nop(op, g, from);
		return;
	case RZ_IL_OP_SET:
		il_op_graph_set(op, g, from);
		return;
	case RZ_IL_OP_JMP:
		il_op_graph_jmp(op, g, from);
		return;
	case RZ_IL_OP_GOTO:
		il_op_graph_goto(op, g, from);
		return;
	case RZ_IL_OP_SEQ:
		il_op_graph_seq(op, g, from);
		return;
	case RZ_IL_OP_BLK:
		il_op_graph_blk(op, g, from);
		return;
	case RZ_IL_OP_REPEAT:
		il_op_graph_repeat(op, g, from);
		return;
	case RZ_IL_OP_BRANCH:
		il_op_graph_branch(op, g, from);
		return;
	default:
		rz_warn_if_reached();
		il_op_graph_add_edge_f(g, from, "unk_%u", op->code);
		return;
	}
}

/**
 * \brief      Generates the graph representation of the IL pure statement
 * \param      op    IL pure statement
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_il_op_pure_graph(RZ_NONNULL RzILOpPure *op, RZ_NULLABLE const char *name) {
	rz_return_val_if_fail(op, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}

	RzGraphNode *to = graph_add_node_il(graph, name ? name : "pure");
	il_op_pure_graph_resolve(op, graph, to);
	return graph;
}

/**
 * \brief      Generates the graph representation of the IL effect statement
 * \param      op    IL effect statement
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_il_op_effect_graph(RZ_NONNULL RzILOpEffect *op, RZ_NULLABLE const char *name) {
	rz_return_val_if_fail(op, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}

	RzGraphNode *to = graph_add_node_il(graph, name ? name : "effect");
	il_op_effect_graph_resolve(op, graph, to);
	return graph;
}
