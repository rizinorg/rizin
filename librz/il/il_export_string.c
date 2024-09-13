// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file il_export_string.c
 * Outputs the IL statements & events in JSON or string format.
 * The string format of a statement is composed simply of s-expressions and looks like below:
 *    (store 0 (var ptr) (+ (load 0 (var ptr)) (bv 8 0x1)))
 * which can be deconstructed like below
 * (store
 *     0
 *     (var ptr)
 *     (+
 *         (load
 *             0
 *             (var ptr)
 *         )
 *         (bv 8 0x1)
 *     )
 * )
 *
 * The json format of an event looks like below:
 *    mem_write(addr: 0x0000000000000000, old: 0x00, new: 0x01)
 */

#include <rz_il/rz_il_vm.h>

#define PRETTY_PAD 2

static void il_op_pure_string_resolve(RzILOpPure *op, RzStrBuf *sb, int pad);
static void il_op_effect_string_resolve(RzILOpEffect *op, RzStrBuf *sb, int pad);

#define il_op_param_0(name) \
	do { \
		if (pad < 0) { \
			rz_strbuf_append(sb, name); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s" name, pad, ""); \
		} \
	} while (0)

#define il_op_param_1(name, opx, v0) \
	do { \
		if (pad < 0) { \
			rz_strbuf_append(sb, "(" name " "); \
			il_op_pure_string_resolve(opx.v0, sb, pad); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s(" name "\n", pad, ""); \
			il_op_pure_string_resolve(opx.v0, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, ")"); \
		} \
	} while (0)

#define il_op_param_2(name, opx, sort0, v0, sort1, v1) \
	do { \
		if (pad < 0) { \
			rz_strbuf_append(sb, "(" name " "); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s(" name "\n", pad, ""); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, ")"); \
		} \
	} while (0)

#define il_op_param_3(name, opx, sort0, v0, sort1, v1, sort2, v2) \
	do { \
		if (pad < 0) { \
			rz_strbuf_append(sb, "(" name " "); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort2##_string_resolve(opx.v2, sb, pad); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s(" name "\n", pad, ""); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort2##_string_resolve(opx.v2, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, ")"); \
		} \
	} while (0)

#define il_op_param_1_with_rmode(name, opx, v0, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		if (pad < 0) { \
			rz_strbuf_append(sb, "(" name " "); \
			rz_strbuf_append(sb, rmode_str); \
			rz_strbuf_append(sb, " "); \
			il_op_pure_string_resolve(opx.v0, sb, pad); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s(" name " %s\n", pad, "", rmode_str); \
			il_op_pure_string_resolve(opx.v0, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, ")"); \
		} \
	} while (0)

#define il_op_param_2_with_rmode(name, opx, sort0, v0, sort1, v1, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		if (pad < 0) { \
			rz_strbuf_append(sb, "(" name " "); \
			rz_strbuf_append(sb, rmode_str); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s(" name " %s\n", pad, "", rmode_str); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, ")"); \
		} \
	} while (0)

#define il_op_param_3_with_rmode(name, opx, sort0, v0, sort1, v1, sort2, v2, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		if (pad < 0) { \
			rz_strbuf_append(sb, "(" name " "); \
			rz_strbuf_append(sb, rmode_str); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad); \
			rz_strbuf_append(sb, " "); \
			il_op_##sort2##_string_resolve(opx.v2, sb, pad); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			rz_strbuf_appendf(sb, "%*.s(" name " %s\n", pad, "", rmode_str); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort0##_string_resolve(opx.v0, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort1##_string_resolve(opx.v1, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, "\n"); \
			il_op_##sort2##_string_resolve(opx.v2, sb, pad + PRETTY_PAD); \
			rz_strbuf_append(sb, ")"); \
		} \
	} while (0)

static void il_opdmp_var(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsVar *opx = &op->op.var;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(var %s)", opx->v);
	} else {
		rz_strbuf_appendf(sb, "%*.s(var %s)", pad, "", opx->v);
	}
}

static void il_opdmp_ite(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_3("ite", op->op.ite, pure, condition, pure, x, pure, y);
}

static void il_opdmp_let(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsLet *opx = &op->op.let;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(let %s ", opx->name);
		il_op_pure_string_resolve(opx->exp, sb, pad);
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->body, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(let %s\n", pad, "", opx->name);
		il_op_pure_string_resolve(opx->exp, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->body, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_bool_false(RzILOpPure *op, RzStrBuf *sb, int pad) {
	if (pad < 0) {
		rz_strbuf_append(sb, "false");
	} else {
		rz_strbuf_appendf(sb, "%*.sfalse", pad, "");
	}
}

static void il_opdmp_bool_true(RzILOpPure *op, RzStrBuf *sb, int pad) {
	if (pad < 0) {
		rz_strbuf_append(sb, "true");
	} else {
		rz_strbuf_appendf(sb, "%*.strue", pad, "");
	}
}

static void il_opdmp_bool_inv(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("!", op->op.boolinv, x);
}

static void il_opdmp_bool_and(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("&&", op->op.booland, pure, x, pure, y);
}

static void il_opdmp_bool_or(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("||", op->op.boolor, pure, x, pure, y);
}

static void il_opdmp_bool_xor(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("^^", op->op.boolxor, pure, x, pure, y);
}

static void il_opdmp_bitv(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsBv *opx = &op->op.bitv;
	char *num = rz_bv_as_hex_string(opx->value, false);
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(bv %u %s)", opx->value->len, num);
	} else {
		rz_strbuf_appendf(sb, "%*.s(bv %u %s)", pad, "", opx->value->len, num);
	}
	free(num);
}

static void il_opdmp_msb(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("msb", op->op.msb, bv);
}

static void il_opdmp_lsb(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("lsb", op->op.lsb, bv);
}

static void il_opdmp_is_zero(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_zero", op->op.lsb, bv);
}

static void il_opdmp_neg(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("~-", op->op.neg, bv);
}

static void il_opdmp_lognot(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("~", op->op.lognot, bv);
}

static void il_opdmp_add(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("+", op->op.add, pure, x, pure, y);
}

static void il_opdmp_sub(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("-", op->op.sub, pure, x, pure, y);
}

static void il_opdmp_mul(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("*", op->op.mul, pure, x, pure, y);
}

static void il_opdmp_div(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("div", op->op.div, pure, x, pure, y);
}

static void il_opdmp_sdiv(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("sdiv", op->op.sdiv, pure, x, pure, y);
}

static void il_opdmp_mod(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("mod", op->op.mod, pure, x, pure, y);
}

static void il_opdmp_smod(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("smod", op->op.smod, pure, x, pure, y);
}

static void il_opdmp_logand(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("&", op->op.logand, pure, x, pure, y);
}

static void il_opdmp_logor(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("|", op->op.logor, pure, x, pure, y);
}

static void il_opdmp_logxor(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("^", op->op.logxor, pure, x, pure, y);
}

static void il_opdmp_shiftr(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_3(">>", op->op.shiftr, pure, x, pure, y, pure, fill_bit);
}

static void il_opdmp_shiftl(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_3("<<", op->op.shiftl, pure, x, pure, y, pure, fill_bit);
}

static void il_opdmp_eq(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("==", op->op.ule, pure, x, pure, y);
}

static void il_opdmp_sle(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("sle", op->op.sle, pure, x, pure, y);
}

static void il_opdmp_ule(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("ule", op->op.ule, pure, x, pure, y);
}

static void il_opdmp_cast(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsCast *opx = &op->op.cast;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(cast %u ", opx->length);
		il_op_pure_string_resolve(opx->fill, sb, pad);
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->val, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(cast %u\n", pad, "", opx->length);
		il_op_pure_string_resolve(opx->fill, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->val, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_append(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("append", op->op.append, pure, high, pure, low);
}

static void il_opdmp_float(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFloat *opx = &op->op.float_;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(float %d ", opx->r);
		il_op_pure_string_resolve(opx->bv, sb, pad);
		rz_strbuf_append(sb, " )");
	} else {
		rz_strbuf_appendf(sb, "%*.s(float %d\n", pad, "", opx->r);
		il_op_pure_string_resolve(opx->bv, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, " )");
	}
}

static void il_opdmp_fbits(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("fbits", op->op.fbits, f);
}

static void il_opdmp_is_finite(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_finite", op->op.is_finite, f);
}

static void il_opdmp_is_nan(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_nan", op->op.is_nan, f);
}

static void il_opdmp_is_inf(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_inf", op->op.is_inf, f);
}

static void il_opdmp_is_fzero(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_fzero", op->op.is_fzero, f);
}

static void il_opdmp_is_fneg(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_fneg", op->op.is_fneg, f);
}

static void il_opdmp_is_fpos(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("is_fpos", op->op.is_fpos, f);
}

static void il_opdmp_fneg(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("fneg", op->op.fneg, f);
}

static void il_opdmp_fabs(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("fpos", op->op.fabs, f);
}

static void il_opdmp_fcast_int(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFCastint *opx = &op->op.fcast_int;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(fcast_int %u ", opx->length);
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->f, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(fcast_int %u ", pad, "", opx->length);
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->f, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_fcast_sint(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFCastsint *opx = &op->op.fcast_sint;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(fcast_sint %u ", opx->length);
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->f, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(fcast_sint %u ", pad, "", opx->length);
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->f, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_fcast_float(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFCastfloat *opx = &op->op.fcast_float;
	if (pad < 0) {
		rz_strbuf_append(sb, "(fcast_float ");
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx->format));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->bv, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(fcast_float ", pad, "");
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx->format));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->bv, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_fcast_sfloat(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFCastsfloat *opx = &op->op.fcast_sfloat;
	if (pad < 0) {
		rz_strbuf_append(sb, "(fcast_sfloat ");
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx->format));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->bv, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(fcast_sfloat ", pad, "");
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx->format));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->bv, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_fconvert(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFconvert *opx = &op->op.fconvert;
	if (pad < 0) {
		rz_strbuf_append(sb, "(fconvert ");
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx->format));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->f, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(fconvert ", pad, "");
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx->format));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->mode));
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->f, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_fround(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFround *opx = &op->op.fround;
	if (pad < 0) {
		rz_strbuf_append(sb, "(fround ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->rmode));
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->f, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(fround ", pad, "");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->rmode));
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->f, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_frequal(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsFrequal *opx = &op->op.frequal;
	if (pad < 0) {
		rz_strbuf_append(sb, "(frequal ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x));
		rz_strbuf_append(sb, " ");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x));
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(frequal\n%*.s", pad, "", pad + PRETTY_PAD, "");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x));
		rz_strbuf_appendf(sb, "\n%*.s", pad + PRETTY_PAD, "");
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x));
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_fsucc(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("fsucc", op->op.fsucc, f);
}
static void il_opdmp_fpred(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1("fpred", op->op.fpred, f);
}

static void il_opdmp_forder(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2("<.", op->op.forder, pure, x, pure, y);
}

static void il_opdmp_fsqrt(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1_with_rmode("fsqrt", op->op.fsqrt, f, rmode);
}

static void il_opdmp_frsqrt(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_1_with_rmode("frsqrt", op->op.frsqrt, f, rmode);
}

static void il_opdmp_fadd(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("+.", op->op.fadd, pure, x, pure, y, rmode);
}

static void il_opdmp_fsub(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("-.", op->op.fsub, pure, x, pure, y, rmode);
}

static void il_opdmp_fmul(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("*.", op->op.fmul, pure, x, pure, y, rmode);
}

static void il_opdmp_fdiv(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("/.", op->op.fdiv, pure, x, pure, y, rmode);
}

static void il_opdmp_fmod(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("%%.", op->op.fmod, pure, x, pure, y, rmode);
}

static void il_opdmp_fhypot(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("hypot", op->op.fhypot, pure, x, pure, y, rmode);
}

static void il_opdmp_fpow(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("pow", op->op.fpow, pure, x, pure, y, rmode);
}

static void il_opdmp_fmad(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_3_with_rmode("fmad", op->op.fmad, pure, x, pure, y, pure, z, rmode);
}

static void il_opdmp_fpown(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("fpown", op->op.fpown, pure, f, pure, n, rmode);
}

static void il_opdmp_frootn(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("frootn", op->op.frootn, pure, f, pure, n, rmode);
}

static void il_opdmp_fcompound(RzILOpPure *op, RzStrBuf *sb, int pad) {
	il_op_param_2_with_rmode("fcompound", op->op.fcompound, pure, f, pure, n, rmode);
}

static void il_opdmp_load(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsLoad *opx = &op->op.load;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(load %u ", (ut32)opx->mem);
		il_op_pure_string_resolve(opx->key, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(load %u\n", pad, "", (ut32)opx->mem);
		il_op_pure_string_resolve(opx->key, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_loadw(RzILOpPure *op, RzStrBuf *sb, int pad) {
	RzILOpArgsLoadW *opx = &op->op.loadw;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(loadw %u %u ", (ut32)opx->mem, (ut32)opx->n_bits);
		il_op_pure_string_resolve(opx->key, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(loadw %u %u\n", pad, "", (ut32)opx->mem, (ut32)opx->n_bits);
		il_op_pure_string_resolve(opx->key, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_store(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	RzILOpArgsStore *opx = &op->op.store;

	if (pad < 0) {
		rz_strbuf_appendf(sb, "(store %u ", (ut32)opx->mem);
		il_op_pure_string_resolve(opx->key, sb, pad);
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->value, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(store %u\n", pad, "", (ut32)opx->mem);
		il_op_pure_string_resolve(opx->key, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->value, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_storew(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	RzILOpArgsStore *opx = &op->op.store;

	if (pad < 0) {
		rz_strbuf_appendf(sb, "(storew %u ", (ut32)opx->mem);
		il_op_pure_string_resolve(opx->key, sb, pad);
		rz_strbuf_append(sb, " ");
		il_op_pure_string_resolve(opx->value, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(storew %u\n", pad, "", (ut32)opx->mem);
		il_op_pure_string_resolve(opx->key, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, "\n");
		il_op_pure_string_resolve(opx->value, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_nop(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	il_op_param_0("nop");
}

static void il_opdmp_empty(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	il_op_param_0("empty");
}

static void il_opdmp_set(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	RzILOpArgsSet *opx = &op->op.set;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(set %s ", opx->v);
		il_op_pure_string_resolve(opx->x, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(set %s\n", pad, "", opx->v);
		il_op_pure_string_resolve(opx->x, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_jmp(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	il_op_param_1("jmp", op->op.jmp, dst);
}

static void il_opdmp_goto(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	RzILOpArgsGoto *opx = &op->op.goto_;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(goto %s)", opx->lbl);
	} else {
		rz_strbuf_appendf(sb, "%*.s(goto %s)", pad, "", opx->lbl);
	}
}

static void il_opdmp_seq_inner(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	RzILOpArgsSeq *seq = &op->op.seq;
	if (seq->x->code == RZ_IL_OP_SEQ) {
		il_opdmp_seq_inner(seq->x, sb, pad);
	} else {
		il_op_effect_string_resolve(seq->x, sb, pad);
	}
	rz_strbuf_append(sb, (pad < 0 ? " " : "\n"));
	if (seq->y->code == RZ_IL_OP_SEQ) {
		il_opdmp_seq_inner(seq->y, sb, pad);
	} else {
		il_op_effect_string_resolve(seq->y, sb, pad);
	}
}

static void il_opdmp_seq(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	// print things like
	//     (seq (...) (seq (...) (...)))
	// as just
	//     (seq (...) (...) (...))
	if (pad < 0) {
		rz_strbuf_append(sb, "(seq ");
		il_opdmp_seq_inner(op, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(seq\n", pad, "");
		il_opdmp_seq_inner(op, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_blk(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	RzILOpArgsBlk *opx = &op->op.blk;
	if (pad < 0) {
		rz_strbuf_appendf(sb, "(blk %s ", opx->label);
		il_op_effect_string_resolve(opx->data_eff, sb, pad);
		rz_strbuf_append(sb, " ");
		il_op_effect_string_resolve(opx->ctrl_eff, sb, pad);
		rz_strbuf_append(sb, ")");
	} else {
		rz_strbuf_appendf(sb, "%*.s(blk %s\n", pad, "", opx->label);
		il_op_effect_string_resolve(opx->data_eff, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, "\n");
		il_op_effect_string_resolve(opx->ctrl_eff, sb, pad + PRETTY_PAD);
		rz_strbuf_append(sb, ")");
	}
}

static void il_opdmp_repeat(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	il_op_param_2("repeat", op->op.repeat, pure, condition, effect, data_eff);
}

static void il_opdmp_branch(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	il_op_param_3("branch", op->op.branch, pure, condition, effect, true_eff, effect, false_eff);
}

static void il_op_pure_string_resolve(RzILOpPure *op, RzStrBuf *sb, int pad) {
	if (!op) {
		if (pad < 0) {
			rz_strbuf_append(sb, "(null)");
		} else {
			rz_strbuf_appendf(sb, "%*.s(null)", pad, "");
		}
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_VAR:
		il_opdmp_var(op, sb, pad);
		return;
	case RZ_IL_OP_ITE:
		il_opdmp_ite(op, sb, pad);
		return;
	case RZ_IL_OP_LET:
		il_opdmp_let(op, sb, pad);
		return;
	case RZ_IL_OP_B0:
		il_opdmp_bool_false(op, sb, pad);
		return;
	case RZ_IL_OP_B1:
		il_opdmp_bool_true(op, sb, pad);
		return;
	case RZ_IL_OP_INV:
		il_opdmp_bool_inv(op, sb, pad);
		return;
	case RZ_IL_OP_AND:
		il_opdmp_bool_and(op, sb, pad);
		return;
	case RZ_IL_OP_OR:
		il_opdmp_bool_or(op, sb, pad);
		return;
	case RZ_IL_OP_XOR:
		il_opdmp_bool_xor(op, sb, pad);
		return;
	case RZ_IL_OP_BITV:
		il_opdmp_bitv(op, sb, pad);
		return;
	case RZ_IL_OP_MSB:
		il_opdmp_msb(op, sb, pad);
		return;
	case RZ_IL_OP_LSB:
		il_opdmp_lsb(op, sb, pad);
		return;
	case RZ_IL_OP_IS_ZERO:
		il_opdmp_is_zero(op, sb, pad);
		return;
	case RZ_IL_OP_NEG:
		il_opdmp_neg(op, sb, pad);
		return;
	case RZ_IL_OP_LOGNOT:
		il_opdmp_lognot(op, sb, pad);
		return;
	case RZ_IL_OP_ADD:
		il_opdmp_add(op, sb, pad);
		return;
	case RZ_IL_OP_SUB:
		il_opdmp_sub(op, sb, pad);
		return;
	case RZ_IL_OP_MUL:
		il_opdmp_mul(op, sb, pad);
		return;
	case RZ_IL_OP_DIV:
		il_opdmp_div(op, sb, pad);
		return;
	case RZ_IL_OP_SDIV:
		il_opdmp_sdiv(op, sb, pad);
		return;
	case RZ_IL_OP_MOD:
		il_opdmp_mod(op, sb, pad);
		return;
	case RZ_IL_OP_SMOD:
		il_opdmp_smod(op, sb, pad);
		return;
	case RZ_IL_OP_LOGAND:
		il_opdmp_logand(op, sb, pad);
		return;
	case RZ_IL_OP_LOGOR:
		il_opdmp_logor(op, sb, pad);
		return;
	case RZ_IL_OP_LOGXOR:
		il_opdmp_logxor(op, sb, pad);
		return;
	case RZ_IL_OP_SHIFTR:
		il_opdmp_shiftr(op, sb, pad);
		return;
	case RZ_IL_OP_SHIFTL:
		il_opdmp_shiftl(op, sb, pad);
		return;
	case RZ_IL_OP_EQ:
		il_opdmp_eq(op, sb, pad);
		return;
	case RZ_IL_OP_SLE:
		il_opdmp_sle(op, sb, pad);
		return;
	case RZ_IL_OP_ULE:
		il_opdmp_ule(op, sb, pad);
		return;
	case RZ_IL_OP_CAST:
		il_opdmp_cast(op, sb, pad);
		return;
	case RZ_IL_OP_APPEND:
		il_opdmp_append(op, sb, pad);
		return;
	case RZ_IL_OP_LOAD:
		il_opdmp_load(op, sb, pad);
		return;
	case RZ_IL_OP_LOADW:
		il_opdmp_loadw(op, sb, pad);
		return;
	case RZ_IL_OP_FLOAT:
		il_opdmp_float(op, sb, pad);
		return;
	case RZ_IL_OP_FBITS:
		il_opdmp_fbits(op, sb, pad);
		return;
	case RZ_IL_OP_IS_FINITE:
		il_opdmp_is_finite(op, sb, pad);
		return;
	case RZ_IL_OP_IS_NAN:
		il_opdmp_is_nan(op, sb, pad);
		return;
	case RZ_IL_OP_IS_INF:
		il_opdmp_is_inf(op, sb, pad);
		return;
	case RZ_IL_OP_IS_FZERO:
		il_opdmp_is_fzero(op, sb, pad);
		return;
	case RZ_IL_OP_IS_FNEG:
		il_opdmp_is_fneg(op, sb, pad);
		return;
	case RZ_IL_OP_IS_FPOS:
		il_opdmp_is_fpos(op, sb, pad);
		return;
	case RZ_IL_OP_FNEG:
		il_opdmp_fneg(op, sb, pad);
		return;
	case RZ_IL_OP_FABS:
		il_opdmp_fabs(op, sb, pad);
		return;
	case RZ_IL_OP_FCAST_INT:
		il_opdmp_fcast_int(op, sb, pad);
		return;
	case RZ_IL_OP_FCAST_SINT:
		il_opdmp_fcast_sint(op, sb, pad);
		return;
	case RZ_IL_OP_FCAST_FLOAT:
		il_opdmp_fcast_float(op, sb, pad);
		return;
	case RZ_IL_OP_FCAST_SFLOAT:
		il_opdmp_fcast_sfloat(op, sb, pad);
		return;
	case RZ_IL_OP_FCONVERT:
		il_opdmp_fconvert(op, sb, pad);
		return;
	case RZ_IL_OP_FREQUAL:
		il_opdmp_frequal(op, sb, pad);
		return;
	case RZ_IL_OP_FSUCC:
		il_opdmp_fsucc(op, sb, pad);
		return;
	case RZ_IL_OP_FPRED:
		il_opdmp_fpred(op, sb, pad);
		return;
	case RZ_IL_OP_FORDER:
		il_opdmp_forder(op, sb, pad);
		return;
	case RZ_IL_OP_FROUND:
		il_opdmp_fround(op, sb, pad);
		return;
	case RZ_IL_OP_FSQRT:
		il_opdmp_fsqrt(op, sb, pad);
		return;
	case RZ_IL_OP_FRSQRT:
		il_opdmp_frsqrt(op, sb, pad);
		return;
	case RZ_IL_OP_FADD:
		il_opdmp_fadd(op, sb, pad);
		return;
	case RZ_IL_OP_FSUB:
		il_opdmp_fsub(op, sb, pad);
		return;
	case RZ_IL_OP_FMUL:
		il_opdmp_fmul(op, sb, pad);
		return;
	case RZ_IL_OP_FDIV:
		il_opdmp_fdiv(op, sb, pad);
		return;
	case RZ_IL_OP_FMOD:
		il_opdmp_fmod(op, sb, pad);
		return;
	case RZ_IL_OP_FHYPOT:
		il_opdmp_fhypot(op, sb, pad);
		return;
	case RZ_IL_OP_FPOW:
		il_opdmp_fpow(op, sb, pad);
		return;
	case RZ_IL_OP_FMAD:
		il_opdmp_fmad(op, sb, pad);
		return;
	case RZ_IL_OP_FPOWN:
		il_opdmp_fpown(op, sb, pad);
		return;
	case RZ_IL_OP_FROOTN:
		il_opdmp_frootn(op, sb, pad);
		return;
	case RZ_IL_OP_FCOMPOUND:
		il_opdmp_fcompound(op, sb, pad);
		return;

	default:
		rz_warn_if_reached();
		if (pad < 0) {
			rz_strbuf_appendf(sb, "(unk_%u)", op->code);
		} else {
			rz_strbuf_appendf(sb, "%*.s(unk_%u)", pad, "", op->code);
		}
		return;
	}
}

static void il_op_effect_string_resolve(RzILOpEffect *op, RzStrBuf *sb, int pad) {
	if (!op) {
		if (pad < 0) {
			rz_strbuf_append(sb, "nop");
		} else {
			rz_strbuf_appendf(sb, "%*.snop", pad, "");
		}
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_EMPTY:
		il_opdmp_empty(op, sb, pad);
		break;
	case RZ_IL_OP_STORE:
		il_opdmp_store(op, sb, pad);
		return;
	case RZ_IL_OP_STOREW:
		il_opdmp_storew(op, sb, pad);
		return;
	case RZ_IL_OP_NOP:
		il_opdmp_nop(op, sb, pad);
		return;
	case RZ_IL_OP_SET:
		il_opdmp_set(op, sb, pad);
		return;
	case RZ_IL_OP_JMP:
		il_opdmp_jmp(op, sb, pad);
		return;
	case RZ_IL_OP_GOTO:
		il_opdmp_goto(op, sb, pad);
		return;
	case RZ_IL_OP_SEQ:
		il_opdmp_seq(op, sb, pad);
		return;
	case RZ_IL_OP_BLK:
		il_opdmp_blk(op, sb, pad);
		return;
	case RZ_IL_OP_REPEAT:
		il_opdmp_repeat(op, sb, pad);
		return;
	case RZ_IL_OP_BRANCH:
		il_opdmp_branch(op, sb, pad);
		return;
	default:
		rz_warn_if_reached();
		if (pad < 0) {
			rz_strbuf_appendf(sb, "unk_%u", op->code);
		} else {
			rz_strbuf_appendf(sb, "%*.sunk_%u", pad, "", op->code);
		}
		return;
	}
}

/**
 * Generates the string representation of the IL statement
 * \param op     IL pure statement
 * \param sb     RzStrBuf*, a pointer to the string buffer
 * \param pretty When true, pretty prints in the string buffer
 */
RZ_API void rz_il_op_pure_stringify(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzStrBuf *sb, bool pretty) {
	rz_return_if_fail(op && sb);
	il_op_pure_string_resolve(op, sb, pretty ? 0 : -1);
}

/**
 * Generates the string representation of the IL statement
 * \param op     IL effect statement
 * \param sb     RzStrBuf*, a pointer to the string buffer
 * \param pretty When true, pretty prints in the string buffer
 */
RZ_API void rz_il_op_effect_stringify(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL RzStrBuf *sb, bool pretty) {
	rz_return_if_fail(op && sb);
	il_op_effect_string_resolve(op, sb, pretty ? 0 : -1);
}

/**
 * Create a readable string representation of \p val
 */
RZ_API char *rz_il_value_stringify(RZ_NONNULL const RzILVal *val) {
	rz_return_val_if_fail(val, NULL);
	if (val->type == RZ_IL_TYPE_PURE_FLOAT) {
		return rz_float_as_string(val->data.f);
	}
	RzBitVector *bv = rz_il_value_to_bv(val);
	if (!bv) {
		return NULL;
	}
	char *r = rz_bv_as_hex_string(bv, false);
	rz_bv_free(bv);
	return r;
}

/**
 * Create a readable string representation of \p evt
 */
RZ_API void rz_il_event_stringify(RZ_NONNULL const RzILEvent *evt, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(evt && sb);
	char *tmp0 = NULL, *tmp1 = NULL, *tmp2 = NULL;

	switch (evt->type) {
	case RZ_IL_EVENT_EXCEPTION:
		rz_strbuf_appendf(sb, "exception(%s)", evt->data.exception);
		break;
	case RZ_IL_EVENT_PC_WRITE:
		tmp0 = rz_bv_as_hex_string(evt->data.pc_write.old_pc, false);
		tmp1 = rz_bv_as_hex_string(evt->data.pc_write.new_pc, false);
		rz_strbuf_appendf(sb, "pc_write(old: %s, new: %s)", tmp0, tmp1);
		break;
	case RZ_IL_EVENT_MEM_READ:
		tmp0 = rz_bv_as_hex_string(evt->data.mem_read.address, false);
		tmp1 = evt->data.mem_read.value ? rz_bv_as_hex_string(evt->data.mem_read.value, false) : NULL;
		rz_strbuf_appendf(sb, "mem_read(addr: %s, value: %s)", tmp0, tmp1 ? tmp1 : "uninitialized memory");
		break;
	case RZ_IL_EVENT_VAR_READ:
		tmp1 = rz_il_value_stringify(evt->data.var_read.value);
		rz_strbuf_appendf(sb, "var_read(name: %s, value: %s)", evt->data.var_write.variable, tmp1 ? tmp1 : "uninitialized variable");
		break;
	case RZ_IL_EVENT_MEM_WRITE:
		tmp0 = rz_bv_as_hex_string(evt->data.mem_write.address, false);
		tmp1 = evt->data.mem_write.old_value ? rz_bv_as_hex_string(evt->data.mem_write.old_value, false) : NULL;
		tmp2 = rz_bv_as_hex_string(evt->data.mem_write.new_value, false);
		rz_strbuf_appendf(sb, "mem_write(addr: %s, old: %s, new: %s)", tmp0, tmp1 ? tmp1 : "uninitialized memory", tmp2);
		break;
	case RZ_IL_EVENT_VAR_WRITE:
		tmp1 = rz_il_value_stringify(evt->data.var_write.old_value);
		tmp2 = rz_il_value_stringify(evt->data.var_write.new_value);
		rz_strbuf_appendf(sb, "var_write(name: %s, old: %s, new: %s)", evt->data.var_write.variable, tmp1 ? tmp1 : "uninitialized variable", tmp2);
		break;
	default:
		rz_warn_if_reached();
		rz_strbuf_append(sb, "unknown(?)");
		break;
	}

	free(tmp0);
	free(tmp1);
	free(tmp2);
}

/**
 * Get a readable representation of \p code
 * \return constant string, must not be freed
 */
RZ_API RZ_NONNULL const char *rz_il_op_pure_code_stringify(RzILOpPureCode code) {
	switch (code) {
	case RZ_IL_OP_VAR:
		return "var";
	case RZ_IL_OP_ITE:
		return "ite";
	case RZ_IL_OP_LET:
		return "let";
	case RZ_IL_OP_B0:
		return "b0";
	case RZ_IL_OP_B1:
		return "b1";
	case RZ_IL_OP_INV:
		return "inv";
	case RZ_IL_OP_AND:
		return "and";
	case RZ_IL_OP_OR:
		return "or";
	case RZ_IL_OP_XOR:
		return "xor";
	case RZ_IL_OP_BITV:
		return "bitv";
	case RZ_IL_OP_MSB:
		return "msb";
	case RZ_IL_OP_LSB:
		return "lsb";
	case RZ_IL_OP_IS_ZERO:
		return "is_zero";
	case RZ_IL_OP_NEG:
		return "neg";
	case RZ_IL_OP_LOGNOT:
		return "lognot";
	case RZ_IL_OP_ADD:
		return "add";
	case RZ_IL_OP_SUB:
		return "sub";
	case RZ_IL_OP_MUL:
		return "mul";
	case RZ_IL_OP_DIV:
		return "div";
	case RZ_IL_OP_SDIV:
		return "sdiv";
	case RZ_IL_OP_MOD:
		return "mod";
	case RZ_IL_OP_SMOD:
		return "smod";
	case RZ_IL_OP_LOGAND:
		return "logand";
	case RZ_IL_OP_LOGOR:
		return "logor";
	case RZ_IL_OP_LOGXOR:
		return "logxor";
	case RZ_IL_OP_SHIFTR:
		return "shiftr";
	case RZ_IL_OP_SHIFTL:
		return "shiftl";
	case RZ_IL_OP_EQ:
		return "eq";
	case RZ_IL_OP_SLE:
		return "sle";
	case RZ_IL_OP_ULE:
		return "ule";
	case RZ_IL_OP_CAST:
		return "cast";
	case RZ_IL_OP_APPEND:
		return "append";
	case RZ_IL_OP_LOAD:
		return "load";
	case RZ_IL_OP_LOADW:
		return "loadw";

	case RZ_IL_OP_FLOAT:
		return "float";
	case RZ_IL_OP_FBITS:
		return "fbits";
	case RZ_IL_OP_IS_FINITE:
		return "is_finite";
	case RZ_IL_OP_IS_NAN:
		return "is_nan";
	case RZ_IL_OP_IS_INF:
		return "is_inf";
	case RZ_IL_OP_IS_FZERO:
		return "is_fzero";
	case RZ_IL_OP_IS_FNEG:
		return "is_fneg";
	case RZ_IL_OP_IS_FPOS:
		return "is_fpos";
	case RZ_IL_OP_FNEG:
		return "fneg";
	case RZ_IL_OP_FABS:
		return "fabs";
	case RZ_IL_OP_FCAST_INT:
		return "fcast_int";
	case RZ_IL_OP_FCAST_SINT:
		return "fcast_sint";
	case RZ_IL_OP_FCAST_FLOAT:
		return "fcast_float";
	case RZ_IL_OP_FCAST_SFLOAT:
		return "fcast_sfloat";
	case RZ_IL_OP_FCONVERT:
		return "fconvert";
	case RZ_IL_OP_FREQUAL:
		return "frequal";
	case RZ_IL_OP_FSUCC:
		return "fsucc";
	case RZ_IL_OP_FPRED:
		return "fpred";
	case RZ_IL_OP_FORDER:
		return "forder";
	case RZ_IL_OP_FROUND:
		return "fround";
	case RZ_IL_OP_FSQRT:
		return "fsqrt";
	case RZ_IL_OP_FRSQRT:
		return "frsqrt";
	case RZ_IL_OP_FADD:
		return "fadd";
	case RZ_IL_OP_FSUB:
		return "fsub";
	case RZ_IL_OP_FMUL:
		return "fmul";
	case RZ_IL_OP_FDIV:
		return "fdiv";
	case RZ_IL_OP_FMOD:
		return "fmod";
	case RZ_IL_OP_FHYPOT:
		return "fhypot";
	case RZ_IL_OP_FPOW:
		return "fpow";
	case RZ_IL_OP_FMAD:
		return "fmad";
	case RZ_IL_OP_FROOTN:
		return "frootn";
	case RZ_IL_OP_FPOWN:
		return "fpown";
	case RZ_IL_OP_FCOMPOUND:
		return "fcompound";

	case RZ_IL_OP_PURE_MAX:
		break;
	}
	return "invalid";
}

/**
 * Get a readable representation of \p sort
 * \return dynamically allocated string, to be freed by the caller
 */
RZ_API RZ_OWN char *rz_il_sort_pure_stringify(RzILSortPure sort) {
	switch (sort.type) {
	case RZ_IL_TYPE_PURE_BITVECTOR:
		return rz_str_newf("bitvector:%u", (unsigned int)sort.props.bv.length);
	case RZ_IL_TYPE_PURE_BOOL:
		return rz_str_dup("bool");
	case RZ_IL_TYPE_PURE_FLOAT:
		return rz_str_newf("float:%u", (unsigned int)sort.props.f.format);
	}
	return rz_str_dup("invalid");
}
