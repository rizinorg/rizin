// SPDX-FileCopyrightText: 2026 Ehab-24 <ehabs1775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>

static bool il_op_pure_string_resolve(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb);
static bool il_op_effect_string_resolve(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb);

static const char *const subscript_digits[10] = { "₀", "₁", "₂", "₃", "₄", "₅", "₆", "₇", "₈", "₉" };

#define UCD_ITE          "↠"
#define UCD_LET          "="
#define UCD_BOOL_FALSE   "⊥"
#define UCD_BOOL_TRUE    "⊤"
#define UCD_BOOL_INV     "¬"
#define UCD_BOOL_AND     "∧"
#define UCD_BOOL_OR      "∨"
#define UCD_BOOL_XOR     "⊻"
#define UCD_MSB          "↑"
#define UCD_LSB          "↓"
#define UCD_IS_ZERO      "≡ 0"
#define UCD_NEG          "−"
#define UCD_LOGNOT       "~"
#define UCD_ADD          "+"
#define UCD_SUB          "-"
#define UCD_MUL          "*"
#define UCD_DIV          "/"
#define UCD_SDIV         "/⁺"
#define UCD_MOD          "%"
#define UCD_SMOD         "%⁺"
#define UCD_LOGAND       "&"
#define UCD_LOGOR        "|"
#define UCD_LOGXOR       "⊕"
#define UCD_SHIFTR       "≫"
#define UCD_SHIFTL       "≪"
#define UCD_EQ           "≡"
#define UCD_SLE          "≦⁺"
#define UCD_ULE          "≦"
#define UCD_CAST         "≈"
#define UCD_APPEND       "⊚"
#define UCD_FBITS        "ꜰʙ "
#define UCD_IS_FINITE    "≢ ∞"
#define UCD_IS_NAN       "≡ ɴаɴ"
#define UCD_IS_INF       "≡ ∞"
#define UCD_IS_FZERO     "≡ 0"
#define UCD_IS_FNEG      "< 0"
#define UCD_IS_FPOS      "> 0"
#define UCD_FNEG         "−"
#define UCD_FABS         "|"
#define UCD_FCAST_INT    "ꜰ≈ɪ"
#define UCD_FCAST_SINT   "ꜰ≈ɪ⁺"
#define UCD_FCAST_FLOAT  "ꜰ≈ꜰ"
#define UCD_FCAST_SFLOAT "ꜰ≈ꜰ⁺"
#define UCD_FCONVERT     "≅"
#define UCD_FSQRT        "²√"
#define UCD_FRSQRT       "¹/√"
#define UCD_FROUND       "⭂"
#define UCD_FREQUAL      "≡"
#define UCD_FSUCC        "⌊"
#define UCD_FPRED        "⌋"
#define UCD_FORDER       "≷"
#define UCD_FEXCEPT      "ᴇ"
#define UCD_FADD         "+"
#define UCD_FSUB         "-"
#define UCD_FMUL         "*"
#define UCD_FDIV         "/"
#define UCD_FMOD         "%"
#define UCD_FHYPOT       "∠"
#define UCD_FPOW         "˰"
#define UCD_FPOWN        "˰ⁿ"
#define UCD_FROOTN       "ⁿ√"
#define UCD_FCOMPOUND    "∪"
#define UCD_LOAD         "ʟᴅ"
#define UCD_LOADW        "ʟᴅ"
#define UCD_STORE        "ꜱᴛ"
#define UCD_STOREW       "ꜱᴛ"
#define UCD_NOP          "ɴᴏᴘ"
#define UCD_EMPTY        "{}"
#define UCD_SET          "←"
#define UCD_JMP          "↷ "
#define UCD_GOTO         "@ "
#define UCD_REPEAT       "⟳"
#define UCD_BRANCH       "⅄"
#define UCD_UNK          "?"

#define return_val_if_fail(x, y) \
	if (!(x)) { \
		return y; \
	}
#define return_false_if_fail(x) return_val_if_fail(x, false)

#define goto_if_fail(x, y) \
	if (!(x)) { \
		goto y; \
	}

#define CASE_IL_OP(x, y) \
	case RZ_IL_OP_##x: \
		return il_opdmp_##y(ctx, op, sb);

#define il_op_param_0(sym) \
	return rz_strbuf_append(sb, sym);

#define il_op_param_1(sym, opx, sort0, v0) \
	do { \
		return_false_if_fail(rz_strbuf_append(sb, sym)); \
		return il_op_##sort0##_string_resolve(ctx, opx.v0, sb); \
	} while (0)

#define il_op_param_1_rtl(sym, opx, sort0, v0) \
	do { \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return rz_strbuf_append(sb, " " sym); \
	} while (0)

#define il_op_param_2(sym, opx, sort0, v0, sort1, v1) \
	do { \
		return_false_if_fail(rz_strbuf_append(sb, "(")); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return_false_if_fail(rz_strbuf_append(sb, " " sym " ")); \
		return_false_if_fail(il_op_##sort1##_string_resolve(ctx, opx.v1, sb)); \
		return rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_3(sym, opx, sort0, v0, sort1, v1, sort2, v2) \
	do { \
		return_false_if_fail(rz_strbuf_append(sb, "(")); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return_false_if_fail(rz_strbuf_append(sb, " " sym " ")); \
		return_false_if_fail(il_op_##sort1##_string_resolve(ctx, opx.v1, sb)); \
		return_false_if_fail(rz_strbuf_append(sb, " ")); \
		return_false_if_fail(il_op_##sort2##_string_resolve(ctx, opx.v2, sb)); \
		return rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_rmode(sym, opx, v0, sort0, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		return_false_if_fail(rmode_str); \
		return_false_if_fail(rz_strbuf_appendf(sb, "(%s " sym " ", rmode_str)); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_fexcept(sym, opx, v0, sort0, ve) \
	do { \
		const char *str = rz_il_float_stringify_exception(opx.ve); \
		return_false_if_fail(str); \
		return_false_if_fail(rz_strbuf_appendf(sb, "(%s " sym " ", str)); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_mode_length(sym, opx, v0, sort0, m, l) \
	do { \
		return_false_if_fail(rz_strbuf_appendf(sb, "(")); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return_false_if_fail(rz_strbuf_append(sb, " " sym)); \
		return_false_if_fail(append_subscript(sb, opx.l)); \
		return_false_if_fail(rz_strbuf_append(sb, " ")); \
		return_false_if_fail(rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx.m))); \
		return rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_mode_format(sym, opx, v0, sort0, m, f) \
	do { \
		return_false_if_fail(rz_strbuf_appendf(sb, "(")); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx->v0, sb)); \
		return_false_if_fail(rz_strbuf_appendf(sb, " %s ", sym)); \
		return_false_if_fail(rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->m))); \
		return rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_2_with_rmode(sym, opx, v0, sort0, v1, sort1, vr) \
	do { \
		return_false_if_fail(rz_strbuf_appendf(sb, "(%s ", rz_il_float_stringify_rmode(opx.vr))); \
		return_false_if_fail(il_op_##sort0##_string_resolve(ctx, opx.v0, sb)); \
		return_false_if_fail(rz_strbuf_append(sb, " " sym " ")); \
		return_false_if_fail(il_op_##sort1##_string_resolve(ctx, opx.v1, sb)); \
		return rz_strbuf_append(sb, ")"); \
	} while (0);

#define sym_with_float_format(x, y) \
	(x) == RZ_FLOAT_IEEE754_BIN_32 ? y "₃₂" : (x) == RZ_FLOAT_IEEE754_BIN_64 ? y "₆₄" \
		: (x) == RZ_FLOAT_IEEE754_BIN_80                                 ? y "₈₀" \
		: (x) == RZ_FLOAT_IEEE754_BIN_128                                ? y "₁₂₈" \
		: (x) == RZ_FLOAT_IEEE754_BIN_16                                 ? y "₁₆" \
		: (x) == RZ_FLOAT_IEEE754_DEC_64                                 ? y "ᵈ₆₄" \
		: (x) == RZ_FLOAT_IEEE754_DEC_128                                ? y "ᵈ₁₂₈" \
										 : ""

static bool append_ut32_glyph(RzStrBuf *sb, ut32 n, const char *const digits[10]) {
	char buffer[32] = { 0 };
	if (rz_strf(buffer, "%u", n) == NULL) {
		return false;
	}

	/* Each unicode superscript/subscript character is at most 3 bytes */
	const size_t len = strlen(buffer);
	for (size_t i = 0; i < len; ++i) {
		int digit = buffer[i] - '0';
		if (!rz_strbuf_append(sb, digits[digit])) {
			return false;
		}
	}
	return true;
}

static bool append_subscript(RzStrBuf *sb, ut32 n) {
	return append_ut32_glyph(sb, n, subscript_digits);
}

static bool il_opdmp_var(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsVar *opx = &op->op.var;
	return rz_strbuf_appendf(sb, "%s", opx->v);
}

static bool il_opdmp_ite(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3(UCD_ITE, op->op.ite, pure, condition, pure, x, pure, y);
}

static bool il_opdmp_let(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsLet *opx = &op->op.let;
	return_false_if_fail(rz_strbuf_appendf(sb, "(%s " UCD_LET " ", opx->name));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->exp, sb));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->body, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_bool_false(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	return rz_strbuf_append(sb, UCD_BOOL_FALSE);
}

static bool il_opdmp_bool_true(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	return rz_strbuf_append(sb, UCD_BOOL_TRUE);
}

static bool il_opdmp_bool_inv(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_BOOL_INV, op->op.boolinv, pure, x);
}

static bool il_opdmp_bool_and(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_BOOL_AND, op->op.booland, pure, x, pure, y);
}

static bool il_opdmp_bool_or(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_BOOL_OR, op->op.boolor, pure, x, pure, y);
}

static bool il_opdmp_bool_xor(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_BOOL_XOR, op->op.boolxor, pure, x, pure, y);
}

static bool il_opdmp_bitv_float(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb, const char *sym) {
	const RzILOpArgsBv *opx = &op->op.bitv;
	char *num = rz_bv_as_hex_string(opx->value, false);
	return_false_if_fail(num);
	goto_if_fail(rz_strbuf_appendf(sb, "%s", num), fini);
	goto_if_fail(rz_strbuf_appendf(sb, "%s", sym), fini);
	free(num);
	return true;

fini:
	free(num);
	return false;
}

static bool il_opdmp_bitv(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsBv *opx = &op->op.bitv;
	char *num = rz_bv_as_hex_string(opx->value, false);
	return_false_if_fail(num);
	goto_if_fail(rz_strbuf_appendf(sb, "%s", num), fini);
	goto_if_fail(append_subscript(sb, opx->value->len), fini);
	free(num);
	return true;

fini:
	free(num);
	return false;
}

static bool il_opdmp_msb(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_MSB, op->op.msb, pure, bv);
}

static bool il_opdmp_lsb(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_LSB, op->op.lsb, pure, bv);
}

static bool il_opdmp_is_zero(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_ZERO, op->op.is_zero, pure, bv);
}

static bool il_opdmp_neg(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_NEG, op->op.neg, pure, bv);
}

static bool il_opdmp_lognot(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_LOGNOT, op->op.lognot, pure, bv);
}

static bool il_opdmp_add(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_ADD, op->op.add, pure, x, pure, y);
}

static bool il_opdmp_sub(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SUB, op->op.sub, pure, x, pure, y);
}

static bool il_opdmp_mul(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_MUL, op->op.mul, pure, x, pure, y);
}

static bool il_opdmp_div(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_DIV, op->op.div, pure, x, pure, y);
}

static bool il_opdmp_sdiv(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SDIV, op->op.sdiv, pure, x, pure, y);
}

static bool il_opdmp_mod(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_MOD, op->op.mod, pure, x, pure, y);
}

static bool il_opdmp_smod(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SMOD, op->op.smod, pure, x, pure, y);
}

static bool il_opdmp_logand(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_LOGAND, op->op.logand, pure, x, pure, y);
}

static bool il_opdmp_logor(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_LOGOR, op->op.logor, pure, x, pure, y);
}

static bool il_opdmp_logxor(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_LOGXOR, op->op.logxor, pure, x, pure, y);
}

static bool il_opdmp_shiftr(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3(UCD_SHIFTR, op->op.shiftr, pure, x, pure, y, pure, fill_bit);
}

static bool il_opdmp_shiftl(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3(UCD_SHIFTL, op->op.shiftl, pure, x, pure, y, pure, fill_bit);
}

static bool il_opdmp_eq(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_EQ, op->op.eq, pure, x, pure, y);
}

static bool il_opdmp_sle(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SLE, op->op.sle, pure, x, pure, y);
}

static bool il_opdmp_ule(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_ULE, op->op.ule, pure, x, pure, y);
}

static bool il_opdmp_cast(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsCast *opx = &op->op.cast;
	return_false_if_fail(rz_strbuf_append(sb, "("));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->val, sb));
	return_false_if_fail(rz_strbuf_append(sb, " " UCD_CAST));
	return_false_if_fail(append_subscript(sb, opx->length));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->fill, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_append(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_APPEND, op->op.append, pure, high, pure, low);
}

static bool il_opdmp_float(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFloat *opx = &op->op.float_;
	switch (opx->bv->code) {
	default:
		return il_op_pure_string_resolve(ctx, opx->bv, sb);
	case RZ_IL_OP_BITV:
		return il_opdmp_bitv_float(ctx, opx->bv, sb, sym_with_float_format(opx->r, ".f"));
	}
}

static bool il_opdmp_fbits(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_FBITS, op->op.fbits, pure, f);
}

static bool il_opdmp_is_finite(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FINITE, op->op.is_finite, pure, f);
}

static bool il_opdmp_is_nan(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_NAN, op->op.is_nan, pure, f);
}

static bool il_opdmp_is_inf(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_INF, op->op.is_inf, pure, f);
}

static bool il_opdmp_is_fzero(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FZERO, op->op.is_fzero, pure, f);
}

static bool il_opdmp_is_fneg(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FNEG, op->op.is_fneg, pure, f);
}

static bool il_opdmp_is_fpos(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FPOS, op->op.is_fpos, pure, f);
}

static bool il_opdmp_fneg(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_FNEG, op->op.fneg, pure, f);
}

static bool il_opdmp_fabs(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	return_false_if_fail(rz_strbuf_append(sb, UCD_FABS));
	return_false_if_fail(il_op_pure_string_resolve(ctx, op->op.fabs.f, sb));
	return rz_strbuf_append(sb, UCD_FABS);
}

static bool il_opdmp_fcast_int(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_length(UCD_FCAST_INT, op->op.fcast_int, f, pure, mode, length);
}

static bool il_opdmp_fcast_sint(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_length(UCD_FCAST_SINT, op->op.fcast_sint, f, pure, mode, length);
}

static bool il_opdmp_fcast_float(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFCastfloat *opx = &op->op.fcast_float;
	const char *sym = sym_with_float_format(opx->format, UCD_FCAST_FLOAT);
	il_op_param_1_with_mode_format(sym, opx, bv, pure, mode, format);
}

static bool il_opdmp_fcast_sfloat(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFCastsfloat *opx = &op->op.fcast_sfloat;
	const char *sym = sym_with_float_format(opx->format, UCD_FCAST_SFLOAT);
	il_op_param_1_with_mode_format(sym, opx, bv, pure, mode, format);
}

static bool il_opdmp_fconvert(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFconvert *opx = &op->op.fconvert;
	const char *sym = sym_with_float_format(opx->format, UCD_FCONVERT);
	il_op_param_1_with_mode_format(sym, opx, f, pure, mode, format);
}

static bool il_opdmp_fsqrt(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_rmode(UCD_FSQRT, op->op.fsqrt, f, pure, rmode);
}

static bool il_opdmp_frsqrt(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_rmode(UCD_FRSQRT, op->op.frsqrt, f, pure, rmode);
}

static bool il_opdmp_fround(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_rmode(UCD_FROUND, op->op.fround, f, pure, rmode);
}

static bool il_opdmp_frequal(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFrequal *opx = &op->op.frequal;
	return_false_if_fail(rz_strbuf_append(sb, "("));
	return_false_if_fail(rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x)));
	return_false_if_fail(rz_strbuf_append(sb, " " UCD_FREQUAL " "));
	return_false_if_fail(rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->y)));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_fsucc(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	return_false_if_fail(rz_strbuf_append(sb, UCD_FSUCC "("));
	return_false_if_fail(il_op_pure_string_resolve(ctx, op->op.fsucc.f, sb));
	return rz_strbuf_append(sb, ")");
}
static bool il_opdmp_fpred(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	return_false_if_fail(rz_strbuf_append(sb, UCD_FPRED "("));
	return_false_if_fail(il_op_pure_string_resolve(ctx, op->op.fpred.f, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_forder(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_FORDER, op->op.forder, pure, x, pure, y);
}

static bool il_opdmp_fexcept(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_fexcept(UCD_FEXCEPT, op->op.fexcept, x, pure, e);
}

static bool il_opdmp_fadd(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FADD, op->op.fadd, x, pure, y, pure, rmode);
}

static bool il_opdmp_fsub(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FSUB, op->op.fsub, x, pure, y, pure, rmode);
}

static bool il_opdmp_fmul(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FMUL, op->op.fmul, x, pure, y, pure, rmode);
}

static bool il_opdmp_fdiv(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FDIV, op->op.fdiv, x, pure, y, pure, rmode);
}

static bool il_opdmp_fmod(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FMOD, op->op.fmod, x, pure, y, pure, rmode);
}

static bool il_opdmp_fhypot(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FHYPOT, op->op.fhypot, x, pure, y, pure, rmode);
}

static bool il_opdmp_fpow(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FPOW, op->op.fpow, x, pure, y, pure, rmode);
}

static bool il_opdmp_fmad(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFmad *opx = &op->op.fmad;
	const char *rmode_str = rz_il_float_stringify_rmode(opx->rmode);
	return_false_if_fail(rmode_str);
	return_false_if_fail(rz_strbuf_appendf(sb, "(%s ", rmode_str));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->x, sb));
	return_false_if_fail(rz_strbuf_append(sb, " " UCD_FMUL " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->y, sb));
	return_false_if_fail(rz_strbuf_append(sb, " " UCD_FADD " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->z, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_fpown(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FPOWN, op->op.fpown, f, pure, n, pure, rmode);
}

static bool il_opdmp_frootn(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FROOTN, op->op.frootn, n, pure, f, pure, rmode);
}

static bool il_opdmp_fcompound(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FCOMPOUND, op->op.fcompound, f, pure, n, pure, rmode);
}

static bool il_opdmp_load(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsLoad *opx = &op->op.load;
	return_false_if_fail(rz_strbuf_append(sb, "(" UCD_LOAD));
	return_false_if_fail(append_subscript(sb, opx->mem));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->key, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_loadw(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsLoadW *opx = &op->op.loadw;
	return_false_if_fail(rz_strbuf_append(sb, "(" UCD_LOADW));
	return_false_if_fail(append_subscript(sb, opx->mem));
	return_false_if_fail(rz_strbuf_appendf(sb, " %u ", opx->n_bits));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->key, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_store(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsStore *opx = &op->op.store;
	return_false_if_fail(rz_strbuf_append(sb, "(" UCD_STORE));
	return_false_if_fail(append_subscript(sb, opx->mem));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->value, sb));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->key, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_storew(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsStoreW *opx = &op->op.storew;
	return_false_if_fail(rz_strbuf_append(sb, "(" UCD_STOREW));
	return_false_if_fail(append_subscript(sb, opx->mem));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->value, sb));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->key, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_nop(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_0(UCD_NOP);
}

static bool il_opdmp_empty(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_0(UCD_EMPTY);
}

static bool il_opdmp_set(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsSet *opx = &op->op.set;
	return_false_if_fail(rz_strbuf_appendf(sb, "(%s " UCD_SET " ", opx->v));
	return_false_if_fail(il_op_pure_string_resolve(ctx, opx->x, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_jmp(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_1(UCD_JMP, op->op.jmp, pure, dst);
}

static bool il_opdmp_goto(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsGoto *opx = &op->op.goto_;
	return rz_strbuf_appendf(sb, "(" UCD_GOTO "%s)", opx->lbl);
}

static bool il_opdmp_seq_inner(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb, size_t indent) {
	const RzILOpArgsSeq *seq = &op->op.seq;
	if (seq->x->code == RZ_IL_OP_SEQ) {
		return_false_if_fail(il_opdmp_seq_inner(ctx, seq->x, sb, indent + ctx->indent_inc));
		return_false_if_fail(rz_strbuf_appendf(sb, "\n%*s", (int)indent, ""));
	} else {
		return_false_if_fail(il_op_effect_string_resolve(ctx, seq->x, sb));
	}
	if (seq->y->code != RZ_IL_OP_SEQ && seq->x->code != RZ_IL_OP_SEQ) {
		return_false_if_fail(rz_strbuf_append(sb, " "));
	}
	if (seq->y->code == RZ_IL_OP_SEQ) {
		if (seq->x->code != RZ_IL_OP_SEQ) {
			return_false_if_fail(rz_strbuf_appendf(sb, "\n%*s", (int)indent, ""));
		}
		return il_opdmp_seq_inner(ctx, seq->y, sb, indent + ctx->indent_inc);
	} else {
		return il_op_effect_string_resolve(ctx, seq->y, sb);
	}
}

static bool il_opdmp_seq(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	return_false_if_fail(rz_strbuf_append(sb, "("));
	return_false_if_fail(il_opdmp_seq_inner(ctx, op, sb, ctx->indent));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_blk(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsBlk *opx = &op->op.blk;
	return_false_if_fail(rz_strbuf_appendf(sb, "(%s: ", opx->label));
	return_false_if_fail(il_op_effect_string_resolve(ctx, opx->data_eff, sb));
	return_false_if_fail(rz_strbuf_append(sb, " "));
	return_false_if_fail(il_op_effect_string_resolve(ctx, opx->ctrl_eff, sb));
	return rz_strbuf_append(sb, ")");
}

static bool il_opdmp_repeat(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_2(UCD_REPEAT, op->op.repeat, pure, condition, effect, data_eff);
}

static bool il_opdmp_branch(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_3(UCD_BRANCH, op->op.branch, pure, condition, effect, true_eff, effect, false_eff);
}

static bool il_op_pure_string_resolve(RzILStringifyCtx *ctx, const RzILOpPure *op, RzStrBuf *sb) {
	if (!op) {
		rz_return_val_if_reached(false);
	}
	switch (op->code) {
		CASE_IL_OP(VAR, var);
		CASE_IL_OP(ITE, ite);
		CASE_IL_OP(LET, let);
		CASE_IL_OP(B0, bool_false);
		CASE_IL_OP(B1, bool_true);
		CASE_IL_OP(INV, bool_inv);
		CASE_IL_OP(AND, bool_and);
		CASE_IL_OP(OR, bool_or);
		CASE_IL_OP(XOR, bool_xor);
		CASE_IL_OP(BITV, bitv);
		CASE_IL_OP(MSB, msb);
		CASE_IL_OP(LSB, lsb);
		CASE_IL_OP(IS_ZERO, is_zero);
		CASE_IL_OP(NEG, neg);
		CASE_IL_OP(LOGNOT, lognot);
		CASE_IL_OP(ADD, add);
		CASE_IL_OP(SUB, sub);
		CASE_IL_OP(MUL, mul);
		CASE_IL_OP(DIV, div);
		CASE_IL_OP(SDIV, sdiv);
		CASE_IL_OP(MOD, mod);
		CASE_IL_OP(SMOD, smod);
		CASE_IL_OP(LOGAND, logand);
		CASE_IL_OP(LOGOR, logor);
		CASE_IL_OP(LOGXOR, logxor);
		CASE_IL_OP(SHIFTR, shiftr);
		CASE_IL_OP(SHIFTL, shiftl);
		CASE_IL_OP(EQ, eq);
		CASE_IL_OP(SLE, sle);
		CASE_IL_OP(ULE, ule);
		CASE_IL_OP(CAST, cast);
		CASE_IL_OP(APPEND, append);
		CASE_IL_OP(LOAD, load);
		CASE_IL_OP(LOADW, loadw);
		CASE_IL_OP(FLOAT, float);
		CASE_IL_OP(FBITS, fbits);
		CASE_IL_OP(IS_FINITE, is_finite);
		CASE_IL_OP(IS_NAN, is_nan);
		CASE_IL_OP(IS_INF, is_inf);
		CASE_IL_OP(IS_FZERO, is_fzero);
		CASE_IL_OP(IS_FNEG, is_fneg);
		CASE_IL_OP(IS_FPOS, is_fpos);
		CASE_IL_OP(FNEG, fneg);
		CASE_IL_OP(FABS, fabs);
		CASE_IL_OP(FCAST_INT, fcast_int);
		CASE_IL_OP(FCAST_SINT, fcast_sint);
		CASE_IL_OP(FCAST_FLOAT, fcast_float);
		CASE_IL_OP(FCAST_SFLOAT, fcast_sfloat);
		CASE_IL_OP(FCONVERT, fconvert);
		CASE_IL_OP(FREQUAL, frequal);
		CASE_IL_OP(FSUCC, fsucc);
		CASE_IL_OP(FPRED, fpred);
		CASE_IL_OP(FORDER, forder);
		CASE_IL_OP(FROUND, fround);
		CASE_IL_OP(FSQRT, fsqrt);
		CASE_IL_OP(FRSQRT, frsqrt);
		CASE_IL_OP(FEXCEPT, fexcept);
		CASE_IL_OP(FADD, fadd);
		CASE_IL_OP(FSUB, fsub);
		CASE_IL_OP(FMUL, fmul);
		CASE_IL_OP(FDIV, fdiv);
		CASE_IL_OP(FMOD, fmod);
		CASE_IL_OP(FHYPOT, fhypot);
		CASE_IL_OP(FPOW, fpow);
		CASE_IL_OP(FMAD, fmad);
		CASE_IL_OP(FPOWN, fpown);
		CASE_IL_OP(FROOTN, frootn);
		CASE_IL_OP(FCOMPOUND, fcompound);
	default:
		rz_warn_if_reached();
		return rz_strbuf_appendf(sb, UCD_UNK "%u", op->code);
	}
}

static bool il_op_effect_string_resolve(RzILStringifyCtx *ctx, const RzILOpEffect *op, RzStrBuf *sb) {
	if (!op) {
		rz_return_val_if_reached(false);
	}
	switch (op->code) {
		CASE_IL_OP(EMPTY, empty);
		CASE_IL_OP(STORE, store);
		CASE_IL_OP(STOREW, storew);
		CASE_IL_OP(NOP, nop);
		CASE_IL_OP(SET, set);
		CASE_IL_OP(JMP, jmp);
		CASE_IL_OP(GOTO, goto);
		CASE_IL_OP(SEQ, seq);
		CASE_IL_OP(BLK, blk);
		CASE_IL_OP(REPEAT, repeat);
		CASE_IL_OP(BRANCH, branch);
	default:
		rz_warn_if_reached();
		return rz_strbuf_appendf(sb, UCD_UNK "%u", op->code);
	}
}

/**
 * \brief Convert a pure IL operation to a Unicode string.
 * \param ctx The stringify context.
 * \param op The pure IL operation to stringify.
 * \param sb The destination string buffer.
 *
 * \return True on success, false on failure.
 */
RZ_API bool rz_il_op_pure_stringify_unicode(RZ_NONNULL RZ_BORROW RzILStringifyCtx *ctx, RZ_NONNULL RZ_BORROW RzILOpPure *op, RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_val_if_fail(op && sb, false);
	return il_op_pure_string_resolve(ctx, op, sb);
}

/**
 * \brief Convert an effect IL operation to a Unicode string.
 * \param ctx The stringify context.
 * \param op The effect IL operation to stringify.
 * \param sb The destination string buffer.
 *
 * \return True on success, false on failure.
 */
RZ_API bool rz_il_op_effect_stringify_unicode(RZ_NONNULL RZ_BORROW RzILStringifyCtx *ctx, RZ_NONNULL RZ_BORROW RzILOpEffect *op, RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_val_if_fail(ctx && op && sb, false);
	return il_op_effect_string_resolve(ctx, op, sb);
}
