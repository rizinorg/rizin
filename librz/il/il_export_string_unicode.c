// SPDX-FileCopyrightText: 2026 Ehab-24 <ehabs1775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>

static void il_op_pure_string_resolve(const RzILOpPure *op, RzStrBuf *sb);
static void il_op_effect_string_resolve(const RzILOpEffect *op, RzStrBuf *sb);

static char *superscript_digits[10] = { "⁰", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹" };

#define UCD_ITE          "↠"
#define UCD_LET          "="
#define UCD_BOOL_FALSE   "⊥"
#define UCD_BOOL_TRUE    "⊤"
#define UCD_BOOL_INV     "!"
#define UCD_BOOL_AND     "&"
#define UCD_BOOL_OR      "|"
#define UCD_BOOL_XOR     "^"
#define UCD_BITV         "ʙ"
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
#define UCD_LOGAND       "∧"
#define UCD_LOGOR        "∨"
#define UCD_LOGXOR       "⊕"
#define UCD_SHIFTR       "≫"
#define UCD_SHIFTL       "≪"
#define UCD_EQ           "≡"
#define UCD_SLE          "≦⁺"
#define UCD_ULE          "≦"
#define UCD_CAST         "≈"
#define UCD_APPEND       "⊚"
#define UCD_FLOAT        "ꜰ"
#define UCD_FBITS        "ꜰʙ"
#define UCD_IS_FINITE    "< ∞"
#define UCD_IS_NAN       "≡ ɴ"
#define UCD_IS_INF       "≡ ∞"
#define UCD_IS_FZERO     "≡ 0"
#define UCD_IS_FNEG      "< 0"
#define UCD_IS_FPOS      "> 0"
#define UCD_FNEG         "−"
#define UCD_FABS         "‖"
#define UCD_FCAST_INT    "ꜰ≈"
#define UCD_FCAST_SINT   "ꜰ≈⁺"
#define UCD_FCAST_FLOAT  "ꜰ≈ꜰ"
#define UCD_FCAST_SFLOAT "ꜰ≈ꜰ⁺"
#define UCD_FCONVERT     "⩭"
#define UCD_FSQRT        "²√"
#define UCD_FRSQRT       "¹/√"
#define UCD_FROUND       "⭂"
#define UCD_FREQUAL      "ꜰ≡"
#define UCD_FSUCC        "⌊"
#define UCD_FPRED        "⌋"
#define UCD_FORDER       "<"
#define UCD_FEXCEPT      "ᴇ"
#define UCD_FADD         "+"
#define UCD_FSUB         "-"
#define UCD_FMUL         "*"
#define UCD_FDIV         "/"
#define UCD_FMOD         "ꜰ%"
#define UCD_FHYPOT       "∠"
#define UCD_FMAD         "ᴍᴀ"
#define UCD_FPOW         "˰"
#define UCD_FPOWN        "˰ⁿ"
#define UCD_FROOTN       "ⁿ√"
#define UCD_FCOMPOUND    "∪"
#define UCD_LOAD         "ʟ"
#define UCD_LOADW        "ʟ"
#define UCD_STORE        "ꜱ"
#define UCD_STOREW       "ŝ"
#define UCD_NOP          "∅"
#define UCD_EMPTY        "{}"
#define UCD_SET          "←"
#define UCD_JMP          "↷"
#define UCD_GOTO         "@"
#define UCD_REPEAT       "⟳"
#define UCD_BRANCH       "⅄"
#define UCD_UNK          "?"

#define il_op_param_0(sym) \
	rz_strbuf_append(sb, sym);

#define il_op_param_1(sym, opx, sort0, v0) \
	do { \
		rz_strbuf_append(sb, sym " "); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
	} while (0)

#define il_op_param_1_rtl(sym, opx, sort0, v0) \
	do { \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, " " sym); \
	} while (0)

#define il_op_param_2(sym, opx, sort0, v0, sort1, v1) \
	do { \
		rz_strbuf_append(sb, "("); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, " " sym " "); \
		il_op_##sort1##_string_resolve(opx.v1, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_3(sym, opx, sort0, v0, sort1, v1, sort2, v2) \
	do { \
		rz_strbuf_append(sb, "("); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, " " sym " "); \
		il_op_##sort1##_string_resolve(opx.v1, sb); \
		rz_strbuf_append(sb, " "); \
		il_op_##sort2##_string_resolve(opx.v2, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_rmode(sym, opx, v0, sort0, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		rz_strbuf_appendf(sb, "(%s " sym " ", rmode_str); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_fexcept(sym, opx, v0, sort0, ve) \
	do { \
		const char *str = rz_il_float_stringify_exception(opx.ve); \
		rz_strbuf_appendf(sb, "(%s " sym " ", str); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_mode_length(sym, opx, v0, sort0, m, l) \
	do { \
		rz_strbuf_appendf(sb, "("); \
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx.m)); \
		rz_strbuf_appendf(sb, " %u " sym " ", opx.l); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_1_with_mode_format(sym, opx, v0, sort0, m, f) \
	do { \
		rz_strbuf_appendf(sb, "("); \
		rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx.m)); \
		rz_strbuf_append(sb, " "); \
		rz_strbuf_append(sb, rz_il_float_stringify_format(opx.f)); \
		rz_strbuf_append(sb, " " sym " "); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define il_op_param_2_with_rmode(sym, opx, v0, sort0, v1, sort1, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		rz_strbuf_appendf(sb, "(%s ", rmode_str); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, " " sym " "); \
		il_op_##sort1##_string_resolve(opx.v1, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0);

#define il_op_param_3_with_rmode(sym, opx, v0, sort0, v1, sort1, v2, sort2, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		rz_strbuf_appendf(sb, "(%s ", rmode_str); \
		il_op_##sort0##_string_resolve(opx.v0, sb); \
		rz_strbuf_append(sb, " " sym " "); \
		il_op_##sort1##_string_resolve(opx.v1, sb); \
		rz_strbuf_append(sb, " "); \
		il_op_##sort2##_string_resolve(opx.v2, sb); \
		rz_strbuf_append(sb, ")"); \
	} while (0)

#define append_superscript(sb, num) \
	do { \
		char *num_str = subscript_ut32(num); \
		if (RZ_STR_ISEMPTY(num_str)) { \
			rz_strbuf_append(sb, "⁰"); \
		} else { \
			rz_strbuf_append(sb, num_str); \
			RZ_FREE(num_str); \
		} \
	} while (0)

static RZ_OWN RZ_NULLABLE char *subscript_ut32(ut32 n) {
	char buffer[32];
	ssize_t len = snprintf(buffer, RZ_ARRAY_SIZE(buffer), "%u", n);
	rz_return_val_if_fail(len >= 0, NULL);

	/* Each unicode superscript character is at most 3 bytes */
	char *result = RZ_NEWS0(char, len * 3 + 1);
	result[0] = '\0';
	for (ssize_t i = 0; i < len; ++i) {
		int digit = buffer[i] - '0';
		strcat(result, superscript_digits[digit]);
	}
	return result;
}

static void il_opdmp_var(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsVar *opx = &op->op.var;
	if (!rz_str_cmp(opx->v, "_val", 4)) {
		rz_strbuf_appendf(sb, "%s", opx->v);
	} else {
		rz_strbuf_appendf(sb, "%s", opx->v);
	}
}

static void il_opdmp_ite(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3(UCD_ITE, op->op.ite, pure, condition, pure, x, pure, y);
}

static void il_opdmp_let(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsLet *opx = &op->op.let;
	rz_strbuf_appendf(sb, "(%s " UCD_LET " ", opx->name);
	il_op_pure_string_resolve(opx->exp, sb);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->body, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_bool_false(const RzILOpPure *op, RzStrBuf *sb) {
	rz_strbuf_append(sb, UCD_BOOL_FALSE);
}

static void il_opdmp_bool_true(const RzILOpPure *op, RzStrBuf *sb) {
	rz_strbuf_append(sb, UCD_BOOL_TRUE);
}

static void il_opdmp_bool_inv(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_BOOL_INV, op->op.boolinv, pure, x);
}

static void il_opdmp_bool_and(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_BOOL_AND, op->op.booland, pure, x, pure, y);
}

static void il_opdmp_bool_or(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_BOOL_OR, op->op.boolor, pure, x, pure, y);
}

static void il_opdmp_bool_xor(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_BOOL_XOR, op->op.boolxor, pure, x, pure, y);
}

static void il_opdmp_bitv(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsBv *opx = &op->op.bitv;
	char *num = rz_bv_as_hex_string(opx->value, false);
	rz_strbuf_append(sb, "(" UCD_BITV);
	append_superscript(sb, opx->value->len);
	rz_strbuf_appendf(sb, " %s)", num);
	free(num);
}

static void il_opdmp_msb(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_MSB, op->op.msb, pure, bv);
}

static void il_opdmp_lsb(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_LSB, op->op.lsb, pure, bv);
}

static void il_opdmp_is_zero(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_ZERO, op->op.lsb, pure, bv);
}

static void il_opdmp_neg(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_NEG, op->op.neg, pure, bv);
}

static void il_opdmp_lognot(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_LOGNOT, op->op.lognot, pure, bv);
}

static void il_opdmp_add(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_ADD, op->op.add, pure, x, pure, y);
}

static void il_opdmp_sub(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SUB, op->op.sub, pure, x, pure, y);
}

static void il_opdmp_mul(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_MUL, op->op.mul, pure, x, pure, y);
}

static void il_opdmp_div(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_DIV, op->op.div, pure, x, pure, y);
}

static void il_opdmp_sdiv(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SDIV, op->op.sdiv, pure, x, pure, y);
}

static void il_opdmp_mod(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_MOD, op->op.mod, pure, x, pure, y);
}

static void il_opdmp_smod(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SMOD, op->op.smod, pure, x, pure, y);
}

static void il_opdmp_logand(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_LOGAND, op->op.logand, pure, x, pure, y);
}

static void il_opdmp_logor(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_LOGOR, op->op.logor, pure, x, pure, y);
}

static void il_opdmp_logxor(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_LOGXOR, op->op.logxor, pure, x, pure, y);
}

static void il_opdmp_shiftr(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3(UCD_SHIFTR, op->op.shiftr, pure, x, pure, y, pure, fill_bit);
}

static void il_opdmp_shiftl(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3(UCD_SHIFTL, op->op.shiftl, pure, x, pure, y, pure, fill_bit);
}

static void il_opdmp_eq(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_EQ, op->op.ule, pure, x, pure, y);
}

static void il_opdmp_sle(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_SLE, op->op.sle, pure, x, pure, y);
}

static void il_opdmp_ule(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_ULE, op->op.ule, pure, x, pure, y);
}

static void il_opdmp_cast(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsCast *opx = &op->op.cast;
	rz_strbuf_append(sb, "(");
	il_op_pure_string_resolve(opx->val, sb);
	rz_strbuf_append(sb, " " UCD_CAST);
	append_superscript(sb, opx->length);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->fill, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_append(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_APPEND, op->op.append, pure, high, pure, low);
}

static void il_opdmp_float(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFloat *opx = &op->op.float_;
	rz_strbuf_appendf(sb, "(%d " UCD_FLOAT " ", opx->r);
	il_op_pure_string_resolve(opx->bv, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_fbits(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_FBITS, op->op.fbits, pure, f);
}

static void il_opdmp_is_finite(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FINITE, op->op.is_finite, pure, f);
}

static void il_opdmp_is_nan(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_NAN, op->op.is_nan, pure, f);
}

static void il_opdmp_is_inf(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_INF, op->op.is_inf, pure, f);
}

static void il_opdmp_is_fzero(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FZERO, op->op.is_fzero, pure, f);
}

static void il_opdmp_is_fneg(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FNEG, op->op.is_fneg, pure, f);
}

static void il_opdmp_is_fpos(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_rtl(UCD_IS_FPOS, op->op.is_fpos, pure, f);
}

static void il_opdmp_fneg(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_FNEG, op->op.fneg, pure, f);
}

static void il_opdmp_fabs(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1(UCD_FABS, op->op.fabs, pure, f);
}

static void il_opdmp_fcast_int(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_length(UCD_FCAST_INT, op->op.fcast_int, f, pure, mode, length);
}

static void il_opdmp_fcast_sint(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_length(UCD_FCAST_SINT, op->op.fcast_sint, f, pure, mode, length);
}

static void il_opdmp_fcast_float(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_format(UCD_FCAST_FLOAT, op->op.fcast_float, bv, pure, mode, format);
}

static void il_opdmp_fcast_sfloat(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_format(UCD_FCAST_SFLOAT, op->op.fcast_sfloat, bv, pure, mode, format);
}

static void il_opdmp_fconvert(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_mode_format(UCD_FCONVERT, op->op.fconvert, f, pure, mode, format);
}

static void il_opdmp_fsqrt(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_rmode(UCD_FSQRT, op->op.fsqrt, f, pure, rmode);
}

static void il_opdmp_frsqrt(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_rmode(UCD_FRSQRT, op->op.frsqrt, f, pure, rmode);
}

static void il_opdmp_fround(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_rmode(UCD_FROUND, op->op.fround, f, pure, rmode);
}

static void il_opdmp_frequal(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsFrequal *opx = &op->op.frequal;
	rz_strbuf_append(sb, "(");
	rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x));
	rz_strbuf_append(sb, " " UCD_FREQUAL " ");
	rz_strbuf_append(sb, rz_il_float_stringify_rmode(opx->x));
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_fsucc(const RzILOpPure *op, RzStrBuf *sb) {
	rz_strbuf_append(sb, UCD_FSUCC "(");
	il_op_pure_string_resolve(op->op.fsucc.f, sb);
	rz_strbuf_append(sb, ")");
}
static void il_opdmp_fpred(const RzILOpPure *op, RzStrBuf *sb) {
	rz_strbuf_append(sb, UCD_FPRED "(");
	il_op_pure_string_resolve(op->op.fpred.f, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_forder(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2(UCD_FORDER, op->op.forder, pure, x, pure, y);
}

static void il_opdmp_fexcept(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_1_with_fexcept(UCD_FEXCEPT, op->op.fexcept, x, pure, e);
}

static void il_opdmp_fadd(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FADD, op->op.fadd, x, pure, y, pure, rmode);
}

static void il_opdmp_fsub(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FSUB, op->op.fsub, x, pure, y, pure, rmode);
}

static void il_opdmp_fmul(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FMUL, op->op.fmul, x, pure, y, pure, rmode);
}

static void il_opdmp_fdiv(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FDIV, op->op.fdiv, x, pure, y, pure, rmode);
}

static void il_opdmp_fmod(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FMOD, op->op.fmod, x, pure, y, pure, rmode);
}

static void il_opdmp_fhypot(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FHYPOT, op->op.fhypot, x, pure, y, pure, rmode);
}

static void il_opdmp_fpow(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FPOW, op->op.fpow, x, pure, y, pure, rmode);
}

static void il_opdmp_fmad(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_3_with_rmode(UCD_FMAD, op->op.fmad, x, pure, y, pure, z, pure, rmode);
}

static void il_opdmp_fpown(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FPOWN, op->op.fpown, f, pure, n, pure, rmode);
}

static void il_opdmp_frootn(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FROOTN, op->op.frootn, f, pure, n, pure, rmode);
}

static void il_opdmp_fcompound(const RzILOpPure *op, RzStrBuf *sb) {
	il_op_param_2_with_rmode(UCD_FCOMPOUND, op->op.fcompound, f, pure, n, pure, rmode);
}

static void il_opdmp_load(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsLoad *opx = &op->op.load;
	rz_strbuf_append(sb, "(" UCD_LOAD);
	append_superscript(sb, opx->mem);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->key, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_loadw(const RzILOpPure *op, RzStrBuf *sb) {
	const RzILOpArgsLoadW *opx = &op->op.loadw;
	rz_strbuf_appendf(sb, "(%u " UCD_LOADW, (ut32)opx->n_bits);
	append_superscript(sb, opx->mem);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->key, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_store(const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsStore *opx = &op->op.store;
	rz_strbuf_append(sb, "(" UCD_STORE);
	append_superscript(sb, opx->mem);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->key, sb);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->value, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_storew(const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsStoreW *opx = &op->op.storew;
	rz_strbuf_append(sb, "(" UCD_STOREW);
	append_superscript(sb, opx->mem);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->key, sb);
	rz_strbuf_append(sb, " ");
	il_op_pure_string_resolve(opx->value, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_nop(const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_0(UCD_NOP);
}

static void il_opdmp_empty(const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_0(UCD_EMPTY);
}

static void il_opdmp_set(const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsSet *opx = &op->op.set;
	rz_strbuf_appendf(sb, "(%s " UCD_SET " ", opx->v);
	il_op_pure_string_resolve(opx->x, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_jmp(const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_1(UCD_JMP, op->op.jmp, pure, dst);
}

static void il_opdmp_goto(const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsGoto *opx = &op->op.goto_;
	rz_strbuf_appendf(sb, "(" UCD_GOTO "%s)", opx->lbl);
}

static void il_opdmp_seq_inner(const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsSeq *seq = &op->op.seq;
	if (seq->x->code == RZ_IL_OP_SEQ) {
		il_opdmp_seq_inner(seq->x, sb);
		rz_strbuf_append(sb, "\n        ");
	} else {
		il_op_effect_string_resolve(seq->x, sb);
	}
	if (seq->y->code != RZ_IL_OP_SEQ && seq->x->code != RZ_IL_OP_SEQ) {
		rz_strbuf_append(sb, " ");
	}
	if (seq->y->code == RZ_IL_OP_SEQ) {
		if (seq->x->code != RZ_IL_OP_SEQ) {
			rz_strbuf_append(sb, "\n        ");
		}
		il_opdmp_seq_inner(seq->y, sb);
	} else {
		il_op_effect_string_resolve(seq->y, sb);
	}
}

static void il_opdmp_seq(const RzILOpEffect *op, RzStrBuf *sb) {
	rz_strbuf_append(sb, "(");
	il_opdmp_seq_inner(op, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_blk(const RzILOpEffect *op, RzStrBuf *sb) {
	const RzILOpArgsBlk *opx = &op->op.blk;
	rz_strbuf_appendf(sb, "(%s: ", opx->label);
	il_op_effect_string_resolve(opx->data_eff, sb);
	rz_strbuf_append(sb, " ");
	il_op_effect_string_resolve(opx->ctrl_eff, sb);
	rz_strbuf_append(sb, ")");
}

static void il_opdmp_repeat(const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_2(UCD_REPEAT, op->op.repeat, pure, condition, effect, data_eff);
}

static void il_opdmp_branch(const RzILOpEffect *op, RzStrBuf *sb) {
	il_op_param_3(UCD_BRANCH, op->op.branch, pure, condition, effect, true_eff, effect, false_eff);
}

static void il_op_pure_string_resolve(const RzILOpPure *op, RzStrBuf *sb) {
	if (!op) {
		rz_strbuf_append(sb, "(null)");
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_VAR:
		il_opdmp_var(op, sb);
		return;
	case RZ_IL_OP_ITE:
		il_opdmp_ite(op, sb);
		return;
	case RZ_IL_OP_LET:
		il_opdmp_let(op, sb);
		return;
	case RZ_IL_OP_B0:
		il_opdmp_bool_false(op, sb);
		return;
	case RZ_IL_OP_B1:
		il_opdmp_bool_true(op, sb);
		return;
	case RZ_IL_OP_INV:
		il_opdmp_bool_inv(op, sb);
		return;
	case RZ_IL_OP_AND:
		il_opdmp_bool_and(op, sb);
		return;
	case RZ_IL_OP_OR:
		il_opdmp_bool_or(op, sb);
		return;
	case RZ_IL_OP_XOR:
		il_opdmp_bool_xor(op, sb);
		return;
	case RZ_IL_OP_BITV:
		il_opdmp_bitv(op, sb);
		return;
	case RZ_IL_OP_MSB:
		il_opdmp_msb(op, sb);
		return;
	case RZ_IL_OP_LSB:
		il_opdmp_lsb(op, sb);
		return;
	case RZ_IL_OP_IS_ZERO:
		il_opdmp_is_zero(op, sb);
		return;
	case RZ_IL_OP_NEG:
		il_opdmp_neg(op, sb);
		return;
	case RZ_IL_OP_LOGNOT:
		il_opdmp_lognot(op, sb);
		return;
	case RZ_IL_OP_ADD:
		il_opdmp_add(op, sb);
		return;
	case RZ_IL_OP_SUB:
		il_opdmp_sub(op, sb);
		return;
	case RZ_IL_OP_MUL:
		il_opdmp_mul(op, sb);
		return;
	case RZ_IL_OP_DIV:
		il_opdmp_div(op, sb);
		return;
	case RZ_IL_OP_SDIV:
		il_opdmp_sdiv(op, sb);
		return;
	case RZ_IL_OP_MOD:
		il_opdmp_mod(op, sb);
		return;
	case RZ_IL_OP_SMOD:
		il_opdmp_smod(op, sb);
		return;
	case RZ_IL_OP_LOGAND:
		il_opdmp_logand(op, sb);
		return;
	case RZ_IL_OP_LOGOR:
		il_opdmp_logor(op, sb);
		return;
	case RZ_IL_OP_LOGXOR:
		il_opdmp_logxor(op, sb);
		return;
	case RZ_IL_OP_SHIFTR:
		il_opdmp_shiftr(op, sb);
		return;
	case RZ_IL_OP_SHIFTL:
		il_opdmp_shiftl(op, sb);
		return;
	case RZ_IL_OP_EQ:
		il_opdmp_eq(op, sb);
		return;
	case RZ_IL_OP_SLE:
		il_opdmp_sle(op, sb);
		return;
	case RZ_IL_OP_ULE:
		il_opdmp_ule(op, sb);
		return;
	case RZ_IL_OP_CAST:
		il_opdmp_cast(op, sb);
		return;
	case RZ_IL_OP_APPEND:
		il_opdmp_append(op, sb);
		return;
	case RZ_IL_OP_LOAD:
		il_opdmp_load(op, sb);
		return;
	case RZ_IL_OP_LOADW:
		il_opdmp_loadw(op, sb);
		return;
	case RZ_IL_OP_FLOAT:
		il_opdmp_float(op, sb);
		return;
	case RZ_IL_OP_FBITS:
		il_opdmp_fbits(op, sb);
		return;
	case RZ_IL_OP_IS_FINITE:
		il_opdmp_is_finite(op, sb);
		return;
	case RZ_IL_OP_IS_NAN:
		il_opdmp_is_nan(op, sb);
		return;
	case RZ_IL_OP_IS_INF:
		il_opdmp_is_inf(op, sb);
		return;
	case RZ_IL_OP_IS_FZERO:
		il_opdmp_is_fzero(op, sb);
		return;
	case RZ_IL_OP_IS_FNEG:
		il_opdmp_is_fneg(op, sb);
		return;
	case RZ_IL_OP_IS_FPOS:
		il_opdmp_is_fpos(op, sb);
		return;
	case RZ_IL_OP_FNEG:
		il_opdmp_fneg(op, sb);
		return;
	case RZ_IL_OP_FABS:
		il_opdmp_fabs(op, sb);
		return;
	case RZ_IL_OP_FCAST_INT:
		il_opdmp_fcast_int(op, sb);
		return;
	case RZ_IL_OP_FCAST_SINT:
		il_opdmp_fcast_sint(op, sb);
		return;
	case RZ_IL_OP_FCAST_FLOAT:
		il_opdmp_fcast_float(op, sb);
		return;
	case RZ_IL_OP_FCAST_SFLOAT:
		il_opdmp_fcast_sfloat(op, sb);
		return;
	case RZ_IL_OP_FCONVERT:
		il_opdmp_fconvert(op, sb);
		return;
	case RZ_IL_OP_FREQUAL:
		il_opdmp_frequal(op, sb);
		return;
	case RZ_IL_OP_FSUCC:
		il_opdmp_fsucc(op, sb);
		return;
	case RZ_IL_OP_FPRED:
		il_opdmp_fpred(op, sb);
		return;
	case RZ_IL_OP_FORDER:
		il_opdmp_forder(op, sb);
		return;
	case RZ_IL_OP_FROUND:
		il_opdmp_fround(op, sb);
		return;
	case RZ_IL_OP_FSQRT:
		il_opdmp_fsqrt(op, sb);
		return;
	case RZ_IL_OP_FRSQRT:
		il_opdmp_frsqrt(op, sb);
		return;
	case RZ_IL_OP_FEXCEPT:
		il_opdmp_fexcept(op, sb);
		return;
	case RZ_IL_OP_FADD:
		il_opdmp_fadd(op, sb);
		return;
	case RZ_IL_OP_FSUB:
		il_opdmp_fsub(op, sb);
		return;
	case RZ_IL_OP_FMUL:
		il_opdmp_fmul(op, sb);
		return;
	case RZ_IL_OP_FDIV:
		il_opdmp_fdiv(op, sb);
		return;
	case RZ_IL_OP_FMOD:
		il_opdmp_fmod(op, sb);
		return;
	case RZ_IL_OP_FHYPOT:
		il_opdmp_fhypot(op, sb);
		return;
	case RZ_IL_OP_FPOW:
		il_opdmp_fpow(op, sb);
		return;
	case RZ_IL_OP_FMAD:
		il_opdmp_fmad(op, sb);
		return;
	case RZ_IL_OP_FPOWN:
		il_opdmp_fpown(op, sb);
		return;
	case RZ_IL_OP_FROOTN:
		il_opdmp_frootn(op, sb);
		return;
	case RZ_IL_OP_FCOMPOUND:
		il_opdmp_fcompound(op, sb);
		return;

	default:
		rz_warn_if_reached();
		rz_strbuf_appendf(sb, UCD_UNK "%u", op->code);
		return;
	}
}

static void il_op_effect_string_resolve(const RzILOpEffect *op, RzStrBuf *sb) {
	if (!op) {
		rz_strbuf_append(sb, UCD_NOP);
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_EMPTY:
		il_opdmp_empty(op, sb);
		break;
	case RZ_IL_OP_STORE:
		il_opdmp_store(op, sb);
		return;
	case RZ_IL_OP_STOREW:
		il_opdmp_storew(op, sb);
		return;
	case RZ_IL_OP_NOP:
		il_opdmp_nop(op, sb);
		return;
	case RZ_IL_OP_SET:
		il_opdmp_set(op, sb);
		return;
	case RZ_IL_OP_JMP:
		il_opdmp_jmp(op, sb);
		return;
	case RZ_IL_OP_GOTO:
		il_opdmp_goto(op, sb);
		return;
	case RZ_IL_OP_SEQ:
		il_opdmp_seq(op, sb);
		return;
	case RZ_IL_OP_BLK:
		il_opdmp_blk(op, sb);
		return;
	case RZ_IL_OP_REPEAT:
		il_opdmp_repeat(op, sb);
		return;
	case RZ_IL_OP_BRANCH:
		il_opdmp_branch(op, sb);
		return;
	default:
		rz_warn_if_reached();
		rz_strbuf_appendf(sb, UCD_UNK "%u", op->code);
		return;
	}
}

RZ_API void rz_il_op_pure_stringify_unicode(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(op && sb);
	il_op_pure_string_resolve(op, sb);
}

RZ_API void rz_il_op_effect_stringify_unicode(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(op && sb);
	il_op_effect_string_resolve(op, sb);
}
