// SPDX-FileCopyrightText: 2001-2004 Fabrice Bellard
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_file.h>
#include <rz_util.h>
#include <math.h>
#include "c_preprocessor.h"
#include "c_preprocessor_tokens.h"

// Preprocessor C types

#define PP_C_TYPE_BTYPE 0x000f /* mask for basic type */

#define PP_C_TYPE_INT32    0 /* int32_t integer type */
#define PP_C_TYPE_INT16    1 /* int16_t short type */
#define PP_C_TYPE_INT8     2 /* int8_t signed byte type */
#define PP_C_TYPE_PTR      4 /* pointer */
#define PP_C_TYPE_ENUM     5 /* enum definition */
#define PP_C_TYPE_FUNC     6 /* function type */
#define PP_C_TYPE_UNION    8 /* union definition */
#define PP_C_TYPE_FLOAT    9 /* IEEE float */
#define PP_C_TYPE_DOUBLE   10 /* IEEE double */
#define PP_C_TYPE_LDOUBLE  11 /* IEEE long double */
#define PP_C_TYPE_BOOL     12 /* ISOC99 boolean type */
#define PP_C_TYPE_INT64    13 /* int64_t */
#define PP_C_TYPE_LONG     14 /* long integer (NEVER USED as type, only during parsing) */
#define PP_C_TYPE_UNSIGNED 0x0020 /* unsigned type */
#define PP_C_TYPE_ARRAY    0x0040 /* array type (also has PP_C_TYPE_PTR) */
#define PP_C_TYPE_CONSTANT 0x1000 /* const modifier */

void preprocessor_debug(CPreprocessorState *state, const char *fmt, ...);
void preprocessor_error(CPreprocessorState *state, const char *fmt, ...);
void preprocessor_warning(CPreprocessorState *state, const char *fmt, ...);

void next(CPreprocessorState *state);

static inline void skip(CPreprocessorState *state, int c) {
	if (state->cur->tok != c) {
		preprocessor_error(state, "'%c' expected (got \"%s\")",
			c, get_tok_str(state, state->cur->tok, &state->cur->tokc));
	}
	next(state);
}

static inline int pp_nerr(CPreprocessorState *state) {
	return state->nb_errors;
}

static void gexpr(CPreprocessorState *state);

void pp_value_push(CPreprocessorState *state, CValue *cval) {
	rz_pvector_push(state->values, cval);
}

void pp_value_push_constant_int(CPreprocessorState *state, int v) {
	CValue *cval = RZ_NEW0(CValue);
	if (!cval) {
		return;
	}
	cval->i = v;
	cval->flags = VT_CONST;
	pp_value_push(state, cval);
}

void pp_value_push_constant_ut64(CPreprocessorState *state, ut64 v) {
	CValue *cval = RZ_NEW0(CValue);
	if (!cval) {
		return;
	}
	cval->ull = v;
	cval->flags = VT_CONST;
	pp_value_push(state, cval);
}

void pp_value_push_constant_size(CPreprocessorState *state, size_t v) {
	CValue *cval = RZ_NEW0(CValue);
	if (!cval) {
		return;
	}
	cval->ull = v;
	cval->flags = VT_CONST;
	pp_value_push(state, cval);
}

static void unary(CPreprocessorState *state) {
	int n, t, align, size, r;
	Sym *s;
	CPreprocessorCursorState *cur = state->cur;

	switch (cur->tok) {
	case TOK_CINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
		vpushi(cur->tokc.i);
		next(state);
		break;
	case TOK_CUINT:
		vpush_tokc(PP_C_TYPE_INT32 | PP_C_TYPE_UNSIGNED);
		next(state);
		break;
	case TOK_CLLONG:
		vpush_tokc(PP_C_TYPE_INT64);
		next(state);
		break;
	case TOK_CULLONG:
		vpush_tokc(PP_C_TYPE_INT64 | PP_C_TYPE_UNSIGNED);
		next(state);
		break;
	case TOK_CFLOAT:
		vpush_tokc(PP_C_TYPE_FLOAT);
		next(state);
		break;
	case TOK_CDOUBLE:
		vpush_tokc(PP_C_TYPE_DOUBLE);
		next(state);
		break;
	case TOK_CLDOUBLE:
		vpush_tokc(PP_C_TYPE_LDOUBLE);
		next(state);
		break;
#if 0
	case TOK_LSTR:
		t = PP_C_TYPE_INT32;
		goto str_init;
	case TOK_STR:
		/* string parsing */
		t = PP_C_TYPE_INT8;
	str_init:
		type.t = t;
		mk_pointer(&type);
		type.t |= PP_C_TYPE_ARRAY; // WHY?
		decl_initializer_alloc(&type, &ad, PP_C_TYPE_CONST, 2, 0, NULL, 0);
		break;
#endif
	case '(':
		next(state);
		if (cur->tok == '{') {
			/* statement expression : we do not accept break/continue
			   inside as GCC does */
			skip(state, ')');
		} else {
			gexpr(state);
			skip(state, ')');
		}
		break;
	case '!':
		next(state);
		unary(state);
		// Invert the symbol
		if ((vtop->flags & PP_C_TYPE_VALMASK) == PP_C_TYPE_CMP) {
			vtop->c.i = vtop->c.i ^ 1;
		}
		break;
	// special qnan , snan and infinity values
	case TOK___NAN__:
		pp_value_push_constant_ut64(state, PP_C_TYPE_DOUBLE, 0x7ff8000000000000ULL);
		next(state);
		break;
	case TOK___SNAN__:
		pp_value_push_constant_ut64(state, PP_C_TYPE_DOUBLE, 0x7ff0000000000001ULL);
		next(state);
		break;
	case TOK___INF__:
		pp_value_push_constant_ut64(state, PP_C_TYPE_DOUBLE, 0x7ff0000000000000ULL);
		next(state);
		break;

	default:
		t = cur->tok;
		next(state);
		if (t < TOK_UIDENT) {
			preprocessor_error(state, "identifier expected");
		}
		s = sym_find(t);
		if (!s) {
			if (cur->tok != '(') {
				preprocessor_error(state, "'%s' undeclared", get_tok_str(t, NULL));
			}
		}
		if (!s) {
			preprocessor_error(state, "invalid declaration '%s'", get_tok_str(t, NULL));
		} else {
			if ((s->type.t & (PP_C_TYPE_STATIC | PP_C_TYPE_INLINE | PP_C_TYPE_BTYPE)) ==
				(PP_C_TYPE_STATIC | PP_C_TYPE_INLINE | PP_C_TYPE_FUNC)) {
				/* if referencing an inline function, then we generate a
				   symbol to it if not already done. It will have the
				   effect to generate code for it at the end of the
				   compilation unit. */
				r = PP_C_TYPE_SYM | PP_C_TYPE_CONST;
			} else {
				r = s->flags;
			}
			vset(&s->type, r, s->c);
			/* if forward reference, we must point to s */
			if (vtop->flags & PP_C_TYPE_SYM) {
				vtop->sym = s;
				vtop->c.ul = 0;
			}
		}
		break;
	}
}

static void expr_prod(CPreprocessorState *state) {
	unary(state);
	CPreprocessorCursorState *cur = state->cur;
	while (cur->tok == '*' || cur->tok == '/' || cur->tok == '%') {
		next(state);
		unary(state);
	}
}

static void expr_sum(CPreprocessorState *state) {
	expr_prod(state);
	CPreprocessorCursorState *cur = state->cur;
	while (cur->tok == '+' || cur->tok == '-') {
		next(state);
		expr_prod(state);
	}
}

static void expr_shift(CPreprocessorState *state) {
	expr_sum(state);
	CPreprocessorCursorState *cur = state->cur;
	while (cur->tok == TOK_SHL || cur->tok == TOK_SAR) {
		next(state);
		expr_sum(state);
	}
}

static void expr_cmp(CPreprocessorState *state) {
	expr_shift(state);
	CPreprocessorCursorState *cur = state->cur;
	while ((cur->tok >= TOK_ULE && cur->tok <= TOK_GT) ||
		cur->tok == TOK_ULT || cur->tok == TOK_UGE) {
		next(state);
		expr_shift(state);
	}
}

static void expr_cmpeq(CPreprocessorState *state) {
	expr_cmp(state);
	CPreprocessorCursorState *cur = state->cur;
	while (cur->tok == TOK_EQ || cur->tok == TOK_NE) {
		next(state);
		expr_cmp(state);
	}
}

static void expr_and(CPreprocessorState *state) {
	expr_cmpeq(state);
	while (state->cur->tok == '&') {
		next(state);
		expr_cmpeq(state);
	}
}

static void expr_xor(CPreprocessorState *state) {
	expr_and(state);
	while (state->cur->tok == '^') {
		next(state);
		expr_and(state);
	}
}

static void expr_or(CPreprocessorState *state) {
	expr_xor(state);
	while (state->cur->tok == '|') {
		next(state);
		expr_xor(state);
	}
}

static void expr_land_const(CPreprocessorState *state) {
	expr_or(state);
	while (state->cur->tok == TOK_LAND) {
		next(state);
		expr_or(state);
	}
}

static void expr_lor_const(CPreprocessorState *state) {
	expr_land_const(state);
	while (state->cur->tok == TOK_LOR) {
		next(state);
		expr_land_const(state);
	}
}

static void expr_cond(CPreprocessorState *state) {
	expr_lor_const(state);
	CPreprocessorCursorState *cur = state->cur;
	CPreprocessorOptions *opts = state->opts;
	if (cur->tok == '?') {
		// shift vtop pointer/vector and put a duplicate of the top element
		vpushv(vtop);
		next(state);
		if (cur->tok != ':' || !opts->gnu_ext) {
			gexpr(state);
		}
		skip(state, ':');
		expr_cond(state);
	}
}

static void expr_eq(CPreprocessorState *state) {
	int t;

	expr_cond(state);
	int tok = state->cur->tok;
	if (tok == '=' ||
		(tok >= TOK_A_MOD && tok <= TOK_A_DIV) ||
		tok == TOK_A_XOR || tok == TOK_A_OR ||
		tok == TOK_A_SHL || tok == TOK_A_SAR) {
		test_lvalue(state);
		t = state->cur->tok;
		next(state);
		if (t == '=') {
			expr_eq(state);
		} else {
			// shift vtop pointer/vector and put a duplicate of the top element
			vpushv(vtop);
			expr_eq(state);
		}
	}
}

static void gexpr(CPreprocessorState *state) {
	while (pp_nerr(state) == 0) {
		expr_eq(state);
		if (state->cur->tok != ',') {
			break;
		}
		next(state);
	}
}

/* parse an integer constant and return its value. */
long long expr_const(CPreprocessorState *state) {
	long long c = 0LL;
	expr_cond(state);
	c = vtop->c.ll;
	return c;
}
