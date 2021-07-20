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

static void unary(CPreprocessorState *state) {
	int n, t, align, size, r, sizeof_caller;
	CType type = { 0 };
	Sym *s;
	AttributeDef ad;
	static int in_sizeof = 0;

	sizeof_caller = in_sizeof;
	in_sizeof = 0;
tok_next:
	switch (tok) {
	case TOK_EXTENSION:
		next(state);
		goto tok_next;
	case TOK_CINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
		vpushi(tokc.i);
		next(state);
		break;
	case TOK_CUINT:
		vpush_tokc(VT_INT32 | VT_UNSIGNED);
		next(state);
		break;
	case TOK_CLLONG:
		vpush_tokc(VT_INT64);
		next(state);
		break;
	case TOK_CULLONG:
		vpush_tokc(VT_INT64 | VT_UNSIGNED);
		next(state);
		break;
	case TOK_CFLOAT:
		vpush_tokc(VT_FLOAT);
		next(state);
		break;
	case TOK_CDOUBLE:
		vpush_tokc(VT_DOUBLE);
		next(state);
		break;
	case TOK_CLDOUBLE:
		vpush_tokc(VT_LDOUBLE);
		next(state);
		break;
	case TOK_LSTR:
		if (!strncmp(tcc_state->os, "windows", 7)) {
			t = VT_INT16 | VT_UNSIGNED;
		} else {
			t = VT_INT32;
		}
		goto str_init;
	case TOK_STR:
		/* string parsing */
		t = VT_INT8;
	str_init:
		if (tcc_state->warn_write_strings) {
			t |= VT_CONSTANT;
		}
		type.t = t;
		mk_pointer(&type);
		type.t |= VT_ARRAY;
		memset(&ad, 0, sizeof(AttributeDef));
		decl_initializer_alloc(&type, &ad, VT_CONST, 2, 0, NULL, 0);
		break;
	case '(':
		next();
		/* cast ? */
		if (parse_btype(&type, &ad)) {
			type_decl(&type, &ad, &n, TYPE_ABSTRACT);
			skip(')');
			/* check ISOC99 compound literal */
			if (tok == '{') {
				/* data is allocated locally by default */
				if (global_expr) {
					r = VT_CONST;
				} else {
					r = VT_LOCAL;
				}
				/* all except arrays are lvalues */
				if (!(type.t & VT_ARRAY)) {
					r |= lvalue_type(type.t);
				}
				memset(&ad, 0, sizeof(AttributeDef));
				decl_initializer_alloc(&type, &ad, r, 1, 0, NULL, 0);
			} else {
				if (sizeof_caller) {
					vpush(&type);
					return;
				}
				unary(state);
			}
		} else if (tok == '{') {
			/* statement expression : we do not accept break/continue
			   inside as GCC does */
			skip(state, ')');
		} else {
			gexpr(state);
			skip(state, ')');
		}
		break;
	case '*':
		next(state);
		unary(state);
		indir(state);
		break;
	case '!':
		next(state);
		unary(state);
		if ((vtop->r & VT_VALMASK) == VT_CMP) {
			vtop->c.i = vtop->c.i ^ 1;
		}
		break;
	// special qnan , snan and infinity values
	case TOK___NAN__:
		vpush64(VT_DOUBLE, 0x7ff8000000000000ULL);
		next(state);
		break;
	case TOK___SNAN__:
		vpush64(VT_DOUBLE, 0x7ff0000000000001ULL);
		next(state);
		break;
	case TOK___INF__:
		vpush64(VT_DOUBLE, 0x7ff0000000000000ULL);
		next(state);
		break;

	default:
	tok_identifier:
		t = tok;
		next();
		if (t < TOK_UIDENT) {
			expect("identifier");
		}
		s = sym_find(t);
		if (!s) {
			if (tok != '(') {
				TCC_ERR("'%s' undeclared", get_tok_str(t, NULL));
			}
		}
		if (!s) {
			TCC_ERR("invalid declaration '%s'", get_tok_str(t, NULL));
		} else {
			if ((s->type.t & (VT_STATIC | VT_INLINE | VT_BTYPE)) ==
				(VT_STATIC | VT_INLINE | VT_FUNC)) {
				/* if referencing an inline function, then we generate a
				   symbol to it if not already done. It will have the
				   effect to generate code for it at the end of the
				   compilation unit. */
				r = VT_SYM | VT_CONST;
			} else {
				r = s->r;
			}
			vset(&s->type, r, s->c);
			/* if forward reference, we must point to s */
			if (vtop->r & VT_SYM) {
				vtop->sym = s;
				vtop->c.ul = 0;
			}
		}
		break;
	}
}

static void expr_prod(CPreprocessorState *state) {
	unary(state);
	while (tok == '*' || tok == '/' || tok == '%') {
		next(state);
		unary(state);
	}
}

static void expr_sum(CPreprocessorState *state) {
	expr_prod(state);
	while (tok == '+' || tok == '-') {
		next(state);
		expr_prod(state);
	}
}

static void expr_shift(CPreprocessorState *state) {
	expr_sum(state);
	while (tok == TOK_SHL || tok == TOK_SAR) {
		next(state);
		expr_sum(state);
	}
}

static void expr_cmp(CPreprocessorState *state) {
	expr_shift(state);
	while ((tok >= TOK_ULE && tok <= TOK_GT) ||
		tok == TOK_ULT || tok == TOK_UGE) {
		next(state);
		expr_shift(state);
	}
}

static void expr_cmpeq(CPreprocessorState *state) {
	expr_cmp(state);
	while (tok == TOK_EQ || tok == TOK_NE) {
		next(state);
		expr_cmp(state);
	}
}

static void expr_and(CPreprocessorState *state) {
	expr_cmpeq(state);
	while (tok == '&') {
		next(state);
		expr_cmpeq(state);
	}
}

static void expr_xor(CPreprocessorState *state) {
	expr_and(state);
	while (tok == '^') {
		next(state);
		expr_and(state);
	}
}

static void expr_or(CPreprocessorState *state) {
	expr_xor(state);
	while (tok == '|') {
		next(state);
		expr_xor(state);
	}
}

static void expr_land_const(CPreprocessorState *state) {
	expr_or(state);
	while (tok == TOK_LAND) {
		next(state);
		expr_or(state);
	}
}

static void expr_lor_const(CPreprocessorState *state) {
	expr_land_const(state);
	while (tok == TOK_LOR) {
		next(state);
		expr_land_const(state);
	}
}

static void expr_cond(CPreprocessorState *state) {
	expr_lor_const(state);
	if (tok == '?') {
		vdup();
		next(state);
		if (tok != ':' || !gnu_ext) {
			gexpr(state);
		}
		skip(state, ':');
		expr_cond(state);
	}
}

static void expr_eq(CPreprocessorState *state) {
	int t;

	expr_cond(state);
	if (tok == '=' ||
		(tok >= TOK_A_MOD && tok <= TOK_A_DIV) ||
		tok == TOK_A_XOR || tok == TOK_A_OR ||
		tok == TOK_A_SHL || tok == TOK_A_SAR) {
		test_lvalue();
		t = tok;
		next();
		if (t == '=') {
			expr_eq(state);
		} else {
			vdup();
			expr_eq(state);
		}
	}
}

static void gexpr(CPreprocessorState *state) {
	while (tcc_nerr(state) == 0) {
		expr_eq(state);
		if (tok != ',') {
			break;
		}
		next(state);
	}
}

/* parse an integer constant and return its value. */
long long expr_const(CPreprocessorState *state) {
	long long c = 0LL;
	expr_cond(state);
	if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) != VT_CONST) {
		expect("constant expression");
	}
	c = vtop->c.ll;
	return c;
}
