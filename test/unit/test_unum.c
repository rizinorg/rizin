// SPDX-FileCopyrightText: 2017 kriw <kotarou777775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_il/rz_il_opcodes.h>
#include <math.h>
#include "minunit.h"

static RzNum *num;

bool test_rz_num_units() {
	char humansz[8];
	const struct {
		const char *expected_res;
		const char *message;
		ut64 num;
	} test_cases[] = {
		{ "0", "B", 0ULL },
		{ "512", "B", 512ULL },
		{ "1K", "K", 1ULL << 10 },
		{ "1M", "M", 1ULL << 20 },
		{ "1G", "G", 1ULL << 30 },
		{ "1T", "T", 1ULL << 40 },
		{ "1P", "P", 1ULL << 50 },
		{ "1E", "E", 1ULL << 60 },
		/* Decimal test */
		{ "1.0K", "K", 1025 },
		{ "994K", "K", 994 * (1ULL << 10) },
		{ "999K", "K", 999 * (1ULL << 10) },
		{ "1.0M", "M", 1025 * (1ULL << 10) },
		{ "1.5M", "M", 1536 * (1ULL << 10) },
		{ "1.9M", "M", 1996 * (1ULL << 10) },
		{ "2.0M", "M", 1997 * (1ULL << 10) },
		{ "2.0M", "M", 2047 * (1ULL << 10) },
		{ "2M", "M", 2048 * (1ULL << 10) },
		{ "2.0M", "M", 2099 * (1ULL << 10) },
		{ "2.1M", "M", 2100 * (1ULL << 10) },
		{ "9.9G", "G", 10188 * (1ULL << 20) },
		/* Biggest units */
		{ "82P", "P", 82 * (1ULL << 50) },
		{ "16E", "E", UT64_MAX }
	};
	size_t nitems = sizeof(test_cases) / sizeof(test_cases[0]);
	size_t i;
	for (i = 0; i < nitems; i++) {
		rz_num_units(humansz, sizeof(humansz), test_cases[i].num);
		mu_assert_streq(humansz, test_cases[i].expected_res, test_cases[i].message);
	}
	mu_end;
}

bool test_rz_num_minmax_swap_i() {
	int a = -1, b = 2;
	rz_num_minmax_swap_i(&a, &b);
	mu_assert_eq(a == -1 && b == 2, 1, "a < b -> a < b");
	a = 2, b = -1;
	rz_num_minmax_swap_i(&a, &b);
	mu_assert_eq(a == -1 && b == 2, 1, "b < a -> a < b");
	mu_end;
}

bool test_rz_num_minmax_swap() {
	ut64 a = 1, b = 2;
	rz_num_minmax_swap(&a, &b);
	mu_assert_eq(a == 1 && b == 2, 1, "a < b -> a < b");
	a = 2, b = 1;
	rz_num_minmax_swap(&a, &b);
	mu_assert_eq(a == 1 && b == 2, 1, "b < a -> a < b");
	mu_end;
}

bool test_rz_num_between() {
	mu_assert_eq(rz_num_between(num, "1 2 3"), 1, "1 <= 2 <= 3");
	mu_assert_eq(rz_num_between(num, "3 2 1"), 0, "3 <= 2 <= 1");
	mu_assert_eq(rz_num_between(num, "1 1 1"), 1, "1 <= 1 <= 1");
	mu_assert_eq(rz_num_between(num, "2 1 3"), 0, "2 <= 1 <= 3");
	mu_assert_eq(rz_num_between(num, "1 2 1+2"), 1, "1 <= 2 <= 1+2");
	mu_assert_eq(rz_num_between(num, "2 3 1+2+3"), 1, "2 <= 3 <= 1+2+3");
	mu_assert_eq(rz_num_between(num, "1+2 2 1+1"), 0, "1+2 <= 2 <= 1+1");
	mu_assert_eq(rz_num_between(num, "1 + 2 2 1 + 1"), 0, "1 + 2 <= 2 <= 1 + 1");
	mu_end;
}

bool test_rz_num_str_len() {
	mu_assert_eq(rz_num_str_len("1"), 1, "\"1\"");
	mu_assert_eq(rz_num_str_len("1+1"), 3, "\"1+1\"");
	mu_assert_eq(rz_num_str_len("1 + 1"), 5, "\"1 + 1\"");
	mu_assert_eq(rz_num_str_len("1 + 1 "), 5, "\"1 + 1 \"");
	mu_assert_eq(rz_num_str_len("1 + 1  "), 5, "\"1 + 1  \"");
	mu_assert_eq(rz_num_str_len("1 + 1 1"), 5, "\"1 + 1 1\"");
	mu_assert_eq(rz_num_str_len("1 + 1 1 + 1"), 5, "\"1 + 1 1 + 1\"");
	mu_assert_eq(rz_num_str_len("1 + (1 + 1) 1"), 11, "\"1 + (1 + 1) 1\"");
	mu_assert_eq(rz_num_str_len("1 + (1 + (1 + 1)) 1"), 17, "\"1 + (1 + (1 + 1)) 1\"");
	mu_assert_eq(rz_num_str_len("1+(1+(1+1)) 1"), 11, "\"1+(1+(1+1)) 1\"");
	mu_assert_eq(rz_num_str_len("(1 + 1) + (1 + 1) 1"), 17, "\"(1 + 1) + (1 + 1) 1\"");
	mu_assert_eq(rz_num_str_len("(1+1)+(1+1) 1"), 11, "\"(1+1)+(1+1) 1\"");
	mu_end;
}

bool test_rz_num_str_split() {
	char *str = malloc(0x20);
	strcpy(str, "1 1 + 2 1 + (2 + 3) 4 ");
	// expected "1\01 + 2\01 + (2 + 3)\04\0"
	int count = rz_num_str_split(str);
	mu_assert_eq(count, 4, "rz_num_str_split (str) == 4");
	mu_assert_streq(str + 0, "1", "1");
	mu_assert_streq(str + 2, "1 + 2", "1 + 2");
	mu_assert_streq(str + 8, "1 + (2 + 3)", "1 + (2 + 3)");
	mu_assert_streq(str + 20, "4", "4");
	free(str);
	mu_end;
}

bool test_rz_num_str_split_list() {
	char *s;
	char *str = malloc(0x20);
	strcpy(str, "1 1 + 2 1 + (2 + 3) 4 ");
	// expected {"1", "1 + 2", "1 + (2 + 3)", "4"} as list
	RzList *list = rz_num_str_split_list(str);
	mu_assert_eq(rz_list_length(list), 4, "rz_list_length (list) == 4");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "1", "1");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "1 + 2", "1 + 2");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "1 + (2 + 3)", "1 + (2 + 3)");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "4", "4");
	free(str);
	rz_list_free(list);
	mu_end;
}

bool test_rz_num_align_delta() {
	ut64 d = rz_num_align_delta(0, 8);
	mu_assert_eq(d, 0, "align delta");
	d = rz_num_align_delta(3, 8);
	mu_assert_eq(d, 5, "align delta");
	d = rz_num_align_delta(0x10, 8);
	mu_assert_eq(d, 0, "align delta");
	d = rz_num_align_delta(0x11, 8);
	mu_assert_eq(d, 7, "align delta");
	d = rz_num_align_delta(0x42, 0);
	mu_assert_eq(d, 0, "align delta");
	mu_end;
}

bool test_rz_num_bitmask() {
	static const ut64 expect_masks[] = {
		0x0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff,
		0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff,
		0xfffff, 0x1fffff, 0x3fffff, 0x7fffff, 0xffffff, 0x1ffffffLL, 0x3ffffffLL,
		0x7ffffffLL, 0xfffffffLL, 0x1fffffffLL, 0x3fffffffLL, 0x7fffffffLL, 0xffffffffLL,
		0x1ffffffffLL, 0x3ffffffffLL, 0x7ffffffffLL, 0xfffffffffLL, 0x1fffffffffLL,
		0x3fffffffffLL, 0x7fffffffffLL, 0xffffffffffLL, 0x1ffffffffffLL, 0x3ffffffffffLL,
		0x7ffffffffffLL, 0xfffffffffffLL, 0x1fffffffffffLL, 0x3fffffffffffLL, 0x7fffffffffffLL,
		0xffffffffffffLL, 0x1ffffffffffffLL, 0x3ffffffffffffLL, 0x7ffffffffffffLL,
		0xfffffffffffffLL, 0x1fffffffffffffLL, 0x3fffffffffffffLL, 0x7fffffffffffffLL,
		0xffffffffffffffLL, 0x1ffffffffffffffLL, 0x3ffffffffffffffLL, 0x7ffffffffffffffLL,
		0xfffffffffffffffLL, 0x1fffffffffffffffLL, 0x3fffffffffffffffLL, 0x7fffffffffffffffLL, 0xffffffffffffffffLL
	};

	for (ut16 width = 0; width < 256; width++) {
		ut64 actual = rz_num_bitmask((ut8)width);
		ut64 expect = expect_masks[RZ_MIN(width, 64)];
		char msg[0x100];
		snprintf(msg, sizeof(msg), "bitmask of %u bits\n", (unsigned int)width);
		mu_assert_eq(actual, expect, msg);
	}

	mu_end;
}

bool test_rz_num_abs() {
	mu_assert_eq(rz_num_abs(ST64_MAX), ST64_MAX, "rz_num_abs(2^63 - 1) = 2^63 - 1");
	mu_assert_eq(rz_num_abs(0), 0, "rz_num_abs(0) = 0");
	mu_assert_eq(rz_num_abs(ST64_MIN), UT64_GT0, "rz_num_abs(-2^63) = 2^63");
	mu_end;
}

// ---------------------------------------------------------------------------
// rz_num_math_value() tests for the tree-sitter-based evaluator.
// ---------------------------------------------------------------------------

static ut64 test_var_cb(RzNum *self, const char *name, int *ok) {
	(void)self;
	if (!strcmp(name, "x")) {
		*ok = 1;
		return 10;
	}
	if (!strcmp(name, "y")) {
		*ok = 1;
		return 20;
	}
	if (!strcmp(name, "$$")) {
		*ok = 1;
		return 0x1000;
	}
	if (!strcmp(name, "$F")) {
		*ok = 1;
		return 0x2000;
	}
	if (!strcmp(name, "$S")) {
		*ok = 1;
		return 0x40000;
	}
	*ok = 0;
	return 0;
}

// Callback for the local-label test. It resolves a function-local
// ".label" relative to the value that precedes the '+', which the
// evaluator must place in nc.number_value.n (mirroring how the rizin
// core callback resolves `.foo` against the function at that address).
// It reads nc through `self`, so the test wires the RzNum's userptr to
// the RzNum itself, exactly as a host that needs nc would.
static ut64 label_cb(RzNum *self, const char *name, int *ok) {
	*ok = 0;
	if (!strcmp(name, "base")) {
		*ok = 1;
		return 0x1000;
	}
	// foo's absolute address is 0x1004; return it as a delta from the
	// base the evaluator handed us through nc.
	if (!strcmp(name, ".foo") && self && self->nc.curr_tok == '+') {
		*ok = 1;
		return 0x1004 - self->nc.number_value.n;
	}
	return 0;
}

#define ASSERT_U64(expr, want) \
	do { \
		RzNumValue _v; \
		rz_num_value_init(&_v); \
		char *_err = NULL; \
		bool _ok = rz_num_math_value(num_with_cb, (expr), &_v, &_err); \
		mu_assert_true(_ok, "evaluation failed: " expr); \
		mu_assert_eq(_v.kind, RZ_NUM_KIND_UT64, "wrong kind for: " expr); \
		mu_assert_eq(_v.val.n, (ut64)(want), "wrong ut64 result for: " expr); \
		rz_num_value_fini(&_v); \
		free(_err); \
	} while (0)

#define ASSERT_F64(expr, want) \
	do { \
		RzNumValue _v; \
		rz_num_value_init(&_v); \
		char *_err = NULL; \
		bool _ok = rz_num_math_value(num_with_cb, (expr), &_v, &_err); \
		mu_assert_true(_ok, "evaluation failed: " expr); \
		mu_assert_eq(_v.kind, RZ_NUM_KIND_FLOAT, "wrong kind for: " expr); \
		mu_assert_true(_v.val.d == (double)(want), "wrong float result for: " expr); \
		rz_num_value_fini(&_v); \
		free(_err); \
	} while (0)

#define ASSERT_FAIL(expr) \
	do { \
		RzNumValue _v; \
		rz_num_value_init(&_v); \
		char *_err = NULL; \
		bool _ok = rz_num_math_value(num_with_cb, (expr), &_v, &_err); \
		mu_assert_false(_ok, "should have failed: " expr); \
		rz_num_value_fini(&_v); \
		free(_err); \
	} while (0)

static RzNum *num_with_cb = NULL;

bool test_rz_num_math_value_integer_arith() {
	ASSERT_U64("1 + 2", 3);
	ASSERT_U64("1 + 2 * 3", 7);
	ASSERT_U64("(1 + 2) * 3", 9);
	ASSERT_U64("10 - 4", 6);
	ASSERT_U64("100 / 10", 10);
	ASSERT_U64("10 mod 3", 1);
	ASSERT_U64("10 % 3", 1);
	ASSERT_U64("0x10 + 0b1010", 0x1a);
	ASSERT_U64("0x10 + 0o10", 0x18);
	ASSERT_U64("0x10 + 0t10", 0x13);
	// C-style octal: a leading 0 followed by more digits is octal,
	// matching the legacy parser (used by e.g. `s 034`).
	ASSERT_U64("034", 28);
	ASSERT_U64("010", 8);
	ASSERT_U64("00120000", 0xa000); // 0o120000 == 40960
	ASSERT_U64("0", 0);
	ASSERT_U64("00", 0);
	ASSERT_U64("07 + 1", 8); // 0o7 + 1
	mu_end;
}

bool test_rz_num_math_value_bitwise() {
	ASSERT_U64("0xff & 0x0f", 0x0f);
	ASSERT_U64("0xf0 | 0x0f", 0xff);
	ASSERT_U64("0xff ^ 0xaa", 0x55);
	ASSERT_U64("~0", UT64_MAX);
	ASSERT_U64("~0xff", UT64_MAX & ~(ut64)0xff);
	ASSERT_U64("1 << 4", 16);
	ASSERT_U64("0x100 >> 4", 0x10);
	// Bitwise precedence: AND > XOR > OR
	ASSERT_U64("0x10 | 0x20 ^ 0x30 & 0xf0", 0x10 | (0x20 ^ (0x30 & 0xf0)));
	// Shift binds tighter than OR
	ASSERT_U64("1 | 2 << 4", 1 | (2 << 4));
	mu_end;
}

bool test_rz_num_math_value_rotate() {
	ASSERT_U64("1 <<< 60", 1ULL << 60);
	// Rotate by 64 == identity (the shift amount is masked to 6 bits)
	ASSERT_U64("0xdeadbeef <<< 64", 0xdeadbeef);
	ASSERT_U64("1 >>> 4", (1ULL >> 4) | (1ULL << (64 - 4)));
	mu_end;
}

bool test_rz_num_math_value_logical() {
	ASSERT_U64("!0", 1);
	ASSERT_U64("!1", 0);
	ASSERT_U64("!42", 0);
	ASSERT_U64("!(1 - 1)", 1);
	mu_end;
}

bool test_rz_num_math_value_unary_signs() {
	// Unary minus and plus are operators, not part of the literal.
	ASSERT_U64("-5", (ut64)(-5LL));
	ASSERT_U64("+5", 5);
	ASSERT_U64("-x", (ut64)(-10LL));
	ASSERT_U64("-(2 + 3)", (ut64)(-5LL));
	// Binary subtraction still binds correctly.
	ASSERT_U64("10 - 3", 7);
	ASSERT_U64("10 + -3", 7);
	ASSERT_U64("10 - +3", 7);
	mu_end;
}

bool test_rz_num_math_value_increment() {
	ASSERT_U64("++5", 6);
	ASSERT_U64("--5", 4);
	mu_end;
}

bool test_rz_num_math_value_floats() {
	// Float literals and mixed-kind arithmetic.
	ASSERT_F64("1.5 + 1.5", 3.0);
	ASSERT_F64("1 + 1.5", 2.5);
	ASSERT_F64("1.5 + 1", 2.5);
	ASSERT_F64("3.0 * 2.0", 6.0);
	ASSERT_F64("3.0 / 2.0", 1.5);
	ASSERT_F64("3.0 % 2.0", 1.0);
	ASSERT_F64("-1.5", -1.5);
	// Comparisons return ut64, even on float operands.
	ASSERT_U64("1.5 < 2.0", 1);
	ASSERT_U64("1.5 == 1.5", 1);
	ASSERT_U64("1.5 != 1.5", 0);
	mu_end;
}

bool test_rz_num_math_value_units() {
	ASSERT_U64("1KiB", 1024);
	ASSERT_U64("2MiB", 2 * 1024 * 1024);
	ASSERT_U64("3PiB", 3ULL << 50);
	ASSERT_U64("4EiB", 4ULL << 60);
	ASSERT_U64("1KB", 1000);
	ASSERT_U64("1MB", 1000000);
	ASSERT_U64("1GB", 1000000000ULL);
	mu_end;
}

bool test_rz_num_math_value_comparisons() {
	ASSERT_U64("1 < 2", 1);
	ASSERT_U64("2 < 1", 0);
	ASSERT_U64("1 <= 1", 1);
	ASSERT_U64("1 > 2", 0);
	ASSERT_U64("2 >= 2", 1);
	ASSERT_U64("3 == 3", 1);
	ASSERT_U64("3 != 4", 1);
	// Comparison composes with arithmetic.
	ASSERT_U64("(1 < 2) + (3 < 4)", 2);
	ASSERT_U64("(1 + 1) == 2", 1);
	mu_end;
}

bool test_rz_num_math_value_special_variables() {
	ASSERT_U64("$$", 0x1000);
	ASSERT_U64("$F", 0x2000);
	ASSERT_U64("$S", 0x40000);
	ASSERT_U64("$F + 0x10", 0x2010);
	ASSERT_U64("$$ * 2", 0x2000);
	mu_end;
}

// Function-local flags: `base + .foo` resolves .foo relative to the
// value before the '+'. The evaluator must publish that value through
// nc.number_value.n / nc.curr_tok so the host callback (here label_cb)
// can turn the absolute label address into a delta. (Regression: the
// new parser left nc untouched, so `s main+.foo` came out as `main`.)
bool test_rz_num_math_value_local_label() {
	RzNum *ln = rz_num_new(label_cb, NULL, NULL);
	mu_assert_notnull(ln, "rz_num_new");
	ln->userptr = ln; // a host that needs nc passes a ptr it can reach nc through

	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	bool ok = rz_num_math_value(ln, "base + .foo", &v, &err);
	mu_assert_true(ok, "base + .foo evaluates");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "ut64 result");
	mu_assert_eq(v.val.n, 0x1004, "base + .foo == foo's absolute address");
	rz_num_value_fini(&v);
	free(err);

	// And through the legacy entry point, since that is what `s` uses.
	mu_assert_eq(rz_num_math(ln, "base + .foo"), 0x1004, "rz_num_math base + .foo");

	rz_num_free(ln);
	mu_end;
}

// Regression: the host callback must receive the opaque userptr that
// was passed to rz_num_new() as its first argument - NOT the RzNum
// itself. RzCore's num_callback casts that first argument straight to
// RzCore*, so passing the RzNum would make it dereference a wrong
// pointer and crash. This callback dereferences its userptr to prove
// the right value is threaded through for plain and special
// variables alike.
typedef struct {
	ut64 magic;
	ut64 base;
} cb_host_ctx;

static ut64 userptr_var_cb(RzNum *self, const char *name, int *ok) {
	// 'self' is really the userptr (a cb_host_ctx*), exactly as
	// RzCore's callback treats it. Dereferencing it must be safe.
	cb_host_ctx *ctx = (cb_host_ctx *)self;
	if (!ctx || ctx->magic != 0xC0FFEE) {
		*ok = 0;
		return 0;
	}
	if (!strcmp(name, "base")) {
		*ok = 1;
		return ctx->base;
	}
	if (!strcmp(name, "$$")) {
		*ok = 1;
		return ctx->base + 0x10;
	}
	*ok = 0;
	return 0;
}

bool test_rz_num_math_value_callback_userptr() {
	cb_host_ctx ctx = { .magic = 0xC0FFEE, .base = 0x4000 };
	RzNum *n = rz_num_new(userptr_var_cb, NULL, &ctx);
	mu_assert_notnull(n, "rz_num_new");

	RzNumValue v;
	char *err = NULL;

	// Plain variable: the callback reads ctx->base via the userptr.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(n, "base + 1", &v, &err),
		"base + 1 resolves via userptr");
	mu_assert_eq(rz_num_value_to_ut64(&v), 0x4001, "base + 1 == 0x4001");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Special variable: same userptr path.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(n, "$$ + 4", &v, &err),
		"$$ + 4 resolves via userptr");
	mu_assert_eq(rz_num_value_to_ut64(&v), 0x4014, "$$ + 4 == 0x4014");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// An unknown name still resolves to 0 without touching anything
	// unsafe (the callback sets ok=0).
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(n, "unknown_name + 7", &v, &err),
		"unknown var resolves to 0");
	mu_assert_eq(rz_num_value_to_ut64(&v), 7, "unknown + 7 == 7");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_free(n);
	mu_end;
}

bool test_rz_num_math_value_string_bytes() {
	// A string-bytes literal now evaluates to a bit-vector whose
	// width is 8 * byte-count, packed little-endian (first source
	// byte is the LSB). This makes len() recover the byte count and
	// lets the value take part in width-aware bit-vector arithmetic.
	RzNumValue v;
	char *err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(num, "\"AB\"", &v, &err), "\"AB\"");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "\"AB\" is bitvector");
	mu_assert_eq(rz_bv_len(v.val.bv), 16, "\"AB\" width 16");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x4241, "\"AB\" value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(num, "\"A\"", &v, &err), "\"A\"");
	mu_assert_eq(rz_bv_len(v.val.bv), 8, "\"A\" width 8");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x41, "\"A\" value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(num, "\"\\x41\\x42\"", &v, &err), "hex escapes");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x4241, "hex-escape value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Arithmetic keeps the bit-vector width: "AB" is 16-bit, so + 1
	// wraps within 16 bits.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(num, "\"AB\" + 1", &v, &err), "\"AB\" + 1");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "\"AB\" + 1 is bitvector");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x4242, "\"AB\" + 1 value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A longer string than would fit a ut64 is now representable.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(num, "\"ABCDEFGHIJ\"", &v, &err), "10-byte string");
	mu_assert_eq(rz_bv_len(v.val.bv), 80, "10-byte string width 80");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_reserved_words() {
	// Bare reserved words must error, not silently resolve to 0.
	ASSERT_FAIL("mod");
	ASSERT_FAIL("log");
	ASSERT_FAIL("le");
	ASSERT_FAIL("be");
	// Identifiers with reserved-word prefix are valid (longest match).
	// `modulus` resolves to 0 (no callback hit) but does not error.
	ASSERT_U64("modulus", 0);
	ASSERT_U64("logger", 0);
	ASSERT_U64("letter", 0);
	// `let` is a true parser keyword: bare use is a parse error.
	ASSERT_FAIL("let");
	mu_end;
}

bool test_rz_num_math_value_errors() {
	ASSERT_FAIL("");
	ASSERT_FAIL("1 +");
	ASSERT_FAIL("(1 +");
	ASSERT_FAIL("1 / 0");
	ASSERT_FAIL("$nonexistent_special_var");
	mu_end;
}

bool test_rz_num_math_value_assignment() {
	// Assignment evaluates to the RHS value.
	ASSERT_U64("x = 5", 5);
	ASSERT_U64("let y = 7", 7);
	ASSERT_U64("x = 1 + 2 * 3", 7);

	// The binding is readable later in the same expression.
	ASSERT_U64("(x = 7) + x", 14);
	ASSERT_U64("(a = 2) * (a + 1)", 6);
	ASSERT_U64("let n = 0x10 + n", 0x10); // n unknown on RHS -> 0

	// Reassignment updates the binding.
	ASSERT_U64("(c = 1) + (c = 9) + c", 19); // 1 + 9 + 9

	// A bignum can be bound and read back at full precision.
	RzNumValue v;
	char *err = NULL;
	bool ok = rz_num_math_value(NULL,
		"(big = 0x10000000000000000) + (big - big)", &v, &err);
	mu_assert_true(ok, "bignum binding");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "bound bignum stays BIG");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A reserved word cannot be assigned.
	mu_assert_false(rz_num_math_value(NULL, "mod = 5", &v, &err),
		"reserved word assignment");
	mu_assert_eq(v.err, RZ_NUM_ERR_RESERVED_WORD, "mod= -> RESERVED_WORD");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_sequence() {
	// ';' separates statements; the value of the whole is the value
	// of the last. Earlier statements run for their side effects
	// (bindings).
	ASSERT_U64("1 + 2; 3 + 4", 7);
	ASSERT_U64("let x = 5; x * 2", 10);
	ASSERT_U64("x = 10; y = 20; x + y", 30);
	// Bindings made earlier in the sequence are visible later.
	ASSERT_U64("a = 3; b = a * a; a + b", 12);
	// A trailing ';' is allowed.
	ASSERT_U64("1 + 1;", 2);
	// A single statement (no ';') is unchanged.
	ASSERT_U64("6 * 7", 42);
	mu_end;
}

bool test_rz_num_math_value_conditional() {
	// Basic selection on a truthy / falsy integer condition.
	ASSERT_U64("1 ? 10 : 20", 10);
	ASSERT_U64("0 ? 10 : 20", 20);
	ASSERT_U64("5 ? 0xaa : 0xbb", 0xaa); // any non-zero is true

	// The condition is usually a comparison.
	ASSERT_U64("5 > 3 ? 100 : 200", 100);
	ASSERT_U64("5 < 3 ? 100 : 200", 200);
	ASSERT_U64("(7 & 1) ? 1 : 2", 1);

	// Right-associative: a ? b : c ? d : e == a ? b : (c ? d : e).
	ASSERT_U64("0 ? 1 : 0 ? 2 : 3", 3);
	ASSERT_U64("0 ? 1 : 1 ? 2 : 3", 2);
	ASSERT_U64("1 ? 2 : 1 ? 3 : 4", 2);

	// Branches can be arbitrary sub-expressions and nest.
	ASSERT_U64("1 ? 2 + 3 : 4 * 5", 5);
	ASSERT_U64("0 ? 2 + 3 : 4 * 5", 20);
	ASSERT_U64("(2 > 1 ? 3 : 4) + 10", 13);

	// Short-circuit: the untaken branch is NOT evaluated, so a
	// division by zero there must not trigger an error.
	ASSERT_U64("1 ? 42 : 1 / 0", 42);
	ASSERT_U64("0 ? 1 / 0 : 42", 42);

	// Float condition is tested as a float: 0.0 is false, any other
	// value (even one whose integer truncation is 0) is true.
	ASSERT_U64("0.5 ? 7 : 8", 7);
	ASSERT_U64("0.0 ? 7 : 8", 8);

	// The selected branch keeps its own kind.
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "1 ? 5u8 : 9u8", &v, &err),
		"bitvector branch");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "ternary yields bitvector");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 5, "1 ? 5u8 : 9u8 == 5u8");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A big-number branch is returned exact.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0 ? 1 : 2 ** 100", &v, &err),
		"bignum branch");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "ternary yields big");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_signed_arith() {
	// Signed division / remainder over the ut64 domain interpreted
	// as two's-complement st64. 0xffff...fb is -5.
	ASSERT_U64("0xfffffffffffffffb sdiv 2", (ut64)(-2)); // -5 / 2 = -2
	ASSERT_U64("10 sdiv 3", 3);
	ASSERT_U64("0xfffffffffffffffb smod 3", (ut64)(-2)); // -5 % 3 = -2
	ASSERT_U64("10 smod 3", 1);
	// Unsigned division differs from signed for "negative" operands.
	ASSERT_U64("0xfffffffffffffffb / 2", 0xfffffffffffffffb / 2);

	// Arithmetic (sign-propagating) shift right.
	ASSERT_U64("256 sar 2", 64); // positive: same as logical
	ASSERT_U64("65280 sar 4", 4080);
	ASSERT_U64("0xffffffffffffff00 sar 4", 0xfffffffffffffff0); // -256 >> 4 = -16
	ASSERT_U64("0xffffffffffffffff sar 4", 0xffffffffffffffff); // -1 stays -1
	// Logical >> on the same value does NOT sign-extend.
	ASSERT_U64("0xffffffffffffff00 >> 4", 0x0ffffffffffffff0);

	// Division / modulo by zero is trapped for the signed ops too.
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(NULL, "5 sdiv 0", &v, &err), "sdiv by zero");
	mu_assert_eq(v.err, RZ_NUM_ERR_DIV_ZERO, "sdiv 0 -> DIV_ZERO");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;
	mu_assert_false(rz_num_math_value(NULL, "5 smod 0", &v, &err), "smod by zero");
	mu_assert_eq(v.err, RZ_NUM_ERR_DIV_ZERO, "smod 0 -> DIV_ZERO");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// sdiv / smod / sar are reserved and cannot be variable names.
	mu_assert_false(rz_num_math_value(NULL, "sdiv = 1", &v, &err), "sdiv reserved");
	mu_assert_eq(v.err, RZ_NUM_ERR_RESERVED_WORD, "sdiv -> RESERVED_WORD");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_len() {
	// len() of a bit-vector is its width in BITS.
	ASSERT_U64("len(5u8)", 8);
	ASSERT_U64("len(0xffu16)", 16);
	ASSERT_U64("len(1u32)", 32);
	// A string literal is a bit-vector of 8 * byte-count; len gives
	// the bit count and len()/8 the byte count.
	ASSERT_U64("len(\"ABCD\")", 32);
	ASSERT_U64("len(\"ABCD\") / 8", 4);
	ASSERT_U64("len(\"ABCDEFGHIJ\") / 8", 10); // longer than a ut64
	// len of a big number is its significant bit width.
	ASSERT_U64("len(2 ** 100)", 101);
	// len of a plain ut64 is its significant bit width.
	ASSERT_U64("len(0xff)", 8);
	ASSERT_U64("len(0)", 0);

	// len on a float is a type error.
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(NULL, "len(1.5)", &v, &err), "len on float");
	mu_assert_eq(v.err, RZ_NUM_ERR_TYPE_MISMATCH, "len(float) -> TYPE_MISMATCH");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_persistent_vars() {
	// A caller-supplied store makes bindings survive across separate
	// rz_num_math_value_ex() calls.
	HtSP *store = rz_num_value_store_new();
	mu_assert_notnull(store, "store created");

	RzNumValue v;
	char *err = NULL;
	RzNumMathOptions opt = { 0 };
	opt.vars = store;

	// Call 1: bind.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value_ex(NULL, "base = 0x1000", &opt, &v, &err), "bind base");
	mu_assert_eq(rz_num_value_to_ut64(&v), 0x1000, "base value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Call 2: read the persisted binding.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value_ex(NULL, "base + 0x20", &opt, &v, &err), "read base");
	mu_assert_eq(rz_num_value_to_ut64(&v), 0x1020, "persisted base + 0x20");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Call 3: bind another using the persisted one, then read it.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value_ex(NULL, "top = base + 0x100", &opt, &v, &err), "bind top");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value_ex(NULL, "top - base", &opt, &v, &err), "read top");
	mu_assert_eq(rz_num_value_to_ut64(&v), 0x100, "top - base");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_store_free(store);

	// Without a store, a binding does NOT persist to the next call.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "ephem = 42", &v, &err), "ephemeral bind");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "ephem + 1", &v, &err), "ephem unknown");
	mu_assert_eq(rz_num_value_to_ut64(&v), 1, "ephem resolves to 0 -> 1"); // unknown var -> 0
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_address_typed() {
	// V1 limitation: dereference is not implemented, so the
	// literal address (the part before the colon) is returned.
	ASSERT_U64("0x1234:le32", 0x1234);
	ASSERT_U64("0x1000:8", 0x1000);
	ASSERT_U64("0x10:le32 + 4", 0x14);
	mu_end;
}

bool test_rz_num_math_value_bignum_arith() {
	RzNumValue v;
	char *err = NULL;

	// Bignum * bignum, checked via exact decimal.
	bool ok = rz_num_math_value(NULL,
		"0x10000000000000000 * 0x10000000000000000", &v, &err);
	mu_assert_true(ok, "big * big");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "big*big is BIG");
	char *dec = rz_big_to_decstr(v.val.big);
	// (2^64)^2 == 2^128
	mu_assert_streq_free(dec,
		"340282366920938463463374607431768211456", "2^128 exact");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Bignum + ut64 stays exact.
	ok = rz_num_math_value(NULL, "0x10000000000000000 + 5", &v, &err);
	mu_assert_true(ok, "big + ut64");
	dec = rz_big_to_decstr(v.val.big);
	mu_assert_streq_free(dec, "18446744073709551621", "2^64 + 5");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Bignum subtraction that demotes back to ut64 when it fits.
	ok = rz_num_math_value(NULL,
		"0x10000000000000000 - 0x10000000000000000", &v, &err);
	mu_assert_true(ok, "big - big");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "demotes to ut64");
	mu_assert_eq(v.val.n, 0, "2^64 - 2^64 == 0");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Decimal bignum literal round-trips through the decstr.
	ok = rz_num_math_value(NULL,
		"123456789012345678901234567890", &v, &err);
	mu_assert_true(ok, "decimal bignum literal");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "decimal overflow -> BIG");
	dec = rz_big_to_decstr(v.val.big);
	mu_assert_streq_free(dec, "123456789012345678901234567890",
		"decimal literal round-trip");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_complex_exprs() {
	// Precedence and nesting sanity, all exact ut64.
	ASSERT_U64("1 + 2 * 3 - 4 / 2", 5);
	ASSERT_U64("((1 + 2) * (3 + 4))", 21);
	ASSERT_U64("0xff & 0x0f | 0x30", 0x3f);
	ASSERT_U64("(1 << 8) + (1 << 4) + 1", 0x111);
	ASSERT_U64("2 ** 3 ** 2", 512); // right-assoc: 2 ** (3 ** 2) == 2**9
	ASSERT_U64("min(max(1, 9), max(2, 3))", 3);
	ASSERT_U64("popcount(0xffff) + popcount(0xff)", 24);
	ASSERT_U64("(0x10 > 0x8) + (0x8 > 0x10)", 1); // true + false
	mu_end;
}

bool test_rz_num_math_value_bitvector() {
	RzNumValue v;
	char *err = NULL;

	// A width-suffixed literal produces a bit-vector of that width.
	bool ok = rz_num_math_value(NULL, "5u8", &v, &err);
	mu_assert_true(ok, "5u8");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "5u8 is bitvector");
	mu_assert_eq(rz_bv_len(v.val.bv), 8, "width 8");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 5, "value 5");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

#define ASSERT_BV(expr, want_width, want_val) \
	do { \
		RzNumValue _v; \
		char *_e = NULL; \
		bool _ok = rz_num_math_value(NULL, (expr), &_v, &_e); \
		mu_assert_true(_ok, expr); \
		mu_assert_eq(_v.kind, RZ_NUM_KIND_BITVECTOR, expr " kind"); \
		mu_assert_eq(rz_bv_len(_v.val.bv), (want_width), expr " width"); \
		mu_assert_eq(rz_bv_to_ut64(_v.val.bv), (want_val), expr " value"); \
		rz_num_value_fini(&_v); \
		free(_e); \
	} while (0)

	// Arithmetic wraps modulo the operand width.
	ASSERT_BV("200u8 + 100u8", 8, 44); // 300 mod 256
	ASSERT_BV("0xffu8 + 1u8", 8, 0); // overflow wraps to 0
	ASSERT_BV("0xffffu16 + 1u16", 16, 0);
	ASSERT_BV("100u8 - 50u8", 8, 50);
	ASSERT_BV("10u16 * 10u16", 16, 100);
	ASSERT_BV("10u8 / 3u8", 8, 3);
	ASSERT_BV("10u8 % 3u8", 8, 1);

	// Bitwise and shifts.
	ASSERT_BV("5u8 & 3u8", 8, 1);
	ASSERT_BV("5u8 | 2u8", 8, 7);
	ASSERT_BV("5u8 ^ 1u8", 8, 4);
	ASSERT_BV("1u8 << 4u8", 8, 16);
	ASSERT_BV("0x80u8 >> 3u8", 8, 16);

	// Mixing a bit-vector with a plain ut64 keeps the bit-vector
	// width.
	ASSERT_BV("5u8 + 3", 8, 8);
	ASSERT_BV("3 + 5u8", 8, 8);

	// A wide bit-vector survives at full width.
	ASSERT_BV("0x123456789abcu64", 64, 0x123456789abcULL);

#undef ASSERT_BV

	// Comparisons on bit-vectors return a ut64 boolean.
	ASSERT_U64("5u8 == 5u8", 1);
	ASSERT_U64("5u8 != 6u8", 1);
	ASSERT_U64("5u8 < 10u8", 1);
	ASSERT_U64("10u8 > 5u8", 1);
	ASSERT_U64("5u8 <= 5u8", 1);
	ASSERT_U64("5u8 >= 6u8", 0);

	// Division by zero on a bit-vector is reported.
	ok = rz_num_math_value(NULL, "1u8 / 0u8", &v, &err);
	mu_assert_false(ok, "bv div by zero fails");
	mu_assert_eq(v.err, RZ_NUM_ERR_DIV_ZERO, "bv div zero -> DIV_ZERO");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// ** on a bit-vector is modular at the operand width: it is
	// computed by iterative squaring entirely within W bits, so a
	// power that overflows wraps rather than failing.
	ok = rz_num_math_value(NULL, "2u8 ** 3u8", &v, &err);
	mu_assert_true(ok, "bv ** succeeds");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "bv ** -> bitvector");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 8, "2u8 ** 3u8 == 8u8");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;
	// Overflow wraps modulo 2^W.
	ok = rz_num_math_value(NULL, "2u8 ** 8u8", &v, &err);
	mu_assert_true(ok, "bv ** overflow ok");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0, "2u8 ** 8u8 wraps to 0");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_bignum() {
	// Hex literal that overflows ut64 is promoted to BIG.
	RzNumValue v;
	rz_num_value_init(&v);
	char *err = NULL;

	bool ok = rz_num_math_value(NULL, "0x10000000000000000", &v, &err);
	mu_assert_true(ok, "parse 65-bit hex");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "65-bit hex is BIG kind");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Arithmetic on a BIG operand stays in BIG when the result
	// also exceeds ut64.
	ok = rz_num_math_value(NULL, "0x10000000000000000 * 2", &v, &err);
	mu_assert_true(ok, "BIG * 2");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "BIG * 2 stays BIG");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Arithmetic that brings a BIG operand back inside ut64 must
	// demote to UT64. 0x10000000000000001 - 2 == 0xffffffffffffffff.
	ok = rz_num_math_value(NULL, "0x10000000000000001 - 2", &v, &err);
	mu_assert_true(ok, "BIG - small demotes");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "result fits in ut64");
	mu_assert_eq(v.val.n, 0xffffffffffffffffULL, "result value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Comparisons between BIG and UT64 work without losing precision.
	ok = rz_num_math_value(NULL,
		"0x10000000000000000 > 0xffffffffffffffff", &v, &err);
	mu_assert_true(ok, "BIG > UT64");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "compare result is ut64");
	mu_assert_eq(v.val.n, 1, "2^64 > 2^64-1");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Large decimal literal that overflows ut64 is also promoted to
	// BIG (was an error in earlier versions; the evaluator now
	// shift-and-adds through rz_big_mul / rz_big_add).
	ok = rz_num_math_value(NULL,
		"99999999999999999999999999999999", &v, &err);
	mu_assert_true(ok, "large decimal parses");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "decimal overflow -> BIG");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Round-trip: a decimal bignum can be used in arithmetic. 10^40
	// divided by 10 is still 10^39, which exceeds ut64 and stays
	// BIG.
	ok = rz_num_math_value(NULL,
		"10000000000000000000000000000000000000000 / 10", &v, &err);
	mu_assert_true(ok, "decimal bignum / 10");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "still BIG after /10");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Binary literal that overflows ut64 also promotes:
	// 2^65 in binary = '1' followed by 65 zeros.
	ok = rz_num_math_value(NULL,
		"0b100000000000000000000000000000000000000000000000000000000000000000",
		&v, &err);
	mu_assert_true(ok, "binary overflow promotes");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "binary overflow -> BIG");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Float-with-big still demotes to float (float kind is the
	// highest-precision-loss kind so it wins).
	ok = rz_num_math_value(NULL, "0x10000000000000000 + 0.5", &v, &err);
	mu_assert_true(ok, "BIG + float");
	mu_assert_eq(v.kind, RZ_NUM_KIND_FLOAT, "float wins over big");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// rz_num_math_ut64 projects BIG back to ut64 by truncation.
	ut64 truncated = rz_num_math(num, "0x10000000000000001");
	mu_assert_eq(truncated, 1, "BIG truncated to low 64 bits");

	// Exact integer exponentiation: 2 ** 64 must be the exact
	// bignum, not the double approximation. Verify via the decimal
	// stringifier.
	ok = rz_num_math_value(NULL, "2 ** 64", &v, &err);
	mu_assert_true(ok, "2 ** 64");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "2^64 is BIG");
	char *dec = rz_big_to_decstr(v.val.big);
	mu_assert_streq_free(dec, "18446744073709551616", "exact 2^64");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// 10 ** 40 is exact.
	ok = rz_num_math_value(NULL, "10 ** 40", &v, &err);
	mu_assert_true(ok, "10 ** 40");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "10^40 is BIG");
	dec = rz_big_to_decstr(v.val.big);
	mu_assert_streq_free(dec,
		"10000000000000000000000000000000000000000", "exact 10^40");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Small integer powers stay ut64.
	ASSERT_U64("2 ** 10", 1024);
	ASSERT_U64("3 ** 5", 243);
	ASSERT_U64("2 ** 0", 1);
	ASSERT_U64("0 ** 0", 1);
	ASSERT_U64("5 ** 1", 5);

	// Boundary of the fixed 4096-bit bignum. 2 ** 4095 is the widest
	// power of two that still fits exactly (1233 decimal digits); it
	// must be an exact BIG, not a truncated value and not a float.
	ok = rz_num_math_value(NULL, "2 ** 4095", &v, &err);
	mu_assert_true(ok, "2 ** 4095");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "2^4095 is BIG");
	dec = rz_big_to_decstr(v.val.big);
	mu_assert_notnull(dec, "2^4095 decstr");
	mu_assert_eq((ut64)strlen(dec), (ut64)1233, "2^4095 digit count");
	free(dec);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// One bit past the ceiling: 2 ** 4096 is 4097 bits and cannot be
	// represented exactly, so the evaluator deliberately falls back
	// to the bounded double path (yielding +inf) rather than silently
	// truncating to a wrong integer. This guards the overflow check.
	ok = rz_num_math_value(NULL, "2 ** 4096", &v, &err);
	mu_assert_true(ok, "2 ** 4096 evaluates");
	mu_assert_eq(v.kind, RZ_NUM_KIND_FLOAT, "2^4096 overflows to float");
	mu_assert_true(isinf(v.val.d), "2^4096 is +inf");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A float operand forces the double path; the result is float.
	ok = rz_num_math_value(NULL, "2 ** 0.5", &v, &err);
	mu_assert_true(ok, "2 ** 0.5");
	mu_assert_eq(v.kind, RZ_NUM_KIND_FLOAT, "fractional exponent -> float");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_timeout() {
	// A long chain of additions that should take measurably more
	// than 1 ms in a debug build. We assert the timeout fires; on
	// hosts so fast that even the chain completes within 1 ms (an
	// optimised release build on a recent CPU) the assertion would
	// flake, so we skip in that case.
	//
	// The intent here is documentary: keep the test in the suite so
	// that anyone tweaking the deadline-check cadence in eval_node
	// can verify the path still fires, while staying robust on
	// future hardware.
	const int N = 3000;
	char *buf = malloc(64 * N);
	mu_assert_notnull(buf, "allocation");
	int p = 0;
	buf[p++] = '0';
	for (int i = 0; i < N; i++) {
		buf[p++] = '+';
		buf[p++] = '1';
	}
	buf[p] = 0;

	// Baseline: no timeout -> the expression completes and we time
	// how long it took, so we can decide whether a 1 ms budget is
	// expected to trip.
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	RzNumMathOptions opt = { .timeout_ms = 0 };
	ut64 t0 = rz_time_now_mono();
	bool ok = rz_num_math_value_ex(NULL, buf, &opt, &v, &err);
	ut64 elapsed_us = rz_time_now_mono() - t0;
	mu_assert_true(ok, "no timeout completes");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "result is ut64");
	mu_assert_eq(v.val.n, (ut64)N, "result value");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	if (elapsed_us > 5000) {
		// The host is slow enough that a 1 ms budget will reliably
		// trip. Assert that it does.
		opt.timeout_ms = 1;
		rz_num_value_init(&v);
		ok = rz_num_math_value_ex(NULL, buf, &opt, &v, &err);
		mu_assert_false(ok, "1ms timeout aborts");
		mu_assert_eq(v.err, RZ_NUM_ERR_TIMEOUT, "1ms -> TIMEOUT");
		rz_num_value_fini(&v);
		free(err);
	}
	free(buf);
	mu_end;
}

bool test_rz_num_math_value_error_codes() {
	// Each category of failure should populate out_value.err with a
	// matching RzNumError, so that callers can dispatch on the
	// category without sniffing the error string.
	RzNumValue v;
	char *err = NULL;

	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(NULL, "", &v, &err), "empty");
	mu_assert_eq(v.err, RZ_NUM_ERR_EMPTY, "empty -> RZ_NUM_ERR_EMPTY");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "1 +", &v, &err), "truncated");
	mu_assert_eq(v.err, RZ_NUM_ERR_PARSE, "truncated -> RZ_NUM_ERR_PARSE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "1 / 0", &v, &err), "div by zero");
	mu_assert_eq(v.err, RZ_NUM_ERR_DIV_ZERO, "div0 -> RZ_NUM_ERR_DIV_ZERO");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "5 % 0", &v, &err), "mod by zero");
	mu_assert_eq(v.err, RZ_NUM_ERR_DIV_ZERO, "mod0 -> RZ_NUM_ERR_DIV_ZERO");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "mod", &v, &err), "reserved word");
	mu_assert_eq(v.err, RZ_NUM_ERR_RESERVED_WORD, "mod -> RZ_NUM_ERR_RESERVED_WORD");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "$nonexistent_var", &v, &err),
		"unknown special variable");
	// The grammar's special_variable rule is a closed alternation
	// (see grammar.js), so an unknown $-name is a SYNTAX error rather
	// than a runtime evaluator error - the parser cannot match it
	// against any alternative. The RZ_NUM_ERR_UNDEFINED_VAR category
	// is reserved for the case where the parser DID match a known
	// special variable but the host's callback does not provide a
	// value for it (NULL host or callback returns ok=false).
	mu_assert_eq(v.err, RZ_NUM_ERR_PARSE,
		"$nonexistent_var -> RZ_NUM_ERR_PARSE (closed-list grammar)");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "foo(1, 2)", &v, &err),
		"unknown function");
	mu_assert_eq(v.err, RZ_NUM_ERR_NOT_IMPLEMENTED,
		"foo() -> RZ_NUM_ERR_NOT_IMPLEMENTED");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Decimal literal overflow is now supported via shift-and-add
	// bignum promotion. RZ_NUM_ERR_OVERFLOW is reserved for cases
	// where even the bignum path could not handle the literal -
	// today none of the supported bases can hit that, but the
	// category remains for future fixed-precision literal kinds
	// (e.g. user-specified bit-vector widths).
	mu_assert_true(rz_num_math_value(NULL,
			       "99999999999999999999999999999999", &v, &err),
		"decimal overflow no longer errors");
	mu_assert_eq(v.err, RZ_NUM_ERR_OK,
		"decimal overflow -> OK (promoted to BIG)");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(NULL, "0 log 5", &v, &err),
		"log with bad base");
	mu_assert_eq(v.err, RZ_NUM_ERR_UNCOMPUTABLE,
		"log(0) -> RZ_NUM_ERR_UNCOMPUTABLE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// On success, err must be RZ_NUM_ERR_OK.
	mu_assert_true(rz_num_math_value(NULL, "1 + 2", &v, &err), "valid");
	mu_assert_eq(v.err, RZ_NUM_ERR_OK, "valid -> RZ_NUM_ERR_OK");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

// --- helpers for the custom-function / IO-callback tests ---

static void tfn_triple(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	(void)user;
	if (argc != 1) {
		out->ok = false;
		return;
	}
	out->ok = true;
	out->kind = RZ_NUM_KIND_UT64;
	out->val.n = args[0].val.n * 3;
}

static void tfn_pow2(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	(void)user;
	if (argc != 1) {
		out->ok = false;
		return;
	}
	RzNumBig *base = rz_big_new();
	RzNumBig *e = rz_big_new();
	RzNumBig *r = rz_big_new();
	rz_big_from_int(base, 2);
	rz_big_from_int(e, (st64)args[0].val.n);
	rz_big_pow(r, base, e);
	rz_big_free(base);
	rz_big_free(e);
	out->ok = true;
	out->kind = RZ_NUM_KIND_BIG;
	out->val.big = r;
}

static void tfn_fail(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	(void)user;
	(void)args;
	(void)argc;
	out->ok = false; // always signals an error
}

// Variadic: sum of all ut64 arguments. Used to prove the registry
// accepts arity -1 and that a call may pass an arbitrary number of
// arguments (beyond the small inline buffer the evaluator uses).
static void tfn_sum(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	(void)user;
	ut64 s = 0;
	for (int i = 0; i < argc; i++) {
		s += args[i].val.n;
	}
	out->ok = true;
	out->kind = RZ_NUM_KIND_UT64;
	out->val.n = s;
}

// Fake IO reader: synthesise raw bytes for the requested address.
// The conceptual value at `addr` is `addr ^ 0xcafe`, written in
// little-endian byte order into `buf` (so a `:le32` decode yields
// `(addr ^ 0xcafe) & 0xffffffff` and a `:beN` decode of the same
// bytes returns its byte-reversed form). The callback returns the
// number of bytes actually written, matching RzPfReadAtCb.
static int tio_read(void *user, ut64 addr, ut8 *buf, int len) {
	(void)user;
	ut64 v = addr ^ 0xcafe;
	for (int i = 0; i < len; i++) {
		buf[i] = (i < 8) ? (ut8)(v >> (8 * i)) : 0;
	}
	return len;
}

bool test_rz_num_math_value_custom_funcs() {
	RzNumFuncRegistry *reg = rz_num_func_registry_new();
	mu_assert_notnull(reg, "registry alloc");
	mu_assert_true(rz_num_func_registry_add(reg, "triple", 1, tfn_triple, NULL),
		"register triple");
	mu_assert_true(rz_num_func_registry_add(reg, "pow2", 1, tfn_pow2, NULL),
		"register pow2");
	mu_assert_true(rz_num_func_registry_add(reg, "boom", 0, tfn_fail, NULL),
		"register boom");

	RzNumMathOptions opt = { .funcs = reg };
	RzNumValue v;
	char *err = NULL;

	// Simple custom ut64 function.
	mu_assert_true(rz_num_math_value_ex(NULL, "triple(7)", &opt, &v, &err),
		"triple(7)");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "triple kind");
	mu_assert_eq(v.val.n, 21, "triple(7) == 21");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Custom function used as a sub-expression.
	mu_assert_true(rz_num_math_value_ex(NULL, "triple(7) + 1", &opt, &v, &err),
		"triple in expr");
	mu_assert_eq(v.val.n, 22, "triple(7)+1 == 22");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Custom function returning a bignum.
	mu_assert_true(rz_num_math_value_ex(NULL, "pow2(100)", &opt, &v, &err),
		"pow2(100)");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BIG, "pow2(100) is BIG");
	char *dec = rz_big_to_decstr(v.val.big);
	mu_assert_streq_free(dec,
		"1267650600228229401496703205376", "pow2(100) exact");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Built-ins still resolve alongside the registry.
	mu_assert_true(rz_num_math_value_ex(NULL, "min(3, 7)", &opt, &v, &err),
		"built-in min still works");
	mu_assert_eq(v.val.n, 3, "min(3,7) == 3");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Nesting a built-in inside a custom function.
	mu_assert_true(rz_num_math_value_ex(NULL, "triple(min(2, 5))", &opt, &v, &err),
		"nest builtin in custom");
	mu_assert_eq(v.val.n, 6, "triple(min(2,5)) == 6");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A callback that signals failure surfaces RZ_NUM_ERR_UNCOMPUTABLE.
	mu_assert_false(rz_num_math_value_ex(NULL, "boom()", &opt, &v, &err),
		"failing callback");
	mu_assert_eq(v.err, RZ_NUM_ERR_UNCOMPUTABLE, "boom -> UNCOMPUTABLE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Arity mismatch on a custom function.
	mu_assert_false(rz_num_math_value_ex(NULL, "triple(1, 2)", &opt, &v, &err),
		"wrong arity");
	mu_assert_eq(v.err, RZ_NUM_ERR_NOT_IMPLEMENTED, "arity -> NOT_IMPLEMENTED");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A function may be registered under a non-ASCII (Unicode) name
	// and is then callable by that name. The name is copied as UTF-8,
	// so any identifier the grammar accepts works.
	//   \u0441\u0443\u043c\u043c\u0430 = Cyrillic "summa" (sum)
	//   \u5408\u8ba1               = CJK "total"
	mu_assert_true(rz_num_func_registry_add(reg,
			       "\u0441\u0443\u043c\u043c\u0430", -1, tfn_sum, NULL),
		"register Cyrillic-named function");
	mu_assert_true(rz_num_func_registry_add(reg,
			       "\u5408\u8ba1", -1, tfn_sum, NULL),
		"register CJK-named function");

	mu_assert_true(rz_num_math_value_ex(NULL,
			       "\u0441\u0443\u043c\u043c\u0430(1, 2, 3)", &opt, &v, &err),
		"call Cyrillic-named function");
	mu_assert_eq(v.val.n, 6, "summa(1,2,3) == 6");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A Unicode-named function nests with the rest of the language.
	mu_assert_true(rz_num_math_value_ex(NULL,
			       "\u5408\u8ba1(10, 20) * 2", &opt, &v, &err),
		"CJK-named function in expr");
	mu_assert_eq(v.val.n, 60, "total(10,20)*2 == 60");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A variadic function may take many arguments - well beyond the
	// small inline buffer the evaluator keeps for the common case -
	// so registration is not limited to a fixed maximum arity.
	mu_assert_true(rz_num_math_value_ex(NULL,
			       "\u0441\u0443\u043c\u043c\u0430(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)",
			       &opt, &v, &err),
		"10-argument call");
	mu_assert_eq(v.val.n, 55, "sum of 1..10 == 55");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_true(rz_num_math_value_ex(NULL,
			       "\u5408\u8ba1(100, 200, 300, 400, 500, 600, 700, 800, "
			       "900, 1000, 1100, 1200)",
			       &opt, &v, &err),
		"12-argument call");
	mu_assert_eq(v.val.n, 7800, "sum of the 12 args == 7800");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A registered function may also shadow a built-in by name; here
	// a variadic "min" replaces the 2-arg built-in and now accepts
	// any number of arguments.
	mu_assert_true(rz_num_func_registry_add(reg, "min", -1, tfn_sum, NULL),
		"register variadic shadow of min");
	mu_assert_true(rz_num_math_value_ex(NULL, "min(1, 2, 3, 4)", &opt, &v, &err),
		"shadowed min with 4 args");
	mu_assert_eq(v.val.n, 10, "shadow min(1,2,3,4) sums to 10");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_func_registry_free(reg);
	mu_end;
}

bool test_rz_num_math_value_io_read() {
	RzNumMathOptions opt = { .io_read = tio_read, .io_read_user = NULL };
	RzNumValue v;
	char *err = NULL;

	// 0x1000 ^ 0xcafe == 0xdafe; masked to 32 bits is unchanged.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x1000:le32", &opt, &v, &err),
		"typed read le32");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "read kind");
	mu_assert_eq(v.val.n, 0xdafe, "0x1000:le32 dereferenced");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Width-2 read with the OPPOSITE endianness of how the mock
	// wrote the bytes: the conceptual value 0xdafe was written
	// little-endian as {0xfe, 0xda}, so a be16 decode swaps it to
	// 0xfeda. The previous test mock pretended endianness did not
	// matter (it returned the same scalar for either flag), which
	// hid this byte-swap; the raw-bytes callback signature makes
	// the actual semantics visible.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x1000:be16", &opt, &v, &err),
		"typed read be16");
	mu_assert_eq(v.val.n, 0xfeda, "0x1000:be16 byte-swaps the LE bytes");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// The dereferenced value is usable in further arithmetic.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x1000:le32 + 1", &opt, &v, &err),
		"typed read in expr");
	mu_assert_eq(v.val.n, 0xdaff, "0x1000:le32 + 1");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Without a callback, the literal address is returned.
	mu_assert_true(rz_num_math_value(NULL, "0x1000:le32", &v, &err),
		"no callback -> literal");
	mu_assert_eq(v.val.n, 0x1000, "literal address when no io_read");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

// Fake IO reader that writes `addr` itself, in little-endian byte
// order, as the raw bytes of the read. This lets a test express the
// exact bit pattern it wants via the address literal: an address of
// 0xffffffff with a `:s32` read produces the bytes {0xff, 0xff, 0xff,
// 0xff}, which sign-extends to -1; 0x3fc00000 with `:f32` produces
// the IEEE-754 bytes for 1.5; and so on. The semantic preserves what
// the previous typed-callback mock produced through the evaluator's
// new raw-bytes path.
static int tio_read_pattern(void *user, ut64 addr, ut8 *buf, int len) {
	(void)user;
	for (int i = 0; i < len; i++) {
		buf[i] = (i < 8) ? (ut8)(addr >> (8 * i)) : 0;
	}
	return len;
}

bool test_rz_num_math_value_typed_reads() {
	RzNumMathOptions opt = { .io_read = tio_read_pattern, .io_read_user = NULL };
	RzNumValue v;
	char *err = NULL;

	// Signed read: 0xffffffff as a signed 32-bit is -1.
	mu_assert_true(rz_num_math_value_ex(NULL, "0xffffffff:s32", &opt, &v, &err),
		"signed s32 read");
	mu_assert_eq(v.kind, RZ_NUM_KIND_UT64, "s32 kind");
	mu_assert_eq(v.val.n, (ut64)(-1), "0xffffffff:s32 == -1");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// The same bytes read unsigned are 0xffffffff.
	mu_assert_true(rz_num_math_value_ex(NULL, "0xffffffff:le32", &opt, &v, &err),
		"unsigned le32 read");
	mu_assert_eq(v.val.n, 0xffffffff, "0xffffffff:le32 == 0xffffffff");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Signed 16-bit: 0xfffe is -2.
	mu_assert_true(rz_num_math_value_ex(NULL, "0xfffe:s16", &opt, &v, &err),
		"signed s16 read");
	mu_assert_eq(v.val.n, (ut64)(-2), "0xfffe:s16 == -2");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A positive signed value is unchanged.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x7f:s8", &opt, &v, &err),
		"signed s8 positive");
	mu_assert_eq(v.val.n, 0x7f, "0x7f:s8 == 127");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Float read (single precision): the raw bits of 1.5f are
	// 0x3fc00000.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x3fc00000:f32", &opt, &v, &err),
		"float f32 read");
	mu_assert_eq(v.kind, RZ_NUM_KIND_FLOAT, "f32 kind is float");
	mu_assert_true(v.val.d == 1.5, "0x3fc00000:f32 == 1.5");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Float read (double precision): the raw bits of 2.0 are
	// 0x4000000000000000.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x4000000000000000:f64", &opt, &v, &err),
		"float f64 read");
	mu_assert_true(v.val.d == 2.0, "...:f64 == 2.0");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Half precision (f16): the raw bits of 1.5 are 0x3e00.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x3e00:f16", &opt, &v, &err),
		"float f16 read");
	mu_assert_eq(v.kind, RZ_NUM_KIND_FLOAT, "f16 kind is float");
	mu_assert_true(v.val.d == 1.5, "0x3e00:f16 == 1.5");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// f16 of 0xc000 is -2.0.
	mu_assert_true(rz_num_math_value_ex(NULL, "0xc000:f16", &opt, &v, &err),
		"float f16 negative");
	mu_assert_true(v.val.d == -2.0, "0xc000:f16 == -2.0");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// f16 Inf/NaN (exp all ones). These decode through a bit-pattern
	// path (no 0.0/0.0), so check the special values come out right.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x7c00:f16", &opt, &v, &err),
		"float f16 +inf read");
	mu_assert_true(isinf(v.val.d) && v.val.d > 0, "0x7c00:f16 == +inf");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_true(rz_num_math_value_ex(NULL, "0xfc00:f16", &opt, &v, &err),
		"float f16 -inf read");
	mu_assert_true(isinf(v.val.d) && v.val.d < 0, "0xfc00:f16 == -inf");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_true(rz_num_math_value_ex(NULL, "0x7e00:f16", &opt, &v, &err),
		"float f16 nan read");
	mu_assert_true(isnan(v.val.d), "0x7e00:f16 == nan");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// 128-bit reads need two underlying IO reads (the callback
	// returns ut64); the result is a width-128 bit-vector. The mock
	// returns `addr` for each read, so at address X we see lo=X and
	// hi=X+8 in little-endian and the swap in big-endian.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x100:128", &opt, &v, &err),
		":128 integer read");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, ":128 yields bitvector");
	mu_assert_eq(rz_bv_len(v.val.bv), 128, ":128 is width 128");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x100, ":128 low qword");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// :f128 likewise yields a width-128 bit-vector carrying the raw
	// IEEE-754 quad-precision bit pattern. RzNum's float kind is
	// double, so the quad value is not decoded to a native double;
	// the bit-vector preserves every bit for inspection and
	// bit-vector arithmetic.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x100:f128", &opt, &v, &err),
		":f128 quad-precision read");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, ":f128 yields bitvector");
	mu_assert_eq(rz_bv_len(v.val.bv), 128, ":f128 is width 128");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Two reads of the same 128-bit value are equal.
	mu_assert_true(rz_num_math_value_ex(NULL, "0x200:128 == 0x200:128",
			       &opt, &v, &err),
		":128 equality");
	mu_assert_eq(v.val.n, 1, ":128 equals itself");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Without an IO callback the literal address comes back (parity
	// with the other typed-read widths).
	mu_assert_true(rz_num_math_value(NULL, "0x1234:128", &v, &err),
		":128 literal fallback");
	mu_assert_eq(v.val.n, 0x1234, ":128 == address with no io_read");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;
	mu_assert_true(rz_num_math_value(NULL, "0x1234:f128", &v, &err),
		":f128 literal fallback");
	mu_assert_eq(v.val.n, 0x1234, ":f128 == address with no io_read");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_bitvector_extended_ops() {
	// Bit-vector rotates, **, log and the signed family. All
	// arithmetic is modular at the combined width; rotates cycle
	// bits within the width and a rotation by W is the identity.
	RzNumValue v;
	char *err = NULL;

	// Rotates.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0x12u8 <<< 4", &v, &err),
		"u8 rol 4");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "rol yields bv");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x21, "0x12u8 rol 4 == 0x21");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0x12u8 >>> 4", &v, &err),
		"u8 ror 4");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x21, "0x12u8 ror 4 == 0x21");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0x12345678u32 <<< 8", &v, &err),
		"u32 rol 8");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0x34567812, "u32 rol 8 wraps top byte");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Rotation by a full width is the identity.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0xabu8 <<< 8", &v, &err),
		"u8 rol 8 == identity");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0xab, "rol full-width is identity");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Power: modular at W bits, exponentiation by squaring.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "3u32 ** 10u32", &v, &err),
		"u32 power");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 59049, "3^10 == 59049");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "2u8 ** 8u8", &v, &err),
		"u8 power overflow wraps");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0, "2u8 ** 8 wraps to 0");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "2u32 ** 32u32", &v, &err),
		"u32 power overflow wraps");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0, "2u32 ** 32 wraps to 0");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Logarithm: floor(log_base(value)) at the combined width.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "2u32 log 16u32", &v, &err),
		"u32 log");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 4, "log2(16) == 4");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "2u8 log 4u8", &v, &err),
		"u8 log");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 2, "log2(4) == 2");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Signed family on bit-vectors. 0xff as u8-signed is -1, 0xfe is
	// -2; sdiv truncates toward zero, sar sign-extends.
	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0xffu8 sdiv 2u8", &v, &err),
		"u8 sdiv");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0, "-1 sdiv 2 == 0 (trunc)");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0xffu8 smod 3u8", &v, &err),
		"u8 smod");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0xff, "-1 smod 3 == -1");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_true(rz_num_math_value(NULL, "0xfeu8 sar 1u8", &v, &err),
		"u8 sar");
	mu_assert_eq(rz_bv_to_ut64(v.val.bv), 0xff, "-2 sar 1 == -1 (sign-fill)");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Division by zero on the signed bit-vector ops is reported.
	mu_assert_false(rz_num_math_value(NULL, "5u8 sdiv 0u8", &v, &err),
		"bv sdiv by zero fails");
	mu_assert_eq(v.err, RZ_NUM_ERR_DIV_ZERO, "bv sdiv 0 -> DIV_ZERO");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_builtins() {
	// Built-in math functions: min, max, abs, popcount, plus the
	// unicode-named aliases that demonstrate the parser's
	// transparent UTF-8 identifier handling.
	ASSERT_U64("min(3, 7)", 3);
	ASSERT_U64("max(3, 7)", 7);
	ASSERT_U64("min(100, 50)", 50);
	ASSERT_U64("abs(0xfffffffffffffffb)", 5); // -5 in ut64
	ASSERT_U64("abs(5)", 5);
	ASSERT_U64("popcount(0xff)", 8);
	ASSERT_U64("popcount(0xffff0000)", 16);
	ASSERT_U64("popcount(0)", 0);
	// Nested calls and use as a sub-expression.
	ASSERT_U64("min(1, max(2, 3))", 1);
	ASSERT_U64("max(min(10, 20), min(30, 40))", 30);

	// Unicode-named aliases. The byte strings below are the UTF-8
	// encodings of "минимум" and "максимум" (Russian for min/max).
	// The grammar's identifier rule (XID_Start / XID_Continue per
	// tree-sitter's word handling) admits these without any
	// special-casing.
	ASSERT_U64("\xd0\xbc\xd0\xb8\xd0\xbd\xd0\xb8\xd0\xbc\xd1\x83\xd0\xbc(5, 10)", 5);
	ASSERT_U64("\xd0\xbc\xd0\xb0\xd0\xba\xd1\x81\xd0\xb8\xd0\xbc\xd1\x83\xd0\xbc(5, 10)", 10);

	// Arity errors surface as RZ_NUM_ERR_NOT_IMPLEMENTED with a
	// descriptive message; we only check the error category, not
	// the diagnostic string.
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(num, "min(1)", &v, &err), "wrong arity");
	mu_assert_eq(v.err, RZ_NUM_ERR_NOT_IMPLEMENTED, "arity -> NOT_IMPLEMENTED");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_assert_false(rz_num_math_value(num, "foo(1, 2)", &v, &err), "unknown");
	mu_assert_eq(v.err, RZ_NUM_ERR_NOT_IMPLEMENTED, "unknown -> NOT_IMPLEMENTED");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

// Math and bit functions: log/ln/log2/log10/sqrt (float results),
// floor/ceil/round (float -> ut64 bridge), gcd, clz, ctz. These are
// the domain-relevant additions on top of min/max/abs/popcount/len.
bool test_rz_num_math_value_math_functions() {
	num = NULL;

	// Exact-valued transcendentals come back as exact floats.
	ASSERT_F64("log(1)", 0.0);
	ASSERT_F64("ln(1)", 0.0);
	ASSERT_F64("log2(256)", 8.0);
	ASSERT_F64("log2(1024)", 10.0);
	ASSERT_F64("log10(1000)", 3.0);
	ASSERT_F64("log10(1)", 0.0);
	ASSERT_F64("sqrt(16)", 4.0);
	ASSERT_F64("sqrt(0)", 0.0);
	ASSERT_F64("sqrt(2)", sqrt(2.0)); // irrational: compare to libm
	ASSERT_F64("log(2.718281828459045)", log(2.718281828459045));
	// log() is natural; the base-b logarithm is the `b log x` operator.
	ASSERT_F64("ln(100)", log(100.0));
	// Integers are unsigned here, so sqrt(-1) is sqrt(2^64-1), not a
	// domain error (same model that makes 0 - 1 == 2^64-1). Genuine
	// domain errors come from negative floats; see below.
	ASSERT_F64("sqrt(-1)", sqrt((double)UT64_MAX));

	// floor/ceil/round bridge float to ut64 (two's complement for
	// negatives). C round() rounds halves away from zero.
	ASSERT_U64("floor(3.7)", 3);
	ASSERT_U64("ceil(3.2)", 4);
	ASSERT_U64("floor(3.0)", 3);
	ASSERT_U64("ceil(3.0)", 3);
	ASSERT_U64("round(2.5)", 3);
	ASSERT_U64("round(2.4)", 2);
	ASSERT_U64("round(-2.5)", (ut64)(-3LL));
	ASSERT_U64("floor(-1.5)", (ut64)(-2LL));
	ASSERT_U64("ceil(-1.5)", (ut64)(-1LL));
	// Integer arguments pass straight through, keeping full precision.
	ASSERT_U64("floor(42)", 42);
	ASSERT_U64("ceil(42)", 42);
	ASSERT_U64("round(42)", 42);

	// gcd over ut64.
	ASSERT_U64("gcd(48, 36)", 12);
	ASSERT_U64("gcd(1071, 462)", 21);
	ASSERT_U64("gcd(17, 5)", 1);
	ASSERT_U64("gcd(100, 0)", 100);
	ASSERT_U64("gcd(0, 0)", 0);

	// clz / ctz over the 64-bit projection.
	ASSERT_U64("clz(1)", 63);
	ASSERT_U64("clz(0)", 64);
	ASSERT_U64("clz(0x8000000000000000)", 0);
	ASSERT_U64("clz(0xff)", 56);
	ASSERT_U64("ctz(8)", 3);
	ASSERT_U64("ctz(0)", 64);
	ASSERT_U64("ctz(1)", 0);
	ASSERT_U64("ctz(0x8000000000000000)", 63);

	// Compositions: number of bits needed to represent N is
	// floor(log2(N)) + 1, a staple of the analysis domain.
	ASSERT_U64("floor(log2(1000)) + 1", 10);
	ASSERT_U64("floor(log2(255)) + 1", 8);
	ASSERT_U64("ceil(log2(1000))", 10);
	ASSERT_U64("clz(0xff) + ctz(0x100)", 64); // 56 + 8

	// Domain violations are reported, not guessed.
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(num, "log(0)", &v, &err), "log(0)");
	mu_assert_eq(v.err, RZ_NUM_ERR_UNCOMPUTABLE, "log(0) -> UNCOMPUTABLE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(num, "log2(0)", &v, &err), "log2(0)");
	mu_assert_eq(v.err, RZ_NUM_ERR_UNCOMPUTABLE, "log2(0) -> UNCOMPUTABLE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(num, "sqrt(-1.5)", &v, &err), "sqrt(-1.5)");
	mu_assert_eq(v.err, RZ_NUM_ERR_UNCOMPUTABLE, "sqrt(-1.5) -> UNCOMPUTABLE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(num, "log(-2.5)", &v, &err), "log(-2.5)");
	mu_assert_eq(v.err, RZ_NUM_ERR_UNCOMPUTABLE, "log(-2.5) -> UNCOMPUTABLE");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Wrong arity still reports NOT_IMPLEMENTED.
	rz_num_value_init(&v);
	mu_assert_false(rz_num_math_value(num, "gcd(1)", &v, &err), "gcd arity");
	mu_assert_eq(v.err, RZ_NUM_ERR_NOT_IMPLEMENTED, "gcd(1) -> NOT_IMPLEMENTED");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

// "Torture" cases: each expression deliberately piles many grammar
// features into a single computation - multiple numeric bases (hex,
// binary, octal, C-style octal, ternary), arithmetic, signed
// operators (sdiv/smod/sar), shifts and rotates, the full bitwise
// precedence ladder (& > ^ > |, all looser than the shifts), unary
// operators, comparisons and equality, nested conditionals,
// assignment/sequencing, fixed-width bit-vectors, and nested function
// calls. Every expected value was cross-checked against an independent
// Python oracle and the sympy-based verifier. Grouping notes are given
// where the precedence is non-obvious (the shift operators - including
// sar - bind looser than + and -, so e.g. `(-100) sar 3 + ...` parses
// as `(-100) sar (3 + ...)`).
bool test_rz_num_math_value_torture() {
	// bases + arithmetic + function + shift + full bitwise ladder
	ASSERT_U64("(0x10 + 0b110) * 0o3 - gcd(36, 24) << 2 & 0xff | 0t21", 0xdf);
	// signed sdiv/smod, comparison, conditional, abs/popcount, unary -
	ASSERT_U64("(100 sdiv 7 > 10 ? abs(0 - 50) : popcount(0xff)) + (-20 smod 6)", 0x30);
	// rotate, exponent, bitwise xor/and with shift-tighter-than-&
	ASSERT_U64("(1 <<< 8 | 0xff) ^ (2 ** 4 - 1) & 0xf0 >>> 4", 0x1f0);
	// unary ~, logical/arith shifts, & ^ | ladder, popcount
	ASSERT_U64("~0 >> 56 & 0xff ^ 0b1100 | popcount(0xffff) << 2", 0xf3);
	// nested gcd/min/max/clz, float-bridging floor(sqrt(...)), octal
	ASSERT_U64("max(gcd(48,36), min(20, clz(0x100))) * 2 + floor(sqrt(0x100)) - 0o17", 0x29);
	// C-style octal (034, 010), equality-in-conditional, ternary base
	ASSERT_U64("(034 + 010) * 2 - 0x10 + (5 > 3 == 1 ? 0b111 : 0t22)", 0x3f);
	// large hex, masking, shift, xor with a rotate of the high word
	ASSERT_U64("((0xdeadbeef & 0xffff) | (0xcafe << 4)) ^ 0xf0f0 >>> 8", 0xf0000000000cbf1f);
	// sar binds looser than +/- : == `(-100) sar (3 + 28 - 2)` == -1
	ASSERT_U64("(-100) sar 3 + 100 sdiv 7 * 2 - 5 smod 3", 0xffffffffffffffff);
	// right-assoc **, comparison/equality conditionals, clz, len(int)
	ASSERT_U64("(2 ** 3 ** 2 > 500 ? 1 : 0) + (popcount(0xff) == 8 ? clz(1) : 0) + len(0x1234)", 0x4d);
	// assignment + sequencing, reuse of a bound variable, bitwise
	ASSERT_U64("a = 0xff; b = a << 4 | a; b & 0xf0f ^ 0x101", 0xe0e);
	// gcd of an exponent and an octal, conditional, abs, rotate
	ASSERT_U64("gcd(2 ** 8, 0o1000) + (3 < 2 ? 999 : abs(10 - 0x20)) * (1 <<< 2)", 0x158);
	// u8 wraparound inside an equality test, clz/ctz, shift, xor, or
	ASSERT_U64("(0xffu8 + 1u8 == 0 ? 0xaa : 0xbb) | (clz(0x8000) << 1) ^ ctz(0x400)", 0xea);
	// string-byte len, bit-vector len, popcount, arithmetic + or
	ASSERT_U64("(len(\"ABCD\") + len(\"XY\")) * 2 - len(0xffffu16) | popcount(0xf0f0)", 0x58);
	// deeply nested conditionals on both sides, right-assoc chaining
	ASSERT_U64("(10 > 5 ? (20 < 15 ? 1 : (3 == 3 ? 0xff : 0)) : 0xaa) + (0 ? 1 : 2 ? 3 : 4)", 0x102);
	// one long precedence chain: mult>add>shift>&>^>|
	ASSERT_U64("1 + 2 * 3 - 4 << 1 | 5 & 6 ^ 7 + 8 >> 2", 0x7);
	mu_end;
}
// both variable names and function names. The grammar's identifier
// rule admits any run of non-operator, non-control UTF-8, so these
// work without special-casing; this test pins that behaviour down.
//
// All identifiers are written as \x escapes to keep the source
// ASCII-clean; the comment on each line gives the script and the
// readable form.
bool test_rz_num_math_value_unicode_names() {
	num = NULL;

	// --- Variable names ------------------------------------------
	// A name is bound with (name = v) and then read back, so the
	// round-trip proves the same byte sequence lexes identically in
	// both the assignment target and a later reference.

	// Mathematical / Greek letters.
	ASSERT_U64("(\xcf\x80 = 3) + \xcf\x80", 6); // "π" (Greek pi)
	ASSERT_U64("(\xce\xb1\xce\xb2\xce\xb3 = 2) * \xce\xb1\xce\xb2\xce\xb3", 4); // "αβγ"
	ASSERT_U64("(\xe2\x84\x95 = 9) - \xe2\x84\x95", 0); // "ℕ" (U+2115, double-struck N)

	// Chinese (Han).
	ASSERT_U64("(\xe5\x8d\x8a\xe5\xbe\x84 = 5) * \xe5\x8d\x8a\xe5\xbe\x84", 25); // "半径" (radius)
	ASSERT_U64("(\xe5\xb9\xb3\xe5\x9d\x87 = 8) + \xe5\xb9\xb3\xe5\x9d\x87", 16); // "平均" (average)

	// Japanese (kanji, and a katakana run).
	ASSERT_U64("(\xe5\xa4\x89\xe6\x95\xb0 = 7) + 1", 8); // "変数" (variable)
	ASSERT_U64("(\xe3\x83\x98\xe3\x83\xb3\xe3\x82\xb9\xe3\x82\xa6 = 4) * 2", 8); // "ヘンスウ"

	// Arabic (right-to-left script; stored and compared as bytes).
	ASSERT_U64("(\xd9\x85\xd8\xaa\xd8\xba\xd9\x8a\xd8\xb1 = 4) + "
		   "\xd9\x85\xd8\xaa\xd8\xba\xd9\x8a\xd8\xb1",
		8); // "متغير" (variable)

	// Cyrillic.
	ASSERT_U64("(\xd0\xbd\xd0\xb0\xd1\x87 = 10) + \xd0\xbd\xd0\xb0\xd1\x87", 20); // "нач"

	// A bound Unicode name is independent of an ASCII one.
	ASSERT_U64("(\xcf\x83 = 1) + (s = 2) + \xcf\x83 + s", 6); // "σ" vs "s"

	// --- Function names ------------------------------------------
	// These map to built-in aliases registered in the evaluator's
	// builtin_table (Cyrillic, Chinese/Japanese, Arabic, Greek
	// symbol). Each is functionally identical to an English builtin.
	ASSERT_U64("\xd0\xbc\xd0\xb8\xd0\xbd\xd0\xb8\xd0\xbc\xd1\x83\xd0\xbc(5, 10)", 5); // "минимум" min
	ASSERT_U64("\xd0\xbc\xd0\xb0\xd0\xba\xd1\x81\xd0\xb8\xd0\xbc\xd1\x83\xd0\xbc(5, 10)", 10); // "максимум" max
	ASSERT_U64("\xe6\x9c\x80\xe5\xb0\x8f(5, 3)", 3); // "最小" (Chinese/Japanese: min)
	ASSERT_U64("\xe6\x9c\x80\xe5\xa4\xa7(5, 3)", 5); // "最大" (Chinese/Japanese: max)
	ASSERT_U64("\xd8\xaf\xd8\xa7\xd9\x84\xd8\xa9(0xfffffffffffffffb)", 5); // "دالة" (Arabic) abs(-5)
	ASSERT_U64("\xce\xa3(0xff)", 8); // "Σ" (Greek sigma) popcount

	// Unicode function name composed with a Unicode variable arg.
	ASSERT_U64("(\xe5\x8d\x8a\xe5\xbe\x84 = 12) + \xe6\x9c\x80\xe5\xb0\x8f(\xe5\x8d\x8a\xe5\xbe\x84, 7)",
		19); // 半径=12, 12 + 最小(12, 7) = 12 + 7

	// An unknown Unicode function name still errors cleanly (it is
	// not silently treated as a variable).
	RzNumValue v;
	char *err = NULL;
	rz_num_value_init(&v);
	mu_assert_false(
		rz_num_math_value(NULL, "\xe9\x96\xa2\xe6\x95\xb0(1, 2)", &v, &err),
		"unknown unicode function"); // "関数" (Japanese: function), unregistered
	mu_assert_eq(v.err, RZ_NUM_ERR_NOT_IMPLEMENTED,
		"unknown unicode fn -> NOT_IMPLEMENTED");
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_value_pretty_print() {
	// Exercise the per-kind pretty-printer. We don't pin down the
	// exact bytes (whitespace and order may be tweaked) but assert
	// that each kind's defining tokens appear, that on-error output
	// includes the category, and that the one-line form is sensible.
	RzNumValue v;
	char *err = NULL;

	// UT64 case: must include the hex form, signed/unsigned dec,
	// the binary token, and the unit conversion.
	rz_num_math_value(NULL, "0x100000", &v, &err);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_num_value_print(&v, sb);
	char *out = rz_strbuf_drain(sb);
	mu_assert_notnull(out, "ut64 print produced output");
	mu_assert_notnull(strstr(out, "0x100000"), "hex");
	mu_assert_notnull(strstr(out, "1048576"), "decimal");
	mu_assert_notnull(strstr(out, "binary"), "binary line");
	mu_assert_notnull(strstr(out, "1M"), "unit");
	free(out);
	char *one = rz_num_value_tostring(&v);
	mu_assert_streq(one, "0x100000", "compact form");
	free(one);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// FLOAT case
	rz_num_math_value(NULL, "3.14159", &v, &err);
	sb = rz_strbuf_new(NULL);
	rz_num_value_print(&v, sb);
	out = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(out, "3.14"), "float value");
	mu_assert_notnull(strstr(out, "hex"), "bit pattern");
	free(out);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// BIG case: decimal + hex + width.
	rz_num_math_value(NULL, "0x10000000000000000", &v, &err);
	sb = rz_strbuf_new(NULL);
	rz_num_value_print(&v, sb);
	out = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(out, "decimal"), "decimal label");
	mu_assert_notnull(strstr(out, "18446744073709551616"),
		"exact decimal form");
	mu_assert_notnull(strstr(out, "0x10000000000000000"), "hex form");
	mu_assert_notnull(strstr(out, "width"), "width hint");
	free(out);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// Error case must surface the category name.
	rz_num_math_value(NULL, "1 / 0", &v, &err);
	sb = rz_strbuf_new(NULL);
	rz_num_value_print(&v, sb);
	out = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(out, "error"), "error label");
	mu_assert_notnull(strstr(out, "division"), "category name");
	free(out);
	one = rz_num_value_tostring(&v);
	mu_assert_notnull(strstr(one, "error"), "compact carries error too");
	free(one);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// rz_num_error_name is stable and covers every category.
	mu_assert_streq(rz_num_error_name(RZ_NUM_ERR_OK), "ok", "ok");
	mu_assert_streq(rz_num_error_name(RZ_NUM_ERR_DIV_ZERO),
		"division by zero", "div0");
	mu_assert_streq(rz_num_error_name(RZ_NUM_ERR_TIMEOUT),
		"timeout", "timeout");
	mu_assert_streq(rz_num_error_name((RzNumError)9999),
		"unknown", "out-of-enum");
	mu_end;
}

bool test_rz_num_math_value_bitvector_unicode() {
	RzNumValue v;
	char *err = NULL;

	// 200u8 + 100u8 == 44 (0x2c) at width 8.
	bool ok = rz_num_math_value(NULL, "200u8 + 100u8", &v, &err);
	mu_assert_true(ok, "bv add");
	mu_assert_eq(v.kind, RZ_NUM_KIND_BITVECTOR, "is bitvector");

	// ASCII default: plain hex / 0b-prefixed binary, width last, and
	// no subscript bytes anywhere.
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_num_value_print(&v, sb);
	char *ascii = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(ascii, "hex     0x2c\n"), "ascii hex");
	mu_assert_notnull(strstr(ascii, "binary  0b00101100\n"), "ascii binary");
	mu_assert_notnull(strstr(ascii, "width   8 bits"), "ascii width");
	// U+2088 (subscript 8) is the bytes e2 82 88; must be absent.
	mu_assert_null(strstr(ascii, "\u2088"), "ascii has no subscript");
	// Width row comes after the value rows.
	mu_assert_true(strstr(ascii, "hex") < strstr(ascii, "width"),
		"ascii width is below the values");
	free(ascii);

	// UTF-8 option: the width is folded into the value rows as a
	// subscript (0x2c then U+2088), the binary form drops 0b, and
	// the width row still comes last.
	RzNumPrintOptions opts = { .utf8 = true };
	sb = rz_strbuf_new(NULL);
	rz_num_value_print_ex(&v, &opts, sb);
	char *uni = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(uni, "hex     0x2c\u2088\n"), "utf8 hex subscript");
	mu_assert_notnull(strstr(uni, "binary  00101100\u2088\n"), "utf8 binary subscript, no 0b");
	mu_assert_null(strstr(uni, "0b"), "utf8 binary has no 0b prefix");
	mu_assert_true(strstr(uni, "hex") < strstr(uni, "width"),
		"utf8 width is below the values");
	free(uni);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// A 16-bit value renders a two-digit subscript: U+2081 U+2086.
	ok = rz_num_math_value(NULL, "10u16 * 10u16", &v, &err);
	mu_assert_true(ok, "bv mul 16");
	sb = rz_strbuf_new(NULL);
	rz_num_value_print_ex(&v, &opts, sb);
	uni = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(uni, "hex     0x0064\u2081\u2086\n"), "16-bit hex subscript");
	mu_assert_notnull(strstr(uni, "binary  0000000001100100\u2081\u2086\n"), "16-bit binary subscript");
	free(uni);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	// NULL opts behaves exactly like the ASCII default.
	ok = rz_num_math_value(NULL, "5u8", &v, &err);
	mu_assert_true(ok, "5u8");
	sb = rz_strbuf_new(NULL);
	rz_num_value_print_ex(&v, NULL, sb);
	uni = rz_strbuf_drain(sb);
	mu_assert_notnull(strstr(uni, "0b"), "NULL opts keeps 0b prefix");
	mu_assert_null(strstr(uni, "\u2085"), "NULL opts -> no subscript");
	free(uni);
	rz_num_value_fini(&v);
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_il_lift() {
	char *err = NULL;

#define ASSERT_LIFT(expr, want) \
	do { \
		char *_e = NULL; \
		RzILOpPure *_op = rz_il_lift_num(NULL, (expr), NULL, &_e); \
		mu_assert_notnull(_op, expr " lifts"); \
		RzStrBuf _sb; \
		rz_strbuf_init(&_sb); \
		RzILStringifyCtx _ctx = { 0 }; \
		rz_il_op_pure_stringify_unicode(&_ctx, _op, &_sb); \
		rz_il_op_pure_free(_op); \
		free(_e); \
		char *_s = rz_strbuf_drain_nofree(&_sb); \
		mu_assert_streq_free(_s, (want), expr); \
	} while (0)

	// Arithmetic keeps precedence and uses RzIL glyphs; ut64 literals
	// become 64-bit bit-vector constants with a subscript width.
	ASSERT_LIFT("1 + 2 * 3", "(0x1\u2086\u2084 + (0x2\u2086\u2084 * 0x3\u2086\u2084))");
	ASSERT_LIFT("(1 + 2) * 3", "((0x1\u2086\u2084 + 0x2\u2086\u2084) * 0x3\u2086\u2084)");
	ASSERT_LIFT("0x10 & 0xff", "(0x10\u2086\u2084 & 0xff\u2086\u2084)");
	// Shifts carry an explicit fill bit as a third operand in RzIL's
	// serialization; a logical shift fills with false (\u22a5).
	ASSERT_LIFT("1 << 4", "(0x1\u2086\u2084 \u226a 0x4\u2086\u2084 \u22a5)");
	ASSERT_LIFT("10 == 10", "(0xa\u2086\u2084 \u2261 0xa\u2086\u2084)");

	// Width-suffixed literals keep their bit-vector width.
	ASSERT_LIFT("5u8 + 3u8", "(0x5\u2088 + 0x3\u2088)");

	// Unary minus / bitwise not render as a prefix glyph directly on the
	// operand (no wrapping parentheses), matching RzIL's exporter.
	ASSERT_LIFT("-5", "\u22120x5\u2086\u2084");
	ASSERT_LIFT("~0xff", "~0xff\u2086\u2084");

	// Functions have no structural RzIL form, so they are grounded to
	// a concrete bit-vector constant first: min(5,3) == 3.
	ASSERT_LIFT("min(5, 3) + 1", "(0x3\u2086\u2084 + 0x1\u2086\u2084)");

	// ** is likewise grounded: 2 ** 8 == 256.
	ASSERT_LIFT("2 ** 8", "0x100\u2086\u2084");

	// Signed division / remainder lift to their RzIL glyphs (the
	// superscript plus marks signedness): sdiv -> /+, smod -> %+.
	ASSERT_LIFT("10 sdiv 3", "(0xa\u2086\u2084 /\u207a 0x3\u2086\u2084)");
	ASSERT_LIFT("10 smod 3", "(0xa\u2086\u2084 %\u207a 0x3\u2086\u2084)");
	// Arithmetic shift right is a plain RzIL shiftr whose fill bit is the
	// sign bit (msb, the \u2191 glyph) of the shifted value.
	ASSERT_LIFT("256 sar 2",
		"(0x100\u2086\u2084 \u226b 0x2\u2086\u2084 \u21910x100\u2086\u2084)");

	// A ';'-separated sequence is grounded to its final value: the
	// last statement wins and earlier bindings are honoured.
	ASSERT_LIFT("1 + 2; 3 + 4", "0x7\u2086\u2084");
	ASSERT_LIFT("x = 5; x + 1", "0x6\u2086\u2084");

	// The ternary lifts structurally to RzIL's ite, rendered exactly
	// as the RzIL Unicode exporter prints it: "(cond <ITE> then else)"
	// with the two-headed-arrow glyph. This is the one control-flow
	// form with a direct RzIL pure-op, so it is not grounded.
	ASSERT_LIFT("1 ? 10 : 20",
		"(0x1\u2086\u2084 \u21a0 0xa\u2086\u2084 0x14\u2086\u2084)");
	ASSERT_LIFT("1 ? 2 + 3 : 4 * 5",
		"(0x1\u2086\u2084 \u21a0 (0x2\u2086\u2084 + 0x3\u2086\u2084) (0x4\u2086\u2084 * 0x5\u2086\u2084))");

	// Float-pure arithmetic lifts to the RzIL float-binop form with
	// the round-nearest-even prefix - "(rne x + y)" - and the operands
	// render as the bit-vector representation of the double with the
	// ".f64" subscript, matching how RzIL prints a `float
	// RZ_FLOAT_IEEE754_BIN_64 <bitv>` op.
	ASSERT_LIFT("1.5 + 2.5",
		"(rne 0x3ff8000000000000.f\u2086\u2084 + 0x4004000000000000.f\u2086\u2084)");
	ASSERT_LIFT("1.0 / 2.0",
		"(rne 0x3ff0000000000000.f\u2086\u2084 / 0x4000000000000000.f\u2086\u2084)");

	// Mixed integer / float is grounded rather than fabricating an
	// implicit cast the user did not write.
	ASSERT_LIFT("1 + 2.5", "0x3\u2086\u2084");

	// Float-conditioned ternary: the evaluator's "non-zero float is
	// true" semantic does not match RzIL's ite (which expects a Bool),
	// so the lift wraps the condition in is_fzero and SWAPS the branches
	// - "(f \u2261 0 \u21a0 else then)". This makes the lifted form pick the
	// same branch as the evaluator: 0.5 -> "then", 0.0 -> "else".
	ASSERT_LIFT("0.5 ? 7 : 8",
		"(0x3fe0000000000000.f\u2086\u2084 \u2261 0 \u21a0 0x8\u2086\u2084 0x7\u2086\u2084)");
	ASSERT_LIFT("0.0 ? 7 : 8",
		"(0x0.f\u2086\u2084 \u2261 0 \u21a0 0x8\u2086\u2084 0x7\u2086\u2084)");

	// Float-conditioned ternary with float branches: both the
	// condition and the branches lift in their float form.
	ASSERT_LIFT("0.5 ? 1.5 : 2.5",
		"(0x3fe0000000000000.f\u2086\u2084 \u2261 0 \u21a0 "
		"0x4004000000000000.f\u2086\u2084 0x3ff8000000000000.f\u2086\u2084)");

#undef ASSERT_LIFT

	// A parse error is reported, not lifted.
	RzILOpPure *bad = rz_il_lift_num(NULL, "1 +", NULL, &err);
	mu_assert_null(bad, "incomplete expression does not lift");
	free(err);
	err = NULL;

	mu_end;
}

bool test_rz_num_math_ut64_legacy_compat() {
	// rz_num_math_ut64 routes through the new parser and falls back
	// to the legacy parser. Both code paths must agree on simple
	// arithmetic.
	mu_assert_eq(rz_num_math(num, "1 + 2"), 3, "1 + 2");
	mu_assert_eq(rz_num_math(num, "0x10 * 2"), 0x20, "0x10 * 2");
	mu_assert_eq(rz_num_math(num, "(1+2)*3"), 9, "(1+2)*3");
	mu_assert_eq(rz_num_math(num, "10"), 10, "10");
	mu_assert_eq(rz_num_math(num, ""), 0, "empty");
	// rz_num_math is the inline alias for rz_num_math_ut64.
	mu_assert_eq(rz_num_math_ut64(num, "5 + 5"), 10, "rz_num_math_ut64 5+5");
	// Reserved-word fall-through: bare `mod`/`log`/`le`/`be` must
	// silently resolve to 0 through this entry point, matching the
	// legacy parser's behaviour for unknown identifiers. (The typed
	// rz_num_math_value still returns an error - that is what
	// test_rz_num_math_value_reserved_words covers.)
	mu_assert_eq(rz_num_math(num, "mod"), 0, "bare 'mod' is silent 0");
	mu_assert_eq(rz_num_math(num, "log"), 0, "bare 'log' is silent 0");
	mu_assert_eq(rz_num_math(num, "le"), 0, "bare 'le' is silent 0");
	mu_assert_eq(rz_num_math(num, "be"), 0, "bare 'be' is silent 0");

	// num->nc.errors contract: callers such as the seek and write
	// commands gate on it, so a successful evaluation must leave it
	// clear even if a previous one set it, and a genuine error must
	// set it. (Regression: the new-parser path used to leave a stale
	// count in place, which made `s main` and friends silently abort.)
	RzNum *ncnum = rz_num_new(NULL, NULL, NULL);
	ncnum->nc.errors = 7;
	mu_assert_eq(rz_num_math(ncnum, "1 + 2"), 3, "value still correct");
	mu_assert_eq(ncnum->nc.errors, 0, "success clears stale nc.errors");
	ncnum->nc.errors = 7;
	mu_assert_eq(rz_num_math(ncnum, "0x1000"), 0x1000, "flagless literal");
	mu_assert_eq(ncnum->nc.errors, 0, "success clears nc.errors (literal)");
	rz_num_math(ncnum, "1 / 0");
	mu_assert_true(ncnum->nc.errors != 0, "division by zero sets nc.errors");
	mu_assert_eq(rz_num_math(ncnum, "42"), 42, "recover after error");
	mu_assert_eq(ncnum->nc.errors, 0, "next success re-clears nc.errors");
	rz_num_free(ncnum);
	mu_end;
}

#undef ASSERT_U64
#undef ASSERT_F64
#undef ASSERT_FAIL

bool all_tests() {
	mu_run_test(test_rz_num_units);
	mu_run_test(test_rz_num_minmax_swap_i);
	mu_run_test(test_rz_num_minmax_swap);
	mu_run_test(test_rz_num_between);
	mu_run_test(test_rz_num_str_len);
	mu_run_test(test_rz_num_str_split);
	mu_run_test(test_rz_num_str_split_list);
	mu_run_test(test_rz_num_align_delta);
	mu_run_test(test_rz_num_bitmask);
	mu_run_test(test_rz_num_abs);
	mu_run_test(test_rz_num_math_value_integer_arith);
	mu_run_test(test_rz_num_math_value_bitwise);
	mu_run_test(test_rz_num_math_value_rotate);
	mu_run_test(test_rz_num_math_value_logical);
	mu_run_test(test_rz_num_math_value_unary_signs);
	mu_run_test(test_rz_num_math_value_increment);
	mu_run_test(test_rz_num_math_value_floats);
	mu_run_test(test_rz_num_math_value_units);
	mu_run_test(test_rz_num_math_value_comparisons);
	mu_run_test(test_rz_num_math_value_special_variables);
	mu_run_test(test_rz_num_math_value_local_label);
	mu_run_test(test_rz_num_math_value_callback_userptr);
	mu_run_test(test_rz_num_math_value_string_bytes);
	mu_run_test(test_rz_num_math_value_reserved_words);
	mu_run_test(test_rz_num_math_value_errors);
	mu_run_test(test_rz_num_math_value_assignment);
	mu_run_test(test_rz_num_math_value_sequence);
	mu_run_test(test_rz_num_math_value_conditional);
	mu_run_test(test_rz_num_math_value_signed_arith);
	mu_run_test(test_rz_num_math_value_len);
	mu_run_test(test_rz_num_math_value_persistent_vars);
	mu_run_test(test_rz_num_math_value_address_typed);
	mu_run_test(test_rz_num_math_value_bignum);
	mu_run_test(test_rz_num_math_value_bitvector);
	mu_run_test(test_rz_num_math_value_bignum_arith);
	mu_run_test(test_rz_num_math_value_complex_exprs);
	mu_run_test(test_rz_num_math_value_timeout);
	mu_run_test(test_rz_num_math_value_error_codes);
	mu_run_test(test_rz_num_math_value_builtins);
	mu_run_test(test_rz_num_math_value_math_functions);
	mu_run_test(test_rz_num_math_value_torture);
	mu_run_test(test_rz_num_math_value_unicode_names);
	mu_run_test(test_rz_num_math_value_custom_funcs);
	mu_run_test(test_rz_num_math_value_io_read);
	mu_run_test(test_rz_num_math_value_typed_reads);
	mu_run_test(test_rz_num_math_value_bitvector_extended_ops);
	mu_run_test(test_rz_num_math_value_pretty_print);
	mu_run_test(test_rz_num_math_value_bitvector_unicode);
	mu_run_test(test_rz_num_math_ut64_legacy_compat);
	mu_run_test(test_rz_num_il_lift);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	num = rz_num_new(NULL, NULL, NULL);
	num_with_cb = rz_num_new(test_var_cb, NULL, NULL);
	return all_tests();
}
