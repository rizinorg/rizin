// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <limits.h>
#include <rz_util.h>
#include "minunit.h"

static const struct {
	ut64 value;
	const char *str;
} vectors[] = {
	{ 0ULL, "0" },
	{ 1ULL, "1" },
	{ 35ULL, "z" },
	{ 36ULL, "10" },
	{ 125ULL, "3h" },
	{ 123456789ULL, "21i3v9" },
	{ UINT64_MAX, "3w5e11264sgsf" }
};

bool test_rz_base36_encode_dyn_basic(void) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(vectors); i++) {
		char *s = rz_base36_encode_dyn(vectors[i].value);
		mu_assert_notnull(s, "encode returned NULL");
		mu_assert_streq(s, vectors[i].str, "unexpected base36 encoding");
		free(s);
	}
	mu_end;
}

bool test_rz_base36_decode_basic(void) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(vectors); i++) {
		ut64 out = 0;
		ut64 ret = rz_base36_decode(&out, vectors[i].str, strlen(vectors[i].str));
		mu_assert_neq(ret, -1, "decode failed unexpectedly");
		mu_assert_eq(out, vectors[i].value, "base36 decode mismatch");
	}
	mu_end;
}

bool test_rz_base36_roundtrip_large(void) {
	const ut64 x = 0xDEADBEEFCAFEBABEULL; /* arbitrary 64‑bit value */
	char *enc = rz_base36_encode_dyn(x);
	mu_assert_notnull(enc, "encode_dyn returned NULL");

	ut64 out = 0;
	st64 ret = rz_base36_decode(&out, enc, strlen(enc));
	free(enc);

	mu_assert_neq(ret, -1, "decode failed unexpectedly");
	mu_assert_eq(out, x, "round‑trip encode/decode failed");
	mu_end;
}

bool test_rz_base36_decode_invalid_char(void) {
	/* '@' is not legal in [0‑9A‑Z] */
	const char bad[] = "1a@";
	ut64 out = 0;
	st64 ret = rz_base36_decode(&out, bad, strlen(bad));
	mu_assert_eq(ret, -1, "decoder did not flag invalid char");
	mu_end;
}

bool test_rz_base36_decode_overflow(void) {
	/* "zzzzzzzzzzzzzz" (14×'z') = 36^14-1 > 2^64-1 */
	const char huge[] = "zzzzzzzzzzzzzz";
	ut64 out = 0;
	ut64 ret = rz_base36_decode(&out, huge, strlen(huge));
	mu_assert_eq(ret, -1, "decoder did not flag overflow");
	mu_end;
}

bool test_rz_base36_decode_dyn(void) {
	ut64 *out = rz_base36_decode_dyn("21i3v9", 6);
	mu_assert_notnull(out, "decode_dyn returned NULL");
	mu_assert_eq(*out, 123456789ULL, "decode_dyn mismatch");
	free(out);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_base36_encode_dyn_basic);
	mu_run_test(test_rz_base36_decode_basic);
	mu_run_test(test_rz_base36_roundtrip_large);
	mu_run_test(test_rz_base36_decode_invalid_char);
	mu_run_test(test_rz_base36_decode_overflow);
	mu_run_test(test_rz_base36_decode_dyn);

	return tests_passed != tests_run;
}

mu_main(all_tests)
