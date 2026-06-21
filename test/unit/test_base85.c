// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_base85_encode_dyn_nodelims(void) {
	const char *src = "hello, ascii85";
	char *dest = rz_base85_encode_dyn(src, strlen(src), 0, 0, 1);
	mu_assert_streq(dest, "BOu!rD_*#>F(8ou3&L", "ascii85 encode mismatch");
	free(dest);
	mu_end;
}

bool test_rz_base85_encode_dyn_delims(void) {
	const char *src = "hello, ascii85";
	char *dest = rz_base85_encode_dyn(src, strlen(src), 1, 0, 1);
	mu_assert_streq(dest, "<~BOu!rD_*#>F(8ou3&L~>", "ascii85 encode mismatch");
	free(dest);
	mu_end;
}

bool test_rz_base85_decode_dyn_nodelims(void) {
	const char *src = "BOu!rD_*#>F(8ou3&L";
	char *dest = rz_base85_decode_dyn(src, strlen(src), 0, 0, NULL);
	mu_assert_streq(dest, "hello, ascii85", "decoder output mismatch");
	free(dest);
	mu_end;
}

bool test_rz_base85_decode_dyn_delims(void) {
	const char *src = "<~BOu!rD_*#>F(8ou3&L~>";
	char *dest = rz_base85_decode_dyn(src, strlen(src), 1, 0, NULL);
	mu_assert_streq(dest, "hello, ascii85", "ascii85 decode with delimiters mismatch");
	free(dest);
	mu_end;
}

bool test_rz_base85_encode_decode_wrap10(void) {
	char src[51];
	memset(src, 'A', 50);
	src[50] = '\0';

	char *encoded = rz_base85_encode_dyn(src, strlen(src), 0, 10, 0);

	int col = 0, newlines = 0;
	for (size_t i = 0; encoded[i]; i++) {
		if (encoded[i] == '\n') {
			mu_assert_eq(col, 10, "line length before \\n not 10");
			col = 0;
			newlines++;
		} else {
			col++;
		}
	}
	mu_assert_true(col <= 10, "final line exceeds wrap length");
	mu_assert_true(newlines > 0, "no line breaks were inserted");

	size_t decoded_len;
	char *decoded = rz_base85_decode_dyn(encoded, strlen(encoded), 0, 0, &decoded_len);

	mu_assert_eq(decoded_len, 50U, "decoded length mismatch");
	mu_assert_true(memcmp(decoded, src, 50) == 0, "decoded data mismatch");

	free(encoded);
	free(decoded);
	mu_end;
}

bool test_rz_base85_encode_decode_z_abbrev(void) {
	const ut8 zeros[4] = { 0, 0, 0, 0 };

	char *enc = rz_base85_encode_dyn((const char *)zeros, 4, 0, 0, 0);
	mu_assert_notnull(enc, "rz_base85_encode_dyn returned NULL");
	mu_assert_streq(enc, "z", "encode zeros should be 'z'");

	size_t decoded_len;
	char *decoded = rz_base85_decode_dyn("zz", -1, 0, 0, &decoded_len);
	mu_assert_notnull(decoded, "rz_base85_decode_dyn returned NULL");
	mu_assert_eq(decoded_len, 8U, "decoded length != 8");

	for (size_t i = 0; i < decoded_len; i++) {
		mu_assert_eq(decoded[i], '\0', "decoded byte non‑zero");
	}

	free(enc);
	free(decoded);
	mu_end;
}

bool test_rz_base85_decode_invalid_strict_vs_lenient(void) {
	const char bad[] = "FCfN8v";
	size_t decoded_len;

	char *strict_out = rz_base85_decode_dyn(bad, -1, 0, 0, &decoded_len);
	mu_assert_true(strict_out == NULL, "decoder accepted garbage in strict mode");

	char *lenient_out = rz_base85_decode_dyn(bad, -1, 0, 1, &decoded_len);
	mu_assert_notnull(lenient_out, "lenient decode returned NULL");
	mu_assert_eq(decoded_len, 4U, "decoded length != 4");
	mu_assert_true(memcmp(lenient_out, "test", 4) == 0, "lenient decode produced wrong bytes");

	free(lenient_out);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_base85_encode_dyn_nodelims);
	mu_run_test(test_rz_base85_decode_dyn_nodelims);
	mu_run_test(test_rz_base85_encode_dyn_delims);
	mu_run_test(test_rz_base85_decode_dyn_delims);
	mu_run_test(test_rz_base85_encode_decode_wrap10);
	mu_run_test(test_rz_base85_encode_decode_z_abbrev);
	mu_run_test(test_rz_base85_decode_invalid_strict_vs_lenient);

	return tests_passed != tests_run;
}

mu_main(all_tests)
