// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_base16_decode_dyn(void) {
	char *hello = (char *)rz_base16_decode_dyn("68656c6c6f", -1);
	mu_assert_streq(hello, "hello", "base16_decode_dyn");
	free(hello);
	mu_end;
}

bool test_rz_base16_decode_even(void) {
	ut8 buf[16];
	int status = rz_base16_decode(buf, "68656c6c6f");
	mu_assert_eq(status, 5, "even-length hex decoded length mismatch");
	mu_assert_memeq(buf, (const ut8 *)"hello", 5, "even-length hex decoded bytes mismatch");
	mu_assert_eq(buf[5], '\0', "missing NUL terminator");
	mu_end;
}

bool test_rz_base16_decode_odd(void) {
	ut8 buf[16];
	int status = rz_base16_decode(buf, "68 65 6c 6c 6f 6");
	mu_assert_eq(status, -6, "odd-length hex did not return negative length");
	mu_assert_memeq(buf, (const ut8 *)"hello\x60", 6, "odd-length hex decoded bytes mismatch");
	mu_assert_eq(buf[6], '\0', "missing NUL terminator");
	mu_end;
}

bool test_rz_base16_decode_invalid(void) {
	ut8 buf[16];
	int status = rz_base16_decode(buf, "68656cZZ");
	mu_assert_eq(status, 0, "invalid char should return 0");
	mu_end;
}

bool test_rz_base16_encode_dyn(void) {
	char *enc = rz_base16_encode_dyn((const ut8 *)"hello", 5);
	mu_assert_streq(enc, "68656c6c6f", "encode_dyn mismatch");
	free(enc);
	mu_end;
}

bool test_rz_base16_encode(void) {
	char enc[16];
	rz_base16_encode(enc, (const ut8 *)"hello", 5);
	mu_assert_streq(enc, "68656c6c6f", "encode mismatch");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_base16_decode_dyn);
	mu_run_test(test_rz_base16_decode_even);
	mu_run_test(test_rz_base16_decode_odd);
	mu_run_test(test_rz_base16_decode_invalid);
	mu_run_test(test_rz_base16_encode_dyn);
	mu_run_test(test_rz_base16_encode);

	return tests_passed != tests_run;
}

mu_main(all_tests)
