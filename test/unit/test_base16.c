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

bool test_rz_base16_decode(void) {
	ut8 *hello = malloc(50);
	int status = rz_base16_decode(hello, "68656c6c6f", -1);
	mu_assert_eq(status, (int)strlen("hello"), "valid base16 decoding");
	mu_assert_streq((char *)hello, "hello", "base16 decoding");
	free(hello);
	mu_end;
}

bool test_rz_base16_decode_invalid(void) {
	ut8 buf[16];
	mu_assert_eq(rz_base16_decode(buf, "MZXW@===", -1), -1, "decoder accepted invalid char");
	mu_end;
}

bool test_rz_base16_encode_dyn(void) {
  char *enc = rz_base16_encode_dyn((const ut8 *)"hello", 5);
  mu_assert_streq(enc, "68656C6C6F", "encode_dyn mismatch");
  free(enc);
  mu_end;
}

bool test_rz_base16_encode(void) {
	char enc[16];
	rz_base16_encode(enc, (const ut8 *)"hello", 5);
	mu_assert_streq(enc, "68656C6C6F", "encode mismatch");
	mu_end;
}

bool test_rz_base16_decode_offby1(void) {
	unsigned char msg[4] = { 'A', 0, 'B', 0 };
	char enc[8] = { 0 };

	rz_base16_encode(enc, msg, 1);
	rz_base16_decode(msg, enc, strlen(enc));
	mu_assert_eq(msg[2], 'B', "base16 decoder wrote past end");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_base16_decode_dyn);
	mu_run_test(test_rz_base16_decode);
	mu_run_test(test_rz_base16_decode_invalid);
	mu_run_test(test_rz_base16_encode_dyn);
	mu_run_test(test_rz_base16_encode);
	mu_run_test(test_rz_base16_decode_offby1);

	return tests_passed != tests_run;
}

mu_main(all_tests)

