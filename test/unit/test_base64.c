// SPDX-FileCopyrightText: 2015 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_base64_decode_dyn(void) {
	char *hello = (char *)rz_base64_decode_dyn("aGVsbG8=", -1);
	mu_assert_streq(hello, "hello", "base64_decode_dyn");
	free(hello);
	mu_end;
}

bool test_rz_base64_decode(void) {
	ut8 *hello = malloc(50);
	int status = rz_base64_decode(hello, "aGVsbG8=", -1);
	mu_assert_eq(status, (int)strlen("hello"), "valid base64 decoding");
	mu_assert_streq((char *)hello, "hello", "base64 decoding");
	free(hello);
	mu_end;
}

bool test_rz_base64_decode_invalid(void) {
	ut8 *hello = malloc(50);
	int status = rz_base64_decode(hello, "\x01\x02\x03\x04\x00", -1);
	// Returns the length of the decoded string, 0 == invalid input.
	mu_assert_eq(status, -1, "invalid base64 decoding");
	free(hello);

	unsigned char *foo1, *foo2;
	foo1 = rz_base64_decode_dyn("Zm,Zb0,Zb1=", -1);
	foo2 = rz_base64_decode_dyn("Zm9v", -1);
	mu_assert_true(memcmp(foo1, foo2, 4) != 0, "incorrect treatment of invalid characters");
	free(foo1);
	free(foo2);
	mu_end;
}

int test_rz_base64_encode_dyn(void) {
	char *hello = rz_base64_encode_dyn((const ut8 *)"hello", 6);
	mu_assert_streq(hello, "aGVsbG8A", "base64_encode_dyn");
	free(hello);
	hello = rz_base64_encode_dyn((const ut8 *)"hello1", 7);
	mu_assert_streq(hello, "aGVsbG8xAA==", "base64_encode_dyn");
	free(hello);
	hello = rz_base64_encode_dyn((const ut8 *)"hello12", 8);
	mu_assert_streq(hello, "aGVsbG8xMgA=", "base64_encode_dyn");
	free(hello);
	hello = rz_base64_encode_dyn((const ut8 *)"hello123", 9);
	mu_assert_streq(hello, "aGVsbG8xMjMA", "base64_encode_dyn");
	free(hello);
	mu_end;
}

int test_rz_base64_encode(void) {
	char *hello = malloc(50);
	rz_base64_encode(hello, (const ut8 *)"hello", 5);
	mu_assert_streq(hello, "aGVsbG8=", "base64_encode");
	free(hello);
	mu_end;
}

int test_rz_base64_decode_offby1(void) {
	unsigned char message[4] = "A\0B";
	char base64[32] = { 0 };
	mu_assert_eq(message[2], 'B', "off-by-1 test");
	rz_base64_encode(base64, message, 1);
	rz_base64_decode(message, base64, strlen(base64));
	mu_assert_eq(message[2], 'B', "rz_base64_decode");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_base64_decode_dyn);
	mu_run_test(test_rz_base64_decode);
	mu_run_test(test_rz_base64_decode_invalid);
	mu_run_test(test_rz_base64_encode_dyn);
	mu_run_test(test_rz_base64_encode);
	mu_run_test(test_rz_base64_decode_offby1);
	return tests_passed != tests_run;
}

mu_main(all_tests)
