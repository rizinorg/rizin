// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_base32_decode_dyn(void) {
	char *hello = (char *)rz_base32_decode_dyn("NBSWY3DP", -1);
	mu_assert_streq(hello, "hello", "base32_decode_dyn");
	free(hello);
	mu_end;
}

bool test_rz_base32_decode(void) {
	ut8 *hello = malloc(50);
	int status = rz_base32_decode(hello, "NBSWY3DP", -1);
	mu_assert_eq(status, (int)strlen("hello"), "valid base32 decoding");
	mu_assert_streq((char *)hello, "hello", "base32 decoding");
	free(hello);
	mu_end;
}

bool test_rz_base32_decode_invalid(void) {
	ut8 buf[16];
	mu_assert_eq(rz_base32_decode(buf, "MZXW@===", -1), -1, "decoder accepted invalid char");
	mu_end;
}

bool test_rz_base32_encode_dyn(void) {
	static const struct {
		const char *in;
		const char *exp;
	} vec[] = {
		{ "hello", "NBSWY3DP" },
		{ "hello1", "NBSWY3DPGE======" },
		{ "hello12", "NBSWY3DPGEZA====" },
		{ "hello123", "NBSWY3DPGEZDG===" }
	};

	for (size_t i = 0; i < RZ_ARRAY_SIZE(vec); i++) {
		char *enc = rz_base32_encode_dyn((const ut8 *)vec[i].in, strlen(vec[i].in));
		mu_assert_streq(enc, vec[i].exp, "encode_dyn mismatch");
		free(enc);
	}
	mu_end;
}

bool test_rz_base32_encode(void) {
	char enc[32];
	rz_base32_encode(enc, (const ut8 *)"hello", 5);
	mu_assert_streq(enc, "NBSWY3DP", "encode mismatch");
	mu_end;
}

bool test_rz_base32_decode_offby1(void) {
	unsigned char msg[4] = { 'A', 0, 'B', 0 };
	char enc[32] = { 0 };

	rz_base32_encode(enc, msg, 1);
	rz_base32_decode(msg, enc, strlen(enc));
	mu_assert_eq(msg[2], 'B', "decoder wrote past end");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_base32_decode_dyn);
	mu_run_test(test_rz_base32_decode);
	mu_run_test(test_rz_base32_decode_invalid);
	mu_run_test(test_rz_base32_encode_dyn);
	mu_run_test(test_rz_base32_encode);
	mu_run_test(test_rz_base32_decode_offby1);
	return tests_passed != tests_run;
}

mu_main(all_tests)
