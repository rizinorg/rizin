// SPDX-FileCopyrightText: 2023 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_crypto.h>
#include "minunit.h"

bool test_use(void) {
	RzCrypto *cry = rz_crypto_new();
	rz_crypto_use(cry, "xor");
	rz_crypto_set_key(cry, (ut8 *)"ABCD", 4, 0, RZ_CRYPTO_DIR_ENCRYPT);
	rz_crypto_final(cry, (ut8 *)"ABCD", 4);
	mu_assert_memeq(rz_crypto_get_output(cry, NULL), (ut8 *)"\x00\x00\x00\x00", 4, "xor same msg is 0");
	rz_crypto_free(cry);
	mu_end;
}

bool test_multi_use(void) {
	RzCrypto *cry = rz_crypto_new();
	rz_crypto_use(cry, "xor");
	rz_crypto_set_key(cry, (ut8 *)"ABCD", 4, 0, RZ_CRYPTO_DIR_ENCRYPT);
	rz_crypto_final(cry, (ut8 *)"ABCD", 4);
	rz_crypto_reset(cry);
	rz_crypto_use(cry, "xor");
	rz_crypto_set_key(cry, (ut8 *)"ABCD", 4, 0, RZ_CRYPTO_DIR_DECRYPT);
	rz_crypto_update(cry, (ut8 *)"\x00\x00\x00\x00", 4);
	mu_assert_memeq(rz_crypto_get_output(cry, NULL), (ut8 *)"ABCD", 4, "xor with 0 is msg");
	rz_crypto_free(cry);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_use);
	mu_run_test(test_multi_use);
	return tests_passed != tests_run;
}

mu_main(all_tests)
