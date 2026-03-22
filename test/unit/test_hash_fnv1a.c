// SPDX-FileCopyrightText: 2026 AHMEDSAMI11
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_hash.h>
#include "minunit.h"

typedef struct {
	const ut8 *input;
	size_t input_size;
	const char *algo;
	const char *expected;
} hash_data_t;

#define INDATA(x) .input = (ut8 *)(x), .input_size = (sizeof(x) - 1)

static hash_data_t fnv1a_hashes[] = {
	{ INDATA(""), .algo = "fnv1a32", .expected = "c59d1c81" },
	{ INDATA("a"), .algo = "fnv1a32", .expected = "2c290ce4" },
	{ INDATA("foobar"), .algo = "fnv1a32", .expected = "68f99cbf" },
	{ INDATA("hello"), .algo = "fnv1a32", .expected = "ab2c9f4f" },
	{ INDATA(""), .algo = "fnv1a64", .expected = "25232284e49cf2cb" },
	{ INDATA("a"), .algo = "fnv1a64", .expected = "8cec01864cdc63af" },
	{ INDATA("foobar"), .algo = "fnv1a64", .expected = "e86739f771419485" },
};

#undef INDATA

bool test_fnv1a_hashes(void) {
	RzHash *rz = rz_hash_new();
	mu_assert_notnull(rz, "rz_hash_new");

	for (size_t i = 0; i < RZ_ARRAY_SIZE(fnv1a_hashes); i++) {
		hash_data_t *hd = &fnv1a_hashes[i];
		char *hex = rz_hash_cfg_calculate_small_block_string(rz, hd->algo, hd->input, hd->input_size, NULL, false);
		mu_assert_notnull(hex, hd->algo);
		mu_assert_streq(hex, hd->expected, hd->algo);
		free(hex);
	}

	rz_hash_free(rz);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_fnv1a_hashes);
	return tests_passed != tests_run;
}

mu_main(all_tests)
