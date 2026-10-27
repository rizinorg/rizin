// SPDX-FileCopyrightText: 2026 Jagath-P <jagathp0210@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static bool test_structured_data_map_add_null(void) {
	RzStructuredData *sd = rz_structured_data_new_map();
	mu_assert_notnull(sd, "map created");

	mu_assert_true(rz_structured_data_map_add_null(sd, "foo"), "add_null succeeds");

	char *json = rz_structured_data_to_json(sd);
	mu_assert_notnull(json, "json generated");
	mu_assert_streq(json, "{\"foo\":null}", "json null value");
	free(json);

	char *yaml = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(yaml, "yaml generated");
	mu_assert_streq(yaml, "foo: null\n", "yaml null value");
	free(yaml);

	rz_structured_data_free(sd);
	mu_end;
}

static bool test_structured_data_array_add_null(void) {
	RzStructuredData *sd = rz_structured_data_new_array();
	mu_assert_notnull(sd, "array created");

	mu_assert_true(rz_structured_data_array_add_null(sd), "add_null succeeds");

	char *json = rz_structured_data_to_json(sd);
	mu_assert_notnull(json, "json generated");
	mu_assert_streq(json, "[null]", "json null value");
	free(json);

	char *yaml = rz_structured_data_to_yaml(sd);
	mu_assert_notnull(yaml, "yaml generated");
	mu_assert_streq(yaml, "- null\n", "yaml null value");
	free(yaml);

	rz_structured_data_free(sd);
	mu_end;
}

static bool test_structured_data_map_add_null_duplicate_key(void) {
	RzStructuredData *sd = rz_structured_data_new_map();
	mu_assert_notnull(sd, "map created");

	mu_assert_true(rz_structured_data_map_add_null(sd, "dup"), "first add succeeds");
	mu_assert_false(rz_structured_data_map_add_null(sd, "dup"), "duplicate key rejected");

	rz_structured_data_free(sd);
	mu_end;
}

static bool test_structured_data_double(void) {
	RzStructuredData *sd = rz_structured_data_new_map();
	mu_assert_notnull(sd, "map created");
	rz_structured_data_map_add_double(sd, "tenth", 0.1);
	rz_structured_data_map_add_double(sd, "tiny", 1e-9);
	rz_structured_data_map_add_double(sd, "one", 1.0);
	RzStructuredData *arr = rz_structured_data_map_add_array(sd, "special");
	mu_assert_notnull(arr, "array created");
	rz_structured_data_array_add_double(arr, -0.0);
	rz_structured_data_array_add_double(arr, F64_NAN);
	rz_structured_data_array_add_double(arr, F64_PINF);
	rz_structured_data_array_add_double(arr, F64_NINF);

	char *json = rz_structured_data_to_json(sd);
	mu_assert_streq_free(json, "{\"tenth\":0.1,\"tiny\":1.0e-09,\"one\":1.0,\"special\":[-0.0,\"NaN\",\"Infinity\",\"-Infinity\"]}", "json doubles");

	char *yaml = rz_structured_data_to_yaml(sd);
	mu_assert_streq_free(yaml, "tenth: 0.1\ntiny: 1.0e-09\none: 1.0\nspecial:\n  - -0.0\n  - .nan\n  - .inf\n  - -.inf\n", "yaml doubles");

	rz_structured_data_free(sd);
	mu_end;
}

static bool test_structured_data_float(void) {
	RzStructuredData *sd = rz_structured_data_new_map();
	mu_assert_notnull(sd, "map created");
	rz_structured_data_map_add_float(sd, "tenth", 0.1f);
	rz_structured_data_map_add_double(sd, "widened", 0.1f);
	RzStructuredData *arr = rz_structured_data_map_add_array(sd, "list");
	mu_assert_notnull(arr, "array created");
	rz_structured_data_array_add_float(arr, 1e-9f);
	rz_structured_data_array_add_float(arr, F32_NAN);
	rz_structured_data_array_add_float(arr, F32_NINF);

	char *json = rz_structured_data_to_json(sd);
	mu_assert_streq_free(json, "{\"tenth\":0.1,\"widened\":0.10000000149011612,\"list\":[1.0e-09,\"NaN\",\"-Infinity\"]}", "json floats");

	char *yaml = rz_structured_data_to_yaml(sd);
	mu_assert_streq_free(yaml, "tenth: 0.1\nwidened: 0.10000000149011612\nlist:\n  - 1.0e-09\n  - .nan\n  - -.inf\n", "yaml floats");

	rz_structured_data_free(sd);
	mu_end;
}

static void nop_new_struct(void *user, RzStructuredDataBlock block, size_t n_elems) {
}

static void nop_end_struct(void *user) {
}

static void nop_key(void *user, const char *key) {
}

static void collect_double(void *user, double d) {
	*(double *)user = d;
}

static bool test_structured_data_float_without_val_float(void) {
	// An iterator written before val_float existed
	const RzStructuredDataIterator it = {
		.new_struct = nop_new_struct,
		.end_struct = nop_end_struct,
		.key = nop_key,
		.val_double = collect_double,
	};
	RzStructuredData *sd = rz_structured_data_new_array();
	mu_assert_notnull(sd, "array created");
	rz_structured_data_array_add_float(sd, 0.1f);
	double got = 0.0;
	rz_structured_data_iterate(sd, &it, &got);
	mu_assert_true(got == (double)0.1f, "val_double gets the float widened");
	rz_structured_data_free(sd);
	mu_end;
}

static bool all_tests() {
	mu_run_test(test_structured_data_map_add_null);
	mu_run_test(test_structured_data_array_add_null);
	mu_run_test(test_structured_data_map_add_null_duplicate_key);
	mu_run_test(test_structured_data_double);
	mu_run_test(test_structured_data_float);
	mu_run_test(test_structured_data_float_without_val_float);
	return tests_passed != tests_run;
}

mu_main(all_tests)
