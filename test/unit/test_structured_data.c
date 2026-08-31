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

static bool all_tests() {
	mu_run_test(test_structured_data_map_add_null);
	mu_run_test(test_structured_data_array_add_null);
	mu_run_test(test_structured_data_map_add_null_duplicate_key);
	return tests_passed != tests_run;
}

mu_main(all_tests)
