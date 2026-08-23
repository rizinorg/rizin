// SPDX-FileCopyrightText: 2026 kx7m2qd <kx7m2qd@users.noreply.github.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static const RzStrUriParamSpec test_grammar[] = {
	{ "d", RZ_STR_URI_PARAM_TYPE_INT, false },
	{ "verbose", RZ_STR_URI_PARAM_TYPE_BOOL, false },
	{ "name", RZ_STR_URI_PARAM_TYPE_STRING, true },
};
static const size_t test_grammar_count = sizeof(test_grammar) / sizeof(test_grammar[0]);

bool test_rz_str_uri_params_happy_path(void) {
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("d=32,verbose=true,name=shake", test_grammar, test_grammar_count, &error);
	mu_assert_notnull(p, "parse should succeed");
	mu_assert_null(error, "no error expected");

	st64 d = 0;
	bool verbose = false;
	const char *name = NULL;
	mu_assert_true(rz_str_uri_params_get_int(p, "d", &d), "get_int d should succeed");
	mu_assert_eq(d, 32, "d value");
	mu_assert_true(rz_str_uri_params_get_bool(p, "verbose", &verbose), "get_bool verbose should succeed");
	mu_assert_true(verbose, "verbose value");
	mu_assert_true(rz_str_uri_params_get_string(p, "name", &name), "get_string name should succeed");
	mu_assert_streq(name, "shake", "name value");

	rz_str_uri_params_free(p);
	mu_end;
}

bool test_rz_str_uri_params_missing_required(void) {
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("d=32", test_grammar, test_grammar_count, &error);
	mu_assert_null(p, "parse should fail when required param is missing");
	mu_assert_notnull(error, "error should be set");
	free(error);
	mu_end;
}

bool test_rz_str_uri_params_unknown_key(void) {
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=x,bogus=1", test_grammar, test_grammar_count, &error);
	mu_assert_null(p, "parse should fail on unknown key");
	mu_assert_notnull(error, "error should be set");
	free(error);
	mu_end;
}

bool test_rz_str_uri_params_bad_int(void) {
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=x,d=notanumber", test_grammar, test_grammar_count, &error);
	mu_assert_null(p, "parse should fail on non-numeric int value");
	mu_assert_notnull(error, "error should be set");
	free(error);
	mu_end;
}

bool test_rz_str_uri_params_optional_absent(void) {
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=onlyname", test_grammar, test_grammar_count, &error);
	mu_assert_notnull(p, "parse should succeed with only required param given");
	mu_assert_null(error, "no error expected");

	mu_assert_false(rz_str_uri_params_has(p, "d"), "d should not be set");
	st64 d = 0;
	mu_assert_false(rz_str_uri_params_get_int(p, "d", &d), "get_int should fail for unset param");

	rz_str_uri_params_free(p);
	mu_end;
}

bool test_rz_str_uri_params_whitespace_tolerant(void) {
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse(" name = spaced , d = 7 ", test_grammar, test_grammar_count, &error);
	mu_assert_notnull(p, "parse should tolerate surrounding whitespace");
	mu_assert_null(error, "no error expected");

	st64 d = 0;
	const char *name = NULL;
	mu_assert_true(rz_str_uri_params_get_int(p, "d", &d), "get_int d should succeed");
	mu_assert_eq(d, 7, "d value");
	mu_assert_true(rz_str_uri_params_get_string(p, "name", &name), "get_string name should succeed");
	mu_assert_streq(name, "spaced", "name value trimmed");

	rz_str_uri_params_free(p);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_str_uri_params_happy_path);
	mu_run_test(test_rz_str_uri_params_missing_required);
	mu_run_test(test_rz_str_uri_params_unknown_key);
	mu_run_test(test_rz_str_uri_params_bad_int);
	mu_run_test(test_rz_str_uri_params_optional_absent);
	mu_run_test(test_rz_str_uri_params_whitespace_tolerant);

	return tests_passed != tests_run;
}

mu_main(all_tests)
