// SPDX-FileCopyrightText: 2026 kx7m2qd <kx7m2qd@users.noreply.github.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static const RzStrUriParamSpec spec_d = { "d", RZ_STR_URI_PARAM_TYPE_INT, false };
static const RzStrUriParamSpec spec_verbose = { "verbose", RZ_STR_URI_PARAM_TYPE_BOOL, false };
static const RzStrUriParamSpec spec_name = { "name", RZ_STR_URI_PARAM_TYPE_STRING, true };

static RzPVector *make_test_grammar(void) {
	RzPVector *grammars = rz_pvector_new(NULL);
	rz_pvector_push(grammars, (void *)&spec_d);
	rz_pvector_push(grammars, (void *)&spec_verbose);
	rz_pvector_push(grammars, (void *)&spec_name);
	return grammars;
}

bool test_rz_str_uri_params_happy_path(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("d=32,verbose=true,name=shake", grammars, &error);
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
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_missing_required(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("d=32", grammars, &error);
	mu_assert_null(p, "parse should fail when required param is missing");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_unknown_key(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=x,bogus=1", grammars, &error);
	mu_assert_null(p, "parse should fail on unknown key");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_bad_int(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=x,d=notanumber", grammars, &error);
	mu_assert_null(p, "parse should fail on non-numeric int value");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_optional_absent(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=onlyname", grammars, &error);
	mu_assert_notnull(p, "parse should succeed with only required param given");
	mu_assert_null(error, "no error expected");

	mu_assert_false(rz_str_uri_params_has(p, "d"), "d should not be set");
	st64 d = 0;
	mu_assert_false(rz_str_uri_params_get_int(p, "d", &d), "get_int should fail for unset param");

	rz_str_uri_params_free(p);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_whitespace_tolerant(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse(" name = spaced , d = 7 ", grammars, &error);
	mu_assert_notnull(p, "parse should tolerate surrounding whitespace");
	mu_assert_null(error, "no error expected");

	st64 d = 0;
	const char *name = NULL;
	mu_assert_true(rz_str_uri_params_get_int(p, "d", &d), "get_int d should succeed");
	mu_assert_eq(d, 7, "d value");
	mu_assert_true(rz_str_uri_params_get_string(p, "name", &name), "get_string name should succeed");
	mu_assert_streq(name, "spaced", "name value trimmed");

	rz_str_uri_params_free(p);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_double_equals(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name==value", grammars, &error);
	mu_assert_null(p, "name==value should fail to parse");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_trailing_double_equals(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name==", grammars, &error);
	mu_assert_null(p, "name== should fail to parse");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_empty_segments(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=x,,,,,d=5", grammars, &error);
	mu_assert_notnull(p, "empty comma segments should be tolerated");
	mu_assert_null(error, "no error expected");

	st64 d = 0;
	const char *name = NULL;
	mu_assert_true(rz_str_uri_params_get_string(p, "name", &name), "name should be set");
	mu_assert_streq(name, "x", "name value");
	mu_assert_true(rz_str_uri_params_get_int(p, "d", &d), "d should be set");
	mu_assert_eq(d, 5, "d value");

	rz_str_uri_params_free(p);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_empty_value(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=", grammars, &error);
	mu_assert_null(p, "name= should fail to parse (empty value)");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_empty_key(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("=novalue", grammars, &error);
	mu_assert_null(p, "=novalue should fail to parse (empty key)");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_multiple_equals(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("name=x=y=z", grammars, &error);
	mu_assert_null(p, "name=x=y=z should fail to parse (unexpected '=' in value)");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool test_rz_str_uri_params_no_equals_anywhere(void) {
	RzPVector *grammars = make_test_grammar();
	char *error = NULL;
	RzStrUriParams *p = rz_str_uri_params_parse("x,y,z", grammars, &error);
	mu_assert_null(p, "x,y,z should fail to parse (no '=' in any segment)");
	mu_assert_notnull(error, "error should be set");
	free(error);
	rz_pvector_free(grammars);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_str_uri_params_happy_path);
	mu_run_test(test_rz_str_uri_params_missing_required);
	mu_run_test(test_rz_str_uri_params_unknown_key);
	mu_run_test(test_rz_str_uri_params_bad_int);
	mu_run_test(test_rz_str_uri_params_optional_absent);
	mu_run_test(test_rz_str_uri_params_whitespace_tolerant);
	mu_run_test(test_rz_str_uri_params_double_equals);
	mu_run_test(test_rz_str_uri_params_trailing_double_equals);
	mu_run_test(test_rz_str_uri_params_empty_segments);
	mu_run_test(test_rz_str_uri_params_empty_value);
	mu_run_test(test_rz_str_uri_params_empty_key);
	mu_run_test(test_rz_str_uri_params_multiple_equals);
	mu_run_test(test_rz_str_uri_params_no_equals_anywhere);

	return tests_passed != tests_run;
}

mu_main(all_tests)
