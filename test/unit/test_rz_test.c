
#define main not_main
#include "../../binrz/rz-test/rz-test.c"
#include "../../binrz/rz-test/load.c"
#include "../../binrz/rz-test/run.c"
#undef main

#include "minunit.h"

#define FILENAME "unit/rz_test_cmd_test"

bool test_rz_test_database_load_cmd(void) {
	RzTestDatabase *db = rz_test_test_database_new ();
	database_load (db, FILENAME, 1);

	mu_assert_eq (rz_pvector_len (&db->tests), 4, "tests count");

	RzTest *test = rz_pvector_at (&db->tests, 0);
	mu_assert_eq (test->type, RZ_TEST_TYPE_CMD, "test type");
	RzCmdTest *cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "multiline0", "name");
	mu_assert_streq (cmd_test->file.value, "-", "file");
	mu_assert_streq (cmd_test->cmds.value, "rm -rf /\n", "cmds");
	mu_assert_streq (cmd_test->expect.value, "expected\noutput\n", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 6, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 10, "line begin");

	test = rz_pvector_at (&db->tests, 1);
	mu_assert_eq (test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "singleline0", "name");
	mu_assert_streq (cmd_test->expect.value, "", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 17, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 18, "line begin");

	test = rz_pvector_at (&db->tests, 2);
	mu_assert_eq (test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "multiline1", "name");
	mu_assert_streq (cmd_test->expect.value, "more\nexpected\noutput\n", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 25, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 30, "line begin");

	test = rz_pvector_at (&db->tests, 3);
	mu_assert_eq (test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq (cmd_test->name.value, "singleline1", "name");
	mu_assert_streq (cmd_test->expect.value, "", "expect");
	mu_assert_eq (cmd_test->expect.line_begin, 37, "line begin");
	mu_assert_eq (cmd_test->expect.line_end, 38, "line begin");

	rz_test_test_database_free (db);
	mu_end;
}

bool test_rz_test_fix(void) {
	RzTestDatabase *db = rz_test_test_database_new ();
	database_load (db, FILENAME, 1);

	RzPVector *results = rz_pvector_new ((RzPVectorFree)rz_test_test_result_info_free);

	RzTestResultInfo *result0 = RZ_NEW0 (RzTestResultInfo);
	rz_pvector_push (results, result0);
	result0->test = rz_pvector_at (&db->tests, 0);
	result0->result = RZ_TEST_RESULT_FAILED;
	result0->proc_out = RZ_NEW0 (RzSubprocessOutput);
	result0->proc_out->out = strdup ("fixed\nresult\nfor\n0\n");
	result0->proc_out->err = strdup ("");

	RzTestResultInfo *result1 = RZ_NEW0 (RzTestResultInfo);
	rz_pvector_push (results, result1);
	result1->test = rz_pvector_at (&db->tests, 1);
	result1->result = RZ_TEST_RESULT_FAILED;
	result1->proc_out = RZ_NEW0 (RzSubprocessOutput);
	result1->proc_out->out = strdup ("fixed\nresult\nfor\n1\n");
	result1->proc_out->err = strdup ("");

	RzTestResultInfo *result2 = RZ_NEW0 (RzTestResultInfo);
	rz_pvector_push (results, result2);
	result2->test = rz_pvector_at (&db->tests, 2);
	result2->result = RZ_TEST_RESULT_FAILED;
	result2->proc_out = RZ_NEW0 (RzSubprocessOutput);
	result2->proc_out->out = strdup ("fixed\nresult\nfor\n2\n");
	result2->proc_out->err = strdup ("");

	RzTestResultInfo *result3 = RZ_NEW0 (RzTestResultInfo);
	rz_pvector_push (results, result3);
	result3->test = rz_pvector_at (&db->tests, 3);
	result3->result = RZ_TEST_RESULT_FAILED;
	result3->proc_out = RZ_NEW0 (RzSubprocessOutput);
	result3->proc_out->out = strdup ("fixed\nresult\nfor\n3\n");
	result3->proc_out->err = strdup ("");

	char *content = rz_file_slurp (FILENAME, NULL);
	mu_assert ("test file", content);

	char *newc = replace_cmd_kv (result0->test->path, content, result0->test->cmd_test->expect.line_begin,
			result0->test->cmd_test->expect.line_end, "EXPECT", result0->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result1->test->path, content, result1->test->cmd_test->expect.line_begin,
			result1->test->cmd_test->expect.line_end, "EXPECT", result1->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result2->test->path, content, result2->test->cmd_test->expect.line_begin,
			result2->test->cmd_test->expect.line_end, "EXPECT", result2->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	newc = replace_cmd_kv (result3->test->path, content, result3->test->cmd_test->expect.line_begin,
			result3->test->cmd_test->expect.line_end, "EXPECT", result3->proc_out->out, results);
	mu_assert ("fixed", newc);
	free (content);
	content = newc;

	rz_pvector_free (results);

	mu_assert_streq (content,
		"NAME=multiline0\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf /\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"0\n"
		"EOF\n"
		"RUN\n"
		"\n"
		"NAME=singleline0\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"1\n"
		"EOF\n"
		"RUN\n"
		"\n"
		"NAME=multiline1\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"2\n"
		"EOF\n"
		"RUN\n"
		"\n"
		"NAME=singleline1\n"
		"FILE=-\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"3\n"
		"EOF\n"
		"RUN", "fixed contents");

	free (content);

	rz_test_test_database_free (db);
	mu_end;
}

int all_tests() {
	mu_run_test (test_rz_test_database_load_cmd);
	mu_run_test (test_rz_test_fix);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
