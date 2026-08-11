// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#define main not_main
#include "../../binrz/rz-test/rz-test.c"
#include "../../binrz/rz-test/load.c"
#include "../../binrz/rz-test/run.c"
#undef main

#include "minunit.h"

#define FILENAME "unit/rz_test_cmd_test"

typedef struct retry_runner_context_t {
	ut64 calls;
	ut64 succeed_on;
	const char *success_out;
} RetryRunnerContext;

static RzSubprocessOutput *retry_runner(RZ_UNUSED const char *file, RZ_UNUSED const char *args[], RZ_UNUSED size_t args_size,
	RZ_UNUSED const char *envvars[], RZ_UNUSED const char *envvals[], RZ_UNUSED size_t env_size, RZ_UNUSED ut64 timeout_ms, void *user) {
	RetryRunnerContext *ctx = user;
	RzSubprocessOutput *out = RZ_NEW0(RzSubprocessOutput);
	if (!out) {
		return NULL;
	}
	ctx->calls++;
	const char *output = ctx->calls >= ctx->succeed_on ? ctx->success_out : "unexpected\n";
	out->out = (ut8 *)strdup(output);
	out->out_len = strlen(output);
	out->err = (ut8 *)strdup("");
	out->err_len = 0;
	out->ret = 0;
	out->timeout = false;
	return out;
}

bool test_rz_test_cmd_retries(void) {
	RzTestDatabase *db = rz_test_test_database_new();
	database_load(db, FILENAME, 1);
	RzTestRunConfig config = { .timeout_ms = 1000 };
	RzCmdTest *retry_test = ((RzTest *)rz_pvector_at(&db->tests, 0))->cmd_test;
	RzCmdTest *single_shot_test = ((RzTest *)rz_pvector_at(&db->tests, 2))->cmd_test;

	RetryRunnerContext ctx = { .succeed_on = 2, .success_out = retry_test->expect.value };
	RzSubprocessOutput *out = run_cmd_test_with_retries(&config, retry_test, retry_runner, &ctx);
	mu_assert_true(rz_test_check_cmd_test(out, retry_test), "retry succeeds");
	mu_assert_eq(ctx.calls, 2, "retry stops after success");
	rz_subprocess_output_free(out);

	ctx = (RetryRunnerContext){ .succeed_on = 5, .success_out = retry_test->expect.value };
	out = run_cmd_test_with_retries(&config, retry_test, retry_runner, &ctx);
	mu_assert_false(rz_test_check_cmd_test(out, retry_test), "retry remains failed");
	mu_assert_eq(ctx.calls, 4, "retry budget is bounded");
	rz_subprocess_output_free(out);

	ctx = (RetryRunnerContext){ .succeed_on = 2, .success_out = single_shot_test->expect.value };
	out = run_cmd_test_with_retries(&config, single_shot_test, retry_runner, &ctx);
	mu_assert_false(rz_test_check_cmd_test(out, single_shot_test), "default remains failed");
	mu_assert_eq(ctx.calls, 1, "default is single shot");
	rz_subprocess_output_free(out);

	rz_test_test_database_free(db);
	mu_end;
}

bool test_rz_test_database_load_cmd(void) {
	RzTestDatabase *db = rz_test_test_database_new();
	database_load(db, FILENAME, 1);

	mu_assert_eq(rz_pvector_len(&db->tests), 4, "tests count");

	RzTest *test = rz_pvector_at(&db->tests, 0);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	RzCmdTest *cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "multiline0", "name");
	mu_assert_streq(cmd_test->file.value, "=", "file");
	mu_assert_streq(cmd_test->cmds.value, "rm -rf /\n", "cmds");
	mu_assert_streq(cmd_test->expect.value, "expected\noutput\n", "expect");
	mu_assert_eq(cmd_test->retries.set, true, "retries set");
	mu_assert_eq(cmd_test->retries.value, 3, "retries value");
	mu_assert_eq(cmd_test->expect.line_begin, 7, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 11, "line begin");

	test = rz_pvector_at(&db->tests, 1);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "singleline0", "name");
	mu_assert_streq(cmd_test->expect.value, "", "expect");
	mu_assert_eq(cmd_test->expect.line_begin, 18, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 19, "line begin");

	test = rz_pvector_at(&db->tests, 2);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "multiline1", "name");
	mu_assert_streq(cmd_test->expect.value, "more\nexpected\noutput\n", "expect");
	mu_assert_eq(cmd_test->expect.line_begin, 26, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 31, "line begin");
	mu_assert_eq(cmd_test->retries.set, false, "retries unset");
	mu_assert_eq(cmd_test->retries.value, 0, "retries value");

	test = rz_pvector_at(&db->tests, 3);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "singleline1", "name");
	mu_assert_streq(cmd_test->expect.value, "", "expect");
	mu_assert_eq(cmd_test->expect.line_begin, 38, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 39, "line begin");

	rz_test_test_database_free(db);
	mu_end;
}

bool test_rz_test_fix(void) {
	RzTestDatabase *db = rz_test_test_database_new();
	database_load(db, FILENAME, 1);

	RzPVector *results = rz_pvector_new((RzPVectorFree)rz_test_test_result_info_free);

	RzTestResultInfo *result0 = RZ_NEW0(RzTestResultInfo);
	rz_pvector_push(results, result0);
	result0->test = rz_pvector_at(&db->tests, 0);
	result0->result = RZ_TEST_RESULT_FAILED;
	result0->proc_out = RZ_NEW0(RzSubprocessOutput);
	result0->proc_out->out = (ut8 *)strdup("fixed\nresult\nfor\n0\n");
	result0->proc_out->out_len = strlen((char *)result0->proc_out->out);
	result0->proc_out->err = (ut8 *)strdup("");
	result0->proc_out->err_len = strlen((char *)result0->proc_out->err);

	RzTestResultInfo *result1 = RZ_NEW0(RzTestResultInfo);
	rz_pvector_push(results, result1);
	result1->test = rz_pvector_at(&db->tests, 1);
	result1->result = RZ_TEST_RESULT_FAILED;
	result1->proc_out = RZ_NEW0(RzSubprocessOutput);
	result1->proc_out->out = (ut8 *)strdup("fixed\nresult\nfor\n1\n");
	result1->proc_out->out_len = strlen((char *)result1->proc_out->out);
	result1->proc_out->err = (ut8 *)strdup("");
	result1->proc_out->err_len = strlen((char *)result1->proc_out->err);

	RzTestResultInfo *result2 = RZ_NEW0(RzTestResultInfo);
	rz_pvector_push(results, result2);
	result2->test = rz_pvector_at(&db->tests, 2);
	result2->result = RZ_TEST_RESULT_FAILED;
	result2->proc_out = RZ_NEW0(RzSubprocessOutput);
	result2->proc_out->out = (ut8 *)strdup("fixed\nresult\nfor\n2\n");
	result2->proc_out->out_len = strlen((char *)result2->proc_out->out);
	result2->proc_out->err = (ut8 *)strdup("");
	result2->proc_out->err_len = strlen((char *)result2->proc_out->err);

	RzTestResultInfo *result3 = RZ_NEW0(RzTestResultInfo);
	rz_pvector_push(results, result3);
	result3->test = rz_pvector_at(&db->tests, 3);
	result3->result = RZ_TEST_RESULT_FAILED;
	result3->proc_out = RZ_NEW0(RzSubprocessOutput);
	result3->proc_out->out = (ut8 *)strdup("fixed\nresult\nfor\n3\n");
	result3->proc_out->err = (ut8 *)strdup("");

	char *content = rz_file_slurp(FILENAME, NULL);
	mu_assert("test file", content);

	char *newc = replace_cmd_kv(result0->test->path, content, result0->test->cmd_test->expect.line_begin,
		result0->test->cmd_test->expect.line_end, "EXPECT", (char *)result0->proc_out->out, results);
	mu_assert("fixed", newc);
	free(content);
	content = newc;

	newc = replace_cmd_kv(result1->test->path, content, result1->test->cmd_test->expect.line_begin,
		result1->test->cmd_test->expect.line_end, "EXPECT", (char *)result1->proc_out->out, results);
	mu_assert("fixed", newc);
	free(content);
	content = newc;

	newc = replace_cmd_kv(result2->test->path, content, result2->test->cmd_test->expect.line_begin,
		result2->test->cmd_test->expect.line_end, "EXPECT", (char *)result2->proc_out->out, results);
	mu_assert("fixed", newc);
	free(content);
	content = newc;

	newc = replace_cmd_kv(result3->test->path, content, result3->test->cmd_test->expect.line_begin,
		result3->test->cmd_test->expect.line_end, "EXPECT", (char *)result3->proc_out->out, results);
	mu_assert("fixed", newc);
	free(content);
	content = newc;

	rz_pvector_free(results);

	mu_assert_streq(content,
		"NAME=multiline0\n"
		"FILE==\n"
		"RETRIES=3\n"
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
		"FILE==\n"
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
		"FILE==\n"
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
		"FILE==\n"
		"CMDS=<<EOF\n"
		"rm -rf\n"
		"EOF\n"
		"EXPECT=<<EOF\n"
		"fixed\n"
		"result\n"
		"for\n"
		"3\n"
		"EOF\n"
		"RUN",
		"fixed contents");

	free(content);

	rz_test_test_database_free(db);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_test_cmd_retries);
	mu_run_test(test_rz_test_database_load_cmd);
	mu_run_test(test_rz_test_fix);
	return tests_passed != tests_run;
}

mu_main(all_tests)