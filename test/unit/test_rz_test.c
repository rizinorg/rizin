// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#define main not_main
#include "../../binrz/rz-test/rz-test.c"
#include "../../binrz/rz-test/load.c"
#include "../../binrz/rz-test/run.c"
#undef main

#include "minunit.h"

#define FILENAME "unit/rz_test_cmd_test"

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
	mu_assert_eq(cmd_test->expect.line_begin, 6, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 10, "line begin");

	test = rz_pvector_at(&db->tests, 1);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "singleline0", "name");
	mu_assert_streq(cmd_test->expect.value, "", "expect");
	mu_assert_eq(cmd_test->expect.line_begin, 17, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 18, "line begin");

	test = rz_pvector_at(&db->tests, 2);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "multiline1", "name");
	mu_assert_streq(cmd_test->expect.value, "more\nexpected\noutput\n", "expect");
	mu_assert_eq(cmd_test->expect.line_begin, 25, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 30, "line begin");

	test = rz_pvector_at(&db->tests, 3);
	mu_assert_eq(test->type, RZ_TEST_TYPE_CMD, "test type");
	cmd_test = test->cmd_test;
	mu_assert_streq(cmd_test->name.value, "singleline1", "name");
	mu_assert_streq(cmd_test->expect.value, "", "expect");
	mu_assert_eq(cmd_test->expect.line_begin, 37, "line begin");
	mu_assert_eq(cmd_test->expect.line_end, 38, "line begin");

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

bool test_rz_test_cmd_batchable(void) {
	RzCmdTest *t = rz_test_cmd_test_new();
	t->file.value = strdup("=");
	t->cmds.value = strdup("echo hi\n?v 1+2");
	mu_assert_true(rz_test_cmd_test_batchable(t), "plain stateless cmd test should be batchable");

	t->args.value = strdup("-a x86 -b 32 -e bin.strings=false");
	mu_assert_true(rz_test_cmd_test_batchable(t), "safe arch/config args should be batchable");

	free(t->cmds.value);
	t->cmds.value = strdup("echo hi | head\necho foo~bar");
	mu_assert_true(rz_test_cmd_test_batchable(t), "plain pipe and grep ~ should remain batchable");

	free(t->args.value);
	t->args.value = strdup("-a x86 -d");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-d debug flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-c echo");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-c flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-i script.rz");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-i flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-I pre.rz");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-I flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-l plugin.so");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-l flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-r profile.rr2");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-r flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-R env=1");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-R flag must not be batched");

	free(t->args.value);
	t->args.value = strdup("-e dir.home=/tmp");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-e dir.home must not be batched");

	free(t->args.value);
	t->args.value = strdup("-e dir.tmp=/tmp");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-e dir.tmp must not be batched");

	free(t->args.value);
	t->args.value = strdup("-e cfg.debug=true");
	mu_assert_false(rz_test_cmd_test_batchable(t), "-e cfg.debug must not be batched");

	free(t->args.value);
	t->args.value = NULL;
	t->tool.value = strdup("rz-bin");
	mu_assert_false(rz_test_cmd_test_batchable(t), "custom TOOL must not be batched");

	RZ_FREE(t->tool.value);
	t->timeout.set = true;
	t->timeout.value = 1200;
	mu_assert_false(rz_test_cmd_test_batchable(t), "explicit TIMEOUT must not be batched");

	t->timeout.set = false;
	free(t->cmds.value);
	t->cmds.value = strdup("echo a; !ls");
	mu_assert_false(rz_test_cmd_test_batchable(t), "shell escape ! must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("echo `!cmd`");
	mu_assert_false(rz_test_cmd_test_batchable(t), "backtick shell escape must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("echo $(!id)");
	mu_assert_false(rz_test_cmd_test_batchable(t), "$() substitution must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("echo a | !cat");
	mu_assert_false(rz_test_cmd_test_batchable(t), "pipe to ! must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("echo a && !cat");
	mu_assert_false(rz_test_cmd_test_batchable(t), "&& ! must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("echo a || !cat");
	mu_assert_false(rz_test_cmd_test_batchable(t), "|| ! must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("\"!ls\"");
	mu_assert_false(rz_test_cmd_test_batchable(t), "quoted ! must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("ood");
	mu_assert_false(rz_test_cmd_test_batchable(t), "ood must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("do");
	mu_assert_false(rz_test_cmd_test_batchable(t), "do must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("o dbg:///bin/ls");
	mu_assert_false(rz_test_cmd_test_batchable(t), "o dbg:// must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("e cfg.debug=true");
	mu_assert_false(rz_test_cmd_test_batchable(t), "e cfg.debug must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("e dir.home=/tmp");
	mu_assert_false(rz_test_cmd_test_batchable(t), "e dir.home must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("e dir.tmp=/tmp");
	mu_assert_false(rz_test_cmd_test_batchable(t), "e dir.tmp must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("L /tmp/plugin.so");
	mu_assert_false(rz_test_cmd_test_batchable(t), "L plugin loader must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup(". scripts/map_clean.rz");
	mu_assert_false(rz_test_cmd_test_batchable(t), "dot script loader must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("cd /tmp");
	mu_assert_false(rz_test_cmd_test_batchable(t), "cd must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("q!");
	mu_assert_false(rz_test_cmd_test_batchable(t), "q! must not be batched");

	free(t->cmds.value);
	t->cmds.value = strdup("echo ok");
	free(t->file.value);
	t->file.value = strdup("-");
	mu_assert_false(rz_test_cmd_test_batchable(t), "stdin file '-' must not be batched");

	mu_assert_true(test_path_is_archos("db/archos/linux-x64/dbg_oo"), "posix archos path must be detected");
	mu_assert_true(test_path_is_archos("db\\archos\\windows-x64\\dbg"), "windows archos path must be detected");
	mu_assert_false(test_path_is_archos("db/cmd/cmd_math"), "regular cmd path is not archos");

	rz_test_cmd_test_free(t);
	mu_end;
}

bool test_rz_test_parse_worker_header(void) {
	int rc = -1;
	size_t olen = 0, elen = 0;
	mu_assert_true(parse_worker_result_header("RESULT 0 12 0", &rc, &olen, &elen), "valid zero-rc header");
	mu_assert_eq(rc, 0, "rc 0");
	mu_assert_eq(olen, 12, "out_len 12");
	mu_assert_eq(elen, 0, "err_len 0");

	mu_assert_true(parse_worker_result_header("RESULT 1 0 42", &rc, &olen, &elen), "valid non-zero rc header");
	mu_assert_eq(rc, 1, "rc 1");
	mu_assert_eq(olen, 0, "out_len 0");
	mu_assert_eq(elen, 42, "err_len 42");

	mu_assert_true(parse_worker_result_header("RESULT -1 0 0", &rc, &olen, &elen), "valid negative rc header");
	mu_assert_eq(rc, -1, "rc -1");

	mu_assert_false(parse_worker_result_header("BAD 0 0 0", &rc, &olen, &elen), "wrong prefix");
	mu_assert_false(parse_worker_result_header("RESULT 0 12", &rc, &olen, &elen), "missing err_len");
	mu_assert_false(parse_worker_result_header("RESULT 0 12 3 extra", &rc, &olen, &elen), "trailing garbage");
	mu_assert_false(parse_worker_result_header("RESULT 0 -1 0", &rc, &olen, &elen), "negative out_len");
	mu_assert_false(parse_worker_result_header("RESULT 0 0 -1", &rc, &olen, &elen), "negative err_len");
	mu_assert_false(parse_worker_result_header("RESULT 0 18446744073709551615 0", &rc, &olen, &elen), "overflow out_len");
	mu_assert_false(parse_worker_result_header("RESULT 0 2147483647 0", &rc, &olen, &elen), "INT_MAX out_len");
	mu_assert_false(parse_worker_result_header("RESULT  0 0", &rc, &olen, &elen), "double space missing field");
	mu_assert_false(parse_worker_result_header("RESULT  0 0 0", &rc, &olen, &elen), "leading space before rc");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_test_database_load_cmd);
	mu_run_test(test_rz_test_fix);
	mu_run_test(test_rz_test_cmd_batchable);
	mu_run_test(test_rz_test_parse_worker_header);
	return tests_passed != tests_run;
}

mu_main(all_tests)