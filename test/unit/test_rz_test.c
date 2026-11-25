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

bool test_rz_test_validate_json_valid(void) {
	const char *cases[] = {
		"",
		" \t\r\n ",
		"{}",
		"[]",
		"null",
		"true",
		"false",
		"0",
		"-0",
		"1234567890",
		"-42.5e+10",
		"1e-3",
		"\"hello \\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u0041\"",
		"{\"a\":[1,true,false,null,{\"b\":\"c\"}]}",
		"{\"a\":1}\n[2,3]\ntrue\nnull\n",
		"{}[]\"s\"",
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		mu_assert_true(rz_test_validate_json(cases[i]), cases[i]);
	}
	mu_end;
}

bool test_rz_test_validate_json_invalid(void) {
	const char *cases[] = {
		"this is not json lol",
		"{",
		"}",
		"[",
		"]",
		"{\"a\":1,}",
		"[1,]",
		"{a:1}",
		"{\"a\" 1}",
		"01",
		"-01",
		"+1",
		".5",
		"1.",
		"1e",
		"1e+",
		"\"unterminated",
		"\"raw\nnewline\"",
		"\"bad\\xescape\"",
		"\"bad\\u123g\"",
		"// comment\n{}",
		"/* comment */ {}",
		"{} garbage",
		"truefalse",
		"123abc",
		"null1",
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		mu_assert_false(rz_test_validate_json(cases[i]), cases[i]);
	}

	// Deep nesting beyond JSON_MAX_DEPTH must be rejected safely without stack overflow.
	size_t depth = JSON_MAX_DEPTH + 10;
	char *deep = malloc(depth * 2 + 1);
	mu_assert_notnull(deep, "alloc deep");
	memset(deep, '[', depth);
	memset(deep + depth, ']', depth);
	deep[depth * 2] = '\0';
	mu_assert_false(rz_test_validate_json(deep), "excessive nesting rejected");
	free(deep);
	mu_end;
}

bool test_rz_test_schedule_queue_lpt(void) {
	RzPVector tests;
	rz_pvector_init(&tests, (RzPVectorFree)rz_test_test_free);

	RzTest *t_norm1 = RZ_NEW0(RzTest);
	t_norm1->type = RZ_TEST_TYPE_CMD;
	t_norm1->path = "db/cmd/cmd_a";
	t_norm1->cmd_test = rz_test_cmd_test_new();
	rz_pvector_push(&tests, t_norm1);

	RzTest *t_heavy_1200 = RZ_NEW0(RzTest);
	t_heavy_1200->type = RZ_TEST_TYPE_CMD;
	t_heavy_1200->path = "db/archos/linux-x64/dbg_cont_back";
	t_heavy_1200->cmd_test = rz_test_cmd_test_new();
	t_heavy_1200->cmd_test->timeout.set = true;
	t_heavy_1200->cmd_test->timeout.value = 1200;
	rz_pvector_push(&tests, t_heavy_1200);

	RzTest *t_rzil = RZ_NEW0(RzTest);
	t_rzil->type = RZ_TEST_TYPE_CMD;
	t_rzil->path = "db/rzil/hexagon";
	t_rzil->cmd_test = rz_test_cmd_test_new();
	rz_pvector_push(&tests, t_rzil);

	RzTest *t_norm2 = RZ_NEW0(RzTest);
	t_norm2->type = RZ_TEST_TYPE_CMD;
	t_norm2->path = "db/cmd/cmd_b";
	t_norm2->cmd_test = rz_test_cmd_test_new();
	rz_pvector_push(&tests, t_norm2);

	RzTest *t_heavy_2040 = RZ_NEW0(RzTest);
	t_heavy_2040->type = RZ_TEST_TYPE_CMD;
	t_heavy_2040->path = "db/cmd/cmd_aae";
	t_heavy_2040->cmd_test = rz_test_cmd_test_new();
	t_heavy_2040->cmd_test->timeout.set = true;
	t_heavy_2040->cmd_test->timeout.value = 2040;
	rz_pvector_push(&tests, t_heavy_2040);

	RzPVector queue;
	rz_pvector_init(&queue, NULL);
	rz_pvector_insert_range(&queue, 0, tests.v.a, rz_pvector_len(&tests));
	rz_test_schedule_queue(&queue);

	// Pop order (back to front): 2040, 1200, rzil, norm2, norm1
	mu_assert_ptreq(rz_pvector_pop(&queue), t_heavy_2040, "pop 1: timeout 2040");
	mu_assert_ptreq(rz_pvector_pop(&queue), t_heavy_1200, "pop 2: timeout 1200");
	mu_assert_ptreq(rz_pvector_pop(&queue), t_rzil, "pop 3: db/rzil");
	mu_assert_ptreq(rz_pvector_pop(&queue), t_norm2, "pop 4: norm2 order preserved");
	mu_assert_ptreq(rz_pvector_pop(&queue), t_norm1, "pop 5: norm1 order preserved");

	rz_pvector_fini(&queue);
	rz_pvector_fini(&tests);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_test_database_load_cmd);
	mu_run_test(test_rz_test_fix);
	mu_run_test(test_rz_test_validate_json_valid);
	mu_run_test(test_rz_test_validate_json_invalid);
	mu_run_test(test_rz_test_schedule_queue_lpt);
	return tests_passed != tests_run;
}

mu_main(all_tests)