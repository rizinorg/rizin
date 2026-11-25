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

bool test_rz_test_parse_asm_batch_stream_ok(void) {
	const char *stream =
		"Warning: arch notice\n"
		"\n\x1eRZ_ASM_BATCH_BEGIN\n"
		"90\n"
		"\n\x1eRZ_ASM_BATCH_ITEM 0 0\n"
		"\n\x1eRZ_ASM_BATCH_ITEM 1 1\n"
		"line1\nline2\n"
		"\n\x1eRZ_ASM_BATCH_ITEM 2 0\n";
	char *preamble = NULL;
	AsmBatchItemSlice *slices = rz_test_parse_asm_batch_stream(stream, 3, &preamble);
	mu_assert_notnull(slices, "parsed valid stream");
	mu_assert_streq(preamble, "Warning: arch notice\n", "startup preamble preserved");
	mu_assert_streq(slices[0].data, "90\n", "slice 0 data");
	mu_assert_eq(slices[0].ret, 0, "slice 0 ret");
	mu_assert_streq(slices[1].data, "", "slice 1 empty data");
	mu_assert_eq(slices[1].ret, 1, "slice 1 ret");
	mu_assert_streq(slices[2].data, "line1\nline2\n", "slice 2 multiline data");
	mu_assert_eq(slices[2].ret, 0, "slice 2 ret");

	char *joined = asm_batch_join_err(preamble, "item err\n");
	mu_assert_streq(joined, "Warning: arch notice\nitem err", "joined stderr");
	free(joined);
	joined = asm_batch_join_err(NULL, "  only err \n");
	mu_assert_streq(joined, "only err", "trimmed stderr without preamble");
	free(joined);

	asm_batch_slices_fini(slices, 3);
	free(preamble);
	mu_end;
}

bool test_rz_test_parse_asm_batch_stream_invalid(void) {
	const char *cases[] = {
		"no begin marker",
		"pre\n\x1eRZ_ASM_BATCH_BEGIN\n90\n",
		"\n\x1eRZ_ASM_BATCH_BEGIN\n90\n\n\x1eRZ_ASM_BATCH_ITEM 1 0\n",
		"\n\x1eRZ_ASM_BATCH_BEGIN\n90\n\n\x1eRZ_ASM_BATCH_ITEM 0 bad\n",
		"\n\x1eRZ_ASM_BATCH_BEGIN\n90\n\n\x1eRZ_ASM_BATCH_ITEM 0 0\ntrailing",
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		char *preamble = (char *)0x1;
		AsmBatchItemSlice *slices = rz_test_parse_asm_batch_stream(cases[i], 1, &preamble);
		mu_assert_null(slices, "invalid stream rejected");
		mu_assert_null(preamble, "preamble cleared on failure");
	}
	mu_end;
}

bool test_rz_test_enqueue_asm_batches(void) {
	RzPVector tests;
	rz_pvector_init(&tests, (RzPVectorFree)rz_test_test_free);

	for (int i = 0; i < ASM_BATCH_MAX + 2; i++) {
		RzTest *t = RZ_NEW0(RzTest);
		t->type = RZ_TEST_TYPE_ASM;
		t->path = "db/asm/x86_64";
		t->asm_test = RZ_NEW0(RzAsmTest);
		t->asm_test->arch = "x86";
		t->asm_test->bits = 64;
		t->asm_test->mode = RZ_ASM_TEST_MODE_DISASSEMBLE;
		rz_pvector_push(&tests, t);
	}

	// Same file but big-endian -> separate batch
	RzTest *t_be = RZ_NEW0(RzTest);
	t_be->type = RZ_TEST_TYPE_ASM;
	t_be->path = "db/asm/x86_64";
	t_be->asm_test = RZ_NEW0(RzAsmTest);
	t_be->asm_test->arch = "x86";
	t_be->asm_test->bits = 64;
	t_be->asm_test->mode = RZ_ASM_TEST_MODE_DISASSEMBLE | RZ_ASM_TEST_MODE_BIG_ENDIAN;
	rz_pvector_push(&tests, t_be);

	// Assemble test with embedded newline -> not batched (single work item)
	RzTest *t_nl = RZ_NEW0(RzTest);
	t_nl->type = RZ_TEST_TYPE_ASM;
	t_nl->path = "db/asm/x86_64";
	t_nl->asm_test = RZ_NEW0(RzAsmTest);
	t_nl->asm_test->arch = "x86";
	t_nl->asm_test->bits = 64;
	t_nl->asm_test->mode = RZ_ASM_TEST_MODE_ASSEMBLE;
	t_nl->asm_test->disasm = rz_str_dup("nop\nnop");
	rz_pvector_push(&tests, t_nl);

	RzPVector queue;
	rz_pvector_init(&queue, (RzPVectorFree)rz_test_work_item_free);
	rz_test_enqueue_tests_ex(&queue, &tests, true);

	// Expect: batch(256), batch(2), batch(1, BE), single(newline)
	mu_assert_eq(rz_pvector_len(&queue), 4, "work items count with batching enabled");
	RzTestWorkItem *w0 = rz_pvector_at(&queue, 0);
	RzTestWorkItem *w1 = rz_pvector_at(&queue, 1);
	RzTestWorkItem *w2 = rz_pvector_at(&queue, 2);
	RzTestWorkItem *w3 = rz_pvector_at(&queue, 3);
	mu_assert_true(w0->is_asm_batch, "w0 is batch");
	mu_assert_eq(rz_pvector_len(&w0->asm_tests), ASM_BATCH_MAX, "w0 capped at ASM_BATCH_MAX");
	mu_assert_true(w1->is_asm_batch, "w1 is overflow batch");
	mu_assert_eq(rz_pvector_len(&w1->asm_tests), 2, "w1 has remainder");
	mu_assert_true(w2->is_asm_batch, "w2 is BE batch");
	mu_assert_eq(rz_pvector_len(&w2->asm_tests), 1, "w2 has 1 BE test");
	mu_assert_false(w3->is_asm_batch, "w3 newline test not batched");
	mu_assert_ptreq(w3->single, t_nl, "w3 points to newline test");

	rz_pvector_clear(&queue);
	rz_test_enqueue_tests_ex(&queue, &tests, false);

	// Expect: 260 single items when batching is disabled
	mu_assert_eq(rz_pvector_len(&queue), ASM_BATCH_MAX + 4, "single work items count with batching disabled");
	for (size_t i = 0; i < rz_pvector_len(&queue); i++) {
		RzTestWorkItem *w = rz_pvector_at(&queue, i);
		mu_assert_false(w->is_asm_batch, "item is not batched");
		mu_assert_ptreq(w->single, rz_pvector_at(&tests, i), "item preserves test pointer");
	}

	rz_pvector_fini(&queue);
	rz_pvector_fini(&tests);
	mu_end;
}

bool test_rz_test_enqueue_asm_batches_load_plugins(void) {
	RzPVector tests;
	rz_pvector_init(&tests, (RzPVectorFree)rz_test_test_free);

	for (int i = 0; i < 2; i++) {
		RzTest *t = RZ_NEW0(RzTest);
		t->type = RZ_TEST_TYPE_ASM;
		t->path = "db/extras/asm/x86_64";
		t->asm_test = RZ_NEW0(RzAsmTest);
		t->asm_test->arch = "x86";
		t->asm_test->bits = 64;
		t->asm_test->mode = RZ_ASM_TEST_MODE_DISASSEMBLE;
		t->asm_test->load_plugins = (i == 1);
		rz_pvector_push(&tests, t);
	}

	RzPVector queue;
	rz_pvector_init(&queue, (RzPVectorFree)rz_test_work_item_free);
	rz_test_enqueue_tests_ex(&queue, &tests, true);

	mu_assert_eq(rz_pvector_len(&queue), 2, "load_plugins splits asm batches");
	RzTestWorkItem *w0 = rz_pvector_at(&queue, 0);
	RzTestWorkItem *w1 = rz_pvector_at(&queue, 1);
	mu_assert_true(w0->is_asm_batch, "w0 is batch");
	mu_assert_eq(rz_pvector_len(&w0->asm_tests), 1, "w0 has load_plugins=false test");
	mu_assert_true(w1->is_asm_batch, "w1 is batch");
	mu_assert_eq(rz_pvector_len(&w1->asm_tests), 1, "w1 has load_plugins=true test");

	rz_pvector_fini(&queue);
	rz_pvector_fini(&tests);
	mu_end;
}

bool test_rz_test_run_asm_batch_empty(void) {
	RzTestRunConfig cfg = { 0 };
	RzTest *dummy = NULL;
	RzPVector *res = rz_test_run_asm_batch(&cfg, &dummy, 0);
	mu_assert_notnull(res, "empty batch returns non-NULL vector");
	mu_assert_eq(rz_pvector_len(res), 0, "empty batch returns 0 results");
	rz_pvector_free(res);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_test_database_load_cmd);
	mu_run_test(test_rz_test_fix);
	mu_run_test(test_rz_test_parse_asm_batch_stream_ok);
	mu_run_test(test_rz_test_parse_asm_batch_stream_invalid);
	mu_run_test(test_rz_test_enqueue_asm_batches);
	mu_run_test(test_rz_test_enqueue_asm_batches_load_plugins);
	mu_run_test(test_rz_test_run_asm_batch_empty);
	return tests_passed != tests_run;
}

mu_main(all_tests)
