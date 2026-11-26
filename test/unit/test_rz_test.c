// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#define main not_main
#include "../../binrz/rz-test/rz-test.c"
#include "../../binrz/rz-test/load.c"
#include "../../binrz/rz-test/run.c"
#undef main

#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_main.h>
#if __WINDOWS__
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#define TEST_DUP     _dup
#define TEST_DUP2    _dup2
#define TEST_CLOSE   _close
#define TEST_OPEN(p) _open((p), _O_RDWR | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE)
#define TEST_FILENO  _fileno
#else
#include <fcntl.h>
#include <unistd.h>
#define TEST_DUP     dup
#define TEST_DUP2    dup2
#define TEST_CLOSE   close
#define TEST_OPEN(p) open((p), O_RDWR | O_CREAT | O_TRUNC, 0600)
#define TEST_FILENO  fileno
#endif

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

typedef struct {
	int init_calls;
	int fini_calls;
	int fail_on_call;
} MockResetState;

static MockResetState mock_reset_state;

static bool mock_plugin_init(void **user) {
	mock_reset_state.init_calls++;
	if (mock_reset_state.fail_on_call > 0 && mock_reset_state.init_calls >= mock_reset_state.fail_on_call) {
		*user = NULL;
		return false;
	}
	*user = (void *)(uintptr_t)mock_reset_state.init_calls;
	return true;
}

static bool mock_plugin_fini(void *user) {
	(void)user;
	mock_reset_state.fini_calls++;
	return true;
}

bool test_rz_analysis_plugin_reset(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "rz_analysis_new");

	// cur == NULL -> no-op success
	mu_assert_true(rz_analysis_plugin_reset(analysis), "reset with no active analysis plugin");

	RzAnalysisPlugin p_nofini = {
		.name = "mock_anal_nofini",
		.arch = "mock_anal_nofini",
		.init = mock_plugin_init,
		.fini = NULL,
	};
	RzAnalysisPlugin p_noinit = {
		.name = "mock_anal_noinit",
		.arch = "mock_anal_noinit",
		.init = NULL,
		.fini = mock_plugin_fini,
	};
	RzAnalysisPlugin p_both = {
		.name = "mock_anal_reset",
		.arch = "mock_anal_reset",
		.init = mock_plugin_init,
		.fini = mock_plugin_fini,
	};

	mu_assert_true(rz_analysis_plugin_add(analysis, &p_nofini), "add p_nofini");
	mu_assert_true(rz_analysis_plugin_add(analysis, &p_noinit), "add p_noinit");
	mu_assert_true(rz_analysis_plugin_add(analysis, &p_both), "add p_both");

	mock_reset_state = (MockResetState){ 0 };
	mu_assert_true(rz_analysis_use(analysis, "mock_anal_nofini"), "use p_nofini");
	mu_assert_true(rz_analysis_use(analysis, "mock_anal_nofini"), "use p_nofini fast path");
	mu_assert_true(rz_analysis_plugin_reset(analysis), "reset with fini == NULL");
	mu_assert_eq(mock_reset_state.init_calls, 1, "nofini did not reinit");

	mu_assert_true(rz_analysis_use(analysis, "mock_anal_noinit"), "use p_noinit");
	mu_assert_true(rz_analysis_plugin_reset(analysis), "reset with init == NULL");
	mu_assert_eq(mock_reset_state.fini_calls, 0, "noinit did not call fini on reset");

	mock_reset_state = (MockResetState){ .fail_on_call = 3 };
	mu_assert_true(rz_analysis_use(analysis, "mock_anal_reset"), "use p_both");
	mu_assert_eq(mock_reset_state.fini_calls, 1, "switching away from p_noinit called its fini");
	mu_assert_eq(mock_reset_state.init_calls, 1, "p_both initial init");
	mu_assert_true(rz_analysis_plugin_reset(analysis), "p_both reset succeeds");
	mu_assert_eq(mock_reset_state.fini_calls, 2, "p_both reset called fini");
	mu_assert_eq(mock_reset_state.init_calls, 2, "p_both reset called init");
	mu_assert_ptreq(rz_analysis_plugin_current(analysis), &p_both, "cur preserved on reset success");

	// Third init fails -> reset returns false and clears cur
	mu_assert_false(rz_analysis_plugin_reset(analysis), "p_both reset fails when init returns false");
	mu_assert_eq(mock_reset_state.fini_calls, 3, "failed reset still called fini");
	mu_assert_eq(mock_reset_state.init_calls, 3, "failed reset attempted init");
	mu_assert_null(rz_analysis_plugin_current(analysis), "cur cleared on reset failure");
	mu_assert_false(rz_analysis_use(analysis, "nonexistent_mock_anal"), "unknown analysis plugin returns false");

	rz_analysis_plugin_del(analysis, &p_nofini);
	rz_analysis_plugin_del(analysis, &p_noinit);
	rz_analysis_plugin_del(analysis, &p_both);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_asm_plugin_reset(void) {
	RzAsm *a = rz_asm_new();
	mu_assert_notnull(a, "rz_asm_new");

	// cur == NULL -> no-op success
	mu_assert_true(rz_asm_plugin_reset(a), "reset with no active asm plugin");

	RzAsmPlugin p_nofini = {
		.name = "mock_asm_nofini",
		.arch = "mock_asm_nofini",
		.bits = 32,
		.init = mock_plugin_init,
		.fini = NULL,
	};
	RzAsmPlugin p_noinit = {
		.name = "mock_asm_noinit",
		.arch = "mock_asm_noinit",
		.bits = 32,
		.init = NULL,
		.fini = mock_plugin_fini,
	};
	RzAsmPlugin p_both = {
		.name = "mock_asm_reset",
		.arch = "mock_asm_reset",
		.bits = 32,
		.init = mock_plugin_init,
		.fini = mock_plugin_fini,
	};

	mu_assert_true(rz_asm_plugin_add(a, &p_nofini), "add p_nofini");
	mu_assert_true(rz_asm_plugin_add(a, &p_noinit), "add p_noinit");
	mu_assert_true(rz_asm_plugin_add(a, &p_both), "add p_both");

	mock_reset_state = (MockResetState){ 0 };
	mu_assert_true(rz_asm_use(a, "mock_asm_nofini"), "use p_nofini");
	mu_assert_true(rz_asm_use(a, "mock_asm_nofini"), "use p_nofini fast path");
	mu_assert_true(rz_asm_plugin_reset(a), "reset with fini == NULL");
	mu_assert_eq(mock_reset_state.init_calls, 1, "nofini did not reinit");

	mu_assert_true(rz_asm_use(a, "mock_asm_noinit"), "use p_noinit");
	mu_assert_true(rz_asm_plugin_reset(a), "reset with init == NULL");
	mu_assert_eq(mock_reset_state.fini_calls, 0, "noinit did not call fini on reset");

	mock_reset_state = (MockResetState){ .fail_on_call = 3 };
	mu_assert_true(rz_asm_use(a, "mock_asm_reset"), "use p_both");
	mu_assert_eq(mock_reset_state.fini_calls, 1, "switching away from p_noinit called its fini");
	mu_assert_eq(mock_reset_state.init_calls, 1, "p_both initial init");
	mu_assert_true(rz_asm_plugin_reset(a), "p_both reset succeeds");
	mu_assert_eq(mock_reset_state.fini_calls, 2, "p_both reset called fini");
	mu_assert_eq(mock_reset_state.init_calls, 2, "p_both reset called init");
	mu_assert_ptreq(rz_asm_plugin_current(a), &p_both, "cur preserved on reset success");

	// Third init fails -> reset returns false and clears cur
	mu_assert_false(rz_asm_plugin_reset(a), "p_both reset fails when init returns false");
	mu_assert_eq(mock_reset_state.fini_calls, 3, "failed reset still called fini");
	mu_assert_eq(mock_reset_state.init_calls, 3, "failed reset attempted init");
	mu_assert_null(rz_asm_plugin_current(a), "cur cleared on reset failure");
	mu_assert_false(rz_asm_use(a, "nonexistent_mock_asm"), "unknown asm plugin returns false");

	rz_asm_plugin_del(a, &p_nofini);
	rz_asm_plugin_del(a, &p_noinit);
	rz_asm_plugin_del(a, &p_both);
	rz_asm_free(a);
	mu_end;
}

static int run_rz_asm_capture(int argc, const char **argv, char **out_str, char **err_str) {
	*out_str = NULL;
	*err_str = NULL;
	char *out_path = rz_file_temp("rz_asm_out");
	char *err_path = rz_file_temp("rz_asm_err");
	if (!out_path || !err_path) {
		free(out_path);
		free(err_path);
		return -1;
	}
	fflush(stdout);
	fflush(stderr);
	int saved_out = TEST_DUP(TEST_FILENO(stdout));
	int saved_err = TEST_DUP(TEST_FILENO(stderr));
	int out_fd = TEST_OPEN(out_path);
	int err_fd = TEST_OPEN(err_path);
	int ret = -1;
	if (saved_out >= 0 && saved_err >= 0 && out_fd >= 0 && err_fd >= 0) {
		TEST_DUP2(out_fd, TEST_FILENO(stdout));
		TEST_DUP2(err_fd, TEST_FILENO(stderr));
		ret = rz_main_rz_asm(argc, argv);
		fflush(stdout);
		fflush(stderr);
		TEST_DUP2(saved_out, TEST_FILENO(stdout));
		TEST_DUP2(saved_err, TEST_FILENO(stderr));
	}
	if (out_fd >= 0) {
		TEST_CLOSE(out_fd);
	}
	if (err_fd >= 0) {
		TEST_CLOSE(err_fd);
	}
	if (saved_out >= 0) {
		TEST_CLOSE(saved_out);
	}
	if (saved_err >= 0) {
		TEST_CLOSE(saved_err);
	}
	*out_str = rz_file_slurp(out_path, NULL);
	*err_str = rz_file_slurp(err_path, NULL);
	if (*out_str) {
		*out_str = (char *)crlf2lf((ut8 *)*out_str);
	}
	if (*err_str) {
		*err_str = (char *)crlf2lf((ut8 *)*err_str);
	}
	rz_file_rm(out_path);
	rz_file_rm(err_path);
	free(out_path);
	free(err_path);
	return ret;
}

bool test_rz_asm_batch_mode(void) {
	char *batch_path = rz_file_temp("rz_asm_batch");
	mu_assert_notnull(batch_path, "batch temp path");

	// Valid batch: CRLF, empty lines, directives (.arch/.cpu/.bits/.big_endian/.att_syntax),
	// state restoration check, assemble error, disasm with/without 0x, IL cache + no trailing NL
	const char *valid_batch =
		"a 0 mov r0, 3\r\n"
		"\n"
		"\r\n"
		"a 0 .arch x86; nop\n"
		"a 0 .cpu generic; mov r0, 3\n"
		"a 0 .bits 16; nop\n"
		"a 0 .big_endian; mov r0, 3\n"
		"a 0 .att_syntax; mov r0, 3\n"
		"a 0 mov r0, 3\n"
		"a 0 invalid_mnemonic_xyz\n"
		"d 0 0x0300a0e3\n"
		"d 0 0300a0e3\n"
		"I 0 0300a0e3\n"
		"I 0 0x0300a0e3";
	mu_assert_true(rz_file_dump(batch_path, (const ut8 *)valid_batch, strlen(valid_batch), false), "dump valid batch");

	const char *argv_valid[] = { "rz-asm", "-a", "arm", "-b", "32", "-c", "cortex-a8", "-t", batch_path };
	char *out = NULL;
	char *err = NULL;
	int ret = run_rz_asm_capture(RZ_ARRAY_SIZE(argv_valid), argv_valid, &out, &err);
	mu_assert_eq(ret, 0, "valid batch exits 0");
	mu_assert_notnull(out, "valid batch stdout");
	mu_assert_notnull(err, "valid batch stderr");

	char *preamble = NULL;
	AsmBatchItemSlice *slices = rz_test_parse_asm_batch_stream(out, 12, &preamble);
	mu_assert_notnull(slices, "valid batch stream parses 12 items");
	mu_assert_eq(slices[0].ret, 0, "item 0 CRLF assemble ok");
	mu_assert_streq(slices[0].data, "0300a0e3\n", "item 0 arm32le mov r0, 3");
	mu_assert_eq(slices[1].ret, 0, "item 1 .arch x86 ok");
	mu_assert_streq(slices[1].data, "90\n", "item 1 x86 nop");
	mu_assert_eq(slices[2].ret, 0, "item 2 .cpu directive ok");
	mu_assert_eq(slices[3].ret, 0, "item 3 .bits 16 ok");
	mu_assert_eq(slices[4].ret, 0, "item 4 .big_endian ok");
	mu_assert_streq(slices[4].data, "e3a00003\n", "item 4 arm32be mov r0, 3");
	mu_assert_eq(slices[5].ret, 0, "item 5 .att_syntax ok");
	mu_assert_eq(slices[6].ret, 0, "item 6 post-directive state restored");
	mu_assert_streq(slices[6].data, "0300a0e3\n", "item 6 arm32le restored after directives");
	mu_assert_eq(slices[7].ret, 1, "item 7 invalid mnemonic fails item");
	mu_assert_eq(slices[8].ret, 0, "item 8 disasm with 0x prefix ok");
	mu_assert_streq(slices[8].data, "mov r0, 3\n", "item 8 disasm output");
	mu_assert_eq(slices[9].ret, 0, "item 9 disasm without 0x ok");
	mu_assert_streq(slices[9].data, "mov r0, 3\n", "item 9 disasm output");
	mu_assert_eq(slices[10].ret, 0, "item 10 IL first lift ok");
	mu_assert_eq(slices[11].ret, 0, "item 11 IL cached VM + 0x + no trailing NL ok");
	mu_assert_streq(slices[10].data, slices[11].data, "IL output consistent across cached VM");
	asm_batch_slices_fini(slices, 12);
	free(preamble);
	free(out);
	free(err);

	// Error cases: invalid op, missing op separator, non-hex offset, offset without trailing space
	const struct {
		const char *content;
		const char *expected_err;
	} err_cases[] = {
		{ "x 0 90\n", "Invalid batch line 0" },
		{ "aX0 nop\n", "Invalid batch line 0" },
		{ "a zzz nop\n", "Invalid batch offset on line 0" },
		{ "a 10\n", "Invalid batch offset on line 0" },
	};
	const char *argv_err[] = { "rz-asm", "-a", "x86", "-b", "64", "-t", batch_path };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(err_cases); i++) {
		mu_assert_true(rz_file_dump(batch_path, (const ut8 *)err_cases[i].content, strlen(err_cases[i].content), false), "dump err batch");
		ret = run_rz_asm_capture(RZ_ARRAY_SIZE(argv_err), argv_err, &out, &err);
		mu_assert_eq(ret, 1, "malformed batch exits 1");
		mu_assert_notnull(err, "malformed batch stderr");
		mu_assert_notnull(strstr(err, err_cases[i].expected_err), "expected batch error message");
		free(out);
		free(err);
	}

	rz_file_rm(batch_path);
	free(batch_path);

	// Nonexistent batch file
	const char *argv_missing[] = { "rz-asm", "-t", "nonexistent_rz_asm_batch_file_unit" };
	ret = run_rz_asm_capture(RZ_ARRAY_SIZE(argv_missing), argv_missing, &out, &err);
	mu_assert_eq(ret, 1, "missing batch file exits 1");
	mu_assert_notnull(err, "missing batch file stderr");
	mu_assert_notnull(strstr(err, "Cannot open batch file"), "missing batch file error message");
	free(out);
	free(err);
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
	mu_run_test(test_rz_analysis_plugin_reset);
	mu_run_test(test_rz_asm_plugin_reset);
	mu_run_test(test_rz_asm_batch_mode);
	return tests_passed != tests_run;
}

mu_main(all_tests)
