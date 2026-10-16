// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>
#include <wasm/wasm.h>
#include "minunit.h"

#include "../../librz/arch/isa/wasm/wasm.c"

bool test_wasm_scope_br_if(void) {
	/* block; nop; br_if 0; end; end. Scan starts on the block end. */
	const ut8 buf[] = { 0x02, 0x40, 0x01, 0x0d, 0x00, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 5, 0, false, &jump), "query");
	mu_assert_eq(jump, 5, "br_if 0 ends the block");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_if_else(void) {
	/* if; nop; else; nop; end; end */
	const ut8 buf[] = { 0x04, 0x40, 0x01, 0x05, 0x01, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 2, 0, true, &jump), "if query");
	mu_assert_eq(jump, 4, "if jumps to the else body");
	mu_assert_true(wasm_scope_index_query(idx, 4, 0, true, &jump), "else query");
	mu_assert_eq(jump, 5, "else jumps to end");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_loop_br(void) {
	/* loop; nop; br 0; end. Query starts on the byte after br. */
	const ut8 buf[] = { 0x03, 0x40, 0x01, 0x0c, 0x00, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 5, 0, false, &jump), "query");
	mu_assert_eq(jump, 0, "br 0 targets the loop start");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_outer_br(void) {
	/* block; block; br_if 1; end; end */
	const ut8 buf[] = { 0x02, 0x40, 0x02, 0x40, 0x0d, 0x01, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 6, 1, false, &jump), "outer query");
	mu_assert_eq(jump, 7, "br_if 1 ends the outer block");
	mu_assert_true(wasm_scope_index_query(idx, 6, 0, false, &jump), "inner query");
	mu_assert_eq(jump, 6, "br_if 0 ends the inner block");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_unreachable(void) {
	// loop; unreachable; br 0; end; end. unreachable must not end the index.
	const ut8 buf[] = { 0x03, 0x40, 0x00, 0x0c, 0x00, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 5, 0, false, &jump), "query");
	mu_assert_eq(jump, 0, "br after unreachable targets the loop");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_br_in_then(void) {
	// if; br 0; else; nop; end; end. br 0 targets the if end, not the else body.
	const ut8 buf[] = { 0x04, 0x40, 0x0c, 0x00, 0x05, 0x01, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 4, 0, false, &jump), "br query");
	mu_assert_eq(jump, 6, "br 0 targets the if end");
	mu_assert_true(wasm_scope_index_query(idx, 2, 0, true, &jump), "if query");
	mu_assert_eq(jump, 5, "if targets the else body");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_trailing(void) {
	// Function end closes the root. A later block must not read an empty stack.
	const ut8 buf[] = { 0x02, 0x40, 0x0b, 0x0b, 0x02, 0x40, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "trailing bytes");
	mu_assert_true(wasm_scope_index_query(idx, 2, 0, false, &jump), "first block");
	mu_assert_eq(jump, 2, "first end");
	mu_assert_false(wasm_scope_index_query(idx, 5, 0, false, &jump), "trailing bytes fail");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_reject(void) {
	const ut8 bad[] = { 0xff };
	const ut8 open[] = { 0x02, 0x40 };
	WasmScopeIndex *idx = wasm_scope_index_new(bad, sizeof(bad));
	ut32 jump = 0;
	mu_assert_null(idx, "invalid opcode");
	idx = wasm_scope_index_new(open, sizeof(open));
	mu_assert_null(idx, "unclosed block");
	idx = wasm_scope_index_new(NULL, 0);
	mu_assert_null(idx, "empty");
	idx = wasm_scope_index_new(bad, sizeof(bad));
	mu_assert_false(wasm_scope_index_query(idx, 1, 0, false, &jump), "null index");
	idx = wasm_scope_index_new((const ut8 *)"\x02\x40\x0b\x0b", 4);
	mu_assert_notnull(idx, "closed block");
	mu_assert_false(wasm_scope_index_query(idx, 100, 0, false, &jump), "from outside");
	mu_assert_false(wasm_scope_index_query(idx, 2, 5, false, &jump), "depth past root");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_calls_three_functions(void) {
	// One import, three bodies. second and third are exported. Calls at 0x3a..0x40.
	const char *uri = "hex://0061736d01000000010401600000020b0103656e7603696d700000030403000000071202067365636f6e64000205746869726400030a1d030a0010001001100210030b08000240010d000b0b070002400c000b0b";
	const ut64 sites[] = { 0x3a, 0x3c, 0x3e, 0x40 };
	const ut64 want[] = { UT64_MAX, 0x3a, 0x45, 0x4e };
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	size_t i;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	for (i = 0; i < RZ_ARRAY_SIZE(sites); i++) {
		RzAnalysisOp *op = rz_core_analysis_op(core, sites[i], RZ_ANALYSIS_OP_MASK_BASIC);
		mu_assert_notnull(op, "call");
		mu_assert_eq(op->jump, want[i], "call slot");
		rz_analysis_op_free(op);
	}
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_calls_and_aav(void) {
	// import func, import memory, import func, defined body: call 0; call 1; call 2.
	// Function index 2 is the defined body. Imports have no code address.
	// export "go" of function 2. An export must not insert another call slot.
	const char *uri = "hex://0061736d01000000010401600000021c0303656e760161000003656e76036d656d02000103656e76016200000302010007060102676f00020a0a0108001000100110020b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	char *flags;
	int pointers;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	pointers = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS);
	mu_assert_eq(pointers, 0, "wasm does not use code pointers");
	flags = rz_core_cmd_str(core, "fl");
	rz_core_cmd0(core, "aav");
	{
		char *after = rz_core_cmd_str(core, "fl");
		mu_assert_streq(flags ? flags : "", after ? after : "", "aav adds no flags");
		free(after);
	}
	free(flags);
	op = rz_core_analysis_op(core, 61, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "call 0");
	mu_assert_eq(op->jump, UT64_MAX, "import 0 is not a code address");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 63, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "call 1");
	mu_assert_eq(op->jump, UT64_MAX, "import 1 is not a code address");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 65, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "call 2");
	mu_assert_eq(op->jump, 61, "defined function follows the two imports");
	rz_analysis_op_free(op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_scope_bad_else(void) {
	// else in a block, a lone else, and a second else are malformed: no index.
	const ut8 in_block[] = { 0x02, 0x40, 0x05, 0x0b, 0x0b };
	const ut8 lone[] = { 0x05, 0x0b };
	const ut8 twice[] = { 0x04, 0x40, 0x05, 0x01, 0x05, 0x01, 0x0b, 0x0b };
	mu_assert_null(wasm_scope_index_new(in_block, sizeof(in_block)), "else in block");
	mu_assert_null(wasm_scope_index_new(lone, sizeof(lone)), "lone else");
	mu_assert_null(wasm_scope_index_new(twice, sizeof(twice)), "double else");
	mu_end;
}

bool test_wasm_scope_truncated(void) {
	// Truncated immediates and unclosed bodies never yield an index.
	const ut8 br[] = { 0x02, 0x40, 0x0c };
	const ut8 call[] = { 0x10 };
	const ut8 unclosed[] = { 0x02, 0x40, 0x0c, 0x00 };
	mu_assert_null(wasm_scope_index_new(br, sizeof(br)), "truncated br");
	mu_assert_null(wasm_scope_index_new(call, sizeof(call)), "truncated call");
	mu_assert_null(wasm_scope_index_new(unclosed, sizeof(unclosed)), "unclosed block");
	mu_end;
}

bool test_wasm_scope_query_bounds(void) {
	// block { loop { br 0 } } - queries at starts, in trailing bytes, and depths.
	const ut8 buf[] = { 0x02, 0x40, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_false(wasm_scope_index_query(idx, 0, 0, false, &jump), "at scope start");
	mu_assert_true(wasm_scope_index_query(idx, 6, 0, false, &jump), "loop query");
	mu_assert_eq(jump, 2, "br 0 targets the loop start");
	mu_assert_true(wasm_scope_index_query(idx, 6, 1, false, &jump), "outer query");
	mu_assert_eq(jump, 7, "outer depth ends the block");
	mu_assert_false(wasm_scope_index_query(idx, 6, 2, false, &jump), "depth past root");
	mu_assert_false(wasm_scope_index_query(idx, 8, 0, false, &jump), "past the end");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_dis_empty(void) {
	// Empty input fails closed instead of reading past the buffer.
	WasmOp wop = { { 0 } };
	ut8 one = 0x0c;
	mu_assert_true(wasm_dis(&wop, NULL, 0) >= 0, "null buf");
	mu_assert_true(wop.failed, "null buf fails");
	free(wop.txt);
	wop.txt = NULL;
	mu_assert_true(wasm_dis(&wop, &one, 0) >= 0, "empty buf");
	mu_assert_true(wop.failed, "empty buf fails");
	free(wop.txt);
	mu_end;
}

bool test_wasm_patch_invalidates(void) {
	// br_if at 0x22 follows a block -> loop patch through the analysis path.
	const char *uri = "hex://0061736d010000000104016000000302010007060102676f00000a0a0108000240010d000b0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	RzAnalysisHint *hint;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	op = rz_core_analysis_op(core, 0x22, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if");
	mu_assert_eq(op->jump, 0x24, "br_if 0 ends the block");
	rz_analysis_op_free(op);
	hint = rz_analysis_hint_get(core->analysis, 0x22);
	mu_assert_null(hint, "no plugin jump hint");
	rz_analysis_hint_set_jump(core->analysis, 0x21, 0x55);
	rz_core_cmd0(core, "s 0x1f; wx 03"); // block -> loop
	op = rz_core_analysis_op(core, 0x22, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if after patch");
	mu_assert_eq(op->jump, 0x1f, "br_if 0 targets the loop start of the new bytes");
	rz_analysis_op_free(op);
	hint = rz_analysis_hint_get(core->analysis, 0x21);
	mu_assert_notnull(hint, "user hint kept");
	mu_assert_eq(hint->jump, 0x55, "user hint intact");
	rz_analysis_hint_free(hint);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_fallback_after_unreachable(void) {
	// loop; br_if 0; unreachable; end; 0xff; end. 0xff fails indexing.
	const ut8 body[] = { 0x03, 0x40, 0x0d, 0x00, 0x00, 0x0b, 0xff, 0x0b };
	const char *uri = "hex://0061736d01000000010401600000030201000a0b01090003400d00000bff0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	mu_assert_null(wasm_scope_index_new(body, sizeof(body)), "0xff fails indexing");
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	op = rz_core_analysis_op(core, 0x19, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if");
	mu_assert_eq(op->type, (ut64)(ut32)RZ_ANALYSIS_OP_TYPE_CJMP, "conditional jump");
	mu_assert_eq(op->jump, 0x1c, "br_if 0 ends the loop past unreachable");
	mu_assert_eq(op->fail, 0x1b, "fallthrough");
	rz_analysis_op_free(op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_call_exact_end(void) {
	// three_functions module: call 1 at 0x3c resolves with only its 2 bytes.
	const char *uri = "hex://0061736d01000000010401600000020b0103656e7603696d700000030403000000071202067365636f6e64000205746869726400030a1d030a0010001001100210030b08000240010d000b0b070002400c000b0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	ut8 buf[2];
	RzAnalysisOp op;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	mu_assert_true(rz_io_read_at_mapped(core->io, 0x3c, buf, sizeof(buf)), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 0x3c, buf, 2, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "op");
	mu_assert_eq(op.jump, 0x3a, "call 1 with exact end");
	rz_analysis_op_fini(&op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_calls_va(void) {
	// Flipping io.va rebuilds the cache; wasm has no VA shift, targets hold.
	const char *uri = "hex://0061736d01000000010401600000020b0103656e7603696d700000030403000000071202067365636f6e64000205746869726400030a1d030a0010001001100210030b08000240010d000b0b070002400c000b0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	rz_core_cmd0(core, "e io.va=true");
	op = rz_core_analysis_op(core, 0x3c, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "call 1 va");
	mu_assert_eq(op->jump, 0x3a, "call slot in va mode");
	rz_analysis_op_free(op);
	rz_core_cmd0(core, "e io.va=false");
	op = rz_core_analysis_op(core, 0x40, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "call 3 back");
	mu_assert_eq(op->jump, 0x4e, "call slot after va flip");
	rz_analysis_op_free(op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_end_reret(void) {
	// A function-final end is RET on every visit, never a stale NOP.
	const char *uri = "hex://0061736d01000000010401600000030201000a06010400010b0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	op = rz_core_analysis_op(core, 0x18, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "end");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_RET, "first visit ret");
	mu_assert_true(op->eob, "first visit eob");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 0x18, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "end again");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_RET, "second visit ret");
	mu_assert_true(op->eob, "second visit eob");
	rz_analysis_op_free(op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_wasm_scope_br_if);
	mu_run_test(test_wasm_scope_if_else);
	mu_run_test(test_wasm_scope_loop_br);
	mu_run_test(test_wasm_scope_outer_br);
	mu_run_test(test_wasm_scope_unreachable);
	mu_run_test(test_wasm_scope_br_in_then);
	mu_run_test(test_wasm_scope_trailing);
	mu_run_test(test_wasm_scope_reject);
	mu_run_test(test_wasm_scope_bad_else);
	mu_run_test(test_wasm_scope_truncated);
	mu_run_test(test_wasm_scope_query_bounds);
	mu_run_test(test_wasm_dis_empty);
	mu_run_test(test_wasm_patch_invalidates);
	mu_run_test(test_wasm_fallback_after_unreachable);
	mu_run_test(test_wasm_call_exact_end);
	mu_run_test(test_wasm_calls_va);
	mu_run_test(test_wasm_end_reret);
	mu_run_test(test_wasm_calls_three_functions);
	mu_run_test(test_wasm_calls_and_aav);
	return tests_passed != tests_run;
}

mu_main(all_tests)
