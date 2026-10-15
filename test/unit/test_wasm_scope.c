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
	rz_core_free(core);
	mu_end;
}

bool test_wasm_calls_with_imports(void) {
	// Two function imports, one memory import, one body. Export must not add a slot.
	const char *uri = "hex://0061736d01000000010401600000021c0303656e760161000003656e76036d656d02000103656e76016200000302010007060102676f00020a0a0108001000100110020b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
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
	mu_run_test(test_wasm_calls_with_imports);
	mu_run_test(test_wasm_calls_three_functions);
	mu_run_test(test_wasm_calls_and_aav);
	return tests_passed != tests_run;
}

mu_main(all_tests)
