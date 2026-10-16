// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>
#include <wasm/wasm.h>
#include <analysis_private.h>
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
	const ut8 lone_end[] = { 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(bad, sizeof(bad));
	ut32 jump = 0;
	mu_assert_null(idx, "invalid opcode learns nothing");
	idx = wasm_scope_index_new(open, sizeof(open));
	mu_assert_notnull(idx, "unclosed block stays partial");
	mu_assert_false(wasm_scope_index_query(idx, 2, 0, false, &jump), "open scope has no end");
	wasm_scope_index_free(idx);
	idx = wasm_scope_index_new(lone_end, sizeof(lone_end));
	mu_assert_notnull(idx, "lone end closes the root");
	mu_assert_false(wasm_scope_index_query(idx, 0, 0, false, &jump), "nothing inside");
	wasm_scope_index_free(idx);
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
	// Stray else bytes are skipped, earlier scopes stay queryable, and only
	// bodies that teach nothing yield no index.
	const ut8 in_block[] = { 0x02, 0x40, 0x05, 0x0b, 0x0b };
	const ut8 lone[] = { 0x05, 0x0b };
	const ut8 twice[] = { 0x04, 0x40, 0x05, 0x01, 0x05, 0x01, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(in_block, sizeof(in_block));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "else in block stays partial");
	mu_assert_true(wasm_scope_index_query(idx, 3, 0, false, &jump), "block query");
	mu_assert_eq(jump, 3, "block end unaffected by the stray else");
	wasm_scope_index_free(idx);
	idx = wasm_scope_index_new(lone, sizeof(lone));
	mu_assert_notnull(idx, "lone else closes the root");
	mu_assert_false(wasm_scope_index_query(idx, 0, 0, false, &jump), "nothing inside");
	wasm_scope_index_free(idx);
	idx = wasm_scope_index_new(twice, sizeof(twice));
	mu_assert_notnull(idx, "double else keeps the first");
	mu_assert_true(wasm_scope_index_query(idx, 2, 0, true, &jump), "if query");
	mu_assert_eq(jump, 3, "first else wins");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_truncated(void) {
	// Truncation stops decoding. earlier scopes stay queryable, the rest fail.
	const ut8 br[] = { 0x02, 0x40, 0x0c };
	const ut8 call[] = { 0x10 };
	const ut8 unclosed[] = { 0x02, 0x40, 0x0c, 0x00 };
	WasmScopeIndex *idx = wasm_scope_index_new(br, sizeof(br));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "truncated br stays partial");
	mu_assert_false(wasm_scope_index_query(idx, 2, 0, false, &jump), "cut scope has no end");
	wasm_scope_index_free(idx);
	mu_assert_null(wasm_scope_index_new(call, sizeof(call)), "truncated call");
	idx = wasm_scope_index_new(unclosed, sizeof(unclosed));
	mu_assert_notnull(idx, "unclosed block stays partial");
	mu_assert_false(wasm_scope_index_query(idx, 4, 0, false, &jump), "unclosed block has no end");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_scope_query_bounds(void) {
	// block { loop { br 0 } } - queries at starts, in trailing bytes, and depths.
	const ut8 buf[] = { 0x02, 0x40, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_false(wasm_scope_index_query(idx, 0, 0, false, &jump), "at scope start");
	mu_assert_true(wasm_scope_index_query(idx, 1, 0, false, &jump), "just inside");
	mu_assert_eq(jump, 7, "just inside still ends the block");
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

bool test_wasm_patch_no_index(void) {
	// fn1's call builds the cache and hook without indexing; fn0 sees only
	// slot pushes. Patching fn0 must still mark it patched and recompute.
	const char *uri = "hex://0061736d01000000010401600000030302000007060102676f00000a100208000240010d000b0b050010000b0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	RzAnalysisHint *hint;
	WasmContext *ctx;
	WasmFuncScope *fn = NULL, *fn1 = NULL;
	void **it;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	rz_core_cmd0(core, "e io.va=true"); // flat module: same addresses either way
	op = rz_core_analysis_op(core, 0x29, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "call");
	mu_assert_eq(op->jump, 0x20, "call 0 targets fn0");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 0x20, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "block");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_NOP, "block opener");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 0x25, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "end");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_NOP, "block end pops the slot");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 0x20, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "block again");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_NOP, "block opener rearmed");
	rz_analysis_op_free(op);
	ctx = core->analysis->plugin_data;
	mu_assert_notnull(ctx, "ctx");
	rz_pvector_foreach (ctx->funcs, it) {
		WasmFuncScope *cand = *it;
		if (cand->addr == 0x20) {
			fn = cand;
		}
		if (cand->addr == 0x29) {
			fn1 = cand;
		}
	}
	mu_assert_notnull(fn, "fn0 tracked");
	mu_assert_notnull(fn1, "fn1 tracked");
	mu_assert_null(fn->idx, "fn0 never indexed");
	mu_assert_false(fn->unindexable, "fn0 not failing");
	mu_assert_false(fn->patched, "fn0 not patched yet");
	rz_core_cmd0(core, "s 0x05; wx 00"); // outside every body
	mu_assert_false(fn->patched, "outside write touches nothing");
	mu_assert_false(fn1->patched, "outside write touches nothing either");
	rz_analysis_hint_set_jump(core->analysis, 0x23, 0x55);
	rz_core_cmd0(core, "s 0x20; wx 03"); // block -> loop
	mu_assert_true(fn->patched, "overlapped write marks fn0 patched");
	op = rz_core_analysis_op(core, 0x20, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "loop opener");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_NOP, "recomputed, not stale UNK");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 0x23, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if after patch");
	mu_assert_eq(op->jump, 0x20, "recomputed from fresh bytes, user hint dormant");
	rz_analysis_op_free(op);
	hint = rz_analysis_hint_get(core->analysis, 0x23);
	mu_assert_notnull(hint, "user hint kept");
	mu_assert_eq(hint->jump, 0x55, "user hint intact");
	rz_analysis_hint_free(hint);
	op = rz_core_analysis_op(core, 0x25, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "loop end");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_NOP, "loop end pops the slot");
	rz_analysis_op_free(op);
	op = rz_core_analysis_op(core, 0x26, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "function end");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_RET, "function end stays RET after patch");
	mu_assert_true(op->eob, "function end eob");
	rz_analysis_op_free(op);
	rz_core_cmd0(core, "s 0x21; wx 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"); // span fn0+fn1 from inside fn0
	mu_assert_true(fn->patched, "span keeps fn0 patched");
	mu_assert_true(fn1->patched, "span marks fn1 patched");
	rz_core_file_close(cf);
	rz_core_free(core);
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
	// loop; br_if 0; unreachable; end; 0xff; end. The 0xff stops indexing,
	// but the loop closed before it stays queryable, so br_if 0 targets the
	// loop start exactly like the indexed path.
	const ut8 body[] = { 0x03, 0x40, 0x0d, 0x00, 0x00, 0x0b, 0xff, 0x0b };
	const char *uri = "hex://0061736d01000000010401600000030201000a0b01090003400d00000bff0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	WasmScopeIndex *idx = wasm_scope_index_new(body, sizeof(body));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "loop before 0xff stays queryable");
	mu_assert_true(wasm_scope_index_query(idx, 4, 0, false, &jump), "prefix query");
	mu_assert_eq(jump, 0, "prefix agrees on the loop start");
	wasm_scope_index_free(idx);
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	op = rz_core_analysis_op(core, 0x19, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if");
	mu_assert_eq(op->type, (ut64)(ut32)RZ_ANALYSIS_OP_TYPE_CJMP, "conditional jump");
	mu_assert_eq(op->jump, 0x17, "br_if 0 targets the loop start");
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

bool test_wasm_call_oob_index(void) {
	// call 999 decodes fine but names no fcn: unresolved, not a wrap.
	const char *uri = "hex://0061736d01000000010401600000020b0103656e7603696d700000030403000000071202067365636f6e64000205746869726400030a1d030a0010001001100210030b08000240010d000b0b070002400c000b0b";
	const ut8 buf[] = { 0x10, 0x87, 0x07 };
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp op;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 0x3c, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC) > 0, "op");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_CALL, "still a call");
	mu_assert_eq(op.jump, UT64_MAX, "out-of-range index unresolved");
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

bool test_wasm_scope_outer_loop(void) {
	// loop { block { br 1 } }: depth 0 ends the block, depth 1 restarts
	// the outer loop instead of exiting it.
	const ut8 buf[] = { 0x03, 0x40, 0x02, 0x40, 0x0c, 0x01, 0x0b, 0x0b, 0x0b };
	WasmScopeIndex *idx = wasm_scope_index_new(buf, sizeof(buf));
	ut32 jump = UT32_MAX;
	mu_assert_notnull(idx, "index");
	mu_assert_true(wasm_scope_index_query(idx, 6, 0, false, &jump), "inner query");
	mu_assert_eq(jump, 6, "br 1 depth 0 ends the block");
	mu_assert_true(wasm_scope_index_query(idx, 6, 1, false, &jump), "outer query");
	mu_assert_eq(jump, 0, "br 1 targets the outer loop start");
	wasm_scope_index_free(idx);
	mu_end;
}

bool test_wasm_fallback_no_index(void) {
	// No binary, no cache: traversal state plus forward scan.
	// br 0 restarts loop. br 1 scans past unreachable to block end.
	const char *uri = "hex://02400340000d000c000c01000b0b00000000000000000000000000";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp op;
	ut8 buf[2];
	WasmContext *ctx;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_analysis_use(core->analysis, "wasm"), "use wasm");
	rz_core_cmd0(core, "e io.va=false"); // no maps w/o a binary: raw access
	mu_assert_true(rz_io_read_at_mapped(core->io, 0, buf, 2), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 0, buf, 2, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "block");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_NOP, "block opener");
	rz_analysis_op_fini(&op);
	mu_assert_true(rz_io_read_at_mapped(core->io, 2, buf, 2), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 2, buf, 2, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "loop");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_NOP, "loop opener");
	rz_analysis_op_fini(&op);
	mu_assert_true(rz_io_read_at_mapped(core->io, 4, buf, 1), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 4, buf, 1, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "unreachable");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_TRAP, "unreachable is trap");
	rz_analysis_op_fini(&op);
	mu_assert_true(rz_io_read_at_mapped(core->io, 5, buf, 2), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 5, buf, 2, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "br_if");
	mu_assert_eq(op.type, (ut64)(ut32)RZ_ANALYSIS_OP_TYPE_CJMP, "conditional branch");
	mu_assert_eq(op.jump, 2, "br_if 0 restarts the loop");
	mu_assert_eq(op.fail, 7, "br_if falls through");
	rz_analysis_op_fini(&op);
	mu_assert_true(rz_io_read_at_mapped(core->io, 7, buf, 2), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 7, buf, 2, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "br");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_JMP, "branch");
	mu_assert_eq(op.jump, 2, "br 0 restarts the loop");
	rz_analysis_op_fini(&op);
	mu_assert_true(rz_io_read_at_mapped(core->io, 9, buf, 2), "read");
	rz_analysis_op_init(&op);
	mu_assert_true(rz_analysis_op(core->analysis, &op, 9, buf, 2, RZ_ANALYSIS_OP_MASK_BASIC) > 0, "br1");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_JMP, "outer branch");
	mu_assert_eq(op.jump, 13, "br 1 skips the loop past unreachable to the block end");
	rz_analysis_op_fini(&op);
	ctx = core->analysis->plugin_data;
	mu_assert_notnull(ctx, "ctx");
	mu_assert_false(ctx->indexed, "no cache without symbols");
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_oversized_tracked(void) {
	// Huge body: tracked, never indexed. A br near the end builds the cache.
	// Writes mark patched, end stays RET.
	static const ut8 hdr[29] = {
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02,
		0x01, 0x00, 0x0a, 0x87, 0x80, 0x80, 0x10, 0x01,
		0x82, 0x80, 0x80, 0x10, 0x00
	};
	const ut8 end = 0x0b;
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	WasmContext *ctx;
	WasmFuncScope *fn = NULL;
	void **it;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, "malloc://33554462", RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open");
	rz_core_cmd0(core, "e io.va=false"); // no maps before bin load: raw access
	mu_assert_true(rz_io_write_at(core->io, 0, hdr, sizeof(hdr)), "header");
	mu_assert_true(rz_io_write_at(core->io, 33554461, &end, 1), "final end");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	op = rz_core_analysis_op(core, 33554461, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "end");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_RET, "huge body end is RET");
	mu_assert_true(op->eob, "huge body end eob");
	rz_analysis_op_free(op);
	// The end alone builds no cache, so a br near the body end forces
	// a real build through the public path. Its scan needs one step.
	rz_core_cmd0(core, "s 33554459; wx 0c00");
	op = rz_core_analysis_op(core, 33554459, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br");
	rz_analysis_op_free(op);
	ctx = core->analysis->plugin_data;
	mu_assert_notnull(ctx, "ctx");
	rz_pvector_foreach (ctx->funcs, it) {
		WasmFuncScope *cand = *it;
		if (cand->addr == 29) {
			fn = cand;
		}
	}
	mu_assert_notnull(fn, "huge body tracked");
	mu_assert_eq(fn->len, 33554433, "full size kept, not truncated");
	mu_assert_null(fn->idx, "huge body never indexed");
	mu_assert_false(fn->unindexable, "no poison");
	mu_assert_false(fn->patched, "not patched yet");
	rz_core_cmd0(core, "s 29; wx 01");
	mu_assert_true(fn->patched, "write marks huge body patched");
	op = rz_core_analysis_op(core, 33554461, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "end again");
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_RET, "still RET after patch");
	rz_analysis_op_free(op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_index_fallback_agree(void) {
	// block { loop { br 0 } end } end, with and without trailing garbage.
	// Queries in the valid prefix must agree, the garbage part must fail.
	const ut8 clean[] = { 0x02, 0x40, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b };
	const ut8 dirty[] = { 0x02, 0x40, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b, 0xff, 0x0b };
	WasmScopeIndex *a = wasm_scope_index_new(clean, sizeof(clean));
	WasmScopeIndex *b = wasm_scope_index_new(dirty, sizeof(dirty));
	ut32 ja = UT32_MAX, jb = UT32_MAX;
	mu_assert_notnull(a, "clean index");
	mu_assert_notnull(b, "dirty prefix stays queryable");
	mu_assert_true(wasm_scope_index_query(a, 6, 0, false, &ja), "clean loop");
	mu_assert_true(wasm_scope_index_query(b, 6, 0, false, &jb), "dirty loop");
	mu_assert_eq(ja, jb, "loop target agrees");
	mu_assert_eq(ja, 2, "br 0 targets the loop start");
	mu_assert_true(wasm_scope_index_query(a, 6, 1, false, &ja), "clean outer");
	mu_assert_true(wasm_scope_index_query(b, 6, 1, false, &jb), "dirty outer");
	mu_assert_eq(ja, jb, "outer target agrees");
	mu_assert_eq(ja, 7, "br 1 ends the outer block");
	mu_assert_false(wasm_scope_index_query(b, 9, 0, false, &jb), "garbage part fails");
	wasm_scope_index_free(a);
	wasm_scope_index_free(b);
	mu_end;
}

static size_t io_write_hooks(RzCore *core) {
	RzEvent *ev = core->io ? core->io->event : NULL;
	RzVector *cbs = ev ? ht_up_find(ev->callbacks, (ut64)RZ_EVENT_IO_WRITE, NULL) : NULL;
	return cbs ? rz_vector_len(cbs) : 0;
}

bool test_wasm_hook_single(void) {
	// Reselecting the analysis plugin must not pile subscriptions on the
	// IO bus: just one stays effective, and writes still invalidate.
	const char *uri = "hex://0061736d010000000104016000000302010007060102676f00000a0a0108000240010d000b0b";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	RzAnalysisOp *op;
	size_t base, i;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "bin");
	op = rz_core_analysis_op(core, 0x22, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if");
	mu_assert_eq(op->jump, 0x24, "br_if 0 ends the block");
	rz_analysis_op_free(op);
	base = io_write_hooks(core);
	for (i = 0; i < 3; i++) {
		mu_assert_true(rz_analysis_use(core->analysis, "x86"), "leave wasm");
		mu_assert_true(rz_analysis_use(core->analysis, "wasm"), "back to wasm");
		op = rz_core_analysis_op(core, 0x22, RZ_ANALYSIS_OP_MASK_BASIC);
		mu_assert_notnull(op, "br_if again");
		mu_assert_eq(op->jump, 0x24, "still the block end");
		rz_analysis_op_free(op);
		mu_assert_eq(io_write_hooks(core), base, "no hook per reselection");
	}
	rz_core_cmd0(core, "s 0x1f; wx 03"); // block -> loop
	op = rz_core_analysis_op(core, 0x22, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_notnull(op, "br_if after patch");
	mu_assert_eq(op->jump, 0x1f, "invalidation still live after reselections");
	rz_analysis_op_free(op);
	rz_core_file_close(cf);
	rz_core_free(core);
	mu_end;
}

bool test_wasm_dis_bounds(void) {
	// Every truncated immediate fails closed with len 1. hostile prefixes
	// must not read past the buffer. A valid branch decodes with its shape.
	WasmOp wop = { { 0 } };
	const ut8 ok_br[] = { 0x0c, 0x00 };
	const ut8 trunc_call[] = { 0x10 };
	const ut8 trunc_br[] = { 0x0c, 0x80 };
	const ut8 trunc_f32[] = { 0x43, 0x00, 0x00 };
	const ut8 trunc_mem[] = { 0x28, 0x02 };
	const ut8 trunc_atomic[] = { 0xfe };
	const ut8 trunc_lane[] = { 0xfd, 0x15 };
	const ut8 big_simd[] = { 0xfd, 0x80, 0x80, 0x80, 0x80, 0x7f };
	const ut8 wide_lane[] = { 0xfd, 0x95, 0x80, 0x80, 0x80, 0x00 };
	const ut8 wide_const[] = { 0xfd, 0x8c, 0x80, 0x80, 0x80, 0x00,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01 };
	mu_assert_eq(wasm_dis(&wop, trunc_call, sizeof(trunc_call)), 1, "truncated call len");
	mu_assert_true(wop.failed, "truncated call fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, trunc_br, sizeof(trunc_br)), 1, "truncated br len");
	mu_assert_true(wop.failed, "truncated br fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, trunc_f32, sizeof(trunc_f32)), 1, "truncated f32 len");
	mu_assert_true(wop.failed, "truncated f32 fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, trunc_mem, sizeof(trunc_mem)), 1, "truncated memarg len");
	mu_assert_true(wop.failed, "truncated memarg fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, trunc_atomic, sizeof(trunc_atomic)), 1, "truncated atomic len");
	mu_assert_true(wop.failed, "truncated atomic fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, trunc_lane, sizeof(trunc_lane)), 1, "truncated lane len");
	mu_assert_true(wop.failed, "truncated lane fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, big_simd, sizeof(big_simd)), 1, "oversized simd len");
	mu_assert_true(wop.failed, "oversized simd fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, wide_lane, sizeof(wide_lane)), 1, "wide lane len");
	mu_assert_true(wop.failed, "wide lane fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(&wop, wide_const, sizeof(wide_const)), 1, "wide const len");
	mu_assert_true(wop.failed, "wide const fails");
	free(wop.txt);
	memset(&wop, 0, sizeof(wop));
	mu_assert_eq(wasm_dis(NULL, trunc_br, sizeof(trunc_br)), -1, "null op");
	mu_assert_eq(wasm_dis(&wop, ok_br, sizeof(ok_br)), 2, "valid br len");
	mu_assert_false(wop.failed, "valid br decodes");
	mu_assert_notnull(wop.txt, "valid br has text");
	free(wop.txt);
	mu_end;
}

bool test_wasm_aav_control(void) {
	// Positive control: on x86 aav must add flags, so the wasm no-op below
	// is capable of failing. The map needs exec perm (io.maps.x).
	const char *uri = "hex://10000000000000009090909090909090909090909090909090";
	RzCore *core = rz_core_new();
	RzCoreFile *cf;
	char *before, *after;
	mu_assert_notnull(core, "core");
	cf = rz_core_file_open(core, uri, RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open");
	mu_assert_notnull(rz_io_map_add(core->io, cf->fd, RZ_PERM_RWX, 0, 0, 0x20), "map");
	before = rz_core_cmd_str(core, "fl");
	rz_core_cmd0(core, "aav");
	after = rz_core_cmd_str(core, "fl");
	mu_assert_true(after && strlen(after) > strlen(before ? before : ""), "aav adds flags on x86");
	free(before);
	free(after);
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
	mu_run_test(test_wasm_patch_no_index);
	mu_run_test(test_wasm_oversized_tracked);
	mu_run_test(test_wasm_fallback_no_index);
	mu_run_test(test_wasm_hook_single);
	mu_run_test(test_wasm_index_fallback_agree);
	mu_run_test(test_wasm_dis_bounds);
	mu_run_test(test_wasm_aav_control);
	mu_run_test(test_wasm_fallback_after_unreachable);
	mu_run_test(test_wasm_call_exact_end);
	mu_run_test(test_wasm_call_oob_index);
	mu_run_test(test_wasm_scope_outer_loop);
	mu_run_test(test_wasm_calls_va);
	mu_run_test(test_wasm_end_reret);
	mu_run_test(test_wasm_calls_three_functions);
	mu_run_test(test_wasm_calls_and_aav);
	return tests_passed != tests_run;
}

mu_main(all_tests)
