// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_windows.h>
#include "minunit.h"

#include "mock_io.inl"

#include "test_analysis_block_invars.inl"
#define check_invariants block_check_invariants
#define check_leaks      block_check_leaks

static size_t blocks_count(RzAnalysis *analysis) {
	size_t count = 0;
	RBIter iter;
	RzAnalysisBlock *block;
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		count++;
	}
	return count;
}

bool test_rz_analysis_block_create() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	mu_assert_eq(blocks_count(analysis), 0, "initial count");

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x1337, 42);
	assert_block_invariants(analysis);
	mu_assert("created block", block);
	mu_assert_eq(block->addr, 0x1337, "created addr");
	mu_assert_eq(block->size, 42, "created size");
	mu_assert_eq(block->ref, 1, "created initial ref");
	mu_assert_eq(block->sp_entry, RZ_STACK_ADDR_INVALID, "created sp_entry");
	mu_assert_eq(blocks_count(analysis), 1, "count after create");

	RzAnalysisBlock *block2 = rz_analysis_create_block(analysis, 0x133f, 100);
	assert_block_invariants(analysis);
	mu_assert("created block (overlap)", block2);
	mu_assert_eq(block2->addr, 0x133f, "created addr");
	mu_assert_eq(block2->size, 100, "created size");
	mu_assert_eq(block2->ref, 1, "created initial ref");
	mu_assert_eq(block2->sp_entry, RZ_STACK_ADDR_INVALID, "created sp_entry");
	mu_assert_eq(blocks_count(analysis), 2, "count after create");

	RzAnalysisBlock *block3 = rz_analysis_create_block(analysis, 0x1337, 5);
	assert_block_invariants(analysis);
	mu_assert("no double create on same start", !block3);
	mu_assert_eq(blocks_count(analysis), 2, "count after failed create");

	rz_analysis_block_unref(block);
	rz_analysis_block_unref(block2);

	assert_block_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_contains() {
	RzAnalysisBlock dummy = { 0 };
	dummy.addr = 0x1337;
	dummy.size = 42;
	mu_assert("contains before", !rz_analysis_block_contains(&dummy, 100));
	mu_assert("contains start", rz_analysis_block_contains(&dummy, 0x1337));
	mu_assert("contains inside", rz_analysis_block_contains(&dummy, 0x1339));
	mu_assert("contains last", rz_analysis_block_contains(&dummy, 0x1337 + 42 - 1));
	mu_assert("contains after", !rz_analysis_block_contains(&dummy, 0x1337 + 42));
	mu_end;
}

bool test_rz_analysis_block_sp() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	ut64 base = 0xfa1afe1;
	RzAnalysisBlock *block = rz_analysis_create_block(analysis, base, 42);
	assert_block_invariants(analysis);
	mu_assert_eq(blocks_count(analysis), 1, "count after create");

	// while ninstr == 0, nothing is known except delta at 0 (always 0)
	st16 delta = rz_analysis_block_get_op_sp_delta(block, 0);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_op_sp_delta(block, 4);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 5);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_sp_delta_at(block, base);
	mu_assert_eq(delta, 0, "sp delta at 0");
	delta = rz_analysis_block_get_sp_delta_at_end(block);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");

	block->ninstr = 5;

	// with ninstr > 0, but nothing set yet, still nothing new is known
	delta = rz_analysis_block_get_op_sp_delta(block, 0);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_op_sp_delta(block, 4);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 5);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_sp_delta_at(block, base);
	mu_assert_eq(delta, 0, "sp delta at 0");
	delta = rz_analysis_block_get_sp_delta_at_end(block);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");

	// after setting one sp delta, this one is known, but nothing else around
	bool succ = rz_analysis_block_set_op_sp_delta(block, 2, -8);
	mu_assert_true(succ, "sp delta set");
	delta = rz_analysis_block_get_op_sp_delta(block, 1);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_op_sp_delta(block, 2);
	mu_assert_eq(delta, -8, "sp delta known after set");
	delta = rz_analysis_block_get_op_sp_delta(block, 3);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");
	delta = rz_analysis_block_get_sp_delta_at_end(block);
	mu_assert_eq(delta, ST16_MAX, "sp delta unknown");

	// fill up the sp deltas for the remaining ops
	succ = rz_analysis_block_set_op_sp_delta(block, 4, -24);
	mu_assert_true(succ, "sp delta set");
	succ = rz_analysis_block_set_op_sp_delta(block, 0, -4);
	mu_assert_true(succ, "sp delta set");
	succ = rz_analysis_block_set_op_sp_delta(block, 1, -5);
	mu_assert_true(succ, "sp delta set");
	succ = rz_analysis_block_set_op_sp_delta(block, 3, -16);
	mu_assert_true(succ, "sp delta set");
	succ = rz_analysis_block_set_op_sp_delta(block, 5, -42);
	mu_assert_false(succ, "set at i >= ninstr");

	delta = rz_analysis_block_get_op_sp_delta(block, 0);
	mu_assert_eq(delta, -4, "sp delta known after set");
	delta = rz_analysis_block_get_op_sp_delta(block, 5);
	mu_assert_eq(delta, ST16_MAX, "sp delta oob");

	// without knowing the op offsets yet, delta by address is at least known
	// at the beginning and after the end of the block
	delta = rz_analysis_block_get_sp_delta_at(block, base);
	mu_assert_eq(delta, 0, "sp delta at 0");
	delta = rz_analysis_block_get_sp_delta_at_end(block);
	mu_assert_eq(delta, -24, "sp delta at end");

	// absolute sps are not known until sp_delta is set
	RzStackAddr sp = rz_analysis_block_get_sp_at(block, base);
	mu_assert_eq(sp, RZ_STACK_ADDR_INVALID, "sp unknown");
	sp = rz_analysis_block_get_sp_at_end(block);
	mu_assert_eq(sp, RZ_STACK_ADDR_INVALID, "sp unknown");

	rz_analysis_block_set_op_offset(block, 1, 1);
	rz_analysis_block_set_op_offset(block, 2, 2);
	rz_analysis_block_set_op_offset(block, 3, 4);
	rz_analysis_block_set_op_offset(block, 4, 30);

	// with the op offsets, all deltas by address are known
	delta = rz_analysis_block_get_sp_delta_at(block, base);
	mu_assert_eq(delta, 0, "sp delta at 0");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 1);
	mu_assert_eq(delta, -4, "sp delta known through op offset");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 2);
	mu_assert_eq(delta, -5, "sp delta known through op offset");
	// When inside an instruction, we want to get the sp delta at the instruction's beginning
	// as the best known value here.
	delta = rz_analysis_block_get_sp_delta_at(block, base + 3);
	mu_assert_eq(delta, -5, "sp delta known through op offset");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 4);
	mu_assert_eq(delta, -8, "sp delta known through op offset");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 10);
	mu_assert_eq(delta, -8, "sp delta known through op offset");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 30);
	mu_assert_eq(delta, -16, "sp delta known through op offset");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 41);
	mu_assert_eq(delta, -16, "sp delta known through op offset");
	delta = rz_analysis_block_get_sp_delta_at(block, base + 42);
	mu_assert_eq(delta, ST16_MAX, "sp delta oob");
	delta = rz_analysis_block_get_sp_delta_at(block, base - 1);
	mu_assert_eq(delta, ST16_MAX, "sp delta oob");
	delta = rz_analysis_block_get_sp_delta_at_end(block);
	mu_assert_eq(delta, -24, "sp delta at end");

	// absolute sps still not known until sp_delta is set
	sp = rz_analysis_block_get_sp_at(block, base);
	mu_assert_eq(sp, RZ_STACK_ADDR_INVALID, "sp unknown");
	sp = rz_analysis_block_get_sp_at_end(block);
	mu_assert_eq(sp, RZ_STACK_ADDR_INVALID, "sp unknown");

	// complete all info by setting sp_entry
	block->sp_entry = -1000;

	// now all actual sps are known for the block
	sp = rz_analysis_block_get_sp_at(block, base);
	mu_assert_eq(sp, -1000, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 1);
	mu_assert_eq(sp, -1004, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 2);
	mu_assert_eq(sp, -1005, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 3);
	mu_assert_eq(sp, -1005, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 4);
	mu_assert_eq(sp, -1008, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 10);
	mu_assert_eq(sp, -1008, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 30);
	mu_assert_eq(sp, -1016, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 41);
	mu_assert_eq(sp, -1016, "sp known");
	sp = rz_analysis_block_get_sp_at(block, base + 42);
	mu_assert_eq(sp, RZ_STACK_ADDR_INVALID, "sp oob");
	sp = rz_analysis_block_get_sp_at(block, base - 1);
	mu_assert_eq(sp, RZ_STACK_ADDR_INVALID, "sp oob");
	sp = rz_analysis_block_get_sp_at_end(block);
	mu_assert_eq(sp, -1024, "sp at end");

	rz_analysis_block_unref(block);

	assert_block_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_split() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x1337, 42);
	assert_block_invariants(analysis);
	mu_assert_eq(blocks_count(analysis), 1, "count after create");
	block->jump = 0xdeadbeef;
	block->fail = 0xc0ffee;
	block->ninstr = 5;
	rz_analysis_block_set_op_offset(block, 0, 0);
	rz_analysis_block_set_op_offset(block, 1, 1);
	rz_analysis_block_set_op_offset(block, 2, 2);
	rz_analysis_block_set_op_offset(block, 3, 4);
	rz_analysis_block_set_op_offset(block, 4, 30);
	block->sp_entry = -1000;
	rz_analysis_block_set_op_sp_delta(block, 0, -4);
	rz_analysis_block_set_op_sp_delta(block, 1, -8);
	rz_analysis_block_set_op_sp_delta(block, 2, -13);
	rz_analysis_block_set_op_sp_delta(block, 3, -18);
	rz_analysis_block_set_op_sp_delta(block, 4, -23);

	RzAnalysisBlock *second = rz_analysis_block_split(block, 0x1337);
	assert_block_invariants(analysis);
	mu_assert_ptreq(second, block, "nop split on first addr");
	mu_assert_eq(blocks_count(analysis), 1, "count after nop split");
	mu_assert_eq(block->ref, 2, "ref after nop split");
	rz_analysis_block_unref(block);

	second = rz_analysis_block_split(block, 0x1339);
	assert_block_invariants(analysis);
	mu_assert_ptrneq(second, block, "non-nop split");
	mu_assert_eq(blocks_count(analysis), 2, "count after non-nop split");

	mu_assert_eq(block->addr, 0x1337, "first addr after split");
	mu_assert_eq(block->size, 2, "first size after split");
	mu_assert_eq(second->addr, 0x1339, "first addr after split");
	mu_assert_eq(second->size, 40, "first size after split");

	mu_assert_eq(block->jump, second->addr, "first jump");
	mu_assert_eq(block->fail, UT64_MAX, "first fail");
	mu_assert_eq(second->jump, 0xdeadbeef, "second jump");
	mu_assert_eq(second->fail, 0xc0ffee, "second fail");

	mu_assert_eq(block->ninstr, 2, "first ninstr after split");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 0), 0, "first op_pos[0]");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 1), 1, "first op_pos[1]");
	mu_assert_eq(block->sp_entry, -1000, "first sp_entry after split");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 0), -4, "first sp_delta[0]");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 1), -8, "first sp_delta[1]");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 2), ST16_MAX, "first sp_delta[3]");
	mu_assert_eq(rz_analysis_block_get_sp_delta_at_end(block), -8, "first sp_delta at end");
	mu_assert_eq(rz_analysis_block_get_sp_at_end(block), -1008, "first sp at end");

	mu_assert_eq(second->ninstr, 3, "second ninstr after split");
	mu_assert_eq(rz_analysis_block_get_op_offset(second, 0), 0, "second op_pos[0]");
	mu_assert_eq(rz_analysis_block_get_op_offset(second, 1), 2, "second op_pos[1]");
	mu_assert_eq(rz_analysis_block_get_op_offset(second, 2), 28, "second op_pos[2]");
	mu_assert_eq(second->sp_entry, -1008, "second sp_entry after split");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(second, 0), -5, "second sp_delta[0]");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(second, 1), -10, "second sp_delta[1]");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(second, 2), -15, "second sp_delta[2]");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(second, 3), ST16_MAX, "second sp_delta[3]");
	mu_assert_eq(rz_analysis_block_get_sp_delta_at_end(second), -15, "second sp_delta at end");
	mu_assert_eq(rz_analysis_block_get_sp_at_end(second), -1023, "second sp at end");

	rz_analysis_block_unref(block);
	rz_analysis_block_unref(second);

	assert_block_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_split_in_function() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "bbowner", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);
	assert_block_invariants(analysis);

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x1337, 42);
	assert_block_invariants(analysis);
	mu_assert_eq(blocks_count(analysis), 1, "count after create");
	rz_analysis_function_add_block(fcn, block);
	assert_block_invariants(analysis);
	mu_assert_eq(block->ref, 2, "block refs after adding to function");

	RzAnalysisBlock *second = rz_analysis_block_split(block, 0x1339);
	assert_block_invariants(analysis);
	mu_assert_ptrneq(second, block, "non-nop split");
	mu_assert_eq(blocks_count(analysis), 2, "count after non-nop split");
	mu_assert_eq(block->ref, 2, "first block refs after adding to function");
	mu_assert_eq(second->ref, 2, "second block refs after adding to function");

	mu_assert("function has first block after split", rz_pvector_contains(fcn->bbs, block));
	mu_assert("function has second block after split", rz_pvector_contains(fcn->bbs, second));
	mu_assert("second block is in function after split", rz_pvector_contains(block->fcns, fcn));
	mu_assert("second block is in function after split", rz_pvector_contains(second->fcns, fcn));

	rz_analysis_block_unref(block);
	rz_analysis_block_unref(second);

	assert_block_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_merge() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisBlock *first = rz_analysis_create_block(analysis, 0x1337, 42);
	RzAnalysisBlock *second = rz_analysis_create_block(analysis, 0x1337 + 42, 624);
	assert_block_invariants(analysis);
	mu_assert_eq(blocks_count(analysis), 2, "count after create");
	second->jump = 0xdeadbeef;
	second->fail = 0xc0ffee;

	first->ninstr = 3;
	rz_analysis_block_set_op_offset(first, 0, 0);
	rz_analysis_block_set_op_offset(first, 1, 13);
	rz_analysis_block_set_op_offset(first, 2, 16);

	second->ninstr = 4;
	rz_analysis_block_set_op_offset(second, 0, 0);
	rz_analysis_block_set_op_offset(second, 1, 4);
	rz_analysis_block_set_op_offset(second, 2, 9);
	rz_analysis_block_set_op_offset(second, 3, 30);

	bool success = rz_analysis_block_merge(first, second);
	assert_block_invariants(analysis);
	mu_assert("merge success", success);
	mu_assert_eq(blocks_count(analysis), 1, "count after merge");
	mu_assert_eq(first->addr, 0x1337, "addr after merge");
	mu_assert_eq(first->size, 666, "size after merge");
	mu_assert_eq(first->jump, 0xdeadbeef, "jump after merge");
	mu_assert_eq(first->fail, 0xc0ffee, "fail after merge");

	mu_assert_eq(first->ninstr, 3 + 4, "ninstr after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 0), 0, "offset 0 after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 1), 13, "offset 1 after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 2), 16, "offset 2 after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 3), 42 + 0, "offset 3 after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 4), 42 + 4, "offset 4 after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 5), 42 + 9, "offset 5 after merge");
	mu_assert_eq(rz_analysis_block_get_op_offset(first, 6), 42 + 30, "offset 6 after merge");

	rz_analysis_block_unref(first);
	// second must be already freed by the merge!

	assert_block_invariants(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_merge_in_function() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "bbowner", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);

	RzAnalysisBlock *first = rz_analysis_create_block(analysis, 0x1337, 42);
	RzAnalysisBlock *second = rz_analysis_create_block(analysis, 0x1337 + 42, 624);
	assert_block_invariants(analysis);
	mu_assert_eq(blocks_count(analysis), 2, "count after create");

	rz_analysis_function_add_block(fcn, first);
	assert_block_invariants(analysis);
	rz_analysis_function_add_block(fcn, second);
	assert_block_invariants(analysis);

	bool success = rz_analysis_block_merge(first, second);
	assert_block_invariants(analysis);
	mu_assert("merge success", success);
	mu_assert_eq(blocks_count(analysis), 1, "count after merge");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "fcn bbs after merge");
	mu_assert_eq(rz_pvector_len(first->fcns), 1, "bb functions after merge");
	mu_assert("function has merged block", rz_pvector_contains(fcn->bbs, first));
	mu_assert("merged block is in function", rz_pvector_contains(first->fcns, fcn));

	rz_analysis_block_unref(first);
	// second must be already freed by the merge!

	assert_block_invariants(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_delete() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "bbowner", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x1337, 42);
	assert_block_invariants(analysis);
	mu_assert_eq(blocks_count(analysis), 1, "count after create");

	rz_analysis_function_add_block(fcn, block);
	assert_block_invariants(analysis);
	mu_assert_eq(block->ref, 2, "refs after adding");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "fcn bbs after add");
	mu_assert_eq(rz_pvector_len(block->fcns), 1, "bb fcns after add");

	rz_analysis_delete_block(block);
	assert_block_invariants(analysis);
	mu_assert_eq(block->ref, 1, "refs after delete");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 0, "fcn bbs after delete");
	mu_assert_eq(rz_pvector_len(block->fcns), 0, "bb fcns after delete");

	rz_analysis_block_unref(block);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_set_size() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "bbowner", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x1337, 42);
	assert_block_invariants(analysis);

	rz_analysis_function_add_block(fcn, block);
	assert_block_invariants(analysis);

	rz_analysis_block_set_size(block, 300);
	assert_block_invariants(analysis);
	mu_assert_eq(block->size, 300, "size after set_size");

	RzAnalysisBlock *second = rz_analysis_create_block(analysis, 0x1337 + 300, 100);
	assert_block_invariants(analysis);
	rz_analysis_function_add_block(fcn, block);
	assert_block_invariants(analysis);
	rz_analysis_function_linear_size(fcn); // trigger lazy calculation of min/max cache
	assert_block_invariants(analysis);

	rz_analysis_block_set_size(second, 500);
	assert_block_invariants(analysis);
	mu_assert_eq(second->size, 500, "size after set_size");

	rz_analysis_block_set_size(block, 80);
	assert_block_invariants(analysis);
	mu_assert_eq(block->size, 80, "size after set_size");

	rz_analysis_block_unref(block);
	rz_analysis_block_unref(second);
	assert_block_invariants(analysis);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_relocate() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "bbowner", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x1337, 42);
	assert_block_invariants(analysis);

	rz_analysis_function_add_block(fcn, block);
	assert_block_invariants(analysis);
	rz_analysis_function_linear_size(fcn); // trigger lazy calculation of min/max cache
	assert_block_invariants(analysis);

	bool success = rz_analysis_block_relocate(block, 0x200, 0x100);
	mu_assert("relocate success", success);
	assert_block_invariants(analysis);
	mu_assert_eq(block->addr, 0x200, "addr after relocate");
	mu_assert_eq(block->size, 0x100, "size after relocate");

	RzAnalysisBlock *second = rz_analysis_create_block(analysis, 0x1337 + 300, 100);
	assert_block_invariants(analysis);
	rz_analysis_function_add_block(fcn, second);
	assert_block_invariants(analysis);

	success = rz_analysis_block_relocate(second, 0x400, 0x123);
	mu_assert("relocate success", success);
	assert_block_invariants(analysis);
	mu_assert_eq(second->addr, 0x400, "addr after relocate");
	mu_assert_eq(second->size, 0x123, "size after relocate");
	rz_analysis_function_linear_size(fcn); // trigger lazy calculation of min/max cache
	assert_block_invariants(analysis);

	success = rz_analysis_block_relocate(block, 0x400, 0x333);
	mu_assert("relocate fail on same addr", !success);
	assert_block_invariants(analysis);
	mu_assert_eq(block->addr, 0x200, "addr after failed relocate");
	mu_assert_eq(block->size, 0x100, "size after failed relocate");
	rz_analysis_function_linear_size(fcn); // trigger lazy calculation of min/max cache
	assert_block_invariants(analysis);

	// jump after the other block
	success = rz_analysis_block_relocate(block, 0x500, 0x333);
	mu_assert("relocate success", success);
	assert_block_invariants(analysis);
	mu_assert_eq(block->addr, 0x500, "addr after failed relocate");
	mu_assert_eq(block->size, 0x333, "size after failed relocate");
	rz_analysis_function_linear_size(fcn); // trigger lazy calculation of min/max cache
	assert_block_invariants(analysis);

	// jump before the other block
	success = rz_analysis_block_relocate(block, 0x10, 0x333);
	mu_assert("relocate success", success);
	assert_block_invariants(analysis);
	mu_assert_eq(block->addr, 0x10, "addr after failed relocate");
	mu_assert_eq(block->size, 0x333, "size after failed relocate");

	rz_analysis_block_unref(block);
	rz_analysis_block_unref(second);
	assert_block_invariants(analysis);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_query() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

#define N       200
#define MAXSIZE 0x300
#define SPACE   0x10000
#define SAMPLES 300

	RzAnalysisBlock *blocks[N];
	size_t i;
	for (i = 0; i < N; i++) {
		blocks[i] = rz_analysis_create_block(analysis, rand() % SPACE, rand() % MAXSIZE); // may return null on duplicates
		assert_block_invariants(analysis);
	}

	// --
	// test rz_analysis_get_block_at()

	for (i = 0; i < N; i++) {
		if (!blocks[i]) {
			continue;
		}
		mu_assert_ptreq(rz_analysis_get_block_at(analysis, blocks[i]->addr), blocks[i], "rz_analysis_get_block_at");
	}

	for (i = 0; i < SAMPLES; i++) {
		ut64 addr = rand() % SPACE;
		size_t j;

		// goal is to check cases where rz_analysis_get_block_at() returns null,
		// but since the addr is random, there may be a block sometimes too.
		RzAnalysisBlock *block = NULL;
		for (j = 0; j < N; j++) {
			if (!blocks[j]) {
				continue;
			}
			if (blocks[j]->addr == addr) {
				block = blocks[j];
				break;
			}
		}

		mu_assert_ptreq(rz_analysis_get_block_at(analysis, addr), block, "rz_analysis_get_block_at");
	}

	// --
	// test rz_analysis_get_blocks_in()

	for (i = 0; i < SAMPLES; i++) {
		ut64 addr = rand() % SPACE;
		RzList *in = rz_analysis_get_blocks_in(analysis, addr);

		RzAnalysisBlock *block;
		RzListIter *it;
		rz_list_foreach (in, it, block) {
			mu_assert_eq(block->ref, 2, "block refd in returned list");
		}

		size_t linear_found = 0;
		size_t j;
		for (j = 0; j < N; j++) {
			if (!blocks[j]) {
				continue;
			}
			if (rz_analysis_block_contains(blocks[j], addr)) {
				linear_found++;
				mu_assert("intersect linear found in list", rz_list_contains(in, blocks[j]));
			}
		}
		mu_assert_eq((size_t)rz_list_length(in), linear_found, "rz_analysis_get_blocks_in count");
		rz_list_free(in);
	}

	// --
	// test rz_analysis_get_blocks_intersect()

	for (i = 0; i < SAMPLES; i++) {
		ut64 addr = rand() % SPACE;
		ut64 size = rand() % MAXSIZE;
		RzList *in = rz_analysis_get_blocks_intersect(analysis, addr, size);

		RzAnalysisBlock *block;
		RzListIter *it;
		rz_list_foreach (in, it, block) {
			mu_assert_eq(block->ref, 2, "block refd in returned list");
		}

		size_t linear_found = 0;
		size_t j;
		for (j = 0; j < N; j++) {
			RzAnalysisBlock *block = blocks[j];
			if (!block || addr + size <= block->addr || addr >= block->addr + block->size) {
				continue;
			}
			linear_found++;
			mu_assert("in linear found in list", rz_list_contains(in, blocks[j]));
		}
		mu_assert_eq((size_t)rz_list_length(in), linear_found, "rz_analysis_get_blocks_intersect count");
		rz_list_free(in);
	}

	for (i = 0; i < N; i++) {
		rz_analysis_block_unref(blocks[i]);
	}

	assert_block_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool addr_list_cb(ut64 addr, void *user) {
	RzList *list = user;
	rz_list_push(list, (void *)(size_t)addr);
	return true;
}

bool test_rz_analysis_block_successors() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisBlock *blocks[10];
	blocks[0] = rz_analysis_create_block(analysis, 0x10, 0x10);
	blocks[1] = rz_analysis_create_block(analysis, 0x30, 0x10);
	blocks[2] = rz_analysis_create_block(analysis, 0x50, 0x10);
	blocks[3] = rz_analysis_create_block(analysis, 0x100, 0x10);
	blocks[4] = rz_analysis_create_block(analysis, 0x110, 0x10);
	blocks[5] = rz_analysis_create_block(analysis, 0x120, 0x10);
	blocks[6] = rz_analysis_create_block(analysis, 0x130, 0x10);
	blocks[7] = rz_analysis_create_block(analysis, 0x140, 0x10);
	blocks[8] = rz_analysis_create_block(analysis, 0xa0, 0x10);
	blocks[9] = rz_analysis_create_block(analysis, 0xc0, 0x10);
	assert_block_invariants(analysis);

	blocks[0]->jump = 0x30;
	blocks[0]->fail = 0x50;
	blocks[1]->jump = 0x10;
	blocks[1]->fail = 0x50;
	blocks[2]->jump = 0x10;

	RzAnalysisSwitchOp *sop = rz_analysis_switch_op_new(0x55, 0x13, 0x15, 0x42);
	mu_assert_eq(sop->addr, 0x55, "addr");
	mu_assert_eq(sop->min_val, 0x13, "addr");
	mu_assert_eq(sop->max_val, 0x15, "addr");
	mu_assert_eq(sop->def_val, 0x42, "addr");
	rz_analysis_switch_op_add_case(sop, 0x55, 1, 0x100);
	rz_analysis_switch_op_add_case(sop, 0x55, 2, 0x110);
	rz_analysis_switch_op_add_case(sop, 0x55, 3, 0x120);
	rz_analysis_switch_op_add_case(sop, 0x55, 4, 0x130);
	rz_analysis_switch_op_add_case(sop, 0x55, 5, 0x140);
	blocks[2]->switch_op = sop;

	RzList *result = rz_list_new();
	rz_analysis_block_successor_addrs_foreach(blocks[0], addr_list_cb, result);
	mu_assert_eq(rz_list_length(result), 2, "jump/fail successors count");
	mu_assert("jmp successor", rz_list_contains(result, (void *)0x30));
	mu_assert("fail successor", rz_list_contains(result, (void *)0x50));
	rz_list_purge(result);

	rz_analysis_block_successor_addrs_foreach(blocks[2], addr_list_cb, result);
	mu_assert_eq(rz_list_length(result), 6, "switch successors count");
	mu_assert("jmp successor", rz_list_contains(result, (void *)0x10));
	mu_assert("case successor", rz_list_contains(result, (void *)0x100));
	mu_assert("case successor", rz_list_contains(result, (void *)0x110));
	mu_assert("case successor", rz_list_contains(result, (void *)0x120));
	mu_assert("case successor", rz_list_contains(result, (void *)0x130));
	mu_assert("case successor", rz_list_contains(result, (void *)0x140));
	rz_list_free(result);

	result = rz_analysis_block_recurse_list(blocks[0]);
	RzAnalysisBlock *block;
	RzListIter *it;
	rz_list_foreach (result, it, block) {
		mu_assert_eq(block->ref, 2, "block refd in returned list");
	}

	mu_assert_eq(rz_list_length(result), 8, "recursive successors count");
	mu_assert("recursive successor", rz_list_contains(result, blocks[0]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[1]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[2]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[3]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[4]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[5]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[6]));
	mu_assert("recursive successor", rz_list_contains(result, blocks[7]));

	rz_list_free(result);

	size_t i;
	for (i = 0; i < sizeof(blocks) / sizeof(RzAnalysisBlock *); i++) {
		rz_analysis_block_unref(blocks[i]);
	}

	assert_block_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_block_automerge() {
	size_t i;
	for (i = 0; i < SAMPLES; i++) {
		RzAnalysis *analysis = rz_analysis_new();
		assert_block_invariants(analysis);

		RzAnalysisBlock *a = rz_analysis_create_block(analysis, 0x100, 0x10);

		RzAnalysisBlock *b = rz_analysis_create_block(analysis, 0x110, 0x10);
		a->jump = b->addr;

		RzAnalysisBlock *c = rz_analysis_create_block(analysis, 0x120, 0x10);
		b->jump = c->addr;
		c->fail = b->addr;

		RzAnalysisBlock *d = rz_analysis_create_block(analysis, 0x130, 0x10);
		c->jump = d->addr;

		RzAnalysisBlock *e = rz_analysis_create_block(analysis, 0x140, 0x10);
		d->jump = e->addr;

		RzAnalysisBlock *f = rz_analysis_create_block(analysis, 0x150, 0x10);
		e->jump = f->addr;

		RzAnalysisFunction *fa = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
		rz_analysis_function_add_block(fa, a);
		rz_analysis_function_add_block(fa, c);
		rz_analysis_function_add_block(fa, d);
		rz_analysis_function_add_block(fa, e);
		rz_analysis_function_add_block(fa, f);

		RzAnalysisFunction *fb = rz_analysis_create_function(analysis, "fcn2", 0x110, RZ_ANALYSIS_FCN_TYPE_FCN);
		rz_analysis_function_add_block(fb, b);
		rz_analysis_function_add_block(fb, c);
		rz_analysis_function_add_block(fb, d);
		rz_analysis_function_add_block(fb, e);
		rz_analysis_function_add_block(fb, f);

		RzList *all_blocks = rz_list_new();
		rz_list_push(all_blocks, a);
		rz_list_push(all_blocks, b);
		rz_list_push(all_blocks, c);
		rz_list_push(all_blocks, d);
		rz_list_push(all_blocks, e);
		rz_list_push(all_blocks, f);

		// Randomize the order in which we give the automerge the block.
		// The outcome should always be the same but it can have some delicate implications on the algorithm inside.
		RzPVector *shuffled_blocks = rz_pvector_new((RzPVectorFree)rz_analysis_block_unref);
		while (!rz_list_empty(all_blocks)) {
			int n = rand() % rz_list_length(all_blocks);
			rz_pvector_push(shuffled_blocks, rz_list_get_n(all_blocks, n));
			rz_list_del_n(all_blocks, n);
		}
		rz_list_free(all_blocks);

		rz_analysis_block_automerge(shuffled_blocks);
		assert_block_invariants(analysis);
		// mu_assert_eq (rz_list_length (shuffled_blocks), 4, "length after automerge");
		mu_assert("remaining blocks a", rz_pvector_contains(shuffled_blocks, a));
		mu_assert("remaining blocks b", rz_pvector_contains(shuffled_blocks, b));
		mu_assert("remaining blocks c", rz_pvector_contains(shuffled_blocks, c));
		mu_assert("remaining blocks d", rz_pvector_contains(shuffled_blocks, d));
		mu_assert_eq(blocks_count(analysis), rz_pvector_len(shuffled_blocks), "blocks in analysis count");
		void **it;
		RzAnalysisBlock *block;
		rz_pvector_foreach (shuffled_blocks, it) {
			block = (RzAnalysisBlock *)*it;
			mu_assert_ptreq(rz_analysis_get_block_at(analysis, block->addr), block, "remaining blocks in analysis");
		}
		rz_pvector_free(shuffled_blocks);

		assert_block_invariants(analysis);
		assert_block_leaks(analysis);
		rz_analysis_free(analysis);
	}
	mu_end;
}

bool test_rz_analysis_block_chop_noreturn(void) {
	RzAnalysis *analysis = rz_analysis_new();
	assert_block_invariants(analysis);

	RzAnalysisBlock *a = rz_analysis_create_block(analysis, 0x100, 0x10);
	RzAnalysisBlock *b = rz_analysis_create_block(analysis, 0x110, 0x10);
	RzAnalysisBlock *c = rz_analysis_create_block(analysis, 0x120, 0x10);
	a->jump = c->addr;
	b->jump = c->addr;

	RzAnalysisFunction *fa = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	rz_analysis_function_add_block(fa, a);
	rz_analysis_function_add_block(fa, b);
	rz_analysis_function_add_block(fa, c);

	RzAnalysisFunction *fb = rz_analysis_create_function(analysis, "fcn2", 0x130, RZ_ANALYSIS_FCN_TYPE_FCN);
	fb->is_noreturn = true;

	rz_analysis_block_chop_noreturn(b, 0x111);

	assert_block_invariants(analysis);
	rz_analysis_free(analysis);

	mu_end;
}

static const uint8_t example_code[0x18] = {
	0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00, // mov rax, 0x2a
	0x48, 0x89, 0xc2, // mov rdx, rax
	0x48, 0x81, 0xc2, 0x0f, 0x05, 0x00, 0x00, // add rdx, 0x50f
	0x48, 0xc7, 0xc0, 0x37, 0x13, 0x00, 0x00 // mov rax, 0x1337
};

bool test_rz_analysis_block_analyze_ops(void) {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "x86");
	rz_analysis_set_bits(a, 64);
	IOMock io;
	io_mock_init(&io, 0x1000, example_code, sizeof(example_code));
	io_mock_bind(&io, &a->iob);

	// clean block with valid code
	RzAnalysisBlock *block = rz_analysis_create_block(a, 0x1000, 0x18);
	mu_assert_eq(block->ninstr, 0, "clean block");
	rz_analysis_block_analyze_ops(block);
	mu_assert_eq(block->ninstr, 4, "ninstr");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 0), 0, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 1), 0x7, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 2), 0xa, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 3), 0x11, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_addr(block, 0), 0x1000, "op addr");
	mu_assert_eq(rz_analysis_block_get_op_addr(block, 1), 0x1007, "op addr");
	mu_assert_eq(rz_analysis_block_get_op_addr(block, 2), 0x100a, "op addr");
	mu_assert_eq(rz_analysis_block_get_op_addr(block, 3), 0x1011, "op addr");
	mu_assert_eq(rz_analysis_block_get_op_size(block, 0), 0x7, "op size");
	mu_assert_eq(rz_analysis_block_get_op_size(block, 1), 0x3, "op size");
	mu_assert_eq(rz_analysis_block_get_op_size(block, 2), 0x7, "op size");
	mu_assert_eq(rz_analysis_block_get_op_size(block, 3), 0x7, "op size");
	mu_assert_eq(rz_analysis_block_get_op_index_in(block, 0x1000), 0, "op index in");
	mu_assert_eq(rz_analysis_block_get_op_index_in(block, 0x1001), 0, "op index in");
	mu_assert_eq(rz_analysis_block_get_op_index_in(block, 0x1006), 0, "op index in");
	mu_assert_eq(rz_analysis_block_get_op_index_in(block, 0x1007), 1, "op index in");
	mu_assert_eq(rz_analysis_block_get_op_index_in(block, 0x1008), 1, "op index in");
	mu_assert_eq(rz_analysis_block_get_op_addr_in(block, 0x1000), 0x1000, "op addr in");
	mu_assert_eq(rz_analysis_block_get_op_addr_in(block, 0x1001), 0x1000, "op addr in");
	mu_assert_eq(rz_analysis_block_get_op_addr_in(block, 0x1006), 0x1000, "op addr in");
	mu_assert_eq(rz_analysis_block_get_op_addr_in(block, 0x1007), 0x1007, "op addr in");
	mu_assert_eq(rz_analysis_block_get_op_addr_in(block, 0x1008), 0x1007, "op addr in");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 0), 0, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 1), 0, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 2), 0, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 3), 0, "sp delta");

	// dirty block with valid code
	rz_analysis_block_relocate(block, 0x1000, 0x11);
	rz_analysis_block_analyze_ops(block);
	mu_assert_eq(block->ninstr, 3, "ninstr");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 0), 0, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 1), 0x7, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 2), 0xa, "op offset");

	rz_analysis_block_unref(block);

	// clean block with invalid code a the end
	// when encountering invalid code, analysis should stop.
	block = rz_analysis_create_block(a, 0x1000, 0x17);
	mu_assert_eq(block->ninstr, 0, "clean block");
	rz_analysis_block_analyze_ops(block);
	mu_assert_eq(block->ninstr, 3, "ninstr");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 0), 0, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 1), 0x7, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 2), 0xa, "op offset");

	rz_analysis_block_unref(block);

	assert_block_invariants(a);
	assert_block_leaks(a);
	rz_analysis_free(a);
	io_mock_fini(&io);
	mu_end;
}

static const uint8_t example_code_sp[0xa] = {
	0x55, // push rbp
	0x48, 0x89, 0xe5, // mov rbp, rsp
	0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
	0xc9, // leave
	0x55, // push rbp
};

bool test_rz_analysis_block_analyze_ops_sp(void) {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "x86");
	rz_analysis_set_bits(a, 64);
	IOMock io;
	io_mock_init(&io, 0x1000, example_code_sp, sizeof(example_code_sp));
	io_mock_bind(&io, &a->iob);

	RzAnalysisBlock *block = rz_analysis_create_block(a, 0x1000, 0xa);
	mu_assert_eq(block->ninstr, 0, "clean block");
	rz_analysis_block_analyze_ops(block);
	mu_assert_eq(block->ninstr, 5, "ninstr");
	mu_assert_eq(block->sp_entry, RZ_STACK_ADDR_INVALID, "sp_entry untouched");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 0), 0, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 1), 0x1, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 2), 0x4, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 3), 0x8, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 4), 0x9, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 0), -8, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 1), -8, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 2), -0x28, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 3), 0, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 4), -8, "sp delta");

	block->sp_entry = -0x10;
	rz_analysis_block_analyze_ops(block);
	mu_assert_eq(block->ninstr, 5, "ninstr");
	mu_assert_eq(block->sp_entry, -0x10, "sp_entry untouched");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 0), 0, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 1), 0x1, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 2), 0x4, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 3), 0x8, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_offset(block, 4), 0x9, "op offset");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 0), -8, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 1), -8, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 2), -0x28, "sp delta");
	// stack reset depends on the sp_entry, which makes the following difference to above:
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 3), 0x10, "sp delta");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 4), 8, "sp delta");

	rz_analysis_block_unref(block);

	assert_block_invariants(a);
	assert_block_leaks(a);
	rz_analysis_free(a);
	io_mock_fini(&io);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_block_chop_noreturn);
	mu_run_test(test_rz_analysis_block_create);
	mu_run_test(test_rz_analysis_block_contains);
	mu_run_test(test_rz_analysis_block_sp);
	mu_run_test(test_rz_analysis_block_split);
	mu_run_test(test_rz_analysis_block_split_in_function);
	mu_run_test(test_rz_analysis_block_merge);
	mu_run_test(test_rz_analysis_block_merge_in_function);
	mu_run_test(test_rz_analysis_block_delete);
	mu_run_test(test_rz_analysis_block_set_size);
	mu_run_test(test_rz_analysis_block_relocate);
	mu_run_test(test_rz_analysis_block_query);
	mu_run_test(test_rz_analysis_block_successors);
	mu_run_test(test_rz_analysis_block_automerge);
	mu_run_test(test_rz_analysis_block_analyze_ops);
	mu_run_test(test_rz_analysis_block_analyze_ops_sp);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	struct timeval tv;
	rz_time_gettimeofday(&tv, NULL);
	unsigned int seed = argc > 1 ? strtoul(argv[1], NULL, 0) : tv.tv_sec + tv.tv_usec;
	printf("seed for test_analysis_block: %u\n", seed);
	return all_tests();
}
