#include <rz_anal.h>
#include <rz_core.h>
#include "minunit.h"

#include "test_anal_block_invars.inl"
#define check_invariants block_check_invariants
#define check_leaks block_check_leaks

static size_t blocks_count(RzAnal *anal) {
	size_t count = 0;
	RBIter iter;
	RzAnalBlock *block;
	rz_rbtree_foreach(anal->bb_tree, iter, block, RzAnalBlock, _rb) {
		count++;
	}
	return count;
}


#define assert_invariants(anal) do { if (!check_invariants (anal)) { return false; } } while (0)
#define assert_leaks(anal) do { if (!check_leaks (anal)) { return false; } } while (0)

bool test_r_anal_block_create() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	mu_assert_eq (blocks_count (anal), 0, "initial count");

	RzAnalBlock *block = rz_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);
	mu_assert ("created block", block);
	mu_assert_eq (block->addr, 0x1337, "created addr");
	mu_assert_eq (block->size, 42, "created size");
	mu_assert_eq (block->ref, 1, "created initial ref");
	mu_assert_eq (blocks_count (anal), 1, "count after create");

	RzAnalBlock *block2 = rz_anal_create_block (anal, 0x133f, 100);
	assert_invariants (anal);
	mu_assert ("created block (overlap)", block2);
	mu_assert_eq (block2->addr, 0x133f, "created addr");
	mu_assert_eq (block2->size, 100, "created size");
	mu_assert_eq (block2->ref, 1, "created initial ref");
	mu_assert_eq (blocks_count (anal), 2, "count after create");

	RzAnalBlock *block3 = rz_anal_create_block (anal, 0x1337, 5);
	assert_invariants (anal);
	mu_assert ("no double create on same start", !block3);
	mu_assert_eq (blocks_count (anal), 2, "count after failed create");

	rz_anal_block_unref (block);
	rz_anal_block_unref (block2);

	assert_leaks (anal);
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_contains() {
	RzAnalBlock dummy = { 0 };
	dummy.addr = 0x1337;
	dummy.size = 42;
	mu_assert ("contains before", !rz_anal_block_contains (&dummy, 100));
	mu_assert ("contains start", rz_anal_block_contains (&dummy, 0x1337));
	mu_assert ("contains inside", rz_anal_block_contains (&dummy, 0x1339));
	mu_assert ("contains last", rz_anal_block_contains (&dummy, 0x1337 + 42 - 1));
	mu_assert ("contains after", !rz_anal_block_contains (&dummy, 0x1337 + 42));
	mu_end;
}

bool test_r_anal_block_split() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalBlock *block = rz_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);
	mu_assert_eq (blocks_count (anal), 1, "count after create");
	block->jump = 0xdeadbeef;
	block->fail = 0xc0ffee;
	block->ninstr = 5;
	rz_anal_bb_set_offset (block, 0, 0);
	rz_anal_bb_set_offset (block, 1, 1);
	rz_anal_bb_set_offset (block, 2, 2);
	rz_anal_bb_set_offset (block, 3, 4);
	rz_anal_bb_set_offset (block, 4, 30);

	RzAnalBlock *second = rz_anal_block_split (block, 0x1337);
	assert_invariants (anal);
	mu_assert_ptreq (second, block, "nop split on first addr");
	mu_assert_eq (blocks_count (anal), 1, "count after nop split");
	mu_assert_eq (block->ref, 2, "ref after nop split");
	rz_anal_block_unref (block);

	second = rz_anal_block_split (block, 0x1339);
	assert_invariants (anal);
	mu_assert_ptrneq (second, block, "non-nop split");
	mu_assert_eq (blocks_count (anal), 2, "count after non-nop split");

	mu_assert_eq (block->addr, 0x1337, "first addr after split");
	mu_assert_eq (block->size, 2, "first size after split");
	mu_assert_eq (second->addr, 0x1339, "first addr after split");
	mu_assert_eq (second->size, 40, "first size after split");

	mu_assert_eq (block->jump, second->addr, "first jump");
	mu_assert_eq (block->fail, UT64_MAX, "first fail");
	mu_assert_eq (second->jump, 0xdeadbeef, "second jump");
	mu_assert_eq (second->fail, 0xc0ffee, "second fail");

	mu_assert_eq (block->ninstr, 2, "first ninstr after split");
	mu_assert_eq (rz_anal_bb_offset_inst (block, 0), 0, "first op_pos[0]");
	mu_assert_eq (rz_anal_bb_offset_inst (block, 1), 1, "first op_pos[1]");

	mu_assert_eq (second->ninstr, 3, "second ninstr after split");
	mu_assert_eq (rz_anal_bb_offset_inst (second, 0), 0, "second op_pos[0]");
	mu_assert_eq (rz_anal_bb_offset_inst (second, 1), 2, "second op_pos[1]");
	mu_assert_eq (rz_anal_bb_offset_inst (second, 2), 28, "second op_pos[2]");

	rz_anal_block_unref (block);
	rz_anal_block_unref (second);

	assert_leaks (anal);
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_split_in_function() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalFunction *fcn = rz_anal_create_function (anal, "bbowner", 0x1337, 0, NULL);
	assert_invariants (anal);

	RzAnalBlock *block = rz_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);
	mu_assert_eq (blocks_count (anal), 1, "count after create");
	rz_anal_function_add_block (fcn, block);
	assert_invariants (anal);
	mu_assert_eq (block->ref, 2, "block refs after adding to function");

	RzAnalBlock *second = rz_anal_block_split (block, 0x1339);
	assert_invariants (anal);
	mu_assert_ptrneq (second, block, "non-nop split");
	mu_assert_eq (blocks_count (anal), 2, "count after non-nop split");
	mu_assert_eq (block->ref, 2, "first block refs after adding to function");
	mu_assert_eq (second->ref, 2, "second block refs after adding to function");

	mu_assert ("function has first block after split", rz_list_contains (fcn->bbs, block));
	mu_assert ("function has second block after split", rz_list_contains (fcn->bbs, second));
	mu_assert ("second block is in function after split", rz_list_contains (block->fcns, fcn));
	mu_assert ("second block is in function after split", rz_list_contains (second->fcns, fcn));

	rz_anal_block_unref (block);
	rz_anal_block_unref (second);

	assert_leaks (anal);
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_merge() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalBlock *first = rz_anal_create_block (anal, 0x1337, 42);
	RzAnalBlock *second = rz_anal_create_block (anal, 0x1337 + 42, 624);
	assert_invariants (anal);
	mu_assert_eq (blocks_count (anal), 2, "count after create");
	second->jump = 0xdeadbeef;
	second->fail = 0xc0ffee;

	first->ninstr = 3;
	rz_anal_bb_set_offset (first, 0, 0);
	rz_anal_bb_set_offset (first, 1, 13);
	rz_anal_bb_set_offset (first, 2, 16);

	second->ninstr = 4;
	rz_anal_bb_set_offset (second, 0, 0);
	rz_anal_bb_set_offset (second, 1, 4);
	rz_anal_bb_set_offset (second, 2, 9);
	rz_anal_bb_set_offset (second, 3, 30);

	bool success = rz_anal_block_merge (first, second);
	assert_invariants (anal);
	mu_assert ("merge success", success);
	mu_assert_eq (blocks_count (anal), 1, "count after merge");
	mu_assert_eq (first->addr, 0x1337, "addr after merge");
	mu_assert_eq (first->size, 666, "size after merge");
	mu_assert_eq (first->jump, 0xdeadbeef, "jump after merge");
	mu_assert_eq (first->fail, 0xc0ffee, "fail after merge");

	mu_assert_eq (first->ninstr, 3+4, "ninstr after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 0), 0, "offset 0 after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 1), 13, "offset 1 after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 2), 16, "offset 2 after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 3), 42+0, "offset 3 after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 4), 42+4, "offset 4 after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 5), 42+9, "offset 5 after merge");
	mu_assert_eq (rz_anal_bb_offset_inst (first, 6), 42+30, "offset 6 after merge");

	rz_anal_block_unref (first);
	// second must be already freed by the merge!

	assert_invariants (anal);
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_merge_in_function() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalFunction *fcn = rz_anal_create_function (anal, "bbowner", 0x1337, 0, NULL);

	RzAnalBlock *first = rz_anal_create_block (anal, 0x1337, 42);
	RzAnalBlock *second = rz_anal_create_block (anal, 0x1337 + 42, 624);
	assert_invariants (anal);
	mu_assert_eq (blocks_count (anal), 2, "count after create");

	rz_anal_function_add_block (fcn, first);
	assert_invariants (anal);
	rz_anal_function_add_block (fcn, second);
	assert_invariants (anal);

	bool success = rz_anal_block_merge (first, second);
	assert_invariants (anal);
	mu_assert ("merge success", success);
	mu_assert_eq (blocks_count (anal), 1, "count after merge");
	mu_assert_eq (rz_list_length (fcn->bbs), 1, "fcn bbs after merge");
	mu_assert_eq (rz_list_length (first->fcns), 1, "bb functions after merge");
	mu_assert ("function has merged block", rz_list_contains (fcn->bbs, first));
	mu_assert ("merged block is in function", rz_list_contains (first->fcns, fcn));

	rz_anal_block_unref (first);
	// second must be already freed by the merge!

	assert_invariants (anal);
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_delete() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalFunction *fcn = rz_anal_create_function (anal, "bbowner", 0x1337, 0, NULL);

	RzAnalBlock *block = rz_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);
	mu_assert_eq (blocks_count (anal), 1, "count after create");

	rz_anal_function_add_block (fcn, block);
	assert_invariants (anal);
	mu_assert_eq (block->ref, 2, "refs after adding");
	mu_assert_eq (rz_list_length (fcn->bbs), 1, "fcn bbs after add");
	mu_assert_eq (rz_list_length (block->fcns), 1, "bb fcns after add");

	rz_anal_delete_block (block);
	assert_invariants (anal);
	mu_assert_eq (block->ref, 1, "refs after delete");
	mu_assert_eq (rz_list_length (fcn->bbs), 0, "fcn bbs after delete");
	mu_assert_eq (rz_list_length (block->fcns), 0, "bb fcns after delete");

	rz_anal_block_unref (block);

	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_set_size() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalFunction *fcn = rz_anal_create_function (anal, "bbowner", 0x1337, 0, NULL);

	RzAnalBlock *block = rz_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);

	rz_anal_function_add_block (fcn, block);
	assert_invariants (anal);

	rz_anal_block_set_size (block, 300);
	assert_invariants (anal);
	mu_assert_eq (block->size, 300, "size after set_size");

	RzAnalBlock *second = rz_anal_create_block (anal, 0x1337+300, 100);
	assert_invariants (anal);
	rz_anal_function_add_block (fcn, block);
	assert_invariants (anal);
	rz_anal_function_linear_size (fcn); // trigger lazy calculation of min/max cache
	assert_invariants (anal);

	rz_anal_block_set_size (second, 500);
	assert_invariants (anal);
	mu_assert_eq (second->size, 500, "size after set_size");

	rz_anal_block_set_size (block, 80);
	assert_invariants (anal);
	mu_assert_eq (block->size, 80, "size after set_size");

	rz_anal_block_unref (block);
	rz_anal_block_unref (second);
	assert_invariants (anal);

	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_relocate() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalFunction *fcn = rz_anal_create_function (anal, "bbowner", 0x1337, 0, NULL);

	RzAnalBlock *block = rz_anal_create_block (anal, 0x1337, 42);
	assert_invariants (anal);

	rz_anal_function_add_block (fcn, block);
	assert_invariants (anal);
	rz_anal_function_linear_size (fcn); // trigger lazy calculation of min/max cache
	assert_invariants (anal);

	bool success = rz_anal_block_relocate (block, 0x200, 0x100);
	mu_assert ("relocate success", success);
	assert_invariants (anal);
	mu_assert_eq (block->addr, 0x200, "addr after relocate");
	mu_assert_eq (block->size, 0x100, "size after relocate");

	RzAnalBlock *second = rz_anal_create_block (anal, 0x1337+300, 100);
	assert_invariants (anal);
	rz_anal_function_add_block (fcn, second);
	assert_invariants (anal);

	success = rz_anal_block_relocate (second, 0x400, 0x123);
	mu_assert ("relocate success", success);
	assert_invariants (anal);
	mu_assert_eq (second->addr, 0x400, "addr after relocate");
	mu_assert_eq (second->size, 0x123, "size after relocate");
	rz_anal_function_linear_size (fcn); // trigger lazy calculation of min/max cache
	assert_invariants (anal);

	success = rz_anal_block_relocate (block, 0x400, 0x333);
	mu_assert ("relocate fail on same addr", !success);
	assert_invariants (anal);
	mu_assert_eq (block->addr, 0x200, "addr after failed relocate");
	mu_assert_eq (block->size, 0x100, "size after failed relocate");
	rz_anal_function_linear_size (fcn); // trigger lazy calculation of min/max cache
	assert_invariants (anal);

	// jump after the other block
	success = rz_anal_block_relocate (block, 0x500, 0x333);
	mu_assert ("relocate success", success);
	assert_invariants (anal);
	mu_assert_eq (block->addr, 0x500, "addr after failed relocate");
	mu_assert_eq (block->size, 0x333, "size after failed relocate");
	rz_anal_function_linear_size (fcn); // trigger lazy calculation of min/max cache
	assert_invariants (anal);

	// jump before the other block
	success = rz_anal_block_relocate (block, 0x10, 0x333);
	mu_assert ("relocate success", success);
	assert_invariants (anal);
	mu_assert_eq (block->addr, 0x10, "addr after failed relocate");
	mu_assert_eq (block->size, 0x333, "size after failed relocate");

	rz_anal_block_unref (block);
	rz_anal_block_unref (second);
	assert_invariants (anal);

	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_query() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

#define N 200
#define MAXSIZE 0x300
#define SPACE 0x10000
#define SAMPLES 300

	RzAnalBlock *blocks[N];
	size_t i;
	for (i = 0; i < N; i++) {
		blocks[i] = rz_anal_create_block (anal, rand () % SPACE, rand () % MAXSIZE); // may return null on duplicates
		assert_invariants (anal);
	}

	// --
	// test rz_anal_get_block_at()

	for (i = 0; i < N; i++) {
		if (!blocks[i]) {
			continue;
		}
		mu_assert_ptreq (rz_anal_get_block_at (anal, blocks[i]->addr), blocks[i], "rz_anal_get_block_at");
	}

	for (i = 0; i < SAMPLES; i++) {
		ut64 addr = rand () % SPACE;
		size_t j;

		// goal is to check cases where rz_anal_get_block_at() returns null,
		// but since the addr is random, there may be a block sometimes too.
		RzAnalBlock *block = NULL;
		for (j = 0; j < N; j++) {
			if (!blocks[j]) {
				continue;
			}
			if (blocks[j]->addr == addr) {
				block = blocks[j];
				break;
			}
		}

		mu_assert_ptreq (rz_anal_get_block_at (anal, addr), block, "rz_anal_get_block_at");
	}

	// --
	// test rz_anal_get_blocks_in()

	for (i = 0; i < SAMPLES; i++) {
		ut64 addr = rand () % SPACE;
		RzList *in = rz_anal_get_blocks_in (anal, addr);

		RzAnalBlock *block;
		RzListIter *it;
		rz_list_foreach (in, it, block) {
			mu_assert_eq (block->ref, 2, "block refd in returned list");
		}

		size_t linear_found = 0;
		size_t j;
		for (j = 0; j < N; j++) {
			if (!blocks[j]) {
				continue;
			}
			if (rz_anal_block_contains (blocks[j], addr)) {
				linear_found++;
				mu_assert ("intersect linear found in list", rz_list_contains (in, blocks[j]));
			}
		}
		mu_assert_eq ((size_t)rz_list_length (in), linear_found, "rz_anal_get_blocks_in count");
		rz_list_free (in);
	}

	// --
	// test rz_anal_get_blocks_intersect()

	for (i = 0; i < SAMPLES; i++) {
		ut64 addr = rand () % SPACE;
		ut64 size = rand() % MAXSIZE;
		RzList *in = rz_anal_get_blocks_intersect (anal, addr, size);

		RzAnalBlock *block;
		RzListIter *it;
		rz_list_foreach (in, it, block) {
			mu_assert_eq (block->ref, 2, "block refd in returned list");
		}

		size_t linear_found = 0;
		size_t j;
		for (j = 0; j < N; j++) {
			RzAnalBlock *block = blocks[j];
			if (!block || addr + size <= block->addr || addr >= block->addr + block->size) {
				continue;
			}
			linear_found++;
			mu_assert ("in linear found in list", rz_list_contains (in, blocks[j]));
		}
		mu_assert_eq ((size_t)rz_list_length (in), linear_found, "rz_anal_get_blocks_intersect count");
		rz_list_free (in);
	}

	for (i = 0; i < N; i++) {
		rz_anal_block_unref (blocks[i]);
	}

	assert_leaks (anal);
	rz_anal_free (anal);
	mu_end;
}

bool addr_list_cb(ut64 addr, void *user) {
	RzList *list = user;
	rz_list_push (list, (void *)addr);
	return true;
}

bool test_r_anal_block_successors() {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalBlock *blocks[10];
	blocks[0] = rz_anal_create_block (anal, 0x10, 0x10);
	blocks[1] = rz_anal_create_block (anal, 0x30, 0x10);
	blocks[2] = rz_anal_create_block (anal, 0x50, 0x10);
	blocks[3] = rz_anal_create_block (anal, 0x100, 0x10);
	blocks[4] = rz_anal_create_block (anal, 0x110, 0x10);
	blocks[5] = rz_anal_create_block (anal, 0x120, 0x10);
	blocks[6] = rz_anal_create_block (anal, 0x130, 0x10);
	blocks[7] = rz_anal_create_block (anal, 0x140, 0x10);
	blocks[8] = rz_anal_create_block (anal, 0xa0, 0x10);
	blocks[9] = rz_anal_create_block (anal, 0xc0, 0x10);
	assert_invariants (anal);

	blocks[0]->jump = 0x30;
	blocks[0]->fail = 0x50;
	blocks[1]->jump = 0x10;
	blocks[1]->fail = 0x50;
	blocks[2]->jump = 0x10;

	RzAnalSwitchOp *sop = rz_anal_switch_op_new (0x55, 0x13, 0x15, 0x42);
	mu_assert_eq (sop->addr, 0x55, "addr");
	mu_assert_eq (sop->min_val, 0x13, "addr");
	mu_assert_eq (sop->max_val, 0x15, "addr");
	mu_assert_eq (sop->def_val, 0x42, "addr");
	rz_anal_switch_op_add_case (sop, 0x55, 1, 0x100);
	rz_anal_switch_op_add_case (sop, 0x55, 2, 0x110);
	rz_anal_switch_op_add_case (sop, 0x55, 3, 0x120);
	rz_anal_switch_op_add_case (sop, 0x55, 4, 0x130);
	rz_anal_switch_op_add_case (sop, 0x55, 5, 0x140);
	blocks[2]->switch_op = sop;

	RzList *result = rz_list_new ();
	rz_anal_block_successor_addrs_foreach (blocks[0], addr_list_cb, result);
	mu_assert_eq (rz_list_length (result), 2, "jump/fail successors count");
	mu_assert ("jmp successor", rz_list_contains (result, (void *)0x30));
	mu_assert ("fail successor", rz_list_contains (result, (void *)0x50));
	rz_list_purge (result);

	rz_anal_block_successor_addrs_foreach (blocks[2], addr_list_cb, result);
	mu_assert_eq (rz_list_length (result), 6, "switch successors count");
	mu_assert ("jmp successor", rz_list_contains (result, (void *)0x10));
	mu_assert ("case successor", rz_list_contains (result, (void *)0x100));
	mu_assert ("case successor", rz_list_contains (result, (void *)0x110));
	mu_assert ("case successor", rz_list_contains (result, (void *)0x120));
	mu_assert ("case successor", rz_list_contains (result, (void *)0x130));
	mu_assert ("case successor", rz_list_contains (result, (void *)0x140));
	rz_list_free (result);

	result = rz_anal_block_recurse_list (blocks[0]);
	RzAnalBlock *block;
	RzListIter *it;
	rz_list_foreach (result, it, block) {
		mu_assert_eq (block->ref, 2, "block refd in returned list");
	}

	mu_assert_eq (rz_list_length (result), 8, "recursive successors count");
	mu_assert ("recursive successor", rz_list_contains (result, blocks[0]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[1]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[2]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[3]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[4]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[5]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[6]));
	mu_assert ("recursive successor", rz_list_contains (result, blocks[7]));

	rz_list_free (result);

	size_t i;
	for (i = 0; i < sizeof (blocks) / sizeof (RzAnalBlock *); i++) {
		rz_anal_block_unref (blocks[i]);
	}

	assert_leaks (anal);
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_block_automerge() {
	size_t i;
	for (i = 0; i < SAMPLES; i++) {
		RzAnal *anal = rz_anal_new ();
		assert_invariants (anal);

		RzAnalBlock *a = rz_anal_create_block (anal, 0x100, 0x10);

		RzAnalBlock *b = rz_anal_create_block (anal, 0x110, 0x10);
		a->jump = b->addr;

		RzAnalBlock *c = rz_anal_create_block (anal, 0x120, 0x10);
		b->jump = c->addr;
		c->fail = b->addr;

		RzAnalBlock *d = rz_anal_create_block (anal, 0x130, 0x10);
		c->jump = d->addr;

		RzAnalBlock *e = rz_anal_create_block (anal, 0x140, 0x10);
		d->jump = e->addr;

		RzAnalBlock *f = rz_anal_create_block (anal, 0x150, 0x10);
		e->jump = f->addr;

		RzAnalFunction *fa = rz_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
		rz_anal_function_add_block (fa, a);
		rz_anal_function_add_block (fa, c);
		rz_anal_function_add_block (fa, d);
		rz_anal_function_add_block (fa, e);
		rz_anal_function_add_block (fa, f);

		RzAnalFunction *fb = rz_anal_create_function (anal, "fcn2", 0x110, R_ANAL_FCN_TYPE_FCN, NULL);
		rz_anal_function_add_block (fb, b);
		rz_anal_function_add_block (fb, c);
		rz_anal_function_add_block (fb, d);
		rz_anal_function_add_block (fb, e);
		rz_anal_function_add_block (fb, f);

		RzList *all_blocks = rz_list_new ();
		rz_list_push (all_blocks, a);
		rz_list_push (all_blocks, b);
		rz_list_push (all_blocks, c);
		rz_list_push (all_blocks, d);
		rz_list_push (all_blocks, e);
		rz_list_push (all_blocks, f);

		// Randomize the order in which we give the automerge the block.
		// The outcome should always be the same but it can have some delicate implications on the algorithm inside.
		RzList *shuffled_blocks = rz_list_newf ((RzListFree)rz_anal_block_unref);
		while (!rz_list_empty (all_blocks)) {
			int n = rand () % rz_list_length (all_blocks);
			rz_list_push (shuffled_blocks, rz_list_get_n (all_blocks, n));
			rz_list_del_n (all_blocks, n);
		}
		rz_list_free (all_blocks);

		rz_anal_block_automerge (shuffled_blocks);
		assert_invariants (anal);
		//mu_assert_eq (rz_list_length (shuffled_blocks), 4, "length after automerge");
		mu_assert ("remaining blocks a", rz_list_contains (shuffled_blocks, a));
		mu_assert ("remaining blocks b", rz_list_contains (shuffled_blocks, b));
		mu_assert ("remaining blocks c", rz_list_contains (shuffled_blocks, c));
		mu_assert ("remaining blocks d", rz_list_contains (shuffled_blocks, d));
		mu_assert_eq (blocks_count (anal), rz_list_length (shuffled_blocks), "blocks in anal count");
		RzListIter *it;
		RzAnalBlock *block;
		rz_list_foreach (shuffled_blocks, it, block) {
			mu_assert_ptreq (rz_anal_get_block_at (anal, block->addr), block, "remaining blocks in anal");
		}
		rz_list_free (shuffled_blocks);

		assert_invariants (anal);
		assert_leaks (anal);
		rz_anal_free (anal);
	}
	mu_end;
}

bool test_r_anal_block_chop_noreturn(void) {
	RzAnal *anal = rz_anal_new ();
	assert_invariants (anal);

	RzAnalBlock *a = rz_anal_create_block (anal, 0x100, 0x10);
	RzAnalBlock *b = rz_anal_create_block (anal, 0x110, 0x10);
	RzAnalBlock *c = rz_anal_create_block (anal, 0x120, 0x10);
	a->jump = c->addr;
	b->jump = c->addr;

	RzAnalFunction *fa = rz_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	rz_anal_function_add_block (fa, a);
	rz_anal_function_add_block (fa, b);
	rz_anal_function_add_block (fa, c);

	RzAnalFunction *fb = rz_anal_create_function (anal, "fcn2", 0x130, R_ANAL_FCN_TYPE_FCN, NULL);
	fb->is_noreturn = true;

	rz_anal_block_chop_noreturn (b, 0x111);

	assert_invariants (anal);

	mu_end;
}

int all_tests() {
	mu_run_test (test_r_anal_block_chop_noreturn);
	mu_run_test (test_r_anal_block_create);
	mu_run_test (test_r_anal_block_contains);
	mu_run_test (test_r_anal_block_split);
	mu_run_test (test_r_anal_block_split_in_function);
	mu_run_test (test_r_anal_block_merge);
	mu_run_test (test_r_anal_block_merge_in_function);
	mu_run_test (test_r_anal_block_delete);
	mu_run_test (test_r_anal_block_set_size);
	mu_run_test (test_r_anal_block_relocate);
	mu_run_test (test_r_anal_block_query);
	mu_run_test (test_r_anal_block_successors);
	mu_run_test (test_r_anal_block_automerge);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	struct timeval tv;
	gettimeofday (&tv, NULL);
	unsigned int seed = argc > 1 ? strtoul (argv[1], NULL, 0) : tv.tv_sec + tv.tv_usec;
	printf("seed for test_anal_block: %u\n", seed);
	return all_tests();
}
