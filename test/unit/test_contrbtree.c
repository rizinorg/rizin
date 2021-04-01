// SPDX-FileCopyrightText: 2019 condret
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include "minunit.h"

static int simple_cmp(void *incoming, void *in, void *user) {
	ut32 v[2] = { (ut32)(size_t)incoming, (ut32)(size_t)in };
	return v[0] - v[1];
}

bool test_rz_rbtree_cont_foreach_empty() {
	RContRBTree *tree = rz_rbtree_cont_new();
	RBIter alf;
	void *v;
	rz_rbtree_cont_foreach(tree, alf, v) {
		mu_assert("not reachable", false);
	}
	rz_rbtree_cont_free(tree);
	mu_end;
}

bool test_rz_rbtree_cont_insert() {
	RContRBTree *tree = rz_rbtree_cont_new();
	ut32 i;
	for (i = 0; i < 2000; i++) {
		ut32 v = (ut32)rz_num_rand(UT32_MAX >> 1);
		rz_rbtree_cont_insert(tree, (void *)(size_t)v, simple_cmp, NULL);
	}
	i = 0;
	bool ret = true;
	void *v;
	RBIter ator;
	rz_rbtree_cont_foreach(tree, ator, v) {
		const ut32 next = (ut32)(size_t)v;
		ret &= (i <= next);
		i = next;
	}
	rz_rbtree_cont_free(tree);
	mu_assert("rbtree_cont_insert", ret);
	mu_end;
}

static int strbuf_num_cmp0(void *incoming, void *in, void *user) {
	ut64 v[2] = {
		rz_num_get(NULL, rz_strbuf_get((RzStrBuf *)incoming)),
		rz_num_get(NULL, rz_strbuf_get((RzStrBuf *)in))
	};
	return (int)(v[0] - v[1]);
}

static int strbuf_num_cmp1(void *incoming, void *in, void *user) {
	ut64 v[2] = { ((ut64 *)incoming)[0], rz_num_get(NULL, rz_strbuf_get((RzStrBuf *)in)) };
	return (int)(v[0] - v[1]);
}

bool test_rz_rbtree_cont_delete() {
	RContRBTree *tree = rz_rbtree_cont_newf((RContRBFree)rz_strbuf_free);
	rz_rbtree_cont_insert(tree, rz_strbuf_new("13"), strbuf_num_cmp0, NULL);
	rz_rbtree_cont_insert(tree, rz_strbuf_new("0x9090"), strbuf_num_cmp0, NULL);
	rz_rbtree_cont_insert(tree, rz_strbuf_new("42"), strbuf_num_cmp0, NULL);
	rz_rbtree_cont_insert(tree, rz_strbuf_new("23"), strbuf_num_cmp0, NULL);
	rz_rbtree_cont_insert(tree, rz_strbuf_new("0x13373"), strbuf_num_cmp0, NULL);
	ut64 del_me = 0x9090;
	rz_rbtree_cont_delete(tree, &del_me, strbuf_num_cmp1, NULL);
	RzStrBuf *s;
	RBIter ator;
	bool ret = true;
	rz_rbtree_cont_foreach_prev(tree, ator, s) {
		const ut64 v = rz_num_get(NULL, rz_strbuf_get(s));
		ret &= (v != 0x9090);
	}
	rz_rbtree_cont_free(tree);
	mu_assert("rbtree_cont_delete", ret);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_rbtree_cont_insert);
	mu_run_test(test_rz_rbtree_cont_delete);
	mu_run_test(test_rz_rbtree_cont_foreach_empty);
	return tests_run != tests_passed;
}

mu_main(all_tests)
