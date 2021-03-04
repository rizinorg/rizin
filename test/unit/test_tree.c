// SPDX-FileCopyrightText: 2016 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

void sum_node(RTreeNode *n, RTreeVisitor *vis) {
	int cur = (int)(intptr_t)vis->data;
	vis->data = (void *)(intptr_t)(cur + (int)(intptr_t)n->data);
}

void add_to_list(RTreeNode *n, RTreeVisitor *vis) {
	RzList *res = (RzList *)vis->data;
	rz_list_append(res, n->data);
}

#define check_list(act, exp, descr) \
	do { \
		RzListIter *ita = rz_list_iterator(act); \
		RzListIter *ite = rz_list_iterator(exp); \
		while (rz_list_iter_next(ita) && rz_list_iter_next(ite)) { \
			int a = (int)(intptr_t)rz_list_iter_get(ita); \
			int e = (int)(intptr_t)rz_list_iter_get(ite); \
			mu_assert_eq(a, e, descr); \
		} \
		mu_assert("lists must have same elements", (!ita && !ite)); \
	} while (0)

#define check_str_list(act, exp, descr) \
	do { \
		RzListIter *ita = rz_list_iterator(act); \
		RzListIter *ite = rz_list_iterator(exp); \
		while (rz_list_iter_next(ita) && rz_list_iter_next(ite)) { \
			char *a = rz_list_iter_get(ita); \
			char *e = rz_list_iter_get(ite); \
			mu_assert_streq(a, e, descr); \
		} \
		mu_assert("lists must have same elements", (!ita && !ite)); \
	} while (0)

bool test_rz_tree() {
	RTreeVisitor calc = { 0 };
	RTreeVisitor lister = { 0 };
	RTree *t = rz_tree_new();

	calc.pre_visit = (RTreeNodeVisitCb)sum_node;
	calc.data = (void *)0;

	rz_tree_add_node(t, NULL, (void *)1);
	rz_tree_bfs(t, &calc);
	mu_assert_eq(1, (int)(intptr_t)calc.data, "calc.data.root");

	rz_tree_add_node(t, t->root, (void *)2);
	RTreeNode *s = rz_tree_add_node(t, t->root, (void *)3);
	RTreeNode *u = rz_tree_add_node(t, t->root, (void *)4);
	calc.data = (void *)0;
	rz_tree_bfs(t, &calc);
	mu_assert_eq(10, (int)(intptr_t)calc.data, "calc.data.childs");

	rz_tree_add_node(t, s, (void *)5);
	rz_tree_add_node(t, s, (void *)10);
	rz_tree_add_node(t, u, (void *)11);
	lister.pre_visit = (RTreeNodeVisitCb)add_to_list;

	RzList *exp1 = rz_list_new();
	rz_list_append(exp1, (void *)1);
	rz_list_append(exp1, (void *)2);
	rz_list_append(exp1, (void *)3);
	rz_list_append(exp1, (void *)4);
	rz_list_append(exp1, (void *)5);
	rz_list_append(exp1, (void *)10);
	rz_list_append(exp1, (void *)11);
	lister.data = rz_list_new();
	rz_tree_bfs(t, &lister);
	check_list((RzList *)lister.data, exp1, "lister.bfs");
	rz_list_free(exp1);
	rz_list_free((RzList *)lister.data);

	RzList *exp2 = rz_list_new();
	rz_list_append(exp2, (void *)1);
	rz_list_append(exp2, (void *)2);
	rz_list_append(exp2, (void *)3);
	rz_list_append(exp2, (void *)5);
	rz_list_append(exp2, (void *)10);
	rz_list_append(exp2, (void *)4);
	rz_list_append(exp2, (void *)11);
	lister.data = rz_list_new();
	rz_tree_dfs(t, &lister);
	check_list((RzList *)lister.data, exp2, "lister.preorder");
	rz_list_free(exp2);
	rz_list_free((RzList *)lister.data);

	rz_tree_reset(t);
	RTreeNode *root = rz_tree_add_node(t, NULL, "root");
	RTreeNode *first = rz_tree_add_node(t, root, "first");
	rz_tree_add_node(t, root, "second");
	rz_tree_add_node(t, root, "third");
	rz_tree_add_node(t, first, "f_first");
	rz_tree_add_node(t, first, "f_second");

	RzList *exp3 = rz_list_new();
	rz_list_append(exp3, "root");
	rz_list_append(exp3, "first");
	rz_list_append(exp3, "f_first");
	rz_list_append(exp3, "f_second");
	rz_list_append(exp3, "second");
	rz_list_append(exp3, "third");
	lister.data = rz_list_new();
	rz_tree_dfs(t, &lister);
	check_str_list((RzList *)lister.data, exp3, "lister.reset.preorder");
	rz_list_free(exp3);
	rz_list_free((RzList *)lister.data);

	rz_tree_free(t);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_tree);
	return tests_passed != tests_run;
}

mu_main(all_tests)