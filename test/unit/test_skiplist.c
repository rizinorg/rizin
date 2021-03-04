// SPDX-FileCopyrightText: 2017 Lowly Worm <cutlassc91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_skiplist.h>
#include "minunit.h"

int cmp_int(int a, int b) {
	return (a > b) - (a < b);
}

bool test_empty(void) {
	RzSkipList *list = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	RzSkipListNode *it;
	void *data;

	rz_skiplist_foreach (list, it, data) {
		mu_fail("there shouldn't be any element in the list");
	}
	mu_assert_eq(rz_skiplist_length(list), 0, "No element in the list");
	rz_skiplist_free(list);
	mu_end;
}

bool test_oneelement(void) {
	RzSkipList *list = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	RzSkipListNode *it;
	void *data;

	rz_skiplist_insert(list, (void *)(intptr_t)(3));
	rz_skiplist_foreach (list, it, data) {
		if ((int)(intptr_t)data != 3) {
			mu_fail("there shouldn't be any element apart from 3");
		}
	}
	mu_assert_eq(rz_skiplist_length(list), 1, "Only one element in the list");
	rz_skiplist_free(list);
	mu_end;
}

bool test_insert(void) {
	int i;
	RzSkipList *list = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	RzSkipListNode *n;
	// Add 100 items.
	for (i = 0; i < 100; i++) {
		rz_skiplist_insert(list, (void *)(intptr_t)i);
	}

	n = rz_skiplist_find(list, (void *)(intptr_t)33);
	mu_assert_notnull(n, "33 should be in the list");
	mu_assert_eq((int)(intptr_t)n->data, 33, "33 should be the data");
	n = rz_skiplist_find(list, (void *)(intptr_t)50);
	mu_assert_notnull(n, "50 should be in the list");
	mu_assert_eq((int)(intptr_t)n->data, 50, "50 should be the data");
	// check first element
	n = rz_skiplist_find(list, (void *)(intptr_t)0);
	mu_assert_notnull(n, "0 should be in the list");
	mu_assert_eq((int)(intptr_t)n->data, 0, "0 should be the data");
	// check last element
	n = rz_skiplist_find(list, (void *)(intptr_t)99);
	mu_assert_notnull(n, "99 should be in the list");
	mu_assert_eq((int)(intptr_t)n->data, 99, "99 should be the data");
	mu_assert_eq(rz_skiplist_length(list), 100, "Four elements in the list");

	// check non existing items
	n = rz_skiplist_find(list, (void *)(intptr_t)150);
	mu_assert_null(n, "150 shouldn't be in the list");
	n = rz_skiplist_find(list, (void *)(intptr_t)(-10));
	mu_assert_null(n, "-10 shouldn't be in the list");

	rz_skiplist_free(list);
	mu_end;
}

bool test_insert_existing(void) {
	RzSkipList *list = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	int i;
	// Add 100 items.
	for (i = 0; i < 100; i++) {
		rz_skiplist_insert(list, (void *)(intptr_t)i);
	}

	mu_assert_eq(rz_skiplist_length(list), 100, "list should contain 100 elements");
	// try to insert again the element 0
	rz_skiplist_insert(list, (void *)(intptr_t)0);
	mu_assert_eq(rz_skiplist_length(list), 100, "list should still contain 100 elements");
	// try to insert again the element 50
	rz_skiplist_insert(list, (void *)(intptr_t)50);
	mu_assert_eq(rz_skiplist_length(list), 100, "list should still contain 100 elements");
	// try to insert again the element 99
	rz_skiplist_insert(list, (void *)(intptr_t)99);
	mu_assert_eq(rz_skiplist_length(list), 100, "list should still contain 100 elements");

	rz_skiplist_free(list);
	mu_end;
}

bool test_purge(void) {
	RzSkipList *list = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	rz_skiplist_insert(list, (void *)(intptr_t)3);
	rz_skiplist_insert(list, (void *)(intptr_t)1);
	rz_skiplist_insert(list, (void *)(intptr_t)30);
	rz_skiplist_insert(list, (void *)(intptr_t)40);
	mu_assert_eq(rz_skiplist_length(list), 4, "the list should contain four elements");
	rz_skiplist_purge(list);
	mu_assert_eq(rz_skiplist_length(list), 0, "the list should be empty at this point");
	rz_skiplist_insert(list, (void *)(intptr_t)4);
	rz_skiplist_insert(list, (void *)(intptr_t)2);
	mu_assert_eq(rz_skiplist_length(list), 2, "the list should contain two new elements");
	rz_skiplist_free(list);
	mu_end;
}

bool test_delete(void) {
	RzSkipList *list = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	rz_skiplist_insert(list, (void *)(intptr_t)3);
	rz_skiplist_insert(list, (void *)(intptr_t)1);
	rz_skiplist_insert(list, (void *)(intptr_t)30);
	rz_skiplist_insert(list, (void *)(intptr_t)40);

	// remove an element in the middle of the list
	rz_skiplist_delete(list, (void *)(intptr_t)3);
	mu_assert_eq(rz_skiplist_length(list), 3, "element 3 should be deleted");
	// remove last element of the list
	rz_skiplist_delete(list, (void *)(intptr_t)40);
	mu_assert_eq(rz_skiplist_length(list), 2, "element 40 should be deleted");
	// remove first element of the list
	rz_skiplist_delete(list, (void *)(intptr_t)1);
	mu_assert_eq(rz_skiplist_length(list), 1, "element 1 should be deleted");

	rz_skiplist_insert(list, (void *)(intptr_t)50);
	mu_assert_eq(rz_skiplist_length(list), 2, "element 50 should be inserted after deleting other elements");

	// remove non existing element
	rz_skiplist_delete(list, (void *)(intptr_t)200);
	mu_assert_eq(rz_skiplist_length(list), 2, "no element should be deleted");

	rz_skiplist_free(list);
	mu_end;
}

bool test_join(void) {
	RzSkipList *l1 = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	rz_skiplist_insert(l1, (void *)(intptr_t)3);
	rz_skiplist_insert(l1, (void *)(intptr_t)1);
	rz_skiplist_insert(l1, (void *)(intptr_t)30);
	rz_skiplist_insert(l1, (void *)(intptr_t)40);

	RzSkipList *l2 = rz_skiplist_new(NULL, (RzListComparator)cmp_int);
	rz_skiplist_insert(l2, (void *)(intptr_t)10);
	rz_skiplist_insert(l2, (void *)(intptr_t)4);
	rz_skiplist_insert(l2, (void *)(intptr_t)1);

	rz_skiplist_join(l1, l2);
	mu_assert("10 is in l1", rz_skiplist_find(l1, (void *)(intptr_t)10));
	mu_assert("4 is in l1", rz_skiplist_find(l1, (void *)(intptr_t)4));
	mu_assert("1 is in l1", rz_skiplist_find(l1, (void *)(intptr_t)1));
	mu_assert("3 is still in l1", rz_skiplist_find(l1, (void *)(intptr_t)3));
	mu_assert_eq(rz_skiplist_length(l1), 6, "no double elements when joining");

	rz_skiplist_free(l1);
	rz_skiplist_free(l2);
	mu_end;
}

int all_tests() {
	mu_run_test(test_empty);
	mu_run_test(test_oneelement);
	mu_run_test(test_insert);
	mu_run_test(test_insert_existing);
	mu_run_test(test_purge);
	mu_run_test(test_delete);
	mu_run_test(test_join);
	return tests_passed != tests_run;
}

mu_main(all_tests)