// SPDX-FileCopyrightText: 2015 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_util/ht_up.h>
#include "minunit.h"
#define BUF_LENGTH 100

bool test_rz_list_size(void) {
	// Test that rz_list adding and deleting works correctly.
	int i;
	RzList *list = rz_list_new();
	intptr_t test = 0x101010;
	// Add 100 items.
	for (i = 0; i < 100; i++) {
		rz_list_append(list, (void *)test);
		mu_assert_eq(rz_list_length(list), i + 1, "rz_list_length failed on append");
	}
	// Delete 50 of them.
	for (i = 0; i < 50; i++) {
		(void)rz_list_pop(list);
		mu_assert_eq(99 - i, rz_list_length(list), "rz_list_length failed on pop");
	}
	// Purge the list.
	rz_list_purge(list);
	mu_assert_eq(0, rz_list_length(list), "rz_list_length failed on purged list");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_values(void) {
	RzList *list = rz_list_new();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	rz_list_append(list, (void *)test1);
	rz_list_append(list, (void *)test2);
	int top1 = (intptr_t)rz_list_pop(list);
	int top2 = (intptr_t)rz_list_pop(list);
	mu_assert_eq(top1, 0x88888, "first value not 0x88888");
	mu_assert_eq(top2, 0x12345, "first value not 0x12345");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_join(void) {
	RzList *list1 = rz_list_new();
	RzList *list2 = rz_list_new();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	rz_list_append(list1, (void *)test1);
	rz_list_append(list2, (void *)test2);
	int joined = rz_list_join(list1, list2);
	mu_assert_eq(joined, 1, "rz_list_join of two lists");
	mu_assert_eq(rz_list_length(list1), 2, "rz_list_join two single element lists result length is 1");
	rz_list_free(list1);
	rz_list_free(list2);
	mu_end;
}

bool test_rz_list_free(void) {
	RzList *list = rz_list_newf((void *)0x9999);
	mu_assert_eq((int)(intptr_t)list->free, 0x9999, "rz_list_newf function gets set properly");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_del_n(void) {
	RzList *list = rz_list_new();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	rz_list_append(list, (void *)test1);
	rz_list_append(list, (void *)test2);
	mu_assert_eq(rz_list_length(list), 2,
		"list is of length 2 when adding 2 values");
	rz_list_del_n(list, 0);
	int top1 = (intptr_t)rz_list_pop(list);
	mu_assert_eq(top1, 0x88888,
		"error, first value not 0x88888");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_sort(void) {
	RzList *list = rz_list_new();
	char *test1 = "AAAA";
	char *test2 = "BBBB";
	char *test3 = "CCCC";
	// Put in not sorted order.
	rz_list_append(list, (void *)test1);
	rz_list_append(list, (void *)test3);
	rz_list_append(list, (void *)test2);
	// Sort.
	rz_list_sort(list, (RzListComparator)strcmp, NULL);
	// Check that the list is actually sorted.
	mu_assert_streq((char *)list->head->elem, "AAAA", "first value in sorted list");
	mu_assert_streq((char *)list->head->next->elem, "BBBB", "second value in sorted list");
	mu_assert_streq((char *)list->head->next->next->elem, "CCCC", "third value in sorted list");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_sort2(void) {
	RzList *list = rz_list_new();
	char *test1 = "AAAA";
	char *test2 = "BBBB";
	char *test3 = "CCCC";
	// Put in not sorted order.
	rz_list_append(list, (void *)test3);
	rz_list_append(list, (void *)test2);
	rz_list_append(list, (void *)test1);
	// Sort.
	rz_list_merge_sort(list, (RzListComparator)strcmp, NULL);
	// Check that the list is actually sorted.
	mu_assert_streq((char *)list->head->elem, "AAAA", "first value in sorted list");
	mu_assert_streq((char *)list->head->next->elem, "BBBB", "second value in sorted list");
	mu_assert_streq((char *)list->head->next->next->elem, "CCCC", "third value in sorted list");
	rz_list_free(list);
	mu_end;
}

static int cmp_range(const void *a, const void *b) {
	int ra = *(int *)a;
	int rb = *(int *)b;
	return ra - rb;
}

bool test_rz_list_sort3(void) {
	RzList *list = rz_list_new();
	int test1 = 33508;
	int test2 = 33480;
	int test3 = 33964;
	// Put in not sorted order.
	rz_list_append(list, (void *)&test1);
	rz_list_append(list, (void *)&test3);
	rz_list_append(list, (void *)&test2);
	// Sort.
	rz_list_merge_sort(list, (RzListComparator)cmp_range, NULL);
	// Check that the list is actually sorted.
	mu_assert_eq(*(int *)list->head->elem, 33480, "first value in sorted list");
	mu_assert_eq(*(int *)list->head->next->elem, 33508, "second value in sorted list");
	mu_assert_eq(*(int *)list->head->next->next->elem, 33964, "third value in sorted list");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_length(void) {
	RzList *list = rz_list_new();
	RzList *list2 = rz_list_new();
	RzListIter *iter;
	int count = 0;
	int test1 = 33508;
	int test2 = 33480;
	int test3 = 33964;
	// Put in not sorted order.
	rz_list_append(list, (void *)&test1);
	rz_list_append(list, (void *)&test3);
	rz_list_append(list, (void *)&test2);
	iter = list->head;
	while (iter) {
		count++;
		iter = iter->next;
	}
	mu_assert_eq(list->length, 3, "First length check");

	rz_list_delete_data(list, (void *)&test1);
	mu_assert_eq(list->length, 2, "Second length check");

	rz_list_append(list, (void *)&test1);
	mu_assert_eq(list->length, 3, "Third length check");

	rz_list_pop(list);
	mu_assert_eq(list->length, 2, "Fourth length check");

	rz_list_pop_head(list);
	mu_assert_eq(list->length, 1, "Fifth length check");

	rz_list_insert(list, 2, (void *)&test2);
	mu_assert_eq(list->length, 2, "Sixth length check");

	rz_list_prepend(list, (void *)&test3);
	mu_assert_eq(list->length, 3, "Seventh length check");

	rz_list_del_n(list, 2);
	mu_assert_eq(list->length, 2, "Eighth length check");

	rz_list_append(list2, (void *)&test1);
	rz_list_append(list2, (void *)&test3);
	rz_list_append(list2, (void *)&test2);
	rz_list_join(list, list2);
	mu_assert_eq(list->length, 5, "Ninth length check");
	iter = list->head;
	count = 0;
	while (iter) {
		count++;
		iter = iter->next;
	}
	mu_assert_eq(list->length, count, "Tenth length check");
	rz_list_free(list);
	rz_list_free(list2);
	mu_end;
}

bool test_rz_list_sort5(void) {
	RzList *list = rz_list_new();
	int i = 0;
	char *upper[] = { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" };
	char *lower[] = { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" };
	for (i = 0; i < 26; i++) {
		rz_list_append(list, (void *)lower[i]);
	}
	for (i = 0; i < 26; i++) {
		rz_list_append(list, (void *)upper[i]);
	}
	// add more than 43 elements to trigger merge sort
	rz_list_sort(list, (RzListComparator)strcmp, NULL);
	mu_assert_streq((char *)list->head->elem, upper[0], "First element");
	mu_assert_streq((char *)list->tail->elem, lower[25], "Last element");
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_from_iter(void) {
	HtUP *alpha_ht = ht_up_new(NULL, NULL);
	char *unordered_alphabeth[] = { "b", "w", "k", "a", "c", "d", "e", "f", "g", "h", "i", "j", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "x", "y", "z" };
	char *lower[] = { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" };

	for (size_t i = 0; i < 26; i++) {
		ht_up_insert(alpha_ht, i, (void *)unordered_alphabeth[i]);
	}
	RzIterator *iter = ht_up_as_iter(alpha_ht);
	RzList *list = rz_list_new_from_iterator(iter);
	rz_list_sort(list, (RzListComparator)strcmp, NULL);
	mu_assert_eq(rz_list_length(list), 26, "Number of elements are off");
	RzListIter *it;
	const char *elem;
	size_t i = 0;
	rz_list_foreach_enum(list, it, elem, i) {
		mu_assert_streq(elem, lower[i], "Value mismatched.");
	}
	ht_up_free(alpha_ht);
	rz_iterator_free(iter);
	rz_list_free(list);
	mu_end;
}

// 3-valued comparator -> {LT,EQ,GT}.
static int pintcmp(int *a, int *b, void *user) {
	return (int)(*a > *b) - (int)(*b > *a);
}

bool test_rz_list_mergesort_pint() {
	// 47 items
	int data[] = { -440, -468, -444, -80, -568, -564, -396, -404, -436, -420,
		-428, -388, -356, -324, -292, -464, -260, -252, -204, -196, -212, -76,
		-160, -540, -216, -536, -532, -148, -116, -560, -556, -244, -460, -448,
		-236, -156, -228, -456, -552, -548, -544, -220, -180, -188, -84, -172,
		-164 };
	int expected[] = { -568, -564, -560, -556, -552, -548, -544, -540, -536,
		-532, -468, -464, -460, -456, -448, -444, -440, -436, -428, -420, -404,
		-396, -388, -356, -324, -292, -260, -252, -244, -236, -228, -220, -216,
		-212, -204, -196, -188, -180, -172, -164, -160, -156, -148, -116, -84,
		-80, -76 };

	RzList *list = rz_list_new();
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(data); i++) {
		rz_list_append(list, (void *)&data[i]);
	}

	// invoke sorting
	rz_list_sort(list, (RzListComparator)pintcmp, NULL);

	// assert the list is sorted as expected
	RzListIter *iter;
	for (i = 0, iter = list->head; i < RZ_ARRAY_SIZE(expected); i++, iter = iter->next) {
		mu_assert_eq(*(int *)iter->elem, expected[i], "array content mismatch");
	}

	rz_list_free(list);
	mu_end;
}

bool test_rz_list_sort4(void) {
	RzList *list = rz_list_new();
	char *test1 = "AAAA";
	char *test2 = "BBBB";
	char *test3 = "CCCC";
	char *test4 = "DDDD";
	char *test5 = "EEEE";
	char *test6_later = "FFFF";
	char *test7 = "GGGG";
	char *test8 = "HHHH";
	char *test9 = "IIII";
	char *test10 = "JJJJ";
	char *ins_tests_odd[] = { test10, test1, test3, test7, test5, test9, test2,
		test4, test8 };
	char *exp_tests_odd[] = { test1, test2, test3, test4, test5, test7,
		test8, test9, test10 };
	int i;

	// Put in not sorted order.
	for (i = 0; i < RZ_ARRAY_SIZE(ins_tests_odd); ++i) {
		rz_list_append(list, (void *)ins_tests_odd[i]);
	}
	// Sort.
	rz_list_merge_sort(list, (RzListComparator)strcmp, NULL);

	// Check that the list (odd-length) is actually sorted.
	RzListIter *next = list->head;
	for (i = 0; i < RZ_ARRAY_SIZE(exp_tests_odd); ++i) {
		char buf[BUF_LENGTH];
		snprintf(buf, BUF_LENGTH, "%d-th value in sorted list", i);
		mu_assert_streq((char *)next->elem, exp_tests_odd[i], buf);
		next = next->next;
	}

#if 0 // Debug Print
	char *data;

	printf("after sorted 1 \n");
	rz_list_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
#endif

	char *exp_tests_even[] = { test1, test2, test3, test4, test5,
		test6_later, test7, test8, test9, test10 };
	// Add test6 to make the length even
	rz_list_append(list, (void *)test6_later);

#if 0 // Debug Printing
	printf("after adding FFFF \n");
	rz_list_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
#endif

	// Sort
	rz_list_merge_sort(list, (RzListComparator)strcmp, NULL);

#if 0 // Debug Printing
	printf("after sorting 2 \n");
	rz_list_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
#endif

	// Check that the list (even-length) is actually sorted.
	next = list->head;
	for (i = 0; i < RZ_ARRAY_SIZE(exp_tests_even); ++i) {
		char buf[BUF_LENGTH];
		snprintf(buf, BUF_LENGTH, "%d-th value in sorted list", i);
		mu_assert_streq((char *)next->elem, exp_tests_even[i], buf);
		next = next->next;
	}
	rz_list_free(list);
	mu_end;
}

bool test_rz_list_append_prepend(void) {

	char *test[] = {
		"HEAD 00",
		"HEAD",
		"foo",
		"bar",
		"cow",
		"LAST"
	};

	RzList *list = rz_list_new();
	RzListIter *iter;

	rz_list_append(list, test[2]);
	rz_list_append(list, test[3]);
	rz_list_append(list, test[4]);
	rz_list_prepend(list, test[1]);
	rz_list_prepend(list, test[0]);
	rz_list_append(list, test[5]);

	char buf[BUF_LENGTH];
	int i;
	// Check that the next sequence is correct
	iter = list->head;
	for (i = 0; i < RZ_ARRAY_SIZE(test); ++i) {
		snprintf(buf, BUF_LENGTH, "%d-th value in list from head", i);
		mu_assert_streq((char *)iter->elem, test[i], buf);
		iter = iter->next;
	}

	// Check that the previous sequence is correct
	iter = list->tail;
	for (i = (RZ_ARRAY_SIZE(test)) - 1; i > 0; --i) {
		snprintf(buf, BUF_LENGTH, "%d-th value in list from tail", i);
		mu_assert_streq((char *)iter->elem, test[i], buf);
		iter = iter->prev;
	}

	rz_list_free(list);
	mu_end;
}

bool test_rz_list_set_get(void) {

	char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

	RzList *list = rz_list_new();

	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(test); ++i) {
		rz_list_append(list, test[i]);
	}

	char *str;
	rz_list_set_n(list, 2, "CC");
	str = (char *)rz_list_get_n(list, 2);
	mu_assert_streq(str, "CC", "value after set");

	rz_list_prepend(list, "AA0");
	str = (char *)rz_list_get_n(list, 3);
	mu_assert_streq(str, "CC", "value after prepend");

	bool s;
	s = rz_list_set_n(list, 100, "ZZZZ");
	mu_assert_eq(s, false, "set out of bound");
	s = rz_list_get_n(list, 100);
	mu_assert_eq(s, false, "get out of bound");

	rz_list_free(list);
	mu_end;
}

bool test_rz_list_reverse(void) {

	char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

	RzList *list = rz_list_new();

	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(test); ++i) {
		rz_list_prepend(list, test[i]);
	}

	rz_list_reverse(list);

	char buf[BUF_LENGTH];
	// Check that the sequence is correct
	RzListIter *iter = list->head;
	for (i = 0; i < RZ_ARRAY_SIZE(test); ++i) {
		snprintf(buf, BUF_LENGTH, "%d-th value in list after reverse", i);
		mu_assert_streq((char *)iter->elem, test[i], buf);
		iter = iter->next;
	}

	rz_list_free(list);
	mu_end;
}

bool test_rz_list_clone(void) {

	char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

	RzList *list1 = rz_list_new();
	RzList *list2;

	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(test); ++i) {
		rz_list_prepend(list1, test[i]);
	}

	list2 = rz_list_clone(list1);

	char buf[BUF_LENGTH];
	RzListIter *iter1 = list1->head;
	RzListIter *iter2 = list2->head;
	for (i = 0; i < RZ_ARRAY_SIZE(test); ++i) {
		snprintf(buf, BUF_LENGTH, "%d-th value after clone", i);
		mu_assert_streq((char *)iter2->elem, (char *)iter1->elem, buf);
		iter1 = iter1->next;
		iter2 = iter2->next;
	}

	rz_list_free(list1);
	rz_list_free(list2);
	mu_end;
}

bool test_rz_list_find_ptr(void) {
	RzList *l = rz_list_new();
	rz_list_push(l, (void *)42);
	rz_list_push(l, (void *)1337);
	rz_list_push(l, (void *)42);

	RzListIter *it = rz_list_find_ptr(l, (void *)42);
	mu_assert_notnull(it, "find_ptr");
	mu_assert_ptreq(it, rz_list_head(l), "find_ptr");

	RzListIter *expect = rz_list_iter_get_next(it);
	mu_assert_notnull(it, "expect next");
	it = rz_list_find_ptr(l, (void *)1337);
	mu_assert_notnull(it, "find_ptr");
	mu_assert_ptreq(it, expect, "find_ptr");

	it = rz_list_find_ptr(l, (void *)123);
	mu_assert_null(it, "find_ptr");

	rz_list_free(l);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_list_size);
	mu_run_test(test_rz_list_values);
	mu_run_test(test_rz_list_join);
	mu_run_test(test_rz_list_free);
	mu_run_test(test_rz_list_del_n);
	mu_run_test(test_rz_list_sort);
	mu_run_test(test_rz_list_sort2);
	mu_run_test(test_rz_list_sort3);
	mu_run_test(test_rz_list_sort4);
	mu_run_test(test_rz_list_sort5);
	mu_run_test(test_rz_list_mergesort_pint);
	mu_run_test(test_rz_list_length);
	mu_run_test(test_rz_list_append_prepend);
	mu_run_test(test_rz_list_set_get);
	mu_run_test(test_rz_list_reverse);
	mu_run_test(test_rz_list_clone);
	mu_run_test(test_rz_list_find_ptr);
	mu_run_test(test_rz_list_from_iter);
	return tests_passed != tests_run;
}

mu_main(all_tests)
