// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <sdb.h>
#include "minunit.h"
#define BUF_LENGTH 100

#define R_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

bool test_r_list_size(void) {
	// Test that r_list adding and deleting works correctly.
	int i;
	SdbList *list = ls_new();
	intptr_t test = 0x101010;
	// Add 100 items.
	for (i = 0; i < 100; ++i) {
		ls_append(list, (void *)test);
		mu_assert_eq((int)ls_length(list), i + 1, "ls_length failed on append");
	}
	// Delete 50 of them.
	for (i = 0; i < 50; ++i) {
		(void)ls_pop(list);
		mu_assert_eq(99 - i, (int)ls_length(list), "ls_length failed on pop");
	}
	// Purge the list.
	ls_destroy(list);
	mu_assert_eq(0, (int)ls_length(list), "ls_length failed on purged list");
	ls_free(list);
	mu_end;
}

bool test_r_list_values(void) {
	SdbList *list = ls_new();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	ls_append(list, (void *)test1);
	ls_append(list, (void *)test2);
	int top1 = (intptr_t)ls_pop(list);
	int top2 = (intptr_t)ls_pop(list);
	mu_assert_eq(top1, 0x88888, "first value not 0x88888");
	mu_assert_eq(top2, 0x12345, "first value not 0x12345");
	ls_free(list);
	mu_end;
}

bool test_ls_join(void) {
	SdbList *list1 = ls_new();
	SdbList *list2 = ls_new();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	ls_append(list1, (void *)test1);
	ls_append(list2, (void *)test2);
	int joined = ls_join(list1, list2);
	mu_assert_eq(joined, 1, "ls_join of two lists");
	mu_assert_eq((int)ls_length(list1), 2, "ls_join two single element lists result length is 1");
	ls_free(list1);
	ls_free(list2);
	mu_end;
}

bool test_ls_free(void) {
	SdbList *list = ls_newf((void *)0x9999);
	mu_assert_eq((int)(intptr_t)list->free, 0x9999, "ls_newf function gets set properly");
	ls_free(list);
	mu_end;
}

bool test_ls_del_n(void) {
	SdbList *list = ls_new();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	ls_append(list, (void *)test1);
	ls_append(list, (void *)test2);
	mu_assert_eq((int)ls_length(list), 2,
		"list is of length 2 when adding 2 values");
	ls_del_n(list, 0);
	int top1 = (intptr_t)ls_pop(list);
	mu_assert_eq(top1, 0x88888,
		"error, first value not 0x88888");
	ls_free(list);
	mu_end;
}

bool test_r_list_sort(void) {
	SdbList *list = ls_new();
	char *test1 = "AAAA";
	char *test2 = "BBBB";
	char *test3 = "CCCC";
	// Put in not sorted order.
	ls_append(list, (void *)test1);
	ls_append(list, (void *)test3);
	ls_append(list, (void *)test2);
	// Sort.
	ls_sort(list, (SdbListComparator)strcmp);
	// Check that the list is actually sorted.
	mu_assert_streq((char *)list->head->data, "AAAA", "first value in sorted list");
	mu_assert_streq((char *)list->head->n->data, "BBBB", "second value in sorted list");
	mu_assert_streq((char *)list->head->n->n->data, "CCCC", "third value in sorted list");
	ls_free(list);
	mu_end;
}

bool test_r_list_sort2(void) {
	SdbList *list = ls_new();
	char *test1 = "AAAA";
	char *test2 = "BBBB";
	char *test3 = "CCCC";
	// Put in not sorted order.
	ls_append(list, (void *)test3);
	ls_append(list, (void *)test2);
	ls_append(list, (void *)test1);
	// Sort.
	ls_merge_sort(list, (SdbListComparator)strcmp);
	// Check that the list is actually sorted.
	mu_assert_streq((char *)list->head->data, "AAAA", "first value in sorted list");
	mu_assert_streq((char *)list->head->n->data, "BBBB", "second value in sorted list");
	mu_assert_streq((char *)list->head->n->n->data, "CCCC", "third value in sorted list");
	ls_free(list);
	mu_end;
}

static int cmp_range(const void *a, const void *b) {
	int ra = *(int *)a;
	int rb = *(int *)b;
	return ra - rb;
}

bool test_r_list_sort3(void) {
	SdbList *list = ls_new();
	int test1 = 33508;
	int test2 = 33480;
	int test3 = 33964;
	// Put in not sorted order.
	ls_append(list, (void *)&test1);
	ls_append(list, (void *)&test3);
	ls_append(list, (void *)&test2);
	// Sort.
	ls_merge_sort(list, (SdbListComparator)cmp_range);
	// Check that the list is actually sorted.
	mu_assert_eq(*(int *)list->head->data, 33480, "first value in sorted list");
	mu_assert_eq(*(int *)list->head->n->data, 33508, "second value in sorted list");
	mu_assert_eq(*(int *)list->head->n->n->data, 33964, "third value in sorted list");
	ls_free(list);
	mu_end;
}

bool test_ls_length(void) {
	SdbList *list = ls_new();
	SdbList *list2 = ls_new();
	SdbListIter *iter;
	int count = 0;
	int test1 = 33508;
	int test2 = 33480;
	int test3 = 33964;
	// Put in not sorted order.
	ls_append(list, (void *)&test1);
	ls_append(list, (void *)&test3);
	ls_append(list, (void *)&test2);
	iter = list->head;
	while (iter) {
		count++;
		iter = iter->n;
	}
	mu_assert_eq((int)list->length, 3, "First length check");

	ls_delete_data(list, (void *)&test1);
	mu_assert_eq((int)list->length, 2, "Second length check");

	ls_append(list, (void *)&test1);
	mu_assert_eq((int)list->length, 3, "Third length check");

	ls_pop(list);
	mu_assert_eq((int)list->length, 2, "Fourth length check");

	ls_pop_head(list);
	mu_assert_eq((int)list->length, 1, "Fifth length check");

	ls_insert(list, 2, (void *)&test2);
	mu_assert_eq((int)list->length, 2, "Sixth length check");

	ls_prepend(list, (void *)&test3);
	mu_assert_eq((int)list->length, 3, "Seventh length check");

	ls_del_n(list, 2);
	mu_assert_eq((int)list->length, 2, "Eighth length check");

	ls_append(list2, (void *)&test1);
	ls_append(list2, (void *)&test3);
	ls_append(list2, (void *)&test2);
	ls_join(list, list2);
	mu_assert_eq((int)list->length, 5, "Ninth length check");
	iter = list->head;
	count = 0;
	while (iter) {
		count++;
		iter = iter->n;
	}
	mu_assert_eq((int)list->length, count, "Tenth length check");
	ls_free(list);
	ls_free(list2);
	mu_end;
}

bool test_r_list_sort5(void) {
	SdbList *list = ls_new();
	int i = 0;
	char *upper[] = { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" };
	char *lower[] = { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" };
	for (i = 0; i < 26; i++) {
		ls_append(list, (void *)lower[i]);
	}
	for (i = 0; i < 26; i++) {
		ls_append(list, (void *)upper[i]);
	}
	// add more than 43 elements to trigger merge sort
	ls_sort(list, (SdbListComparator)strcmp);
	mu_assert_streq((char *)list->head->data, upper[0], "First element");
	mu_assert_streq((char *)list->tail->data, lower[25], "Last element");
	ls_free(list);
	mu_end;
}

static int cmp_order(const void *a, const void *b) {
	int ra = *(int *)a;
	int rb = *(int *)b;
	return ra > rb;
}

bool test_r_list_sort6(void) {
	int values[] = {
		4640,
		5152,
		5664,
		6176,
		6688,
		7200,
		7712,
		32,
		544,
		1056,
		1568,
		2080,
		2592,
		3104,
		3616,
		4128,
		4640,
		5152,
		5664,
		6176,
		6688,
		7200,
		7712,
		8224,
		8273,
		8337,
		8356,
		8452,
		8577,
		8625,
		8641,
		8657,
		8673,
		8689,
		8736,
		9248,
		9760,
		10272,
		10784,
		11296,
		11808,
		12320,
		12832,
		13344,
		13856,
		14368,
		14880,
		15392,
		15904,
		16416,
		16928,
		17440,
		17952,
		18464,
		18976,
		19488,
		20000,
		20512,
		21024,
		21536,
		22048,
		22560,
		23072,
		23584,
		24096,
		24608,
		8768,
		9792,
		10816,
		11840,
		12864,
		13888,
		14912,
		15936,
		16960,
		17984,
		19008,
		20032,
		21056,
		22080,
		23104,
		24128,
		25152,
		26176,
		27200,
		28224,
		29248,
		30272,
		31296,
		32320,
		33344,
		34368,
		35392,
		36416,
		37440,
		38464,
		39488,
		40512,
		8832,
		10880,
		12928,
		14976,
		17024,
		19072,
		21120,
		23168,
		25216,
		27264,
		29312,
		31360,
		33408,
		35456,
		37504,
		39552,
	};
	int i;
	int a, b;
	SdbListIter *iter;
	SdbList *list = ls_new();

	for (i = 0; i < R_ARRAY_SIZE(values); i++) {
		ls_append(list, (void *)&values[i]);
	}

	ls_merge_sort(list, (SdbListComparator)cmp_order);

	a = *(int *)list->head->data;
	for (iter = list->head->n, i = 0; iter; iter = iter->n, i++) {
		b = *(int *)iter->data;
#if 0 // Debug print
		printf("Element %d : %d < %d\n", i+1, a, b);
#endif
		mu_assert("nth element not inferior or equal to next", a <= b);
		a = b;
	}
	ls_free(list);
	mu_end;
}

bool test_r_list_sort4(void) {
	SdbList *list = ls_new();
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
	for (i = 0; i < R_ARRAY_SIZE(ins_tests_odd); ++i) {
		ls_append(list, (void *)ins_tests_odd[i]);
	}
	// Sort.
	ls_merge_sort(list, (SdbListComparator)strcmp);

	// Check that the list (odd-length) is actually sorted.
	SdbListIter *next = list->head;
	for (i = 0; i < R_ARRAY_SIZE(exp_tests_odd); ++i) {
		char buf[BUF_LENGTH];
		snprintf(buf, BUF_LENGTH, "%d-th value in sorted list", i);
		mu_assert_streq((char *)next->data, exp_tests_odd[i], buf);
		next = next->n;
	}

	char *data;
	printf("after sorted 1 \n");
	ls_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}

	char *exp_tests_even[] = { test1, test2, test3, test4, test5,
		test6_later, test7, test8, test9, test10 };
	// Add test6 to make the length even
	ls_append(list, (void *)test6_later);
	printf("after adding FFFF \n");
	ls_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
	// Sort
	ls_merge_sort(list, (SdbListComparator)strcmp);
	printf("after sorting 2 \n");
	ls_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
	// Check that the list (even-length) is actually sorted.
	next = list->head;
	for (i = 0; i < R_ARRAY_SIZE(exp_tests_even); ++i) {
		char buf[BUF_LENGTH];
		snprintf(buf, BUF_LENGTH, "%d-th value in sorted list", i);
		mu_assert_streq((char *)next->data, exp_tests_even[i], buf);
		next = next->n;
	}
	ls_free(list);
	mu_end;
}

int all_tests() {
	mu_run_test(test_r_list_size);
	mu_run_test(test_r_list_values);
	mu_run_test(test_ls_join);
	mu_run_test(test_ls_free);
	mu_run_test(test_ls_del_n);
	mu_run_test(test_r_list_sort);
	mu_run_test(test_r_list_sort2);
	mu_run_test(test_r_list_sort3);
	mu_run_test(test_r_list_sort4);
	mu_run_test(test_r_list_sort5);
	mu_run_test(test_r_list_sort6);
	mu_run_test(test_ls_length);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
