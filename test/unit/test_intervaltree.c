// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_util.h>
#include "minunit.h"
#include <rz_windows.h> // For struct timeval

bool check_invariants(RzIntervalNode *node) {
	if (!node) {
		return true;
	}
	ut64 max = node->end;
	int i;
	for (i = 0; i < 2; i++) {
		if (!node->node.child[i]) {
			continue;
		}
		RzIntervalNode *child = container_of(node->node.child[i], RzIntervalNode, node);
		if (child->max_end > max) {
			max = child->max_end;
		}
		if (!check_invariants(child)) {
			return false;
		}

		if (i == 0) {
			mu_assert("left <= this", child->start <= node->start);
		} else {
			mu_assert("right >= this", child->start >= node->start);
		}
	}

	mu_assert_eq_fmt(node->max_end, max, "max_end invariant", "0x%" PFMT64x);
	return true;
}

bool test_rz_interval_tree_insert_at() {
	RzIntervalTree tree;
	rz_interval_tree_init(&tree, NULL);

	rz_interval_tree_insert(&tree, 1, 10, NULL);
	rz_interval_tree_insert(&tree, 4, 20, NULL);
	rz_interval_tree_insert(&tree, 5, 123, NULL);
	rz_interval_tree_insert(&tree, 6, 54, NULL);
	rz_interval_tree_insert(&tree, 4, 5, NULL);
	rz_interval_tree_insert(&tree, 3, 9, (void *)0x1337);
	rz_interval_tree_insert(&tree, 4, 11, NULL);
	rz_interval_tree_insert(&tree, 1, 42, NULL);

	if (!check_invariants(tree.root)) {
		return false;
	}

	RzIntervalNode *node = rz_interval_tree_node_at(&tree, 3);
	mu_assert_notnull(node, "at not null");
	mu_assert_ptreq(node->data, (void *)0x1337, "at node data");
	mu_assert_eq_fmt(node->start, (ut64)3, "at node start", "0x%" PFMT64x);
	mu_assert_eq_fmt(node->end, (ut64)9, "at node end", "0x%" PFMT64x);
	void *direct = rz_interval_tree_at(&tree, 3);
	mu_assert_ptreq(direct, (void *)0x1337, "at data");

	rz_interval_tree_fini(&tree);

	mu_end;
}

#define N       1000
#define SAMPLES 1000
#define MAXVAL  0x10000

typedef struct {
	ut64 start;
	ut64 end;

	// Tree algorithm that is being tested increases, cheap linear reference decreases
	// if in the end all counters are exactly 0, the test passes
	int counter;

	int freed;
} TestEntry;

static void random_entries(TestEntry entries[N]) {
	size_t i;
	for (i = 0; i < N; i++) {
		entries[i].start = rand() % MAXVAL;
		entries[i].end = entries[i].start + rand() % MAXVAL;
		entries[i].counter = 0;
		entries[i].freed = 0;
	}
}

static bool probe_cb(RzIntervalNode *node, void *user) {
	TestEntry *entry = node->data;
	entry->counter++;
	if (entry->start != node->start || entry->end != node->end) {
		entry->counter = -99999; // something went terribly wrong
	}
	return true;
}

static void free_cb(void *data) {
	TestEntry *entry = data;
	entry->freed++;
}

bool test_rz_interval_tree_in(bool end_inclusive, bool intervals) {
	RzIntervalTree tree;
	rz_interval_tree_init(&tree, NULL);

	TestEntry entries[N];
	random_entries(entries);

	size_t i;
	for (i = 0; i < N; i++) {
		rz_interval_tree_insert(&tree, entries[i].start, entries[i].end, entries + i);
	}

	if (!check_invariants(tree.root)) {
		return false;
	}

	for (i = 0; i < SAMPLES; i++) {
		ut64 start = rand() % (2 * MAXVAL);
		ut64 end = start + (intervals ? rand() % (2 * MAXVAL) : 0);
		if (intervals) {
			rz_interval_tree_all_intersect(&tree, start, end, end_inclusive, probe_cb, NULL);
		} else {
			rz_interval_tree_all_in(&tree, start, end_inclusive, probe_cb, NULL);
		}
		size_t j;
		for (j = 0; j < N; j++) {
			TestEntry *entry = entries + j;
			if (intervals
					? ((end_inclusive ? end < entry->start : end <= entry->start) || (end_inclusive ? start > entry->end : start >= entry->end))
					: (start < entry->start || (end_inclusive ? start > entry->end : start >= entry->end))) {
				continue;
			}
			entries[j].counter--;
		}
		for (j = 0; j < N; j++) {
			if (entries[j].counter) {
				printf("[%" PFMT64u "; %" PFMT64u "%c intersect ", entries[j].start, entries[j].end, end_inclusive ? ']' : '[');
				if (intervals) {
					printf("[%" PFMT64u "; %" PFMT64u "%c ", start, end, end_inclusive ? ']' : '[');
				} else {
					printf("%" PFMT64u, start);
				}
				printf(" => %d\n", entries[j].counter);
			}
			mu_assert_eq(entries[j].counter, 0, "counter 0 after reference check");
		}
	}

	rz_interval_tree_fini(&tree);
	return true;
}

#define TEST_IN(name, end_inclusive, intervals) \
	bool name() { \
		if (!test_rz_interval_tree_in(end_inclusive, intervals)) \
			return false; \
		mu_end; \
	}
TEST_IN(test_rz_interval_tree_in_end_exclusive_point, false, false)
TEST_IN(test_rz_interval_tree_in_end_inclusive_point, true, false)
TEST_IN(test_rz_interval_tree_in_end_exclusive_interval, false, true)
TEST_IN(test_rz_interval_tree_in_end_inclusive_interval, true, true)

bool test_rz_interval_tree_all_at() {
	RzIntervalTree tree;
	rz_interval_tree_init(&tree, NULL);
	TestEntry entries[N];
	random_entries(entries);
	size_t i;
	for (i = 0; i < N; i++) {
		rz_interval_tree_insert(&tree, entries[i].start, entries[i].end, entries + i);
	}

	if (!check_invariants(tree.root)) {
		return false;
	}

	for (i = 0; i < SAMPLES; i++) {
		ut64 start;
		if (i % 2 == 0) {
			start = entries[rand() % N].start;
		} else {
			start = rand() % MAXVAL;
		}
		rz_interval_tree_all_at(&tree, start, probe_cb, NULL);

		size_t j;
		for (j = 0; j < N; j++) {
			if (entries[j].start == start) {
				entries[j].counter--;
			}
			mu_assert_eq(entries[j].counter, 0, "counter 0 after reference check");
		}
	}

	rz_interval_tree_fini(&tree);
	mu_end;
}

bool test_rz_interval_tree_node_at_data() {
	RzIntervalTree tree;
	rz_interval_tree_init(&tree, NULL);
	TestEntry entries[N];
	random_entries(entries);
	size_t i;
	for (i = 0; i < N; i++) {
		rz_interval_tree_insert(&tree, entries[i].start, entries[i].end, entries + i);
	}
	if (!check_invariants(tree.root)) {
		return false;
	}
	for (i = 0; i < N; i++) {
		TestEntry *entry = entries + i;
		RzIntervalNode *node = rz_interval_tree_node_at_data(&tree, entry->start, entry);
		mu_assert_notnull(node, "node not null");
		mu_assert_ptreq(node->data, entry, "node at data contains correct data");
	}
	rz_interval_tree_fini(&tree);
	mu_end;
}

bool test_rz_interval_tree_delete() {
	RzIntervalTree tree;
	rz_interval_tree_init(&tree, free_cb);
	TestEntry entries[N];
	random_entries(entries);
	RzPVector contained_entries;
	rz_pvector_init(&contained_entries, NULL);
	size_t i;
	for (i = 0; i < N; i++) {
		rz_interval_tree_insert(&tree, entries[i].start, entries[i].end, entries + i);
		rz_pvector_push(&contained_entries, entries + i);
	}
	if (!check_invariants(tree.root)) {
		return false;
	}

	while (!rz_pvector_empty(&contained_entries)) {
		TestEntry *entry = rz_pvector_remove_at(&contained_entries, rand() % rz_pvector_len(&contained_entries));
		RzIntervalNode *node = rz_interval_tree_node_at_data(&tree, entry->start, entry);
		mu_assert_notnull(node, "node not null");

		mu_assert_eq(entry->freed, 0, "entry not freed before delete");
		bool s = rz_interval_tree_delete(&tree, node, true);
		mu_assert("delete success", s);
		mu_assert_eq(entry->freed, 1, "entry not freed after delete");

		RzIntervalTreeIter it;
		rz_interval_tree_foreach (&tree, it, entry) {
			entry->counter++;
		}
		void **pit;
		rz_pvector_foreach (&contained_entries, pit) {
			entry = *pit;
			entry->counter--;
		}
		for (i = 0; i < N; i++) {
			mu_assert_eq(entries[i].counter, 0, "contents after delete");
		}
	}

	mu_assert_null(tree.root, "root null after deleting all entries");
	rz_interval_tree_fini(&tree);
	rz_pvector_clear(&contained_entries);
	mu_end;
}

bool test_rz_interval_tree_resize(bool end_only) {
	RzIntervalTree tree;
	rz_interval_tree_init(&tree, free_cb);
	TestEntry entries[N];
	random_entries(entries);
	size_t i;
	for (i = 0; i < N; i++) {
		rz_interval_tree_insert(&tree, entries[i].start, entries[i].end, entries + i);
	}
	if (!check_invariants(tree.root)) {
		return false;
	}

	for (i = 0; i < SAMPLES; i++) {
		TestEntry *entry = entries + (rand() % N);
		RzIntervalNode *node = rz_interval_tree_node_at_data(&tree, entry->start, entry);
		if (!end_only) {
			entry->start = rand() % MAXVAL;
		}
		entry->end = entry->start + rand() % MAXVAL;
		mu_assert_notnull(node, "node not null");
		bool s = rz_interval_tree_resize(&tree, node, entry->start, entry->end);
		mu_assert("resize success", s);

		if (!check_invariants(tree.root)) {
			return false;
		}
		RBIter it;
		RzIntervalNode *intervalnode;
		rz_rbtree_foreach (&tree.root->node, it, intervalnode, RzIntervalNode, node) {
			entry = (TestEntry *)intervalnode->data;
			entry->counter++;
			mu_assert_eq_fmt(intervalnode->start, entry->start, "correct start", "%" PFMT64u);
			mu_assert_eq_fmt(intervalnode->end, entry->end, "correct end", "%" PFMT64u);
		}
		size_t j;
		for (j = 0; j < N; j++) {
			entries[j].counter--;
			mu_assert_eq(entries[j].counter, 0, "counter 0 after reference check");
		}
	}

	rz_interval_tree_fini(&tree);
	mu_end;
}

bool test_rz_interval_tree_resize_start_and_end() {
	return test_rz_interval_tree_resize(false);
}

bool test_rz_interval_tree_resize_end_only() {
	return test_rz_interval_tree_resize(true);
}

int all_tests() {
	mu_run_test(test_rz_interval_tree_insert_at);
	mu_run_test(test_rz_interval_tree_in_end_exclusive_point);
	mu_run_test(test_rz_interval_tree_in_end_inclusive_point);
	mu_run_test(test_rz_interval_tree_in_end_exclusive_interval);
	mu_run_test(test_rz_interval_tree_in_end_inclusive_interval);
	mu_run_test(test_rz_interval_tree_all_at);
	mu_run_test(test_rz_interval_tree_node_at_data);
	mu_run_test(test_rz_interval_tree_delete);
	mu_run_test(test_rz_interval_tree_resize_start_and_end);
	mu_run_test(test_rz_interval_tree_resize_end_only);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	struct timeval tv;
	rz_time_gettimeofday(&tv);
	unsigned int seed = argc > 1 ? strtoul(argv[1], NULL, 0) : tv.tv_sec + tv.tv_usec;
	printf("seed for test_intervaltree: %u\n", seed);
	srand(seed);
	return all_tests();
}
