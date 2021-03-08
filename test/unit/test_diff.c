// SPDX-FileCopyrightText: 2017 lonetech <yann-github@vernier.se>
// SPDX-License-Identifier: LGPL-3.0-only

#include <math.h>
#include <rz_diff.h>
#include "minunit.h"

#define R(a, b, c, d) \
	{ (const ut8 *)a, (const ut8 *)b, (int)c, (int)d }
static struct {
	const ut8 *a;
	const ut8 *b;
	int di_distance;
	int dis_distance;
} tests[] = {
	R("", "zzz", 3, 3),
	R("meow", "", 4, 4),
	R("a", "b", 2, 1),
	R("aaa", "aaa", 0, 0),
	R("aaaaa", "aabaa", 2, 1),
	R("aaaa", "aabaa", 1, 1),
	R("aaba", "babca", 3, 2),
	R("foo", "foobar", 3, 3),
	R("wallaby", "wallet", 5, 3),
	R("identity", "identity", 0, 0),
	{ NULL, NULL, 0, 0 }
};

bool test_rz_diff_buffers_distance(void) {
	char msg[128];
	RzDiff *diff = rz_diff_new();
	if (!diff) {
		return false;
	}
	unsigned int distance;
	int i;

	// Levenshtein edit distance (deletion/insertion/substitution)
	diff->type = 'l';
	for (i = 0; tests[i].a; i++) {
		size_t la = strlen((const char *)tests[i].a), lb = strlen((const char *)tests[i].b);
		rz_diff_buffers_distance(diff, tests[i].a, la, tests[i].b, lb, &distance, NULL);
		snprintf(msg, sizeof msg, "levenshtein %s/%s distance", tests[i].a, tests[i].b);
		mu_assert_eq(distance, tests[i].dis_distance, msg);
	}

	// Eugene W. Myers' O(ND) diff algorithm, deletion/insertion edit distance
	diff->type = 'm';
	for (i = 0; tests[i].a; i++) {
		size_t la = strlen((const char *)tests[i].a), lb = strlen((const char *)tests[i].b);
		rz_diff_buffers_distance(diff, tests[i].a, la, tests[i].b, lb, &distance, NULL);
		snprintf(msg, sizeof msg, "myers %s/%s distance", tests[i].a, tests[i].b);
		mu_assert_eq(distance, tests[i].di_distance, msg);
	}

	rz_diff_free(diff);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_diff_buffers_distance);
	return tests_passed != tests_run;
}

mu_main(all_tests)
