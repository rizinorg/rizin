// SPDX-FileCopyrightText: 2016 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_bitmap_set(void) {
	int i;
	static const int max_value = (2343 + 1);
	static const ut32 values[] = { 1, 2, 3, 4, 8, 34, 543, 2343 };
	static const int len = (sizeof(values) / sizeof(ut32));
	RzBitmap *bitmap = rz_bitmap_new(max_value);
	for (i = 0; i < len; i++) {
		rz_bitmap_set(bitmap, values[i]);
	}
	for (i = 0; i < len; i++) {
		mu_assert_eq(rz_bitmap_test(bitmap, values[i]), true,
			"Bit should be set.");
	}
	for (i = 0; i < len; i++) {
		rz_bitmap_unset(bitmap, values[i]);
	}
	for (i = 0; i < len; i++) {
		mu_assert_eq(rz_bitmap_test(bitmap, values[i]), false,
			"Bit should not be set.");
	}
	rz_bitmap_free(bitmap);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_bitmap_set);
	return tests_passed != tests_run;
}

mu_main(all_tests)
