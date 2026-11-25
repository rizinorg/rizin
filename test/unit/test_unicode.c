// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

#include "../../librz/util/unicode_tables.inc"
#include "../../librz/util/undefined_ranges_bitmap.inc"

bool test_undefined_ranges_bitmap_is_synced(void) {
	size_t n_words = RZ_ARRAY_SIZE(undefined_ranges_bitmap);
	size_t n_bits = n_words * sizeof(undefined_ranges_bitmap[0]) * 8;
	ut64 *reference = RZ_NEWS0(ut64, n_words);

	mu_assert_notnull(reference, "allocation failed");

	for (size_t i = 0; i < RZ_ARRAY_SIZE(undefined_ranges); i++) {
		ut32 from = undefined_ranges[i].from;
		if (from >= n_bits) {
			break;
		}
		ut32 to = RZ_MIN(undefined_ranges[i].to, (ut32)(n_bits - 1));
		for (ut32 cp = from; cp <= to; cp++) {
			reference[cp / 64] |= 1ull << (cp % 64);
		}
	}

	bool in_sync = !memcmp(reference, undefined_ranges_bitmap, n_words * sizeof(ut64));
	free(reference);

	mu_assert_true(in_sync,
		"undefined_ranges_bitmap.inc is out of sync with the `undefined_ranges` table in "
		"unicode.c. Regenerate it with: python3 sys/gen_unicode_undefined_bitmap.py");

	mu_end;
}

int all_tests() {
	mu_run_test(test_undefined_ranges_bitmap_is_synced);
	return tests_passed != tests_run;
}

mu_main(all_tests)
