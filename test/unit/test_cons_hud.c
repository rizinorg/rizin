// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

// HUD internal functions testing
// Copying __matchString here to avoid including the whole hud.c
static bool __matchString_test(char *entry, char *filter, char *mask, const int mask_size) {
	if (!entry || !filter || !mask)
		return false;
	char *p, *current_token = filter;
	const char *filter_end = filter + strlen(filter);
	char *ansi_filtered = rz_str_dup(entry);
	if (!ansi_filtered)
		return false;
	int *cps = NULL;
	int j = rz_str_ansi_filter(ansi_filtered, NULL, &cps, -1);
	if (j < 0 || !cps) {
		free(ansi_filtered);
		return false;
	}
	entry = ansi_filtered;
	for (p = filter; p <= filter_end; p++) {
		if (*p == ' ' || *p == '\0') {
			const char *next_match, *entry_ptr = entry;
			char old_char = *p;
			int token_len;

			if (p == current_token) {
				current_token++;
				continue;
			}
			*p = 0;
			token_len = strlen(current_token);
			while ((next_match = rz_str_casestr(entry_ptr, current_token))) {
				int real_pos, filtered_pos = next_match - entry;
				if (filtered_pos + token_len > j) {
					break;
				}
				int end_pos = cps[filtered_pos + token_len];
				for (real_pos = cps[filtered_pos];
					real_pos < end_pos && real_pos < mask_size;
					real_pos = cps[++filtered_pos]) {
					mask[real_pos] = 'x';
				}
				entry_ptr += token_len;
			}
			*p = old_char;
			if (entry_ptr == entry) {
				free(cps);
				free(ansi_filtered);
				return false;
			}
			current_token = p + 1;
		}
	}
	free(cps);
	free(ansi_filtered);
	return true;
}

bool test_hud_matchString(void) {
	char mask[128];
	memset(mask, 0, sizeof(mask));

	char *filter = strdup("hello");
	mu_assert_notnull(filter, "Filter string should not be null");
	bool res = __matchString_test("hello world", filter, mask, sizeof(mask));
	mu_assert_true(res, "Match hello");
	free(filter);

	filter = strdup("world hello");
	res = __matchString_test("hello world", filter, mask, sizeof(mask));
	mu_assert_true(res, "Match multiple words out of order");
	mu_assert_eq(mask[6], 'x', "Mask 'w' in world");
	mu_assert_eq(mask[10], 'x', "Mask 'd' in world at end of string");
	free(filter);

	filter = strdup("hello");
	res = __matchString_test("\x1b[31mhello\x1b[0m world", filter, mask, sizeof(mask));
	mu_assert_true(res, "Match hello with ANSI");
	mu_assert_eq(mask[5], 'x', "Mask set correctly for hello (accounting for ANSI color at 0)");
	// Actually real_pos is in terms of ORIGINAL string.
	// hello starts at index 5 in "\x1b[31mhello"
	free(filter);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_hud_matchString);
	return tests_passed != tests_run;
}

mu_main(all_tests)
