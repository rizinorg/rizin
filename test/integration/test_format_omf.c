// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <omf/omf_common.h>
#include "../unit/minunit.h"

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C binary
 */
bool test_omf_get_idx(void) {
	const ut8 buf0[2] = { 0xfd, 0xff };
	const ut8 buf1[2] = { 0x40, 0xff };
	const ut8 buf2[3] = { 0xfc, 0x11, 0xff };
	const ut8 buf3[3] = { 0x7c, 0x11, 0xff };
	size_t offset0 = 0;
	size_t offset1 = 0;
	size_t offset2 = 0;
	size_t offset3 = 0;
	const ut16 x0 = omf_get_idx_offset(&buf0, sizeof(buf0), &offset0);
	mu_assert_eq(x0, 0, "Incorrect return");
	mu_assert_eq(offset0, 0, "Incorrect offset");
	const ut16 x1 = omf_get_idx_offset(&buf1, sizeof(buf1), &offset1);
	mu_assert_eq(x1, 0x40, "Incorrect return");
	mu_assert_eq(offset1, 1, "Incorrect offset");
	const ut16 x2 = omf_get_idx_offset(&buf2, sizeof(buf2), &offset2);
	mu_assert_eq(x2, 0x7c11, "Incorrect return");
	mu_assert_eq(offset2, 2, "Incorrect offset");
	const ut16 x3 = omf_get_idx_offset(&buf3, sizeof(buf3), &offset3);
	mu_assert_eq(x3, 0x7c, "Incorrect return");
	mu_assert_eq(offset3, 1, "Incorrect offset");
	mu_end;
}

bool all_tests() {
	srand(time(0));
	mu_run_test(test_omf_get_idx);
	return tests_passed != tests_run;
}

mu_main(all_tests)