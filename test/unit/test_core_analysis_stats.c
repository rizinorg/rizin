// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

bool test_stats_bounds(void) {
	RzCore *core = rz_core_new();

	rz_flag_set(core->flags, "peri", 7, 1);
	rz_flag_set(core->flags, "phery", -7, 1);
	rz_meta_set_string(core->analysis, RZ_META_TYPE_STRING, -0x23, "elephant talk");

	// low extreme
	RzCoreAnalysisStats *as = rz_core_analysis_get_stats(core, 0, 0xff, 0x20);
	mu_assert_notnull(as, "stats");
	mu_assert_eq(rz_vector_len(&as->blocks), 0x100 / 0x20, "blocks count");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 0))->flags, 1, "flags");
	rz_core_analysis_stats_free(as);

	// high extreme
	as = rz_core_analysis_get_stats(core, -0x100, UT64_MAX, 0x20);
	mu_assert_notnull(as, "stats");
	mu_assert_eq(rz_vector_len(&as->blocks), 0x100 / 0x20, "blocks count");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 7))->flags, 1, "flags");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 7))->strings, 0, "strings");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 6))->strings, 1, "strings");
	rz_core_analysis_stats_free(as);

	// entire range
	as = rz_core_analysis_get_stats(core, 0, UT64_MAX, 1ull << 61);
	mu_assert_notnull(as, "stats");
	mu_assert_eq(rz_vector_len(&as->blocks), 8, "blocks count");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 7))->flags, 1, "flags");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 7))->strings, 1, "strings");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 6))->flags, 0, "flags");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 6))->strings, 0, "strings");
	rz_core_analysis_stats_free(as);

	// not divisable
	as = rz_core_analysis_get_stats(core, 0, UT64_MAX, (1ull << 61) + 3);
	mu_assert_notnull(as, "stats");
	mu_assert_eq(rz_vector_len(&as->blocks), 8, "blocks count");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 7))->flags, 1, "flags");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 7))->strings, 1, "strings");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 6))->flags, 0, "flags");
	mu_assert_eq(((RzCoreAnalysisStatsItem *)rz_vector_index_ptr(&as->blocks, 6))->strings, 0, "strings");
	rz_core_analysis_stats_free(as);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_stats_bounds);
	return tests_passed != tests_run;
}

mu_main(all_tests)
