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

bool test_core_auto_analysis_clears_timeout(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");

	mu_assert_eq(rz_core_cmd0_rzshell(core, "e asm.arch=x86; e asm.bits=64; o malloc://64; wx c3 @ 0; e analysis.timeout=2"),
		RZ_CMD_STATUS_OK, "setup");

	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_DEEP);
	mu_assert_eq(core->intr->timeout, 0, "completed auto analysis must disarm timeout");
	mu_assert_false(rz_interrupt_is_breaked(core->intr), "not breaked after analysis");

	mu_assert_eq(rz_core_cmd0_rzshell(core, "e analysis.timeout=-1"), RZ_CMD_STATUS_OK, "negative timeout setup");
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_DEEP);
	mu_assert_eq(core->intr->timeout, 0, "negative analysis.timeout keeps timeout disabled");
	mu_assert_false(rz_interrupt_is_breaked(core->intr), "negative analysis.timeout must not break");

	rz_core_free(core);
	mu_end;
}

bool test_core_auto_analysis_timeout_clamp_and_interrupt(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");

	mu_assert_eq(rz_core_cmd0_rzshell(core, "e asm.arch=x86; e asm.bits=64; o malloc://64; wx c3 @ 0; e analysis.autoname=true; e analysis.timeout=100000000"),
		RZ_CMD_STATUS_OK, "setup");

	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
	mu_assert_eq(core->intr->timeout, 0, "experimental auto analysis clears clamped timeout");
	mu_assert_false(rz_interrupt_is_breaked(core->intr), "not breaked after clamped timeout analysis");

	rz_interrupt_raise(core->intr);
	mu_assert_false(rz_core_analysis_everything(core, true, NULL), "pre-breaked analysis returns false");
	rz_interrupt_break_clear(core->intr);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_stats_bounds);
	mu_run_test(test_core_auto_analysis_clears_timeout);
	mu_run_test(test_core_auto_analysis_timeout_clamp_and_interrupt);
	return tests_passed != tests_run;
}

mu_main(all_tests)
