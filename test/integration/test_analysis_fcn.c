// SPDX-FileCopyrightText: 2025 KarlisS <karlis3p70l1ij@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../unit/minunit.h"
#include "rz_analysis.h"
#include "rz_config.h"
#include "rz_types_base.h"

/**
 * Test the function analysis on >64K function.
 */
static bool test_analysis_fcn_large() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "init core");
	RzCoreFile *cf = rz_core_file_open(core, "malloc://240000", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open 0 file");
	rz_core_bin_load(core, NULL, 0);
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);

	rz_core_analysis_fcn(core, 0, -1, RZ_ANALYSIS_XREF_TYPE_NULL, 5);

	RzAnalysisFunction *f = rz_analysis_get_function_at(core->analysis, 0);
	mu_assert_notnull(f, "Function not found");

	// no point in rest of test if some sanity check limited function size smaller than this
	mu_assert_eq(rz_analysis_function_linear_size(f), 240000, "function cut short");

	mu_assert_eq(rz_core_prevop_addr_force(core, 0x22202, 1), 0x22200, "Prev not working");

	ut64 end = 0;
	RzAnalysisBlock *block = rz_analysis_fcn_bbget_at(core->analysis, f, 0);
	while (block) {
		end = RZ_MAX(end, block->addr + block->size);
		if (block->jump != UT64_MAX) {
			mu_assert_eq(block->jump, block->addr + block->size, "blocks aren't chained");
			block = rz_analysis_fcn_bbget_at(core->analysis, f, block->jump);
		} else {
			block = NULL;
		}
	}
	mu_assert_eq(end, 240000, "Blocks don't cover whole function");

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_analysis_fcn_large);
	return tests_passed != tests_run;
}

mu_main(all_tests)
