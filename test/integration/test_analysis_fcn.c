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

static bool always_valid(RzIO *io, ut64 addr, int r) {
	return true;
}

static bool test_analysis_xrefs_comment() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new failed");

	mu_assert_notnull(rz_core_file_open(core, "malloc://1024", RZ_PERM_RWX, 0), "file open failed");

	RzAnalysis *analysis = core->analysis;
	mu_assert_notnull(analysis, "analysis is null");
	analysis->iob.is_valid_offset = always_valid;

	mu_assert_true(rz_analysis_set_bits(analysis, 64), "set bits failed");
	mu_assert_true(rz_analysis_use(analysis, "x86"), "use x86 failed");

	RzAnalysisFunction *f_src = rz_analysis_create_function(analysis, "src_fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(f_src, "create src function");
	ut64 target = 0x200;

	rz_analysis_xrefs_set(analysis, 0x100, target, RZ_ANALYSIS_XREF_TYPE_CODE);
	char *res = rz_core_get_xref_comment(core, target);
	mu_assert_streq(res, "; CODE XREF from src_fcn @ ", "xref prefix failed");
	free(res);

	rz_analysis_xrefs_set(analysis, 0x102, target, RZ_ANALYSIS_XREF_TYPE_CODE);
	res = rz_core_get_xref_comment(core, target);
	mu_assert_streq(res, "; CODE XREFS from src_fcn @ , +0x2", "xref join failed");
	free(res);

	rz_analysis_xrefs_set(analysis, 0x104, target, RZ_ANALYSIS_XREF_TYPE_CODE);
	rz_config_set_i(core->config, "asm.xrefs.max", 2);
	res = rz_core_get_xref_comment(core, target);
	mu_assert_streq(res, "; XREFS(3)", "asm.xrefs.max failed");
	free(res);

	rz_config_set_i(core->config, "asm.xrefs.max", 10);
	rz_config_set_i(core->config, "asm.xrefs.fold", 2);

	res = rz_core_get_xref_comment(core, target);
	const char *exp = "; XREFS: CODE 0x00000100  CODE 0x00000102  CODE 0x00000104  ";
	mu_assert_streq(res, exp, "asm.xrefs.fold failed");
	free(res);

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_analysis_fcn_large);
	mu_run_test(test_analysis_xrefs_comment);
	return tests_passed != tests_run;
}

mu_main(all_tests)
