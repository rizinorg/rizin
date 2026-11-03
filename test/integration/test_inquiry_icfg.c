// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../unit/minunit.h"
#include "rz_config.h"
#include <rz_core.h>
#include <rz_inquiry/rz_absint.h>
#include <rz_inquiry/rz_icfg.h>

typedef struct test_absint_t {
	RzAnalysis *analysis;
	RzIO *io;
	RzILCache *il_cache;
	RzAbsIntInstance *inst;
} TestInterp;

static RzAbsIntDriverConfig *driver_new_all(const char *arch, int bits, ut64 baddr, const char *url, RZ_OUT RzCore **core_out) {
	RzAbsIntDriverConfig *dconfig = RZ_NEW0(RzAbsIntDriverConfig);
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	*core_out = core;
	mu_assert_true(rz_core_file_open_load(core, url, 0644, baddr, false), "Load failed");

	dconfig->dimens = RZ_ABSINT_RESULT_DIMEN_BASE | RZ_ABSINT_RESULT_DIMEN_XREFS;
	dconfig->fcn_entry_points = rz_set_u_new();
	dconfig->io = core->io;
	dconfig->bin = core->bin;
	dconfig->analysis = core->analysis;
	dconfig->n_threads = 1;
	rz_core_inquiry_collect_entrypoints_all(core, dconfig->fcn_entry_points);

	return dconfig;
}

bool test_absint_block_resolve_bounds_single(void) {
	RzICFG *icfg = rz_icfg_new();
	RzCore *core;
	RzAbsIntDriverConfig *dconf = driver_new_all("x86", 64, 0x10000, "bins/inquiry/icfg_conflicts/simple_tailcall.s.obj", &core);
	mu_assert_notnull(dconf, "init");
	// RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_driver_run(dconf, icfg);

	// EXTRACT_RESULT(code, res, 1);

	// RzAnalysisFunction *fcn = rz_analysis_get_function_at(dconf->analysis, 0x10000);
	// mu_assert_notnull(fcn, "analysis function");
	// mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "analysis block count");
	// ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, UT64_MAX, UT64_MAX);

	rz_set_u_free(dconf->fcn_entry_points);
	free(dconf);
	rz_icfg_free(icfg);
	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_absint_block_resolve_bounds_single);
	return tests_passed != tests_run;
}

mu_main(all_tests)
