// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

static bool test_rust_metadata_api_edge_cases(void) {
	rz_core_rust_info_free(NULL);

	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");

	/* No bin object loaded: returns NULL / 0 cleanly */
	mu_assert_null(rz_core_analysis_recover_rust_metadata(core), "recover without bin returns NULL");
	mu_assert_eq(rz_core_analysis_resolve_rust_strings(core), 0, "resolve_rust_strings without bin");

	/* Raw IO buffer with no bin object */
	RzCoreFile *cf = rz_core_file_open(core, "malloc://64", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open malloc://64");
	mu_assert_notnull(rz_io_map_add(core->io, cf->fd, RZ_PERM_RWX, 0, 0, 64), "map malloc://64");
	rz_config_set_i(core->config, "asm.bits", 32);
	mu_assert_null(rz_core_analysis_recover_rust_metadata(core), "recover on raw buffer returns NULL");
	mu_assert_eq(rz_core_analysis_resolve_rust_strings(core), 0, "resolve_rust_strings on raw buffer");

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rust_metadata_api_edge_cases);
	return tests_passed != tests_run;
}

mu_main(all_tests)
