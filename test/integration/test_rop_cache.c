// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_rop.h>
#include "../unit/minunit.h"

bool test_rop_cache(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");

#if __WINDOWS__
	const char *test_bin = "bins/pe/standard.exe";
#else
	const char *test_bin = "bins/elf/analysis/hello-linux-x86_64";
#endif

	RzCoreFile *cf = rz_core_file_open(core, test_bin, RZ_PERM_RX, 0);
	mu_assert_notnull(cf, "open file");
	rz_core_bin_load(core, NULL, 0);
	rz_config_set_b(core->config, "rop.cache", true);

	RzCmdStateOutput state;
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET, core);

	RzRopSearchContext *ctx = rz_core_rop_search_context_new(
		core, "", false, RZ_ROP_GADGET_PRINT, RZ_ROP_DETAIL_SEARCH_NON, &state);
	rz_core_rop_search(core, ctx);
	rz_core_rop_search_context_free(ctx);

	if (core->analysis->ht_rop) {
		mu_assert_eq(core->analysis->ht_rop->count, 0, "empty filter not cached");
	}

	const char *filter = "ret";
	ut64 key = rz_str_djb2_hash(filter);

	ctx = rz_core_rop_search_context_new(
		core, filter, false, RZ_ROP_GADGET_PRINT, RZ_ROP_DETAIL_SEARCH_NON, &state);
	rz_core_rop_search(core, ctx);
	rz_core_rop_search_context_free(ctx);

	mu_assert_notnull(core->analysis->ht_rop, "ht_rop");
	char *result = ht_up_find(core->analysis->ht_rop, key, NULL);
	mu_assert_notnull(result, "cached result");

	ctx = rz_core_rop_search_context_new(
		core, filter, false, RZ_ROP_GADGET_PRINT, RZ_ROP_DETAIL_SEARCH_NON, &state);
	rz_core_rop_search(core, ctx);
	rz_core_rop_search_context_free(ctx);

	char *result2 = ht_up_find(core->analysis->ht_rop, key, NULL);
	mu_assert_ptreq(result2, result, "cache hit");

	const char *filter2 = "pop";
	ut64 key2 = rz_str_djb2_hash(filter2);

	ctx = rz_core_rop_search_context_new(
		core, filter2, false, RZ_ROP_GADGET_PRINT, RZ_ROP_DETAIL_SEARCH_NON, &state);
	rz_core_rop_search(core, ctx);
	rz_core_rop_search_context_free(ctx);

	char *result3 = ht_up_find(core->analysis->ht_rop, key2, NULL);
	mu_assert_notnull(result3, "pop cached");
	mu_assert_ptrneq(result3, result, "different cache entries");
	mu_assert_eq(core->analysis->ht_rop->count, 2, "cache count");

	rz_cmd_state_output_fini(&state);
	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rop_cache);
	return tests_passed != tests_run;
}

mu_main(all_tests)
