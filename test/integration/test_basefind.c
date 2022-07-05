// SPDX-FileCopyrightText: 2015 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_basefind.h>
#include "../unit/minunit.h"

static void basefind_options_set_valid(RzBaseFindOpt *options) {
	options->start_address = 0;
	options->end_address = 4096;
	options->pointer_size = 32;
	options->min_score = 1;
	options->min_string_len = 10;
	options->alignment = RZ_BASEFIND_BASE_ALIGNMENT;
	options->max_threads = 1;
	options->callback = NULL;
	options->user = NULL;
}

static bool test_basefind_callback_false(const RzBaseFindThreadInfo *th_info, void *user) {
	return false;
}

static bool test_basefind_callback_true(const RzBaseFindThreadInfo *th_info, void *user) {
	return true;
}

int test_rz_basefind_with_callbacks(void) {
	RzBaseFindOpt options;
	RzList *result = NULL;
	RzCore *core = rz_core_new();
	rz_core_file_open_load(core, "bins/firmware/stm32f103-dapboot-v1.20-bluepill.bin", 0, RZ_PERM_R, false);

	// test_basefind_callback_true
	basefind_options_set_valid(&options);
	options.callback = test_basefind_callback_true;
	result = rz_basefind(core, &options);
	mu_assert_notnull(result, "valid callback (true)");
	rz_list_free(result);

	// test_basefind_callback_false
	basefind_options_set_valid(&options);
	options.callback = test_basefind_callback_false;
	result = rz_basefind(core, &options);
	mu_assert_notnull(result, "valid callback (false)");
	rz_list_free(result);

	rz_core_free(core);
	mu_end;
}

int test_rz_basefind_no_callback(void) {
	RzBaseFindOpt options;
	RzList *result = NULL;
	RzCore *core = rz_core_new();
	rz_core_file_open_load(core, "bins/firmware/stm32f103-dapboot-v1.20-bluepill.bin", 0, RZ_PERM_R, false);

	// valid configuration
	basefind_options_set_valid(&options);
	result = rz_basefind(core, &options);
	mu_assert_notnull(result, "valid pointer_size 32");
	rz_list_free(result);

	// valid configuration
	basefind_options_set_valid(&options);
	options.pointer_size = 64;
	result = rz_basefind(core, &options);
	mu_assert_notnull(result, "valid pointer_size 64");
	rz_list_free(result);

	// pointer_size
	basefind_options_set_valid(&options);
	options.pointer_size = 77;
	result = rz_basefind(core, &options);
	mu_assert_null(result, "invalid pointer_size");

	// min_score
	basefind_options_set_valid(&options);
	options.min_score = 0;
	result = rz_basefind(core, &options);
	mu_assert_null(result, "invalid min_score");

	// min_string_len
	basefind_options_set_valid(&options);
	options.min_string_len = 0;
	result = rz_basefind(core, &options);
	mu_assert_null(result, "invalid min_string_len");

	// alignment
	basefind_options_set_valid(&options);
	options.alignment = 0;
	result = rz_basefind(core, &options);
	mu_assert_null(result, "invalid alignment");

	// start == end
	basefind_options_set_valid(&options);
	options.start_address = 0x1111;
	options.end_address = 0x1111;
	result = rz_basefind(core, &options);
	mu_assert_null(result, "invalid address (start == end).");

	// start > end
	basefind_options_set_valid(&options);
	options.start_address = 0x1111;
	options.end_address = 0x77;
	result = rz_basefind(core, &options);
	mu_assert_null(result, "invalid address (start > end).");

	rz_core_free(core);
	mu_end;
}

int test_rz_basefind_no_core_load(void) {
	RzBaseFindOpt options;
	RzList *result = NULL;
	RzCore *core = rz_core_new();

	rz_io_open(core->io, "bins/firmware/stm32f103-dapboot-v1.20-bluepill.bin", RZ_PERM_R, 0);
	basefind_options_set_valid(&options);
	result = rz_basefind(core, &options);
	mu_assert_null(result, "file not loaded via core");

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_basefind_no_core_load);
	mu_run_test(test_rz_basefind_no_callback);
	mu_run_test(test_rz_basefind_with_callbacks);
	return tests_passed != tests_run;
}

mu_main(all_tests)
