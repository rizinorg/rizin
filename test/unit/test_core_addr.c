// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

bool test_rz_core_addr_options_new(void) {
	RzCoreAddrOptions *opts = rz_core_addr_options_new();
	mu_assert_notnull(opts, "options should be allocated");
	mu_assert_true(opts->show_offset, "show_offset should default to true");
	mu_assert_true(opts->prefer_function, "prefer_function should default to true");
	mu_assert_true(opts->show_flag, "show_flag should default to true");
	mu_assert_true(opts->use_decimal, "use_decimal should default to true");
	mu_assert_false(opts->show_color, "show_color should default to false");
	mu_assert_false(opts->show_source_info, "show_source_info should default to false");
	mu_assert_false(opts->use_realnames, "use_realnames should default to false");
	mu_assert_eq(opts->max_flag_delta, 0, "max_flag_delta should default to 0 (unlimited)");
	mu_assert_false(opts->use_spaces_around_delta, "use_spaces_around_delta should default to false");
	rz_core_addr_options_free(opts);
	mu_end;
}

bool test_rz_core_addr_describe_basic(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be allocated");

	// Add a flag for testing
	rz_flag_set(core->flags, "sym.main", 0x1000, 10);

	// Test basic description
	RzCoreAddr *desc = rz_core_addr_describe(core, 0x1000, NULL);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_eq(desc->addr, 0x1000, "addr should match");
	mu_assert_notnull(desc->flag_name, "flag_name should be set");
	mu_assert_streq(desc->flag_name, "sym.main", "flag_name should match");
	mu_assert_eq(desc->flag_delta, 0, "flag_delta should be 0");
	rz_core_addr_free(desc);

	// Test with offset
	desc = rz_core_addr_describe(core, 0x1005, NULL);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_eq(desc->addr, 0x1005, "addr should match");
	mu_assert_notnull(desc->flag_name, "flag_name should be set");
	mu_assert_streq(desc->flag_name, "sym.main", "flag_name should match");
	mu_assert_eq(desc->flag_delta, 5, "flag_delta should be 5");
	rz_core_addr_free(desc);

	// Test with address BEFORE any flag (should have no flag)
	desc = rz_core_addr_describe(core, 0x500, NULL);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_eq(desc->addr, 0x500, "addr should match");
	mu_assert_null(desc->flag_name, "flag_name should be NULL for address before any flag");
	rz_core_addr_free(desc);

	rz_core_free(core);
	mu_end;
}

bool test_rz_core_addr_to_string(void) {
	RzCoreAddr desc = {
		.addr = 0x1005,
		.flag_name = "sym.main",
		.flag_offset = 0x1000,
		.flag_delta = 5
	};

	// Test hex format
	RzCoreAddrOptions opts = {
		.show_offset = true,
		.prefer_function = false,
		.show_flag = true,
		.use_decimal = false,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	char *str = rz_core_addr_to_string(&desc, &opts);
	mu_assert_notnull(str, "string should be allocated");
	mu_assert_streq(str, "sym.main+0x5", "string should be name+offset");
	free(str);

	// Test decimal format
	opts.use_decimal = true;
	str = rz_core_addr_to_string(&desc, &opts);
	mu_assert_notnull(str, "string should be allocated");
	mu_assert_streq(str, "sym.main+5", "string should be name+decimal offset");
	free(str);

	// Test with zero delta
	desc.flag_delta = 0;
	str = rz_core_addr_to_string(&desc, &opts);
	mu_assert_notnull(str, "string should be allocated");
	mu_assert_streq(str, "sym.main", "string should be just name");
	free(str);

	// Test with no name
	RzCoreAddr desc2 = {
		.addr = 0x2000,
		.flag_name = NULL
	};
	opts.use_decimal = false;
	str = rz_core_addr_to_string(&desc2, &opts);
	mu_assert_notnull(str, "string should be allocated");
	mu_assert_streq(str, "0x2000", "string should be hex address");
	free(str);

	mu_end;
}

bool test_rz_core_addr_get_name_delta(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be allocated");

	// Add flags for testing
	rz_flag_set(core->flags, "sym.main", 0x1000, 10);
	rz_flag_set(core->flags, "sym.helper", 0x2000, 20);

	// Test exact match
	char *str = rz_core_addr_get_name_delta(core, 0x1000);
	mu_assert_notnull(str, "string should be allocated");
	mu_assert_streq(str, "sym.main", "string should be flag name");
	free(str);

	// Test with offset (uses decimal format by default)
	str = rz_core_addr_get_name_delta(core, 0x100a);
	mu_assert_notnull(str, "string should be allocated");
	mu_assert_streq(str, "sym.main+10", "string should be name+offset");
	free(str);

	// Test no match - returns hex address string when no flag found (hex for clarity)
	str = rz_core_addr_get_name_delta(core, 0x500);
	mu_assert_notnull(str, "string should be allocated for unknown address");
	mu_assert_streq(str, "0x500", "string should be hex address when no flag found");
	free(str);

	rz_core_free(core);
	mu_end;
}

bool test_rz_core_addr_with_function(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be allocated");

	// Create a function for testing
	RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, "main", 0x1000, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "function should be created");

	// Test function preference - test at function start address
	// (rz_analysis_get_fcn_in requires basic blocks, so use rz_analysis_get_function_at)
	RzCoreAddrOptions opts = {
		.show_offset = true,
		.prefer_function = true,
		.show_flag = true,
		.use_decimal = false,
		.show_color = false,
		.show_source_info = false,
		.use_realnames = false
	};

	RzCoreAddr *desc = rz_core_addr_describe(core, 0x1000, &opts);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_notnull(desc->fcn_name, "fcn_name should be set");
	mu_assert_streq(desc->fcn_name, "main", "fcn_name should match");
	mu_assert_eq(desc->fcn_delta, 0, "fcn_delta should be 0 at function start");
	rz_core_addr_free(desc);

	rz_core_free(core);
	mu_end;
}

bool test_rz_core_addr_describe_pj(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be allocated");

	// Add a flag for testing
	rz_flag_set(core->flags, "sym.test", 0x1000, 10);

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "pj should be allocated");

	rz_core_addr_describe_pj(core, pj, 0x1005, NULL);

	char *json_str = pj_drain(pj);
	mu_assert_notnull(json_str, "json string should be allocated");
	// Should contain addr and flag info
	mu_assert("should contain addr", strstr(json_str, "\"addr\"") != NULL);
	mu_assert("should contain flag_name", strstr(json_str, "\"flag_name\"") != NULL);
	free(json_str);

	rz_core_free(core);
	mu_end;
}

bool test_rz_core_addr_max_flag_delta(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be allocated");

	// Add a flag far away from test address
	rz_flag_set(core->flags, "sym.distant", 0x1000, 10);

	// Test with unlimited delta (0) - should find the flag
	RzCoreAddrOptions opts_unlimited = {
		.show_offset = true,
		.show_flag = true,
		.max_flag_delta = 0 // unlimited
	};
	RzCoreAddr *desc = rz_core_addr_describe(core, 0x10000, &opts_unlimited);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_notnull(desc->flag_name, "flag_name should be set with unlimited delta");
	mu_assert_streq(desc->flag_name, "sym.distant", "flag_name should match");
	rz_core_addr_free(desc);

	// Test with default 8192 limit (-1) - should NOT find the flag (delta too large)
	RzCoreAddrOptions opts_default = {
		.show_offset = true,
		.show_flag = true,
		.max_flag_delta = -1 // default 8192 limit
	};
	desc = rz_core_addr_describe(core, 0x10000, &opts_default);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_null(desc->flag_name, "flag_name should be NULL with 8192 limit (delta too large)");
	rz_core_addr_free(desc);

	// Test with small delta within limit - should find the flag
	desc = rz_core_addr_describe(core, 0x1100, &opts_default);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_notnull(desc->flag_name, "flag_name should be set (delta within 8192)");
	mu_assert_eq(desc->flag_delta, 0x100, "flag_delta should be 0x100");
	rz_core_addr_free(desc);

	// Test with custom limit
	RzCoreAddrOptions opts_custom = {
		.show_offset = true,
		.show_flag = true,
		.max_flag_delta = 100 // small custom limit
	};
	desc = rz_core_addr_describe(core, 0x1100, &opts_custom);
	mu_assert_notnull(desc, "description should be allocated");
	mu_assert_null(desc->flag_name, "flag_name should be NULL with 100 limit (delta 0x100 > 100)");
	rz_core_addr_free(desc);

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_core_addr_options_new);
	mu_run_test(test_rz_core_addr_describe_basic);
	mu_run_test(test_rz_core_addr_to_string);
	mu_run_test(test_rz_core_addr_get_name_delta);
	mu_run_test(test_rz_core_addr_with_function);
	mu_run_test(test_rz_core_addr_describe_pj);
	mu_run_test(test_rz_core_addr_max_flag_delta);
	return tests_passed != tests_run;
}

mu_main(all_tests)
