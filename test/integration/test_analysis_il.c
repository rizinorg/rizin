// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../unit/minunit.h"

/**
 * Test running an IL vm with Analysis connection independently of the global user-faced vm
 */
static bool test_analysis_il_vm_step() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "init core");
	RzCoreFile *cf = rz_core_file_open(core, "hex://a9754937", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open hex file");
	rz_core_bin_load(core, NULL, 0);
	rz_config_set(core->config, "asm.arch", "6502");

	RzReg *reg = rz_reg_new();
	mu_assert_notnull(reg, "create reg");
	char *reg_profile = rz_analysis_get_reg_profile(core->analysis);
	mu_assert_notnull(reg_profile, "reg profile");
	bool succ = rz_reg_set_profile_string(reg, reg_profile);
	rz_mem_free(reg_profile);
	mu_assert_true(succ, "apply reg profile");

	RzAnalysisILVM *vm = rz_analysis_il_vm_new(core->analysis, reg);
	mu_assert_notnull(vm, "create analysis vm");
	rz_analysis_il_vm_sync_to_reg(vm, reg); // initial sync to get any plugin-specified initialization

	// a9 75    lda #0x75
	RzAnalysisILStepResult sr = rz_analysis_il_vm_step(core->analysis, vm, reg);
	mu_assert_eq(sr, RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS, "il step");
	mu_assert_eq(rz_reg_getv(reg, "a"), 0x75, "result in local reg");
	mu_assert_eq(rz_reg_get_value_by_role(reg, RZ_REG_NAME_PC), 2, "pc in local reg");
	mu_assert_eq(rz_reg_getv(core->analysis->reg, "a"), 0x0, "global reg untouched");
	mu_assert_eq(rz_reg_get_value_by_role(core->analysis->reg, RZ_REG_NAME_PC), 0, "global reg untouched");

	// 49 37    eor #0x37
	//     ==> 0x75 ^ 0x37 = 0x42
	sr = rz_analysis_il_vm_step(core->analysis, vm, reg);
	mu_assert_eq(sr, RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS, "il step");
	mu_assert_eq(rz_reg_getv(reg, "a"), 0x42, "result in local reg");
	mu_assert_eq(rz_reg_get_value_by_role(reg, RZ_REG_NAME_PC), 4, "pc in local reg");
	mu_assert_eq(rz_reg_getv(core->analysis->reg, "a"), 0x0, "global reg untouched");
	mu_assert_eq(rz_reg_get_value_by_role(core->analysis->reg, RZ_REG_NAME_PC), 0, "global reg untouched");

	rz_reg_free(reg);
	rz_analysis_il_vm_free(vm);
	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_analysis_il_vm_step);
	return tests_passed != tests_run;
}

mu_main(all_tests)
