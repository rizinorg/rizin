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

static bool test_analysis_il() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "init core");
	RzCoreFile *cf = rz_core_file_open(core, "bins/elf/emulateme.arm64", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open file");
	mu_assert("load file", rz_core_bin_load(core, NULL, 0));
	mu_assert("il vm setup", rz_analysis_il_vm_setup(core->analysis));
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_DEEP);

	RzStrBuf sb = { 0 };
	RzAnalysisOp op = { 0 };

	rz_analysis_op(core->analysis, &op, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_IL);
	rz_il_op_effect_stringify(op.il_op, &sb, false);
	mu_assert_streq(rz_strbuf_get(&sb), "(seq "
					    "(storew 0 (- (var sp) (bv 64 0x20)) (var x29)) "
					    "(storew 0 (+ (- (var sp) (bv 64 0x20)) (bv 64 0x8)) (var x30)) "
					    "(set sp (- (var sp) (bv 64 0x20))))",
		"stringify il op");

	ut64 addr = rz_num_math(core->num, "sym.decrypt");
	rz_core_seek(core, addr, true);
	RzIterator *iter = rz_core_analysis_op_function_iter(core, RZ_ANALYSIS_OP_MASK_IL);
	mu_assert_notnull(iter, "function rzil");
	ut64 count = 0;
	RzAnalysisOp *pop = NULL;
	rz_iterator_foreach(RzAnalysisOp *, iter, pop) {
		if (op.addr == 0x804) {
			rz_strbuf_fini(&sb);
			rz_il_op_effect_stringify(pop->il_op, &sb, false);
			mu_assert_streq(rz_strbuf_get(&sb), "(set sp (- (var sp) (bv 64 0x30)))",
				"stringify il op");
		} else if (op.addr == 0x888) {
			rz_strbuf_fini(&sb);
			rz_il_op_effect_stringify(pop->il_op, &sb, false);
			mu_assert_streq(rz_strbuf_get(&sb), "(set x0 (loadw 0 64 (+ (var sp) (bv 64 0x20))))",
				"stringify il op");
		}
		++count;
	}
	mu_assert_eq(count, 69, "il op count of function");
	rz_iterator_free(iter);

	count = 0;
	iter = rz_core_analysis_op_chunk_iter(core, 0x918, 0, 30, RZ_ANALYSIS_OP_MASK_IL);
	mu_assert_notnull(iter, "chunk rzil");
	rz_iterator_foreach(RzAnalysisOp *, iter, pop) {
		if (op.addr == 0x918) {
			rz_strbuf_fini(&sb);
			rz_il_op_effect_stringify(pop->il_op, &sb, false);
			mu_assert_streq(rz_strbuf_get(&sb), "(seq (storew 0 (- (var sp) (bv 64 0x30)) (var x29)) (storew 0 (+ (- (var sp) (bv 64 0x30)) (bv 64 0x8)) (var x30)) (set sp (- (var sp) (bv 64 0x30))))",
				"stringify il op");
		} else if (op.addr == 0x954) {
			rz_strbuf_fini(&sb);
			rz_il_op_effect_stringify(pop->il_op, &sb, false);
			mu_assert_streq(rz_strbuf_get(&sb), "(set x0 (loadw 0 64 (+ (var sp) (bv 64 0x10))))",
				"stringify il op");
		}
		++count;
	}
	mu_assert_eq(count, 30, "il op count of function");
	rz_iterator_free(iter);

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_analysis_il_vm_step);
	mu_run_test(test_analysis_il);
	return tests_passed != tests_run;
}

mu_main(all_tests)
