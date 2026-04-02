// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

static bool test_mspcode_analysis(void) {
	RzAnalysis *a = rz_analysis_new(NULL);
	mu_assert_notnull(a, "Failed to create RzAnalysis");

	bool ret = rz_analysis_use(a, "mspcode");
	mu_assert_true(ret, "Failed to use mspcode plugin");

	RzAnalysisOp *op = rz_analysis_op_new();
	mu_assert_notnull(op, "Failed to create RzAnalysisOp");

	// Test IDE marker (0x00)
	const ut8 buf_add[] = { 0x00 };
	rz_analysis_op(a, op, 0x1000, buf_add, sizeof(buf_add), RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_NOP, "0x00 type mismatch");

	// Test Push (0x01)
	const ut8 buf_sub[] = { 0x01 };
	rz_analysis_op(a, op, 0x1000, buf_sub, sizeof(buf_sub), RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_PUSH, "0x01 type mismatch");

	// Test Push LitI2_Byte (0x27)
	const ut8 buf_push[] = { 0x27, 0x0a };
	rz_analysis_op(a, op, 0x1000, buf_push, sizeof(buf_push), RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_PUSH, "Push type mismatch");

	// Test Push ptr (0x1B)
	const ut8 buf_jmp[] = { 0x1B, 0x05, 0x00 };
	rz_analysis_op(a, op, 0x1000, buf_jmp, sizeof(buf_jmp), RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_PUSH, "Branch type mismatch");

	// Test If Pop=0 (CJMP) (0x1C) with offset 0x0008
	const ut8 buf_cjmp[] = { 0x1C, 0x08, 0x00 };
	rz_analysis_op(a, op, 0x1000, buf_cjmp, sizeof(buf_cjmp), RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_CJMP, "BranchT type mismatch");

	// Test End (RET) (0x14)
	const ut8 buf_ret[] = { 0x14 };
	rz_analysis_op(a, op, 0x1000, buf_ret, sizeof(buf_ret), RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op->type, RZ_ANALYSIS_OP_TYPE_RET, "End type mismatch");

	rz_analysis_op_free(op);
	rz_analysis_free(a);
	mu_end;
}

static bool all_tests() {
	mu_run_test(test_mspcode_analysis);
	return tests_passed != tests_run;
}

mu_main(all_tests)