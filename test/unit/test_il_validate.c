// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_il_validate_pure_bool() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_b0();
	RzILSortPure sort = rz_il_sort_pure_bv(0xffff);
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_b1();
	sort = rz_il_sort_pure_bv(0xffff);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_bitv_from_ut64(42, 123);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(42)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv_binop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(63, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand sizes of add op do not agree: 63 vs. 64.", "report");

	op = rz_il_op_new_add(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of add op is not a bitvector.", "report");

	op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of add op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_let() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	// body type
	RzILOpPure *op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	// bound
	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	// shadowing
	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_let(
			"y", rz_il_op_new_bitv_from_ut64(32, 123),
			rz_il_op_new_let(
				"x", rz_il_op_new_bitv_from_ut64(42, 321),
				rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE))));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(42)), "sort");
	mu_assert_null(report, "no report");
	free(report);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_let(
			"y", rz_il_op_new_bitv_from_ut64(32, 123),
			rz_il_op_new_let(
				"x", rz_il_op_new_bitv_from_ut64(42, 321),
				rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL_PURE))));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(32)), "sort");
	mu_assert_null(report, "no report");
	free(report);
	rz_il_op_pure_free(op);

	// invalid cases
	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	free(report);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_GLOBAL));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	free(report);
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_validate_pure_bitv);
	mu_run_test(test_il_validate_pure_bool);
	mu_run_test(test_il_validate_pure_bitv_binop);
	mu_run_test(test_il_validate_pure_let);
	return tests_passed != tests_run;
}

mu_main(all_tests)
