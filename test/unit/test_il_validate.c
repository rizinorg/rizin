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

static bool test_il_validate_pure_ite() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_ite(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, 0), rz_il_op_new_bitv_from_ut64(32, 0));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(32)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_ite(rz_il_op_new_b0(), rz_il_op_new_b0(), rz_il_op_new_b1());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_ite(rz_il_op_new_bitv_from_ut64(12, 0), rz_il_op_new_bitv_from_ut64(32, 0), rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	mu_assert_streq_free(report, "Condition of ite op is not boolean.", "report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_ite(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, 0), rz_il_op_new_bitv_from_ut64(31, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	mu_assert_streq_free(report, "Types of ite branches do not agree: bitvector:32 vs. bitvector:31.", "report");
	rz_il_op_pure_free(op);

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

static bool test_il_validate_pure_var() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();
	rz_il_validate_global_context_add_var(ctx, "y", rz_il_sort_pure_bv(42));

	RzILOpPure *op = rz_il_op_new_var("y", RZ_IL_VAR_KIND_GLOBAL);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(42)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_var("x", RZ_IL_VAR_KIND_GLOBAL);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"x\" referenced by var op does not exist.", "report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_inv() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_bool_inv(rz_il_op_new_b0());
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_bool_inv(rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand of boolean inv op is not boolean.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bool_binop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_bool_and(
		rz_il_op_new_b0(),
		rz_il_op_new_b1());
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_bool_and(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of and op is not bool.", "report");

	op = rz_il_op_new_bool_and(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of and op is not bool.", "report");

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

static bool test_il_validate_pure_bitv_bool_unop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_msb(rz_il_op_new_bitv_from_ut64(64, 123));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_msb(rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand of msb op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv_unop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_log_not(rz_il_op_new_bitv_from_ut64(64, 123));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_log_not(rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand of lognot op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_shift() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 123), rz_il_op_new_bitv_from_ut64(32, 32));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_shiftl(rz_il_op_new_bitv_from_ut64(8, 0),
		rz_il_op_new_bitv_from_ut64(64, 123), rz_il_op_new_bitv_from_ut64(32, 32));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Fill operand of shiftl op is not bool.", "report");

	op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, 32));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Value operand of shiftl op is not a bitvector.", "report");

	op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(32, 32), rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Distance operand of shiftl op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_cmp() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_eq(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_eq(
		rz_il_op_new_bitv_from_ut64(63, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand sizes of eq op do not agree: 63 vs. 64.", "report");

	op = rz_il_op_new_eq(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of eq op is not a bitvector.", "report");

	op = rz_il_op_new_eq(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of eq op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_cast() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_cast(13,
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(13)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_cast(13,
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	op->op.cast.length = 0;
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of cast op is 0.", "report");

	op = rz_il_op_new_cast(13,
		rz_il_op_new_bitv_from_ut64(12, 0),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Fill operand of cast op is not bool.", "report");

	op = rz_il_op_new_cast(13,
		rz_il_op_new_b0(),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Value operand of cast op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_append() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();

	RzILOpPure *op = rz_il_op_new_append(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(41, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64 + 41)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_append(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "High operand of append op is not a bitvector.", "report");

	op = rz_il_op_new_append(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Low operand of append op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_load() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();
	rz_il_validate_global_context_add_mem(ctx, 1, 16, 9);

	RzILOpPure *op = rz_il_op_new_load(1, rz_il_op_new_bitv_from_ut64(16, 123));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(9)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_load(1, rz_il_op_new_bitv_from_ut64(9, 123));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of key operand (9) of load op is not equal to key length 16 of mem 1.", "report");

	op = rz_il_op_new_load(0, rz_il_op_new_bitv_from_ut64(16, 123));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Mem 0 referenced by load op does not exist.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_loadw() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();
	rz_il_validate_global_context_add_mem(ctx, 1, 16, 9);

	RzILOpPure *op = rz_il_op_new_loadw(1, rz_il_op_new_bitv_from_ut64(16, 123), 32);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(32)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_loadw(1, rz_il_op_new_bitv_from_ut64(9, 123), 32);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of key operand (9) of loadw op is not equal to key length 16 of mem 1.", "report");

	op = rz_il_op_new_loadw(0, rz_il_op_new_bitv_from_ut64(16, 123), 32);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Mem 0 referenced by loadw op does not exist.", "report");

	op = rz_il_op_new_loadw(1, rz_il_op_new_bitv_from_ut64(16, 123), 32);
	op->op.loadw.n_bits = 0;
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of loadw op is 0.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_validate_pure_bitv);
	mu_run_test(test_il_validate_pure_bool);
	mu_run_test(test_il_validate_pure_ite);
	mu_run_test(test_il_validate_pure_let);
	mu_run_test(test_il_validate_pure_var);
	mu_run_test(test_il_validate_pure_inv);
	mu_run_test(test_il_validate_pure_bool_binop);
	mu_run_test(test_il_validate_pure_bitv_binop);
	mu_run_test(test_il_validate_pure_bitv_bool_unop);
	mu_run_test(test_il_validate_pure_bitv_unop);
	mu_run_test(test_il_validate_pure_shift);
	mu_run_test(test_il_validate_pure_cmp);
	mu_run_test(test_il_validate_pure_cast);
	mu_run_test(test_il_validate_pure_append);
	mu_run_test(test_il_validate_pure_load);
	mu_run_test(test_il_validate_pure_loadw);
	return tests_passed != tests_run;
}

mu_main(all_tests)
