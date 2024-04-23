// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"
#include "rz_il/rz_il_opcodes.h"
#include "rz_il/rz_il_vm.h"

static bool test_il_extract32() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 32, false);
	RzILVal *vm_result = NULL;

	// Extract all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(32, 0x01234567);
	RzILOpBitVector *start = rz_il_op_new_bitv_from_ut64(32, 0);
	RzILOpBitVector *len = rz_il_op_new_bitv_from_ut64(32, 32);
	RzILOpBitVector *result = rz_il_extract32(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x01234567, "extract32(0x01234567, 0, 32) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Extract none
	val = rz_il_op_new_bitv_from_ut64(32, 0x01234567);
	start = rz_il_op_new_bitv_from_ut64(32, 0);
	len = rz_il_op_new_bitv_from_ut64(32, 0);
	result = rz_il_extract32(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0, "extract32(0x01234567, 0, 0) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Extract within
	val = rz_il_op_new_bitv_from_ut64(32, 0x01234567);
	start = rz_il_op_new_bitv_from_ut64(32, 4);
	len = rz_il_op_new_bitv_from_ut64(32, 5);
	result = rz_il_extract32(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x16, "extract32(0x01234567, 4, 5) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_extract64() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILVal *vm_result = NULL;

	// Extract all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	RzILOpBitVector *start = rz_il_op_new_bitv_from_ut64(64, 0);
	RzILOpBitVector *len = rz_il_op_new_bitv_from_ut64(32, 64);
	RzILOpBitVector *result = rz_il_extract64(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0123456789abcdef, "extract64(0x0123456789abcdef, 0, 64) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Extract none
	val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	start = rz_il_op_new_bitv_from_ut64(64, 0);
	len = rz_il_op_new_bitv_from_ut64(32, 0);
	result = rz_il_extract64(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0, "extract64(0x0123456789abcdef, 0, 0) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Extract within
	val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	start = rz_il_op_new_bitv_from_ut64(64, 4);
	len = rz_il_op_new_bitv_from_ut64(32, 5);
	result = rz_il_extract64(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x1e, "extract64(0x0123456789abcdef, 4, 5) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_sextract64() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILVal *vm_result = NULL;

	// Extract all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	RzILOpBitVector *start = rz_il_op_new_bitv_from_ut64(32, 0);
	RzILOpBitVector *len = rz_il_op_new_bitv_from_ut64(32, 64);
	RzILOpBitVector *result = rz_il_sextract64(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0123456789abcdef, "sextract64(0x0123456789abcdef, 0, 64) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Extract none
	val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	start = rz_il_op_new_bitv_from_ut64(32, 0);
	len = rz_il_op_new_bitv_from_ut64(32, 0);
	result = rz_il_sextract64(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0, "sextract64(0x0123456789abcdef, 0, 0) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Extract within
	val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	start = rz_il_op_new_bitv_from_ut64(32, 28);
	len = rz_il_op_new_bitv_from_ut64(32, 4);
	result = rz_il_sextract64(val, start, len);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0xfffffffffffffff8, "extract64(0x0123456789abcdef, 28, 4) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_deposit32() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 32, false);
	RzILVal *vm_result = NULL;

	// Deposit all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(32, 0x00000000);
	RzILOpBitVector *field = rz_il_op_new_bitv_from_ut64(32, 0xffffffff);
	RzILOpBitVector *start = rz_il_op_new_bitv_from_ut64(32, 0);
	RzILOpBitVector *len = rz_il_op_new_bitv_from_ut64(32, 32);
	RzILOpBitVector *result = rz_il_deposit32(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0xffffffff, "deposit32(0x00000000, 0, 32, 0xffffffff) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Deposit none
	val = rz_il_op_new_bitv_from_ut64(32, 0x00000000);
	field = rz_il_op_new_bitv_from_ut64(32, 0xffffffff);
	start = rz_il_op_new_bitv_from_ut64(32, 0);
	len = rz_il_op_new_bitv_from_ut64(32, 0);
	result = rz_il_deposit32(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0, "deposit32(0x00000000, 0, 0, 0xffffffff) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Deposit within
	val = rz_il_op_new_bitv_from_ut64(32, 0xffffffff);
	field = rz_il_op_new_bitv_from_ut64(32, 0x0);
	start = rz_il_op_new_bitv_from_ut64(32, 8);
	len = rz_il_op_new_bitv_from_ut64(32, 7);
	result = rz_il_deposit32(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0xffff80ff, "deposit32(0xffffffff, 8, 7, 0xffff80ff) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Deposit no wrap around
	val = rz_il_op_new_bitv_from_ut64(32, 0xffffffff);
	field = rz_il_op_new_bitv_from_ut64(32, 0x0);
	start = rz_il_op_new_bitv_from_ut64(32, 30);
	len = rz_il_op_new_bitv_from_ut64(32, 9);
	result = rz_il_deposit32(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x3fffffff, "deposit32(0xffffffff, 30, 9, 0x0) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_deposit64() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 32, false);
	RzILVal *vm_result = NULL;

	// Deposit all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(64, 0x0);
	RzILOpBitVector *field = rz_il_op_new_bitv_from_ut64(64, 0xffffffffffffffff);
	RzILOpBitVector *start = rz_il_op_new_bitv_from_ut64(32, 0);
	RzILOpBitVector *len = rz_il_op_new_bitv_from_ut64(32, 64);
	RzILOpBitVector *result = rz_il_deposit64(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0xffffffffffffffff, "deposit64(0x00000000, 0, 64, 0xffffffffffffffff) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Deposit none
	val = rz_il_op_new_bitv_from_ut64(64, 0x0);
	field = rz_il_op_new_bitv_from_ut64(64, 0xffffffffffffffff);
	start = rz_il_op_new_bitv_from_ut64(32, 0);
	len = rz_il_op_new_bitv_from_ut64(32, 0);
	result = rz_il_deposit64(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x0, "deposit64(0x00000000, 0, 0, 0xffffffffffffffff) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Deposit within
	val = rz_il_op_new_bitv_from_ut64(64, 0xffffffffffffffff);
	field = rz_il_op_new_bitv_from_ut64(64, 0x0);
	start = rz_il_op_new_bitv_from_ut64(32, 8);
	len = rz_il_op_new_bitv_from_ut64(32, 7);
	result = rz_il_deposit64(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0xffffffffffff80ff, "deposit64(0xffffffffffffffff, 8, 7, 0xffff80ff) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	// Deposit no wrap around
	val = rz_il_op_new_bitv_from_ut64(64, 0xffffffffffffffff);
	field = rz_il_op_new_bitv_from_ut64(64, 0x0);
	start = rz_il_op_new_bitv_from_ut64(32, 62);
	len = rz_il_op_new_bitv_from_ut64(32, 9);
	result = rz_il_deposit64(val, start, len, field);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x3fffffffffffffff, "deposit64(0xffffffffffffffff, 62, 9, 0x0) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_bswap16() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 32, false);
	RzILVal *vm_result = NULL;

	// Deposit all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(16, 0x0123);
	RzILOpBitVector *result = rz_il_bswap16(val);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x2301, "bswap16(0x0123) resulting value mismatch.");
	rz_il_vm_free(vm);
	rz_il_op_pure_free(result);

	rz_il_validate_global_context_free(ctx);
	rz_il_value_free(vm_result);

	mu_end;
}

static bool test_il_bswap32() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 32, false);
	RzILVal *vm_result = NULL;

	// Deposit all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(32, 0x01234567);
	RzILOpBitVector *result = rz_il_bswap32(val);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0x67452301, "bswap32(0x01234567) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_bswap64() {
	RzILSortPure sort;
	RzILValidateReport report;
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	bool valid = false;
	RzILVM *vm = rz_il_vm_new(0, 32, false);
	RzILVal *vm_result = NULL;

	// Deposit all
	RzILOpBitVector *val = rz_il_op_new_bitv_from_ut64(64, 0x0123456789abcdef);
	RzILOpBitVector *result = rz_il_bswap64(val);

	valid = rz_il_validate_pure(result, ctx, &sort, &report);
	mu_assert_true(valid, "invalid pure");
	vm_result = rz_il_evaluate_val(vm, result);
	mu_assert_eq(vm_result->data.bv->bits.small_u, 0xefcdab8967452301, "bswap64(0x0123456789abcdef) resulting value mismatch.");
	rz_il_value_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);

	mu_end;
}

static bool test_il_fneq() {
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILBool *vm_result = NULL;
	RzILOpBool *result = NULL;

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337 != 0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(0.1337001), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337001 != 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(-0.1337001), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337001 != -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 != -0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 != 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 != -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fneq(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337 != 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);

	mu_end;
}

static bool test_il_feq() {
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILBool *vm_result = NULL;
	RzILOpBool *result = NULL;

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337 == 0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(0.1337001), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337001 == 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(-0.1337001), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337001 == -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 == -0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 == 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 == -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_feq(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337 == 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);

	mu_end;
}

static bool test_il_flt() {
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILBool *vm_result = NULL;
	RzILOpBool *result = NULL;

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337 < 0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(0.1337001), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337001 < 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(-0.1337001), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337001 < -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 < -0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 < 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 < -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_flt(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337 < 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);

	mu_end;
}

static bool test_il_fle() {
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILBool *vm_result = NULL;
	RzILOpBool *result = NULL;

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337 <= 0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(0.1337001), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337001 <= 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(-0.1337001), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337001 <= -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 <= -0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 <= 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 <= -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fle(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337 <= 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);

	mu_end;
}

static bool test_il_fgt() {
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILBool *vm_result = NULL;
	RzILOpBool *result = NULL;

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337 > 0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(0.1337001), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337001 > 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(-0.1337001), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337001 > -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 > -0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 > 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 > -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fgt(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337 > 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);

	mu_end;
}

static bool test_il_fge() {
	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILBool *vm_result = NULL;
	RzILOpBool *result = NULL;

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "0.1337 >= 0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(0.1337001), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337001 >= 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(-0.1337001), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337001 >= -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337001));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 >= -0.1337001");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_false(vm_result->b, "-0.1337 >= 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(-0.1337), rz_il_op_new_float_from_f32(-0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "-0.1337 >= -0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	result = rz_il_op_new_fge(rz_il_op_new_float_from_f32(0.1337), rz_il_op_new_float_from_f32(0.1337));
	vm_result = rz_il_evaluate_bool(vm, result);
	mu_assert_true(vm_result->b, "0.1337 >= 0.1337");
	rz_il_bool_free(vm_result);
	rz_il_op_pure_free(result);

	rz_il_vm_free(vm);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_extract32);
	mu_run_test(test_il_extract64);
	mu_run_test(test_il_sextract64);
	mu_run_test(test_il_deposit32);
	mu_run_test(test_il_deposit64);
	mu_run_test(test_il_bswap16);
	mu_run_test(test_il_bswap32);
	mu_run_test(test_il_bswap64);
	mu_run_test(test_il_fneq);
	mu_run_test(test_il_feq);
	mu_run_test(test_il_flt);
	mu_run_test(test_il_fle);
	mu_run_test(test_il_fgt);
	mu_run_test(test_il_fge);

	return tests_passed != tests_run;
}

mu_main(all_tests)
