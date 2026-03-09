// SPDX-FileCopyrightText: 2024 rizinorg
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Tests to verify pointer ownership semantics for functions annotated
 * with RZ_OWN and RZ_BORROW (issue #5870).
 *
 * RZ_OWN functions must return newly allocated memory that the caller can free.
 * RZ_BORROW functions must return pointers to existing internal data.
 */

#include <rz_util.h>
#include <rz_hash.h>
#include <rz_config.h>
#include <rz_search.h>
#include <rz_il.h>
#include <rz_core.h>
#include <rz_type.h>
#include "minunit.h"

// ==================== RZ_OWN tests ====================
// These tests verify that _new/_dup/_cast functions return
// owned pointers that the caller is responsible for freeing.

bool test_rz_hash_new_ownership(void) {
	RzHash *rh = rz_hash_new();
	mu_assert_notnull(rh, "rz_hash_new should return a non-null owned pointer");
	rz_hash_free(rh);
	mu_end;
}

bool test_rz_config_hold_new_ownership(void) {
	RzConfig *cfg = rz_config_new(NULL);
	mu_assert_notnull(cfg, "rz_config_new should return non-null");

	RzConfigHold *hold = rz_config_hold_new(cfg);
	mu_assert_notnull(hold, "rz_config_hold_new should return a non-null owned pointer");
	rz_config_hold_free(hold);

	rz_config_free(cfg);
	mu_end;
}

bool test_rz_type_db_new_ownership(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "rz_type_db_new should return a non-null owned pointer");
	rz_type_db_free(typedb);
	mu_end;
}

bool test_rz_event_new_ownership(void) {
	RzEvent *ev = rz_event_new(NULL);
	mu_assert_notnull(ev, "rz_event_new should return a non-null owned pointer");
	rz_event_free(ev);
	mu_end;
}

bool test_rz_annotated_code_new_ownership(void) {
	char *code = strdup("int main() { return 0; }");
	RzAnnotatedCode *ac = rz_annotated_code_new(code);
	mu_assert_notnull(ac, "rz_annotated_code_new should return a non-null owned pointer");
	rz_annotated_code_free(ac);
	mu_end;
}

bool test_rz_search_new_ownership(void) {
	RzSearch *s = rz_search_new(RZ_SEARCH_KEYWORD);
	mu_assert_notnull(s, "rz_search_new should return a non-null owned pointer");
	rz_search_free(s);
	mu_end;
}

bool test_rz_search_keyword_new_str_ownership(void) {
	RzSearchKeyword *kw = rz_search_keyword_new_str("hello", NULL, NULL, 0);
	mu_assert_notnull(kw, "rz_search_keyword_new_str should return a non-null owned pointer");
	rz_search_keyword_free(kw);
	mu_end;
}

bool test_rz_search_keyword_new_hex_ownership(void) {
	RzSearchKeyword *kw = rz_search_keyword_new_hex("deadbeef", NULL, NULL);
	mu_assert_notnull(kw, "rz_search_keyword_new_hex should return a non-null owned pointer");
	rz_search_keyword_free(kw);
	mu_end;
}

bool test_rz_il_bool_new_ownership(void) {
	RzILBool *b = rz_il_bool_new(true);
	mu_assert_notnull(b, "rz_il_bool_new should return a non-null owned pointer");
	mu_assert_eq(b->b, true, "bool value should be true");
	rz_il_bool_free(b);
	mu_end;
}

bool test_rz_il_bool_and_ownership(void) {
	RzILBool *a = rz_il_bool_new(true);
	RzILBool *b = rz_il_bool_new(false);

	RzILBool *result = rz_il_bool_and(a, b);
	mu_assert_notnull(result, "rz_il_bool_and should return a non-null owned pointer");
	mu_assert_eq(result->b, false, "true AND false = false");

	// Result is a NEW allocation, distinct from inputs
	mu_assert_ptrneq(result, a, "result should be a new allocation, not input a");
	mu_assert_ptrneq(result, b, "result should be a new allocation, not input b");

	rz_il_bool_free(result);
	rz_il_bool_free(a);
	rz_il_bool_free(b);
	mu_end;
}

bool test_rz_il_bool_or_ownership(void) {
	RzILBool *a = rz_il_bool_new(false);
	RzILBool *b = rz_il_bool_new(true);

	RzILBool *result = rz_il_bool_or(a, b);
	mu_assert_notnull(result, "rz_il_bool_or should return a non-null owned pointer");
	mu_assert_eq(result->b, true, "false OR true = true");
	mu_assert_ptrneq(result, a, "result should be a new allocation");
	mu_assert_ptrneq(result, b, "result should be a new allocation");

	rz_il_bool_free(result);
	rz_il_bool_free(a);
	rz_il_bool_free(b);
	mu_end;
}

bool test_rz_il_bool_not_ownership(void) {
	RzILBool *a = rz_il_bool_new(true);

	RzILBool *result = rz_il_bool_not(a);
	mu_assert_notnull(result, "rz_il_bool_not should return a non-null owned pointer");
	mu_assert_eq(result->b, false, "NOT true = false");
	mu_assert_ptrneq(result, a, "result should be a new allocation");

	rz_il_bool_free(result);
	rz_il_bool_free(a);
	mu_end;
}

bool test_rz_il_bool_xor_ownership(void) {
	RzILBool *a = rz_il_bool_new(true);
	RzILBool *b = rz_il_bool_new(true);

	RzILBool *result = rz_il_bool_xor(a, b);
	mu_assert_notnull(result, "rz_il_bool_xor should return a non-null owned pointer");
	mu_assert_eq(result->b, false, "true XOR true = false");
	mu_assert_ptrneq(result, a, "result should be a new allocation");

	rz_il_bool_free(result);
	rz_il_bool_free(a);
	rz_il_bool_free(b);
	mu_end;
}

bool test_rz_il_mem_load_ownership(void) {
	ut8 data[] = { 0x0, 0x42, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	RzILMem *mem = rz_il_mem_new_owned(buf, 16);
	mu_assert_notnull(mem, "Create mem");

	RzBitVector *addr = rz_bv_new_from_ut64(16, 1);
	RzBitVector *val = rz_il_mem_load(mem, addr);
	mu_assert_notnull(val, "rz_il_mem_load should return a non-null owned pointer");
	mu_assert_eq(rz_bv_to_ut64(val), 0x42, "loaded value");

	// val is a NEW allocation that the caller owns
	rz_bv_free(val);
	rz_bv_free(addr);
	rz_il_mem_free(mem);
	mu_end;
}

bool test_rz_il_mem_loadw_ownership(void) {
	ut8 data[] = { 0x0, 0x13, 0x37, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	RzILMem *mem = rz_il_mem_new_owned(buf, 16);
	mu_assert_notnull(mem, "Create mem");

	RzBitVector *addr = rz_bv_new_from_ut64(16, 1);
	RzBitVector *val = rz_il_mem_loadw(mem, addr, 16, true);
	mu_assert_notnull(val, "rz_il_mem_loadw should return a non-null owned pointer");
	mu_assert_eq(rz_bv_len(val), 16, "loadw size");
	mu_assert_eq(rz_bv_to_ut64(val), 0x1337, "loadw val (big endian)");

	rz_bv_free(val);
	rz_bv_free(addr);
	rz_il_mem_free(mem);
	mu_end;
}

bool test_rz_il_op_pure_dup_ownership(void) {
	RzILOpPure *op = rz_il_op_new_bitv_from_ut64(32, 0xdeadbeef);
	mu_assert_notnull(op, "original op");

	RzILOpPure *dup = rz_il_op_pure_dup(op);
	mu_assert_notnull(dup, "rz_il_op_pure_dup should return a non-null owned pointer");
	mu_assert_ptrneq(dup, op, "dup should be a distinct allocation from original");

	rz_il_op_pure_free(dup);
	rz_il_op_pure_free(op);
	mu_end;
}

bool test_rz_il_effect_label_dup_ownership(void) {
	RzILEffectLabel *lbl = rz_il_effect_label_new("test_label", RZ_IL_EFFECT_LABEL_SYSCALL);
	mu_assert_notnull(lbl, "original label");

	RzILEffectLabel *dup = rz_il_effect_label_dup(lbl);
	mu_assert_notnull(dup, "rz_il_effect_label_dup should return a non-null owned pointer");
	mu_assert_ptrneq(dup, lbl, "dup should be a distinct allocation from original");
	mu_assert_streq(dup->label_id, lbl->label_id, "dup should have same label");
	mu_assert_eq(dup->type, lbl->type, "dup should have same type");

	rz_il_effect_label_free(dup);
	rz_il_effect_label_free(lbl);
	mu_end;
}

bool test_rz_bv_cast_ownership(void) {
	RzBitVector *bv = rz_bv_new_from_ut64(16, 0x1234);
	mu_assert_notnull(bv, "original bv");

	RzBitVector *cast = rz_bv_cast(bv, 32, false);
	mu_assert_notnull(cast, "rz_bv_cast should return a non-null owned pointer");
	mu_assert_ptrneq(cast, bv, "cast should be a distinct allocation from original");
	mu_assert_eq(rz_bv_len(cast), 32, "cast should have new size");
	mu_assert_eq(rz_bv_to_ut64(cast), 0x1234, "cast value should be preserved");

	rz_bv_free(cast);
	rz_bv_free(bv);
	mu_end;
}

// ==================== RZ_BORROW tests ====================
// These tests verify that _get functions return internal pointers
// that the caller must NOT free.

bool test_rz_strbuf_get_borrow(void) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_strbuf_set(&sb, "hello world");

	// rz_strbuf_get returns a BORROWED pointer to internal data
	char *ptr = rz_strbuf_get(&sb);
	mu_assert_notnull(ptr, "rz_strbuf_get should return non-null");
	mu_assert_streq(ptr, "hello world", "rz_strbuf_get content");

	// Modifying the strbuf should be reflected in the borrowed pointer
	// (it may point to a different address after set, but that's fine)
	rz_strbuf_set(&sb, "changed");
	char *ptr2 = rz_strbuf_get(&sb);
	mu_assert_streq(ptr2, "changed", "borrowed pointer reflects changes");

	// Do NOT free ptr — it's borrowed
	rz_strbuf_fini(&sb);
	mu_end;
}

bool test_rz_strbuf_getbin_borrow(void) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_strbuf_setbin(&sb, (const ut8 *)"\x01\x02\x03\x04", 4);

	size_t len = 0;
	ut8 *bin = rz_strbuf_getbin(&sb, &len);
	mu_assert_notnull(bin, "rz_strbuf_getbin should return non-null");
	mu_assert_eq(len, 4, "binary length");
	mu_assert_memeq(bin, (const ut8 *)"\x01\x02\x03\x04", 4, "binary content");

	// Do NOT free bin — it's borrowed
	rz_strbuf_fini(&sb);
	mu_end;
}

bool test_rz_il_validate_context_new_ownership(void) {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(32);
	mu_assert_notnull(ctx, "rz_il_validate_global_context_new_empty should return a non-null owned pointer");
	rz_il_validate_global_context_free(ctx);
	mu_end;
}

bool all_tests() {
	// RZ_OWN tests — verify functions return owned, freeable pointers
	mu_run_test(test_rz_hash_new_ownership);
	mu_run_test(test_rz_config_hold_new_ownership);
	mu_run_test(test_rz_type_db_new_ownership);
	mu_run_test(test_rz_event_new_ownership);
	mu_run_test(test_rz_annotated_code_new_ownership);
	mu_run_test(test_rz_search_new_ownership);
	mu_run_test(test_rz_search_keyword_new_str_ownership);
	mu_run_test(test_rz_search_keyword_new_hex_ownership);
	mu_run_test(test_rz_il_bool_new_ownership);
	mu_run_test(test_rz_il_bool_and_ownership);
	mu_run_test(test_rz_il_bool_or_ownership);
	mu_run_test(test_rz_il_bool_not_ownership);
	mu_run_test(test_rz_il_bool_xor_ownership);
	mu_run_test(test_rz_il_mem_load_ownership);
	mu_run_test(test_rz_il_mem_loadw_ownership);
	mu_run_test(test_rz_il_op_pure_dup_ownership);
	mu_run_test(test_rz_il_effect_label_dup_ownership);
	mu_run_test(test_rz_bv_cast_ownership);
	mu_run_test(test_rz_il_validate_context_new_ownership);

	// RZ_BORROW tests — verify functions return internal pointers
	mu_run_test(test_rz_strbuf_get_borrow);
	mu_run_test(test_rz_strbuf_getbin_borrow);

	return tests_passed != tests_run;
}

mu_main(all_tests)
