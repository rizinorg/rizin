// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_rzil_vm_init() {
	RzILVM *vm = RZ_NEW0(struct rz_il_vm_t);
	mu_assert_notnull(vm, "Create VM");
	rz_il_vm_init(vm, 0, 8, 8);
	mu_assert_eq(vm->addr_size, 8, "VM Init");
	rz_il_vm_close(vm);
	mu_end;
}

static bool test_rzil_vm_basic_operation() {
	RzILVM *vm = RZ_NEW0(struct rz_il_vm_t);
	mu_assert_notnull(vm, "Create vm");
	rz_il_vm_init(vm, 0, 8, 16);

	// 1. create variables
	RzILVar *var_r1 = rz_il_vm_create_variable(vm, "r1");
	RzILVar *var_r2 = rz_il_vm_create_variable(vm, "r2");
	mu_assert_notnull(var_r1, "Create var 1");
	mu_assert_notnull(var_r2, "Create var 2");

	// check name
	mu_assert_streq(var_r1->var_name, "r1", "var r1 name");
	mu_assert_streq(var_r2->var_name, "r2", "var r2 name");

	// check type
	mu_assert_eq(var_r1->type, RZIL_VAR_TYPE_UNK, "var r1 type unk");
	mu_assert_eq(var_r2->type, RZIL_VAR_TYPE_UNK, "var r2 type unk");

	// 2. find vars from vm
	RzILVar *find_var_r1 = rz_il_find_var_by_name(vm, "r1");
	RzILVar *find_var_r2 = rz_il_find_var_by_name(vm, "r2");
	mu_assert_eq(var_r1, find_var_r1, "Store and find r1");
	mu_assert_eq(var_r2, find_var_r2, "Store and find r2");

	// 3. create value
	RzILVal *val_r1 = rz_il_vm_create_value(vm, RZIL_VAR_TYPE_BV);
	RzILVal *val_r2 = rz_il_vm_create_value(vm, RZIL_VAR_TYPE_BOOL);
	mu_assert_notnull(val_r1, "Create val 1");
	mu_assert_notnull(val_r2, "Create val 2");

	// check type
	mu_assert_eq(val_r1->type, RZIL_VAR_TYPE_BV, "val 1 has type bitv");
	mu_assert_eq(val_r2->type, RZIL_VAR_TYPE_BOOL, "val 2 has type bool");

	// 4. bind value to var
	rz_il_hash_bind(vm, var_r1, val_r1);
	rz_il_hash_bind(vm, var_r2, val_r2);
	RzILVal *find_val_r1 = rz_il_hash_find_val_by_name(vm, "r1");
	RzILVal *find_val_r2 = rz_il_hash_find_val_by_name(vm, "r2");
	mu_assert_eq(val_r1, find_val_r1, "Bind and find");
	mu_assert_eq(val_r2, find_val_r2, "Bind and find");

	// 5. cancel binding
	rz_il_hash_cancel_binding(vm, var_r1);
	RzILVal *null_val = rz_il_hash_find_val_by_name(vm, "r1");
	mu_assert_null(null_val, "Cancel binding");

	// 6. bind to another one
	rz_il_hash_bind(vm, var_r1, val_r2);
	RzILVal *cur_var_r1_value = rz_il_hash_find_val_by_name(vm, "r1");
	RzILVal *cur_var_r2_value = rz_il_hash_find_val_by_name(vm, "r2");
	mu_assert_eq(cur_var_r1_value, cur_var_r2_value, "Bind to the same value");

	// 7. create label
	RzILBitVector *addr = rz_il_bv_new_from_ut32(16, 233);
	RzILEffectLabel *blackhole = rz_il_vm_create_label(vm, "blackhole", addr);

	// default type is LABEL_ADDR
	mu_assert_eq(blackhole->type, EFFECT_LABEL_ADDR, "Label type");
	mu_assert_streq(blackhole->label_id, "blackhole", "Label name");

	bool is_equal_bv = rz_il_bv_cmp(blackhole->addr, addr) == 0 ? true : false;
	mu_assert("Label address correct", is_equal_bv);

	// find label
	RzILEffectLabel *find_blackhole = rz_il_vm_find_label_by_name(vm, "blackhole");
	mu_assert_eq(blackhole, find_blackhole, "Find Label");

	RzILBitVector *find_addr = rz_il_hash_find_addr_by_lblname(vm, "blackhole");
	is_equal_bv = rz_il_bv_cmp(find_addr, addr) == 0 ? true : false;
	mu_assert("Find address equal", is_equal_bv);

	// 8. create label lazy (without giving an address)
	RzILEffectLabel *lazy = rz_il_vm_create_label_lazy(vm, "lazy");
	RzILEffectLabel *find_lazy = rz_il_vm_find_label_by_name(vm, "lazy");
	mu_assert_eq(lazy, find_lazy, "Find lazy label");

	RzILBitVector *lazy_addr = rz_il_hash_find_addr_by_lblname(vm, "lazy");
	mu_assert_null(lazy_addr, "Lazy label have NULL address");

	// 9. update the address of lazy label
	rz_il_vm_update_label(vm, "lazy", addr);
	lazy_addr = rz_il_hash_find_addr_by_lblname(vm, "lazy");
	is_equal_bv = rz_il_bv_cmp(lazy_addr, addr) == 0 ? true : false;
	mu_assert("Update lazy label successfully", is_equal_bv);

	rz_il_bv_free(addr);
	rz_il_vm_close(vm);
	mu_end;
}

static bool test_rzil_vm_operation() {
	RzILVM *vm = RZ_NEW0(struct rz_il_vm_t);
	rz_il_vm_init(vm, 0, 8, 16);

	// 1. create register r0 and r1
	rz_il_vm_add_reg(vm, "r0", 8);
	rz_il_vm_add_reg(vm, "r1", 8);

	RzILVar *reg_r0 = rz_il_find_var_by_name(vm, "r0");
	RzILVar *reg_r1 = rz_il_find_var_by_name(vm, "r1");
	mu_assert_streq(reg_r0->var_name, "r0", "register name r0");
	mu_assert_streq(reg_r1->var_name, "r1", "register name r1");

	RzILVal *val_r0 = rz_il_hash_find_val_by_name(vm, "r0");
	RzILVal *val_r1 = rz_il_hash_find_val_by_name(vm, "r1");
	mu_assert_eq(val_r0->type, RZIL_VAR_TYPE_BV, "r0 is bitvector");
	mu_assert_eq(val_r1->type, RZIL_VAR_TYPE_BV, "r1 is bitvector");

	RzILVal *r0 = rz_il_hash_find_val_by_name(vm, "r0");
	RzILVal *r1 = rz_il_hash_find_val_by_name(vm, "r1");

	bool is_zero = rz_il_bv_is_zero_vector(r0->data.bv);
	mu_assert("Init r0 as all zero bitvector", is_zero);

	is_zero = rz_il_bv_is_zero_vector(r1->data.bv);
	mu_assert("Init r1 as all zero bitvector", is_zero);

	rz_il_vm_close(vm);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_vm_init);
	mu_run_test(test_rzil_vm_basic_operation);
	mu_run_test(test_rzil_vm_operation);
	return tests_passed != tests_run;
}

mu_main(all_tests)