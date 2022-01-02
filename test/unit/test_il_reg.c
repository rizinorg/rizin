// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_il_reg_binding_derive() {
	// very simple case, just pairwise disjoint regs
	const char *profile_no_overlap =
		"=PC	pc\n"
		"gpr	r1	.64	8	0\n"
		"gpr	r0	.64	0	0\n"
		"gpr	r3	.64	24	0\n"
		"gpr	pc	.64	32	0\n";
	RzReg *reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile_no_overlap);
	RzILRegBinding *rb = rz_il_reg_binding_derive(reg);
	rz_reg_free(reg);
	mu_assert_eq(rb->regs_count, 3, "no overlap count");
	mu_assert_streq(rb->regs[0].name, "r0", "no overlap r0");
	mu_assert_eq(rb->regs[0].size, 64, "bind size");
	mu_assert_streq(rb->regs[1].name, "r1", "no overlap r1");
	mu_assert_eq(rb->regs[1].size, 64, "bind size");
	mu_assert_streq(rb->regs[2].name, "r3", "no overlap r3");
	mu_assert_eq(rb->regs[2].size, 64, "bind size");
	rz_il_reg_binding_free(rb);

	// typical case where some regs are "fully covered" by others
	// only the largest should be bound.
	const char *profile_overlap_classic =
		"gpr	rax	.64	0	0\n"
		"gpr	eax	.32	0	0\n"
		"gpr	ax	.16	0	0\n"
		"gpr	al	.8	0	0\n"
		"gpr	ah	.8	1	0\n"
		"gpr	rbx	.64	8	0\n"
		"gpr	ebx	.32	8	0\n"
		"gpr	bx	.16	8	0\n"
		"gpr	bl	.8	8	0\n"
		"gpr	bh	.8	9	0\n";
	reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile_overlap_classic);
	rb = rz_il_reg_binding_derive(reg);
	rz_reg_free(reg);
	mu_assert_eq(rb->regs_count, 2, "overlap classic count");
	mu_assert_streq(rb->regs[0].name, "rax", "overlap classic rax");
	mu_assert_eq(rb->regs[0].size, 64, "bind size");
	mu_assert_streq(rb->regs[1].name, "rbx", "overlap classic rbx");
	mu_assert_eq(rb->regs[1].size, 64, "bind size");
	rz_il_reg_binding_free(rb);

	// weird, non-fully-covered overlaps
	// here, the ones with the higher offset are removed
	// this is done primarily to keep the binding deterministic.
	const char *profile_overlap_weird =
		"gpr	rax	.64	0	0\n"
		"gpr	eax	.32	7	0\n"
		"gpr	rbx	.64	9	0\n"
		"gpr	ebx	.32	8	0\n";
	reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile_overlap_weird);
	rb = rz_il_reg_binding_derive(reg);
	rz_reg_free(reg);
	mu_assert_eq(rb->regs_count, 2, "overlap weird count");
	mu_assert_streq(rb->regs[0].name, "rax", "overlap weird rax");
	mu_assert_eq(rb->regs[0].size, 64, "bind size");
	mu_assert_streq(rb->regs[1].name, "ebx", "overlap weird ebx");
	mu_assert_eq(rb->regs[1].size, 32, "bind size");
	rz_il_reg_binding_free(rb);

	// different reg types don't affect each other
	const char *profile_multitype =
		"gpr	rax	.64	0	0\n"
		"gpr	xar	.32	0	0\n"
		"drx	eax	.32	0	0\n"
		"fpu	al	.8	0	0\n"
		"fpu	ah	.8	1	0\n";
	reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile_multitype);
	rb = rz_il_reg_binding_derive(reg);
	rz_reg_free(reg);
	mu_assert_eq(rb->regs_count, 4, "overlap multitype");
	mu_assert_streq(rb->regs[0].name, "rax", "overlap multitype rax");
	mu_assert_eq(rb->regs[0].size, 64, "bind size");
	mu_assert_streq(rb->regs[1].name, "eax", "overlap multitype eax");
	mu_assert_eq(rb->regs[1].size, 32, "bind size");
	mu_assert_streq(rb->regs[2].name, "al", "overlap multitype al");
	mu_assert_eq(rb->regs[2].size, 8, "bind size");
	mu_assert_streq(rb->regs[3].name, "ah", "overlap multitype ah");
	mu_assert_eq(rb->regs[3].size, 8, "bind size");
	rz_il_reg_binding_free(rb);

	// overlapping regs, but also flags
	const char *profile_flags =
		"gpr	rax	.64	0	0\n"
		"gpr	eax	.32	0	0\n"
		"gpr	ax	.16	0	0\n"
		"gpr	al	.8	0	0\n"
		"gpr	ah	.8	1	0\n"
		"gpr	rbx	.64	8	0\n"
		"gpr	ebx	.32	8	0\n"
		"gpr	bx	.16	8	0\n"
		"gpr	bl	.8	8	0\n"
		"gpr	bh	.8	9	0\n"
		"gpr	sreg	.8	40	0\n"
		"gpr	cf	.1	40.0	0\n"
		"gpr	zf	.1	40.1	0\n"
		"gpr	nf	.1	40.2	0\n"
		"gpr	vf	.1	40.3	0\n"
		"gpr	hfsf	.2	40.4	0\n" // this one is two bits and covered, but should still be kept
		"gpr	tf	.1	40.6	0\n"
		"gpr	if	.1	40.7	0\n";
	reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile_flags);
	rb = rz_il_reg_binding_derive(reg);
	rz_reg_free(reg);
	mu_assert_eq(rb->regs_count, 9, "overlap flags count");
	// flags
	mu_assert_streq(rb->regs[0].name, "cf", "overlap flags rax");
	mu_assert_eq(rb->regs[0].size, 1, "bind size");
	mu_assert_streq(rb->regs[1].name, "zf", "overlap flags rax");
	mu_assert_eq(rb->regs[1].size, 1, "bind size");
	mu_assert_streq(rb->regs[2].name, "nf", "overlap flags rax");
	mu_assert_eq(rb->regs[2].size, 1, "bind size");
	mu_assert_streq(rb->regs[3].name, "vf", "overlap flags rax");
	mu_assert_eq(rb->regs[3].size, 1, "bind size");
	mu_assert_streq(rb->regs[4].name, "tf", "overlap flags rax");
	mu_assert_eq(rb->regs[4].size, 1, "bind size");
	mu_assert_streq(rb->regs[5].name, "if", "overlap flags rax");
	mu_assert_eq(rb->regs[5].size, 1, "bind size");
	// regular regs
	mu_assert_streq(rb->regs[6].name, "rax", "overlap flags rax");
	mu_assert_eq(rb->regs[6].size, 64, "bind size");
	mu_assert_streq(rb->regs[7].name, "rbx", "overlap flags rbx");
	mu_assert_eq(rb->regs[7].size, 64, "bind size");
	// still kept this one
	mu_assert_streq(rb->regs[8].name, "hfsf", "overlap flags rbx");
	mu_assert_eq(rb->regs[8].size, 2, "bind size");
	rz_il_reg_binding_free(rb);

	mu_end;
}

static bool test_il_vm_sync_to_reg() {
	const char *profile =
		"=PC	pc\n"
		"gpr	r1	.32	8	0\n"
		"gpr	r0	.64	0	0\n"
		"gpr	r3	.64	24	0\n"
		"gpr	pc	.64	32	0\n";
	const char *bind[] = { "r0", "r1" };

	RzReg *reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile);
	rz_reg_setv(reg, "r0", 0x1234);
	rz_reg_setv(reg, "r1", 0x5678);
	rz_reg_setv(reg, "r3", 0xc0ffee);
	rz_reg_setv(reg, "pc", 0x0);

	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILRegBinding *rb = rz_il_reg_binding_exactly(reg, RZ_ARRAY_SIZE(bind), bind);
	rz_il_vm_setup_reg_binding(vm, rb);

	RzILVar *var = rz_il_find_var_by_name(vm, "r0");
	mu_assert_notnull(var, "var");
	rz_il_hash_bind(vm, var, rz_il_vm_fortify_bitv(vm, rz_bv_new_from_ut64(64, 0x8247abc)));
	var = rz_il_find_var_by_name(vm, "r1");
	mu_assert_notnull(var, "var");
	rz_il_hash_bind(vm, var, rz_il_vm_fortify_bitv(vm, rz_bv_new_from_ut64(32, 0xfed134)));

	rz_bv_set_from_ut64(vm->pc, 0x10001);

	rz_il_vm_sync_to_reg(vm, reg);
	mu_assert_eq(rz_reg_getv(reg, "r0"), 0x8247abc, "reg from vm");
	mu_assert_eq(rz_reg_getv(reg, "r1"), 0xfed134, "reg from vm");
	mu_assert_eq(rz_reg_getv(reg, "pc"), 0x10001, "reg from vm");

	rz_reg_free(reg);
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_il_vm_sync_from_reg() {
	const char *profile =
		"=PC	pc\n"
		"gpr	r1	.32	8	0\n"
		"gpr	r0	.64	0	0\n"
		"gpr	r3	.64	24	0\n"
		"gpr	pc	.64	32	0\n";
	const char *bind[] = { "r0", "r1" };

	RzReg *reg = rz_reg_new();
	rz_reg_set_profile_string(reg, profile);
	rz_reg_setv(reg, "r0", 0x1234);
	rz_reg_setv(reg, "r1", 0x5678);
	rz_reg_setv(reg, "r3", 0xc0ffee);
	rz_reg_setv(reg, "pc", 0x10001);

	RzILVM *vm = rz_il_vm_new(0, 64, false);
	RzILRegBinding *rb = rz_il_reg_binding_exactly(reg, RZ_ARRAY_SIZE(bind), bind);
	rz_il_vm_setup_reg_binding(vm, rb);

	rz_il_vm_sync_from_reg(vm, reg);
	RzILVal *val = rz_il_hash_find_val_by_name(vm, "r0");
	mu_assert_notnull(val, "val");
	mu_assert_eq(val->type, RZIL_VAR_TYPE_BV, "val type");
	mu_assert_eq(rz_bv_len(val->data.bv), 64, "val len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 0x1234, "val val");
	val = rz_il_hash_find_val_by_name(vm, "r1");
	mu_assert_notnull(val, "val");
	mu_assert_eq(val->type, RZIL_VAR_TYPE_BV, "val type");
	mu_assert_eq(rz_bv_len(val->data.bv), 32, "val len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 0x5678, "val val");
	RzILVar *var = rz_il_find_var_by_name(vm, "r3");
	mu_assert_null(var, "unbound");

	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x10001, "pc");

	rz_reg_free(reg);
	rz_il_vm_free(vm);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_reg_binding_derive);
	mu_run_test(test_il_vm_sync_to_reg);
	mu_run_test(test_il_vm_sync_from_reg);
	return tests_passed != tests_run;
}

mu_main(all_tests)
