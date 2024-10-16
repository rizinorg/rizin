// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"
#include <rz_rop.h>

// Define the register profile string for your architecture
#define REGISTER_PROFILE_STRING \
	"=PC   trip\n" \
	"=SP   rsp\n" \
	"=BP   rbp\n" \
	"=A0   rdi\n" \
	"=A1   rsi\n" \
	"=A2   rdx\n" \
	"=A3   rcx\n" \
	"=A4   r8\n" \
	"=A5   r9\n" \
	"=A6   r10\n" \
	"=A7   r11\n" \
	"=SN   rax\n" \
	"gpr    rax    .64    80    0\n" \
	"gpr    eax    .32    80    0\n" \
	"gpr    ax     .16    80    0\n" \
	"gpr    al     .8     80    0\n" \
	"gpr    ah     .8     81    0\n" \
	"gpr    rbx    .64    40    0\n" \
	"gpr    ebx    .32    40    0\n" \
	"gpr    bx     .16    40    0\n" \
	"gpr    bl     .8     40    0\n" \
	"gpr    bh     .8     41    0\n"

static void setup_rz_core(RzCore *core) {
	rz_config_set(core->config, "analysis.arch", "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_reg_set_profile_string(core->analysis->reg, REGISTER_PROFILE_STRING);
}

bool test_parse_reg_to_const(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rz_core(core);

	// Test case 1: Valid register to constant
	char str1[] = " eax =    123 ";
	RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, str1);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_CONST, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_null(rop_constraint->args[SRC_REG], "Source register should be NULL");
	mu_assert_streq(rop_constraint->args[SRC_CONST], "123", "Invalid constant value");

	rz_core_rop_constraint_free(rop_constraint);
	// Test case 2: Invalid format
	char str2[] = "eax =";
	rop_constraint = rop_constraint_parse_args(core, str2);
	mu_assert_null(rop_constraint, "parse_reg_constraints failed on invalid input");
	rz_core_rop_constraint_free(rop_constraint);

	mu_end;
}

bool test_parse_reg_to_reg(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rz_core(core);

	// Test case 1: Valid register to register
	char str1[] = "eax = ebx  ";
	RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, str1);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_REG, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "ebx", "Invalid source register");
	rz_core_rop_constraint_free(rop_constraint);

	// Test case 2: Invalid format
	char str2[] = "eax =";
	rop_constraint = rop_constraint_parse_args(core, str2);
	mu_assert_null(rop_constraint, "parse_reg_constraints failed on invalid input");
	rz_core_rop_constraint_free(rop_constraint);

	mu_end;
}

bool test_parse_reg_op_const(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rz_core(core);

	// Test case 1: Valid register operation with constant
	char str1[] = "eax=eax+3";
	RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, str1);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_OP_CONST, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "eax", "Invalid source register");
	mu_assert_streq(rop_constraint->args[OP], "add", "Invalid operator");
	mu_assert_streq(rop_constraint->args[SRC_CONST], "3", "Invalid constant value");

	rz_core_rop_constraint_free(rop_constraint);

	// Test case 2: Invalid format
	char str2[] = "eax=eax+";
	rop_constraint = rop_constraint_parse_args(core, str2);
	mu_assert_null(rop_constraint, "parse_reg_constraints failed on invalid input");
	rz_core_rop_constraint_free(rop_constraint);

	// Test case 3: Valid register operation with increment operator
	char str3[] = "eax++";
	rop_constraint = rop_constraint_parse_args(core, str3);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_OP_CONST, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "eax", "Invalid source register");
	mu_assert_streq(rop_constraint->args[OP], "add", "Invalid operator");
	mu_assert_streq(rop_constraint->args[SRC_CONST], "1", "Invalid constant value");
	rz_core_rop_constraint_free(rop_constraint);

	// Test case 4: Valid register operation with decrement operator
	char str4[] = "eax--";
	rop_constraint = rop_constraint_parse_args(core, str4);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_OP_CONST, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "eax", "Invalid source register");
	mu_assert_streq(rop_constraint->args[OP], "sub", "Invalid operator");
	mu_assert_streq(rop_constraint->args[SRC_CONST], "1", "Invalid constant value");
	rz_core_rop_constraint_free(rop_constraint);

	// Test case 5: Valid register operation with compound operator
	char str5[] = "eax  *=   1";
	rop_constraint = rop_constraint_parse_args(core, str5);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_OP_CONST, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "eax", "Invalid source register");
	mu_assert_streq(rop_constraint->args[OP], "mul", "Invalid operator");
	mu_assert_streq(rop_constraint->args[SRC_CONST], "1", "Invalid constant value");
	rz_core_rop_constraint_free(rop_constraint);

	mu_end;
}

bool test_parse_reg_op_reg(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rz_core(core);

	// Test case 1: Valid register operation with register
	char str1[] = "eax=ebx-ecx";
	RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, str1);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_OP_REG, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "ebx", "Invalid source register");
	mu_assert_streq(rop_constraint->args[OP], "sub", "Invalid operator");
	mu_assert_streq(rop_constraint->args[SRC_REG_SECOND], "ecx", "Invalid destination constant register");

	rz_core_rop_constraint_free(rop_constraint);

	// Test case 2: Invalid format
	char str2[] = "eax =  eax+ ";
	rop_constraint = rop_constraint_parse_args(core, str2);
	mu_assert_null(rop_constraint, "parse_reg_constraints failed on invalid input");

	// Test case 3: Valid register operation with register
	char str3[] = "eax  +=  ebx";
	rop_constraint = rop_constraint_parse_args(core, str3);
	mu_assert_notnull(rop_constraint, "parse_reg_constraints failed on valid input");
	mu_assert_eq(rop_constraint->type, MOV_OP_REG, "Invalid constraint type");
	mu_assert_streq(rop_constraint->args[DST_REG], "eax", "Invalid destination register");
	mu_assert_streq(rop_constraint->args[SRC_REG], "eax", "Invalid source register");
	mu_assert_streq(rop_constraint->args[SRC_REG_SECOND], "ebx", "Invalid destination constant register");
	mu_assert_streq(rop_constraint->args[OP], "add", "Invalid operator");

	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_parse_reg_to_const);
	mu_run_test(test_parse_reg_to_reg);
	mu_run_test(test_parse_reg_op_const);
	mu_run_test(test_parse_reg_op_reg);
	return tests_passed != tests_run;
}

mu_main(all_tests)
