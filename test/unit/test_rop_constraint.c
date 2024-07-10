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

void setup_rzcore(RzCore *core) {
	rz_config_set(core->config, "analysis.arch", "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_reg_set_profile_string(core->analysis->reg, REGISTER_PROFILE_STRING);
}

bool test_parse_reg_to_const(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rzcore(core);
	RzRopConstraint rop_constraint = { 0 };

	// Test case 1: Valid register to constant
	char str1[] = " eax =    123 ";
	mu_assert("parse_reg_to_const failed on valid input", rz_core_rop_analyze_constraint(core, str1, &rop_constraint));
	mu_assert_eq(strcmp(rop_constraint.args[DST_REG], "eax"), 0, "Invalid destination register");
	mu_assert("Source register should be NULL", rop_constraint.args[SRC_REG] == NULL);
	mu_assert_eq(strcmp(rop_constraint.args[SRC_CONST], "123"), 0, "Invalid constant value");

	free(rop_constraint.args[DST_REG]);
	free(rop_constraint.args[SRC_CONST]);

	// Test case 2: Invalid format
	char str2[] = "eax =";
	mu_assert("parse_reg_to_const should fail on invalid input", !rz_core_rop_analyze_constraint(core, str2, &rop_constraint));

	mu_end;
}

bool test_parse_reg_to_reg(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rzcore(core);
	RzRopConstraint rop_constraint = { 0 };

	// Test case 1: Valid register to register
	char str1[] = "eax = ebx  ";
	mu_assert("parse_reg_to_reg failed on valid input", rz_core_rop_analyze_constraint(core, str1, &rop_constraint));
	mu_assert_eq(strcmp(rop_constraint.args[DST_REG], "eax"), 0, "Invalid destination register");
	mu_assert_eq(strcmp(rop_constraint.args[SRC_REG], "ebx"), 0, "Invalid source register");

	free(rop_constraint.args[DST_REG]);
	free(rop_constraint.args[SRC_REG]);

	// Test case 2: Invalid format
	char str2[] = "eax =";
	mu_assert("parse_reg_to_reg should fail on invalid input", !rz_core_rop_analyze_constraint(core, str2, &rop_constraint));

	mu_end;
}

bool test_parse_reg_op_const(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rzcore(core);
	RzRopConstraint rop_constraint = { 0 };

	// Test case 1: Valid register operation with constant
	char str1[] = "eax=eax+3";
	mu_assert("parse_reg_op_const failed on valid input", rz_core_rop_analyze_constraint(core, str1, &rop_constraint));
	mu_assert_eq(strcmp(rop_constraint.args[DST_REG], "eax"), 0, "Invalid destination register");
	mu_assert_eq(strcmp(rop_constraint.args[SRC_REG], "eax"), 0, "Invalid source register");
	mu_assert_eq(strcmp(rop_constraint.args[OP], "add"), 0, "Invalid operator");
	mu_assert_eq(strcmp(rop_constraint.args[SRC_CONST], "3"), 0, "Invalid constant value");

	free(rop_constraint.args[DST_REG]);
	free(rop_constraint.args[SRC_REG]);
	free(rop_constraint.args[OP]);
	free(rop_constraint.args[SRC_CONST]);

	// Test case 2: Invalid format
	char str2[] = "eax=eax+";
	mu_assert("parse_reg_op_const should fail on invalid input", !rz_core_rop_analyze_constraint(core, str2, &rop_constraint));

	mu_end;
}

bool test_parse_reg_op_reg(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	setup_rzcore(core);
	RzRopConstraint rop_constraint = { 0 };

	// Test case 1: Valid register operation with register
	char str1[] = "eax=eax-ebx";
	mu_assert("parse_reg_op_reg failed on valid input", rz_core_rop_analyze_constraint(core, str1, &rop_constraint));
	mu_assert_eq(strcmp(rop_constraint.args[DST_REG], "eax"), 0, "Invalid destination register");
	mu_assert_eq(strcmp(rop_constraint.args[SRC_REG], "eax"), 0, "Invalid source register");
	mu_assert_eq(strcmp(rop_constraint.args[OP], "sub"), 0, "Invalid operator");
	mu_assert_eq(strcmp(rop_constraint.args[SRC_CONST], "ebx"), 0, "Invalid destination constant register");

	free(rop_constraint.args[DST_REG]);
	free(rop_constraint.args[SRC_REG]);
	free(rop_constraint.args[OP]);
	free(rop_constraint.args[SRC_CONST]);

	// Test case 2: Invalid format
	char str2[] = "eax =  eax+ ";
	mu_assert("parse_reg_op_reg should fail on invalid input", !rz_core_rop_analyze_constraint(core, str2, &rop_constraint));

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
