// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

// The tables are static inline in a header that only librz_arch sees, so they
// are not linkable; include the header directly, as test_c6x_packet.c does with
// the packet decoder.
#include "../../librz/arch/isa/tms320/tms320_dwarf_regnum_table.h"

/**
 * The C28x and C6000 tables are transcriptions of published TI tables that
 * nothing else in the tree exercises: no C28x or C6000 object available carries
 * DWARF variables located in registers, so the mapping is never reached at
 * runtime. These assertions pin the values that were transcribed, so a later
 * edit that shifts a numbering is caught here rather than silently producing
 * wrong register names in debug info.
 */

bool test_tms320_c28x_dwarf_regs(void) {
	// SPRAC71C Table 10-1. The 16-bit halves and their 32-bit parents get
	// separate numbers, so AR0 and XAR0 are distinct rather than aliases.
	mu_assert_streq(tms320_c28x_register_name(0), "al", "DWARF 0 is AL");
	mu_assert_streq(tms320_c28x_register_name(1), "ah", "DWARF 1 is AH");
	mu_assert_streq(tms320_c28x_register_name(4), "ar0", "DWARF 4 is AR0");
	mu_assert_streq(tms320_c28x_register_name(5), "xar0", "DWARF 5 is XAR0");
	mu_assert_streq(tms320_c28x_register_name(19), "xar7", "DWARF 19 is XAR7");
	mu_assert_streq(tms320_c28x_register_name(20), "sp", "DWARF 20 is SP");
	mu_assert_streq(tms320_c28x_register_name(25), "pc", "DWARF 25 is PC");
	// TI lists 28 as FP, which on the C28x is XAR2
	mu_assert_streq(tms320_c28x_register_name(28), "xar2", "DWARF 28 is the frame pointer");
	mu_assert_streq(tms320_c28x_register_name(29), "dp", "DWARF 29 is DP");
	mu_assert_streq(tms320_c28x_register_name(37), "ier", "DWARF 37 is IER");

	// numbers TI reserves stay NULL rather than resolving to a wrong register
	mu_assert_null(tms320_c28x_register_name(27), "DWARF 27 is reserved");
	mu_assert_null(tms320_c28x_register_name(33), "DWARF 33 is reserved");
	mu_assert_null(tms320_c28x_register_name(1000), "out of range");
	mu_end;
}

bool test_tms320_c6000_dwarf_regs(void) {
	// SPRAB89B Table 12-1. A0-A15 then B0-B15, with the upper halves of both
	// files displaced past the control registers at 33-36.
	mu_assert_streq(tms320_c6000_register_name(0), "a0", "DWARF 0 is A0");
	mu_assert_streq(tms320_c6000_register_name(15), "a15", "DWARF 15 is A15");
	mu_assert_streq(tms320_c6000_register_name(16), "b0", "DWARF 16 is B0");
	mu_assert_streq(tms320_c6000_register_name(31), "b15", "DWARF 31 is B15");
	mu_assert_streq(tms320_c6000_register_name(33), "pce1", "DWARF 33 is PCE1");
	mu_assert_streq(tms320_c6000_register_name(37), "a16", "DWARF 37 is A16");
	mu_assert_streq(tms320_c6000_register_name(52), "a31", "DWARF 52 is A31");
	mu_assert_streq(tms320_c6000_register_name(53), "b16", "DWARF 53 is B16");
	mu_assert_streq(tms320_c6000_register_name(68), "b31", "DWARF 68 is B31");
	mu_assert_streq(tms320_c6000_register_name(69), "amr", "DWARF 69 is AMR");
	// SPRAB89B spells 70 "CST"; the register is the control status register,
	// which the profile and the rest of the C6000 documentation call CSR
	mu_assert_streq(tms320_c6000_register_name(70), "csr", "DWARF 70 is CSR");
	mu_assert_streq(tms320_c6000_register_name(99), "ierr", "DWARF 99 is IERR");

	mu_assert_null(tms320_c6000_register_name(32), "DWARF 32 is reserved");
	// control registers the C6000 register profile does not model
	mu_assert_null(tms320_c6000_register_name(75), "IN is not in the profile");
	mu_assert_null(tms320_c6000_register_name(87), "ARP is not in the profile");
	mu_assert_null(tms320_c6000_register_name(1000), "out of range");
	mu_end;
}

bool test_tms320_c55x_dwarf_regs(void) {
	// unchanged by this series; asserted so a later edit to the shared header
	// cannot quietly disturb the core that was already using it
	mu_assert_streq(tms320_c55x_register_name(0), "ac0", "DWARF 0 is AC0");
	mu_assert_null(tms320_c55x_register_name(1000), "out of range");
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_tms320_c28x_dwarf_regs);
	mu_run_test(test_tms320_c6000_dwarf_regs);
	mu_run_test(test_tms320_c55x_dwarf_regs);
	return tests_passed != tests_run;
}

mu_main(all_tests)
