// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>

#define RZ_BIN_ELF64 1
#include "../../librz/bin/format/elf/elf.h"

#include "minunit.h"

/**
 * \brief Test that R_AARCH64_LDST32_ABS_LO12_NC and R_AARCH64_IRELATIVE
 * are correctly converted instead of falling through to the unsupported default.
 *
 * This covers the fix for issue #5130 / PR #6000.
 */
static bool test_aarch64_reloc_conversion(void) {
	// Create a minimal ELFOBJ with just the machine type set
	ELFOBJ bin = { 0 };
	bin.ehdr.e_machine = EM_AARCH64;

	// Test R_AARCH64_LDST32_ABS_LO12_NC (type 285)
	RzBinElfReloc rel_ldst32 = { 0 };
	rel_ldst32.type = R_AARCH64_LDST32_ABS_LO12_NC;

	RzBinReloc *result = Elf_(rz_bin_elf_convert_relocation)(&bin, &rel_ldst32, 0);
	mu_assert_notnull(result, "R_AARCH64_LDST32_ABS_LO12_NC conversion should succeed");
	mu_assert_streq(result->print_name, "R_AARCH64_LDST32_ABS_LO12_NC", "reloc name");
	mu_assert_eq(result->type, RZ_BIN_RELOC_32, "reloc size should be 32-bit");
	rz_bin_reloc_free(result);

	// Test R_AARCH64_IRELATIVE (type 1032)
	RzBinElfReloc rel_irelative = { 0 };
	rel_irelative.type = R_AARCH64_IRELATIVE;

	result = Elf_(rz_bin_elf_convert_relocation)(&bin, &rel_irelative, 0);
	mu_assert_notnull(result, "R_AARCH64_IRELATIVE conversion should succeed");
	mu_assert_streq(result->print_name, "R_AARCH64_IRELATIVE", "reloc name");
	mu_assert_eq(result->type, RZ_BIN_RELOC_64, "reloc size should be 64-bit");
	mu_assert_true(result->is_ifunc, "R_AARCH64_IRELATIVE should set is_ifunc");
	rz_bin_reloc_free(result);

	mu_end;
}

static bool all_tests(void) {
	mu_run_test(test_aarch64_reloc_conversion);
	return tests_passed != tests_run;
}

mu_main(all_tests)
