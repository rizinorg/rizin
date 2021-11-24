// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>
#include <rz_util/rz_ebcdic.h>
#include "minunit.h"
#include <string.h>

bool test_ascii_to_ebcdic() {
	ut8 dst[1];
	rz_str_ibm037_from_ascii(dst, 'a');
	mu_assert_eq(dst[0], 0x81, "rz_str_ibm037_from_ascii 'a'");
	rz_str_ibm037_from_ascii(dst, 'z');
	mu_assert_eq(dst[0], 0xa9, "rz_str_ibm037_from_ascii 'z'");
	rz_str_ibm037_from_ascii(dst, 'A');
	mu_assert_eq(dst[0], 0xc1, "rz_str_ibm037_from_ascii 'A'");
	rz_str_ibm037_from_ascii(dst, 'Z');
	mu_assert_eq(dst[0], 0xe9, "rz_str_ibm037_from_ascii 'Z'");

	mu_end;
}

bool test_ebcdic_to_ascii() {
	ut8 dst[1];
	rz_str_ibm037_to_ascii(0x81, dst);
	mu_assert_eq(dst[0], 'a', "rz_str_ibm037_to_ascii 'a'");
	rz_str_ibm037_to_ascii(0xa9, dst);
	mu_assert_eq(dst[0], 'z', "rz_str_ibm037_to_ascii 'z'");
	rz_str_ibm037_to_ascii(0xc1, dst);
	mu_assert_eq(dst[0], 'A', "rz_str_ibm037_to_ascii 'A'");
	rz_str_ibm037_to_ascii(0xe9, dst);
	mu_assert_eq(dst[0], 'Z', "rz_str_ibm037_to_ascii 'Z'");

	mu_end;
}

int all_tests() {
	mu_run_test(test_ascii_to_ebcdic);
	mu_run_test(test_ebcdic_to_ascii);

	return tests_passed != tests_run;
}

mu_main(all_tests)
