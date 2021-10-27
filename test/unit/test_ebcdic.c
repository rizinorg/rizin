// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>
#include <rz_util/rz_ebcdic.h>
#include "minunit.h"
#include <string.h>

bool test_ascii_to_ebcdic() {
	return true;
}

int all_tests() {
	mu_run_test(test_ascii_to_ebcdic);
	return tests_passed != tests_run;
}

mu_main(all_tests)
