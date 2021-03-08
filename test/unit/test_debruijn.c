// SPDX-FileCopyrightText: 2016 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_debruijn_pattern(void) {
	char *pattern = rz_debruijn_pattern(256, 0, NULL /*default charset*/);
	mu_assert_eq((int)strlen(pattern), 256, "pattern length");
	mu_assert_streq(pattern, "AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABY", "pattern of 256 length");
	free(pattern);
	mu_end;
}

bool test_rz_debruijn_offset(void) {
	// From ropasaurusrex.
	ut64 offset = 0x41417641;
	mu_assert_eq(rz_debruijn_offset(offset, false /*little endian*/), 140, "debruijn offset - little endian");
	offset = 0x41764141;
	mu_assert_eq(rz_debruijn_offset(offset, true /*big endian*/), 140, "debruijn offset - big endian");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_debruijn_pattern);
	mu_run_test(test_rz_debruijn_offset);
	return tests_passed != tests_run;
}

mu_main(all_tests)