#include <rz_anal.h>
#include "minunit.h"

bool test_r_anal_xrefs_count() {
	RzAnal *anal = rz_anal_new ();

	mu_assert_eq (rz_anal_xrefs_count (anal), 0, "xrefs count");

	rz_anal_xrefs_set (anal, 0x1337, 42, RZ_ANAL_REF_TYPE_NULL);
	rz_anal_xrefs_set (anal, 0x1337, 43, RZ_ANAL_REF_TYPE_CODE);
	rz_anal_xrefs_set (anal, 1234, 43, RZ_ANAL_REF_TYPE_CALL);
	rz_anal_xrefs_set (anal, 12345, 43, RZ_ANAL_REF_TYPE_CALL);
	rz_anal_xrefs_set (anal, 4321, 4242, RZ_ANAL_REF_TYPE_CALL);

	mu_assert_eq (rz_anal_xrefs_count (anal), 5, "xrefs count");

	rz_anal_free (anal);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_anal_xrefs_count);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
