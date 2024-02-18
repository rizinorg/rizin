#include "../unit/minunit.h"
#include <rz_heap_glibc.h>
#include <rz_core.h>

int int_round(double x) {
	return (int)(x + 0.5);
}

bool test_get_glibc_version(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	double version = rz_get_glibc_version_64(core, "bins/elf/libc-2.27.so", NULL);
	int glibc_version = int_round((version * 100));
	mu_assert_eq(glibc_version, 227, "Incorrect libc version, expected 2.27");

	version = rz_get_glibc_version_64(core, "bins/elf/libc-2.31.so", NULL);
	glibc_version = int_round((version * 100));
	mu_assert_eq(glibc_version, 231, "Incorrect libc version, expected 2.31");

	version = rz_get_glibc_version_64(core, "bins/elf/libc-2.32.so", NULL);
	glibc_version = int_round((version * 100));
	mu_assert_eq(glibc_version, 232, "Incorrect libc version, expected 2.32");

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_get_glibc_version);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
