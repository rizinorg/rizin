#include <rz_util.h>
#include "minunit.h"

bool test_r_buf_new_sparse(void) {
	ut8 data[128];
	RBuffer *b = rz_buf_new_sparse (0xff);
	rz_buf_write_at (b, 0x100, (void*)"Hello World", 12);
	rz_buf_write_at (b, 0x200, (void*)"This Rocks!", 12);
	rz_buf_write_at (b, 0x102, (void*)"XX", 2);
	rz_buf_read_at (b, 0x101, data, 12);
	rz_buf_free (b);
	mu_assert_streq ((const char *)data, "eXXo World", "test_r_buf_new_sparse");
	mu_end;
}

bool all_tests() {
	mu_run_test(test_r_buf_new_sparse);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
