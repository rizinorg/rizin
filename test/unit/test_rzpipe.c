#include <rz_util.h>
#include <rz_socket.h>
#include "minunit.h"

static bool test_rzpipe(void) {
	R2Pipe *r = rzpipe_open ("rizin -q0 -");
	mu_assert ("rzpipe can spawn", r);
	char *hello = rzpipe_cmd (r, "?e hello world");
	mu_assert_streq (hello, "hello world\n", "rzpipe hello world");
	free (hello);
	rzpipe_close (r);
	mu_end;
}

static bool test_rzpipe_404(void) {
	R2Pipe *r = rzpipe_open ("rodoro2 -q0 -");
	mu_assert ("rzpipe can spawn", !r);
	mu_end;
}

static int all_tests() {
	mu_run_test (test_rzpipe);
	mu_run_test (test_rzpipe_404);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
