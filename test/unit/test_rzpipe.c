// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_socket.h>
#include "minunit.h"

static bool test_rzpipe(void) {
#ifndef __WINDOWS__
	RzPipe *r = rzpipe_open("rizin -q0 -");
	mu_assert("rzpipe can spawn", r);
	char *hello = rzpipe_cmd(r, "?e hello world");
	mu_assert_streq(hello, "hello world\n", "rzpipe hello world");
	free(hello);
	rzpipe_close(r);
#else
	mu_test_status = MU_TEST_BROKEN;
#endif
	mu_end;
}

static bool test_rzpipe_404(void) {
#ifndef __WINDOWS__
	RzPipe *r = rzpipe_open("ricin -q0 -");
	mu_assert("rzpipe can spawn", !r);
#else
	mu_test_status = MU_TEST_BROKEN;
#endif
	mu_end;
}

static int all_tests() {
	mu_run_test(test_rzpipe);
	mu_run_test(test_rzpipe_404);
	return tests_passed != tests_run;
}

mu_main(all_tests)