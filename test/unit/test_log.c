// SPDX-FileCopyrightText: 2022 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static int small_check(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	mu_assert_streq(output, "ERROR: 3", "small check msg should be correct");
	return 0;
}

static int bind_check(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	mu_assert_streq(output, "ERROR: 3", "bind check msg should be correct");
	return 0;
}

static int large_check(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	char *exp_msg = RZ_NEWS0(char, 2000);
	strcpy(exp_msg, "ERROR: ");
	for (size_t i = 0; i < 999; i++) {
		exp_msg[strlen("ERROR: ") + i] = 'A';
	}
	mu_assert_streq(output, exp_msg, "large check msg should be correct");
	free(exp_msg);
	return 0;
}

bool test_log_small(void) {
	rz_log_del_callback((RzLogCallback)large_check);
	rz_log_del_callback((RzLogCallback)bind_check);
	rz_log_add_callback((RzLogCallback)small_check);
	rz_log("func", "file", 1, RZ_LOGLVL_ERROR, NULL, "%d", 3);
	mu_end;
}

bool test_log_binding(void) {
	rz_log_del_callback((RzLogCallback)large_check);
	rz_log_del_callback((RzLogCallback)small_check);
	rz_log_add_callback((RzLogCallback)bind_check);
	rz_log_bind("func", "file", 1, RZ_LOGLVL_ERROR, NULL, "3");
	mu_end;
}

bool test_log_large(void) {
	rz_log_del_callback((RzLogCallback)small_check);
	rz_log_del_callback((RzLogCallback)bind_check);
	rz_log_add_callback((RzLogCallback)large_check);
	char *buf = RZ_NEWS(char, 1000);
	memset(buf, 0x41, 999);
	buf[999] = '\0';
	rz_log("func", "file", 1, RZ_LOGLVL_ERROR, NULL, "%s", buf);
	free(buf);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_log_small);
	mu_run_test(test_log_binding);
	mu_run_test(test_log_large);
	return tests_passed != tests_run;
}

mu_main(all_tests)
