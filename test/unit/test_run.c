// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_socket.h>
#include "minunit.h"

static char tmp_path[1000];
static const char *runprofile =
	"program=%s\n"
	"arg1=argument1\n"
	"arg2=argument2\n"
	"arg3=argument3\n"
	"setenv=FOO=BAR\n"
	"timeout=3\n"
	"stdout=foo.txt\n";

const char *get_auxiliary_path(const char *s) {
	char *p = rz_sys_pid_to_path(rz_sys_getpid());
	char *pp = (char *)rz_str_lchr(p, RZ_SYS_DIR[0]);
	if (pp) {
		*pp = '\0';
	}
	snprintf(tmp_path, sizeof(tmp_path), "%s%s%s%s%s", p, RZ_SYS_DIR, "auxiliary", RZ_SYS_DIR, s);
	free(p);
	return tmp_path;
}

bool test_rz_run_profile_parse(void) {
	RzRunProfile *rp = rz_run_new(NULL);
	mu_assert_notnull(rp, "create new run profile");

	const char *exe_path = get_auxiliary_path("subprocess-multiargs");
	char *profile = rz_str_newf(runprofile, exe_path);
	bool res = rz_run_parse(rp, profile);
	mu_assert_true(res, "parse run profile");

	rz_run_free(rp);
	mu_end;
}

bool test_rz_run_profile(void) {
	RzRunProfile *rp = rz_run_new(NULL);
	mu_assert_notnull(rp, "create new run profile");

	const char *exe_path = get_auxiliary_path("subprocess-multiargs");
	char *profile = rz_str_newf(runprofile, exe_path);
	bool res = rz_run_parse(rp, profile);
	mu_assert_true(res, "parse run profile");

	int exitcode = rz_run_start(rp);
	mu_assert_eq(exitcode, 0, "run success");

	rz_run_free(rp);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_run_profile_parse);
	mu_run_test(test_rz_run_profile);
	return tests_passed != tests_run;
}

mu_main(all_tests)
