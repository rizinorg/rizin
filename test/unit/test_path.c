// SPDX-FileCopyrightText: 2021 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_path.h>
#include <rz_util/rz_file.h>
#include "minunit.h"

bool test_basic_paths(void) {
	mu_assert_streq_free(rz_path_prefix(NULL), RZ_PREFIX, "prefix should be returned");
	mu_assert_streq_free(rz_path_prefix("bin"), RZ_JOIN_2_PATHS(RZ_PREFIX, "bin"), "prefix/bin should be returned");
	mu_assert_streq_free(rz_path_incdir(), RZ_JOIN_2_PATHS(RZ_PREFIX, RZ_INCDIR), "includedir should be returned");
	mu_assert_streq_free(rz_path_libdir(), RZ_JOIN_2_PATHS(RZ_PREFIX, RZ_LIBDIR), "includedir should be returned");
	mu_end;
}

bool test_system_paths(void) {
	mu_assert_streq_free(rz_path_system_rc(), RZ_JOIN_2_PATHS(RZ_PREFIX, RZ_GLOBAL_RC), "prefix/rizinrc should be returned");
	mu_assert_streq_free(rz_path_system_plugins(), RZ_JOIN_2_PATHS(RZ_PREFIX, RZ_PLUGINS), "plugin dir should be returned");
	mu_end;
}

bool test_home_paths(void) {
	char *home = getenv(RZ_SYS_HOME);
	char *homerc = rz_file_path_join(home, ".rizinrc");
	char *homeplugins = rz_file_path_join(home, RZ_HOME_PLUGINS);
	mu_assert_streq_free(rz_path_home_rc(), homerc, "~/.rizinrc should be returned");
	mu_assert_streq_free(rz_path_home_plugins(), homeplugins, "~/.local/share/rizin/plugins dir should be returned");
	free(homeplugins);
	free(homerc);
	mu_end;
}

int all_tests() {
	mu_run_test(test_basic_paths);
	mu_run_test(test_system_paths);
	mu_run_test(test_home_paths);
	return tests_passed != tests_run;
}

mu_main(all_tests)
