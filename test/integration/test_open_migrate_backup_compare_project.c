// SPDX-FileCopyrightText: 2026 Ami Branch <Amira.Branch@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_project.h>

#include "../unit/minunit.h"

// Returns true if files are identical
static bool compare_files(const char *a, const char *b) {
	FILE *fa = fopen(a, "rb");
	if (!fa)
		return false;

	FILE *fb = fopen(b, "rb");
	if (!fb) {
		fclose(fa);
		return false;
	}

	unsigned char buf_a[4096];
	unsigned char buf_b[4096];
	bool ret = false;

	for (;;) {
		size_t na = fread(buf_a, 1, sizeof(buf_a), fa);
		size_t nb = fread(buf_b, 1, sizeof(buf_b), fb);

		if (na != nb) {
			goto end;
		}

		if (na == 0)
			break;

		if (memcmp(buf_a, buf_b, na) != 0) {
			goto end;
		}
	}

	ret = true;

end:
	fclose(fa);
	fclose(fb);
	return ret;
}

bool test_open_migrate_backup_compare() {
	// 1. Cleanup potential backup file from previous run
	const char *back_path = "prj/.v2-typelink-callables.rzdb_2.BAK";
	if (rz_file_exists(back_path)) {
		rz_file_rm(back_path);
	}
	mu_assert_eq(rz_file_exists(back_path), false, "backup file exists");

	// 2. Open project and load core (will implicitly migrate sdb inside)
	RzCore *core = rz_core_new();
	const char *proj_path = "prj/v2-typelink-callables.rzdb";
	// const char *proj_path = "prj/v16-flags-base.rzdb";
	mu_assert_eq(rz_core_project_load_for_cli(core, proj_path, false), true, "load core");

	// 3. Save backup
	RzProjectErr err = rz_project_save_backup_file(core, proj_path, false);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "save backup");
	rz_core_free(core);

	// 4. Compare files
	mu_assert_eq(rz_file_exists(back_path), true, "backup file created");
	mu_assert_eq(rz_file_size(back_path), rz_file_size(proj_path), "file size");
	mu_assert_eq(compare_files(back_path, proj_path), 1, "file compare");

	mu_end;
}

int all_tests() {
	mu_run_test(test_open_migrate_backup_compare);
	return tests_passed != tests_run;
}

mu_main(all_tests)
