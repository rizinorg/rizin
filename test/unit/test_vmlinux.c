// SPDX-FileCopyrightText: 2017 Fangrui Song <i@maskray.me>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <vmlinux.h>
#include <stdbool.h>

static bool test_vmlinux_vercmp(void) {
    unsigned long v1[3] = {6, 7, 1};
    unsigned long v2[3] = {5, 17, 0};

	mu_assert("v1 > v2", vmlinux_vercmp(v1, v2) > 0);
	mu_assert("v1 > v2_str", vmlinux_vercmp_with_str(v1, "5.17") > 0);
	
	mu_end;
}

static bool test_vmlinux_config(void) {
	RzVmlinuxConfig *vmlinux_config = rz_vmlinux_config_new();
	RzVmlinuxConfigTable *config_tbl = vmlinux_config->config_tbl;
	const char *config_lines[] = {
		"CONFIG_SLAB_FREELIST_RANDOM=y",
		"CONFIG_SLAB_FREELIST_HARDENED=n",
		"# CONFIG_SLAB_FREELIST_HARDENED=y",
		"CONFIG_STATIC_USERMODEHELPER=y",
		"CONFIG_UNKNOWN=y",
	};

	size_t config_size = sizeof(config_lines) / sizeof(config_lines[0]);
	for (size_t i = 0; i < config_size; ++i) {
		// eprintf("%p, %p\n", config_lines[i], config_tbl);
		vmlinux_parse_apply_config_string(config_lines[i], config_tbl);
	}
	
	mu_assert("Expected CONFIG_SLAB_FREELIST_RANDOM=y", config_tbl->config_slab_freelist_random);
	mu_assert("Expected CONFIG_SLAB_FREELIST_HARDENED=n", !config_tbl->config_slab_freelist_hardened);

	rz_vmlinux_config_free(vmlinux_config);
	
	mu_end;
}


int all_tests(void) {
	mu_run_test(test_vmlinux_vercmp);
	mu_run_test(test_vmlinux_config);
	return tests_passed != tests_run;
}

mu_main(all_tests)