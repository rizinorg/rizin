// SPDX-FileCopyrightText: 2024 rockrid3r <rockrid3r@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include "vmlinux.h"
#include <stdio.h>

static void add_config(RzVmlinuxConfigTable *config_tbl, char *config_name, char *config_value);

/**
 * \brief Parses the given kernel configuration file. Sets up RzVmlinuxConfigTable object.
 * \param config_filepath Path to the kernel configuration file.
 * \param config_tbl RzVmlinuxConfigTable to set up.
 * \returns true if parsing was successful. false on error.
 */
RZ_API bool rz_vmlinux_parse_apply_config_file(RZ_NONNULL const char *config_filepath, RZ_NONNULL RzVmlinuxConfigTable *config_tbl) {
	rz_return_val_if_fail(config_filepath && config_tbl, false);

	FILE *f = fopen(config_filepath, "r");
	if (!f) {
		return false;
	}

	size_t line_size = 256;
	char *line = malloc(line_size);
	if (!line) {
		return false;
	}

	int err = 0;
	while (true) {
		ssize_t read_sz = getline(&line, &line_size, f); // reallocs if not enough
		if (read_sz <= 0) {
			err = 1;
			goto out;
		}

		rz_str_trim(line);

		if (!rz_vmlinux_parse_apply_config_string(line, config_tbl)) {
			RZ_LOG_WARN("Skipping line '%s'", line);
		}
	}
out:
	free(line);
	fclose(f);
	return !err;
}

/**
 * \brief Parses the given config line. Sets the corresponding value into RzVmlinuxConfigTable.
 * \param config_str config line to process. For example: "CONFIG_SLAB_FREELIST_RANDOM=y"
 * \param config_tbl RzVmlinuxConfigTable to set the value into.
 * \return true if parsing was successful. false on error.
 */
RZ_API bool rz_vmlinux_parse_apply_config_string(RZ_NONNULL const char *config_str, RZ_NONNULL RzVmlinuxConfigTable *config_tbl) {
	rz_return_val_if_fail(config_str && config_tbl, false);

	char *config_name;
	char *config_value;

	if (config_str[0] == '#' || !config_str[0]) {
		return true;
	} else if (rz_str_split_by_first_dupstr(config_str, "=", true, &config_name, &config_value)) {
		add_config(config_tbl, config_name, config_value);
		free(config_name);
		free(config_value);
		return true;
	}
	return false;
}

/**
 * \brief Parses the vmlinux version.
 * \param version destination.
 * \param version_string version string to parse in format "x.x.x". For example: "5" and "5.17" and "5.17.0" are allowed, but "" is not.
 * \return true if parsing was successful. false on error.
 */
RZ_API bool rz_vmlinux_parse_version(unsigned long version[3], RZ_NONNULL const char *version_string) {
	rz_return_val_if_fail(version_string, false);

	int n_set = sscanf(version_string, "%lu.%lu.%lu", &version[0], &version[1], &version[2]);
	if (n_set < 3) {
		version[2] = 0;
	}
	if (n_set < 2) {
		version[1] = 0;
	}

	return n_set > 0;
}

#define SET_VMLINUX_CONFIG(config_var, config_value) \
	do { \
		if (!strcmp(config_value, "y")) { \
			config_var = VMLINUX_CONFIG_VALUE_Y; \
		} else if (!strcmp(config_value, "n")) { \
			config_var = VMLINUX_CONFIG_VALUE_N; \
		} else if (!strcmp(config_value, "m")) { \
			config_var = VMLINUX_CONFIG_VALUE_M; \
		} \
	} while (0)

static void add_config(RzVmlinuxConfigTable *config_tbl, char *config_name, char *config_value) {
	if (!strcmp(config_name, "CONFIG_SLAB_FREELIST_RANDOM")) {
		SET_VMLINUX_CONFIG(config_tbl->config_slab_freelist_random, config_value);
	} else if (!strcmp(config_name, "CONFIG_SLAB_FREELIST_HARDENED")) {
		SET_VMLINUX_CONFIG(config_tbl->config_slab_freelist_hardened, config_value);
	} else if (!strcmp(config_name, "CONFIG_MEMCG")) {
		SET_VMLINUX_CONFIG(config_tbl->config_memcg, config_value);
	} else if (!strcmp(config_name, "CONFIG_MEMCG_KMEM")) {
		SET_VMLINUX_CONFIG(config_tbl->config_memcg_kmem, config_value);
	}
}

/**
 * \brief Allocates a new RzVmlinuxConfigTable. Sets all config values to 'N'.
 */
RZ_API RZ_OWN RzVmlinuxConfigTable *rz_vmlinux_config_table_new() {
	RzVmlinuxConfigTable *config_tbl = RZ_NEW(RzVmlinuxConfigTable);
	config_tbl->config_slab_freelist_random = VMLINUX_CONFIG_VALUE_N;
	config_tbl->config_slab_freelist_hardened = VMLINUX_CONFIG_VALUE_N;
	config_tbl->config_memcg = VMLINUX_CONFIG_VALUE_N;
	config_tbl->config_memcg_kmem = VMLINUX_CONFIG_VALUE_N;
	return config_tbl;
}

/**
 * \brief Allocates a new RzVmlinuxConfig. Sets all config values to 'N'.
 */
RZ_API RZ_OWN RzVmlinuxConfig *rz_vmlinux_config_new() {
	RzVmlinuxConfig *config = RZ_NEW(RzVmlinuxConfig);
	config->config_tbl = rz_vmlinux_config_table_new();
	return config;
}

/**
 * \brief Compares 2 passed kernel versions
 * \param v1 1st linux version
 * \param v2 2nd linux version
 * \return Returns a positive value if v1 > v2, negative if v1 < v2, else 0.
 */
RZ_API int rz_vmlinux_vercmp(unsigned long v1[3], unsigned long v2[3]) {
	size_t diff_idx;
	for (diff_idx = 0; diff_idx < 3; ++diff_idx)
		if (v1[diff_idx] != v2[diff_idx])
			break;

	if (diff_idx == 3) {
		return 0;
	}

	if (v1[diff_idx] > v2[diff_idx]) {
		return 1;
	}

	return -1;
}

/**
 * \brief Compares 2 passed kernel versions
 * \param v1 1st linux version
 * \param v2 2nd linux version
 * \return Returns a positive value if v1 > v2, negative if v1 < v2, else 0.
 */
RZ_API int rz_vmlinux_vercmp_with_str(unsigned long v1[3], const char *v2_str) {
	unsigned long v2[3];
	rz_vmlinux_parse_version(v2, v2_str);
	return rz_vmlinux_vercmp(v1, v2);
}

/**
 * \brief Frees the allocated RzVmlinuxConfig
 * \param vmlinux_config RzVmlinuxConfig to free
 */
RZ_API void rz_vmlinux_config_free(RZ_NULLABLE RzVmlinuxConfig *vmlinux_config) {
	if (!vmlinux_config) {
		return;
	}
	rz_vmlinux_config_table_free(vmlinux_config->config_tbl);
	free(vmlinux_config);
}

/**
 * \brief Frees the allocated RzVmlinuxConfigTable
 * \param config_tbl RzVmlinuxConfigTable to free
 */
RZ_API void rz_vmlinux_config_table_free(RZ_NULLABLE RzVmlinuxConfigTable *config_tbl) {
	free(config_tbl);
}