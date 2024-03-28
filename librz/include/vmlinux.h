// SPDX-FileCopyrightText: 2024 rockrid3r <rockrid3r@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Provides interface for working with linux kernel configuration.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/**
 * \brief Enum representing the linux config value.
 */
enum vmlinux_config_value {
	VMLINUX_CONFIG_VALUE_N = 0, /**< N (no) */
	VMLINUX_CONFIG_VALUE_Y, /**< Y (yes) */
	VMLINUX_CONFIG_VALUE_M, /**< M (module) */
};

/**
 * \brief Structure representing supported linux configs
 */
typedef struct vmlinux_config_table {
	enum vmlinux_config_value config_slab_freelist_random; /**< CONFIG_SLAB_FREELIST_RANDOM */
	enum vmlinux_config_value config_slab_freelist_hardened; /**< CONFIG_SLAB_FREELIST_HARDENED */
	enum vmlinux_config_value config_memcg; /**< CONFIG_MEMCG */
	enum vmlinux_config_value config_memcg_kmem; /**< CONFIG_MEMCG_KMEM */
} RzVmlinuxConfigTable;

/**
 * \brief Main structure for holding linux kernel info: version, configuration, etc.
 * \brief Is attached to RzAnalysis.
 */
typedef struct vmlinux_config {
	RzVmlinuxConfigTable *config_tbl;
	unsigned long version[3];
} RzVmlinuxConfig;

RZ_API RZ_OWN RzVmlinuxConfigTable *rz_vmlinux_config_table_new();
RZ_API RZ_OWN RzVmlinuxConfig *rz_vmlinux_config_new();
RZ_API void rz_vmlinux_config_free(RZ_NULLABLE RzVmlinuxConfig *vmlinux_config);
RZ_API void rz_vmlinux_config_table_free(RZ_NULLABLE RzVmlinuxConfigTable *config_tbl);
RZ_API bool rz_vmlinux_parse_apply_config_file(RZ_NONNULL const char *config_filepath, RZ_NONNULL RzVmlinuxConfigTable *config_tbl);
RZ_API bool rz_vmlinux_parse_apply_config_string(RZ_NONNULL const char *config_str, RZ_NONNULL RzVmlinuxConfigTable *config_tbl);
RZ_API bool rz_vmlinux_parse_version(unsigned long version[3], RZ_NONNULL const char *version_string);
RZ_API int rz_vmlinux_vercmp(unsigned long v1[3], unsigned long v2[3]);
RZ_API int rz_vmlinux_vercmp_with_str(unsigned long v1[3], const char *v2_str);

#endif /* __VMLINUX_H__ */