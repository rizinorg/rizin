#pragma once

enum vmlinux_config_value {
    VMLINUX_CONFIG_VALUE_N = 0,
    VMLINUX_CONFIG_VALUE_Y,
    VMLINUX_CONFIG_VALUE_M,
};

typedef struct vmlinux_config_table {
    enum vmlinux_config_value config_slab_freelist_random;
    enum vmlinux_config_value config_slab_freelist_hardened;
    enum vmlinux_config_value config_memcg;
    enum vmlinux_config_value config_memcg_kmem;
} RzVmlinuxConfigTable;

typedef struct vmlinux_config {
    RzVmlinuxConfigTable* config_tbl;
    unsigned long version[3];
} RzVmlinuxConfig;

RZ_IPI RzVmlinuxConfigTable* rz_vmlinux_config_table_new();
RZ_IPI RzVmlinuxConfig* rz_vmlinux_config_new();
RZ_IPI void rz_vmlinux_config_free(RzVmlinuxConfig* vmlinux_config);
RZ_IPI void rz_vmlinux_config_table_free(RzVmlinuxConfigTable* config_tbl);
RZ_IPI bool vmlinux_parse_apply_config_file(const char* config_filepath, RzVmlinuxConfigTable* config_tbl);
RZ_IPI bool vmlinux_parse_version(const char* version_string, unsigned long version[3]);
RZ_API int vmlinux_vercmp(unsigned long v1[3], unsigned long v2[3]);
RZ_API int vmlinux_vercmp_with_str(unsigned long v1[3], const char* v2_str);