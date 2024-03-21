#include <rz_core.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include "vmlinux.h"
#include <stdio.h>

static void add_config(RzVmlinuxConfigTable* config_tbl, char* config_name, char* config_value);

RZ_API bool vmlinux_parse_apply_config_file(const char* config_filepath, RzVmlinuxConfigTable* config_tbl) {
    rz_return_val_if_fail(config_filepath && config_tbl, false);

    FILE* f = fopen(config_filepath, "r");
    if (!f) {
        return false;
    }

    size_t line_size = 256;
    char* line = malloc(line_size);
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

        if (!vmlinux_parse_apply_config_string(line, config_tbl)) {
            RZ_LOG_WARN("Skipping line '%s'", line);
        }
    }
out:
    free(line);
    fclose(f);
    return !err;
}

RZ_API bool vmlinux_parse_apply_config_string(const char *config_str, RzVmlinuxConfigTable *config_tbl) {
    rz_return_val_if_fail(config_str && config_tbl, false);

    char* config_name;
    char* config_value;

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
 * Numeric 90+
*/
RZ_API bool vmlinux_parse_version(const char* version_string, unsigned long version[3]) {
    RzList* version_list = rz_str_split_duplist_n(version_string, ".", 3, true);
    RzListIter* it;
    char* str;

    for (size_t i = 0; i < 3; ++i) version[i] = 0;

    size_t v = 0;
    rz_list_foreach(version_list, it, str) {
        if (v == 3) { // 3 dots? 
            break;
        }

        size_t i;

        for (i = 0; str[i] != '\0'; ++i) if (!isdigit(str[i])) break;

        if (str[i] == '\0') { // is number
            unsigned long numbr = strtoul(str, NULL, 10);
            version[v] = numbr;
        } else {
            rz_list_free(version_list);
            return false;
        }

        ++v;
    }
    rz_list_free(version_list);
    return true;
}

#define SET_VMLINUX_CONFIG(config_var, config_value)   \
    do {                                                            \
        if (!strcmp(config_value, "y")) {                           \
            config_var = VMLINUX_CONFIG_VALUE_Y;                    \
        } else if (!strcmp(config_value, "n")) {                    \
            config_var = VMLINUX_CONFIG_VALUE_N;                    \
        } else if (!strcmp(config_value, "m")) {                    \
            config_var = VMLINUX_CONFIG_VALUE_M;                    \
        }                                                           \
    } while (0)                                                       

static void add_config(RzVmlinuxConfigTable* config_tbl, char* config_name, char* config_value) {
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


RZ_API RzVmlinuxConfigTable* rz_vmlinux_config_table_new() {
    RzVmlinuxConfigTable* config_tbl = malloc(sizeof(RzVmlinuxConfigTable));
    config_tbl->config_slab_freelist_random = VMLINUX_CONFIG_VALUE_N;
    config_tbl->config_slab_freelist_hardened = VMLINUX_CONFIG_VALUE_N;
    config_tbl->config_memcg = VMLINUX_CONFIG_VALUE_N;
    config_tbl->config_memcg_kmem = VMLINUX_CONFIG_VALUE_N;
    return config_tbl;
}

RZ_API RzVmlinuxConfig* rz_vmlinux_config_new() {
    RzVmlinuxConfig* config = malloc(sizeof(RzVmlinuxConfig));
    config->config_tbl = rz_vmlinux_config_table_new();
    return config;
}


RZ_API int vmlinux_vercmp(unsigned long v1[3], unsigned long v2[3]) {
    size_t diff_idx;
    for (diff_idx = 0; diff_idx < 3; ++diff_idx) if (v1[diff_idx] != v2[diff_idx]) break;

    if (diff_idx == 3) {
        return 0;
    }

    if (v1[diff_idx] > v2[diff_idx]) {
        return 1;
    } 

    return -1;
}


RZ_API int vmlinux_vercmp_with_str(unsigned long v1[3], const char* v2_str) {
    unsigned long v2[3];
    vmlinux_parse_version(v2_str, v2);
    return vmlinux_vercmp(v1, v2);
}


RZ_API void rz_vmlinux_config_free(RzVmlinuxConfig* vmlinux_config) {
    rz_vmlinux_config_table_free(vmlinux_config->config_tbl);
    free(vmlinux_config);
}

RZ_API void rz_vmlinux_config_table_free(RzVmlinuxConfigTable* config_tbl) {
    free(config_tbl);
}