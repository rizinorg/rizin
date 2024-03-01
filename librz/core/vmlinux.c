#include <rz_core.h>
#include <rz_util/rz_str.h>
#include "vmlinux.h"
#include <stdio.h>

static void add_config(RzVmlinuxConfigTable* config_tbl, char* config_name, char* config_value);

RZ_IPI bool vmlinux_parse_apply_config_file(const char* config_filepath, RzVmlinuxConfigTable* config_tbl) {
    FILE* f = fopen(config_filepath, "r");
    if (!f) {
        return false;
    }

    size_t line_size = 256;
    char* line = malloc(line_size);
    int err = 0;
    while (true) {
        ssize_t read_sz = getline(&line, &line_size, f); // reallocs if not enough
        if (read_sz <= 0) {
            err = 1;
            goto out;
        }

        rz_str_trim(line);

        char* config_name;
        char* config_value;

        if (line[0] == '#' || !line[0]) {
            continue;
        } else if (rz_str_split_by_first_dupstr(line, "=", true, &config_name, &config_value)) {
            add_config(&config_tbl, config_name, config_value);
        } else {
            RZ_LOG_WARN("Skipping line '%s'", line);
            continue;
        }
    }
out:
    free(line);
    fclose(f);
    return !err;
}

/**
 * Numeric 90+
*/
RZ_IPI bool vmlinux_parse_version(const char* version_string, unsigned long version[3]) {
    RzList* version_list = rz_str_split_duplist_n(version_string, ".", 3, 1);
    RzListIter* it;
    char** str;

    size_t v = 0;
    rz_list_foreach(version_list, it, str) {
        size_t i;
        for (i = 0; str[i] != '0'; ++i) if (!isdigit(i)) break;

        if (str[i] == '0') { // is number
            unsigned long numbr = strtoul(str, NULL, 10);
            version[v] = numbr;
        } else {
            return false;
        }

        ++v;
    }
    return true;
}

#define SET_VMLINUX_CONFIG(config_var, config_name, config_value)   \
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
        SET_VMLINUX_CONFIG(config_tbl->config_slab_freelist_random, config_name, config_value);
    } else if (!strcmp(config_name, "CONFIG_SLAB_FREELIST_HARDENED")) {
        SET_VMLINUX_CONFIG(config_tbl->config_slab_freelist_hardened, config_name, config_value);
    } else if (!strcmp(config_name, "CONFIG_MEMCG")) {
        SET_VMLINUX_CONFIG(config_tbl->config_memcg, config_name, config_value);
    } else if (!strcmp(config_name, "CONFIG_MEMCG_KMEM")) {
        SET_VMLINUX_CONFIG(config_tbl->config_memcg_kmem, config_name, config_value);
    }
}


RZ_IPI RzVmlinuxConfigTable* rz_vmlinux_config_table_new() {
    RzVmlinuxConfigTable* config_tbl = malloc(sizeof(RzVmlinuxConfigTable));
    config_tbl->config_slab_freelist_random = VMLINUX_CONFIG_VALUE_N;
    config_tbl->config_slab_freelist_hardened = VMLINUX_CONFIG_VALUE_N;
    config_tbl->config_memcg = VMLINUX_CONFIG_VALUE_N;
    config_tbl->config_memcg_kmem = VMLINUX_CONFIG_VALUE_N;
    return config_tbl;
}

RZ_IPI RzVmlinuxConfig* rz_vmlinux_config_new() {
    RzVmlinuxConfig* config = malloc(sizeof(RzVmlinuxConfig));
    return config;
}