//
// Created by heersin on 2/28/21.
//

#include <rz_bin.h>
#include <rz_lib.h>
#include "luac/luac_specs.h"

static bool check_buffer(RzBuffer *buff) {
    if (rz_buf_size(buff) > 4 ){
        ut8 buf[4];
        rz_buf_read_at(buff, 0, buf, sizeof(buf));
        return (!memcmp(buf, LUAC_MAGIC, sizeof(buf)));
    }
    return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
    return check_buffer(buf);
}


RzBinPlugin rz_bin_plugin_luac = {
        .name = "luac",
        .desc = "LUAC_FORMAT",
        .license = "MIT",
        .get_sdb = NULL,
        .load_buffer = &load_buffer,
        .check_buffer = &check_buffer,
        .baddr = NULL,
        .entries = NULL,
        .sections = NULL,
        .info = NULL
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
        .type = RZ_LIB_TYPE_BIN,
        .data = &rz_bin_plugin_luac,
        .version = RZ_VERSION
};
#endif