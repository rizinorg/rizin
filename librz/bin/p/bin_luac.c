//
// Created by heersin on 2/28/21.
//

#include <rz_bin.h>
#include <rz_lib.h>
#include "luac/luac_54.h"

static ut8 MAJOR_VERSION;
static ut8 MINOR_VERSION;

static bool check_buffer(RzBuffer *buff) {
    if (rz_buf_size(buff) > 4 ){
        ut8 buf[4];
        rz_buf_read_at(buff, 0, buf, sizeof(buf));
        return (!memcmp(buf, LUAC_MAGIC, sizeof(buf)));
    }
    return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
    rz_buf_read_at(buf, 4, &MAJOR_VERSION, sizeof(MAJOR_VERSION));        /* 1-byte in fact */
    rz_buf_read_at(buf, 5, &MINOR_VERSION, sizeof(MINOR_VERSION));
    return check_buffer(buf);
}

static RzBinInfo *info(RzBinFile *bf) {
    if (MAJOR_VERSION != 5){
        eprintf("currently not support lua version < 5\n");
        return NULL;
    }

    switch (MINOR_VERSION) {
        case 4:
            return info_54(bf, MAJOR_VERSION, MINOR_VERSION);
            break;
        default:
            eprintf("lua 5.%c not support now\n", MINOR_VERSION + '0');
            return NULL;
    }
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