//
// Created by heersin on 3/1/21.
//

#include "luac_54.h"

RzBinInfo *info_54(RzBinFile *bf, int major, int minor)
{
    RzBinInfo *ret = NULL;
    luacHdr54 hdr;
    memset(&hdr, 0, LUAC_HDR_SIZE_54);

    int reat = rz_buf_read_at(bf->buf, 0, (ut8 *)&hdr, LUAC_HDR_SIZE_54);
    if (reat != LUAC_HDR_SIZE_54){
        eprintf("Truncated Header\n");
        return NULL;
    }
    if (!(ret = RZ_NEW0(RzBinInfo))){
        return NULL;
    }

    ret->file = strdup(bf->file);
    ret->type = rz_str_newf("Lua %c.%c compiled file", major + '0', minor + '0');
    ret->bclass = strdup("Lua compiled file");
    ret->rclass = strdup("luac");
    ret->arch = strdup("luac");
    ret->machine = rz_str_newf("Lua %c.%c VM ", major + '0', minor + '0');
    ret->os = strdup("any");
    ret->bits = 8;

    return ret;
}