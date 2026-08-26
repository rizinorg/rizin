// SPDX-FileCopyrightText: 2026 Yashwin <iskalayashwinsai@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define AR_MAGIC "!<arch>\n"
#define AR_MAGIC_LEN 8
#define AR_HDR_SIZE 60

typedef struct {
    char name[16];
    char date[12];
    char uid[6];
    char gid[6];
    char mode[8];
    char size[10];
    char fmag[2];
} ar_hdr;

static bool check_bytes(const ut8 *buf, ut64 length) {
    if (length < AR_MAGIC_LEN) return false;
    return !memcmp(buf, AR_MAGIC, AR_MAGIC_LEN);
}

// CRITICAL: Rizin requires this callback to populate the 'iI' command
static RzBinInfo *info(RzBinFile *bf) {
    RzBinInfo *ret = RZ_NEW0(RzBinInfo);
    if (!ret) return NULL;
    ret->bclass = rz_str_dup("archive");
    ret->type = rz_str_dup("ar");
    ret->machine = rz_str_dup("any");
    ret->os = rz_str_dup("any");
    ret->arch = rz_str_dup("any");
    ret->bits = 32;
    return ret;
}

static ut64 baddr(RzBinFile *bf) {
    return 0;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *bin_obj, RzBuffer *buf, Sdb *sdb) {
    ut64 buf_size = rz_buf_size(buf);
    if (buf_size < AR_MAGIC_LEN) return false;

    // Prevent Rizin from silently dropping the object
    bin_obj->size = buf_size; 

    if (!bin_obj->sections) {
        bin_obj->sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
    }

    ut64 offset = AR_MAGIC_LEN;
    int obj_count = 0;
    
    // Dynamically parse the actual .a archive headers
    while (offset + AR_HDR_SIZE <= buf_size) {
        ar_hdr hdr;
        if (rz_buf_read_at(buf, offset, (ut8 *)&hdr, AR_HDR_SIZE) != AR_HDR_SIZE) break;
        if (hdr.fmag[0] != '`' || hdr.fmag[1] != '\n') break;

        char size_str[11] = {0};
        memcpy(size_str, hdr.size, 10);
        ut64 file_size = strtoull(size_str, NULL, 10);

        char name_str[17] = {0};
        memcpy(name_str, hdr.name, 16);
        char *slash = strchr(name_str, '/');
        if (slash) *slash = '\0';
        char *space = strchr(name_str, ' ');
        if (space) *space = '\0';

        offset += AR_HDR_SIZE;
        if (offset + file_size > buf_size) break;

        RzBinSection *sec = RZ_NEW0(RzBinSection);
        if (sec) {
            sec->name = rz_str_newf("%s_%d", name_str[0] ? name_str : "obj", obj_count);
            sec->size = file_size;
            sec->vsize = file_size;
            sec->paddr = offset;
            sec->vaddr = offset; // Linear mapping
            sec->perm = RZ_PERM_R | RZ_PERM_W | RZ_PERM_X;
            rz_pvector_push(bin_obj->sections, sec);
        }

        obj_count++;
        offset += file_size;
        
        // ar archives align to 2-byte boundaries
        if (offset % 2 != 0) offset++;
    }
    return true;
}

RzBinPlugin rz_bin_plugin_ar = {
    .name = "ar",
    .desc = "ar archive bin plugin",
    .license = "LGPL3",
    .check_bytes = check_bytes,
    .load_buffer = load_buffer,
    .info = info,       // <--- Fixes the 'iI' N/A bug
    .baddr = baddr,
};