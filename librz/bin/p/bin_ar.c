// SPDX-FileCopyrightText: 2026 Yashwin <iskalayashwinsai@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include <stdlib.h>

#define AR_MAGIC     "!<arch>\n"
#define AR_MAGIC_LEN 8
#define AR_HDR_SIZE  60

typedef struct {
    char name[16];
    char date[12];
    char uid[6];
    char gid[6];
    char mode[8];
    char size[10];
    char fmag[2];
} ar_hdr;

typedef struct ar_member_t {
    char *name;
    ut64 offset; ///< offset of the member's data within the archive buffer
    ut64 size;
} ArMember;

typedef struct ar_data_t {
    RzPVector *members; ///< list of ArMember*, one per non-special archive member
    char *arch;
    char *machine;
    char *os;
    int bits;
    bool big_endian;
    bool has_object; ///< true if at least one member was recognized as ELF/Mach-O/COFF
    bool mixed_arch; ///< true if recognized members disagree on arch/bits
} ArData;

static void ar_member_free(void *p) {
    ArMember *m = p;
    if (m) {
        free(m->name);
        free(m);
    }
}

static void ar_data_free(ArData *data) {
    if (!data) {
        return;
    }
    rz_pvector_free(data->members);
    free(data->arch);
    free(data->machine);
    free(data->os);
    free(data);
}

static ut32 read_u32(const ut8 *b, bool big_endian) {
    if (big_endian) {
        return ((ut32)b[0] << 24) | ((ut32)b[1] << 16) | ((ut32)b[2] << 8) | b[3];
    }
    return ((ut32)b[3] << 24) | ((ut32)b[2] << 16) | ((ut32)b[1] << 8) | b[0];
}

static bool ar_detect_elf(RzBuffer *buf, ut64 off, ut64 size, ArData *data) {
    if (size < 20) {
        return false;
    }
    ut8 ident[16];
    if (rz_buf_read_at(buf, off, ident, 16) != 16) {
        return false;
    }
    int ei_class = ident[4]; // 1 = 32-bit, 2 = 64-bit
    int ei_data = ident[5]; // 1 = LE, 2 = BE
    bool big_endian = (ei_data == 2);

    ut8 hdr2[4]; // e_type (2 bytes) followed by e_machine (2 bytes)
    if (rz_buf_read_at(buf, off + 16, hdr2, 4) != 4) {
        return false;
    }
    ut16 e_machine = big_endian
        ? (((ut16)hdr2[2] << 8) | hdr2[3])
        : (((ut16)hdr2[3] << 8) | hdr2[2]);

    const char *arch = "unknown";
    switch (e_machine) {
    case 3: arch = "x86"; break; // EM_386
    case 62: arch = "x86"; break; // EM_X86_64
    case 40: arch = "arm"; break; // EM_ARM
    case 183: arch = "arm"; break; // EM_AARCH64
    case 8: arch = "mips"; break; // EM_MIPS
    case 20: arch = "ppc"; break; // EM_PPC
    case 21: arch = "ppc"; break; // EM_PPC64
    case 2: arch = "sparc"; break; // EM_SPARC
    case 243: arch = "riscv"; break; // EM_RISCV
    default: break;
    }
    int bits = (ei_class == 2) ? 64 : 32;

    if (!data->has_object) {
        data->arch = rz_str_dup(arch);
        data->machine = rz_str_dup(arch);
        data->os = rz_str_dup("linux"); // heuristic: refine via EI_OSABI in a follow-up
        data->bits = bits;
        data->big_endian = big_endian;
        data->has_object = true;
    } else if (strcmp(data->arch, arch) != 0 || data->bits != bits) {
        data->mixed_arch = true;
    }
    return true;
}

static const ut8 MACHO_MAGIC_32[4] = { 0xfe, 0xed, 0xfa, 0xce };
static const ut8 MACHO_MAGIC_32_SWAP[4] = { 0xce, 0xfa, 0xed, 0xfe };
static const ut8 MACHO_MAGIC_64[4] = { 0xfe, 0xed, 0xfa, 0xcf };
static const ut8 MACHO_MAGIC_64_SWAP[4] = { 0xcf, 0xfa, 0xed, 0xfe };

static bool ar_detect_macho(RzBuffer *buf, ut64 off, ut64 size, ArData *data) {
    if (size < 8) {
        return false;
    }
    ut8 magic[4];
    if (rz_buf_read_at(buf, off, magic, 4) != 4) {
        return false;
    }

    bool is64, swapped;
    if (!memcmp(magic, MACHO_MAGIC_32, 4)) {
        is64 = false;
        swapped = false;
    } else if (!memcmp(magic, MACHO_MAGIC_32_SWAP, 4)) {
        is64 = false;
        swapped = true;
    } else if (!memcmp(magic, MACHO_MAGIC_64, 4)) {
        is64 = true;
        swapped = false;
    } else if (!memcmp(magic, MACHO_MAGIC_64_SWAP, 4)) {
        is64 = true;
        swapped = true;
    } else {
        return false;
    }

    ut8 cpu_bytes[4];
    if (rz_buf_read_at(buf, off + 4, cpu_bytes, 4) != 4) {
        return false;
    }
    ut32 cputype = read_u32(cpu_bytes, !swapped);

    const char *arch = "unknown";
    switch (cputype) {
    case 7: arch = "x86"; break; // CPU_TYPE_X86
    case 0x01000007: arch = "x86"; break; // CPU_TYPE_X86_64
    case 12: arch = "arm"; break; // CPU_TYPE_ARM
    case 0x0100000C: arch = "arm"; break; // CPU_TYPE_ARM64
    case 18: arch = "ppc"; break; // CPU_TYPE_POWERPC
    case 0x01000012: arch = "ppc"; break; // CPU_TYPE_POWERPC64
    default: break;
    }
    int bits = is64 ? 64 : 32;

    if (!data->has_object) {
        data->arch = rz_str_dup(arch);
        data->machine = rz_str_dup(arch);
        data->os = rz_str_dup("macos");
        data->bits = bits;
        data->big_endian = !swapped;
        data->has_object = true;
    } else if (strcmp(data->arch, arch) != 0 || data->bits != bits) {
        data->mixed_arch = true;
    }
    return true;
}

/**
 * COFF has no magic bytes: the header starts directly with a ut16 machine-type
 * field. We key off the known IMAGE_FILE_MACHINE_* constants as a heuristic,
 * same approach GNU binutils uses. Must be tried last in the dispatcher since
 * it has no unique signature to rule out false positives up front.
 */
static bool ar_detect_coff(RzBuffer *buf, ut64 off, ut64 size, ArData *data) {
    if (size < 20) {
        return false;
    }
    ut8 mbytes[2];
    if (rz_buf_read_at(buf, off, mbytes, 2) != 2) {
        return false;
    }
    ut16 machine = mbytes[0] | ((ut16)mbytes[1] << 8); // COFF header is always LE

    const char *arch = NULL;
    int bits = 32;
    switch (machine) {
    case 0x014c: arch = "x86"; bits = 32; break; // IMAGE_FILE_MACHINE_I386
    case 0x8664: arch = "x86"; bits = 64; break; // IMAGE_FILE_MACHINE_AMD64
    case 0x01c0: arch = "arm"; bits = 32; break; // IMAGE_FILE_MACHINE_ARM
    case 0xaa64: arch = "arm"; bits = 64; break; // IMAGE_FILE_MACHINE_ARM64
    case 0x0200: arch = "ia64"; bits = 64; break; // IMAGE_FILE_MACHINE_IA64
    default: return false;
    }

    if (!data->has_object) {
        data->arch = rz_str_dup(arch);
        data->machine = rz_str_dup(arch);
        data->os = rz_str_dup("windows");
        data->bits = bits;
        data->big_endian = false;
        data->has_object = true;
    } else if (strcmp(data->arch, arch) != 0 || data->bits != bits) {
        data->mixed_arch = true;
    }
    return true;
}

static bool ar_detect_member_arch(RzBuffer *buf, ut64 off, ut64 size, ArData *data) {
    if (size < 4) {
        return false;
    }
    ut8 magic[4];
    if (rz_buf_read_at(buf, off, magic, 4) != 4) {
        return false;
    }
    if (!memcmp(magic, "\x7f""ELF", 4)) {
        return ar_detect_elf(buf, off, size, data);
    }
    if (!memcmp(magic, MACHO_MAGIC_32, 4) || !memcmp(magic, MACHO_MAGIC_32_SWAP, 4) ||
        !memcmp(magic, MACHO_MAGIC_64, 4) || !memcmp(magic, MACHO_MAGIC_64_SWAP, 4)) {
        return ar_detect_macho(buf, off, size, data);
    }
    return ar_detect_coff(buf, off, size, data);
}

static ArData *ar_data_new(RzBuffer *buf, ut64 buf_size) {
    ArData *data = RZ_NEW0(ArData);
    if (!data) {
        return NULL;
    }
    data->members = rz_pvector_new((RzPVectorFree)ar_member_free);
    if (!data->members) {
        free(data);
        return NULL;
    }

    ut64 offset = AR_MAGIC_LEN;
    while (offset + AR_HDR_SIZE <= buf_size) {
        ar_hdr hdr;
        if (rz_buf_read_at(buf, offset, (ut8 *)&hdr, AR_HDR_SIZE) != AR_HDR_SIZE) {
            break;
        }
        if (hdr.fmag[0] != '`' || hdr.fmag[1] != '\n') {
            break;
        }

        char size_str[11] = { 0 };
        memcpy(size_str, hdr.size, 10);
        ut64 member_size = strtoull(size_str, NULL, 10);

        char name_str[17] = { 0 };
        memcpy(name_str, hdr.name, 16);
        for (int i = 15; i >= 0; i--) {
            if (name_str[i] == ' ' || name_str[i] == '\0') {
                name_str[i] = '\0';
            } else {
                break;
            }
        }

        // GNU symbol-table ("/") and extended-name-table ("//") members must be
        // identified before stripping the trailing "/" that regular short names
        // carry (e.g. "real.o/") -- otherwise "/" -> "" and "//" -> "/" and
        // neither special case is caught below.
        bool is_special = !strcmp(name_str, "/") || !strcmp(name_str, "//");

        if (!is_special) {
            size_t name_len = strlen(name_str);
            if (name_len > 0 && name_str[name_len - 1] == '/') {
                name_str[name_len - 1] = '\0';
            }
        }

        ut64 data_offset = offset + AR_HDR_SIZE;
        if (data_offset + member_size > buf_size) {
            break;
        }

        if (!is_special) {
            ArMember *m = RZ_NEW0(ArMember);
            if (m) {
                m->name = rz_str_dup(name_str[0] ? name_str : "obj");
                m->offset = data_offset;
                m->size = member_size;
                rz_pvector_push(data->members, m);
            }
            ar_detect_member_arch(buf, data_offset, member_size, data);
        }

        offset = data_offset + member_size;
        if (offset & 1) {
            offset++;
        }
    }

    return data;
}

static bool check_buffer(RzBuffer *b) {
    if (!b || rz_buf_size(b) < AR_MAGIC_LEN) {
        return false;
    }
    ut8 magic[AR_MAGIC_LEN];
    if (rz_buf_read_at(b, 0, magic, AR_MAGIC_LEN) != AR_MAGIC_LEN) {
        return false;
    }
    return !memcmp(magic, AR_MAGIC, AR_MAGIC_LEN);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *bin_obj, RzBuffer *buf, Sdb *sdb) {
    ut64 buf_size = rz_buf_size(buf);
    if (buf_size < AR_MAGIC_LEN) {
        return false;
    }
    ArData *data = ar_data_new(buf, buf_size);
    if (!data) {
        return false;
    }
    if (!data->has_object) {
        RZ_LOG_WARN("bin_ar: no recognized object files found inside archive; "
                    "opened as a raw archive with no architecture info\n");
    }
    if (data->mixed_arch) {
        RZ_LOG_WARN("bin_ar: archive contains object files of different architectures; "
                    "reporting the first one found\n");
    }
    bin_obj->bin_obj = data;
    bin_obj->size = buf_size;
    return true;
}

static RzPVector *sections(RzBinFile *bf) {
    if (!bf || !bf->o || !bf->o->bin_obj) {
        return NULL;
    }
    ArData *data = bf->o->bin_obj;

    RzPVector *sections_vec = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
    if (!sections_vec) {
        return NULL;
    }

    int idx = 0;
    void **it;
    rz_pvector_foreach(data->members, it) {
        ArMember *m = *it;
        RzBinSection *sec = RZ_NEW0(RzBinSection);
        if (!sec) {
            continue;
        }
        sec->name = rz_str_newf("%s_%d", m->name, idx);
        sec->size = m->size;
        sec->vsize = m->size;
        sec->paddr = m->offset;
        sec->vaddr = m->offset;
        sec->perm = RZ_PERM_R | RZ_PERM_W | RZ_PERM_X;
        rz_pvector_push(sections_vec, sec);
        idx++;
    }
    return sections_vec;
}

static RzBinInfo *info(RzBinFile *bf) {
    RzBinInfo *ret = RZ_NEW0(RzBinInfo);
    if (!ret) {
        return NULL;
    }
    ArData *data = (bf && bf->o) ? bf->o->bin_obj : NULL;

    ret->bclass = rz_str_dup("archive");
    ret->rclass = rz_str_dup("ar");
    ret->type = rz_str_dup("ar");

    if (data && data->has_object) {
        ret->arch = rz_str_dup(data->arch);
        ret->machine = rz_str_dup(data->machine);
        ret->os = rz_str_dup(data->os);
        ret->bits = data->bits;
        ret->big_endian = data->big_endian;
    } else {
        // Nothing detected inside the archive: leave arch/machine/os NULL
        // (already zeroed by RZ_NEW0) rather than a placeholder value, since
        // the core config only accepts real plugin names for asm.arch et al.
        ret->bits = 0;
    }
    return ret;
}

static ut64 baddr(RzBinFile *bf) {
    return 0;
}

static void destroy(RzBinFile *bf) {
    if (!bf || !bf->o) {
        return;
    }
    ar_data_free(bf->o->bin_obj);
    bf->o->bin_obj = NULL;
}

RzBinPlugin rz_bin_plugin_ar = {
    .name = "ar",
    .desc = "ar archive bin plugin",
    .license = "LGPL3",
    .check_buffer = &check_buffer,
    .load_buffer = &load_buffer,
    .info = &info,
    .sections = &sections,
    .baddr = &baddr,
    .destroy = &destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
    .type = RZ_LIB_TYPE_BIN,
    .data = &rz_bin_plugin_ar,
    .version = RZ_VERSION,
};
#endif