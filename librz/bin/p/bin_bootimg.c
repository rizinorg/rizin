// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define BOOT_MAGIC                    "ANDROID!"
#define BOOT_MAGIC_SIZE               8
#define BOOT_NAME_SIZE                16
#define BOOT_ARGS_SIZE                512
#define BOOT_EXTRA_ARGS_SIZE          1024
#define BOOT_HEADER_VERSION_OFFSET    0x28
#define BOOT_IMAGE_HEADER_V3_PAGESIZE 4096
#define BOOT_KERNEL_ADDR_DEFAULT      0x00008000
#define BOOT_SECOND_ADDR_DEFAULT      0x00f00000
#define BOOT_RAMDISK_ADDR_DEFAULT     0x01000000
#define BOOT_DTB_ADDR_DEFAULT         0x01f00000

#define ADD_REMAINDER(val, aln) ((val) + ((aln) != 0 ? ((val) % (aln)) : 0))
#define ROUND_DOWN(val, aln)    ((aln) != 0 ? (((val) / (aln)) * (aln)) : (val))

/**
 * Boot image version 0
 */
typedef struct boot_img_hdr_0 {
	ut8 magic[BOOT_MAGIC_SIZE];
	ut32 kernel_size; ///< size in bytes
	ut32 kernel_addr; ///< physical load addr
	ut32 ramdisk_size; ///< size in bytes
	ut32 ramdisk_addr; ///< physical load addr
	ut32 second_size; ///< size in bytes
	ut32 second_addr; ///< physical load addr
	ut32 tags_addr; ///< physical addr for kernel tags
	ut32 page_size; ///< flash page size we assume
	ut32 unused; ///< must be 0
	ut32 os_version; ///< OS version
	char name[BOOT_NAME_SIZE]; ///< asciiz product name
	char cmdline[BOOT_ARGS_SIZE];
	ut32 id[8]; ///< timestamp / checksum / sha1 / etc
	/*
	 * Supplemental command line data; kept here to maintain
	 * binary compatibility with older versions of mkbootimg
	 */
	char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} BootImage0;

/**
 * Boot image version 1
 */
typedef struct boot_img_hdr_1 {
	ut8 magic[BOOT_MAGIC_SIZE];
	ut32 kernel_size; ///< size in bytes
	ut32 kernel_addr; ///< physical load addr
	ut32 ramdisk_size; ///< size in bytes
	ut32 ramdisk_addr; ///< physical load addr
	ut32 second_size; ///< size in bytes
	ut32 second_addr; ///< physical load addr
	ut32 tags_addr; ///< physical addr for kernel tags
	ut32 page_size; ///< flash page size we assume
	ut32 header_version; ///< Must be 1
	ut32 os_version;
	char name[BOOT_NAME_SIZE]; ///< asciiz product name
	char cmdline[BOOT_ARGS_SIZE];
	ut32 id[8]; ///< timestamp / checksum / sha1 / etc
	char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
	ut32 recovery_dtbo_acpio_size; ///< size of recovery image
	ut64 recovery_dtbo_acpio_offset; ///< offset in boot image
	ut32 header_size; ///< size of boot image header in bytes
} BootImage1;

/**
 * Boot image version 2
 */
typedef struct boot_img_hdr_2 {
	ut8 magic[BOOT_MAGIC_SIZE];
	ut32 kernel_size; ///< size in bytes
	ut32 kernel_addr; ///< physical load addr
	ut32 ramdisk_size; ///< size in bytes
	ut32 ramdisk_addr; ///< physical load addr
	ut32 second_size; ///< size in bytes
	ut32 second_addr; ///< physical load addr
	ut32 tags_addr; ///< physical addr for kernel tags
	ut32 page_size; ///< flash page size we assume
	ut32 header_version;
	ut32 os_version;
	char name[BOOT_NAME_SIZE]; ///< asciiz product name
	char cmdline[BOOT_ARGS_SIZE];
	ut32 id[8]; ///< timestamp / checksum / sha1 / etc
	char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
	ut32 recovery_dtbo_acpio_size; ///< size of recovery image
	ut64 recovery_dtbo_acpio_offset; ///< offset in boot image
	ut32 header_size; ///< size of boot image header in bytes
	ut32 dtb_size; ///< size of dtb image
	ut64 dtb_addr; ///< physical load address
} BootImage2;

/**
 * Boot image version 3
 */
typedef struct boot_img_hdr_3 {
	ut8 magic[BOOT_MAGIC_SIZE];
	ut32 kernel_size; ///< size in bytes
	ut32 ramdisk_size; ///< size in bytes
	ut32 os_version;
	ut32 header_size; ///< size of boot image header in bytes
	ut32 reserved[4];
	ut32 header_version; ///< offset remains constant for version check
	char cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
} BootImage3;

/**
 * Boot image version 4
 */
typedef struct boot_img_hdr_4 {
	ut8 magic[BOOT_MAGIC_SIZE];
	ut32 kernel_size; ///< size in bytes
	ut32 ramdisk_size; ///< size in bytes
	ut32 os_version;
	ut32 header_size; ///< size of boot image header in bytes
	ut32 reserved[4];
	ut32 header_version; ///< offset remains constant for version check
	char cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
	ut32 signature_size; ///< size in bytes
} BootImage4;

typedef struct boot_image_obj_s {
	Sdb *kv;
	ut32 version;
	ut32 header_size;
	union {
		BootImage0 v0;
		BootImage1 v1;
		BootImage2 v2;
		BootImage3 v3;
		BootImage4 v4;
	} bootimg;
} BootImageObj;

static bool bootimg_set_sdb_value(Sdb *db, const char *key, const char *value, size_t v_size) {
	if (RZ_STR_ISEMPTY(value)) {
		// ignore empty strings.
		sdb_set(db, key, "(empty)");
		return true;
	}

	char *safe = rz_str_ndup(value, v_size);
	if (!safe) {
		return false;
	}

	sdb_set(db, key, safe);
	free(safe);
	return true;
}

static bool bootimg_set_sdb_array32(Sdb *db, const char *key, const ut32 *value, size_t array_size) {
	for (size_t i = 0; i < array_size; i++) {
		sdb_array_insert_num(db, "id", i, value[i]);
	}
	return true;
}

static bool bootimg_parse_v0(RzBuffer *buf, ut64 off, BootImage0 *h, Sdb *db) {
	return rz_buf_read_offset(buf, &off, h->magic, sizeof(h->magic)) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->second_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->second_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->tags_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->page_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->unused) &&
		rz_buf_read_le32_offset(buf, &off, &h->os_version) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->name, sizeof(h->name)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->cmdline, sizeof(h->cmdline)) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[0]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[1]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[2]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[3]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[4]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[5]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[6]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[7]) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->extra_cmdline, sizeof(h->extra_cmdline)) &&
		bootimg_set_sdb_value(db, "name", h->name, sizeof(h->name)) &&
		bootimg_set_sdb_value(db, "cmdline", h->cmdline, sizeof(h->cmdline)) &&
		bootimg_set_sdb_array32(db, "id", h->id, RZ_ARRAY_SIZE(h->id)) &&
		bootimg_set_sdb_value(db, "extra_cmdline", h->extra_cmdline, sizeof(h->extra_cmdline));
}

static bool bootimg_parse_v1(RzBuffer *buf, ut64 off, BootImage1 *h, Sdb *db) {
	return rz_buf_read_offset(buf, &off, h->magic, sizeof(h->magic)) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->second_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->second_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->tags_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->page_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_version) &&
		rz_buf_read_le32_offset(buf, &off, &h->os_version) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->name, sizeof(h->name)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->cmdline, sizeof(h->cmdline)) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[0]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[1]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[2]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[3]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[4]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[5]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[6]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[7]) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->extra_cmdline, sizeof(h->extra_cmdline)) &&
		rz_buf_read_le32_offset(buf, &off, &h->recovery_dtbo_acpio_size) &&
		rz_buf_read_le64_offset(buf, &off, &h->recovery_dtbo_acpio_offset) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_size) &&
		bootimg_set_sdb_value(db, "name", h->name, sizeof(h->name)) &&
		bootimg_set_sdb_value(db, "cmdline", h->cmdline, sizeof(h->cmdline)) &&
		bootimg_set_sdb_array32(db, "id", h->id, RZ_ARRAY_SIZE(h->id)) &&
		bootimg_set_sdb_value(db, "extra_cmdline", h->extra_cmdline, sizeof(h->extra_cmdline));
}

static bool bootimg_parse_v2(RzBuffer *buf, ut64 off, BootImage2 *h, Sdb *db) {
	return rz_buf_read_offset(buf, &off, h->magic, sizeof(h->magic)) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->second_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->second_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->tags_addr) &&
		rz_buf_read_le32_offset(buf, &off, &h->page_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_version) &&
		rz_buf_read_le32_offset(buf, &off, &h->os_version) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->name, sizeof(h->name)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->cmdline, sizeof(h->cmdline)) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[0]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[1]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[2]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[3]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[4]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[5]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[6]) &&
		rz_buf_read_le32_offset(buf, &off, &h->id[7]) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->extra_cmdline, sizeof(h->extra_cmdline)) &&
		rz_buf_read_le32_offset(buf, &off, &h->recovery_dtbo_acpio_size) &&
		rz_buf_read_le64_offset(buf, &off, &h->recovery_dtbo_acpio_offset) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->dtb_size) &&
		rz_buf_read_le64_offset(buf, &off, &h->dtb_addr) &&
		bootimg_set_sdb_value(db, "name", h->name, sizeof(h->name)) &&
		bootimg_set_sdb_value(db, "cmdline", h->cmdline, sizeof(h->cmdline)) &&
		bootimg_set_sdb_array32(db, "id", h->id, RZ_ARRAY_SIZE(h->id)) &&
		bootimg_set_sdb_value(db, "extra_cmdline", h->extra_cmdline, sizeof(h->extra_cmdline));
}

static bool bootimg_parse_v3(RzBuffer *buf, ut64 off, BootImage3 *h, Sdb *db) {
	return rz_buf_read_offset(buf, &off, h->magic, sizeof(h->magic)) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->os_version) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[0]) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[1]) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[2]) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[3]) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_version) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->cmdline, sizeof(h->cmdline)) &&
		bootimg_set_sdb_value(db, "cmdline", h->cmdline, sizeof(h->cmdline));
}

static bool bootimg_parse_v4(RzBuffer *buf, ut64 off, BootImage4 *h, Sdb *db) {
	return rz_buf_read_offset(buf, &off, h->magic, sizeof(h->magic)) &&
		rz_buf_read_le32_offset(buf, &off, &h->kernel_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->ramdisk_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->os_version) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_size) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[0]) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[1]) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[2]) &&
		rz_buf_read_le32_offset(buf, &off, &h->reserved[3]) &&
		rz_buf_read_le32_offset(buf, &off, &h->header_version) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->cmdline, sizeof(h->cmdline)) &&
		rz_buf_read_le32_offset(buf, &off, &h->signature_size) &&
		bootimg_set_sdb_value(db, "cmdline", h->cmdline, sizeof(h->cmdline));
}

static void bootimg_free(BootImageObj *bio) {
	if (!bio) {
		return;
	}
	sdb_free(bio->kv);
	free(bio);
}

static bool bootimg_parse(RzBuffer *buf, ut64 off, BootImageObj *img) {
	sdb_num_set(img->kv, "header_version", img->version);
	switch (img->version) {
	case 0:
		img->header_size = sizeof(BootImage0);
		return bootimg_parse_v0(buf, off, &img->bootimg.v0, img->kv);
	case 1:
		img->header_size = sizeof(BootImage1);
		return bootimg_parse_v1(buf, off, &img->bootimg.v1, img->kv);
	case 2:
		img->header_size = sizeof(BootImage2);
		return bootimg_parse_v2(buf, off, &img->bootimg.v2, img->kv);
	case 3:
		img->header_size = sizeof(BootImage3);
		return bootimg_parse_v3(buf, off, &img->bootimg.v3, img->kv);
	case 4:
		img->header_size = sizeof(BootImage4);
		return bootimg_parse_v4(buf, off, &img->bootimg.v4, img->kv);
	default:
		RZ_LOG_ERROR("bootimg: unsupported version v%u\n", img->version);
		return false;
	}
}

static bool bootimg_check_buffer(RzBuffer *buf) {
	ut8 tmp[8] = { 0 };
	if (rz_buf_read_at(buf, 0, tmp, 8) != 8) {
		return false;
	}
	return !memcmp(tmp, (const ut8 *)"ANDROID!", 8);
}

static bool bootimg_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	BootImageObj *img = RZ_NEW0(BootImageObj);
	if (!img) {
		return false;
	}

	if (!rz_buf_read_le32_at(buf, BOOT_HEADER_VERSION_OFFSET, &img->version)) {
		bootimg_free(img);
		return false;
	}

	img->kv = sdb_new0();
	if (!img->kv || !bootimg_parse(buf, 0, img)) {
		bootimg_free(img);
		return false;
	}

	sdb_ns_set(sdb, "info", img->kv);
	obj->bin_obj = img;
	return true;
}

static void bootimg_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}
	BootImageObj *img = bf->o->bin_obj;
	bf->o->bin_obj = NULL;
	bootimg_free(img);
}

static Sdb *bootimg_get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	BootImageObj *ao;
	if (!o) {
		return NULL;
	}
	ao = o->bin_obj;
	return ao ? ao->kv : NULL;
}

static ut64 bootimg_kernel_vaddr(const BootImageObj *bio) {
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.kernel_addr;
	case 1:
		return bio->bootimg.v1.kernel_addr;
	case 2:
		return bio->bootimg.v2.kernel_addr;
	case 3:
		// TODO: requires parsing the vendor boot header.
		rz_warn_if_reached();
		return BOOT_KERNEL_ADDR_DEFAULT;
	case 4:
		// TODO: requires parsing the vendor boot header.
		rz_warn_if_reached();
		return BOOT_KERNEL_ADDR_DEFAULT;
	default:
		// default based on mkbootimg
		return BOOT_KERNEL_ADDR_DEFAULT;
	}
}

static ut64 bootimg_page_size(const BootImageObj *bio) {
	// before v3 the page_size is available, afterwards is at 4096
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.page_size;
	case 1:
		return bio->bootimg.v1.page_size;
	case 2:
		return bio->bootimg.v2.page_size;
	default:
		return BOOT_IMAGE_HEADER_V3_PAGESIZE;
	}
}

static ut64 bootimg_kernel_size(const BootImageObj *bio) {
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.kernel_size;
	case 1:
		return bio->bootimg.v1.kernel_size;
	case 2:
		return bio->bootimg.v2.kernel_size;
	case 3:
		return bio->bootimg.v3.kernel_size;
	case 4:
		return bio->bootimg.v4.kernel_size;
	default:
		return 0;
	}
}

static ut64 bootimg_ramdisk_vaddr(const BootImageObj *bio) {
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.ramdisk_addr;
	case 1:
		return bio->bootimg.v1.ramdisk_addr;
	case 2:
		return bio->bootimg.v2.ramdisk_addr;
	case 3:
		// TODO: requires parsing the vendor boot header.
		rz_warn_if_reached();
		return BOOT_RAMDISK_ADDR_DEFAULT;
	case 4:
		// TODO: requires parsing the vendor boot header.
		rz_warn_if_reached();
		return BOOT_RAMDISK_ADDR_DEFAULT;
	default:
		// default based on mkbootimg
		return BOOT_RAMDISK_ADDR_DEFAULT;
	}
}

static ut64 bootimg_ramdisk_size(const BootImageObj *bio) {
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.ramdisk_size;
	case 1:
		return bio->bootimg.v1.ramdisk_size;
	case 2:
		return bio->bootimg.v2.ramdisk_size;
	case 3:
		return bio->bootimg.v3.ramdisk_size;
	case 4:
		return bio->bootimg.v4.ramdisk_size;
	default:
		return 0;
	}
}

static ut64 bootimg_second_vaddr(const BootImageObj *bio) {
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.second_addr;
	case 1:
		return bio->bootimg.v1.second_addr;
	case 2:
		return bio->bootimg.v2.second_addr;
	default:
		// from v3 the secondary bootloader does not exists.
		return 0;
	}
}

static ut64 bootimg_second_size(const BootImageObj *bio) {
	switch (bio->version) {
	case 0:
		return bio->bootimg.v0.second_size;
	case 1:
		return bio->bootimg.v1.second_size;
	case 2:
		return bio->bootimg.v2.second_size;
	default:
		// from v3 the secondary bootloader does not exists.
		return 0;
	}
}

static ut64 bootimg_baddr(RzBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	return bootimg_kernel_vaddr(bio);
}

static RzBinInfo *bootimg_info(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	BootImageObj *bio = bf->o->bin_obj;

	ret->lang = NULL;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_newf("Android Boot Image)");
	ret->bclass = rz_str_newf("Android Boot Image (v%u)", bio->version);
	ret->os = rz_str_dup("android");
	ret->subsystem = rz_str_dup("unknown");
	ret->machine = rz_str_dup("arm");
	ret->arch = rz_str_dup("arm");
	ret->has_va = 1;
	ret->has_pi = 0;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->rclass = rz_str_dup("bootimg");
	return ret;
}

static void bootimg_structure_v0(const BootImage0 *bi, RzStructuredData *root) {
	rz_structured_data_map_add_bytes(root, "magic", bi->magic, sizeof(bi->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(root, "kernel_size", bi->kernel_size, false);
	rz_structured_data_map_add_unsigned(root, "kernel_addr", bi->kernel_addr, true);
	rz_structured_data_map_add_unsigned(root, "ramdisk_size", bi->ramdisk_size, false);
	rz_structured_data_map_add_unsigned(root, "ramdisk_addr", bi->ramdisk_addr, true);
	rz_structured_data_map_add_unsigned(root, "second_size", bi->second_size, false);
	rz_structured_data_map_add_unsigned(root, "second_addr", bi->second_addr, true);
	rz_structured_data_map_add_unsigned(root, "tags_addr", bi->tags_addr, true);
	rz_structured_data_map_add_unsigned(root, "page_size", bi->page_size, false);
	rz_structured_data_map_add_unsigned(root, "unused", bi->unused, true);
	rz_structured_data_map_add_unsigned(root, "os_version", bi->os_version, true);
	rz_structured_data_map_add_string_n(root, "name", bi->name, sizeof(bi->name));
	rz_structured_data_map_add_string_n(root, "cmdline", bi->cmdline, sizeof(bi->cmdline));

	RzStructuredData *id_array = rz_structured_data_map_add_array(root, "id");
	if (id_array) {
		rz_structured_data_array_add_unsigned(id_array, bi->id[0], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[1], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[2], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[3], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[4], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[5], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[6], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[7], true);
	}

	rz_structured_data_map_add_string_n(root, "extra_cmdline", bi->extra_cmdline, sizeof(bi->extra_cmdline));
}

static void bootimg_structure_v1(const BootImage1 *bi, RzStructuredData *root) {
	rz_structured_data_map_add_bytes(root, "magic", bi->magic, sizeof(bi->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(root, "kernel_size", bi->kernel_size, false);
	rz_structured_data_map_add_unsigned(root, "kernel_addr", bi->kernel_addr, true);
	rz_structured_data_map_add_unsigned(root, "ramdisk_size", bi->ramdisk_size, false);
	rz_structured_data_map_add_unsigned(root, "ramdisk_addr", bi->ramdisk_addr, true);
	rz_structured_data_map_add_unsigned(root, "second_size", bi->second_size, false);
	rz_structured_data_map_add_unsigned(root, "second_addr", bi->second_addr, true);
	rz_structured_data_map_add_unsigned(root, "tags_addr", bi->tags_addr, true);
	rz_structured_data_map_add_unsigned(root, "page_size", bi->page_size, false);
	rz_structured_data_map_add_unsigned(root, "header_version", bi->header_version, true);
	rz_structured_data_map_add_unsigned(root, "os_version", bi->os_version, true);
	rz_structured_data_map_add_string_n(root, "name", bi->name, sizeof(bi->name));
	rz_structured_data_map_add_string_n(root, "cmdline", bi->cmdline, sizeof(bi->cmdline));

	RzStructuredData *id_array = rz_structured_data_map_add_array(root, "id");
	if (id_array) {
		rz_structured_data_array_add_unsigned(id_array, bi->id[0], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[1], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[2], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[3], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[4], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[5], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[6], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[7], true);
	}

	rz_structured_data_map_add_string_n(root, "extra_cmdline", bi->extra_cmdline, sizeof(bi->extra_cmdline));
	rz_structured_data_map_add_unsigned(root, "recovery_dtbo_acpio_size", bi->recovery_dtbo_acpio_size, false);
	rz_structured_data_map_add_unsigned(root, "recovery_dtbo_acpio_offset", bi->recovery_dtbo_acpio_offset, true);
	rz_structured_data_map_add_unsigned(root, "header_size", bi->header_size, false);
}

static void bootimg_structure_v2(const BootImage2 *bi, RzStructuredData *root) {
	rz_structured_data_map_add_bytes(root, "magic", bi->magic, sizeof(bi->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(root, "kernel_size", bi->kernel_size, false);
	rz_structured_data_map_add_unsigned(root, "kernel_addr", bi->kernel_addr, true);
	rz_structured_data_map_add_unsigned(root, "ramdisk_size", bi->ramdisk_size, false);
	rz_structured_data_map_add_unsigned(root, "ramdisk_addr", bi->ramdisk_addr, true);
	rz_structured_data_map_add_unsigned(root, "second_size", bi->second_size, false);
	rz_structured_data_map_add_unsigned(root, "second_addr", bi->second_addr, true);
	rz_structured_data_map_add_unsigned(root, "tags_addr", bi->tags_addr, true);
	rz_structured_data_map_add_unsigned(root, "page_size", bi->page_size, false);
	rz_structured_data_map_add_unsigned(root, "header_version", bi->header_version, true);
	rz_structured_data_map_add_unsigned(root, "os_version", bi->os_version, true);
	rz_structured_data_map_add_string_n(root, "name", bi->name, sizeof(bi->name));
	rz_structured_data_map_add_string_n(root, "cmdline", bi->cmdline, sizeof(bi->cmdline));

	RzStructuredData *id_array = rz_structured_data_map_add_array(root, "id");
	if (id_array) {
		rz_structured_data_array_add_unsigned(id_array, bi->id[0], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[1], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[2], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[3], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[4], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[5], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[6], true);
		rz_structured_data_array_add_unsigned(id_array, bi->id[7], true);
	}

	rz_structured_data_map_add_string_n(root, "extra_cmdline", bi->extra_cmdline, sizeof(bi->extra_cmdline));
	rz_structured_data_map_add_unsigned(root, "recovery_dtbo_acpio_size", bi->recovery_dtbo_acpio_size, false);
	rz_structured_data_map_add_unsigned(root, "recovery_dtbo_acpio_offset", bi->recovery_dtbo_acpio_offset, true);
	rz_structured_data_map_add_unsigned(root, "header_size", bi->header_size, false);
	rz_structured_data_map_add_unsigned(root, "dtb_size", bi->dtb_size, false);
	rz_structured_data_map_add_unsigned(root, "dtb_addr", bi->dtb_addr, true);
}

static void bootimg_structure_v3(const BootImage3 *bi, RzStructuredData *root) {
	rz_structured_data_map_add_bytes(root, "magic", bi->magic, sizeof(bi->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(root, "kernel_size", bi->kernel_size, false);
	rz_structured_data_map_add_unsigned(root, "ramdisk_size", bi->ramdisk_size, false);
	rz_structured_data_map_add_unsigned(root, "os_version", bi->os_version, true);
	rz_structured_data_map_add_unsigned(root, "header_size", bi->header_size, false);
	RzStructuredData *reserved = rz_structured_data_map_add_array(root, "reserved");
	if (reserved) {
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[0], true);
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[1], true);
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[2], true);
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[3], true);
	}
	rz_structured_data_map_add_unsigned(root, "header_version", bi->header_version, false);
	rz_structured_data_map_add_string_n(root, "cmdline", bi->cmdline, sizeof(bi->cmdline));
}

static void bootimg_structure_v4(const BootImage4 *bi, RzStructuredData *root) {
	rz_structured_data_map_add_bytes(root, "magic", bi->magic, sizeof(bi->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(root, "kernel_size", bi->kernel_size, false);
	rz_structured_data_map_add_unsigned(root, "ramdisk_size", bi->ramdisk_size, false);
	rz_structured_data_map_add_unsigned(root, "os_version", bi->os_version, true);
	rz_structured_data_map_add_unsigned(root, "header_size", bi->header_size, false);
	RzStructuredData *reserved = rz_structured_data_map_add_array(root, "reserved");
	if (reserved) {
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[0], true);
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[1], true);
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[2], true);
		rz_structured_data_array_add_unsigned(reserved, bi->reserved[3], true);
	}
	rz_structured_data_map_add_unsigned(root, "header_version", bi->header_version, false);
	rz_structured_data_map_add_string_n(root, "cmdline", bi->cmdline, sizeof(bi->cmdline));
	rz_structured_data_map_add_unsigned(root, "signature_size", bi->signature_size, false);
}

static RzStructuredData *bootimg_structure(RzBinFile *bf) {
	BootImageObj *img = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_map_add_map(info, "bootimg");
	if (!root) {
		rz_structured_data_free(info);
		return NULL;
	}

	switch (img->version) {
	case 0:
		bootimg_structure_v0(&img->bootimg.v0, root);
		break;
	case 1:
		bootimg_structure_v1(&img->bootimg.v1, root);
		break;
	case 2:
		bootimg_structure_v2(&img->bootimg.v2, root);
		break;
	case 3:
		bootimg_structure_v3(&img->bootimg.v3, root);
		break;
	case 4:
		bootimg_structure_v4(&img->bootimg.v4, root);
		break;
	default:
		rz_structured_data_free(info);
		return NULL;
	}

	return info;
}

static RzPVector /*<RzBinAddr *>*/ *bootimg_entries(RzBinFile *bf) {
	BootImageObj *img = bf->o->bin_obj;
	RzBinAddr *ptr = NULL;
	if (!img) {
		return NULL;
	}
	RzPVector *ret;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}

	ptr->paddr = bootimg_page_size(img);
	ptr->vaddr = bootimg_kernel_vaddr(img);
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzBinSection *bootimg_bin_section_new(const char *name, ut64 paddr, size_t psize, ut64 vaddr, size_t vsize, ut32 perm) {
	RzBinSection *sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		return NULL;
	}
	sec->name = rz_str_dup(name);
	if (!sec->name) {
		free(sec);
		return NULL;
	}

	sec->paddr = paddr;
	sec->size = psize;
	sec->vaddr = vaddr;
	sec->vsize = vsize;
	sec->perm = perm;
	return sec;
}

static void bootimg_sections_add_ramdisk(BootImageObj *img, RzPVector /*<RzBinSection *>*/ *ret) {
	ut64 kernel_size = bootimg_kernel_size(img);
	ut64 ramdisk_size = bootimg_ramdisk_size(img);
	ut64 page_size = bootimg_page_size(img);
	ut64 ramdisk_addr = bootimg_ramdisk_vaddr(img);
	if (ramdisk_size < 1) {
		return;
	}

	ut64 base = kernel_size + 2 * page_size - 1;
	ut64 paddr = ROUND_DOWN(base, page_size);
	size_t vsize = ADD_REMAINDER(ramdisk_size, page_size);

	RzBinSection *ptr = bootimg_bin_section_new("ramdisk", paddr, ramdisk_size, ramdisk_addr, vsize, RZ_PERM_RX);
	if (!ptr || !rz_pvector_push(ret, ptr)) {
		rz_bin_section_free(ptr);
	}
}

static void bootimg_sections_add_secondary_bootloader(BootImageObj *img, RzPVector /*<RzBinSection *>*/ *ret) {
	ut64 second_size = bootimg_second_size(img);
	ut64 second_addr = bootimg_second_vaddr(img);
	ut64 kernel_size = bootimg_kernel_size(img);
	ut64 ramdisk_size = bootimg_ramdisk_size(img);
	ut64 page_size = bootimg_page_size(img);
	if (second_size < 1) {
		return;
	}

	ut64 base = kernel_size + ramdisk_size + 2 * page_size - 1;
	ut64 paddr = ROUND_DOWN(base, page_size);
	size_t vsize = ADD_REMAINDER(second_size, page_size);

	RzBinSection *ptr = bootimg_bin_section_new("second", paddr, second_size, second_addr, vsize, RZ_PERM_RX);
	if (!ptr || !rz_pvector_push(ret, ptr)) {
		rz_bin_section_free(ptr);
	}
}

static RzPVector /*<RzBinSection *>*/ *bootimg_sections(RzBinFile *bf) {
	BootImageObj *img = bf->o->bin_obj;
	if (!img) {
		return NULL;
	}
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;

	ut64 kernel_size = bootimg_kernel_size(img);
	ut64 page_size = bootimg_page_size(img);
	ut64 kernel_vaddr = bootimg_kernel_vaddr(img);

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}

	ptr = bootimg_bin_section_new("header", 0, img->header_size, 0, page_size, RZ_PERM_R);
	if (!ptr || !rz_pvector_push(ret, ptr)) {
		rz_bin_section_free(ptr);
		return ret;
	}

	size_t kernel_vsize = ADD_REMAINDER(kernel_size, page_size);
	ptr = bootimg_bin_section_new("kernel", page_size, kernel_size, kernel_vaddr, kernel_vsize, RZ_PERM_R);
	if (!ptr || !rz_pvector_push(ret, ptr)) {
		rz_bin_section_free(ptr);
		return ret;
	}

	bootimg_sections_add_ramdisk(img, ret);
	bootimg_sections_add_secondary_bootloader(img, ret);

	return ret;
}

RzBinPlugin rz_bin_plugin_bootimg = {
	.name = "bootimg",
	.desc = "Android Boot Image",
	.license = "LGPL3",
	.author = "pancake",
	.get_sdb = &bootimg_get_sdb,
	.load_buffer = &bootimg_load_buffer,
	.destroy = &bootimg_destroy,
	.check_buffer = &bootimg_check_buffer,
	.baddr = &bootimg_baddr,
	.maps = rz_bin_maps_of_file_sections,
	.sections = &bootimg_sections,
	.entries = &bootimg_entries,
	.info = &bootimg_info,
	.bin_structure = &bootimg_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bootimg,
	.version = RZ_VERSION
};
#endif
