// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

typedef struct boot_img_hdr BootImage;

#define BOOT_MAGIC           "ANDROID!"
#define BOOT_MAGIC_SIZE      8
#define BOOT_NAME_SIZE       16
#define BOOT_ARGS_SIZE       512
#define BOOT_EXTRA_ARGS_SIZE 1024

#define ADD_REMAINDER(val, aln) ((val) + ((aln) != 0 ? ((val) % (aln)) : 0))
#define ROUND_DOWN(val, aln)    ((aln) != 0 ? (((val) / (aln)) * (aln)) : (val))

RZ_PACKED(
	struct boot_img_hdr {
		ut8 magic[BOOT_MAGIC_SIZE];

		ut32 kernel_size; /* size in bytes */
		ut32 kernel_addr; /* physical load addr */

		ut32 ramdisk_size; /* size in bytes */
		ut32 ramdisk_addr; /* physical load addr */

		ut32 second_size; /* size in bytes */
		ut32 second_addr; /* physical load addr */

		ut32 tags_addr; /* physical addr for kernel tags */
		ut32 page_size; /* flash page size we assume */
		ut32 unused[2]; /* future expansion: should be 0 */
		ut8 name[BOOT_NAME_SIZE]; /* asciiz product name */
		ut8 cmdline[BOOT_ARGS_SIZE];
		ut32 id[8]; /* timestamp / checksum / sha1 / etc */

		/* Supplemental command line data; kept here to maintain
		 * binary compatibility with older versions of mkbootimg */
		ut8 extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
	});

typedef struct {
	Sdb *kv;
	BootImage bi;
	RzBuffer *buf;
} BootImageObj;

static int bootimg_header_load(BootImageObj *obj, Sdb *db) {
	char *n;
	int i;
	if (rz_buf_size(obj->buf) < sizeof(BootImage)) {
		return false;
	}
	// TODO make it endian-safe (void)rz_buf_fread_at (buf, 0, (ut8*)bi, "IIiiiiiiiiiiii", 1);
	BootImage *bi = &obj->bi;
	(void)rz_buf_read_at(obj->buf, 0, (ut8 *)bi, sizeof(BootImage));
	if ((n = rz_str_ndup((char *)bi->name, BOOT_NAME_SIZE))) {
		sdb_set(db, "name", n);
		free(n);
	}
	if ((n = rz_str_ndup((char *)bi->cmdline, BOOT_ARGS_SIZE))) {
		sdb_set(db, "cmdline", n);
		free(n);
	}
	for (i = 0; i < 8; i++) {
		sdb_num_set(db, "id", (ut64)bi->id[i]);
	}
	if ((n = rz_str_ndup((char *)bi->extra_cmdline, BOOT_EXTRA_ARGS_SIZE))) {
		sdb_set(db, "extra_cmdline", n);
		free(n);
	}
	return true;
}

static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	BootImageObj *ao;
	if (!o) {
		return NULL;
	}
	ao = o->bin_obj;
	return ao ? ao->kv : NULL;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	BootImageObj *bio = RZ_NEW0(BootImageObj);
	if (!bio) {
		return false;
	}
	bio->kv = sdb_new0();
	if (!bio->kv) {
		free(bio);
		return false;
	}
	bio->buf = rz_buf_ref(buf);
	if (!bootimg_header_load(bio, bio->kv)) {
		free(bio);
		return false;
	}
	sdb_ns_set(sdb, "info", bio->kv);
	obj->bin_obj = bio;
	return true;
}

static void destroy(RzBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	rz_buf_free(bio->buf);
	RZ_FREE(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	return bio ? bio->bi.kernel_addr : 0;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->lang = NULL;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("Android Boot Image");
	ret->os = rz_str_dup("android");
	ret->subsystem = rz_str_dup("unknown");
	ret->machine = rz_str_dup("arm");
	ret->arch = rz_str_dup("arm");
	ret->has_va = 1;
	ret->has_pi = 0;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->rclass = rz_str_dup("image");
	return ret;
}

static bool check_buffer(RzBuffer *buf) {
	ut8 tmp[13];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	return r > 12 && !strncmp((const char *)tmp, "ANDROID!", 8);
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	RzBinAddr *ptr = NULL;
	if (!bio) {
		return NULL;
	}
	BootImage *bi = &bio->bi;
	RzPVector *ret;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = bi->page_size;
	ptr->vaddr = bi->kernel_addr;
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	if (!bio) {
		return NULL;
	}
	BootImage *bi = &bio->bi;
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("header");
	ptr->size = sizeof(BootImage);
	ptr->vsize = bi->page_size;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = RZ_PERM_R; // r--
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("kernel");
	ptr->size = bi->kernel_size;
	ptr->vsize = ADD_REMAINDER(ptr->size, bi->page_size);
	ptr->paddr = bi->page_size;
	ptr->vaddr = bi->kernel_addr;
	ptr->perm = RZ_PERM_R; // r--
	rz_pvector_push(ret, ptr);

	if (bi->ramdisk_size > 0) {
		ut64 base = bi->kernel_size + 2 * bi->page_size - 1;
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("ramdisk");
		ptr->size = bi->ramdisk_size;
		ptr->vsize = ADD_REMAINDER(bi->ramdisk_size, bi->page_size);
		ptr->paddr = ROUND_DOWN(base, bi->page_size);
		ptr->vaddr = bi->ramdisk_addr;
		ptr->perm = RZ_PERM_RX; // r-x
		rz_pvector_push(ret, ptr);
	}

	if (bi->second_size > 0) {
		ut64 base = bi->kernel_size + bi->ramdisk_size + 2 * bi->page_size - 1;
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("second");
		ptr->size = bi->second_size;
		ptr->vsize = ADD_REMAINDER(bi->second_size, bi->page_size);
		ptr->paddr = ROUND_DOWN(base, bi->page_size);
		ptr->vaddr = bi->second_addr;
		ptr->perm = RZ_PERM_RX; // r-x
		rz_pvector_push(ret, ptr);
	}

	return ret;
}

RzBinPlugin rz_bin_plugin_bootimg = {
	.name = "bootimg",
	.desc = "Android Boot Image",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.maps = rz_bin_maps_of_file_sections,
	.sections = &sections,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bootimg,
	.version = RZ_VERSION
};
#endif
