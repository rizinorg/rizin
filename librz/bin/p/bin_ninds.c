// SPDX-FileCopyrightText: 2015-2019 a0rtega
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

#include "../format/nin/nds.h"

static struct nds_hdr loaded_header;

static bool check_buffer(RzBuffer *b) {
	ut8 ninlogohead[6];
	if (rz_buf_read_at(b, 0xc0, ninlogohead, sizeof(ninlogohead)) == 6) {
		/* begin of nintendo logo =    \x24\xff\xae\x51\x69\x9a */
		if (!memcmp(ninlogohead, "\x24\xff\xae\x51\x69\x9a", 6)) {
			return true;
		}
		/* begin of Homebrew magic */
		if (!memcmp(ninlogohead, "\xC8\x60\x4F\xE2\x01\x70", 6)) {
			return true;
		}
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	rz_buf_read_at(b, 0, (ut8 *)&loaded_header, sizeof(loaded_header));
	*bin_obj = &loaded_header;
	return (*bin_obj != NULL);
}

static ut64 baddr(RzBinFile *bf) {
	return (ut64)loaded_header.arm9_ram_address;
}

static ut64 boffset(RzBinFile *bf) {
	return 0LL;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSection *ptr9 = NULL, *ptr7 = NULL;

	if (!(ret = rz_list_new())) {
		return NULL;
	}
	if (!(ptr9 = RZ_NEW0(RzBinSection))) {
		rz_list_free(ret);
		return NULL;
	}
	if (!(ptr7 = RZ_NEW0(RzBinSection))) {
		rz_list_free(ret);
		free(ptr9);
		return NULL;
	}

	ptr9->name = strdup("arm9");
	ptr9->size = loaded_header.arm9_size;
	ptr9->vsize = loaded_header.arm9_size;
	ptr9->paddr = loaded_header.arm9_rom_offset;
	ptr9->vaddr = loaded_header.arm9_ram_address;
	ptr9->perm = rz_str_rwx("rwx");
	ptr9->add = true;
	rz_list_append(ret, ptr9);

	ptr7->name = strdup("arm7");
	ptr7->size = loaded_header.arm7_size;
	ptr7->vsize = loaded_header.arm7_size;
	ptr7->paddr = loaded_header.arm7_rom_offset;
	ptr7->vaddr = loaded_header.arm7_ram_address;
	ptr7->perm = rz_str_rwx("rwx");
	ptr7->add = true;
	rz_list_append(ret, ptr7);

	return ret;
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_new();
	RzBinAddr *ptr9 = NULL, *ptr7 = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		ret->free = free;
		if (!(ptr9 = RZ_NEW0(RzBinAddr))) {
			rz_list_free(ret);
			return NULL;
		}
		if (!(ptr7 = RZ_NEW0(RzBinAddr))) {
			rz_list_free(ret);
			free(ptr9);
			return NULL;
		}

		/* ARM9 entry point */
		ptr9->vaddr = loaded_header.arm9_entry_address;
		// ptr9->paddr = loaded_header.arm9_entry_address;
		rz_list_append(ret, ptr9);

		/* ARM7 entry point */
		ptr7->vaddr = loaded_header.arm7_entry_address;
		// ptr7->paddr = loaded_header.arm7_entry_address;
		rz_list_append(ret, ptr7);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->buf, NULL);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (ret) {
		char *filepath = rz_str_newf("%.12s - %.4s",
			loaded_header.title, loaded_header.gamecode);
		ret->file = filepath;
		ret->type = strdup("ROM");
		ret->machine = strdup("Nintendo DS");
		ret->os = strdup("nds");
		ret->arch = strdup("arm");
		ret->has_va = true;
		ret->bits = 32;
	}
	return ret;
}

RzBinPlugin rz_bin_plugin_ninds = {
	.name = "ninds",
	.desc = "Nintendo DS format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.boffset = &boffset,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ninds,
	.version = RZ_VERSION
};
#endif
