// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2015-2019 a0rtega
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

#include "../format/nin/nds.h"

#define nds_get_hdr(bf) ((NDSHeader *)bf->o->bin_obj)

static bool nds_read_header(RzBuffer *buf, NDSHeader *hdr) {
	ut64 offset = 0;
	return rz_buf_read_offset(buf, &offset, (ut8 *)hdr->title, sizeof(hdr->title)) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)hdr->gamecode, sizeof(hdr->gamecode)) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)hdr->makercode, sizeof(hdr->makercode)) &&
		rz_buf_read8_offset(buf, &offset, &hdr->unitcode) &&
		rz_buf_read8_offset(buf, &offset, &hdr->devicetype) &&
		rz_buf_read8_offset(buf, &offset, &hdr->devicecap) &&
		rz_buf_read_offset(buf, &offset, hdr->reserved1, sizeof(hdr->reserved1)) &&
		rz_buf_read8_offset(buf, &offset, &hdr->romversion) &&
		rz_buf_read8_offset(buf, &offset, &hdr->reserved2) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_rom_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_entry_address) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_ram_address) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_rom_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_entry_address) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_ram_address) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->fnt_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->fnt_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->fat_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->fat_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_overlay_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_overlay_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_overlay_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_overlay_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->rom_control_info1) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->rom_control_info2) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->banner_offset) &&
		rz_buf_read_le16_offset(buf, &offset, &hdr->secure_area_crc) &&
		rz_buf_read_le16_offset(buf, &offset, &hdr->rom_control_info3) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x70) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x74) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x78) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x7C) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->application_end_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->rom_header_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x88) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x8C) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x90) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x94) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x98) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0x9C) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xA0) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xA4) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xA8) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xAC) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xB0) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xB4) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xB8) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->offset_0xBC) &&
		rz_buf_read_offset(buf, &offset, hdr->logo, sizeof(hdr->logo)) &&
		rz_buf_read_le16_offset(buf, &offset, &hdr->logo_crc) &&
		rz_buf_read_le16_offset(buf, &offset, &hdr->header_crc);
}

static bool nds_check_buffer(RzBuffer *b) {
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

static bool nds_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	NDSHeader *hdr = RZ_NEW0(NDSHeader);
	if (!hdr || !nds_read_header(b, hdr)) {
		free(hdr);
		return false;
	}
	obj->bin_obj = hdr;
	return true;
}

static void nds_destroy(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}

	NDSHeader *hdr = nds_get_hdr(bf);
	free(hdr);
}

static ut64 nds_baddr(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return 0;
	}
	NDSHeader *hdr = nds_get_hdr(bf);
	return (ut64)hdr->arm9_ram_address;
}

static ut64 nds_boffset(RzBinFile *bf) {
	return 0LL;
}

static RzList /*<RzBinSection *>*/ *nds_sections(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	RzList *ret = NULL;
	RzBinSection *ptr9 = NULL, *ptr7 = NULL;

	if (!(ret = rz_list_newf((RzListFree)rz_bin_section_free)) ||
		!(ptr9 = RZ_NEW0(RzBinSection)) ||
		!(ptr7 = RZ_NEW0(RzBinSection))) {
		rz_list_free(ret);
		free(ptr9);
		return NULL;
	}
	NDSHeader *hdr = nds_get_hdr(bf);

	ptr9->name = strdup("arm9");
	ptr9->size = hdr->arm9_size;
	ptr9->vsize = hdr->arm9_size;
	ptr9->paddr = hdr->arm9_rom_offset;
	ptr9->vaddr = hdr->arm9_ram_address;
	ptr9->perm = rz_str_rwx("rwx");
	rz_list_append(ret, ptr9);

	ptr7->name = strdup("arm7");
	ptr7->size = hdr->arm7_size;
	ptr7->vsize = hdr->arm7_size;
	ptr7->paddr = hdr->arm7_rom_offset;
	ptr7->vaddr = hdr->arm7_ram_address;
	ptr7->perm = rz_str_rwx("rwx");
	rz_list_append(ret, ptr7);

	return ret;
}

static RzList /*<RzBinAddr *>*/ *nds_entries(RzBinFile *bf) {
	if (!bf || !bf->buf) {
		return NULL;
	}
	RzBinAddr *ptr9 = NULL, *ptr7 = NULL;
	RzList *ret = NULL;

	if (!(ret = rz_list_newf(free)) ||
		!(ptr9 = RZ_NEW0(RzBinAddr)) ||
		!(ptr7 = RZ_NEW0(RzBinAddr))) {
		rz_list_free(ret);
		free(ptr9);
		return NULL;
	}
	NDSHeader *hdr = nds_get_hdr(bf);

	/* ARM9 entry point */
	ptr9->vaddr = hdr->arm9_entry_address;
	ptr9->paddr = hdr->arm9_rom_offset + (hdr->arm9_entry_address - hdr->arm9_ram_address);
	rz_list_append(ret, ptr9);

	/* ARM7 entry point */
	ptr7->vaddr = hdr->arm7_entry_address;
	ptr7->paddr = hdr->arm7_rom_offset + (hdr->arm7_entry_address - hdr->arm7_ram_address);
	rz_list_append(ret, ptr7);
	return ret;
}

static RzBinInfo *nds_info(RzBinFile *bf) {
	if (!bf || !bf->buf) {
		return NULL;
	}

	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	NDSHeader *hdr = nds_get_hdr(bf);

	ret->file = rz_str_newf("%.12s - %.4s", hdr->title, hdr->gamecode);
	ret->type = strdup("ROM");
	ret->machine = strdup("Nintendo DS");
	ret->os = strdup("nds");
	ret->arch = strdup("arm");
	ret->has_va = true;
	ret->bits = 32;
	return ret;
}

RzBinPlugin rz_bin_plugin_ninds = {
	.name = "ninds",
	.desc = "Nintendo DS plugin",
	.license = "LGPL3",
	.load_buffer = &nds_load_buffer,
	.check_buffer = &nds_check_buffer,
	.destroy = &nds_destroy,
	.baddr = &nds_baddr,
	.boffset = &nds_boffset,
	.entries = &nds_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &nds_sections,
	.info = &nds_info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ninds,
	.version = RZ_VERSION
};
#endif
