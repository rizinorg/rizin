// SPDX-FileCopyrightText: 2022-2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2015-2019 a0rtega
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

#include "../format/nin/nds.h"

typedef struct nds_rom_t {
	NDSHeader header;
	RzPVector *fat_table;
	RzPVector *arm9_overlays;
	RzPVector *arm7_overlays;
} NDSRom;

#define nds_get_rom(bf) ((NDSRom *)bf->o->bin_obj)
#define nds_get_hdr(bf) (&nds_get_rom(bf)->header)

static bool nds_read_overlay_entry(RzBuffer *buf, NDSOverlayTblEntry *entry, ut64 *offset) {
	return rz_buf_read_le32_offset(buf, offset, &entry->id) &&
		rz_buf_read_le32_offset(buf, offset, &entry->load_address) &&
		rz_buf_read_le32_offset(buf, offset, &entry->ram_size) &&
		rz_buf_read_le32_offset(buf, offset, &entry->bss_size) &&
		rz_buf_read_le32_offset(buf, offset, &entry->static_initializer_start_address) &&
		rz_buf_read_le32_offset(buf, offset, &entry->static_initializer_end_address) &&
		rz_buf_read_le32_offset(buf, offset, &entry->file_id) &&
		rz_buf_read_le32_offset(buf, offset, &entry->reserved);
}

static bool nds_read_overlay_table(RzBuffer *buf, RzPVector *table, ut32 offset_begin, ut32 size) {
	if (!buf || !table) {
		rz_warn_if_reached();
		return false;
	} else if (offset_begin < 1 || size < 1) {
		return true;
	}
	ut64 offset_end = offset_begin + size;
	for (ut64 offset = offset_begin; offset < offset_end;) {
		NDSOverlayTblEntry *entry = RZ_NEW0(NDSOverlayTblEntry);
		if (!entry || !nds_read_overlay_entry(buf, entry, &offset)) {
			free(entry);
			rz_warn_if_reached();
			return false;
		}
		rz_pvector_push(table, entry);
	}

	return true;
}

static bool nds_read_file_alloc_entry(RzBuffer *buf, NDSFatEntry *entry, ut64 *offset) {
	// these addresses are relative to the beginning of the file.
	// https://problemkaputt.de/gbatek-ds-cartridge-nitrorom-and-nitroarc-file-systems.htm
	return rz_buf_read_le32_offset(buf, offset, &entry->file_start_offset) &&
		rz_buf_read_le32_offset(buf, offset, &entry->file_end_offset);
}

static bool nds_read_file_alloc_table(RzBuffer *buf, RzPVector *table, NDSHeader *header) {
	if (!buf || !table) {
		rz_warn_if_reached();
		return false;
	} else if (header->fat_offset < 1 || header->fat_size < 1) {
		return true;
	}
	ut64 offset_end = header->fat_offset + header->fat_size;
	eprintf("img: 0x%llx\n", offset_end);
	for (ut64 offset = header->fat_offset; offset < offset_end;) {
		NDSFatEntry *entry = RZ_NEW0(NDSFatEntry);
		if (!entry || !nds_read_file_alloc_entry(buf, entry, &offset)) {
			free(entry);
			rz_warn_if_reached();
			return false;
		}
		rz_pvector_push(table, entry);
	}

	return true;
}

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
		rz_buf_read_le16_offset(buf, &offset, &hdr->secure_transfer_timeout) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_autoload) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm7_autoload) &&
		rz_buf_read_le64_offset(buf, &offset, &hdr->secure_disable) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->ntr_region_rom_size) &&
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

static void nds_rom_free(NDSRom *rom) {
	if (!rom) {
		return;
	}
	rz_pvector_free(rom->fat_table);
	rz_pvector_free(rom->arm7_overlays);
	rz_pvector_free(rom->arm9_overlays);
	free(rom);
}

static bool nds_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	NDSRom *rom = RZ_NEW0(NDSRom);
	rom->fat_table = rz_pvector_new((RzPVectorFree)free);
	rom->arm9_overlays = rz_pvector_new((RzPVectorFree)free);
	rom->arm7_overlays = rz_pvector_new((RzPVectorFree)free);
	if (!rom ||
		!nds_read_header(b, &rom->header) ||
		!nds_read_file_alloc_table(b, rom->fat_table, &rom->header) ||
		!nds_read_overlay_table(b, rom->arm9_overlays, rom->header.arm9_overlay_offset, rom->header.arm9_overlay_size) ||
		!nds_read_overlay_table(b, rom->arm7_overlays, rom->header.arm7_overlay_offset, rom->header.arm7_overlay_size)) {
		nds_rom_free(rom);
		rz_warn_if_reached();
		return false;
	}
	obj->bin_obj = rom;
	return true;
}

static void nds_destroy(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}

	NDSRom *rom = nds_get_rom(bf);
	nds_rom_free(rom);
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

static RzPVector /*<RzBinSection *>*/ *nds_sections(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	RzPVector *ret = NULL;
	RzBinSection *ptr9 = NULL, *ptr7 = NULL;
	int perm_rwx = rz_str_rwx("rwx");

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free)) ||
		!(ptr9 = RZ_NEW0(RzBinSection)) ||
		!(ptr7 = RZ_NEW0(RzBinSection))) {
		rz_pvector_free(ret);
		free(ptr9);
		return NULL;
	}
	NDSRom *rom = nds_get_rom(bf);
	NDSHeader *hdr = &rom->header;

	ptr9->name = strdup("arm9");
	ptr9->size = hdr->arm9_size;
	ptr9->vsize = hdr->arm9_size;
	ptr9->paddr = hdr->arm9_rom_offset;
	ptr9->vaddr = hdr->arm9_ram_address;
	ptr9->perm = perm_rwx;
	rz_pvector_push(ret, ptr9);

	ptr7->name = strdup("arm7");
	ptr7->size = hdr->arm7_size;
	ptr7->vsize = hdr->arm7_size;
	ptr7->paddr = hdr->arm7_rom_offset;
	ptr7->vaddr = hdr->arm7_ram_address;
	ptr7->perm = perm_rwx;
	rz_pvector_push(ret, ptr7);

	void **it;

	rz_pvector_foreach (rom->arm7_overlays, it) {
		NDSOverlayTblEntry *ovl_entry = *it;
		NDSFatEntry *fat_entry = rz_pvector_at(rom->fat_table, ovl_entry->file_id);
		if (!fat_entry) {
			rz_warn_if_reached();
			continue;
		}

		RzBinSection *overlay = RZ_NEW0(RzBinSection);
		if (!overlay) {
			return ret;
		}

		overlay->name = rz_str_newf("arm7_overlay_%" PFMT32u, ovl_entry->id);
		overlay->size = fat_entry->file_end_offset - fat_entry->file_start_offset;
		overlay->vsize = ovl_entry->ram_size;
		overlay->paddr = fat_entry->file_start_offset;
		overlay->vaddr = ovl_entry->load_address;
		overlay->perm = perm_rwx;
		rz_pvector_push(ret, overlay);
	}

	rz_pvector_foreach (rom->arm9_overlays, it) {
		NDSOverlayTblEntry *ovl_entry = *it;
		NDSFatEntry *fat_entry = rz_pvector_at(rom->fat_table, ovl_entry->file_id);
		if (!fat_entry) {
			rz_warn_if_reached();
			continue;
		}

		RzBinSection *overlay = RZ_NEW0(RzBinSection);
		if (!overlay) {
			return ret;
		}

		overlay->name = rz_str_newf("arm9_overlay_%" PFMT32u, ovl_entry->id);
		overlay->size = fat_entry->file_end_offset - fat_entry->file_start_offset;
		overlay->vsize = ovl_entry->ram_size;
		overlay->paddr = fat_entry->file_start_offset;
		overlay->vaddr = ovl_entry->load_address;
		overlay->perm = perm_rwx;
		rz_pvector_push(ret, overlay);
	}
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *nds_entries(RzBinFile *bf) {
	if (!bf || !bf->buf) {
		return NULL;
	}
	RzBinAddr *ptr9 = NULL, *ptr7 = NULL;
	RzPVector *ret = NULL;

	if (!(ret = rz_pvector_new(free)) ||
		!(ptr9 = RZ_NEW0(RzBinAddr)) ||
		!(ptr7 = RZ_NEW0(RzBinAddr))) {
		rz_pvector_free(ret);
		free(ptr9);
		return NULL;
	}
	NDSHeader *hdr = nds_get_hdr(bf);

	/* ARM9 entry point */
	ptr9->vaddr = hdr->arm9_entry_address;
	ptr9->paddr = hdr->arm9_rom_offset + (hdr->arm9_entry_address - hdr->arm9_ram_address);
	rz_pvector_push(ret, ptr9);

	/* ARM7 entry point */
	ptr7->vaddr = hdr->arm7_entry_address;
	ptr7->paddr = hdr->arm7_rom_offset + (hdr->arm7_entry_address - hdr->arm7_ram_address);
	rz_pvector_push(ret, ptr7);
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
