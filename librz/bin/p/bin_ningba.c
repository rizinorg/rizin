// SPDX-FileCopyrightText: 2014-2019 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/nin/gba.h"

static bool check_buffer(RzBuffer *b) {
	ut8 lict[156];
	rz_return_val_if_fail(b, false);
	rz_buf_read_at(b, 4, (ut8 *)lict, sizeof(lict));
	return !memcmp(lict, lic_gba, 156);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return check_buffer(buf);
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new(free);
	RzBinAddr *ptr = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = 0x8000000;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	ut8 rom_info[16];
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);

	if (!ret) {
		return NULL;
	}

	if (!bf || !bf->buf) {
		free(ret);
		return NULL;
	}

	ret->lang = NULL;
	rz_buf_read_at(bf->buf, 0xa0, rom_info, 16);
	ret->file = rz_str_ndup((const char *)rom_info, 12);
	ret->type = rz_str_ndup((char *)&rom_info[12], 4);
	ret->machine = rz_str_dup("GameBoy Advance");
	ret->os = rz_str_dup("any");
	ret->arch = rz_str_dup("arm");
	ret->has_va = true;
	ret->bits = 32;
	ret->big_endian = false;
	ret->dbg_info = RZ_BIN_DBG_STRIPPED;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (!s) {
		return NULL;
	}
	ut64 sz = rz_buf_size(bf->buf);
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		free(s);
		return NULL;
	}
	s->name = rz_str_dup("ROM");
	s->paddr = 0;
	s->vaddr = 0x8000000;
	s->size = sz;
	s->vsize = 0x2000000;
	s->perm = RZ_PERM_RX;

	rz_pvector_push(ret, s);
	return ret;
}

static bool ningba_parse_header(RzBuffer *buf, gba_header_t *hdr) {
	rz_return_val_if_fail(buf && hdr, false);
	const ut64 sz = rz_buf_size(buf);
	if (sz < GBA_ROM_CARTRIDGE_HEADER_SIZE) {
		return false;
	}

	memset(hdr, 0, sizeof(*hdr));

	ut64 off = 0;
	if (!rz_buf_read_le32_offset(buf, &off, &hdr->entry_point) ||
		!rz_buf_read_offset(buf, &off, hdr->nintendo_logo, sizeof(hdr->nintendo_logo)) ||
		!rz_buf_read_offset(buf, &off, (ut8 *)hdr->title, sizeof(hdr->title)) ||
		!rz_buf_read_offset(buf, &off, (ut8 *)hdr->game_code, sizeof(hdr->game_code)) ||
		!rz_buf_read_offset(buf, &off, (ut8 *)hdr->maker_code, sizeof(hdr->maker_code)) ||
		!rz_buf_read8_offset(buf, &off, &hdr->fixed_value) ||
		!rz_buf_read8_offset(buf, &off, &hdr->main_unit_code) ||
		!rz_buf_read8_offset(buf, &off, &hdr->device_type) ||
		!rz_buf_read_offset(buf, &off, hdr->reserved_area_1, sizeof(hdr->reserved_area_1)) ||
		!rz_buf_read8_offset(buf, &off, &hdr->software_version) ||
		!rz_buf_read8_offset(buf, &off, &hdr->complement_check) ||
		!rz_buf_read_offset(buf, &off, hdr->reserved_area_2, sizeof(hdr->reserved_area_2))) {
		return false;
	}
	return true;
}

static RzStructuredData *ningba_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->buf, NULL);
	gba_header_t hdr;
	if (!ningba_parse_header(bf->buf, &hdr)) {
		return NULL;
	}
	RzStructuredData *map = rz_structured_data_new_map();
	if (!map) {
		return NULL;
	}
	RzStructuredData *gba = rz_structured_data_map_add_map(map, "gba");
	if (!gba) {
		rz_structured_data_free(map);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(gba, "entry_point", hdr.entry_point, true);
	rz_structured_data_map_add_string_n(gba, "title", hdr.title, sizeof(hdr.title));
	rz_structured_data_map_add_string_n(gba, "game_code", hdr.game_code, sizeof(hdr.game_code));
	rz_structured_data_map_add_string_n(gba, "maker_code", hdr.maker_code, sizeof(hdr.maker_code));
	rz_structured_data_map_add_unsigned(gba, "fixed_value", hdr.fixed_value, true);
	rz_structured_data_map_add_unsigned(gba, "main_unit_code", hdr.main_unit_code, true);
	rz_structured_data_map_add_unsigned(gba, "device_type", hdr.device_type, true);
	rz_structured_data_map_add_unsigned(gba, "software_version", hdr.software_version, true);
	rz_structured_data_map_add_unsigned(gba, "complement_check", hdr.complement_check, true);

	return map;
}

RzBinPlugin rz_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Nintendo Game Boy Advance",
	.license = "LGPL3",
	.author = "condret",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.info = &info,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.bin_structure = &ningba_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ningba,
	.version = RZ_VERSION
};
#endif
