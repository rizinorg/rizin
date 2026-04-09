// SPDX-FileCopyrightText: 2016-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define MENUET_VERSION(x) x[7]

// db      'MENUET00'           ; 8 byte id
// dd      38                   ; required os
// dd      START                ; program start
// dd      I_END                ; image size
// dd      0x100000             ; reguired amount of memory
// dd      0x00000000           ; reserved=no extended header

// org     0x0
// db      'MENUET01'              ; 8 byte id
// dd      1                       ; header version
// dd      START                   ; program start
// dd      I_END                   ; program image size
// dd      0x1000                  ; required amount of memory
// dd      0x1000                  ; esp
// dd      0, 0                    ; no parameters, no path

//  0 db 'MENUET02'
//  8 dd 0x01
// 12 dd __start
// 16 dd __iend
// 20 dd __bssend
// 24 dd __stack
// 28 dd __cmdline
// 32 dd __pgmname
// 36 dd 0x0; tls map
// 40 dd __idata_start; секция .import
// 44 dd __idata_end
// 48 dd main

// db 'MENUET02'
// dd 1
// dd start
// dd i_end
// dd mem
// dd mem
// dd cmdline
// dd path
// dd 0

static bool check_buffer(RzBuffer *b) {
	ut8 buf[8];
	if (rz_buf_read_at(b, 0, buf, sizeof(buf)) != sizeof(buf)) {
		return false;
	}
	if (rz_buf_size(b) >= 32 && !memcmp(buf, "MENUET0", 7)) {
		switch (buf[7]) {
		case '0':
		case '1':
		case '2':
			return true;
		}
		RZ_LOG_ERROR("Unsupported MENUET version header\n");
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	return check_buffer(b);
}

static ut64 baddr(RzBinFile *bf) {
	return 0; // 0x800000;
}

static ut64 menuetEntry(const ut8 *buf, int buf_size) {
	switch (MENUET_VERSION(buf)) {
	case '0': return rz_read_ble32(buf + 12, false);
	case '1': return rz_read_ble32(buf + 12, false);
	case '2': return rz_read_ble32(buf + 44, false);
	}
	return UT64_MAX;
}

typedef struct {
	ut8 magic[8];
	ut8 version_char;
	ut32 header_version;
	ut32 program_start;
	ut32 image_size;
	ut32 memory_size;
	ut32 field_24;
	ut32 field_28;
	ut32 field_32;
	ut32 tls_map;
	ut32 import_start;
	ut32 import_end;
	ut32 entry_point;
	bool truncated_v2;
} MenuetHeader;

static bool menuet_parse_header(RzBuffer *buf, MenuetHeader *hdr) {
	rz_return_val_if_fail(buf && hdr, false);
	const ut64 sz = rz_buf_size(buf);
	if (sz < 36) {
		return false;
	}
	memset(hdr, 0, sizeof(*hdr));

	ut64 off = 0;
	if (!rz_buf_read_offset(buf, &off, hdr->magic, sizeof(hdr->magic)) ||
		memcmp(hdr->magic, "MENUET0", 7) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->header_version) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->program_start) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->image_size) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->memory_size) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->field_24) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->field_28) ||
		!rz_buf_read_le32_offset(buf, &off, &hdr->field_32)) {
		return false;
	}

	hdr->version_char = MENUET_VERSION(hdr->magic);
	if (hdr->version_char != '2') {
		return true;
	}
	if (sz < 52) {
		hdr->truncated_v2 = true;
		return true;
	}

	return rz_buf_read_le32_offset(buf, &off, &hdr->tls_map) &&
		rz_buf_read_le32_offset(buf, &off, &hdr->import_start) &&
		rz_buf_read_le32_offset(buf, &off, &hdr->import_end) &&
		rz_buf_read_le32_offset(buf, &off, &hdr->entry_point);
}

static RzStructuredData *menuet_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->buf, NULL);

	MenuetHeader hdr;
	if (!menuet_parse_header(bf->buf, &hdr)) {
		return NULL;
	}

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}
	RzStructuredData *menuet = rz_structured_data_map_add_map(info, "menuet");
	if (!menuet) {
		rz_structured_data_free(info);
		return NULL;
	}

	const ut8 version_char = hdr.version_char;
	const ut64 version = (version_char >= '0' && version_char <= '9') ? (ut64)(version_char - '0') : UT64_MAX;
	rz_structured_data_map_add_bytes(menuet, "magic", hdr.magic, sizeof(hdr.magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	if (version != UT64_MAX) {
		rz_structured_data_map_add_unsigned(menuet, "version", version, false);
	}

	rz_structured_data_map_add_unsigned(menuet, "program_start", hdr.program_start, true);
	rz_structured_data_map_add_unsigned(menuet, "image_size", hdr.image_size, true);
	rz_structured_data_map_add_unsigned(menuet, "memory_size", hdr.memory_size, true);

	switch (version_char) {
	case '0':
		rz_structured_data_map_add_unsigned(menuet, "required_os", hdr.header_version, false);
		rz_structured_data_map_add_unsigned(menuet, "reserved", hdr.field_24, true);
		break;
	case '1':
		rz_structured_data_map_add_unsigned(menuet, "header_version", hdr.header_version, false);
		rz_structured_data_map_add_unsigned(menuet, "stack_pointer", hdr.field_24, true);
		rz_structured_data_map_add_unsigned(menuet, "parameters", hdr.field_28, true);
		rz_structured_data_map_add_unsigned(menuet, "path", hdr.field_32, true);
		break;
	case '2':
		if (hdr.truncated_v2) {
			rz_structured_data_map_add_boolean(menuet, "truncated", true);
			break;
		}
		rz_structured_data_map_add_unsigned(menuet, "header_version", hdr.header_version, false);
		rz_structured_data_map_add_unsigned(menuet, "stack_pointer", hdr.field_24, true);
		rz_structured_data_map_add_unsigned(menuet, "cmdline", hdr.field_28, true);
		rz_structured_data_map_add_unsigned(menuet, "path", hdr.field_32, true);
		rz_structured_data_map_add_unsigned(menuet, "tls_map", hdr.tls_map, true);
		rz_structured_data_map_add_unsigned(menuet, "import_start", hdr.import_start, true);
		rz_structured_data_map_add_unsigned(menuet, "import_end", hdr.import_end, true);
		rz_structured_data_map_add_unsigned(menuet, "entry_point", hdr.entry_point, true);
		break;
	default:
		rz_structured_data_map_add_boolean(menuet, "unknown_version", true);
		break;
	}

	return info;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	ut8 buf[64] = { 0 };
	RzBinAddr *ptr = NULL;
	const int buf_size = RZ_MIN(sizeof(buf), rz_buf_size(bf->buf));

	rz_buf_read_at(bf->buf, 0, buf, buf_size);
	ut64 entry = menuetEntry(buf, buf_size);
	if (entry == UT64_MAX) {
		return NULL;
	}
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = rz_read_ble32(buf + 12, false);
		ptr->vaddr = ptr->paddr + baddr(bf);
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	ut8 buf[64] = { 0 };
	const int buf_size = RZ_MIN(sizeof(buf), rz_buf_size(bf->buf));

	rz_buf_read_at(bf->buf, 0, buf, buf_size);
	if (!bf->o->info) {
		return NULL;
	}

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	// add text segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("text");
	ptr->size = rz_read_ble32(buf + 16, false);
	ptr->vsize = ptr->size + (ptr->size % 4096);
	ptr->paddr = rz_read_ble32(buf + 12, false);
	ptr->vaddr = ptr->paddr + baddr(bf);
	ptr->perm = RZ_PERM_RX; // r-x
	rz_pvector_push(ret, ptr);

	if (MENUET_VERSION(buf)) {
		/* add data section */
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("idata");
		const ut32 idata_start = rz_read_ble32(buf + 40, false);
		const ut32 idata_end = rz_read_ble32(buf + 44, false);
		ptr->size = idata_end - idata_start;
		ptr->vsize = ptr->size + (ptr->size % 4096);
		ptr->paddr = rz_read_ble32(buf + 40, false);
		ptr->vaddr = ptr->paddr + baddr(bf);
		ptr->perm = RZ_PERM_R; // r--
		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("program");
	ret->rclass = rz_str_dup("menuet");
	ret->os = rz_str_dup("MenuetOS");
	ret->arch = rz_str_dup("x86");
	ret->machine = rz_str_dup(ret->arch);
	ret->subsystem = rz_str_dup("kolibri");
	ret->type = rz_str_dup("EXEC");
	ret->bits = 32;
	ret->has_va = true;
	ret->big_endian = false;
	ret->dbg_info = RZ_BIN_DBG_STRIPPED;
	return ret;
}

static ut64 size(RzBinFile *bf) {
	ut8 buf[4] = { 0 };
	if (!bf->o->info) {
		bf->o->info = info(bf);
	}
	if (!bf->o->info) {
		return 0;
	}
	rz_buf_read_at(bf->buf, 16, buf, 4);
	return (ut64)rz_read_ble32(buf, false);
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RzBuffer *create(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	RzBuffer *buf = rz_buf_new_with_bytes(NULL, 0);
#define B(x, y) rz_buf_append_bytes(buf, (const ut8 *)(x), y)
#define D(x)    rz_buf_append_ut32(buf, x)
	B("MENUET01", 8);
	D(1); // header version
	D(32); // program start
	D(0x1000); // program image size
	D(0x1000); // ESP
	D(0); // no parameters
	D(0); // no path
	B(code, codelen);
	return buf;
}

RzBinPlugin rz_bin_plugin_menuet = {
	.name = "menuet",
	.desc = "Menuet/KolibriOS binary",
	.license = "LGPL3",
	.author = "pancake",
	.load_buffer = &load_buffer,
	.size = &size,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.info = &info,
	.bin_structure = &menuet_structure,
	.create = &create,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_menuet,
	.version = RZ_VERSION
};
#endif
