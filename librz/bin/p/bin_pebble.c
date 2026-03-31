// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

// Taken from https://pebbledev.org/wiki/Applications

#define APP_NAME_BYTES     32
#define COMPANY_NAME_BYTES 32

#define pebble_get_pai(bf) ((PebbleAppInfo *)bf->o->bin_obj)

typedef struct {
	ut8 major; //!< "compatibility" version number
	ut8 minor;
} Version;

typedef struct {
	char header[8]; //!< Sentinel value, should always be 'PBLAPP\0\0'
	Version struct_version; //!< version of this structure's format
	Version sdk_version; //!< version of the SDK used to build this app
	Version app_version; //!< version of the app
	ut16 size; //!< size of the app binary, including this metadata but not the reloc table
	ut32 offset; //!< The entry point of this executable
	ut32 crc; //!< CRC of the app data only, ie, not including this struct or the reloc table at the end
	char name[APP_NAME_BYTES]; //!< Name to display on the menu
	char company[COMPANY_NAME_BYTES]; //!< Name of the maker of this app
	ut32 icon_resource_id; //!< Resource ID within this app's bank to use as a 32x32 icon
	ut32 sym_table_addr; //!< The system will poke the sdk's symbol table address into this field on load
	ut32 flags; //!< Bitwise OR of PebbleAppFlags
	ut32 reloc_list_start; //!< The offset of the address relocation list
	ut32 num_reloc_entries; //!< The number of entries in the address relocation list
	ut8 uuid[16];
} PebbleAppInfo;

static bool pebble_check_buffer(RzBuffer *b) {
	ut8 magic[8];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) != sizeof(magic)) {
		return false;
	}
	return !memcmp(magic, "PBLAPP\x00\x00", 8);
}

static inline bool parse_pebble_version(RzBuffer *buf, ut64 *offset, Version *v) {
	return rz_buf_read8_offset(buf, offset, &v->major) &&
		rz_buf_read8_offset(buf, offset, &v->minor);
}

static bool parse_pebble_app_info(RzBuffer *buf, PebbleAppInfo *pai) {
	ut64 offset = 0;
	return rz_buf_read_offset(buf, &offset, (ut8 *)pai->header, sizeof(pai->header)) &&
		parse_pebble_version(buf, &offset, &pai->struct_version) &&
		parse_pebble_version(buf, &offset, &pai->sdk_version) &&
		parse_pebble_version(buf, &offset, &pai->app_version) &&
		rz_buf_read_le16_offset(buf, &offset, &pai->size) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->offset) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->crc) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)pai->name, sizeof(pai->name)) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)pai->company, sizeof(pai->company)) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->icon_resource_id) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->sym_table_addr) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->flags) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->reloc_list_start) &&
		rz_buf_read_le32_offset(buf, &offset, &pai->num_reloc_entries) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)pai->uuid, sizeof(pai->uuid));
}

static bool pebble_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	PebbleAppInfo *pai = RZ_NEW0(PebbleAppInfo);
	if (!pai ||
		!parse_pebble_app_info(b, pai)) {
		free(pai);
		rz_warn_if_reached();
		return false;
	}
	obj->bin_obj = pai;
	return true;
}

static ut64 pebble_baddr(RzBinFile *bf) {
	return 0LL;
}

static RzBinInfo *pebble_info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	PebbleAppInfo *pai = pebble_get_pai(bf);
	if (!pai) {
		RZ_LOG_ERROR("Invalid PebbleAppInfo header\n");
		return NULL;
	}
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		RZ_LOG_ERROR("Failed to allocate Pebble RzBinInfo\n");
		return NULL;
	}

	ret->lang = NULL;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("pebble");
	ret->bclass = rz_str_ndup(pai->name, sizeof(pai->name));
	ret->rclass = rz_str_ndup(pai->company, sizeof(pai->company));
	ret->os = rz_str_dup("rtos");
	ret->subsystem = rz_str_dup("pebble");
	ret->machine = rz_str_dup("watch");
	ret->arch = rz_str_dup("arm"); // thumb only
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *pebble_sections(RzBinFile *bf) {
	ut64 textsize = UT64_MAX;
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	PebbleAppInfo *pai = pebble_get_pai(bf);
	if (!pai) {
		RZ_LOG_ERROR("Invalid PebbleAppInfo header\n");
		return NULL;
	}

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	// TODO: load all relocs
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("relocs");
	ptr->vsize = ptr->size = ((ut64)pai->num_reloc_entries) * sizeof(ut32);
	ptr->vaddr = ptr->paddr = pai->reloc_list_start;
	ptr->perm = RZ_PERM_RW;
	rz_pvector_push(ret, ptr);
	if (ptr->vaddr < textsize) {
		textsize = ptr->vaddr;
	}

	// imho this must be a symbol
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("symtab");
	ptr->vsize = ptr->size = 0;
	ptr->vaddr = ptr->paddr = pai->sym_table_addr;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);
	if (ptr->vaddr < textsize) {
		textsize = ptr->vaddr;
	}

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("text");
	ptr->vaddr = ptr->paddr = 0x80;
	ptr->vsize = ptr->size = textsize - ptr->paddr;
	ptr->perm = RZ_PERM_RWX;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("header");
	ptr->vsize = ptr->size = sizeof(PebbleAppInfo);
	ptr->vaddr = ptr->paddr = 0;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *pebble_entries(RzBinFile *bf) {
	RzBinAddr *ptr = NULL;
	RzPVector *ret;
	PebbleAppInfo *pai = pebble_get_pai(bf);
	if (!pai) {
		RZ_LOG_ERROR("Invalid PebbleAppInfo header\n");
		return NULL;
	}

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = ptr->vaddr = pai->offset;
	rz_pvector_push(ret, ptr);
	return ret;
}

RzBinPlugin rz_bin_plugin_pebble = {
	.name = "pebble",
	.desc = "Pebble Watch App",
	.license = "LGPL",
	.author = "pancake",
	.load_buffer = &pebble_load_buffer,
	.check_buffer = &pebble_check_buffer,
	.baddr = &pebble_baddr,
	.entries = pebble_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = pebble_sections,
	.info = &pebble_info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pebble,
	.version = RZ_VERSION
};
#endif
