// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

static bool check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);

	ut64 sz = rz_buf_size(buf);
	if (sz <= 0xffff) {
		return false;
	}

	const ut32 ep = sz - 0x10000 + 0xfff0; /* F000:FFF0 address */
	/* hacky check to avoid detecting multidex or MZ bins as bios */
	/* need better fix for this */
	ut8 tmp[3];
	if (rz_buf_read_at(buf, 0, tmp, sizeof(tmp)) != sizeof(tmp) ||
		tmp[0] == 0xcf || tmp[0] == 0x7f ||
		!memcmp(tmp, "dex", 3) || !memcmp(tmp, "MZ", 2)) {
		return false;
	}

	/* Check if this a 'jmp' opcode */
	ut8 bep;
	if (!rz_buf_read8_at(buf, ep, &bep)) {
		return false;
	}

	return bep == 0xea || bep == 0xe9;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return check_buffer(buf);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("bios");
	ret->bclass = rz_str_dup("1.0");
	ret->rclass = rz_str_dup("bios");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("unknown");
	ret->machine = rz_str_dup("pc");
	ret->arch = rz_str_dup("x86");
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}
	// program headers is another section
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("bootblk"); // Maps to 0xF000:0000 segment
	ptr->vsize = ptr->size = 0x10000;
	ptr->paddr = rz_buf_size(bf->buf) - ptr->size;
	ptr->vaddr = 0xf0000;
	ptr->perm = RZ_PERM_RWX;
	rz_pvector_push(ret, ptr);
	// If image bigger than 128K - add one more section
	if (bf->size >= 0x20000) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("_e000"); // Maps to 0xE000:0000 segment
		ptr->vsize = ptr->size = 0x10000;
		ptr->paddr = rz_buf_size(bf->buf) - 2 * ptr->size;
		ptr->vaddr = 0xe0000;
		ptr->perm = RZ_PERM_RWX;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = 0; // 0x70000;
	ptr->vaddr = 0xffff0;
	rz_pvector_push(ret, ptr);
	return ret;
}

static void bios_structure_add_entry_info(RzStructuredData *bios, RzBuffer *buf) {
	ut64 sz = rz_buf_size(buf);
	ut32 ep = sz - 0x10000 + 0xfff0;

	RzStructuredData *entry = rz_structured_data_map_add_map(bios, "entry_point");
	if (!entry) {
		return;
	}

	ut8 bep;
	if (rz_buf_read8_at(buf, ep, &bep)) {
		rz_structured_data_map_add_unsigned(entry, "opcode", bep, true);
		if (bep == 0xea) {
			rz_structured_data_map_add_string(entry, "type", "far jump");
		} else if (bep == 0xe9) {
			rz_structured_data_map_add_string(entry, "type", "near jump");
		}
	}
}

static void bios_structure_add_sections(RzStructuredData *bios, RzBinFile *bf) {
	RzStructuredData *sections = rz_structured_data_map_add_array(bios, "sections");
	if (!sections) {
		return;
	}

	RzStructuredData *bootblk = rz_structured_data_array_add_map(sections);
	if (bootblk) {
		rz_structured_data_map_add_string(bootblk, "name", "bootblk");
		rz_structured_data_map_add_unsigned(bootblk, "address", 0xf0000, true);
		rz_structured_data_map_add_unsigned(bootblk, "size", 0x10000, true);
	}

	if (bf->size >= 0x20000) {
		RzStructuredData *e000 = rz_structured_data_array_add_map(sections);
		if (e000) {
			rz_structured_data_map_add_string(e000, "name", "_e000");
			rz_structured_data_map_add_unsigned(e000, "address", 0xe0000, true);
			rz_structured_data_map_add_unsigned(e000, "size", 0x10000, true);
		}
	}
}

static RzStructuredData *bios_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *bios = rz_structured_data_map_add_map(info, "bios");
	if (!bios) {
		rz_structured_data_free(info);
		return NULL;
	}

	bios_structure_add_entry_info(bios, bf->buf);
	bios_structure_add_sections(bios, bf);

	return info;
}

RzBinPlugin rz_bin_plugin_bios = {
	.name = "bios",
	.desc = "BIOS binary",
	.license = "LGPL",
	.author = "pancake",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = entries,
	.maps = rz_bin_maps_of_file_sections,
	.sections = sections,
	.info = &info,
	.bin_structure = &bios_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bios,
	.version = RZ_VERSION
};
#endif
