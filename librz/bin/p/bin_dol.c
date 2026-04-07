// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file bin_dol.c
 *
 * Parses the GameCube & Wii executable file format.
 *
 * It is a simple file format consisting of a header and up to 7 loadable
 * code sections (Text0..Text6) and up to 11 data sections (Data0..Data10).
 *
 * All values in the header are unsigned big-endian 32-bit values.
 *
 * https://wiibrew.org/wiki/DOL
 *
 * Start   End    Length    Description
 * 0x0     0x3    4         File offset to start of Text0
 * 0x04    0x1b   24        File offsets for Text1..6
 * 0x1c    0x47   44        File offsets for Data0..10
 * 0x48    0x4B   4         Loading address for Text0
 * 0x4C    0x8F   68        Loading addresses for Text1..6, Data0..10
 * 0x90    0xD7   72        Section sizes for Text0..6, Data0..10
 * 0xD8    0xDB   4         BSS address
 * 0xDC    0xDF   4         BSS size
 * 0xE0    0xE3   4         Entry point
 * 0xE4    0xFF             padding
 */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

#define N_TEXT       7
#define N_DATA       11
#define DOL_HDR_SIZE 0x100

typedef struct dol_header_s {
	ut32 text_paddr[N_TEXT];
	ut32 data_paddr[N_DATA];
	ut32 text_vaddr[N_TEXT];
	ut32 data_vaddr[N_DATA];
	ut32 text_size[N_TEXT];
	ut32 data_size[N_DATA];
	ut32 bss_addr;
	ut32 bss_size;
	ut32 entrypoint;
	ut32 padding[10];
} DolHeader;

/*
 * Performs a check on the buffer to verify if is a DOL header.
 * The DOL format does not have a magic, thus requires some heuristics
 * to detect it.
 *
 * The size is always 0x100 and thus we expect the text0 offset to always
 * start after 0x100.
 *
 * On the Broadway the executable range starts from 0x80000000 till 0x80003F00
 * for iOS and for applications between the 0x80003F00 and 0x81330000.
 *
 * Thus, we expect the entrypoint for these files to always have the MSB to 1.
 *
 * Reference:
 * 	https://wiki.tockdom.com/wiki/DOL_(File_Format)
 * 	https://wiibrew.org/wiki/Memory_map
 */

static bool dol_check_buffer(RzBuffer *buf) {
	size_t buf_size = rz_buf_size(buf);
	if (!buf || buf_size < DOL_HDR_SIZE) {
		return false;
	}
	ut32 text0 = 0;
	ut32 entry = 0;
	if (!rz_buf_read_be32_at(buf, 0x00, &text0) ||
		!rz_buf_read_be32_at(buf, 0xE0, &entry)) {
		return false;
	}

	bool text0_check = (text0 >= DOL_HDR_SIZE) && (text0 < buf_size) && (text0 % 4 == 0);
	bool entry_check = (entry & 0xF0000000) == 0x80000000;
	return text0_check && entry_check;
}

static inline bool read_be32_as_array(RzBuffer *b, ut64 *off, ut32 *dst, const size_t n) {
	for (size_t i = 0; i < n; i++) {
		if (!rz_buf_read_be32_offset(b, off, &dst[i])) {
			return false;
		}
	}
	return true;
}

static bool dol_parse_header(RzBuffer *buf, DolHeader *dol) {
	ut64 off = 0;
	return read_be32_as_array(buf, &off, dol->text_paddr, N_TEXT) &&
		read_be32_as_array(buf, &off, dol->data_paddr, N_DATA) &&
		read_be32_as_array(buf, &off, dol->text_vaddr, N_TEXT) &&
		read_be32_as_array(buf, &off, dol->data_vaddr, N_DATA) &&
		read_be32_as_array(buf, &off, dol->text_size, N_TEXT) &&
		read_be32_as_array(buf, &off, dol->data_size, N_DATA) &&
		rz_buf_read_be32_offset(buf, &off, &dol->bss_addr) &&
		rz_buf_read_be32_offset(buf, &off, &dol->bss_size) &&
		rz_buf_read_be32_offset(buf, &off, &dol->entrypoint);
}

static bool dol_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	if (!bf || !obj || !buf || rz_buf_size(buf) < DOL_HDR_SIZE) {
		return false;
	}
	DolHeader *dol = RZ_NEW0(DolHeader);
	if (!dol) {
		return false;
	}
	if (!dol_parse_header(buf, dol)) {
		free(dol);
		return false;
	}
	obj->bin_obj = dol;
	return true;
}

static RzPVector /*<RzBinSection *>*/ *dol_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	DolHeader *dol = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	for (ut32 i = 0; i < N_TEXT; i++) {
		if (!dol->text_paddr[i] || !dol->text_vaddr[i] || dol->text_size[i] < 1) {
			continue;
		}
		RzBinSection *s = RZ_NEW0(RzBinSection);
		if (!s) {
			rz_pvector_free(ret);
			return NULL;
		}
		s->name = rz_str_newf(".text%u", i);
		s->paddr = dol->text_paddr[i];
		s->vaddr = dol->text_vaddr[i];
		s->size = dol->text_size[i];
		s->vsize = s->size;
		s->perm = RZ_PERM_RX;
		rz_pvector_push(ret, s);
	}

	for (ut32 i = 0; i < N_DATA; i++) {
		if (!dol->data_paddr[i] || !dol->data_vaddr[i] || dol->data_size[i] < 1) {
			continue;
		}
		RzBinSection *s = RZ_NEW0(RzBinSection);
		if (!s) {
			rz_pvector_free(ret);
			return NULL;
		}
		s->name = rz_str_newf(".data%u", i);
		s->paddr = dol->data_paddr[i];
		s->vaddr = dol->data_vaddr[i];
		s->size = dol->data_size[i];
		s->vsize = s->size;
		s->perm = RZ_PERM_R;
		rz_pvector_push(ret, s);
	}

	if (dol->bss_size) {
		RzBinSection *bss = RZ_NEW0(RzBinSection);
		if (!bss) {
			rz_pvector_free(ret);
			return NULL;
		}
		bss->name = rz_str_dup(".bss");
		bss->paddr = UT64_MAX;
		bss->vaddr = dol->bss_addr;
		bss->size = dol->bss_size;
		bss->vsize = bss->size;
		bss->perm = RZ_PERM_RW;
		rz_pvector_push(ret, bss);
	}
	return ret;
}

static ut64 dol_vaddr_to_paddr(DolHeader *dol, const ut64 vaddr) {
	for (int i = 0; i < N_TEXT; i++) {
		ut64 start = dol->text_vaddr[i];
		ut64 end = start + dol->text_size[i];
		if (vaddr < start || vaddr >= end) {
			continue;
		}

		ut64 diff = vaddr - start;
		return dol->text_paddr[i] + diff;
	}
	return UT64_MAX;
}

static RzPVector /*<RzBinAddr *>*/ *dol_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	DolHeader *dol = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_pvector_free(ret);
		return NULL;
	}
	addr->vaddr = dol->entrypoint;
	addr->paddr = dol_vaddr_to_paddr(dol, addr->vaddr);
	rz_pvector_push(ret, addr);
	return ret;
}

static RzBinInfo *dol_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->file = rz_str_dup(bf->file);
	ret->big_endian = true;
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("Nintendo Wii/GC");
	ret->os = rz_str_dup("wii-ios");
	ret->arch = rz_str_dup("ppc");
	ret->bits = 32;
	ret->has_va = true;

	return ret;
}

static bool add_unsigned_array(RzStructuredData *parent, const char *name, const ut32 *values, size_t count) {
	RzStructuredData *arr = rz_structured_data_map_add_array(parent, name);
	if (!arr) {
		return false;
	}
	for (size_t i = 0; i < count; i++) {
		rz_structured_data_array_add_unsigned(arr, values[i], true);
	}
	return true;
}

static RzStructuredData *dol_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	DolHeader *dh = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *dol = rz_structured_data_map_add_map(info, "dol");
	if (!dol) {
		rz_structured_data_free(info);
		return NULL;
	}

	if (!add_unsigned_array(dol, "text_paddr", dh->text_paddr, N_TEXT) ||
		!add_unsigned_array(dol, "text_vaddr", dh->text_vaddr, N_TEXT) ||
		!add_unsigned_array(dol, "text_size", dh->text_size, N_TEXT) ||
		!add_unsigned_array(dol, "data_paddr", dh->data_paddr, N_DATA) ||
		!add_unsigned_array(dol, "data_vaddr", dh->data_vaddr, N_DATA) ||
		!add_unsigned_array(dol, "data_size", dh->data_size, N_DATA)) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(dol, "bss_addr", dh->bss_addr, true);
	rz_structured_data_map_add_unsigned(dol, "bss_size", dh->bss_size, true);
	rz_structured_data_map_add_unsigned(dol, "entrypoint", dh->entrypoint, true);

	return info;
}

static ut64 dol_baddr(RzBinFile *bf) {
	// This should probably derived instead of being hardcoded.
	return 0x80004000;
}

RzBinPlugin rz_bin_plugin_dol = {
	.name = "dol",
	.desc = "Nintendo Dolphin binary",
	.license = "BSD",
	.author = "pancake",
	.check_buffer = &dol_check_buffer,
	.load_buffer = &dol_load_buffer,
	.entries = &dol_entries,
	.sections = &dol_sections,
	.maps = &rz_bin_maps_of_file_sections,
	.info = &dol_info,
	.baddr = &dol_baddr,
	.bin_structure = &dol_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dol,
	.version = RZ_VERSION
};
#endif
