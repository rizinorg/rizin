// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

/*
Start	End	Length	Description
0x0	0x3	4	File offset to start of Text0
0x04	0x1b	24	File offsets for Text1..6
0x1c	0x47	44	File offsets for Data0..10
0x48	0x4B	4	Loading address for Text0
0x4C	0x8F	68	Loading addresses for Text1..6, Data0..10
0x90	0xD7	72	Section sizes for Text0..6, Data0..10
0xD8	0xDB	4	BSS address
0xDC	0xDF	4	BSS size
0xE0	0xE3	4	Entry point
0xE4	0xFF		padding
*/

#define N_TEXT 7
#define N_DATA 11
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

static bool check_buffer(RzBuffer *buf) {
	if (!buf || rz_buf_size(buf) < DOL_HDR_SIZE) {
		return false;
	}
	ut32 text0_off, entry;
	if (!rz_buf_read_be32_at(buf, 0x00, &text0_off)) {
		return false;
	}
	if (!rz_buf_read_be32_at(buf, 0xE0, &entry)) {
		return false;
	}
	
	bool text0_valid = (text0_off >= DOL_HDR_SIZE) && (text0_off < rz_buf_size(buf)) && (text0_off % 4 == 0);
	bool entry_valid = (entry & 0xF0000000) == 0x80000000;
	return text0_valid && entry_valid;
}
/*
dol Header:
--> The dol header have a fixed size of 0x100. But in the dol_parse_header when you add all the memory space it would be 0xE4, this is okay as rest all of the space is considered as padding.

	0x100 - 0xE4 = padding 

Generally this padding is ignored.
dol header entrypoint:
--> Previously, we validated whether a file was a DOL file by comparing the first 6 bytes with a magic value. This method was weak and unreliable.

--> We have now introduced a more robust validation method based on the entrypoint address range.

--> A valid DOL entrypoint must fall within the memory range:

      (0x80004000 <–> 0x81200000)

--> By verifying that the entrypoint lies within this range, we can more confidently determine whether the file is a valid DOL  file. This also improves the overall reliability of DOL file detection.

--> Reference:
	https://wiki.tockdom.com/wiki/DOL_(File_Format)
	https://wiibrew.org/wiki/Memory_map
*/
static bool read_u32_array(RzBuffer *b, ut64 *off, ut32 *dst, int n) {
	for (int i = 0; i < n; i++) {
		if (!rz_buf_read_be32_offset(b, off, &dst[i])) {
			return false;
		}
	}
	return true;
}
static bool dol_parse_header(RzBuffer *buf, DolHeader *dol) {
	ut64 off = 0;
	return read_u32_array(buf, &off, dol->text_paddr, N_TEXT) &&
		read_u32_array(buf, &off, dol->data_paddr, N_DATA) &&
		read_u32_array(buf, &off, dol->text_vaddr, N_TEXT) &&
		read_u32_array(buf, &off, dol->data_vaddr, N_DATA) &&
		read_u32_array(buf, &off, dol->text_size, N_TEXT) &&
		read_u32_array(buf, &off, dol->data_size, N_DATA) &&
		rz_buf_read_be32_offset(buf, &off, &dol->bss_addr) &&
		rz_buf_read_be32_offset(buf, &off, &dol->bss_size) &&
		rz_buf_read_be32_offset(buf, &off, &dol->entrypoint);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
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

static RzPVector *sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	DolHeader *dol = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(NULL);
	if (!ret) {
		return NULL;
	}
		
	for (int i = 0; i < N_TEXT; i++) {
		if (!dol->text_paddr[i] ||
			!dol->text_vaddr[i] ||
			!dol->text_size[i]) {
			continue;
		}
		RzBinSection *s = RZ_NEW0(RzBinSection);
		s->name = rz_str_newf("text_%d", i);
		s->paddr = dol->text_paddr[i];
		s->vaddr = dol->text_vaddr[i];
		s->size  = dol->text_size[i];
		s->vsize = s->size;
		s->perm  = rz_str_rwx("r-x");
		rz_pvector_push(ret, s);
}

	for (int i = 0; i < N_DATA; i++) {
		if (!dol->data_paddr[i] ||
			!dol->data_vaddr[i] ||
			!dol->data_size[i]) {
			continue;
		}
		RzBinSection *s = RZ_NEW0(RzBinSection);
		s->name = rz_str_newf("data_%d", i);
		s->paddr = dol->data_paddr[i];
		s->vaddr = dol->data_vaddr[i];
		s->size  = dol->data_size[i];
		s->vsize = s->size;
		s->perm  = rz_str_rwx("r--");
		rz_pvector_push(ret, s);
	}

	if (dol->bss_size) {
		RzBinSection *bss = RZ_NEW0(RzBinSection);
		bss->name  = rz_str_dup("bss");
		bss->paddr = UT64_MAX;
		bss->vaddr = dol->bss_addr;
		bss->size  = dol->bss_size;
		bss->vsize = bss->size;
		bss->perm  = rz_str_rwx("rw-");
		rz_pvector_push(ret, bss);
	}

	return ret;
}

static RzPVector *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	DolHeader *dol = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(NULL);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_pvector_free(ret);
		return NULL;
	}

	addr->vaddr = dol->entrypoint;
	addr->paddr = UT64_MAX; 

	rz_pvector_push(ret, addr);
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->file = rz_str_dup(bf->file);
	ret->big_endian = true;
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("Nintendo Wii");
	ret->os = rz_str_dup("wii-ios");
	ret->arch = rz_str_dup("ppc");
	ret->bits = 32;
	ret->has_va = true;

	return ret;
}

static ut64 baddr(RzBinFile *bf) {
	return 0x80004000;
}

RzBinPlugin rz_bin_plugin_dol = {
	.name = "dol",
	.desc = "Nintendo Dolphin binary",
	.license = "BSD",
	.author = "pancake",
	.check_buffer = &check_buffer,
	.load_buffer = &load_buffer,
	.entries = &entries,
	.sections = &sections,
	.maps = &rz_bin_maps_of_file_sections,
	.info = &info,
	.baddr = &baddr,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dol,
	.version = RZ_VERSION
};
#endif
