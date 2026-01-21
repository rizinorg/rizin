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


typedef struct {
	ut32 text_paddr[N_TEXT];
	ut32 data_paddr[N_DATA];
	ut32 text_vaddr[N_TEXT];
	ut32 data_vaddr[N_DATA];
	ut32 text_size[N_TEXT];
	ut32 data_size[N_DATA];
	ut32 bss_addr;
	ut32 bss_size;
	ut32 entrypoint;
	}
DolHeader;

static bool read_u32_array(RzBuffer *buf, ut64 *offset, ut32 *arr, size_t count) {
	for (size_t i = 0; i < count; i++) {
		if (!rz_buf_read_be32_offset(buf, offset, &arr[i])) {
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
	bool text0_valid = (text0_off >= 0x100) && (text0_off % 4 == 0);
	bool entry_valid = (entry & 0xF0000000) == 0x80000000;

	return text0_valid && entry_valid;
}
static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	if (rz_buf_size(buf) < DOL_HDR_SIZE) {
		return false;
	}
	DolHeader *dol = RZ_NEW0(DolHeader);
	if (!dol) {
		return false;
	}
	char *lowername = rz_str_dup(bf->file);
	if (!lowername) {
		goto dol_err;
	}
	rz_str_case(lowername, 0);
	char *ext = strstr(lowername, ".dol");
	if (!ext || ext[4] != 0) {
		goto lowername_err;
	}
	free(lowername);
	if (!dol_parse_header(buf, dol)) {
		goto dol_err;
	}
	obj->bin_obj = dol;
	return true;

lowername_err:
	free(lowername);
	free(dol);
	return false;
dol_err:
	free(dol);
	return false;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	int i;
	RzPVector *ret;
	RzBinSection *s;
	DolHeader *dol = bf->o->bin_obj;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}

	/* text sections */
	for (i = 0; i < N_TEXT; i++) {
		if (!dol->text_paddr[i] || !dol->text_vaddr[i]) {
			continue;
		}
		s = RZ_NEW0(RzBinSection);
		s->name = rz_str_newf("text_%d", i);
		s->paddr = dol->text_paddr[i];
		s->vaddr = dol->text_vaddr[i];
		s->size = dol->text_size[i];
		s->vsize = s->size;
		s->perm = rz_str_rwx("r-x");
		rz_pvector_push(ret, s);
	}
	/* data sections */
	for (i = 0; i < N_DATA; i++) {
		if (!dol->data_paddr[i] || !dol->data_vaddr[i]) {
			continue;
		}
		s = RZ_NEW0(RzBinSection);
		s->name = rz_str_newf("data_%d", i);
		s->paddr = dol->data_paddr[i];
		s->vaddr = dol->data_vaddr[i];
		s->size = dol->data_size[i];
		s->vsize = s->size;
		s->perm = rz_str_rwx("r--");
		rz_pvector_push(ret, s);
	}
	/* bss section */
	s = RZ_NEW0(RzBinSection);
	s->name = rz_str_dup("bss");
	s->paddr = 0;
	s->vaddr = dol->bss_addr;
	s->size = dol->bss_size;
	s->vsize = s->size;
	s->perm = rz_str_rwx("rw-");
	rz_pvector_push(ret, s);

	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzPVector *ret = rz_pvector_new(NULL);
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	DolHeader *dol = bf->o->bin_obj;
	addr->vaddr = (ut64)dol->entrypoint;
	addr->paddr = addr->vaddr & 0xFFFF;
	rz_pvector_push(ret, addr);
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->buf, NULL);
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
	ret->has_va = true;
	ret->bits = 32;

	return ret;
}

static ut64 baddr(RzBinFile *bf) {
	return 0x80b00000; // XXX
}

RzBinPlugin rz_bin_plugin_dol = {
	.name = "dol",
	.desc = "Nintendo Dolphin binary",
	.license = "BSD",
	.author = "pancake",
	.load_buffer = &load_buffer,
	.baddr = &baddr,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dol,
	.version = RZ_VERSION
};
#endif
