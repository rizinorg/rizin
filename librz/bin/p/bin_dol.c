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

RZ_PACKED(
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
		ut32 padding[10];
		// 0x100 -- start of data section
	})
DolHeader;

static bool check_buffer(RzBuffer *buf) {
	ut8 tmp[6];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	bool one = r == sizeof(tmp) && !memcmp(tmp, "\x00\x00\x01\x00\x00\x00", sizeof(tmp));
	if (one) {
		int r = rz_buf_read_at(buf, 6, tmp, sizeof(tmp));
		if (r != 6) {
			return false;
		}
		return sizeof(tmp) && !memcmp(tmp, "\x00\x00\x00\x00\x00\x00", sizeof(tmp));
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	if (rz_buf_size(buf) < sizeof(DolHeader)) {
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
	rz_buf_fread_at(bf->buf, 0, (void *)dol, "67I", 1);
	obj->bin_obj = dol;
	return true;

lowername_err:
	free(lowername);
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
	.desc = "Nintendo Dolphin binary format",
	.license = "BSD",
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
