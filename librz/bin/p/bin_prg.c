// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>

static bool check_buffer(RzBuffer *b) {
	// no magic
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return true;
}

static ut64 baddr(RzBinFile *bf) {
	ut16 base;
	if (!rz_buf_read_le16_at(bf->buf, 0, &base)) {
		return 0;
	}

	return base;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("PRG");
	ret->machine = rz_str_dup("Commodore 64");
	ret->os = rz_str_dup("c64");
	ret->arch = rz_str_dup("6502");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	ut64 sz = rz_buf_size(bf->buf);
	if (sz < 2) {
		return ret;
	}
	RzBinSection *section = RZ_NEW0(RzBinSection);
	if (!section) {
		return ret;
	}
	section->name = rz_str_dup("prg");
	section->paddr = 2;
	section->size = sz - 2;
	section->vaddr = baddr(bf);
	section->vsize = sz - 2;
	section->perm = RZ_PERM_RWX;
	rz_pvector_push(ret, section);
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	RzBinAddr *binaddr = RZ_NEW0(RzBinAddr);
	if (!binaddr) {
		return ret;
	}
	binaddr->paddr = 2;
	binaddr->vaddr = baddr(bf);
	rz_pvector_push(ret, binaddr);
	return ret;
}

RzBinPlugin rz_bin_plugin_prg = {
	.name = "prg",
	.desc = "C64 PRG",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.baddr = baddr,
	.check_buffer = check_buffer,
	.entries = entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = sections,
	.info = info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_prg,
	.version = RZ_VERSION
};
#endif
