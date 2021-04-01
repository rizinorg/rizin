// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>

static bool check_buffer(RzBuffer *b) {
	// no magic
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static ut64 baddr(RzBinFile *bf) {
	ut16 base = rz_buf_read_le16_at(bf->buf, 0);
	return base != UT16_MAX ? base : 0;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->type = strdup("PRG");
	ret->machine = strdup("Commodore 64");
	ret->os = strdup("c64");
	ret->arch = strdup("6502");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_section_free);
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
	section->name = strdup("prg");
	section->paddr = 2;
	section->size = sz - 2;
	section->vaddr = baddr(bf);
	section->vsize = sz - 2;
	section->perm = RZ_PERM_RWX;
	section->add = true;
	rz_list_append(ret, section);
	return ret;
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	RzBinAddr *binaddr = RZ_NEW0(RzBinAddr);
	if (!binaddr) {
		return ret;
	}
	binaddr->paddr = 2;
	binaddr->vaddr = baddr(bf);
	rz_list_append(ret, binaddr);
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
