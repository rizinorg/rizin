// SPDX-FileCopyrightText: 2015-2019 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "omf/omf.h"

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	rz_return_val_if_fail(buf, false);
	*bin_obj = rz_bin_internal_omf_load(buf, size);
	return *bin_obj != NULL;
}

static void destroy(RzBinFile *bf) {
	rz_bin_free_all_omf_obj(bf->o->bin_obj);
	bf->o->bin_obj = NULL;
}

static bool check_buffer(RzBuffer *b) {
	int i;
	ut8 ch;
	if (rz_buf_read_at(b, 0, &ch, 1) != 1) {
		return false;
	}
	if (ch != 0x80 && ch != 0x82) {
		return false;
	}
	ut16 rec_size = rz_buf_read_le16_at(b, 1);
	ut8 str_size;
	(void)rz_buf_read_at(b, 3, &str_size, 1);
	ut64 length = rz_buf_size(b);
	if (str_size + 2 != rec_size || length < rec_size + 3) {
		return false;
	}
	// check that the string is ASCII
	for (i = 4; i < str_size + 4; i++) {
		if (rz_buf_read_at(b, i, &ch, 1) != 1) {
			break;
		}
		if (ch > 0x7f) {
			return false;
		}
	}
	const ut8 *buf = rz_buf_data(b, NULL);
	if (buf == NULL) {
		// hackaround until we make this plugin not use RBuf.data
		ut8 buf[1024] = { 0 };
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return rz_bin_checksum_omf_ok(buf, sizeof(buf));
	}
	rz_return_val_if_fail(buf, false);
	return rz_bin_checksum_omf_ok(buf, length);
}

static ut64 baddr(RzBinFile *bf) {
	return OMF_BASE_ADDR;
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret;
	RzBinAddr *addr;

	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}
	if (!(addr = RZ_NEW0(RzBinAddr))) {
		rz_list_free(ret);
		return NULL;
	}
	if (!rz_bin_omf_get_entry(bf->o->bin_obj, addr)) {
		RZ_FREE(addr);
	} else {
		rz_list_append(ret, addr);
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret;
	ut32 ct_omf_sect = 0;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	rz_bin_omf_obj *obj = bf->o->bin_obj;

	if (!(ret = rz_list_new())) {
		return NULL;
	}

	while (ct_omf_sect < obj->nb_section) {
		if (!rz_bin_omf_send_sections(ret,
			    obj->sections[ct_omf_sect++], bf->o->bin_obj)) {
			return ret;
		}
	}
	return ret;
}

static RzList *symbols(RzBinFile *bf) {
	RzList *ret;
	RzBinSymbol *sym;
	OMF_symbol *sym_omf;
	int ct_sym = 0;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = rz_list_new())) {
		return NULL;
	}

	ret->free = free;

	while (ct_sym < ((rz_bin_omf_obj *)bf->o->bin_obj)->nb_symbol) {
		if (!(sym = RZ_NEW0(RzBinSymbol))) {
			return ret;
		}
		sym_omf = ((rz_bin_omf_obj *)bf->o->bin_obj)->symbols[ct_sym++];
		sym->name = strdup(sym_omf->name);
		sym->forwarder = "NONE";
		sym->paddr = rz_bin_omf_get_paddr_sym(bf->o->bin_obj, sym_omf);
		sym->vaddr = rz_bin_omf_get_vaddr_sym(bf->o->bin_obj, sym_omf);
		sym->ordinal = ct_sym;
		sym->size = 0;
		rz_list_append(ret, sym);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->bclass = strdup("OMF");
	ret->rclass = strdup("omf");
	// the "E" is here to made rva return the same value for 16 bit en 32 bits files
	ret->type = strdup("E OMF (Relocatable Object Module Format)");
	ret->os = strdup("any");
	ret->machine = strdup("i386");
	ret->arch = strdup("x86");
	ret->big_endian = false;
	ret->has_va = true;
	ret->has_lit = true;
	ret->bits = rz_bin_omf_get_bits(bf->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

RzBinPlugin rz_bin_plugin_omf = {
	.name = "omf",
	.desc = "omf bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.get_vaddr = &get_vaddr,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_omf,
	.version = RZ_VERSION
};
#endif
