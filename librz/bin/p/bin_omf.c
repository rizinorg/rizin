// SPDX-FileCopyrightText: 2015-2019 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "omf/omf.h"

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	rz_return_val_if_fail(buf, false);
	obj->bin_obj = rz_bin_internal_omf_load(buf, size);
	return obj->bin_obj;
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

	ut16 rec_size;
	if (!rz_buf_read_le16_at(b, 1, &rec_size)) {
		return false;
	}

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
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
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

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *addr;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(addr = RZ_NEW0(RzBinAddr))) {
		rz_pvector_free(ret);
		return NULL;
	}
	if (!rz_bin_omf_get_entry(bf->o->bin_obj, addr)) {
		RZ_FREE(addr);
	} else {
		rz_pvector_push(ret, addr);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret;
	ut32 ct_omf_sect = 0;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	rz_bin_omf_obj *obj = bf->o->bin_obj;

	if (!(ret = rz_pvector_new(NULL))) {
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

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret;
	RzBinSymbol *sym;
	OMF_symbol *sym_omf;
	int ct_sym = 0;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	while (ct_sym < ((rz_bin_omf_obj *)bf->o->bin_obj)->nb_symbol) {
		if (!(sym = RZ_NEW0(RzBinSymbol))) {
			return ret;
		}
		sym_omf = ((rz_bin_omf_obj *)bf->o->bin_obj)->symbols[ct_sym++];
		sym->name = rz_str_dup(sym_omf->name);
		sym->forwarder = "NONE";
		sym->paddr = rz_bin_omf_get_paddr_sym(bf->o->bin_obj, sym_omf);
		sym->vaddr = rz_bin_omf_get_vaddr_sym(bf->o->bin_obj, sym_omf);
		sym->ordinal = ct_sym;
		sym->size = 0;
		rz_pvector_push(ret, sym);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("OMF");
	ret->rclass = rz_str_dup("omf");
	// the "E" is here to made rva return the same value for 16 bit en 32 bits files
	ret->type = rz_str_dup("E OMF (Relocatable Object Module Format)");
	ret->os = rz_str_dup("any");
	ret->machine = rz_str_dup("i386");
	ret->arch = rz_str_dup("x86");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = rz_bin_omf_get_bits(bf->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

#define OMF_MAX_DATA_BLOCKS 100

static const char *omf_segment_name(rz_bin_omf_obj *obj, OMF_segment *seg) {
	if (!seg || seg->name_idx == 0 || seg->name_idx > obj->nb_name || !obj->names) {
		return NULL;
	}
	return obj->names[seg->name_idx - 1];
}

static void omf_structure_add_names(RzStructuredData *omf, rz_bin_omf_obj *obj) {
	if (obj->nb_name == 0 || !obj->names) {
		return;
	}

	RzStructuredData *names = rz_structured_data_map_add_array(omf, "names");
	if (!names) {
		return;
	}

	for (ut32 i = 0; i < obj->nb_name; i++) {
		if (obj->names[i]) {
			rz_structured_data_array_add_string(names, obj->names[i]);
		}
	}
}

static void omf_structure_add_data_blocks(RzStructuredData *section, OMF_segment *seg) {
	if (!seg->data) {
		return;
	}

	RzStructuredData *data_blocks = rz_structured_data_map_add_array(section, "data_blocks");
	if (!data_blocks) {
		return;
	}

	OMF_data *data = seg->data;
	ut32 block_count = 0;
	while (data && block_count < OMF_MAX_DATA_BLOCKS) {
		RzStructuredData *block = rz_structured_data_array_add_map(data_blocks);
		if (block) {
			rz_structured_data_map_add_unsigned(block, "paddr", data->paddr, true);
			rz_structured_data_map_add_unsigned(block, "size", data->size, false);
			rz_structured_data_map_add_unsigned(block, "offset", data->offset, true);
		}
		data = data->next;
		block_count++;
	}
	if (block_count >= OMF_MAX_DATA_BLOCKS && data) {
		RZ_LOG_WARN("OMF: Maximum number of data blocks (%d) reached, some blocks may be missing\n", OMF_MAX_DATA_BLOCKS);
	}
}

static void omf_structure_add_section(RzStructuredData *sections, OMF_segment *seg, rz_bin_omf_obj *obj) {
	RzStructuredData *section = rz_structured_data_array_add_map(sections);
	if (!section) {
		return;
	}

	const char *name = omf_segment_name(obj, seg);

	rz_structured_data_map_add_string(section, "name", rz_str_get(name));
	rz_structured_data_map_add_unsigned(section, "name_idx", seg->name_idx, false);
	rz_structured_data_map_add_unsigned(section, "vaddr", seg->vaddr, true);
	rz_structured_data_map_add_unsigned(section, "size", seg->size, false);
	rz_structured_data_map_add_unsigned(section, "bits", seg->bits, false);

	omf_structure_add_data_blocks(section, seg);
}

static void omf_structure_add_sections(RzStructuredData *omf, rz_bin_omf_obj *obj) {
	if (obj->nb_section == 0 || !obj->sections) {
		return;
	}

	RzStructuredData *sections = rz_structured_data_map_add_array(omf, "sections");
	if (!sections) {
		return;
	}

	for (ut32 i = 0; i < obj->nb_section; i++) {
		OMF_segment *seg = obj->sections[i];
		if (!seg) {
			continue;
		}
		omf_structure_add_section(sections, seg, obj);
	}
}

static void omf_structure_add_symbol(RzStructuredData *symbols, OMF_symbol *sym, rz_bin_omf_obj *obj) {
	RzStructuredData *symbol = rz_structured_data_array_add_map(symbols);
	if (!symbol) {
		return;
	}

	rz_structured_data_map_add_string(symbol, "name", rz_str_get(sym->name));
	rz_structured_data_map_add_unsigned(symbol, "seg_idx", sym->seg_idx, false);
	rz_structured_data_map_add_unsigned(symbol, "offset", sym->offset, true);

	if (sym->seg_idx > 0 && sym->seg_idx <= obj->nb_section && obj->sections) {
		OMF_segment *seg = obj->sections[sym->seg_idx - 1];
		const char *seg_name = omf_segment_name(obj, seg);
		rz_structured_data_map_add_string(symbol, "segment", rz_str_get(seg_name));
	}

	ut64 paddr = rz_bin_omf_get_paddr_sym(obj, sym);
	ut64 vaddr = rz_bin_omf_get_vaddr_sym(obj, sym);
	rz_structured_data_map_add_unsigned(symbol, "paddr", paddr, true);
	rz_structured_data_map_add_unsigned(symbol, "vaddr", vaddr, true);
}

static void omf_structure_add_symbols(RzStructuredData *omf, rz_bin_omf_obj *obj) {
	if (obj->nb_symbol == 0 || !obj->symbols) {
		return;
	}

	RzStructuredData *symbols = rz_structured_data_map_add_array(omf, "symbols");
	if (!symbols) {
		return;
	}

	for (ut32 i = 0; i < obj->nb_symbol; i++) {
		OMF_symbol *sym = obj->symbols[i];
		if (!sym) {
			continue;
		}
		omf_structure_add_symbol(symbols, sym, obj);
	}
}

static RzStructuredData *omf_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	rz_bin_omf_obj *obj = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *omf = rz_structured_data_map_add_map(info, "omf");
	if (!omf) {
		rz_structured_data_free(info);
		return NULL;
	}

	int bits = rz_bin_omf_get_bits(obj);
	rz_structured_data_map_add_unsigned(omf, "bits", bits, false);
	rz_structured_data_map_add_unsigned(omf, "num_names", obj->nb_name, false);
	rz_structured_data_map_add_unsigned(omf, "num_sections", obj->nb_section, false);
	rz_structured_data_map_add_unsigned(omf, "num_symbols", obj->nb_symbol, false);

	omf_structure_add_names(omf, obj);
	omf_structure_add_sections(omf, obj);
	omf_structure_add_symbols(omf, obj);

	return info;
}

RzBinPlugin rz_bin_plugin_omf = {
	.name = "omf",
	.desc = "OMF (Object Module Format)",
	.license = "LGPL3",
	.author = "ampotos",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.bin_structure = &omf_structure,
	.get_vaddr = &get_vaddr,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_omf,
	.version = RZ_VERSION
};
#endif
