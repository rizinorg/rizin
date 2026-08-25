// SPDX-FileCopyrightText: 2015-2019 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "omf/omf96.h"
#include "omf/omf51.h"
#include "omf/omf166.h"
#include "omf/omf_common.h"

static bool load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *b, RZ_UNUSED Sdb *sdb) {
	if (!obj) {
		return false;
	}
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	if (!buf) {
		return false;
	}

	rz_bin_omf_base_obj *base_obj = (rz_bin_omf_base_obj *)RZ_NEW0(rz_bin_omf_base_obj);

	const OMF_FILE_TARGET_TYPE omf_type = check_omf_type(b);
	switch (omf_type) {
	case OMF_FILE_TARGET_C166:
		base_obj->target_obj = (rz_bin_omf166_obj *)RZ_NEW0(rz_bin_omf166_obj);
		if (!base_obj->target_obj) {
			RZ_FREE(base_obj);
			return false;
		}
		base_obj->init_internal_storage = rz_bin_format_omf166_init_internal_storage;
		base_obj->is_valid_omf_type = is_valid_omf166_type;
		base_obj->load_omf_content = rz_bin_format_omf166_load_content;
		base_obj->get_bits = rz_bin_omf166_get_bits;
		base_obj->omf_structure = omf166_structure;
		base_obj->free_all_omf_obj = rz_bin_free_all_omf166_obj;
		base_obj->post_init = rz_bin_format_omf166_post_init;
		base_obj->sections = omf166_sections;
		base_obj->maps = omf166_maps;
		base_obj->symbols = omf166_symbols;
		base_obj->get_entry = rz_bin_omf166_get_entry;
		base_obj->max_record_size = omf166_max_record_size;
		base_obj->info = omf166_info;
		base_obj->baddr = omf166_baddr;
		break;
	case OMF_FILE_TARGET_51: {
		base_obj->target_obj = (rz_bin_omf51_obj *)RZ_NEW0(rz_bin_omf51_obj);
		if (!base_obj->target_obj) {
			RZ_FREE(base_obj);
			return false;
		}
		base_obj->init_internal_storage = rz_bin_format_omf51_init_internal_storage;
		base_obj->get_bits = rz_bin_omf51_get_bits;
		base_obj->load_omf_content = rz_bin_format_omf51_load_content;
		base_obj->is_valid_omf_type = is_valid_omf51_type;
		base_obj->omf_structure = NULL;
		base_obj->free_all_omf_obj = rz_bin_free_all_omf51_obj;
		base_obj->post_init = rz_bin_format_omf51_post_init;
		base_obj->sections = omf51_sections;
		base_obj->maps = omf51_maps;
		base_obj->symbols = omf51_symbols;
		base_obj->get_entry = rz_bin_omf51_get_entry;
		base_obj->max_record_size = omf51_max_record_size;
		base_obj->info = omf51_info;
		base_obj->baddr = omf51_baddr;
		break;
	}
	case OMF_FILE_TARGET_96:
		base_obj->target_obj = (rz_bin_omf96_obj *)RZ_NEW0(rz_bin_omf96_obj);
		if (!base_obj->target_obj) {
			RZ_FREE(base_obj);
			return false;
		}
		base_obj->init_internal_storage = rz_bin_format_omf96_init_internal_storage;
		base_obj->get_bits = rz_bin_omf96_get_bits;
		base_obj->load_omf_content = rz_bin_format_omf96_load_omf_content;
		base_obj->is_valid_omf_type = omf_is_valid_omf96_type;
		base_obj->omf_structure = omf96_structure;
		base_obj->free_all_omf_obj = rz_bin_free_all_omf96_obj;
		base_obj->post_init = rz_bin_format_omf96_post_init;
		base_obj->sections = omf96_sections;
		base_obj->maps = omf96_maps;
		base_obj->symbols = omf96_symbols;
		base_obj->get_entry = rz_bin_omf96_get_entry;
		base_obj->max_record_size = omf96_max_record_size;
		base_obj->info = omf96_info;
		base_obj->baddr = omf96_baddr;
		break;
	default:
		rz_warn_if_reached();
		return false;
	}

	if (!base_obj->target_obj) {
		return false;
	}

	if (!rz_bin_format_omf_load_all_records(base_obj, buf, size)) {
		RZ_LOG_DEBUG("rz_bin_internal_omf_load error\n");
		if (base_obj->free_all_omf_obj) {
			base_obj->free_all_omf_obj(base_obj->target_obj);
		}
		return NULL;
	}

	obj->bin_obj = base_obj;
	return true;
}

bool omf_load_buffer(RZ_UNUSED RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb) {
	return load_buffer(bf, obj, buf, sdb);
}

static void destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}
	if (bf->o->lines) {
		RzBinSourceLineInfo *lines = bf->o->lines;
		const size_t sc = lines->samples_count;
		for (size_t i = 0; i < sc; i++) {
			RzBinSourceLineSample *sample = &lines->samples[i];
			RZ_FREE(sample->file);
		}
		RZ_FREE(lines->samples);
	}

	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (base_obj->free_all_omf_obj) {
		base_obj->free_all_omf_obj(base_obj->target_obj);
	}
	RZ_FREE(bf->o->bin_obj);
}

static bool check_buffer(RzBuffer *b) {
	return omf_check_buffer(b);
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (!base_obj->get_entry) {
		return NULL;
	}
	RzBinAddr *addr = base_obj->get_entry(base_obj->target_obj);
	if (!addr) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		RZ_FREE(addr);
		return NULL;
	}
	rz_pvector_push(ret, addr);
	return ret;
}

char *sect_name(const rz_bin_omf96_obj *omf_obj, const ut16 idx) {
	if (!omf_obj->sections_vec) {
		return NULL;
	}
	const OMF1_1_sections *section = (OMF1_1_sections *)rz_pvector_at(omf_obj->sections_vec, idx);
	if (!section) {
		RZ_LOG_DEBUG("unknown section segment id: 0x%02x\n", idx);
		rz_warn_if_reached();
		return NULL;
	}
	const OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(omf_obj->lnames_vec, section->seg_name_idx);
	if (!lname) {
		RZ_LOG_DEBUG("unknown section segment id: 0x%02x\n", idx);
		rz_warn_if_reached();
		return NULL;
	}
	const OMF_lnames *c_lname = (OMF_lnames *)rz_pvector_at(omf_obj->lnames_vec, section->class_name_idx);
	if (!c_lname) {
		rz_warn_if_reached();
		return NULL;
	}

	const char *name = RZ_STR_ISNOTEMPTY(lname->name) ? lname->name : "UNKNOWN";
	const char *class_name = RZ_STR_ISNOTEMPTY(c_lname->name) ? c_lname->name : "UNKNOWN";
	char *class_and_name = rz_str_newf("%s_%s", name, class_name);
	return class_and_name;
}

RzPVector /*<RzBinSection *>*/ *omf96_maps(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = NULL;
	void **it;
	rz_pvector_foreach (obj->pe_vec, it) {
		const OMF_pes *pe = (OMF_pes *)*it;
		map = RZ_NEW0(RzBinMap);
		if (!map) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->paddr = pe->paddr;
		const OMF1_1_sections *sect = rz_pvector_at(obj->sections_vec, pe->seg_idx - 1);
		if (!sect) {
			rz_warn_if_reached();
			rz_pvector_free(ret);
			return NULL;
		}

		map->vaddr = sect->vaddr + pe->offset;
		map->psize = pe->size;
		map->vsize = pe->size;
		map->perm = RZ_PERM_R;
		map->name = sect_name(obj, pe->seg_idx - 1);
		if (strstr(map->name, "CODE")) {
			map->perm = RZ_PERM_RX;
		}
		if (strstr(map->name, "DATA")) {
			map->perm = RZ_PERM_RW;
		}
		if (strstr(map->name, "DWARF")) {
			map->perm = RZ_PERM_R;
		}
		if (strstr(map->name, "UNKNOWN")) {
			map->perm = RZ_PERM_R;
		}
		RZ_LOG_DEBUG("OMF_LEDATA\t%d\tseg_idx: %d, map->name: `%s`, offset: 0x%06" PFMT32x ", "
			     "pe->paddr: 0x%06" PFMT32x " [%u] map->vaddr: 0x%06" PFMT64x ", psize: %" PFMT32u "\n",
			pe->use32 ? 32 : 16,
			pe->seg_idx, map->name,
			pe->offset, pe->paddr,
			pe->paddr, map->vaddr, pe->psize);
		rz_pvector_push(ret, map);
	}

	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (base_obj->maps) {
		return base_obj->maps(base_obj->target_obj);
	}
	return NULL;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (base_obj->sections) {
		return base_obj->sections(base_obj->target_obj);
	}
	return NULL;
}

RzPVector /*<RzBinSection *>*/ *omf96_symbols(RZ_NONNULL const void *target_obj) {
	const rz_bin_omf96_obj *obj = (const rz_bin_omf96_obj *)target_obj;
	int ct_sym = 0;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	if (!obj->symbols_vec) {
		return ret;
	}
	void **it;
	rz_pvector_foreach (obj->symbols_vec, it) {
		const OMF_symbol *sym_omf = (OMF_symbol *)*it;
		if (sym_omf->rec_type == OMF_EXTDEF) {
			RZ_LOG_DEBUG("OMF_EXTDEF - External Names Definition Record\n");
			continue;
		}
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			return ret;
		}
		sym->name = rz_str_dup(sym_omf->name2);
		sym->forwarder = "NONE";
		sym->paddr = rz_bin_omf96_get_paddr_sym(obj, sym_omf->seg_idx, sym_omf->offset);
		sym->vaddr = rz_bin_omf_get_vaddr_sym(obj, sym_omf);
		sym->ordinal = ct_sym;
		sym->size = 0;
		sym->bind = RZ_BIN_BIND_GLOBAL_STR;
		RZ_LOG_DEBUG("ext: [%d] seg_idx: %d, sym->name: `%s`, sym->forwarder: %s, "
			     "sym->paddr: 0x%06" PFMT64x ", sym->vaddr: 0x%06" PFMT64x "\n",
			sym_omf->is_extdef, sym_omf->seg_idx, sym->name, sym->forwarder, sym->paddr, sym->vaddr);
		ct_sym++;
		rz_pvector_push(ret, sym);
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (base_obj->symbols) {
		return base_obj->symbols(base_obj->target_obj);
	}
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_omf_base_obj *base_obj = (const rz_bin_omf_base_obj *)bf->o->bin_obj;
	if (base_obj->info) {
		RzBinInfo *ret = base_obj->info(base_obj->target_obj);
		ret->file = rz_str_dup(bf->file);
		return ret;
	}
	return NULL;
}

static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	(void)bf;
	(void)baddr;
	(void)paddr;
	return vaddr;
}

const char *fixup_location_desc(const ut8 type);

ut64 get_target_vaddr(const rz_bin_omf96_obj *obj, ut8 target_type, ut32 target_datum) {
	///< target_type == 0 -> SEGDEF index (1-based)
	const size_t num_segments = rz_pvector_len(obj->sections_vec);
	if (target_type == 0 && target_datum > 0 && target_datum <= num_segments) {
		const OMF1_1_sections *section = (OMF1_1_sections *)rz_pvector_at(obj->sections_vec, target_datum - 1);
		return section->vaddr;
	}
	return 0;
}

ut64 get_frame_vaddr(const rz_bin_omf96_obj *obj, ut8 frame_type, ut32 frame_datum, ut64 target_vaddr) {
	switch (frame_type) {
	case 1: ///< F1: GRPDEF index
	{
		const size_t num_groups = rz_pvector_len(obj->groups_vec);
		if (frame_datum > 0 && frame_datum <= num_groups) {
			const OMF_group *group = (OMF_group *)rz_pvector_at(obj->groups_vec, frame_datum - 1);
			return group->vaddr;
		}
		break;
	}
	case 5: ///< F5: TARGET == FRAME
		return target_vaddr;
	default:
		return 0;
	}
	return 0;
}

OMF_symbol *find_sym_by_address(const rz_bin_omf96_obj *obj, const ut64 address);

static RzStructuredData *omf_structure(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (base_obj->omf_structure) {
		return base_obj->omf_structure(base_obj->target_obj);
	}
	return NULL;
}

static ut64 omf_baddr(RzBinFile *bf) {
	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (base_obj->baddr) {
		return base_obj->baddr(base_obj->target_obj);
	}
	return 0U;
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	const rz_bin_omf_base_obj *base_obj = bf->o->bin_obj;
	if (type == RZ_BIN_SPECIAL_SYMBOL_ENTRY) {
		///< entrypoint is always RESET vector (base_addr)
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (!ptr) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
		if (base_obj->baddr) {
			ptr->vaddr = base_obj->baddr(base_obj->target_obj);
		}
		ptr->vaddr = 0U;
		return ptr;
	}
	if (type == RZ_BIN_SPECIAL_SYMBOL_MAIN) {
		if (!base_obj->get_entry) {
			return NULL;
		}

		RzBinAddr *ptr = base_obj->get_entry(base_obj->target_obj);
		if (!ptr) {
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_MAIN;
		return ptr;
	}
	return NULL;
}

RzBinPlugin rz_bin_plugin_omf = {
	.name = "omf",
	.desc = "OMF (Object Module Format)",
	.license = "LGPL3",
	.author = "ampotos",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.binsym = &binsym,
	.symbols = &symbols,
	.info = &info,
	.bin_structure = &omf_structure,
	.get_vaddr = &get_vaddr,
	.baddr = &omf_baddr
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_omf,
	.version = RZ_VERSION
};
#endif
