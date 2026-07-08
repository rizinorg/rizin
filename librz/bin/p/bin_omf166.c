// SPDX-FileCopyrightText: 2015-2019 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "omf/omf.h"

// Modified from one in analysis_riscv
// First arg is checked against all others
#define is_any_n(...) _is_any_n(__VA_ARGS__, NULL)
static bool _is_any_n(const char *str, size_t n, ...) {
	va_list va;
	va_start(va, n);
	while (true) {
		char *cur = va_arg(va, char *);
		if (!cur) {
			break;
		}
		if (!strncmp(str, cur, n)) {
			va_end(va);
			return true;
		}
	}
	va_end(va);
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	if (!buf) {
		return false;
	}

	obj->bin_obj = rz_bin_format_omf166_load(buf, size);
	if (!obj->bin_obj) {
		return false;
	}
	return true;
}

static void destroy(RzBinFile *bf) {
	if (bf->o->lines) {
		RzBinSourceLineInfo *lines = bf->o->lines;
		const size_t sc = lines->samples_count;
		for (size_t i = 0; i < sc; i++) {
			RzBinSourceLineSample *sample = &lines->samples[i];
			RZ_FREE(sample->file);
		}
		RZ_FREE(lines->samples);
	}

	rz_bin_omf166_obj *omf_obj = (rz_bin_omf166_obj *)bf->o->bin_obj;
	if (!omf_obj) {
		return;
	}
	ht_up_free(omf_obj->ht_types);
	rz_bin_format_omf166_fini(omf_obj);
}

// Look for p....C166 or p....A166
static bool check_buffer(RzBuffer *b) {
	ut8 ch;
	if (rz_buf_read_at(b, 0, &ch, 1) != 1) {
		return false;
	}
	if (ch != 0x70 && ch != 0x72) {
		return false;
	}

	ut16 rec_size;
	if (!rz_buf_read_le16_at(b, 1, &rec_size)) {
		return false;
	}

	const ut64 length = rz_buf_size(b);
	if (length < rec_size + 3) {
		return false;
	}

	ut8 in[5];
	if (!rz_buf_read_at(b, 5, in, sizeof(in)) || !is_any_n((const char *)in, sizeof(in), "C166 ", "A166 ")) {
		return false;
	}
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	if (buf == NULL) {
		// hackaround until we make this plugin not use RBuf.data
		ut8 sbuf[1024] = RZ_EMPTY;
		rz_buf_read_at(b, 0, sbuf, sizeof(sbuf));
		return rz_bin_checksum_omf_ok(sbuf, sizeof(sbuf));
	}
	return rz_bin_checksum_omf_ok(buf, length);
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *addr;
	if (!((ret = rz_pvector_new(free)))) {
		return NULL;
	}
	if (!((addr = RZ_NEW0(RzBinAddr)))) {
		rz_pvector_free(ret);
		return NULL;
	}
	addr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
	addr->vaddr = 0xC00000;
	rz_pvector_push(ret, addr);
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	const rz_bin_omf166_obj *obj = bf->o->bin_obj;
	RzBinMap *map = NULL;
	void **it;
	rz_pvector_foreach (obj->pe_vec, it) {
		const OMF_pes *pe = (OMF_pes *)*it;
		if (!((map = RZ_NEW0(RzBinMap)))) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->paddr = pe->paddr;
		map->vaddr = (pe->SegmentNumber8 << 16) + pe->offset;
		map->psize = map->vsize = pe->size;
		map->perm = get_perm_by_type(pe->data_type);
		map->name = rz_str_dup(get_data_type(pe->data_type));
		rz_pvector_push(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	RzPVector *ret;
	if (!((ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free)))) {
		return NULL;
	}

	const rz_bin_omf166_obj *obj = bf->o->bin_obj;
	void **it;
	rz_pvector_foreach (obj->sections_vec, it) {
		const OMF_sections *section = (OMF_sections *)*it;

		RzBinSection *new = NULL;
		if (!((new = RZ_NEW0(RzBinSection)))) {
			rz_pvector_free(ret);
			return NULL;
		}

		OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->index);
		if (!lname) {
			rz_warn_if_reached();
			RZ_FREE(new);
			continue;
		}
		OMF_lnames *c_lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->class_index);
		if (!c_lname) {
			rz_warn_if_reached();
			RZ_FREE(new);
			continue;
		}
		const char *name = RZ_STR_ISNOTEMPTY(lname->name) ? lname->name : "UNKNOWN";
		const char *class_name = RZ_STR_ISNOTEMPTY(c_lname->name) ? c_lname->name : "UNKNOWN";
		new->name = rz_str_newf("%s_%s", name, class_name);
		new->size = new->vsize = section->Seclen;
		new->vaddr = (section->SegmentNumber8 << 16) + section->offset;
		new->has_strings = (section->Type == 1) ? true : false;
		new->is_data = (section->Type == 1) ? true : false;
		new->is_segment = 0;
		new->perm = c166_get_perms_from_class(section->class_index);
		rz_pvector_push(ret, new);
	}
	return ret;
}

static int offset_cmp(const void *a, const void *b, void *user) {
	const OMF_symbol *sa = a;
	const OMF_symbol *sb = b;
	// first, sort by addr
	if (sa->offset < sb->offset) {
		return -1;
	}
	if (sa->offset > sb->offset) {
		return 1;
	}
	return strcmp(sa->name2, sb->name2);
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}

	const rz_bin_omf166_obj *obj = (rz_bin_omf166_obj *)bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	if (!rz_pvector_len(obj->symbols_vec)) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	rz_pvector_sort(obj->symbols_vec, offset_cmp, NULL);
	void **it;
	rz_pvector_foreach (obj->symbols_vec, it) {
		const OMF_symbol *p = (OMF_symbol *)*it;
		if (p->is_data)
			continue;
		const char *name = NULL;
		if (p->ti == 0x4B) {
			name = rz_str_newf("label.%s", p->name2);
		} else if (p->ti == 0x4D) {
			name = rz_str_newf("a166_NEAR.%s", p->name2);
		} else if (p->ti == 0x4E) {
			name = rz_str_newf("a166_FAR.%s", p->name2);
		} else if (p->ti == 0x53) {
			name = rz_str_newf("a166_INTNO.%s", p->name2);
		} else if (p->ti == 0x54) {
			name = rz_str_newf("a166_REGBANK.%s", p->name2);
		} else {
			name = rz_str_dup(p->name2);
		}

		RzBinSymbol *sym = rz_bin_symbol_new(name, p->offset, p->base + p->offset);
		RZ_FREE(name);
		sym->forwarder = "NONE";
		sym->size = p->size;
		if (p->ti == 0x4D) {
			sym->bits = 16; ///< NEAR
		} else {
			sym->bits = 32;
		}

		switch (p->rec_type) {
		case OMF166_GLBDEF:
		case OMF166_PUBDEF:
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
			sym->type = RZ_BIN_TYPE_FUNC_STR;
			break;
		case OMF166_LOCSYM:
			sym->bind = RZ_BIN_BIND_LOCAL_STR;
			sym->type = RZ_BIN_TYPE_FUNC_STR;
			break;
		default:
			sym->bind = RZ_BIN_BIND_UNKNOWN_STR;
			sym->type = RZ_BIN_TYPE_UNKNOWN_STR;
			break;
		}
		rz_pvector_push(ret, sym);
	}
	rz_pvector_foreach (obj->pe_vec, it) {
		const OMF_pes *pe = (OMF_pes *)*it;
		if (pe->isVector) {
			const ut64 addr = (pe->SegmentNumber8 << 16) + pe->offset;
			char *sym_name = pe->offset == 0x00 ? rz_str_newf("int.RESET") : rz_str_newf("isr_vec_0x%" PFMT64x, addr & 0xff);
			RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
			if (!ptr) {
				free(sym_name);
				return ret;
			}
			ptr->name = sym_name;
			ptr->paddr = addr;
			ptr->vaddr = addr;
			ptr->size = pe->size;
			ptr->ordinal = 0;
			ptr->bits = 16;
			ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			rz_pvector_push(ret, ptr);
		}
	}
	return ret;
}

static RzStructuredData *omf166_structure(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	const rz_bin_omf166_obj *obj = (rz_bin_omf166_obj *)bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *modinfo = rz_structured_data_map_add_map(info, "omf166-modinfo");
	if (!modinfo) {
		rz_structured_data_free(info);
		return NULL;
	}

	RZ_LOG_DEBUG("OMF166_MODINF: 0x%02x\n", obj->modinfo);
	/*
	  7   6   5   4   3   2   1   0
	*********************************
	* D | F | x | m | m | m | C | M *
	*********************************
	  |   |   |               |   +----> [NON]SEGMENTED
	  |   |   |   \----+---/  +--------> [NO]CASE
	  |   |   |        +---------------> MEMORY MODEL
	  |   |   +------------------------> MOD167
	  |   +----------------------------> FLOAT-USED
	  +--------------------------------> DOUB
	*/

	/**
	 * The module contains double precision float operations.
	 * This bit is intended for the linker for automatic selection of libraries.
	 */
	rz_structured_data_map_add_boolean(modinfo, "DoubleUsed", obj->modinfo >> 7);
	/**
	 * The module contains single precision float operations.
	 * This bit is intended for the linker for automatic selection of libraries.
	 */
	rz_structured_data_map_add_boolean(modinfo, "FloatUsed", (obj->modinfo & 0x40) >> 6);
	/**
	 * If bit is set, then the module is intended to be executed on an 80C167 CPU,
	 * otherwise the module is for a 80C166 CPU.
	 */
	rz_structured_data_map_add_boolean(modinfo, "MOD167", (obj->modinfo & 0x20) >> 5);
	/**
	 * If bit is set, then names are to be considered case sensitive.
	 * This info is intended for the linker when combining object modules.
	 */
	rz_structured_data_map_add_boolean(modinfo, "CaseSensitive", (obj->modinfo & 0x02) >> 1);
	///< If bit is set, then the segmented cpu mode was choosen for the module.
	rz_structured_data_map_add_boolean(modinfo, "Segmented", (obj->modinfo & 0x01));
	const char *mm = get_memory_model(obj->modinfo);
	rz_structured_data_map_add_string(modinfo, "MemoryModel", mm);
	free((char *)mm);
	return info;
}

static RzBinInfo *info(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	const rz_bin_omf166_obj *obj = (rz_bin_omf166_obj *)bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	RzBinInfo *ret;
	if (!((ret = RZ_NEW0(RzBinInfo)))) {
		return NULL;
	}

	ret->type = get_memory_model(obj->modinfo);
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("OMF (Object Module Format)");
	ret->rclass = rz_str_dup("OMF166");
	ret->compiler = rz_str_dup("keil");
	ret->os = rz_str_dup("c166");
	ret->machine = rz_str_dup("Siemens/Infineon C166 family microcontroller");
	ret->arch = rz_str_dup("c166");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = 16;
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.string_encoding = RZ_STRING_ENC_UTF8;
	return rz_bin_file_strings(bf, &opt);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	RzBinAddr *ptr = NULL;

	switch (type) {
	case RZ_BIN_SPECIAL_SYMBOL_ENTRY:
		// entrypoint is always RESET vector (0xC00000)
		if (!((ptr = RZ_NEW0(RzBinAddr)))) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
		ptr->vaddr = 0xC00000;
		return ptr;
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
		if (!((ptr = RZ_NEW0(RzBinAddr)))) {
			return NULL;
		}
		if (!rz_bin_omf166_get_entry(bf->o->bin_obj, ptr)) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_MAIN;
		return ptr;
	default:
		return NULL;
	}
}

RzBinPlugin rz_bin_plugin_omf166 = {
	.name = "omf166",
	.desc = "OMF166 (Object Module Format by Siemens)",
	.license = "LGPL3",
	.author = "SSharshunov",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.binsym = &binsym,
	.symbols = &symbols,
	.bin_structure = &omf166_structure,
	.info = &info,
	.strings = &strings,
	.get_vaddr = &get_vaddr,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_omf166,
	.version = RZ_VERSION
};
#endif
