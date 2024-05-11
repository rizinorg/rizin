// SPDX-FileCopyrightText: 2014-2019 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_util/ht_uu.h>

#include "coff/coff.h"

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

static void populate_symbols(RzBinFile *bf);

static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	struct rz_bin_coff_obj *bin = (struct rz_bin_coff_obj *)o->bin_obj;
	if (bin->kv) {
		return bin->kv;
	}
	return NULL;
}

static bool rz_coff_is_stripped(struct rz_bin_coff_obj *obj) {
	return !!(obj->hdr.f_flags & (COFF_FLAGS_TI_F_RELFLG | COFF_FLAGS_TI_F_LNNO | COFF_FLAGS_TI_F_LSYMS));
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	obj->bin_obj = rz_bin_coff_new_buf(buf, bf->rbin->verbose);
	return obj->bin_obj != NULL;
}

static void destroy(RzBinFile *bf) {
	rz_bin_coff_free((struct rz_bin_coff_obj *)bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	return NULL;
}

#define DTYPE_IS_FUNCTION(type) (COFF_SYM_GET_DTYPE(type) == COFF_SYM_DTYPE_FUNCTION)

static bool is_imported_symbol(struct coff_symbol *s) {
	return s->n_scnum == COFF_SYM_SCNUM_UNDEF && s->n_sclass == COFF_SYM_CLASS_EXTERNAL;
}

static bool _fill_bin_symbol(RzBin *rbin, struct rz_bin_coff_obj *bin, int idx, RzBinSymbol **sym) {
	RzBinSymbol *ptr = *sym;
	struct coff_scn_hdr *sc_hdr = NULL;
	if (idx < 0 || idx > bin->hdr.f_nsyms) {
		return false;
	}
	if (!bin->symbols) {
		return false;
	}
	char tmpbuf[32];
	struct coff_symbol *s = &bin->symbols[idx];
	char *coffname = rz_coff_symbol_name(bin, (const ut8 *)&s->n_name);
	if (!coffname) {
		return false;
	}
	ptr->size = 4;
	ptr->ordinal = 0;
	ptr->name = coffname;
	ptr->forwarder = "NONE";
	ptr->bind = RZ_BIN_BIND_LOCAL_STR;
	ptr->is_imported = is_imported_symbol(s);
	ptr->vaddr = UT64_MAX;
	if (s->n_scnum < bin->hdr.f_nscns + 1 && s->n_scnum > 0) {
		// first index is 0 that is why -1
		sc_hdr = &bin->scn_hdrs[s->n_scnum - 1];
		ptr->paddr = sc_hdr->s_scnptr + s->n_value;
		if (bin->scn_va) {
			ptr->vaddr = bin->scn_va[s->n_scnum - 1] + s->n_value;
		}
	}
	if (ptr->is_imported) {
		// if the symbol is an import and it will be assigned an artificial target,
		// assign this target as the vaddr of the symbol.
		bool found;
		ut64 imp_idx = ht_uu_find(bin->imp_index, idx, &found);
		if (found) {
			ptr->vaddr = rz_coff_import_index_addr(bin, imp_idx);
		}
	}

	switch (s->n_sclass) {
	case COFF_SYM_CLASS_FUNCTION:
		ptr->type = RZ_BIN_TYPE_FUNC_STR;
		break;
	case COFF_SYM_CLASS_FILE:
		ptr->type = RZ_BIN_TYPE_FILE_STR;
		break;
	case COFF_SYM_CLASS_SECTION:
		ptr->type = RZ_BIN_TYPE_SECTION_STR;
		break;
	case COFF_SYM_CLASS_EXTERNAL:
		if (s->n_scnum == COFF_SYM_SCNUM_UNDEF) {
			ptr->paddr = UT64_MAX;
			ptr->bind = "NONE";
		} else {
			ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
		}
		ptr->type = (DTYPE_IS_FUNCTION(s->n_type) || !strcmp(coffname, "main"))
			? RZ_BIN_TYPE_FUNC_STR
			: RZ_BIN_TYPE_UNKNOWN_STR;
		break;
	case COFF_SYM_CLASS_STATIC:
		if (s->n_scnum == COFF_SYM_SCNUM_ABS) {
			ptr->type = "ABS";
			ptr->paddr = UT64_MAX;
			char *newname = rz_str_newf("%s-0x%08x", coffname, s->n_value);
			if (newname) {
				free(ptr->name);
				ptr->name = newname;
			}
		} else if (sc_hdr && !memcmp(sc_hdr->s_name, s->n_name, 8)) {
			ptr->type = RZ_BIN_TYPE_SECTION_STR;
		} else {
			ptr->type = DTYPE_IS_FUNCTION(s->n_type)
				? RZ_BIN_TYPE_FUNC_STR
				: RZ_BIN_TYPE_UNKNOWN_STR;
		}
		break;
	case COFF_SYM_CLASS_LABEL:
		ptr->type = "LABEL";
		ptr->size = 0;
		break;
	default:
		ptr->type = rz_str_constpool_get(&rbin->constpool, rz_strf(tmpbuf, "%i", s->n_sclass));
		break;
	}
	return true;
}

static RzBinImport *_fill_bin_import(struct rz_bin_coff_obj *bin, int idx) {
	RzBinImport *ptr = RZ_NEW0(RzBinImport);
	if (!ptr || idx < 0 || idx > bin->hdr.f_nsyms) {
		free(ptr);
		return NULL;
	}
	struct coff_symbol *s = &bin->symbols[idx];
	if (!is_imported_symbol(s)) {
		free(ptr);
		return NULL;
	}
	char *coffname = rz_coff_symbol_name(bin, (const ut8 *)s->n_name);
	if (!coffname) {
		free(ptr);
		return NULL;
	}
	ptr->name = coffname;
	ptr->bind = "NONE";
	ptr->type = DTYPE_IS_FUNCTION(s->n_type)
		? RZ_BIN_TYPE_FUNC_STR
		: RZ_BIN_TYPE_UNKNOWN_STR;
	return ptr;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret;
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	RzBinAddr *ptr = rz_coff_get_entry(obj);
	if (ptr) {
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzPVector *r = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!r) {
		return NULL;
	}
	RzBinObject *o = bf->o;
	struct rz_bin_coff_obj *obj = o ? o->bin_obj : NULL;
	if (!obj) {
		return r;
	}
	populate_symbols(bf); // the patching depends on symbols to be available
	// virtual file for reloc targets (where the relocs will point into)
	ut64 rtmsz = rz_coff_get_reloc_targets_vfile_size(obj);
	if (rtmsz) {
		RzBuffer *buf = rz_buf_new_empty(rtmsz);
		if (!buf) {
			return r;
		}
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return r;
		}
		vf->buf = buf;
		vf->buf_owned = true;
		vf->name = strdup(VFILE_NAME_RELOC_TARGETS);
		rz_pvector_push(r, vf);
	}
	// virtual file mirroring the raw file, but with relocs patched
	RzBuffer *buf_patched = rz_coff_get_patched_buf(obj);
	if (buf_patched) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return r;
		}
		vf->buf = buf_patched;
		vf->name = strdup(VFILE_NAME_PATCHED);
		rz_pvector_push(r, vf);
	}
	return r;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	RzBinObject *o = bf->o;
	struct rz_bin_coff_obj *obj = o ? o->bin_obj : NULL;
	if (!obj || !obj->scn_hdrs) {
		return ret;
	}
	populate_symbols(bf);
	for (size_t i = 0; i < obj->hdr.f_nscns; i++) {
		RzBinMap *ptr = RZ_NEW0(RzBinMap);
		if (!ptr) {
			return ret;
		}
		struct coff_scn_hdr *hdr = &obj->scn_hdrs[i];
		ptr->name = rz_coff_symbol_name(obj, (const ut8 *)hdr->s_name);
		ptr->psize = hdr->s_size;
		ptr->vsize = hdr->s_size;
		ptr->paddr = hdr->s_scnptr;
		if (obj->scn_va) {
			ptr->vaddr = obj->scn_va[i];
		}
		ptr->perm = rz_coff_perms_from_section_flags(hdr->s_flags);
		if (hdr->s_nreloc) {
			ptr->vfile_name = strdup(VFILE_NAME_PATCHED);
		}
		rz_pvector_push(ret, ptr);
	}
	ut64 rtmsz = rz_coff_get_reloc_targets_vfile_size(obj);
	if (rtmsz) {
		// virtual file for reloc targets (where the relocs will point into)
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->name = strdup("reloc-targets");
		map->paddr = 0;
		map->psize = rtmsz;
		map->vaddr = rz_coff_get_reloc_targets_map_base(obj);
		map->vsize = rtmsz;
		map->perm = RZ_PERM_R;
		map->vfile_name = strdup(VFILE_NAME_RELOC_TARGETS);
		rz_pvector_push_front(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	if (!obj || !obj->scn_hdrs) {
		return ret;
	}
	for (size_t i = 0; i < obj->hdr.f_nscns; i++) {
		RzBinSection *ptr = RZ_NEW0(RzBinSection);
		if (!ptr) {
			return ret;
		}
		ptr->name = rz_coff_symbol_name(obj, (const ut8 *)&obj->scn_hdrs[i].s_name);
		if (strstr(ptr->name, "data")) {
			ptr->is_data = true;
		}
		ptr->size = obj->scn_hdrs[i].s_size;
		ptr->vsize = obj->scn_hdrs[i].s_size;
		ptr->paddr = obj->scn_hdrs[i].s_scnptr;
		ptr->flags = obj->scn_hdrs[i].s_flags;
		if (obj->scn_va) {
			ptr->vaddr = obj->scn_va[i];
		}
		ptr->perm = rz_coff_perms_from_section_flags(ptr->flags);
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static void populate_imports(struct rz_bin_coff_obj *obj) {
	if (obj->imp_index->count || !obj->symbols) {
		return;
	}
	int ord = 0;
	ut64 imp_idx = 0;
	for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
		RzBinImport *ptr = _fill_bin_import(obj, i);
		if (ptr) {
			ptr->ordinal = ord++;
			ht_up_insert(obj->imp_ht, (ut64)i, ptr, NULL);
			ht_uu_insert(obj->imp_index, (ut64)i, imp_idx++, NULL);
		}
		i += obj->symbols[i].n_numaux;
	}
}

static void populate_symbols(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	if (obj->sym_ht->count || !obj->symbols) {
		return;
	}
	populate_imports(obj);
	for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
		RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
		if (!ptr) {
			break;
		}
		if (_fill_bin_symbol(bf->rbin, obj, i, &ptr)) {
			ht_up_insert(obj->sym_ht, (ut64)i, ptr, NULL);
		} else {
			free(ptr);
		}
		i += obj->symbols[i].n_numaux;
	}
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	if (obj->symbols) {
		populate_symbols(bf);
		for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
			RzBinSymbol *ptr = ht_up_find(obj->sym_ht, i, NULL);
			if (ptr) {
				rz_pvector_push(ret, ptr);
			}
			i += obj->symbols[i].n_numaux;
		}
	}
	return ret;
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	int i;
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	if (obj->symbols) {
		populate_imports(obj);
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			RzBinImport *ptr = ht_up_find(obj->imp_ht, i, NULL);
			if (ptr) {
				rz_pvector_push(ret, ptr);
			}
			i += obj->symbols[i].n_numaux;
		}
	}
	return ret;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	populate_symbols(bf);
	return rz_coff_get_relocs(bf->o->bin_obj);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;

	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->rclass = strdup("coff");
	ret->bclass = strdup("coff");
	ret->type = strdup("COFF (Executable file)");
	ret->os = strdup("any");
	ret->subsystem = strdup("any");
	ret->big_endian = obj->endian;
	ret->has_va = true;
	ret->dbg_info = 0;

	if (rz_coff_is_stripped(obj)) {
		ret->dbg_info |= RZ_BIN_DBG_STRIPPED;
	} else {
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_RELFLG)) {
			ret->dbg_info |= RZ_BIN_DBG_RELOCS;
		}
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_LNNO)) {
			ret->dbg_info |= RZ_BIN_DBG_LINENUMS;
		}
		if (!(obj->hdr.f_flags & COFF_FLAGS_TI_F_EXEC)) {
			ret->dbg_info |= RZ_BIN_DBG_SYMS;
		}
	}

	switch (obj->hdr.f_magic) {
	case COFF_FILE_MACHINE_R4000:
	case COFF_FILE_MACHINE_MIPS16:
	case COFF_FILE_MACHINE_MIPSFPU:
	case COFF_FILE_MACHINE_MIPSFPU16:
		ret->machine = strdup("mips");
		ret->arch = strdup("mips");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_I386:
		ret->machine = strdup("i386");
		ret->arch = strdup("x86");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_AMD64:
		ret->machine = strdup("AMD64");
		ret->arch = strdup("x86");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_H8300:
		ret->machine = strdup("H8300");
		ret->arch = strdup("h8300");
		ret->bits = 16;
		break;
	case COFF_FILE_MACHINE_AMD29KBE:
	case COFF_FILE_MACHINE_AMD29KLE:
		ret->cpu = strdup("29000");
		ret->machine = strdup("amd29k");
		ret->arch = strdup("amd29k");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_THUMB:
		ret->machine = strdup("arm");
		ret->arch = strdup("arm");
		ret->bits = 16;
		break;
	case COFF_FILE_MACHINE_ARM:
	case COFF_FILE_MACHINE_ARMNT:
		ret->machine = strdup("arm");
		ret->arch = strdup("arm");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_ARM64:
		ret->machine = strdup("arm");
		ret->arch = strdup("arm");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_SH3:
	case COFF_FILE_MACHINE_SH3DSP:
	case COFF_FILE_MACHINE_SH4:
	case COFF_FILE_MACHINE_SH5:
		ret->machine = strdup("sh");
		ret->arch = strdup("sh");
		ret->bits = 32;
		break;
	case COFF_FILE_TI_COFF:
		switch (obj->target_id) {
		case COFF_FILE_MACHINE_TMS320C54:
			ret->machine = strdup("c54x");
			ret->arch = strdup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_MACHINE_TMS320C55:
			ret->machine = strdup("c55x");
			ret->arch = strdup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_MACHINE_TMS320C55PLUS:
			ret->machine = strdup("c55x+");
			ret->arch = strdup("tms320");
			ret->bits = 32;
			break;
		}
		break;
	default:
		ret->machine = strdup("unknown");
	}

	return ret;
}

static RzPVector /*<RzBinField *>*/ *fields(RzBinFile *bf) {
	return NULL;
}

static ut64 size(RzBinFile *bf) {
	return 0;
}

static bool check_buffer(RzBuffer *buf) {
#if 0
TODO: do more checks here to avoid false positives

ut16 MACHINE
ut16 NSECTIONS
ut32 DATE
ut32 PTRTOSYMTABLE
ut32 NUMOFSYMS
ut16 OPTHDRSIZE
ut16 CHARACTERISTICS
#endif

	ut8 tmp[20];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	return r >= 20 && rz_coff_supported_arch(tmp);
}

#define ADD_FLAG_MASK(x, m) \
	if ((flag & m) == COFF_SCN_##x) { \
		rz_list_append(flag_list, RZ_STR(x)); \
	}

#define ADD_FLAG(x) \
	if (flag & COFF_SCN_##x) { \
		rz_list_append(flag_list, RZ_STR(x)); \
	}

RzList /*<char *>*/ *coff_section_flag_to_rzlist(ut64 flag) {
	RzList *flag_list = rz_list_new();
	ADD_FLAG(TYPE_NO_PAD);
	ADD_FLAG(CNT_CODE);
	ADD_FLAG(CNT_INIT_DATA);
	ADD_FLAG(CNT_UNIN_DATA);
	ADD_FLAG(LNK_OTHER);
	ADD_FLAG(LNK_INFO);
	ADD_FLAG(LNK_REMOVE);
	ADD_FLAG(LNK_COMDAT);
	ADD_FLAG(GPREL);
	ADD_FLAG(MEM_PURGEABLE);
	ADD_FLAG(MEM_16BIT);
	ADD_FLAG(MEM_LOCKED);
	ADD_FLAG(MEM_PRELOAD);
	ADD_FLAG_MASK(ALIGN_1BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_2BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_4BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_8BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_16BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_32BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_64BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_128BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_256BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_512BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_1024BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_2048BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_4096BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG_MASK(ALIGN_8192BYTES, COFF_SCN_ALIGN_MASK);
	ADD_FLAG(LNK_NRELOC_OVFL);
	ADD_FLAG(MEM_DISCARDABLE);
	ADD_FLAG(MEM_NOT_CACHED);
	ADD_FLAG(MEM_NOT_PAGED);

	// special check for no read
	if (!(flag & COFF_SCN_MEM_READ)) {
		rz_list_append(flag_list, "MEM_NO_READ");
	}
	return flag_list;
}

#undef ADD_FLAG_MASK
#undef ADD_FLAG

RzBinPlugin rz_bin_plugin_coff = {
	.name = "coff",
	.desc = "COFF format rz_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.section_flag_to_rzlist = coff_section_flag_to_rzlist,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_coff,
	.version = RZ_VERSION
};
#endif
