// SPDX-FileCopyrightText: 2019-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2014-2019 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_util/ht_uu.h>

#include "coff/coff.h"

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

static void coff_populate_symbols(RzBinFile *bf);

static Sdb *coff_get_sdb(RzBinFile *bf) {
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

static bool coff_is_stripped(struct rz_bin_coff_obj *obj) {
	return !!(obj->hdr.f_flags & (COFF_FLAGS_TI_F_RELFLG | COFF_FLAGS_TI_F_LNNO | COFF_FLAGS_TI_F_LSYMS));
}

static bool coff_check_buffer(RzBuffer *buf) {
	return rz_coff_supported_arch(buf);
}

static bool coff_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	obj->bin_obj = rz_bin_coff_new_buf(buf);
	return obj->bin_obj != NULL;
}

static void coff_destroy(RzBinFile *bf) {
	rz_bin_coff_free((struct rz_bin_coff_obj *)bf->o->bin_obj);
}

#define DTYPE_IS_FUNCTION(type) (COFF_SYM_GET_DTYPE(type) == COFF_SYM_DTYPE_FUNCTION)

static bool is_imported_symbol(struct coff_symbol *s) {
	return s->n_scnum == COFF_SYM_SCNUM_UNDEF && s->n_sclass == COFF_SYM_CLASS_EXTERNAL;
}

static bool coff_fill_bin_symbol(RzBin *rbin, struct rz_bin_coff_obj *bin, size_t idx, RzBinSymbol **sym) {
	RzBinSymbol *ptr = *sym;
	struct coff_scn_hdr *sc_hdr = NULL;
	if (idx < 0 || idx > bin->hdr.f_nsyms) {
		return false;
	}
	if (!bin->symbols) {
		return false;
	}
	char tmpbuf[32];
	struct coff_symbol *s = rz_vector_index_ptr(bin->symbols, idx);
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
		sc_hdr = rz_vector_index_ptr(bin->scn_hdrs, s->n_scnum - 1);
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

static RzBinImport *coff_fill_bin_import(struct rz_bin_coff_obj *bin, size_t idx) {
	RzBinImport *ptr = RZ_NEW0(RzBinImport);
	if (!ptr || idx < 0 || idx > bin->hdr.f_nsyms) {
		free(ptr);
		return NULL;
	}
	struct coff_symbol *s = rz_vector_index_ptr(bin->symbols, idx);
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

static RzPVector /*<RzBinAddr *>*/ *coff_entries(RzBinFile *bf) {
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

static RzPVector /*<RzBinVirtualFile *>*/ *coff_virtual_files(RzBinFile *bf) {
	RzPVector *r = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!r) {
		return NULL;
	}
	RzBinObject *o = bf->o;
	struct rz_bin_coff_obj *obj = o ? o->bin_obj : NULL;
	if (!obj) {
		return r;
	}
	coff_populate_symbols(bf); // the patching depends on symbols to be available
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
		vf->name = rz_str_dup(VFILE_NAME_RELOC_TARGETS);
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
		vf->name = rz_str_dup(VFILE_NAME_PATCHED);
		rz_pvector_push(r, vf);
	}
	return r;
}

static ut32 coff_guess_perms_from_section_name(const char *section_name) {
	// this function should be called only if rz_coff_perms_from_section_flags
	// returns an 0 permission flag, which is unusual.
	if (RZ_STR_ISEMPTY(section_name)) {
		RZ_LOG_WARN("coff: found a no-named section with no permissions\n");
		return RZ_PERM_R;
	} else if (RZ_STR_EQ(section_name, ".text")) {
		return RZ_PERM_RX;
	} else if (RZ_STR_EQ(section_name, ".data")) {
		return RZ_PERM_RW;
	} else if (RZ_STR_EQ(section_name, ".bss")) {
		return RZ_PERM_RW;
	}
	RZ_LOG_INFO("coff: unhandled section '%s' with no permissions\n", section_name);
	return RZ_PERM_R;
}

static RzPVector /*<RzBinMap *>*/ *coff_maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	RzBinObject *o = bf->o;
	struct rz_bin_coff_obj *obj = o ? o->bin_obj : NULL;
	if (!obj || !obj->scn_hdrs) {
		return ret;
	}
	coff_populate_symbols(bf);

	size_t i = 0;
	CoffScnHdr *hdr;
	rz_vector_enumerate (obj->scn_hdrs, hdr, i) {
		RzBinMap *ptr = RZ_NEW0(RzBinMap);
		if (!ptr) {
			return ret;
		}
		ptr->name = rz_coff_symbol_name(obj, (const ut8 *)hdr->s_name);
		ptr->psize = hdr->s_size;
		ptr->vsize = hdr->s_size;
		ptr->paddr = hdr->s_scnptr;
		if (obj->scn_va) {
			ptr->vaddr = obj->scn_va[i];
		}
		ptr->perm = rz_coff_perms_from_section_flags(hdr->s_flags);
		if (!ptr->perm) {
			ptr->perm = coff_guess_perms_from_section_name(ptr->name);
		}
		if (hdr->s_nreloc) {
			ptr->vfile_name = rz_str_dup(VFILE_NAME_PATCHED);
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
		map->name = rz_str_dup("reloc-targets");
		map->paddr = 0;
		map->psize = rtmsz;
		map->vaddr = rz_coff_get_reloc_targets_map_base(obj);
		map->vsize = rtmsz;
		map->perm = RZ_PERM_R;
		map->vfile_name = rz_str_dup(VFILE_NAME_RELOC_TARGETS);
		rz_pvector_push_front(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *coff_sections(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	if (!obj || !obj->scn_hdrs) {
		return ret;
	}

	size_t i = 0;
	CoffScnHdr *scn_hdr;
	rz_vector_enumerate (obj->scn_hdrs, scn_hdr, i) {
		RzBinSection *ptr = RZ_NEW0(RzBinSection);
		if (!ptr) {
			return ret;
		}
		ptr->name = rz_coff_symbol_name(obj, (const ut8 *)scn_hdr->s_name);
		if (strstr(ptr->name, "data")) {
			ptr->is_data = true;
		}
		ptr->size = scn_hdr->s_size;
		ptr->vsize = scn_hdr->s_size;
		ptr->paddr = scn_hdr->s_scnptr;
		ptr->flags = scn_hdr->s_flags;
		if (obj->scn_va) {
			ptr->vaddr = obj->scn_va[i];
		}
		ptr->perm = rz_coff_perms_from_section_flags(ptr->flags);
		if (!ptr->perm) {
			ptr->perm = coff_guess_perms_from_section_name(ptr->name);
		}
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static void coff_populate_imports(struct rz_bin_coff_obj *obj) {
	if (ht_uu_size(obj->imp_index) || !obj->symbols) {
		return;
	}
	int ord = 0;
	ut64 imp_idx = 0;
	for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
		RzBinImport *ptr = coff_fill_bin_import(obj, i);
		if (ptr) {
			ptr->ordinal = ord++;
			ht_up_insert(obj->imp_ht, (ut64)i, ptr);
			ht_uu_insert(obj->imp_index, (ut64)i, imp_idx++);
		}
		struct coff_symbol *sym = rz_vector_index_ptr(obj->symbols, i);
		i += sym->n_numaux;
	}
}

static void coff_populate_symbols(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	if (ht_up_size(obj->sym_ht) || !obj->symbols) {
		return;
	}
	coff_populate_imports(obj);
	for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
		RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
		if (!ptr) {
			break;
		}
		if (coff_fill_bin_symbol(bf->rbin, obj, i, &ptr)) {
			ht_up_insert(obj->sym_ht, (ut64)i, ptr);
		} else {
			free(ptr);
		}

		struct coff_symbol *sym = rz_vector_index_ptr(obj->symbols, i);
		i += sym->n_numaux;
	}
}

static RzPVector /*<RzBinSymbol *>*/ *coff_symbols(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	if (obj->symbols) {
		coff_populate_symbols(bf);
		for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
			RzBinSymbol *ptr = ht_up_find(obj->sym_ht, i, NULL);
			if (ptr) {
				rz_pvector_push(ret, ptr);
			}
			struct coff_symbol *sym = rz_vector_index_ptr(obj->symbols, i);
			i += sym->n_numaux;
		}
	}
	return ret;
}

static RzPVector /*<RzBinImport *>*/ *coff_imports(RzBinFile *bf) {
	int i;
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	if (obj->symbols) {
		coff_populate_imports(obj);
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			RzBinImport *ptr = ht_up_find(obj->imp_ht, i, NULL);
			if (ptr) {
				rz_pvector_push(ret, ptr);
			}

			struct coff_symbol *sym = rz_vector_index_ptr(obj->symbols, i);
			i += sym->n_numaux;
		}
	}
	return ret;
}

static RzPVector /*<RzBinReloc *>*/ *coff_relocs(RzBinFile *bf) {
	coff_populate_symbols(bf);
	return rz_coff_get_relocs(bf->o->bin_obj);
}

static RzBinInfo *coff_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;

	ret->file = rz_str_dup(bf->file);
	ret->rclass = rz_str_dup("coff");
	ret->bclass = rz_str_dup("coff");
	ret->type = rz_str_dup("COFF (Executable file)");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("any");
	ret->big_endian = obj->big_endian;
	ret->has_va = true;
	ret->dbg_info = 0;

	if (coff_is_stripped(obj)) {
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
	case COFF_FILE_MACHINE_ALPHA:
		ret->machine = rz_str_dup("alpha");
		ret->cpu = rz_str_dup("alpha");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_ALPHA64:
		ret->machine = rz_str_dup("alpha");
		ret->cpu = rz_str_dup("alpha");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_AM33:
		ret->machine = rz_str_dup("am33");
		ret->cpu = rz_str_dup("am33");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_AMD64:
		ret->machine = rz_str_dup("amd64");
		ret->arch = rz_str_dup("x86");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_ARM:
		ret->machine = rz_str_dup("arm");
		ret->arch = rz_str_dup("arm");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_THUMB:
		ret->machine = rz_str_dup("arm");
		ret->arch = rz_str_dup("arm");
		ret->bits = 16;
		break;
	case COFF_FILE_MACHINE_ARMNT:
		ret->machine = rz_str_dup("arm");
		ret->arch = rz_str_dup("arm");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_ARM64:
		ret->machine = rz_str_dup("arm");
		ret->arch = rz_str_dup("arm");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_EBC:
		ret->machine = rz_str_dup("ebc");
		ret->arch = rz_str_dup("ebc");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_I386:
		/* fall-thru */
	case COFF_FILE_MACHINE_I386_PTX:
		/* fall-thru */
	case COFF_FILE_MACHINE_I386_AIX:
		ret->machine = rz_str_dup("i386");
		ret->arch = rz_str_dup("x86");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_IA64:
		ret->machine = rz_str_dup("ia64");
		ret->arch = rz_str_dup("x86");
		ret->bits = 64;
		break;
	case COFF_FILE_MACHINE_M32R:
		ret->machine = rz_str_dup("m32r");
		ret->arch = rz_str_dup("m32r");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_MIPS16:
		/* fall-thru */
	case COFF_FILE_MACHINE_MIPSFPU16:
		ret->machine = rz_str_dup("mips");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips16");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_MIPSFPU:
		/* fall-thru */
	case COFF_FILE_MACHINE_WCEMIPSV2:
		ret->machine = rz_str_dup("mips");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips32");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_AMD29KBE:
		/* fall-thru */
	case COFF_FILE_MACHINE_AMD29KLE:
		ret->cpu = rz_str_dup("29000");
		ret->machine = rz_str_dup("amd29k");
		ret->arch = rz_str_dup("amd29k");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_POWERPC:
		/* fall-thru */
	case COFF_FILE_MACHINE_POWERPCFP:
		ret->machine = rz_str_dup("ppc");
		ret->arch = rz_str_dup("ppc");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_SH3:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH3DSP:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH4:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH5:
		ret->machine = rz_str_dup("sh");
		ret->arch = rz_str_dup("sh");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_H8300:
		ret->machine = rz_str_dup("H8300");
		ret->arch = rz_str_dup("h8300");
		ret->bits = 16;
		break;
	case COFF_FILE_MACHINE_H8500:
		ret->machine = rz_str_dup("H8500");
		ret->arch = rz_str_dup("h8500");
		ret->bits = 16;
		break;
	case COFF_FILE_MACHINE_M68K:
		/* fall-thru */
	case COFF_FILE_MACHINE_68KAUX:
		ret->machine = rz_str_dup("m68k");
		ret->arch = rz_str_dup("m68k");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_PIC30:
		ret->machine = rz_str_dup("pic30");
		ret->arch = rz_str_dup("pic");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_I960RO:
		/* fall-thru */
	case COFF_FILE_MACHINE_I960RW:
		ret->machine = rz_str_dup("i960");
		ret->arch = rz_str_dup("x86");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_R3000:
		ret->machine = rz_str_dup("MIPS R3000");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("r3000");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_R4000:
		ret->machine = rz_str_dup("MIPS R4000");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("r4000");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_R10000:
		ret->machine = rz_str_dup("MIPS R10000");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("r10000");
		ret->bits = 32;
		break;
	case COFF_FILE_MACHINE_TI_1:
		/* fall-thru */
	case COFF_FILE_MACHINE_TI_2:
		switch (obj->target_id) {
		case COFF_FILE_TARGET_TI_TMS320C3x4x:
			ret->machine = rz_str_dup("TMS320C3x/4x");
			ret->cpu = rz_str_dup("c54x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_TMS470:
			ret->machine = rz_str_dup("TMS470");
			ret->cpu = rz_str_dup("c54x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_TMS320C5400:
			ret->machine = rz_str_dup("TMS320C5400");
			ret->cpu = rz_str_dup("c54x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_TMS320C6000:
			ret->machine = rz_str_dup("TMS320C6000");
			ret->cpu = rz_str_dup("c55x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_TMS320C5500:
			ret->machine = rz_str_dup("TMS320C5500");
			ret->cpu = rz_str_dup("c55x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_TMS320C2800:
			ret->machine = rz_str_dup("TMS320C2800");
			ret->cpu = rz_str_dup("c54x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_MSP430:
			ret->machine = rz_str_dup("TMS320C2800");
			ret->cpu = rz_str_dup("c54x");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		case COFF_FILE_TARGET_TI_TMS320C5500_PLUS:
			ret->machine = rz_str_dup("TMS320C5500+");
			ret->cpu = rz_str_dup("c55x+");
			ret->arch = rz_str_dup("tms320");
			ret->bits = 32;
			break;
		default:
			ret->machine = rz_str_newf("unknown TI 0x%08x", obj->target_id);
			break;
		}
		break;
	default:
		ret->machine = rz_str_newf("unknown 0x%08x", obj->hdr.f_magic);
		break;
	}

	return ret;
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
	.desc = "COFF (Common Object File Format)",
	.license = "LGPL3",
	.author = "Fedor Sakharov",
	.get_sdb = &coff_get_sdb,
	.load_buffer = &coff_load_buffer,
	.destroy = &coff_destroy,
	.check_buffer = &coff_check_buffer,
	.entries = &coff_entries,
	.virtual_files = &coff_virtual_files,
	.maps = &coff_maps,
	.sections = &coff_sections,
	.symbols = &coff_symbols,
	.imports = &coff_imports,
	.info = &coff_info,
	.relocs = &coff_relocs,
	.section_flag_to_rzlist = coff_section_flag_to_rzlist,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_coff,
	.version = RZ_VERSION
};
#endif
