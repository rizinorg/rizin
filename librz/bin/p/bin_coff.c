// SPDX-FileCopyrightText: 2014-2019 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <ht_uu.h>

#include "coff/coff.h"

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

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	*bin_obj = rz_bin_coff_new_buf(buf, bf->rbin->verbose);
	return *bin_obj != NULL;
}

static void destroy(RzBinFile *bf) {
	rz_bin_coff_free((struct rz_bin_coff_obj *)bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzBinAddr *binsym(RzBinFile *bf, int sym) {
	return NULL;
}

#define DTYPE_IS_FUNCTION(type) (COFF_SYM_GET_DTYPE(type) == COFF_SYM_DTYPE_FUNCTION)

static bool _fill_bin_symbol(RzBin *rbin, struct rz_bin_coff_obj *bin, int idx, RzBinSymbol **sym) {
	RzBinSymbol *ptr = *sym;
	struct coff_symbol *s = NULL;
	struct coff_scn_hdr *sc_hdr = NULL;
	if (idx < 0 || idx > bin->hdr.f_nsyms) {
		return false;
	}
	if (!bin->symbols) {
		return false;
	}
	s = &bin->symbols[idx];
	char *coffname = rz_coff_symbol_name(bin, s);
	if (!coffname) {
		return false;
	}
	ptr->size = 4;
	ptr->ordinal = 0;
	ptr->name = coffname;
	ptr->forwarder = "NONE";
	ptr->bind = RZ_BIN_BIND_LOCAL_STR;
	ptr->is_imported = false;
	if (s->n_scnum < bin->hdr.f_nscns + 1 && s->n_scnum > 0) {
		//first index is 0 that is why -1
		sc_hdr = &bin->scn_hdrs[s->n_scnum - 1];
		ptr->paddr = sc_hdr->s_scnptr + s->n_value;
		if (bin->scn_va) {
			ptr->vaddr = bin->scn_va[s->n_scnum - 1] + s->n_value;
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
			ptr->is_imported = true;
			ptr->paddr = ptr->vaddr = UT64_MAX;
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
			ptr->paddr = ptr->vaddr = UT64_MAX;
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
		ptr->type = rz_str_constpool_get(&rbin->constpool, sdb_fmt("%i", s->n_sclass));
		break;
	}
	return true;
}

static bool is_imported_symbol(struct coff_symbol *s) {
	return s->n_scnum == COFF_SYM_SCNUM_UNDEF && s->n_sclass == COFF_SYM_CLASS_EXTERNAL;
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
	char *coffname = rz_coff_symbol_name(bin, s);
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

static RzList *entries(RzBinFile *bf) {
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzList *ret;
	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}
	RzBinAddr *ptr = rz_coff_get_entry(obj);
	if (ptr) {
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	char *tmp = NULL;
	size_t i;
	RzBinSection *ptr = NULL;
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;

	RzList *ret = rz_list_newf((RzListFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	if (obj && obj->scn_hdrs) {
		for (i = 0; i < obj->hdr.f_nscns; i++) {
			tmp = rz_coff_symbol_name(obj, &obj->scn_hdrs[i]);
			if (!tmp) {
				rz_list_free(ret);
				return NULL;
			}
			//IO does not like sections with the same name append idx
			//since it will update it
			ptr = RZ_NEW0(RzBinSection);
			if (!ptr) {
				free(tmp);
				return ret;
			}
			ptr->name = rz_str_newf("%s-%zu", tmp, i);
			free(tmp);
			if (strstr(ptr->name, "data")) {
				ptr->is_data = true;
			}
			ptr->size = obj->scn_hdrs[i].s_size;
			ptr->vsize = obj->scn_hdrs[i].s_size;
			ptr->paddr = obj->scn_hdrs[i].s_scnptr;
			if (obj->scn_va) {
				ptr->vaddr = obj->scn_va[i];
			}
			ptr->add = true;
			ptr->perm = 0;
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_READ) {
				ptr->perm |= RZ_PERM_R;
			}
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_WRITE) {
				ptr->perm |= RZ_PERM_W;
			}
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_EXECUTE) {
				ptr->perm |= RZ_PERM_X;
			}
			rz_list_append(ret, ptr);
		}
	}
	return ret;
}

static RzList *symbols(RzBinFile *bf) {
	int i;
	RzBinSymbol *ptr = NULL;
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzList *ret = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	if (obj->symbols) {
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if (!(ptr = RZ_NEW0(RzBinSymbol))) {
				break;
			}
			if (_fill_bin_symbol(bf->rbin, obj, i, &ptr)) {
				rz_list_append(ret, ptr);
				ht_up_insert(obj->sym_ht, (ut64)i, ptr);
			} else {
				free(ptr);
			}
			i += obj->symbols[i].n_numaux;
		}
	}
	return ret;
}

static RzList *imports(RzBinFile *bf) {
	int i;
	struct rz_bin_coff_obj *obj = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	RzList *ret = rz_list_newf((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	if (obj->symbols) {
		int ord = 0;
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			RzBinImport *ptr = _fill_bin_import(obj, i);
			if (ptr) {
				ptr->ordinal = ord++;
				rz_list_append(ret, ptr);
				ht_up_insert(obj->imp_ht, (ut64)i, ptr);
			}
			i += obj->symbols[i].n_numaux;
		}
	}
	return ret;
}

static RzList *libs(RzBinFile *bf) {
	return NULL;
}

static ut32 _read_le32(RzBin *rbin, ut64 addr) {
	ut8 data[4] = { 0 };
	if (!rbin->iob.read_at(rbin->iob.io, addr, data, sizeof(data))) {
		return UT32_MAX;
	}
	return rz_read_le32(data);
}

static ut16 _read_le16(RzBin *rbin, ut64 addr) {
	ut8 data[2] = { 0 };
	if (!rbin->iob.read_at(rbin->iob.io, addr, data, sizeof(data))) {
		return UT16_MAX;
	}
	return rz_read_le16(data);
}

#define BYTES_PER_IMP_RELOC 8

static RzList *_relocs_list(RzBin *rbin, struct rz_bin_coff_obj *bin, bool patch, ut64 imp_map) {
	rz_return_val_if_fail(bin && bin->scn_hdrs, NULL);

	RzBinReloc *reloc;
	struct coff_reloc *rel;
	int j, i = 0;
	RzList *list_rel = rz_list_newf(free);
	if (!list_rel) {
		return NULL;
	}
	const bool patch_imports = patch && (imp_map != UT64_MAX);
	HtUU *imp_vaddr_ht = patch_imports ? ht_uu_new0() : NULL;
	if (patch_imports && !imp_vaddr_ht) {
		rz_list_free(list_rel);
		return NULL;
	}
	for (i = 0; i < bin->hdr.f_nscns; i++) {
		if (!bin->scn_hdrs[i].s_nreloc) {
			continue;
		}
		int len = 0, size = bin->scn_hdrs[i].s_nreloc * sizeof(struct coff_reloc);
		if (size < 0) {
			break;
		}
		rel = calloc(1, size + sizeof(struct coff_reloc));
		if (!rel) {
			break;
		}
		if (bin->scn_hdrs[i].s_relptr > bin->size ||
			bin->scn_hdrs[i].s_relptr + size > bin->size) {
			free(rel);
			break;
		}
		len = rz_buf_read_at(bin->b, bin->scn_hdrs[i].s_relptr, (ut8 *)rel, size);
		if (len != size) {
			free(rel);
			break;
		}
		for (j = 0; j < bin->scn_hdrs[i].s_nreloc; j++) {
			RzBinSymbol *symbol = (RzBinSymbol *)ht_up_find(bin->sym_ht, (ut64)rel[j].rz_symndx, NULL);
			if (!symbol) {
				continue;
			}
			reloc = RZ_NEW0(RzBinReloc);
			if (!reloc) {
				continue;
			}

			reloc->symbol = symbol;
			reloc->paddr = bin->scn_hdrs[i].s_scnptr + rel[j].rz_vaddr;
			if (bin->scn_va) {
				reloc->vaddr = bin->scn_va[i] + rel[j].rz_vaddr;
			}
			reloc->type = rel[j].rz_type;

			ut64 sym_vaddr = symbol->vaddr;
			if (symbol->is_imported) {
				reloc->import = (RzBinImport *)ht_up_find(bin->imp_ht, (ut64)rel[j].rz_symndx, NULL);
				if (patch_imports) {
					bool found;
					sym_vaddr = ht_uu_find(imp_vaddr_ht, (ut64)rel[j].rz_symndx, &found);
					if (!found) {
						sym_vaddr = imp_map;
						imp_map += BYTES_PER_IMP_RELOC;
						ht_uu_insert(imp_vaddr_ht, (ut64)rel[j].rz_symndx, sym_vaddr);
						symbol->vaddr = sym_vaddr;
					}
				}
			}

			if (sym_vaddr) {
				int plen = 0;
				ut8 patch_buf[8];
				switch (bin->hdr.f_magic) {
				case COFF_FILE_MACHINE_I386:
					switch (rel[j].rz_type) {
					case COFF_REL_I386_DIR32:
						reloc->type = RZ_BIN_RELOC_32;
						rz_write_le32(patch_buf, (ut32)sym_vaddr);
						plen = 4;
						break;
					case COFF_REL_I386_REL32:
						reloc->type = RZ_BIN_RELOC_32;
						reloc->additive = 1;
						ut64 data = _read_le32(rbin, reloc->vaddr);
						if (data == UT32_MAX) {
							break;
						}
						reloc->addend = data;
						data += sym_vaddr - reloc->vaddr - 4;
						rz_write_le32(patch_buf, (st32)data);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_AMD64:
					switch (rel[j].rz_type) {
					case COFF_REL_AMD64_REL32:
						reloc->type = RZ_BIN_RELOC_32;
						reloc->additive = 1;
						ut64 data = _read_le32(rbin, reloc->vaddr);
						if (data == UT32_MAX) {
							break;
						}
						reloc->addend = data;
						data += sym_vaddr - reloc->vaddr - 4;
						rz_write_le32(patch_buf, (st32)data);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_ARMNT:
					switch (rel[j].rz_type) {
					case COFF_REL_ARM_BRANCH24T:
					case COFF_REL_ARM_BLX23T:
						reloc->type = RZ_BIN_RELOC_32;
						ut16 hiword = _read_le16(rbin, reloc->vaddr);
						if (hiword == UT16_MAX) {
							break;
						}
						ut16 loword = _read_le16(rbin, reloc->vaddr + 2);
						if (loword == UT16_MAX) {
							break;
						}
						ut64 dst = sym_vaddr - reloc->vaddr - 4;
						if (dst & 1) {
							break;
						}
						loword |= (ut16)(dst >> 1) & 0x7ff;
						hiword |= (ut16)(dst >> 12) & 0x7ff;
						rz_write_le16(patch_buf, hiword);
						rz_write_le16(patch_buf + 2, loword);
						plen = 4;
						break;
					}
					break;
				case COFF_FILE_MACHINE_ARM64:
					switch (rel[j].rz_type) {
					case COFF_REL_ARM64_BRANCH26:
						reloc->type = RZ_BIN_RELOC_32;
						ut32 data = _read_le32(rbin, reloc->vaddr);
						if (data == UT32_MAX) {
							break;
						}
						ut64 dst = sym_vaddr - reloc->vaddr;
						data |= (ut32)((dst >> 2) & 0x3ffffffULL);
						rz_write_le32(patch_buf, data);
						plen = 4;
						break;
					}
					break;
				}
				if (patch && plen) {
					rbin->iob.write_at(rbin->iob.io, reloc->vaddr, patch_buf, plen);
					if (symbol->is_imported) {
						reloc->vaddr = sym_vaddr;
					}
				}
			}
			rz_list_append(list_rel, reloc);
		}
		free(rel);
	}
	ht_uu_free(imp_vaddr_ht);
	return list_rel;
}

static RzList *relocs(RzBinFile *bf) {
	struct rz_bin_coff_obj *bin = (struct rz_bin_coff_obj *)bf->o->bin_obj;
	return _relocs_list(bf->rbin, bin, false, UT64_MAX);
}

static RzList *patch_relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBin *b = bf->rbin;
	RzBinObject *bo = bf->o;
	RzIO *io = b->iob.io;
	if (!bo || !bo->bin_obj) {
		return NULL;
	}
	struct rz_bin_coff_obj *bin = (struct rz_bin_coff_obj *)bo->bin_obj;
	if (bin->hdr.f_flags & COFF_FLAGS_TI_F_EXEC) {
		return NULL;
	}
	if (!(io->cached & RZ_PERM_W)) {
		eprintf(
			"Warning: please run rizin with -e io.cache=true to patch "
			"relocations\n");
		return NULL;
	}

	size_t nimports = 0;
	int i;
	for (i = 0; i < bin->hdr.f_nsyms; i++) {
		if (is_imported_symbol(&bin->symbols[i])) {
			nimports++;
		}
		i += bin->symbols[i].n_numaux;
	}
	ut64 m_vaddr = UT64_MAX;
	if (nimports) {
		void **it;
		ut64 offset = 0;
		rz_pvector_foreach (&io->maps, it) {
			RzIOMap *map = *it;
			if ((map->itv.addr + map->itv.size) > offset) {
				offset = map->itv.addr + map->itv.size;
			}
		}
		m_vaddr = RZ_ROUND(offset, 16);
		ut64 size = nimports * BYTES_PER_IMP_RELOC;
		char *muri = rz_str_newf("malloc://%" PFMT64u, size);
		RzIODesc *desc = b->iob.open_at(io, muri, RZ_PERM_R, 0664, m_vaddr);
		free(muri);
		if (!desc) {
			return NULL;
		}

		RzIOMap *map = b->iob.map_get(io, m_vaddr);
		if (!map) {
			return NULL;
		}
		map->name = strdup(".imports.rz");
	}

	return _relocs_list(b, bin, true, m_vaddr);
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
	ret->has_lit = true;

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

static RzList *fields(RzBinFile *bf) {
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
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_coff,
	.version = RZ_VERSION
};
#endif
