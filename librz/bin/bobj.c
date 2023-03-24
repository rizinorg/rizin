// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_util.h>
#include "i/private.h"

/**
 * \brief  Tries to decode the base64 string hold by RzBinString and overwrites it
 *
 * \param  bstr  The RzBinString to decode
 */
RZ_API void rz_bin_string_decode_base64(RZ_NONNULL RzBinString *bstr) {
	rz_return_if_fail(bstr);

	char *decoded = bstr->string;
	do {
		// ensure to decode base64 strings encoded multiple times.
		char *tmp = (char *)rz_base64_decode_dyn(decoded, -1);
		if (!tmp || !rz_str_is_printable(tmp)) {
			free(tmp);
			break;
		}
		free(decoded);
		decoded = tmp;
	} while (1);

	if (decoded == bstr->string) {
		return;
	}
	free(bstr->string);
	bstr->string = decoded;
	bstr->length = strlen(decoded);
	bstr->type = RZ_STRING_ENC_BASE64;
}

static void bin_object_decode_all_base64_strings(RzList /*<RzBinString *>*/ *strings) {
	rz_return_if_fail(strings);

	RzBinString *bstr;
	RzListIter *iter;
	rz_list_foreach (strings, iter, bstr) {
		rz_bin_string_decode_base64(bstr);
	}
}

RZ_API void rz_bin_mem_free(void *data) {
	RzBinMem *mem = (RzBinMem *)data;
	if (mem && mem->mirrors) {
		mem->mirrors->free = rz_bin_mem_free;
		rz_list_free(mem->mirrors);
		mem->mirrors = NULL;
	}
	free(mem);
}

/// size of the reloc (where it is supposed to be patched) in bits
RZ_API ut64 rz_bin_reloc_size(RzBinReloc *reloc) {
	switch (reloc->type) {
	case RZ_BIN_RELOC_8:
		return 8;
	case RZ_BIN_RELOC_16:
		return 16;
	case RZ_BIN_RELOC_24:
		return 24;
	case RZ_BIN_RELOC_32:
		return 32;
	case RZ_BIN_RELOC_64:
		return 64;
	}
	return 0;
}

#define CMP_CHECK(member) \
	do { \
		if (ar->member != br->member) { \
			return RZ_NUM_CMP(ar->member, br->member); \
		} \
	} while (0);

static int reloc_cmp(const void *a, const void *b) {
	const RzBinReloc *ar = a;
	const RzBinReloc *br = b;
	CMP_CHECK(vaddr);
	CMP_CHECK(paddr);
	CMP_CHECK(type);
	CMP_CHECK(target_vaddr);
	return 0;
}

static int reloc_target_cmp(const void *a, const void *b) {
	const RzBinReloc *ar = a;
	const RzBinReloc *br = b;
	CMP_CHECK(target_vaddr);
	CMP_CHECK(vaddr);
	CMP_CHECK(paddr);
	CMP_CHECK(type);
	return 0;
}

#undef CMP_CHECK

RZ_API RzBinRelocStorage *rz_bin_reloc_storage_new(RZ_OWN RzList /*<RzBinReloc *>*/ *relocs) {
	RzBinRelocStorage *ret = RZ_NEW0(RzBinRelocStorage);
	if (!ret) {
		return NULL;
	}
	RzPVector sorter;
	rz_pvector_init(&sorter, NULL);
	rz_pvector_reserve(&sorter, rz_list_length(relocs));
	RzPVector target_sorter;
	rz_pvector_init(&target_sorter, NULL);
	rz_pvector_reserve(&target_sorter, rz_list_length(relocs));
	RzListIter *it;
	RzBinReloc *reloc;
	rz_list_foreach (relocs, it, reloc) {
		rz_pvector_push(&sorter, reloc);
		if (rz_bin_reloc_has_target(reloc)) {
			rz_pvector_push(&target_sorter, reloc);
		}
	}
	relocs->free = NULL; // ownership of relocs transferred
	rz_list_free(relocs);
	rz_pvector_sort(&sorter, reloc_cmp);
	ret->relocs_count = rz_pvector_len(&sorter);
	ret->relocs = (RzBinReloc **)rz_pvector_flush(&sorter);
	rz_pvector_fini(&sorter);
	rz_pvector_sort(&target_sorter, reloc_target_cmp);
	ret->target_relocs_count = rz_pvector_len(&target_sorter);
	ret->target_relocs = (RzBinReloc **)rz_pvector_flush(&target_sorter);
	rz_pvector_fini(&target_sorter);
	return ret;
}

RZ_API void rz_bin_reloc_storage_free(RzBinRelocStorage *storage) {
	if (!storage) {
		return;
	}
	for (size_t i = 0; i < storage->relocs_count; i++) {
		rz_bin_reloc_free(storage->relocs[i]);
	}
	free(storage->relocs);
	free(storage->target_relocs);
	free(storage);
}

static int reloc_vaddr_cmp(ut64 ref, RzBinReloc *reloc) {
	return RZ_NUM_CMP(ref, reloc->vaddr);
}

/// Get the reloc with the lowest vaddr that starts inside the given interval
RZ_API RzBinReloc *rz_bin_reloc_storage_get_reloc_in(RzBinRelocStorage *storage, ut64 vaddr, ut64 size) {
	rz_return_val_if_fail(storage && size >= 1, NULL);
	if (!storage->relocs) {
		return NULL;
	}
	size_t i;
	rz_array_lower_bound(storage->relocs, storage->relocs_count, vaddr, i, reloc_vaddr_cmp);
	if (i >= storage->relocs_count) {
		return NULL;
	}
	RzBinReloc *r = storage->relocs[i];
	return r->vaddr >= vaddr && r->vaddr < vaddr + size ? r : NULL;
}

static int reloc_target_vaddr_cmp(ut64 ref, RzBinReloc *reloc) {
	return RZ_NUM_CMP(ref, reloc->target_vaddr);
}

/// Get a reloc that points exactly to vaddr or NULL
RZ_API RzBinReloc *rz_bin_reloc_storage_get_reloc_to(RzBinRelocStorage *storage, ut64 vaddr) {
	rz_return_val_if_fail(storage, NULL);
	if (!storage->target_relocs) {
		return NULL;
	}
	size_t i;
	rz_array_upper_bound(storage->target_relocs, storage->target_relocs_count, vaddr, i, reloc_target_vaddr_cmp);
	if (!i) {
		return NULL;
	}
	i--;
	RzBinReloc *r = storage->target_relocs[i];
	return r->target_vaddr == vaddr ? r : NULL;
}

RZ_IPI void rz_bin_object_free(RzBinObject *o) {
	if (!o) {
		return;
	}
	free(o->regstate);
	rz_bin_info_free(o->info);
	ht_up_free(o->addrzklassmethod);
	rz_list_free(o->entries);
	rz_list_free(o->maps);
	rz_list_free(o->vfiles);
	rz_list_free(o->fields);
	rz_list_free(o->imports);
	rz_list_free(o->libs);
	rz_bin_reloc_storage_free(o->relocs);
	rz_list_free(o->sections);
	rz_bin_string_database_free(o->strings);
	ht_pp_free(o->import_name_symbols);
	rz_list_free(o->symbols);
	rz_list_free(o->classes);
	ht_pp_free(o->classes_ht);
	ht_pp_free(o->methods_ht);
	rz_bin_source_line_info_free(o->lines);
	rz_list_free(o->mem);
	for (ut32 i = 0; i < RZ_BIN_SPECIAL_SYMBOL_LAST; i++) {
		free(o->binsym[i]);
	}
	free(o);
}

static char *swiftField(const char *dn, const char *cn) {
	if (!dn || !cn) {
		return NULL;
	}

	char *p = strstr(dn, ".getter_");
	if (!p) {
		p = strstr(dn, ".setter_");
		if (!p) {
			p = strstr(dn, ".method_");
		}
	}
	if (p) {
		char *q = strstr(dn, cn);
		if (q && q[strlen(cn)] == '.') {
			q = strdup(q + strlen(cn) + 1);
			char *r = strchr(q, '.');
			if (r) {
				*r = 0;
			}
			return q;
		}
	}
	return NULL;
}

static RzList /*<RzBinClass *>*/ *classes_from_symbols(RzBinFile *bf) {
	RzBinSymbol *sym;
	RzListIter *iter;
	rz_list_foreach (bf->o->symbols, iter, sym) {
		if (!sym->name || sym->name[0] != '_') {
			continue;
		}
		const char *cn = sym->classname;
		if (cn) {
			RzBinClass *c = rz_bin_file_add_class(bf, sym->classname, NULL, 0);
			if (!c) {
				continue;
			}
			// swift specific
			char *dn = sym->dname;
			char *fn = swiftField(dn, cn);
			if (fn) {
				RzBinField *f = rz_bin_field_new(sym->paddr, sym->vaddr, sym->size, fn, NULL, NULL, false);
				rz_list_append(c->fields, f);
				free(fn);
			} else {
				char *mn = strstr(dn, "..");
				if (!mn) {
					mn = strstr(dn, cn);
					if (mn && mn[strlen(cn)] == '.') {
						rz_list_append(c->methods, sym);
					}
				}
			}
		}
	}
	return bf->o->classes;
}

// TODO: kill offset and sz, because those should be inferred from binfile->buf
RZ_IPI RzBinObject *rz_bin_object_new(RzBinFile *bf, RzBinPlugin *plugin, RzBinObjectLoadOptions *opts, ut64 offset, ut64 sz) {
	rz_return_val_if_fail(bf && plugin, NULL);
	ut64 bytes_sz = rz_buf_size(bf->buf);
	RzBinObject *o = RZ_NEW0(RzBinObject);
	if (!o) {
		return NULL;
	}
	o->opts = *opts;
	if (o->opts.loadaddr == UT64_MAX) {
		// no loadaddr means 0 loadaddr
		o->opts.loadaddr = 0;
	}
	o->obj_size = (bytes_sz >= sz + offset) ? sz : 0;
	o->boffset = offset;
	o->regstate = NULL;
	o->classes = rz_list_newf((RzListFree)rz_bin_class_free);
	o->classes_ht = ht_pp_new0();
	o->methods_ht = ht_pp_new0();
	o->baddr_shift = 0;
	o->plugin = plugin;

	if (plugin && plugin->load_buffer) {
		if (!plugin->load_buffer(bf, o, bf->buf, bf->sdb)) {
			if (bf->rbin->verbose) {
				RZ_LOG_ERROR("rz_bin_object_new: load_buffer failed for %s plugin\n", plugin->name);
			}
			rz_bin_object_free(o);
			return NULL;
		}
	} else {
		RZ_LOG_WARN("Plugin %s should implement load_buffer method.\n", plugin->name);
		rz_bin_object_free(o);
		return NULL;
	}

	// XXX - object size can't be set here and needs to be set where where
	// the object is created from. The reason for this is to prevent
	// mis-reporting when the file is loaded from impartial bytes or is
	// extracted from a set of bytes in the file
	rz_bin_file_set_obj(bf->rbin, bf, o);
	rz_bin_set_baddr(bf->rbin, o->opts.baseaddr);
	rz_bin_object_set_items(bf, o);

	if (!bf->rbin->sdb) {
		return o;
	}

	sdb_ns_set(bf->sdb, "info", o->kv);
	sdb_ns_set(bf->rbin->sdb, "cur", bf->sdb);
	char *fdns = rz_str_newf("fd.%d", bf->fd);
	if (fdns) {
		sdb_ns_set(bf->rbin->sdb, fdns, bf->sdb);
		free(fdns);
	}
	bf->sdb->refs++;

	return o;
}

static void filter_classes(RzBinFile *bf, RzList /*<RzBinClass *>*/ *list) {
	HtPU *db = ht_pu_new0();
	HtPP *ht = ht_pp_new0();
	RzListIter *iter, *iter2;
	RzBinClass *cls;
	RzBinSymbol *sym;
	rz_list_foreach (list, iter, cls) {
		if (!cls->name) {
			continue;
		}
		int namepad_len = strlen(cls->name) + 32;
		char *namepad = malloc(namepad_len + 1);
		if (!namepad) {
			RZ_LOG_ERROR("Cannot allocate %d byte(s)\n", namepad_len);
			break;
		}

		strcpy(namepad, cls->name);
		char *p = rz_bin_filter_name(bf, db, cls->index, namepad);
		if (p) {
			namepad = p;
		}
		free(cls->name);
		cls->name = namepad;
		rz_list_foreach (cls->methods, iter2, sym) {
			if (sym->name) {
				rz_bin_filter_sym(bf, ht, sym->vaddr, sym);
			}
		}
	}
	ht_pu_free(db);
	ht_pp_free(ht);
}

static void rz_bin_object_rebuild_classes_ht(RzBinObject *o) {
	ht_pp_free(o->classes_ht);
	ht_pp_free(o->methods_ht);
	o->classes_ht = ht_pp_new0();
	o->methods_ht = ht_pp_new0();

	RzListIter *it, *it2;
	RzBinClass *klass;
	RzBinSymbol *method;
	rz_list_foreach (o->classes, it, klass) {
		if (klass->name) {
			ht_pp_insert(o->classes_ht, klass->name, klass);

			rz_list_foreach (klass->methods, it2, method) {
				const char *name = sdb_fmt("%s::%s", klass->name, method->name);
				ht_pp_insert(o->methods_ht, name, method);
			}
		}
	}
}

RZ_API int rz_bin_object_set_items(RzBinFile *bf, RzBinObject *o) {
	rz_return_val_if_fail(bf && o && o->plugin, false);

	RzBin *bin = bf->rbin;
	RzBinPlugin *p = o->plugin;
	int minlen = (bf->rbin->minstrlen > 0) ? bf->rbin->minstrlen : p->minstrlen;
	bf->o = o;

	if (p->file_type) {
		int type = p->file_type(bf);
		if (type == RZ_BIN_TYPE_CORE) {
			if (p->regstate) {
				o->regstate = p->regstate(bf);
			}
		}
	}

	if (p->boffset) {
		o->boffset = p->boffset(bf);
	}
	// XXX: no way to get info from xtr pluginz?
	// Note, object size can not be set from here due to potential
	// inconsistencies
	if (p->size) {
		o->size = p->size(bf);
	}
	// XXX this is expensive because is O(n^n)
	if (p->binsym) {
		for (size_t i = 0; i < RZ_BIN_SPECIAL_SYMBOL_LAST; i++) {
			o->binsym[i] = p->binsym(bf, i);
			if (o->binsym[i]) {
				o->binsym[i]->paddr += o->opts.loadaddr;
			}
		}
	}
	if (p->entries) {
		o->entries = p->entries(bf);
		REBASE_PADDR(o, o->entries, RzBinAddr);
	}
	if (p->virtual_files) {
		o->vfiles = p->virtual_files(bf);
	}
	if (p->maps) {
		o->maps = p->maps(bf);
		if (o->maps) {
			REBASE_PADDR(o, o->maps, RzBinMap);
		}
	}
	if (p->fields) {
		o->fields = p->fields(bf);
		if (o->fields) {
			rz_warn_if_fail(o->fields->free);
			REBASE_PADDR(o, o->fields, RzBinField);
		}
	}
	if (p->imports) {
		rz_list_free(o->imports);
		o->imports = p->imports(bf);
		if (o->imports) {
			rz_warn_if_fail(o->imports->free);
		}
	}
	if (p->populate_symbols) {
		o->symbols = p->populate_symbols(bf);
		if (o->symbols) {
			REBASE_PADDR(o, o->symbols, RzBinSymbol);
			if (bin->filter) {
				rz_bin_filter_symbols(bf, o->symbols);
			}
			o->import_name_symbols = ht_pp_new0();
			if (o->import_name_symbols) {
				RzBinSymbol *sym;
				RzListIter *it;
				rz_list_foreach (o->symbols, it, sym) {
					if (!sym->is_imported || !sym->name || !*sym->name) {
						continue;
					}
					ht_pp_insert(o->import_name_symbols, sym->name, sym);
				}
			}
		}
	}
	if (p->libs) {
		o->libs = p->libs(bf);
	}
	if (p->sections) {
		// XXX sections are populated by call to size
		if (!o->sections) {
			o->sections = p->sections(bf);
		}
		REBASE_PADDR(o, o->sections, RzBinSection);
		if (bin->filter) {
			rz_bin_filter_sections(bf, o->sections);
		}
	}

	o->info = p->info ? p->info(bf) : NULL;

	if (bin->filter_rules & (RZ_BIN_REQ_RELOCS | RZ_BIN_REQ_IMPORTS)) {
		if (p->relocs) {
			RzList *l = p->relocs(bf);
			if (l) {
				REBASE_PADDR(o, l, RzBinReloc);
				o->relocs = rz_bin_reloc_storage_new(l);
			}
		}
	}
	if (bin->filter_rules & RZ_BIN_REQ_STRINGS) {
		RzList *strings;
		if (p->strings) {
			strings = p->strings(bf);
		} else {
			// when a bin plugin does not provide it's own strings
			// we always take all the strings found in the binary
			// the method also converts the paddrs to vaddrs
			strings = rz_bin_file_strings(bf, minlen, true);
		}

		if (bin->debase64) {
			bin_object_decode_all_base64_strings(strings);
		}
		REBASE_PADDR(o, strings, RzBinString);

		// RzBinStrDb becomes the owner of the RzList strings
		o->strings = rz_bin_string_database_new(strings);
	}

	if (o->info && RZ_STR_ISEMPTY(o->info->compiler)) {
		free(o->info->compiler);
		o->info->compiler = rz_bin_file_golang_compiler(bf);
		if (o->info->compiler) {
			o->info->lang = "go";
		}
	}

	o->lang = rz_bin_language_detect(bf);

	if (p->demangle_symbols) {
		p->demangle_symbols(bf, o->symbols);
	}

	if (bin->filter_rules & (RZ_BIN_REQ_CLASSES | RZ_BIN_REQ_CLASSES_SOURCES)) {
		if (p->classes) {
			RzList *classes = p->classes(bf);
			if (classes) {
				// XXX we should probably merge them instead
				rz_list_free(o->classes);
				o->classes = classes;
				rz_bin_object_rebuild_classes_ht(o);
			}

			if (o->lang == RZ_BIN_LANGUAGE_SWIFT) {
				o->classes = classes_from_symbols(bf);
			}
		} else {
			RzList *classes = classes_from_symbols(bf);
			if (classes) {
				o->classes = classes;
			}
		}

		if (bin->filter) {
			filter_classes(bf, o->classes);
		}

		// cache addr=class+method
		if (o->classes) {
			RzList *klasses = o->classes;
			RzListIter *iter, *iter2;
			RzBinClass *klass;
			RzBinSymbol *method;
			if (!o->addrzklassmethod) {
				// this is slow. must be optimized, but at least its cached
				o->addrzklassmethod = ht_up_new0();
				rz_list_foreach (klasses, iter, klass) {
					rz_list_foreach (klass->methods, iter2, method) {
						ht_up_insert(o->addrzklassmethod, method->vaddr, method);
					}
				}
			}
		}
	}
	if (p->lines) {
		o->lines = p->lines(bf);
	}
	if (p->get_sdb) {
		Sdb *new_kv = p->get_sdb(bf);
		if (new_kv != o->kv) {
			sdb_free(o->kv);
		}
		o->kv = new_kv;
	}
	if (p->mem) {
		o->mem = p->mem(bf);
	}
	if (p->resources) {
		o->resources = p->resources(bf);
	}
	return true;
}

RZ_API RzBinRelocStorage *rz_bin_object_patch_relocs(RzBinFile *bf, RzBinObject *o) {
	rz_return_val_if_fail(bf && o, NULL);

	static bool first = true;
	// rz_bin_object_set_items set o->relocs but there we don't have access
	// to io so we need to be run from bin_relocs, free the previous reloc and get
	// the patched ones
	if (first && o->plugin && o->plugin->patch_relocs) {
		RzList *tmp = o->plugin->patch_relocs(bf);
		first = false;
		if (!tmp) {
			return o->relocs;
		}
		rz_bin_reloc_storage_free(o->relocs);
		REBASE_PADDR(o, tmp, RzBinReloc);
		o->relocs = rz_bin_reloc_storage_new(tmp);
		first = false;
		bf->rbin->is_reloc_patched = true;
	}
	return o->relocs;
}

/**
 * \brief Find the symbol that represents the given import
 * This is necessary for example to determine the address of an import.
 */
RZ_API RzBinSymbol *rz_bin_object_get_symbol_of_import(RzBinObject *o, RzBinImport *imp) {
	rz_return_val_if_fail(o && imp && imp->name, NULL);
	if (!o->import_name_symbols) {
		return NULL;
	}
	return ht_pp_find(o->import_name_symbols, imp->name, NULL);
}

RZ_API RzBinVirtualFile *rz_bin_object_get_virtual_file(RzBinObject *o, const char *name) {
	rz_return_val_if_fail(o && name, NULL);
	if (!o->vfiles) {
		return NULL;
	}
	RzListIter *it;
	RzBinVirtualFile *vf;
	rz_list_foreach (o->vfiles, it, vf) {
		if (!strcmp(vf->name, name)) {
			return vf;
		}
	}
	return NULL;
}

RZ_IPI RzBinObject *rz_bin_object_get_cur(RzBin *bin) {
	rz_return_val_if_fail(bin && bin->cur, NULL);
	return bin->cur->o;
}

RZ_IPI RzBinObject *rz_bin_object_find_by_arch_bits(RzBinFile *bf, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail(bf && arch && name, NULL);
	if (bf->o) {
		RzBinInfo *info = bf->o->info;
		if (info && info->arch && info->file &&
			(bits == info->bits) &&
			!strcmp(info->arch, arch) &&
			!strcmp(info->file, name)) {
			return bf->o;
		}
	}
	return NULL;
}

/**
 * \brief Put the given address on top of o's base address
 */
RZ_API ut64 rz_bin_object_addr_with_base(RzBinObject *o, ut64 addr) {
	return o ? addr + o->baddr_shift : addr;
}

/* \brief Resolve the given address pair to a vaddr if possible
 * returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise
 */
RZ_API ut64 rz_bin_object_get_vaddr(RzBinObject *o, ut64 paddr, ut64 vaddr) {
	rz_return_val_if_fail(o, UT64_MAX);

	if (paddr == UT64_MAX) {
		// everything we have is the vaddr
		return vaddr;
	}

	/* hack to realign thumb symbols */
	if (o->info && o->info->arch) {
		if (o->info->bits == 16) {
			RzBinSection *s = rz_bin_get_section_at(o, paddr, false);
			// autodetect thumb
			if (s && (s->perm & RZ_PERM_X) && strstr(s->name, "text")) {
				if (!strcmp(o->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}

	if (o->info && o->info->has_va) {
		return rz_bin_object_addr_with_base(o, vaddr);
	}
	return paddr;
}

/**
 * \brief Return the \p RzBinAddr structure representing the special symbol \p sym
 */
RZ_API const RzBinAddr *rz_bin_object_get_special_symbol(RzBinObject *o, RzBinSpecialSymbol sym) {
	rz_return_val_if_fail(o, NULL);
	if (sym < 0 || sym >= RZ_BIN_SPECIAL_SYMBOL_LAST) {
		return NULL;
	}
	return o ? o->binsym[sym] : NULL;
}

/**
 * \brief Get list of \p RzBinAddr representing the entry points of the binary object.
 */
RZ_API const RzList /*<RzBinAddr *>*/ *rz_bin_object_get_entries(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->entries;
}

/**
 * \brief Get list of \p RzBinField representing the fields of the binary object.
 */
RZ_API const RzList /*<RzBinField *>*/ *rz_bin_object_get_fields(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->fields;
}

/**
 * \brief Get list of \p RzBinImport representing the imports of the binary object.
 */
RZ_API const RzList /*<RzBinImport *>*/ *rz_bin_object_get_imports(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->imports;
}

/**
 * \brief Get the \p RzBinInfo of the binary object.
 */
RZ_API const RzBinInfo *rz_bin_object_get_info(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->info;
}

/**
 * \brief Get list of \p char* representing the libraries used by the binary object.
 */
RZ_API const RzList /*<char *>*/ *rz_bin_object_get_libs(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->libs;
}

/**
 * \brief Get list of \p RzBinSection representing both the sections and the segments of the binary object.
 */
RZ_API const RzList /*<RzBinSection *>*/ *rz_bin_object_get_sections_all(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->sections;
}

static RzList /*<RzBinSection *>*/ *get_sections_or_segment(RzBinObject *obj, bool is_segment) {
	RzList *res = rz_list_new();
	if (!res) {
		return NULL;
	}
	const RzList *all = rz_bin_object_get_sections_all(obj);
	RzListIter *it;
	RzBinSection *sec;
	rz_list_foreach (all, it, sec) {
		if (sec->is_segment == is_segment) {
			rz_list_append(res, sec);
		}
	}
	return res;
}

/**
 * \brief Get list of \p RzBinSection representing only the sections of the binary object.
 */
RZ_API RZ_OWN RzList /*<RzBinSection *>*/ *rz_bin_object_get_sections(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return get_sections_or_segment(obj, false);
}

/**
 * \brief Get list of \p RzBinSection representing only the segments of the binary object.
 */
RZ_API RZ_OWN RzList /*<RzBinSection *>*/ *rz_bin_object_get_segments(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return get_sections_or_segment(obj, true);
}

/**
 * \brief Get list of \p RzBinMap representing only the maps of the binary object.
 */
RZ_API RZ_OWN RzList /*<RzBinMap *>*/ *rz_bin_object_get_maps(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->maps;
}

/**
 * \brief Get list of \p RzBinClass representing the classes (e.g. C++ classes) defined in the binary object.
 */
RZ_API const RzList /*<RzBinClass *>*/ *rz_bin_object_get_classes(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->classes;
}

/**
 * \brief Get list of \p RzBinString representing the strings identified in the binary object.
 */
RZ_API const RzList /*<RzBinString *>*/ *rz_bin_object_get_strings(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	if (!obj->strings) {
		return NULL;
	}
	return obj->strings->list;
}

/**
 * \brief Get list of \p RzBinMem representing the memory regions identified in the binary object.
 */
RZ_API const RzList /*<RzBinMem *>*/ *rz_bin_object_get_mem(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->mem;
}

/**
 * \brief Get list of \p RzBinSymbol representing the symbols in the binary object.
 */
RZ_API const RzList /*<RzBinSymbol *>*/ *rz_bin_object_get_symbols(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->symbols;
}

/**
 * \brief Get a list of \p RzBinResource representing the resources in the binary object.
 */
RZ_API const RzList /*<RzBinResource *>*/ *rz_bin_object_get_resources(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->resources;
}

/**
 * \brief Remove all previously identified strings in the binary object and scan it again for strings.
 */
RZ_API bool rz_bin_object_reset_strings(RZ_NONNULL RzBin *bin, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(bin && bf && obj, false);
	RZ_FREE_CUSTOM(obj->strings, rz_bin_string_database_free);

	RzList *strings = NULL;
	RzBinPlugin *plugin = obj->plugin;
	if (plugin && plugin->strings) {
		strings = plugin->strings(bf);
	} else {
		// when a bin plugin does not provide it's own strings
		// we always take all the strings found in the binary
		// the method also converts the paddrs to vaddrs
		strings = rz_bin_file_strings(bf, bin->minstrlen, true);
	}

	if (bin->debase64) {
		bin_object_decode_all_base64_strings(strings);
	}
	REBASE_PADDR(obj, strings, RzBinString);

	// RzBinStrDb becomes the owner of the RzList strings
	obj->strings = rz_bin_string_database_new(strings);
	return obj->strings != NULL;
}

/**
 * \brief Return RzBinString if at \p address \p there is an entry in the RzBinObject string database
 */
RZ_API RZ_BORROW RzBinString *rz_bin_object_get_string_at(RZ_NONNULL RzBinObject *obj, ut64 address, bool is_va) {
	rz_return_val_if_fail(obj, false);
	if (!obj->strings) {
		return NULL;
	}
	if (is_va) {
		return ht_up_find(obj->strings->virt, address, NULL);
	}
	return ht_up_find(obj->strings->phys, address, NULL);
}

/**
 * \brief Return true if the binary object \p obj is big endian.
 */
RZ_API bool rz_bin_object_is_big_endian(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, false);
	return obj->info ? obj->info->big_endian : false;
}

/**
 * \brief Return true if the binary object \p obj is detected as statically compiled.
 */
RZ_API bool rz_bin_object_is_static(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, false);
	if (obj->libs && rz_list_length(obj->libs) > 0) {
		return RZ_BIN_DBG_STATIC & obj->info->dbg_info;
	}
	return true;
}

static void bin_section_map_fini(void *e, void *user) {
	(void)user;
	RzBinSectionMap *bsm = (RzBinSectionMap *)e;
	rz_pvector_fini(&bsm->sections);
}

/**
 * \brief Get the mapping between segments and sections in the binary
 *
 * \return A RzVector* with RzBinSectionMap structure inside.
 **/
RZ_API RZ_OWN RzVector /*<RzBinSectionMap>*/ *rz_bin_object_sections_mapping_list(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);

	const RzList *all = rz_bin_object_get_sections_all(obj);
	if (!all) {
		return NULL;
	}

	RzList *sections = rz_list_new();
	RzList *segments = rz_list_new();
	RzBinSection *section, *segment;
	RzListIter *iter;

	rz_list_foreach (all, iter, section) {
		RzList *list = section->is_segment ? segments : sections;
		rz_list_append(list, section);
	}

	RzVector *res = rz_vector_new(sizeof(RzBinSectionMap), bin_section_map_fini, NULL);
	if (!res) {
		goto err;
	}
	rz_vector_reserve(res, rz_list_length(segments));

	rz_list_foreach (segments, iter, segment) {
		if (segment->vaddr == UT64_MAX) {
			continue;
		}
		RzInterval segment_itv = (RzInterval){ segment->vaddr, segment->size };
		RzListIter *iter2;

		RzBinSectionMap map;
		map.segment = segment;
		rz_pvector_init(&map.sections, NULL);

		rz_list_foreach (sections, iter2, section) {
			if (section->vaddr == UT64_MAX) {
				continue;
			}
			RzInterval section_itv = (RzInterval){ section->vaddr, section->vsize };
			if (rz_itv_begin(section_itv) >= rz_itv_begin(segment_itv) && rz_itv_end(section_itv) <= rz_itv_end(segment_itv) && section->name[0]) {
				rz_pvector_push(&map.sections, section);
			}
		}
		rz_vector_push(res, &map);
	}

err:
	rz_list_free(segments);
	rz_list_free(sections);
	return res;
}

static ut64 map_p2v(RzBinMap *m, ut64 paddr) {
	ut64 delta = paddr - m->paddr;
	if (delta >= m->vsize) {
		return UT64_MAX;
	}
	return m->vaddr + delta;
}

/**
 * \brief Convert offset in the file to virtual address according to binary mappings
 *
 * \param obj Reference to \p RzBinObject
 * \param paddr Offset in the file
 * \return Converted offset to virtual address or UT64_MAX if the conversion cannot be done
 */
RZ_API ut64 rz_bin_object_p2v(RZ_NONNULL RzBinObject *obj, ut64 paddr) {
	rz_return_val_if_fail(obj, UT64_MAX);
	RzBinMap *m = rz_bin_object_get_map_at(obj, paddr, false);
	if (!m) {
		return UT64_MAX;
	}

	return map_p2v(m, paddr);
}

/**
 * \brief Convert offset in the file to all possible virtual addresses according to binary mappings
 *
 * \param obj Reference to \p RzBinObject
 * \param paddr Offset in the file
 * \return Vector containing \p ut64 values of all possible virtual addresses
 */
RZ_API RzVector /*<ut64>*/ *rz_bin_object_p2v_all(RZ_NONNULL RzBinObject *obj, ut64 paddr) {
	rz_return_val_if_fail(obj, NULL);
	RzPVector *maps = rz_bin_object_get_maps_at(obj, paddr, false);
	if (!maps) {
		return NULL;
	}

	RzVector *res = rz_vector_new(sizeof(ut64), NULL, NULL);
	void **it;
	rz_pvector_foreach (maps, it) {
		RzBinMap *map = *(RzBinMap **)it;
		ut64 vaddr = map_p2v(map, paddr);
		if (vaddr != UT64_MAX) {
			rz_vector_push(res, &vaddr);
		}
	}

	rz_pvector_free(maps);
	return res;
}

/**
 * \brief Convert virtual address to offset in the file according to binary mappings
 *
 * \param obj Reference to \p RzBinObject
 * \param paddr Virtual address
 * \return Converted virtual address to offset in the file or UT64_MAX if the conversion cannot be done
 */
RZ_API ut64 rz_bin_object_v2p(RZ_NONNULL RzBinObject *obj, ut64 vaddr) {
	rz_return_val_if_fail(obj, UT64_MAX);
	RzBinMap *m = rz_bin_object_get_map_at(obj, vaddr, true);
	if (!m) {
		return UT64_MAX;
	}

	ut64 delta = vaddr - m->vaddr;
	if (delta >= m->psize) {
		return UT64_MAX;
	}
	return m->paddr + delta;
}

/**
 * \brief   Allocates and initializes the RzBinStrDb structure with the given list of strings
 *
 * \param   list  The list of strings to initialize the database with
 *
 * \return  On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzBinStrDb *rz_bin_string_database_new(RZ_NULLABLE RZ_OWN RzList /*<RzBinString *>*/ *list) {
	RzBinStrDb *db = RZ_NEW0(RzBinStrDb);
	if (!db) {
		RZ_LOG_ERROR("rz_bin: Cannot allocate RzBinStrDb\n");
		rz_list_free(list);
		return NULL;
	}

	db->list = list ? list : rz_list_newf((RzListFree)rz_bin_string_free);
	db->phys = ht_up_new0();
	db->virt = ht_up_new0();
	if (!db->list || !db->phys || !db->virt) {
		RZ_LOG_ERROR("rz_bin: Cannot allocate RzBinStrDb internal data structure.\n");
		goto fail;
	}

	RzListIter *it;
	RzBinString *bstr;
	rz_list_foreach (list, it, bstr) {
		if (!ht_up_update(db->phys, bstr->paddr, bstr)) {
			RZ_LOG_ERROR("rz_bin: Cannot insert/update RzBinString in RzBinStrDb (phys)\n");
			goto fail;
		}
		if (!ht_up_update(db->virt, bstr->vaddr, bstr)) {
			RZ_LOG_ERROR("rz_bin: Cannot insert/update RzBinString in RzBinStrDb (virt)\n");
			goto fail;
		}
	}
	return db;

fail:
	rz_bin_string_database_free(db);
	return NULL;
}

/**
 * \brief  Frees a RzBinStrDb structure
 *
 * \param  db    The string database to free
 */
RZ_API void rz_bin_string_database_free(RZ_NULLABLE RzBinStrDb *db) {
	if (!db) {
		return;
	}
	rz_list_free(db->list);
	ht_up_free(db->phys);
	ht_up_free(db->virt);
	free(db);
}

/**
 * \brief   { function_description }
 *
 * \param   db    The database
 * \param   bstr  The bstr
 *
 * \return  { description_of_the_return_value }
 */
RZ_API bool rz_bin_string_database_add(RZ_NONNULL RzBinStrDb *db, RZ_NONNULL RzBinString *bstr) {
	rz_return_val_if_fail(db && bstr, false);

	if (!rz_list_append(db->list, bstr)) {
		RZ_LOG_ERROR("rz_bin: Cannot add RzBinString in RzBinStrDb (list)\n");
		return false;
	}

	if (!ht_up_update(db->phys, bstr->paddr, bstr)) {
		RZ_LOG_ERROR("rz_bin: Cannot add RzBinString in RzBinStrDb (phys)\n");
		return false;
	}

	if (!ht_up_update(db->virt, bstr->vaddr, bstr)) {
		RZ_LOG_ERROR("rz_bin: Cannot add RzBinString in RzBinStrDb (virt)\n");
		return false;
	}
	return true;
}

/**
 * \brief Return true if the given \p address \p has been removed to the RzBinObject string database
 */
RZ_API bool rz_bin_string_database_remove(RZ_NONNULL RzBinStrDb *db, ut64 address, bool is_va) {
	rz_return_val_if_fail(db, false);

	RzBinString *bstr = ht_up_find(is_va ? db->virt : db->phys, address, NULL);
	if (!bstr) {
		return false;
	}

	ht_up_delete(db->virt, bstr->vaddr);
	ht_up_delete(db->phys, bstr->paddr);
	rz_list_delete_data(db->list, bstr);
	return true;
}
