// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_util.h>
#include "i/private.h"

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

RZ_API RzBinRelocStorage *rz_bin_reloc_storage_new(RZ_OWN RzList *relocs) {
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

static void object_delete_items(RzBinObject *o) {
	ut32 i = 0;
	rz_return_if_fail(o);
	ht_up_free(o->addrzklassmethod);
	rz_list_free(o->entries);
	rz_list_free(o->maps);
	rz_list_free(o->vfiles);
	rz_list_free(o->fields);
	rz_list_free(o->imports);
	rz_list_free(o->libs);
	rz_bin_reloc_storage_free(o->relocs);
	rz_list_free(o->sections);
	rz_list_free(o->strings);
	ht_up_free(o->strings_db);
	ht_pp_free(o->import_name_symbols);
	rz_list_free(o->symbols);
	rz_list_free(o->classes);
	ht_pp_free(o->classes_ht);
	ht_pp_free(o->methods_ht);
	rz_bin_source_line_info_free(o->lines);
	sdb_free(o->kv);
	rz_list_free(o->mem);
	for (i = 0; i < RZ_BIN_SPECIAL_SYMBOL_LAST; i++) {
		free(o->binsym[i]);
	}
}

RZ_IPI void rz_bin_object_free(void /*RzBinObject*/ *o_) {
	RzBinObject *o = o_;
	if (o) {
		free(o->regstate);
		rz_bin_info_free(o->info);
		object_delete_items(o);
		free(o);
	}
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

static RzList *classes_from_symbols(RzBinFile *bf) {
	RzBinSymbol *sym;
	RzListIter *iter;
	rz_list_foreach (bf->o->symbols, iter, sym) {
		if (sym->name[0] != '_') {
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
				// eprintf ("FIELD %s  %s\n", cn, fn);
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
	Sdb *sdb = bf->sdb;
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
	o->strings_db = ht_up_new0();
	o->regstate = NULL;
	o->kv = sdb_new0(); // XXX bf->sdb bf->o->sdb
	o->classes = rz_list_newf((RzListFree)rz_bin_class_free);
	o->classes_ht = ht_pp_new0();
	o->methods_ht = ht_pp_new0();
	o->baddr_shift = 0;
	o->plugin = plugin;

	if (plugin && plugin->load_buffer) {
		if (!plugin->load_buffer(bf, &o->bin_obj, bf->buf, o->opts.loadaddr, sdb)) {
			if (bf->rbin->verbose) {
				eprintf("Error in rz_bin_object_new: load_buffer failed for %s plugin\n", plugin->name);
			}
			sdb_free(o->kv);
			free(o);
			return NULL;
		}
	} else {
		RZ_LOG_WARN("Plugin %s should implement load_buffer method.\n", plugin->name);
		sdb_free(o->kv);
		free(o);
		return NULL;
	}

	// XXX - object size can't be set here and needs to be set where where
	// the object is created from. The reason for this is to prevent
	// mis-reporting when the file is loaded from impartial bytes or is
	// extracted from a set of bytes in the file
	rz_bin_file_set_obj(bf->rbin, bf, o);
	rz_bin_set_baddr(bf->rbin, o->opts.baseaddr);
	rz_bin_object_set_items(bf, o);

	bf->sdb_info = o->kv;
	sdb = bf->rbin->sdb;
	if (sdb) {
		Sdb *bdb = bf->sdb; // sdb_new0 ();
		sdb_ns_set(bdb, "info", o->kv);
		o->kv = bdb;
		// bf->sdb = o->kv;
		// bf->sdb_info = o->kv;
		// sdb_ns_set (bf->sdb, "info", o->kv);
		//sdb_ns (sdb, sdb_fmt ("fd.%d", bf->fd), 1);
		sdb_set(bf->sdb, "archs", "0:0:x86:32", 0); // x86??
		/* NOTE */
		/* Those refs++ are necessary because sdb_ns() doesnt rerefs all
		 * sub-namespaces */
		/* And if any namespace is referenced backwards it gets
		 * double-freed */
		// bf->sdb_info = sdb_ns (bf->sdb, "info", 1);
		sdb_ns_set(sdb, "cur", bdb); // bf->sdb);
		const char *fdns = sdb_fmt("fd.%d", bf->fd);
		sdb_ns_set(sdb, fdns, bdb); // bf->sdb);
		bf->sdb->refs++;
	}
	return o;
}

static void filter_classes(RzBinFile *bf, RzList *list) {
	Sdb *db = sdb_new0();
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
		if (namepad) {
			char *p;
			strcpy(namepad, cls->name);
			p = rz_bin_filter_name(bf, db, cls->index, namepad);
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
		} else {
			eprintf("Cannot alloc %d byte(s)\n", namepad_len);
		}
	}
	sdb_free(db);
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

	int i;
	bool isSwift = false;
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
		for (i = 0; i < RZ_BIN_SPECIAL_SYMBOL_LAST; i++) {
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
	if (p->symbols) {
		o->symbols = p->symbols(bf);
		if (o->symbols) {
			rz_warn_if_fail(o->symbols->free);
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
	o->info = p->info ? p->info(bf) : NULL;
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
		o->strings = p->strings
			? p->strings(bf)
			: rz_bin_file_get_strings(bf, minlen, 0, bf->rawstr);
		if (bin->debase64) {
			rz_bin_object_filter_strings(o);
		}
		REBASE_PADDR(o, o->strings, RzBinString);
	}
	if (bin->filter_rules & RZ_BIN_REQ_CLASSES) {
		if (p->classes) {
			RzList *classes = p->classes(bf);
			if (classes) {
				// XXX we should probably merge them instead
				rz_list_free(o->classes);
				o->classes = classes;
				rz_bin_object_rebuild_classes_ht(o);
			}
			isSwift = rz_bin_lang_swift(bf);
			if (isSwift) {
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
	if (o->info && bin->filter_rules & (RZ_BIN_REQ_INFO | RZ_BIN_REQ_SYMBOLS | RZ_BIN_REQ_IMPORTS)) {
		o->lang = isSwift ? RZ_BIN_NM_SWIFT : rz_bin_load_languages(bf);
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

RZ_IPI void rz_bin_object_filter_strings(RzBinObject *bo) {
	rz_return_if_fail(bo && bo->strings);

	RzList *strings = bo->strings;
	RzBinString *ptr;
	RzListIter *iter;
	rz_list_foreach (strings, iter, ptr) {
		char *dec = (char *)rz_base64_decode_dyn(ptr->string, -1);
		if (dec) {
			char *s = ptr->string;
			for (;;) {
				char *dec2 = (char *)rz_base64_decode_dyn(s, -1);
				if (!dec2) {
					break;
				}
				if (!rz_str_is_printable(dec2)) {
					free(dec2);
					break;
				}
				free(dec);
				s = dec = dec2;
			}
			if (rz_str_is_printable(dec) && strlen(dec) > 3) {
				free(ptr->string);
				ptr->string = dec;
				ptr->type = RZ_STRING_TYPE_BASE64;
			} else {
				free(dec);
			}
		}
	}
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

RZ_API const RzBinAddr *rz_bin_object_get_special_symbol(RzBinObject *o, RzBinSpecialSymbol sym) {
	rz_return_val_if_fail(o, NULL);
	if (sym < 0 || sym >= RZ_BIN_SPECIAL_SYMBOL_LAST) {
		return NULL;
	}
	return o ? o->binsym[sym] : NULL;
}

// TODO: obj->entries & co should be set here, not somewhere else
RZ_API const RzList *rz_bin_object_get_entries(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->entries;
}

RZ_API const RzList *rz_bin_object_get_fields(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->fields;
}

RZ_API const RzList *rz_bin_object_get_imports(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->imports;
}

RZ_API const RzBinInfo *rz_bin_object_get_info(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->info;
}

RZ_API const RzList *rz_bin_object_get_libs(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->libs;

}

RZ_API const RzList *rz_bin_object_get_sections_all(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->sections;
}

static RzList *get_sections_or_segment(RzBinObject *obj, bool is_segment) {
	RzList *res = rz_list_new();
	if (!res) {
		return NULL;
	}
	const RzList *all = rz_bin_object_get_sections_all(obj);
	RzListIter *it;
	RzBinSection *sec;
	rz_list_foreach(all, it, sec) {
		if (sec->is_segment == is_segment) {
			rz_list_append(res, sec);
		}
	}
	return res;
}

RZ_API RzList *rz_bin_object_get_sections(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return get_sections_or_segment(obj, false);
}

RZ_API RzList *rz_bin_object_get_segments(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return get_sections_or_segment(obj, true);
}

RZ_API const RzList *rz_bin_object_get_classes(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->classes;
}

RZ_API const RzList *rz_bin_object_get_strings(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->strings;
}

RZ_API const RzList *rz_bin_object_get_mem(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->mem;
}

RZ_API const RzList *rz_bin_object_get_symbols(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->symbols;
}

RZ_API char *rz_bin_object_get_signature(RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	// TODO: implement me
	return NULL;
}

RZ_API const RzList *rz_bin_object_reset_strings(RzBin *bin, RzBinFile *bf, RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	if (obj->strings) {
		rz_list_free(obj->strings);
		obj->strings = NULL;
	}
	ht_up_free(obj->strings_db);
	obj->strings_db = ht_up_new0();

	bf->rawstr = bin->rawstr;
	RzBinPlugin *plugin = obj->plugin;
	if (plugin && plugin->strings) {
		obj->strings = plugin->strings(bf);
	} else {
		obj->strings = rz_bin_file_get_strings(bf, bin->minstrlen, 0, bf->rawstr);
	}
	if (bin->debase64) {
		rz_bin_object_filter_strings(obj);
	}
	return obj->strings;
}

RZ_API bool rz_bin_object_is_string(RzBinObject *obj, ut64 va) {
	rz_return_val_if_fail(obj, false);
	RzBinString *string;
	RzListIter *iter;
	const RzList *list;
	if (!(list = rz_bin_object_get_strings(obj))) {
		return false;
	}
	rz_list_foreach (list, iter, string) {
		if (string->vaddr == va) {
			return true;
		}
		if (string->vaddr > va) {
			return false;
		}
	}
	return false;
}

RZ_API bool rz_bin_object_is_big_endian(RzBinObject *obj) {
	rz_return_val_if_fail(obj, false);
	return obj->info ? obj->info->big_endian : false;
}

RZ_API bool rz_bin_object_is_static(RzBinObject *obj) {
	rz_return_val_if_fail(obj, false);
	if (obj->libs && rz_list_length(obj->libs) > 0) {
		return RZ_BIN_DBG_STATIC & obj->info->dbg_info;
	}
	return true;
}
