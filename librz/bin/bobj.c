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

static int reloc_cmp(const void *a, const RBNode *b, void *user) {
	const RzBinReloc *ar = (const RzBinReloc *)a;
	const RzBinReloc *br = container_of(b, const RzBinReloc, vrb);
	if (ar->vaddr > br->vaddr) {
		return 1;
	}
	if (ar->vaddr < br->vaddr) {
		return -1;
	}
	return 0;
}

static void reloc_free(RBNode *rbn, void *user) {
	free(container_of(rbn, RzBinReloc, vrb));
}

static void object_delete_items(RzBinObject *o) {
	ut32 i = 0;
	rz_return_if_fail(o);
	ht_up_free(o->addrzklassmethod);
	rz_list_free(o->entries);
	rz_list_free(o->fields);
	rz_list_free(o->imports);
	rz_list_free(o->libs);
	rz_rbtree_free(o->relocs, reloc_free, NULL);
	rz_list_free(o->sections);
	rz_list_free(o->strings);
	ht_up_free(o->strings_db);
	rz_list_free(o->symbols);
	rz_list_free(o->classes);
	ht_pp_free(o->classes_ht);
	ht_pp_free(o->methods_ht);
	rz_list_free(o->lines);
	sdb_free(o->kv);
	rz_list_free(o->mem);
	for (i = 0; i < RZ_BIN_SYM_LAST; i++) {
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
RZ_IPI RzBinObject *rz_bin_object_new(RzBinFile *bf, RzBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz) {
	rz_return_val_if_fail(bf && plugin, NULL);
	ut64 bytes_sz = rz_buf_size(bf->buf);
	Sdb *sdb = bf->sdb;
	RzBinObject *o = RZ_NEW0(RzBinObject);
	if (!o) {
		return NULL;
	}
	o->obj_size = (bytes_sz >= sz + offset) ? sz : 0;
	o->boffset = offset;
	o->strings_db = ht_up_new0();
	o->regstate = NULL;
	o->kv = sdb_new0(); // XXX bf->sdb bf->o->sdb
	o->baddr = baseaddr;
	o->classes = rz_list_newf((RzListFree)rz_bin_class_free);
	o->classes_ht = ht_pp_new0();
	o->methods_ht = ht_pp_new0();
	o->baddr_shift = 0;
	o->plugin = plugin;
	o->loadaddr = loadaddr != UT64_MAX ? loadaddr : 0;

	if (plugin && plugin->load_buffer) {
		if (!plugin->load_buffer(bf, &o->bin_obj, bf->buf, loadaddr, sdb)) {
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
	rz_bin_set_baddr(bf->rbin, o->baddr);
	rz_bin_object_set_items(bf, o);

	bf->sdb_info = o->kv;
	sdb = bf->rbin->sdb;
	if (sdb) {
		Sdb *bdb = bf->sdb; // sdb_new0 ();
		sdb_ns_set(bdb, "info", o->kv);
		sdb_ns_set(bdb, "addrinfo", bf->sdb_addrinfo);
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
		//	bf->sdb_addrinfo = sdb_ns (bf->sdb, "addrinfo", 1);
		//	bf->sdb_addrinfo->refs++;
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

static RBNode *list2rbtree(RzList *relocs) {
	RzListIter *it;
	RzBinReloc *reloc;
	RBNode *res = NULL;

	rz_list_foreach (relocs, it, reloc) {
		rz_rbtree_insert(&res, reloc, &reloc->vrb, reloc_cmp, NULL);
	}
	return res;
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
			if (p->maps) {
				o->maps = p->maps(bf);
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
		for (i = 0; i < RZ_BIN_SYM_LAST; i++) {
			o->binsym[i] = p->binsym(bf, i);
			if (o->binsym[i]) {
				o->binsym[i]->paddr += o->loadaddr;
			}
		}
	}
	if (p->entries) {
		o->entries = p->entries(bf);
		REBASE_PADDR(o, o->entries, RzBinAddr);
	}
	if (p->fields) {
		o->fields = p->fields(bf);
		if (o->fields) {
			o->fields->free = rz_bin_field_free;
			REBASE_PADDR(o, o->fields, RzBinField);
		}
	}
	if (p->imports) {
		rz_list_free(o->imports);
		o->imports = p->imports(bf);
		if (o->imports) {
			o->imports->free = rz_bin_import_free;
		}
	}
	if (p->symbols) {
		o->symbols = p->symbols(bf); // 5s
		if (o->symbols) {
			o->symbols->free = rz_bin_symbol_free;
			REBASE_PADDR(o, o->symbols, RzBinSymbol);
			if (bin->filter) {
				rz_bin_filter_symbols(bf, o->symbols); // 5s
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
				o->relocs = list2rbtree(l);
				l->free = NULL;
				rz_list_free(l);
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

RZ_IPI RBNode *rz_bin_object_patch_relocs(RzBinFile *bf, RzBinObject *o) {
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
		rz_rbtree_free(o->relocs, reloc_free, NULL);
		REBASE_PADDR(o, tmp, RzBinReloc);
		o->relocs = list2rbtree(tmp);
		first = false;
		bf->rbin->is_reloc_patched = true;
		tmp->free = NULL;
		rz_list_free(tmp);
	}
	return o->relocs;
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

RZ_API bool rz_bin_object_delete(RzBin *bin, ut32 bf_id) {
	rz_return_val_if_fail(bin, false);

	bool res = false;
	RzBinFile *bf = rz_bin_file_find_by_id(bin, bf_id);
	if (bf) {
		if (bin->cur == bf) {
			bin->cur = NULL;
		}
		if (!bf->o) {
			rz_list_delete_data(bin->binfiles, bf);
		}
	}
	return res;
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

RZ_API ut64 rz_bin_object_addr_with_base(RzBinObject *o, ut64 addr) {
	return o ? addr + o->baddr_shift : addr;
}
