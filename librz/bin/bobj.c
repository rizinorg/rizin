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
RZ_IPI void rz_bin_string_decode_base64(RZ_NONNULL RzBinString *bstr) {
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

RZ_API void rz_bin_mem_free(RZ_NULLABLE void *data) {
	if (!data) {
		return;
	}
	RzBinMem *mem = (RzBinMem *)data;
	free(mem->name);
	if (mem->mirrors) {
		mem->mirrors->v.free_user = rz_bin_mem_free;
		rz_pvector_free(mem->mirrors);
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

static int reloc_cmp(const void *a, const void *b, void *user) {
	const RzBinReloc *ar = a;
	const RzBinReloc *br = b;
	CMP_CHECK(vaddr);
	CMP_CHECK(paddr);
	CMP_CHECK(type);
	CMP_CHECK(target_vaddr);
	return 0;
}

static int reloc_target_cmp(const void *a, const void *b, void *user) {
	const RzBinReloc *ar = a;
	const RzBinReloc *br = b;
	CMP_CHECK(target_vaddr);
	CMP_CHECK(vaddr);
	CMP_CHECK(paddr);
	CMP_CHECK(type);
	return 0;
}

#undef CMP_CHECK

RZ_API RzBinRelocStorage *rz_bin_reloc_storage_new(RZ_OWN RzPVector /*<RzBinReloc *>*/ *relocs) {
	RzBinRelocStorage *ret = RZ_NEW0(RzBinRelocStorage);
	if (!ret) {
		return NULL;
	}
	RzPVector sorter;
	rz_pvector_init(&sorter, NULL);
	rz_pvector_reserve(&sorter, rz_pvector_len(relocs));
	RzPVector target_sorter;
	rz_pvector_init(&target_sorter, NULL);
	rz_pvector_reserve(&target_sorter, rz_pvector_len(relocs));
	void **it;
	RzBinReloc *reloc;
	rz_pvector_foreach (relocs, it) {
		reloc = *it;
		rz_pvector_push(&sorter, reloc);
		if (rz_bin_reloc_has_target(reloc)) {
			rz_pvector_push(&target_sorter, reloc);
		}
	}
	ret->relocs_free = relocs->v.free_user;
	relocs->v.free = NULL; // ownership of relocs transferred
	rz_pvector_free(relocs);
	rz_pvector_sort(&sorter, reloc_cmp, NULL);
	ret->relocs_count = rz_pvector_len(&sorter);
	ret->relocs = (RzBinReloc **)rz_pvector_flush(&sorter);
	rz_pvector_fini(&sorter);
	rz_pvector_sort(&target_sorter, reloc_target_cmp, NULL);
	ret->target_relocs_count = rz_pvector_len(&target_sorter);
	ret->target_relocs = (RzBinReloc **)rz_pvector_flush(&target_sorter);
	rz_pvector_fini(&target_sorter);
	return ret;
}

RZ_API void rz_bin_reloc_storage_free(RzBinRelocStorage *storage) {
	if (!storage) {
		return;
	}
	if (storage->relocs_free) {
		for (size_t i = 0; i < storage->relocs_count; i++) {
			storage->relocs_free(storage->relocs[i]);
		}
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
	ht_sp_free(o->glue_to_class_field);
	ht_sp_free(o->glue_to_class_method);
	ht_sp_free(o->name_to_class_object);
	ht_sp_free(o->import_name_symbols);
	ht_up_free(o->vaddr_to_class_method);
	rz_bin_info_free(o->info);
	rz_bin_reloc_storage_free(o->relocs);
	rz_bin_source_line_info_free(o->lines);
	rz_bin_string_database_free(o->strings);
	rz_pvector_free(o->classes);
	rz_pvector_free(o->entries);
	rz_pvector_free(o->fields);
	rz_pvector_free(o->imports);
	rz_pvector_free(o->libs);
	rz_pvector_free(o->maps);
	rz_pvector_free(o->mem);
	rz_pvector_free(o->sections);
	rz_pvector_free(o->symbols);
	rz_pvector_free(o->vfiles);
	rz_pvector_free(o->resources);
	for (ut32 i = 0; i < RZ_BIN_SPECIAL_SYMBOL_LAST; i++) {
		free(o->binsym[i]);
	}
	free(o);
}

/**
 * \brief      Find a class based on the given name
 *
 * \param      o       The RzBinObject to search into
 * \param[in]  name    The class name
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_BORROW RzBinClass *rz_bin_object_find_class(RZ_NONNULL RzBinObject *o, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(o && name, NULL);
	return ht_sp_find(o->name_to_class_object, name, NULL);
}

static RzBinClass *bin_class_new(RzBinObject *o, const char *name, const char *super, ut64 address) {
	RzBinClass *c = RZ_NEW0(RzBinClass);
	if (!c) {
		return NULL;
	}

	c->name = strdup(name);
	c->super = rz_str_dup(super);
	c->methods = rz_list_newf((RzListFree)rz_bin_symbol_free);
	c->fields = rz_list_newf((RzListFree)rz_bin_class_field_free);
	c->addr = address;
	return c;
}

RZ_IPI int rz_bin_compare_class(RzBinClass *a, RzBinClass *b) {
	st64 ret = 0;
	if (a->name && b->name && (ret = strcmp(a->name, b->name))) {
		return ret;
	}
	return a->addr - b->addr;
}

RZ_IPI int rz_bin_compare_method(RzBinSymbol *a, RzBinSymbol *b) {
	st64 ret = 0;
	if ((ret = a->vaddr - b->vaddr)) {
		return ret;
	} else if ((ret = a->paddr - b->paddr)) {
		return ret;
	} else if (a->classname && b->classname && (ret = strcmp(a->classname, b->classname))) {
		return ret;
	} else if (a->name && b->name && (ret = strcmp(a->name, b->name))) {
		return ret;
	}
	return 0;
}

RZ_IPI int rz_bin_compare_class_field(RzBinClassField *a, RzBinClassField *b) {
	st64 ret = 0;
	if ((ret = a->vaddr - b->vaddr)) {
		return ret;
	} else if ((ret = a->paddr - b->paddr)) {
		return ret;
	} else if (a->classname && b->classname && (ret = strcmp(a->classname, b->classname))) {
		return ret;
	} else if (a->name && b->name && (ret = strcmp(a->name, b->name))) {
		return ret;
	}
	return 0;
}

static int bin_compare_method(RzBinSymbol *a, RzBinSymbol *b, void *user) {
	return rz_bin_compare_method(a, b);
}

static int bin_compare_class(RzBinClass *a, RzBinClass *b, void *user) {
	return rz_bin_compare_class(a, b);
}

static int bin_compare_class_field(RzBinClassField *a, RzBinClassField *b, void *user) {
	return rz_bin_compare_class_field(a, b);
}

/**
 * \brief      Tries to add a new class unless its name is found and returns it.
 *
 * \param      o      The RzBinObject to add a new class into
 * \param[in]  name   The name name of the class
 * \param[in]  super  The super class name of the new class
 * \param[in]  vaddr  The virtual address of the objc class metadata.
 *
 * \return     On success returns a valid pointer, otherwise returns NULL.
 */
RZ_API RZ_BORROW RzBinClass *rz_bin_object_add_class(RZ_NONNULL RzBinObject *o, RZ_NONNULL const char *name, RZ_NULLABLE const char *super, ut64 vaddr) {
	rz_return_val_if_fail(o && RZ_STR_ISNOTEMPTY(name), NULL);

	RzBinClass *oclass = ht_sp_find(o->name_to_class_object, name, NULL);
	if (oclass) {
		if (super && !oclass->super) {
			oclass->super = strdup(super);
		}
		if (oclass->addr == UT64_MAX) {
			oclass->addr = vaddr;
		}
		return oclass;
	}

	oclass = bin_class_new(o, name, super, vaddr);
	if (!oclass) {
		return NULL;
	}

	rz_pvector_push(o->classes, oclass);
	rz_pvector_sort(o->classes, (RzPVectorComparator)bin_compare_class, NULL);
	ht_sp_insert(o->name_to_class_object, name, oclass);
	return oclass;
}

/**
 * \brief      Find a method based on the class name, method name and its virtual address
 *
 * \param      o       The RzBinObject to search into
 * \param[in]  klass   The class name
 * \param[in]  method  The method name
 * \param[in]  vaddr   The virtual address of the method
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RzBinSymbol *rz_bin_object_find_method(RZ_NONNULL RzBinObject *o, RZ_NONNULL const char *klass, RZ_NONNULL const char *method) {
	rz_return_val_if_fail(o && klass && method, NULL);
	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, klass, method);
	if (!key) {
		return NULL;
	}
	RzBinSymbol *sym = (RzBinSymbol *)ht_sp_find(o->glue_to_class_method, key, NULL);
	free(key);
	return sym;
}

/**
 * \brief      Find a method based on the given virtual address
 *
 * \param      o       The RzBinObject to search into
 * \param[in]  vaddr   The virtual address of the method
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RzBinSymbol *rz_bin_object_find_method_by_vaddr(RZ_NONNULL RzBinObject *o, ut64 vaddr) {
	rz_return_val_if_fail(o, NULL);
	return (RzBinSymbol *)ht_up_find(o->vaddr_to_class_method, vaddr, NULL);
}

/**
 * \brief      Adds a new class method to a given RzBinObject
 *
 * This function adds methods to an existing class, if the class
 * is not known, then is added and then the method is linked to
 * the new class.
 *
 * \param      o       The RzBinObject to add the new method to
 * \param[in]  klass   The class name
 * \param[in]  method  The method name
 * \param[in]  paddr   The method paddr
 * \param[in]  vaddr   The method vaddr
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_BORROW RzBinSymbol *rz_bin_object_add_method(RZ_NONNULL RzBinObject *o, RZ_NONNULL const char *klass, RZ_NONNULL const char *method, ut64 paddr, ut64 vaddr) {
	rz_return_val_if_fail(o && RZ_STR_ISNOTEMPTY(klass) && RZ_STR_ISNOTEMPTY(method), NULL);
	RzBinSymbol *symbol = NULL;
	RzBinClass *c = NULL;

	if ((symbol = rz_bin_object_find_method(o, klass, method))) {
		if (symbol->paddr == UT64_MAX && paddr != UT64_MAX) {
			symbol->paddr = paddr;
		}
		if (symbol->vaddr == UT64_MAX && vaddr != UT64_MAX) {
			symbol->vaddr = vaddr;
		}
		return symbol;
	}

	if (!(c = rz_bin_object_add_class(o, klass, NULL, UT64_MAX))) {
		return NULL;
	}

	symbol = rz_bin_symbol_new(method, paddr, vaddr);
	if (!symbol) {
		return NULL;
	}
	symbol->classname = rz_str_dup(klass);

	if (!c->methods->sorted) {
		rz_list_sort(c->methods, (RzListComparator)bin_compare_method, NULL);
	}
	rz_list_add_sorted(c->methods, symbol, (RzListComparator)bin_compare_method, NULL);

	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, klass, method);
	if (key) {
		ht_sp_insert(o->glue_to_class_method, key, symbol);
		free(key);
	}

	if (symbol->vaddr != UT64_MAX) {
		ht_up_insert(o->vaddr_to_class_method, symbol->vaddr, symbol);
	}

	return symbol;
}

/**
 * \brief      Find a field based on the class name, field name and its virtual address
 *
 * \param      o      The RzBinObject to search into
 * \param[in]  klass  The class name
 * \param[in]  field  The field name
 * \param[in]  vaddr  The virtual address of the field
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RzBinClassField *rz_bin_object_find_field(RZ_NONNULL RzBinObject *o, RZ_NONNULL const char *klass, RZ_NONNULL const char *field) {
	rz_return_val_if_fail(o && klass && field, NULL);
	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, klass, field);
	if (!key) {
		return NULL;
	}
	RzBinClassField *sym = (RzBinClassField *)ht_sp_find(o->glue_to_class_field, key, NULL);
	free(key);
	return sym;
}

/**
 * \brief      Adds a new class field to a given RzBinObject
 *
 * This function adds fields to an existing class; if the class
 * is not known, then is created and then the field is linked to
 * the new class.
 *
 * \param      o      The RzBinObject to add the new field to
 * \param[in]  klass  The class name
 * \param[in]  name   The field name
 * \param[in]  paddr  The field paddr
 * \param[in]  vaddr  The field vaddr
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_BORROW RzBinClassField *rz_bin_object_add_field(RZ_NONNULL RzBinObject *o, RZ_NONNULL const char *klass, RZ_NONNULL const char *name, ut64 paddr, ut64 vaddr) {
	rz_return_val_if_fail(o && RZ_STR_ISNOTEMPTY(klass) && RZ_STR_ISNOTEMPTY(name), NULL);
	RzBinClassField *field = NULL;
	RzBinClass *c = NULL;

	if ((field = rz_bin_object_find_field(o, klass, name))) {
		if (field->paddr == UT64_MAX) {
			field->paddr = paddr;
		}
		if (field->vaddr == UT64_MAX) {
			field->vaddr = vaddr;
		}
		return field;
	}

	if (!(c = rz_bin_object_add_class(o, klass, NULL, UT64_MAX))) {
		return NULL;
	}

	field = rz_bin_class_field_new(paddr, vaddr, name, klass, NULL, NULL);
	if (!field) {
		return NULL;
	}

	if (!c->fields->sorted) {
		rz_list_sort(c->fields, (RzListComparator)bin_compare_class_field, NULL);
	}
	rz_list_add_sorted(c->fields, field, (RzListComparator)bin_compare_class_field, NULL);
	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, klass, name);
	if (key) {
		ht_sp_insert(o->glue_to_class_field, key, field);
		free(key);
	}
	return field;
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
	rz_bin_object_process_plugin_data(bf, o);

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

RZ_API RzBinRelocStorage *rz_bin_object_patch_relocs(RzBinFile *bf, RzBinObject *o) {
	rz_return_val_if_fail(bf && o, NULL);

	// rz_bin_object_set_items set o->relocs but there we don't have access
	// to io so we need to be run from bin_relocs, free the previous reloc and get
	// the patched ones
	if (!bf->rbin->is_reloc_patched && o->plugin && o->plugin->patch_relocs) {
		RzPVector *tmp = o->plugin->patch_relocs(bf);
		if (!tmp) {
			return o->relocs;
		}
		rz_bin_reloc_storage_free(o->relocs);
		REBASE_PADDR(o, tmp, RzBinReloc);
		o->relocs = rz_bin_reloc_storage_new(tmp);
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
	return ht_sp_find(o->import_name_symbols, imp->name, NULL);
}

RZ_API RzBinVirtualFile *rz_bin_object_get_virtual_file(RzBinObject *o, const char *name) {
	rz_return_val_if_fail(o && name, NULL);
	if (!o->vfiles) {
		return NULL;
	}
	void **it;
	RzBinVirtualFile *vf;
	rz_pvector_foreach (o->vfiles, it) {
		vf = *it;
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
 * \brief Get pvector of \p RzBinAddr representing the entry points of the binary object.
 */
RZ_API RZ_BORROW const RzPVector /*<RzBinAddr *>*/ *rz_bin_object_get_entries(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->entries;
}

/**
 * \brief Get pvector of \p RzBinField representing the fields of the binary object.
 */
RZ_API const RzPVector /*<RzBinField *>*/ *rz_bin_object_get_fields(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->fields;
}

/**
 * \brief Get list of \p RzBinImport representing the imports of the binary object.
 */
RZ_API const RzPVector /*<RzBinImport *>*/ *rz_bin_object_get_imports(RZ_NONNULL RzBinObject *obj) {
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
 * \brief Get pvector of \p char* representing the libraries used by the binary object.
 */
RZ_API const RzPVector /*<char *>*/ *rz_bin_object_get_libs(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->libs;
}

/**
 * \brief Get pvector of \p RzBinSection representing both the sections and the segments of the binary object.
 */
RZ_API const RzPVector /*<RzBinSection *>*/ *rz_bin_object_get_sections_all(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->sections;
}

static RzPVector /*<RzBinSection *>*/ *get_sections_or_segment(RzBinObject *obj, bool is_segment) {
	RzPVector *res = rz_pvector_new(NULL);
	if (!res) {
		return NULL;
	}
	const RzPVector *all = rz_bin_object_get_sections_all(obj);
	void **it;
	RzBinSection *sec;
	rz_pvector_foreach (all, it) {
		sec = *it;
		if (sec->is_segment == is_segment) {
			rz_pvector_push(res, sec);
		}
	}
	return res;
}

/**
 * \brief Get pvector of \p RzBinSection representing only the sections of the binary object.
 */
RZ_API RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_object_get_sections(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return get_sections_or_segment(obj, false);
}

/**
 * \brief Get pvector of \p RzBinSection representing only the segments of the binary object.
 */
RZ_API RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_object_get_segments(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return get_sections_or_segment(obj, true);
}

/**
 * \brief Get list of \p RzBinMap representing only the maps of the binary object.
 */
RZ_API RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_object_get_maps(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->maps;
}

/**
 * \brief Get list of \p RzBinClass representing the classes (e.g. C++ classes) defined in the binary object.
 */
RZ_API const RzPVector /*<RzBinClass *>*/ *rz_bin_object_get_classes(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->classes;
}

/**
 * \brief Get RzPVector of \p RzBinString representing the strings identified in the binary object.
 */
RZ_API const RzPVector /*<RzBinString *>*/ *rz_bin_object_get_strings(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	if (!obj->strings) {
		return NULL;
	}
	return obj->strings->pvec;
}

/**
 * \brief Get list of \p RzBinMem representing the memory regions identified in the binary object.
 */
RZ_API RZ_BORROW const RzPVector /*<RzBinMem *>*/ *rz_bin_object_get_mem(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->mem;
}

/**
 * \brief Get pvector of \p RzBinSymbol representing the symbols in the binary object.
 */
RZ_API const RzPVector /*<RzBinSymbol *>*/ *rz_bin_object_get_symbols(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->symbols;
}

/**
 * \brief Get a pvector of \p RzBinResource representing the resources in the binary object.
 */
RZ_API const RzPVector /*<RzBinResource *>*/ *rz_bin_object_get_resources(RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(obj, NULL);
	return obj->resources;
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
	if (obj->libs && rz_pvector_len(obj->libs) > 0) {
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

	const RzPVector *all = rz_bin_object_get_sections_all(obj);
	if (!all) {
		return NULL;
	}

	RzList *sections = rz_list_new();
	RzList *segments = rz_list_new();
	RzBinSection *section, *segment;
	RzListIter *iter;

	void **it;
	rz_pvector_foreach (all, it) {
		section = *it;
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
 * \param   pvector  The pvector of strings to initialize the database with
 *
 * \return  On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzBinStrDb *rz_bin_string_database_new(RZ_NULLABLE RZ_OWN RzPVector /*<RzBinString *>*/ *pvector) {
	RzBinStrDb *db = RZ_NEW0(RzBinStrDb);
	if (!db) {
		RZ_LOG_ERROR("rz_bin: Cannot allocate RzBinStrDb\n");
		rz_pvector_free(pvector);
		return NULL;
	}

	db->pvec = pvector ? pvector : rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	db->phys = ht_up_new(NULL, NULL);
	db->virt = ht_up_new(NULL, NULL);
	if (!db->pvec || !db->phys || !db->virt) {
		RZ_LOG_ERROR("rz_bin: Cannot allocate RzBinStrDb internal data structure.\n");
		goto fail;
	}

	void **it;
	RzBinString *bstr;
	rz_pvector_foreach (pvector, it) {
		bstr = *it;
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
	rz_pvector_free(db->pvec);
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

	if (!rz_pvector_push(db->pvec, bstr)) {
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
	rz_pvector_remove_data(db->pvec, bstr);
	return true;
}
