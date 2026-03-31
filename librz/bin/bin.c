// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_demangler.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_io.h>
#include "i/private.h"

// include both generated plugin lists.
#include <rz_bin_plugins.h>
#include <rz_bin_xtr_plugins.h>
#include <rz_util/rz_iterator.h>

RZ_LIB_VERSION(rz_bin);

#define DB a->sdb;
#define RBINLISTFREE(x) \
	if (x) { \
		rz_list_free(x); \
		(x) = NULL; \
	}

#define ARCHS_KEY "archs"

static RzBinPlugin *bin_static_plugins[] = { RZ_BIN_STATIC_PLUGINS };
static RzBinXtrPlugin *bin_xtr_static_plugins[] = { RZ_BIN_XTR_STATIC_PLUGINS };

static ut64 __getoffset(RzBin *bin, int type, int idx) {
	RzBinFile *a = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(a);
	if (plugin && plugin->get_offset) {
		return plugin->get_offset(a, type, idx);
	}
	return UT64_MAX;
}

static char *__getname(RzBin *bin, int type, int idx) {
	RzBinFile *a = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(a);
	if (plugin && plugin->get_name) {
		return plugin->get_name(a, type, idx);
	}
	return NULL;
}

// TODO: move these two function do a different file
RZ_API RzBinXtrData *rz_bin_xtrdata_new(RzBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RzBinXtrMetadata *metadata) {
	RzBinXtrData *data = RZ_NEW0(RzBinXtrData);
	if (data) {
		data->offset = offset;
		data->size = size;
		data->file_count = file_count;
		data->metadata = metadata;
		data->loaded = 0;
		// don't slice twice TODO. review this
		data->buf = rz_buf_ref(buf); // rz_buf_new_slice (buf, offset, size);
	}
	return data;
}

RZ_API void rz_bin_xtrdata_free(RZ_NULLABLE void /*RzBinXtrData*/ *data_) {
	if (!data_) {
		return;
	}
	RzBinXtrData *data = data_;
	if (data->metadata) {
		free(data->metadata->libname);
		free(data->metadata->arch);
		free(data->metadata->machine);
		free(data->metadata);
	}
	free(data->file);
	rz_buf_free(data->buf);
	free(data);
}

RZ_API void rz_bin_options_init(RzBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, bool patch_relocs) {
	memset(opt, 0, sizeof(*opt));
	opt->obj_opts.baseaddr = baseaddr;
	opt->obj_opts.loadaddr = loadaddr;
	opt->obj_opts.patch_relocs = patch_relocs;
	opt->obj_opts.elf_load_sections = true;
	opt->fd = fd;
}

RZ_API void rz_bin_arch_options_init(RzBinArchOptions *opt, const char *arch, int bits) {
	opt->arch = arch ? arch : RZ_SYS_ARCH;
	opt->bits = bits ? bits : RZ_SYS_BITS;
}

RZ_API void rz_bin_file_hash_free(RZ_NULLABLE RzBinFileHash *fhash) {
	if (!fhash) {
		return;
	}
	RZ_FREE(fhash->type);
	RZ_FREE(fhash->hex);
	free(fhash);
}

RZ_API void rz_bin_info_free(RZ_NULLABLE RzBinInfo *rb) {
	if (!rb) {
		return;
	}

	rz_pvector_free(rb->file_hashes);
	free(rb->intrp);
	free(rb->file);
	free(rb->type);
	free(rb->bclass);
	free(rb->rclass);
	free(rb->arch);
	free(rb->cpu);
	free(rb->machine);
	free(rb->os);
	free(rb->features);
	free(rb->subsystem);
	free(rb->default_cc);
	free(rb->rpath);
	free(rb->guid);
	free(rb->debug_file_name);
	free(rb->actual_checksum);
	free(rb->claimed_checksum);
	free(rb->compiler);
	free(rb->head_flag);
	free(rb);
}

RZ_API RzBinImport *rz_bin_import_clone(RzBinImport *o) {
	rz_return_val_if_fail(o, NULL);

	RzBinImport *res = rz_mem_dup(o, sizeof(*o));
	if (res) {
		res->name = RZ_STR_DUP(o->name);
		res->dname = RZ_STR_DUP(o->dname);
		res->libname = RZ_STR_DUP(o->libname);
		res->classname = RZ_STR_DUP(o->classname);
		res->descriptor = RZ_STR_DUP(o->descriptor);
		res->bind = o->bind;
		res->type = o->type;
		res->ordinal = o->ordinal;
	}
	return res;
}

RZ_API void rz_bin_import_free(RZ_NULLABLE RzBinImport *imp) {
	if (!imp) {
		return;
	}
	free(imp->name);
	free(imp->dname);
	free(imp->libname);
	free(imp->classname);
	free(imp->descriptor);
	free(imp);
}

RZ_API void rz_bin_resource_free(RZ_NULLABLE RzBinResource *res) {
	if (!res) {
		return;
	}
	free(res->name);
	free(res->time);
	free(res->type);
	free(res->language);
	free(res);
}

RZ_API RZ_OWN char *rz_bin_symbol_name(RZ_NONNULL RzBinSymbol *s) {
	rz_return_val_if_fail(s, NULL);
	if (s->dup_count) {
		return rz_str_newf("%s_%d", s->name, s->dup_count);
	}
	return rz_str_dup(s->name);
}

RZ_API RzBinSymbol *rz_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (sym) {
		sym->name = rz_str_dup(name);
		sym->paddr = paddr;
		sym->vaddr = vaddr;
	}
	return sym;
}

RZ_API void rz_bin_symbol_free(RZ_NULLABLE RzBinSymbol *sym) {
	if (!sym) {
		return;
	}

	free(sym->name);
	free(sym->dname);
	free(sym->libname);
	free(sym->classname);
	free(sym->visibility_str);
	free(sym);
}

RZ_API void rz_bin_reloc_free(RZ_NULLABLE RzBinReloc *reloc) {
	if (!reloc) {
		return;
	}
	rz_bin_import_free(reloc->import);
	rz_bin_symbol_free(reloc->symbol);
	free(reloc);
}

RZ_API void rz_bin_string_free(RZ_NULLABLE void *_str) {
	if (!_str) {
		return;
	}
	RzBinString *str = (RzBinString *)_str;
	free(str->string);
	free(str);
}

RZ_API RzBinFile *rz_bin_open(RzBin *bin, const char *file, RzBinOptions *opt) {
	rz_return_val_if_fail(bin && bin->iob.io && opt, NULL);

	RzIOBind *iob = &(bin->iob);
	if (!iob->desc_get(iob->io, opt->fd)) {
		opt->fd = iob->fd_open(iob->io, file, RZ_PERM_R, 0644);
	}
	if (opt->fd < 0) {
		RZ_LOG_ERROR("Couldn't open bin for file '%s'\n", file);
		return NULL;
	}
	opt->sz = 0;
	return rz_bin_open_io(bin, opt);
}

RZ_API RzBinFile *rz_bin_reload(RzBin *bin, RzBinFile *bf, ut64 baseaddr) {
	rz_return_val_if_fail(bin && bf, NULL);

	bool big_endian = bf->o ? bf->o->opts.big_endian : false;
	bool patch_relocs = bf->o ? bf->o->opts.patch_relocs : false;
	bool elf_load_sections = bf->o ? bf->o->opts.elf_load_sections : false;
	bool elf_checks_sections = bf->o ? bf->o->opts.elf_checks_sections : false;
	bool elf_checks_segments = bf->o ? bf->o->opts.elf_checks_segments : false;

	RzBinOptions opt;
	rz_bin_options_init(&opt, bf->fd, baseaddr, bf->loadaddr, patch_relocs);
	opt.obj_opts.elf_load_sections = elf_load_sections;
	opt.obj_opts.elf_checks_sections = elf_checks_sections;
	opt.obj_opts.elf_checks_segments = elf_checks_segments;
	opt.obj_opts.big_endian = big_endian;
	opt.filename = bf->file;
	rz_buf_seek(bf->buf, 0, RZ_BUF_SET);
	RzBinFile *nbf = rz_bin_open_buf(bin, bf->buf, &opt);
	rz_bin_file_delete(bin, bf);
	return nbf;
}

RZ_API RzBinFile *rz_bin_open_buf(RzBin *bin, RzBuffer *buf, RzBinOptions *opt) {
	rz_return_val_if_fail(bin && opt, NULL);

	RzIterator *it = ht_sp_as_iter(bin->binxtrs);
	RzBinXtrPlugin **val;

	bin->file = opt->filename;
	if (opt->obj_opts.loadaddr == UT64_MAX) {
		opt->obj_opts.loadaddr = 0;
	}

	RzBinFile *bf = NULL;
	if (bin->use_xtr && !opt->pluginname) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		rz_iterator_foreach(it, val) {
			RzBinXtrPlugin *xtr = *val;
			if (!xtr->check_buffer) {
				RZ_LOG_ERROR("Missing check_buffer callback for '%s'\n", xtr->name);
				continue;
			}
			if (xtr->check_buffer(buf)) {
				if (xtr->extract_from_buffer || xtr->extractall_from_buffer ||
					xtr->extract_from_bytes || xtr->extractall_from_bytes) {
					bf = rz_bin_file_xtr_load_buffer(bin, xtr,
						bin->file, buf, &opt->obj_opts,
						opt->xtr_idx, opt->fd);
				}
			}
		}
	}
	rz_iterator_free(it);
	if (!bf) {
		// Uncomment for this speedup: 20s vs 22s
		// RzBuffer *buf = rz_buf_new_slurp (bin->file);
		bf = rz_bin_file_new_from_buffer(bin, bin->file, buf,
			&opt->obj_opts, opt->fd, opt->pluginname);
		if (!bf) {
			return NULL;
		}
	}
	rz_bin_file_set_obj(bf, bf->o);
	rz_bin_set_cur_binfile(bin, bf);
	rz_id_storage_set(bin->ids, bin->cur, bf->id);
	return bf;
}

RZ_API RzBinFile *rz_bin_open_io(RzBin *bin, RzBinOptions *opt) {
	rz_return_val_if_fail(bin && opt && bin->iob.io, NULL);
	rz_return_val_if_fail(opt->fd >= 0 && (st64)opt->sz >= 0, NULL);

	RzIOBind *iob = &(bin->iob);
	RzIO *io = iob ? iob->io : NULL;

	bool is_debugger = iob->fd_is_dbg(io, opt->fd);
	const char *fname = iob->fd_get_name(io, opt->fd);
	if (opt->obj_opts.loadaddr == UT64_MAX) {
		opt->obj_opts.loadaddr = 0;
	}

	// Create RzBuffer from the opened file
	// When debugging something, we want to open the backed file because
	// not all binary info are mapped in the virtual space. If that is not
	// possible (e.g. remote file) just try to load bin info from the
	// debugee process.
	RzBuffer *buf = NULL;
	if (is_debugger) {
		buf = rz_buf_new_file(fname, O_RDONLY, 0);
		is_debugger = false;
	}
	if (!buf) {
		buf = rz_buf_new_with_io_fd(&bin->iob, opt->fd);
	}
	if (!buf) {
		return NULL;
	}

	if (!opt->sz) {
		opt->sz = rz_buf_size(buf);
	}

	// Slice buffer if necessary
	RzBuffer *slice = buf;
	if (!is_debugger && (opt->obj_opts.loadaddr != 0 || opt->sz != rz_buf_size(buf))) {
		slice = rz_buf_new_slice(buf, opt->obj_opts.loadaddr, opt->sz);
	} else if (is_debugger && opt->obj_opts.baseaddr != UT64_MAX && opt->obj_opts.baseaddr != 0) {
		slice = rz_buf_new_slice(buf, opt->obj_opts.baseaddr, opt->sz);
	}
	if (slice != buf) {
		rz_buf_free(buf);
		buf = slice;
	}

	opt->filename = fname;
	RzBinFile *bf = rz_bin_open_buf(bin, buf, opt);
	rz_buf_free(buf);
	return bf;
}

RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_name(RzBin *bin, const char *name) {
	rz_return_val_if_fail(bin && name, NULL);

	bool found = false;
	RzBinPlugin *plugin = ht_sp_find(bin->plugins, name, &found);
	if (found) {
		return plugin;
	}
	return NULL;
}

static RZ_OWN RzStrBuf *join_plugin_names(const RzPVector /*<char *>*/ *plugin_names) {
	RzStrBuf *result = rz_strbuf_new("");
	if (!result) {
		return NULL;
	}
	void **it = NULL;
	ut32 idx = 0;
	rz_pvector_enumerate (plugin_names, it, idx) {
		const char *name = *it;
		rz_strbuf_append(result, name);
		rz_strbuf_append(result, idx < rz_pvector_len(plugin_names) - 1 ? "," : "\0");
	}
	return result;
}

/**
 * \brief Iterates through the registered bin plugins and selects one which can open the file contained in \p buf.
 *
 * \param bin bin context.
 * \param buf buffer holding the contents of an input file.
 * \return returns a pointer to a `RzBinPlugin` of a compatible plugin (if found), NULL otherwise.
 */
RZ_API RzBinPlugin *rz_bin_get_binplugin_by_buffer(RzBin *bin, RzBuffer *buf) {
	rz_return_val_if_fail(bin && buf, NULL);

	RzPVector /*<char *>*/ *compatible_plugins = rz_pvector_new((RzPVectorFree)free);
	if (!compatible_plugins) {
		return NULL;
	}
	RzIterator *it = ht_sp_as_iter_keys(bin->plugins);
	if (!it) {
		rz_pvector_free(compatible_plugins);
		return NULL;
	}
	// Iterate all plugins and save compatible plugins to `compatible_plugins`
	char **key;
	rz_iterator_foreach(it, key) {
		bool found = false;
		RzBinPlugin *plugin = (RzBinPlugin *)ht_sp_find(bin->plugins, *key, &found);
		if (!found) {
			rz_warn_if_reached();
			continue;
		}
		if (plugin->check_buffer && plugin->check_buffer(buf)) {
			rz_pvector_push(compatible_plugins, rz_str_dup(*key));
		}
	}
	rz_iterator_free(it);

	if (rz_pvector_empty(compatible_plugins)) {
		rz_pvector_free(compatible_plugins);
		return NULL;
	}
	const char *default_plugin = rz_pvector_at(compatible_plugins, 0);
	if (rz_pvector_len(compatible_plugins) > 1) {
		RzStrBuf *compatible_plugin_list = join_plugin_names(compatible_plugins);
		RZ_LOG_WARN("The input file can be opened by multiple binary plugins (%s). The '%s' plugin will be used by default.\n",
			compatible_plugin_list ? rz_strbuf_get(compatible_plugin_list) : "", default_plugin);
		rz_strbuf_free(compatible_plugin_list);
	}
	RzBinPlugin *result = (RzBinPlugin *)ht_sp_find(bin->plugins, default_plugin, NULL);
	rz_pvector_free(compatible_plugins);
	return result;
}

RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_filename(RzBin *bin) {
	RzIterator *it = ht_sp_as_iter(bin->plugins);
	RzBinPlugin **val;

	rz_return_val_if_fail(bin, NULL);

	const char *filename = strrchr(bin->file, RZ_SYS_DIR[0]);
	filename = filename ? filename + 1 : bin->file;
	rz_iterator_foreach(it, val) {
		RzBinPlugin *plugin = *val;
		if (plugin->check_filename) {
			if (plugin->check_filename(filename)) {
				rz_iterator_free(it);
				return plugin;
			}
		}
	}
	rz_iterator_free(it);
	return NULL;
}

RZ_IPI RzBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RzBin *bin, const char *name) {
	rz_return_val_if_fail(bin && name, NULL);

	bool found = false;
	RzBinXtrPlugin *xtr = ht_sp_find(bin->binxtrs, name, &found);
	if (found) {
		return xtr;
	}
	return NULL;
}

RZ_API bool rz_bin_plugin_add(RzBin *bin, RZ_NONNULL RzBinPlugin *plugin) {
	rz_return_val_if_fail(bin && plugin, false);
	if (!ht_sp_insert(bin->plugins, plugin->name, plugin)) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
	}
	return true;
}

RZ_API bool rz_bin_plugin_del(RzBin *bin, RZ_NONNULL RzBinPlugin *plugin) {
	rz_return_val_if_fail(bin && plugin, false);

	RzListIter *it, *tmp;
	RzBinFile *bf;

	rz_list_foreach_safe (bin->binfiles, it, tmp, bf) {
		if (bf->o && bf->o->plugin == plugin) {
			rz_bin_file_delete(bin, bf);
		}
	}
	return ht_sp_delete(bin->plugins, plugin->name);
}

RZ_API bool rz_bin_xtr_plugin_add(RzBin *bin, RZ_NONNULL RzBinXtrPlugin *plugin) {
	rz_return_val_if_fail(bin && plugin, false);

	if (!ht_sp_insert(bin->binxtrs, plugin->name, plugin)) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
	}
	if (plugin->init) {
		plugin->init(bin->user);
	}
	return true;
}

static bool plugin_fini(RzBin *bin, RzBinXtrPlugin *p) {
	return !p->fini || p->fini(bin->user);
}

RZ_API bool rz_bin_xtr_plugin_del(RzBin *bin, RZ_NONNULL RzBinXtrPlugin *plugin) {
	rz_return_val_if_fail(bin && plugin, false);

	RzListIter *it, *tmp;
	RzBinFile *bf;

	rz_list_foreach_safe (bin->binfiles, it, tmp, bf) {
		if (bf->curxtr == plugin) {
			rz_bin_file_delete(bin, bf);
			if (!plugin_fini(bin, plugin)) {
				return false;
			}
		}
	}
	return ht_sp_delete(bin->binxtrs, plugin->name);
}

RZ_API void rz_bin_free(RZ_NULLABLE RzBin *bin) {
	if (!bin) {
		return;
	}
	bin->file = NULL;
	free(bin->force);
	free(bin->srcdir);
	// rz_bin_free_bin_files (bin);
	rz_list_free(bin->binfiles);

	RzIterator *it = ht_sp_as_iter(bin->binxtrs);
	RzBinXtrPlugin **val;
	rz_iterator_foreach(it, val) {
		RzBinXtrPlugin *p = *val;
		plugin_fini(bin, p);
	}
	rz_iterator_free(it);
	ht_sp_free(bin->binxtrs);
	ht_sp_free(bin->plugins);
	rz_list_free(bin->default_hashes);
	sdb_free(bin->sdb);
	rz_id_storage_free(bin->ids);
	rz_hash_free(bin->hash);
	rz_event_free(bin->event);
	rz_str_constpool_fini(&bin->constpool);
	rz_demangler_free(bin->demangler);
	free(bin);
}

static bool rz_bin_print_plugin_details(RzBin *bin, RzBinPlugin *bp, PJ *pj, int json) {
	if (json == 'q') {
		bin->cb_printf("%s\n", bp->name);
	} else if (json) {
		pj_o(pj);
		pj_ks(pj, "name", bp->name);
		pj_ks(pj, "description", bp->desc);
		pj_ks(pj, "license", bp->license ? bp->license : "???");
		pj_end(pj);
	} else {
		bin->cb_printf("Name: %s\n", bp->name);
		bin->cb_printf("Description: %s\n", bp->desc);
		if (bp->license) {
			bin->cb_printf("License: %s\n", bp->license);
		}
		if (bp->version) {
			bin->cb_printf("Version: %s\n", bp->version);
		}
		if (bp->author) {
			bin->cb_printf("Author: %s\n", bp->author);
		}
	}
	return true;
}

static void __printXtrPluginDetails(RzBin *bin, RzBinXtrPlugin *bx, int json) {
	if (json == 'q') {
		bin->cb_printf("%s\n", bx->name);
	} else if (json) {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		pj_o(pj);
		pj_ks(pj, "name", bx->name);
		pj_ks(pj, "description", bx->desc);
		pj_ks(pj, "license", bx->license ? bx->license : "???");
		pj_end(pj);
		bin->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
	} else {
		bin->cb_printf("Name: %s\n", bx->name);
		bin->cb_printf("Description: %s\n", bx->desc);
		if (bx->license) {
			bin->cb_printf("License: %s\n", bx->license);
		}
	}
}

RZ_API bool rz_bin_list_plugin(RzBin *bin, const char *name, PJ *pj, int json) {
	RzBinPlugin *bp;
	RzBinXtrPlugin *bx;

	rz_return_val_if_fail(bin && name, false);

	bool found = false;
	bp = ht_sp_find(bin->plugins, name, &found);
	if (found) {
		return rz_bin_print_plugin_details(bin, bp, pj, json);
	}
	bx = ht_sp_find(bin->binxtrs, name, &found);
	if (found) {
		__printXtrPluginDetails(bin, bx, json);
		return true;
	}

	RZ_LOG_ERROR("Cannot find plugin %s\n", name);
	return false;
}

/* returns the base address of bin or UT64_MAX in case of errors */
RZ_API ut64 rz_bin_get_baddr(RzBin *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);
	return rz_bin_file_get_baddr(bin->cur);
}

/* returns the load address of bin or UT64_MAX in case of errors */
RZ_API ut64 rz_bin_get_laddr(RzBin *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->opts.loadaddr : UT64_MAX;
}

// TODO: should be RzBinFile specific imho
RZ_API void rz_bin_set_baddr(RzBin *bin, ut64 baddr) {
	rz_return_if_fail(bin);
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinObject *o = rz_bin_cur_object(bin);
	if (!o || !o->plugin || !o->plugin->baddr) {
		return;
	}
	ut64 file_baddr = o->plugin->baddr(bf);
	if (baddr == UT64_MAX) {
		o->opts.baseaddr = file_baddr;
		o->baddr_shift = 0; // o->baddr; // - file_baddr;
	} else if (file_baddr != UT64_MAX) {
		o->opts.baseaddr = baddr;
		o->baddr_shift = baddr - file_baddr;
	}
}

/**
 * \brief Find the binary section at offset \p off.
 *
 * \param o Reference to the \p RzBinObject instance
 * \param off Address to search
 * \param va When false the offset \p off is considered a physical address, otherwise a virtual address
 * \return Pointer to a \p RzBinSection containing the address
 */
RZ_API RZ_BORROW RzBinSection *rz_bin_get_section_at(RZ_NONNULL RzBinObject *o, ut64 off, bool va) {
	rz_return_val_if_fail(o, NULL);

	RzBinSection *section;
	void **iter;
	ut64 from, to;

	rz_pvector_foreach (o->sections, iter) {
		section = *iter;
		if (section->is_segment) {
			continue;
		}
		from = va ? rz_bin_object_addr_with_base(o, section->vaddr) : section->paddr;
		to = from + (va ? section->vsize : section->size);
		if (off >= from && off < to) {
			return section;
		}
	}
	return NULL;
}

/**
 * \brief Find the binary segment at offset \p off.
 *
 * \param o Reference to the \p RzBinObject instance
 * \param off Address to search
 * \param va When false the offset \p off is considered a physical address, otherwise a virtual address
 * \return Pointer to a \p RzBinSection containing the address
 */
RZ_API RZ_BORROW RzBinSection *rz_bin_get_segment_at(RZ_NONNULL RzBinObject *o, ut64 off, bool va) {
	rz_return_val_if_fail(o, NULL);

	RzBinSection *section;
	void **iter;
	ut64 from, to;

	rz_pvector_foreach (o->sections, iter) {
		section = *iter;
		if (!section->is_segment) {
			continue;
		}
		from = va ? rz_bin_object_addr_with_base(o, section->vaddr) : section->paddr;
		to = from + (va ? section->vsize : section->size);
		if (off >= from && off < to) {
			return section;
		}
	}
	return NULL;
}

/**
 * \brief Find the last binary map at offset \p off .
 *
 * This function returns the last binary map that contains offset \p off,
 * because it assumes that maps are sorted by priority, thus the last one will
 * be the most important one.
 *
 * \param o Reference to the \p RzBinObject instance
 * \param off Address to search
 * \param va When false the offset \p off is considered a physical address, otherwise a virtual address
 * \return Pointer to a \p RzBinMap containing the address
 */
RZ_API RZ_BORROW RzBinMap *rz_bin_object_get_map_at(RZ_NONNULL RzBinObject *o, ut64 off, bool va) {
	rz_return_val_if_fail(o, NULL);

	RzBinMap *map;
	void **iter;
	ut64 from, to;

	rz_pvector_foreach_prev(o->maps, iter) {
		map = *iter;
		from = va ? rz_bin_object_addr_with_base(o, map->vaddr) : map->paddr;
		to = from + (va ? map->vsize : map->psize);
		if (off >= from && off < to) {
			return map;
		}
	}
	return NULL;
}

/**
 * \brief Find the binary symbol at offset \p off.
 *
 * \param o Reference to the \p RzBinObject instance
 * \param off Address to search
 * \param va When false, the offset \p off is considered a physical address; otherwise, a virtual address
 * \return Pointer to a \p RzBinSymbol containing the address, or NULL if no symbol is found at the address
 */
RZ_API RZ_BORROW RzBinSymbol *rz_bin_object_get_symbol_at(RZ_NONNULL RzBinObject *o, ut64 off, bool va) {
	rz_return_val_if_fail(o, NULL);

	RzBinSymbol *sym;
	void **iter;

	if (va) {
		rz_pvector_foreach (o->symbols, iter) {
			sym = *iter;
			if (off == sym->vaddr) {
				return sym;
			}
		}
	} else {
		rz_pvector_foreach (o->symbols, iter) {
			sym = *iter;
			if (off == sym->paddr) {
				return sym;
			}
		}
	}
	return NULL;
}

/**
 * \brief Find all binary maps at offset \p off .
 *
 * \param o Reference to the \p RzBinObject instance
 * \param off Address to search
 * \param va When false the offset \p off is considered a physical address, otherwise a virtual address
 * \return Vector of \p RzBinMap pointers
 */
RZ_API RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_object_get_maps_at(RzBinObject *o, ut64 off, bool va) {
	rz_return_val_if_fail(o, NULL);

	RzBinMap *map;
	void **iter;
	ut64 from, to;

	RzPVector *res = rz_pvector_new(NULL);
	if (!res) {
		return NULL;
	}

	rz_pvector_foreach (o->maps, iter) {
		map = *iter;
		from = va ? rz_bin_object_addr_with_base(o, map->vaddr) : map->paddr;
		to = from + (va ? map->vsize : map->psize);
		if (off >= from && off < to) {
			rz_pvector_push(res, map);
		}
	}
	return res;
}

RZ_DEPRECATE RZ_API int rz_bin_is_static(RZ_NONNULL RzBin *bin) {
	rz_return_val_if_fail(bin, false);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? rz_bin_object_is_static(o) : false;
}

RZ_IPI void rz_bin_file_free(void /*RzBinFile*/ *_bf);

RZ_API RzBin *rz_bin_new(void) {
	RzBin *bin = RZ_NEW0(RzBin);
	if (!bin) {
		return NULL;
	}
	/* demanglers */
	bin->demangler = rz_demangler_new();
	if (!bin->demangler) {
		goto trashbin;
	}
	if (!rz_str_constpool_init(&bin->constpool)) {
		goto trashbin_demangler;
	}
	bin->event = rz_event_new(bin);
	if (!bin->event) {
		goto trashbin_constpool;
	}
	rz_bin_string_search_opt_init(&bin->str_search_cfg);
	bin->force = NULL;
	bin->filter_rules = UT64_MAX;
	bin->sdb = sdb_new0();
	bin->cb_printf = (PrintfCallback)printf;
	bin->strpurge = NULL;
	bin->want_dbginfo = true;
	bin->cur = NULL;
	bin->hash = rz_hash_new();
	if (!bin->hash) {
		goto trashbin_event;
	}

	bin->ids = rz_id_storage_new(0, ST32_MAX);

	/* bin parsers */
	bin->binfiles = rz_list_newf((RzListFree)rz_bin_file_free);

	bin->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(bin_static_plugins); ++i) {
		if (!ht_sp_insert(bin->plugins, bin_static_plugins[i]->name, bin_static_plugins[i])) {
			RZ_LOG_WARN("Plugin '%s' was already added.\n", bin_static_plugins[i]->name);
		}
	}
	/* extractors */
	bin->binxtrs = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(bin_xtr_static_plugins); ++i) {
		if (!ht_sp_insert(bin->binxtrs, bin_xtr_static_plugins[i]->name, bin_xtr_static_plugins[i])) {
			RZ_LOG_WARN("Plugin '%s' was already added.\n", bin_xtr_static_plugins[i]->name);
		}
	}

	return bin;

trashbin_event:
	rz_event_free(bin->event);
trashbin_constpool:
	rz_str_constpool_fini(&bin->constpool);
trashbin_demangler:
	rz_demangler_free(bin->demangler);
trashbin:
	free(bin);
	return NULL;
}

/**
 * \brief Sets the object file matching the \p arch, \p bits and optionally the \p machine and \p filename.
 *
 * \param bin The current RzBin instance.
 * \param arch The architecture of the binary file.
 * \param bits The architecture bits of the binary file.
 * \param machine (Optional) The machine of the binary file.
 * \param filename (Optional) The filename of the RzBinFile to load. Can be NULL.
 *
 * \return True if the binary file was successfully set according to the parameters. False otherwise.
 */
RZ_API bool rz_bin_use_arch(RzBin *bin, const char *arch, int bits, RZ_NULLABLE const char *machine, RZ_NULLABLE const char *filename) {
	rz_return_val_if_fail(bin && arch, false);

	RzBinFile *binfile = rz_bin_file_find_by_arch_bits(bin, arch, bits, machine, filename);
	if (!binfile) {
		RZ_LOG_WARN("Cannot find binfile with arch/bits %s/%d\n", arch, bits);
		return false;
	}

	RzBinObject *obj = rz_bin_object_find_by_arch_bits(binfile, arch, bits, machine, filename);
	if (!obj && binfile->xtr_data) {
		RzBinXtrData *xtr_data = rz_list_get_n(binfile->xtr_data, 0);
		if (xtr_data && !xtr_data->loaded) {
			RzBinObjectLoadOptions obj_opts = {
				.baseaddr = UT64_MAX,
				.loadaddr = rz_bin_get_laddr(bin)
			};
			if (!rz_bin_file_set_xtr_data_as_current_obj(bin, binfile, &obj_opts, xtr_data)) {
				return false;
			}
		}
		obj = binfile->o;
	}
	if (!rz_bin_file_set_obj(binfile, obj)) {
		return false;
	}
	return rz_bin_set_cur_binfile(bin, binfile);
}

/**
 * \brief Selects the binfile matching \p arch, \p bits and optionally \p machine
 * and \p filename and sets it as current binfile in RzBin.
 *
 * \param bin The current RzBin instance.
 * \param arch The architecture of the binary file.
 * \param bits The architecture bits of the binary file.
 * \param machine (Optional) The machine of the binary file.
 * \param filename (Optional) The filename of RzBinFile to load.
 *
 * \return True if the binary file was successfully set according to the parameters. False otherwise.
 */
RZ_API bool rz_bin_select(RzBin *bin, RZ_NONNULL const char *arch, int bits, RZ_NULLABLE const char *machine, RZ_NULLABLE const char *filename) {
	rz_return_val_if_fail(bin && arch, false);

	RzBinObject *obj = NULL;
	RzBinFile *binfile = rz_bin_file_find_by_arch_bits(bin, arch, bits, machine, filename);
	if (binfile) {
		obj = rz_bin_object_find_by_arch_bits(binfile, arch, bits, machine, filename);
	}
	if (!rz_bin_file_set_obj(binfile, obj)) {
		return NULL;
	}
	return rz_bin_set_cur_binfile(bin, binfile);
}

// NOTE: this functiona works as expected, but  we need to merge bfid and boid
RZ_API bool rz_bin_select_bfid(RzBin *bin, ut32 bf_id) {
	rz_return_val_if_fail(bin, false);
	RzBinFile *bf = rz_bin_file_find_by_id(bin, bf_id);
	if (!bf) {
		return false;
	}
	if (!rz_bin_file_set_obj(bf, bf->o)) {
		return false;
	}
	return rz_bin_set_cur_binfile(bin, bf);
}

RZ_API void rz_bin_set_user_ptr(RzBin *bin, void *user) {
	bin->user = user;
}

static RzBinSection *__get_vsection_at(RzBin *bin, ut64 vaddr) {
	rz_return_val_if_fail(bin, NULL);
	if (!bin->cur || !bin->cur->o) {
		return NULL;
	}
	return rz_bin_get_section_at(bin->cur->o, vaddr, true);
}

RZ_API void rz_bin_bind(RzBin *bin, RzBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = __getoffset;
		b->get_name = __getname;
		b->get_sections = rz_bin_object_get_sections_all;
		b->get_vsect_at = __get_vsection_at;
		b->demangle = rz_bin_demangle;
	}
}

RZ_API RzBuffer *rz_bin_create(RzBin *bin, const char *p,
	const ut8 *code, int codelen,
	const ut8 *data, int datalen,
	RzBinArchOptions *opt) {

	rz_return_val_if_fail(bin && p && opt, NULL);

	RzBinPlugin *plugin = rz_bin_get_binplugin_by_name(bin, p);
	if (!plugin) {
		RZ_LOG_WARN("Cannot find RzBin plugin named '%s'.\n", p);
		return NULL;
	}
	if (!plugin->create) {
		RZ_LOG_WARN("RzBin plugin '%s' does not implement \"create\" method.\n", p);
		return NULL;
	}
	codelen = RZ_MAX(codelen, 0);
	datalen = RZ_MAX(datalen, 0);
	return plugin->create(bin, code, codelen, data, datalen, opt);
}

RZ_API ut64 rz_bin_get_size(RzBin *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->size : 0;
}

RZ_API RzBinFile *rz_bin_cur(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	return bin->cur;
}

RZ_API RzBinObject *rz_bin_cur_object(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinFile *binfile = rz_bin_cur(bin);
	return binfile ? binfile->o : NULL;
}

RZ_API void rz_bin_force_plugin(RzBin *bin, const char *name) {
	rz_return_if_fail(bin);
	free(bin->force);
	bin->force = RZ_STR_ISNOTEMPTY(name) ? rz_str_dup(name) : NULL;
}

RZ_API const char *rz_bin_entry_type_string(int etype) {
	switch (etype) {
	case RZ_BIN_ENTRY_TYPE_PROGRAM:
		return "program";
	case RZ_BIN_ENTRY_TYPE_MAIN:
		return "main";
	case RZ_BIN_ENTRY_TYPE_INIT:
		return "init";
	case RZ_BIN_ENTRY_TYPE_FINI:
		return "fini";
	case RZ_BIN_ENTRY_TYPE_TLS:
		return "tls";
	case RZ_BIN_ENTRY_TYPE_PREINIT:
		return "preinit";
	}
	return NULL;
}

/**
 * \brief Returns a first possible entry point address of the object.
 * If no entry point could be determined, it just returns 0, which is also a valid address.
 *
 * If the object has entry points defined, it returns the first one.
 * If it doesn't it returns the start address of the first executable section.
 * Otherwise 0.
 *
 * It always prioritizes virtual addresses.
 *
 * \param obj The object file to get the entry point from.
 *
 * \return The entry point address of the binary.
 */
RZ_API ut64 rz_bin_get_first_entrypoint(RZ_NULLABLE RzBinObject *obj) {
	if (!obj) {
		return 0;
	} else if (obj->entries && rz_pvector_len(obj->entries) > 0) {
		// The binary loader specified entry points. Use the first one.
		const RzBinAddr *entry = rz_pvector_at(obj->entries, 0);
		ut64 addr = entry->vaddr ? entry->vaddr : entry->paddr;
		return addr;
	}
	const RzPVector *sections = rz_bin_object_get_sections_all(obj);
	if (!sections) {
		return 0;
	}
	// The binary loader did not specify entry points.
	// Fall back to the first executable section.
	void **iter;
	rz_pvector_foreach (sections, iter) {
		RzBinSection *s = *iter;
		if (s->perm & RZ_PERM_X) {
			ut64 addr = s->vaddr ? s->vaddr : s->paddr;
			return addr;
		}
	}
	return 0;
}

RZ_API void rz_bin_load_filter(RzBin *bin, ut64 rules) {
	bin->filter_rules = rules;
}

/* RzBinField */
RZ_API RzBinField *rz_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named) {
	RzBinField *ptr = RZ_NEW0(RzBinField);
	if (!ptr) {
		return NULL;
	}

	ptr->name = rz_str_dup(name);
	ptr->comment = rz_str_dup(comment);
	ptr->format = rz_str_dup(format);
	ptr->format_named = format_named;
	ptr->paddr = paddr;
	ptr->size = size;
	ptr->vaddr = vaddr;
	return ptr;
}

RZ_API void rz_bin_field_free(RZ_NULLABLE RzBinField *field) {
	if (!field) {
		return;
	}
	free(field->name);
	free(field->type);
	free(field->comment);
	free(field->format);
	free(field);
}

/* RzBinClassField */
RZ_API RzBinClassField *rz_bin_class_field_new(ut64 vaddr, ut64 paddr, const char *name, const char *classname, const char *libname, const char *type) {
	RzBinClassField *ptr = RZ_NEW0(RzBinClassField);
	if (!ptr) {
		return NULL;
	}

	ptr->vaddr = vaddr ? vaddr : UT64_MAX;
	ptr->paddr = paddr;
	ptr->name = rz_str_dup(name);
	ptr->classname = rz_str_dup(classname);
	ptr->libname = rz_str_dup(libname);
	ptr->type = rz_str_dup(type);
	return ptr;
}

RZ_API void rz_bin_class_field_free(RZ_NULLABLE RzBinClassField *field) {
	if (!field) {
		return;
	}
	free(field->name);
	free(field->classname);
	free(field->libname);
	free(field->type);
	free(field->visibility_str);
	free(field);
}

RZ_API const char *rz_bin_get_meth_flag_string(ut64 flag, bool compact) {
	switch (flag) {
	case RZ_BIN_METH_CLASS:
		return compact ? "c" : "class";
	case RZ_BIN_METH_STATIC:
		return compact ? "s" : "static";
	case RZ_BIN_METH_PUBLIC:
		return compact ? "p" : "public";
	case RZ_BIN_METH_PRIVATE:
		return compact ? "P" : "private";
	case RZ_BIN_METH_PROTECTED:
		return compact ? "r" : "protected";
	case RZ_BIN_METH_INTERNAL:
		return compact ? "i" : "internal";
	case RZ_BIN_METH_OPEN:
		return compact ? "o" : "open";
	case RZ_BIN_METH_FILEPRIVATE:
		return compact ? "e" : "fileprivate";
	case RZ_BIN_METH_FINAL:
		return compact ? "f" : "final";
	case RZ_BIN_METH_VIRTUAL:
		return compact ? "v" : "virtual";
	case RZ_BIN_METH_CONST:
		return compact ? "k" : "const";
	case RZ_BIN_METH_MUTATING:
		return compact ? "m" : "mutating";
	case RZ_BIN_METH_ABSTRACT:
		return compact ? "a" : "abstract";
	case RZ_BIN_METH_SYNCHRONIZED:
		return compact ? "y" : "synchronized";
	case RZ_BIN_METH_NATIVE:
		return compact ? "n" : "native";
	case RZ_BIN_METH_BRIDGE:
		return compact ? "b" : "bridge";
	case RZ_BIN_METH_VARARGS:
		return compact ? "g" : "varargs";
	case RZ_BIN_METH_SYNTHETIC:
		return compact ? "h" : "synthetic";
	case RZ_BIN_METH_STRICT:
		return compact ? "t" : "strict";
	case RZ_BIN_METH_MIRANDA:
		return compact ? "A" : "miranda";
	case RZ_BIN_METH_CONSTRUCTOR:
		return compact ? "C" : "constructor";
	case RZ_BIN_METH_DECLARED_SYNCHRONIZED:
		return compact ? "Y" : "declared_synchronized";
	default:
		return NULL;
	}
}

RZ_API void rz_bin_virtual_file_free(RZ_NULLABLE RzBinVirtualFile *vfile) {
	if (!vfile) {
		return;
	}
	if (vfile->buf_owned) {
		rz_buf_free(vfile->buf);
	}
	free(vfile->name);
	free(vfile);
}

/**
 * \brief Clones the virtual file. If the buffer associated with it is owned, it will also clone the buffer.
 * If it is not owned, it will copy the pointer.
 *
 * \param vfile The virtual file to clone.
 *
 * \return The virtual file clone or NULL in case of failure.
 */
RZ_API RZ_OWN RzBinVirtualFile *rz_bin_virtual_file_clone(RZ_BORROW RZ_NONNULL RzBinVirtualFile *vfile) {
	rz_return_val_if_fail(vfile, NULL);
	RzBinVirtualFile *clone = RZ_NEW0(RzBinVirtualFile);
	if (!clone) {
		return NULL;
	}
	clone->buf_owned = vfile->buf_owned;
	clone->buf = vfile->buf_owned ? rz_buf_new_with_buf(vfile->buf) : vfile->buf;
	if (!clone->buf) {
		rz_bin_virtual_file_free(clone);
		return NULL;
	}
	clone->name = rz_str_dup(vfile->name);
	if (!clone->name) {
		rz_bin_virtual_file_free(clone);
		return NULL;
	}
	return clone;
}

RZ_API void rz_bin_map_free(RZ_NULLABLE RzBinMap *map) {
	if (!map) {
		return;
	}
	free(map->vfile_name);
	free(map->name);
	free(map);
}

/**
 * \brief Clones an RzBinMap.
 *
 * \param map The map to clone.
 *
 * \return The clone of \p map or NULL in case of failure.
 */
RZ_API RZ_OWN RzBinMap *rz_bin_map_clone(RZ_NONNULL RzBinMap *map) {
	rz_return_val_if_fail(map, NULL);
	RzBinMap *clone = RZ_NEW0(RzBinMap);
	if (!clone) {
		return NULL;
	}
	rz_mem_copy(clone, sizeof(RzBinMap), map, sizeof(RzBinMap));
	clone->name = rz_str_dup(map->name);
	clone->vfile_name = map->vfile_name ? rz_str_dup(map->vfile_name) : NULL;
	return clone;
}

/**
 * \brief Create a pvector of RzBinMap from RzBinSections queried from the given file
 *
 * Some binary formats have a 1:1 correspondence of mapping and
 * their RzBinSections. This is not always the case (e.g. ELF)
 * but if it is, plugins can use this function as their maps callback,
 * which will generate mappings for sections.
 * */
RZ_API RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_maps_of_file_sections(RZ_NONNULL RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	if (!binfile->o || !binfile->o->plugin || !binfile->o->plugin->sections) {
		return NULL;
	}
	RzPVector *sections = binfile->o->plugin->sections(binfile);
	if (!sections) {
		return NULL;
	}
	RzPVector *r = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!r) {
		goto hcf;
	}
	RzBinSection *sec;
	void **it;
	rz_pvector_foreach (sections, it) {
		sec = *it;
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			goto hcf;
		}
		map->name = rz_str_dup(sec->name);
		map->paddr = sec->paddr;
		map->psize = sec->size;
		map->vaddr = sec->vaddr;
		map->vsize = sec->vsize;
		map->perm = sec->perm;
		rz_pvector_push(r, map);
	}
hcf:
	rz_pvector_free(sections);
	return r;
}

/**
 * \brief Create a pvector of RzBinSection from RzBinMaps
 *
 * Some binary formats have a 1:1 correspondence of mapping and
 * some of their RzBinSections, but also want to add some unmapped sections.
 * In this case, they can implement their mapped sections in their maps callback,
 * then in their sections callback use this function to create sections from them
 * and add some additional ones.
 * See also rz_bin_maps_of_file_sections() for the inverse, when no additional
 * sections should be added.
 * */
RZ_API RzPVector /*<RzBinSection *>*/ *rz_bin_sections_of_maps(RzPVector /*<RzBinMap *>*/ *maps) {
	rz_return_val_if_fail(maps, NULL);
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	void **it;
	RzBinMap *map;
	rz_pvector_foreach (maps, it) {
		map = *it;
		RzBinSection *sec = RZ_NEW0(RzBinSection);
		if (!sec) {
			break;
		}
		sec->name = rz_str_dup(map->name);
		sec->paddr = map->paddr;
		sec->size = map->psize;
		sec->vaddr = map->vaddr;
		sec->vsize = map->vsize;
		sec->perm = map->perm;
		rz_pvector_push(ret, sec);
	}
	return ret;
}

RZ_API RzBinSection *rz_bin_section_new(const char *name) {
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (s) {
		s->name = rz_str_dup(name);
	}
	return s;
}

RZ_API void rz_bin_section_free(RZ_NULLABLE RzBinSection *bs) {
	if (!bs) {
		return;
	}
	free(bs->name);
	free(bs);
}

static bool is_data_permission(ut32 permissions) {
	switch (permissions) {
	case RZ_PERM_R:
		/* fall-thru */
	case RZ_PERM_RX:
		/* fall-thru */
	case RZ_PERM_RW:
		return true;
	default:
		return false;
	}
}

/**
 * \brief      Checks whether the given section contains data
 *
 * \param      section  The section to test
 *
 * \return     Returns false on error or if is not a data section, otherwise true
 */
RZ_API bool rz_bin_section_is_data(RZ_NONNULL const RzBinSection *section) {
	rz_return_val_if_fail(section, false);
	if (section->size < 1) {
		return false;
	} else if (section->name && strstr(section->name, "data")) {
		return true;
	}
	return is_data_permission(section->perm & RZ_PERM_RWX);
}

/**
 * \brief      Checks whether the given map contains data
 *
 * \param      map  The map to test
 *
 * \return     Returns false on error or if is not a data map, otherwise true
 */
RZ_API bool rz_bin_map_is_data(RZ_NONNULL const RzBinMap *map) {
	rz_return_val_if_fail(map, false);
	if (map->psize < 1) {
		return false;
	} else if (map->name && strstr(map->name, "data")) {
		return true;
	}
	return is_data_permission(map->perm & RZ_PERM_RWX);
}

/**
 * \brief Converts the RzBinSection type to the string representation
 *
 * Some binary formats have a function interface called "section_type_to_string"
 * The returned string type name is different between formats
 *
 * \param bin RzBin instance
 * \param type A type field of the RzBinSection (differs between formats)
 * */
RZ_API RZ_OWN char *rz_bin_section_type_to_string(RzBin *bin, int type) {
	RzBinFile *a = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(a);
	if (plugin && plugin->section_type_to_string) {
		return plugin->section_type_to_string(type);
	}
	return NULL;
}

/**
 * \brief Converts the RzBinSection flags to a list of string representations
 *
 * Some binary formats have a function interface called "section_flag_to_rzlist"
 * The returned string flag names are different between formats
 *
 * \param bin RzBin instance
 * \param flag A flag field of the RzBinSection (differs between formats)
 * */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_bin_section_flag_to_list(RzBin *bin, ut64 flag) {
	RzBinFile *a = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(a);
	if (plugin && plugin->section_flag_to_rzlist) {
		return plugin->section_flag_to_rzlist(flag);
	}
	return NULL;
}

RZ_API RzBinFile *rz_bin_file_at(RzBin *bin, ut64 at) {
	RzListIter *it;
	RzBinFile *bf;
	rz_list_foreach (bin->binfiles, it, bf) {
		if (!bf->o) {
			continue;
		}
		RzBinMap *map = rz_bin_object_get_map_at(bf->o, at, true);
		if (map) {
			return bf;
		}
		if (at >= bf->o->opts.baseaddr && at < (bf->o->opts.baseaddr + bf->size)) {
			return bf;
		}
	}
	return NULL;
}

RZ_API RzBinTrycatch *rz_bin_trycatch_new(ut64 source, ut64 from, ut64 to, ut64 handler, ut64 filter) {
	RzBinTrycatch *tc = RZ_NEW0(RzBinTrycatch);
	if (tc) {
		tc->source = source;
		tc->from = from;
		tc->to = to;
		tc->handler = handler;
		tc->filter = filter;
	}
	return tc;
}

RZ_API void rz_bin_trycatch_free(RzBinTrycatch *tc) {
	free(tc);
}

/**
 * \brief Get a RzBinPlugin by name
 */
RZ_API const RzBinPlugin *rz_bin_plugin_get(RZ_NONNULL RzBin *bin, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bin && name, NULL);

	bool found = false;
	RzBinPlugin *bp = ht_sp_find(bin->plugins, name, &found);
	if (found) {
		return bp;
	}
	return NULL;
}

/**
 * \brief Get a RzBinXtrPlugin by name
 */
RZ_API const RzBinXtrPlugin *rz_bin_xtrplugin_get(RZ_NONNULL RzBin *bin, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bin && name, NULL);
	bool found = false;
	RzBinXtrPlugin *bp = ht_sp_find(bin->plugins, name, &found);
	if (found) {
		return bp;
	}
	return NULL;
}
