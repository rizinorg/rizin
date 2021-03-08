// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_io.h>
#include <config.h>
#include "i/private.h"

RZ_LIB_VERSION(rz_bin);

#define DB a->sdb;
#define RBINLISTFREE(x) \
	if (x) { \
		rz_list_free(x); \
		(x) = NULL; \
	}

#define ARCHS_KEY "archs"

#if !defined(RZ_BIN_STATIC_PLUGINS)
#define RZ_BIN_STATIC_PLUGINS 0
#endif
#if !defined(RZ_BIN_XTR_STATIC_PLUGINS)
#define RZ_BIN_XTR_STATIC_PLUGINS 0
#endif
#if !defined(RZ_BIN_LDR_STATIC_PLUGINS)
#define RZ_BIN_LDR_STATIC_PLUGINS 0
#endif

static RzBinPlugin *bin_static_plugins[] = { RZ_BIN_STATIC_PLUGINS, NULL };
static RzBinXtrPlugin *bin_xtr_static_plugins[] = { RZ_BIN_XTR_STATIC_PLUGINS, NULL };
static RzBinLdrPlugin *bin_ldr_static_plugins[] = { RZ_BIN_LDR_STATIC_PLUGINS, NULL };

static int __getoffset(RzBin *bin, int type, int idx) {
	RzBinFile *a = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(a);
	if (plugin && plugin->get_offset) {
		return plugin->get_offset(a, type, idx);
	}
	return -1;
}

static const char *__getname(RzBin *bin, int type, int idx, bool sd) {
	RzBinFile *a = rz_bin_cur(bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(a);
	if (plugin && plugin->get_name) {
		return plugin->get_name(a, type, idx, sd);
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

RZ_API const char *rz_bin_string_type(int type) {
	switch (type) {
	case 'a': return "ascii";
	case 'u': return "utf8";
	case 'w': return "utf16le";
	case 'W': return "utf32le";
	case 'b': return "base64";
	}
	return "ascii"; // XXX
}

RZ_API void rz_bin_xtrdata_free(void /*RzBinXtrData*/ *data_) {
	RzBinXtrData *data = data_;
	rz_return_if_fail(data);
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

RZ_API RzList *rz_bin_raw_strings(RzBinFile *bf, int min) {
	rz_return_val_if_fail(bf, NULL);
	return rz_bin_file_get_strings(bf, min, 0, 2);
}

RZ_API RzList *rz_bin_dump_strings(RzBinFile *bf, int min, int raw) {
	rz_return_val_if_fail(bf, NULL);
	return rz_bin_file_get_strings(bf, min, 1, raw);
}

RZ_API void rz_bin_options_init(RzBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr) {
	memset(opt, 0, sizeof(*opt));
	opt->baseaddr = baseaddr;
	opt->loadaddr = loadaddr;
	opt->fd = fd;
	opt->rawstr = rawstr;
}

RZ_API void rz_bin_arch_options_init(RzBinArchOptions *opt, const char *arch, int bits) {
	opt->arch = arch ? arch : RZ_SYS_ARCH;
	opt->bits = bits ? bits : RZ_SYS_BITS;
}

RZ_API void rz_bin_file_hash_free(RzBinFileHash *fhash) {
	if (fhash) {
		RZ_FREE(fhash->type);
		RZ_FREE(fhash->hex);
		free(fhash);
	}
}

RZ_API void rz_bin_info_free(RzBinInfo *rb) {
	if (!rb) {
		return;
	}

	rz_list_free(rb->file_hashes);
	free(rb->intrp);
	free(rb->file);
	free(rb->type);
	free(rb->bclass);
	free(rb->rclass);
	free(rb->arch);
	free(rb->cpu);
	free(rb->machine);
	free(rb->os);
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
		res->classname = RZ_STR_DUP(o->classname);
		res->descriptor = RZ_STR_DUP(o->descriptor);
	}
	return res;
}

RZ_API void rz_bin_import_free(void *_imp) {
	RzBinImport *imp = (RzBinImport *)_imp;
	if (imp) {
		RZ_FREE(imp->name);
		RZ_FREE(imp->libname);
		RZ_FREE(imp->classname);
		RZ_FREE(imp->descriptor);
		free(imp);
	}
}

RZ_API const char *rz_bin_symbol_name(RzBinSymbol *s) {
	if (s->dup_count) {
		return sdb_fmt("%s_%d", s->name, s->dup_count);
	}
	return s->name;
}

RZ_API RzBinSymbol *rz_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (sym) {
		sym->name = name ? strdup(name) : NULL;
		sym->paddr = paddr;
		sym->vaddr = vaddr;
	}
	return sym;
}

RZ_API void rz_bin_symbol_free(void *_sym) {
	RzBinSymbol *sym = (RzBinSymbol *)_sym;
	if (sym) {
		free(sym->name);
		free(sym->libname);
		free(sym->classname);
		free(sym);
	}
}

RZ_API void rz_bin_string_free(void *_str) {
	RzBinString *str = (RzBinString *)_str;
	if (str) {
		free(str->string);
		free(str);
	}
}

// XXX - change this to RzBinObject instead of RzBinFile
// makes no sense to pass in a binfile and set the RzBinObject
// kinda a clunky functions
// XXX - this is a rather hacky way to do things, there may need to be a better
// way.
RZ_API bool rz_bin_open(RzBin *bin, const char *file, RzBinOptions *opt) {
	rz_return_val_if_fail(bin && bin->iob.io && opt, false);

	RzIOBind *iob = &(bin->iob);
	if (!iob->desc_get(iob->io, opt->fd)) {
		opt->fd = iob->fd_open(iob->io, file, RZ_PERM_R, 0644);
	}
	if (opt->fd < 0) {
		eprintf("Couldn't open bin for file '%s'\n", file);
		return false;
	}
	opt->sz = 0;
	opt->pluginname = NULL;
	return rz_bin_open_io(bin, opt);
}

RZ_API bool rz_bin_reload(RzBin *bin, ut32 bf_id, ut64 baseaddr) {
	rz_return_val_if_fail(bin, false);

	RzBinFile *bf = rz_bin_file_find_by_id(bin, bf_id);
	if (!bf) {
		eprintf("rz_bin_reload: No file to reopen\n");
		return false;
	}
	RzBinOptions opt;
	rz_bin_options_init(&opt, bf->fd, baseaddr, bf->loadaddr, bin->rawstr);
	opt.filename = bf->file;

	bool res = rz_bin_open_buf(bin, bf->buf, &opt);
	rz_bin_file_delete(bin, bf->id);
	return res;
}

RZ_API bool rz_bin_open_buf(RzBin *bin, RzBuffer *buf, RzBinOptions *opt) {
	rz_return_val_if_fail(bin && opt, false);

	RzListIter *it;
	RzBinXtrPlugin *xtr;

	bin->rawstr = opt->rawstr;
	bin->file = opt->filename;
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
	}

	RzBinFile *bf = NULL;
	if (bin->use_xtr && !opt->pluginname) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		rz_list_foreach (bin->binxtrs, it, xtr) {
			if (!xtr->check_buffer) {
				eprintf("Missing check_buffer callback for '%s'\n", xtr->name);
				continue;
			}
			if (xtr->check_buffer(buf)) {
				if (xtr->extract_from_buffer || xtr->extractall_from_buffer ||
					xtr->extract_from_bytes || xtr->extractall_from_bytes) {
					bf = rz_bin_file_xtr_load_buffer(bin, xtr,
						bin->file, buf, opt->baseaddr, opt->loadaddr,
						opt->xtr_idx, opt->fd, bin->rawstr);
				}
			}
		}
	}
	if (!bf) {
		// Uncomment for this speedup: 20s vs 22s
		// RzBuffer *buf = rz_buf_new_slurp (bin->file);
		bf = rz_bin_file_new_from_buffer(bin, bin->file, buf, bin->rawstr,
			opt->baseaddr, opt->loadaddr, opt->fd, opt->pluginname);
		if (!bf) {
			return false;
		}
	}
	if (!rz_bin_file_set_cur_binfile(bin, bf)) {
		return false;
	}
	rz_id_storage_set(bin->ids, bin->cur, bf->id);
	return true;
}

RZ_API bool rz_bin_open_io(RzBin *bin, RzBinOptions *opt) {
	rz_return_val_if_fail(bin && opt && bin->iob.io, false);
	rz_return_val_if_fail(opt->fd >= 0 && (st64)opt->sz >= 0, false);

	RzIOBind *iob = &(bin->iob);
	RzIO *io = iob ? iob->io : NULL;

	bool is_debugger = iob->fd_is_dbg(io, opt->fd);
	const char *fname = iob->fd_get_name(io, opt->fd);
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
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
		buf = rz_buf_new_with_io(&bin->iob, opt->fd);
	}
	if (!buf) {
		return false;
	}

	if (!opt->sz) {
		opt->sz = rz_buf_size(buf);
	}

	// Slice buffer if necessary
	RzBuffer *slice = buf;
	if (!is_debugger && (opt->loadaddr != 0 || opt->sz != rz_buf_size(buf))) {
		slice = rz_buf_new_slice(buf, opt->loadaddr, opt->sz);
	} else if (is_debugger && opt->baseaddr != UT64_MAX && opt->baseaddr != 0) {
		slice = rz_buf_new_slice(buf, opt->baseaddr, opt->sz);
	}
	if (slice != buf) {
		rz_buf_free(buf);
		buf = slice;
	}

	opt->filename = fname;
	bool res = rz_bin_open_buf(bin, buf, opt);
	rz_buf_free(buf);
	return res;
}

RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_name(RzBin *bin, const char *name) {
	RzBinPlugin *plugin;
	RzListIter *it;

	rz_return_val_if_fail(bin && name, NULL);

	rz_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp(plugin->name, name)) {
			return plugin;
		}
	}
	return NULL;
}

RZ_API RzBinPlugin *rz_bin_get_binplugin_by_buffer(RzBin *bin, RzBuffer *buf) {
	RzBinPlugin *plugin;
	RzListIter *it;

	rz_return_val_if_fail(bin && buf, NULL);

	rz_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_buffer) {
			if (plugin->check_buffer(buf)) {
				return plugin;
			}
		}
	}
	return NULL;
}

RZ_IPI RzBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RzBin *bin, const char *name) {
	RzBinXtrPlugin *xtr;
	RzListIter *it;

	rz_return_val_if_fail(bin && name, NULL);

	// TODO: use a hashtable here
	rz_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp(xtr->name, name)) {
			return xtr;
		}
		// must be set to null
		xtr = NULL;
	}
	return NULL;
}

static void rz_bin_plugin_free(RzBinPlugin *p) {
	if (p && p->fini) {
		p->fini(NULL);
	}
	RZ_FREE(p);
}

// rename to rz_bin_plugin_add like the rest
RZ_API bool rz_bin_add(RzBin *bin, RzBinPlugin *foo) {
	RzListIter *it;
	RzBinPlugin *plugin;

	rz_return_val_if_fail(bin && foo, false);

	if (foo->init) {
		foo->init(bin->user);
	}
	rz_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp(plugin->name, foo->name)) {
			return false;
		}
	}
	plugin = RZ_NEW0(RzBinPlugin);
	memcpy(plugin, foo, sizeof(RzBinPlugin));
	rz_list_append(bin->plugins, plugin);
	return true;
}

RZ_API bool rz_bin_ldr_add(RzBin *bin, RzBinLdrPlugin *foo) {
	RzListIter *it;
	RzBinLdrPlugin *ldr;

	rz_return_val_if_fail(bin && foo, false);

	if (foo->init) {
		foo->init(bin->user);
	}
	// avoid duplicates
	rz_list_foreach (bin->binldrs, it, ldr) {
		if (!strcmp(ldr->name, foo->name)) {
			return false;
		}
	}
	rz_list_append(bin->binldrs, foo);
	return true;
}

RZ_API bool rz_bin_xtr_add(RzBin *bin, RzBinXtrPlugin *foo) {
	RzListIter *it;
	RzBinXtrPlugin *xtr;

	rz_return_val_if_fail(bin && foo, false);

	if (foo->init) {
		foo->init(bin->user);
	}
	// avoid duplicates
	rz_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp(xtr->name, foo->name)) {
			return false;
		}
	}
	rz_list_append(bin->binxtrs, foo);
	return true;
}

RZ_API void rz_bin_free(RzBin *bin) {
	if (bin) {
		bin->file = NULL;
		free(bin->force);
		free(bin->srcdir);
		free(bin->strenc);
		//rz_bin_free_bin_files (bin);
		rz_list_free(bin->binfiles);
		rz_list_free(bin->binxtrs);
		rz_list_free(bin->plugins);
		rz_list_free(bin->binldrs);
		sdb_free(bin->sdb);
		rz_id_storage_free(bin->ids);
		rz_str_constpool_fini(&bin->constpool);
		free(bin);
	}
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
	RzListIter *it;
	RzBinPlugin *bp;
	RzBinXtrPlugin *bx;

	rz_return_val_if_fail(bin && name, false);

	rz_list_foreach (bin->plugins, it, bp) {
		if (!rz_str_cmp(name, bp->name, strlen(name))) {
			continue;
		}
		return rz_bin_print_plugin_details(bin, bp, pj, json);
	}
	rz_list_foreach (bin->binxtrs, it, bx) {
		if (!rz_str_cmp(name, bx->name, strlen(name))) {
			continue;
		}
		__printXtrPluginDetails(bin, bx, json);
		return true;
	}

	eprintf("Cannot find plugin %s\n", name);
	return false;
}

RZ_API void rz_bin_list(RzBin *bin, PJ *pj, int format) {
	RzListIter *it;
	RzBinPlugin *bp;
	RzBinXtrPlugin *bx;
	RzBinLdrPlugin *ld;

	if (format == 'q') {
		rz_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf("%s\n", bp->name);
		}
		rz_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf("%s\n", bx->name);
		}
	} else if (format) {
		pj_o(pj);
		pj_ka(pj, "bin");
		rz_list_foreach (bin->plugins, it, bp) {
			pj_o(pj);
			pj_ks(pj, "name", bp->name);
			pj_ks(pj, "description", bp->desc);
			pj_ks(pj, "license", bp->license ? bp->license : "???");
			pj_end(pj);
		}
		pj_end(pj);
		pj_ka(pj, "xtr");
		rz_list_foreach (bin->binxtrs, it, bx) {
			pj_o(pj);
			pj_ks(pj, "name", bx->name);
			pj_ks(pj, "description", bx->desc);
			pj_ks(pj, "license", bx->license ? bx->license : "???");
			pj_end(pj);
		}
		pj_end(pj);
		pj_ka(pj, "ldr");
		rz_list_foreach (bin->binxtrs, it, ld) {
			pj_o(pj);
			pj_ks(pj, "name", ld->name);
			pj_ks(pj, "description", ld->desc);
			pj_ks(pj, "license", ld->license ? ld->license : "???");
			pj_end(pj);
		}
		pj_end(pj);
		pj_end(pj);
	} else {
		rz_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf("bin  %-11s %s (%s) %s %s\n",
				bp->name, bp->desc, bp->license ? bp->license : "???",
				bp->version ? bp->version : "",
				bp->author ? bp->author : "");
		}
		rz_list_foreach (bin->binxtrs, it, bx) {
			const char *name = strncmp(bx->name, "xtr.", 4) ? bx->name : bx->name + 3;
			bin->cb_printf("xtr  %-11s %s (%s)\n", name,
				bx->desc, bx->license ? bx->license : "???");
		}
		rz_list_foreach (bin->binldrs, it, ld) {
			const char *name = strncmp(ld->name, "ldr.", 4) ? ld->name : ld->name + 3;
			bin->cb_printf("ldr  %-11s %s (%s)\n", name,
				ld->desc, ld->license ? ld->license : "???");
		}
	}
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
	return o ? o->loadaddr : UT64_MAX;
}

// TODO: should be RzBinFile specific imho
RZ_API void rz_bin_set_baddr(RzBin *bin, ut64 baddr) {
	rz_return_if_fail(bin);
	RzBinFile *bf = rz_bin_cur(bin);
	RzBinObject *o = rz_bin_cur_object(bin);
	if (o) {
		if (!o->plugin || !o->plugin->baddr) {
			return;
		}
		ut64 file_baddr = o->plugin->baddr(bf);
		if (baddr == UT64_MAX) {
			o->baddr = file_baddr;
			o->baddr_shift = 0; // o->baddr; // - file_baddr;
		} else {
			if (file_baddr != UT64_MAX) {
				o->baddr = baddr;
				o->baddr_shift = baddr - file_baddr;
			}
		}
	} else {
		eprintf("Warning: This should be an assert probably.\n");
	}
	// XXX - update all the infos?
	// maybe in RzBinFile.rebase() ?
}

RZ_API RzBinAddr *rz_bin_get_sym(RzBin *bin, int sym) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	if (sym < 0 || sym >= RZ_BIN_SYM_LAST) {
		return NULL;
	}
	return o ? o->binsym[sym] : NULL;
}

// XXX: those accessors are redundant
RZ_API RzList *rz_bin_get_entries(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->entries : NULL;
}

RZ_API RzList *rz_bin_get_fields(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->fields : NULL;
}

RZ_API RzList *rz_bin_get_imports(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->imports : NULL;
}

RZ_API RzBinInfo *rz_bin_get_info(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->info : NULL;
}

RZ_API RzList *rz_bin_get_libs(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->libs : NULL;
}

static RzList *relocs_rbtree2list(RBNode *root) {
	RzList *res = rz_list_new();
	RzBinReloc *reloc;
	RBIter it;

	rz_rbtree_foreach (root, it, reloc, RzBinReloc, vrb) {
		rz_list_append(res, reloc);
	}
	return res;
}

RZ_API RBNode *rz_bin_patch_relocs(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinFile *bf = rz_bin_cur(bin);
	if (!bf || !bf->o) {
		return NULL;
	}
	return rz_bin_object_patch_relocs(bf, bf->o);
}

// return a list of <const RzBinReloc> that needs to be freed by the caller
RZ_API RzList *rz_bin_patch_relocs_list(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RBNode *root = rz_bin_patch_relocs(bin);
	return root ? relocs_rbtree2list(root) : NULL;
}

RZ_API RBNode *rz_bin_get_relocs(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->relocs : NULL;
}

// return a list of <const RzBinReloc> that needs to be freed by the caller
RZ_API RzList *rz_bin_get_relocs_list(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RBNode *root = rz_bin_get_relocs(bin);
	return root ? relocs_rbtree2list(root) : NULL;
}

RZ_API RzList *rz_bin_get_sections(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->sections : NULL;
}

RZ_API RzBinSection *rz_bin_get_section_at(RzBinObject *o, ut64 off, int va) {
	RzBinSection *section;
	RzListIter *iter;
	ut64 from, to;

	rz_return_val_if_fail(o, NULL);
	// TODO: must be O(1) .. use sdb here
	rz_list_foreach (o->sections, iter, section) {
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

RZ_API RzList *rz_bin_reset_strings(RzBin *bin) {
	RzBinFile *bf = rz_bin_cur(bin);

	if (!bf || !bf->o) {
		return NULL;
	}
	if (bf->o->strings) {
		rz_list_free(bf->o->strings);
		bf->o->strings = NULL;
	}
	ht_up_free(bf->o->strings_db);
	bf->o->strings_db = ht_up_new0();

	bf->rawstr = bin->rawstr;
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);

	if (plugin && plugin->strings) {
		bf->o->strings = plugin->strings(bf);
	} else {
		bf->o->strings = rz_bin_file_get_strings(bf, bin->minstrlen, 0, bf->rawstr);
	}
	if (bin->debase64) {
		rz_bin_object_filter_strings(bf->o);
	}
	return bf->o->strings;
}

RZ_API RzList *rz_bin_get_strings(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->strings : NULL;
}

RZ_API int rz_bin_is_string(RzBin *bin, ut64 va) {
	RzBinString *string;
	RzListIter *iter;
	RzList *list;
	if (!(list = rz_bin_get_strings(bin))) {
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

RZ_API RzList *rz_bin_get_symbols(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->symbols : NULL;
}

RZ_API RzList *rz_bin_get_mem(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->mem : NULL;
}

RZ_API int rz_bin_is_big_endian(RzBin *bin) {
	rz_return_val_if_fail(bin, -1);
	RzBinObject *o = rz_bin_cur_object(bin);
	return (o && o->info) ? o->info->big_endian : -1;
}

RZ_API int rz_bin_is_static(RzBin *bin) {
	rz_return_val_if_fail(bin, false);
	RzBinObject *o = rz_bin_cur_object(bin);
	if (o && o->libs && rz_list_length(o->libs) > 0) {
		return RZ_BIN_DBG_STATIC & o->info->dbg_info;
	}
	return true;
}

RZ_API RzBin *rz_bin_new(void) {
	int i;
	RzBinXtrPlugin *static_xtr_plugin;
	RzBinLdrPlugin *static_ldr_plugin;
	RzBin *bin = RZ_NEW0(RzBin);
	if (!bin) {
		return NULL;
	}
	if (!rz_str_constpool_init(&bin->constpool)) {
		goto trashbin;
	}
	bin->force = NULL;
	bin->filter_rules = UT64_MAX;
	bin->sdb = sdb_new0();
	bin->cb_printf = (PrintfCallback)printf;
	bin->plugins = rz_list_newf((RzListFree)rz_bin_plugin_free);
	bin->minstrlen = 0;
	bin->strpurge = NULL;
	bin->strenc = NULL;
	bin->want_dbginfo = true;
	bin->cur = NULL;
	bin->ids = rz_id_storage_new(0, ST32_MAX);

	/* bin parsers */
	bin->binfiles = rz_list_newf((RzListFree)rz_bin_file_free);
	for (i = 0; bin_static_plugins[i]; i++) {
		rz_bin_add(bin, bin_static_plugins[i]);
	}
	/* extractors */
	bin->binxtrs = rz_list_new();
	bin->binxtrs->free = free;
	for (i = 0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = RZ_NEW0(RzBinXtrPlugin);
		if (!static_xtr_plugin) {
			goto trashbin_binxtrs;
		}
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		if (!rz_bin_xtr_add(bin, static_xtr_plugin)) {
			free(static_xtr_plugin);
		}
	}
	/* loaders */
	bin->binldrs = rz_list_new();
	bin->binldrs->free = free;
	for (i = 0; bin_ldr_static_plugins[i]; i++) {
		static_ldr_plugin = RZ_NEW0(RzBinLdrPlugin);
		if (!static_ldr_plugin) {
			goto trashbin_binldrs;
		}
		*static_ldr_plugin = *bin_ldr_static_plugins[i];
		if (!rz_bin_ldr_add(bin, static_ldr_plugin)) {
			free(static_ldr_plugin);
		}
	}
	return bin;
trashbin_binldrs:
	rz_list_free(bin->binldrs);
trashbin_binxtrs:
	rz_list_free(bin->binxtrs);
	rz_list_free(bin->binfiles);
	rz_id_storage_free(bin->ids);
	rz_str_constpool_fini(&bin->constpool);
trashbin:
	free(bin);
	return NULL;
}

RZ_API bool rz_bin_use_arch(RzBin *bin, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail(bin && arch, false);

	RzBinFile *binfile = rz_bin_file_find_by_arch_bits(bin, arch, bits);
	if (!binfile) {
		RZ_LOG_WARN("Cannot find binfile with arch/bits %s/%d\n", arch, bits);
		return false;
	}

	RzBinObject *obj = rz_bin_object_find_by_arch_bits(binfile, arch, bits, name);
	if (!obj && binfile->xtr_data) {
		RzBinXtrData *xtr_data = rz_list_get_n(binfile->xtr_data, 0);
		if (xtr_data && !xtr_data->loaded) {
			if (!rz_bin_file_object_new_from_xtr_data(bin, binfile,
				    UT64_MAX, rz_bin_get_laddr(bin), xtr_data)) {
				return false;
			}
		}
		obj = binfile->o;
	}
	return rz_bin_file_set_obj(bin, binfile, obj);
}

RZ_API bool rz_bin_select(RzBin *bin, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail(bin, false);

	RzBinFile *cur = rz_bin_cur(bin);
	RzBinObject *obj = NULL;
	name = !name && cur ? cur->file : name;
	RzBinFile *binfile = rz_bin_file_find_by_arch_bits(bin, arch, bits);
	if (binfile && name) {
		obj = rz_bin_object_find_by_arch_bits(binfile, arch, bits, name);
	}
	return rz_bin_file_set_obj(bin, binfile, obj);
}

RZ_API int rz_bin_select_object(RzBinFile *binfile, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail(binfile, false);
	RzBinObject *obj = rz_bin_object_find_by_arch_bits(binfile, arch, bits, name);
	return rz_bin_file_set_obj(binfile->rbin, binfile, obj);
}

// NOTE: this functiona works as expected, but  we need to merge bfid and boid
RZ_API bool rz_bin_select_bfid(RzBin *bin, ut32 bf_id) {
	rz_return_val_if_fail(bin, false);
	RzBinFile *bf = rz_bin_file_find_by_id(bin, bf_id);
	return bf ? rz_bin_file_set_obj(bin, bf, NULL) : false;
}

static void list_xtr_archs(RzBin *bin, PJ *pj, int mode) {
	RzBinFile *binfile = rz_bin_cur(bin);
	if (binfile->xtr_data) {
		RzListIter *iter_xtr;
		RzBinXtrData *xtr_data;
		int bits, i = 0;
		char *arch, *machine;

		if (mode == 'j') {
			pj_ka(pj, "bins");
		}

		rz_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (!xtr_data || !xtr_data->metadata ||
				!xtr_data->metadata->arch) {
				continue;
			}
			arch = xtr_data->metadata->arch;
			machine = xtr_data->metadata->machine;
			bits = xtr_data->metadata->bits;
			switch (mode) {
			case 'q': // "iAq"
				bin->cb_printf("%s\n", arch);
				break;
			case 'j': { // "iAj"
				pj_o(pj);
				pj_ks(pj, "arch", arch);
				pj_ki(pj, "bits", bits);
				pj_kN(pj, "offset", xtr_data->offset);
				pj_kN(pj, "size", xtr_data->size);
				pj_ks(pj, "machine", machine);
				pj_end(pj);
				break;
			}
			default:
				bin->cb_printf("%03i 0x%08" PFMT64x
					       " %" PFMT64d " %s_%i %s\n",
					i++, xtr_data->offset,
					xtr_data->size, arch, bits,
					machine);
				break;
			}
		}

		if (mode == 'j') {
			pj_end(pj);
		}
	}
}

RZ_API void rz_bin_list_archs(RzBin *bin, PJ *pj, int mode) {
	rz_return_if_fail(bin);

	char unk[128];
	char archline[256];
	RzBinFile *binfile = rz_bin_cur(bin);
	const char *name = binfile ? binfile->file : NULL;
	int narch = binfile ? binfile->narch : 0;

	//are we with xtr format?
	if (binfile && binfile->curxtr) {
		list_xtr_archs(bin, pj, mode);
		return;
	}
	Sdb *binfile_sdb = binfile ? binfile->sdb : NULL;
	if (!binfile_sdb) {
		//	eprintf ("Cannot find SDB!\n");
		return;
	}
	if (!binfile) {
		//	eprintf ("Binary format not currently loaded!\n");
		return;
	}
	sdb_unset(binfile_sdb, ARCHS_KEY, 0);
	RzBinFile *nbinfile = rz_bin_file_find_by_name(bin, name);
	if (!nbinfile) {
		return;
	}
	RzTable *table = rz_table_new();
	const char *fmt = "dXnss";
	if (mode == 'j') {
		pj_ka(pj, "bins");
	}
	RzBinObject *obj = nbinfile->o;
	RzBinInfo *info = obj->info;
	char bits = info ? info->bits : 0;
	ut64 boffset = obj->boffset;
	ut64 obj_size = obj->obj_size;
	const char *arch = info ? info->arch : NULL;
	const char *machine = info ? info->machine : "unknown_machine";
	const char *h_flag = info ? info->head_flag : NULL;
	char *str_fmt;
	if (!arch) {
		snprintf(unk, sizeof(unk), "unk_0");
		arch = unk;
	}
	rz_table_hide_header(table);
	rz_table_set_columnsf(table, fmt, "num", "offset", "size", "arch", "machine", NULL);

	if (info && narch > 1) {
		switch (mode) {
		case 'q':
			bin->cb_printf("%s\n", arch);
			break;
		case 'j':
			pj_o(pj);
			pj_ks(pj, "arch", arch);
			pj_ki(pj, "bits", bits);
			pj_kn(pj, "offset", boffset);
			pj_kn(pj, "size", obj_size);
			if (!strcmp(arch, "mips")) {
				pj_ks(pj, "isa", info->cpu);
				pj_ks(pj, "features", info->features);
			}
			if (machine) {
				pj_ks(pj, "machine", machine);
			}
			pj_end(pj);
			break;
		default:
			str_fmt = h_flag && strcmp(h_flag, "unknown_flag") ? sdb_fmt("%s_%i %s", arch, bits, h_flag)
									   : sdb_fmt("%s_%i", arch, bits);
			rz_table_add_rowf(table, fmt, 0, boffset, obj_size, str_fmt, machine);
			bin->cb_printf("%s", rz_table_tostring(table));
		}
		snprintf(archline, sizeof(archline) - 1,
			"0x%08" PFMT64x ":%" PFMT64u ":%s:%d:%s",
			boffset, obj_size, arch, bits, machine);
		/// xxx machine not exported?
		//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
	} else {
		if (info) {
			switch (mode) {
			case 'q':
				bin->cb_printf("%s\n", arch);
				break;
			case 'j':
				pj_o(pj);
				pj_ks(pj, "arch", arch);
				pj_ki(pj, "bits", bits);
				pj_kn(pj, "offset", boffset);
				pj_kn(pj, "size", obj_size);
				if (!strcmp(arch, "mips")) {
					pj_ks(pj, "isa", info->cpu);
					pj_ks(pj, "features", info->features);
				}
				if (machine) {
					pj_ks(pj, "machine", machine);
				}
				pj_end(pj);
				break;
			default:
				str_fmt = h_flag && strcmp(h_flag, "unknown_flag") ? sdb_fmt("%s_%i %s", arch, bits, h_flag)
										   : sdb_fmt("%s_%i", arch, bits);
				rz_table_add_rowf(table, fmt, 0, boffset, obj_size, str_fmt, "");
				bin->cb_printf("%s", rz_table_tostring(table));
			}
			snprintf(archline, sizeof(archline),
				"0x%08" PFMT64x ":%" PFMT64u ":%s:%d",
				boffset, obj_size, arch, bits);
		} else if (nbinfile && mode) {
			switch (mode) {
			case 'q':
				bin->cb_printf("%s\n", arch);
				break;
			case 'j':
				pj_o(pj);
				pj_ks(pj, "arch", arch);
				pj_ki(pj, "bits", bits);
				pj_kn(pj, "offset", boffset);
				pj_kn(pj, "size", obj_size);
				if (machine) {
					pj_ks(pj, "machine", machine);
				}
				pj_end(pj);
				break;
			default:
				rz_table_add_rowf(table, fmt, 0, boffset, obj_size, "", "");
				bin->cb_printf("%s", rz_table_tostring(table));
			}
			snprintf(archline, sizeof(archline),
				"0x%08" PFMT64x ":%" PFMT64u ":%s:%d",
				boffset, obj_size, "unk", 0);
		} else {
			eprintf("Error: Invalid RzBinFile.\n");
		}
		//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
	}
	if (mode == 'j') {
		pj_end(pj);
	}
	rz_table_free(table);
}

RZ_API void rz_bin_set_user_ptr(RzBin *bin, void *user) {
	bin->user = user;
}

static RzBinSection *__get_vsection_at(RzBin *bin, ut64 vaddr) {
	rz_return_val_if_fail(bin, NULL);
	if (!bin->cur) {
		return NULL;
	}
	return rz_bin_get_section_at(bin->cur->o, vaddr, true);
}

RZ_API void rz_bin_bind(RzBin *bin, RzBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = __getoffset;
		b->get_name = __getname;
		b->get_sections = rz_bin_get_sections;
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

RZ_API RzBuffer *rz_bin_package(RzBin *bin, const char *type, const char *file, RzList *files) {
	if (!strcmp(type, "zip")) {
		// XXX: implement me
		rz_warn_if_reached();
	} else if (!strcmp(type, "fat")) {
		// XXX: this should be implemented in the fat plugin, not here
		// XXX should pick the callback from the plugin list
		const char *f;
		RzListIter *iter;
		ut32 num;
		ut8 *num8 = (ut8 *)&num;
		RzBuffer *buf = rz_buf_new_file(file, O_RDWR | O_CREAT, 0644);
		if (!buf) {
			eprintf("Cannot open file %s - Permission Denied.\n", file);
			return NULL;
		}
		rz_buf_write_at(buf, 0, (const ut8 *)"\xca\xfe\xba\xbe", 4);
		int count = rz_list_length(files);

		num = rz_read_be32(&count);
		ut64 from = 0x1000;
		rz_buf_write_at(buf, 4, num8, 4);
		int off = 12;
		int item = 0;
		rz_list_foreach (files, iter, f) {
			size_t f_len = 0;
			ut8 *f_buf = (ut8 *)rz_file_slurp(f, &f_len);
			if (f_buf) {
				eprintf("ADD %s %" PFMT64u "\n", f, (ut64)f_len);
			} else {
				eprintf("Cannot open %s\n", f);
				free(f_buf);
				continue;
			}
			item++;
			/* CPU */
			num8[0] = f_buf[7];
			num8[1] = f_buf[6];
			num8[2] = f_buf[5];
			num8[3] = f_buf[4];
			rz_buf_write_at(buf, off - 4, num8, 4);
			/* SUBTYPE */
			num8[0] = f_buf[11];
			num8[1] = f_buf[10];
			num8[2] = f_buf[9];
			num8[3] = f_buf[8];
			rz_buf_write_at(buf, off, num8, 4);
			ut32 from32 = from;
			/* FROM */
			num = rz_read_be32(&from32);
			rz_buf_write_at(buf, off + 4, num8, 4);
			rz_buf_write_at(buf, from, f_buf, f_len);
			/* SIZE */
			num = rz_read_be32(&f_len);
			rz_buf_write_at(buf, off + 8, num8, 4);
			off += 20;
			from += f_len + (f_len % 0x1000);
			free(f_buf);
		}
		rz_buf_free(buf);
		return NULL;
	} else {
		eprintf("Usage: rz-bin -X [fat|zip] [filename] [files ...]\n");
	}
	return NULL;
}

RZ_API RzList * /*<RzBinClass>*/ rz_bin_get_classes(RzBin *bin) {
	rz_return_val_if_fail(bin, NULL);
	RzBinObject *o = rz_bin_cur_object(bin);
	return o ? o->classes : NULL;
}

/* returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise */
RZ_API ut64 rz_bin_get_vaddr(RzBin *bin, ut64 paddr, ut64 vaddr) {
	rz_return_val_if_fail(bin && paddr != UT64_MAX, UT64_MAX);

	if (!bin->cur) {
		return paddr;
	}
	/* hack to realign thumb symbols */
	if (bin->cur->o && bin->cur->o->info && bin->cur->o->info->arch) {
		if (bin->cur->o->info->bits == 16) {
			RzBinSection *s = rz_bin_get_section_at(bin->cur->o, paddr, false);
			// autodetect thumb
			if (s && (s->perm & RZ_PERM_X) && strstr(s->name, "text")) {
				if (!strcmp(bin->cur->o->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}
	return rz_bin_file_get_vaddr(bin->cur, paddr, vaddr);
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
	bin->force = (name && *name) ? strdup(name) : NULL;
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

RZ_API void rz_bin_load_filter(RzBin *bin, ut64 rules) {
	bin->filter_rules = rules;
}

/* RzBinField */
RZ_API RzBinField *rz_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named) {
	RzBinField *ptr = RZ_NEW0(RzBinField);
	if (ptr) {
		ptr->name = strdup(name);
		ptr->comment = (comment && *comment) ? strdup(comment) : NULL;
		ptr->format = (format && *format) ? strdup(format) : NULL;
		ptr->format_named = format_named;
		ptr->paddr = paddr;
		ptr->size = size;
		//	ptr->visibility = any default visibility?
		ptr->vaddr = vaddr;
	}
	return ptr;
}

// use void* to honor the RzListFree signature
RZ_API void rz_bin_field_free(void *_field) {
	RzBinField *field = (RzBinField *)_field;
	if (field) {
		free(field->name);
		free(field->comment);
		free(field->format);
		free(field);
	}
}

// method name too long
// RzBin.methFlagToString(RzBin.Method.CLASS)
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

RZ_IPI RzBinSection *rz_bin_section_new(const char *name) {
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (s) {
		s->name = name ? strdup(name) : NULL;
	}
	return s;
}

RZ_IPI void rz_bin_section_free(RzBinSection *bs) {
	if (bs) {
		free(bs->name);
		free(bs->format);
		free(bs);
	}
}

RZ_API RzBinFile *rz_bin_file_at(RzBin *bin, ut64 at) {
	RzListIter *it, *it2;
	RzBinFile *bf;
	RzBinSection *s;
	rz_list_foreach (bin->binfiles, it, bf) {
		// chk for baddr + size of no section is covering anything
		// we should honor maps not sections imho
		rz_list_foreach (bf->o->sections, it2, s) {
			if (at >= s->vaddr && at < (s->vaddr + s->vsize)) {
				return bf;
			}
		}
		if (at >= bf->o->baddr && at < (bf->o->baddr + bf->size)) {
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
