/* rizin - LGPL - Copyright 2009-2020 - pancake, nibble, dso */

#include <rz_bin.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_io.h>
#include <config.h>
#include "i/private.h"

R_LIB_VERSION (rz_bin);

#define DB a->sdb;
#define RBINLISTFREE(x)\
	if (x) { \
		rz_list_free (x);\
		(x) = NULL;\
	}

#define ARCHS_KEY "archs"

#if !defined(R_BIN_STATIC_PLUGINS)
#define R_BIN_STATIC_PLUGINS 0
#endif
#if !defined(R_BIN_XTR_STATIC_PLUGINS)
#define R_BIN_XTR_STATIC_PLUGINS 0
#endif
#if !defined(R_BIN_LDR_STATIC_PLUGINS)
#define R_BIN_LDR_STATIC_PLUGINS 0
#endif

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS, NULL };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS, NULL };
static RBinLdrPlugin *bin_ldr_static_plugins[] = { R_BIN_LDR_STATIC_PLUGINS, NULL };

static int __getoffset(RBin *bin, int type, int idx) {
	RBinFile *a = rz_bin_cur (bin);
	RBinPlugin *plugin = rz_bin_file_cur_plugin (a);
	if (plugin && plugin->get_offset) {
		return plugin->get_offset (a, type, idx);
	}
	return -1;
}

static const char *__getname(RBin *bin, int type, int idx, bool sd) {
	RBinFile *a = rz_bin_cur (bin);
	RBinPlugin *plugin = rz_bin_file_cur_plugin (a);
	if (plugin && plugin->get_name) {
		return plugin->get_name (a, type, idx, sd);
	}
	return NULL;
}

static ut64 binobj_a2b(RBinObject *o, ut64 addr) {
	return o ? addr + o->baddr_shift : addr;
}

// TODO: move these two function do a different file
RZ_API RBinXtrData *rz_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RBinXtrMetadata *metadata) {
	RBinXtrData *data = R_NEW0 (RBinXtrData);
	if (data) {
		data->offset = offset;
		data->size = size;
		data->file_count = file_count;
		data->metadata = metadata;
		data->loaded = 0;
// don't slice twice TODO. review this
		data->buf = rz_buf_ref (buf); // rz_buf_new_slice (buf, offset, size);
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

RZ_API void rz_bin_xtrdata_free(void /*RBinXtrData*/ *data_) {
	RBinXtrData *data = data_;
	rz_return_if_fail (data);
	if (data->metadata) {
		free (data->metadata->libname);
		free (data->metadata->arch);
		free (data->metadata->machine);
		free (data->metadata);
	}
	free (data->file);
	rz_buf_free (data->buf);
	free (data);
}

RZ_API RzList *rz_bin_raw_strings(RBinFile *bf, int min) {
	rz_return_val_if_fail (bf, NULL);
	return rz_bin_file_get_strings (bf, min, 0, 2);
}

RZ_API RzList *rz_bin_dump_strings(RBinFile *bf, int min, int raw) {
	rz_return_val_if_fail (bf, NULL);
	return rz_bin_file_get_strings (bf, min, 1, raw);
}

RZ_API void rz_bin_options_init(RBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr) {
	memset (opt, 0, sizeof (*opt));
	opt->baseaddr = baseaddr;
	opt->loadaddr = loadaddr;
	opt->fd = fd;
	opt->rawstr = rawstr;
}

RZ_API void rz_bin_arch_options_init(RBinArchOptions *opt, const char *arch, int bits) {
	opt->arch = arch? arch: R_SYS_ARCH;
	opt->bits = bits? bits: R_SYS_BITS;
}

RZ_API void rz_bin_file_hash_free(RBinFileHash *fhash) {
	if (fhash) {
		R_FREE (fhash->type);
		R_FREE (fhash->hex);
		free (fhash);
	}
}

RZ_API void rz_bin_info_free(RBinInfo *rb) {
	if (!rb) {
		return;
	}

	rz_list_free (rb->file_hashes);
	free (rb->intrp);
	free (rb->file);
	free (rb->type);
	free (rb->bclass);
	free (rb->rclass);
	free (rb->arch);
	free (rb->cpu);
	free (rb->machine);
	free (rb->os);
	free (rb->subsystem);
	free (rb->default_cc);
	free (rb->rpath);
	free (rb->guid);
	free (rb->debug_file_name);
	free (rb->actual_checksum);
	free (rb->claimed_checksum);
	free (rb->compiler);
	free (rb);
}

RZ_API RBinImport *rz_bin_import_clone(RBinImport *o) {
	rz_return_val_if_fail (o, NULL);

	RBinImport *res = rz_mem_dup (o, sizeof (*o));
	if (res) {
		res->name = R_STR_DUP (o->name);
		res->classname = R_STR_DUP (o->classname);
		res->descriptor = R_STR_DUP (o->descriptor);
	}
	return res;
}

RZ_API void rz_bin_import_free(void *_imp) {
	RBinImport *imp = (RBinImport *)_imp;
	if (imp) {
		R_FREE (imp->name);
		R_FREE (imp->libname);
		R_FREE (imp->classname);
		R_FREE (imp->descriptor);
		free (imp);
	}
}

RZ_API const char *rz_bin_symbol_name(RBinSymbol *s) {
	if (s->dup_count) {
		return sdb_fmt ("%s_%d", s->name, s->dup_count);
	}
	return s->name;
}

RZ_API RBinSymbol *rz_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
		sym->name = name? strdup (name): NULL;
		sym->paddr = paddr;
		sym->vaddr = vaddr;
	}
	return sym;
}

RZ_API void rz_bin_symbol_free(void *_sym) {
	RBinSymbol *sym = (RBinSymbol *)_sym;
	if (sym) {
		free (sym->name);
		free (sym->libname);
		free (sym->classname);
		free (sym);
	}
}

RZ_API void rz_bin_string_free(void *_str) {
	RBinString *str = (RBinString *)_str;
	if (str) {
		free (str->string);
		free (str);
	}
}

// XXX - change this to RBinObject instead of RBinFile
// makes no sense to pass in a binfile and set the RBinObject
// kinda a clunky functions
// XXX - this is a rather hacky way to do things, there may need to be a better
// way.
RZ_API bool rz_bin_open(RBin *bin, const char *file, RBinOptions *opt) {
	rz_return_val_if_fail (bin && bin->iob.io && opt, false);

	RzIOBind *iob = &(bin->iob);
	if (!iob->desc_get (iob->io, opt->fd)) {
		opt->fd = iob->fd_open (iob->io, file, R_PERM_R, 0644);
	}
	if (opt->fd < 0) {
		eprintf ("Couldn't open bin for file '%s'\n", file);
		return false;
	}
	opt->sz = 0;
	opt->pluginname = NULL;
	return rz_bin_open_io (bin, opt);
}

RZ_API bool rz_bin_reload(RBin *bin, ut32 bf_id, ut64 baseaddr) {
	rz_return_val_if_fail (bin, false);

	RBinFile *bf = rz_bin_file_find_by_id (bin, bf_id);
	if (!bf) {
		eprintf ("rz_bin_reload: No file to reopen\n");
		return false;
	}
	RBinOptions opt;
	rz_bin_options_init (&opt, bf->fd, baseaddr, bf->loadaddr, bin->rawstr);
	opt.filename = bf->file;

	bool res = rz_bin_open_buf (bin, bf->buf, &opt);
	rz_bin_file_delete (bin, bf->id);
	return res;
}

RZ_API bool rz_bin_open_buf(RBin *bin, RBuffer *buf, RBinOptions *opt) {
	rz_return_val_if_fail (bin && opt, false);

	RzListIter *it;
	RBinXtrPlugin *xtr;

	bin->rawstr = opt->rawstr;
	bin->file = opt->filename;
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
	}

	RBinFile *bf = NULL;
	if (bin->use_xtr && !opt->pluginname) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		rz_list_foreach (bin->binxtrs, it, xtr) {
			if (!xtr->check_buffer) {
				eprintf ("Missing check_buffer callback for '%s'\n", xtr->name);
				continue;
			}
			if (xtr->check_buffer (buf)) {
				if (xtr->extract_from_buffer || xtr->extractall_from_buffer ||
				    xtr->extract_from_bytes || xtr->extractall_from_bytes) {
					bf = rz_bin_file_xtr_load_buffer (bin, xtr,
						bin->file, buf, opt->baseaddr, opt->loadaddr,
						opt->xtr_idx, opt->fd, bin->rawstr);
				}
			}
		}
	}
	if (!bf) {
		// Uncomment for this speedup: 20s vs 22s
		// RBuffer *buf = rz_buf_new_slurp (bin->file);
		bf = rz_bin_file_new_from_buffer (bin, bin->file, buf, bin->rawstr,
			opt->baseaddr, opt->loadaddr, opt->fd, opt->pluginname);
		if (!bf) {
			return false;
		}
	}
	if (!rz_bin_file_set_cur_binfile (bin, bf)) {
		return false;
	}
	rz_id_storage_set (bin->ids, bin->cur, bf->id);
	return true;
}

RZ_API bool rz_bin_open_io(RBin *bin, RBinOptions *opt) {
	rz_return_val_if_fail (bin && opt && bin->iob.io, false);
	rz_return_val_if_fail (opt->fd >= 0 && (st64)opt->sz >= 0, false);

	RzIOBind *iob = &(bin->iob);
	RzIO *io = iob? iob->io: NULL;

	bool is_debugger = iob->fd_is_dbg (io, opt->fd);
	const char *fname = iob->fd_get_name (io, opt->fd);
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
	}

	// Create RBuffer from the opened file
	// When debugging something, we want to open the backed file because
	// not all binary info are mapped in the virtual space. If that is not
	// possible (e.g. remote file) just try to load bin info from the
	// debugee process.
	RBuffer *buf = NULL;
	if (is_debugger) {
		buf = rz_buf_new_file (fname, O_RDONLY, 0);
		is_debugger = false;
	}
	if (!buf) {
		buf = rz_buf_new_with_io (&bin->iob, opt->fd);
	}
	if (!buf) {
		return false;
	}

	if (!opt->sz) {
		opt->sz = rz_buf_size (buf);
	}

	// Slice buffer if necessary
	RBuffer *slice = buf;
	if (!is_debugger && (opt->loadaddr != 0 || opt->sz != rz_buf_size (buf))) {
		slice = rz_buf_new_slice (buf, opt->loadaddr, opt->sz);
	} else if (is_debugger && opt->baseaddr != UT64_MAX && opt->baseaddr != 0) {
		slice = rz_buf_new_slice (buf, opt->baseaddr, opt->sz);
	}
	if (slice != buf) {
		rz_buf_free (buf);
		buf = slice;
	}

	opt->filename = fname;
	bool res = rz_bin_open_buf (bin, buf, opt);
	rz_buf_free (buf);
	return res;
}

R_IPI RBinPlugin *rz_bin_get_binplugin_by_name(RBin *bin, const char *name) {
	RBinPlugin *plugin;
	RzListIter *it;

	rz_return_val_if_fail (bin && name, NULL);

	rz_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, name)) {
			return plugin;
		}
	}
	return NULL;
}

RZ_API RBinPlugin *rz_bin_get_binplugin_by_buffer(RBin *bin, RBuffer *buf) {
	RBinPlugin *plugin;
	RzListIter *it;

	rz_return_val_if_fail (bin && buf, NULL);

	rz_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_buffer) {
			if (plugin->check_buffer (buf)) {
				return plugin;
			}
		}
	}
	return NULL;
}

R_IPI RBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RBin *bin, const char *name) {
	RBinXtrPlugin *xtr;
	RzListIter *it;

	rz_return_val_if_fail (bin && name, NULL);

	// TODO: use a hashtable here
	rz_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, name)) {
			return xtr;
		}
		// must be set to null
		xtr = NULL;
	}
	return NULL;
}

static void rz_bin_plugin_free(RBinPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
	R_FREE (p);
}

// rename to rz_bin_plugin_add like the rest
RZ_API bool rz_bin_add(RBin *bin, RBinPlugin *foo) {
	RzListIter *it;
	RBinPlugin *plugin;

	rz_return_val_if_fail (bin && foo, false);

	if (foo->init) {
		foo->init (bin->user);
	}
	rz_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, foo->name)) {
			return false;
		}
	}
	plugin = R_NEW0 (RBinPlugin);
	memcpy (plugin, foo, sizeof (RBinPlugin));
	rz_list_append (bin->plugins, plugin);
	return true;
}

RZ_API bool rz_bin_ldr_add(RBin *bin, RBinLdrPlugin *foo) {
	RzListIter *it;
	RBinLdrPlugin *ldr;

	rz_return_val_if_fail (bin && foo, false);

	if (foo->init) {
		foo->init (bin->user);
	}
	// avoid duplicates
	rz_list_foreach (bin->binldrs, it, ldr) {
		if (!strcmp (ldr->name, foo->name)) {
			return false;
		}
	}
	rz_list_append (bin->binldrs, foo);
	return true;
}

RZ_API bool rz_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	RzListIter *it;
	RBinXtrPlugin *xtr;

	rz_return_val_if_fail (bin && foo, false);

	if (foo->init) {
		foo->init (bin->user);
	}
	// avoid duplicates
	rz_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, foo->name)) {
			return false;
		}
	}
	rz_list_append (bin->binxtrs, foo);
	return true;
}

RZ_API void rz_bin_free(RBin *bin) {
	if (bin) {
		bin->file = NULL;
		free (bin->force);
		free (bin->srcdir);
		free (bin->strenc);
		//rz_bin_free_bin_files (bin);
		rz_list_free (bin->binfiles);
		rz_list_free (bin->binxtrs);
		rz_list_free (bin->plugins);
		rz_list_free (bin->binldrs);
		sdb_free (bin->sdb);
		rz_id_storage_free (bin->ids);
		rz_str_constpool_fini (&bin->constpool);
		free (bin);
	}
}

static bool rz_bin_print_plugin_details(RBin *bin, RBinPlugin *bp, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bp->name);
	} else if (json) {
		bin->cb_printf (
			"{\"name\":\"%s\",\"description\":\"%s\","
			"\"license\":\"%s\"}\n",
			bp->name, bp->desc, bp->license? bp->license: "???");
	} else {
		bin->cb_printf ("Name: %s\n", bp->name);
		bin->cb_printf ("Description: %s\n", bp->desc);
		if (bp->license) {
			bin->cb_printf ("License: %s\n", bp->license);
		}
		if (bp->version) {
			bin->cb_printf ("Version: %s\n", bp->version);
		}
		if (bp->author) {
			bin->cb_printf ("Author: %s\n", bp->author);
		}
	}
	return true;
}

static void __printXtrPluginDetails(RBin *bin, RBinXtrPlugin *bx, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bx->name);
	} else if (json) {
		bin->cb_printf (
			"{\"name\":\"%s\",\"description\":\"%s\","
			"\"license\":\"%s\"}\n",
			bx->name, bx->desc, bx->license? bx->license: "???");
	} else {
		bin->cb_printf ("Name: %s\n", bx->name);
		bin->cb_printf ("Description: %s\n", bx->desc);
		if (bx->license) {
			bin->cb_printf ("License: %s\n", bx->license);
		}
	}
}

RZ_API bool rz_bin_list_plugin(RBin *bin, const char* name, int json) {
	RzListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;

	rz_return_val_if_fail (bin && name, false);

	rz_list_foreach (bin->plugins, it, bp) {
		if (!rz_str_cmp (name, bp->name, strlen (name))) {
			continue;
		}
		return rz_bin_print_plugin_details (bin, bp, json);
	}
	rz_list_foreach (bin->binxtrs, it, bx) {
		if (!rz_str_cmp (name, bx->name, strlen (name))) {
			continue;
		}
		__printXtrPluginDetails (bin, bx, json);
		return true;
	}

	eprintf ("Cannot find plugin %s\n", name);
	return false;
}

RZ_API void rz_bin_list(RBin *bin, int format) {
	RzListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;
	RBinLdrPlugin *ld;

	if (format == 'q') {
		rz_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("%s\n", bp->name);
		}
		rz_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf ("%s\n", bx->name);
		}
	} else if (format) {
		int i;

		i = 0;
		bin->cb_printf ("{\"bin\":[");
		rz_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", bp->name, bp->desc, bp->license? bp->license: "???");
			i++;
		}

		i = 0;
		bin->cb_printf ("],\"xtr\":[");
		rz_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", bx->name, bx->desc, bx->license? bx->license: "???");
			i++;
		}

		i = 0;
		bin->cb_printf ("],\"ldr\":[");
		rz_list_foreach (bin->binxtrs, it, ld) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", ld->name, ld->desc, ld->license? ld->license: "???");
			i++;
		}
		bin->cb_printf ("]}\n");
	} else {
		rz_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("bin  %-11s %s (%s) %s %s\n",
				bp->name, bp->desc, bp->license? bp->license: "???",
				bp->version? bp->version: "",
				bp->author? bp->author: "");
		}
		rz_list_foreach (bin->binxtrs, it, bx) {
			const char *name = strncmp (bx->name, "xtr.", 4)? bx->name : bx->name + 3;
			bin->cb_printf ("xtr  %-11s %s (%s)\n", name,
				bx->desc, bx->license? bx->license: "???");
		}
		rz_list_foreach (bin->binldrs, it, ld) {
			const char *name = strncmp (ld->name, "ldr.", 4)? ld->name : ld->name + 3;
			bin->cb_printf ("ldr  %-11s %s (%s)\n", name,
				ld->desc, ld->license? ld->license: "???");
		}
	}
}

/* returns the base address of bin or UT64_MAX in case of errors */
RZ_API ut64 rz_bin_get_baddr(RBin *bin) {
	rz_return_val_if_fail (bin, UT64_MAX);
	return rz_bin_file_get_baddr (bin->cur);
}

/* returns the load address of bin or UT64_MAX in case of errors */
RZ_API ut64 rz_bin_get_laddr(RBin *bin) {
	rz_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->loadaddr : UT64_MAX;
}

// TODO: should be RBinFile specific imho
RZ_API void rz_bin_set_baddr(RBin *bin, ut64 baddr) {
	rz_return_if_fail (bin);
	RBinFile *bf = rz_bin_cur (bin);
	RBinObject *o = rz_bin_cur_object (bin);
	if (o) {
		if (!o->plugin || !o->plugin->baddr) {
			return;
		}
		ut64 file_baddr = o->plugin->baddr (bf);
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
		eprintf ("Warning: This should be an assert probably.\n");
	}
	// XXX - update all the infos?
	// maybe in RBinFile.rebase() ?
}

RZ_API RBinAddr *rz_bin_get_sym(RBin *bin, int sym) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	if (sym < 0 || sym >= R_BIN_SYM_LAST) {
		return NULL;
	}
	return o? o->binsym[sym]: NULL;
}

// XXX: those accessors are redundant
RZ_API RzList *rz_bin_get_entries(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->entries : NULL;
}

RZ_API RzList *rz_bin_get_fields(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->fields : NULL;
}

RZ_API RzList *rz_bin_get_imports(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->imports : NULL;
}

RZ_API RBinInfo *rz_bin_get_info(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->info : NULL;
}

RZ_API RzList *rz_bin_get_libs(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->libs : NULL;
}

static RzList *relocs_rbtree2list(RBNode *root) {
	RzList *res = rz_list_new ();
	RBinReloc *reloc;
	RBIter it;

	rz_rbtree_foreach (root, it, reloc, RBinReloc, vrb) {
		rz_list_append (res, reloc);
	}
	return res;
}

RZ_API RBNode *rz_bin_patch_relocs(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o? rz_bin_object_patch_relocs (bin, o): NULL;
}

// return a list of <const RBinReloc> that needs to be freed by the caller
RZ_API RzList *rz_bin_patch_relocs_list(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBNode *root = rz_bin_patch_relocs (bin);
	return root? relocs_rbtree2list (root): NULL;
}

RZ_API RBNode *rz_bin_get_relocs(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->relocs : NULL;
}

// return a list of <const RBinReloc> that needs to be freed by the caller
RZ_API RzList *rz_bin_get_relocs_list(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBNode *root = rz_bin_get_relocs (bin);
	return root? relocs_rbtree2list (root): NULL;
}

RZ_API RzList *rz_bin_get_sections(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->sections : NULL;
}

RZ_API RBinSection *rz_bin_get_section_at(RBinObject *o, ut64 off, int va) {
	RBinSection *section;
	RzListIter *iter;
	ut64 from, to;

	rz_return_val_if_fail (o, NULL);
	// TODO: must be O(1) .. use sdb here
	rz_list_foreach (o->sections, iter, section) {
		if (section->is_segment) {
			continue;
		}
		from = va ? binobj_a2b (o, section->vaddr) : section->paddr;
		to = from + (va ? section->vsize: section->size);
		if (off >= from && off < to) {
			return section;
		}
	}
	return NULL;
}

RZ_API RzList *rz_bin_reset_strings(RBin *bin) {
	RBinFile *bf = rz_bin_cur (bin);

	if (!bf || !bf->o) {
		return NULL;
	}
	if (bf->o->strings) {
		rz_list_free (bf->o->strings);
		bf->o->strings = NULL;
	}

	bf->rawstr = bin->rawstr;
	RBinPlugin *plugin = rz_bin_file_cur_plugin (bf);

	if (plugin && plugin->strings) {
		bf->o->strings = plugin->strings (bf);
	} else {
		bf->o->strings = rz_bin_file_get_strings (bf, bin->minstrlen, 0, bf->rawstr);
	}
	if (bin->debase64) {
		rz_bin_object_filter_strings (bf->o);
	}
	return bf->o->strings;
}

RZ_API RzList *rz_bin_get_strings(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->strings : NULL;
}

RZ_API int rz_bin_is_string(RBin *bin, ut64 va) {
	RBinString *string;
	RzListIter *iter;
	RzList *list;
	if (!(list = rz_bin_get_strings (bin))) {
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

RZ_API RzList *rz_bin_get_symbols(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o? o->symbols: NULL;
}

RZ_API RzList *rz_bin_get_mem(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->mem : NULL;
}

RZ_API int rz_bin_is_big_endian(RBin *bin) {
	rz_return_val_if_fail (bin, -1);
	RBinObject *o = rz_bin_cur_object (bin);
	return (o && o->info) ? o->info->big_endian : -1;
}

RZ_API int rz_bin_is_static(RBin *bin) {
	rz_return_val_if_fail (bin, false);
	RBinObject *o = rz_bin_cur_object (bin);
	if (o && o->libs && rz_list_length (o->libs) > 0) {
		return R_BIN_DBG_STATIC & o->info->dbg_info;
	}
	return true;
}

RZ_API RBin *rz_bin_new(void) {
	int i;
	RBinXtrPlugin *static_xtr_plugin;
	RBinLdrPlugin *static_ldr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) {
		return NULL;
	}
	if (!rz_str_constpool_init (&bin->constpool)) {
		goto trashbin;
	}
	bin->force = NULL;
	bin->filter_rules = UT64_MAX;
	bin->sdb = sdb_new0 ();
	bin->cb_printf = (PrintfCallback)printf;
	bin->plugins = rz_list_newf ((RzListFree)rz_bin_plugin_free);
	bin->minstrlen = 0;
	bin->strpurge = NULL;
	bin->strenc = NULL;
	bin->want_dbginfo = true;
	bin->cur = NULL;
	bin->ids = rz_id_storage_new (0, ST32_MAX);

	/* bin parsers */
	bin->binfiles = rz_list_newf ((RzListFree)rz_bin_file_free);
	for (i = 0; bin_static_plugins[i]; i++) {
		rz_bin_add (bin, bin_static_plugins[i]);
	}
	/* extractors */
	bin->binxtrs = rz_list_new ();
	bin->binxtrs->free = free;
	for (i = 0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW0 (RBinXtrPlugin);
		if (!static_xtr_plugin) {
			goto trashbin_binxtrs;
		}
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		rz_bin_xtr_add (bin, static_xtr_plugin);
	}
	/* loaders */
	bin->binldrs = rz_list_new ();
	bin->binldrs->free = free;
	for (i = 0; bin_ldr_static_plugins[i]; i++) {
		static_ldr_plugin = R_NEW0 (RBinLdrPlugin);
		if (!static_ldr_plugin) {
			goto trashbin_binldrs;
		}
		*static_ldr_plugin = *bin_ldr_static_plugins[i];
		rz_bin_ldr_add (bin, static_ldr_plugin);
	}
	return bin;
trashbin_binldrs:
	rz_list_free (bin->binldrs);
trashbin_binxtrs:
	rz_list_free (bin->binxtrs);
	rz_list_free (bin->binfiles);
	rz_id_storage_free (bin->ids);
	rz_str_constpool_fini (&bin->constpool);
trashbin:
	free(bin);
	return NULL;
}

RZ_API bool rz_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail (bin && arch, false);

	RBinFile *binfile = rz_bin_file_find_by_arch_bits (bin, arch, bits);
	if (!binfile) {
		R_LOG_WARN ("Cannot find binfile with arch/bits %s/%d\n", arch, bits);
		return false;
	}

	RBinObject *obj = rz_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	if (!obj && binfile->xtr_data) {
		RBinXtrData *xtr_data = rz_list_get_n (binfile->xtr_data, 0);
		if (xtr_data && !xtr_data->loaded) {
			if (!rz_bin_file_object_new_from_xtr_data (bin, binfile,
				    UT64_MAX, rz_bin_get_laddr (bin), xtr_data)) {
				return false;
			}
		}
		obj = binfile->o;
	}
	return rz_bin_file_set_obj (bin, binfile, obj);
}

RZ_API bool rz_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail (bin, false);

	RBinFile *cur = rz_bin_cur (bin);
	RBinObject *obj = NULL;
	name = !name && cur? cur->file: name;
	RBinFile *binfile = rz_bin_file_find_by_arch_bits (bin, arch, bits);
	if (binfile && name) {
		obj = rz_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	}
	return rz_bin_file_set_obj (bin, binfile, obj);
}

RZ_API int rz_bin_select_object(RBinFile *binfile, const char *arch, int bits, const char *name) {
	rz_return_val_if_fail (binfile, false);
	RBinObject *obj = rz_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	return rz_bin_file_set_obj (binfile->rbin, binfile, obj);
}

// NOTE: this functiona works as expected, but  we need to merge bfid and boid
RZ_API bool rz_bin_select_bfid (RBin *bin, ut32 bf_id) {
	rz_return_val_if_fail (bin, false);
	RBinFile *bf = rz_bin_file_find_by_id (bin, bf_id);
	return bf? rz_bin_file_set_obj (bin, bf, NULL): false;
}

static void list_xtr_archs(RBin *bin, int mode) {
	RBinFile *binfile = rz_bin_cur (bin);
	if (binfile->xtr_data) {
		RzListIter *iter_xtr;
		RBinXtrData *xtr_data;
		int bits, i = 0;
		char *arch, *machine;

		if (mode == 'j') {
			bin->cb_printf ("\"bins\":[");
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
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j': { // "iAj"
				PJ * pj = pj_new ();
				pj_o (pj);
				pj_a (pj);
				pj_ks (pj, "arch", arch);
				pj_ki (pj, "bits", bits);
				pj_ki (pj, "offset", xtr_data->offset);
				pj_kn (pj, "size", xtr_data->size);
				if (machine) {
					pj_ks (pj, "machine", machine);
				}
				pj_end (pj);
				pj_end (pj);
				bin->cb_printf ("%s\n", pj_string (pj));
				pj_free (pj);
				break;
			}
			default:
				bin->cb_printf ("%03i 0x%08" PFMT64x
						" %" PFMT64d " %s_%i %s\n",
						i++, xtr_data->offset,
						xtr_data->size, arch, bits,
						machine);
				break;
			}
		}

		if (mode == 'j') {
			bin->cb_printf ("]");
		}
	}
}

RZ_API void rz_bin_list_archs(RBin *bin, int mode) {
	rz_return_if_fail (bin);

	int i = 0;
	char unk[128];
	char archline[256];
	RBinFile *binfile = rz_bin_cur (bin);
	RTable *table = rz_table_new ();
	const char *name = binfile? binfile->file: NULL;
	int narch = binfile? binfile->narch: 0;

	//are we with xtr format?
	if (binfile && binfile->curxtr) {
		list_xtr_archs (bin, mode);
		rz_table_free (table);
		return;
	}
	Sdb *binfile_sdb = binfile? binfile->sdb: NULL;
	if (!binfile_sdb) {
	//	eprintf ("Cannot find SDB!\n");
		rz_table_free (table);
		return;
	}
	if (!binfile) {
	//	eprintf ("Binary format not currently loaded!\n");
		rz_table_free (table);
		return;
	}
	sdb_unset (binfile_sdb, ARCHS_KEY, 0);
	PJ *pj = pj_new ();
	pj_o (pj);
	if (mode == 'j') {
		pj_k (pj, "bins");
		pj_a (pj);
	}
	RBinFile *nbinfile = rz_bin_file_find_by_name_n (bin, name, i);
	if (!nbinfile) {
		pj_free (pj);
		rz_table_free (table);
		return;
	}
	i = -1;
	RBinObject *obj = nbinfile->o;
	RBinInfo *info = obj->info;
	char bits = info? info->bits: 0;
	ut64 boffset = obj->boffset;
	ut64 obj_size = obj->obj_size;
	const char *arch = info? info->arch: NULL;
	const char *machine = info? info->machine: "unknown_machine";
	const char *h_flag = info? info->head_flag: NULL;
	char * str_fmt;
	i++;
	if (!arch) {
		snprintf (unk, sizeof (unk), "unk_%d", i);
		arch = unk;
	}
	rz_table_hide_header (table);
	rz_table_set_columnsf (table, "nXnss", "num", "offset", "size", "arch", "machine", NULL);

	if (info && narch > 1) {
		switch (mode) {
		case 'q':
			bin->cb_printf ("%s\n", arch);
			break;
		case 'j':
			pj_o (pj);
			pj_ks (pj, "arch", arch);
			pj_ki (pj, "bits", bits);
			pj_kn (pj, "offset", boffset);
			pj_kn (pj, "size", obj_size);
			if (!strcmp (arch, "mips")) {
				pj_ks (pj, "isa", info->cpu);
				pj_ks (pj, "features", info->features);
			}
			if (machine) {
				pj_ks (pj, "machine", machine);
			}
			pj_end (pj);
			break;
		default:
			str_fmt = h_flag && strcmp (h_flag, "unknown_flag")? sdb_fmt ("%s_%i %s", arch, bits, h_flag) \
				: sdb_fmt ("%s_%i", arch, bits);
			rz_table_add_rowf (table, "nXnss", i, boffset, obj_size, str_fmt , machine);
			bin->cb_printf ("%s\n", rz_table_tostring(table));
		}
		snprintf (archline, sizeof (archline) - 1,
			"0x%08" PFMT64x ":%" PFMT64u ":%s:%d:%s",
			boffset, obj_size, arch, bits, machine);
		/// xxx machine not exported?
		//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
	} else {
		if (info) {
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				pj_o (pj);
				pj_ks (pj, "arch", arch);
				pj_ki (pj, "bits", bits);
				pj_kn (pj, "offset", boffset);
				pj_kn (pj, "size", obj_size);
				if (!strcmp (arch, "mips")) {
					pj_ks (pj, "isa", info->cpu);
					pj_ks (pj, "features", info->features);
				}
				if (machine) {
					pj_ks (pj, "machine", machine);
				}
				pj_end (pj);
				break;
			default:
				str_fmt = h_flag && strcmp (h_flag, "unknown_flag")? sdb_fmt ("%s_%i %s", arch, bits, h_flag) \
					: sdb_fmt ("%s_%i", arch, bits);
				rz_table_add_rowf (table, "nsnss", i, sdb_fmt ("0x%08" PFMT64x , boffset), obj_size, str_fmt, "");
				bin->cb_printf ("%s\n", rz_table_tostring(table));
			}
			snprintf (archline, sizeof (archline),
				"0x%08" PFMT64x ":%" PFMT64u ":%s:%d",
				boffset, obj_size, arch, bits);
		} else if (nbinfile && mode) {
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				pj_o (pj);
				pj_ks (pj, "arch", arch);
				pj_ki (pj, "bits", bits);
				pj_kn (pj, "offset", boffset);
				pj_kn (pj, "size", obj_size);
				if (machine) {
					pj_ks (pj, "machine", machine);
				}
				pj_end (pj);
				break;
			default:
				rz_table_add_rowf (table, "nsnss", i, sdb_fmt ("0x%08" PFMT64x , boffset), obj_size, "", "");
				bin->cb_printf ("%s\n", rz_table_tostring(table));
			}
			snprintf (archline, sizeof (archline),
				"0x%08" PFMT64x ":%" PFMT64u ":%s:%d",
				boffset, obj_size, "unk", 0);
		} else {
			eprintf ("Error: Invalid RBinFile.\n");
		}
		//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
	}
	if (mode == 'j') {
		pj_end (pj);
		pj_end (pj);
		const char *s = pj_string (pj);
		if (s) {
			bin->cb_printf ("%s\n", s);
		}
	}
	pj_free (pj);
	rz_table_free (table);
}

RZ_API void rz_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static RBinSection* __get_vsection_at(RBin *bin, ut64 vaddr) {
	rz_return_val_if_fail (bin, NULL);
	if (!bin->cur) {
		return NULL;
	}
	return rz_bin_get_section_at (bin->cur->o, vaddr, true);
}

RZ_API void rz_bin_bind(RBin *bin, RBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = __getoffset;
		b->get_name = __getname;
		b->get_sections = rz_bin_get_sections;
		b->get_vsect_at = __get_vsection_at;
		b->demangle = rz_bin_demangle;
	}
}

RZ_API RBuffer *rz_bin_create(RBin *bin, const char *p,
	const ut8 *code, int codelen,
	const ut8 *data, int datalen,
	RBinArchOptions *opt) {

	rz_return_val_if_fail (bin && p && opt, NULL);

	RBinPlugin *plugin = rz_bin_get_binplugin_by_name (bin, p);
	if (!plugin) {
		R_LOG_WARN ("Cannot find RBin plugin named '%s'.\n", p);
		return NULL;
	}
	if (!plugin->create) {
		R_LOG_WARN ("RBin plugin '%s' does not implement \"create\" method.\n", p);
		return NULL;
	}
	codelen = R_MAX (codelen, 0);
	datalen = R_MAX (datalen, 0);
	return plugin->create (bin, code, codelen, data, datalen, opt);
}

RZ_API RBuffer *rz_bin_package(RBin *bin, const char *type, const char *file, RzList *files) {
	if (!strcmp (type, "zip")) {
		// XXX: implement me
		rz_warn_if_reached ();
	} else if (!strcmp (type, "fat")) {
		// XXX: this should be implemented in the fat plugin, not here
		// XXX should pick the callback from the plugin list
		const char *f;
		RzListIter *iter;
		ut32 num;
		ut8 *num8 = (ut8*)&num;
		RBuffer *buf = rz_buf_new_file (file, O_RDWR | O_CREAT, 0644);
		if (!buf) {
			eprintf ("Cannot open file %s - Permission Denied.\n", file);
			return NULL;
		}
		rz_buf_write_at (buf, 0, (const ut8*)"\xca\xfe\xba\xbe", 4);
		int count = rz_list_length (files);

		num = rz_read_be32 (&count);
		ut64 from = 0x1000;
		rz_buf_write_at (buf, 4, num8, 4);
		int off = 12;
		int item = 0;
		rz_list_foreach (files, iter, f) {
			size_t f_len = 0;
			ut8 *f_buf = (ut8 *)rz_file_slurp (f, &f_len);
			if (f_buf) {
				eprintf ("ADD %s %"PFMT64u"\n", f, (ut64)f_len);
			} else {
				eprintf ("Cannot open %s\n", f);
				free (f_buf);
				continue;
			}
			item++;
			/* CPU */
			num8[0] = f_buf[7];
			num8[1] = f_buf[6];
			num8[2] = f_buf[5];
			num8[3] = f_buf[4];
			rz_buf_write_at (buf, off - 4, num8, 4);
			/* SUBTYPE */
			num8[0] = f_buf[11];
			num8[1] = f_buf[10];
			num8[2] = f_buf[9];
			num8[3] = f_buf[8];
			rz_buf_write_at (buf, off, num8, 4);
			ut32 from32 = from;
			/* FROM */
			num = rz_read_be32 (&from32);
			rz_buf_write_at (buf, off + 4, num8, 4);
			rz_buf_write_at (buf, from, f_buf, f_len);
			/* SIZE */
			num = rz_read_be32 (&f_len);
			rz_buf_write_at (buf, off + 8, num8, 4);
			off += 20;
			from += f_len + (f_len % 0x1000);
			free (f_buf);
		}
		rz_buf_free (buf);
		return NULL;
	} else {
		eprintf ("Usage: rz_bin -X [fat|zip] [filename] [files ...]\n");
	}
	return NULL;
}

RZ_API RzList * /*<RBinClass>*/ rz_bin_get_classes(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->classes : NULL;
}

/* returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise */
RZ_API ut64 rz_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr) {
	rz_return_val_if_fail (bin && paddr != UT64_MAX, UT64_MAX);

	if (!bin->cur) {
		return paddr;
	}
	/* hack to realign thumb symbols */
	if (bin->cur->o && bin->cur->o->info && bin->cur->o->info->arch) {
		if (bin->cur->o->info->bits == 16) {
			RBinSection *s = rz_bin_get_section_at (bin->cur->o, paddr, false);
			// autodetect thumb
			if (s && (s->perm & R_PERM_X) && strstr (s->name, "text")) {
				if (!strcmp (bin->cur->o->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}
	return rz_bin_file_get_vaddr (bin->cur, paddr, vaddr);
}

RZ_API ut64 rz_bin_a2b(RBin *bin, ut64 addr) {
	rz_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = rz_bin_cur_object (bin);
	return binobj_a2b (o, addr);
}

RZ_API ut64 rz_bin_get_size(RBin *bin) {
	rz_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = rz_bin_cur_object (bin);
	return o ? o->size : 0;
}

RZ_API RBinFile *rz_bin_cur(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	return bin->cur;
}

RZ_API RBinObject *rz_bin_cur_object(RBin *bin) {
	rz_return_val_if_fail (bin, NULL);
	RBinFile *binfile = rz_bin_cur (bin);
	return binfile ? binfile->o : NULL;
}

RZ_API void rz_bin_force_plugin(RBin *bin, const char *name) {
	rz_return_if_fail (bin);
	free (bin->force);
	bin->force = (name && *name) ? strdup (name) : NULL;
}

RZ_API const char *rz_bin_entry_type_string(int etype) {
	switch (etype) {
	case R_BIN_ENTRY_TYPE_PROGRAM:
		return "program";
	case R_BIN_ENTRY_TYPE_MAIN:
		return "main";
	case R_BIN_ENTRY_TYPE_INIT:
		return "init";
	case R_BIN_ENTRY_TYPE_FINI:
		return "fini";
	case R_BIN_ENTRY_TYPE_TLS:
		return "tls";
	case R_BIN_ENTRY_TYPE_PREINIT:
		return "preinit";
	}
	return NULL;
}

RZ_API void rz_bin_load_filter(RBin *bin, ut64 rules) {
	bin->filter_rules = rules;
}

/* RBinField */
RZ_API RBinField *rz_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named) {
	RBinField *ptr = R_NEW0 (RBinField);
	if (ptr) {
		ptr->name = strdup (name);
		ptr->comment = (comment && *comment)? strdup (comment): NULL;
		ptr->format = (format && *format)? strdup (format): NULL;
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
	RBinField *field = (RBinField*) _field;
	if (field) {
		free (field->name);
		free (field->comment);
		free (field->format);
		free (field);
	}
}

// method name too long
// RBin.methFlagToString(RBin.Method.CLASS)
RZ_API const char *rz_bin_get_meth_flag_string(ut64 flag, bool compact) {
	switch (flag) {
	case R_BIN_METH_CLASS:
		return compact ? "c" : "class";
	case R_BIN_METH_STATIC:
		return compact ? "s" : "static";
	case R_BIN_METH_PUBLIC:
		return compact ? "p" : "public";
	case R_BIN_METH_PRIVATE:
		return compact ? "P" : "private";
	case R_BIN_METH_PROTECTED:
		return compact ? "r" : "protected";
	case R_BIN_METH_INTERNAL:
		return compact ? "i" : "internal";
	case R_BIN_METH_OPEN:
		return compact ? "o" : "open";
	case R_BIN_METH_FILEPRIVATE:
		return compact ? "e" : "fileprivate";
	case R_BIN_METH_FINAL:
		return compact ? "f" : "final";
	case R_BIN_METH_VIRTUAL:
		return compact ? "v" : "virtual";
	case R_BIN_METH_CONST:
		return compact ? "k" : "const";
	case R_BIN_METH_MUTATING:
		return compact ? "m" : "mutating";
	case R_BIN_METH_ABSTRACT:
		return compact ? "a" : "abstract";
	case R_BIN_METH_SYNCHRONIZED:
		return compact ? "y" : "synchronized";
	case R_BIN_METH_NATIVE:
		return compact ? "n" : "native";
	case R_BIN_METH_BRIDGE:
		return compact ? "b" : "bridge";
	case R_BIN_METH_VARARGS:
		return compact ? "g" : "varargs";
	case R_BIN_METH_SYNTHETIC:
		return compact ? "h" : "synthetic";
	case R_BIN_METH_STRICT:
		return compact ? "t" : "strict";
	case R_BIN_METH_MIRANDA:
		return compact ? "A" : "miranda";
	case R_BIN_METH_CONSTRUCTOR:
		return compact ? "C" : "constructor";
	case R_BIN_METH_DECLARED_SYNCHRONIZED:
		return compact ? "Y" : "declared_synchronized";
	default:
		return NULL;
	}
}

R_IPI RBinSection *rz_bin_section_new(const char *name) {
	RBinSection *s = R_NEW0 (RBinSection);
	if (s) {
		s->name = name? strdup (name): NULL;
	}
	return s;
}

R_IPI void rz_bin_section_free(RBinSection *bs) {
	if (bs) {
		free (bs->name);
		free (bs->format);
		free (bs);
	}
}

RZ_API RBinFile *rz_bin_file_at(RBin *bin, ut64 at) {
	RzListIter *it, *it2;
	RBinFile *bf;
	RBinSection *s;
	rz_list_foreach (bin->binfiles, it, bf) {
		// chk for baddr + size of no section is covering anything
		// we should honor maps not sections imho
		rz_list_foreach (bf->o->sections, it2, s) {
			if (at >= s->vaddr  && at < (s->vaddr + s->vsize)) {
				return bf;
			}
		}
		if (at >= bf->o->baddr && at < (bf->o->baddr + bf->size)) {
			return bf;
		}
	}
	return NULL;
}

RZ_API RBinTrycatch *rz_bin_trycatch_new(ut64 source, ut64 from, ut64 to, ut64 handler, ut64 filter) {
	RBinTrycatch *tc = R_NEW0 (RBinTrycatch);
	if (tc) {
		tc->source = source;
		tc->from = from;
		tc->to = to;
		tc->handler = handler;
		tc->filter = filter;
	}
	return tc;
}

RZ_API void rz_bin_trycatch_free(RBinTrycatch *tc) {
	free (tc);
}
