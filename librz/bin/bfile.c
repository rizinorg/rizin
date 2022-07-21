// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_hash.h>
#include <rz_util/rz_log.h>
#include "i/private.h"

static RzBinClass *__getClass(RzBinFile *bf, const char *name) {
	rz_return_val_if_fail(bf && bf->o && bf->o->classes_ht && name, NULL);
	return ht_pp_find(bf->o->classes_ht, name, NULL);
}

static RzBinSymbol *__getMethod(RzBinFile *bf, const char *klass, const char *method) {
	rz_return_val_if_fail(bf && bf->o && bf->o->methods_ht && klass && method, NULL);
	const char *name = sdb_fmt("%s::%s", klass, method);
	return ht_pp_find(bf->o->methods_ht, name, NULL);
}

RZ_IPI RzBinFile *rz_bin_file_new(RzBin *bin, const char *file, ut64 file_sz, int fd, const char *xtrname, bool steal_ptr) {
	ut32 bf_id;
	if (!rz_id_pool_grab_id(bin->ids->pool, &bf_id)) {
		return NULL;
	}
	RzBinFile *bf = RZ_NEW0(RzBinFile);
	if (!bf) {
		return NULL;
	}

	bf->id = bf_id;
	bf->rbin = bin;
	bf->file = RZ_STR_DUP(file);
	bf->fd = fd;
	bf->curxtr = xtrname ? rz_bin_get_xtrplugin_by_name(bin, xtrname) : NULL;
	bf->size = file_sz;
	bf->xtr_data = rz_list_newf((RzListFree)rz_bin_xtrdata_free);
	bf->xtr_obj = NULL;
	bf->sdb = sdb_new0();
	return bf;
}

RZ_IPI void rz_bin_file_free(void /*RzBinFile*/ *_bf) {
	if (!_bf) {
		return;
	}
	RzBinFile *bf = _bf;
	if (bf->rbin->cur == bf) {
		bf->rbin->cur = NULL;
	}
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	// Binary format objects are connected to the
	// RzBinObject, so the plugin must destroy the
	// format data first
	if (plugin && plugin->destroy) {
		plugin->destroy(bf);
	}
	rz_buf_free(bf->buf);
	if (bf->curxtr && bf->curxtr->destroy && bf->xtr_obj) {
		bf->curxtr->free_xtr((void *)(bf->xtr_obj));
	}
	free(bf->file);
	rz_bin_object_free(bf->o);
	rz_list_free(bf->xtr_data);
	sdb_free(bf->sdb);
	if (bf->id != -1) {
		// TODO: use rz_storage api
		rz_id_pool_kick_id(bf->rbin->ids->pool, bf->id);
	}
	free(bf);
}

static RzBinPlugin *get_plugin_from_buffer(RzBin *bin, const char *pluginname, RzBuffer *buf) {
	RzBinPlugin *plugin = bin->force ? rz_bin_get_binplugin_by_name(bin, bin->force) : NULL;
	if (plugin) {
		return plugin;
	}
	plugin = pluginname ? rz_bin_get_binplugin_by_name(bin, pluginname) : NULL;
	if (plugin) {
		return plugin;
	}
	plugin = rz_bin_get_binplugin_by_buffer(bin, buf);
	if (plugin) {
		return plugin;
	}
	plugin = rz_bin_get_binplugin_by_filename(bin);
	if (plugin) {
		return plugin;
	}
	return rz_bin_get_binplugin_by_name(bin, "any");
}

RZ_API bool rz_bin_file_object_new_from_xtr_data(RzBin *bin, RzBinFile *bf, RzBinObjectLoadOptions *opts, RzBinXtrData *data) {
	rz_return_val_if_fail(bin && bf && data, false);

	ut64 offset = data->offset;
	ut64 sz = data->size;

	RzBinPlugin *plugin = get_plugin_from_buffer(bin, NULL, data->buf);
	bf->buf = rz_buf_ref(data->buf);

	RzBinObject *o = rz_bin_object_new(bf, plugin, opts, offset, sz);
	if (!o) {
		return false;
	}
	// size is set here because the reported size of the object depends on
	// if loaded from xtr plugin or partially read
	if (!o->size) {
		o->size = sz;
	}
	bf->narch = data->file_count;
	if (!o->info) {
		o->info = RZ_NEW0(RzBinInfo);
	}
	free(o->info->file);
	free(o->info->arch);
	free(o->info->machine);
	free(o->info->type);
	o->info->file = strdup(bf->file);
	o->info->arch = strdup(data->metadata->arch);
	o->info->machine = strdup(data->metadata->machine);
	o->info->type = strdup(data->metadata->type);
	o->info->bits = data->metadata->bits;
	o->info->has_crypto = bf->o->info->has_crypto;
	data->loaded = true;
	return true;
}

static bool xtr_metadata_match(RzBinXtrData *xtr_data, const char *arch, int bits) {
	if (!xtr_data->metadata || !xtr_data->metadata->arch) {
		return false;
	}
	const char *iter_arch = xtr_data->metadata->arch;
	int iter_bits = xtr_data->metadata->bits;
	return bits == iter_bits && !strcmp(iter_arch, arch) && !xtr_data->loaded;
}

RZ_IPI RzBinFile *rz_bin_file_new_from_buffer(RzBin *bin, const char *file, RzBuffer *buf, RzBinObjectLoadOptions *opts, int fd, const char *pluginname) {
	rz_return_val_if_fail(bin && file && buf, NULL);

	RzBinFile *bf = rz_bin_file_new(bin, file, rz_buf_size(buf), fd, pluginname, false);
	if (!bf) {
		return NULL;
	}

	RzListIter *item = rz_list_append(bin->binfiles, bf);
	bf->buf = rz_buf_ref(buf);
	RzBinPlugin *plugin = get_plugin_from_buffer(bin, pluginname, bf->buf);
	RzBinObject *o = rz_bin_object_new(bf, plugin, opts, 0, rz_buf_size(bf->buf));
	if (!o) {
		rz_list_delete(bin->binfiles, item);
		return NULL;
	}
	// size is set here because the reported size of the object depends on
	// if loaded from xtr plugin or partially read
	if (!o->size) {
		o->size = rz_buf_size(buf);
	}
	return bf;
}

RZ_API RzBinFile *rz_bin_file_find_by_arch_bits(RzBin *bin, const char *arch, int bits) {
	RzListIter *iter;
	RzBinFile *binfile = NULL;
	RzBinXtrData *xtr_data;

	rz_return_val_if_fail(bin && arch, NULL);

	rz_list_foreach (bin->binfiles, iter, binfile) {
		RzListIter *iter_xtr;
		if (!binfile->xtr_data) {
			continue;
		}
		// look for sub-bins in Xtr Data and Load if we need to
		rz_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (xtr_metadata_match(xtr_data, arch, bits)) {
				if (!rz_bin_file_object_new_from_xtr_data(bin, binfile, &xtr_data->obj_opts, xtr_data)) {
					return NULL;
				}
				return binfile;
			}
		}
	}
	return binfile;
}

RZ_IPI RzBinFile *rz_bin_file_find_by_id(RzBin *bin, ut32 bf_id) {
	RzBinFile *bf;
	RzListIter *iter;
	rz_list_foreach (bin->binfiles, iter, bf) {
		if (bf->id == bf_id) {
			return bf;
		}
	}
	return NULL;
}

RZ_API ut64 rz_bin_file_delete_all(RzBin *bin) {
	rz_return_val_if_fail(bin, 0);
	ut64 counter = rz_list_length(bin->binfiles);
	RzListIter *it;
	RzBinFile *bf;
	rz_list_foreach (bin->binfiles, it, bf) {
		RzEventBinFileDel ev = { bf };
		rz_event_send(bin->event, RZ_EVENT_BIN_FILE_DEL, &ev);
	}
	rz_list_purge(bin->binfiles);
	bin->cur = NULL;
	return counter;
}

RZ_API bool rz_bin_file_delete(RzBin *bin, RzBinFile *bf) {
	rz_return_val_if_fail(bin && bf, false);
	RzListIter *it = rz_list_find_ptr(bin->binfiles, bf);
	rz_return_val_if_fail(it, false); // calling del on a bf not in the bin is a programming error
	if (bin->cur == bf) {
		bin->cur = NULL;
	}
	RzEventBinFileDel ev = { bf };
	rz_event_send(bin->event, RZ_EVENT_BIN_FILE_DEL, &ev);
	rz_list_delete(bin->binfiles, it);
	return true;
}

RZ_API RzBinFile *rz_bin_file_find_by_fd(RzBin *bin, ut32 bin_fd) {
	rz_return_val_if_fail(bin, NULL);
	RzListIter *iter;
	RzBinFile *bf;

	rz_list_foreach (bin->binfiles, iter, bf) {
		if (bf->fd == bin_fd) {
			return bf;
		}
	}
	return NULL;
}

RZ_API RzBinFile *rz_bin_file_find_by_name(RzBin *bin, const char *name) {
	RzListIter *iter;
	RzBinFile *bf;

	rz_return_val_if_fail(bin && name, NULL);

	rz_list_foreach (bin->binfiles, iter, bf) {
		if (bf->file && !strcmp(bf->file, name)) {
			return bf;
		}
	}
	return NULL;
}

RZ_API bool rz_bin_file_set_cur_by_id(RzBin *bin, ut32 bin_id) {
	RzBinFile *bf = rz_bin_file_find_by_id(bin, bin_id);
	return bf ? rz_bin_file_set_cur_binfile(bin, bf) : false;
}

RZ_API bool rz_bin_file_set_cur_by_fd(RzBin *bin, ut32 bin_fd) {
	RzBinFile *bf = rz_bin_file_find_by_fd(bin, bin_fd);
	return bf ? rz_bin_file_set_cur_binfile(bin, bf) : false;
}

RZ_IPI bool rz_bin_file_set_obj(RzBin *bin, RzBinFile *bf, RzBinObject *obj) {
	rz_return_val_if_fail(bin && bf, false);
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	if (obj) {
		bf->o = obj;
	} else {
		obj = bf->o;
	}
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	if (bin->minstrlen < 1) {
		bin->minstrlen = plugin ? plugin->minstrlen : bin->minstrlen;
	}
	if (obj) {
		if (!obj->info) {
			return false;
		}
		if (!obj->info->lang) {
			obj->info->lang = rz_bin_language_to_string(obj->lang);
		}
	}
	return true;
}

RZ_API bool rz_bin_file_set_cur_binfile(RzBin *bin, RzBinFile *bf) {
	rz_return_val_if_fail(bin && bf, false);
	return rz_bin_file_set_obj(bin, bf, bf->o);
}

RZ_API bool rz_bin_file_set_cur_by_name(RzBin *bin, const char *name) {
	rz_return_val_if_fail(bin && name, false);
	RzBinFile *bf = rz_bin_file_find_by_name(bin, name);
	return rz_bin_file_set_cur_binfile(bin, bf);
}

RZ_IPI RzBinFile *rz_bin_file_xtr_load_buffer(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, RzBuffer *buf, RzBinObjectLoadOptions *obj_opts, int idx, int fd) {
	rz_return_val_if_fail(bin && xtr && buf, NULL);

	RzBinFile *bf = rz_bin_file_find_by_name(bin, filename);
	if (!bf) {
		bf = rz_bin_file_new(bin, filename, rz_buf_size(buf), fd, xtr->name, false);
		if (!bf) {
			return NULL;
		}
		rz_list_append(bin->binfiles, bf);
		if (!bin->cur) {
			bin->cur = bf;
		}
	}
	rz_list_free(bf->xtr_data);
	bf->xtr_data = NULL;
	if (xtr->extractall_from_buffer) {
		bf->xtr_data = xtr->extractall_from_buffer(bin, buf);
	} else if (xtr->extractall_from_bytes) {
		ut64 sz = 0;
		const ut8 *bytes = rz_buf_data(buf, &sz);
		RZ_LOG_INFO("TODO: Implement extractall_from_buffer in '%s' xtr.bin plugin\n", xtr->name);
		bf->xtr_data = xtr->extractall_from_bytes(bin, bytes, sz);
	}
	if (bf->xtr_data) {
		RzListIter *iter;
		RzBinXtrData *x;
		// populate xtr_data with baddr and laddr that will be used later on
		// rz_bin_file_object_new_from_xtr_data
		rz_list_foreach (bf->xtr_data, iter, x) {
			x->obj_opts = *obj_opts;
		}
	}
	bf->loadaddr = obj_opts->loadaddr;
	return bf;
}

// XXX deprecate this function imho.. wee can just access bf->buf directly
RZ_IPI bool rz_bin_file_set_bytes(RzBinFile *bf, const ut8 *bytes, ut64 sz, bool steal_ptr) {
	rz_return_val_if_fail(bf && bytes, false);
	rz_buf_free(bf->buf);
	if (steal_ptr) {
		bf->buf = rz_buf_new_with_pointers(bytes, sz, true);
	} else {
		bf->buf = rz_buf_new_with_bytes(bytes, sz);
	}
	return bf->buf != NULL;
}

RZ_API RzBinPlugin *rz_bin_file_cur_plugin(RzBinFile *bf) {
	return (bf && bf->o) ? bf->o->plugin : NULL;
}

RZ_API ut64 rz_bin_file_get_baddr(RzBinFile *bf) {
	if (bf && bf->o) {
		return bf->o->opts.baseaddr;
	}
	return UT64_MAX;
}

RZ_API bool rz_bin_file_close(RzBin *bin, int bd) {
	rz_return_val_if_fail(bin, false);
	RzBinFile *bf = rz_id_storage_take(bin->ids, bd);
	if (bf) {
		// file_free removes the fd already.. maybe its unnecessary
		rz_id_storage_delete(bin->ids, bd);
		rz_bin_file_free(bf);
		return true;
	}
	return false;
}

static inline bool add_file_hash(RzHashCfg *md, const char *name, RzList *list) {
	char hash[128];
	const ut8 *digest = NULL;
	RzHashSize digest_size = 0;

	digest = rz_hash_cfg_get_result(md, name, &digest_size);
	if (!digest) {
		return false;
	}

	if (!strcmp(name, "entropy")) {
		double entropy = rz_read_be_double(digest);
		rz_strf(hash, "%f", entropy);
	} else {
		rz_hex_bin2str(digest, digest_size, hash);
	}

	RzBinFileHash *fh = RZ_NEW0(RzBinFileHash);
	if (!fh) {
		RZ_LOG_ERROR("Cannot allocate RzBinFileHash\n");
		return false;
	}

	fh->type = strdup(name);
	fh->hex = strdup(hash);
	rz_list_push(list, fh);
	return true;
}

static ut64 buf_compute_hashes(const ut8 *buf, ut64 size, void *user) {
	if (!rz_hash_cfg_update((RzHashCfg *)user, buf, size)) {
		return 0;
	}
	return size;
}

/**
 * Return a list of RzBinFileHash structures with the hashes md5, sha1, sha256, crc32 and entropy
 * computed over the whole \p bf .
 */
RZ_API RZ_OWN RzList *rz_bin_file_compute_hashes(RzBin *bin, RzBinFile *bf, ut64 limit) {
	rz_return_val_if_fail(bin && bf && bf->o, NULL);
	RzBinObject *o = bf->o;
	RzList *file_hashes = NULL;
	RzHashCfg *md = NULL;
	RzBuffer *buf = rz_buf_new_with_io_fd(&bin->iob, bf->fd);
	const ut64 buf_size = rz_buf_size(buf);
	if (!buf_size) {
		rz_buf_free(buf);
		return NULL;
	}
	if (buf_size > limit) {
		if (bin->verbose) {
			RZ_LOG_WARN("rz_bin_file_hash: file exceeds bin.hashlimit\n");
		}
		return NULL;
	}
	file_hashes = rz_list_newf((RzListFree)rz_bin_file_hash_free);
	if (!file_hashes) {
		RZ_LOG_ERROR("Cannot allocate file hash list\n");
		goto rz_bin_file_compute_hashes_bad;
	}

	md = rz_hash_cfg_new(bin->hash);
	if (!md) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (!rz_hash_cfg_configure(md, "md5") ||
		!rz_hash_cfg_configure(md, "sha1") ||
		!rz_hash_cfg_configure(md, "sha256") ||
		!rz_hash_cfg_configure(md, "crc32") ||
		!rz_hash_cfg_configure(md, "entropy")) {
		goto rz_bin_file_compute_hashes_bad;
	}
	if (!rz_hash_cfg_init(md)) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (rz_buf_fwd_scan(buf, 0, buf_size, buf_compute_hashes, md) != buf_size) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (!rz_hash_cfg_final(md)) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (!add_file_hash(md, "md5", file_hashes) ||
		!add_file_hash(md, "sha1", file_hashes) ||
		!add_file_hash(md, "sha256", file_hashes) ||
		!add_file_hash(md, "crc32", file_hashes) ||
		!add_file_hash(md, "entropy", file_hashes)) {
		goto rz_bin_file_compute_hashes_bad;
	}

	if (o->plugin && o->plugin->hashes) {
		RzList *plugin_hashes = o->plugin->hashes(bf);
		rz_list_join(file_hashes, plugin_hashes);
		rz_list_free(plugin_hashes);
	}

	// TODO: add here more rows
	rz_buf_free(buf);
	rz_hash_cfg_free(md);
	return file_hashes;

rz_bin_file_compute_hashes_bad:
	rz_buf_free(buf);
	rz_hash_cfg_free(md);
	rz_list_free(file_hashes);
	return NULL;
}

/**
 * \brief Set \p file_hashes on current RzBinInfo
 * \return RzList of previous file_hashes
 */
RZ_API RZ_OWN RzList *rz_bin_file_set_hashes(RzBin *bin, RZ_OWN RzList /*<RzBinFileHash *>*/ *new_hashes) {
	rz_return_val_if_fail(bin && bin->cur && bin->cur->o && bin->cur->o->info, NULL);
	RzBinFile *bf = bin->cur;
	RzBinInfo *info = bf->o->info;

	RzList *prev_hashes = info->file_hashes;
	info->file_hashes = new_hashes;

	return prev_hashes;
}

RZ_IPI RzBinClass *rz_bin_class_new(const char *name, const char *super, int view) {
	rz_return_val_if_fail(name, NULL);
	RzBinClass *c = RZ_NEW0(RzBinClass);
	if (c) {
		c->name = strdup(name);
		c->super = super ? strdup(super) : NULL;
		c->methods = rz_list_new();
		c->fields = rz_list_new();
		c->visibility = view;
	}
	return c;
}

RZ_IPI void rz_bin_class_free(RzBinClass *k) {
	if (k && k->name) {
		free(k->name);
		free(k->super);
		rz_list_free(k->methods);
		rz_list_free(k->fields);
		free(k->visibility_str);
		free(k);
	}
}

RZ_API RzBinClass *rz_bin_file_add_class(RzBinFile *bf, const char *name, const char *super, int view) {
	rz_return_val_if_fail(name && bf && bf->o, NULL);
	RzBinClass *c = __getClass(bf, name);
	if (c) {
		if (super) {
			free(c->super);
			c->super = strdup(super);
		}
		return c;
	}
	c = rz_bin_class_new(name, super, view);
	if (c) {
		// XXX. no need for a list, the ht is iterable too
		c->index = rz_list_length(bf->o->classes);
		rz_list_append(bf->o->classes, c);
		ht_pp_insert(bf->o->classes_ht, name, c);
	}
	return c;
}

RZ_API RzBinSymbol *rz_bin_file_add_method(RzBinFile *bf, const char *klass, const char *method, int nargs) {
	rz_return_val_if_fail(bf, NULL);

	RzBinClass *c = rz_bin_file_add_class(bf, klass, NULL, 0);
	if (!c) {
		RZ_LOG_ERROR("Cannot allocate RzBinClass for '%s'\n", klass);
		return NULL;
	}
	RzBinSymbol *sym = __getMethod(bf, klass, method);
	if (!sym) {
		sym = RZ_NEW0(RzBinSymbol);
		if (sym) {
			sym->name = strdup(method);
			rz_list_append(c->methods, sym);
			const char *name = sdb_fmt("%s::%s", klass, method);
			ht_pp_insert(bf->o->methods_ht, name, sym);
		}
	}
	return sym;
}

RZ_API RzList *rz_bin_file_get_trycatch(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->plugin, NULL);
	if (bf->o->plugin->trycatch) {
		return bf->o->plugin->trycatch(bf);
	}
	return NULL;
}

RZ_API RzList *rz_bin_file_get_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinObject *o = bf->o;
	return o ? (RzList *)rz_bin_object_get_symbols(o) : NULL;
}
