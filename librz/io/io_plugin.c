// SPDX-FileCopyrightText: 2008-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <stdio.h>

#include "rz_io_plugins.h"
#include "rz_util/ht_sp.h"
#include "rz_util/rz_iterator.h"

static volatile RzIOPlugin *default_plugin = NULL;

static RzIOPlugin *io_static_plugins[] = { RZ_IO_STATIC_PLUGINS };

RZ_API bool rz_io_plugin_add(RzIO *io, RZ_NONNULL RZ_BORROW RzIOPlugin *plugin) {
	rz_return_val_if_fail(io && plugin && plugin->name, false);
	ht_sp_insert(io->plugins, plugin->name, plugin);
	return true;
}

static bool close_if_plugin(void *user, void *data, ut32 id) {
	RzIOPlugin *plugin = (RzIOPlugin *)user;
	RzIODesc *desc = (RzIODesc *)data;
	if (desc->plugin == plugin) {
		rz_io_desc_close(desc);
	}
	return true;
}

RZ_API bool rz_io_plugin_del(RzIO *io, RZ_NONNULL RZ_BORROW RzIOPlugin *plugin) {
	rz_return_val_if_fail(io && plugin, false);
	rz_id_storage_foreach(io->files, close_if_plugin, plugin);
	return ht_sp_delete(io->plugins, plugin->name);
}

RZ_API bool rz_io_plugin_init(RzIO *io) {
	int i;
	if (!io) {
		return false;
	}
	io->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (i = 0; i < RZ_ARRAY_SIZE(io_static_plugins); i++) {
		if (!io_static_plugins[i]->name) {
			continue;
		}
		rz_io_plugin_add(io, io_static_plugins[i]);
	}
	return true;
}

RZ_API RzIOPlugin *rz_io_plugin_get_default(RzIO *io, const char *filename, bool many) {
	if (!default_plugin || !default_plugin->check || !default_plugin->check(io, filename, many)) {
		return NULL;
	}
	return (RzIOPlugin *)default_plugin;
}

RZ_API RzIOPlugin *rz_io_plugin_resolve(RzIO *io, const char *filename, bool many) {
	RzIterator *iter = ht_sp_as_iter(io->plugins);
	RzIOPlugin *ret;
	rz_iterator_foreach(iter, ret) {
		if (!ret || !ret->check) {
			continue;
		}
		if (ret->check(io, filename, many)) {
			return ret;
		}
	}
	rz_iterator_free(iter);
	return rz_io_plugin_get_default(io, filename, many);
}

RZ_API RzIOPlugin *rz_io_plugin_byname(RzIO *io, const char *name) {
	RzIterator *iter = ht_sp_as_iter(io->plugins);
	RzIOPlugin *iop;
	rz_iterator_foreach(iter, iop) {
		if (!strcmp(name, iop->name)) {
			return iop;
		}
	}
	rz_iterator_free(iter);
	return rz_io_plugin_get_default(io, name, false);
}

RZ_API int rz_io_plugin_read(RzIODesc *desc, ut8 *buf, size_t len) {
	if (!buf || !desc || !desc->plugin || len < 1 || !(desc->perm & RZ_PERM_R)) {
		return 0;
	}
	if (!desc->plugin->read) {
		return -1;
	}
	return desc->plugin->read(desc->io, desc, buf, len);
}

RZ_API int rz_io_plugin_write(RzIODesc *desc, const ut8 *buf, size_t len) {
	if (!buf || !desc || !desc->plugin || len < 1 || !(desc->perm & RZ_PERM_W)) {
		return 0;
	}
	if (!desc->plugin->write) {
		return -1;
	}
	const ut64 cur_addr = rz_io_desc_seek(desc, 0LL, RZ_IO_SEEK_CUR);
	int ret = desc->plugin->write(desc->io, desc, buf, len);
	RzEventIOWrite iow = { cur_addr, buf, len };
	rz_event_send(desc->io->event, RZ_EVENT_IO_WRITE, &iow);
	return ret;
}

RZ_API int rz_io_plugin_read_at(RzIODesc *desc, ut64 addr, ut8 *buf, size_t len) {
	if (rz_io_desc_is_chardevice(desc) || (rz_io_desc_seek(desc, addr, RZ_IO_SEEK_SET) == addr)) {
		return rz_io_plugin_read(desc, buf, len);
	}
	return 0;
}

RZ_API int rz_io_plugin_write_at(RzIODesc *desc, ut64 addr, const ut8 *buf, size_t len) {
	if (rz_io_desc_is_chardevice(desc) || rz_io_desc_seek(desc, addr, RZ_IO_SEEK_SET) == addr) {
		return rz_io_plugin_write(desc, buf, len);
	}
	return 0;
}
