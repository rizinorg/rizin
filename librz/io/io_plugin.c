// SPDX-FileCopyrightText: 2008-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "config.h"
#include <stdio.h>

static volatile RzIOPlugin *default_plugin = NULL;

static RzIOPlugin *io_static_plugins[] = {
	RZ_IO_STATIC_PLUGINS
};

RZ_API bool rz_io_plugin_add(RzIO *io, RZ_BORROW RzIOPlugin *plugin) {
	if (!io || !io->plugins || !plugin || !plugin->name) {
		return false;
	}
	RzListIter *it;
	RzIOPlugin *nplugin;
	rz_list_foreach (io->plugins, it, nplugin) {
		if (!strcmp(nplugin->name, plugin->name)) {
			return false;
		}
	}
	nplugin = RZ_NEW0(RzIOPlugin);
	if (!nplugin) {
		return false;
	}
	memcpy(nplugin, plugin, sizeof(RzIOPlugin));
	rz_list_append(io->plugins, nplugin);
	return true;
}

RZ_API bool rz_io_plugin_init(RzIO *io) {
	int i;
	if (!io) {
		return false;
	}
	io->plugins = rz_list_newf(free);
	for (i = 0; io_static_plugins[i]; i++) {
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
	RzListIter *iter;
	RzIOPlugin *ret;
	rz_list_foreach (io->plugins, iter, ret) {
		if (!ret || !ret->check) {
			continue;
		}
		if (ret->check(io, filename, many)) {
			return ret;
		}
	}
	return rz_io_plugin_get_default(io, filename, many);
}

RZ_API RzIOPlugin *rz_io_plugin_byname(RzIO *io, const char *name) {
	RzListIter *iter;
	RzIOPlugin *iop;
	rz_list_foreach (io->plugins, iter, iop) {
		if (!strcmp(name, iop->name)) {
			return iop;
		}
	}
	return rz_io_plugin_get_default(io, name, false);
}

RZ_API int rz_io_plugin_read(RzIODesc *desc, ut8 *buf, int len) {
	if (!buf || !desc || !desc->plugin || len < 1 || !(desc->perm & RZ_PERM_R)) {
		return 0;
	}
	if (!desc->plugin->read) {
		return -1;
	}
	return desc->plugin->read(desc->io, desc, buf, len);
}

RZ_API int rz_io_plugin_write(RzIODesc *desc, const ut8 *buf, int len) {
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

RZ_API int rz_io_plugin_read_at(RzIODesc *desc, ut64 addr, ut8 *buf, int len) {
	if (rz_io_desc_is_chardevice(desc) || (rz_io_desc_seek(desc, addr, RZ_IO_SEEK_SET) == addr)) {
		return rz_io_plugin_read(desc, buf, len);
	}
	return 0;
}

RZ_API int rz_io_plugin_write_at(RzIODesc *desc, ut64 addr, const ut8 *buf, int len) {
	if (rz_io_desc_is_chardevice(desc) || rz_io_desc_seek(desc, addr, RZ_IO_SEEK_SET) == addr) {
		return rz_io_plugin_write(desc, buf, len);
	}
	return 0;
}
