// SPDX-FileCopyrightText: 2008-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "config.h"
#include <stdio.h>

static volatile RzIOPlugin *default_plugin = NULL;

static RzIOPlugin *io_static_plugins[] = {
	RZ_IO_STATIC_PLUGINS
};

RZ_API bool rz_io_plugin_add(RzIO *io, RzIOPlugin *plugin) {
	if (!io || !io->plugins || !plugin || !plugin->name) {
		return false;
	}
	ls_append(io->plugins, plugin);
	return true;
}

RZ_API bool rz_io_plugin_init(RzIO *io) {
	RzIOPlugin *static_plugin;
	int i;
	if (!io) {
		return false;
	}
	io->plugins = ls_newf(free);
	for (i = 0; io_static_plugins[i]; i++) {
		if (!io_static_plugins[i]->name) {
			continue;
		}
		static_plugin = RZ_NEW0(RzIOPlugin);
		if (!static_plugin) {
			return false;
		}
		memcpy(static_plugin, io_static_plugins[i], sizeof(RzIOPlugin));
		rz_io_plugin_add(io, static_plugin);
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
	SdbListIter *iter;
	RzIOPlugin *ret;
	ls_foreach (io->plugins, iter, ret) {
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
	SdbListIter *iter;
	RzIOPlugin *iop;
	ls_foreach (io->plugins, iter, iop) {
		if (!strcmp(name, iop->name)) {
			return iop;
		}
	}
	return rz_io_plugin_get_default(io, name, false);
}

RZ_API int rz_io_plugin_list(RzIO *io) {
	RzIOPlugin *plugin;
	SdbListIter *iter;
	char str[4];
	int n = 0;

	ls_foreach (io->plugins, iter, plugin) {
		str[0] = 'r';
		str[1] = plugin->write ? 'w' : '_';
		str[2] = plugin->isdbg ? 'd' : '_';
		str[3] = 0;
		io->cb_printf("%s  %-8s %s (%s)",
			str, plugin->name,
			plugin->desc, plugin->license);
		if (plugin->uris) {
			io->cb_printf(" %s", plugin->uris);
		}
		if (plugin->version) {
			io->cb_printf(" v%s", plugin->version);
		}
		if (plugin->author) {
			io->cb_printf(" %s", plugin->author);
		}
		io->cb_printf("\n");
		n++;
	}
	return n;
}

RZ_API int rz_io_plugin_list_json(RzIO *io) {
	RzIOPlugin *plugin;
	SdbListIter *iter;
	PJ *pj = pj_new();
	if (!pj) {
		return 0;
	}

	char str[4];
	int n = 0;
	pj_o(pj);
	pj_k(pj, "io_plugins");
	pj_a(pj);
	ls_foreach (io->plugins, iter, plugin) {
		str[0] = 'r';
		str[1] = plugin->write ? 'w' : '_';
		str[2] = plugin->isdbg ? 'd' : '_';
		str[3] = 0;

		pj_o(pj);
		pj_ks(pj, "permissions", str);
		pj_ks(pj, "name", plugin->name);
		pj_ks(pj, "description", plugin->desc);
		pj_ks(pj, "license", plugin->license);

		if (plugin->uris) {
			char *uri;
			char *uris = strdup(plugin->uris);
			RzList *plist = rz_str_split_list(uris, ",", 0);
			RzListIter *piter;
			pj_k(pj, "uris");
			pj_a(pj);
			rz_list_foreach (plist, piter, uri) {
				pj_s(pj, uri);
			}
			pj_end(pj);
			rz_list_free(plist);
			free(uris);
		}
		if (plugin->version) {
			pj_ks(pj, "version", plugin->version);
		}
		if (plugin->author) {
			pj_ks(pj, "author", plugin->author);
		}
		pj_end(pj);
		n++;
	}
	pj_end(pj);
	pj_end(pj);
	io->cb_printf("%s", pj_string(pj));
	pj_free(pj);
	return n;
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
