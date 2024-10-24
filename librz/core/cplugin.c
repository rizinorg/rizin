// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_list.h>
#include <rz_lib.h>
#include <stdio.h>
#include "rz_core_plugins.h"
#include <rz_util/rz_iterator.h>

static RzCorePlugin *core_static_plugins[] = { RZ_CORE_STATIC_PLUGINS };

RZ_API bool rz_core_plugin_fini(RzCore *core) {
	rz_return_val_if_fail(core->plugins, false);

	RzIterator *iter = ht_sp_as_iter(core->plugins);
	RzCorePlugin **val;
	rz_iterator_foreach(iter, val) {
		RzCorePlugin *plugin = *val;
		if (plugin->fini) {
			bool found = false;
			void *pdata = ht_sp_find(core->plugins_data, plugin->name, &found);
			plugin->fini(core, found ? &pdata : NULL);
		}
	}
	rz_iterator_free(iter);
	ht_sp_free(core->plugins);
	ht_sp_free(core->plugins_data);
	ht_sp_free(core->plugins_config);
	core->plugins = NULL;
	return true;
}

RZ_API bool rz_core_plugin_add(RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core, false);
	rz_return_val_if_fail(plugin && plugin->init && plugin->name && plugin->author && plugin->license, false);
	bool found = false;
	if (found) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
		return true;
	}

	ht_sp_insert(core->plugins, plugin->name, plugin);
	ht_sp_insert(core->plugins_data, plugin->name, NULL);
	HtSPKv *pdata = ht_sp_find_kv(core->plugins_data, plugin->name, NULL);
	if (!plugin->init(core, &pdata->value)) {
		ht_sp_delete(core->plugins, plugin->name);
		ht_sp_delete(core->plugins_data, plugin->name);
		return false;
	}

	if (plugin->get_config) {
		RzConfig *pcfg = plugin->get_config(pdata->value);
		rz_config_lock(pcfg, 1);
		ht_sp_insert(core->plugins_config, plugin->name, pcfg);
	}
	return true;
}

RZ_API bool rz_core_plugin_del(RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core && plugin, false);
	ht_sp_delete(core->plugins_config, plugin->name);
	HtSPKv *pdata = ht_sp_find_kv(core->plugins_data, plugin->name, NULL);
	if (plugin->fini && !plugin->fini(core, &pdata->value)) {
		return false;
	}
	ht_sp_delete(core->plugins_data, plugin->name);
	ht_sp_delete(core->plugins_config, plugin->name);
	return ht_sp_delete(core->plugins, plugin->name);
}

RZ_API bool rz_core_plugin_init(RzCore *core) {
	bool res = true;
	core->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	core->plugins_data = ht_sp_new(HT_STR_DUP, NULL, NULL);
	core->plugins_config = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_config_free);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(core_static_plugins); i++) {
		if (!rz_core_plugin_add(core, core_static_plugins[i])) {
			RZ_LOG_ERROR("core: error loading core plugin '%s'\n", core_static_plugins[i]->name);
			res = false;
		}
	}
	return res;
}
