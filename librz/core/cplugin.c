// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_list.h>
#include <rz_lib.h>
#include <stdio.h>
#include "rz_core_plugins.h"

static RzCorePlugin *core_static_plugins[] = { RZ_CORE_STATIC_PLUGINS };

RZ_API bool rz_core_plugin_fini(RzCore *core) {
	rz_return_val_if_fail(core->plugins, false);

	RzListIter *iter;
	RzCorePlugin *plugin;
	rz_list_foreach (core->plugins, iter, plugin) {
		if (plugin->fini) {
			plugin->fini(core);
		}
	}
	rz_list_free(core->plugins);
	ht_sp_free(core->plugin_configs);
	core->plugins = NULL;
	return true;
}

RZ_API bool rz_core_plugin_add(RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core, false);
	rz_return_val_if_fail(plugin && plugin->init && plugin->name && plugin->author && plugin->license, false);
	// TODO: Add config from core plugin.
	RZ_PLUGIN_CHECK_AND_ADD(core->plugins, plugin, RzCorePlugin);
	if (!plugin->init(core)) {
		RZ_PLUGIN_REMOVE(core->plugins, plugin);
		return false;
	}
	return true;
}

RZ_API bool rz_core_plugin_del(RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core && plugin, false);
	ht_sp_delete(core->plugin_configs, plugin->name);
	if (plugin->fini && !plugin->fini(core)) {
		return false;
	}
	return rz_list_delete_data(core->plugins, plugin);
}

RZ_API bool rz_core_plugin_init(RzCore *core) {
	int i;
	bool res = true;
	core->plugins = rz_list_new();
	for (i = 0; i < RZ_ARRAY_SIZE(core_static_plugins); i++) {
		if (!rz_core_plugin_add(core, core_static_plugins[i])) {
			RZ_LOG_ERROR("core: error loading core plugin '%s'\n", core_static_plugins[i]->name);
			res = false;
		}
	}
	return res;
}
