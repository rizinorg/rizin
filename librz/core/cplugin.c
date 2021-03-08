// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <config.h>
#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_list.h>
#include <stdio.h>

static RzCorePlugin *core_static_plugins[] = {
	RZ_CORE_STATIC_PLUGINS
};

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
	core->plugins = NULL;
	return true;
}

RZ_API bool rz_core_plugin_add(RzCore *core, RzCorePlugin *plugin) {
	rz_return_val_if_fail(core, false);
	rz_return_val_if_fail(plugin && plugin->init && plugin->name && plugin->author && plugin->license, false);
	if (!plugin->init(core)) {
		return false;
	}
	rz_list_append(core->plugins, plugin);
	return true;
}

RZ_API bool rz_core_plugin_init(RzCore *core) {
	int i;
	core->plugins = rz_list_newf(NULL); // memleak or dblfree
	for (i = 0; core_static_plugins[i]; i++) {
		if (!rz_core_plugin_add(core, core_static_plugins[i])) {
			eprintf("Error loading core plugin\n");
			return false;
		}
	}
	return true;
}