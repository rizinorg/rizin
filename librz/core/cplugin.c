// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_list.h>
#include <rz_lib.h>
#include <stdio.h>
#include "rz_core_plugins.h"

static RzCorePlugin *core_static_plugins[] = { RZ_CORE_STATIC_PLUGINS };

static bool core_plugin_init(RzCore *core, RzCorePlugin *plugin, void **user) {
	*user = NULL;
	return plugin->init(core, user);
}

static bool core_plugin_fini(RzCore *core, RzCorePlugin *plugin) {
	void *user = rz_core_plugin_context_get(core, plugin);
	bool res = true;
	if (plugin->fini) {
		res = plugin->fini(core, user);
	}
	if (res && core->plugin_contexts) {
		ht_sp_delete(core->plugin_contexts, plugin->name);
	}
	return res;
}

RZ_API bool rz_core_plugin_fini(RzCore *core) {
	rz_return_val_if_fail(core->plugins, false);

	RzIterator *iter = ht_sp_as_iter(core->plugins);
	RzCorePlugin **val;
	rz_iterator_foreach(iter, val) {
		RzCorePlugin *plugin = *val;
		core_plugin_fini(core, plugin);
	}
	rz_iterator_free(iter);
	ht_sp_free(core->plugins);
	RZ_FREE_CUSTOM(core->plugin_contexts, ht_sp_free);
	ht_sp_free(core->plugin_configs);
	core->plugins = NULL;
	core->plugin_contexts = NULL;
	return true;
}

RZ_API bool rz_core_plugin_add(RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core, false);
	rz_return_val_if_fail(plugin && plugin->init && plugin->name && plugin->author && plugin->license, false);
	// TODO: Add config from core plugin.
	bool found = false;
	ht_sp_find(core->plugins, plugin->name, &found);
	if (found) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
		return false;
	}
	if (!ht_sp_insert(core->plugins, plugin->name, plugin)) {
		return false;
	}
	void *user = NULL;
	if (!core_plugin_init(core, plugin, &user)) {
		if (plugin->fini && user) {
			plugin->fini(core, user);
		}
		ht_sp_delete(core->plugins, plugin->name);
		return false;
	}
	if (user && (!core->plugin_contexts || !ht_sp_insert(core->plugin_contexts, plugin->name, user))) {
		if (plugin->fini) {
			plugin->fini(core, user);
		}
		ht_sp_delete(core->plugins, plugin->name);
		return false;
	}
	return true;
}

RZ_API bool rz_core_plugin_del(RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core && plugin, false);
	ht_sp_delete(core->plugin_configs, plugin->name);
	if (!core_plugin_fini(core, plugin)) {
		return false;
	}
	return ht_sp_delete(core->plugins, plugin->name);
}

RZ_API bool rz_core_plugin_init(RzCore *core) {
	int i;
	bool res = true;
	core->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	core->plugin_contexts = ht_sp_new(HT_STR_DUP, NULL, NULL);
	if (!core->plugins || !core->plugin_contexts) {
		RZ_FREE_CUSTOM(core->plugins, ht_sp_free);
		RZ_FREE_CUSTOM(core->plugin_contexts, ht_sp_free);
		return false;
	}
	for (i = 0; i < RZ_ARRAY_SIZE(core_static_plugins); i++) {
		if (!rz_core_plugin_add(core, core_static_plugins[i])) {
			RZ_LOG_ERROR("core: error loading core plugin '%s'\n", core_static_plugins[i]->name);
			res = false;
		}
	}
	return res;
}

RZ_API void *rz_core_plugin_context_get(RZ_NONNULL RzCore *core, RZ_NONNULL RzCorePlugin *plugin) {
	rz_return_val_if_fail(core && plugin && plugin->name, NULL);
	return core->plugin_contexts ? ht_sp_find(core->plugin_contexts, plugin->name, NULL) : NULL;
}

RZ_API RzCmdDesc *rz_core_plugin_cmd_desc_argv_new(RZ_NONNULL RzCore *core,
	RZ_NONNULL const char *name, RZ_NONNULL RzCmdArgvCb cb,
	RZ_NONNULL const RzCmdDescHelp *help) {
	rz_return_val_if_fail(core && core->rcmd && name && cb && help, NULL);
	RzCmdDesc *root_cd = rz_cmd_get_root(core->rcmd);
	return root_cd ? rz_cmd_desc_argv_new(core->rcmd, root_cd, name, cb, help) : NULL;
}

RZ_API RzCmdDesc *rz_core_plugin_cmd_desc_group_new(RZ_NONNULL RzCore *core,
	RZ_NONNULL const char *name, RZ_NULLABLE RzCmdArgvCb cb,
	RZ_NULLABLE const RzCmdDescHelp *help,
	RZ_NONNULL const RzCmdDescHelp *group_help) {
	rz_return_val_if_fail(core && core->rcmd && name && group_help, NULL);
	RzCmdDesc *root_cd = rz_cmd_get_root(core->rcmd);
	return root_cd ? rz_cmd_desc_group_new(core->rcmd, root_cd, name, cb, help, group_help) : NULL;
}

RZ_API bool rz_core_plugin_cmd_desc_remove(RZ_NONNULL RzCore *core, RZ_NULLABLE RzCmdDesc *desc) {
	rz_return_val_if_fail(core && core->rcmd, false);
	return desc ? rz_cmd_desc_remove(core->rcmd, desc) : true;
}
