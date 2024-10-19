// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_lib.h>
#include "rz_debug_plugins.h"

static RzDebugPlugin *debug_static_plugins[] = { RZ_DEBUG_STATIC_PLUGINS };

RZ_API void rz_debug_plugin_init(RzDebug *dbg) {
	int i;
	dbg->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (i = 0; i < RZ_ARRAY_SIZE(debug_static_plugins); i++) {
		rz_debug_plugin_add(dbg, debug_static_plugins[i]);
	}
}

RZ_API bool rz_debug_use(RzDebug *dbg, const char *name) {
	rz_return_val_if_fail(dbg, false);
	RzDebugPlugin *new_plugin = NULL;
	if (name) {
		bool found = false;
		new_plugin = ht_sp_find(dbg->plugins, name, &found);
		if (!found) {
			return false;
		}
	}
	if (new_plugin == dbg->cur) {
		return true;
	}
	if (dbg->cur && dbg->cur->fini) {
		dbg->cur->fini(dbg, dbg->plugin_data);
	}
	dbg->cur = new_plugin;
	dbg->plugin_data = NULL;
	if (!dbg->cur) {
		return true;
	}
	if (dbg->analysis && dbg->analysis->cur) {
		rz_debug_set_arch(dbg, dbg->analysis->cur->arch, dbg->bits);
	}
	dbg->bp->breakpoint = dbg->cur->breakpoint;
	dbg->bp->user = dbg;
	if (dbg->cur->init) {
		dbg->cur->init(dbg, &dbg->plugin_data);
	}
	// Syncing the reg profile here may fail if the plugin is not ready, but it should
	// at least clean up the old RzReg contents.
	rz_debug_reg_profile_sync(dbg);
	return true;
}

RZ_API bool rz_debug_plugin_add(RzDebug *dbg, RZ_NONNULL RzDebugPlugin *plugin) {
	rz_return_val_if_fail(dbg && plugin && plugin->name, false);
	ht_sp_insert(dbg->plugins, plugin->name, plugin);
	return true;
}

RZ_API bool rz_debug_plugin_del(RzDebug *dbg, RZ_NONNULL RzDebugPlugin *plugin) {
	rz_return_val_if_fail(dbg && plugin, false);
	if (dbg->cur == plugin) {
		dbg->cur->fini(dbg, dbg->plugin_data);
		dbg->cur = NULL;
		dbg->plugin_data = NULL;
	}
	return ht_sp_delete(dbg->plugins, plugin->name);
}

RZ_API bool rz_debug_plugin_set_reg_profile(RzDebug *dbg, const char *profile) {
	char *str = rz_file_slurp(profile, NULL);
	if (!str) {
		eprintf("rz_debug_plugin_set_reg_profile: Cannot find '%s'\n", profile);
		return false;
	}
	if (dbg && dbg->cur && dbg->cur->set_reg_profile) {
		return dbg->cur->set_reg_profile(dbg, str);
	}
	free(str);
	return false;
}
