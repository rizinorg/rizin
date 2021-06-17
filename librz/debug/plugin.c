// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <config.h>

static RzDebugPlugin *debug_static_plugins[] = {
	RZ_DEBUG_STATIC_PLUGINS
};

RZ_API void rz_debug_plugin_init(RzDebug *dbg) {
	int i;
	dbg->plugins = rz_list_newf(free);
	for (i = 0; debug_static_plugins[i]; i++) {
		rz_debug_plugin_add(dbg, debug_static_plugins[i]);
	}
}

RZ_API bool rz_debug_use(RzDebug *dbg, const char *str) {
	rz_return_val_if_fail(dbg, false);
	RzDebugPlugin *new_plugin = NULL;
	if (str) {
		RzDebugPlugin *h;
		RzListIter *iter;
		rz_list_foreach (dbg->plugins, iter, h) {
			if (h->name && !strcmp(str, h->name)) {
				new_plugin = h;
				break;
			}
		}
		if (!new_plugin) {
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
	if (dbg->cur->reg_profile) {
		char *p = dbg->cur->reg_profile(dbg);
		if (p) {
			rz_reg_set_profile_string(dbg->reg, p);
			if (dbg->analysis && dbg->reg != dbg->analysis->reg) {
				rz_reg_free(dbg->analysis->reg);
				dbg->analysis->reg = dbg->reg;
			}
			rz_reg_set_profile_string(dbg->reg, p);
			free(p);
		} else {
			eprintf("Cannot retrieve reg profile from debug plugin (%s)\n", dbg->cur->name);
		}
	}
	return true;
}

RZ_API bool rz_debug_plugin_add(RzDebug *dbg, RzDebugPlugin *foo) {
	if (!dbg || !foo || !foo->name) {
		return false;
	}
	RzDebugPlugin *dp = RZ_NEW(RzDebugPlugin);
	memcpy(dp, foo, sizeof(RzDebugPlugin));
	rz_list_append(dbg->plugins, dp);
	return true;
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
