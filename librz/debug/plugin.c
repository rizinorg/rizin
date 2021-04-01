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
	if (dbg && str) {
		RzDebugPlugin *h;
		RzListIter *iter;
		rz_list_foreach (dbg->plugins, iter, h) {
			if (h->name && !strcmp(str, h->name)) {
				dbg->h = h;
				if (dbg->analysis && dbg->analysis->cur) {
					rz_debug_set_arch(dbg, dbg->analysis->cur->arch, dbg->bits);
				}
				dbg->bp->breakpoint = dbg->h->breakpoint;
				dbg->bp->user = dbg;
			}
		}
	}
	if (dbg && dbg->h && dbg->h->reg_profile) {
		char *p = dbg->h->reg_profile(dbg);
		if (p) {
			rz_reg_set_profile_string(dbg->reg, p);
			if (dbg->analysis && dbg->reg != dbg->analysis->reg) {
				rz_reg_free(dbg->analysis->reg);
				dbg->analysis->reg = dbg->reg;
			}
			if (dbg->h->init) {
				dbg->h->init(dbg);
			}
			rz_reg_set_profile_string(dbg->reg, p);
			free(p);
		} else {
			eprintf("Cannot retrieve reg profile from debug plugin (%s)\n", dbg->h->name);
		}
	}
	return (dbg && dbg->h);
}

RZ_API int rz_debug_plugin_list(RzDebug *dbg, int mode) {
	char spaces[16];
	int count = 0;
	memset(spaces, ' ', 15);
	spaces[15] = 0;
	RzDebugPlugin *h;
	RzListIter *iter;
	if (mode == 'j') {
		dbg->cb_printf("[");
	}
	rz_list_foreach (dbg->plugins, iter, h) {
		int sp = 8 - strlen(h->name);
		spaces[sp] = 0;
		if (mode == 'q') {
			dbg->cb_printf("%s\n", h->name);
		} else if (mode == 'j') {
			dbg->cb_printf("%s{\"name\":\"%s\",\"license\":\"%s\"}",
				(count ? "," : ""),
				h->name,
				h->license);
		} else {
			dbg->cb_printf("%d  %s  %s %s%s\n",
				count, (h == dbg->h) ? "dbg" : "---",
				h->name, spaces, h->license);
		}
		spaces[sp] = ' ';
		count++;
	}
	if (mode == 'j') {
		dbg->cb_printf("]");
	}
	return false;
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
	if (dbg && dbg->h && dbg->h->set_reg_profile) {
		return dbg->h->set_reg_profile(str);
	}
	free(str);
	return false;
}
