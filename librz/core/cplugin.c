/* radare - LGPL - Copyright 2010-2018 - pancake */

/* covardly copied from rz_cmd */

#include <config.h>
#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_list.h>
#include <stdio.h>

static RzCorePlugin *cmd_static_plugins[] = {
	RZ_CORE_STATIC_PLUGINS
};

RZ_API int rz_core_plugin_fini(RzCmd *cmd) {
	RzListIter *iter;
	RzCorePlugin *plugin;
	if (!cmd->plist) {
		return false;
	}
	rz_list_foreach (cmd->plist, iter, plugin) {
		if (plugin && plugin->fini) {
			plugin->fini (cmd, NULL);
		}
	}
	/* empty the list */
	rz_list_free (cmd->plist);
	cmd->plist = NULL;
	return true;
}

RZ_API int rz_core_plugin_add(RzCmd *cmd, RzCorePlugin *plugin) {
	if (!cmd || (plugin && plugin->init && !plugin->init (cmd, NULL))) {
		return false;
	}
	rz_list_append (cmd->plist, plugin);
	return true;
}

RZ_API int rz_core_plugin_init(RzCmd *cmd) {
	int i;
	cmd->plist = rz_list_newf (NULL); // memleak or dblfree
	for (i = 0; cmd_static_plugins[i]; i++) {
		if (!rz_core_plugin_add (cmd, cmd_static_plugins[i])) {
			eprintf ("Error loading cmd plugin\n");
			return false;
		}
	}
	return true;
}

RZ_API int rz_core_plugin_check(RzCmd *cmd, const char *a0) {
	RzListIter *iter;
	RzCorePlugin *cp;
	rz_list_foreach (cmd->plist, iter, cp) {
		if (cp->call (NULL, a0)) {
			return true;
		}
	}
	return false;
}
