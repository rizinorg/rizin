// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debugger.h>

static RzDebuggerPlugin *debugger_static_plugins[] = {
	/*RZ_DEBUGGER_STATIC_PLUGINS*/
	&rz_debugger_plugin_native,
	&rz_debugger_plugin_null,
};

/**
 * \brief      Allocates and initialize a new RzDebugger structure.
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzDebugger *rz_debugger_new(void) {
	RzDebugger *dbg = RZ_NEW0(RzDebugger);
	if (!dbg) {
		return NULL;
	}

	dbg->plugins = rz_list_new_from_array((const void **)debugger_static_plugins, RZ_ARRAY_SIZE(debugger_static_plugins));
	if (!dbg->plugins || !rz_debugger_use(dbg, "null")) {
		goto fail;
	}

	dbg->process_id = RZ_PROCESS_ID_INVALID;
	dbg->thread_id = RZ_PROCESS_ID_INVALID;
	return dbg;

fail:
	rz_debugger_free(dbg);
	return NULL;
}

static void debugger_plugin_fini(RzDebugger *dbg) {
	if (dbg->handle && dbg->handle->fini) {
		dbg->handle->fini(dbg->handle_ctx);
	}
	dbg->handle = NULL;
	dbg->handle_ctx = NULL;
	dbg->process_id = RZ_PROCESS_ID_INVALID;
	dbg->thread_id = RZ_PROCESS_ID_INVALID;
}

static void debugger_plugin_init(RzDebugger *dbg, const RzDebuggerPlugin *handle) {
	if (!handle) {
		return;
	}
	dbg->handle = handle;
	if (dbg->handle->init) {
		dbg->handle_ctx = dbg->handle->init();
	}
}

/**
 * \brief      Frees a RzDebugger structure.
 *
 * \param      dbg   RzDebugger struct to free.
 */
RZ_API void rz_debugger_free(RZ_NULLABLE RzDebugger *dbg) {
	if (!dbg) {
		return;
	}
	debugger_plugin_fini(dbg);
	rz_list_free(dbg->plugins);
	free(dbg);
}

/**
 * \brief      Selects which debugger to use.
 *
 * \param      dbg   RzDebugger struct to use
 * \param[in]  name  The name of the plugin to select
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_debugger_use(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(dbg && name, false);

	RzListIter *iter;
	const RzDebuggerPlugin *h;
	rz_list_foreach (dbg->plugins, iter, h) {
		rz_warn_if_fail(h && h->name);
		if (h->name && !strcmp(name, h->name)) {
			debugger_plugin_fini(dbg);
			debugger_plugin_init(dbg, h);
			return true;
		}
	}
	return false;
}

/**
 * \brief      Adds a new RzDebuggerPlugin to a RzDebugger structure.
 *
 * \param      dbg     RzDebugger struct to use
 * \param      plugin  The pointer to plugin to add
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_debugger_plugin_add(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RzDebuggerPlugin *plugin) {
	rz_return_val_if_fail(dbg && plugin, false);

	RZ_PLUGIN_CHECK_AND_ADD(dbg->plugins, plugin, RzDebuggerPlugin);
	return true;
}

/**
 * \brief      Removes a new RzDebuggerPlugin to a RzDebugger structure.
 * if the plugin is being used, it will call the fini callback.
 *
 * \param      dbg     RzDebugger struct to use
 * \param      plugin  The pointer to plugin to remove
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_debugger_plugin_del(RZ_NONNULL RzDebugger *dbg, RZ_NONNULL RzDebuggerPlugin *plugin) {
	rz_return_val_if_fail(dbg && plugin, false);

	if (dbg->handle == plugin) {
		debugger_plugin_fini(dbg);
	}
	rz_list_delete_data(dbg->plugins, plugin);
	return true;
}
