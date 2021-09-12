// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_demangler.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_libdemangle.h>

static RzList *demangler_plugins = NULL;

#define DEFINE_DEMANGLER_PLUGIN(name, lang, lic, auth, handler) \
	RZ_API RzDemanglerPlugin libdemangle_##name = { \
		.language = lang, \
		.license = lic, \
		.author = auth, \
		.demangle = &handler, \
	}

#if WITH_GPL
DEFINE_DEMANGLER_PLUGIN(cpp, "c++", "GPL-2", "Free Software Foundation", libdemangle_handler_cxx);
#endif
#if WITH_SWIFT_DEMANGLER
DEFINE_DEMANGLER_PLUGIN(swift, "swift", "MIT", "pancake", libdemangle_handler_swift);
#endif

DEFINE_DEMANGLER_PLUGIN(java, "java", "LGPL3", "deroad", libdemangle_handler_java);
DEFINE_DEMANGLER_PLUGIN(msvc, "msvc", "LGPL3", "inisider", libdemangle_handler_msvc);
DEFINE_DEMANGLER_PLUGIN(objc, "objc", "LGPL3", "pancake", libdemangle_handler_objc);
DEFINE_DEMANGLER_PLUGIN(rust, "rust", "LGPL3", "pancake", libdemangle_handler_rust);

RZ_LIB_VERSION(rz_demangler);

/**
 * \brief Demangles java symbols
 */
RZ_API RZ_OWN char *rz_demangler_java(RZ_NULLABLE const char *symbol) {
	return libdemangle_handler_java(symbol);
}

/**
 * \brief Demangles c++ symbols
 */
RZ_API RZ_OWN char *rz_demangler_cxx(RZ_NONNULL const char *symbol) {
#if WITH_GPL
	return libdemangle_handler_cxx(symbol);
#else
	return NULL;
#endif
}

/**
 * \brief Demangles objc symbols
 */
RZ_API RZ_OWN char *rz_demangler_objc(RZ_NONNULL const char *symbol) {
	return libdemangle_handler_objc(symbol);
}

/**
 * \brief Demangles rust symbols
 */
RZ_API RZ_OWN char *rz_demangler_rust(RZ_NONNULL const char *symbol) {
	return libdemangle_handler_rust(symbol);
}

/**
 * \brief Demangles microsft vc symbols
 */
RZ_API RZ_OWN char *rz_demangler_msvc(RZ_NONNULL const char *symbol) {
	return libdemangle_handler_msvc(symbol);
}

/**
 * \brief Initializes the plugin list and sets the default demanglers
 */
RZ_API bool rz_demangler_plugin_init() {
	if (demangler_plugins) {
		return false;
	}

	demangler_plugins = rz_list_new();
	if (!demangler_plugins) {
		return false;
#if WITH_GPL
	} else if (!rz_list_append(demangler_plugins, &libdemangle_cpp)) {
		RZ_LOG_WARN("rz_demangler: failed to add cpp plugin");
		return false;
#endif
#if WITH_SWIFT_DEMANGLER
	} else if (!rz_list_append(demangler_plugins, &libdemangle_swift)) {
		RZ_LOG_WARN("rz_demangler: failed to add swift plugin");
		return false;
#endif
	} else if (!rz_list_append(demangler_plugins, &libdemangle_java)) {
		RZ_LOG_WARN("rz_demangler: failed to add java plugin");
		return false;
	} else if (!rz_list_append(demangler_plugins, &libdemangle_msvc)) {
		RZ_LOG_WARN("rz_demangler: failed to add msvc plugin");
		return false;
	} else if (!rz_list_append(demangler_plugins, &libdemangle_objc)) {
		RZ_LOG_WARN("rz_demangler: failed to add objc plugin");
		return false;
	} else if (!rz_list_append(demangler_plugins, &libdemangle_rust)) {
		RZ_LOG_WARN("rz_demangler: failed to add rust plugin");
		return false;
	}
	return true;
}

/**
 * \brief Frees the plugin list
 */
RZ_API void rz_demangler_plugin_fini() {
	rz_list_free(demangler_plugins);
	demangler_plugins = NULL;
}

/**
 * \brief Iterates over the plugin list
 * 
 * Iterates over the plugin list and passes a RzDemanglerPlugin pointer
 * to the iter function; if the iter function returns false, then the
 * iteration is halted.
 */
RZ_API void rz_demangler_plugin_iterate(RZ_NONNULL RzDemanglerIter iter, RZ_NULLABLE void *data) {
	rz_return_if_fail(iter);
	const RzDemanglerPlugin *plugin;
	RzListIter *it;

	rz_list_foreach (demangler_plugins, it, plugin) {
		if (!iter(plugin, data)) {
			break;
		}
	}
}

/**
 * \brief Adds a new demangler plugin to the plugin list
 * 
 * If two plugins handles the same language, then the old plugin is removed.
 */
RZ_API bool rz_demangler_plugin_add(RZ_NONNULL RzDemanglerPlugin *plugin) {
	rz_return_val_if_fail(demangler_plugins && plugin && plugin->language, false);
	rz_warn_if_fail(plugin->author);
	rz_warn_if_fail(plugin->license);

	const RzDemanglerPlugin *cp;
	RzListIter *it = NULL;

	rz_list_foreach (demangler_plugins, it, cp) {
		if (!strcmp(cp->language, plugin->language)) {
			// avoids to have duplicates
			rz_list_delete(demangler_plugins, it);
			break;
		}
	}

	return rz_list_append(demangler_plugins, plugin);
}

/**
 * \brief Returns a demangler plugin pointer based on the language that is found
 * 
 * This function returns NULL only when the requested language is not available.
 */
RZ_API RZ_BORROW const RzDemanglerPlugin *rz_demangler_plugin_get(RZ_NONNULL const char *language) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(language) && demangler_plugins, NULL);

	RzListIter *it;
	const RzDemanglerPlugin *plugin;
	rz_list_foreach (demangler_plugins, it, plugin) {
		if (!strcmp(language, plugin->language)) {
			return plugin;
		}
	}

	return NULL;
}

/**
 * \brief Resolves a symbol based on its language and return an output that needs to be freed
 * 
 * This function fails only when the requested language is not available.
 */
RZ_API bool rz_demangler_resolve(RZ_NULLABLE const char *symbol, RZ_NONNULL const char *language, RZ_NONNULL RZ_OWN char **output) {
	rz_return_val_if_fail(language && demangler_plugins && output, false);

	if (RZ_STR_ISEMPTY(symbol)) {
		*output = NULL;
		return true;
	}

	const RzDemanglerPlugin *plugin;
	RzListIter *it;

	rz_list_foreach (demangler_plugins, it, plugin) {
		if (!strcmp(plugin->language, language)) {
			*output = plugin->demangle(symbol);
			return true;
		}
	}

	return false;
}
