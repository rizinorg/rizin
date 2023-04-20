// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_demangler.h>
#include <rz_util.h>
#include <rz_libdemangle.h>
#include <rz_lib.h>
#include <config.h>

#define DEFINE_DEMANGLER_PLUGIN(name, lang, lic, auth, handler) \
	RZ_API RzDemanglerPlugin rz_demangler_plugin_##name = { \
		.language = lang, \
		.license = lic, \
		.author = auth, \
		.demangle = &handler, \
	}

#if WITH_GPL
// cpp demangler contains GPL2 code and LGPL3 for delphi
DEFINE_DEMANGLER_PLUGIN(cpp, "c++", "GPL-2,LGPL3", "FSF/deroad", libdemangle_handler_cxx);
#else
// cpp demangler contain only the LGPL3 for delphi
DEFINE_DEMANGLER_PLUGIN(cpp, "c++", "LGPL3", "deroad", libdemangle_handler_cxx);
#endif /* WITH_GPL */

#if WITH_SWIFT_DEMANGLER
DEFINE_DEMANGLER_PLUGIN(swift, "swift", "MIT", "pancake", libdemangle_handler_swift);
#endif

DEFINE_DEMANGLER_PLUGIN(rust, "rust", "LGPL3", "Dhruv Maroo", libdemangle_handler_rust);
DEFINE_DEMANGLER_PLUGIN(java, "java", "LGPL3", "deroad", libdemangle_handler_java);
DEFINE_DEMANGLER_PLUGIN(msvc, "msvc", "LGPL3", "inisider", libdemangle_handler_msvc);
DEFINE_DEMANGLER_PLUGIN(objc, "objc", "LGPL3", "pancake", libdemangle_handler_objc);
DEFINE_DEMANGLER_PLUGIN(pascal, "pascal", "LGPL3", "deroad", libdemangle_handler_pascal);

static RzDemanglerPlugin *demangler_static_plugins[] = { RZ_DEMANGLER_STATIC_PLUGINS };

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
	return libdemangle_handler_cxx(symbol);
}

/**
 * \brief Demangles objc symbols
 */
RZ_API RZ_OWN char *rz_demangler_objc(RZ_NONNULL const char *symbol) {
	return libdemangle_handler_objc(symbol);
}

/**
 * \brief Demangles pascal symbols
 */
RZ_API RZ_OWN char *rz_demangler_pascal(RZ_NONNULL const char *symbol) {
	return libdemangle_handler_pascal(symbol);
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
 * \brief Initializes the plugin list and returns a RzDemangler struct
 */
RZ_API RZ_OWN RzDemangler *rz_demangler_new(void) {
	RzDemangler *dem = RZ_NEW0(RzDemangler);
	if (!dem) {
		return NULL;
	}

	RzList *plugins = rz_list_new();
	if (!plugins) {
		free(dem);
		return NULL;
	}

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(demangler_static_plugins); ++i) {
		RzDemanglerPlugin *p = demangler_static_plugins[i];
		rz_warn_if_fail(p->language);
		rz_warn_if_fail(p->license);
		rz_warn_if_fail(p->author);
		rz_warn_if_fail(p->demangle);
		if (!p->demangle || !rz_list_append(plugins, p)) {
			const char *lang = p->language ? p->language : "";
			RZ_LOG_WARN("rz_demangler: failed to add '%s' plugin at index %u", lang, i);
		}
	}

	dem->plugins = plugins;
	return dem;
}

/**
 * \brief Frees the RzDemangler struct
 */
RZ_API void rz_demangler_free(RZ_NULLABLE RzDemangler *dem) {
	if (!dem) {
		return;
	}
	rz_list_free(dem->plugins);
	free(dem);
}

/**
 * \brief Iterates over the plugin list
 *
 * Iterates over the plugin list and passes a RzDemanglerPlugin pointer
 * to the iter function; if the iter function returns false, then the
 * iteration is halted.
 */
RZ_API void rz_demangler_plugin_iterate(RZ_NONNULL RzDemangler *dem, RZ_NONNULL RzDemanglerIter iter, RZ_NULLABLE void *data) {
	rz_return_if_fail(dem && dem->plugins && iter);
	const RzDemanglerPlugin *plugin;
	RzListIter *it;

	rz_list_foreach (dem->plugins, it, plugin) {
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
RZ_API bool rz_demangler_plugin_add(RZ_NONNULL RzDemangler *dem, RZ_NONNULL RzDemanglerPlugin *plugin) {
	rz_return_val_if_fail(dem && dem->plugins && plugin && plugin->language, false);
	rz_warn_if_fail(plugin->author);
	rz_warn_if_fail(plugin->license);

	const RzDemanglerPlugin *cp;
	RzListIter *it = NULL;

	rz_list_foreach (dem->plugins, it, cp) {
		if (!strcmp(cp->language, plugin->language)) {
			// avoids to have duplicates
			rz_list_delete(dem->plugins, it);
			break;
		}
	}

	rz_list_append(dem->plugins, plugin);
	return true;
}

RZ_API bool rz_demangler_plugin_del(RZ_NONNULL RzDemangler *dem, RZ_NONNULL RzDemanglerPlugin *plugin) {
	rz_return_val_if_fail(dem && dem->plugins && plugin && plugin->language, false);
	return rz_list_delete_data(dem->plugins, plugin);
}

/**
 * \brief Returns a demangler plugin pointer based on the language that is found
 *
 * This function returns NULL only when the requested language is not available.
 */
RZ_API RZ_BORROW const RzDemanglerPlugin *rz_demangler_plugin_get(RZ_NONNULL RzDemangler *dem, RZ_NONNULL const char *language) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(language) && dem && dem->plugins, NULL);

	RzListIter *it;
	const RzDemanglerPlugin *plugin;
	rz_list_foreach (dem->plugins, it, plugin) {
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
RZ_API bool rz_demangler_resolve(RZ_NONNULL RzDemangler *dem, RZ_NULLABLE const char *symbol, RZ_NONNULL const char *language, RZ_NONNULL RZ_OWN char **output) {
	rz_return_val_if_fail(language && dem && dem->plugins && output, false);

	if (RZ_STR_ISEMPTY(symbol)) {
		*output = NULL;
		return true;
	}

	const RzDemanglerPlugin *plugin;
	RzListIter *it;

	rz_list_foreach (dem->plugins, it, plugin) {
		if (!strcmp(plugin->language, language)) {
			*output = plugin->demangle(symbol);
			return true;
		}
	}

	return false;
}
