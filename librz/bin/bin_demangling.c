// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_th.h>

typedef struct bin_demangling_s {
	const RzDemanglerPlugin *plugin;
	RzThreadQueue *queue;
	bool update_class_name;
} bin_demangling_t;

#define skip_prefix_s(s, p) \
	do { \
		if (!strncmp(s, p, strlen(p))) { \
			s += strlen(p); \
		} \
	} while (0)

#define skip_prefix_n(s, p, n) \
	do { \
		if (!strncmp(s, p, strlen(p))) { \
			s += n; \
		} \
	} while (0)

static const char *get_symbol_name(RzBinSymbol *bsym) {
	const char *symbol = NULL;
	symbol = bsym->name;

	if (!strncmp(symbol, "__OBJC_$", strlen("__OBJC_$"))) {
		// this is never a symbol
		return NULL;
	}

	skip_prefix_s(symbol, "reloc.");
	skip_prefix_s(symbol, "imp.");
	skip_prefix_s(symbol, "target.");
	skip_prefix_n(symbol, "__OBJC_", 1);

	return RZ_STR_ISEMPTY(symbol) ? NULL : symbol;
}

#undef skip_prefix

static void demangle_symbol(const RzDemanglerPlugin *plugin, RzBinSymbol *bsym, bool update_class_name) {
	const char *symbol = get_symbol_name(bsym);
	if (!symbol) {
		return;
	}

	bsym->dname = plugin->demangle(symbol);
	// eprintf("sym->name: '%s' -> '%s'\n", bsym->name, bsym->dname);
	if (!update_class_name || !bsym->dname || bsym->is_imported) {
		return;
	}
	// this step is used only by kernelcache and mach0
	char *dot = strchr(bsym->dname, '.');
	if (!dot) {
		return;
	} else if (IS_UPPER(bsym->name[0])) {
		bsym->classname = rz_str_ndup(bsym->name, dot - bsym->name);
	} else if (IS_UPPER(dot[1])) {
		dot++;
		char *next_dot = strchr(dot, '.');
		bsym->classname = rz_str_ndup(dot, next_dot - dot);
	}
}

static void *thread_demangle_cb(bin_demangling_t *bdem) {
	const RzDemanglerPlugin *plugin = bdem->plugin;
	RzThreadQueue *queue = bdem->queue;
	bool update_class_name = bdem->update_class_name;
	RzBinSymbol *bsym = NULL;

	while ((bsym = rz_th_queue_pop(queue, false))) {
		demangle_symbol(plugin, bsym, update_class_name);
	}
	return NULL;
}

static bool demangler_should_update_class_name(RzBinFile *bf) {
	if (!bf) {
		return false;
	}
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);

	return plugin && plugin->name && (!strcmp(plugin->name, "kernelcache") ||
						 // mach0 and mach064
						 !strncmp(plugin->name, "mach0", strlen("mach0")));
}

RZ_IPI void rz_bin_demangle_symbols(RzBinFile *bf, const RzList *symbols, RzBinLanguage lang) {
	lang = RZ_BIN_LANGUAGE_MASK(lang);
	size_t max_size = rz_list_length(symbols);
	if (!bf || !bf->rbin || max_size < 1 || lang == RZ_BIN_LANGUAGE_UNKNOWN) {
		return;
	}

	bin_demangling_t shared;
	RzListIter *it;
	RzBinSymbol *symbol;
	RzThreadPool *pool = NULL;
	RzThreadQueue *queue = NULL;
	const RzDemanglerPlugin *plugin = NULL;
	const char *language = rz_bin_language_to_string(lang);
	if (!language) {
		return;
	}

	// optimize by excluding langs which doesn't demangle.
	plugin = rz_demangler_plugin_get(bf->rbin->demangler, language);
	if (!plugin) {
		RZ_LOG_INFO("bin: there are no available demanglers for '%s'\n", language);
		return;
	}

	pool = rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES);
	queue = rz_th_queue_new(max_size, NULL);
	if (!queue || !pool) {
		RZ_LOG_ERROR("bin: failed to allocate memory for threaded demangling\n");
		goto fail;
	}

	rz_list_foreach (symbols, it, symbol) {
		if (symbol->dname) {
			continue;
		}
		rz_th_queue_push(queue, symbol, true);
	}

	shared.update_class_name = demangler_should_update_class_name(bf);
	shared.plugin = plugin;
	shared.queue = queue;

	ut32 pool_size = rz_th_pool_size(pool);
	RZ_LOG_VERBOSE("bin: using %u threads for threaded demangling\n", pool_size);

	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_new((RzThreadFunction)thread_demangle_cb, &shared);
		if (th) {
			rz_th_pool_add_thread(pool, th);
		}
	}

	rz_th_pool_wait(pool);

fail:
	rz_th_queue_free(queue);
	rz_th_pool_free(pool);
}

RZ_IPI void rz_bin_demangle_symbol(RzBinFile *bf, RzBinSymbol *symbol, RzBinLanguage lang) {
	if (!symbol || symbol->dname || !bf || !bf->rbin) {
		return;
	}

	const char *language = rz_bin_language_to_string(RZ_BIN_LANGUAGE_MASK(lang));
	if (!language) {
		return;
	}

	// optimize by excluding langs which doesn't demangle.
	const RzDemanglerPlugin *plugin = rz_demangler_plugin_get(bf->rbin->demangler, language);
	if (!plugin) {
		RZ_LOG_INFO("bin: there are no available demanglers for '%s'\n", language);
		return;
	}

	bool update_class_name = demangler_should_update_class_name(bf);
	demangle_symbol(plugin, symbol, update_class_name);
}
