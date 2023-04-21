// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_th.h>

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

static const char *get_mangled_name(const char *mangled) {
	if (!strncmp(mangled, "__OBJC_$", strlen("__OBJC_$"))) {
		// this is never a mangled name
		return NULL;
	}

	skip_prefix_s(mangled, "reloc.");
	skip_prefix_s(mangled, "imp.");
	skip_prefix_s(mangled, "target.");
	skip_prefix_n(mangled, "__OBJC_", 1);

	return RZ_STR_ISEMPTY(mangled) ? NULL : mangled;
}

#undef skip_prefix

static void demangle_symbol_only(RzBinSymbol *bsym, const RzDemanglerPlugin *plugin) {
	if (bsym->dname) {
		return;
	}

	const char *mangled = get_mangled_name(bsym->name);
	if (!mangled) {
		return;
	}

	bsym->dname = plugin->demangle(mangled);
}

static void demangle_symbol_and_update_class(RzBinSymbol *bsym, const RzDemanglerPlugin *plugin) {
	if (bsym->dname) {
		return;
	}

	const char *mangled = get_mangled_name(bsym->name);
	if (!mangled) {
		return;
	}

	bsym->dname = plugin->demangle(mangled);

	if (!bsym->dname || bsym->is_imported) {
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

static RzThreadIterator demangler_get_symbol_iterator(RzBinFile *bf) {
	if (!bf) {
		return (RzThreadIterator)demangle_symbol_only;
	}
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);

	if (plugin &&
		plugin->name &&
		(!strcmp(plugin->name, "kernelcache") ||
			!strncmp(plugin->name, "mach0", strlen("mach0")))) {
		return (RzThreadIterator)demangle_symbol_and_update_class;
	}
	return (RzThreadIterator)demangle_symbol_only;
}

RZ_IPI void rz_bin_demangle_symbols(RzBinFile *bf, const RzList /*<RzBinSymbol*>*/ *symbols, RzBinLanguage lang) {
	lang = RZ_BIN_LANGUAGE_MASK(lang);
	size_t length = rz_list_length(symbols);
	if (!bf || !bf->rbin || length < 1 || lang == RZ_BIN_LANGUAGE_UNKNOWN) {
		return;
	}

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

	RzThreadIterator iterator = demangler_get_symbol_iterator(bf);
	rz_th_iterate_list(symbols, iterator, RZ_THREAD_POOL_ALL_CORES, plugin);
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

	RzThreadIterator iterator = demangler_get_symbol_iterator(bf);
	iterator(symbol, plugin);
}

static void demangle_import(RzBinImport *import, const RzDemanglerPlugin *plugin) {
	if (!import->name) {
		return;
	}

	const char *mangled = get_mangled_name(import->name);
	if (!mangled) {
		return;
	}

	char *demangled = plugin->demangle(mangled);
	if (!demangled) {
		return;
	}

	free(import->name);
	import->name = demangled;
}

RZ_IPI void rz_bin_demangle_imports(RzBinFile *bf, const RzList /*<RzBinImport*>*/ *imports, RzBinLanguage lang) {
	lang = RZ_BIN_LANGUAGE_MASK(lang);
	size_t length = rz_list_length(imports);
	if (!bf || !bf->rbin || length < 1 || lang == RZ_BIN_LANGUAGE_UNKNOWN) {
		return;
	}

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

	rz_th_iterate_list(imports, (RzThreadIterator)demangle_import, RZ_THREAD_POOL_ALL_CORES, plugin);
}

RZ_IPI void rz_bin_demangle_import(RzBinFile *bf, RzBinImport *import, RzBinLanguage lang) {
	if (!import || !import->name || !bf || !bf->rbin) {
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

	demangle_import(import, plugin);
}

static void demangle_reloc(RzBinReloc *reloc, const RzDemanglerPlugin *plugin) {
	if (reloc->import) {
		demangle_import(reloc->import, plugin);
	}
	if (reloc->symbol) {
		demangle_symbol_only(reloc->symbol, plugin);
	}
}

RZ_IPI void rz_bin_demangle_relocs(RzBinFile *bf, const RzBinRelocStorage *storage, RzBinLanguage lang) {
	if (!storage || !bf || !bf->rbin) {
		return;
	}

	lang = RZ_BIN_LANGUAGE_MASK(lang);
	size_t count = storage->relocs_count + storage->target_relocs_count;
	if (!bf || !bf->rbin || count < 1 || lang == RZ_BIN_LANGUAGE_UNKNOWN) {
		return;
	}

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

	RzPVector pvec = { 0 };
	pvec.v.elem_size = sizeof(void *);
	pvec.v.capacity = 0;

	pvec.v.a = (void *)storage->relocs;
	pvec.v.len = storage->relocs_count;
	rz_th_iterate_pvector(&pvec, (RzThreadIterator)demangle_reloc, RZ_THREAD_POOL_ALL_CORES, plugin);

	pvec.v.a = (void *)storage->target_relocs;
	pvec.v.len = storage->target_relocs_count;
	rz_th_iterate_pvector(&pvec, (RzThreadIterator)demangle_reloc, RZ_THREAD_POOL_ALL_CORES, plugin);
}

RZ_IPI void rz_bin_demangle_reloc(RzBinFile *bf, RzBinReloc *reloc, RzBinLanguage lang) {
	if (!reloc || !bf || !bf->rbin) {
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

	demangle_reloc(reloc, plugin);
}
