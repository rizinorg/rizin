// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_th.h>
#include "i/private.h"

typedef bool (*ProcessDemangle)(void *element, const void *user);
typedef void (*ProcessLanguage)(RzBinObject *o, const void *user);

typedef struct process_context_s {
	RzBinObject *object;
	ProcessDemangle demangle;
	ProcessLanguage language;
	const RzDemanglerPlugin *plugin;
	RzThreadLock *lock;
} process_context_t;

static const RzDemanglerPlugin *process_get_demangler_plugin_from_lang(RzBinFile *bf, RzBinLanguage language) {
	language = RZ_BIN_LANGUAGE_MASK(language);
	const char *lang_s = rz_bin_language_to_string(language);
	if (!lang_s) {
		return NULL;
	}
	return rz_demangler_plugin_get(bf->rbin->demangler, lang_s);
}

#if 0
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
#endif

static void process_cxx_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	if (strstr(symbol->dname, " for ")) {
		/* these symbols are not fields nor methods. */
		return;
	}

	bool is_method = true;
	const char *limit = strchr(symbol->dname, '(');
	if (!limit) {
		limit = symbol->dname + (strlen(symbol->dname) - 1);
		is_method = false;
	}

	// find where to split symbol.
	char *str = symbol->dname;
	char *ptr = NULL;
	char *name = NULL;
	for (;;) {
		ptr = strstr(str, "::");
		if (!ptr || ptr > limit) {
			break;
		}
		name = ptr;
		str = ptr + 2;
	}

	if (RZ_STR_ISEMPTY(name)) {
		return;
	}

	*name = 0;
	if (is_method) {
		rz_bin_object_add_method(o, symbol->dname, name + 2, symbol->paddr, symbol->vaddr);
	} else {
		rz_bin_object_add_field(o, symbol->dname, name + 2, symbol->size, symbol->paddr, symbol->vaddr);
	}
	*name = ':';
}

static void process_objc_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	if (!symbol->classname) {
		char *dot = strchr(symbol->dname, '.');
		if (!dot) {
			return;
		} else if (IS_UPPER(symbol->name[0])) {
			symbol->classname = rz_str_ndup(symbol->name, dot - symbol->name);
		} else if (IS_UPPER(dot[1])) {
			dot++;
			char *next_dot = strchr(dot, '.');
			symbol->classname = next_dot ? rz_str_ndup(dot, next_dot - dot) : NULL;
		}
	}

	if (symbol->classname) {
		rz_bin_object_add_class(o, symbol->classname, NULL, symbol->vaddr);
	}
}

#if WITH_SWIFT_DEMANGLER
// this process function does not work with the Apple demangler.
static char *get_swift_field(const char *demangled, const char *classname) {
	if (!demangled || !classname) {
		return NULL;
	}

	char *p = strstr(demangled, ".getter_");
	if (!p) {
		p = strstr(demangled, ".setter_");
		if (!p) {
			p = strstr(demangled, ".method_");
		}
	}
	if (p) {
		char *q = strstr(demangled, classname);
		if (q && q[strlen(classname)] == '.') {
			q = strdup(q + strlen(classname) + 1);
			char *r = strchr(q, '.');
			if (r) {
				*r = 0;
			}
			return q;
		}
	}
	return NULL;
}

static void process_swift_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	if (!symbol->classname) {
		return;
	}

	char *field_name = get_swift_field(symbol->dname, symbol->classname);
	if (field_name) {
		rz_bin_object_add_field(o, symbol->classname, field_name, symbol->size, symbol->paddr, symbol->vaddr);
		free(field_name);
		return;
	}

	// this code looks very wrong. this was copied from the original one and just refactored.
	char *method_name = strstr(symbol->dname, "..");
	if (!method_name) {
		method_name = strstr(symbol->dname, symbol->classname);
	}
	if (method_name && method_name[strlen(symbol->classname)] == '.') {
		rz_bin_object_add_method(o, symbol->classname, method_name, symbol->paddr, symbol->vaddr);
	}
}
#endif

static ProcessLanguage process_language_symbol(RzBinObject *o) {
	switch (o->lang) {
	case RZ_BIN_LANGUAGE_RUST:
		/* fall-thru */
	case RZ_BIN_LANGUAGE_CXX:
		return (ProcessLanguage)process_cxx_symbol;
	case RZ_BIN_LANGUAGE_OBJC:
		return (ProcessLanguage)process_objc_symbol;
#if WITH_SWIFT_DEMANGLER
	// this process function does not work with the Apple demangler.
	case RZ_BIN_LANGUAGE_SWIFT:
		return (ProcessLanguage)process_swift_symbol;
#endif
	default:
		return NULL;
	}
}

static void process_handle_symbol(RzBinSymbol *symbol, process_context_t *process) {
	RzBinObject *obj = process->object;

	// rebase physical address
	symbol->paddr += obj->opts.loadaddr;

	// add symbol to the 'import' map[name]symbol
	if (symbol->is_imported && RZ_STR_ISNOTEMPTY(symbol->name)) {
		rz_th_lock_enter(process->lock);
		if (!ht_pp_find(obj->import_name_symbols, symbol->name, NULL)) {
			ht_pp_insert(obj->import_name_symbols, symbol->name, symbol);
		}
		rz_th_lock_leave(process->lock);
	}

	if (!process->plugin ||
		!process->demangle(symbol, process->plugin) ||
		!process->language) {
		return;
	}

	rz_th_lock_enter(process->lock);
	process->language(obj, symbol);
	rz_th_lock_leave(process->lock);
}

static void process_symbols(RzBinFile *bf, RzBinObject *o) {
	if (rz_list_length(o->symbols) < 1) {
		return;
	}

	process_context_t context = {
		.object = o,
		.language = (ProcessLanguage)process_language_symbol(o),
		.demangle = (ProcessDemangle)rz_bin_demangle_symbol,
		.plugin = process_get_demangler_plugin_from_lang(bf, o->lang),
		.lock = rz_th_lock_new(true),
	};

	if (!context.lock) {
		RZ_LOG_ERROR("bin: failed to allocate RzThreadLock for bin process\n");
		return;
	}

	rz_th_iterate_list(o->symbols, (RzThreadIterator)process_handle_symbol, RZ_THREAD_POOL_ALL_CORES, &context);
	rz_th_lock_free(context.lock);
}

RZ_IPI bool rz_bin_object_process_data(RzBinFile *bf, RzBinObject *o) {
	// as first thing, we need to detect the language of the binary
	// we can detect this based on the compiler.
	if (o->info && RZ_STR_ISEMPTY(o->info->compiler)) {
		free(o->info->compiler);
		o->info->compiler = rz_bin_file_golang_compiler(bf);
		if (o->info->compiler) {
			o->info->lang = "go";
			o->lang = RZ_BIN_LANGUAGE_GO;
		}
	}

	// or based on the symbols/strings in the RzBinFile
	if (RZ_BIN_LANGUAGE_MASK(o->lang) == RZ_BIN_LANGUAGE_UNKNOWN) {
		o->lang = rz_bin_language_detect(bf);
	}

	// once we know the language we can process the data.
	process_symbols(bf, o);

	return true;
}
