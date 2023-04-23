// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct process_symbol_ctx_s {
	RzBinObject *object;
	ProcessLanguage language;
	const RzDemanglerPlugin *plugin;
	RzThreadHtPP *imports;
	RzThreadLock *lang_lock;
} process_symbol_ctx_t;

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

static void process_rust_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	if (!symbol->type) {
		return;
	}
	bool is_method = !strcmp(symbol->type, RZ_BIN_TYPE_FUNC_STR) ||
		!strcmp(symbol->type, RZ_BIN_TYPE_IFACE_STR) ||
		!strcmp(symbol->type, RZ_BIN_TYPE_METH_STR);
	process_rust(o, symbol->dname, symbol->paddr, symbol->vaddr, is_method);
}

static void process_cxx_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	process_cxx(o, symbol->dname, symbol->paddr, symbol->vaddr);
}

#if WITH_SWIFT_DEMANGLER
// this process function does not work with the Apple demangler.
static void process_swift_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	process_swift(o, symbol->classname, symbol->dname, symbol->paddr, symbol->vaddr);
}
#endif

static ProcessLanguage process_language_symbol(RzBinObject *o) {
	switch (o->lang) {
	case RZ_BIN_LANGUAGE_RUST:
		return (ProcessLanguage)process_rust_symbol;
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

static void process_handle_symbol(RzBinSymbol *symbol, process_symbol_ctx_t *process) {
	RzBinObject *obj = process->object;

	// rebase physical address
	symbol->paddr += obj->opts.loadaddr;

	// add symbol to the 'import' map[name]symbol
	if (symbol->is_imported && RZ_STR_ISNOTEMPTY(symbol->name)) {
		if (!rz_th_ht_pp_find(process->imports, symbol->name, NULL)) {
			rz_th_ht_pp_insert(process->imports, symbol->name, symbol);
		}
	}

	// demangle the symbol
	if (!rz_bin_demangle_symbol(symbol, process->plugin) ||
		!process->language) {
		return;
	}

	// handle the demangled string at language
	// level; this can allow to add also classes
	// methods and fields.
	rz_th_lock_enter(process->lang_lock);
	process->language(obj, symbol);
	rz_th_lock_leave(process->lang_lock);
}

static void process_symbols(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *plugin) {
	if (rz_list_length(o->symbols) < 1) {
		return;
	}

	process_symbol_ctx_t context = {
		.object = o,
		.language = process_language_symbol(o),
		.plugin = plugin,
		.imports = rz_th_ht_pp_new0(),
		.lang_lock = rz_th_lock_new(true),
	};

	if (!context.lang_lock || !context.imports) {
		RZ_LOG_ERROR("bin: failed to allocate RzThread data for symbol process\n");
		goto fail;
	}

	rz_th_iterate_list(o->symbols, (RzThreadIterator)process_handle_symbol, RZ_THREAD_POOL_ALL_CORES, &context);
	ht_pp_free(o->import_name_symbols);
	o->import_name_symbols = rz_th_ht_pp_move(context.imports);

fail:
	rz_th_lock_free(context.lang_lock);
	rz_th_ht_pp_free(context.imports);
}

static void set_symbols(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->symbols);
	if (!plugin->symbols || !(o->symbols = plugin->symbols(bf))) {
		o->symbols = rz_list_newf((RzListFree)rz_bin_symbol_free);
	}
}
