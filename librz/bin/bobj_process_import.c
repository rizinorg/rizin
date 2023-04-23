// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct process_import_ctx_s {
	RzBinObject *object;
	ProcessDemangle demangle;
	ProcessLanguage language;
	const RzDemanglerPlugin *plugin;
	RzThreadLock *lang_lock;
} process_import_ctx_t;

static void process_cxx_import(RzBinObject *o, RzBinImport *import) {
	process_cxx(o, import->name, 0, UT64_MAX, UT64_MAX);
}

static ProcessLanguage process_language_import(RzBinObject *o) {
	switch (o->lang) {
	case RZ_BIN_LANGUAGE_RUST:
		/* fall-thru */
	case RZ_BIN_LANGUAGE_CXX:
		return (ProcessLanguage)process_cxx_import;
	default:
		return NULL;
	}
}

static void process_handle_import(RzBinImport *import, process_import_ctx_t *process) {
	RzBinObject *obj = process->object;

	// demangle the import
	if (!process->demangle(import, process->plugin) ||
		!process->language) {
		return;
	}

	// handle the demangled string at language
	// level; this can allow to add also classes
	// methods and fields.
	rz_th_lock_enter(process->lang_lock);
	process->language(obj, import);
	rz_th_lock_leave(process->lang_lock);
}

static void process_imports(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *plugin) {
	if (!plugin || rz_list_length(o->imports) < 1) {
		return;
	}

	process_import_ctx_t context = {
		.object = o,
		.language = (ProcessLanguage)process_language_import(o),
		.demangle = (ProcessDemangle)rz_bin_demangle_import,
		.plugin = plugin,
		.lang_lock = rz_th_lock_new(true),
	};

	if (!context.lang_lock) {
		RZ_LOG_ERROR("bin: failed to allocate RzThreadLock for import process\n");
		return;
	}

	rz_th_iterate_list(o->imports, (RzThreadIterator)process_handle_import, RZ_THREAD_POOL_ALL_CORES, &context);
	rz_th_lock_free(context.lang_lock);
}

static void set_imports(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->imports);
	if (!plugin->imports || !(o->imports = plugin->imports(bf))) {
		o->imports = rz_list_newf((RzListFree)rz_bin_import_free);
	}
	rz_warn_if_fail(o->imports->free);
}
