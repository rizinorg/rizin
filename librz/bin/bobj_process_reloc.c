// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct process_reloc_ctx_s {
	RzBinObject *object;
	ProcessLanguage lang_import;
	ProcessLanguage lang_symbol;
	const RzDemanglerPlugin *demangler;
	RzThreadLock *lang_lock;
} process_reloc_ctx_t;

static void process_handle_reloc(RzBinReloc *reloc, process_reloc_ctx_t *process) {
	RzBinObject *obj = process->object;

	// rebase physical address
	reloc->paddr += obj->opts.loadaddr;

	if (!process->demangler) {
		return;
	}

	const RzDemanglerPlugin *demangler = process->demangler;
	if (reloc->import &&
		rz_bin_demangle_import(reloc->import, demangler) &&
		process->lang_import) {

		rz_th_lock_enter(process->lang_lock);
		process->lang_import(obj, reloc->import);
		rz_th_lock_leave(process->lang_lock);
	}

	if (reloc->symbol &&
		rz_bin_demangle_symbol(reloc->symbol, demangler) &&
		process->lang_symbol) {
		rz_th_lock_enter(process->lang_lock);
		process->lang_symbol(obj, reloc->symbol);
		rz_th_lock_leave(process->lang_lock);
	}
}

static void set_and_process_relocs(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;
	RzList *relocs = NULL;

	rz_bin_reloc_storage_free(o->relocs);
	if (!(bin->filter_rules & (RZ_BIN_REQ_RELOCS | RZ_BIN_REQ_IMPORTS)) ||
		!plugin->relocs || !(relocs = plugin->relocs(bf))) {
		relocs = rz_list_newf((RzListFree)rz_bin_reloc_free);
	}

	process_reloc_ctx_t context = {
		.object = o,
		.lang_import = process_language_import(o),
		.lang_symbol = process_language_symbol(o),
		.demangler = demangler,
		.lang_lock = rz_th_lock_new(true),
	};

	if (!context.lang_lock) {
		RZ_LOG_ERROR("bin: failed to allocate RzThread data for reloc process\n");
		goto fail;
	}

	rz_th_iterate_list(relocs, (RzThreadIterator)process_handle_reloc, RZ_THREAD_POOL_ALL_CORES, &context);
	o->relocs = rz_bin_reloc_storage_new(relocs);

fail:
	rz_th_lock_free(context.lang_lock);
}
