// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

static void process_handle_reloc(RzBinReloc *reloc, RzBinObjectLoadOptions *o) {
	// rebase physical address
	reloc->paddr += o->loadaddr;
}

static void set_and_process_relocs(RzBinFile *bf, RzBinObject *o) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;
	RzList *relocs = NULL;

	rz_bin_reloc_storage_free(o->relocs);
	if (!(bin->filter_rules & (RZ_BIN_REQ_RELOCS | RZ_BIN_REQ_IMPORTS)) ||
		!plugin->relocs || !(relocs = plugin->relocs(bf))) {
		relocs = rz_list_newf((RzListFree)rz_bin_reloc_free);
	}

	rz_th_iterate_list(relocs, (RzThreadIterator)process_handle_reloc, RZ_THREAD_POOL_ALL_CORES, &o->opts);
	o->relocs = rz_bin_reloc_storage_new(relocs);
}
