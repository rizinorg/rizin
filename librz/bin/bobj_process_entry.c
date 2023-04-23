// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

static void process_handle_entry(RzBinAddr *address, RzBinObjectLoadOptions *o) {
	// rebase physical address
	address->paddr += o->loadaddr;
}

static void set_and_process_entries(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->entries);
	if (!plugin->entries || !(o->entries = plugin->entries(bf))) {
		o->entries = rz_list_newf(free);
		return;
	}

	rz_th_iterate_list(o->entries, (RzThreadIterator)process_handle_entry, RZ_THREAD_POOL_ALL_CORES, &o->opts);
}
