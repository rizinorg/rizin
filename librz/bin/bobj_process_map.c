// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

static void process_handle_map(RzBinMap *map, RzBinObjectLoadOptions *o) {
	// rebase physical address
	map->paddr += o->loadaddr;
}

static void set_and_process_maps(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->maps);
	if (!plugin->maps || !(o->maps = plugin->maps(bf))) {
		o->maps = rz_list_newf((RzListFree)rz_bin_map_free);
		return;
	}

	rz_th_iterate_list(o->maps, (RzThreadIterator)process_handle_map, RZ_THREAD_POOL_ALL_CORES, &o->opts);
}
