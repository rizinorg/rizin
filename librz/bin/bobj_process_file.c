// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

RZ_IPI void rz_bin_set_and_process_file(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	// set base offset from the plugin
	if (plugin->boffset) {
		o->boffset = plugin->boffset(bf);
	}

	// set object size from the plugin instead from file
	// but this can create inconsistencies within rizin
	if (plugin->size) {
		o->size = plugin->size(bf);
	}

	// set register state only if the plugin is RZ_BIN_TYPE_CORE
	free(o->regstate);
	if (!plugin->file_type ||
		!plugin->regstate ||
		plugin->file_type(bf) != RZ_BIN_TYPE_CORE ||
		!(o->regstate = plugin->regstate(bf))) {
		o->regstate = NULL;
	}

	// set the virtual files.
	rz_pvector_free(o->vfiles);
	if (!plugin->virtual_files || !(o->vfiles = plugin->virtual_files(bf))) {
		o->vfiles = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	}

	// set the special symbols from the plugin
	for (size_t i = 0; i < RZ_BIN_SPECIAL_SYMBOL_LAST; i++) {
		RZ_FREE(o->binsym[i]);
		if (plugin->binsym && (o->binsym[i] = plugin->binsym(bf, i))) {
			o->binsym[i]->paddr += o->opts.loadaddr;
		}
	}

	rz_pvector_free(o->libs);
	if (!plugin->libs || !(o->libs = plugin->libs(bf))) {
		o->libs = rz_pvector_new(free);
	}

	rz_bin_info_free(o->info);
	if (!plugin->info || !(o->info = plugin->info(bf))) {
		o->info = NULL;
	}

	rz_structured_data_free(o->structured_data);
	if (!plugin->bin_structure || !(o->structured_data = plugin->bin_structure(bf))) {
		o->structured_data = NULL;
	}

	rz_bin_source_line_info_free(o->lines);
	if (!plugin->lines || !(o->lines = plugin->lines(bf))) {
		o->lines = NULL;
	}

	sdb_free(o->kv);
	if (!plugin->get_sdb || !(o->kv = plugin->get_sdb(bf))) {
		o->kv = sdb_new0();
	}

	rz_pvector_free(o->mem);
	if (!plugin->mem || !(o->mem = plugin->mem(bf))) {
		o->mem = rz_pvector_new((RzPVectorFree)rz_bin_mem_free);
	}

	rz_pvector_free(o->resources);
	if (!plugin->resources || !(o->resources = plugin->resources(bf))) {
		o->resources = rz_pvector_new((RzPVectorFree)rz_bin_resource_free);
	}
}
