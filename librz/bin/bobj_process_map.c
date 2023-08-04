// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

RZ_IPI void rz_bin_set_and_process_maps(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->maps);
	if (!plugin->maps || !(o->maps = plugin->maps(bf))) {
		o->maps = rz_list_newf((RzListFree)rz_bin_map_free);
		return;
	}

	RzListIter *it;
	RzBinMap *element;
	rz_list_foreach (o->maps, it, element) {
		// rebase physical address
		element->paddr += o->opts.loadaddr;
	}
}
