// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

RZ_IPI void rz_bin_set_and_process_entries(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_pvector_free(o->entries);
	if (!plugin->entries || !(o->entries = plugin->entries(bf))) {
		o->entries = rz_pvector_new(free);
		return;
	}

	void **it;
	RzBinAddr *element;
	rz_pvector_foreach (o->entries, it) {
		element = *it;
		// rebase physical address
		element->paddr += o->opts.loadaddr;
	}
}
