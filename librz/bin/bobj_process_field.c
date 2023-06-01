// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

/* This is about processing binary fields, not class fields. */

RZ_IPI void rz_bin_set_and_process_fields(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->fields);
	if (!plugin->fields || !(o->fields = plugin->fields(bf))) {
		o->fields = rz_list_newf((RzListFree)rz_bin_field_free);
		return;
	}

	RzListIter *it;
	RzBinField *element;
	rz_list_foreach (o->fields, it, element) {
		// rebase physical address
		element->paddr += o->opts.loadaddr;
	}
}
