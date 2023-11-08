// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

/* This is about processing binary fields, not class fields. */

RZ_IPI void rz_bin_set_and_process_fields(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_pvector_free(o->fields);
	if (!plugin->fields || !(o->fields = plugin->fields(bf))) {
		o->fields = rz_pvector_new((RzPVectorFree)rz_bin_field_free);
		return;
	}

	void **it;
	RzBinField *element;
	rz_pvector_foreach (o->fields, it) {
		element = *it;
		// rebase physical address
		element->paddr += o->opts.loadaddr;
	}
}
