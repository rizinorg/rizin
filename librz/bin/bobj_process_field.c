// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/* This is about processing binary fields, not class fields. */

static void process_handle_field(RzBinField *field, RzBinObjectLoadOptions *o) {
	// rebase physical address
	field->paddr += o->loadaddr;
}

static void set_and_process_fields(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->fields);
	if (!plugin->fields || !(o->fields = plugin->fields(bf))) {
		o->fields = rz_list_newf((RzListFree)rz_bin_field_free);
		return;
	}

	rz_th_iterate_list(o->fields, (RzThreadIterator)process_handle_field, RZ_THREAD_POOL_ALL_CORES, &o->opts);
}
