// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

static void process_handle_string(RzBinString *string, RzBinObjectLoadOptions *o) {
	// rebase physical address
	string->paddr += o->loadaddr;
}

static void process_handle_string_and_decode(RzBinString *string, RzBinObjectLoadOptions *o) {
	// rebase physical address
	string->paddr += o->loadaddr;

	rz_bin_string_decode_base64(string);
}

static void set_and_process_strings(RzBinFile *bf, RzBinObject *o) {
	RzBin *bin = bf->rbin;

	rz_bin_string_database_free(o->strings);
	if (!(bin->filter_rules & RZ_BIN_REQ_STRINGS)) {
		o->strings = rz_bin_string_database_new(NULL);
		return;
	}

	RzList *strings = NULL;
	RzBinPlugin *plugin = o->plugin;

	if (!plugin->strings || !(strings = plugin->strings(bf))) {
		int minlen = (bin->minstrlen > 0) ? bin->minstrlen : plugin->minstrlen;
		strings = rz_bin_file_strings(bf, minlen, true);
	}

	RzThreadIterator iterator = bin->debase64 ? (RzThreadIterator)process_handle_string_and_decode : (RzThreadIterator)process_handle_string;

	rz_th_iterate_list(strings, iterator, RZ_THREAD_POOL_ALL_CORES, &o->opts);
	o->strings = rz_bin_string_database_new(strings);
}
