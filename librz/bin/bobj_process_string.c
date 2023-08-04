// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

RZ_IPI void rz_bin_set_and_process_strings(RzBinFile *bf, RzBinObject *o) {
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

	RzListIter *it;
	RzBinString *string;
	rz_list_foreach (strings, it, string) {
		// rebase physical address
		string->paddr += o->opts.loadaddr;

		if (bin->debase64) {
			rz_bin_string_decode_base64(string);
		}
	}

	o->strings = rz_bin_string_database_new(strings);
}
