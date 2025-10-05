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

	RzPVector *strings = NULL;
	RzBinPlugin *plugin = o->plugin;

	/**
	 * We call rz_bin_file_strings only if the seach mode is not `auto`
	 * or if the plugin fails to generate the string vector.
	 */
	if (bin->str_search_cfg.mode != RZ_BIN_STRING_SEARCH_MODE_AUTO ||
		!plugin->strings ||
		!(strings = plugin->strings(bf))) {
		switch (bf->o->lang) {
		default:
			break;
		case RZ_BIN_LANGUAGE_GO:
		case RZ_BIN_LANGUAGE_RUST:
			bin->str_search_cfg.string_encoding = RZ_STRING_ENC_UTF8;
			break;
		}
		strings = rz_bin_file_strings(bf, &bin->str_search_cfg);
	}

	void **it;
	RzBinString *string;
	rz_pvector_foreach (strings, it) {
		string = *it;
		// rebase physical address
		string->paddr += o->opts.loadaddr;
	}

	o->strings = rz_bin_string_database_new(strings);
}
