// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_iterator.h>

static RzCmdStatus core_crypto_plugin_print(RzCmdStateOutput *state, const RzCryptoPlugin *plugin) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_printf("%s ", plugin->name);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "name", plugin->name);
		pj_ks(pj, "license", plugin->license);
		pj_ks(pj, "author", plugin->author);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("%-14s %-10s %s\n", plugin->name, plugin->license, plugin->author);

		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_crypto_plugins_print(RzCrypto *cry, RzCmdStateOutput *state) {
	rz_return_val_if_fail(cry, RZ_CMD_STATUS_ERROR);

	RzCmdStatus status;
	rz_cmd_state_output_array_start(state);
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_println("algorithm      license    author");
	}
	RzIterator *iter = ht_sp_as_iter(cry->plugins);
	RzList *plugin_list = rz_list_new_from_iterator(iter);
	rz_list_sort(plugin_list, (RzListComparator)rz_crypto_plugin_cmp, NULL);
	RzListIter *it;
	RzCryptoPlugin *plugin;
	rz_list_foreach (plugin_list, it, plugin) {
		status = core_crypto_plugin_print(state, plugin);
		if (status != RZ_CMD_STATUS_OK) {
			rz_list_free(plugin_list);
			rz_iterator_free(iter);
			return status;
		}
	}
	rz_list_free(plugin_list);
	rz_iterator_free(iter);

	if (state->mode == RZ_OUTPUT_MODE_QUIET) {
		rz_cons_newline();
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
