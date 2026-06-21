// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_iterator.h>

static RzCmdStatus core_crypto_plugin_print(RzCmdStateOutput *state, const RzCryptoPlugin *plugin) {
	const char *name = rz_str_get(plugin->name);
	const char *license = rz_str_get(plugin->license);
	const char *author = rz_str_get(plugin->author);
	const char *description = rz_str_get(plugin->description);

	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(name);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_ks(pj, "name", name);
		pj_ks(pj, "license", license);
		pj_ks(pj, "author", author);
		pj_ks(pj, "description", description);
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%-14s %-10s %-24s %s\n", name, license, author, description);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "ssss", name, license, author, description);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_crypto_plugins_print(RzCrypto *cry, RzCmdStateOutput *state) {
	rz_return_val_if_fail(cry, RZ_CMD_STATUS_ERROR);

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "ssss", "algorithm", "license", "author", "description");

	RzIterator *iter = ht_sp_as_iter(cry->plugins);
	RzList *plugin_list = rz_list_new_from_iterator(iter);
	if (!plugin_list) {
		rz_iterator_free(iter);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_list_sort(plugin_list, (RzListComparator)rz_crypto_plugin_cmp, NULL);

	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzListIter *it;
	RzCryptoPlugin *plugin;
	rz_list_foreach (plugin_list, it, plugin) {
		status = core_crypto_plugin_print(state, plugin);
		if (status != RZ_CMD_STATUS_OK) {
			break;
		}
	}
	rz_list_free(plugin_list);
	rz_iterator_free(iter);
	rz_cmd_state_output_array_end(state);
	return status;
}
