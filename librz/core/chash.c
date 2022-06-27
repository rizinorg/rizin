// SPDX-FileCopyrightText: 2021 theopechli <theofilos.pechlivanis@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API RzCmdStatus rz_core_hash_plugin_print(RzCmdStateOutput *state, const RzHashPlugin *plugin) {
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

RZ_API RzCmdStatus rz_core_hash_plugins_print(RzHash *hash, RzCmdStateOutput *state) {
	rz_return_val_if_fail(hash, RZ_CMD_STATUS_ERROR);

	const RzHashPlugin *plugin = NULL;
	RzCmdStatus status;
	RzListIter *it;
	rz_cmd_state_output_array_start(state);
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_println("algorithm      license    author");
	}
	rz_list_foreach (hash->plugins, it, plugin) {
		status = rz_core_hash_plugin_print(state, plugin);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
	}
	if (state->mode == RZ_OUTPUT_MODE_QUIET) {
		rz_cons_newline();
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
