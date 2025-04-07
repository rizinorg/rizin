// SPDX-FileCopyrightText: 2021 theopechli <theofilos.pechlivanis@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API RzCmdStatus rz_core_parser_plugin_print(RzParsePlugin *plugin, RzCmdStateOutput *state) {
	const char *name = rz_str_get(plugin->name);
	const char *desc = rz_str_get(plugin->desc);

	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(name);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_ks(pj, "name", name);
		pj_ks(pj, "desc", desc);
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%-15s %s\n", name, desc);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "ss", name, desc);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_parser_plugins_print(RzParse *parser, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzParsePlugin *plugin;
	if (!parser) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "ss", "name", "description");
	rz_list_foreach (parser->parsers, iter, plugin) {
		rz_core_parser_plugin_print(plugin, state);
	}

	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
