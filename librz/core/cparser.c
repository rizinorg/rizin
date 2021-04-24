// SPDX-FileCopyrightText: 2021 theopechli <theofilos.pechlivanis@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_API RzCmdStatus rz_core_parser_plugin_print(RzParsePlugin *plugin, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "name", plugin->name);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("%s\n", plugin->name);
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
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
	rz_list_foreach (parser->parsers, iter, plugin) {
		rz_core_parser_plugin_print(plugin, state);
	}

	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
