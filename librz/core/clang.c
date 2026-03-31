// SPDX-FileCopyrightText: 2021 theopechli <theofilos.pechlivanis@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

static RzCmdStatus core_lang_plugin_print(RzLangPlugin *lp, RzCmdStateOutput *state) {
	const char *name = rz_str_get(lp->name);
	const char *description = rz_str_get(lp->desc);
	const char *license = rz_str_get(lp->license);

	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "sss", name, description, license);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_ks(pj, "name", name);
		pj_ks(pj, "description", description);
		pj_ks(pj, "license", license);
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%s: %s (%s)\n", name, description, license);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(name);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_lang_plugins_print(RzLang *lang, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzLangPlugin *lp;
	RzCmdStatus status;
	if (!lang) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sss", "name", "description", "license");
	rz_list_foreach (lang->langs, iter, lp) {
		status = core_lang_plugin_print(lp, state);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
