// SPDX-FileCopyrightText: 2022 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_cmd.h>
#include <rz_core.h>
#include <cmd_descs.h>
#include "../core_private.h"

static bool macro_print_cb(RzCmd *cmd, const RzCmdMacro *macro, void *user) {
	RzCmdStateOutput *state = (RzCmdStateOutput *)user;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("(%s", macro->name);
		for (int i = 0; i < macro->nargs; i++) {
			rz_cons_printf(" %s", macro->args[i]);
		}
		rz_cons_printf("%s)\n", macro->code);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "name", macro->name);
		pj_ka(state->d.pj, "args");
		for (int i = 0; i < macro->nargs; i++) {
			pj_s(state->d.pj, macro->args[i]);
		}
		pj_end(state->d.pj);
		pj_ks(state->d.pj, "code", macro->code);
		pj_end(state->d.pj);
		break;
	default:
		rz_warn_if_reached();
		return false;
	}
	return true;
}

RZ_IPI RzCmdStatus rz_macros_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_cmd_state_output_array_start(state);
	rz_cmd_macro_foreach(core->rcmd, macro_print_cb, state);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_macros_remove_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_cmd_macro_rm(core->rcmd, argv[1]));
}

RZ_IPI RzCmdStatus rz_macros_handler(RzCore *core, const char *name, const char **args, const char *body, const char **argv) {
	rz_return_val_if_fail(core && name && args && body, RZ_CMD_STATUS_INVALID);

	const RzCmdMacro *macro = rz_cmd_macro_get(core->rcmd, name);
	if (!macro) {
		if (!rz_cmd_macro_add(core->rcmd, name, args, body)) {
			RZ_LOG_ERROR("core: Cannot add macro '%s'\n", name);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!rz_cmd_macro_update(core->rcmd, name, args, body)) {
			RZ_LOG_ERROR("core: Cannot update macro '%s'\n", name);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	return argv ? rz_cmd_macro_call(core->rcmd, name, argv) : RZ_CMD_STATUS_OK;
}
