// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_project.h>

RZ_IPI RzCmdStatus rz_project_save_handler(RzCore *core, int argc, const char **argv) {
	RzProjectErr err = rz_project_save_file (core, argv[1]);
	if (err != RZ_PROJECT_ERR_SUCCESS) {
		eprintf ("Failed to save project: %s\n", rz_project_err_message (err));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_project_open_handler(RzCore *core, int argc, const char **argv) {
	RzSerializeResultInfo *res = rz_serialize_result_info_new ();
	RzProjectErr err = rz_project_load_file (core, argv[1], true, res);
	if (err != RZ_PROJECT_ERR_SUCCESS) {
		eprintf ("Failed to load project: %s\n", rz_project_err_message (err));
		RzListIter *it;
		char *s;
		rz_list_foreach (res, it, s) {
			eprintf ("  %s\n", s);
		}
	}
	rz_serialize_result_info_free (res);
	return RZ_CMD_STATUS_OK;
}
