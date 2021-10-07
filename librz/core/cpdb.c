// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_pdb.h>

static void rz_core_bin_pdb_types_print(const RzTypeDB *db, const RzPdb *pdb, const RzCmdStateOutput *state) {
	rz_return_if_fail(db && pdb);
	char *str = rz_bin_pdb_types_as_string(db, pdb, state);
	if (!str) {
		return;
	}
	rz_cons_print(str);
	RZ_FREE(str);
}

static void rz_core_bin_pdb_gvars_print(const RzPdb *pdb, const ut64 img_base, const RzCmdStateOutput *state) {
	rz_return_if_fail(pdb);
	char *str = rz_bin_pdb_gvars_as_string(pdb, img_base, state);
	if (!str) {
		return;
	}
	rz_cons_print(str);
	RZ_FREE(str);
}

/**
 * \brief Print parsed PDB file info and integrate with typedb
 * 
 * \param core RzCore instance
 * \param file Path of PDB file
 * \param state Output State
 * \return bool
 */
RZ_API bool rz_core_pdb_info_print(RzCore *core, const char *file, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && file, false);

	ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
	if (core->bin->cur && core->bin->cur->o && core->bin->cur->o->opts.baseaddr) {
		baddr = core->bin->cur->o->opts.baseaddr;
	} else {
		eprintf("Warning: Cannot find base address, flags will probably be misplaced\n");
	}

	RzPdb *pdb = rz_bin_pdb_parse_from_file(file);
	if (!pdb) {
		return false;
	}

	// Save compound types into types database
	rz_parse_pdb_types(core->analysis->typedb, pdb);
	if (state) {
		rz_cmd_state_output_array_start(state);
		rz_core_bin_pdb_types_print(core->analysis->typedb, pdb, state);
		rz_core_bin_pdb_gvars_print(pdb, baddr, state);
		rz_cmd_state_output_array_end(state);
	}
	char *cmd = rz_bin_pdb_gvars_as_cmd_string(pdb, baddr);
	rz_core_cmd0(core, cmd);
	free(cmd);
	rz_bin_pdb_free(pdb);
	return true;
}