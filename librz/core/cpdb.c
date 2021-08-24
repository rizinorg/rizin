// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../bin/pdb/pdb.h"

static void rz_core_bin_pdb_types_print(const RzTypeDB *db, const RzPdb *pdb, const RzOutputMode mode) {
	rz_return_if_fail(db && pdb);
	char *str = rz_bin_pdb_types_as_string(db, pdb, mode);
	if (!str) {
		return;
	}
	// we use 'puts' here because the output of 'rz_cons_print' will be recognized as a command
	puts(str);
	RZ_FREE(str);
}

static void rz_core_bin_pdb_gvars_print(const RzPdb *pdb, const ut64 img_base, const RzOutputMode mode) {
	rz_return_if_fail(pdb);
	char *str = rz_bin_pdb_gvars_as_string(pdb, img_base, mode);
	if (!str) {
		return;
	}
	puts(str);
	RZ_FREE(str);
}

/**
 * \brief Print parsed PDB file info and integrate with typedb
 * 
 * \param core RzCore instance
 * \param file Path of PDB file
 * \param mode Output Mode
 * \return bool
 */
RZ_API bool rz_core_pdb_info(RzCore *core, const char *file, RzOutputMode mode) {
	rz_return_val_if_fail(core && file, false);

	// sacrifice
	if (mode == RZ_MODE_JSON) {
		mode = RZ_OUTPUT_MODE_JSON;
	} else if (mode == RZ_MODE_PRINT) {
		mode = RZ_OUTPUT_MODE_STANDARD;
	}

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
	rz_core_bin_pdb_types_print(core->analysis->typedb, pdb, mode);
	rz_core_bin_pdb_gvars_print(pdb, baddr, mode);
	rz_bin_pdb_free(pdb);
	return true;
}