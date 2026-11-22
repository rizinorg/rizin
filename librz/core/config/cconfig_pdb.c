// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

static bool core_config_init_pdb(RzCore *core) {
	RzConfig *cfg = core->config;
	char *pdb_path = rz_path_home_prefix(RZ_PDB);
	bool ret = pdb_path &&
		rz_config_add_string(cfg, "pdb.server", "Semi-colon separated list of base URLs for Microsoft symbol servers", "https://msdl.microsoft.com/download/symbols") &&
		rz_config_add_string(cfg, "pdb.symstore", "Path to downstream symbol store", pdb_path) &&
		rz_config_add_bool(cfg, "pdb.extract", "Avoid extract of the pdb file, just download", true) &&
		rz_config_add_bool(cfg, "pdb.autoload", "Automatically load the required pdb files for loaded DLLs", false);

	free(pdb_path);
	return ret;
}
