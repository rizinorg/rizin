// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_flirt.h>

RZ_IPI RzCmdStatus rz_flirt_create_handler(RzCore *core, int argc, const char **argv) {
	const char *filename = argv[1];
	ut32 written_nodes = 0;
	if (!rz_core_flirt_create_file(core, filename, &written_nodes)) {
		RZ_LOG_ERROR("failed to create FLIRT file '%s'\n", filename);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%u FLIRT signatures were written in '%s'\n", written_nodes, filename);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flirt_dump_handler(RzCore *core, int argc, const char **argv) {
	rz_core_flirt_dump_file(argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flirt_scan_handler(RzCore *core, int argc, const char **argv) {
	int new, old;
	int depth = rz_config_get_i(core->config, "dir.depth");
	const char *arch = rz_config_get(core->config, "asm.arch");
	char *file = NULL;
	RzListIter *iter = NULL;
	RzList *files = rz_file_globsearch(argv[1], depth);
	ut8 arch_id = rz_core_flirt_arch_from_name(arch);

	old = rz_flag_count(core->flags, "flirt");
	rz_list_foreach (files, iter, file) {
		rz_sign_flirt_apply(core->analysis, file, arch_id);
	}
	rz_list_free(files);
	new = rz_flag_count(core->flags, "flirt");

	rz_cons_printf("Found %d FLIRT signatures via %s\n", new - old, argv[1]);
	return RZ_CMD_STATUS_OK;
}
