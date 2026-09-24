// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

static const RzCmdDescArg no_args[] = {
	{ 0 }
};

static const RzCmdDescArg cmd_prologues_gen_dir_args[] = {
	{
		.name = "dir",
		.type = RZ_CMD_ARG_TYPE_FOLDER,
	},
	{ 0 }
};

static const RzCmdDescHelp prologues_gen_help = {
	.summary = "Core plugin to generate prologues from given set of binaries having symbol info.",
	.args = no_args,
};

static const RzCmdDescHelp cmd_prologues_gen_help = {
	.summary = "Generate prologues only from current open file",
	.args = no_args,
};

static const RzCmdDescHelp cmd_prologues_gen_all_help = {
	.summary = "Generate prologues for all open files (arch will be adopted from first open binary)",
	.args = no_args,
};

static const RzCmdDescHelp cmd_prologues_gen_dir_help = {
	.summary = "Generate prologues for all files in a directory (arch will be adopted from first valid binary)",
	.args = cmd_prologues_gen_dir_args,
};
