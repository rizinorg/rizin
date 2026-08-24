// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

static const RzCmdDescArg cmd_prologues_gen_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_raw_prologues_gen_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_raw_prologues_gen_all_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_raw_prologues_gen_dir_args[] = {
	{
		.name = "dir",
		.type = RZ_CMD_ARG_TYPE_FOLDER,
	},
	{ 0 }
};

static const RzCmdDescHelp prologues_gen_help = {
	.summary = "Core plugin to generate prologues from given set of binaries having symbol info.",
	.args = cmd_prologues_gen_args,
};

static const RzCmdDescHelp cmd_raw_prologues_gen_help = {
	.summary = "Generate raw prologues prefix tree  only for current file, without any generalisation",
	.args = cmd_raw_prologues_gen_args,
};

static const RzCmdDescHelp cmd_raw_prologues_gen_all_help = {
	.summary = "Generate raw prologues prefix tree for all open files, without any generalisation",
	.args = cmd_raw_prologues_gen_all_args,
};

static const RzCmdDescHelp cmd_raw_prologues_gen_dir_help = {
	.summary = "Generate raw prologues prefix tree for all files in a directory, without any generalisation",
	.args = cmd_raw_prologues_gen_dir_args,
};
