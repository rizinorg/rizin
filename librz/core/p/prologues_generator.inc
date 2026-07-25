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
static const RzCmdDescArg cmd_prologues_load_args[] = {
	{
		.name = "file",
		.type = RZ_CMD_ARG_TYPE_FILE,
	},
	{ 0 }
};
static const RzCmdDescArg cmd_prologues_generalize_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_prologues_search_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_prefix_tree_print_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_prologues_print_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_prologues_trie_clear_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_prologues_store_clear_args[] = {
	{ 0 }
};
static const RzCmdDescArg cmd_reset_session_args[] = {
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

static const RzCmdDescHelp cmd_prologues_load_help = {
	.summary = "Load prologues from a json file into the prologue store (replaces any existing prologues in the store)",
	.args = cmd_prologues_load_args,
};

static const RzCmdDescHelp cmd_prologues_generalize_help = {
	.summary = "Generalize the raw prologues extracted from binaries (pg[a|d]) and store them in prologues store (replaces any existing prologues in the store)",
	.args = cmd_prologues_generalize_args,
};

static const RzCmdDescHelp cmd_prologues_search_help = {
	.summary = "Analyse the current binary by searching for prologues from store (creates functions on hit)",
	.args = cmd_prologues_search_args,
};

static const RzCmdDescHelp cmd_prefix_tree_print_help = {
	.summary = "Trie Print: the prefix tree generated so far",
	.args = cmd_prefix_tree_print_args,
};

static const RzCmdDescHelp cmd_prologues_print_help = {
	.summary = "Print prologues currently in the store",
	.args = cmd_prologues_print_args,
};

static const RzCmdDescHelp cmd_prologues_trie_clear_help = {
	.summary = "Clear only the prologues prefix tree and associated data",
	.args = cmd_prologues_trie_clear_args,
};

static const RzCmdDescHelp cmd_prologues_store_clear_help = {
	.summary = "Clear only the prologues store and associated data",
	.args = cmd_prologues_store_clear_args,
};

static const RzCmdDescHelp cmd_reset_session_help = {
	.summary = "Reset prologue generation session: clears Prologues Trie, Prologues List and all metadata",
	.args = cmd_reset_session_args,
};
