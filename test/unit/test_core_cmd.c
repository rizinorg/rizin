// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

static const RzCmdDescArg string_args[] = {
	{ .name = "s", .type = RZ_CMD_ARG_TYPE_STRING },
	{ 0 },
};
static const RzCmdDescHelp string_help = {
	.summary = "string help",
	.args = string_args,
};
static const RzCmdDescArg cmd_args[] = {
	{ .name = "c", .type = RZ_CMD_ARG_TYPE_CMD },
	{ 0 },
};
static const RzCmdDescHelp cmd_help = {
	.summary = "cmd help",
	.args = cmd_args,
};
static const RzCmdDescArg cmd_last_args[] = {
	{ .name = "c", .type = RZ_CMD_ARG_TYPE_CMD, .flags = RZ_CMD_ARG_FLAG_LAST },
	{ 0 },
};
static const RzCmdDescHelp cmd_last_help = {
	.summary = "cmd_last help",
	.args = cmd_last_args,
};
static const RzCmdDescArg cmd_last_opt_args[] = {
	{ .name = "c1", .type = RZ_CMD_ARG_TYPE_CMD },
	{ .name = "c2", .type = RZ_CMD_ARG_TYPE_CMD, .flags = RZ_CMD_ARG_FLAG_LAST, .optional = true },
	{ 0 },
};
static const RzCmdDescHelp cmd_last_opt_help = {
	.summary = "cmd_last help",
	.args = cmd_last_opt_args,
};

static const RzCmdDescArg no_args[] = {
	{ 0 },
};
static const RzCmdDescHelp fail_help = {
	.summary = "fail help",
	.args = no_args,
};
static const RzCmdDescHelp peek_help = {
	.summary = "peek help",
	.args = no_args,
};
static const RzCmdDescHelp quit_help = {
	.summary = "quit help",
	.args = no_args,
};

static RzCmdStatus peeked_status;

static RzCmdStatus string_handler(RzCore *core, int argc, const char **argv) {
	return argc == 2 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus cmd_handler(RzCore *core, int argc, const char **argv) {
	return argc == 2 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus cmd_last_handler(RzCore *core, int argc, const char **argv) {
	return argc == 2 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus cmd_last_with_at_handler(RzCore *core, int argc, const char **argv) {
	mu_assert_eq(argc, 2, "just one arg");
	mu_assert_streq(argv[1], "string hello \\@ 0xdeadbeef", "the command should be passed as argument");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus cmd_last_opt_handler(RzCore *core, int argc, const char **argv) {
	if (argc >= 2) {
		mu_assert_streq(argv[1], "string 'hello everybody'", "first cmd, non optional, should be string");
	}
	if (argc == 3) {
		mu_assert_streq(argv[2], "cmd string\\ hello", "second cmd, optional, should be cmd");
		RzCmdStatus s = rz_core_cmd0_rzshell(core, argv[2]);
		mu_assert_eq(s, RZ_CMD_STATUS_OK, "cmd_last second arg should be executed well");
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus fail_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus peek_handler(RzCore *core, int argc, const char **argv) {
	peeked_status = core->last_cmd_status;
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus quit_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_EXIT;
}

static RzCmd *old_rcmd = NULL;

static RzCore *fake_core_new(void) {
	RzCore *core = rz_core_new();
	old_rcmd = core->rcmd;
	core->rcmd = rz_core_cmd_new(core, true);
	RzCmdDesc *root = rz_cmd_get_root(core->rcmd);
	rz_cmd_desc_argv_new(core->rcmd, root, "string", string_handler, &string_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "cmd", cmd_handler, &cmd_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "cmd_last", cmd_last_handler, &cmd_last_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "cmd_last_with_at", cmd_last_with_at_handler, &cmd_last_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "cmd_last_opt", cmd_last_opt_handler, &cmd_last_opt_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "fail", fail_handler, &fail_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "peek", peek_handler, &peek_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "quit", quit_handler, &quit_help);
	return core;
}

static void fake_core_free(RzCore *core) {
	rz_cmd_free(core->rcmd);
	core->rcmd = old_rcmd;
	rz_core_free(core);
}

static bool test_arg_cmd(void) {
	RzCore *core = fake_core_new();
	RzCmdStatus s = rz_core_cmd0_rzshell(core, "cmd \"string hello\"");
	mu_assert_eq(s, RZ_CMD_STATUS_OK, "argument cmd is passed");
	fake_core_free(core);
	mu_end;
}

static bool test_arg_cmd_last(void) {
	RzCore *core = fake_core_new();
	RzCmdStatus s = rz_core_cmd0_rzshell(core, "cmd_last string hello");
	mu_assert_eq(s, RZ_CMD_STATUS_OK, "argument cmd is passed as a single arg");
	fake_core_free(core);
	mu_end;
}

static bool test_arg_cmd_last_with_at(void) {
	RzCore *core = fake_core_new();
	RzCmdStatus s = rz_core_cmd0_rzshell(core, "cmd_last_with_at string hello \\@ 0xdeadbeef");
	mu_assert_eq(s, RZ_CMD_STATUS_OK, "argument cmd is passed as a single arg");
	fake_core_free(core);
	mu_end;
}

static bool test_arg_cmd_last_opt(void) {
	RzCore *core = fake_core_new();
	RzCmdStatus s = rz_core_cmd0_rzshell(core, "cmd_last_opt \"string 'hello everybody'\" cmd 'string hello'");
	mu_assert_eq(s, RZ_CMD_STATUS_OK, "argument cmd is passed as a single arg");
	s = rz_core_cmd0_rzshell(core, "cmd_last_opt \"string 'hello everybody'\"");
	mu_assert_eq(s, RZ_CMD_STATUS_OK, "argument cmd is passed as a single arg");
	fake_core_free(core);
	mu_end;
}

static bool test_last_cmd_status(void) {
	RzCore *core = fake_core_new();
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_INVALID, "no command ran yet");
	rz_core_cmd0_rzshell(core, "string hello");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_OK, "success should be tracked");
	rz_core_cmd0_rzshell(core, "zzz");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_NONEXISTINGCMD, "unknown command should be tracked");
	rz_core_cmd0_rzshell(core, "string");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_WRONG_ARGS, "wrong arguments should be tracked");
	rz_core_cmd0_rzshell(core, "fail; peek");
	mu_assert_eq(peeked_status, RZ_CMD_STATUS_ERROR, "a statement should see the status of the previous one");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_ERROR, "the line should keep the status of its failing statement");
	rz_core_cmd0_rzshell(core, "quit");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_EXIT, "quitting should be tracked");
	mu_assert_eq(rz_core_cmd0_rzshell(core, "fail; quit"), RZ_CMD_STATUS_EXIT, "the line should still quit");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_ERROR, "quitting should not hide an earlier failure");
	rz_core_cmd0_rzshell(core, "string \"hello");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_INVALID, "parse errors should be tracked");
	fake_core_free(core);
	mu_end;
}

static bool test_cmd_str_status(void) {
	RzCore *core = rz_core_new();
	RzCmdStatus status = RZ_CMD_STATUS_INVALID;
	char *out = rz_core_cmd_str_status(core, "echo hello", &status);
	mu_assert_streq_free(out, "hello\n", "output of a successful command");
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "status of a successful command");
	out = rz_core_cmd_str_status(core, "zzz", &status);
	mu_assert_streq_free(out, "", "a missing command prints nothing");
	mu_assert_eq(status, RZ_CMD_STATUS_NONEXISTINGCMD, "status of a missing command");
	out = rz_core_cmd_str_status(core, "echo partial; zzz", &status);
	mu_assert_streq_free(out, "partial\n", "the output should be kept on failure");
	mu_assert_eq(status, RZ_CMD_STATUS_NONEXISTINGCMD, "status of a failed command line");
	mu_assert_null(rz_core_cmd_str(core, "echo partial; zzz"), "rz_core_cmd_str() should still discard a failed output");
	rz_core_free(core);
	mu_end;
}

static RzCmdStatus diag_levels_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_INFO("diag-ignored-info\n");
	rz_log("test", "test", 1, RZ_LOGLVL_NONE, NULL, "diag-ignored-none\n");
	RZ_LOG_WARN("\r\n");
	RZ_LOG_WARN("diag-warn-msg\n");
	RZ_LOG_FATAL("diag-fatal-msg\n");
	for (int i = 0; i < 35; i++) {
		RZ_LOG_WARN("diag-cap-%d\n", i);
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus diag_empty_warn_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_WARN("\r\n");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus diag_invalid_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_INVALID;
}

static RzCmdStatus diag_disable_and_log_handler(RzCore *core, int argc, const char **argv) {
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", false);
	RZ_LOG_ERROR("diag-ignored-after-disable\n");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus nested_merge_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd0_rzshell(core, "s foo");
	RZ_LOG_ERROR("outer-merge-diag\n");
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus nested_empty_inner_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd0_rzshell(core, "s 0");
	RZ_LOG_ERROR("outer-only-diag\n");
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus nested_exit_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd0_rzshell(core, "s 0");
	return RZ_CMD_STATUS_EXIT;
}

static RzCmdStatus warn_ok_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_WARN("inner-ok-warn\n");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus nested_warn_fail_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd0_rzshell(core, "zdiag_warn_ok");
	RZ_LOG_ERROR("outer-after-warn-err\n");
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus nested_prewarn_ok_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_WARN("pre-inner-warn\n");
	rz_core_cmd0_rzshell(core, "s 0");
	RZ_LOG_WARN("post-inner-warn\n");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus diag_last_fail_handler(RzCore *core, int argc, const char **argv) {
	RZ_LOG_ERROR("last-arg-failed\n");
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus exit_json_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return RZ_CMD_STATUS_EXIT;
}

static RzCmdStatus nonl_json_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_cons_print(core->cons, "{}");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus invalid_json_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return RZ_CMD_STATUS_INVALID;
}

static RzCmdStatus nested_merge_json_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return nested_merge_handler(core, argc, argv);
}

static RzCmdStatus disable_diag_json_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return diag_disable_and_log_handler(core, argc, argv);
}

static RzCmdStatus enable_diag_json_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", true);
	return RZ_CMD_STATUS_OK;
}

static int test_prompt_eof_fgets(char *buf, int len, void *user) {
	return -2;
}

static const RzCmdDescHelp diag_test_help = {
	.summary = "diag test helper",
	.args = (const RzCmdDescArg[]){ { 0 } },
};

static const RzCmdDescHelp diag_last_help = {
	.summary = "diag last-arg helper",
	.args = (const RzCmdDescArg[]){
		{ .name = "s", .type = RZ_CMD_ARG_TYPE_STRING, .flags = RZ_CMD_ARG_FLAG_LAST },
		{ 0 },
	},
};

static const RzCmdDescHelp diag_opt_str_help = {
	.summary = "diag optional arg helper",
	.args = (const RzCmdDescArg[]){
		{ .name = "x", .type = RZ_CMD_ARG_TYPE_STRING, .optional = true },
		{ 0 },
	},
};

static const RzCmdDescHelp diag_args_str_help = {
	.summary = "diag explicit args_str helper",
	.args_str = "<custom>",
	.args = (const RzCmdDescArg[]){
		{ .name = "x", .type = RZ_CMD_ARG_TYPE_STRING },
		{ 0 },
	},
};

static const RzCmdDescHelp diag_nosummary_help = {
	.summary = NULL,
	.args = (const RzCmdDescArg[]){
		{ .name = "x", .type = RZ_CMD_ARG_TYPE_STRING },
		{ 0 },
	},
};

static bool test_last_cmd_status_verbose_json(void) {
	RzCore *core = rz_core_new();
	RzCmdStatus status = RZ_CMD_STATUS_INVALID;
	RzCmdDesc *root = rz_cmd_get_root(core->rcmd);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_levels", diag_levels_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_empty_warn", diag_empty_warn_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_invalid", diag_invalid_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_dislog", diag_disable_and_log_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_merge", nested_merge_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_outer", nested_empty_inner_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_nexit", nested_exit_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_warn_ok", warn_ok_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_warn_fail", nested_warn_fail_handler,
		&diag_opt_str_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_prewarn_ok", nested_prewarn_ok_handler,
		&diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_last", diag_last_fail_handler,
		&diag_last_help);
	rz_cmd_desc_argv_modes_new(core->rcmd, root, "zdiag_exit", RZ_OUTPUT_MODE_JSON,
		exit_json_handler, &diag_opt_str_help);
	rz_cmd_desc_group_new(core->rcmd, root, "zdiag_selfgrp", diag_levels_handler,
		&diag_args_str_help, &diag_test_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_args", diag_levels_handler,
		&diag_args_str_help);
	rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_nosum", diag_levels_handler,
		&diag_nosummary_help);
	RzCmdDesc *vanish_cd = rz_cmd_desc_argv_new(core->rcmd, root, "zdiag_vanish",
		diag_levels_handler, &diag_args_str_help);
	rz_cmd_desc_argv_modes_new(core->rcmd, root, "zdiag_nonl", RZ_OUTPUT_MODE_JSON,
		nonl_json_handler, &diag_test_help);
	rz_cmd_desc_argv_modes_new(core->rcmd, root, "zdiag_inv", RZ_OUTPUT_MODE_JSON,
		invalid_json_handler, &diag_test_help);
	rz_cmd_desc_argv_modes_new(core->rcmd, root, "zdiag_mrg", RZ_OUTPUT_MODE_JSON,
		nested_merge_json_handler, &diag_test_help);
	rz_cmd_desc_argv_modes_new(core->rcmd, root, "zdiag_dis", RZ_OUTPUT_MODE_JSON,
		disable_diag_json_handler, &diag_test_help);
	rz_cmd_desc_argv_modes_new(core->rcmd, root, "zdiag_enb", RZ_OUTPUT_MODE_JSON,
		enable_diag_json_handler, &diag_test_help);

	// Disabled by default: _sj stays minimal and does not allocate last_cmd_info
	mu_assert_false(core->cmd_diagnostics, "cfg.cmd.diagnostics should default to false");
	rz_core_cmd0_rzshell(core, "agfj");
	mu_assert_null(core->last_cmd_info, "disabled diagnostics must not allocate last_cmd_info");
	char *out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "_sj should succeed");
	mu_assert_streq_free(out,
		"{\"error\":{\"code\":\"NONEXISTINGCMD\","
		"\"message\":\"Command does not exist\"}}\n",
		"_sj must remain unchanged when cfg.cmd.diagnostics is false");

	// Enable cfg.cmd.diagnostics
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", true);
	mu_assert_true(core->cmd_diagnostics, "cfg.cmd.diagnostics should be enabled");

	// Success -> {"error":null}
	rz_core_cmd0_rzshell(core, "s 0");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "_sj should succeed");
	mu_assert_streq_free(out, "{\"error\":null}\n", "_sj on OK command");

	// NONEXISTINGCMD -> command, diagnostics, and closest suggestion
	rz_core_cmd0_rzshell(core, "agfj");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "_sj after NONEXISTINGCMD should succeed");
	mu_assert_notnull(strstr(out, "\"code\":\"NONEXISTINGCMD\""),
		"expected NONEXISTINGCMD code");
	mu_assert_notnull(strstr(out, "\"command\":\"agfj\""), "expected failing command");
	mu_assert_notnull(strstr(out, "\"diagnostics\":["), "expected diagnostics array");
	mu_assert_notnull(strstr(out, "does not exist"), "expected missing command diagnostic");
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"agf\""),
		"expected agf suggestion");
	free(out);

	// Subsequent _sj sees OK of prior _sj
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_streq_free(out, "{\"error\":null}\n", "second _sj should report OK");

	// NONEXISTINGCMD ending with '?' + args skips suggestion lookup
	rz_core_cmd0_rzshell(core, "s? foo");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"NONEXISTINGCMD\""), "expected NONEXISTINGCMD");
	mu_assert_null(strstr(out, "\"suggestion\":"), "expected no suggestion for 's? foo'");
	free(out);

	// Large subcommand group caps suggestion.subcommands at 24
	rz_core_cmd0_rzshell(core, "azzz");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"a\""),
		"expected 'a' group suggestion");
	mu_assert_notnull(strstr(out, "\"subcommands\":["), "expected capped subcommands");
	free(out);

	// WRONG_ARGS -> command, diagnostics, suggestion (ARGV_STATE modes + explicit args_str)
	rz_core_cmd0_rzshell(core, "wx");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"WRONG_ARGS\""), "expected WRONG_ARGS code");
	mu_assert_notnull(strstr(out, "\"command\":\"wx\""), "expected wx command");
	mu_assert_notnull(strstr(out, "Wrong number of arguments"),
		"expected wrong args diagnostic");
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"wx\""),
		"expected wx suggestion");
	free(out);

	rz_core_cmd0_rzshell(core, "flj a b");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"fl\""),
		"expected ARGV_STATE suggestion");
	mu_assert_notnull(strstr(out, "\"modes\":["), "expected ARGV_STATE modes");
	free(out);

	rz_core_cmd0_rzshell(core, "zdiag_args");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"args_str\":\"<custom>\""),
		"expected explicit args_str in suggestion");
	free(out);

	// Same-line statement handoff: s foo; _sj
	out = rz_core_cmd_str_status(core, "s foo; _sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"ERROR\""), "expected ERROR code");
	mu_assert_notnull(strstr(out, "\"command\":\"s\""), "expected s command");
	mu_assert_notnull(strstr(out, "\"args\":[\"foo\"]"), "expected foo argument");
	free(out);

	// Parse error -> INVALID + parse diagnostic
	rz_core_cmd0_rzshell(core, "s \"unterminated");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"INVALID\""), "expected INVALID code");
	mu_assert_notnull(strstr(out, "Error while parsing command"), "expected parse diagnostic");
	free(out);

	// Warning, fatal, newline-only skip, and RZ_CORE_CMD_MAX_DIAGNOSTICS (32) cap
	RzLogLevel prev_log_level = rz_log_get_level();
	rz_log_set_level(RZ_LOGLVL_INFO);
	rz_log_set_abortlevel(RZ_LOGLVL_NONE);
	rz_core_cmd0_rzshell(core, "zdiag_levels");
	rz_log_set_abortlevel(RZ_LOGLVL_FATAL);
	rz_log_set_level(prev_log_level);
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"error\":null"), "expected error:null on OK command");
	mu_assert_notnull(strstr(out, "\"level\":\"warning\",\"message\":\"diag-warn-msg\""),
		"expected warning level diagnostic");
	mu_assert_notnull(strstr(out, "\"level\":\"fatal\",\"message\":\"diag-fatal-msg\""),
		"expected fatal level diagnostic");
	mu_assert_null(strstr(out, "diag-ignored-info"), "info logs must be ignored");
	mu_assert_null(strstr(out, "diag-ignored-none"), "NONE logs must be ignored");
	mu_assert_null(strstr(out, "diag-cap-34"), "diagnostics must be capped at 32");
	free(out);

	// OK command logging only CR/LF yields allocated info with empty diagnostics
	rz_core_cmd0_rzshell(core, "zdiag_empty_warn");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_streq_free(out, "{\"error\":null}\n",
		"newline-only warning on OK command must not emit diagnostics array");

	// WRONG_ARGS on ARGV_MODES, NULL summary, and removed command descriptors
	rz_core_cmd0_rzshell(core, "zdiag_nonlj extra");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"modes\":[\"j\"]"),
		"expected ARGV_MODES suggestion modes");
	free(out);

	rz_core_cmd0_rzshell(core, "zdiag_nosum");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"zdiag_nosum\""),
		"expected suggestion for descriptor without summary");
	mu_assert_null(strstr(out, "\"summary\":"),
		"NULL summary must be omitted from suggestion");
	free(out);

	rz_core_cmd0_rzshell(core, "zdiag_vanish");
	mu_assert_true(rz_cmd_desc_remove(core->rcmd, vanish_cd),
		"removing temporary command descriptor should succeed");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"WRONG_ARGS\""),
		"removed descriptor must still report WRONG_ARGS");
	mu_assert_null(strstr(out, "\"suggestion\":"),
		"removed descriptor must omit suggestion cleanly");
	free(out);

	// INVALID handler -> command and execution error diagnostic captured
	rz_core_cmd0_rzshell(core, "zdiag_invalid");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"INVALID\""), "expected INVALID code");
	mu_assert_notnull(strstr(out, "\"command\":\"zdiag_invalid\""),
		"expected failing invalid command name");
	mu_assert_notnull(strstr(out, "Error while executing command: zdiag_invalid"),
		"INVALID command must capture execution error diagnostic");
	free(out);

	// Standalone q sets EXIT status with NULL last_cmd_info
	rz_core_cmd0_rzshell(core, "q");
	mu_assert_null(core->last_cmd_info, "standalone q must not allocate last_cmd_info");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_streq_free(out,
		"{\"error\":{\"code\":\"EXIT\","
		"\"message\":\"Command requested to exit the prompt\"}}\n",
		"standalone q must emit minimal EXIT JSON");

	// Nested failing command merges outer diagnostics into inner last_cmd_info
	rz_core_cmd0_rzshell(core, "zdiag_merge");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address"),
		"expected inner diagnostic preserved");
	mu_assert_notnull(strstr(out, "outer-merge-diag"),
		"expected outer diagnostic merged into inner info");
	free(out);

	// Nested OK inner + failing outer preserves outer diagnostics
	rz_core_cmd0_rzshell(core, "zdiag_outer");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "outer-only-diag"),
		"expected outer diagnostic when inner had no info");
	free(out);

	// Nested OK inner + EXIT outer with NULL cap->info
	rz_core_cmd0_rzshell(core, "zdiag_nexit");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_streq_free(out,
		"{\"error\":{\"code\":\"EXIT\","
		"\"message\":\"Command requested to exit the prompt\"}}\n",
		"nested exit without outer info must report EXIT");

	// Empty command clears stale last_cmd_info when cmd.repeat is false
	rz_config_set_b(core->config, "cmd.repeat", false);
	rz_core_cmd0_rzshell(core, "s foo");
	rz_core_cmd0_rzshell(core, "");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_streq_free(out, "{\"error\":null}\n",
		"empty command must clear stale diagnostics from previous failure");

	// cfg.json.status + cfg.cmd.diagnostics inserts newline after non-NL JSON output
	rz_config_set_b(core->config, "cfg.json.status", true);
	rz_cons_reset(core->cons);
	rz_core_cmd0_rzshell(core, "zdiag_nonlj");
	const char *nonl_out = rz_cons_get_buffer(core->cons);
	mu_assert_streq(nonl_out, "{}\n{\"error\":null}\n",
		"cfg.json.status with diagnostics must add newline before status line");
	rz_config_set_b(core->config, "cfg.json.status", false);

	// Diagnostics logged during an OK command are still reported by _sj
	rz_core_cmd0_rzshell(core, "flt:nonexistent_column_xyz");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"error\":null"), "expected error:null for OK status");
	mu_assert_notnull(strstr(out, "\"diagnostics\":["),
		"expected diagnostics array on OK command with log");
	mu_assert_notnull(strstr(out, "Invalid column"), "expected table column diagnostic");
	free(out);

	// Quitting after a failure must preserve error diagnostics
	rz_core_cmd0_rzshell(core, "wx; q");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_WRONG_ARGS,
		"q must not hide earlier failure");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"WRONG_ARGS\""),
		"q must not hide earlier diagnostics");
	free(out);

	rz_core_cmd0_rzshell(core, "s foo; q");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_ERROR,
		"q after ERROR statement must not hide earlier failure");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"ERROR\""),
		"q after ERROR statement must preserve ERROR status");
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address"),
		"q after ERROR statement must preserve earlier diagnostics");
	free(out);

	// Prompt hooks (cmd.prompt) must not clobber last_cmd_info
	rz_core_cmd0_rzshell(core, "s foo");
	rz_config_set(core->config, "cmd.prompt", "s bar");
	int (*prev_fgets)(char *, int, void *) = core->cons->user_fgets;
	core->cons->user_fgets = test_prompt_eof_fgets;
	mu_assert_eq(rz_core_prompt(core, false), RZ_CORE_CMD_EXIT,
		"prompt stub should return EOF exit");
	core->cons->user_fgets = prev_fgets;
	rz_config_set(core->config, "cmd.prompt", "");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address 'foo'"),
		"set_prompt must preserve user last_cmd_info across cmd.prompt");
	mu_assert_null(strstr(out, "'bar'"),
		"cmd.prompt failure must not replace user last_cmd_info");
	free(out);

	// Disabling inside a handler ignores subsequent logs and detaches on exit
	rz_core_cmd0_rzshell(core, "zdiag_dislog");
	mu_assert_false(core->cmd_diagnostics, "handler should disable cfg.cmd.diagnostics");
	mu_assert_null(core->last_cmd_info, "disabling inside handler must not store diagnostics");
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", true);

	// Disabling mid-line detaches capture before subsequent statements
	out = rz_core_cmd_str_status(core, "e cfg.cmd.diagnostics=false; s foo; _sj", &status);
	mu_assert_streq_free(out,
		"{\"error\":{\"code\":\"ERROR\",\"message\":\"Command execution failed\"}}\n",
		"mid-line disable must detach capture and revert _sj");
	mu_assert_null(core->last_cmd_info, "disabling must free cached last_cmd_info");

	// Enabling mid-line works for subsequent statements on the same line
	out = rz_core_cmd_str_status(core, "e cfg.cmd.diagnostics=true; s foo; _sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"ERROR\""),
		"mid-line enable should capture ERROR status on subsequent statements");
	mu_assert_notnull(strstr(out, "\"args\":[\"foo\"]"),
		"mid-line enable should capture args on subsequent statements");
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address"),
		"mid-line enable should capture diagnostics on subsequent statements");
	free(out);

	// Mid-line enable also captures NONEXISTINGCMD suggestions before line abort
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", false);
	rz_core_cmd0_rzshell(core, "e cfg.cmd.diagnostics=true; agfj");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"agf\""),
		"mid-line enable should capture NONEXISTINGCMD suggestion");
	free(out);

	// Nested inner OK+warning followed by outer failure preserves outer command/args and both diagnostics
	rz_core_cmd0_rzshell(core, "zdiag_warn_fail myarg");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"command\":\"zdiag_warn_fail\""),
		"outer command must be preserved after inner warning");
	mu_assert_notnull(strstr(out, "\"args\":[\"myarg\"]"),
		"outer args must be preserved after inner warning");
	mu_assert_notnull(strstr(out, "inner-ok-warn"),
		"inner warning diagnostic must be preserved");
	mu_assert_notnull(strstr(out, "outer-after-warn-err"),
		"outer error diagnostic must be preserved");
	free(out);

	// Outer OK warning logged before a clean inner OK command must not be lost
	rz_core_cmd0_rzshell(core, "zdiag_prewarn_ok");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"error\":null"), "expected error:null on OK command");
	mu_assert_notnull(strstr(out, "pre-inner-warn"),
		"pre-inner warning must survive nested clean OK command");
	mu_assert_notnull(strstr(out, "post-inner-warn"),
		"post-inner warning must be preserved");
	free(out);

	// Pre-mutation typed args are preserved for RZ_CMD_ARG_FLAG_LAST commands
	rz_core_cmd0_rzshell(core, "zdiag_last a b c");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"args\":[\"a\",\"b\",\"c\"]"),
		"args must reflect typed tokens before args_preprocessing joins them");
	free(out);

	// cfg.json.status + cfg.cmd.diagnostics preserves command/args on EXIT JSON commands
	rz_config_set_b(core->config, "cfg.json.status", true);
	rz_cons_reset(core->cons);
	rz_core_cmd0_rzshell(core, "zdiag_exitj x");
	const char *exitj_out = rz_cons_get_buffer(core->cons);
	mu_assert_notnull(strstr(exitj_out, "\"code\":\"EXIT\""),
		"cfg.json.status must emit EXIT code");
	mu_assert_notnull(strstr(exitj_out, "\"command\":\"zdiag_exitj\""),
		"cfg.json.status must emit command on EXIT even without captured info");
	mu_assert_notnull(strstr(exitj_out, "\"args\":[\"x\"]"),
		"cfg.json.status must emit typed args on EXIT");
	rz_config_set_b(core->config, "cfg.json.status", false);

	// Self-only GROUP descriptor must omit empty subcommands array
	rz_core_cmd0_rzshell(core, "zdiag_selfgrp");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"suggestion\":{\"command\":\"zdiag_selfgrp\""),
		"expected self-only group suggestion");
	mu_assert_null(strstr(out, "\"subcommands\":"),
		"self-only group must not emit empty subcommands array");
	free(out);

	// Quiet log.level=NONE still captures WARN/ERROR diagnostics in _sj
	prev_log_level = rz_log_get_level();
	rz_log_set_level(RZ_LOGLVL_NONE);
	rz_core_cmd0_rzshell(core, "s foo");
	rz_log_set_level(prev_log_level);
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address 'foo'"),
		"cfg.cmd.diagnostics must capture error diagnostics even when log.level=NONE");
	free(out);

	// Project config load must not overwrite cfg.cmd.diagnostics
	Sdb *proj_db = sdb_new0();
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", false);
	rz_serialize_core_save(proj_db, core, NULL);
	rz_config_set_b(core->config, "cfg.cmd.diagnostics", true);
	RzSerializeResultInfo *sres = rz_serialize_result_info_new();
	mu_assert_true(rz_serialize_core_load(proj_db, core, false, NULL, sres),
		"core project load should succeed");
	rz_serialize_result_info_free(sres);
	sdb_free(proj_db);
	mu_assert_true(core->cmd_diagnostics,
		"loading project must not disable cfg.cmd.diagnostics");

	// Multi-statement ERROR; OK preserves failing statement's command, args, and diagnostics
	rz_core_cmd0_rzshell(core, "s foo; s 0");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_ERROR,
		"s foo; s 0 must preserve ERROR status");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "\"code\":\"ERROR\""),
		"s foo; s 0 must report ERROR code");
	mu_assert_notnull(strstr(out, "\"command\":\"s\""),
		"s foo; s 0 must preserve failing command");
	mu_assert_notnull(strstr(out, "\"args\":[\"foo\"]"),
		"s foo; s 0 must preserve failing args");
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address 'foo'"),
		"s foo; s 0 must preserve failing diagnostics");
	free(out);

	// Trailing OK warning must not replace an earlier failure's diagnostics
	rz_core_cmd0_rzshell(core, "s foo; zdiag_warn_ok");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_ERROR,
		"s foo; zdiag_warn_ok must preserve ERROR status");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address 'foo'"),
		"trailing OK warning must not clobber earlier failure diagnostics");
	mu_assert_null(strstr(out, "inner-ok-warn"),
		"trailing OK warning must not leak into earlier failure diagnostics");
	free(out);

	// Trailing EXIT running a nested OK command must still preserve earlier failure diagnostics
	rz_core_cmd0_rzshell(core, "s foo; zdiag_nexit");
	mu_assert_eq(core->last_cmd_status, RZ_CMD_STATUS_ERROR,
		"s foo; zdiag_nexit must preserve ERROR status");
	out = rz_core_cmd_str_status(core, "_sj", &status);
	mu_assert_notnull(strstr(out, "Cannot seek to unknown address 'foo'"),
		"trailing EXIT with inner OK command must preserve earlier failure diagnostics");
	free(out);

	// cfg.json.status + cfg.cmd.diagnostics emits INVALID execution error in trailer
	rz_config_set_b(core->config, "cfg.json.status", true);
	rz_cons_reset(core->cons);
	rz_core_cmd0_rzshell(core, "zdiag_invj");
	const char *invj_out = rz_cons_get_buffer(core->cons);
	mu_assert_notnull(strstr(invj_out, "\"code\":\"INVALID\""),
		"cfg.json.status must emit INVALID code");
	mu_assert_notnull(strstr(invj_out, "\"command\":\"zdiag_invj\""),
		"cfg.json.status must emit INVALID command name");
	mu_assert_notnull(strstr(invj_out, "Error while executing command: zdiag_invj"),
		"cfg.json.status INVALID trailer must include execution error diagnostic");

	// cfg.json.status + cfg.cmd.diagnostics emits merged nested diagnostics in trailer
	rz_cons_reset(core->cons);
	rz_core_cmd0_rzshell(core, "zdiag_mrgj");
	const char *mrgj_out = rz_cons_get_buffer(core->cons);
	mu_assert_notnull(strstr(mrgj_out, "\"code\":\"ERROR\""),
		"cfg.json.status nested failure must emit ERROR code");
	mu_assert_notnull(strstr(mrgj_out, "Cannot seek to unknown address 'foo'"),
		"cfg.json.status nested trailer must include inner diagnostic");
	mu_assert_notnull(strstr(mrgj_out, "outer-merge-diag"),
		"cfg.json.status nested trailer must include outer diagnostic");

	// Toggling cfg.cmd.diagnostics inside a JSON handler must neither drop nor double-print status
	rz_cons_reset(core->cons);
	rz_core_cmd0_rzshell(core, "zdiag_disj");
	mu_assert_false(core->cmd_diagnostics, "zdiag_disj should disable diagnostics");
	mu_assert_streq(rz_cons_get_buffer(core->cons), "{\"error\":null}\n",
		"disabling cfg.cmd.diagnostics inside a JSON handler must still print status once");

	rz_cons_reset(core->cons);
	rz_core_cmd0_rzshell(core, "zdiag_enbj");
	mu_assert_true(core->cmd_diagnostics, "zdiag_enbj should enable diagnostics");
	mu_assert_streq(rz_cons_get_buffer(core->cons), "{\"error\":null}\n",
		"enabling cfg.cmd.diagnostics inside a JSON handler must not double-print status");
	rz_config_set_b(core->config, "cfg.json.status", false);

	rz_core_free(core);
	mu_end;
}

static bool test_hist_push(void) {
	RzCore *core = rz_core_new();
	RzLine *line = core->cons->line;
	const char *mark = "i5824";
	const char *cmd = "echo i5824";

	rz_line_hist_add(line, cmd);
	int history_top = line->history.top;
	rz_cons_readflush(core->cons);

	free(core->cmdqueue);
	core->cmdqueue = rz_str_newf("< \\x12%s\\n", mark);
	mu_assert_notnull(core->cmdqueue, "cmdqueue should be allocated");

	mu_assert_eq(rz_core_prompt_exec(core), 0, "push_escaped prompt command should execute");
	mu_assert_eq(line->history.top, history_top, "push_escaped should not be added to history");
	mu_assert_streq(rz_line_hist_get(line, history_top), cmd, "last history entry should remain the preexisting matching command");

	const char *res = rz_line_readline(line);
	mu_assert_notnull(res, "reverse-search result should not be null");
	mu_assert_streq(res, cmd, "reverse-search should resolve to prior history, not the injector command");

	rz_cons_readflush(core->cons);
	rz_core_free(core);
	mu_end;
}

static bool test_hist_push_seq(void) {
	RzCore *core = rz_core_new();
	RzLine *line = core->cons->line;
	const char *mark = "i5824s";
	const char *cmd = "echo i5824s";

	rz_line_hist_add(line, cmd);
	int history_top = line->history.top;
	rz_cons_readflush(core->cons);

	free(core->cmdqueue);
	core->cmdqueue = rz_str_newf("echo %s; < \\x12%s\\n", mark, mark);
	mu_assert_notnull(core->cmdqueue, "cmdqueue should be allocated");

	mu_assert_eq(rz_core_prompt_exec(core), 0, "push_escaped prompt command should execute");
	mu_assert_eq(line->history.top, history_top, "command lines containing push_escaped should not be added to history");
	mu_assert_streq(rz_line_hist_get(line, history_top), cmd, "last history entry should remain the preexisting matching command");

	const char *res = rz_line_readline(line);
	mu_assert_notnull(res, "reverse-search result should not be null");
	mu_assert_streq(res, cmd, "reverse-search should resolve to prior history, not the injector command");

	rz_cons_readflush(core->cons);
	rz_core_free(core);
	mu_end;
}

static bool test_hist_push_load(void) {
	int retval = MU_PASSED;
	const char *cmd = "echo i5824l";
	const char *data = "< \\x12i5824l\\n\necho i5824l\n";
	char *old = rz_sys_getenv(RZ_SYS_HOME);
	char *home = rz_file_temp("rz5824");
	char *hist = NULL;
	char *dir = NULL;
	char *cache = NULL;
	RzCore *core = NULL;

	if (!home) {
		mu_cleanup_fail(beach, "home path should be available");
	}
	if (!rz_sys_mkdirp(home)) {
		mu_cleanup_fail(beach, "home dir should be created");
	}
	rz_sys_setenv(RZ_SYS_HOME, home);
	hist = rz_path_home_history();
	if (!hist) {
		mu_cleanup_fail(beach, "history path should be available");
	}
	dir = rz_file_dirname(hist);
	if (!dir) {
		mu_cleanup_fail(beach, "history dir should be available");
	}
	cache = rz_file_dirname(dir);
	if (!cache) {
		mu_cleanup_fail(beach, "cache dir should be available");
	}
	if (!rz_sys_mkdirp(dir)) {
		mu_cleanup_fail(beach, "history dir should be created");
	}
	if (!rz_file_dump(hist, (const ut8 *)data, (int)strlen(data), false)) {
		mu_cleanup_fail(beach, "history file should be written");
	}
	core = rz_core_new();
	if (!core) {
		mu_cleanup_fail(beach, "core should be created");
	}
	mu_assert_streq(rz_line_hist_get(core->cons->line, 1), cmd, "loaded history should keep only normal commands");
	mu_assert_null(rz_line_hist_get(core->cons->line, 2), "loaded push_escaped entry should be removed");

beach:
	rz_core_free(core);
	rz_sys_setenv(RZ_SYS_HOME, old);
	if (hist) {
		rz_file_rm(hist);
	}
	if (dir) {
		rz_file_rm(dir);
	}
	if (cache) {
		rz_file_rm(cache);
	}
	if (home) {
		rz_file_rm(home);
	}
	free(old);
	free(cache);
	free(dir);
	free(hist);
	free(home);
	mu_cleanup_end;
}

static bool test_disasm_until_ret_json(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_true(rz_core_file_open_load(core, "malloc://64", 0, RZ_PERM_RW, true), "file");
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);
	rz_core_cmd0(core, "wx 90c3");
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	mu_assert_true(rz_core_disasm_until_ret(core, 0, 8, RZ_OUTPUT_MODE_JSON, true, &buf), "capture JSON");
	mu_assert_streq(rz_strbuf_get(&buf), "[{\"offset\":0,\"size\":1,\"opcode\":\"nop\",\"type\":\"nop\"},{\"offset\":1,\"size\":1,\"opcode\":\"ret\",\"type\":\"ret\"}]", "path to return");
	rz_cons_push(core->cons);
	mu_assert_true(rz_core_disasm_until_ret(core, 0, 8, RZ_OUTPUT_MODE_JSON, false, NULL), "print JSON");
	char *printed = rz_str_newf("%s\n", rz_strbuf_get(&buf));
	mu_assert_streq(rz_cons_get_buffer(core->cons), printed, "console and capture agree");
	free(printed);
	rz_cons_pop(core->cons);
	rz_strbuf_set(&buf, "");
	mu_assert_true(rz_core_disasm_until_ret(core, 0, 8, RZ_OUTPUT_MODE_QUIET, true, &buf), "capture text");
	mu_assert_streq(rz_strbuf_get(&buf), "nop\nret", "quiet capture is unchanged");
	rz_strbuf_set(&buf, "prefix");
	mu_assert_true(rz_core_disasm_until_ret(core, 0, 0, RZ_OUTPUT_MODE_JSON, true, &buf), "empty path");
	mu_assert_streq(rz_strbuf_get(&buf), "prefix[]", "append instead of replacing the buffer");
	mu_assert_false(rz_core_disasm_until_ret(core, 0, -1, RZ_OUTPUT_MODE_JSON, true, &buf), "negative limit");
	mu_assert_false(rz_core_disasm_until_ret(core, 0, 1, RZ_OUTPUT_MODE_JSON, true, NULL), "missing output buffer");
	mu_assert_false(rz_core_disasm_until_ret(core, UT64_MAX, 1, RZ_OUTPUT_MODE_JSON, true, &buf), "failed decode");
	mu_assert_streq(rz_strbuf_get(&buf), "prefix[]", "failed requests append no JSON");
	rz_strbuf_fini(&buf);
	rz_core_free(core);
	mu_end;
}

static bool test_type_command_colors(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	const char *setup =
		"td \"struct Point { int x; const char *name; };\"; "
		"td \"union Value { int i; char c; };\"; "
		"td \"enum Mode { READ = 1, WRITE = 2 };\"; "
		"td \"typedef struct Point PointAlias;\"; "
		"td \"int process(const struct Point *p);\"";
	mu_assert_eq(rz_core_cmd0_rzshell(core, setup), RZ_CMD_STATUS_OK, "define test types");
	mu_assert_true(rz_analysis_cc_set(core->analysis, "rax example_cc(rdi, rsi)"), "calling convention");
	RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, "example", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "function for type references");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzType *type = rz_type_parse_string_single(typedb->parser, "struct Point", NULL);
	mu_assert_notnull(type, "variable type");
	RzAnalysisVarStorage storage;
	rz_analysis_var_storage_init_stack(&storage, -0x10);
	RzAnalysisVar *var = rz_analysis_function_set_var(fcn, &storage, type, 0, "point");
	rz_type_free(type);
	mu_assert_notnull(var, "variable for type references");
	const struct {
		const char *cmd;
		bool colored;
	} cases[] = {
		{ "tc", true },
		{ "tc Point", true },
		{ "tcd", true },
		{ "tcd Point", true },
		{ "tsc", true },
		{ "tsc Point", true },
		{ "tsd", true },
		{ "tsd Point", true },
		{ "tuc", true },
		{ "tuc Value", true },
		{ "tud", true },
		{ "tud Value", true },
		{ "tec", true },
		{ "tec Mode", true },
		{ "ted", true },
		{ "ted Mode", true },
		{ "ttc", true },
		{ "ttc PointAlias", true },
		{ "tt PointAlias", true },
		{ "tf", true },
		{ "tf process", true },
		{ "tsl", true },
		{ "tul", true },
		{ "tcc example_cc", true },
		{ "tccl", true },
		{ "tx", true },
		{ "txf 0x100", true },
		{ "txl", false },
		{ "txg", false },
		{ "t", false },
		{ "ts", false },
		{ "tu", false },
		{ "te", false },
		{ "tt", true },
		{ "tcc", false },
		{ "tccj", false },
		{ "tj", false },
		{ "tsj", false },
		{ "tuj", false },
		{ "tej", false },
		{ "ttj", false },
		{ "tfj", false },
		{ "t Point", false },
		{ "ts Point", false },
		{ "tu Value", false },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
		char *plain = rz_core_cmd_str(core, cases[i].cmd);
		mu_assert_notnull(plain, cases[i].cmd);
		mu_assert_null(strchr(plain, '\x1b'), "plain output has no escapes");
		rz_config_set_i(core->config, "scr.color", COLOR_MODE_16);
		char *colored = rz_core_cmd_str(core, cases[i].cmd);
		mu_assert_notnull(colored, cases[i].cmd);
		mu_assert_eq(strchr(colored, '\x1b') != NULL, cases[i].colored, cases[i].cmd);
		rz_str_ansi_filter(colored, NULL, NULL, -1);
		mu_assert_streq(colored, plain, cases[i].cmd);
		free(plain);
		free(colored);
	}
	rz_core_cmd0(core, "ec func_var_type red");
	char *custom = rz_core_cmd_str(core, "tc Point");
	mu_assert_notnull(custom, "custom palette output");
	mu_assert_notnull(strstr(custom, Color_RED "char" Color_RESET), "active type color");
	free(custom);
	char *source = rz_core_types_as_c(core, "Point", true);
	mu_assert_notnull(source, "C source for editor/API callers");
	mu_assert_null(strchr(source, '\x1b'), "source APIs stay uncolored");
	free(source);
	rz_core_cmd0(core, "t-*");
	char *empty = rz_core_cmd_str(core, "tc");
	mu_assert_streq_free(empty, "", "empty type listing adds no newline");
	rz_core_free(core);
	mu_end;
}

static bool visual_hexdump_shown;

static RzCmdStatus visual_hexdump_handler(RzCore *core, int argc, const char **argv) {
	visual_hexdump_shown = true;
	return RZ_CMD_STATUS_OK;
}

static bool test_visual_function_preview(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	const char *setup =
		"e scr.interactive=true; e scr.color=0; e scr.utf8=false; "
		"e scr.columns=120; e scr.rows=16; e asm.arch=x86; e asm.bits=64; "
		"on malloc://0x2001; wx c3; wx 90 @ 0x2000; "
		"af+ sparse; afb+ 0 0 1; afb+ 0 0x2000 1";
	mu_assert_eq(rz_core_cmd0_rzshell(core, setup), RZ_CMD_STATUS_OK, "sparse function");
	rz_analysis_set_gp(core->analysis, 0x12345678);
	RzCmdDesc *hexdump = rz_cmd_get_desc(core->rcmd, "pxa");
	mu_assert_notnull(hexdump, "hexdump command");
	hexdump->d.argv_data.cb = visual_hexdump_handler;
	visual_hexdump_shown = false;
	mu_assert_true(rz_cons_readpush(core->cons, "Ppqq", 4), "preview keys");
	int length;
	ut8 *output = rz_core_cmd_raw(core, "Vv", &length);
	mu_assert_notnull(output, "visual output");
	mu_assert_notnull(rz_mem_mem(output, length, (const ut8 *)"0x00002000", 10), "preview includes the distant block");
	mu_assert_true(visual_hexdump_shown, "P wraps to the last representation");
	mu_assert_eq(rz_analysis_get_gp(core->analysis), 0x12345678, "preview preserves the global pointer");
	free(output);
	rz_core_free(core);
	mu_end;
}

static size_t visual_render_count;
static bool visual_resize_preview;

static RzCmdStatus visual_preview_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	visual_render_count++;
	if (visual_resize_preview) {
		rz_config_set_i(core->config, "scr.rows", 20);
		visual_resize_preview = false;
	}
	rz_cons_printf(core->cons, "preview at 0x%" PFMT64x "\n", core->offset);
	return RZ_CMD_STATUS_OK;
}

static bool test_visual_preview_cache(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	const char *setup =
		"e scr.interactive=true; e scr.color=0; e scr.utf8=false; "
		"e scr.columns=120; e scr.rows=16; e asm.arch=x86; e asm.bits=64; "
		"on malloc://16 0x100000000; s 0x100000000; af+ first; "
		"on malloc://16 0x200000000; s 0x200000000; af+ second; s 0x100000000";
	mu_assert_eq(rz_core_cmd0_rzshell(core, setup), RZ_CMD_STATUS_OK, "64-bit functions");
	RzCmdDesc *preview = rz_cmd_desc_get_exec(rz_cmd_get_desc(core->rcmd, "pdr"));
	mu_assert_notnull(preview, "function preview command");
	preview->d.argv_state_data.cb = visual_preview_handler;
	visual_render_count = 0;
	const struct {
		const char *keys;
		size_t renders;
		bool resize;
	} cases[] = {
		{ "\tjjkk\tqq", 1, false },
		{ "qq", 2, false },
		{ "jkqq", 5, false },
		{ "\tk\tqq", 7, true },
		{ ":e asm.bytes=true\n\nqq", 9, false },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		visual_resize_preview = cases[i].resize;
		mu_assert_true(rz_cons_readpush(core->cons, cases[i].keys, strlen(cases[i].keys)), "preview keys");
		char *output = rz_core_cmd_str(core, "Vv");
		mu_assert_notnull(output, "visual output");
		free(output);
		mu_assert_eq(visual_render_count, cases[i].renders, "reuse only the current function preview");
	}
	rz_core_free(core);
	mu_end;
}

static bool test_visual_graph_previews(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_eq(rz_core_cmd0_rzshell(core,
			     "e scr.interactive=true; e scr.color=0; e scr.utf8=false; "
			     "e scr.columns=120; e scr.rows=16; e asm.arch=x86; e asm.bits=64; "
			     "on malloc://512 0x1000; s 0x1000; af+ wide"),
		RZ_CMD_STATUS_OK, "graph setup");
	// A branching graph puts its entry beyond the leftmost preview viewport.
	for (int i = 0; i < 31; i++) {
		ut64 addr = 0x1000 + i * 16;
		ut64 jump = i < 15 ? 0x1000 + (2 * i + 1) * 16 : UT64_MAX;
		ut64 fail = i < 15 ? 0x1000 + (2 * i + 2) * 16 : UT64_MAX;
		rz_core_cmdf(core, "wx c3 @ 0x%" PFMT64x, addr);
		rz_core_cmdf(core, "afb+ 0x1000 0x%" PFMT64x " 1 0x%" PFMT64x " 0x%" PFMT64x,
			addr, jump, fail);
	}
	for (int mode = 0; mode < 6; mode++) {
		if (mode) {
			mu_assert_true(rz_cons_readpush(core->cons, "pqq", 3), "next mode");
			free(rz_core_cmd_str(core, "Vv"));
		}
		mu_assert_true(rz_cons_readpush(core->cons, "qq", 2), "reenter mode");
		int length;
		ut8 *output = rz_core_cmd_raw(core, "Vv", &length);
		mu_assert_notnull(output, "preview output");
		if (mode == 2 || mode == 3) {
			const char *title = "|  0x1000";
			mu_assert_notnull(rz_mem_mem(output, length, (const ut8 *)title, strlen(title)),
				"graph entry is visible in the preview");
		}
		free(output);
	}
	rz_core_free(core);
	mu_end;
}

static bool test_type_and_signature_cmd_status(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");

	mu_assert_eq(rz_core_cmd0_rzshell(core, "e asm.arch=x86; e asm.bits=64; o malloc://64"),
		RZ_CMD_STATUS_OK, "setup");

	mu_assert_eq(rz_core_cmd0_rzshell(core, "tos /nonexistent_rz_dir_xyz/missing.sdb"),
		RZ_CMD_STATUS_ERROR, "tos returns ERROR on missing sdb");
	mu_assert_eq(rz_core_cmd0_rzshell(core, "td \"\""),
		RZ_CMD_STATUS_ERROR, "td returns ERROR on empty input");
	mu_assert_eq(rz_core_cmd0_rzshell(core, "td \"struct broken {{{ \""),
		RZ_CMD_STATUS_ERROR, "td returns ERROR on invalid C syntax");
	mu_assert_eq(rz_core_cmd0_rzshell(core, "td \"struct rz_test_ok { int a; }\""),
		RZ_CMD_STATUS_OK, "td returns OK on valid C struct");

	mu_assert_eq(rz_core_cmd0_rzshell(core, "af+ test_fn; afb+ 0 0 1"),
		RZ_CMD_STATUS_OK, "create function");
	mu_assert_eq(rz_core_cmd0_rzshell(core, "afs \"not a valid signature (((\" @ 0"),
		RZ_CMD_STATUS_ERROR, "afs returns ERROR on invalid signature");
	mu_assert_eq(rz_core_cmd0_rzshell(core, "afs \"int test_fn(int x)\" @ 0"),
		RZ_CMD_STATUS_OK, "afs returns OK on valid signature");

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_visual_function_preview);
	mu_run_test(test_visual_preview_cache);
	mu_run_test(test_visual_graph_previews);
	mu_run_test(test_type_command_colors);
	mu_run_test(test_arg_cmd);
	mu_run_test(test_arg_cmd_last);
	mu_run_test(test_arg_cmd_last_with_at);
	mu_run_test(test_arg_cmd_last_opt);
	mu_run_test(test_last_cmd_status);
	mu_run_test(test_cmd_str_status);
	mu_run_test(test_last_cmd_status_verbose_json);
	mu_run_test(test_disasm_until_ret_json);
	mu_run_test(test_hist_push);
	mu_run_test(test_hist_push_seq);
	mu_run_test(test_hist_push_load);
	mu_run_test(test_type_and_signature_cmd_status);
	return tests_passed != tests_run;
}

mu_main(all_tests)
