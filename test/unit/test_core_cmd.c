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

static bool test_hist_push(void) {
	RzCore *core = rz_core_new();
	RzLine *line = core->cons->line;
	const char *mark = "i5824";
	const char *cmd = "echo i5824";

	rz_line_hist_add(line, cmd);
	int history_top = line->history.top;
	rz_cons_readflush();

	free(core->cmdqueue);
	core->cmdqueue = rz_str_newf("< \\x12%s\\n", mark);
	mu_assert_notnull(core->cmdqueue, "cmdqueue should be allocated");

	mu_assert_eq(rz_core_prompt_exec(core), 0, "push_escaped prompt command should execute");
	mu_assert_eq(line->history.top, history_top, "push_escaped should not be added to history");
	mu_assert_streq(rz_line_hist_get(line, history_top), cmd, "last history entry should remain the preexisting matching command");

	const char *res = rz_line_readline(line);
	mu_assert_notnull(res, "reverse-search result should not be null");
	mu_assert_streq(res, cmd, "reverse-search should resolve to prior history, not the injector command");

	rz_cons_readflush();
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
	rz_cons_readflush();

	free(core->cmdqueue);
	core->cmdqueue = rz_str_newf("echo %s; < \\x12%s\\n", mark, mark);
	mu_assert_notnull(core->cmdqueue, "cmdqueue should be allocated");

	mu_assert_eq(rz_core_prompt_exec(core), 0, "push_escaped prompt command should execute");
	mu_assert_eq(line->history.top, history_top, "command lines containing push_escaped should not be added to history");
	mu_assert_streq(rz_line_hist_get(line, history_top), cmd, "last history entry should remain the preexisting matching command");

	const char *res = rz_line_readline(line);
	mu_assert_notnull(res, "reverse-search result should not be null");
	mu_assert_streq(res, cmd, "reverse-search should resolve to prior history, not the injector command");

	rz_cons_readflush();
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

int all_tests() {
	mu_run_test(test_arg_cmd);
	mu_run_test(test_arg_cmd_last);
	mu_run_test(test_arg_cmd_last_with_at);
	mu_run_test(test_arg_cmd_last_opt);
	mu_run_test(test_last_cmd_status);
	mu_run_test(test_cmd_str_status);
	mu_run_test(test_hist_push);
	mu_run_test(test_hist_push_seq);
	mu_run_test(test_hist_push_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
