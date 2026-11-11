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

int all_tests() {
	mu_run_test(test_type_command_colors);
	mu_run_test(test_arg_cmd);
	mu_run_test(test_arg_cmd_last);
	mu_run_test(test_arg_cmd_last_with_at);
	mu_run_test(test_arg_cmd_last_opt);
	mu_run_test(test_last_cmd_status);
	mu_run_test(test_cmd_str_status);
	mu_run_test(test_disasm_until_ret_json);
	mu_run_test(test_hist_push);
	mu_run_test(test_hist_push_seq);
	mu_run_test(test_hist_push_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
