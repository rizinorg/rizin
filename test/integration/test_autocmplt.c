// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_str.h>
#include "../unit/minunit.h"

static RzCmdDescArg xd_args[] = {
	{ .name = "f1", .type = RZ_CMD_ARG_TYPE_FILE },
	{ .name = "F2", .type = RZ_CMD_ARG_TYPE_FCN },
	{ .name = "e3", .type = RZ_CMD_ARG_TYPE_ENV },
	{ .name = "Z4", .type = RZ_CMD_ARG_TYPE_REG_TYPE },
	{ .name = "E5", .type = RZ_CMD_ARG_TYPE_EVAL_FULL },
	{ 0 },
};

static RzCmdDescHelp xd_help = {
	.summary = "xd summary",
	.args = xd_args,
};

static RzCmdDescArg xr_args[] = {
	{ .name = "D1", .type = RZ_CMD_ARG_TYPE_FOLDER },
	{ 0 },
};

static RzCmdDescHelp xr_help = {
	.summary = "xr summary",
	.args = xr_args,
};

static RzCmdDescArg xe_args[] = {
	{ .name = "f1", .type = RZ_CMD_ARG_TYPE_STRING },
	{ 0 },
};

static RzCmdDescHelp xe_help = {
	.summary = "xe summary",
	.args = xe_args,
};

static RzCmdDescHelp x_group_help = {
	.summary = "x group summary",
};

static RzCmdDescHelp p_help = {
	.summary = "p summary",
	.args = xe_args,
};

static RzCmdDescArg s_args[] = {
	{ .name = "v1", .type = RZ_CMD_ARG_TYPE_RZNUM, .flags = RZ_CMD_ARG_FLAG_LAST },
	{ 0 },
};

static RzCmdDescHelp s_help = {
	.summary = "s summary",
	.args = s_args,
};

static char **z_args_choices_cb(RzCore *core) {
	char **res = RZ_NEWS0(char *, 3);
	res[0] = strdup("Hello");
	res[1] = strdup("World");
	return res;
}

static RzCmdDescArg z_args[] = {
	{ .name = "v1", .type = RZ_CMD_ARG_TYPE_CHOICES, .choices.choices_cb = z_args_choices_cb },
	{ 0 },
};

static RzCmdDescHelp z_help = {
	.summary = "z summary",
	.args = z_args,
};

static RzCmdStatus x_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static RzCmd *old_rcmd = NULL;

static RzCore *fake_core_new(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzCoreFile *cf = rz_core_file_open(core, "bins/elf/hello_world", RZ_PERM_R, 0);
	mu_assert_notnull(cf, "file should be opened");
	rz_core_bin_load(core, "bins/elf/hello_world", 0);
	old_rcmd = core->rcmd;
	RzCmd *cmd = rz_core_cmd_new(core, true);
	mu_assert_notnull(cmd, "cmd should be created");
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	mu_assert_notnull(root, "root should be present");
	RzCmdDesc *x = rz_cmd_desc_group_new(cmd, root, "x", NULL, NULL, &x_group_help);
	mu_assert_notnull(x, "x");
	RzCmdDesc *xd = rz_cmd_desc_argv_new(cmd, x, "xd", x_handler, &xd_help);
	mu_assert_notnull(xd, "xd");
	RzCmdDesc *xr = rz_cmd_desc_argv_new(cmd, x, "xr", x_handler, &xr_help);
	mu_assert_notnull(xr, "xr");
	RzCmdDesc *xe = rz_cmd_desc_argv_new(cmd, x, "xe", x_handler, &xe_help);
	mu_assert_notnull(xe, "xe");
	RzCmdDesc *p = rz_cmd_desc_argv_new(cmd, root, "p", x_handler, &p_help);
	mu_assert_notnull(p, "p");
	RzCmdDesc *s = rz_cmd_desc_argv_new(cmd, root, "s", x_handler, &s_help);
	mu_assert_notnull(s, "s");
	RzCmdDesc *z = rz_cmd_desc_argv_new(cmd, root, "z", x_handler, &z_help);
	mu_assert_notnull(z, "z");
	core->rcmd = cmd;
	rz_core_cmd(core, "", 0);
	return core;
}

static void fake_core_free(RzCore *core) {
	rz_cmd_free(core->rcmd);
	core->rcmd = old_rcmd;
	rz_core_free(core);
}

static RzCore *fake_core_new2(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzCoreFile *cf = rz_core_file_open(core, "bins/elf/hello_world", RZ_PERM_R, 0);
	mu_assert_notnull(cf, "file should be opened");
	rz_core_bin_load(core, "bins/elf/hello_world", 0);

	RzCmdDesc *root = rz_cmd_get_root(core->rcmd);
	mu_assert_notnull(root, "root should be present");
	RzCmdDesc *unittest_cd = rz_cmd_desc_argv_new(core->rcmd, root, "unittest", x_handler, &xd_help);
	mu_assert_notnull(unittest_cd, "unittest_cd");
	rz_core_cmd(core, "", 0);
	return core;
}

static bool test_autocmplt_cmdid(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	strcpy(buf->data, "x");
	buf->length = strlen("x");
	buf->index = 1;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_eq(r->start, 0, "should autocomplete starting from 0");
	mu_assert_eq(r->end, 1, "should autocomplete ending at 1");
	mu_assert_eq(rz_pvector_len(&r->options), 3, "there are 3 commands starting with `x`");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "xd", "one is xd");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "xr", "one is xr");
	mu_assert_streq(rz_pvector_at(&r->options, 2), "xe", "one is xe");
	rz_line_ns_completion_result_free(r);

	strcpy(buf->data, "p @@c:x");
	buf->length = strlen("p @@c:x");
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should be returned");
	mu_assert_eq(r->start, buf->length - 1, "start is ok");
	mu_assert_eq(r->end, buf->length, "end is ok");
	mu_assert_eq(rz_pvector_len(&r->options), 3, "there are 3 commands starting with `x`");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "xd", "one is xd");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "xr", "one is xr");
	mu_assert_streq(rz_pvector_at(&r->options, 2), "xe", "one is xe");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_newcommand(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	strcpy(buf->data, "p @@c:");
	buf->length = strlen("p @@c:");
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "result should be there");
	mu_assert_eq(r->start, buf->length, "start should be ok");
	mu_assert_eq(r->end, buf->length, "end should be ok");
	mu_assert_eq(rz_pvector_len(&r->options), 6, "there are 4 commands available");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "p", "one is p");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "s", "one is s");
	mu_assert_streq(rz_pvector_at(&r->options, 2), "xd", "one is xd");
	mu_assert_streq(rz_pvector_at(&r->options, 3), "xr", "one is xr");
	mu_assert_streq(rz_pvector_at(&r->options, 4), "xe", "one is xe");
	mu_assert_streq(rz_pvector_at(&r->options, 5), "z", "one is z");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_argid(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "xd ./unit/test_interv";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, 3, "should autocomplete starting from ./...");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 1, "there is just one file with test_interv");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "." RZ_SYS_DIR "unit" RZ_SYS_DIR "test_intervaltree.c", "test_intervaltree.c");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_quotedarg(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "xd \"./unit/test_interv";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, 4, "should autocomplete starting from ./...");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 1, "there is just one file with test_interv");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "." RZ_SYS_DIR "unit" RZ_SYS_DIR "test_intervaltree.c", "test_intervaltree.c");
	mu_assert_streq(r->end_string, "\" ", "double quotes should be put at the end of the string");
	rz_line_ns_completion_result_free(r);

	s = "xd './unit/test_interv";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, 4, "should autocomplete starting from ./...");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 1, "there is just one file with test_interv");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "." RZ_SYS_DIR "unit" RZ_SYS_DIR "test_intervaltree.c", "test_intervaltree.c");
	mu_assert_streq(r->end_string, "' ", "double quotes should be put at the end of the string");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_newarg(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	char *cwd = rz_sys_getdir();
	rz_sys_mkdir("newarg_test");
	rz_sys_chdir("newarg_test");
	mu_assert_true(rz_file_touch("file0"), "");
	mu_assert_true(rz_file_touch("file1"), "");
	mu_assert_true(rz_file_touch("file2"), "");

	const char *s = "xd ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, buf->length, "should autocomplete starting after space");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 3, "there are 3 files in newarg_test dir");
	bool found[3] = { false, false, false };
	void **it;
	rz_pvector_foreach (&r->options, it) {
		char *f = *(char **)it;
		mu_assert_true(rz_str_startswith(f, "." RZ_SYS_DIR "file"), "options start with ./file");
		int v = atoi(f + strlen("./file"));
		found[v] = true;
	}
	mu_assert_true(found[0], "file0 found");
	mu_assert_true(found[1], "file1 found");
	mu_assert_true(found[2], "file2 found");
	rz_line_ns_completion_result_free(r);

	rz_file_rm("file0");
	rz_file_rm("file1");
	rz_file_rm("file2");
	rz_file_rm("newarg_test");
	rz_sys_chdir(cwd);
	free(cwd);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_arg_folder(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	char *cwd = rz_sys_getdir();
	rz_sys_mkdir("New_test_folder");
	rz_sys_chdir("New_test_folder");
	rz_sys_mkdir("test_folder_1");
	rz_sys_mkdir("test_folder_2");
	mu_assert_true(rz_file_touch("test_file_1"), "create test_file_1");
	mu_assert_true(rz_file_touch("test_file_2"), "create test_file_2");

	const char *s = "xr ";

	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;

	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "completion result should not be null for command");
	mu_assert_eq(r->start, buf->length, "should autocomplete starting from position");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");

	size_t found_folder_1 = 0, found_folder_2 = 0, found_files = 0;
	void **it;
	rz_pvector_foreach (&r->options, it) {
		const char *f = *(const char **)it;

		if (rz_file_is_directory(f)) {
			if (rz_str_strchr(f, "test_folder_1"))
				found_folder_1 = 1;
			if (rz_str_strchr(f, "test_folder_2"))
				found_folder_2 = 1;
		} else {
			found_files++;
		}
	}

	mu_assert_true(found_folder_1, "test_folder_1 should be in completions");
	mu_assert_true(found_folder_2, "test_folder_2 should be in completions");
	mu_assert_eq(found_files, 0, "NO files should be in folder type completions");
	rz_line_ns_completion_result_free(r);

	rz_file_rm("test_file_1");
	rz_file_rm("test_file_2");
	rz_file_rm("test_folder_1");
	rz_file_rm("test_folder_2");
	rz_file_rm("New_test_folder");
	rz_sys_chdir(cwd);
	free(cwd);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_fcn(void) {
	RzCore *core = fake_core_new2();
	mu_assert_notnull(core, "core not null");
	RzLineBuffer *buf = &core->cons->line->buffer;

	rz_core_analysis_all(core);

	const char *s = "unittest ./file2 sym.imp.s";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("unittest ./file1 "), "should autocomplete starting after space");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 3, "there are 3 functions starting with sym.imp.s");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "sym.imp.strlen", "strlen");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "sym.imp.strcpy", "strcpy");
	mu_assert_streq(rz_pvector_at(&r->options, 2), "sym.imp.strcat", "strcat");
	rz_line_ns_completion_result_free(r);

	rz_core_free(core);
	mu_end;
}

static bool test_autocmplt_eval(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "xd 1 2 3 4 asm.lines.w";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("xd 1 2 3 4 "), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "there are 2 config evals starting with asm.lines.w");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "asm.lines.wide", "asm.lines.wide found");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "asm.lines.width", "asm.lines.width found");
	rz_line_ns_completion_result_free(r);

	s = "xd 1 2 3 4 search.in=io.maps.r";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("xd 1 2 3 4 search.in="), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 4, "there are 4 options values for config eval search.in");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_seek(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");

	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "s ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("s "), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 177, "there are 177 rznum vars on loading");
	rz_line_ns_completion_result_free(r);

	rz_flag_set(core->flags, "flag1", 0x1000, 1);
	rz_flag_set(core->flags, "flag2", 0x2000, 1);
	rz_flag_set(core->flags, "test3", 0x3000, 1);
	rz_flag_set(core->flags, "test4", 0x4000, 1);

	s = "s fl";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("s "), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "there are 2 rznum vars starting with fl");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "flag1", "flag1 found");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "flag2", "flag2 found");
	rz_line_ns_completion_result_free(r);

	s = "s flag1 + tes";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("s flag1 + "), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "there are 2 rznum vars starting with tes");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "test3", "test3 found");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "test4", "test4 found");
	rz_line_ns_completion_result_free(r);

	s = "s flag1+tes";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("s flag1+"), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "there are 2 rznum vars starting with tes");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "test3", "test3 found");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "test4", "test4 found");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_global(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should not be null");

	RzAnalysisVarGlobal *glob1 = rz_analysis_var_global_new("GINT", 0x1337); // untyped global
	mu_assert_notnull(glob1, "glob1 null");
	bool added = rz_analysis_var_global_add(core->analysis, glob1);
	mu_assert_true(added, "unable to add glob1");

	RzAnalysisVarGlobal *glob2 = rz_analysis_var_global_new("GCHR", 0xd3ad); // typed global
	mu_assert_notnull(glob2, "glob2 null");
	added = rz_analysis_var_global_add(core->analysis, glob2);
	mu_assert_true(added, "unable to add glob2");
	RzTypeParser *parser = rz_type_parser_new();
	mu_assert_notnull(parser, "create type parser");
	char *errmsg = NULL;
	RzType *typ = rz_type_parse_string_single(parser, "int", &errmsg);
	free(errmsg);

	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob2, typ);

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "avgl ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;

	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("avgl "), "should autocomplete the last arg");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "there are 2 global vars");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "GINT", "GINT found");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "GCHR", "GCHR found");
	rz_line_ns_completion_result_free(r);

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

static bool test_autocmplt_tmp_operators(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "pd @";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("pd "), "should autocomplete the @ operator");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");

	const char *tmp_ops[] = {
		"@ ",
		"@!",
		"@(",
		"@a:",
		"@b:",
		"@B:",
		"@e:",
		"@f:",
		"@F:",
		"@i:",
		"@k:",
		"@o:",
		"@r:",
		"@s:",
		"@v:",
		"@x:",
		"@@.",
		"@@=",
		"@@@=",
		"@@",
		"@@c:",
		"@@@c:",
		"@@C",
		"@@C:",
		"@@dbt",
		"@@dbtb",
		"@@dbts",
		"@@t",
		"@@b",
		"@@i",
		"@@ii",
		"@@iS",
		"@@iSS",
		"@@is",
		"@@iz",
		"@@f",
		"@@f:",
		"@@F",
		"@@F:",
		"@@om",
		"@@dm",
		"@@r",
		"@@s:",
	};
	mu_assert_eq(rz_pvector_len(&r->options), RZ_ARRAY_SIZE(tmp_ops), "there are all @/@@/@@ operators (see @?, @@?)");
	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(tmp_ops); i++) {
		char msg[100];
		rz_strf(msg, "%d-th should be %s", i, tmp_ops[i]);
		mu_assert_streq(rz_pvector_at(&r->options, i), tmp_ops[i], msg);
	}
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_iter_operators(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "pd @@";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("pd "), "should autocomplete the @@ operator");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");

	const char *iter_ops[] = {
		"@@.",
		"@@=",
		"@@@=",
		"@@",
		"@@c:",
		"@@@c:",
		"@@C",
		"@@C:",
		"@@dbt",
		"@@dbtb",
		"@@dbts",
		"@@t",
		"@@b",
		"@@i",
		"@@ii",
		"@@iS",
		"@@iSS",
		"@@is",
		"@@iz",
		"@@f",
		"@@f:",
		"@@F",
		"@@F:",
		"@@om",
		"@@dm",
		"@@r",
		"@@s:",
	};
	mu_assert_eq(rz_pvector_len(&r->options), RZ_ARRAY_SIZE(iter_ops), "there are all @@/@@ operators (see @@?)");
	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(iter_ops); i++) {
		char msg[100];
		rz_strf(msg, "%d-th should be %s", i, iter_ops[i]);
		mu_assert_streq(rz_pvector_at(&r->options, i), iter_ops[i], msg);
	}
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_tmp_seek(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "pd @ ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("pd @ "), "should autocomplete the @ operator");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_true(rz_pvector_len(&r->options) > 100, "there are a lot of possible values to seek to");
	rz_line_ns_completion_result_free(r);

	s = "pd @ st";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("pd @ "), "should autocomplete the @ operator");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 15, "there are 15 possible values to seek to starting with st");
	mu_assert_streq(rz_pvector_at(&r->options, 13), "str.Hello", "hello string is there");
	mu_assert_streq(rz_pvector_at(&r->options, 14), "str.r2_folks", "r2_folks string is there");
	rz_line_ns_completion_result_free(r);
	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_tmp_config(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "pd @e:";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("pd @e:"), "should autocomplete the @ operator");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_true(rz_pvector_len(&r->options) > 20, "there are many possible eval vars");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_tmp_arch(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "pd @a:w";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, strlen("pd @a:"), "should autocomplete the @ operator");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 1, "there is just 1 arch starting with w: wasm");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "wasm", "hello string is there");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_choices_cb_arg(void) {
	RzCore *core = fake_core_new();
	mu_assert_notnull(core, "core should be created");
	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "z ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);

	mu_assert_notnull(r, "r should not be null");
	mu_assert_eq(r->start, buf->length, "should autocomplete starting after space");
	mu_assert_eq(r->end, buf->length, "should autocomplete ending at end of buffer");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "there are 2 choices from cb");

	mu_assert_streq(rz_pvector_at(&r->options, 0), "Hello", "hello choice is there");
	mu_assert_streq(rz_pvector_at(&r->options, 1), "World", "world choice is there");
	rz_line_ns_completion_result_free(r);

	fake_core_free(core);
	mu_end;
}

static bool test_autocmplt_eco_themes(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");

	RzLineBuffer *buf = &core->cons->line->buffer;

	const char *s = "eco ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;

	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "Autocomplete result should not be NULL");

	size_t count = rz_pvector_len(&r->options);

	mu_assert_true(count > 0, "There should be at least one theme");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "ayu", "First theme should be ayu or similar");

	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Register two named `pf` formats and confirm `pfn <TAB>` lists them. */
static bool test_autocmplt_pf_format_name(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_alpha", "x4 magic");
	rz_type_db_format_set(typedb, "ut_beta", "x4d4 magic count");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pfn ut_";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;

	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result should be returned");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "two formats start with 'ut_'");
	/* Order is whatever `rz_type_db_format_all` returns; verify membership. */
	bool saw_alpha = false, saw_beta = false;
	for (size_t i = 0; i < rz_pvector_len(&r->options); i++) {
		const char *opt = rz_pvector_at(&r->options, i);
		if (!strcmp(opt, "ut_alpha")) {
			saw_alpha = true;
		}
		if (!strcmp(opt, "ut_beta")) {
			saw_beta = true;
		}
	}
	mu_assert_true(saw_alpha, "ut_alpha should be offered");
	mu_assert_true(saw_beta, "ut_beta should be offered");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* `pf.` is the named-display command and accepts `<name>.<field>` paths.
 * With no dot in the partial, completion lists format names; once a dot
 * is typed, completion descends into the named format's top-level field
 * names and rewrites `start` so only the field portion is replaced. */
static bool test_autocmplt_pf_format_path(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_path", "x4d4z magic count name");

	RzLineBuffer *buf = &core->cons->line->buffer;

	/* Phase 1: no dot yet -- complete format name. */
	const char *s1 = "pf. ut_pa";
	strcpy(buf->data, s1);
	buf->length = strlen(s1);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "phase1 result");
	mu_assert_eq(rz_pvector_len(&r->options), 1, "one format matches 'ut_pa'");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "ut_path", "format name");
	mu_assert_streq(r->end_string, "", "no trailing space so the user can type '.' next");
	rz_line_ns_completion_result_free(r);

	/* Phase 2: dot typed, prefix is empty -- list all top-level fields. */
	const char *s2 = "pf. ut_path.";
	strcpy(buf->data, s2);
	buf->length = strlen(s2);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "phase2 result");
	mu_assert_eq(rz_pvector_len(&r->options), 3, "three fields: magic, count, name");
	/* start should point past the dot so only the field is replaced. */
	mu_assert_eq(r->start, buf->length, "start advanced to post-dot");
	bool saw_magic = false, saw_count = false, saw_name = false;
	for (size_t i = 0; i < rz_pvector_len(&r->options); i++) {
		const char *opt = rz_pvector_at(&r->options, i);
		if (!strcmp(opt, "magic")) {
			saw_magic = true;
		}
		if (!strcmp(opt, "count")) {
			saw_count = true;
		}
		if (!strcmp(opt, "name")) {
			saw_name = true;
		}
	}
	mu_assert_true(saw_magic && saw_count && saw_name, "all three field names offered");
	rz_line_ns_completion_result_free(r);

	/* Phase 3: dot + field prefix -- narrow to matching field. */
	const char *s3 = "pf. ut_path.cou";
	strcpy(buf->data, s3);
	buf->length = strlen(s3);
	buf->index = buf->length;
	r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "phase3 result");
	mu_assert_eq(rz_pvector_len(&r->options), 1, "only 'count' starts with 'cou'");
	mu_assert_streq(rz_pvector_at(&r->options, 0), "count", "narrowed to count");
	rz_line_ns_completion_result_free(r);

	rz_core_free(core);
	mu_end;
}

/* `pfw <format>` also takes a `name.field` path (the write side of the
 * same syntax `pf.` uses). Make sure the same PATH completer fires here
 * too -- not a separate code path. */
static bool test_autocmplt_pfw_format_path(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_w", "x4x4 a b");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pfw ut_w.";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "two fields: a, b");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* `pf.` with no argument and no partial should list every registered
 * format. This is the discovery use case ("what formats do I have?"). */
static bool test_autocmplt_pf_format_path_empty(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	/* Snapshot what's already registered (the default type DB seeds a
	 * handful of named formats) so the count assertion stays robust. */
	RzList *baseline = rz_type_db_format_all(typedb);
	size_t baseline_len = baseline ? rz_list_length(baseline) : 0;
	rz_list_free(baseline);
	rz_type_db_format_set(typedb, "ut_empty_test", "x4x magic v");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), baseline_len + 1,
		"all existing formats plus the one we just added");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Unknown format name in front of the dot: no fields to descend into,
 * so the completer returns an empty option list (instead of crashing or
 * leaking the typedb error path). */
static bool test_autocmplt_pf_format_path_unknown_name(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_not_a_format.";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 0, "no options for unknown name");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Fields without an explicit name (anonymous, e.g. skip/align) must be
 * skipped silently rather than crashing on a NULL `fields[i].name`. The
 * format below mixes a named field with an unnamed skip slot. */
static bool test_autocmplt_pf_format_path_anon_field(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	/* `.` is the skip specifier and has no associated name slot. */
	rz_type_db_format_set(typedb, "ut_anon", "x4.x4 a b");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_anon.";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	/* Two named fields: a and b. The skip slot is anonymous and
	 * dropped. */
	mu_assert_eq(rz_pvector_len(&r->options), 2, "two named fields offered");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Two-level nested-struct descent: `outer` references `inner` via a
 * STRUCT field, and `pf. outer.body.<TAB>` should descend into
 * `inner`'s top-level fields. This is the smallest case that exercises
 * the new re-parse-on-type_name loop in pf_resolve_path_format. */
static bool test_autocmplt_pf_format_path_nested(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_inner", "x4d4 first second");
	rz_type_db_format_set(typedb, "ut_outer", "?(ut_inner) body");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_outer.body.";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 2, "inner's two fields offered");
	mu_assert_eq(r->start, buf->length, "start advanced past the second dot");
	bool saw_first = false, saw_second = false;
	for (size_t i = 0; i < rz_pvector_len(&r->options); i++) {
		const char *opt = rz_pvector_at(&r->options, i);
		if (!strcmp(opt, "first")) {
			saw_first = true;
		}
		if (!strcmp(opt, "second")) {
			saw_second = true;
		}
	}
	mu_assert_true(saw_first && saw_second, "first + second offered");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Three-level descent narrows correctly: `pf. A.B.C.bo<TAB>` should
 * walk A -> B -> C and offer only fields of C that start with `bo`. */
static bool test_autocmplt_pf_format_path_three_levels(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_C", "x4d4d4 top bottom border");
	rz_type_db_format_set(typedb, "ut_B", "?(ut_C) mid");
	rz_type_db_format_set(typedb, "ut_A", "?(ut_B) outer");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_A.outer.mid.bo";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	/* Of C's fields (top, bottom, border) only the two starting with
	 * "bo" should be offered. */
	mu_assert_eq(rz_pvector_len(&r->options), 2, "bottom + border match 'bo'");
	bool saw_bottom = false, saw_border = false;
	for (size_t i = 0; i < rz_pvector_len(&r->options); i++) {
		const char *opt = rz_pvector_at(&r->options, i);
		if (!strcmp(opt, "bottom")) {
			saw_bottom = true;
		}
		if (!strcmp(opt, "border")) {
			saw_border = true;
		}
	}
	mu_assert_true(saw_bottom && saw_border, "bottom + border offered");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Array index in a middle segment: the cmd_pf2 test exercises
 * `pf. troll.str[1].two` at runtime. Verify the completer accepts
 * `troll.str[1].<TAB>` and offers plop's fields. */
static bool test_autocmplt_pf_format_path_array_index(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_plop", "d4x2x8x2 one two three four");
	rz_type_db_format_set(typedb, "ut_troll", "[3]?(ut_plop) str");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_troll.str[1].";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 4, "plop's four fields offered");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* When the cursor sits inside an unclosed `[`, the user is mid-index
 * and identifier completion would be nonsense; offer nothing. */
static bool test_autocmplt_pf_format_path_inside_brackets(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_arr", "[3]?(ut_arr_inner) arr");
	rz_type_db_format_set(typedb, "ut_arr_inner", "x4 v");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_arr.arr[";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 0,
		"no completion while cursor is mid-index");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* `name[N]` followed by no dot yet is also mid-descent: the next
 * keystroke needs to be `.` before fields are meaningful, so offer
 * nothing rather than suggesting field names that would be a syntax
 * error if the user accepted them. */
static bool test_autocmplt_pf_format_path_after_close_bracket(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_acb_inner", "x4d4 a b");
	rz_type_db_format_set(typedb, "ut_acb", "[3]?(ut_acb_inner) arr");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_acb.arr[2]";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 0,
		"no completion after ] without trailing .");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

/* Descent through a scalar field is meaningless and must return no
 * options (rather than offering top-level format names or crashing). */
static bool test_autocmplt_pf_format_path_through_scalar(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_format_set(typedb, "ut_scalar_path", "x4d4 num val");

	RzLineBuffer *buf = &core->cons->line->buffer;
	const char *s = "pf. ut_scalar_path.num.";
	strcpy(buf->data, s);
	buf->length = strlen(s);
	buf->index = buf->length;
	RzLineNSCompletionResult *r = rz_core_autocomplete_rzshell(core, buf, RZ_LINE_PROMPT_DEFAULT);
	mu_assert_notnull(r, "result");
	mu_assert_eq(rz_pvector_len(&r->options), 0,
		"no descent past a scalar field");
	rz_line_ns_completion_result_free(r);
	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_autocmplt_cmdid);
	mu_run_test(test_autocmplt_newcommand);
	mu_run_test(test_autocmplt_argid);
	mu_run_test(test_autocmplt_quotedarg);
	mu_run_test(test_autocmplt_newarg);
	mu_run_test(test_autocmplt_arg_folder);
	mu_run_test(test_autocmplt_fcn);
	mu_run_test(test_autocmplt_eval);
	mu_run_test(test_autocmplt_seek);
	mu_run_test(test_autocmplt_global);
	mu_run_test(test_autocmplt_tmp_operators);
	mu_run_test(test_autocmplt_iter_operators);
	mu_run_test(test_autocmplt_tmp_seek);
	mu_run_test(test_autocmplt_tmp_config);
	mu_run_test(test_autocmplt_tmp_arch);
	mu_run_test(test_autocmplt_choices_cb_arg);
	mu_run_test(test_autocmplt_eco_themes);
	mu_run_test(test_autocmplt_pf_format_name);
	mu_run_test(test_autocmplt_pf_format_path);
	mu_run_test(test_autocmplt_pfw_format_path);
	mu_run_test(test_autocmplt_pf_format_path_empty);
	mu_run_test(test_autocmplt_pf_format_path_unknown_name);
	mu_run_test(test_autocmplt_pf_format_path_anon_field);
	mu_run_test(test_autocmplt_pf_format_path_nested);
	mu_run_test(test_autocmplt_pf_format_path_three_levels);
	mu_run_test(test_autocmplt_pf_format_path_array_index);
	mu_run_test(test_autocmplt_pf_format_path_inside_brackets);
	mu_run_test(test_autocmplt_pf_format_path_after_close_bracket);
	mu_run_test(test_autocmplt_pf_format_path_through_scalar);
	return tests_passed != tests_run;
}

mu_main(all_tests)
