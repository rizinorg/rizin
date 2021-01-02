#include <rz_core.h>
#include "minunit.h"

static RzCmdDescArg xd_args[] = {
    { .name = "f1", .type = RZ_CMD_ARG_TYPE_FILE },
    { .name = "F2", .type = RZ_CMD_ARG_TYPE_FCN },
    { .name = "e3", .type = RZ_CMD_ARG_TYPE_ENV },
    { .name = "Z4", .type = RZ_CMD_ARG_TYPE_ZIGN_SPACE },
    { 0 },
};

static RzCmdDescHelp xd_help = {
    .summary = "xd summary",
    .args = xd_args,
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

static RzCmdStatus x_handler(RzCore *core, int argc, const char **argv) {
    return RZ_CMD_STATUS_OK;
}

static RzCore *fake_core_new(void) {
    RzCore *core = rz_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzCoreFile *cf = rz_core_file_open (core, "bins/elf/hello_world", RZ_PERM_R, 0);
    mu_assert_notnull (cf, "file should be opened");
    rz_core_bin_load (core, "bins/elf/hello_world", 0);
    rz_cmd_free (core->rcmd);
    RzCmd *cmd = rz_cmd_new (true);
    mu_assert_notnull (cmd, "cmd should be created");
    RzCmdDesc *root = rz_cmd_get_root (cmd);
    mu_assert_notnull (root, "root should be present");
    RzCmdDesc *x = rz_cmd_desc_group_new (cmd, root, "x", NULL, NULL, &x_group_help);
    mu_assert_notnull (x, "x");
    RzCmdDesc *xd = rz_cmd_desc_argv_new (cmd, x, "xd", x_handler, &xd_help);
    mu_assert_notnull (xd, "xd");
    RzCmdDesc *xe = rz_cmd_desc_argv_new (cmd, x, "xe", x_handler, &xe_help);
    mu_assert_notnull (xe, "xe");
    RzCmdDesc *p = rz_cmd_desc_argv_new (cmd, root, "p", x_handler, &p_help);
    mu_assert_notnull (p, "p");
    core->rcmd = cmd;
    rz_core_cmd (core, "", 0);
    return core;
}

static RzCore *fake_core_new2(void) {
    RzCore *core = rz_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzCoreFile *cf = rz_core_file_open (core, "bins/elf/hello_world", RZ_PERM_R, 0);
    mu_assert_notnull (cf, "file should be opened");
    rz_core_bin_load (core, "bins/elf/hello_world", 0);

    RzCmdDesc *root = rz_cmd_get_root (core->rcmd);
    mu_assert_notnull (root, "root should be present");
    RzCmdDesc *unittest_cd = rz_cmd_desc_argv_new (core->rcmd, root, "unittest", x_handler, &xd_help);
    mu_assert_notnull (unittest_cd, "unittest_cd");
    rz_core_cmd (core, "", 0);
    return core;
}

static bool test_autocmplt_cmdid(void) {
    RzCore *core = fake_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzLineBuffer *buf = &core->cons->line->buffer;

    strcpy (buf->data, "x");
    buf->length = strlen ("x");
    buf->index = 1;
    RzLineNSCompletionResult *r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_eq (r->start, 0, "should autocomplete starting from 0");
    mu_assert_eq (r->end, 1, "should autocomplete ending at 1");
    mu_assert_eq (rz_pvector_len (&r->options), 2, "there are 2 commands starting with `x`");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "xd", "one is xd");
    mu_assert_streq (rz_pvector_at (&r->options, 1), "xe", "one is xe");
    rz_line_ns_completion_result_free (r);

    strcpy (buf->data, "p @@c:x");
    buf->length = strlen ("p @@c:x");
    buf->index = buf->length;
    r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should be returned");
    mu_assert_eq (r->start, buf->length - 1, "start is ok");
    mu_assert_eq (r->end, buf->length, "end is ok");
    mu_assert_eq (rz_pvector_len (&r->options), 2, "there are 2 commands starting with `x`");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "xd", "one is xd");
    mu_assert_streq (rz_pvector_at (&r->options, 1), "xe", "one is xe");
    rz_line_ns_completion_result_free (r);

    rz_core_free (core);
    mu_end;
}

static bool test_autocmplt_newcommand(void) {
    RzCore *core = fake_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzLineBuffer *buf = &core->cons->line->buffer;

    strcpy (buf->data, "");
    buf->length = strlen ("");
    buf->index = 0;
    RzLineNSCompletionResult *r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should be returned");
    mu_assert_eq (r->start, 0, "should autocomplete starting from 0");
    mu_assert_eq (r->end, 0, "should autocomplete ending at 0");
    mu_assert_eq (rz_pvector_len (&r->options), 3, "there are 2 commands available");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "xd", "one is xd");
    mu_assert_streq (rz_pvector_at (&r->options, 1), "xe", "one is xe");
    mu_assert_streq (rz_pvector_at (&r->options, 2), "p", "one is p");
    rz_line_ns_completion_result_free (r);

    strcpy (buf->data, "p @@c:");
    buf->length = strlen ("p @@c:");
    buf->index = buf->length;
    r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "result should be there");
    mu_assert_eq (r->start, buf->length, "start should be ok");
    mu_assert_eq (r->end, buf->length, "end should be ok");
    mu_assert_eq (rz_pvector_len (&r->options), 3, "there are 2 commands available");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "xd", "one is xd");
    mu_assert_streq (rz_pvector_at (&r->options, 1), "xe", "one is xe");
    mu_assert_streq (rz_pvector_at (&r->options, 2), "p", "one is p");
    rz_line_ns_completion_result_free (r);

    rz_core_free (core);
    mu_end;
}

static bool test_autocmplt_argid(void) {
    RzCore *core = fake_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzLineBuffer *buf = &core->cons->line->buffer;

    const char *s = "xd ./unit/test_interv";
    strcpy (buf->data, s);
    buf->length = strlen (s);
    buf->index = buf->length;
    RzLineNSCompletionResult *r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should not be null");
    mu_assert_eq (r->start, 3, "should autocomplete starting from ./...");
    mu_assert_eq (r->end, buf->length, "should autocomplete ending at end of buffer");
    mu_assert_eq (rz_pvector_len (&r->options), 1, "there is just one file with test_interv");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "." RZ_SYS_DIR "unit" RZ_SYS_DIR "test_intervaltree.c", "test_intervaltree.c");
    rz_line_ns_completion_result_free (r);

    rz_core_free (core);
    mu_end;
}

static bool test_autocmplt_quotedarg(void) {
    RzCore *core = fake_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzLineBuffer *buf = &core->cons->line->buffer;

    const char *s = "xd \"./unit/test_interv";
    strcpy (buf->data, s);
    buf->length = strlen (s);
    buf->index = buf->length;
    RzLineNSCompletionResult *r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should not be null");
    mu_assert_eq (r->start, 4, "should autocomplete starting from ./...");
    mu_assert_eq (r->end, buf->length, "should autocomplete ending at end of buffer");
    mu_assert_eq (rz_pvector_len (&r->options), 1, "there is just one file with test_interv");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "." RZ_SYS_DIR "unit" RZ_SYS_DIR "test_intervaltree.c", "test_intervaltree.c");
    mu_assert_streq (r->end_string, "\" ", "double quotes should be put at the end of the string");
    rz_line_ns_completion_result_free (r);

    s = "xd './unit/test_interv";
    strcpy (buf->data, s);
    buf->length = strlen (s);
    buf->index = buf->length;
    r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should not be null");
    mu_assert_eq (r->start, 4, "should autocomplete starting from ./...");
    mu_assert_eq (r->end, buf->length, "should autocomplete ending at end of buffer");
    mu_assert_eq (rz_pvector_len (&r->options), 1, "there is just one file with test_interv");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "." RZ_SYS_DIR "unit" RZ_SYS_DIR "test_intervaltree.c", "test_intervaltree.c");
    mu_assert_streq (r->end_string, "' ", "double quotes should be put at the end of the string");
    rz_line_ns_completion_result_free (r);

    rz_core_free (core);
    mu_end;
}

static bool test_autocmplt_newarg(void) {
    RzCore *core = fake_core_new ();
    mu_assert_notnull (core, "core should be created");
    RzLineBuffer *buf = &core->cons->line->buffer;

    char *cwd = rz_sys_getdir ();
    rz_sys_mkdir ("newarg_test");
    rz_sys_chdir ("newarg_test");
    mu_assert_true (rz_file_touch ("file0"), "");
    mu_assert_true (rz_file_touch ("file1"), "");
    mu_assert_true (rz_file_touch ("file2"), "");

    const char *s = "xd ";
    strcpy (buf->data, s);
    buf->length = strlen (s);
    buf->index = buf->length;
    RzLineNSCompletionResult *r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should not be null");
    mu_assert_eq (r->start, buf->length, "should autocomplete starting after space");
    mu_assert_eq (r->end, buf->length, "should autocomplete ending at end of buffer");
    mu_assert_eq (rz_pvector_len (&r->options), 3, "there are 3 files in newarg_test dir");
    bool found[3] = {false, false, false};
    void **it;
    rz_pvector_foreach (&r->options, it) {
        char *f = *(char **)it;
        mu_assert_true (rz_str_startswith (f, "." RZ_SYS_DIR "file"), "options start with ./file");
        int v = atoi (f + strlen ("./file"));
        found[v] = true;
    }
    mu_assert_true (found[0], "file0 found");
    mu_assert_true (found[1], "file1 found");
    mu_assert_true (found[2], "file2 found");
    rz_line_ns_completion_result_free (r);

    rz_file_rm ("file0");
    rz_file_rm ("file1");
    rz_file_rm ("file2");
    rz_file_rm ("newarg_test");
    rz_sys_chdir (cwd);
    free (cwd);

    rz_core_free (core);
    mu_end;
}

static bool test_autocmplt_fcn(void) {
    RzCore *core = fake_core_new2 ();
    mu_assert_notnull (core, "core not null");
    RzLineBuffer *buf = &core->cons->line->buffer;

    rz_core_analysis_all (core);

    const char *s = "unittest ./file2 sym.imp.s";
    strcpy (buf->data, s);
    buf->length = strlen (s);
    buf->index = buf->length;
    RzLineNSCompletionResult *r = rz_core_autocomplete_newshell (core, buf, RZ_LINE_PROMPT_DEFAULT);

    mu_assert_notnull (r, "r should not be null");
    mu_assert_eq (r->start, strlen ("unittest ./file1 "), "should autocomplete starting after space");
    mu_assert_eq (r->end, buf->length, "should autocomplete ending at end of buffer");
    mu_assert_eq (rz_pvector_len (&r->options), 3, "there are 3 functions starting with sym.imp.s");
    mu_assert_streq (rz_pvector_at (&r->options, 0), "sym.imp.strlen", "strlen");
    mu_assert_streq (rz_pvector_at (&r->options, 1), "sym.imp.strcpy", "strcpy");
    mu_assert_streq (rz_pvector_at (&r->options, 2), "sym.imp.strcat", "strcat");
    rz_line_ns_completion_result_free (r);

    rz_core_free (core);
    mu_end;
}

bool all_tests() {
	mu_run_test (test_autocmplt_cmdid);
	mu_run_test (test_autocmplt_newcommand);
	mu_run_test (test_autocmplt_argid);
	mu_run_test (test_autocmplt_quotedarg);
	mu_run_test (test_autocmplt_newarg);
	mu_run_test (test_autocmplt_fcn);
	return tests_passed != tests_run;
}

mu_main (all_tests)