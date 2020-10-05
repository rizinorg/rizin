#include <rz_cmd.h>
#include <rz_cons.h>
#include <stdlib.h>
#include "minunit.h"

bool test_parsed_args_noargs(void) {
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new ("pd", 0, NULL);
	mu_assert_streq (a->argv[0], "pd", "pd is the command");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "", "empty arguments");
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), "pd", "only command");
	rz_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_onearg(void) {
	char *args[] = {"10"};
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new ("pd", 1, args);
	mu_assert_streq (a->argv[0], "pd", "pd is the command");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "10", "one argument");
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), "pd 10", "cmd + arg");
	rz_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_args(void) {
	char *args[] = { "d", "0" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new ("wA", 2, args);
	mu_assert_streq (a->argv[0], "wA", "wA is the command");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "d 0", "two args");
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), "wA d 0", "cmd + args");
	rz_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_nospace(void) {
	char *args[] = { "dr*" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new (".", 1, args);
	a->has_space_after_cmd = false;
	mu_assert_streq (a->argv[0], ".", ". is the command");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "dr*", "arg");
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), ".dr*", "cmd + args without space");
	rz_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_newcmd(void) {
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd ("pd");
	mu_assert_streq (a->argv[0], "pd", "pd is the command");
	char *args[] = { "10" };
	bool res = rz_cmd_parsed_args_setargs (a, 1, args);
	mu_assert ("args should be added", res);
	mu_assert_eq (a->argc, 2, "argc == 2");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "10", "arg");
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), "pd 10", "cmd + args");

	char *args2[] = { "2", "3" };
	res = rz_cmd_parsed_args_setargs (a, 2, args2);
	mu_assert_eq (a->argc, 3, "argc == 3");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "2 3", "arg");
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), "pd 2 3", "cmd + args");

	rz_cmd_parsed_args_free (a);
	mu_end;
}

bool test_parsed_args_newargs(void) {
	char *args[] = { "0", "1", "2" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newargs (3, args);
	mu_assert_eq (a->argc, 4, "argc == 4");
	mu_assert_streq_free (rz_cmd_parsed_args_argstr (a), "0 1 2", "args");
	mu_assert_streq (a->argv[1], "0", "first arg");
	mu_assert_streq (a->argv[2], "1", "second arg");

	bool res = rz_cmd_parsed_args_setcmd (a, "pd");
	mu_assert ("cmd should be added", res);
	mu_assert_streq_free (rz_cmd_parsed_args_execstr (a), "pd 0 1 2", "cmd + args");
	rz_cmd_parsed_args_free (a);
	mu_end;
}

static RzCmdStatus afl_argv_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

bool test_cmd_descriptor_argv(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *cd = rz_cmd_desc_argv_new (cmd, root, "afl", afl_argv_handler, NULL);
	mu_assert_notnull (cd, "cmddesc created");
	mu_assert_streq (cd->name, "afl", "command descriptor name is afl");
	mu_assert_eq (cd->type, RZ_CMD_DESC_TYPE_ARGV, "type of command descriptor is argv");
	mu_assert_ptreq (rz_cmd_desc_parent (cd), root, "root parent descriptor");
	mu_assert_eq (root->n_children, 1, "root has 1 child");
	mu_assert_eq (cd->n_children, 0, "no children");
	rz_cmd_free (cmd);
	mu_end;
}

bool test_cmd_descriptor_argv_nested(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *af_cd = rz_cmd_desc_argv_new (cmd, root, "af", NULL, NULL);
	rz_cmd_desc_argv_new (cmd, root, "af2", NULL, NULL);
	RzCmdDesc *cd = rz_cmd_desc_argv_new (cmd, af_cd, "afl", afl_argv_handler, NULL);
	mu_assert_ptreq (rz_cmd_desc_parent (cd), af_cd, "parent of afl is af");
	mu_assert_true (rz_pvector_contains (&af_cd->children, cd), "afl is child of af");
	rz_cmd_free (cmd);
	mu_end;
}

static int a_oldinput_cb(void *user, const char *input) {
	return 0;
}

bool test_cmd_descriptor_oldinput(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *cd = rz_cmd_desc_oldinput_new (cmd, root, "a", a_oldinput_cb, NULL);
	mu_assert_notnull (cd, "cmddesc created");
	mu_assert_streq (cd->name, "a", "command descriptor name is a");
	mu_assert_eq (cd->type, RZ_CMD_DESC_TYPE_OLDINPUT, "type of command descriptor is oldinput");
	mu_assert_ptreq (rz_cmd_desc_parent (cd), root, "root parent descriptor");
	mu_assert_eq (cd->n_children, 0, "no children");
	rz_cmd_free (cmd);
	mu_end;
}

static RzCmdStatus a_exec_cb(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus ab_cb(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

bool test_cmd_descriptor_group(void) {
	const RzCmdDescHelp ab_help = { .summary = "ab help" };
	const RzCmdDescHelp a_exec_help = { .summary = "a exec help" };
	const RzCmdDescHelp a_group_help = { .summary = "a group help" };

	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *cd = rz_cmd_desc_group_new (cmd, root, "a", a_exec_cb, &a_exec_help, &a_group_help);
	rz_cmd_desc_argv_new (cmd, cd, "ab", ab_cb, &ab_help);
	mu_assert_notnull (cd, "cmddesc created");
	mu_assert_streq (cd->name, "a", "command descriptor name is a");
	mu_assert_eq (cd->type, RZ_CMD_DESC_TYPE_GROUP, "type of command descriptor is group");
	mu_assert_ptreq (rz_cmd_desc_parent (cd), root, "root parent descriptor");
	mu_assert_eq (cd->n_children, 2, "no children");
	mu_assert_true (rz_cmd_desc_has_handler (cd), "a_exec_cb is the handler for this");

	mu_assert_ptreq (rz_cmd_get_desc (cmd, "a"), cd, "cd is the desc for `a`");
	mu_assert_null (rz_cmd_get_desc (cmd, "afjb"), "nothing should be found for non-existing cmd");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd("a??");
	char *h = rz_cmd_get_help (cmd, pa, false);
	mu_assert_streq (h, "Usage: a   # a exec help\n", "detailed help for a is a_exec_help");
	rz_cmd_parsed_args_free (pa);
	free (h);

	pa = rz_cmd_parsed_args_newcmd ("a?");
	h = rz_cmd_get_help (cmd, pa, false);
	const char *exp_h = "Usage: a[b]   # a group help\n"
		"| a  # a exec help\n"
		"| ab # ab help\n";
	mu_assert_streq (h, exp_h, "regular help for a is a_group_help");
	free (h);

	rz_cmd_free (cmd);
	mu_end;
}

static RzCmdStatus ap_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus aeir_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static int ae_handler(void *user, const char *input) {
	return 0;
}

static int w_handler(void *user, const char *input) {
	return 0;
}

bool test_cmd_descriptor_tree(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *a_cd = rz_cmd_desc_argv_new (cmd, root, "a", NULL, NULL);
	rz_cmd_desc_argv_new (cmd, a_cd, "ap", ap_handler, NULL);
	rz_cmd_desc_oldinput_new (cmd, root, "w", w_handler, NULL);

	void **it_cd;
	rz_cmd_desc_children_foreach (root, it_cd) {
		RzCmdDesc *cd = *it_cd;
		mu_assert_ptreq (rz_cmd_desc_parent (cd), root, "root is the parent");
	}

	rz_cmd_free (cmd);
	mu_end;
}

bool test_cmd_get_desc(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *a_cd = rz_cmd_desc_argv_new (cmd, root, "a", NULL, NULL);
	RzCmdDesc *ap_cd = rz_cmd_desc_argv_new (cmd, a_cd, "ap", ap_handler, NULL);
	RzCmdDesc *apd_cd = rz_cmd_desc_argv_new (cmd, ap_cd, "apd", ap_handler, NULL);
	RzCmdDesc *ae_cd = rz_cmd_desc_oldinput_new (cmd, a_cd, "ae", ae_handler, NULL);
	RzCmdDesc *aeir_cd = rz_cmd_desc_argv_new (cmd, ae_cd, "aeir", aeir_handler, NULL);
	RzCmdDesc *w_cd = rz_cmd_desc_oldinput_new (cmd, root, "w", w_handler, NULL);

	mu_assert_null (rz_cmd_get_desc (cmd, "afl"), "afl does not have any handler");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "ap"), ap_cd, "ap will be handled by ap");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "wx"), w_cd, "wx will be handled by w");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "wao"), w_cd, "wao will be handled by w");
	mu_assert_null (rz_cmd_get_desc (cmd, "apx"), "apx does not have any handler");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "apd"), apd_cd, "apd will be handled by apd");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "ae"), ae_cd, "ae will be handled by ae");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "aeim"), ae_cd, "aeim will be handled by ae");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "aeir"), aeir_cd, "aeir will be handled by aeir");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "aei"), ae_cd, "aei will be handled by ae");

	rz_cmd_free (cmd);
	mu_end;
}

static RzCmdStatus pd_handler(RzCore *core, int argc, const char **argv) {
	mu_assert_eq (argc, 2, "pd_handler called with 2 arguments (name and arg)");
	mu_assert_streq (argv[0], "pd", "pd is argv[0]");
	mu_assert_streq (argv[1], "10", "10 is argv[1]");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus p_handler_argv(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static int p_handler(void *user, const char *input) {
	mu_assert_streq (input, "x 10", "input is +1");
	return -1;
}

static int px_handler(void *user, const char *input) {
	if (*input == '?') {
		rz_cons_printf ("Free format px help\n");
	}
	return 0;
}

static int wv_handler(void *user, const char *input) {
	mu_assert_streq (input, "8 0xdeadbeef", "input is +2");
	return 1;
}

static int q_handler(void *user, const char *input) {
	return -2;
}

bool test_cmd_call_desc(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_argv_new (cmd, root, "p", NULL, NULL);
	rz_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler, NULL);
	rz_cmd_desc_oldinput_new (cmd, p_cd, "p", p_handler, NULL);
	rz_cmd_desc_oldinput_new (cmd, root, "wv", wv_handler, NULL);
	rz_cmd_desc_oldinput_new (cmd, root, "q", q_handler, NULL);

	char *pd_args[] = {"10"};
	char *px_args[] = {"10"};
	char *wv8_args[] = {"0xdeadbeef"};

	RzCmdParsedArgs *a = rz_cmd_parsed_args_new ("pd", 1, pd_args);
	mu_assert_eq(rz_cmd_call_parsed_args (cmd, a), RZ_CMD_STATUS_OK, "pd was called correctly");
	rz_cmd_parsed_args_free (a);

	a = rz_cmd_parsed_args_new ("px", 1, px_args);
	mu_assert_eq(rz_cmd_call_parsed_args (cmd, a), RZ_CMD_STATUS_INVALID, "p was called correctly");
	rz_cmd_parsed_args_free (a);

	a = rz_cmd_parsed_args_new ("wv8", 1, wv8_args);
	mu_assert_eq(rz_cmd_call_parsed_args (cmd, a), RZ_CMD_STATUS_OK, "wv was called correctly");
	rz_cmd_parsed_args_free (a);

	a = rz_cmd_parsed_args_new ("quit", 0, NULL);
	mu_assert_eq (rz_cmd_call_parsed_args (cmd, a), RZ_CMD_STATUS_EXIT, "quit is going to exit");
	rz_cmd_parsed_args_free (a);

	rz_cmd_free (cmd);
	mu_end;
}

bool test_cmd_help(void) {
	const RzCmdDescHelp p_help = {
		.summary = "p summary",
		.usage = "p-usage",
		.args_str = "",
		.description = NULL,
		.examples = NULL,
	};

	const RzCmdDescExample pd_help_examples[] = {
		{ .example = "pd 10", .comment = "print 10 disassembled instructions" },
		{ 0 },
	};

	const RzCmdDescHelp pd_help = {
		.summary = "pd summary",
		.usage = NULL,
		.args_str = " <num>",
		.description = "pd long description",
		.examples = pd_help_examples,
	};

	const RzCmdDescHelp px_help = {
		.summary = "px summary",
		.usage = "px-usage",
		.args_str = " <verylongarg_str_num>",
		.description = "px long description",
		.examples = NULL,
	};

	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_argv_new (cmd, root, "p", NULL, &p_help);
	rz_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler, &pd_help);
	rz_cmd_desc_oldinput_new (cmd, p_cd, "px", px_handler, &px_help);

	const char *p_help_exp = "Usage: p-usage   # p summary\n"
		"| pd <num>                    # pd summary\n"
		"| px[?] <verylongarg_str_num> # px summary\n";
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd ("p?");
	char *h = rz_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, p_help_exp, "wrong help for p?");
	free (h);
	rz_cmd_parsed_args_free (a);

	const char *pd_help_exp = "Usage: pd <num>   # pd summary\n";
	a = rz_cmd_parsed_args_newcmd ("pd?");
	h = rz_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, pd_help_exp, "wrong help for pd?");
	free (h);
	rz_cmd_parsed_args_free (a);

	const char *pd_long_help_exp = "Usage: pd <num>   # pd summary\n"
		"\n"
		"pd long description\n"
		"\n"
		"Examples:\n"
		"| pd 10 # print 10 disassembled instructions\n";
	a = rz_cmd_parsed_args_newcmd ("pd??");
	h = rz_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, pd_long_help_exp, "wrong help for pd??");
	free (h);
	rz_cmd_parsed_args_free (a);

	rz_cmd_free (cmd);
	mu_end;
}

bool test_cmd_group_help(void) {
	const RzCmdDescHelp p_help = {
		.summary = "p summary",
		.usage = "p-usage",
		.args_str = "",
		.description = NULL,
		.examples = NULL,
	};

	const RzCmdDescHelp p_group_help = {
		.usage = "p-usage",
		.summary = "p group-summary",
		.args_str = NULL,
		.description = NULL,
		.examples = NULL,
	};

	const RzCmdDescHelp pd_help = {
		.summary = "pd summary",
		.usage = NULL,
		.args_str = " <num>",
		.description = "pd long description",
		.examples = NULL,
	};

	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new (cmd, root, "p", p_handler_argv, &p_help, &p_group_help);
	rz_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler, &pd_help);

	const char *p_help_exp = "Usage: p-usage   # p group-summary\n"
		"| p        # p summary\n"
		"| pd <num> # pd summary\n";
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd ("p?");
	char *h = rz_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, p_help_exp, "wrong help for p?");
	free (h);
	rz_cmd_parsed_args_free (a);

	rz_cmd_free (cmd);
	mu_end;
}

bool test_cmd_oldinput_help(void) {
	rz_cons_new ();

	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_argv_new (cmd, root, "p", NULL, NULL);
	rz_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler, NULL);
	rz_cmd_desc_oldinput_new (cmd, p_cd, "px", px_handler, NULL);

	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd ("px?");
	const char *px_help_exp = "Free format px help\n";
	char *h = rz_cmd_get_help (cmd, a, false);
	mu_assert_notnull (h, "help is not null");
	mu_assert_streq (h, px_help_exp, "wrong help for px?");
	free (h);
	rz_cmd_parsed_args_free (a);

	rz_cmd_free (cmd);
	rz_cons_free ();
	mu_end;
}

bool test_remove_cmd(void) {
	RzCmd *cmd = rz_cmd_new ();
	RzCmdDesc *root = rz_cmd_get_root (cmd);
	RzCmdDesc *x_cd = rz_cmd_desc_argv_new (cmd, root, "x", NULL, NULL);
	RzCmdDesc *p_cd = rz_cmd_desc_argv_new (cmd, root, "p", NULL, NULL);
	RzCmdDesc *pd_cd = rz_cmd_desc_argv_new (cmd, p_cd, "pd", pd_handler, NULL);
	rz_cmd_desc_argv_new (cmd, p_cd, "px", pd_handler, NULL);

	mu_assert_ptreq (rz_cmd_get_desc (cmd, "x"), x_cd, "x is found");
	mu_assert_ptreq (rz_cmd_get_desc (cmd, "pd"), pd_cd, "pd is found");
	mu_assert_eq (root->n_children, 2, "root has 2 commands as children");
	rz_cmd_desc_remove (cmd, p_cd);
	mu_assert_eq (root->n_children, 1, "p was removed, now root has 1 command as children");
	mu_assert_null (rz_cmd_get_desc (cmd, "p"), "p should not be found anymore");
	mu_assert_null (rz_cmd_get_desc (cmd, "pd"), "pd should not be found anymore");
	mu_assert_null (rz_cmd_get_desc (cmd, "px"), "px should not be found anymore");

	void **it_cd;
	rz_cmd_desc_children_foreach (root, it_cd) {
		RzCmdDesc *cd = *it_cd;
		mu_assert_ptrneq (cd, p_cd, "p should not be found anymore");
	}

	rz_cmd_free (cmd);
	rz_cons_free ();
	mu_end;
}

int all_tests() {
	mu_run_test (test_parsed_args_noargs);
	mu_run_test (test_parsed_args_onearg);
	mu_run_test (test_parsed_args_args);
	mu_run_test (test_parsed_args_nospace);
	mu_run_test (test_parsed_args_newcmd);
	mu_run_test (test_parsed_args_newargs);
	mu_run_test (test_cmd_descriptor_argv);
	mu_run_test (test_cmd_descriptor_argv_nested);
	mu_run_test (test_cmd_descriptor_oldinput);
	mu_run_test (test_cmd_descriptor_tree);
	mu_run_test (test_cmd_descriptor_group);
	mu_run_test (test_cmd_get_desc);
	mu_run_test (test_cmd_call_desc);
	mu_run_test (test_cmd_help);
	mu_run_test (test_cmd_group_help);
	mu_run_test (test_cmd_oldinput_help);
	mu_run_test (test_remove_cmd);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
