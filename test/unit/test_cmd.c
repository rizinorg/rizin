// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <stdlib.h>
#include "minunit.h"

static RzCmdDescArg fake_args[] = {
	{ 0 },
};

static RzCmdDescHelp fake_help = {
	.summary = "fake help",
	.args = fake_args,
};

bool test_parsed_args_noargs(void) {
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new("pd", 0, NULL);
	mu_assert_streq(a->argv[0], "pd", "pd is the command");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "", "empty arguments");
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), "pd", "only command");
	rz_cmd_parsed_args_free(a);
	mu_end;
}

bool test_parsed_args_onearg(void) {
	char *args[] = { "10" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new("pd", 1, args);
	mu_assert_streq(a->argv[0], "pd", "pd is the command");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "10", "one argument");
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), "pd 10", "cmd + arg");
	rz_cmd_parsed_args_free(a);
	mu_end;
}

bool test_parsed_args_args(void) {
	char *args[] = { "d", "0" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new("wA", 2, args);
	mu_assert_streq(a->argv[0], "wA", "wA is the command");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "d 0", "two args");
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), "wA d 0", "cmd + args");
	rz_cmd_parsed_args_free(a);
	mu_end;
}

bool test_parsed_args_nospace(void) {
	char *args[] = { "dr*" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_new(".", 1, args);
	a->has_space_after_cmd = false;
	mu_assert_streq(a->argv[0], ".", ". is the command");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "dr*", "arg");
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), ".dr*", "cmd + args without space");
	rz_cmd_parsed_args_free(a);
	mu_end;
}

bool test_parsed_args_newcmd(void) {
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd("pd");
	mu_assert_streq(a->argv[0], "pd", "pd is the command");
	char *args[] = { "10" };
	bool res = rz_cmd_parsed_args_setargs(a, 1, args);
	mu_assert("args should be added", res);
	mu_assert_eq(a->argc, 2, "argc == 2");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "10", "arg");
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), "pd 10", "cmd + args");

	char *args2[] = { "2", "3" };
	rz_cmd_parsed_args_setargs(a, 2, args2);
	mu_assert_eq(a->argc, 3, "argc == 3");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "2 3", "arg");
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), "pd 2 3", "cmd + args");

	rz_cmd_parsed_args_free(a);
	mu_end;
}

bool test_parsed_args_newargs(void) {
	char *args[] = { "0", "1", "2" };
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newargs(3, args);
	mu_assert_eq(a->argc, 4, "argc == 4");
	mu_assert_streq_free(rz_cmd_parsed_args_argstr(a), "0 1 2", "args");
	mu_assert_streq(a->argv[1], "0", "first arg");
	mu_assert_streq(a->argv[2], "1", "second arg");

	bool res = rz_cmd_parsed_args_setcmd(a, "pd");
	mu_assert("cmd should be added", res);
	mu_assert_streq_free(rz_cmd_parsed_args_execstr(a), "pd 0 1 2", "cmd + args");
	rz_cmd_parsed_args_free(a);
	mu_end;
}

static RzCmdStatus afl_argv_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

bool test_cmd_descriptor_argv(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *cd = rz_cmd_desc_argv_new(cmd, root, "afl", afl_argv_handler, &fake_help);
	mu_assert_notnull(cd, "cmddesc created");
	mu_assert_streq(cd->name, "afl", "command descriptor name is afl");
	mu_assert_eq(cd->type, RZ_CMD_DESC_TYPE_ARGV, "type of command descriptor is argv");
	mu_assert_ptreq(rz_cmd_desc_parent(cd), root, "root parent descriptor");
	mu_assert_eq(root->n_children, 1, "root has 1 children");
	mu_assert_eq(cd->n_children, 0, "no children");
	rz_cmd_free(cmd);
	mu_end;
}

bool test_cmd_descriptor_argv_nested(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *af_cd = rz_cmd_desc_group_new(cmd, root, "af", NULL, NULL, &fake_help);
	rz_cmd_desc_argv_new(cmd, root, "af2", NULL, &fake_help);
	RzCmdDesc *cd = rz_cmd_desc_argv_new(cmd, af_cd, "afl", afl_argv_handler, &fake_help);
	mu_assert_ptreq(rz_cmd_desc_parent(cd), af_cd, "parent of afl is af");
	mu_assert_true(rz_pvector_contains(&af_cd->children, cd), "afl is child of af");
	rz_cmd_free(cmd);
	mu_end;
}

static int a_oldinput_cb(void *user, const char *input) {
	return 0;
}

bool test_cmd_descriptor_oldinput(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *cd = rz_cmd_desc_oldinput_new(cmd, root, "a", a_oldinput_cb, NULL);
	mu_assert_notnull(cd, "cmddesc created");
	mu_assert_streq(cd->name, "a", "command descriptor name is a");
	mu_assert_eq(cd->type, RZ_CMD_DESC_TYPE_OLDINPUT, "type of command descriptor is oldinput");
	mu_assert_ptreq(rz_cmd_desc_parent(cd), root, "root parent descriptor");
	mu_assert_eq(cd->n_children, 0, "no children");
	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus a_exec_cb(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus ab_cb(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

bool test_cmd_descriptor_group(void) {
	const RzCmdDescHelp ab_help = { .summary = "ab help", .args = fake_args };
	const RzCmdDescHelp a_exec_help = { .summary = "a exec help", .args = fake_args };
	const RzCmdDescHelp a_group_help = { .summary = "a group help" };

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *cd = rz_cmd_desc_group_new(cmd, root, "a", a_exec_cb, &a_exec_help, &a_group_help);
	rz_cmd_desc_argv_new(cmd, cd, "ab", ab_cb, &ab_help);
	mu_assert_notnull(cd, "cmddesc created");
	mu_assert_streq(cd->name, "a", "command descriptor name is a");
	mu_assert_eq(cd->type, RZ_CMD_DESC_TYPE_GROUP, "type of command descriptor is group");
	mu_assert_ptreq(rz_cmd_desc_parent(cd), root, "root parent descriptor");
	mu_assert_eq(cd->n_children, 2, "no children");
	mu_assert_true(rz_cmd_desc_has_handler(cd), "a_exec_cb is the handler for this");

	mu_assert_ptreq(rz_cmd_get_desc(cmd, "a"), cd, "cd is the desc for `a`");
	mu_assert_null(rz_cmd_get_desc(cmd, "afjb"), "nothing should be found for non-existing cmd");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd("a??");
	char *h = rz_cmd_get_help(cmd, pa, false);
	mu_assert_streq(h, "Usage: a   # a exec help\n", "detailed help for a is a_exec_help");
	rz_cmd_parsed_args_free(pa);
	free(h);

	pa = rz_cmd_parsed_args_newcmd("a?");
	h = rz_cmd_get_help(cmd, pa, false);
	const char *exp_h = "Usage: a[b]   # a group help\n"
			    "| a  # a exec help\n"
			    "| ab # ab help\n";
	mu_assert_streq(h, exp_h, "regular help for a is a_group_help");
	rz_cmd_parsed_args_free(pa);
	free(h);

	rz_cmd_free(cmd);
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
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *a_cd = rz_cmd_desc_group_new(cmd, root, "a", NULL, NULL, &fake_help);
	rz_cmd_desc_argv_new(cmd, a_cd, "ap", ap_handler, &fake_help);
	rz_cmd_desc_oldinput_new(cmd, root, "w", w_handler, NULL);

	void **it_cd;
	rz_cmd_desc_children_foreach(root, it_cd) {
		RzCmdDesc *cd = *it_cd;
		mu_assert_ptreq(rz_cmd_desc_parent(cd), root, "root is the parent");
	}

	rz_cmd_free(cmd);
	mu_end;
}

bool test_cmd_get_desc(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *a_cd = rz_cmd_desc_group_new(cmd, root, "a", NULL, NULL, &fake_help);
	RzCmdDesc *ap_cd = rz_cmd_desc_group_new(cmd, a_cd, "ap", ap_handler, NULL, &fake_help);
	RzCmdDesc *apd_cd = rz_cmd_desc_argv_new(cmd, ap_cd, "apd", ap_handler, &fake_help);
	RzCmdDesc *ae_cd = rz_cmd_desc_oldinput_new(cmd, a_cd, "ae", ae_handler, NULL);
	RzCmdDesc *aeir_cd = rz_cmd_desc_argv_new(cmd, ae_cd, "aeir", aeir_handler, &fake_help);
	RzCmdDesc *w_cd = rz_cmd_desc_oldinput_new(cmd, root, "w", w_handler, NULL);

	mu_assert_null(rz_cmd_get_desc(cmd, "afl"), "afl does not have any handler");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "ap"), ap_cd, "ap will be handled by ap");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "wx"), w_cd, "wx will be handled by w");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "wao"), w_cd, "wao will be handled by w");
	mu_assert_null(rz_cmd_get_desc(cmd, "apx"), "apx does not have any handler");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "apd"), apd_cd, "apd will be handled by apd");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "ae"), ae_cd, "ae will be handled by ae");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "aeim"), ae_cd, "aeim will be handled by ae");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "aeir"), aeir_cd, "aeir will be handled by aeir");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "aei"), ae_cd, "aei will be handled by ae");

	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus pd_handler(RzCore *core, int argc, const char **argv) {
	mu_assert_eq(argc, 2, "pd_handler called with 2 arguments (name and arg)");
	mu_assert_streq(argv[0], "pd", "pd is argv[0]");
	mu_assert_streq(argv[1], "10", "10 is argv[1]");
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus p_handler_argv(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static int p_handler(void *user, const char *input) {
	mu_assert_streq(input, "x 10", "input is +1");
	return -1;
}

static int px_handler(void *user, const char *input) {
	if (*input == '?') {
		rz_cons_printf("Free format px help\n");
	}
	return 0;
}

static int wv_handler(void *user, const char *input) {
	mu_assert_streq(input, "8 0xdeadbeef", "input is +2");
	return 1;
}

static int q_handler(void *user, const char *input) {
	return -2;
}

bool test_cmd_call_desc(void) {
	RzCmdDescArg pd_help_args[] = {
		{ .name = "n1", .type = RZ_CMD_ARG_TYPE_NUM },
		{ 0 },
	};
	RzCmdDescHelp pd_help = {
		.args = pd_help_args,
	};

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", NULL, NULL, &fake_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pd", pd_handler, &pd_help);
	rz_cmd_desc_oldinput_new(cmd, p_cd, "p", p_handler, NULL);
	rz_cmd_desc_oldinput_new(cmd, root, "wv", wv_handler, NULL);
	rz_cmd_desc_oldinput_new(cmd, root, "q", q_handler, NULL);

	char *pd_args[] = { "10" };
	char *px_args[] = { "10" };
	char *wv8_args[] = { "0xdeadbeef" };

	RzCmdParsedArgs *a = rz_cmd_parsed_args_new("pd", 1, pd_args);
	mu_assert_eq(rz_cmd_call_parsed_args(cmd, a), RZ_CMD_STATUS_OK, "pd was called correctly");
	rz_cmd_parsed_args_free(a);

	a = rz_cmd_parsed_args_new("px", 1, px_args);
	mu_assert_eq(rz_cmd_call_parsed_args(cmd, a), RZ_CMD_STATUS_NONEXISTINGCMD, "px was not called because it does not exist");
	rz_cmd_parsed_args_free(a);

	a = rz_cmd_parsed_args_new("wv8", 1, wv8_args);
	mu_assert_eq(rz_cmd_call_parsed_args(cmd, a), RZ_CMD_STATUS_OK, "wv was called correctly");
	rz_cmd_parsed_args_free(a);

	a = rz_cmd_parsed_args_new("quit", 0, NULL);
	mu_assert_eq(rz_cmd_call_parsed_args(cmd, a), RZ_CMD_STATUS_EXIT, "quit is going to exit");
	rz_cmd_parsed_args_free(a);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_cmd_help(void) {
	const RzCmdDescHelp p_group_help = {
		.summary = "p summary",
		.usage = "p-usage",
		.args_str = "",
		.description = NULL,
		.details = NULL,
	};

	const RzCmdDescDetailEntry pd_help_examples[] = {
		{ .text = "pd 10", .comment = "print 10 disassembled instructions" },
		{ 0 },
	};

	const RzCmdDescDetail pd_help_details[] = {
		{ .name = "Examples", .entries = pd_help_examples },
		{ 0 },
	};

	const RzCmdDescHelp pd_help = {
		.summary = "pd summary",
		.usage = NULL,
		.args_str = " <num>",
		.description = "pd long description",
		.details = pd_help_details,
		.args = fake_args,
	};

	const RzCmdDescHelp px_help = {
		.summary = "px summary",
		.usage = "px-usage",
		.args_str = " <verylongarg_str_num>",
		.description = "px long description",
		.details = NULL,
		.args = fake_args,
	};

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", NULL, NULL, &p_group_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pd", pd_handler, &pd_help);
	rz_cmd_desc_oldinput_new(cmd, p_cd, "px", px_handler, &px_help);

	const char *p_help_exp = "Usage: p-usage   # p summary\n"
				 "| pd <num>                    # pd summary\n"
				 "| px[?] <verylongarg_str_num> # px summary\n";
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd("p?");
	char *h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, p_help_exp, "wrong help for p?");
	free(h);
	rz_cmd_parsed_args_free(a);

	const char *pd_long_help_exp = "Usage: pd <num>   # pd summary\n"
				       "\n"
				       "pd long description\n"
				       "\n"
				       "Examples:\n"
				       "| pd 10 # print 10 disassembled instructions\n";
	a = rz_cmd_parsed_args_newcmd("pd??");
	h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, pd_long_help_exp, "wrong help for pd??");
	free(h);
	rz_cmd_parsed_args_free(a);

	a = rz_cmd_parsed_args_newcmd("pd?");
	h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, pd_long_help_exp, "wrong help for pd?");
	free(h);
	rz_cmd_parsed_args_free(a);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_cmd_group_help(void) {
	const RzCmdDescHelp p_help = {
		.summary = "p summary",
		.usage = "p-usage",
		.description = NULL,
		.details = NULL,
		.args = fake_args,
	};

	const RzCmdDescHelp p_group_help = {
		.usage = "p-usage",
		.summary = "p group-summary",
		.args_str = NULL,
		.description = NULL,
		.details = NULL,
	};

	const RzCmdDescHelp pd_help = {
		.summary = "pd summary",
		.usage = NULL,
		.args_str = " <num>",
		.description = "pd long description",
		.details = NULL,
		.args = fake_args,
	};

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", p_handler_argv, &p_help, &p_group_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pd", pd_handler, &pd_help);

	const char *p_help_exp = "Usage: p-usage   # p group-summary\n"
				 "| p        # p summary\n"
				 "| pd <num> # pd summary\n";
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd("p?");
	char *h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, p_help_exp, "wrong help for p?");
	free(h);
	rz_cmd_parsed_args_free(a);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_cmd_oldinput_help(void) {
	rz_cons_new();

	RzCmd *cmd = rz_cmd_new(NULL, true);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", NULL, NULL, &fake_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pd", pd_handler, &fake_help);
	rz_cmd_desc_oldinput_new(cmd, p_cd, "px", px_handler, NULL);

	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd("px?");
	const char *px_help_exp = "Free format px help\n";
	char *h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, px_help_exp, "wrong help for px?");
	free(h);
	rz_cmd_parsed_args_free(a);

	rz_cmd_free(cmd);
	rz_cons_free();
	mu_end;
}

bool test_cmd_group_exec_help(void) {
	const RzCmdDescHelp p_help = {
		.summary = "p summary",
		.usage = "p-usage",
		.description = "This is p-command description",
		.details = NULL,
		.args = fake_args,
	};

	const RzCmdDescHelp p_group_help = {
		.usage = "p-usage",
		.summary = "p group-summary",
		.args_str = NULL,
		.description = NULL,
		.details = NULL,
	};

	const RzCmdDescHelp pd_help = {
		.summary = "pd summary",
		.usage = NULL,
		.args_str = " <num>",
		.description = "pd long description",
		.details = NULL,
		.args = fake_args,
	};

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", p_handler_argv, &p_help, &p_group_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pd", pd_handler, &pd_help);

	const char *p_group_help_exp = "Usage: p-usage   # p group-summary\n"
				       "| p        # p summary\n"
				       "| pd <num> # pd summary\n";
	RzCmdParsedArgs *a = rz_cmd_parsed_args_newcmd("p?");
	char *h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, p_group_help_exp, "wrong help for p?");
	free(h);
	rz_cmd_parsed_args_free(a);

	const char *p_help_exp = "Usage: p-usage   # p summary\n"
				 "\n"
				 "This is p-command description\n";
	a = rz_cmd_parsed_args_newcmd("p??");
	h = rz_cmd_get_help(cmd, a, false);
	mu_assert_notnull(h, "help is not null");
	mu_assert_streq(h, p_help_exp, "wrong help for p??");
	free(h);
	rz_cmd_parsed_args_free(a);

	const char *pd_help_exp = "Usage: pd <num>   # pd summary\n"
				  "\n"
				  "pd long description\n";
	a = rz_cmd_parsed_args_newcmd("pd?");
	char *h1 = rz_cmd_get_help(cmd, a, false);
	rz_cmd_parsed_args_free(a);
	a = rz_cmd_parsed_args_newcmd("pd??");
	char *h2 = rz_cmd_get_help(cmd, a, false);
	rz_cmd_parsed_args_free(a);
	mu_assert_streq(h1, h2, "pd? should be the same as pd?? because it is a terminal command");
	mu_assert_streq(h1, pd_help_exp, "pd?/pd?? should print full help");
	free(h1);
	free(h2);

	rz_cmd_free(cmd);
	mu_end;
}
bool test_remove_cmd(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *x_cd = rz_cmd_desc_argv_new(cmd, root, "x", NULL, &fake_help);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", NULL, NULL, &fake_help);
	RzCmdDesc *pd_cd = rz_cmd_desc_argv_new(cmd, p_cd, "pd", pd_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "px", pd_handler, &fake_help);

	mu_assert_ptreq(rz_cmd_get_desc(cmd, "x"), x_cd, "x is found");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "pd"), pd_cd, "pd is found");
	mu_assert_eq(root->n_children, 2, "root has 2 commands as children");
	rz_cmd_desc_remove(cmd, p_cd);
	mu_assert_eq(root->n_children, 1, "p was removed, now root has 1 command as children");
	mu_assert_null(rz_cmd_get_desc(cmd, "p"), "p should not be found anymore");
	mu_assert_null(rz_cmd_get_desc(cmd, "pd"), "pd should not be found anymore");
	mu_assert_null(rz_cmd_get_desc(cmd, "px"), "px should not be found anymore");

	void **it_cd;
	rz_cmd_desc_children_foreach(root, it_cd) {
		RzCmdDesc *cd = *it_cd;
		mu_assert_ptrneq(cd, p_cd, "p should not be found anymore");
	}

	rz_cmd_free(cmd);
	mu_end;
}

bool test_cmd_args(void) {
	const char *x_c_choices[] = { "A", "B", "C" };
	RzCmdDescArg x_args[] = {
		{ .name = "c", .type = RZ_CMD_ARG_TYPE_CHOICES, .choices.choices = x_c_choices },
		{ .name = "from", .optional = true, .type = RZ_CMD_ARG_TYPE_NUM },
		{ .name = "to", .type = RZ_CMD_ARG_TYPE_NUM },
		{ .name = "n", .optional = true, .type = RZ_CMD_ARG_TYPE_NUM, .default_value = "5" },
		{ 0 },
	};
	RzCmdDescHelp x_help = { 0 };
	x_help.summary = "x summary";
	x_help.args = x_args;

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *x_cd = rz_cmd_desc_argv_new(cmd, root, "x", NULL, &x_help);

	mu_assert_ptreq(rz_cmd_get_desc(cmd, "x"), x_cd, "x is found");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd("x??");
	char *h = rz_cmd_get_help(cmd, pa, false);
	mu_assert_streq(h, "Usage: x <c> [<from> <to> [<n>=5]]   # x summary\n", "arguments are considered");
	rz_cmd_parsed_args_free(pa);
	free(h);

	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus z_modes_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return RZ_CMD_STATUS_OK;
}

bool test_cmd_argv_modes(void) {
	RzCmdDescArg z_args[] = { { 0 } };
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_argv_modes_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_LONG_JSON, z_modes_handler, &z_help);

	mu_assert_ptreq(rz_cmd_get_desc(cmd, "z"), z_cd, "z is found");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zj"), z_cd, "zj is handled by z");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zq"), z_cd, "zq is handled by z");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zJ"), z_cd, "zJ is handled by z");
	mu_assert_null(rz_cmd_get_desc(cmd, "z*"), "z* was not defined");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd("?");
	char *h = rz_cmd_get_help(cmd, pa, false);
	char *exp_h = "Usage: [.][times][cmd][~grep][@[@iter]addr][|>pipe] ; ...\n"
		      "| z[jqJ] # z summary\n";
	mu_assert_streq(h, exp_h, "zj, zJ and zq are considered in the help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	exp_h = "Usage: z[jqJ]   # z summary\n"
		"| z       # z summary\n"
		"| zj      # z summary (JSON mode)\n"
		"| zq      # z summary (quiet mode)\n"
		"| zJ      # z summary (verbose JSON mode)\n";
	pa = rz_cmd_parsed_args_newcmd("z?");
	h = rz_cmd_get_help(cmd, pa, false);
	mu_assert_streq(h, exp_h, "zj, zJ and zq are considered in the sub help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	pa = rz_cmd_parsed_args_newcmd("z??");
	h = rz_cmd_get_help(cmd, pa, false);
	mu_assert_streq(h, exp_h, "zj, zJ and zq are considered in the sub help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus z_state_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		return !!state->d.pj ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_ERROR;
}

bool test_cmd_argv_state(void) {
	RzCmdDescHelp group_help = { 0 };
	group_help.summary = "group summary";

	RzCmdDescArg z_args[] = { { 0 } };
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_group_state_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_LONG_JSON, z_state_handler, &z_help, &group_help);

	mu_assert_ptreq(rz_cmd_get_desc(cmd, "z"), z_cd, "z is found");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zj"), z_cd, "zj is handled by z");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zq"), z_cd, "zq is handled by z");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zJ"), z_cd, "zJ is handled by z");
	mu_assert_null(rz_cmd_get_desc(cmd, "z*"), "z* was not defined");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd("?");
	char *h = rz_cmd_get_help(cmd, pa, false);
	char *exp_h = "Usage: [.][times][cmd][~grep][@[@iter]addr][|>pipe] ; ...\n"
		      "| z[jqJ] # group summary\n";
	mu_assert_streq(h, exp_h, "zj, zJ and zq are considered in the help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	pa = rz_cmd_parsed_args_newcmd("z?");
	h = rz_cmd_get_help(cmd, pa, false);
	exp_h = "Usage: z[jqJ]   # group summary\n"
		"| z[jqJ] # z summary\n";
	mu_assert_streq(h, exp_h, "zj, zJ and zq are considered in the sub help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	pa = rz_cmd_parsed_args_new("zj", 0, NULL);
	RzCmdStatus status = rz_cmd_call_parsed_args(cmd, pa);
	rz_cmd_parsed_args_free(pa);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "json mode was used and pj was initialized");

	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus zd_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

bool test_cmd_group_argv_modes(void) {
	RzCmdDescArg z_args[] = { { 0 } };
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;
	RzCmdDescHelp z_group_help = { 0 };
	z_group_help.summary = "z group summary";

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_group_modes_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET, z_modes_handler, &z_help, &z_group_help);
	RzCmdDesc *zd_cd = rz_cmd_desc_argv_new(cmd, z_cd, "zd", zd_handler, &fake_help);

	mu_assert_ptreq(rz_cmd_get_desc(cmd, "z"), z_cd, "z is found");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zj"), z_cd, "zj is handled by z");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zq"), z_cd, "zq is handled by z");
	mu_assert_null(rz_cmd_get_desc(cmd, "z*"), "z* was not defined");
	mu_assert_ptreq(rz_cmd_get_desc(cmd, "zd"), zd_cd, "zd is handled by zd");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd("?");
	char *h = rz_cmd_get_help(cmd, pa, false);
	char *exp_h = "Usage: [.][times][cmd][~grep][@[@iter]addr][|>pipe] ; ...\n"
		      "| z[jqd] # z group summary\n";
	mu_assert_streq(h, exp_h, "zd is considered in the help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	pa = rz_cmd_parsed_args_newcmd("z?");
	h = rz_cmd_get_help(cmd, pa, false);
	exp_h = "Usage: z[jqd]   # z group summary\n"
		"| z[jq] # z summary\n"
		"| zd    # fake help\n";
	mu_assert_streq(h, exp_h, "zj/zq and zd are considered in the sub help");
	free(h);
	rz_cmd_parsed_args_free(pa);

	rz_cmd_free(cmd);
	mu_end;
}

static bool foreach_cmdname_cb(RzCmd *cmd, const RzCmdDesc *desc, void *user) {
	rz_list_append((RzList *)user, strdup(desc->name));
	return true;
}

bool test_foreach_cmdname(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_group_modes_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET, z_modes_handler, &fake_help, &fake_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zd", zd_handler, &fake_help);
	rz_cmd_desc_argv_modes_new(cmd, z_cd, "zs", RZ_OUTPUT_MODE_QUIET, z_modes_handler, &fake_help);
	rz_cmd_desc_fake_new(cmd, root, "x", &fake_help);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", NULL, NULL, &fake_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pi", zd_handler, &fake_help);
	RzCmdDesc *v_cd = rz_cmd_desc_oldinput_new(cmd, root, "v", a_oldinput_cb, &fake_help);
	RzCmdDesc *v_inner_cd = rz_cmd_desc_inner_new(cmd, v_cd, "v", &fake_help);
	rz_cmd_desc_argv_new(cmd, v_inner_cd, "v1", zd_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, v_inner_cd, "v2", zd_handler, &fake_help);

	RzList *res = rz_list_newf(free);
	rz_cmd_foreach_cmdname(cmd, NULL, foreach_cmdname_cb, res);

	const char *exp_regular[] = { "z", "zj", "zq", "zd", "zsq", "pi", "v", "v1", "v2" };
	mu_assert_eq(rz_list_length(res), RZ_ARRAY_SIZE(exp_regular), "count regular commands that can be executed");

	RzList *exp_regular_l = rz_list_new_from_array((const void **)exp_regular, RZ_ARRAY_SIZE(exp_regular));
	rz_list_sort(exp_regular_l, (RzListComparator)strcmp, NULL);
	rz_list_sort(res, (RzListComparator)strcmp, NULL);

	RzListIter *it;
	char *s;
	size_t i = 0;
	rz_list_foreach (exp_regular_l, it, s) {
		RzStrBuf sb;
		rz_strbuf_initf(&sb, "check command `%s`", s);
		mu_assert_streq(rz_list_get_n(res, i++), s, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
	}

	rz_list_free(res);
	rz_list_free(exp_regular_l);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_foreach_cmdname_begin(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_group_modes_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET, z_modes_handler, &fake_help, &fake_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zd", zd_handler, &fake_help);
	rz_cmd_desc_argv_modes_new(cmd, z_cd, "zs", RZ_OUTPUT_MODE_QUIET, z_modes_handler, &fake_help);
	rz_cmd_desc_fake_new(cmd, root, "x", &fake_help);
	RzCmdDesc *p_cd = rz_cmd_desc_group_new(cmd, root, "p", NULL, NULL, &fake_help);
	rz_cmd_desc_argv_new(cmd, p_cd, "pi", zd_handler, &fake_help);
	RzCmdDesc *v_cd = rz_cmd_desc_oldinput_new(cmd, root, "v", a_oldinput_cb, &fake_help);
	RzCmdDesc *v_inner_cd = rz_cmd_desc_inner_new(cmd, v_cd, "v", &fake_help);
	rz_cmd_desc_argv_new(cmd, v_inner_cd, "v1", zd_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, v_inner_cd, "v2", zd_handler, &fake_help);

	RzList *res = rz_list_newf(free);
	rz_cmd_foreach_cmdname(cmd, v_cd, foreach_cmdname_cb, res);

	const char *exp_regular[] = { "v", "v1", "v2" };
	mu_assert_eq(rz_list_length(res), RZ_ARRAY_SIZE(exp_regular), "count regular commands that can be executed");

	RzList *exp_regular_l = rz_list_new_from_array((const void **)exp_regular, RZ_ARRAY_SIZE(exp_regular));
	rz_list_sort(exp_regular_l, (RzListComparator)strcmp, NULL);
	rz_list_sort(res, (RzListComparator)strcmp, NULL);

	RzListIter *it;
	char *s;
	size_t i = 0;
	rz_list_foreach (exp_regular_l, it, s) {
		RzStrBuf sb;
		rz_strbuf_initf(&sb, "check command `%s`", s);
		mu_assert_streq(rz_list_get_n(res, i++), s, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
	}

	rz_list_free(res);
	rz_list_free(exp_regular_l);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_arg_escaping(void) {
	mu_assert_streq_free(rz_cmd_escape_arg("hello", RZ_CMD_ESCAPE_ONE_ARG), "hello", "regular string remains the same");
	mu_assert_streq_free(rz_cmd_escape_arg("hello world", RZ_CMD_ESCAPE_ONE_ARG), "hello\\ world", "spaces are escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello $(world)", RZ_CMD_ESCAPE_ONE_ARG), "hello\\ \\$\\(world\\)", "$ is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello `world`", RZ_CMD_ESCAPE_ONE_ARG), "hello\\ \\`world\\`", "` is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello\"world\"", RZ_CMD_ESCAPE_ONE_ARG), "hello\\\"world\\\"", "\" is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello>world", RZ_CMD_ESCAPE_ONE_ARG), "hello\\>world", "> is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello|world", RZ_CMD_ESCAPE_ONE_ARG), "hello\\|world", "| is escaped");

	mu_assert_streq_free(rz_cmd_unescape_arg("hello", RZ_CMD_ESCAPE_ONE_ARG), "hello", "regular string remains the same");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\ world", RZ_CMD_ESCAPE_ONE_ARG), "hello world", "spaces are unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello \\$\\(world\\)", RZ_CMD_ESCAPE_ONE_ARG), "hello $(world)", "$ is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello \\`world\\`", RZ_CMD_ESCAPE_ONE_ARG), "hello `world`", "` is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\\"world\\\"", RZ_CMD_ESCAPE_ONE_ARG), "hello\"world\"", "\" is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\>world", RZ_CMD_ESCAPE_ONE_ARG), "hello>world", "> is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\|world", RZ_CMD_ESCAPE_ONE_ARG), "hello|world", "| is unescaped");

	mu_assert_streq_free(rz_cmd_escape_arg("hello `world`", RZ_CMD_ESCAPE_MULTI_ARG), "hello \\`world\\`", "` is escaped");
	mu_end;
}

bool test_double_quoted_arg_escaping(void) {
	mu_assert_streq_free(rz_cmd_escape_arg("hello", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello", "regular string remains the same");
	mu_assert_streq_free(rz_cmd_escape_arg("hello world", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello world", "spaces are not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello\"world\"", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello\\\"world\\\"", "\" is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello'world'", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello'world'", "' is not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello|world", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello|world", "| is not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello>world", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello>world", "> is not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello@world", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello@world", "@ is not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello $(world)", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello \\$\\(world\\)", "$ is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello `world`", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello \\`world\\`", "` is escaped");

	mu_assert_streq_free(rz_cmd_unescape_arg("hello", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello", "regular string remains the same");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello world", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello world", "spaces are not escaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\\"world\\\"", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello\"world\"", "\" is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\'world\\'", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello\\'world\\'", "' is not unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello \\$\\(world\\)", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello $(world)", "$ is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello \\`world\\`", RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG), "hello `world`", "` is unescaped");
	mu_end;
}

bool test_single_quoted_arg_escaping(void) {
	mu_assert_streq_free(rz_cmd_escape_arg("hello", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello", "regular string remains the same");
	mu_assert_streq_free(rz_cmd_escape_arg("hello world", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello world", "spaces are not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello\"world\"", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello\"world\"", "\" is not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello'world'", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello\\'world\\'", "' is escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello|@>world", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello|@>world", "|@> are not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello $(world)", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello $(world)", "$ is not escaped");
	mu_assert_streq_free(rz_cmd_escape_arg("hello `world`", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello `world`", "` is not escaped");

	mu_assert_streq_free(rz_cmd_unescape_arg("hello", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello", "regular string remains the same");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello world", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello world", "spaces are not escaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\\"world\\\"", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello\\\"world\\\"", "\" is not unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello\\'world\\'", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello'world'", "' is unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello \\$\\(world\\)", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello \\$\\(world\\)", "$ is not unescaped");
	mu_assert_streq_free(rz_cmd_unescape_arg("hello \\`world\\`", RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG), "hello \\`world\\`", "` is not unescaped");
	mu_end;
}

static RzCmdStatus z_last_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 2) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (strcmp(argv[1], "o file 10 rwx")) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus x_array_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (strcmp(argv[1], "s1")) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (strcmp(argv[2], "s2")) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (strcmp(argv[3], "s3")) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

bool test_arg_flags(void) {
	RzCmdDescArg z_args[] = {
		{ .name = "cmdlast", .type = RZ_CMD_ARG_TYPE_CMD, .flags = RZ_CMD_ARG_FLAG_LAST },
		{ 0 }
	};
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;
	RzCmdDescArg x_args[] = {
		{ .name = "strarr", .type = RZ_CMD_ARG_TYPE_STRING, .flags = RZ_CMD_ARG_FLAG_ARRAY },
		{ 0 }
	};
	RzCmdDescHelp x_help = { 0 };
	x_help.summary = "x summary";
	x_help.args = x_args;
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	rz_cmd_desc_argv_new(cmd, root, "z", z_last_handler, &z_help);
	rz_cmd_desc_argv_new(cmd, root, "x", x_array_handler, &x_help);

	char *z_prargs[] = { "o", "file", "10", "rwx" };
	RzCmdParsedArgs *pra = rz_cmd_parsed_args_new("z", 4, z_prargs);
	RzCmdStatus act = rz_cmd_call_parsed_args(cmd, pra);
	mu_assert_eq(act, RZ_CMD_STATUS_OK, "z was called correctly");
	rz_cmd_parsed_args_free(pra);

	char *x_prargs[] = { "s1", "s2", "s3" };
	pra = rz_cmd_parsed_args_new("x", 3, x_prargs);
	act = rz_cmd_call_parsed_args(cmd, pra);
	mu_assert_eq(act, RZ_CMD_STATUS_OK, "x was called correctly");
	rz_cmd_parsed_args_free(pra);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_get_arg(void) {
	RzCmdDescArg z_args[] = {
		{ .name = "a1", .type = RZ_CMD_ARG_TYPE_STRING },
		{ .name = "a2", .type = RZ_CMD_ARG_TYPE_CMD, .flags = RZ_CMD_ARG_FLAG_LAST },
		{ 0 }
	};
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;
	RzCmdDescArg x_args[] = {
		{ .name = "b1", .type = RZ_CMD_ARG_TYPE_STRING },
		{ .name = "b2", .type = RZ_CMD_ARG_TYPE_STRING },
		{ .name = "b3", .type = RZ_CMD_ARG_TYPE_STRING },
		{ 0 }
	};
	RzCmdDescHelp x_help = { 0 };
	x_help.summary = "x summary";
	x_help.args = x_args;
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_argv_new(cmd, root, "z", z_last_handler, &z_help);
	RzCmdDesc *x_cd = rz_cmd_desc_argv_new(cmd, root, "x", x_array_handler, &x_help);

	const RzCmdDescArg *a1 = rz_cmd_desc_get_arg(z_cd, 0);
	mu_assert_streq(a1->name, "a1", "0th arg of z is a1");
	const RzCmdDescArg *a2 = rz_cmd_desc_get_arg(z_cd, 1);
	mu_assert_streq(a2->name, "a2", "1th arg of z is a2");
	const RzCmdDescArg *an = rz_cmd_desc_get_arg(z_cd, 10);
	mu_assert_streq(an->name, "a2", "10th arg of z is a2");

	const RzCmdDescArg *b1 = rz_cmd_desc_get_arg(x_cd, 0);
	mu_assert_streq(b1->name, "b1", "0th arg of x is b1");
	const RzCmdDescArg *b2 = rz_cmd_desc_get_arg(x_cd, 1);
	mu_assert_streq(b2->name, "b2", "1th arg of x is b2");
	const RzCmdDescArg *bn = rz_cmd_desc_get_arg(x_cd, 10);
	mu_assert_null(bn, "10th arg of x does not exist");

	rz_cmd_free(cmd);
	mu_end;
}

bool test_parent_details(void) {
	const RzCmdDescDetailEntry z_help_examples[] = {
		{ .text = "z", .comment = "comment" },
		{ 0 },
	};
	const RzCmdDescDetail z_help_details[] = {
		{ .name = "Examples", .entries = z_help_examples },
		{ 0 },
	};

	RzCmdDescHelp z_group_help = { 0 };
	z_group_help.summary = "z summary";
	z_group_help.details = z_help_details;
	RzCmdDescArg zx_args[] = {
		{ 0 }
	};
	RzCmdDescHelp zx_help = { 0 };
	zx_help.summary = "x summary";
	zx_help.args = zx_args;
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_group_new(cmd, root, "z", NULL, NULL, &z_group_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zx", x_array_handler, &zx_help);

	RzCmdParsedArgs *args = rz_cmd_parsed_args_new("zx??", 0, NULL);
	char *h = rz_cmd_get_help(cmd, args, false);
	mu_assert_strcontains(h, "Examples", "zx help should include examples from parent z");
	mu_assert_strcontains(h, "comment", "zx help should include examples from parent z");
	free(h);
	rz_cmd_parsed_args_free(args);

	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus default_value_handler(RzCore *core, int argc, const char **argv) {
	mu_assert_eq(argc, 2, "An argument should always be passed to this handler");
	return !strcmp(argv[1], "default") ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

bool test_default_value(void) {
	RzCmdDescArg z_args[] = {
		{ .name = "a1", .type = RZ_CMD_ARG_TYPE_STRING, .default_value = "default" },
		{ 0 }
	};
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	rz_cmd_desc_argv_new(cmd, root, "z", default_value_handler, &z_help);

	RzCmdParsedArgs *a = rz_cmd_parsed_args_new("z", 0, NULL);
	mu_assert_eq(rz_cmd_call_parsed_args(cmd, a), RZ_CMD_STATUS_OK, "z was called correctly with default arg");
	rz_cmd_parsed_args_free(a);

	char *args[] = { "10" };
	a = rz_cmd_parsed_args_new("z", 1, args);
	mu_assert_eq(rz_cmd_call_parsed_args(cmd, a), RZ_CMD_STATUS_ERROR, "z was called correctly with given arg");
	rz_cmd_parsed_args_free(a);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_sort_subcommands(void) {
	RzCmdDescHelp z_group_help = { 0 };
	z_group_help.summary = "z summary";
	z_group_help.sort_subcommands = true;
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_group_new(cmd, root, "z", NULL, NULL, &z_group_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zx", x_array_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zc", x_array_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "za", x_array_handler, &fake_help);

	const char *exp1[] = { "za", "zc", "zx" };
	void **it_cd;
	size_t i = 0;

	rz_cmd_desc_children_foreach(z_cd, it_cd) {
		RzCmdDesc *child = *(RzCmdDesc **)it_cd;
		mu_assert_streq(child->name, exp1[i++], "children of z should be sorted");
	}

	rz_cmd_batch_start(cmd);
	rz_cmd_desc_argv_new(cmd, z_cd, "zz", x_array_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zb", x_array_handler, &fake_help);
	rz_cmd_desc_argv_new(cmd, z_cd, "zi", x_array_handler, &fake_help);
	rz_cmd_batch_end(cmd);

	const char *exp2[] = { "za", "zb", "zc", "zi", "zx", "zz" };
	i = 0;
	rz_cmd_desc_children_foreach(z_cd, it_cd) {
		RzCmdDesc *child = *(RzCmdDesc **)it_cd;
		mu_assert_streq(child->name, exp2[i++], "children of z should be sorted even with batch");
	}

	rz_cmd_free(cmd);
	mu_end;
}

static void func1_output(RzCmdStateOutput *state) {
	rz_cmd_state_output_set_columnsf(state, "d", "val");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("val=33\n");
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_kn(state->d.pj, "val", 33);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "d", 33);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("33\n");
		break;
	default:
		break;
	}
}

static void func2_output(RzCmdStateOutput *state) {
	rz_cmd_state_output_set_columnsf(state, "sd", "name", "val");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("name=second,val=55\n");
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "name", "second");
		pj_kn(state->d.pj, "val", 55);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "sd", "second", 55);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("second=55\n");
		break;
	default:
		break;
	}
}

bool test_state_output_concat_standard(void) {
	RzCmdStateOutput state;
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD), "state is initialized correctly");

	rz_cons_flush();
	rz_cons_push();
	func1_output(&state);
	rz_cmd_state_output_print(&state);
	const char *s = rz_cons_get_buffer();
	mu_assert_streq(s, "val=33\n", "standard output was printed");
	rz_cons_pop();
	rz_cmd_state_output_fini(&state);

	rz_cons_flush();
	rz_cons_push();
	func1_output(&state);
	func2_output(&state);
	rz_cmd_state_output_print(&state);
	s = rz_cons_get_buffer();
	mu_assert_streq(s, "val=33\nname=second,val=55\n", "standard output was printed concatenated");
	rz_cons_pop();
	rz_cmd_state_output_fini(&state);

	mu_end;
}

bool test_state_output_concat_table(void) {
	RzCmdStateOutput state;

	rz_cons_flush();
	rz_cons_push();
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_TABLE), "state is initialized correctly");
	func1_output(&state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_TABLE), "state is initialized correctly");
	func2_output(&state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	const char *s = rz_cons_get_buffer();
	const char *exp = "val \n"
			  "----\n"
			  "33\n"
			  "name   val \n"
			  "-----------\n"
			  "second 55\n";
	mu_assert_streq(s, exp, "tables output was printed");
	rz_cons_pop();
	rz_cmd_state_output_fini(&state);

	mu_end;
}

bool test_state_output_concat_mix(void) {
	RzCmdStateOutput state;

	rz_cons_flush();
	rz_cons_push();
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_TABLE), "state is initialized correctly");
	func1_output(&state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET), "state is initialized correctly");
	func2_output(&state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	const char *s = rz_cons_get_buffer();
	const char *exp = "val \n"
			  "----\n"
			  "33\n"
			  "second=55\n";
	mu_assert_streq(s, exp, "table+quiet output was printed");
	rz_cons_pop();
	rz_cmd_state_output_fini(&state);

	mu_end;
}

bool test_state_output_concat_json(void) {
	RzCmdStateOutput state;

	rz_cons_flush();
	rz_cons_push();
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON), "state is initialized correctly");
	func1_output(&state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON), "state is initialized correctly");
	func2_output(&state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	const char *s = rz_cons_get_buffer();
	const char *exp_union = "{\"val\":33}\n"
				"{\"name\":\"second\",\"val\":55}\n";
	mu_assert_streq(s, exp_union, "json+json output was printed");
	rz_cons_pop();

	rz_cons_flush();
	rz_cons_push();
	mu_assert_true(rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON), "state is initialized correctly");
	pj_o(state.d.pj);
	pj_k(state.d.pj, "first");
	func1_output(&state);
	pj_k(state.d.pj, "second");
	func2_output(&state);
	pj_end(state.d.pj);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	s = rz_cons_get_buffer();
	const char *exp_comp = "{\"first\":{\"val\":33},\"second\":{\"name\":\"second\",\"val\":55}}\n";
	mu_assert_streq(s, exp_comp, "json composition output was printed");
	rz_cons_pop();

	mu_end;
}

static RzCmdStatus x_default_mode_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	mu_assert_eq(state->mode, RZ_OUTPUT_MODE_JSON, "x handler should be called with JSON mode");
	mu_assert_notnull(state->d.pj, "x handler should be called with pj nonnull");
	return RZ_CMD_STATUS_OK;
}

bool test_default_mode(void) {
	RzCmdDescArg z_args[] = { { 0 } };
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;

	RzCmdDescArg x_args[] = { { 0 } };
	RzCmdDescHelp x_help = { 0 };
	x_help.summary = "x summary";
	x_help.args = x_args;

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *z_cd = rz_cmd_desc_argv_modes_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_LONG_JSON, z_modes_handler, &z_help);
	RzCmdDesc *x_cd = rz_cmd_desc_argv_state_new(cmd, root, "x", RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_LONG_JSON, x_default_mode_handler, &x_help);

	bool changed = rz_cmd_desc_set_default_mode(z_cd, RZ_OUTPUT_MODE_JSON);
	mu_assert_false(changed, "default_mode was not changed because _STANDARD is already defined for z_cd");
	mu_assert_eq(z_cd->d.argv_modes_data.default_mode, RZ_OUTPUT_MODE_STANDARD, "default_mode is still _STANDARD for z_cd");

	changed = rz_cmd_desc_set_default_mode(x_cd, RZ_OUTPUT_MODE_JSON);
	mu_assert_true(changed, "default_mode was changed for x_cd");
	mu_assert_eq(x_cd->d.argv_state_data.default_mode, RZ_OUTPUT_MODE_JSON, "default_mode is now _JSON for x_cd");

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_new("x", 0, NULL);
	RzCmdStatus status = rz_cmd_call_parsed_args(cmd, pa);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "x handler should be correctly executed");
	rz_cmd_parsed_args_free(pa);

	pa = rz_cmd_parsed_args_new("x?", 0, NULL);
	char *h = rz_cmd_get_help(cmd, pa, false);
	mu_assert_strcontains(h, "x[jqJ]   # x summary (JSON mode)", "x help should contain the default=json mode");
	mu_assert_strcontains(h, "xj      # x summary (JSON mode)", "x help should contain the json mode");
	mu_assert_strcontains(h, "xq      # x summary (quiet mode)", "x help should contain the quiet mode");
	free(h);
	rz_cmd_parsed_args_free(pa);

	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdDescDetail *z_details_cb(RzCore *core, int argc, const char **argv) {
	RzCmdDescDetail *z_details_cb_data = RZ_NEWS0(RzCmdDescDetail, 3);
	z_details_cb_data[0].name = (const char *)strdup("Examples");
	RzCmdDescDetailEntry *entries = RZ_NEWS0(RzCmdDescDetailEntry, 3);
	entries[0].text = (const char *)strdup("z");
	entries[0].comment = (const char *)strdup("dynamically generated detail");
	entries[1].text = (const char *)strdup("z");
	entries[1].comment = (const char *)strdup("dynamically generated detail 2");
	z_details_cb_data[0].entries = (const RzCmdDescDetailEntry *)entries;
	z_details_cb_data[1].name = (const char *)strdup("Examples 2");
	z_details_cb_data[2].entries = NULL;
	return z_details_cb_data;
}

bool test_details_cb(void) {
	RzCmdDescArg z_args[] = { { 0 } };
	RzCmdDescHelp z_help = { 0 };
	z_help.summary = "z summary";
	z_help.args = z_args;
	z_help.details_cb = z_details_cb;

	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	rz_cmd_desc_argv_modes_new(cmd, root, "z", RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_LONG_JSON, z_modes_handler, &z_help);

	RzCmdParsedArgs *pa = rz_cmd_parsed_args_new("z?", 0, NULL);
	char *h = rz_cmd_get_help(cmd, pa, false);
	mu_assert_strcontains(h, "# dynamically generated detail", "z help should contain result of the details_cb");
	mu_assert_strcontains(h, "Examples 2", "z help should contain result of the details_cb 2");
	free(h);
	rz_cmd_parsed_args_free(pa);

	rz_cmd_free(cmd);
	mu_end;
}

bool test_get_best_match(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDesc *a_cd = rz_cmd_desc_group_new(cmd, root, "a", NULL, NULL, &fake_help);
	RzCmdDesc *ap_cd = rz_cmd_desc_group_new(cmd, a_cd, "ap", ap_handler, NULL, &fake_help);
	RzCmdDesc *apd_cd = rz_cmd_desc_argv_new(cmd, ap_cd, "apd", ap_handler, &fake_help);
	RzCmdDesc *ae_cd = rz_cmd_desc_oldinput_new(cmd, a_cd, "ae", ae_handler, NULL);
	rz_cmd_desc_argv_new(cmd, ae_cd, "aeir", aeir_handler, &fake_help);
	rz_cmd_desc_oldinput_new(cmd, root, "w", w_handler, NULL);

	mu_assert_ptreq(rz_cmd_get_desc_best(cmd, "ap"), ap_cd, "ap should be best match for ap");
	mu_assert_ptreq(rz_cmd_get_desc_best(cmd, "apn"), ap_cd, "ap should be best match for apn");
	mu_assert_ptreq(rz_cmd_get_desc_best(cmd, "apd"), apd_cd, "apd should be best match for apd");
	mu_assert_ptreq(rz_cmd_get_desc_best(cmd, "afff"), a_cd, "a should be best match for afff");

	rz_cmd_free(cmd);
	mu_end;
}

bool test_no_macros(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	RzList *l = rz_cmd_macro_list(cmd);
	mu_assert_eq(rz_list_length(l), 0, "no macros");
	rz_list_free(l);
	rz_cmd_free(cmd);
	mu_end;
}

bool test_simple_macros(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	const char *macro1_args[] = { "a", "b", NULL };
	bool res = rz_cmd_macro_add(cmd, "macro1", macro1_args, "pd ${a} @ ${b}");
	mu_assert_true(res, "macro1 should be added");
	RzList *l = rz_cmd_macro_list(cmd);
	mu_assert_eq(rz_list_length(l), 1, "no macros");
	const RzCmdMacro *macro1 = (const RzCmdMacro *)rz_list_first(l);
	mu_assert_streq(macro1->name, "macro1", "macro should be named macro1");
	mu_assert_eq(macro1->nargs, 2, "macro1 should have 2 args");
	mu_assert_streq(macro1->args[0], "a", "macro1 first arg should be a");
	mu_assert_streq(macro1->args[1], "b", "macro1 first arg should be b");
	mu_assert_streq(macro1->code, "pd ${a} @ ${b}", "macro1 code should be right");
	mu_assert_ptreq(rz_cmd_macro_get(cmd, "macro1"), macro1, "_get should get the same element");
	rz_list_free(l);
	rz_cmd_free(cmd);
	mu_end;
}

bool test_remove_macros(void) {
	RzCmd *cmd = rz_cmd_new(NULL, false);
	const char *macro1_args[] = { NULL };
	rz_cmd_macro_add(cmd, "macro1", macro1_args, "pd ${a} @ ${b}");
	mu_assert_notnull(rz_cmd_macro_get(cmd, "macro1"), "macro1 should be retrieved");
	bool res = rz_cmd_macro_rm(cmd, "macro1");
	mu_assert_true(res, "macro1 should be removed");
	mu_assert_null(rz_cmd_macro_get(cmd, "macro1"), "macro1 should be not retrieved anymore");
	res = rz_cmd_macro_rm(cmd, "macro1");
	mu_assert_false(res, "macro1 should have been already removed");
	rz_cmd_free(cmd);
	mu_end;
}

static RzCmdStatus a_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus b_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 3) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!strcmp(argv[1], "20")) {
		return !strcmp(argv[2], "10") ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	} else if (!strcmp(argv[1], "40")) {
		return !strcmp(argv[2], "30") ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_ERROR;
}

bool test_call_macros(void) {
	RzCore *core = RZ_NEW0(RzCore);
	core->cons = rz_cons_singleton();
	RzCmd *cmd = rz_core_cmd_new(core, false);
	core->rcmd = cmd;
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	rz_cmd_desc_argv_new(cmd, root, "a", a_handler, &fake_help);
	RzCmdDescArg b_args[] = {
		{ .name = "n1", .type = RZ_CMD_ARG_TYPE_STRING },
		{ .name = "n2", .type = RZ_CMD_ARG_TYPE_STRING },
		{ 0 },
	};
	RzCmdDescHelp b_help = {
		.summary = "b help",
		.args = b_args,
	};
	rz_cmd_desc_argv_new(cmd, root, "b", b_handler, &b_help);
	const char *macro_args[] = { NULL };
	const char *macro2_args[] = { "a", "b", NULL };
	rz_cmd_macro_add(cmd, "macro1", macro_args, "a");
	rz_cmd_macro_add(cmd, "macro2", macro2_args, "b ${b} ${a}");
	rz_cmd_macro_add(cmd, "macro3", macro_args, "c");

	const char *macro_args_val[] = { NULL };
	const char *macro2_args_val[] = { "10", "20", NULL };

	RzCmdStatus status = rz_cmd_macro_call(cmd, "macro1", macro_args_val);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "a handler has been called correctly");
	status = rz_cmd_macro_call(cmd, "macro2", macro2_args_val);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "b handler has been called correctly");
	status = rz_cmd_macro_call(cmd, "macro3", macro_args_val);
	mu_assert_eq(status, RZ_CMD_STATUS_NONEXISTINGCMD, "c command should not exist");

	rz_cmd_free(cmd);
	mu_end;
}

bool test_call_multiple_macros(void) {
	RzCore *core = RZ_NEW0(RzCore);
	core->cons = rz_cons_singleton();
	RzCmd *cmd = rz_core_cmd_new(core, false);
	core->rcmd = cmd;
	RzCmdDesc *root = rz_cmd_get_root(cmd);
	RzCmdDescArg b_args[] = {
		{ .name = "n1", .type = RZ_CMD_ARG_TYPE_STRING },
		{ .name = "n2", .type = RZ_CMD_ARG_TYPE_STRING },
		{ 0 },
	};
	RzCmdDescHelp b_help = {
		.summary = "b help",
		.args = b_args,
	};
	rz_cmd_desc_argv_new(cmd, root, "b", b_handler, &b_help);
	const char *macro2_args[] = { "a", "b", NULL };
	rz_cmd_macro_add(cmd, "macro2", macro2_args, "b ${b} ${a}");

	const char *macro_args_val[] = { "10", "20", "30", "40", NULL };
	const char *macro_args_val_wrong[] = { "10", "20", "30", NULL };

	RzCmdStatus status = rz_cmd_macro_call_multiple(cmd, "macro2", macro_args_val);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "macro2 has been called correctly");
	status = rz_cmd_macro_call(cmd, "macro2", macro_args_val_wrong);
	mu_assert_eq(status, RZ_CMD_STATUS_INVALID, "macro2 should be called with a multiple of arguments");
	rz_cmd_free(cmd);
	mu_end;
}

int all_tests() {
	mu_run_test(test_parsed_args_noargs);
	mu_run_test(test_parsed_args_onearg);
	mu_run_test(test_parsed_args_args);
	mu_run_test(test_parsed_args_nospace);
	mu_run_test(test_parsed_args_newcmd);
	mu_run_test(test_parsed_args_newargs);
	mu_run_test(test_cmd_descriptor_argv);
	mu_run_test(test_cmd_descriptor_argv_nested);
	mu_run_test(test_cmd_descriptor_oldinput);
	mu_run_test(test_cmd_descriptor_tree);
	mu_run_test(test_cmd_descriptor_group);
	mu_run_test(test_cmd_get_desc);
	mu_run_test(test_cmd_call_desc);
	mu_run_test(test_cmd_help);
	mu_run_test(test_cmd_group_help);
	mu_run_test(test_cmd_oldinput_help);
	mu_run_test(test_cmd_group_exec_help);
	mu_run_test(test_remove_cmd);
	mu_run_test(test_cmd_args);
	mu_run_test(test_cmd_argv_modes);
	mu_run_test(test_cmd_argv_state);
	mu_run_test(test_cmd_group_argv_modes);
	mu_run_test(test_foreach_cmdname);
	mu_run_test(test_foreach_cmdname_begin);
	mu_run_test(test_arg_escaping);
	mu_run_test(test_double_quoted_arg_escaping);
	mu_run_test(test_single_quoted_arg_escaping);
	mu_run_test(test_arg_flags);
	mu_run_test(test_get_arg);
	mu_run_test(test_parent_details);
	mu_run_test(test_default_value);
	mu_run_test(test_sort_subcommands);
	mu_run_test(test_state_output_concat_standard);
	mu_run_test(test_state_output_concat_table);
	mu_run_test(test_state_output_concat_mix);
	mu_run_test(test_state_output_concat_json);
	mu_run_test(test_default_mode);
	mu_run_test(test_details_cb);
	mu_run_test(test_get_best_match);
	mu_run_test(test_no_macros);
	mu_run_test(test_simple_macros);
	mu_run_test(test_remove_macros);
	mu_run_test(test_call_macros);
	mu_run_test(test_call_multiple_macros);
	return tests_passed != tests_run;
}

mu_main(all_tests)
