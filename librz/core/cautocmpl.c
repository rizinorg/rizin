// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <tree_sitter/api.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <rz_cmd.h>

#include "core_private.h"

/**
 * Describe what needs to be autocompleted.
 */
enum autocmplt_type_t {
	AUTOCMPLT_UNKNOWN = 0, ///< Unknown, nothing will be autocompleted
	AUTOCMPLT_CMD_ID, ///< A command identifier (aka command name) needs to be autocompleted
	AUTOCMPLT_CMD_ARG, ///< The argument of an arged_stmt (see grammar.js) needs to be autocompleted
	AUTOCMPLT_AT_STMT, ///< A temporary modifier operator like `@ `, `@a:`, `@v:` or a iter operator like `@@.`, `@@`, `@@i`, etc.
	AUTOCMPLT_RZNUM, ///< A expression that can be parsed by RzNum (e.g. "flag+3")
	AUTOCMPLT_ARCH, ///< An architecture supported by Rizin (e.g. x86, arm, etc.)
	AUTOCMPLT_BITS, ///< A bits value supported by the currently selected architecture (e asm.bits=?)
	AUTOCMPLT_FILE, ///< A file needs to be autocompleted
	AUTOCMPLT_FLAG_SPACE, ///< A flag space needs to be autocompleted
	AUTOCMPLT_REG, ///< A cpu register needs to be autocompleted
	AUTOCMPLT_EVAL_FULL, ///< A name=value of a evaluable variable (e.g. `e` command)
	AUTOCMPLT_FLAG, ///< A flag item needs to be autocompleted
	AUTOCMPLT_FUNCTION, ///< A function name needs to be autocompleted
};

/**
 * Group all data necessary for autocompletion, including the type and other
 * fields as required by the type.
 */
struct autocmplt_data_t {
	enum autocmplt_type_t type; ///< Type of token that will be autocompleted
	RzLineNSCompletionResult *res; ///< Result returned to RzCons API to provide possible suggestions
	const RzCmdDesc *cd; ///< Used if type is \p AUTOCMPLT_CMD_ARG to describe the related command
	size_t i_arg; ///< Used if type is \p AUTOCMPLT_CMD_ARG to describe the argument that will be autocompleted
};

/**
 * Group data that needs to be passed to rz_cmd_foreach_cmdname callback.
 */
struct autocmplt_cmdidentifier_t {
	RzLineNSCompletionResult *res;
	const char *s;
	size_t len;
};

/**
 * Result of a guessing of what needs to be autocompleted, by modifying the
 * real input with additional data.
 */
struct guess_data_t {
	char *input; ///< Modified input
	TSParser *parser; ///< Parser used to parser the modified input
	TSTree *tree; ///< Pointer to the syntax tree of the modified input
	TSNode node; ///< Node identified under the user position cursor when using the modified input
};

static void guess_data_free(struct guess_data_t *g) {
	ts_tree_delete(g->tree);
	ts_parser_delete(g->parser);
	free(g->input);
	free(g);
}

/**
 * Modify the input in \p buf to add additional characters, trying to detect
 * what token could go in the current position of the buffer. For example, to
 * detect that a CMD_ID is expected at * `?e $(<TAB>`, you could try inserting
 * a letter and see what would be the new syntax tree.
 */
static struct guess_data_t *guess_next_autocmplt_token(RzCore *core, RzLineBuffer *buf, const char *fake_text, size_t offset) {
	size_t fake_len = strlen(fake_text);
	char *tmp = malloc(strlen(buf->data) + 1 + fake_len);
	memcpy(tmp, buf->data, buf->index);
	memcpy(tmp + buf->index, fake_text, fake_len);
	memcpy(tmp + buf->index + fake_len, buf->data + buf->index, buf->length - buf->index);
	tmp[buf->length + fake_len] = '\0';
	RZ_LOG_DEBUG("guess_next_autocmplt_token = '%s'\n", tmp);

	TSParser *parser = ts_parser_new();
	ts_parser_set_language(parser, (TSLanguage *)core->rcmd->language);
	TSTree *tree = ts_parser_parse_string(parser, NULL, tmp, buf->length + fake_len);
	TSNode root = ts_tree_root_node(tree);
	TSNode node = ts_node_named_descendant_for_byte_range(root, buf->index + offset, buf->index + offset + 1);
	if (ts_node_is_null(node)) {
		goto err;
	}

	struct guess_data_t *g = RZ_NEW0(struct guess_data_t);
	g->node = node;
	g->tree = tree;
	g->parser = parser;
	g->input = tmp;
	return g;

err:
	ts_tree_delete(tree);
	ts_parser_delete(parser);
	free(tmp);
	return NULL;
}

static bool do_autocmplt_cmdidentifier(RzCmd *cmd, const RzCmdDesc *desc, void *user) {
	struct autocmplt_cmdidentifier_t *u = (struct autocmplt_cmdidentifier_t *)user;
	if (!strncmp(desc->name, u->s, u->len)) {
		rz_line_ns_completion_result_add(u->res, desc->name);
	}
	return true;
}

static void autocmplt_cmdidentifier(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	struct autocmplt_cmdidentifier_t u = {
		.res = res,
		.s = s,
		.len = len,
	};
	rz_cmd_foreach_cmdname(core->rcmd, NULL, do_autocmplt_cmdidentifier, &u);
}

static void autocmplt_at_stmt(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	const char *stmts[] = {
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
		NULL,
	};
	const char **stmt;
	for (stmt = stmts; *stmt; stmt++) {
		if (!strncmp(*stmt, s, len)) {
			rz_line_ns_completion_result_add(res, *stmt);
		}
	}
	res->end_string = "";
}

static void autocmplt_bits_plugin(RzAsmPlugin *plugin, RzLineNSCompletionResult *res, const char *s, size_t len) {
	int bits = plugin->bits;
	int i;
	char sbits[5];
	for (i = 1; i <= bits; i <<= 1) {
		if (i & bits && !strncmp(rz_strf(sbits, "%d", i), s, len)) {
			rz_line_ns_completion_result_add(res, sbits);
		}
	}
}

static void autocmplt_arch(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	rz_return_if_fail(core->rasm);

	RzList *asm_plugins = rz_asm_get_plugins(core->rasm);
	RzListIter *it;
	RzAsmPlugin *plugin;

	// @a: can either be used with @a:arch or @a:arch:bits
	// Check for `:` to determine where we are
	const char *delim = rz_sub_str_rchr(s, 0, len, ':');
	if (!delim) {
		// We autocomplete just the architecture part
		rz_list_foreach (asm_plugins, it, plugin) {
			if (!strncmp(plugin->name, s, len)) {
				rz_line_ns_completion_result_add(res, plugin->name);
			}
		}
		res->end_string = "";
	} else {
		// We autocomplete the bits part
		res->start += delim + 1 - s;
		rz_list_foreach (asm_plugins, it, plugin) {
			if (!strncmp(plugin->name, s, delim - s)) {
				autocmplt_bits_plugin(plugin, res, delim + 1, len - (delim + 1 - s));
				break;
			}
		}
	}
}

static void autocmplt_bits(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	rz_return_if_fail(core->rasm && core->rasm->cur);

	autocmplt_bits_plugin(core->rasm->cur, res, s, len);
}

static void autocmplt_flag_space(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzSpace *space;
	RBIter it;

	rz_flag_space_foreach(core->flags, it, space) {
		if (!strncmp(space->name, s, len)) {
			rz_line_ns_completion_result_add(res, space->name);
		}
	}
	if (len == 0) {
		rz_line_ns_completion_result_add(res, "*");
	}
}

static void autocmplt_reg(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzReg *reg = rz_core_reg_default(core);
	const RzList *regs = rz_reg_get_list(reg, RZ_REG_TYPE_ANY);
	RzListIter *it;
	RzRegItem *regitem;

	rz_list_foreach (regs, it, regitem) {
		if (!strncmp(regitem->name, s, len)) {
			rz_line_ns_completion_result_add(res, regitem->name);
		}
	}
}

static void autocmplt_cmd_arg_file(RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *input = rz_str_ndup(s, len);
	if (!input) {
		return;
	}

	if (RZ_STR_ISEMPTY(input)) {
		free(input);
		input = strdup(".");
	} else if (!rz_file_is_abspath(input) && !rz_str_startswith(input, ".")) {
		const char *fmt = ".%s%s";
#if __WINDOWS__
		if (strchr(input, ':')) {
			fmt = "%.0s%s";
		}
#endif
		char *tmp = rz_str_newf(fmt, RZ_SYS_DIR, input);
		if (!tmp) {
			return;
		}
		free(input);
		input = tmp;
	}
	char *einput = rz_path_home_expand(input);
	free(input);

	char *basedir = rz_file_dirname(einput);
	const char *basename = rz_file_basename(einput + 1);
#if __WINDOWS__
	rz_str_replace_ch(basedir, '/', '\\', true);
#endif

	RzList *l = rz_sys_dir(basedir);
	RzListIter *iter;
	char *filename;
	rz_list_foreach (l, iter, filename) {
		if (!strcmp(filename, ".") || !strcmp(filename, "..")) {
			continue;
		}
		if (!strncmp(filename, basename, strlen(basename))) {
			// TODO: only show/autocomplete the last part of the path, not the whole path
			char *tmpfilename = rz_file_path_join(basedir, filename);
			if (rz_file_is_directory(tmpfilename)) {
				res->end_string = RZ_SYS_DIR;
			}
			rz_line_ns_completion_result_add(res, tmpfilename);
			free(tmpfilename);
		}
	}
	rz_list_free(l);
	free(basedir);
	free(einput);
}

static void autocmplt_cmd_arg_env(RzLineNSCompletionResult *res, const char *s, size_t len) {
	char **env;
	res->end_string = "";
	for (env = rz_sys_get_environ(); *env; env++) {
		const char *eq = strchr(*env, '=');
		char *envkey = eq ? rz_str_ndup(*env, eq - *env) : strdup(*env);
		if (!strncmp(envkey, s, len)) {
			rz_line_ns_completion_result_add(res, envkey);
		}
		free(envkey);
	}
}

static void autocmplt_cmd_arg_macro(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzCmdMacroItem *item;
	RzListIter *iter;
	rz_list_foreach (core->rcmd->macro.macros, iter, item) {
		char *p = item->name;
		if (!strncmp(p, s, len)) {
			rz_line_ns_completion_result_add(res, p);
		}
	}
}

static void autocmplt_cmd_arg_flag(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzFlagItem *item;
	RzListIter *iter;
	RzList *list = rz_flag_all_list(core->flags, false);
	rz_list_foreach (list, iter, item) {
		char *flag = item->name;
		if (!strncmp(flag, s, len)) {
			rz_line_ns_completion_result_add(res, flag);
		}
	}
	rz_list_free(list);
}

static bool offset_prompt_add_flag(RzFlagItem *fi, void *user) {
	RzLineNSCompletionResult *res = (RzLineNSCompletionResult *)user;
	rz_line_ns_completion_result_add(res, fi->name);
	return true;
}

static void autocmplt_cmd_arg_fcn(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		char *name = rz_core_analysis_fcn_name(core, fcn);
		if (!strncmp(name, s, len)) {
			rz_line_ns_completion_result_add(res, name);
		}
		free(name);
	}
}

static void autocmplt_cmd_arg_enum_type(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *item;
	RzListIter *iter;
	RzList *list = rz_type_db_enum_names(core->analysis->typedb);
	rz_list_foreach (list, iter, item) {
		if (!strncmp(item, s, len)) {
			rz_line_ns_completion_result_add(res, item);
		}
	}
	rz_list_free(list);
}

static void autocmplt_cmd_arg_struct_type(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *item;
	RzListIter *iter;
	RzList *list = rz_type_db_struct_names(core->analysis->typedb);
	rz_list_foreach (list, iter, item) {
		if (!strncmp(item, s, len)) {
			rz_line_ns_completion_result_add(res, item);
		}
	}
	rz_list_free(list);
}

static void autocmplt_cmd_arg_union_type(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *item;
	RzListIter *iter;
	RzList *list = rz_type_db_union_names(core->analysis->typedb);
	rz_list_foreach (list, iter, item) {
		if (!strncmp(item, s, len)) {
			rz_line_ns_completion_result_add(res, item);
		}
	}
	rz_list_free(list);
}

static void autocmplt_cmd_arg_alias_type(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *item;
	RzListIter *iter;
	RzList *list = rz_type_db_typedef_names(core->analysis->typedb);
	rz_list_foreach (list, iter, item) {
		if (!strncmp(item, s, len)) {
			rz_line_ns_completion_result_add(res, item);
		}
	}
	rz_list_free(list);
}

static void autocmplt_cmd_arg_any_type(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *item;
	RzListIter *iter;
	RzList *list = rz_type_db_all(core->analysis->typedb);
	rz_list_foreach (list, iter, item) {
		if (!strncmp(item, s, len)) {
			rz_line_ns_completion_result_add(res, item);
		}
	}
	rz_list_free(list);
}

static void autocmplt_cmd_arg_global_var(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzAnalysisVarGlobal *glob;
	RzListIter *iter;
	RzList *list = rz_analysis_var_global_get_all(core->analysis);
	rz_list_foreach (list, iter, glob) {
		char *name = glob->name;
		if (!strncmp(name, s, len)) {
			rz_line_ns_completion_result_add(res, name);
		}
	}
	rz_list_free(list);
}

static void autocmplt_cmd_arg_reg_filter(RzCore *core, const RzCmdDesc *cd, RzLineNSCompletionResult *res, const char *s, size_t len) {
	bool is_analysis = cd->name && cd->name[0] == 'a';
	RzReg *reg = is_analysis ? core->analysis->reg : core->dbg->reg;
	if (!reg) {
		return;
	}

	rz_line_ns_completion_result_propose(res, "8", s, len);
	rz_line_ns_completion_result_propose(res, "16", s, len);
	rz_line_ns_completion_result_propose(res, "32", s, len);
	rz_line_ns_completion_result_propose(res, "64", s, len);
	rz_line_ns_completion_result_propose(res, "128", s, len);
	rz_line_ns_completion_result_propose(res, "256", s, len);

	for (int type = 0; type < RZ_REG_TYPE_LAST; type++) {
		const char *name = rz_reg_get_type(type);
		if (!name) {
			continue;
		}
		rz_line_ns_completion_result_propose(res, name, s, len);
	}
	rz_line_ns_completion_result_propose(res, "all", s, len);

	for (int role = 0; role < RZ_REG_NAME_LAST; role++) {
		if (!reg->name[role]) {
			// don't autocomplete if there isn't a register with this role anyway
			continue;
		}
		const char *name = rz_reg_get_role(role);
		if (!name) {
			continue;
		}
		rz_line_ns_completion_result_propose(res, name, s, len);
	}

	RzListIter *iter;
	RzRegItem *ri;
	rz_list_foreach (reg->allregs, iter, ri) {
		if (!ri->name) {
			continue;
		}
		rz_line_ns_completion_result_propose(res, ri->name, s, len);
	}
}

static void autocmplt_cmd_arg_reg_type(RzCore *core, const RzCmdDesc *cd, RzLineNSCompletionResult *res, const char *s, size_t len) {
	for (int t = 0; t < RZ_REG_TYPE_LAST; t++) {
		rz_line_ns_completion_result_propose(res, rz_reg_get_type(t), s, len);
	}
}

static void autocmplt_cmd_arg_help_var(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	const char **vars = rz_core_help_vars_get(core);
	while (*vars) {
		if (!strncmp(*vars, s, len)) {
			rz_line_ns_completion_result_add(res, *vars);
		}
		vars++;
	}
}

static bool is_op_ch(char ch) {
	return ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '%' ||
		ch == '>' || ch == '<';
}

static void autocmplt_cmd_arg_rznum(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	if (len > 0) {
		// If the argument is composed of a complex expression with some
		// operator, autocomplete only the last part
		const char *p;
		size_t plen;
		for (p = s, plen = len; *p && plen > 0; p++, plen--) {
			if (is_op_ch(*p)) {
				res->start += p + 1 - s;
				s = p + 1;
				len = plen - 1;
			}
		}
	}
	autocmplt_cmd_arg_fcn(core, res, s, len);
	rz_flag_foreach_prefix(core->flags, s, len, offset_prompt_add_flag, res);
	autocmplt_cmd_arg_help_var(core, res, s, len);
}

static void autocmplt_cmd_arg_zign_space(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzSpaces *zs = &core->analysis->zign_spaces;
	RzSpace *space;
	RzSpaceIter it;

	rz_spaces_foreach(zs, it, space) {
		if (!strncmp(space->name, s, len)) {
			rz_line_ns_completion_result_add(res, space->name);
		}
	}

	if (len == 0) {
		rz_line_ns_completion_result_add(res, "*");
	}
}

static void autocmplt_cmd_arg_choices(RzLineNSCompletionResult *res, const char *s, size_t len, const RzCmdDescArg *arg) {
	const char **c;
	for (c = arg->choices; *c; c++) {
		if (!strncmp(*c, s, len)) {
			rz_line_ns_completion_result_add(res, *c);
		}
	}
}

static void autocmplt_cmd_arg_eval_key(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzListIter *iter;
	RzConfigNode *bt;
	rz_list_foreach (core->config->nodes, iter, bt) {
		if (!strncmp(bt->name, s, len)) {
			rz_line_ns_completion_result_add(res, bt->name);
		}
	}
}

static void autocmplt_cmd_arg_eval_full(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *eq = (char *)rz_sub_str_rchr(s, 0, len, '=');
	if (!eq) {
		// autocomplete only the key
		res->end_string = "";
		autocmplt_cmd_arg_eval_key(core, res, s, len);
		return;
	}

	char *k = rz_str_ndup(s, eq - s);
	char *v = NULL;
	RzConfigNode *node = rz_config_node_get(core->config, k);
	if (!node) {
		goto err;
	}

	v = rz_str_ndup(eq + 1, len - (eq - s) - 1);
	len = strlen(v);

	res->start += strlen(k) + 1;

	if (node->options && rz_list_length(node->options)) {
		RzListIter *iter;
		char *opt;
		rz_list_foreach (node->options, iter, opt) {
			if (!strncmp(opt, v, len)) {
				rz_line_ns_completion_result_add(res, opt);
			}
		}
	} else if (rz_config_node_is_bool(node)) {
		if (!strncmp("true", v, len)) {
			rz_line_ns_completion_result_add(res, "true");
		}
		if (!strncmp("false", v, len)) {
			rz_line_ns_completion_result_add(res, "false");
		}
	}

err:
	free(v);
	free(k);
}

static void autocmplt_cmd_arg_fcn_var(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		return;
	}
	RzList *vars = rz_analysis_var_all_list(core->analysis, fcn);
	RzListIter *iter;
	RzAnalysisVar *var;
	rz_list_foreach (vars, iter, var) {
		if (!strncmp(var->name, s, len)) {
			rz_line_ns_completion_result_add(res, var->name);
		}
	}
	rz_list_free(vars);
}

static bool is_arg_type(const char *type) {
	return !strcmp(type, "concatenation") || !strcmp(type, "arg") ||
		!strcmp(type, "args") || !strcmp(type, "arg_identifier") ||
		!strcmp(type, "double_quoted_arg") || !strcmp(type, "single_quoted_arg");
}

static RzCmdDesc *get_cd_from_cmdid(RzCore *core, const char *data, TSNode cmd_id) {
	ut32 command_start = ts_node_start_byte(cmd_id);
	ut32 command_end = ts_node_end_byte(cmd_id);
	char *cmdid = rz_str_ndup(data + command_start, command_end - command_start);
	RzCmdDesc *cd = rz_cmd_desc_get_exec(rz_cmd_get_desc(core->rcmd, cmdid));
	free(cmdid);
	return cd;
}

static RzCmdDesc *get_cd_from_arg(RzCore *core, const char *data, TSNode arg) {
	if (ts_node_is_null(arg)) {
		return NULL;
	}
	const char *parent_type;
	TSNode parent = arg;
	do {
		parent = ts_node_parent(parent);
		if (ts_node_is_null(parent)) {
			return NULL;
		}
		parent_type = ts_node_type(parent);
	} while (is_arg_type(parent_type));

	if (strcmp(parent_type, "arged_stmt")) {
		return NULL;
	}

	TSNode cmdid = ts_node_named_child(parent, 0);
	const char *node_type = ts_node_is_null(cmdid) ? "" : ts_node_type(cmdid);
	if (strcmp(node_type, "cmd_identifier")) {
		return false;
	}

	return get_cd_from_cmdid(core, data, cmdid);
}

static size_t get_arg_number(TSNode arg) {
	const char *arg_type = ts_node_type(arg);
	while (strcmp(arg_type, "arg")) {
		arg = ts_node_parent(arg);
		arg_type = ts_node_type(arg);
	}

	size_t i_arg = 0;
	arg = ts_node_prev_sibling(arg);
	while (!ts_node_is_null(arg)) {
		i_arg++;
		arg = ts_node_prev_sibling(arg);
	}
	return i_arg;
}

/**
 * Fill \p res with all the available options for the argument i_arg-th of the
 * command \p cd . This is based on the type of argument a command may accept.
 */
static void autocmplt_cmd_arg(RzCore *core, RzLineNSCompletionResult *res, const RzCmdDesc *cd, size_t i_arg, const char *s, size_t len) {
	const RzCmdDescArg *arg = rz_cmd_desc_get_arg(core->rcmd, cd, i_arg);
	if (!arg) {
		return;
	}

	RzCmdArgType arg_type = arg->type;
	switch (arg_type) {
	case RZ_CMD_ARG_TYPE_FILE:
		autocmplt_cmd_arg_file(res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ENV:
		autocmplt_cmd_arg_env(res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ZIGN_SPACE:
		autocmplt_cmd_arg_zign_space(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_CHOICES:
		autocmplt_cmd_arg_choices(res, s, len, arg);
		break;
	case RZ_CMD_ARG_TYPE_FCN:
		autocmplt_cmd_arg_fcn(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_MACRO:
		autocmplt_cmd_arg_macro(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_RZNUM:
		autocmplt_cmd_arg_rznum(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_EVAL_KEY:
		autocmplt_cmd_arg_eval_key(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_EVAL_FULL:
		autocmplt_cmd_arg_eval_full(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_FCN_VAR:
		autocmplt_cmd_arg_fcn_var(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_FLAG:
		autocmplt_cmd_arg_flag(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ENUM_TYPE:
		autocmplt_cmd_arg_enum_type(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_STRUCT_TYPE:
		autocmplt_cmd_arg_struct_type(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_UNION_TYPE:
		autocmplt_cmd_arg_union_type(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ALIAS_TYPE:
		autocmplt_cmd_arg_alias_type(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ANY_TYPE:
		autocmplt_cmd_arg_any_type(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_GLOBAL_VAR:
		autocmplt_cmd_arg_global_var(core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_REG_FILTER:
		autocmplt_cmd_arg_reg_filter(core, cd, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_REG_TYPE:
		autocmplt_cmd_arg_reg_type(core, cd, res, s, len);
		break;
	default:
		break;
	}
}

static bool fill_autocmplt_data(struct autocmplt_data_t *ad, enum autocmplt_type_t type, ut32 start, ut32 end) {
	ad->type = type;
	ad->res = rz_line_ns_completion_result_new(start, end, NULL);
	return true;
}

/**
 * Fill the \p ad structure with all the data required to autocomplete the
 * cmdidentifier of a command.
 */
static bool fill_autocmplt_data_cmdid(struct autocmplt_data_t *ad, ut32 start, ut32 end) {
	return fill_autocmplt_data(ad, AUTOCMPLT_CMD_ID, start, end);
}

/**
 * Fill the \p ad structure with all the data required to autocomplete the
 * argument of a command. This includes the command descriptor of the command
 * and the position of the argument that needs to be auto completed.
 */
static bool fill_autocmplt_data_cmdarg(struct autocmplt_data_t *ad, ut32 start, ut32 end, const char *s, TSNode node, RzCore *core) {
	ad->type = AUTOCMPLT_CMD_ARG;
	ad->cd = get_cd_from_arg(core, s, node);
	if (!ad->cd) {
		return false;
	}

	ad->i_arg = get_arg_number(node);

	const RzCmdDescArg *arg = rz_cmd_desc_get_arg(core->rcmd, ad->cd, ad->i_arg);
	if (!arg) {
		return false;
	}

	ad->res = rz_line_ns_completion_result_new(start, end, NULL);
	return true;
}

/**
 * Fill the \p ad structure with all the data required to autocomplete a tmp
 * stmt (@, @(, @a:, etc.) or a iter stmt (@@, @@., @@i, etc.)
 */
static bool fill_autocmplt_data_at_stmt(struct autocmplt_data_t *ad, ut32 start, ut32 end) {
	return fill_autocmplt_data(ad, AUTOCMPLT_AT_STMT, start, end);
}

static bool find_autocmplt_type_newcmd_or_arg(struct autocmplt_data_t *ad, RzCore *core, RzLineBuffer *buf) {
	bool res = false;
	struct guess_data_t *g = guess_next_autocmplt_token(core, buf, "a", 0);
	if (g) {
		const char *node_type = ts_node_type(g->node);
		ut32 node_start = ts_node_start_byte(g->node);
		if (!strcmp(node_type, "cmd_identifier")) {
			res = fill_autocmplt_data_cmdid(ad, node_start, node_start);
		} else if (is_arg_type(node_type)) {
			res = fill_autocmplt_data_cmdarg(ad, node_start, node_start, g->input, g->node, core);
		}
		guess_data_free(g);
	}
	return res;
}

static TSNode get_arg_parent(TSNode node) {
	while (!ts_node_is_null(node) && is_arg_type(ts_node_type(node))) {
		node = ts_node_parent(node);
	}
	return node;
}

static bool is_arg_identifier_in_tmp_stmt(TSNode node) {
	if (!is_arg_type(ts_node_type(node))) {
		return false;
	}
	node = get_arg_parent(node);
	if (ts_node_is_null(node)) {
		return false;
	}
	const char *node_type = ts_node_type(node);
	bool is_iter_or_tmp = rz_str_startswith(node_type, "tmp_") || rz_str_startswith(node_type, "iter_");
	return is_iter_or_tmp && rz_str_endswith(node_type, "_stmt");
}

static bool find_autocmplt_type_at_stmt(struct autocmplt_data_t *ad, RzCore *core, RzLineBuffer *buf) {
	bool res = false;
	if (buf->index > 1 && buf->data[buf->index - 1] == '@' && buf->data[buf->index - 2] == '@') {
		struct guess_data_t *g = guess_next_autocmplt_token(core, buf, "=a", 1);
		if (g) {
			ut32 node_start = ts_node_start_byte(g->node);
			ut32 node_end = ts_node_end_byte(g->node);
			ut32 start = node_start - 3;
			if (buf->index > 2 && buf->data[buf->index - 3] == '@') {
				start--;
				node_start--;
			}
			if (is_arg_identifier_in_tmp_stmt(g->node) && node_start > 3) {
				res = fill_autocmplt_data_at_stmt(ad, start, node_end - 2);
			}
			guess_data_free(g);
		}
	} else if (buf->index > 0 && buf->data[buf->index - 1] == '@') {
		struct guess_data_t *g = guess_next_autocmplt_token(core, buf, " a", 1);
		if (g) {
			ut32 node_start = ts_node_start_byte(g->node);
			ut32 node_end = ts_node_end_byte(g->node);
			if (is_arg_identifier_in_tmp_stmt(g->node) && node_start > 2) {
				res = fill_autocmplt_data_at_stmt(ad, node_start - 2, node_end - 2);
			}
			guess_data_free(g);
		}
	}
	if (res) {
		return res;
	}

	char *start_iter = buf->data + buf->index;
	char *p = start_iter;
	// 4 is the longest @@ iter command (see @@dbta)
	// We don't care to look for the @@ pattern before that point, because it
	// wouldn't be a valid command anyway
	char *maximum_search = buf->index > 4 ? start_iter - 4 : start_iter;
	while (p > buf->data + 2 && p > maximum_search && !(*(p - 1) == '@' && *(p - 2) == '@') && *p != ' ') {
		p--;
	}
	if (p > buf->data + 2 && p > maximum_search && p + 4 - buf->data < RZ_LINE_BUFSIZE && *(p - 3) == '@' && *p != ' ') {
		// This handles the case <cmd> @@@c<TAB>
		int idx = buf->index;
		buf->index = p - buf->data + 1;
		char last_char = buf->data[buf->index - 1];
		buf->data[buf->index - 1] = '=';
		struct guess_data_t *g = guess_next_autocmplt_token(core, buf, "a", 0);
		buf->data[buf->index - 1] = last_char;
		buf->index = idx;
		if (g) {
			if (is_arg_identifier_in_tmp_stmt(g->node)) {
				res = fill_autocmplt_data_at_stmt(ad, p - buf->data - 3, buf->index);
			}
			guess_data_free(g);
		}
	} else if (p > buf->data + 2 && p > maximum_search && p + 4 - buf->data < RZ_LINE_BUFSIZE && *p != ' ') {
		// This handles the cases <cmd> @@d<TAB> and similar
		int idx = buf->index;
		buf->index = p - buf->data + 1;
		char last_char = buf->data[buf->index - 1];
		buf->data[buf->index - 1] = 'd';
		struct guess_data_t *g = guess_next_autocmplt_token(core, buf, "bta", 2);
		buf->data[buf->index - 1] = last_char;
		buf->index = idx;
		if (g) {
			const char *node_type = ts_node_type(g->node);
			if (!strcmp(node_type, "iter_dbta_stmt")) {
				res = fill_autocmplt_data_at_stmt(ad, p - buf->data - 2, buf->index);
			}
			guess_data_free(g);
		}
	} else if (buf->index > 1 && buf->data[buf->index - 2] == '@') {
		// This handles the cases <cmd> @v<TAB> and similar
		struct guess_data_t *g = guess_next_autocmplt_token(core, buf, ":a", 1);
		if (g) {
			ut32 node_start = ts_node_start_byte(g->node);
			ut32 node_end = ts_node_end_byte(g->node);
			if (is_arg_identifier_in_tmp_stmt(g->node) && node_start > 3 && node_end > 2) {
				res = fill_autocmplt_data_at_stmt(ad, node_start - 3, node_end - 2);
			}
			guess_data_free(g);
		}
	}
	return res;
}

static bool find_autocmplt_type_at_stmt_op(struct autocmplt_data_t *ad, RzCore *core, RzLineBuffer *buf,
	const char *tmp_op, const char *newtext, enum autocmplt_type_t ad_type) {
	bool res = false;
	struct guess_data_t *g = guess_next_autocmplt_token(core, buf, newtext, 0);
	if (g) {
		ut32 node_start = ts_node_start_byte(g->node);
		ut32 node_end = ts_node_end_byte(g->node);
		const char *node_type = ts_node_type(g->node);
		TSNode parent = get_arg_parent(g->node);
		if (!ts_node_is_null(parent)) {
			const char *parent_type = ts_node_type(parent);
			if (!strcmp(node_type, "arg_identifier") && !strcmp(parent_type, tmp_op)) {
				res = fill_autocmplt_data(ad, ad_type, node_start, node_end - 1);
			}
		}
		guess_data_free(g);
	}
	return res;
}

static bool find_autocmplt_type_quoted_arg(struct autocmplt_data_t *ad, RzCore *core, RzLineBuffer *buf, const char *quote, const char *quote_node_type) {
	bool res = false;
	struct guess_data_t *g = guess_next_autocmplt_token(core, buf, quote, 0);
	if (g) {
		const char *node_type = ts_node_type(g->node);
		ut32 node_start = ts_node_start_byte(g->node);
		ut32 node_end = ts_node_end_byte(g->node);
		if (!strcmp(node_type, quote_node_type) && !ts_node_has_error(g->node)) {
			res = fill_autocmplt_data_cmdarg(ad, node_start + 1, node_end - 1, g->input, g->node, core);
		}
		guess_data_free(g);
	}
	return res;
}

static bool find_autocmplt_type_arg_identifier(struct autocmplt_data_t *ad, RzCore *core, TSNode root, RzLineBuffer *buf, ut32 lstart, ut32 lend) {
	TSNode parent = get_arg_parent(root);
	if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_seek_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_RZNUM, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_fromto_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_RZNUM, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_arch_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_ARCH, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_bits_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_BITS, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_file_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_FILE, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_fs_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_FLAG_SPACE, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_reg_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_REG, lstart, lend);
	} else if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "tmp_eval_stmt")) {
		return fill_autocmplt_data(ad, AUTOCMPLT_EVAL_FULL, lstart, lend);
	} else {
		return fill_autocmplt_data_cmdarg(ad, lstart, lend, buf->data, root, core);
	}
}

/**
 * \brief Returns true and a properly filled \p ad when something to autocomplete was discovered.
 *
 * If possible, determine the type to autocomplete based on the syntax tree
 * returned by the rizin parser. However, sometimes the autocompletion has to
 * guess what type needs to be autocompleted, because the syntax tree contain
 * errors (as you write a command it may still be invalid) or it does not have
 * yet the token you want to autocomplete.
 */
static bool find_autocmplt_type(struct autocmplt_data_t *ad, RzCore *core, TSNode root, RzLineBuffer *buf) {
	ut32 lstart = ts_node_start_byte(root);
	ut32 lend = ts_node_end_byte(root);
	if (lend > buf->index) {
		lend = buf->index;
	}

	const char *root_type = ts_node_type(root);
	bool res = false;
	RZ_LOG_DEBUG("lstart = %d, lend = %d, type = %s\n", lstart, lend, root_type);
	if (!strcmp(root_type, "cmd_identifier") && buf->data[lend - 1] != ' ') {
		res = fill_autocmplt_data_cmdid(ad, lstart, lend);
	} else if (!strcmp(root_type, "statements") && ts_node_named_child_count(root) == 0) {
		res = fill_autocmplt_data_cmdid(ad, lend, lend);
	} else if (!strcmp(root_type, "arg_identifier")) {
		res = find_autocmplt_type_arg_identifier(ad, core, root, buf, lstart, lend);
	} else if (!strcmp(root_type, "double_quoted_arg")) {
		res = fill_autocmplt_data_cmdarg(ad, lstart + 1, lend, buf->data, root, core);
		if (res) {
			ad->res->end_string = "\" ";
		}
	} else if (!strcmp(root_type, "single_quoted_arg")) {
		res = fill_autocmplt_data_cmdarg(ad, lstart + 1, lend, buf->data, root, core);
		if (res) {
			ad->res->end_string = "' ";
		}
	}
	if (res) {
		return true;
	}

	// while writing a command and asking for autocompletion, the command
	// could still be invalid (e.g. missing ending `"`, missing ending `)`,
	// etc.). In this case we try to guess what is the correct type to
	// autocomplete.
	if (find_autocmplt_type_newcmd_or_arg(ad, core, buf)) {
		return true;
	} else if (find_autocmplt_type_quoted_arg(ad, core, buf, "\"", "double_quoted_arg")) {
		ad->res->end_string = "\" ";
		return true;
	} else if (find_autocmplt_type_quoted_arg(ad, core, buf, "'", "single_quoted_arg")) {
		ad->res->end_string = "' ";
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_seek_stmt", "a", AUTOCMPLT_RZNUM)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_fromto_stmt", "a b)", AUTOCMPLT_RZNUM)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_arch_stmt", "a", AUTOCMPLT_ARCH)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_bits_stmt", "1", AUTOCMPLT_BITS)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_file_stmt", "a", AUTOCMPLT_FILE)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_fs_stmt", "a", AUTOCMPLT_FLAG_SPACE)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_reg_stmt", "a", AUTOCMPLT_REG)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "tmp_eval_stmt", "a", AUTOCMPLT_EVAL_FULL)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "iter_offsets_stmt", "a", AUTOCMPLT_RZNUM)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "iter_offsetssizes_stmt", "a", AUTOCMPLT_RZNUM)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "iter_file_lines_stmt", "a", AUTOCMPLT_FILE)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "iter_flags_stmt", "a", AUTOCMPLT_FLAG)) {
		return true;
	} else if (find_autocmplt_type_at_stmt_op(ad, core, buf, "iter_function_stmt", "a", AUTOCMPLT_FUNCTION)) {
		return true;
	} else if (find_autocmplt_type_at_stmt(ad, core, buf)) {
		return true;
	}
	return false;
}

/**
 * Returns a \p RzLineNSCompletionResult structure containing all the info to
 * autocomplete what is currently in \p buf.
 */
RZ_API RzLineNSCompletionResult *rz_core_autocomplete_rzshell(RzCore *core, RzLineBuffer *buf, RzLinePromptType prompt_type) {
	RzLineNSCompletionResult *res = NULL;
	if (prompt_type == RZ_LINE_PROMPT_OFFSET) {
		res = rz_line_ns_completion_result_new(0, buf->length, NULL);
		int n = strlen(buf->data);
		autocmplt_cmd_arg_rznum(core, res, buf->data, n);
		return res;
	} else if (prompt_type == RZ_LINE_PROMPT_FILE) {
		res = rz_line_ns_completion_result_new(0, buf->length, NULL);
		size_t len = strlen(buf->data);
		autocmplt_cmd_arg_file(res, buf->data, len);
		return res;
	}

	struct autocmplt_data_t ad = { 0 };
	TSParser *parser = ts_parser_new();
	ts_parser_set_language(parser, (TSLanguage *)core->rcmd->language);

	TSTree *tree = ts_parser_parse_string(parser, NULL, buf->data, buf->length);
	TSNode root = ts_tree_root_node(tree);
	TSNode node = ts_node_named_descendant_for_byte_range(root, buf->index - 1, buf->index);
	if (ts_node_is_null(node)) {
		goto err;
	}
	char *root_string = ts_node_string(root);
	char *node_string = ts_node_string(node);
	RZ_LOG_DEBUG("autocomplete_rzshell root = '%s'\n", root_string);
	RZ_LOG_DEBUG("autocomplete_rzshell node = '%s'\n", node_string);
	free(node_string);
	free(root_string);

	// the autocompletion works in 2 steps:
	// 1) it finds the proper type to autocomplete (sometimes it guesses)
	// 2) it traverses the proper RzCore structures to provide opportune
	//    autocompletion options for the discovered type
	bool type_found = find_autocmplt_type(&ad, core, node, buf);
	if (type_found) {
		switch (ad.type) {
		case AUTOCMPLT_CMD_ID:
			autocmplt_cmdidentifier(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_CMD_ARG:
			autocmplt_cmd_arg(core, ad.res, ad.cd, ad.i_arg, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_AT_STMT:
			autocmplt_at_stmt(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_RZNUM:
			autocmplt_cmd_arg_rznum(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_ARCH:
			autocmplt_arch(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_BITS:
			autocmplt_bits(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_FILE:
			autocmplt_cmd_arg_file(ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_FLAG_SPACE:
			autocmplt_flag_space(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_REG:
			autocmplt_reg(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_EVAL_FULL:
			autocmplt_cmd_arg_eval_full(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_FLAG:
			autocmplt_cmd_arg_flag(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_FUNCTION:
			autocmplt_cmd_arg_fcn(core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		default:
			break;
		}
	}

err:
	ts_tree_delete(tree);
	ts_parser_delete(parser);
	return ad.res;
}
