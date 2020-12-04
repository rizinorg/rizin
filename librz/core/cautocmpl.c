// SPDX-License-Identifier: LGPL-3.0-only

#include <tree_sitter/api.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <rz_cmd.h>

/**
 * Describe what needs to be autocompleted.
 */
enum autocmplt_type_t {
	AUTOCMPLT_UNKNOWN = 0, ///< Unknown, nothing will be autocompleted
	AUTOCMPLT_CMD_ID, ///< A command identifier (aka command name) needs to be autocompleted
	AUTOCMPLT_CMD_ARG, ///< The argument of an arged_command (see grammar.js) needs to be autocompleted
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
	ts_tree_delete (g->tree);
	ts_parser_delete (g->parser);
	free (g->input);
	free (g);
}

/**
 * Modify the input in \p buf to add additional characters, trying to detect
 * what token could go in the current position of the buffer. For example, to
 * detect that a CMD_ID is expected at * `?e $(<TAB>`, you could try inserting
 * a letter and see what would be the new syntax tree.
 */
static struct guess_data_t *guess_next_autocmplt_token(RzCore *core, RzLineBuffer *buf, const char *fake_text) {
	size_t fake_len = strlen (fake_text);
	char *tmp = malloc (strlen (buf->data) + 1 + fake_len);
	memcpy (tmp, buf->data, buf->index);
	memcpy (tmp + buf->index, fake_text, fake_len);
	memcpy (tmp + buf->index + fake_len, buf->data + buf->index, buf->length - buf->index);
	tmp[buf->length + fake_len] = '\0';

	TSParser *parser = ts_parser_new ();
	ts_parser_set_language (parser, (TSLanguage *)core->rcmd->language);
	TSTree *tree = ts_parser_parse_string (parser, NULL, tmp, buf->length + fake_len);
	TSNode root = ts_tree_root_node (tree);
	TSNode node = ts_node_named_descendant_for_byte_range (root, buf->index, buf->index + 1);
	if (ts_node_is_null (node)) {
		goto err;
	}

	struct guess_data_t *g = RZ_NEW0 (struct guess_data_t);
	g->node = node;
	g->tree = tree;
	g->parser = parser;
	g->input = tmp;
	return g;

err:
	ts_tree_delete (tree);
	ts_parser_delete (parser);
	free (tmp);
	return NULL;
}

static bool do_autocmplt_cmdidentifier(RzCmd *cmd, const char *name, void *user) {
	struct autocmplt_cmdidentifier_t *u = (struct autocmplt_cmdidentifier_t *)user;
	if (!strncmp (name, u->s, u->len)) {
		rz_line_ns_completion_result_add (u->res, name);
	}
	return true;
}

static void autocmplt_cmdidentifier(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	struct autocmplt_cmdidentifier_t u = {
		.res = res,
		.s = s,
		.len = len,
	};
	rz_cmd_foreach_cmdname (core->rcmd, do_autocmplt_cmdidentifier, &u);
}

static void autocmplt_cmd_arg_file(RzLineNSCompletionResult *res, const char *s, size_t len) {
	char *input = rz_str_ndup (s, len);
	if (!input) {
		return;
	}

	if (RZ_STR_ISEMPTY (input)) {
		free (input);
		input = strdup (".");
	} else if (rz_str_startswith (input, "~")) {
		input = rz_str_replace (input, "~", rz_str_home (NULL), 0);
	} else if (!rz_file_is_abspath (input) && !rz_str_startswith (input, ".")) {
		const char *fmt = ".%s%s";
#if __WINDOWS__
		if (strchr (input, ':')) {
			fmt = "%.0s%s";
		}
#endif
		char *tmp = rz_str_newf (fmt, RZ_SYS_DIR, input);
		if (!tmp) {
			return;
		}
		free (input);
		input = tmp;
	}
	char *basedir = rz_file_dirname (input);
	const char *basename = rz_file_basename (input + 1);

	RzList *l = rz_sys_dir (basedir);
	RzListIter *iter;
	char *filename;
	rz_list_foreach (l, iter, filename) {
		if (!strcmp (filename, ".") || !strcmp (filename, "..")) {
			continue;
		}
		if (!strncmp (filename, basename, strlen (basename)))  {
			// TODO: only show/autocomplete the last part of the path, not the whole path
			char *tmpfilename = rz_file_path_join (basedir, filename);
			if (rz_file_is_directory (tmpfilename)) {
				res->end_string = RZ_SYS_DIR;
			}
			rz_line_ns_completion_result_add (res, tmpfilename);
			free (tmpfilename);
		}
	}
	rz_list_free (l);
	free (input);
}

static void autocmplt_cmd_arg_env(RzLineNSCompletionResult *res, const char *s, size_t len) {
	char **env;
	for (env = rz_sys_get_environ (); *env; env++) {
		const char *eq = strchr (*env, '=');
		char *envkey = eq? rz_str_ndup (*env, eq - *env): strdup (*env);
		if (!strncmp (envkey, s, len)) {
			rz_line_ns_completion_result_add (res, envkey);
		}
		free (envkey);
	}
}

static void autocmplt_cmd_arg_macro(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzCmdMacroItem *item;
	RzListIter *iter;
	rz_list_foreach (core->rcmd->macro.macros, iter, item) {
		char *p = item->name;
		if (!strncmp (p, s, len)) {
			rz_line_ns_completion_result_add (res, p);
		}
	}
}

static bool offset_prompt_add_flag(RzFlagItem *fi, void *user) {
	RzLineNSCompletionResult *res = (RzLineNSCompletionResult *)user;
	rz_line_ns_completion_result_add (res, fi->name);
	return true;
}

static void autocmplt_cmd_arg_num(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	rz_flag_foreach_prefix (core->flags, s, len, offset_prompt_add_flag, res);
}

static void autocmplt_cmd_arg_zign_space(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzSpaces *zs = &core->anal->zign_spaces;
	RzSpace *space;
	RzSpaceIter it;

	rz_spaces_foreach (zs, it, space) {
		if (!strncmp (space->name, s, len)) {
			rz_line_ns_completion_result_add (res, space->name);
		}
	}

	if (len == 0) {
		rz_line_ns_completion_result_add (res, "*");
	}
}

static void autocmplt_cmd_arg_fcn(RzCore *core, RzLineNSCompletionResult *res, const char *s, size_t len) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->anal->fcns, iter, fcn) {
		char *name = rz_core_anal_fcn_name (core, fcn);
		if (!strncmp (name, s, len)) {
			rz_line_ns_completion_result_add (res, name);
		}
		free (name);
	}
}

static void autocmplt_cmd_arg_choices(RzLineNSCompletionResult *res, const char *s, size_t len, const RzCmdDescArg *arg) {
	const char **c;
	for (c = arg->choices; *c; c++) {
		if (!strncmp (*c, s, len)) {
			rz_line_ns_completion_result_add (res, *c);
		}
	}
}

static bool is_arg_type(const char *type) {
	return !strcmp (type, "concatenation") || !strcmp (type, "arg") ||
		!strcmp (type, "args") || !strcmp (type, "arg_identifier") ||
		!strcmp (type, "double_quoted_arg") || !strcmp (type, "single_quoted_arg");
}

static RzCmdDesc *get_cd_from_cmdid(RzCore *core, const char *data, TSNode cmd_id) {
	ut32 command_start = ts_node_start_byte (cmd_id);
	ut32 command_end = ts_node_end_byte (cmd_id);
	char *cmdid = rz_str_ndup (data + command_start, command_end - command_start);
	RzCmdDesc *cd = rz_cmd_desc_get_exec (rz_cmd_get_desc (core->rcmd, cmdid));
	free (cmdid);
	return cd;
}

static RzCmdDesc *get_cd_from_arg(RzCore *core, const char *data, TSNode arg) {
	if (ts_node_is_null (arg)) {
		return NULL;
	}
	const char *parent_type;
	TSNode parent = arg;
	do {
		parent = ts_node_parent (parent);
		if (ts_node_is_null (parent)) {
			return NULL;
		}
		parent_type = ts_node_type (parent);
	} while (is_arg_type (parent_type));

	if (strcmp (parent_type, "arged_command")) {
		return NULL;
	}

	TSNode cmdid = ts_node_named_child (parent, 0);
	const char *node_type = ts_node_is_null (cmdid) ? "" : ts_node_type (cmdid);
	if (strcmp (node_type, "cmd_identifier")) {
		return false;
	}

	return get_cd_from_cmdid (core, data, cmdid);
}

static size_t get_arg_number(TSNode arg) {
	const char *arg_type = ts_node_type (arg);
	while (strcmp (arg_type, "arg")) {
		arg = ts_node_parent (arg);
		arg_type = ts_node_type (arg);
	}

	size_t i_arg = 0;
	arg = ts_node_prev_sibling (arg);
	while (!ts_node_is_null (arg)) {
		i_arg++;
		arg = ts_node_prev_sibling (arg);
	}
	return i_arg;
}

/**
 * Fill \p res with all the available options for the argument i_arg-th of the
 * command \p cd . This is based on the type of argument a command may accept.
 */
static void autocmplt_cmd_arg(RzCore *core, RzLineNSCompletionResult *res, const RzCmdDesc *cd, size_t i_arg, const char *s, size_t len) {
	const RzCmdDescArg *arg = cd->help->args;
	size_t i;
	for (i = 0; i < i_arg && arg && arg->name; i++, arg++);
	if (!arg || !arg->name) {
		return;
	}

	RzCmdArgType arg_type = arg->type;
	switch (arg_type) {
	case RZ_CMD_ARG_TYPE_FILE:
		autocmplt_cmd_arg_file (res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ENV:
		autocmplt_cmd_arg_env (res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_ZIGN_SPACE:
		autocmplt_cmd_arg_zign_space (core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_CHOICES:
		autocmplt_cmd_arg_choices (res, s, len, arg);
		break;
	case RZ_CMD_ARG_TYPE_FCN:
		autocmplt_cmd_arg_fcn (core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_MACRO:
		autocmplt_cmd_arg_macro (core, res, s, len);
		break;
	case RZ_CMD_ARG_TYPE_NUM:
		autocmplt_cmd_arg_num (core, res, s, len);
		break;
	default:
		break;
	}
}

/**
 * Fill the \p ad structure with all the data required to autocomplete the
 * cmdidentifier of a command.
 */
static bool fill_autocmplt_data_cmdid(struct autocmplt_data_t *ad, ut32 start, ut32 end) {
	ad->type = AUTOCMPLT_CMD_ID;
	ad->res = rz_line_ns_completion_result_new (start, end, NULL);
	return true;
}

/**
 * Fill the \p ad structure with all the data required to autocomplete the
 * argument of a command. This includes the command descriptor of the command
 * and the position of the argument that needs to be auto completed.
 */
static bool fill_autocmplt_data_cmdarg(struct autocmplt_data_t *ad, ut32 start, ut32 end, const char *s, TSNode node, RzCore *core) {
	ad->type = AUTOCMPLT_CMD_ARG;
	ad->cd = get_cd_from_arg (core, s, node);
	if (!ad->cd) {
		return false;
	}

	ad->i_arg = get_arg_number (node);

	const RzCmdDescArg *arg = ad->cd->help->args;
	size_t i;
	for (i = 0; i < ad->i_arg && arg && arg->name; i++, arg++);
	if (!arg || !arg->name) {
		return false;
	}

	ad->res = rz_line_ns_completion_result_new (start, end, NULL);
	return true;
}

static bool find_autocmplt_type_newcmd_or_arg(struct autocmplt_data_t *ad, RzCore *core, RzLineBuffer *buf) {
	bool res = false;
	struct guess_data_t *g = guess_next_autocmplt_token (core, buf, "a");
	if (g) {
		const char *node_type = ts_node_type (g->node);
		ut32 node_start = ts_node_start_byte (g->node);
		if (!strcmp (node_type, "cmd_identifier")) {
			res = fill_autocmplt_data_cmdid (ad, node_start, node_start);
		} else if (is_arg_type (node_type)) {
			res = fill_autocmplt_data_cmdarg (ad, node_start, node_start, g->input, g->node, core);
		}
		guess_data_free (g);
	}
	return res;
}

static bool find_autocmplt_type_quoted_arg(struct autocmplt_data_t *ad, RzCore *core, RzLineBuffer *buf, const char *quote, const char *quote_node_type) {
	bool res = false;
	struct guess_data_t *g = guess_next_autocmplt_token (core, buf, quote);
	if (g) {
		const char *node_type = ts_node_type (g->node);
		ut32 node_start = ts_node_start_byte (g->node);
		ut32 node_end = ts_node_end_byte (g->node);
		if (!strcmp (node_type, quote_node_type)) {
			res = fill_autocmplt_data_cmdarg (ad, node_start + 1, node_end - 1, g->input, g->node, core);
		}
		guess_data_free (g);
	}
	return res;
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
	ut32 lstart = ts_node_start_byte (root);
	ut32 lend = ts_node_end_byte (root);
	if (lend > buf->index) {
		lend = buf->index;
	}

	const char *root_type = ts_node_type (root);
	bool res = false;
	RZ_LOG_DEBUG ("lstart = %d, lend = %d, type = %s\n", lstart, lend, root_type);
	if (!strcmp (root_type, "cmd_identifier") && buf->data[lend - 1] != ' ') {
		res = fill_autocmplt_data_cmdid (ad, lstart, lend);
	} else if (!strcmp (root_type, "commands") && ts_node_named_child_count (root) == 0) {
		res = fill_autocmplt_data_cmdid (ad, lend, lend);
	} else if (!strcmp (root_type, "arg_identifier")) {
		res = fill_autocmplt_data_cmdarg (ad, lstart, lend, buf->data, root, core);
	} else if (!strcmp (root_type, "double_quoted_arg")) {
		res = fill_autocmplt_data_cmdarg (ad, lstart + 1, lend, buf->data, root, core);
		if (res) {
			ad->res->end_string = "\" ";
		}
	} else if (!strcmp (root_type, "single_quoted_arg")) {
		res = fill_autocmplt_data_cmdarg (ad, lstart + 1, lend, buf->data, root, core);
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
	if (find_autocmplt_type_newcmd_or_arg (ad, core, buf)) {
		return true;
	} else if (find_autocmplt_type_quoted_arg (ad, core, buf, "\"", "double_quoted_arg")) {
		ad->res->end_string = "\" ";
		return true;
	} else if (find_autocmplt_type_quoted_arg (ad, core, buf, "'", "single_quoted_arg")) {
		ad->res->end_string = "' ";
		return true;
	}
	return false;
}

/**
 * Returns a \p RzLineNSCompletionResult structure containing all the info to
 * autocomplete what is currently in \p buf.
 */
RZ_API RzLineNSCompletionResult *rz_core_autocomplete_newshell(RzCore *core, RzLineBuffer *buf, RzLinePromptType prompt_type) {
	RzLineNSCompletionResult *res = NULL;
	if (prompt_type == RZ_LINE_PROMPT_OFFSET) {
		res = rz_line_ns_completion_result_new (0, buf->length, NULL);
		int n = strlen (buf->data);
		autocmplt_cmd_arg_num (core, res, buf->data, n);
		return res;
	} else if (prompt_type == RZ_LINE_PROMPT_FILE) {
		res = rz_line_ns_completion_result_new (0, buf->length, NULL);
		size_t len = strlen (buf->data);
		autocmplt_cmd_arg_file (res, buf->data, len);
		return res;
	}

	struct autocmplt_data_t ad = { 0 };
	TSParser *parser = ts_parser_new ();
	ts_parser_set_language (parser, (TSLanguage *)core->rcmd->language);

	TSTree *tree = ts_parser_parse_string (parser, NULL, buf->data, buf->length);
	TSNode root = ts_tree_root_node (tree);
	RZ_LOG_DEBUG ("root = '%s'\n", ts_node_string (root));

	TSNode node = ts_node_named_descendant_for_byte_range (root, buf->index - 1, buf->index);
	if (ts_node_is_null (node)) {
		goto err;
	}
	RZ_LOG_DEBUG ("cur_node = '%s'\n", ts_node_string (node));

	// the autocompletion works in 2 steps:
	// 1) it finds the proper type to autocomplete (sometimes it guesses)
	// 2) it traverses the proper RzCore structures to provide opportune
	//    autocompletion options for the discovered type
	bool type_found = find_autocmplt_type (&ad, core, node, buf);
	if (type_found) {
		switch (ad.type) {
		case AUTOCMPLT_CMD_ID:
			autocmplt_cmdidentifier (core, ad.res, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		case AUTOCMPLT_CMD_ARG:
			autocmplt_cmd_arg (core, ad.res, ad.cd, ad.i_arg, buf->data + ad.res->start, ad.res->end - ad.res->start);
			break;
		default:
			break;
		}
	}

err:
	ts_tree_delete (tree);
	ts_parser_delete (parser);
	return ad.res;
}
