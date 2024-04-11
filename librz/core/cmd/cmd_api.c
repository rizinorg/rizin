// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_util.h>
#include <stdio.h>
#include <rz_cons.h>
#include <rz_cmd.h>
#include <rz_core.h>

/*!
 * Number of sub-commands to show as options when displaying the help of a
 * command. When a command has more options than MAX_CHILDREN_SHOW, `?` is shown
 * instead.
 *
 * Example with MAX_CHILDREN_SHOW=3:
 * w -> wa
 *   -> wb
 *   -> wc
 *
 * When doing `?`, you would see:
 * w[abc]
 *
 * If there is also:
 *   -> wd
 * you would see:
 * w[?]
 */
#define MAX_CHILDREN_SHOW 7

#define MIN_SUMMARY_WIDTH    6
#define MAX_RIGHT_ALIGHNMENT 20

// NOTE: this should be in sync with SPECIAL_CHARACTERS in
//       rizin-shell-parser grammar, except for ", ' and
//       whitespaces, because we let cmd_substitution_arg create
//       new arguments
static const char *SPECIAL_CHARS_REGULAR = "@;~$#|`\"'()<>";
static const char *SPECIAL_CHARS_REGULAR_SINGLE = "@;~$#|`\"'()<> ";
static const char *SPECIAL_CHARS_PF = "@;~$#|`\"'<>";
static const char *SPECIAL_CHARS_DOUBLE_QUOTED = "\"$()`";
static const char *SPECIAL_CHARS_SINGLE_QUOTED = "'";

static const RzCmdDescHelp not_defined_help = {
	.usage = "Usage not defined",
	.summary = "Help summary not defined",
	.description = "Help description not defined.",
};

static const RzCmdDescHelp root_help = {
	.usage = "[.][times][cmd][~grep][@[@iter]addr][|>pipe] ; ...",
	.description = "",
	.sort_subcommands = true,
};

static const struct argv_modes_t {
	const char *suffix;
	const char *summary_suffix;
	RzOutputMode mode;
} argv_modes[] = {
	{ "", "", RZ_OUTPUT_MODE_STANDARD },
	{ "j", " (JSON mode)", RZ_OUTPUT_MODE_JSON },
	{ "*", " (rizin mode)", RZ_OUTPUT_MODE_RIZIN },
	{ "q", " (quiet mode)", RZ_OUTPUT_MODE_QUIET },
	{ "Q", " (quietest mode)", RZ_OUTPUT_MODE_QUIETEST },
	{ "k", " (sdb mode)", RZ_OUTPUT_MODE_SDB },
	{ "l", " (verbose mode)", RZ_OUTPUT_MODE_LONG },
	{ "J", " (verbose JSON mode)", RZ_OUTPUT_MODE_LONG_JSON },
	{ "t", " (table mode)", RZ_OUTPUT_MODE_TABLE },
};

RZ_IPI int rz_output_mode_to_char(RzOutputMode mode) {
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(argv_modes); i++) {
		if (argv_modes[i].mode == mode) {
			return argv_modes[i].suffix[0];
		}
	}
	return -1;
}

RZ_IPI const char *rz_output_mode_to_summary(RzOutputMode mode) {
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(argv_modes); i++) {
		if (argv_modes[i].mode == mode) {
			return argv_modes[i].summary_suffix;
		}
	}
	return "";
}

#define NCMDS (sizeof(cmd->cmds) / sizeof(*cmd->cmds))
RZ_LIB_VERSION(rz_cmd);

static bool fill_details(RzCmd *cmd, RzCmdDesc *cd, RzStrBuf *sb, bool use_color);

static int cd_sort(const void *a, const void *b, void *user) {
	RzCmdDesc *ca = (RzCmdDesc *)a;
	RzCmdDesc *cb = (RzCmdDesc *)b;
	return rz_str_casecmp(ca->name, cb->name);
}

static bool cmd_desc_set_parent(RzCmd *cmd, RzCmdDesc *cd, RzCmdDesc *parent) {
	rz_return_val_if_fail(cd && !cd->parent, false);
	if (parent) {
		switch (parent->type) {
		case RZ_CMD_DESC_TYPE_OLDINPUT:
		case RZ_CMD_DESC_TYPE_GROUP:
		case RZ_CMD_DESC_TYPE_INNER:
			break;
		case RZ_CMD_DESC_TYPE_ARGV:
		case RZ_CMD_DESC_TYPE_ARGV_MODES:
		case RZ_CMD_DESC_TYPE_ARGV_STATE:
		case RZ_CMD_DESC_TYPE_FAKE:
			rz_warn_if_reached();
			return false;
		}
	}
	if (parent) {
		cd->parent = parent;
		rz_pvector_push(&parent->children, cd);
		if (!cmd->batch && parent->help->sort_subcommands) {
			rz_pvector_sort(&parent->children, cd_sort, NULL);
		}
		parent->n_children++;
	}
	return true;
}

static void cmd_desc_unset_parent(RzCmdDesc *cd) {
	rz_return_if_fail(cd && cd->parent);
	RzCmdDesc *parent = cd->parent;
	rz_pvector_remove_data(&parent->children, cd);
	parent->n_children--;
	cd->parent = NULL;
}

static void cmd_desc_remove_from_ht_cmds(RzCmd *cmd, RzCmdDesc *cd) {
	void **it_cd;
	ht_pp_delete(cmd->ht_cmds, cd->name);
	rz_cmd_desc_children_foreach(cd, it_cd) {
		RzCmdDesc *child_cd = *it_cd;
		cmd_desc_remove_from_ht_cmds(cmd, child_cd);
	}
}

static void cmd_desc_free(RzCmdDesc *cd) {
	if (!cd) {
		return;
	}

	rz_pvector_clear(&cd->children);
	free(cd->name);
	free(cd);
}

static RzCmdDesc *create_cmd_desc(RzCmd *cmd, RzCmdDesc *parent, RzCmdDescType type, const char *name, const RzCmdDescHelp *help, bool ht_insert) {
	RzCmdDesc *res = RZ_NEW0(RzCmdDesc);
	if (!res) {
		return NULL;
	}
	res->type = type;
	res->name = strdup(name);
	if (!res->name) {
		goto err;
	}
	res->n_children = 0;
	res->help = help ? help : &not_defined_help;
	rz_pvector_init(&res->children, (RzPVectorFree)cmd_desc_free);
	if (ht_insert && !ht_pp_insert(cmd->ht_cmds, name, res)) {
		goto err;
	}
	cmd_desc_set_parent(cmd, res, parent);
	return res;
err:
	cmd_desc_free(res);
	return NULL;
}

RZ_API void rz_cmd_alias_init(RzCmd *cmd) {
	cmd->aliases.count = 0;
	cmd->aliases.keys = NULL;
	cmd->aliases.values = NULL;
}

static void macro_fini(RzCmdMacro *macro) {
	if (!macro) {
		return;
	}
	free(macro->name);
	free(macro->code);
	for (size_t i = 0; i < macro->nargs; i++) {
		free(macro->args[i]);
	}
	free(macro->args);
}

static void macro_free(RzCmdMacro *macro) {
	macro_fini(macro);
	free(macro);
}

static void free_macro_kv(HtPPKv *kv) {
	free(kv->key);
	macro_free(kv->value);
}

/**
 * \brief Create a generic instance of RzCmd.
 *
 * \param core Reference to RzCore, passed to each command handler
 * \param has_cons Whether RzCons is available for use or not
 * \return New reference to RzCmd or NULL
 */
RZ_API RzCmd *rz_cmd_new(RzCore *core, bool has_cons) {
	int i;
	RzCmd *cmd = RZ_NEW0(RzCmd);
	if (!cmd) {
		return cmd;
	}
	cmd->has_cons = has_cons;
	for (i = 0; i < NCMDS; i++) {
		cmd->cmds[i] = NULL;
	}
	cmd->core = core;
	cmd->nullcallback = NULL;
	cmd->macros = ht_pp_new(NULL, free_macro_kv, NULL);
	cmd->ht_cmds = ht_pp_new0();
	cmd->root_cmd_desc = create_cmd_desc(cmd, NULL, RZ_CMD_DESC_TYPE_GROUP, "", &root_help, true);
	rz_cmd_alias_init(cmd);
	return cmd;
}

RZ_API RzCmd *rz_cmd_free(RzCmd *cmd) {
	int i;
	if (!cmd) {
		return NULL;
	}
	ht_up_free(cmd->ts_symbols_ht);
	rz_cmd_alias_free(cmd);
	ht_pp_free(cmd->ht_cmds);
	for (i = 0; i < NCMDS; i++) {
		if (cmd->cmds[i]) {
			RZ_FREE(cmd->cmds[i]);
		}
	}
	ht_pp_free(cmd->macros);
	cmd_desc_free(cmd->root_cmd_desc);
	free(cmd);
	return NULL;
}

/**
 * \brief Get the root command descriptor
 */
RZ_API RzCmdDesc *rz_cmd_get_root(RzCmd *cmd) {
	return cmd->root_cmd_desc;
}

/**
 * \brief Mark the start of the batched changes to RzCmd
 *
 * Commands added after this call won't be sorted until \p rz_cmd_batch_end is
 * called.
 */
RZ_API void rz_cmd_batch_start(RzCmd *cmd) {
	cmd->batch = true;
}

static void sort_groups(RzCmdDesc *group) {
	void **it_cd;

	if (group->help->sort_subcommands) {
		rz_pvector_sort(&group->children, cd_sort, NULL);
	}
	rz_cmd_desc_children_foreach(group, it_cd) {
		RzCmdDesc *cd = *(RzCmdDesc **)it_cd;
		if (cd->n_children) {
			sort_groups(cd);
		}
	}
}

/**
 * \brief Mark the end of the batched changes to RzCmd
 *
 * All groups are sorted, if necessary. Call \p rz_cmd_batch_start before using
 * this function.
 */
RZ_API void rz_cmd_batch_end(RzCmd *cmd) {
	cmd->batch = false;
	sort_groups(rz_cmd_get_root(cmd));
}

static RzOutputMode suffix2mode(const char *suffix) {
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(argv_modes); i++) {
		if (!strcmp(suffix, argv_modes[i].suffix)) {
			return argv_modes[i].mode;
		}
	}
	return 0;
}

static bool has_cd_submodes(const RzCmdDesc *cd) {
	return cd->type == RZ_CMD_DESC_TYPE_ARGV_MODES || cd->type == RZ_CMD_DESC_TYPE_ARGV_STATE;
}

static bool is_valid_argv_modes(RzCmdDesc *cd, char last_letter) {
	if (!cd || !has_cd_submodes(cd) || last_letter == '\0') {
		return false;
	}
	char suffix[] = { last_letter, '\0' };
	return cd->d.argv_modes_data.modes & suffix2mode(suffix);
}

RZ_API RzCmdDesc *rz_cmd_desc_get_exec(RzCmdDesc *cd) {
	if (!cd) {
		return NULL;
	}
	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_GROUP:
		return cd->d.group_data.exec_cd;
	default:
		return cd;
	}
}

static RzCmdDesc *cmd_get_desc_best(RzCmd *cmd, const char *cmd_identifier, bool best_match) {
	rz_return_val_if_fail(cmd && cmd_identifier, NULL);
	char *cmdid = strdup(cmd_identifier);
	char *end_cmdid = cmdid + strlen(cmdid);
	RzCmdDesc *res = NULL;
	bool is_exact_match = true;
	char last_letter = '\0', o_last_letter = end_cmdid > cmdid ? *(end_cmdid - 1) : '\0';
	// match longer commands first
	while (*cmdid) {
		RzCmdDesc *cd = ht_pp_find(cmd->ht_cmds, cmdid, NULL);
		if (cd) {
			switch (cd->type) {
			case RZ_CMD_DESC_TYPE_ARGV:
			case RZ_CMD_DESC_TYPE_GROUP:
			case RZ_CMD_DESC_TYPE_FAKE:
			case RZ_CMD_DESC_TYPE_ARGV_MODES:
			case RZ_CMD_DESC_TYPE_ARGV_STATE:
				if (!best_match && (!is_exact_match && !is_valid_argv_modes(rz_cmd_desc_get_exec(cd), last_letter))) {
					break;
				}
				res = cd;
				goto out;
			case RZ_CMD_DESC_TYPE_OLDINPUT:
				res = cd;
				goto out;
			case RZ_CMD_DESC_TYPE_INNER:
				break;
			}
		}
		// only the last letter is considered, then we zero last_letter
		last_letter = o_last_letter;
		o_last_letter = '\0';

		is_exact_match = false;
		*(--end_cmdid) = '\0';
	}
out:
	free(cmdid);
	return res;
}

/**
 * \brief Retrieve the command descriptor that best matches the name \p cmd_identifier
 *
 * Check if there is a command with exactly the name \p cmd_identifier. If there
 * isn't, it tries to find the best matching one (right now by by removing one
 * letter at a time, but this matching algorithm may be improved later).
 *
 * \param cmd Reference to RzCmd instance
 * \param cmd_identifier Name of the command to search
 * \return RzCmdDesc reference or NULL if not found
 */
RZ_API RzCmdDesc *rz_cmd_get_desc_best(RzCmd *cmd, const char *cmd_identifier) {
	return cmd_get_desc_best(cmd, cmd_identifier, true);
}

/**
 * \brief Retrieve the command descriptor for the command named \p cmd_identifier
 *
 * Check if there is a command with exactly the name \p cmd_identifier.
 *
 * If there isn't, it removes one letter at a time to be compatible with radare2
 * behaviour until all commands are converted to rzshell. This best-matching
 * works only to find OLDINPUT command references.
 *
 * \param cmd Reference to RzCmd instance
 * \param cmd_identifier Name of the command to search
 * \return RzCmdDesc reference or NULL if not found
 */
RZ_API RzCmdDesc *rz_cmd_get_desc(RzCmd *cmd, const char *cmd_identifier) {
	return cmd_get_desc_best(cmd, cmd_identifier, false);
}

/**
 * \brief Set the default mode of the command descriptor, if the type allows it.
 *
 * Command descriptors that support multiple output modes can also have a
 * default one. This function can be used to set it.
 *
 * \return True if the default output mode was changed, false otherwise.
 */
RZ_API bool rz_cmd_desc_set_default_mode(RzCmdDesc *cd, RzOutputMode mode) {
	rz_return_val_if_fail(cd, false);

	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
		if (cd->d.argv_modes_data.modes & RZ_OUTPUT_MODE_STANDARD) {
			return false;
		}
		cd->d.argv_modes_data.default_mode = mode;
		return true;
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		if (cd->d.argv_state_data.modes & RZ_OUTPUT_MODE_STANDARD) {
			return false;
		}
		cd->d.argv_state_data.default_mode = mode;
		return true;
	case RZ_CMD_DESC_TYPE_GROUP: {
		RzCmdDesc *exec_cd = rz_cmd_desc_get_exec(cd);
		if (exec_cd) {
			return rz_cmd_desc_set_default_mode(exec_cd, mode);
		}
		return false;
	}
	default:
		return false;
	}
}

RZ_API char **rz_cmd_alias_keys(RzCmd *cmd, int *sz) {
	if (sz) {
		*sz = cmd->aliases.count;
	}
	return cmd->aliases.keys;
}

RZ_API void rz_cmd_alias_free(RzCmd *cmd) {
	int i; // find
	for (i = 0; i < cmd->aliases.count; i++) {
		free(cmd->aliases.keys[i]);
		free(cmd->aliases.values[i]);
	}
	cmd->aliases.count = 0;
	RZ_FREE(cmd->aliases.keys);
	RZ_FREE(cmd->aliases.values);
	free(cmd->aliases.remote);
}

RZ_API bool rz_cmd_alias_del(RzCmd *cmd, const char *k) {
	int i; // find
	for (i = 0; i < cmd->aliases.count; i++) {
		if (!k || !strcmp(k, cmd->aliases.keys[i])) {
			RZ_FREE(cmd->aliases.values[i]);
			cmd->aliases.count--;
			if (cmd->aliases.count > 0) {
				if (i > 0) {
					free(cmd->aliases.keys[i]);
					cmd->aliases.keys[i] = cmd->aliases.keys[0];
					free(cmd->aliases.values[i]);
					cmd->aliases.values[i] = cmd->aliases.values[0];
				}
				memmove(cmd->aliases.values,
					cmd->aliases.values + 1,
					cmd->aliases.count * sizeof(void *));
				memmove(cmd->aliases.keys,
					cmd->aliases.keys + 1,
					cmd->aliases.count * sizeof(void *));
			}
			return true;
		}
	}
	return false;
}

// XXX: use a hashtable or any other standard data structure
RZ_API int rz_cmd_alias_set(RzCmd *cmd, const char *k, const char *v, int remote) {
	void *tofree = NULL;
	if (!strncmp(v, "base64:", 7)) {
		ut8 *s = rz_base64_decode_dyn(v + 7, -1);
		if (s) {
			tofree = s;
			v = (const char *)s;
		}
	}
	int i;
	for (i = 0; i < cmd->aliases.count; i++) {
		int matches = !strcmp(k, cmd->aliases.keys[i]);
		if (matches) {
			free(cmd->aliases.values[i]);
			cmd->aliases.values[i] = strdup(v);
			free(tofree);
			return 1;
		}
	}

	i = cmd->aliases.count++;
	char **K = (char **)realloc(cmd->aliases.keys,
		sizeof(char *) * cmd->aliases.count);
	if (K) {
		cmd->aliases.keys = K;
		int *R = (int *)realloc(cmd->aliases.remote,
			sizeof(int) * cmd->aliases.count);
		if (R) {
			cmd->aliases.remote = R;
			char **V = (char **)realloc(cmd->aliases.values,
				sizeof(char *) * cmd->aliases.count);
			if (V) {
				cmd->aliases.values = V;
				cmd->aliases.keys[i] = strdup(k);
				cmd->aliases.values[i] = strdup(v);
				cmd->aliases.remote[i] = remote;
			}
		}
	}
	free(tofree);
	return 0;
}

RZ_API char *rz_cmd_alias_get(RzCmd *cmd, const char *k, int remote) {
	int matches, i;
	if (!cmd || !k) {
		return NULL;
	}
	for (i = 0; i < cmd->aliases.count; i++) {
		matches = 0;
		if (remote) {
			if (cmd->aliases.remote[i]) {
				matches = !strncmp(k, cmd->aliases.keys[i],
					strlen(cmd->aliases.keys[i]));
			}
		} else {
			matches = !strcmp(k, cmd->aliases.keys[i]);
		}
		if (matches) {
			return cmd->aliases.values[i];
		}
	}
	return NULL;
}

RZ_API int rz_cmd_add(RzCmd *c, const char *cmd, RzCmdCb cb) {
	int idx = (ut8)cmd[0];
	RzCmdItem *item = c->cmds[idx];
	if (!item) {
		item = RZ_NEW0(RzCmdItem);
		c->cmds[idx] = item;
	}
	strncpy(item->cmd, cmd, sizeof(item->cmd) - 1);
	item->callback = cb;
	return true;
}

RZ_API int rz_cmd_del(RzCmd *cmd, const char *command) {
	int idx = (ut8)command[0];
	RZ_FREE(cmd->cmds[idx]);
	return 0;
}

RZ_API int rz_cmd_call(RzCmd *cmd, const char *input) {
	struct rz_cmd_item_t *c;
	int ret = -1;
	rz_return_val_if_fail(cmd && input, -1);
	if (!*input) {
		if (cmd->nullcallback) {
			ret = cmd->nullcallback(cmd->core);
		}
	} else {
		char *nstr = NULL;
		const char *ji = rz_cmd_alias_get(cmd, input, 1);
		if (ji) {
			if (*ji == '$') {
				rz_cons_strcat(ji + 1);
				return true;
			} else {
				nstr = rz_str_newf("R! %s", input);
				input = nstr;
			}
		}
		if (!*input) {
			free(nstr);
			return -1;
		}
		c = cmd->cmds[((ut8)input[0]) & 0xff];
		if (c && c->callback) {
			const char *inp = (*input) ? input + 1 : "";
			ret = c->callback(cmd->core, inp);
		} else {
			ret = -1;
		}
		free(nstr);
	}
	return ret;
}

static RzCmdStatus int2cmdstatus(int v) {
	if (v == -2) {
		return RZ_CMD_STATUS_EXIT;
	} else if (v < 0) {
		return RZ_CMD_STATUS_ERROR;
	} else {
		return RZ_CMD_STATUS_OK;
	}
}

static void get_minmax_argc(RzCmdDesc *cd, int *min_argc, int *max_argc) {
	*min_argc = 1;
	*max_argc = 1;
	const RzCmdDescArg *arg = cd->help->args;
	while (arg && arg->name && !arg->optional) {
		if (arg->type == RZ_CMD_ARG_TYPE_FAKE) {
			arg++;
			continue;
		}
		(*min_argc)++;
		(*max_argc)++;
		if (arg->flags & RZ_CMD_ARG_FLAG_LAST) {
			return;
		} else if (arg->flags & RZ_CMD_ARG_FLAG_ARRAY) {
			*max_argc = INT_MAX;
			return;
		}
		arg++;
	}
	while (arg && arg->name) {
		if (arg->type == RZ_CMD_ARG_TYPE_FAKE) {
			arg++;
			continue;
		}
		(*max_argc)++;
		if (arg->flags & RZ_CMD_ARG_FLAG_ARRAY) {
			*max_argc = INT_MAX;
			return;
		}
		arg++;
	}
}

static RzOutputMode get_cd_default_mode(RzCmdDesc *cd) {
	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
		return cd->d.argv_modes_data.default_mode;
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		return cd->d.argv_state_data.default_mode;
	default:
		return RZ_OUTPUT_MODE_STANDARD;
	}
}

static bool has_cd_default_mode(RzCmdDesc *cd) {
	return get_cd_default_mode(cd) != RZ_OUTPUT_MODE_STANDARD;
}

static RzOutputMode cd_suffix2mode(RzCmdDesc *cd, const char *cmdid) {
	if (!has_cd_submodes(cd)) {
		return 0;
	}
	RzOutputMode mode = suffix2mode(cmdid + strlen(cd->name));
	if (mode == RZ_OUTPUT_MODE_STANDARD && has_cd_default_mode(cd)) {
		mode = get_cd_default_mode(cd);
	}
	return mode;
}

/**
 * Performs a preprocessing step on the user arguments.
 *
 * This is used to group together some arguments that are returned by the
 * parser as multiple arguments but we want to let the command handler see them
 * as a single one to make life easier for users.
 *
 * It can also provide default arguments as specified by the command
 * descriptor.
 *
 * For example:
 * `cmdid pd 10` would be considered as having 2 arguments, "pd" and "10".
 * However, if <cmdid> was defined to have as argument
 * RZ_CMD_ARG_FLAG_LAST, we want to group "pd" and "10" in one single
 * argument "pd 10" and pass that to <cmdid> handler.
 */
static void args_preprocessing(RzCmdDesc *cd, RzCmdParsedArgs *args) {
	const RzCmdDescArg *arg;
	size_t i, j;
	for (arg = cd->help->args, i = 1; arg && arg->name && i < args->argc - 1; arg++, i++) {
		char *tmp;
		if (arg->flags & RZ_CMD_ARG_FLAG_LAST) {
			if (arg->type == RZ_CMD_ARG_TYPE_CMD) {
				for (j = i; j < args->argc; j++) {
					char *s = rz_cmd_escape_arg(args->argv[j], RZ_CMD_ESCAPE_ONE_ARG);
					if (strcmp(s, args->argv[j])) {
						free(args->argv[j]);
						args->argv[j] = s;
					} else {
						free(s);
					}
				}
			}

			tmp = rz_str_array_join((const char **)&args->argv[i], args->argc - i, " ");
			if (!tmp) {
				return;
			}
			for (j = i; j < args->argc; j++) {
				free(args->argv[j]);
			}
			args->argv[i] = tmp;
			args->argc = i + 1;
			return;
		}
	}
	for (; arg && arg->name; arg++, i++) {
		if (arg->default_value && i >= args->argc) {
			rz_cmd_parsed_args_addarg(args, arg->default_value);
		}
	}
}

static RzCmdStatus argv_call_cb(RzCmd *cmd, RzCmdDesc *cd, RzCmdParsedArgs *args) {
	if (!rz_cmd_desc_has_handler(cd)) {
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}

	args_preprocessing(cd, args);

	int i;
	const char *s;
	rz_cmd_parsed_args_foreach_arg(args, i, s) {
		RZ_LOG_DEBUG("processed parsed_arg %d: '%s'\n", i, s);
	}

	RzOutputMode mode;
	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_ARGV:
		if (args->argc < cd->d.argv_data.min_argc || args->argc > cd->d.argv_data.max_argc) {
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		return cd->d.argv_data.cb(cmd->core, args->argc, (const char **)args->argv);
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
		mode = cd_suffix2mode(cd, rz_cmd_parsed_args_cmd(args));
		if (!mode) {
			return RZ_CMD_STATUS_NONEXISTINGCMD;
		}
		if (args->argc < cd->d.argv_modes_data.min_argc || args->argc > cd->d.argv_modes_data.max_argc) {
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		return cd->d.argv_modes_data.cb(cmd->core, args->argc, (const char **)args->argv, mode);
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		mode = cd_suffix2mode(cd, rz_cmd_parsed_args_cmd(args));
		if (!mode) {
			return RZ_CMD_STATUS_NONEXISTINGCMD;
		}
		if (args->argc < cd->d.argv_state_data.min_argc || args->argc > cd->d.argv_state_data.max_argc) {
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		RzCmdStateOutput state;
		if (!rz_cmd_state_output_init(&state, mode)) {
			return RZ_CMD_STATUS_INVALID;
		}
		RzCmdStatus res = cd->d.argv_state_data.cb(cmd->core, args->argc, (const char **)args->argv, &state);
		if (args->extra && state.mode == RZ_OUTPUT_MODE_TABLE) {
			bool res = rz_table_query(state.d.t, args->extra);
			if (!res) {
				rz_cmd_state_output_fini(&state);
				return RZ_CMD_STATUS_INVALID;
			}
		}
		if (res == RZ_CMD_STATUS_OK) {
			rz_cmd_state_output_print(&state);
		}
		rz_cmd_state_output_fini(&state);
		return res;
	default:
		return RZ_CMD_STATUS_INVALID;
	}
}

static RzCmdStatus call_cd(RzCmd *cmd, RzCmdDesc *cd, RzCmdParsedArgs *args) {
	char *exec_string;
	RzCmdStatus res = RZ_CMD_STATUS_INVALID;

	int i;
	const char *s;
	rz_cmd_parsed_args_foreach_arg(args, i, s) {
		RZ_LOG_DEBUG("parsed_arg %d: '%s'\n", i, s);
	}

	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_GROUP:
		if (!cd->d.group_data.exec_cd) {
			return RZ_CMD_STATUS_NONEXISTINGCMD;
		}
		return call_cd(cmd, cd->d.group_data.exec_cd, args);
	case RZ_CMD_DESC_TYPE_ARGV:
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		return argv_call_cb(cmd, cd, args);
	case RZ_CMD_DESC_TYPE_OLDINPUT:
		exec_string = rz_cmd_parsed_args_execstr(args);
		res = int2cmdstatus(cd->d.oldinput_data.cb(cmd->core, exec_string + strlen(cd->name)));
		RZ_FREE(exec_string);
		return res;
	default:
		RZ_LOG_ERROR("RzCmdDesc type not handled\n");
		return RZ_CMD_STATUS_INVALID;
	}
}

RZ_API RzCmdStatus rz_cmd_call_parsed_args(RzCmd *cmd, RzCmdParsedArgs *args) {
	RzCmdDesc *cd = rz_cmd_get_desc(cmd, rz_cmd_parsed_args_cmd(args));
	if (!cd) {
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}

	return call_cd(cmd, cd, args);
}

static size_t strlen0(const char *s) {
	return s ? strlen(s) : 0;
}

static size_t strbuf_append_calc(RzStrBuf *sb, const char *s) {
	rz_strbuf_append(sb, s);
	return strlen(s);
}

static void fill_modes_children_chars(RzStrBuf *sb, const RzCmdDesc *cd) {
	// RZ_CMD_DESC_TYPE_ARGV_MODES does not have actual children for
	// the output modes, so we consider it separately
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(argv_modes); i++) {
		if (cd->d.argv_modes_data.modes & argv_modes[i].mode) {
			rz_strbuf_append(sb, argv_modes[i].suffix);
		}
	}
}

static size_t fill_children_chars(RzStrBuf *sb, const RzCmdDesc *cd) {
	if (cd->help->options) {
		return strbuf_append_calc(sb, cd->help->options);
	}

	RzStrBuf csb;
	rz_strbuf_init(&csb);

	void **it;
	bool has_other_commands = false;
	const RzCmdDesc *exec_cd = rz_cmd_desc_get_exec((RzCmdDesc *)cd);
	if (exec_cd) {
		switch (exec_cd->type) {
		case RZ_CMD_DESC_TYPE_ARGV_MODES:
		case RZ_CMD_DESC_TYPE_ARGV_STATE:
			fill_modes_children_chars(&csb, exec_cd);
			break;
		default:
			break;
		}
	}
	rz_cmd_desc_children_foreach(cd, it) {
		RzCmdDesc *child = *(RzCmdDesc **)it;
		if (rz_str_startswith(child->name, cd->name) && strlen(child->name) == strlen(cd->name) + 1) {
			rz_strbuf_appendf(&csb, "%c", child->name[strlen(cd->name)]);
		} else if (strcmp(child->name, cd->name)) {
			has_other_commands = true;
		}
	}

	if (rz_strbuf_is_empty(&csb) || rz_strbuf_length(&csb) >= MAX_CHILDREN_SHOW) {
		rz_strbuf_fini(&csb);
		rz_strbuf_set(&csb, "?");
		has_other_commands = false;
	}

	if (has_other_commands) {
		rz_strbuf_append(&csb, "?");
	}

	if (!cd->n_children || rz_cmd_desc_has_handler(cd)) {
		rz_strbuf_prepend(&csb, "[");
		rz_strbuf_append(&csb, "]");
	} else {
		rz_strbuf_prepend(&csb, "<");
		rz_strbuf_append(&csb, ">");
	}
	size_t res = rz_strbuf_length(&csb);
	char *s = rz_strbuf_drain_nofree(&csb);
	rz_strbuf_append(sb, s);
	free(s);
	return res;
}

static bool show_children_shortcut(const RzCmdDesc *cd) {
	return cd->n_children || cd->help->options || cd->type == RZ_CMD_DESC_TYPE_OLDINPUT ||
		has_cd_submodes(cd);
}

static void fill_colored_args(RzCmd *cmd, RzStrBuf *sb, const char *line, bool use_color, const char *reset_color) {
	const char *pal_args_color = "";
	if (cmd->has_cons && use_color) {
		RzCons *cons = rz_cons_singleton();
		pal_args_color = cons->context->pal.args;
	}

	while (line) {
		const char *close_arg = NULL;
		const char *open_arg = strchr(line, '<');
		if (!open_arg) {
			break;
		}
		close_arg = strchr(open_arg, '>');
		if (!close_arg) {
			break;
		}
		rz_strbuf_appendf(sb, "%.*s%s", (int)(open_arg - line), line, pal_args_color);
		rz_strbuf_appendf(sb, "%.*s%s", (int)(close_arg - open_arg + 1), open_arg, reset_color);
		line = close_arg + 1;
	}
	rz_strbuf_append(sb, line);
}

static void fill_wrapped_comment(RzCmd *cmd, RzStrBuf *sb, const char *comment, size_t columns, bool use_color) {
	int rows, cols;
	bool is_interactive = false;
	const char *help_color = "";
	if (cmd->has_cons) {
		RzCons *cons = rz_cons_singleton();
		cols = rz_cons_get_size(&rows);
		is_interactive = rz_cons_is_interactive();
		help_color = use_color ? cons->context->pal.help : "";
	}
	if (is_interactive && cols > 0 && cols - columns > MIN_SUMMARY_WIDTH && !RZ_STR_ISEMPTY(comment)) {
		char *text = strdup(comment);
		RzList *wrapped_text = rz_str_wrap(text, cols - columns - 2);
		RzListIter *it;
		const char *line;
		bool first = true;
		rz_list_foreach (wrapped_text, it, line) {
			if (!first) {
				rz_strbuf_appendf(sb, "\n%*s", (int)(columns + 2), "");
			} else {
				rz_strbuf_append(sb, "# ");
				first = false;
			}

			fill_colored_args(cmd, sb, line, use_color, help_color);
		}
		rz_list_free(wrapped_text);
		free(text);
	} else if (!RZ_STR_ISEMPTY(comment)) {
		rz_strbuf_appendf(sb, "# %s", comment);
	}
}

static void close_optionals(size_t *n_optionals, RzStrBuf *sb, size_t *len) {
	for (; *n_optionals > 0; (*n_optionals)--) {
		rz_strbuf_append(sb, "]");
		(*len)++;
	}
}

static size_t fill_args(RzStrBuf *sb, const RzCmdDesc *cd) {
	const RzCmdDescArg *arg;
	size_t n_optionals = 0;
	size_t len = 0;
	bool has_array = false;
	for (arg = cd->help->args; arg && arg->name; arg++) {
		if (arg->type == RZ_CMD_ARG_TYPE_FAKE) {
			if (!arg->optional) {
				// Assume arg is a closing bracket
				close_optionals(&n_optionals, sb, &len);
			}
			rz_strbuf_append(sb, arg->name);
			len += strlen(arg->name);
			continue;
		}

		if (has_array) {
			rz_warn_if_reached();
			break;
		}
		if (!arg->no_space) {
			rz_strbuf_append(sb, " ");
			len++;
		}
		if (arg->optional) {
			rz_strbuf_append(sb, "[");
			len++;
			n_optionals++;
		}
		if (arg->flags & RZ_CMD_ARG_FLAG_ARRAY) {
			has_array = true;
			rz_strbuf_appendf(sb, "<%s1>", arg->name);
			len += strlen(arg->name) + 3;
			rz_strbuf_appendf(sb, " <%s2> ...", arg->name);
			len += strlen(arg->name) + 8;
		} else if (arg->flags & RZ_CMD_ARG_FLAG_OPTION) {
			rz_strbuf_appendf(sb, "-%s", arg->name);
			len += strlen(arg->name) + 1;
		} else {
			rz_strbuf_appendf(sb, "<%s>", arg->name);
			len += strlen(arg->name) + 2;
			if (arg->default_value) {
				rz_strbuf_appendf(sb, "=%s", arg->default_value);
				len += strlen(arg->default_value) + 1;
			}
		}
	}
	close_optionals(&n_optionals, sb, &len);
	return len;
}

static void fill_usage_strbuf(RzCmd *cmd, RzStrBuf *sb, RzCmdDesc *cd, bool use_color) {
	const char *pal_label_color = "",
		   *pal_args_color = "",
		   *pal_input_color = "",
		   *pal_help_color = "",
		   *pal_reset = "";

	if (cmd->has_cons && use_color) {
		RzCons *cons = rz_cons_singleton();
		pal_label_color = cons->context->pal.label;
		pal_args_color = cons->context->pal.args;
		pal_input_color = cons->context->pal.input;
		pal_help_color = cons->context->pal.help;
		pal_reset = cons->context->pal.reset;
	}

	size_t columns = 0;
	rz_strbuf_append(sb, pal_label_color);
	columns += strbuf_append_calc(sb, "Usage: ");
	rz_strbuf_append(sb, pal_reset);
	if (cd->help->usage) {
		columns += strbuf_append_calc(sb, cd->help->usage);
		rz_strbuf_append(sb, pal_reset);
	} else {
		rz_strbuf_append(sb, pal_input_color);
		columns += strbuf_append_calc(sb, cd->name);
		if (show_children_shortcut(cd)) {
			rz_strbuf_append(sb, pal_reset);
			columns += fill_children_chars(sb, cd);
		}
		rz_strbuf_append(sb, pal_args_color);
		if (cd->help->args_str) {
			columns += strbuf_append_calc(sb, cd->help->args_str);
		} else {
			columns += fill_args(sb, cd);
		}
		rz_strbuf_append(sb, pal_reset);
	}
	if (cd->help->summary) {
		RzStrBuf *summary_sb = rz_strbuf_new(cd->help->summary);
		if (summary_sb) {
			columns += strbuf_append_calc(sb, "   ");
			rz_strbuf_append(sb, pal_help_color);
			if (has_cd_default_mode(cd)) {
				rz_strbuf_appendf(summary_sb, "%s", rz_output_mode_to_summary(get_cd_default_mode(cd)));
			}
			fill_wrapped_comment(cmd, sb, rz_strbuf_get(summary_sb), columns, use_color);
			rz_strbuf_append(sb, pal_reset);
			rz_strbuf_free(summary_sb);
		}
	}
	rz_strbuf_append(sb, "\n");
}

static size_t calc_padding_len(const RzCmdDesc *cd, const char *name, bool show_children) {
	size_t name_len = strlen(name);
	size_t args_len = 0;
	size_t children_length = 0;
	if (show_children && show_children_shortcut(cd)) {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		fill_children_chars(&sb, cd);
		children_length += rz_strbuf_length(&sb);
		rz_strbuf_fini(&sb);
	}
	if (cd->help->args_str) {
		args_len = strlen0(cd->help->args_str);
	} else {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		fill_args(&sb, cd);
		args_len = rz_strbuf_length(&sb);
		rz_strbuf_fini(&sb);
	}
	return name_len + args_len + children_length;
}

static void update_minmax_len(RzCmdDesc *cd, size_t *max_len, size_t *min_len, bool show_children) {
	size_t val = calc_padding_len(cd, cd->name, show_children);
	*max_len = val > *max_len ? val : *max_len;
	*min_len = val < *min_len ? val : *min_len;
}

static void do_print_child_help(RzCmd *cmd, RzStrBuf *sb, const RzCmdDesc *cd, const char *name, const char *summary, bool show_children, size_t max_len, bool use_color) {
	size_t str_len = calc_padding_len(cd, name, show_children);
	int padding = str_len < max_len ? max_len - str_len : 0;
	const char *pal_args_color = "",
		   *pal_opt_color = "",
		   *pal_help_color = "",
		   *pal_input_color = "",
		   *pal_reset = "";

	if (cmd->has_cons && use_color) {
		RzCons *cons = rz_cons_singleton();
		pal_args_color = cons->context->pal.args;
		pal_opt_color = cons->context->pal.reset;
		pal_help_color = cons->context->pal.help;
		pal_input_color = cons->context->pal.input;
		pal_reset = cons->context->pal.reset;
	}

	size_t columns = 0;
	columns += strbuf_append_calc(sb, "| ");
	rz_strbuf_append(sb, pal_input_color);
	columns += strbuf_append_calc(sb, name);
	if (show_children && show_children_shortcut(cd)) {
		rz_strbuf_append(sb, pal_opt_color);
		columns += fill_children_chars(sb, cd);
	}
	rz_strbuf_append(sb, pal_args_color);
	if (cd->help->args_str) {
		columns += strbuf_append_calc(sb, cd->help->args_str);
	} else {
		columns += fill_args(sb, cd);
	}
	rz_strbuf_appendf(sb, " %*s", padding, "");
	columns += padding + 1;
	rz_strbuf_append(sb, pal_help_color);

	fill_wrapped_comment(cmd, sb, summary, columns, use_color);
	rz_strbuf_appendf(sb, "%s\n", pal_reset);
}

static void print_child_help(RzCmd *cmd, RzStrBuf *sb, RzCmdDesc *cd, size_t max_len, bool use_color) {
	do_print_child_help(cmd, sb, cd, cd->name, cd->help->summary ? cd->help->summary : "", true, max_len, use_color);
}

static char *group_get_help(RzCmd *cmd, RzCmdDesc *cd, bool use_color) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	fill_usage_strbuf(cmd, sb, cd, use_color);

	void **it_cd;
	size_t max_len = 0, min_len = SIZE_MAX;

	rz_cmd_desc_children_foreach(cd, it_cd) {
		RzCmdDesc *child = *(RzCmdDesc **)it_cd;
		update_minmax_len(child, &max_len, &min_len, true);
	}
	if (max_len - min_len > MAX_RIGHT_ALIGHNMENT) {
		max_len = min_len + MAX_RIGHT_ALIGHNMENT;
	}

	rz_cmd_desc_children_foreach(cd, it_cd) {
		RzCmdDesc *child = *(RzCmdDesc **)it_cd;
		print_child_help(cmd, sb, child, max_len, use_color);
	}

	bool details_filled = fill_details(cmd, cd, sb, use_color);
	if (!details_filled &&
		cd->type == RZ_CMD_DESC_TYPE_GROUP &&
		cd->d.group_data.exec_cd &&
		cd->d.group_data.exec_cd->help->details) {

		cd = cd->d.group_data.exec_cd;
		const char *pal_args_color = "",
			   *pal_input_color = "",
			   *pal_reset = "";

		if (cmd->has_cons && use_color) {
			RzCons *cons = rz_cons_singleton();
			pal_args_color = cons->context->pal.args;
			pal_input_color = cons->context->pal.input;
			pal_reset = cons->context->pal.reset;
		}

		rz_strbuf_appendf(sb, "\nDetailed help for %s%s%s", pal_input_color, cd->name, pal_args_color);
		if (cd->help->args_str) {
			rz_strbuf_appendf(sb, "%s", cd->help->args_str);
		} else {
			fill_args(sb, cd);
		}
		rz_strbuf_appendf(sb, "%s is provided by %s??.\n", pal_reset, cd->name);
	}
	return rz_strbuf_drain(sb);
}

static void fill_argv_modes_help_strbuf(RzCmd *cmd, RzStrBuf *sb, RzCmdDesc *cd, bool use_color) {
	size_t max_len = 0, min_len = SIZE_MAX;
	update_minmax_len(cd, &max_len, &min_len, true);
	max_len++; // consider the suffix letter
	if (max_len - min_len > MAX_RIGHT_ALIGHNMENT) {
		max_len = min_len + MAX_RIGHT_ALIGHNMENT;
	}

	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(argv_modes); i++) {
		if (cd->d.argv_modes_data.modes & argv_modes[i].mode) {
			char *name = rz_str_newf("%s%s", cd->name, argv_modes[i].suffix);
			char *summary = rz_str_newf("%s%s", cd->help->summary, argv_modes[i].summary_suffix);
			do_print_child_help(cmd, sb, cd, name, summary, false, max_len, use_color);
			free(name);
			free(summary);
		}
	}
}

static const RzCmdDescDetail *get_cd_details(RzCmdDesc *cd) {
	do {
		if (cd->help->details) {
			return cd->help->details;
		}
		cd = cd->parent;
	} while (cd);
	return NULL;
}

static RzCmdDescDetail *get_cd_details_cb(RzCmd *cmd, RzCmdDesc *cd) {
	do {
		if (cd->help->details || cd->help->details_cb) {
			const char *argv[] = { cd->name, NULL };
			return cd->help->details_cb ? cd->help->details_cb(cmd->core, 1, argv) : NULL;
		}
		cd = cd->parent;
	} while (cd);
	return NULL;
}

static void fill_details_do(RzCmd *cmd, const RzCmdDescDetail *detail_it, RzStrBuf *sb, bool use_color) {
	const char *pal_help_color = "",
		   *pal_input_color = "",
		   *pal_label_color = "",
		   *pal_args_color = "",
		   *pal_reset = "";
	if (cmd->has_cons && use_color) {
		RzCons *cons = rz_cons_singleton();
		pal_help_color = cons->context->pal.help;
		pal_input_color = cons->context->pal.input;
		pal_label_color = cons->context->pal.label;
		pal_args_color = cons->context->pal.args;
		pal_reset = cons->context->pal.reset;
	}

	while (detail_it->name) {
		if (!RZ_STR_ISEMPTY(detail_it->name)) {
			rz_strbuf_appendf(sb, "\n%s%s:%s\n", pal_label_color, detail_it->name, pal_reset);
		}
		const RzCmdDescDetailEntry *entry_it = detail_it->entries;
		size_t max_len = 0, min_len = SIZE_MAX;
		while (entry_it && entry_it->text) {
			size_t len = strlen(entry_it->text) + strlen0(entry_it->arg_str);
			if (max_len < len) {
				max_len = len;
			}
			if (min_len > len) {
				min_len = len;
			}
			entry_it++;
		}
		if (max_len - min_len > MAX_RIGHT_ALIGHNMENT) {
			max_len = min_len + MAX_RIGHT_ALIGHNMENT;
		}

		entry_it = detail_it->entries;
		while (entry_it && entry_it->text) {
			size_t len = strlen(entry_it->text) + strlen0(entry_it->arg_str);
			int padding = len < max_len ? max_len - len : 0;
			const char *arg_str = entry_it->arg_str ? entry_it->arg_str : "";
			rz_strbuf_appendf(sb, "| %s%s%s%s %*s%s",
				pal_input_color, entry_it->text,
				pal_args_color, arg_str,
				padding, "",
				pal_help_color);
			size_t columns = strlen("| ") + strlen(entry_it->text) +
				strlen(" ") + strlen(arg_str) + padding;
			fill_wrapped_comment(cmd, sb, entry_it->comment, columns, use_color);
			rz_strbuf_appendf(sb, "%s\n", pal_reset);
			entry_it++;
		}
		detail_it++;
	}
}

static bool fill_details_static(RzCmd *cmd, RzCmdDesc *cd, RzStrBuf *sb, bool use_color) {
	const RzCmdDescDetail *detail_it = get_cd_details(cd);
	if (!detail_it) {
		return false;
	}
	fill_details_do(cmd, detail_it, sb, use_color);
	return true;
}

static bool fill_details_cb(RzCmd *cmd, RzCmdDesc *cd, RzStrBuf *sb, bool use_color) {
	RzCmdDescDetail *detail_it = get_cd_details_cb(cmd, cd);
	if (!detail_it) {
		return false;
	}
	fill_details_do(cmd, detail_it, sb, use_color);
	rz_cmd_desc_details_free(detail_it);
	return true;
}

static bool fill_details(RzCmd *cmd, RzCmdDesc *cd, RzStrBuf *sb, bool use_color) {
	return (int)fill_details_static(cmd, cd, sb, use_color) |
		(int)fill_details_cb(cmd, cd, sb, use_color);
}

static char *argv_get_help(RzCmd *cmd, RzCmdDesc *cd, size_t detail, bool use_color) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	const char *pal_reset = "";
	if (cmd->has_cons && use_color) {
		RzCons *cons = rz_cons_singleton();
		pal_reset = cons->context->pal.reset;
	}

	fill_usage_strbuf(cmd, sb, cd, use_color);

	if (cd->type == RZ_CMD_DESC_TYPE_ARGV_MODES || cd->type == RZ_CMD_DESC_TYPE_ARGV_STATE) {
		fill_argv_modes_help_strbuf(cmd, sb, cd, use_color);
	}

	switch (detail) {
	case 1:
	case 2:
		if (cd->help->description) {
			rz_strbuf_append(sb, "\n");
			fill_colored_args(cmd, sb, cd->help->description, use_color, pal_reset);
			rz_strbuf_append(sb, "\n");
		}
		fill_details(cmd, cd, sb, use_color);
		break;
	default:
		rz_strbuf_free(sb);
		return NULL;
	}
	return rz_strbuf_drain(sb);
}

static char *fake_get_help(RzCmd *cmd, RzCmdDesc *cd, bool use_color) {
	// abuse detail=2 of the argv help as they show essentially the same info
	return argv_get_help(cmd, cd, 2, use_color);
}

static char *oldinput_get_help(RzCmd *cmd, RzCmdDesc *cd, RzCmdParsedArgs *a) {
	if (!cmd->has_cons) {
		return NULL;
	}

	char *res = NULL;
	rz_cons_push();
	// rz_cons_push disables flushing, which is going to be a problem if a help menu is
	// displayed.
	rz_cons_set_flush(true);
	RzCmdStatus status = rz_cmd_call_parsed_args(cmd, a);
	if (status == RZ_CMD_STATUS_OK) {
		rz_cons_filter();
		res = rz_cons_get_buffer_dup();
	}
	if (!res) {
		res = strdup("");
	}
	rz_cons_pop();
	return res;
}

static char *get_help(RzCmd *cmd, RzCmdDesc *cd, const char *cmdid, RzCmdParsedArgs *args, bool use_color, size_t detail) {
	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_GROUP:
		if (cd->d.group_data.exec_cd && (detail > 1 || (detail == 1 && strcmp(cmdid, cd->name)))) {
			return get_help(cmd, cd->d.group_data.exec_cd, cmdid, args, use_color, detail);
		}
		if (detail == 1) {
			// show the group help only when doing <cmd>?
			return group_get_help(cmd, cd, use_color);
		}
		return argv_get_help(cmd, cd, detail, use_color);
	case RZ_CMD_DESC_TYPE_ARGV:
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		return argv_get_help(cmd, cd, detail, use_color);
	case RZ_CMD_DESC_TYPE_FAKE:
		if (detail != 1) {
			return NULL;
		}
		return fake_get_help(cmd, cd, use_color);
	case RZ_CMD_DESC_TYPE_OLDINPUT:
		return oldinput_get_help(cmd, cd, args);
	case RZ_CMD_DESC_TYPE_INNER:
		rz_warn_if_reached();
		return NULL;
	}
	return NULL;
}

static void fill_args_json(const RzCmd *cmd, const RzCmdDesc *cd, PJ *j) {
	const RzCmdDescArg *arg;
	bool has_array = false;
	pj_ka(j, "args");
	const char *argtype = NULL;
	for (arg = cd->help->args; arg && arg->name; arg++) {
		if (has_array) {
			rz_warn_if_reached();
			break;
		}
		pj_o(j);
#define CASE_TYPE(x, y) \
	case (x): \
		argtype = (y); \
		break
		switch (arg->type) {
			CASE_TYPE(RZ_CMD_ARG_TYPE_FAKE, "fake");
			CASE_TYPE(RZ_CMD_ARG_TYPE_NUM, "number");
			CASE_TYPE(RZ_CMD_ARG_TYPE_RZNUM, "expression");
			CASE_TYPE(RZ_CMD_ARG_TYPE_STRING, "string");
			CASE_TYPE(RZ_CMD_ARG_TYPE_ENV, "environment_variable");
			CASE_TYPE(RZ_CMD_ARG_TYPE_CHOICES, "choice");
			CASE_TYPE(RZ_CMD_ARG_TYPE_FCN, "function");
			CASE_TYPE(RZ_CMD_ARG_TYPE_FILE, "filename");
			CASE_TYPE(RZ_CMD_ARG_TYPE_OPTION, "option");
			CASE_TYPE(RZ_CMD_ARG_TYPE_CMD, "command");
			CASE_TYPE(RZ_CMD_ARG_TYPE_MACRO, "macro");
			CASE_TYPE(RZ_CMD_ARG_TYPE_EVAL_KEY, "evaluable");
			CASE_TYPE(RZ_CMD_ARG_TYPE_EVAL_FULL, "evaluable_full");
#undef CASE_TYPE
		default:
			argtype = "unknown";
			break;
		}
		pj_ks(j, "type", argtype);
		pj_ks(j, "name", arg->name);
		if (arg->type == RZ_CMD_ARG_TYPE_FAKE) {
			pj_end(j);
			continue;
		}
		if (arg->no_space) {
			pj_kb(j, "nospace", true);
		}
		if (!arg->optional) {
			pj_kb(j, "required", true);
		}
		if (arg->flags & RZ_CMD_ARG_FLAG_LAST) {
			pj_kb(j, "is_last", true);
		}
		if (arg->flags & RZ_CMD_ARG_FLAG_ARRAY) {
			pj_kb(j, "is_array", true);
		}
		if (arg->flags & RZ_CMD_ARG_FLAG_OPTION) {
			pj_kb(j, "is_option", true);
		}
		if (arg->default_value) {
			pj_ks(j, "default", arg->default_value);
		}
		if (arg->type == RZ_CMD_ARG_TYPE_CHOICES) {
			pj_ka(j, "choices");
			char **ochoice = arg->choices.choices_cb ? arg->choices.choices_cb(cmd->core) : (char **)arg->choices.choices;
			for (char **choice = ochoice; *choice; choice++) {
				pj_s(j, *choice);
			}
			pj_end(j);
			if (arg->choices.choices_cb) {
				for (char **choice = ochoice; *choice; choice++) {
					free(*choice);
				}
				free(ochoice);
			}
		}
		pj_end(j);
	}
	pj_end(j);
}

/**
 * \brief Generates a JSON output of the given help message description
 *
 * \param cmd reference to RzCmd
 * \param cd reference to RzCmdDesc
 * \param j reference to PJ
 *
 * \return returns false if an invalid argument was given, otherwise true.
 */
RZ_API bool rz_cmd_get_help_json(RzCmd *cmd, const RzCmdDesc *cd, PJ *j) {
	rz_return_val_if_fail(cmd && cd && j, false);
	pj_ko(j, cd->name);
	pj_ks(j, "cmd", cd->name);
	const char *type;
	switch (cd->type) {
#define CASE_CDTYPE(x, y) \
	case (x): \
		type = (y); \
		break
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_OLDINPUT, "oldinput");
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_ARGV, "argv");
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_GROUP, "group");
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_INNER, "inner");
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_FAKE, "fake");
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_ARGV_MODES, "argv_modes");
		CASE_CDTYPE(RZ_CMD_DESC_TYPE_ARGV_STATE, "argv_state");
#undef CASE_CDTYPE
	default:
		type = "unknown";
		break;
	}
	pj_ks(j, "type", type);
	if (cd->help->args_str) {
		pj_ks(j, "args_str", cd->help->args_str);
	} else {
		RzStrBuf *sb = rz_strbuf_new(NULL);
		fill_args(sb, cd);
		char *args = rz_strbuf_drain(sb);
		pj_ks(j, "args_str", args);
		free(args);
	}
	fill_args_json(cmd, cd, j);
	pj_ks(j, "description", cd->help->description ? cd->help->description : "");
	pj_ks(j, "summary", cd->help->summary ? cd->help->summary : "");
	pj_end(j);
	return true;
}

/**
 * \brief Generates a text output of the given help message description (summary format)
 *
 * \param cmd reference to RzCmd
 * \param cd reference to RzCmdDesc
 * \param use_color output strings with color codes.
 * \param sb reference to RzStrBuf
 *
 * \return returns false if an invalid argument was given, otherwise true.
 */
RZ_API bool rz_cmd_get_help_strbuf(RzCmd *cmd, const RzCmdDesc *cd, bool use_color, RzStrBuf *sb) {
	rz_return_val_if_fail(cmd && cd && sb, false);
	do_print_child_help(cmd, sb, cd, cd->name, cd->help->summary, false, MAX_RIGHT_ALIGHNMENT, use_color);
	return true;
}

RZ_API char *rz_cmd_get_help(RzCmd *cmd, RzCmdParsedArgs *args, bool use_color) {
	char *cmdid = strdup(rz_cmd_parsed_args_cmd(args));
	if (!cmdid) {
		return NULL;
	}
	char *cmdid_p = cmdid + strlen(cmdid) - 1;
	size_t detail = 0;
	while (cmdid_p >= cmdid && *cmdid_p == '?' && detail < 2) {
		*cmdid_p = '\0';
		cmdid_p--;
		detail++;
	}

	char *res = NULL;
	if (detail == 0) {
		// there should be at least one `?`
		goto err;
	}

	RzCmdDesc *cd = cmdid_p >= cmdid ? rz_cmd_get_desc(cmd, cmdid) : rz_cmd_get_root(cmd);
	if (!cd || !cd->help) {
		goto err;
	}

	res = get_help(cmd, cd, cmdid, args, use_color, detail);
err:
	free(cmdid);
	return res;
}

/* RzCmdMacro*/

/**
 * \brief Add a new macro named \p name, accepting the arguments \p args, that executes the rizin shell code \p code
 *
 * \param cmd Reference to RzCmd
 * \param name Name of the new macro
 * \param args Array of strings, terminated by NULL, each string representing the name of the argument
 * \param code Body of the new macro
 * \return True when the macro is successfully added, false otherwise
 */
RZ_API bool rz_cmd_macro_add(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, const char **args, RZ_NONNULL const char *code) {
	rz_return_val_if_fail(cmd && name && args && code, false);

	RzCmdMacro *macro = RZ_NEW0(RzCmdMacro);
	if (!macro) {
		return false;
	}
	macro->name = strdup(name);
	if (!macro->name) {
		goto err;
	}
	macro->code = strdup(code);
	if (!macro->code) {
		goto err;
	}
	const char **arg = args;
	for (macro->nargs = 0; *arg; macro->nargs++, arg++) {
	}
	macro->args = RZ_NEWS0(char *, macro->nargs);
	if (!macro->args) {
		goto err;
	}
	for (size_t i = 0; i < macro->nargs; i++) {
		macro->args[i] = strdup(args[i]);
		if (!macro->args[i]) {
			goto err;
		}
	}
	return ht_pp_insert(cmd->macros, macro->name, macro);

err:
	macro_free(macro);
	return false;
}

/**
 * \brief Update an existing macro named \p name, accepting the arguments \p args, that executes the rizin shell code \p code
 *
 * \param cmd Reference to RzCmd
 * \param name Name of the new macro
 * \param args Array of strings, terminated by NULL, each string representing the name of the argument
 * \param code Body of the new macro
 * \return True when the macro is successfully added, false otherwise
 */
RZ_API bool rz_cmd_macro_update(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, const char **args, RZ_NONNULL const char *code) {
	rz_return_val_if_fail(cmd && name && args && code, false);

	RzCmdMacro *macro = ht_pp_find(cmd->macros, name, NULL);
	if (!macro) {
		return false;
	}

	char *new_name = NULL, *new_code = NULL;
	char **new_args = NULL;
	size_t new_nargs = 0;

	new_name = strdup(name);
	if (!new_name) {
		goto err;
	}
	new_code = strdup(code);
	if (!new_code) {
		goto err;
	}
	for (new_nargs = 0; args[new_nargs]; new_nargs++) {
	}
	new_args = RZ_NEWS0(char *, new_nargs);
	if (!new_args) {
		goto err;
	}
	for (size_t i = 0; i < new_nargs; i++) {
		new_args[i] = strdup(args[i]);
		if (!new_args[i]) {
			goto err;
		}
	}

	macro_fini(macro);
	macro->name = new_name;
	macro->code = new_code;
	macro->args = new_args;
	macro->nargs = new_nargs;
	return true;

err:
	for (size_t i = 0; i < new_nargs; i++) {
		free(new_args[i]);
	}
	free(new_args);
	free(new_code);
	free(new_name);
	return false;
}

/**
 * \brief Remove macro named \p name
 *
 * \param cmd Reference to RzCmd
 * \param name Name of the macro to remove
 * \return True if the removal was successful, false otherwise
 */
RZ_API bool rz_cmd_macro_rm(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cmd && name, false);

	return ht_pp_delete(cmd->macros, name);
}

/**
 * \brief Get a reference to a macro named \p name
 *
 * \param cmd Reference to RzCmd
 * \param name Name of the macro to retrieve
 * \return Reference to the associated \p RzCmdMacro object
 */
RZ_API const RzCmdMacro *rz_cmd_macro_get(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cmd && name, false);

	return ht_pp_find(cmd->macros, name, NULL);
}

static bool macros_to_list(void *user, const void *key, const void *value) {
	RzList *res = (RzList *)user;
	rz_list_append(res, (void *)value);
	return true;
}

/**
 * \brief Get the list of macros currently defined
 *
 * \param cmd Reference to RzCmd
 * \return List of macros
 */
RZ_API RZ_OWN RzList /*<RzCmdMacro *>*/ *rz_cmd_macro_list(RZ_NONNULL RzCmd *cmd) {
	rz_return_val_if_fail(cmd, NULL);

	RzList *res = rz_list_new();
	if (!res) {
		return NULL;
	}
	ht_pp_foreach(cmd->macros, macros_to_list, res);
	return res;
}

static RzCmdStatus macro_call(RzCmd *cmd, const RzCmdMacro *macro, const char **argv) {
	char *code = strdup(macro->code);
	char key[100];
	size_t i;
	for (i = 0; i < macro->nargs; i++) {
		code = rz_str_replace(code, rz_strf(key, "${%s}", macro->args[i]), argv[i], true);
	}
	RzCmdStatus res = rz_core_cmd_lines_rzshell(cmd->core, code);
	rz_cons_flush();
	free(code);
	return res;
}

/**
 * \brief Call a macro named \p name passing it the arguments defined in \p argv
 *
 * \param cmd Reference to RzCmd
 * \param name Name of the macro to call
 * \param argv Array of arguments, terminated by a NULL element
 * \return Status of the execution of the macros body.
 */
RZ_API RzCmdStatus rz_cmd_macro_call(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, RZ_NONNULL const char **argv) {
	rz_return_val_if_fail(cmd && name && argv, RZ_CMD_STATUS_INVALID);

	const RzCmdMacro *macro = rz_cmd_macro_get(cmd, name);
	if (!macro) {
		RZ_LOG_ERROR("No macro named '%s' was found.\n", name);
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}

	size_t nargv;
	for (nargv = 0; argv[nargv]; nargv++) {
	}

	if (nargv != macro->nargs) {
		RZ_LOG_ERROR("Macro '%s' expects %zu args, not %zu\n", name, macro->nargs, nargv);
		return RZ_CMD_STATUS_INVALID;
	}

	return macro_call(cmd, macro, argv);
}

/**
 * \brief Call a macro named \p name one or more times by passing it the arguments defined in \p argv
 *
 * The arguments \p argv should have the number of arguments the macro accepts
 * (n) or a multiple of it. Each invocation of the macro gets n argument.
 *
 * \param cmd Reference to RzCmd
 * \param name Name of the macro to call
 * \param argv Array of arguments, terminated by a NULL element
 * \return Status of the execution of the macros body.
 */
RZ_API RzCmdStatus rz_cmd_macro_call_multiple(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, RZ_NONNULL const char **argv) {
	rz_return_val_if_fail(cmd && name && argv, RZ_CMD_STATUS_INVALID);

	const RzCmdMacro *macro = rz_cmd_macro_get(cmd, name);
	if (!macro) {
		RZ_LOG_ERROR("No macro named '%s' was found.\n", name);
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}

	size_t nargv;
	for (nargv = 0; argv[nargv]; nargv++) {
	}

	if ((macro->nargs == 0 || nargv == 0) && nargv != macro->nargs) {
		RZ_LOG_ERROR("Macro '%s' expects %zu args, not %zu\n", name, macro->nargs, nargv);
		return RZ_CMD_STATUS_INVALID;
	}
	if (macro->nargs != 0 && nargv % macro->nargs != 0) {
		RZ_LOG_ERROR("Macro '%s' expects %zu args and %zu is not a multiple of %zu\n", name, macro->nargs, nargv, macro->nargs);
		return RZ_CMD_STATUS_INVALID;
	}

	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	size_t j = 0;
	do {
		res = macro_call(cmd, macro, argv + j);
		if (res != RZ_CMD_STATUS_OK) {
			break;
		}
		j += macro->nargs;
	} while (j < nargv);
	return res;
}

struct macro_foreach_t {
	RzCmd *cmd;
	RzCmdForeachMacroCb cb;
	void *user;
};

static bool macro_foreach_cb(void *user, const void *key, const void *value) {
	struct macro_foreach_t *u = (struct macro_foreach_t *)user;
	RzCmdMacro *macro = (RzCmdMacro *)value;
	return u->cb(u->cmd, macro, u->user);
}

/**
 * \brief Calls a callback \p cb on each defined macro
 *
 * \param cmd Reference to RzCmd
 * \param cb Callback called for each macro
 * \param user Additional data passed to the callback
 */
RZ_API void rz_cmd_macro_foreach(RZ_NONNULL RzCmd *cmd, RzCmdForeachMacroCb cb, void *user) {
	rz_return_if_fail(cmd && cb);

	struct macro_foreach_t u = {
		.cmd = cmd,
		.user = user,
		.cb = cb,
	};
	ht_pp_foreach(cmd->macros, macro_foreach_cb, &u);
}

/* RzCmdParsedArgs */

RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_new(const char *cmd, int n_args, char **args) {
	rz_return_val_if_fail(cmd && n_args >= 0, NULL);
	RzCmdParsedArgs *res = RZ_NEW0(RzCmdParsedArgs);
	res->has_space_after_cmd = true;
	res->argc = n_args + 1;
	res->argv = RZ_NEWS0(char *, res->argc + 1);
	res->argv[0] = strdup(cmd);
	int i;
	for (i = 1; i < res->argc; i++) {
		res->argv[i] = strdup(args[i - 1]);
	}
	res->argv[res->argc] = NULL;
	return res;
}

RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_newcmd(const char *cmd) {
	return rz_cmd_parsed_args_new(cmd, 0, NULL);
}

RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_newargs(int n_args, char **args) {
	return rz_cmd_parsed_args_new("", n_args, args);
}

RZ_API void rz_cmd_parsed_args_free(RzCmdParsedArgs *a) {
	if (!a) {
		return;
	}

	int i;
	for (i = 0; i < a->argc; i++) {
		free(a->argv[i]);
	}
	free(a->argv);
	free(a);
}

static void free_array(char **arr, int n) {
	int i;
	for (i = 0; i < n; i++) {
		free(arr[i]);
	}
	free(arr);
}

RZ_API bool rz_cmd_parsed_args_setargs(RzCmdParsedArgs *a, int n_args, char **args) {
	rz_return_val_if_fail(a && a->argv && a->argv[0], false);
	char **tmp = RZ_NEWS0(char *, n_args + 2);
	if (!tmp) {
		return false;
	}
	tmp[0] = strdup(a->argv[0]);
	int i;
	for (i = 1; i < n_args + 1; i++) {
		tmp[i] = strdup(args[i - 1]);
		if (!tmp[i]) {
			goto err;
		}
	}
	tmp[n_args + 1] = NULL;
	free_array(a->argv, a->argc);
	a->argv = tmp;
	a->argc = n_args + 1;
	return true;
err:
	free_array(tmp, n_args + 1);
	return false;
}

RZ_API bool rz_cmd_parsed_args_addarg(RzCmdParsedArgs *a, const char *arg) {
	char **tmp = realloc(a->argv, sizeof(a->argv[0]) * (a->argc + 2));
	if (!tmp) {
		return false;
	}

	a->argv = tmp;
	a->argv[a->argc] = strdup(arg);
	a->argv[a->argc + 1] = NULL;
	a->argc++;
	return true;
}

RZ_API bool rz_cmd_parsed_args_setcmd(RzCmdParsedArgs *a, const char *cmd) {
	rz_return_val_if_fail(a && a->argv && a->argv[0], false);
	char *tmp = strdup(cmd);
	if (!tmp) {
		return false;
	}
	free(a->argv[0]);
	a->argv[0] = tmp;
	return true;
}

static void parsed_args_iterateargs(RzCmdParsedArgs *a, RzStrBuf *sb) {
	int i;
	for (i = 1; i < a->argc; i++) {
		if (i > 1) {
			rz_strbuf_append(sb, " ");
		}
		rz_strbuf_append(sb, a->argv[i]);
	}
}

RZ_API char *rz_cmd_parsed_args_argstr(RzCmdParsedArgs *a) {
	rz_return_val_if_fail(a && a->argv && a->argv[0], NULL);
	RzStrBuf *sb = rz_strbuf_new("");
	parsed_args_iterateargs(a, sb);
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_cmd_parsed_args_execstr(RzCmdParsedArgs *a) {
	rz_return_val_if_fail(a && a->argv && a->argv[0], NULL);
	RzStrBuf *sb = rz_strbuf_new(a->argv[0]);
	if (a->argc > 1 && a->has_space_after_cmd) {
		rz_strbuf_append(sb, " ");
	}
	parsed_args_iterateargs(a, sb);
	if (a->extra) {
		rz_strbuf_append(sb, a->extra);
	}
	return rz_strbuf_drain(sb);
}

RZ_API const char *rz_cmd_parsed_args_cmd(RzCmdParsedArgs *a) {
	rz_return_val_if_fail(a && a->argv && a->argv[0], NULL);
	return a->argv[0];
}

/* RzCmdDescriptor */

static RzCmdDesc *argv_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help, bool ht_insert) {
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_ARGV, name, help, ht_insert);
	if (!res) {
		return NULL;
	}

	res->d.argv_data.cb = cb;
	get_minmax_argc(res, &res->d.argv_data.min_argc, &res->d.argv_data.max_argc);
	return res;
}

RZ_API RzCmdDesc *rz_cmd_desc_argv_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help) {
	rz_return_val_if_fail(cmd && parent && name && help && help->args, NULL);
	return argv_new(cmd, parent, name, cb, help, true);
}

static RzCmdDesc *argv_modes_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvModesCb cb, const RzCmdDescHelp *help, bool ht_insert) {
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_ARGV_MODES, name, help, ht_insert);
	if (!res) {
		return NULL;
	}

	res->d.argv_modes_data.cb = cb;
	res->d.argv_modes_data.modes = modes;
	res->d.argv_modes_data.default_mode = RZ_OUTPUT_MODE_STANDARD;
	get_minmax_argc(res, &res->d.argv_modes_data.min_argc, &res->d.argv_modes_data.max_argc);
	return res;
}

static RzCmdDesc *argv_state_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvStateCb cb, const RzCmdDescHelp *help, bool ht_insert) {
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_ARGV_STATE, name, help, ht_insert);
	if (!res) {
		return NULL;
	}

	res->d.argv_state_data.cb = cb;
	res->d.argv_state_data.modes = modes;
	res->d.argv_state_data.default_mode = RZ_OUTPUT_MODE_STANDARD;
	get_minmax_argc(res, &res->d.argv_state_data.min_argc, &res->d.argv_state_data.max_argc);
	return res;
}

/**
 * \brief Create a new command descriptor for a command that supports multiple output
 * modes (e.g. rizin commands, json, csv, etc.).
 *
 * \param cmd reference to the RzCmd
 * \param parent Parent command descriptor of the command being added
 * \param name Base name of the command. New commands will be created with the proper suffix based on the supported \p modes
 * \param modes Modes supported by the handler (see RzOutputMode). They can be put in OR to support multiple modes
 * \param cb Callback that actually executes the command
 * \param help Help structure used to describe the command when using `?` and `??`
 */
RZ_API RzCmdDesc *rz_cmd_desc_argv_modes_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvModesCb cb, const RzCmdDescHelp *help) {
	rz_return_val_if_fail(cmd && parent && name && help && help->args && modes, NULL);
	return argv_modes_new(cmd, parent, name, modes, cb, help, true);
}

/**
 * \brief Create a new command descriptor for a command that supports multiple output
 * modes (e.g. rizin commands, json, csv, etc.), where the state of the output
 * is handled by RzCmd itself.
 *
 * \param cmd reference to the RzCmd
 * \param parent Parent command descriptor of the command being added
 * \param name Base name of the command. New commands will be created with the proper suffix based on the supported \p modes
 * \param modes Modes supported by the handler (see RzOutputMode). They can be put in OR to support multiple modes
 * \param cb Callback that actually executes the command
 * \param help Help structure used to describe the command when using `?` and `??`
 */
RZ_API RzCmdDesc *rz_cmd_desc_argv_state_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvStateCb cb, const RzCmdDescHelp *help) {
	rz_return_val_if_fail(cmd && parent && name && help && help->args && modes, NULL);
	return argv_state_new(cmd, parent, name, modes, cb, help, true);
}

RZ_API RzCmdDesc *rz_cmd_desc_inner_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, const RzCmdDescHelp *help) {
	rz_return_val_if_fail(cmd && parent && name && help, NULL);
	return create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_INNER, name, help, false);
}

/**
 * \brief Create a new command descriptor for a name that is used both
 * as a group but that has a sub-command with the same name as well.
 *
 * \param cmd reference to the RzCmd
 * \param parent Parent command descriptor of the command being added
 * \param name Base name of the group/sub-command.
 * \param cb Callback that actually executes the command
 * \param help Help structure used to describe the command when using `?` and `??`
 * \param group_help Help structure used to describe the group
 */
RZ_API RzCmdDesc *rz_cmd_desc_group_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help) {
	rz_return_val_if_fail(cmd && parent && name && group_help, NULL);
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_GROUP, name, group_help, true);
	if (!res) {
		return NULL;
	}

	RzCmdDesc *exec_cd = NULL;
	if (cb && help) {
		rz_return_val_if_fail(help->args, NULL);
		exec_cd = argv_new(cmd, res, name, cb, help, false);
		if (!exec_cd) {
			rz_cmd_desc_remove(cmd, res);
			return NULL;
		}
	}

	res->d.group_data.exec_cd = exec_cd;
	return res;
}

/**
 * \brief Create a new command descriptor for a name that is used both
 * as a group but that has a sub-command with the same name as well. The
 * sub-command supports multiple output modes (e.g. rizin commands, json, csv,
 * etc.).
 *
 * \param cmd reference to the RzCmd
 * \param parent Parent command descriptor of the command being added
 * \param name Base name of the group/sub-command. New commands will be created with the proper suffix based on the supported \p modes
 * \param modes Modes supported by the handler (see RzOutputMode). They can be put in OR to support multiple modes
 * \param cb Callback that actually executes the command
 * \param help Help structure used to describe the command when using `?` and `??`
 * \param group_help Help structure used to describe the group
 */
RZ_API RzCmdDesc *rz_cmd_desc_group_modes_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvModesCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help) {
	rz_return_val_if_fail(cmd && parent && name && group_help && modes && cb && help && help->args, NULL);
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_GROUP, name, group_help, true);
	if (!res) {
		return NULL;
	}

	RzCmdDesc *exec_cd = argv_modes_new(cmd, res, name, modes, cb, help, false);
	if (!exec_cd) {
		rz_cmd_desc_remove(cmd, res);
		return NULL;
	}

	res->d.group_data.exec_cd = exec_cd;
	return res;
}

/**
 * \brief Create a new command descriptor for a name that is used both
 * as a group but that has a sub-command with the same name as well. The
 * sub-command supports multiple output modes (e.g. rizin commands, json, csv,
 * etc.), where the state of the output is handled by RzCmd itself.
 *
 * \param cmd reference to the RzCmd
 * \param parent Parent command descriptor of the command being added
 * \param name Base name of the group/sub-command. New commands will be created with the proper suffix based on the supported \p modes
 * \param modes Modes supported by the handler (see RzOutputMode). They can be put in OR to support multiple modes
 * \param cb Callback that actually executes the command
 * \param help Help structure used to describe the command when using `?` and `??`
 * \param group_help Help structure used to describe the group
 */
RZ_API RzCmdDesc *rz_cmd_desc_group_state_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvStateCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help) {
	rz_return_val_if_fail(cmd && parent && name && group_help && modes && cb && help && help->args, NULL);
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_GROUP, name, group_help, true);
	if (!res) {
		return NULL;
	}

	RzCmdDesc *exec_cd = argv_state_new(cmd, res, name, modes, cb, help, false);
	if (!exec_cd) {
		rz_cmd_desc_remove(cmd, res);
		return NULL;
	}

	res->d.group_data.exec_cd = exec_cd;
	return res;
}

RZ_API RzCmdDesc *rz_cmd_desc_oldinput_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdCb cb, const RzCmdDescHelp *help) {
	rz_return_val_if_fail(cmd && parent && name && cb, NULL);
	RzCmdDesc *res = create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_OLDINPUT, name, help, true);
	if (!res) {
		return NULL;
	}
	res->d.oldinput_data.cb = cb;
	return res;
}

RZ_API RzCmdDesc *rz_cmd_desc_fake_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, const RzCmdDescHelp *help) {
	rz_return_val_if_fail(cmd && parent && name && help, NULL);
	return create_cmd_desc(cmd, parent, RZ_CMD_DESC_TYPE_FAKE, name, help, true);
}

RZ_API RzCmdDesc *rz_cmd_desc_parent(RzCmdDesc *cd) {
	rz_return_val_if_fail(cd, NULL);
	return cd->parent;
}

RZ_API bool rz_cmd_desc_has_handler(const RzCmdDesc *cd) {
	rz_return_val_if_fail(cd, false);
	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_ARGV:
		return cd->d.argv_data.cb;
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
		return cd->d.argv_modes_data.cb;
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		return cd->d.argv_state_data.cb;
	case RZ_CMD_DESC_TYPE_OLDINPUT:
		return cd->d.oldinput_data.cb;
	case RZ_CMD_DESC_TYPE_FAKE:
	case RZ_CMD_DESC_TYPE_INNER:
		return false;
	case RZ_CMD_DESC_TYPE_GROUP:
		return cd->d.group_data.exec_cd && rz_cmd_desc_has_handler(cd->d.group_data.exec_cd);
	}
	return false;
}

RZ_API bool rz_cmd_desc_remove(RzCmd *cmd, RzCmdDesc *cd) {
	rz_return_val_if_fail(cmd && cd, false);
	if (cd->parent) {
		cmd_desc_unset_parent(cd);
	}
	cmd_desc_remove_from_ht_cmds(cmd, cd);
	cmd_desc_free(cd);
	return true;
}

/**
 * \brief Get a reference to the i-th argument of a command descriptor.
 *
 * Get a reference to the i-th argument of a command. This function is useful
 * to know which RzCmdDescArg an argument actually belongs to. In particular,
 * it deals with arguments with special flags like \p RZ_CMD_ARG_FLAG_LAST or
 * \p RZ_CMD_ARG_FLAG_ARRAY, where even if there is just one RzCmdDescArg,
 * everything is considered as part of the same RzCmdDescArg.
 */
RZ_API const RzCmdDescArg *rz_cmd_desc_get_arg(const RzCmdDesc *cd, size_t i) {
	const RzCmdDescArg *arg = cd->help->args;
	size_t j = 0;
	while (arg && arg->name) {
		if (arg->type == RZ_CMD_ARG_TYPE_FAKE) {
			arg++;
			continue;
		}
		if (i == j) {
			return arg;
		}
		if ((arg->flags & RZ_CMD_ARG_FLAG_LAST) || (arg->flags & RZ_CMD_ARG_FLAG_ARRAY)) {
			return arg;
		}
		arg++;
		j++;
	}
	return NULL;
}

static RzCmdDescHelp *mode_cmd_desc_help(RzCmdDescHelp *dst, const RzCmdDescHelp *src, const char *suffix) {
	dst->summary = rz_str_newf("%s%s", src->summary, suffix);
	dst->description = src->description;
	dst->args_str = src->args_str;
	dst->usage = src->usage;
	dst->options = src->options;
	dst->details = src->details;
	dst->args = src->args;
	return dst;
}

static void cmd_foreach_cmdname_modes(RzCmd *cmd, RzCmdDesc *cd, int modes, RzCmdForeachNameCb cb, void *user) {
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(argv_modes); i++) {
		if (modes & argv_modes[i].mode) {
			RzCmdDescHelp mode_help;
			const RzCmdDescHelp *copy = cd->help;
			cd->help = mode_cmd_desc_help(&mode_help, copy, argv_modes[i].summary_suffix);

			char *name = cd->name;
			cd->name = rz_str_newf("%s%s", name, argv_modes[i].suffix);

			cb(cmd, cd, user);

			free(cd->name);
			free((char *)mode_help.summary);
			cd->name = name;
			cd->help = copy;
		}
	}
}

static void cmd_foreach_cmdname(RzCmd *cmd, RzCmdDesc *cd, RzCmdForeachNameCb cb, void *user) {
	if (!cd) {
		return;
	}

	void **it_cd;

	switch (cd->type) {
	case RZ_CMD_DESC_TYPE_ARGV:
		if (rz_cmd_desc_has_handler(cd)) {
			cb(cmd, cd, user);
		}
		break;
	case RZ_CMD_DESC_TYPE_ARGV_STATE:
		cmd_foreach_cmdname_modes(cmd, cd, cd->d.argv_state_data.modes, cb, user);
		break;
	case RZ_CMD_DESC_TYPE_ARGV_MODES:
		cmd_foreach_cmdname_modes(cmd, cd, cd->d.argv_modes_data.modes, cb, user);
		break;
	case RZ_CMD_DESC_TYPE_FAKE:
		break;
	case RZ_CMD_DESC_TYPE_OLDINPUT:
		if (rz_cmd_desc_has_handler(cd)) {
			cb(cmd, cd, user);
		}
		// fallthrough
	case RZ_CMD_DESC_TYPE_INNER:
	case RZ_CMD_DESC_TYPE_GROUP:
		rz_cmd_desc_children_foreach(cd, it_cd) {
			RzCmdDesc *child = *it_cd;
			cmd_foreach_cmdname(cmd, child, cb, user);
		}
		break;
	}
}

/**
 * \brief Execute a callback function on each possible command the user can execute.
 *
 * Only command names that can actually execute something are iterated. Help
 * commands (e.g. ?, h?, etc.) are ignored.
 *
 * \param cmd Reference to RzCmd
 * \param begin Reference to RzCmdDesc from where to begin the for loop; if NULL the root will be used.
 * \param cb Callback function that is called for each command name.
 * \param user Additional user data that is passed to the callback \p cb.
 */
RZ_API void rz_cmd_foreach_cmdname(RzCmd *cmd, RzCmdDesc *begin, RzCmdForeachNameCb cb, void *user) {
	RzCmdDesc *cd = begin ? begin : rz_cmd_get_root(cmd);
	cmd_foreach_cmdname(cmd, cd, cb, user);
}

static char *escape_special_chars(const char *s, const char *special_chars) {
	size_t s_len = strlen(s);
	char *d = RZ_NEWS(char, s_len * 2 + 1);
	int i, j = 0;
	for (i = 0; i < s_len; i++) {
		if (strchr(special_chars, s[i])) {
			d[j++] = '\\';
		}
		d[j++] = s[i];
	}
	d[j++] = '\0';
	return d;
}

static char *unescape_special_chars(const char *s, const char *special_chars) {
	char *dst = RZ_NEWS(char, strlen(s) + 1);
	int i, j = 0;

	for (i = 0; s[i]; i++) {
		if (s[i] == '\\' && s[i + 1] == '\\') {
			dst[j++] = '\\';
			dst[j++] = '\\';
			i++;
			continue;
		}
		if (s[i] != '\\' || !strchr(special_chars, s[i + 1])) {
			dst[j++] = s[i];
			continue;
		}
		dst[j++] = s[++i];
		if (!s[i]) {
			break;
		}
	}
	dst[j++] = '\0';
	return dst;
}

/**
 * Returns an heap-allocated string with special characters considered by the
 * rizin grammar as special characters escaped. Use this when you need to
 * escape a string that should appear as argument of a command.
 */
RZ_API char *rz_cmd_escape_arg(const char *arg, RzCmdEscape esc) {
	switch (esc) {
	case RZ_CMD_ESCAPE_ONE_ARG:
		return escape_special_chars(arg, SPECIAL_CHARS_REGULAR_SINGLE);
	case RZ_CMD_ESCAPE_MULTI_ARG:
		return escape_special_chars(arg, SPECIAL_CHARS_REGULAR);
	case RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG:
		return escape_special_chars(arg, SPECIAL_CHARS_DOUBLE_QUOTED);
	case RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG:
		return escape_special_chars(arg, SPECIAL_CHARS_SINGLE_QUOTED);
	case RZ_CMD_ESCAPE_PF_ARG:
		return escape_special_chars(arg, SPECIAL_CHARS_PF);
	}
	rz_return_val_if_reached(strdup(arg));
}

/**
 * Returns an heap-allocated unescaped string. It is the opposite of
 * \p rz_cmd_escape_arg.
 */
RZ_API char *rz_cmd_unescape_arg(const char *arg, RzCmdEscape esc) {
	switch (esc) {
	case RZ_CMD_ESCAPE_ONE_ARG:
		return unescape_special_chars(arg, SPECIAL_CHARS_REGULAR_SINGLE);
	case RZ_CMD_ESCAPE_MULTI_ARG:
		return unescape_special_chars(arg, SPECIAL_CHARS_REGULAR);
	case RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG:
		return unescape_special_chars(arg, SPECIAL_CHARS_DOUBLE_QUOTED);
	case RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG:
		return unescape_special_chars(arg, SPECIAL_CHARS_SINGLE_QUOTED);
	case RZ_CMD_ESCAPE_PF_ARG:
		return unescape_special_chars(arg, SPECIAL_CHARS_PF);
	}
	rz_return_val_if_reached(strdup(arg));
}

/**
 * \brief Mark the start of an array of elements in the output.
 *
 * Output modes that support arrays will use this to mark the start of an array
 * (e.g. JSON). Used by command handlers before "printing" a list of elements.
 */
RZ_API void rz_cmd_state_output_array_start(RzCmdStateOutput *state) {
	rz_return_if_fail(state);
	if (state->mode == RZ_OUTPUT_MODE_JSON || state->mode == RZ_OUTPUT_MODE_LONG_JSON) {
		rz_return_if_fail(state->d.pj);
		pj_a(state->d.pj);
	}
}

/**
 * \brief Mark the end of an array of elements in the output.
 *
 * Output modes that support arrays will use this to mark the end of an array
 * (e.g. JSON). Used by command handlers after "printing" a list of elements.
 */
RZ_API void rz_cmd_state_output_array_end(RzCmdStateOutput *state) {
	rz_return_if_fail(state);
	if (state->mode == RZ_OUTPUT_MODE_JSON || state->mode == RZ_OUTPUT_MODE_LONG_JSON) {
		rz_return_if_fail(state->d.pj);
		pj_end(state->d.pj);
	}
}

/**
 * \brief Specify the columns of the command output
 *
 * \param state Reference to \p RzCmdStateOutput
 * \param fmt String containing the numer and types of the columns (see \p
 *            RzTable for a reference of the possible types)
 * \param ... Variable number of strings that specify the names of the columns.
 *            There should be enough string as characters in \p fmt .
 */
RZ_API void rz_cmd_state_output_set_columnsf(RzCmdStateOutput *state, const char *fmt, ...) {
	rz_return_if_fail(state);
	va_list ap;
	va_start(ap, fmt);
	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		rz_return_if_fail(state->d.t);
		rz_table_set_vcolumnsf(state->d.t, fmt, ap);
	}
	va_end(ap);
}

/**
 * \brief Clear the inner fields of RzCmdStateOutput structure, but do not free it.
 */
RZ_API void rz_cmd_state_output_fini(RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_if_fail(state);

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
	case RZ_OUTPUT_MODE_LONG_JSON:
		pj_free(state->d.pj);
		state->d.pj = NULL;
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_free(state->d.t);
		state->d.t = NULL;
		break;
	default:
		break;
	}
}

/**
 * \brief Free the RzCmdStateOutput structure and its inner fields appropriately
 */
RZ_API void rz_cmd_state_output_free(RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_if_fail(state);

	rz_cmd_state_output_fini(state);
	free(state);
}

/**
 * \brief Initialize a RzCmdStateOutput structure and its inner fields based on the provided mode
 */
RZ_API bool rz_cmd_state_output_init(RZ_NONNULL RzCmdStateOutput *state, RzOutputMode mode) {
	rz_return_val_if_fail(state, false);

	state->mode = mode;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_TABLE:
		state->d.t = rz_table_new();
		if (!state->d.t) {
			return false;
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
	case RZ_OUTPUT_MODE_LONG_JSON:
		state->d.pj = pj_new();
		if (!state->d.pj) {
			return false;
		}
		break;
	default:
		memset(&state->d, 0, sizeof(state->d));
		break;
	}
	return true;
}

/**
 * \brief Print the output accumulated in \p state to RzCons, if necessary
 *
 * Some output modes like JSON and TABLE accumulate their output in their
 * respective data structures, thus it is needed to print them to have the
 * output on screen. This function takes care of that, doing nothing in case the
 * output was already printed to console for those types that output as they go
 * (e.g. STANDARD, QUIET).
 */
RZ_API void rz_cmd_state_output_print(RZ_NONNULL RzCmdStateOutput *state) {
	rz_return_if_fail(state);

	char *s;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
	case RZ_OUTPUT_MODE_LONG_JSON:
		rz_cons_println(pj_string(state->d.pj));
		break;
	case RZ_OUTPUT_MODE_TABLE:
		s = rz_table_tostring(state->d.t);
		rz_cons_printf("%s", s);
		free(s);
		break;
	default:
		break;
	}
}

/**
 * \brief Free an array of \p RzCmdDescDetail sections
 *
 * Usually command handlers do not need to free the \p details sections because
 * they are const, but due to \p details_cb those sections could be dynamically
 * generated. In that case all the data within the details should be dynamically
 * allocated memory, even the one marked as const, as they are going to be freed
 * anyway.
 *
 * \param entries Pointer to the array of RzCmdDescDetails
 */
RZ_API void rz_cmd_desc_details_free(RzCmdDescDetail *details) {
	RzCmdDescDetail *detail_it = details;
	while (detail_it->name) {
		free((char *)detail_it->name);
		RzCmdDescDetailEntry *oentry, *entry;
		oentry = entry = (RzCmdDescDetailEntry *)detail_it->entries;
		while (entry && entry->text) {
			free((char *)entry->text);
			free((char *)entry->comment);
			free((char *)entry->arg_str);
			entry++;
		}
		free(oentry);
		detail_it++;
	}
	free(details);
}
