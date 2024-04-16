#ifndef RZ_CMD_H
#define RZ_CMD_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

// RZ_LIB_VERSION_HEADER (rz_cmd);

/**
 * Value returned by a command handler.
 */
typedef enum rz_cmd_status_t {
	RZ_CMD_STATUS_OK = 0, ///< command handler exited in the right way
	RZ_CMD_STATUS_WRONG_ARGS, ///< command handler could not handle the arguments passed to it
	RZ_CMD_STATUS_ERROR, ///< command handler had issues while running (e.g. allocation error, etc.)
	RZ_CMD_STATUS_INVALID, ///< command could not be executed (e.g. shell level error, bad expression, etc.)
	RZ_CMD_STATUS_NONEXISTINGCMD, ///< command does not exist
	RZ_CMD_STATUS_EXIT, ///< command handler asks to exit the prompt loop
} RzCmdStatus;

/**
 * Type of argument a command handler can have. This is used for visualization
 * in help messages and for autocompletion as well.
 */
typedef enum rz_cmd_arg_type_t {
	RZ_CMD_ARG_TYPE_FAKE, ///< This is not considered a real argument, just used to show something in the help. Name of arg is shown as-is and it is not counted.
	RZ_CMD_ARG_TYPE_NUM, ///< Argument is a number
	RZ_CMD_ARG_TYPE_RZNUM, ///< Argument that can be interpreted by RzNum (numbers, flags, operations, etc.)
	RZ_CMD_ARG_TYPE_STRING, ///< Argument that can be an arbitrary string
	RZ_CMD_ARG_TYPE_RAW, ///< Like RZ_CMD_ARG_TYPE_STRING, but quote unwrapping and unescaping is not done. TODO: currently only quote unwrapping is prevented.
	RZ_CMD_ARG_TYPE_ENV, ///< Argument can be the name of an existing rizin variable
	RZ_CMD_ARG_TYPE_CHOICES, ///< Argument can be one of the provided choices
	RZ_CMD_ARG_TYPE_FCN, ///< Argument can be the name of an existing function
	RZ_CMD_ARG_TYPE_FILE, ///< Argument is a filename
	RZ_CMD_ARG_TYPE_OPTION, ///< Argument is an option, prefixed with `-`. It is present or not. No argument.
	RZ_CMD_ARG_TYPE_CMD, ///< Argument is an rizin command
	RZ_CMD_ARG_TYPE_MACRO, ///< Argument is the name of a pre-defined macro
	RZ_CMD_ARG_TYPE_EVAL_KEY, ///< Argument is the name of a evaluable variable (e.g. `et` command)
	RZ_CMD_ARG_TYPE_EVAL_FULL, ///< Argument is the name+(optional)value of a evaluable variable (e.g. `e` command)
	RZ_CMD_ARG_TYPE_FCN_VAR, ///< Argument is the name of a function variable/argument
	RZ_CMD_ARG_TYPE_FLAG, ///< Argument is a rizin flag
	RZ_CMD_ARG_TYPE_ENUM_TYPE, ///< Argument is a C enum type name
	RZ_CMD_ARG_TYPE_STRUCT_TYPE, ///< Argument is a C struct type name
	RZ_CMD_ARG_TYPE_UNION_TYPE, ///< Argument is a C union type name
	RZ_CMD_ARG_TYPE_ALIAS_TYPE, ///< Argument is a C typedef (alias) name
	RZ_CMD_ARG_TYPE_CLASS_TYPE, ///< Argument is a C++/etc class name
	RZ_CMD_ARG_TYPE_ANY_TYPE, ///< Argument is the any of the C or C++ type name
	RZ_CMD_ARG_TYPE_GLOBAL_VAR, ///< Argument is a user defined global variable
	RZ_CMD_ARG_TYPE_REG_FILTER, ///< Argument is a register name, size, type or "all"
	RZ_CMD_ARG_TYPE_REG_TYPE, ///< Argument is a register type/arena like "gpr"
} RzCmdArgType;

/**
 * Argument can contain spaces when it is the last of a command and it would
 * be considered as a single argument by the command handler.
 */
#define RZ_CMD_ARG_FLAG_LAST (1 << 0)
/**
 * Argument is an array of elements. It must be the last in the list of
 * arguments of a command.
 */
#define RZ_CMD_ARG_FLAG_ARRAY (1 << 1)
/**
 * Argument is an option, prefixed with `-`. It is present or not.
 */
#define RZ_CMD_ARG_FLAG_OPTION (1 << 2)

typedef enum rz_cmd_escape_t {
	RZ_CMD_ESCAPE_ONE_ARG, ///< The string should be escaped so that it appears as one single argument
	RZ_CMD_ESCAPE_MULTI_ARG, ///< The string should be escaped so that it appears as one or multiple arguments
	RZ_CMD_ESCAPE_PF_ARG, ///< The string should be escaped so that it appears as one or multiple `pf` arguments
	RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG, ///< The string should be escaped so that it can be wrapped in "...."
	RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG, ///< The string should be escaped so that it can be wrapped in '....'
} RzCmdEscape;

/**
 * \brief Enum to describe the way data are printed
 */
typedef enum {
	RZ_OUTPUT_MODE_STANDARD = 1 << 0,
	RZ_OUTPUT_MODE_JSON = 1 << 1,
	RZ_OUTPUT_MODE_RIZIN = 1 << 2,
	RZ_OUTPUT_MODE_QUIET = 1 << 3,
	RZ_OUTPUT_MODE_SDB = 1 << 4,
	RZ_OUTPUT_MODE_LONG = 1 << 5,
	RZ_OUTPUT_MODE_LONG_JSON = 1 << 6,
	RZ_OUTPUT_MODE_TABLE = 1 << 7,
	RZ_OUTPUT_MODE_QUIETEST = 1 << 8,
} RzOutputMode;

/**
 * \brief Represent the output state of a command handler.
 *
 * This structure is passed to commands of type \p RZ_CMD_DESC_TYPE_ARGV_STATE .
 */
typedef struct rz_cmd_state_output_t {
	/**
	 * Output mode expected from the command handler
	 */
	RzOutputMode mode;
	/**
	 * mode-specific data. Handlers are called with these data already
	 * initialized as necessary, based on the requested mode, and they do not
	 * need to be freed by the handler.
	 */
	union {
		PJ *pj;
		RzTable *t;
	} d;
} RzCmdStateOutput;

typedef int (*RzCmdCb)(void *user, const char *input);
typedef RzCmdStatus (*RzCmdArgvCb)(RzCore *core, int argc, const char **argv);
typedef RzCmdStatus (*RzCmdArgvModesCb)(RzCore *core, int argc, const char **argv, RzOutputMode mode);
typedef RzCmdStatus (*RzCmdArgvStateCb)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state);
typedef RzCmdStatus (*RzCmdMacroCb)(RzCore *core, int argc, const char **argv, int macro);
typedef int (*RzCmdNullCb)(void *user);

/**
 * argc/argv data created from parsing the input command string.
 */
typedef struct rz_cmd_parsed_args_t {
	int argc;
	char **argv;
	bool has_space_after_cmd;
	char *extra; ///< Extra data that is neither a command name nor an argument (e.g. command modifiers/specifiers, table queries, etc.)
} RzCmdParsedArgs;

typedef struct rz_cmd_macro_t {
	char *name;
	char **args;
	size_t nargs;
	char *code;
} RzCmdMacro;

typedef struct rz_cmd_item_t {
	char cmd[64];
	RzCmdCb callback;
} RzCmdItem;

typedef struct rz_cmd_alias_t {
	int count;
	char **keys;
	char **values;
	int *remote;
} RzCmdAlias;

/**
 * \brief A detailed entry that can be used to show additional info about a command entry.
 *
 * It can contain whatever relevant information (e.g. examples, specific uses of
 * a command, variables, etc.).
 *
 * Displayed as:
 * | <text><arg_str> # <comment>
 */
typedef struct rz_cmd_desc_detail_entry_t {
	/**
	 * Main text of the detailed entry
	 */
	const char *text;
	/**
	 * Short explanation of the entry, shown with the comment color
	 */
	const char *comment;
	/**
	 * Text to show in a different color, after `text`, usually used to show
	 * arguments for examples.
	 *
	 * Optional.
	 */
	const char *arg_str;
} RzCmdDescDetailEntry;

/**
 * A detail section used to better describe a command.
 */
typedef struct rz_cmd_desc_detail_t {
	/**
	 * Name of the section, displayed at the beginning of the section.
	 */
	const char *name;
	/**
	 * NULL-terminated array of entries, displayed one per line.
	 */
	const RzCmdDescDetailEntry *entries;
} RzCmdDescDetail;

/**
 * Callback used to dynamically generate the details sections in the help of a command.
 * NOTE: The array of RzCmdDescDetail returned will be freed, so all fields
 * within need to be dynamically allocated even if they are marked as `const`.
 */
typedef RZ_OWN RzCmdDescDetail *(*RzCmdDescDetailCb)(RzCore *core, int argc, const char **argv);

/**
 * Callback used to dynamically generate the choices of an argument with type \p RZ_CMD_ARG_TYPE_CHOICES
 */
typedef RZ_OWN char **(*RzCmdArgChoiceCb)(RzCore *core);

/**
 * A description of an argument of a RzCmdDesc.
 */
typedef struct rz_cmd_desc_arg_t {
	/**
	 * The name of the argument, shown also in its help.
	 */
	const char *name;
	/**
	 * True if the argument is optional. If argument X is optional, then all
	 * arguments after X can only be specified if X was provided as well and
	 * they don't need to be set as optional.
	 *
	 * Example:
	 * CMDNAME <mandatory-arg0> [<optional-arg1> <optional-arg2> [<optional-arg3> [optional-arg4]]]
	 * <mandatory-arg0> has optional=false
	 * <optional-arg1> has optional=true
	 * <optional-arg2> has optional=false (it can be specified only if arg1
	 *                 was specified as well, so it doesn't need to be optional)
	 * <optional-arg3> has optional=true
	 * <optional-arg4> has optional=true
	 * Given the above:
	 * - `CMDNAME a0` is a valid command
	 * - `CMDNAME a0 a1 a2` is a valid command
	 * - `CMDNAME a0 a1` is not a valid command, because if a1 is specified, also a2 has to be
	 * - `CMDNAME a0 a1 a2 a3` is a valid command
	 * - `CMDNAME a0 a1 a2 a3 a4` is a valid command
	 */
	bool optional;
	/**
	 * True if no space should be displayed before this argument in the help. By default it is
	 * false and a space is displayed before this argument.
	 */
	bool no_space;
	/**
	 * Type of the argument.
	 */
	RzCmdArgType type;
	/**
	 * Flag of the argument, used to modify the behaviour of this argument. See RZ_CMD_ARG_FLAG_ values.
	 */
	int flags;
	/**
	 * Default value for the argument, if it is not specified. This field
	 * shall be used only when \p optional is true.
	 */
	const char *default_value;
	/**
	 * Additional data which is type specific.
	 */
	union {
		/**
		 * Data associated with an argument of \p type RZ_CMD_ARG_TYPE_CHOICES.
		 */
		struct {
			/**
			 * Predefined list of possible values.
			 */
			const char **choices;
			/**
			 * Callback used to generate a list of possible values.
			 * When this is specified, \p choices is ignored.
			 */
			RzCmdArgChoiceCb choices_cb;
		} choices;
	};
} RzCmdDescArg;

/**
 * Define how the command looks like in the help.
 */
typedef struct rz_cmd_desc_help_t {
	/**
	 * Short-sentence explaining what the command does.
	 * This is shown, for example, when the list of sub-commands is printed
	 * and each sub-command has a very short description on the right,
	 * explaining what it does.
	 */
	const char *summary;
	/**
	 * Long description of what the command does. It can be as long as you
	 * want and it should explain well how the command behaves. This is
	 * shown, for example, when `??` is appended on a command. In that case,
	 * the short summary is extended with this longer description.
	 *
	 * Optional.
	 */
	const char *description;
	/**
	 * String used to identify the arguments. This usually comes together
	 * with the summary.
	 * TODO: explain how to differentiate between required and optional arguments
	 */
	const char *args_str;
	/**
	 * String that overrides the name+args_str usually used to describe the
	 * command.
	 *
	 * Optional.
	 */
	const char *usage;
	/**
	 * String to use as sub-commands suggestions instead of the
	 * auto-generated one (e.g. [abcd] or [?] that you can see near command
	 * names when doing `w?`). If not provided, the options will be
	 * auto-generated.
	 *
	 * Optional.
	 */
	const char *options;
	/**
	 * When true, the subcommands are automatically sorted alphabetically. By
	 * default subcommands are shown in the order provided by the developer.
	 *
	 * Optional.
	 */
	bool sort_subcommands;
	/**
	 * NULL-terminated array of details sections used to better explain how
	 * to use the command. This is shown together with the long description.
	 *
	 * Optional.
	 */
	const RzCmdDescDetail *details;
	/**
	 * Function that returns an array of details sections used to better explain
	 * how to use the command. This is shown together with the long description
	 * and can be used in addition or in alternative of \p details , when the
	 * output needs to be generated dynamically.
	 *
	 * Optional.
	 */
	RzCmdDescDetailCb details_cb;
	/**
	 * Description of the arguments accepted by this command.
	 */
	const RzCmdDescArg *args;
} RzCmdDescHelp;

typedef enum rz_cmd_desc_type_t {
	/**
	 * For old handlers that parse their own input and accept a single string.
	 * Mainly used for legacy reasons with old command handlers.
	 */
	RZ_CMD_DESC_TYPE_OLDINPUT = 0,
	/**
	 * For handlers that accept argc/argv. It cannot have children. Use
	 * RZ_CMD_DESC_TYPE_GROUP if you need a command that can be both
	 * executed and has sub-commands.
	 */
	RZ_CMD_DESC_TYPE_ARGV,
	/**
	 * For cmd descriptors that are parent of other sub-commands, even if
	 * they may also have a sub-command with the same name. For example,
	 * `wc` is both the parent of `wci`, `wc*`, etc. but there is also `wc`
	 * as a sub-command.
	 */
	RZ_CMD_DESC_TYPE_GROUP,
	/**
	 * For cmd descriptors that are just used to group together related
	 * sub-commands. Do not use this if the command can be used by itself or
	 * if it's necessary to show its help, because this descriptor is not
	 * stored in the hashtable and cannot be retrieved except by listing the
	 * children of its parent. Most of the time you want RZ_CMD_DESC_TYPE_GROUP.
	 */
	RZ_CMD_DESC_TYPE_INNER,
	/**
	 * For entries that shall be shown in the help tree but that are not
	 * commands on their own. `|?`, `@?`, `>?` are example of this. It is
	 * useful to provide help entries for them in the tree, but there are no
	 * command handlers for these. The RzCmdDescDetail in the help can be
	 * used to show fake children of this descriptor.
	 */
	RZ_CMD_DESC_TYPE_FAKE,
	/**
	 * For handlers that accept argc/argv and that provides multiple output
	 * modes (e.g. rizin commands, quiet output, json, long). It cannot have
	 * children. Use RZ_CMD_DESC_TYPE_GROUP if you need a command that can
	 * be both executed and has sub-commands.
	 */
	RZ_CMD_DESC_TYPE_ARGV_MODES,
	/**
	 * For handlers that accept argc/argv and that provides multiple output
	 * modes (e.g. rizin commands, quiet output, json, long). It cannot have
	 * children. Use RZ_CMD_DESC_TYPE_GROUP if you need a command that can
	 * be both executed and has sub-commands.
	 *
	 * Differently from \p RZ_CMD_DESC_TYPE_ARGV_MODES, these handlers receive
	 * an output structure with the mode and data already initialized (e.g. PJ,
	 * RzTable, etc.) and the handler just has to fill the data in those
	 * structure, while RzCmd will allocate, free and print the data within.
	 */
	RZ_CMD_DESC_TYPE_ARGV_STATE,
} RzCmdDescType;

/**
 * Command Descriptor structure. It represents a command that can be executed
 * by the user on the shell or a part of the command help (e.g. groups of
 * commands). Anything that appears under `?` has an associated command
 * descriptor.
 */
typedef struct rz_cmd_desc_t {
	/**
	 * Type of the command descriptor. There are several types of commands:
	 * those that are still using the old-style and parses the input string
	 * themselves, those that accept argc/argv, etc.
	 */
	RzCmdDescType type;
	/**
	 * Base name of the command. This is used to retrieve the \p RzCmdDesc when
	 * a user executes a command. It can match multiple user-called commands.
	 * For example a command that accepts STANDARD and JSON \p modes is called
	 * for both `<name>` and `<name>j`.
	 */
	char *name;
	/**
	 * Parent of this command descriptor.
	 *
	 * Commands are organized in a tree, with the root being shown when doing
	 * `?`. This relationship is used when showing commands helps.
	 */
	struct rz_cmd_desc_t *parent;
	/**
	 * Number of children command descriptors of this node.
	 */
	int n_children;
	/**
	 * Vector of childrens command descriptors.
	 */
	RzPVector /*<RzCmdDesc *>*/ children;
	/**
	 * Reference to the help structure of this command descriptor.
	 */
	const RzCmdDescHelp *help;

	/**
	 * Type-specific fields.
	 */
	union {
		struct {
			RzCmdCb cb;
		} oldinput_data;
		struct {
			RzCmdArgvCb cb;
			int min_argc;
			int max_argc;
		} argv_data;
		struct {
			struct rz_cmd_desc_t *exec_cd;
		} group_data;
		struct {
			RzCmdArgvModesCb cb;
			int modes; ///< A combination of RzOutputMode values
			RzOutputMode default_mode; ///< Make one of the modes the default one, used even when the special suffix is not specified.
			int min_argc;
			int max_argc;
		} argv_modes_data;
		struct {
			RzCmdArgvStateCb cb;
			int modes; ///< A combination of RzOutputMode values
			RzOutputMode default_mode; ///< Make one of the modes the default one, used even when the special suffix is not specified.
			int min_argc;
			int max_argc;
		} argv_state_data;
	} d;
} RzCmdDesc;

typedef struct rz_cmd_t {
	RzCore *core;
	RzCmdNullCb nullcallback;
	RzCmdItem *cmds[UT8_MAX];
	RzCmdAlias aliases;
	HtSP *macros; ///< Map of macros (char *)name -> RzCmdMacro
	void *language; // used to store TSLanguage *
	HtUP *ts_symbols_ht;
	RzCmdDesc *root_cmd_desc;
	HtSP *ht_cmds;
	/**
	 * True if a rz_cons_instance exists. When used from RzCore this is
	 * commonly true. However, it can be used in tests to avoid access to
	 * non-initialized RzCons.
	 */
	bool has_cons;
	/**
	 * True when you want to add multiple commands in batch. This is an
	 * optimization mainly for groups that require sorted sub-commands, so
	 * instead of sorting on each addition we just sort one time at the end.
	 * False by default.
	 */
	bool batch;
} RzCmd;

// TODO: remove this once transitioned to RzCmdDesc
typedef struct rz_cmd_descriptor_t {
	const char *cmd;
	const char **help_msg;
	const char **help_detail;
	const char **help_detail2;
	struct rz_cmd_descriptor_t *sub[127];
} RzCmdDescriptor;

typedef bool (*RzCmdForeachNameCb)(RzCmd *cmd, const RzCmdDesc *desc, void *user);
typedef bool (*RzCmdForeachMacroCb)(RzCmd *cmd, const RzCmdMacro *macro, void *user);

#ifdef RZ_API
RZ_API RzCmd *rz_cmd_new(RzCore *core, bool has_cons);
RZ_API RzCmd *rz_cmd_free(RzCmd *cmd);
RZ_API void rz_cmd_batch_start(RzCmd *cmd);
RZ_API void rz_cmd_batch_end(RzCmd *cmd);
RZ_API int rz_cmd_add(RzCmd *cmd, const char *command, RzCmdCb callback);
RZ_API int rz_cmd_call(RzCmd *cmd, const char *command);
RZ_API RzCmdStatus rz_cmd_call_parsed_args(RzCmd *cmd, RzCmdParsedArgs *args);
RZ_API RzCmdDesc *rz_cmd_get_root(RzCmd *cmd);
RZ_API RzCmdDesc *rz_cmd_get_desc(RzCmd *cmd, const char *cmd_identifier);
RZ_API RzCmdDesc *rz_cmd_get_desc_best(RzCmd *cmd, const char *cmd_identifier);
RZ_API char *rz_cmd_get_help(RzCmd *cmd, RzCmdParsedArgs *args, bool use_color);
RZ_API bool rz_cmd_get_help_json(RzCmd *cmd, const RzCmdDesc *cd, PJ *j);
RZ_API bool rz_cmd_get_help_strbuf(RzCmd *cmd, const RzCmdDesc *cd, bool use_color, RzStrBuf *sb);

static inline RzCmdStatus rz_cmd_int2status(int v) {
	if (v == -2) {
		return RZ_CMD_STATUS_EXIT;
	} else if (v < 0) {
		return RZ_CMD_STATUS_ERROR;
	} else {
		return RZ_CMD_STATUS_OK;
	}
}

static inline int rz_cmd_status2int(RzCmdStatus s) {
	switch (s) {
	case RZ_CMD_STATUS_OK:
		return 0;
	case RZ_CMD_STATUS_ERROR:
	case RZ_CMD_STATUS_WRONG_ARGS:
	case RZ_CMD_STATUS_INVALID:
	case RZ_CMD_STATUS_NONEXISTINGCMD:
		return -1;
	case RZ_CMD_STATUS_EXIT:
	default:
		return -2;
	}
}

/* RzCmdDescriptor */
RZ_API RzCmdDesc *rz_cmd_desc_argv_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_argv_modes_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvModesCb cb, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_argv_state_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvStateCb cb, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_inner_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_group_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help);
RZ_API RzCmdDesc *rz_cmd_desc_group_modes_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvModesCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help);
RZ_API RzCmdDesc *rz_cmd_desc_group_state_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, int modes, RzCmdArgvStateCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help);
RZ_API RzCmdDesc *rz_cmd_desc_oldinput_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdCb cb, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_fake_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_parent(RzCmdDesc *cd);
RZ_API RzCmdDesc *rz_cmd_desc_get_exec(RzCmdDesc *cd);
RZ_API bool rz_cmd_desc_set_default_mode(RzCmdDesc *cd, RzOutputMode mode);
RZ_API bool rz_cmd_desc_has_handler(const RzCmdDesc *cd);
RZ_API bool rz_cmd_desc_remove(RzCmd *cmd, RzCmdDesc *cd);
RZ_API void rz_cmd_foreach_cmdname(RzCmd *cmd, RzCmdDesc *begin, RzCmdForeachNameCb cb, void *user);
RZ_API const RzCmdDescArg *rz_cmd_desc_get_arg(const RzCmdDesc *cd, size_t i);

#define rz_cmd_desc_children_foreach(root, it_cd) rz_pvector_foreach (&root->children, it_cd)

RZ_API void rz_cmd_desc_details_free(RzCmdDescDetail *details);

/* RzCmdParsedArgs */
RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_new(const char *cmd, int n_args, char **args);
RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_newcmd(const char *cmd);
RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_newargs(int n_args, char **args);
RZ_API void rz_cmd_parsed_args_free(RzCmdParsedArgs *args);
RZ_API bool rz_cmd_parsed_args_setargs(RzCmdParsedArgs *arg, int n_args, char **args);
RZ_API bool rz_cmd_parsed_args_addarg(RzCmdParsedArgs *a, const char *arg);
RZ_API bool rz_cmd_parsed_args_setcmd(RzCmdParsedArgs *arg, const char *cmd);
RZ_API char *rz_cmd_parsed_args_argstr(RzCmdParsedArgs *arg);
RZ_API char *rz_cmd_parsed_args_execstr(RzCmdParsedArgs *arg);
RZ_API const char *rz_cmd_parsed_args_cmd(RzCmdParsedArgs *arg);

RZ_API char *rz_cmd_escape_arg(const char *arg, RzCmdEscape escape);
RZ_API char *rz_cmd_unescape_arg(const char *arg, RzCmdEscape escape);

RZ_API void rz_cmd_state_output_array_start(RzCmdStateOutput *state);
RZ_API void rz_cmd_state_output_array_end(RzCmdStateOutput *state);
RZ_API void rz_cmd_state_output_set_columnsf(RzCmdStateOutput *state, const char *fmt, ...);
RZ_API bool rz_cmd_state_output_init(RZ_NONNULL RzCmdStateOutput *state, RzOutputMode mode);
RZ_API void rz_cmd_state_output_fini(RZ_NONNULL RzCmdStateOutput *state);
RZ_API void rz_cmd_state_output_free(RZ_NONNULL RzCmdStateOutput *state);
RZ_API void rz_cmd_state_output_print(RZ_NONNULL RzCmdStateOutput *state);

#define rz_cmd_parsed_args_foreach_arg(args, i, arg) for ((i) = 1; (i) < (args->argc) && ((arg) = (args)->argv[i]); (i)++)

/* rz_cmd_macro */
RZ_API bool rz_cmd_macro_add(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, const char **args, RZ_NONNULL const char *code);
RZ_API bool rz_cmd_macro_update(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, const char **args, RZ_NONNULL const char *code);
RZ_API bool rz_cmd_macro_rm(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name);
RZ_API const RzCmdMacro *rz_cmd_macro_get(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name);
RZ_API RZ_OWN RzList /*<RzCmdMacro *>*/ *rz_cmd_macro_list(RZ_NONNULL RzCmd *cmd);
RZ_API RzCmdStatus rz_cmd_macro_call(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, RZ_NONNULL const char **argv);
RZ_API RzCmdStatus rz_cmd_macro_call_multiple(RZ_NONNULL RzCmd *cmd, RZ_NONNULL const char *name, RZ_NONNULL const char **argv);
RZ_API void rz_cmd_macro_foreach(RZ_NONNULL RzCmd *cmd, RzCmdForeachMacroCb cb, void *user);

RZ_API bool rz_cmd_alias_del(RzCmd *cmd, const char *k);
RZ_API char **rz_cmd_alias_keys(RzCmd *cmd, int *sz);
RZ_API int rz_cmd_alias_set(RzCmd *cmd, const char *k, const char *v, int remote);
RZ_API char *rz_cmd_alias_get(RzCmd *cmd, const char *k, int remote);
RZ_API void rz_cmd_alias_free(RzCmd *cmd);

#ifdef __cplusplus
}
#endif

#endif
#endif
