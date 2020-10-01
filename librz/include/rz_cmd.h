#ifndef R2_CMD_H
#define R2_CMD_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_core_t RzCore;

//R_LIB_VERSION_HEADER (rz_cmd);

#define MACRO_LIMIT 1024
#define MACRO_LABELS 20
#define R_CMD_MAXLEN 4096

typedef enum rz_cmd_status_t {
	R_CMD_STATUS_OK = 0, // command handler exited in the right way
	R_CMD_STATUS_WRONG_ARGS, // command handler could not handle the arguments passed to it
	R_CMD_STATUS_ERROR, // command handler had issues while running (e.g. allocation error, etc.)
	R_CMD_STATUS_INVALID, // command could not be executed (e.g. shell level error, not existing command, bad expression, etc.)
	R_CMD_STATUS_EXIT, // command handler asks to exit the prompt loop
} RzCmdStatus;

typedef int (*RzCmdCb) (void *user, const char *input);
typedef RzCmdStatus (*RzCmdArgvCb) (RzCore *core, int argc, const char **argv);
typedef int (*RzCmdNullCb) (void *user);

typedef struct rz_cmd_parsed_args_t {
	int argc;
	char **argv;
	bool has_space_after_cmd;
} RzCmdParsedArgs;

typedef struct rz_cmd_macro_label_t {
	char name[80];
	char *ptr;
} RzCmdMacroLabel;

typedef struct rz_cmd_macro_item_t {
	char *name;
	char *args;
	char *code;
	int codelen;
	int nargs;
} RzCmdMacroItem;

typedef struct rz_cmd_macro_t {
	int counter;
	ut64 *brk_value;
	ut64 _brk_value;
	int brk;
// 	int (*cmd)(void *user, const char *cmd);
	RzCoreCmd cmd;
	PrintfCallback cb_printf;
	void *user;
	RNum *num;
	int labels_n;
	RzCmdMacroLabel labels[MACRO_LABELS];
	RzList *macros;
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

typedef struct rz_cmd_desc_example_t {
	const char *example;
	const char *comment;
} RzCmdDescExample;

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
	 * want and it should explain well how the command behaves.
	 * This is shown, for example, when `??` is appended on command or `?`
	 * is appended and the command has no children to show. In that case,
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
	 * List of examples used to better explain how to use the command. This
	 * is shown together with the long description.
	 *
	 * Optional.
	 */
	const RzCmdDescExample *examples;
} RzCmdDescHelp;

typedef enum {
	// for old handlers that parse their own input and accept a single string
	R_CMD_DESC_TYPE_OLDINPUT = 0,
	// for handlers that accept argc/argv
	R_CMD_DESC_TYPE_ARGV,
	// for cmd descriptors that are just used to group together related
	// sub-commands. Do not use this if the command can be used by itself or
	// if it's necessary to show its help, because this descriptor is not
	// stored in the hashtable and cannot be retrieved except by listing the
	// children of its parent.
	R_CMD_DESC_TYPE_INNER,
	// for cmd descriptors that are parent of other sub-commands but that
	// may also have a sub-command with the same name. For example, `wc` is
	// both the parent of `wci`, `wc*`, etc. but there is also `wc` as a
	// sub-command.
	R_CMD_DESC_TYPE_GROUP,
} RzCmdDescType;

typedef struct rz_cmd_desc_t {
	RzCmdDescType type;
	char *name;
	struct rz_cmd_desc_t *parent;
	int n_children;
	RPVector children;
	const RzCmdDescHelp *help;

	union {
		struct {
			RzCmdCb cb;
		} oldinput_data;
		struct {
			RzCmdArgvCb cb;
		} argv_data;
		struct {
			struct rz_cmd_desc_t *exec_cd;
		} group_data;
	} d;
} RzCmdDesc;

typedef struct rz_cmd_t {
	void *data;
	RzCmdNullCb nullcallback;
	RzCmdItem *cmds[UT8_MAX];
	RzCmdMacro macro;
	RzList *lcmds;
	RzList *plist;
	RzCmdAlias aliases;
	void *language; // used to store TSLanguage *
	HtUP *ts_symbols_ht;
	RzCmdDesc *root_cmd_desc;
	HtPP *ht_cmds;
} RzCmd;

// TODO: remove this once transitioned to RzCmdDesc
typedef struct rz_cmd_descriptor_t {
	const char *cmd;
	const char **help_msg;
	const char **help_detail;
	const char **help_detail2;
	struct rz_cmd_descriptor_t *sub[127];
} RzCmdDescriptor;

// TODO: move into rz_core.h
typedef struct rz_core_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	const char *author;
	const char *version;
	RzCmdCb call; // returns true if command was handled, false otherwise.
	RzCmdCb init;
	RzCmdCb fini;
} RzCorePlugin;

#define DEFINE_CMD_ARGV_DESC_DETAIL(core, name, c_name, parent, handler, help) \
	RzCmdDesc *c_name##_cd = rz_cmd_desc_argv_new (core->rcmd, parent, #name, handler, help); \
	rz_warn_if_fail (c_name##_cd)
#define DEFINE_CMD_ARGV_DESC_SPECIAL(core, name, c_name, parent) \
	DEFINE_CMD_ARGV_DESC_DETAIL (core, name, c_name, parent, c_name##_handler, &c_name##_help)
#define DEFINE_CMD_ARGV_DESC_INNER(core, name, c_name, parent) \
	RzCmdDesc *c_name##_cd = rz_cmd_desc_inner_new (core->rcmd, parent, #name, &c_name##_help); \
	rz_warn_if_fail (c_name##_cd)
#define DEFINE_CMD_ARGV_GROUP_WITH_CHILD(core, name, parent)                                    \
	RzCmdDesc *name##_cd = rz_cmd_desc_group_new (core->rcmd, parent, #name, name##_handler, &name##_help, &name##_group_help); \
	rz_warn_if_fail (name##_cd)
#define DEFINE_CMD_ARGV_DESC(core, name, parent) \
	DEFINE_CMD_ARGV_DESC_SPECIAL (core, name, name, parent)
#define DEFINE_CMD_OLDINPUT_DESC(core, name, parent) \
	RzCmdDesc *name##_cd = rz_cmd_desc_oldinput_new (core->rcmd, parent, #name, name##_handler_old, &name##_help); \
	rz_warn_if_fail (name##_cd)

#ifdef RZ_API
RZ_API int rz_core_plugin_init(RzCmd *cmd);
RZ_API int rz_core_plugin_add(RzCmd *cmd, RzCorePlugin *plugin);
RZ_API int rz_core_plugin_check(RzCmd *cmd, const char *a0);
RZ_API int rz_core_plugin_fini(RzCmd *cmd);

RZ_API RzCmd *rz_cmd_new(void);
RZ_API RzCmd *rz_cmd_free(RzCmd *cmd);
RZ_API int rz_cmd_set_data(RzCmd *cmd, void *data);
RZ_API int rz_cmd_add(RzCmd *cmd, const char *command, RzCmdCb callback);
RZ_API int rz_core_del(RzCmd *cmd, const char *command);
RZ_API int rz_cmd_call(RzCmd *cmd, const char *command);
RZ_API RzCmdStatus rz_cmd_call_parsed_args(RzCmd *cmd, RzCmdParsedArgs *args);
RZ_API RzCmdDesc *rz_cmd_get_root(RzCmd *cmd);
RZ_API RzCmdDesc *rz_cmd_get_desc(RzCmd *cmd, const char *cmd_identifier);
RZ_API char *rz_cmd_get_help(RzCmd *cmd, RzCmdParsedArgs *args, bool use_color);

static inline RzCmdStatus rz_cmd_int2status(int v) {
	if (v == -2) {
		return R_CMD_STATUS_EXIT;
	} else if (v < 0) {
		return R_CMD_STATUS_ERROR;
	} else {
		return R_CMD_STATUS_OK;
	}
}

static inline int rz_cmd_status2int(RzCmdStatus s) {
	switch (s) {
	case R_CMD_STATUS_OK:
		return 0;
	case R_CMD_STATUS_ERROR:
	case R_CMD_STATUS_WRONG_ARGS:
	case R_CMD_STATUS_INVALID:
		return -1;
	case R_CMD_STATUS_EXIT:
	default:
		return -2;
	}
}

/* RzCmdDescriptor */
RZ_API RzCmdDesc *rz_cmd_desc_argv_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_inner_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_group_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdArgvCb cb, const RzCmdDescHelp *help, const RzCmdDescHelp *group_help);
RZ_API RzCmdDesc *rz_cmd_desc_oldinput_new(RzCmd *cmd, RzCmdDesc *parent, const char *name, RzCmdCb cb, const RzCmdDescHelp *help);
RZ_API RzCmdDesc *rz_cmd_desc_parent(RzCmdDesc *cd);
RZ_API bool rz_cmd_desc_has_handler(RzCmdDesc *cd);
RZ_API bool rz_cmd_desc_remove(RzCmd *cmd, RzCmdDesc *cd);

#define rz_cmd_desc_children_foreach(root, it_cd) rz_pvector_foreach (&root->children, it_cd)

/* RzCmdParsedArgs */
RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_new(const char *cmd, int n_args, char **args);
RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_newcmd(const char *cmd);
RZ_API RzCmdParsedArgs *rz_cmd_parsed_args_newargs(int n_args, char **args);
RZ_API void rz_cmd_parsed_args_free(RzCmdParsedArgs *args);
RZ_API bool rz_cmd_parsed_args_setargs(RzCmdParsedArgs *arg, int n_args, char **args);
RZ_API bool rz_cmd_parsed_args_setcmd(RzCmdParsedArgs *arg, const char *cmd);
RZ_API char *rz_cmd_parsed_args_argstr(RzCmdParsedArgs *arg);
RZ_API char *rz_cmd_parsed_args_execstr(RzCmdParsedArgs *arg);
RZ_API const char *rz_cmd_parsed_args_cmd(RzCmdParsedArgs *arg);

#define rz_cmd_parsed_args_foreach_arg(args, i, arg) for ((i) = 1; (i) < (args->argc) && ((arg) = (args)->argv[i]); (i)++)

/* rz_cmd_macro */
RZ_API RzCmdMacroItem *rz_cmd_macro_item_new(void);
RZ_API void rz_cmd_macro_item_free(RzCmdMacroItem *item);
RZ_API void rz_cmd_macro_init(RzCmdMacro *mac);
RZ_API int rz_cmd_macro_add(RzCmdMacro *mac, const char *name);
RZ_API int rz_cmd_macro_rm(RzCmdMacro *mac, const char *_name);
RZ_API void rz_cmd_macro_list(RzCmdMacro *mac);
RZ_API void rz_cmd_macro_meta(RzCmdMacro *mac);
RZ_API int rz_cmd_macro_call(RzCmdMacro *mac, const char *name);
RZ_API int rz_cmd_macro_break(RzCmdMacro *mac, const char *value);

RZ_API bool rz_cmd_alias_del(RzCmd *cmd, const char *k);
RZ_API char **rz_cmd_alias_keys(RzCmd *cmd, int *sz);
RZ_API int rz_cmd_alias_set(RzCmd *cmd, const char *k, const char *v, int remote);
RZ_API char *rz_cmd_alias_get(RzCmd *cmd, const char *k, int remote);
RZ_API void rz_cmd_alias_free(RzCmd *cmd);
RZ_API void rz_cmd_macro_fini(RzCmdMacro *mac);

#ifdef __cplusplus
}
#endif

#endif
#endif
