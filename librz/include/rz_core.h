// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CORE_H
#define RZ_CORE_H

#include <rz_main.h>
#include <rz_arch.h>
#include <rz_types.h>
#include <rz_magic.h>
#include <rz_agraph.h>
#include <rz_io.h>
#include <rz_lib.h>
#include <rz_diff.h>
#include <rz_egg.h>
#include <rz_lang.h>
#include <rz_asm.h>
#include <rz_parse.h>
#include <rz_analysis.h>
#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_search.h>
#include <rz_sign.h>
#include <rz_debug.h>
#include <rz_flag.h>
#include <rz_config.h>
#include <rz_bin.h>
#include <rz_hash.h>
#include <rz_util.h>
#include <rz_util/ht_uu.h>
#include <rz_util/rz_print.h>
#include <rz_crypto.h>
#include <rz_bind.h>
#include <rz_util/rz_annotated_code.h>
#include <rz_heap_glibc.h>
#include <rz_windows_heap.h>

#ifdef __cplusplus
extern "C" {
#endif
RZ_LIB_VERSION_HEADER(rz_core);

#define RZ_CORE_CMD_OK      0
#define RZ_CORE_CMD_INVALID -1
#define RZ_CORE_CMD_EXIT    -2

#define RZ_CORE_BLOCKSIZE     0x100
#define RZ_CORE_BLOCKSIZE_MAX 0x3200000 /* 32MB */

#define RZ_FLAGS_FS_CLASSES                 "classes"
#define RZ_FLAGS_FS_FUNCTIONS               "functions"
#define RZ_FLAGS_FS_IMPORTS                 "imports"
#define RZ_FLAGS_FS_RELOCS                  "relocs"
#define RZ_FLAGS_FS_REGISTERS               "registers"
#define RZ_FLAGS_FS_RESOURCES               "resources"
#define RZ_FLAGS_FS_SECTIONS                "sections"
#define RZ_FLAGS_FS_SEGMENTS                "segments"
#define RZ_FLAGS_FS_SIGNS                   "sign"
#define RZ_FLAGS_FS_STRINGS                 "strings"
#define RZ_FLAGS_FS_SYMBOLS                 "symbols"
#define RZ_FLAGS_FS_SYMBOLS_SECTIONS        "symbols.sections"
#define RZ_FLAGS_FS_SYSCALLS                "syscalls"
#define RZ_FLAGS_FS_MMIO_REGISTERS          "registers.mmio"
#define RZ_FLAGS_FS_MMIO_REGISTERS_EXTENDED "registers.extended"
#define RZ_FLAGS_FS_PLATFORM_PORTS          "platform.ports"
#define RZ_FLAGS_FS_GLOBALS                 "globals"
#define RZ_FLAGS_FS_DEBUG_MAPS              "maps"
#define RZ_FLAGS_FS_POINTERS                "pointers"

///
#define RZ_CONS_COLOR_DEF(x, def) ((core->cons && core->cons->context->pal.x) ? core->cons->context->pal.x : def)
#define RZ_CONS_COLOR(x)          RZ_CONS_COLOR_DEF(x, "")

/* rtr */
#define RTR_PROTOCOL_RAP  0
#define RTR_PROTOCOL_TCP  1
#define RTR_PROTOCOL_UDP  2
#define RTR_PROTOCOL_HTTP 3
#define RTR_PROTOCOL_UNIX 4

#define RTR_MAX_HOSTS 255

typedef enum {
	RZ_CORE_WRITE_OP_BYTESWAP2, ///< Swap the endianess of 2-bytes values
	RZ_CORE_WRITE_OP_BYTESWAP4, ///< Swap the endianess of 4-bytes values
	RZ_CORE_WRITE_OP_BYTESWAP8, ///< Swap the endianess of 8-bytes values
	RZ_CORE_WRITE_OP_ADD, ///< Write the addition of existing byte and argument value
	RZ_CORE_WRITE_OP_SUB, ///< Write the subtraction of existing byte and argument value
	RZ_CORE_WRITE_OP_DIV, ///< Write the division of existing byte and argument value
	RZ_CORE_WRITE_OP_MUL, ///< Write the multiplication of existing byte and argument value
	RZ_CORE_WRITE_OP_AND, ///< Write the bitwise-and of existing byte and argument value
	RZ_CORE_WRITE_OP_OR, ///< Write the bitwise-or of existing byte and argument value
	RZ_CORE_WRITE_OP_XOR, ///< Write the bitwise-xor of existing byte and argument value
	RZ_CORE_WRITE_OP_SHIFT_LEFT, ///< Write the shift left of existing byte by argument value
	RZ_CORE_WRITE_OP_SHIFT_RIGHT, ///< Write the shift right of existing byte and argument value
} RzCoreWriteOp;

typedef bool (*RzCorePluginCallback)(RzCore *core);

typedef struct rz_core_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	const char *author;
	const char *version;
	RzCorePluginCallback init; ///< Is called when the plugin is loaded by rizin
	RzCorePluginCallback fini; ///< Is called when the plugin is unloaded by rizin
	RzCorePluginCallback analysis; ///< Is called when automatic analysis is performed.
} RzCorePlugin;

typedef struct rz_core_rtr_host_t RzCoreRtrHost;

typedef enum {
	AUTOCOMPLETE_DEFAULT,
	AUTOCOMPLETE_MS
} RAutocompleteType;

/**
 * Represent an entry in the seek history.
 * This is the "full state" of that point in time.
 */
typedef struct rz_core_seek_undo_t {
	ut64 offset; ///< Value of core->offset at the given time in history
	int cursor; ///< Position of the cursor at the given time in history
	bool is_current; ///< True if this is the current seek value
	int idx; ///< Position of the item relative to the current seek item (0 current seek, < 0 for undos, > 0 for redos)
} RzCoreSeekItem;

typedef struct rz_core_file_t {
	struct rz_core_t *core;
	int dbg;
	int fd;
	RzPVector /*<RzBinFile *>*/ binfiles; ///< all bin files that have been created for this core file
	RzPVector /*<RzIODesc *>*/ extra_files; ///< additional files opened during mapping, for example for zeroed maps
	RzPVector /*<RzIOMap *>*/ maps; ///< all maps that have been created as a result of loading this file
} RzCoreFile;

/**
 * Data to be stored inside RzIOMap.user to track back to its origin
 */
typedef struct rz_core_io_map_info_t {
	RzCoreFile *cf;

	/**
	 * Original perms as specified for example by the RzBinMap.
	 *
	 * This may be different from the RzIOMap's perms because io will disable writing if the
	 * file has been opened read-only. If one needs the info whether a e.g. the segment causing
	 * this map is writeable, this is the place to look for.
	 * Used by rz-ghidra for example.
	 */
	int perm_orig;
} RzCoreIOMapInfo;

typedef struct rz_core_times_t {
	ut64 loadlibs_init_time;
	ut64 loadlibs_time;
	ut64 file_open_time;
} RzCoreTimes;

#define RZ_CORE_ASMQJMPS_NUM         10
#define RZ_CORE_ASMQJMPS_LETTERS     26
#define RZ_CORE_ASMQJMPS_MAX_LETTERS (26 * 26 * 26 * 26 * 26)
#define RZ_CORE_ASMQJMPS_LEN_LETTERS 5

typedef enum rz_core_autocomplete_types_t {
	RZ_CORE_AUTOCMPLT_DFLT = 0,
	RZ_CORE_AUTOCMPLT_FLAG,
	RZ_CORE_AUTOCMPLT_FLSP,
	RZ_CORE_AUTOCMPLT_SEEK,
	RZ_CORE_AUTOCMPLT_FCN,
	RZ_CORE_AUTOCMPLT_EVAL,
	RZ_CORE_AUTOCMPLT_MINS,
	RZ_CORE_AUTOCMPLT_BRKP,
	RZ_CORE_AUTOCMPLT_MACR,
	RZ_CORE_AUTOCMPLT_FILE,
	RZ_CORE_AUTOCMPLT_THME,
	RZ_CORE_AUTOCMPLT_OPTN,
	RZ_CORE_AUTOCMPLT_MS,
	RZ_CORE_AUTOCMPLT_SDB,
	// --- left as last always
	RZ_CORE_AUTOCMPLT_END,
} RzCoreAutocompleteType;

typedef struct rz_core_autocomplete_t {
	const char *cmd;
	int length;
	int n_subcmds;
	bool locked;
	int type;
	struct rz_core_autocomplete_t **subcmds;
} RzCoreAutocomplete;

typedef struct {
	int x;
	int y;
	int w;
	int h;
	char *cmd;
} RzCoreGadget;

typedef struct rz_core_task_t RzCoreTask;

/**
 * Scheduler-wide callback to switch any necessary context from cur to next.
 */
typedef void (*RzCoreTaskContextSwitch)(RzCoreTask *next, void *user);

/**
 * Scheduler-wide callback for breaking a task.
 */
typedef void (*RzCoreTaskBreak)(RzCoreTask *task, void *user);

typedef struct rz_core_tasks_t {
	RzCoreTaskContextSwitch ctx_switch;
	void *ctx_switch_user;
	RzCoreTaskBreak break_cb;
	void *break_cb_user;
	int task_id_next;
	RzList /*<RzCoreTask *>*/ *tasks;
	RzList /*<RzCoreTask *>*/ *tasks_queue;
	RzList /*<OneShot *>*/ *oneshot_queue;
	int oneshots_enqueued;
	struct rz_core_task_t *current_task;
	struct rz_core_task_t *main_task;
	RzThreadLock *lock;
	int tasks_running;
	bool oneshot_running;
} RzCoreTaskScheduler;

/**
 * Keep track of the seek history, by allowing undo/redo behaviour. Each seek
 * is saved in the undos stack (unless cfg.seek.silent is set), so you can go
 * back to where you previously were. Once an undo is done, the previously set
 * address is put in the redos stack, so it is possible to go back and forth.
 * Once a new seek is performed, all redos are lost.
 */
typedef struct rz_core_seek_history_t {
	RzVector /*<RzCoreSeekItem>*/ undos; ///< Stack of RzCoreSeekItems, allowing to "go back in time"
	RzVector /*<RzCoreSeekItem>*/ redos; ///< Stack of RzCoreSeekItems, allowing to re-do an action that was undone.
	bool saved_set; ///< When true, the \p saved field is set
	RzCoreSeekItem saved_item; ///< Position to save in history
} RzCoreSeekHistory;

struct rz_core_t {
	RzBin *bin;
	RzList /*<RzCorePlugin *>*/ *plugins; ///< List of registered core plugins
	RzConfig *config;
	ut64 offset; // current seek
	ut64 prompt_offset; // temporarily set to offset to have $$ in expressions always stay the same during temp seeks
	ut32 blocksize;
	ut32 blocksize_max;
	ut8 *block;
	RzBuffer *yank_buf;
	ut64 yank_addr;
	bool tmpseek;
	bool vmode;
	int interrupted; // XXX IS THIS DUPPED SOMEWHERE?
	/* files */
	RzCons *cons;
	RzIO *io;
	RzCoreFile *file;
	RzList /*<RzCoreFile *>*/ *files;
	RzNum *num;
	ut64 rc; // command's return code .. related to num->value;
	RzLib *lib;
	RzCmd *rcmd;
	RzCmdDescriptor root_cmd_descriptor;
	RzList /*<RzCmdDescriptor *>*/ *cmd_descriptors;
	RzAnalysis *analysis;
	RzAsm *rasm;
	/* ^^ */
	RzCoreTimes *times;
	RzParse *parser;
	RzPrint *print;
	RzLang *lang;
	RzDebug *dbg;
	RzFlag *flags;
	RzSearch *search;
	RzEgg *egg;
	RzCrypto *crypto;
	RzAGraph *graph;
	char *cmdqueue;
	char *lastcmd;
	bool is_lastcmd;
	bool is_pipe;
	char *cmdlog;
	int cmdrepeat; // cmd.repeat
	const char *cmdtimes; // cmd.times
	RZ_DEPRECATE bool cmd_in_backticks; // whether currently executing a cmd out of backticks
	int rtr_n;
	RzCoreRtrHost *rtr_host; // array of RzCoreRtrHost
	ut64 *asmqjmps;
	int asmqjmps_count;
	int asmqjmps_size;
	bool is_asmqjmps_letter;
	bool keep_asmqjmps;
	/* TODO: Remove this from RzCore */
	void *visual; /* RzCoreVisual */
	int http_up;
	int gdbserver_up;
	char *stkcmd;
	bool in_search;
	RzList /*<RzCoreCmpWatcher *>*/ *watchers;
	RzList /*<char *>*/ *scriptstack;
	RzCoreTaskScheduler tasks;
	int max_cmd_depth;
	ut8 switch_file_view;
	Sdb *sdb;
	int incomment;
	/* TODO: Move this to RzCoreVisual instead */
	int curtab; // current tab
	int seltab; // selected tab
	char *cmdremote;
	char *lastsearch;
	char *cmdfilter;
	char *curtheme;
	bool break_loop;
	bool binat;
	bool fixedbits; // will be true when using @b:
	bool fixedarch; // will be true when using @a:
	bool fixedblock;
	char *table_query;
	struct rz_core_t *c2;
	RzCoreAutocomplete *autocomplete;
	int autocomplete_type;
	int maxtab;
	RzEvent *ev;
	RzList /*<RzCoreGadget *>*/ *gadgets;
	bool scr_gadgets;
	bool log_events; // core.c:cb_event_handler : log actions from events if cfg.log.events is set
	RzList /*<char *>*/ *ropchain;
	RzCoreSeekHistory seek_history;
	RzHash *hash;

	bool marks_init;
	ut64 marks[UT8_MAX + 1];

	RzMainCallback rz_main_rizin;
	// int (*rz_main_rizin)(int argc, char **argv);
	int (*rz_main_rz_find)(int argc, const char **argv);
	int (*rz_main_rz_diff)(int argc, const char **argv);
	int (*rz_main_rz_bin)(int argc, const char **argv);
	int (*rz_main_rz_run)(int argc, const char **argv);
	int (*rz_main_rz_gg)(int argc, const char **argv);
	int (*rz_main_rz_asm)(int argc, const char **argv);
	int (*rz_main_rz_ax)(int argc, const char **argv);
};

// maybe move into RzAnalysis
typedef struct rz_core_item_t {
	const char *type;
	ut64 addr;
	ut64 next;
	ut64 prev;
	int size;
	int perm;
	char *data;
	char *comment;
	char *sectname;
	char *fcnname;
} RzCoreItem;

typedef int (*RzCoreSearchCallback)(RzCore *core, ut64 from, ut8 *buf, int len);

/**
 * \brief Store some display name from RzBinSymbol
 * \see rz_core_sym_name_init
 * \see rz_core_sym_name_fini
 */
typedef struct rz_bin_sym_names_t {
	const char *pfx; ///< prefix for flags
	char *name; ///< raw symbol name
	char *symbolname; ///< display symbol name
	char *libname; ///< name of the lib this symbol is specific to, if any
	char *nameflag; ///< flag name for symbol
	char *demname; ///< demangled raw symbol name
	char *demflag; ///< flag name for demangled symbol
	char *classname; ///< classname
	char *classflag; ///< flag for classname
	char *methname; ///< methods [class]::[method]
	char *methflag; ///< methods flag sym.[class].[method]
} RzBinSymNames;

/**
 * \brief Message for `pdJ`
 */
typedef struct rz_analysis_disasm_text_t {
	ut64 offset;
	ut64 arrow; ///< In general, arrow = UT64_MAX, if there is a jump(jmp, ...), arrow = dst offset
	char *text;
} RzAnalysisDisasmText;

#ifdef RZ_API
RZ_API int rz_core_bind(RzCore *core, RzCoreBind *bnd);

RZ_API void rz_core_notify_begin(RZ_NONNULL RzCore *core, RZ_NONNULL const char *format, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API void rz_core_notify_done(RZ_NONNULL RzCore *core, RZ_NONNULL const char *format, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API void rz_core_notify_error(RZ_NONNULL RzCore *core, RZ_NONNULL const char *format, ...) RZ_PRINTF_CHECK(2, 3);

RZ_API void rz_core_notify_begin_bind(RZ_NONNULL RzCore *core, RZ_NONNULL const char *text);
RZ_API void rz_core_notify_done_bind(RZ_NONNULL RzCore *core, RZ_NONNULL const char *text);
RZ_API void rz_core_notify_error_bind(RZ_NONNULL RzCore *core, RZ_NONNULL const char *text);

/**
 * \brief APIs to handle Visual Gadgets
 */
RZ_API void rz_core_gadget_free(RzCoreGadget *g);
RZ_API void rz_core_gadget_print(RzCore *core);

RZ_API bool rz_core_plugin_init(RzCore *core);
RZ_API bool rz_core_plugin_add(RzCore *core, RZ_NONNULL RzCorePlugin *plugin);
RZ_API bool rz_core_plugin_del(RzCore *core, RZ_NONNULL RzCorePlugin *plugin);
RZ_API bool rz_core_plugin_fini(RzCore *core);

// #define rz_core_ncast(x) (RzCore*)(size_t)(x)
RZ_API RZ_OWN RzList /*<char *>*/ *rz_core_theme_list(RZ_NONNULL RzCore *core);
RZ_API char *rz_core_theme_get(RzCore *core);
RZ_API bool rz_core_theme_load(RzCore *core, const char *name);
RZ_API void rz_core_theme_nextpal(RzCore *core, RzConsPalSeekMode mode);
RZ_API RZ_OWN char *rz_core_get_section_name(RzCore *core, ut64 addr);
RZ_API RzCons *rz_core_get_cons(RzCore *core);
RZ_API RzBin *rz_core_get_bin(RzCore *core);
RZ_API RzConfig *rz_core_get_config(RzCore *core);
RZ_API bool rz_core_init(RzCore *core);
RZ_API void rz_core_bind_cons(RzCore *core); // to restore pointers in cons
RZ_API RzCore *rz_core_new(void);
RZ_API void rz_core_free(RzCore *core);
RZ_API void rz_core_fini(RzCore *c);
RZ_API void rz_core_wait(RzCore *core);
RZ_API RzCore *rz_core_ncast(ut64 p);
RZ_API RzCore *rz_core_cast(void *p);
RZ_API bool rz_core_bin_load_structs(RZ_NONNULL RzCore *core, RZ_NONNULL const char *file);
RZ_API int rz_core_config_init(RzCore *core);
RZ_API void rz_core_config_print_all(RzConfig *cfg, const char *str, RzCmdStateOutput *state);
RZ_API void rz_core_parse_rizinrc(RzCore *r);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_core_config_in_space(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *space);
RZ_API int rz_core_prompt(RzCore *core, int sync);
RZ_API int rz_core_prompt_exec(RzCore *core);
RZ_API void rz_core_prompt_loop(RzCore *core);
RZ_API ut64 rz_core_pava(RzCore *core, ut64 addr);
RZ_API int rz_core_cmd(RzCore *core, const char *cmd, int log);
RZ_API RzCmdStatus rz_core_cmd_rzshell(RzCore *core, const char *cmd, int log);
RZ_API RZ_OWN char *rz_core_editor(const RzCore *core, RZ_NULLABLE const char *file, RZ_NULLABLE const char *str);
RZ_API int rz_core_fgets(char *buf, int len, void *user);
RZ_API RzFlagItem *rz_core_flag_get_by_spaces(RzFlag *f, ut64 off);
RZ_API int rz_core_flush(RzCore *core, const char *cmd);
RZ_API void rz_core_cmd_init(RzCore *core);
RZ_API int rz_core_cmd_pipe_old(RzCore *core, char *rizin_cmd, char *shell_cmd);
RZ_API char *rz_core_cmd_str(RzCore *core, const char *cmd);
RZ_API ut8 *rz_core_cmd_raw(RzCore *core, const char *cmd, int *length);
RZ_API char *rz_core_cmd_strf(RzCore *core, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API char *rz_core_cmd_str_pipe(RzCore *core, const char *cmd);
RZ_API int rz_core_cmd_file(RzCore *core, const char *file);
RZ_API int rz_core_cmd_lines(RzCore *core, const char *lines);
RZ_API RzCmdStatus rz_core_cmd_lines_rzshell(RzCore *core, const char *lines);
RZ_API int rz_core_cmd_command(RzCore *core, const char *command);
RZ_API bool rz_core_run_script(RzCore *core, RZ_NONNULL const char *file);
RZ_API void rz_core_seek_item_free(RzCoreSeekItem *item);
RZ_API bool rz_core_seek(RzCore *core, ut64 addr, bool rb);
RZ_API bool rz_core_seek_and_save(RzCore *core, ut64 addr, bool rb);
RZ_API bool rz_core_seek_opt(RzCore *core, ut64 addr, bool read_block, bool save);
RZ_API bool rz_core_seek_mark(RzCore *core);
RZ_API bool rz_core_seek_save(RzCore *core);
RZ_API bool rz_core_seek_undo(RzCore *core);
RZ_API bool rz_core_seek_redo(RzCore *core);
RZ_API void rz_core_seek_reset(RzCore *core);
RZ_API void rz_core_seek_free(RzCore *core);
RZ_API RzList /*<RzCoreSeekItem *>*/ *rz_core_seek_list(RzCore *core);
RZ_API RzCoreSeekItem *rz_core_seek_peek(RzCore *core, int idx);
RZ_API int rz_core_seek_base(RzCore *core, const char *hex, bool save);
RZ_API bool rz_core_seek_prev(RzCore *core, const char *type, bool save);
RZ_API bool rz_core_seek_next(RzCore *core, const char *type, bool save);
RZ_API bool rz_core_seek_align(RzCore *core, ut64 align, bool save);
RZ_API bool rz_core_seek_delta(RzCore *core, st64 delta, bool save);
RZ_API bool rz_core_seek_analysis_bb(RzCore *core, ut64 addr, bool save);
RZ_API void rz_core_arch_bits_at(RzCore *core, ut64 addr, RZ_OUT RZ_NULLABLE int *bits, RZ_OUT RZ_BORROW RZ_NULLABLE const char **arch);
RZ_API void rz_core_seek_arch_bits(RzCore *core, ut64 addr);
RZ_API int rz_core_block_read(RzCore *core);
RZ_API bool rz_core_block_size(RzCore *core, ut32 bsize);
RZ_API int rz_core_is_valid_offset(RZ_NONNULL RzCore *core, ut64 offset);
RZ_API int rz_core_write_hexpair(RzCore *core, ut64 addr, const char *pairs);
RZ_API int rz_core_write_assembly(RzCore *core, ut64 addr, RZ_NONNULL const char *instructions);
RZ_API int rz_core_write_assembly_fill(RzCore *core, ut64 addr, RZ_NONNULL const char *instructions);
RZ_API bool rz_core_write_block(RzCore *core, ut64 addr, ut8 *data, size_t len);
RZ_API bool rz_core_write_seq_at(RzCore *core, ut64 addr, ut64 from, ut64 to, ut64 step, int value_size);
RZ_API bool rz_core_shift_block(RzCore *core, ut64 addr, ut64 b_size, st64 dist);
RZ_API RzLineNSCompletionResult *rz_core_autocomplete_rzshell(RzCore *core, RzLineBuffer *buf, RzLinePromptType prompt_type);
RZ_DEPRECATE RZ_API void rz_core_help_vars_print(RzCore *core);
RZ_API bool rz_core_prevop_addr(RzCore *core, ut64 start_addr, int numinstrs, RZ_OUT RZ_BORROW RZ_NONNULL ut64 *prev_addr);
RZ_API ut64 rz_core_prevop_addr_force(RzCore *core, ut64 start_addr, int numinstrs);
RZ_API RzBinReloc *rz_core_getreloc(RzCore *core, ut64 addr, int size);
RZ_API RzBinReloc *rz_core_get_reloc_to(RzCore *core, ut64 addr);
RZ_API ut64 rz_core_get_asmqjmps(RzCore *core, const char *str);
RZ_API void rz_core_set_asmqjmps(RzCore *core, char *str, size_t len, int i);
RZ_API char *rz_core_add_asmqjmp(RzCore *core, ut64 addr);

RZ_API void rz_core_analysis_type_init(RzCore *core);
RZ_API char *rz_core_analysis_hasrefs_to_depth(RzCore *core, ut64 value, PJ *pj, int depth);
RZ_API void rz_core_global_vars_propagate_types(RzCore *core, RzAnalysisFunction *fcn);
RZ_API bool rz_core_analysis_objc_refs(RzCore *core, bool auto_analysis);
RZ_API void rz_core_analysis_objc_stubs(RzCore *core);
RZ_API void rz_core_analysis_cc_init_by_path(RzCore *core, RZ_NULLABLE const char *path, RZ_NULLABLE const char *homepath);
RZ_API void rz_core_analysis_cc_init(RzCore *core);
RZ_API void rz_core_analysis_paths(RzCore *core, ut64 from, ut64 to, bool followCalls, int followDepth, bool is_json);
RZ_API RZ_OWN char *rz_core_types_as_c(RZ_NONNULL RzCore *core, RZ_NONNULL const char *name, bool multiline);
RZ_API RZ_OWN char *rz_core_types_as_c_all(RZ_NONNULL RzCore *core, bool multiline);

RZ_API bool rz_core_analysis_esil_trace_start(RzCore *core);
RZ_API bool rz_core_analysis_esil_trace_stop(RzCore *core);

RZ_API int rz_core_search_cb(RzCore *core, ut64 from, ut64 to, RzCoreSearchCallback cb);
RZ_API bool rz_core_serve(RzCore *core, RzIODesc *fd);
RZ_API bool rz_core_file_reopen(RzCore *core, const char *args, int perm, int binload);
RZ_API void rz_core_file_reopen_in_malloc(RzCore *core);
RZ_API void rz_core_file_reopen_debug(RzCore *core, const char *args);
RZ_API void rz_core_file_reopen_remote_debug(RzCore *core, const char *uri, ut64 addr);
RZ_API bool rz_core_file_resize(RzCore *core, ut64 newsize);
RZ_API bool rz_core_file_resize_delta(RzCore *core, st64 delta);
RZ_API RzCoreFile *rz_core_file_find_by_fd(RzCore *core, ut64 fd);
RZ_API RzCoreFile *rz_core_file_find_by_name(RzCore *core, const char *name);
RZ_API RzCoreFile *rz_core_file_cur(RzCore *r);
RZ_API int rz_core_file_set_by_fd(RzCore *core, ut64 fd);
RZ_API int rz_core_file_set_by_name(RzCore *core, const char *name);
RZ_API int rz_core_file_set_by_file(RzCore *core, RzCoreFile *cf);
RZ_API int rz_core_setup_debugger(RzCore *r, const char *debugbackend, bool attach);

RZ_API bool rz_core_file_open_load(RZ_NONNULL RzCore *core, RZ_NONNULL const char *filepath, ut64 addr, int perms, bool write_mode);
RZ_API RZ_BORROW RzCoreFile *rz_core_file_open(RZ_NONNULL RzCore *core, RZ_NONNULL const char *file, int flags, ut64 loadaddr);
RZ_API RZ_BORROW RzCoreFile *rz_core_file_open_many(RZ_NONNULL RzCore *r, RZ_NULLABLE const char *file, int perm, ut64 loadaddr);
RZ_API RzCoreFile *rz_core_file_get_by_fd(RzCore *core, int fd);
RZ_API void rz_core_file_close(RzCoreFile *fh);
RZ_API bool rz_core_file_close_fd(RzCore *core, int fd);
RZ_API bool rz_core_file_close_all_but(RzCore *core);
RZ_API bool rz_core_raw_file_print(RzCore *core);
RZ_API bool rz_core_file_print(RzCore *core, RzOutputMode mode);
RZ_API int rz_core_file_binlist(RzCore *core);
RZ_API bool rz_core_file_bin_raise(RzCore *core, ut32 num);
RZ_API void rz_core_io_file_open(RZ_NONNULL RzCore *core, int fd);
RZ_API void rz_core_io_file_reopen(RZ_NONNULL RzCore *core, int fd, int perms);
RZ_API bool rz_core_extend_at(RzCore *core, ut64 addr, ut64 size);
RZ_API bool rz_core_write_at(RzCore *core, ut64 addr, const ut8 *buf, int size);
RZ_API bool rz_core_write_value_at(RzCore *core, ut64 addr, ut64 value, int sz);
RZ_API bool rz_core_write_value_inc_at(RzCore *core, ut64 addr, st64 value, int sz);
RZ_API bool rz_core_write_string_at(RzCore *core, ut64 addr, RZ_NONNULL const char *s);
RZ_API bool rz_core_write_string_zero_at(RzCore *core, ut64 addr, const char *s);
RZ_API bool rz_core_write_string_wide_at(RzCore *core, ut64 addr, const char *s);
RZ_API bool rz_core_write_length_string_at(RzCore *core, ut64 addr, const char *s);
RZ_API bool rz_core_write_base64d_at(RzCore *core, ut64 addr, RZ_NONNULL const char *s);
RZ_API bool rz_core_write_base64_at(RzCore *core, ut64 addr, RZ_NONNULL const char *s);
RZ_API bool rz_core_write_random_at(RzCore *core, ut64 addr, size_t len);
RZ_API bool rz_core_write_block_op_at(RzCore *core, ut64 addr, RzCoreWriteOp op, RZ_NULLABLE ut8 *hex, size_t hexlen);
RZ_API bool rz_core_write_duplicate_at(RzCore *core, ut64 addr, ut64 from, int len);
RZ_API RZ_OWN ut8 *rz_core_transform_op(RzCore *core, ut64 addr, RzCoreWriteOp op, RZ_NULLABLE ut8 *hex, size_t hexlen, size_t *buflen);
RZ_API ut32 rz_core_file_cur_fd(RzCore *core);
RZ_API RzCmdStatus rz_core_io_cache_print(RzCore *core, RzCmdStateOutput *state);
RZ_API RzCmdStatus rz_core_io_pcache_print(RzCore *core, RzIODesc *desc, RzCmdStateOutput *state);

/* creg.c */
RZ_API RzReg *rz_core_reg_default(RzCore *core);
RZ_API ut64 rz_core_reg_getv_by_role_or_name(RzCore *core, const char *name);
RZ_API bool rz_core_reg_set_by_role_or_name(RzCore *core, const char *name, ut64 num);
RZ_API void rz_core_reg_update_flags(RzCore *core);

/* cdebug.c */
RZ_API bool rz_core_is_debug(RzCore *core);
RZ_API bool rz_core_debug_step_one(RzCore *core, int times);
RZ_API bool rz_core_debug_continue_until(RzCore *core, ut64 addr, ut64 to);
RZ_API void rz_core_debug_bp_add_noreturn_func(RzCore *core);
RZ_API void rz_core_debug_breakpoint_toggle(RZ_NONNULL RzCore *core, ut64 addr);

RZ_API void rz_core_debug_set_register_flags(RzCore *core);
RZ_API void rz_core_debug_clear_register_flags(RzCore *core);

RZ_API bool rz_core_debug_process_close(RzCore *core);
RZ_API bool rz_core_debug_step_until_frame(RzCore *core);
RZ_API bool rz_core_debug_step_back(RzCore *core, int steps);
RZ_API bool rz_core_debug_step_over(RzCore *core, int steps);
RZ_API bool rz_core_debug_step_skip(RzCore *core, int times);
RZ_API void rz_core_dbg_follow_seek_register(RzCore *core);

RZ_API RZ_OWN RzList /*<RzBacktrace *>*/ *rz_core_debug_backtraces(RzCore *core);
RZ_API void rz_backtrace_free(RZ_NULLABLE RzBacktrace *bt);

RZ_API RzCmdStatus rz_core_debug_plugins_print(RzCore *core, RzCmdStateOutput *state);
RZ_API void rz_core_debug_map_update_flags(RzCore *core);
RZ_API void rz_core_debug_map_print(RzCore *core, ut64 addr, RzCmdStateOutput *state);

/* chash.c */
RZ_API RzCmdStatus rz_core_hash_plugins_print(RzHash *hash, RzCmdStateOutput *state);

/* ccrypto.c */
RZ_API RzCmdStatus rz_core_crypto_plugins_print(RzCrypto *cry, RzCmdStateOutput *state);

/* cio.c */
RZ_API RzCmdStatus rz_core_io_plugins_print(RzIO *io, RzCmdStateOutput *state);

/* cio.c */
RZ_API RzCmdStatus rz_core_parser_plugins_print(RzParse *parser, RzCmdStateOutput *state);

/* fortune */
RZ_API void rz_core_fortune_list_types(void);
RZ_API void rz_core_fortune_list(RzCore *core);
RZ_API RZ_OWN char *rz_core_fortune_get_random(RzCore *core);
RZ_API void rz_core_fortune_print_random(RzCore *core);

#define RZ_CORE_FOREIGN_ADDR -1
RZ_API RZ_OWN char *rz_core_yank_as_string(RzCore *core, ut64 pos);
RZ_API bool rz_core_yank(RzCore *core, ut64 addr, ut64 len);
RZ_API bool rz_core_yank_string(RzCore *core, ut64 addr, ut64 maxlen);
RZ_API bool rz_core_yank_hexpair(RzCore *core, const char *str);
RZ_API bool rz_core_yank_paste(RzCore *core, ut64 addr, ut64 len);
RZ_API bool rz_core_yank_set(RzCore *core, ut64 addr, RZ_NONNULL const ut8 *buf, ut64 len);
RZ_API bool rz_core_yank_set_str(RzCore *core, ut64 addr, RZ_NONNULL const char *str);
RZ_API bool rz_core_yank_to(RzCore *core, ut64 len, ut64 addr);
RZ_API bool rz_core_yank_dump(RzCore *core, ut64 pos, RzCmdStateOutput *state);
RZ_API bool rz_core_yank_print_hexdump(RzCore *core, ut64 pos);
RZ_API bool rz_core_yank_print(RzCore *core, ut64 pos);
RZ_API bool rz_core_yank_print_string(RzCore *core, ut64 pos);
RZ_API bool rz_core_yank_hud_file(RzCore *core, const char *input);
RZ_API bool rz_core_yank_hud_path(RzCore *core, const char *input, int dir);
RZ_API bool rz_core_yank_file(RzCore *core, ut64 len, ut64 addr, const char *filename);
RZ_API bool rz_core_yank_file_all(RzCore *core, const char *filename);

#define RZ_CORE_LOADLIBS_ENV    (1 << 0)
#define RZ_CORE_LOADLIBS_HOME   (1 << 1)
#define RZ_CORE_LOADLIBS_SYSTEM (1 << 2)
#define RZ_CORE_LOADLIBS_CONFIG (1 << 3)
#define RZ_CORE_LOADLIBS_EXTRA  (1 << 4)
#define RZ_CORE_LOADLIBS_ALL    UT32_MAX

RZ_API void rz_core_loadlibs_init(RzCore *core);
RZ_API int rz_core_loadlibs(RzCore *core, int where);
RZ_API RzCmd *rz_core_cmd_new(RzCore *core, bool has_cons);
RZ_API int rz_core_cmd_buffer(RzCore *core, const char *buf);
RZ_API int rz_core_cmdf(RzCore *core, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_core_cmd0(RzCore *core, const char *cmd);
RZ_API RzCmdStatus rz_core_cmd0_rzshell(RzCore *core, const char *cmd);
RZ_API int rz_core_cmd_foreach(RzCore *core, const char *cmd, char *each);
RZ_API int rz_core_cmd_foreach3(RzCore *core, const char *cmd, char *each);
RZ_API char *rz_core_op_str(RzCore *core, ut64 addr);
RZ_API RzAnalysisOp *rz_core_op_analysis(RzCore *core, ut64 addr, RzAnalysisOpMask mask);
RZ_API char *rz_core_disassemble_instr(RzCore *core, ut64 addr, int l);
RZ_API char *rz_core_disassemble_bytes(RzCore *core, ut64 addr, int b);

/* carg.c */
RZ_DEPRECATE RZ_API ut64 rz_core_arg_get(RzCore *core, const char *cc, int num);
RZ_API RZ_OWN RzList /*<RzAnalysisFuncArg *>*/ *rz_core_get_func_args(RzCore *core, const char *func_name);
RZ_API void rz_core_print_func_args(RzCore *core);
RZ_API char *resolve_fcn_name(RzAnalysis *analysis, const char *func_name);

/* clang.c */
RZ_API RzCmdStatus rz_core_lang_plugins_print(RzLang *lang, RzCmdStateOutput *state);

/* ccore.c */
RZ_API RzCmdStatus rz_core_core_plugins_print(RzCore *core, RzCmdStateOutput *state);

/* cil.c */
RZ_API void rz_core_analysis_esil(RzCore *core, ut64 addr, ut64 size, RZ_NULLABLE RzAnalysisFunction *fcn);
RZ_API bool rz_core_esil_cmd(RzAnalysisEsil *esil, const char *cmd, ut64 a1, ut64 a2);
RZ_API int rz_core_esil_step(RzCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver);
RZ_API int rz_core_esil_step_back(RzCore *core);
RZ_API bool rz_core_esil_dumpstack(RzAnalysisEsil *esil);
RZ_API bool rz_core_esil_continue_back(RZ_NONNULL RzCore *core);
RZ_API void rz_core_analysis_esil_step_over(RZ_NONNULL RzCore *core);
RZ_API void rz_core_analysis_esil_reinit(RZ_NONNULL RzCore *core);
RZ_API void rz_core_analysis_esil_deinit(RZ_NONNULL RzCore *core);
RZ_API void rz_core_analysis_esil_init_mem(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *name, ut64 addr, ut32 size);
RZ_API void rz_core_analysis_esil_init_mem_del(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *name, ut64 addr, ut32 size);
RZ_API void rz_core_analysis_esil_init_regs(RZ_NONNULL RzCore *core);

RZ_API void rz_core_analysis_il_reinit(RZ_NONNULL RzCore *core);
RZ_API bool rz_core_il_step(RZ_NONNULL RzCore *core, ut64 n);
RZ_API bool rz_core_il_step_until(RZ_NONNULL RzCore *core, ut64 until);

/* canalysis.c */
typedef enum rz_core_analysis_name_type {
	RZ_CORE_ANALYSIS_NAME_TYPE_VAR = 0,
	RZ_CORE_ANALYSIS_NAME_TYPE_FUNCTION,
	RZ_CORE_ANALYSIS_NAME_TYPE_FLAG,
	RZ_CORE_ANALYSIS_NAME_TYPE_ADDRESS,
} RzCoreAnalysisNameType;

typedef struct rz_core_analysis_name_t {
	char *name;
	char *realname;
	RzCoreAnalysisNameType type;
	ut64 offset;
} RzCoreAnalysisName;

/**
 *  Defines the level of analysis performed by
 * `rz_core_perform_auto_analysis`
 * */
typedef enum {
	RZ_CORE_ANALYSIS_SIMPLE, ///< aa
	RZ_CORE_ANALYSIS_DEEP, ///< aaa
	RZ_CORE_ANALYSIS_EXPERIMENTAL, ///< aaaa
} RzCoreAnalysisType;

RZ_API RzAnalysisOp *rz_core_analysis_op(RzCore *core, ut64 addr, int mask);
RZ_API void rz_core_analysis_fcn_merge(RzCore *core, ut64 addr, ut64 addr2);
RZ_API const char *rz_core_analysis_optype_colorfor(RzCore *core, ut64 addr, bool verbose);
RZ_API ut64 rz_core_analysis_address(RzCore *core, ut64 addr);
RZ_API void rz_core_analysis_undefine(RzCore *core, ut64 off);
RZ_API void rz_core_analysis_hint_print(RzAnalysis *a, ut64 addr, RzCmdStateOutput *state);
RZ_API void rz_core_analysis_hint_list_print(RzAnalysis *a, RzCmdStateOutput *state);
RZ_API int rz_core_analysis_search(RzCore *core, ut64 from, ut64 to, ut64 ref, int mode);
RZ_API int rz_core_analysis_search_xrefs(RZ_NONNULL RzCore *core, ut64 from, ut64 to);
RZ_API void rz_core_analysis_data(RZ_NONNULL RzCore *core, ut64 addr, ut32 count, ut32 depth, ut32 wordsize);
RZ_API void rz_core_analysis_resolve_jumps(RZ_NONNULL RzCore *core);
RZ_API bool rz_core_analysis_refs(RZ_NONNULL RzCore *core, size_t nbytes);
RZ_API void rz_core_analysis_flag_every_function(RzCore *core);
RZ_API bool rz_core_analysis_function_rename(RzCore *core, ut64 addr, const char *_name);
RZ_API bool rz_core_analysis_function_add(RzCore *core, const char *name, ut64 addr, bool analyze_recursively);
RZ_API int rz_core_analysis_fcn(RzCore *core, ut64 at, ut64 from, int reftype, int depth);
RZ_API RZ_OWN char *rz_core_analysis_function_autoname(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisFunction *fcn);
RZ_API void rz_core_analysis_function_strings_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE PJ *pj);
RZ_API void rz_core_analysis_autoname_all_fcns(RzCore *core);
RZ_API bool rz_core_analysis_recover_golang_functions(RzCore *core);
RZ_API void rz_core_analysis_resolve_golang_strings(RzCore *core);
RZ_API int rz_core_analysis_fcn_clean(RzCore *core, ut64 addr);
RZ_API RzList /*<RzAnalysisBlock *>*/ *rz_core_analysis_graph_to(RzCore *core, ut64 addr, int n);
RZ_API int rz_core_analysis_all(RzCore *core);
RZ_API bool rz_core_analysis_everything(RzCore *core, bool experimental, char *dh_orig);
RZ_API RZ_OWN RzList /*<RzSigDBEntry *>*/ *rz_core_analysis_sigdb_list(RZ_NONNULL RzCore *core, bool with_details);
RZ_API bool rz_core_analysis_sigdb_apply(RZ_NONNULL RzCore *core, RZ_NULLABLE int *n_applied, RZ_NULLABLE const char *filter);
RZ_API void rz_core_analysis_sigdb_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzTable *table);
RZ_API RzList /*<RzAnalysisCycleHook *>*/ *rz_core_analysis_cycles(RzCore *core, int ccl);
RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_core_analysis_fcn_get_calls(RzCore *core, RzAnalysisFunction *fcn); // get all calls from a function
RZ_API void rz_core_analysis_calls(RZ_NONNULL RzCore *core, bool imports_only);
RZ_API int rz_core_get_stacksz(RzCore *core, ut64 from, ut64 to);
RZ_API bool rz_core_analysis_hint_set_offset(RZ_NONNULL RzCore *core, RZ_NONNULL const char *struct_member);
RZ_API bool rz_core_analysis_continue_until_syscall(RZ_NONNULL RzCore *core);
RZ_API bool rz_core_analysis_continue_until_call(RZ_NONNULL RzCore *core);

RZ_API bool rz_core_is_debugging(RZ_NONNULL RzCore *core);
RZ_API void rz_core_perform_auto_analysis(RZ_NONNULL RzCore *core, RzCoreAnalysisType type);

RZ_API st64 rz_core_analysis_coverage_count(RZ_NONNULL RzCore *core);
RZ_API st64 rz_core_analysis_code_count(RZ_NONNULL RzCore *core);
RZ_API st64 rz_core_analysis_calls_count(RZ_NONNULL RzCore *core);

RZ_API RZ_BORROW const char *rz_core_analysis_name_type_to_str(RzCoreAnalysisNameType typ);
RZ_API void rz_core_analysis_name_free(RZ_NULLABLE RzCoreAnalysisName *p);
RZ_API RZ_OWN RzCoreAnalysisName *rz_core_analysis_name(RZ_NONNULL RzCore *core, ut64 addr);
RZ_API bool rz_core_analysis_rename(RZ_NONNULL RzCore *core, RZ_NONNULL const char *name, ut64 addr);

RZ_API void rz_analysis_bytes_free(RZ_NULLABLE void *ptr);
RZ_API RZ_OWN RzIterator *rz_core_analysis_bytes(RZ_NONNULL RzCore *core, ut64 start_addr, RZ_NONNULL const ut8 *buf, ut64 len, ut64 nops);
RZ_API RZ_OWN RzIterator *rz_core_analysis_op_chunk_iter(RZ_NONNULL RzCore *core, ut64 offset, ut64 len, ut64 nops, RzAnalysisOpMask mask);
RZ_API RZ_OWN RzIterator *rz_core_analysis_op_function_iter(RZ_NONNULL RzCore *core, RZ_NONNULL RZ_BORROW RzAnalysisFunction *fcn, RzAnalysisOpMask mask);
RZ_API ut64 rz_core_analysis_ops_size(RZ_NONNULL RzCore *core, ut64 start_addr, RZ_NONNULL const ut8 *buf, ut64 len, ut64 nops);

/* cgraph.c */
/**
 * \brief RzGraph format for print/convert
 */
typedef enum {
	RZ_CORE_GRAPH_FORMAT_VISUAL = 0,
	RZ_CORE_GRAPH_FORMAT_SDB,
	RZ_CORE_GRAPH_FORMAT_GML,
	RZ_CORE_GRAPH_FORMAT_DOT,
	RZ_CORE_GRAPH_FORMAT_JSON,
	RZ_CORE_GRAPH_FORMAT_JSON_DISASM,
	RZ_CORE_GRAPH_FORMAT_CMD,
	RZ_CORE_GRAPH_FORMAT_ASCII_ART,
	RZ_CORE_GRAPH_FORMAT_UNK,
} RzCoreGraphFormat;

/**
 * \brief RzGraph type
 */
typedef enum {
	RZ_CORE_GRAPH_TYPE_DATAREF = 0, ///< Data reference graph
	RZ_CORE_GRAPH_TYPE_FUNCALL, ///< Function callgraph
	RZ_CORE_GRAPH_TYPE_DIFF, ///< Diff graph
	RZ_CORE_GRAPH_TYPE_BLOCK_FUN, ///< Basic blocks function graph
	RZ_CORE_GRAPH_TYPE_IMPORT, ///< Imports graph
	RZ_CORE_GRAPH_TYPE_REF, ///< References graph
	RZ_CORE_GRAPH_TYPE_LINE, ///< Line graph
	RZ_CORE_GRAPH_TYPE_XREF, ///< Cross-references graph
	RZ_CORE_GRAPH_TYPE_CUSTOM, ///< Custom graph
	RZ_CORE_GRAPH_TYPE_NORMAL, ///< Normal graph
	RZ_CORE_GRAPH_TYPE_IL, ///< RzIL graph
	RZ_CORE_GRAPH_TYPE_ICFG, ///< Inter-procedual control flow graph
	RZ_CORE_GRAPH_TYPE_CFG, ///< control flow graph (without calls)
	RZ_CORE_GRAPH_TYPE_UNK ///< Unknown graph
} RzCoreGraphType;

RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_datarefs(RZ_NONNULL RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_coderefs(RZ_NONNULL RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_codexrefs(RZ_NONNULL RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_importxrefs(RZ_NONNULL RzCore *core);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_callgraph(RZ_NONNULL RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_function(RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_line(RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_il(RZ_NONNULL RzCore *core, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph(RzCore *core, RzCoreGraphType type, ut64 addr);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_icfg(RZ_NONNULL RzCore *core);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_cfg(RZ_NONNULL RzCore *core, ut64 addr);

RZ_API RzCoreGraphFormat rz_core_graph_format_from_string(RZ_NULLABLE const char *x);
RZ_API RzCoreGraphType rz_core_graph_type_from_string(RZ_NULLABLE const char *x);
RZ_API bool rz_core_graph_write_graph(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RZ_NONNULL const char *filename);
RZ_API bool rz_core_graph_write(RZ_NONNULL RzCore *core, ut64 addr, RzCoreGraphType type, RZ_NONNULL const char *path);
RZ_API RZ_OWN char *rz_core_graph_to_dot_str(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph);
RZ_API RZ_OWN char *rz_core_graph_to_sdb_str(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph);

/*tp.c*/
RZ_API void rz_core_analysis_type_match(RzCore *core, RzAnalysisFunction *fcn, HtUU *addr_loop_table);

/* asm.c */
#define RZ_MIDFLAGS_HIDE     0
#define RZ_MIDFLAGS_SHOW     1
#define RZ_MIDFLAGS_REALIGN  2
#define RZ_MIDFLAGS_SYMALIGN 3

typedef struct rz_core_asm_hit {
	char *code;
	int len;
	ut64 addr;
	ut8 valid;
} RzCoreAsmHit;

/**
 * \brief Disassemble Options, just for rz_core_print_disasm
 */
typedef struct rz_core_disasm_options {
	int invbreak;
	int cbytes; ///< set false to ignore the constraint of \p len and print \p nlines instructions in rz_core_print_disasm
	RzAnalysisFunction *function; ///< Disassemble a function
	RzPVector /*<RzAnalysisDisasmText *>*/ *vec; ///< Not print, but append as RzPVector<RzAnalysisDisasmText>
} RzCoreDisasmOptions;

#define RZ_CORE_MAX_DISASM (1024 * 1024 * 8)

RZ_API RzBuffer *rz_core_syscall(RzCore *core, const char *name, const char *args);
RZ_API RzBuffer *rz_core_syscallf(RzCore *core, const char *name, const char *fmt, ...) RZ_PRINTF_CHECK(3, 4);
RZ_API RzCoreAsmHit *rz_core_asm_hit_new(void);
RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_hit_list_new(void);
RZ_API void rz_core_asm_hit_free(void *_hit);
RZ_API void rz_core_set_asm_configs(RzCore *core, char *arch, ut32 bits, int segoff);
RZ_API char *rz_core_asm_search(RzCore *core, const char *input);
RZ_API RzCmdStatus rz_core_asm_plugins_print(RzCore *core, const char *arch, RzCmdStateOutput *state);
RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_strsearch(RzCore *core, const char *input, ut64 from, ut64 to, int maxhits, int regexp, int everyByte, int mode);
RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_bwdisassemble(RzCore *core, ut64 addr, int n, int len);
RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_back_disassemble_instr(RzCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
RZ_API RzList /*<RzCoreAsmHit *>*/ *rz_core_asm_back_disassemble_byte(RzCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
RZ_API ut32 rz_core_asm_bwdis_len(RzCore *core, int *len, ut64 *start_addr, ut32 l);
RZ_API int rz_core_print_disasm(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL ut8 *buf, int len, int nlines, RZ_NULLABLE RzCmdStateOutput *state, RZ_NULLABLE RzCoreDisasmOptions *options);
RZ_API int rz_core_print_disasm_json(RzCore *core, ut64 addr, ut8 *buf, int len, int lines, PJ *pj);
RZ_API int rz_core_print_disasm_instructions_with_buf(RzCore *core, ut64 address, ut8 *buf, int nb_bytes, int nb_opcodes);
RZ_API int rz_core_print_disasm_instructions(RzCore *core, int nb_bytes, int nb_opcodes);
RZ_API int rz_core_print_disasm_all(RzCore *core, ut64 addr, int l, int len, int mode);
RZ_API int rz_core_disasm_pdi_with_buf(RzCore *core, ut64 address, ut8 *buf, ut32 nb_opcodes, ut32 nb_bytes, int fmt);
RZ_API int rz_core_disasm_pdi(RzCore *core, int nb_opcodes, int nb_bytes, int fmt);
RZ_API int rz_core_disasm_pde(RzCore *core, int nb_opcodes, RzCmdStateOutput *state);
RZ_API RZ_OWN char *rz_core_disasm_instruction(RzCore *core, ut64 addr, ut64 reladdr, RZ_NULLABLE RzAnalysisFunction *fcn, bool color);
RZ_API bool rz_core_print_function_disasm_json(RzCore *core, RzAnalysisFunction *fcn, PJ *pj);
RZ_API int rz_core_flag_in_middle(RzCore *core, ut64 at, int oplen, int *midflags);
RZ_API int rz_core_bb_starts_in_middle(RzCore *core, ut64 at, int oplen);
RZ_API void rz_analysis_disasm_text_free(RzAnalysisDisasmText *t);

/**
 * \brief Use RzAsmOp if it is sufficient
 */
typedef struct {
	ut64 offset;
	ut64 size;
	char *hex;
	char *assembly;
	char *assembly_colored;
} RzCoreDisasmOp;

RZ_API void rz_core_disasm_op_free(RzCoreDisasmOp *x);
RZ_API RZ_OWN RzPVector /*<RzCoreDisasmOp *>*/ *rz_core_disasm_all_possible_opcodes(RZ_NONNULL RzCore *core, RZ_NONNULL ut8 *buffer, ut64 addr, ut64 n_bytes);

/* cbin.c */
RZ_API bool rz_core_bin_raise(RzCore *core, ut32 bfid);
RZ_API bool rz_core_bin_set_cur(RZ_NONNULL RzCore *core, RZ_NULLABLE RzBinFile *binfile);
RZ_API RZ_BORROW const char *rz_core_bin_get_compile_time(RZ_NONNULL RzBinFile *bf);
RZ_API void rz_core_bin_options_init(RzCore *core, RZ_OUT RzBinOptions *opts, int fd, ut64 baseaddr, ut64 loadaddr);
RZ_API bool rz_core_bin_apply_strings(RzCore *r, RzBinFile *binfile);
RZ_API bool rz_core_bin_apply_config(RzCore *r, RzBinFile *binfile);
RZ_API bool rz_core_bin_apply_maps(RzCore *core, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_main(RzCore *r, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_dwarf(RzCore *core, RzBinFile *binfile);
RZ_API bool rz_core_bin_apply_entry(RzCore *core, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_sections(RzCore *core, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_relocs(RzCore *core, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_imports(RzCore *core, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_symbols(RzCore *core, RzBinFile *binfile, bool va);
RZ_API bool rz_core_bin_apply_classes(RzCore *core, RzBinFile *binfile);
RZ_API bool rz_core_bin_apply_resources(RzCore *core, RzBinFile *binfile);
RZ_API bool rz_core_bin_apply_info(RzCore *r, RzBinFile *binfile, ut32 mask);
RZ_API bool rz_core_bin_apply_all_info(RzCore *r, RzBinFile *binfile);
RZ_API int rz_core_bin_set_by_fd(RzCore *core, ut64 bin_fd);
RZ_API int rz_core_bin_set_by_name(RzCore *core, const char *name);
RZ_API bool rz_core_bin_load(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *file_uri, ut64 base_addr);
RZ_API bool rz_core_bin_rebase(RZ_NONNULL RzCore *core, ut64 baddr);
RZ_API void rz_core_bin_export_info(RzCore *core, int mode);
RZ_API bool rz_core_binfiles_print(RzCore *core, RzCmdStateOutput *state);
RZ_API bool rz_core_binfiles_delete(RzCore *core, RzBinFile *bf);
RZ_API RZ_OWN HtSS *rz_core_bin_create_digests(RzCore *core, ut64 paddr, ut64 size, RzList /*<char *>*/ *digests);

RZ_API void rz_core_bin_print_source_line_sample(RzCore *core, const RzBinSourceLineSample *s, RzCmdStateOutput *state);
RZ_API void rz_core_bin_print_source_line_info(RzCore *core, const RzBinSourceLineInfo *li, RzCmdStateOutput *state);

RZ_API bool rz_core_sym_is_export(RZ_NONNULL RzBinSymbol *s);

RZ_API void rz_core_sysenv_begin(RzCore *core);
RZ_API void rz_core_sysenv_end(RzCore *core);

RZ_API void rz_core_recover_vars(RzCore *core, RzAnalysisFunction *fcn, bool argonly);

/* cmd_linux_heap_glibc.c */
RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list(RzCore *core, ut64 m_arena);
RZ_API RzList /*<MallocState *>*/ *rz_heap_arenas_list(RzCore *core);
RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr);
RZ_API RzHeapBin *rz_heap_bin_content(RzCore *core, MallocState *arena, int bin_num, ut64 m_arena);
RZ_API RzHeapBin *rz_heap_fastbin_content(RzCore *core, MallocState *arena, int bin_num);
RZ_API MallocState *rz_heap_get_arena(RzCore *core, ut64 m_state);
RZ_API RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content(RzCore *core, ut64 arena_base);
RZ_API bool rz_heap_write_chunk(RzCore *core, RzHeapChunkSimple *chunk_simple);

/* cmd_windows_heap.c */
RZ_API RZ_OWN RzList /*<RzWindowsHeapBlock *>*/ *rz_heap_windows_blocks_list(RzCore *core);
RZ_API RZ_OWN RzList /*<RzWindowsHeapInfo *>*/ *rz_heap_windows_heap_list(RzCore *core);

// XXX dupe from rz_bin.h
/* bin.c */
#define RZ_CORE_BIN_ACC_STRINGS          0x001
#define RZ_CORE_BIN_ACC_INFO             0x002
#define RZ_CORE_BIN_ACC_MAIN             0x004
#define RZ_CORE_BIN_ACC_ENTRIES          0x008
#define RZ_CORE_BIN_ACC_RELOCS           0x010
#define RZ_CORE_BIN_ACC_IMPORTS          0x020
#define RZ_CORE_BIN_ACC_SYMBOLS          0x040
#define RZ_CORE_BIN_ACC_SECTIONS         0x080
#define RZ_CORE_BIN_ACC_FIELDS           0x100
#define RZ_CORE_BIN_ACC_LIBS             0x200
#define RZ_CORE_BIN_ACC_CLASSES          0x400
#define RZ_CORE_BIN_ACC_DWARF            0x800
#define RZ_CORE_BIN_ACC_SIZE             0x1000
#define RZ_CORE_BIN_ACC_PDB              0x2000
#define RZ_CORE_BIN_ACC_MEM              0x4000
#define RZ_CORE_BIN_ACC_EXPORTS          0x8000
#define RZ_CORE_BIN_ACC_VERSIONINFO      0x10000
#define RZ_CORE_BIN_ACC_SIGNATURE        0x20000
#define RZ_CORE_BIN_ACC_RAW_STRINGS      0x40000
#define RZ_CORE_BIN_ACC_HEADER           0x80000
#define RZ_CORE_BIN_ACC_RESOURCES        0x100000
#define RZ_CORE_BIN_ACC_INITFINI         0x200000
#define RZ_CORE_BIN_ACC_SEGMENTS         0x400000
#define RZ_CORE_BIN_ACC_BASEFIND         0x800000
#define RZ_CORE_BIN_ACC_TRYCATCH         0x20000000
#define RZ_CORE_BIN_ACC_SECTIONS_MAPPING 0x40000000
#define RZ_CORE_BIN_ACC_MAPS             0x80000000
#define RZ_CORE_BIN_ACC_ALL              0x80504FFF

#define RZ_CORE_PRJ_FLAGS           0x0001
#define RZ_CORE_PRJ_EVAL            0x0002
#define RZ_CORE_PRJ_IO_MAPS         0x0004
#define RZ_CORE_PRJ_SECTIONS        0x0008
#define RZ_CORE_PRJ_META            0x0010
#define RZ_CORE_PRJ_XREFS           0x0020
#define RZ_CORE_PRJ_FCNS            0x0040
#define RZ_CORE_PRJ_ANALYSIS_HINTS  0x0080
#define RZ_CORE_PRJ_ANALYSIS_TYPES  0x0100
#define RZ_CORE_PRJ_ANALYSIS_MACROS 0x0200
#define RZ_CORE_PRJ_ANALYSIS_SEEK   0x0400
#define RZ_CORE_PRJ_DBG_BREAK       0x0800
#define RZ_CORE_PRJ_ALL             0xFFFF

typedef struct rz_core_bin_filter_t {
	ut64 offset;
	const char *name;
} RzCoreBinFilter;

RZ_API int rz_core_bin_set_arch_bits(RzCore *r, const char *name, const char *arch, ut16 bits);
RZ_API int rz_core_bin_update_arch_bits(RzCore *r);
RZ_API RZ_OWN char *rz_core_bin_class_build_flag_name(RZ_NONNULL RzBinClass *cls);
RZ_API RZ_OWN char *rz_core_bin_super_build_flag_name(RZ_NONNULL RzBinClass *cls);
RZ_API RZ_OWN char *rz_core_bin_method_build_flag_name(RZ_NONNULL RzBinClass *cls, RZ_NONNULL RzBinSymbol *meth);
RZ_API RZ_OWN char *rz_core_bin_field_build_flag_name(RZ_NONNULL RzBinClass *cls, RZ_NONNULL RzBinClassField *field);
RZ_API char *rz_core_bin_method_flags_str(ut64 flags, int mode);
RZ_API RZ_OWN char *rz_core_bin_pdb_get_filename(RZ_NONNULL RzCore *core);
RZ_API bool rz_core_bin_pdb_load(RZ_NONNULL RzCore *core, RZ_NONNULL const char *filename);
RZ_API RzPdb *rz_core_pdb_load_info(RZ_NONNULL RzCore *core, RZ_NONNULL const char *file);
RZ_API void rz_core_pdb_info_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzTypeDB *db, RZ_NONNULL RzPdb *pdb, RZ_NONNULL RzCmdStateOutput *state);
RZ_API char *rz_core_bin_pdb_gvars_as_string(RZ_NONNULL const RzPdb *pdb, const ut64 img_base, RzCmdStateOutput *state);
RZ_API RzCmdStatus rz_core_bin_plugins_print(RzBin *bin, RzCmdStateOutput *state);

RZ_API bool rz_core_bin_archs_print(RZ_NONNULL RzBin *bin, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_entries_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_initfini_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_exports_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzCoreBinFilter *filter);
RZ_API bool rz_core_bin_cur_export_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_symbols_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzCoreBinFilter *filter);
RZ_API bool rz_core_bin_cur_symbol_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_imports_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzCoreBinFilter *filter);
RZ_API bool rz_core_bin_libs_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_main_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_relocs_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_sections_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzCoreBinFilter *filter, RzList /*<char *>*/ *hashes);
RZ_API bool rz_core_bin_cur_section_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzList /*<char *>*/ *hashes);
RZ_API bool rz_core_bin_cur_segment_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzList /*<char *>*/ *hashes);
RZ_API bool rz_core_bin_segments_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RzCoreBinFilter *filter, RzList /*<char *>*/ *hashes);
RZ_API bool rz_core_bin_strings_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API RZ_OWN RzPVector /*<RzBinString *>*/ *rz_core_bin_whole_strings(RZ_NONNULL RzCore *core, RZ_NULLABLE RzBinFile *bf);
RZ_API bool rz_core_bin_whole_strings_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_file_info_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_info_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_classes_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_class_as_source_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, const char *class_name);
RZ_API bool rz_core_bin_class_fields_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, const char *class_name);
RZ_API bool rz_core_bin_class_methods_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, const char *class_name);
RZ_API bool rz_core_bin_signatures_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_fields_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_headers_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf);
RZ_API bool rz_core_bin_dwarf_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_memory_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_resources_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RZ_NULLABLE RzList /*<char *>*/ *hashes);
RZ_API bool rz_core_bin_versions_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_trycatch_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_size_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_sections_mapping_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state);
RZ_API bool rz_core_bin_print(RzCore *core, RZ_NONNULL RzBinFile *bf, ut32 mask, RzCoreBinFilter *filter, RzCmdStateOutput *state, RzList /*<char *>*/ *hashes);
RZ_API bool rz_core_bin_basefind_print(RzCore *core, ut32 pointer_size, RzCmdStateOutput *state);

// cmeta.c
RZ_API bool rz_core_meta_string_add(RzCore *core, ut64 addr, ut64 size, RzStrEnc encoding, RZ_NULLABLE const char *name);
RZ_API bool rz_core_meta_pascal_string_add(RzCore *core, ut64 addr, RzStrEnc encoding, RZ_NULLABLE const char *name);

// cprint.c
typedef enum {
	RZ_CORE_PRINT_FORMAT_TYPE_OCTAL = 0,
	RZ_CORE_PRINT_FORMAT_TYPE_INTEGER,
	RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL,
	RZ_CORE_PRINT_FORMAT_TYPE_INVALID,
} RzCorePrintFormatType;

RZ_API RZ_OWN char *rz_core_print_string_c_cpp(RzCore *core);
RZ_API RZ_OWN char *rz_core_hex_of_assembly(RzCore *core, const char *assembly);
RZ_API RZ_OWN char *rz_core_esil_of_assembly(RzCore *core, const char *assembly);
RZ_API RZ_OWN char *rz_core_assembly_of_hex(RzCore *core, ut8 *hex, int len);
RZ_API RZ_OWN char *rz_core_esil_of_hex(RzCore *core, ut8 *hex, int len);

RZ_API RZ_OWN char *rz_core_print_hexdump_diff_str(RZ_NONNULL RzCore *core, ut64 aa, ut64 ba, ut64 len);
RZ_API RZ_OWN char *rz_core_print_dump_str(RZ_NONNULL RzCore *core, RzOutputMode mode, ut64 addr, ut8 n, int len, RzCorePrintFormatType format);
RZ_API RZ_OWN char *rz_core_print_hexdump_or_hexdiff_str(RZ_NONNULL RzCore *core, RzOutputMode mode, ut64 addr, int len, bool use_comment);
RZ_API RZ_OWN char *rz_core_print_hexdump_byline_str(RZ_NONNULL RzCore *core, bool hex_offset, ut64 addr, int len, ut8 size);
RZ_API RZ_OWN char *rz_core_print_bytes_with_inst(RZ_NONNULL RzCore *core, RZ_NONNULL const ut8 *buf, ut64 addr, int len);

typedef enum {
	RZ_CORE_DISASM_STRINGS_MODE_BYTES = 0,
	RZ_CORE_DISASM_STRINGS_MODE_INST,
	RZ_CORE_DISASM_STRINGS_MODE_BLOCK,
	RZ_CORE_DISASM_STRINGS_MODE_FUNCTION,
} RzCorePrintDisasmStringsMode;
RZ_API RZ_OWN char *rz_core_print_disasm_strings(RZ_NONNULL RzCore *core, RzCorePrintDisasmStringsMode mode, ut64 n_bytes, RZ_NULLABLE RzAnalysisFunction *fcn);

/* rtr */
RZ_API bool rz_core_rtr_init(RZ_NONNULL RzCore *core);
RZ_API void rz_core_rtr_cmds(RzCore *core, const char *port);
RZ_API char *rz_core_rtr_cmds_query(RzCore *core, const char *host, const char *port, const char *cmd);
RZ_API void rz_core_rtr_pushout(RzCore *core, const char *input);
RZ_API void rz_core_rtr_list(RzCore *core);
RZ_API void rz_core_rtr_add(RzCore *core, const char *input);
RZ_API void rz_core_rtr_remove(RzCore *core, const char *input);
RZ_API void rz_core_rtr_session(RzCore *core, const char *input);
RZ_API void rz_core_rtr_cmd(RzCore *core, const char *input);
RZ_API int rz_core_rtr_http(RzCore *core, int launch, int browse, const char *path);
RZ_API int rz_core_rtr_gdb(RzCore *core, int launch, const char *path);

RZ_API int rz_core_search_preludes(RzCore *core, bool log);
RZ_API int rz_core_search_prelude(RzCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen);
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_prot(RzCore *core, int protection, const char *mode, const char *prefix);

RZ_API void rz_core_hack_help(const RzCore *core);
RZ_API bool rz_core_hack(RzCore *core, const char *op);
RZ_API bool rz_core_dump(RzCore *core, const char *file, ut64 addr, ut64 size, int append);
RZ_API RZ_OWN char *rz_core_clippy(RZ_NONNULL RzCore *core, RZ_NONNULL const char *msg);

// TODO MOVE SOMEWHERE ELSE
typedef char *(*PrintItemCallback)(void *user, void *p, bool selected);
RZ_API char *rz_str_widget_list(void *user, RzList /*<void *>*/ *list, int rows, int cur, PrintItemCallback cb);
/* help */
RZ_API void rz_core_cmd_help(const RzCore *core, const char *help[]);
RZ_DEPRECATE RZ_API const char **rz_core_help_vars_get(RzCore *core);

/* analysis stats */

/**
 * Single sub-range of statistics as part of an entire RzCoreAnalysisStats.
 *
 * The range that this covers is given by rz_core_analysis_stats_get_block_from()/to().
 */
typedef struct {
	ut32 youarehere;
	ut32 flags;
	ut32 comments;
	ut32 functions;
	ut32 blocks;
	ut32 in_functions;
	ut32 symbols;
	ut32 strings;
	ut32 perm;
} RzCoreAnalysisStatsItem;

/**
 * Statistics for a range of memory, split up into smaller blocks.
 */
typedef struct {
	ut64 from;
	ut64 to;
	ut64 step;
	RzVector /*<RzCoreAnalysisStatsItem>*/ blocks;
} RzCoreAnalysisStats;

RZ_API char *rz_core_analysis_hasrefs(RzCore *core, ut64 value, int mode);
RZ_API char *rz_core_analysis_get_comments(RzCore *core, ut64 addr);
RZ_API RZ_OWN RzCoreAnalysisStats *rz_core_analysis_get_stats(RZ_NONNULL RzCore *a, ut64 from, ut64 to, ut64 step);
RZ_API void rz_core_analysis_stats_free(RzCoreAnalysisStats *s);
RZ_API ut64 rz_core_analysis_stats_get_block_from(RZ_NONNULL const RzCoreAnalysisStats *s, size_t i);
RZ_API ut64 rz_core_analysis_stats_get_block_to(RZ_NONNULL const RzCoreAnalysisStats *s, size_t i);

RZ_API RZ_OWN char *rz_core_syscall_as_string(RzCore *core, st64 num, ut64 addr);

/* tasks */

typedef enum {
	RZ_CORE_TASK_STATE_BEFORE_START,
	RZ_CORE_TASK_STATE_RUNNING,
	RZ_CORE_TASK_STATE_SLEEPING,
	RZ_CORE_TASK_STATE_DONE
} RzTaskState;

/**
 * Main payload of a task, the function that should be executed asynchronously.
 */
typedef void (*RzCoreTaskRunner)(RzCoreTaskScheduler *sched, void *user);

/**
 * Task-specific callback to free/cleanup any runner-specific data.
 */
typedef void (*RzCoreTaskRunnerFree)(void *user);

struct rz_core_task_t {
	RzCoreTaskScheduler *sched;
	int id;
	RzTaskState state;
	bool transient; // delete when finished
	int refcount;
	RzThreadSemaphore *running_sem;
	bool dispatched;
	RzThreadCond *dispatch_cond;
	RzThreadLock *dispatch_lock;
	RzThread *thread;
	bool breaked;

	RzCoreTaskRunner runner; // will be NULL for main task
	RzCoreTaskRunnerFree runner_free;
	void *runner_user;
};

typedef void (*RzCoreTaskOneShot)(void *);

RZ_API RzTable *rz_core_table(RzCore *core);

RZ_API void rz_core_task_scheduler_init(RzCoreTaskScheduler *sched,
	RzCoreTaskContextSwitch ctx_switch, void *ctx_switch_user,
	RzCoreTaskBreak break_cb, void *break_cb_user);
RZ_API void rz_core_task_scheduler_fini(RzCoreTaskScheduler *tasks);
RZ_API RzCoreTask *rz_core_task_get_incref(RzCoreTaskScheduler *scheduler, int id);
RZ_API int rz_core_task_running_tasks_count(RzCoreTaskScheduler *scheduler);
RZ_API RzCoreTask *rz_core_task_new(RzCoreTaskScheduler *sched, RzCoreTaskRunner runner, RzCoreTaskRunnerFree runner_free, void *runner_user);
RZ_API void rz_core_task_incref(RzCoreTask *task);
RZ_API void rz_core_task_decref(RzCoreTask *task);
RZ_API void rz_core_task_enqueue(RzCoreTaskScheduler *scheduler, RzCoreTask *task);
RZ_API void rz_core_task_enqueue_oneshot(RzCoreTaskScheduler *scheduler, RzCoreTaskOneShot func, void *user);
RZ_API int rz_core_task_run_sync(RzCoreTaskScheduler *scheduler, RzCoreTask *task);
RZ_API void rz_core_task_sync_begin(RzCoreTaskScheduler *scheduler);
RZ_API void rz_core_task_sync_end(RzCoreTaskScheduler *scheduler);
RZ_API void rz_core_task_yield(RzCoreTaskScheduler *scheduler);
RZ_API void rz_core_task_sleep_begin(RzCoreTask *task);
RZ_API void rz_core_task_sleep_end(RzCoreTask *task);
RZ_API void rz_core_task_break(RzCoreTaskScheduler *scheduler, int id);
RZ_API void rz_core_task_break_all(RzCoreTaskScheduler *scheduler);
RZ_API int rz_core_task_del(RzCoreTaskScheduler *scheduler, int id);
RZ_API RzCoreTask *rz_core_task_self(RzCoreTaskScheduler *scheduler);
RZ_API void rz_core_task_join(RzCoreTaskScheduler *scheduler, RzCoreTask *current, int id);
typedef void (*inRangeCb)(RzCore *core, ut64 from, ut64 to, int vsize, void *cb_user);
RZ_API int rz_core_search_value_in_range(RzCore *core, RzInterval search_itv,
	ut64 vmin, ut64 vmax, int vsize, inRangeCb cb, void *cb_user);

// core-specific tasks
typedef void (*RzCoreCmdTaskFinished)(const char *res, void *user);
RZ_API RzCoreTask *rz_core_cmd_task_new(RzCore *core, const char *cmd, RzCoreCmdTaskFinished finished_cb, void *finished_cb_user);
RZ_API const char *rz_core_cmd_task_get_result(RzCoreTask *task);
typedef void *(*RzCoreTaskFunction)(RzCore *core, void *user);
RZ_API RzCoreTask *rz_core_function_task_new(RzCore *core, RzCoreTaskFunction fcn, void *fcn_user);
RZ_API void *rz_core_function_task_get_result(RzCoreTask *task);
RZ_API const char *rz_core_task_status(RzCoreTask *task);
RZ_API void rz_core_task_print(RzCore *core, RzCoreTask *task, int mode, PJ *j);
RZ_API void rz_core_task_list(RzCore *core, int mode);
RZ_API bool rz_core_task_is_cmd(RzCore *core, int id);
RZ_API void rz_core_task_del_all_done(RzCore *core);

RZ_API void rz_core_analysis_propagate_noreturn(RzCore *core, ut64 addr);

RZ_API bool rz_core_flirt_dump_file(RZ_NONNULL const char *flirt_file);
RZ_API bool rz_core_flirt_create_file(RZ_NONNULL RzCore *core, RZ_NONNULL const char *output_file, RZ_NULLABLE ut32 *written_nodes);
RZ_API bool rz_core_flirt_convert_file(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input_file, RZ_NONNULL const char *ouput_file);
RZ_API const char *rz_core_flirt_arch_from_id(ut8 arch);
RZ_API ut8 rz_core_flirt_arch_from_name(RZ_NONNULL const char *arch);
RZ_API ut32 rz_core_flirt_file_from_option_list(RZ_NONNULL const char *file_list);
RZ_API ut16 rz_core_flirt_os_from_option_list(RZ_NONNULL const char *os_list);
RZ_API ut16 rz_core_flirt_app_from_option_list(RZ_NONNULL const char *app_list);

/* DECOMPILER PRINTING FUNCTIONS */
/**
 * @brief Prints the data contained in the specified RzAnnotatedCode in JSON format.
 *
 * The function will print the output in console using the function rz_cons_printf();
 *
 * @param code Pointer to a RzAnnotatedCode.
 */
RZ_API void rz_core_annotated_code_print_json(RzAnnotatedCode *code);
/**
 * @brief Prints the decompiled code from the specified RzAnnotatedCode.
 *
 * This function is used for printing the output of commands pdg and pdgo.
 * It can print the decompiled code with or without offsets. If line_offsets is a null pointer,
 * the output will be printed without offsets (pdg), otherwise, the output will be
 * printed with offsets.
 * This function will print the output in console using the function rz_cons_printf();
 *
 * @param code Pointer to a RzAnnotatedCode.
 * @param line_offsets Pointer to a @ref RzVector that contains offsets for the decompiled code.
 */
RZ_API void rz_core_annotated_code_print(RzAnnotatedCode *code, RzVector /*<ut64>*/ *line_offsets);
/**
 * @brief  Prints the decompiled code as comments
 *
 * This function is used for the output of command pdg*
 * Output will be printed in console using the function rz_cons_printf();
 *
 * @param code Pointer to a RzAnnotatedCode.
 */
RZ_API void rz_core_annotated_code_print_comment_cmds(RzAnnotatedCode *code);

/* serialize */

/**
 * @param prj_file filename of the project that db will be saved to later. This is only used to re-locate the loaded RIO descs, the project file itself is not touched by this function.
 */
RZ_API void rz_serialize_core_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file);

/**
 * @param load_bin_io whether to also load the underlying RIO and RBin state from the project. If false, the current state will be kept and the project loaded on top.
 * @param prj_file filename of the project that db comes from. This is only used to re-locate the loaded RIO descs, the project file itself is not touched by this function.
 */
RZ_API bool rz_serialize_core_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, bool load_bin_io,
	RZ_NULLABLE const char *prj_file, RZ_NULLABLE RzSerializeResultInfo *res);

RZ_API void rz_serialize_core_seek_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core);

RZ_API bool rz_serialize_core_seek_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE RzSerializeResultInfo *res);

/**
 * \brief Load a project and print info and errors
 */
RZ_API bool rz_core_project_load_for_cli(RzCore *core, const char *file, bool load_bin_io);

RZ_API bool rz_platform_index_add_flags_comments(RzCore *core);

/* regs */
/// Callback for synchronizing register state in commands (only relevant for debug, not for analysis)
typedef bool (*RzCmdRegSync)(RzCore *core, RzRegisterType type, bool write);
RZ_API bool rz_core_reg_assign_sync(RZ_NONNULL RzCore *core, RZ_NONNULL RzReg *reg, RzCmdRegSync sync_cb, RZ_NONNULL const char *name, ut64 val);
RZ_API RZ_OWN RzList /*<RzRegItem *>*/ *rz_core_reg_filter_items_sync(RZ_NONNULL RzCore *core, RZ_NONNULL RzReg *reg, RzCmdRegSync sync_cb, RZ_NULLABLE const char *filter);

RZ_API void rz_core_cmd_show_analysis_help(RZ_NONNULL RzCore *core);
RZ_API void rz_core_rtr_enable(RZ_NONNULL RzCore *core, const char *cmdremote);

RZ_API RZ_OWN char *rz_core_analysis_var_to_string(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisVar *var);
RZ_API RZ_OWN char *rz_core_analysis_var_display(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisVar *var, bool add_name);

RZ_API ut64 rz_core_analysis_var_addr(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisVar *var);

RZ_API void rz_core_sym_name_init(RZ_NONNULL RZ_OUT RzBinSymNames *names, RZ_NONNULL RzBinSymbol *symbol, bool demangle);
RZ_API void rz_core_sym_name_fini(RZ_NULLABLE RzBinSymNames *names);

RZ_API void rz_core_analysis_bytes_il(RZ_NONNULL RzCore *core, ut64 len, ut64 num_ops, bool pretty);

#endif

#ifdef __cplusplus
}
#endif

#endif
