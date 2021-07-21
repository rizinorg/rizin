// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CORE_H
#define RZ_CORE_H

#include <rz_main.h>
#include <rz_socket.h>
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
#include <rz_msg_digest.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_crypto.h>
#include <rz_bind.h>
#include <rz_util/rz_annotated_code.h>
#include "rz_heap_glibc.h"

#ifdef __cplusplus
extern "C" {
#endif
RZ_LIB_VERSION_HEADER(rz_core);

#define RZ_CORE_CMD_OK      0
#define RZ_CORE_CMD_INVALID -1
#define RZ_CORE_CMD_EXIT    -2

#define RZ_CORE_BLOCKSIZE     0x100
#define RZ_CORE_BLOCKSIZE_MAX 0x3200000 /* 32MB */

#define RZ_CORE_ANALYSIS_GRAPHLINES         1
#define RZ_CORE_ANALYSIS_GRAPHBODY          2
#define RZ_CORE_ANALYSIS_GRAPHDIFF          4
#define RZ_CORE_ANALYSIS_JSON               8
#define RZ_CORE_ANALYSIS_KEYVALUE           16
#define RZ_CORE_ANALYSIS_JSON_FORMAT_DISASM 32
#define RZ_CORE_ANALYSIS_STAR               64

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

#define RZ_GRAPH_FORMAT_NO     0
#define RZ_GRAPH_FORMAT_GMLFCN 1
#define RZ_GRAPH_FORMAT_JSON   2
#define RZ_GRAPH_FORMAT_GML    3
#define RZ_GRAPH_FORMAT_DOT    4
#define RZ_GRAPH_FORMAT_CMD    5

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

/* visual mode */
typedef enum {
	RZ_CORE_VISUAL_MODE_PX = 0,
	RZ_CORE_VISUAL_MODE_PD = 1,
	RZ_CORE_VISUAL_MODE_DB = 2,
	RZ_CORE_VISUAL_MODE_OV = 3,
	RZ_CORE_VISUAL_MODE_CD = 4
} RzCoreVisualMode;

typedef bool (*RzCorePluginInit)(RzCore *core);
typedef bool (*RzCorePluginFini)(RzCore *core);

typedef struct rz_core_plugin_t {
	const char *name;
	const char *desc;
	const char *license;
	const char *author;
	const char *version;
	RzCorePluginInit init;
	RzCorePluginFini fini;
} RzCorePlugin;

typedef struct rz_core_rtr_host_t {
	int proto;
	char host[512];
	int port;
	char file[1024];
	RzSocket *fd;
} RzCoreRtrHost;

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
	RzPVector /*<RzBinFile>*/ binfiles; ///< all bin files that have been created for this core file
	RzPVector /*<RzIODesc>*/ extra_files; ///< additional files opened during mapping, for example for zeroed maps
	RzPVector /*<RzIOMap>*/ maps; ///< all maps that have been created as a result of loading this file
} RzCoreFile;

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
	RZ_CORE_AUTOCMPLT_ZIGN,
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

typedef struct rz_core_visual_tab_t {
	int printidx;
	ut64 offset;
	bool cur_enabled;
	int cur;
	int ocur;
	int cols;
	int disMode;
	int hexMode;
	int asm_offset;
	int asm_instr;
	int asm_indent;
	int asm_bytes;
	int asm_cmt_col;
	int printMode;
	int current3format;
	int current4format;
	int current5format;
	int dumpCols;
	char name[32]; // XXX leak because no  rz_core_visual_tab_free
	// TODO: cursor and such
} RzCoreVisualTab;
// #define RzCoreVisualTab Tab

typedef struct rz_core_visual_t {
	RzList *tabs;
	int tab;
} RzCoreVisual;
// #define RzCoreVisual Visual

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
	RzList *tasks;
	RzList *tasks_queue;
	RzList *oneshot_queue;
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
	RzVector undos; ///< Stack of RzCoreSeekItems, allowing to "go back in time"
	RzVector redos; ///< Stack of RzCoreSeekItems, allowing to re-do an action that was undone.
	bool saved_set; ///< When true, the \p saved field is set
	RzCoreSeekItem saved_item; ///< Position to save in history
} RzCoreSeekHistory;

struct rz_core_t {
	RzBin *bin;
	RzList *plugins; ///< List of registered core plugins
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
	RzList *files;
	RNum *num;
	ut64 rc; // command's return code .. related to num->value;
	RzLib *lib;
	RzCmd *rcmd;
	RzCmdDescriptor root_cmd_descriptor;
	RzList /*<RzCmdDescriptor>*/ *cmd_descriptors;
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
	RzAGraph *graph;
	RzPanelsRoot *panels_root;
	RzPanels *panels;
	char *cmdqueue;
	char *lastcmd;
	bool is_lastcmd;
	char *cmdlog;
	int cmdrepeat; // cmd.repeat
	const char *cmdtimes; // cmd.times
	RZ_DEPRECATE bool cmd_in_backticks; // whether currently executing a cmd out of backticks
	int rtr_n;
	RzCoreRtrHost rtr_host[RTR_MAX_HOSTS];
	ut64 *asmqjmps;
	int asmqjmps_count;
	int asmqjmps_size;
	bool is_asmqjmps_letter;
	bool keep_asmqjmps;
	RzCoreVisual visual;
	// visual // TODO: move them into RzCoreVisual
	int http_up;
	int gdbserver_up;
	RzCoreVisualMode printidx;
	char *stkcmd;
	bool in_search;
	RzList *watchers;
	RzList *scriptstack;
	RzCoreTaskScheduler tasks;
	int max_cmd_depth;
	ut8 switch_file_view;
	Sdb *sdb;
	int incomment;
	int curtab; // current tab
	int seltab; // selected tab
	char *cmdremote;
	char *lastsearch;
	char *cmdfilter;
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
	RzList *gadgets;
	bool scr_gadgets;
	bool log_events; // core.c:cb_event_handler : log actions from events if cfg.log.events is set
	RzList *ropchain;
	bool use_tree_sitter_rzcmd;
	bool use_rzshell_autocompletion;
	RzCoreSeekHistory seek_history;

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

RZ_API void rz_core_item_free(RzCoreItem *ci);

typedef struct rz_core_cmpwatch_t {
	ut64 addr;
	int size;
	char cmd[32];
	ut8 *odata;
	ut8 *ndata;
} RzCoreCmpWatcher;

typedef int (*RzCoreSearchCallback)(RzCore *core, ut64 from, ut8 *buf, int len);

#ifdef RZ_API
RZ_API int rz_core_bind(RzCore *core, RzCoreBind *bnd);

/**
 * \brief APIs to handle Visual Gadgets
 */
RZ_API void rz_core_gadget_free(RzCoreGadget *g);
RZ_API void rz_core_gadget_print(RzCore *core);

RZ_API bool rz_core_plugin_init(RzCore *core);
RZ_API bool rz_core_plugin_add(RzCore *core, RzCorePlugin *plugin);
RZ_API bool rz_core_plugin_fini(RzCore *core);

//#define rz_core_ncast(x) (RzCore*)(size_t)(x)
RZ_API RzList *rz_core_list_themes(RzCore *core);
RZ_API char *rz_core_get_theme(void);
RZ_API void rz_core_theme_nextpal(RzCore *core, int mode);
RZ_API const char *rz_core_get_section_name(RzCore *core, ut64 addr);
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
RZ_API bool rz_core_bin_load_structs(RzCore *core, const char *file);
RZ_API int rz_core_config_init(RzCore *core);
RZ_API void rz_core_parse_rizinrc(RzCore *r);
RZ_API int rz_core_prompt(RzCore *core, int sync);
RZ_API int rz_core_prompt_exec(RzCore *core);
RZ_API void rz_core_prompt_loop(RzCore *core);
RZ_API ut64 rz_core_pava(RzCore *core, ut64 addr);
RZ_API int rz_core_cmd(RzCore *core, const char *cmd, int log);
RZ_API RzCmdStatus rz_core_cmd_rzshell(RzCore *core, const char *cmd, int log);
RZ_API char *rz_core_editor(const RzCore *core, const char *file, const char *str);
RZ_API int rz_core_fgets(char *buf, int len, void *user);
RZ_API RzFlagItem *rz_core_flag_get_by_spaces(RzFlag *f, ut64 off);
RZ_API int rz_core_cmdf(RzCore *core, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_core_flush(RzCore *core, const char *cmd);
RZ_API int rz_core_cmd0(RzCore *core, const char *cmd);
RZ_API void rz_core_cmd_init(RzCore *core);
RZ_API int rz_core_cmd_pipe(RzCore *core, char *rizin_cmd, char *shell_cmd);
RZ_API char *rz_core_cmd_str(RzCore *core, const char *cmd);
RZ_API char *rz_core_cmd_strf(RzCore *core, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API char *rz_core_cmd_str_pipe(RzCore *core, const char *cmd);
RZ_API int rz_core_cmd_file(RzCore *core, const char *file);
RZ_API int rz_core_cmd_lines(RzCore *core, const char *lines);
RZ_API RzCmdStatus rz_core_cmd_lines_rzshell(RzCore *core, const char *lines);
RZ_API int rz_core_cmd_command(RzCore *core, const char *command);
RZ_API bool rz_core_run_script(RzCore *core, const char *file);
RZ_API void rz_core_seek_item_free(RzCoreSeekItem *item);
RZ_API bool rz_core_seek(RzCore *core, ut64 addr, bool rb);
RZ_API bool rz_core_seek_and_save(RzCore *core, ut64 addr, bool rb);
RZ_API bool rz_core_seek_opt(RzCore *core, ut64 addr, bool rb, bool save);
RZ_API bool rz_core_seek_mark(RzCore *core);
RZ_API bool rz_core_seek_save(RzCore *core);
RZ_API bool rz_core_seek_undo(RzCore *core);
RZ_API bool rz_core_seek_redo(RzCore *core);
RZ_API void rz_core_seek_reset(RzCore *core);
RZ_API void rz_core_seek_free(RzCore *core);
RZ_API RzList *rz_core_seek_list(RzCore *core);
RZ_API RzCoreSeekItem *rz_core_seek_peek(RzCore *core, int idx);
RZ_API int rz_core_seek_base(RzCore *core, const char *hex, bool save);
RZ_API bool rz_core_seek_prev(RzCore *core, const char *type, bool save);
RZ_API bool rz_core_seek_next(RzCore *core, const char *type, bool save);
RZ_API bool rz_core_seek_align(RzCore *core, ut64 align, bool save);
RZ_API bool rz_core_seek_delta(RzCore *core, st64 delta, bool save);
RZ_API bool rz_core_seek_analysis_bb(RzCore *core, ut64 addr, bool save);
RZ_API bool rz_core_visual_bit_editor(RzCore *core);
RZ_API void rz_core_arch_bits_at(RzCore *core, ut64 addr, RZ_OUT RZ_NULLABLE int *bits, RZ_OUT RZ_BORROW RZ_NULLABLE const char **arch);
RZ_API void rz_core_seek_arch_bits(RzCore *core, ut64 addr);
RZ_API int rz_core_block_read(RzCore *core);
RZ_API int rz_core_block_size(RzCore *core, int bsize);
RZ_API int rz_core_is_valid_offset(RzCore *core, ut64 offset);
RZ_API int rz_core_write_hexpair(RzCore *core, ut64 addr, const char *pairs);
RZ_API int rz_core_write_assembly(RzCore *core, ut64 addr, const char *instructions, bool pretend, bool pad);
RZ_API int rz_core_shift_block(RzCore *core, ut64 addr, ut64 b_size, st64 dist);
RZ_API void rz_core_autocomplete(RZ_NULLABLE RzCore *core, RzLineCompletion *completion, RzLineBuffer *buf, RzLinePromptType prompt_type);
RZ_API RzLineNSCompletionResult *rz_core_autocomplete_rzshell(RzCore *core, RzLineBuffer *buf, RzLinePromptType prompt_type);
RZ_API void rz_core_print_scrollbar(RzCore *core);
RZ_API void rz_core_print_scrollbar_bottom(RzCore *core);
RZ_API void rz_core_help_vars_print(RzCore *core);
RZ_API void rz_core_visual_prompt_input(RzCore *core);
RZ_API void rz_core_visual_toggle_hints(RzCore *core);
RZ_API void rz_core_visual_toggle_decompiler_disasm(RzCore *core, bool for_graph, bool reset);
RZ_API void rz_core_visual_applyDisMode(RzCore *core, int disMode);
RZ_API void rz_core_visual_applyHexMode(RzCore *core, int hexMode);
RZ_API int rz_core_visual_xrefs(RzCore *core, bool xref_to, bool fcnInsteadOfAddr);
RZ_API void rz_core_visual_append_help(RzStrBuf *p, const char *title, const char **help);
RZ_API bool rz_core_prevop_addr(RzCore *core, ut64 start_addr, int numinstrs, ut64 *prev_addr);
RZ_API ut64 rz_core_prevop_addr_force(RzCore *core, ut64 start_addr, int numinstrs);
RZ_API bool rz_core_visual_hudstuff(RzCore *core);
RZ_API int rz_core_visual_classes(RzCore *core);
RZ_API int rz_core_visual_analysis_classes(RzCore *core);
RZ_API int rz_core_visual(RzCore *core, const char *input);
RZ_API int rz_core_visual_graph(RzCore *core, RzAGraph *g, RzAnalysisFunction *_fcn, int is_interactive);
RZ_API bool rz_core_visual_panels_root(RzCore *core, RzPanelsRoot *panels_root);
RZ_API void rz_core_visual_browse(RzCore *core, const char *arg);
RZ_API int rz_core_visual_cmd(RzCore *core, const char *arg);
RZ_API void rz_core_visual_seek_animation(RzCore *core, ut64 addr);
RZ_API void rz_core_visual_seek_animation_redo(RzCore *core);
RZ_API void rz_core_visual_seek_animation_undo(RzCore *core);
RZ_API void rz_core_visual_asm(RzCore *core, ut64 addr);
RZ_API void rz_core_visual_colors(RzCore *core);
RZ_API void rz_core_visual_showcursor(RzCore *core, int x);
RZ_API void rz_core_visual_offset(RzCore *core);
RZ_API int rz_core_visual_hud(RzCore *core);
RZ_API void rz_core_visual_jump(RzCore *core, ut8 ch);
RZ_API void rz_core_visual_disasm_up(RzCore *core, int *cols);
RZ_API void rz_core_visual_disasm_down(RzCore *core, RzAsmOp *op, int *cols);
RZ_API RzBinReloc *rz_core_getreloc(RzCore *core, ut64 addr, int size);
RZ_API RzBinReloc *rz_core_get_reloc_to(RzCore *core, ut64 addr);
RZ_API ut64 rz_core_get_asmqjmps(RzCore *core, const char *str);
RZ_API void rz_core_set_asmqjmps(RzCore *core, char *str, size_t len, int i);
RZ_API char *rz_core_add_asmqjmp(RzCore *core, ut64 addr);

RZ_API void rz_core_analysis_type_init(RzCore *core);
RZ_API char *rz_core_analysis_hasrefs_to_depth(RzCore *core, ut64 value, PJ *pj, int depth);
RZ_API void rz_core_link_stroff(RzCore *core, RzAnalysisFunction *fcn);
RZ_API bool cmd_analysis_objc(RzCore *core, bool auto_analysis);
RZ_API void rz_core_analysis_cc_init(RzCore *core);
RZ_API void rz_core_analysis_paths(RzCore *core, ut64 from, ut64 to, bool followCalls, int followDepth, bool is_json);
RZ_API void rz_core_analysis_esil_graph(RzCore *core, const char *expr);

RZ_API RzListInfo *rz_listinfo_new(const char *name, RzInterval pitv, RzInterval vitv, int perm, const char *extra);
RZ_API void rz_listinfo_free(RzListInfo *info);
/* visual marks */
RZ_API void rz_core_visual_mark_seek(RzCore *core, ut8 ch);
RZ_API void rz_core_visual_mark(RzCore *core, ut8 ch);
RZ_API void rz_core_visual_mark_set(RzCore *core, ut8 ch, ut64 addr);
RZ_API void rz_core_visual_mark_del(RzCore *core, ut8 ch);
RZ_API bool rz_core_visual_mark_dump(RzCore *core);
RZ_API void rz_core_visual_mark_reset(RzCore *core);

RZ_API int rz_core_search_cb(RzCore *core, ut64 from, ut64 to, RzCoreSearchCallback cb);
RZ_API bool rz_core_serve(RzCore *core, RzIODesc *fd);
RZ_API int rz_core_file_reopen(RzCore *core, const char *args, int perm, int binload);
RZ_API void rz_core_file_reopen_debug(RzCore *core, const char *args);
RZ_API void rz_core_file_reopen_remote_debug(RzCore *core, char *uri, ut64 addr);
RZ_API bool rz_core_file_resize(RzCore *core, ut64 newsize);
RZ_API bool rz_core_file_resize_delta(RzCore *core, st64 delta);
RZ_API RzCoreFile *rz_core_file_find_by_fd(RzCore *core, ut64 fd);
RZ_API RzCoreFile *rz_core_file_find_by_name(RzCore *core, const char *name);
RZ_API RzCoreFile *rz_core_file_cur(RzCore *r);
RZ_API int rz_core_file_set_by_fd(RzCore *core, ut64 fd);
RZ_API int rz_core_file_set_by_name(RzCore *core, const char *name);
RZ_API int rz_core_file_set_by_file(RzCore *core, RzCoreFile *cf);
RZ_API int rz_core_setup_debugger(RzCore *r, const char *debugbackend, bool attach);

RZ_API RzCoreFile *rz_core_file_open(RzCore *core, const char *file, int flags, ut64 loadaddr);
RZ_API RzCoreFile *rz_core_file_open_many(RzCore *r, const char *file, int flags, ut64 loadaddr);
RZ_API RzCoreFile *rz_core_file_get_by_fd(RzCore *core, int fd);
RZ_API void rz_core_file_close(RzCoreFile *fh);
RZ_API bool rz_core_file_close_fd(RzCore *core, int fd);
RZ_API bool rz_core_file_close_all_but(RzCore *core);
RZ_API int rz_core_file_list(RzCore *core, int mode);
RZ_API int rz_core_file_binlist(RzCore *core);
RZ_API bool rz_core_file_bin_raise(RzCore *core, ut32 num);
RZ_API bool rz_core_extend_at(RzCore *core, ut64 addr, int size);
RZ_API bool rz_core_write_at(RzCore *core, ut64 addr, const ut8 *buf, int size);
RZ_API int rz_core_write_op(RzCore *core, const char *arg, char op);
RZ_API ut8 *rz_core_transform_op(RzCore *core, const char *arg, char op);
RZ_API ut32 rz_core_file_cur_fd(RzCore *core);

/* cdebug.c */
RZ_API bool rz_core_debug_step_one(RzCore *core, int times);
RZ_API bool rz_core_debug_continue_until(RzCore *core, ut64 addr, ut64 to);

RZ_API void rz_core_debug_ri(RzCore *core, RzReg *reg, int mode);
RZ_API void rz_core_debug_rr(RzCore *core, RzReg *reg, int mode);
RZ_API void rz_core_debug_set_register_flags(RzCore *core);
RZ_API void rz_core_debug_clear_register_flags(RzCore *core);

RZ_API RzCmdStatus rz_core_debug_plugins_print(RzCore *core, RzCmdStateOutput *state);

/* chash.c */
RZ_API RzCmdStatus rz_core_hash_plugins_print(RzCmdStateOutput *state);

/* cio.c */
RZ_API RzCmdStatus rz_core_io_plugins_print(RzIO *io, RzCmdStateOutput *state);

/* cio.c */
RZ_API RzCmdStatus rz_core_parser_plugins_print(RzParse *parser, RzCmdStateOutput *state);

/* fortune */
RZ_API void rz_core_fortune_list_types(void);
RZ_API void rz_core_fortune_list(RzCore *core);
RZ_API void rz_core_fortune_print_random(RzCore *core);

#define RZ_CORE_FOREIGN_ADDR -1
RZ_API int rz_core_yank(RzCore *core, ut64 addr, int len);
RZ_API int rz_core_yank_string(RzCore *core, ut64 addr, int maxlen);
RZ_API bool rz_core_yank_hexpair(RzCore *core, const char *input);
RZ_API int rz_core_yank_paste(RzCore *core, ut64 addr, int len);
RZ_API int rz_core_yank_set(RzCore *core, ut64 addr, const ut8 *buf, ut32 len); // set yank buffer bytes
RZ_API int rz_core_yank_set_str(RzCore *core, ut64 addr, const char *buf, ut32 len); // Null terminate the bytes
RZ_API int rz_core_yank_to(RzCore *core, const char *arg);
RZ_API bool rz_core_yank_dump(RzCore *core, ut64 pos, int format);
RZ_API int rz_core_yank_hexdump(RzCore *core, ut64 pos);
RZ_API int rz_core_yank_cat(RzCore *core, ut64 pos);
RZ_API int rz_core_yank_cat_string(RzCore *core, ut64 pos);
RZ_API int rz_core_yank_hud_file(RzCore *core, const char *input);
RZ_API int rz_core_yank_hud_path(RzCore *core, const char *input, int dir);
RZ_API bool rz_core_yank_file_ex(RzCore *core, const char *input);
RZ_API int rz_core_yank_file_all(RzCore *core, const char *input);

#define RZ_CORE_LOADLIBS_ENV    1
#define RZ_CORE_LOADLIBS_HOME   2
#define RZ_CORE_LOADLIBS_SYSTEM 4
#define RZ_CORE_LOADLIBS_CONFIG 8
#define RZ_CORE_LOADLIBS_ALL    UT32_MAX

RZ_API void rz_core_loadlibs_init(RzCore *core);
RZ_API int rz_core_loadlibs(RzCore *core, int where, const char *path);
RZ_API int rz_core_cmd_buffer(RzCore *core, const char *buf);
RZ_API int rz_core_cmdf(RzCore *core, const char *fmt, ...) RZ_PRINTF_CHECK(2, 3);
RZ_API int rz_core_cmd0(RzCore *core, const char *cmd);
RZ_API RzCmdStatus rz_core_cmd0_rzshell(RzCore *core, const char *cmd);
RZ_API char *rz_core_cmd_str(RzCore *core, const char *cmd);
RZ_API int rz_core_cmd_foreach(RzCore *core, const char *cmd, char *each);
RZ_API int rz_core_cmd_foreach3(RzCore *core, const char *cmd, char *each);
RZ_API char *rz_core_op_str(RzCore *core, ut64 addr);
RZ_API RzAnalysisOp *rz_core_op_analysis(RzCore *core, ut64 addr, RzAnalysisOpMask mask);
RZ_API char *rz_core_disassemble_instr(RzCore *core, ut64 addr, int l);
RZ_API char *rz_core_disassemble_bytes(RzCore *core, ut64 addr, int b);

/* carg.c */
RZ_API RzList *rz_core_get_func_args(RzCore *core, const char *func_name);
RZ_API void rz_core_print_func_args(RzCore *core);
RZ_API char *resolve_fcn_name(RzAnalysis *analysis, const char *func_name);

/* clang.c */
RZ_API RzCmdStatus rz_core_lang_plugins_print(RzLang *lang, RzCmdStateOutput *state);

/* ccore.c */
RZ_API RzCmdStatus rz_core_core_plugins_print(RzCore *core, RzCmdStateOutput *state);

/* canalysis.c */
RZ_API RzAnalysisOp *rz_core_analysis_op(RzCore *core, ut64 addr, int mask);
RZ_API void rz_core_analysis_esil(RzCore *core, const char *str, const char *addr);
RZ_API void rz_core_analysis_fcn_merge(RzCore *core, ut64 addr, ut64 addr2);
RZ_API const char *rz_core_analysis_optype_colorfor(RzCore *core, ut64 addr, bool verbose);
RZ_API ut64 rz_core_analysis_address(RzCore *core, ut64 addr);
RZ_API void rz_core_analysis_undefine(RzCore *core, ut64 off);
RZ_API void rz_core_analysis_hint_print(RzAnalysis *a, ut64 addr, int mode);
RZ_API void rz_core_analysis_hint_list(RzAnalysis *a, int mode);
RZ_API int rz_core_analysis_search(RzCore *core, ut64 from, ut64 to, ut64 ref, int mode);
RZ_API int rz_core_analysis_search_xrefs(RzCore *core, ut64 from, ut64 to, PJ *pj, int rad);
RZ_API int rz_core_analysis_data(RzCore *core, ut64 addr, int count, int depth, int wordsize);
RZ_API void rz_core_analysis_datarefs(RzCore *core, ut64 addr);
RZ_API void rz_core_analysis_coderefs(RzCore *core, ut64 addr);
RZ_API RzGraph /*RzGraphNodeInfo*/ *rz_core_analysis_codexrefs(RzCore *core, ut64 addr);
RZ_API RzGraph /*RzGraphNodeInfo*/ *rz_core_analysis_importxrefs(RzCore *core);
RZ_API void rz_core_analysis_callgraph(RzCore *core, ut64 addr, int fmt);
RZ_API int rz_core_analysis_refs(RzCore *core, const char *input);
RZ_API void rz_core_agraph_print(RzCore *core, int use_utf, const char *input);
RZ_API bool rz_core_esil_cmd(RzAnalysisEsil *esil, const char *cmd, ut64 a1, ut64 a2);
RZ_API int rz_core_esil_step(RzCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver);
RZ_API int rz_core_esil_step_back(RzCore *core);
RZ_API void rz_core_analysis_flag_every_function(RzCore *core);
RZ_API bool rz_core_analysis_function_rename(RzCore *core, ut64 addr, const char *_name);
RZ_API bool rz_core_analysis_function_add(RzCore *core, const char *name, ut64 addr, bool analyze_recursively);
RZ_API int rz_core_analysis_fcn(RzCore *core, ut64 at, ut64 from, int reftype, int depth);
RZ_API char *rz_core_analysis_fcn_autoname(RzCore *core, ut64 addr, int dump, int mode);
RZ_API void rz_core_analysis_autoname_all_fcns(RzCore *core);
RZ_API void rz_core_analysis_autoname_all_golang_fcns(RzCore *core);
RZ_DEPRECATE RZ_API int rz_core_analysis_fcn_list(RzCore *core, const char *input, const char *rad);
RZ_API char *rz_core_analysis_fcn_name(RzCore *core, RzAnalysisFunction *fcn);
RZ_API ut64 rz_core_analysis_fcn_list_size(RzCore *core);
RZ_API int rz_core_analysis_fcn_clean(RzCore *core, ut64 addr);
RZ_API int rz_core_print_bb_custom(RzCore *core, RzAnalysisFunction *fcn);
RZ_API int rz_core_print_bb_gml(RzCore *core, RzAnalysisFunction *fcn);
RZ_API bool rz_core_analysis_graph(RzCore *core, ut64 addr, int opts);
RZ_API RzList *rz_core_analysis_graph_to(RzCore *core, ut64 addr, int n);
RZ_API int rz_core_analysis_all(RzCore *core);
RZ_API bool rz_core_analysis_everything(RzCore *core, bool experimental, char *dh_orig);
RZ_API RzList *rz_core_analysis_cycles(RzCore *core, int ccl);
RZ_API RzList *rz_core_analysis_fcn_get_calls(RzCore *core, RzAnalysisFunction *fcn); // get all calls from a function
RZ_API void rz_cmd_analysis_calls(RzCore *core, const char *input, bool printCommands, bool importsOnly);
RZ_API int rz_core_get_stacksz(RzCore *core, ut64 from, ut64 to);

/*tp.c*/
RZ_API void rz_core_analysis_type_match(RzCore *core, RzAnalysisFunction *fcn);

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

RZ_API RzBuffer *rz_core_syscall(RzCore *core, const char *name, const char *args);
RZ_API RzBuffer *rz_core_syscallf(RzCore *core, const char *name, const char *fmt, ...) RZ_PRINTF_CHECK(3, 4);
RZ_API RzCoreAsmHit *rz_core_asm_hit_new(void);
RZ_API RzList *rz_core_asm_hit_list_new(void);
RZ_API void rz_core_asm_hit_free(void *_hit);
RZ_API void rz_core_set_asm_configs(RzCore *core, char *arch, ut32 bits, int segoff);
RZ_API char *rz_core_asm_search(RzCore *core, const char *input);
RZ_API RzCmdStatus rz_core_asm_plugins_print(RzCore *core, const char *arch, RzCmdStateOutput *state);
RZ_API RzList *rz_core_asm_strsearch(RzCore *core, const char *input, ut64 from, ut64 to, int maxhits, int regexp, int everyByte, int mode);
RZ_API RzList *rz_core_asm_bwdisassemble(RzCore *core, ut64 addr, int n, int len);
RZ_API RzList *rz_core_asm_back_disassemble_instr(RzCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
RZ_API RzList *rz_core_asm_back_disassemble_byte(RzCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
RZ_API ut32 rz_core_asm_bwdis_len(RzCore *core, int *len, ut64 *start_addr, ut32 l);
RZ_API int rz_core_print_disasm(RzPrint *p, RzCore *core, ut64 addr, ut8 *buf, int len, int lines, int invbreak, int nbytes, bool json, PJ *pj, RzAnalysisFunction *pdf);
RZ_API int rz_core_print_disasm_json(RzCore *core, ut64 addr, ut8 *buf, int len, int lines, PJ *pj);
RZ_API int rz_core_print_disasm_instructions_with_buf(RzCore *core, ut64 address, ut8 *buf, int nb_bytes, int nb_opcodes);
RZ_API int rz_core_print_disasm_instructions(RzCore *core, int nb_bytes, int nb_opcodes);
RZ_API int rz_core_print_disasm_all(RzCore *core, ut64 addr, int l, int len, int mode);
RZ_API int rz_core_disasm_pdi_with_buf(RzCore *core, ut64 address, ut8 *buf, ut32 nb_opcodes, ut32 nb_bytes, int fmt);
RZ_API int rz_core_disasm_pdi(RzCore *core, int nb_opcodes, int nb_bytes, int fmt);
RZ_API int rz_core_disasm_pde(RzCore *core, int nb_opcodes, int mode);
RZ_API RZ_OWN char *rz_core_disasm_instruction(RzCore *core, ut64 addr, ut64 reladdr, RZ_NULLABLE RzAnalysisFunction *fcn, bool color);
RZ_API bool rz_core_print_function_disasm_json(RzCore *core, RzAnalysisFunction *fcn, PJ *pj);
RZ_API int rz_core_flag_in_middle(RzCore *core, ut64 at, int oplen, int *midflags);
RZ_API int rz_core_bb_starts_in_middle(RzCore *core, ut64 at, int oplen);

RZ_API bool rz_core_bin_raise(RzCore *core, ut32 bfid);

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
RZ_API bool rz_core_bin_load(RzCore *core, const char *file, ut64 baseaddr);
RZ_API int rz_core_bin_rebase(RzCore *core, ut64 baddr);
RZ_API void rz_core_bin_export_info(RzCore *core, int mode);
RZ_API int rz_core_bin_list(RzCore *core, int mode);
RZ_API bool rz_core_bin_delete(RzCore *core, RzBinFile *bf);
RZ_API ut64 rz_core_bin_impaddr(RzBin *bin, int va, const char *name);

RZ_API void rz_core_bin_print_source_line_sample(RzCore *core, const RzBinSourceLineSample *s, RzOutputMode mode, PJ *pj);
RZ_API void rz_core_bin_print_source_line_info(RzCore *core, const RzBinSourceLineInfo *li, RzOutputMode mode, PJ *pj);

// bin_dwarf
RZ_API void rz_core_bin_dwarf_print_abbrev_section(const RzBinDwarfDebugAbbrev *da);
RZ_API void rz_core_bin_dwarf_print_attr_value(const RzBinDwarfAttrValue *val);
RZ_API void rz_core_bin_dwarf_print_debug_info(const RzBinDwarfDebugInfo *inf);
RZ_API void rz_core_bin_dwarf_print_loc(HtUP /*<offset, RzBinDwarfLocList*>*/ *loc_table, int addr_size);
RZ_API void rz_core_bin_dwarf_print_aranges(RzList /*<RzBinDwarfARangeSet>*/ *aranges);
RZ_API void rz_core_bin_dwarf_print_line_units(RzList /*<RzBinDwarfLineUnit>*/ *lines);

// XXX - this is kinda hacky, maybe there should be a way to
// refresh the bin environment without specific calls?
RZ_API int rz_core_pseudo_code(RzCore *core, const char *input);

/* gdiff.c */
RZ_API bool rz_core_gdiff_2_files(RzCore *core1, RzCore *core2);
RZ_API bool rz_core_gdiff_function_1_file(RzCore *c, ut64 addr, ut64 addr2);
RZ_API bool rz_core_gdiff_function_2_files(RzCore *core1, RzCore *core2, ut64 addr, ut64 addr2);

RZ_API char *rz_core_sysenv_begin(RzCore *core, const char *cmd);
RZ_API void rz_core_sysenv_end(RzCore *core, const char *cmd);

RZ_API void rz_core_recover_vars(RzCore *core, RzAnalysisFunction *fcn, bool argonly);

/* cmd_linux_heap_glibc.c */
RZ_API RzList *rz_heap_chunks_list(RzCore *core, ut64 m_arena);
RZ_API RzList *rz_heap_arenas_list(RzCore *core);
RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr);
RZ_API RzHeapBin *rz_heap_bin_content(RzCore *core, MallocState *arena, int bin_num, ut64 m_arena);
RZ_API RzHeapBin *rz_heap_fastbin_content(RzCore *core, MallocState *arena, int bin_num);
RZ_API MallocState *rz_heap_get_arena(RzCore *core, ut64 m_state);

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
#define RZ_CORE_BIN_ACC_HASHES           0x10000000
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

RZ_API int rz_core_bin_info(RzCore *core, int action, PJ *pj, int mode, int va, RzCoreBinFilter *filter, const char *chksum);
RZ_API int rz_core_bin_set_arch_bits(RzCore *r, const char *name, const char *arch, ut16 bits);
RZ_API int rz_core_bin_update_arch_bits(RzCore *r);
RZ_API char *rz_core_bin_method_build_flag_name(RzBinClass *cls, RzBinSymbol *meth);
RZ_API char *rz_core_bin_method_flags_str(ut64 flags, int mode);
RZ_API bool rz_core_pdb_info(RzCore *core, const char *file, PJ *pj, int mode);
RZ_API RzCmdStatus rz_core_bin_plugins_print(RzBin *bin, RzCmdStateOutput *state);

typedef enum {
	RZ_CORE_STRING_KIND_UNKNOWN,
	RZ_CORE_STRING_KIND_ASCII,
	RZ_CORE_STRING_KIND_WIDE16, // No UTF/Unicode encoding
	RZ_CORE_STRING_KIND_WIDE32, // NO UTF/Unicode encoding
	RZ_CORE_STRING_KIND_UTF8,
	RZ_CORE_STRING_KIND_UTF16,
	RZ_CORE_STRING_KIND_UTF32,
} RzCoreStringKind;

/**
 * \brief A structure to hold information about string - type, size, and location
 */
typedef struct rz_core_string_t {
	/**
	 * The pointer to the string data itself.
	 */
	const char *string;
	ut64 offset;
	/**
	 * Size of buffer containing the string in bytes.
	 */
	ut32 size;
	/**
	 * Length of string in chars.
	 */
	ut32 length;
	/**
	 * A string kind - ASCII, Wide, or various Unicode types.
	 */
	RzCoreStringKind kind;
	/**
	 * A section name that contains the string.
	 */
	const char *section_name;
} RzCoreString;

RZ_API RZ_OWN RzCoreString *rz_core_string_information(RzCore *core, const char *block, ut32 len, RzCoreStringKind kind);

/* rtr */
RZ_API int rz_core_rtr_cmds(RzCore *core, const char *port);
RZ_API char *rz_core_rtr_cmds_query(RzCore *core, const char *host, const char *port, const char *cmd);
RZ_API void rz_core_rtr_pushout(RzCore *core, const char *input);
RZ_API void rz_core_rtr_list(RzCore *core);
RZ_API void rz_core_rtr_add(RzCore *core, const char *input);
RZ_API void rz_core_rtr_remove(RzCore *core, const char *input);
RZ_API void rz_core_rtr_session(RzCore *core, const char *input);
RZ_API void rz_core_rtr_cmd(RzCore *core, const char *input);
RZ_API int rz_core_rtr_http(RzCore *core, int launch, int browse, const char *path);
RZ_API int rz_core_rtr_http_stop(RzCore *u);
RZ_API int rz_core_rtr_gdb(RzCore *core, int launch, const char *path);

RZ_API int rz_core_visual_prevopsz(RzCore *core, ut64 addr);
RZ_API void rz_core_visual_config(RzCore *core);
RZ_API void rz_core_visual_analysis(RzCore *core, const char *input);
RZ_API void rz_core_visual_debugtraces(RzCore *core, const char *input);
RZ_API void rz_core_visual_define(RzCore *core, const char *arg, int distance);
RZ_API int rz_core_visual_trackflags(RzCore *core);
RZ_API int rz_core_visual_view_graph(RzCore *core);
RZ_API int rz_core_visual_view_zigns(RzCore *core);
RZ_API int rz_core_visual_view_rop(RzCore *core);
RZ_API int rz_core_visual_comments(RzCore *core);
RZ_API int rz_core_visual_prompt(RzCore *core);
RZ_API bool rz_core_visual_esil(RzCore *core);
RZ_API int rz_core_search_preludes(RzCore *core, bool log);
RZ_API int rz_core_search_prelude(RzCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen);
RZ_API RzList * /*<RzIOMap*>*/ rz_core_get_boundaries_prot(RzCore *core, int protection, const char *mode, const char *prefix);

RZ_API void rz_core_hack_help(const RzCore *core);
RZ_API int rz_core_hack(RzCore *core, const char *op);
RZ_API bool rz_core_dump(RzCore *core, const char *file, ut64 addr, ut64 size, int append);
RZ_API void rz_core_diff_show(RzCore *core, RzCore *core2, bool json);
RZ_API bool rz_core_diff_show_function(RzCore *core, RzCore *core2, ut64 addr, bool json);
RZ_API void rz_core_clippy(RzCore *core, const char *msg);

/* watchers */
RZ_API void rz_core_cmpwatch_free(RzCoreCmpWatcher *w);
RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RzCore *core, ut64 addr);
RZ_API int rz_core_cmpwatch_add(RzCore *core, ut64 addr, int size, const char *cmd);
RZ_API int rz_core_cmpwatch_del(RzCore *core, ut64 addr);
RZ_API int rz_core_cmpwatch_update(RzCore *core, ut64 addr);
RZ_API int rz_core_cmpwatch_show(RzCore *core, ut64 addr, int mode);
RZ_API int rz_core_cmpwatch_revert(RzCore *core, ut64 addr);

// TODO MOVE SOMEWHERE ELSE
typedef char *(*PrintItemCallback)(void *user, void *p, bool selected);
RZ_API char *rz_str_widget_list(void *user, RzList *list, int rows, int cur, PrintItemCallback cb);
/* help */
RZ_API void rz_core_cmd_help(const RzCore *core, const char *help[]);
RZ_API const char **rz_core_help_vars_get(RzCore *core);

/* analysis stats */

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
} RzCoreAnalStatsItem;
typedef struct {
	RzCoreAnalStatsItem *block;
} RzCoreAnalStats;

RZ_API char *rz_core_analysis_hasrefs(RzCore *core, ut64 value, int mode);
RZ_API char *rz_core_analysis_get_comments(RzCore *core, ut64 addr);
RZ_API RzCoreAnalStats *rz_core_analysis_get_stats(RzCore *a, ut64 from, ut64 to, ut64 step);
RZ_API void rz_core_analysis_stats_free(RzCoreAnalStats *s);

RZ_API int rz_line_hist_offset_up(RzLine *line);
RZ_API int rz_line_hist_offset_down(RzLine *line);

// TODO : move into debug or syscall++
RZ_API char *cmd_syscall_dostr(RzCore *core, st64 num, ut64 addr);

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

RZ_API void rz_core_echo(RzCore *core, const char *msg);
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

RZ_API RzCoreAutocomplete *rz_core_autocomplete_add(RzCoreAutocomplete *parent, const char *cmd, int type, bool lock);
RZ_API void rz_core_autocomplete_free(RzCoreAutocomplete *obj);
RZ_API void rz_core_autocomplete_reload(RzCore *core);
RZ_API RzCoreAutocomplete *rz_core_autocomplete_find(RzCoreAutocomplete *parent, const char *cmd, bool exact);
RZ_API bool rz_core_autocomplete_remove(RzCoreAutocomplete *parent, const char *cmd);
RZ_API void rz_core_analysis_propagate_noreturn(RzCore *core, ut64 addr);

/* PLUGINS */
extern RzCorePlugin rz_core_plugin_java;

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
RZ_API void rz_core_annotated_code_print(RzAnnotatedCode *code, RzVector *line_offsets);
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

/**
 * \brief Load a project and print info and errors
 */
RZ_API bool rz_core_project_load_for_cli(RzCore *core, const char *file, bool load_bin_io);

RZ_API bool rz_arch_platform_add_flags_comments(RzCore *core);

#endif

#ifdef __cplusplus
}
#endif

#endif
