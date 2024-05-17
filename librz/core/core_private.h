// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CORE_PRIVATE_INCLUDE_H_
#define RZ_CORE_PRIVATE_INCLUDE_H_

#include <rz_types.h>
#include <rz_core.h>
#include <rz_il.h>

RZ_IPI void rz_core_kuery_print(RzCore *core, const char *k);
RZ_IPI int rz_output_mode_to_char(RzOutputMode mode);

RZ_IPI int bb_cmpaddr(const void *_a, const void *_b, void *user);
RZ_IPI int fcn_cmpaddr(const void *_a, const void *_b, void *user);

RZ_IPI void rz_core_add_string_ref(RzCore *core, ut64 xref_from, ut64 xref_to);
RZ_IPI bool rz_core_get_string_at(RzCore *core, ut64 address, char **string, size_t *length, RzStrEnc *encoding, bool can_search);
RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val);
RZ_IPI void rz_core_analysis_esil_init(RzCore *core);
RZ_IPI void rz_core_analysis_esil_init_mem_p(RzCore *core);
RZ_IPI void rz_core_analysis_esil_step_over_until(RzCore *core, ut64 addr);
RZ_IPI void rz_core_analysis_esil_step_over_untilexpr(RzCore *core, const char *expr);
RZ_IPI void rz_core_analysis_esil_references_all_functions(RzCore *core);
RZ_IPI void rz_core_analysis_esil_emulate(RzCore *core, ut64 addr, ut64 until_addr, int off);
RZ_IPI void rz_core_analysis_esil_emulate_bb(RzCore *core);
RZ_IPI void rz_core_analysis_esil_default(RzCore *core);
RZ_IPI void rz_core_debug_esil_watch_print(RzDebug *dbg, RzCmdStateOutput *state);

RZ_IPI bool rz_core_analysis_il_vm_set(RzCore *core, const char *var_name, ut64 value);
RZ_IPI void rz_core_analysis_il_vm_status(RzCore *core, const char *varname, RzOutputMode mode);
RZ_IPI bool rz_core_analysis_il_step_with_events(RzCore *core, PJ *pj);
RZ_IPI void rz_core_il_cons_print(RZ_NONNULL RzCore *core, RZ_NONNULL RZ_BORROW RzIterator *iter, bool pretty);

RZ_IPI bool rz_core_analysis_var_rename(RzCore *core, const char *name, const char *newname);
RZ_IPI char *rz_core_analysis_function_signature(RzCore *core, RzOutputMode mode, char *fcn_name);
RZ_IPI bool rz_core_analysis_function_delete_var(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarStorageType kind, const char *id);
RZ_IPI char *rz_core_analysis_all_vars_display(RzCore *core, RzAnalysisFunction *fcn, bool add_name);
RZ_IPI bool rz_analysis_var_global_list_show(RzAnalysis *analysis, RzCmdStateOutput *state, RZ_NULLABLE const char *name);
RZ_IPI bool rz_core_analysis_types_propagation(RzCore *core);
RZ_IPI bool rz_core_analysis_function_set_signature(RzCore *core, RzAnalysisFunction *fcn, const char *newsig);
RZ_IPI void rz_core_analysis_function_signature_editor(RzCore *core, ut64 addr);
RZ_IPI void rz_core_analysis_bbs_asciiart(RzCore *core, RzAnalysisFunction *fcn);
RZ_IPI void rz_core_analysis_fcn_returns(RzCore *core, RzAnalysisFunction *fcn);
RZ_IPI void rz_core_analysis_bbs_info_print(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state);
RZ_IPI void rz_core_analysis_bb_info_print(RzCore *core, RzAnalysisBlock *bb, ut64 addr, RzCmdStateOutput *state);
RZ_IPI void rz_core_analysis_function_until(RzCore *core, ut64 addr_end);
RZ_IPI void rz_core_analysis_value_pointers(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_analysis_cc_print(RzCore *core, RZ_NONNULL const char *cc, RZ_NULLABLE PJ *pj);
RZ_IPI void rz_core_analysis_resolve_pointers_to_data(RzCore *core);
RZ_IPI ut64 rz_core_prevop_addr_heuristic(RzCore *core, ut64 addr);

/* cmeta.c */
RZ_IPI void rz_core_spaces_print(RzCore *core, RzSpaces *spaces, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print(RzCore *core, RzAnalysisMetaItem *d, ut64 start, ut64 size, bool show_full, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print_list_at(RzCore *core, ut64 addr, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print_list_all(RzCore *core, int type, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print_list_in_function(RzCore *core, int type, ut64 addr, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_append(RzCore *core, const char *newcomment, RzAnalysisMetaType mtype, ut64 addr);
RZ_IPI void rz_core_meta_editor(RzCore *core, RzAnalysisMetaType mtype, ut64 addr);

RZ_IPI bool rz_core_cmd_calculate_expr(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input, RZ_BORROW PJ *pj);

/* ctypes.c */
// Enums
RZ_IPI void rz_core_types_enum_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_enum_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI RZ_OWN char *rz_core_types_enum_as_c(RzTypeDB *typedb, const RzBaseType *btype, bool multiline);
RZ_IPI RZ_OWN char *rz_core_types_enum_as_c_all(RzTypeDB *typedb, bool multiline);
// Unions
RZ_IPI void rz_core_types_union_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_union_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI RZ_OWN char *rz_core_types_union_as_c(RzTypeDB *typedb, const RzBaseType *btype, bool multiline);
RZ_IPI RZ_OWN char *rz_core_types_union_as_c_all(RzTypeDB *typedb, bool multiline);
// Structs
RZ_IPI void rz_core_types_struct_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_struct_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI RZ_OWN char *rz_core_types_struct_as_c(RzTypeDB *typedb, const RzBaseType *btype, bool multiline);
RZ_IPI RZ_OWN char *rz_core_types_struct_as_c_all(RzTypeDB *typedb, bool multiline);
// Typedefs
RZ_IPI void rz_core_types_typedef_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_typedef_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI RZ_OWN char *rz_core_types_typedef_as_c(RzTypeDB *typedb, const RzBaseType *btype);
RZ_IPI RZ_OWN char *rz_core_types_typedef_as_c_all(RzTypeDB *typedb);

RZ_IPI RZ_OWN char *rz_core_base_type_as_c(RzCore *core, RZ_NONNULL RzBaseType *type, bool multiline);

RZ_IPI void rz_core_types_calling_conventions_print(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_function_print(RzTypeDB *typedb, const char *function, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_function_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_function_noreturn_print(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_show_format(RzCore *core, const char *name, RzOutputMode mode);
RZ_IPI void rz_core_types_struct_print_format_all(RzCore *core);
RZ_IPI void rz_core_types_union_print_format_all(RzCore *core);
RZ_IPI void rz_core_types_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_types_define(RzCore *core, const char *type);
RZ_IPI bool rz_types_open_file(RzCore *core, const char *path);
RZ_IPI bool rz_types_open_editor(RzCore *core, RZ_NONNULL const char *typename);

/* agraph.c */
RZ_IPI void rz_core_agraph_add_node(RzCore *core, const char *title, const char *body);
RZ_IPI void rz_core_agraph_del_node(RzCore *core, const char *title);
RZ_IPI void rz_core_agraph_add_edge(RzCore *core, const char *un, const char *vn);
RZ_IPI void rz_core_agraph_del_edge(RzCore *core, const char *un, const char *vn);
RZ_IPI void rz_core_agraph_reset(RzCore *core);
RZ_IPI void rz_core_agraph_print_ascii(RzCore *core);
RZ_IPI void rz_core_agraph_print_tiny(RzCore *core);
RZ_IPI void rz_core_agraph_print_sdb(RzCore *core);
RZ_IPI void rz_core_agraph_print_interactive(RzCore *core);
RZ_IPI void rz_core_agraph_print_dot(RzCore *core);
RZ_IPI void rz_core_agraph_print_rizin(RzCore *core);
RZ_IPI void rz_core_agraph_print_json(RzCore *core);
RZ_IPI void rz_core_agraph_print_gml(RzCore *core);
RZ_IPI bool rz_core_agraph_print(RzCore *core, RzCoreGraphFormat format);
RZ_IPI bool rz_core_agraph_is_shortcuts(RzCore *core, RzAGraph *g);
RZ_IPI bool rz_core_agraph_add_shortcut(RzCore *core, RzAGraph *g, RzANode *an, ut64 addr, char *title);
RZ_IPI bool rz_core_agraph_apply(RzCore *core, RzGraph /*<RzGraphNodeInfo *>*/ *graph);

/* cgraph.c */
RZ_IPI bool rz_core_graph_print_graph(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RzCoreGraphFormat format, bool use_offset);
RZ_IPI bool rz_core_graph_print(RzCore *core, ut64 addr, RzCoreGraphType type, RzCoreGraphFormat format);

RZ_IPI RzCmdStatus rz_core_bin_plugin_print(const RzBinPlugin *bp, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_core_binxtr_plugin_print(const RzBinXtrPlugin *bx, RzCmdStateOutput *state);

/* creg.c */
RZ_IPI RzList /*<RzRegItem *>*/ *rz_core_reg_flags_candidates(RzCore *core, RzReg *reg);
RZ_IPI void rz_core_reg_print_diff(RzReg *reg, RzList /*<RzRegItem *>*/ *items);

/* cdebug.c */
RZ_IPI void rz_core_debug_single_step_in(RzCore *core);
RZ_IPI void rz_core_debug_single_step_over(RzCore *core);
RZ_IPI void rz_core_debug_continue(RzCore *core);
RZ_IPI void rz_core_debug_attach(RzCore *core, int pid);
RZ_IPI void rz_core_debug_print_status(RzCore *core);
RZ_IPI void rz_core_debug_bp_add(RzCore *core, ut64 addr, const char *arg_perm, const char *arg_size, bool hwbp, bool watch);
RZ_IPI void rz_core_debug_ri(RzCore *core);
RZ_IPI bool rz_core_debug_pid_print(RzDebug *dbg, int pid, RzCmdStateOutput *state);
RZ_IPI bool rz_core_debug_thread_print(RzDebug *dbg, int pid, RzCmdStateOutput *state);
RZ_IPI bool rz_core_debug_desc_print(RzDebug *dbg, RzCmdStateOutput *state);
RZ_IPI void rz_core_debug_signal_print(RzDebug *dbg, RzCmdStateOutput *state);

/* cfile.c */
RZ_IPI RzCoreIOMapInfo *rz_core_io_map_info_new(RzCoreFile *cf, int perm_orig);
RZ_IPI void rz_core_io_map_info_free(RzCoreIOMapInfo *info);

/* cflag.c */
RZ_IPI void rz_core_flag_print(RzFlag *f, RzCmdStateOutput *state);
RZ_IPI void rz_core_flag_real_name_print(RzFlag *f, RzCmdStateOutput *state);
RZ_IPI void rz_core_flag_range_print(RzFlag *f, RzCmdStateOutput *state, ut64 range_from, ut64 range_to);

/* cdisasm.c */
RZ_IPI bool rz_disasm_check_end(st64 nb_opcodes, st64 i_opcodes, st64 nb_bytes, st64 i_bytes);
RZ_IPI void rz_core_asm_bb_middle(RZ_NONNULL RzCore *core, ut64 at, RZ_INOUT RZ_NONNULL int *oplen, RZ_NONNULL int *ret);
RZ_IPI ut64 rz_core_backward_offset(RZ_NONNULL RzCore *core, ut64 cur_offset, RZ_NONNULL RZ_INOUT int *pn_opcodes, RZ_NONNULL RZ_INOUT int *pn_bytes);

/* cprint.c */
RZ_IPI bool rz_core_print_hexdump_diff(RZ_NONNULL RzCore *core, ut64 aa, ut64 ba, ut64 len);
RZ_IPI bool rz_core_print_dump(RZ_NONNULL RzCore *core, RzOutputMode mode, ut64 addr, ut8 n, int len, RzCorePrintFormatType format);
RZ_IPI bool rz_core_print_hexdump_or_hexdiff(RZ_NONNULL RzCore *core, RzOutputMode mode, ut64 addr, int len, bool use_comments);
RZ_IPI bool rz_core_print_hexdump_byline(RZ_NONNULL RzCore *core, bool hex_offset, ut64 addr, int len, ut8 size);
RZ_IPI RZ_OWN char *rz_core_print_hexdump_refs(RZ_NONNULL RzCore *core, ut64 address, size_t len, int wordsize);
RZ_IPI const char *rz_core_print_stack_command(RZ_NONNULL RzCore *core);
RZ_IPI RZ_OWN char *rz_core_print_cons_disassembly(RzCore *core, ut64 addr, ut32 byte_len, ut32 inst_len);
RZ_IPI RZ_OWN char *rz_core_print_format(RzCore *core, const char *fmt, int mode, ut64 address);
RZ_IPI RZ_OWN char *rz_core_print_format_write(RzCore *core, const char *fmt, const char *value, ut64 address);

/* cmd_seek.c */
RZ_IPI bool rz_core_seek_to_register(RzCore *core, const char *input, bool is_silent);
RZ_IPI int rz_core_seek_opcode_forward(RzCore *core, int n, bool silent);
RZ_IPI int rz_core_seek_opcode(RzCore *core, int numinstr, bool silent);
RZ_IPI bool rz_core_seek_bb_instruction(RzCore *core, int index);

/* cmd_meta.c */
RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr);

/* cmd_flag.c */
RZ_IPI void rz_core_flag_describe(RzCore *core, ut64 addr, bool strict_offset, RzCmdStateOutput *state);

/* cmd_debug.c */
RZ_IPI void rz_core_static_debug_stop(void *u);

/* cmd_macro.c */
RZ_IPI RzCmdStatus rz_macros_handler(RzCore *core, const char *name, const char **args, const char *body, const char **argv);

/* cmd_regs.c */
RZ_IPI RzCmdStatus rz_regs_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_regs_columns_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_regs_references_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzOutputMode mode);
RZ_IPI void rz_regs_show_valgroup(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, const RzList /*<RzRegItem *>*/ *list);
RZ_IPI RzCmdStatus rz_regs_valgroup_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_push_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_pop_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_swap_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_zero_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_hexdump_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_stack_size_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_arenas_write_hex_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_regs_args_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzOutputMode mode);
RZ_IPI RzCmdStatus rz_reg_types_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_roles_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_flags_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, bool unset);
RZ_IPI RzCmdStatus rz_reg_profile_handler(RzCore *core, RzReg *reg, int argc, const char **argv, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_reg_profile_comments_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_profile_open_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_profile_gdb_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_cond_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_reg_cc_handler(RzCore *core, RzReg *reg, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_regs_diff_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_regs_prev_handler(RzCore *core, RzReg *reg, int argc, const char **argv, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_regs_fpu_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);

RZ_IPI void rz_core_print_hexdump(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL const ut8 *buf, int len, int base, int step, size_t zoomsz);
RZ_IPI void rz_core_print_jsondump(RZ_NONNULL RzCore *core, RZ_NONNULL const ut8 *buf, int len, int wordsize);
RZ_IPI void rz_core_print_hexdiff(RZ_NONNULL RzCore *core, ut64 aa, RZ_NONNULL const ut8 *_a, ut64 ba, RZ_NONNULL const ut8 *_b, int len, int scndcol);

// cmd_help.c
RZ_IPI void rz_core_clippy_print(RzCore *core, const char *msg);

#if __WINDOWS__
/* windows_heap.c */
RZ_IPI RzList *rz_heap_blocks_list(RzCore *core);
RZ_IPI RzList *rz_heap_list(RzCore *core);
RZ_IPI void rz_heap_debug_block_win(RzCore *core, const char *addr, RzOutputMode mode, bool flag);
RZ_IPI void rz_heap_list_w32(RzCore *core, RzOutputMode mode);
#endif

RZ_IPI bool rz_core_cmd_lastcmd_repeat(RzCore *core, bool next);

static inline RzCmdStatus bool2status(bool val) {
	return val ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

/* Visual modes */

typedef enum {
	RZ_CORE_VISUAL_MODE_PX = 0, ///< Hexadecimal view
	RZ_CORE_VISUAL_MODE_PD = 1, ///< Disassembly view
	RZ_CORE_VISUAL_MODE_DB = 2, ///< Debug mode
	RZ_CORE_VISUAL_MODE_OV = 3, ///< Color blocks (entropy)
	RZ_CORE_VISUAL_MODE_CD = 4 ///< Print in string format
} RzCoreVisualMode;

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

typedef int (*RzPanelsMenuCallback)(void *user);
typedef struct rz_panels_menu_item {
	int selectedIndex;
	char *name;
	RzPVector /*<RzPanelsMenuItem *>*/ submenus;
	RzPanelsMenuCallback cb;
	RzPanel *p;
} RzPanelsMenuItem;

typedef struct rz_panels_menu_t {
	RzPanelsMenuItem *root;
	RzPanelsMenuItem **history;
	int depth;
	int n_refresh;
	RzPanel **refreshPanels;
} RzPanelsMenu;

typedef enum {
	PANEL_MODE_DEFAULT,
	PANEL_MODE_MENU,
	PANEL_MODE_ZOOM,
	PANEL_MODE_WINDOW,
	PANEL_MODE_HELP
} RzPanelsMode;

typedef enum {
	PANEL_LAYOUT_DEFAULT_STATIC = 0,
	PANEL_LAYOUT_DEFAULT_DYNAMIC = 1
} RzPanelsLayout;

typedef struct rz_panels_tab_t {
	RzConsCanvas *can;
	RzPanel **panel;
	int n_panels;
	int columnWidth;
	int curnode;
	int mouse_orig_x;
	int mouse_orig_y;
	bool autoUpdate;
	bool mouse_on_edge_x;
	bool mouse_on_edge_y;
	RzPanelsMenu *panels_menu;
	HtSS *db;
	HtSP *rotate_db;
	HtSP *almighty_db;
	HtSP *mht;
	RzPanelsMode mode;
	RzPanelsMode prevMode;
	RzPanelsLayout layout;
	char *name;
	bool first_run;
} RzPanelsTab;

typedef enum {
	DEFAULT,
	ROTATE,
	DEL,
	QUIT,
} RzPanelsRootState;

typedef struct rz_panels_root_t {
	int cur_tab;
	RzPVector /*<RzPanelsTab *>*/ tabs;
	RzPanelsTab *active_tab; // Seems redudant since we have cur_tab index
	RzPanelsRootState root_state;
	RzPVector /*<char *>*/ *themes; ///< Available rizin themes
	bool from_visual;
} RzPanelsRoot;

typedef struct rz_core_visual_view_t {
	int level;
	st64 delta;
	ut64 column_nlines;
	// output is used to store the result of printCmds
	// and avoid duplicated analysis while j and k is pressed
	char *output;
	// output_mode labels which printCmds' result is stored in output
	int output_mode;
	int output_addr;
	int option;
	int variable_option;
	int printMode;
	bool selectPanel;
	bool hide_legend;
	bool is_inputing; // whether the user is inputing
	char *inputing; // for filter on the go in Vv mode
} RzCoreVisualView;

typedef struct rz_core_visual_t {
	RzList /*<RzCoreVisualTab *>*/ *tabs;
	int tab;
	RzCoreVisualMode printidx;
	/* TODO: Reorganize */
	int obs;
	bool autoblocksize;
	int disMode;
	int hexMode;
	int printMode;
	int color;
	int debug;
	/* Insert mode */
	bool insertMode;
	int insertNibble;
	/* Split view */
	bool splitView;
	ut64 splitPtr;
	/* Output formats */
	int currentFormat;
	int current0format;
	int current3format;
	int current4format;
	int current5format;
	/* Panels */
	RzPanelsRoot *panels_root;
	/* file percentage */
	float percentage;
	/* visual view */
	RzCoreVisualView *view;
} RzCoreVisual;

RZ_IPI RZ_OWN RzCoreVisual *rz_core_visual_new();
RZ_IPI void rz_core_visual_free(RZ_NULLABLE RzCoreVisual *visual);

RZ_IPI void rz_panels_root_free(RZ_NULLABLE RzPanelsRoot *panels_root);

RZ_IPI void rz_core_visual_prompt_input(RzCore *core);
RZ_IPI void rz_core_visual_toggle_hints(RzCore *core);
RZ_IPI void rz_core_visual_toggle_decompiler_disasm(RzCore *core, bool for_graph, bool reset);
RZ_IPI void rz_core_visual_applyDisMode(RzCore *core, int disMode);
RZ_IPI void rz_core_visual_applyHexMode(RzCore *core, int hexMode);
RZ_IPI int rz_core_visual_xrefs(RzCore *core, bool xref_to, bool fcnInsteadOfAddr);
RZ_IPI void rz_core_visual_append_help(RzStrBuf *p, const char *title, const char **help);

/* tui/biteditor.c */
RZ_IPI bool rz_core_visual_bit_editor(RzCore *core);

/* tui/classes.c */
RZ_IPI int rz_core_visual_classes(RzCore *core);
RZ_IPI int rz_core_visual_analysis_classes(RzCore *core);

/* tui/comments.c */
RZ_IPI int rz_core_visual_comments(RzCore *core);

/* tui/config.c */
RZ_IPI void rz_core_visual_config(RzCore *core);

/* tui/define.c */
RZ_IPI void rz_core_visual_define(RzCore *core, const char *arg, int distance);

/* tui/esil.c */
RZ_IPI bool rz_core_visual_esil(RzCore *core);

/* tui/flags.c */
RZ_IPI int rz_core_visual_trackflags(RzCore *core);

/* tui/hud.c */
RZ_IPI bool rz_core_visual_hudstuff(RzCore *core);
RZ_IPI bool rz_core_visual_hud(RzCore *core);
RZ_IPI bool rz_core_visual_config_hud(RzCore *core);
RZ_IPI bool rz_core_visual_hudclasses(RzCore *core);

/* tui/rop.c */
RZ_IPI int rz_core_visual_view_rop(RzCore *core);

/* tui/tabs.c */
RZ_IPI void rz_core_visual_tab_free(RzCoreVisualTab *tab);
RZ_IPI int rz_core_visual_tab_count(RzCore *core);
RZ_IPI RZ_OWN char *rz_core_visual_tab_string(RzCore *core, const char *kolor);
RZ_IPI void rz_core_visual_tabget(RzCore *core, RzCoreVisualTab *tab);
RZ_IPI void rz_core_visual_tabset(RzCore *core, RzCoreVisualTab *tab);
RZ_IPI RZ_OWN RzCoreVisualTab *rz_core_visual_tab_new(RzCore *core);
RZ_IPI void rz_core_visual_tab_update(RzCore *core);
RZ_IPI RZ_OWN RzCoreVisualTab *rz_core_visual_newtab(RzCore *core);
RZ_IPI void rz_core_visual_nthtab(RzCore *core, int n);
RZ_IPI void rz_core_visual_tabname_prompt(RzCore *core);
RZ_IPI void rz_core_visual_nexttab(RzCore *core);
RZ_IPI void rz_core_visual_prevtab(RzCore *core);
RZ_IPI void rz_core_visual_closetab(RzCore *core);

RZ_IPI int rz_core_visual(RzCore *core, const char *input);
RZ_IPI int rz_core_visual_graph(RzCore *core, RzAGraph *g, RzAnalysisFunction *_fcn, int is_interactive);
RZ_IPI bool rz_core_visual_panels_root(RzCore *core, RzPanelsRoot *panels_root);
RZ_IPI void rz_core_visual_browse(RzCore *core, const char *arg);
RZ_IPI int rz_core_visual_cmd(RzCore *core, const char *arg);
RZ_IPI void rz_core_visual_seek_animation(RzCore *core, ut64 addr);
RZ_IPI void rz_core_visual_seek_animation_redo(RzCore *core);
RZ_IPI void rz_core_visual_seek_animation_undo(RzCore *core);
RZ_IPI void rz_core_visual_asm(RzCore *core, ut64 addr);
RZ_IPI void rz_core_visual_colors(RzCore *core);
RZ_IPI void rz_core_visual_showcursor(RzCore *core, int x);
RZ_IPI void rz_core_visual_offset(RzCore *core);
RZ_IPI void rz_core_visual_jump(RzCore *core, ut8 ch);
RZ_IPI void rz_core_visual_disasm_up(RzCore *core, int *cols);
RZ_IPI void rz_core_visual_disasm_down(RzCore *core, RzAsmOp *op, int *cols);

RZ_IPI int rz_core_visual_prevopsz(RzCore *core, ut64 addr);
RZ_IPI void rz_core_visual_analysis(RzCore *core, const char *input);
RZ_IPI void rz_core_visual_debugtraces(RzCore *core, const char *input);
RZ_IPI int rz_core_visual_view_graph(RzCore *core);
RZ_IPI int rz_core_visual_prompt(RzCore *core);

RZ_IPI void rz_core_visual_scrollbar(RzCore *core);
RZ_IPI void rz_core_visual_scrollbar_bottom(RzCore *core);

RZ_IPI int rz_line_hist_offset_up(RzLine *line);
RZ_IPI int rz_line_hist_offset_down(RzLine *line);

/* visual marks */
RZ_IPI void rz_core_visual_mark_seek(RzCore *core, ut8 ch);
RZ_IPI void rz_core_visual_mark(RzCore *core, ut8 ch);
RZ_IPI void rz_core_visual_mark_set(RzCore *core, ut8 ch, ut64 addr);
RZ_IPI void rz_core_visual_mark_del(RzCore *core, ut8 ch);
RZ_IPI bool rz_core_visual_mark_dump(RzCore *core);
RZ_IPI void rz_core_visual_mark_reset(RzCore *core);

static inline char *rz_address_str(ut64 addr) {
	return rz_str_newf("0x%" PFMT64x, addr);
}

RZ_IPI void rz_core_prompt_highlight(RzCore *core);

#endif
