// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CORE_PRIVATE_INCLUDE_H_
#define RZ_CORE_PRIVATE_INCLUDE_H_

#include <rz_types.h>
#include <rz_core.h>
#include <rz_il.h>

RZ_IPI void rz_core_kuery_print(RzCore *core, const char *k);
RZ_IPI int rz_output_mode_to_char(RzOutputMode mode);

RZ_IPI int bb_cmpaddr(const void *_a, const void *_b);
RZ_IPI int fcn_cmpaddr(const void *_a, const void *_b);

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val);
RZ_IPI void rz_core_analysis_esil_init(RzCore *core);
RZ_IPI void rz_core_analysis_esil_reinit(RzCore *core);
RZ_IPI void rz_core_analysis_esil_init_mem_del(RzCore *core, const char *name, ut64 addr, ut32 size);
RZ_IPI void rz_core_analysis_esil_init_mem(RzCore *core, const char *name, ut64 addr, ut32 size);
RZ_IPI void rz_core_analysis_esil_init_mem_p(RzCore *core);
RZ_IPI void rz_core_analysis_esil_init_regs(RzCore *core);
RZ_IPI void rz_core_analysis_esil_step_over(RzCore *core);
RZ_IPI void rz_core_analysis_esil_step_over_until(RzCore *core, ut64 addr);
RZ_IPI void rz_core_analysis_esil_step_over_untilexpr(RzCore *core, const char *expr);
RZ_IPI void rz_core_analysis_esil_references_all_functions(RzCore *core);
RZ_IPI void rz_core_analysis_esil_emulate(RzCore *core, ut64 addr, ut64 until_addr, int off);
RZ_IPI void rz_core_analysis_esil_emulate_bb(RzCore *core);
RZ_IPI void rz_core_analysis_esil_default(RzCore *core);

RZ_IPI void rz_core_analysis_rzil_reinit(RzCore *core);
RZ_IPI void rz_core_analysis_rzil_vm_status(RzCore *core, const char *varname, RzOutputMode mode);
RZ_IPI void rz_core_rzil_step(RzCore *core);
RZ_IPI void rz_core_analysis_rzil_step_with_events(RzCore *core, PJ *pj);

RZ_IPI bool rz_core_analysis_var_rename(RzCore *core, const char *name, const char *newname);
RZ_IPI char *rz_core_analysis_function_signature(RzCore *core, RzOutputMode mode, char *fcn_name);
RZ_IPI bool rz_core_analysis_function_delete_var(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarKind kind, const char *id);
RZ_IPI char *rz_core_analysis_var_display(RzCore *core, RzAnalysisVar *var, bool add_name);
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

/* cmeta.c */
RZ_IPI void rz_core_meta_print(RzCore *core, RzAnalysisMetaItem *d, ut64 start, ut64 size, bool show_full, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print_list_at(RzCore *core, ut64 addr, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print_list_all(RzCore *core, int type, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_print_list_in_function(RzCore *core, int type, ut64 addr, RzCmdStateOutput *state);
RZ_IPI void rz_core_meta_append(RzCore *core, const char *newcomment, RzAnalysisMetaType mtype, ut64 addr);
RZ_IPI void rz_core_meta_editor(RzCore *core, RzAnalysisMetaType mtype, ut64 addr);

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
RZ_IPI RZ_OWN char *rz_core_types_as_c(RzCore *core, RZ_NONNULL const char *name, bool multiline);

RZ_IPI void rz_core_types_calling_conventions_print(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_function_print(RzTypeDB *typedb, const char *function, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_function_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_function_noreturn_print(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_show_format(RzCore *core, const char *name, RzOutputMode mode);
RZ_IPI void rz_core_types_struct_print_format_all(RzCore *core);
RZ_IPI void rz_core_types_union_print_format_all(RzCore *core);
RZ_IPI void rz_core_types_link_print(RzCore *core, RzType *type, ut64 addr, RzOutputMode mode, PJ *pj);
RZ_IPI void rz_core_types_link_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_core_types_link_show(RzCore *core, ut64 addr);
RZ_IPI void rz_core_types_print_all(RzCore *core, RzOutputMode mode);
RZ_IPI void rz_types_define(RzCore *core, const char *type);
RZ_IPI bool rz_types_open_file(RzCore *core, const char *path);
RZ_IPI bool rz_types_open_editor(RzCore *core, const char *typename);

/* agraph.c */
RZ_IPI void rz_core_agraph_add_node(RzCore *core, const char *title, const char *body, int color);
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
RZ_IPI void rz_core_agraph_print_write(RzCore *core, const char *filename);

RZ_IPI RzCmdStatus rz_core_bin_plugin_print(const RzBinPlugin *bp, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_core_binxtr_plugin_print(const RzBinXtrPlugin *bx, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_core_binldr_plugin_print(const RzBinLdrPlugin *ld, RzCmdStateOutput *state);

/* creg.c */
RZ_IPI void rz_core_reg_update_flags(RzCore *core);
RZ_IPI RzList /*<RzRegItem>*/ *rz_core_reg_flags_candidates(RzCore *core, RzReg *reg);

/* cdebug.c */
RZ_IPI bool rz_core_debug_reg_set(RzCore *core, const char *regname, ut64 val, const char *strval);
RZ_IPI bool rz_core_debug_reg_list(RzCore *core, int type, int size, bool skip_covered, PJ *pj, int rad, const char *use_color);
RZ_IPI void rz_core_debug_sync_bits(RzCore *core);
RZ_IPI void rz_core_debug_single_step_in(RzCore *core);
RZ_IPI void rz_core_debug_single_step_over(RzCore *core);
RZ_IPI void rz_core_debug_breakpoint_toggle(RzCore *core, ut64 addr);
RZ_IPI void rz_core_debug_continue(RzCore *core);
RZ_IPI void rz_core_debug_attach(RzCore *core, int pid);
RZ_IPI void rz_core_debug_print_status(RzCore *core);

/* cfile.c */
RZ_IPI void rz_core_io_file_open(RzCore *core, int fd);
RZ_IPI void rz_core_io_file_reopen(RzCore *core, int fd, int perms);

/* cmd_seek.c */

RZ_IPI bool rz_core_seek_to_register(RzCore *core, const char *input, bool is_silent);
RZ_IPI int rz_core_seek_opcode_forward(RzCore *core, int n, bool silent);
RZ_IPI int rz_core_seek_opcode_forward(RzCore *core, int n, bool silent);
RZ_IPI int rz_core_seek_opcode(RzCore *core, int numinstr, bool silent);

/* cmd_meta.c */
RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr);

/* cmd_flag.c */
RZ_IPI void rz_core_flag_describe(RzCore *core, ut64 addr, bool strict_offset, RzOutputMode mode);

/* cmd_debug.c */
RZ_IPI void rz_core_dbg_follow_seek_register(RzCore *core);
RZ_IPI void rz_core_static_debug_stop(void *u);

/* cmd_regs.c */
/// Callback for synchronizing register state in commands (only relevant for debug, not for analysis)
typedef bool (*RzCmdRegSync)(RzCore *core, RzRegisterType type, bool write);
RZ_IPI RzCmdStatus rz_regs_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus rz_regs_columns_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_regs_references_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzOutputMode mode);
RZ_IPI void rz_regs_show_valgroup(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, const RzList *list);
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

#if __WINDOWS__
/* windows_heap.c */
RZ_IPI RzList *rz_heap_blocks_list(RzCore *core);
RZ_IPI RzList *rz_heap_list(RzCore *core);
RZ_IPI void rz_heap_debug_block_win(RzCore *core, const char *addr, RzOutputMode mode, bool flag);
RZ_IPI void rz_heap_list_w32(RzCore *core, RzOutputMode mode);
#endif

#endif
