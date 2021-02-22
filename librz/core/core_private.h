#ifndef RZ_CORE_PRIVATE_INCLUDE_H_
#define RZ_CORE_PRIVATE_INCLUDE_H_

#include <rz_types.h>
#include <rz_core.h>

RZ_IPI void rz_core_kuery_print(RzCore *core, const char *k);
RZ_IPI int rz_output_mode_to_char(RzOutputMode mode);

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val);
RZ_IPI void rz_core_analysis_esil_init(RzCore *core);
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

RZ_IPI bool rz_core_analysis_var_rename(RzCore *core, const char *name, const char *newname);
RZ_IPI RzList *rz_core_analysis_calling_conventions(RzCore *core);
RZ_IPI void rz_core_analysis_calling_conventions_print(RzCore *core);
RZ_IPI char *rz_core_analysis_function_signature(RzCore *core, RzOutputMode mode, char *fcn_name);
RZ_IPI bool rz_core_analysis_everything(RzCore *core, bool experimental, char *dh_orig);
RZ_IPI bool rz_core_analysis_function_delete_var(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarKind kind, const char *id);
RZ_IPI char *rz_core_analysis_var_display(RzCore *core, RzAnalysisVar *var, bool add_name);
RZ_IPI char *rz_core_analysis_all_vars_display(RzCore *core, RzAnalysisFunction *fcn, bool add_name);
RZ_IPI bool rz_core_analysis_types_propagation(RzCore *core);
RZ_IPI bool rz_core_analysis_function_set_signature(RzCore *core, RzAnalysisFunction *fcn, const char *newsig);
RZ_IPI void rz_core_analysis_function_signature_editor(RzCore *core, ut64 addr);
RZ_IPI void rz_core_analysis_bbs_asciiart(RzCore *core, RzAnalysisFunction *fcn);
RZ_IPI void rz_core_analysis_fcn_returns(RzCore *core, RzAnalysisFunction *fcn);
RZ_IPI void rz_core_analysis_bbs_info_print(RzCore *core, RzAnalysisFunction *fcn, RzOutputMode mode);
RZ_IPI void rz_core_analysis_bb_info_print(RzCore *core, RzAnalysisBlock *bb, ut64 addr, RzOutputMode mode);
RZ_IPI void rz_core_analysis_function_until(RzCore *core, ut64 addr_end);

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

/* cdebug.c */
RZ_IPI bool rz_core_debug_reg_set(RzCore *core, const char *regname, ut64 val, const char *strval);
RZ_IPI bool rz_core_debug_reg_list(RzCore *core, int type, int size, PJ *pj, int rad, const char *use_color);
RZ_IPI void rz_core_debug_regs2flags(RzCore *core, int bits);
RZ_IPI void rz_core_regs2flags(RzCore *core);
RZ_IPI void rz_core_debug_single_step_in(RzCore *core);
RZ_IPI void rz_core_debug_single_step_over(RzCore *core);
RZ_IPI void rz_core_debug_breakpoint_toggle(RzCore *core, ut64 addr);
RZ_IPI void rz_core_debug_continue(RzCore *core);
RZ_IPI void rz_core_debug_attach(RzCore *core, int pid);

/* cfile.c */
RZ_IPI void rz_core_io_file_open(RzCore *core, int fd);
RZ_IPI void rz_core_io_file_reopen(RzCore *core, int fd, int perms);

/* cmd_eval.c */
RZ_IPI bool rz_core_load_theme(RzCore *core, const char *name);

/* cmd_seek.c */

RZ_IPI bool rz_core_seek_to_register(RzCore *core, const char *input, bool is_silent);
RZ_IPI int rz_core_seek_opcode_forward(RzCore *core, int n, bool silent);
RZ_IPI int rz_core_seek_opcode_forward(RzCore *core, int n, bool silent);
RZ_IPI int rz_core_seek_opcode(RzCore *core, int numinstr, bool silent);

/* cmd_meta.c */
RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr);

/* cmd_flag.c */
RZ_IPI void rz_core_flag_describe(RzCore *core, ut64 addr, bool strict_offset, RzOutputMode mode);
#endif
