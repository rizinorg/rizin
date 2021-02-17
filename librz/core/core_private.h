#ifndef RZ_CORE_PRIVATE_INCLUDE_H_
#define RZ_CORE_PRIVATE_INCLUDE_H_

#include <rz_types.h>
#include <rz_core.h>

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val);
RZ_IPI void rz_core_analysis_esil_init(RzCore *core);
RZ_IPI void rz_core_analysis_esil_init_mem_del(RzCore *core, const char *name, ut64 addr, ut32 size);
RZ_IPI void rz_core_analysis_esil_init_mem(RzCore *core, const char *name, ut64 addr, ut32 size);
RZ_IPI void rz_core_analysis_esil_init_mem_p(RzCore *core);
RZ_IPI void rz_core_analysis_esil_init_regs(RzCore *core);
RZ_IPI bool rz_core_analysis_var_rename(RzCore *core, const char *name, const char *newname);
RZ_IPI void rz_core_analysis_calling_conventions_print(RzCore *core);
RZ_IPI char *rz_core_analysis_function_signature(RzCore *core, RzOutputMode mode, char *fcn_name);
RZ_IPI bool rz_core_analysis_everything(RzCore *core, bool experimental, char *dh_orig);
RZ_IPI bool rz_core_analysis_function_delete_var(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarKind kind, const char *id);
RZ_IPI char *rz_core_analysis_var_display(RzCore *core, RzAnalysisVar *var, bool add_name);
RZ_IPI char *rz_core_analysis_all_vars_display(RzCore *core, RzAnalysisFunction *fcn, bool add_name);

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
#endif
