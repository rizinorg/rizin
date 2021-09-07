// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

// TODO : rewrite this file when migrate to new op structure

/**
 * In ESIL, stats is used to collect these info :
 * 1: ops.list : ESIL op
 * 2: flg.read : List<flag> list of flag been read from
 * 3: flg.write : List<flag> list of flags been written to
 * 4: mem.read : List<memory address> list of memory address
 * 5: mem.write : List<memory address> list of memory address
 * 6: reg.read : List<register names> list of register names
 * 7: reg.write : List<register names> list of register names
 * These infos seems be used in `cmd_search_rop.c` only
 *
 * In the New IL, we should have the similar behavior at first
 *
 * CHECK_ME : flag read and write never been called in ESIL ??
*/

static bool is_flag_reg(RzAnalysis *analysis, const char *reg_name) {
	return false;
}

static char *opcode_to_str(RzILOPCode opcode) {
	return "OP_NOP";
}

static void stats_add_mem(RzAnalysisRzil *rzil, ut64 addr, RzILTraceOpType type) {
	switch (type) {
	case RZ_IL_TRACE_OP_WRITE:
		sdb_array_add_num(rzil->stats, "mem.write", addr, 0);
		break;
	case RZ_IL_TRACE_OP_READ:
		sdb_array_add_num(rzil->stats, "mem.read", addr, 0);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void stats_add_reg(RzAnalysisRzil *rzil, const char *regname, RzILTraceOpType type) {
	switch (type) {
	case RZ_IL_TRACE_OP_WRITE:
		sdb_array_add(rzil->stats, "reg.read", regname, 0);
		break;
	case RZ_IL_TRACE_OP_READ:
		sdb_array_add(rzil->stats, "reg.write", regname, 0);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void stats_add_flg(RzAnalysisRzil *rzil, const char *flg, RzILTraceOpType type) {
	switch (type) {
	case RZ_IL_TRACE_OP_WRITE:
		sdb_array_add(rzil->stats, "flg.read", flg, 0);
		break;
	case RZ_IL_TRACE_OP_READ:
		sdb_array_add(rzil->stats, "flg.write", flg, 0);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void stats_parse_and_add_flgs() {
	eprintf("TODO : parse and add flgs\n");
	stats_add_flg(NULL, NULL, RZ_IL_TRACE_OP_WRITE);
	stats_add_flg(NULL, NULL, RZ_IL_TRACE_OP_READ);
	rz_warn_if_reached();
	// call add flg here
}

static void stats_add_op(RzAnalysisRzil *rzil, RzILOPCode opcode) {
	const char *op_name = opcode_to_str(opcode);
	sdb_array_add(rzil->stats, "ops.list", op_name, 0);
}

static void rz_analysis_rzil_stats_focus_mem_read(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp *single_op) {
	RzILOpLoad *op_load = single_op->op.load;
	RzILVM *vm = rzil->vm;

	ut64 addr = rz_il_bv_to_ut64(rz_il_get_bv_temp(vm, op_load->key));
	stats_add_mem(rzil, addr, RZ_IL_TRACE_OP_READ);
}

static void rz_analysis_rzil_stats_focus_mem_write(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp *single_op) {
	RzILOpStore *op_store = single_op->op.store;
	RzILVM *vm = rzil->vm;

	ut64 addr = rz_il_bv_to_ut64(rz_il_get_bv_temp(vm, op_store->key));
	stats_add_mem(rzil, addr, RZ_IL_TRACE_OP_WRITE);
}

static void rz_analysis_rzil_stats_focus_reg_read(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp *single_op) {
	RzILOpVar *op_var = single_op->op.var;

	const char *reg_name = rz_str_constpool_get(&analysis->constpool, op_var->v);

	// add flag stats
	if (is_flag_reg(analysis, reg_name)) {
		stats_parse_and_add_flgs();
	}

	// add register statsst
	stats_add_reg(rzil, reg_name, RZ_IL_TRACE_OP_READ);
}

static void rz_analysis_rzil_stats_focus_reg_write(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp *single_op) {
	RzILOpSet *op_set = single_op->op.set;

	const char *reg_name = rz_str_constpool_get(&analysis->constpool, op_set->v);

	// add flag stats
	if (is_flag_reg(analysis, reg_name)) {
		stats_parse_and_add_flgs();
	}

	// add register stats
	stats_add_reg(rzil, reg_name, RZ_IL_TRACE_OP_WRITE);
}

static void rz_analysis_rzil_stats_focus(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp *single_op) {
	// focus those op only
	// flags treated as register
	stats_add_op(rzil, single_op->code);
	switch (single_op->code) {
	case RZIL_OP_LOAD:
		rz_analysis_rzil_stats_focus_mem_read(analysis, rzil, single_op);
		break;
	case RZIL_OP_STORE:
		rz_analysis_rzil_stats_focus_mem_write(analysis, rzil, single_op);
		break;
	case RZIL_OP_SET:
		rz_analysis_rzil_stats_focus_reg_write(analysis, rzil, single_op);
		break;
	case RZIL_OP_VAR:
		rz_analysis_rzil_stats_focus_reg_read(analysis, rzil, single_op);
		break;
	default:
		// don't need to trace info
		break;
	}
}

/**
 * Record memory R/W address, register R/W names. similar to `trace`
 * \param analysis RzAnalysis
 * \param rzil RZIL instance
 * \param op  a general RZIL op structure (Designed for switching between different implementations of RZIL op struct)
 */
RZ_API void rz_analysis_rzil_record_stats(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisRzilOp *op) {
	RzPVector *op_list = op->ops;

	void **iter;
	rz_pvector_foreach (op_list, iter) {
		RzILOp *single_op = *iter;
		rz_analysis_rzil_stats_focus(analysis, rzil, single_op);
	}
}
