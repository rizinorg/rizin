// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

/**
 * Create an empty RzAnalysisRzil instance
 * inner VM should be init in adaptive plugin
 * \return RzAnalysisRzil* a pointer to RzAnalysisRzil instance
 */
RZ_API RzAnalysisRzil *rz_analysis_rzil_new() {
	RzAnalysisRzil *rzil = RZ_NEW0(RzAnalysisRzil);
	if (!rzil) {
		return NULL;
	}
	rzil->vm = RZ_NEW0(struct rz_il_vm_t);
	if (!rzil->vm) {
		free(rzil);
		return NULL;
	}
	return rzil;
}

/**
 * Cleanup rzil instance : clean VM, clean arch-specific user_data, and rzil itself
 * \param analysis pointer to rizin's RzAnalysis
 * \param rzil pointer to RzAnalysisRzil
 */
RZ_API void rz_analysis_rzil_cleanup(RzAnalysis *analysis, RzAnalysisRzil *rzil) {
	if (!rzil) {
		eprintf("uninitialized rzil\n");
		return;
	}
	if (analysis && analysis->cur && analysis->cur->rzil_fini) {
		analysis->cur->rzil_fini(analysis);
	}
	free(rzil);
	analysis->rzil = NULL;
}

/**
 * Set pc of rzil
 * \param rzil RzAnalysis* pointer to RzAnalysisRzil instance
 * \param addr ut64 address of new pc
 * \return true if set successfully, else return false
 */
RZ_API bool rz_analysis_rzil_set_pc(RzAnalysisRzil *rzil, ut64 addr) {
	if (rzil) {
		rzil->pc_addr = addr;
		return true;
	}
	return false;
}

/**
 * Init an empty rzil
 * \param analysis RzAnalysis* pointer to RzAnalysis
 * \param rzil RzAnalysisRzil* pointer to RzAnalysisRzil
 * \param romem int is read only mem ?
 * \param stats int use stats ?
 * \param nonull int is pc cannot be null ?
 * \return true if setup, else return false
 */
RZ_API bool rz_analysis_rzil_setup(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, false);

	RzAnalysisRzil *rzil = rz_analysis_rzil_new();
	if (!rzil) {
		return false;
	}
	analysis->rzil = rzil;

	// init RZIL according to different archs
	if (analysis->cur && analysis->cur->rzil_init) {
		analysis->cur->rzil_init(analysis);
	}

	return true;
}

/**
 * Set op at address in VM
 * \param rzil RzAnalysisRzil* pointer to RzAnalysisRzil
 * \param addr ut64 address of current pc
 * \param oplist RzPvector* vector of core theory opcodes
 */
RZ_API void rz_analysis_set_rzil_op(RzAnalysisRzil *rzil, ut64 addr, RzPVector *oplist) {
	if (!rzil) {
		eprintf("uninitialized rzil, cannot set op\n");
		return;
	}
	RzILBitVector bv_addr = rz_il_ut64_addr_to_bv(addr);
	rz_il_vm_store_opcodes_to_addr(rzil->vm, bv_addr, oplist);
	rz_il_free_bv_addr(bv_addr);
}

static void rz_analysis_rzil_parse_pvector(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisRzilOp *ops) {
	rz_return_if_fail(analysis && rzil);

	// RZIL disabled
	if (!ops) {
		return;
	}

	RzILVM vm = rzil->vm;
	RzPVector *op_list = ops->ops;

	if (!ops->ops) {
		return;
	}

	// 1. step exec the op
	rz_il_vm_list_step(vm, op_list);

	// 2. call trace to collect trace info
	rz_analysis_rzil_trace_op(analysis, rzil, ops);

	// 3. call stats to collect stats info
	rz_analysis_rzil_record_stats(analysis, rzil, ops);

	// 4. clean the temp
	rz_il_clean_temps(vm);
}

/**
 * Collect both `trace` and `stats` info of an instruction
 * \param analysis
 * \param rzil
 * \param op
 */
RZ_API void rz_analysis_rzil_collect_info(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisOp *op, bool use_new) {
	rz_return_if_fail(analysis && rzil && op);
	if (use_new) {
		RZ_LOG_ERROR("TODO : New Op Structure\n");
		return;
	}

	if (!rzil->trace) {
		rzil->trace = rz_analysis_rzil_trace_new(analysis, rzil);
		if (!rzil->trace) {
			RZ_LOG_ERROR("Unable to init RZIL trace\n");
			return;
		}
	}

	// TODO : add restore as esil_trace_op did
	if (rzil->trace->idx != rzil->trace->end_idx) {
		RZ_LOG_DEBUG("Restore WIP\n");
		return;
	}

	// Debug Only
	//	const char *charset = "[]<>+-,.";
	//	if (op->id > 0) {
	//		printf("op : {%c}\n", charset[op->id - 1]);
	//	}

	// Create instruction trace for current instruction
	RzILTraceInstruction *instruction = rz_analysis_il_trace_instruction_new(op->addr);
	rz_pvector_push(rzil->trace->instructions, instruction);
	rzil->trace->idx++;
	rzil->trace->end_idx++;

	// TODO : Add register change for sync with analysis->register

	// Parse and emulate RZIL opcode, and collect `trace` and `stats` info
	rz_analysis_rzil_parse_pvector(analysis, rzil, op->rzil_op);
}
