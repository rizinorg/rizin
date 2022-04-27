// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

/**
 * Create an empty RzAnalysisRzil instance
 * inner VM should be init in adaptive plugin
 * \return RzAnalysisRzil* a pointer to RzAnalysisRzil instance
 */
RZ_API RZ_OWN RzAnalysisRzil *rz_analysis_rzil_new() {
	RzAnalysisRzil *rzil = RZ_NEW0(RzAnalysisRzil);
	if (!rzil) {
		return NULL;
	}
	rzil->vm = RZ_NEW0(RzILVM);
	if (!rzil->vm) {
		free(rzil);
		return NULL;
	}
	return rzil;
}

/**
 * Frees an RzAnalysisRzil instance
 */
RZ_API void rz_analysis_rzil_free(RZ_NULLABLE RzAnalysisRzil *rzil) {
	if (!rzil) {
		return;
	}
	rz_il_vm_free(rzil->vm);
	rz_buf_free(rzil->io_buf);
	free(rzil);
}

/**
 * Cleanup RZIL instance : clean VM, clean arch-specific user_data, and RZIL itself
 * \param analysis pointer to rizin's RzAnalysis
 */
RZ_API void rz_analysis_rzil_cleanup(RzAnalysis *analysis) {
	rz_return_if_fail(analysis);
	if (!analysis->rzil) {
		return;
	}
	if (analysis->cur && analysis->cur->rzil_fini) {
		analysis->cur->rzil_fini(analysis);
	}
	rz_analysis_rzil_free(analysis->rzil); // need to get rid of rzil even if we don't have callbacks
	analysis->rzil = NULL;
}

/**
 * Set instruction pointer for the current RZIL VM session
 * \param rzil RzAnalysis* pointer to RzAnalysisRzil instance
 * \param addr ut64 address of new pc
 * \return true if set successfully, else return false
 */
RZ_API bool rz_analysis_rzil_set_pc(RzAnalysisRzil *rzil, ut64 addr) {
	if (!rzil) {
		return false;
	}
	rzil->pc_addr = addr;
	return true;
}

static void setup_regs(RzAnalysis *a, RzAnalysisRzil *rzil) {
	if (!a->cur->get_reg_profile) {
		return;
	}
	// Explicitly use a new reg here!
	// The a->reg might be changed by the user, but plugins expect exactly
	// the register profile they supplied. Syncing will later adjust the register
	// contents if necessary.
	RzReg *reg = rz_reg_new();
	if (!reg) {
		return;
	}
	char *profile = a->cur->get_reg_profile(a);
	if (!profile) {
		goto new_real;
	}
	bool succ = rz_reg_set_profile_string(reg, profile);
	free(profile);
	if (!succ) {
		goto new_real;
	}
	// for now, we always derive the bound automatically,
	// but manual binding dictated by the plugin would be plausible too
	// in the future.
	RzILRegBinding *rb = rz_il_reg_binding_derive(reg);
	if (!rb) {
		goto new_real;
	}
	rz_il_vm_setup_reg_binding(rzil->vm, rb);
new_real:
	rz_reg_free(reg);
	return;
}

/**
 * Init an empty RZIL
 * \param analysis RzAnalysis* pointer to RzAnalysis
 * \return true if setup, else return false
 */
RZ_API bool rz_analysis_rzil_setup(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && !analysis->rzil, false);
	if (!analysis->cur || !analysis->cur->rzil_init) {
		return false;
	}

	RzAnalysisRzil *rzil = rz_analysis_rzil_new();
	if (!rzil) {
		return false;
	}
	rzil->io_buf = rz_buf_new_with_io(&analysis->iob);
	analysis->rzil = rzil;
	analysis->cur->rzil_init(analysis);
	setup_regs(analysis, rzil);
	return true;
}

static void rz_analysis_rzil_parse_root(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisRzilOp *ops) {
	rz_return_if_fail(analysis && rzil);

	// RZIL disabled
	if (!ops) {
		return;
	}

	// 1. step exec the op
	// 2. call trace to collect trace info
	// 3. call stats to collect stats info
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

	// Create instruction trace for current instruction
	RzILTraceInstruction *instruction = rz_analysis_il_trace_instruction_new(op->addr);
	rz_pvector_push(rzil->trace->instructions, instruction);
	rzil->trace->idx++;
	rzil->trace->end_idx++;

	// TODO : Add register change for sync with analysis->register

	// Parse and emulate RZIL opcode, and collect `trace` and `stats` info
	// Use new op struct for parsing
	rz_analysis_rzil_parse_root(analysis, rzil, op->rzil_op);
}
