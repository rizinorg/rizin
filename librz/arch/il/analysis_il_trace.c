// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

/**
 * IL trace should also these info
 * 1. mem.read address & data
 * 2. mem.write address & data
 * 3. reg.read name & data
 * 4. reg.write name & data
 **/

/**
 * Create a new trace to collect infos
 * \param analysis pointer to RzAnalysis
 * \param rzil RZ_IL instance
 * \return pointer to RzilTrace
 */
RZ_API RzAnalysisRzilTrace *rz_analysis_rzil_trace_new(RzAnalysis *analysis, RZ_NONNULL RzAnalysisILVM *rzil) {
	rz_return_val_if_fail(rzil, NULL);
	size_t i;
	RzAnalysisEsilTrace *trace = RZ_NEW0(RzAnalysisEsilTrace);
	if (!trace) {
		return NULL;
	}

	// TODO : maybe we could remove memory && register in rzil trace ?
	trace->registers = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!trace->registers) {
		RZ_LOG_ERROR("rzil: Cannot allocate hasmap for trace registers\n");
		goto error;
	}
	trace->memory = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!trace->memory) {
		RZ_LOG_ERROR("rzil: Cannot allocate hasmap for trace memory\n");
		goto error;
	}
	trace->instructions = rz_pvector_new((RzPVectorFree)rz_analysis_il_trace_instruction_free);
	if (!trace->instructions) {
		RZ_LOG_ERROR("rzil: Cannot allocate vector for trace instructions\n");
		goto error;
	}

	// TODO : Integrate with stack panel in the future

	// Save initial registers arenas
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = analysis->reg->regset[i].arena;
		RzRegArena *b = rz_reg_arena_new(a->size);
		if (!b) {
			RZ_LOG_ERROR("rzil: Cannot allocate register arena for trace\n");
			goto error;
		}
		if (b->bytes && a->bytes && b->size > 0) {
			memcpy(b->bytes, a->bytes, b->size);
		}
		trace->arena[i] = b;
	}
	return trace;
error:
	rz_analysis_esil_trace_free(trace);
	return NULL;
}

/**
 * Free an IL trace
 * \param trace trace to be free
 */
RZ_API void rz_analysis_rzil_trace_free(RzAnalysisEsilTrace *trace) {
	size_t i;
	if (!trace) {
		return;
	}

	ht_up_free(trace->registers);
	ht_up_free(trace->memory);
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_reg_arena_free(trace->arena[i]);
	}
	rz_pvector_free(trace->instructions);
	trace->instructions = NULL;
	RZ_FREE(trace);
}

/**
 * This function should be called after executing the IL op
 * Collect trace info (target and data of mem/reg read/write)
 * \param analysis RzAnalysis
 * \param rzil IL instance
 * \param op RzAnalysisRzilOp, a general IL op structure (Designed for switching between different implementations of IL op struct)
 */
RZ_API void rz_analysis_rzil_trace_op(RzAnalysis *analysis, RZ_NONNULL RzAnalysisILVM *rzil, RZ_NONNULL RzAnalysisLiftedILOp op) {
	// TODO : rewrite this file when migrate to new op structure
}
