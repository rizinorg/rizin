// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

/**
 * Rzil trace should also these info
 * 1. mem.read address & data
 * 2. mem.write address & data
 * 3. reg.read name & data
 * 4. reg.write name & data
**/

const string op2str(RzILOp op) {
        char *ctops[64] = {
                "VAR",
                "UNK",
                "ITE",
                "B0",
                "B1",
                "INV",
                "AND_",
                "OR_",
                "INT",
                "MSB",
                "LSB",
                "NEG",
                "NOT",
                "ADD",
                "SUB",
                "MUL",
                "DIV",
                "SDIV",
                "MOD",
                "SMOD",
                "LOGAND",
                "LOGOR",
                "LOGXOR",
                "SHIFTR",
                "SHIFTL",
                "SLE",
                "ULE",
                "CAST",
                "CONCAT",
                "APPEND",
                "LOAD",
                "STORE",
                "PERFORM",
                "SET",
                "JMP",
                "GOTO",
                "SEQ",
                "BLK",
                "REPEAT",
                "BRANCH",
                "INVALID",
        };
        return ctops[op->code];
}

static void htup_vector_free(HtUPKv *kv) {
	rz_vector_free(kv->value);
}

RZ_API RzAnalysisRzilTrace *rz_analysis_rzil_trace_new(RzAnalysis *analysis, RzAnalysisRzil *rzil) {
	rz_return_val_if_fail(rzil && rzil->stack_addr && rzil->stack_size, NULL);
	size_t i;
	RzAnalysisEsilTrace *trace = RZ_NEW0(RzAnalysisEsilTrace);
	if (!trace) {
		return NULL;
	}

	// TODO : maybe we could remove memory && register in rzil trace ?
	trace->registers = ht_up_new(NULL, htup_vector_free, NULL);
	if (!trace->registers) {
		goto error;
	}
	trace->memory = ht_up_new(NULL, htup_vector_free, NULL);
	if (!trace->memory) {
		goto error;
	}
	trace->instructions = rz_pvector_new((RzPVectorFree)rz_analysis_il_trace_instruction_free);
	if (!trace->instructions) {
		goto error;
	}

	// TODO : Integrate with stack pannel in the future

	// Save initial registers arenas
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = analysis->reg->regset[i].arena;
		RzRegArena *b = rz_reg_arena_new(a->size);
		if (!b) {
			goto error;
		}
		if (b->bytes && a->bytes && b->size > 0) {
			memcpy(b->bytes, a->bytes, b->size);
		}
		trace->arena[i] = b;
	}
	return trace;
error:
	eprintf("error\n");
	rz_analysis_esil_trace_free(trace);
	return NULL;
}

RZ_API void rz_analysis_rzil_trace_free(RzAnalysisEsilTrace *trace) {
	size_t i;
	if (trace) {
		ht_up_free(trace->registers);
		ht_up_free(trace->memory);
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_reg_arena_free(trace->arena[i]);
		}
		rz_pvector_free(trace->instructions);
		trace->instructions = NULL;
		RZ_FREE(trace);
	}
}

// IL trace wrapper of esil
static inline void rzil_add_mem_trace(RzAnalysisRzilTrace *rtrace, RzILTraceMemOp *mem) {
	RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(rtrace, rtrace->idx);
	rz_analysis_il_trace_add_mem(instr_trace, mem);
}

static inline void rzil_add_reg_trace(RzAnalysisRzilTrace *rtrace, RzILTraceRegOp *reg) {
	RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(rtrace, rtrace->idx);
	rz_analysis_il_trace_add_reg(instr_trace, reg);
}

// buf limit 32
static void bv_to_databuf(ut8 *buf, BitVector bv) {
	rz_il_bv_prepend_zero(bv, 128 - bv->len);
	if (bv->_elem_len != 16) {
		RZ_LOG_ERROR("BAD SIZE\n");
		return;
	}
}

static void rz_analysis_rzil_trace_focus_mem_read(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp single_op) {
	RzILOpLoad op_load = single_op->op.load;

	BitVector addr = rz_il_get_bv_temp(rzil->vm, op_load->key);
	BitVector data = rz_il_get_bv_temp(rzil->vm, op_load->ret);

	if (data->len > 128) {
		RZ_LOG_ERROR("RZIL memory read more than 128 bits\n");
		return;
	}

	RzILTraceMemOp *mem_read = RZ_NEW0(RzILTraceMemOp);
	if (!mem_read) {
		RZ_LOG_ERROR("RZIL cannot init memory read trace\n");
		return;
	}
	mem_read->behavior = RZ_IL_TRACE_OP_READ;
	mem_read->addr = rz_il_bv_to_ut64(addr);
	bv_to_databuf(mem_read->data_buf, data);

	rzil_add_mem_trace(rzil->trace, mem_read);
}

static void rz_analysis_rzil_trace_focus_mem_write(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp single_op) {
	RzILOpStore op_store = single_op->op.store;

	BitVector addr = rz_il_get_bv_temp(rzil->vm, op_store->key);
	BitVector data = rz_il_get_bv_temp(rzil->vm, op_store->ret);

	if (data->len > 128) {
		RZ_LOG_ERROR("RZIL memory write more than 128 bits\n");
		return;
	}

	RzILTraceMemOp *mem_write = RZ_NEW0(RzILTraceMemOp);
	if (!mem_write) {
		RZ_LOG_ERROR("RZIL cannot init memory write trace\n");
		return;
	}
	mem_write->behavior = RZ_IL_TRACE_OP_WRITE;
	mem_write->addr = rz_il_bv_to_ut64(addr);
	bv_to_databuf(mem_write->data_buf, data);

	rzil_add_mem_trace(rzil->trace, mem_write);
}

static void rz_analysis_rzil_trace_focus_reg_read(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp single_op) {
	RzILOpVar op_var = single_op->op.var;
	RzILVM vm = rzil->vm;

	const char *reg_name = rz_str_constpool_get(&analysis->constpool, op_var->v);
	ut64 data = rz_il_bv_to_ut64(rz_il_get_bv_temp(vm, op_var->ret));

	RzILTraceRegOp *reg_read = RZ_NEW0(RzILTraceRegOp);
	if (!reg_read) {
		RZ_LOG_ERROR("RZIL cannot init register read trace\n");
		return;
	}
	reg_read->behavior = RZ_IL_TRACE_OP_READ;
	reg_read->reg_name = reg_name;
	reg_read->value = data;

	rzil_add_reg_trace(rzil->trace, reg_read);
}

static void rz_analysis_rzil_trace_focus_reg_write(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp single_op) {
	RzILOpSet op_set = single_op->op.set;
	RzILVM vm = rzil->vm;

	const char *reg_name = rz_str_constpool_get(&analysis->constpool, op_set->v);
	ut64 data = rz_il_bv_to_ut64(rz_il_get_bv_temp(vm, op_set->x));

	RzILTraceRegOp *reg_write = RZ_NEW0(RzILTraceRegOp);
	if (!reg_write) {
		RZ_LOG_ERROR("RZIL cannot init register write trace\n");
		return;
	}
	reg_write->behavior = RZ_IL_TRACE_OP_WRITE;
	reg_write->reg_name = reg_name;
	reg_write->value = data;

	rzil_add_reg_trace(rzil->trace, reg_write);
}

static void rz_analysis_rzil_trace_focus(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzILOp single_op) {
	// focus those op only
	switch (single_op->code) {
	case RZIL_OP_LOAD:
		rz_analysis_rzil_trace_focus_mem_read(analysis, rzil, single_op);
		break;
	case RZIL_OP_STORE:
		rz_analysis_rzil_trace_focus_mem_write(analysis, rzil, single_op);
		break;
	case RZIL_OP_SET:
		rz_analysis_rzil_trace_focus_reg_write(analysis, rzil, single_op);
		break;
	case RZIL_OP_VAR:
		rz_analysis_rzil_trace_focus_reg_read(analysis, rzil, single_op);
		break;
	default:
		// don't need to trace info
		break;
	}
}

/**
 * This function should be called after executing the RZIL op
 * Collect trace info (target and data of mem/reg read/write)
 * @param analysis
 * @param rzil
 * @param op
 */
RZ_API void rz_analysis_rzil_trace_op(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisRzilOp *op) {
	// TODO : rewrite this file when migrate to new op structure
	RzPVector *op_list = op->ops;

	void **iter;
	rz_pvector_foreach (op_list, iter) {
		RzILOp single_op = *iter;
		rz_analysis_rzil_trace_focus(analysis, rzil, single_op);
	}
}
