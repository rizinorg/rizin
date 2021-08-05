/**
 * Il trace instruction things
 * Should be moved to librz/il after integrations
 * Used by :
 *  analysis_tp.c
 *  debug/trace.c
**/

#include <rz_util.h>
#include <rz_analysis.h>

/* New Trace Implementation */
/* Basic */
RZ_API RzILTraceInstruction *rz_analysis_il_trace_instruction_new(ut64 addr) {
	RzILTraceInstruction *instruction_trace = RZ_NEW0(RzILTraceInstruction);
	if (!instruction_trace) {
		eprintf("Cannot create instruction trace\n");
		return NULL;
	}

	instruction_trace->addr = addr;

	instruction_trace->read_mem_ops = rz_vector_new(1, (RzVectorFree)free, NULL);
	instruction_trace->read_reg_ops = rz_vector_new(1, (RzVectorFree)free, NULL);
	instruction_trace->write_mem_ops = rz_vector_new(1, (RzVectorFree)free, NULL);
	instruction_trace->write_reg_ops = rz_vector_new(1, (RzVectorFree)free, NULL);

	// TODO : handle error
	return instruction_trace;
}

RZ_API void rz_analysis_il_trace_instruction_free(RzILTraceInstruction *instruction) {
	if (instruction->write_reg_ops) {
		rz_vector_free(instruction->write_reg_ops);
	}

	if (instruction->read_reg_ops) {
		rz_vector_free(instruction->read_reg_ops);
	}

	if (instruction->write_mem_ops) {
		rz_vector_free(instruction->write_mem_ops);
	}

	if (instruction->read_mem_ops) {
		rz_vector_free(instruction->read_mem_ops);
	}

	RZ_FREE(instruction);
}

/* Trace operations */
RZ_API void rz_analysis_il_trace_add_mem(RzILTraceInstruction *trace, RzILTraceMemOp *mem) {
	if (!trace || !mem) {
		return;
	}

	int is_write = mem->behavior;
	if (rz_analysis_il_mem_trace_contains(trace, mem->addr, is_write)) {
		return;
	}

	if (is_write) {
		rz_vector_push(trace->write_mem_ops, mem);
		trace->stats |= TRACE_INS_HAS_MEM_W;
	} else {
		rz_vector_push(trace->read_mem_ops, mem);
		trace->stats |= TRACE_INS_HAS_MEM_R;
	}
}

RZ_API void rz_analysis_il_trace_add_reg(RzILTraceInstruction *trace, RzILTraceRegOp *reg) {
	if (!trace || !reg) {
		return;
	}

	int is_write = reg->behavior;
	if (rz_analysis_il_reg_trace_contains(trace, reg->reg_name, is_write)) {
		return;
	}

	if (is_write) {
		rz_vector_push(trace->write_reg_ops, reg);
		trace->stats |= TRACE_INS_HAS_REG_W;
	} else {
		rz_vector_push(trace->read_reg_ops, reg);
		trace->stats |= TRACE_INS_HAS_REG_R;
	}
}

RZ_API RzILTraceMemOp *rz_analysis_il_get_mem_op_trace(RzILTraceInstruction *trace, ut64 addr, bool is_write) {
	if (!trace) {
		return NULL;
	}

	RzVector *mem_ops;
	RzILTraceMemOp *mem_op;
	if (is_write) {
		mem_ops = trace->write_mem_ops;
	} else {
		mem_ops = trace->read_mem_ops;
	}

	rz_vector_foreach(mem_ops, mem_op) {
		if (mem_op->addr == addr) {
			return mem_op;
		}
	}

	return NULL;
}

RZ_API RzILTraceRegOp *rz_analysis_il_get_reg_op_trace(RzILTraceInstruction *trace, const char *regname, bool is_write) {
	if (!trace) {
		return NULL;
	}

	RzVector *reg_ops;
	RzILTraceRegOp *reg_op;
	if (is_write) {
		reg_ops = trace->write_reg_ops;
	} else {
		reg_ops = trace->read_reg_ops;
	}

	rz_vector_foreach(reg_ops, reg_op) {
		if (strcmp(reg_op->reg_name, regname) == 0) {
			return reg_op;
		}
	}

	return NULL;
}

RZ_API bool rz_analysis_il_mem_trace_contains(RzILTraceInstruction *trace, ut64 addr, bool is_write) {
	return rz_analysis_il_get_mem_op_trace(trace, addr, is_write) ? true : false;
}

RZ_API bool rz_analysis_il_reg_trace_contains(RzILTraceInstruction *trace, const char *regname, bool is_write) {
	return rz_analysis_il_get_reg_op_trace(trace, regname, is_write) ? true : false;
}
