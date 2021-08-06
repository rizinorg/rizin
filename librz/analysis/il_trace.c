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

	instruction_trace->read_mem_ops = rz_pvector_new((RzPVectorFree)free);
	instruction_trace->read_reg_ops = rz_pvector_new((RzPVectorFree)free);
	instruction_trace->write_mem_ops = rz_pvector_new((RzPVectorFree)free);
	instruction_trace->write_reg_ops = rz_pvector_new((RzPVectorFree)free);
	// TODO : handle error
	return instruction_trace;
}

RZ_API void rz_analysis_il_trace_instruction_free(RzILTraceInstruction *instruction) {
	if (instruction->write_reg_ops) {
		rz_pvector_free(instruction->write_reg_ops);
		instruction->write_reg_ops = NULL;
	}

	if (instruction->read_reg_ops) {
		rz_pvector_free(instruction->read_reg_ops);
		instruction->read_reg_ops = NULL;
	}

	if (instruction->write_mem_ops) {
		rz_pvector_free(instruction->write_mem_ops);
		instruction->write_mem_ops = NULL;
	}

	if (instruction->read_mem_ops) {
		rz_pvector_free(instruction->read_mem_ops);
		instruction->read_mem_ops = NULL;
	}

//	RZ_FREE(instruction);
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
		rz_pvector_push(trace->write_mem_ops, mem);
		trace->stats |= TRACE_INS_HAS_MEM_W;
	} else {
		rz_pvector_push(trace->read_mem_ops, mem);
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
		rz_pvector_push(trace->write_reg_ops, reg);
		trace->stats |= TRACE_INS_HAS_REG_W;
	} else {
		rz_pvector_push(trace->read_reg_ops, reg);
		trace->stats |= TRACE_INS_HAS_REG_R;
	}
}

RZ_API RzILTraceMemOp *rz_analysis_il_get_mem_op_trace(RzILTraceInstruction *trace, ut64 addr, bool is_write) {
	if (!trace) {
		return NULL;
	}

	RzPVector *mem_ops;
	RzILTraceMemOp *mem_op;
	if (is_write) {
		mem_ops = trace->write_mem_ops;
	} else {
		mem_ops = trace->read_mem_ops;
	}

	void **iter;
	rz_pvector_foreach(mem_ops, iter) {
		mem_op = *iter;
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

	RzPVector *reg_ops;
	RzILTraceRegOp *reg_op;
	if (is_write) {
		reg_ops = trace->write_reg_ops;
	} else {
		reg_ops = trace->read_reg_ops;
	}

	void **iter;
	rz_pvector_foreach(reg_ops, iter) {
		reg_op = *iter;
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
