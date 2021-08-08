// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file il_trace.c
 * \brief new rizin IL trace implementation
 *
 * provide operations to new IL trace structure to record
 * the memory changes and register changes.
 * TODO : Should be moved to librz/il after integrations with new il
 *      : should move the prototypes and trace structure to new header, too
 * prototypes in <rz_analysis.h>
 * Used by : analysis_tp.c, debug/trace.c
**/

#include <rz_util.h>
#include <rz_analysis.h>

static void free_reg_op(RzILTraceRegOp *reg_op) {
	if (reg_op) {
		if (reg_op->reg_name) {
			free(reg_op->reg_name);
		}
		RZ_FREE(reg_op);
	}
}

/**
 * create and init a trace structure for an instruction at address
 * \param addr ut64, address of instruction
 * \return RzILTraceInstruction, trace structure of an instruction
 */
RZ_API RzILTraceInstruction *rz_analysis_il_trace_instruction_new(ut64 addr) {
	RzILTraceInstruction *instruction_trace = RZ_NEW0(RzILTraceInstruction);
	if (!instruction_trace) {
		eprintf("Cannot create instruction trace\n");
		return NULL;
	}

	instruction_trace->addr = addr;

	instruction_trace->read_mem_ops = rz_pvector_new((RzPVectorFree)free);
	instruction_trace->read_reg_ops = rz_pvector_new((RzPVectorFree)free_reg_op);
	instruction_trace->write_mem_ops = rz_pvector_new((RzPVectorFree)free);
	instruction_trace->write_reg_ops = rz_pvector_new((RzPVectorFree)free_reg_op);
	// TODO : handle error
	return instruction_trace;
}

/**
 * clean an il trace
 * \param instruction RzILTraceInstruction, trace to be cleaned
 */
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

	RZ_FREE(instruction);
}

/**
 * add memory change to an instruction trace
 * \param trace RzILTraceInstruction *, trace of instruction which triggers a memory change
 * \param mem RzILTraceMemOp *, info of memory change
 */
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

/**
 * add register change to an instruction trace
 * \param trace RzILTraceInstruction *, trace of instruction which triggers a register change
 * \param mem RzILTraceRegOp *, info of register change
 */
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

/**
 * Find the memory change in an instruction by given address
 * \param trace RzILTraceInstruction *, instruction trace
 * \param addr ut64, memory address
 * \param is_write bool, true if you want to find a write operation to address, else find a read operation
 * \return RzILTraceMemOp *, info of memory change
 */
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
	rz_pvector_foreach (mem_ops, iter) {
		mem_op = *iter;
		if (mem_op->addr == addr) {
			return mem_op;
		}
	}

	return NULL;
}

/**
 * Find the register change in an instruction by register name
 * \param trace RzILTraceInstruction *, instruction trace
 * \param regname const char *, name of register
 * \param is_write bool, true if you want to find a write operation to register, else find a read operation
 * \return RzILTraceRegOp *, info of register change
 */
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
	rz_pvector_foreach (reg_ops, iter) {
		reg_op = *iter;
		if (regname == NULL) {
			return NULL;
		}
		if (strcmp(reg_op->reg_name, regname) == 0) {
			return reg_op;
		}
	}

	return NULL;
}

/**
 * Check if instruction contains a read/write to given address
 * \param trace RzILTraceInstruction *, instruction trace
 * \param addr ut64, Address of memory
 * \param is_write bool, set true to find if it contains a write to address, else read
 * \return bool, true if contains, else return a false
 */
RZ_API bool rz_analysis_il_mem_trace_contains(RzILTraceInstruction *trace, ut64 addr, bool is_write) {
	return rz_analysis_il_get_mem_op_trace(trace, addr, is_write) ? true : false;
}

/**
 * Check if instruction contains a read/write to given register
 * \param trace RzILTraceInstruction *, instruction trace
 * \param regname const char *, name of register
 * \param is_write bool, set true to find if it contains a write to the register, else read
 * \return bool, true if contains, else return a false
 */
RZ_API bool rz_analysis_il_reg_trace_contains(RzILTraceInstruction *trace, const char *regname, bool is_write) {
	return rz_analysis_il_get_reg_op_trace(trace, regname, is_write) ? true : false;
}
