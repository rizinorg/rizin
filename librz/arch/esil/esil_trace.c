// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2015-2020 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#define CMP_REG_CHANGE(x, y) ((x) - ((RzAnalysisEsilRegChange *)(y))->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((RzAnalysisEsilMemChange *)(y))->idx)

#define ESILISTATE esil->analysis->esilinterstate

// IL trace wrapper of esil
static inline bool esil_add_mem_trace(RzAnalysisEsilTrace *etrace, RzILTraceMemOp *mem) {
	RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(etrace, etrace->idx);
	return rz_analysis_il_trace_add_mem(instr_trace, mem);
}

static inline bool esil_add_reg_trace(RzAnalysisEsilTrace *etrace, RzILTraceRegOp *reg) {
	RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(etrace, etrace->idx);
	return rz_analysis_il_trace_add_reg(instr_trace, reg);
}

RZ_API RzAnalysisEsilTrace *rz_analysis_esil_trace_new(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil && esil->stack_addr && esil->stack_size, NULL);
	size_t i;
	RzAnalysisEsilTrace *trace = RZ_NEW0(RzAnalysisEsilTrace);
	if (!trace) {
		return NULL;
	}
	trace->registers = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!trace->registers) {
		RZ_LOG_ERROR("esil: Cannot allocate hashmap for trace registers\n");
		goto error;
	}
	trace->memory = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!trace->memory) {
		RZ_LOG_ERROR("esil: Cannot allocate hashmap for trace memory\n");
		goto error;
	}
	trace->instructions = rz_pvector_new((RzPVectorFree)rz_analysis_il_trace_instruction_free);
	if (!trace->instructions) {
		RZ_LOG_ERROR("esil: Cannot allocate vector for trace instructions\n");
		goto error;
	}
	// Save initial ESIL stack memory
	trace->stack_addr = esil->stack_addr;
	trace->stack_size = esil->stack_size;
	trace->stack_data = malloc(esil->stack_size);
	if (!trace->stack_data) {
		RZ_LOG_ERROR("esil: Cannot allocate stack for trace\n");
		goto error;
	}
	esil->analysis->iob.read_at(esil->analysis->iob.io, trace->stack_addr,
		trace->stack_data, trace->stack_size);
	// Save initial registers arenas
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = esil->analysis->reg->regset[i].arena;
		RzRegArena *b = rz_reg_arena_new(a->size);
		if (!b) {
			RZ_LOG_ERROR("esil: Cannot allocate register arena for trace\n");
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

RZ_API void rz_analysis_esil_trace_free(RzAnalysisEsilTrace *trace) {
	if (!trace) {
		return;
	}
	size_t i;
	ht_up_free(trace->registers);
	ht_up_free(trace->memory);
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_reg_arena_free(trace->arena[i]);
	}
	free(trace->stack_data);
	rz_pvector_free(trace->instructions);
	trace->instructions = NULL;
	RZ_FREE(trace);
}

static void add_reg_change(RzAnalysisEsilTrace *trace, int idx, RzRegItem *ri, ut64 data) {
	ut64 addr = ri->offset | (ri->arena << 16);
	RzVector *vreg = ht_up_find(trace->registers, addr, NULL);
	if (!vreg) {
		vreg = rz_vector_new(sizeof(RzAnalysisEsilRegChange), NULL, NULL);
		if (!vreg) {
			RZ_LOG_ERROR("Creating a register vector.\n");
			return;
		}
		ht_up_insert(trace->registers, addr, vreg, NULL);
	}
	RzAnalysisEsilRegChange reg = { idx, data };
	rz_vector_push(vreg, &reg);
}

static void add_mem_change(RzAnalysisEsilTrace *trace, int idx, ut64 addr, ut8 data) {
	RzVector *vmem = ht_up_find(trace->memory, addr, NULL);
	if (!vmem) {
		vmem = rz_vector_new(sizeof(RzAnalysisEsilMemChange), NULL, NULL);
		if (!vmem) {
			RZ_LOG_ERROR("Creating a memory vector.\n");
			return;
		}
		ht_up_insert(trace->memory, addr, vmem, NULL);
	}
	RzAnalysisEsilMemChange mem = { idx, data };
	rz_vector_push(vmem, &mem);
}

static int trace_hook_reg_read(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	if (*name == '0') {
		// RZ_LOG_WARN("Register not found in profile\n");
		return 0;
	}
	if (ESILISTATE->callbacks.hook_reg_read) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ESILISTATE->callbacks;
		ret = ESILISTATE->callbacks.hook_reg_read(esil, name, res, size);
		esil->cb = cbs;
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read(esil, name, res, size);
	}
	if (ret) {
		// Trace reg read behavior
		RzILTraceRegOp *reg_read = RZ_NEW0(RzILTraceRegOp);
		if (!reg_read) {
			RZ_LOG_ERROR("failed to init reg read trace\n");
			return 0;
		}
		reg_read->reg_name = rz_str_constpool_get(&esil->analysis->constpool, name);
		reg_read->behavior = RZ_IL_TRACE_OP_READ;
		reg_read->value = *res;
		if (!esil_add_reg_trace(esil->trace, reg_read)) {
			RZ_FREE(reg_read);
		}
	}
	return ret;
}

static int trace_hook_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	int ret = 0;

	// add reg write to trace
	RzILTraceRegOp *reg_write = RZ_NEW0(RzILTraceRegOp);
	if (!reg_write) {
		RZ_LOG_ERROR("failed to init reg write\n");
		return ret;
	}
	reg_write->reg_name = rz_str_constpool_get(&esil->analysis->constpool, name);
	reg_write->behavior = RZ_IL_TRACE_OP_WRITE;
	reg_write->value = *val;
	if (!esil_add_reg_trace(esil->trace, reg_write)) {
		RZ_FREE(reg_write);
	}

	RzRegItem *ri = rz_reg_get(esil->analysis->reg, name, -1);
	add_reg_change(esil->trace, esil->trace->idx + 1, ri, *val);
	if (ESILISTATE->callbacks.hook_reg_write) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ESILISTATE->callbacks;
		ret = ESILISTATE->callbacks.hook_reg_write(esil, name, val);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	int ret = 0;
	if (esil->cb.mem_read) {
		ret = esil->cb.mem_read(esil, addr, buf, len);
	}

	// Trace memory read behavior
	RzILTraceMemOp *mem_read = RZ_NEW0(RzILTraceMemOp);
	if (!mem_read) {
		RZ_LOG_ERROR("fail to init memory read trace\n");
		return 0;
	}

	if (len > sizeof(mem_read->data_buf)) {
		RZ_LOG_ERROR("read memory more than 32 bytes, cannot trace\n");
		RZ_FREE(mem_read);
		return 0;
	}

	rz_mem_copy(mem_read->data_buf, sizeof(mem_read->data_buf), buf, len);
	mem_read->data_len = len;
	mem_read->behavior = RZ_IL_TRACE_OP_READ;
	mem_read->addr = addr;
	if (!esil_add_mem_trace(esil->trace, mem_read)) {
		RZ_FREE(mem_read);
	}

	if (ESILISTATE->callbacks.hook_mem_read) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ESILISTATE->callbacks;
		ret = ESILISTATE->callbacks.hook_mem_read(esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	size_t i;
	int ret = 0;

	// Trace memory read behavior
	RzILTraceMemOp *mem_write = RZ_NEW0(RzILTraceMemOp);
	if (!mem_write) {
		RZ_LOG_ERROR("fail to init memory write trace\n");
		return 0;
	}

	if (len > sizeof(mem_write->data_buf)) {
		RZ_LOG_ERROR("write memory more than 32 bytes, cannot trace\n");
		RZ_FREE(mem_write);
		return 0;
	}

	rz_mem_copy(mem_write->data_buf, sizeof(mem_write->data_buf), buf, len);
	mem_write->data_len = len;
	mem_write->behavior = RZ_IL_TRACE_OP_WRITE;
	mem_write->addr = addr;
	if (!esil_add_mem_trace(esil->trace, mem_write)) {
		RZ_FREE(mem_write);
	}

	for (i = 0; i < len; i++) {
		add_mem_change(esil->trace, esil->trace->idx + 1, addr + i, buf[i]);
	}

	if (ESILISTATE->callbacks.hook_mem_write) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ESILISTATE->callbacks;
		ret = ESILISTATE->callbacks.hook_mem_write(esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

/**
 * Get instruction trace from ESIL trace by index
 * \param etrace RzAnalysisEsilTrace *, ESIL trace
 * \param idx int, index of instruction
 * \return RzILTraceInstruction *, instruction trace at index
 */
RZ_API RZ_BORROW RzILTraceInstruction *rz_analysis_esil_get_instruction_trace(RZ_NONNULL RzAnalysisEsilTrace *etrace, int idx) {
	rz_return_val_if_fail(etrace, NULL);
	if (idx < 0 || idx >= rz_pvector_len(etrace->instructions)) {
		return NULL;
	}
	return rz_pvector_at(etrace->instructions, idx);
}

RZ_API void rz_analysis_esil_trace_op(RzAnalysisEsil *esil, RZ_NONNULL RzAnalysisOp *op) {
	rz_return_if_fail(esil && op);
	const char *expr = rz_strbuf_get(&op->esil);
	if (RZ_STR_ISEMPTY(expr)) {
		// do nothing
		return;
	}
	if (!esil->trace) {
		esil->trace = rz_analysis_esil_trace_new(esil);
		if (!esil->trace) {
			return;
		}
	}
	/* restore from trace when `idx` is not at the end */
	if (esil->trace->idx != esil->trace->end_idx) {
		rz_analysis_esil_trace_restore(esil, esil->trace->idx + 1);
		return;
	}
	/* save old callbacks */
	int esil_verbose = esil->verbose;
	if (ESILISTATE->callbacks_set) {
		RZ_LOG_ERROR("esil: Cannot call recursively\n");
	}
	ESILISTATE->callbacks = esil->cb;
	ESILISTATE->callbacks_set = true;

	RzILTraceInstruction *instruction = rz_analysis_il_trace_instruction_new(op->addr);
	rz_pvector_push(esil->trace->instructions, instruction);

	RzRegItem *pc_ri = rz_reg_get(esil->analysis->reg, "PC", -1);
	add_reg_change(esil->trace, esil->trace->idx, pc_ri, op->addr);
	/* set hooks */
	esil->verbose = 0;
	esil->cb.hook_reg_read = trace_hook_reg_read;
	esil->cb.hook_reg_write = trace_hook_reg_write;
	esil->cb.hook_mem_read = trace_hook_mem_read;
	esil->cb.hook_mem_write = trace_hook_mem_write;

	/* evaluate esil expression */
	rz_analysis_esil_parse(esil, expr);
	rz_analysis_esil_stack_free(esil);
	/* restore hooks */
	esil->cb = ESILISTATE->callbacks;
	ESILISTATE->callbacks_set = false;
	esil->verbose = esil_verbose;
	/* increment idx */
	esil->trace->idx++;
	esil->trace->end_idx++;
}

static bool restore_memory_cb(void *user, const ut64 key, const void *value) {
	size_t index;
	RzAnalysisEsil *esil = user;
	RzVector *vmem = (RzVector *)value;

	rz_vector_upper_bound(vmem, esil->trace->idx, index, CMP_MEM_CHANGE);
	if (index > 0 && index <= vmem->len) {
		RzAnalysisEsilMemChange *c = rz_vector_index_ptr(vmem, index - 1);
		esil->analysis->iob.write_at(esil->analysis->iob.io, key, &c->data, 1);
	}
	return true;
}

static bool restore_register(RzAnalysisEsil *esil, RzRegItem *ri, int idx) {
	size_t index;
	RzVector *vreg = ht_up_find(esil->trace->registers, ri->offset | (ri->arena << 16), NULL);
	if (vreg) {
		rz_vector_upper_bound(vreg, idx, index, CMP_REG_CHANGE);
		if (index > 0 && index <= vreg->len) {
			RzAnalysisEsilRegChange *c = rz_vector_index_ptr(vreg, index - 1);
			rz_reg_set_value(esil->analysis->reg, ri, c->data);
		}
	}
	return true;
}

RZ_API void rz_analysis_esil_trace_restore(RzAnalysisEsil *esil, int idx) {
	rz_return_if_fail(esil);
	size_t i;
	RzAnalysisEsilTrace *trace = esil->trace;
	// Restore initial state when going backward
	if (idx < esil->trace->idx) {
		// Restore initial registers value
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			RzRegArena *a = esil->analysis->reg->regset[i].arena;
			RzRegArena *b = trace->arena[i];
			if (a && b) {
				memcpy(a->bytes, b->bytes, a->size);
			}
		}
		// Restore initial stack memory
		esil->analysis->iob.write_at(esil->analysis->iob.io, trace->stack_addr,
			trace->stack_data, trace->stack_size);
	}
	// Apply latest changes to registers and memory
	esil->trace->idx = idx;
	RzListIter *iter;
	RzRegItem *ri;
	rz_list_foreach (esil->analysis->reg->allregs, iter, ri) {
		restore_register(esil, ri, idx);
	}
	ht_up_foreach(trace->memory, restore_memory_cb, esil);
}

static void print_instruction_ops(RzILTraceInstruction *instruction, int idx, RzILTraceInsOp focus) {
	bool reg = focus == RZ_IL_TRACE_INS_HAS_REG_R || focus == RZ_IL_TRACE_INS_HAS_REG_W;
	bool read = focus == RZ_IL_TRACE_INS_HAS_REG_R || focus == RZ_IL_TRACE_INS_HAS_MEM_R;
	const char *direction = read ? "read" : "write";
	void **it;
	bool first = true;

	if (reg) {
		RzPVector *ops = read ? instruction->read_reg_ops : instruction->write_reg_ops;
		if (!rz_pvector_empty(ops)) {
			rz_cons_printf("%d.reg.%s=", idx, direction);
			rz_pvector_foreach (ops, it) {
				RzILTraceRegOp *op = (RzILTraceRegOp *)*it;
				first ? (first = false) : rz_cons_print(",");
				rz_cons_printf("%s", op->reg_name);
			}
			rz_cons_newline();
		}
		rz_pvector_foreach (ops, it) {
			RzILTraceRegOp *op = (RzILTraceRegOp *)*it;
			rz_cons_printf("%d.reg.%s.%s=%s%" PFMT64x "\n", idx, direction,
				op->reg_name, op->value < 10 ? "" : "0x", op->value);
		}
	} else {
		RzPVector *ops = read ? instruction->read_mem_ops : instruction->write_mem_ops;
		if (!rz_pvector_empty(ops)) {
			rz_cons_printf("%d.mem.%s=", idx, direction);
			rz_pvector_foreach (ops, it) {
				RzILTraceMemOp *op = (RzILTraceMemOp *)*it;
				first ? (first = false) : rz_cons_print(",");
				rz_cons_printf("0x%" PFMT64x, op->addr);
			}
			rz_cons_newline();
		}
		rz_pvector_foreach (ops, it) {
			RzILTraceMemOp *op = (RzILTraceMemOp *)*it;
			char hexstr[sizeof(op->data_buf) * 2 + 1];
			rz_hex_bin2str(op->data_buf, RZ_MIN(sizeof(op->data_buf), op->data_len), hexstr);
			rz_cons_printf("%d.mem.%s.data.0x%" PFMT64x "=%s\n", idx, direction, op->addr, hexstr);
		}
	}
}

static void print_instruction_trace(RzILTraceInstruction *instruction, int idx) {
	rz_cons_printf("%d.addr=0x%" PFMT64x "\n", idx, instruction->addr);

	// IL ops within an instruction are printed in the order reg read, mem
	// read, reg write, mem write that is partially based on x86 PUSH. This
	// print order MAY NOT be the same as the actual ops order.
	print_instruction_ops(instruction, idx, RZ_IL_TRACE_INS_HAS_REG_R);
	print_instruction_ops(instruction, idx, RZ_IL_TRACE_INS_HAS_MEM_R);
	print_instruction_ops(instruction, idx, RZ_IL_TRACE_INS_HAS_REG_W);
	print_instruction_ops(instruction, idx, RZ_IL_TRACE_INS_HAS_MEM_W);
}

/**
 * List all traces
 * \param esil RzAnalysisEsil *, ESIL instance
 */
RZ_API void rz_analysis_esil_trace_list(RzAnalysisEsil *esil) {
	rz_return_if_fail(esil);
	if (!esil->trace) {
		return;
	}

	RzILTraceInstruction *instruction_trace;
	int idx = 0;
	void **iter;
	rz_pvector_foreach (esil->trace->instructions, iter) {
		instruction_trace = *iter;
		print_instruction_trace(instruction_trace, idx);
		idx++;
	}
	rz_cons_printf("idx=%d\n", idx - 1);
}

/**
 * Display an ESIL trace at index `idx`
 * \param esil RzAnalysisEsil *, ESIL instance
 * \param idx int, index of trace
 */
RZ_API void rz_analysis_esil_trace_show(RzAnalysisEsil *esil, int idx) {
	rz_return_if_fail(esil);
	if (!esil->trace) {
		return;
	}

	RzILTraceInstruction *instruction = rz_analysis_esil_get_instruction_trace(esil->trace, idx);
	if (!instruction) {
		RZ_LOG_ERROR("Invalid trace id : %d\n", idx);
		return;
	}

	print_instruction_trace(instruction, idx);
}
