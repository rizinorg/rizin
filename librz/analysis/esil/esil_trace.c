// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2015-2020 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#define CMP_REG_CHANGE(x, y) ((x) - ((RzAnalysisEsilRegChange *)(y))->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((RzAnalysisEsilMemChange *)(y))->idx)

static int ocbs_set = false;
static RzAnalysisEsilCallbacks ocbs = { 0 };

// il trace wrapper of esil
static inline void esil_add_mem_trace(RzAnalysisEsilTrace *etrace, RzILTraceMemOp *mem) {
	RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(etrace, etrace->idx);
	rz_analysis_il_trace_add_mem(instr_trace, mem);
}

static inline void esil_add_reg_trace(RzAnalysisEsilTrace *etrace, RzILTraceRegOp *reg) {
        RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(etrace, etrace->idx);
        rz_analysis_il_trace_add_reg(instr_trace, reg);
}

static void htup_vector_free(HtUPKv *kv) {
	rz_vector_free(kv->value);
}

RZ_API RzAnalysisEsilTrace *rz_analysis_esil_trace_new(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil && esil->stack_addr && esil->stack_size, NULL);
	size_t i;
	RzAnalysisEsilTrace *trace = RZ_NEW0(RzAnalysisEsilTrace);
	if (!trace) {
		return NULL;
	}
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
	// Save initial ESIL stack memory
	trace->stack_addr = esil->stack_addr;
	trace->stack_size = esil->stack_size;
	trace->stack_data = malloc(esil->stack_size);
	if (!trace->stack_data) {
		goto error;
	}
	esil->analysis->iob.read_at(esil->analysis->iob.io, trace->stack_addr,
		trace->stack_data, trace->stack_size);
	// Save initial registers arenas
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = esil->analysis->reg->regset[i].arena;
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

RZ_API void rz_analysis_esil_trace_free(RzAnalysisEsilTrace *trace) {
	size_t i;
	if (trace) {
		ht_up_free(trace->registers);
		ht_up_free(trace->memory);
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_reg_arena_free(trace->arena[i]);
		}
		free(trace->stack_data);
		if (trace->instructions) {
                        rz_pvector_free(trace->instructions);
			trace->instructions = NULL;
                }
		RZ_FREE(trace);
	}
}

static void add_reg_change(RzAnalysisEsilTrace *trace, int idx, RzRegItem *ri, ut64 data) {
	ut64 addr = ri->offset | (ri->arena << 16);
	RzVector *vreg = ht_up_find(trace->registers, addr, NULL);
	if (!vreg) {
		vreg = rz_vector_new(sizeof(RzAnalysisEsilRegChange), NULL, NULL);
		if (!vreg) {
			eprintf("Error: creating a register vector.\n");
			return;
		}
		ht_up_insert(trace->registers, addr, vreg);
	}
	RzAnalysisEsilRegChange reg = { idx, data };
	rz_vector_push(vreg, &reg);
}

static void add_mem_change(RzAnalysisEsilTrace *trace, int idx, ut64 addr, ut8 data) {
	RzVector *vmem = ht_up_find(trace->memory, addr, NULL);
	if (!vmem) {
		vmem = rz_vector_new(sizeof(RzAnalysisEsilMemChange), NULL, NULL);
		if (!vmem) {
			eprintf("Error: creating a memory vector.\n");
			return;
		}
		ht_up_insert(trace->memory, addr, vmem);
	}
	RzAnalysisEsilMemChange mem = { idx, data };
	rz_vector_push(vmem, &mem);
}

static int trace_hook_reg_read(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	if (*name == '0') {
		//eprintf ("Register not found in profile\n");
		return 0;
	}
	if (ocbs.hook_reg_read) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_reg_read(esil, name, res, size);
		esil->cb = cbs;
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read(esil, name, res, size);
	}
	if (ret) {
		// Trace reg read behavior
		RzILTraceRegOp *reg_read = RZ_NEW0(RzILTraceRegOp);
		reg_read->reg_name = (char *)name;
		reg_read->behavior = TRACE_READ;
		reg_read->value = *res;
		esil_add_reg_trace(esil->trace, reg_read);
	}
	return ret;
}

static int trace_hook_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	int ret = 0;

	// add reg write to trace
	RzILTraceRegOp *reg_write = RZ_NEW0(RzILTraceRegOp);
	reg_write->reg_name = (char *)name;
	reg_write->behavior = TRACE_WRITE;
	reg_write->value = *val;
	esil_add_reg_trace(esil->trace, reg_write);

	RzRegItem *ri = rz_reg_get(esil->analysis->reg, name, -1);
	add_reg_change(esil->trace, esil->trace->idx + 1, ri, *val);
	if (ocbs.hook_reg_write) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_reg_write(esil, name, val);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	char *hexbuf = calloc((1 + len), 4);
	int ret = 0;
	if (esil->cb.mem_read) {
		ret = esil->cb.mem_read(esil, addr, buf, len);
	}

	// convert data to ut64
	// FIXME : a better way to convert between them or change the argument
	rz_hex_bin2str(buf, len, hexbuf);
	ut64 val = strtol(hexbuf, NULL, 16);

	// Trace memory read behavior
	RzILTraceMemOp *mem_read = RZ_NEW0(RzILTraceMemOp);
	mem_read->value = val;
	mem_read->behavior = TRACE_READ;
	mem_read->addr = addr;
	esil_add_mem_trace(esil->trace, mem_read);

	free(hexbuf);

	if (ocbs.hook_mem_read) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_mem_read(esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	size_t i;
	int ret = 0;
	char *hexbuf = malloc((1 + len) * 3);

        // convert data to ut64
        // FIXME : a better way to convert between them or change the argument
        rz_hex_bin2str(buf, len, hexbuf);
	ut64 val = strtol(hexbuf, NULL, 16);

        // Trace memory read behavior
        RzILTraceMemOp *mem_write = RZ_NEW0(RzILTraceMemOp);
        mem_write->value = val;
        mem_write->behavior = TRACE_WRITE;
        mem_write->addr = addr;
        esil_add_mem_trace(esil->trace, mem_write);

	// clean the hex buffer
	free(hexbuf);

	for (i = 0; i < len; i++) {
		add_mem_change(esil->trace, esil->trace->idx + 1, addr + i, buf[i]);
	}

	if (ocbs.hook_mem_write) {
		RzAnalysisEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_mem_write(esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

RZ_API RzILTraceInstruction *rz_analysis_esil_get_instruction_trace(RzAnalysisEsilTrace *etrace, int idx) {
	return rz_pvector_at(etrace->instructions, idx);
}

static void dbg_print_il_instr_trace(RzILTraceInstruction *instr, int idx) {
        if (instr) {
                printf("======== [%d] ========\n", idx);
                printf("instruction addr : %lld\n", instr->addr);
                printf("mem_read : %p\nmem_write : %p\nreg_read : %p\nreg_write : %p\n",
                       instr->read_mem_ops,
                       instr->write_mem_ops,
                       instr->read_reg_ops,
                       instr->write_reg_ops);
        }

        printf("No Instruction in [%d]\n", idx);
}

static void dbg_print_esil_trace(RzAnalysisEsilTrace *etrace) {
        if (etrace && etrace->instructions) {

		void **iter;
		RzILTraceInstruction *cur_ins;
		int i = 0;
		rz_pvector_foreach(etrace->instructions, iter) {
			cur_ins = *iter;
			dbg_print_il_instr_trace(cur_ins, i);
			++i;
		}
	}
}

RZ_API void rz_analysis_esil_trace_op(RzAnalysisEsil *esil, RzAnalysisOp *op) {
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
	if (ocbs_set) {
		eprintf("cannot call recursively\n");
	}
	ocbs = esil->cb;
	ocbs_set = true;

	RzILTraceInstruction *instruction = rz_analysis_il_trace_instruction_new(op->addr);
	rz_pvector_push(esil->trace->instructions, instruction);

	printf("Create Instruction : %p\n", instruction);

	RzILTraceInstruction *get_ins = rz_pvector_at(esil->trace->instructions, 0);
        printf("Fetched from vector : %p\n", get_ins);

	printf("Trace Op : init instruction\n");
	dbg_print_esil_trace(esil->trace);

	RzRegItem *pc_ri = rz_reg_get(esil->analysis->reg, "PC", -1);
	add_reg_change(esil->trace, esil->trace->idx, pc_ri, op->addr);
	//	sdb_set (DB, KEY ("opcode"), op->mnemonic, 0);
	//	sdb_set (DB, KEY ("addr"), expr, 0);
	//eprintf ("[ESIL] ADDR 0x%08"PFMT64x"\n", op->addr);
	//eprintf ("[ESIL] OPCODE %s\n", op->mnemonic);
	//eprintf ("[ESIL] EXPR = %s\n", expr);
	/* set hooks */
	esil->verbose = 0;
	esil->cb.hook_reg_read = trace_hook_reg_read;
	esil->cb.hook_reg_write = trace_hook_reg_write;
	esil->cb.hook_mem_read = trace_hook_mem_read;
	esil->cb.hook_mem_write = trace_hook_mem_write;

        printf("Trace Op : Before Parse\n");
        dbg_print_esil_trace(esil->trace);

        /* evaluate esil expression */
	rz_analysis_esil_parse(esil, expr);
	rz_analysis_esil_stack_free(esil);
	/* restore hooks */
	esil->cb = ocbs;
	ocbs_set = false;
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

static void print_instructino_trace(RzILTraceInstruction *instruction) {
	printf("instruction addr -> %lld\n", instruction->addr);
}

RZ_API void rz_analysis_esil_trace_list(RzAnalysisEsil *esil) {
	if (!esil->trace) {
		return;
	}

	RzILTraceInstruction *instruction_trace;
	void **iter;
	rz_pvector_foreach(esil->trace->instructions, iter) {
		instruction_trace = *iter;
		print_instructino_trace(instruction_trace);
	}
}

RZ_API void rz_analysis_esil_trace_show(RzAnalysisEsil *esil, int idx) {
	printf("Trace Show : WIP\n");

	if (!esil->trace) {
		return;
	}

	RzILTraceInstruction *instruction = rz_pvector_at(esil->trace->instructions, idx);
	if (!instruction) {
		printf("Invalid trace id : %d\n", idx);
	}

	print_instructino_trace(instruction);
}
