// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#include "../core_private.h"

static ut64 initializeEsil(RzCore *core) {
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int exectrap = rz_config_get_i(core->config, "esil.exectrap");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	if (!(core->analysis->esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return UT64_MAX;
	}
	ut64 addr;
	RzAnalysisEsil *esil = core->analysis->esil;
	esil->verbose = rz_config_get_i(core->config, "esil.verbose");
	esil->cmd = rz_core_esil_cmd;
	rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL); // setup io
	{
		const char *cmd_esil_step = rz_config_get(core->config, "cmd.esil.step");
		if (cmd_esil_step && *cmd_esil_step) {
			esil->cmd_step = rz_str_dup(cmd_esil_step);
		}
		const char *cmd_esil_step_out = rz_config_get(core->config, "cmd.esil.stepout");
		if (cmd_esil_step_out && *cmd_esil_step_out) {
			esil->cmd_step_out = rz_str_dup(cmd_esil_step_out);
		}
		{
			const char *s = rz_config_get(core->config, "cmd.esil.intr");
			if (s) {
				char *my = rz_str_dup(s);
				if (my) {
					rz_config_set(core->config, "cmd.esil.intr", my);
					free(my);
				}
			}
		}
	}
	esil->exectrap = exectrap;
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzPVector *entries = obj ? (RzPVector *)rz_bin_object_get_entries(obj) : NULL;
	RzBinAddr *entry = NULL;
	RzBinInfo *info = NULL;
	if (entries && !rz_pvector_empty(entries)) {
		entry = (RzBinAddr *)rz_pvector_pop_front(entries);
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		info = obj ? (RzBinInfo *)rz_bin_object_get_info(obj) : NULL;
		addr = info->has_va ? entry->vaddr : entry->paddr;
		rz_pvector_push(entries, entry);
	} else {
		addr = core->offset;
	}
	// set memory read only
	return addr;
}

RZ_API int rz_core_esil_step(RzCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver) {
#define return_tail(x) \
	{ \
		tail_return_value = x; \
		goto tail_return; \
	}
	int tail_return_value = 0;
	int ret;
	ut8 code[32];
	RzAnalysisOp op = { 0 };
	RzAnalysisEsil *esil = core->analysis->esil;
	const char *name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	ut64 addr = 0;
	bool breakoninvalid = rz_config_get_i(core->config, "esil.breakoninvalid");
	int esiltimeout = rz_config_get_i(core->config, "esil.timeout");
	ut64 startTime;

	if (esiltimeout > 0) {
		startTime = rz_time_now_mono();
	}
	rz_cons_break_push(NULL, NULL);
repeat:
	if (rz_cons_is_breaked()) {
		RZ_LOG_WARN("core: esil: emulation interrupted at 0x%08" PFMT64x "\n", addr);
		return_tail(0);
	}
	// Break if we have exceeded esil.timeout
	if (esiltimeout > 0) {
		ut64 elapsedTime = rz_time_now_mono() - startTime;
		elapsedTime >>= 20;
		if (elapsedTime >= esiltimeout) {
			RZ_LOG_WARN("core: esil: timeout exceeded.\n");
			return_tail(0);
		}
	}
	if (!esil) {
		addr = initializeEsil(core);
		esil = core->analysis->esil;
		if (!esil) {
			return_tail(0);
		}
	} else {
		esil->trap = 0;
		addr = rz_reg_getv(core->analysis->reg, name);
		// eprintf ("PC=0x%"PFMT64x"\n", (ut64)addr);
	}
	if (prev_addr) {
		*prev_addr = addr;
	}
	if (esil->exectrap) {
		if (!rz_io_is_valid_offset(core->io, addr, RZ_PERM_X)) {
			esil->trap = RZ_ANALYSIS_TRAP_EXEC_ERR;
			esil->trap_code = addr;
			RZ_LOG_ERROR("core: esil: Trap, trying to execute on non-executable memory\n");
			return_tail(1);
		}
	}
	rz_asm_set_pc(core->rasm, addr);

	(void)rz_io_read_at_mapped(core->io, addr, code, sizeof(code));
	// TODO: sometimes this is dupe
	rz_analysis_op_init(&op);
	ret = rz_analysis_op(core->analysis, &op, addr, code, sizeof(code), RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
	// if type is JMP then we execute the next N instructions
	// update the esil pointer because RzAnalysis.op() can change it
	esil = core->analysis->esil;
	if (op.size < 1 || ret < 1) {
		if (esil->cmd && esil->cmd_trap) {
			esil->cmd(esil, esil->cmd_trap, addr, RZ_ANALYSIS_TRAP_INVALID);
		}
		if (breakoninvalid) {
			RZ_LOG_ERROR("core: esil: Stopped execution in an invalid instruction (see e??esil.breakoninvalid)\n");
			return_tail(0);
		}
		op.size = 1; // avoid inverted stepping
	}
	if (stepOver) {
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_SWI:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_CALL:
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_RET:
		case RZ_ANALYSIS_OP_TYPE_CRET:
		case RZ_ANALYSIS_OP_TYPE_UJMP:
			if (addr == until_addr) {
				return_tail(0);
			} else {
				rz_reg_setv(core->analysis->reg, "PC", op.addr + op.size);
			}
			return_tail(1);
		}
	}
	rz_reg_setv(core->analysis->reg, name, addr + op.size);
	if (ret) {
		rz_analysis_esil_set_pc(esil, addr);
		const char *e = RZ_STRBUF_SAFEGET(&op.esil);
		if (core->dbg->trace->enabled) {
			RzReg *reg = core->dbg->reg;
			core->dbg->reg = core->analysis->reg;
			rz_debug_trace_op(core->dbg, &op);
			core->dbg->reg = reg;
		} else if (RZ_STR_ISNOTEMPTY(e)) {
			rz_analysis_esil_parse(esil, e);
			if (core->analysis->cur && core->analysis->cur->esil_post_loop) {
				core->analysis->cur->esil_post_loop(esil, &op);
			}
			rz_analysis_esil_stack_free(esil);
		}
		bool isNextFall = false;
		if (op.type == RZ_ANALYSIS_OP_TYPE_CJMP) {
			ut64 pc = rz_reg_getv(core->analysis->reg, name);
			if (pc == addr + op.size) {
				// do not opdelay here
				isNextFall = true;
			}
		}
		// only support 1 slot for now
		if (op.delay && !isNextFall) {
			ut8 code2[32];
			ut64 naddr = addr + op.size;
			RzAnalysisOp op2;
			// emulate only 1 instruction
			rz_analysis_esil_set_pc(esil, naddr);
			(void)rz_io_read_at(core->io, naddr, code2, sizeof(code2));
			// TODO: sometimes this is dupe
			rz_analysis_op_init(&op2);
			ret = rz_analysis_op(core->analysis, &op2, naddr, code2, sizeof(code2), RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
			if (ret > 0) {
				switch (op2.type) {
				case RZ_ANALYSIS_OP_TYPE_CJMP:
				case RZ_ANALYSIS_OP_TYPE_JMP:
				case RZ_ANALYSIS_OP_TYPE_CRET:
				case RZ_ANALYSIS_OP_TYPE_RET:
					// branches are illegal in a delay slot
					esil->trap = RZ_ANALYSIS_TRAP_EXEC_ERR;
					esil->trap_code = addr;
					RZ_LOG_WARN("core: ESIL: Trap, trying to execute a branch in a delay slot\n");
					return_tail(1);
					break;
				}
				const char *e = RZ_STRBUF_SAFEGET(&op2.esil);
				if (RZ_STR_ISNOTEMPTY(e)) {
					rz_analysis_esil_parse(esil, e);
				}
			} else {
				RZ_LOG_ERROR("core: Invalid instruction at 0x%08" PFMT64x "\n", naddr);
			}
			rz_analysis_op_fini(&op2);
		}
		tail_return_value = 1;
	}
	// esil->verbose ?
	// eprintf ("REPE 0x%llx %s => 0x%llx\n", addr, RZ_STRBUF_SAFEGET (&op.esil), rz_reg_getv (core->analysis->reg, "PC"));

	ut64 pc = rz_reg_getv(core->analysis->reg, name);
	if (core->analysis->pcalign > 0) {
		pc -= (pc % core->analysis->pcalign);
		rz_reg_setv(core->analysis->reg, name, pc);
	}

	st64 follow = (st64)rz_config_get_i(core->config, "dbg.follow");
	if (follow > 0) {
		ut64 pc = rz_reg_getv(core->analysis->reg, name);
		if ((pc < core->offset) || (pc >= (core->offset + follow))) {
			rz_core_seek_to_register(core, "PC", false);
		}
	}
	// check breakpoints
	if (rz_bp_get_at(core->dbg->bp, pc)) {
		rz_cons_printf("[ESIL] hit breakpoint at 0x%" PFMT64x "\n", pc);
		return_tail(0);
	}
	// check addr
	if (until_addr != UT64_MAX) {
		if (pc == until_addr) {
			return_tail(0);
		}
		goto repeat;
	}
	// check esil
	if (esil && esil->trap) {
		if (core->analysis->esil->verbose) {
			RZ_LOG_WARN("core: TRAP\n");
		}
		return_tail(0);
	}
	if (until_expr) {
		if (rz_analysis_esil_condition(core->analysis->esil, until_expr)) {
			if (core->analysis->esil->verbose) {
				RZ_LOG_WARN("core: ESIL BREAK!\n");
			}
			return_tail(0);
		}
		goto repeat;
	}
tail_return:
	rz_analysis_op_fini(&op);
	rz_cons_break_pop();
	return tail_return_value;
}

RZ_API int rz_core_esil_step_back(RzCore *core) {
	rz_return_val_if_fail(core->analysis->esil && core->analysis->esil->trace, -1);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil->trace->idx > 0) {
		rz_analysis_esil_trace_restore(esil, esil->trace->idx - 1);
		rz_core_reg_update_flags(core);
		return 1;
	}
	return 0;
}

RZ_API bool rz_core_esil_continue_back(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core->analysis->esil && core->analysis->esil->trace, false);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil->trace->idx == 0) {
		return true;
	}

	RzRegItem *ripc = rz_reg_get(esil->analysis->reg, "PC", -1);
	RzVector *vreg = ht_up_find(esil->trace->registers, ripc->offset | (ripc->arena << 16), NULL);
	if (!vreg) {
		RZ_LOG_ERROR("failed to find PC change vector\n");
		return false;
	}

	// Search for the nearest breakpoint in the tracepoints before the current position
	bool bp_found = false;
	int idx = 0;
	RzAnalysisEsilRegChange *reg;
	rz_vector_foreach_prev (vreg, reg) {
		if (reg->idx >= esil->trace->idx) {
			continue;
		}
		bp_found = rz_bp_get_in(core->dbg->bp, reg->data, RZ_PERM_X) != NULL;
		if (bp_found) {
			idx = reg->idx;
			RZ_LOG_WARN("core: hit breakpoint at: 0x%" PFMT64x " idx: %d\n", reg->data, reg->idx);
			break;
		}
	}

	// Return to the nearest breakpoint or jump back to the first index if a breakpoint wasn't found
	rz_analysis_esil_trace_restore(esil, idx);

	rz_core_reg_update_flags(core);

	return true;
}

RZ_API bool rz_core_esil_dumpstack(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);
	int i;
	if (esil->trap) {
		rz_cons_printf("ESIL TRAP type %d code 0x%08x %s\n",
			esil->trap, esil->trap_code,
			rz_analysis_esil_trapstr(esil->trap));
	}
	if (esil->stackptr < 1) {
		return false;
	}
	for (i = esil->stackptr - 1; i >= 0; i--) {
		rz_cons_printf("%s\n", esil->stack[i]);
	}
	return true;
}

RZ_IPI void rz_core_debug_esil_watch_print(RzDebug *dbg, RzCmdStateOutput *state) {
	RzDebugEsilWatchpoint *ew;
	RzListIter *iter;
	RzList *watchpoints = rz_debug_esil_watch_list(dbg);
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sss", "permissions", "kind", "expression");
	rz_list_foreach (watchpoints, iter, ew) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "permissions", rz_str_rwx_i(ew->rwx));
			pj_ks(state->d.pj, "kind", ew->dev == 'r' ? "reg" : "mem");
			pj_ks(state->d.pj, "expression", ew->expr);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "sss",
				rz_str_rwx_i(ew->rwx), ew->dev == 'r' ? "reg" : "mem",
				ew->expr);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%s %c %s\n", rz_str_rwx_i(ew->rwx), ew->dev, ew->expr);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("de %s %c %s\n", rz_str_rwx_i(ew->rwx), ew->dev, ew->expr);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
}
