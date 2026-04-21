// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_list.h>
#include <rz_flag.h>
#include <rz_core.h>
#include <rz_bin.h>
#include <rz_util/ht_uu.h>
#include <rz_util/rz_graph_drawable.h>
#include "core_private.h"

static ut64 initializeEsil(RzCore *core) {
	ut64 addr = 0;
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int exectrap = rz_config_get_i(core->config, "esil.exectrap");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	RzAnalysisEsil *esil = rz_analysis_esil_new(stacksize, iotrap, addrsize);
	if (!esil) {
		return UT64_MAX;
	}
	rz_analysis_set_esil(core->analysis, esil);
	esil->verbose = rz_config_get_i(core->config, "esil.verbose");
	esil->cmd = rz_core_esil_cmd;
	rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL, core); // setup io
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
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	const char *name = rz_reg_get_name(rreg, RZ_REG_NAME_PC);
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
		esil = rz_analysis_get_esil(core->analysis);
		if (!esil) {
			return_tail(0);
		}
	} else {
		esil->trap = 0;
		addr = rz_reg_getv(rreg, name);
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
	esil = rz_analysis_get_esil(core->analysis);
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
				rz_reg_setv(rreg, "PC", op.addr + op.size);
			}
			return_tail(1);
		}
	}
	rz_reg_setv(rreg, name, addr + op.size);
	if (ret) {
		rz_analysis_esil_set_pc(esil, addr);
		const char *e = RZ_STRBUF_SAFEGET(&op.esil);
		if (core->dbg->trace->enabled) {
			RzReg *reg = core->dbg->reg;
			core->dbg->reg = rreg;
			rz_debug_trace_op(core->dbg, &op);
			core->dbg->reg = reg;
		} else if (RZ_STR_ISNOTEMPTY(e)) {
			rz_analysis_esil_parse(esil, e);
			rz_analysis_esil_stack_free(esil);
		}
		bool isNextFall = false;
		if (op.type == RZ_ANALYSIS_OP_TYPE_CJMP) {
			ut64 pc = rz_reg_getv(rreg, name);
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
			(void)rz_io_read_at_mapped(core->io, naddr, code2, sizeof(code2));
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
					RZ_LOG_INFO("core: ESIL: Trap, trying to execute a branch in a delay slot\n");
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
	// eprintf ("REPE 0x%" PFMT64x " %s => 0x%" PFMT64x "\n", addr, RZ_STRBUF_SAFEGET (&op.esil), rz_reg_getv (rreg, "PC"));

	ut64 pc = rz_reg_getv(rreg, name);
	int pcalign = rz_analysis_get_pc_align(core->analysis);
	if (pcalign > 1) {
		pc -= (pc % pcalign);
		rz_reg_setv(rreg, name, pc);
	}

	st64 follow = (st64)rz_config_get_i(core->config, "dbg.follow");
	if (follow > 0) {
		ut64 pc = rz_reg_getv(rreg, name);
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
		if (esil->verbose) {
			RZ_LOG_WARN("core: TRAP\n");
		}
		return_tail(0);
	}
	if (until_expr) {
		if (rz_analysis_esil_condition(esil, until_expr)) {
			if (esil->verbose) {
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
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	if (!esil || !esil->trace) {
		return -1;
	}
	if (esil->trace->idx > 0) {
		rz_analysis_esil_trace_restore(esil, esil->trace->idx - 1);
		rz_core_reg_update_flags(core);
		return 1;
	}
	return 0;
}

RZ_API bool rz_core_esil_continue_back(RZ_NONNULL RzCore *core) {
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	if (!esil || !esil->trace) {
		return false;
	}

	if (esil->trace->idx == 0) {
		return true;
	}

	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzRegItem *ripc = rz_reg_get(rreg, "PC", -1);
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
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
}

static void core_esil_init(RzCore *core) {
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	int verbose = rz_config_get_i(core->config, "esil.verbose");
	RzAnalysisEsil *esil = rz_analysis_esil_new(stacksize, iotrap, addrsize);
	if (!esil) {
		return;
	}
	rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL, core); // setup io
	esil->verbose = verbose;
	rz_analysis_set_esil(core->analysis, esil);
	const char *s = rz_config_get(core->config, "cmd.esil.intr");
	if (s) {
		char *my = rz_str_dup(s);
		if (my) {
			rz_config_set(core->config, "cmd.esil.intr", my);
			free(my);
		}
	}
}

RZ_IPI void rz_core_analysis_esil_init(RzCore *core) {
	if (rz_analysis_get_esil(core->analysis)) {
		return;
	}
	core_esil_init(core);
}

/**
 * \brief Reinitialize esil
 * \param core RzCore reference
 */
RZ_API void rz_core_analysis_esil_reinit(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core && core->analysis);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	rz_analysis_set_esil(core->analysis, NULL);
	rz_analysis_esil_free(esil);
	core_esil_init(core);
	// reinitialize
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	rz_reg_set_value_by_role(rreg, RZ_REG_NAME_PC, core->offset);
}

/**
 * \brief Deinitialize esil
 * \param core RzCore reference
 */
RZ_API void rz_core_analysis_esil_deinit(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core && core->analysis);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	rz_analysis_set_esil(core->analysis, NULL);
	if (esil) {
		sdb_reset(esil->stats);
	}
	rz_analysis_esil_free(esil);
}

static void initialize_stack(RzCore *core, ut64 addr, ut64 size) {
	const char *mode = rz_config_get(core->config, "esil.fillstack");
	if (mode && *mode && *mode != '0') {
		const ut64 bs = 4096 * 32;
		ut64 i;
		for (i = 0; i < size; i += bs) {
			ut64 left = RZ_MIN(bs, size - i);
			//	rz_core_cmdf (core, "wx 10203040 @ 0x%" PFMT64x "", addr);
			switch (*mode) {
			case 'd': { // "debrujn"
				ut8 *buf = (ut8 *)rz_debruijn_pattern(left, 0, NULL);
				if (buf) {
					if (!rz_core_write_at(core, addr + i, buf, left)) {
						RZ_LOG_ERROR("core: cannot write at %" PFMT64x "\n", addr + i);
					}
					free(buf);
				} else {
					RZ_LOG_ERROR("core: cannot generate pattern of length %" PFMT64d "\n", left);
				}
			} break;
			case 's': // "seq"
				rz_core_cmdf(core, "woe 1 0xff 1 4 @ 0x%" PFMT64x "!0x%" PFMT64x, addr + i, left);
				break;
			case 'r': // "random"
				rz_core_cmdf(core, "woR %" PFMT64u " @ 0x%" PFMT64x "!0x%" PFMT64x, left, addr + i, left);
				break;
			case 'z': // "zero"
			case '0':
				rz_core_cmdf(core, "wb 00 @ 0x%" PFMT64x "!0x%" PFMT64x, addr + i, left);
				break;
			}
		}
	}
}

static char *get_esil_stack_name(RzCore *core, const char *name, ut64 *addr, ut32 *size) {
	ut64 sx_addr = rz_config_get_i(core->config, "esil.stack.addr");
	ut32 sx_size = rz_config_get_i(core->config, "esil.stack.size");
	RzIOMap *map = rz_io_map_get(core->io, sx_addr);
	if (map) {
		sx_addr = UT64_MAX;
	}
	if (sx_addr == UT64_MAX) {
		const ut64 align = 0x10000000;
		sx_addr = rz_io_map_next_available(core->io, core->offset, sx_size, align);
	}
	if (*addr != UT64_MAX) {
		sx_addr = *addr;
	}
	if (*size != UT32_MAX) {
		sx_size = *size;
	}
	if (sx_size < 1) {
		sx_size = 0xf0000;
	}
	*addr = sx_addr;
	*size = sx_size;
	if (RZ_STR_ISEMPTY(name)) {
		return rz_str_newf("mem.0x%" PFMT64x "_0x%x", sx_addr, sx_size);
	} else {
		return rz_str_newf("mem.%s", name);
	}
}

/**
 * Initialize esil memory stack region.
 *
 * \param core RzCore reference
 * \param name Optional name of the memory stack region. If NULL, a name is
 *             computed automatically based on \p addr and \p size
 * \param addr Base address of the stack region, if UT64_MAX it is automatically computed
 * \param size Size of the stack region, if UT32_MAX it is automatically computed
 */
RZ_API void rz_core_analysis_esil_init_mem(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *name, ut64 addr, ut32 size) {
	rz_return_if_fail(core && core->analysis);
	ut64 current_offset = core->offset;
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	if (!esil) {
		RZ_LOG_ERROR("core: cannot initialize esil\n");
		return;
	}
	RzIOMap *stack_map;
	if (!name && addr == UT64_MAX && size == UT32_MAX) {
		const char *fi = sdb_const_get(core->sdb, "aeim.fd");
		if (fi) {
			// Close the fd associated with the aeim stack
			ut64 fd = sdb_atoi(fi);
			(void)rz_io_fd_close(core->io, fd);
		}
	}
	const char *pattern = rz_config_get(core->config, "esil.stack.pattern");
	char *stack_name = get_esil_stack_name(core, name, &addr, &size);

	char uri[32];
	rz_strf(uri, "malloc://%u", size);
	esil->stack_fd = rz_io_fd_open(core->io, uri, RZ_PERM_RW, 0);
	if (!(stack_map = rz_io_map_add(core->io, esil->stack_fd, RZ_PERM_RW, 0LL, addr, size))) {
		rz_io_fd_close(core->io, esil->stack_fd);
		RZ_LOG_ERROR("core: cannot create map for the stack, fd %d got closed again\n", esil->stack_fd);
		free(stack_name);
		esil->stack_fd = 0;
		return;
	}
	rz_io_map_set_name(stack_map, stack_name);
	free(stack_name);
	char val[128], *v;
	v = sdb_itoa(esil->stack_fd, val, 10);
	sdb_set(core->sdb, "aeim.fd", v);

	rz_config_set_b(core->config, "io.va", true);
	if (pattern && *pattern) {
		switch (*pattern) {
		case '0':
			// do nothing
			break;
		case 'd':
			rz_core_cmdf(core, "wopD %d @ 0x%" PFMT64x, size, addr);
			break;
		case 'i':
			rz_core_cmdf(core, "woe 0 255 1 @ 0x%" PFMT64x "!%d", addr, size);
			break;
		case 'w':
			rz_core_cmdf(core, "woe 0 0xffff 1 4 @ 0x%" PFMT64x "!%d", addr, size);
			break;
		}
	}
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	rz_reg_set_value_by_role(rreg, RZ_REG_NAME_SP, addr + (size / 2)); // size / 2 to have free space in both directions
	rz_reg_set_value_by_role(rreg, RZ_REG_NAME_BP, addr + (size / 2));
	rz_reg_set_value_by_role(rreg, RZ_REG_NAME_PC, current_offset);
	rz_core_reg_update_flags(core);
	esil->stack_addr = addr;
	esil->stack_size = size;
	initialize_stack(core, addr, size);
	rz_core_seek(core, current_offset, false);
}

RZ_IPI void rz_core_analysis_esil_init_mem_p(RzCore *core) {
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	ut64 addr = 0x100000;
	ut32 size = 0xf0000;
	RzFlagItem *fi = rz_flag_get(core->flags, "aeim.stack");
	if (fi) {
		addr = fi->offset;
		size = fi->size;
	} else {
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	if (esil) {
		esil->stack_addr = addr;
		esil->stack_size = size;
	}
	initialize_stack(core, addr, size);
	return;
}

/**
 * \brief Remove esil VM stack
 * \param core RzCore reference
 * \param name Optional name of the memory stack region. If NULL, a name is computed automatically based on \p addr
 *             and \p size
 * \param addr Base address of the stack region, if UT64_MAX it is automatically computed
 * \param size Size of the stack region, if UT32_MAX it is automatically computed
 */
RZ_API void rz_core_analysis_esil_init_mem_del(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *name, ut64 addr, ut32 size) {
	rz_return_if_fail(core && core->analysis);
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	char *stack_name = get_esil_stack_name(core, name, &addr, &size);
	if (esil && esil->stack_fd > 2) { // 0, 1, 2 are reserved for stdio/stderr
		rz_io_fd_close(core->io, esil->stack_fd);
		// no need to kill the maps, rz_io_map_cleanup does that for us in the close
		esil->stack_fd = 0;
	} else {
		RZ_LOG_ERROR("core: cannot deinitialize %s\n", stack_name);
	}
	rz_flag_unset_name(core->flags, stack_name);
	rz_flag_unset_name(core->flags, "aeim.stack");
	sdb_unset(core->sdb, "aeim.fd");
	free(stack_name);
}

/**
 * Initialize esil registers.
 *
 * \param core RzCore reference
 */
RZ_API void rz_core_analysis_esil_init_regs(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core);
	rz_core_analysis_set_reg(core, "PC", core->offset);
}

RZ_API void rz_core_analysis_esil_step_over(RZ_NONNULL RzCore *core) {
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzAnalysisOp *op = rz_core_analysis_op(core, rz_reg_getv(rreg, rz_reg_get_name(rreg, RZ_REG_NAME_PC)), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
	ut64 until_addr = UT64_MAX;
	if (op && op->type == RZ_ANALYSIS_OP_TYPE_CALL) {
		until_addr = op->addr + op->size;
	}
	rz_core_esil_step(core, until_addr, NULL, NULL, false);
	rz_analysis_op_free(op);
	rz_core_reg_update_flags(core);
}

RZ_IPI void rz_core_analysis_esil_step_over_until(RzCore *core, ut64 addr) {
	rz_core_esil_step(core, addr, NULL, NULL, true);
	rz_core_reg_update_flags(core);
}

RZ_IPI void rz_core_analysis_esil_step_over_untilexpr(RzCore *core, const char *expr) {
	rz_core_esil_step(core, UT64_MAX, expr, NULL, true);
	rz_core_reg_update_flags(core);
}

RZ_IPI void rz_core_analysis_esil_references_all_functions(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	RzList *fcns = rz_analysis_function_list(core->analysis);
	rz_list_foreach (fcns, it, fcn) {
		ut64 from = rz_analysis_function_min_addr(fcn);
		ut64 to = rz_analysis_function_max_addr(fcn);
		rz_core_analysis_esil(core, from, to - from, fcn);
	}
}

/**
 * Emulate \p n_instr instructions from \p addr. If \p until_addr is
 * specified and that address is met before all the instructions are emulated,
 * stop there.
 */
RZ_IPI void rz_core_analysis_esil_emulate(RzCore *core, ut64 addr, ut64 until_addr, int off) {
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	int i = 0, j = 0;
	ut8 *buf = NULL;
	RzAnalysisOp aop = { 0 };
	int ret, bsize = RZ_MAX(4096, core->blocksize);
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	const char *pc = rz_reg_get_name(rreg, RZ_REG_NAME_PC);
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	ut64 addrsize = rz_config_get_i(core->config, "esil.addr.size");

	if (!esil) {
		RZ_LOG_WARN("core: cmd_espc: creating new esil instance\n");
		if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
			return;
		}
		rz_analysis_set_esil(core->analysis, esil);
	}
	buf = malloc(bsize);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate %d byte(s)\n", bsize);
		return;
	}
	if (addr == -1) {
		addr = rz_reg_getv(rreg, pc);
	}
	(void)rz_analysis_esil_setup(esil, core->analysis, 0, 0, 0, core); // int romem, int stats, int nonull) {
	ut64 cursp = rz_reg_getv(rreg, "SP");
	ut64 oldoff = core->offset;
	const ut64 flags = RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_DISASM;
	for (i = 0, j = 0; j < off; i++, j++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (!i) {
			rz_io_read_at_mapped(core->io, addr, buf, bsize);
		}
		if (addr == until_addr) {
			break;
		}
		rz_analysis_op_init(&aop);
		ret = rz_analysis_op(core->analysis, &aop, addr, buf + i, bsize - i, flags);
		if (ret < 1) {
			RZ_LOG_ERROR("core: failed esil analysis at 0x%08" PFMT64x "\n", addr);
			break;
		}
		// skip calls and such
		if (aop.type == RZ_ANALYSIS_OP_TYPE_CALL) {
			// nothing
		} else {
			rz_reg_setv(rreg, "PC", aop.addr + aop.size);
			const char *e = RZ_STRBUF_SAFEGET(&aop.esil);
			if (e && *e) {
				// eprintf ("   0x%08" PFMT64x " %d  %s\n", aop.addr, ret, aop.mnemonic);
				(void)rz_analysis_esil_parse(esil, e);
			}
		}
		int inc = (core->search->align > 1) ? core->search->align - 1 : ret - 1;
		if (inc < 0) {
			inc = minopcode;
		}
		i += inc;
		addr += ret; // aop.size;
		rz_analysis_op_fini(&aop);
	}
	rz_core_seek(core, oldoff, true);
	rz_reg_setv(rreg, "SP", cursp);
	free(buf);
}

RZ_IPI void rz_core_analysis_esil_emulate_bb(RzCore *core) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!bb) {
		RZ_LOG_ERROR("core: cannot find basic block for 0x%08" PFMT64x "\n", core->offset);
		return;
	}
	rz_core_analysis_esil_emulate(core, bb->addr, UT64_MAX, bb->ninstr);
}

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val) {
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	RzRegItem *r = rz_reg_get(rreg, regname, -1);
	if (!r) {
		int role = rz_reg_get_name_idx(regname);
		if (role != -1) {
			const char *alias = rz_reg_get_name(rreg, role);
			if (alias) {
				r = rz_reg_get(rreg, alias, -1);
			}
		}
	}
	if (!r) {
		RZ_LOG_ERROR("core: unknown register '%s'\n", regname);
		return -1;
	}
	rz_reg_set_value(rreg, r, val);
	rz_core_reg_update_flags(core);
	return 0;
}

RZ_IPI void rz_core_analysis_esil_default(RzCore *core) {
	RzIOMap *map;
	RzListIter *iter;
	RzList *list = rz_core_get_boundaries_select(core, "analysis.from", "analysis.to", "analysis.in");
	if (!list) {
		return;
	}
	if (!strcmp("range", rz_config_get(core->config, "analysis.in"))) {
		ut64 from = rz_config_get_i(core->config, "analysis.from");
		ut64 to = rz_config_get_i(core->config, "analysis.to");
		if (to > from) {
			rz_core_analysis_esil(core, from, to - from, NULL);
		} else {
			RZ_LOG_ERROR("core: analysis.from > analysis.to\n");
		}
	} else {
		rz_list_foreach (list, iter, map) {
			if (map->perm & RZ_PERM_X) {
				rz_core_analysis_esil(core, map->itv.addr, map->itv.size, NULL);
			}
		}
	}
	rz_list_free(list);
}

/**
 * \brief Re-initializes the intermediate language virtual machine for analysis
 *
 * This function re-initializes the IL (Intermediate Language) virtual machine for the analysis module.
 * The initial PC (Program Counter) is set with the current offset.
 * It then updates the register flags and syncs the register info back to the IL VM.
 *
 * \param core The RzCore object, which contains all the rizin classes and their functions.
 */
RZ_API void rz_core_analysis_il_reinit(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core);
	if (!rz_analysis_il_vm_setup(core->analysis)) {
		RZ_LOG_WARN("IL VM setup failed\n");
	}
	RzAnalysisILVM *il_vm = rz_analysis_get_il_vm(core->analysis);
	if (!il_vm) {
		return;
	}
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	// initialize the program counter with the current offset
	rz_reg_set_value_by_role(rreg, RZ_REG_NAME_PC, core->offset);
	rz_core_reg_update_flags(core);

	// sync back to il vm
	rz_analysis_il_vm_sync_from_reg(il_vm, rreg);
}

// used to speedup strcmp with rz_config_get in loops
enum {
	RZ_ARCH_THUMB,
	RZ_ARCH_ARM32,
	RZ_ARCH_ARM64,
	RZ_ARCH_MIPS
};
// 128M
#define MAX_SCAN_SIZE 0x7ffffff

static void cccb(void *u) {
	RzCore *core = u;
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	if (esil) {
		esil->esilinterstate->analysis_stop = true;
	}
	eprintf("^C\n");
}

// dup with isValidAddress
static bool myvalid(RzIO *io, ut64 addr) {
	if (addr < 0x100) {
		return false;
	}
	if (addr == UT32_MAX || addr == UT64_MAX) { // the best of the best of the best :(
		return false;
	}
	if (!rz_io_is_valid_offset(io, addr, 0)) {
		return false;
	}
	return true;
}

typedef struct {
	RzAnalysisOp *op;
	RzAnalysisFunction *fcn;
	const char *spname;
	ut64 initial_sp;
	RzStackAddr shadow_store;
} EsilBreakCtx;

static const char *reg_name_for_access(RzAnalysisOp *op, RzAnalysisVarAccessType type) {
	if (type == RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE) {
		if (op->dst && op->dst->reg) {
			return op->dst->reg->name;
		}
	} else {
		if (op->src[0] && op->src[0]->reg) {
			return op->src[0]->reg->name;
		}
	}
	return NULL;
}

static ut64 delta_for_access(RzAnalysisOp *op, RzAnalysisVarAccessType type) {
	if (type == RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE) {
		if (op->dst) {
			return op->dst->imm + op->dst->delta;
		}
	} else {
		if (op->src[1] && (op->src[1]->imm || op->src[1]->delta)) {
			return op->src[1]->imm + op->src[1]->delta;
		}
		if (op->src[0]) {
			return op->src[0]->imm + op->src[0]->delta;
		}
	}
	return 0;
}

static void handle_var_stack_access(RzAnalysisEsil *esil, ut64 addr, RzAnalysisVarAccessType type, int len) {
	EsilBreakCtx *ctx = esil->user;
	const char *regname = reg_name_for_access(ctx->op, type);
	if (!ctx->fcn || !regname) {
		return;
	}

	RzReg *rreg = rz_analysis_get_reg((RzAnalysis *)esil->panalysis);
	ut64 spaddr = rz_reg_getv(rreg, ctx->spname);
	if (addr >= spaddr && addr < ctx->initial_sp) {
		st64 stack_off = addr - ctx->initial_sp + ctx->shadow_store;
		RzAnalysisVarStorage stor;
		rz_analysis_var_storage_init_stack(&stor, stack_off);
		RzAnalysisVar *var = rz_analysis_function_get_var_at(ctx->fcn, &stor);
		if (!var && stack_off >= -ctx->fcn->maxstack) {
			// "s" for positive shadow space to avoid conflicts
			char *varname = rz_str_newf("var_%s%" PFMT64x "h", stack_off > 0 ? "s" : "", RZ_ABS(stack_off));
			var = rz_analysis_function_set_var(ctx->fcn, &stor, NULL, len, varname);
			free(varname);
		}
		if (var) {
			rz_analysis_var_set_access(var, regname, ctx->op->addr, type, delta_for_access(ctx->op, type));
		}
	}
}

static int esilbreak_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, len);
	return 1;
}

// TODO differentiate endian-aware mem_read with other reads
static int esilbreak_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	RzCore *core = esil->pcore;
	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	RzAnalysisEsilInterState *estate = esil->esilinterstate;

	if (addr != UT64_MAX) {
		estate->last_read = addr;
	}
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, len);
	if (myvalid(core->io, addr) && rz_io_read_at_mapped(core->io, addr, (ut8 *)buf, len)) {
		ut64 refptr;
		bool trace = true;
		switch (len) {
		case 2:
			estate->last_data = refptr = (ut64)rz_read_ble16(buf, big_endian);
			break;
		case 4:
			estate->last_data = refptr = (ut64)rz_read_ble32(buf, big_endian);
			break;
		case 8:
			estate->last_data = refptr = rz_read_ble64(buf, big_endian);
			break;
		default:
			trace = false;
			rz_io_read_at_mapped(core->io, addr, (ut8 *)buf, len);
			break;
		}
		// TODO incorrect
		if (trace && myvalid(core->io, refptr)) {
			ut8 str[128] = { 0 };
			if (rz_io_read_at_mapped(core->io, refptr, str, sizeof(str)) < 1) {
				// RZ_LOG_ERROR("core: invalid read\n");
				str[0] = 0;
			} else {
				rz_analysis_xrefs_set(core->analysis, esil->address, refptr, RZ_ANALYSIS_XREF_TYPE_DATA);
				str[sizeof(str) - 1] = 0;
				rz_core_add_string_ref(core, esil->address, refptr);
				estate->last_data = UT64_MAX;
			}
		}

		/** resolve ptr */
		rz_analysis_xrefs_set(core->analysis, esil->address, addr, RZ_ANALYSIS_XREF_TYPE_DATA);
	}
	return 0; // fallback
}

static int esilbreak_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	if (!esil) {
		return 0;
	}
	RzAnalysis *analysis = esil->panalysis;
	RzCore *core = esil->pcore;
	EsilBreakCtx *ctx = esil->user;
	RzAnalysisOp *op = ctx->op;
	int bits = rz_asm_get_bits(core->rasm);
	bool is_arm = rz_asm_is_arch(core->rasm, "arm");
	const RzAnalysisOptions *aopts = rz_analysis_get_options(analysis);

	handle_var_stack_access(esil, *val, RZ_ANALYSIS_VAR_ACCESS_TYPE_PTR, rz_analysis_guessed_mem_access_width(analysis));

	// specific case to handle blx/bx cases in arm through emulation
	//  XXX this thing creates a lot of false positives
	ut64 at = *val;
	if (aopts->armthumb && bits < 33 && is_arm && !strcmp(name, "pc") && op) {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_RCALL: // BLX
		case RZ_ANALYSIS_OP_TYPE_RJMP: // BX
			// maybe UJMP/UCALL is enough here
			if (!(*val & 1)) {
				rz_analysis_hint_set_bits(analysis, *val, 32);
			} else {
				RzReg *rreg = rz_analysis_get_reg(analysis);
				ut64 snv = rz_reg_getv(rreg, "pc");
				if (snv != UT32_MAX && snv != UT64_MAX) {
					if (rz_io_is_valid_offset(core->io, *val, 1)) {
						rz_analysis_hint_set_bits(analysis, *val - 1, 16);
					}
				}
			}
			break;
		default:
			break;
		}
	}

	if (bits == 32 && is_arm && (!(at & 1)) &&
		rz_io_is_valid_offset(core->io, at, 0)) {
		rz_core_add_string_ref(core, esil->address, at);
	}
	return 0;
}

static void getpcfromstack(RzCore *core, RzAnalysisEsil *esil) {
	if (!esil) {
		return;
	}
	ut64 cur;
	ut64 addr;
	ut64 size;
	int idx;
	RzAnalysisEsil esil_cpy;
	RzAnalysisOp op = { 0 };
	RzAnalysisFunction *fcn = NULL;
	ut8 *buf = NULL;
	char *tmp_esil_str = NULL;
	int tmp_esil_str_len;
	const char *esilstr;
	const int maxaddrlen = 20;
	const char *spname = NULL;
	RzReg *rreg = rz_analysis_get_reg(core->analysis);

	memcpy(&esil_cpy, esil, sizeof(esil_cpy));
	addr = cur = esil_cpy.cur;
	fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (!fcn) {
		return;
	}

	size = rz_analysis_function_linear_size(fcn);
	if (size <= 0) {
		return;
	}

	buf = malloc(size + 2);
	if (!buf) {
		perror("malloc");
		return;
	}

	rz_io_read_at_mapped(core->io, addr, buf, size + 1);

	// TODO Hardcoding for 2 instructions (mov e_p,[esp];ret). More work needed
	idx = 0;
	rz_analysis_op_init(&op);
	if (rz_analysis_op(core->analysis, &op, cur, buf + idx, size - idx, RZ_ANALYSIS_OP_MASK_ESIL) <= 0 ||
		op.size <= 0 ||
		(op.type != RZ_ANALYSIS_OP_TYPE_MOV && op.type != RZ_ANALYSIS_OP_TYPE_CMOV)) {
		goto err_analysis_op;
	}

	rz_asm_set_pc(core->rasm, cur);
	esilstr = RZ_STRBUF_SAFEGET(&op.esil);
	if (!esilstr) {
		goto err_analysis_op;
	}
	// Ugly code
	// This is a hack, since esil doesn't always preserve values pushed on the stack. That probably needs to be rectified
	spname = rz_reg_get_name(rreg, RZ_REG_NAME_SP);
	if (!spname || !*spname) {
		goto err_analysis_op;
	}
	tmp_esil_str_len = strlen(esilstr) + strlen(spname) + maxaddrlen;
	tmp_esil_str = (char *)malloc(tmp_esil_str_len);
	if (!tmp_esil_str) {
		goto err_analysis_op;
	}
	tmp_esil_str[tmp_esil_str_len - 1] = '\0';
	snprintf(tmp_esil_str, tmp_esil_str_len - 1, "%s,[", spname);
	if (!*esilstr || (strncmp(esilstr, tmp_esil_str, strlen(tmp_esil_str)))) {
		free(tmp_esil_str);
		goto err_analysis_op;
	}

	snprintf(tmp_esil_str, tmp_esil_str_len - 1, "%20" PFMT64u "%s", esil_cpy.old, &esilstr[strlen(spname) + 4]);
	rz_str_trim(tmp_esil_str);
	idx += op.size;
	rz_analysis_esil_set_pc(&esil_cpy, cur);
	rz_analysis_esil_parse(&esil_cpy, tmp_esil_str);
	rz_analysis_esil_stack_free(&esil_cpy);
	free(tmp_esil_str);

	cur = addr + idx;
	rz_analysis_op_fini(&op);
	rz_analysis_op_init(&op);
	if (rz_analysis_op(core->analysis, &op, cur, buf + idx, size - idx, RZ_ANALYSIS_OP_MASK_ESIL) <= 0 ||
		op.size <= 0 ||
		(op.type != RZ_ANALYSIS_OP_TYPE_RET && op.type != RZ_ANALYSIS_OP_TYPE_CRET)) {
		goto err_analysis_op;
	}
	rz_asm_set_pc(core->rasm, cur);

	esilstr = RZ_STRBUF_SAFEGET(&op.esil);
	rz_analysis_esil_set_pc(&esil_cpy, cur);
	if (!esilstr || !*esilstr) {
		goto err_analysis_op;
	}
	rz_analysis_esil_parse(&esil_cpy, esilstr);
	rz_analysis_esil_stack_free(&esil_cpy);

	memcpy(esil, &esil_cpy, sizeof(esil_cpy));

err_analysis_op:
	rz_analysis_op_fini(&op);
	free(buf);
}

typedef struct {
	RzCore *core;
	ut64 start_addr;
	ut64 end_addr;
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *cur_bb;
	RzList /*<RzAnalysisBlock *>*/ *bbl, *path;
	RzList /*<RzAnalysisCaseOp *>*/ *switch_path;
} IterCtx;

static int find_bb(ut64 *addr, RzAnalysisBlock *bb, void *user) {
	return *addr != bb->addr;
}

static RzList /*<void *>*/ *pvector_to_list(RzPVector /*<void *>*/ *pvec) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (pvec, it) {
		rz_list_append(list, *it);
	}
	return list;
}

static inline bool get_next_i(IterCtx *ctx, size_t *next_i) {
	(*next_i)++;
	RzCore *core = ctx->core;
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	ut64 cur_addr = *next_i + ctx->start_addr;
	if (ctx->fcn) {
		if (!ctx->cur_bb) {
			ctx->path = rz_list_new();
			ctx->switch_path = rz_list_new();
			ctx->bbl = pvector_to_list(ctx->fcn->bbs);
			ctx->cur_bb = rz_analysis_get_block_at(core->analysis, ctx->fcn->addr);
			rz_list_push(ctx->path, ctx->cur_bb);
		}
		RzAnalysisBlock *bb = ctx->cur_bb;
		if (cur_addr >= bb->addr + bb->size) {
			rz_reg_arena_push(rreg);
			RzListIter *bbit = NULL;
			if (bb->switch_op) {
				RzAnalysisCaseOp *cop = rz_list_first_val(bb->switch_op->cases);
				bbit = rz_list_find(ctx->bbl, &cop->jump, (RzListComparator)find_bb, NULL);
				if (bbit) {
					rz_list_push(ctx->switch_path, bb->switch_op->cases->head);
				}
			} else {
				bbit = rz_list_find(ctx->bbl, &bb->jump, (RzListComparator)find_bb, NULL);
				if (!bbit && bb->fail != UT64_MAX) {
					bbit = rz_list_find(ctx->bbl, &bb->fail, (RzListComparator)find_bb, NULL);
				}
			}
			if (!bbit) {
				RzListIter *cop_it = rz_list_last_val(ctx->switch_path);
				RzAnalysisBlock *prev_bb = NULL;
				do {
					rz_reg_arena_pop(rreg);
					prev_bb = rz_list_pop(ctx->path);
					if (prev_bb->fail != UT64_MAX) {
						bbit = rz_list_find(ctx->bbl, &prev_bb->fail, (RzListComparator)find_bb, NULL);
						if (bbit) {
							rz_reg_arena_push(rreg);
							rz_list_push(ctx->path, prev_bb);
						}
					}
					if (!bbit && cop_it) {
						RzAnalysisCaseOp *cop = rz_list_val(cop_it);
						if (cop->jump == prev_bb->addr && rz_list_has_next(cop_it)) {
							cop = rz_list_iter_get_next_data(cop_it);
							rz_list_pop(ctx->switch_path);
							rz_list_push(ctx->switch_path, rz_list_next(cop_it));
							cop_it = rz_list_next(cop_it);
							bbit = rz_list_find(ctx->bbl, &cop->jump, (RzListComparator)find_bb, NULL);
						}
					}
					if (cop_it && !rz_list_has_next(cop_it)) {
						rz_list_pop(ctx->switch_path);
						cop_it = rz_list_last_val(ctx->switch_path);
					}
				} while (!bbit && !rz_list_empty(ctx->path));
			}
			if (!bbit) {
				rz_list_free(ctx->path);
				rz_list_free(ctx->switch_path);
				rz_list_free(ctx->bbl);
				return false;
			}
			ctx->cur_bb = rz_list_val(bbit);
			rz_list_push(ctx->path, ctx->cur_bb);
			rz_list_delete(ctx->bbl, bbit);
			*next_i = ctx->cur_bb->addr - ctx->start_addr;
		}
	} else if (cur_addr >= ctx->end_addr) {
		return false;
	}
	return true;
}

/**
 * Analyze references with esil (aae)
 *
 * \p addr start address
 * \p size number of bytes to analyze
 * \p fcn optional, when analyzing for a specific function
 */
RZ_API void rz_core_analysis_esil(RzCore *core, ut64 addr, ut64 size, RZ_NULLABLE RzAnalysisFunction *fcn) {
	RzReg *rreg = rz_analysis_get_reg(core->analysis);
	bool cfg_analysis_strings = rz_config_get_i(core->config, "analysis.strings");
	bool emu_lazy = rz_config_get_i(core->config, "emu.lazy");
	bool gp_fixed = rz_config_get_i(core->config, "analysis.gpfixed");
	ut64 refptr = 0LL;
	const char *pcname;
	RzAnalysisEsilInterState *estate = NULL;
	RzAnalysisOp op = RZ_EMPTY;
	ut8 *buf = NULL;
	ut64 iend;
	int minopsize = 4; // XXX this depends on asm->mininstrsize
	bool archIsArm = false;
	ut64 start = addr;
	ut64 end = addr + size;
	if (end <= start) {
		return;
	}
	iend = end - start;
	if (iend < 0) {
		return;
	} else if (iend > MAX_SCAN_SIZE) {
		RZ_LOG_WARN("core: not going to analyze 0x%08" PFMT64x " bytes.\n", iend);
		return;
	}

	buf = malloc((size_t)iend + 2);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate %" PFMT64u "\n", (iend + 2));
		return;
	}
	rz_io_read_at_mapped(core->io, start, buf, iend + 1);
	rz_reg_arena_push(rreg);

	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	if (!esil) {
		rz_core_analysis_esil_reinit(core);
		esil = rz_analysis_get_esil(core->analysis);
		if (!esil) {
			RZ_LOG_ERROR("core: esil has not been initialized\n");
			goto out_pop_regs;
		}
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	estate = esil->esilinterstate;
	estate->last_read = UT64_MAX;
	const char *spname = rz_reg_get_name(rreg, RZ_REG_NAME_SP);
	EsilBreakCtx ctx = {
		.op = &op,
		.fcn = fcn,
		.spname = spname,
		.initial_sp = rz_reg_getv(rreg, spname),
		.shadow_store = fcn && fcn->cc ? rz_analysis_cc_shadow_store(core->analysis, fcn->cc) : 0
	};
	esil->cb.hook_reg_write = &esilbreak_reg_write;
	// this is necessary for the hook to read the id of RzAnalysisOp
	esil->user = &ctx;
	esil->cb.hook_mem_read = &esilbreak_mem_read;
	esil->cb.hook_mem_write = &esilbreak_mem_write;
	if (ctx.shadow_store) {
		rz_reg_setv(rreg, ctx.spname, ctx.initial_sp - ctx.shadow_store);
	}
	// RZ_LOG_ERROR("core: analyzing esil refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	//  TODO: backup/restore register state before/after analysis
	pcname = rz_reg_get_name(rreg, RZ_REG_NAME_PC);
	if (!pcname || !*pcname) {
		RZ_LOG_ERROR("core: cannot find program counter register in the current profile.\n");
		goto out_pop_regs;
	}
	estate->analysis_stop = false;
	rz_cons_break_push(cccb, core);

	int arch = -1;
	if (rz_asm_is_arch(core->rasm, "arm")) {
		switch (rz_asm_get_bits(core->rasm)) {
		case 64: arch = RZ_ARCH_ARM64; break;
		case 32: arch = RZ_ARCH_ARM32; break;
		case 16: arch = RZ_ARCH_THUMB; break;
		}
		archIsArm = true;
	}

	ut64 gp = rz_config_get_i(core->config, "analysis.gp");
	const char *gp_reg = NULL;
	if (rz_asm_is_arch(core->rasm, "mips")) {
		gp_reg = "gp";
		arch = RZ_ARCH_MIPS;
	}

	RZ_NULLABLE const char *sn = rz_reg_get_name(rreg, RZ_REG_NAME_SN);

	IterCtx ictx = { core, start, end, fcn, NULL };
	size_t i = 0;
	do {
		if (estate->analysis_stop || rz_cons_is_breaked()) {
			break;
		}
		size_t i_old = i;
		ut64 cur = start + i;
		if (!rz_io_is_valid_offset(core->io, cur, 0)) {
			break;
		}
		{
			RzPVector *list = rz_meta_get_all_in(core->analysis, cur, RZ_META_TYPE_ANY);
			void **it;
			rz_pvector_foreach (list, it) {
				RzIntervalNode *node = *it;
				RzAnalysisMetaItem *meta = node->data;
				switch (meta->type) {
				case RZ_META_TYPE_DATA:
				case RZ_META_TYPE_STRING:
				case RZ_META_TYPE_FORMAT:
					i += 4;
					rz_pvector_free(list);
					goto repeat;
				default:
					break;
				}
			}
			rz_pvector_free(list);
		}

		/* realign address if needed */
		rz_core_seek_arch_bits(core, cur);
		int opalign = rz_analysis_get_pc_align(core->analysis);
		if (opalign > 1) {
			cur -= (cur % opalign);
		}

		rz_analysis_op_fini(&op);
		rz_asm_set_pc(core->rasm, cur);
		if (i >= iend) {
			goto repeat;
		}
		rz_analysis_op_init(&op);
		rz_analysis_op(core->analysis, &op, cur, buf + i, iend - i, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT);
		// if (op.type & 0x80000000 || op.type == 0) {
		if (op.type == RZ_ANALYSIS_OP_TYPE_ILL || op.type == RZ_ANALYSIS_OP_TYPE_UNK) {
			// i += 2
			rz_analysis_op_fini(&op);
			goto repeat;
		}
		// we need to check again i because buf+i may goes beyond its boundaries
		// because of i+= minopsize - 1
		if (i > iend) {
			goto repeat;
		}
		if (op.size < 1) {
			i += minopsize - 1;
			goto repeat;
		}
		if (emu_lazy) {
			if (op.type & RZ_ANALYSIS_OP_TYPE_REP) {
				i += op.size - 1;
				goto repeat;
			}
			switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
			case RZ_ANALYSIS_OP_TYPE_CJMP:
			case RZ_ANALYSIS_OP_TYPE_CALL:
			case RZ_ANALYSIS_OP_TYPE_RET:
			case RZ_ANALYSIS_OP_TYPE_ILL:
			case RZ_ANALYSIS_OP_TYPE_NOP:
			case RZ_ANALYSIS_OP_TYPE_UJMP:
			case RZ_ANALYSIS_OP_TYPE_IO:
			case RZ_ANALYSIS_OP_TYPE_LEAVE:
			case RZ_ANALYSIS_OP_TYPE_CRYPTO:
			case RZ_ANALYSIS_OP_TYPE_CPL:
			case RZ_ANALYSIS_OP_TYPE_SYNC:
			case RZ_ANALYSIS_OP_TYPE_SWI:
			case RZ_ANALYSIS_OP_TYPE_CMP:
			case RZ_ANALYSIS_OP_TYPE_ACMP:
			case RZ_ANALYSIS_OP_TYPE_NULL:
			case RZ_ANALYSIS_OP_TYPE_CSWI:
			case RZ_ANALYSIS_OP_TYPE_TRAP:
				i += op.size - 1;
				goto repeat;
			//  those require write support
			case RZ_ANALYSIS_OP_TYPE_PUSH:
			case RZ_ANALYSIS_OP_TYPE_POP:
				i += op.size - 1;
				goto repeat;
			}
		}
		if (sn && op.type == RZ_ANALYSIS_OP_TYPE_SWI) {
			char tmpbuf[256];
			rz_flag_space_set(core->flags, RZ_FLAGS_FS_SYSCALLS);
			int snv = (arch == RZ_ARCH_THUMB) ? op.val : (int)rz_reg_getv(rreg, sn);
			RzSyscall *sysc = rz_analysis_get_syscall(core->analysis);
			RzSyscallItem *si = rz_syscall_get(sysc, snv, -1);
			if (si) {
				//	eprintf ("0x%08"PFMT64x" SYSCALL %-4d %s\n", cur, snv, si->name);
				rz_flag_set_next(core->flags, rz_strf(tmpbuf, "syscall.%s", si->name), cur, 1);
				rz_syscall_item_free(si);
			} else {
				// todo were doing less filtering up top because we can't match against 80 on all platforms
				//  might get too many of this path now..
				//	eprintf ("0x%08"PFMT64x" SYSCALL %d\n", cur, snv);
				rz_flag_set_next(core->flags, rz_strf(tmpbuf, "syscall.%d", snv), cur, 1);
			}
			rz_flag_space_set(core->flags, NULL);
		}
		const char *esilstr = RZ_STRBUF_SAFEGET(&op.esil);
		i += op.size - 1;
		if (!esilstr || !*esilstr) {
			goto repeat;
		}
		rz_analysis_esil_set_pc(esil, cur);
		rz_reg_setv(rreg, pcname, cur + op.size);
		if (gp_fixed && gp_reg) {
			rz_reg_setv(rreg, gp_reg, gp);
		}
		(void)rz_analysis_esil_parse(esil, esilstr);
#define CHECKREF(x) ((refptr && (x) == refptr) || !refptr)
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_LEA:
			// arm64
			if (arch == RZ_ARCH_ARM64) {
				if (CHECKREF(esil->cur)) {
					rz_analysis_xrefs_set(core->analysis, cur, esil->cur, RZ_ANALYSIS_XREF_TYPE_STRING);
				}
			}
			if (CHECKREF(esil->cur)) {
				const RzAnalysisOptions *opts = rz_analysis_get_options(core->analysis);
				if (op.ptr && rz_io_is_valid_offset(core->io, op.ptr, !opts->noncode)) {
					rz_analysis_xrefs_set(core->analysis, cur, op.ptr, RZ_ANALYSIS_XREF_TYPE_STRING);
				} else {
					rz_analysis_xrefs_set(core->analysis, cur, esil->cur, RZ_ANALYSIS_XREF_TYPE_STRING);
				}
			}
			if (cfg_analysis_strings) {
				rz_core_add_string_ref(core, op.addr, op.ptr);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_ADD:
			/* TODO: test if this is valid for other archs too */
			if (archIsArm) {
				/* This code is known to work on Thumb, ARM and ARM64 */
				ut64 dst = esil->cur;
				if (CHECKREF(dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
				}
				if (cfg_analysis_strings) {
					rz_core_add_string_ref(core, op.addr, dst);
				}
			} else if (rz_asm_is_bits(core->rasm, 32) && arch == RZ_ARCH_MIPS) {
				ut64 dst = esil->cur;
				if (!op.src[0] || !op.src[0]->reg || !op.src[0]->reg->name) {
					break;
				}
				if (!strcmp(op.src[0]->reg->name, "sp")) {
					break;
				}
				if (!strcmp(op.src[0]->reg->name, "zero")) {
					break;
				}
				if (dst > 0xffff && op.src[1] && (dst & 0xffff) == (op.src[1]->imm & 0xffff) && myvalid(core->io, dst)) {
					RzFlagItem *f;
					char *str = NULL;
					if (CHECKREF(dst) || CHECKREF(cur)) {
						rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
						if (cfg_analysis_strings) {
							rz_core_add_string_ref(core, op.addr, dst);
						}
						if ((f = rz_core_flag_get_by_spaces(core->flags, dst))) {
							rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, f->name);
						} else if (rz_core_get_string_at(core, dst, &str, NULL, NULL, true)) {
							char *str2 = rz_str_newf("esilref: '%s'", str);
							// HACK avoid format string inside string used later as format
							// string crashes disasm inside agf under some conditions.
							rz_str_replace_char(str2, '%', '&');
							rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, str2);
							free(str);
							free(str2);
						}
					}
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD: {
			ut64 dst = estate->last_read;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
					if (cfg_analysis_strings) {
						rz_core_add_string_ref(core, op.addr, dst);
					}
				}
			}
			dst = estate->last_data;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
					if (cfg_analysis_strings) {
						rz_core_add_string_ref(core, op.addr, dst);
					}
				}
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_JMP: {
			ut64 dst = op.jump;
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_CALL: {
			ut64 dst = op.jump;
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_CALL);
				}
				esil->old = cur + op.size;
				getpcfromstack(core, esil);
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
		case RZ_ANALYSIS_OP_TYPE_MJMP: {
			ut64 dst = esil->jump_target;
			if (dst == 0 || dst == UT64_MAX) {
				dst = rz_reg_getv(rreg, pcname);
			}
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					RzAnalysisXRefType ref =
						(op.type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_UCALL
						? RZ_ANALYSIS_XREF_TYPE_CALL
						: RZ_ANALYSIS_XREF_TYPE_CODE;
					rz_analysis_xrefs_set(core->analysis, cur, dst, ref);
					rz_core_analysis_fcn(core, dst, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
				}
			}
		} break;
		default:
			break;
		}
		rz_analysis_esil_stack_free(esil);
	repeat:
		if (!rz_analysis_get_block_at(core->analysis, cur)) {
			for (size_t bb_i = i_old + 1; bb_i <= i; bb_i++) {
				if (rz_analysis_get_block_at(core->analysis, start + bb_i)) {
					i = bb_i - 1;
					break;
				}
			}
		}
		if (i > iend) {
			break;
		}
	} while (get_next_i(&ictx, &i));
#undef CHECKREF
	free(buf);
	esil->cb.hook_mem_read = NULL;
	esil->cb.hook_mem_write = NULL;
	esil->cb.hook_reg_write = NULL;
	esil->user = NULL;
	rz_analysis_op_fini(&op);
	rz_cons_break_pop();
out_pop_regs:
	// restore register
	rz_reg_arena_pop(rreg);
}
