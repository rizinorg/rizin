// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include "core_private.h"

static bool is_x86_call(RzDebug *dbg, ut64 addr) {
	ut8 buf[3];
	ut8 *op = buf;
	(void)dbg->iob.read_at(dbg->iob.io, addr, buf, RZ_ARRAY_SIZE(buf));
	switch (buf[0]) { /* Segment override prefixes */
	case 0x65:
	case 0x64:
	case 0x26:
	case 0x3e:
	case 0x36:
	case 0x2e:
		op++;
	}
	if (op[0] == 0xe8) {
		return true;
	}
	if (op[0] == 0xff /* bits 4-5 (from right) of next byte must be 01 */
		&& (op[1] & 0x30) == 0x10) {
		return true;
	}
	/* ... */
	return false;
}

static bool is_x86_ret(RzDebug *dbg, ut64 addr) {
	ut8 buf[1];
	(void)dbg->iob.read_at(dbg->iob.io, addr, buf, RZ_ARRAY_SIZE(buf));
	switch (buf[0]) {
	case 0xc3:
	case 0xcb:
	case 0xc2:
	case 0xca:
		return true;
	default:
		return false;
	}
	/* Possibly incomplete with regard to instruction prefixes */
}

RZ_API bool rz_core_debug_step_one(RzCore *core, int times) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		rz_reg_arena_swap(core->dbg->reg, true);
		// sync registers for BSD PT_STEP/PT_CONT
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
		ut64 pc = rz_debug_reg_get(core->dbg, "PC");
		rz_debug_trace_pc(core->dbg, pc);
		if (!rz_debug_step(core->dbg, times)) {
			eprintf("Step failed\n");
			rz_core_debug_regs2flags(core);
			core->break_loop = true;
			return false;
		}
		rz_core_debug_regs2flags(core);
	} else {
		int i = 0;
		do {
			rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			rz_core_regs2flags(core);
			i++;
		} while (i < times);
	}
	return true;
}

RZ_IPI void rz_core_debug_continue(RzCore *core) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		rz_cons_break_push(rz_core_static_debug_stop, core->dbg);
		rz_reg_arena_swap(core->dbg->reg, true);
#if __linux__
		core->dbg->continue_all_threads = true;
#endif
		rz_debug_continue(core->dbg);
		rz_core_debug_regs2flags(core);
		rz_cons_break_pop();
		rz_core_dbg_follow_seek_register(core);
	} else {
		rz_core_esil_step(core, UT64_MAX, "0", NULL, false);
		rz_core_regs2flags(core);
	}
}

RZ_API bool rz_core_debug_continue_until(RzCore *core, ut64 addr, ut64 to) {
	ut64 pc;
	if (!strcmp(core->dbg->btalgo, "trace") && core->dbg->arch && !strcmp(core->dbg->arch, "x86") && core->dbg->bits == 4) {
		unsigned long steps = 0;
		long level = 0;
		const char *pc_name = core->dbg->reg->name[RZ_REG_NAME_PC];
		ut64 prev_pc = UT64_MAX;
		bool prev_call = false;
		bool prev_ret = false;
		const char *sp_name = core->dbg->reg->name[RZ_REG_NAME_SP];
		ut64 old_sp, cur_sp;
		rz_cons_break_push(NULL, NULL);
		rz_list_free(core->dbg->call_frames);
		core->dbg->call_frames = rz_list_new();
		core->dbg->call_frames->free = free;
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
		old_sp = rz_debug_reg_get(core->dbg, sp_name);
		while (true) {
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
			pc = rz_debug_reg_get(core->dbg, pc_name);
			if (prev_call) {
				ut32 ret_addr;
				RzDebugFrame *frame = RZ_NEW0(RzDebugFrame);
				cur_sp = rz_debug_reg_get(core->dbg, sp_name);
				(void)core->dbg->iob.read_at(core->dbg->iob.io, cur_sp, (ut8 *)&ret_addr,
					sizeof(ret_addr));
				frame->addr = ret_addr;
				frame->size = old_sp - cur_sp;
				frame->sp = cur_sp;
				frame->bp = old_sp;
				rz_list_prepend(core->dbg->call_frames, frame);
				eprintf("%ld Call from 0x%08" PFMT64x " to 0x%08" PFMT64x " ret 0x%08" PFMT32x "\n",
					level, prev_pc, pc, ret_addr);
				level++;
				old_sp = cur_sp;
				prev_call = false;
			} else if (prev_ret) {
				RzDebugFrame *head = rz_list_get_bottom(core->dbg->call_frames);
				if (head && head->addr != pc) {
					eprintf("*");
				} else {
					rz_list_pop_head(core->dbg->call_frames);
					eprintf("%ld", level);
					level--;
				}
				eprintf(" Ret from 0x%08" PFMT64x " to 0x%08" PFMT64x "\n",
					prev_pc, pc);
				prev_ret = false;
			}
			if (steps % 500 == 0 || pc == addr) {
				eprintf("At 0x%08" PFMT64x " after %lu steps\n", pc, steps);
			}
			if (rz_cons_is_breaked() || rz_debug_is_dead(core->dbg) || pc == addr) {
				break;
			}
			if (is_x86_call(core->dbg, pc)) {
				prev_pc = pc;
				prev_call = true;
			} else if (is_x86_ret(core->dbg, pc)) {
				prev_pc = pc;
				prev_ret = true;
			}
			rz_debug_step(core->dbg, 1);
			steps++;
		}
		rz_core_debug_regs2flags(core);
		rz_cons_break_pop();
		return true;
	}
	eprintf("Continue until 0x%08" PFMT64x " using %d bpsize\n", addr, core->dbg->bpsize);
	rz_reg_arena_swap(core->dbg->reg, true);
	if (rz_bp_add_sw(core->dbg->bp, addr, core->dbg->bpsize, RZ_PERM_X)) {
		if (rz_debug_is_dead(core->dbg)) {
			eprintf("Cannot continue, run ood?\n");
		} else {
			rz_debug_continue(core->dbg);
			rz_core_debug_regs2flags(core);
		}
		rz_bp_del(core->dbg->bp, addr);
	} else {
		eprintf("Cannot set breakpoint of size %d at 0x%08" PFMT64x "\n",
			core->dbg->bpsize, addr);
		return false;
	}
	return true;
}

/// Construct the list of registers that should be applied as flags by default
/// (e.g. because their size matches the pointer size)
RZ_IPI RzList /*<RzRegItem>*/ *rz_core_regs2flags_candidates(RzCore *core, RzReg *reg) {
	const RzList *l = rz_reg_get_list(core->dbg->reg, RZ_REG_TYPE_GPR);
	if (!l) {
		return NULL;
	}
	int size = rz_analysis_get_address_bits(core->analysis);
	RzList *ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	RzListIter *iter;
	RzRegItem *item;
	rz_list_foreach (l, iter, item) {
		if (size != 0 && size != item->size) {
			continue;
		}
		rz_list_push(ret, item);
	}
	return ret;
}

static void regs_to_flags(RzCore *core) {
	RzList *l = rz_core_regs2flags_candidates(core, core->dbg->reg);
	if (!l) {
		return;
	}
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_REGISTERS);
	RzListIter *iter;
	RzRegItem *reg;
	rz_list_foreach (l, iter, reg) {
		ut64 regval = rz_reg_get_value(core->dbg->reg, reg);
		rz_flag_set(core->flags, reg->name, regval, reg->size / 8);
	}
	rz_flag_space_pop(core->flags);
	rz_list_free(l);
}

RZ_IPI void rz_core_regs2flags(RzCore *core) {
	regs_to_flags(core);
}

/// update or create flags for all registers where it makes sense (regs that have the same size as an address)
RZ_IPI void rz_core_debug_regs2flags(RzCore *core) {
	if (core->bin->is_debugger) {
		if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
			regs_to_flags(core);
		}
	} else {
		rz_core_regs2flags(core);
	}
}

RZ_IPI bool rz_core_debug_reg_set(RzCore *core, const char *regname, ut64 val, const char *strval) {
	RzRegItem *r = rz_reg_get(core->dbg->reg, regname, -1);
	if (!r) {
		int role = rz_reg_get_name_idx(regname);
		if (role != -1) {
			const char *alias = rz_reg_get_name(core->dbg->reg, role);
			if (alias) {
				r = rz_reg_get(core->dbg->reg, alias, -1);
			}
		}
	}
	if (!r) {
		eprintf("Unknown register '%s'\n", regname);
		return false;
	}

	if (r->flags) {
		if (strval) {
			rz_reg_set_bvalue(core->dbg->reg, r, strval);
		} else {
			eprintf("String value cannot be NULL\n");
			return false;
		}
	} else {
		rz_reg_set_value(core->dbg->reg, r, val);
	}
	rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ANY, true);
	rz_core_debug_regs2flags(core);
	return true;
}

RZ_IPI bool rz_core_debug_reg_list(RzCore *core, int type, int size, bool skip_covered, PJ *pj, int rad, const char *use_color) {
	RzDebug *dbg = core->dbg;
	int delta, cols, n = 0;
	const char *fmt, *fmt2, *kwhites;
	RzPrint *pr = NULL;
	int colwidth = 20;
	ut64 diff;
	char strvalue[256];
	bool isJson = (rad == 'j' || rad == 'J');
	if (!dbg || !dbg->reg) {
		return false;
	}
	if (dbg->corebind.core) {
		pr = ((RzCore *)dbg->corebind.core)->print;
	}
	if (size != 0 && !(dbg->reg->bits & size)) {
		// TODO: verify if 32bit exists, otherwise use 64 or 8?
		size = 32;
	}
	if (dbg->bits & RZ_SYS_BITS_64) {
		// fmt = "%s = 0x%08"PFMT64x"%s";
		fmt = "%s = %s%s";
		fmt2 = "%s%7s%s %s%s";
		kwhites = "         ";
		colwidth = dbg->regcols ? 20 : 25;
		cols = 3;
	} else {
		// fmt = "%s = 0x%08"PFMT64x"%s";
		fmt = "%s = %s%s";
		fmt2 = "%s%7s%s %s%s";
		kwhites = "    ";
		colwidth = 20;
		cols = 4;
	}
	if (dbg->regcols) {
		cols = dbg->regcols;
	}
	if (isJson) {
		pj_o(pj);
	}
	// with the new field "arena" into reg items why need
	// to get all arenas.

	int itmidx = -1;
	dbg->creg = NULL;
	const RzList *head = rz_reg_get_list(dbg->reg, type);
	if (!head) {
		return false;
	}
	if (rad == 1 || rad == '*') {
		rz_cons_printf("fs+%s\n", RZ_FLAGS_FS_REGISTERS);
	}
	RzList *filtered_list = NULL;
	if (skip_covered) {
		filtered_list = rz_reg_filter_items_covered(head);
		if (filtered_list) {
			head = filtered_list;
		}
	}
	RzListIter *iter;
	RzRegItem *item;
	rz_list_foreach (head, iter, item) {
		ut64 value;
		utX valueBig;
		if (type != -1) {
			if (type != item->type && RZ_REG_TYPE_FLG != item->type) {
				continue;
			}
			if (size != 0 && size != item->size) {
				continue;
			}
		}
		// Is this register being asked?
		if (dbg->q_regs) {
			if (!rz_list_empty(dbg->q_regs)) {
				RzListIter *iterreg;
				RzList *q_reg = dbg->q_regs;
				char *q_name;
				bool found = false;
				rz_list_foreach (q_reg, iterreg, q_name) {
					if (!strcmp(item->name, q_name)) {
						found = true;
						break;
					}
				}
				if (!found) {
					continue;
				}
				rz_list_delete(q_reg, iterreg);
			} else {
				// List is empty, all requested regs were taken, no need to go further
				goto beach;
			}
		}
		int regSize = item->size;
		if (regSize < 80) {
			value = rz_reg_get_value(dbg->reg, item);
			rz_reg_arena_swap(dbg->reg, false);
			diff = rz_reg_get_value(dbg->reg, item);
			rz_reg_arena_swap(dbg->reg, false);
			delta = value - diff;
			if (isJson) {
				pj_kn(pj, item->name, value);
			} else {
				if (pr && pr->wide_offsets && dbg->bits & RZ_SYS_BITS_64) {
					snprintf(strvalue, sizeof(strvalue), "0x%016" PFMT64x, value);
				} else {
					snprintf(strvalue, sizeof(strvalue), "0x%08" PFMT64x, value);
				}
			}
		} else {
			rz_reg_get_value_big(dbg->reg, item, &valueBig);
			switch (regSize) {
			case 80:
				snprintf(strvalue, sizeof(strvalue), "0x%04x%016" PFMT64x "", valueBig.v80.High, valueBig.v80.Low);
				break;
			case 96:
				snprintf(strvalue, sizeof(strvalue), "0x%08x%016" PFMT64x "", valueBig.v96.High, valueBig.v96.Low);
				break;
			case 128:
				snprintf(strvalue, sizeof(strvalue), "0x%016" PFMT64x "%016" PFMT64x "", valueBig.v128.High, valueBig.v128.Low);
				break;
			case 256:
				snprintf(strvalue, sizeof(strvalue), "0x%016" PFMT64x "%016" PFMT64x "%016" PFMT64x "%016" PFMT64x "",
					valueBig.v256.High.High, valueBig.v256.High.Low, valueBig.v256.Low.High, valueBig.v256.Low.Low);
				break;
			default:
				snprintf(strvalue, sizeof(strvalue), "ERROR");
			}
			if (isJson) {
				pj_ks(pj, item->name, strvalue);
			}
			delta = 0; // TODO: calculate delta with big values.
		}
		itmidx++;

		if (isJson) {
			continue;
		}
		switch (rad) {
		case '-':
			rz_cons_printf("f-%s\n", item->name);
			break;
		case 'R':
			rz_cons_printf("aer %s = %s\n", item->name, strvalue);
			break;
		case 1:
		case '*':
			rz_cons_printf("f %s %d %s\n", item->name, item->size / 8, strvalue);
			break;
		case '.':
			rz_cons_printf("dr %s=%s\n", item->name, strvalue);
			break;
		case '=': {
			int len, highlight = use_color && pr && pr->cur_enabled && itmidx == pr->cur;
			char whites[32], content[300];
			const char *a = "", *b = "";
			if (highlight) {
				a = Color_INVERT;
				b = Color_INVERT_RESET;
				dbg->creg = item->name;
			}
			strcpy(whites, kwhites);
			if (delta && use_color) {
				rz_cons_printf("%s", use_color);
			}
			snprintf(content, sizeof(content),
				fmt2, "", item->name, "", strvalue, "");
			len = colwidth - strlen(content);
			if (len < 0) {
				len = 0;
			}
			memset(whites, ' ', sizeof(whites));
			whites[len] = 0;
			rz_cons_printf(fmt2, a, item->name, b, strvalue,
				((n + 1) % cols) ? whites : "\n");
			if (highlight) {
				rz_cons_printf(Color_INVERT_RESET);
			}
			if (delta && use_color) {
				rz_cons_printf(Color_RESET);
			}
		} break;
		case 'd':
		case 3:
			if (delta) {
				char woot[512];
				snprintf(woot, sizeof(woot),
					" was 0x%" PFMT64x " delta %d\n", diff, delta);
				rz_cons_printf(fmt, item->name, strvalue, woot);
			}
			break;
		default:
			if (delta && use_color) {
				rz_cons_printf("%s", use_color);
				rz_cons_printf(fmt, item->name, strvalue, Color_RESET "\n");
			} else {
				rz_cons_printf(fmt, item->name, strvalue, "\n");
			}
			break;
		}
		n++;
	}
	if (rad == 1 || rad == '*') {
		rz_cons_printf("fs-\n");
	}
beach:
	rz_list_free(filtered_list);
	if (isJson) {
		pj_end(pj);
	} else if (n > 0 && (rad == 2 || rad == '=') && ((n % cols))) {
		rz_cons_printf("\n");
	}
	return n != 0;
}

RZ_IPI void rz_core_debug_sync_bits(RzCore *core) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		ut64 asm_bits = rz_config_get_i(core->config, "asm.bits");
		if (asm_bits != core->dbg->bits * 8) {
			rz_config_set_i(core->config, "asm.bits", core->dbg->bits * 8);
		}
	}
}

RZ_IPI void rz_core_debug_single_step_in(RzCore *core) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			rz_core_debug_continue_until(core, core->offset, core->offset + core->print->cur);
			core->print->cur_enabled = 0;
		} else {
			rz_core_debug_step_one(core, 1);
		}
	} else {
		rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
		rz_core_regs2flags(core);
	}
}

RZ_IPI void rz_core_debug_single_step_over(RzCore *core) {
	bool io_cache = rz_config_get_b(core->config, "io.cache");
	rz_config_set_b(core->config, "io.cache", false);
	if (rz_config_get_b(core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			rz_cons_break_push(rz_core_static_debug_stop, core->dbg);
			rz_reg_arena_swap(core->dbg->reg, true);
			rz_debug_continue_until_optype(core->dbg, RZ_ANALYSIS_OP_TYPE_RET, 1);
			rz_core_debug_regs2flags(core);
			rz_cons_break_pop();
			rz_core_dbg_follow_seek_register(core);
			core->print->cur_enabled = 0;
		} else {
			rz_core_cmd(core, "dso", 0);
			rz_core_debug_regs2flags(core);
		}
	} else {
		rz_core_analysis_esil_step_over(core);
	}
	rz_config_set_b(core->config, "io.cache", io_cache);
}

RZ_IPI void rz_core_debug_breakpoint_toggle(RzCore *core, ut64 addr) {
	RzBreakpointItem *bpi = rz_bp_get_at(core->dbg->bp, addr);
	if (bpi) {
		rz_bp_del(core->dbg->bp, addr);
	} else {
		int hwbp = rz_config_get_i(core->config, "dbg.hwbp");
		bpi = rz_debug_bp_add(core->dbg, addr, hwbp, false, 0, NULL, 0);
		if (!bpi) {
			eprintf("Cannot set breakpoint at 0x%" PFMT64x "\n", addr);
		}
	}
	rz_bp_enable(core->dbg->bp, addr, true, 0);
}

/**
 * \brief Put a breakpoint into every no-return function
 *
 * \param core Current RzCore instance
 * \return void
 */
RZ_API void rz_core_debug_bp_add_noreturn_func(RzCore *core) {
	RzList *symbols = rz_bin_get_symbols(core->bin);
	if (!symbols) {
		RZ_LOG_ERROR("Unable to find symbols in the binary\n");
		return;
	}
	RzBinSymbol *symbol;
	RzListIter *iter;
	RzBreakpointItem *bp;
	int hwbp = rz_config_get_i(core->config, "dbg.hwbp");
	rz_list_foreach (symbols, iter, symbol) {
		if (symbol->type && !strcmp(symbol->type, RZ_BIN_TYPE_FUNC_STR)) {
			if (rz_analysis_noreturn_at(core->analysis, symbol->vaddr)) {
				bp = rz_debug_bp_add(core->dbg, symbol->vaddr, hwbp, false, 0, NULL, 0);
				if (!bp) {
					RZ_LOG_ERROR("Unable to add a breakpoint into a noreturn function %s at addr 0x%" PFMT64x "\n", symbol->name, symbol->vaddr);
					return;
				}
				char *name = rz_str_newf("%s.%s", "sym", symbol->name);
				if (!rz_bp_item_set_name(bp, name)) {
					RZ_LOG_ERROR("Failed to set name for breakpoint at 0x%" PFMT64x "\n", symbol->vaddr);
				}
				free(name);
			}
		}
	}
}

RZ_IPI void rz_core_debug_attach(RzCore *core, int pid) {
	rz_debug_reg_profile_sync(core->dbg);
	if (pid > 0) {
		rz_debug_attach(core->dbg, pid);
	} else {
		if (core->file && core->io) {
			rz_debug_attach(core->dbg, rz_io_fd_get_pid(core->io, core->file->fd));
		}
	}
	rz_debug_select(core->dbg, core->dbg->pid, core->dbg->tid);
	rz_config_set_i(core->config, "dbg.swstep", (core->dbg->cur && !core->dbg->cur->canstep));
	rz_core_cmdf(core, "R! \"pid %d\"", core->dbg->pid);
}

RZ_API RzCmdStatus rz_core_debug_plugin_print(RzDebug *dbg, RzDebugPlugin *plugin, RzCmdStateOutput *state, int count, char *spaces) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_printf("%s\n", plugin->name);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "arch", plugin->arch);
		pj_ks(pj, "name", plugin->name);
		pj_ks(pj, "license", plugin->license);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("%d  %s  %s %s%s\n",
			count, (plugin == dbg->cur) ? "dbg" : "---",
			plugin->name, spaces, plugin->license);
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_debug_plugins_print(RzCore *core, RzCmdStateOutput *state) {
	int count = 0;
	char spaces[16];
	memset(spaces, ' ', 15);
	spaces[15] = 0;
	RzDebug *dbg = core->dbg;
	RzListIter *iter;
	RzDebugPlugin *plugin;
	RzCmdStatus status;
	if (!dbg) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (dbg->plugins, iter, plugin) {
		int sp = 8 - strlen(plugin->name);
		spaces[sp] = 0;
		status = rz_core_debug_plugin_print(dbg, plugin, state, count, spaces);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
		spaces[sp] = ' ';
		count++;
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI void rz_core_debug_print_status(RzCore *core) {
	const char *use_color = core->cons->context->pal.creg
		? core->cons->context->pal.creg
		: Color_BWHITE;
	rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, core->dbg->bits, true, NULL, 3, use_color);
	ut64 old_address = core->offset;
	rz_core_seek(core, rz_debug_reg_get(core->dbg, "PC"), true);
	rz_core_print_disasm_instructions(core, 0, 1);
	rz_core_seek(core, old_address, true);
	rz_cons_flush();
}

/* Print out the JSON body for memory maps in the passed map region */
static void print_debug_map_json(RzDebugMap *map, PJ *pj) {
	pj_o(pj);
	if (map->name && *map->name) {
		pj_ks(pj, "name", map->name);
	}
	if (map->file && *map->file) {
		pj_ks(pj, "file", map->file);
	}
	pj_kn(pj, "addr", map->addr);
	pj_kn(pj, "addr_end", map->addr_end);
	pj_ks(pj, "type", map->user ? "u" : "s");
	pj_ks(pj, "perm", rz_str_rwx_i(map->perm));
	pj_end(pj);
}

/* Write a single memory map line to the console */
static void print_debug_map_line(RzDebug *dbg, RzDebugMap *map, ut64 addr, RzOutputMode mode) {
	char humansz[8];
	if (mode == RZ_OUTPUT_MODE_QUIET) { // "dmq"
		char *name = (map->name && *map->name)
			? rz_str_newf("%s.%s", map->name, rz_str_rwx_i(map->perm))
			: rz_str_newf("%08" PFMT64x ".%s", map->addr, rz_str_rwx_i(map->perm));
		rz_name_filter(name, 0, true);
		rz_num_units(humansz, sizeof(humansz), map->addr_end - map->addr);
		rz_cons_printf("0x%016" PFMT64x " - 0x%016" PFMT64x " %6s %5s %s\n",
			map->addr,
			map->addr_end,
			humansz,
			rz_str_rwx_i(map->perm),
			name);
		free(name);
	} else {
		const char *fmtstr = dbg->bits & RZ_SYS_BITS_64
			? "0x%016" PFMT64x " - 0x%016" PFMT64x " %c %s %6s %c %s %s %s%s%s\n"
			: "0x%08" PFMT64x " - 0x%08" PFMT64x " %c %s %6s %c %s %s %s%s%s\n";
		const char *type = map->shared ? "sys" : "usr";
		const char *flagname = dbg->corebind.getName
			? dbg->corebind.getName(dbg->corebind.core, map->addr)
			: NULL;
		if (!flagname) {
			flagname = "";
		} else if (map->name) {
			char *filtered_name = strdup(map->name);
			rz_name_filter(filtered_name, 0, true);
			if (!strncmp(flagname, "map.", 4) &&
				!strcmp(flagname + 4, filtered_name)) {
				flagname = "";
			}
			free(filtered_name);
		}
		rz_num_units(humansz, sizeof(humansz), map->size);
		rz_cons_printf(fmtstr,
			map->addr,
			map->addr_end,
			(addr >= map->addr && addr < map->addr_end) ? '*' : '-',
			type,
			humansz,
			map->user ? 'u' : 's',
			rz_str_rwx_i(map->perm),
			map->name ? map->name : "?",
			map->file ? map->file : "?",
			*flagname ? " ; " : "",
			flagname);
	}
}

RZ_API void rz_debug_map_print(RzDebug *dbg, ut64 addr, RzCmdStateOutput *state) {
	int i;
	RzListIter *iter;
	RzDebugMap *map;
	PJ *pj = state->d.pj;
	if (!dbg) {
		return;
	}
	RzOutputMode mode = state->mode;
	rz_cmd_state_output_array_start(state);
	for (i = 0; i < 2; i++) { // Iterate over dbg::maps and dbg::maps_user
		RzList *maps = rz_debug_map_list(dbg, (bool)i);
		rz_list_foreach (maps, iter, map) {
			switch (mode) {
			case RZ_OUTPUT_MODE_JSON: // "dmj"
				print_debug_map_json(map, pj);
				break;
			case RZ_OUTPUT_MODE_RIZIN: // "dm*"
			{
				char *name = (map->name && *map->name)
					? rz_str_newf("%s.%s", map->name, rz_str_rwx_i(map->perm))
					: rz_str_newf("%08" PFMT64x ".%s", map->addr, rz_str_rwx_i(map->perm));
				rz_name_filter(name, 0, true);
				rz_cons_printf("f map.%s 0x%08" PFMT64x " 0x%08" PFMT64x "\n",
					name, map->addr_end - map->addr + 1, map->addr);
				free(name);
			} break;
			case RZ_OUTPUT_MODE_QUIET: // "dmq"
				print_debug_map_line(dbg, map, addr, mode);
				break;
			case RZ_OUTPUT_MODE_LONG: // workaround for '.'
				if (addr >= map->addr && addr < map->addr_end) {
					print_debug_map_line(dbg, map, addr, mode);
				}
				break;
			default:
				print_debug_map_line(dbg, map, addr, mode);
				break;
			}
		}
	}
	rz_cmd_state_output_array_end(state);
}

static int cmp(const void *a, const void *b) {
	RzDebugMap *ma = (RzDebugMap *)a;
	RzDebugMap *mb = (RzDebugMap *)b;
	return ma->addr - mb->addr;
}

/**
 * \brief Find the min and max addresses in an RzList of maps.
 * \param maps RzList of maps that will be searched through
 * \param min Pointer to a ut64 that the min will be stored in
 * \param max Pointer to a ut64 that the max will be stored in
 * \param skip How many maps to skip at the start of iteration
 * \param width Divisor for the return value
 * \return (max-min)/width
 *
 * Used to determine the min & max addresses of maps and
 * scale the ascii bar to the width of the terminal
 */
static int findMinMax(RzList *maps, ut64 *min, ut64 *max, int skip, int width) {
	RzDebugMap *map;
	RzListIter *iter;
	*min = UT64_MAX;
	*max = 0;
	rz_list_foreach (maps, iter, map) {
		if (skip > 0) {
			skip--;
			continue;
		}
		if (map->addr < *min) {
			*min = map->addr;
		}
		if (map->addr_end > *max) {
			*max = map->addr_end;
		}
	}
	return (int)(*max - *min) / width;
}

static void print_debug_maps_ascii_art(RzDebug *dbg, RzList *maps, ut64 addr, int colors) {
	ut64 mul; // The amount of address space a single console column will represent in bar graph
	ut64 min = -1, max = 0;
	int width = rz_cons_get_size(NULL) - 90;
	RzListIter *iter;
	RzDebugMap *map;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (width < 1) {
		width = 30;
	}
	rz_list_sort(maps, cmp);
	mul = findMinMax(maps, &min, &max, 0, width);
	ut64 last = min;
	if (min != -1 && mul != 0) {
		const char *color_prefix = ""; // Color escape code prefixed to string (address coloring)
		const char *color_suffix = ""; // Color escape code appended to end of string
		const char *fmtstr;
		char humansz[8]; // Holds the human formatted size string [124K]
		int skip = 0; // Number of maps to skip when re-calculating the minmax
		rz_list_foreach (maps, iter, map) {
			rz_num_units(humansz, sizeof(humansz), map->size); // Convert map size to human readable string
			if (colors) {
				color_suffix = Color_RESET;
				if ((map->perm & 2) && (map->perm & 1)) { // Writable & Executable
					color_prefix = pal->widget_sel;
				} else if (map->perm & 2) { // Writable
					color_prefix = pal->graph_false;
				} else if (map->perm & 1) { // Executable
					color_prefix = pal->graph_true;
				} else {
					color_prefix = "";
					color_suffix = "";
				}
			} else {
				color_prefix = "";
				color_suffix = "";
			}
			if ((map->addr - last) > UT32_MAX) { // TODO: Comment what this is for
				mul = findMinMax(maps, &min, &max, skip, width); //  Recalculate minmax
			}
			skip++;
			fmtstr = dbg->bits & RZ_SYS_BITS_64 // Prefix formatting string (before bar)
				? "map %4.8s %c %s0x%016" PFMT64x "%s |"
				: "map %4.8s %c %s0x%08" PFMT64x "%s |";
			rz_cons_printf(fmtstr, humansz,
				(addr >= map->addr &&
					addr < map->addr_end)
					? '*'
					: '-',
				color_prefix, map->addr, color_suffix); // * indicates map is within our current sought offset
			int col;
			for (col = 0; col < width; col++) { // Iterate over the available width/columns for bar graph
				ut64 pos = min + (col * mul); // Current address space to check
				ut64 npos = min + ((col + 1) * mul); // Next address space to check
				if (map->addr < npos && map->addr_end > pos) {
					rz_cons_printf("#"); // TODO: Comment what a # represents
				} else {
					rz_cons_printf("-");
				}
			}
			fmtstr = dbg->bits & RZ_SYS_BITS_64 ? // Suffix formatting string (after bar)
				"| %s0x%016" PFMT64x "%s %s %s\n"
							    : "| %s0x%08" PFMT64x "%s %s %s\n";
			rz_cons_printf(fmtstr, color_prefix, map->addr_end, color_suffix,
				rz_str_rwx_i(map->perm), map->name);
			last = map->addr;
		}
	}
}

RZ_API void rz_debug_map_list_visual(RzDebug *dbg, ut64 addr, const char *input, int colors) {
	if (!dbg) {
		return;
	}
	int i;
	for (i = 0; i < 2; i++) { // Iterate over dbg::maps and dbg::maps_user
		RzList *maps = rz_debug_map_list(dbg, (bool)i);
		if (!maps) {
			continue;
		}
		print_debug_maps_ascii_art(dbg, maps, addr, colors);
	}
}
