// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include "core_private.h"
#include "rz_bin.h"

/**
 * \brief Check whether the core is in debug mode (equivalent to cfg.debug)
 */
RZ_API bool rz_core_is_debug(RzCore *core) {
	return core->bin->is_debugger;
}

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
	if (rz_core_is_debug(core)) {
		rz_reg_arena_swap(core->dbg->reg, true);
		// sync registers for BSD PT_STEP/PT_CONT
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
		ut64 pc = rz_debug_reg_get(core->dbg, "PC");
		rz_debug_trace_pc(core->dbg, pc);
		if (!rz_debug_step(core->dbg, times)) {
			RZ_LOG_ERROR("core: failed to step\n");
			rz_core_reg_update_flags(core);
			core->break_loop = true;
			return false;
		}
		rz_core_reg_update_flags(core);
	} else {
		int i = 0;
		do {
			rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			rz_core_reg_update_flags(core);
			i++;
		} while (i < times);
	}
	return true;
}

RZ_IPI void rz_core_debug_continue(RzCore *core) {
	if (rz_core_is_debug(core)) {
		rz_cons_break_push(rz_core_static_debug_stop, core->dbg);
		rz_reg_arena_swap(core->dbg->reg, true);
#if __linux__
		core->dbg->continue_all_threads = true;
#endif
		rz_debug_continue(core->dbg);
		rz_core_reg_update_flags(core);
		rz_cons_break_pop();
		rz_core_dbg_follow_seek_register(core);
	} else {
		rz_core_esil_step(core, UT64_MAX, "0", NULL, false);
		rz_core_reg_update_flags(core);
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
				RzDebugFrame *head = rz_list_first(core->dbg->call_frames);
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
		rz_core_reg_update_flags(core);
		rz_cons_break_pop();
		return true;
	}
	eprintf("Continue until 0x%08" PFMT64x "\n", addr);
	rz_reg_arena_swap(core->dbg->reg, true);
	if (rz_bp_add_sw(core->dbg->bp, addr, 0, RZ_PERM_X)) {
		if (rz_debug_is_dead(core->dbg)) {
			RZ_LOG_ERROR("core: cannot continue, run ood?\n");
		} else {
			rz_debug_continue(core->dbg);
			rz_core_reg_update_flags(core);
		}
		rz_bp_del(core->dbg->bp, addr);
	} else {
		RZ_LOG_ERROR("core: cannot set breakpoint for continuing until 0x%08" PFMT64x "\n", addr);
		return false;
	}
	return true;
}

RZ_IPI void rz_core_debug_single_step_in(RzCore *core) {
	if (rz_core_is_debug(core)) {
		if (core->print->cur_enabled) {
			rz_core_debug_continue_until(core, core->offset, core->offset + core->print->cur);
			core->print->cur_enabled = 0;
		} else {
			rz_core_debug_step_one(core, 1);
		}
	} else {
		rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
		rz_core_reg_update_flags(core);
	}
}

RZ_IPI void rz_core_debug_single_step_over(RzCore *core) {
	bool io_cache = rz_config_get_b(core->config, "io.cache");
	rz_config_set_b(core->config, "io.cache", false);
	if (rz_core_is_debug(core)) {
		if (core->print->cur_enabled) {
			rz_cons_break_push(rz_core_static_debug_stop, core->dbg);
			rz_reg_arena_swap(core->dbg->reg, true);
			rz_debug_continue_until_optype(core->dbg, RZ_ANALYSIS_OP_TYPE_RET, 1);
			rz_core_reg_update_flags(core);
			rz_cons_break_pop();
			rz_core_dbg_follow_seek_register(core);
			core->print->cur_enabled = 0;
		} else {
			rz_core_debug_step_over(core, 1);
			rz_core_dbg_follow_seek_register(core);
			rz_core_reg_update_flags(core);
		}
	} else {
		rz_core_analysis_esil_step_over(core);
	}
	rz_config_set_b(core->config, "io.cache", io_cache);
}

/**
 * \brief Toggle breakpoint
 * \param core RzCore instance
 * \param addr Breakpoint addr
 */
RZ_API void rz_core_debug_breakpoint_toggle(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_if_fail(core && core->dbg);
	RzBreakpointItem *bpi = rz_bp_get_at(core->dbg->bp, addr);
	if (bpi) {
		rz_bp_del(core->dbg->bp, addr);
	} else {
		bool hwbp = (int)rz_config_get_b(core->config, "dbg.hwbp");
		bpi = rz_debug_bp_add(core->dbg, addr, 0, hwbp, false, 0, NULL, 0);
		if (!bpi) {
			RZ_LOG_ERROR("core: cannot set breakpoint at 0x%" PFMT64x "\n", addr);
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
	RzBinObject *o = rz_bin_cur_object(core->bin);
	RzPVector *symbols = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	if (!symbols) {
		RZ_LOG_ERROR("Unable to find symbols in the binary\n");
		return;
	}
	RzBinSymbol *symbol;
	void **iter;
	RzBreakpointItem *bp;
	bool hwbp = rz_config_get_b(core->config, "dbg.hwbp");
	rz_pvector_foreach (symbols, iter) {
		symbol = *iter;
		if (symbol->type && !strcmp(symbol->type, RZ_BIN_TYPE_FUNC_STR)) {
			if (rz_analysis_noreturn_at(core->analysis, symbol->vaddr)) {
				bp = rz_debug_bp_add(core->dbg, symbol->vaddr, 0, hwbp, false, 0, NULL, 0);
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
	char buf[20];

	if (pid > 0) {
		rz_debug_attach(core->dbg, pid);
	} else {
		if (core->file && core->io) {
			rz_debug_attach(core->dbg, rz_io_fd_get_pid(core->io, core->file->fd));
		}
	}
	rz_debug_select(core->dbg, core->dbg->pid, core->dbg->tid);
	rz_config_set_i(core->config, "dbg.swstep", (core->dbg->cur && !core->dbg->cur->canstep));
	rz_io_system(core->io, rz_strf(buf, "pid %d", core->dbg->pid));
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
	RzReg *reg = rz_core_reg_default(core);
	RzList *ritems = rz_reg_filter_items_covered(reg->allregs);
	if (ritems) {
		rz_core_reg_print_diff(reg, ritems);
		rz_list_free(ritems);
	}
	ut64 old_address = core->offset;
	rz_core_seek(core, rz_reg_get_value_by_role(reg, RZ_REG_NAME_PC), true);
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
static void print_debug_map_line(RzDebug *dbg, RzDebugMap *map, ut64 addr, RzCmdStateOutput *state) {
	char humansz[8];
	if (state->mode == RZ_OUTPUT_MODE_QUIET) { // "dmq"
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
	} else if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		rz_num_units(humansz, sizeof(humansz), map->size);
		rz_table_add_rowf(state->d.t, "xxssbsss",
			map->addr,
			map->addr_end,
			map->shared ? "sys" : "usr",
			humansz,
			map->user,
			rz_str_rwx_i(map->perm),
			map->file ? map->file : "?",
			map->name ? map->name : "?");
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

static void apply_maps_as_flags(RzCore *core, RzList /*<RzDebugMap *>*/ *maps, bool print_only) {
	RzListIter *iter;
	RzDebugMap *map;
	rz_list_foreach (maps, iter, map) {
		char *name = (map->name && *map->name)
			? rz_str_newf("%s.%s", map->name, rz_str_rwx_i(map->perm))
			: rz_str_newf("%08" PFMT64x ".%s", map->addr, rz_str_rwx_i(map->perm));
		if (!name) {
			continue;
		}
		rz_name_filter(name, 0, true);
		ut64 size = map->addr_end - map->addr;
		if (print_only) {
			rz_cons_printf("f+ map.%s 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n",
				name, size, map->addr);
		} else {
			rz_flag_set_next(core->flags, name, map->addr, size);
		}
		free(name);
	}
}

/**
 * Create or update flags for all current debug maps in the "maps" flagspace
 */
RZ_API void rz_core_debug_map_update_flags(RzCore *core) {
	rz_return_if_fail(core);
	rz_flag_unset_all_in_space(core->flags, RZ_FLAGS_FS_DEBUG_MAPS);
	if (rz_debug_is_dead(core->dbg)) {
		return;
	}
	rz_debug_map_sync(core->dbg);
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_DEBUG_MAPS);
	RzList *maps = rz_debug_map_list(core->dbg, false);
	if (maps) {
		apply_maps_as_flags(core, maps, false);
	}
	maps = rz_debug_map_list(core->dbg, true);
	if (maps) {
		apply_maps_as_flags(core, maps, false);
	}
	rz_flag_space_pop(core->flags);
}

RZ_API void rz_core_debug_map_print(RzCore *core, ut64 addr, RzCmdStateOutput *state) {
	rz_return_if_fail(core);
	int i;
	RzListIter *iter;
	RzDebugMap *map;
	PJ *pj = state->d.pj;
	RzDebug *dbg = core->dbg;
	if (!dbg) {
		return;
	}
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "xxssbsss",
		"begin", "end", "type", "size",
		"user", "perms", "file", "name");
	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_print("fss+ " RZ_FLAGS_FS_DEBUG_MAPS "\n");
	}
	for (i = 0; i < 2; i++) { // Iterate over dbg::maps and dbg::maps_user
		RzList *maps = rz_debug_map_list(dbg, (bool)i);
		if (!maps) {
			continue;
		}
		if (state->mode == RZ_OUTPUT_MODE_RIZIN) { // "dm*"
			apply_maps_as_flags(core, maps, true);
			continue;
		}
		rz_list_foreach (maps, iter, map) {
			switch (state->mode) {
			case RZ_OUTPUT_MODE_JSON: // "dmj"
				print_debug_map_json(map, pj);
				break;
			case RZ_OUTPUT_MODE_LONG: // workaround for '.'
				if (addr >= map->addr && addr < map->addr_end) {
					print_debug_map_line(dbg, map, addr, state);
				}
				break;
			case RZ_OUTPUT_MODE_TABLE: // "dmt"
			case RZ_OUTPUT_MODE_QUIET: // "dmq"
			default: // "dm"
				print_debug_map_line(dbg, map, addr, state);
				break;
			}
		}
	}
	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_print("fss-\n");
	}
	rz_cmd_state_output_array_end(state);
}

static int cmp(const void *a, const void *b, void *user) {
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
static int findMinMax(RzList /*<RzDebugMap *>*/ *maps, ut64 *min, ut64 *max, int skip, int width) {
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

static void print_debug_maps_ascii_art(RzDebug *dbg, RzList /*<RzDebugMap *>*/ *maps, ut64 addr, int colors) {
	ut64 mul; // The amount of address space a single console column will represent in bar graph
	ut64 min = -1, max = 0;
	int width = rz_cons_get_size(NULL) - 90;
	RzListIter *iter;
	RzDebugMap *map;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (width < 1) {
		width = 30;
	}
	rz_list_sort(maps, cmp, NULL);
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

/**
 * Print all traces
 * \param dbg core->dbg
 * \param mode output mode, default RZ_OUTPUT_MODE_STANDARD
 * \param offset offset of address
 */
RZ_API void rz_debug_trace_print(RzDebug *dbg, RzCmdStateOutput *state, ut64 offset) {
	rz_return_if_fail(dbg);
	int tag = dbg->trace->tag;
	RzListIter *iter;
	RzDebugTracepoint *trace;
	rz_list_foreach (dbg->trace->traces, iter, trace) {
		if (trace->tag && !(tag & trace->tag)) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%" PFMT64x "\n", trace->addr);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("dt+ 0x%" PFMT64x " %d\n", trace->addr, trace->times);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
		default:
			rz_cons_printf("0x%08" PFMT64x " size=%d count=%d times=%d tag=%d\n",
				trace->addr, trace->size, trace->count, trace->times, trace->tag);
			break;
		}
	}
}

/**
 * Print trace info in ASCII Art
 * \param dbg core->dbg
 * \param offset offset of address
 */
RZ_API void rz_debug_traces_ascii(RzDebug *dbg, ut64 offset) {
	rz_return_if_fail(dbg);
	RzList *info_list = rz_debug_traces_info(dbg, offset);
	RzTable *table = rz_table_new();
	table->cons = rz_cons_singleton();
	rz_table_visual_list(table, info_list, offset, 1,
		rz_cons_get_size(NULL), dbg->iob.io->va);
	char *s = rz_table_tostring(table);
	rz_cons_printf("\n%s\n", s);
	free(s);
	rz_table_free(table);
	rz_list_free(info_list);
}

/**
 * \brief Close debug process (Kill debugee and all child processes)
 * \param core The RzCore instance
 * \return success
 */
RZ_API bool rz_core_debug_process_close(RzCore *core) {
	rz_return_val_if_fail(core && core->dbg, false);
	RzDebug *dbg = core->dbg;
	// Stop trace session
	if (dbg->session) {
		rz_debug_session_free(dbg->session);
		dbg->session = NULL;
	}
#ifndef SIGKILL
#define SIGKILL 9
#endif
	// Kill debugee and all child processes
	if (dbg->cur && dbg->cur->pids && dbg->pid != -1) {
		RzList *list = dbg->cur->pids(dbg, dbg->pid);
		RzListIter *iter;
		RzDebugPid *p;
		if (list) {
			rz_list_foreach (list, iter, p) {
				rz_debug_kill(dbg, p->pid, p->pid, SIGKILL);
				rz_debug_detach(dbg, p->pid);
			}
		} else {
			rz_debug_kill(dbg, dbg->pid, dbg->pid, SIGKILL);
			rz_debug_detach(dbg, dbg->pid);
		}
	}
	// Remove the target's registers from the flag list
	rz_core_debug_clear_register_flags(core);
	// Reopen and rebase the original file
	rz_core_io_file_open(core, core->io->desc->fd);
	return true;
}

/**
 * \brief Step until end of frame
 * \param core The RzCore instance
 * \return success
 */
RZ_API bool rz_core_debug_step_until_frame(RzCore *core) {
	rz_return_val_if_fail(core && core->dbg, false);
	int maxLoops = 200000;
	ut64 off, now = rz_debug_reg_get(core->dbg, "SP");
	rz_cons_break_push(NULL, NULL);
	do {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (rz_debug_is_dead(core->dbg)) {
			break;
		}
		// XXX (HACK!)
		rz_debug_step_over(core->dbg, 1);
		off = rz_debug_reg_get(core->dbg, "SP");
		// check breakpoint here
		if (--maxLoops < 0) {
			RZ_LOG_INFO("step loop limit exceeded\n");
			break;
		}
	} while (off <= now);
	rz_core_reg_update_flags(core);
	rz_cons_break_pop();
	return true;
}

/**
 * \brief Step back
 * \param core The RzCore instance
 * \param steps Step steps
 * \return success
 */
RZ_API bool rz_core_debug_step_back(RzCore *core, int steps) {
	if (!rz_core_is_debug(core)) {
		if (!rz_core_esil_step_back(core)) {
			RZ_LOG_ERROR("cannot step back\n");
			return false;
		}
		return true;
	}
	if (!core->dbg->session) {
		RZ_LOG_ERROR("session has not started\n");
		return false;
	}
	if (rz_debug_step_back(core->dbg, steps) < 0) {
		RZ_LOG_ERROR("stepping back failed\n");
		return false;
	}
	rz_core_reg_update_flags(core);
	return true;
}

/**
 * \brief Step over
 * \param core The RzCore instance
 * \param steps Step steps
 */
RZ_API bool rz_core_debug_step_over(RzCore *core, int steps) {
	if (rz_config_get_i(core->config, "dbg.skipover")) {
		rz_core_debug_step_skip(core, steps);
		return true;
	}
	if (!rz_core_is_debug(core)) {
		for (int i = 0; i < steps; i++) {
			rz_core_analysis_esil_step_over(core);
		}
		return true;
	}
	bool hwbp = rz_config_get_b(core->config, "dbg.hwbp");
	ut64 addr = rz_debug_reg_get(core->dbg, "PC");
	RzBreakpointItem *bpi = rz_bp_get_at(core->dbg->bp, addr);
	rz_bp_del(core->dbg->bp, addr);
	rz_reg_arena_swap(core->dbg->reg, true);
	rz_debug_step_over(core->dbg, steps);
	if (bpi) {
		(void)rz_debug_bp_add(core->dbg, addr, 0, hwbp, false, 0, NULL, 0);
	}
	rz_core_reg_update_flags(core);
	return true;
}

/**
 * \brief Skip operations
 * \param core The RzCore instance
 * \param times Skip op times
 */
RZ_API bool rz_core_debug_step_skip(RzCore *core, int times) {
	bool hwbp = rz_config_get_b(core->config, "dbg.hwbp");
	ut64 addr = rz_debug_reg_get(core->dbg, "PC");
	ut8 buf[64];
	RzAnalysisOp aop = { 0 };
	RzBreakpointItem *bpi = rz_bp_get_at(core->dbg->bp, addr);
	rz_reg_arena_swap(core->dbg->reg, true);
	for (int i = 0; i < times; i++) {
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
		rz_io_read_at(core->io, addr, buf, sizeof(buf));
		rz_analysis_op_init(&aop);
		rz_analysis_op(core->analysis, &aop, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
		addr += aop.size;
		rz_analysis_op_fini(&aop);
	}
	rz_debug_reg_set(core->dbg, "PC", addr);
	rz_reg_setv(core->analysis->reg, "PC", addr);
	rz_core_reg_update_flags(core);
	if (bpi) {
		(void)rz_debug_bp_add(core->dbg, addr, 0, hwbp, false, 0, NULL, 0);
	}
	return true;
}

RZ_API void rz_backtrace_free(RZ_NULLABLE RzBacktrace *bt) {
	if (!bt) {
		return;
	}
	free(bt->frame);
	free(bt->desc);
	free(bt->pcstr);
	free(bt->spstr);
	free(bt->flagdesc);
	free(bt->flagdesc2);
	free(bt);
}

static void get_backtrace_info(RzCore *core, RzDebugFrame *frame, ut64 addr,
	char **flagdesc, char **flagdesc2, char **pcstr, char **spstr) {
	RzFlagItem *f = rz_flag_get_at_by_spaces(core->flags, true, frame->addr,
		RZ_FLAGS_FS_CLASSES,
		RZ_FLAGS_FS_FUNCTIONS,
		RZ_FLAGS_FS_IMPORTS,
		RZ_FLAGS_FS_RELOCS,
		RZ_FLAGS_FS_RESOURCES,
		RZ_FLAGS_FS_SECTIONS,
		RZ_FLAGS_FS_SEGMENTS,
		RZ_FLAGS_FS_SYMBOLS,
		RZ_FLAGS_FS_SYMBOLS_SECTIONS,
		RZ_FLAGS_FS_DEBUG_MAPS,
		RZ_FLAGS_FS_POINTERS,
		NULL);
	RzFlagItem *f2 = NULL;
	*flagdesc = NULL;
	*flagdesc2 = NULL;
	if (f) {
		if (f->offset != addr) {
			int delta = (int)(frame->addr - f->offset);
			if (delta > 0) {
				*flagdesc = rz_str_newf("%s+%d", f->name, delta);
			} else if (delta < 0) {
				*flagdesc = rz_str_newf("%s%d", f->name, delta);
			} else {
				*flagdesc = rz_str_newf("%s", f->name);
			}
		} else {
			*flagdesc = rz_str_newf("%s", f->name);
		}
		if (!strchr(f->name, '.')) {
			f2 = rz_flag_get_at(core->flags, frame->addr - 1, true);
		}
		if (f2 && f2 != f) {
			if (f2->offset != addr) {
				int delta = (int)(frame->addr - 1 - f2->offset);
				if (delta > 0) {
					*flagdesc2 = rz_str_newf("%s+%d", f2->name, delta + 1);
				} else if (delta < 0) {
					*flagdesc2 = rz_str_newf("%s%d", f2->name, delta + 1);
				} else {
					*flagdesc2 = rz_str_newf("%s+1", f2->name);
				}
			} else {
				*flagdesc2 = rz_str_newf("%s", f2->name);
			}
		}
	}
	if (!rz_str_cmp(*flagdesc, *flagdesc2, -1)) {
		free(*flagdesc2);
		*flagdesc2 = NULL;
	}
	if (!(pcstr && spstr)) {
		return;
	}
	if (core->dbg->bits & RZ_SYS_BITS_64) {
		*pcstr = rz_str_newf("0x%-16" PFMT64x, frame->addr);
		*spstr = rz_str_newf("0x%-16" PFMT64x, frame->sp);
	} else if (core->dbg->bits & RZ_SYS_BITS_32) {
		*pcstr = rz_str_newf("0x%-8" PFMT64x, frame->addr);
		*spstr = rz_str_newf("0x%-8" PFMT64x, frame->sp);
	} else {
		*pcstr = rz_str_newf("0x%" PFMT64x, frame->addr);
		*spstr = rz_str_newf("0x%" PFMT64x, frame->sp);
	}
}

/**
 * \brief Get backtraces based on dbg.btdepth and dbg.btalgo
 * \param core The RzCore instance
 * \return A list of RzBacktrace
 */
RZ_API RZ_OWN RzList /*<RzBacktrace *>*/ *rz_core_debug_backtraces(RzCore *core) {
	RzList *list = rz_debug_frames(core->dbg, UT64_MAX);
	if (!list) {
		return NULL;
	}
	RzListIter *iter;
	RzDebugFrame *frame;
	RzList *bts = rz_list_newf((RzListFree)rz_backtrace_free);
	if (!bts) {
		rz_list_free(list);
		return NULL;
	}
	rz_list_foreach (list, iter, frame) {
		RzBacktrace *bt = RZ_NEW0(RzBacktrace);
		if (!bt) {
			rz_list_free(list);
			rz_list_free(bts);
			return NULL;
		}
		rz_list_append(bts, bt);
		get_backtrace_info(core, frame, UT64_MAX, &bt->flagdesc, &bt->flagdesc2, &bt->pcstr, &bt->spstr);
		bt->fcn = rz_analysis_get_fcn_in(core->analysis, frame->addr, 0);
		bt->frame = RZ_NEWCOPY(RzDebugFrame, frame);
		bt->desc = rz_str_newf("%s%s", rz_str_get_null(bt->flagdesc), rz_str_get_null(bt->flagdesc2));
	}
	rz_list_free(list);
	return bts;
}

/**
 * \brief Seek to `PC` if needed
 * \param core The RzCore instance
 */
RZ_API void rz_core_dbg_follow_seek_register(RzCore *core) {
	ut64 follow = rz_config_get_i(core->config, "dbg.follow");
	if (follow <= 0) {
		return;
	}
	ut64 pc = rz_debug_reg_get(core->dbg, "PC");
	if ((pc < core->offset) || (pc >= (core->offset + follow))) {
		rz_core_seek_to_register(core, "PC", false);
	}
}

static void foreach_reg_set_or_clear(RzCore *core, bool set) {
	RzReg *reg = rz_core_reg_default(core);
	const RzList *regs = rz_reg_get_list(reg, RZ_REG_TYPE_GPR);
	RzListIter *it;
	RzRegItem *reg_item;
	rz_list_foreach (regs, it, reg_item) {
		if (set) {
			const ut64 value = rz_reg_get_value(reg, reg_item);
			rz_flag_set(core->flags, reg_item->name, value, reg_item->size / 8);
		} else {
			rz_flag_unset_name(core->flags, reg_item->name);
		}
	}
}

RZ_API void rz_core_debug_set_register_flags(RzCore *core) {
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_REGISTERS);
	foreach_reg_set_or_clear(core, true);
	rz_flag_space_pop(core->flags);
}

RZ_API void rz_core_debug_clear_register_flags(RzCore *core) {
	foreach_reg_set_or_clear(core, false);
}

RZ_IPI bool rz_core_debug_pid_print(RzDebug *dbg, int pid, RzCmdStateOutput *state) {
	if (!dbg || !dbg->cur || !dbg->cur->pids) {
		return false;
	}
	RzList *list = dbg->cur->pids(dbg, RZ_MAX(0, pid));
	if (!list) {
		return false;
	}
	RzListIter *iter;
	RzDebugPid *p;
	char status[2];
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sdddss", "current",
		"ppid", "pid", "uid", "status", "path");
	rz_list_foreach (list, iter, p) {
		rz_strf(status, "%c", p->status);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kb(state->d.pj, "current", dbg->pid == p->pid);
			pj_ki(state->d.pj, "ppid", p->ppid);
			pj_ki(state->d.pj, "pid", p->pid);
			pj_ki(state->d.pj, "uid", p->uid);
			pj_ks(state->d.pj, "status", status);
			pj_ks(state->d.pj, "path", p->path);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "sdddss", dbg->pid == p->pid ? "true" : "", p->ppid,
				p->pid, p->uid, status, p->path);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf(" %c %d ppid:%d uid:%d %s %s\n",
				dbg->pid == p->pid ? '*' : '-',
				p->pid, p->ppid, p->uid, status, p->path);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_list_free(list);
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_IPI bool rz_core_debug_thread_print(RzDebug *dbg, int pid, RzCmdStateOutput *state) {
	if (pid == -1) {
		return false;
	}
	if (!dbg || !dbg->cur || !dbg->cur->threads) {
		return false;
	}
	RzList *list = dbg->cur->threads(dbg, pid);
	if (!list) {
		return false;
	}
	RzListIter *iter;
	RzDebugPid *p;
	RzAnalysisFunction *fcn = NULL;
	RzDebugMap *map = NULL;
	RzStrBuf *path = NULL;
	char status[2];
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "bdss", "current",
		"pid", "status", "path");
	rz_list_foreach (list, iter, p) {
		path = rz_strbuf_new(p->path);
		if (p->pc != 0) {
			map = rz_debug_map_get(dbg, p->pc);
			if (map && map->name && map->name[0]) {
				rz_strbuf_appendf(path, " %s", map->name);
			}

			rz_strbuf_appendf(path, " (0x%" PFMT64x ")", p->pc);

			fcn = rz_analysis_get_fcn_in(dbg->analysis, p->pc, 0);
			if (fcn) {
				if (p->pc == fcn->addr) {
					rz_strbuf_appendf(path, " at %s", fcn->name);
				} else {
					st64 delta = p->pc - fcn->addr;
					char sign = delta >= 0 ? '+' : '-';
					rz_strbuf_appendf(path, " in %s%c%" PFMT64u, fcn->name, sign, RZ_ABS(delta));
				}
			} else {
				const char *flag_name = dbg->corebind.getName(dbg->corebind.core, p->pc);
				if (flag_name) {
					rz_strbuf_appendf(path, " at %s", flag_name);
				} else {
					char *name_delta = dbg->corebind.getNameDelta(dbg->corebind.core, p->pc);
					if (name_delta) {
						rz_strbuf_appendf(path, " in %s", name_delta);
						free(name_delta);
					}
				}
			}
		}
		rz_strf(status, "%c", p->status);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kb(state->d.pj, "current", dbg->tid == p->pid);
			pj_ki(state->d.pj, "pid", p->pid);
			pj_ks(state->d.pj, "status", status);
			pj_ks(state->d.pj, "path", rz_strbuf_get(path));
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "bdss", dbg->pid == p->pid, p->pid,
				status, rz_strbuf_get(path));
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf(" %c %d %s %s\n",
				dbg->tid == p->pid ? '*' : '-',
				p->pid, status, rz_strbuf_get(path));
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		rz_strbuf_free(path);
	}
	rz_cmd_state_output_array_end(state);
	rz_list_free(list);
	return true;
}

RZ_IPI bool rz_core_debug_desc_print(RzDebug *dbg, RzCmdStateOutput *state) {
	if (!dbg || !dbg->cur || !dbg->cur->desc.list) {
		return false;
	}
	RzList *list = dbg->cur->desc.list(dbg->pid);
	if (!list) {
		return false;
	}
	RzListIter *iter;
	RzDebugDesc *p;
	char desctype[2];
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "ddsss", "fd",
		"offset", "perms", "type", "path");
	rz_list_foreach (list, iter, p) {
		rz_strf(desctype, "%c", p->type);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ki(state->d.pj, "fd", p->fd);
			pj_ki(state->d.pj, "offset", p->off);
			pj_ks(state->d.pj, "perms", rz_str_rwx_i(p->perm));
			pj_ks(state->d.pj, "type", desctype);
			pj_ks(state->d.pj, "path", p->path);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "ddsss", p->fd, p->off,
				rz_str_rwx_i(p->perm), desctype, p->path);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%i 0x%" PFMT64x " %s %s %s\n", p->fd, p->off,
				rz_str_rwx_i(p->perm),
				desctype, p->path);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	rz_list_free(list);
	return true;
}

struct RzCoreDebugState {
	RzDebug *dbg;
	RzCmdStateOutput *state;
};

static const char *signal_option(int opt) {
	if (opt == RZ_DBG_SIGNAL_CONT) {
		return ("continue");
	}
	if (opt == RZ_DBG_SIGNAL_SKIP) {
		return ("skip");
	}
	return NULL;
}

static bool siglistcb(void *p, const char *k, ut32 klen, const char *v, ut32 vlen) {
	char key[32] = "cfg.";
	struct RzCoreDebugState *ds = p;
	int opt;
	if (atoi(k) > 0) {
		strncpy(key + 4, k, 20);
		opt = sdb_num_get(ds->dbg->sgnls, key, 0);
		if (opt && ds->state->mode == RZ_OUTPUT_MODE_STANDARD) {
			rz_cons_printf("%s %s", k, v);
			const char *optstr = signal_option(opt);
			if (optstr) {
				rz_cons_printf(" %s", optstr);
			}
			rz_cons_newline();
		} else {
			rz_cons_printf("%s %s\n", k, v);
		}
	}
	return true;
}

static bool siglistjsoncb(void *p, const char *k, ut32 klen, const char *v, ut32 vlen) {
	char key[32] = "cfg.";
	struct RzCoreDebugState *ds = p;
	int opt;
	if (atoi(k) > 0) {
		strncpy(key + 4, k, 20);
		opt = (int)sdb_num_get(ds->dbg->sgnls, key, 0);
		pj_o(ds->state->d.pj);
		pj_ks(ds->state->d.pj, "signum", k);
		pj_ks(ds->state->d.pj, "name", v);
		const char *optstr = signal_option(opt);
		if (optstr) {
			pj_ks(ds->state->d.pj, "option", optstr);
		} else {
			pj_knull(ds->state->d.pj, "option");
		}
		pj_end(ds->state->d.pj);
	}
	return true;
}

static bool siglisttblcb(void *p, const char *k, ut32 klen, const char *v, ut32 vlen) {
	char key[32] = "cfg.";
	struct RzCoreDebugState *ds = p;
	int opt;
	if (atoi(k) > 0) {
		strncpy(key + 4, k, 20);
		opt = (int)sdb_num_get(ds->dbg->sgnls, key, 0);
		const char *optstr = signal_option(opt);
		rz_table_add_rowf(ds->state->d.t, "sss", k, v, rz_str_get(optstr));
	}
	return true;
}

RZ_IPI void rz_core_debug_signal_print(RzDebug *dbg, RzCmdStateOutput *state) {
	struct RzCoreDebugState ds = { dbg, state };
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sss", "signum",
		"name", "option");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		sdb_foreach(dbg->sgnls, siglistjsoncb, &ds);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		sdb_foreach(dbg->sgnls, siglisttblcb, &ds);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_QUIET:
		sdb_foreach(dbg->sgnls, siglistcb, &ds);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_cmd_state_output_array_end(state);
}
