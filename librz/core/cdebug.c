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
	if (rz_config_get_i(core->config, "cfg.debug")) {
		rz_reg_arena_swap(core->dbg->reg, true);
		// sync registers for BSD PT_STEP/PT_CONT
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
		ut64 pc = rz_debug_reg_get(core->dbg, "PC");
		rz_debug_trace_pc(core->dbg, pc);
		if (!rz_debug_step(core->dbg, times)) {
			eprintf("Step failed\n");
			core->break_loop = true;
			return false;
		}
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
		rz_cons_break_pop();
		return true;
	}
	eprintf("Continue until 0x%08" PFMT64x " using %d bpsize\n", addr, core->dbg->bpsize);
	rz_reg_arena_swap(core->dbg->reg, true);
	if (rz_bp_add_sw(core->dbg->bp, addr, core->dbg->bpsize, RZ_BP_PROT_EXEC)) {
		if (rz_debug_is_dead(core->dbg)) {
			eprintf("Cannot continue, run ood?\n");
		} else {
			rz_debug_continue(core->dbg);
		}
		rz_bp_del(core->dbg->bp, addr);
	} else {
		eprintf("Cannot set breakpoint of size %d at 0x%08" PFMT64x "\n",
			core->dbg->bpsize, addr);
		return false;
	}
	return true;
}
static void regs_to_flags(RzCore *core, int size) {
	const RzList *l = rz_reg_get_list(core->dbg->reg, RZ_REG_TYPE_GPR);
	RzListIter *iter;
	RzRegItem *reg;
	rz_list_foreach (l, iter, reg) {
		if (reg->type != RZ_REG_TYPE_GPR && reg->type != RZ_REG_TYPE_FLG) {
			continue;
		}
		if (size != 0 && size != reg->size) {
			continue;
		}
		ut64 regval = rz_reg_get_value(core->dbg->reg, reg);
		rz_flag_set(core->flags, reg->name, regval, reg->size / 8);
	}
}

static int get_regs_bits(RzCore *core) {
	// Copied from cmd_analysis.c:__analysis_reg_list
	int bits = core->analysis->bits;
	if (!strcmp(core->analysis->cur->arch, "arm") && bits == 16) {
		/* workaround for thumb */
		bits = 32;
	} else if ((!strcmp(core->analysis->cur->arch, "6502") && bits == 8) || (!strcmp(core->analysis->cur->arch, "avr") && bits == 8)) {
		/* workaround for 6502 and avr*/
		regs_to_flags(core, 16);
	}
	return bits;
}

RZ_IPI void rz_core_regs2flags(RzCore *core) {
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_REGISTERS);
	int size = get_regs_bits(core);
	regs_to_flags(core, size);
	rz_flag_space_pop(core->flags);
}

RZ_IPI void rz_core_debug_regs2flags(RzCore *core, int bits) {
	if (core->bin->is_debugger) {
		if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
			rz_flag_space_push(core->flags, RZ_FLAGS_FS_REGISTERS);
			int size = bits <= 0 ? get_regs_bits(core) : bits;
			regs_to_flags(core, size);
			rz_flag_space_pop(core->flags);
		}
	} else {
		rz_core_regs2flags(core);
	}
}

RZ_IPI bool rz_core_debug_reg_list(RzCore *core, int type, int size, PJ *pj, int rad, const char *use_color) {
	RzDebug *dbg = core->dbg;
	int delta, cols, n = 0;
	const char *fmt, *fmt2, *kwhites;
	RzPrint *pr = NULL;
	int colwidth = 20;
	RzListIter *iter;
	RzRegItem *item;
	const RzList *head;
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
		//fmt = "%s = 0x%08"PFMT64x"%s";
		fmt = "%s = %s%s";
		fmt2 = "%s%7s%s %s%s";
		kwhites = "         ";
		colwidth = dbg->regcols ? 20 : 25;
		cols = 3;
	} else {
		//fmt = "%s = 0x%08"PFMT64x"%s";
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
	head = rz_reg_get_list(dbg->reg, type);
	if (!head) {
		return false;
	}
	if (rad == 1 || rad == '*') {
		dbg->cb_printf("fs+%s\n", RZ_FLAGS_FS_REGISTERS);
	}
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
		dbg->cb_printf("fs-\n");
	}
beach:
	if (isJson) {
		pj_end(pj);
	} else if (n > 0 && (rad == 2 || rad == '=') && ((n % cols))) {
		rz_cons_printf("\n");
	}
	return n != 0;
}
