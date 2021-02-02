// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include "private.h"

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
			rz_core_regs_to_flags(core);
			i++;
		} while (i < times);
	}
	return true;
}

RZ_IPI void rz_core_regs_to_flags(RzCore *core) {
	RzList *l = rz_reg_get_list(core->dbg->reg, RZ_REG_TYPE_GPR);
	RzListIter *iter;
	RzRegItem *reg;
	rz_list_foreach (l, iter, reg) {
		ut64 regval = rz_reg_get_value(core->dbg->reg, reg);
		rz_flag_set(core->flags, reg->name, regval, reg->size);
	}
	rz_list_free(l);
}

RZ_IPI bool rz_core_debug_reg_list(RzDebug *dbg, int type, int size, PJ *pj, int rad, const char *use_color) {
	int delta, cols, n = 0;
	const char *fmt, *fmt2, *kwhites;
	RzPrint *pr = NULL;
	int colwidth = 20;
	RzListIter *iter;
	RzRegItem *item;
	RzList *head;
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
			value = rz_reg_get_value_big(dbg->reg, item, &valueBig);
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
beach:
	if (isJson) {
		pj_end(pj);
	} else if (n > 0 && (rad == 2 || rad == '=') && ((n % cols))) {
		rz_cons_printf("\n");
	}
	return n != 0;
}
