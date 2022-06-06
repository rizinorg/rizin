// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

#if 0
	/* debugesil performs step into + esil conditionals */
	ESIL conditionals can be used to detect when a specific address is
	accessed, or a register. Those esil conditionals must be evaluated
	every iteration to ensure the register values are updated. Think
	in DebugESIL as software-watchpoints.

	[read|write|exec]-[reg|mem] [expression]

	de rw reg eax
	de-*

#expression can be a number or a range(if..is found)
#The <=, >=, ==, <, > comparisons are also supported

#endif

typedef struct {
	int rwx;
	int dev;
	char *expr;
} EsilBreak;

// TODO: Kill those globals
RzDebug *dbg = NULL;
static int has_match = 0;
static int prestep = 1; // TODO: make it configurable
static ut64 opc = 0;
RzList *esil_watchpoints = NULL;
#define EWPS esil_watchpoints
#define ESIL dbg->analysis->esil

static int exprmatch(RzDebug *dbg, ut64 addr, const char *expr) {
	char *e = strdup(expr);
	if (!e) {
		return 0;
	}
	char *p = strstr(e, "..");
	ut64 a, b;
	int ret = 0;
	if (p) {
		*p = 0;
		p += 2;
		a = rz_num_math(dbg->num, e);
		b = rz_num_math(dbg->num, p);
		if (a < b) {
			if (addr >= a && addr <= b) {
				ret = 1;
			}
		} else {
			if (addr >= b && addr <= a) {
				ret = 1;
			}
		}
	} else {
		a = rz_num_math(dbg->num, e);
		if (addr == a) {
			ret = 1;
		}
	}
	has_match = ret;
	free(e);
	return ret;
}

static int esilbreak_check_pc(RzDebug *dbg, ut64 pc) {
	EsilBreak *ew;
	RzListIter *iter;
	if (!pc) {
		pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	}
	rz_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & RZ_PERM_X) {
			if (exprmatch(dbg, pc, ew->expr)) {
				return 1;
			}
		}
	}
	return 0;
}

static int esilbreak_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	EsilBreak *ew;
	RzListIter *iter;
	eprintf(Color_GREEN "MEM READ 0x%" PFMT64x "\n" Color_RESET, addr);
	rz_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & RZ_PERM_R && ew->dev == 'm') {
			if (exprmatch(dbg, addr, ew->expr)) {
				has_match = 1;
				return 1;
			}
		}
	}
	return 0; // fallback
}

static int esilbreak_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	EsilBreak *ew;
	RzListIter *iter;
	eprintf(Color_RED "MEM WRTE 0x%" PFMT64x "\n" Color_RESET, addr);
	rz_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & RZ_PERM_W && ew->dev == 'm') {
			if (exprmatch(dbg, addr, ew->expr)) {
				has_match = 1;
				return 1;
			}
		}
	}
	return 1; // fallback
}

static int esilbreak_reg_read(RzAnalysisEsil *esil, const char *regname, ut64 *num, int *size) {
	EsilBreak *ew;
	RzListIter *iter;
	if (regname[0] >= '0' && regname[0] <= '9') {
		// eprintf (Color_CYAN"IMM READ %s\n"Color_RESET, regname);
		return 0;
	}
	eprintf(Color_YELLOW "REG READ %s\n" Color_RESET, regname);
	rz_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & RZ_PERM_R && ew->dev == 'r') {
			// XXX: support array of regs in expr
			if (!strcmp(regname, ew->expr)) {
				has_match = 1;
				return 1;
			}
		}
	}
	return 0; // fallback
}

static int exprtoken(RzDebug *dbg, char *s, const char *sep, char **o) {
	char *p = strstr(s, sep);
	if (p) {
		*p = 0;
		p += strlen(sep);
		*o = p;
		return 1;
	}
	*o = NULL;
	return 0;
}

static int exprmatchreg(RzDebug *dbg, const char *regname, const char *expr) {
	int ret = 0;
	char *p;
	char *s = strdup(expr);
	if (!s) {
		return 0;
	}
	if (!strcmp(regname, s)) {
		ret = 1;
	} else {
#define CURVAL 0){} \
	rz_str_trim(s);if (!strcmp(regname,s) && regval
		ut64 regval = rz_debug_reg_get(dbg, regname);
		if (exprtoken(dbg, s, ">=", &p)) {
			if (CURVAL >= rz_num_math(dbg->num, p))
				ret = 1;
		} else if (exprtoken(dbg, s, "<=", &p)) {
			if (CURVAL <= rz_num_math(dbg->num, p))
				ret = 1;
		} else if (exprtoken(dbg, s, "==", &p)) {
			if (CURVAL <= rz_num_math(dbg->num, p))
				ret = 1;
		} else if (exprtoken(dbg, s, "<", &p)) {
			if (CURVAL < rz_num_math(dbg->num, p))
				ret = 1;
		} else if (exprtoken(dbg, s, ">", &p)) {
			if (CURVAL > rz_num_math(dbg->num, p))
				ret = 1;
		} else if (exprtoken(dbg, s, " ", &p)) {
			rz_str_trim(s);
			if (!strcmp(regname, s)) {
				ut64 num = rz_num_math(dbg->num, p);
				ret = exprmatch(dbg, num, s);
			}
		} else {
			if (!strcmp(regname, s)) {
				ret = 1;
			}
		}
	}
	free(s);
	return ret;
}

static int esilbreak_reg_write(RzAnalysisEsil *esil, const char *regname, ut64 *num) {
	EsilBreak *ew;
	RzListIter *iter;
	if (regname[0] >= '0' && regname[0] <= '9') {
		// this should never happen
		// eprintf (Color_BLUE"IMM WRTE %s\n"Color_RESET, regname);
		return 0;
	}
	eprintf(Color_MAGENTA "REG WRTE %s 0x%" PFMT64x "\n" Color_RESET, regname, *num);
	rz_list_foreach (EWPS, iter, ew) {
		if ((ew->rwx & RZ_PERM_W) && (ew->dev == 'r')) {
			// XXX: support array of regs in expr
			if (exprmatchreg(dbg, regname, ew->expr)) {
				has_match = 1;
				return 1;
			}
		}
	}
	return 1; // fallback
}

RZ_API void rz_debug_esil_prestep(RzDebug *d, int p) {
	prestep = p;
}

RZ_API int rz_debug_esil_stepi(RzDebug *d) {
	RzAnalysisOp op;
	ut8 obuf[64];
	int ret = 1;
	dbg = d;
	if (!ESIL) {
		ESIL = rz_analysis_esil_new(32, true, 64);
		// TODO setup something?
		if (!ESIL) {
			return 0;
		}
	}

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
	opc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	dbg->iob.read_at(dbg->iob.io, opc, obuf, sizeof(obuf));

	// dbg->iob.read_at (dbg->iob.io, npc, buf, sizeof (buf));

	// dbg->analysis->reg = dbg->reg; // hack
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;
	ESIL->cb.hook_reg_read = &esilbreak_reg_read;
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;

	if (prestep) {
		// required when a exxpression is like <= == ..
		// otherwise it will stop at the next instruction
		if (rz_debug_step(dbg, 1) < 1) {
			eprintf("Step failed\n");
			return 0;
		}
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
		//	npc = rz_debug_reg_get (dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	}

	if (rz_analysis_op(dbg->analysis, &op, opc, obuf, sizeof(obuf), RZ_ANALYSIS_OP_MASK_ESIL)) {
		if (esilbreak_check_pc(dbg, opc)) {
			eprintf("STOP AT 0x%08" PFMT64x "\n", opc);
			ret = 0;
		} else {
			rz_analysis_esil_set_pc(ESIL, opc);
			eprintf("0x%08" PFMT64x "  %s\n", opc, RZ_STRBUF_SAFEGET(&op.esil));
			(void)rz_analysis_esil_parse(ESIL, RZ_STRBUF_SAFEGET(&op.esil));
			// rz_analysis_esil_dumpstack (ESIL);
			rz_analysis_esil_stack_free(ESIL);
			ret = 1;
		}
	}
	if (!prestep) {
		if (ret && !has_match) {
			if (rz_debug_step(dbg, 1) < 1) {
				eprintf("Step failed\n");
				return 0;
			}
			rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
			//	npc = rz_debug_reg_get (dbg, dbg->reg->name[RZ_REG_NAME_PC]);
		}
	}
	return ret;
}

RZ_API ut64 rz_debug_esil_step(RzDebug *dbg, ut32 count) {
	count++;
	has_match = 0;
	rz_cons_break_push(NULL, NULL);
	do {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (has_match) {
			eprintf("EsilBreak match at 0x%08" PFMT64x "\n", opc);
			break;
		}
		if (count > 0) {
			count--;
			if (!count) {
				// eprintf ("Limit reached\n");
				break;
			}
		}
	} while (rz_debug_esil_stepi(dbg));
	rz_cons_break_pop();
	return opc;
}

RZ_API ut64 rz_debug_esil_continue(RzDebug *dbg) {
	return rz_debug_esil_step(dbg, UT32_MAX);
}

static void ewps_free(EsilBreak *ew) {
	RZ_FREE(ew->expr);
	free(ew);
}

RZ_API int rz_debug_esil_watch_empty(RzDebug *dbg) {
	return rz_list_empty(EWPS);
}

RZ_API void rz_debug_esil_watch(RzDebug *dbg, int rwx, int dev, const char *expr) {
	if (!EWPS) {
		EWPS = rz_list_new();
		if (!EWPS) {
			return;
		}
		EWPS->free = (RzListFree)ewps_free;
	}
	EsilBreak *ew = RZ_NEW0(EsilBreak);
	if (!ew) {
		RZ_FREE(EWPS);
		return;
	}
	ew->rwx = rwx;
	ew->dev = dev;
	ew->expr = strdup(expr);
	rz_list_append(EWPS, ew);
}

RZ_API void rz_debug_esil_watch_reset(RzDebug *dbg) {
	rz_list_free(EWPS);
	EWPS = NULL;
}

RZ_API void rz_debug_esil_watch_list(RzDebug *dbg) {
	EsilBreak *ew;
	RzListIter *iter;
	rz_list_foreach (EWPS, iter, ew) {
		dbg->cb_printf("de %s %c %s\n", rz_str_rwx_i(ew->rwx), ew->dev, ew->expr);
	}
}
