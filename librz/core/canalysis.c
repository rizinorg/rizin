// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_list.h>
#include <rz_flag.h>
#include <rz_core.h>
#include <rz_bin.h>
#include <ht_uu.h>
#include <rz_util/rz_graph_drawable.h>

#include "core_private.h"

HEAPTYPE(ut64);

// used to speedup strcmp with rconfig.get in loops
enum {
	RZ_ARCH_THUMB,
	RZ_ARCH_ARM32,
	RZ_ARCH_ARM64,
	RZ_ARCH_MIPS
};
// 128M
#define MAX_SCAN_SIZE 0x7ffffff

static void loganalysis(ut64 from, ut64 to, int depth) {
	rz_cons_clear_line(1);
	eprintf("0x%08" PFMT64x " > 0x%08" PFMT64x " %d\r", from, to, depth);
}

static int cmpsize(const void *a, const void *b) {
	ut64 as = rz_analysis_function_linear_size((RzAnalysisFunction *)a);
	ut64 bs = rz_analysis_function_linear_size((RzAnalysisFunction *)b);
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpfcncc(const void *_a, const void *_b) {
	RzAnalysisFunction *a = (RzAnalysisFunction *)_a;
	RzAnalysisFunction *b = (RzAnalysisFunction *)_b;
	ut64 as = rz_analysis_function_complexity(a);
	ut64 bs = rz_analysis_function_complexity(b);
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpedges(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	int as, bs;
	rz_analysis_function_count_edges(a, &as);
	rz_analysis_function_count_edges(b, &bs);
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpframe(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	int as = a->maxstack;
	int bs = b->maxstack;
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpxrefs(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	int as = a->meta.numrefs;
	int bs = b->meta.numrefs;
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpname(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	int as = strcmp(a->name, b->name);
	int bs = strcmp(b->name, a->name);
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpcalls(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	int as = a->meta.numcallrefs;
	int bs = b->meta.numcallrefs;
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

static int cmpnbbs(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	ut64 as = rz_list_length(a->bbs);
	ut64 bs = rz_list_length(b->bbs);
	return (as > bs) ? 1 : (as < bs) ? -1
					 : 0;
}

RZ_IPI int bb_cmpaddr(const void *_a, const void *_b) {
	const RzAnalysisBlock *a = _a, *b = _b;
	return (a->addr > b->addr) - (a->addr < b->addr);
}

RZ_IPI int fcn_cmpaddr(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	return (a->addr > b->addr) - (a->addr < b->addr);
}

static char *getFunctionName(RzCore *core, ut64 addr) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (bf && bf->o) {
		RzBinSymbol *sym = ht_up_find(bf->o->addrzklassmethod, addr, NULL);
		if (sym && sym->classname && sym->name) {
			return rz_str_newf("method.%s.%s", sym->classname, sym->name);
		}
	}
	RzFlagItem *flag = rz_core_flag_get_by_spaces(core->flags, addr);
	return (flag && flag->name) ? strdup(flag->name) : NULL;
}

static char *getFunctionNamePrefix(RzCore *core, ut64 off, const char *name) {
	if (rz_reg_get(core->analysis->reg, name, -1)) {
		return rz_str_newf("%s.%08" PFMT64x, "fcn", off);
	}
	return strdup(name);
}

static RzCore *mycore = NULL;

// XXX: copypaste from analysis/data.c
#define MINLEN 1
static int is_string(const ut8 *buf, int size, int *len) {
	int i, fakeLen = 0;
	if (size < 1) {
		return 0;
	}
	if (!len) {
		len = &fakeLen;
	}
	if (size > 3 && buf[0] && !buf[1] && buf[2] && !buf[3]) {
		*len = 1; // XXX: TODO: Measure wide string length
		return 2; // is wide
	}
	for (i = 0; i < size; i++) {
		if (!buf[i] && i > MINLEN) {
			*len = i;
			return 1;
		}
		if (buf[i] == 10 || buf[i] == 13 || buf[i] == 9) {
			continue;
		}
		if (buf[i] < 32 || buf[i] > 127) {
			// not ascii text
			return 0;
		}
		if (!IS_PRINTABLE(buf[i])) {
			*len = i;
			return 0;
		}
	}
	*len = i;
	return 1;
}

static char *is_string_at(RzCore *core, ut64 addr, int *olen) {
	ut8 rstr[128] = { 0 };
	int ret = 0, len = 0;
	ut8 *str = calloc(256, 1);
	if (!str) {
		if (olen) {
			*olen = 0;
		}
		return NULL;
	}
	rz_io_read_at(core->io, addr, str, 255);

	str[255] = 0;
	if (is_string(str, 256, &len)) {
		if (olen) {
			*olen = len;
		}
		return (char *)str;
	}

	ut64 *cstr = (ut64 *)str;
	ut64 lowptr = cstr[0];
	if (lowptr >> 32) { // must be pa mode only
		lowptr &= UT32_MAX;
	}
	// cstring
	if (cstr[0] == 0 && cstr[1] < 0x1000) {
		ut64 ptr = cstr[2];
		if (ptr >> 32) { // must be pa mode only
			ptr &= UT32_MAX;
		}
		if (ptr) {
			rz_io_read_at(core->io, ptr, rstr, sizeof(rstr));
			rstr[127] = 0;
			ret = is_string(rstr, 128, &len);
			if (ret) {
				strcpy((char *)str, (char *)rstr);
				if (olen) {
					*olen = len;
				}
				return (char *)str;
			}
		}
	} else {
		// pstring
		rz_io_read_at(core->io, lowptr, rstr, sizeof(rstr));
		rstr[127] = 0;
		ret = is_string(rstr, sizeof(rstr), &len);
		if (ret) {
			strcpy((char *)str, (char *)rstr);
			if (olen) {
				*olen = len;
			}
			return (char *)str;
		}
	}
	// check if current section have no exec bit
	if (len < 1) {
		ret = 0;
		free(str);
		len = -1;
	} else if (olen) {
		*olen = len;
	}
	// NOTE: coverity says that ret is always 0 here, so str is dead code
	return ret ? (char *)str : NULL;
}

/* returns the RZ_ANALYSIS_ADDR_TYPE_* of the address 'addr' */
RZ_API ut64 rz_core_analysis_address(RzCore *core, ut64 addr) {
	ut64 types = 0;
	RzRegSet *rs = NULL;
	if (!core) {
		return 0;
	}
	if (core->dbg && core->dbg->reg) {
		rs = rz_reg_regset_get(core->dbg->reg, RZ_REG_TYPE_GPR);
	}
	if (rs) {
		RzRegItem *r;
		RzListIter *iter;
		rz_list_foreach (rs->regs, iter, r) {
			if (r->type == RZ_REG_TYPE_GPR) {
				ut64 val = rz_reg_getv(core->dbg->reg, r->name);
				if (addr == val) {
					types |= RZ_ANALYSIS_ADDR_TYPE_REG;
					break;
				}
			}
		}
	}
	if (rz_flag_get_i(core->flags, addr)) {
		types |= RZ_ANALYSIS_ADDR_TYPE_FLAG;
	}
	if (rz_analysis_get_fcn_in(core->analysis, addr, 0)) {
		types |= RZ_ANALYSIS_ADDR_TYPE_FUNC;
	}
	// check registers
	if (core->bin && core->bin->is_debugger && core->dbg) { // TODO: if cfg.debug here
		RzDebugMap *map;
		RzListIter *iter;
		// use 'dm'
		// XXX: this line makes r2 debugging MUCH slower
		// rz_debug_map_sync (core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				if (map->name && map->name[0] == '/') {
					if (core->io && core->io->desc &&
						core->io->desc->name &&
						!strcmp(map->name,
							core->io->desc->name)) {
						types |= RZ_ANALYSIS_ADDR_TYPE_PROGRAM;
					} else {
						types |= RZ_ANALYSIS_ADDR_TYPE_LIBRARY;
					}
				}
				if (map->perm & RZ_PERM_X) {
					types |= RZ_ANALYSIS_ADDR_TYPE_EXEC;
				}
				if (map->perm & RZ_PERM_R) {
					types |= RZ_ANALYSIS_ADDR_TYPE_READ;
				}
				if (map->perm & RZ_PERM_W) {
					types |= RZ_ANALYSIS_ADDR_TYPE_WRITE;
				}
				// find function
				if (map->name && strstr(map->name, "heap")) {
					types |= RZ_ANALYSIS_ADDR_TYPE_HEAP;
				}
				if (map->name && strstr(map->name, "stack")) {
					types |= RZ_ANALYSIS_ADDR_TYPE_STACK;
				}
				break;
			}
		}
	} else {
		int _perm = -1;
		if (core->io) {
			// sections
			void **it;
			rz_pvector_foreach (&core->io->maps, it) {
				RzIOMap *s = *it;
				if (addr >= s->itv.addr && addr < (s->itv.addr + s->itv.size)) {
					// sections overlap, so we want to get the one with lower perms
					_perm = (_perm != -1) ? RZ_MIN(_perm, s->perm) : s->perm;
					// TODO: we should identify which maps come from the program or other
					//types |= RZ_ANALYSIS_ADDR_TYPE_PROGRAM;
					// find function those sections should be created by hand or esil init
					if (s->name && strstr(s->name, "heap")) {
						types |= RZ_ANALYSIS_ADDR_TYPE_HEAP;
					}
					if (s->name && strstr(s->name, "stack")) {
						types |= RZ_ANALYSIS_ADDR_TYPE_STACK;
					}
				}
			}
		}
		if (_perm != -1) {
			if (_perm & RZ_PERM_X) {
				types |= RZ_ANALYSIS_ADDR_TYPE_EXEC;
			}
			if (_perm & RZ_PERM_R) {
				types |= RZ_ANALYSIS_ADDR_TYPE_READ;
			}
			if (_perm & RZ_PERM_W) {
				types |= RZ_ANALYSIS_ADDR_TYPE_WRITE;
			}
		}
	}

	// check if it's ascii
	if (addr != 0) {
		int not_ascii = 0;
		int i, failed_sequence, dir, on;
		for (i = 0; i < 8; i++) {
			ut8 n = (addr >> (i * 8)) & 0xff;
			if (n && !IS_PRINTABLE(n)) {
				not_ascii = 1;
			}
		}
		if (!not_ascii) {
			types |= RZ_ANALYSIS_ADDR_TYPE_ASCII;
		}
		failed_sequence = 0;
		dir = on = -1;
		for (i = 0; i < 8; i++) {
			ut8 n = (addr >> (i * 8)) & 0xff;
			if (on != -1) {
				if (dir == -1) {
					dir = (n > on) ? 1 : -1;
				}
				if (n == on + dir) {
					// ok
				} else {
					failed_sequence = 1;
					break;
				}
			}
			on = n;
		}
		if (!failed_sequence) {
			types |= RZ_ANALYSIS_ADDR_TYPE_SEQUENCE;
		}
	}
	return types;
}

RZ_IPI void rz_core_analysis_bbs_asciiart(RzCore *core, RzAnalysisFunction *fcn) {
	RzList *flist = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!flist) {
		return;
	}
	RzListIter *iter;
	RzAnalysisBlock *b;
	ls_foreach (fcn->bbs, iter, b) {
		RzInterval inter = (RzInterval){ b->addr, b->size };
		RzListInfo *info = rz_listinfo_new(NULL, inter, inter, -1, NULL);
		if (!info) {
			break;
		}
		rz_list_append(flist, info);
	}
	RzTable *table = rz_core_table(core);
	rz_table_visual_list(table, flist, core->offset, core->blocksize,
		rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
	rz_cons_printf("\n%s\n", rz_table_tostring(table));
	rz_table_free(table);
	rz_list_free(flist);
	return;
}

RZ_IPI void rz_core_analysis_fcn_returns(RzCore *core, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisBlock *b;
	ls_foreach (fcn->bbs, iter, b) {
		if (b->jump == UT64_MAX) {
			ut64 retaddr = rz_analysis_block_get_op_addr(b, b->ninstr - 1);
			if (retaddr == UT64_MAX) {
				break;
			}

			rz_cons_printf("0x%08" PFMT64x "\n", retaddr);
		}
	}
}

static int casecmp(const void *_a, const void *_b) {
	const RzAnalysisCaseOp *a = _a;
	const RzAnalysisCaseOp *b = _b;
	return a->addr != b->addr;
}

static ut64 __opaddr(RzAnalysisBlock *b, ut64 addr) {
	int i;
	if (addr >= b->addr && addr < (b->addr + b->size)) {
		for (i = 0; i < b->ninstr; i++) {
			ut64 aa = rz_analysis_block_get_op_addr(b, i);
			ut64 ab = rz_analysis_block_get_op_addr(b, i + 1);
			if (addr >= aa && addr < ab) {
				return aa;
			}
		}
	}
	return UT64_MAX;
}

static void bb_info_print(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisBlock *bb,
	ut64 addr, RzOutputMode mode, PJ *pj, RzTable *t) {
	RzDebugTracepoint *tp = NULL;
	RzListIter *iter;
	RzAnalysisBlock *bb2;
	int outputs = (bb->jump != UT64_MAX) + (bb->fail != UT64_MAX);
	int inputs = 0;
	rz_list_foreach (fcn->bbs, iter, bb2) {
		inputs += (bb2->jump == bb->addr) + (bb2->fail == bb->addr);
	}
	if (bb->switch_op) {
		RzList *unique_cases = rz_list_uniq(bb->switch_op->cases, casecmp);
		outputs += rz_list_length(unique_cases);
		rz_list_free(unique_cases);
	}
	ut64 opaddr = __opaddr(bb, addr);

	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		tp = rz_debug_trace_get(core->dbg, bb->addr);
		rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %02X:%04X %" PFMT64d,
			bb->addr, bb->addr + bb->size,
			tp ? tp->times : 0, tp ? tp->count : 0,
			bb->size);
		if (bb->jump != UT64_MAX) {
			rz_cons_printf(" j 0x%08" PFMT64x, bb->jump);
		}
		if (bb->fail != UT64_MAX) {
			rz_cons_printf(" f 0x%08" PFMT64x, bb->fail);
		}
		if (bb->switch_op) {
			RzAnalysisCaseOp *cop;
			RzListIter *iter;
			RzList *unique_cases = rz_list_uniq(bb->switch_op->cases, casecmp);
			rz_list_foreach (unique_cases, iter, cop) {
				rz_cons_printf(" s 0x%08" PFMT64x, cop->addr);
			}
			rz_list_free(unique_cases);
		}
		rz_cons_newline();
		break;
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		if (bb->jump != UT64_MAX) {
			pj_kn(pj, "jump", bb->jump);
		}
		if (bb->fail != UT64_MAX) {
			pj_kn(pj, "fail", bb->fail);
		}
		if (bb->switch_op) {
			pj_k(pj, "switch_op");
			pj_o(pj);
			pj_kn(pj, "addr", bb->switch_op->addr);
			pj_kn(pj, "min_val", bb->switch_op->min_val);
			pj_kn(pj, "def_val", bb->switch_op->def_val);
			pj_kn(pj, "max_val", bb->switch_op->max_val);
			pj_k(pj, "cases");
			pj_a(pj);
			{
				RzListIter *case_op_iter;
				RzAnalysisCaseOp *case_op;
				rz_list_foreach (bb->switch_op->cases, case_op_iter, case_op) {
					pj_o(pj);
					pj_kn(pj, "addr", case_op->addr);
					pj_kn(pj, "jump", case_op->jump);
					pj_kn(pj, "value", case_op->value);
					pj_end(pj);
				}
			}
			pj_end(pj);
			pj_end(pj);
		}
		pj_kn(pj, "opaddr", opaddr);
		pj_kn(pj, "addr", bb->addr);
		pj_ki(pj, "size", bb->size);
		pj_ki(pj, "inputs", inputs);
		pj_ki(pj, "outputs", outputs);
		pj_ki(pj, "ninstr", bb->ninstr);
		pj_kb(pj, "traced", bb->traced);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(t, "xdxx", bb->addr, bb->size, bb->jump, bb->fail);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_printf("f bb.%05" PFMT64x " = 0x%08" PFMT64x "\n", bb->addr & 0xFFFFF, bb->addr);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("0x%08" PFMT64x "\n", bb->addr);
		break;
	case RZ_OUTPUT_MODE_LONG: {
		if (bb->jump != UT64_MAX) {
			rz_cons_printf("jump: 0x%08" PFMT64x "\n", bb->jump);
		}
		if (bb->fail != UT64_MAX) {
			rz_cons_printf("fail: 0x%08" PFMT64x "\n", bb->fail);
		}
		rz_cons_printf("opaddr: 0x%08" PFMT64x "\n", opaddr);
		rz_cons_printf("addr: 0x%08" PFMT64x "\nsize: %" PFMT64d "\ninputs: %d\noutputs: %d\nninstr: %d\ntraced: %s\n",
			bb->addr, bb->size, inputs, outputs, bb->ninstr, rz_str_bool(bb->traced));
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

static int bb_cmp(const void *a, const void *b) {
	const RzAnalysisBlock *ba = a;
	const RzAnalysisBlock *bb = b;
	return ba->addr - bb->addr;
}

RZ_IPI void rz_core_analysis_bbs_info_print(RzCore *core, RzAnalysisFunction *fcn, RzOutputMode mode) {
	RzListIter *iter;
	RzAnalysisBlock *bb;
	PJ *pj = NULL;
	RzTable *t = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = rz_core_pj_new(core);
		pj_a(pj);
	} else if (mode == RZ_OUTPUT_MODE_TABLE) {
		t = rz_table_new();
		rz_table_set_columnsf(t, "xdxx", "addr", "size", "jump", "fail");
	} else if (mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_printf("fs blocks\n");
	}

	rz_list_sort(fcn->bbs, bb_cmp);
	rz_list_foreach (fcn->bbs, iter, bb) {
		bb_info_print(core, fcn, bb, bb->addr, mode, pj, t);
	}

	if (mode == RZ_OUTPUT_MODE_TABLE) {
		char *ts = rz_table_tofancystring(t);
		rz_cons_printf("%s", ts);
		free(ts);
		rz_table_free(t);
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI void rz_core_analysis_bb_info_print(RzCore *core, RzAnalysisBlock *bb, ut64 addr, RzOutputMode mode) {
	PJ *pj = NULL;
	RzTable *t = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = rz_core_pj_new(core);
	} else if (mode == RZ_OUTPUT_MODE_TABLE) {
		t = rz_table_new();
		rz_table_set_columnsf(t, "xdxx", "addr", "size", "jump", "fail");
	}
	RzAnalysisFunction *fcn = rz_list_first(bb->fcns);
	bb_info_print(core, fcn, bb, addr, mode, pj, t);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else if (mode == RZ_OUTPUT_MODE_TABLE) {
		char *ts = rz_table_tofancystring(t);
		rz_cons_printf("%s", ts);
		free(ts);
		rz_table_free(t);
	}
}

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val) {
	int bits = (core->analysis->bits & RZ_SYS_BITS_64) ? 64 : 32;
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
		eprintf("ar: Unknown register '%s'\n", regname);
		return -1;
	}
	rz_reg_set_value(core->dbg->reg, r, val);
	rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, true);
	rz_core_debug_regs2flags(core, bits);
	return 0;
}

static void core_esil_init(RzCore *core, RzAnalysisEsil *esil) {
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	int verbose = rz_config_get_i(core->config, "esil.verbose");
	if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return;
	}
	rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL); // setup io
	core->analysis->esil = esil;
	esil->verbose = verbose;
	const char *s = rz_config_get(core->config, "cmd.esil.intr");
	if (s) {
		char *my = strdup(s);
		if (my) {
			rz_config_set(core->config, "cmd.esil.intr", my);
			free(my);
		}
	}
}

RZ_IPI void rz_core_analysis_esil_init(RzCore *core) {
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil) {
		return;
	}
	core_esil_init(core, esil);
}

RZ_IPI void rz_core_analysis_esil_reinit(RzCore *core) {
	RzAnalysisEsil *esil = core->analysis->esil;
	rz_analysis_esil_free(esil);
	core_esil_init(core, esil);
	// reinitialize
	const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	if (pc && rz_reg_getv(core->analysis->reg, pc) == 0LL) {
		rz_core_analysis_set_reg(core, "PC", core->offset);
	}
}

static void initialize_stack(RzCore *core, ut64 addr, ut64 size) {
	const char *mode = rz_config_get(core->config, "esil.fillstack");
	if (mode && *mode && *mode != '0') {
		const ut64 bs = 4096 * 32;
		ut64 i;
		for (i = 0; i < size; i += bs) {
			ut64 left = RZ_MIN(bs, size - i);
			//	rz_core_cmdf (core, "wx 10203040 @ 0x%llx", addr);
			switch (*mode) {
			case 'd': { // "debrujn"
				ut8 *buf = (ut8 *)rz_debruijn_pattern(left, 0, NULL);
				if (buf) {
					if (!rz_core_write_at(core, addr + i, buf, left)) {
						eprintf("Couldn't write at %" PFMT64x "\n", addr + i);
					}
					free(buf);
				} else {
					eprintf("Couldn't generate pattern of length %" PFMT64d "\n", left);
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
				rz_core_cmdf(core, "wow 00 @ 0x%" PFMT64x "!0x%" PFMT64x, addr + i, left);
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
 * Initialize ESIL memory stack region.
 *
 * \param core RzCore reference
 * \param name Optional name of the memory stack region. If NULL, a name is
 *             computed automatically based on \p addr and \p size
 * \param addr Base address of the stack region, if UT64_MAX it is automatically computed
 * \param size Size of the stack region, if UT32_MAX it is automatically computed
 */
RZ_IPI void rz_core_analysis_esil_init_mem(RzCore *core, const char *name, ut64 addr, ut32 size) {
	ut64 current_offset = core->offset;
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	RzIOMap *stack_map;
	if (!name && addr == UT64_MAX && size == UT32_MAX) {
		char *fi = sdb_get(core->sdb, "aeim.fd", 0);
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
		eprintf("Cannot create map for tha stack, fd %d got closed again\n", esil->stack_fd);
		free(stack_name);
		esil->stack_fd = 0;
		return;
	}
	rz_io_map_set_name(stack_map, stack_name);
	free(stack_name);
	char val[128], *v;
	v = sdb_itoa(esil->stack_fd, val, 10);
	sdb_set(core->sdb, "aeim.fd", v, 0);

	rz_config_set_i(core->config, "io.va", true);
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
	// SP
	const char *sp = rz_reg_get_name(core->dbg->reg, RZ_REG_NAME_SP);
	if (sp) {
		rz_debug_reg_set(core->dbg, sp, addr + (size / 2));
	}
	// BP
	const char *bp = rz_reg_get_name(core->dbg->reg, RZ_REG_NAME_BP);
	if (bp) {
		rz_debug_reg_set(core->dbg, bp, addr + (size / 2));
	}
	// PC
	const char *pc = rz_reg_get_name(core->dbg->reg, RZ_REG_NAME_PC);
	if (pc) {
		rz_debug_reg_set(core->dbg, pc, current_offset);
	}
	rz_core_regs2flags(core);
	if (esil) {
		esil->stack_addr = addr;
		esil->stack_size = size;
	}
	initialize_stack(core, addr, size);
	rz_core_seek(core, current_offset, false);
}

RZ_IPI void rz_core_analysis_esil_init_mem_p(RzCore *core) {
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
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

RZ_IPI void rz_core_analysis_esil_init_mem_del(RzCore *core, const char *name, ut64 addr, ut32 size) {
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	char *stack_name = get_esil_stack_name(core, name, &addr, &size);
	if (esil->stack_fd > 2) { //0, 1, 2 are reserved for stdio/stderr
		rz_io_fd_close(core->io, esil->stack_fd);
		// no need to kill the maps, rz_io_map_cleanup does that for us in the close
		esil->stack_fd = 0;
	} else {
		eprintf("Cannot deinitialize %s\n", stack_name);
	}
	rz_flag_unset_name(core->flags, stack_name);
	rz_flag_unset_name(core->flags, "aeim.stack");
	sdb_unset(core->sdb, "aeim.fd", 0);
	free(stack_name);
	return;
}
/**
 * Initialize ESIL registers.
 *
 * \param core RzCore reference
 */
RZ_IPI void rz_core_analysis_esil_init_regs(RzCore *core) {
	rz_core_analysis_set_reg(core, "PC", core->offset);
}

RZ_IPI void rz_core_analysis_esil_step_over(RzCore *core) {
	RzAnalysisOp *op = rz_core_analysis_op(core, rz_reg_getv(core->analysis->reg, rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC)), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
	ut64 until_addr = UT64_MAX;
	if (op && op->type == RZ_ANALYSIS_OP_TYPE_CALL) {
		until_addr = op->addr + op->size;
	}
	rz_core_esil_step(core, until_addr, NULL, NULL, false);
	rz_analysis_op_free(op);
	rz_core_regs2flags(core);
}

RZ_IPI void rz_core_analysis_esil_step_over_until(RzCore *core, ut64 addr) {
	rz_core_esil_step(core, addr, NULL, NULL, true);
	rz_core_regs2flags(core);
}

RZ_IPI void rz_core_analysis_esil_step_over_untilexpr(RzCore *core, const char *expr) {
	rz_core_esil_step(core, UT64_MAX, expr, NULL, true);
	rz_core_regs2flags(core);
}

RZ_IPI void rz_core_analysis_esil_references_all_functions(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	ut64 cur_seek = core->offset;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		rz_core_seek(core, fcn->addr, true);
		rz_core_analysis_esil(core, "f", NULL);
	}
	rz_core_seek(core, cur_seek, true);
}

/**
 * Emulate \p n_instr instructions from \p addr. If \p until_addr is
 * specified and that address is met before all the instructions are emulated,
 * stop there.
 */
RZ_IPI void rz_core_analysis_esil_emulate(RzCore *core, ut64 addr, ut64 until_addr, int off) {
	RzAnalysisEsil *esil = core->analysis->esil;
	int i, j = 0;
	ut8 *buf;
	RzAnalysisOp aop = { 0 };
	int ret, bsize = RZ_MAX(4096, core->blocksize);
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	const char *pc = rz_reg_get_name(core->dbg->reg, RZ_REG_NAME_PC);
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	ut64 addrsize = rz_config_get_i(core->config, "esil.addr.size");

	if (!esil) {
		eprintf("Warning: cmd_espc: creating new esil instance\n");
		if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
			return;
		}
		core->analysis->esil = esil;
	}
	buf = malloc(bsize);
	if (!buf) {
		eprintf("Cannot allocate %d byte(s)\n", bsize);
		free(buf);
		return;
	}
	if (addr == -1) {
		addr = rz_reg_getv(core->dbg->reg, pc);
	}
	(void)rz_analysis_esil_setup(core->analysis->esil, core->analysis, 0, 0, 0); // int romem, int stats, int nonull) {
	ut64 cursp = rz_reg_getv(core->dbg->reg, "SP");
	ut64 oldoff = core->offset;
	const ut64 flags = RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_DISASM;
	for (i = 0, j = 0; j < off; i++, j++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
			eprintf("Warning: Chomp\n");
		}
		if (!i) {
			rz_io_read_at(core->io, addr, buf, bsize);
		}
		if (addr == until_addr) {
			break;
		}
		ret = rz_analysis_op(core->analysis, &aop, addr, buf + i, bsize - i, flags);
		if (ret < 1) {
			eprintf("Failed analysis at 0x%08" PFMT64x "\n", addr);
			break;
		}
		// skip calls and such
		if (aop.type == RZ_ANALYSIS_OP_TYPE_CALL) {
			// nothing
		} else {
			rz_reg_setv(core->analysis->reg, "PC", aop.addr + aop.size);
			rz_reg_setv(core->dbg->reg, "PC", aop.addr + aop.size);
			const char *e = RZ_STRBUF_SAFEGET(&aop.esil);
			if (e && *e) {
				// eprintf ("   0x%08llx %d  %s\n", aop.addr, ret, aop.mnemonic);
				(void)rz_analysis_esil_parse(esil, e);
			}
		}
		int inc = (core->search->align > 0) ? core->search->align - 1 : ret - 1;
		if (inc < 0) {
			inc = minopcode;
		}
		i += inc;
		addr += ret; // aop.size;
		rz_analysis_op_fini(&aop);
	}
	rz_core_seek(core, oldoff, true);
	rz_reg_setv(core->dbg->reg, "SP", cursp);
}

RZ_IPI void rz_core_analysis_esil_emulate_bb(RzCore *core) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	rz_core_analysis_esil_emulate(core, bb->addr, UT64_MAX, bb->ninstr);
}

static bool blacklisted_word(char *name) {
	const char *list[] = {
		"__stack_chk_guard",
		"__stderrp",
		"__stdinp",
		"__stdoutp",
		"_DefaultRuneLocale"
	};
	int i;
	for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
		if (strstr(name, list[i])) {
			return true;
		}
	}
	return false;
}

static char *analysis_fcn_autoname(RzCore *core, RzAnalysisFunction *fcn, int dump, int mode) {
	int use_getopt = 0;
	int use_isatty = 0;
	PJ *pj = NULL;
	char *do_call = NULL;
	RzAnalysisRef *ref;
	RzListIter *iter;
	RzList *refs = rz_analysis_function_get_refs(fcn);
	if (mode == 'j') {
		// start a new JSON object
		pj = rz_core_pj_new(core);
		pj_a(pj);
	}
	if (refs) {
		rz_list_foreach (refs, iter, ref) {
			RzFlagItem *f = rz_flag_get_i(core->flags, ref->addr);
			if (f) {
				// If dump is true, print all strings referenced by the function
				if (dump) {
					// take only strings flags
					if (!strncmp(f->name, "str.", 4)) {
						if (mode == 'j') {
							// add new json item
							pj_o(pj);
							pj_kn(pj, "addr", ref->at);
							pj_kn(pj, "ref", ref->addr);
							pj_ks(pj, "flag", f->name);
							pj_end(pj);
						} else {
							rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %s\n", ref->at, ref->addr, f->name);
						}
					}
				} else if (do_call) { // break if a proper autoname found and not in dump mode
					break;
				}
				// enter only if a candidate name hasn't found yet
				if (!do_call) {
					if (blacklisted_word(f->name)) {
						continue;
					}
					if (strstr(f->name, ".isatty")) {
						use_isatty = 1;
					}
					if (strstr(f->name, ".getopt")) {
						use_getopt = 1;
					}
					if (!strncmp(f->name, "method.", 7)) {
						free(do_call);
						do_call = strdup(f->name + 7);
						continue;
					}
					if (!strncmp(f->name, "str.", 4)) {
						free(do_call);
						do_call = strdup(f->name + 4);
						continue;
					}
					if (!strncmp(f->name, "sym.imp.", 8)) {
						free(do_call);
						do_call = strdup(f->name + 8);
						continue;
					}
					if (!strncmp(f->name, "reloc.", 6)) {
						free(do_call);
						do_call = strdup(f->name + 6);
						continue;
					}
				}
			}
		}
		rz_list_free(refs);
	}
	if (mode == 'j') {
		pj_end(pj);
	}
	if (pj) {
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
	// TODO: append counter if name already exists
	if (use_getopt) {
		RzFlagItem *item = rz_flag_get(core->flags, "main");
		free(do_call);
		// if referenced from entrypoint. this should be main
		if (item && item->offset == fcn->addr) {
			return strdup("main"); // main?
		}
		return strdup("parse_args"); // main?
	}
	if (use_isatty) {
		char *ret = rz_str_newf("sub.setup_tty_%s_%" PFMT64x, do_call, fcn->addr);
		free(do_call);
		return ret;
	}
	if (do_call) {
		char *ret = rz_str_newf("sub.%s_%" PFMT64x, do_call, fcn->addr);
		free(do_call);
		return ret;
	}
	return NULL;
}

/*this only autoname those function that start with fcn.* or sym.func.* */
RZ_API void rz_core_analysis_autoname_all_fcns(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;

	rz_list_foreach (core->analysis->fcns, it, fcn) {
		if (!strncmp(fcn->name, "fcn.", 4) || !strncmp(fcn->name, "sym.func.", 9)) {
			RzFlagItem *item = rz_flag_get(core->flags, fcn->name);
			if (item) {
				char *name = analysis_fcn_autoname(core, fcn, 0, 0);
				if (name) {
					rz_flag_rename(core->flags, item, name);
					free(fcn->name);
					fcn->name = name;
				}
			} else {
				// there should always be a flag for a function
				rz_warn_if_reached();
			}
		}
	}
}

/* reads .gopclntab section in go binaries to recover function names
   and adds them as sym.go.* flags */
RZ_API void rz_core_analysis_autoname_all_golang_fcns(RzCore *core) {
	RzList *section_list = rz_bin_get_sections(core->bin);
	RzListIter *iter;
	const char *oldstr = NULL;
	RzBinSection *section;
	ut64 gopclntab = 0;
	rz_list_foreach (section_list, iter, section) {
		if (strstr(section->name, ".gopclntab")) {
			gopclntab = section->vaddr;
			break;
		}
	}
	if (!gopclntab) {
		oldstr = rz_print_rowlog(core->print, "Could not find .gopclntab section");
		rz_print_rowlog_done(core->print, oldstr);
		return;
	}
	int ptr_size = core->analysis->bits / 8;
	ut64 offset = gopclntab + 2 * ptr_size;
	ut64 size_offset = gopclntab + 3 * ptr_size;
	ut8 temp_size[4] = { 0 };
	if (!rz_io_nread_at(core->io, size_offset, temp_size, 4)) {
		return;
	}
	ut32 size = rz_read_le32(temp_size);
	int num_syms = 0;
	//rz_cons_print ("[x] Reading .gopclntab...\n");
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	while (offset < gopclntab + size) {
		ut8 temp_delta[4] = { 0 };
		ut8 temp_func_addr[4] = { 0 };
		ut8 temp_func_name[4] = { 0 };
		if (!rz_io_nread_at(core->io, offset + ptr_size, temp_delta, 4)) {
			break;
		}
		ut32 delta = rz_read_le32(temp_delta);
		ut64 func_offset = gopclntab + delta;
		if (!rz_io_nread_at(core->io, func_offset, temp_func_addr, 4) ||
			!rz_io_nread_at(core->io, func_offset + ptr_size, temp_func_name, 4)) {
			break;
		}
		ut32 func_addr = rz_read_le32(temp_func_addr);
		ut32 func_name_offset = rz_read_le32(temp_func_name);
		ut8 func_name[64] = { 0 };
		rz_io_read_at(core->io, gopclntab + func_name_offset, func_name, 63);
		if (func_name[0] == 0xff) {
			break;
		}
		rz_name_filter((char *)func_name, 0);
		//rz_cons_printf ("[x] Found symbol %s at 0x%x\n", func_name, func_addr);
		rz_flag_set(core->flags, sdb_fmt("sym.go.%s", func_name), func_addr, 1);
		offset += 2 * ptr_size;
		num_syms++;
	}
	rz_flag_space_pop(core->flags);
	if (num_syms) {
		oldstr = rz_print_rowlog(core->print, sdb_fmt("Found %d symbols and saved them at sym.go.*", num_syms));
		rz_print_rowlog_done(core->print, oldstr);
	} else {
		oldstr = rz_print_rowlog(core->print, "Found no symbols.");
		rz_print_rowlog_done(core->print, oldstr);
	}
}

/* suggest a name for the function at the address 'addr'.
 * If dump is true, every strings associated with the function is printed */
RZ_API char *rz_core_analysis_fcn_autoname(RzCore *core, ut64 addr, int dump, int mode) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (fcn) {
		return analysis_fcn_autoname(core, fcn, dump, mode);
	}
	return NULL;
}

static ut64 *next_append(ut64 *next, int *nexti, ut64 v) {
	ut64 *tmp_next = realloc(next, sizeof(ut64) * (1 + *nexti));
	if (!tmp_next) {
		return NULL;
	}
	next = tmp_next;
	next[*nexti] = v;
	(*nexti)++;
	return next;
}

static void rz_analysis_set_stringrefs(RzCore *core, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzList *refs = rz_analysis_function_get_refs(fcn);
	rz_list_foreach (refs, iter, ref) {
		if (ref->type == RZ_ANALYSIS_REF_TYPE_DATA &&
			rz_bin_is_string(core->bin, ref->addr)) {
			rz_analysis_xrefs_set(core->analysis, ref->at, ref->addr, RZ_ANALYSIS_REF_TYPE_STRING);
		}
	}
	rz_list_free(refs);
}

static bool rz_analysis_try_get_fcn(RzCore *core, RzAnalysisRef *ref, int fcndepth, int refdepth) {
	if (!refdepth) {
		return false;
	}
	RzIOMap *map = rz_io_map_get(core->io, ref->addr);
	if (!map) {
		return false;
	}

	if (map->perm & RZ_PERM_X) {
		ut8 buf[64];
		rz_io_read_at(core->io, ref->addr, buf, sizeof(buf));
		bool looksLikeAFunction = rz_analysis_check_fcn(core->analysis, buf, sizeof(buf), ref->addr, map->itv.addr,
			map->itv.addr + map->itv.size);
		if (looksLikeAFunction) {
			if (core->analysis->limit) {
				if (ref->addr < core->analysis->limit->from ||
					ref->addr > core->analysis->limit->to) {
					return 1;
				}
			}
			rz_core_analysis_fcn(core, ref->addr, ref->at, ref->type, fcndepth - 1);
		}
	} else {
		ut64 offs = 0;
		ut64 sz = core->analysis->bits >> 3;
		RzAnalysisRef ref1;
		ref1.type = RZ_ANALYSIS_REF_TYPE_DATA;
		ref1.at = ref->addr;
		ref1.addr = 0;
		ut32 i32;
		ut16 i16;
		ut8 i8;
		ut64 offe = offs + 1024;
		for (offs = 0; offs < offe; offs += sz, ref1.at += sz) {
			ut8 bo[8];
			rz_io_read_at(core->io, ref->addr + offs, bo, RZ_MIN(sizeof(bo), sz));
			bool be = core->analysis->big_endian;
			switch (sz) {
			case 1:
				i8 = rz_read_ble8(bo);
				ref1.addr = (ut64)i8;
				break;
			case 2:
				i16 = rz_read_ble16(bo, be);
				ref1.addr = (ut64)i16;
				break;
			case 4:
				i32 = rz_read_ble32(bo, be);
				ref1.addr = (ut64)i32;
				break;
			case 8:
				ref1.addr = rz_read_ble64(bo, be);
				break;
			}
			rz_analysis_try_get_fcn(core, &ref1, fcndepth, refdepth - 1);
		}
	}
	return 1;
}

static int rz_analysis_analyze_fcn_refs(RzCore *core, RzAnalysisFunction *fcn, int depth) {
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzList *refs = rz_analysis_function_get_refs(fcn);

	rz_list_foreach (refs, iter, ref) {
		if (ref->addr == UT64_MAX) {
			continue;
		}
		switch (ref->type) {
		case RZ_ANALYSIS_REF_TYPE_DATA:
			if (core->analysis->opt.followdatarefs) {
				rz_analysis_try_get_fcn(core, ref, depth, 2);
			}
			break;
		case RZ_ANALYSIS_REF_TYPE_CODE:
		case RZ_ANALYSIS_REF_TYPE_CALL:
			rz_core_analysis_fcn(core, ref->addr, ref->at, ref->type, depth - 1);
			break;
		default:
			break;
		}
		// TODO: fix memleak here, fcn not freed even though it is
		// added in core->analysis->fcns which is freed in rz_analysis_free()
	}
	rz_list_free(refs);
	return 1;
}

static void function_rename(RzFlag *flags, RzAnalysisFunction *fcn) {
	const char *locname = "loc.";
	const size_t locsize = strlen(locname);
	char *fcnname = fcn->name;

	if (strncmp(fcn->name, locname, locsize) == 0) {
		const char *fcnpfx, *restofname;
		RzFlagItem *f;

		fcn->type = RZ_ANALYSIS_FCN_TYPE_FCN;
		fcnpfx = rz_analysis_fcntype_tostring(fcn->type);
		restofname = fcn->name + locsize;
		fcn->name = rz_str_newf("%s.%s", fcnpfx, restofname);

		f = rz_flag_get_i(flags, fcn->addr);
		rz_flag_rename(flags, f, fcn->name);

		free(fcnname);
	}
}

static void autoname_imp_trampoline(RzCore *core, RzAnalysisFunction *fcn) {
	if (rz_list_length(fcn->bbs) == 1 && ((RzAnalysisBlock *)rz_list_first(fcn->bbs))->ninstr == 1) {
		RzList *refs = rz_analysis_function_get_refs(fcn);
		if (refs && rz_list_length(refs) == 1) {
			RzAnalysisRef *ref = rz_list_first(refs);
			if (ref->type != RZ_ANALYSIS_REF_TYPE_CALL) { /* Some fcns don't return */
				RzFlagItem *flg = rz_flag_get_i(core->flags, ref->addr);
				if (flg && rz_str_startswith(flg->name, "sym.imp.")) {
					RZ_FREE(fcn->name);
					fcn->name = rz_str_newf("sub.%s", flg->name + 8);
				}
			}
		}
		rz_list_free(refs);
	}
}

static void set_fcn_name_from_flag(RzAnalysisFunction *fcn, RzFlagItem *f, const char *fcnpfx) {
	bool nameChanged = false;
	if (f && f->name) {
		if (!strncmp(fcn->name, "loc.", 4) || !strncmp(fcn->name, "fcn.", 4)) {
			rz_analysis_function_rename(fcn, f->name);
			nameChanged = true;
		} else if (strncmp(f->name, "sect", 4)) {
			rz_analysis_function_rename(fcn, f->name);
			nameChanged = true;
		}
	}
	if (!nameChanged) {
		rz_analysis_function_rename(fcn, sdb_fmt("%s.%08" PFMT64x, fcnpfx, fcn->addr));
	}
}

static bool is_entry_flag(RzFlagItem *f) {
	return f->space && !strcmp(f->space->name, RZ_FLAGS_FS_SYMBOLS) && rz_str_startswith(f->name, "entry.");
}

static int __core_analysis_fcn(RzCore *core, ut64 at, ut64 from, int reftype, int depth) {
	if (depth < 0) {
		//		printf ("Too deep for 0x%08"PFMT64x"\n", at);
		//		rz_sys_backtrace ();
		return false;
	}
	int has_next = rz_config_get_i(core->config, "analysis.hasnext");
	RzAnalysisHint *hint = NULL;
	int i, nexti = 0;
	ut64 *next = NULL;
	int fcnlen;
	RzAnalysisFunction *fcn = rz_analysis_function_new(core->analysis);
	const char *fcnpfx = rz_config_get(core->config, "analysis.fcnprefix");
	if (!fcnpfx) {
		fcnpfx = "fcn";
	}
	if (!fcn) {
		eprintf("Error: new (fcn)\n");
		return false;
	}
	fcn->cc = rz_str_constpool_get(&core->analysis->constpool, rz_analysis_cc_default(core->analysis));
	rz_warn_if_fail(!core->analysis->sdb_cc->path || fcn->cc);
	hint = rz_analysis_hint_get(core->analysis, at);
	if (hint && hint->bits == 16) {
		// expand 16bit for function
		fcn->bits = 16;
	} else {
		fcn->bits = core->analysis->bits;
	}
	fcn->addr = at;
	fcn->name = getFunctionName(core, at);

	if (!fcn->name) {
		fcn->name = rz_str_newf("%s.%08" PFMT64x, fcnpfx, at);
	}
	rz_analysis_fcn_invalidate_read_ahead_cache();
	do {
		RzFlagItem *f;
		ut64 delta = rz_analysis_function_linear_size(fcn);
		if (!rz_io_is_valid_offset(core->io, at + delta, !core->analysis->opt.noncode)) {
			goto error;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
		fcnlen = rz_analysis_fcn(core->analysis, fcn, at + delta, core->analysis->opt.bb_max_size, reftype);
		if (core->analysis->opt.searchstringrefs) {
			rz_analysis_set_stringrefs(core, fcn);
		}
		if (fcnlen == 0) {
			if (core->analysis->verbose) {
				eprintf("Analyzed function size is 0 at 0x%08" PFMT64x "\n", at + delta);
			}
			goto error;
		}
		if (fcnlen < 0) {
			switch (fcnlen) {
			case RZ_ANALYSIS_RET_ERROR:
			case RZ_ANALYSIS_RET_NEW:
			case RZ_ANALYSIS_RET_DUP:
			case RZ_ANALYSIS_RET_END:
				break;
			default:
				eprintf("Oops. Negative fcnsize at 0x%08" PFMT64x " (%d)\n", at, fcnlen);
				continue;
			}
		}
		f = rz_core_flag_get_by_spaces(core->flags, fcn->addr);
		set_fcn_name_from_flag(fcn, f, fcnpfx);

		if (fcnlen == RZ_ANALYSIS_RET_ERROR ||
			(fcnlen == RZ_ANALYSIS_RET_END && !rz_analysis_function_realsize(fcn))) { /* Error analyzing function */
			if (core->analysis->opt.followbrokenfcnsrefs) {
				rz_analysis_analyze_fcn_refs(core, fcn, depth);
			}
			goto error;
		} else if (fcnlen == RZ_ANALYSIS_RET_END) { /* Function analysis complete */
			f = rz_core_flag_get_by_spaces(core->flags, fcn->addr);
			if (f && f->name && strncmp(f->name, "sect", 4)) { /* Check if it's already flagged */
				char *new_name = strdup(f->name);
				if (is_entry_flag(f)) {
					RzListIter *iter;
					RzBinSymbol *sym;
					const RzList *syms = rz_bin_get_symbols(core->bin);
					ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
					rz_list_foreach (syms, iter, sym) {
						if ((sym->paddr + baddr) == fcn->addr && !strcmp(sym->type, RZ_BIN_TYPE_FUNC_STR)) {
							free(new_name);
							new_name = rz_str_newf("sym.%s", sym->name);
							break;
						}
					}
				}
				free(fcn->name);
				fcn->name = new_name;
			} else {
				RZ_FREE(fcn->name);
				const char *fcnpfx = rz_analysis_fcntype_tostring(fcn->type);
				if (!fcnpfx || !*fcnpfx || !strcmp(fcnpfx, "fcn")) {
					fcnpfx = rz_config_get(core->config, "analysis.fcnprefix");
				}
				fcn->name = rz_str_newf("%s.%08" PFMT64x, fcnpfx, fcn->addr);
				autoname_imp_trampoline(core, fcn);
				/* Add flag */
				rz_flag_space_push(core->flags, RZ_FLAGS_FS_FUNCTIONS);
				rz_flag_set(core->flags, fcn->name, fcn->addr, rz_analysis_function_linear_size(fcn));
				rz_flag_space_pop(core->flags);
			}

			/* New function: Add initial xref */
			if (from != UT64_MAX) {
				rz_analysis_xrefs_set(core->analysis, from, fcn->addr, reftype);
			}
			// XXX: this is wrong. See CID 1134565
			rz_analysis_add_function(core->analysis, fcn);
			if (has_next) {
				ut64 addr = rz_analysis_function_max_addr(fcn);
				RzIOMap *map = rz_io_map_get(core->io, addr);
				// only get next if found on an executable section
				if (!map || (map && map->perm & RZ_PERM_X)) {
					for (i = 0; i < nexti; i++) {
						if (next[i] == addr) {
							break;
						}
					}
					if (i == nexti) {
						ut64 at = rz_analysis_function_max_addr(fcn);
						while (true) {
							ut64 size;
							RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, at, RZ_META_TYPE_ANY, &size);
							if (!mi) {
								break;
							}
							at += size;
						}
						// TODO: ensure next address is function after padding (nop or trap or wat)
						// XXX noisy for test cases because we want to clear the stderr
						rz_cons_clear_line(1);
						loganalysis(fcn->addr, at, 10000 - depth);
						next = next_append(next, &nexti, at);
					}
				}
			}
			if (!rz_analysis_analyze_fcn_refs(core, fcn, depth)) {
				goto error;
			}
		}
	} while (fcnlen != RZ_ANALYSIS_RET_END);
	rz_list_free(core->analysis->leaddrs);
	core->analysis->leaddrs = NULL;
	if (has_next) {
		for (i = 0; i < nexti; i++) {
			if (!next[i] || rz_analysis_get_fcn_in(core->analysis, next[i], 0)) {
				continue;
			}
			rz_core_analysis_fcn(core, next[i], from, 0, depth - 1);
		}
		free(next);
	}
	if (core->analysis->cur && core->analysis->cur->arch && !strcmp(core->analysis->cur->arch, "x86")) {
		rz_analysis_function_check_bp_use(fcn);
		if (fcn && !fcn->bp_frame) {
			rz_analysis_function_delete_vars_by_kind(fcn, RZ_ANALYSIS_VAR_KIND_BPV);
		}
	}
	rz_analysis_hint_free(hint);
	return true;

error:
	rz_list_free(core->analysis->leaddrs);
	core->analysis->leaddrs = NULL;
	// ugly hack to free fcn
	if (fcn) {
		if (!rz_analysis_function_realsize(fcn) || fcn->addr == UT64_MAX) {
			rz_analysis_function_free(fcn);
			fcn = NULL;
		} else {
			// TODO: mark this function as not properly analyzed
			if (!fcn->name) {
				// XXX dupped code.
				fcn->name = rz_str_newf(
					"%s.%08" PFMT64x,
					rz_analysis_fcntype_tostring(fcn->type),
					at);
				/* Add flag */
				rz_flag_space_push(core->flags, RZ_FLAGS_FS_FUNCTIONS);
				rz_flag_set(core->flags, fcn->name, at, rz_analysis_function_linear_size(fcn));
				rz_flag_space_pop(core->flags);
			}
			rz_analysis_add_function(core->analysis, fcn);
		}
		if (fcn && has_next) {
			ut64 newaddr = rz_analysis_function_max_addr(fcn);
			RzIOMap *map = rz_io_map_get(core->io, newaddr);
			if (!map || (map && (map->perm & RZ_PERM_X))) {
				next = next_append(next, &nexti, newaddr);
				for (i = 0; i < nexti; i++) {
					if (!next[i]) {
						continue;
					}
					rz_core_analysis_fcn(core, next[i], next[i], 0, depth - 1);
				}
				free(next);
			}
		}
	}
	if (fcn && core->analysis->cur && core->analysis->cur->arch && !strcmp(core->analysis->cur->arch, "x86")) {
		rz_analysis_function_check_bp_use(fcn);
		if (!fcn->bp_frame) {
			rz_analysis_function_delete_vars_by_kind(fcn, RZ_ANALYSIS_VAR_KIND_BPV);
		}
	}
	rz_analysis_hint_free(hint);
	return false;
}

static char *get_title(ut64 addr) {
	return rz_str_newf("0x%" PFMT64x, addr);
}

/* decode and return the RzAnalysisOp at the address addr */
RZ_API RzAnalysisOp *rz_core_analysis_op(RzCore *core, ut64 addr, int mask) {
	int len;
	ut8 buf[32];
	ut8 *ptr;

	rz_return_val_if_fail(core, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	RzAnalysisOp *op = RZ_NEW0(RzAnalysisOp);
	if (!op) {
		return NULL;
	}
	int delta = (addr - core->offset);
	int minopsz = 8;
	if (delta > 0 && delta + minopsz < core->blocksize && addr >= core->offset && addr + 16 < core->offset + core->blocksize) {
		ptr = core->block + delta;
		len = core->blocksize - delta;
		if (len < 1) {
			goto err_op;
		}
	} else {
		if (!rz_io_read_at(core->io, addr, buf, sizeof(buf))) {
			goto err_op;
		}
		ptr = buf;
		len = sizeof(buf);
	}
	if (rz_analysis_op(core->analysis, op, addr, ptr, len, mask) < 1) {
		goto err_op;
	}
	// TODO This code block must be deleted when all the analysis plugins support disasm
	if (!op->mnemonic && mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		RzAsmOp asmop;
		if (core->analysis->verbose) {
			eprintf("WARNING: Implement RzAnalysisOp.MASK_DISASM for current analysis.arch. Using the sluggish RzAsmOp fallback for now.\n");
		}
		rz_asm_set_pc(core->rasm, addr);
		rz_asm_op_init(&asmop);
		if (rz_asm_disassemble(core->rasm, &asmop, ptr, len) > 0) {
			op->mnemonic = strdup(rz_strbuf_get(&asmop.buf_asm));
		}
		rz_asm_op_fini(&asmop);
	}
	return op;
err_op:
	free(op);
	return NULL;
}

// Node for tree-sorting analysis hints or collecting hint records at a single addr
typedef struct {
	RBNode rb;
	ut64 addr;
	enum {
		HINT_NODE_ADDR,
		HINT_NODE_ARCH,
		HINT_NODE_BITS
	} type;
	union {
		const RzVector /*<const RzAnalysisAddrHintRecord>*/ *addr_hints;
		const char *arch;
		int bits;
	};
} HintNode;

static void print_hint_h_format(HintNode *node) {
	switch (node->type) {
	case HINT_NODE_ADDR: {
		const RzAnalysisAddrHintRecord *record;
		rz_vector_foreach(node->addr_hints, record) {
			switch (record->type) {
			case RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE:
				rz_cons_printf(" immbase=%d", record->immbase);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP:
				rz_cons_printf(" jump=0x%08" PFMT64x, record->jump);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL:
				rz_cons_printf(" fail=0x%08" PFMT64x, record->fail);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME:
				rz_cons_printf(" stackframe=0x%" PFMT64x, record->stackframe);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_PTR:
				rz_cons_printf(" ptr=0x%" PFMT64x, record->ptr);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD:
				rz_cons_printf(" nword=%d", record->nword);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_RET:
				rz_cons_printf(" ret=0x%08" PFMT64x, record->retval);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS:
				rz_cons_printf(" newbits=%d", record->newbits);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE:
				rz_cons_printf(" size=%" PFMT64u, record->size);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX:
				rz_cons_printf(" syntax='%s'", record->syntax);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE: {
				const char *type = rz_analysis_optype_to_string(record->optype);
				if (type) {
					rz_cons_printf(" type='%s'", type);
				}
				break;
			}
			case RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE:
				rz_cons_printf(" opcode='%s'", record->opcode);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET:
				rz_cons_printf(" offset='%s'", record->type_offset);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL:
				rz_cons_printf(" esil='%s'", record->esil);
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH:
				rz_cons_printf(" high=true");
				break;
			case RZ_ANALYSIS_ADDR_HINT_TYPE_VAL:
				rz_cons_printf(" val=0x%08" PFMT64x, record->val);
				break;
			}
		}
		break;
	}
	case HINT_NODE_ARCH:
		if (node->arch) {
			rz_cons_printf(" arch='%s'", node->arch);
		} else {
			rz_cons_print(" arch=RESET");
		}
		break;
	case HINT_NODE_BITS:
		if (node->bits) {
			rz_cons_printf(" bits=%d", node->bits);
		} else {
			rz_cons_print(" bits=RESET");
		}
		break;
	}
}

// if mode == 'j', pj must be an existing PJ!
static void hint_node_print(HintNode *node, int mode, PJ *pj) {
	switch (mode) {
	case '*':
#define HINTCMD_ADDR(hint, fmt, x) rz_cons_printf(fmt " @ 0x%" PFMT64x "\n", x, (hint)->addr)
		switch (node->type) {
		case HINT_NODE_ADDR: {
			const RzAnalysisAddrHintRecord *record;
			rz_vector_foreach(node->addr_hints, record) {
				switch (record->type) {
				case RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE:
					HINTCMD_ADDR(node, "ahi %d", record->immbase);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP:
					HINTCMD_ADDR(node, "ahc 0x%" PFMT64x, record->jump);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL:
					HINTCMD_ADDR(node, "ahf 0x%" PFMT64x, record->fail);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME:
					HINTCMD_ADDR(node, "ahF 0x%" PFMT64x, record->stackframe);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_PTR:
					HINTCMD_ADDR(node, "ahp 0x%" PFMT64x, record->ptr);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD:
					// no command for this
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_RET:
					HINTCMD_ADDR(node, "ahr 0x%" PFMT64x, record->retval);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS:
					// no command for this
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE:
					HINTCMD_ADDR(node, "ahs 0x%" PFMT64x, record->size);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX:
					HINTCMD_ADDR(node, "ahS %s", record->syntax); // TODO: escape for newcmd
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE: {
					const char *type = rz_analysis_optype_to_string(record->optype);
					if (type) {
						HINTCMD_ADDR(node, "aho %s", type); // TODO: escape for newcmd
					}
					break;
				}
				case RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE:
					HINTCMD_ADDR(node, "ahd %s", record->opcode);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET:
					HINTCMD_ADDR(node, "aht %s", record->type_offset); // TODO: escape for newcmd
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL:
					HINTCMD_ADDR(node, "ahe %s", record->esil); // TODO: escape for newcmd
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH:
					rz_cons_printf("ahh @ 0x%" PFMT64x "\n", node->addr);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_VAL:
					// no command for this
					break;
				}
			}
			break;
		}
		case HINT_NODE_ARCH:
			HINTCMD_ADDR(node, "aha %s", node->arch ? node->arch : "0");
			break;
		case HINT_NODE_BITS:
			HINTCMD_ADDR(node, "ahb %d", node->bits);
			break;
		}
#undef HINTCMD_ADDR
		break;
	case 'j':
		switch (node->type) {
		case HINT_NODE_ADDR: {
			const RzAnalysisAddrHintRecord *record;
			rz_vector_foreach(node->addr_hints, record) {
				switch (record->type) {
				case RZ_ANALYSIS_ADDR_HINT_TYPE_IMMBASE:
					pj_ki(pj, "immbase", record->immbase);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP:
					pj_kn(pj, "jump", record->jump);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_FAIL:
					pj_kn(pj, "fail", record->fail);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_STACKFRAME:
					pj_kn(pj, "stackframe", record->stackframe);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_PTR:
					pj_kn(pj, "ptr", record->ptr);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_NWORD:
					pj_ki(pj, "nword", record->nword);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_RET:
					pj_kn(pj, "ret", record->retval);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_NEW_BITS:
					pj_ki(pj, "newbits", record->newbits);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_SIZE:
					pj_kn(pj, "size", record->size);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_SYNTAX:
					pj_ks(pj, "syntax", record->syntax);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_OPTYPE: {
					const char *type = rz_analysis_optype_to_string(record->optype);
					if (type) {
						pj_ks(pj, "type", type);
					}
					break;
				}
				case RZ_ANALYSIS_ADDR_HINT_TYPE_OPCODE:
					pj_ks(pj, "opcode", record->opcode);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_TYPE_OFFSET:
					pj_ks(pj, "offset", record->type_offset);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_ESIL:
					pj_ks(pj, "esil", record->esil);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_HIGH:
					pj_kb(pj, "high", true);
					break;
				case RZ_ANALYSIS_ADDR_HINT_TYPE_VAL:
					pj_kn(pj, "val", record->val);
					break;
				}
			}
			break;
		}
		case HINT_NODE_ARCH:
			if (node->arch) {
				pj_ks(pj, "arch", node->arch);
			} else {
				pj_knull(pj, "arch");
			}
			break;
		case HINT_NODE_BITS:
			pj_ki(pj, "bits", node->bits);
			break;
		}
		break;
	default:
		print_hint_h_format(node);
		break;
	}
}

void hint_node_free(RBNode *node, void *user) {
	free(container_of(node, HintNode, rb));
}

int hint_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 ia = *(ut64 *)incoming;
	ut64 ta = container_of(in_tree, const HintNode, rb)->addr;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

bool print_addr_hint_cb(ut64 addr, const RzVector /*<const RzAnalysisAddrHintRecord>*/ *records, void *user) {
	HintNode *node = RZ_NEW0(HintNode);
	if (!node) {
		return false;
	}
	node->addr = addr;
	node->type = HINT_NODE_ADDR;
	node->addr_hints = records;
	rz_rbtree_insert(user, &addr, &node->rb, hint_node_cmp, NULL);
	return true;
}

bool print_arch_hint_cb(ut64 addr, RZ_NULLABLE const char *arch, void *user) {
	HintNode *node = RZ_NEW0(HintNode);
	if (!node) {
		return false;
	}
	node->addr = addr;
	node->type = HINT_NODE_ARCH;
	node->arch = arch;
	rz_rbtree_insert(user, &addr, &node->rb, hint_node_cmp, NULL);
	return true;
}

bool print_bits_hint_cb(ut64 addr, int bits, void *user) {
	HintNode *node = RZ_NEW0(HintNode);
	if (!node) {
		return false;
	}
	node->addr = addr;
	node->type = HINT_NODE_BITS;
	node->bits = bits;
	rz_rbtree_insert(user, &addr, &node->rb, hint_node_cmp, NULL);
	return true;
}

static void print_hint_tree(RBTree tree, int mode) {
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new();
		pj_a(pj);
	}
#define END_ADDR \
	if (pj) { \
		pj_end(pj); \
	} else if (mode != '*') { \
		rz_cons_newline(); \
	}
	RBIter it;
	HintNode *node;
	ut64 last_addr = 0;
	bool in_addr = false;
	rz_rbtree_foreach (tree, it, node, HintNode, rb) {
		if (!in_addr || last_addr != node->addr) {
			if (in_addr) {
				END_ADDR
			}
			in_addr = true;
			last_addr = node->addr;
			if (pj) {
				pj_o(pj);
				pj_kn(pj, "addr", node->addr);
			} else if (mode != '*') {
				rz_cons_printf(" 0x%08" PFMT64x " =>", node->addr);
			}
		}
		hint_node_print(node, mode, pj);
	}
	if (in_addr) {
		END_ADDR
	}
#undef BEGIN_ADDR
#undef END_ADDR
	if (pj) {
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
}

RZ_API void rz_core_analysis_hint_list(RzAnalysis *a, int mode) {
	RBTree tree = NULL;
	// Collect all hints in the tree to sort them
	rz_analysis_arch_hints_foreach(a, print_arch_hint_cb, &tree);
	rz_analysis_bits_hints_foreach(a, print_bits_hint_cb, &tree);
	rz_analysis_addr_hints_foreach(a, print_addr_hint_cb, &tree);
	print_hint_tree(tree, mode);
	rz_rbtree_free(tree, hint_node_free, NULL);
}

RZ_API void rz_core_analysis_hint_print(RzAnalysis *a, ut64 addr, int mode) {
	RBTree tree = NULL;
	ut64 hint_addr = UT64_MAX;
	const char *arch = rz_analysis_hint_arch_at(a, addr, &hint_addr);
	if (hint_addr != UT64_MAX) {
		print_arch_hint_cb(hint_addr, arch, &tree);
	}
	int bits = rz_analysis_hint_bits_at(a, addr, &hint_addr);
	if (hint_addr != UT64_MAX) {
		print_bits_hint_cb(hint_addr, bits, &tree);
	}
	const RzVector *addr_hints = rz_analysis_addr_hints_at(a, addr);
	if (addr_hints) {
		print_addr_hint_cb(addr, addr_hints, &tree);
	}
	print_hint_tree(tree, mode);
	rz_rbtree_free(tree, hint_node_free, NULL);
}

static char *core_analysis_graph_label(RzCore *core, RzAnalysisBlock *bb, int opts) {
	int is_html = rz_cons_singleton()->is_html;
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;
	char cmd[1024], file[1024], *cmdstr = NULL, *filestr = NULL, *str = NULL;
	int line = 0, oline = 0, idx = 0;
	ut64 at;

	if (opts & RZ_CORE_ANALYSIS_GRAPHLINES) {
		for (at = bb->addr; at < bb->addr + bb->size; at += 2) {
			rz_bin_addr2line(core->bin, at, file, sizeof(file) - 1, &line);
			if (line != 0 && line != oline && strcmp(file, "??")) {
				filestr = rz_file_slurp_line(file, line, 0);
				if (filestr) {
					int flen = strlen(filestr);
					cmdstr = realloc(cmdstr, idx + flen + 8);
					memcpy(cmdstr + idx, filestr, flen);
					idx += flen;
					if (is_json) {
						strcpy(cmdstr + idx, "\\n");
						idx += 2;
					} else if (is_html) {
						strcpy(cmdstr + idx, "<br />");
						idx += 6;
					} else {
						strcpy(cmdstr + idx, "\\l");
						idx += 2;
					}
					free(filestr);
				}
			}
			oline = line;
		}
	} else if (opts & RZ_CORE_ANALYSIS_STAR) {
		snprintf(cmd, sizeof(cmd), "pdb %" PFMT64u " @ 0x%08" PFMT64x, bb->size, bb->addr);
		str = rz_core_cmd_str(core, cmd);
	} else if (opts & RZ_CORE_ANALYSIS_GRAPHBODY) {
		const bool scrColor = rz_config_get(core->config, "scr.color");
		const bool scrUtf8 = rz_config_get(core->config, "scr.utf8");
		rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
		rz_config_set(core->config, "scr.utf8", "false");
		snprintf(cmd, sizeof(cmd), "pD %" PFMT64u " @ 0x%08" PFMT64x, bb->size, bb->addr);
		cmdstr = rz_core_cmd_str(core, cmd);
		rz_config_set_i(core->config, "scr.color", scrColor);
		rz_config_set_i(core->config, "scr.utf8", scrUtf8);
	}
	if (cmdstr) {
		str = rz_str_escape_dot(cmdstr);
		free(cmdstr);
	}
	return str;
}

static char *palColorFor(const char *k) {
	if (!rz_cons_singleton()) {
		return NULL;
	}
	RzColor rcolor = rz_cons_pal_get(k);
	return rz_cons_rgb_tostring(rcolor.r, rcolor.g, rcolor.b);
}

static void core_analysis_color_curr_node(RzCore *core, RzAnalysisBlock *bbi) {
	bool color_current = rz_config_get_i(core->config, "graph.gv.current");
	char *pal_curr = palColorFor("graph.current");
	bool current = rz_analysis_block_contains(bbi, core->offset);

	if (current && color_current) {
		rz_cons_printf("\t\"0x%08" PFMT64x "\" ", bbi->addr);
		rz_cons_printf("\t[fillcolor=%s style=filled shape=box];\n", pal_curr);
	}
	free(pal_curr);
}

static int core_analysis_graph_construct_edges(RzCore *core, RzAnalysisFunction *fcn, int opts, PJ *pj, Sdb *DB) {
	RzAnalysisBlock *bbi;
	RzListIter *iter;
	int is_keva = opts & RZ_CORE_ANALYSIS_KEYVALUE;
	int is_star = opts & RZ_CORE_ANALYSIS_STAR;
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;
	int is_html = rz_cons_singleton()->is_html;
	char *pal_jump = palColorFor("graph.true");
	char *pal_fail = palColorFor("graph.false");
	char *pal_trfa = palColorFor("graph.trufae");
	int nodes = 0;
	rz_list_foreach (fcn->bbs, iter, bbi) {
		if (bbi->jump != UT64_MAX) {
			nodes++;
			if (is_keva) {
				char key[128];
				char val[128];
				snprintf(key, sizeof(key), "bb.0x%08" PFMT64x ".to", bbi->addr);
				if (bbi->fail != UT64_MAX) {
					snprintf(val, sizeof(val), "0x%08" PFMT64x, bbi->jump);
				} else {
					snprintf(val, sizeof(val), "0x%08" PFMT64x ",0x%08" PFMT64x,
						bbi->jump, bbi->fail);
				}
				// bb.<addr>.to=<jump>,<fail>
				sdb_set(DB, key, val, 0);
			} else if (is_html) {
				rz_cons_printf("<div class=\"connector _0x%08" PFMT64x " _0x%08" PFMT64x "\">\n"
					       "  <img class=\"connector-end\" src=\"img/arrow.gif\" /></div>\n",
					bbi->addr, bbi->jump);
			} else if (!is_json && !is_keva) {
				if (is_star) {
					char *from = get_title(bbi->addr);
					char *to = get_title(bbi->jump);
					rz_cons_printf("age %s %s\n", from, to);
					free(from);
					free(to);
				} else {
					rz_cons_printf("        \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
						       "[color=\"%s\"];\n",
						bbi->addr, bbi->jump,
						bbi->fail != -1 ? pal_jump : pal_trfa);
					core_analysis_color_curr_node(core, bbi);
				}
			}
		}
		if (bbi->fail != -1) {
			nodes++;
			if (is_html) {
				rz_cons_printf("<div class=\"connector _0x%08" PFMT64x " _0x%08" PFMT64x "\">\n"
					       "  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
					bbi->addr, bbi->fail);
			} else if (!is_keva && !is_json) {
				if (is_star) {
					char *from = get_title(bbi->addr);
					char *to = get_title(bbi->fail);
					rz_cons_printf("age %s %s\n", from, to);
					free(from);
					free(to);
				} else {
					rz_cons_printf("        \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
						       "[color=\"%s\"];\n",
						bbi->addr, bbi->fail, pal_fail);
					core_analysis_color_curr_node(core, bbi);
				}
			}
		}
		if (bbi->switch_op) {
			RzAnalysisCaseOp *caseop;
			RzListIter *iter;

			if (bbi->fail != UT64_MAX) {
				if (is_html) {
					rz_cons_printf("<div class=\"connector _0x%08" PFMT64x " _0x%08" PFMT64x "\">\n"
						       "  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
						bbi->addr, bbi->fail);
				} else if (!is_keva && !is_json) {
					if (is_star) {
						char *from = get_title(bbi->addr);
						char *to = get_title(bbi->fail);
						rz_cons_printf("age %s %s\n", from, to);
						free(from);
						free(to);
					} else {
						rz_cons_printf("        \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
							       "[color=\"%s\"];\n",
							bbi->addr, bbi->fail, pal_fail);
						core_analysis_color_curr_node(core, bbi);
					}
				}
			}
			rz_list_foreach (bbi->switch_op->cases, iter, caseop) {
				nodes++;
				if (is_keva) {
					char key[128];
					snprintf(key, sizeof(key),
						"bb.0x%08" PFMT64x ".switch.%" PFMT64d,
						bbi->addr, caseop->value);
					sdb_num_set(DB, key, caseop->jump, 0);
					snprintf(key, sizeof(key),
						"bb.0x%08" PFMT64x ".switch", bbi->addr);
					sdb_array_add_num(DB, key, caseop->value, 0);
				} else if (is_html) {
					rz_cons_printf("<div class=\"connector _0x%08" PFMT64x " _0x%08" PFMT64x "\">\n"
						       "  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
						caseop->addr, caseop->jump);
				} else if (!is_json && !is_keva) {
					if (is_star) {
						char *from = get_title(caseop->addr);
						char *to = get_title(caseop->jump);
						rz_cons_printf("age %s %s\n", from, to);
						free(from);
						free(to);
					} else {
						rz_cons_printf("        \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
							       "[color2=\"%s\"];\n",
							caseop->addr, caseop->jump, pal_fail);
						core_analysis_color_curr_node(core, bbi);
					}
				}
			}
		}
	}
	free(pal_jump);
	free(pal_fail);
	free(pal_trfa);
	return nodes;
}

static int core_analysis_graph_construct_nodes(RzCore *core, RzAnalysisFunction *fcn, int opts, PJ *pj, Sdb *DB) {
	RzAnalysisBlock *bbi;
	RzListIter *iter;
	int is_keva = opts & RZ_CORE_ANALYSIS_KEYVALUE;
	int is_star = opts & RZ_CORE_ANALYSIS_STAR;
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;
	int is_html = rz_cons_singleton()->is_html;
	int left = 300;
	int top = 0;

	int is_json_format_disasm = opts & RZ_CORE_ANALYSIS_JSON_FORMAT_DISASM;
	char *pal_curr = palColorFor("graph.current");
	char *pal_traced = palColorFor("graph.traced");
	char *pal_box4 = palColorFor("graph.box4");
	const char *font = rz_config_get(core->config, "graph.font");
	bool color_current = rz_config_get_i(core->config, "graph.gv.current");
	char *str;
	int nodes = 0;
	rz_list_foreach (fcn->bbs, iter, bbi) {
		if (is_keva) {
			char key[128];
			sdb_array_push_num(DB, "bbs", bbi->addr, 0);
			snprintf(key, sizeof(key), "bb.0x%08" PFMT64x ".size", bbi->addr);
			sdb_num_set(DB, key, bbi->size, 0); // bb.<addr>.size=<num>
		} else if (is_json) {
			RzDebugTracepoint *t = rz_debug_trace_get(core->dbg, bbi->addr);
			ut8 *buf = malloc(bbi->size);
			pj_o(pj);
			pj_kn(pj, "offset", bbi->addr);
			pj_kn(pj, "size", bbi->size);
			if (bbi->jump != UT64_MAX) {
				pj_kn(pj, "jump", bbi->jump);
			}
			if (bbi->fail != -1) {
				pj_kn(pj, "fail", bbi->fail);
			}
			if (bbi->switch_op) {
				RzAnalysisSwitchOp *op = bbi->switch_op;
				pj_k(pj, "switchop");
				pj_o(pj);
				pj_kn(pj, "offset", op->addr);
				pj_kn(pj, "defval", op->def_val);
				pj_kn(pj, "maxval", op->max_val);
				pj_kn(pj, "minval", op->min_val);
				pj_k(pj, "cases");
				pj_a(pj);
				RzAnalysisCaseOp *case_op;
				RzListIter *case_iter;
				rz_list_foreach (op->cases, case_iter, case_op) {
					pj_o(pj);
					pj_kn(pj, "offset", case_op->addr);
					pj_kn(pj, "value", case_op->value);
					pj_kn(pj, "jump", case_op->jump);
					pj_end(pj);
				}
				pj_end(pj);
				pj_end(pj);
			}
			if (t) {
				pj_k(pj, "trace");
				pj_o(pj);
				pj_ki(pj, "count", t->count);
				pj_ki(pj, "times", t->times);
				pj_end(pj);
			}
			pj_kn(pj, "colorize", bbi->colorize);
			pj_k(pj, "ops");
			pj_a(pj);
			if (buf) {
				rz_io_read_at(core->io, bbi->addr, buf, bbi->size);
				if (is_json_format_disasm) {
					rz_core_print_disasm(core->print, core, bbi->addr, buf, bbi->size, bbi->size, 0, 1, true, pj, NULL);
				} else {
					rz_core_print_disasm_json(core, bbi->addr, buf, bbi->size, 0, pj);
				}
				free(buf);
			} else {
				eprintf("cannot allocate %" PFMT64u " byte(s)\n", bbi->size);
			}
			pj_end(pj);
			pj_end(pj);
			continue;
		}
		if ((str = core_analysis_graph_label(core, bbi, opts))) {
			if (opts & RZ_CORE_ANALYSIS_GRAPHDIFF) {
				const char *difftype = bbi->diff ? (
									   bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? "lightgray" : bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? "yellow"
																							   : "red")
								 : "orange";
				const char *diffname = bbi->diff ? (
									   bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? "match" : bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? "unmatch"
																						       : "new")
								 : "unk";
				if (is_keva) {
					sdb_set(DB, "diff", diffname, 0);
					sdb_set(DB, "label", str, 0);
				} else if (!is_json) {
					nodes++;
					RzConfigHold *hc = rz_config_hold_new(core->config);
					rz_config_hold_i(hc, "scr.color", "scr.utf8", "asm.offset", "asm.lines",
						"asm.cmt.right", "asm.lines.fcn", "asm.bytes", NULL);
					RzDiff *d = rz_diff_new();
					rz_config_set_i(core->config, "scr.utf8", 0);
					rz_config_set_i(core->config, "asm.offset", 0);
					rz_config_set_i(core->config, "asm.lines", 0);
					rz_config_set_i(core->config, "asm.cmt.right", 0);
					rz_config_set_i(core->config, "asm.lines.fcn", 0);
					rz_config_set_i(core->config, "asm.bytes", 0);
					if (!is_star) {
						rz_config_set_i(core->config, "scr.color", 0); // disable color for dot
					}

					if (bbi->diff && bbi->diff->type != RZ_ANALYSIS_DIFF_TYPE_MATCH && core->c2) {
						RzCore *c = core->c2;
						RzConfig *oc = c->config;
						char *str = rz_core_cmd_strf(core, "pdb @ 0x%08" PFMT64x, bbi->addr);
						c->config = core->config;
						// XXX. the bbi->addr doesnt needs to be in the same address in core2
						char *str2 = rz_core_cmd_strf(c, "pdb @ 0x%08" PFMT64x, bbi->diff->addr);
						char *diffstr = rz_diff_buffers_to_string(d,
							(const ut8 *)str, strlen(str),
							(const ut8 *)str2, strlen(str2));

						if (diffstr) {
							char *nl = strchr(diffstr, '\n');
							if (nl) {
								nl = strchr(nl + 1, '\n');
								if (nl) {
									nl = strchr(nl + 1, '\n');
									if (nl) {
										rz_str_cpy(diffstr, nl + 1);
									}
								}
							}
						}

						if (is_star) {
							char *title = get_title(bbi->addr);
							char *body_b64 = rz_base64_encode_dyn((const ut8 *)diffstr, strlen(diffstr));
							if (!title || !body_b64) {
								free(body_b64);
								free(title);
								rz_diff_free(d);
								return false;
							}
							body_b64 = rz_str_prepend(body_b64, "base64:");
							rz_cons_printf("agn %s %s %d\n", title, body_b64, bbi->diff->type);
							free(body_b64);
							free(title);
						} else {
							diffstr = rz_str_replace(diffstr, "\n", "\\l", 1);
							diffstr = rz_str_replace(diffstr, "\"", "'", 1);
							rz_cons_printf(" \"0x%08" PFMT64x "\" [fillcolor=\"%s\","
								       "color=\"black\", fontname=\"%s\","
								       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
								bbi->addr, difftype, diffstr, font, fcn->name,
								bbi->addr);
						}
						free(diffstr);
						c->config = oc;
					} else {
						if (is_star) {
							char *title = get_title(bbi->addr);
							char *body_b64 = rz_base64_encode_dyn((const ut8 *)str, strlen(title));
							int color = (bbi && bbi->diff) ? bbi->diff->type : 0;
							if (!title || !body_b64) {
								free(body_b64);
								free(title);
								rz_diff_free(d);
								return false;
							}
							body_b64 = rz_str_prepend(body_b64, "base64:");
							rz_cons_printf("agn %s %s %d\n", title, body_b64, color);
							free(body_b64);
							free(title);
						} else {
							rz_cons_printf(" \"0x%08" PFMT64x "\" [fillcolor=\"%s\","
								       "color=\"black\", fontname=\"%s\","
								       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
								bbi->addr, difftype, str, font, fcn->name, bbi->addr);
						}
					}
					rz_diff_free(d);
					rz_config_set_i(core->config, "scr.color", 1);
					rz_config_hold_free(hc);
				}
			} else {
				if (is_html) {
					nodes++;
					rz_cons_printf("<p class=\"block draggable\" style=\""
						       "top: %dpx; left: %dpx; width: 400px;\" id=\""
						       "_0x%08" PFMT64x "\">\n%s</p>\n",
						top, left, bbi->addr, str);
					left = left ? 0 : 600;
					if (!left) {
						top += 250;
					}
				} else if (!is_json && !is_keva) {
					bool current = rz_analysis_block_contains(bbi, core->offset);
					const char *label_color = bbi->traced
						? pal_traced
						: (current && color_current)
						? pal_curr
						: pal_box4;
					const char *fill_color = ((current && color_current) || label_color == pal_traced) ? pal_traced : "white";
					nodes++;
					if (is_star) {
						char *title = get_title(bbi->addr);
						char *body_b64 = rz_base64_encode_dyn((const ut8 *)str, strlen(str));
						int color = (bbi && bbi->diff) ? bbi->diff->type : 0;
						if (!title || !body_b64) {
							free(body_b64);
							free(title);
							return false;
						}
						body_b64 = rz_str_prepend(body_b64, "base64:");
						rz_cons_printf("agn %s %s %d\n", title, body_b64, color);
						free(body_b64);
						free(title);
					} else {
						rz_cons_printf("\t\"0x%08" PFMT64x "\" ["
							       "URL=\"%s/0x%08" PFMT64x "\", fillcolor=\"%s\","
							       "color=\"%s\", fontname=\"%s\","
							       "label=\"%s\"]\n",
							bbi->addr, fcn->name, bbi->addr,
							fill_color, label_color, font, str);
					}
				}
			}
			free(str);
		}
	}
	return nodes;
}

static int core_analysis_graph_nodes(RzCore *core, RzAnalysisFunction *fcn, int opts, PJ *pj) {
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;
	int is_keva = opts & RZ_CORE_ANALYSIS_KEYVALUE;
	int nodes = 0;
	Sdb *DB = NULL;
	char *pal_jump = palColorFor("graph.true");
	char *pal_fail = palColorFor("graph.false");
	char *pal_trfa = palColorFor("graph.trufae");
	char *pal_curr = palColorFor("graph.current");
	char *pal_traced = palColorFor("graph.traced");
	char *pal_box4 = palColorFor("graph.box4");
	if (!fcn || !fcn->bbs) {
		eprintf("No fcn\n");
		return -1;
	}

	if (is_keva) {
		char ns[64];
		DB = sdb_ns(core->analysis->sdb, "graph", 1);
		snprintf(ns, sizeof(ns), "fcn.0x%08" PFMT64x, fcn->addr);
		DB = sdb_ns(DB, ns, 1);
	}

	if (is_keva) {
		char *ename = sdb_encode((const ut8 *)fcn->name, -1);
		sdb_set(DB, "name", fcn->name, 0);
		sdb_set(DB, "ename", ename, 0);
		free(ename);
		sdb_num_set(DB, "size", rz_analysis_function_linear_size(fcn), 0);
		if (fcn->maxstack > 0) {
			sdb_num_set(DB, "stack", fcn->maxstack, 0);
		}
		sdb_set(DB, "pos", "0,0", 0); // needs to run layout
		sdb_set(DB, "type", rz_analysis_fcntype_tostring(fcn->type), 0);
	} else if (is_json) {
		// TODO: show vars, refs and xrefs
		char *fcn_name_escaped = rz_str_escape_utf8_for_json(fcn->name, -1);
		pj_o(pj);
		pj_ks(pj, "name", rz_str_get_null(fcn_name_escaped));
		free(fcn_name_escaped);
		pj_kn(pj, "offset", fcn->addr);
		pj_ki(pj, "ninstr", fcn->ninstr);
		pj_ki(pj, "nargs",
			rz_analysis_var_count(core->analysis, fcn, 'r', 1) +
				rz_analysis_var_count(core->analysis, fcn, 's', 1) +
				rz_analysis_var_count(core->analysis, fcn, 'b', 1));
		pj_ki(pj, "nlocals",
			rz_analysis_var_count(core->analysis, fcn, 'r', 0) +
				rz_analysis_var_count(core->analysis, fcn, 's', 0) +
				rz_analysis_var_count(core->analysis, fcn, 'b', 0));
		pj_kn(pj, "size", rz_analysis_function_linear_size(fcn));
		pj_ki(pj, "stack", fcn->maxstack);
		pj_ks(pj, "type", rz_analysis_fcntype_tostring(fcn->type));
		pj_k(pj, "blocks");
		pj_a(pj);
	}
	nodes += core_analysis_graph_construct_nodes(core, fcn, opts, pj, DB);
	nodes += core_analysis_graph_construct_edges(core, fcn, opts, pj, DB);
	if (is_json) {
		pj_end(pj);
		pj_end(pj);
	}
	free(pal_jump);
	free(pal_fail);
	free(pal_trfa);
	free(pal_curr);
	free(pal_traced);
	free(pal_box4);
	return nodes;
}

/* seek basic block that contains address addr or do nothing if there is no block. */
RZ_API bool rz_core_analysis_bb_seek(RzCore *core, ut64 addr) {
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
	if (block) {
		rz_core_seek_and_save(core, block->addr, false);
		return true;
	}
	return false;
}

RZ_API int rz_core_analysis_esil_fcn(RzCore *core, ut64 at, ut64 from, int reftype, int depth) {
	const char *esil;
	eprintf("TODO\n");
	while (1) {
		// TODO: Implement the proper logic for doing esil analysis
		RzAnalysisOp *op = rz_core_analysis_op(core, at, RZ_ANALYSIS_OP_MASK_ESIL);
		if (!op) {
			break;
		}
		esil = RZ_STRBUF_SAFEGET(&op->esil);
		eprintf("0x%08" PFMT64x " %d %s\n", at, op->size, esil);
		// at += op->size;
		// esilIsRet()
		// esilIsCall()
		// esilIsJmp()
		rz_analysis_op_free(op);
		break;
	}
	return 0;
}

static int find_sym_flag(const void *a1, const void *a2) {
	const RzFlagItem *f = (const RzFlagItem *)a2;
	return f->space && !strcmp(f->space->name, RZ_FLAGS_FS_SYMBOLS) ? 0 : 1;
}

static bool is_skippable_addr(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (!fcn) {
		return false;
	}
	if (fcn->addr == addr) {
		return true;
	}
	const RzList *flags = rz_flag_get_list(core->flags, addr);
	return !(flags && rz_list_find(flags, fcn, find_sym_flag));
}

// XXX: This function takes sometimes forever
/* analyze a RzAnalysisFunction at the address 'at'.
 * If the function has been already analyzed, it adds a
 * reference to that fcn */
RZ_API int rz_core_analysis_fcn(RzCore *core, ut64 at, ut64 from, int reftype, int depth) {
	if (from == UT64_MAX && is_skippable_addr(core, at)) {
		if (core->analysis->verbose) {
			eprintf("Message: Invalid address for function 0x%08" PFMT64x "\n", at);
		}
		return 0;
	}

	const bool use_esil = rz_config_get_i(core->config, "analysis.esil");
	RzAnalysisFunction *fcn;

	//update bits based on the core->offset otherwise we could have the
	//last value set and blow everything up
	rz_core_seek_arch_bits(core, at);

	if (core->io->va) {
		if (!rz_io_is_valid_offset(core->io, at, !core->analysis->opt.noncode)) {
			if (core->analysis->verbose) {
				eprintf("Warning: Address not mapped or not executable at 0x%08" PFMT64x "\n", at);
			}
			return false;
		}
	}
	if (use_esil) {
		return rz_core_analysis_esil_fcn(core, at, from, reftype, depth);
	}

	if ((from != UT64_MAX && !at) || at == UT64_MAX) {
		eprintf("Invalid address from 0x%08" PFMT64x "\n", from);
		return false;
	}
	if (depth < 0) {
		if (core->analysis->verbose) {
			eprintf("Warning: analysis depth reached\n");
		}
		return false;
	}
	if (rz_cons_is_breaked()) {
		return false;
	}
	fcn = rz_analysis_get_fcn_in(core->analysis, at, 0);
	if (fcn) {
		if (fcn->addr == at) {
			// if the function was already analyzed as a "loc.",
			// convert it to function and rename it to "fcn.",
			// because we found a call to this address
			if (reftype == RZ_ANALYSIS_REF_TYPE_CALL && fcn->type == RZ_ANALYSIS_FCN_TYPE_LOC) {
				function_rename(core->flags, fcn);
			}

			return 0; // already analyzed function
		}
		if (rz_analysis_function_contains(fcn, from)) { // inner function
			RzList *l = rz_analysis_xrefs_get(core->analysis, from);
			if (l && !rz_list_empty(l)) {
				rz_list_free(l);
				return true;
			}
			rz_list_free(l);

			// we should analyze and add code ref otherwise aaa != aac
			if (from != UT64_MAX) {
				rz_analysis_xrefs_set(core->analysis, from, at, reftype);
			}
			return true;
		}
	}
	if (__core_analysis_fcn(core, at, from, reftype, depth - 1)) {
		// split function if overlaps
		if (fcn) {
			rz_analysis_function_resize(fcn, at - fcn->addr);
		}
		return true;
	}
	return false;
}

/* if addr is 0, remove all functions
 * otherwise remove the function addr falls into */
RZ_API int rz_core_analysis_fcn_clean(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcni;
	RzListIter *iter, *iter_tmp;

	if (!addr) {
		rz_list_purge(core->analysis->fcns);
		if (!(core->analysis->fcns = rz_list_new())) {
			return false;
		}
	} else {
		rz_list_foreach_safe (core->analysis->fcns, iter, iter_tmp, fcni) {
			if (rz_analysis_function_contains(fcni, addr)) {
				rz_analysis_function_delete(fcni);
			}
		}
	}
	return true;
}

RZ_API int rz_core_print_bb_custom(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *iter;
	if (!fcn) {
		return false;
	}

	RzConfigHold *hc = rz_config_hold_new(core->config);
	rz_config_hold_i(hc, "scr.color", "scr.utf8", "asm.marks", "asm.offset", "asm.lines",
		"asm.cmt.right", "asm.cmt.col", "asm.lines.fcn", "asm.bytes", NULL);
	/*rz_config_set_i (core->config, "scr.color", 0);*/
	rz_config_set_i(core->config, "scr.utf8", 0);
	rz_config_set_i(core->config, "asm.marks", 0);
	rz_config_set_i(core->config, "asm.offset", 0);
	rz_config_set_i(core->config, "asm.lines", 0);
	rz_config_set_i(core->config, "asm.cmt.right", 0);
	rz_config_set_i(core->config, "asm.cmt.col", 0);
	rz_config_set_i(core->config, "asm.lines.fcn", 0);
	rz_config_set_i(core->config, "asm.bytes", 0);

	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *title = get_title(bb->addr);
		char *body = rz_core_cmd_strf(core, "pdb @ 0x%08" PFMT64x, bb->addr);
		char *body_b64 = rz_base64_encode_dyn((const ut8 *)body, strlen(body));
		if (!title || !body || !body_b64) {
			free(body_b64);
			free(body);
			free(title);
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			return false;
		}
		body_b64 = rz_str_prepend(body_b64, "base64:");
		rz_cons_printf("agn %s %s\n", title, body_b64);
		free(body);
		free(body_b64);
		free(title);
	}

	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);

	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *u = get_title(bb->addr), *v = NULL;
		if (bb->jump != UT64_MAX) {
			v = get_title(bb->jump);
			rz_cons_printf("age %s %s\n", u, v);
			free(v);
		}
		if (bb->fail != UT64_MAX) {
			v = get_title(bb->fail);
			rz_cons_printf("age %s %s\n", u, v);
			free(v);
		}
		if (bb->switch_op) {
			RzListIter *it;
			RzAnalysisCaseOp *cop;
			rz_list_foreach (bb->switch_op->cases, it, cop) {
				v = get_title(cop->addr);
				rz_cons_printf("age %s %s\n", u, v);
				free(v);
			}
		}
		free(u);
	}
	return true;
}

#define USE_ID 1
RZ_API int rz_core_print_bb_gml(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *iter;
	if (!fcn) {
		return false;
	}
	int id = 0;
	HtUUOptions opt = { 0 };
	HtUU *ht = ht_uu_new_opt(&opt);

	rz_cons_printf("graph\n[\n"
		       "hierarchic 1\n"
		       "label \"\"\n"
		       "directed 1\n");

	rz_list_foreach (fcn->bbs, iter, bb) {
		RzFlagItem *flag = rz_flag_get_i(core->flags, bb->addr);
		char *msg = flag ? strdup(flag->name) : rz_str_newf("0x%08" PFMT64x, bb->addr);
#if USE_ID
		ht_uu_insert(ht, bb->addr, id);
		rz_cons_printf("  node [\n"
			       "    id  %d\n"
			       "    label  \"%s\"\n"
			       "  ]\n",
			id, msg);
		id++;
#else
		rz_cons_printf("  node [\n"
			       "    id  %" PFMT64d "\n"
			       "    label  \"%s\"\n"
			       "  ]\n",
			bb->addr, msg);
#endif
		free(msg);
	}

	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}

#if USE_ID
		if (bb->jump != UT64_MAX) {
			bool found;
			int i = ht_uu_find(ht, bb->addr, &found);
			if (found) {
				int i2 = ht_uu_find(ht, bb->jump, &found);
				if (found) {
					rz_cons_printf("  edge [\n"
						       "    source  %d\n"
						       "    target  %d\n"
						       "  ]\n",
						i, i2);
				}
			}
		}
		if (bb->fail != UT64_MAX) {
			bool found;
			int i = ht_uu_find(ht, bb->addr, &found);
			if (found) {
				int i2 = ht_uu_find(ht, bb->fail, &found);
				if (found) {
					rz_cons_printf("  edge [\n"
						       "    source  %d\n"
						       "    target  %d\n"
						       "  ]\n",
						i, i2);
				}
			}
		}
		if (bb->switch_op) {
			RzListIter *it;
			RzAnalysisCaseOp *cop;
			rz_list_foreach (bb->switch_op->cases, it, cop) {
				bool found;
				int i = ht_uu_find(ht, bb->addr, &found);
				if (found) {
					int i2 = ht_uu_find(ht, cop->addr, &found);
					if (found) {
						rz_cons_printf("  edge [\n"
							       "    source  %d\n"
							       "    target  %d\n"
							       "  ]\n",
							i, i2);
					}
				}
			}
		}
#else
		if (bb->jump != UT64_MAX) {
			rz_cons_printf("  edge [\n"
				       "    source  %" PFMT64d "\n"
				       "    target  %" PFMT64d "\n"
				       "  ]\n",
				bb->addr, bb->jump);
		}
		if (bb->fail != UT64_MAX) {
			rz_cons_printf("  edge [\n"
				       "    source  %" PFMT64d "\n"
				       "    target  %" PFMT64d "\n"
				       "  ]\n",
				bb->addr, bb->fail);
		}
		if (bb->switch_op) {
			RzListIter *it;
			RzAnalysisCaseOp *cop;
			rz_list_foreach (bb->switch_op->cases, it, cop) {
				rz_cons_printf("  edge [\n"
					       "    source  %" PFMT64d "\n"
					       "    target  %" PFMT64d "\n"
					       "  ]\n",
					bb->addr, cop->addr);
			}
		}
#endif
	}
	rz_cons_printf("]\n");
	ht_uu_free(ht);
	return true;
}

RZ_API void rz_core_analysis_datarefs(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
	if (fcn) {
		bool found = false;
		const char *me = fcn->name;
		RzListIter *iter;
		RzAnalysisRef *ref;
		RzList *refs = rz_analysis_function_get_refs(fcn);
		rz_list_foreach (refs, iter, ref) {
			RzBinObject *obj = rz_bin_cur_object(core->bin);
			RzBinSection *binsec = rz_bin_get_section_at(obj, ref->addr, true);
			if (binsec && binsec->is_data) {
				if (!found) {
					rz_cons_printf("agn %s\n", me);
					found = true;
				}
				RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
				const char *dst = item ? item->name : sdb_fmt("0x%08" PFMT64x, ref->addr);
				rz_cons_printf("agn %s\n", dst);
				rz_cons_printf("age %s %s\n", me, dst);
			}
		}
		rz_list_free(refs);
	} else {
		eprintf("Not in a function. Use 'df' to define it.\n");
	}
}

RZ_API void rz_core_analysis_coderefs(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
	if (fcn) {
		const char *me = fcn->name;
		RzListIter *iter;
		RzAnalysisRef *ref;
		RzList *refs = rz_analysis_function_get_refs(fcn);
		rz_cons_printf("agn %s\n", me);
		rz_list_foreach (refs, iter, ref) {
			RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
			const char *dst = item ? item->name : sdb_fmt("0x%08" PFMT64x, ref->addr);
			rz_cons_printf("agn %s\n", dst);
			rz_cons_printf("age %s %s\n", me, dst);
		}
		rz_list_free(refs);
	} else {
		eprintf("Not in a function. Use 'df' to define it.\n");
	}
}

static void add_single_addr_xrefs(RzCore *core, ut64 addr, RzGraph *graph) {
	rz_return_if_fail(graph);
	RzFlagItem *f = rz_flag_get_at(core->flags, addr, false);
	char *me = (f && f->offset == addr)
		? rz_str_new(f->name)
		: rz_str_newf("0x%" PFMT64x, addr);

	RzGraphNode *curr_node = rz_graph_add_node_info(graph, me, NULL, addr);
	RZ_FREE(me);
	if (!curr_node) {
		return;
	}
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzList *list = rz_analysis_xrefs_get(core->analysis, addr);
	rz_list_foreach (list, iter, ref) {
		RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
		char *src = item ? rz_str_new(item->name) : rz_str_newf("0x%08" PFMT64x, ref->addr);
		RzGraphNode *reference_from = rz_graph_add_node_info(graph, src, NULL, ref->addr);
		free(src);
		rz_graph_add_edge(graph, reference_from, curr_node);
	}
	rz_list_free(list);
}

RZ_API RzGraph *rz_core_analysis_importxrefs(RzCore *core) {
	RzBinInfo *info = rz_bin_get_info(core->bin);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	bool lit = info ? info->has_lit : false;
	bool va = core->io->va || core->bin->is_debugger;

	RzListIter *iter;
	RzBinImport *imp;
	if (!obj) {
		return NULL;
	}
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	rz_list_foreach (obj->imports, iter, imp) {
		ut64 addr = lit ? rz_core_bin_impaddr(core->bin, va, imp->name) : 0;
		if (addr) {
			add_single_addr_xrefs(core, addr, graph);
		} else {
			rz_graph_add_node_info(graph, imp->name, NULL, 0);
		}
	}
	return graph;
}

RZ_API RzGraph *rz_core_analysis_codexrefs(RzCore *core, ut64 addr) {
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	add_single_addr_xrefs(core, addr, graph);
	return graph;
}

static int RzAnalysisRef_cmp(const RzAnalysisRef *ref1, const RzAnalysisRef *ref2) {
	return ref1->addr != ref2->addr;
}

RZ_API void rz_core_analysis_callgraph(RzCore *core, ut64 addr, int fmt) {
	const char *font = rz_config_get(core->config, "graph.font");
	int is_html = rz_cons_singleton()->is_html;
	bool refgraph = rz_config_get_i(core->config, "graph.refs");
	RzListIter *iter, *iter2;
	int usenames = rz_config_get_i(core->config, "graph.json.usenames");
	;
	RzAnalysisFunction *fcni;
	RzAnalysisRef *fcnr;
	PJ *pj = NULL;

	ut64 from = rz_config_get_i(core->config, "graph.from");
	ut64 to = rz_config_get_i(core->config, "graph.to");

	switch (fmt) {
	case RZ_GRAPH_FORMAT_JSON:
		pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
		break;
	case RZ_GRAPH_FORMAT_GML:
	case RZ_GRAPH_FORMAT_GMLFCN:
		rz_cons_printf("graph\n[\n"
			       "hierarchic  1\n"
			       "label  \"\"\n"
			       "directed  1\n");
		break;
	case RZ_GRAPH_FORMAT_DOT:
		if (!is_html) {
			const char *gv_edge = rz_config_get(core->config, "graph.gv.edge");
			char *gv_node = strdup(rz_config_get(core->config, "graph.gv.node"));
			const char *gv_grph = rz_config_get(core->config, "graph.gv.graph");
			const char *gv_spline = rz_config_get(core->config, "graph.gv.spline");
			if (!gv_edge || !*gv_edge) {
				gv_edge = "arrowhead=\"normal\" style=bold weight=2";
			}
			if (!gv_node || !*gv_node) {
				free(gv_node);
				gv_node = rz_str_newf("penwidth=4 fillcolor=white style=filled fontname=\"%s Bold\" fontsize=14 shape=box", font);
			}
			if (!gv_grph || !*gv_grph) {
				gv_grph = "bgcolor=azure";
			}
			if (!gv_spline || !*gv_spline) {
				// ortho for bbgraph and curved for callgraph
				gv_spline = "splines=\"curved\"";
			}
			rz_cons_printf("digraph code {\n"
				       "rankdir=LR;\n"
				       "outputorder=edgesfirst;\n"
				       "graph [%s fontname=\"%s\" %s];\n"
				       "node [%s];\n"
				       "edge [%s];\n",
				gv_grph, font, gv_spline,
				gv_node, gv_edge);
			free(gv_node);
		}
		break;
	}
	ut64 base = UT64_MAX;
	int iteration = 0;
repeat:
	rz_list_foreach (core->analysis->fcns, iter, fcni) {
		if (base == UT64_MAX) {
			base = fcni->addr;
		}
		if (from != UT64_MAX && fcni->addr < from) {
			continue;
		}
		if (to != UT64_MAX && fcni->addr > to) {
			continue;
		}
		if (addr != UT64_MAX && addr != fcni->addr) {
			continue;
		}
		RzList *refs = rz_analysis_function_get_refs(fcni);
		RzList *calls = rz_list_new();
		// TODO: maybe fcni->calls instead ?
		rz_list_foreach (refs, iter2, fcnr) {
			//  TODO: tail calll jumps are also calls
			if (fcnr->type == 'C' && rz_list_find(calls, fcnr, (RzListComparator)RzAnalysisRef_cmp) == NULL) {
				rz_list_append(calls, fcnr);
			}
		}
		if (rz_list_empty(calls)) {
			rz_list_free(refs);
			rz_list_free(calls);
			continue;
		}
		switch (fmt) {
		case RZ_GRAPH_FORMAT_NO:
			rz_cons_printf("0x%08" PFMT64x "\n", fcni->addr);
			break;
		case RZ_GRAPH_FORMAT_GML:
		case RZ_GRAPH_FORMAT_GMLFCN: {
			RzFlagItem *flag = rz_flag_get_i(core->flags, fcni->addr);
			if (iteration == 0) {
				char *msg = flag ? strdup(flag->name) : rz_str_newf("0x%08" PFMT64x, fcni->addr);
				rz_cons_printf("  node [\n"
					       "  id  %" PFMT64d "\n"
					       "    label  \"%s\"\n"
					       "  ]\n",
					fcni->addr - base, msg);
				free(msg);
			}
			break;
		}
		case RZ_GRAPH_FORMAT_JSON:
			pj_o(pj);
			if (usenames) {
				pj_ks(pj, "name", fcni->name);
			} else {
				char fcni_addr[20];
				snprintf(fcni_addr, sizeof(fcni_addr) - 1, "0x%08" PFMT64x, fcni->addr);
				pj_ks(pj, "name", fcni_addr);
			}
			pj_kn(pj, "size", rz_analysis_function_linear_size(fcni));
			pj_ka(pj, "imports");
			break;
		case RZ_GRAPH_FORMAT_DOT:
			rz_cons_printf("  \"0x%08" PFMT64x "\" "
				       "[label=\"%s\""
				       " URL=\"%s/0x%08" PFMT64x "\"];\n",
				fcni->addr, fcni->name,
				fcni->name, fcni->addr);
		}
		rz_list_foreach (calls, iter2, fcnr) {
			// TODO: display only code or data refs?
			RzFlagItem *flag = rz_flag_get_i(core->flags, fcnr->addr);
			char *fcnr_name = (flag && flag->name) ? flag->name : rz_str_newf("unk.0x%" PFMT64x, fcnr->addr);
			switch (fmt) {
			case RZ_GRAPH_FORMAT_GMLFCN:
				if (iteration == 0) {
					rz_cons_printf("  node [\n"
						       "    id  %" PFMT64d "\n"
						       "    label  \"%s\"\n"
						       "  ]\n",
						fcnr->addr - base, fcnr_name);
					rz_cons_printf("  edge [\n"
						       "    source  %" PFMT64d "\n"
						       "    target  %" PFMT64d "\n"
						       "  ]\n",
						fcni->addr - base, fcnr->addr - base);
				}
			case RZ_GRAPH_FORMAT_GML:
				if (iteration != 0) {
					rz_cons_printf("  edge [\n"
						       "    source  %" PFMT64d "\n"
						       "    target  %" PFMT64d "\n"
						       "  ]\n",
						fcni->addr - base, fcnr->addr - base); //, "#000000"
				}
				break;
			case RZ_GRAPH_FORMAT_DOT:
				rz_cons_printf("  \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
					       "[color=\"%s\" URL=\"%s/0x%08" PFMT64x "\"];\n",
					//"[label=\"%s\" color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
					fcni->addr, fcnr->addr, //, fcnr_name,
					"#61afef",
					fcnr_name, fcnr->addr);
				rz_cons_printf("  \"0x%08" PFMT64x "\" "
					       "[label=\"%s\""
					       " URL=\"%s/0x%08" PFMT64x "\"];\n",
					fcnr->addr, fcnr_name,
					fcnr_name, fcnr->addr);
				break;
			case RZ_GRAPH_FORMAT_JSON:
				if (usenames) {
					pj_s(pj, fcnr_name);
				} else {
					char fcnr_addr[20];
					snprintf(fcnr_addr, sizeof(fcnr_addr) - 1, "0x%08" PFMT64x, fcnr->addr);
					pj_s(pj, fcnr_addr);
				}
				break;
			default:
				if (refgraph || fcnr->type == RZ_ANALYSIS_REF_TYPE_CALL) {
					// TODO: avoid recreating nodes unnecessarily
					rz_cons_printf("agn %s\n", fcni->name);
					rz_cons_printf("agn %s\n", fcnr_name);
					rz_cons_printf("age %s %s\n", fcni->name, fcnr_name);
				} else {
					rz_cons_printf("# - 0x%08" PFMT64x " (%c)\n", fcnr->addr, fcnr->type);
				}
			}
			if (!(flag && flag->name)) {
				free(fcnr_name);
			}
		}
		rz_list_free(refs);
		rz_list_free(calls);
		if (fmt == RZ_GRAPH_FORMAT_JSON) {
			pj_end(pj);
			pj_end(pj);
		}
	}
	if (iteration == 0 && fmt == RZ_GRAPH_FORMAT_GML) {
		iteration++;
		goto repeat;
	}
	if (iteration == 0 && fmt == RZ_GRAPH_FORMAT_GMLFCN) {
		iteration++;
	}
	switch (fmt) {
	case RZ_GRAPH_FORMAT_GML:
	case RZ_GRAPH_FORMAT_GMLFCN:
		rz_cons_printf("]\n");
		break;
	case RZ_GRAPH_FORMAT_JSON:
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		break;
	case RZ_GRAPH_FORMAT_DOT:
		rz_cons_printf("}\n");
		break;
	}
}

static void fcn_list_bbs(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bbi;
	RzListIter *iter;

	rz_list_foreach (fcn->bbs, iter, bbi) {
		rz_cons_printf("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %" PFMT64u " ",
			fcn->addr, bbi->addr, bbi->size);
		rz_cons_printf("0x%08" PFMT64x " ", bbi->jump);
		rz_cons_printf("0x%08" PFMT64x, bbi->fail);
		if (bbi->diff) {
			if (bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH) {
				rz_cons_printf(" m");
			} else if (bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH) {
				rz_cons_printf(" u");
			} else {
				rz_cons_printf(" n");
			}
		}
		rz_cons_printf("\n");
	}
}

RZ_API ut64 rz_core_analysis_fcn_list_size(RzCore *core) {
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	ut64 total = 0;

	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		total += rz_analysis_function_realsize(fcn);
	}
	rz_cons_printf("%" PFMT64u "\n", total);
	return total;
}

/* Fill out metadata struct of functions */
static int fcnlist_gather_metadata(RzAnalysis *analysis, RzList *fcns) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	RzList *xrefs;

	rz_list_foreach (fcns, iter, fcn) {
		// Count the number of references and number of calls
		RzListIter *callrefiter;
		RzAnalysisRef *ref;
		RzList *refs = rz_analysis_function_get_refs(fcn);
		int numcallrefs = 0;
		rz_list_foreach (refs, callrefiter, ref) {
			if (ref->type == RZ_ANALYSIS_REF_TYPE_CALL) {
				numcallrefs++;
			}
		}
		rz_list_free(refs);
		fcn->meta.numcallrefs = numcallrefs;
		xrefs = rz_analysis_xrefs_get(analysis, fcn->addr);
		fcn->meta.numrefs = xrefs ? xrefs->length : 0;
		rz_list_free(xrefs);
	}
	// TODO: Determine sgnc, sgec
	return 0;
}

RZ_API char *rz_core_analysis_fcn_name(RzCore *core, RzAnalysisFunction *fcn) {
	bool demangle = rz_config_get_i(core->config, "bin.demangle");
	const char *lang = demangle ? rz_config_get(core->config, "bin.lang") : NULL;
	bool keep_lib = rz_config_get_i(core->config, "bin.demangle.libs");
	char *name = strdup(fcn->name ? fcn->name : "");
	if (demangle) {
		char *tmp = rz_bin_demangle(core->bin->cur, lang, name, fcn->addr, keep_lib);
		if (tmp) {
			free(name);
			name = tmp;
		}
	}
	return name;
}

#define FCN_LIST_VERBOSE_ENTRY "%s0x%0*" PFMT64x " %4" PFMT64d " %5d %5d %5d %4d 0x%0*" PFMT64x " %5" PFMT64d " 0x%0*" PFMT64x " %5d %4d %6d %4d %5d %s%s\n"
static int fcn_print_verbose(RzCore *core, RzAnalysisFunction *fcn, bool use_color) {
	char *name = rz_core_analysis_fcn_name(core, fcn);
	int ebbs = 0;
	int addrwidth = 8;
	const char *color = "";
	const char *color_end = "";
	if (use_color) {
		color_end = Color_RESET;
		if (strstr(name, "sym.imp.")) {
			color = Color_YELLOW;
		} else if (strstr(name, "sym.")) {
			color = Color_GREEN;
		} else if (strstr(name, "sub.")) {
			color = Color_MAGENTA;
		}
	}

	if (core->analysis->bits == 64) {
		addrwidth = 16;
	}

	rz_cons_printf(FCN_LIST_VERBOSE_ENTRY, color,
		addrwidth, fcn->addr,
		rz_analysis_function_realsize(fcn),
		rz_list_length(fcn->bbs),
		rz_analysis_function_count_edges(fcn, &ebbs),
		rz_analysis_function_complexity(fcn),
		rz_analysis_function_cost(fcn),
		addrwidth, rz_analysis_function_min_addr(fcn),
		rz_analysis_function_linear_size(fcn),
		addrwidth, rz_analysis_function_max_addr(fcn),
		fcn->meta.numcallrefs,
		rz_analysis_var_count(core->analysis, fcn, 's', 0) +
			rz_analysis_var_count(core->analysis, fcn, 'b', 0) +
			rz_analysis_var_count(core->analysis, fcn, 'r', 0),
		rz_analysis_var_count(core->analysis, fcn, 's', 1) +
			rz_analysis_var_count(core->analysis, fcn, 'b', 1) +
			rz_analysis_var_count(core->analysis, fcn, 'r', 1),
		fcn->meta.numrefs,
		fcn->maxstack,
		name,
		color_end);
	free(name);
	return 0;
}

static int fcn_list_verbose(RzCore *core, RzList *fcns, const char *sortby) {
	bool use_color = rz_config_get_i(core->config, "scr.color");
	int headeraddr_width = 10;
	char *headeraddr = "==========";

	if (core->analysis->bits == 64) {
		headeraddr_width = 18;
		headeraddr = "==================";
	}

	if (sortby) {
		if (!strcmp(sortby, "size")) {
			rz_list_sort(fcns, cmpsize);
		} else if (!strcmp(sortby, "addr")) {
			rz_list_sort(fcns, fcn_cmpaddr);
		} else if (!strcmp(sortby, "cc")) {
			rz_list_sort(fcns, cmpfcncc);
		} else if (!strcmp(sortby, "edges")) {
			rz_list_sort(fcns, cmpedges);
		} else if (!strcmp(sortby, "calls")) {
			rz_list_sort(fcns, cmpcalls);
		} else if (strstr(sortby, "name")) {
			rz_list_sort(fcns, cmpname);
		} else if (strstr(sortby, "frame")) {
			rz_list_sort(fcns, cmpframe);
		} else if (strstr(sortby, "ref")) {
			rz_list_sort(fcns, cmpxrefs);
		} else if (!strcmp(sortby, "nbbs")) {
			rz_list_sort(fcns, cmpnbbs);
		}
	}

	rz_cons_printf("%-*s %4s %5s %5s %5s %4s %*s range %-*s %s %s %s %s %s %s\n",
		headeraddr_width, "address", "size", "nbbs", "edges", "cc", "cost",
		headeraddr_width, "min bound", headeraddr_width, "max bound", "calls",
		"locals", "args", "xref", "frame", "name");
	rz_cons_printf("%s ==== ===== ===== ===== ==== %s ===== %s ===== ====== ==== ==== ===== ====\n",
		headeraddr, headeraddr, headeraddr);
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, iter, fcn) {
		fcn_print_verbose(core, fcn, use_color);
	}

	return 0;
}

static void __fcn_print_default(RzCore *core, RzAnalysisFunction *fcn, bool quiet) {
	if (quiet) {
		rz_cons_printf("0x%08" PFMT64x " ", fcn->addr);
	} else {
		char *msg, *name = rz_core_analysis_fcn_name(core, fcn);
		ut64 realsize = rz_analysis_function_realsize(fcn);
		ut64 size = rz_analysis_function_linear_size(fcn);
		if (realsize == size) {
			msg = rz_str_newf("%-12" PFMT64u, size);
		} else {
			msg = rz_str_newf("%-4" PFMT64u " -> %-4" PFMT64u, size, realsize);
		}
		rz_cons_printf("0x%08" PFMT64x " %4d %4s %s\n",
			fcn->addr, rz_list_length(fcn->bbs), msg, name);
		free(name);
		free(msg);
	}
}

static int fcn_list_default(RzCore *core, RzList *fcns, bool quiet) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, iter, fcn) {
		__fcn_print_default(core, fcn, quiet);
		if (quiet) {
			rz_cons_newline();
		}
	}
	return 0;
}

// for a given function returns an RzList of all functions that were called in it
RZ_API RzList *rz_core_analysis_fcn_get_calls(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisRef *refi;
	RzListIter *iter, *iter2;

	// get all references from this function
	RzList *refs = rz_analysis_function_get_refs(fcn);
	// sanity check
	if (!rz_list_empty(refs)) {
		// iterate over all the references and remove these which aren't of type call
		rz_list_foreach_safe (refs, iter, iter2, refi) {
			if (refi->type != RZ_ANALYSIS_REF_TYPE_CALL) {
				rz_list_delete(refs, iter);
			}
		}
	}
	return refs;
}

// Lists function names and their calls (uniqified)
static int fcn_print_makestyle(RzCore *core, RzList *fcns, char mode) {
	RzListIter *refiter;
	RzListIter *fcniter;
	RzAnalysisFunction *fcn;
	RzAnalysisRef *refi;
	RzList *refs = NULL;
	PJ *pj = NULL;

	if (mode == 'j') {
		pj = rz_core_pj_new(core);
		pj_a(pj);
	}

	// Iterate over all functions
	rz_list_foreach (fcns, fcniter, fcn) {
		// Get all refs for a function
		refs = rz_core_analysis_fcn_get_calls(core, fcn);
		// Uniquify the list by ref->addr
		refs = rz_list_uniq(refs, (RzListComparator)RzAnalysisRef_cmp);

		// don't enter for functions with 0 refs
		if (!rz_list_empty(refs)) {
			if (pj) { // begin json output of function
				pj_o(pj);
				pj_ks(pj, "name", fcn->name);
				pj_kn(pj, "addr", fcn->addr);
				pj_k(pj, "calls");
				pj_a(pj);
			} else {
				rz_cons_printf("%s", fcn->name);
			}

			if (mode == 'm') {
				rz_cons_printf(":\n");
			} else if (mode == 'q') {
				rz_cons_printf(" -> ");
			}
			// Iterate over all refs from a function
			rz_list_foreach (refs, refiter, refi) {
				RzFlagItem *f = rz_flag_get_i(core->flags, refi->addr);
				char *dst = rz_str_newf((f ? f->name : "0x%08" PFMT64x), refi->addr);
				if (pj) { // Append calee json item
					pj_o(pj);
					pj_ks(pj, "name", dst);
					pj_kn(pj, "addr", refi->addr);
					pj_end(pj); // close referenced item
				} else if (mode == 'q') {
					rz_cons_printf("%s ", dst);
				} else {
					rz_cons_printf("    %s\n", dst);
				}
			}
			if (pj) {
				pj_end(pj); // close list of calls
				pj_end(pj); // close function item
			} else {
				rz_cons_newline();
			}
		}
	}

	if (mode == 'j') {
		pj_end(pj); // close json output
		rz_cons_printf("%s\n", pj_string(pj));
	}
	if (pj) {
		pj_free(pj);
	}
	return 0;
}

static int fcn_print_json(RzCore *core, RzAnalysisFunction *fcn, PJ *pj) {
	RzListIter *iter;
	RzAnalysisRef *refi;
	RzList *refs, *xrefs;
	if (!pj) {
		return -1;
	}
	int ebbs = 0;
	pj_o(pj);
	pj_kn(pj, "offset", fcn->addr);
	char *name = rz_core_analysis_fcn_name(core, fcn);
	if (name) {
		pj_ks(pj, "name", name);
	}
	pj_kn(pj, "size", rz_analysis_function_linear_size(fcn));
	pj_ks(pj, "is-pure", rz_str_bool(rz_analysis_function_purity(fcn)));
	pj_kn(pj, "realsz", rz_analysis_function_realsize(fcn));
	pj_kb(pj, "noreturn", fcn->is_noreturn);
	pj_ki(pj, "stackframe", fcn->maxstack);
	if (fcn->cc) {
		pj_ks(pj, "calltype", fcn->cc); // calling conventions
	}
	pj_ki(pj, "cost", rz_analysis_function_cost(fcn)); // execution cost
	pj_ki(pj, "cc", rz_analysis_function_complexity(fcn)); // cyclic cost
	pj_ki(pj, "bits", fcn->bits);
	pj_ks(pj, "type", rz_analysis_fcntype_tostring(fcn->type));
	pj_ki(pj, "nbbs", rz_list_length(fcn->bbs));
	pj_ki(pj, "edges", rz_analysis_function_count_edges(fcn, &ebbs));
	pj_ki(pj, "ebbs", ebbs);
	{
		char *sig = rz_core_analysis_function_signature(core, RZ_OUTPUT_MODE_STANDARD, fcn->name);
		if (sig) {
			rz_str_trim(sig);
			pj_ks(pj, "signature", sig);
			free(sig);
		}
	}
	pj_kn(pj, "minbound", rz_analysis_function_min_addr(fcn));
	pj_kn(pj, "maxbound", rz_analysis_function_max_addr(fcn));

	int outdegree = 0;
	refs = rz_analysis_function_get_refs(fcn);
	if (!rz_list_empty(refs)) {
		pj_k(pj, "callrefs");
		pj_a(pj);
		rz_list_foreach (refs, iter, refi) {
			if (refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
				outdegree++;
			}
			if (refi->type == RZ_ANALYSIS_REF_TYPE_CODE ||
				refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
				pj_o(pj);
				pj_kn(pj, "addr", refi->addr);
				pj_ks(pj, "type", rz_analysis_xrefs_type_tostring(refi->type));
				pj_kn(pj, "at", refi->at);
				pj_end(pj);
			}
		}
		pj_end(pj);

		pj_k(pj, "datarefs");
		pj_a(pj);
		rz_list_foreach (refs, iter, refi) {
			if (refi->type == RZ_ANALYSIS_REF_TYPE_DATA) {
				pj_n(pj, refi->addr);
			}
		}
		pj_end(pj);
	}
	rz_list_free(refs);

	int indegree = 0;
	xrefs = rz_analysis_function_get_xrefs(fcn);
	if (!rz_list_empty(xrefs)) {
		pj_k(pj, "codexrefs");
		pj_a(pj);
		rz_list_foreach (xrefs, iter, refi) {
			if (refi->type == RZ_ANALYSIS_REF_TYPE_CODE ||
				refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
				indegree++;
				pj_o(pj);
				pj_kn(pj, "addr", refi->addr);
				pj_ks(pj, "type", rz_analysis_xrefs_type_tostring(refi->type));
				pj_kn(pj, "at", refi->at);
				pj_end(pj);
			}
		}

		pj_end(pj);
		pj_k(pj, "dataxrefs");
		pj_a(pj);

		rz_list_foreach (xrefs, iter, refi) {
			if (refi->type == RZ_ANALYSIS_REF_TYPE_DATA) {
				pj_n(pj, refi->addr);
			}
		}
		pj_end(pj);
	}
	rz_list_free(xrefs);

	pj_ki(pj, "indegree", indegree);
	pj_ki(pj, "outdegree", outdegree);

	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		pj_ki(pj, "nlocals", rz_analysis_var_count(core->analysis, fcn, 'b', 0) + rz_analysis_var_count(core->analysis, fcn, 'r', 0) + rz_analysis_var_count(core->analysis, fcn, 's', 0));
		pj_ki(pj, "nargs", rz_analysis_var_count(core->analysis, fcn, 'b', 1) + rz_analysis_var_count(core->analysis, fcn, 'r', 1) + rz_analysis_var_count(core->analysis, fcn, 's', 1));

		pj_k(pj, "bpvars");
		rz_analysis_var_list_show(core->analysis, fcn, 'b', 'j', pj);
		pj_k(pj, "spvars");
		rz_analysis_var_list_show(core->analysis, fcn, 's', 'j', pj);
		pj_k(pj, "regvars");
		rz_analysis_var_list_show(core->analysis, fcn, 'r', 'j', pj);

		pj_ks(pj, "difftype", fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? "match" : fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? "unmatch"
																		  : "new");
		if (fcn->diff->addr != -1) {
			pj_kn(pj, "diffaddr", fcn->diff->addr);
		}
		if (fcn->diff->name) {
			pj_ks(pj, "diffname", fcn->diff->name);
		}
	}
	pj_end(pj);
	free(name);
	return 0;
}

static int fcn_list_json(RzCore *core, RzList *fcns, bool quiet) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	PJ *pj = rz_core_pj_new(core);
	if (!pj) {
		return -1;
	}
	pj_a(pj);
	rz_list_foreach (fcns, iter, fcn) {
		if (quiet) {
			pj_n(pj, fcn->addr);
		} else {
			fcn_print_json(core, fcn, pj);
		}
	}
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	return 0;
}

static int fcn_list_verbose_json(RzCore *core, RzList *fcns) {
	return fcn_list_json(core, fcns, false);
}

static int fcn_print_detail(RzCore *core, RzAnalysisFunction *fcn) {
	const char *defaultCC = rz_analysis_cc_default(core->analysis);
	char *name = rz_core_analysis_fcn_name(core, fcn);
	rz_cons_printf("\"f %s %" PFMT64u " 0x%08" PFMT64x "\"\n", name, rz_analysis_function_linear_size(fcn), fcn->addr);
	rz_cons_printf("\"af+ 0x%08" PFMT64x " %s %c %c\"\n",
		fcn->addr, name, //rz_analysis_fcn_size (fcn), name,
		fcn->type == RZ_ANALYSIS_FCN_TYPE_LOC ? 'l' : fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM ? 's'
			: fcn->type == RZ_ANALYSIS_FCN_TYPE_IMP                                     ? 'i'
												    : 'f',
		fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? 'm' : fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? 'u'
															: 'n');
	// FIXME: this command prints something annoying. Does it have important side-effects?
	fcn_list_bbs(fcn);
	if (fcn->bits != 0) {
		rz_cons_printf("afB %d @ 0x%08" PFMT64x "\n", fcn->bits, fcn->addr);
	}
	// FIXME command injection vuln here
	if (fcn->cc || defaultCC) {
		rz_cons_printf("afc %s @ 0x%08" PFMT64x "\n", fcn->cc ? fcn->cc : defaultCC, fcn->addr);
	}
	if (fcn) {
		/* show variables  and arguments */
		rz_analysis_var_list_show(core->analysis, fcn, 'b', '*', NULL);
		rz_analysis_var_list_show(core->analysis, fcn, 'r', '*', NULL);
		rz_analysis_var_list_show(core->analysis, fcn, 's', '*', NULL);
	}
	/* Show references */
	RzListIter *refiter;
	RzAnalysisRef *refi;
	RzList *refs = rz_analysis_function_get_refs(fcn);
	rz_list_foreach (refs, refiter, refi) {
		switch (refi->type) {
		case RZ_ANALYSIS_REF_TYPE_CALL:
			rz_cons_printf("axC 0x%" PFMT64x " 0x%" PFMT64x "\n", refi->addr, refi->at);
			break;
		case RZ_ANALYSIS_REF_TYPE_DATA:
			rz_cons_printf("axd 0x%" PFMT64x " 0x%" PFMT64x "\n", refi->addr, refi->at);
			break;
		case RZ_ANALYSIS_REF_TYPE_CODE:
			rz_cons_printf("axc 0x%" PFMT64x " 0x%" PFMT64x "\n", refi->addr, refi->at);
			break;
		case RZ_ANALYSIS_REF_TYPE_STRING:
			rz_cons_printf("axs 0x%" PFMT64x " 0x%" PFMT64x "\n", refi->addr, refi->at);
			break;
		case RZ_ANALYSIS_REF_TYPE_NULL:
		default:
			rz_cons_printf("ax 0x%" PFMT64x " 0x%" PFMT64x "\n", refi->addr, refi->at);
			break;
		}
	}
	rz_list_free(refs);
	/*Saving Function stack frame*/
	rz_cons_printf("afS %d @ 0x%" PFMT64x "\n", fcn->maxstack, fcn->addr);
	free(name);
	return 0;
}

static bool is_fcn_traced(RzDebugTrace *traced, RzAnalysisFunction *fcn) {
	int tag = traced->tag;
	RzListIter *iter;
	RzDebugTracepoint *trace;

	rz_list_foreach (traced->traces, iter, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			if (rz_analysis_function_contains(fcn, trace->addr)) {
				rz_cons_printf("\ntraced: %d\n", trace->times);
				return true;
			}
		}
	}
	return false;
}

static int fcn_print_legacy(RzCore *core, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisRef *refi;
	RzList *refs, *xrefs;
	int ebbs = 0;
	char *name = rz_core_analysis_fcn_name(core, fcn);

	rz_cons_printf("#\noffset: 0x%08" PFMT64x "\nname: %s\nsize: %" PFMT64u,
		fcn->addr, name, rz_analysis_function_linear_size(fcn));
	rz_cons_printf("\nis-pure: %s", rz_str_bool(rz_analysis_function_purity(fcn)));
	rz_cons_printf("\nrealsz: %" PFMT64d, rz_analysis_function_realsize(fcn));
	rz_cons_printf("\nstackframe: %d", fcn->maxstack);
	if (fcn->cc) {
		rz_cons_printf("\ncall-convention: %s", fcn->cc);
	}
	rz_cons_printf("\ncyclomatic-cost: %d", rz_analysis_function_cost(fcn));
	rz_cons_printf("\ncyclomatic-complexity: %d", rz_analysis_function_complexity(fcn));
	rz_cons_printf("\nbits: %d", fcn->bits);
	rz_cons_printf("\ntype: %s", rz_analysis_fcntype_tostring(fcn->type));
	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		rz_cons_printf(" [%s]",
			fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? "MATCH" : fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? "UNMATCH"
																    : "NEW");
	}
	rz_cons_printf("\nnum-bbs: %d", rz_list_length(fcn->bbs));
	rz_cons_printf("\nedges: %d", rz_analysis_function_count_edges(fcn, &ebbs));
	rz_cons_printf("\nend-bbs: %d", ebbs);
	rz_cons_printf("\ncall-refs:");
	int outdegree = 0;
	refs = rz_analysis_function_get_refs(fcn);
	rz_list_foreach (refs, iter, refi) {
		if (refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
			outdegree++;
		}
		if (refi->type == RZ_ANALYSIS_REF_TYPE_CODE || refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
			rz_cons_printf(" 0x%08" PFMT64x " %c", refi->addr,
				refi->type == RZ_ANALYSIS_REF_TYPE_CALL ? 'C' : 'J');
		}
	}
	rz_cons_printf("\ndata-refs:");
	rz_list_foreach (refs, iter, refi) {
		// global or local?
		if (refi->type == RZ_ANALYSIS_REF_TYPE_DATA) {
			rz_cons_printf(" 0x%08" PFMT64x, refi->addr);
		}
	}
	rz_list_free(refs);

	int indegree = 0;
	rz_cons_printf("\ncode-xrefs:");
	xrefs = rz_analysis_function_get_xrefs(fcn);
	rz_list_foreach (xrefs, iter, refi) {
		if (refi->type == RZ_ANALYSIS_REF_TYPE_CODE || refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
			indegree++;
			rz_cons_printf(" 0x%08" PFMT64x " %c", refi->addr,
				refi->type == RZ_ANALYSIS_REF_TYPE_CALL ? 'C' : 'J');
		}
	}
	rz_cons_printf("\nnoreturn: %s", rz_str_bool(fcn->is_noreturn));
	rz_cons_printf("\nin-degree: %d", indegree);
	rz_cons_printf("\nout-degree: %d", outdegree);
	rz_cons_printf("\ndata-xrefs:");
	rz_list_foreach (xrefs, iter, refi) {
		if (refi->type == RZ_ANALYSIS_REF_TYPE_DATA) {
			rz_cons_printf(" 0x%08" PFMT64x, refi->addr);
		}
	}
	rz_list_free(xrefs);

	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		int args_count = rz_analysis_var_count(core->analysis, fcn, 'b', 1);
		args_count += rz_analysis_var_count(core->analysis, fcn, 's', 1);
		args_count += rz_analysis_var_count(core->analysis, fcn, 'r', 1);
		int var_count = rz_analysis_var_count(core->analysis, fcn, 'b', 0);
		var_count += rz_analysis_var_count(core->analysis, fcn, 's', 0);
		var_count += rz_analysis_var_count(core->analysis, fcn, 'r', 0);

		rz_cons_printf("\nlocals: %d\nargs: %d\n", var_count, args_count);
		rz_analysis_var_list_show(core->analysis, fcn, 'b', 0, NULL);
		rz_analysis_var_list_show(core->analysis, fcn, 's', 0, NULL);
		rz_analysis_var_list_show(core->analysis, fcn, 'r', 0, NULL);
		rz_cons_printf("diff: type: %s",
			fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? "match" : fcn->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH ? "unmatch"
																    : "new");
		if (fcn->diff->addr != -1) {
			rz_cons_printf("addr: 0x%" PFMT64x, fcn->diff->addr);
		}
		if (fcn->diff->name) {
			rz_cons_printf("function: %s", fcn->diff->name);
		}
	}
	free(name);

	// traced
	if (core->dbg->trace->enabled) {
		is_fcn_traced(core->dbg->trace, fcn);
	}
	return 0;
}

static int fcn_list_detail(RzCore *core, RzList *fcns) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, iter, fcn) {
		fcn_print_detail(core, fcn);
	}
	rz_cons_newline();
	return 0;
}

static int fcn_list_table(RzCore *core, const char *q, int fmt) {
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	RzTable *t = rz_core_table(core);
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	rz_table_add_column(t, typeNumber, "addr", 0);
	rz_table_add_column(t, typeNumber, "size", 0);
	rz_table_add_column(t, typeString, "name", 0);
	rz_table_add_column(t, typeNumber, "nbbs", 0);
	rz_table_add_column(t, typeNumber, "xref", 0);
	rz_table_add_column(t, typeNumber, "calls", 0);
	rz_table_add_column(t, typeNumber, "cc", 0);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		const char *fcnAddr = sdb_fmt("0x%08" PFMT64x, fcn->addr);
		const char *fcnSize = sdb_fmt("%" PFMT64u, rz_analysis_function_linear_size(fcn));
		const char *nbbs = sdb_fmt("%d", rz_list_length(fcn->bbs)); // rz_analysis_fcn_size (fcn));
		RzList *xrefs = rz_analysis_function_get_xrefs(fcn);
		char xref[128], ccstr[128];
		snprintf(xref, sizeof(xref), "%d", rz_list_length(xrefs));
		rz_list_free(xrefs);

		RzList *calls = rz_core_analysis_fcn_get_calls(core, fcn);
		// Uniquify the list by ref->addr
		calls = rz_list_uniq(calls, (RzListComparator)RzAnalysisRef_cmp);
		const char *callstr = sdb_fmt("%d", rz_list_length(calls));
		rz_list_free(calls);
		snprintf(ccstr, sizeof(ccstr), "%d", rz_analysis_function_complexity(fcn));

		rz_table_add_row(t, fcnAddr, fcnSize, fcn->name, nbbs, xref, callstr, ccstr, NULL);
	}
	if (rz_table_query(t, q)) {
		char *s = (fmt == 'j')
			? rz_table_tojson(t)
			: rz_table_tofancystring(t);
		// char *s = rz_table_tostring (t);
		rz_cons_printf("%s\n", s);
		free(s);
	}
	rz_table_free(t);
	return 0;
}

static int fcn_list_legacy(RzCore *core, RzList *fcns) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, iter, fcn) {
		fcn_print_legacy(core, fcn);
	}
	rz_cons_newline();
	return 0;
}

RZ_API int rz_core_analysis_fcn_list(RzCore *core, const char *input, const char *rad) {
	char temp[64];
	rz_return_val_if_fail(core && core->analysis, 0);
	if (rz_list_empty(core->analysis->fcns)) {
		return 0;
	}
	if (*rad == '.') {
		RzList *fcns = rz_analysis_get_functions_in(core->analysis, core->offset);
		if (!fcns || rz_list_empty(fcns)) {
			eprintf("No functions at current address.\n");
			rz_list_free(fcns);
			return -1;
		}
		fcn_list_default(core, fcns, false);
		rz_list_free(fcns);
		return 0;
	}

	if (rad && (*rad == 'l' || *rad == 'j')) {
		fcnlist_gather_metadata(core->analysis, core->analysis->fcns);
	}

	const char *name = input;
	ut64 addr = core->offset;
	if (input && *input) {
		name = input + 1;
		addr = rz_num_math(core->num, name);
	}

	RzList *fcns = rz_list_newf(NULL);
	if (!fcns) {
		return -1;
	}
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		if (!input || rz_analysis_function_contains(fcn, addr) || (!strcmp(name, fcn->name))) {
			rz_list_append(fcns, fcn);
		}
	}

	// rz_list_sort (fcns, &cmpfcn);
	if (!rad) {
		fcn_list_default(core, fcns, false);
		rz_list_free(fcns);
		return 0;
	}
	switch (*rad) {
	case '+':
		rz_core_analysis_fcn_list_size(core);
		break;
	case '=': { // afl=
		rz_list_sort(fcns, fcn_cmpaddr);
		RzList *flist = rz_list_newf((RzListFree)rz_listinfo_free);
		if (!flist) {
			rz_list_free(fcns);
			return -1;
		}
		ls_foreach (fcns, iter, fcn) {
			RzInterval inter = { rz_analysis_function_min_addr(fcn), rz_analysis_function_linear_size(fcn) };
			RzListInfo *info = rz_listinfo_new(rz_core_analysis_fcn_name(core, fcn), inter, inter, -1, sdb_itoa(fcn->bits, temp, 10));
			if (!info) {
				break;
			}
			rz_list_append(flist, info);
		}
		RzTable *table = rz_core_table(core);
		rz_table_visual_list(table, flist, core->offset, core->blocksize,
			rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
		rz_cons_printf("\n%s\n", rz_table_tostring(table));
		rz_table_free(table);
		rz_list_free(flist);
		break;
	}
	case 't': // "aflt" "afltj"
		if (rad[1] == 'j') {
			fcn_list_table(core, rz_str_trim_head_ro(rad + 2), 'j');
		} else {
			fcn_list_table(core, rz_str_trim_head_ro(rad + 1), rad[1]);
		}
		break;
	case 'l': // "afll" "afllj"
		if (rad[1] == 'j') {
			fcn_list_verbose_json(core, fcns);
		} else {
			char *sp = strchr(rad, ' ');
			fcn_list_verbose(core, fcns, sp ? sp + 1 : NULL);
		}
		break;
	case 'q':
		if (rad[1] == 'j') {
			fcn_list_json(core, fcns, true);
		} else {
			fcn_list_default(core, fcns, true);
		}
		break;
	case 'j':
		fcn_list_json(core, fcns, false);
		break;
	case '*':
		fcn_list_detail(core, fcns);
		break;
	case 'm': // "aflm"
	{
		char mode = 'm';
		if (rad[1] != 0) {
			if (rad[1] == 'j') { // "aflmj"
				mode = 'j';
			} else if (rad[1] == 'q') { // "aflmq"
				mode = 'q';
			}
		}
		fcn_print_makestyle(core, fcns, mode);
		break;
	}
	case 1:
		fcn_list_legacy(core, fcns);
		break;
	default:
		fcn_list_default(core, fcns, false);
		break;
	}
	rz_list_free(fcns);
	return 0;
}

static RzList *recurse_bb(RzCore *core, ut64 addr, RzAnalysisBlock *dest);

static RzList *recurse(RzCore *core, RzAnalysisBlock *from, RzAnalysisBlock *dest) {
	recurse_bb(core, from->jump, dest);
	recurse_bb(core, from->fail, dest);

	/* same for all calls */
	// TODO: RzAnalysisBlock must contain a linked list of calls
	return NULL;
}

static RzList *recurse_bb(RzCore *core, ut64 addr, RzAnalysisBlock *dest) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
	if (bb == dest) {
		eprintf("path found!");
		return NULL;
	}
	return recurse(core, bb, dest);
}

#define REG_SET_SIZE (RZ_ANALYSIS_CC_MAXARG + 2)

typedef struct {
	int count;
	RzPVector reg_set;
	bool argonly;
	RzAnalysisFunction *fcn;
	RzCore *core;
} BlockRecurseCtx;

static bool analysis_block_on_exit(RzAnalysisBlock *bb, BlockRecurseCtx *ctx) {
	int *cur_regset = rz_pvector_pop(&ctx->reg_set);
	int *prev_regset = rz_pvector_at(&ctx->reg_set, rz_pvector_len(&ctx->reg_set) - 1);
	size_t i;
	for (i = 0; i < REG_SET_SIZE; i++) {
		if (!prev_regset[i] && cur_regset[i] == 1) {
			prev_regset[i] = 1;
		}
	}
	free(cur_regset);
	return true;
}

static bool analysis_block_cb(RzAnalysisBlock *bb, BlockRecurseCtx *ctx) {
	if (rz_cons_is_breaked()) {
		return false;
	}
	if (bb->size < 1) {
		return true;
	}
	if (bb->size > ctx->core->analysis->opt.bb_max_size) {
		return true;
	}
	int *parent_reg_set = rz_pvector_at(&ctx->reg_set, rz_pvector_len(&ctx->reg_set) - 1);
	int *reg_set = RZ_NEWS(int, REG_SET_SIZE);
	memcpy(reg_set, parent_reg_set, REG_SET_SIZE * sizeof(int));
	rz_pvector_push(&ctx->reg_set, reg_set);
	RzCore *core = ctx->core;
	RzAnalysisFunction *fcn = ctx->fcn;
	fcn->stack = bb->parent_stackptr;
	ut64 pos = bb->addr;
	while (pos < bb->addr + bb->size) {
		if (rz_cons_is_breaked()) {
			break;
		}
		RzAnalysisOp *op = rz_core_analysis_op(core, pos, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT);
		if (!op) {
			//eprintf ("Cannot get op\n");
			break;
		}
		rz_analysis_extract_rarg(core->analysis, op, fcn, reg_set, &ctx->count);
		if (!ctx->argonly) {
			if (op->stackop == RZ_ANALYSIS_STACK_INC) {
				fcn->stack += op->stackptr;
			} else if (op->stackop == RZ_ANALYSIS_STACK_RESET) {
				fcn->stack = 0;
			}
			rz_analysis_extract_vars(core->analysis, fcn, op);
		}
		int opsize = op->size;
		int optype = op->type;
		rz_analysis_op_free(op);
		if (opsize < 1) {
			break;
		}
		if (optype == RZ_ANALYSIS_OP_TYPE_CALL) {
			size_t i;
			int max_count = fcn->cc ? rz_analysis_cc_max_arg(core->analysis, fcn->cc) : 0;
			for (i = 0; i < max_count; i++) {
				reg_set[i] = 2;
			}
		}
		pos += opsize;
	}
	return true;
}

// TODO: move this logic into the main analysis loop
RZ_API void rz_core_recover_vars(RzCore *core, RzAnalysisFunction *fcn, bool argonly) {
	rz_return_if_fail(core && core->analysis && fcn);
	if (core->analysis->opt.bb_max_size < 1) {
		return;
	}
	BlockRecurseCtx ctx = { 0, { { 0 } }, argonly, fcn, core };
	rz_pvector_init(&ctx.reg_set, free);
	int *reg_set = RZ_NEWS0(int, REG_SET_SIZE);
	rz_pvector_push(&ctx.reg_set, reg_set);
	int saved_stack = fcn->stack;
	RzAnalysisBlock *first_bb = rz_analysis_get_block_at(fcn->analysis, fcn->addr);
	rz_analysis_block_recurse_depth_first(first_bb, (RzAnalysisBlockCb)analysis_block_cb, (RzAnalysisBlockCb)analysis_block_on_exit, &ctx);
	rz_pvector_fini(&ctx.reg_set);
	fcn->stack = saved_stack;
}

static bool analysis_path_exists(RzCore *core, ut64 from, ut64 to, RzList *bbs, int depth, HtUP *state, HtUP *avoid) {
	rz_return_val_if_fail(bbs, false);
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, from);
	RzListIter *iter = NULL;
	RzAnalysisRef *refi;

	if (depth < 1) {
		eprintf("going too deep\n");
		return false;
	}

	if (!bb) {
		return false;
	}

	ht_up_update(state, from, bb);

	// try to find the target in the current function
	if (rz_analysis_block_contains(bb, to) ||
		((!ht_up_find(avoid, bb->jump, NULL) &&
			!ht_up_find(state, bb->jump, NULL) &&
			analysis_path_exists(core, bb->jump, to, bbs, depth - 1, state, avoid))) ||
		((!ht_up_find(avoid, bb->fail, NULL) &&
			!ht_up_find(state, bb->fail, NULL) &&
			analysis_path_exists(core, bb->fail, to, bbs, depth - 1, state, avoid)))) {
		rz_list_prepend(bbs, bb);
		return true;
	}

	// find our current function
	RzAnalysisFunction *cur_fcn = rz_analysis_get_fcn_in(core->analysis, from, 0);

	// get call refs from current basic block and find a path from them
	if (cur_fcn) {
		RzList *refs = rz_analysis_function_get_refs(cur_fcn);
		if (refs) {
			rz_list_foreach (refs, iter, refi) {
				if (refi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
					if (rz_analysis_block_contains(bb, refi->at)) {
						if ((refi->at != refi->addr) && !ht_up_find(state, refi->addr, NULL) && analysis_path_exists(core, refi->addr, to, bbs, depth - 1, state, avoid)) {
							rz_list_prepend(bbs, bb);
							rz_list_free(refs);
							return true;
						}
					}
				}
			}
		}
		rz_list_free(refs);
	}

	return false;
}

static RzList *analysis_graph_to(RzCore *core, ut64 addr, int depth, HtUP *avoid) {
	RzAnalysisFunction *cur_fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	RzList *list = rz_list_new();
	HtUP *state = ht_up_new0();

	if (!list || !state || !cur_fcn) {
		rz_list_free(list);
		ht_up_free(state);
		return NULL;
	}

	// forward search
	if (analysis_path_exists(core, core->offset, addr, list, depth - 1, state, avoid)) {
		ht_up_free(state);
		return list;
	}

	// backward search
	RzList *xrefs = rz_analysis_xrefs_get(core->analysis, cur_fcn->addr);
	if (xrefs) {
		RzListIter *iter;
		RzAnalysisRef *xref = NULL;
		rz_list_foreach (xrefs, iter, xref) {
			if (xref->type == RZ_ANALYSIS_REF_TYPE_CALL) {
				ut64 offset = core->offset;
				core->offset = xref->addr;
				rz_list_free(list);
				list = analysis_graph_to(core, addr, depth - 1, avoid);
				core->offset = offset;
				if (list && rz_list_length(list)) {
					rz_list_free(xrefs);
					ht_up_free(state);
					return list;
				}
			}
		}
	}

	rz_list_free(xrefs);
	ht_up_free(state);
	rz_list_free(list);
	return NULL;
}

RZ_API RzList *rz_core_analysis_graph_to(RzCore *core, ut64 addr, int n) {
	int depth = rz_config_get_i(core->config, "analysis.graph_depth");
	RzList *path, *paths = rz_list_new();
	HtUP *avoid = ht_up_new0();
	while (n) {
		path = analysis_graph_to(core, addr, depth, avoid);
		if (path) {
			rz_list_append(paths, path);
			if (rz_list_length(path) >= 2) {
				RzAnalysisBlock *last = rz_list_get_n(path, rz_list_length(path) - 2);
				ht_up_update(avoid, last->addr, last);
				n--;
				continue;
			}
		}
		// no more path found
		break;
	}
	ht_up_free(avoid);
	return paths;
}

RZ_API int rz_core_analysis_graph(RzCore *core, ut64 addr, int opts) {
	ut64 from = rz_config_get_i(core->config, "graph.from");
	ut64 to = rz_config_get_i(core->config, "graph.to");
	const char *font = rz_config_get(core->config, "graph.font");
	int is_html = rz_cons_singleton()->is_html;
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;
	int is_json_format_disasm = opts & RZ_CORE_ANALYSIS_JSON_FORMAT_DISASM;
	int is_keva = opts & RZ_CORE_ANALYSIS_KEYVALUE;
	int is_star = opts & RZ_CORE_ANALYSIS_STAR;
	RzConfigHold *hc;
	RzAnalysisFunction *fcni;
	RzListIter *iter;
	int nodes = 0;
	PJ *pj = NULL;

	if (!addr) {
		addr = core->offset;
	}
	if (rz_list_empty(core->analysis->fcns)) {
		return false;
	}
	hc = rz_config_hold_new(core->config);
	if (!hc) {
		return false;
	}

	rz_config_hold_i(hc, "asm.lines", "asm.bytes", "asm.dwarf", NULL);
	//opts |= RZ_CORE_ANALYSIS_GRAPHBODY;
	rz_config_set_i(core->config, "asm.lines", 0);
	rz_config_set_i(core->config, "asm.dwarf", 0);
	if (!is_json_format_disasm) {
		rz_config_hold_i(hc, "asm.bytes", NULL);
		rz_config_set_i(core->config, "asm.bytes", 0);
	}
	if (!is_html && !is_json && !is_keva && !is_star) {
		const char *gv_edge = rz_config_get(core->config, "graph.gv.edge");
		const char *gv_node = rz_config_get(core->config, "graph.gv.node");
		const char *gv_spline = rz_config_get(core->config, "graph.gv.spline");
		if (!gv_edge || !*gv_edge) {
			gv_edge = "arrowhead=\"normal\"";
		}
		if (!gv_node || !*gv_node) {
			gv_node = "fillcolor=gray style=filled shape=box";
		}
		if (!gv_spline || !*gv_spline) {
			gv_spline = "splines=\"ortho\"";
		}
		rz_cons_printf("digraph code {\n"
			       "\tgraph [bgcolor=azure fontsize=8 fontname=\"%s\" %s];\n"
			       "\tnode [%s];\n"
			       "\tedge [%s];\n",
			font, gv_spline, gv_node, gv_edge);
	}
	if (is_json) {
		pj = rz_core_pj_new(core);
		if (!pj) {
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			return false;
		}
		pj_a(pj);
	}
	rz_list_foreach (core->analysis->fcns, iter, fcni) {
		if (fcni->type & (RZ_ANALYSIS_FCN_TYPE_SYM | RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_LOC) &&
			(addr == UT64_MAX || rz_analysis_get_fcn_in(core->analysis, addr, 0) == fcni)) {
			if (addr == UT64_MAX && (from != UT64_MAX && to != UT64_MAX)) {
				if (fcni->addr < from || fcni->addr > to) {
					continue;
				}
			}
			nodes += core_analysis_graph_nodes(core, fcni, opts, pj);
			if (addr != UT64_MAX) {
				break;
			}
		}
	}
	if (!nodes) {
		if (!is_html && !is_json && !is_keva) {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
			if (is_star) {
				char *name = get_title(fcn ? fcn->addr : addr);
				rz_cons_printf("agn %s;", name);
			} else {
				rz_cons_printf("\t\"0x%08" PFMT64x "\";\n", fcn ? fcn->addr : addr);
			}
		}
	}
	if (!is_keva && !is_html && !is_json && !is_star && !is_json_format_disasm) {
		rz_cons_printf("}\n");
	}
	if (is_json) {
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return true;
}

static int core_analysis_followptr(RzCore *core, int type, ut64 at, ut64 ptr, ut64 ref, int code, int depth) {
	// SLOW Operation try to reduce as much as possible
	if (!ptr) {
		return false;
	}
	if (ref == UT64_MAX || ptr == ref) {
		const RzAnalysisRefType t = code ? type ? type : RZ_ANALYSIS_REF_TYPE_CODE : RZ_ANALYSIS_REF_TYPE_DATA;
		rz_analysis_xrefs_set(core->analysis, at, ptr, t);
		return true;
	}
	if (depth < 1) {
		return false;
	}
	int wordsize = (int)(core->analysis->bits / 8);
	ut64 dataptr;
	if (!rz_io_read_i(core->io, ptr, &dataptr, wordsize, false)) {
		// eprintf ("core_analysis_followptr: Cannot read word at destination\n");
		return false;
	}
	return core_analysis_followptr(core, type, at, dataptr, ref, code, depth - 1);
}

static bool opiscall(RzCore *core, RzAnalysisOp *aop, ut64 addr, const ut8 *buf, int len, int arch) {
	switch (arch) {
	case RZ_ARCH_ARM64:
		aop->size = 4;
		//addr should be aligned by 4 in aarch64
		if (addr % 4) {
			char diff = addr % 4;
			addr = addr - diff;
			buf = buf - diff;
		}
		//if is not bl do not analyze
		if (buf[3] == 0x94) {
			if (rz_analysis_op(core->analysis, aop, addr, buf, len, RZ_ANALYSIS_OP_MASK_BASIC)) {
				return true;
			}
		}
		break;
	default:
		aop->size = 1;
		if (rz_analysis_op(core->analysis, aop, addr, buf, len, RZ_ANALYSIS_OP_MASK_BASIC)) {
			switch (aop->type & RZ_ANALYSIS_OP_TYPE_MASK) {
			case RZ_ANALYSIS_OP_TYPE_CALL:
			case RZ_ANALYSIS_OP_TYPE_CCALL:
				return true;
			}
		}
		break;
	}
	return false;
}

#define OPSZ 8
RZ_API int rz_core_analysis_search(RzCore *core, ut64 from, ut64 to, ut64 ref, int mode) {
	ut8 *buf = (ut8 *)malloc(core->blocksize);
	if (!buf) {
		return -1;
	}
	int ptrdepth = rz_config_get_i(core->config, "analysis.ptrdepth");
	int i, count = 0;
	RzAnalysisOp op = RZ_EMPTY;
	ut64 at;
	char bckwrds, do_bckwrd_srch;
	int arch = -1;
	if (core->rasm->bits == 64) {
		// speedup search
		if (!strncmp(core->rasm->cur->name, "arm", 3)) {
			arch = RZ_ARCH_ARM64;
		}
	}
	// TODO: get current section range here
	// ???
	// XXX must read bytes correctly
	do_bckwrd_srch = bckwrds = core->search->bckwrds;
	if (core->file) {
		rz_io_use_fd(core->io, core->file->fd);
	}
	if (!ref) {
		eprintf("Null reference search is not supported\n");
		free(buf);
		return -1;
	}
	rz_cons_break_push(NULL, NULL);
	if (core->blocksize > OPSZ) {
		if (bckwrds) {
			if (from + core->blocksize > to) {
				at = from;
				do_bckwrd_srch = false;
			} else {
				at = to - core->blocksize;
			}
		} else {
			at = from;
		}
		while ((!bckwrds && at < to) || bckwrds) {
			eprintf("\r[0x%08" PFMT64x "-0x%08" PFMT64x "] ", at, to);
			if (rz_cons_is_breaked()) {
				break;
			}
			// TODO: this can be probably enhanced
			if (!rz_io_read_at(core->io, at, buf, core->blocksize)) {
				eprintf("Failed to read at 0x%08" PFMT64x "\n", at);
				break;
			}
			for (i = bckwrds ? (core->blocksize - OPSZ - 1) : 0;
				(!bckwrds && i < core->blocksize - OPSZ) ||
				(bckwrds && i > 0);
				bckwrds ? i-- : i++) {
				// TODO: honor analysis.align
				if (rz_cons_is_breaked()) {
					break;
				}
				switch (mode) {
				case 'c':
					(void)opiscall(core, &op, at + i, buf + i, core->blocksize - i, arch);
					if (op.size < 1) {
						op.size = 1;
					}
					break;
				case 'r':
				case 'w':
				case 'x': {
					rz_analysis_op(core->analysis, &op, at + i, buf + i, core->blocksize - i, RZ_ANALYSIS_OP_MASK_BASIC);
					int mask = mode == 'r' ? 1 : mode == 'w' ? 2
						: mode == 'x'                    ? 4
										 : 0;
					if (op.direction == mask) {
						i += op.size;
					}
					rz_analysis_op_fini(&op);
					continue;
				} break;
				default:
					if (!rz_analysis_op(core->analysis, &op, at + i, buf + i, core->blocksize - i, RZ_ANALYSIS_OP_MASK_BASIC)) {
						rz_analysis_op_fini(&op);
						continue;
					}
				}
				switch (op.type) {
				case RZ_ANALYSIS_OP_TYPE_JMP:
				case RZ_ANALYSIS_OP_TYPE_CJMP:
				case RZ_ANALYSIS_OP_TYPE_CALL:
				case RZ_ANALYSIS_OP_TYPE_CCALL:
					if (op.jump != UT64_MAX &&
						core_analysis_followptr(core, 'C', at + i, op.jump, ref, true, 0)) {
						count++;
					}
					break;
				case RZ_ANALYSIS_OP_TYPE_UCJMP:
				case RZ_ANALYSIS_OP_TYPE_UJMP:
				case RZ_ANALYSIS_OP_TYPE_IJMP:
				case RZ_ANALYSIS_OP_TYPE_RJMP:
				case RZ_ANALYSIS_OP_TYPE_IRJMP:
				case RZ_ANALYSIS_OP_TYPE_MJMP:
					if (op.ptr != UT64_MAX &&
						core_analysis_followptr(core, 'c', at + i, op.ptr, ref, true, 1)) {
						count++;
					}
					break;
				case RZ_ANALYSIS_OP_TYPE_UCALL:
				case RZ_ANALYSIS_OP_TYPE_ICALL:
				case RZ_ANALYSIS_OP_TYPE_RCALL:
				case RZ_ANALYSIS_OP_TYPE_IRCALL:
				case RZ_ANALYSIS_OP_TYPE_UCCALL:
					if (op.ptr != UT64_MAX &&
						core_analysis_followptr(core, 'C', at + i, op.ptr, ref, true, 1)) {
						count++;
					}
					break;
				default: {
					if (!rz_analysis_op(core->analysis, &op, at + i, buf + i, core->blocksize - i, RZ_ANALYSIS_OP_MASK_BASIC)) {
						rz_analysis_op_fini(&op);
						continue;
					}
				}
					if (op.ptr != UT64_MAX &&
						core_analysis_followptr(core, 'd', at + i, op.ptr, ref, false, ptrdepth)) {
						count++;
					}
					break;
				}
				if (op.size < 1) {
					op.size = 1;
				}
				i += op.size - 1;
				rz_analysis_op_fini(&op);
			}
			if (bckwrds) {
				if (!do_bckwrd_srch) {
					break;
				}
				if (at > from + core->blocksize - OPSZ) {
					at -= core->blocksize;
				} else {
					do_bckwrd_srch = false;
					at = from;
				}
			} else {
				at += core->blocksize - OPSZ;
			}
		}
	} else {
		eprintf("error: block size too small\n");
	}
	rz_cons_break_pop();
	free(buf);
	rz_analysis_op_fini(&op);
	return count;
}

static bool found_xref(RzCore *core, ut64 at, ut64 xref_to, RzAnalysisRefType type, PJ *pj, int rad, int cfg_debug, bool cfg_analysis_strings) {
	// Validate the reference. If virtual addressing is enabled, we
	// allow only references to virtual addresses in order to reduce
	// the number of false positives. In debugger mode, the reference
	// must point to a mapped memory region.
	if (type == RZ_ANALYSIS_REF_TYPE_NULL) {
		return false;
	}
	if (cfg_debug) {
		if (!rz_debug_map_get(core->dbg, xref_to)) {
			return false;
		}
	} else if (core->io->va) {
		if (!rz_io_is_valid_offset(core->io, xref_to, 0)) {
			return false;
		}
	}
	if (!rad) {
		if (cfg_analysis_strings && type == RZ_ANALYSIS_REF_TYPE_DATA) {
			int len = 0;
			char *str_string = is_string_at(core, xref_to, &len);
			if (str_string) {
				rz_name_filter(str_string, -1);
				char *str_flagname = rz_str_newf("str.%s", str_string);
				rz_flag_space_push(core->flags, RZ_FLAGS_FS_STRINGS);
				(void)rz_flag_set(core->flags, str_flagname, xref_to, 1);
				rz_flag_space_pop(core->flags);
				free(str_flagname);
				if (len > 0) {
					rz_meta_set(core->analysis, RZ_META_TYPE_STRING, xref_to,
						len, (const char *)str_string);
				}
				free(str_string);
			}
		}
		// Add to SDB
		if (xref_to) {
			rz_analysis_xrefs_set(core->analysis, at, xref_to, type);
		}
	} else if (rad == 'j') {
		char *key = sdb_fmt("0x%" PFMT64x, xref_to);
		char *value = sdb_fmt("0x%" PFMT64x, at);
		pj_ks(pj, key, value);
	} else {
		int len = 0;
		// Display in rizin commands format
		char *cmd;
		switch (type) {
		case RZ_ANALYSIS_REF_TYPE_CODE: cmd = "axc"; break;
		case RZ_ANALYSIS_REF_TYPE_CALL: cmd = "axC"; break;
		case RZ_ANALYSIS_REF_TYPE_DATA: cmd = "axd"; break;
		default: cmd = "ax"; break;
		}
		rz_cons_printf("%s 0x%08" PFMT64x " 0x%08" PFMT64x "\n", cmd, xref_to, at);
		if (cfg_analysis_strings && type == RZ_ANALYSIS_REF_TYPE_DATA) {
			char *str_flagname = is_string_at(core, xref_to, &len);
			if (str_flagname) {
				ut64 str_addr = xref_to;
				rz_name_filter(str_flagname, -1);
				rz_cons_printf("f str.%s=0x%" PFMT64x "\n", str_flagname, str_addr);
				rz_cons_printf("Cs %d @ 0x%" PFMT64x "\n", len, str_addr);
				free(str_flagname);
			}
		}
	}
	return true;
}

RZ_API int rz_core_analysis_search_xrefs(RzCore *core, ut64 from, ut64 to, PJ *pj, int rad) {
	int cfg_debug = rz_config_get_i(core->config, "cfg.debug");
	bool cfg_analysis_strings = rz_config_get_i(core->config, "analysis.strings");
	ut64 at;
	int count = 0;
	const int bsz = 8096;
	RzAnalysisOp op = { 0 };

	if (from == to) {
		return -1;
	}
	if (from > to) {
		eprintf("Invalid range (0x%" PFMT64x
			" >= 0x%" PFMT64x ")\n",
			from, to);
		return -1;
	}

	if (core->blocksize <= OPSZ) {
		eprintf("Error: block size too small\n");
		return -1;
	}
	ut8 *buf = malloc(bsz);
	if (!buf) {
		eprintf("Error: cannot allocate a block\n");
		return -1;
	}
	ut8 *block = malloc(bsz);
	if (!block) {
		eprintf("Error: cannot allocate a temp block\n");
		free(buf);
		return -1;
	}
	rz_cons_break_push(NULL, NULL);
	at = from;
	st64 asm_sub_varmin = rz_config_get_i(core->config, "asm.sub.varmin");
	while (at < to && !rz_cons_is_breaked()) {
		int i = 0, ret = bsz;
		if (!rz_io_is_valid_offset(core->io, at, RZ_PERM_X)) {
			break;
		}
		(void)rz_io_read_at(core->io, at, buf, bsz);
		memset(block, -1, bsz);
		if (!memcmp(buf, block, bsz)) {
			//	eprintf ("Error: skipping uninitialized block \n");
			at += ret;
			continue;
		}
		memset(block, 0, bsz);
		if (!memcmp(buf, block, bsz)) {
			//	eprintf ("Error: skipping uninitialized block \n");
			at += ret;
			continue;
		}
		while (i < bsz && !rz_cons_is_breaked()) {
			ret = rz_analysis_op(core->analysis, &op, at + i, buf + i, bsz - i, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
			ret = ret > 0 ? ret : 1;
			i += ret;
			if (ret <= 0 || i > bsz) {
				break;
			}
			// find references
			if ((st64)op.val > asm_sub_varmin && op.val != UT64_MAX && op.val != UT32_MAX) {
				if (found_xref(core, op.addr, op.val, RZ_ANALYSIS_REF_TYPE_DATA, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
			}
			// find references
			if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
				if (found_xref(core, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_DATA, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
			}
			// find references
			if (op.addr > 512 && op.disp > 512 && op.disp && op.disp != UT64_MAX) {
				if (found_xref(core, op.addr, op.disp, RZ_ANALYSIS_REF_TYPE_DATA, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
			}
			switch (op.type) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
			case RZ_ANALYSIS_OP_TYPE_CJMP:
				if (found_xref(core, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CODE, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CALL:
			case RZ_ANALYSIS_OP_TYPE_CCALL:
				if (found_xref(core, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CALL, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_UJMP:
			case RZ_ANALYSIS_OP_TYPE_IJMP:
			case RZ_ANALYSIS_OP_TYPE_RJMP:
			case RZ_ANALYSIS_OP_TYPE_IRJMP:
			case RZ_ANALYSIS_OP_TYPE_MJMP:
			case RZ_ANALYSIS_OP_TYPE_UCJMP:
				count++;
				if (found_xref(core, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_CODE, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_UCALL:
			case RZ_ANALYSIS_OP_TYPE_ICALL:
			case RZ_ANALYSIS_OP_TYPE_RCALL:
			case RZ_ANALYSIS_OP_TYPE_IRCALL:
			case RZ_ANALYSIS_OP_TYPE_UCCALL:
				if (found_xref(core, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_CALL, pj, rad, cfg_debug, cfg_analysis_strings)) {
					count++;
				}
				break;
			default:
				break;
			}
			rz_analysis_op_fini(&op);
		}
		at += bsz;
		rz_analysis_op_fini(&op);
	}
	rz_cons_break_pop();
	free(buf);
	free(block);
	return count;
}

static bool isValidSymbol(RzBinSymbol *symbol) {
	if (symbol && symbol->type) {
		const char *type = symbol->type;
		return (symbol->paddr != UT64_MAX) && (!strcmp(type, RZ_BIN_TYPE_FUNC_STR) || !strcmp(type, RZ_BIN_TYPE_HIOS_STR) || !strcmp(type, RZ_BIN_TYPE_LOOS_STR) || !strcmp(type, RZ_BIN_TYPE_METH_STR) || !strcmp(type, RZ_BIN_TYPE_STATIC_STR));
	}
	return false;
}

static bool isSkippable(RzBinSymbol *s) {
	if (s && s->name && s->bind) {
		if (rz_str_startswith(s->name, "radr://")) {
			return true;
		}
		if (!strcmp(s->name, "__mh_execute_header")) {
			return true;
		}
		if (!strcmp(s->bind, "NONE")) {
			if (s->is_imported && s->libname && strstr(s->libname, ".dll")) {
				return true;
			}
		}
	}
	return false;
}

RZ_API int rz_core_analysis_all(RzCore *core) {
	RzList *list;
	RzListIter *iter;
	RzFlagItem *item;
	RzAnalysisFunction *fcni;
	RzBinAddr *binmain;
	RzBinAddr *entry;
	RzBinSymbol *symbol;
	int depth = core->analysis->opt.depth;
	bool analysis_vars = rz_config_get_i(core->config, "analysis.vars");

	/* Analyze Functions */
	/* Entries */
	item = rz_flag_get(core->flags, "entry0");
	if (item) {
		rz_core_analysis_fcn(core, item->offset, -1, RZ_ANALYSIS_REF_TYPE_NULL, depth - 1);
		rz_core_analysis_function_rename(core, item->offset, "entry0");
	} else {
		rz_core_analysis_function_add(core, NULL, core->offset, false);
	}

	rz_core_task_yield(&core->tasks);

	rz_cons_break_push(NULL, NULL);
	/* Symbols (Imports are already analyzed by rz_bin on init) */
	if ((list = rz_bin_get_symbols(core->bin)) != NULL) {
		rz_list_foreach (list, iter, symbol) {
			if (rz_cons_is_breaked()) {
				break;
			}
			// Stop analyzing PE imports further
			if (isSkippable(symbol)) {
				continue;
			}
			if (isValidSymbol(symbol)) {
				ut64 addr = rz_bin_get_vaddr(core->bin, symbol->paddr,
					symbol->vaddr);
				rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_REF_TYPE_NULL, depth - 1);
			}
		}
	}
	rz_core_task_yield(&core->tasks);
	/* Main */
	if ((binmain = rz_bin_get_sym(core->bin, RZ_BIN_SYM_MAIN))) {
		if (binmain->paddr != UT64_MAX) {
			ut64 addr = rz_bin_get_vaddr(core->bin, binmain->paddr, binmain->vaddr);
			rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_REF_TYPE_NULL, depth - 1);
		}
	}
	rz_core_task_yield(&core->tasks);
	if ((list = rz_bin_get_entries(core->bin))) {
		rz_list_foreach (list, iter, entry) {
			if (entry->paddr == UT64_MAX) {
				continue;
			}
			ut64 addr = rz_bin_get_vaddr(core->bin, entry->paddr, entry->vaddr);
			rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_REF_TYPE_NULL, depth - 1);
		}
	}
	rz_core_task_yield(&core->tasks);
	if (analysis_vars) {
		/* Set fcn type to RZ_ANALYSIS_FCN_TYPE_SYM for symbols */
		rz_list_foreach_prev(core->analysis->fcns, iter, fcni) {
			if (rz_cons_is_breaked()) {
				break;
			}
			rz_core_recover_vars(core, fcni, true);
			if (!strncmp(fcni->name, "sym.", 4) || !strncmp(fcni->name, "main", 4)) {
				fcni->type = RZ_ANALYSIS_FCN_TYPE_SYM;
			}
		}
	}
	rz_cons_break_pop();
	return true;
}

RZ_API int rz_core_analysis_data(RzCore *core, ut64 addr, int count, int depth, int wordsize) {
	RzAnalysisData *d;
	ut64 dstaddr = 0LL;
	ut8 *buf = core->block;
	int len = core->blocksize;
	int word = wordsize ? wordsize : core->rasm->bits / 8;
	char *str;
	int i, j;

	count = RZ_MIN(count, len);
	buf = malloc(len + 1);
	if (!buf) {
		return false;
	}
	memset(buf, 0xff, len);
	rz_io_read_at(core->io, addr, buf, len);
	buf[len - 1] = 0;

	RzConsPrintablePalette *pal = rz_config_get_i(core->config, "scr.color") ? &rz_cons_singleton()->context->pal : NULL;
	for (i = j = 0; j < count; j++) {
		if (i >= len) {
			rz_io_read_at(core->io, addr + i, buf, len);
			buf[len] = 0;
			addr += i;
			i = 0;
			continue;
		}
		/* rz_analysis_data requires null-terminated buffer according to coverity */
		/* but it should not.. so this must be fixed in analysis/data.c instead of */
		/* null terminating here */
		d = rz_analysis_data(core->analysis, addr + i, buf + i, len - i, wordsize);
		str = rz_analysis_data_to_string(d, pal);
		rz_cons_println(str);

		if (d) {
			switch (d->type) {
			case RZ_ANALYSIS_DATA_TYPE_POINTER:
				rz_cons_printf("`- ");
				dstaddr = rz_mem_get_num(buf + i, word);
				if (depth > 0) {
					rz_core_analysis_data(core, dstaddr, 1, depth - 1, wordsize);
				}
				i += word;
				break;
			case RZ_ANALYSIS_DATA_TYPE_STRING:
				buf[len - 1] = 0;
				i += strlen((const char *)buf + i) + 1;
				break;
			default:
				i += (d->len > 3) ? d->len : word;
				break;
			}
		} else {
			i += word;
		}
		free(str);
		rz_analysis_data_free(d);
	}
	free(buf);
	return true;
}

struct block_flags_stat_t {
	ut64 step;
	ut64 from;
	RzCoreAnalStats *as;
};

static bool block_flags_stat(RzFlagItem *fi, void *user) {
	struct block_flags_stat_t *u = (struct block_flags_stat_t *)user;
	int piece = (fi->offset - u->from) / u->step;
	u->as->block[piece].flags++;
	return true;
}

/* core analysis stats */
/* stats --- colorful bar */
RZ_API RzCoreAnalStats *rz_core_analysis_get_stats(RzCore *core, ut64 from, ut64 to, ut64 step) {
	RzAnalysisFunction *F;
	RzAnalysisBlock *B;
	RzBinSymbol *S;
	RzListIter *iter, *iter2;
	RzCoreAnalStats *as = NULL;
	int piece, as_size, blocks;
	ut64 at;

	if (from == to || from == UT64_MAX || to == UT64_MAX) {
		eprintf("Cannot alloc for this range\n");
		return NULL;
	}
	as = RZ_NEW0(RzCoreAnalStats);
	if (!as) {
		return NULL;
	}
	if (step < 1) {
		step = 1;
	}
	blocks = (to - from) / step;
	as_size = (1 + blocks) * sizeof(RzCoreAnalStatsItem);
	as->block = malloc(as_size);
	if (!as->block) {
		free(as);
		return NULL;
	}
	memset(as->block, 0, as_size);
	for (at = from; at < to; at += step) {
		RzIOMap *map = rz_io_map_get(core->io, at);
		piece = (at - from) / step;
		as->block[piece].perm = map ? map->perm : (core->io->desc ? core->io->desc->perm : 0);
	}
	// iter all flags
	struct block_flags_stat_t u = { .step = step, .from = from, .as = as };
	rz_flag_foreach_range(core->flags, from, to + 1, block_flags_stat, &u);
	// iter all functions
	rz_list_foreach (core->analysis->fcns, iter, F) {
		if (F->addr < from || F->addr > to) {
			continue;
		}
		piece = (F->addr - from) / step;
		as->block[piece].functions++;
		ut64 last_piece = RZ_MIN((F->addr + rz_analysis_function_linear_size(F) - 1) / step, blocks - 1);
		for (; piece <= last_piece; piece++) {
			as->block[piece].in_functions++;
		}
		// iter all basic blocks
		rz_list_foreach (F->bbs, iter2, B) {
			if (B->addr < from || B->addr > to) {
				continue;
			}
			piece = (B->addr - from) / step;
			as->block[piece].blocks++;
		}
	}
	// iter all symbols
	rz_list_foreach (rz_bin_get_symbols(core->bin), iter, S) {
		if (S->vaddr < from || S->vaddr > to) {
			continue;
		}
		piece = (S->vaddr - from) / step;
		as->block[piece].symbols++;
	}
	RzPVector *metas = to > from ? rz_meta_get_all_intersect(core->analysis, from, to - from, RZ_META_TYPE_ANY) : NULL;
	if (metas) {
		void **it;
		rz_pvector_foreach (metas, it) {
			RzIntervalNode *node = *it;
			RzAnalysisMetaItem *mi = node->data;
			if (node->start < from || node->end > to) {
				continue;
			}
			piece = (node->start - from) / step;
			switch (mi->type) {
			case RZ_META_TYPE_STRING:
				as->block[piece].strings++;
				break;
			case RZ_META_TYPE_COMMENT:
				as->block[piece].comments++;
				break;
			default:
				break;
			}
		}
		rz_pvector_free(metas);
	}
	return as;
}

RZ_API void rz_core_analysis_stats_free(RzCoreAnalStats *s) {
	if (s) {
		free(s->block);
	}
	free(s);
}

RZ_API RzList *rz_core_analysis_cycles(RzCore *core, int ccl) {
	ut64 addr = core->offset;
	int depth = 0;
	RzAnalysisOp *op = NULL;
	RzAnalysisCycleFrame *prev = NULL, *cf = NULL;
	RzAnalysisCycleHook *ch;
	RzList *hooks = rz_list_new();
	if (!hooks) {
		return NULL;
	}
	cf = rz_analysis_cycle_frame_new();
	rz_cons_break_push(NULL, NULL);
	while (cf && !rz_cons_is_breaked()) {
		if ((op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC)) && (op->cycles) && (ccl > 0)) {
			rz_cons_clear_line(1);
			eprintf("%i -- ", ccl);
			addr += op->size;
			switch (op->type) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
				addr = op->jump;
				ccl -= op->cycles;
				loganalysis(op->addr, addr, depth);
				break;
			case RZ_ANALYSIS_OP_TYPE_UJMP:
			case RZ_ANALYSIS_OP_TYPE_MJMP:
			case RZ_ANALYSIS_OP_TYPE_UCALL:
			case RZ_ANALYSIS_OP_TYPE_ICALL:
			case RZ_ANALYSIS_OP_TYPE_RCALL:
			case RZ_ANALYSIS_OP_TYPE_IRCALL:
				ch = RZ_NEW0(RzAnalysisCycleHook);
				ch->addr = op->addr;
				eprintf("0x%08" PFMT64x " > ?\r", op->addr);
				ch->cycles = ccl;
				rz_list_append(hooks, ch);
				ch = NULL;
				while (!ch && cf) {
					ch = rz_list_pop(cf->hooks);
					if (ch) {
						addr = ch->addr;
						ccl = ch->cycles;
						free(ch);
					} else {
						rz_analysis_cycle_frame_free(cf);
						cf = prev;
						if (cf) {
							prev = cf->prev;
						}
					}
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CJMP:
				ch = RZ_NEW0(RzAnalysisCycleHook);
				ch->addr = addr;
				ch->cycles = ccl - op->failcycles;
				rz_list_push(cf->hooks, ch);
				ch = NULL;
				addr = op->jump;
				loganalysis(op->addr, addr, depth);
				break;
			case RZ_ANALYSIS_OP_TYPE_UCJMP:
			case RZ_ANALYSIS_OP_TYPE_UCCALL:
				ch = RZ_NEW0(RzAnalysisCycleHook);
				ch->addr = op->addr;
				ch->cycles = ccl;
				rz_list_append(hooks, ch);
				ch = NULL;
				ccl -= op->failcycles;
				eprintf("0x%08" PFMT64x " > ?\r", op->addr);
				break;
			case RZ_ANALYSIS_OP_TYPE_CCALL:
				ch = RZ_NEW0(RzAnalysisCycleHook);
				ch->addr = addr;
				ch->cycles = ccl - op->failcycles;
				rz_list_push(cf->hooks, ch);
				ch = NULL;
			case RZ_ANALYSIS_OP_TYPE_CALL:
				if (op->addr != op->jump) { //no selfies
					cf->naddr = addr;
					prev = cf;
					cf = rz_analysis_cycle_frame_new();
					cf->prev = prev;
				}
				ccl -= op->cycles;
				addr = op->jump;
				loganalysis(op->addr, addr, depth - 1);
				break;
			case RZ_ANALYSIS_OP_TYPE_RET:
				ch = RZ_NEW0(RzAnalysisCycleHook);
				if (prev) {
					ch->addr = prev->naddr;
					ccl -= op->cycles;
					ch->cycles = ccl;
					rz_list_push(prev->hooks, ch);
					eprintf("0x%08" PFMT64x " < 0x%08" PFMT64x "\r", prev->naddr, op->addr);
				} else {
					ch->addr = op->addr;
					ch->cycles = ccl;
					rz_list_append(hooks, ch);
					eprintf("? < 0x%08" PFMT64x "\r", op->addr);
				}
				ch = NULL;
				while (!ch && cf) {
					ch = rz_list_pop(cf->hooks);
					if (ch) {
						addr = ch->addr;
						ccl = ch->cycles;
						free(ch);
					} else {
						rz_analysis_cycle_frame_free(cf);
						cf = prev;
						if (cf) {
							prev = cf->prev;
						}
					}
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CRET:
				ch = RZ_NEW0(RzAnalysisCycleHook);
				if (prev) {
					ch->addr = prev->naddr;
					ch->cycles = ccl - op->cycles;
					rz_list_push(prev->hooks, ch);
					eprintf("0x%08" PFMT64x " < 0x%08" PFMT64x "\r", prev->naddr, op->addr);
				} else {
					ch->addr = op->addr;
					ch->cycles = ccl - op->cycles;
					rz_list_append(hooks, ch);
					eprintf("? < 0x%08" PFMT64x "\r", op->addr);
				}
				ccl -= op->failcycles;
				break;
			default:
				ccl -= op->cycles;
				eprintf("0x%08" PFMT64x "\r", op->addr);
				break;
			}
		} else {
			ch = RZ_NEW0(RzAnalysisCycleHook);
			if (!ch) {
				rz_analysis_cycle_frame_free(cf);
				rz_list_free(hooks);
				return NULL;
			}
			ch->addr = addr;
			ch->cycles = ccl;
			rz_list_append(hooks, ch);
			ch = NULL;
			while (!ch && cf) {
				ch = rz_list_pop(cf->hooks);
				if (ch) {
					addr = ch->addr;
					ccl = ch->cycles;
					free(ch);
				} else {
					rz_analysis_cycle_frame_free(cf);
					cf = prev;
					if (cf) {
						prev = cf->prev;
					}
				}
			}
		}
		rz_analysis_op_free(op);
	}
	if (rz_cons_is_breaked()) {
		while (cf) {
			ch = rz_list_pop(cf->hooks);
			while (ch) {
				free(ch);
				ch = rz_list_pop(cf->hooks);
			}
			prev = cf->prev;
			rz_analysis_cycle_frame_free(cf);
			cf = prev;
		}
	}
	rz_cons_break_pop();
	return hooks;
}

RZ_API void rz_core_analysis_undefine(RzCore *core, ut64 off) {
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, off, -1);
	if (f) {
		if (!strncmp(f->name, "fcn.", 4)) {
			rz_flag_unset_name(core->flags, f->name);
		}
		rz_meta_del(core->analysis, RZ_META_TYPE_ANY, rz_analysis_function_min_addr(f), rz_analysis_function_linear_size(f));
	}
	rz_analysis_fcn_del_locs(core->analysis, off);
	rz_analysis_fcn_del(core->analysis, off);
}

/* Join function at addr2 into function at addr */
// addr use to be core->offset
RZ_API void rz_core_analysis_fcn_merge(RzCore *core, ut64 addr, ut64 addr2) {
	RzListIter *iter;
	ut64 min = 0;
	ut64 max = 0;
	int first = 1;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f1 = rz_analysis_get_function_at(core->analysis, addr);
	RzAnalysisFunction *f2 = rz_analysis_get_function_at(core->analysis, addr2);
	if (!f1 || !f2) {
		eprintf("Cannot find function\n");
		return;
	}
	if (f1 == f2) {
		eprintf("Cannot merge the same function\n");
		return;
	}
	// join all basic blocks from f1 into f2 if they are not
	// delete f2
	eprintf("Merge 0x%08" PFMT64x " into 0x%08" PFMT64x "\n", addr, addr2);
	rz_list_foreach (f1->bbs, iter, bb) {
		if (first) {
			min = bb->addr;
			max = bb->addr + bb->size;
			first = 0;
		} else {
			if (bb->addr < min) {
				min = bb->addr;
			}
			if (bb->addr + bb->size > max) {
				max = bb->addr + bb->size;
			}
		}
	}
	rz_list_foreach (f2->bbs, iter, bb) {
		if (first) {
			min = bb->addr;
			max = bb->addr + bb->size;
			first = 0;
		} else {
			if (bb->addr < min) {
				min = bb->addr;
			}
			if (bb->addr + bb->size > max) {
				max = bb->addr + bb->size;
			}
		}
		rz_analysis_function_add_block(f1, bb);
	}
	// TODO: import data/code/refs
	rz_analysis_function_delete(f2);
	// update size
	rz_analysis_function_relocate(f2, RZ_MIN(addr, addr2));
}

static bool esil_analysis_stop = false;
static void cccb(void *u) {
	esil_analysis_stop = true;
	eprintf("^C\n");
}

static void add_string_ref(RzCore *core, ut64 xref_from, ut64 xref_to) {
	int len = 0;
	if (xref_to == UT64_MAX || !xref_to) {
		return;
	}
	if (!xref_from || xref_from == UT64_MAX) {
		xref_from = core->analysis->esil->address;
	}
	char *str_flagname = is_string_at(core, xref_to, &len);
	if (str_flagname) {
		rz_analysis_xrefs_set(core->analysis, xref_from, xref_to, RZ_ANALYSIS_REF_TYPE_DATA);
		rz_name_filter(str_flagname, -1);
		char *flagname = sdb_fmt("str.%s", str_flagname);
		rz_flag_space_push(core->flags, RZ_FLAGS_FS_STRINGS);
		rz_flag_set(core->flags, flagname, xref_to, len);
		rz_flag_space_pop(core->flags);
		rz_meta_set(core->analysis, 's', xref_to, len, str_flagname);
		free(str_flagname);
	}
}

// dup with isValidAddress
static bool myvalid(RzIO *io, ut64 addr) {
	if (addr < 0x100) {
		return false;
	}
	if (addr == UT32_MAX || addr == UT64_MAX) { //the best of the best of the best :(
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
	if (ctx->fcn && regname) {
		ut64 spaddr = rz_reg_getv(esil->analysis->reg, ctx->spname);
		if (addr >= spaddr && addr < ctx->initial_sp) {
			int stack_off = addr - ctx->initial_sp;
			RzAnalysisVar *var = rz_analysis_function_get_var(ctx->fcn, RZ_ANALYSIS_VAR_KIND_SPV, stack_off);
			if (!var) {
				var = rz_analysis_function_get_var(ctx->fcn, RZ_ANALYSIS_VAR_KIND_BPV, stack_off);
			}
			if (!var && stack_off >= -ctx->fcn->maxstack) {
				char *varname;
				varname = ctx->fcn->analysis->opt.varname_stack
					? rz_str_newf("var_%xh", RZ_ABS(stack_off))
					: rz_analysis_function_autoname_var(ctx->fcn, RZ_ANALYSIS_VAR_KIND_SPV, "var", delta_for_access(ctx->op, type));
				var = rz_analysis_function_set_var(ctx->fcn, stack_off, RZ_ANALYSIS_VAR_KIND_SPV, NULL, len, false, varname);
				free(varname);
			}
			if (var) {
				rz_analysis_var_set_access(var, regname, ctx->op->addr, type, delta_for_access(ctx->op, type));
			}
		}
	}
}

static int esilbreak_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, len);
	return 1;
}

/* TODO: move into RzCore? */
static ut64 esilbreak_last_read = UT64_MAX;
static ut64 esilbreak_last_data = UT64_MAX;

static ut64 ntarget = UT64_MAX;

// TODO differentiate endian-aware mem_read with other reads; move ntarget handling to another function
static int esilbreak_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	ut8 str[128];
	if (addr != UT64_MAX) {
		esilbreak_last_read = addr;
	}
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, len);
	if (myvalid(mycore->io, addr) && rz_io_read_at(mycore->io, addr, (ut8 *)buf, len)) {
		ut64 refptr;
		bool trace = true;
		switch (len) {
		case 2:
			esilbreak_last_data = refptr = (ut64)rz_read_ble16(buf, esil->analysis->big_endian);
			break;
		case 4:
			esilbreak_last_data = refptr = (ut64)rz_read_ble32(buf, esil->analysis->big_endian);
			break;
		case 8:
			esilbreak_last_data = refptr = rz_read_ble64(buf, esil->analysis->big_endian);
			break;
		default:
			trace = false;
			rz_io_read_at(mycore->io, addr, (ut8 *)buf, len);
			break;
		}
		// TODO incorrect
		bool validRef = false;
		if (trace && myvalid(mycore->io, refptr)) {
			if (ntarget == UT64_MAX || ntarget == refptr) {
				str[0] = 0;
				if (rz_io_read_at(mycore->io, refptr, str, sizeof(str)) < 1) {
					//eprintf ("Invalid read\n");
					str[0] = 0;
					validRef = false;
				} else {
					rz_analysis_xrefs_set(mycore->analysis, esil->address, refptr, RZ_ANALYSIS_REF_TYPE_DATA);
					str[sizeof(str) - 1] = 0;
					add_string_ref(mycore, esil->address, refptr);
					esilbreak_last_data = UT64_MAX;
					validRef = true;
				}
			}
		}

		/** resolve ptr */
		if (ntarget == UT64_MAX || ntarget == addr || (ntarget == UT64_MAX && !validRef)) {
			rz_analysis_xrefs_set(mycore->analysis, esil->address, addr, RZ_ANALYSIS_REF_TYPE_DATA);
		}
	}
	return 0; // fallback
}

static int esilbreak_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	if (!esil) {
		return 0;
	}
	RzAnalysis *analysis = esil->analysis;
	EsilBreakCtx *ctx = esil->user;
	RzAnalysisOp *op = ctx->op;
	RzCore *core = analysis->coreb.core;
	handle_var_stack_access(esil, *val, RZ_ANALYSIS_VAR_ACCESS_TYPE_PTR, esil->analysis->bits / 8);
	//specific case to handle blx/bx cases in arm through emulation
	// XXX this thing creates a lot of false positives
	ut64 at = *val;
	if (analysis && analysis->opt.armthumb) {
		if (analysis->cur && analysis->cur->arch && analysis->bits < 33 &&
			strstr(analysis->cur->arch, "arm") && !strcmp(name, "pc") && op) {
			switch (op->type) {
			case RZ_ANALYSIS_OP_TYPE_UCALL: // BLX
			case RZ_ANALYSIS_OP_TYPE_UJMP: // BX
				// maybe UJMP/UCALL is enough here
				if (!(*val & 1)) {
					rz_analysis_hint_set_bits(analysis, *val, 32);
				} else {
					ut64 snv = rz_reg_getv(analysis->reg, "pc");
					if (snv != UT32_MAX && snv != UT64_MAX) {
						if (rz_io_is_valid_offset(analysis->iob.io, *val, 1)) {
							rz_analysis_hint_set_bits(analysis, *val - 1, 16);
						}
					}
				}
				break;
			default:
				break;
			}
		}
	}
	if (core->rasm->bits == 32 && strstr(core->rasm->cur->name, "arm")) {
		if ((!(at & 1)) && rz_io_is_valid_offset(analysis->iob.io, at, 0)) { //  !core->analysis->opt.noncode)) {
			add_string_ref(analysis->coreb.core, esil->address, at);
		}
	}
	return 0;
}

static void getpcfromstack(RzCore *core, RzAnalysisEsil *esil) {
	ut64 cur;
	ut64 addr;
	ut64 size;
	int idx;
	RzAnalysisEsil esil_cpy;
	RzAnalysisOp op = RZ_EMPTY;
	RzAnalysisFunction *fcn = NULL;
	ut8 *buf = NULL;
	char *tmp_esil_str = NULL;
	int tmp_esil_str_len;
	const char *esilstr;
	const int maxaddrlen = 20;
	const char *spname = NULL;
	if (!esil) {
		return;
	}

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

	rz_io_read_at(core->io, addr, buf, size + 1);

	// TODO Hardcoding for 2 instructions (mov e_p,[esp];ret). More work needed
	idx = 0;
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
	// This is a hack, since ESIL doesn't always preserve values pushed on the stack. That probably needs to be rectified
	spname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
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
	ut64 start_addr;
	ut64 end_addr;
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *cur_bb;
	RzList *bbl, *path, *switch_path;
} IterCtx;

static int find_bb(ut64 *addr, RzAnalysisBlock *bb) {
	return *addr != bb->addr;
}

static inline bool get_next_i(IterCtx *ctx, size_t *next_i) {
	(*next_i)++;
	ut64 cur_addr = *next_i + ctx->start_addr;
	if (ctx->fcn) {
		if (!ctx->cur_bb) {
			ctx->path = rz_list_new();
			ctx->switch_path = rz_list_new();
			ctx->bbl = rz_list_clone(ctx->fcn->bbs);
			ctx->cur_bb = rz_analysis_get_block_at(ctx->fcn->analysis, ctx->fcn->addr);
			rz_list_push(ctx->path, ctx->cur_bb);
		}
		RzAnalysisBlock *bb = ctx->cur_bb;
		if (cur_addr >= bb->addr + bb->size) {
			rz_reg_arena_push(ctx->fcn->analysis->reg);
			RzListIter *bbit = NULL;
			if (bb->switch_op) {
				RzAnalysisCaseOp *cop = rz_list_first(bb->switch_op->cases);
				bbit = rz_list_find(ctx->bbl, &cop->jump, (RzListComparator)find_bb);
				if (bbit) {
					rz_list_push(ctx->switch_path, bb->switch_op->cases->head);
				}
			} else {
				bbit = rz_list_find(ctx->bbl, &bb->jump, (RzListComparator)find_bb);
				if (!bbit && bb->fail != UT64_MAX) {
					bbit = rz_list_find(ctx->bbl, &bb->fail, (RzListComparator)find_bb);
				}
			}
			if (!bbit) {
				RzListIter *cop_it = rz_list_last(ctx->switch_path);
				RzAnalysisBlock *prev_bb = NULL;
				do {
					rz_reg_arena_pop(ctx->fcn->analysis->reg);
					prev_bb = rz_list_pop(ctx->path);
					if (prev_bb->fail != UT64_MAX) {
						bbit = rz_list_find(ctx->bbl, &prev_bb->fail, (RzListComparator)find_bb);
						if (bbit) {
							rz_reg_arena_push(ctx->fcn->analysis->reg);
							rz_list_push(ctx->path, prev_bb);
						}
					}
					if (!bbit && cop_it) {
						RzAnalysisCaseOp *cop = cop_it->data;
						if (cop->jump == prev_bb->addr && cop_it->n) {
							cop = cop_it->n->data;
							rz_list_pop(ctx->switch_path);
							rz_list_push(ctx->switch_path, cop_it->n);
							cop_it = cop_it->n;
							bbit = rz_list_find(ctx->bbl, &cop->jump, (RzListComparator)find_bb);
						}
					}
					if (cop_it && !cop_it->n) {
						rz_list_pop(ctx->switch_path);
						cop_it = rz_list_last(ctx->switch_path);
					}
				} while (!bbit && !rz_list_empty(ctx->path));
			}
			if (!bbit) {
				rz_list_free(ctx->path);
				rz_list_free(ctx->switch_path);
				rz_list_free(ctx->bbl);
				return false;
			}
			ctx->cur_bb = bbit->data;
			rz_list_push(ctx->path, ctx->cur_bb);
			rz_list_delete(ctx->bbl, bbit);
			*next_i = ctx->cur_bb->addr - ctx->start_addr;
		}
	} else if (cur_addr >= ctx->end_addr) {
		return false;
	}
	return true;
}

RZ_API void rz_core_analysis_esil(RzCore *core, const char *str, const char *target) {
	bool cfg_analysis_strings = rz_config_get_i(core->config, "analysis.strings");
	bool emu_lazy = rz_config_get_i(core->config, "emu.lazy");
	bool gp_fixed = rz_config_get_i(core->config, "analysis.gpfixed");
	RzAnalysisEsil *ESIL = core->analysis->esil;
	ut64 refptr = 0LL;
	const char *pcname;
	RzAnalysisOp op = RZ_EMPTY;
	ut8 *buf = NULL;
	bool end_address_set = false;
	int iend;
	int minopsize = 4; // XXX this depends on asm->mininstrsize
	bool archIsArm = false;
	ut64 addr = core->offset;
	ut64 start = addr;
	ut64 end = 0LL;
	ut64 cur;

	mycore = core;
	if (!strcmp(str, "?")) {
		eprintf("Usage: aae[f] [len] [addr] - analyze refs in function, section or len bytes with esil\n");
		eprintf("  aae $SS @ $S             - analyze the whole section\n");
		eprintf("  aae $SS str.Hello @ $S   - find references for str.Hellow\n");
		eprintf("  aaef                     - analyze functions discovered with esil\n");
		return;
	}
#define CHECKREF(x) ((refptr && (x) == refptr) || !refptr)
	if (target) {
		const char *expr = rz_str_trim_head_ro(target);
		if (*expr) {
			refptr = ntarget = rz_num_math(core->num, expr);
			if (!refptr) {
				ntarget = refptr = addr;
			}
		} else {
			ntarget = UT64_MAX;
			refptr = 0LL;
		}
	} else {
		ntarget = UT64_MAX;
		refptr = 0LL;
	}
	RzAnalysisFunction *fcn = NULL;
	if (!strcmp(str, "f")) {
		fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (fcn) {
			start = rz_analysis_function_min_addr(fcn);
			addr = fcn->addr;
			end = rz_analysis_function_max_addr(fcn);
			end_address_set = true;
		}
	}

	if (!end_address_set) {
		if (str[0] == ' ') {
			end = addr + rz_num_math(core->num, str + 1);
		} else {
			RzIOMap *map = rz_io_map_get(core->io, addr);
			if (map) {
				end = map->itv.addr + map->itv.size;
			} else {
				end = addr + core->blocksize;
			}
		}
	}

	iend = end - start;
	if (iend < 0) {
		return;
	}
	if (iend > MAX_SCAN_SIZE) {
		eprintf("Warning: Not going to analyze 0x%08" PFMT64x " bytes.\n", (ut64)iend);
		return;
	}
	buf = malloc((size_t)iend + 2);
	if (!buf) {
		perror("malloc");
		return;
	}
	esilbreak_last_read = UT64_MAX;
	rz_io_read_at(core->io, start, buf, iend + 1);
	if (!ESIL) {
		rz_core_analysis_esil_reinit(core);
		ESIL = core->analysis->esil;
		if (!ESIL) {
			eprintf("ESIL not initialized\n");
			return;
		}
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	const char *spname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	EsilBreakCtx ctx = {
		&op,
		fcn,
		spname,
		rz_reg_getv(core->analysis->reg, spname)
	};
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;
	//this is necessary for the hook to read the id of analop
	ESIL->user = &ctx;
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;

	if (fcn && fcn->reg_save_area) {
		rz_reg_setv(core->analysis->reg, ctx.spname, ctx.initial_sp - fcn->reg_save_area);
	}
	//eprintf ("Analyzing ESIL refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	// TODO: backup/restore register state before/after analysis
	pcname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	if (!pcname || !*pcname) {
		eprintf("Cannot find program counter register in the current profile.\n");
		return;
	}
	esil_analysis_stop = false;
	rz_cons_break_push(cccb, core);

	int arch = -1;
	if (!strcmp(core->analysis->cur->arch, "arm")) {
		switch (core->analysis->cur->bits) {
		case 64: arch = RZ_ARCH_ARM64; break;
		case 32: arch = RZ_ARCH_ARM32; break;
		case 16: arch = RZ_ARCH_THUMB; break;
		}
		archIsArm = true;
	}

	ut64 gp = rz_config_get_i(core->config, "analysis.gp");
	const char *gp_reg = NULL;
	if (!strcmp(core->analysis->cur->arch, "mips")) {
		gp_reg = "gp";
		arch = RZ_ARCH_MIPS;
	}

	const char *sn = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SN);
	if (!sn) {
		eprintf("Warning: No SN reg alias for current architecture.\n");
	}
	rz_reg_arena_push(core->analysis->reg);

	IterCtx ictx = { start, end, fcn, NULL };
	size_t i = addr - start;
	do {
		if (esil_analysis_stop || rz_cons_is_breaked()) {
			break;
		}
		size_t i_old = i;
		cur = start + i;
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
		int opalign = core->analysis->pcalign;
		if (opalign > 0) {
			cur -= (cur % opalign);
		}

		rz_analysis_op_fini(&op);
		rz_asm_set_pc(core->rasm, cur);
		if (!rz_analysis_op(core->analysis, &op, cur, buf + i, iend - i, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT)) {
			i += minopsize - 1; //   XXX dupe in op.size below
		}
		// if (op.type & 0x80000000 || op.type == 0) {
		if (op.type == RZ_ANALYSIS_OP_TYPE_ILL || op.type == RZ_ANALYSIS_OP_TYPE_UNK) {
			// i += 2
			rz_analysis_op_fini(&op);
			goto repeat;
		}
		//we need to check again i because buf+i may goes beyond its boundaries
		//because of i+= minopsize - 1
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
			rz_flag_space_set(core->flags, RZ_FLAGS_FS_SYSCALLS);
			int snv = (arch == RZ_ARCH_THUMB) ? op.val : (int)rz_reg_getv(core->analysis->reg, sn);
			RzSyscallItem *si = rz_syscall_get(core->analysis->syscall, snv, -1);
			if (si) {
				//	eprintf ("0x%08"PFMT64x" SYSCALL %-4d %s\n", cur, snv, si->name);
				rz_flag_set_next(core->flags, sdb_fmt("syscall.%s", si->name), cur, 1);
				rz_syscall_item_free(si);
			} else {
				//todo were doing less filtering up top because we can't match against 80 on all platforms
				// might get too many of this path now..
				//	eprintf ("0x%08"PFMT64x" SYSCALL %d\n", cur, snv);
				rz_flag_set_next(core->flags, sdb_fmt("syscall.%d", snv), cur, 1);
			}
			rz_flag_space_set(core->flags, NULL);
		}
		const char *esilstr = RZ_STRBUF_SAFEGET(&op.esil);
		i += op.size - 1;
		if (!esilstr || !*esilstr) {
			goto repeat;
		}
		rz_analysis_esil_set_pc(ESIL, cur);
		rz_reg_setv(core->analysis->reg, pcname, cur + op.size);
		if (gp_fixed && gp_reg) {
			rz_reg_setv(core->analysis->reg, gp_reg, gp);
		}
		(void)rz_analysis_esil_parse(ESIL, esilstr);
		// looks like ^C is handled by esil_parse !!!!
		//rz_analysis_esil_dumpstack (ESIL);
		//rz_analysis_esil_stack_free (ESIL);
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_LEA:
			// arm64
			if (core->analysis->cur && arch == RZ_ARCH_ARM64) {
				if (CHECKREF(ESIL->cur)) {
					rz_analysis_xrefs_set(core->analysis, cur, ESIL->cur, RZ_ANALYSIS_REF_TYPE_STRING);
				}
			} else if ((target && op.ptr == ntarget) || !target) {
				if (CHECKREF(ESIL->cur)) {
					if (op.ptr && rz_io_is_valid_offset(core->io, op.ptr, !core->analysis->opt.noncode)) {
						rz_analysis_xrefs_set(core->analysis, cur, op.ptr, RZ_ANALYSIS_REF_TYPE_STRING);
					} else {
						rz_analysis_xrefs_set(core->analysis, cur, ESIL->cur, RZ_ANALYSIS_REF_TYPE_STRING);
					}
				}
			}
			if (cfg_analysis_strings) {
				add_string_ref(core, op.addr, op.ptr);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_ADD:
			/* TODO: test if this is valid for other archs too */
			if (core->analysis->cur && archIsArm) {
				/* This code is known to work on Thumb, ARM and ARM64 */
				ut64 dst = ESIL->cur;
				if ((target && dst == ntarget) || !target) {
					if (CHECKREF(dst)) {
						rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_DATA);
					}
				}
				if (cfg_analysis_strings) {
					add_string_ref(core, op.addr, dst);
				}
			} else if ((core->analysis->bits == 32 && core->analysis->cur && arch == RZ_ARCH_MIPS)) {
				ut64 dst = ESIL->cur;
				if (!op.src[0] || !op.src[0]->reg || !op.src[0]->reg->name) {
					break;
				}
				if (!strcmp(op.src[0]->reg->name, "sp")) {
					break;
				}
				if (!strcmp(op.src[0]->reg->name, "zero")) {
					break;
				}
				if ((target && dst == ntarget) || !target) {
					if (dst > 0xffff && op.src[1] && (dst & 0xffff) == (op.src[1]->imm & 0xffff) && myvalid(mycore->io, dst)) {
						RzFlagItem *f;
						char *str;
						if (CHECKREF(dst) || CHECKREF(cur)) {
							rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_DATA);
							if (cfg_analysis_strings) {
								add_string_ref(core, op.addr, dst);
							}
							if ((f = rz_core_flag_get_by_spaces(core->flags, dst))) {
								rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, f->name);
							} else if ((str = is_string_at(mycore, dst, NULL))) {
								char *str2 = sdb_fmt("esilref: '%s'", str);
								// HACK avoid format string inside string used later as format
								// string crashes disasm inside agf under some conditions.
								// https://github.com/rizinorg/rizin/issues/6937
								rz_str_replace_char(str2, '%', '&');
								rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, str2);
								free(str);
							}
						}
					}
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD: {
			ut64 dst = esilbreak_last_read;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(mycore->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_DATA);
					if (cfg_analysis_strings) {
						add_string_ref(core, op.addr, dst);
					}
				}
			}
			dst = esilbreak_last_data;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(mycore->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_DATA);
					if (cfg_analysis_strings) {
						add_string_ref(core, op.addr, dst);
					}
				}
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_JMP: {
			ut64 dst = op.jump;
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_CODE);
				}
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_CALL: {
			ut64 dst = op.jump;
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_CALL);
				}
				ESIL->old = cur + op.size;
				getpcfromstack(core, ESIL);
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
		case RZ_ANALYSIS_OP_TYPE_MJMP: {
			ut64 dst = core->analysis->esil->jump_target;
			if (dst == 0 || dst == UT64_MAX) {
				dst = rz_reg_getv(core->analysis->reg, pcname);
			}
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					RzAnalysisRefType ref =
						(op.type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_UCALL
						? RZ_ANALYSIS_REF_TYPE_CALL
						: RZ_ANALYSIS_REF_TYPE_CODE;
					rz_analysis_xrefs_set(core->analysis, cur, dst, ref);
					rz_core_analysis_fcn(core, dst, UT64_MAX, RZ_ANALYSIS_REF_TYPE_NULL, 1);
// analyze function here
#if 0
						if (op.type == RZ_ANALYSIS_OP_TYPE_UCALL || op.type == RZ_ANALYSIS_OP_TYPE_RCALL) {
							eprintf ("0x%08"PFMT64x"  RCALL TO %llx\n", cur, dst);
						}
#endif
				}
			}
		} break;
		default:
			break;
		}
		rz_analysis_esil_stack_free(ESIL);
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
	free(buf);
	ESIL->cb.hook_mem_read = NULL;
	ESIL->cb.hook_mem_write = NULL;
	ESIL->cb.hook_reg_write = NULL;
	ESIL->user = NULL;
	rz_analysis_op_fini(&op);
	rz_cons_break_pop();
	// restore register
	rz_reg_arena_pop(core->analysis->reg);
}

RZ_IPI void rz_core_analysis_esil_default(RzCore *core) {
	ut64 at = core->offset;
	RzIOMap *map;
	RzListIter *iter;
	RzList *list = rz_core_get_boundaries_prot(core, -1, NULL, "analysis");
	if (!list) {
		return;
	}
	if (!strcmp("range", rz_config_get(core->config, "analysis.in"))) {
		ut64 from = rz_config_get_i(core->config, "analysis.from");
		ut64 to = rz_config_get_i(core->config, "analysis.to");
		if (to > from) {
			char *len = rz_str_newf(" 0x%" PFMT64x, to - from);
			rz_core_seek(core, from, true);
			rz_core_analysis_esil(core, len, NULL);
			free(len);
		} else {
			eprintf("Assert: analysis.from > analysis.to\n");
		}
	} else {
		rz_list_foreach (list, iter, map) {
			if (map->perm & RZ_PERM_X) {
				char *ss = rz_str_newf(" 0x%" PFMT64x, map->itv.size);
				rz_core_seek(core, map->itv.addr, true);
				rz_core_analysis_esil(core, ss, NULL);
				free(ss);
			}
		}
		rz_list_free(list);
	}
	rz_core_seek(core, at, true);
}

static bool isValidAddress(RzCore *core, ut64 addr) {
	// check if address is mapped
	RzIOMap *map = rz_io_map_get(core->io, addr);
	if (!map) {
		return false;
	}
	st64 fdsz = (st64)rz_io_fd_size(core->io, map->fd);
	if (fdsz > 0 && map->delta > fdsz) {
		return false;
	}
	// check if associated file is opened
	RzIODesc *desc = rz_io_desc_get(core->io, map->fd);
	if (!desc) {
		return false;
	}
	// check if current map->fd is null://
	if (!strncmp(desc->name, "null://", 7)) {
		return false;
	}
	return true;
}

static bool stringAt(RzCore *core, ut64 addr) {
	ut8 buf[32];
	rz_io_read_at(core->io, addr - 1, buf, sizeof(buf));
	// check if previous byte is a null byte, all strings, except pascal ones should be like this
	if (buf[0] != 0) {
		return false;
	}
	return is_string(buf + 1, 31, NULL);
}

RZ_API int rz_core_search_value_in_range(RzCore *core, RzInterval search_itv, ut64 vmin,
	ut64 vmax, int vsize, inRangeCb cb, void *cb_user) {
	int i, align = core->search->align, hitctr = 0;
	bool vinfun = rz_config_get_b(core->config, "analysis.vinfun");
	bool vinfunr = rz_config_get_b(core->config, "analysis.vinfunrange");
	bool analyze_strings = rz_config_get_b(core->config, "analysis.strings");
	mycore = core;
	ut8 buf[4096];
	ut64 v64, value = 0, size;
	ut64 from = search_itv.addr, to = rz_itv_end(search_itv);
	ut32 v32;
	ut16 v16;
	if (from >= to) {
		eprintf("Error: from must be lower than to\n");
		return -1;
	}
	bool maybeThumb = false;
	if (align && core->analysis->cur && core->analysis->cur->arch) {
		if (!strcmp(core->analysis->cur->arch, "arm") && core->analysis->bits != 64) {
			maybeThumb = true;
		}
	}

	if (vmin >= vmax) {
		eprintf("Error: vmin must be lower than vmax\n");
		return -1;
	}
	if (to == UT64_MAX) {
		eprintf("Error: Invalid destination boundary\n");
		return -1;
	}
	rz_cons_break_push(NULL, NULL);

	if (!rz_io_is_valid_offset(core->io, from, 0)) {
		return -1;
	}
	while (from < to) {
		size = RZ_MIN(to - from, sizeof(buf));
		memset(buf, 0xff, sizeof(buf)); // probably unnecessary
		if (rz_cons_is_breaked()) {
			goto beach;
		}
		bool res = rz_io_read_at_mapped(core->io, from, buf, size);
		if (!res || !memcmp(buf, "\xff\xff\xff\xff", 4) || !memcmp(buf, "\x00\x00\x00\x00", 4)) {
			if (!isValidAddress(core, from)) {
				ut64 next = rz_io_map_next_address(core->io, from);
				if (next == UT64_MAX) {
					from += sizeof(buf);
				} else {
					from += (next - from);
				}
				continue;
			}
		}
		for (i = 0; i <= (size - vsize); i++) {
			void *v = (buf + i);
			ut64 addr = from + i;
			if (rz_cons_is_breaked()) {
				goto beach;
			}
			if (align && (addr) % align) {
				continue;
			}
			int match = false;
			int left = size - i;
			if (vsize > left) {
				break;
			}
			switch (vsize) {
			case 1:
				value = *(ut8 *)v;
				match = (buf[i] >= vmin && buf[i] <= vmax);
				break;
			case 2:
				v16 = *(uut16 *)v;
				match = (v16 >= vmin && v16 <= vmax);
				value = v16;
				break;
			case 4:
				v32 = *(uut32 *)v;
				match = (v32 >= vmin && v32 <= vmax);
				value = v32;
				break;
			case 8:
				v64 = *(uut64 *)v;
				match = (v64 >= vmin && v64 <= vmax);
				value = v64;
				break;
			default: eprintf("Unknown vsize %d\n", vsize); return -1;
			}
			if (match && !vinfun) {
				if (vinfunr) {
					if (rz_analysis_get_fcn_in_bounds(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL)) {
						match = false;
					}
				} else {
					if (rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL)) {
						match = false;
					}
				}
			}
			if (match && value) {
				bool isValidMatch = true;
				if (align && (value % align)) {
					// ignored .. unless we are analyzing arm/thumb and lower bit is 1
					isValidMatch = false;
					if (maybeThumb && (value & 1)) {
						isValidMatch = true;
					}
				}
				if (isValidMatch) {
					cb(core, addr, value, vsize, cb_user);
					if (analyze_strings && stringAt(core, addr)) {
						add_string_ref(mycore, addr, value);
					}
					hitctr++;
				}
			}
		}
		if (size == to - from) {
			break;
		}
		from += size - vsize + 1;
	}
beach:
	rz_cons_break_pop();
	return hitctr;
}

typedef struct {
	HtUU *visited;
	RzList *path;
	RzCore *core;
	ut64 from;
	RzAnalysisBlock *fromBB;
	ut64 to;
	RzAnalysisBlock *toBB;
	RzAnalysisBlock *cur;
	bool followCalls;
	int followDepth;
	int count; // max number of results
} RzCoreAnalPaths;

static bool printAnalPaths(RzCoreAnalPaths *p, PJ *pj) {
	RzListIter *iter;
	RzAnalysisBlock *path;
	if (pj) {
		pj_a(pj);
	} else {
		rz_cons_printf("pdb @@= ");
	}

	rz_list_foreach (p->path, iter, path) {
		if (pj) {
			pj_n(pj, path->addr);
		} else {
			rz_cons_printf("0x%08" PFMT64x " ", path->addr);
		}
	}

	if (pj) {
		pj_end(pj);
	} else {
		rz_cons_printf("\n");
	}
	return (p->count < 1 || --p->count > 0);
}
static void analPaths(RzCoreAnalPaths *p, PJ *pj);

static void analPathFollow(RzCoreAnalPaths *p, ut64 addr, PJ *pj) {
	if (addr == UT64_MAX) {
		return;
	}
	bool found;
	ht_uu_find(p->visited, addr, &found);
	if (!found) {
		p->cur = rz_analysis_find_most_relevant_block_in(p->core->analysis, addr);
		analPaths(p, pj);
	}
}

static void analPaths(RzCoreAnalPaths *p, PJ *pj) {
	RzAnalysisBlock *cur = p->cur;
	if (!cur) {
		// eprintf ("eof\n");
		return;
	}
	/* handle ^C */
	if (rz_cons_is_breaked()) {
		return;
	}
	ht_uu_insert(p->visited, cur->addr, 1);
	rz_list_append(p->path, cur);
	if (p->followDepth && --p->followDepth == 0) {
		return;
	}
	if (p->toBB && cur->addr == p->toBB->addr) {
		if (!printAnalPaths(p, pj)) {
			return;
		}
	} else {
		RzAnalysisBlock *c = cur;
		ut64 j = cur->jump;
		ut64 f = cur->fail;
		analPathFollow(p, j, pj);
		cur = c;
		analPathFollow(p, f, pj);
		if (p->followCalls) {
			int i;
			for (i = 0; i < cur->op_pos_size; i++) {
				ut64 addr = cur->addr + cur->op_pos[i];
				RzAnalysisOp *op = rz_core_analysis_op(p->core, addr, RZ_ANALYSIS_OP_MASK_BASIC);
				if (op && op->type == RZ_ANALYSIS_OP_TYPE_CALL) {
					analPathFollow(p, op->jump, pj);
				}
				cur = c;
				rz_analysis_op_free(op);
			}
		}
	}
	p->cur = rz_list_pop(p->path);
	ht_uu_delete(p->visited, cur->addr);
	if (p->followDepth) {
		p->followDepth++;
	}
}

RZ_API void rz_core_analysis_paths(RzCore *core, ut64 from, ut64 to, bool followCalls, int followDepth, bool is_json) {
	RzAnalysisBlock *b0 = rz_analysis_find_most_relevant_block_in(core->analysis, from);
	RzAnalysisBlock *b1 = rz_analysis_find_most_relevant_block_in(core->analysis, to);
	PJ *pj = NULL;
	if (!b0) {
		eprintf("Cannot find basic block for 0x%08" PFMT64x "\n", from);
		return;
	}
	if (!b1) {
		eprintf("Cannot find basic block for 0x%08" PFMT64x "\n", to);
		return;
	}
	RzCoreAnalPaths rcap = { 0 };
	rcap.visited = ht_uu_new0();
	rcap.path = rz_list_new();
	rcap.core = core;
	rcap.from = from;
	rcap.fromBB = b0;
	rcap.to = to;
	rcap.toBB = b1;
	rcap.cur = b0;
	rcap.count = rz_config_get_i(core->config, "search.maxhits");
	;
	rcap.followCalls = followCalls;
	rcap.followDepth = followDepth;

	// Initialize a PJ object for json mode
	if (is_json) {
		pj = rz_core_pj_new(core);
		pj_a(pj);
	}

	analPaths(&rcap, pj);

	if (is_json) {
		pj_end(pj);
		rz_cons_printf("%s", pj_string(pj));
	}

	if (pj) {
		pj_free(pj);
	}

	ht_uu_free(rcap.visited);
	rz_list_free(rcap.path);
}

static bool analyze_noreturn_function(RzCore *core, RzAnalysisFunction *f) {
	RzListIter *iter;
	RzAnalysisBlock *bb;
	rz_list_foreach (f->bbs, iter, bb) {
		ut64 opaddr = rz_analysis_block_get_op_addr(bb, bb->ninstr - 1);
		if (opaddr == UT64_MAX) {
			return false;
		}

		// get last opcode
		RzAnalysisOp *op = rz_core_op_analysis(core, opaddr, RZ_ANALYSIS_OP_MASK_HINT);
		if (!op) {
			eprintf("Cannot analyze opcode at 0x%08" PFMT64x "\n", opaddr);
			return false;
		}

		switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
		case RZ_ANALYSIS_OP_TYPE_ILL:
		case RZ_ANALYSIS_OP_TYPE_RET:
			rz_analysis_op_free(op);
			return false;
		case RZ_ANALYSIS_OP_TYPE_JMP:
			if (!rz_analysis_function_contains(f, op->jump)) {
				rz_analysis_op_free(op);
				return false;
			}
			break;
		}
		rz_analysis_op_free(op);
	}
	return true;
}

/* set flags for every function */
RZ_API void rz_core_analysis_flag_every_function(RzCore *core) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_FUNCTIONS);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		rz_flag_set(core->flags, fcn->name,
			fcn->addr, rz_analysis_function_size_from_entry(fcn));
	}
	rz_flag_space_pop(core->flags);
}

/* TODO: move into rz_analysis_function_rename (); */
RZ_API bool rz_core_analysis_function_rename(RzCore *core, ut64 addr, const char *_name) {
	rz_return_val_if_fail(core && _name, false);
	_name = rz_str_trim_head_ro(_name);
	char *name = getFunctionNamePrefix(core, addr, _name);
	// RzAnalysisFunction *fcn = rz_analysis_get_fcn_in (core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_ANY);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
	if (fcn) {
		RzFlagItem *flag = rz_flag_get(core->flags, fcn->name);
		if (flag && flag->space && strcmp(flag->space->name, RZ_FLAGS_FS_FUNCTIONS) == 0) {
			// Only flags in the functions fs should be renamed, e.g. we don't want to rename symbol flags.
			rz_flag_rename(core->flags, flag, name);
		} else {
			// No flag or not specific to the function, create a new one.
			rz_flag_space_push(core->flags, RZ_FLAGS_FS_FUNCTIONS);
			rz_flag_set(core->flags, name, fcn->addr, rz_analysis_function_size_from_entry(fcn));
			rz_flag_space_pop(core->flags);
		}
		rz_analysis_function_rename(fcn, name);
		if (core->analysis->cb.on_fcn_rename) {
			core->analysis->cb.on_fcn_rename(core->analysis, core->analysis->user, fcn, name);
		}
		free(name);
		return true;
	}
	free(name);
	return false;
}

RZ_API bool rz_core_analysis_function_add(RzCore *core, const char *name, ut64 addr, bool analyze_recursively) {
	int depth = rz_config_get_i(core->config, "analysis.depth");
	RzAnalysisFunction *fcn = NULL;

	//rz_core_analysis_undefine (core, core->offset);
	rz_core_analysis_fcn(core, addr, UT64_MAX, RZ_ANALYSIS_REF_TYPE_NULL, depth);
	fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (fcn) {
		/* ensure we use a proper name */
		rz_core_analysis_function_rename(core, addr, fcn->name);
		if (core->analysis->opt.vars) {
			rz_core_recover_vars(core, fcn, true);
		}
		rz_analysis_fcn_vars_add_types(core->analysis, fcn);
	} else {
		if (core->analysis->verbose) {
			eprintf("Warning: Unable to analyze function at 0x%08" PFMT64x "\n", addr);
			return false;
		}
	}
	if (analyze_recursively) {
		fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0); /// XXX wrong in case of nopskip
		if (fcn) {
			RzAnalysisRef *ref;
			RzListIter *iter;
			RzList *refs = rz_analysis_function_get_refs(fcn);
			rz_list_foreach (refs, iter, ref) {
				if (ref->addr == UT64_MAX) {
					//eprintf ("Warning: ignore 0x%08"PFMT64x" call 0x%08"PFMT64x"\n", ref->at, ref->addr);
					continue;
				}
				if (ref->type != RZ_ANALYSIS_REF_TYPE_CODE && ref->type != RZ_ANALYSIS_REF_TYPE_CALL) {
					/* only follow code/call references */
					continue;
				}
				if (!rz_io_is_valid_offset(core->io, ref->addr, !core->analysis->opt.noncode)) {
					continue;
				}
				rz_core_analysis_fcn(core, ref->addr, fcn->addr, RZ_ANALYSIS_REF_TYPE_CALL, depth);
				/* use recursivity here */
				RzAnalysisFunction *f = rz_analysis_get_function_at(core->analysis, ref->addr);
				if (f) {
					RzListIter *iter;
					RzAnalysisRef *ref;
					RzList *refs1 = rz_analysis_function_get_refs(f);
					rz_list_foreach (refs1, iter, ref) {
						if (!rz_io_is_valid_offset(core->io, ref->addr, !core->analysis->opt.noncode)) {
							continue;
						}
						if (ref->type != 'c' && ref->type != 'C') {
							continue;
						}
						rz_core_analysis_fcn(core, ref->addr, f->addr, RZ_ANALYSIS_REF_TYPE_CALL, depth);
						// recursively follow fcn->refs again and again
					}
					rz_list_free(refs1);
				} else {
					f = rz_analysis_get_fcn_in(core->analysis, fcn->addr, 0);
					if (f) {
						/* cut function */
						rz_analysis_function_resize(f, addr - fcn->addr);
						rz_core_analysis_fcn(core, ref->addr, fcn->addr,
							RZ_ANALYSIS_REF_TYPE_CALL, depth);
						f = rz_analysis_get_function_at(core->analysis, fcn->addr);
					}
					if (!f) {
						eprintf("af: Cannot find function at 0x%08" PFMT64x "\n", fcn->addr);
						rz_list_free(refs);
						return false;
					}
				}
			}
			rz_list_free(refs);
			if (core->analysis->opt.vars) {
				rz_core_recover_vars(core, fcn, true);
			}
		}
	}
	if (name) {
		if (*name && !rz_core_analysis_function_rename(core, addr, name)) {
			eprintf("af: Cannot find function at 0x%08" PFMT64x "\n", addr);
			return false;
		}
	}
	rz_core_analysis_propagate_noreturn(core, addr);
	rz_core_analysis_flag_every_function(core);
	return true;
}

RZ_IPI char *rz_core_analysis_function_signature(RzCore *core, RzOutputMode mode, char *fcn_name) {
	RzListIter *iter;
	RzAnalysisFuncArg *arg;
	RzAnalysisFunction *fcn;
	if (fcn_name) {
		fcn = rz_analysis_get_function_byname(core->analysis, fcn_name);
	} else {
		fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (fcn) {
			fcn_name = fcn->name;
		}
	}
	if (!fcn) {
		return NULL;
	}

	char *signature = NULL;

	if (mode == RZ_OUTPUT_MODE_JSON) {
		PJ *j = pj_new();
		if (!j) {
			return NULL;
		}
		pj_a(j);

		char *key = NULL;
		if (fcn_name) {
			key = resolve_fcn_name(core->analysis, fcn_name);
		}

		if (key) {
			const char *fcn_type = rz_type_func_ret(core->analysis->sdb_types, key);
			int nargs = rz_type_func_args_count(core->analysis->sdb_types, key);
			if (fcn_type) {
				pj_o(j);
				pj_ks(j, "name", rz_str_get_null(key));
				pj_ks(j, "return", rz_str_get_null(fcn_type));
				pj_k(j, "args");
				pj_a(j);
				if (nargs) {
					RzList *list = rz_core_get_func_args(core, fcn_name);
					rz_list_foreach (list, iter, arg) {
						char *type = arg->orig_c_type;
						pj_o(j);
						pj_ks(j, "name", arg->name);
						pj_ks(j, "type", type);
						pj_end(j);
					}
					rz_list_free(list);
				}
				pj_end(j);
				pj_ki(j, "count", nargs);
				pj_end(j);
			}
			free(key);
		} else {
			pj_o(j);
			pj_ks(j, "name", rz_str_get_null(fcn_name));
			pj_k(j, "args");
			pj_a(j);

			RzAnalysisFcnVarsCache cache;
			rz_analysis_fcn_vars_cache_init(core->analysis, &cache, fcn);
			int nargs = 0;
			RzAnalysisVar *var;
			rz_list_foreach (cache.rvars, iter, var) {
				nargs++;
				pj_o(j);
				pj_ks(j, "name", var->name);
				pj_ks(j, "type", var->type);
				pj_end(j);
			}
			rz_list_foreach (cache.bvars, iter, var) {
				if (var->delta <= 0) {
					continue;
				}
				nargs++;
				pj_o(j);
				pj_ks(j, "name", var->name);
				pj_ks(j, "type", var->type);
				pj_end(j);
			}
			rz_list_foreach (cache.svars, iter, var) {
				if (!var->isarg) {
					continue;
				}
				nargs++;
				pj_o(j);
				pj_ks(j, "name", var->name);
				pj_ks(j, "type", var->type);
				pj_end(j);
			}
			rz_analysis_fcn_vars_cache_fini(&cache);

			pj_end(j);
			pj_ki(j, "count", nargs);
			pj_end(j);
		}
		pj_end(j);
		signature = strdup(pj_string(j));
		pj_free(j);
	} else {
		signature = rz_analysis_fcn_format_sig(core->analysis, fcn, fcn_name, NULL, NULL, NULL);
	}
	return signature;
}

RZ_API void rz_core_analysis_propagate_noreturn(RzCore *core, ut64 addr) {
	RzList *todo = rz_list_newf(free);
	if (!todo) {
		return;
	}

	HtUU *done = ht_uu_new0();
	if (!done) {
		rz_list_free(todo);
		return;
	}

	RzAnalysisFunction *request_fcn = NULL;
	if (addr != UT64_MAX) {
		request_fcn = rz_analysis_get_function_at(core->analysis, addr);
		if (!request_fcn) {
			rz_list_free(todo);
			ht_uu_free(done);
			return;
		}
	}

	// find known noreturn functions to propagate
	RzListIter *iter;
	RzAnalysisFunction *f;
	rz_list_foreach (core->analysis->fcns, iter, f) {
		if (f->is_noreturn) {
			ut64 *n = ut64_new(f->addr);
			rz_list_append(todo, n);
		}
	}

	while (!rz_list_empty(todo)) {
		ut64 *paddr = (ut64 *)rz_list_pop(todo);
		ut64 noret_addr = *paddr;
		free(paddr);
		if (rz_cons_is_breaked()) {
			break;
		}
		RzList *xrefs = rz_analysis_xrefs_get(core->analysis, noret_addr);
		RzAnalysisRef *xref;
		rz_list_foreach (xrefs, iter, xref) {
			RzAnalysisOp *xrefop = rz_core_op_analysis(core, xref->addr, RZ_ANALYSIS_OP_MASK_ALL);
			if (!xrefop) {
				eprintf("Cannot analyze opcode at 0x%08" PFMT64x "\n", xref->addr);
				continue;
			}
			ut64 call_addr = xref->addr;
			ut64 chop_addr = call_addr + xrefop->size;
			rz_analysis_op_free(xrefop);
			if (xref->type != RZ_ANALYSIS_REF_TYPE_CALL) {
				continue;
			}

			// Find the block that has an instruction at exactly the xref addr
			RzList *blocks = rz_analysis_get_blocks_in(core->analysis, call_addr);
			if (!blocks) {
				continue;
			}
			RzAnalysisBlock *block = NULL;
			RzListIter *bit;
			RzAnalysisBlock *block_cur;
			rz_list_foreach (blocks, bit, block_cur) {
				if (rz_analysis_block_op_starts_at(block_cur, call_addr)) {
					block = block_cur;
					break;
				}
			}
			if (block) {
				rz_analysis_block_ref(block);
			}
			rz_list_free(blocks);
			if (!block) {
				continue;
			}

			RzList *block_fcns = rz_list_clone(block->fcns);
			if (request_fcn) {
				// specific function requested, check if it contains the bb
				if (!rz_list_contains(block->fcns, request_fcn)) {
					goto kontinue;
				}
			} else {
				// rz_analysis_block_chop_noreturn() might free the block!
				block = rz_analysis_block_chop_noreturn(block, chop_addr);
			}

			RzListIter *fit;
			rz_list_foreach (block_fcns, fit, f) {
				bool found = ht_uu_find(done, f->addr, NULL) != 0;
				if (f->addr && !found && analyze_noreturn_function(core, f)) {
					f->is_noreturn = true;
					rz_analysis_noreturn_add(core->analysis, NULL, f->addr);
					ut64 *n = malloc(sizeof(ut64));
					*n = f->addr;
					rz_list_append(todo, n);
					ht_uu_insert(done, *n, 1);
				}
			}
		kontinue:
			if (block) {
				rz_analysis_block_unref(block);
			}
			rz_list_free(block_fcns);
		}
		rz_list_free(xrefs);
	}
	rz_list_free(todo);
	ht_uu_free(done);
}

RZ_API void rz_core_analysis_esil_graph(RzCore *core, const char *expr) {
	RzAnalysisEsilDFG *edf = rz_analysis_esil_dfg_expr(core->analysis, NULL, expr);
	RzListIter *iter, *ator;
	RzGraphNode *node, *edon;
	RzStrBuf *buf = rz_strbuf_new("");
	rz_cons_printf("ag-\n");
	rz_list_foreach (rz_graph_get_nodes(edf->flow), iter, node) {
		const RzAnalysisEsilDFGNode *enode = (RzAnalysisEsilDFGNode *)node->data;
		char *esc_str = rz_str_escape(rz_strbuf_get(enode->content));
		rz_strbuf_set(buf, esc_str);
		if (enode->type == RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE) {
			rz_strbuf_prepend(buf, "generative:");
		}
		char *b64_buf = rz_base64_encode_dyn((const ut8 *)rz_strbuf_get(buf), buf->len);
		rz_cons_printf("agn %d base64:%s\n", enode->idx, b64_buf);
		free(b64_buf);
		free(esc_str);
	}
	rz_strbuf_free(buf);

	rz_list_foreach (rz_graph_get_nodes(edf->flow), iter, node) {
		const RzAnalysisEsilDFGNode *enode = (RzAnalysisEsilDFGNode *)node->data;
		rz_list_foreach (rz_graph_get_neighbours(edf->flow, node), ator, edon) {
			const RzAnalysisEsilDFGNode *edone = (RzAnalysisEsilDFGNode *)edon->data;
			rz_cons_printf("age %d %d\n", enode->idx, edone->idx);
		}
	}

	rz_analysis_esil_dfg_free(edf);
}

RZ_IPI bool rz_core_analysis_var_rename(RzCore *core, const char *name, const char *newname) {
	RzAnalysisOp *op = rz_core_analysis_op(core, core->offset, RZ_ANALYSIS_OP_MASK_BASIC);
	if (!name) {
		RzAnalysisVar *var = op ? rz_analysis_get_used_function_var(core->analysis, op->addr) : NULL;
		if (var) {
			name = var->name;
		} else {
			eprintf("Cannot find var @ 0x%08" PFMT64x "\n", core->offset);
			rz_analysis_op_free(op);
			return false;
		}
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
	if (fcn) {
		RzAnalysisVar *v1 = rz_analysis_function_get_var_byname(fcn, name);
		if (v1) {
			rz_analysis_var_rename(v1, newname, true);
		} else {
			eprintf("Cant find var by name\n");
			return false;
		}
	} else {
		eprintf("afv: Cannot find function in 0x%08" PFMT64x "\n", core->offset);
		rz_analysis_op_free(op);
		return false;
	}
	rz_analysis_op_free(op);
	return true;
}

static bool is_unknown_file(RzCore *core) {
	if (core->bin->cur && core->bin->cur->o) {
		return (rz_list_empty(core->bin->cur->o->sections));
	}
	return true;
}

static bool is_apple_target(RzCore *core) {
	const char *arch = rz_config_get(core->config, "asm.arch");
	if (!strstr(arch, "ppc") && !strstr(arch, "arm") && !strstr(arch, "x86")) {
		return false;
	}
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	rz_return_val_if_fail(!bo || (bo->plugin && bo->plugin->name), false);
	return bo ? strstr(bo->plugin->name, "mach") : false;
}

/**
 * Runs all the steps of the deep analysis.
 *
 * Returns true if all steps were finished and false if it was interrupted.
 *
 * \param core RzCore reference
 * \param experimental Enable more experimental analysis stages ("aaaa" command)
 * \param dh_orig Name of the debug handler, e.g. "esil"
 */
RZ_IPI bool rz_core_analysis_everything(RzCore *core, bool experimental, char *dh_orig) {
	bool didAap = false;
	ut64 curseek = core->offset;
	bool cfg_debug = rz_config_get_i(core->config, "cfg.debug");
	const char *oldstr = NULL;
	if (rz_str_startswith(rz_config_get(core->config, "bin.lang"), "go")) {
		oldstr = rz_print_rowlog(core->print, "Find function and symbol names from golang binaries (aang)");
		rz_print_rowlog_done(core->print, oldstr);
		rz_core_analysis_autoname_all_golang_fcns(core);
		oldstr = rz_print_rowlog(core->print, "Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
		rz_core_cmd0(core, "aF @@f:sym.go.*");
		rz_print_rowlog_done(core->print, oldstr);
	}
	rz_core_task_yield(&core->tasks);
	if (!cfg_debug) {
		if (dh_orig && strcmp(dh_orig, "esil")) {
			rz_config_set(core->config, "dbg.backend", "esil");
			rz_core_task_yield(&core->tasks);
		}
	}
	int c = rz_config_get_i(core->config, "analysis.calls");
	rz_config_set_i(core->config, "analysis.calls", 1);
	ut64 t = rz_num_math(core->num, "$S");
	rz_core_seek(core, t, true);
	if (rz_cons_is_breaked()) {
		return false;
	}

	oldstr = rz_print_rowlog(core->print, "Analyze function calls (aac)");
	(void)rz_cmd_analysis_calls(core, "", false, false); // "aac"
	rz_core_seek(core, curseek, true);
	rz_print_rowlog_done(core->print, oldstr);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}

	if (is_unknown_file(core)) {
		oldstr = rz_print_rowlog(core->print, "find and analyze function preludes (aap)");
		(void)rz_core_search_preludes(core, false); // "aap"
		didAap = true;
		rz_print_rowlog_done(core->print, oldstr);
		rz_core_task_yield(&core->tasks);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}

	oldstr = rz_print_rowlog(core->print, "Analyze len bytes of instructions for references (aar)");
	(void)rz_core_analysis_refs(core, ""); // "aar"
	rz_print_rowlog_done(core->print, oldstr);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}
	if (is_apple_target(core)) {
		oldstr = rz_print_rowlog(core->print, "Check for objc references");
		rz_print_rowlog_done(core->print, oldstr);
		cmd_analysis_objc(core, true);
	}
	rz_core_task_yield(&core->tasks);
	oldstr = rz_print_rowlog(core->print, "Check for vtables");
	rz_analysis_rtti_recover_all(core->analysis);
	rz_print_rowlog_done(core->print, oldstr);
	rz_core_task_yield(&core->tasks);
	rz_config_set_i(core->config, "analysis.calls", c);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}
	if (!rz_str_startswith(rz_config_get(core->config, "asm.arch"), "x86")) {
		rz_core_analysis_value_pointers(core, RZ_OUTPUT_MODE_STANDARD);
		rz_core_task_yield(&core->tasks);
		bool ioCache = rz_config_get_i(core->config, "io.pcache");
		rz_config_set_i(core->config, "io.pcache", 1);
		oldstr = rz_print_rowlog(core->print, "Emulate functions to find computed references (aaef)");
		rz_core_analysis_esil_references_all_functions(core);
		rz_print_rowlog_done(core->print, oldstr);
		rz_core_task_yield(&core->tasks);
		rz_config_set_i(core->config, "io.pcache", ioCache);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}
	if (rz_config_get_i(core->config, "analysis.autoname")) {
		oldstr = rz_print_rowlog(core->print, "Speculatively constructing a function name "
						      "for fcn.* and sym.func.* functions (aan)");
		rz_core_analysis_autoname_all_fcns(core);
		rz_print_rowlog_done(core->print, oldstr);
		rz_core_task_yield(&core->tasks);
	}
	if (core->analysis->opt.vars) {
		RzAnalysisFunction *fcni;
		RzListIter *iter;
		rz_list_foreach (core->analysis->fcns, iter, fcni) {
			if (rz_cons_is_breaked()) {
				break;
			}
			RzList *list = rz_analysis_var_list(core->analysis, fcni, 'r');
			if (!rz_list_empty(list)) {
				rz_list_free(list);
				continue;
			}
			//extract only reg based var here
			rz_core_recover_vars(core, fcni, true);
			rz_list_free(list);
		}
		rz_core_task_yield(&core->tasks);
	}
	if (!sdb_isempty(core->analysis->sdb_zigns)) {
		oldstr = rz_print_rowlog(core->print, "Check for zignature from zigns folder (z/)");
		rz_core_cmd0(core, "z/");
		rz_print_rowlog_done(core->print, oldstr);
		rz_core_task_yield(&core->tasks);
	}

	oldstr = rz_print_rowlog(core->print, "Type matching analysis for all functions (aaft)");
	rz_core_analysis_types_propagation(core);
	rz_print_rowlog_done(core->print, oldstr);
	rz_core_task_yield(&core->tasks);

	oldstr = rz_print_rowlog(core->print, "Propagate noreturn information");
	rz_core_analysis_propagate_noreturn(core, UT64_MAX);
	rz_print_rowlog_done(core->print, oldstr);
	rz_core_task_yield(&core->tasks);

	// Apply DWARF function information
	Sdb *dwarf_sdb = sdb_ns(core->analysis->sdb, "dwarf", 0);
	if (dwarf_sdb) {
		oldstr = rz_print_rowlog(core->print, "Integrate dwarf function information.");
		rz_analysis_dwarf_integrate_functions(core->analysis, core->flags, dwarf_sdb);
		rz_print_rowlog_done(core->print, oldstr);
	}

	oldstr = rz_print_rowlog(core->print, "Use -AA or aaaa to perform additional experimental analysis.");
	rz_print_rowlog_done(core->print, oldstr);

	if (experimental) {
		if (!didAap) {
			oldstr = rz_print_rowlog(core->print, "Finding function preludes");
			(void)rz_core_search_preludes(core, false); // "aap"
			rz_print_rowlog_done(core->print, oldstr);
			rz_core_task_yield(&core->tasks);
		}

		oldstr = rz_print_rowlog(core->print, "Enable constraint types analysis for variables");
		rz_config_set(core->config, "analysis.types.constraint", "true");
		rz_print_rowlog_done(core->print, oldstr);
	}
	rz_core_seek_undo(core);
	if (dh_orig) {
		rz_config_set(core->config, "dbg.backend", dh_orig);
		rz_core_task_yield(&core->tasks);
	}
	return true;
}

RZ_IPI bool rz_core_analysis_function_delete_var(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarKind kind, const char *id) {
	RzAnalysisVar *var = NULL;
	if (IS_DIGIT(*id)) {
		int delta = rz_num_math(core->num, id);
		var = rz_analysis_function_get_var(fcn, kind, delta);
	} else {
		var = rz_analysis_function_get_var_byname(fcn, id);
	}
	if (!var || var->kind != kind) {
		return false;
	}
	rz_analysis_var_delete(var);
	return true;
}

RZ_IPI char *rz_core_analysis_var_display(RzCore *core, RzAnalysisVar *var, bool add_name) {
	RzAnalysis *analysis = core->analysis;
	RzStrBuf *sb = rz_strbuf_new(NULL);
	char *fmt = rz_type_format(analysis->sdb_types, var->type);
	RzRegItem *i;
	if (!fmt) {
		RZ_LOG_DEBUG("type:%s doesn't exist\n", var->type);
		return rz_strbuf_drain(sb);
	}
	bool usePxr = !strcmp(var->type, "int"); // hacky but useful
	if (add_name) {
		rz_strbuf_appendf(sb, "%s %s = ", var->isarg ? "arg" : "var", var->name);
	}
	switch (var->kind) {
	case RZ_ANALYSIS_VAR_KIND_REG:
		i = rz_reg_index_get(analysis->reg, var->delta);
		if (i) {
			char *r;
			if (usePxr) {
				r = rz_core_cmd_strf(core, "pxr $w @r:%s", i->name);
			} else {
				r = rz_core_cmd_strf(core, "pf r (%s)", i->name);
			}
			rz_strbuf_append(sb, r);
			free(r);
		} else {
			RZ_LOG_DEBUG("register not found\n");
		}
		break;
	case RZ_ANALYSIS_VAR_KIND_BPV: {
		const st32 real_delta = var->delta + var->fcn->bp_off;
		const ut32 udelta = RZ_ABS(real_delta);
		const char sign = real_delta >= 0 ? '+' : '-';
		char *r;
		if (usePxr) {
			r = rz_core_cmd_strf(core, "pxr $w @%s%c0x%x", analysis->reg->name[RZ_REG_NAME_BP], sign, udelta);
		} else {
			r = rz_core_cmd_strf(core, "pf %s @%s%c0x%x", fmt, analysis->reg->name[RZ_REG_NAME_BP], sign, udelta);
		}
		rz_strbuf_append(sb, r);
		free(r);
	} break;
	case RZ_ANALYSIS_VAR_KIND_SPV: {
		ut32 udelta = RZ_ABS(var->delta + var->fcn->maxstack);
		char *r;
		if (usePxr) {
			r = rz_core_cmd_strf(core, "pxr $w @%s+0x%x", analysis->reg->name[RZ_REG_NAME_SP], udelta);
		} else {
			r = rz_core_cmd_strf(core, "pf %s @ %s+0x%x", fmt, analysis->reg->name[RZ_REG_NAME_SP], udelta);
		}
		rz_strbuf_append(sb, r);
		free(r);
		break;
	}
	}
	free(fmt);
	return rz_strbuf_drain(sb);
}

RZ_IPI char *rz_core_analysis_all_vars_display(RzCore *core, RzAnalysisFunction *fcn, bool add_name) {
	RzListIter *iter;
	RzAnalysisVar *p;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_list_foreach (list, iter, p) {
		char *r = rz_core_analysis_var_display(core, p, add_name);
		rz_strbuf_append(sb, r);
		free(r);
	}
	rz_list_free(list);
	return rz_strbuf_drain(sb);
}

RZ_IPI bool rz_core_analysis_types_propagation(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	ut64 seek;
	if (rz_config_get_i(core->config, "cfg.debug")) {
		eprintf("TOFIX: aaft can't run in debugger mode.\n");
		return false;
	}
	const char *io_cache_key = "io.pcache.write";
	RzConfigHold *hold = rz_config_hold_new(core->config);
	rz_config_hold_i(hold, "io.va", io_cache_key, NULL);
	bool io_cache = rz_config_get_i(core->config, io_cache_key);
	if (!io_cache) {
		// XXX. we shouldnt need this, but it breaks 'rizin -c aaa -w ls'
		rz_config_set_i(core->config, io_cache_key, true);
	}
	const bool delete_regs = !rz_flag_space_count(core->flags, RZ_FLAGS_FS_REGISTERS);
	seek = core->offset;
	rz_reg_arena_push(core->analysis->reg);
	rz_reg_arena_zero(core->analysis->reg);
	rz_core_analysis_esil_init(core);
	rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	ut8 *saved_arena = rz_reg_arena_peek(core->analysis->reg);
	// Iterating Reverse so that we get function in top-bottom call order
	rz_list_foreach_prev(core->analysis->fcns, it, fcn) {
		int ret = rz_core_seek(core, fcn->addr, true);
		if (!ret) {
			continue;
		}
		rz_reg_arena_poke(core->analysis->reg, saved_arena);
		rz_analysis_esil_set_pc(core->analysis->esil, fcn->addr);
		rz_core_analysis_type_match(core, fcn);
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_analysis_fcn_vars_add_types(core->analysis, fcn);
	}
	if (delete_regs) {
		rz_core_debug_clear_register_flags(core);
	}
	rz_core_seek(core, seek, true);
	rz_reg_arena_pop(core->analysis->reg);
	rz_config_hold_restore(hold);
	rz_config_hold_free(hold);
	free(saved_arena);
	return true;
}

RZ_IPI bool rz_core_analysis_function_set_signature(RzCore *core, RzAnalysisFunction *fcn, const char *newsig) {
	bool res = false;
	char *fcnstr = rz_str_newf("%s;", newsig);
	char *fcnstr_copy = strdup(fcnstr);
	char *fcnname_aux = strtok(fcnstr_copy, "(");
	rz_str_trim_tail(fcnname_aux);
	char *fcnname = NULL;
	const char *ls = rz_str_lchr(fcnname_aux, ' ');
	fcnname = strdup(ls ? ls : fcnname_aux);
	if (!fcnname) {
		goto err;
	}
	// TODO: move this into rz_analysis_str_to_fcn()
	if (strcmp(fcn->name, fcnname)) {
		(void)rz_core_analysis_function_rename(core, fcn->addr, fcnname);
		fcn = rz_analysis_get_fcn_in(core->analysis, fcn->addr, -1);
	}
	rz_analysis_str_to_fcn(core->analysis, fcn, fcnstr);
	res = true;
err:
	free(fcnname);
	free(fcnstr_copy);
	free(fcnstr);
	return res;
}

RZ_IPI void rz_core_analysis_function_signature_editor(RzCore *core, ut64 addr) {
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
	if (!f) {
		eprintf("Cannot find function in 0x%08" PFMT64x "\n", core->offset);
		return;
	}

	char *sig = rz_analysis_function_get_signature(f);
	char *data = rz_core_editor(core, NULL, sig);
	if (sig && data) {
		rz_core_analysis_function_set_signature(core, f, data);
	}
	free(sig);
	free(data);
}

RZ_IPI void rz_core_analysis_function_until(RzCore *core, ut64 addr_end) {
	rz_return_if_fail(core->offset <= addr_end);
	ut64 addr = core->offset;
	int depth = 1;
	ut64 a, b;
	const char *c;
	a = rz_config_get_i(core->config, "analysis.from");
	b = rz_config_get_i(core->config, "analysis.to");
	c = rz_config_get(core->config, "analysis.limits");
	rz_config_set_i(core->config, "analysis.from", addr);
	rz_config_set_i(core->config, "analysis.to", addr_end);
	rz_config_set(core->config, "analysis.limits", "true");

	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (fcn) {
		rz_analysis_function_resize(fcn, addr_end - addr);
	}
	rz_core_analysis_fcn(core, addr, UT64_MAX,
		RZ_ANALYSIS_REF_TYPE_NULL, depth);
	fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (fcn) {
		rz_analysis_function_resize(fcn, addr_end - addr);
	}
	rz_config_set_i(core->config, "analysis.from", a);
	rz_config_set_i(core->config, "analysis.to", b);
	rz_config_set(core->config, "analysis.limits", c ? c : "");
}

static bool archIsThumbable(RzCore *core) {
	RzAsm *as = core ? core->rasm : NULL;
	if (as && as->cur && as->bits <= 32 && as->cur->name) {
		return strstr(as->cur->name, "arm");
	}
	return false;
}

static void _CbInRangeAav(RzCore *core, ut64 from, ut64 to, int vsize, void *user) {
	bool pretend = (user && *(RzOutputMode *)user == RZ_OUTPUT_MODE_RIZIN);
	int arch_align = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
	bool vinfun = rz_config_get_b(core->config, "analysis.vinfun");
	int searchAlign = rz_config_get_i(core->config, "search.align");
	int align = (searchAlign > 0) ? searchAlign : arch_align;
	if (align > 1) {
		if ((from % align) || (to % align)) {
			bool itsFine = false;
			if (archIsThumbable(core)) {
				if ((from & 1) || (to & 1)) {
					itsFine = true;
				}
			}
			if (!itsFine) {
				return;
			}
			if (core->analysis->verbose) {
				eprintf("Warning: aav: false positive in 0x%08" PFMT64x "\n", from);
			}
		}
	}
	if (!vinfun) {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, from, -1);
		if (fcn) {
			return;
		}
	}
	if (pretend) {
		rz_cons_printf("ax 0x%" PFMT64x " 0x%" PFMT64x "\n", to, from);
		rz_cons_printf("Cd %d @ 0x%" PFMT64x "\n", vsize, from);
		rz_cons_printf("f+ aav.0x%08" PFMT64x "= 0x%08" PFMT64x, to, to);
	} else {
		rz_analysis_xrefs_set(core->analysis, from, to, RZ_ANALYSIS_REF_TYPE_NULL);
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, from, vsize, NULL);
		if (!rz_flag_get_at(core->flags, to, false)) {
			char *name = rz_str_newf("aav.0x%08" PFMT64x, to);
			rz_flag_set(core->flags, name, to, vsize);
			free(name);
		}
	}
}

RZ_IPI void rz_core_analysis_value_pointers(RzCore *core, RzOutputMode mode) {
	ut64 o_align = rz_config_get_i(core->config, "search.align");
	const char *analysisin = rz_config_get(core->config, "analysis.in");
	char *tmp = strdup(analysisin);
	bool is_debug = rz_config_get_b(core->config, "cfg.debug");
	int archAlign = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
	rz_config_set_i(core->config, "search.align", archAlign);
	rz_config_set(core->config, "analysis.in", "io.maps.x");
	const char *oldstr = rz_print_rowlog(core->print, "Finding xrefs in noncode section with analysis.in=io.maps");
	rz_print_rowlog_done(core->print, oldstr);

	int vsize = 4; // 32bit dword
	if (core->rasm->bits == 64) {
		vsize = 8;
	}

	// body
	oldstr = rz_print_rowlog(core->print, "Analyze value pointers (aav)");
	rz_print_rowlog_done(core->print, oldstr);
	rz_cons_break_push(NULL, NULL);
	if (is_debug) {
		RzList *list = rz_core_get_boundaries_prot(core, 0, "dbg.map", "analysis");
		RzListIter *iter;
		RzIOMap *map;
		if (!list) {
			goto beach;
		}
		rz_list_foreach (list, iter, map) {
			if (rz_cons_is_breaked()) {
				break;
			}
			oldstr = rz_print_rowlog(core->print, sdb_fmt("from 0x%" PFMT64x " to 0x%" PFMT64x " (aav)", map->itv.addr, rz_itv_end(map->itv)));
			rz_print_rowlog_done(core->print, oldstr);
			(void)rz_core_search_value_in_range(core, map->itv,
				map->itv.addr, rz_itv_end(map->itv), vsize, _CbInRangeAav, (void *)&mode);
		}
		rz_list_free(list);
	} else {
		RzList *list = rz_core_get_boundaries_prot(core, 0, NULL, "analysis");
		if (!list) {
			goto beach;
		}
		RzListIter *iter, *iter2;
		RzIOMap *map, *map2;
		ut64 from = UT64_MAX;
		ut64 to = UT64_MAX;
		// find values pointing to non-executable regions
		rz_list_foreach (list, iter2, map2) {
			if (rz_cons_is_breaked()) {
				break;
			}
			//TODO: Reduce multiple hits for same addr
			from = rz_itv_begin(map2->itv);
			to = rz_itv_end(map2->itv);
			oldstr = rz_print_rowlog(core->print, sdb_fmt("Value from 0x%08" PFMT64x " to 0x%08" PFMT64x " (aav)", from, to));
			if ((to - from) > MAX_SCAN_SIZE) {
				eprintf("Warning: Skipping large region\n");
				continue;
			}
			rz_print_rowlog_done(core->print, oldstr);
			rz_list_foreach (list, iter, map) {
				ut64 begin = map->itv.addr;
				ut64 end = rz_itv_end(map->itv);
				if (rz_cons_is_breaked()) {
					break;
				}
				if (end - begin > UT32_MAX) {
					oldstr = rz_print_rowlog(core->print, "Skipping huge range");
					rz_print_rowlog_done(core->print, oldstr);
					continue;
				}
				oldstr = rz_print_rowlog(core->print, sdb_fmt("0x%08" PFMT64x "-0x%08" PFMT64x " in 0x%" PFMT64x "-0x%" PFMT64x " (aav)", from, to, begin, end));
				rz_print_rowlog_done(core->print, oldstr);
				(void)rz_core_search_value_in_range(core, map->itv, from, to, vsize, _CbInRangeAav, (void *)&mode);
			}
		}
		rz_list_free(list);
	}
beach:
	rz_cons_break_pop();
	// end
	rz_config_set(core->config, "analysis.in", tmp);
	free(tmp);
	rz_config_set_i(core->config, "search.align", o_align);
}

RZ_API int rz_core_get_stacksz(RzCore *core, ut64 from, ut64 to) {
	int stack = 0, maxstack = 0;
	ut64 at = from;

	if (from >= to) {
		return 0;
	}
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	while (at < to) {
		RzAnalysisOp *op = rz_core_analysis_op(core, at, RZ_ANALYSIS_OP_MASK_BASIC);
		if (!op || op->size <= 0) {
			at += minopcode;
			rz_analysis_op_free(op);
			continue;
		}
		if ((op->stackop == RZ_ANALYSIS_STACK_INC) && RZ_ABS(op->stackptr) < 8096) {
			stack += op->stackptr;
			if (stack > maxstack) {
				maxstack = stack;
			}
		}
		at += op->size;
		rz_analysis_op_free(op);
	}
	return maxstack;
}
