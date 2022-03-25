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
#include <rz_util/rz_path.h>

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
	rs = rz_reg_regset_get(core->analysis->reg, RZ_REG_TYPE_GPR);
	if (rs) {
		RzRegItem *r;
		RzListIter *iter;
		rz_list_foreach (rs->regs, iter, r) {
			if (r->type == RZ_REG_TYPE_GPR) {
				ut64 val = rz_reg_getv(core->analysis->reg, r->name);
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
	if (rz_core_is_debug(core)) {
		RzDebugMap *map;
		RzListIter *iter;
		// use 'dm'
		// XXX: this line makes rz debugging MUCH slower
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
			RzPVector *maps = rz_io_maps(core->io);
			rz_pvector_foreach (maps, it) {
				RzIOMap *s = *it;
				if (addr >= s->itv.addr && addr < (s->itv.addr + s->itv.size)) {
					// sections overlap, so we want to get the one with lower perms
					_perm = (_perm != -1) ? RZ_MIN(_perm, s->perm) : s->perm;
					// TODO: we should identify which maps come from the program or other
					// types |= RZ_ANALYSIS_ADDR_TYPE_PROGRAM;
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
		rz_cons_printf("f bb.%05" PFMT64x " @ 0x%08" PFMT64x "\n", bb->addr & 0xFFFFF, bb->addr);
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

RZ_IPI void rz_core_analysis_bbs_info_print(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	rz_return_if_fail(core && fcn && state);
	RzListIter *iter;
	RzAnalysisBlock *bb;
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "xdxx", "addr", "size", "jump", "fail");
	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_printf("fs blocks\n");
	}

	rz_list_sort(fcn->bbs, bb_cmp);
	rz_list_foreach (fcn->bbs, iter, bb) {
		bb_info_print(core, fcn, bb, bb->addr, state->mode, state->d.pj, state->d.t);
	}

	rz_cmd_state_output_array_end(state);
}

RZ_IPI void rz_core_analysis_bb_info_print(RzCore *core, RzAnalysisBlock *bb, ut64 addr, RzCmdStateOutput *state) {
	rz_return_if_fail(core && bb && state);
	rz_cmd_state_output_set_columnsf(state, "xdxx", "addr", "size", "jump", "fail");
	RzAnalysisFunction *fcn = rz_list_first(bb->fcns);
	bb_info_print(core, fcn, bb, addr, state->mode, state->d.pj, state->d.t);
}

/*this only autoname those function that start with fcn.* or sym.func.* */
RZ_API void rz_core_analysis_autoname_all_fcns(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;

	rz_list_foreach (core->analysis->fcns, it, fcn) {
		if (!strncmp(fcn->name, "fcn.", 4) || !strncmp(fcn->name, "sym.func.", 9)) {
			RzFlagItem *item = rz_flag_get(core->flags, fcn->name);
			if (item) {
				char *name = rz_core_analysis_function_autoname(core, fcn);
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
		oldstr = rz_core_notify_begin(core, "Could not find .gopclntab section");
		rz_core_notify_done(core, oldstr);
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
	// rz_cons_print ("[x] Reading .gopclntab...\n");
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
		rz_name_filter((char *)func_name, 0, true);
		// rz_cons_printf ("[x] Found symbol %s at 0x%x\n", func_name, func_addr);
		rz_flag_set(core->flags, sdb_fmt("sym.go.%s", func_name), func_addr, 1);
		offset += 2 * ptr_size;
		num_syms++;
	}
	rz_flag_space_pop(core->flags);
	if (num_syms) {
		oldstr = rz_core_notify_begin(core, sdb_fmt("Found %d symbols and saved them at sym.go.*", num_syms));
		rz_core_notify_done(core, oldstr);
	} else {
		oldstr = rz_core_notify_begin(core, "Found no symbols.");
		rz_core_notify_done(core, oldstr);
	}
}

static bool blacklisted_word(const char *name) {
	const char *list[] = {
		"__stack_chk_guard",
		"__stderrp",
		"__stdinp",
		"__stdoutp",
		"_DefaultRuneLocale"
	};
	for (int i = 0; i < RZ_ARRAY_SIZE(list); i++) {
		if (strstr(name, list[i])) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Suggest a name for the function
 */
RZ_API RZ_OWN char *rz_core_analysis_function_autoname(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(core && fcn, NULL);

	RzAnalysisXRef *xref;
	RzListIter *iter;
	bool use_getopt = false;
	bool use_isatty = false;
	char *do_call = NULL;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xref) {
		RzFlagItem *f = rz_flag_get_i(core->flags, xref->to);
		if (f && !blacklisted_word(f->name)) {
			if (strstr(f->name, ".isatty")) {
				use_isatty = 1;
			}
			if (strstr(f->name, ".getopt")) {
				use_getopt = 1;
			}
			if (!strncmp(f->name, "method.", 7)) {
				free(do_call);
				do_call = strdup(f->name + 7);
				break;
			}
			if (!strncmp(f->name, "str.", 4)) {
				free(do_call);
				do_call = strdup(f->name + 4);
				break;
			}
			if (!strncmp(f->name, "sym.imp.", 8)) {
				free(do_call);
				do_call = strdup(f->name + 8);
				break;
			}
			if (!strncmp(f->name, "reloc.", 6)) {
				free(do_call);
				do_call = strdup(f->name + 6);
				break;
			}
		}
	}
	rz_list_free(xrefs);
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

/**
 * \brief Print all string flags referenced by the function
 */
RZ_API void rz_core_analysis_function_strings_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE PJ *pj) {
	rz_return_if_fail(core && fcn);

	RzAnalysisXRef *xref;
	RzListIter *iter;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xref) {
		RzFlagItem *f = rz_flag_get_by_spaces(core->flags, xref->to, RZ_FLAGS_FS_STRINGS, NULL);
		if (!f || !f->space || strcmp(f->space->name, RZ_FLAGS_FS_STRINGS)) {
			continue;
		}
		if (pj) {
			pj_o(pj);
			pj_kn(pj, "addr", xref->from);
			pj_kn(pj, "ref", xref->to);
			pj_ks(pj, "flag", f->name);
			pj_end(pj);
		} else {
			rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %s\n", xref->from, xref->to, f->name);
		}
	}
	rz_list_free(xrefs);
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
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_REF_TYPE_DATA &&
			rz_bin_is_string(core->bin, xref->to)) {
			rz_analysis_xrefs_set(core->analysis, xref->from, xref->to, RZ_ANALYSIS_REF_TYPE_STRING);
		}
	}
	rz_list_free(xrefs);
}

static bool rz_analysis_try_get_fcn(RzCore *core, RzAnalysisXRef *xref, int fcndepth, int refdepth) {
	if (!refdepth) {
		return false;
	}
	RzIOMap *map = rz_io_map_get(core->io, xref->to);
	if (!map) {
		return false;
	}

	if (map->perm & RZ_PERM_X) {
		ut8 buf[64];
		rz_io_read_at(core->io, xref->to, buf, sizeof(buf));
		bool looksLikeAFunction = rz_analysis_check_fcn(core->analysis, buf, sizeof(buf), xref->to, map->itv.addr,
			map->itv.addr + map->itv.size);
		if (looksLikeAFunction) {
			if (core->analysis->limit) {
				if (xref->to < core->analysis->limit->from ||
					xref->to > core->analysis->limit->to) {
					return 1;
				}
			}
			rz_core_analysis_fcn(core, xref->to, xref->from, xref->type, fcndepth - 1);
		}
	} else {
		ut64 offs = 0;
		ut64 sz = core->analysis->bits >> 3;
		RzAnalysisXRef xref1;
		xref1.type = RZ_ANALYSIS_REF_TYPE_DATA;
		xref1.from = xref->to;
		xref1.to = 0;
		ut32 i32;
		ut16 i16;
		ut8 i8;
		ut64 offe = offs + 1024;
		for (offs = 0; offs < offe; offs += sz, xref1.from += sz) {
			ut8 bo[8];
			rz_io_read_at(core->io, xref->to + offs, bo, RZ_MIN(sizeof(bo), sz));
			bool be = core->analysis->big_endian;
			switch (sz) {
			case 1:
				i8 = rz_read_ble8(bo);
				xref1.to = (ut64)i8;
				break;
			case 2:
				i16 = rz_read_ble16(bo, be);
				xref1.to = (ut64)i16;
				break;
			case 4:
				i32 = rz_read_ble32(bo, be);
				xref1.to = (ut64)i32;
				break;
			case 8:
				xref1.to = rz_read_ble64(bo, be);
				break;
			}
			rz_analysis_try_get_fcn(core, &xref1, fcndepth, refdepth - 1);
		}
	}
	return 1;
}

static int rz_analysis_analyze_fcn_refs(RzCore *core, RzAnalysisFunction *fcn, int depth) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->to == UT64_MAX) {
			continue;
		}
		switch (xref->type) {
		case RZ_ANALYSIS_REF_TYPE_DATA:
			if (core->analysis->opt.followdatarefs) {
				rz_analysis_try_get_fcn(core, xref, depth, 2);
			}
			break;
		case RZ_ANALYSIS_REF_TYPE_CODE:
		case RZ_ANALYSIS_REF_TYPE_CALL:
			rz_core_analysis_fcn(core, xref->to, xref->from, xref->type, depth - 1);
			break;
		default:
			break;
		}
		// TODO: fix memleak here, fcn not freed even though it is
		// added in core->analysis->fcns which is freed in rz_analysis_free()
	}
	rz_list_free(xrefs);
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
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		if (xrefs && rz_list_length(xrefs) == 1) {
			RzAnalysisXRef *xref = rz_list_first(xrefs);
			if (xref->type != RZ_ANALYSIS_REF_TYPE_CALL) { /* Some fcns don't return */
				RzFlagItem *flg = rz_flag_get_i(core->flags, xref->to);
				if (flg && rz_str_startswith(flg->name, "sym.imp.")) {
					RZ_FREE(fcn->name);
					fcn->name = rz_str_newf("sub.%s", flg->name + 8);
				}
			}
		}
		rz_list_free(xrefs);
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
			RZ_LOG_DEBUG("Analyzed function has size of 0 at 0x%08" PFMT64x "\n", at + delta);
			goto error;
		}
		if (fcnlen < 0) {
			switch (fcnlen) {
			case RZ_ANALYSIS_RET_ERROR:
			case RZ_ANALYSIS_RET_END:
				break;
			case RZ_ANALYSIS_RET_COND:
			case RZ_ANALYSIS_RET_BRANCH:
				continue;
			default:
				RZ_LOG_ERROR("Found negative function size at 0x%08" PFMT64x " (%d)\n", at, fcnlen);
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
		RZ_LOG_DEBUG("Unimplemented RZ_ANALYSIS_OP_MASK_DISASM for current analysis.arch. Using the RzAsmOp as fallback for now.\n");
		rz_asm_set_pc(core->rasm, addr);
		rz_asm_op_init(&asmop);
		if (rz_asm_disassemble(core->rasm, &asmop, ptr, len) > 0) {
			op->mnemonic = strdup(rz_strbuf_get(&asmop.buf_asm));
		}
		rz_asm_op_fini(&asmop);
	}
	return op;
err_op:
	rz_analysis_op_free(op);
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

static void hint_node_print(HintNode *node, RzOutputMode mode, PJ *pj) {
	switch (mode) {
	case RZ_OUTPUT_MODE_RIZIN:
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
	case RZ_OUTPUT_MODE_JSON:
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

static void print_hint_tree(RBTree tree, RzCmdStateOutput *state) {
	PJ *pj = state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL;
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
#define END_ADDR \
	if (pj) { \
		pj_end(pj); \
	} else if (state->mode == RZ_OUTPUT_MODE_STANDARD) { \
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
			} else if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
				rz_cons_printf(" 0x%08" PFMT64x " =>", node->addr);
			}
		}
		hint_node_print(node, state->mode, pj);
	}
	if (in_addr) {
		END_ADDR
	}
#undef BEGIN_ADDR
#undef END_ADDR
	if (pj) {
		pj_end(pj);
	}
}

RZ_API void rz_core_analysis_hint_list_print(RzAnalysis *a, RzCmdStateOutput *state) {
	rz_return_if_fail(a && state);
	RBTree tree = NULL;
	// Collect all hints in the tree to sort them
	rz_analysis_arch_hints_foreach(a, print_arch_hint_cb, &tree);
	rz_analysis_bits_hints_foreach(a, print_bits_hint_cb, &tree);
	rz_analysis_addr_hints_foreach(a, print_addr_hint_cb, &tree);
	print_hint_tree(tree, state);
	rz_rbtree_free(tree, hint_node_free, NULL);
}

RZ_API void rz_core_analysis_hint_print(RzAnalysis *a, ut64 addr, RzCmdStateOutput *state) {
	rz_return_if_fail(a && state);
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
	print_hint_tree(tree, state);
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
		const int scrColor = rz_config_get_i(core->config, "scr.color");
		const bool scrUtf8 = rz_config_get_b(core->config, "scr.utf8");
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
	char *pal_trfa = palColorFor("graph.ujump");
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
						char dff_from[32], dff_to[32];

						RzCore *c = core->c2;
						RzConfig *oc = c->config;
						char *str = rz_core_cmd_strf(core, "pdb @ 0x%08" PFMT64x, bbi->addr);
						c->config = core->config;
						// XXX. the bbi->addr doesnt needs to be in the same address in core2
						char *str2 = rz_core_cmd_strf(c, "pdb @ 0x%08" PFMT64x, bbi->diff->addr);
						snprintf(dff_from, sizeof(dff_from), "0x%08" PFMT64x, bbi->addr);
						snprintf(dff_to, sizeof(dff_to), "0x%08" PFMT64x, bbi->diff->addr);

						RzDiff *dff = rz_diff_lines_new(str, str2, NULL);
						char *diffstr = rz_diff_unified_text(dff, dff_from, dff_to, false, false);
						rz_diff_free(dff);

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
							if (!title) {
								rz_config_hold_free(hc);
								return false;
							}
							char *body_b64 = rz_base64_encode_dyn((const ut8 *)diffstr, strlen(diffstr));
							if (!body_b64) {
								free(title);
								rz_config_hold_free(hc);
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
							if (!title) {
								rz_config_hold_free(hc);
								return false;
							}
							char *body_b64 = rz_base64_encode_dyn((const ut8 *)str, strlen(title));
							int color = (bbi && bbi->diff) ? bbi->diff->type : 0;
							if (!title || !body_b64) {
								free(body_b64);
								free(title);
								rz_config_hold_free(hc);
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
	rz_return_val_if_fail(fcn && fcn->bbs, -1);
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;
	int is_keva = opts & RZ_CORE_ANALYSIS_KEYVALUE;
	int nodes = 0;
	Sdb *DB = NULL;
	char *pal_jump = palColorFor("graph.true");
	char *pal_fail = palColorFor("graph.false");
	char *pal_trfa = palColorFor("graph.ujump");
	char *pal_curr = palColorFor("graph.current");
	char *pal_traced = palColorFor("graph.traced");
	char *pal_box4 = palColorFor("graph.box4");

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
		RZ_LOG_DEBUG("invalid address for function 0x%08" PFMT64x "\n", at);
		return 0;
	}

	const bool use_esil = rz_config_get_i(core->config, "analysis.esil");
	RzAnalysisFunction *fcn;

	// update bits based on the core->offset otherwise we could have the
	// last value set and blow everything up
	rz_core_seek_arch_bits(core, at);

	if (core->io->va) {
		if (!rz_io_is_valid_offset(core->io, at, !core->analysis->opt.noncode)) {
			RZ_LOG_DEBUG("address not mapped or not executable at 0x%08" PFMT64x "\n", at);
			return false;
		}
	}
	if (use_esil) {
		return rz_core_analysis_esil_fcn(core, at, from, reftype, depth);
	}

	if ((from != UT64_MAX && !at) || at == UT64_MAX) {
		RZ_LOG_WARN("invalid address from 0x%08" PFMT64x "\n", from);
		return false;
	}
	if (depth < 0) {
		RZ_LOG_DEBUG("analysis depth reached\n");
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
			RzList *l = rz_analysis_xrefs_get_to(core->analysis, from);
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
		RzAnalysisXRef *xref;
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		rz_list_foreach (xrefs, iter, xref) {
			RzBinObject *obj = rz_bin_cur_object(core->bin);
			RzBinSection *binsec = rz_bin_get_section_at(obj, xref->to, true);
			if (binsec && binsec->is_data) {
				if (!found) {
					rz_cons_printf("agn %s\n", me);
					found = true;
				}
				RzFlagItem *item = rz_flag_get_i(core->flags, xref->to);
				const char *dst = item ? item->name : sdb_fmt("0x%08" PFMT64x, xref->to);
				rz_cons_printf("agn %s\n", dst);
				rz_cons_printf("age %s %s\n", me, dst);
			}
		}
		rz_list_free(xrefs);
	} else {
		eprintf("Not in a function. Use 'df' to define it.\n");
	}
}

RZ_API void rz_core_analysis_coderefs(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
	if (fcn) {
		const char *me = fcn->name;
		RzListIter *iter;
		RzAnalysisXRef *xref;
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		rz_cons_printf("agn %s\n", me);
		rz_list_foreach (xrefs, iter, xref) {
			RzFlagItem *item = rz_flag_get_i(core->flags, xref->to);
			const char *dst = item ? item->name : sdb_fmt("0x%08" PFMT64x, xref->from);
			rz_cons_printf("agn %s\n", dst);
			rz_cons_printf("age %s %s\n", me, dst);
		}
		rz_list_free(xrefs);
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
	RzAnalysisXRef *xref;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, addr);
	rz_list_foreach (list, iter, xref) {
		RzFlagItem *item = rz_flag_get_i(core->flags, xref->from);
		char *src = item ? rz_str_new(item->name) : rz_str_newf("0x%08" PFMT64x, xref->from);
		RzGraphNode *reference_from = rz_graph_add_node_info(graph, src, NULL, xref->from);
		free(src);
		rz_graph_add_edge(graph, reference_from, curr_node);
	}
	rz_list_free(list);
}

RZ_API RzGraph *rz_core_analysis_importxrefs(RzCore *core) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
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
		RzBinSymbol *sym = rz_bin_object_get_symbol_of_import(obj, imp);
		ut64 addr = sym ? (va ? rz_bin_object_get_vaddr(obj, sym->paddr, sym->vaddr) : sym->paddr) : UT64_MAX;
		if (addr && addr != UT64_MAX) {
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

static int RzAnalysisRef_cmp(const RzAnalysisXRef *xref1, const RzAnalysisXRef *xref2) {
	return xref1->to != xref2->to;
}

RZ_API void rz_core_analysis_callgraph(RzCore *core, ut64 addr, int fmt) {
	const char *font = rz_config_get(core->config, "graph.font");
	int is_html = rz_cons_singleton()->is_html;
	bool refgraph = rz_config_get_i(core->config, "graph.refs");
	RzListIter *iter, *iter2;
	int usenames = rz_config_get_i(core->config, "graph.json.usenames");
	;
	RzAnalysisFunction *fcni;
	RzAnalysisXRef *fcnr;
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
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcni);
		RzList *calls = rz_list_new();
		// TODO: maybe fcni->calls instead ?
		rz_list_foreach (xrefs, iter2, fcnr) {
			//  TODO: tail calll jumps are also calls
			if (fcnr->type == 'C' && rz_list_find(calls, fcnr, (RzListComparator)RzAnalysisRef_cmp) == NULL) {
				rz_list_append(calls, fcnr);
			}
		}
		if (rz_list_empty(calls)) {
			rz_list_free(xrefs);
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
			RzFlagItem *flag = rz_flag_get_i(core->flags, fcnr->to);
			char *fcnr_name = (flag && flag->name) ? flag->name : rz_str_newf("unk.0x%" PFMT64x, fcnr->to);
			switch (fmt) {
			case RZ_GRAPH_FORMAT_GMLFCN:
				if (iteration == 0) {
					rz_cons_printf("  node [\n"
						       "    id  %" PFMT64d "\n"
						       "    label  \"%s\"\n"
						       "  ]\n",
						fcnr->to - base, fcnr_name);
					rz_cons_printf("  edge [\n"
						       "    source  %" PFMT64d "\n"
						       "    target  %" PFMT64d "\n"
						       "  ]\n",
						fcni->addr - base, fcnr->to - base);
				}
				// fallthrough
			case RZ_GRAPH_FORMAT_GML:
				if (iteration != 0) {
					rz_cons_printf("  edge [\n"
						       "    source  %" PFMT64d "\n"
						       "    target  %" PFMT64d "\n"
						       "  ]\n",
						fcni->addr - base, fcnr->to - base); //, "#000000"
				}
				break;
			case RZ_GRAPH_FORMAT_DOT:
				rz_cons_printf("  \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
					       "[color=\"%s\" URL=\"%s/0x%08" PFMT64x "\"];\n",
					//"[label=\"%s\" color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
					fcni->addr, fcnr->to, //, fcnr_name,
					"#61afef",
					fcnr_name, fcnr->to);
				rz_cons_printf("  \"0x%08" PFMT64x "\" "
					       "[label=\"%s\""
					       " URL=\"%s/0x%08" PFMT64x "\"];\n",
					fcnr->to, fcnr_name,
					fcnr_name, fcnr->to);
				break;
			case RZ_GRAPH_FORMAT_JSON:
				if (usenames) {
					pj_s(pj, fcnr_name);
				} else {
					char fcnr_addr[20];
					snprintf(fcnr_addr, sizeof(fcnr_addr) - 1, "0x%08" PFMT64x, fcnr->to);
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
					rz_cons_printf("# - 0x%08" PFMT64x " (%c)\n", fcnr->to, fcnr->type);
				}
			}
			if (!(flag && flag->name)) {
				free(fcnr_name);
			}
		}
		rz_list_free(xrefs);
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

// for a given function returns an RzList of all functions that were called in it
RZ_API RzList *rz_core_analysis_fcn_get_calls(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xrefi;
	RzListIter *iter, *iter2;

	// get all references from this function
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	// sanity check
	if (!rz_list_empty(xrefs)) {
		// iterate over all the references and remove these which aren't of type call
		rz_list_foreach_safe (xrefs, iter, iter2, xrefi) {
			if (xrefi->type != RZ_ANALYSIS_REF_TYPE_CALL) {
				rz_list_delete(xrefs, iter);
			}
		}
	}
	return xrefs;
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
			// eprintf ("Cannot get op\n");
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
	if (first_bb) {
		rz_analysis_block_recurse_depth_first(first_bb, (RzAnalysisBlockCb)analysis_block_cb, (RzAnalysisBlockCb)analysis_block_on_exit, &ctx);
	}
	rz_pvector_fini(&ctx.reg_set);
	fcn->stack = saved_stack;
}

static bool analysis_path_exists(RzCore *core, ut64 from, ut64 to, RzList *bbs, int depth, HtUP *state, HtUP *avoid) {
	rz_return_val_if_fail(bbs, false);
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, from);
	RzListIter *iter = NULL;
	RzAnalysisXRef *xrefi;

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
		RzList *xrefs = rz_analysis_function_get_xrefs_from(cur_fcn);
		if (xrefs) {
			rz_list_foreach (xrefs, iter, xrefi) {
				if (xrefi->type == RZ_ANALYSIS_REF_TYPE_CALL) {
					if (rz_analysis_block_contains(bb, xrefi->from)) {
						if ((xrefi->from != xrefi->to) && !ht_up_find(state, xrefi->to, NULL) && analysis_path_exists(core, xrefi->to, to, bbs, depth - 1, state, avoid)) {
							rz_list_prepend(bbs, bb);
							rz_list_free(xrefs);
							return true;
						}
					}
				}
			}
		}
		rz_list_free(xrefs);
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
	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, cur_fcn->addr);
	if (xrefs) {
		RzListIter *iter;
		RzAnalysisXRef *xref = NULL;
		rz_list_foreach (xrefs, iter, xref) {
			if (xref->type == RZ_ANALYSIS_REF_TYPE_CALL) {
				ut64 offset = core->offset;
				core->offset = xref->from;
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

RZ_API bool rz_core_analysis_graph(RzCore *core, ut64 addr, int opts) {
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
	// opts |= RZ_CORE_ANALYSIS_GRAPHBODY;
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
		pj = pj_new();
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
		const RzAnalysisXRefType t = code ? type ? type : RZ_ANALYSIS_REF_TYPE_CODE : RZ_ANALYSIS_REF_TYPE_DATA;
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
		// addr should be aligned by 4 in aarch64
		if (addr % 4) {
			char diff = addr % 4;
			addr = addr - diff;
			buf = buf - diff;
		}
		// if is not bl do not analyze
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

/**
 * \brief Validates a xref. Mainly checks if it points out of the memory map.
 *
 * \param core The rizin core.
 * \param xref_to The target address of the xref.
 * \param type The xref type.
 * \param cfg_debug Flag if debugging configured.
 * \return true xref is valid.
 * \return false xref is not valid.
 */
static bool is_valid_xref(RzCore *core, ut64 xref_to, RzAnalysisXRefType type, int cfg_debug) {
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
	return true;
}

/**
 * \brief Prints a xref according to the given \p out_mode.
 *
 * \param core The rizin core.
 * \param at The address where the xref is located.
 * \param xref_to The target address of the xref.
 * \param type The xref type.
 * \param pj The print JSON object.
 * \param out_mode The output mode. If set to RZ_OUTPUT_MODE_JSON the \p 'pj' parameter will be filled with the xrefs found.
 * \param cfg_analysis_strings
 */
static void print_xref(RzCore *core, ut64 at, ut64 xref_to, RzAnalysisXRefType type, PJ *pj, RzOutputMode out_mode, bool cfg_analysis_strings) {
	if (out_mode == RZ_OUTPUT_MODE_STANDARD) {
		if (cfg_analysis_strings && type == RZ_ANALYSIS_REF_TYPE_DATA) {
			int len = 0;
			char *str_string = is_string_at(core, xref_to, &len);
			if (str_string) {
				rz_name_filter(str_string, -1, true);
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
	} else if (out_mode == RZ_OUTPUT_MODE_JSON) {
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
		rz_cons_printf("%s 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", cmd, xref_to, at);
		if (cfg_analysis_strings && type == RZ_ANALYSIS_REF_TYPE_DATA) {
			char *str_flagname = is_string_at(core, xref_to, &len);
			if (str_flagname) {
				ut64 str_addr = xref_to;
				rz_name_filter(str_flagname, -1, true);
				rz_cons_printf("f str.%s @ 0x%" PFMT64x "\n", str_flagname, str_addr);
				rz_cons_printf("Cs %d @ 0x%" PFMT64x "\n", len, str_addr);
				free(str_flagname);
			}
		}
	}
}

/**
 * \brief Searches for xrefs in the range of the paramters \p 'from' and \p 'to'.
 *
 * \param core The Rizin core.
 * \param from Start of search interval.
 * \param to End of search interval.
 * \param pj The print JSON object.
 * \param out_mode The output mode. If set to RZ_OUTPUT_MODE_JSON the \p 'pj' parameter will be filled with the xrefs found.
 * \return int Number of found xrefs. -1 in case of failure.
 */
RZ_API int rz_core_analysis_search_xrefs(RzCore *core, ut64 from, ut64 to, PJ *pj, RzOutputMode out_mode) {
	bool cfg_debug = rz_config_get_b(core->config, "cfg.debug");
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
				if (is_valid_xref(core, op.val, RZ_ANALYSIS_REF_TYPE_DATA, cfg_debug)) {
					print_xref(core, op.addr, op.val, RZ_ANALYSIS_REF_TYPE_DATA, pj, out_mode, cfg_analysis_strings);
					count++;
				}
			}
			for (ut8 i = 0; i < 6; ++i) {
				st64 aval = op.analysis_vals[i].imm;
				if (aval > asm_sub_varmin && aval != UT64_MAX && aval != UT32_MAX) {
					if (is_valid_xref(core, aval, RZ_ANALYSIS_REF_TYPE_DATA, cfg_debug)) {
						print_xref(core, op.addr, aval, RZ_ANALYSIS_REF_TYPE_DATA, pj, out_mode, cfg_analysis_strings);
						count++;
					}
				}
			}
			// find references
			if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
				if (is_valid_xref(core, op.ptr, RZ_ANALYSIS_REF_TYPE_DATA, cfg_debug)) {
					print_xref(core, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_DATA, pj, out_mode, cfg_analysis_strings);
					count++;
				}
			}
			// find references
			if (op.addr > 512 && op.disp > 512 && op.disp && op.disp != UT64_MAX) {
				if (is_valid_xref(core, op.disp, RZ_ANALYSIS_REF_TYPE_DATA, cfg_debug)) {
					print_xref(core, op.addr, op.disp, RZ_ANALYSIS_REF_TYPE_DATA, pj, out_mode, cfg_analysis_strings);
					count++;
				}
			}
			switch (op.type) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
				if (is_valid_xref(core, op.jump, RZ_ANALYSIS_REF_TYPE_CODE, cfg_debug)) {
					print_xref(core, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CODE, pj, out_mode, cfg_analysis_strings);
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CJMP:
				if (rz_config_get_b(core->config, "analysis.jmp.cref") &&
					is_valid_xref(core, op.jump, RZ_ANALYSIS_REF_TYPE_CODE, cfg_debug)) {
					print_xref(core, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CODE, pj, out_mode, cfg_analysis_strings);
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CALL:
			case RZ_ANALYSIS_OP_TYPE_CCALL:
				if (is_valid_xref(core, op.jump, RZ_ANALYSIS_REF_TYPE_CALL, cfg_debug)) {
					print_xref(core, op.addr, op.jump, RZ_ANALYSIS_REF_TYPE_CALL, pj, out_mode, cfg_analysis_strings);
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
				if (is_valid_xref(core, op.ptr, RZ_ANALYSIS_REF_TYPE_CODE, cfg_debug)) {
					print_xref(core, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_CODE, pj, out_mode, cfg_analysis_strings);
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_UCALL:
			case RZ_ANALYSIS_OP_TYPE_ICALL:
			case RZ_ANALYSIS_OP_TYPE_RCALL:
			case RZ_ANALYSIS_OP_TYPE_IRCALL:
			case RZ_ANALYSIS_OP_TYPE_UCCALL:
				if (is_valid_xref(core, op.ptr, RZ_ANALYSIS_REF_TYPE_CALL, cfg_debug)) {
					print_xref(core, op.addr, op.ptr, RZ_ANALYSIS_REF_TYPE_CALL, pj, out_mode, cfg_analysis_strings);
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
	const RzBinAddr *binmain;
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

	RzBinFile *bf = core->bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
	/* Symbols (Imports are already analyzed by rz_bin on init) */
	if (o && (list = o->symbols) != NULL) {
		rz_list_foreach (list, iter, symbol) {
			if (rz_cons_is_breaked()) {
				break;
			}
			// Stop analyzing PE imports further
			if (isSkippable(symbol)) {
				continue;
			}
			if (isValidSymbol(symbol)) {
				ut64 addr = rz_bin_object_get_vaddr(o, symbol->paddr, symbol->vaddr);
				rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_REF_TYPE_NULL, depth - 1);
			}
		}
	}
	rz_core_task_yield(&core->tasks);
	/* Main */
	if (o && (binmain = rz_bin_object_get_special_symbol(o, RZ_BIN_SPECIAL_SYMBOL_MAIN))) {
		if (binmain->paddr != UT64_MAX) {
			ut64 addr = rz_bin_object_get_vaddr(o, binmain->paddr, binmain->vaddr);
			rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_REF_TYPE_NULL, depth - 1);
		}
	}
	rz_core_task_yield(&core->tasks);
	if ((list = rz_bin_get_entries(core->bin))) {
		rz_list_foreach (list, iter, entry) {
			if (entry->paddr == UT64_MAX) {
				continue;
			}
			ut64 addr = rz_bin_object_get_vaddr(o, entry->paddr, entry->vaddr);
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
	rz_core_task_yield(&core->tasks);

	rz_arch_profile_add_flag_every_io(core->analysis->arch_target->profile, core->flags);
	rz_arch_platform_add_flags_comments(core);

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
				// fallthrough
			case RZ_ANALYSIS_OP_TYPE_CALL:
				if (op->addr != op->jump) { // no selfies
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
		rz_name_filter(str_flagname, -1, true);
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
	RzCore *core = esil->analysis->coreb.core;
	ut8 str[128];
	if (addr != UT64_MAX) {
		esilbreak_last_read = addr;
	}
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, len);
	if (myvalid(core->io, addr) && rz_io_read_at(core->io, addr, (ut8 *)buf, len)) {
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
			rz_io_read_at(core->io, addr, (ut8 *)buf, len);
			break;
		}
		// TODO incorrect
		bool validRef = false;
		if (trace && myvalid(core->io, refptr)) {
			if (ntarget == UT64_MAX || ntarget == refptr) {
				str[0] = 0;
				if (rz_io_read_at(core->io, refptr, str, sizeof(str)) < 1) {
					// eprintf ("Invalid read\n");
					str[0] = 0;
					validRef = false;
				} else {
					rz_analysis_xrefs_set(core->analysis, esil->address, refptr, RZ_ANALYSIS_REF_TYPE_DATA);
					str[sizeof(str) - 1] = 0;
					add_string_ref(core, esil->address, refptr);
					esilbreak_last_data = UT64_MAX;
					validRef = true;
				}
			}
		}

		/** resolve ptr */
		if (ntarget == UT64_MAX || ntarget == addr || (ntarget == UT64_MAX && !validRef)) {
			rz_analysis_xrefs_set(core->analysis, esil->address, addr, RZ_ANALYSIS_REF_TYPE_DATA);
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
	// specific case to handle blx/bx cases in arm through emulation
	//  XXX this thing creates a lot of false positives
	ut64 at = *val;
	if (analysis && analysis->opt.armthumb) {
		if (analysis->cur && analysis->cur->arch && analysis->bits < 33 &&
			strstr(analysis->cur->arch, "arm") && !strcmp(name, "pc") && op) {
			switch (op->type) {
			case RZ_ANALYSIS_OP_TYPE_RCALL: // BLX
			case RZ_ANALYSIS_OP_TYPE_RJMP: // BX
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
	rz_reg_arena_push(core->analysis->reg);

	RzAnalysisEsil *ESIL = core->analysis->esil;
	if (!ESIL) {
		rz_core_analysis_esil_reinit(core);
		ESIL = core->analysis->esil;
		if (!ESIL) {
			eprintf("ESIL not initialized\n");
			goto out_pop_regs;
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
	// this is necessary for the hook to read the id of analop
	ESIL->user = &ctx;
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;

	if (fcn && fcn->reg_save_area) {
		rz_reg_setv(core->analysis->reg, ctx.spname, ctx.initial_sp - fcn->reg_save_area);
	}
	// eprintf ("Analyzing ESIL refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	//  TODO: backup/restore register state before/after analysis
	pcname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	if (!pcname || !*pcname) {
		eprintf("Cannot find program counter register in the current profile.\n");
		goto out_pop_regs;
	}
	esil_analysis_stop = false;
	rz_cons_break_push(cccb, core);

	int arch = -1;
	if (!strcmp(core->analysis->cur->arch, "arm")) {
		switch (core->analysis->bits) {
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

	RZ_NULLABLE const char *sn = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SN);

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
			rz_flag_space_set(core->flags, RZ_FLAGS_FS_SYSCALLS);
			int snv = (arch == RZ_ARCH_THUMB) ? op.val : (int)rz_reg_getv(core->analysis->reg, sn);
			RzSyscallItem *si = rz_syscall_get(core->analysis->syscall, snv, -1);
			if (si) {
				//	eprintf ("0x%08"PFMT64x" SYSCALL %-4d %s\n", cur, snv, si->name);
				rz_flag_set_next(core->flags, sdb_fmt("syscall.%s", si->name), cur, 1);
				rz_syscall_item_free(si);
			} else {
				// todo were doing less filtering up top because we can't match against 80 on all platforms
				//  might get too many of this path now..
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
		// rz_analysis_esil_dumpstack (ESIL);
		// rz_analysis_esil_stack_free (ESIL);
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
					if (dst > 0xffff && op.src[1] && (dst & 0xffff) == (op.src[1]->imm & 0xffff) && myvalid(core->io, dst)) {
						RzFlagItem *f;
						char *str;
						if (CHECKREF(dst) || CHECKREF(cur)) {
							rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_DATA);
							if (cfg_analysis_strings) {
								add_string_ref(core, op.addr, dst);
							}
							if ((f = rz_core_flag_get_by_spaces(core->flags, dst))) {
								rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, f->name);
							} else if ((str = is_string_at(core, dst, NULL))) {
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
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_REF_TYPE_DATA);
					if (cfg_analysis_strings) {
						add_string_ref(core, op.addr, dst);
					}
				}
			}
			dst = esilbreak_last_data;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
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
		case RZ_ANALYSIS_OP_TYPE_RJMP:
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
					RzAnalysisXRefType ref =
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
out_pop_regs:
	// restore register
	rz_reg_arena_pop(core->analysis->reg);
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
						add_string_ref(core, addr, value);
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
		pj = pj_new();
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

static bool add_mmio_flag_cb(void *user, const ut64 addr, const void *v) {
	const char *name = v;
	RzFlag *flags = (RzFlag *)user;
	rz_flag_space_push(flags, RZ_FLAGS_FS_MMIO_REGISTERS);
	rz_flag_set(flags, name, addr, 1);
	rz_flag_space_pop(flags);
	return true;
}

static bool add_mmio_extended_flag_cb(void *user, const ut64 addr, const void *v) {
	const char *name = v;
	RzFlag *flags = (RzFlag *)user;
	rz_flag_space_push(flags, RZ_FLAGS_FS_MMIO_REGISTERS_EXTENDED);
	rz_flag_set(flags, name, addr, 1);
	rz_flag_space_pop(flags);
	return true;
}

/**
 * \brief Adds the IO and extended IO registers from the CPU profiles as flags
 * \param profile reference to RzArchProfile
 * \param flags reference to RzFlag
 */
RZ_API void rz_arch_profile_add_flag_every_io(RzArchProfile *profile, RzFlag *flags) {
	rz_flag_unset_all_in_space(flags, RZ_FLAGS_FS_MMIO_REGISTERS);
	rz_flag_unset_all_in_space(flags, RZ_FLAGS_FS_MMIO_REGISTERS_EXTENDED);
	ht_up_foreach(profile->registers_mmio, add_mmio_flag_cb, flags);
	ht_up_foreach(profile->registers_extended, add_mmio_extended_flag_cb, flags);
}

static bool add_arch_platform_flag_comment_cb(void *user, const ut64 addr, const void *v) {
	if (!v) {
		return false;
	}
	RzArchPlatformItem *item = (RzArchPlatformItem *)v;
	RzCore *core = (RzCore *)user;
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_PLATFORM_PORTS);
	rz_flag_set(core->flags, item->name, addr, 1);
	rz_flag_space_pop(core->flags);
	if (item->comment) {
		rz_core_meta_comment_add(core, item->comment, addr);
	}
	return true;
}

/**
 * \brief Adds the information from the Platform Profiles as flags and comments
 *
 * \param core reference to RzCore
 */
RZ_API bool rz_arch_platform_add_flags_comments(RzCore *core) {
	rz_flag_unset_all_in_space(core->flags, RZ_FLAGS_FS_PLATFORM_PORTS);
	ht_up_foreach(core->analysis->platform_target->platforms, add_arch_platform_flag_comment_cb, core);
	return true;
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
			core->analysis->cb.on_fcn_rename(core->analysis, core, fcn, name);
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

	// rz_core_analysis_undefine (core, core->offset);
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
		RZ_LOG_DEBUG("Unable to analyze function at 0x%08" PFMT64x "\n", addr);
	}
	if (analyze_recursively) {
		fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0); /// XXX wrong in case of nopskip
		if (fcn) {
			RzAnalysisXRef *xref;
			RzListIter *iter;
			RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
			rz_list_foreach (xrefs, iter, xref) {
				if (xref->to == UT64_MAX) {
					// eprintf ("Warning: ignore 0x%08"PFMT64x" call 0x%08"PFMT64x"\n", ref->at, ref->addr);
					continue;
				}
				if (xref->type != RZ_ANALYSIS_REF_TYPE_CODE && xref->type != RZ_ANALYSIS_REF_TYPE_CALL) {
					/* only follow code/call references */
					continue;
				}
				if (!rz_io_is_valid_offset(core->io, xref->to, !core->analysis->opt.noncode)) {
					continue;
				}
				rz_core_analysis_fcn(core, xref->to, fcn->addr, RZ_ANALYSIS_REF_TYPE_CALL, depth);
				/* use recursivity here */
				RzAnalysisFunction *f = rz_analysis_get_function_at(core->analysis, xref->to);
				if (f) {
					RzListIter *iter;
					RzAnalysisXRef *xref1;
					RzList *xrefs1 = rz_analysis_function_get_xrefs_from(f);
					rz_list_foreach (xrefs1, iter, xref1) {
						if (!rz_io_is_valid_offset(core->io, xref1->to, !core->analysis->opt.noncode)) {
							continue;
						}
						if (xref1->type != 'c' && xref1->type != 'C') {
							continue;
						}
						rz_core_analysis_fcn(core, xref1->to, f->addr, RZ_ANALYSIS_REF_TYPE_CALL, depth);
						// recursively follow fcn->refs again and again
					}
					rz_list_free(xrefs1);
				} else {
					f = rz_analysis_get_fcn_in(core->analysis, fcn->addr, 0);
					if (f) {
						/* cut function */
						rz_analysis_function_resize(f, addr - fcn->addr);
						rz_core_analysis_fcn(core, xref->to, fcn->addr,
							RZ_ANALYSIS_REF_TYPE_CALL, depth);
						f = rz_analysis_get_function_at(core->analysis, fcn->addr);
					}
					if (!f) {
						eprintf("af: Cannot find function at 0x%08" PFMT64x "\n", fcn->addr);
						rz_list_free(xrefs);
						return false;
					}
				}
			}
			rz_list_free(xrefs);
			if (core->analysis->opt.vars) {
				rz_core_recover_vars(core, fcn, true);
			}
		}
	}
	if (RZ_STR_ISNOTEMPTY(name) && !rz_core_analysis_function_rename(core, addr, name)) {
		RZ_LOG_ERROR("af: Cannot find function at 0x%08" PFMT64x "\n", addr);
		return false;
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
			RzType *ret_type = rz_type_func_ret(core->analysis->typedb, key);
			char *ret_type_str = NULL;
			if (ret_type) {
				ret_type_str = rz_type_as_string(core->analysis->typedb, ret_type);
			}
			int nargs = rz_type_func_args_count(core->analysis->typedb, key);
			pj_o(j);
			pj_ks(j, "name", rz_str_get_null(key));
			if (ret_type_str) {
				pj_ks(j, "return", ret_type_str);
			}
			pj_k(j, "args");
			pj_a(j);
			if (nargs) {
				RzList *list = rz_core_get_func_args(core, fcn_name);
				rz_list_foreach (list, iter, arg) {
					char *type = rz_type_as_string(core->analysis->typedb, arg->orig_c_type);
					pj_o(j);
					pj_ks(j, "name", arg->name);
					pj_ks(j, "type", type);
					pj_end(j);
					free(type);
				}
				rz_list_free(list);
			}
			pj_end(j);
			pj_ki(j, "count", nargs);
			pj_end(j);
			free(ret_type_str);
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
				char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
				pj_ks(j, "type", vartype);
				pj_end(j);
				free(vartype);
			}
			rz_list_foreach (cache.bvars, iter, var) {
				if (var->delta <= 0) {
					continue;
				}
				nargs++;
				pj_o(j);
				pj_ks(j, "name", var->name);
				char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
				pj_ks(j, "type", vartype);
				pj_end(j);
				free(vartype);
			}
			rz_list_foreach (cache.svars, iter, var) {
				if (!var->isarg) {
					continue;
				}
				nargs++;
				pj_o(j);
				pj_ks(j, "name", var->name);
				char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
				pj_ks(j, "type", vartype);
				pj_end(j);
				free(vartype);
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

static RzAnalysisBlock *find_block_at_xref_addr(RzCore *core, ut64 addr) {
	RzList *blocks = rz_analysis_get_blocks_in(core->analysis, addr);
	if (!blocks) {
		return NULL;
	}
	RzAnalysisBlock *block = NULL;
	RzListIter *bit;
	RzAnalysisBlock *block_cur;
	rz_list_foreach (blocks, bit, block_cur) {
		if (rz_analysis_block_op_starts_at(block_cur, addr)) {
			block = block_cur;
			break;
		}
	}
	if (block) {
		rz_analysis_block_ref(block);
	}
	rz_list_free(blocks);
	return block;
}

static void relocation_function_process_noreturn(RzCore *core, RzAnalysisBlock *b, SetU *todo, ut64 opsize, ut64 reladdr, ut64 addr) {
	rz_analysis_noreturn_add(core->analysis, NULL, reladdr);

	// Add all functions that might have become noreturn by this to the todo list to reanalyze them later.
	// This must be done before chopping because b might get freed.
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (b->fcns, it, fcn) {
		set_u_add(todo, (ut64)(size_t)fcn);
	}

	// Chop the block
	rz_analysis_block_chop_noreturn(b, addr + opsize);
}

static void relocation_noreturn_process(RzCore *core, RzList *noretl, SetU *todo, RzAnalysisBlock *b, RzBinReloc *rel, ut64 opsize, ut64 addr) {
	RzListIter *iter3;
	char *noret;
	if (rel->import) {
		rz_list_foreach (noretl, iter3, noret) {
			if (!strcmp(rel->import->name, noret)) {
				relocation_function_process_noreturn(core, b, todo, opsize, rel->vaddr, addr);
			}
		}
	} else if (rel->symbol) {
		rz_list_foreach (noretl, iter3, noret) {
			if (!strcmp(rel->symbol->name, noret)) {
				relocation_function_process_noreturn(core, b, todo, opsize, rel->symbol->vaddr, addr);
			}
		}
	}
}

#define CALL_BUF_SIZE 32

struct core_noretl {
	RzCore *core;
	RzList *noretl;
	SetU *todo;
};

static bool process_reference_noreturn_cb(void *u, const ut64 k, const void *v) {
	RzCore *core = ((struct core_noretl *)u)->core;
	RzList *noretl = ((struct core_noretl *)u)->noretl;
	SetU *todo = ((struct core_noretl *)u)->todo;
	RzAnalysisXRef *xref = (RzAnalysisXRef *)v;
	if (xref->type == RZ_ANALYSIS_REF_TYPE_CALL || xref->type == RZ_ANALYSIS_REF_TYPE_CODE) {
		// At first we check if there are any relocations that override the call address
		// Note, that the relocation overrides only the part of the instruction
		ut64 addr = k;
		ut8 buf[CALL_BUF_SIZE] = { 0 };
		RzAnalysisOp op = { 0 };
		if (core->analysis->iob.read_at(core->analysis->iob.io, addr, buf, CALL_BUF_SIZE)) {
			if (rz_analysis_op(core->analysis, &op, addr, buf, core->blocksize, 0)) {
				RzBinReloc *rel = rz_core_getreloc(core, addr, op.size);
				if (rel) {
					// Find the block that has an instruction at exactly the reference addr
					RzAnalysisBlock *block = find_block_at_xref_addr(core, addr);
					if (!block) {
						rz_analysis_op_fini(&op);
						return true;
					}
					relocation_noreturn_process(core, noretl, todo, block, rel, op.size, addr);
				}
			}
			rz_analysis_op_fini(&op);
		} else {
			RZ_LOG_INFO("analysis: Fail to load %d bytes of data at 0x%08" PFMT64x "\n", CALL_BUF_SIZE, addr);
		}
	}
	return true;
}

static bool process_refs_cb(void *u, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach(ht, process_reference_noreturn_cb, u);
	return true;
}

static bool reanalyze_fcns_cb(void *u, const ut64 k, const void *v) {
	RzCore *core = u;
	RzAnalysisFunction *fcn = (RzAnalysisFunction *)(size_t)k;
	if (fcn->addr && analyze_noreturn_function(core, fcn)) {
		fcn->is_noreturn = true;
		rz_analysis_noreturn_add(core->analysis, NULL, fcn->addr);
	}
	return true;
}

RZ_API void rz_core_analysis_propagate_noreturn_relocs(RzCore *core, ut64 addr) {
	// Processing every reference calls rz_analysis_op() which sometimes changes the
	// state of `asm.bits` variable, thus we save it to restore after the processing
	// is finished.
	int bits1 = core->analysis->bits;
	int bits2 = core->rasm->bits;
	// find known noreturn functions to propagate
	RzList *noretl = rz_analysis_noreturn_functions(core->analysis);
	// List of the potentially noreturn functions
	SetU *todo = set_u_new();
	struct core_noretl u = { core, noretl, todo };
	ht_up_foreach(core->analysis->ht_xrefs_to, process_refs_cb, &u);
	rz_list_free(noretl);
	core->analysis->bits = bits1;
	core->rasm->bits = bits2;
	// For every function in todo list analyze if it's potentially become noreturn
	ht_up_foreach(todo, reanalyze_fcns_cb, core);
	set_u_free(todo);
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

	// At first we propagate all noreturn functions that are imports or symbols
	// via the relocations
	rz_core_analysis_propagate_noreturn_relocs(core, addr);

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
		RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, noret_addr);
		RzAnalysisXRef *xref;
		rz_list_foreach (xrefs, iter, xref) {
			RzAnalysisOp *xrefop = rz_core_op_analysis(core, xref->from, RZ_ANALYSIS_OP_MASK_ALL);
			if (!xrefop) {
				eprintf("Cannot analyze opcode at 0x%08" PFMT64x "\n", xref->from);
				continue;
			}
			ut64 call_addr = xref->from;
			ut64 chop_addr = call_addr + xrefop->size;
			rz_analysis_op_free(xrefop);
			if (xref->type != RZ_ANALYSIS_REF_TYPE_CALL) {
				continue;
			}

			// Find the block that has an instruction at exactly the xref addr
			RzAnalysisBlock *block = find_block_at_xref_addr(core, call_addr);
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
RZ_API bool rz_core_analysis_everything(RzCore *core, bool experimental, char *dh_orig) {
	bool didAap = false;
	ut64 curseek = core->offset;
	bool cfg_debug = rz_config_get_b(core->config, "cfg.debug");
	bool plugin_supports_esil = core->analysis->cur->esil;
	const char *oldstr = NULL;
	if (rz_str_startswith(rz_config_get(core->config, "bin.lang"), "go")) {
		oldstr = rz_core_notify_begin(core, "Find function and symbol names from golang binaries (aang)");
		rz_core_notify_done(core, oldstr);
		rz_core_analysis_autoname_all_golang_fcns(core);
		oldstr = rz_core_notify_begin(core, "Analyze all flags starting with sym.go. (aF @@f:sym.go.*)");
		rz_core_cmd0(core, "aF @@f:sym.go.*");
		rz_core_notify_done(core, oldstr);
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

	oldstr = rz_core_notify_begin(core, "Analyze function calls (aac)");
	(void)rz_cmd_analysis_calls(core, "", false, false); // "aac"
	rz_core_seek(core, curseek, true);
	rz_core_notify_done(core, oldstr);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}

	if (is_unknown_file(core)) {
		oldstr = rz_core_notify_begin(core, "find and analyze function preludes (aap)");
		(void)rz_core_search_preludes(core, false); // "aap"
		didAap = true;
		rz_core_notify_done(core, oldstr);
		rz_core_task_yield(&core->tasks);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}

	oldstr = rz_core_notify_begin(core, "Analyze len bytes of instructions for references (aar)");
	(void)rz_core_analysis_refs(core, ""); // "aar"
	rz_core_notify_done(core, oldstr);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}
	if (is_apple_target(core)) {
		oldstr = rz_core_notify_begin(core, "Check for objc references");
		rz_core_notify_done(core, oldstr);
		cmd_analysis_objc(core, true);
	}
	rz_core_task_yield(&core->tasks);
	oldstr = rz_core_notify_begin(core, "Check for classes");
	rz_analysis_class_recover_all(core->analysis);
	rz_core_notify_done(core, oldstr);
	rz_core_task_yield(&core->tasks);
	rz_config_set_i(core->config, "analysis.calls", c);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}
	if (!rz_str_startswith(rz_config_get(core->config, "asm.arch"), "x86")) {
		rz_core_analysis_value_pointers(core, RZ_OUTPUT_MODE_STANDARD);
		rz_core_task_yield(&core->tasks);
		bool pcache = rz_config_get_b(core->config, "io.pcache");
		rz_config_set_b(core->config, "io.pcache", false);
		oldstr = rz_core_notify_begin(core, "Emulate functions to find computed references (aaef)");
		if (plugin_supports_esil) {
			rz_core_analysis_esil_references_all_functions(core);
		}
		rz_core_notify_done(core, oldstr);
		rz_core_task_yield(&core->tasks);
		rz_config_set_b(core->config, "io.pcache", pcache);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}
	if (rz_config_get_i(core->config, "analysis.autoname")) {
		oldstr = rz_core_notify_begin(core, "Speculatively constructing a function name "
						    "for fcn.* and sym.func.* functions (aan)");
		rz_core_analysis_autoname_all_fcns(core);
		rz_core_notify_done(core, oldstr);
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
			// extract only reg based var here
			rz_core_recover_vars(core, fcni, true);
			rz_list_free(list);
		}
		rz_core_task_yield(&core->tasks);
	}
	if (!sdb_isempty(core->analysis->sdb_zigns)) {
		oldstr = rz_core_notify_begin(core, "Check for zignature from zigns folder (z/)");
		rz_core_cmd0(core, "z/");
		rz_core_notify_done(core, oldstr);
		rz_core_task_yield(&core->tasks);
	}
	if (plugin_supports_esil) {
		oldstr = rz_core_notify_begin(core, "Type matching analysis for all functions (aaft)");
		rz_core_analysis_types_propagation(core);
		rz_core_notify_done(core, oldstr);
		rz_core_task_yield(&core->tasks);
	}

	oldstr = rz_core_notify_begin(core, "Propagate noreturn information");
	rz_core_analysis_propagate_noreturn(core, UT64_MAX);
	rz_core_notify_done(core, oldstr);
	rz_core_task_yield(&core->tasks);

	// Apply DWARF function information
	Sdb *dwarf_sdb = sdb_ns(core->analysis->sdb, "dwarf", 0);
	if (dwarf_sdb) {
		oldstr = rz_core_notify_begin(core, "Integrate dwarf function information.");
		rz_analysis_dwarf_integrate_functions(core->analysis, core->flags, dwarf_sdb);
		rz_core_notify_done(core, oldstr);
	}

	oldstr = rz_core_notify_begin(core, "Use -AA or aaaa to perform additional experimental analysis.");
	rz_core_notify_done(core, oldstr);

	if (experimental) {
		if (!didAap) {
			oldstr = rz_core_notify_begin(core, "Finding function preludes");
			(void)rz_core_search_preludes(core, false); // "aap"
			rz_core_notify_done(core, oldstr);
			rz_core_task_yield(&core->tasks);
		}

		oldstr = rz_core_notify_begin(core, "Enable constraint types analysis for variables");
		rz_config_set(core->config, "analysis.types.constraint", "true");
		rz_core_notify_done(core, oldstr);
	}
	rz_core_seek_undo(core);
	if (dh_orig) {
		rz_config_set(core->config, "dbg.backend", dh_orig);
		rz_core_task_yield(&core->tasks);
	}
	if (!is_unknown_file(core)) {
		rz_analysis_add_device_peripheral_map(core->bin->cur->o, core->analysis);
	}

	if (rz_config_get_b(core->config, "analysis.apply.signature")) {
		int n_applied = 0;
		char message[100];
		rz_core_notify_begin(core, "Applying signatures from sigdb");
		rz_core_analysis_sigdb_apply(core, &n_applied, NULL);
		rz_strf(message, "Applied %d FLIRT signatures via sigdb", n_applied);
		rz_core_notify_done(core, message);
	}

	return true;
}

static int core_sigdb_sorter(const RzSigDBEntry *a, const RzSigDBEntry *b) {
	return strcmp(a->short_path, b->short_path);
}

static RzList *core_load_all_signatures_from_sigdb(RzCore *core, bool with_details) {
	RzList *sysdb = NULL, *userdb = NULL;
	char *system_sigdb = rz_path_system(RZ_SIGDB);
	if (RZ_STR_ISNOTEMPTY(system_sigdb) && rz_file_is_directory(system_sigdb)) {
		sysdb = rz_sign_sigdb_load_database(system_sigdb, with_details);
	}
	free(system_sigdb);

	const char *user_sigdb = rz_config_get(core->config, "flirt.sigdb.path");
	if (RZ_STR_ISEMPTY(user_sigdb)) {
		return sysdb;
	} else if (!rz_file_is_directory(user_sigdb)) {
		RZ_LOG_ERROR("Invalid signature database path (flirt.sigdb.path)\n");
		return sysdb;
	} else {
		userdb = rz_sign_sigdb_load_database(user_sigdb, with_details);
	}
	if (sysdb && userdb) {
		rz_list_join(userdb, sysdb);
		rz_list_free(sysdb);
		rz_list_sort(userdb, (RzListComparator)core_sigdb_sorter);
		sysdb = NULL;
	}
	return userdb ? userdb : sysdb;
}

/**
 * \brief Outputs the list of signatures found in the flirt.sigdb.path
 *
 * \param core The RzCore instance
 */
RZ_API void rz_core_analysis_sigdb_print(RzCore *core) {
	RzList *sigdb = core_load_all_signatures_from_sigdb(core, true);
	if (!sigdb) {
		return;
	}

	RzTable *table = rz_table_new();
	if (!table) {
		rz_list_free(sigdb);
		rz_warn_if_reached();
		return;
	}
	rz_table_set_columnsf(table, "ssnsns", "bin", "arch", "bits", "name", "modules", "details");

	RzSigDBEntry *sig = NULL;
	RzListIter *iter = NULL;
	ut64 bits, nmods;

	rz_list_foreach (sigdb, iter, sig) {
		bits = sig->arch_bits;
		nmods = sig->n_modules;
		rz_table_add_rowf(table, "ssnsns", sig->bin_name, sig->arch_name, bits, sig->base_name, nmods, sig->details);
	}

	char *output = rz_table_tostring(table);
	if (output) {
		rz_cons_printf("%s", output);
		free(output);
	}
	rz_list_free(sigdb);
	rz_table_free(table);
}

/**
 * \brief tries to apply the signatures in the flirt.sigdb.path
 *
 * \param core       The RzCore instance
 * \param n_applied  Returns the number of successfully applied signatures
 * \param filter     Filters the signatures found following the user input
 * \return fail when an error occurs otherwise true
 */
RZ_API bool rz_core_analysis_sigdb_apply(RzCore *core, int *n_applied, const char *filter) {
	rz_return_val_if_fail(core, false);
	const char *bin = NULL;
	const char *arch = NULL;
	ut64 bits = 32;
	RzSigDBEntry *sig = NULL;
	RzList *sigdb = NULL;
	RzListIter *iter = NULL;
	RzBinObject *obj = NULL;

	int n_flags_new, n_flags_old;
	ut8 arch_id = RZ_FLIRT_SIG_ARCH_ANY;

	if (RZ_STR_ISEMPTY(filter)) {
		obj = core->bin ? rz_bin_cur_object(core->bin) : NULL;
		if ((!obj || !obj->plugin)) {
			RZ_LOG_INFO("Cannot apply signatures due unknown bin type\n");
			return false;
		} else if (!strcmp(obj->plugin->name, "elf64")) {
			bin = "elf";
		} else if (!strcmp(obj->plugin->name, "pe64")) {
			bin = "pe";
		} else {
			bin = obj->plugin->name;
		}
	}

	arch = rz_config_get(core->config, "asm.arch");
	bits = rz_config_get_i(core->config, "asm.bits");
	arch_id = rz_core_flirt_arch_from_name(arch);
	if (RZ_STR_ISEMPTY(filter) && arch_id >= RZ_FLIRT_SIG_ARCH_ANY) {
		RZ_LOG_INFO("Cannot apply signatures due unknown arch (%s)\n", arch);
		return false;
	}

	sigdb = core_load_all_signatures_from_sigdb(core, false);
	if (!sigdb) {
		return false;
	}

	n_flags_old = rz_flag_count(core->flags, "flirt");
	rz_list_foreach (sigdb, iter, sig) {
		if (RZ_STR_ISEMPTY(filter)) {
			// apply signatures automatically based on bin, arch and bits
			if (strcmp(bin, sig->bin_name) || strcmp(arch, sig->arch_name) || bits != sig->arch_bits) {
				continue;
			} else if (strstr(sig->base_name, "c++") &&
				obj->lang != RZ_BIN_LANGUAGE_CXX &&
				obj->lang != RZ_BIN_LANGUAGE_RUST) {
				// C++ libs can create many false positives, especially on C binaries.
				// So their usage is limited to C++ and RUST lang
				continue;
			}
			RZ_LOG_INFO("Applying %s signature file\n", sig->short_path);
		} else {
			// apply signatures based on filter value
			if (!strstr(sig->short_path, filter)) {
				continue;
			}
			rz_cons_printf("Applying %s/%s/%u/%s signature file\n",
				sig->bin_name, sig->arch_name, sig->arch_bits, sig->base_name);
		}
		rz_sign_flirt_apply(core->analysis, sig->file_path, arch_id);
	}
	rz_list_free(sigdb);
	n_flags_new = rz_flag_count(core->flags, "flirt");

	if (n_applied) {
		*n_applied = n_flags_new - n_flags_old;
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
	char *fmt = rz_type_as_format(analysis->typedb, var->type);
	RzRegItem *i;
	if (!fmt) {
		return rz_strbuf_drain(sb);
	}
	bool usePxr = rz_type_is_strictly_atomic(core->analysis->typedb, var->type) && rz_type_atomic_str_eq(core->analysis->typedb, var->type, "int");
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
			r = rz_core_cmd_strf(core, "pxr $w @ %s%c0x%x", analysis->reg->name[RZ_REG_NAME_BP], sign, udelta);
		} else {
			r = rz_core_cmd_strf(core, "pf %s @ %s%c0x%x", fmt, analysis->reg->name[RZ_REG_NAME_BP], sign, udelta);
		}
		rz_strbuf_append(sb, r);
		free(r);
	} break;
	case RZ_ANALYSIS_VAR_KIND_SPV: {
		ut32 udelta = RZ_ABS(var->delta + var->fcn->maxstack);
		char *r;
		if (usePxr) {
			r = rz_core_cmd_strf(core, "pxr $w @ %s+0x%x", analysis->reg->name[RZ_REG_NAME_SP], udelta);
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

RZ_IPI bool rz_analysis_var_global_list_show(RzAnalysis *analysis, RzCmdStateOutput *state, RZ_NULLABLE const char *name) {
	rz_return_val_if_fail(analysis && state, false);
	RzList *global_vars = NULL;
	RzAnalysisVarGlobal *glob = NULL;
	if (name) {
		global_vars = rz_list_new();
		if (!global_vars) {
			return false;
		}
		glob = rz_analysis_var_global_get_byname(analysis, name);
		if (!glob) {
			RZ_LOG_ERROR("Global variable '%s' does not exist!\n", name);
			rz_list_free(global_vars);
			return false;
		}
		rz_list_append(global_vars, glob);
	} else {
		global_vars = rz_analysis_var_global_get_all(analysis);
	}

	RzListIter *it = NULL;
	char *var_type = NULL;
	bool json = state->mode == RZ_OUTPUT_MODE_JSON;
	PJ *pj = json ? state->d.pj : NULL;

	rz_cmd_state_output_array_start(state);
	if (!global_vars) {
		rz_cmd_state_output_array_end(state);
		return false;
	}
	rz_list_foreach (global_vars, it, glob) {
		var_type = rz_type_as_string(analysis->typedb, glob->type);
		if (!var_type) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("global %s %s @ 0x%" PFMT64x "\n",
				var_type, glob->name, glob->addr);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", glob->name);
			pj_ks(pj, "type", var_type);
			char addr[32];
			rz_strf(addr, "0x%" PFMT64x, glob->addr);
			pj_ks(pj, "addr", addr);
			pj_end(pj);
			break;
		default:
			break;
		}
		free(var_type);
	}
	rz_cmd_state_output_array_end(state);
	rz_list_free(global_vars);
	return true;
}

static int check_rom_exists(const void *value, const void *data) {
	const char *name = (const char *)value;
	const RzBinSection *sections = (const RzBinSection *)data;
	return strcmp(name, sections->name);
}

/**
 * \brief Maps the device peripherals as sections
 *
 * Gets the ROM_ADDRESS and ROM_SIZE from the corresponding CPU Profile
 * and adds it as a section (RzBinSection) named ".rom" which will appear
 * when you run `iS`.
 *
 * \param o reference to RzBinObject
 * \param analysis reference to RzAnalysis
 */
RZ_API bool rz_analysis_add_device_peripheral_map(RzBinObject *o, RzAnalysis *analysis) {
	rz_return_val_if_fail(o && analysis, false);
	if (!o || !analysis) {
		return false;
	}
	ut64 rom_size = analysis->arch_target->profile->rom_size;
	ut64 rom_address = analysis->arch_target->profile->rom_address;
	if (rom_address == 0 || rom_size == 0) {
		return false;
	}
	if (!o->sections) {
		return false;
	}
	if (rz_list_find(o->sections, ".rom", check_rom_exists)) {
		return false;
	}
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (!s) {
		return false;
	}
	s->name = strdup(".rom");
	s->vaddr = rom_address;
	s->vsize = rom_size;
	s->size = rom_size;
	s->paddr = rom_address;
	s->perm = RZ_PERM_RX;
	rz_list_append(o->sections, s);
	return true;
}

RZ_IPI bool rz_core_analysis_types_propagation(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	ut64 seek;
	if (rz_config_get_b(core->config, "cfg.debug")) {
		eprintf("TOFIX: aaft can't run in debugger mode.\n");
		return false;
	}
	RzConfigHold *hold = rz_config_hold_new(core->config);
	rz_config_hold_i(hold, "io.va", "io.pcache.write", NULL);
	bool io_cache = rz_config_get_b(core->config, "io.pcache.write");
	if (!io_cache) {
		// XXX. we shouldnt need this, but it breaks 'rizin -c aaa -w ls'
		rz_config_set_b(core->config, "io.pcache.write", true);
	}
	const bool delete_regs = !rz_flag_space_count(core->flags, RZ_FLAGS_FS_REGISTERS);
	seek = core->offset;
	rz_reg_arena_push(core->analysis->reg);
	rz_reg_arena_zero(core->analysis->reg, RZ_REG_TYPE_ANY);
	rz_core_analysis_esil_init(core);
	rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	ut8 *saved_arena = rz_reg_arena_peek(core->analysis->reg);

	// loop count of rz_core_analysis_type_match
	// TODO : figure out the reason to hold a `LOOP COUNT` in type_match
	// HtUU <addr->loop_count>
	HtUU *loop_table = ht_uu_new0();

	// Iterating Reverse so that we get function in top-bottom call order
	rz_list_foreach_prev(core->analysis->fcns, it, fcn) {
		int ret = rz_core_seek(core, fcn->addr, true);
		if (!ret) {
			continue;
		}
		rz_reg_arena_poke(core->analysis->reg, saved_arena);
		rz_analysis_esil_set_pc(core->analysis->esil, fcn->addr);
		rz_core_analysis_type_match(core, fcn, loop_table);
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
	rz_core_analysis_esil_init_mem_del(core, NULL, UT64_MAX, UT32_MAX);
	rz_config_hold_restore(hold);
	rz_config_hold_free(hold);
	free(saved_arena);
	ht_uu_free(loop_table);
	return true;
}

RZ_IPI bool rz_core_analysis_function_set_signature(RzCore *core, RzAnalysisFunction *fcn, const char *newsig) {
	bool res = false;
	char *fcnname = NULL;
	char *fcnstr = rz_str_newf("%s;", newsig);
	char *fcnstr_copy = strdup(fcnstr);
	char *fcnname_aux = strtok(fcnstr_copy, "(");
	if (!fcnname_aux) {
		goto err;
	}
	rz_str_trim_tail(fcnname_aux);
	const char *ls = rz_str_lchr(fcnname_aux, ' ');
	fcnname = strdup(ls ? ls : fcnname_aux);
	if (!fcnname) {
		goto err;
	}
	// TODO: move this into rz_analysis_function_set_type_str()
	if (strcmp(fcn->name, fcnname)) {
		(void)rz_core_analysis_function_rename(core, fcn->addr, fcnname);
		fcn = rz_analysis_get_fcn_in(core->analysis, fcn->addr, -1);
	}
	rz_analysis_function_set_type_str(core->analysis, fcn, fcnstr);
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
			RZ_LOG_DEBUG("Warning: aav: false positive in 0x%08" PFMT64x "\n", from);
		}
	}
	if (!vinfun) {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, from, -1);
		if (fcn) {
			return;
		}
	}
	if (pretend) {
		rz_cons_printf("ax 0x%" PFMT64x " @ 0x%" PFMT64x "\n", to, from);
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
	const char *oldstr = rz_core_notify_begin(core, "Finding xrefs in noncode section with analysis.in=io.maps");
	rz_core_notify_done(core, oldstr);

	int vsize = 4; // 32bit dword
	if (core->rasm->bits == 64) {
		vsize = 8;
	}

	// body
	oldstr = rz_core_notify_begin(core, "Analyze value pointers (aav)");
	rz_core_notify_done(core, oldstr);
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
			oldstr = rz_core_notify_begin(core, sdb_fmt("from 0x%" PFMT64x " to 0x%" PFMT64x " (aav)", map->itv.addr, rz_itv_end(map->itv)));
			rz_core_notify_done(core, oldstr);
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
			// TODO: Reduce multiple hits for same addr
			from = rz_itv_begin(map2->itv);
			to = rz_itv_end(map2->itv);
			oldstr = rz_core_notify_begin(core, sdb_fmt("Value from 0x%08" PFMT64x " to 0x%08" PFMT64x " (aav)", from, to));
			if ((to - from) > MAX_SCAN_SIZE) {
				eprintf("Warning: Skipping large region\n");
				continue;
			}
			rz_core_notify_done(core, oldstr);
			rz_list_foreach (list, iter, map) {
				ut64 begin = map->itv.addr;
				ut64 end = rz_itv_end(map->itv);
				if (rz_cons_is_breaked()) {
					break;
				}
				if (end - begin > UT32_MAX) {
					oldstr = rz_core_notify_begin(core, "Skipping huge range");
					rz_core_notify_done(core, oldstr);
					continue;
				}
				oldstr = rz_core_notify_begin(core, sdb_fmt("0x%08" PFMT64x "-0x%08" PFMT64x " in 0x%" PFMT64x "-0x%" PFMT64x " (aav)", from, to, begin, end));
				rz_core_notify_done(core, oldstr);
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

RZ_API void rz_core_analysis_type_init(RzCore *core) {
	rz_return_if_fail(core && core->analysis);
	int bits = core->rasm->bits;
	const char *analysis_arch = rz_config_get(core->config, "analysis.arch");
	const char *os = rz_config_get(core->config, "asm.os");

	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	rz_type_db_init(core->analysis->typedb, types_dir, analysis_arch, bits, os);
	free(types_dir);
}

static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	sdb_merge(s, db);
	sdb_close(db);
	sdb_free(db);
}

RZ_API void rz_core_analysis_cc_init(RzCore *core) {
	const char *analysis_arch = rz_config_get(core->config, "analysis.arch");
	Sdb *cc = core->analysis->sdb_cc;
	if (!strcmp(analysis_arch, "null")) {
		sdb_reset(cc);
		RZ_FREE(cc->path);
		return;
	}

	int bits = core->analysis->bits;
	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	char *home_types_dir = rz_path_home_prefix(RZ_SDB_TYPES);
	char buf[40];
	char *dbpath = rz_file_path_join(types_dir, rz_strf(buf, "cc-%s-%d.sdb", analysis_arch, bits));
	char *dbhomepath = rz_file_path_join(home_types_dir, rz_strf(buf, "cc-%s-%d.sdb", analysis_arch, bits));
	free(types_dir);
	free(home_types_dir);

	// Avoid sdb reloading
	if (cc->path && (!strcmp(cc->path, dbpath) || !strcmp(cc->path, dbhomepath))) {
		free(dbpath);
		free(dbhomepath);
		return;
	}
	sdb_reset(cc);
	RZ_FREE(cc->path);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(cc, dbpath);
		cc->path = strdup(dbpath);
	}
	if (rz_file_exists(dbhomepath)) {
		sdb_concat_by_path(cc, dbhomepath);
		cc->path = strdup(dbhomepath);
	}
	// same as "tcc `arcc`"
	char *s = rz_reg_profile_to_cc(core->analysis->reg);
	if (s) {
		if (!rz_analysis_cc_set(core->analysis, s)) {
			eprintf("Warning: Invalid CC from reg profile.\n");
		}
		free(s);
	} else {
		eprintf("Warning: Cannot derive CC from reg profile.\n");
	}
	if (sdb_isempty(core->analysis->sdb_cc)) {
		eprintf("Warning: Missing calling conventions for '%s'. Deriving it from the regprofile.\n", analysis_arch);
	}
	free(dbpath);
	free(dbhomepath);
}
