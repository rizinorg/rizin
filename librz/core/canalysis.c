// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_list.h>
#include <rz_flag.h>
#include <rz_core.h>
#include <rz_bin.h>
#include <rz_util/ht_uu.h>
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

RZ_IPI int bb_cmpaddr(const void *_a, const void *_b, void *user) {
	const RzAnalysisBlock *a = _a, *b = _b;
	return (a->addr > b->addr) - (a->addr < b->addr);
}

RZ_IPI int fcn_cmpaddr(const void *_a, const void *_b, void *user) {
	const RzAnalysisFunction *a = _a, *b = _b;
	return (a->addr > b->addr) - (a->addr < b->addr);
}

static char *getFunctionName(RzCore *core, ut64 addr) {
	RzBinFile *bf = rz_bin_cur(core->bin);

	RzBinSymbol *sym = bf && bf->o ? rz_bin_object_find_method_by_vaddr(bf->o, addr) : NULL;
	if (sym && sym->classname && sym->name) {
		return rz_str_newf("method.%s.%s", sym->classname, sym->name);
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

static bool find_string_at(RzCore *core, RzBinObject *bobj, ut64 pointer, char **string, size_t *length, RzStrEnc *encoding) {
	RzBin *bin = core->bin;
	ut8 buffer[512] = { 0 };
	bool ret = false;
	RzDetectedString *detected = NULL;

	RzList *strings = rz_list_newf((RzListFree)rz_detected_string_free);
	if (!strings) {
		return false;
	}

	RzStrEnc strenc = bin->str_search_cfg.string_encoding;
	RzUtilStrScanOptions scan_opt = {
		.buf_size = sizeof(buffer),
		.max_uni_blocks = bin->str_search_cfg.max_uni_blocks,
		.min_str_length = bin->str_search_cfg.min_length,
		.prefer_big_endian = core->analysis->big_endian,
		.check_ascii_freq = bin->str_search_cfg.check_ascii_freq,
	};

	rz_io_pread_at(core->io, pointer, buffer, sizeof(buffer));
	if (rz_scan_strings_raw(buffer, strings, &scan_opt, 0, sizeof(buffer), strenc) < 1 ||
		!(detected = rz_list_first(strings)) ||
		// ignore any address that is not address 0
		// because we only want strings starting at 0
		detected->addr) {
		goto end;
	}

	if (string) {
		*string = detected->string;
		detected->string = NULL;
	}
	if (length) {
		*length = detected->size;
	}
	if (encoding) {
		*encoding = detected->type;
	}
	ret = true;

end:
	rz_list_free(strings);
	return ret;
}

RZ_IPI bool rz_core_get_string_at(RzCore *core, ut64 address, char **string, size_t *length, RzStrEnc *encoding, bool can_search) {
	ut8 tmp64[32] = { 0 };
	ut64 pointer = UT64_MAX, paddress = 0;
	RzIOMap *map = NULL;
	RzBinString *bstr = NULL;
	RzBinObject *bobj = rz_bin_cur_object(core->bin);
	if (!bobj) {
		return false;
	}

	map = rz_io_map_get(core->io, address);
	if (map && (map->perm & RZ_PERM_RX) != RZ_PERM_RX && (map->perm & RZ_PERM_X)) {
		return false;
	}

	if (core->io->va && (paddress = rz_io_v2p(core->io, address)) != UT64_MAX) {
		address = paddress;
	}

	if (rz_io_read_at(core->io, address, tmp64, sizeof(tmp64))) {
		// checks if is a pointer to a string structure
		pointer = rz_read_ble(tmp64, core->analysis->big_endian, core->analysis->bits);
	}

	bstr = rz_bin_object_get_string_at(bobj, address, false);
	if (!bstr) {
		if (!pointer) {
			// maybe is a cstring
			// usually a cstring has a header set to 0, then the length and then the actual pointer to the string.
			ut32 n_bytes = core->analysis->bits / 8;
			ut64 clength = rz_read_ble(&tmp64[n_bytes], core->analysis->big_endian, core->analysis->bits);
			if (clength < 1000) {
				pointer = rz_read_ble(tmp64, core->analysis->big_endian, core->analysis->bits);
			}
		}

		if (core->io->va && (paddress = rz_io_v2p(core->io, pointer)) != UT64_MAX) {
			pointer = paddress;
		}

		bstr = rz_bin_object_get_string_at(bobj, pointer, false);
		if (!bstr) {
			return can_search && (find_string_at(core, bobj, address, string, length, encoding) || find_string_at(core, bobj, pointer, string, length, encoding));
		}
	}

	if (string) {
		*string = rz_str_ndup(bstr->string, bstr->length);
	}
	if (length) {
		*length = bstr->size;
	}
	if (encoding) {
		*encoding = bstr->type;
	}
	return true;
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

	RzAnalysisBlock *b;
	void **iter;
	rz_pvector_foreach (fcn->bbs, iter) {
		b = (RzAnalysisBlock *)*iter;
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
	RzAnalysisBlock *b;
	void **iter;
	rz_pvector_foreach (fcn->bbs, iter) {
		b = (RzAnalysisBlock *)*iter;
		if (b->jump == UT64_MAX) {
			ut64 retaddr = rz_analysis_block_get_op_addr(b, b->ninstr - 1);
			if (retaddr == UT64_MAX) {
				break;
			}

			rz_cons_printf("0x%08" PFMT64x "\n", retaddr);
		}
	}
}

static int casecmp(const void *_a, const void *_b, void *user) {
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
	int outputs = (bb->jump != UT64_MAX) + (bb->fail != UT64_MAX);
	int inputs = 0;

	void **iter;
	RzAnalysisBlock *bb2;
	rz_pvector_foreach (fcn->bbs, iter) {
		bb2 = (RzAnalysisBlock *)*iter;
		inputs += (bb2->jump == bb->addr) + (bb2->fail == bb->addr);
	}
	if (bb->switch_op) {
		RzList *unique_cases = rz_list_uniq(bb->switch_op->cases, casecmp, NULL);
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
			RzList *unique_cases = rz_list_uniq(bb->switch_op->cases, casecmp, NULL);
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

static int bb_cmp(const void *a, const void *b, void *user) {
	const RzAnalysisBlock *ba = a;
	const RzAnalysisBlock *bb = b;
	return ba->addr - bb->addr;
}

RZ_IPI void rz_core_analysis_bbs_info_print(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	rz_return_if_fail(core && fcn && state);
	void **iter;
	RzAnalysisBlock *bb;
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "xdxx", "addr", "size", "jump", "fail");
	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_printf("fs blocks\n");
	}

	rz_pvector_sort(fcn->bbs, bb_cmp, NULL);
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
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
	bool is_va = core->io->va;
	RzBinObject *bobj = rz_bin_cur_object(core->bin);
	if (!bobj) {
		return;
	}
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_DATA &&
			rz_bin_object_get_string_at(bobj, xref->to, is_va)) {
			rz_analysis_xrefs_set(core->analysis, xref->from, xref->to, RZ_ANALYSIS_XREF_TYPE_STRING);
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
		xref1.type = RZ_ANALYSIS_XREF_TYPE_DATA;
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
		case RZ_ANALYSIS_XREF_TYPE_DATA:
			if (core->analysis->opt.followdatarefs) {
				rz_analysis_try_get_fcn(core, xref, depth, 2);
			}
			break;
		case RZ_ANALYSIS_XREF_TYPE_CODE:
		case RZ_ANALYSIS_XREF_TYPE_CALL:
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
	if (rz_pvector_len(fcn->bbs) == 1 && ((RzAnalysisBlock *)rz_pvector_head(fcn->bbs))->ninstr == 1) {
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		if (xrefs && rz_list_length(xrefs) == 1) {
			RzAnalysisXRef *xref = rz_list_first(xrefs);
			if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL) { /* Some fcns don't return */
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
	char tmpbuf[128];
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
		rz_analysis_function_rename(fcn, rz_strf(tmpbuf, "%s.%08" PFMT64x, fcnpfx, fcn->addr));
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
		RZ_LOG_ERROR("core: cannot allocate RzAnalysisFunction struct.\n");
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
					RzBinSymbol *sym;
					RzBinObject *o = rz_bin_cur_object(core->bin);
					const RzPVector *syms = o ? rz_bin_object_get_symbols(o) : NULL;
					ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
					void **it;
					rz_pvector_foreach (syms, it) {
						sym = *it;
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
	}
	rz_analysis_hint_free(hint);
	return false;
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
	RzAnalysisOp *op = rz_analysis_op_new();
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
		rz_vector_foreach (node->addr_hints, record) {
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
			rz_vector_foreach (node->addr_hints, record) {
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
			rz_vector_foreach (node->addr_hints, record) {
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

static int find_sym_flag(const void *a1, const void *a2, void *user) {
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
	return !(flags && rz_list_find(flags, fcn, find_sym_flag, NULL));
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
			if (reftype == RZ_ANALYSIS_XREF_TYPE_CALL && fcn->type == RZ_ANALYSIS_FCN_TYPE_LOC) {
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

/**
 * \brief for a given function returns an RzList of all functions that were called in it
 */
RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_core_analysis_fcn_get_calls(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xrefi;
	RzListIter *iter, *iter2;

	// get all references from this function
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	// sanity check
	if (!rz_list_empty(xrefs)) {
		// iterate over all the references and remove these which aren't of type call
		rz_list_foreach_safe (xrefs, iter, iter2, xrefi) {
			if (xrefi->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
				rz_list_delete(xrefs, iter);
			}
		}
	}
	return xrefs;
}

#define REG_SET_SIZE (RZ_ANALYSIS_CC_MAXARG + 2)

typedef struct {
	int count;
	RzPVector /*<int *>*/ reg_set;
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
	fcn->stack = bb->sp_entry;
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
			rz_analysis_extract_vars(core->analysis, fcn, op, -fcn->stack);
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

static bool analysis_path_exists(RzCore *core, ut64 from, ut64 to, RzList /*<RzAnalysisBlock *>*/ *bbs, int depth, HtUP *state, HtUP *avoid) {
	rz_return_val_if_fail(bbs, false);
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, from);
	RzListIter *iter = NULL;
	RzAnalysisXRef *xrefi;

	if (depth < 1) {
		RZ_LOG_ERROR("core: maximum recursive depth reached (%d)\n", depth);
		return false;
	}

	if (!bb) {
		return false;
	}

	ht_up_update(state, from, bb, NULL);

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
				if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
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

static RzList /*<RzAnalysisBlock *>*/ *analysis_graph_to(RzCore *core, ut64 addr, int depth, HtUP *avoid) {
	RzAnalysisFunction *cur_fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	RzList *list = rz_list_new();
	HtUP *state = ht_up_new(NULL, NULL);

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
			if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
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

RZ_API RzList /*<RzAnalysisBlock *>*/ *rz_core_analysis_graph_to(RzCore *core, ut64 addr, int n) {
	int depth = rz_config_get_i(core->config, "analysis.graph_depth");
	RzList *path, *paths = rz_list_new();
	HtUP *avoid = ht_up_new(NULL, NULL);
	while (n) {
		path = analysis_graph_to(core, addr, depth, avoid);
		if (path) {
			rz_list_append(paths, path);
			if (rz_list_length(path) >= 2) {
				RzAnalysisBlock *last = rz_list_get_n(path, rz_list_length(path) - 2);
				ht_up_update(avoid, last->addr, last, NULL);
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

static int core_analysis_followptr(RzCore *core, int type, ut64 at, ut64 ptr, ut64 ref, int code, int depth) {
	// SLOW Operation try to reduce as much as possible
	if (!ptr) {
		return false;
	}
	if (ref == UT64_MAX || ptr == ref) {
		const RzAnalysisXRefType t = code ? type ? type : RZ_ANALYSIS_XREF_TYPE_CODE : RZ_ANALYSIS_XREF_TYPE_DATA;
		rz_analysis_xrefs_set(core->analysis, at, ptr, t);
		return true;
	}
	if (depth < 1) {
		return false;
	}
	int wordsize = (int)(core->analysis->bits / 8);
	ut64 dataptr;
	if (!rz_io_read_i(core->io, ptr, &dataptr, wordsize, false)) {
		// RZ_LOG_ERROR("core_analysis_followptr: Cannot read word at destination\n");
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
			if (rz_analysis_op(core->analysis, aop, addr, buf, len, RZ_ANALYSIS_OP_MASK_BASIC) > 0) {
				return true;
			}
		}
		break;
	default:
		aop->size = 1;
		if (rz_analysis_op(core->analysis, aop, addr, buf, len, RZ_ANALYSIS_OP_MASK_BASIC) > 0) {
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
	RzAnalysisOp op = { 0 };
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
		RZ_LOG_ERROR("core: null reference search is not supported\n");
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
				RZ_LOG_ERROR("core: failed to read at 0x%08" PFMT64x "\n", at);
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
					rz_analysis_op_init(&op);
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
					rz_analysis_op_init(&op);
					if (rz_analysis_op(core->analysis, &op, at + i, buf + i, core->blocksize - i, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
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
						core_analysis_followptr(core, RZ_ANALYSIS_XREF_TYPE_CALL, at + i, op.jump, ref, true, 0)) {
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
						core_analysis_followptr(core, RZ_ANALYSIS_XREF_TYPE_CODE, at + i, op.ptr, ref, true, 1)) {
						count++;
					}
					break;
				case RZ_ANALYSIS_OP_TYPE_UCALL:
				case RZ_ANALYSIS_OP_TYPE_ICALL:
				case RZ_ANALYSIS_OP_TYPE_RCALL:
				case RZ_ANALYSIS_OP_TYPE_IRCALL:
				case RZ_ANALYSIS_OP_TYPE_UCCALL:
					if (op.ptr != UT64_MAX &&
						core_analysis_followptr(core, RZ_ANALYSIS_XREF_TYPE_CALL, at + i, op.ptr, ref, true, 1)) {
						count++;
					}
					break;
				default: {
					rz_analysis_op_init(&op);
					if (rz_analysis_op(core->analysis, &op, at + i, buf + i, core->blocksize - i, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
						rz_analysis_op_fini(&op);
						continue;
					}
				}
					if (op.ptr != UT64_MAX &&
						core_analysis_followptr(core, RZ_ANALYSIS_XREF_TYPE_DATA, at + i, op.ptr, ref, false, ptrdepth)) {
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
		RZ_LOG_ERROR("core: block size too small\n");
	}
	rz_cons_break_pop();
	free(buf);
	rz_analysis_op_fini(&op);
	return count;
}

static bool core_search_for_xrefs_in_boundaries(RzCore *core, ut64 from, ut64 to) {
	if ((from == UT64_MAX && to == UT64_MAX) ||
		(!from && !to) ||
		(to - from > rz_io_size(core->io))) {
		return false;
	}
	return rz_core_analysis_search_xrefs(core, from, to) > 0;
}

/**
 * \brief      Resolves any unresolved jump
 *
 * \param[in]  core  The RzCore to use
 */
RZ_API void rz_core_analysis_resolve_jumps(RZ_NONNULL RzCore *core) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_xrefs_list(core->analysis);
	bool analyze_recursively = rz_config_get_b(core->config, "analysis.calls");

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
			continue;
		}

		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, xref->from, -1);
		if (fcn) {
			continue;
		}

		rz_core_analysis_function_add(core, NULL, xref->from, analyze_recursively);
	}

	rz_list_free(xrefs);
}

/**
 * \brief      Analyze xrefs and prints the result.
 *
 * \param[in]  core    The RzCore to use
 * \param[in]  nbytes  Sets a custom boundary from current offset for N bytes (set it to 0 to use the maps)
 *
 * \return     False on failure, otherwise true
 */
RZ_API bool rz_core_analysis_refs(RZ_NONNULL RzCore *core, size_t nbytes) {
	rz_return_val_if_fail(core, false);

	bool cfg_debug = rz_config_get_b(core->config, "cfg.debug");
	ut64 from = 0, to = 0;

	if (nbytes) {
		from = core->offset;
		to = core->offset + nbytes;
		return core_search_for_xrefs_in_boundaries(core, from, to);
	} else if (cfg_debug) {
		// get boundaries of current memory map, section or io map
		RzDebugMap *map = rz_debug_map_get(core->dbg, core->offset);
		if (!map) {
			RZ_LOG_ERROR("Cannot find debug map boundaries at current offset\n");
			return false;
		}
		from = map->addr;
		to = map->addr_end;
		return core_search_for_xrefs_in_boundaries(core, from, to);
	}

	RzList *list = rz_core_get_boundaries_prot(core, RZ_PERM_X, NULL, "analysis");
	RzListIter *iter;
	RzIOMap *map;
	if (!list) {
		RZ_LOG_ERROR("cannot find maps with exec permisions\n");
		return false;
	}

	rz_list_foreach (list, iter, map) {
		from = map->itv.addr;
		to = rz_itv_end(map->itv);
		if (rz_cons_is_breaked()) {
			break;
		}
		core_search_for_xrefs_in_boundaries(core, from, to);
	}
	rz_list_free(list);
	return true;
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
	if (type == RZ_ANALYSIS_XREF_TYPE_NULL) {
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
 * \brief Sets a new xref according to the given to and from addresses.
 *
 * \param core       The rizin core.
 * \param xref_from  The address where the xref is located.
 * \param xref_to    The target address of the xref.
 * \param type       The xref type.
 * \param can_search When true, search and set the new string.
 */
static void set_new_xref(RzCore *core, ut64 xref_from, ut64 xref_to, RzAnalysisXRefType type, bool can_search) {
	size_t length = 0;
	char *string = NULL;
	RzStrEnc encoding = 0;
	if (type == RZ_ANALYSIS_XREF_TYPE_DATA && rz_core_get_string_at(core, xref_to, &string, &length, &encoding, can_search)) {
		rz_meta_set_with_subtype(core->analysis, RZ_META_TYPE_STRING, encoding, xref_to, length, string);
		rz_name_filter(string, -1, true);
		char *flagname = rz_str_newf("str.%s", string);
		rz_flag_space_push(core->flags, RZ_FLAGS_FS_STRINGS);
		(void)rz_flag_set(core->flags, flagname, xref_to, length);
		rz_flag_space_pop(core->flags);
		free(flagname);
		free(string);
	}
	// Add to SDB
	if (xref_to) {
		rz_analysis_xrefs_set(core->analysis, xref_from, xref_to, type);
	}
}

/**
 * \brief Searches for xrefs in the range of the paramters \p 'from' and \p 'to'.
 *
 * \param core The Rizin core.
 * \param from Start of search interval.
 * \param to End of search interval.
 * \return int Number of found xrefs. -1 in case of failure.
 */
RZ_API int rz_core_analysis_search_xrefs(RZ_NONNULL RzCore *core, ut64 from, ut64 to) {
	rz_return_val_if_fail(core, -1);

	bool cfg_debug = rz_config_get_b(core->config, "cfg.debug");
	bool can_search_string = rz_config_get_b(core->config, "analysis.strings");
	ut64 at;
	int count = 0;
	const int bsz = 8096;
	RzAnalysisOp op = { 0 };

	if (from == to) {
		return -1;
	} else if (from > to) {
		RZ_LOG_ERROR("Invalid range (0x%" PFMT64x " >= 0x%" PFMT64x ")\n", from, to);
		return -1;
	} else if (core->blocksize <= OPSZ) {
		RZ_LOG_ERROR("block size is too small (blocksize <= %u)\n", OPSZ);
		return -1;
	}

	ut8 *buf = malloc(bsz);
	if (!buf) {
		RZ_LOG_ERROR("cannot allocate a block\n");
		return -1;
	}

	ut8 *block = malloc(bsz);
	if (!block) {
		RZ_LOG_ERROR("cannot allocate a temp block\n");
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
			at += ret;
			continue;
		}
		memset(block, 0, bsz);
		if (!memcmp(buf, block, bsz)) {
			at += ret;
			continue;
		}
		while (i < bsz && !rz_cons_is_breaked()) {
			rz_analysis_op_init(&op);
			ret = rz_analysis_op(core->analysis, &op, at + i, buf + i, bsz - i, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
			ret = ret > 0 ? ret : 1;
			i += ret;
			if (ret <= 0 || i > bsz) {
				break;
			}
			// find references
			if ((st64)op.val > asm_sub_varmin && op.val != UT64_MAX && op.val != UT32_MAX) {
				if (is_valid_xref(core, op.val, RZ_ANALYSIS_XREF_TYPE_DATA, cfg_debug)) {
					set_new_xref(core, op.addr, op.val, RZ_ANALYSIS_XREF_TYPE_DATA, can_search_string);
					count++;
				}
			}
			for (ut8 i = 0; i < 6; ++i) {
				st64 aval = op.analysis_vals[i].imm;
				if (aval > asm_sub_varmin && aval != UT64_MAX && aval != UT32_MAX) {
					if (is_valid_xref(core, aval, RZ_ANALYSIS_XREF_TYPE_DATA, cfg_debug)) {
						set_new_xref(core, op.addr, aval, RZ_ANALYSIS_XREF_TYPE_DATA, can_search_string);
						count++;
					}
				}
			}
			// find references
			if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
				if (is_valid_xref(core, op.ptr, RZ_ANALYSIS_XREF_TYPE_DATA, cfg_debug)) {
					set_new_xref(core, op.addr, op.ptr, RZ_ANALYSIS_XREF_TYPE_DATA, can_search_string);
					count++;
				}
			}
			// find references
			if (op.addr > 512 && op.disp > 512 && op.disp && op.disp != UT64_MAX) {
				if (is_valid_xref(core, op.disp, RZ_ANALYSIS_XREF_TYPE_DATA, cfg_debug)) {
					set_new_xref(core, op.addr, op.disp, RZ_ANALYSIS_XREF_TYPE_DATA, can_search_string);
					count++;
				}
			}
			switch (op.type) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
				if (is_valid_xref(core, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE, cfg_debug)) {
					set_new_xref(core, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE, can_search_string);
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CJMP:
				if (rz_config_get_b(core->config, "analysis.jmp.cref") &&
					is_valid_xref(core, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE, cfg_debug)) {
					set_new_xref(core, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CODE, can_search_string);
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_CALL:
			case RZ_ANALYSIS_OP_TYPE_CCALL:
				if (is_valid_xref(core, op.jump, RZ_ANALYSIS_XREF_TYPE_CALL, cfg_debug)) {
					set_new_xref(core, op.addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CALL, can_search_string);
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
				if (is_valid_xref(core, op.ptr, RZ_ANALYSIS_XREF_TYPE_CODE, cfg_debug)) {
					set_new_xref(core, op.addr, op.ptr, RZ_ANALYSIS_XREF_TYPE_CODE, can_search_string);
					count++;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_UCALL:
			case RZ_ANALYSIS_OP_TYPE_ICALL:
			case RZ_ANALYSIS_OP_TYPE_RCALL:
			case RZ_ANALYSIS_OP_TYPE_IRCALL:
			case RZ_ANALYSIS_OP_TYPE_UCCALL:
				if (is_valid_xref(core, op.ptr, RZ_ANALYSIS_XREF_TYPE_CALL, cfg_debug)) {
					set_new_xref(core, op.addr, op.ptr, RZ_ANALYSIS_XREF_TYPE_CALL, can_search_string);
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
	RzPVector *vector;
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
		rz_core_analysis_fcn(core, item->offset, -1, RZ_ANALYSIS_XREF_TYPE_NULL, depth - 1);
		rz_core_analysis_function_rename(core, item->offset, "entry0");
	} else {
		rz_core_analysis_function_add(core, NULL, core->offset, false);
	}

	rz_core_task_yield(&core->tasks);

	rz_cons_break_push(NULL, NULL);

	RzBinFile *bf = core->bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
	/* Symbols (Imports are already analyzed by rz_bin on init) */
	void **it;
	if (o && (vector = o->symbols) != NULL) {
		rz_pvector_foreach (vector, it) {
			symbol = *it;
			if (rz_cons_is_breaked()) {
				break;
			}
			// Stop analyzing PE imports further
			if (isSkippable(symbol)) {
				continue;
			}
			if (isValidSymbol(symbol)) {
				ut64 addr = rz_bin_object_get_vaddr(o, symbol->paddr, symbol->vaddr);
				rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_XREF_TYPE_NULL, depth - 1);
			}
		}
	}
	rz_core_task_yield(&core->tasks);
	/* Main */
	if (o && (binmain = rz_bin_object_get_special_symbol(o, RZ_BIN_SPECIAL_SYMBOL_MAIN))) {
		if (binmain->paddr != UT64_MAX) {
			ut64 addr = rz_bin_object_get_vaddr(o, binmain->paddr, binmain->vaddr);
			rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_XREF_TYPE_NULL, depth - 1);
		}
	}
	rz_core_task_yield(&core->tasks);
	RzBinObject *bin = rz_bin_cur_object(core->bin);
	vector = bin ? (RzPVector *)rz_bin_object_get_entries(bin) : NULL;
	if (vector) {
		rz_pvector_foreach (vector, it) {
			entry = *it;
			if (entry->paddr == UT64_MAX) {
				continue;
			}
			ut64 addr = rz_bin_object_get_vaddr(o, entry->paddr, entry->vaddr);
			rz_core_analysis_fcn(core, addr, -1, RZ_ANALYSIS_XREF_TYPE_NULL, depth - 1);
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

	rz_platform_profile_add_flag_every_io(core->analysis->arch_target->profile, core->flags);
	rz_platform_index_add_flags_comments(core);

	rz_cons_break_pop();
	return true;
}

/**
 * \brief      Tries to detect the type of data at a given address and prints its contents.
 *
 * \param  core      The RzCore structure to use
 * \param  addr      The address to analyze
 * \param  count     The number of bytes to analyze
 * \param  depth     The max depth for analyzing pointers
 * \param  wordsize  The word size (when 0, the word size will be set to arch bits/8)
 */
RZ_API void rz_core_analysis_data(RZ_NONNULL RzCore *core, ut64 addr, ut32 count, ut32 depth, ut32 wordsize) {
	rz_return_if_fail(core);

	RzAnalysisData *d = NULL;
	ut8 *buf = core->block;
	ut32 old_len = core->blocksize;
	ut64 old_offset = core->offset;
	rz_core_seek_arch_bits(core, addr);
	int word = wordsize ? wordsize : core->rasm->bits / 8;
	char *str = NULL;
	RzConsPrintablePalette *pal = rz_config_get_i(core->config, "scr.color") ? &rz_cons_singleton()->context->pal : NULL;

	if (count > old_len) {
		rz_core_block_size(core, count);
	}
	rz_core_seek(core, addr, true);

	for (ut32 i = 0, j = 0; j < count; j++) {
		d = rz_analysis_data(core->analysis, addr + i, buf + i, count - i, wordsize);
		if (!d) {
			i += word;
			continue;
		}

		str = rz_analysis_data_to_string(d, pal);
		if (RZ_STR_ISNOTEMPTY(str)) {
			rz_cons_println(str);
		}
		switch (d->type) {
		case RZ_ANALYSIS_DATA_INFO_TYPE_POINTER:
			rz_cons_printf("`- ");
			if (depth > 0) {
				ut64 pointer = rz_mem_get_num(buf + i, word);
				rz_core_analysis_data(core, pointer, 1, depth - 1, wordsize);
			}
			i += word;
			break;
		case RZ_ANALYSIS_DATA_INFO_TYPE_STRING:
			i += d->len;
			break;
		default:
			i += (d->len > 3) ? d->len : word;
			break;
		}
		free(str);
		rz_analysis_data_free(d);
	}

	if (count > old_len) {
		rz_core_block_size(core, old_len);
	}
	rz_core_seek(core, old_offset, true);
}

struct block_flags_stat_t {
	ut64 step;
	ut64 from;
	RzCoreAnalysisStatsItem *blocks;
};

static bool block_flags_stat(RzFlagItem *fi, void *user) {
	struct block_flags_stat_t *u = (struct block_flags_stat_t *)user;
	size_t piece = (fi->offset - u->from) / u->step;
	u->blocks[piece].flags++;
	return true;
}

/**
 * Generate statistics for a range of memory, e.g. for a colorful overview bar.
 *
 * Let `fullsz = to + 1 - from`.
 * If `fullsz % step = 0`, then the result will be `fullsz / step` blocks of size `step`.
 * Otherwise, it will be `fullsz / step` blocks of size `step` and one additional block
 * covering the rest.
 *
 * \param lowest address to consider
 * \param highest address to consider, inclusive. Must be greater than or equal to from.
 * \param size of a single block in the output
 */
RZ_API RZ_OWN RzCoreAnalysisStats *rz_core_analysis_get_stats(RZ_NONNULL RzCore *core, ut64 from, ut64 to, ut64 step) {
	rz_return_val_if_fail(core && to >= from && step, NULL);
	RzAnalysisFunction *F;
	RzAnalysisBlock *B;
	RzBinSymbol *S;
	RzListIter *iter;
	void **it;
	ut64 at;
	RzCoreAnalysisStats *as = RZ_NEW0(RzCoreAnalysisStats);
	if (!as) {
		return NULL;
	}
	as->from = from;
	as->to = to;
	as->step = step;
	rz_vector_init(&as->blocks, sizeof(RzCoreAnalysisStatsItem), NULL, NULL);
	size_t count = (to == UT64_MAX && from == 0) ? rz_num_2_pow_64_div(step) : (to + 1 - from) / step;
	if (from + count * step != to + 1) {
		count++;
	}
	if (!count || SZT_MUL_OVFCHK(count, sizeof(RzCoreAnalysisStatsItem))) {
		rz_core_analysis_stats_free(as);
		return NULL;
	}
	RzCoreAnalysisStatsItem *blocks = rz_vector_insert_range(&as->blocks, 0, NULL, count);
	if (!blocks) {
		rz_core_analysis_stats_free(as);
		return NULL;
	}
	memset(blocks, 0, count * sizeof(RzCoreAnalysisStatsItem));
	for (at = from; at < to;) {
		RzIOMap *map = rz_io_map_get(core->io, at);
		size_t piece = (at - from) / step;
		blocks[piece].perm = map ? map->perm : (core->io->desc ? core->io->desc->perm : 0);
		ut64 prev = at;
		at += step;
		if (at < prev) {
			break;
		}
	}
	// iter all flags
	struct block_flags_stat_t u = { .step = step, .from = from, .blocks = blocks };
	rz_flag_foreach_range(core->flags, from, to, block_flags_stat, &u);
	// iter all functions
	rz_list_foreach (core->analysis->fcns, iter, F) {
		if (F->addr < from || F->addr > to) {
			continue;
		}
		size_t piece = (F->addr - from) / step;
		blocks[piece].functions++;
		ut64 last_piece = RZ_MIN((F->addr + rz_analysis_function_linear_size(F) - 1) / step, count - 1);
		for (; piece <= last_piece; piece++) {
			blocks[piece].in_functions++;
		}
		// iter all basic blocks
		rz_pvector_foreach (F->bbs, it) {
			B = (RzAnalysisBlock *)*it;
			if (B->addr < from || B->addr > to) {
				continue;
			}
			piece = (B->addr - from) / step;
			blocks[piece].blocks++;
		}
	}
	// iter all symbols
	RzBinObject *o = rz_bin_cur_object(core->bin);
	RzPVector *symbols = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	rz_pvector_foreach (symbols, it) {
		S = *it;
		if (S->vaddr < from || S->vaddr > to) {
			continue;
		}
		size_t piece = (S->vaddr - from) / step;
		blocks[piece].symbols++;
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
			size_t piece = (node->start - from) / step;
			switch (mi->type) {
			case RZ_META_TYPE_STRING:
				blocks[piece].strings++;
				break;
			case RZ_META_TYPE_COMMENT:
				blocks[piece].comments++;
				break;
			default:
				break;
			}
		}
		rz_pvector_free(metas);
	}
	return as;
}

RZ_API void rz_core_analysis_stats_free(RzCoreAnalysisStats *s) {
	if (!s) {
		return;
	}
	rz_vector_fini(&s->blocks);
	free(s);
}

/**
 * Get the lowest address that the i-th block in s covers (inclusive)
 */
RZ_API ut64 rz_core_analysis_stats_get_block_from(RZ_NONNULL const RzCoreAnalysisStats *s, size_t i) {
	rz_return_val_if_fail(s, 0);
	return s->from + s->step * i;
}

/**
 * Get the highest address that the i-th block in s covers (inclusive)
 */
RZ_API ut64 rz_core_analysis_stats_get_block_to(RZ_NONNULL const RzCoreAnalysisStats *s, size_t i) {
	rz_return_val_if_fail(s, 0);
	size_t count = rz_vector_len(&s->blocks);
	rz_return_val_if_fail(i < count, 0);
	if (i + 1 == count) {
		return s->to;
	}
	return rz_core_analysis_stats_get_block_from(s, i + 1) - 1;
}

RZ_API RzList /*<RzAnalysisCycleHook *>*/ *rz_core_analysis_cycles(RzCore *core, int ccl) {
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
				rz_cons_break_pop();
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
	void **iter;
	ut64 min = 0;
	ut64 max = 0;
	int first = 1;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f1 = rz_analysis_get_function_at(core->analysis, addr);
	RzAnalysisFunction *f2 = rz_analysis_get_function_at(core->analysis, addr2);
	if (!f1 || !f2) {
		RZ_LOG_ERROR("core: cannot find function\n");
		return;
	} else if (f1 == f2) {
		RZ_LOG_ERROR("core: cannot merge the same function\n");
		return;
	}
	// join all basic blocks from f1 into f2 if they are not
	// delete f2
	RZ_LOG_WARN("core: merging 0x%08" PFMT64x " into 0x%08" PFMT64x "\n", addr, addr2);

	rz_pvector_foreach (f1->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
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
	rz_pvector_foreach (f2->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
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

RZ_IPI void rz_core_add_string_ref(RzCore *core, ut64 xref_from, ut64 xref_to) {
	if (xref_to == UT64_MAX || !xref_to) {
		return;
	}
	if (!xref_from || xref_from == UT64_MAX) {
		xref_from = core->analysis->esil->address;
	}
	size_t length = 0;
	char *string = NULL;
	RzStrEnc encoding = 0;
	if (rz_core_get_string_at(core, xref_to, &string, &length, &encoding, true)) {
		rz_analysis_xrefs_set(core->analysis, xref_from, xref_to, RZ_ANALYSIS_XREF_TYPE_DATA);
		rz_name_filter(string, -1, true);
		char *flagname = rz_str_newf("str.%s", string);
		rz_flag_space_push(core->flags, RZ_FLAGS_FS_STRINGS);
		rz_flag_set(core->flags, flagname, xref_to, length);
		rz_flag_space_pop(core->flags);
		rz_meta_set_with_subtype(core->analysis, RZ_META_TYPE_STRING, encoding, xref_to, length, string);
		free(string);
		free(flagname);
	}
}

RZ_API int rz_core_search_value_in_range(RzCore *core, RzInterval search_itv, ut64 vmin,
	ut64 vmax, int vsize, inRangeCb cb, void *cb_user) {
	int i, align = core->search->align, hitctr = 0;
	bool vinfun = rz_config_get_b(core->config, "analysis.vinfun");
	bool vinfunr = rz_config_get_b(core->config, "analysis.vinfunrange");
	bool analyze_strings = rz_config_get_b(core->config, "analysis.strings");
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	ut8 buf[4096];
	ut64 v64, value = 0, size;
	ut64 from = rz_itv_begin(search_itv), to = rz_itv_end(search_itv);
	ut32 v32;
	ut16 v16;
	if (from >= to) {
		RZ_LOG_ERROR("core: `from` must be lower than `to`\n");
		return -1;
	}
	bool maybeThumb = false;
	if (align && core->analysis->cur && core->analysis->cur->arch) {
		if (!strcmp(core->analysis->cur->arch, "arm") && core->analysis->bits != 64) {
			maybeThumb = true;
		}
	}

	if (vmin >= vmax) {
		RZ_LOG_ERROR("core: `vmin` must be lower than `vmax`\n");
		return -1;
	}
	if (to == UT64_MAX) {
		RZ_LOG_ERROR("core: invalid destination boundary\n");
		return -1;
	}
	rz_cons_break_push(NULL, NULL);

	if (!rz_io_is_valid_offset(core->io, from, 0)) {
		hitctr = -1;
		goto beach;
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
		if (size <= vsize) {
			break;
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
				value = rz_read_ble8(v);
				match = (buf[i] >= vmin && buf[i] <= vmax);
				break;
			case 2:
				v16 = rz_read_ble16(v, big_endian);
				match = (v16 >= vmin && v16 <= vmax);
				value = v16;
				break;
			case 4:
				v32 = rz_read_ble32(v, big_endian);
				match = (v32 >= vmin && v32 <= vmax);
				value = v32;
				break;
			case 8:
				v64 = rz_read_ble64(v, big_endian);
				match = (v64 >= vmin && v64 <= vmax);
				value = v64;
				break;
			default:
				RZ_LOG_ERROR("core: unknown vsize %d (supported only 1,2,4,8)\n", vsize);
				hitctr = -1;
				goto beach;
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
					if (analyze_strings) {
						rz_core_add_string_ref(core, addr, value);
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
	RzList /*<RzAnalysisBlock *>*/ *path;
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
	ht_uu_insert(p->visited, cur->addr, 1, NULL);
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
		RZ_LOG_ERROR("core: cannot find basic block for 0x%08" PFMT64x "\n", from);
		return;
	}
	if (!b1) {
		RZ_LOG_ERROR("core: cannot find basic block for 0x%08" PFMT64x "\n", to);
		return;
	}
	RzCoreAnalPaths rcap = { 0 };
	rcap.visited = ht_uu_new();
	rcap.path = rz_list_new();
	rcap.core = core;
	rcap.from = from;
	rcap.fromBB = b0;
	rcap.to = to;
	rcap.toBB = b1;
	rcap.cur = b0;
	rcap.count = rz_config_get_i(core->config, "search.maxhits");
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
	void **iter;
	RzAnalysisBlock *bb;

	rz_pvector_foreach (f->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		ut64 opaddr = rz_analysis_block_get_op_addr(bb, bb->ninstr - 1);
		if (opaddr == UT64_MAX) {
			return false;
		}

		// get last opcode
		RzAnalysisOp *op = rz_core_op_analysis(core, opaddr, RZ_ANALYSIS_OP_MASK_HINT);
		if (!op) {
			RZ_LOG_ERROR("core: cannot analyze opcode at 0x%08" PFMT64x "\n", opaddr);
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
 * \param profile reference to RzPlatformProfile
 * \param flags reference to RzFlag
 */
RZ_API void rz_platform_profile_add_flag_every_io(RzPlatformProfile *profile, RzFlag *flags) {
	rz_flag_unset_all_in_space(flags, RZ_FLAGS_FS_MMIO_REGISTERS);
	rz_flag_unset_all_in_space(flags, RZ_FLAGS_FS_MMIO_REGISTERS_EXTENDED);
	ht_up_foreach(profile->registers_mmio, add_mmio_flag_cb, flags);
	ht_up_foreach(profile->registers_extended, add_mmio_extended_flag_cb, flags);
}

static bool add_arch_platform_flag_comment_cb(void *user, const ut64 addr, const void *v) {
	if (!v) {
		return false;
	}
	RzPlatformItem *item = (RzPlatformItem *)v;
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
RZ_API bool rz_platform_index_add_flags_comments(RzCore *core) {
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
			if (!rz_flag_rename(core->flags, flag, name)) {
				// If the rename failed, it may be because there is already a flag with the target name
				if (rz_flag_get(core->flags, name)) {
					// If that is the case, just unset the old one to not leak it (e.g. leaving behind fcn.<offset>)
					rz_flag_unset(core->flags, flag);
				}
			}
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
	rz_core_analysis_fcn(core, addr, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, depth);
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
					// RZ_LOG_WARN("core: ignore 0x%08"PFMT64x" call 0x%08"PFMT64x"\n", ref->at, ref->addr);
					continue;
				}
				if (xref->type != RZ_ANALYSIS_XREF_TYPE_CODE && xref->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
					/* only follow code/call references */
					continue;
				}
				if (!rz_io_is_valid_offset(core->io, xref->to, !core->analysis->opt.noncode)) {
					continue;
				}
				rz_core_analysis_fcn(core, xref->to, fcn->addr, RZ_ANALYSIS_XREF_TYPE_CALL, depth);
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
						if (xref1->type != RZ_ANALYSIS_XREF_TYPE_CODE && xref1->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
							continue;
						}
						rz_core_analysis_fcn(core, xref1->to, f->addr, RZ_ANALYSIS_XREF_TYPE_CALL, depth);
						// recursively follow fcn->refs again and again
					}
					rz_list_free(xrefs1);
				} else {
					f = rz_analysis_get_fcn_in(core->analysis, fcn->addr, 0);
					if (f) {
						/* cut function */
						rz_analysis_function_resize(f, addr - fcn->addr);
						rz_core_analysis_fcn(core, xref->to, fcn->addr,
							RZ_ANALYSIS_XREF_TYPE_CALL, depth);
						f = rz_analysis_get_function_at(core->analysis, fcn->addr);
					}
					if (!f) {
						RZ_LOG_ERROR("core: cannot find function at 0x%08" PFMT64x "\n", fcn->addr);
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
		RZ_LOG_ERROR("core: cannot find function at 0x%08" PFMT64x "\n", addr);
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
			int nargs = rz_list_length(cache.arg_vars);
			RzAnalysisVar *var;
			rz_list_foreach (cache.sorted_vars, iter, var) {
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

static void relocation_noreturn_process(RzCore *core, RzList /*<char *>*/ *noretl, SetU *todo, RzAnalysisBlock *b, RzBinReloc *rel, ut64 opsize, ut64 addr) {
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
	RzList /*<char *>*/ *noretl;
	SetU *todo;
};

static bool process_reference_noreturn_cb(void *u, const ut64 k, const void *v) {
	RzCore *core = ((struct core_noretl *)u)->core;
	RzList *noretl = ((struct core_noretl *)u)->noretl;
	SetU *todo = ((struct core_noretl *)u)->todo;
	RzAnalysisXRef *xref = (RzAnalysisXRef *)v;
	if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL || xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
		// At first we check if there are any relocations that override the call address
		// Note, that the relocation overrides only the part of the instruction
		ut64 addr = k;
		ut8 buf[CALL_BUF_SIZE] = { 0 };
		RzAnalysisOp op = { 0 };
		if (core->analysis->iob.read_at(core->analysis->iob.io, addr, buf, CALL_BUF_SIZE)) {
			rz_analysis_op_init(&op);
			if (rz_analysis_op(core->analysis, &op, addr, buf, CALL_BUF_SIZE, 0) > 0) {
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

	HtUU *done = ht_uu_new();
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
				RZ_LOG_ERROR("core: cannot analyze opcode at 0x%08" PFMT64x "\n", xref->from);
				continue;
			}
			ut64 call_addr = xref->from;
			ut64 chop_addr = call_addr + xrefop->size;
			rz_analysis_op_free(xrefop);
			if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
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
					ht_uu_insert(done, *n, 1, NULL);
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
			RZ_LOG_ERROR("core: cannot find var at 0x%08" PFMT64x "\n", core->offset);
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
			RZ_LOG_ERROR("core: cannot find var by name (%s)\n", name);
			return false;
		}
	} else {
		RZ_LOG_ERROR("core: cannot find function at 0x%08" PFMT64x "\n", core->offset);
		rz_analysis_op_free(op);
		return false;
	}
	rz_analysis_op_free(op);
	return true;
}

static bool is_in_data_map(RzCore *core, const ut64 address) {
	if (address < 256 || address == UT64_MAX) {
		// prevents a lot of false positives when it comes
		// to invalid addresses, especially in x86 arch with
		// mov and jmp instructions.
		return false;
	}
	RzBinObject *o = rz_bin_cur_object(core->bin);
	if (!o) {
		return false;
	}

	const RzBinMap *map = rz_bin_object_get_map_at(o, address, core->io->va);
	return map && map->psize > 2 && rz_bin_map_is_data(map);
}

static ut32 add_data_pointer(RzCore *core, const ut8 *bytes, const ut32 size, ut64 pc, ut32 min_op_size) {
	RzAnalysis *analysis = core->analysis;
	RzAnalysisOp aop = { 0 };
	ut32 isize = 0;
	ut64 pointer = 0;

	rz_analysis_op_init(&aop);
	if (rz_analysis_op(analysis, &aop, pc, bytes, size, RZ_ANALYSIS_OP_MASK_DISASM) < 1) {
		rz_analysis_op_fini(&aop);
		return min_op_size;
	}

	isize = aop.size;
	pointer = aop.ptr;
	rz_analysis_op_fini(&aop);

	if (pointer == pc ||
		!is_in_data_map(core, pointer) ||
		rz_flag_get_list(core->flags, pointer) ||
		rz_analysis_get_function_at(analysis, pointer)) {
		return isize;
	}

	char *flagname = rz_str_newf("data.%08" PFMT64x, pointer);
	if (!flagname) {
		RZ_LOG_ERROR("Failed allocate flag name buffer for pointer to data\n");
		return 0;
	}

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_POINTERS);
	rz_flag_set(core->flags, flagname, pointer, analysis->bits / 8);
	rz_flag_space_pop(core->flags);
	free(flagname);
	rz_analysis_xrefs_set(analysis, pc, pointer, RZ_ANALYSIS_XREF_TYPE_DATA);
	return isize;
}

/**
 * \brief      Tries to resolve all the constant pointers and adds flags named data.XXXXXX
 *
 * \param      core  The RzCore to analyze
 */
RZ_IPI void rz_core_analysis_resolve_pointers_to_data(RzCore *core) {
	RzAnalysis *analysis = core->analysis;

	bool can_use_pointers = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS);
	if (!can_use_pointers) {
		// never run this for archs that does not use pointers
		return;
	}

	RzListIter *it;
	RzAnalysisFunction *func = NULL;
	RzAnalysisBlock *block = NULL;
	ut8 *bytes = NULL;
	void *archbits = NULL;
	ut32 isize = 0, bsize = 0;
	ut64 pc = 0;
	ut32 min_op_size = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);

	// ignore any hint.
	RZ_PTR_MOVE(archbits, analysis->coreb.archbits);

	rz_list_foreach (analysis->fcns, it, func) {
		if (rz_cons_is_breaked()) {
			break;
		}
		void **vit;
		rz_pvector_foreach (func->bbs, vit) {
			block = (RzAnalysisBlock *)*vit;
			if (block->size < 1) {
				continue;
			}

			bytes = malloc(block->size);
			if (!bytes) {
				RZ_LOG_ERROR("Failed allocate basic block bytes buffer\n");
				goto end;
			} else if (rz_io_nread_at(core->io, block->addr, bytes, block->size) < 0) {
				free(bytes);
				RZ_LOG_ERROR("Failed to read function basic block at address %" PFMT64x "\n", block->addr);
				goto end;
			}

			for (ut32 i = 0; i < block->size;) {
				pc = block->addr + i;
				bsize = block->size - i;
				if (!(isize = add_data_pointer(core, bytes + i, bsize, pc, min_op_size))) {
					free(bytes);
					goto end;
				}
				i += isize;
			}
			free(bytes);
		}
	}

end:
	analysis->coreb.archbits = archbits;
}

static bool is_unknown_file(RzCore *core) {
	if (core->bin->cur && core->bin->cur->o) {
		return (rz_pvector_empty(core->bin->cur->o->sections));
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

static void core_analysis_using_plugins(RzCore *core) {
	RzListIter *it;
	const RzCorePlugin *plugin;
	rz_list_foreach (core->plugins, it, plugin) {
		if (plugin->analysis) {
			plugin->analysis(core);
		}
	}
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
	const char *notify = NULL;
	ut64 curseek = core->offset;
	bool cfg_debug = rz_config_get_b(core->config, "cfg.debug");
	bool plugin_supports_esil = core->analysis->cur->esil;
	bool is_apple = is_apple_target(core);

	if (rz_str_startswith(rz_config_get(core->config, "bin.lang"), "go")) {
		rz_core_notify_done(core, "Find function and symbol names from golang binaries");
		if (rz_core_analysis_recover_golang_functions(core)) {
			rz_core_analysis_resolve_golang_strings(core);
		}
		rz_core_task_yield(&core->tasks);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}

	if (is_apple) {
		notify = "Recover all Objective-C selector stub names";
		rz_core_notify_begin(core, "%s", notify);
		rz_core_analysis_objc_stubs(core); // "aalos"
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
		if (rz_cons_is_breaked()) {
			return false;
		}
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

	notify = "Analyze function calls";
	rz_core_notify_begin(core, "%s", notify);
	(void)rz_core_analysis_calls(core, false); // "aac"
	rz_core_seek(core, curseek, true);
	rz_core_notify_done(core, "%s", notify);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}

	if (!rz_str_startswith(rz_config_get(core->config, "asm.arch"), "x86")) {
		notify = "find and analyze function preludes";
		rz_core_notify_begin(core, "%s", notify);
		(void)rz_core_search_preludes(core, false); // "aap"
		didAap = true;
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}

	notify = "Analyze len bytes of instructions for references";
	rz_core_notify_begin(core, "%s", notify);
	(void)rz_core_analysis_refs(core, 0); // "aar"
	rz_core_notify_done(core, "%s", notify);
	rz_core_task_yield(&core->tasks);
	if (rz_cons_is_breaked()) {
		return false;
	}

	if (is_apple) {
		notify = "Check for objc references";
		rz_core_notify_begin(core, "%s", notify);
		rz_core_analysis_objc_refs(core, true); // "aalor"
		rz_core_notify_done(core, "%s", notify);
	}
	rz_core_task_yield(&core->tasks);

	notify = "Check for classes";
	rz_core_notify_begin(core, "%s", notify);
	rz_analysis_class_recover_all(core->analysis);
	rz_core_notify_done(core, "%s", notify);
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
		notify = "Emulate functions to find computed references";
		rz_core_notify_begin(core, "%s", notify);
		if (plugin_supports_esil) {
			rz_core_analysis_esil_references_all_functions(core);
		}
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
		rz_config_set_b(core->config, "io.pcache", pcache);
		if (rz_cons_is_breaked()) {
			return false;
		}
	}

	if (rz_config_get_i(core->config, "analysis.autoname")) {
		notify = "Speculatively constructing a function name "
			 "for fcn.* and sym.func.* functions (aan)";
		rz_core_notify_begin(core, "%s", notify);
		rz_core_analysis_autoname_all_fcns(core);
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
	}

	if (core->analysis->opt.vars) {
		notify = "Analyze local variables and arguments";
		rz_core_notify_begin(core, "%s", notify);
		RzAnalysisFunction *fcni;
		RzListIter *iter;
		rz_list_foreach (core->analysis->fcns, iter, fcni) {
			if (rz_cons_is_breaked()) {
				break;
			}
			RzList *list = rz_analysis_var_list(fcni, RZ_ANALYSIS_VAR_STORAGE_REG);
			if (!rz_list_empty(list)) {
				rz_list_free(list);
				continue;
			}
			// extract only reg based var here
			rz_core_recover_vars(core, fcni, true);
			rz_list_free(list);
		}
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
	}

	if (plugin_supports_esil) {
		notify = "Type matching analysis for all functions";
		rz_core_notify_begin(core, "%s", notify);
		rz_core_analysis_types_propagation(core);
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
	}

	if (rz_config_get_b(core->config, "analysis.apply.signature")) {
		int n_applied = 0;
		rz_core_notify_begin(core, "Applying signatures from sigdb");
		rz_core_analysis_sigdb_apply(core, &n_applied, NULL);
		rz_core_notify_done(core, "Applied %d FLIRT signatures via sigdb", n_applied);
		rz_core_task_yield(&core->tasks);
	}

	notify = "Propagate noreturn information";
	rz_core_notify_begin(core, "%s", notify);
	rz_core_analysis_propagate_noreturn(core, UT64_MAX);
	rz_core_notify_done(core, "%s", notify);
	rz_core_task_yield(&core->tasks);

	// Apply DWARF function information
	if (core->analysis->debug_info) {
		notify = "Integrate dwarf function information.";
		rz_core_notify_begin(core, "%s", notify);
		rz_analysis_dwarf_integrate_functions(core->analysis, core->flags);
		rz_core_notify_done(core, "%s", notify);
	}

	if (rz_config_get_b(core->config, "analysis.resolve.pointers")) {
		notify = "Resolve pointers to data sections";
		rz_core_notify_begin(core, "%s", notify);
		rz_core_analysis_resolve_pointers_to_data(core);
		rz_core_notify_done(core, "%s", notify);
		rz_core_task_yield(&core->tasks);
	}

	if (experimental) {
		if (!didAap) {
			notify = "Finding function preludes";
			rz_core_notify_begin(core, "%s", notify);
			(void)rz_core_search_preludes(core, false); // "aap"
			rz_core_notify_done(core, "%s", notify);
			rz_core_task_yield(&core->tasks);
		}
		notify = "Enable constraint types analysis for variables";
		rz_core_notify_begin(core, "%s", notify);
		rz_config_set(core->config, "analysis.types.constraint", "true");
		rz_core_notify_done(core, "%s", notify);
	} else {
		rz_core_notify_done(core, "Use -AA or aaaa to perform additional experimental analysis.");
	}

	rz_core_seek_undo(core);
	if (dh_orig) {
		rz_config_set(core->config, "dbg.backend", dh_orig);
		rz_core_task_yield(&core->tasks);
	}

	if (!is_unknown_file(core)) {
		rz_analysis_add_device_peripheral_map(core->bin->cur->o, core->analysis);
	}

	core_analysis_using_plugins(core);
	return true;
}

static void analysis_sigdb_add(RzSigDb *sigs, const char *path, bool with_details) {
	if (RZ_STR_ISEMPTY(path) || !rz_file_is_directory(path)) {
		return;
	}
	RzSigDb *tmp = rz_sign_sigdb_load_database(path, with_details);
	if (tmp) {
		rz_sign_sigdb_merge(sigs, tmp);
		rz_sign_sigdb_free(tmp);
	}
}

/**
 * \brief Returns all the signatures found in the default path.
 *
 * Scans for signature in the following paths:
 * - home path + RZ_SIGDB
 * - system install prefix path + RZ_SIGDB
 * - flirt.sigdb.path user custom sigdb path
 *
 * \param      core          The RzCore to use.
 * \param[in]  with_details  The reads the signature details and sets them in RzSigDBEntry
 * \return     On success a RzList containing RzSigDBEntry entries, otherwise NULL.
 */
RZ_API RZ_OWN RzList /*<RzSigDBEntry *>*/ *rz_core_analysis_sigdb_list(RZ_NONNULL RzCore *core, bool with_details) {
	rz_return_val_if_fail(core, NULL);

	RzSigDb *sigs = rz_sign_sigdb_new();
	if (!sigs) {
		return NULL;
	}

	if (rz_config_get_b(core->config, "flirt.sigdb.load.home")) {
		char *home_sigdb = rz_path_home_prefix(RZ_SIGDB);
		analysis_sigdb_add(sigs, home_sigdb, with_details);
		free(home_sigdb);
	}

	if (rz_config_get_b(core->config, "flirt.sigdb.load.system")) {
		char *system_sigdb = rz_path_system(RZ_SIGDB);
		analysis_sigdb_add(sigs, system_sigdb, with_details);
		free(system_sigdb);
	}

	if (rz_config_get_b(core->config, "flirt.sigdb.load.extra")) {
		char *extra_sigdb = rz_path_extra(RZ_SIGDB);
		analysis_sigdb_add(sigs, extra_sigdb, with_details);
		free(extra_sigdb);
	}

	const char *user_sigdb = rz_config_get(core->config, "flirt.sigdb.path");
	analysis_sigdb_add(sigs, user_sigdb, with_details);

	RzList *lst = rz_sign_sigdb_list(sigs);
	sigs->entries->opt.finiKV = NULL;
	rz_sign_sigdb_free(sigs);
	return lst;
}

/**
 * \brief Adds all the signatures to a RzTable structure.
 *
 * \param[in] core   The RzCore to use
 * \param[in] table  The RzTable to use
 */
RZ_API void rz_core_analysis_sigdb_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzTable *table) {
	rz_return_if_fail(core && table);

	RzList *sigdb = rz_core_analysis_sigdb_list(core, true);
	if (!sigdb) {
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

	rz_list_free(sigdb);
}

/**
 * \brief tries to apply the signatures in the flirt.sigdb.path
 *
 * \param core       The RzCore instance
 * \param n_applied  Returns the number of successfully applied signatures
 * \param filter     Filters the signatures found following the user input
 * \return fail when an error occurs otherwise true
 */
RZ_API bool rz_core_analysis_sigdb_apply(RZ_NONNULL RzCore *core, RZ_NULLABLE int *n_applied, RZ_NULLABLE const char *filter) {
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
		} else if (!strcmp(obj->plugin->name, "coff")) {
			// coff files are used also for PE, we can use the same signatures.
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

	sigdb = rz_core_analysis_sigdb_list(core, false);
	if (!sigdb) {
		return false;
	}

	n_flags_old = rz_flag_count(core->flags, "flirt");
	rz_list_foreach (sigdb, iter, sig) {
		if (rz_cons_is_breaked()) {
			break;
		}
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

RZ_IPI bool rz_core_analysis_function_delete_var(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarStorageType kind, const char *id) {
	RzAnalysisVar *var = NULL;
	if (kind == RZ_ANALYSIS_VAR_STORAGE_STACK && IS_DIGIT(*id)) {
		st64 delta = rz_num_math(core->num, id);
		var = rz_analysis_function_get_stack_var_at(fcn, delta);
	} else {
		var = rz_analysis_function_get_var_byname(fcn, id);
	}
	if (!var || var->storage.type != kind) {
		return false;
	}
	rz_analysis_var_delete(var);
	return true;
}

/**
 * \brief Get the address of a stack variable.
 *
 * The address for stack backed variables is computed from the
 * current base pointer register. Register backed variables will always
 * return UT64_MAX.
 *
 * \param var Pointer to a \ref RzAnalysisVar.
 */
RZ_API ut64 rz_core_analysis_var_addr(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisVar *var) {
	rz_return_val_if_fail(core && var, UT64_MAX);
	if (var->storage.type == RZ_ANALYSIS_VAR_STORAGE_STACK) {
		// TODO: If bp is not available, we can also get the address from the sp
		// through info available from rz_analysis_block_get_sp_at()
		ut64 stack = rz_core_reg_getv_by_role_or_name(core, "BP");
		return stack + var->fcn->bp_off + var->storage.stack_off;
	}
	return UT64_MAX;
}

RZ_API RZ_OWN char *rz_core_analysis_var_display(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisVar *var, bool add_name) {
	RzAnalysis *analysis = core->analysis;
	RzStrBuf *sb = rz_strbuf_new(NULL);
	char *fmt = rz_type_as_format(analysis->typedb, var->type);
	if (!fmt) {
		return rz_strbuf_drain(sb);
	}
	bool use_hexval = rz_type_is_strictly_atomic(core->analysis->typedb, var->type) && rz_type_atomic_str_eq(core->analysis->typedb, var->type, "int");
	if (add_name) {
		rz_strbuf_appendf(sb, "%s %s = ", rz_analysis_var_is_arg(var) ? "arg" : "var", var->name);
	}
	switch (var->storage.type) {
	case RZ_ANALYSIS_VAR_STORAGE_REG: {
		char *r;
		if (use_hexval) {
			int wordsize = rz_analysis_get_address_bits(core->analysis) / 8;
			// Read register value
			ut64 regval = rz_debug_reg_get(core->dbg, var->storage.reg);
			r = rz_core_print_hexdump_refs(core, wordsize, wordsize, regval);
		} else {
			char *regfmt = rz_str_newf("r (%s)", var->storage.reg);
			r = rz_core_print_format(core, regfmt, RZ_PRINT_MUSTSEE, core->offset);
			free(regfmt);
		}
		rz_strbuf_append(sb, r);
		free(r);
		break;
	}
	case RZ_ANALYSIS_VAR_STORAGE_STACK: {
		ut64 addr = rz_core_analysis_var_addr(core, var);
		char *r;
		if (use_hexval) {
			int wordsize = rz_analysis_get_address_bits(core->analysis) / 8;
			r = rz_core_print_hexdump_refs(core, wordsize, wordsize, addr);
		} else {
			r = rz_core_print_format(core, fmt, RZ_PRINT_MUSTSEE, addr);
		}
		rz_strbuf_append(sb, r);
		free(r);
	} break;
	default:
		rz_strbuf_append(sb, "unimplemented");
	}
	free(fmt);
	return rz_strbuf_drain(sb);
}

RZ_IPI char *rz_core_analysis_all_vars_display(RzCore *core, RzAnalysisFunction *fcn, bool add_name) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *p = *it;
		char *r = rz_core_analysis_var_display(core, p, add_name);
		rz_strbuf_append(sb, r);
		free(r);
	}
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

static int check_rom_exists(const void *value, const void *data, void *user) {
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
	if (rz_pvector_find(o->sections, ".rom", check_rom_exists, NULL)) {
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
	rz_pvector_push(o->sections, s);
	return true;
}

RZ_IPI bool rz_core_analysis_types_propagation(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	ut64 seek;
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RZ_LOG_WARN("core: analysis propagation type can't be exectured when in debugger mode.\n");
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
	HtUU *loop_table = ht_uu_new();

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
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, addr, -1);
	if (!f) {
		RZ_LOG_ERROR("core: cannot find function in 0x%08" PFMT64x "\n", addr);
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
		RZ_ANALYSIS_XREF_TYPE_NULL, depth);
	fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (fcn) {
		rz_analysis_function_resize(fcn, addr_end - addr);
	}
	rz_config_set_i(core->config, "analysis.from", a);
	rz_config_set_i(core->config, "analysis.to", b);
	rz_config_set(core->config, "analysis.limits", c ? c : "");
}

static bool arch_is(RzCore *core, const char *x) {
	RzAsm *as = core ? core->rasm : NULL;
	if (as && as->cur && as->bits <= 32 && as->cur->name) {
		return strstr(as->cur->name, x);
	}
	return false;
}

static bool archIsThumbable(RzCore *core) {
	return arch_is(core, "arm");
}

static void _CbInRangeAav(RzCore *core, ut64 from, ut64 to, int vsize, void *user) {
	bool pretend = (user && *(RzOutputMode *)user == RZ_OUTPUT_MODE_RIZIN);
	int arch_align = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
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
		rz_analysis_xrefs_set(core->analysis, from, to, RZ_ANALYSIS_XREF_TYPE_NULL);
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
	int archAlign = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
	rz_config_set_i(core->config, "search.align", archAlign);
	rz_config_set(core->config, "analysis.in", "io.maps.x");
	rz_core_notify_done(core, "Finding xrefs in noncode section with analysis.in=io.maps");

	int vsize = 4; // 32bit dword
	if (core->rasm->bits == 64) {
		vsize = 8;
	}

	// body
	rz_core_notify_done(core, "Analyze value pointers (aav)");
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
			rz_core_notify_done(core, "from 0x%" PFMT64x " to 0x%" PFMT64x " (aav)", map->itv.addr, rz_itv_end(map->itv));
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
			if ((to - from) > MAX_SCAN_SIZE) {
				rz_core_notify_done(core, "Skipping large region (from 0x%08" PFMT64x " to 0x%08" PFMT64x ")", from, to);
				continue;
			}
			rz_core_notify_done(core, "Value from 0x%08" PFMT64x " to 0x%08" PFMT64x " (aav)", from, to);
			rz_list_foreach (list, iter, map) {
				ut64 begin = rz_itv_begin(map->itv);
				ut64 end = rz_itv_end(map->itv);
				if (rz_cons_is_breaked()) {
					break;
				}
				if (end - begin > UT32_MAX) {
					rz_core_notify_done(core, "Skipping huge range");
					continue;
				}
				rz_core_notify_done(core, "0x%08" PFMT64x "-0x%08" PFMT64x " in 0x%" PFMT64x "-0x%" PFMT64x " (aav)", from, to, begin, end);
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

RZ_API void rz_core_analysis_cc_init_by_path(RzCore *core, RZ_NULLABLE const char *path, RZ_NULLABLE const char *homepath) {
	const char *analysis_arch = rz_config_get(core->config, "analysis.arch");
	Sdb *cc = core->analysis->sdb_cc;
	if (!strcmp(analysis_arch, "null")) {
		sdb_reset(cc);
		RZ_FREE(cc->path);
		return;
	}

	char buf[40];
	int bits = core->analysis->bits;
	char *dbpath = rz_file_path_join(path ? path : "", rz_strf(buf, "cc-%s-%d.sdb", analysis_arch, bits));
	char *dbhomepath = rz_file_path_join(homepath ? homepath : "", rz_strf(buf, "cc-%s-%d.sdb", analysis_arch, bits));

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
		free(cc->path);
		cc->path = strdup(dbhomepath);
	}
	free(dbpath);
	free(dbhomepath);

	// same as "tcc `arcc`"
	char *s = rz_reg_profile_to_cc(core->analysis->reg);
	if (s && !rz_analysis_cc_set(core->analysis, s)) {
		RZ_LOG_ERROR("core: invalid CC from reg profile.\n");
	} else if (!s) {
		RZ_LOG_ERROR("core: cannot derive CC from reg profile.\n");
	}
	free(s);
	if (sdb_isempty(cc)) {
		RZ_LOG_WARN("core: missing calling conventions for '%s'. Deriving it from the regprofile.\n", analysis_arch);
	}
}

RZ_API void rz_core_analysis_cc_init(RzCore *core) {
	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	char *home_types_dir = rz_path_home_prefix(RZ_SDB_TYPES);
	rz_core_analysis_cc_init_by_path(core, types_dir, home_types_dir);
	free(types_dir);
	free(home_types_dir);
}

/**
 * \brief Print Calling Convention info
 *
 * \param core The RzCore instance
 * \param cc Calling Convention name
 * \param pj Optional PJ instance for JSON mode
 */
RZ_IPI void rz_core_analysis_cc_print(RzCore *core, RZ_NONNULL const char *cc, RZ_NULLABLE PJ *pj) {
	rz_return_if_fail(core && cc);
	if (pj) {
		pj_o(pj);
	}
	if (pj) {
		pj_ks(pj, "name", cc);
	} else {
		rz_cons_printf("name: %s\n", cc);
	}
	const char *regname = rz_analysis_cc_ret(core->analysis, cc);
	if (regname) {
		if (pj) {
			pj_ks(pj, "ret", regname);
		} else {
			rz_cons_printf("ret: %s\n", regname);
		}
	}
	if (pj) {
		pj_ka(pj, "args");
	}
	int maxargs = rz_analysis_cc_max_arg(core->analysis, cc);
	for (int i = 0; i < maxargs; i++) {
		regname = rz_analysis_cc_arg(core->analysis, cc, i);
		if (pj) {
			pj_s(pj, regname);
		} else {
			rz_cons_printf("arg%d: %s\n", i, regname);
		}
	}
	if (pj) {
		pj_end(pj);
	}
	regname = rz_analysis_cc_self(core->analysis, cc);
	if (regname) {
		if (pj) {
			pj_ks(pj, "self", regname);
		} else {
			rz_cons_printf("self: %s\n", regname);
		}
	}
	regname = rz_analysis_cc_error(core->analysis, cc);
	if (regname) {
		if (pj) {
			pj_ks(pj, "error", regname);
		} else {
			rz_cons_printf("error: %s\n", regname);
		}
	}
	if (pj) {
		pj_end(pj);
	}
}

/**
 * \brief Start ESIL trace session
 *
 * \param core The RzCore instance
 * \return false when an error occurs otherwise true
 */
RZ_API bool rz_core_analysis_esil_trace_start(RzCore *core) {
	RzAnalysisEsil *esil = core->analysis->esil;
	if (!esil) {
		RZ_LOG_ERROR("ESIL is not initialized. Use `aeim` first.\n");
		return false;
	}
	if (esil->trace) {
		RZ_LOG_ERROR("ESIL trace already started\n");
		return false;
	}
	esil->trace = rz_analysis_esil_trace_new(esil);
	if (!esil->trace) {
		return false;
	}
	rz_config_set_i(core->config, "dbg.trace", true);
	return true;
}

/**
 * \brief Stop ESIL trace session
 *
 * \param core The RzCore instance
 * \return false when an error occurs otherwise true
 */
RZ_API bool rz_core_analysis_esil_trace_stop(RzCore *core) {
	RzAnalysisEsil *esil = core->analysis->esil;
	if (!esil) {
		RZ_LOG_ERROR("ESIL is not initialized. Use `aeim` first.\n");
		return false;
	}
	if (!esil->trace) {
		RZ_LOG_ERROR("No ESIL trace started\n");
		return false;
	}
	rz_analysis_esil_trace_free(esil->trace);
	esil->trace = NULL;
	rz_config_set_i(core->config, "dbg.trace", false);
	return true;
}

static void analysis_bytes_fini(RZ_NULLABLE void *ptr) {
	if (!ptr) {
		return;
	}
	RzAnalysisBytes *ab = ptr;
	rz_analysis_op_free(ab->op);
	rz_analysis_hint_free(ab->hint);
	free(ab->opcode);
	free(ab->disasm);
	free(ab->pseudo);
	free(ab->description);
	free(ab->mask);
	free(ab->bytes);
}

/**
 * Free RzAnalysisBytes
 *
 * \param ptr RzAnalysisBytes pointer
 */
RZ_API void rz_analysis_bytes_free(RZ_NULLABLE void *ptr) {
	if (!ptr) {
		return;
	}
	analysis_bytes_fini(ptr);
	free(ptr);
}

static ut64 analysis_bytes_oplen(RzCore *core, const ut8 *ptr, ut64 addr, int len, int min_op_size, int mask) {
	int oplen = 0;
	RzAsmOp asmop;
	RzAnalysisOp op;
	rz_asm_op_init(&asmop);
	rz_asm_set_pc(core->rasm, addr);
	rz_analysis_op_init(&op);
	int reta = rz_analysis_op(core->analysis, &op, addr, ptr, len, mask);
	rz_analysis_op_fini(&op);
	int ret = rz_asm_disassemble(core->rasm, &asmop, ptr, len);
	if (reta < 1 || ret < 1) {
		return min_op_size;
	}
	oplen = rz_asm_op_get_size(&asmop);
	rz_core_asm_bb_middle(core, addr, &oplen, &ret);
	return oplen;
}

/**
 *
 * Analyze and disassemble bytes use rz_analysis_op and rz_asm_disassemble
 * and return how many bytes were consumed
 *
 * \param core The RzCore instance
 * \param buf data to analysis
 * \param len analysis len bytes
 * \param nops analysis n ops
 * \return amount of the bytes consumed
 */
RZ_API ut64 rz_core_analysis_ops_size(
	RZ_NONNULL RzCore *core, ut64 start_addr, RZ_NONNULL const ut8 *buf, ut64 len, ut64 nops) {
	static const int mask = RZ_ANALYSIS_OP_MASK_HINT;
	int min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	ut64 end_offset = start_addr + len;
	ut64 offset = start_addr;
	int consumed = 0;
	int remain = len;
	while (offset < end_offset && nops > 0) {
		const ut8 *ptr = buf + consumed;
		remain = len - consumed;
		consumed += analysis_bytes_oplen(core, ptr, offset, remain, min_op_size, mask);
		offset += consumed;
		nops--;
	}
	return consumed;
}

typedef struct {
	RzCore *core;
	int max_op_size;
	ut64 len;
	ut64 nops;
	ut8 *buf;
	ut64 begin;
	ut64 offset;
	ut64 iops;
	RzAnalysisOp op;
	RzAnalysisOpMask mask;
} AnalysisOpContext;

static void AnalysisOpContext_fini(void *x) {
	if (!x) {
		return;
	}
	AnalysisOpContext *ctx = x;
	rz_analysis_op_fini(&ctx->op);
	free(ctx->buf);
}

static void AnalysisOpContext_free(void *x) {
	if (!x) {
		return;
	}
	AnalysisOpContext_fini(x);
	free(x);
}

typedef struct {
	AnalysisOpContext inner;
	RzAnalysisBytes ab;
	RzAsmOp asmop;
	const ut8 *buf;
	int min_op_size;
	bool bigendian;
	bool asm_sub_var;
	char asm_buff[512];
	char disasm[512];
	char opcode[512];
	char pseudo[512];
	char mnemonic[512];
} AnalysisBytesContext;

static void *AnalysisBytesContext_next(RzIterator *it) {
	AnalysisBytesContext *ctx = it->u;
	AnalysisOpContext *inner = &ctx->inner;
	RzCore *core = inner->core;
	if ((inner->offset >= inner->len) || (inner->nops && (inner->iops >= inner->nops))) {
		return NULL;
	}
	RzAsmOp *asmop = &ctx->asmop;
	RzAnalysisBytes *ab = &ctx->ab;
	RzAnalysisOp *op = ab->op = &inner->op;

	ut64 addr = inner->begin + inner->offset;
	ut64 remain = inner->len - inner->offset;
	const ut8 *ptr = ctx->buf + inner->offset;

	rz_asm_op_fini(asmop);
	rz_asm_op_init(asmop);
	op->mnemonic = NULL;
	rz_analysis_op_fini(op);
	rz_analysis_op_init(op);

	rz_asm_set_pc(core->rasm, addr);
	ab->hint = rz_analysis_hint_get(core->analysis, addr);
	int reta = rz_analysis_op(core->analysis, op, addr, ptr, remain, inner->mask);
	int ret = rz_asm_disassemble(core->rasm, asmop, ptr, remain);
	if (reta < 1 || ret < 1) {
		ab->oplen = ctx->min_op_size;
		ab->opcode = "invalid";
		ab->disasm = "invalid";
		ab->bytes = rz_asm_op_get_hex(asmop);
		goto out;
	}
	ab->oplen = rz_asm_op_get_size(asmop);

	if (core->parser->subrel) {
		ut64 subrel_addr = UT64_MAX;
		if (rz_io_read_i(core->io, op->ptr, &subrel_addr, op->refptr, ctx->bigendian)) {
			core->parser->subrel_addr = subrel_addr;
		}
	}

	const char *an_asm = rz_asm_op_get_asm(asmop);
	strcpy(ctx->opcode, an_asm);
	ab->opcode = ctx->opcode;
	strcpy(ctx->mnemonic, an_asm);
	char *mnem = ctx->mnemonic;
	char *sp = strchr(mnem, ' ');
	if (sp) {
		*sp = 0;
		if (op->prefix) {
			char *p = strchr(sp + 1, ' ');
			*p = 0;
			memmove(ctx->mnemonic, sp + 1, p - sp);
		}
	}
	op->mnemonic = mnem;

	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	strcpy(ctx->asm_buff, an_asm);

	if (ctx->asm_sub_var) {
		rz_parse_subvar(core->parser, fcn, op,
			ctx->asm_buff, ctx->asm_buff, sizeof(asmop->buf_asm));
	}

	rz_parse_filter(core->parser, addr, core->flags, ab->hint,
		ctx->asm_buff, ctx->disasm, sizeof(ctx->disasm), ctx->bigendian);
	rz_asm_op_set_asm(asmop, ctx->asm_buff);

	ab->disasm = ctx->disasm;
	rz_core_asm_bb_middle(core, addr, &ab->oplen, &ret);

	// apply pseudo if needed
	ab->pseudo = rz_parse_pseudocode(core->parser, ctx->disasm);
	ab->description = rz_asm_describe(core->rasm, op->mnemonic);

	ut8 *amask = rz_analysis_mask(core->analysis, remain, ptr, addr);
	ab->mask = rz_hex_bin2strdup(amask, ab->oplen);
	free(amask);

	ab->bytes = rz_asm_op_get_hex(asmop);

out:
	inner->offset += ab->oplen;
	++inner->iops;
	return ab;
}

static void AnalysisBytesContext_free(void *x) {
	if (!x) {
		return;
	}
	AnalysisBytesContext *ctx1 = x;
	AnalysisOpContext *inner = &ctx1->inner;
	inner->op.mnemonic = NULL;

	AnalysisOpContext_fini(inner);
	rz_asm_op_fini(&ctx1->asmop);
	free(x);
}

static void RzAnalysisBytes_free_mod(void *x) {
	if (!x) {
		return;
	}
	RzAnalysisBytes *ab = x;
	ab->op = NULL;
	ab->disasm = NULL;
	ab->opcode = NULL;
	ab->pseudo = NULL;
	analysis_bytes_fini(ab);
	memset(ab, 0, sizeof(RzAnalysisBytes));
}
/**
 *
 * Analyze and disassemble bytes use rz_analysis_op and rz_asm_disassemble
 *
 * \param core The RzCore instance
 * \param buf data to analysis
 * \param len analysis len bytes
 * \param nops analysis n ops
 * \return RzIterator of RzAnalysisBytes
 */
RZ_API RZ_OWN RzIterator *rz_core_analysis_bytes(
	RZ_NONNULL RzCore *core, ut64 start_addr, RZ_NONNULL const ut8 *buf, ut64 len, ut64 nops) {
	rz_return_val_if_fail(core && buf, NULL);

	static const int mask = RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_HINT;
	int min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);

	core->parser->subrel = rz_config_get_i(core->config, "asm.sub.rel");
	core->parser->localvar_only = rz_config_get_i(core->config, "asm.sub.varonly");

	AnalysisBytesContext *ctx = RZ_NEW0(AnalysisBytesContext);
	ctx->bigendian = rz_config_get_b(core->config, "cfg.bigendian");
	ctx->asm_sub_var = rz_config_get_i(core->config, "asm.sub.var");
	ctx->min_op_size = min_op_size;
	ctx->buf = buf;

	ctx->inner.core = core;
	ctx->inner.mask = mask;
	ctx->inner.begin = start_addr;
	ctx->inner.nops = nops;
	ctx->inner.len = len;

	return rz_iterator_new(AnalysisBytesContext_next, RzAnalysisBytes_free_mod, AnalysisBytesContext_free, ctx);
}

static void *analysis_op_next(RzIterator *it) {
	AnalysisOpContext *ctx = it->u;
	if ((ctx->offset >= ctx->len) || (ctx->nops && (ctx->iops >= ctx->nops))) {
		return NULL;
	}

	ut64 addr = ctx->begin + ctx->offset;
	ut8 *ptr = ctx->buf + ctx->offset;
	ut64 remain = ctx->len - ctx->offset;

	rz_analysis_op_fini(&ctx->op);
	rz_analysis_op_init(&ctx->op);
	if (rz_analysis_op(ctx->core->analysis, &ctx->op, addr, ptr, remain, ctx->mask) < 1) {
		RZ_LOG_ERROR("Invalid instruction at 0x%08" PFMT64x "...\n", addr);
		return NULL;
	}

	ctx->offset += ctx->op.size;
	++ctx->iops;
	return &ctx->op;
}

/**
 * \brief Parse \p len bytes and \p nops RzAnalysisOps,
 *        restricted by \p len and \p nops at the same time
 *
 * \param core RzCore
 * \param len Maximum length read from \p buf in bytes. set to 0 to disable it (only use \p nops).
 * \param nops Maximum number of instruction, set to 0 to disable it (only use \p len).
 * \param mask The which analysis details should be disassembled.
 * \return RzIterator of RzAnalysisOp
 */
RZ_API RZ_OWN RzIterator *rz_core_analysis_op_chunk_iter(
	RZ_NONNULL RzCore *core, ut64 offset, ut64 len, ut64 nops, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(core, NULL);

	int max_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	max_op_size = max_op_size > 0 ? max_op_size : 32;
	len = len > 0 ? len : nops * max_op_size;

	if (len == 0 && nops == 0) {
		return NULL;
	}

	AnalysisOpContext *ctx = NULL;
	ut8 *buf = RZ_NEWS0(ut8, len);
	if (!buf) {
		goto cleanup;
	}
	ctx = RZ_NEW0(AnalysisOpContext);
	if (!ctx) {
		goto cleanup;
	}
	if (!rz_io_read_at(core->io, offset, buf, len)) {
		goto cleanup;
	}

	ctx->core = core;
	ctx->nops = nops;
	ctx->max_op_size = max_op_size;
	ctx->mask = mask;
	ctx->buf = buf;
	ctx->len = len;
	ctx->begin = offset;

	return rz_iterator_new(analysis_op_next, NULL, AnalysisOpContext_free, ctx);
cleanup:
	free(buf);
	free(ctx);
	return NULL;
}

/**
 * \brief Parse RzAnalysisOps of function at core->offset
 *
 * \param core RzCore
 * \param fcn Pointer to `RzAnalysisFunction` used to analysis.
 * \param mask The which analysis details should be disassembled.
 * \return RzIterator of RzAnalysisOp
 */
RZ_API RZ_OWN RzIterator *rz_core_analysis_op_function_iter(RZ_NONNULL RzCore *core, RZ_NONNULL RZ_BORROW RzAnalysisFunction *fcn, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(core && fcn, NULL);

	RzIterator *ops = NULL;
	ut64 start = fcn->addr;
	ut64 end = rz_analysis_function_max_addr(fcn);
	if (end <= start) {
		RZ_LOG_ERROR("Cannot print function because the end offset is less or equal to the start offset\n");
		goto exit;
	}
	ut64 size = end - start;
	ops = rz_core_analysis_op_chunk_iter(core, start, size, 0, mask);
exit:
	return ops;
}

/**
 * \brief Set analysis hint for the first immediate of the instruction at current offset to \p struct_member.
 * \param core The RzCore instance
 * \param struct_member struct.member
 */
RZ_API bool rz_core_analysis_hint_set_offset(RZ_NONNULL RzCore *core, RZ_NONNULL const char *struct_member) {
	rz_return_val_if_fail(core && struct_member, false);
	RzAnalysisOp op = { 0 };
	ut8 code[128] = { 0 };
	if (!rz_io_read_at(core->io, core->offset, code, sizeof(code))) {
		return false;
	}
	bool res = false;
	rz_analysis_op_init(&op);
	int ret = rz_analysis_op(core->analysis, &op, core->offset, code, sizeof(code), RZ_ANALYSIS_OP_MASK_VAL);
	if (ret < 1) {
		goto exit;
	}
	// HACK: Just convert only the first imm seen
	ut64 offimm = 0;
	for (int i = 0; i < 3; i++) {
		if (op.src[i]) {
			if (op.src[i]->imm) {
				offimm = op.src[i]->imm;
			} else if (op.src[i]->delta) {
				offimm = op.src[i]->delta;
			}
		}
	}
	if (!offimm && op.dst) {
		if (op.dst->imm) {
			offimm = op.dst->imm;
		} else if (op.dst->delta) {
			offimm = op.dst->delta;
		}
	}
	if (!offimm) {
		goto exit;
	}
	// TODO: Allow to select from multiple choices
	RzList *otypes = rz_type_db_get_by_offset(core->analysis->typedb, offimm);
	RzListIter *iter;
	RzTypePath *tpath;
	rz_list_foreach (otypes, iter, tpath) {
		// TODO: Support also arrays and pointers
		if (tpath->typ->kind == RZ_TYPE_KIND_IDENTIFIER) {
			if (!strcmp(struct_member, tpath->path)) {
				rz_analysis_hint_set_offset(core->analysis, core->offset, tpath->path);
				break;
			}
		}
	}
	rz_list_free(otypes);
	res = true;
exit:
	rz_analysis_op_fini(&op);
	return res;
}

/**
 * \brief Continue until syscall
 * \param core The RzCore instance
 * \return success
 */
RZ_API bool rz_core_analysis_continue_until_syscall(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core, false);
	const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	RzAnalysisOp *op = NULL;
	while (!rz_cons_is_breaked()) {
		if (!rz_core_esil_step(core, UT64_MAX, NULL, NULL, false)) {
			break;
		}
		rz_core_reg_update_flags(core);
		ut64 addr = rz_num_get(core->num, pc);
		op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
		if (!op) {
			break;
		}
		if (op->type == RZ_ANALYSIS_OP_TYPE_SWI) {
			RZ_LOG_ERROR("syscall at 0x%08" PFMT64x "\n", addr);
			break;
		} else if (op->type == RZ_ANALYSIS_OP_TYPE_TRAP) {
			RZ_LOG_ERROR("trap at 0x%08" PFMT64x "\n", addr);
			break;
		}
		rz_analysis_op_free(op);
		op = NULL;
		if (core->analysis->esil->trap || core->analysis->esil->trap_code) {
			break;
		}
	}
	rz_analysis_op_free(op);
	return true;
}

/**
 * \brief Continue until call
 * \param core The RzCore instance
 * \return success
 */
RZ_API bool rz_core_analysis_continue_until_call(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core, false);
	const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	RzAnalysisOp *op = NULL;
	while (!rz_cons_is_breaked()) {
		if (!rz_core_esil_step(core, UT64_MAX, NULL, NULL, false)) {
			break;
		}
		rz_core_reg_update_flags(core);
		ut64 addr = rz_num_get(core->num, pc);
		op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC);
		if (!op) {
			break;
		}
		if (op->type == RZ_ANALYSIS_OP_TYPE_CALL || op->type == RZ_ANALYSIS_OP_TYPE_UCALL) {
			RZ_LOG_ERROR("call at 0x%08" PFMT64x "\n", addr);
			break;
		}
		rz_analysis_op_free(op);
		op = NULL;
		if (core->analysis->esil->trap || core->analysis->esil->trap_code) {
			break;
		}
	}
	rz_analysis_op_free(op);
	return true;
}

/**
 * \brief Compute analysis coverage count
 */
RZ_API st64 rz_core_analysis_coverage_count(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core && core->analysis, ST64_MAX);
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	st64 cov = 0;
	cov += (st64)rz_meta_get_size(core->analysis, RZ_META_TYPE_DATA);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (map->perm & RZ_PERM_X) {
				ut64 section_end = map->itv.addr + map->itv.size;
				ut64 s = rz_analysis_function_realsize(fcn);
				if (fcn->addr >= map->itv.addr && (fcn->addr + s) < section_end) {
					cov += (st64)s;
				}
			}
		}
	}
	return cov;
}

/**
 * \brief Compute analysis code count
 */
RZ_API st64 rz_core_analysis_code_count(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core, ST64_MAX);
	st64 code = 0;
	void **it;
	RzPVector *maps = rz_io_maps(core->io);
	rz_pvector_foreach (maps, it) {
		RzIOMap *map = *it;
		if (map->perm & RZ_PERM_X) {
			code += (st64)map->itv.size;
		}
	}
	return code;
}

/**
 * \brief Compute analysis function xrefs count
 */
RZ_API st64 rz_core_analysis_calls_count(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core && core->analysis, ST64_MAX);
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	st64 cov = 0;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		if (xrefs) {
			cov += rz_list_length(xrefs);
			rz_list_free(xrefs);
		}
	}
	return cov;
}

static const char *RzCoreAnalysisNameTypeStrs[] = {
	"var",
	"function",
	"flag",
	"address",
};

/**
 * \brief Convert \p typ to string (const char*)
 */
RZ_API RZ_BORROW const char *rz_core_analysis_name_type_to_str(RzCoreAnalysisNameType typ) {
	switch (typ) {
	case RZ_CORE_ANALYSIS_NAME_TYPE_VAR:
	case RZ_CORE_ANALYSIS_NAME_TYPE_FUNCTION:
	case RZ_CORE_ANALYSIS_NAME_TYPE_FLAG:
	case RZ_CORE_ANALYSIS_NAME_TYPE_ADDRESS:
		return RzCoreAnalysisNameTypeStrs[typ];
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

RZ_API void rz_core_analysis_name_free(RZ_NULLABLE RzCoreAnalysisName *p) {
	if (!p) {
		return;
	}
	free(p->name);
	free(p->realname);
	free(p);
}

/**
 * \brief Rename whatever var/flag/function is used at \p addr to \p name
 * \return success?
 */
RZ_API bool rz_core_analysis_rename(RZ_NONNULL RzCore *core, RZ_NONNULL const char *name, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis && RZ_STR_ISNOTEMPTY(name), false);

	ut8 buf[128];
	if (!rz_io_read_at(core->io, addr, buf, sizeof(buf))) {
		return false;
	}

	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	rz_analysis_op(core->analysis, &op, core->offset,
		buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
	RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, op.addr);
	ut64 tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
	rz_analysis_op_fini(&op);

	bool result = false;
	if (var) {
		result = rz_analysis_var_rename(var, name, true);
	} else if (tgt_addr != UT64_MAX) {
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, tgt_addr);
		RzFlagItem *f = rz_flag_get_i(core->flags, tgt_addr);
		if (fcn) {
			result = rz_core_analysis_function_rename(core, tgt_addr, name);
		} else if (f) {
			result = rz_flag_rename(core->flags, f, name);
		} else {
			result = rz_flag_set(core->flags, name, tgt_addr, 1);
		}
	}

	return result;
}

/**
 * \brief Get information on whatever var/flag/function is used at \p addr
 * \return RzAnalysisName
 */
RZ_API RZ_OWN RzCoreAnalysisName *rz_core_analysis_name(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);

	ut8 buf[128];
	if (!rz_io_read_at(core->io, addr, buf, sizeof(buf))) {
		return NULL;
	}

	RzCoreAnalysisName *p = RZ_NEW0(RzCoreAnalysisName);
	if (!p) {
		return NULL;
	}

	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	rz_analysis_op(core->analysis, &op, core->offset,
		buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
	RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, op.addr);
	ut64 tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
	rz_analysis_op_fini(&op);

	if (var) {
		p->type = RZ_CORE_ANALYSIS_NAME_TYPE_VAR;
		p->name = strdup(var->name);
		p->offset = op.addr;
	} else if (tgt_addr != UT64_MAX) {
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, tgt_addr);
		RzFlagItem *f = rz_flag_get_i(core->flags, tgt_addr);
		if (fcn) {
			p->type = RZ_CORE_ANALYSIS_NAME_TYPE_FUNCTION;
			p->name = strdup(fcn->name);
			p->offset = tgt_addr;
		} else if (f) {
			p->type = RZ_CORE_ANALYSIS_NAME_TYPE_FLAG;
			p->name = strdup(f->name);
			p->realname = strdup(f->realname);
			p->offset = tgt_addr;
		} else {
			p->type = RZ_CORE_ANALYSIS_NAME_TYPE_ADDRESS;
			p->offset = tgt_addr;
		}
	} else {
		rz_core_analysis_name_free(p);
		return NULL;
	}

	return p;
}

static void _analysis_calls(RzCore *core, ut64 addr, ut64 addr_end, bool imports_only) {
	RzAnalysisOp op = { 0 };
	int depth = rz_config_get_i(core->config, "analysis.depth");
	const int addrbytes = core->io->addrbytes;
	const int bsz = 4096;
	int bufi = 0;
	int bufi_max = bsz - 16;
	if (addr_end - addr > UT32_MAX) {
		return;
	}
	ut8 *buf = malloc(bsz);
	ut8 *block0 = calloc(1, bsz);
	ut8 *block1 = malloc(bsz);
	if (!buf || !block0 || !block1) {
		RZ_LOG_ERROR("core: cannot allocate buf or block\n");
		free(buf);
		free(block0);
		free(block1);
		return;
	}
	memset(block1, -1, bsz);
	int minop = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	if (minop < 1) {
		minop = 1;
	}
	int setBits = rz_config_get_i(core->config, "asm.bits");
	rz_cons_break_push(NULL, NULL);
	while (addr < addr_end && !rz_cons_is_breaked()) {
		// TODO: too many ioreads here
		if (bufi > bufi_max) {
			bufi = 0;
		}
		if (!bufi) {
			(void)rz_io_read_at(core->io, addr, buf, bsz);
		}
		if (!memcmp(buf, block0, bsz) || !memcmp(buf, block1, bsz)) {
			// eprintf ("Error: skipping uninitialized block \n");
			addr += bsz;
			continue;
		}
		RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, addr);
		if (hint && hint->bits) {
			setBits = hint->bits;
		}
		rz_analysis_hint_free(hint);
		if (setBits != core->rasm->bits) {
			rz_config_set_i(core->config, "asm.bits", setBits);
		}
		rz_analysis_op_init(&op);
		if (rz_analysis_op(core->analysis, &op, addr, buf + bufi, bsz - bufi, 0) > 0) {
			if (op.size < 1) {
				op.size = minop;
			}
			if (op.type == RZ_ANALYSIS_OP_TYPE_CALL) {
				bool isValidCall = true;
				if (imports_only) {
					RzFlagItem *f = rz_flag_get_i(core->flags, op.jump);
					if (!f || !strstr(f->name, "imp.")) {
						isValidCall = false;
					}
				}
				RzBinReloc *rel = rz_core_getreloc(core, addr, op.size);
				if (rel && (rel->import || rel->symbol)) {
					isValidCall = false;
				}
				if (isValidCall) {
					ut8 buf[4];
					rz_io_read_at(core->io, op.jump, buf, 4);
					isValidCall = memcmp(buf, "\x00\x00\x00\x00", 4);
				}
				if (isValidCall) {
					// add xref here
					rz_analysis_xrefs_set(core->analysis, addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CALL);
					if (rz_io_is_valid_offset(core->io, op.jump, 1)) {
						rz_core_analysis_fcn(core, op.jump, addr, RZ_ANALYSIS_XREF_TYPE_CALL, depth);
					}
				}
			}
		} else {
			op.size = minop;
		}
		if ((int)op.size < 1) {
			op.size = minop;
		}
		addr += op.size;
		bufi += addrbytes * op.size;
		rz_analysis_op_fini(&op);
	}
	rz_cons_break_pop();
	free(buf);
	free(block0);
	free(block1);
}

/*
 * \brief Performs analysis on each call sight, creates new functions whenever necessary.
 * \param core RzCore instance
 * \param imports_only if true it analyses calls only of imported functions, otherwise - every flag
 */
RZ_API void rz_core_analysis_calls(RZ_NONNULL RzCore *core, bool imports_only) {
	rz_return_if_fail(core);

	RzList *ranges = NULL;
	RzIOMap *r;
	ut64 addr;
	RzBinFile *binfile = rz_bin_cur(core->bin);
	addr = core->offset;
	if (binfile) {
		ranges = rz_core_get_boundaries_prot(core, RZ_PERM_X, NULL, "analysis");
	}
	rz_cons_break_push(NULL, NULL);
	if (!binfile || rz_list_length(ranges) < 1) {
		RzListIter *iter;
		RzIOMap *map;
		rz_list_free(ranges);
		ranges = rz_core_get_boundaries_prot(core, 0, NULL, "analysis");
		if (ranges) {
			rz_list_foreach (ranges, iter, map) {
				ut64 addr = map->itv.addr;
				_analysis_calls(core, addr, rz_itv_end(map->itv), imports_only);
			}
		}
	} else {
		RzListIter *iter;
		if (binfile) {
			rz_list_foreach (ranges, iter, r) {
				addr = r->itv.addr;
				// this normally will happen on fuzzed binaries, dunno if with huge
				// binaries as well
				if (rz_cons_is_breaked()) {
					break;
				}
				_analysis_calls(core, addr, rz_itv_end(r->itv), imports_only);
			}
		}
	}
	rz_cons_break_pop();
	rz_list_free(ranges);
}

/**
 * Try to guess the address of the instruction before addr
 */
RZ_IPI ut64 rz_core_prevop_addr_heuristic(RzCore *core, ut64 addr) {
#define OPDELTA 32
	ut8 buf[OPDELTA * 2];
	ut64 target, base;
	RzAnalysisBlock *bb;
	RzAnalysisOp op = { 0 };
	int len, ret, i;
	int minop = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	int maxop = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);

	if (minop == maxop) {
		if (minop == -1) {
			return addr - 4;
		}
		return addr - minop;
	}

	// let's see if we can use analysis info to get the previous instruction
	// TODO: look in the current basicblock, then in the current function
	// and search in all functions only as a last chance, to try to speed
	// up the process.
	bb = rz_analysis_find_most_relevant_block_in(core->analysis, addr - minop);
	if (bb) {
		ut64 res = rz_analysis_block_get_op_addr_in(bb, addr - minop);
		if (res != UT64_MAX) {
			return res;
		}
	}
	// if we analysis info didn't help then fallback to the dumb solution.
	int midflags = rz_config_get_i(core->config, "asm.flags.middle");
	target = addr;
	base = target > OPDELTA ? target - OPDELTA : 0;
	rz_io_read_at(core->io, base, buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++) {
		rz_analysis_op_init(&op);
		ret = rz_analysis_op(core->analysis, &op, base + i,
			buf + i, sizeof(buf) - i, RZ_ANALYSIS_OP_MASK_BASIC);
		if (ret > 0) {
			len = op.size;
			if (len < 1) {
				len = 1;
			}
			if (midflags >= RZ_MIDFLAGS_REALIGN) {
				int skip_bytes = rz_core_flag_in_middle(core, base + i, len, &midflags);
				if (skip_bytes && base + i + skip_bytes < target) {
					i += skip_bytes - 1;
					rz_analysis_op_fini(&op);
					continue;
				}
			}
		} else {
			len = 1;
		}
		rz_analysis_op_fini(&op);
		if (target <= base + i + len) {
			return base + i;
		}
		i += len - 1;
	}
	return target > 4 ? target - 4 : 0;
}

/**
 * Search of the numinstrs-th instruction before start_addr.
 *
 * Sets prev_addr to the value of the instruction numinstrs back.
 * If we can't use the analysis, then sets prev_addr to UT64_MAX and returns false
 *
 * \return if analysis was able to find the previous instruction address
 */
RZ_API bool rz_core_prevop_addr(RzCore *core, ut64 start_addr, int numinstrs, RZ_OUT RZ_BORROW RZ_NONNULL ut64 *prev_addr) {
	rz_return_val_if_fail(core && prev_addr, false);
	RzAnalysisBlock *bb;
	int i;
	// Check that we're in a bb, otherwise this prevop stuff won't work.
	bb = rz_analysis_find_most_relevant_block_in(core->analysis, start_addr);
	if (bb) {
		if (rz_analysis_block_get_op_addr_in(bb, start_addr) != UT64_MAX) {
			// Do some analysis looping.
			for (i = 0; i < numinstrs; i++) {
				*prev_addr = rz_core_prevop_addr_heuristic(core, start_addr);
				start_addr = *prev_addr;
			}
			return true;
		}
	}
	// Dang! not in a bb, return false and fallback to other methods.
	*prev_addr = UT64_MAX;
	return false;
}

/**
 * Like rz_core_prevop_addr(), but also uses heuristics as fallback if
 * no concrete analysis info is available.
 */
RZ_API ut64 rz_core_prevop_addr_force(RzCore *core, ut64 start_addr, int numinstrs) {
	rz_return_val_if_fail(core, UT64_MAX);
	for (int i = 0; i < numinstrs; i++) {
		start_addr = rz_core_prevop_addr_heuristic(core, start_addr);
	}
	return start_addr;
}

/**
 * \brief Check if core is debugging.
 * \param core RzCore instance performing analysis.
 * \return true if core is debugging, false otherwise.
 * */
RZ_API bool rz_core_is_debugging(RZ_NONNULL RzCore *core) {
	return core && core->io && core->io->desc && core->io->desc->plugin && core->io->desc->plugin->isdbg;
}

/**
 * \brief Perform auto analysis based on given analysis type.
 * \param core RzCore instance that'll be used to perform the analysis.
 * \param type Analysis type.
 * */
RZ_API void rz_core_perform_auto_analysis(RZ_NONNULL RzCore *core, RzCoreAnalysisType type) {
	rz_return_if_fail(core);

	ut64 old_offset = core->offset;
	const char *notify = "Analyze all flags starting with sym. and entry0 (aa)";
	rz_core_notify_begin(core, "%s", notify);
	rz_cons_break_push(NULL, NULL);
	ut64 timeout = rz_config_get_i(core->config, "analysis.timeout");
	rz_cons_break_timeout(timeout);
	rz_core_analysis_all(core);
	rz_core_notify_done(core, "%s", notify);
	rz_core_task_yield(&core->tasks);

	// set debugger only if is debugging
	char *debugger = NULL;
	if (rz_core_is_debugging(core)) {
		debugger = core->dbg->cur ? strdup(core->dbg->cur->name) : strdup("esil");
	}
	rz_cons_clear_line(1);

	// if type was simple only then don't proceed further
	if (type == RZ_CORE_ANALYSIS_SIMPLE || rz_cons_is_breaked()) {
		goto finish;
	}

	// Run pending analysis immediately after analysis
	// Usefull when running commands with ";" or via rizin -c,-i
	rz_core_analysis_everything(core, type == RZ_CORE_ANALYSIS_EXPERIMENTAL, debugger);
finish:
	rz_core_seek(core, old_offset, true);
	// XXX this shouldnt be called. flags muts be created wheen the function is registered
	rz_core_analysis_flag_every_function(core);
	rz_cons_break_pop();
	RZ_FREE(debugger);
}

/**
 * \brief Get string representation of RzAnalysisVar.
 *
 * \param core RzCore instance
 * \param var RzAnalysisVar to be converted to string
 */
RZ_API RZ_OWN char *rz_core_analysis_var_to_string(RZ_NONNULL RzCore *core, RZ_NONNULL RzAnalysisVar *var) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}

	bool color = rz_config_get_b(core->config, "scr.color");
	bool color_arg = color && rz_config_get_b(core->config, "scr.color.args");
	RzConsPrintablePalette *pal = &core->cons->context->pal;

	const char *pfx = rz_analysis_var_is_arg(var) ? "arg" : "var";
	char *constr = rz_analysis_var_get_constraints_readable(var);
	char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
	rz_strbuf_appendf(sb, "%s%s %s%s%s%s %s%s%s%s@ ",
		color_arg ? pal->func_var : "", pfx,
		color_arg ? pal->func_var_type : "", vartype,
		rz_str_endswith(vartype, "*") ? "" : " ",
		var->name,
		color_arg ? pal->func_var_addr : "",
		constr ? " { " : "",
		constr ? constr : "",
		constr ? "} " : "");
	free(vartype);
	free(constr);
	rz_analysis_var_storage_dump(core->analysis, sb, var, &var->storage);
	return rz_strbuf_drain(sb);
}
