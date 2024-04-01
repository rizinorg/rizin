// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_socket.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_print.h>
#include "core_private.h"
#include "rz_analysis.h"
#include <rz_util/rz_strbuf.h>

#define HASRETRY      1
#define HAVE_LOCALS   1
#define DEFAULT_NARGS 4
#define FLAG_PREFIX   ";-- "

#define COLOR(ds, field)       ((ds)->show_color ? (ds)->core->cons->context->pal.field : "")
#define COLOR_ARG(ds, field)   ((ds)->show_color && (ds)->show_color_args ? (ds)->core->cons->context->pal.field : "")
#define COLOR_CONST(ds, color) ((ds)->show_color ? Color_##color : "")
#define COLOR_RESET(ds)        COLOR_CONST(ds, RESET)

#define DS_ANALYSIS_OP_MASK (RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_ESIL | \
	RZ_ANALYSIS_OP_MASK_VAL | (ds->show_cmt_il ? RZ_ANALYSIS_OP_MASK_IL : 0))

#define ESILISTATE core->analysis->esilinterstate

static const ut8 MAX_OPSIZE = 16;
static const ut8 MIN_OPSIZE = 1;

static const char *rz_vline_a[] = {
	"|", // LINE_VERT
	"|-", // LINE_CROSS
	"-", // LINE_HORIZ
	":", // LINE_UP
	",", // LUP_CORNER
	"\\", // RDWN_CORNER
	"/", // RUP_CORNER
	"`", // LDWN_CORNER
	"->", // ARROW_RIGHT
	"=<", // ARROW_LEFT
	"@", // SELF_LOOP
};

static const char *rz_vline_u[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"─", // LINE_HORIZ
	"╎", // LINE_UP
	// "↑", // LINE_UP
	//"┌", // LUP_CORNER
	"┘", // LUP_CORNER
	"└", // RDWN_CORNER
	"┌", // RUP_CORNER
	"┐", // LDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
	"@", // SELF_LOOP
};

static const char *rz_vline_uc[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"─", // LINE_HORIZ
	// "↑", // LINE_UP
	"╎", // LINE_UP
	// "≀", // LINE_UP
	//"┌", // LUP_CORNER
	"╯", // LUP_CORNER
	"╰", // RDWN_CORNER
	"╭", // RUP_CORNER
	"╮", // LDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
	"@", // SELF_LOOP
};

#define DS_PRE_NONE       0
#define DS_PRE_EMPTY      1
#define DS_PRE_FCN_HEAD   2
#define DS_PRE_FCN_MIDDLE 3
#define DS_PRE_FCN_TAIL   4

// TODO: what about using bit shifting and enum for keys? see librz/util/bitmap.c
// the problem of this is that the fields will be more opaque to bindings, but we will earn some bits
typedef struct {
	RzCore *core;
	char str[1024], strsub[1024];
	bool immtrim;
	bool immstr;
	bool use_esil;
	bool show_color;
	bool show_color_bytes;
	bool show_color_args;
	int colorop;
	int acase;
	bool capitalize;
	bool show_flgoff;
	bool hasMidflag;
	bool hasMidbb;
	int atabs;
	int atabsonce;
	int atabsoff;
	int decode;
	bool pseudo;
	int subnames;
	int interactive;
	bool subjmp;
	bool subvar;
	bool show_lines;
	bool show_lines_bb;
	bool show_lines_ret;
	bool show_lines_call;
	bool show_lines_fcn;
	bool linesright;
	int tracespace;
	int cyclespace;
	int show_indent;
	RzDebugInfoOption debuginfo;

	bool show_size;
	bool show_trace;
	bool show_family;
	bool asm_describe;
	int linesout;
	int adistrick;
	bool asm_meta;
	bool asm_xrefs_code;
	bool asm_instr;
	bool show_offset;
	bool show_offdec; // dupe for rz_print->flags
	bool show_bbline;
	bool show_emu;
	bool pre_emu;
	bool show_emu_str;
	bool show_emu_stroff;
	bool show_emu_strinv;
	bool show_emu_strflag;
	bool show_emu_stack;
	bool show_emu_write;
	bool show_optype;
	bool show_emu_strlea;
	bool show_emu_ssa;
	bool show_section;
	int show_section_col;
	bool flags_inline;
	bool show_section_perm;
	bool show_section_name;
	bool show_symbols;
	int show_symbols_col;
	bool show_flags;
	bool bblined;
	bool show_bytes;
	bool show_bytes_right;
	bool show_reloff;
	bool show_reloff_flags;
	bool show_comments;
	bool show_usercomments;
	bool asm_hints;
	bool asm_hint_jmp;
	bool asm_hint_cdiv;
	bool asm_hint_call;
	bool asm_hint_call_indirect;
	bool asm_hint_lea;
	bool asm_hint_emu;
	int asm_hint_pos;
	ut64 emuptr;
	bool show_slow;
	Sdb *ssa;
	int cmtcol;
	bool show_calls;
	bool show_cmtflgrefs;
	bool show_cmt_esil;
	bool show_cmt_il;
	bool show_cycles;
	bool show_refptr;
	bool show_stackptr;
	int stackFd;
	bool show_xrefs;
	bool show_cmtrefs;
	const char *show_cmtoff;
	bool show_functions;
	bool show_marks;
	bool show_asciidot;
	RzStrEnc strenc;
	int cursor;
	int show_comment_right_default;
	RzSpace *flagspace_ports;
	bool show_flag_in_bytes;
	int lbytes;
	int show_comment_right;
	int pre;
	const char *ocomment;
	int linesopts;
	int lastfail;
	int ocols;
	int lcols;
	int nb, nbytes;
	int show_utf8;
	int lines;
	int oplen;
	bool show_varaccess;
	bool show_vars;
	bool show_fcnsig;
	bool show_fcnsize;
	bool hinted_line;
	int show_varsum;
	const char *fold_var;
	int midflags;
	bool midbb;
	bool midcursor;
	bool show_noisy_comments;
	ut64 asm_highlight;

	RzFlagItem *lastflag;
	RzAnalysisHint *hint;
	RzPrint *print;

	ut64 esil_old_pc;
	ut8 *esil_regstate;
	int esil_regstate_size;
	bool esil_likely;

	int nlines;
	int middle;
	int indent_level;
	int indent_space;
	char *line;
	char *line_col, *prev_line_col;
	char *refline, *refline2;
	char *comment;
	char *opstr;
	char *osl, *sl;
	int index;
	ut64 at, vat, addr, dest;
	int tries, cbytes, idx;
	char chref;
	bool retry;
	RzAsmOp asmop;
	RzAnalysisOp analysis_op;
	RzAnalysisFunction *fcn;
	RzAnalysisFunction *pdf;
	const ut8 *buf;
	int len;
	int maxrefs;
	int foldxrefs;
	char *prev_ins;
	bool prev_ins_eq;
	int prev_ins_count;
	bool show_nodup;
	bool has_description;
	// caches
	char *_tabsbuf;
	int _tabsoff;
	bool showpayloads;
	bool showrelocs;
	int cmtcount;
	bool asm_analysis;
	ut64 printed_str_addr;
	ut64 printed_flag_addr;
	ut64 min_ref_addr;

	PJ *pj; // not null if printing json
	int buf_line_begin;
	const char *strip;
	int maxflags;
	int asm_types;

	bool sparse;

	RzPVector /*<RzAnalysisDisasmText *>*/ *vec;
#if 0 // TODO: remove
	RzFlagItem lastflagitem;
#endif
} RzDisasmState;

static void ds_setup_print_pre(RzDisasmState *ds, bool tail, bool middle);
static void ds_setup_pre(RzDisasmState *ds, bool tail, bool middle);
static void ds_print_pre(RzDisasmState *ds, bool fcnline);
static void ds_pre_line(RzDisasmState *ds);
static void ds_begin_line(RzDisasmState *ds);
static void ds_newline(RzDisasmState *ds);
static void ds_begin_cont(RzDisasmState *ds);
static void ds_print_esil_analysis(RzDisasmState *ds);
static void ds_reflines_init(RzDisasmState *ds);
static void ds_align_comment(RzDisasmState *ds);
static RzDisasmState *ds_init(RzCore *core);
static void ds_build_op_str(RzDisasmState *ds, bool print_color);
static void ds_print_show_bytes(RzDisasmState *ds);
static void ds_pre_xrefs(RzDisasmState *ds, bool no_fcnlines);
static void ds_show_xrefs(RzDisasmState *ds);
static void ds_atabs_option(RzDisasmState *ds);
static void ds_show_functions(RzDisasmState *ds);
static void ds_control_flow_comments(RzDisasmState *ds);
static void ds_adistrick_comments(RzDisasmState *ds);
static void ds_print_comments_right(RzDisasmState *ds);
static void ds_show_comments_right(RzDisasmState *ds);
static void ds_show_flags(RzDisasmState *ds, bool overlapped);
static void ds_update_ref_lines(RzDisasmState *ds);
static int ds_disassemble(RzDisasmState *ds, ut8 *buf, int len);
static void ds_print_lines_right(RzDisasmState *ds);
static void ds_print_lines_left(RzDisasmState *ds);
static void ds_print_cycles(RzDisasmState *ds);
static void ds_print_family(RzDisasmState *ds);
static void ds_print_stackptr(RzDisasmState *ds);
static void ds_print_offset(RzDisasmState *ds);
static void ds_print_op_size(RzDisasmState *ds);
static void ds_print_trace(RzDisasmState *ds);
static void ds_print_opstr(RzDisasmState *ds);
static void ds_print_color_reset(RzDisasmState *ds);
static int ds_print_middle(RzDisasmState *ds, int ret);
static bool ds_print_labels(RzDisasmState *ds, RzAnalysisFunction *f);
static void ds_print_sysregs(RzDisasmState *ds);
static void ds_print_fcn_name(RzDisasmState *ds);
static void ds_print_as_string(RzDisasmState *ds);
static bool ds_print_core_vmode(RzDisasmState *ds, int pos);
static void ds_print_debuginfo(RzDisasmState *ds);
static void ds_print_asmop_payload(RzDisasmState *ds, const ut8 *buf);
static char *ds_esc_str(RzDisasmState *ds, const char *str, int len, const char **prefix_out, bool is_comment);
static void ds_print_ptr(RzDisasmState *ds, int len, int idx);
static void ds_print_str(RzDisasmState *ds, const char *str, int len, ut64 refaddr);
static void ds_opstr_sub_jumps(RzDisasmState *ds);
static void ds_start_line_highlight(RzDisasmState *ds);
static void ds_end_line_highlight(RzDisasmState *ds);
static bool line_highlighted(RzDisasmState *ds);
static int ds_print_shortcut(RzDisasmState *ds, ut64 addr, int pos);
static void ds_asmop_fixup(RzDisasmState *ds);

#define theme_printf(kwd, fmt, ...) rz_cons_printf("%s" fmt "%s", COLOR(ds, kwd), __VA_ARGS__, COLOR_RESET(ds))
#define theme_print(kwd, x) \
	do { \
		rz_cons_print(COLOR(ds, kwd)); \
		rz_cons_print(x); \
		rz_cons_print(COLOR_RESET(ds)); \
	} while (false)
#define theme_print_color(kwd) rz_cons_print(COLOR(ds, kwd))

RZ_API ut64 rz_core_pava(RzCore *core, ut64 addr) {
	if (core->print->pava) {
		RzIOMap *map = rz_io_map_get_paddr(core->io, addr);
		if (map) {
			return addr - map->delta + map->itv.addr;
		}
	}
	return addr;
}

static RzAnalysisFunction *fcnIn(RzDisasmState *ds, ut64 at, int type) {
	if (ds->fcn && rz_analysis_function_contains(ds->fcn, at)) {
		return ds->fcn;
	}
	return rz_analysis_get_fcn_in(ds->core->analysis, at, type);
}

static const char *get_utf8_char(const char line, RzDisasmState *ds) {
	switch (line) {
	case '<': return ds->core->cons->vline[ARROW_LEFT];
	case '>': return ds->core->cons->vline[ARROW_RIGHT];
	case ':': return ds->core->cons->vline[LINE_UP];
	case '|': return ds->core->cons->vline[LINE_VERT];
	case '=':
	case '-': return ds->core->cons->vline[LINE_HORIZ];
	case ',': return ds->core->cons->vline[CORNER_TL];
	case '.': return ds->core->cons->vline[CORNER_TR];
	case '`': return ds->core->cons->vline[CORNER_BL];
	case '@': return ds->core->cons->vline[SELF_LOOP];
	default: return " ";
	}
}

static void ds_print_ref_lines(char *line, char *line_col, RzDisasmState *ds) {
	int i;
	int len = strlen(line);
	if (ds->core->cons->use_utf8 || ds->linesopts & RZ_ANALYSIS_REFLINE_TYPE_UTF8) {
		if (ds->show_color) {
			for (i = 0; i < len; i++) {
				if (line[i] == ' ') {
					rz_cons_printf(" ");
					continue;
				}
				if (line_col[i] == 'd') {
					theme_printf(flow, "%s", get_utf8_char(line[i], ds));
				} else {
					theme_printf(flow2, "%s", get_utf8_char(line[i], ds));
				}
			}
		} else {
			len = strlen(line);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%s", get_utf8_char(line[i], ds));
			}
		}
	} else {
		if (ds->show_color) {
			for (i = 0; i < len; i++) {
				if (line[i] == ' ') {
					rz_cons_printf(" ");
					continue;
				}
				if (line_col[i] == 'd') {
					theme_printf(flow, "%c", line[i]);
				} else {
					theme_printf(flow2, "%c", line[i]);
				}
			}
		} else {
			rz_cons_printf("%s", line);
		}
	}
}

static void get_bits_comment(RzCore *core, RzAnalysisFunction *f, char *cmt, int cmt_size) {
	if (core && f && cmt && cmt_size > 0 && f->bits && f->bits != core->rasm->bits) {
		const char *asm_arch = rz_config_get(core->config, "asm.arch");
		if (asm_arch && *asm_arch && strstr(asm_arch, "arm")) {
			switch (f->bits) {
			case 16: strcpy(cmt, " (thumb)"); break;
			case 32: strcpy(cmt, " (arm)"); break;
			case 64: strcpy(cmt, " (aarch64)"); break;
			}
		} else {
			snprintf(cmt, cmt_size, " (%d bits)", f->bits);
		}
	} else {
		if (cmt) {
			cmt[0] = 0;
		}
	}
}

RZ_API RZ_OWN char *rz_core_get_section_name(RzCore *core, ut64 addr) {
	char *section = NULL;
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	RzBinSection *s = bo ? rz_bin_get_section_at(bo, addr, core->io->va) : NULL;
	if (s && RZ_STR_ISNOTEMPTY(s->name)) {
		return rz_str_dup(s->name);
	} else {
		RzListIter *iter;
		RzDebugMap *map;
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				const char *mn = rz_str_lchr(map->name, '/');
				section = rz_str_dup(mn ? mn + 1 : map->name);
				break;
			}
		}
	}
	return section;
}

// up means if this lines go up, it controls whether to insert `_
// nl if we have to insert new line, it controls whether to insert \n
static void _ds_comment_align_(RzDisasmState *ds, bool up, bool nl) {
	if (ds->show_comment_right) {
		theme_print_color(comment);
		return;
	}
	char *sn = ds->show_section ? rz_core_get_section_name(ds->core, ds->at) : NULL;
	ds_align_comment(ds);
	ds_align_comment(ds);
	rz_cons_print(COLOR_RESET(ds));
	ds_print_pre(ds, true);
	rz_cons_printf("%s%s", nl ? "\n" : "", rz_str_get(sn));
	ds_print_ref_lines(ds->refline, ds->line_col, ds);
	rz_cons_printf("  %s %s", up ? "" : ".-", COLOR(ds, comment));
	free(sn);
}
#define CMT_ALIGN _ds_comment_align_(ds, true, false)

static void ds_comment_lineup(RzDisasmState *ds) {
	CMT_ALIGN;
}

static void ds_comment_(RzDisasmState *ds, bool align, bool nl, const char *format, va_list ap) {
	if (ds->show_comments) {
		if (ds->show_comment_right && align) {
			ds_align_comment(ds);
		} else {
			theme_print_color(comment);
		}
	}

	rz_cons_printf_list(format, ap);
	if (!ds->show_comment_right && nl) {
		ds_newline(ds);
	}
}

static void ds_comment(RzDisasmState *ds, bool align, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	ds->cmtcount++;
	ds_comment_(ds, align, align, format, ap);
	va_end(ap);
}

#define DS_COMMENT_FUNC(name, align, nl) \
	static void ds_comment_##name(RzDisasmState *ds, const char *format, ...) { \
		va_list ap; \
		va_start(ap, format); \
		ds_comment_(ds, align, nl, format, ap); \
		va_end(ap); \
	}

DS_COMMENT_FUNC(start, true, false)
DS_COMMENT_FUNC(middle, false, false)
DS_COMMENT_FUNC(end, false, true)

static void ds_comment_esil(RzDisasmState *ds, bool up, bool end, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	if (ds->show_comments && up) {
		ds->show_comment_right ? ds_align_comment(ds) : ds_comment_lineup(ds);
	}
	rz_cons_printf_list(format, ap);
	va_end(ap);

	if (ds->show_comments && !ds->show_comment_right) {
		if (end) {
			ds_newline(ds);
		}
	}
}

static void ds_print_esil_analysis_fini(RzDisasmState *ds) {
	RzCore *core = ds->core;
	if (ds->show_emu && ds->esil_regstate) {
		RzCore *core = ds->core;
		core->analysis->last_disasm_reg = rz_reg_arena_peek(core->analysis->reg);
		const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
		RzRegSet *regset = rz_reg_regset_get(ds->core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!regset) {
			RZ_LOG_ERROR("core: ESIL: fail to get regset\n");
			RZ_FREE(ds->esil_regstate);
			return;
		}
		if (ds->esil_regstate_size == regset->arena->size) {
			rz_reg_arena_poke(core->analysis->reg, ds->esil_regstate);
		}
		rz_reg_setv(core->analysis->reg, pc, ds->esil_old_pc);
		RZ_FREE(ds->esil_regstate);
	}
	if (core && core->analysis && core->analysis->esil) {
		// make sure to remove reference to ds to avoid UAF
		core->analysis->esil->user = NULL;
	}
}

static void RzBinSourceLineCacheItem_free(RzBinSourceLineCacheItem *x) {
	if (!x) {
		return;
	}
	free(x->file_content);
	rz_pvector_free(x->line_by_ln);
	free(x);
}

static void RzBinSourceLineCacheItem_HtPPKv_free(HtPPKv *x) {
	if (!x) {
		return;
	}
	free(x->key);
	RzBinSourceLineCacheItem_free(x->value);
}

static RzDisasmState *ds_init(RzCore *core) {
	RzDisasmState *ds = RZ_NEW0(RzDisasmState);
	if (!ds) {
		return NULL;
	}
	ds->core = core;
	ds->strip = rz_config_get(core->config, "asm.strip");

	ds->show_color = rz_config_get_i(core->config, "scr.color");
	ds->show_color_bytes = rz_config_get_b(core->config, "scr.color.bytes"); // maybe rename to asm.color.bytes
	ds->show_color_args = rz_config_get_b(core->config, "scr.color.args");
	ds->colorop = rz_config_get_b(core->config, "scr.color.ops"); // XXX confusing name // asm.color.inst (mnemonic + operands) ?
	ds->show_utf8 = rz_config_get_b(core->config, "scr.utf8");

	ds->immstr = rz_config_get_b(core->config, "asm.imm.str");
	ds->immtrim = rz_config_get_b(core->config, "asm.imm.trim");
	ds->use_esil = rz_config_get_b(core->config, "asm.esil");
	ds->pre_emu = rz_config_get_b(core->config, "emu.pre");
	ds->show_flgoff = rz_config_get_b(core->config, "asm.flags.offset");
	ds->show_nodup = rz_config_get_b(core->config, "asm.nodup");
	{
		const char *ah = rz_config_get(core->config, "asm.highlight");
		ds->asm_highlight = (ah && *ah) ? rz_num_math(core->num, ah) : UT64_MAX;
	}
	ds->asm_analysis = rz_config_get_b(core->config, "asm.analysis");
	ds->acase = rz_config_get_b(core->config, "asm.ucase");
	ds->capitalize = rz_config_get_b(core->config, "asm.capitalize");
	ds->atabs = rz_config_get_i(core->config, "asm.tabs");
	ds->atabsonce = rz_config_get_b(core->config, "asm.tabs.once");
	ds->atabsoff = rz_config_get_i(core->config, "asm.tabs.off");
	ds->midflags = rz_config_get_i(core->config, "asm.flags.middle");
	ds->midbb = rz_config_get_b(core->config, "asm.bb.middle");
	ds->midcursor = rz_config_get_b(core->config, "asm.midcursor");
	ds->decode = rz_config_get_b(core->config, "asm.decode");
	core->parser->pseudo = ds->pseudo = rz_config_get_b(core->config, "asm.pseudo");
	if (ds->pseudo) {
		ds->atabs = 0;
	}
	ds->subnames = rz_config_get_b(core->config, "asm.sub.names");
	ds->interactive = rz_cons_is_interactive();
	ds->subjmp = rz_config_get_b(core->config, "asm.sub.jmp");
	ds->subvar = rz_config_get_b(core->config, "asm.sub.var");
	core->parser->subrel = rz_config_get_b(core->config, "asm.sub.rel");
	core->parser->subreg = rz_config_get_b(core->config, "asm.sub.reg");
	core->parser->localvar_only = rz_config_get_b(core->config, "asm.sub.varonly");
	core->parser->retleave_asm = NULL;
	ds->show_fcnsig = rz_config_get_b(core->config, "asm.fcn.signature");
	ds->show_fcnsize = rz_config_get_b(core->config, "asm.fcn.size");
	ds->show_vars = rz_config_get_b(core->config, "asm.var");
	ds->show_varsum = rz_config_get_i(core->config, "asm.var.summary");
	ds->fold_var = rz_config_get(core->config, "asm.var.fold");
	ds->show_varaccess = rz_config_get_b(core->config, "asm.var.access");
	ds->maxrefs = rz_config_get_i(core->config, "asm.xrefs.max");
	ds->maxflags = rz_config_get_i(core->config, "asm.flags.limit");
	ds->flags_inline = rz_config_get_i(core->config, "asm.flags.inline");
	ds->asm_types = rz_config_get_i(core->config, "asm.types");
	ds->foldxrefs = rz_config_get_i(core->config, "asm.xrefs.fold");
	ds->show_lines = rz_config_get_b(core->config, "asm.lines");
	ds->show_lines_bb = ds->show_lines ? rz_config_get_b(core->config, "asm.lines.bb") : false;
	ds->linesright = rz_config_get_b(core->config, "asm.lines.right");
	ds->show_indent = rz_config_get_b(core->config, "asm.indent");
	ds->indent_space = rz_config_get_i(core->config, "asm.indentspace");
	ds->tracespace = rz_config_get_i(core->config, "asm.tracespace");
	ds->cyclespace = rz_config_get_i(core->config, "asm.cyclespace");

	ds->debuginfo.enable = rz_config_get_b(core->config, "asm.debuginfo");
	ds->debuginfo.file = rz_config_get_b(core->config, "asm.debuginfo.file");
	ds->debuginfo.abspath = rz_config_get_b(core->config, "asm.debuginfo.abspath");
	ds->debuginfo.lines = rz_config_get_b(core->config, "asm.debuginfo.lines");
	ds->debuginfo.cache.items = ht_pp_new(NULL, RzBinSourceLineCacheItem_HtPPKv_free, NULL);

	ds->show_lines_call = ds->show_lines ? rz_config_get_b(core->config, "asm.lines.call") : false;
	ds->show_lines_ret = ds->show_lines ? rz_config_get_b(core->config, "asm.lines.ret") : false;
	ds->show_size = rz_config_get_b(core->config, "asm.size");
	ds->show_trace = rz_config_get_b(core->config, "asm.trace");
	ds->linesout = rz_config_get_i(core->config, "asm.lines.out");
	ds->adistrick = rz_config_get_i(core->config, "asm.middle"); // TODO: find better name
	ds->asm_describe = rz_config_get_b(core->config, "asm.describe");
	ds->show_offset = rz_config_get_b(core->config, "asm.offset");
	ds->show_offdec = rz_config_get_b(core->config, "asm.decoff");
	ds->show_bbline = rz_config_get_b(core->config, "asm.bb.line");
	ds->show_section = rz_config_get_b(core->config, "asm.section");
	ds->show_section_col = rz_config_get_i(core->config, "asm.section.col");
	ds->show_section_perm = rz_config_get_b(core->config, "asm.section.perm");
	ds->show_section_name = rz_config_get_b(core->config, "asm.section.name");
	ds->show_symbols = rz_config_get_b(core->config, "asm.symbol");
	ds->show_symbols_col = rz_config_get_i(core->config, "asm.symbol.col");
	ds->asm_instr = rz_config_get_b(core->config, "asm.instr");
	ds->show_emu = rz_config_get_b(core->config, "asm.emu");
	ds->show_emu_str = rz_config_get_b(core->config, "emu.str");
	ds->show_emu_stroff = rz_config_get_b(core->config, "emu.str.off");
	ds->show_emu_strinv = rz_config_get_b(core->config, "emu.str.inv");
	ds->show_emu_strflag = rz_config_get_b(core->config, "emu.str.flag");
	ds->show_emu_strlea = rz_config_get_b(core->config, "emu.str.lea");
	ds->show_emu_write = rz_config_get_b(core->config, "emu.write");
	ds->show_emu_ssa = rz_config_get_b(core->config, "emu.ssa");
	ds->show_emu_stack = rz_config_get_b(core->config, "emu.stack");
	ds->stackFd = -1;
	if (ds->show_emu_stack) {
		// TODO: initialize fake stack in here
		const char *uri = "malloc://32K";
		ut64 size = rz_num_get(core->num, "32K");
		ut64 addr = rz_reg_getv(core->analysis->reg, "SP") - (size / 2);
		ESILISTATE->emustack_min = addr;
		ESILISTATE->emustack_max = addr + size;
		ds->stackFd = rz_io_fd_open(core->io, uri, RZ_PERM_RW, 0);
		RzIOMap *map = rz_io_map_add(core->io, ds->stackFd, RZ_PERM_RW, 0LL, addr, size);
		if (!map) {
			rz_io_fd_close(core->io, ds->stackFd);
			RZ_LOG_ERROR("core: cannot create map for tha stack, fd %d got closed again\n", ds->stackFd);
			ds->stackFd = -1;
		} else {
			rz_io_map_set_name(map, "fake.stack");
		}
	}
	ds->show_flags = rz_config_get_b(core->config, "asm.flags");
	ds->show_bytes = rz_config_get_b(core->config, "asm.bytes");
	ds->show_bytes_right = rz_config_get_b(core->config, "asm.bytes.right");
	ds->show_optype = rz_config_get_b(core->config, "asm.optype");
	ds->asm_meta = rz_config_get_i(core->config, "asm.meta");
	ds->asm_xrefs_code = rz_config_get_i(core->config, "asm.xrefs.code");
	ds->show_reloff = rz_config_get_b(core->config, "asm.reloff");
	ds->show_reloff_flags = rz_config_get_b(core->config, "asm.reloff.flags");
	ds->show_lines_fcn = ds->show_lines ? rz_config_get_b(core->config, "asm.lines.fcn") : false;
	ds->show_comments = rz_config_get_b(core->config, "asm.comments");
	ds->show_usercomments = rz_config_get_b(core->config, "asm.usercomments");
	ds->asm_hint_jmp = rz_config_get_b(core->config, "asm.hint.jmp");
	ds->asm_hint_call = rz_config_get_b(core->config, "asm.hint.call");
	ds->asm_hint_call_indirect = rz_config_get_b(core->config, "asm.hint.call.indirect");
	ds->asm_hint_lea = rz_config_get_b(core->config, "asm.hint.lea");
	ds->asm_hint_emu = rz_config_get_b(core->config, "asm.hint.emu");
	ds->asm_hint_cdiv = rz_config_get_b(core->config, "asm.hint.cdiv");
	ds->asm_hint_pos = rz_config_get_i(core->config, "asm.hint.pos");
	ds->asm_hints = rz_config_get_b(core->config, "asm.hints");
	ds->show_slow = rz_config_get_b(core->config, "asm.slow");
	ds->show_refptr = rz_config_get_b(core->config, "asm.refptr");
	ds->show_calls = rz_config_get_b(core->config, "asm.calls");
	ds->show_family = rz_config_get_b(core->config, "asm.family");
	ds->cmtcol = rz_config_get_i(core->config, "asm.cmt.col");
	ds->show_cmt_esil = rz_config_get_b(core->config, "asm.cmt.esil");
	ds->show_cmt_il = rz_config_get_b(core->config, "asm.cmt.il");
	ds->show_cmtflgrefs = rz_config_get_b(core->config, "asm.cmt.flgrefs");
	ds->show_cycles = rz_config_get_b(core->config, "asm.cycles");
	ds->show_stackptr = rz_config_get_b(core->config, "asm.stackptr");
	ds->show_xrefs = rz_config_get_b(core->config, "asm.xrefs");
	ds->show_cmtrefs = rz_config_get_b(core->config, "asm.cmt.refs");
	ds->show_cmtoff = rz_config_get(core->config, "asm.cmt.off");
	if (!ds->show_cmtoff) {
		ds->show_cmtoff = "nodup";
	}
	ds->show_functions = rz_config_get_b(core->config, "asm.functions");
	ds->nbytes = rz_config_get_i(core->config, "asm.nbytes");
	ds->show_asciidot = !strcmp(core->print->strconv_mode, "asciidot");
	ds->strenc = core->bin->str_search_cfg.string_encoding;
	core->print->bytespace = rz_config_get_i(core->config, "asm.bytes.space");
	ds->cursor = 0;
	ds->nb = 0;
	ds->flagspace_ports = rz_flag_space_get(core->flags, "ports");
	ds->lbytes = rz_config_get_i(core->config, "asm.lbytes");
	ds->show_comment_right_default = rz_config_get_b(core->config, "asm.cmt.right");
	ds->show_comment_right = ds->show_comment_right_default;
	ds->show_flag_in_bytes = rz_config_get_b(core->config, "asm.flags.inbytes");
	ds->show_marks = rz_config_get_b(core->config, "asm.marks");
	ds->show_noisy_comments = rz_config_get_b(core->config, "asm.noisy");
	ds->pre = DS_PRE_NONE;
	ds->ocomment = NULL;
	ds->linesopts = 0;
	ds->lastfail = 0;
	ds->ocols = 0;
	ds->lcols = 0;
	ds->printed_str_addr = UT64_MAX;
	ds->printed_flag_addr = UT64_MAX;

	ds->esil_old_pc = UT64_MAX;
	ds->esil_regstate = NULL;
	ds->esil_likely = false;

	ds->showpayloads = rz_config_get_b(ds->core->config, "asm.payloads");
	ds->showrelocs = rz_config_get_b(core->config, "bin.relocs");
	ds->min_ref_addr = rz_config_get_i(core->config, "asm.sub.varmin");

	if (ds->show_flag_in_bytes) {
		ds->show_flags = false;
	}
	if (rz_config_get_i(core->config, "asm.lines.wide")) {
		ds->linesopts |= RZ_ANALYSIS_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= RZ_ANALYSIS_REFLINE_TYPE_UTF8;
		}
	}
	if (ds->show_lines_bb) {
		ds->ocols += 10; // XXX
	}
	if (ds->show_offset) {
		ds->ocols += 14;
	}
	ds->lcols = ds->ocols + 2;
	if (ds->show_bytes) {
		ds->ocols += 20;
	}
	if (ds->show_trace) {
		ds->ocols += 8;
	}
	if (ds->show_stackptr) {
		ds->ocols += 4;
	}
	/* disasm */ ds->ocols += 20;
	ds->nb = ds->nbytes ? (1 + ds->nbytes * 2) : 0;
	ds->tries = 3;
	if (core->print->cur_enabled) {
		if (core->print->cur < 0) {
			core->print->cur = 0;
		}
		ds->cursor = core->print->cur;
	} else {
		ds->cursor = -1;
	}
	if (rz_config_get_b(core->config, "asm.lines.wide")) {
		ds->linesopts |= RZ_ANALYSIS_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= RZ_ANALYSIS_REFLINE_TYPE_UTF8;
		}
	}
	return ds;
}

static void ds_reflines_fini(RzDisasmState *ds) {
	RzAnalysis *analysis = ds->core->analysis;
	rz_list_free(analysis->reflines);
	analysis->reflines = NULL;
	RZ_FREE(ds->refline);
	RZ_FREE(ds->refline2);
	RZ_FREE(ds->prev_line_col);
}

static void ds_reflines_init(RzDisasmState *ds) {
	RzAnalysis *analysis = ds->core->analysis;

	// refline info is needed when it is shown as ascii,
	// or returned as part of a json or C struct representation.
	if (ds->show_lines_bb || ds->vec || ds->pj) {
		ds_reflines_fini(ds);
		analysis->reflines = rz_analysis_reflines_get(analysis,
			ds->addr, ds->buf, ds->len, ds->nlines,
			ds->linesout, ds->show_lines_call);
	} else {
		rz_list_free(analysis->reflines);
		analysis->reflines = NULL;
	}
}

static void ds_free(RzDisasmState *ds) {
	if (!ds) {
		return;
	}
	if (ds->show_emu_stack) {
		// TODO: destroy fake stack in here
		RZ_LOG_ERROR("core: free fake stack\n");
		if (ds->stackFd != -1) {
			rz_io_fd_close(ds->core->io, ds->stackFd);
		}
	}
	rz_asm_op_fini(&ds->asmop);
	rz_analysis_op_fini(&ds->analysis_op);
	rz_analysis_hint_free(ds->hint);
	ds_print_esil_analysis_fini(ds);
	ds_reflines_fini(ds);
	ds_print_esil_analysis_fini(ds);
	sdb_free(ds->ssa);
	ht_pp_free(ds->debuginfo.cache.items);
	free(ds->comment);
	free(ds->line);
	free(ds->line_col);
	free(ds->refline);
	free(ds->refline2);
	free(ds->prev_line_col);
	free(ds->opstr);
	free(ds->osl);
	free(ds->sl);
	free(ds->_tabsbuf);
	RZ_FREE(ds);
}

static bool ds_must_strip(RzDisasmState *ds) {
	if (ds && ds->strip && *ds->strip) {
		const char *optype = rz_analysis_optype_to_string(ds->analysis_op.type);
		if (optype && *optype) {
			return strstr(ds->strip, optype);
		}
	}
	return false;
}

static void ds_highlight_word(RzDisasmState *ds, char *word, char *color) {
	char *source = ds->opstr ? ds->opstr : rz_asm_op_get_asm(&ds->asmop);
	const char *color_reset = line_highlighted(ds) ? COLOR(ds, linehl) : Color_RESET_BG;
	char *asm_str = rz_str_highlight(source, word, color, color_reset);
	ds->opstr = asm_str ? asm_str : source;
}

static void __replaceImports(RzDisasmState *ds) {
	if (ds->core->analysis->imports) {
		char *imp;
		RzListIter *iter;
		rz_list_foreach (ds->core->analysis->imports, iter, imp) {
			ds->opstr = rz_str_replace(ds->opstr, imp, ".", 1);
		}
	}
	if (ds->fcn && ds->fcn->imports) {
		char *imp;
		RzListIter *iter;
		rz_list_foreach (ds->fcn->imports, iter, imp) {
			ds->opstr = rz_str_replace(ds->opstr, imp, ".", 1);
		}
	}
}

static void ds_opstr_try_colorize(RzDisasmState *ds, bool print_color) {
	bool colorize_asm = print_color && ds->show_color && ds->colorop;
	if (!colorize_asm) {
		return;
	}
	RzCore *core = ds->core;
	RzStrBuf bw_asm;
	rz_strbuf_init(&bw_asm);
	rz_strbuf_set(&bw_asm, ds->opstr ? ds->opstr : rz_asm_op_get_asm(&ds->asmop));
	core->print->colorize_opts.reset_bg = line_highlighted(ds);
	RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, ds->analysis_op.type);
	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&bw_asm, core->print, param, ds->asmop.asm_toks);
	rz_asm_parse_param_free(param);
	rz_strbuf_fini(&bw_asm);
	if (!colored_asm) {
		return;
	}
	char *new_opstr = rz_strbuf_drain(colored_asm);
	free(ds->opstr);
	ds->opstr = new_opstr;
}

static void ds_build_op_str(RzDisasmState *ds, bool print_color) {
	RzCore *core = ds->core;

	if (ds->use_esil) {
		free(ds->opstr);
		if (*RZ_STRBUF_SAFEGET(&ds->analysis_op.esil)) {
			ds->opstr = strdup(RZ_STRBUF_SAFEGET(&ds->analysis_op.esil));
		} else {
			ds->opstr = strdup(",");
		}
		return;
	}
	if (ds->decode) {
		free(ds->opstr);
		ds->opstr = rz_analysis_op_to_string(core->analysis, &ds->analysis_op);
		return;
	}
	if (!ds->opstr) {
		const char *assembly = rz_asm_op_get_asm(&ds->asmop);
		if (ds->pseudo) {
			char *tmp = rz_parse_pseudocode(core->parser, assembly);
			if (tmp) {
				snprintf(ds->str, sizeof(ds->str), "%s", tmp);
				ds->opstr = tmp;
			} else {
				ds->opstr = strdup("");
				ds->str[0] = 0;
			}
		} else {
			ds->opstr = strdup(assembly);
		}
	}
	if (ds->opstr && core->bin && core->bin->cur) {
		RzBinPlugin *plugin = rz_bin_file_cur_plugin(core->bin->cur);
		char *tmp = plugin && plugin->enrich_asm ? plugin->enrich_asm(core->bin->cur, ds->opstr, strlen(ds->opstr)) : NULL;
		if (tmp) {
			free(ds->opstr);
			ds->opstr = tmp;
		}
	}

	if (ds->analysis_op.mmio_address != UT64_MAX) {
		char number[32];
		rz_strf(number, "0x%" PFMT64x, ds->analysis_op.mmio_address);

		RzPlatformTarget *arch_target = core->analysis->arch_target;

		const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, ds->analysis_op.mmio_address);
		if (resolved) {
			ds->opstr = rz_str_replace(ds->opstr, number, resolved, 0);
		}
	}

	if (ds->analysis_op.ptr != UT64_MAX) {
		char number[32];
		rz_strf(number, "0x%" PFMT64x, ds->analysis_op.ptr);

		RzPlatformTarget *arch_target = core->analysis->arch_target;

		const char *resolved = rz_platform_profile_resolve_extended_register(arch_target->profile, ds->analysis_op.ptr);
		if (resolved) {
			ds->opstr = rz_str_replace(ds->opstr, number, resolved, 0);
		}
	}

	/* initialize */
	core->parser->subrel = rz_config_get_b(core->config, "asm.sub.rel");
	core->parser->subreg = rz_config_get_b(core->config, "asm.sub.reg");
	core->parser->subrel_addr = 0;
	if (core->parser->subrel && (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_LEA || ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_MOV || ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_CMP) && ds->analysis_op.ptr != UT64_MAX) {
		core->parser->subrel_addr = ds->analysis_op.ptr;
	}
	if (ds->subvar && ds->opstr) {
		ut64 at = ds->vat;
		RzAnalysisFunction *f = fcnIn(ds, at, RZ_ANALYSIS_FCN_TYPE_NULL);
		rz_parse_subvar(core->parser, f, &ds->analysis_op, ds->opstr, ds->strsub, sizeof(ds->strsub));
		if (*ds->strsub) {
			free(ds->opstr);
			ds->opstr = strdup(ds->strsub);
		}
		if (core->parser->subrel) {
			RzList *list = rz_analysis_xrefs_get_from(core->analysis, at);
			RzListIter *iter;
			RzAnalysisXRef *xref;
			rz_list_foreach (list, iter, xref) {
				if ((xref->type == RZ_ANALYSIS_XREF_TYPE_DATA || xref->type == RZ_ANALYSIS_XREF_TYPE_STRING) && ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_LEA) {
					core->parser->subrel_addr = xref->to;
					break;
				}
			}
			rz_list_free(list);
		}
	}

	ds_opstr_sub_jumps(ds);
	if (ds->immtrim) {
		char *res = rz_parse_immtrim(ds->opstr);
		if (res) {
			ds->opstr = res;
		}
		return;
	}
	if (ds->hint && ds->hint->opcode) {
		free(ds->opstr);
		ds->opstr = strdup(ds->hint->opcode);
	}
	if (ds->subnames) {
		RzSpace *ofs = core->parser->flagspace;
		RzSpace *fs = ds->flagspace_ports;
		if (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_IO) {
			core->parser->notin_flagspace = NULL;
			core->parser->flagspace = fs;
		} else {
			if (fs) {
				core->parser->notin_flagspace = fs;
				core->parser->flagspace = fs;
			} else {
				core->parser->notin_flagspace = NULL;
				core->parser->flagspace = NULL;
			}
		}
		if (core->parser->subrel && ds->analysis_op.refptr) {
			if (core->parser->subrel_addr == 0) {
				ut64 sub_address = UT64_MAX;
				const int be = core->rasm->big_endian;
				rz_io_read_i(core->io, ds->analysis_op.ptr, &sub_address, ds->analysis_op.refptr, be);
				core->parser->subrel_addr = sub_address;
			}
		}

		ds_opstr_try_colorize(ds, print_color);
		rz_parse_filter(core->parser, ds->vat, core->flags, ds->hint, ds->opstr,
			ds->str, sizeof(ds->str), core->print->big_endian);
		// subvar depends on filter
		if (ds->subvar) {
			// HACK to do subvar outside rparse becacuse the whole rparse api must be rewritten
			char *ox = strstr(ds->str, "0x");
			if (ox) {
				char *e = strchr(ox, ']');
				if (e) {
					e = strdup(e);
					ut64 addr = rz_num_get(NULL, ox);
					if (addr > ds->min_ref_addr) {
						RzFlagItem *fi = rz_flag_get_i(ds->core->flags, addr);
						if (fi) {
							rz_str_cpy(ox, rz_flag_item_get_name(fi));
							rz_str_cat(ox, e);
						}
					}
					free(e);
				}
			}
		}
		core->parser->flagspace = ofs;
		free(ds->opstr);
		ds->opstr = strdup(ds->str);
	} else {
		ds_opstr_try_colorize(ds, print_color);
	}
	rz_str_trim_char(ds->opstr, '\n');
	// updates ds->opstr
	__replaceImports(ds);
	if (ds->show_color) {
		int i = 0;
		char *word = NULL;
		char *bgcolor = NULL;
		const char *wcdata = rz_meta_get_string(ds->core->analysis, RZ_META_TYPE_HIGHLIGHT, ds->at);
		int argc = 0;
		char **wc_array = rz_str_argv(wcdata, &argc);
		for (i = 0; i < argc; i++) {
			bgcolor = strchr(wc_array[i], '\x1b');
			word = rz_str_newlen(wc_array[i], bgcolor - wc_array[i]);
			ds_highlight_word(ds, word, bgcolor);
		}
	}
}

RZ_API RzAnalysisHint *rz_core_hint_begin(RzCore *core, RzAnalysisHint *hint, ut64 at) {
	rz_analysis_hint_free(hint);
	hint = rz_analysis_hint_get(core->analysis, at);
	if (hint) {
		/* syntax */
		if (hint->syntax) {
			rz_config_set(core->config, "asm.syntax", hint->syntax);
		}
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, at, 0);
	if (fcn) {
		if (fcn->bits == 16 || fcn->bits == 32) {
			if (!hint) {
				hint = RZ_NEW0(RzAnalysisHint);
			}
			hint->bits = fcn->bits;
			hint->new_bits = fcn->bits;
		}
	}
	return hint;
}

static void ds_pre_line(RzDisasmState *ds) {
	ds_setup_pre(ds, false, false);
	ds_print_pre(ds, true);
	char *tmp = ds->line;
	char *tmp_col = ds->line_col;
	ds->line = ds->refline2;
	ds->line_col = ds->prev_line_col;
	ds_print_lines_left(ds);
	ds->line = tmp;
	ds->line_col = tmp_col;
}

static RzAnalysisDisasmText *ds_disasm_text(RzDisasmState *ds, RzAnalysisDisasmText *t, char *text) {
	if (!t) {
		return NULL;
	}
	t->offset = ds->vat;
	t->arrow = UT64_MAX;
	t->text = text;
	if (ds->core->analysis->reflines) {
		RzAnalysisRefline *ref;
		RzListIter *iter;
		rz_list_foreach (ds->core->analysis->reflines, iter, ref) {
			if (ref->from == ds->vat) {
				t->arrow = ref->to;
				break;
			}
		}
	}
	return t;
}

static void ds_begin_line(RzDisasmState *ds) {
	if (ds->vec) {
		return;
	}

	if (ds->pj) {
		pj_o(ds->pj);
		pj_kn(ds->pj, "offset", ds->vat);
		if (ds->core->analysis->reflines) {
			RzAnalysisRefline *ref;
			RzListIter *iter;
			// XXX Probably expensive
			rz_list_foreach (ds->core->analysis->reflines, iter, ref) {
				if (ref->from == ds->vat) {
					pj_kn(ds->pj, "arrow", ref->to);
					break;
				}
			}
		}
		pj_k(ds->pj, "text");
	}
	ds->buf_line_begin = rz_cons_get_buffer_len();
	if (!ds->pj && ds->asm_hint_pos == -1) {
		if (!ds_print_core_vmode(ds, ds->asm_hint_pos)) {
			rz_cons_printf("    ");
		}
	}
}

static void ds_newline(RzDisasmState *ds) {
	if (ds->vec) {
		RzAnalysisDisasmText *t = RZ_NEW0(RzAnalysisDisasmText);
		if (!t) {
			return;
		}
		ds_disasm_text(ds, t, rz_cons_get_buffer_dup());
		rz_cons_reset();
		rz_pvector_push(ds->vec, t);
		return;
	}

	if (ds->pj) {
		const bool is_html = rz_config_get_b(ds->core->config, "scr.html");
		if (is_html) {
			char *s = rz_cons_html_filter(rz_cons_get_buffer(), NULL);
			pj_s(ds->pj, s);
			free(s);
		} else {
			pj_s(ds->pj, rz_cons_get_buffer());
		}
		rz_cons_reset();
		pj_end(ds->pj);
	} else {
		rz_cons_newline();
	}
}

static void ds_begin_cont(RzDisasmState *ds) {
	ds_begin_line(ds);
	ds_setup_print_pre(ds, false, false);
	if (!ds->linesright && ds->show_lines_bb && ds->line) {
		RzAnalysisRefStr *refstr = rz_analysis_reflines_str(ds->core, ds->at,
			ds->linesopts | RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_AFTER);
		ds_print_ref_lines(refstr->str, refstr->cols, ds);
		rz_analysis_reflines_str_free(refstr);
	}
}

static void ds_begin_comment(RzDisasmState *ds) {
	if (ds->show_comment_right) {
		CMT_ALIGN;
	} else {
		ds_begin_line(ds);
		ds_pre_xrefs(ds, false);
	}
}

static void ds_show_refs(RzDisasmState *ds) {
	RzAnalysisXRef *xref;
	RzListIter *iter;

	if (!ds->show_cmtrefs) {
		return;
	}
	RzList *list = rz_analysis_xrefs_get_from(ds->core->analysis, ds->at);

	rz_list_foreach (list, iter, xref) {
		const char *cmt = rz_meta_get_string(ds->core->analysis, RZ_META_TYPE_COMMENT, xref->to);
		const RzList *fls = rz_flag_get_list(ds->core->flags, xref->to);
		RzListIter *iter2;
		RzFlagItem *fis;
		rz_list_foreach (fls, iter2, fis) {
			ds_begin_comment(ds);
			ds_comment(ds, true, "; (%s)", rz_flag_item_get_name(fis));
		}

		// ds_align_comment (ds);
		theme_print_color(comment);
		if (cmt) {
			ds_begin_comment(ds);
			ds_comment(ds, true, "; (%s)", cmt);
		}
		if (xref->type & RZ_ANALYSIS_XREF_TYPE_CALL) {
			RzAnalysisOp aop = { 0 };
			ut8 buf[12];
			rz_io_read_at(ds->core->io, xref->from, buf, sizeof(buf));
			rz_analysis_op(ds->core->analysis, &aop, xref->from, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
			if ((aop.type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_UCALL) {
				RzAnalysisFunction *fcn = rz_analysis_get_function_at(ds->core->analysis, xref->to);
				ds_begin_comment(ds);
				if (fcn) {
					ds_comment(ds, true, "; %s", fcn->name);
				} else {
					ds_comment(ds, true, "; 0x%" PFMT64x "", xref->to);
				}
			}
		}
		ds_print_color_reset(ds);
	}
	rz_list_free(list);
}

static void ds_show_xrefs(RzDisasmState *ds) {
	RzAnalysisXRef *xrefi;
	RzListIter *iter, *it;
	RzCore *core = ds->core;
	char *name, *realname;
	int count = 0;
	if (!ds->show_xrefs || !ds->show_comments) {
		return;
	}
	/* show xrefs */
	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, ds->at);
	if (!xrefs) {
		return;
	}
	// only show fcnline in xrefs when addr is not the beginning of a function
	bool fcnlines = (ds->fcn && ds->fcn->addr == ds->at);
	if (rz_list_length(xrefs) > ds->maxrefs) {
		ds_begin_line(ds);
		ds_pre_xrefs(ds, fcnlines);
		ds_comment(ds, false, "%s; XREFS(%d)",
			COLOR(ds, comment),
			rz_list_length(xrefs));
		ds_print_color_reset(ds);
		ds_newline(ds);
		rz_list_free(xrefs);
		return;
	}
	if (rz_list_length(xrefs) > ds->foldxrefs) {
		int cols = rz_cons_get_size(NULL);
		cols -= 15;
		cols /= 23;
		cols = cols > 5 ? 5 : cols;
		ds_begin_line(ds);
		ds_pre_xrefs(ds, fcnlines);
		ds_comment(ds, false, "%s; XREFS: ", COLOR(ds, comment));
		rz_list_foreach (xrefs, iter, xrefi) {
			ds_comment(ds, false, "%s 0x%08" PFMT64x "  ",
				rz_analysis_xrefs_type_tostring(xrefi->type), xrefi->from);
			if (count == cols) {
				if (rz_list_iter_has_next(iter)) {
					ds_print_color_reset(ds);
					ds_newline(ds);
					ds_begin_line(ds);
					ds_pre_xrefs(ds, fcnlines);
					ds_comment(ds, false, "%s; XREFS: ", COLOR(ds, comment));
				}
				count = 0;
			} else {
				count++;
			}
		}
		ds_print_color_reset(ds);
		ds_newline(ds);
		rz_list_free(xrefs);
		return;
	}

	RzList *addrs = rz_list_newf(free);
	RzAnalysisFunction *fun, *next_fun;
	RzFlagItem *f, *next_f;
	rz_list_foreach (xrefs, iter, xrefi) {
		if (!ds->asm_xrefs_code && xrefi->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			continue;
		}
		if (xrefi->to == ds->at) {
			realname = NULL;
			fun = fcnIn(ds, xrefi->from, -1);
			if (fun) {
				if (iter != rz_list_tail(xrefs)) {
					ut64 next_addr = ((RzAnalysisXRef *)rz_list_iter_get_next_data(iter))->from;
					next_fun = rz_analysis_get_fcn_in(core->analysis, next_addr, -1);
					if (next_fun && next_fun->addr == fun->addr) {
						rz_list_append(addrs, rz_num_dup(xrefi->from));
						continue;
					}
				}
				name = strdup(fun->name);
				rz_list_append(addrs, rz_num_dup(xrefi->from));
			} else {
				f = rz_flag_get_at(core->flags, xrefi->from, true);
				if (f) {
					if (iter != rz_list_tail(xrefs)) {
						ut64 next_addr = ((RzAnalysisXRef *)rz_list_iter_get_next_data(iter))->from;
						next_f = rz_flag_get_at(core->flags, next_addr, true);
						if (next_f && rz_flag_item_get_offset(f) == rz_flag_item_get_offset(next_f)) {
							rz_list_append(addrs, rz_num_dup(xrefi->from - rz_flag_item_get_offset(f)));
							continue;
						}
					}
					name = strdup(rz_flag_item_get_name(f));
					rz_list_append(addrs, rz_num_dup(xrefi->from - rz_flag_item_get_offset(f)));
				} else {
					name = strdup("unk");
				}
			}
			ds_begin_line(ds);
			ds_pre_xrefs(ds, fcnlines);
			const char *plural = rz_list_length(addrs) > 1 ? "S" : "";
			const char *plus = fun ? "" : "+";
			ds_comment(ds, false, "%s; %s XREF%s from %s @ ",
				COLOR(ds, comment), rz_analysis_xrefs_type_tostring(xrefi->type), plural,
				realname ? realname : name);
			ut64 *addrptr;
			rz_list_foreach (addrs, it, addrptr) {
				if (addrptr && *addrptr) {
					ds_comment(ds, false, "%s%s0x%" PFMT64x, it == rz_list_head(addrs) ? "" : ", ", plus, *addrptr);
				}
			}
			if (realname && (!fun || rz_analysis_get_function_at(core->analysis, ds->at))) {
				const char *pad = ds->show_comment_right ? "" : " ";
				if (!ds->show_comment_right) {
					ds_newline(ds);
					ds_begin_line(ds);
					ds_pre_xrefs(ds, fcnlines);
				}
				ds_comment(ds, false, " %s; %s", pad, name);
			}
			ds_comment(ds, false, "%s", COLOR_RESET(ds));
			ds_newline(ds);
			rz_list_purge(addrs);
			RZ_FREE(name);
			free(realname);
		} else {
			RZ_LOG_ERROR("core: corrupted database?\n");
		}
	}
	rz_list_free(addrs);
	rz_list_free(xrefs);
}

static bool calc_tab_buf_size(size_t len, size_t tabs, size_t *c) {
	if (SZT_ADD_OVFCHK(tabs, 1)) {
		return true;
	}
	tabs++;
	if (SZT_MUL_OVFCHK(len, tabs)) {
		return true;
	}
	len *= tabs;
	if (SZT_MUL_OVFCHK(len, 4)) {
		return true;
	}
	len *= 4;
	if (SZT_ADD_OVFCHK(len, 4)) {
		return true;
	}
	len += 4;
	*c = len;
	return false;
}

static void ds_atabs_option(RzDisasmState *ds) {
	int n, i = 0, comma = 0, word = 0;
	int brackets = 0;
	char *t, *b;
	if (!ds || !ds->atabs) {
		return;
	}
	size_t size;
	const char *opstr;
	if (ds->opstr) {
		if (calc_tab_buf_size(strlen(ds->opstr), ds->atabs, &size)) {
			return;
		}
		opstr = ds->opstr;
	} else {
		if (calc_tab_buf_size(rz_strbuf_length(&ds->asmop.buf_asm), ds->atabs, &size)) {
			return;
		}
		opstr = rz_strbuf_get(&ds->asmop.buf_asm);
	}
	b = malloc(size);
	if (!b) {
		return;
	}
	rz_str_ncpy(b, opstr, size);
	free(ds->opstr);
	ds->opstr = b;
	for (; *b; b++, i++) {
		if (*b == '(' || *b == '[') {
			brackets++;
		}
		if (*b == ')' || *b == ']') {
			brackets--;
		}
		if (*b == ',') {
			comma = 1;
		}
		if (*b != ' ') {
			continue;
		}
		if (word > 0 && !comma) {
			continue; //&& b[1]=='[') continue;
		}
		if (brackets > 0) {
			continue;
		}
		comma = 0;
		brackets = 0;
		n = (ds->atabs - i);
		t = strdup(b + 1); // XXX slow!
		if (n < 1) {
			n = 1;
		}
		memset(b, ' ', n);
		b += n;
		strcpy(b, t);
		free(t);
		i = 0;
		word++;
		if (ds->atabsonce) {
			break;
		}
	}
}

static int handleMidFlags(RzCore *core, RzDisasmState *ds, bool print) {
	ds->midflags = rz_config_get_i(core->config, "asm.flags.middle");
	ds->hasMidflag = false;
	if (ds->midcursor && core->print->cur != -1) {
		ut64 cur = core->offset + core->print->cur;
		ut64 from = ds->at;
		ut64 to = ds->at + ds->oplen;
		if (cur > from && cur < to) {
			return cur - from;
		}
	}
	if (!ds->midflags) {
		return 0;
	}
	for (int i = 1; i < ds->oplen; i++) {
		RzFlagItem *fi = rz_flag_get_i(core->flags, ds->at + i);
		if (fi && rz_flag_item_get_name(fi)) {
			if (rz_analysis_find_most_relevant_block_in(core->analysis, ds->at + i)) {
				ds->midflags = ds->midflags ? RZ_MIDFLAGS_SHOW : RZ_MIDFLAGS_HIDE;
			}
			if (ds->midflags == RZ_MIDFLAGS_REALIGN &&
				((rz_flag_item_get_name(fi)[0] == '$') || (rz_flag_item_get_realname(fi) && rz_flag_item_get_realname(fi)[0] == '$'))) {
				i = 0;
			} else if (!strncmp(rz_flag_item_get_name(fi), "hit.", 4)) { // use search.prefix ?
				i = 0;
			} else if (!strncmp(rz_flag_item_get_name(fi), "str.", 4)) {
				ds->midflags = RZ_MIDFLAGS_REALIGN;
			} else if (rz_flag_item_get_space(fi) && !strcmp(rz_flag_item_get_space(fi)->name, RZ_FLAGS_FS_RELOCS)) {
				continue;
			} else if (ds->midflags == RZ_MIDFLAGS_SYMALIGN) {
				if (strncmp(rz_flag_item_get_name(fi), "sym.", 4)) {
					continue;
				}
			}
			ds->hasMidflag = true;
			return i;
		}
	}
	return 0;
}

static int handleMidBB(RzCore *core, RzDisasmState *ds) {
	int i;
	ds->hasMidbb = false;
	rz_return_val_if_fail(core->analysis, 0);
	// Unfortunately, can't just check the addr of the last insn byte since
	// a bb (and fcn) can be as small as 1 byte, and advancing i based on
	// bb->size is unsound if basic blocks can nest or overlap
	for (i = 1; i < ds->oplen; i++) {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, ds->at + i, 0);
		if (fcn) {
			RzAnalysisBlock *bb = rz_analysis_fcn_bbget_in(core->analysis, fcn, ds->at + i);
			if (bb && bb->addr > ds->at) {
				ds->hasMidbb = true;
				return bb->addr - ds->at;
			}
		}
	}
	return 0;
}

/**
 * \brief Update \p oplen by "asm.bb.middle" and "asm.flags.middle"
 * \param core RzCore reference
 * \param at Address
 * \param[in,out] oplen Opcode length
 * \param ret Value by call rz_asm_disassemble
 */
RZ_IPI void rz_core_asm_bb_middle(RZ_NONNULL RzCore *core, ut64 at,
	RZ_INOUT RZ_NONNULL int *oplen, RZ_NONNULL int *ret) {
	rz_return_if_fail(core && oplen && ret);
	bool midbb = rz_config_get_b(core->config, "asm.bb.middle");
	RzDisasmState ds = {
		.at = at,
		.oplen = *oplen,
	};
	int skip_bytes_flag = handleMidFlags(core, &ds, false);
	int skip_bytes_bb = midbb ? handleMidBB(core, &ds) : 0;
	if (skip_bytes_flag && ds.midflags > RZ_MIDFLAGS_SHOW) {
		*oplen = *ret = skip_bytes_flag;
	}
	if (skip_bytes_bb && skip_bytes_bb < *ret) {
		*oplen = skip_bytes_bb;
	}
}

RZ_API int rz_core_flag_in_middle(RzCore *core, ut64 at, int oplen, int *midflags) {
	rz_return_val_if_fail(midflags, 0);
	RzDisasmState ds = {
		.at = at,
		.oplen = oplen,
		.midflags = *midflags
	};
	int ret = handleMidFlags(core, &ds, true);
	*midflags = ds.midflags;
	return ret;
}

RZ_API int rz_core_bb_starts_in_middle(RzCore *core, ut64 at, int oplen) {
	RzDisasmState ds = {
		.at = at,
		.oplen = oplen
	};
	return handleMidBB(core, &ds);
}

static void ds_print_show_cursor(RzDisasmState *ds) {
	RzCore *core = ds->core;
	char res[] = "     ";
	if (!ds->show_marks) {
		return;
	}
	int q = core->print->cur_enabled &&
		ds->cursor >= ds->index &&
		ds->cursor < (ds->index + ds->asmop.size);
	RzBreakpointItem *p = rz_bp_get_at(core->dbg->bp, ds->at);
	(void)handleMidFlags(core, ds, false);
	if (ds->midbb) {
		(void)handleMidBB(core, ds);
	}
	if (p) {
		res[0] = 'b';
	}
	if (ds->hasMidflag || ds->hasMidbb) {
		res[1] = '~';
	}
	if (q) {
		if (ds->cursor == ds->index) {
			res[2] = '*';
		} else {
			int i = 2, diff = ds->cursor - ds->index;
			if (diff > 9) {
				res[i++] = '0' + (diff / 10);
			}
			res[i] = '0' + (diff % 10);
		}
	}
	rz_cons_strcat(res);
}

static void ds_pre_xrefs(RzDisasmState *ds, bool no_fcnlines) {
	ds_setup_pre(ds, false, false);
	if (ds->pre != DS_PRE_NONE && ds->pre != DS_PRE_EMPTY) {
		ds->pre = no_fcnlines ? DS_PRE_EMPTY : DS_PRE_FCN_MIDDLE;
	}
	ds_print_pre(ds, !no_fcnlines);
	char *tmp = ds->line;
	char *tmp_col = ds->line_col;
	ds->line = ds->refline2;
	ds->line_col = ds->prev_line_col;
	ds_print_lines_left(ds);
	if (!ds->show_offset && ds->show_marks) {
		ds_print_show_cursor(ds);
	}
	ds->line = tmp;
	ds->line_col = tmp_col;
}

static void ds_show_function_var(RzDisasmState *ds, RzAnalysisFunction *fcn, RzAnalysisVar *var) {
	char *s = rz_core_analysis_var_to_string(ds->core, var);
	if (s) {
		rz_cons_print(s);
		free(s);
	}

	if (ds->show_varsum != -1) {
		return;
	}
	char *val = rz_core_analysis_var_display(ds->core, var, false);
	if (!val) {
		return;
	}
	rz_str_replace_char(val, '\n', '\0');
	rz_cons_printf(" = %s", val);
	free(val);
}

static void printVarSummary(RzDisasmState *ds, RzList /*<RzAnalysisVar *>*/ *list) {
	const char *numColor = ds->core->cons->context->pal.num;
	RzAnalysisVar *var;
	RzListIter *iter;
	int stack_vars = 0;
	int reg_vars = 0;
	int stack_args = 0;
	int reg_args = 0;
	const char *stack_vars_color = COLOR_RESET(ds);
	const char *reg_vars_color = COLOR_RESET(ds);
	const char *stack_args_color = COLOR_RESET(ds);
	const char *reg_args_color = COLOR_RESET(ds);
	rz_list_foreach (list, iter, var) {
		if (rz_analysis_var_is_arg(var)) {
			switch (var->storage.type) {
			case RZ_ANALYSIS_VAR_STORAGE_STACK:
				stack_args++;
				break;
			case RZ_ANALYSIS_VAR_STORAGE_REG:
				reg_args++;
				break;
			default:
				break;
			}
		} else {
			switch (var->storage.type) {
			case RZ_ANALYSIS_VAR_STORAGE_STACK:
				stack_vars++;
				break;
			case RZ_ANALYSIS_VAR_STORAGE_REG:
				reg_vars++;
				break;
			default:
				break;
			}
		}
	}
	if (stack_vars) {
		stack_vars_color = numColor;
	}
	if (reg_vars) {
		reg_vars_color = numColor;
	}
	if (stack_args) {
		stack_args_color = numColor;
	}
	if (reg_args) {
		reg_args_color = numColor;
	}
	if (ds->show_varsum == 2) {
		ds_begin_line(ds);
		ds_print_pre(ds, true);
		rz_cons_printf("vars: %s%d%s %s%d%s",
			stack_vars_color, stack_vars, COLOR_RESET(ds),
			reg_vars_color, reg_vars, COLOR_RESET(ds));
		ds_newline(ds);
		ds_begin_line(ds);
		ds_print_pre(ds, true);
		rz_cons_printf("args: %s%d%s %s%d%s",
			stack_args_color, stack_args, COLOR_RESET(ds),
			reg_args_color, reg_args, COLOR_RESET(ds));
		ds_newline(ds);
		return;
	}
	ds_begin_line(ds);
	ds_print_pre(ds, true);
	rz_cons_printf("stack: %s%d%s (vars %s%d%s, args %s%d%s)",
		stack_args || stack_vars ? numColor : COLOR_RESET(ds), stack_args + stack_vars, COLOR_RESET(ds),
		stack_vars_color, stack_vars, COLOR_RESET(ds),
		stack_args_color, stack_args, COLOR_RESET(ds));
	ds_newline(ds);
	ds_begin_line(ds);
	ds_print_pre(ds, true);
	rz_cons_printf("rg: %s%d%s (vars %s%d%s, args %s%d%s)",
		reg_args || reg_vars ? numColor : COLOR_RESET(ds), reg_args + reg_vars, COLOR_RESET(ds),
		reg_vars_color, reg_vars, COLOR_RESET(ds),
		reg_args_color, reg_args, COLOR_RESET(ds));
	ds_newline(ds);
}

/**
 * \brief Fold same-typed variables, set by asm.var.fold
 * \return the steps that original iter needs to go forward
 **/
static ut32 fold_variables(RzCore *core, RzDisasmState *ds, RzListIter /*<RzAnalysisVar *>*/ *iter) {
	ut32 iter_mov = 0;
	RzAnalysisVar *var = rz_list_iter_get_data(iter);
	if (!strcmp(ds->fold_var, "none") || rz_analysis_var_is_arg(var)) {
		return iter_mov;
	}
	char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
	RzListIter *temp_it = rz_list_iter_get_next(iter);
	ut32 same_type_cnt = 1;
	while (temp_it) {
		RzAnalysisVar *temp_var = rz_list_iter_get_data(temp_it);
		if (!temp_var) {
			break;
		}
		char *temp_vartype = rz_type_as_string(core->analysis->typedb, temp_var->type);
		if (!temp_vartype) {
			break;
		}
		if (strcmp(temp_vartype, vartype) || rz_analysis_var_is_arg(temp_var)) {
			free(temp_vartype);
			break;
		}
		same_type_cnt += 1;
		free(temp_vartype);
		temp_it = rz_list_iter_get_next(temp_it);
	}

	// fold if more than 3 same-typed variables
	if (same_type_cnt < 3) {
		free(vartype);
		return iter_mov;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_strbuf_appendf(sb, "var %s [", vartype);
	// fold_var = group -> group every three var
	// fold_var = hide -> group the first two var with ellipsis in tail
	ut32 group_num = strcmp(ds->fold_var, "group") ? 2 : 3;
	while (iter_mov < group_num) {
		RzAnalysisVar *temp_var = rz_list_iter_get_data(iter);
		const RzStackAddr off = temp_var->storage.stack_off;
		const char sign = off >= 0 ? '+' : '-';
		rz_strbuf_appendf(sb, "%s @ stack %c 0x%" PFMT64x "; ", temp_var->name, sign, RZ_ABS(off));
		iter_mov++;
		iter = rz_list_iter_get_next(iter);
	}
	// remove extra "; " in tail
	rz_strbuf_slice(sb, 0, sb->len - 2);
	if (!strcmp(ds->fold_var, "hide")) {
		// add ellipsis
		rz_strbuf_append(sb, " ...");
		// boost iter to proper position
		while (iter_mov < same_type_cnt) {
			iter_mov++;
		}
	}
	rz_strbuf_append(sb, "]");

	ds_begin_line(ds);
	ds_pre_xrefs(ds, false);
	rz_cons_printf("%s; ", COLOR_ARG(ds, func_var));
	char *line = rz_strbuf_drain(sb);
	rz_cons_print(line);
	rz_cons_print(COLOR_RESET(ds));
	ds_newline(ds);
	free(line);
	free(vartype);
	return iter_mov;
}

static void ds_show_fn_var_line(
	RzDisasmState *ds, RzAnalysisFunction *f, RzAnalysisVar *var) {
	ds_begin_line(ds);
	ds_pre_xrefs(ds, false);
	if (ds->show_flgoff) {
		ds_print_offset(ds);
	}
	rz_cons_printf("%s; ", COLOR_ARG(ds, func_var));
	ds_show_function_var(ds, f, var);
	if (var->comment) {
		rz_cons_printf("    %s; %s", COLOR(ds, comment), var->comment);
	}
	rz_cons_print(COLOR_RESET(ds));
	ds_newline(ds);
}

static void ds_show_fn_vars_lines(
	RzDisasmState *ds,
	RzAnalysisFunction *f,
	RzAnalysisFcnVarsCache *vars_cache) {
	RzAnalysisVar *var;
	RzListIter *iter;
	rz_list_foreach (vars_cache->sorted_vars, iter, var) {
		// fold same-typed variables
		ut32 iter_mov = fold_variables(ds->core, ds, iter);
		if (iter_mov > 0) {
			int cnt = 0;
			while (cnt++ < iter_mov - 1) {
				iter = rz_list_iter_get_next(iter);
			}
			continue;
		}
		ds_show_fn_var_line(ds, f, var);
	}
}

static void ds_show_functions(RzDisasmState *ds) {
	RzAnalysisFunction *f;
	RzCore *core = ds->core;
	char *fcn_name;
	bool fcn_name_alloc = false; // whether fcn_name needs to be freed by this function

	if (!ds->show_functions) {
		return;
	}
	bool fcnsig = ds->show_fcnsig;
	const char *fcntype;
	f = rz_analysis_get_function_at(core->analysis, ds->at);
	if (!f) {
		return;
	}
	fcn_name = f->name;

	ds_begin_line(ds);

	RzAnalysisFcnVarsCache vars_cache;
	rz_analysis_fcn_vars_cache_init(core->analysis, &vars_cache, f);

	int o_varsum = ds->show_varsum;
	if (ds->interactive && !o_varsum) {
		int padding = 10;
		int numvars = rz_list_length(vars_cache.sorted_vars);
		ds->show_varsum = (numvars > padding) && ((numvars + padding) > ds->nlines);
	}
	// show function's realname in the signature if realnames are enabled
	if (core->flags->realnames) {
		RzFlagItem *flag = rz_flag_get(core->flags, fcn_name);
		if (flag && rz_flag_item_get_realname(flag)) {
			fcn_name = rz_flag_item_get_realname(flag);
		}
	}

	if (f->type == RZ_ANALYSIS_FCN_TYPE_LOC) {
		rz_cons_printf("%s%s ", COLOR(ds, fline),
			core->cons->vline[LINE_CROSS]); // |-
		fcntype = "loc";
	} else {
		char cmt[32];
		get_bits_comment(core, f, cmt, sizeof(cmt));

		switch (f->type) {
		case RZ_ANALYSIS_FCN_TYPE_FCN:
		case RZ_ANALYSIS_FCN_TYPE_SYM:
			fcntype = "fcn";
			break;
		case RZ_ANALYSIS_FCN_TYPE_IMP:
			fcntype = "imp";
			break;
		default:
			fcntype = "loc";
			break;
		}
		// ds_set_pre (ds, core->cons->vline[CORNER_TL]);
		if (ds->show_lines_fcn) {
			ds->pre = DS_PRE_FCN_HEAD;
		}
		ds_print_pre(ds, true);
		if (ds->show_flgoff) {
			ds_print_lines_left(ds);
			ds_print_offset(ds);
		}
	}
	if (!strcmp(fcntype, "fcn")) {
		rz_cons_printf("%s", COLOR(ds, fname));
	} else {
		rz_cons_printf("%s(%s) ", COLOR(ds, fname), fcntype);
	}

	if (ds->show_fcnsize) {
		rz_cons_printf("%" PFMT64d ": ", rz_analysis_function_realsize(f));
	}
	// show function's realname in the signature if realnames are enabled
	if (core->flags->realnames) {
		RzFlagItem *flag = rz_flag_get(core->flags, fcn_name);
		if (flag && rz_flag_item_get_realname(flag)) {
			fcn_name = rz_flag_item_get_realname(flag);
		}
	}

	char *sig = rz_analysis_fcn_format_sig(core->analysis, f, fcn_name, &vars_cache, COLOR(ds, fname), COLOR_RESET(ds));
	if (sig && fcnsig) {
		rz_cons_print(sig);
		RZ_FREE(sig);
	} else {
		rz_cons_printf("%s", fcn_name);
	}
	ds_newline(ds);

	if (ds->show_lines_fcn) {
		ds->pre = DS_PRE_FCN_MIDDLE;
	}

	if (ds->show_vars) {
		if (ds->show_varsum && ds->show_varsum != -1) { // show_varsum = 1 and 2
			printVarSummary(ds, vars_cache.sorted_vars);
		} else {
			ds_show_fn_vars_lines(ds, f, &vars_cache);
		}
	}
	ds->show_varsum = o_varsum;
	rz_analysis_fcn_vars_cache_fini(&vars_cache);
	if (fcn_name_alloc) {
		free(fcn_name);
	}

	RzListIter *iter;
	char *imp;
	if (ds->fcn && ds->fcn->imports) {
		rz_list_foreach (ds->fcn->imports, iter, imp) {
			ds_print_pre(ds, true);
			ds_print_lines_left(ds);
			rz_cons_printf(".import %s", imp);
			ds_newline(ds);
		}
	}
	rz_list_foreach (ds->core->analysis->imports, iter, imp) {
		ds_print_pre(ds, true);
		ds_print_lines_left(ds);
		rz_cons_printf(".globalimport %s", imp);
		ds_newline(ds);
	}
}

static void ds_setup_print_pre(RzDisasmState *ds, bool tail, bool middle) {
	ds_setup_pre(ds, tail, middle);
	ds_print_pre(ds, true);
}

static void ds_setup_pre(RzDisasmState *ds, bool tail, bool middle) {
	ds->cmtcount = 0;
	if (!ds->show_functions || !ds->show_lines_fcn) {
		ds->pre = DS_PRE_NONE;
		return;
	}
	ds->pre = DS_PRE_EMPTY;
	RzAnalysisFunction *f = fcnIn(ds, ds->at, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (f) {
		if (f->addr == ds->at) {
			if (ds->analysis_op.size == rz_analysis_function_linear_size(f) && !middle) {
				ds->pre = DS_PRE_FCN_TAIL;
			} else {
				ds->pre = DS_PRE_FCN_MIDDLE;
			}
		} else if (rz_analysis_function_max_addr(f) - ds->analysis_op.size == ds->at && f->addr == rz_analysis_function_min_addr(f)) {
			ds->pre = DS_PRE_FCN_TAIL;
		} else if (rz_analysis_function_contains(f, ds->at)) {
			ds->pre = DS_PRE_FCN_MIDDLE;
		}
		if (tail) {
			if (ds->pre == DS_PRE_FCN_TAIL) {
				ds->pre = DS_PRE_EMPTY;
			}
			if (ds->pre == DS_PRE_FCN_MIDDLE) {
				ds->pre = DS_PRE_FCN_TAIL;
			}
		}
	}
}

static void ds_print_pre(RzDisasmState *ds, bool fcnline) {
	RzCore *core = ds->core;
	int pre = ds->pre;
	const char *c = NULL;
	if (!fcnline) {
		pre = DS_PRE_EMPTY;
	}
	switch (pre) {
	case DS_PRE_FCN_HEAD:
		c = core->cons->vline[CORNER_TL];
		break;
	case DS_PRE_FCN_MIDDLE:
		c = core->cons->vline[LINE_VERT];
		break;
	case DS_PRE_FCN_TAIL:
		c = core->cons->vline[CORNER_BL];
		break;
	case DS_PRE_EMPTY:
		rz_cons_print("  ");
		return;
	case DS_PRE_NONE:
	default:
		return;
	}

	theme_print(fline, c);
	rz_cons_print(" ");
}

static void ds_show_comments_describe(RzDisasmState *ds) {
	/* respect asm.describe */
	char *desc = NULL;
	if (ds->asm_describe && !ds->has_description) {
		char *op, *locase = strdup(rz_asm_op_get_asm(&ds->asmop));
		if (!locase) {
			return;
		}
		op = strchr(locase, ' ');
		if (op) {
			*op = 0;
		}
		rz_str_case(locase, 0);
		desc = rz_asm_describe(ds->core->rasm, locase);
		free(locase);
	}
	if (RZ_STR_ISNOTEMPTY(desc)) {
		ds_begin_comment(ds);
		ds_align_comment(ds);
		theme_printf(comment, "; %s", desc);
		ds_newline(ds);
		free(desc);
	}
}

// XXX review this with asm.cmt.right
static void ds_show_comments_right(RzDisasmState *ds) {
	int linelen;
	RzCore *core = ds->core;
	/* show comment at right? */
	int scr = ds->show_comment_right;
	if (!ds->show_comments && !ds->show_usercomments) {
		return;
	}
	RzFlagItem *item = rz_flag_get_i(core->flags, ds->at);
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, ds->at);
	const char *vartype = rz_meta_get_string(core->analysis, RZ_META_TYPE_VARTYPE, ds->at);
	if (!comment) {
		if (vartype) {
			ds->comment = rz_str_newf("%s; %s", COLOR_ARG(ds, func_var_type), vartype);
		} else {
			const char *comment = item ? rz_flag_item_get_comment(item) : NULL;
			if (comment && *comment) {
				ds->ocomment = comment;
				ds->comment = strdup(comment);
			}
		}
	} else if (vartype) {
		ds->comment = rz_str_newf("%s; %s %s%s; %s", COLOR_ARG(ds, func_var_type), vartype, COLOR_RESET(ds), COLOR(ds, usercomment), comment);
	} else {
		ds->comment = rz_str_newf("%s; %s", COLOR_ARG(ds, usercomment), comment);
	}
	if (!ds->comment || !*ds->comment) {
		return;
	}
	linelen = strlen(ds->comment) + 5;
	if (ds->show_comment_right_default) {
		if (ds->ocols + linelen < core->cons->columns) {
			if (!strchr(ds->comment, '\n')) { // more than one line?
				ds->show_comment_right = true;
			}
		}
	}
	if (!ds->show_comment_right) {
		ds_begin_line(ds);
		int mycols = ds->lcols;
		if ((mycols + linelen + 10) > core->cons->columns) {
			mycols = 0;
		}
		mycols /= 2;
		theme_print_color(comment);
		ds_pre_xrefs(ds, false);

		theme_print_color(usercomment);
		ds_comment(ds, false, "%s", ds->comment);
		ds_print_color_reset(ds);

		RZ_FREE(ds->comment);
		ds_newline(ds);
		/* flag one */
		const char *flagcomment = item ? rz_flag_item_get_comment(item) : NULL;
		if (flagcomment && ds->ocomment != flagcomment) {
			ds_begin_line(ds);
			theme_print_color(comment);
			ds_newline(ds);
			ds_begin_line(ds);
			rz_cons_strcat("  ;  ");
			rz_cons_strcat_justify(flagcomment, mycols, ';');
			ds_newline(ds);
			ds_print_color_reset(ds);
		}
	}
	ds->show_comment_right = scr;
}

static int flagCmp(const void *a, const void *b, void *user) {
	const RzFlagItem *fa = a;
	const RzFlagItem *fb = b;
	if (rz_flag_item_get_realname(fa) && rz_flag_item_get_realname(fb)) {
		return strcmp(rz_flag_item_get_realname(fa), rz_flag_item_get_realname(fb));
	}
	return strcmp(rz_flag_item_get_name(fa), rz_flag_item_get_name(fb));
}

static void __preline_flag(RzDisasmState *ds, RzFlagItem *flag) {
	ds_newline(ds);
	ds_begin_line(ds);
	ds_pre_line(ds);
	if (ds->show_color) {
		bool hasColor = false;
		if (rz_flag_item_get_color(flag)) {
			char *color = rz_cons_pal_parse(rz_flag_item_get_color(flag), NULL);
			if (color) {
				rz_cons_strcat(color);
				free(color);
				ds->lastflag = flag;
				hasColor = true;
			}
		}
		if (!hasColor) {
			rz_cons_strcat(COLOR(ds, flag));
		}
	}
	if (!ds->show_offset) {
		rz_cons_printf("     ");
	}
}

// check the equality between names from symbol tab and debug info
// like sym.func_name and dbg.func_name
static bool is_sym_dbg_equal(const char *a, const char *b) {
	if (!rz_str_startswith(a, "sym.") && !rz_str_startswith(a, "dbg.")) {
		return false;
	}
	if (!rz_str_startswith(b, "sym.") && !rz_str_startswith(b, "dbg.")) {
		return false;
	}
	const size_t sym_n = strlen("sym.");
	return !strcmp(a + sym_n, b + sym_n);
}

static inline bool is_flag_overlapped(RzFlagItem *flag, RzAnalysisFunction *f) {
	const bool name_overlapped = !strcmp(rz_flag_item_get_name(flag), f->name) || is_sym_dbg_equal(rz_flag_item_get_name(flag), f->name);
	return f->addr == rz_flag_item_get_offset(flag) && name_overlapped;
}

#define printPre (outline || !*comma)
static void ds_show_flags(RzDisasmState *ds, bool overlapped) {
	// const char *beginch;
	RzFlagItem *flag;
	RzListIter *iter;
	RzAnalysisFunction *f = NULL;
	if (!ds->show_flags) {
		return;
	}
	RzCore *core = ds->core;
	char addr[64];
	ut64 switch_addr = UT64_MAX;
	int case_start = -1, case_prev = 0, case_current = 0;
	f = rz_analysis_get_function_at(ds->core->analysis, ds->at);
	const RzList *flaglist = rz_flag_get_list(core->flags, ds->at);
	RzList *uniqlist = flaglist ? rz_list_uniq(flaglist, flagCmp, NULL) : NULL;
	int count = 0;
	bool outline = !ds->flags_inline;
	const char *comma = "";
	bool docolon = true;
	int nth = 0;
	RzAnalysisBlock *switch_block = NULL;
	const char *switch_enum_name = NULL;
	rz_list_foreach (uniqlist, iter, flag) {
		if (!overlapped && f && is_flag_overlapped(flag, f)) {
			// do not show non-overlapped flags that have the same name as the function
			continue;
		}
		bool no_fcn_lines = (!overlapped && f && f->addr == rz_flag_item_get_offset(flag));
		if (ds->maxflags && count >= ds->maxflags) {
			if (printPre) {
				ds_pre_xrefs(ds, no_fcn_lines);
			}
			rz_cons_printf("...");
			break;
		}
		count++;
		if (!strncmp(rz_flag_item_get_name(flag), "case.", 5)) {
			sscanf(rz_flag_item_get_name(flag) + 5, "%63[^.].%d", addr, &case_current);
			ut64 saddr = rz_num_math(core->num, addr);
			if (case_start == -1) {
				switch_addr = saddr;
				case_prev = case_current;
				case_start = case_current;
				if (iter != uniqlist->tail) {
					continue;
				}
			}
			if (case_current == case_prev + 1 && switch_addr == saddr) {
				case_prev = case_current;
				if (iter != uniqlist->tail) {
					continue;
				}
			}
		}
		if (printPre) {
			ds_begin_line(ds);
		}

		bool fake_flag_marks = (!ds->show_offset && ds->show_marks);
		if (printPre) {
			if (ds->show_flgoff) {
				ds_pre_line(ds);
				ds_print_offset(ds);
				if (!fake_flag_marks) {
					rz_cons_printf(" ");
				}
			} else {
				ds_pre_xrefs(ds, no_fcn_lines);
			}
		}

		bool hasColor = false;
		char *color = NULL;
		if (ds->show_color) {
			if (rz_flag_item_get_color(flag)) {
				color = rz_cons_pal_parse(rz_flag_item_get_color(flag), NULL);
				if (color) {
					rz_cons_strcat(color);
					ds->lastflag = flag;
					hasColor = true;
				}
			}
			if (!hasColor) {
				rz_cons_strcat(COLOR(ds, flag));
			}
		}

		if (rz_flag_item_get_realname(flag)) {
			if (!strncmp(rz_flag_item_get_name(flag), "switch.", 7)) {
				rz_cons_printf(FLAG_PREFIX "switch");
			} else if (!strncmp(rz_flag_item_get_name(flag), "case.", 5)) {
				if (nth > 0) {
					__preline_flag(ds, flag);
				}
				if (!switch_block || switch_block->switch_op->addr != switch_addr) {
					switch_enum_name = NULL;
					switch_block = NULL;
					RzList *blocks = rz_analysis_get_blocks_in(core->analysis, switch_addr);
					RzListIter *it;
					RzAnalysisBlock *block;
					rz_list_foreach (blocks, it, block) {
						if (block->switch_op && block->switch_op->addr == switch_addr) {
							switch_block = block;
							if (block->switch_op->enum_type) {
								switch_enum_name = rz_type_identifier(block->switch_op->enum_type);
							}
							break;
						}
					}
					rz_list_free(blocks);
				}
				if (!strncmp(rz_flag_item_get_name(flag) + 5, "default", 7)) {
					rz_cons_printf(FLAG_PREFIX "default:"); // %s:", rz_flag_item_get_name(flag));
					rz_str_ncpy(addr, rz_flag_item_get_name(flag) + 5 + strlen("default."), sizeof(addr));
					nth = 0;
				} else {
					const char *case_prev_name = NULL;
					if (switch_enum_name) {
						case_prev_name = rz_type_db_enum_member_by_val(core->analysis->typedb, switch_enum_name, case_prev);
					}
					rz_cons_printf(FLAG_PREFIX "case ");
					if (case_prev != case_start) {
						const char *case_start_name = NULL;
						if (switch_enum_name) {
							case_start_name = rz_type_db_enum_member_by_val(core->analysis->typedb, switch_enum_name, case_start);
						}
						if (case_start_name) {
							rz_cons_printf("%s...", case_start_name);
						} else {
							rz_cons_printf("%d...", case_start);
						}
						if (case_prev_name) {
							rz_cons_printf("%s:", case_prev_name);
						} else {
							rz_cons_printf("%d:", case_prev);
						}
						if (iter != uniqlist->head && iter != uniqlist->tail) {
							iter = rz_list_iter_get_prev(iter);
						}
						case_start = case_current;
					} else {
						if (!case_prev_name) {
							rz_cons_printf("%d:", case_prev);
						} else {
							rz_cons_printf("%s:", case_prev_name);
						}
						case_start = -1;
					}
				}
				case_prev = case_current;
				ds_align_comment(ds);
				rz_cons_printf("%s; from %s", COLOR(ds, comment), addr);
				outline = false;
				docolon = false;
			} else {
				char *name = strdup(rz_flag_item_get_realname(flag) ? rz_flag_item_get_realname(flag) : rz_flag_item_get_name(flag));
				if (name) {
					rz_str_ansi_filter(name, NULL, NULL, -1);
					if (!ds->flags_inline || nth == 0) {
						rz_cons_printf(FLAG_PREFIX);
						if (overlapped) {
							rz_cons_printf("%s(0x%08" PFMT64x ")%s ", COLOR(ds, offset), ds->at,
								ds->show_color ? (hasColor ? color : COLOR(ds, flag)) : "");
						}
					}
					if (outline) {
						rz_cons_printf("%s:", name);
					} else {
						rz_cons_printf("%s%s", comma, rz_flag_item_get_name(flag));
					}
					RZ_FREE(name);
				}
			}
		} else {
			if (outline) {
				rz_cons_printf(FLAG_PREFIX "%s", rz_flag_item_get_name(flag));
			} else {
				rz_cons_printf("%s%s", comma, rz_flag_item_get_name(flag));
			}
		}
		ds_print_color_reset(ds);
		if (outline) {
			ds_newline(ds);
		} else {
			comma = ", ";
		}
		free(color);
		nth++;
	}
	if (!outline && *comma) {
		if (nth > 0 && docolon) {
			rz_cons_printf(":");
		}
		ds_newline(ds);
	}
	rz_list_free(uniqlist);
}

static void ds_update_ref_lines(RzDisasmState *ds) {
	if (ds->show_lines_bb) {
		free(ds->line);
		free(ds->line_col);
		RzAnalysisRefStr *line = rz_analysis_reflines_str(ds->core, ds->at, ds->linesopts);
		ds->line = line->str;
		ds->line_col = line->cols;
		free(ds->refline);
		ds->refline = ds->line ? strdup(ds->line) : NULL;
		free(ds->refline2);
		free(ds->prev_line_col);
		free(line);
		line = rz_analysis_reflines_str(ds->core, ds->at,
			ds->linesopts | RZ_ANALYSIS_REFLINE_TYPE_MIDDLE_BEFORE);
		ds->refline2 = line->str;
		ds->prev_line_col = line->cols;
		if (ds->line) {
			if (strchr(ds->line, '<')) {
				ds->indent_level++;
			}
			if (strchr(ds->line, '>')) {
				ds->indent_level--;
			}
		} else {
			ds->indent_level = 0;
		}
		free(line);
	} else {
		RZ_FREE(ds->line);
		RZ_FREE(ds->line_col);
		RZ_FREE(ds->prev_line_col);
		free(ds->refline);
		free(ds->refline2);
		free(ds->prev_line_col);
		ds->refline = strdup("");
		ds->refline2 = strdup("");
		ds->line = NULL;
		ds->line_col = NULL;
		ds->prev_line_col = NULL;
	}
}

static int ds_disassemble(RzDisasmState *ds, ut8 *buf, int len) {
	RzCore *core = ds->core;
	int ret;

	// find the meta item at this offset if any
	RzPVector *metas = rz_meta_get_all_at(ds->core->analysis, ds->at); // TODO: do in range
	RzAnalysisMetaItem *meta = NULL;
	ut64 meta_size = UT64_MAX;
	if (metas) {
		void **it;
		rz_pvector_foreach (metas, it) {
			RzIntervalNode *node = *it;
			RzAnalysisMetaItem *mi = node->data;
			switch (mi->type) {
			case RZ_META_TYPE_DATA:
			case RZ_META_TYPE_STRING:
			case RZ_META_TYPE_FORMAT:
			case RZ_META_TYPE_MAGIC:
			case RZ_META_TYPE_HIDE:
				meta = mi;
				meta_size = rz_meta_item_size(node->start, node->end);
				break;
			default:
				break;
			}
		}
		rz_pvector_free(metas);
	}
	if (ds->hint && ds->hint->bits) {
		if (!ds->core->analysis->opt.ignbithints) {
			rz_config_set_i(core->config, "asm.bits", ds->hint->bits);
		}
	}
	if (ds->hint && ds->hint->size) {
		ds->oplen = ds->hint->size;
	}
	if (ds->hint && ds->hint->opcode) {
		free(ds->opstr);
		ds->opstr = strdup(ds->hint->opcode);
	}
	rz_asm_op_fini(&ds->asmop);
	ret = rz_asm_disassemble(core->rasm, &ds->asmop, buf, len);
	ds_asmop_fixup(ds);
	if (ds->asmop.size < 1) {
		ds->asmop.size = 1;
	}
	// handle meta here //
	if (!ds->asm_meta) {
		int i = 0;
		if (meta && meta_size > 0 && meta->type != RZ_META_TYPE_HIDE) {
			// XXX this is just noise. should be rewritten
			switch (meta->type) {
			case RZ_META_TYPE_DATA:
				if (meta->str) {
					rz_cons_printf(".data: %s\n", meta->str);
				}
				i += meta_size;
				break;
			case RZ_META_TYPE_STRING:
				i += meta_size;
				break;
			case RZ_META_TYPE_FORMAT:
				rz_cons_printf(".format : %s\n", meta->str);
				i += meta_size;
				break;
			case RZ_META_TYPE_MAGIC:
				rz_cons_printf(".magic : %s\n", meta->str);
				i += meta_size;
				break;
			default:
				break;
			}
			int sz = RZ_MIN(16, meta_size);
			ds->asmop.size = sz;
			rz_asm_op_set_hexbuf(&ds->asmop, buf, sz);
			const char *tail = (meta_size > 16) ? "..." : "";
			switch (meta->type) {
			case RZ_META_TYPE_STRING:
				rz_asm_op_setf_asm(&ds->asmop, ".string \"%s%s\"", meta->str, tail);
				break;
			default: {
				char *op_hex = rz_asm_op_get_hex(&ds->asmop);
				rz_asm_op_setf_asm(&ds->asmop, ".hex %s%s", op_hex, tail);
				free(op_hex);
				break;
			}
			}
			ds->oplen = meta_size;
			return i;
		}
	}

	if (ds->show_nodup) {
		const char *opname = (ret < 1) ? "invalid" : rz_asm_op_get_asm(&ds->asmop);
		if (ds->prev_ins && !strcmp(ds->prev_ins, opname)) {
			if (!ds->prev_ins_eq) {
				ds->prev_ins_eq = true;
				rz_cons_printf("...");
			}
			ds->prev_ins_count++;
			return -31337;
		}
		if (ds->prev_ins_eq) {
			rz_cons_printf("dup (%d)\n", ds->prev_ins_count);
		}
		ds->prev_ins_count = 0;
		ds->prev_ins_eq = false;
		if (ds->prev_ins) {
			RZ_FREE(ds->prev_ins);
		}
		ds->prev_ins = strdup(rz_asm_op_get_asm(&ds->asmop));
	}
	ds->oplen = ds->asmop.size;

	if (ret < 1) {
		ret = -1;
#if HASRETRY
		if (!ds->cbytes && ds->tries > 0) {
			ds->addr = core->rasm->pc;
			ds->tries--;
			ds->idx = 0;
			ds->retry = true;
			return ret;
		}
#endif
		ds->lastfail = 1;
		ds->asmop.size = (ds->hint && ds->hint->size) ? ds->hint->size : 1;
		ds->oplen = ds->asmop.size;
	} else {
		ds->lastfail = 0;
		ds->asmop.size = (ds->hint && ds->hint->size)
			? ds->hint->size
			: rz_asm_op_get_size(&ds->asmop);
		ds->oplen = ds->asmop.size;
	}
	if (ds->pseudo) {
		const char *opstr = rz_asm_op_get_asm(&ds->asmop);
		char *tmp = rz_parse_pseudocode(core->parser, opstr);
		free(ds->opstr);
		if (tmp) {
			snprintf(ds->str, sizeof(ds->str), "%s", tmp);
			ds->opstr = tmp;
		} else {
			ds->opstr = strdup("");
			ds->str[0] = 0;
		}
	}
	if (ds->acase) {
		rz_str_case(rz_asm_op_get_asm(&ds->asmop), 1);
	} else if (ds->capitalize) {
		char *ba = rz_asm_op_get_asm(&ds->asmop);
		rz_str_case(ba, true);
	}
	if (meta && meta_size != UT64_MAX) {
		ds->oplen = meta_size;
	}
	return ret;
}

static void ds_control_flow_comments(RzDisasmState *ds) {
	if (ds->show_comments && ds->show_cmtflgrefs) {
		RzFlagItem *item;
		if (ds->asm_analysis) {
			switch (ds->analysis_op.type) {
			case RZ_ANALYSIS_OP_TYPE_CALL:
				rz_core_analysis_function_add(ds->core, NULL, ds->analysis_op.jump, false);
				break;
			}
		}
		switch (ds->analysis_op.type) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			item = rz_flag_get_i(ds->core->flags, ds->analysis_op.jump);
			const char *fcomment = item ? rz_flag_item_get_comment(item) : NULL;
			if (item && fcomment) {
				theme_print_color(comment);
				ds_align_comment(ds);
				rz_cons_printf("  ; ref to %s: %s\n", rz_flag_item_get_name(item), fcomment);
				ds_print_color_reset(ds);
			}
			break;
		}
	}
}

static void ds_print_lines_right(RzDisasmState *ds) {
	if (ds->linesright && ds->show_lines_bb && ds->line) {
		ds_print_ref_lines(ds->line, ds->line_col, ds);
	}
}

static void printCol(RzDisasmState *ds, char *sect, int cols, const char *color) {
	int pre;
	if (cols < 8) {
		cols = 8;
	}
	int outsz = cols + 32;
	char *out = malloc(outsz);
	if (!out) {
		return;
	}
	memset(out, ' ', outsz);
	out[outsz - 1] = 0;
	int sect_len = strlen(sect);

	if (sect_len > cols) {
		sect[cols - 2] = '.';
		sect[cols - 1] = '.';
		sect[cols] = 0;
	}
	if (ds->show_color) {
		pre = strlen(color) + 1;
		snprintf(out, outsz - pre, "%s %s", color, sect);
		strcat(out, COLOR_RESET(ds));
		out[outsz - 1] = 0;
	} else {
		rz_str_ncpy(out + 1, sect, outsz - 2);
	}
	strcat(out, " ");
	rz_cons_strcat(out);
	free(out);
}

static void ds_print_lines_left(RzDisasmState *ds) {
	if (ds->linesright) {
		return;
	}
	RzCore *core = ds->core;
	if (ds->show_section) {
		char *str = NULL;
		if (ds->show_section_perm && core->bin && core->bin->cur) {
			int va = rz_config_get_i(core->config, "io.va");
			RzBinSection *sec = rz_bin_get_section_at(core->bin->cur->o, ds->at, va);
			str = strdup(sec ? rz_str_rwx_i(sec->perm) : "---");
		}
		if (ds->show_section_name && core->bin && core->bin->cur) {
			int va = rz_config_get_i(core->config, "io.va");
			RzBinSection *sec = rz_bin_get_section_at(core->bin->cur->o, ds->at, va);
			if (sec) {
				if (str) {
					str = rz_str_append(str, " ");
				}
				str = rz_str_appendf(str, "%10.10s", sec->name);
			}
		}
		char *sect = str ? str : strdup("");
		printCol(ds, sect, ds->show_section_col, COLOR(ds, reg));
		free(sect);
	}
	if (ds->show_symbols) {
		const char *name = "";
		int delta = 0;
#if 0 // TODO: make sure this does break some tests, if not add some!
		if (ds->fcn) {
			ds->lastflagitem.offset = ds->fcn->addr;
			ds->lastflagitem.name = ds->fcn->name;
			ds->lastflag = &ds->lastflagitem;
		} else {
			RzFlagItem *fi = rz_flag_get_at(core->flags, ds->at, !ds->lastflag);
			if (fi) { // && (!ds->lastflag || rz_flag_item_get_offset(fi) != ds->at))
				ds->lastflagitem.offset = rz_flag_item_get_offset(fi);
				ds->lastflagitem.name = rz_flag_item_get_name(fi);
				ds->lastflag = &ds->lastflagitem;
			}
#endif
		}
		if (ds->lastflag && ds->lastrz_flag_item_get_name(flag)) {
			name = ds->lastrz_flag_item_get_name(flag);
			delta = ds->at - ds->lastrz_flag_item_get_offset(flag);
		}
		{
			char *str = rz_str_newf("%s + %-4d", name, delta);
			printCol(ds, str, ds->show_symbols_col, COLOR(ds, num));
			free(str);
		}
	}
	if (ds->line) {
		ds_print_ref_lines(ds->line, ds->line_col, ds);
	}
}

static void ds_print_family(RzDisasmState *ds) {
	if (ds->show_family) {
		const char *familystr = rz_analysis_op_family_to_string(ds->analysis_op.family);
		rz_cons_printf("%5s ", familystr ? familystr : "");
	}
}

static void ds_print_cycles(RzDisasmState *ds) {
	if (ds->show_cycles) {
		if (!ds->analysis_op.failcycles) {
			rz_cons_printf("%3d     ", ds->analysis_op.cycles);
		} else {
			rz_cons_printf("%3d %3d ", ds->analysis_op.cycles, ds->analysis_op.failcycles);
		}
	}
	if (ds->cyclespace) {
		char spaces[32];
		int times = RZ_MIN(ds->analysis_op.cycles / 4, 30); // limit to 30
		memset(spaces, ' ', sizeof(spaces));
		spaces[times] = 0;
		rz_cons_strcat(spaces);
	}
}

static RzStackAddr ds_stackptr_at(RzDisasmState *ds, ut64 addr) {
	if (!ds->fcn) {
		return RZ_STACK_ADDR_INVALID;
	}
	RzAnalysisBlock *block = rz_analysis_fcn_bbget_in(ds->core->analysis, ds->fcn, addr);
	if (!block) {
		return RZ_STACK_ADDR_INVALID;
	}
	return rz_analysis_block_get_sp_at(block, addr);
}

/**
 * Print stackpointer info between offset and disassembly like
 *     0x08049413   -12 -= 4       push  str.echoes
 */
static void ds_print_stackptr(RzDisasmState *ds) {
	if (!ds->show_stackptr) {
		return;
	}
	RzStackAddr sp = ds_stackptr_at(ds, ds->at);
	if (sp == RZ_STACK_ADDR_INVALID) {
		rz_cons_print("    ? ");
	} else {
		rz_cons_printf("%5" PFMT64d " ", sp);
	}
	char *eff = rz_analysis_op_describe_sp_effect(&ds->analysis_op);
	if (eff) {
		rz_cons_print(eff);
		int len = strlen(eff);
		for (; len < 6; len++) {
			rz_cons_print(" ");
		}
	} else {
		rz_cons_print("      ");
	}
}

static void ds_print_offset(RzDisasmState *ds) {
	RzCore *core = ds->core;
	ut64 at = ds->vat;

	bool hasCustomColor = false;
	// probably tooslow
	RzFlagItem *f = rz_flag_get_at(core->flags, at, 1);
	if (ds->show_color && f) { // ds->lastflag) {
		const char *color = f->color;
		if (ds->at >= f->offset && ds->at < f->offset + f->size) {
			//	if (rz_itv_inrange (f->itv, ds->at))
			if (color && *color) {
				char *k = rz_cons_pal_parse(f->color, NULL);
				if (k) {
					rz_cons_printf("%s", k);
					hasCustomColor = true;
					free(k);
				}
			}
		}
	}
	rz_print_set_screenbounds(core->print, at);
	if (ds->show_offset) {
		const char *label = NULL;
		RzFlagItem *fi;
		int delta = -1;
		bool show_trace = false;
		unsigned int seggrn = rz_config_get_i(core->config, "asm.seggrn");

		if (ds->show_reloff) {
			RzAnalysisFunction *f = rz_analysis_get_function_at(core->analysis, at);
			if (!f) {
				f = fcnIn(ds, at, RZ_ANALYSIS_FCN_TYPE_NULL); // rz_analysis_get_fcn_in (core->analysis, at, RZ_ANALYSIS_FCN_TYPE_NULL);
			}
			if (f) {
				delta = at - f->addr;
#if 0 // TODO: make sure this does break some tests, if not add some!
				ds->lastflagitem.name = f->name;
				ds->lastflagitem.offset = f->addr;
				ds->lastflag = &ds->lastflagitem;
#endif
				label = f->name;
			} else {
				if (ds->show_reloff_flags) {
					/* XXX: this is wrong if starting to disasm after a flag */
					fi = rz_flag_get_i(core->flags, at);
					if (fi) {
						ds->lastflag = fi;
					}
					if (ds->lastflag) {
						if (ds->lastrz_flag_item_get_offset(flag) == at) {
							delta = 0;
						} else {
							delta = at - ds->lastrz_flag_item_get_offset(flag);
						}
					} else {
						delta = at - core->offset;
					}
					if (ds->lastflag) {
						label = ds->lastrz_flag_item_get_name(flag);
					}
				}
			}
			if (!ds->lastflag) {
				delta = 0;
			}
		}
		if (ds->show_trace) {
			RzDebugTracepoint *tp = rz_debug_trace_get(ds->core->dbg, ds->at);
			show_trace = (tp ? !!tp->count : false);
		}
		if (ds->hint && ds->hint->high) {
			show_trace = true;
		}
		if (hasCustomColor) {
			int of = core->print->flags;
			core->print->flags = 0;
			rz_print_offset_sg(core->print, at, (at == ds->dest) || show_trace,
				rz_config_get_b(core->config, "asm.segoff"), seggrn, ds->show_offdec, delta, label);
			core->print->flags = of;
			rz_cons_strcat(Color_RESET);
		} else {
			rz_print_offset_sg(core->print, at, (at == ds->dest) || show_trace,
				rz_config_get_b(core->config, "asm.segoff"), seggrn, ds->show_offdec, delta, label);
		}
	}
	if (ds->atabsoff > 0 && ds->show_offset) {
		if (ds->_tabsoff != ds->atabsoff) {
			// TODO optimize to avoid down resizing
			char *b = malloc(ds->atabsoff + 1);
			if (b) {
				memset(b, ' ', ds->atabsoff);
				b[ds->atabsoff] = 0;
				free(ds->_tabsbuf);
				ds->_tabsbuf = b;
				ds->_tabsoff = ds->atabsoff;
			}
		}
		rz_cons_strcat(ds->_tabsbuf);
	}
}

static bool requires_op_size(RzDisasmState *ds) {
	RzPVector *metas = rz_meta_get_all_in(ds->core->analysis, ds->at, RZ_META_TYPE_ANY);
	if (!metas) {
		return false;
	}

	void **it;
	bool res = true;
	rz_pvector_foreach (metas, it) {
		RzIntervalNode *node = *it;
		RzAnalysisMetaItem *mi = node->data;
		switch (mi->type) {
		case RZ_META_TYPE_DATA:
		case RZ_META_TYPE_STRING:
		case RZ_META_TYPE_FORMAT:
		case RZ_META_TYPE_MAGIC:
		case RZ_META_TYPE_HIDE:
			res = false;
			break;
		default:
			break;
		}
	}

	rz_pvector_free(metas);
	return res;
}

static void ds_print_op_size(RzDisasmState *ds) {
	if (ds->show_size && requires_op_size(ds)) {
		int size = ds->oplen;
		rz_cons_printf("%d ", size); // ds->analysis_op.size);
	}
}

static void ds_print_trace(RzDisasmState *ds) {
	RzDebugTracepoint *tp = NULL;
	if (ds->show_trace) {
		tp = rz_debug_trace_get(ds->core->dbg, ds->at);
		rz_cons_printf("%02x:%04x ", tp ? tp->times : 0, tp ? tp->count : 0);
	}
	if (ds->tracespace) {
		char spaces[32];
		int times;
		if (!tp) {
			tp = rz_debug_trace_get(ds->core->dbg, ds->at);
		}
		if (tp) {
			times = RZ_MIN(tp->times, 30); // limit to 30
			memset(spaces, ' ', sizeof(spaces));
			spaces[times] = 0;
			rz_cons_strcat(spaces);
		}
	}
}

static void ds_adistrick_comments(RzDisasmState *ds) {
	if (ds->adistrick) {
		ds->middle = rz_analysis_reflines_middle(ds->core->analysis,
			ds->core->analysis->reflines, ds->at, ds->analysis_op.size);
	}
}

// TODO move into RzAnalysis.meta
static bool ds_print_data_type(RzDisasmState *ds, const ut8 *buf, int ib, int size) {
	RzCore *core = ds->core;
	const char *type = NULL;
	char msg[64];
	const int isSigned = (ib == 1 || ib == 8 || ib == 10) ? 1 : 0;
	switch (size) {
	case 1: type = isSigned ? ".char" : ".byte"; break;
	case 2: type = isSigned ? ".int16" : ".word"; break;
	case 3: type = "htons"; break;
	case 4: type = isSigned ? ".int32" : ".dword"; break;
	case 8: type = isSigned ? ".int64" : ".qword"; break;
	default: return false;
	}
	// adjust alignment
	ut64 n = rz_read_ble(buf, core->print->big_endian, size * 8);
	if (rz_config_get_b(core->config, "asm.marks")) {
		rz_cons_printf("  ");
		int q = core->print->cur_enabled &&
			ds->cursor >= ds->index &&
			ds->cursor < (ds->index + size);
		if (q) {
			if (ds->cursor > ds->index) {
				int diff = ds->cursor - ds->index;
				rz_cons_printf("%d  ", diff);
			} else if (ds->cursor == ds->index) {
				rz_cons_printf("*  ");
			} else {
				rz_cons_printf("   ");
			}
		} else {
			rz_cons_printf("   ");
		}
	}

	rz_cons_strcat(COLOR(ds, mov));
	switch (ib) {
	case 1:
		rz_str_bits(msg, buf, size * 8, NULL);
		rz_cons_printf("%s %sb", type, msg);
		break;
	case 3:
		rz_cons_printf("%s %d", type, ntohs(n & 0xFFFF));
		break;
	case 8:
		rz_cons_printf("%s %" PFMT64o "o", type, n);
		break;
	case 10:
		rz_cons_printf("%s %" PFMT64d, type, n);
		break;
	default:
		switch (size) {
		case 1:
			rz_cons_printf("%s 0x%02" PFMT64x, type, n);
			break;
		case 2:
			rz_cons_printf("%s 0x%04" PFMT64x, type, n);
			break;
		case 4:
			rz_cons_printf("%s 0x%08" PFMT64x, type, n);
			break;
		case 8:
			rz_cons_printf("%s 0x%016" PFMT64x, type, n);
			break;
		default:
			return false;
		}
	}

	if (size == 4 || size == 8) {
		if (rz_str_startswith(rz_config_get(core->config, "asm.arch"), "arm")) {
			ut64 bits = rz_config_get_i(core->config, "asm.bits");
			// adjust address for arm/thumb address
			if (bits < 64) {
				if (n & 1) {
					n--;
				}
			}
		}
		if (n >= ds->min_ref_addr) {
			const RzList *flags = rz_flag_get_list(core->flags, n);
			RzListIter *iter;
			RzFlagItem *fi;
			rz_list_foreach (flags, iter, fi) {
				rz_cons_printf(" ; %s", rz_flag_item_get_name(fi));
			}
		}
	}
	return true;
}

static bool ds_print_meta_infos(RzDisasmState *ds, ut8 *buf, int len, int idx, int *mi_type) {
	bool ret = false;
	RzAnalysisMetaItem *fmi;
	RzCore *core = ds->core;
	if (!ds->asm_meta) {
		return false;
	}
	RzPVector *metas = rz_meta_get_all_in(core->analysis, ds->at, RZ_META_TYPE_ANY);
	if (!metas) {
		return false;
	}
	bool once = true;
	fmi = NULL;
	void **it;
	rz_pvector_foreach (metas, it) {
		RzIntervalNode *node = *it;
		RzAnalysisMetaItem *mi = node->data;
		switch (mi->type) {
		case RZ_META_TYPE_DATA:
			if (once) {
				if (ds->asm_hint_pos == 0) {
					if (ds->asm_hint_lea) {
						ds_print_shortcut(ds, node->start, 0);
					} else {
						rz_cons_strcat("   ");
					}
				}
				once = false;
			}
			break;
		case RZ_META_TYPE_STRING:
			fmi = mi;
			break;
		default:
			break;
		}
	}
	rz_pvector_foreach (metas, it) {
		RzIntervalNode *node = *it;
		RzAnalysisMetaItem *mi = node->data;
		ut64 mi_size = rz_meta_node_size(node);
		char *out = NULL;
		int hexlen;
		int delta;
		if (fmi && mi != fmi) {
			continue;
		}
		if (mi_type) {
			*mi_type = mi->type;
		}
		switch (mi->type) {
		case RZ_META_TYPE_STRING:
			if (mi->str) {
				RzStrEscOptions opt = { 0 };
				opt.esc_bslash = core->print->esc_bslash;
				opt.esc_double_quotes = true;
				opt.show_asciidot = false;

				switch (mi->subtype) {
				case RZ_STRING_ENC_UTF8:
					out = rz_str_escape_utf8(mi->str, &opt);
					break;
				case 0: /* temporary legacy workaround */
					opt.esc_bslash = false;
					/* fallthrough */
				default:
					out = rz_str_escape_8bit(mi->str, false, &opt);
					break;
				}
				if (!out) {
					break;
				}
				rz_cons_printf("    .string %s\"%s\"%s ; len=%" PFMT64d,
					COLOR(ds, btext), out, COLOR_RESET(ds),
					mi_size);
				free(out);
				delta = ds->at - node->start;
				ds->oplen = mi_size - delta;
				ds->asmop.size = (int)mi_size;
				// i += mi->size-1;
				RZ_FREE(ds->line);
				RZ_FREE(ds->line_col);
				RZ_FREE(ds->refline);
				RZ_FREE(ds->refline2);
				RZ_FREE(ds->prev_line_col);
				ret = true;
			}
			break;
		case RZ_META_TYPE_HIDE:
			rz_cons_printf("(%" PFMT64d " bytes hidden)", mi_size);
			ds->asmop.size = mi_size;
			ds->oplen = mi_size;
			ret = true;
			break;
		case RZ_META_TYPE_DATA:
			hexlen = len - idx;
			delta = ds->at - node->start;
			if (mi_size < hexlen) {
				hexlen = mi_size;
			}
			ds->oplen = mi_size - delta;
			core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
			int size = RZ_MIN(mi_size, len - idx);
			if (!ds_print_data_type(ds, buf + idx, ds->hint ? ds->hint->immbase : 0, size)) {
				if (size > delta && hexlen > delta) {
					rz_cons_printf("hex length=%d delta=%d\n", size, delta);
					rz_core_print_hexdump(core, ds->at, buf + idx, hexlen - delta, 16, 1, 1);
				} else {
					rz_cons_printf("hex size=%d hexlen=%d delta=%d", size, hexlen, delta);
				}
			}
			core->print->flags |= RZ_PRINT_FLAGS_HEADER;
			ds->asmop.size = (int)size - (node->start - ds->at);
			RZ_FREE(ds->line);
			RZ_FREE(ds->line_col);
			RZ_FREE(ds->refline);
			RZ_FREE(ds->refline2);
			RZ_FREE(ds->prev_line_col);
			ret = true;
			break;
		case RZ_META_TYPE_FORMAT: {
			rz_cons_printf("pf %s # size=%" PFMT64d "\n", mi->str, mi_size);
			int len_before = rz_cons_get_buffer_len();
			char *format = rz_type_format_data(core->analysis->typedb, core->print, ds->at, buf + idx,
				len - idx, mi->str, RZ_PRINT_MUSTSEE, NULL, NULL);
			if (format) {
				rz_cons_print(format);
				free(format);
			}
			int len_after = rz_cons_get_buffer_len();
			const char *cons_buf = rz_cons_get_buffer();
			if (len_after > len_before && buf && cons_buf[len_after - 1] == '\n') {
				rz_cons_drop(1);
			}
			ds->oplen = ds->asmop.size = (int)mi_size;
			RZ_FREE(ds->line);
			RZ_FREE(ds->refline);
			RZ_FREE(ds->refline2);
			RZ_FREE(ds->prev_line_col);
			ret = true;
		} break;
		default:
			break;
		}
	}
	rz_pvector_free(metas);
	return ret;
}

static st64 revert_cdiv_magic(st64 magic) {
	ut64 amagic = llabs(magic);
	const st64 N = ST64_MAX;
	st64 E, candidate;
	short s;

	if (amagic < 0xFFFFFF || amagic > UT32_MAX) {
		return 0;
	}
	if (magic < 0) {
		magic += 1LL << 32;
	}
	for (s = 0; s < 16; s++) {
		E = 1LL << (32 + s);
		candidate = (E + magic - 1) / magic;
		if (candidate > 0) {
			if (((N * magic) >> (32 + s)) == (N / candidate)) {
				return candidate;
			}
		}
	}
	return 0;
}

static void ds_cdiv_optimization(RzDisasmState *ds) {
	char *esil;
	char *end, *comma;
	st64 imm;
	st64 divisor;
	if (!ds->asm_hints || !ds->asm_hint_cdiv) {
		return;
	}
	switch (ds->analysis_op.type) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_MUL:
		esil = RZ_STRBUF_SAFEGET(&ds->analysis_op.esil);
		while (esil) {
			comma = strchr(esil, ',');
			if (!comma) {
				break;
			}
			imm = strtol(esil, &end, 10);
			if (comma && comma == end) {
				divisor = revert_cdiv_magic(imm);
				if (divisor) {
					rz_cons_printf(" ; CDIV: %lld * 2^n", divisor);
					break;
				}
			}
			esil = comma + 1;
		}
	}
	// /TODO: check following SHR instructions
}

static void ds_print_show_bytes(RzDisasmState *ds) {
	RzCore *core = ds->core;
	char *nstr, *str = NULL, pad[64];
	char *flagstr = NULL;
	int oldFlags = core->print->flags;
	char extra[128];
	int j, k;

	if (!ds->show_bytes || ds->nb < 1) {
		return;
	}
	if (!ds->show_color_bytes) {
		core->print->flags &= ~RZ_PRINT_FLAGS_COLOR;
	}
	strcpy(extra, " ");
	if (ds->show_flag_in_bytes) {
		flagstr = rz_flag_get_liststr(core->flags, ds->at);
	}
	if (flagstr) {
		str = rz_str_newf("%s:", flagstr);
		if (ds->nb > 0) {
			k = ds->nb - strlen(str) - 1;
			if (k < 0) {
				str[ds->nb - 1] = '\0';
			}
			if (k > sizeof(pad)) {
				k = 0;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
		} else {
			pad[0] = 0;
		}
		RZ_FREE(flagstr);
	} else {
		if (ds->show_flag_in_bytes) {
			k = ds->nb - 1;
			if (k < 0 || k > sizeof(pad)) {
				k = 0;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
			str = strdup("");
		} else {
			str = rz_asm_op_get_hex(&ds->asmop);
			if (rz_str_ansi_len(str) > ds->nb) {
				char *p = (char *)rz_str_ansi_chrn(str, ds->nb);
				if (p) {
					p[0] = '.';
					p[1] = '\0';
				}
			}
			ds->print->cur_enabled = (ds->cursor != -1);
			nstr = rz_print_hexpair(ds->print, str, ds->index);
			if (ds->print->bytespace) {
				k = (ds->nb + (ds->nb / 2)) - rz_str_ansi_len(nstr) + 2;
			} else {
				k = ds->nb - rz_str_ansi_len(nstr) + 1;
			}
			if (k > 0) {
				// setting to sizeof screw up the disasm
				if (k > sizeof(pad)) {
					k = 18;
				}
				for (j = 0; j < k; j++) {
					pad[j] = ' ';
				}
				pad[j] = 0;
				if (ds->lbytes) {
					// hack to align bytes left
					strcpy(extra, pad);
					*pad = 0;
				}
			} else {
				pad[0] = 0;
			}
			free(str);
			str = nstr;
		}
	}
	rz_cons_printf("%s%s %s", pad, str, extra);
	free(str);
	core->print->flags = oldFlags;
}

static void ds_print_indent(RzDisasmState *ds) {
	if (ds->show_indent) {
		char indent[128];
		int num = ds->indent_level * ds->indent_space;
		if (num < 0) {
			num = 0;
		}
		if (num >= sizeof(indent)) {
			num = sizeof(indent) - 1;
		}
		memset(indent, ' ', num);
		indent[num] = 0;
		rz_cons_strcat(indent);
	}
}

static void ds_print_optype(RzDisasmState *ds) {
	if (ds->show_optype) {
		const char *optype = rz_analysis_optype_to_string(ds->analysis_op.type);
		ds_print_color_reset(ds);
		char *pad = rz_str_pad(' ', 8 - strlen(optype));
		rz_cons_printf("[%s]%s", optype, pad);
		free(pad);
	}
}

static void ds_print_opstr(RzDisasmState *ds) {
	ds_print_indent(ds);
	if (ds->asm_instr) {
		rz_cons_strcat(ds->opstr);
		ds_print_color_reset(ds);
	}
}

static void ds_print_color_reset(RzDisasmState *ds) {
	if (ds->show_color) {
		rz_cons_strcat(Color_RESET);
	}
}

static int ds_print_middle(RzDisasmState *ds, int ret) {
	if (ds->middle != 0) {
		ret -= ds->middle;
		ds_align_comment(ds);
		theme_printf(comment, " ; *middle* %d", ret);
	}
	return ret;
}

static bool ds_print_labels(RzDisasmState *ds, RzAnalysisFunction *f) {
	const char *label;
	if (!f) {
		// f = rz_analysis_get_fcn_in (core->analysis, ds->at, 0);
		f = fcnIn(ds, ds->at, 0);
	}
	if (!f) {
		return false;
	}
	label = rz_analysis_function_get_label_at(f, ds->at);
	if (!label) {
		return false;
	}
	ds_pre_line(ds);
	theme_printf(label, " .%s:\n", label);
	return true;
}

static void ds_print_sysregs(RzDisasmState *ds) {
	RzCore *core = ds->core;
	if (!ds->show_comments) {
		return;
	}
	switch (ds->analysis_op.type) {
	case RZ_ANALYSIS_OP_TYPE_IO: {
		const int imm = (int)ds->analysis_op.val;
		const char *ioname = rz_sysreg_get(core->analysis->syscall, "mmio", imm);
		if (ioname) {
			CMT_ALIGN;
			ds_comment(ds, true, "; IO %s", ioname);
			ds->has_description = true;
		}
	} break;
	// Then sysregs
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_STORE: {
		const int imm = (int)ds->analysis_op.ptr;
		const char *sr = rz_sysreg_get(core->analysis->syscall, "reg", imm);
		if (sr) {
			CMT_ALIGN;
			ds_comment(ds, true, "; REG %s - %s", sr, "");
			// TODO: add register description description
			ds->has_description = true;
		}
	} break;
	}
}

static void ds_print_fcn_name(RzDisasmState *ds) {
	if (!ds->show_comments) {
		return;
	}
	if (ds->analysis_op.type != RZ_ANALYSIS_OP_TYPE_JMP && ds->analysis_op.type != RZ_ANALYSIS_OP_TYPE_CJMP && ds->analysis_op.type != RZ_ANALYSIS_OP_TYPE_CALL) {
		return;
	}
	RzAnalysisFunction *f = fcnIn(ds, ds->analysis_op.jump, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!f && ds->core->flags && (!ds->core->vmode || (!ds->subjmp && !ds->subnames))) {
		const char *arch;
		RzFlagItem *flag = rz_flag_get_by_spaces(ds->core->flags, ds->analysis_op.jump,
			RZ_FLAGS_FS_CLASSES, RZ_FLAGS_FS_SYMBOLS, NULL);
		if (flag && rz_flag_item_get_name(flag) && ds->opstr && !strstr(ds->opstr, rz_flag_item_get_name(flag)) && (rz_str_startswith(rz_flag_item_get_name(flag), "sym.") || rz_str_startswith(rz_flag_item_get_name(flag), "method.")) && (arch = rz_config_get(ds->core->config, "asm.arch")) && strcmp(arch, "dalvik")) {
			RzFlagItem *flag_sym = flag;
			if (ds->core->vmode && (rz_str_startswith(rz_flag_item_get_name(flag), "sym.") || (flag_sym = rz_flag_get_by_spaces(ds->core->flags, ds->analysis_op.jump, RZ_FLAGS_FS_SYMBOLS, NULL))) && flag_sym->demangled) {
				return;
			}
			if (ds->core->flags->realnames && rz_flag_item_get_realname(flag)) {
				ds_begin_comment(ds);
				ds_comment(ds, true, "; %s", rz_flag_item_get_name(flag));
			}
			return;
		}
	}
	if (!f || !f->name) {
		return;
	}
	st64 delta = ds->analysis_op.jump - f->addr;
	const char *label = rz_analysis_function_get_label_at(f, ds->analysis_op.jump);
	if (label) {
		ds_begin_comment(ds);
		ds_comment(ds, true, "; %s.%s", f->name, label);
	} else {
		RzAnalysisFunction *f2 = fcnIn(ds, ds->at, 0);
		if (f == f2) {
			return;
		}
		if (delta > 0) {
			ds_begin_comment(ds);
			ds_comment(ds, true, "; %s+0x%x", f->name, delta);
		} else if (delta < 0) {
			ds_begin_comment(ds);
			ds_comment(ds, true, "; %s-0x%x", f->name, -delta);
		} else if ((!ds->core->vmode || (!ds->subjmp && !ds->subnames)) && (!ds->opstr || !strstr(ds->opstr, f->name))) {
			RzFlagItem *flag_sym;
			if (ds->core->vmode && (flag_sym = rz_flag_get_by_spaces(ds->core->flags, ds->analysis_op.jump, RZ_FLAGS_FS_SYMBOLS, NULL)) && flag_sym->demangled) {
				return;
			}
			ds_begin_comment(ds);
			ds_comment(ds, true, "; %s", f->name);
		}
	}
}

static int ds_print_shortcut(RzDisasmState *ds, ut64 addr, int pos) {
	char *shortcut = rz_core_add_asmqjmp(ds->core, addr);
	int slen = shortcut ? strlen(shortcut) : 0;
	if (ds->asm_hint_pos > 0) {
		if (pos) {
			ds_align_comment(ds);
		}
	}
	const char *ch = (pos) ? ";" : "";
	if (ds->asm_hint_pos == -1) {
		ch = " ";
	}
	theme_print_color(comment);
	if (*ch) {
		slen++;
	}
	if (shortcut) {
		if (ds->core->is_asmqjmps_letter) {
			rz_cons_printf("%s[o%s]", ch, shortcut);
			slen++;
		} else {
			rz_cons_printf("%s[%s]", ch, shortcut);
		}
		free(shortcut);
	} else {
		rz_cons_printf("%s[?]", ch);
	}
	if (ds->show_color) {
		if (ds->core->print->resetbg) {
			rz_cons_strcat(Color_RESET);
		} else {
			rz_cons_strcat(Color_RESET_NOBG);
		}
	}
	slen++;
	return slen;
}

static bool ds_print_core_vmode_jump_hit(RzDisasmState *ds, int pos) {
	RzCore *core = ds->core;
	RzAnalysis *a = core->analysis;
	RzAnalysisHint *hint = rz_analysis_hint_get(a, ds->at);
	bool res = false;
	if (hint) {
		if (hint->jump != UT64_MAX) {
			ds_print_shortcut(ds, hint->jump, pos);
			res = true;
		}
		rz_analysis_hint_free(hint);
	}
	return res;
}

static ut64 get_ptr(RzDisasmState *ds, ut64 addr) {
	ut8 buf[sizeof(ut64)] = { 0 };
	rz_io_read_at(ds->core->io, addr, buf, sizeof(buf));
	ut64 n64_32;
	if (ds->core->rasm->bits == 64) {
		n64_32 = rz_read_ble64(buf, 0);
	} else {
		n64_32 = rz_read_ble32(buf, 0);
	}
	return n64_32;
}

static ut64 get_ptr_ble(RzDisasmState *ds, ut64 addr) {
	ut8 buf[sizeof(ut64)] = { 0 };
	int endian = ds->core->rasm->big_endian;
	ut64 n64_32;
	rz_io_read_at(ds->core->io, addr, buf, sizeof(buf));
	if (ds->core->rasm->bits == 64) {
		n64_32 = rz_read_ble64(buf, endian);
	} else {
		n64_32 = rz_read_ble32(buf, endian);
	}
	return n64_32;
}

static bool ds_print_core_vmode(RzDisasmState *ds, int pos) {
	RzCore *core = ds->core;
	bool gotShortcut = false;
	int i, slen = 0;

	if (!core->vmode) {
		return false;
	}
	if (!ds->asm_hints) {
		return false;
	}
	if (ds->asm_hint_emu) {
		if (ds->emuptr) {
			if (rz_io_is_valid_offset(core->io, ds->emuptr, 0)) {
				ds_print_shortcut(ds, ds->emuptr, pos);
				// getPtr (ds, ds->emuptr, pos);
				ds->emuptr = 0;
				ds->hinted_line = true;
				gotShortcut = true;
				goto beach;
			}
		}
	}
	if (ds->asm_hint_lea) {
		ut64 size;
		RzAnalysisMetaItem *mi = rz_meta_get_at(ds->core->analysis, ds->at, RZ_META_TYPE_ANY, &size);
		if (mi) {
			int obits = ds->core->rasm->bits;
			ds->core->rasm->bits = size * 8;
			slen = ds_print_shortcut(ds, get_ptr(ds, ds->at), pos);
			ds->core->rasm->bits = obits;
			gotShortcut = true;
		}
	}
	switch (ds->analysis_op.type) {
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP | RZ_ANALYSIS_OP_TYPE_IND:
	case RZ_ANALYSIS_OP_TYPE_UJMP | RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_COND:
	case RZ_ANALYSIS_OP_TYPE_UJMP | RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_REG:
		if (ds->asm_hint_lea) {
			if (ds->analysis_op.ptr != UT64_MAX && ds->analysis_op.ptr != UT32_MAX) {
				slen = ds_print_shortcut(ds, get_ptr(ds, ds->analysis_op.ptr), pos);
				gotShortcut = true;
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (ds->asm_hint_lea) {
			if (ds->analysis_op.ptr != UT64_MAX && ds->analysis_op.ptr != UT32_MAX && ds->analysis_op.ptr > 256) {
				slen = ds_print_shortcut(ds, ds->analysis_op.ptr, pos);
				gotShortcut = true;
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL | RZ_ANALYSIS_OP_TYPE_REG | RZ_ANALYSIS_OP_TYPE_IND:
	case RZ_ANALYSIS_OP_TYPE_UCALL | RZ_ANALYSIS_OP_TYPE_IND:
		if (ds->asm_hint_call) {
			if (ds->analysis_op.jump != UT64_MAX) {
				slen = ds_print_shortcut(ds, ds->analysis_op.jump, pos);
			} else {
				ut64 addr;
				if (ds->asm_hint_call_indirect) {
					addr = get_ptr_ble(ds, ds->analysis_op.ptr);
				} else {
					addr = ds->analysis_op.ptr;
				}
				slen = ds_print_shortcut(ds, addr, pos);
			}
			gotShortcut = true;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
		if (ds->analysis_op.jump != UT64_MAX && ds->analysis_op.jump != UT32_MAX) {
			ds->analysis_op.jump = get_ptr_ble(ds, ds->analysis_op.jump);
			slen = ds_print_shortcut(ds, ds->analysis_op.jump, pos);
			gotShortcut = true;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
		if (ds->asm_hint_jmp) {
			slen = ds_print_shortcut(ds, ds->analysis_op.jump, pos);
			gotShortcut = true;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_COND | RZ_ANALYSIS_OP_TYPE_CALL:
		if (ds->asm_hint_call) {
			slen = ds_print_shortcut(ds, ds->analysis_op.jump, pos);
			gotShortcut = true;
		}
		break;
	default:
		if (ds_print_core_vmode_jump_hit(ds, pos)) {
			gotShortcut = true;
		}
		break;
	}
beach:
	if (ds->asm_hint_pos > 0) {
		const int begin = gotShortcut ? 2 : 3;
		for (i = begin - slen; i > 0; i--) {
			rz_cons_strcat(" ");
		}
	} else if (ds->asm_hint_pos == 0 && !gotShortcut) {
		rz_cons_strcat("   ");
	}
	ds->hinted_line = gotShortcut;
	return gotShortcut;
}

static void ds_begin_nl_comment(RzDisasmState *ds) {
	if (ds->cmtcount > 0 && ds->show_comment_right) {
		ds_newline(ds);
		ds_begin_cont(ds);
	} else if (ds->cmtcount > 0 || !ds->show_comment_right) {
		ds_begin_line(ds);
		ds_pre_xrefs(ds, false);
	}
	if (ds->show_color && (ds->cmtcount > 0 || ds->show_comment_right)) {
		theme_print_color(comment);
	}
}

// align for comment
static void ds_align_comment(RzDisasmState *ds) {
	if (!ds->show_comment_right_default) {
		return;
	}
	const int cmtcol = ds->cmtcol - 1;
	const char *ll = rz_cons_get_buffer();
	if (!ll) {
		return;
	}
	ll += ds->buf_line_begin;
	int cells = rz_str_len_utf8_ansi(ll);
	int cols = ds->interactive ? ds->core->cons->columns : 1024;
	if (cells < cmtcol) {
		int len = cmtcol - cells;
		if (len < cols && len > 0) {
			rz_cons_memset(' ', len);
		}
	}
	rz_cons_print(" ");
}

static void ds_print_debuginfo(RzDisasmState *ds) {
	if (!ds->debuginfo.enable)
		return;

	RzBinObject *o = rz_bin_cur_object(ds->core->bin);
	RzBinSourceLineInfo *sl = o ? o->lines : NULL;
	if (ds->debuginfo.lines && sl) {
		free(ds->sl);
		ds->sl = rz_bin_source_line_addr2text(sl, ds->at, ds->debuginfo);
		if (RZ_STR_ISEMPTY(ds->sl))
			return;
		if (ds->osl && !(ds->osl && strcmp(ds->sl, ds->osl)))
			return;
		ds_align_comment(ds);
		theme_printf(comment, "; %s", ds->sl);
		free(ds->osl);
		ds->osl = ds->sl;
		ds->sl = NULL;
	}
}

static void ds_print_asmop_payload(RzDisasmState *ds, const ut8 *buf) {
	if (ds->show_varaccess) {
		// XXX assume analysis_op is filled
		// rz_analysis_op (core->analysis, &ds->analysis_op, ds->at, core->block+i, core->blocksize-i);
		int v = ds->analysis_op.ptr;
		switch (ds->analysis_op.stackop) {
		case RZ_ANALYSIS_STACK_GET:
			if (v < 0) {
				rz_cons_printf(" ; local.get %d", -v);
			} else {
				rz_cons_printf(" ; arg.get %d", v);
			}
			break;
		case RZ_ANALYSIS_STACK_SET:
			if (v < 0) {
				rz_cons_printf(" ; local.set %d", -v);
			} else {
				rz_cons_printf(" ; arg.set %d", v);
			}
			break;
		default:
			break;
		}
	}
	if (ds->asmop.payload != 0) {
		rz_cons_printf("\n; .. payload of %d byte(s)", ds->asmop.payload);
		if (ds->showpayloads) {
			int mod = ds->asmop.payload % ds->core->rasm->dataalign;
			int x;
			for (x = 0; x < ds->asmop.payload; x++) {
				rz_cons_printf("\n        0x%02x", buf[ds->oplen + x]);
			}
			for (x = 0; x < mod; x++) {
				rz_cons_printf("\n        0x%02x ; alignment", buf[ds->oplen + ds->asmop.payload + x]);
			}
		}
	}
}

/* Do not use this function for escaping JSON! */
static char *ds_esc_str(RzDisasmState *ds, const char *str, int len, const char **prefix_out, bool is_comment) {
	int str_len;
	char *escstr = NULL;
	const char *prefix = "";
	RzStrEnc strenc = ds->strenc;
	if (strenc == RZ_STRING_ENC_GUESS) {
		strenc = rz_utf_bom_encoding((ut8 *)str, len);
	}
	RzStrEscOptions opt = { 0 };
	opt.show_asciidot = ds->show_asciidot;
	opt.esc_double_quotes = true;
	opt.esc_bslash = ds->core->print->esc_bslash;
	switch (strenc) {
	case RZ_STRING_ENC_8BIT:
		escstr = rz_str_escape_8bit(str, is_comment, &opt);
		break;
	case RZ_STRING_ENC_UTF8:
		escstr = rz_str_escape_utf8(str, &opt);
		break;
	case RZ_STRING_ENC_UTF16LE:
		escstr = rz_str_escape_utf16le(str, len, &opt);
		prefix = "u";
		break;
	case RZ_STRING_ENC_UTF32LE:
		escstr = rz_str_escape_utf32le(str, len, &opt);
		prefix = "U";
		break;
	case RZ_STRING_ENC_UTF16BE:
		escstr = rz_str_escape_utf16be(str, len, &opt);
		prefix = "ub";
		break;
	case RZ_STRING_ENC_UTF32BE:
		escstr = rz_str_escape_utf32be(str, len, &opt);
		prefix = "Ub";
		break;
	default:
		str_len = strlen(str);
		if ((str_len == 1 && len > 3 && str[2] && !str[3]) || (str_len == 3 && len > 5 && !memcmp(str, "\xff\xfe", 2) && str[4] && !str[5])) {
			escstr = rz_str_escape_utf16le(str, len, &opt);
			prefix = "u";
		} else if (str_len == 1 && len > 7 && !str[2] && !str[3] && str[4] && !str[5]) {
			RzStrEnc enc = RZ_STRING_ENC_UTF32LE;
			RzRune ch;
			const char *ptr, *end;
			end = (const char *)rz_mem_mem_aligned((ut8 *)str, len, (ut8 *)"\0\0\0\0", 4, 4);
			if (!end) {
				end = str + len - 1;
			}
			for (ptr = str; ptr < end; ptr += 4) {
				if (rz_utf32le_decode((ut8 *)ptr, end - ptr, &ch) > 0 && ch > 0x10ffff) {
					enc = RZ_STRING_ENC_8BIT;
					break;
				}
			}
			if (enc == RZ_STRING_ENC_UTF32LE) {
				escstr = rz_str_escape_utf32le(str, len, &opt);
				prefix = "U";
			} else {
				escstr = rz_str_escape_8bit(str, is_comment, &opt);
			}
		} else {
			RzStrEnc enc = RZ_STRING_ENC_8BIT;
			const char *ptr = str, *end = str + str_len;
			for (; ptr < end; ptr++) {
				if (rz_utf8_decode((ut8 *)ptr, end - ptr, NULL) > 1) {
					enc = RZ_STRING_ENC_UTF8;
					break;
				}
			}
			escstr = (enc == RZ_STRING_ENC_UTF8 ? rz_str_escape_utf8(str, &opt) : rz_str_escape_8bit(str, is_comment, &opt));
		}
	}
	if (prefix_out) {
		*prefix_out = prefix;
	}
	return escstr;
}

static void ds_print_str(RzDisasmState *ds, const char *str, int len, ut64 refaddr) {
	if (ds->core->flags->realnames || !rz_bin_string_filter(ds->core->bin, str, refaddr)) {
		return;
	}
	// do not resolve strings on arm64 pointed with ADRP
	if (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_LEA) {
		if (ds->core->rasm->bits == 64 && rz_str_startswith(rz_config_get(ds->core->config, "asm.arch"), "arm")) {
			return;
		}
	}
	const char *prefix;
	char *escstr = ds_esc_str(ds, str, len, &prefix, false);
	if (escstr) {
		bool inv = ds->show_color && !ds->show_emu_strinv;
		ds_begin_comment(ds);
		ds_comment(ds, true, "; %s%s\"%.128s\"%s", inv ? Color_INVERT : "", prefix, escstr,
			inv ? Color_INVERT_RESET : "");
		ds->printed_str_addr = refaddr;
		free(escstr);
	}
}

static inline bool is_filtered_flag(RzDisasmState *ds, const char *name) {
	if (ds->show_noisy_comments || strncmp(name, "str.", 4)) {
		return false;
	}
	ut64 refaddr = ds->analysis_op.ptr;
	const char *analysis_flag = rz_meta_get_string(ds->core->analysis, RZ_META_TYPE_STRING, refaddr);
	if (analysis_flag) {
		char *dupped = strdup(analysis_flag);
		if (dupped) {
			rz_name_filter(dupped, -1, true);
			if (!strcmp(&name[4], dupped)) {
				return true;
			}
		}
	}
	return false;
}

/* convert numeric value in opcode to ascii char or number */
static void ds_print_ptr(RzDisasmState *ds, int len, int idx) {
	RzCore *core = ds->core;
	ut64 p = ds->analysis_op.ptr;
	ut64 v = ds->analysis_op.val;
	ut64 refaddr = p;
	bool aligned = false;
	int refptr = ds->analysis_op.refptr;
	RzFlagItem *f = NULL, *f2 = NULL;
	bool f2_in_opstr = false; /* Also if true, f exists */
	if (!ds->show_comments || !ds->show_slow) {
		return;
	}
	const int opType = ds->analysis_op.type & RZ_ANALYSIS_OP_TYPE_MASK;
	bool canHaveChar = opType == RZ_ANALYSIS_OP_TYPE_MOV;
	if (!canHaveChar) {
		canHaveChar = opType == RZ_ANALYSIS_OP_TYPE_PUSH;
	}

	ds->chref = 0;
	if ((char)v > 0 && v >= '!') {
		ds->chref = (char)v;
		if (ds->immstr) {
			char *str = rz_str_from_ut64(rz_read_ble64(&v, core->print->big_endian));
			if (str && *str) {
				const char *ptr = str;
				bool printable = true;
				for (; *ptr; ptr++) {
					if (!IS_PRINTABLE(*ptr)) {
						printable = false;
						break;
					}
				}
				if (rz_flag_get_i(core->flags, v)) {
					printable = false;
				}
				if (canHaveChar && printable) {
					ds_begin_comment(ds);
					ds_comment(ds, true, "; '%s'", str);
				}
			}
			free(str);
		} else {
			if (canHaveChar && (char)v > 0 && v >= '!' && v <= '~') {
				ds_begin_comment(ds);
				aligned = true;
				ds_comment(ds, true, "; '%c'", (char)v);
			}
		}
	}
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *list = rz_analysis_xrefs_get_from(core->analysis, ds->at);
	rz_list_foreach (list, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_STRING || xref->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			if ((f = rz_flag_get_i(core->flags, xref->to))) {
				refaddr = xref->to;
				break;
			}
		}
	}
	rz_list_free(list);
	if (ds->analysis_op.type == (RZ_ANALYSIS_OP_TYPE_MOV | RZ_ANALYSIS_OP_TYPE_REG) && ds->analysis_op.stackop == RZ_ANALYSIS_STACK_SET && ds->analysis_op.val != UT64_MAX && ds->analysis_op.val > 10) {
		const char *arch = rz_config_get(core->config, "asm.arch");
		if (arch && !strcmp(arch, "x86")) {
			p = refaddr = ds->analysis_op.val;
			refptr = 0;
		}
	}
	bool flag_printed = false;
	bool refaddr_printed = false;
	bool string_printed = false;
	if (refaddr == UT64_MAX) {
		/* do nothing */
	} else if (((st64)p) > 0 || ((st64)refaddr) > 0) {
		RzAnalysisDataKind data_kind = RZ_ANALYSIS_DATA_KIND_UNKNOWN;
		char *msg = calloc(sizeof(char), len);
		if (((st64)p) > 0) {
			f = rz_flag_get_i(core->flags, p);
			if (f) {
				ut64 subrel_addr = core->parser->subrel_addr;
				if (subrel_addr && subrel_addr != p) {
					f2 = rz_core_flag_get_by_spaces(core->flags, subrel_addr);
					f2_in_opstr = f2 && ds->opstr &&
						((f2->name && strstr(ds->opstr, f2->name)) ||
							(f2->realname && strstr(ds->opstr, f2->realname)));
				}
				refaddr = p;
				if (!flag_printed && !is_filtered_flag(ds, f->name) && (!ds->opstr || (!strstr(ds->opstr, f->name) && !strstr(ds->opstr, f->realname))) && !f2_in_opstr) {
					ds_begin_comment(ds);
					ds_comment(ds, true, "; %s", f->name);
					ds->printed_flag_addr = p;
					flag_printed = true;
				}
			}
		}
		rz_io_read_at(core->io, refaddr, (ut8 *)msg, len - 1);
		if (refptr && ds->show_refptr) {
			ut64 num = rz_read_ble(msg, core->print->big_endian, refptr * 8);
			st64 n = (st64)num;
			st32 n32 = (st32)(n & UT32_MAX);
			if (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_LEA) {
				char str[128] = { 0 };
				f = rz_flag_get_i(core->flags, refaddr);
				if (!f && ds->show_slow) {
					rz_io_read_at(ds->core->io, ds->analysis_op.ptr,
						(ut8 *)str, sizeof(str) - 1);
					str[sizeof(str) - 1] = 0;
					if (!string_printed && str[0] && rz_str_is_printable_incl_newlines(str)) {
						ds_print_str(ds, str, sizeof(str), ds->analysis_op.ptr);
						string_printed = true;
					}
				}
			} else {
				if (n == UT32_MAX || n == UT64_MAX) {
					ds_begin_nl_comment(ds);
					ds_comment(ds, true, "; [0x%" PFMT64x ":%d]=-1",
						refaddr, refptr);
				} else if (n == n32 && (n32 > -512 && n32 < 512)) {
					ds_begin_nl_comment(ds);
					ds_comment(ds, true, "; [0x%" PFMT64x ":%d]=%" PFMT64d, refaddr, refptr, n);
				} else {
					const char *flag = "";
					char *msg2 = NULL;
					RzFlagItem *f2_ = rz_flag_get_i(core->flags, n);
					if (f2_) {
						flag = f2_->name;
					} else {
						msg2 = calloc(sizeof(char), len);
						rz_io_read_at(core->io, n, (ut8 *)msg2, len - 1);
						msg2[len - 1] = 0;
						data_kind = rz_analysis_data_kind(core->analysis, refaddr, (const ut8 *)msg2, len - 1);
						if (data_kind == RZ_ANALYSIS_DATA_KIND_STRING) {
							rz_str_filter(msg2);
							if (*msg2) {
								char *lala = rz_str_newf("\"%s\"", msg2);
								free(msg2);
								flag = msg2 = lala;
							}
						}
					}
					// ds_align_comment (ds);
					{
						const char *refptrstr = "";
						if (core->print->flags & RZ_PRINT_FLAGS_SECSUB) {
							RzBinObject *bo = rz_bin_cur_object(core->bin);
							RzBinSection *s = bo ? rz_bin_get_section_at(bo, n, core->io->va) : NULL;
							if (s) {
								refptrstr = s->name;
							}
						}
						ds_begin_nl_comment(ds);
						ds_comment_start(ds, "; [");
						if (f && f2_in_opstr) {
							ds_comment_middle(ds, "%s", f->name);
							flag_printed = true;
						} else {
							ds_comment_middle(ds, "0x%" PFMT64x, refaddr);
						}
						ds_comment_end(ds, ":%d]=%s%s0x%" PFMT64x "%s%s",
							refptr, refptrstr, *refptrstr ? "." : "",
							n, (flag && *flag) ? " " : "", flag);
					}
					free(msg2);
				}
				refaddr_printed = true;
			}
		}
		if (!strcmp(ds->show_cmtoff, "true")) {
			ds_begin_comment(ds);
			ds_comment(ds, true, "; 0x%" PFMT64x, refaddr);
		} else if (!refaddr_printed && strcmp(ds->show_cmtoff, "false")) {
			char addrstr[32] = { 0 };
			snprintf(addrstr, sizeof(addrstr), "0x%" PFMT64x, refaddr);
			if (!ds->opstr || !strstr(ds->opstr, addrstr)) {
				snprintf(addrstr, sizeof(addrstr), "0x%08" PFMT64x, refaddr);
				if (!ds->opstr || !strstr(ds->opstr, addrstr)) {
					bool print_refaddr = true;
					if (refaddr < 10) {
						snprintf(addrstr, sizeof(addrstr), "%" PFMT64u, refaddr);
						if (ds->opstr && strstr(ds->opstr, addrstr)) {
							print_refaddr = false;
						}
					}
					if (print_refaddr) {
						if (!aligned) {
							ds_begin_nl_comment(ds);
						}
						ds_comment(ds, true, "; 0x%" PFMT64x, refaddr);
					}
				}
			}
		}
		bool print_msg = true;
#if 1
		if (ds->strenc == RZ_STRING_ENC_GUESS && rz_utf_bom_encoding((ut8 *)msg, len) == RZ_STRING_ENC_GUESS && !(IS_PRINTABLE(*msg) || IS_WHITECHAR(*msg))) {
			print_msg = false;
		} else {
			msg[len - 1] = 0;
		}
#endif
		f = rz_flag_get_i(core->flags, refaddr);
		if (f) {
			if (strlen(msg) != 1) {
				char *msg2 = rz_str_dup(msg);
				if (msg2) {
					rz_str_filter(msg2);
					if (!strncmp(msg2, "UH..", 4)) {
						print_msg = false;
					}
					free(msg2);
				}
			}
			if (print_msg) {
				if (!string_printed) {
					ds_print_str(ds, msg, len, refaddr);
				}
			} else if (!flag_printed && (!ds->opstr || (!strstr(ds->opstr, f->name) && !strstr(ds->opstr, f->realname)))) {
				ds_begin_nl_comment(ds);
				ds_comment(ds, true, "; %s", f->name);
				ds->printed_flag_addr = refaddr;
			}
		} else {
			if (refaddr == UT64_MAX || refaddr == UT32_MAX) {
				ds_begin_comment(ds);
				ds_comment(ds, true, "; -1");
			} else if (((char)refaddr > 0) && refaddr >= '!' && refaddr <= '~') {
				char ch = refaddr;
				if (canHaveChar && ch != ds->chref) {
					ds_begin_comment(ds);
					ds_comment(ds, true, "; '%c'", ch);
				}
			} else if ((st64)refaddr > 10 &&
				(rz_core_analysis_address(core, refaddr) & RZ_ANALYSIS_ADDR_TYPE_ASCII) &&
				!string_printed && print_msg) {
				ds_print_str(ds, msg, len, refaddr);
				string_printed = true;
			}
			data_kind = rz_analysis_data_kind(core->analysis, refaddr, (const ut8 *)msg, len - 1);
			if (data_kind == RZ_ANALYSIS_DATA_KIND_STRING && !string_printed && print_msg) {
				ds_print_str(ds, msg, len, refaddr);
			} else if (data_kind == RZ_ANALYSIS_DATA_KIND_INVALID) {
				st32 n = (st32)refaddr;
				ut64 p = ds->analysis_op.val;
				if (p == UT64_MAX || p == UT32_MAX) {
					p = ds->analysis_op.ptr;
				}
				/* avoid double ; -1 */
				if (p != UT64_MAX && p != UT32_MAX) {
					if (n > -0xfff && n < 0xfff) {
						if (!aligned) {
							ds_begin_comment(ds);
						}
						ds_comment(ds, true, "; %" PFMT64d, p);
					}
				}
			}
		}
		free(msg);
	} else {
		ds_print_as_string(ds);
	}
	if (!ds->show_comment_right && ds->cmtcount > 0) {
		const char *p = rz_cons_get_buffer();
		if (p) {
			int l = strlen(p);
			if (p[l - 1] != '\n') {
				ds_newline(ds);
			}
		}
	}
#if DEADCODE
	if (aligned && ds->show_color) {
		rz_cons_strcat(Color_RESET);
	}
#endif
}

static void ds_print_cmt_esil(RzDisasmState *ds) {
	if (!ds->show_cmt_esil) {
		return;
	}
	const char *esil = RZ_STRBUF_SAFEGET(&ds->analysis_op.esil);
	ds_begin_comment(ds);
	ds_comment(ds, true, "; %s", esil);
}

static void ds_print_cmt_il(RzDisasmState *ds) {
	if (!ds->show_cmt_il || !ds->analysis_op.il_op) {
		return;
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_il_op_effect_stringify(ds->analysis_op.il_op, &sb, false);
	ds_begin_comment(ds);
	ds_comment(ds, true, "; %s", rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);
}

static void ds_print_relocs(RzDisasmState *ds) {
	if (!ds->showrelocs || !ds->show_slow) {
		return;
	}
	RzCore *core = ds->core;
	RzBinReloc *rel = rz_core_getreloc(core, ds->at, ds->analysis_op.size);
	const char *rel_label = "RELOC";
	if (!rel) {
		rel = rz_core_get_reloc_to(core, ds->at);
		rel_label = "RELOC TARGET";
	}
	if (rel) {
		int cstrlen = 0;
		char *ll = rz_cons_lastline(&cstrlen);
		if (!ll) {
			return;
		}
		int ansilen = rz_str_ansi_len(ll);
		int utf8len = rz_utf8_strlen((const ut8 *)ll);
		int cells = utf8len - (cstrlen - ansilen);
		int len = ds->cmtcol - cells;
		rz_cons_memset(' ', len);
		if (rel->import) {
			RzBinImport *imp = rel->import;
			rz_cons_printf("; %s %d %s", rel_label, rel->type, imp->dname ? imp->dname : imp->name);
		} else if (rel->symbol) {
			RzBinSymbol *sym = rel->symbol;
			rz_cons_printf("; %s %d %s @ 0x%08" PFMT64x,
				rel_label,
				rel->type, sym->dname ? sym->dname : sym->name,
				rel->symbol->vaddr);
			if (rel->addend) {
				if (rel->addend > 0) {
					rz_cons_printf(" + 0x%" PFMT64x, rel->addend);
				} else {
					rz_cons_printf(" - 0x%" PFMT64x, -rel->addend);
				}
			}
		} else {
			rz_cons_printf("; %s %d ", rel_label, rel->type);
		}
	}
}

static int mymemwrite0(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return 0;
}

static int mymemwrite1(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return 1;
}

static int mymemwrite2(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return (addr >= esil->analysis->esilinterstate->emustack_min && addr < esil->analysis->esilinterstate->emustack_max);
}

static char *ssa_get(RzAnalysisEsil *esil, const char *reg) {
	RzDisasmState *ds = esil->user;
	if (isdigit(*reg)) {
		return strdup(reg);
	}
	if (!ds->ssa) {
		ds->ssa = sdb_new0();
	}
	int n = sdb_num_get(ds->ssa, reg, NULL);
	return rz_str_newf("%s_%d", reg, n);
}

static void ssa_set(RzAnalysisEsil *esil, const char *reg) {
	RzDisasmState *ds = esil->user;
	(void)sdb_num_inc(ds->ssa, reg, 1, 0);
}

#define RZ_DISASM_MAX_STR 512
static int myregread(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size) {
	RzDisasmState *ds = esil->user;
	if (ds && ds->show_emu_ssa) {
		if (!isdigit(*name)) {
			char *r = ssa_get(esil, name);
			ds_comment_esil(ds, true, false, "<%s", r);
			free(r);
		}
	}
	return 0;
}

static int myregwrite(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	char str[64], *msg = NULL;
	bool big_endian = esil->analysis ? esil->analysis->big_endian : false;
	RzDisasmState *ds = esil->user;
	if (!ds) {
		return 0;
	}
	if (!ds->show_emu_strlea && ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_LEA) {
		// useful for ARM64
		// reduce false positives in emu.str=true when loading strings via adrp+add
		return 0;
	}
	ds->esil_likely = true;
	if (ds->show_emu_ssa) {
		ssa_set(esil, name);
		char *r = ssa_get(esil, name);
		ds_comment_esil(ds, true, false, ">%s", r);
		free(r);
		return 0;
	}
	if (!ds->show_slow) {
		return 0;
	}
	memset(str, 0, sizeof(str));
	if (*val) {
		bool emu_str_printed = false;
		char *type = NULL;
		(void)rz_io_read_at(esil->analysis->iob.io, *val, (ut8 *)str, sizeof(str) - 1);
		str[sizeof(str) - 1] = 0;
		ds->emuptr = *val;
		// support cstring here
		{
			ut64 mem_0 = rz_read_at_ble64(str, 0, big_endian);
			ut64 mem_1 = rz_read_at_ble64(str, 8, big_endian);
			ut64 mem_2 = rz_read_at_ble64(str, 16, big_endian);
			ut64 addr = rz_read_at_ble64(str, 0, big_endian);
			if (!(*val >> 32)) {
				addr = addr & UT32_MAX;
			}
			if (mem_0 == 0 && mem_1 < 0x1000) {
				ut64 addr = mem_2;
				if (!(*val >> 32)) {
					addr = addr & UT32_MAX;
				}
				(void)rz_io_read_at(esil->analysis->iob.io, addr,
					(ut8 *)str, sizeof(str) - 1);
				//	eprintf ("IS CSTRING 0x%llx %s\n", addr, str);
				type = rz_str_newf("(cstr 0x%08" PFMT64x ") ", addr);
				ds->printed_str_addr = mem_2;
			} else if (rz_io_is_valid_offset(esil->analysis->iob.io, addr, 0)) {
				ds->printed_str_addr = mem_0;
				type = rz_str_newf("(pstr 0x%08" PFMT64x ") ", addr);
				(void)rz_io_read_at(esil->analysis->iob.io, addr,
					(ut8 *)str, sizeof(str) - 1);
				//	eprintf ("IS PSTRING 0x%llx %s\n", addr, str);
			}
		}

		if (*str && !rz_bin_strpurge(ds->core->bin, str, *val) && rz_str_is_printable_incl_newlines(str) && (ds->printed_str_addr == UT64_MAX || *val != ds->printed_str_addr)) {
			bool jump_op = false;
			bool ignored = false;
			switch (ds->analysis_op.type) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
			case RZ_ANALYSIS_OP_TYPE_UJMP:
			case RZ_ANALYSIS_OP_TYPE_RJMP:
			case RZ_ANALYSIS_OP_TYPE_IJMP:
			case RZ_ANALYSIS_OP_TYPE_IRJMP:
			case RZ_ANALYSIS_OP_TYPE_CJMP:
			case RZ_ANALYSIS_OP_TYPE_MJMP:
			case RZ_ANALYSIS_OP_TYPE_UCJMP:
				jump_op = true;
				break;
			case RZ_ANALYSIS_OP_TYPE_TRAP:
			case RZ_ANALYSIS_OP_TYPE_RET:
				ignored = true;
				break;
			case RZ_ANALYSIS_OP_TYPE_LEA:
				if (ds->core->rasm->bits == 64 && rz_str_startswith(rz_config_get(ds->core->config, "asm.arch"), "arm")) {
					ignored = true;
				}
				break;
			}
			if (!jump_op && !ignored) {
				const char *prefix = NULL;
				ds->emuptr = *val;
				char *escstr = ds_esc_str(ds, str, sizeof(str) - 1, &prefix, false);
				if (escstr) {
					char *m;
					if (ds->show_color) {
						bool inv = ds->show_emu_strinv;
						m = rz_str_newf("%s%s%s\"%s\"%s",
							prefix, type ? type : "", inv ? Color_INVERT : "",
							escstr, inv ? Color_INVERT_RESET : "");
					} else {
						m = rz_str_newf("%s%s\"%s\"", prefix, type ? type : "", escstr);
					}
					msg = rz_str_append_owned(msg, m);
					emu_str_printed = true;
					free(escstr);
				}
			}
		} else {
			ut32 mem_value = rz_read_ble32((const ut8 *)str, big_endian);
			if (mem_value && mem_value != UT32_MAX && !ds->show_emu_str) {
				msg = rz_str_appendf(msg, "-> 0x%x", mem_value);
			}
		}
		RZ_FREE(type);
		if ((ds->printed_flag_addr == UT64_MAX || *val != ds->printed_flag_addr) && (ds->show_emu_strflag || !emu_str_printed)) {
			RzFlagItem *fi = rz_flag_get_i(esil->analysis->flb.f, *val);
			if (fi && (!ds->opstr || !strstr(ds->opstr, rz_flag_item_get_name(fi)))) {
				msg = rz_str_appendf(msg, "%s%s", msg && *msg ? " " : "", rz_flag_item_get_name(fi));
			}
		}
	}
	if (ds->show_emu_str) {
		if (msg && *msg) {
			ds->emuptr = *val;
			if (ds->show_emu_stroff && *msg == '"') {
				ds_comment_esil(ds, true, false, "; 0x%" PFMT64x " %s", *val, msg);
			} else {
				ds_comment_esil(ds, true, false, "; %s", msg);
			}
			if (ds->show_comments && !ds->show_comment_right) {
				ds_newline(ds);
			}
		}
	} else {
		if (msg && *msg) {
			ds_comment_esil(ds, true, false, "; %s=0x%" PFMT64x " %s", name, *val, msg);
		} else {
			ds_comment_esil(ds, true, false, "; %s=0x%" PFMT64x, name, *val);
		}
		if (ds->show_comments && !ds->show_comment_right) {
			ds_newline(ds);
		}
	}
	free(msg);
	return 0;
}

static void ds_pre_emulation(RzDisasmState *ds) {
	bool do_esil = ds->show_emu;
	if (!ds->pre_emu) {
		return;
	}
	RzFlagItem *f = rz_flag_get_at(ds->core->flags, ds->core->offset, true);
	if (!f) {
		return;
	}
	ut64 base = f->offset;
	RzAnalysisEsil *esil = ds->core->analysis->esil;
	int i, end = ds->core->offset - base;
	int maxemu = 1024 * 1024;
	RzAnalysisEsilHookRegWriteCB orig_cb = esil->cb.hook_reg_write;
	if (end < 0 || end > maxemu) {
		return;
	}
	esil->cb.hook_reg_write = NULL;
	for (i = 0; i < end; i++) {
		ut64 addr = base + i;
		RzAnalysisOp *op = rz_core_analysis_op(ds->core, addr, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
		if (op) {
			if (do_esil) {
				rz_analysis_esil_set_pc(esil, addr);
				rz_analysis_esil_parse(esil, RZ_STRBUF_SAFEGET(&op->esil));
				if (op->size > 0) {
					i += op->size - 1;
				}
			}
			rz_analysis_op_free(op);
		}
	}
	esil->cb.hook_reg_write = orig_cb;
}

static void ds_print_esil_analysis_init(RzDisasmState *ds) {
	RzCore *core = ds->core;
	const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	if (!pc) {
		return;
	}
	ds->esil_old_pc = rz_reg_getv(core->analysis->reg, pc);
	if (!ds->esil_old_pc || ds->esil_old_pc == UT64_MAX) {
		ds->esil_old_pc = core->offset;
	}
	if (!ds->show_emu) {
		// XXX. stackptr not computed without asm.emu, when its not required
		return;
	}
	if (!core->analysis->esil) {
		int iotrap = rz_config_get_i(core->config, "esil.iotrap");
		int esd = rz_config_get_i(core->config, "esil.stack.depth");
		unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");

		if (!(core->analysis->esil = rz_analysis_esil_new(esd, iotrap, addrsize))) {
			RZ_FREE(ds->esil_regstate);
			return;
		}
		rz_analysis_esil_setup(core->analysis->esil, core->analysis, 0, 0, 1);
	}
	core->analysis->esil->user = ds;
	free(ds->esil_regstate);
	RZ_FREE(core->analysis->last_disasm_reg);
	if (core->analysis->gp) {
		rz_reg_setv(core->analysis->reg, "gp", core->analysis->gp);
	}
	ds->esil_regstate = rz_reg_arena_peek(core->analysis->reg);
	RzRegSet *regset = rz_reg_regset_get(core->analysis->reg, RZ_REG_TYPE_GPR);
	if (ds->esil_regstate && regset) {
		ds->esil_regstate_size = regset->arena->size;
	}

	// TODO: emulate N instructions BEFORE the current offset to get proper full function emulation
	ds_pre_emulation(ds);
}

static void ds_print_bbline(RzDisasmState *ds) {
	if (ds->show_bbline && ds->at) {
		RzAnalysisBlock *bb = NULL;
		RzAnalysisFunction *f_before = NULL;
		if (ds->fcn) {
			bb = rz_analysis_fcn_bbget_at(ds->core->analysis, ds->fcn, ds->at);
		} else {
			f_before = fcnIn(ds, ds->at - 1, RZ_ANALYSIS_FCN_TYPE_NULL);
		}
		if ((ds->fcn && bb && ds->fcn->addr != ds->at) || (!ds->fcn && f_before)) {
			ds_begin_line(ds);
			// adapted from ds_setup_pre ()
			ds->cmtcount = 0;
			if (!ds->show_functions || !ds->show_lines_fcn) {
				ds->pre = DS_PRE_NONE;
			} else {
				ds->pre = DS_PRE_EMPTY;
				if (!f_before) {
					f_before = fcnIn(ds, ds->at - 1, RZ_ANALYSIS_FCN_TYPE_NULL);
				}
				if (f_before == ds->fcn) {
					ds->pre = DS_PRE_FCN_MIDDLE;
				}
			}
			ds_print_pre(ds, true);
			if (!ds->linesright && ds->show_lines_bb && ds->line) {
				char *refline, *reflinecol = NULL;
				ds_update_ref_lines(ds);
				refline = ds->refline2;
				reflinecol = ds->prev_line_col;
				ds_print_ref_lines(refline, reflinecol, ds);
			}
			rz_cons_printf("|");
			ds_newline(ds);
		}
	}
}

static void print_fcn_arg(RzCore *core, RzType *type, const char *name,
	const char *fmt, const ut64 addr,
	const int on_stack, int asm_types) {
	if (on_stack == 1 && asm_types > 1) {
		char *typestr = rz_type_as_string(core->analysis->typedb, type);
		rz_cons_printf("%s", typestr);
		free(typestr);
	}
	if (addr != UT32_MAX && addr != UT64_MAX && addr != 0) {
		char *realfmt = NULL;
		if (on_stack == 1) {
			realfmt = rz_str_newf("*%s %s", fmt, name);
		} else {
			realfmt = rz_str_newf("%s %s", fmt, name);
		}
		int mode = (asm_types == 2) ? RZ_PRINT_MUSTSEE : RZ_PRINT_QUIET | RZ_PRINT_MUSTSEE;
		char *format = rz_core_print_format(core, realfmt, mode, addr);
		rz_str_trim(format);
		rz_cons_print(format);
		free(realfmt);
		free(format);
	} else {
		rz_cons_printf("-1");
	}
	rz_cons_chop();
}

static void delete_last_comment(RzDisasmState *ds) {
	if (!ds->show_comment_right_default) {
		return;
	}
	const char *ll = rz_cons_get_buffer();
	if (!ll) {
		return;
	}
	ll += ds->buf_line_begin;
	const char *begin = ll;
	if (begin) {
		ds_newline(ds);
		ds_begin_cont(ds);
	}
}

static bool can_emulate_metadata(RzCore *core, ut64 at) {
	// check if there is a meta at the addr that is unemulateable
	const char *emuskipmeta = rz_config_get(core->config, "emu.skip");
	bool ret = true;
	RzPVector *metas = rz_meta_get_all_at(core->analysis, at);
	void **it;
	rz_pvector_foreach (metas, it) {
		RzAnalysisMetaItem *item = ((RzIntervalNode *)*it)->data;
		if (strchr(emuskipmeta, (char)item->type)) {
			ret = false;
			break;
		}
	}
	rz_pvector_free(metas);
	return ret;
}

static void mipsTweak(RzDisasmState *ds) {
	RzCore *core = ds->core;
	const char *asm_arch = rz_config_get(core->config, "asm.arch");
	if (asm_arch && *asm_arch && strstr(asm_arch, "mips")) {
		if (rz_config_get_b(core->config, "analysis.gpfixed")) {
			ut64 gp = rz_config_get_i(core->config, "analysis.gp");
			rz_reg_setv(core->analysis->reg, "gp", gp);
		}
	}
}

typedef int (*MemWriteFn)(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len);

// modifies analysis register state
static void ds_print_esil_analysis(RzDisasmState *ds) {
	RzCore *core = ds->core;
	RzAnalysisEsil *esil = core->analysis->esil;
	const char *pc;
	MemWriteFn hook_mem_write = NULL;
	int i, nargs;
	ut64 at = rz_core_pava(core, ds->at);
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return;
	}
	if (!esil) {
		ds_print_esil_analysis_init(ds);
		esil = core->analysis->esil;
	}
	if (!ds->show_emu) {
		goto beach;
	}
	if (!can_emulate_metadata(core, at)) {
		goto beach;
	}
	theme_print_color(comment);
	esil = core->analysis->esil;
	pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	if (pc) {
		rz_reg_setv(core->analysis->reg, pc, at + ds->analysis_op.size);
		esil->cb.user = ds;
		esil->cb.hook_reg_write = myregwrite;
		esil->cb.hook_reg_read = myregread;
		hook_mem_write = esil->cb.hook_mem_write;
	}
	if (ds->show_emu_stack) {
		esil->cb.hook_mem_write = mymemwrite2;
	} else {
		if (ds->show_emu_write) {
			esil->cb.hook_mem_write = mymemwrite0;
		} else {
			esil->cb.hook_mem_write = mymemwrite1;
		}
	}
	ds->esil_likely = 0;
	const char *esilstr = RZ_STRBUF_SAFEGET(&ds->analysis_op.esil);
	if (RZ_STR_ISNOTEMPTY(esilstr)) {
		mipsTweak(ds);
		rz_analysis_esil_set_pc(esil, at);
		rz_analysis_esil_parse(esil, esilstr);
	}
	rz_analysis_esil_stack_free(esil);
	rz_config_hold_i(hc, "io.cache", NULL);
	rz_config_set(core->config, "io.cache", "true");
	if (!ds->show_comments) {
		goto beach;
	}
	switch (ds->analysis_op.type) {
	case RZ_ANALYSIS_OP_TYPE_SWI: {
		char *s = rz_core_syscall_as_string(core, ds->analysis_op.val, at);
		if (s) {
			ds_comment_esil(ds, true, true, "; %s", s);
			free(s);
		}
	} break;
	case RZ_ANALYSIS_OP_TYPE_CJMP:
		ds_comment_esil(ds, true, true, ds->esil_likely ? "; likely" : "; unlikely");
		break;
	case RZ_ANALYSIS_OP_TYPE_JMP: {
		ut64 addr = ds->analysis_op.jump;
		if (!rz_analysis_get_function_at(ds->core->analysis, addr) && !rz_flag_get_at(core->flags, addr, false)) {
			break;
		}
	}
		// fallthrough
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_CALL: {
		RzAnalysisFunction *fcn;
		RzAnalysisFuncArg *arg;
		RzListIter *iter;
		RzListIter *nextele;
		const char *fcn_name = NULL;
		char *key = NULL;
		ut64 pcv = ds->analysis_op.jump;
		if (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_RCALL) {
			pcv = UT64_MAX;
		}
		if (pcv == UT64_MAX) {
			pcv = ds->analysis_op.ptr; // call [reloc-addr] // windows style
			if (pcv == UT64_MAX || !pcv) {
				rz_analysis_esil_reg_read(esil, "$jt", &pcv, NULL);
				if (pcv == UT64_MAX || !pcv) {
					pcv = rz_reg_getv(core->analysis->reg, pc);
				}
			}
		}
		fcn = rz_analysis_get_function_at(core->analysis, pcv);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			RzFlagItem *item = rz_flag_get_i(core->flags, pcv);
			if (item) {
				fcn_name = item->name;
			}
		}
		if (fcn_name) {
			key = resolve_fcn_name(core->analysis, fcn_name);
		}
		if (key) {
			if (ds->asm_types < 1) {
				free(key);
				break;
			}
			RzType *fcn_type = rz_type_func_ret(core->analysis->typedb, key);
			int nargs = rz_type_func_args_count(core->analysis->typedb, key);
			// remove other comments
			delete_last_comment(ds);
			// ds_comment_start (ds, "");
			ds_comment_esil(ds, true, false, "%s", COLOR(ds, comment));
			char *fcn_type_str = NULL;
			if (fcn_type) {
				fcn_type_str = rz_type_as_string(core->analysis->typedb, fcn_type);
			}
			const char *sp = fcn_type && fcn_type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
			ds_comment_middle(ds, "; %s%s%s(",
				fcn_type_str ? fcn_type_str : "", sp,
				rz_str_get_null(key));
			free(fcn_type_str);
			free(key);
			if (!nargs) {
				ds_comment_end(ds, "void)");
				break;
			}
		}
		ut64 s_width = (core->analysis->bits == 64) ? 8 : 4;
		const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
		ut64 spv = rz_reg_getv(core->analysis->reg, sp);
		rz_reg_setv(core->analysis->reg, sp, spv + s_width); // temporarily set stack ptr to sync with carg.c
		RzList *list = rz_core_get_func_args(core, fcn_name);
		if (!rz_list_empty(list)) {
			bool warning = false;
			bool on_stack = false;
			rz_list_foreach (list, iter, arg) {
				if (arg->cc_source && rz_str_startswith(arg->cc_source, "stack")) {
					on_stack = true;
				}
				if (!arg->size) {
					if (ds->asm_types == 2) {
						ds_comment_middle(ds, "%s: unk_size", arg->c_type);
					}
					warning = true;
				}
				nextele = rz_list_iter_get_next(iter);
				if (RZ_STR_ISEMPTY(arg->fmt)) {
					if (ds->asm_types > 1) {
						if (warning) {
							ds_comment_middle(ds, "_format");
						} else {
							ds_comment_middle(ds, "%s : unk_format", arg->c_type);
						}
					} else {
						ds_comment_middle(ds, "?");
					}
					ds_comment_middle(ds, nextele ? ", " : ")");
				} else {
					// TODO: may need ds_comment_esil
					print_fcn_arg(core, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack, ds->asm_types);
					ds_comment_middle(ds, nextele ? ", " : ")");
				}
			}
			ds_comment_end(ds, "");
			rz_list_free(list);
			break;
		} else {
			rz_list_free(list);
			nargs = DEFAULT_NARGS;
			if (fcn) {
				nargs = rz_analysis_arg_count(fcn);
			}
			if (nargs > 0) {
				ds_comment_esil(ds, true, false, "%s", COLOR(ds, comment));
				if (fcn_name) {
					ds_comment_middle(ds, "; %s(", fcn_name);
				} else {
					ds_comment_middle(ds, "; 0x%" PFMT64x "(", pcv);
				}
				const char *cc = rz_analysis_syscc_default(core->analysis);
				for (i = 0; i < nargs; i++) {
					ut64 v = rz_core_arg_get(core, cc, i);
					ds_comment_middle(ds, "%s0x%" PFMT64x, i ? ", " : "", v);
				}
				ds_comment_end(ds, ")");
			}
		}
		rz_reg_setv(core->analysis->reg, sp, spv); // reset stack ptr
	} break;
	}
	ds_print_color_reset(ds);
beach:
	if (esil) {
		esil->cb.hook_mem_write = hook_mem_write;
	}
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
}

static void ds_print_calls_hints(RzDisasmState *ds) {
	bool emu = rz_config_get_b(ds->core->config, "asm.emu");
	bool emuwrite = rz_config_get_b(ds->core->config, "emu.write");
	if (emu && emuwrite) {
		// this is done by ESIL
		return;
	}
	RzAnalysis *analysis = ds->core->analysis;
	char *name;
	char *full_name = NULL;
	if (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_CALL) {
		// RzAnalysisFunction *fcn = rz_analysis_get_fcn_in (analysis, ds->analysis_op.jump, -1);
		RzAnalysisFunction *fcn = fcnIn(ds, ds->analysis_op.jump, -1);
		if (fcn) {
			full_name = fcn->name;
		}
	} else if (ds->analysis_op.ptr != UT64_MAX) {
		RzFlagItem *flag = rz_flag_get_i(ds->core->flags, ds->analysis_op.ptr);
		if (flag && rz_flag_item_get_space(flag) && !strcmp(rz_flag_item_get_space(flag)->name, RZ_FLAGS_FS_IMPORTS)) {
			full_name = rz_flag_item_get_realname(flag);
		}
	}
	if (!full_name) {
		return;
	}
	if (rz_type_func_exist(analysis->typedb, full_name)) {
		name = strdup(full_name);
	} else if (!(name = rz_analysis_function_name_guess(analysis->typedb, full_name))) {
		return;
	}
	ds_begin_comment(ds);
	RzType *fcn_type = rz_type_func_ret(analysis->typedb, name);
	char *fcn_type_str = NULL;
	if (fcn_type) {
		fcn_type_str = rz_type_as_string(analysis->typedb, fcn_type);
	}
	const char *sp = fcn_type && fcn_type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
	char *cmt = rz_str_newf("; %s%s%s(", fcn_type_str ? fcn_type_str : "", sp, name);
	int i, arg_max = rz_type_func_args_count(analysis->typedb, name);
	if (!arg_max) {
		cmt = rz_str_append(cmt, "void)");
	} else {
		for (i = 0; i < arg_max; i++) {
			RzType *arg_type = rz_type_func_args_type(analysis->typedb, name, i);
			const char *tname = rz_type_func_args_name(analysis->typedb, name, i);
			if (arg_type) {
				char *arg_type_str = rz_type_as_string(analysis->typedb, arg_type);
				const char *sp = arg_type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
				cmt = rz_str_appendf(cmt, "%s%s%s%s%s", i == 0 ? "" : " ", arg_type_str, sp,
					tname, i == arg_max - 1 ? ")" : ",");
				free(arg_type_str);
			} else if (tname && !strcmp(tname, "...")) {
				cmt = rz_str_appendf(cmt, "%s%s%s", i == 0 ? "" : " ",
					tname, i == arg_max - 1 ? ")" : ",");
			}
		}
	}
	ds_comment(ds, true, "%s", cmt);
	ds_print_color_reset(ds);
	free(fcn_type_str);
	free(cmt);
	free(name);
}

static void ds_print_comments_right(RzDisasmState *ds) {
	char *desc = NULL;
	RzCore *core = ds->core;
	ds_print_relocs(ds);
	bool is_code = (!ds->hint) || (ds->hint && ds->hint->type != 'd');
	RzAnalysisMetaItem *mi = rz_meta_get_at(ds->core->analysis, ds->at, RZ_META_TYPE_ANY, NULL);
	if (mi) {
		is_code = mi->type != 'd';
		mi = NULL;
	}
	if (is_code && ds->asm_describe && !ds->has_description) {
		char *op, *locase = strdup(rz_asm_op_get_asm(&ds->asmop));
		if (!locase) {
			return;
		}
		op = strchr(locase, ' ');
		if (op) {
			*op = 0;
		}
		rz_str_case(locase, 0);
		desc = rz_asm_describe(core->rasm, locase);
		free(locase);
	}
	if (ds->show_usercomments || ds->show_comments) {
		if (RZ_STR_ISNOTEMPTY(desc)) {
			ds_align_comment(ds);
			theme_printf(comment, "; %s", desc);
		}
		if (ds->show_comment_right && ds->comment) {
			char *comment = ds->comment;
			rz_str_trim(comment);
			if (*comment) {
				if (!desc) {
					ds_align_comment(ds);
				}
				if (strchr(comment, '\n')) {
					comment = strdup(comment);
					if (comment) {
						ds_newline(ds);
						ds_begin_line(ds);
						size_t lines_count;
						size_t *line_indexes = rz_str_split_lines(comment, &lines_count);
						if (line_indexes) {
							int i;
							for (i = 0; i < lines_count; i++) {
								char *c = comment + line_indexes[i];
								ds_print_pre(ds, true);
								theme_print_color(usercomment);
								rz_cons_printf(i == 0 ? "%s" : "; %s", c);
								if (i < lines_count - 1) {
									ds_newline(ds);
									ds_begin_line(ds);
								}
							}
						}
						free(line_indexes);
					}
					free(comment);
				} else {
					if (comment) {
						rz_cons_strcat(comment);
					}
				}
			}
			// rz_cons_strcat_justify (comment, strlen (ds->refline) + 5, ';');
			ds_print_color_reset(ds);
			RZ_FREE(ds->comment);
		}
	}
	free(desc);
	if ((ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_CALL || ds->analysis_op.type & RZ_ANALYSIS_OP_TYPE_UCALL) && ds->show_calls) {
		ds_print_calls_hints(ds);
	}
}

static void ds_print_as_string(RzDisasmState *ds) {
	char *str = rz_num_as_string(NULL, ds->analysis_op.ptr, true);
	if (str) {
		ds_comment(ds, false, "%s; \"%s\"%s", COLOR(ds, comment),
			str, COLOR_RESET(ds));
	}
	free(str);
}

static char *_find_next_number(char *op) {
	if (!op) {
		return NULL;
	}
	char *p = op;
	while (*p) {
		// look for start of next separator or ANSI sequence
		while (*p && !IS_SEPARATOR(*p) && *p != 0x1b) {
			p++;
		}
		if (*p == 0x1b) {
			// skip to end of ANSI sequence (lower or uppercase char)
			while (*p && !(*p >= 'A' && *p <= 'Z') && !(*p >= 'a' && *p <= 'z')) {
				p++;
			}
			if (*p) {
				p++;
			}
		}
		if (IS_SEPARATOR(*p)) {
			// skip to end of separator
			while (*p && IS_SEPARATOR(*p)) {
				p++;
			}
		}
		if (IS_DIGIT(*p)) {
			// we found the start of the next number
			return p;
		}
	}
	return NULL;
}

static bool set_jump_realname(RzDisasmState *ds, ut64 addr, const char **kw, const char **name) {
	RzFlag *f = ds->core->flags;
	if (!f) {
		return false;
	}
	if (!f->realnames) {
		// nothing to do, neither demangled nor regular realnames should be shown
		return false;
	}
	RzFlagItem *flag_sym = rz_flag_get_by_spaces(f, addr, RZ_FLAGS_FS_FUNCTIONS, RZ_FLAGS_FS_SYMBOLS, NULL);
	if (!flag_sym || !flag_sym->realname) {
		// nothing to replace
		return false;
	}
	if (!flag_sym->demangled && !f->realnames) {
		// realname is not demangled and we don't want to show non-demangled realnames
		return false;
	}
	*name = flag_sym->realname;
	RzFlagItem *flag_mthd = rz_flag_get_by_spaces(f, addr, RZ_FLAGS_FS_CLASSES, NULL);
	if (!f->realnames) {
		// for asm.flags.real, we don't want these prefixes
		if (flag_mthd && flag_mthd->name && rz_str_startswith(flag_mthd->name, "method.")) {
			*kw = "method ";
		} else {
			*kw = "sym ";
		}
	}
	return true;
}

/**
 * \brief Remove '#' from the asm string
 * \param op RzAsmOp instance
 */
void rz_asm_op_tricore_fixup(RzAsmOp *op) {
	char *asmstr = rz_asm_op_get_asm(op);
	rz_str_remove_char(asmstr, '#');
	rz_asm_op_set_asm(op, asmstr);
	if (op->asm_toks) {
		rz_asm_token_string_free(op->asm_toks);
		op->asm_toks = NULL;
	}
}

static void ds_asmop_fixup(RzDisasmState *ds) {
	int optype = ds->analysis_op.type & 0xFFFF;
	switch (optype) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		break;
	default:
		return;
	}
	if (rz_str_cmp(ds->core->rasm->cur->arch, "tricore", -1) == 0) {
		rz_asm_op_tricore_fixup(&ds->asmop);
	}
}

// TODO: this should be moved into rz_parse
static void ds_opstr_sub_jumps(RzDisasmState *ds) {
	RzAnalysis *analysis = ds->core->analysis;
	RzFlag *f = ds->core->flags;
	const char *name = NULL;
	const char *kw = "";
	if (!ds->subjmp || !analysis) {
		return;
	}
	int optype = ds->analysis_op.type & 0xFFFF;
	switch (optype) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		break;
	default:
		return;
	}

	ut64 addr = ds->analysis_op.jump;
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, addr);
	if (fcn) {
		if (!set_jump_realname(ds, addr, &kw, &name)) {
			name = fcn->name;
		}
	} else if (f && !set_jump_realname(ds, addr, &kw, &name)) {
		RzFlagItem *flag = rz_core_flag_get_by_spaces(f, addr);
		if (flag) {
			if (strchr(rz_flag_item_get_name(flag), '.')) {
				name = rz_flag_item_get_name(flag);
				if (f->realnames && rz_flag_item_get_realname(flag)) {
					name = rz_flag_item_get_realname(flag);
				}
			}
		}
	}

	if (!name) {
		// If there are no functions and no flags, but there is a reloc, show that
		RzBinReloc *rel = NULL;
		if (!ds->core->bin->is_reloc_patched) {
			rel = rz_core_getreloc(ds->core, ds->analysis_op.addr, ds->analysis_op.size);
		}
		if (!rel) {
			rel = rz_core_get_reloc_to(ds->core, addr);
		}
		if (rel) {
			if (rel && rel->import && rel->import->name) {
				name = rel->import->name;
			} else if (rel && rel->symbol && rel->symbol->name) {
				name = rel->symbol->name;
			}
		}
	}

	if (name) {
		char *nptr, *ptr;
		ut64 numval;
		ptr = ds->opstr;
		while ((nptr = _find_next_number(ptr))) {
			ptr = nptr;
			numval = rz_num_get(NULL, ptr);
			if (numval == addr) {
				while (*nptr && !IS_SEPARATOR(*nptr) && *nptr != 0x1b) {
					nptr++;
				}
				char *kwname = rz_str_newf("%s%s", kw, name);
				if (kwname) {
					char *numstr = rz_str_ndup(ptr, nptr - ptr);
					if (numstr) {
						ds->opstr = rz_str_replace(ds->opstr, numstr, kwname, 0);
						free(numstr);
					}
					free(kwname);
				}
				break;
			}
		}
	}
}

static bool line_highlighted(RzDisasmState *ds) {
	return ds->asm_highlight != UT64_MAX && ds->vat == ds->asm_highlight;
}

static void ds_start_line_highlight(RzDisasmState *ds) {
	if (ds->show_color && line_highlighted(ds)) {
		rz_cons_strcat(COLOR(ds, linehl));
	}
}

static void ds_end_line_highlight(RzDisasmState *ds) {
	if (ds->show_color && line_highlighted(ds)) {
		rz_cons_strcat(Color_RESET);
	}
}

/**
 * \brief Free RzAnalysisDisasmText \p p
 */
RZ_API void rz_analysis_disasm_text_free(RzAnalysisDisasmText *t) {
	if (!t) {
		return;
	}
	free(t->text);
	free(t);
}

/**
 * \brief Disassemble \p len bytes or \p nlines opcodes
 * 	  restricted by \p len and \p nlines at the same time
 *        \p len and \p nlines cannot be zero at the same time
 * \param core RzCore reference
 * \param addr Address
 * \param buf Buffer
 * \param len Bytes number
 * \param nlines Opcode number
 * \param options Disassemble Options
 * \return Disassemble bytes number
 */
RZ_API int rz_core_print_disasm(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL ut8 *buf, int len, int nlines, RZ_NULLABLE RzCmdStateOutput *state,
	RZ_NULLABLE RzCoreDisasmOptions *options) {
	rz_return_val_if_fail(core && buf && (len || nlines), 0);

	PJ *pj = state ? state->d.pj : NULL;
	bool json = state && state->mode == RZ_OUTPUT_MODE_JSON;

	RzPrint *p = core->print;
	int continueoninvbreak = (len == nlines) && (options ? options->invbreak : 0);
	RzAnalysisFunction *f = NULL;
	bool calc_row_offsets = p->calc_row_offsets;
	int ret, inc = 0, skip_bytes_flag = 0, skip_bytes_bb = 0, idx = 0;
	ut8 *nbuf = NULL;
	const int addrbytes = core->io->addrbytes;

	RzConfigHold *rch = rz_config_hold_new(core->config);
	if (!rch) {
		return 0;
	}
	rz_config_hold_i(rch, "asm.bits", NULL);
	rz_config_hold_s(rch, "asm.arch", NULL);

	// TODO: All those ds must be print flags
	RzDisasmState *ds = ds_init(core);
	ds->cbytes = options ? options->cbytes : 0;
	ds->print = p;
	ds->nlines = nlines;
	ds->buf = buf;
	ds->len = len;
	ds->addr = addr;
	ds->hint = NULL;
	ds->buf_line_begin = 0;
	ds->pdf = options ? options->function : NULL;
	ds->pj = NULL;
	ds->vec = options ? options->vec : NULL;

	if (!ds->vec && json) {
		ds->pj = pj ? pj : pj_new();
		if (!ds->pj) {
			ds_free(ds);
			rz_config_hold_restore(rch);
			rz_config_hold_free(rch);
			return 0;
		}
		rz_cons_push();
	}

	// disable row_offsets to prevent other commands to overwrite computed info
	p->calc_row_offsets = false;

	// rz_cons_printf ("len =%d nlines=%d ib=%d limit=%d\n", len, nlines, invbreak, p->limit);
	//  TODO: import values from debugger is possible
	//  TODO: allow to get those register snapshots from traces
	//  TODO: per-function register state trace
	//  XXX - is there a better way to reset a the analysis counter so that
	//  when code is disassembled, it can actually find the correct offsets
	{ /* used by asm.emu */
		rz_reg_arena_push(core->analysis->reg);
	}

	ds_reflines_init(ds);
	/* reset jmp table if not asked to keep it */
	if (!core->keep_asmqjmps) { // hack
		core->asmqjmps_count = 0;
		ut64 *p = realloc(core->asmqjmps, RZ_CORE_ASMQJMPS_NUM * sizeof(ut64));
		if (p) {
			core->asmqjmps_size = RZ_CORE_ASMQJMPS_NUM;
			core->asmqjmps = p;
			for (int i = 0; i < RZ_CORE_ASMQJMPS_NUM; i++) {
				core->asmqjmps[i] = UT64_MAX;
			}
		}
	}
	if (!ds->vec && ds->pj && !pj) {
		pj_a(ds->pj);
	}

	const ut8 min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);

toro:
	// uhm... is this necessary? imho can be removed
	rz_asm_set_pc(core->rasm, rz_core_pava(core, ds->addr + idx));
	core->cons->vline = rz_config_get_b(core->config, "scr.utf8") ? (rz_config_get_b(core->config, "scr.utf8.curvy") ? rz_vline_uc : rz_vline_u) : rz_vline_a;

	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		rz_analysis_op_fini(&ds->analysis_op);
		rz_analysis_op_init(&ds->analysis_op);
		if (rz_analysis_op(core->analysis, &ds->analysis_op, core->offset + core->print->cur,
			    buf + core->print->cur, (int)(len - core->print->cur), DS_ANALYSIS_OP_MASK) > 0) {
			// TODO: check for ds->analysis_op.type and ret
			ds->dest = ds->analysis_op.jump;
		}
	} else {
		/* highlight eip */
		RzReg *reg = rz_core_reg_default(core);
		const char *pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
		if (pc) {
			ds->dest = rz_reg_getv(reg, pc);
		}
	}

	ds_print_esil_analysis_init(ds);
	inc = 0;
	if (!ds->nlines) {
		ds->nlines = core->blocksize;
	}
	rz_cons_break_push(NULL, NULL);
	for (idx = ret = 0; addrbytes * idx < len && ds->lines < ds->nlines; idx += inc, ds->index += inc, ds->lines++) {
		ds->at = ds->addr + idx;
		ds->vat = rz_core_pava(core, ds->at);
		if (rz_cons_is_breaked()) {
			RZ_FREE(nbuf);
			if (!ds->vec && ds->pj) {
				rz_cons_pop();
			}
			rz_cons_break_pop();
			rz_config_hold_restore(rch);
			rz_config_hold_free(rch);
			ds_free(ds);
			return 0; // break;
		}
		if (core->print->flags & RZ_PRINT_FLAGS_UNALLOC) {
			if (!core->analysis->iob.is_valid_offset(core->analysis->iob.io, ds->at, 0)) {
				ds_begin_line(ds);
				ds_print_labels(ds, f);
				ds_setup_print_pre(ds, false, false);
				ds_print_lines_left(ds);
				core->print->resetbg = (ds->asm_highlight == UT64_MAX);
				ds_start_line_highlight(ds);
				ds_print_offset(ds);
				rz_cons_printf("  unmapped\n");
				inc = 1;
				continue;
			}
		}
		rz_core_seek_arch_bits(core, ds->at); // slow but safe
		ds->has_description = false;
		ds->hint = rz_core_hint_begin(core, ds->hint, ds->at);
		ds->printed_str_addr = UT64_MAX;
		ds->printed_flag_addr = UT64_MAX;
		// XXX. this must be done in ds_update_pc()
		// ds_update_pc (ds, ds->at);
		rz_asm_set_pc(core->rasm, ds->at);
		ds_update_ref_lines(ds);
		rz_analysis_op_fini(&ds->analysis_op);
		rz_analysis_op_init(&ds->analysis_op);
		rz_analysis_op(core->analysis, &ds->analysis_op, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx), DS_ANALYSIS_OP_MASK);
		if (ds_must_strip(ds)) {
			inc = ds->analysis_op.size;
			// inc = ds->asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign);
			rz_analysis_op_fini(&ds->analysis_op);
			continue;
		}
		// f = rz_analysis_get_fcn_in (core->analysis, ds->at, RZ_ANALYSIS_FCN_TYPE_NULL);
		f = ds->fcn = fcnIn(ds, ds->at, RZ_ANALYSIS_FCN_TYPE_NULL);
		ds_show_comments_right(ds);
		RzAnalysisVarGlobal *gv = rz_analysis_var_global_get_byaddr_at(core->analysis, ds->addr + idx);
		if (gv) {
			char *fmt = rz_type_as_format_pair(core->analysis->typedb, gv->type);
			const char *typename = rz_type_identifier(gv->type);
			if (fmt && typename) {
				rz_cons_printf("(%s %s)\n", typename, gv->name);
				char *r = rz_core_print_format(core, fmt, RZ_PRINT_MUSTSEE, ds->addr + idx);
				rz_cons_print(r);
				free(r);
				const ut32 type_bitsize = rz_type_db_get_bitsize(core->analysis->typedb, gv->type);
				// always round up when calculating byte_size from bit_size of types
				// could be struct with a bitfield entry
				inc = (type_bitsize >> 3) + (!!(type_bitsize & 0x7));
				free(fmt);
				rz_analysis_op_fini(&ds->analysis_op);
				continue;
			}
		} else {
			if (idx >= 0) {
				ret = ds_disassemble(ds, buf + addrbytes * idx, len - addrbytes * idx);
				if (ret == -31337) {
					inc = ds->oplen;
					rz_analysis_op_fini(&ds->analysis_op);
					continue;
				}
			}
		}
		if (ds->retry) {
			ds->retry = false;
			rz_cons_break_pop();
			rz_analysis_op_fini(&ds->analysis_op);
			goto retry;
		}
		ds_atabs_option(ds);
		if (ds->analysis_op.addr != ds->at) {
			rz_analysis_op_fini(&ds->analysis_op);
			rz_analysis_op_init(&ds->analysis_op);
			rz_analysis_op(core->analysis, &ds->analysis_op, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx), DS_ANALYSIS_OP_MASK);
		}
		if (ret < 1) {
			rz_strbuf_fini(&ds->analysis_op.esil);
			rz_strbuf_init(&ds->analysis_op.esil);
			ds->analysis_op.type = RZ_ANALYSIS_OP_TYPE_ILL;
		}
		if (ds->hint) {
			if (ds->hint->size) {
				ds->analysis_op.size = ds->hint->size;
			}
			if (ds->hint->ptr) {
				ds->analysis_op.ptr = ds->hint->ptr;
			}
		}
		ds_print_bbline(ds);
		if (ds->at >= addr) {
			rz_print_set_rowoff(core->print, ds->lines, ds->at - addr, calc_row_offsets);
		}
		skip_bytes_flag = handleMidFlags(core, ds, true);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB(core, ds);
		}
		ds_show_xrefs(ds);
		ds_show_flags(ds, false);
		if (skip_bytes_flag && ds->midflags == RZ_MIDFLAGS_SHOW &&
			(!ds->midbb || !skip_bytes_bb || skip_bytes_bb > skip_bytes_flag)) {
			ds->at += skip_bytes_flag;
			ds_show_xrefs(ds);
			ds_show_flags(ds, true);
			ds->at -= skip_bytes_flag;
		}
		if (ds->pdf) {
			RzAnalysisBlock *bb = rz_analysis_fcn_bbget_in(core->analysis, ds->pdf, ds->at);
			if (!bb) {
				for (inc = 1; inc < ds->oplen; inc++) {
					RzAnalysisBlock *bb = rz_analysis_fcn_bbget_in(core->analysis, ds->pdf, ds->at + inc);
					if (bb) {
						break;
					}
				}
				rz_analysis_op_fini(&ds->analysis_op);
				RZ_FREE(ds->opstr);
				if (!ds->sparse) {
					rz_cons_printf("..\n");
					ds->sparse = true;
				}
				continue;
			}
			ds->sparse = false;
		}
		ds_control_flow_comments(ds);
		ds_adistrick_comments(ds);
		/* XXX: This is really cpu consuming.. need to be fixed */
		ds_show_functions(ds);
		if (ds->show_comments && !ds->show_comment_right) {
			ds_show_refs(ds);
			ds_build_op_str(ds, false);
			ds_print_cmt_esil(ds);
			ds_print_cmt_il(ds);
			ds_print_ptr(ds, len + 256, idx);
			ds_print_sysregs(ds);
			ds_print_fcn_name(ds);
			ds_print_color_reset(ds);
			if (!ds->pseudo) {
				RZ_FREE(ds->opstr);
			}
			if (ds->show_emu) {
				ds_print_esil_analysis(ds);
			}
			if ((ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_CALL || ds->analysis_op.type & RZ_ANALYSIS_OP_TYPE_UCALL) && ds->show_calls) {
				ds_print_calls_hints(ds);
			}
			ds_show_comments_describe(ds);
		}
		f = fcnIn(ds, ds->addr, 0);
		ds_begin_line(ds);
		ds_print_labels(ds, f);
		ds_setup_print_pre(ds, false, false);
		ds_print_lines_left(ds);
		core->print->resetbg = (ds->asm_highlight == UT64_MAX);
		ds_start_line_highlight(ds);
		ds_print_offset(ds);
		////
		RzAnalysisFunction *fcn = f;
		if (fcn) {
			RzAnalysisBlock *bb = rz_analysis_fcn_bbget_in(core->analysis, fcn, ds->at);
			if (!bb) {
				fcn = rz_analysis_get_function_at(core->analysis, ds->at);
				if (fcn) {
					rz_analysis_fcn_bbget_in(core->analysis, fcn, ds->at);
				}
			}
		}
		int mi_type;
		bool mi_found = ds_print_meta_infos(ds, buf, len, idx, &mi_type);
		if (ds->asm_hint_pos == 0) {
			if (mi_found) {
				rz_cons_printf("      ");
			} else {
				ds_print_core_vmode(ds, ds->asm_hint_pos);
			}
		}
		ds_print_op_size(ds);
		ds_print_trace(ds);
		ds_print_cycles(ds);
		ds_print_family(ds);
		ds_print_stackptr(ds);
		if (mi_found) {
			ds_print_debuginfo(ds);
			ret = ds_print_middle(ds, ret);

			ds_print_asmop_payload(ds, buf + addrbytes * idx);
			if (core->rasm->syntax != RZ_ASM_SYNTAX_INTEL) {
				RzAsmOp ao; /* disassemble for the vm .. */
				int os = core->rasm->syntax;
				rz_asm_set_syntax(core->rasm, RZ_ASM_SYNTAX_INTEL);
				rz_asm_disassemble(core->rasm, &ao, buf + addrbytes * idx,
					len - addrbytes * idx + 5);
				rz_asm_set_syntax(core->rasm, os);
			}
			if (mi_type == RZ_META_TYPE_FORMAT) {
				if ((ds->show_comments || ds->show_usercomments) && ds->show_comment_right) {
					//		haveMeta = false;
				}
			}
			if (mi_type != RZ_META_TYPE_FORMAT) {
				if (ds->asm_hint_pos > 0) {
					ds_print_core_vmode(ds, ds->asm_hint_pos);
				}
			}
			{
				ds_end_line_highlight(ds);
				if ((ds->show_comments || ds->show_usercomments) && ds->show_comment_right) {
					ds_print_color_reset(ds);
					ds_print_comments_right(ds);
				}
			}
		} else {
			/* show cursor */
			ds_print_show_cursor(ds);
			if (!ds->show_bytes_right) {
				ds_print_show_bytes(ds);
			}
			ds_print_lines_right(ds);
			ds_print_optype(ds);
			ds_build_op_str(ds, true);
			ds_print_opstr(ds);
			ds_end_line_highlight(ds);
			ds_print_debuginfo(ds);
			ret = ds_print_middle(ds, ret);

			ds_print_asmop_payload(ds, buf + addrbytes * idx);
			if (core->rasm->syntax != RZ_ASM_SYNTAX_INTEL) {
				RzAsmOp ao; /* disassemble for the vm .. */
				int os = core->rasm->syntax;
				rz_asm_set_syntax(core->rasm, RZ_ASM_SYNTAX_INTEL);
				rz_asm_disassemble(core->rasm, &ao, buf + addrbytes * idx,
					len - addrbytes * idx + 5);
				rz_asm_set_syntax(core->rasm, os);
			}
			if (ds->show_bytes_right && ds->show_bytes) {
				ds_comment(ds, true, "");
				ds_print_show_bytes(ds);
			}
			if (ds->asm_hint_pos > 0) {
				ds_print_core_vmode(ds, ds->asm_hint_pos);
			}
			// ds_print_cc_update (ds);

			ds_cdiv_optimization(ds);
			if ((ds->show_comments || ds->show_usercomments) && ds->show_comment_right) {
				ds_print_cmt_esil(ds);
				ds_print_cmt_il(ds);
				ds_print_ptr(ds, len + 256, idx);
				ds_print_sysregs(ds);
				ds_print_fcn_name(ds);
				ds_print_color_reset(ds);
				ds_print_comments_right(ds);
				ds_print_esil_analysis(ds);
				ds_show_refs(ds);
			}
		}

		core->print->resetbg = true;
		ds_newline(ds);
		if (ds->line) {
			if (ds->show_lines_ret && ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_RET) {
				if (strchr(ds->line, '>')) {
					memset(ds->line, ' ', rz_str_len_utf8(ds->line));
				}
				ds_begin_line(ds);
				ds_print_pre(ds, true);
				ds_print_ref_lines(ds->line, ds->line_col, ds);
				rz_cons_printf("; --------------------------------------");
				ds_newline(ds);
			}
			RZ_FREE(ds->line);
			RZ_FREE(ds->line_col);
			RZ_FREE(ds->refline);
			RZ_FREE(ds->refline2);
			RZ_FREE(ds->prev_line_col);
		}
		RZ_FREE(ds->opstr);
		inc = ds->oplen;

		if (ds->midflags == RZ_MIDFLAGS_REALIGN && skip_bytes_flag) {
			inc = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < inc) {
			inc = skip_bytes_bb;
		}
		if (inc < 1) {
			inc = min_op_size;
		}
		inc += ds->asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign);
	}
	rz_analysis_op_fini(&ds->analysis_op);

	RZ_FREE(nbuf);
	rz_cons_break_pop();

#if HASRETRY
	if (!ds->cbytes && ds->lines < ds->nlines) {
		ds->addr = ds->at + inc;
	retry:
		if (len < 4) {
			len = 4;
		}
		free(nbuf);
		buf = nbuf = malloc(len);
		if (ds->tries > 0) {
			if (rz_io_read_at(core->io, ds->addr, buf, len)) {
				goto toro;
			}
		}
		if (ds->lines < ds->nlines) {
			// ds->addr += idx;
			if (!rz_io_read_at(core->io, ds->addr, buf, len)) {
				// ds->tries = -1;
			}
			goto toro;
		}
		if (continueoninvbreak) {
			goto toro;
		}
		RZ_FREE(nbuf);
	}
#endif
	if (!ds->vec && ds->pj) {
		rz_cons_pop();
		if (!pj) {
			pj_end(ds->pj);
			rz_cons_printf("%s", pj_string(ds->pj));
			pj_free(ds->pj);
		}
	}
	rz_print_set_rowoff(core->print, ds->lines, ds->at - addr, calc_row_offsets);
	rz_print_set_rowoff(core->print, ds->lines + 1, UT32_MAX, calc_row_offsets);
	// TODO: this too (must review)
	ds_print_esil_analysis_fini(ds);
	ds_reflines_fini(ds);
	rz_config_hold_restore(rch);
	rz_config_hold_free(rch);
	ds_free(ds);
	RZ_FREE(nbuf);
	p->calc_row_offsets = calc_row_offsets;
	/* used by asm.emu */
	rz_reg_arena_pop(core->analysis->reg);
	return addrbytes * idx; //-ds->lastfail;
}

/**
 * \brief Is \p i_opcodes \< \p nb_opcodes and \p i_bytes \< \p nb_bytes ?
 */
RZ_IPI bool rz_disasm_check_end(st64 nb_opcodes, st64 i_opcodes, st64 nb_bytes, st64 i_bytes) {
	if (nb_opcodes > 0) {
		if (nb_bytes > 0) {
			return i_opcodes < nb_opcodes && i_bytes < nb_bytes;
		}
		return i_opcodes < nb_opcodes;
	}
	return i_bytes < nb_bytes;
}

/**
 * \brief Disassemble \p nb_bytes bytes or \p nb_opcodes instructions, the length is
 *      constrained by both of them. Set one of them to 0 will disable its constraint.
 *      Both of them cannot be 0 at the same time.
 * \param core RzCore reference
 * \param address Start address of disassembling
 * \param buf Buffer, if NULL, read from address
 * \param nb_bytes Bytes number
 * \param nb_opcodes Opcode number
 * \return Number of disassembled bytes
 */
RZ_API int rz_core_print_disasm_instructions_with_buf(RzCore *core, ut64 address, ut8 *buf, int nb_bytes, int nb_opcodes) {
	// unclear stop condition if nb_bytes and nb_opcodes are both 0
	rz_return_val_if_fail(core && (nb_bytes || nb_opcodes), 0);

	RzDisasmState *ds = NULL;
	int i, j, ret, len = 0;
	char *tmpopstr;
	bool hasanalysis = false;
	bool alloc_buf = !buf;
	const size_t addrbytes = buf ? 1 : core->io->addrbytes;
	int skip_bytes_flag = 0, skip_bytes_bb = 0;

	// set the parameter equaling 0 to a value that won't affect another parameter
	if (nb_bytes == 0 && nb_opcodes != 0) {
		nb_bytes = MAX_OPSIZE * RZ_ABS(nb_opcodes) + 1;
	}
	if (nb_bytes != 0 && nb_opcodes == 0) {
		nb_opcodes = nb_bytes / MIN_OPSIZE + 1;
	}

	if (nb_bytes < 1 && nb_opcodes < 1) {
		return 0;
	}

	rz_reg_arena_push(core->analysis->reg);

	ds = ds_init(core);
	ds->nlines = nb_opcodes;
	ds->len = nb_opcodes * 8;

	if (!buf) {
		buf = malloc(RZ_ABS(nb_bytes) + 1);
		if (!buf) {
			RZ_LOG_ERROR("Fail to alloc memory.");
			ds_free(ds);
			return 0;
		}
		if (rz_io_nread_at(core->io, address, buf, RZ_ABS(nb_bytes) + 1) == -1) {
			RZ_LOG_ERROR("Fail to read from 0x%" PFMT64x ".", address);
			ds_free(ds);
			free(buf);
			return 0;
		}
	}

	rz_cons_break_push(NULL, NULL);
	// build ranges to map addr with bits
	j = 0;
	for (i = 0; rz_disasm_check_end(nb_opcodes, j, nb_bytes, addrbytes * i); i += ret, j++) {
		ds->at = address + i;
		ds->vat = rz_core_pava(core, ds->at);
		int len = nb_bytes - addrbytes * i;
		hasanalysis = false;
		rz_core_seek_arch_bits(core, ds->at);
		if (rz_cons_is_breaked()) {
			break;
		}
		ds->hint = rz_core_hint_begin(core, ds->hint, ds->at);
		ds->has_description = false;
		rz_asm_set_pc(core->rasm, ds->at);
		// XXX copypasta from main disassembler function
		// rz_analysis_get_fcn_in (core->analysis, ds->at, RZ_ANALYSIS_FCN_TYPE_NULL);
		ret = rz_asm_disassemble(core->rasm, &ds->asmop,
			buf + addrbytes * i, len);
		ds->oplen = ret;
		skip_bytes_flag = handleMidFlags(core, ds, true);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB(core, ds);
		}
		if (skip_bytes_flag && ds->midflags > RZ_MIDFLAGS_SHOW) {
			ret = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < ret) {
			ret = skip_bytes_bb;
		}
		rz_analysis_op_fini(&ds->analysis_op);
		if (!hasanalysis) {
			// XXX we probably don't need MASK_ALL
			rz_analysis_op_init(&ds->analysis_op);
			rz_analysis_op(core->analysis, &ds->analysis_op, ds->at, buf + addrbytes * i, len, RZ_ANALYSIS_OP_MASK_ALL);
			hasanalysis = true;
		}
		if (ds_must_strip(ds)) {
			continue;
		}

		if (ds->hint && ds->hint->size > 0) {
			ret = ds->hint->size;
			ds->oplen = ret;
			ds->analysis_op.size = ret;
			ds->asmop.size = ret;
		}
		/* fix infinite loop */
		if (ret < 1) {
			ret = 1;
		}
		len += RZ_MAX(0, ret);
		if (ds->hint && ds->hint->opcode) {
			free(ds->opstr);
			ds->opstr = strdup(ds->hint->opcode);
		} else {
			if (ds->decode && !ds->immtrim) {
				RZ_FREE(ds->opstr);
				if (!hasanalysis) {
					rz_analysis_op_init(&ds->analysis_op);
					rz_analysis_op(core->analysis, &ds->analysis_op, ds->at, buf + i, nb_bytes - i, RZ_ANALYSIS_OP_MASK_ALL);
				}
				tmpopstr = rz_analysis_op_to_string(core->analysis, &ds->analysis_op);
				ds->opstr = (tmpopstr) ? tmpopstr : strdup(rz_asm_op_get_asm(&ds->asmop));
			} else if (ds->immtrim) {
				free(ds->opstr);
				ds->opstr = strdup(rz_asm_op_get_asm(&ds->asmop));
				rz_parse_immtrim(ds->opstr);
			} else if (ds->use_esil) {
				if (!hasanalysis) {
					rz_analysis_op_init(&ds->analysis_op);
					rz_analysis_op(core->analysis, &ds->analysis_op,
						ds->at, buf + i,
						nb_bytes - i, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
				}
				if (*RZ_STRBUF_SAFEGET(&ds->analysis_op.esil)) {
					free(ds->opstr);
					ds->opstr = strdup(RZ_STRBUF_SAFEGET(&ds->analysis_op.esil));
				}
			} else if (ds->subnames) {
				RzSpace *ofs = core->parser->flagspace;
				RzSpace *fs = ds->flagspace_ports;
				if (ds->analysis_op.type == RZ_ANALYSIS_OP_TYPE_IO) {
					core->parser->notin_flagspace = NULL;
					core->parser->flagspace = fs;
				} else {
					if (fs) {
						core->parser->notin_flagspace = fs;
						core->parser->flagspace = fs;
					} else {
						core->parser->notin_flagspace = NULL;
						core->parser->flagspace = NULL;
					}
				}
				ds_build_op_str(ds, true);
				free(ds->opstr);
				ds->opstr = strdup(ds->str);

				if (!(ds->show_color && ds->colorop) && !ds->opstr) {
					ds->opstr = strdup(rz_asm_op_get_asm(&ds->asmop));
				}

				core->parser->flagspace = ofs;
			} else {
				ds->opstr = strdup(rz_asm_op_get_asm(&ds->asmop));
			}
			if (ds->immtrim) {
				free(ds->opstr);
				ds->opstr = strdup(rz_asm_op_get_asm(&ds->asmop));
				ds->opstr = rz_parse_immtrim(ds->opstr);
			}
		}
		if (ds->asm_instr) {
			if (ds->show_color) {
				rz_cons_printf("%s\n", ds->opstr);
			} else {
				rz_cons_println(ds->opstr);
			}
			RZ_FREE(ds->opstr);
		}
		if (ds->hint) {
			rz_analysis_hint_free(ds->hint);
			ds->hint = NULL;
		}
	}
	rz_cons_break_pop();
	ds_free(ds);
	rz_reg_arena_pop(core->analysis->reg);
	if (alloc_buf) {
		free(buf);
	}
	return len;
}

/**
 * \brief Calculate the offset while \p pn_opcodes and \p pn_bytes
 *       are negative, and \p pn_opcodes and \p pn_bytes will be
 *       converted to positive numbers.
 * \param core RzCore reference
 * \param cur_offset current offset
 * \prarm pn_opcodes Pointer to n_opcodes
 * \param pn_bytes Pointer to n_bytes
 * \return calculated offset
 */
RZ_IPI ut64 rz_core_backward_offset(RZ_NONNULL RzCore *core, ut64 cur_offset, RZ_NONNULL RZ_INOUT int *pn_opcodes, RZ_NONNULL RZ_INOUT int *pn_bytes) {
	rz_return_val_if_fail(core && pn_opcodes && pn_bytes, false);

	if (*pn_opcodes >= 0 && *pn_bytes >= 0) {
		return cur_offset;
	}

	ut64 opcode_offset = cur_offset;
	if (*pn_opcodes < 0) {
		*pn_opcodes = -*pn_opcodes;
		if (!rz_core_prevop_addr(core, cur_offset, *pn_opcodes, &opcode_offset)) {
			opcode_offset = rz_core_prevop_addr_force(core, cur_offset, *pn_opcodes);
		}
	}

	ut64 byte_offset = cur_offset;
	if (*pn_bytes < 0) {
		*pn_bytes = RZ_MIN(RZ_ABS(*pn_bytes), RZ_CORE_MAX_DISASM);
		byte_offset = cur_offset - *pn_bytes;
	}

	return RZ_MIN(opcode_offset, byte_offset);
}

/* Disassemble either `nb_opcodes` instructions, or
 * `nb_bytes` bytes; both can be negative.
 * Set to 0 the parameter you don't use */
RZ_API int rz_core_print_disasm_instructions(RzCore *core, int nb_bytes, int nb_opcodes) {
	int ret = -1;
	// handler negative parameters
	ut64 offset = rz_core_backward_offset(core, core->offset, &nb_opcodes, &nb_bytes);
	ret = rz_core_print_disasm_instructions_with_buf(core, offset, NULL, nb_bytes, nb_opcodes);
	return ret;
}

RZ_API int rz_core_print_disasm_json(RzCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes, PJ *pj) {
	bool res = true;
	RzIterator *iter = NULL;
	ut64 offset = rz_core_backward_offset(core, addr, &nb_opcodes, &nb_bytes);
	iter = rz_core_analysis_bytes(core, offset, buf, nb_bytes, nb_opcodes);
	if (!iter) {
		res = false;
		goto clean_return;
	}

	bool asm_pseudo = rz_config_get_i(core->config, "asm.pseudo");

	RzAnalysisBytes *ab;
	rz_iterator_foreach(iter, ab) {
		RzAnalysisOp *op = ab->op;
		if (!op) {
			continue;
		}
		pj_o(pj);
		pj_kn(pj, "offset", op->addr);
		if (op->type == RZ_ANALYSIS_OP_TYPE_ILL) {
			pj_ki(pj, "size", 1);
			pj_ks(pj, "bytes", ab->bytes);
			pj_ks(pj, "opcode", "invalid");
			pj_end(pj);
			continue;
		}
		if (op->ptr != UT64_MAX) {
			pj_kn(pj, "ptr", op->ptr);
		}
		if (op->val != UT64_MAX) {
			pj_kn(pj, "val", op->val);
		}

		RzAnalysisHint *hint = ab->hint;
		pj_k(pj, "esil"); // split key and value to allow empty strings
		const char *esil = RZ_STRBUF_SAFEGET(&op->esil);
		pj_s(pj, hint && hint->esil ? hint->esil : (esil ? esil : ""));

		pj_kb(pj, "refptr", op->refptr);

		RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, op->addr, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM | RZ_ANALYSIS_FCN_TYPE_LOC);
		pj_kn(pj, "fcn_addr", f ? f->addr : 0);
		pj_kn(pj, "fcn_last", f ? rz_analysis_function_max_addr(f) - ab->oplen : 0);
		pj_ki(pj, "size", op->size);
		pj_ks(pj, "opcode", asm_pseudo ? ab->pseudo : ab->opcode);
		pj_ks(pj, "disasm", ab->disasm);
		pj_k(pj, "bytes");
		pj_s(pj, ab->bytes);
		pj_ks(pj, "family", rz_analysis_op_family_to_string(op->family));
		pj_ks(pj, "type", rz_analysis_optype_to_string(op->type));
		// indicate a relocated address
		RzBinReloc *rel = rz_core_getreloc(core, op->addr, op->size);
		// reloc is true if address in reloc table
		pj_kb(pj, "reloc", rel);
		// wanted the numerical values of the type information
		pj_kn(pj, "type_num", (ut64)(op->type & UT64_MAX));
		pj_kn(pj, "type2_num", (ut64)(op->type2 & UT64_MAX));
		// handle switch statements
		if (op->switch_op && rz_list_length(op->switch_op->cases) > 0) {
			// XXX - the java caseop will still be reported in the assembly,
			// this is an artifact to make ensure the disassembly is properly
			// represented during the analysis
			RzListIter *iter2;
			RzAnalysisCaseOp *caseop;
			pj_k(pj, "switch");
			pj_a(pj);
			rz_list_foreach (op->switch_op->cases, iter2, caseop) {
				pj_o(pj);
				pj_kn(pj, "addr", caseop->addr);
				pj_kN(pj, "value", (st64)caseop->value);
				pj_kn(pj, "jump", caseop->jump);
				pj_end(pj);
			}
			pj_end(pj);
		}
		if (op->jump != UT64_MAX) {
			pj_kN(pj, "jump", op->jump);
			if (op->fail != UT64_MAX) {
				pj_kn(pj, "fail", op->fail);
			}
		}
		/* add flags */
		{
			const RzList *flags = rz_flag_get_list(core->flags, op->addr);
			RzFlagItem *flag;
			RzListIter *iter2;
			if (flags && !rz_list_empty(flags)) {
				pj_k(pj, "flags");
				pj_a(pj);
				rz_list_foreach (flags, iter2, flag) {
					pj_s(pj, rz_flag_item_get_name(flag));
				}
				pj_end(pj);
			}
		}
		/* add comments */
		{
			// TODO: slow because we are encoding b64
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, op->addr);
			if (comment) {
				char *b64comment = sdb_encode((const ut8 *)comment, -1);
				pj_ks(pj, "comment", b64comment);
				free(b64comment);
			}
		}
		/* add xrefs from */
		{
			RzAnalysisXRef *xref;
			RzListIter *iter2;
			RzList *xrefs = rz_analysis_xrefs_get_from(core->analysis, op->addr);
			if (xrefs && !rz_list_empty(xrefs)) {
				pj_k(pj, "xrefs_from");
				pj_a(pj);
				rz_list_foreach (xrefs, iter2, xref) {
					pj_o(pj);
					pj_kn(pj, "addr", xref->to);
					pj_ks(pj, "type", rz_analysis_xrefs_type_tostring(xref->type));
					pj_end(pj);
				}
				pj_end(pj);
			}
			rz_list_free(xrefs);
		}
		/* add xrefs to */
		{
			RzAnalysisXRef *xref;
			RzListIter *iter2;
			RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, op->addr);
			if (xrefs && !rz_list_empty(xrefs)) {
				pj_k(pj, "xrefs_to");
				pj_a(pj);
				rz_list_foreach (xrefs, iter2, xref) {
					pj_o(pj);
					pj_kn(pj, "addr", xref->from);
					pj_ks(pj, "type", rz_analysis_xrefs_type_tostring(xref->type));
					pj_end(pj);
				}
				pj_end(pj);
			}
			rz_list_free(xrefs);
		}

		pj_end(pj);
	}
clean_return:
	rz_iterator_free(iter);
	return res;
}

RZ_API int rz_core_print_disasm_all(RzCore *core, ut64 addr, int l, int len, int mode) {
	const bool scr_color = rz_config_get_i(core->config, "scr.color");
	int i, ret, count = 0;
	ut8 *buf = core->block;
	char str[128];
	RzAsmOp asmop;
	if (l < 1) {
		l = len;
	}
	RzDisasmState *ds = ds_init(core);
	if (l > core->blocksize || addr != core->offset) {
		buf = malloc(l + 1);
		rz_io_read_at(core->io, addr, buf, l);
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new();
		if (!pj) {
			return 0;
		}
		pj_a(pj);
	}
	rz_cons_break_push(NULL, NULL);
	for (i = 0; i < l; i++) {
		ds->at = addr + i;
		ds->vat = rz_core_pava(core, ds->at);
		rz_asm_set_pc(core->rasm, ds->vat);
		if (rz_cons_is_breaked()) {
			break;
		}
		ret = rz_asm_disassemble(core->rasm, &asmop, buf + i, l - i);
		if (ret < 1) {
			switch (mode) {
			case 'j':
			case '=':
				break;
			case 'i':
				rz_cons_printf("???\n");
				break;
			default:
				rz_cons_printf("0x%08" PFMT64x " ???\n", ds->vat);
				break;
			}
		} else {
			count++;
			switch (mode) {
			case 'i':
				rz_parse_filter(core->parser, ds->vat, core->flags, ds->hint, rz_asm_op_get_asm(&asmop),
					str, sizeof(str), core->print->big_endian);
				if (scr_color) {
					RzAnalysisOp aop = { 0 };
					rz_analysis_op_init(&aop);
					rz_analysis_op(core->analysis, &aop, addr, buf + i, l - i, RZ_ANALYSIS_OP_MASK_ALL);
					RzStrBuf *colored_asm;
					RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
					colored_asm = rz_asm_colorize_asm_str(&asmop.buf_asm, core->print, param, asmop.asm_toks);
					rz_analysis_op_fini(&aop);
					rz_asm_parse_param_free(param);
					if (colored_asm) {
						rz_cons_printf("%s\n", rz_strbuf_get(colored_asm));
						rz_strbuf_free(colored_asm);
					}
				} else {
					rz_cons_println(rz_asm_op_get_asm(&asmop));
				}
				break;
			case '=':
				if (i < 28) {
					char *str = rz_str_newf("0x%08" PFMT64x " %60s  %s\n", ds->vat, "", rz_asm_op_get_asm(&asmop));
					char *sp = strchr(str, ' ');
					if (sp) {
						char *end = sp + 60 + 1;
						char *src = rz_asm_op_get_hex(&asmop);
						char *dst = sp + 1 + (i * 2);
						int len = strlen(src);
						if (dst < end) {
							if (dst + len >= end) {
								len = end - dst;
								dst[len] = '.';
							}
							memcpy(dst, src, len);
						}
						free(src);
					}
					rz_cons_strcat(str);
					free(str);
				}
				break;
			case 'j': {
				char *op_hex = rz_asm_op_get_hex(&asmop);
				pj_o(pj);
				pj_kn(pj, "addr", addr + i);
				pj_ks(pj, "bytes", op_hex);
				pj_ks(pj, "inst", rz_asm_op_get_asm(&asmop));
				pj_end(pj);
				free(op_hex);
				break;
			}
			default: {
				char *op_hex = rz_asm_op_get_hex(&asmop);
				rz_cons_printf("0x%08" PFMT64x " %20s  %s\n",
					addr + i, op_hex,
					rz_asm_op_get_asm(&asmop));
				free(op_hex);
			}
			}
		}
	}
	rz_cons_break_pop();
	if (buf != core->block) {
		free(buf);
	}
	if (mode == 'j') {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
	ds_free(ds);
	return count;
}

RZ_API int rz_core_disasm_pdi_with_buf(RzCore *core, ut64 address, ut8 *buf, ut32 nb_opcodes, ut32 nb_bytes, int fmt) {
	bool show_offset = rz_config_get_b(core->config, "asm.offset");
	bool show_bytes = rz_config_get_b(core->config, "asm.bytes");
	bool decode = rz_config_get_b(core->config, "asm.decode");
	bool subnames = rz_config_get_b(core->config, "asm.sub.names");
	int show_color = rz_config_get_i(core->config, "scr.color");
	bool asm_ucase = rz_config_get_b(core->config, "asm.ucase");
	bool asm_instr = rz_config_get_b(core->config, "asm.instr");
	bool esil = rz_config_get_b(core->config, "asm.esil");
	bool flags = rz_config_get_b(core->config, "asm.flags");
	bool asm_immtrim = rz_config_get_b(core->config, "asm.imm.trim");
	bool alloc_buf = !buf;
	int i = 0, j, ret, err = 0;
	RzAsmOp asmop;
	const size_t addrbytes = buf ? 1 : core->io->addrbytes;

	// set the parameter equaling 0 to a value that won't affect another parameter
	if (nb_bytes == 0 && nb_opcodes != 0) {
		nb_bytes = MAX_OPSIZE * RZ_ABS(nb_opcodes) + 1;
	}
	if (nb_bytes != 0 && nb_opcodes == 0) {
		nb_opcodes = nb_bytes / MIN_OPSIZE + 1;
	}

	if (fmt == 'e') {
		show_bytes = false;
		decode = 1;
	}

	if (nb_opcodes < 1 && nb_bytes < 1) {
		return 0;
	}

	if (!buf) {
		buf = malloc(RZ_ABS(nb_bytes) + 1);
		if (!buf) {
			RZ_LOG_ERROR("Fail to alloc memory.");
			return 0;
		}
		if (rz_io_nread_at(core->io, address, buf, RZ_ABS(nb_bytes) + 1) == -1) {
			free(buf);
			RZ_LOG_ERROR("Fail to read from 0x%" PFMT64x ".", address);
			return 0;
		}
	}

	rz_cons_break_push(NULL, NULL);
	int midflags = rz_config_get_i(core->config, "asm.flags.middle");
	bool midbb = rz_config_get_b(core->config, "asm.bb.middle");
	bool asmmarks = rz_config_get_b(core->config, "asm.marks");
	rz_config_set_i(core->config, "asm.marks", false);
	i = 0;
	j = 0;
	RzAnalysisMetaItem *meta = NULL;
	for (; rz_disasm_check_end(nb_opcodes, j, nb_bytes, addrbytes * i); j++) {
		if (rz_cons_is_breaked()) {
			err = 1;
			break;
		}
		ut64 at = address + i;
		if (flags) {
			if (fmt != 'e') { // pie
				RzFlagItem *item = rz_flag_get_i(core->flags, at);
				if (item) {
					if (show_offset) {
						const int show_offseg = (core->print->flags & RZ_PRINT_FLAGS_SEGOFF) != 0;
						const int show_offdec = (core->print->flags & RZ_PRINT_FLAGS_ADDRDEC) != 0;
						unsigned int seggrn = rz_config_get_i(core->config, "asm.seggrn");
						rz_print_offset_sg(core->print, at, 0, show_offseg, seggrn, show_offdec, 0, NULL);
					}
					rz_cons_printf("  %s:\n", item->name);
				}
			} // do not show flags in pie
		}
		if (show_offset) {
			const int show_offseg = (core->print->flags & RZ_PRINT_FLAGS_SEGOFF) != 0;
			const int show_offdec = (core->print->flags & RZ_PRINT_FLAGS_ADDRDEC) != 0;
			unsigned int seggrn = rz_config_get_i(core->config, "asm.seggrn");
			rz_print_offset_sg(core->print, at, 0, show_offseg, seggrn, show_offdec, 0, NULL);
		}
		ut64 meta_start = at;
		ut64 meta_size;
		meta = rz_meta_get_at(core->analysis, meta_start, RZ_META_TYPE_ANY, &meta_size);
		if (meta) {
			switch (meta->type) {
			case RZ_META_TYPE_DATA:
				// rz_cons_printf (".data: %s\n", meta->str);
				i += meta_size;
				{
					int idx = i;
					ut64 at = address + i;
					int hexlen = nb_bytes - idx;
					int delta = at - meta_start;
					if (meta_size < hexlen) {
						hexlen = meta_size;
					}
					// int oplen = meta->size - delta;
					core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
					// TODO do not pass a copy in parameter buf that is possibly to small for this
					// print operation
					int size = RZ_MIN(meta_size, nb_bytes - idx);
					RzDisasmState ds = { 0 };
					ds.core = core;
					if (!ds_print_data_type(&ds, buf + i, 0, size)) {
						rz_cons_printf("hex length=%d delta=%d\n", size, delta);
						rz_core_print_hexdump(core, at, buf + idx, hexlen - delta, 16, 1, 1);
					} else {
						rz_cons_newline();
					}
				}
				continue;
			case RZ_META_TYPE_STRING:
				// rz_cons_printf (".string: %s\n", meta->str);
				i += meta_size;
				continue;
			case RZ_META_TYPE_FORMAT:
				// rz_cons_printf (".format : %s\n", meta->str);
				i += meta_size;
				continue;
			case RZ_META_TYPE_MAGIC:
				// rz_cons_printf (".magic : %s\n", meta->str);
				i += meta_size;
				continue;
			default:
				break;
			}
		}
		rz_asm_set_pc(core->rasm, address + i);
		ret = rz_asm_disassemble(core->rasm, &asmop, buf + addrbytes * i,
			nb_bytes - addrbytes * i);
		if (midflags || midbb) {
			RzDisasmState ds = {
				.oplen = ret,
				.at = address + i,
				.midflags = midflags
			};
			int skip_bytes_flag = 0, skip_bytes_bb = 0;
			skip_bytes_flag = handleMidFlags(core, &ds, true);
			if (midbb) {
				skip_bytes_bb = handleMidBB(core, &ds);
			}
			if (skip_bytes_flag && midflags > RZ_MIDFLAGS_SHOW) {
				asmop.size = ret = skip_bytes_flag;
			}
			if (skip_bytes_bb && skip_bytes_bb < ret) {
				asmop.size = ret = skip_bytes_bb;
			}
		}
		if (fmt == 'C') {
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset + i);
			if (comment) {
				rz_cons_printf("0x%08" PFMT64x " %s\n", core->offset + i, comment);
			}
			i += ret;
			continue;
		}
		// rz_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ret < 1) {
			err = 1;
			ret = asmop.size;
			if (ret < 1) {
				ret = 1;
			}
			if (show_bytes) {
				rz_cons_printf("%18s%02x  ", "", buf[i]);
			}
			rz_cons_println("invalid"); // ???");
		} else {
			if (show_bytes) {
				char *op_hex = rz_asm_op_get_hex(&asmop);
				rz_cons_printf("%20s  ", op_hex);
				free(op_hex);
			}
			ret = asmop.size;
			if (!asm_instr) {
				rz_cons_newline();
			} else if (!asm_immtrim && (decode || esil)) {
				RzAnalysisOp analysis_op;
				char *tmpopstr, *opstr = NULL;
				rz_analysis_op_init(&analysis_op);
				rz_analysis_op(core->analysis, &analysis_op, address + i,
					buf + addrbytes * i, nb_bytes - addrbytes * i, RZ_ANALYSIS_OP_MASK_ALL);
				tmpopstr = rz_analysis_op_to_string(core->analysis, &analysis_op);
				if (fmt == 'e') { // pie
					char *esil = (RZ_STRBUF_SAFEGET(&analysis_op.esil));
					rz_cons_println(esil);
				} else {
					if (decode) {
						opstr = tmpopstr ? tmpopstr : rz_asm_op_get_asm(&(asmop));
					} else if (esil) {
						opstr = (RZ_STRBUF_SAFEGET(&analysis_op.esil));
					}
					if (asm_immtrim) {
						rz_parse_immtrim(opstr);
					}
					rz_cons_println(opstr);
				}
				rz_analysis_op_fini(&analysis_op);
			} else {
				char opstr[128] = {
					0
				};
				char *asm_str = rz_asm_op_get_asm(&asmop);
				if (asm_ucase) {
					rz_str_case(asm_str, 1);
				}
				if (asm_immtrim) {
					rz_parse_immtrim(asm_str);
				}
				if (subnames) {
					RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, at);
					rz_parse_filter(core->parser, at, core->flags, hint,
						asm_str, opstr, sizeof(opstr) - 1, core->print->big_endian);
					rz_analysis_hint_free(hint);
					asm_str = (char *)&opstr;
				}
				if (show_color) {
					RzAnalysisOp aop = { 0 };
					rz_analysis_op_init(&aop);
					rz_analysis_op(core->analysis, &aop, address + i,
						buf + addrbytes * i, nb_bytes - addrbytes * i, RZ_ANALYSIS_OP_MASK_BASIC);
					RzStrBuf *colored_asm, *bw_str = rz_strbuf_new(asm_str);
					RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
					colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asmop.asm_toks);
					rz_asm_parse_param_free(param);
					rz_cons_printf("%s" Color_RESET "\n", colored_asm ? rz_strbuf_get(colored_asm) : "");
					rz_strbuf_free(colored_asm);
					rz_analysis_op_fini(&aop);
				} else {
					rz_cons_println(asm_str);
				}
			}
		}
		i += ret;
	}
	rz_config_set_i(core->config, "asm.marks", asmmarks);
	rz_cons_break_pop();
	if (alloc_buf) {
		free(buf);
	}
	return err;
}

RZ_API int rz_core_disasm_pdi(RzCore *core, int nb_opcodes, int nb_bytes, int fmt) {
	int ret = -1;
	ut64 offset = rz_core_backward_offset(core, core->offset, &nb_opcodes, &nb_bytes);
	ret = rz_core_disasm_pdi_with_buf(core, offset, NULL, nb_opcodes, nb_bytes, fmt);
	return ret;
}

static bool read_ahead(RzIO *io, ut8 **buf, size_t *buf_sz, ut64 address, size_t offset_into_buf, size_t bytes_to_read) {
	if (offset_into_buf + bytes_to_read > *buf_sz) {
		const size_t new_sz = *buf_sz * 2;
		ut8 *tmp = realloc(*buf, new_sz);
		if (!tmp) {
			return false;
		}
		*buf_sz = new_sz;
		*buf = tmp;
	}
	return rz_io_read_at_mapped(io, address, *buf + offset_into_buf, bytes_to_read);
}

RZ_API int rz_core_disasm_pde(RzCore *core, int nb_opcodes, RzCmdStateOutput *state) {
	if (nb_opcodes < 1) {
		return 0;
	}
	RzReg *reg = core->analysis->reg;
	RzRegItem *pc = rz_reg_get(reg, "PC", RZ_REG_TYPE_ANY);
	if (!pc) {
		return -1;
	}
	rz_cmd_state_output_array_start(state);
	if (!core->analysis->esil) {
		rz_core_analysis_esil_reinit(core);
		if (!rz_config_get_b(core->config, "cfg.debug")) {
			rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
		}
	}
	RzAnalysisEsil *esil = core->analysis->esil;
	RzPVector ocache = core->io->cache;
	const int ocached = core->io->cached;
	if (ocache.v.a) {
		RzPVector *vec = rz_pvector_clone(&ocache);
		vec->v.free = NULL;
		vec->v.free_user = ocache.v.free_user;
		core->io->cache = *vec;
		free(vec);
	} else {
		rz_io_cache_init(core->io);
	}
	rz_reg_arena_push(reg);
	RzConfigHold *chold = rz_config_hold_new(core->config);
	rz_config_hold_i(chold, "io.cache", "asm.lines", NULL);
	rz_config_set_i(core->config, "io.cache", true);
	rz_config_set_i(core->config, "asm.lines", false);
	const char *strip = rz_config_get(core->config, "asm.strip");
	const int max_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	int min_op_size = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	min_op_size = min_op_size > 0 ? min_op_size : 1;
	const ut64 read_len = max_op_size > 0 ? max_op_size : 32;
	size_t buf_sz = 0x100, block_sz = 0, block_instr = 0;
	ut64 block_start = rz_reg_get_value(reg, pc);
	ut8 *buf = malloc(buf_sz);
	size_t i;
	for (i = 0; i < nb_opcodes; i++) {
		const ut64 op_addr = rz_reg_get_value(reg, pc);
		if (!read_ahead(core->io, &buf, &buf_sz, op_addr, block_sz, read_len)) {
			break;
		}
		RzAnalysisOp op = { 0 };
		rz_analysis_op_init(&op);
		int ret = rz_analysis_op(core->analysis, &op, op_addr, buf + block_sz, read_len, RZ_ANALYSIS_OP_MASK_ESIL);
		const bool invalid_instr = ret < 1 || op.size < 1 || op.type == RZ_ANALYSIS_OP_TYPE_ILL;
		bool end_of_block = false;
		switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK & ~RZ_ANALYSIS_OP_HINT_MASK) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_CALL:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_RET:
			end_of_block = true;
			break;
		}
		if (RZ_STR_ISNOTEMPTY(strip) && strstr(strip, rz_analysis_optype_to_string(op.type))) {
			i--;
		} else {
			if (invalid_instr) {
				block_sz += min_op_size;
			} else {
				block_sz += op.size;
			}
			if (invalid_instr || (i + 1 >= nb_opcodes)) {
				end_of_block = true;
			}
			block_instr++;
		}
		if (end_of_block) {
			if (op.delay) {
				const ut64 ops_to_read = RZ_MIN(op.delay, nb_opcodes - (i + 1));
				const ut64 bytes_to_read = ops_to_read * read_len;
				if (!read_ahead(core->io, &buf, &buf_sz, op_addr + op.size, block_sz, bytes_to_read)) {
					break;
				}
				block_instr += ops_to_read;
				block_sz += bytes_to_read;
				i += ops_to_read;
			}
			if (block_instr) {
				switch (state->mode) {
				case RZ_OUTPUT_MODE_JSON:
					rz_core_print_disasm_json(core, block_start, buf, block_sz, block_instr, state->d.pj);
					break;
				case RZ_OUTPUT_MODE_QUIET:
					rz_core_disasm_pdi_with_buf(core, block_start, buf, block_instr, block_sz, 0);
					break;
				case RZ_OUTPUT_MODE_QUIETEST:
					rz_core_print_disasm_instructions_with_buf(core, block_start, buf, block_sz, block_instr);
					break;
				default:
					rz_core_print_disasm(core, block_start, buf, block_sz, block_instr, state, NULL);
					break;
				}
			}
			block_sz = 0;
			block_instr = 0;
		}
		if (invalid_instr) {
			break;
		}
		rz_analysis_esil_set_pc(core->analysis->esil, op_addr);
		rz_reg_set_value(reg, pc, op_addr + op.size);
		const char *e = rz_strbuf_get(&op.esil);
		if (RZ_STR_ISNOTEMPTY(e)) {
			rz_analysis_esil_parse(esil, e);
		}
		rz_analysis_op_fini(&op);

		if (end_of_block) {
			block_start = rz_reg_get_value(reg, pc);
			rz_core_seek_arch_bits(core, block_start);
		}
	}

	rz_cmd_state_output_array_end(state);
	free(buf);
	rz_reg_arena_pop(reg);
	int len = rz_pvector_len(&ocache);
	if (rz_pvector_len(&core->io->cache) > len) {
		// TODO: Implement push/pop for IO.cache
		while (len > 0) {
			(void)rz_pvector_pop_front(&core->io->cache);
			len--;
		}
		core->io->cache.v.free = ocache.v.free;
	}
	rz_io_cache_fini(core->io);
	core->io->cache = ocache;
	rz_skyline_clear(&core->io->cache_skyline);
	void **it;
	rz_pvector_foreach (&ocache, it) {
		RzIOCache *c = (RzIOCache *)*it;
		rz_skyline_add(&core->io->cache_skyline, c->itv, c);
	}
	core->io->cached = ocached;
	rz_config_hold_restore(chold);
	rz_config_hold_free(chold);
	return i;
}

RZ_API bool rz_core_print_function_disasm_json(RzCore *core, RzAnalysisFunction *fcn, PJ *pj) {
	RzAnalysisBlock *b;
	void **locs_it = NULL;
	ut32 fcn_size = rz_analysis_function_realsize(fcn);
	const char *orig_bb_middle = rz_config_get(core->config, "asm.bb.middle");
	rz_config_set_i(core->config, "asm.bb.middle", false);
	pj_o(pj);
	pj_ks(pj, "name", fcn->name);
	pj_kn(pj, "size", fcn_size);
	pj_kn(pj, "addr", fcn->addr);
	pj_k(pj, "ops");
	pj_a(pj);
	rz_pvector_sort(fcn->bbs, bb_cmpaddr, NULL);
	rz_pvector_foreach (fcn->bbs, locs_it) {
		b = (RzAnalysisBlock *)*locs_it;
		ut8 *buf = malloc(b->size);
		if (buf) {
			rz_io_read_at(core->io, b->addr, buf, b->size);
			rz_core_print_disasm_json(core, b->addr, buf, b->size, 0, pj);
			free(buf);
		} else {
			RZ_LOG_ERROR("core: cannot allocate %" PFMT64u " byte(s)\n", b->size);
			return false;
		}
	}
	pj_end(pj);
	pj_end(pj);
	rz_config_set(core->config, "asm.bb.middle", orig_bb_middle);
	return true;
}

/**
 * \brief Returns a disassembly of one instruction
 *
 * It returns disassembly on one instruction with additional output changes:
 * function local variables subsitution, PC-relative addressing subsitution,
 * analysis hints affecting the disassembly output, optional colors.
 *
 * \param core RzCore instance
 * \param addr An address of the instruction
 * \param reladdr An address to substitute PC-relative expressions in disasm (`asm.sub.rel` config)
 * \param fcn A function where the instruction located for local variables substitution (optional)
 * \param color To toggle color escape sequences in the output
 * */
RZ_API RZ_OWN char *rz_core_disasm_instruction(RzCore *core, ut64 addr, ut64 reladdr, RZ_NULLABLE RzAnalysisFunction *fcn, bool color) {
	rz_return_val_if_fail(core, NULL);
	int has_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	char str[512];
	const int size = 12;
	ut8 buf[12];
	RzAsmOp asmop = { 0 };
	char *buf_asm = NULL;
	bool asm_subvar = rz_config_get_i(core->config, "asm.sub.var");
	core->parser->pseudo = rz_config_get_i(core->config, "asm.pseudo");
	core->parser->subrel = rz_config_get_i(core->config, "asm.sub.rel");
	core->parser->localvar_only = rz_config_get_i(core->config, "asm.sub.varonly");

	if (core->parser->subrel) {
		core->parser->subrel_addr = reladdr;
	}
	rz_io_read_at(core->io, addr, buf, size);
	rz_asm_set_pc(core->rasm, addr);
	// use core binding to set asm.bits correctly based on the addr
	// this is because of the hassle of arm/thumb
	rz_core_seek_arch_bits(core, addr);
	rz_asm_disassemble(core->rasm, &asmop, buf, size);
	int ba_len = rz_strbuf_length(&asmop.buf_asm) + 128;
	char *ba = malloc(ba_len);
	strcpy(ba, rz_strbuf_get(&asmop.buf_asm));
	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	rz_analysis_op(core->analysis, &op, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
	if (asm_subvar) {
		rz_parse_subvar(core->parser, fcn, &op,
			ba, ba, sizeof(asmop.buf_asm));
		rz_analysis_op_fini(&op);
	}
	RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, addr);
	rz_parse_filter(core->parser, addr, core->flags, hint,
		ba, str, sizeof(str), core->print->big_endian);
	rz_analysis_hint_free(hint);
	rz_asm_op_set_asm(&asmop, ba);
	free(ba);
	if (color && has_color) {
		RzStrBuf *colored_asm, *bw_str = rz_strbuf_new(str);
		RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, op.type);
		colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asmop.asm_toks);
		rz_strbuf_free(bw_str);
		rz_asm_parse_param_free(param);
		return colored_asm ? rz_strbuf_drain(colored_asm) : NULL;
	} else {
		buf_asm = rz_str_dup(str);
	}
	return buf_asm;
}

RZ_API void rz_core_disasm_op_free(RzCoreDisasmOp *x) {
	if (!x) {
		return;
	}
	free(x->assembly);
	free(x->assembly_colored);
	free(x->hex);
	free(x);
}

/**
 * \brief Disassemble all possible opcodes (byte per byte) at \p addr
 */
RZ_API RZ_OWN RzPVector /*<RzCoreDisasmOp *>*/ *rz_core_disasm_all_possible_opcodes(RZ_NONNULL RzCore *core, RZ_NONNULL ut8 *buffer, ut64 addr, ut64 n_bytes) {
	rz_return_val_if_fail(core && buffer, NULL);
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_core_disasm_op_free);
	if (!vec) {
		return NULL;
	}
	rz_pvector_reserve(vec, n_bytes);

	for (ut64 position = 0; position < n_bytes && !rz_cons_is_breaked(); position++) {
		ut64 offset = addr + position;
		ut8 *ptr = buffer + position;
		int length = (int)(n_bytes - position);
		rz_asm_set_pc(core->rasm, offset);

		RzCoreDisasmOp *op = RZ_NEW0(RzCoreDisasmOp);
		if (!op) {
			break;
		}
		rz_pvector_push(vec, op);
		op->offset = offset;
		RzAsmOp asm_op = { 0 };
		op->size = rz_asm_disassemble(core->rasm, &asm_op, ptr, length);
		op->hex = rz_hex_bin2strdup(ptr, RZ_MAX(op->size, 1));
		op->assembly = strdup(op->size > 0 ? rz_asm_op_get_asm(&asm_op) : "illegal");

		RzAnalysisOp aop = { 0 };
		rz_analysis_op_init(&aop);
		rz_analysis_op(core->analysis, &aop, offset, ptr, length, RZ_ANALYSIS_OP_MASK_ALL);
		RzStrBuf *bw_str = rz_strbuf_new(op->assembly);
		RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
		RzStrBuf *colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asm_op.asm_toks);
		rz_asm_op_fini(&asm_op);
		rz_strbuf_free(bw_str);
		rz_asm_parse_param_free(param);
		op->assembly_colored = colored_asm ? rz_strbuf_drain(colored_asm) : NULL;
		rz_analysis_op_fini(&aop);
	}
	return vec;
}
