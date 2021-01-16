// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_debug.h"
#include "rz_io.h"

static const char *help_msg_s[] = {
	"Usage: s", "", " # Help for the seek commands. See ?$? to see all variables",
	"s", "", "Print current address",
	"s.", "hexoff", "Seek honoring a base from core->offset",
	"s:", "pad", "Print current address with N padded zeros (defaults to 8)",
	"s", " addr", "Seek to address",
	"s-", "", "Undo seek",
	"s-*", "", "Reset undo seek history",
	"s-", " n", "Seek n bytes backward",
	"s--", "[n]", "Seek blocksize bytes backward (/=n)",
	"s+", "", "Redo seek",
	"s+", " n", "Seek n bytes forward",
	"s++", "[n]", "Seek blocksize bytes forward (/=n)",
	"s[j*=!]", "", "List undo seek history (JSON, =list, *rz, !=names, s==)",
	"s/", " DATA", "Search for next occurrence of 'DATA'",
	"s/x", " 9091", "Search for next occurrence of \\x90\\x91",
	"sa", " [[+-]a] [asz]", "Seek asz (or bsize) aligned to addr",
	"sb", "", "Seek aligned to bb start",
	"sC", "[?] string", "Seek to comment matching given string",
	"sf", "", "Seek to next function (f->addr+f->size)",
	"sf", " function", "Seek to address of specified function",
	"sf.", "", "Seek to the beginning of current function",
	"sg/sG", "", "Seek begin (sg) or end (sG) of section or file",
	"sn/sp", " ([nkey])", "Seek to next/prev location, as specified by scr.nkey",
	"so", " [N]", "Seek to N next opcode(s)",
	"sr", " pc", "Seek to register",
	"ss", "", "Seek silently (without adding an entry to the seek history)",
	// "sp [page]  seek page N (page = block)",
	NULL
};

static const char *help_msg_sC[] = {
	"Usage:", "sC", "Comment grep",
	"sC", "*", "List all comments",
	"sC", " str", "Seek to the first comment matching 'str'",
	NULL
};

static const char *help_msg_ss[] = {
	"Usage: ss", "", " # Seek silently (not recorded in the seek history)",
	"s?", "", "Works with all s subcommands",
	NULL
};

static void printPadded(RzCore *core, int pad) {
	if (pad < 1) {
		pad = 8;
	}
	char *fmt = rz_str_newf ("0x%%0%d" PFMT64x, pad);
	char *off = rz_str_newf (fmt, core->offset);
	rz_cons_printf ("%s\n", off);
	free (off);
	free (fmt);
}

static void seek_to_register(RzCore *core, const char *input, bool is_silent) {
	ut64 off;
	if (core->bin->is_debugger) {
		off = rz_debug_reg_get (core->dbg, input);
		rz_core_seek_opt (core, off, true, !is_silent);
	} else {
		RzReg *orig = core->dbg->reg;
		core->dbg->reg = core->analysis->reg;
		off = rz_debug_reg_get (core->dbg, input);
		core->dbg->reg = orig;
		rz_core_seek_opt (core, off, true, !is_silent);
	}
}

static int cmd_sort(void *data, const char *input) { // "sort"
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg = rz_str_trim_head_ro (arg + 1);
	}
	switch (*input) {
	case '?': // "sort?"
		eprintf ("Usage: sort # sort the contents of the file\n");
		break;
	default: // "ls"
		if (!arg) {
			arg = "";
		}
		char *res = rz_syscmd_sort (arg);
		if (res) {
			rz_cons_print (res);
			free (res);
		}
		break;
	}
	return 0;
}

static int cmd_seek_opcode_backward(RzCore *core, int numinstr, bool silent) {
	int i, val = 0;
	// N previous instructions
	ut64 addr = core->offset;
	int ret = 0;
	if (rz_core_prevop_addr (core, core->offset, numinstr, &addr)) {
		ret = core->offset - addr;
	} else {
#if 0
		// core_asm_bwdis_len is really buggy and we should remove it. seems like prevop_addr
		// works as expected, because is the one used from visual
		ret = rz_core_asm_bwdis_len (core, &instr_len, &addr, numinstr);
#endif
		addr = core->offset;
		const int mininstrsize = rz_analysis_archinfo (core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		for (i = 0; i < numinstr; i++) {
			ut64 prev_addr = rz_core_prevop_addr_force (core, addr, 1);
			if (prev_addr == UT64_MAX) {
				prev_addr = addr - mininstrsize;
			}
			if (prev_addr == UT64_MAX || prev_addr >= core->offset) {
				break;
			}
			RzAsmOp op = {0};
			rz_core_seek (core, prev_addr, true);
			rz_asm_disassemble (core->rasm, &op, core->block, 32);
			if (op.size < mininstrsize) {
				op.size = mininstrsize;
			}
			val += op.size;
			addr = prev_addr;
		}
	}
	rz_core_seek_opt (core, addr, true, !silent);
	val += ret;
	return val;
}

static int cmd_seek_opcode_forward (RzCore *core, int n, bool silent) {
	// N forward instructions
	int i, ret, val = 0;
	if (!silent) {
		rz_core_seek_save (core);
	}
	for (val = i = 0; i < n; i++) {
		RzAnalysisOp op;
		ret = rz_analysis_op (core->analysis, &op, core->offset, core->block,
			core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC);
		if (ret < 1) {
			ret = 1;
		}
		rz_core_seek_delta (core, ret, false);
		rz_analysis_op_fini (&op);
		val += ret;
	}
	return val;
}

static void cmd_seek_opcode(RzCore *core, const char *input, bool silent) {
	if (input[0] == '?') {
		eprintf ("Usage: so [-][n]\n");
		return;
	}
	if (!strcmp (input, "-")) {
		input = "-1";
	}
	int n = rz_num_math (core->num, input);
	if (n == 0) {
		n = 1;
	}
	int val = (n < 0)
		? cmd_seek_opcode_backward (core, -n, silent)
		: cmd_seek_opcode_forward (core, n, silent);
	core->num->value = val;
}

RZ_IPI int rz_cmd_seek(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	char *cmd, *p;
	ut64 off = core->offset;

	if (!*input) {
		rz_cons_printf ("0x%"PFMT64x "\n", core->offset);
		return 0;
	}
	char *ptr;
	if ((ptr = strstr (input, "+.")) != NULL) {
		char *dup = strdup (input);
		dup[ptr - input] = '\x00';
		off = rz_num_math (core->num, dup + 1);
		core->offset = off;
		free (dup);
	}
	const char *inputnum = strchr (input, ' ');
	if (rz_str_cmp (input, "ort", 3)) {					// hack to handle Invalid Argument for sort
		const char *u_num = inputnum? inputnum + 1: input + 1;
		off = rz_num_math (core->num, u_num);
		if (*u_num == '-') {
			off = -(st64)off;
		}
	}
#if 1
//	int sign = 1;
	if (input[0] == ' ') {
		switch (input[1]) {
		case '-':
//			sign = -1;
			/* pass thru */
		case '+':
			input++;
			break;
		}
	}
#endif
	bool silent = false;
	if (*input == 's') {
		silent = true;
		input++;
		if (*input == '?') {
			rz_core_cmd_help (core, help_msg_ss);
			return 0;
		}
	}

	switch (*input) {
	case 'r': // "sr"
		if (input[1] && input[2]) {
			seek_to_register (core, input + 2, silent);
		} else {
			eprintf ("|Usage| 'sr PC' seek to program counter register\n");
		}
		break;
	case 'C': // "sC"
		if (input[1] == '*') { // "sC*"
			rz_core_cmd0 (core, "C*~^\"CC");
		} else if (input[1] == ' ') {
			RzIntervalTreeIter it;
			RzAnalysisMetaItem *meta;
			bool seeked = false;
			rz_interval_tree_foreach (&core->analysis->meta, it, meta) {
				if (meta->type == RZ_META_TYPE_COMMENT && !strcmp (meta->str, input + 2)) {
					rz_core_seek_opt (core, off, true, !silent);
					seeked = true;
					break;
				}
			}
			if (!seeked) {
				eprintf ("No matching comment.\n");
			}
		} else {
			rz_core_cmd_help (core, help_msg_sC);
		}
		break;
	case ' ': // "s "
	{
		ut64 addr = rz_num_math (core->num, input + 1);
		if (core->num->nc.errors) {
			if (rz_cons_singleton ()->context->is_interactive) {
				eprintf ("Cannot seek to unknown address '%s'\n", core->num->nc.calc_buf);
			}
			break;
		}
		rz_core_seek_opt (core, addr, true, !silent);
	}
	break;
	case '/': // "s/"
	{
		const char *pfx = rz_config_get (core->config, "search.prefix");
		const ut64 saved_from = rz_config_get_i (core->config, "search.from");
		const ut64 saved_maxhits = rz_config_get_i (core->config, "search.maxhits");
// kwidx cfg var is ignored
		int kwidx = core->search->n_kws; // (int)rz_config_get_i (core->config, "search.kwidx")-1;
		if (kwidx < 0) {
			kwidx = 0;
		}
		switch (input[1]) {
		case ' ':
		case 'v':
		case 'V':
		case 'w':
		case 'W':
		case 'z':
		case 'm':
		case 'c':
		case 'A':
		case 'e':
		case 'E':
		case 'i':
		case 'R':
		case 'r':
		case '/':
		case 'x':
			rz_config_set_i (core->config, "search.from", core->offset + 1);
			rz_config_set_i (core->config, "search.maxhits", 1);
			rz_core_cmdf (core, "s+1; %s; s-1; s %s%d_0; f-%s%d_0",
				input, pfx, kwidx, pfx, kwidx);
			rz_config_set_i (core->config, "search.from", saved_from);
			rz_config_set_i (core->config, "search.maxhits", saved_maxhits);
			break;
		case '?':
			eprintf ("Usage: s/.. arg.\n");
			rz_cons_printf ("/?\n");
			break;
		default:
			eprintf ("unknown search method\n");
			break;
		}
	}
	break;
	case '.': // "s." "s.."
		for (input++; *input == '.'; input++) {
			;
		}
		rz_core_seek_base (core, input, !silent);
		break;
	case 'j':  // "sj"
	case '*': // "s*"
	case '=': // "s="
	case '!': // "s!"
		{
			int mode = input[0];
			RzList *list = rz_core_seek_list (core);
			RzListIter *iter;
			RzCoreSeekItem *undo;
			PJ *pj = NULL;
			if (mode == 'j') {
				pj = rz_core_pj_new (core);
				pj_a (pj);
			}
			bool current_met = false;
			rz_list_foreach (list, iter, undo) {
				RzFlagItem *f = rz_flag_get_at (core->flags, undo->offset, true);
				char *name = NULL;
				if (f) {
					if (f->offset != undo->offset) {
						name = rz_str_newf ("%s+%" PFMT64d, f->name, undo->offset - f->offset);
					} else {
						name = strdup (f->name);
					}
				}
				current_met |= undo->is_current;
				if (mode == 'j') {
					pj_o (pj);
					pj_kn (pj, "offset", undo->offset);
					pj_kn (pj, "cursor", undo->cursor);
					if (name) {
						pj_ks (pj, "name", name);
					}
					pj_kb (pj, "current", undo->is_current);
					pj_end (pj);
				} else if (mode == '=') {
					if (!name) {
						name = rz_str_newf ("0x%" PFMT64x, undo->offset);
					}
					const char *sep = "";
					if (iter->n && current_met) {
						sep = " < ";
					} else if (iter->n) {
						sep = " > ";
					} else {
						sep = "\n";
					}
					rz_cons_printf ("%s%s", name, sep);
				} else if (mode == '!') {
					const char *comment = "";
					if (undo->is_current) {
						comment = " # current seek";
					} else if (current_met) {
						comment = " # redo";
					}
					rz_cons_printf ("0x%" PFMT64x " %s%s\n", undo->offset, name? name: "", comment);
				} else if (mode == '*') {
					if (undo->is_current) {
						rz_cons_printf ("# Current seek @ 0x%" PFMT64x "\n", undo->offset);
					} else if (current_met) {
						rz_cons_printf ("f redo_%d @ 0x%" PFMT64x "\n", RZ_ABS (undo->idx - 1), undo->offset);
					} else {
						rz_cons_printf ("f undo_%d @ 0x%" PFMT64x "\n", RZ_ABS (undo->idx + 1), undo->offset);
					}
				}
				free (name);
			}
			if (mode == 'j') {
				pj_end (pj);
				char *s = pj_drain (pj);
				rz_cons_printf ("%s\n", s);
				free (s);
			}
			break;
		}
	case '+': // "s+"
		if (input[1] != '\0') {
			int delta = off;
			if (input[1] == '+') {
				delta = core->blocksize;
				int mult = rz_num_math (core->num, input + 2);
				if (mult > 0) {
					delta /= mult;
				}
			}
			rz_core_seek_delta (core, delta, !silent);
		} else {
			rz_core_seek_redo (core);
		}
		break;
	case '-': // "s-"
		switch (input[1]) {
		case '*': // "s-*"
			rz_core_seek_reset (core);
			break;
		case 0: // "s-"
			rz_core_seek_undo (core);
			break;
		case '-': // "s--"
		default:
			{
				int delta = -off;
				if (input[1] == '-') {
					delta = -core->blocksize;
					int mult = rz_num_math (core->num, input + 2);
					if (mult > 0) {
						delta /= mult;
					}
				}
				rz_core_seek_delta (core, delta, !silent);
			}
		break;
		}
		break;
	case 'n': // "sn"
		{
			const char *nkey = (input[1] == ' ')
				? input + 2
				: rz_config_get (core->config, "scr.nkey");
			rz_core_seek_next (core, nkey, !silent);
		}
		break;
	case 'p': // "sp"
		{
			const char *nkey = (input[1] == ' ')
				? input + 2
				: rz_config_get (core->config, "scr.nkey");
			rz_core_seek_prev (core, nkey, !silent);
		}
		break;
	case 'a': // "sa"
		off = core->blocksize;
		if (input[1] && input[2]) {
			cmd = strdup (input);
			p = strchr (cmd + 2, ' ');
			if (p) {
				off = rz_num_math (core->num, p + 1);;
				*p = '\0';
			}
			cmd[0] = 's';
			// perform real seek if provided
			rz_cmd_call (core->rcmd, cmd);
			free (cmd);
		}
		rz_core_seek_align (core, off, !silent);
		break;
	case 'b': // "sb"
		if (off == 0) {
			off = core->offset;
		}
		rz_core_seek_analysis_bb (core, off, !silent);
		break;
	case 'f': { // "sf"
		RzAnalysisFunction *fcn;
		switch (input[1]) {
		case '\0': // "sf"
			fcn = rz_analysis_get_fcn_in (core->analysis, core->offset, 0);
			if (fcn) {
				rz_core_seek_opt (core, rz_analysis_function_max_addr (fcn), true, !silent);
			}
			break;
		case ' ': // "sf "
			fcn = rz_analysis_get_function_byname (core->analysis, input + 2);
			if (fcn) {
				rz_core_seek_opt (core, fcn->addr, true, !silent);
			}
			break;
		case '.': // "sf."
			fcn = rz_analysis_get_fcn_in (core->analysis, core->offset, 0);
			if (fcn) {
				rz_core_seek_opt (core, fcn->addr, true, !silent);
			}
			break;
		}
		break;
	}
	case 'o': // "so"
		switch (input[1]) {
		case 'r':
			if (input[2] == 't') {
				cmd_sort (core, input);
			} else {
				return -1;
			}
			break;
		case ' ':
		case '\0':
		case '+':
		case '-':
			cmd_seek_opcode (core, input + 1, silent);
			break;
		default:
			return -1;	// invalid command
		}
		break;
	case 'g': // "sg"
	{
		RzIOMap *map  = rz_io_map_get (core->io, core->offset);
		if (map) {
			rz_core_seek_opt (core, map->itv.addr, true, !silent);
		} else {
			rz_core_seek_opt (core, 0, true, !silent);
		}
	}
	break;
	case 'G': // "sG"
	{
		if (!core->file) {
			break;
		}
		RzIOMap *map = rz_io_map_get (core->io, core->offset);
		// XXX: this +2 is a hack. must fix gap between sections
		if (map) {
			rz_core_seek_opt (core, map->itv.addr + map->itv.size + 2, true, !silent);
		} else {
			rz_core_seek_opt (core, rz_io_fd_size (core->io, core->file->fd), true, !silent);
		}
	}
	break;
	case ':': // "s:"
		printPadded (core, atoi (input + 1));
		break;
	case '?': // "s?"
		rz_core_cmd_help (core, help_msg_s);
		break;
	default:
		{
			ut64 n = rz_num_math (core->num, input);
			if (n) {
				rz_core_seek_opt (core, n, true, !silent);
			}
		}
		break;
	}
	return 0;
}
