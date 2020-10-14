/* radare - LGPL - Copyright 2009-2020 - pancake */

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
	"sl", "[?] [+-]line", "Seek to line",
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

static const char *help_msg_sl[] = {
	"Usage:", "sl+ or sl- or slc", "",
	"sl", " [line]", "Seek to absolute line",
	"sl", "[+-][line]", "Seek to relative line",
	"slc", "", "Clear line cache",
	"sll", "", "Show total number of lines",
	"sleep", " [seconds]", "Sleep for an specific amount of time",
	NULL
};

static const char *help_msg_ss[] = {
	"Usage: ss", "", " # Seek silently (not recorded in the seek history)",
	"s?", "", "Works with all s subcommands",
	NULL
};

static void cmd_seek_init(RzCore *core, RzCmdDesc *parent) {
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, s);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, sC);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, sl);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, ss);
}

static void __init_seek_line(RzCore *core) {
	ut64 from, to;

	rz_config_bump (core->config, "lines.to");
	from = rz_config_get_i (core->config, "lines.from");
	const char *to_str = rz_config_get (core->config, "lines.to");
	to = rz_num_math (core->num, (to_str && *to_str) ? to_str : "$s");
	if (rz_core_lines_initcache (core, from, to) == -1) {
		eprintf ("ERROR: \"lines.from\" and \"lines.to\" must be set\n");
	}
}

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

static void __get_current_line(RzCore *core) {
	if (core->print->lines_cache_sz > 0) {
		int curr = rz_util_lines_getline (core->print->lines_cache, core->print->lines_cache_sz, core->offset);
		rz_cons_printf ("%d\n", curr);
	}
}

static void __seek_line_absolute(RzCore *core, int numline) {
	if (numline < 1 || numline > core->print->lines_cache_sz - 1) {
		eprintf ("ERROR: Line must be between 1 and %d\n", core->print->lines_cache_sz - 1);
	} else {
		rz_core_seek (core, core->print->lines_cache[numline - 1], true);
	}
}

static void __seek_line_relative(RzCore *core, int numlines) {
	int curr = rz_util_lines_getline (core->print->lines_cache, core->print->lines_cache_sz, core->offset);
	if (numlines > 0 && curr + numlines >= core->print->lines_cache_sz - 1) {
		eprintf ("ERROR: Line must be < %d\n", core->print->lines_cache_sz - 1);
	} else if (numlines < 0 && curr + numlines < 1) {
		eprintf ("ERROR: Line must be > 1\n");
	} else {
		rz_core_seek (core, core->print->lines_cache[curr + numlines - 1], true);
	}
}

static void __clean_lines_cache(RzCore *core) {
	core->print->lines_cache_sz = -1;
	RZ_FREE (core->print->lines_cache);
}

RZ_API int rz_core_lines_currline(RzCore *core) {  // make priv8 again
	int imin = 0;
	int imax = core->print->lines_cache_sz;
	int imid = 0;

	while (imin <= imax) {
		imid = imin + ((imax - imin) / 2);
		if (core->print->lines_cache[imid] == core->offset) {
			return imid;
		} else if (core->print->lines_cache[imid] < core->offset) {
			imin = imid + 1;
		} else {
			imax = imid - 1;
		}
	}
	return imin;
}

RZ_API int rz_core_lines_initcache(RzCore *core, ut64 start_addr, ut64 end_addr) {
	int i, bsz = core->blocksize;
	ut64 off = start_addr;
	ut64 baddr;
	if (start_addr == UT64_MAX || end_addr == UT64_MAX) {
		return -1;
	}

	free (core->print->lines_cache);
	core->print->lines_cache = RZ_NEWS0 (ut64, bsz);
	if (!core->print->lines_cache) {
		return -1;
	}

	baddr = rz_config_get_i (core->config, "bin.baddr");

	int line_count = start_addr? 0: 1;
	core->print->lines_cache[0] = start_addr? 0: baddr;
	char *buf = malloc (bsz);
	if (!buf) {
		return -1;
	}
	rz_cons_break_push (NULL, NULL);
	while (off < end_addr) {
		if (rz_cons_is_breaked ()) {
			break;
		}
		rz_io_read_at (core->io, off, (ut8 *) buf, bsz);
		for (i = 0; i < bsz; i++) {
			if (buf[i] != '\n') {
				continue;
			}
			if ((line_count + 1) >= bsz) {
				break;
			}
			core->print->lines_cache[line_count] = start_addr? off + i + 1: off + i + 1 + baddr;
			line_count++;
			if (line_count % bsz == 0) {
				ut64 *tmp = realloc (core->print->lines_cache,
					(line_count + bsz) * sizeof (ut64));
				if (tmp) {
					core->print->lines_cache = tmp;
				} else {
					RZ_FREE (core->print->lines_cache);
					goto beach;
				}
			}
		}
		off += bsz;
	}
	free (buf);
	rz_cons_break_pop ();
	return line_count;
beach:
	free (buf);
	rz_cons_break_pop ();
	return -1;
}

static void seek_to_register(RzCore *core, const char *input, bool is_silent) {
	ut64 off;
	if (core->bin->is_debugger) {
		off = rz_debug_reg_get (core->dbg, input);
		if (!is_silent) {
			rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
		}
		rz_core_seek (core, off, true);
	} else {
		RzReg *orig = core->dbg->reg;
		core->dbg->reg = core->anal->reg;
		off = rz_debug_reg_get (core->dbg, input);
		core->dbg->reg = orig;
		if (!is_silent) {
			rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
		}
		rz_core_seek (core, off, true);
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

static int cmd_seek_opcode_backward(RzCore *core, int numinstr) {
	int i, val = 0;
	// N previous instructions
	ut64 addr = core->offset;
	int ret = 0;
	if (rz_core_prevop_addr (core, core->offset, numinstr, &addr)) {
		ret = core->offset - addr;
	} else {
#if 0
		// core_asm_bwdis_len is buggy as hell we should kill it. seems like prevop_addr
		// works as expected, because is the one used from visual
		ret = rz_core_asm_bwdis_len (core, &instr_len, &addr, numinstr);
#endif
		addr = core->offset;
		const int mininstrsize = rz_anal_archinfo (core->anal, RZ_ANAL_ARCHINFO_MIN_OP_SIZE);
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
	rz_core_seek (core, addr, true);
	val += ret;
	return val;
}

static int cmd_seek_opcode_forward (RzCore *core, int n) {
	// N forward instructions
	int i, ret, val = 0;
	for (val = i = 0; i < n; i++) {
		RzAnalOp op;
		ret = rz_anal_op (core->anal, &op, core->offset, core->block,
			core->blocksize, RZ_ANAL_OP_MASK_BASIC);
		if (ret < 1) {
			ret = 1;
		}
		rz_core_seek_delta (core, ret);
		rz_anal_op_fini (&op);
		val += ret;
	}
	return val;
}

static void cmd_seek_opcode(RzCore *core, const char *input) {
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
		? cmd_seek_opcode_backward (core, -n)
		: cmd_seek_opcode_forward (core, n);
	core->num->value = val;
}

static int cmd_seek(void *data, const char *input) {
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
			RIntervalTreeIter it;
			RzAnalMetaItem *meta;
			bool seeked = false;
			rz_interval_tree_foreach (&core->anal->meta, it, meta) {
				if (meta->type == RZ_META_TYPE_COMMENT && !strcmp (meta->str, input + 2)) {
					if (!silent) {
						rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
					}
					rz_core_seek (core, off, true);
					rz_core_block_read (core);
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
		if (!silent) {
			rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
		}
		rz_core_seek (core, addr, true);
		rz_core_block_read (core);
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
				input, pfx, kwidx, pfx, kwidx, pfx, kwidx);
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
		rz_core_seek_base (core, input);
		rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
		break;
	case 'j':  // "sj"
		{
			RzList /*<ut64 *>*/ *addrs = rz_list_newf (free);
			RzList /*<char *>*/ *names = rz_list_newf (free);
			RzList *list = rz_io_sundo_list (core->io, '!');
			ut64 lsz = 0;
			ut64 i;
			RzListIter *iter;
			RzIOUndos *undo;
			if (list) {
				rz_list_foreach (list, iter, undo) {
					char *name = NULL;

					RzFlagItem *f = rz_flag_get_at (core->flags, undo->off, true);
					if (f) {
						if (f->offset != undo->off) {
							name = rz_str_newf ("%s+%d", f->name,
									(int)(undo->off- f->offset));
						} else {
							name = strdup (f->name);
						}
					}
					if (!name) {
						name = strdup ("");
					}
					ut64 *val = malloc (sizeof (ut64));
					if (!val) {
						free (name);
						break;
					}
					*val = undo->off;
					rz_list_append (addrs, val);
					rz_list_append (names, strdup (name));
					lsz++;
					free (name);
				}
				rz_list_free (list);
			}
			PJ *pj = pj_new ();
			pj_a (pj);
			for (i = 0; i < lsz; i++) {
				ut64 *addr = rz_list_get_n (addrs, i);
				const char *name = rz_list_get_n (names, i);
				pj_o (pj);
				pj_kn (pj, "offset", *addr);
				if (name && *name) {
					pj_ks (pj, "name", name);
				}
				if (core->io->undo.undos == i) {
					pj_kb (pj, "current", true);
				}
				pj_end (pj);
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			rz_cons_printf ("%s\n", s);
			free (s);
			rz_list_free (addrs);
			rz_list_free (names);
		}
		break;
	case '*': // "s*"
	case '=': // "s="
	case '!': // "s!"
		{
			char mode = input[0];
			if (input[1] == '=') {
				mode = 0;
			}
			RzList *list = rz_io_sundo_list (core->io, mode);
			if (list) {
				RzListIter *iter;
				RzIOUndos *undo;
				rz_list_foreach (list, iter, undo) {
					char *name = NULL;

					RzFlagItem *f = rz_flag_get_at (core->flags, undo->off, true);
					if (f) {
						if (f->offset != undo->off) {
							name = rz_str_newf ("%s + %d\n", f->name,
									(int)(undo->off - f->offset));
						} else {
							name = strdup (f->name);
						}
					}
					if (mode) {
						rz_cons_printf ("0x%"PFMT64x" %s\n", undo->off, name? name: "");
					} else {
						if (!name) {
							name = rz_str_newf ("0x%"PFMT64x, undo->off);
						}
						rz_cons_printf ("%s%s", name, iter->n? " > ":"");
					}
					free (name);
				}
				rz_list_free (list);
				if (!mode) {
					rz_cons_newline ();
				}
			}
		}
		break;
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
			// int delta = (input[1] == '+')? core->blocksize: off;
			if (!silent) {
				rz_io_sundo_push (core->io, core->offset,
					rz_print_get_cursor (core->print));
			}
			rz_core_seek_delta (core, delta);
			rz_core_block_read (core);
		} else {
			RzIOUndos *undo = rz_io_sundo_redo (core->io);
			if (undo) {
				rz_core_seek (core, undo->off, false);
				rz_core_block_read (core);
			}
		}
		break;
	case '-': // "s-"
		switch (input[1]) {
		case '*': // "s-*"
			rz_io_sundo_reset (core->io);
			break;
		case 0: // "s-"
			{
				RzIOUndos *undo = rz_io_sundo (core->io, core->offset);
				if (undo) {
					rz_core_seek (core, undo->off, false);
					rz_core_block_read (core);
				}
			}
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
				if (!silent) {
					rz_io_sundo_push (core->io, core->offset,
							rz_print_get_cursor (core->print));
				}
				rz_core_seek_delta (core, delta);
				rz_core_block_read (core);
			}
		break;
		}
		break;
	case 'n': // "sn"
		{
			if (!silent) {
				rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
			}
			const char *nkey = (input[1] == ' ')
				? input + 2
				: rz_config_get (core->config, "scr.nkey");
			rz_core_seek_next (core, nkey);
		}
		break;
	case 'p': // "sp"
		{
			if (!silent) {
				rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
			}
			const char *nkey = (input[1] == ' ')
				? input + 2
				: rz_config_get (core->config, "scr.nkey");
			rz_core_seek_previous (core, nkey);
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
		if (!silent) {
			rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
		}
		rz_core_seek_align (core, off, 0);
		break;
	case 'b': // "sb"
		if (off == 0) {
			off = core->offset;
		}
		if (!silent) {
			rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
		}
		rz_core_anal_bb_seek (core, off);
		break;
	case 'f': { // "sf"
		RzAnalFunction *fcn;
		switch (input[1]) {
		case '\0': // "sf"
			fcn = rz_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				rz_core_seek (core, rz_anal_function_max_addr (fcn), true);
			}
			break;
		case ' ': // "sf "
			fcn = rz_anal_get_function_byname (core->anal, input + 2);
			if (fcn) {
				rz_core_seek (core, fcn->addr, true);
			}
			break;
		case '.': // "sf."
			fcn = rz_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				rz_core_seek (core, fcn->addr, true);
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
			cmd_seek_opcode (core, input + 1);
			break;
		default:
			return -1;	// invalid command
		}
		break;
	case 'g': // "sg"
	{
		RzIOMap *map  = rz_io_map_get (core->io, core->offset);
		if (map) {
			rz_core_seek (core, map->itv.addr, true);
		} else {
			rz_core_seek (core, 0, true);
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
			rz_core_seek (core, map->itv.addr + map->itv.size + 2, true);
		} else {
			rz_core_seek (core, rz_io_fd_size (core->io, core->file->fd), true);
		}
	}
	break;
	case 'l': // "sl"
	{
		int sl_arg = rz_num_math (core->num, input + 1);
		switch (input[1]) {
		case 'e': // "sleep"
			{
				const char *arg = strchr (input, ' ');
				if (arg) {
					void *bed = rz_cons_sleep_begin ();
					rz_sys_sleep (atoi (arg + 1));
					rz_cons_sleep_end (bed);
				} else {
					eprintf ("Usage: sleep [seconds]\n");
				}
			}
			break;
		case '\0': // "sl"
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			__get_current_line (core);
			break;
		case ' ': // "sl "
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			__seek_line_absolute (core, sl_arg);
			break;
		case '+': // "sl+"
		case '-': // "sl-"
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			__seek_line_relative (core, sl_arg);
			break;
		case 'c': // "slc"
			__clean_lines_cache (core);
			break;
		case 'l': // "sll"
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			eprintf ("%d lines\n", core->print->lines_cache_sz - 1);
			break;
		case '?': // "sl?"
			rz_core_cmd_help (core, help_msg_sl);
			break;
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
				if (!silent) {
					rz_io_sundo_push (core->io, core->offset, rz_print_get_cursor (core->print));
				}
				rz_core_seek (core, n, true);
				rz_core_block_read (core);
			}
		}
		break;
	}
	return 0;
}
