// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_debug.h"
#include "rz_io.h"

static void printPadded(RzCore *core, int pad) {
	if (pad < 1) {
		pad = 8;
	}
	char *fmt = rz_str_newf("0x%%0%d" PFMT64x, pad);
	char *off = rz_str_newf(fmt, core->offset);
	rz_cons_printf("%s\n", off);
	free(off);
	free(fmt);
}

RZ_IPI bool rz_core_seek_to_register(RzCore *core, const char *regname, bool is_silent) {
	ut64 off = rz_core_reg_getv_by_role_or_name(core, regname);
	return rz_core_seek_opt(core, off, true, !is_silent);
}

RZ_IPI int rz_core_seek_opcode_backward(RzCore *core, int numinstr, bool silent) {
	int i, val = 0;
	// N previous instructions
	ut64 addr = core->offset;
	int ret = 0;
	if (rz_core_prevop_addr(core, core->offset, numinstr, &addr)) {
		ret = core->offset - addr;
	} else {
#if 0
		// core_asm_bwdis_len is really buggy and we should remove it. seems like prevop_addr
		// works as expected, because is the one used from visual
		ret = rz_core_asm_bwdis_len (core, &instr_len, &addr, numinstr);
#endif
		addr = core->offset;
		const int mininstrsize = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		for (i = 0; i < numinstr; i++) {
			ut64 prev_addr = rz_core_prevop_addr_force(core, addr, 1);
			if (prev_addr == UT64_MAX) {
				prev_addr = addr - mininstrsize;
			}
			if (prev_addr == UT64_MAX || prev_addr >= core->offset) {
				break;
			}
			RzAsmOp op = { 0 };
			rz_core_seek(core, prev_addr, true);
			rz_asm_disassemble(core->rasm, &op, core->block, 32);
			if (op.size < mininstrsize) {
				op.size = mininstrsize;
			}
			val += op.size;
			addr = prev_addr;
		}
	}
	rz_core_seek_opt(core, addr, true, !silent);
	val += ret;
	return val;
}

RZ_IPI int rz_core_seek_opcode_forward(RzCore *core, int n, bool silent) {
	// N forward instructions
	int i, ret, val = 0;
	if (!silent) {
		rz_core_seek_mark(core);
	}
	for (val = i = 0; i < n; i++) {
		RzAnalysisOp op;
		ret = rz_analysis_op(core->analysis, &op, core->offset, core->block,
			core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC);
		if (ret < 1) {
			ret = 1;
		}
		rz_core_seek_delta(core, ret, false);
		rz_analysis_op_fini(&op);
		val += ret;
	}
	rz_core_seek_save(core);
	return val;
}

RZ_IPI int rz_core_seek_opcode(RzCore *core, int n, bool silent) {
	int val = (n < 0)
		? rz_core_seek_opcode_backward(core, -n, silent)
		: rz_core_seek_opcode_forward(core, n, silent);
	core->num->value = val;
	return val;
}

static void cmd_seek_opcode(RzCore *core, const char *input, bool silent) {
	if (input[0] == '?') {
		eprintf("Usage: so [-][n]\n");
		return;
	}
	if (!strcmp(input, "-")) {
		input = "-1";
	}
	int n = rz_num_math(core->num, input);
	if (n == 0) {
		n = 1;
	}
	rz_core_seek_opcode(core, n, silent);
}

RZ_IPI int rz_seek_search(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	const char *pfx = rz_config_get(core->config, "search.prefix");
	const ut64 saved_from = rz_config_get_i(core->config, "search.from");
	const ut64 saved_maxhits = rz_config_get_i(core->config, "search.maxhits");
	int kwidx = core->search->n_kws; // (int)rz_config_get_i (core->config, "search.kwidx")-1;
	if (kwidx < 0) {
		kwidx = 0;
	}
	switch (input[0]) {
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
		rz_config_set_i(core->config, "search.from", core->offset + 1);
		rz_config_set_i(core->config, "search.maxhits", 1);
		rz_core_cmdf(core, "sd 1@e:cfg.seek.silent=true; /%s; sd -1@e:cfg.seek.silent=true; s %s%d_0; f- %s%d_0",
			input, pfx, kwidx, pfx, kwidx);
		rz_config_set_i(core->config, "search.from", saved_from);
		rz_config_set_i(core->config, "search.maxhits", saved_maxhits);
		break;
	case '?':
		eprintf("Usage: s/.. arg.\n");
		rz_cons_printf("/?\n");
		break;
	default:
		eprintf("unknown search method\n");
		break;
	}
	return 0;
}

static RzCmdStatus bool2cmdstatus(bool res) {
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_seek_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		rz_cons_printf("0x%" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_OK;
	}

	rz_core_seek_mark(core);

	// NOTE: hack to make it work with local function labels
	char *ptr;
	if ((ptr = strstr(argv[1], "+.")) != NULL) {
		char *dup = strdup(argv[1]);
		dup[ptr - argv[1]] = '\x00';
		core->offset = rz_num_math(core->num, dup);
		;
		free(dup);
	}

	ut64 addr = rz_num_math(core->num, argv[1]);
	if (core->num->nc.errors) {
		if (rz_cons_singleton()->context->is_interactive) {
			eprintf("Cannot seek to unknown address '%s'\n", core->num->nc.calc_buf);
		}
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2cmdstatus(rz_core_seek_and_save(core, addr, true));
}

RZ_IPI RzCmdStatus rz_seek_delta_handler(RzCore *core, int argc, const char **argv) {
	st64 delta = strtoll(argv[1], NULL, 0);
	return bool2cmdstatus(rz_core_seek_delta(core, delta, true));
}

RZ_IPI RzCmdStatus rz_seek_padded_handler(RzCore *core, int argc, const char **argv) {
	int n = argc > 1 ? atoi(argv[1]) : 0;
	printPadded(core, n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_seek_base_handler(RzCore *core, int argc, const char **argv) {
	return bool2cmdstatus(rz_core_seek_base(core, argv[1], true));
}

RZ_IPI RzCmdStatus rz_seek_blocksize_backward_handler(RzCore *core, int argc, const char **argv) {
	int n = 1;
	if (argc == 2) {
		n = rz_num_math(core->num, argv[1]);
	}
	int delta = -core->blocksize / n;
	return bool2cmdstatus(rz_core_seek_delta(core, delta, true));
}

RZ_IPI RzCmdStatus rz_seek_blocksize_forward_handler(RzCore *core, int argc, const char **argv) {
	int n = 1;
	if (argc == 2) {
		n = rz_num_math(core->num, argv[1]);
	}
	int delta = core->blocksize / n;
	return bool2cmdstatus(rz_core_seek_delta(core, delta, true));
}

RZ_IPI RzCmdStatus rz_seek_redo_handler(RzCore *core, int argc, const char **argv) {
	return bool2cmdstatus(rz_core_seek_redo(core));
}

RZ_IPI RzCmdStatus rz_seek_undo_handler(RzCore *core, int argc, const char **argv) {
	return bool2cmdstatus(rz_core_seek_undo(core));
}

RZ_IPI RzCmdStatus rz_seek_undo_reset_handler(RzCore *core, int argc, const char **argv) {
	rz_core_seek_reset(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_seek_history_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *list = rz_core_seek_list(core);
	RzListIter *iter;
	RzCoreSeekItem *undo;
	PJ *pj = state->d.pj;
	rz_cmd_state_output_array_start(state);
	bool current_met = false;
	rz_list_foreach (list, iter, undo) {
		RzFlagItem *f = rz_flag_get_at(core->flags, undo->offset, true);
		const char *comment;
		char *name = NULL;
		if (f) {
			if (f->offset != undo->offset) {
				name = rz_str_newf("%s+%" PFMT64d, f->name, undo->offset - f->offset);
			} else {
				name = strdup(f->name);
			}
		}
		current_met |= undo->is_current;
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_kn(pj, "offset", undo->offset);
			pj_kn(pj, "cursor", undo->cursor);
			if (name) {
				pj_ks(pj, "name", name);
			}
			pj_kb(pj, "current", undo->is_current);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			comment = "";
			if (undo->is_current) {
				comment = " # current seek";
			} else if (current_met) {
				comment = " # redo";
			}
			rz_cons_printf("0x%" PFMT64x " %s%s\n", undo->offset, name ? name : "", comment);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			if (undo->is_current) {
				rz_cons_printf("# Current seek @ 0x%" PFMT64x "\n", undo->offset);
			} else if (current_met) {
				rz_cons_printf("f redo_%d @ 0x%" PFMT64x "\n", RZ_ABS(undo->idx - 1), undo->offset);
			} else {
				rz_cons_printf("f undo_%d @ 0x%" PFMT64x "\n", RZ_ABS(undo->idx + 1), undo->offset);
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		free(name);
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_seek_asz_handler(RzCore *core, int argc, const char **argv) {
	ut64 align = rz_num_math(NULL, argv[1]);
	ut64 addr = core->offset;
	rz_core_seek_mark(core);
	if (argc > 2) {
		addr = rz_num_math(core->num, argv[2]);
		rz_core_seek(core, addr, false);
	}
	return bool2cmdstatus(rz_core_seek_align(core, align, true));
}

RZ_IPI RzCmdStatus rz_seek_basicblock_handler(RzCore *core, int argc, const char **argv) {
	return bool2cmdstatus(rz_core_seek_analysis_bb(core, core->offset, true));
}

RZ_IPI RzCmdStatus rz_seek_function_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = NULL;
	ut64 addr;
	if (argc == 1) {
		fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (!fcn) {
			return RZ_CMD_STATUS_ERROR;
		}
		addr = rz_analysis_function_max_addr(fcn);
	} else {
		fcn = rz_analysis_get_function_byname(core->analysis, argv[1]);
		if (!fcn) {
			return RZ_CMD_STATUS_ERROR;
		}
		addr = fcn->addr;
	}
	return bool2cmdstatus(rz_core_seek_and_save(core, addr, true));
}

RZ_IPI RzCmdStatus rz_seek_function_current_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2cmdstatus(rz_core_seek_and_save(core, fcn->addr, true));
}

RZ_IPI RzCmdStatus rz_seek_begin_handler(RzCore *core, int argc, const char **argv) {
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	ut64 addr = map ? map->itv.addr : 0;
	return bool2cmdstatus(rz_core_seek_and_save(core, addr, true));
}

RZ_IPI RzCmdStatus rz_seek_end_handler(RzCore *core, int argc, const char **argv) {
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	// XXX: this +2 is a hack. must fix gap between sections
	ut64 addr = map ? map->itv.addr + map->itv.size + 2 : rz_io_fd_size(core->io, core->file->fd);
	return bool2cmdstatus(rz_core_seek_and_save(core, addr, true));
}

RZ_IPI RzCmdStatus rz_seek_next_handler(RzCore *core, int argc, const char **argv) {
	const char *nkey;
	if (argc == 1) {
		nkey = rz_config_get(core->config, "scr.nkey");
	} else {
		nkey = argv[1];
	}
	return bool2cmdstatus(rz_core_seek_next(core, nkey, true));
}

RZ_IPI RzCmdStatus rz_seek_prev_handler(RzCore *core, int argc, const char **argv) {
	const char *nkey;
	if (argc == 1) {
		nkey = rz_config_get(core->config, "scr.nkey");
	} else {
		nkey = argv[1];
	}
	return bool2cmdstatus(rz_core_seek_prev(core, nkey, true));
}

RZ_IPI RzCmdStatus rz_seek_opcode_handler(RzCore *core, int argc, const char **argv) {
	cmd_seek_opcode(core, argc > 1 ? argv[1] : "", false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_seek_register_handler(RzCore *core, int argc, const char **argv) {
	return bool2cmdstatus(rz_core_seek_to_register(core, argv[1], false));
}
