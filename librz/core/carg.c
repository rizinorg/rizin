// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define MAXSTRLEN 50

/**
 * \brief Get the value of the num-th argument from the current debug or emulation state
 *
 * Warning: this function contains hacks. Rewrite it before using it in new code.
 */
RZ_DEPRECATE RZ_API ut64 rz_core_arg_get(RzCore *core, const char *cc, int num) {
	rz_return_val_if_fail(core, UT64_MAX);
	if (!cc) {
		cc = rz_analysis_syscc_default(core->analysis);
	}
	if (rz_core_is_debug(core)) {
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ANY, false);
	}
	if (!RZ_STR_ISEMPTY(cc)) {
		if (!strcmp(cc, "stdcall") || !strcmp(cc, "pascal")) {
			ut64 sp = rz_reg_get_value_by_role(rz_core_reg_default(core), RZ_REG_NAME_SP);
			int bits = rz_core_is_debug(core) ? core->dbg->bits : core->analysis->bits;
			if (bits) {
				ut64 n64;
				sp += 8; // skip return address, assume we are inside the call
				sp += 8 * num;
				// FIXME: honor endianness of platform
				rz_io_read_at(core->io, sp, (ut8 *)&n64, sizeof(ut64));
				return (ut64)n64;
			} else {
				sp += 4; // skip return address, assume we are inside the call
				sp += 4 * num;
				ut32 n32;
				// FIXME: honor endianness of platform
				rz_io_read_at(core->io, sp, (ut8 *)&n32, sizeof(ut32));
				return (ut64)n32;
			}
		}
		const char *rn = rz_analysis_cc_arg(core->analysis, cc, num);
		if (rn) {
			return rz_core_reg_getv_by_role_or_name(core, rn);
		}
	}
	char reg[32];
	return rz_core_reg_getv_by_role_or_name(core, rz_strf(reg, "A%d", num));
}

/**
 * \brief Set the value of the num-th argument in the current debug or emulation state
 *
 * Warning: this function contains hacks. Rewrite it before using it in new code.
 */
RZ_DEPRECATE RZ_API bool rz_core_arg_set(RzCore *core, const char *cc, int num, ut64 val) {
	rz_return_val_if_fail(core, false);
	if (!RZ_STR_ISEMPTY(cc)) {
		cc = rz_analysis_syscc_default(core->analysis);
	}
	const char *rn = rz_analysis_cc_arg(core->analysis, cc, num);
	if (rn) {
		rz_core_reg_set_by_role_or_name(core, rn, val);
		return true;
	}
	char reg[32];
	rz_core_reg_set_by_role_or_name(core, rz_strf(reg, "A%d", num), val);
	return true;
}

static void set_fcn_args_info(RzAnalysisFuncArg *arg, RzAnalysis *analysis, const char *fcn_name, const char *cc, int arg_num) {
	if (!fcn_name || !arg || !analysis) {
		return;
	}
	arg->name = rz_type_func_args_name(analysis->typedb, fcn_name, arg_num);
	arg->orig_c_type = rz_type_func_args_type(analysis->typedb, fcn_name, arg_num);
	if (!arg->name || !arg->orig_c_type) {
		RZ_LOG_ERROR("core: missing type for function argument (%s)\n", fcn_name);
		return;
	}
	arg->c_type = arg->orig_c_type;
	arg->fmt = rz_type_as_format(analysis->typedb, arg->c_type);
	arg->size = rz_type_db_get_bitsize(analysis->typedb, arg->c_type) / 8;
	arg->cc_source = rz_analysis_cc_arg(analysis, cc, arg_num);
}

RZ_API char *resolve_fcn_name(RzAnalysis *analysis, const char *func_name) {
	const char *str = func_name;
	const char *name = func_name;
	if (rz_type_func_exist(analysis->typedb, func_name)) {
		return strdup(func_name);
	}
	while ((str = strchr(str, '.'))) {
		name = str + 1;
		str++;
	}
	if (rz_type_func_exist(analysis->typedb, name)) {
		return strdup(name);
	}
	return rz_analysis_function_name_guess(analysis->typedb, (char *)func_name);
}

static ut64 get_buf_val(ut8 *buf, int endian, int width) {
	return (width == 8) ? rz_read_ble64(buf, endian) : (ut64)rz_read_ble32(buf, endian);
}

static void print_arg_str(int argcnt, const char *name, bool color) {
	if (color) {
		rz_cons_printf(Color_BYELLOW " arg [%d]" Color_RESET " -" Color_BCYAN " %s" Color_RESET " : ",
			argcnt, name);
	} else {
		rz_cons_printf(" arg [%d] -  %s : ", argcnt, name);
	}
}

static void print_format_values(RzCore *core, const char *fmt, bool onstack, ut64 src, bool color) {
	char opt;
	ut64 bval = src;
	int i;
	int endian = core->print->big_endian;
	int width = (core->analysis->bits == 64) ? 8 : 4;
	int bsize = RZ_MIN(64, core->blocksize);

	ut8 *buf = malloc(bsize);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate %d byte(s)\n", bsize);
		free(buf);
		return;
	}
	if (fmt) {
		opt = *fmt;
	} else {
		opt = 'p'; // void *ptr
	}
	if (onstack || ((opt != 'd' && opt != 'x') && !onstack)) {
		if (color) {
			rz_cons_printf(Color_BGREEN "0x%08" PFMT64x Color_RESET " --> ", bval);
		} else {
			rz_cons_printf("0x%08" PFMT64x " --> ", bval);
		}
		rz_io_read_at(core->io, bval, buf, bsize);
	}
	if (onstack) { // Fetch value from stack
		bval = get_buf_val(buf, endian, width);
		if (opt != 'd' && opt != 'x') {
			rz_io_read_at(core->io, bval, buf, bsize); // update buf with val from stack
		}
	}
	rz_cons_print(color ? Color_BGREEN : "");
	switch (opt) {
	case 'z': // Null terminated string
		rz_cons_print(color ? Color_RESET Color_BWHITE : "");
		rz_cons_print("\"");
		for (i = 0; i < MAXSTRLEN; i++) {
			if (buf[i] == '\0') {
				break;
			}
			ut8 b = buf[i];
			if (IS_PRINTABLE(b)) {
				rz_cons_printf("%c", b);
			} else {
				rz_cons_printf("\\x%02x", b);
			}
			if (i == MAXSTRLEN - 1) {
				rz_cons_print("..."); // To show string is truncated
			}
		}
		rz_cons_print("\"");
		rz_cons_newline();
		break;
	case 'd': // integer
	case 'x':
		rz_cons_printf("0x%08" PFMT64x, bval);
		rz_cons_newline();
		break;
	case 'c': // char
		rz_cons_print("\'");
		ut8 ch = buf[0];
		if (IS_PRINTABLE(ch)) {
			rz_cons_printf("%c", ch);
		} else {
			rz_cons_printf("\\x%02x", ch);
		}
		rz_cons_print("\'");
		rz_cons_newline();
		break;
	case 'p': // pointer
	{
		// Try to deref the pointer once again
		rz_cons_printf("0x%08" PFMT64x, get_buf_val(buf, endian, width));
		rz_cons_newline();
		break;
	}
	default:
		// TODO: support types like structs and unions
		rz_cons_println("unk_format");
	}
	rz_cons_print(Color_RESET);
	free(buf);
}

/* This function display list of arg with some colors */

RZ_API void rz_core_print_func_args(RzCore *core) {
	RzListIter *iter;
	bool color = rz_config_get_i(core->config, "scr.color");
	if (!core->analysis) {
		return;
	}
	if (!core->analysis->reg) {
		return;
	}
	const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	ut64 cur_addr = rz_reg_getv(core->analysis->reg, pc);
	RzAnalysisOp *op = rz_core_analysis_op(core, cur_addr, RZ_ANALYSIS_OP_MASK_BASIC);
	if (!op) {
		return;
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_CALL) {
		RzAnalysisFunction *fcn;
		RzAnalysisFuncArg *arg;
		bool onstack = false;
		const char *fcn_name = NULL;
		ut64 pcv = op->jump;
		if (pcv == UT64_MAX) {
			pcv = op->ptr;
		}
		fcn = rz_analysis_get_function_at(core->analysis, pcv);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			if (core->flags) {
				RzFlagItem *item = rz_flag_get_i(core->flags, pcv);
				if (item) {
					fcn_name = rz_flag_item_get_name(item);
				}
			}
		}
		RzList *list = rz_core_get_func_args(core, fcn_name);
		if (!rz_list_empty(list)) {
			int argcnt = 0;
			rz_list_foreach (list, iter, arg) {
				if (arg->cc_source && !strncmp(arg->cc_source, "stack", 5)) {
					onstack = true;
				}
				print_arg_str(argcnt, arg->name, color);
				print_format_values(core, arg->fmt, onstack, arg->src, color);
				argcnt++;
			}
		} else {
			int nargs = 4; // TODO: use a correct value here when available
			// if (nargs > 0) {
			int i;
			const char *cc = rz_analysis_cc_default(core->analysis); // or use "reg" ?
			for (i = 0; i < nargs; i++) {
				ut64 v = rz_core_arg_get(core, cc, i);
				print_arg_str(i, "", color);
				rz_cons_printf("0x%08" PFMT64x, v);
				rz_cons_newline();
			}
			//} else {
			//	print_arg_str (0, "void", color);
			//}
		}
		rz_list_free(list);
	}
	rz_analysis_op_fini(op);
}

static void rz_analysis_fcn_arg_free(RzAnalysisFuncArg *arg) {
	if (!arg) {
		return;
	}
	free(arg->fmt);
	free(arg);
}

RZ_API RZ_OWN RzList /*<RzAnalysisFuncArg *>*/ *rz_core_get_func_args(RzCore *core, const char *fcn_name) {
	if (!fcn_name || !core->analysis) {
		return NULL;
	}
	char *key = resolve_fcn_name(core->analysis, fcn_name);
	if (!key) {
		return NULL;
	}
	RzList *list = rz_list_newf((RzListFree)rz_analysis_fcn_arg_free);
	const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	int nargs = rz_type_func_args_count(core->analysis->typedb, key);
	if (!rz_analysis_cc_func(core->analysis, key)) {
		rz_list_free(list);
		return NULL;
	}
	char *cc = strdup(rz_analysis_cc_func(core->analysis, key));
	const char *src = rz_analysis_cc_arg(core->analysis, cc, 0); // src of first argument
	if (!cc) {
		// unsupported calling convention
		free(key);
		rz_list_free(list);
		return NULL;
	}
	int i;
	ut64 spv = rz_reg_getv(core->analysis->reg, sp);
	ut64 s_width = (core->analysis->bits == 64) ? 8 : 4;
	if (src && !strcmp(src, "stack_rev")) {
		for (i = nargs - 1; i >= 0; i--) {
			RzAnalysisFuncArg *arg = RZ_NEW0(RzAnalysisFuncArg);
			set_fcn_args_info(arg, core->analysis, key, cc, i);
			arg->src = spv;
			spv += arg->size ? arg->size : s_width;
			rz_list_append(list, arg);
		}
	} else {
		for (i = 0; i < nargs; i++) {
			RzAnalysisFuncArg *arg = RZ_NEW0(RzAnalysisFuncArg);
			if (!arg) {
				free(cc);
				rz_list_free(list);
				return NULL;
			}
			set_fcn_args_info(arg, core->analysis, key, cc, i);
			if (src && !strncmp(src, "stack", 5)) {
				arg->src = spv;
				if (!arg->size) {
					arg->size = s_width;
				}
				spv += arg->size;
			} else {
				const char *cs = arg->cc_source;
				if (!cs) {
					cs = rz_analysis_cc_default(core->analysis);
				}
				if (cs) {
					arg->src = rz_reg_getv(core->analysis->reg, cs);
				}
			}
			rz_list_append(list, arg);
		}
	}
	free(key);
	free(cc);
	return list;
}
