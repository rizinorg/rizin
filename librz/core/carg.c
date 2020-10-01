/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <rz_core.h>

#define MAXSTRLEN 50

static void set_fcn_args_info(RzAnalFuncArg *arg, RzAnal *anal, const char *fcn_name, const char *cc, int arg_num) {
	if (!fcn_name || !arg || !anal) {
		return;
	}
	Sdb *TDB = anal->sdb_types;
	arg->name = rz_type_func_args_name (TDB, fcn_name, arg_num);
	arg->orig_c_type = rz_type_func_args_type (TDB, fcn_name, arg_num);
	if (!arg->name || !arg->orig_c_type) {
		eprintf ("Missing type for function argument (%s)\n", fcn_name);
		return;
	}
	if (!strncmp ("const ", arg->orig_c_type, 6)) {
		arg->c_type = arg->orig_c_type + 6;
	} else {
		arg->c_type = arg->orig_c_type;
	}
	const char *query = sdb_fmt ("type.%s", arg->c_type);
	arg->fmt = sdb_const_get (TDB, query, 0);
	const char *t_query = sdb_fmt ("type.%s.size", arg->c_type);
	arg->size = sdb_num_get (TDB, t_query, 0) / 8;
	arg->cc_source = rz_anal_cc_arg (anal, cc, arg_num);
}

RZ_API char *resolve_fcn_name(RzAnal *anal, const char *func_name) {
	const char *str = func_name;
	const char *name = func_name;
	if (rz_type_func_exist (anal->sdb_types, func_name)) {
		return strdup (func_name);
	}
	while ((str = strchr (str, '.'))) {
		name = str + 1;
		str++;
	}
	if (rz_type_func_exist (anal->sdb_types, name)) {
		return strdup (name);
	}
	return rz_type_func_guess (anal->sdb_types, (char*)func_name);
}

static ut64 get_buf_val(ut8 *buf, int endian, int width) {
	return (width == 8)? rz_read_ble64 (buf, endian) : (ut64) rz_read_ble32 (buf,endian);
}

static void print_arg_str(int argcnt, const char *name, bool color) {
	if (color) {
		rz_cons_printf (Color_BYELLOW" arg [%d]"Color_RESET" -"Color_BCYAN" %s"Color_RESET" : ",
				argcnt, name);
	} else {
		rz_cons_printf (" arg [%d] -  %s : ", argcnt, name);
	}
}

static void print_format_values(RzCore *core, const char *fmt, bool onstack, ut64 src, bool color) {
	char opt;
	ut64 bval = src;
	int i;
	int endian = core->print->big_endian;
	int width = (core->anal->bits == 64)? 8: 4;
	int bsize = R_MIN (64, core->blocksize);

	ut8 *buf = malloc (bsize);
	if (!buf) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		free (buf);
		return;
	}
	if (fmt) {
		opt = *fmt;
	} else {
		opt = 'p'; // void *ptr
	}
	if (onstack || ((opt != 'd' && opt != 'x') && !onstack)) {
		if (color) {
			rz_cons_printf (Color_BGREEN"0x%08"PFMT64x Color_RESET" --> ", bval);
		} else {
			rz_cons_printf ("0x%08"PFMT64x" --> ", bval);
		}
		rz_io_read_at (core->io, bval, buf, bsize);
	}
	if (onstack) { // Fetch value from stack
		bval = get_buf_val (buf, endian, width);
		if (opt != 'd' && opt != 'x') {
			rz_io_read_at (core->io, bval, buf, bsize); // update buf with val from stack
		}
	}
	rz_cons_print (color? Color_BGREEN: "");
	switch (opt) {
	case 'z' : // Null terminated string
		rz_cons_print (color ?Color_RESET Color_BWHITE:"");
		rz_cons_print ("\"");
		for (i = 0; i < MAXSTRLEN; i++) {
			if (buf[i] == '\0') {
				break;
			}
			ut8 b = buf[i];
			if (IS_PRINTABLE (b)) {
				rz_cons_printf ("%c", b);
			} else {
				rz_cons_printf ("\\x%02x", b);
			}
			if (i == MAXSTRLEN - 1) {
				 rz_cons_print ("..."); // To show string is truncated
			}
		}
		rz_cons_print ("\"");
		rz_cons_newline ();
		break;
	case 'd' : // integer
	case 'x' :
		rz_cons_printf ("0x%08" PFMT64x, bval);
		rz_cons_newline ();
		break;
	case 'c' : // char
		rz_cons_print ("\'");
		ut8 ch = buf[0];
		if (IS_PRINTABLE (ch)) {
			rz_cons_printf ("%c", ch);
		} else {
			rz_cons_printf ("\\x%02x", ch);
		}
		rz_cons_print ("\'");
		rz_cons_newline ();
		break;
	case 'p' : // pointer
		{
		// Try to deref the pointer once again
		rz_cons_printf ("0x%08"PFMT64x, get_buf_val (buf, endian, width));
		rz_cons_newline ();
		break;
		}
	default:
		//TODO: support types like structs and unions
		rz_cons_println ("unk_format");
	}
	rz_cons_print (Color_RESET);
	free (buf);
}

/* This function display list of arg with some colors */

RZ_API void rz_core_print_func_args(RzCore *core) {
	RzListIter *iter;
	bool color = rz_config_get_i (core->config, "scr.color");
	if (!core->anal) {
		return;
	}
	if (!core->anal->reg) {
		return;
	}
	const char *pc = rz_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ut64 cur_addr = rz_reg_getv (core->anal->reg, pc);
	RzAnalOp *op = rz_core_anal_op (core, cur_addr, R_ANAL_OP_MASK_BASIC);
	if (!op) {
		return;
	}
	if (op->type == R_ANAL_OP_TYPE_CALL) {
		RzAnalFunction *fcn;
		RzAnalFuncArg *arg;
		bool onstack = false;
		const char *fcn_name = NULL;
		ut64 pcv = op->jump;
		if (pcv == UT64_MAX) {
			pcv = op->ptr;
		}
		fcn = rz_anal_get_function_at (core->anal, pcv);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			if (core->flags) {
				RzFlagItem *item = rz_flag_get_i (core->flags, pcv);
				if (item) {
					fcn_name = item->name;
				}
			}
		}
		RzList *list = rz_core_get_func_args (core, fcn_name);
		if (!rz_list_empty (list)) {
			int argcnt = 0;
			rz_list_foreach (list, iter, arg) {
				if (arg->cc_source && !strncmp (arg->cc_source, "stack", 5)) {
					onstack = true;
				}
				print_arg_str (argcnt, arg->name, color);
				print_format_values (core, arg->fmt, onstack, arg->src, color);
				argcnt++;
			}
		} else {
			int nargs = 4; // TODO: use a correct value here when available
			//if (nargs > 0) {
				int i;
				for (i = 0; i < nargs; i++) {
					ut64 v = rz_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_STDCALL, i);
					print_arg_str (i, "", color);
					rz_cons_printf ("0x%08" PFMT64x, v);
					rz_cons_newline ();
				}
			//} else {
			//	print_arg_str (0, "void", color);
			//}
		}
	}
	rz_anal_op_fini (op);
}

static void rz_anal_fcn_arg_free(RzAnalFuncArg *arg) {
	if (!arg) {
		return;
	}
	free (arg->orig_c_type);
	free (arg);
}

/* Returns a list of RzAnalFuncArg */
RZ_API RzList *rz_core_get_func_args(RzCore *core, const char *fcn_name) {
	if (!fcn_name || !core->anal) {
		return NULL;
	}
	Sdb *TDB = core->anal->sdb_types;
	RzList *list = rz_list_newf ((RzListFree)rz_anal_fcn_arg_free);
	char *key = resolve_fcn_name (core->anal, fcn_name);
	if (!key) {
		return NULL;
	}
	const char *sp = rz_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	int nargs = rz_type_func_args_count (TDB, key);
	if (!rz_anal_cc_func (core->anal, key)){
		return NULL;
	}
	char *cc = strdup (rz_anal_cc_func (core->anal, key));
	const char *src = rz_anal_cc_arg (core->anal, cc, 0); // src of first argument
	if (!cc) {
		// unsupported calling convention
		free (key);
		return NULL;
	}
	int i;
	ut64 spv = rz_reg_getv (core->anal->reg, sp);
	ut64 s_width = (core->anal->bits == 64)? 8: 4;
	if (src && !strcmp (src, "stack_rev")) {
		for (i = nargs - 1; i >= 0; i--) {
			RzAnalFuncArg *arg = R_NEW0 (RzAnalFuncArg);
			set_fcn_args_info (arg, core->anal, key, cc, i);
			arg->src = spv;
			spv += arg->size? arg->size : s_width;
			rz_list_append (list, arg);
		}
	} else {
		for (i = 0; i < nargs; i++) {
			RzAnalFuncArg *arg = R_NEW0 (RzAnalFuncArg);
			if (!arg) {
				return NULL;
			}
			set_fcn_args_info (arg, core->anal, key, cc, i);
			if (src && !strncmp (src, "stack", 5)) {
				arg->src = spv;
				if (!arg->size) {
					arg->size = s_width;
				}
				spv += arg->size;
			} else {
				const char *cs = arg->cc_source;
				if (!cs) {
					cs = rz_anal_cc_default (core->anal);
				}
				if (cs) {
					arg->src = rz_reg_getv (core->anal->reg, cs);
				}
			}
			rz_list_append (list, arg);
		}
	}
	free (key);
	free (cc);
	return list;
}
