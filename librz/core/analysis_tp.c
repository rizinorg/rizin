// SPDX-FileCopyrightText: 2016-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2016-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
/* type matching - type propagation */

#include <rz_analysis.h>
#include <rz_util.h>
#include <ht_uu.h>
#include <rz_core.h>
#define LOOP_MAX 10

static bool analysis_emul_init(RzCore *core, RzConfigHold *hc, RzDebugTrace **dt, RzAnalysisEsilTrace **et, RzAnalysisRzilTrace **rt) {
	if (!core->analysis->esil || !core->analysis->rzil) {
		return false;
	}
	*dt = core->dbg->trace;
	*et = core->analysis->esil->trace;

	core->dbg->trace = rz_debug_trace_new();
	core->analysis->esil->trace = rz_analysis_esil_trace_new(core->analysis->esil);
	core->analysis->rzil->trace = rz_analysis_rzil_trace_new(core->analysis, core->analysis->rzil);

	rz_config_hold_i(hc, "esil.romem", "dbg.trace",
		"esil.nonull", "dbg.follow", NULL);
	rz_config_set(core->config, "esil.romem", "true");
	rz_config_set(core->config, "dbg.trace", "true");
	rz_config_set(core->config, "esil.nonull", "true");
	rz_config_set_i(core->config, "dbg.follow", false);
	const char *bp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_BP);
	const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	if ((bp && !rz_reg_getv(core->analysis->reg, bp)) && (sp && !rz_reg_getv(core->analysis->reg, sp))) {
		eprintf("Stack isn't initialized.\n");
		eprintf("Try running aei and aeim commands before aft for default stack initialization\n");
		return false;
	}
	return (core->dbg->trace && core->analysis->esil->trace);
}

static void analysis_emul_restore(RzCore *core, RzConfigHold *hc, RzDebugTrace *dt, RzAnalysisEsilTrace *et, RzAnalysisRzilTrace *rt) {
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	rz_debug_trace_free(core->dbg->trace);
	rz_analysis_esil_trace_free(core->analysis->esil->trace);
	if (!core->analysis->rzil) {
		// not enable rzil or be freed ?
		if (core->analysis->cur->rzil_init) {
			// enable but be freed ??
			rz_warn_if_reached();
		}
	} else {
		rz_analysis_rzil_trace_free(core->analysis->rzil->trace);
		core->analysis->rzil->trace = rt;
	}
	core->analysis->esil->trace = et;
	core->dbg->trace = dt;
}

static bool type_pos_hit(RzAnalysis *analysis, RzILTraceInstruction *instr_trace, bool in_stack, int size, const char *place) {
	if (in_stack) {
		const char *sp_name = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
		ut64 sp = rz_reg_getv(analysis->reg, sp_name);

		ut64 write_addr = 0LL;
		if (instr_trace && (instr_trace->stats & RZ_IL_TRACE_INS_HAS_MEM_W)) {
			// TODO : This assumes an op will only write to memory once
			//      : which may be wrong in some archs. this is only a temporary solution
			RzILTraceMemOp *mem = rz_pvector_at(instr_trace->write_mem_ops, 0);
			write_addr = mem->addr;
		} else {
			// no reg write
			write_addr = 0LL;
		}
		return (write_addr == sp + size);
	}

	return rz_analysis_il_reg_trace_contains(instr_trace, place, true);
}

static void var_rename(RzAnalysis *analysis, RzAnalysisVar *v, const char *name, ut64 addr) {
	if (!name || !v) {
		return;
	}
	if (!*name || !strcmp(name, "...")) {
		return;
	}
	bool is_default = (rz_str_startswith(v->name, VARPREFIX) || rz_str_startswith(v->name, ARGPREFIX));
	if (*name == '*') {
		rz_warn_if_reached();
		name++;
	}
	// longer name tends to be meaningful like "src" instead of "s1"
	if (!is_default && (strlen(v->name) > strlen(name))) {
		return;
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, addr, 0);
	if (!fcn) {
		return;
	}
	rz_analysis_var_rename(v, name, false);
}

static void var_type_set_sign(RzAnalysis *analysis, RzAnalysisVar *var, bool sign) {
	rz_return_if_fail(analysis && var);
	// Check if it's integral number first
	if (rz_type_is_integral(analysis->typedb, var->type)) {
		rz_type_integral_set_sign(analysis->typedb, &var->type, sign);
	}
}

static bool var_type_simple_to_complex(const RzTypeDB *typedb, RzType *a, RzType *b) {
	// `*int*` types to anything else of the typeclass
	if (rz_type_is_integral(typedb, a) && !rz_type_is_char_ptr_nested(a) && !rz_type_is_integral(typedb, b)) {
		return true;
	}
	// `*int*` types to pointers or arrays
	if (rz_type_is_integral(typedb, a) && !rz_type_is_char_ptr_nested(a) && b->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return true;
	}
	return false;
}

// TODO: Handle also non-atomic types here
static void var_type_set(RzAnalysis *analysis, RzAnalysisVar *var, RZ_BORROW RzType *type, bool ref) {
	rz_return_if_fail(analysis && var && type);
	RzTypeDB *typedb = analysis->typedb;
	// removing this return makes 64bit vars become 32bit
	if (rz_type_is_default(typedb, type) || rz_type_atomic_is_void(typedb, type)) {
		// default or void (not void* !) type
		return;
	}
	if (!rz_type_is_default(typedb, var->type) && !rz_type_is_void_ptr(var->type) && !var_type_simple_to_complex(typedb, var->type, type)) {
		// return since type is already propagated
		// except for "void *", since "void *" => "char *" is possible
		// except for simple types to the more complex types
		return;
	}
	// Since the type could be used by something else we should clone it
	RzType *cloned = rz_type_clone(type);
	if (!cloned) {
		eprintf("Cannot clone the type for the variable \"%s.%s\"\n", var->fcn->name, var->name);
		return;
	}
	// Make a pointer of the existing type
	if (ref) {
		// By default we create non-const pointers
		RzType *ptrtype = rz_type_pointer_of_type(typedb, cloned, false);
		if (!ptrtype) {
			eprintf("Cannot convert the type for the variable \"%s.%s\" into pointer\n", var->fcn->name, var->name);
			return;
		}
		rz_analysis_var_set_type(var, ptrtype);
		return;
	}

	rz_analysis_var_set_type(var, cloned);
}

static void var_type_set_str(RzAnalysis *analysis, RzAnalysisVar *var, const char *type, bool ref) {
	rz_return_if_fail(analysis && var && type);
	char *error_msg = NULL;
	RzType *realtype = rz_type_parse_string_single(analysis->typedb->parser, type, &error_msg);
	if (!realtype && error_msg) {
		eprintf("Fail to parse type \"%s\":\n%s\n", type, error_msg);
		free(error_msg);
		return;
	}
	var_type_set(analysis, var, realtype, ref);
	// Since we clone the type here, free it
	rz_type_free(realtype);
}

static void get_src_regname(RzCore *core, ut64 addr, char *regname, int size) {
	RzAnalysis *analysis = core->analysis;
	RzAnalysisOp *op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_ESIL);
	if (!op || rz_strbuf_is_empty(&op->esil)) {
		rz_analysis_op_free(op);
		return;
	}
	char *op_esil = strdup(rz_strbuf_get(&op->esil));
	char *tmp = strchr(op_esil, ',');
	if (tmp) {
		*tmp = '\0';
	}
	memset(regname, 0, size);
	RzRegItem *ri = rz_reg_get(analysis->reg, op_esil, -1);
	if (ri) {
		if ((analysis->bits == 64) && (ri->size == 32)) {
			const char *reg = rz_reg_32_to_64(analysis->reg, op_esil);
			if (reg) {
				free(op_esil);
				op_esil = strdup(reg);
			}
		}
		strncpy(regname, op_esil, size - 1);
	}
	free(op_esil);
	rz_analysis_op_free(op);
}

static ut64 get_addr(RzAnalysis *analysis, const char *regname, int idx) {
	if (!regname || !*regname) {
		return UT64_MAX;
	}

	RzAnalysisEsilTrace *etrace = analysis->esil->trace;
	RzILTraceInstruction *instruction_trace = rz_analysis_esil_get_instruction_trace(etrace, idx);
	RzILTraceRegOp *reg_op = rz_analysis_il_get_reg_op_trace(instruction_trace, regname, false);

	if (!reg_op) {
		return UT64_MAX;
	}

	return reg_op->value;
}

static RzList *parse_format(RzCore *core, char *fmt) {
	if (!fmt || !*fmt) {
		return NULL;
	}
	RzList *ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	Sdb *s = core->analysis->sdb_fmts;
	const char *spec = rz_config_get(core->config, "analysis.types.spec");
	char arr[10] = { 0 };
	char *ptr = strchr(fmt, '%');
	fmt[strlen(fmt) - 1] = '\0';
	while (ptr) {
		ptr++;
		// strip [width] specifier
		while (IS_DIGIT(*ptr)) {
			ptr++;
		}
		rz_str_ncpy(arr, ptr, sizeof(arr) - 1);
		char *tmp = arr;
		while (tmp && (IS_LOWER(*tmp) || IS_UPPER(*tmp))) {
			tmp++;
		}
		*tmp = '\0';
		const char *query = sdb_fmt("spec.%s.%s", spec, arr);
		char *type = (char *)sdb_const_get(s, query, 0);
		if (type) {
			rz_list_append(ret, type);
		}
		ptr = strchr(ptr, '%');
	}
	return ret;
}

static void retype_callee_arg(RzAnalysis *analysis, const char *callee_name, bool in_stack, const char *place, int size, RZ_BORROW RzType *type) {
	RzAnalysisFunction *fcn = rz_analysis_get_function_byname(analysis, callee_name);
	if (!fcn) {
		return;
	}
	if (in_stack) {
		RzAnalysisVar *var = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_BPV, size - fcn->bp_off + 8);
		if (!var) {
			return;
		}
		var_type_set(analysis, var, type, false);
	} else {
		RzRegItem *item = rz_reg_get(analysis->reg, place, -1);
		if (!item) {
			return;
		}
		RzAnalysisVar *rvar = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_REG, item->index);
		if (!rvar) {
			return;
		}
		var_type_set(analysis, rvar, type, false);
		RzAnalysisVar *lvar = rz_analysis_var_get_dst_var(rvar);
		if (lvar) {
			var_type_set(analysis, lvar, type, false);
		}
	}
}

RzAnalysisOp *op_cache_get(HtUP *cache, RzCore *core, ut64 addr) {
	RzAnalysisOp *op = ht_up_find(cache, addr, NULL);
	if (op) {
		return op;
	}
	op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_VAL);
	if (!ht_up_insert(cache, addr, op)) {
		rz_analysis_op_free(op);
		return NULL;
	}
	return op;
}

RzCallable *function_type_derive(RzAnalysis *analysis, RZ_NONNULL const char *fcn_name, bool *owned) {
	rz_return_val_if_fail(fcn_name && owned, NULL);
	// Because in the case of `rz_type_func_get()` we get the borrowed
	// pointer to the RzCallable and in the case of `rz_analysis_function_derive_type()`
	// we get the owned pointer, we should free the pointer in the one case but not another.
	*owned = false;
	RzCallable *callable = rz_type_func_get(analysis->typedb, fcn_name);
	if (!callable) {
		RzAnalysisFunction *fcn = rz_analysis_get_function_byname(analysis, fcn_name);
		if (!fcn) {
			return NULL;
		}
		callable = rz_analysis_function_derive_type(analysis, fcn);
		if (!callable) {
			return NULL;
		}
		*owned = true;
	}
	return callable;
}

bool function_argument_type_derive(RZ_NULLABLE const RzCallable *callable, int arg_num, RzType **type, char **name) {
	rz_return_val_if_fail(type && name, false);
	if (!callable) {
		return false;
	}
	if (arg_num >= rz_pvector_len(callable->args)) {
		return false;
	}
	RzCallableArg *arg = *rz_pvector_index_ptr(callable->args, arg_num);
	if (!arg) {
		return false;
	}
	*type = rz_type_clone(arg->type);
	*name = strdup(arg->name);
	return true;
}

#define DEFAULT_MAX  3
#define REGNAME_SIZE 10
#define MAX_INSTR    5

/**
 * type match at a call instruction inside another function
 *
 * \param fcn_name name of the callee
 * \param addr addr of the call instruction
 * \param baddr addr of the caller function
 * \param cc cc of the callee
 * \param prev_idx index in the esil trace
 * \param userfnc whether the callee is a user function (affects propagation direction)
 * \param caddr addr of the callee
 */
static void type_match(RzCore *core, char *fcn_name, ut64 addr, ut64 baddr, const char *cc,
	int prev_idx, bool userfnc, ut64 caddr, HtUP *op_cache) {
	RzAnalysisEsilTrace *etrace = core->analysis->esil->trace;
	RzTypeDB *typedb = core->analysis->typedb;
	RzAnalysis *analysis = core->analysis;
	RzList *types = NULL;

	int idx = rz_pvector_len(etrace->instructions) - 1;

	bool verbose = rz_config_get_i(core->config, "analysis.types.verbose");
	bool stack_rev = false, in_stack = false, format = false;

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, pos = 0, size = 0, max = rz_type_func_args_count(typedb, fcn_name);
	const char *place = rz_analysis_cc_arg(analysis, cc, ST32_MAX);
	rz_cons_break_push(NULL, NULL);

	if (place && !strcmp(place, "stack_rev")) {
		stack_rev = true;
	}
	place = rz_analysis_cc_arg(analysis, cc, 0);
	if (place && rz_str_startswith("stack", place)) {
		in_stack = true;
	}
	if (verbose && !strncmp(fcn_name, "sym.imp.", 8)) {
		eprintf("%s missing function definition\n", fcn_name + 8);
	}
	if (!max || max == -1) {
		if (!in_stack) {
			max = rz_analysis_cc_max_arg(analysis, cc);
		} else {
			max = DEFAULT_MAX;
		}
	}
	// Because in the case of `rz_type_func_get()` we get the borrowed
	// pointer to the RzCallable and in the case of `rz_analysis_function_derive_type()`
	// we get the owned pointer, we should free the pointer in the one case but not another.
	bool owned = false;
	RzCallable *callable = function_type_derive(analysis, fcn_name, &owned);
	// We don't check if the callable is NULL because we not always need it, for example
	// in case of the `format` set it's unnecessary for the type derivation.
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev ? (max - 1 - i) : i;
		RzType *type = NULL;
		char *name = NULL;
		if (format) {
			if (rz_list_empty(types)) {
				break;
			}
			const char *typestr = rz_str_new(rz_list_get_n(types, pos++));
			if (typestr) {
				type = rz_type_parse_string_single(typedb->parser, typestr, NULL);
			}
		} else {
			if (!function_argument_type_derive(callable, arg_num, &type, &name)) {
				continue;
			}
		}
		if (!type && !userfnc) {
			free(name);
			continue;
		}
		if (!in_stack) {
			// XXX: param arg_num must be fixed to support floating point register
			place = rz_analysis_cc_arg(analysis, cc, arg_num);
			if (place && rz_str_startswith("stack", place)) {
				in_stack = true;
			}
		}
		char regname[REGNAME_SIZE] = { 0 };
		ut64 xaddr = UT64_MAX;
		bool memref = false;
		bool cmt_set = false;
		bool res = false;
		// Backtrace instruction from source sink to prev source sink
		for (j = idx; j >= prev_idx; j--) {
			RzILTraceInstruction *instr_trace = rz_analysis_esil_get_instruction_trace(etrace, j);
			ut64 instr_addr = instr_trace->addr;
			if (instr_addr < baddr) {
				break;
			}
			RzAnalysisOp *op = op_cache_get(op_cache, core, instr_addr);
			if (!op) {
				break;
			}
			RzAnalysisOp *next_op = op_cache_get(op_cache, core, instr_addr + op->size);
			if (!next_op || (j != idx && (next_op->type == RZ_ANALYSIS_OP_TYPE_CALL || next_op->type == RZ_ANALYSIS_OP_TYPE_JMP))) {
				break;
			}
			RzAnalysisVar *var = rz_analysis_get_used_function_var(analysis, op->addr);

			// FIXME : It seems also assume only read memory once ?
			if (op->type == RZ_ANALYSIS_OP_TYPE_MOV && (instr_trace->stats & RZ_IL_TRACE_INS_HAS_MEM_R)) {
				memref = !(!memref && var && (var->kind != RZ_ANALYSIS_VAR_KIND_REG));
			}
			// Match type from function param to instr
			if (type_pos_hit(analysis, instr_trace, in_stack, size, place)) {
				if (!cmt_set && type && name) {
					char *typestr = rz_type_as_string(analysis->typedb, type);
					const char *maybe_space = type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
					rz_meta_set_string(analysis, RZ_META_TYPE_VARTYPE, instr_addr,
						sdb_fmt("%s%s%s", typestr, maybe_space, name));
					cmt_set = true;
					if ((op->ptr && op->ptr != UT64_MAX) && !strcmp(name, "format")) {
						RzFlagItem *f = rz_flag_get_by_spaces(core->flags, op->ptr, RZ_FLAGS_FS_STRINGS, NULL);
						if (f) {
							char formatstr[0x200];
							int read = rz_io_nread_at(core->io, f->offset, (ut8 *)formatstr, RZ_MIN(sizeof(formatstr) - 1, f->size));
							if (read > 0) {
								formatstr[read] = '\0';
								if ((types = parse_format(core, formatstr))) {
									max += rz_list_length(types);
								}
								format = true;
							}
						}
					}
					free(typestr);
				}
				if (var) {
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						var_type_set(analysis, var, type, memref);
						var_rename(analysis, var, name, addr);
					} else {
						// callee is a userfunction, propagate our variable's type into the callee's args
						retype_callee_arg(analysis, fcn_name, in_stack, place, size, var->type);
					}
					res = true;
				} else {
					get_src_regname(core, instr_addr, regname, sizeof(regname));
					xaddr = get_addr(analysis, regname, j);
				}
			}
			// Type propagate by following source reg
			if (!res && *regname && rz_analysis_il_get_reg_op_trace(instr_trace, regname, true)) {
				if (var) {
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						var_type_set(analysis, var, type, memref);
						var_rename(analysis, var, name, addr);
					} else {
						// callee is a userfunction, propagate our variable's type into the callee's args
						retype_callee_arg(analysis, fcn_name, in_stack, place, size, var->type);
					}
					res = true;
				} else {
					switch (op->type) {
					case RZ_ANALYSIS_OP_TYPE_MOV:
					case RZ_ANALYSIS_OP_TYPE_PUSH:
						get_src_regname(core, instr_addr, regname, sizeof(regname));
						break;
					case RZ_ANALYSIS_OP_TYPE_LEA:
					case RZ_ANALYSIS_OP_TYPE_LOAD:
					case RZ_ANALYSIS_OP_TYPE_STORE:
						res = true;
						break;
					}
				}
			} else if (var && res && xaddr && (xaddr != UT64_MAX)) { // Type progation using value
				char tmp[REGNAME_SIZE] = { 0 };
				get_src_regname(core, instr_addr, tmp, sizeof(tmp));
				ut64 ptr = get_addr(analysis, tmp, j);
				if (ptr == xaddr) {
					if (type) {
						var_type_set(analysis, var, type, memref);
					} else {
						var_type_set_str(analysis, var, "int", memref);
					}
				}
			}
		}
		size += analysis->bits / 8;
		rz_type_free(type);
		free(name);
	}
	if (owned) {
		rz_type_callable_free(callable);
	}
	rz_list_free(types);
	rz_cons_break_pop();
}

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RzAnalysisBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

void free_op_cache_kv(HtUPKv *kv) {
	rz_analysis_op_free(kv->value);
}

void handle_stack_canary(RzCore *core, RzAnalysisOp *aop, int cur_idx) {
	RzILTraceInstruction *prev_trace = rz_analysis_esil_get_instruction_trace(
		core->analysis->esil->trace,
		cur_idx - 1);

	ut64 mov_addr;
	if (prev_trace) {
		mov_addr = prev_trace->addr;
	} else {
		return;
	}

	RzAnalysisOp *mop = rz_core_analysis_op(core, mov_addr, RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_BASIC);
	if (mop) {
		RzAnalysisVar *mopvar = rz_analysis_get_used_function_var(core->analysis, mop->addr);
		ut32 type = mop->type & RZ_ANALYSIS_OP_TYPE_MASK;
		if (type == RZ_ANALYSIS_OP_TYPE_MOV) {
			var_rename(core->analysis, mopvar, "canary", aop->addr);
		}
	}
	rz_analysis_op_free(mop);
}

struct ReturnTypeAnalysisCtx {
	bool resolved;
	RzType *ret_type;
	char *ret_reg;
};

static inline bool return_type_analysis_context_unresolved(struct ReturnTypeAnalysisCtx *ctx) {
	return !ctx->resolved && ctx->ret_type && ctx->ret_reg;
}

// Progate return type passed using pointer
static void propagate_return_type_pointer(RzCore *core, RzAnalysisOp *aop, RzPVector *used_vars, ut64 addr, struct ReturnTypeAnalysisCtx *ctx) {
	// int *ret; *ret = strlen(s);
	// TODO: memref check , dest and next src match
	char nsrc[REGNAME_SIZE] = { 0 };
	void **uvit;
	get_src_regname(core, addr, nsrc, sizeof(nsrc));
	if (ctx->ret_reg && *nsrc && strstr(ctx->ret_reg, nsrc) && aop->direction == RZ_ANALYSIS_OP_DIR_READ) {
		if (used_vars && !rz_pvector_empty(used_vars)) {
			rz_pvector_foreach (used_vars, uvit) {
				RzAnalysisVar *var = *uvit;
				var_type_set(core->analysis, var, ctx->ret_type, true);
			}
		}
	}
}

// Forward propagation of function return type
static void propagate_return_type(RzCore *core, RzAnalysisOp *aop, RzAnalysisOp *next_op, RzILTraceInstruction *trace, struct ReturnTypeAnalysisCtx *ctx, RzPVector *used_vars) {
	char src[REGNAME_SIZE] = { 0 };
	void **uvit;

	// TODO : handle multiple registers case, this is a temporary solution
	RzILTraceRegOp *single_write_reg = NULL;
	if (trace && (trace->stats & RZ_IL_TRACE_INS_HAS_REG_W)) {
		single_write_reg = rz_pvector_at(trace->write_reg_ops, 0);
	}

	get_src_regname(core, aop->addr, src, sizeof(src));
	ut32 type = aop->type & RZ_ANALYSIS_OP_TYPE_MASK;
	if (ctx->ret_reg && *src && strstr(ctx->ret_reg, src)) {
		if (used_vars && !rz_pvector_empty(used_vars) && aop->direction == RZ_ANALYSIS_OP_DIR_WRITE) {
			rz_pvector_foreach (used_vars, uvit) {
				RzAnalysisVar *var = *uvit;
				var_type_set(core->analysis, var, ctx->ret_type, false);
			}
			ctx->resolved = true;
		} else if (type == RZ_ANALYSIS_OP_TYPE_MOV) {
			RZ_FREE(ctx->ret_reg);
			if (single_write_reg && single_write_reg->reg_name) {
				ctx->ret_reg = strdup(single_write_reg->reg_name);
			}
		}
	} else if (single_write_reg) {
		if (ctx->ret_reg &&
			(single_write_reg->reg_name && strstr(ctx->ret_reg, single_write_reg->reg_name))) {
			ctx->resolved = true;
		} else if (type == RZ_ANALYSIS_OP_TYPE_MOV &&
			(next_op && next_op->type == RZ_ANALYSIS_OP_TYPE_MOV)) {
			// Progate return type passed using pointer
			propagate_return_type_pointer(core, aop, used_vars, next_op->addr, ctx);
		}
	}
}

struct TypeAnalysisCtx {
	struct ReturnTypeAnalysisCtx *retctx;
	int cur_idx;
	const char *prev_dest;
	bool str_flag;
};

void propagate_types_among_used_variables(RzCore *core, HtUP *op_cache, RzAnalysisFunction *fcn, RzAnalysisBlock *bb, RzAnalysisOp *aop, struct TypeAnalysisCtx *ctx) {
	RzPVector *used_vars = rz_analysis_function_get_vars_used_at(fcn, aop->addr);
	bool chk_constraint = rz_config_get_b(core->config, "analysis.types.constraint");
	RzAnalysisOp *next_op = op_cache_get(op_cache, core, aop->addr + aop->size);
	void **uvit;
	RzType *prev_type = NULL;
	int prev_idx = 0;
	bool prev_var = false;
	char *fcn_name = NULL;
	bool userfnc = false;
	bool prop = false;
	ut32 type = aop->type & RZ_ANALYSIS_OP_TYPE_MASK;
	RzAnalysis *analysis = core->analysis;

	RzAnalysisEsilTrace *etrace = core->analysis->esil->trace;
	RzILTraceInstruction *cur_instr_trace = rz_analysis_esil_get_instruction_trace(etrace, ctx->cur_idx);

	if (aop->type == RZ_ANALYSIS_OP_TYPE_CALL || aop->type & RZ_ANALYSIS_OP_TYPE_UCALL) {
		char *full_name = NULL;
		ut64 callee_addr;
		if (aop->type == RZ_ANALYSIS_OP_TYPE_CALL) {
			RzAnalysisFunction *fcn_call = rz_analysis_get_fcn_in(core->analysis, aop->jump, -1);
			if (fcn_call) {
				full_name = fcn_call->name;
				callee_addr = fcn_call->addr;
			}
		} else if (aop->ptr != UT64_MAX) {
			RzFlagItem *flag = rz_flag_get_by_spaces(core->flags, aop->ptr, RZ_FLAGS_FS_IMPORTS, NULL);
			if (flag && flag->realname) {
				full_name = flag->realname;
				callee_addr = aop->ptr;
			}
		}
		// TODO: Apart from checking the types database, we should also derive the information
		// from the RzAnalysisFunction if nothing was found in the RzTypeDB
		if (full_name) {
			if (rz_type_func_exist(core->analysis->typedb, full_name)) {
				fcn_name = strdup(full_name);
			} else {
				fcn_name = rz_analysis_function_name_guess(core->analysis->typedb, full_name);
			}
			if (!fcn_name) {
				fcn_name = strdup(full_name);
				userfnc = true;
			}
			const char *Cc = rz_analysis_cc_func(core->analysis, fcn_name);
			if (Cc && rz_analysis_cc_exist(core->analysis, Cc)) {
				char *cc = strdup(Cc);
				type_match(core, fcn_name, aop->addr, bb->addr, cc, prev_idx, userfnc, callee_addr, op_cache);
				prev_idx = ctx->cur_idx;
				ctx->retctx->ret_type = rz_type_func_ret(core->analysis->typedb, fcn_name);
				RZ_FREE(ctx->retctx->ret_reg);
				const char *rr = rz_analysis_cc_ret(core->analysis, cc);
				if (rr) {
					ctx->retctx->ret_reg = strdup(rr);
				}
				ctx->retctx->resolved = false;
				free(cc);
			}
			if (!strcmp(fcn_name, "__stack_chk_fail")) {
				handle_stack_canary(core, aop, ctx->cur_idx);
			}
			free(fcn_name);
		}
	} else if (return_type_analysis_context_unresolved(ctx->retctx)) {
		// Forward propagation of function return type
		propagate_return_type(core, aop, next_op, cur_instr_trace, ctx->retctx, used_vars);
	}
	// Type propagation using instruction access pattern
	if (used_vars && !rz_pvector_empty(used_vars)) {
		rz_pvector_foreach (used_vars, uvit) {
			RzAnalysisVar *var = *uvit;
			bool sign = false;
			if ((type == RZ_ANALYSIS_OP_TYPE_CMP) && next_op) {
				if (next_op->sign) {
					sign = true;
				} else {
					// cmp [local_ch], rax ; jb
					// set to "unsigned"
					var_type_set_sign(core->analysis, var, false);
				}
			}
			// cmp [local_ch], rax ; jge
			if (sign || aop->sign) {
				// set to "signed"
				var_type_set_sign(core->analysis, var, true);
			}
			// lea rax , str.hello  ; mov [local_ch], rax;
			// mov rdx , [local_4h] ; mov [local_8h], rdx;
			if (ctx->prev_dest && (type == RZ_ANALYSIS_OP_TYPE_MOV || type == RZ_ANALYSIS_OP_TYPE_STORE)) {
				char reg[REGNAME_SIZE] = { 0 };
				get_src_regname(core, aop->addr, reg, sizeof(reg));
				bool match = strstr(ctx->prev_dest, reg) != NULL;
				if (ctx->str_flag && match) {
					var_type_set_str(core->analysis, var, "const char *", false);
				}
				if (prop && match && prev_var && prev_type) {
					// Here we clone the type
					var_type_set(core->analysis, var, prev_type, false);
				}
			}
			if (chk_constraint && var && (type == RZ_ANALYSIS_OP_TYPE_CMP && aop->disp != UT64_MAX) && next_op && next_op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
				bool jmp = false;
				RzAnalysisOp *jmp_op = { 0 };
				ut64 jmp_addr = next_op->jump;
				RzAnalysisBlock *jmpbb = rz_analysis_fcn_bbget_in(core->analysis, fcn, jmp_addr);

				// Check exit status of jmp branch
				int i;
				for (i = 0; i < MAX_INSTR; i++) {
					jmp_op = rz_core_analysis_op(core, jmp_addr, RZ_ANALYSIS_OP_MASK_BASIC);
					if (!jmp_op) {
						break;
					}
					if ((jmp_op->type == RZ_ANALYSIS_OP_TYPE_RET && rz_analysis_block_contains(jmpbb, jmp_addr)) || jmp_op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
						jmp = true;
						rz_analysis_op_free(jmp_op);
						break;
					}
					jmp_addr += jmp_op->size;
					rz_analysis_op_free(jmp_op);
				}
				RzTypeConstraint constr = {
					.cond = jmp ? rz_type_cond_invert(next_op->cond) : next_op->cond,
					.val = aop->val
				};
				rz_analysis_var_add_constraint(var, &constr);
			}
		}
	}
	prev_var = (used_vars && !rz_pvector_empty(used_vars) && aop->direction == RZ_ANALYSIS_OP_DIR_READ);
	ctx->str_flag = false;
	prop = false;
	ctx->prev_dest = NULL;
	switch (type) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (aop->ptr && aop->refptr && aop->ptr != UT64_MAX) {
			if (type == RZ_ANALYSIS_OP_TYPE_LOAD) {
				ut8 buf[256] = { 0 };
				rz_io_read_at(core->io, aop->ptr, buf, sizeof(buf) - 1);
				ut64 ptr = rz_read_ble(buf, core->print->big_endian, aop->refptr * 8);
				if (ptr && ptr != UT64_MAX) {
					RzFlagItem *f = rz_flag_get_by_spaces(core->flags, ptr, RZ_FLAGS_FS_STRINGS, NULL);
					if (f) {
						ctx->str_flag = true;
					}
				}
			} else if (rz_flag_exist_at(core->flags, "str", 3, aop->ptr)) {
				ctx->str_flag = true;
			}
		}

		// Assert : reg write only once here
		RzILTraceRegOp *w_reg = NULL;
		if (cur_instr_trace) {
			if (cur_instr_trace->stats & RZ_IL_TRACE_INS_HAS_REG_W) {
				w_reg = rz_pvector_at(cur_instr_trace->write_reg_ops, 0);
				if (w_reg) {
					ctx->prev_dest = rz_str_constpool_get(&analysis->constpool, w_reg->reg_name);
				}
			}
		}

		if (used_vars && !rz_pvector_empty(used_vars)) {
			rz_pvector_foreach (used_vars, uvit) {
				RzAnalysisVar *var = *uvit;
				// mov dword [local_4h], str.hello;
				if (ctx->str_flag) {
					var_type_set_str(core->analysis, var, "const char *", false);
				}
				prev_type = var->type;
				prop = true;
			}
		}
	}
}

RZ_API void rz_core_analysis_type_match(RzCore *core, RzAnalysisFunction *fcn, HtUU *loop_table) {
	RzListIter *it;

	rz_return_if_fail(core && core->analysis && fcn);

	if (!core->analysis->esil) {
		eprintf("Please run aeim\n");
		return;
	}

	RzAnalysis *analysis = core->analysis;
	RzReg *reg = analysis->reg;
	const int mininstrsz = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return;
	}
	RzDebugTrace *dt = NULL;
	RzAnalysisEsilTrace *et = NULL;
	RzAnalysisRzilTrace *rt = NULL;
	if (!analysis_emul_init(core, hc, &dt, &et, &rt) || !fcn) {
		analysis_emul_restore(core, hc, dt, et, rt);
		return;
	}

	// Reserve bigger ht to avoid rehashing
	HtPPOptions opt;
	RzDebugTrace *dtrace = core->dbg->trace;
	opt = dtrace->ht->opt;
	ht_pp_free(dtrace->ht);
	dtrace->ht = ht_pp_new_size(fcn->ninstr, opt.dupvalue, opt.freefn, opt.calcsizeV);
	dtrace->ht->opt = opt;

	// Create a new context to store the return type propagation state
	struct ReturnTypeAnalysisCtx retctx = {
		.resolved = false,
		.ret_type = NULL,
		.ret_reg = NULL,
	};
	struct TypeAnalysisCtx ctx = {
		.retctx = &retctx,
		.cur_idx = 0,
		.prev_dest = NULL,
		.str_flag = false
	};

	HtUP *op_cache = NULL;
	const char *pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
	if (!pc) {
		goto out_function;
	}
	RzRegItem *r = rz_reg_get(reg, pc, -1);
	if (!r) {
		goto out_function;
	}
	rz_cons_break_push(NULL, NULL);
	rz_list_sort(fcn->bbs, bb_cmpaddr);
	// TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	RzAnalysisBlock *bb;
	rz_list_foreach (fcn->bbs, it, bb) {
		ut64 addr = bb->addr;
		rz_reg_set_value(reg, r, addr);
		ht_up_free(op_cache);
		op_cache = ht_up_new(NULL, free_op_cache_kv, NULL);
		if (!op_cache) {
			break;
		}
		while (1) {
			if (rz_cons_is_breaked()) {
				goto out_function;
			}
			ut64 pcval = rz_reg_getv(reg, pc);
			if ((addr >= bb->addr + bb->size) || (addr < bb->addr) || pcval != addr) {
				break;
			}
			RzAnalysisOp *aop = op_cache_get(op_cache, core, addr);
			if (!aop) {
				break;
			}
			if (aop->type == RZ_ANALYSIS_OP_TYPE_ILL) {
				addr += minopcode;
				continue;
			}

			// CHECK_ME : why we hold a loop_count here ?
			//          : can we remove it ?
			// when set null, do not track loop count
			if (loop_table) {
				ut64 loop_count = ht_uu_find(loop_table, addr, NULL);
				if (loop_count > LOOP_MAX || aop->type == RZ_ANALYSIS_OP_TYPE_RET) {
					break;
				}
				loop_count += 1;
				ht_uu_update(loop_table, addr, loop_count);
			}

			if (rz_analysis_op_nonlinear(aop->type)) { // skip the instr
				rz_reg_set_value(reg, r, addr + aop->size);
			} else {
				rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			}

			RzPVector *ins_traces = analysis->esil->trace->instructions;
			ctx.cur_idx = rz_pvector_len(ins_traces) - 1;
			RzList *fcns = rz_analysis_get_functions_in(analysis, aop->addr);
			if (!fcns) {
				break;
			}
			RzListIter *it;
			RzAnalysisFunction *fcn;
			rz_list_foreach (fcns, it, fcn) {
				propagate_types_among_used_variables(core, op_cache, fcn, bb, aop, &ctx);
			}
			addr += aop->size;
			rz_list_free(fcns);
		}
	}
	// Type propagation for register based args
	void **vit;
	rz_pvector_foreach (&fcn->vars, vit) {
		RzAnalysisVar *rvar = *vit;
		if (rvar->kind == RZ_ANALYSIS_VAR_KIND_REG) {
			RzAnalysisVar *lvar = rz_analysis_var_get_dst_var(rvar);
			RzRegItem *i = rz_reg_index_get(reg, rvar->delta);
			if (!i) {
				continue;
			}
			// Note that every `var_type_set()` call could remove some variables
			// due to the overlaps resolution
			if (lvar) {
				// Propagate local var type = to => register-based var
				var_type_set(analysis, rvar, lvar->type, false);
				// Propagate local var type <= from = register-based var
				var_type_set(analysis, lvar, rvar->type, false);
			}
		}
	}
out_function:
	free(retctx.ret_reg);
	ht_up_free(op_cache);
	rz_cons_break_pop();
	analysis_emul_restore(core, hc, dt, et, rt);
}
