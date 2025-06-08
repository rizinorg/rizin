// SPDX-FileCopyrightText: 2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

/**
 * \brief Used to describe current state of tainting
 */
typedef enum {
	RZ_TAINT_MODE_OFF, ///< No tainting in this mode
	RZ_TAINT_MODE_RED, ///< Mode when `new` is identified but constructor is yet to be identified
	RZ_TAINT_MODE_BLUE, ///< Mode after constructor is also identified, write to variable is yet to be identified
} RzTaintDevirt;

typedef struct var_t {
	char *name; ///< for now, checks varibles discovered by ESIL
	ut64 stack_addr; ///< address of the stack where variable is stored according to RzIL VM
	ut64 instr_addr; ///< address of instruction which writes to variable
	RzList *class_names; ///< Single variable might store multiple classes based on conditionals
} Variable;

typedef struct rz_variable_book_t {
	RzAnalysisFunction *function;
	HtUP /*<ut64, RzVariable*>*/ *class_variables;
	RzList *stack_variables;
} RzVariableBook;

typedef struct rz_taint_state_t {
	RzTaintDevirt taint;
	RzAnalysisOp *op;
	ut64 addr;
	char *class_name;
	RzVariableBook *var_book;
} RzTaintState;

#define RZ_TAINT_VALUE 0x1A2B3C

RzList *list_of_operator_new_functions(RzCore *core) {
	RzList *list = rz_analysis_function_list(core->analysis);
	if (!list) {
		return NULL;
	}
	RzListIter *it;
	RzAnalysisFunction *fcn;
	RzList *ret_list = rz_list_new();
	rz_list_foreach (list, it, fcn) {
		char *res = strstr(fcn->name, "sym.imp.operator_new");
		if (res != NULL) {
			rz_list_push(ret_list, it->elem);
		}
	}
	return ret_list;
}

static bool rz_taint_vm_step(RzCore *core, RzTaintDevirt *taint) {
	if (!rz_core_il_step(core, 1)) {
		return false;
	}

	if (!core->analysis || !core->analysis->il_vm) {
		return false;
	}

	RzILVM *vm = core->analysis->il_vm->vm;

	void **it;
	RzILEvent *evt;

	rz_config_set_cb(core->config, "rzil.step.events.read", "true", NULL);
	rz_config_set_cb(core->config, "rzil.step.events.write", "true", NULL);

	rz_pvector_foreach (vm->events, it) {
		evt = *it;
		switch (evt->type) {
		case RZ_IL_EVENT_MEM_WRITE: {
			ut64 new_val = rz_bv_to_ut64(evt->data.mem_write.new_value);
			if (new_val == RZ_TAINT_VALUE) {
				return true;
			}
		}
		default: {
			break;
		}
		}
	}
	return false;
}

static void xrefs_of_new(RzList *list, RzAnalysis *analysis, ut64 addr) {
	RzList *curr_list = rz_analysis_xrefs_get_to(analysis, addr);
	RzListIter *it;
	RzAnalysisXRef *xref;
	rz_list_foreach (curr_list, it, xref) {
		rz_list_append(list, &(xref->from));
	}
}

static int compare(const void *void_value, const void *void_list_data, void *user) {
	const ut64 *value = void_value;
	const ut64 *list_data = void_list_data;
	if (*value == *list_data) {
		return 0;
	} else if (*value > *list_data) {
		return 1;
	} else {
		return -1;
	}
}

void rz_taint_init(RzAnalysis *analysis, RzCore *core) {
	rz_core_analysis_esil_init_mem(core, NULL, 0x1000, 0x1050); // Memory allocation
	rz_core_analysis_il_reinit(core); // initializing VM
	// TODO : Make general for other archs
	if (!rz_str_cmp(analysis->arch_target->arch, "x86", -1)) {
		rz_core_analysis_il_vm_set(core, "rbp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "rsp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "rax", RZ_TAINT_VALUE);
	} else if (!rz_str_cmp(analysis->arch_target->arch, "arm", -1)) {
		rz_core_analysis_il_vm_set(core, "fp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "sp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "x0", RZ_TAINT_VALUE);
	}
}

RzList *get_variable_writes(RzAnalysisFunction *fcn) {
	void **it;
	RzList *var_list = rz_list_new();
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
			if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE)) {
				continue;
			}
			ut64 addr = fcn->addr + acc->offset;
			Variable *write_var = RZ_NEW0(Variable);
			write_var->instr_addr = addr;
			write_var->name = rz_str_dup(var->name);
			write_var->class_names = rz_list_new();
			rz_list_push(var_list, write_var);
		}
	}
	return var_list;
}

static Variable *var_at_write(RzTaintState *state, RzList *var_write_list, ut64 stack_addr) {
	HtUP *stack_vars = state->var_book->class_variables;
	bool found = false;
	Variable *ht_var = ht_up_find(stack_vars, stack_addr, &found);
	if (found) {
		return ht_var;
	}
	RzListIter *it;
	Variable *var;
	rz_list_foreach (var_write_list, it, var) {
		if (var->instr_addr == state->addr) {
			var->stack_addr = stack_addr;
			ht_up_insert(stack_vars, stack_addr, var);
			return var;
		}
	}
	return NULL;
}

static char *get_class_name_from_func(const char *func_name) {
	// Get class name from method.class_name.init
	const char *first = strchr(func_name, '.');
	if (!first) {
		return NULL;
	}

	const char *second = strchr(first + 1, '.');
	if (!second) {
		return NULL;
	}

	uint32_t len = second - first - 1;
	if (len == 0) {
		return NULL;
	}

	char *class_name = malloc(len + 1);
	rz_str_ncpy(class_name, first + 1, len + 1);

	return class_name;
}

static char *get_class_name(RzAnalysis *analysis, ut64 addr) {
	RzList *list = rz_analysis_xrefs_get_from(analysis, addr);
	RzListIter *it;
	RzAnalysisXRef *xref;
	RzCore *core = analysis->core;
	rz_list_foreach (list, it, xref) {
		RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, xref->to, RZ_ANALYSIS_FCN_TYPE_ROOT);
		if (!function) {
			function = rz_analysis_get_fcn_in(core->analysis, xref->to, 0);
		}
		char *class_name = get_class_name_from_func(function->name);
		if (class_name) {
			return class_name;
		}
		free(class_name);
	}
	return NULL;
}

static bool is_call_instruction(RzAnalysisOp *op) {
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_CALL:
		return true;
	case RZ_ANALYSIS_OP_TYPE_RCALL:
		return true;
	case RZ_ANALYSIS_OP_TYPE_JMP:
		return true;
	default:
		return false;
	}
}

static void add_taint_value(RzAnalysis *analysis) {
	RzCore *core = analysis->core;
	if (!rz_str_cmp(analysis->arch_target->arch, "x86", -1)) {
		rz_core_analysis_il_vm_set(core, "rax", RZ_TAINT_VALUE);
	} else if (!rz_str_cmp(analysis->arch_target->arch, "arm", -1)) {
		rz_core_analysis_il_vm_set(core, "x0", RZ_TAINT_VALUE);
	}
}

static ut64 rz_var_stack_address_track(RzAnalysis *analysis) {
	RzCore *core = analysis->core;
	if (!rz_core_il_step(core, 1)) {
		return -1;
	}

	if (!core->analysis || !core->analysis->il_vm) {
		return -1;
	}

	RzILVM *vm = core->analysis->il_vm->vm;

	void **it;
	RzILEvent *evt;

	rz_config_set_cb(core->config, "rzil.step.events.read", "true", NULL);
	rz_config_set_cb(core->config, "rzil.step.events.write", "true", NULL);

	rz_pvector_foreach (vm->events, it) {
		evt = *it;
		switch (evt->type) {
		case RZ_IL_EVENT_MEM_WRITE: {
			return rz_bv_to_ut64(evt->data.mem_write.address);
			break;
		}
		default: {
			break;
		}
		}
	}
	return -1;
}

static void add_class_name_to_var(Variable *var, char *name) {
	RzList *class_names = var->class_names;
	RzListIter *it;
	char *elem_name;
	rz_list_foreach (class_names, it, elem_name) {
		if (RZ_STR_EQ(name, elem_name)) {
			return;
		}
	}
	rz_list_insert(class_names, 1, rz_str_dup(name));
}

static void define_and_mark_variable(RzAnalysis *analysis, RzTaintState *state, const Variable *var) {
	RzList *class_names = var->class_names;
	ut64 len = rz_list_length(class_names);
	char *type = NULL;
	char *class_name = rz_list_get_n(class_names, 0);
	char *old_type = NULL;
	char *var_type = NULL;

	if (len == 1) {
		type = rz_str_newf("struct %s{}", class_name);
		old_type = class_name;
		var_type = rz_str_newf("%s*", class_name);
	} else {
		type = rz_str_newf("union RZ_%s_HYBRID{%s* %s;", var->name, class_name, var->name);

		for (size_t i = 1; i < len; i++) {
			char *other_class_name = rz_list_get_n(class_names, i);
			type = rz_str_append(type, rz_str_newf(" %s* %s;", other_class_name, var->name));
		}
		rz_str_append(type, "}");
		old_type = rz_str_newf("RZ_%s_HYBRID", var->name);
		var_type = old_type;
	}

	char *exists = rz_type_format(analysis->typedb, old_type);
	if (exists) {
		rz_type_db_del(analysis->typedb, old_type);
	}
	rz_types_define(analysis->core, type);
	RzType *v_type = rz_type_parse_string_single(analysis->typedb->parser, var_type, NULL);
	RzAnalysisVar *v = rz_analysis_function_get_var_byname(state->var_book->function, var->name);
	rz_analysis_var_set_type(v, v_type, true);
}

static bool rz_taint_off_step(RzAnalysis *analysis, RzTaintState *state) {
	RzList *list = list_of_operator_new_functions(analysis->core);
	RzList *list_xrefs = rz_list_new();
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		xrefs_of_new(list_xrefs, analysis, fcn->addr);
	}
	ut64 *p_addr = &(state->addr);
	RzAnalysisOp *op = state->op;
	RzCore *core = analysis->core;
	if (rz_list_find(list_xrefs, p_addr, compare, NULL) != NULL) {
		state->taint = RZ_TAINT_MODE_RED;
		add_taint_value(analysis);
		return true;
	}
	if (is_call_instruction(op)) {
		return true;
	}
	rz_taint_vm_step(core, &(state->taint));
	return false;
}

static bool rz_taint_red_step(RzAnalysis *analysis, RzTaintState *state) {
	RzAnalysisOp *op = state->op;
	RzCore *core = analysis->core;
	if (is_call_instruction(op)) {
		char *temp = get_class_name(analysis, state->addr);
		if (!temp) {
			return true;
		}
		if (state->class_name != NULL) {
			free(state->class_name);
		}
		state->class_name = temp;
		state->taint = RZ_TAINT_MODE_BLUE;
		return true;
	}
	rz_taint_vm_step(core, &(state->taint));
	return false;
}

static bool rz_taint_blue_step(RzAnalysis *analysis, RzTaintState *state) {
	RzCore *core = analysis->core;
	RzAnalysisOp *op = state->op;

	if (is_call_instruction(op)) {
		return true;
	}
	bool ret = rz_taint_vm_step(core, &(state->taint));
	if (!ret) {
		return false;
	}

	ut64 stack_addr = rz_var_stack_address_track(analysis);
	Variable *var = var_at_write(state, state->var_book->stack_variables, stack_addr);
	add_class_name_to_var(var, state->class_name);
	define_and_mark_variable(analysis, state, var);
	state->taint = RZ_TAINT_MODE_OFF;
	return false;
}

RZ_API void rz_analysis_mark_classes(RzAnalysis *analysis) {

	RzList *list = list_of_operator_new_functions(analysis->core);

	RzList *list_xrefs = rz_list_new();
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		xrefs_of_new(list_xrefs, analysis, fcn->addr);
	}

	RzCore *core = analysis->core;
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!function) {
		function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	}
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}

	RzTaintState *state = RZ_NEW0(RzTaintState);
	state->addr = function->addr; // start of the function
	ut64 end = rz_analysis_function_max_addr(function);
	RzAnalysisOp *op = rz_analysis_op_new();
	state->op = op;
	state->taint = RZ_TAINT_MODE_OFF;
	core->offset = state->addr;
	RzList *var_write_list = get_variable_writes(function);

	bool refresh_vm = false;

	ut8 *bytes = malloc(end - state->addr);
	rz_io_read_at(core->io, state->addr, bytes, end - state->addr);
	ut64 offset = 0;

	rz_taint_init(analysis, core);

	RzVariableBook *var_book = RZ_NEW0(RzVariableBook);
	var_book->class_variables = ht_up_new(NULL, NULL);
	var_book->function = function;
	var_book->stack_variables = var_write_list;
	state->var_book = var_book;

	while (state->addr < end) {
		rz_analysis_op(analysis, op, state->addr, bytes + offset, end - state->addr, RZ_ANALYSIS_OP_MASK_ALL);
		if (refresh_vm) {
			rz_core_analysis_il_reinit(core);
			refresh_vm = false;
		}
		switch (state->taint) {
		case RZ_TAINT_MODE_OFF: {
			refresh_vm = rz_taint_off_step(analysis, state);
			break;
		}
		case RZ_TAINT_MODE_RED: {
			refresh_vm = rz_taint_red_step(analysis, state);
			break;
		}
		case RZ_TAINT_MODE_BLUE: {
			refresh_vm = rz_taint_blue_step(analysis, state);
			break;
		}
		default: {
			break;
		}
		}
		state->addr += op->size;
		offset += op->size;
		core->offset = state->addr;
	}
	core->offset = function->addr;
	rz_core_analysis_il_reinit(core);

	// TODO : Check for leaks
	// TODO : Implement free for lists
	rz_analysis_op_fini(op);
	rz_list_free(list);
	free(bytes);
}

RZ_API void rz_analysis_devirtualize_methods(RzAnalysis *analysis) {
	// TODO : Generalize for classes

	rz_analysis_mark_classes(analysis);
}