// SPDX-FileCopyrightText: 2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

/**
 * \file
 * Partially uses ESIL uplifting but will be ported to RzIL
 */

/**
 * \brief Used to describe current state of tainting
 */
typedef enum rz_taint_devirt_t {
	RZ_TAINT_MODE_OFF, ///< No tainting in this mode
	RZ_TAINT_MODE_RED, ///< Mode when `new` is identified but constructor is yet to be identified
	RZ_TAINT_MODE_BLUE, ///< Mode after constructor is also identified, write to variable is yet to be identified
} RzTaintDevirt;

typedef struct var_t {
	char *name; ///< for now, checks varibles discovered by ESIL
	ut64 stack_addr; ///< address of the stack where variable is stored according to RzIL VM
	ut64 instr_addr; ///< address of instruction which writes to variable
	RzList /*<char *>*/ *class_names; ///< Single variable might store multiple classes based on conditionals
	RzList /*<ut64 *>*/ *object_addr; ///< Address of allocated object which stores vtable ptr
} CppVariable;

typedef struct rz_taint_state_t {
	RzTaintDevirt taint; ///< current taint mode
	RzAnalysisOp *op; ///< analysis instruction op
	ut64 addr; ///< current instruction address
	char *class_name; ///< class name to be stored in variable
	RzCppVariableBook *var_book; ///< collection of all stack variables
} RzTaintState;

typedef struct rz_virtual_calls_t {
	HtUP /*<ut64,RzSetS *>*/ *virt_calls; ///< hash map of instruction address and class method name
} RzVirtualCalls;

#define RZ_TAINT_VALUE 0x1A2B3C

/**
 * \return list of `RzAnalysisFunction *` of all allocator i.e. `new` functions
 */
RzList /*<RzAnalysisFunction *>*/ *list_new_fcns(RzCore *core) {
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

static void rz_taint_vm_step(RzCore *core) {
	if (!rz_core_il_step(core, 1)) {
		return;
	}

	if (!core->analysis || !core->analysis->il_vm) {
		return;
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
				return;
			}
		}
		default: {
			break;
		}
		}
	}
}

/**
 * \brief adds xrefs to an addr to `list`
 */
static void xrefs_of_new(RZ_OUT RzList /*<RzAnalysisFunction *>*/ *list, RzAnalysis *analysis, ut64 addr) {
	RzList *curr_list = rz_analysis_xrefs_get_to(analysis, addr);
	RzListIter *it;
	RzAnalysisXRef *xref;
	rz_list_foreach (curr_list, it, xref) {
		ut64 *p_addr = RZ_NEW0(ut64);
		*p_addr = xref->from;
		rz_list_append(list, p_addr);
	}
	rz_list_free(curr_list);
}

static void free_xrefs_of_new(RzList /*<ut64 *>*/ *list_xrefs) {
	RzListIter *it;
	ut64 *addr = NULL;
	rz_list_foreach (list_xrefs, it, addr) {
		free(addr);
	}
	rz_list_free(list_xrefs);
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

/**
 * \brief initialises stack and registers for tainting
 */
void rz_taint_init(RzAnalysis *analysis, RzCore *core) {
	// Random Memory allocation representing function stack
	rz_core_analysis_esil_init_mem(core, NULL, 0x1000, 0x1050);
	rz_core_analysis_il_reinit(core); // initializing VM
	// TODO : Make general for other archs
	if (!rz_str_cmp(analysis->arch_target->arch, "x86", -1)) {
		rz_core_analysis_il_vm_set(core, "rbp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "rsp", 0x1fff);
	} else if (!rz_str_cmp(analysis->arch_target->arch, "arm", -1)) {
		rz_core_analysis_il_vm_set(core, "fp", 0x1fff);
		rz_core_analysis_il_vm_set(core, "sp", 0x1fff);
	}
}

/**
 * \return list of all stack variables written in the function call
 */
static RzList /*<CppVariable *>*/ *get_variable_writes(RzAnalysisFunction *fcn) {
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
			CppVariable *write_var = RZ_NEW0(CppVariable);
			write_var->instr_addr = addr;
			write_var->name = rz_str_dup(var->name);
			write_var->class_names = rz_list_new();
			write_var->object_addr = rz_list_new();
			rz_list_push(var_list, write_var);
		}
	}
	return var_list;
}

/**
 * \param state current tainting state
 * \param var_write_list list of all stack variables\
 * \param stack_addr stack address accessed during write operation
 * \return returns variable with stack address \p stack_addr
 */
static CppVariable *var_at_write(RzTaintState *state, RzList /*<CppVariable *>*/ *var_write_list, ut64 stack_addr) {
	HtUP *stack_vars = state->var_book->class_variables;
	bool found = false;
	CppVariable *ht_var = ht_up_find(stack_vars, stack_addr, &found);
	if (found) {
		return ht_var;
	}
	RzListIter *it;
	CppVariable *var;
	rz_list_foreach (var_write_list, it, var) {
		if (var->instr_addr == state->addr) {
			var->stack_addr = stack_addr;
			ht_up_insert(stack_vars, stack_addr, var);
			rz_list_insert(state->var_book->class_var_list, 0, var);
			return var;
		}
	}
	return NULL;
}

// TODO : Convert this into a hashmap of func name v/s class name
/**
 * \brief returns class name from function name
 */
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

/**
 * \param addr instruction address of constructor call
 * \return class name if a valid constructor call else `NULL`
 */
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
			rz_list_free(list);
			return class_name;
		}
	}
	rz_list_free(list);
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

/**
 * \brief changes the value in register to `RZ_TAINT_VALUE` during tainting
 */
static void taint_register(RzAnalysis *analysis) {
	RzCore *core = analysis->core;
	if (!rz_str_cmp(analysis->arch_target->arch, "x86", -1)) {
		rz_core_analysis_il_vm_set(core, "rax", RZ_TAINT_VALUE);
	} else if (!rz_str_cmp(analysis->arch_target->arch, "arm", -1)) {
		rz_core_analysis_il_vm_set(core, "x0", RZ_TAINT_VALUE);
	}
}

/**
 * \return stack address of memory write operation else 0
 */
static ut64 rz_var_stack_address_track(RzAnalysis *analysis) {
	RzCore *core = analysis->core;
	if (!rz_core_il_step(core, 1)) {
		return 0;
	}

	if (!core->analysis || !core->analysis->il_vm) {
		return 0;
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
		}
		default: {
			break;
		}
		}
	}
	return 0;
}

/**
 * \param var variable containing object(s)
 * \brief adds class name to \p var (can have multiple class names)
 */
static void add_class_name_to_var(CppVariable *var, char *name) {
	RzList *class_names = var->class_names;
	RzListIter *it;
	char *elem_name;
	rz_list_foreach (class_names, it, elem_name) {
		if (RZ_STR_EQ(name, elem_name)) {
			return;
		}
	}
	rz_list_insert(class_names, 0, rz_str_dup(name));
}

/**
 * \param state current tainting state
 * \param var variable to be marked
 * \brief labels the type of the variable with appropriate class name
 */
static void define_and_mark_variable(RzAnalysis *analysis, RzTaintState *state, const CppVariable *var) {
	RzList *class_names = var->class_names;
	ut64 len = rz_list_length(class_names);
	char *type = NULL;
	char *class_name = rz_list_get_n(class_names, 0);
	char *old_type = NULL;
	char *var_type = NULL;

	if (len == 1) {
		type = rz_str_newf("struct %s{}", class_name);
		old_type = rz_str_dup(class_name);
		var_type = rz_str_newf("%s*", class_name);
	} else {
		type = rz_str_newf("union RZ_%s_HYBRID{%s* %s;", var->name, class_name, var->name);

		for (size_t i = 1; i < len; i++) {
			char *other_class_name = rz_list_get_n(class_names, i);
			type = rz_str_append(type, rz_str_newf(" %s* %s;", other_class_name, var->name));
		}
		type = rz_str_append(type, "}");
		old_type = rz_str_newf("RZ_%s_HYBRID", var->name);
		var_type = rz_str_dup(old_type);
	}

	char *exists = rz_type_format(analysis->typedb, old_type);
	if (exists) {
		rz_type_db_del(analysis->typedb, old_type);
	}
	rz_types_define(analysis->core, type);
	RzType *v_type = rz_type_parse_string_single(analysis->typedb->parser, var_type, NULL);
	RzAnalysisVar *v = rz_analysis_function_get_var_byname(state->var_book->function, var->name);
	rz_analysis_var_set_type(v, v_type, true);

	free(type);
	free(old_type);
	free(var_type);
}

/**
 * \param state current taint state
 * \brief tainting step when state if `RZ_TAINT_MODE_OFF`
 * \return `true` if skipping an instruction is required else `false`
 */
static bool rz_taint_off_step(RzAnalysis *analysis, RzTaintState *state) {
	RzList *list = list_new_fcns(analysis->core);
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
		taint_register(analysis);
		free_xrefs_of_new(list_xrefs);
		rz_list_free(list);
		return true;
	}
	if (is_call_instruction(op)) {
		free_xrefs_of_new(list_xrefs);
		rz_list_free(list);
		return true;
	}
	rz_taint_vm_step(core);
	free_xrefs_of_new(list_xrefs);
	rz_list_free(list);
	return false;
}

/**
 * \param state current taint state
 * \brief tainting step when state if `RZ_TAINT_MODE_RED`
 * \return `true` if skipping an instruction is required else `false`
 */
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
	rz_taint_vm_step(core);
	return false;
}

/**
 * \param state current taint state
 * \brief tainting step when state if `RZ_TAINT_MODE_BLUE`
 * \return `true` if skipping an instruction is required else `false`
 */
static bool rz_taint_blue_step(RzAnalysis *analysis, RzTaintState *state) {
	RzAnalysisOp *op = state->op;

	if (is_call_instruction(op)) {
		return true;
	}

	ut64 stack_addr = rz_var_stack_address_track(analysis);

	if (stack_addr == 0) {
		return false;
	}
	CppVariable *var = var_at_write(state, state->var_book->stack_variables, stack_addr);
	add_class_name_to_var(var, state->class_name);
	define_and_mark_variable(analysis, state, var);
	state->taint = RZ_TAINT_MODE_OFF;
	return false;
}

static void free_taint_state(RzTaintState *state) {
	if (state->class_name != NULL) {
		free(state->class_name);
	}
	rz_analysis_op_free(state->op);
	free(state);
}

static void free_variable(CppVariable *var) {
	RzListIter *it;

	// Free class names
	char *name;
	rz_list_foreach (var->class_names, it, name) {
		free(name);
	}
	rz_list_free(var->class_names);

	// Free object addresses
	ut64 *p_addr;
	rz_list_foreach (var->object_addr, it, p_addr) {
		free(p_addr);
	}
	rz_list_free(var->object_addr);

	// Free variable name
	free(var->name);

	free(var);
}

/**
 * \param analysis rizin analysis object
 * \brief marks all variables that store object(s) with respective class name(s)
 * \return pointer to `RzCppVariableBook` book containing marked variable information
 */
RZ_API RzCppVariableBook *rz_analysis_mark_classes(RzAnalysis *analysis) {

	RzList *list = list_new_fcns(analysis->core);

	RzCore *core = analysis->core;
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!function) {
		function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	}
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return NULL;
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

	RzCppVariableBook *var_book = RZ_NEW0(RzCppVariableBook);
	var_book->class_variables = ht_up_new(NULL, NULL);
	var_book->function = function;
	var_book->stack_variables = var_write_list;
	var_book->class_var_list = rz_list_new();
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
		rz_analysis_op_fini(op);
	}
	core->offset = function->addr;
	rz_core_analysis_il_reinit(core);

	// TODO : Check for leaks
	// TODO : Implement free for lists
	free_taint_state(state);
	rz_list_free(list);
	free(bytes);
	return var_book;
}

/**
 * \param vtables `RzVector` of virtual tables
 * \param var variable to be simulated
 * \param addr start of simulated object
 * \brief stores virtual table addresses on simulated object memory
 * \return address for starting vtable store for next variable
 */
static ut64 store_objects(RzCore *core, RzVector /*<RzAnalysisVtable>*/ *vtables, CppVariable *var, ut64 addr) {
	RzAnalysisVTable *vtable;
	rz_vector_foreach (vtables, vtable) {
		ut8 buf[8];
		rz_write_le64(buf, vtable->addr);
		char str[17]; // 2 chars per byte + null terminator
		for (int i = 0; i < 8; i++) {
			sprintf(&str[i * 2], "%02x", buf[i]);
		}
		str[16] = '\0'; // null-terminate

		rz_core_write_hexpair(core, addr, str);
		ut64 *ptr = RZ_NEW0(ut64);
		*ptr = addr;
		rz_list_insert(var->object_addr, 0, ptr);
		addr += 0x8;
	}
	return addr;
}

/**
 * \param var_book collection of stack variables
 * \brief allocates simulated objects of all class variables
 */
static void allocate_objects(RzAnalysis *analysis, RzCppVariableBook *var_book) {
	RzList *var_list = var_book->class_var_list;
	RzListIter *it;
	CppVariable *var;
	ut64 addr = 0x3000;
	rz_list_foreach (var_list, it, var) {
		RzListIter *itt;
		char *name;
		rz_list_foreach (var->class_names, itt, name) {
			RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, name);
			addr = store_objects(analysis->core, vtables, var, addr);
			if (vtables != NULL) {
				rz_vector_free(vtables);
			}
		}
	}
}

static void fill_value_at_stack_address(RzCore *core, ut64 stack_addr, ut64 value) {
	ut8 buf[8];
	rz_write_le64(buf, value);
	char str[17];
	for (int i = 0; i < 8; i++) {
		sprintf(&str[i * 2], "%02x", buf[i]);
	}
	str[16] = '\0';
	rz_core_write_hexpair(core, stack_addr, str);
}

/**
 * \param var_book collection of stack variables
 * \param m_var variable getting analysed
 * \param obj_addr address of start simulated object
 * \brief preserves values in all variables and makes sure that \p m_var is marked as \p obj_addr (useful for conditional object storing)
 */
static void rz_preserve_stack(RzAnalysis *analysis, RzCppVariableBook *var_book, CppVariable *m_var, ut64 obj_addr) {
	// Preserve stack and set value for var as obj_addr
	RzCore *core = analysis->core;
	RzListIter *it;
	CppVariable *var;
	rz_list_foreach (var_book->class_var_list, it, var) {
		RzListIter *itt;
		ut64 *curr_obj_addr;
		rz_list_foreach (var->object_addr, itt, curr_obj_addr) {
			fill_value_at_stack_address(core, var->stack_addr, *curr_obj_addr);
		}
	}
	fill_value_at_stack_address(core, m_var->stack_addr, obj_addr);
}

/**
 * \param var_book collection of stack variables
 * \param var variable to be analyzed for devirtualization
 * \param obj_addr start address of simulated object
 * \param virt_calls devirtualization information
 * \brief devirtualizes all virtual calls for a variable \p var and stores information in \p virt_calls
 */
static void devirtualize_variable_vtable(RzAnalysis *analysis, RzCppVariableBook *var_book, CppVariable *var, ut64 obj_addr, RzVirtualCalls *virt_calls) {
	RzCore *core = analysis->core;

	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!function) {
		function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	}
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}

	ut64 start = function->addr; // start of the function
	ut64 end = rz_analysis_function_max_addr(function);
	RzAnalysisOp *op = rz_analysis_op_new();

	ut8 *bytes = malloc(end - start);
	rz_io_read_at(core->io, start, bytes, end - start);
	ut64 offset = 0;

	rz_taint_init(analysis, core);
	rz_preserve_stack(analysis, var_book, var, obj_addr);

	bool refresh_vm = false;

	while (start < end) {
		rz_analysis_op(analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL);
		if (refresh_vm) {
			rz_core_analysis_il_reinit(core);
			refresh_vm = false;
		}
		refresh_vm = is_call_instruction(op);

		rz_core_il_step(core, 1);
		rz_preserve_stack(analysis, var_book, var, obj_addr);

		if (op->type == RZ_ANALYSIS_OP_TYPE_RCALL) {
			// devirtualizing
			RzAnalysisILVM *vm = core->analysis->il_vm;
			RzILVal *reg = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, op->reg);
			if (reg) {

				RzBitVector *bv = rz_il_value_to_bv(reg);
				ut64 vf_addr = rz_bv_to_ut64(bv);
				rz_core_analysis_il_vm_set(core, op->reg, 0);
				rz_bv_free(bv);

				RzAnalysisFunction *vfunc = rz_analysis_get_fcn_in(core->analysis, vf_addr, RZ_ANALYSIS_FCN_TYPE_ROOT);
				if (!vfunc) {
					vfunc = rz_analysis_get_fcn_in(core->analysis, vf_addr, 0);
				}
				if (vfunc) {
					bool found = false;
					RzSetS *curr_set = ht_up_find(virt_calls->virt_calls, start, &found);
					if (found) {
						rz_set_s_add(curr_set, vfunc->name);
					} else {
						RzSetS *set = rz_set_s_new(HT_STR_DUP);
						rz_set_s_add(set, vfunc->name);
						ht_up_insert(virt_calls->virt_calls, start, set);
					}
				}
			}
		}
		start += op->size;
		offset += op->size;
		core->offset = start;
		rz_analysis_op_fini(op);
	}

	core->offset = function->addr;
	rz_core_analysis_il_reinit(core);
	free(bytes);
	rz_analysis_op_free(op);
}

static bool add_comment(void *user, const ut64 key, const void *v) {
	RzCore *core = (RzCore *)user;
	RzSetS *set = (RzSetS *)v;

	RzPVector *vect = rz_set_s_to_vector(set);
	void **it;

	char *comment = NULL;
	bool first = true;
	rz_pvector_foreach (vect, it) {
		const char *vfunc_name = *it;
		if (first) {
			comment = rz_str_newf("Virtual Call : %s", vfunc_name);
			first = false;
			continue;
		}
		char *add_class = rz_str_newf(" / %s", vfunc_name);
		comment = rz_str_append(comment, add_class);
		RZ_FREE(add_class);
	}

	rz_core_meta_comment_add(core, comment, key);
	rz_pvector_fini(vect);
	if (comment) {
		RZ_FREE(comment);
	}

	rz_pvector_foreach (vect, it) {
		free(*it);
	}
	rz_pvector_free(vect);

	return true;
}

static bool free_virt_calls(void *user, const ut64 key, const void *v) {
	RzSetS *set = (RzSetS *)v;
	ht_sp_free(set);
	return true;
}

RZ_API void rz_analysis_devirtualize(RzAnalysis *analysis, RzCppVariableBook *var_book) {
	rz_core_analysis_esil_init_mem(analysis->core, "simulated object space", 0x3000, 0x1000); // Memory allocation for obbjects
	allocate_objects(analysis, var_book);
	RzListIter *it;
	CppVariable *var;

	RzVirtualCalls *virt_calls = RZ_NEW0(RzVirtualCalls);
	virt_calls->virt_calls = ht_up_new(NULL, NULL);

	rz_list_foreach (var_book->class_var_list, it, var) {
		RzListIter *itt;
		ut64 *obj_addr;
		rz_list_foreach (var->object_addr, itt, obj_addr) {
			devirtualize_variable_vtable(analysis, var_book, var, *obj_addr, virt_calls);
		}
	}

	ht_up_foreach(virt_calls->virt_calls, add_comment, analysis->core); // add devirtualization information

	ht_up_foreach(virt_calls->virt_calls, free_virt_calls, NULL);
	ht_up_free(virt_calls->virt_calls);
	free(virt_calls);
	rz_core_analysis_esil_init_mem_del(analysis->core, "simulated object space", 0x3000, 0x1000);
}

static void free_variable_book(RzCppVariableBook *var_book) {
	if (var_book == NULL) {
		return;
	}

	// free all stack variables
	RzListIter *it;
	CppVariable *var;
	rz_list_foreach (var_book->stack_variables, it, var) {
		free_variable(var);
	}
	rz_list_free(var_book->stack_variables);

	// free class variables
	ht_up_free(var_book->class_variables);

	// free class var list
	rz_list_free(var_book->class_var_list);

	free(var_book);
}

/**
 * \brief devirtualize virtual calls in cpp
 */
RZ_API void rz_analysis_devirtualize_methods(RzAnalysis *analysis) {
	// TODO : Generalize for classes
	RzCppVariableBook *var_book = rz_analysis_mark_classes(analysis);
	if (!var_book) {
		return;
	}
	rz_analysis_devirtualize(analysis, var_book);
	free_variable_book(var_book);
}