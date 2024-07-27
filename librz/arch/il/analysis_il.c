// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

/**
 * \name Config and Init State
 * @{
 */

static void var_state_free(void *e, void *user) {
	RzAnalysisILInitStateVar *s = e;
	if (!s) {
		return;
	}
	rz_il_value_free(s->val);
}

RZ_API RzAnalysisILInitState *rz_analysis_il_init_state_new() {
	RzAnalysisILInitState *r = RZ_NEW0(RzAnalysisILInitState);
	if (!r) {
		return NULL;
	}
	rz_vector_init(&r->vars, sizeof(RzAnalysisILInitStateVar), var_state_free, NULL);
	return r;
}

RZ_API void rz_analysis_il_init_state_free(RzAnalysisILInitState *state) {
	if (!state) {
		return;
	}
	rz_vector_fini(&state->vars);
}

/**
 * Set the value of the global variable called \p name name to \p val in the initial state \p state
 */
RZ_API void rz_analysis_il_init_state_set_var(RZ_NONNULL RzAnalysisILInitState *state,
	RZ_NONNULL const char *name, RZ_NONNULL RZ_OWN RzILVal *val) {
	rz_return_if_fail(state && name && val);
	RzAnalysisILInitStateVar *v = rz_vector_push(&state->vars, NULL);
	if (!v) {
		rz_il_value_free(val);
		return;
	}
	v->name = name;
	v->val = val;
}

/**
 * Create an IL config and initialize it with the given minimal mandatory info
 */
RZ_API RZ_OWN RzAnalysisILConfig *rz_analysis_il_config_new(ut32 pc_size, bool big_endian, ut32 mem_key_size) {
	rz_return_val_if_fail(pc_size && mem_key_size, NULL);
	RzAnalysisILConfig *r = RZ_NEW0(RzAnalysisILConfig);
	if (!r) {
		return NULL;
	}
	r->pc_size = pc_size;
	r->big_endian = big_endian;
	r->mem_key_size = mem_key_size;
	rz_pvector_init(&r->labels, (RzPVectorFree)rz_il_effect_label_free);
	return r;
}

RZ_API void rz_analysis_il_config_free(RzAnalysisILConfig *cfg) {
	if (!cfg) {
		return;
	}
	rz_pvector_fini(&cfg->labels);
	free(cfg);
}

/**
 * Add \p label to the IL config \p cfg to describe that it is globally available in a vm
 */
RZ_API void rz_analysis_il_config_add_label(RZ_NONNULL RzAnalysisILConfig *cfg, RZ_NONNULL RZ_OWN RzILEffectLabel *label) {
	rz_return_if_fail(cfg && label);
	rz_pvector_push(&cfg->labels, label);
}

/// @}

/////////////////////////////////////////////////////////
/**
 * \name Analysis IL VM
 * @{
 */

static void setup_vm_from_config(RzAnalysis *analysis, RzAnalysisILVM *vm, RzAnalysisILConfig *cfg);
static void setup_vm_init_state(RzAnalysisILVM *vm, RZ_NULLABLE RzAnalysisILInitState *is, RZ_NULLABLE RzReg *reg);

/**
 * Create and initialize an RzAnalysisILVM with the current arch/cpu/bits configuration and plugin
 * \p init_state_reg optional RzReg to take variable values from, unless the plugin overrides them using RzAnalysisILInitState
 * \return RzAnalysisRzil* a pointer to RzAnalysisILVM instance
 */
RZ_API RZ_OWN RzAnalysisILVM *rz_analysis_il_vm_new(RzAnalysis *a, RZ_NULLABLE RzReg *init_state_reg) {
	rz_return_val_if_fail(a, NULL);
	RzAnalysisILConfig *config = a->cur->il_config(a);
	if (!config) {
		return false;
	}
	RzAnalysisILVM *r = RZ_NEW0(RzAnalysisILVM);
	if (!r) {
		goto ruby_pool;
	}
	r->io_buf = rz_buf_new_with_io(&a->iob);
	setup_vm_from_config(a, r, config);
	if (!r->vm) {
		rz_buf_free(r->io_buf);
		free(r);
		r = NULL;
		goto ruby_pool;
	}
	setup_vm_init_state(r, config->init_state, init_state_reg);
ruby_pool:
	rz_analysis_il_config_free(config);
	return r;
}

/**
 * Frees an RzAnalysisILVM instance
 */
RZ_API void rz_analysis_il_vm_free(RZ_NULLABLE RzAnalysisILVM *vm) {
	if (!vm) {
		return;
	}
	rz_il_vm_free(vm->vm);
	rz_il_reg_binding_free(vm->reg_binding);
	rz_buf_free(vm->io_buf);
	free(vm);
}

static bool setup_regs(RzAnalysis *a, RzAnalysisILVM *vm, RzAnalysisILConfig *cfg) {
	if (!a->cur->get_reg_profile) {
		return false;
	}
	// Explicitly use a new reg here!
	// The a->reg might be changed by the user, but plugins expect exactly
	// the register profile they supplied. Syncing will later adjust the register
	// contents if necessary.
	RzReg *reg = rz_reg_new();
	if (!reg) {
		return false;
	}
	char *profile = a->cur->get_reg_profile(a);
	bool succ;
	if (!profile) {
		succ = false;
		goto new_real;
	}
	succ = rz_reg_set_profile_string(reg, profile);
	free(profile);
	if (!succ) {
		goto new_real;
	}
	if (cfg->reg_bindings) {
		size_t count = 0;
		while (cfg->reg_bindings[count]) {
			count++;
		}
		vm->reg_binding = rz_il_reg_binding_exactly(reg, count, cfg->reg_bindings);
	} else {
		vm->reg_binding = rz_il_reg_binding_derive(reg);
	}
	if (!vm->reg_binding) {
		succ = false;
		goto new_real;
	}
	rz_il_vm_setup_reg_binding(vm->vm, vm->reg_binding);
new_real:
	rz_reg_free(reg);
	return succ;
}

static void setup_vm_from_config(RzAnalysis *analysis, RzAnalysisILVM *vm, RzAnalysisILConfig *cfg) {
	vm->vm = rz_il_vm_new(0, cfg->pc_size, cfg->big_endian);
	if (!vm->vm) {
		return;
	}
	if (!setup_regs(analysis, vm, cfg)) {
		rz_il_vm_free(vm->vm);
		vm->vm = NULL;
		return;
	}
	rz_il_vm_add_mem(vm->vm, 0, rz_il_mem_new(vm->io_buf, cfg->mem_key_size));
	void **it;
	rz_pvector_foreach (&cfg->labels, it) {
		RzILEffectLabel *lbl = *it;
		rz_il_vm_add_label(vm->vm, rz_il_effect_label_dup(lbl));
	}
}

static void setup_vm_init_state(RzAnalysisILVM *vm, RZ_NULLABLE RzAnalysisILInitState *is, RZ_NULLABLE RzReg *reg) {
	if (reg) {
		rz_il_vm_sync_from_reg(vm->vm, vm->reg_binding, reg);
	}
	if (is) {
		RzAnalysisILInitStateVar *v;
		rz_vector_foreach (&is->vars, v) {
			rz_il_vm_set_global_var(vm->vm, v->name, rz_il_value_dup(v->val));
		}
	}
}

/**
 * Set the values of all variables in \p vm that are bound to registers and PC to the respective contents from \p reg.
 *
 * This is like the low-level `rz_il_vm_sync_from_reg()`, but uses the binding that is part of \p vm.
 * See its documentation for details.
 */
RZ_API void rz_analysis_il_vm_sync_from_reg(RzAnalysisILVM *vm, RZ_NONNULL RzReg *reg) {
	rz_return_if_fail(vm && reg);
	rz_il_vm_sync_from_reg(vm->vm, vm->reg_binding, reg);
}

/**
 * Set the values of all bound regs in \p reg to the respective variable or PC contents in \p vm.
 *
 * This is like the low-level `rz_il_vm_sync_to_reg()`, but uses the binding that is part of \p vm.
 * See its documentation for details.
 *
 * \return whether the sync was cleanly applied without errors or adjustments
 */
RZ_API bool rz_analysis_il_vm_sync_to_reg(RzAnalysisILVM *vm, RZ_NONNULL RzReg *reg) {
	rz_return_val_if_fail(vm && reg, false);
	return rz_il_vm_sync_to_reg(vm->vm, vm->reg_binding, reg);
}

static void il_events(RzILVM *vm, RzStrBuf *sb) {
	void **it;
	rz_pvector_foreach (vm->events, it) {
		RzILEvent *evt = *it;
		rz_il_event_stringify(evt, sb);
		rz_strbuf_append(sb, "\n");
	}
}

static RzAnalysisILStepResult analysis_il_vm_step_while(
	RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisILVM *vm, RZ_NULLABLE RzReg *reg,
	bool with_events, RZ_NONNULL RzAnalysisILVMCondCallback cond, RZ_NULLABLE void *user) {

	rz_return_val_if_fail(analysis && vm, false);
	RzAnalysisPlugin *cur = analysis->cur;
	if (!cur || !analysis->read_at) {
		return RZ_ANALYSIS_IL_STEP_RESULT_NOT_SET_UP;
	}

	if (reg) {
		rz_analysis_il_vm_sync_from_reg(vm, reg);
	}

	RzAnalysisOp op = { 0 };
	RzAnalysisILStepResult res = RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS;
	while (cond(vm, user)) {
		ut64 addr = rz_bv_to_ut64(vm->vm->pc);
		ut8 code[32] = { 0 };
		analysis->read_at(analysis, addr, code, sizeof(code));
		int r = rz_analysis_op(analysis, &op, addr, code, sizeof(code), RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_DISASM);

		if (r < 0 || !op.il_op) {
			res = RZ_ANALYSIS_IL_STEP_INVALID_OP;
			break;
		}
		if (!rz_il_vm_step(vm->vm, op.il_op, addr + (op.size > 0 ? op.size : 1))) {
			res = RZ_ANALYSIS_IL_STEP_IL_RUNTIME_ERROR;
			break;
		}
		if (!with_events) {
			rz_analysis_op_fini(&op);
			continue;
		}

		RzStrBuf sb = { 0 };
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(op.il_op, &sb, false);
		rz_strbuf_append(&sb, "\n");
		il_events(vm->vm, &sb);

		rz_cons_printf("0x%llx [", addr);
		for (int i = 0; i < op.size; ++i) {
			rz_cons_printf("%x", code[i]);
		}
		rz_cons_printf("] %s\n%s\n", op.mnemonic, rz_strbuf_get(&sb));
		rz_cons_flush();
		rz_strbuf_fini(&sb);
		rz_analysis_op_fini(&op);
	}
	rz_analysis_op_fini(&op);
	if (reg) {
		rz_analysis_il_vm_sync_to_reg(vm, reg);
	}
	return res;
}

/**
 * \brief Repeatedly perform steps in the VM until the \p cond callback returns false
 *
 * \param analysis Pointer to an RzAnalysis struct, likely representing the analysis context.
 * \param vm Pointer to an RzAnalysisILVM struct, representing the IL virtual machine to be stepped.
 * \param reg Optional pointer to an RzReg struct, potentially holding register values to be used during the step.
 * \param cond Pointer to a function that determines the loop's continuation condition. This function takes two arguments:
 *          * vm: Pointer to the same RzAnalysisILVM struct passed to rz_analysis_il_vm_step_while.
 *          * user: Pointer to user-provided data that can be used by the condition function.
 * \param user Pointer to user-defined data that can be passed to the condition function.
 *
 * \return RZ_ANALYSIS_IL_STEP_RESULT: Enumeration value indicating the outcome of the stepping operation.
 *         Possible values (implementation specific):
 *             - RZ_ANALYSIS_IL_STEP_OK: Successful execution of the while loop step.
 *             - RZ_ANALYSIS_IL_STEP_ERROR: Encountered an error during execution.
 *             - RZ_ANALYSIS_IL_STEP_INVALID: Invalid arguments or state resulted in undefined behavior.
 */
RZ_API RzAnalysisILStepResult rz_analysis_il_vm_step_while(
	RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisILVM *vm, RZ_NULLABLE RzReg *reg,
	RZ_NONNULL RzAnalysisILVMCondCallback cond, RZ_NULLABLE void *user) {
	return analysis_il_vm_step_while(analysis, vm, reg, false, cond, user);
}

/**
 * \brief Repeatedly perform steps in the VM until the \p cond callback returns false
 *        and output VM changes (read & write)
 *
 * \param analysis Pointer to an RzAnalysis struct, likely representing the analysis context.
 * \param vm Pointer to an RzAnalysisILVM struct, representing the IL virtual machine to be stepped.
 * \param reg Optional pointer to an RzReg struct, potentially holding register values to be used during the step.
 * \param cond Pointer to a function that determines the loop's continuation condition. This function takes two arguments:
 *          * vm: Pointer to the same RzAnalysisILVM struct passed to rz_analysis_il_vm_step_while.
 *          * user: Pointer to user-provided data that can be used by the condition function.
 * \param user Pointer to user-defined data that can be passed to the condition function.
 *
 * \return RZ_ANALYSIS_IL_STEP_RESULT: Enumeration value indicating the outcome of the stepping operation.
 *         Possible values (implementation specific):
 *             - RZ_ANALYSIS_IL_STEP_OK: Successful execution of the while loop step.
 *             - RZ_ANALYSIS_IL_STEP_ERROR: Encountered an error during execution.
 *             - RZ_ANALYSIS_IL_STEP_INVALID: Invalid arguments or state resulted in undefined behavior.
 */
RZ_API RzAnalysisILStepResult rz_analysis_il_vm_step_while_with_events(
	RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisILVM *vm, RZ_NULLABLE RzReg *reg,
	RZ_NONNULL RzAnalysisILVMCondCallback cond, RZ_NULLABLE void *user) {
	return analysis_il_vm_step_while(analysis, vm, reg, true, cond, user);
}

static bool step_cond_once(RzAnalysisILVM *vm, void *user) {
	bool *stepped = user;
	if (*stepped) {
		return false;
	}
	*stepped = true;
	return true;
}

/**
 * Perform a single step in the VM
 *
 * If given, this syncs the contents of \p reg into the vm.
 * Then it disassembles an instruction at the program counter of the vm and executes it.
 * Finally the contents are optionally synced back to \p reg.
 *
 * \return and indicator for which error occured, if any
 */
RZ_API RzAnalysisILStepResult rz_analysis_il_vm_step(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisILVM *vm, RZ_NULLABLE RzReg *reg) {
	bool stepped = false;
	return rz_analysis_il_vm_step_while(analysis, vm, reg, step_cond_once, &stepped);
}

/// @}

/////////////////////////////////////////////////////////
/**
 * \name Global, user-faced VM setup
 * @{
 */

/**
 * (Re)initialize the global user-faced vm
 * \return whether the init succeeded
 */
RZ_API bool rz_analysis_il_vm_setup(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, false);
	rz_analysis_il_vm_cleanup(analysis);
	if (!analysis->cur || !analysis->cur->il_config) {
		RZ_LOG_WARN("Could not set up VM. Analysis plugin or RZIL config was NULL.\n");
		return false;
	}
	analysis->il_vm = rz_analysis_il_vm_new(analysis, analysis->reg);
	if (analysis->il_vm) {
		// rz_analysis_il_vm_new merges the contents of analysis->reg with the plugin's optional RzAnalysisILInitState
		// Now sync the merged state back:
		rz_il_vm_sync_to_reg(analysis->il_vm->vm, analysis->il_vm->reg_binding, analysis->reg);
	}
	return !!analysis->il_vm;
}

/**
 * Destroy the global user-faced vm
 */
RZ_API void rz_analysis_il_vm_cleanup(RzAnalysis *analysis) {
	rz_return_if_fail(analysis);
	rz_analysis_il_vm_free(analysis->il_vm);
	analysis->il_vm = NULL;
}

/// @}
