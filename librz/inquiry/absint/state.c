// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "absint_priv.h"
#include "rz_il/definitions/variable.h"
#include "rz_util/rz_assert.h"
#include "rz_vector.h"

static void var_arr_fini(RZ_NONNULL RzAbsIntInstance *inst, RZ_OWN RzVector *array) {
	if (!array) {
		return;
	}
	rz_return_if_fail(inst);
	void *it;
	rz_vector_foreach (array, it) {
		val_domain(inst)->val_free(it);
	}
}

static void var_arr_free(RZ_NONNULL RzAbsIntInstance *inst, RZ_OWN RzVector *array) {
	var_arr_fini(inst, array);
	rz_vector_free(array);
}

static RzVector *var_arr_clone(const RzAbsIntInstance *inst, const RzVector *array) {
	rz_return_val_if_fail(inst && array, NULL);
	RzVector *clone = rz_vector_clone(array);
	for (size_t i = 0; i < rz_vector_len(array); i++) {
		RzAbsIntVal *clone_aval = rz_vector_index_ptr(clone, i);
		val_domain(inst)->copy(clone_aval, rz_vector_index_ptr(array, i));
	}
	return clone;
}

static bool join_var_arrs(RzAbsIntInstance *inst, RZ_BORROW RZ_INOUT RzVector *a, const RZ_IN RzVector *b) {
	bool changed = false;
	for (size_t i = 0; i < rz_vector_len(a); i++) {
		RzAbsIntVal *av = rz_vector_index_ptr(a, i);
		RzAbsIntVal *bv = rz_vector_index_ptr(b, i);
		if (val_domain(inst)->join(av, bv)) {
			changed = true;
		}
	}
	return changed;
}

/**
 * \brief Returns a pointer to an RzAbsIntVal which can be used by the value domain
 * for temporary calculations.
 * Its content is undefined and has to be initialized with val_domain(inst)->val_new_top(scratch_val)
 * before use.
 */
RZ_IPI RZ_BORROW RzAbsIntVal *rz_absint_scratch_get(RZ_NONNULL RZ_BORROW RzAbsIntState *state) {
	rz_return_val_if_fail(state, NULL);
	if (rz_vector_len(state->scratch->pad) < state->scratch->i) {
		return rz_vector_index_ptr(state->scratch->pad, state->scratch->i++);
	}
	size_t new_cap = rz_vector_len(state->scratch->pad) * 1.2;
	rz_vector_reserve(state->globals, new_cap);
	return rz_vector_index_ptr(state->scratch->pad, state->scratch->i++);
}

/**
 * \brief Resets the scratch values.
 * So new values will be taken from the head of the array again.
 */
RZ_IPI void rz_absint_scratch_reset(RZ_NONNULL RZ_BORROW RzAbsIntInstance *inst, RZ_NONNULL RZ_BORROW RzAbsIntState *state) {
	rz_return_if_fail(state);
	var_arr_fini(inst, state->scratch->pad);
	rz_vector_purge(state->scratch->pad);
	state->scratch->i = 0;
}

/**
 * \brief Initializes an abstract state.
 */
RZ_API RZ_OWN RzAbsIntState *rz_absint_state_new(
	RZ_NONNULL RzAbsIntInstance *inst) {
	rz_return_val_if_fail(inst, NULL);
	RzAbsIntState *state = RZ_NEW0(RzAbsIntState);
	if (!state) {
		return NULL;
	}
	state->pc_state = RZ_ABSINT_PC_UNREACHABLE;
	state->scratch->pad = rz_vector_new(val_domain(inst)->val_size(), NULL, NULL);
	rz_vector_reserve(state->globals, RZ_ABS_INT_INIT_SCRATCH_PAD_SIZE);
	if (!state->scratch->pad) {
		rz_warn_if_reached();
		free(state);
		return NULL;
	}

	// Initialize the register file with uninitialized abstract values.
	state->globals = rz_vector_new(val_domain(inst)->val_size(), NULL, NULL);
	if (!state->globals) {
		rz_warn_if_reached();
		goto err_globals;
	}
	rz_vector_reserve(state->globals, inst->il_ctx->reg_binding->regs_count);
	void *it;
	rz_vector_foreach (state->globals, it) {
		if (!val_domain(inst)->val_new_top(it)) {
			rz_warn_if_reached();
			goto err_globals;
		}
	}
	state->locals = ht_up_new(NULL, NULL);
	state->lets = ht_up_new(NULL, NULL);
	return state;
err_globals:
	var_arr_free(inst, state->globals);
	free(state);
	return NULL;
}

static void var_set_free(RzAbsIntInstance *inst, HtUP *vars) {
	if (!vars) {
		return;
	}
	RzIterator *it = ht_up_as_iter(vars);
	RzAbsIntVal **v;
	rz_iterator_foreach(it, v) {
		val_domain(inst)->val_free(*v);
	}
	rz_iterator_free(it);
	ht_up_free(vars);
}

RZ_API void rz_absint_state_free(RZ_BORROW RzAbsIntInstance *inst, RZ_OWN RZ_NULLABLE RzAbsIntState *state) {
	if (!state) {
		return;
	}
	var_arr_free(inst, state->scratch->pad);
	var_arr_free(inst, state->globals);
	var_set_free(inst, state->locals);
	var_set_free(inst, state->lets);
	free(state);
}

/**
 * \brief Set the PC of the \p state to the given constant value.
 *
 * \param state The state to set the PC in.
 * \param pc The constant value to set it to.
 */
RZ_API void rz_absint_state_set_pc_const(RzAbsIntState *state, ut64 pc) {
	rz_return_if_fail(state);
	state->pc = pc;
	state->pc_state = RZ_ABSINT_PC_CONST;
}

RZ_IPI bool reset_state(RzAbsIntInstance *inst, RZ_BORROW RzAbsIntState *state, ut64 entry_point) {
	state->pc_state = RZ_ABSINT_PC_CONST;
	state->pc = entry_point;

	void *it;
	rz_vector_foreach (state->globals, it) {
		if (!val_domain(inst)->val_new_top(it)) {
			rz_warn_if_reached();
		}
	}
	return true;
}

/**
 * \brief Prints the state as string to \p sb.
 *
 * \param inst The abstract instance for accessing the value domain.
 * \param state The abstract state to print.
 * \param sb The string buffer to output the string into.
 *
 * \return True on success, false otherwise.
 */
RZ_API bool rz_absint_state_as_str(RZ_NONNULL RzAbsIntInstance *inst, RZ_NONNULL const RzAbsIntState *state, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(inst && state && sb, false);

	rz_strbuf_append(sb, "Globals\n\n");
	rz_strbuf_append(sb, "\tpc = ");
	if (state->pc_state == RZ_ABSINT_PC_CONST) {
		rz_strbuf_appendf(sb, "0x%" PFMT64x, state->pc);
	} else {
		rz_strbuf_append(sb, state->pc_state == RZ_ABSINT_PC_ANY ? RZ_ABSINT_STR_TOP : RZ_ABSINT_STR_BOTTOM);
	}
	rz_strbuf_append(sb, "\n\n");

	// RzIterator *it = ht_up_as_iter_keys(state->globals);
	// ut64 *k;
	// rz_iterator_foreach(it, k) {
	// 	const char *gname = ht_up_find(inst->var_name_hashes, *k, NULL);
	// 	rz_strbuf_appendf(sb, "\t%s = ", gname);
	// 	RzAbsIntVal *av = ht_up_find(state->globals, *k, NULL);
	// 	val_domain(inst)->val_as_str(av, sb);
	// 	rz_strbuf_append(sb, "\n");
	// }
	// rz_iterator_free(it);
	return true;
}

/**
 * \brief Prints the state as a _single line_ string to \p sb.
 * Use rz_absint_state_as_str() to print more details.
 *
 * \param inst The abstract instance for accessing the value domain.
 * \param state The abstract state to print.
 * \param sb The string buffer to output the string into.
 *
 * \return True on success, false otherwise.
 */
RZ_API bool rz_absint_state_as_str_short(RZ_NONNULL RzAbsIntInstance *inst, RZ_NONNULL const RzAbsIntState *astate, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(inst && astate && sb, false);

	// bool first = true;
	// RzIterator *it = ht_up_as_iter_keys(astate->globals);
	// ut64 *k;
	// bool all_top = true;
	// rz_iterator_foreach(it, k) {
	// 	ut64 djb2_reg_name = *k;
	// 	RzAbsIntVal *av = ht_up_find(astate->globals, djb2_reg_name, NULL);
	// 	if (!av || val_domain(inst)->is_top(av)) {
	// 		continue;
	// 	}
	// 	all_top = false;
	// 	if (!first) {
	// 		rz_strbuf_append(sb, ", ");
	// 	}
	// 	first = false;
	// 	const char *varname = ht_up_find(inst->var_name_hashes, djb2_reg_name, NULL);
	// 	rz_strbuf_appendf(sb, "%s = ", varname);
	// 	val_domain(inst)->val_as_str(av, sb);
	// }
	// rz_iterator_free(it);
	// if (all_top) {
	// 	rz_strbuf_append(sb, RZ_ABSINT_STR_TOP);
	// }
	return true;
}

static HtUP *var_set_clone(const RzAbsIntInstance *inst, HtUP *vars) {
	HtUP *r = ht_up_new(NULL, NULL);
	if (!r) {
		return NULL;
	}
	RzAbsIntVal *val = (RzAbsIntVal *)RZ_NEWS0(ut8, val_domain(inst)->val_size());
	RzIterator *it = ht_up_as_iter_keys(vars);
	ut64 *key;
	rz_iterator_foreach(it, key) {
		if (!val_domain(inst)->val_new_top(val)) {
			rz_warn_if_reached();
			break;
		}
		val_domain(inst)->copy(val, ht_up_find(vars, *key, NULL));
		ht_up_insert(r, *key, val);
	}
	rz_iterator_free(it);
	return r;
}

RZ_API RZ_OWN RzAbsIntState *rz_absint_state_clone(RZ_NONNULL RzAbsIntInstance *iset, const RzAbsIntState *state) {
	rz_return_val_if_fail(iset && state, NULL);

	RzAbsIntState *r = RZ_NEW0(RzAbsIntState);
	if (!state) {
		return NULL;
	}
	r->pc = state->pc;
	r->pc_state = state->pc_state;
	r->globals = var_arr_clone(iset, state->globals);
	r->locals = var_set_clone(iset, state->locals);
	r->lets = var_set_clone(iset, state->lets);
	return r;
}

/**
 * \brief Join (least upper bound) on var sets
 * \return True if a was changed
 */
static bool join_vars_sets(RzAbsIntInstance *inst, RZ_BORROW RZ_INOUT HtUP *a, RZ_BORROW RZ_IN HtUP *b) {
	RzIterator *it = ht_up_as_iter_keys(a);
	ut64 *k;
	bool changed = false;
	rz_iterator_foreach(it, k) {
		RzAbsIntVal *av = ht_up_find(a, *k, NULL);
		RzAbsIntVal *bv = ht_up_find(b, *k, NULL);
		if (!av || !bv) {
			continue;
		}
		if (val_domain(inst)->join(av, bv)) {
			changed = true;
		}
	}
	rz_iterator_free(it);
	return changed;
}

RZ_IPI bool join_state(RzAbsIntInstance *inst, RZ_BORROW RZ_INOUT RzAbsIntState *a, RZ_BORROW RZ_IN const RzAbsIntState *b) {
	bool global_change = join_var_arrs(inst, a->globals, b->globals);
	bool local_change = join_vars_sets(inst, a->locals, b->locals);
	// lets are not be relevant here since they are immutable within their scope
	return global_change || local_change;
}
