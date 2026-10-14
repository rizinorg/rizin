// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "absint_priv.h"
#include "rz_il/definitions/variable.h"
#include "rz_util/rz_assert.h"
#include "rz_vector.h"

#define LOCAL_ARR_LEN 64

RZ_IPI size_t rz_absint_djb2_idx_lookup(const RzVector /*<RzAbsIntDJB2Idx>*/ *djb2_idx_map, ut64 djb2) {
	rz_return_val_if_fail(djb2_idx_map, SIZE_MAX);
	size_t len = rz_vector_len(djb2_idx_map);
	if (len == 0 || len > rz_vector_capacity(djb2_idx_map)) {
		return SIZE_MAX;
	} else if (len == 1) {
		const RzAbsIntDJB2Idx *a = rz_vector_index_ptr(djb2_idx_map, 0);
		return a->djb2 == djb2 ? a->idx : SIZE_MAX;
	}
	size_t low = 0;
	size_t hi = len;

	while (low < hi) {
		size_t mid = low + ((hi - low) >> 1);
		const RzAbsIntDJB2Idx *a = rz_vector_index_ptr(djb2_idx_map, mid);
		if (a->djb2 == djb2) {
			return a->idx;
		} else if (a->djb2 > djb2) {
			low = mid + 1;
		} else {
			hi = mid;
		}
	}
	return SIZE_MAX;
}

static int cmp_reverse(const RzAbsIntDJB2Idx *a, const RzAbsIntDJB2Idx *b, void *user) {
	if (a->djb2 > b->djb2) {
		return -1;
	} else if (a->djb2 < b->djb2) {
		return 1;
	}
	return 0;
}

/**
 * \brief Inserts the entry of {djb2: idx} into the lookup map.
 */
RZ_IPI void rz_absint_djb2_idx_add(RzVector /*<RzAbsIntDJB2Idx>*/ *djb2_idx_map, ut64 djb2, size_t idx) {
	rz_return_if_fail(djb2_idx_map);
	RzAbsIntDJB2Idx pair = { .djb2 = djb2, .idx = idx };
	rz_vector_insert_sorted(djb2_idx_map, &pair, (RzVectorComparator)cmp_reverse, NULL);
}

static void var_arr_fini(RZ_NONNULL RzAbsIntInstance *inst, RZ_OWN RzVector *array) {
	if (!array) {
		return;
	}
	rz_return_if_fail(inst);
	void *it;
	rz_vector_foreach (array, it) {
		val_domain(inst)->val_fini(it);
	}
}

static void var_vec_clone(const RzAbsIntInstance *inst, RzVector *dst_vec, const RzVector *vec, const RzVector *bv_array_clone) {
	rz_return_if_fail(inst && vec);
	rz_vector_clone_into(dst_vec, vec);
	for (size_t i = 0; i < rz_vector_capacity(vec); i++) {
		RzAbsIntVal *clone_aval = rz_vector_index_ptr(dst_vec, i);
		val_domain(inst)->val_new_top(clone_aval, rz_vector_index_ptr(bv_array_clone, i));
		val_domain(inst)->copy(clone_aval, rz_vector_index_ptr(vec, i));
	}
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
 * \brief If init_offset == 0, it will allocate a new array of the given size and
 * write it to the given pointers.
 */
RZ_IPI bool rz_absint_init_var_array(RzAbsIntInstance *inst,
	RZ_OUT RzVector /*<RzAbsIntVal>*/ *arr,
	RZ_OUT RzVector /*<RzBitVector>*/ *bvs,
	size_t cap,
	bool set_len_to_cap) {
	rz_vector_init(arr, val_domain(inst)->val_size(), NULL, NULL);
	rz_vector_init(bvs, sizeof(RzBitVector), NULL, NULL);
	rz_vector_reserve(arr, cap);
	rz_vector_reserve(bvs, cap);
	if (set_len_to_cap) {
		rz_vector_set_len(arr, rz_vector_capacity(arr));
		rz_vector_set_len(bvs, rz_vector_capacity(bvs));
	}

	for (size_t i = 0; i < cap; ++i) {
		RzBitVector *bv = rz_vector_index_ptr(bvs, i);
		rz_bv_init(bv, 64);
		if (!val_domain(inst)->val_new_top(
			    rz_vector_index_ptr(arr, i),
			    bv)) {
			rz_warn_if_reached();
			var_arr_fini(inst, arr);
			rz_vector_free(bvs);
			return false;
		}
	}
	return true;
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

	if (!rz_absint_init_var_array(inst, &state->globals, &state->global_bvs, inst->il_ctx->config->global_idx_tbl_len, true)) {
		rz_warn_if_reached();
		goto err;
	}
	rz_vector_init(&state->locals_idx, sizeof(RzAbsIntDJB2Idx), NULL, NULL);
	rz_vector_reserve(&state->locals_idx, LOCAL_ARR_LEN);
	if (!rz_absint_init_var_array(inst, &state->locals, &state->local_bvs, LOCAL_ARR_LEN, false)) {
		rz_warn_if_reached();
		goto err;
	}
	state->lets = ht_up_new(NULL, NULL);
	if (!state->lets) {
		rz_warn_if_reached();
		goto err;
	}
	return state;
err:
	rz_vector_fini(&state->global_bvs);
	var_arr_fini(inst, &state->globals);
	rz_vector_fini(&state->locals_idx);
	rz_vector_fini(&state->local_bvs);
	var_arr_fini(inst, &state->locals);
	free(state);
	return NULL;
}

#undef LOCAL_ARR_LEN

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
	rz_vector_fini(&state->global_bvs);
	var_arr_fini(inst, &state->globals);
	rz_vector_fini(&state->locals_idx);
	rz_vector_fini(&state->local_bvs);
	var_arr_fini(inst, &state->locals);
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

RZ_API void rz_absint_state_reset_locals(RzAbsIntState *state) {
	rz_return_if_fail(state);
	rz_vector_set_len(&state->locals, 0);
	rz_vector_set_len(&state->local_bvs, 0);
	rz_vector_set_len(&state->locals_idx, 0);
}

RZ_IPI bool reset_state(RzAbsIntInstance *inst, RZ_BORROW RzAbsIntState *state, ut64 entry_point) {
	state->pc_state = RZ_ABSINT_PC_CONST;
	state->pc = entry_point;

	rz_absint_state_reset_locals(state);

	for (size_t i = 0; i < rz_vector_len(&state->globals); ++i) {
		if (!val_domain(inst)->val_new_top(rz_vector_index_ptr(&state->globals, i), rz_vector_index_ptr(&state->global_bvs, i))) {
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
	RzIterator *it = ht_up_as_iter_keys(vars);
	ut64 *key;
	rz_iterator_foreach(it, key) {
		RzAbsIntVal *val = (RzAbsIntVal *)RZ_NEWS0(ut8, val_domain(inst)->val_size());
		if (!val || !val_domain(inst)->val_new_top(val, NULL)) {
			rz_warn_if_reached();
			free(val);
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
	rz_vector_clone_into(&r->global_bvs, &state->global_bvs);
	var_vec_clone(iset, &r->globals, &state->globals, &r->global_bvs);

	rz_vector_clone_into(&r->locals_idx, &state->locals_idx);
	rz_vector_clone_into(&r->local_bvs, &state->local_bvs);
	var_vec_clone(iset, &r->locals, &state->locals, &r->local_bvs);

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
	bool global_change = join_var_arrs(inst, &a->globals, &b->globals);
	bool local_change = join_var_arrs(inst, &a->locals, &b->locals);
	// lets are not be relevant here since they are immutable within their scope
	return global_change || local_change;
}
