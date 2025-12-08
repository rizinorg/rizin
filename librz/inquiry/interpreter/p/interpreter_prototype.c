// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_util.h>

#include "../prototype/eval.h"

static bool eval(RZ_NONNULL RzInterpreterAbstrState *state,
	RZ_NONNULL const RzILOpEffect *effect,
	RZ_NONNULL RZ_BORROW HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
	void *plugin_data) {
	bool result = interpreter_prototype_eval_effect(state, effect, yield_queues, io_request, io_result, plugin_data);
	// TODO: Clean up local variables.
	// Or maybe not? Just costs performance. And the uplifted instructions should
	// always set it before, otherwise the tests don't pass.
	return result;
}

bool successors(RZ_NONNULL const RzInterpreterAbstrState *state,
	RZ_NONNULL RZ_OUT RzVector /*<ut64>*/ *successors,
	void *plugin_data) {
	rz_return_val_if_fail(state && successors, false);

	RzInterpreterAbstrVal *pc = state->pc;
	if (!pc || !pc->abstr_data) {
		RZ_LOG_ERROR("No PC found.\n");
		return false;
	}
	ProtoIntrprAbstrData *adata = pc->abstr_data;
	if (!adata->is_concrete) {
		// The PC is not a concrete value.
		// This prototype can't estimate a reasonable concretization for it.
		return true;
	}
	if (rz_bv_len(adata->bv) > 64) {
		RZ_LOG_WARN("PC has a length of more than 64 bits!\n");
		return true;
	}

	ut64 next_pc = rz_bv_to_ut64(adata->bv);
	rz_vector_push(successors, &next_pc);
	return true;
}

static bool init_state(RZ_BORROW RzInterpreterAbstrState *state, ut64 entry_point, void *plugin_data) {
	state->pc->abstr_data = RZ_NEW0(ProtoIntrprAbstrData);
	AD(state->pc->abstr_data)->bv = rz_bv_new_from_ut64(state->addr_bits, entry_point);
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpreterAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		av->abstr_data = RZ_NEW0(ProtoIntrprAbstrData);
	}
	rz_iterator_free(it);
	state->ext = RZ_NEW0(RzInterpreterIORequest);
	return true;
}

static bool fini_state(RZ_BORROW RzInterpreterAbstrState *state, void *plugin_data) {
	ProtoIntrprAbstrData *ad = state->pc->abstr_data;
	if (ad->bv) {
		rz_bv_free(ad->bv);
	}
	free(ad);
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpreterAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad->bv) {
			rz_bv_free(ad->bv);
		}
		free(ad);
	}
	rz_iterator_free(it);

	it = ht_up_as_iter(state->locals);
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad->bv) {
			rz_bv_free(ad->bv);
		}
		free(ad);
	}
	rz_iterator_free(it);

	it = ht_up_as_iter(state->lets);
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad->bv) {
			rz_bv_free(ad->bv);
		}
		free(ad);
	}
	rz_iterator_free(it);
	free(state->ext);
	return true;
}

/**
 * \brief This hash function is just an example implementation.
 * It is likely not sufficient to prevent collisions.
 * It is also slow.
 */
static ut64 hash_state(RZ_NONNULL const RzInterpreterAbstrState *state, void *plugin_data) {
	ut64 hash = 0;
	ProtoIntrprAbstrData *ad = state->pc->abstr_data;
	if (ad->bv) {
		hash ^= rz_bv_to_ut64(ad->bv);
	}
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpreterAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad->bv) {
			hash ^= rz_bv_to_ut64(ad->bv);
		}
	}
	rz_iterator_free(it);
	return hash;
}

static RzInterpreterPlugin rz_interpreter_plugin_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/bottom abstractions.",
	.license = "LGPL-3.0-only",
	.supported_abstractions = RZ_INTERPRETER_ABSTRACTION_CONST,
	.supported_yields = RZ_INTERPRETER_YIELD_KIND_XREF,
	.init = NULL,
	.fini = NULL,
	.eval = eval,
	.successors = successors,
	.init_state = init_state,
	.fini_state = fini_state,
	.hash_state = hash_state,
	.clone_state = NULL,
};

RZ_API RzInquiryPlugin rz_inquiry_plugin_interpreter_prototype = {
	.p_interpreter = &rz_interpreter_plugin_prototype,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_INTERPRETER,
	.data = &interpreter_prototype
};
#endif
