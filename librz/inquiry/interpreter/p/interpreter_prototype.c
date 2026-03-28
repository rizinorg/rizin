// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_util.h>

#include "../prototype/eval.h"
#include "rz_util/ht_uu.h"

#define MAX_INVOCATIONS_PER_BB 3

static bool eval(RZ_NONNULL RzInterpreterSet *iset,
	RZ_NONNULL const RzInterpreterILBB *il_bb,
	void *plugin_data) {
	ProtoIntrprPluginData *pdata = plugin_data;

	// Check invocation count of the current address.
	// Never execute the same address more than MAX_INVOCATIONS_PER_BB times.
	bool found = false;
	ut64 ic_pc = ht_uu_find(pdata->bb_invocation_count, il_bb->bb_addr, &found);
	if (!found) {
		ic_pc = 0;
	} else if (ic_pc > MAX_INVOCATIONS_PER_BB) {
		// TODO: Make it configurable
		RZ_LOG_DEBUG("Reached maximum number of invocations of basic block at 0x%" PFMT64x ". Skipping it.\n", il_bb->bb_addr)
		set_pc(iset->state, il_bb->bb_addr + il_bb->size, plugin_data);
		return true;
	}
	ht_uu_update(pdata->bb_invocation_count, il_bb->bb_addr, ic_pc + 1);
	RZ_LOG_DEBUG("Eval BB (ic: %" PFMT64d ") = 0x%" PFMT64x "\n", ic_pc, il_bb->bb_addr);

	// Reset call candidate tracking for each basic block.
	memset(&pdata->call_cand, 0, sizeof(pdata->call_cand));

	// Now execute the actual effects of the BB.
	void **it;
	rz_pvector_foreach (il_bb->il_ops, it) {
		ut64 pc = rz_bv_to_ut64(AD(iset->state->pc->abstr_data)->bv);
		RZ_LOG_DEBUG("Eval PC = 0x%" PFMT64x "\n", pc);
		RzInterpreterInsnPkt *pkt = *it;
		if (!interpreter_prototype_eval_effect(iset, pkt->effect, pkt->insn_pkt_size, plugin_data)) {
			return false;
		}
		if (pc == rz_bv_to_ut64(AD(iset->state->pc->abstr_data)->bv) && AD(iset->state->pc->abstr_data)->is_concrete) {
			// Instruction did not manipulate the PC. Set it to the next instruction (packet).
			set_pc(iset->state, pc + pkt->insn_pkt_size, plugin_data);
		}
	}
	// TODO: Clean up local variables.
	// Or maybe not? Just costs performance. And the uplifted instructions should
	// always set it before reading, otherwise the tests wouldn't pass.
	return true;
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
	AD(state->pc->abstr_data)->bv = rz_bv_new_from_ut64(state->il_config->mem_key_size, entry_point);
	AD(state->pc->abstr_data)->is_concrete = true;
	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpreterAbstrVal *av = ht_up_find(state->globals, djb2_reg_name, NULL);
		rz_return_val_if_fail(av, false);
		av->abstr_data = RZ_NEW0(ProtoIntrprAbstrData);
		// Length doesn't matter here. Because the destination is always
		// set to the length of the src.
		// TODO: Really a good idea to be so liberal?
		// Or should the length of the globals be enforced?
		// The bitvector arithmetic does enforce the length.
		AD(av->abstr_data)->bv = rz_bv_new(state->il_config->mem_key_size);
		// TODO: This is debatable. It depends on the ABI what the default values are.
		// Some values must be concrete, otherwise the interpretation of the prototype end too early.
		AD(av->abstr_data)->is_concrete = true;
		if (state->il_config->init_state) {
			RzAnalysisILInitStateVar *il_var;
			rz_vector_foreach(&state->il_config->init_state->vars, il_var) {
				if (rz_str_djb2_hash(il_var->name) != djb2_reg_name) {
					continue;
				}
				// The RzArch plugin defined a default value for this global.
				RzBitVector *default_val = rz_il_value_to_bv(il_var->val);
				rz_bv_copy(AD(av->abstr_data)->bv, default_val);
				rz_bv_free(default_val);
			}
		}
	}
	rz_iterator_free(it);
	return true;
}

static bool fini_state(RZ_BORROW RzInterpreterAbstrState *state, void *plugin_data) {
	ProtoIntrprAbstrData *ad = state->pc->abstr_data;
	if (ad && ad->bv) {
		rz_bv_free(ad->bv);
	}
	free(ad);
	state->pc->abstr_data = NULL;

	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpreterAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad && ad->bv) {
			rz_bv_free(ad->bv);
		}
		free(ad);
		av->abstr_data = NULL;
	}
	rz_iterator_free(it);

	it = ht_up_as_iter(state->locals);
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad && ad->bv) {
			rz_bv_free(ad->bv);
		}
		free(ad);
		av->abstr_data = NULL;
	}
	rz_iterator_free(it);

	it = ht_up_as_iter(state->lets);
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad && ad->bv) {
			rz_bv_free(ad->bv);
		}
		free(ad);
		av->abstr_data = NULL;
	}
	rz_iterator_free(it);
	return true;
}

/**
 * \brief This hash function is just an example implementation.
 * It is likely not sufficient to prevent collisions.
 * It is also slow.
 */
static ut64 hash_state(RZ_NONNULL const RzInterpreterAbstrState *state, void *plugin_data) {
	ut64 h = 5381;
	ProtoIntrprAbstrData *ad = state->pc->abstr_data;
	if (ad->bv) {
		h = (h ^ (h << 5)) ^ rz_bv_to_ut64(ad->bv);
	}
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpreterAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpreterAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad->bv) {
			h = (h ^ (h << 5)) ^ rz_bv_to_ut64(ad->bv);
		}
	}
	rz_iterator_free(it);
	return h;
}

bool state_as_str(RZ_NONNULL const RzInterpreterAbstrState *state,
	RZ_NONNULL RZ_OUT RzStrBuf *sb,
	void *plugin_data) {
	rz_return_val_if_fail(state && sb, false);

	ut64 hash = hash_state(state, plugin_data);
	rz_strbuf_appendf(sb, "hash = 0x%" PFMT64x "\n\n", hash);
	rz_strbuf_append(sb, "Globals\n\n");
	char *value = AD(state->pc->abstr_data)->is_concrete ? rz_bv_as_hex_string(AD(state->pc->abstr_data)->bv, true) : rz_str_dup("⊥");
	rz_strbuf_appendf(sb, "\tpc = %s\n\n", value);
	free(value);

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		const char *gname = ht_up_find(state->var_name_hashes, *k, NULL);
		RzInterpreterAbstrVal *av = ht_up_find(state->globals, *k, NULL);
		ProtoIntrprAbstrData *ad = av->abstr_data;
		value = ad->is_concrete ? rz_bv_as_hex_string(ad->bv, true) : rz_str_dup("⊥");
		rz_strbuf_appendf(sb, "\t%s = %s\n", gname, value);
		free(value);
	}
	rz_iterator_free(it);
	return true;
}

bool init(void **plugin_data) {
	ProtoIntrprPluginData *pdata = RZ_NEW0(ProtoIntrprPluginData);
	if (!pdata) {
		return NULL;
	}
	RZ_LOG_DEBUG("prototype: init()\n");
	pdata->bb_invocation_count = ht_uu_new();
	if (!pdata->bb_invocation_count) {
		free(pdata);
		return false;
	}
	*plugin_data = pdata;
	return true;
}

bool fini(void *plugin_data) {
	if (!plugin_data) {
		return true;
	}
	RZ_LOG_DEBUG("prototype: fini()\n");
	ProtoIntrprPluginData *pdata = plugin_data;
	ht_uu_free(pdata->bb_invocation_count);
	free(pdata);
	return true;
}

static RzInterpreterPlugin rz_interpreter_plugin_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/bottom abstractions.",
	.license = "LGPL-3.0-only",
	.supported_abstractions = RZ_INTERPRETER_ABSTRACTION_CONST,
	.supported_yields = RZ_INTERPRETER_YIELD_KIND_XREF | RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE,
	.init = init,
	.fini = fini,
	.eval = eval,
	.successors = successors,
	.init_state = init_state,
	.fini_state = fini_state,
	.hash_state = hash_state,
	.set_pc = set_pc,
	.state_as_str = state_as_str,
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
