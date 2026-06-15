// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_util.h>

#include "../prototype/eval.h"
#include "rz_util/ht_uu.h"
#include "rz_util/rz_bitvector.h"

#define INITIAL_STACK_CAPACITY 8

#define MAX_INVOCATIONS_PER_BLOCK 3

bool state_as_str(RZ_NONNULL const RzInterpAbstrState *state,
	RZ_NONNULL RZ_OUT RzStrBuf *sb,
	void *plugin_data);

RZ_OWN RzInterpAbstrVal *clone_val(const RzInterpAbstrVal *val, void *plugin_data) {
	RzInterpAbstrVal *r = RZ_NEW0(RzInterpAbstrVal);
	if (!r) {
		return NULL;
	}
	r->kind = val->kind;
	r->abstr_data = RZ_NEW0(ProtoIntrprAbstrData);
	AD(r->abstr_data)->is_const = AD(val->abstr_data)->is_const;
	AD(r->abstr_data)->bv = rz_bv_dup(AD(val->abstr_data)->bv);
	return r;
}

static bool eval(RZ_NONNULL RzInterpSet *iset,
	RZ_NONNULL const RzILCacheBlock *il_bb,
	void *plugin_data) {
	ProtoIntrprPluginData *pdata = plugin_data;

	// Check invocation count of the current address.
	// Never execute the same address more than MAX_INVOCATIONS_PER_BLOCK times.
	bool found = false;
	HtUUKv *ic_pc = ht_uu_find_kv(pdata->bb_invocation_count, il_bb->addr, &found);
	if (found) {
		ic_pc->value++;
		RZ_LOG_DEBUG("prototype: Eval BLOCK (ic: %" PFMT64d ") = 0x%" PFMT64x "\n", ic_pc->value, il_bb->addr);
		if (ic_pc->value > MAX_INVOCATIONS_PER_BLOCK) {
			// TODO: Make it configurable
			RZ_LOG_DEBUG("prototype: Reached maximum number of invocations of basic block at 0x%" PFMT64x ". Skipping it.\n", il_bb->addr)
			set_pc(iset->astate, il_bb->addr + il_bb->size, plugin_data);
			return true;
		}
	} else {
		ht_uu_update(pdata->bb_invocation_count, il_bb->addr, 1);
	}

	// Reset call candidate tracking for each basic block.
	memset(&pdata->call_cand, 0, sizeof(pdata->call_cand));

	// Now execute the actual effects of the BLOCK.
	RzInterpAbstrState *astate = iset->astate;
	void **it;
	rz_pvector_foreach (il_bb->il_ops, it) {
		ut64 pc = astate->pc;
		RZ_LOG_DEBUG("prototype: Eval PC = 0x%" PFMT64x "\n", pc);
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		state_as_str(iset->astate, &sb, plugin_data);
		RZ_LOG_DEBUG("%s\n", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		rz_strbuf_init(&sb);
		state_as_str_short(iset, &sb, iset->astate);
		rz_meta_set_string(iset->a, RZ_META_TYPE_COMMENT, pc, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		RzILCacheInsnPkt *pkt = *it;

		// Prepare next pc, the evalutation may overwrite this.
		ut64 next_pc = pc + pkt->insn_pkt_size;
		set_pc(iset->astate, next_pc, plugin_data);

		if (!interpreter_prototype_eval_effect(iset, pkt->effect, pkt->insn_pkt_size, plugin_data)) {
			return false;
		}
		if (astate->pc_state != RZ_INTERP_PC_CONST || astate->pc != next_pc) {
			// Unreachable or a jump happened somewhere other than fallthrough, so we can't continue
			// interpreting the block linearly, but have to push the new location
			break;
		}
	}

	if (astate->pc_state != RZ_INTERP_PC_UNREACHABLE) {
		rz_interp_set_push(iset, iset->astate);
	}

	return true;
}

bool successors(RZ_NONNULL const RzInterpAbstrState *state,
	RZ_NONNULL RZ_OUT RzVector /*<RzInterpBranch>*/ *successors,
	void *plugin_data) {
	rz_return_val_if_fail(state && successors, false);
	ProtoIntrprPluginData *pdata = plugin_data;
	if (state->pc_state != RZ_INTERP_PC_CONST) {
		// The PC is not a concrete value.
		// This prototype can't estimate a reasonable concretization for it.
		return true;
	}

	ut64 next_pc = state->pc;
	RzInterpCtrlFlow branch = { 0 };
	branch.target_addr = branch.actual_target = next_pc;
	branch.src_block_addr = pdata->prev_pc;
	rz_vector_push(successors, &branch);
	return true;
}

static bool init_state(RZ_BORROW RzInterpAbstrState *state, void *plugin_data) {
	state->pc = 0;
	state->pc_state = RZ_INTERP_PC_UNREACHABLE;

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(state->globals, djb2_reg_name, NULL);
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
		AD(av->abstr_data)->is_const = false;
		/*if (state->il_config->init_state) {
			RzAnalysisILInitStateVar *il_var;
			rz_vector_foreach (&state->il_config->init_state->vars, il_var) {
				if (rz_str_djb2_hash(il_var->name) != djb2_reg_name) {
					continue;
				}
				// The RzArch plugin defined a default value for this global.
				RzBitVector *default_val = rz_il_value_to_bv(il_var->val);
				rz_bv_copy(AD(av->abstr_data)->bv, default_val);
				rz_bv_free(default_val);
			}
		}*/
	}
	rz_iterator_free(it);
	return true;
}

static bool reset_state(RZ_BORROW RzInterpAbstrState *state, ut64 entry_point, void *plugin_data) {
	state->pc_state = RZ_INTERP_PC_CONST;
	state->pc = entry_point;

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(state->globals, djb2_reg_name, NULL);
		rz_bv_set_from_ut64(AD(av->abstr_data)->bv, 0);
		AD(av->abstr_data)->is_const = false;
		/*if (state->il_config->init_state) {
			RzAnalysisILInitStateVar *il_var;
			rz_vector_foreach (&state->il_config->init_state->vars, il_var) {
				if (rz_str_djb2_hash(il_var->name) != djb2_reg_name) {
					continue;
				}
				// The RzArch plugin defined a default value for this global.
				RzBitVector *default_val = rz_il_value_to_bv(il_var->val);
				rz_bv_copy(AD(av->abstr_data)->bv, default_val);
				rz_bv_free(default_val);
			}
		}*/
	}
	rz_iterator_free(it);
	state->bb_addr = 0;
	state->bb_size = 0;
	return true;
}

static bool fini_state(RZ_BORROW RzInterpAbstrState *state, void *plugin_data) {
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpAbstrVal *av = *v;
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
		RzInterpAbstrVal *av = *v;
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
		RzInterpAbstrVal *av = *v;
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
static ut64 hash_state(RZ_NONNULL const RzInterpAbstrState *state, void *plugin_data) {
	ut64 h = 5381;
	h = (h ^ (h << 5)) ^ (ut64)state->pc_state;
	if (state->pc_state == RZ_INTERP_PC_CONST) {
		h = (h ^ (h << 5)) ^ state->pc;
	}
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpAbstrVal **v;
	rz_iterator_foreach(it, v) {
		RzInterpAbstrVal *av = *v;
		ProtoIntrprAbstrData *ad = av->abstr_data;
		if (ad->bv) {
			h = (h ^ (h << 5)) ^ rz_bv_to_ut64(ad->bv);
		}
	}
	rz_iterator_free(it);
	return h;
}

/**
 * \brief Join (least upper bound) on values
 * \return True if a was changed
 */
static bool join_val(RZ_BORROW RZ_INOUT RzInterpAbstrVal *a, RZ_BORROW RZ_IN const RzInterpAbstrVal *b) {
	ProtoIntrprAbstrData *ad = AD(a->abstr_data);
	ProtoIntrprAbstrData *bd = AD(b->abstr_data);
	if (ad->is_const && bd->is_const && rz_bv_eq(ad->bv, bd->bv)) {
		// identical values, a already has the least upper bound
		return false;
	}
	// for anything else, the least upper bound is top
	bool changed = ad->is_const;
	ad->is_const = false;
	return changed;
}

/**
 * \brief Join (least upper bound) on var sets
 * \return True if a was changed
 */
static bool join_vars(RZ_BORROW RZ_INOUT HtUP *a, RZ_BORROW RZ_IN HtUP *b) {
	RzIterator *it = ht_up_as_iter_keys(a);
	ut64 *k;
	bool changed = false;
	rz_iterator_foreach(it, k) {
		RzInterpAbstrVal *av = ht_up_find(a, *k, NULL);
		RzInterpAbstrVal *bv = ht_up_find(b, *k, NULL);
		if (!av || !bv) {
			continue;
		}
		if (join_val(av, bv)) {
			changed = true;
		}
	}
	return changed;
}

bool join_state(RZ_BORROW RZ_INOUT RzInterpAbstrState *a, RZ_BORROW RZ_IN const RzInterpAbstrState *b, void *plugin_data) {
	bool global_change = join_vars(a->globals, b->globals);
	bool local_change = join_vars(a->locals, b->locals);
	// lets are not be relevant here since they are immutable within their scope
	return global_change || local_change;
}

bool val_as_str(RZ_NONNULL const RzInterpAbstrVal *val, RZ_NONNULL RZ_OUT RzStrBuf *sb, void *plugin_data) {
	rz_return_val_if_fail(val && sb, false);
	ProtoIntrprAbstrData *av = AD(val->abstr_data);
	if (av->is_const) {
		char *s = rz_bv_as_hex_string(av->bv, false);
		if (!s) {
			return false;
		}
		rz_strbuf_append(sb, s);
		free(s);
	} else {
		rz_strbuf_append(sb, "⊤");
	}
	return true;
}

bool state_as_str(RZ_NONNULL const RzInterpAbstrState *state,
	RZ_NONNULL RZ_OUT RzStrBuf *sb,
	void *plugin_data) {
	rz_return_val_if_fail(state && sb, false);

	ut64 hash = hash_state(state, plugin_data);
	rz_strbuf_appendf(sb, "hash = 0x%" PFMT64x "\n\n", hash);
	rz_strbuf_append(sb, "Globals\n\n");
	rz_strbuf_append(sb, "\tpc = ");
	if (state->pc_state == RZ_INTERP_PC_CONST) {
		rz_strbuf_appendf(sb, "0x%" PFMT64x, state->pc);
	} else {
		rz_strbuf_append(sb, state->pc_state == RZ_INTERP_PC_ANY ? "⊤" : "⊥");
	}
	rz_strbuf_append(sb, "\n\n");

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		const char *gname = ht_up_find(state->var_name_hashes, *k, NULL);
		rz_strbuf_appendf(sb, "\t%s = ", gname);
		RzInterpAbstrVal *av = ht_up_find(state->globals, *k, NULL);
		val_as_str(av, sb, plugin_data);
		rz_strbuf_append(sb, "\n");
	}
	rz_iterator_free(it);
	return true;
}

void state_as_str_short(RzInterpSet *iset, RZ_OUT RzStrBuf *out, RzInterpAbstrState *astate) {
	bool first = true;
	RzIterator *it = ht_up_as_iter_keys(astate->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(astate->globals, djb2_reg_name, NULL);
		ProtoIntrprAbstrData *val = av->abstr_data;
		if (!val->is_const) {
			continue;
		}
		if (!first) {
			rz_strbuf_append(out, ", ");
		}
		first = false;
		const char *varname = ht_up_find(astate->var_name_hashes, djb2_reg_name, NULL);
		rz_strbuf_appendf(out, "%s = ", varname);
		iset->plugin->val_as_str(av, out, iset->intrpr_priv);
	}
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
	rz_vector_init(&pdata->stack,
		sizeof(ProtoInterprAbstrStackFrame),
		(RzVectorFree)stack_frame_fini, NULL);
	rz_vector_reserve(&pdata->stack, INITIAL_STACK_CAPACITY);
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
	rz_vector_fini(&pdata->stack);
	free(pdata);
	return true;
}

bool reset(void *plugin_data) {
	if (!plugin_data) {
		return true;
	}
	RZ_LOG_DEBUG("prototype: reset()\n");
	ProtoIntrprPluginData *pdata = plugin_data;
	pdata->prev_pc = UT64_MAX;
	ht_uu_clear(pdata->bb_invocation_count);
	memset(&pdata->call_cand, 0, sizeof(RzAnalysisCallCandidate));
	rz_vector_purge(&pdata->stack);
	return true;
}

static RzInterpPlugin rz_interpreter_plugin_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/top abstractions.",
	.license = "LGPL-3.0-only",
	.supported_abstractions = RZ_INTERP_ABSTRACTION_CONST,
	.supported_yields = { RZ_INTERP_YIELD_KIND_XREF, RZ_INTERP_YIELD_KIND_CALL_CANDIDATE },
	.init = init,
	.reset = reset,
	.fini = fini,
	.clone_val = clone_val,
	.eval = eval,
	.successors = successors,
	.init_state = init_state,
	.reset_state = reset_state,
	.fini_state = fini_state,
	.hash_state = hash_state,
	.join_state = join_state,
	.set_pc = set_pc,
	.state_as_str = state_as_str,
	.val_as_str = val_as_str
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
