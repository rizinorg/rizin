// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_anal.h>

#define D if (anal->verbose)

static bool get_functions_block_cb(RzAnalBlock *block, void *user) {
	RzList *list = user;
	RzListIter *iter;
	RzAnalFunction *fcn;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (rz_list_contains (list, fcn)) {
			continue;
		}
		rz_list_push (list, fcn);
	}
	return true;
}

RZ_API RzList *rz_anal_get_functions_in(RzAnal *anal, ut64 addr) {
	RzList *list = rz_list_new ();
	if (!list) {
		return NULL;
	}
	rz_anal_blocks_foreach_in (anal, addr, get_functions_block_cb, list);
	return list;
}

static bool __fcn_exists(RzAnal *anal, const char *name, ut64 addr) {
	// check if name is already registered
	bool found = false;
	if (addr == UT64_MAX) {
		eprintf ("Invalid function address (-1) '%s'\n", name);
		return true;
	}
	if (!name) {
		eprintf ("TODO: Empty function name, we must auto generate one\n");
		return true;
	}
	RzAnalFunction *f = ht_pp_find (anal->ht_name_fun, name, &found);
	if (f && found) {
		eprintf ("Invalid function name '%s' at 0x%08"PFMT64x"\n", name, addr);
		return true;
	}
	// check if there's a function already in the given address
	found = false;
	f = ht_up_find (anal->ht_addr_fun, addr, &found);
	if (f && found) {
		eprintf ("Function already defined in 0x%08"PFMT64x"\n", addr);
		return true;
	}
	return false;
}

RZ_IPI void rz_anal_var_free(RzAnalVar *av);

static void inst_vars_kv_free(HtUPKv *kv) {
	rz_pvector_free (kv->value);
}

static void labels_kv_free(HtUPKv *kv) {
	free (kv->value);
}

static void label_addrs_kv_free(HtPPKv *kv) {
	free (kv->key);
	free (kv->value);
}

RZ_API RzAnalFunction *rz_anal_function_new(RzAnal *anal) {
	RzAnalFunction *fcn = RZ_NEW0 (RzAnalFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->anal = anal;
	fcn->addr = UT64_MAX;
	fcn->cc = rz_str_constpool_get (&anal->constpool, rz_anal_cc_default (anal));
	fcn->bits = anal->bits;
	fcn->bbs = rz_list_new ();
	fcn->diff = rz_anal_diff_new ();
	fcn->has_changed = true;
	fcn->bp_frame = true;
	fcn->is_noreturn = false;
	fcn->meta._min = UT64_MAX;
	rz_pvector_init (&fcn->vars, NULL);
	fcn->inst_vars = ht_up_new (NULL, inst_vars_kv_free, NULL);
	fcn->labels = ht_up_new (NULL, labels_kv_free, NULL);
	fcn->label_addrs = ht_pp_new (NULL, label_addrs_kv_free, NULL);
	return fcn;
}

RZ_API void rz_anal_function_free(void *_fcn) {
	RzAnalFunction *fcn = _fcn;
	if (!_fcn) {
		return;
	}

	RzAnalBlock *block;
	RzListIter *iter;
	rz_list_foreach (fcn->bbs, iter, block) {
		rz_list_delete_data (block->fcns, fcn);
		rz_anal_block_unref (block);
	}
	rz_list_free (fcn->bbs);

	RzAnal *anal = fcn->anal;
	if (ht_up_find (anal->ht_addr_fun, fcn->addr, NULL) == _fcn) {
		ht_up_delete (anal->ht_addr_fun, fcn->addr);
	}
	if (ht_pp_find (anal->ht_name_fun, fcn->name, NULL) == _fcn) {
		ht_pp_delete (anal->ht_name_fun, fcn->name);
	}

	ht_up_free (fcn->inst_vars);
	fcn->inst_vars = NULL;
	rz_anal_function_delete_all_vars (fcn);

	ht_up_free (fcn->labels);
	ht_pp_free (fcn->label_addrs);

	free (fcn->name);
	fcn->bbs = NULL;
	free (fcn->fingerprint);
	rz_anal_diff_free (fcn->diff);
	rz_list_free (fcn->imports);
	free (fcn);
}

RZ_API bool rz_anal_add_function(RzAnal *anal, RzAnalFunction *fcn) {
	if (__fcn_exists (anal, fcn->name, fcn->addr)) {
		return false;
	}
	if (anal->cb.on_fcn_new) {
		anal->cb.on_fcn_new (anal, anal->user, fcn);
	}
	if (anal->flg_fcn_set) {
		anal->flg_fcn_set (anal->flb.f, fcn->name, fcn->addr, rz_anal_function_size_from_entry (fcn));
	}
	fcn->is_noreturn = rz_anal_noreturn_at_addr (anal, fcn->addr);
	rz_list_append (anal->fcns, fcn);
	ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
	ht_up_insert (anal->ht_addr_fun, fcn->addr, fcn);
	return true;
}

RZ_API RzAnalFunction *rz_anal_create_function(RzAnal *anal, const char *name, ut64 addr, int type, RzAnalDiff *diff) {
	RzAnalFunction *fcn = rz_anal_function_new (anal);
	if (!fcn) {
		return NULL;
	}
	fcn->addr = addr;
	fcn->type = type;
	fcn->cc = rz_str_constpool_get (&anal->constpool, rz_anal_cc_default (anal));
	fcn->bits = anal->bits;
	if (name) {
		free (fcn->name);
		fcn->name = strdup (name);
	} else {
		const char *fcnprefix = anal->coreb.cfgGet ? anal->coreb.cfgGet (anal->coreb.core, "anal.fcnprefix") : NULL;
		if (!fcnprefix) {
			fcnprefix = "fcn";
		}
		fcn->name = rz_str_newf ("%s.%08"PFMT64x, fcnprefix, fcn->addr);
	}
	if (diff) {
		fcn->diff->type = diff->type;
		fcn->diff->addr = diff->addr;
		RZ_FREE (fcn->diff->name);
		if (diff->name) {
			fcn->diff->name = strdup (diff->name);
		}
	}
	if (!rz_anal_add_function (anal, fcn)) {
		rz_anal_function_free (fcn);
		return NULL;
	}
	return fcn;
}

RZ_API bool rz_anal_function_delete(RzAnalFunction *fcn) {
	return rz_list_delete_data (fcn->anal->fcns, fcn);
}

RZ_API RzAnalFunction *rz_anal_get_function_at(RzAnal *anal, ut64 addr) {
	bool found = false;
	RzAnalFunction *f = ht_up_find (anal->ht_addr_fun, addr, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

typedef struct {
	HtUP *inst_vars_new;
	st64 delta;
} InstVarsRelocateCtx;

static bool inst_vars_relocate_cb(void *user, const ut64 k, const void *v) {
	InstVarsRelocateCtx *ctx = user;
	ht_up_insert (ctx->inst_vars_new, k - ctx->delta, (void *)v);
	return true;
}

RZ_API bool rz_anal_function_relocate(RzAnalFunction *fcn, ut64 addr) {
	if (fcn->addr == addr) {
		return true;
	}
	if (rz_anal_get_function_at (fcn->anal, addr)) {
		return false;
	}
	ht_up_delete (fcn->anal->ht_addr_fun, fcn->addr);

	// relocate the var accesses (their addrs are relative to the function addr)
	st64 delta = (st64)addr - (st64)fcn->addr;
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalVar *var = *it;
		RzAnalVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
			acc->offset -= delta;
		}
	}
	InstVarsRelocateCtx ctx = {
		.inst_vars_new = ht_up_new (NULL, inst_vars_kv_free, NULL),
		.delta = delta
	};
	if (ctx.inst_vars_new) {
		ht_up_foreach (fcn->inst_vars, inst_vars_relocate_cb, &ctx);
		// Do not free the elements of the Ht, because they were moved to ctx.inst_vars_new
		fcn->inst_vars->opt.freefn = NULL;
		ht_up_free (fcn->inst_vars);
		fcn->inst_vars = ctx.inst_vars_new;
	}

	fcn->addr = addr;
	ht_up_insert (fcn->anal->ht_addr_fun, addr, fcn);
	return true;
}

RZ_API bool rz_anal_function_rename(RzAnalFunction *fcn, const char *name) {
	RzAnal *anal = fcn->anal;
	RzAnalFunction *existing = ht_pp_find (anal->ht_name_fun, name, NULL);
	if (existing) {
		if (existing == fcn) {
			// fcn->name == name, nothing to do
			return true;
		}
		return false;
	}
	char *newname = strdup (name);
	if (!newname) {
		return false;
	}
	bool in_tree = ht_pp_delete (anal->ht_name_fun, fcn->name);
	free (fcn->name);
	fcn->name = newname;
	if (in_tree) {
		// only re-insert if it really was in the tree before
		ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
	}
	return true;
}

RZ_API void rz_anal_function_add_block(RzAnalFunction *fcn, RzAnalBlock *bb) {
	if (rz_list_contains (bb->fcns, fcn)) {
		return;
	}
	rz_list_append (bb->fcns, fcn); // associate the given fcn with this bb
	rz_anal_block_ref (bb);
	rz_list_append (fcn->bbs, bb);

	if (fcn->meta._min != UT64_MAX) {
		if (bb->addr + bb->size > fcn->meta._max) {
			fcn->meta._max = bb->addr + bb->size;
		}
		if (bb->addr < fcn->meta._min) {
			fcn->meta._min = bb->addr;
		}
	}

	if (fcn->anal->cb.on_fcn_bb_new) {
		fcn->anal->cb.on_fcn_bb_new (fcn->anal, fcn->anal->user, fcn, bb);
	}
}

RZ_API void rz_anal_function_remove_block(RzAnalFunction *fcn, RzAnalBlock *bb) {
	rz_list_delete_data (bb->fcns, fcn);

	if (fcn->meta._min != UT64_MAX
		&& (fcn->meta._min == bb->addr || fcn->meta._max == bb->addr + bb->size)) {
		// If a block is removed at the beginning or end, updating min/max is not trivial anymore, just invalidate
		fcn->meta._min = UT64_MAX;
	}

	rz_list_delete_data (fcn->bbs, bb);
	rz_anal_block_unref (bb);
}

static void ensure_fcn_range(RzAnalFunction *fcn) {
	if (fcn->meta._min != UT64_MAX) { // recalculate only if invalid
		return;
	}
	ut64 minval = UT64_MAX;
	ut64 maxval = UT64_MIN;
	RzAnalBlock *block;
	RzListIter *iter;
	rz_list_foreach (fcn->bbs, iter, block) {
			if (block->addr < minval) {
				minval = block->addr;
			}
			if (block->addr + block->size > maxval) {
				maxval = block->addr + block->size;
			}
		}
	fcn->meta._min = minval;
	fcn->meta._max = minval == UT64_MAX ? UT64_MAX : maxval;
}

RZ_API ut64 rz_anal_function_linear_size(RzAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._max - fcn->meta._min;
}

RZ_API ut64 rz_anal_function_min_addr(RzAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._min;
}

RZ_API ut64 rz_anal_function_max_addr(RzAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._max;
}

RZ_API ut64 rz_anal_function_size_from_entry(RzAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._min == UT64_MAX ? 0 : fcn->meta._max - fcn->addr;
}

RZ_API ut64 rz_anal_function_realsize(const RzAnalFunction *fcn) {
	RzListIter *iter;
	RzAnalBlock *bb;
	ut64 sz = 0;
	if (!sz) {
		rz_list_foreach (fcn->bbs, iter, bb) {
			sz += bb->size;
		}
	}
	return sz;
}

static bool fcn_in_cb(RzAnalBlock *block, void *user) {
	RzListIter *iter;
	RzAnalFunction *fcn;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (fcn == user) {
			return false;
		}
	}
	return true;
}

RZ_API bool rz_anal_function_contains(RzAnalFunction *fcn, ut64 addr) {
	// fcn_in_cb breaks with false if it finds the fcn
	return !rz_anal_blocks_foreach_in (fcn->anal, addr, fcn_in_cb, fcn);
}

RZ_API bool rz_anal_function_was_modified(RzAnalFunction *fcn) {
	rz_return_val_if_fail (fcn, false);
	RzListIter *it;
	RzAnalBlock *bb;
	rz_list_foreach (fcn->bbs, it, bb) {
		if (rz_anal_block_was_modified (bb)) {
			return true;
		}
	}
	return false;
}
