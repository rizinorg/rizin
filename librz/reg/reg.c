// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>
#include <rz_util.h>

RZ_LIB_VERSION(rz_reg);

static const char *types[RZ_REG_TYPE_LAST + 1] = {
	"gpr", "drx", "fpu", "mmx", "xmm", "ymm", "flg", "seg", "sys", "sec", NULL
};

// Take the 32bits name of a register, and return the 64 bit name of it.
// If there is no equivalent 64 bit register return NULL.
// SLOW
RZ_API const char *rz_reg_32_to_64(RzReg *reg, const char *rreg32) {
	int i, j = -1;
	RzListIter *iter;
	RzRegItem *item;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size == 32 && !rz_str_casecmp(rreg32, item->name)) {
				j = item->offset;
				break;
			}
		}
	}
	if (j != -1) {
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_list_foreach (reg->regset[i].regs, iter, item) {
				if (item->offset == j && item->size == 64) {
					return item->name;
				}
			}
		}
	}
	return NULL;
}

// Take the 64 bits name of a register, and return the 32 bit name of it.
// If there is no equivalent 32 bit register return NULL.
// SLOW
RZ_API const char *rz_reg_64_to_32(RzReg *reg, const char *rreg64) {
	int i, j = -1;
	RzListIter *iter;
	RzRegItem *item;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size == 64 && !rz_str_casecmp(rreg64, item->name)) {
				j = item->offset;
				break;
			}
		}
	}
	if (j != -1) {
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_list_foreach (reg->regset[i].regs, iter, item) {
				if (item->offset == j && item->size == 32) {
					return item->name;
				}
			}
		}
	}
	return NULL;
}

RZ_API const char *rz_reg_get_type(int idx) {
	return (idx >= 0 && idx < RZ_REG_TYPE_LAST) ? types[idx] : NULL;
}

RZ_API const char *rz_reg_get_name_by_type(RzReg *reg, const char *alias_name) {
	const int n = rz_reg_get_name_idx(alias_name);
	return (n != -1) ? rz_reg_get_name(reg, n) : NULL;
}

RZ_API int rz_reg_type_by_name(const char *str) {
	rz_return_val_if_fail(str, -1);
	int i;
	for (i = 0; i < RZ_REG_TYPE_LAST && types[i]; i++) {
		if (!strcmp(types[i], str)) {
			return i;
		}
	}
	if (!strcmp(str, "all")) {
		return RZ_REG_TYPE_ANY;
	}
	return -1;
}

RZ_API void rz_reg_item_free(RzRegItem *item) {
	free(item->name);
	free(item->flags);
	free(item);
}

RZ_API int rz_reg_get_name_idx(const char *type) {
	rz_return_val_if_fail(type, -1);
	if (type[0] && type[1] && !type[2])
		switch (*type | (type[1] << 8)) {
		/* flags */
		case 'Z' + ('F' << 8): return RZ_REG_NAME_ZF;
		case 'S' + ('F' << 8): return RZ_REG_NAME_SF;
		case 'C' + ('F' << 8): return RZ_REG_NAME_CF;
		case 'O' + ('F' << 8): return RZ_REG_NAME_OF;
		/* gpr */
		case 'P' + ('C' << 8): return RZ_REG_NAME_PC;
		case 'S' + ('R' << 8): return RZ_REG_NAME_SR;
		case 'L' + ('R' << 8): return RZ_REG_NAME_LR;
		case 'S' + ('P' << 8): return RZ_REG_NAME_SP;
		case 'B' + ('P' << 8): return RZ_REG_NAME_BP;
		case 'S' + ('N' << 8): return RZ_REG_NAME_SN;
		/* args */
		case 'A' + ('0' << 8): return RZ_REG_NAME_A0;
		case 'A' + ('1' << 8): return RZ_REG_NAME_A1;
		case 'A' + ('2' << 8): return RZ_REG_NAME_A2;
		case 'A' + ('3' << 8): return RZ_REG_NAME_A3;
		case 'A' + ('4' << 8): return RZ_REG_NAME_A4;
		case 'A' + ('5' << 8): return RZ_REG_NAME_A5;
		case 'A' + ('6' << 8): return RZ_REG_NAME_A6;
		case 'A' + ('7' << 8): return RZ_REG_NAME_A7;
		case 'A' + ('8' << 8): return RZ_REG_NAME_A8;
		case 'A' + ('9' << 8): return RZ_REG_NAME_A9;
		/* return values */
		case 'R' + ('0' << 8): return RZ_REG_NAME_R0;
		case 'R' + ('1' << 8): return RZ_REG_NAME_R1;
		case 'R' + ('2' << 8): return RZ_REG_NAME_R2;
		case 'R' + ('3' << 8): return RZ_REG_NAME_R3;
		}
	return -1;
}

RZ_API bool rz_reg_set_name(RzReg *reg, int role, const char *name) {
	rz_return_val_if_fail(reg && name, false);
	if (role >= 0 && role < RZ_REG_NAME_LAST) {
		reg->name[role] = rz_str_dup(reg->name[role], name);
		return true;
	}
	return false;
}

RZ_API const char *rz_reg_get_name(RzReg *reg, int role) {
	if (reg && role >= 0 && role < RZ_REG_NAME_LAST) {
		return reg->name[role];
	}
	return NULL;
}

RZ_API RzRegItem *rz_reg_get_by_role(RzReg *reg, RzRegisterId role) {
	rz_return_val_if_fail(reg, NULL);
	const char *name = rz_reg_get_name(reg, role);
	if (!name) {
		return NULL;
	}
	return rz_reg_get(reg, name, RZ_REG_TYPE_ANY);
}

static const char *roles[RZ_REG_NAME_LAST + 1] = {
	"PC", "SP", "SR", "BP", "LR",
	"A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9",
	"R0", "R1", "R2", "R3",
	"ZF", "SF", "CF", "OF",
	"SN",
	NULL
};

RZ_API const char *rz_reg_get_role(int role) {
	if (role >= 0 && role < RZ_REG_NAME_LAST) {
		return roles[role];
	}
	return NULL;
}

/// Get the RzRegisterId with the given name or -1
RZ_API int rz_reg_role_by_name(RZ_NONNULL const char *str) {
	rz_return_val_if_fail(str, -1);
	int i;
	for (i = 0; i < RZ_REG_NAME_LAST && roles[i]; i++) {
		if (!strcmp(roles[i], str)) {
			return i;
		}
	}
	return -1;
}

RZ_API void rz_reg_free_internal(RzReg *reg, bool init) {
	rz_return_if_fail(reg);
	ut32 i;

	rz_list_free(reg->roregs);
	reg->roregs = NULL;
	RZ_FREE(reg->reg_profile_str);
	RZ_FREE(reg->reg_profile_cmt);

	for (i = 0; i < RZ_REG_NAME_LAST; i++) {
		if (reg->name[i]) {
			RZ_FREE(reg->name[i]);
		}
	}
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		ht_pp_free(reg->regset[i].ht_regs);
		reg->regset[i].ht_regs = NULL;
		if (!reg->regset[i].pool) {
			continue;
		}
		if (init) {
			rz_list_free(reg->regset[i].regs);
			reg->regset[i].regs = rz_list_newf((RzListFree)rz_reg_item_free);
		} else {
			rz_list_free(reg->regset[i].regs);
			reg->regset[i].regs = NULL;
			// Ensure arena is freed and its registered in the pool
			if (!rz_list_delete_data(reg->regset[i].pool, reg->regset[i].arena)) {
				rz_reg_arena_free(reg->regset[i].arena);
			}
			reg->regset[i].arena = NULL;
			rz_list_free(reg->regset[i].pool);
			reg->regset[i].pool = NULL;
		}
	}
	if (!init) {
		rz_list_free(reg->allregs);
		reg->allregs = NULL;
	}
	reg->size = 0;
}

static int regcmp(RzRegItem *a, RzRegItem *b) {
	int offa = (a->offset * 16) + a->size;
	int offb = (b->offset * 16) + b->size;
	return (offa > offb) - (offa < offb);
}

RZ_API void rz_reg_reindex(RzReg *reg) {
	int i, index;
	RzListIter *iter;
	RzRegItem *r;
	RzList *all = rz_list_newf(NULL);
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_list_foreach (reg->regset[i].regs, iter, r) {
			rz_list_append(all, r);
		}
	}
	rz_list_sort(all, (RzListComparator)regcmp);
	index = 0;
	rz_list_foreach (all, iter, r) {
		r->index = index++;
	}
	rz_list_free(reg->allregs);
	reg->allregs = all;
}

RZ_API RzRegItem *rz_reg_index_get(RzReg *reg, int idx) {
	RzRegItem *r;
	RzListIter *iter;
	if (idx < 0) {
		return NULL;
	}
	if (!reg->allregs) {
		rz_reg_reindex(reg);
	}
	rz_list_foreach (reg->allregs, iter, r) {
		if (r->index == idx) {
			return r;
		}
	}
	return NULL;
}

RZ_API void rz_reg_free(RzReg *reg) {
	if (reg) {
		rz_reg_free_internal(reg, false);
		free(reg);
	}
}

RZ_API RzReg *rz_reg_new(void) {
	RzRegArena *arena;
	RzReg *reg = RZ_NEW0(RzReg);
	int i;
	if (!reg) {
		return NULL;
	}
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		arena = rz_reg_arena_new(0);
		if (!arena) {
			free(reg);
			return NULL;
		}
		reg->regset[i].pool = rz_list_newf((RzListFree)rz_reg_arena_free);
		reg->regset[i].regs = rz_list_newf((RzListFree)rz_reg_item_free);
		rz_list_push(reg->regset[i].pool, arena);
		reg->regset[i].arena = arena;
	}
	rz_reg_arena_push(reg);
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		reg->regset[i].cur = rz_list_tail(reg->regset[i].pool);
	}
	return reg;
}

RZ_API bool rz_reg_is_readonly(RzReg *reg, RzRegItem *item) {
	const char *name;
	RzListIter *iter;
	if (!reg->roregs) {
		return false;
	}
	// XXX O(n)
	rz_list_foreach (reg->roregs, iter, name) {
		if (!strcmp(item->name, name)) {
			return true;
		}
	}
	return false;
}

RZ_API ut64 rz_reg_setv(RzReg *reg, const char *name, ut64 val) {
	rz_return_val_if_fail(reg && name, UT64_MAX);
	RzRegItem *ri = rz_reg_get(reg, name, -1);
	return ri ? rz_reg_set_value(reg, ri, val) : UT64_MAX;
}

RZ_API ut64 rz_reg_getv(RzReg *reg, const char *name) {
	rz_return_val_if_fail(reg && name, UT64_MAX);
	RzRegItem *ri = rz_reg_get(reg, name, -1);
	return ri ? rz_reg_get_value(reg, ri) : UT64_MAX;
}

RZ_API ut64 rz_reg_getv_by_role_or_name(RzReg *reg, const char *name) {
	rz_return_val_if_fail(reg && name, UT64_MAX);
	RzRegItem *ri = rz_reg_get_by_role_or_name(reg, name);
	return ri ? rz_reg_get_value(reg, ri) : UT64_MAX;
}

RZ_API RzRegItem *rz_reg_get(RzReg *reg, const char *name, int type) {
	int i, e;
	rz_return_val_if_fail(reg && name, NULL);
	// TODO: define flag register as RZ_REG_TYPE_FLG
	if (type == RZ_REG_TYPE_FLG) {
		type = RZ_REG_TYPE_GPR;
	}
	if (type == -1) {
		i = 0;
		e = RZ_REG_TYPE_LAST;
		int alias = rz_reg_get_name_idx(name);
		if (alias != -1) {
			const char *nname = rz_reg_get_name(reg, alias);
			if (nname) {
				name = nname;
			}
		}
	} else {
		i = type;
		e = type + 1;
	}
	for (; i < e; i++) {
		HtPP *pp = reg->regset[i].ht_regs;
		if (pp) {
			bool found = false;
			RzRegItem *item = ht_pp_find(pp, name, &found);
			if (found) {
				return item;
			}
		}
	}
	return NULL;
}

RZ_API RzRegItem *rz_reg_get_by_role_or_name(RzReg *reg, const char *name) {
	int role = rz_reg_get_name_idx(name);
	if (role != -1) {
		RzRegItem *r = rz_reg_get_by_role(reg, role);
		if (r) {
			return r;
		}
	}
	return rz_reg_get(reg, name, RZ_REG_TYPE_ANY);
}

RZ_API const RzList *rz_reg_get_list(RzReg *reg, int type) {
	if (type == RZ_REG_TYPE_ANY) {
		return reg->allregs;
	}

	RzList *regs;
	int i, mask;
	if (type < 0 || type > (RZ_REG_TYPE_LAST - 1)) {
		return NULL;
	}

	regs = reg->regset[type].regs;
	if (rz_list_length(regs) == 0) {
		mask = ((int)1 << type);
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			if (reg->regset[i].maskregstype & mask) {
				regs = reg->regset[i].regs;
			}
		}
	}

	return regs;
}

// TODO regsize is in bits, delta in bytes, maybe we should standarize this..
RZ_API RzRegItem *rz_reg_get_at(RzReg *reg, int type, int regsize, int delta) {
	rz_return_val_if_fail(reg, NULL);
	const RzList *list = rz_reg_get_list(reg, type);
	RzRegItem *ri;
	RzListIter *iter;
	rz_list_foreach (list, iter, ri) {
		if (ri->size == regsize) {
			if (BITS2BYTES(ri->offset) == delta) {
				return ri;
			}
		}
	}
	return NULL;
}

/* return the next register in the current regset that differs from */
RZ_API RzRegItem *rz_reg_next_diff(RzReg *reg, int type, const ut8 *buf, int buflen, RzRegItem *prev_ri, int regsize) {
	rz_return_val_if_fail(reg && buf, NULL);
	if (type < 0 || type > (RZ_REG_TYPE_LAST - 1)) {
		return NULL;
	}
	RzRegArena *arena = reg->regset[type].arena;
	int prev_offset = prev_ri ? (prev_ri->offset / 8) + (prev_ri->size / 8) : 0;
	RzList *list = reg->regset[type].regs;
	RzRegItem *ri;
	RzListIter *iter;
	int offset;
	rz_list_foreach (list, iter, ri) {
		offset = ri->offset / 8;
		if (offset > prev_offset) {
			if (memcmp(arena->bytes + offset, buf + offset, ri->size / 8)) {
				return ri;
			}
		}
	}
	return NULL;
}

RZ_API RzRegSet *rz_reg_regset_get(RzReg *r, int type) {
	rz_return_val_if_fail(r, NULL);
	if (type < 0 || type >= RZ_REG_TYPE_LAST) {
		return NULL;
	}
	RzRegSet *rs = &r->regset[type];
	return rs->arena ? rs : NULL;
}

static bool foreach_reg_cb(RzIntervalNode *node, void *user) {
	RzRegItem *from_list = user;
	RzRegItem *from_tree = node->data;
	if (from_list == from_tree) {
		return true;
	}
	// Check if from_list is covered entirely by from_tree, but is also smaller than it.
	// We already know that
	//   from_tree->offset <= from_list->offset < from_tree->offset + from_tree->size
	if (from_list->offset + from_list->size > from_tree->offset + from_tree->size) {
		// from_list expands beyond from_tree, so it's not covered
		return true;
	}
	if (from_list->offset + from_list->size == from_tree->offset + from_tree->size) {
		// they end at the same position, so it is covered entirely, but is it also smaller?
		if (from_list->offset == from_tree->offset) {
			// nope
			return true;
		}
	}
	// from_list ends before from_tree, so it is covered and smaller
	return false;
}

/**
 * \brief Filter out all register items that are smaller than but covered entirely by some other register
 * \param regs list of RzRegItem
 */
RZ_API RZ_OWN RzList *rz_reg_filter_items_covered(RZ_BORROW RZ_NONNULL const RzList /* <RzRegItem> */ *regs) {
	rz_return_val_if_fail(regs, NULL);
	RzList *ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	RzIntervalTree t;
	rz_interval_tree_init(&t, NULL);
	RzRegItem *item;
	RzListIter *it;
	rz_list_foreach (regs, it, item) {
		if (item->offset < 0 || item->size <= 0) {
			continue;
		}
		rz_interval_tree_insert(&t, item->offset, item->offset + item->size - 1, item);
	}
	rz_list_foreach (regs, it, item) {
		if (item->offset < 0 || item->size <= 0) {
			rz_list_push(ret, item);
			continue;
		}
		if (!rz_interval_tree_all_in(&t, item->offset, true, foreach_reg_cb, item)) {
			// foreach_reg_cb break-ed so it found a cover
			continue;
		}
		rz_list_push(ret, item);
	}
	rz_interval_tree_fini(&t);
	return ret;
}
