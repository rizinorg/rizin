// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_reg.h>
#include <rz_il/rz_il_vm.h>
#include <rz_util.h>

static int reg_offset_cmp(const void *value, const void *list_data, void *user) {
	return ((RzRegItem *)value)->offset - ((RzRegItem *)list_data)->offset;
}

static void reg_binding_item_fini(RzILRegBindingItem *item, void *unused) {
	free(item->name);
}

/**
 * \brief Calculate a new binding of IL variables against the profile of the given RzReg
 *
 * Because registers can overlap, not all registers may get a binding.
 * Informally, only the "larger" ones, containing "smaller" ones are bound,
 * except for 1-bit registers, which are always preferred.
 *
 * More specifically, the set of registers to be bound is determined like this:
 * First, bind all 1-bit registers (flags).
 * Then, bind a (sub)set of the remaining registers like this:
 * * Begin with the set of all registers.
 * * Remove all registers overlapping with an already-bound 1-bit register.
 * * Remove all registers that are covered entirely by another register in the same set and are smaller than it.
 * * Remove the one marked with RZ_REG_NAME_PC, if it exists.
 * * While there still exists at least overlap, from the overlap of two registers at the lowest offset,
 *   remove the register with the higher offset.
 *
 * If two registers have the same offset and size, the result is currently undefined.
 */
RZ_API RzILRegBinding *rz_il_reg_binding_derive(RZ_NONNULL RzReg *reg) {
	rz_return_val_if_fail(reg, NULL);
	RzILRegBinding *rb = RZ_NEW0(RzILRegBinding);
	if (!rb) {
		return NULL;
	}
	RzVector regs;
	rz_vector_init(&regs, sizeof(RzILRegBindingItem), (RzVectorFree)reg_binding_item_fini, NULL);
	for (int i = 0; i < RZ_REG_TYPE_LAST; i++) {
		// bind all flags (1-bit regs) unconditionally
		RzRegItem *item;
		RzListIter *iter;
		RzList *flags = rz_list_new();
		if (!flags) {
			continue;
		}
		rz_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size != 1) {
				continue;
			}
			// check for same-offset flag
			RzRegItem *item2;
			RzListIter *iter2;
			rz_list_foreach (flags, iter2, item2) {
				if (item2->offset == item->offset) {
					goto next_flag;
				}
			}
			// all good, bind it
			rz_list_push(flags, item);
			char *name = rz_str_dup(item->name);
			if (!name) {
				rz_list_free(flags);
				goto err;
			}
			RzILRegBindingItem *bitem = rz_vector_push(&regs, NULL);
			if (!bitem) {
				free(name);
				rz_list_free(flags);
				goto err;
			}
			bitem->name = name;
			bitem->size = item->size;
		next_flag:
			continue;
		}
		// for the remaining regs, first filter regs that contain a flag
		RzList *nonflags = rz_list_new();
		if (!nonflags) {
			rz_list_free(flags);
			goto err;
		}
		rz_list_foreach (reg->regset[i].regs, iter, item) {
			RzRegItem *flag;
			RzListIter *fiter;
			rz_list_foreach (flags, fiter, flag) {
				if (flag->offset >= item->offset && flag->offset < item->offset + item->size) {
					goto next_reg;
				}
			}
			rz_list_push(nonflags, item);
		next_reg:
			continue;
		}
		// then bind the remaining regs, favoring larger ones on overlaps
		RzList *items = rz_reg_filter_items_covered(nonflags);
		rz_list_free(nonflags);
		if (!items) {
			rz_list_free(flags);
			continue;
		}
		rz_list_sort(items, reg_offset_cmp, NULL);
		const char *pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
		RzRegItem *prev = NULL;
		rz_list_foreach (items, iter, item) {
			if (prev && prev->offset + prev->size > item->offset) {
				RZ_LOG_WARN("Could not bind register \"%s\"\n"
					    "\t It is not fully contained in another but overlaps with one.\n",
					item->name);
				continue;
			}
			if (pc && !strcmp(item->name, pc)) {
				// pc is handled outside of reg binding
				continue;
			}
			char *name = rz_str_dup(item->name);
			if (!name) {
				rz_list_free(flags);
				rz_list_free(items);
				goto err;
			}
			RzILRegBindingItem *bitem = rz_vector_push(&regs, NULL);
			if (!bitem) {
				free(name);
				rz_list_free(flags);
				rz_list_free(items);
				goto err;
			}
			bitem->name = name;
			bitem->size = item->size;
			prev = item;
		}
		rz_list_free(items);
		rz_list_free(flags);
	}
	// from now on, the array should be treated immutable, so we deliberately don't use RzVector anymore.
	rb->regs_count = rz_vector_len(&regs);
	rb->regs = rz_vector_flush(&regs);
	rz_vector_fini(&regs);
	return rb;
err:
	rz_vector_fini(&regs);
	free(rb);
	return NULL;
}

/**
 * Create a new binding that binds exactly the given register names, querying \p reg for any additionally needed info
 * \param regs array of \p regs_count names of registers. Each of these must be part of \p reg and they must not overlap.
 */
RZ_API RzILRegBinding *rz_il_reg_binding_exactly(RZ_NONNULL RzReg *reg, size_t regs_count, RZ_NONNULL RZ_BORROW const char **regs) {
	rz_return_val_if_fail(reg && regs, NULL);
	RzILRegBinding *rb = RZ_NEW(RzILRegBinding);
	if (!rb) {
		return NULL;
	}
	rb->regs_count = regs_count;
	rb->regs = RZ_NEWS0(RzILRegBindingItem, regs_count);
	if (!rb->regs) {
		goto err_rb;
	}
	// all bound items to check for overlaps
	RzRegItem **items = RZ_NEWS(RzRegItem *, regs_count);
	if (!items) {
		goto err_regs;
	}
	for (size_t i = 0; i < regs_count; i++) {
		RzRegItem *ri = rz_reg_get(reg, regs[i], RZ_REG_TYPE_ANY);
		if (!ri) {
			goto err_regs;
		}
		// Check if this item overlaps any already bound registers.
		// Overlaps must not happen because they will confuse the VM and analysis.
		for (size_t j = 0; j < i; j++) {
			if (items[j]->type != ri->type) {
				continue;
			}
			if (items[j]->offset + items[j]->size <= ri->offset || items[j]->offset >= ri->offset + ri->size) {
				continue;
			}
			// overlap detected
			goto err_regs;
		}
		rb->regs[i].name = rz_str_dup(regs[i]);
		if (!rb->regs[i].name) {
			goto err_regs;
		}
		rb->regs[i].size = ri->size;
		items[i] = ri;
	}
	free(items);
	return rb;
err_regs:
	for (size_t i = 0; i < regs_count; i++) {
		reg_binding_item_fini(&rb->regs[i], NULL);
	}
	free(rb->regs);
	free(items);
err_rb:
	free(rb);
	return NULL;
}

RZ_API void rz_il_reg_binding_free(RzILRegBinding *rb) {
	if (!rb) {
		return;
	}
	for (size_t i = 0; i < rb->regs_count; i++) {
		reg_binding_item_fini(&rb->regs[i], NULL);
	}
	free(rb->regs);
	free(rb);
}

/**
 * Setup variables to bind against registers
 * \p rb the binding for which to create variables
 */
RZ_API void rz_il_vm_setup_reg_binding(RZ_NONNULL RzILVM *vm, RZ_NONNULL RZ_BORROW RzILRegBinding *rb) {
	rz_return_if_fail(vm && rb);
	for (size_t i = 0; i < rb->regs_count; i++) {
		rz_il_vm_create_global_var(vm, rb->regs[i].name,
			rb->regs[i].size == 1 ? rz_il_sort_pure_bool() : rz_il_sort_pure_bv(rb->regs[i].size));
	}
}

/**
 * Set the values of all bound regs in \p reg to the respective variable or PC contents in \p vm.
 *
 * Contents of unbound registers are left unchanged (unless they overlap with bound registers).
 *
 * If for example the register profile used for \p reg does not match the one used to build the initial binding,
 * different errors might happen, e.g. a register size might not match the variable's value size.
 * In such cases, this function still applies everything it can, zero-extending or cropping values where necessary.
 *
 * \return whether the sync was cleanly applied without errors or adjustments
 */
RZ_API bool rz_il_vm_sync_to_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILRegBinding *rb, RZ_NONNULL RzReg *reg) {
	rz_return_val_if_fail(vm && rb && reg, false);
	bool perfect = true;
	const char *pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
	if (pc) {
		RzRegItem *ri = rz_reg_get(reg, pc, RZ_REG_TYPE_ANY);
		if (ri) {
			RzBitVector *pcbv = rz_bv_new_zero(ri->size);
			if (pcbv) {
				perfect &= rz_bv_len(pcbv) == rz_bv_len(vm->pc);
				rz_bv_copy_nbits(vm->pc, 0, pcbv, 0, RZ_MIN(rz_bv_len(pcbv), rz_bv_len(vm->pc)));
				rz_reg_set_bv(reg, ri, pcbv);
				rz_bv_free(pcbv);
			} else {
				perfect = false;
			}
		} else {
			perfect = false;
		}
	} else {
		perfect = false;
	}
	for (size_t i = 0; i < rb->regs_count; i++) {
		RzILRegBindingItem *item = &rb->regs[i];
		RzRegItem *ri = rz_reg_get(reg, item->name, RZ_REG_TYPE_ANY);
		if (!ri) {
			perfect = false;
			continue;
		}
		RzILVal *val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, item->name);
		if (!val) {
			perfect = false;
			RzBitVector *bv = rz_bv_new_zero(ri->size);
			if (!bv) {
				break;
			}
			if (bv) {
				rz_reg_set_bv(reg, ri, bv);
				rz_bv_free(bv);
			}
			continue;
		}
		RzBitVector *dupped = NULL;
		const RzBitVector *bv;
		if (val->type == RZ_IL_TYPE_PURE_BITVECTOR) {
			bv = val->data.bv;
			if (rz_bv_len(bv) != ri->size) {
				perfect = false;
				dupped = rz_bv_new_zero(ri->size);
				if (!dupped) {
					break;
				}
				if (ri->size > 1) {
					rz_bv_copy_nbits(bv, 0, dupped, 0, RZ_MIN(rz_bv_len(bv), ri->size));
				} else {
					rz_bv_set_from_ut64(dupped, rz_bv_is_zero_vector(bv) ? 0 : 1);
				}
				bv = dupped;
			}
		} else { // RZ_IL_VAR_TYPE_BOOL
			bv = dupped = val->data.b->b ? rz_bv_new_one(ri->size) : rz_bv_new_zero(ri->size);
			if (!dupped) {
				break;
			}
		}
		perfect &= rz_reg_set_bv(reg, ri, bv);
		rz_bv_free(dupped);
	}
	return perfect;
}

/**
 * Set the values of all variables in \p vm that are bound to registers and PC to the respective contents from \p reg.
 * Contents of variables that are not bound to a register are left unchanged.
 */
RZ_API void rz_il_vm_sync_from_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILRegBinding *rb, RZ_NONNULL RzReg *reg) {
	rz_return_if_fail(vm && rb && reg);
	const char *pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
	if (pc) {
		RzRegItem *ri = rz_reg_get(reg, pc, RZ_REG_TYPE_ANY);
		if (ri) {
			rz_bv_set_all(vm->pc, 0);
			RzBitVector *pcbv = rz_reg_get_bv(reg, ri);
			if (pcbv) {
				rz_bv_copy_nbits(pcbv, 0, vm->pc, 0, RZ_MIN(rz_bv_len(pcbv), rz_bv_len(vm->pc)));
				rz_bv_free(pcbv);
			}
		}
	}
	for (size_t i = 0; i < rb->regs_count; i++) {
		RzILRegBindingItem *item = &rb->regs[i];
		RzILVar *var = rz_il_vm_get_var(vm, RZ_IL_VAR_KIND_GLOBAL, item->name);
		if (!var) {
			RZ_LOG_ERROR("IL Variable \"%s\" does not exist for bound register of the same name.\n", item->name);
			continue;
		}
		RzRegItem *ri = rz_reg_get(reg, item->name, RZ_REG_TYPE_ANY);
		if (item->size == 1) {
			bool b = ri ? rz_reg_get_value(reg, ri) != 0 : false;
			rz_il_vm_set_global_var(vm, var->name, rz_il_value_new_bool(rz_il_bool_new(b)));
		} else {
			RzBitVector *bv = ri ? rz_reg_get_bv(reg, ri) : rz_bv_new_zero(item->size);
			if (!bv) {
				continue;
			}
			RzBitVector *dupped = NULL;
			if (rz_bv_len(bv) != item->size) {
				RzBitVector *nbv = rz_bv_new_zero(item->size);
				if (!nbv) {
					rz_bv_free(bv);
					break;
				}
				rz_bv_copy_nbits(bv, 0, nbv, 0, RZ_MIN(rz_bv_len(bv), item->size));
				dupped = bv;
				bv = nbv;
			}
			rz_il_vm_set_global_var(vm, var->name, rz_il_value_new_bitv(bv));
			rz_bv_free(dupped);
		}
	}
}
