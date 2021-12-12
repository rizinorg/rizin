// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h> // just to get the RzPrint instance
#include <rz_debug.h>
#include <rz_cons.h>
#include <rz_reg.h>

RZ_API int rz_debug_reg_sync(RzDebug *dbg, int type, int write) {
	int i, n, size;
	if (!dbg || !dbg->reg || !dbg->cur) {
		return false;
	}
	// There's no point in syncing a dead target
	if (rz_debug_is_dead(dbg)) {
		return false;
	}
	// Check if the functions needed are available
	if (write && !dbg->cur->reg_write) {
		return false;
	}
	if (!write && !dbg->cur->reg_read) {
		return false;
	}
	// Sync all the types sequentially if asked
	i = (type == RZ_REG_TYPE_ANY) ? RZ_REG_TYPE_GPR : type;
	// Check to get the correct arena when using @ into reg profile (arena!=type)
	// if request type is positive and the request regset don't have regs
	if (i >= RZ_REG_TYPE_GPR && dbg->reg->regset[i].regs && !dbg->reg->regset[i].regs->length) {
		// seek into the other arena for redirections.
		for (n = RZ_REG_TYPE_GPR; n < RZ_REG_TYPE_LAST; n++) {
			// get regset mask
			int mask = dbg->reg->regset[n].maskregstype;
			// convert request arena to mask value
			int v = ((int)1 << i);
			// skip checks on same request arena and check if this arena have inside the request arena type
			if (n != i && (mask & v)) {
				// eprintf(" req = %i arena = %i mask = %x search = %x \n", i, n, mask, v);
				// eprintf(" request arena %i found at arena %i\n", i, n );
				//  if this arena have the request arena type, force to use this arena.
				i = n;
				break;
			}
		}
	}
	do {
		if (write) {
			ut8 *buf = rz_reg_get_bytes(dbg->reg, i, &size);
			if (!buf || !dbg->cur->reg_write(dbg, i, buf, size)) {
				if (i == RZ_REG_TYPE_GPR) {
					eprintf("rz_debug_reg: error writing "
						"registers %d to %d\n",
						i, dbg->tid);
				}
				if (type != RZ_REG_TYPE_ANY || i == RZ_REG_TYPE_GPR) {
					free(buf);
					return false;
				}
			}
			free(buf);
		} else {
			// int bufsize = RZ_MAX (1024, dbg->reg->size*2); // i know. its hacky
			int bufsize = dbg->reg->size;
			// int bufsize = dbg->reg->regset[i].arena->size;
			if (bufsize > 0) {
				ut8 *buf = calloc(1 + 1, bufsize);
				if (!buf) {
					return false;
				}
				// we have already checked dbg->h and dbg->h->reg_read above
				size = dbg->cur->reg_read(dbg, i, buf, bufsize);
				// we need to check against zero because reg_read can return false
				if (size > 0) {
					rz_reg_set_bytes(dbg->reg, i, buf, size); // RZ_MIN (size, bufsize));
					//		free (buf);
					//		return true;
				}
				free(buf);
			}
		}
		// DO NOT BREAK RZ_REG_TYPE_ANY PLEASE
		//   break;
		// Continue the synchronization or just stop if it was asked only for a single type of regs
		i++;
	} while ((type == RZ_REG_TYPE_ANY) && (i < RZ_REG_TYPE_LAST));
	return true;
}

RZ_API int rz_debug_reg_set(struct rz_debug_t *dbg, const char *name, ut64 num) {
	RzRegItem *ri = rz_reg_get_by_role_or_name(dbg->reg, name);
	if (!ri) {
		return false;
	}
	rz_reg_set_value(dbg->reg, ri, num);
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, true);
	return true;
}

RZ_API ut64 rz_debug_reg_get(RzDebug *dbg, const char *name) {
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	return rz_reg_getv_by_role_or_name(dbg->reg, name);
}

RZ_API ut64 rz_debug_num_callback(RzNum *userptr, const char *str, int *ok) {
	RzDebug *dbg = (RzDebug *)userptr;
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	RzRegItem *ri = rz_reg_get_by_role_or_name(dbg->reg, str);
	if (!ri) {
		*ok = 0;
		return UT64_MAX;
	}
	*ok = 1;
	return rz_reg_get_value(dbg->reg, ri);
}

RZ_API bool rz_debug_reg_profile_sync(RzDebug *dbg) {
	if (dbg->cur->reg_profile) {
		char *p = dbg->cur->reg_profile(dbg);
		if (p) {
			rz_reg_set_profile_string(dbg->reg, p);
			rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
			if (dbg->analysis && dbg->reg != dbg->analysis->reg) {
				rz_reg_free(dbg->analysis->reg);
				dbg->analysis->reg = dbg->reg;
			}
			free(p);
		} else {
			RZ_LOG_WARN("Cannot retrieve reg profile from debug plugin (%s)\n", dbg->cur->name);
			return false;
		}
	}
	return true;
}
