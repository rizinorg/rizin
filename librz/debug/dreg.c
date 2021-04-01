// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h> // just to get the RzPrint instance
#include <rz_debug.h>
#include <rz_cons.h>
#include <rz_reg.h>

RZ_API int rz_debug_reg_sync(RzDebug *dbg, int type, int write) {
	int i, n, size;
	if (!dbg || !dbg->reg || !dbg->h) {
		return false;
	}
	// There's no point in syncing a dead target
	if (rz_debug_is_dead(dbg)) {
		return false;
	}
	// Check if the functions needed are available
	if (write && !dbg->h->reg_write) {
		return false;
	}
	if (!write && !dbg->h->reg_read) {
		return false;
	}
	// Sync all the types sequentially if asked
	i = (type == RZ_REG_TYPE_ALL) ? RZ_REG_TYPE_GPR : type;
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
				//eprintf(" req = %i arena = %i mask = %x search = %x \n", i, n, mask, v);
				//eprintf(" request arena %i found at arena %i\n", i, n );
				// if this arena have the request arena type, force to use this arena.
				i = n;
				break;
			}
		}
	}
	do {
		if (write) {
			ut8 *buf = rz_reg_get_bytes(dbg->reg, i, &size);
			if (!buf || !dbg->h->reg_write(dbg, i, buf, size)) {
				if (i == RZ_REG_TYPE_GPR) {
					eprintf("rz_debug_reg: error writing "
						"registers %d to %d\n",
						i, dbg->tid);
				}
				if (type != RZ_REG_TYPE_ALL || i == RZ_REG_TYPE_GPR) {
					free(buf);
					return false;
				}
			}
			free(buf);
		} else {
			// int bufsize = RZ_MAX (1024, dbg->reg->size*2); // i know. its hacky
			int bufsize = dbg->reg->size;
			//int bufsize = dbg->reg->regset[i].arena->size;
			if (bufsize > 0) {
				ut8 *buf = calloc(1 + 1, bufsize);
				if (!buf) {
					return false;
				}
				//we have already checked dbg->h and dbg->h->reg_read above
				size = dbg->h->reg_read(dbg, i, buf, bufsize);
				// we need to check against zero because reg_read can return false
				if (size > 0) {
					rz_reg_set_bytes(dbg->reg, i, buf, size); //RZ_MIN (size, bufsize));
					//		free (buf);
					//		return true;
				}
				free(buf);
			}
		}
		// DO NOT BREAK RZ_REG_TYPE_ALL PLEASE
		//   break;
		// Continue the synchronization or just stop if it was asked only for a single type of regs
		i++;
	} while ((type == RZ_REG_TYPE_ALL) && (i < RZ_REG_TYPE_LAST));
	return true;
}

RZ_API int rz_debug_reg_set(struct rz_debug_t *dbg, const char *name, ut64 num) {
	RzRegItem *ri;
	int role = rz_reg_get_name_idx(name);
	if (!dbg || !dbg->reg) {
		return false;
	}
	if (role != -1) {
		name = rz_reg_get_name(dbg->reg, role);
	}
	ri = rz_reg_get(dbg->reg, name, RZ_REG_TYPE_ALL);
	if (ri) {
		rz_reg_set_value(dbg->reg, ri, num);
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_ALL, true);
	}
	return (ri != NULL);
}

RZ_API ut64 rz_debug_reg_get(RzDebug *dbg, const char *name) {
	// ignores errors
	return rz_debug_reg_get_err(dbg, name, NULL, NULL);
}

RZ_API ut64 rz_debug_reg_get_err(RzDebug *dbg, const char *name, int *err, utX *value) {
	RzRegItem *ri = NULL;
	ut64 ret = 0LL;
	int role = rz_reg_get_name_idx(name);
	const char *pname = name;
	if (err) {
		*err = 0;
	}
	if (!dbg || !dbg->reg) {
		if (err) {
			*err = 1;
		}
		return UT64_MAX;
	}
	if (role != -1) {
		name = rz_reg_get_name(dbg->reg, role);
		if (!name || *name == '\0') {
			eprintf("No debug register profile defined for '%s'.\n", pname);
			if (err) {
				*err = 1;
			}
			return UT64_MAX;
		}
	}
	ri = rz_reg_get(dbg->reg, name, RZ_REG_TYPE_ALL);
	if (ri) {
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_ALL, false);
		if (value && ri->size > 64) {
			if (err) {
				*err = ri->size;
			}
			ret = rz_reg_get_value_big(dbg->reg, ri, value);
		} else {
			ret = rz_reg_get_value(dbg->reg, ri);
		}
	} else {
		if (err) {
			*err = 1;
		}
	}
	return ret;
}

// XXX: dup for get_Err!
RZ_API ut64 rz_debug_num_callback(RNum *userptr, const char *str, int *ok) {
	RzDebug *dbg = (RzDebug *)userptr;
	// resolve using regnu
	return rz_debug_reg_get_err(dbg, str, ok, NULL);
}
