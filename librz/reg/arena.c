// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>
#include <rz_util/rz_str.h>

/* non-endian safe - used for raw mapping with system registers */
RZ_API ut8 *rz_reg_get_bytes(RzReg *reg, int type, int *size) {
	RzRegArena *arena;
	int i, sz, osize;
	ut8 *buf, *newbuf;
	if (size) {
		*size = 0;
	}
	if (type == -1) {
		/* serialize ALL register types in a single buffer */
		// owned buffer is returned
		osize = sz = 0;
		buf = malloc(8);
		if (!buf) {
			return NULL;
		}
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			arena = reg->regset[i].arena;
			sz += arena->size;
			newbuf = realloc(buf, sz);
			if (!newbuf) {
				break;
			}
			buf = newbuf;
			memcpy(buf + osize, arena->bytes, arena->size);
			osize = sz;
		}
		if (size) {
			*size = sz;
		}
		return buf;
	}
	if (type < 0 || type > (RZ_REG_TYPE_LAST - 1)) {
		return NULL;
	}
	sz = reg->regset[type].arena->size;
	if (size) {
		*size = sz;
	}
	if (!sz) {
		return NULL;
	}
	buf = malloc(sz);
	if (buf) {
		memcpy(buf, reg->regset[type].arena->bytes, sz);
	}
	return buf;
}

/* deserialize ALL register types into buffer */
/* XXX does the same as rz_reg_get_bytes? */
RZ_API bool rz_reg_read_regs(RzReg *reg, ut8 *buf, const int len) {
	int i, off = 0;
	RzRegArena *arena;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		if (reg->regset[i].arena) {
			arena = reg->regset[i].arena;
		} else {
			arena = reg->regset[i].arena = RZ_NEW0(RzRegArena);
			if (!arena) {
				return false;
			}
			arena->size = len;
			arena->bytes = calloc(1, len);
			if (!arena->bytes) {
				rz_reg_arena_free(arena);
				return false;
			}
		}
		if (!arena->bytes) {
			arena->size = 0;
			return false;
		}
		memset(arena->bytes, 0, arena->size);
		memcpy(arena->bytes, buf + off,
			RZ_MIN(len - off, arena->size));
		off += arena->size;
		if (off > len) {
			return false;
		}
	}
	return true;
}

/* TODO reduce number of return statements */
RZ_API bool rz_reg_set_bytes(RzReg *reg, int type, const ut8 *buf, const int len) {
	int maxsz, minsz;
	struct rz_reg_set_t *regset;
	RzRegArena *arena;
	if (len < 1 || !buf) {
		return false;
	}
	if (type < 0 || type >= RZ_REG_TYPE_LAST) {
		return false;
	}
	regset = &reg->regset[type];
	arena = regset->arena;
	if (!arena) {
		return false;
	}
	maxsz = RZ_MAX(arena->size, len);
	minsz = RZ_MIN(arena->size, len);
	if ((arena->size != len) || (!arena->bytes)) {
		free(arena->bytes);
		arena->bytes = calloc(1, maxsz);
		if (!arena->bytes) {
			arena->size = 0;
			return false;
		}
		arena->size = maxsz;
	}
	if (arena->size != maxsz) {
		ut8 *tmp = realloc(arena->bytes, maxsz);
		if (!tmp) {
			eprintf("Error resizing arena to %d\n", len);
			return false;
		}
		arena->size = maxsz;
		arena->bytes = tmp;
	}
	if (arena->bytes) {
		memset(arena->bytes, 0, arena->size);
		memcpy(arena->bytes, buf, minsz);
		return true;
	}
	return false;
}

RZ_API int rz_reg_fit_arena(RzReg *reg) {
	RzRegArena *arena;
	RzListIter *iter;
	RzRegItem *r;
	int size, i, newsize;

	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		arena = reg->regset[i].arena;
		if (!arena) {
			continue;
		}
		newsize = 0;
		rz_list_foreach (reg->regset[i].regs, iter, r) {
			// XXX: bits2bytes doesnt seems to work fine
			size = BITS2BYTES(r->offset + r->size);
			newsize = RZ_MAX(size, newsize);
		}
		if (newsize < 1) {
			RZ_FREE(arena->bytes);
			arena->size = 0;
		} else {
			ut8 *buf = realloc(arena->bytes, newsize);
			if (buf) {
				arena->size = newsize;
				arena->bytes = buf;
				memset(arena->bytes, 0, arena->size);
			} else {
				arena->bytes = NULL;
				arena->size = 0;
			}
		}
	}
	return true;
}

RZ_API RzRegArena *rz_reg_arena_new(size_t size) {
	RzRegArena *arena = RZ_NEW0(RzRegArena);
	if (!arena) {
		RZ_LOG_ERROR("Failed to allocate RzRegArena.\n");
		return NULL;
	}

	arena->size = size;
	if (size < 1) {
		return arena;
	}

	if (!(arena->bytes = calloc(1, size + 8))) {
		RZ_LOG_ERROR("Failed to allocate arena bytes.\n");
		RZ_FREE(arena);
	}
	return arena;
}

RZ_API void rz_reg_arena_free(RzRegArena *ra) {
	if (ra) {
		free(ra->bytes);
		free(ra);
	}
}

RZ_API void rz_reg_arena_swap(RzReg *reg, int copy) {
	/* XXX: swap current arena to head(previous arena) */
	int i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		if (!reg->regset[i].pool) {
			continue;
		}
		if (rz_list_length(reg->regset[i].pool) > 1) {
			RzListIter *ia = reg->regset[i].cur;
			RzListIter *ib = reg->regset[i].pool->head;
			void *tmp = ia->data;
			ia->data = ib->data;
			ib->data = tmp;
			reg->regset[i].arena = ia->data;
		} else {
			break;
		}
	}
}

RZ_API void rz_reg_arena_pop(RzReg *reg) {
	RzRegArena *a;
	int i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		if (!reg->regset[i].pool) {
			continue;
		}
		if (rz_list_length(reg->regset[i].pool) < 2) {
			continue;
		}
		a = rz_list_pop(reg->regset[i].pool);
		rz_reg_arena_free(a);
		a = reg->regset[i].pool->tail->data;
		if (a) {
			reg->regset[i].arena = a;
			reg->regset[i].cur = reg->regset[i].pool->tail;
		}
	}
}

RZ_API int rz_reg_arena_push(RzReg *reg) {
	int i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = reg->regset[i].arena; // current arena
		if (!a) {
			continue;
		}
		RzRegArena *b = rz_reg_arena_new(a->size); // new arena
		if (!b) {
			continue;
		}
		//b->size == a->size always because of how rz_reg_arena_new behave
		if (a->bytes) {
			memcpy(b->bytes, a->bytes, b->size);
		}
		rz_list_push(reg->regset[i].pool, b);
		reg->regset[i].arena = b;
		reg->regset[i].cur = reg->regset[i].pool->tail;
	}
	if (reg->regset[0].pool) {
		return rz_list_length(reg->regset[0].pool);
	}
	return 0;
}

RZ_API void rz_reg_arena_zero(RzReg *reg) {
	int i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegArena *a = reg->regset[i].arena;
		if (a->size > 0) {
			memset(reg->regset[i].arena->bytes, 0, a->size);
		}
	}
}

RZ_API ut8 *rz_reg_arena_peek(RzReg *reg) {
	RzRegSet *regset = rz_reg_regset_get(reg, RZ_REG_TYPE_GPR);
	if (!reg || !regset || !regset->arena || (regset->arena->size < 1)) {
		return NULL;
	}
	ut8 *ret = malloc(regset->arena->size);
	if (!ret) {
		return NULL;
	}
	memcpy(ret, regset->arena->bytes, regset->arena->size);
	return ret;
}

RZ_API void rz_reg_arena_poke(RzReg *reg, const ut8 *ret) {
	RzRegSet *regset = rz_reg_regset_get(reg, RZ_REG_TYPE_GPR);
	if (!ret || !regset || !regset->arena || !regset->arena->bytes) {
		return;
	}
	memcpy(regset->arena->bytes, ret, regset->arena->size);
}

RZ_API ut8 *rz_reg_arena_dup(RzReg *reg, const ut8 *source) {
	RzRegSet *regset = rz_reg_regset_get(reg, RZ_REG_TYPE_GPR);
	if (!reg || !regset || !regset->arena || (regset->arena->size < 1)) {
		return NULL;
	}
	ut8 *ret = malloc(regset->arena->size);
	if (!ret) {
		return NULL;
	}
	memcpy(ret, source, regset->arena->size);
	return ret;
}

RZ_API int rz_reg_arena_set_bytes(RzReg *reg, const char *str) {
	str = rz_str_trim_head_ro(str);
	int len = rz_hex_str_is_valid(str);
	if (len == -1) {
		eprintf("Invalid input\n");
		return -1;
	}
	int bin_str_len = (len + 1) / 2; //2 hex chrs for 1 byte
	ut8 *bin_str = malloc(bin_str_len);
	if (!bin_str) {
		eprintf("Failed to decode hex str.\n");
		return -1;
	}
	rz_hex_str2bin(str, bin_str);

	int i, n = 0; //n - cumulative sum of arena's sizes
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		int sz = reg->regset[i].arena->size;
		int bl = bin_str_len - n; //bytes left
		int bln = bl - n;
		if (bln > 0 && bln < sz) {
			rz_reg_set_bytes(reg, i, bin_str + n, bln);
			break;
		}
		rz_reg_set_bytes(reg, i, bin_str + n, bin_str_len - n);
		n += sz;
	}
	free(bin_str);
	return 0;
}

RZ_API void rz_reg_arena_shrink(RzReg *reg) {
	RzListIter *iter;
	RzRegArena *a;
	int i;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_list_foreach (reg->regset[i].pool, iter, a) {
			free(a->bytes);
			/* ha ha ha */
			a->bytes = calloc(1024, 1);
			a->size = 1024;
			/* looks like sizing down the arena breaks the regsync */
			/* and sizing it up fixes reallocation when fit() is called */
		}
	}
}
