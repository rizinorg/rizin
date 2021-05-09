// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_diff.h>
#include <rz_util.h>
/**/
#include <ht_pp.h>
#include <ht_uu.h>

#define NUM2PTR(x) ((void *)(intptr_t)(x))
#define PTR2NUM(x) ((intptr_t)(void *)(x))

RZ_LIB_VERSION(rz_diff);

typedef struct block_t {
	ut32 a_low;
	ut32 a_hi;
	ut32 b_low;
	ut32 b_hi;
} Block;

typedef void (*RzDiffMethodFree)(const void *array);

typedef struct methods_internal_t {
	RzDiffMethodElemAt elem_at;
	RzDiffMethodElemHash elem_hash;
	RzDiffMethodCompare compare;
	RzDiffMethodIgnore ignore;
	RzDiffMethodStringify stringify;
	RzDiffMethodFree free;
} MethodsInternal;

struct rz_diff_t {
	const void *a;
	const void *b;
	ut32 a_size;
	ut32 b_size;
	HtPP *b_hits;
	MethodsInternal methods;
};

RZ_API ut32 rz_diff_hash_data(const ut8 *buffer, ut32 size) {
	ut32 h = 5381;
	if (!buffer || !size) {
		return h;
	}
	for (ut32 i = 0; i < size; ++i) {
		h = (h + (h << 5)) ^ buffer[i];
	}
	return h;
}

static ut32 default_ksize(const void *a) {
	return sizeof(ut32);
}

static bool fake_ignore(const void *value) {
	return false;
}

#include "bytes_diff.c"
#include "lines_diff.c"
#include "unified_diff.c"

static bool set_a(RzDiff2 *diff, const void *a, ut32 a_size) {
	rz_return_val_if_fail(a, false);

	diff->a = a;
	diff->a_size = a_size;
	return true;
}

static void free_hits(HtPPKv *kv) {
	rz_list_free(kv->value);
}

static bool set_b(RzDiff2 *diff, const void *b, ut32 b_size) {
	rz_return_val_if_fail(b && diff->methods.elem_at && diff->methods.elem_hash && diff->methods.compare && diff->methods.ignore, false);

	diff->b = b;
	diff->b_size = b_size;

	RzList *list = NULL;
	RzDiffMethodElemAt elem_at = diff->methods.elem_at;
	RzDiffMethodIgnore ignore = diff->methods.ignore;

	/* we need to generate the hits list for B */
	ht_pp_free(diff->b_hits);
	diff->b_hits = ht_pp_new(NULL, free_hits, NULL);
	diff->b_hits->opt.cmp /*      */ = diff->methods.compare;
	diff->b_hits->opt.calcsizeK /**/ = default_ksize;
	diff->b_hits->opt.dupkey /*   */ = NULL; // avoid to duplicate key
	diff->b_hits->opt.hashfn /*   */ = diff->methods.elem_hash;

	for (ut64 i = 0; i < diff->b_size; ++i) {
		const void *elem = elem_at(diff->b, i);
		if (ignore && ignore(elem)) {
			continue;
		}

		list = ht_pp_find(diff->b_hits, elem, NULL);
		if (!list) {
			list = rz_list_newf(NULL);
			if (!list) {
				RZ_LOG_ERROR("rz_diff_set_b: cannot allocate list\n");
				return false;
			}
			ht_pp_insert(diff->b_hits, elem, list);
		}

		if (!rz_list_append(list, NUM2PTR(i))) {
			RZ_LOG_ERROR("rz_diff_set_b: cannot append index to list\n");
			return false;
		}
	}

	return true;
}

RZ_API RZ_OWN RzDiff2 *rz_diff_bytes_new(const ut8 *a, ut32 a_size, const ut8 *b, ut32 b_size, RzDiffIgnoreByte ignore) {
	rz_return_val_if_fail(a && b, NULL);

	RzDiff2 *diff = RZ_NEW0(RzDiff2);
	if (!diff) {
		return NULL;
	}

	diff->methods = methods_bytes;
	if (ignore) {
		diff->methods.ignore = (RzDiffMethodIgnore)ignore;
	}

	if (!set_a(diff, a, a_size)) {
		rz_diff_free2(diff);
		return NULL;
	}
	if (!set_b(diff, b, b_size)) {
		rz_diff_free2(diff);
		return NULL;
	}
	return diff;
}

RZ_API RZ_OWN RzDiff2 *rz_diff_lines_new(const char *a, const char *b, RzDiffIgnoreLine ignore) {
	rz_return_val_if_fail(a && b, NULL);

	RzDiff2 *diff = RZ_NEW0(RzDiff2);
	if (!diff) {
		return NULL;
	}

	RzList *a_lines = tokenize_lines(a);
	RzList *b_lines = tokenize_lines(b);
	if (!a_lines || !b_lines) {
		rz_list_free(a_lines);
		rz_list_free(b_lines);
		free(diff);
		return NULL;
	}

	diff->methods = methods_lines;

	if (ignore) {
		diff->methods.ignore = (RzDiffMethodIgnore)ignore;
	}

	if (!set_a(diff, a_lines, rz_list_length(a_lines))) {
		rz_diff_free2(diff);
		return NULL;
	}
	if (!set_b(diff, b_lines, rz_list_length(b_lines))) {
		rz_diff_free2(diff);
		return NULL;
	}
	return diff;
}

RZ_API RZ_OWN RzDiff2 *rz_diff_generic_new(const void *a, ut32 a_size, const void *b, ut32 b_size, RzDiffMethods *methods) {
	rz_return_val_if_fail(a && b && methods && methods->elem_at && methods->elem_hash && methods->compare && methods->stringify, NULL);

	RzDiff2 *diff = RZ_NEW0(RzDiff2);
	if (!diff) {
		return NULL;
	}

	diff->methods.free = NULL;
	diff->methods.elem_at = methods->elem_at;
	diff->methods.elem_hash = methods->elem_hash;
	diff->methods.compare = methods->compare;
	diff->methods.stringify = methods->stringify;

	if (methods->ignore) {
		diff->methods.ignore = methods->ignore;
	} else {
		diff->methods.ignore = fake_ignore;
	}

	if (!set_a(diff, a, a_size)) {
		rz_diff_free2(diff);
		return NULL;
	}
	if (!set_b(diff, b, b_size)) {
		rz_diff_free2(diff);
		return NULL;
	}
	return diff;
}

RZ_API void rz_diff_free2(RzDiff2 *diff) {
	if (!diff) {
		return;
	}
	if (diff->methods.free) {
		diff->methods.free(diff->a);
		diff->methods.free(diff->b);
	}
	ht_pp_free(diff->b_hits);
	free(diff);
}

RZ_API const void *rz_diff_get_a(RzDiff2 *diff) {
	rz_return_val_if_fail(diff, NULL);
	return diff->a;
}

RZ_API const void *rz_diff_get_b(RzDiff2 *diff) {
	rz_return_val_if_fail(diff, NULL);
	return diff->b;
}

static inline bool stack_append_block(RzList *stack, ut32 a_low, ut32 a_hi, ut32 b_low, ut32 b_hi) {
	Block *block = RZ_NEW0(Block);
	if (!block) {
		return false;
	}

	block->a_low = a_low;
	block->a_hi = a_hi;
	block->b_low = b_low;
	block->b_hi = b_hi;
	if (!rz_list_append(stack, block)) {
		free(block);
		return false;
	}
	return true;
}

static RzDiffMatch *match_new(ut32 a, ut32 b, ut32 size) {
	RzDiffMatch *match = RZ_NEW0(RzDiffMatch);
	if (!match) {
		return NULL;
	}

	match->a = a;
	match->b = b;
	match->size = size;
	return match;
}

static RzDiffMatch *find_longest_match(RzDiff2 *diff, Block *block) {
	rz_return_val_if_fail(diff && diff->methods.elem_at && diff->methods.compare && diff->methods.ignore, false);
	RzList *list = NULL;
	RzListIter *it = NULL;
	RzDiffMatch *match = NULL;
	HtUU *tmp = NULL;
	HtUU *len_map = NULL;
	void *pnum = NULL;
	const ut8 *a = diff->a;
	const ut8 *b = diff->b;
	const void *elem_a = NULL;
	const void *elem_b = NULL;
	RzDiffMethodIgnore ignore = diff->methods.ignore;
	RzDiffMethodElemAt elem_at = diff->methods.elem_at;
	RzDiffMethodCompare compare = diff->methods.compare;

	ut32 a_low = block->a_low;
	ut32 a_hi = block->a_hi;
	ut32 b_low = block->b_low;
	ut32 b_hi = block->b_hi;

	ut32 hit_a = a_low;
	ut32 hit_b = b_low;
	ut32 hit_size = 0;

	len_map = ht_uu_new0();
	if (!len_map) {
		RZ_LOG_ERROR("find_longest_match: cannot allocate len_map\n");
		goto find_longest_match_fail;
	}

	for (ut32 a_pos = a_low; a_pos < a_hi; ++a_pos) {
		elem_a = elem_at(a, a_pos);
		tmp = ht_uu_new0();
		if (!tmp) {
			RZ_LOG_ERROR("find_longest_match: cannot allocate tmp\n");
			goto find_longest_match_fail;
		}

		list = ht_pp_find(diff->b_hits, elem_a, NULL);
		rz_list_foreach (list, it, pnum) {
			ut64 b_pos = PTR2NUM(pnum);
			if (b_pos < b_low) {
				continue;
			} else if (b_pos >= b_hi) {
				break;
			}
			ut32 len = ht_uu_find(len_map, b_pos - 1, NULL) + 1;
			ht_uu_insert(tmp, b_pos, len);
			if (len > hit_size) {
				hit_a = a_pos - len + 1;
				hit_b = b_pos - len + 1;
				hit_size = len;
			}
		}

		ht_uu_free(len_map);
		len_map = tmp;
		tmp = NULL;
	}

	// Now let's handle the without the ignored chars.
	while (hit_a > a_low && hit_b > b_low) {
		elem_a = elem_at(a, hit_a - 1);
		elem_b = elem_at(b, hit_b - 1);
		if (ignore(elem_b) || compare(elem_a, elem_b)) {
			break;
		}
		hit_a--;
		hit_b--;
		hit_size++;
	}

	while (hit_a + hit_size < a_hi && hit_b + hit_size < b_hi) {
		elem_a = elem_at(a, hit_a + hit_size);
		elem_b = elem_at(b, hit_b + hit_size);
		if (ignore(elem_b) || compare(elem_a, elem_b)) {
			break;
		}
		hit_size++;
	}

	// Now let's handle the ignored chars.
	while (hit_a > a_low && hit_b > b_low) {
		elem_a = elem_at(a, hit_a - 1);
		elem_b = elem_at(b, hit_b - 1);
		if (!ignore(elem_b) || compare(elem_a, elem_b)) {
			break;
		}
		hit_a--;
		hit_b--;
		hit_size++;
	}

	while (hit_a + hit_size < a_hi && hit_b + hit_size < b_hi) {
		elem_a = elem_at(a, hit_a + hit_size);
		elem_b = elem_at(b, hit_b + hit_size);
		if (!ignore(elem_b) || compare(elem_a, elem_b)) {
			break;
		}
		hit_size++;
	}

	match = match_new(hit_a, hit_b, hit_size);
	if (!match) {
		RZ_LOG_ERROR("find_longest_match: cannot allocate RzDiffMatch\n");
		goto find_longest_match_fail;
	}

	ht_uu_free(len_map);
	return match;

find_longest_match_fail:
	ht_uu_free(tmp);
	ht_uu_free(len_map);
	return NULL;
}

static int cmp_matches(RzDiffMatch *m0, RzDiffMatch *m1) {
	if (m0->a > m1->a) {
		return 1;
	} else if (m0->a < m1->a) {
		return -1;
	} else if (m0->b > m1->b) {
		return 1;
	} else if (m0->b < m1->b) {
		return -1;
	} else if (m0->size > m1->size) {
		return 1;
	} else if (m0->size < m1->size) {
		return -1;
	}
	return 0;
}

/**
 * \brief generates a list of matching blocks
 *
 * Generates a list of matching blocks that are found in both inputs.
 * If non are found it returns a match result with size of 0
 * */
RZ_API RzList *rz_diff_matches_new(RzDiff2 *diff) {
	rz_return_val_if_fail(diff, NULL);
	RzList *stack = NULL;
	RzList *matches = NULL;
	RzList *non_adjacent = NULL;
	RzListIter *it = NULL;
	Block *block = NULL;
	RzDiffMatch *match = NULL;
	ut32 adj_a = 0, adj_b = 0, adj_size = 0;

	matches = rz_list_newf((RzListFree)free);
	if (!matches) {
		RZ_LOG_ERROR("rz_diff_matches_new: cannot allocate matches\n");
		goto rz_diff_matches_new_fail;
	}
	non_adjacent = rz_list_newf((RzListFree)free);
	if (!matches) {
		RZ_LOG_ERROR("rz_diff_matches_new: cannot allocate non_adjacent\n");
		goto rz_diff_matches_new_fail;
	}

	stack = rz_list_newf((RzListFree)free);
	if (!stack) {
		RZ_LOG_ERROR("rz_diff_matches_new: cannot allocate stack\n");
		goto rz_diff_matches_new_fail;
	}

	if (!stack_append_block(stack, 0, diff->a_size, 0, diff->b_size)) {
		RZ_LOG_ERROR("rz_diff_matches_new: cannot append initial block "
			     "into stack\n");
		goto rz_diff_matches_new_fail;
	}

	while (rz_list_length(stack) > 0) {
		block = (Block *)rz_list_pop(stack);
		match = find_longest_match(diff, block);
		if (!match) {
			continue;
		}

		if (match->size > 0) {
			if (!rz_list_append(matches, match)) {
				RZ_LOG_ERROR("rz_diff_matches_new: cannot append match into matches\n");
				free(match);
				goto rz_diff_matches_new_fail;
			}
			if (block->a_low < match->a && block->b_low < match->b) {
				if (!stack_append_block(stack, block->a_low, match->a, block->b_low, match->b)) {
					RZ_LOG_ERROR("rz_diff_matches_new: cannot append low block into stack\n");
					goto rz_diff_matches_new_fail;
				}
			}
			if (match->a + match->size < block->a_hi && match->b + match->size < block->b_hi) {
				if (!stack_append_block(stack, match->a + match->size, block->a_hi, match->b + match->size, block->b_hi)) {
					RZ_LOG_ERROR("rz_diff_matches_new: cannot append high block into stack\n");
					goto rz_diff_matches_new_fail;
				}
			}
		} else {
			free(match);
		}
		free(block);
	}
	rz_list_sort(matches, (RzListComparator)cmp_matches);

	adj_a = 0;
	adj_b = 0;
	adj_size = 0;
	rz_list_foreach (matches, it, match) {
		if ((adj_a + adj_size) == match->a && (adj_b + adj_size) == match->b) {
			adj_size += match->size;
		} else {
			RzDiffMatch *m = adj_size ? match_new(adj_a, adj_b, adj_size) : NULL;
			if (adj_size && (!m || !rz_list_append(non_adjacent, m))) {
				RZ_LOG_ERROR("rz_diff_matches_new: cannot append match into non_adjacent\n");
				free(m);
				goto rz_diff_matches_new_fail;
			}
			adj_a = match->a;
			adj_b = match->b;
			adj_size = match->size;
		}
	}
	match = adj_size ? match_new(adj_a, adj_b, adj_size) : NULL;
	if (adj_size && (!match || !rz_list_append(non_adjacent, match))) {
		RZ_LOG_ERROR("rz_diff_matches_new: cannot append match into non_adjacent\n");
		free(match);
		goto rz_diff_matches_new_fail;
	}

	match = match_new(diff->a_size, diff->b_size, 0);
	if (!match || !rz_list_append(non_adjacent, match)) {
		RZ_LOG_ERROR("rz_diff_matches_new: cannot append match into non_adjacent\n");
		free(match);
		goto rz_diff_matches_new_fail;
	}

	rz_list_free(matches);
	rz_list_free(stack);
	return non_adjacent;

rz_diff_matches_new_fail:
	rz_list_free(non_adjacent);
	rz_list_free(matches);
	rz_list_free(stack);
	return NULL;
}

static RzDiffOp *opcode_new(RzDiffOpType type, st32 a_beg, st32 a_end, st32 b_beg, st32 b_end) {
	RzDiffOp *op = RZ_NEW0(RzDiffOp);
	if (!op) {
		return NULL;
	}
	op->type = type;
	op->a_beg = a_beg;
	op->a_end = a_end;
	op->b_beg = b_beg;
	op->b_end = b_end;
	return op;
}

static void opcode_set(RzDiffOp *op, RzDiffOpType type, st32 a_beg, st32 a_end, st32 b_beg, st32 b_end) {
	op->type = type;
	op->a_beg = a_beg;
	op->a_end = a_end;
	op->b_beg = b_beg;
	op->b_end = b_end;
}

/**
 * \brief Generates a list of steps needed to go from A to B
 *
 * Generates a list of opcodes that are needed to convert A to B.
 * */
RZ_API RzList *rz_diff_opcodes_new(RzDiff2 *diff) {
	rz_return_val_if_fail(diff, NULL);
	ut32 a = 0, b = 0;
	RzDiffOpType type = RZ_DIFF_OP_INVALID;
	RzDiffOp *op = NULL;
	RzDiffMatch *match = NULL;
	RzListIter *it = NULL;
	RzList *matches = NULL;
	RzList *opcodes = NULL;

	matches = rz_diff_matches_new(diff);
	if (!matches) {
		goto rz_diff_opcodes_new_fail;
	}

	opcodes = rz_list_newf((RzListFree)free);
	if (!opcodes) {
		RZ_LOG_ERROR("rz_diff_opcodes_new: cannot allocate opcodes\n");
		goto rz_diff_opcodes_new_fail;
	}

	a = 0;
	b = 0;
	rz_list_foreach (matches, it, match) {
		type = RZ_DIFF_OP_INVALID;

		if (a < match->a && b < match->b) {
			type = RZ_DIFF_OP_REPLACE;
		} else if (a < match->a) {
			type = RZ_DIFF_OP_DELETE;
		} else if (b < match->b) {
			type = RZ_DIFF_OP_INSERT;
		}

		if (type != RZ_DIFF_OP_INVALID) {
			op = opcode_new(type, a, match->a, b, match->b);
			if (!op) {
				RZ_LOG_ERROR("rz_diff_opcodes_new: cannot allocate op\n");
				goto rz_diff_opcodes_new_fail;
			} else if (!rz_list_append(opcodes, op)) {
				RZ_LOG_ERROR("rz_diff_opcodes_new: cannot append op into opcodes\n");
				free(op);
				goto rz_diff_opcodes_new_fail;
			}
		}
		a = match->a + match->size;
		b = match->b + match->size;

		if (match->size > 0) {
			op = opcode_new(RZ_DIFF_OP_EQUAL, match->a, a, match->b, b);
			if (!op) {
				RZ_LOG_ERROR("rz_diff_opcodes_new: cannot allocate op\n");
				goto rz_diff_opcodes_new_fail;
			} else if (!rz_list_append(opcodes, op)) {
				RZ_LOG_ERROR("rz_diff_opcodes_new: cannot append op into opcodes\n");
				free(op);
				goto rz_diff_opcodes_new_fail;
			}
		}
	}

	rz_list_free(matches);
	return opcodes;

rz_diff_opcodes_new_fail:
	rz_list_free(matches);
	rz_list_free(opcodes);
	return NULL;
}

static void group_op_free(RzList *ops) {
	rz_list_free(ops);
}

RZ_API RzList /*<RzList<RzDiffOp>>*/ *rz_diff_opcodes_grouped_new(RzDiff2 *diff, ut32 n_groups) {
	rz_return_val_if_fail(diff && n_groups > 1, NULL);
	RzDiffOp *op = NULL;
	RzListIter *it = NULL;
	RzList *group = NULL;
	RzList *groups = NULL;
	RzList *opcodes = NULL;
	st32 a_beg = 0, b_beg = 0, max_groups = 0;

	max_groups = n_groups << 1;

	groups = rz_list_newf((RzListFree)group_op_free);
	if (!groups) {
		RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot allocate groups\n");
		goto rz_diff_opcodes_grouped_new_fail;
	}

	opcodes = rz_diff_opcodes_new(diff);
	if (!opcodes) {
		goto rz_diff_opcodes_grouped_new_fail;
	}

	if (rz_list_length(opcodes) < 1) {
		op = opcode_new(RZ_DIFF_OP_EQUAL, 0, 1, 0, 1);
		if (!op) {
			RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot allocate op for opcodes\n");
			goto rz_diff_opcodes_grouped_new_fail;
		} else if (!rz_list_append(opcodes, op)) {
			RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot append op into opcodes\n");
			free(op);
			goto rz_diff_opcodes_grouped_new_fail;
		}
	}

	op = rz_list_first(opcodes);
	if (op->type == RZ_DIFF_OP_EQUAL) {
		opcode_set(op, op->type, RZ_MAX(op->a_beg, op->a_end - n_groups), op->a_end, RZ_MAX(op->b_beg, op->b_end - n_groups), op->b_end);
	}

	op = rz_list_last(opcodes);
	if (op->type == RZ_DIFF_OP_EQUAL) {
		opcode_set(op, op->type, op->a_beg, RZ_MIN(op->a_end, op->a_beg + n_groups), op->b_beg, RZ_MIN(op->b_end, op->b_beg + n_groups));
	}

	group = rz_list_newf((RzListFree)free);
	if (!group) {
		RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot allocate group\n");
		goto rz_diff_opcodes_grouped_new_fail;
	}

	rz_list_foreach (opcodes, it, op) {
		a_beg = op->a_beg;
		b_beg = op->b_beg;

		if (op->type == RZ_DIFF_OP_EQUAL && (op->a_end - a_beg) > max_groups) {
			// append the last op of the group, append group to groups and create a new group.
			RzDiffOp *op2 = opcode_new(RZ_DIFF_OP_EQUAL, a_beg, RZ_MIN(op->a_end, a_beg + n_groups), b_beg, RZ_MIN(op->b_end, b_beg + n_groups));
			if (!op2) {
				RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot allocate op for group\n");
				goto rz_diff_opcodes_grouped_new_fail;
			} else if (!rz_list_append(group, op2)) {
				RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot append op into group\n");
				free(op2);
				goto rz_diff_opcodes_grouped_new_fail;
			} else if (!rz_list_append(groups, group)) {
				RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot append group into groups\n");
				rz_list_free(group);
				goto rz_diff_opcodes_grouped_new_fail;
			}

			group = rz_list_newf((RzListFree)free);
			if (!group) {
				RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot allocate new group\n");
				goto rz_diff_opcodes_grouped_new_fail;
			}
			a_beg = RZ_MAX(a_beg, op->a_end - n_groups);
			b_beg = RZ_MAX(b_beg, op->b_end - n_groups);
		}

		op = opcode_new(op->type, a_beg, op->a_end, b_beg, op->b_end);
		if (!op) {
			RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot allocate op for group\n");
			goto rz_diff_opcodes_grouped_new_fail;
		} else if (!rz_list_append(group, op)) {
			RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot append op into group\n");
			free(op);
			goto rz_diff_opcodes_grouped_new_fail;
		}
	}

	op = rz_list_first(opcodes);
	if (!(rz_list_length(opcodes) == 1 && op->type == RZ_DIFF_OP_EQUAL)) {
		if (!rz_list_append(groups, group)) {
			RZ_LOG_ERROR("rz_diff_opcodes_grouped_new: cannot append group into groups\n");
			rz_list_free(group);
			goto rz_diff_opcodes_grouped_new_fail;
		}
	} else {
		rz_list_free(group);
	}

	rz_list_free(opcodes);
	return groups;

rz_diff_opcodes_grouped_new_fail:
	rz_list_free(groups);
	rz_list_free(opcodes);
	return NULL;
}

/**
 * \brief Calculates the difference ratio between A and B.
 *
 * Calculates the difference ratio between A and B.
 * */
RZ_API bool rz_diff_ratio(RzDiff2 *diff, double *result) {
	rz_return_val_if_fail(diff && result, false);
	RzList *matches = NULL;
	RzDiffMatch *match = NULL;
	RzListIter *it = NULL;
	ut32 hits = 0;

	matches = rz_diff_matches_new(diff);
	if (!matches) {
		return false;
	}
	rz_list_foreach (matches, it, match) {
		hits += match->size;
	}
	rz_list_free(matches);

	/* simple cast to avoid math issues */
	double d_hits = hits;
	double d_size = diff->a_size + diff->b_size;
	if (d_size > 0.0) {
		*result = (2.0 * d_hits) / d_size;
	} else {
		*result = 1.0;
	}
	return true;
}

/**
 * \brief Calculates the size ratio between A and B.
 *
 * Calculates the size ratio between A and B.
 * */
RZ_API bool rz_diff_sizes_ratio(RzDiff2 *diff, double *result) {
	rz_return_val_if_fail(diff && result, false);

	/* simple cast to avoid math issues */
	double d_hits = RZ_MIN(diff->a_size, diff->b_size);
	double d_size = diff->a_size + diff->b_size;
	if (d_size > 0.0) {
		*result = (2.0 * d_hits) / d_size;
	} else {
		*result = 1.0;
	}
	return true;
}
