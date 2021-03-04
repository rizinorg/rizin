// SPDX-FileCopyrightText: 2020 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_skyline.h>

#define CMP_BEGIN_GTE_PART(addr, part) \
	(((addr) > (rz_itv_begin(((RzSkylineItem *)(part))->itv))) - ((addr) < (rz_itv_begin(((RzSkylineItem *)(part))->itv))))

#define CMP_END_GTE_PART(addr, part) \
	(((addr) < (rz_itv_end(((RzSkylineItem *)(part))->itv)) || !rz_itv_end(((RzSkylineItem *)(part))->itv)) ? -1 : 1)

RZ_API bool rz_skyline_add(RzSkyline *skyline, RzInterval itv, void *user) {
	rz_return_val_if_fail(skyline, false);
	RzVector *skyline_vec = &skyline->v;
	RzSkylineItem new_part = { itv, user };
	const ut64 new_part_end = rz_itv_end(new_part.itv);

	// `slot` is the index of the first RzSkylineItem with part->itv.addr >= new_part.itv.addr
	size_t slot;
	rz_vector_lower_bound(skyline_vec, new_part.itv.addr, slot, CMP_BEGIN_GTE_PART);
	const bool is_last = slot == rz_vector_len(skyline_vec);
	bool is_inside_prev_part = false;
	if (slot) {
		RzSkylineItem *prev_part = rz_vector_index_ptr(skyline_vec, slot - 1);
		const ut64 prev_part_end = rz_itv_end(prev_part->itv);
		if (prev_part_end > rz_itv_begin(new_part.itv)) {
			prev_part->itv.size = rz_itv_begin(new_part.itv) - rz_itv_begin(prev_part->itv);
			if (prev_part_end > new_part_end) {
				RzSkylineItem tail;
				tail.user = prev_part->user;
				tail.itv.addr = new_part_end;
				tail.itv.size = prev_part_end - rz_itv_begin(tail.itv);
				rz_vector_insert(skyline_vec, slot, &tail);
				is_inside_prev_part = true;
			}
		}
	}
	if (!is_last && !is_inside_prev_part) {
		RzSkylineItem *part = rz_vector_index_ptr(skyline_vec, slot);
		while (part && rz_itv_include(new_part.itv, part->itv)) {
			// Remove `part` that fits in `new_part`
			rz_vector_remove_at(skyline_vec, slot, NULL);
			part = slot < rz_vector_len(skyline_vec) ? rz_vector_index_ptr(skyline_vec, slot) : NULL;
		}
		if (part && rz_itv_overlap(new_part.itv, part->itv)) {
			// Chop start of last `part` that intersects `new_part`
			const ut64 oaddr = rz_itv_begin(part->itv);
			part->itv.addr = new_part_end;
			part->itv.size -= rz_itv_begin(part->itv) - oaddr;
		}
	}
	rz_vector_insert(skyline_vec, slot, &new_part);
	return true;
}

RZ_API const RzSkylineItem *rz_skyline_get_item_intersect(RzSkyline *skyline, ut64 addr, ut64 len) {
	rz_return_val_if_fail(skyline, NULL);
	RzVector *skyline_vec = &skyline->v;
	size_t i, l = rz_vector_len(skyline_vec);
	rz_vector_lower_bound(skyline_vec, addr, i, CMP_END_GTE_PART);
	if (i == l) {
		return false;
	}
	const RzSkylineItem *item = rz_vector_index_ptr(skyline_vec, i);
	return item->itv.addr <= addr + len ? item : NULL;
}
