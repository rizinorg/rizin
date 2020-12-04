// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_list.h>
#include <limits.h>

typedef struct {
	ut64 addr;
	RzAnalysisBlock *ret;
} BBFromOffsetJmpmidCtx;

static bool bb_from_offset_jmpmid_cb(RzAnalysisBlock *block, void *user) {
	BBFromOffsetJmpmidCtx *ctx = user;
	// If an instruction starts exactly at the search addr, return that block immediately
	if (rz_analysis_block_op_starts_at (block, ctx->addr)) {
		ctx->ret = block;
		return false;
	}
	// else search the closest one
	if (!ctx->ret || ctx->ret->addr < block->addr) {
		ctx->ret = block;
	}
	return true;
}

static bool bb_from_offset_first_cb(RzAnalysisBlock *block, void *user) {
	RzAnalysisBlock **ret = user;
	*ret = block;
	return false;
}

RZ_API RzAnalysisBlock *rz_analysis_bb_from_offset(RzAnalysis *anal, ut64 off) {
	const bool x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");
	if (anal->opt.jmpmid && x86) {
		BBFromOffsetJmpmidCtx ctx = { off, NULL };
		rz_analysis_blocks_foreach_in (anal, off, bb_from_offset_jmpmid_cb, &ctx);
		return ctx.ret;
	}

	RzAnalysisBlock *ret = NULL;
	rz_analysis_blocks_foreach_in (anal, off, bb_from_offset_first_cb, &ret);
	return ret;
}

/* return the offset of the i-th instruction in the basicblock bb.
 * If the index of the instruction is not valid, it returns UT16_MAX */
RZ_API ut16 rz_analysis_bb_offset_inst(RzAnalysisBlock *bb, int i) {
	if (i < 0 || i >= bb->ninstr) {
		return UT16_MAX;
	}
	return (i > 0 && (i - 1) < bb->op_pos_size)? bb->op_pos[i - 1]: 0;
}

/* return the address of the i-th instruction in the basicblock bb.
 * If the index of the instruction is not valid, it returns UT64_MAX */
RZ_API ut64 rz_analysis_bb_opaddr_i(RzAnalysisBlock *bb, int i) {
	ut16 offset = rz_analysis_bb_offset_inst (bb, i);
	if (offset == UT16_MAX) {
		return UT64_MAX;
	}
	return bb->addr + offset;
}

/* set the offset of the i-th instruction in the basicblock bb */
RZ_API bool rz_analysis_bb_set_offset(RzAnalysisBlock *bb, int i, ut16 v) {
	// the offset 0 of the instruction 0 is not stored because always 0
	if (i > 0 && v > 0) {
		if (i >= bb->op_pos_size) {
			int new_pos_size = i * 2;
			ut16 *tmp_op_pos = realloc (bb->op_pos, new_pos_size * sizeof (*bb->op_pos));
			if (!tmp_op_pos) {
				return false;
			}
			bb->op_pos_size = new_pos_size;
			bb->op_pos = tmp_op_pos;
		}
		bb->op_pos[i - 1] = v;
		return true;
	}
	return true;
}

/* return the address of the instruction that occupy a given offset.
 * If the offset is not part of the given basicblock, UT64_MAX is returned. */
RZ_API ut64 rz_analysis_bb_opaddr_at(RzAnalysisBlock *bb, ut64 off) {
	ut16 delta, delta_off, last_delta;
	int i;

	if (!rz_analysis_block_contains (bb, off)) {
		return UT64_MAX;
	}
	last_delta = 0;
	delta_off = off - bb->addr;
	for (i = 0; i < bb->ninstr; i++) {
		delta = rz_analysis_bb_offset_inst (bb, i);
		if (delta > delta_off) {
			return bb->addr + last_delta;
		}
		last_delta = delta;
	}
	return bb->addr + last_delta;
}

// returns the size of the i-th instruction in a basic block
RZ_API ut64 rz_analysis_bb_size_i(RzAnalysisBlock *bb, int i) {
	if (i < 0 || i >= bb->ninstr) {
		return UT64_MAX;
	}
	ut16 idx_cur = rz_analysis_bb_offset_inst (bb, i);
	ut16 idx_next = rz_analysis_bb_offset_inst (bb, i + 1);
	return idx_next != UT16_MAX? idx_next - idx_cur: bb->size - idx_cur;
}

/* returns the address of the basic block that contains addr or UT64_MAX if
 * there is no such basic block */
RZ_API ut64 rz_analysis_get_bbaddr(RzAnalysis *anal, ut64 addr) {
	RzAnalysisBlock *bb = rz_analysis_bb_from_offset (anal, addr);
	return bb? bb->addr: UT64_MAX;
}
