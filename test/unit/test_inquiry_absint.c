// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../../librz/inquiry/absint/absint_priv.h"

#include "minunit.h"

typedef struct test_absint_t {
	RzAnalysis *analysis;
	RzIO *io;
	RzILCache *il_cache;
	RzAbsIntInstance *inst;
} TestInterp;

static RzAbsIntIOReadResult io_read(RzAbsIntIOReadRequest *req, void *user) {
	return RZ_ABSINT_IO_READ_RESULT_TOP; // Currently we do not care about contents, just make the interpreter continue
}

static RzAbsIntLiftBlockResult lift_block(ut64 addr, const RzILCacheBlock **block_out, void *user) {
	TestInterp *interp = user;
	const RzILCacheBlock *block = rz_il_cache_lift_il_block(interp->il_cache, addr);
	if (block) {
		*block_out = block;
		return RZ_ABSINT_LIFT_BLOCK_RESULT_OK;
	}
	return RZ_ABSINT_LIFT_BLOCK_RESULT_FAILED;
}

static TestInterp *interp_new(const char *arch, int bits, ut64 baddr, const char *url) {
	// for debugging, uncomment:
	// eprintf("rz -a %s -b %d -m 0x%" PFMT64x " %s\n", arch, bits, baddr, url);
	TestInterp *interp = RZ_NEW(TestInterp);
	interp->analysis = rz_analysis_new(NULL);
	rz_analysis_use(interp->analysis, arch);
	rz_analysis_set_bits(interp->analysis, bits);
	interp->io = rz_io_new();
	interp->io->va = 1;
	interp->il_cache = rz_il_cache_new(interp->analysis, interp->io, RZ_IL_CACHE_CONFIG_NOP_UNLIFTED);
	RzAbsIntConfig config = {
		.val_domain = &rz_absint_value_domain_const,
		.cb_user = interp,
		.io_read = io_read,
		.lift_block = lift_block
	};
	interp->inst = rz_absint_instance_new(interp->analysis, &config);
	RzIODesc *desc = rz_io_open_at(interp->io, url, RZ_PERM_RX, 0644, baddr, NULL);
	if (!desc) {
		mu_perror("load code");
		return NULL;
	}
	return interp;
}

static void interp_free(TestInterp *interp) {
	rz_absint_instance_free(interp->inst);
	rz_il_cache_free(interp->il_cache);
	rz_io_free(interp->io);
	rz_analysis_free(interp->analysis);
	free(interp);
}

static size_t do_extract_blocks(RzAbsIntResult *res, RzAbsIntBlock *blocks[], size_t count) {
	size_t r = 0;
	RzIntervalTreeIter it;
	RzAbsIntBlock *block;
	rz_interval_tree_foreach (&res->blocks, it, block) {
		if (r < count) {
			blocks[r] = block;
		}
		r++;
	}
	return r;
}

static ut64 block_start(RzAbsIntBlock *block) {
	return block->entry_state->pc;
}

static ut64 block_end(RzAbsIntBlock *block) {
	return block->node->end + 1;
}

#define STR_HELPER(x) #x
#define STR(x)        STR_HELPER(x)

/** Extract single result from interp as well as its blocks into local vars for easy assertion */
#define EXTRACT_RESULT(code, res, blocks_count) \
	mu_assert_eq(code, RZ_ABSINT_RESULT_OK, "result code"); \
	mu_assert_notnull(res, "result"); \
	RzAbsIntBlock *blocks[blocks_count]; \
	mu_assert_eq(do_extract_blocks(res, blocks, blocks_count), blocks_count, "blocks count")

#define ASSERT_BLOCK(i, start, end, is_fallthrough, jump) \
	do { \
		mu_assert_eq(block_start(blocks[i]), start, "block " STR(i) " start"); \
		mu_assert_eq(block_end(blocks[i]), end, "block " STR(i) " end"); \
		mu_assert_eq(blocks[i]->fallthrough, (is_fallthrough), "fallthrough"); \
		if ((jump) != UT64_MAX) { \
			mu_assert_eq(rz_vector_len(&blocks[i]->jump_targets), 1, "jump targets count"); \
			mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&blocks[i]->jump_targets, 0), (jump), "jump"); \
		} else { \
			mu_assert_eq(rz_vector_len(&blocks[i]->jump_targets), 0, "jump targets count"); \
		} \
	} while (0)

#define ASSERT_XREF(i, from_v, to_v, type_v) \
	do { \
		RzAnalysisXRef *xref = rz_vector_index_ptr(&res->xrefs, i); \
		mu_assert_eq(xref->from, from_v, "xref " STR(i) " from"); \
		mu_assert_eq(xref->to, to_v, "xref " STR(i) " to"); \
		mu_assert_eq(xref->type, type_v, "xref " STR(i) " type"); \
	} while (0)

#define ASSERT_ANALYSIS_BLOCK(block, start, end, jumpv, failv) \
	do { \
		mu_assert_eq(((RzAnalysisBlock *)block)->addr, (start), "analysis block start"); \
		mu_assert_eq(((RzAnalysisBlock *)block)->size, (end) - (start), "analysis block size"); \
		mu_assert_eq(((RzAnalysisBlock *)block)->jump, jumpv, "analysis block jump"); \
		mu_assert_eq(((RzAnalysisBlock *)block)->fail, failv, "analysis block fail"); \
	} while (0)

static size_t blocks_count(RzAbsIntRunContext *ctx) {
	size_t r = 0;
	RzIntervalTreeIter it;
	RzAbsIntBlock *block;
	rz_interval_tree_foreach (&ctx->blocks, it, block) {
		r++;
	}
	return r;
}

bool test_absint_block_resolve_bounds_single(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"000080d2"  // 0x00  mov   x0, 0
					// ---
		"200080d2"  // 0x04  mov   x0, 1 <- entry
		"400080d2"  // 0x08  mov   x0, 2
		"600080d2"  // 0x0c  mov   x0, 3
		"800080d2"  // 0x10  mov   x0, 4
		"a00080d2"  // 0x14  mov   x0, 5
		"c0035fd6"  // 0x18  ret
					// ---
		// clang-format on
	);

	RzAbsIntRunContext ctx;
	mu_assert_true(rz_absint_run_context_init(&ctx, interp->inst), "init run context");

	RzAbsIntState *as = rz_absint_state_new(interp->inst);
	rz_absint_state_set_pc_const(as, 0x10008);
	rz_absint_run_push(&ctx, as, false);
	rz_absint_state_free(interp->inst, as);

	mu_assert_eq(blocks_count(&ctx), 1, "blocks count");
	RzAbsIntBlock *block = rz_absint_block_at(&ctx, 0x10008);
	mu_assert_notnull(block, "block");

	const RzILCacheBlock *il_block = rz_il_cache_lift_il_block(interp->il_cache, 0x10008);
	rz_absint_block_resolve_bounds(&ctx, block, il_block);
	mu_assert_true(block->bounds_resolved, "bounds resolved");
	mu_assert_eq(rz_absint_block_get_start(block), 0x10008, "block start");
	mu_assert_eq(rz_absint_block_get_end(block), 0x1001b, "block end");
	mu_assert_eq(rz_vector_len(&block->insn_offsets), 4, "insn count");
	mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&block->insn_offsets, 0), 0x04, "insn offset");
	mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&block->insn_offsets, 1), 0x08, "insn offset");
	mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&block->insn_offsets, 2), 0x0c, "insn offset");
	mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&block->insn_offsets, 3), 0x10, "insn offset");

	rz_absint_run_context_fini(&ctx);
	interp_free(interp);
	mu_end;
}

bool test_absint_block_resolve_bounds_prepend(bool single_op_existing_block, bool single_op_prepend) {
	// single_op_existing_block and single_op_prepend are for testing for potential bugs in insn offset handling

	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		            // --- blocks for single_op_existing_block == false
		"000080d2"  // 0x00  mov   x0, 0 <- prepended block
		"200080d2"  // 0x04  mov   x0, 1 <- alternative entry if single_op_prepend
					// ---
		"400080d2"  // 0x08  mov   x0, 2 <- existing block
		"600080d2"  // 0x0c  mov   x0, 3
		"800080d2"  // 0x10  mov   x0, 4
		"a00080d2"  // 0x14  mov   x0, 5
		"c0035fd6"  // 0x18  ret
					// ---

		//             --- blocks for single_op_existing_block == true
		//             0x10  mov   x0, 4 <- prepended block
		//             0x14  mov   x0, 5 <- alternative entry if single_op_prepend
		//             ---
		//             0x18  ret         <- existing block
		//             ---
		// clang-format on
	);

	RzAbsIntRunContext ctx;
	mu_assert_true(rz_absint_run_context_init(&ctx, interp->inst), "init run context");

	ut64 existing_block_start = single_op_existing_block ? 0x10018 : 0x10008;
	ut64 prepended_block_start = existing_block_start - (single_op_prepend ? 4 : 8);

	RzAbsIntState *as = rz_absint_state_new(interp->inst);
	rz_absint_state_set_pc_const(as, existing_block_start);
	rz_absint_run_push(&ctx, as, false);
	rz_absint_state_free(interp->inst, as);

	as = rz_absint_state_new(interp->inst);
	rz_absint_state_set_pc_const(as, prepended_block_start);
	rz_absint_run_push(&ctx, as, false);
	rz_absint_state_free(interp->inst, as);

	mu_assert_eq(blocks_count(&ctx), 2, "blocks count");
	RzAbsIntBlock *block = rz_absint_block_at(&ctx, prepended_block_start);
	mu_assert_notnull(block, "block");

	const RzILCacheBlock *il_block = rz_il_cache_lift_il_block(interp->il_cache, prepended_block_start);
	rz_absint_block_resolve_bounds(&ctx, block, il_block);

	mu_assert_true(block->bounds_resolved, "bounds resolved");
	mu_assert_eq(rz_absint_block_get_start(block), prepended_block_start, "block start");
	mu_assert_eq(rz_absint_block_get_end(block), existing_block_start - 1, "block end");
	mu_assert_eq(rz_vector_len(&block->insn_offsets), single_op_prepend ? 0 : 1, "insn count");
	if (!single_op_prepend) {
		mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&block->insn_offsets, 0), 0x04, "insn offset");
	}

	rz_absint_run_context_fini(&ctx);
	interp_free(interp);
	mu_end;
}

bool test_absint_block_resolve_bounds_split(bool single_op_existing_block, bool single_op_split) {
	// single_op_existing_block and single_op_prepend are for testing for potential bugs in insn offset handling

	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		            // --- blocks for single_op_split == false
		"000080d2"  // 0x00  mov   x0, 0 <- existing block
		"200080d2"  // 0x04  mov   x0, 1 <- alternative entry if single_op_existing_block
					// ---
		"400080d2"  // 0x08  mov   x0, 2 <- splitting block
		"c0035fd6"  // 0x0c  ret
					// ---

		//             --- blocks for single_op_split == false
		//             0x00  mov   x0, 0
		//             0x04  mov   x0, 1 <- existing block
		//             0x08  mov   x0, 2 <- alternative entry if single_op_existing_block
		//             ---
		//             0x0c  ret         <- splitting block
		//             ---
		// clang-format on
	);

	RzAbsIntRunContext ctx;
	mu_assert_true(rz_absint_run_context_init(&ctx, interp->inst), "init run context");

	ut64 splitting_block_start = single_op_split ? 0x1000c : 0x10008;
	ut64 existing_block_start = splitting_block_start - (single_op_existing_block ? 4 : 8);

	RzAbsIntState *as = rz_absint_state_new(interp->inst);
	rz_absint_state_set_pc_const(as, existing_block_start);
	rz_absint_run_push(&ctx, as, false);
	rz_absint_state_free(interp->inst, as);
	RzAbsIntBlock *existing_block = rz_absint_block_at(&ctx, existing_block_start);
	mu_assert_notnull(existing_block, "block");

	const RzILCacheBlock *il_block = rz_il_cache_lift_il_block(interp->il_cache, existing_block_start);
	rz_absint_block_resolve_bounds(&ctx, existing_block, il_block);
	mu_assert_true(existing_block->bounds_resolved, "bounds resolved");
	mu_assert_eq(rz_absint_block_get_start(existing_block), existing_block_start, "block start");
	mu_assert_eq(rz_absint_block_get_end(existing_block), splitting_block_start + (single_op_split ? 3 : 7), "block end");
	size_t off_count_expect = (single_op_existing_block ? 0 : 1) + (single_op_split ? 1 : 2);
	mu_assert_eq(rz_vector_len(&existing_block->insn_offsets), off_count_expect, "insn count");
	for (size_t i = 0; i < off_count_expect; i++) {
		mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&existing_block->insn_offsets, i), 4 + 4 * i, "insn offset");
	}
	existing_block->fallthrough = false;
	ut64 target = 0x12345;
	rz_vector_push(&existing_block->jump_targets, &target);

	as = rz_absint_state_new(interp->inst);
	rz_absint_state_set_pc_const(as, splitting_block_start);
	rz_absint_run_push(&ctx, as, false);
	rz_absint_state_free(interp->inst, as);

	mu_assert_eq(blocks_count(&ctx), 2, "blocks count");
	RzAbsIntBlock *splitting_block = rz_absint_block_at(&ctx, splitting_block_start);
	mu_assert_notnull(splitting_block, "block");

	il_block = rz_il_cache_lift_il_block(interp->il_cache, splitting_block_start);
	rz_absint_block_resolve_bounds(&ctx, splitting_block, il_block);

	mu_assert_true(splitting_block->bounds_resolved, "bounds resolved");
	mu_assert_eq(rz_absint_block_get_start(splitting_block), splitting_block_start, "block start");
	mu_assert_eq(rz_absint_block_get_end(splitting_block), splitting_block_start + (single_op_split ? 3 : 7), "block end");
	mu_assert_eq(rz_vector_len(&splitting_block->insn_offsets), single_op_split ? 0 : 1, "insn count");
	if (!single_op_split) {
		mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&splitting_block->insn_offsets, 0), 0x04, "insn offset");
	}

	// existing has been modified to go only until the splitting block
	mu_assert_true(existing_block->bounds_resolved, "bounds resolved");
	mu_assert_eq(rz_absint_block_get_start(existing_block), existing_block_start, "block start");
	mu_assert_eq(rz_absint_block_get_end(existing_block), splitting_block_start - 1, "block end");
	mu_assert_eq(rz_vector_len(&existing_block->insn_offsets), single_op_existing_block ? 0 : 1, "insn count");
	if (!single_op_existing_block) {
		mu_assert_eq(*(ut16 *)rz_vector_index_ptr(&existing_block->insn_offsets, 0), 0x04, "insn offset");
	}
	mu_assert_true(existing_block->fallthrough, "existing fallthrough");
	mu_assert_eq(rz_vector_len(&existing_block->jump_targets), 0, "existing jump targets");

	rz_absint_run_context_fini(&ctx);
	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_single_block(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600880d2"  // 0x00  mov   x0, 0x43
		"c0035fd6"  // 0x04  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 1);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_direct_jmp(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600880d2"  // 0x00  mov   x0, 0x43
		"03000014"  // 0x04  b     0x10      ---
		"1f2003d5"  // 0x08  nop                |
		"1f2003d5"  // 0x0c  nop                |
		"400880d2"  // 0x10  mov   x0, 0x42  <--
		"c0035fd6"  // 0x14  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 2);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, false, 0x10010);
	ASSERT_BLOCK(1, 0x10010, 0x10018, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 2, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, 0x10010, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10010, 0x10018, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_branch(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600880d2"  // 0x00  mov   x0, 0x43
		"69000054"  // 0x04  b.ls  0x10      ---
		"1f2003d5"  // 0x08  nop                |
		"c0035fd6"  // 0x0c  ret                |
		"400880d2"  // 0x10  mov   x0, 0x42  <--
		"c0035fd6"  // 0x14  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 3);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, true, 0x10010);
	ASSERT_BLOCK(1, 0x10008, 0x10010, false, UT64_MAX);
	ASSERT_BLOCK(2, 0x10010, 0x10018, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 3, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, 0x10010, 0x10008);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10008, 0x10010, UT64_MAX, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x10010, 0x10018, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_branch_join(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"1f8c04f1"  // 0x00  cmp   x0, 0x123
		"69000054"  // 0x04  b.ls  0x10      ---
					//                          |
		"600880d2"  // 0x08  mov   x0, 0x43     |
		"02000014"  // 0x0c  b     0x14      -- | --
					//                          |   |
		"400880d2"  // 0x10  mov   x0, 0x42  <--    |
					//                              |
		"c0035fd6"  // 0x14  ret             <------
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 4);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, true, 0x10010);
	ASSERT_BLOCK(1, 0x10008, 0x10010, false, 0x10014);
	ASSERT_BLOCK(2, 0x10010, 0x10014, true, UT64_MAX);
	ASSERT_BLOCK(3, 0x10014, 0x10018, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 4, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, 0x10010, 0x10008);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10008, 0x10010, 0x10014, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x10010, 0x10014, 0x10014, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 3), 0x10014, 0x10018, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_multi_entry_fallthrough_jmp(bool swap) {
	// This is about a sequence of instructions that ends with some control flow instruction,
	// but has two entrypoints into it, where one entrypoint falls through into the other.
	// The swapping of the branches is there because potential bugs in the interpreter may
	// depend on the order of block addresses added.
	TestInterp *interp = interp_new("arm", 64, 0x10000, // clang-format off
		!swap ? "hex://"
			"a9000054"  // 0x00  b.ls  0x14      ------
			"02000014"  // 0x04  b     0xc       ---   |
			"1f2003d5"  // 0x08  nop                |  |
			"400880d2"  // 0x0c  mov   x0, 0x42  <--   |
			"1f2003d5"  // 0x10  nop                   |
			"610880d2"  // 0x14  mov   x1, 0x43  <-----
			"c0035fd6"  // 0x18  ret
		: "hex://"
			"69000054"  // 0x00  b.ls  0xc       ---
			"04000014"  // 0x04  b     0x14      -- | --
			"1f2003d5"  // 0x08  nop                |   |
			"400880d2"  // 0x0c  mov   x0, 0x42  <--    |
			"1f2003d5"  // 0x10  nop                    |
			"610880d2"  // 0x14  mov   x1, 0x43  <------
			"c0035fd6"  // 0x18  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 4);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10004, true, !swap ? 0x10014 : 0x1000c);
	ASSERT_BLOCK(1, 0x10004, 0x10008, false, !swap ? 0x1000c : 0x10014);
	ASSERT_BLOCK(2, 0x1000c, 0x10014, true, UT64_MAX);
	ASSERT_BLOCK(3, 0x10014, 0x1001c, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 4, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10004, !swap ? 0x10014 : 0x1000c, 0x10004);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10004, 0x10008, !swap ? 0x1000c : 0x10014, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x1000c, 0x10014, 0x10014, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 3), 0x10014, 0x1001c, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_multi_entry_fallthrough_jmp_before() {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"400880d2"  // 0x00  mov   x0, 0x42   <--
		"1f8c04f1"  // 0x04  cmp   x0, 0x123     |
		"c9ffff54"  // 0x08  b.ls  0          ---
		"c0035fd6"  // 0x0c  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10008, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 3);
	mu_assert_eq(res->entry, 0x10008, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, true, UT64_MAX);
	ASSERT_BLOCK(1, 0x10008, 0x1000c, true, 0x10000);
	ASSERT_BLOCK(2, 0x1000c, 0x10010, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10008);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 3, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, 0x10008, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10008, 0x1000c, 0x10000, 0x1000c);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x1000c, 0x10010, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_multi_entry_fallthrough_jmp_inside_self() {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600080d2"  // 0x00  mov   x0, 3
		"000400d1"  // 0x04  sub   x0, x0, 1 <--
		"e1ffff54"  // 0x08  b.ne  4         ---
		"c0035fd6"  // 0x0c  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 3);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10004, true, UT64_MAX);
	ASSERT_BLOCK(1, 0x10004, 0x1000c, true, 0X10004);
	ASSERT_BLOCK(2, 0x1000c, 0x10010, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 3, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10004, 0x10004, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10004, 0x1000c, 0x10004, 0x1000c);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x1000c, 0x10010, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_multi_entry_fallthrough_jmp_inside_other() {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600080d2"  // 0x00  mov   x0, 3
		"000400d1"  // 0x04  sub   x0, x0, 1 <--------
		"02000014"  // 0x08  b     0x10      ---      |
		"1f2003d5"  // 0x0c  nop                |     |
		"a1ffff54"  // 0x10  b.ne  4         <--   ---
		"c0035fd6"  // 0x14  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 4);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10004, true, UT64_MAX);
	ASSERT_BLOCK(1, 0x10004, 0x1000c, false, 0x10010);
	ASSERT_BLOCK(2, 0x10010, 0x10014, true, 0x10004);
	ASSERT_BLOCK(3, 0x10014, 0x10018, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 4, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10004, 0x10004, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10004, 0x1000c, 0x10010, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x10010, 0x10014, 0x10004, 0x10014);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 3), 0x10014, 0x10018, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_call_link_register(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600880d2"  // 0x00  mov   x0, 0x43
		"ff430094"  // 0x04  bl    0x11000
		"c0035fd6"  // 0x08  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 2);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, true, UT64_MAX);
	ASSERT_BLOCK(1, 0x10008, 0x1000c, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x1000c, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_call_multi_insn(void) {
	TestInterp *interp = interp_new("arm", 32, 0x10000, "hex://" // clang-format off
		// this pattern is common on ARMv4 to perform an indirect call
		"110aa0e3"  // 0x00  mov   r0, 0xff000
		"0fe0a0e1"  // 0x04  mov   lr, pc
		"00f0a0e1"  // 0x08  mov   pc, r0
		"1eff2fe1"  // 0x0c  bx    lr
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 2);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x1000c, true, UT64_MAX);
	ASSERT_BLOCK(1, 0x1000c, 0x10010, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10010, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_call_ret_in_memory(void) {
	TestInterp *interp = interp_new("x86", 64, 0x10000, "hex://" // clang-format off
		"89c1"            // 0x00  mov   ecx, eax
		"ff14cde0000008"  // 0x02  call  qword [rcx*8+0x80000e0]
		"c3"              // 0x09  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 2);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10009, true, UT64_MAX);
	ASSERT_BLOCK(1, 0x10009, 0x1000a, false, UT64_MAX);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x1000a, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

bool test_absint_cfg_merge_multiple_consecutive(void) {
	// multiple consecutive interp blocks should be merged, but only until the next in-edge
	// or until there is another non-fallthrough out-edge.
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"01010054"  // 0x00  b.ne  0x20     -----
		"200080d2"  // 0x04  mov   x0, 0x1       |
		"fe030094"  // 0x08  bl    0x11000       |
		"400080d2"  // 0x0c  mov   x0, 0x2       |
		"fc070094"  // 0x10  bl    0x11000       |
		"600080d2"  // 0x14  mov   x0, 0x3       |
		"40000054"  // 0x18  b.eq  0x20     ---  |
		"800080d2"  // 0x1c  mov   x0, 4       | |
		"c0035fd6"  // 0x20  ret            <-- -
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);

	EXTRACT_RESULT(code, res, 6);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10004, true, 0x10020);
	ASSERT_BLOCK(1, 0x10004, 0x1000c, true, UT64_MAX);
	ASSERT_BLOCK(2, 0x1000c, 0x10014, true, UT64_MAX);
	ASSERT_BLOCK(3, 0x10014, 0x1001c, true, 0x10020);
	ASSERT_BLOCK(4, 0x1001c, 0x10020, true, UT64_MAX);
	ASSERT_BLOCK(5, 0x10020, 0x10024, false, UT64_MAX);

	// Insert an unaligned block that should not be merged with when applying to analysis
	RzAbsIntState *as = rz_absint_state_new(interp->inst);
	as->pc_state = RZ_ABSINT_PC_CONST;
	as->pc = 0x10006;
	RzAbsIntBlock *b = rz_absint_block_create(interp->inst, &res->blocks, as);
	rz_absint_state_free(interp->inst, as);
	rz_interval_tree_resize(&res->blocks, b->node, 0x10006, 0x10009);
	b->bounds_resolved = true;
	b->uninterpreted = false;

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(interp->analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 5, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10004, 0x10020, 0x10004);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10004, 0x1001c, 0x10020, 0x1001c);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x10006, 0x1000a, UT64_MAX, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 3), 0x1001c, 0x10020, 0x10020, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 4), 0x10020, 0x10024, UT64_MAX, UT64_MAX);

	interp_free(interp);
	mu_end;
}

static int xref_cmp(const void *a, const void *b, void *user) {
	const RzAnalysisXRef *ax = a;
	const RzAnalysisXRef *bx = b;
	return (st64)ax->from - (st64)bx->from; // addrs in our tests are small enough that this is fine
}

bool test_absint_xrefs(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600880d2"  // 0x00  mov   x0, 0x43
		"a9000054"  // 0x04  b.ls  0x18      ------
		"81000090"  // 0x08  adrp  x1, 0x20000     |
		"230440f9"  // 0x0c  ldr   x3, [x1, 8]     |
		"200800f9"  // 0x10  str   x0, [x1, 0x10]  |
		"fb030094"  // 0x14  bl    0x1000          |
		"400880d2"  // 0x18  mov   x0, 0x42  <-----
		"c0035fd6"  // 0x1c  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzIODesc *data_desc = rz_io_open_at(interp->io, "malloc://0x100", RZ_PERM_RW, 0644, 0x20000, NULL);
	mu_assert_notnull(data_desc, "load data");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_XREFS, &res);

	EXTRACT_RESULT(code, res, 3);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, true, 0x10018);
	ASSERT_BLOCK(1, 0x10008, 0x10018, true, UT64_MAX);
	ASSERT_BLOCK(2, 0x10018, 0x10020, false, UT64_MAX);

	mu_assert_eq(rz_vector_len(&res->xrefs), 4, "xrefs count");
	rz_vector_sort(&res->xrefs, xref_cmp, false, NULL);
	ASSERT_XREF(0, 0x10004, 0x10018, RZ_ANALYSIS_XREF_TYPE_CODE);
	ASSERT_XREF(1, 0x1000c, 0x20008, RZ_ANALYSIS_XREF_TYPE_MEM_READ);
	ASSERT_XREF(2, 0x10010, 0x20010, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
	ASSERT_XREF(3, 0x10014, 0x11000, RZ_ANALYSIS_XREF_TYPE_CALL);

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);
	RzList *l = rz_analysis_xrefs_get_from(interp->analysis, 0x1000c);
	mu_assert_eq(rz_list_length(l), 1, "analysis xref");
	RzAnalysisXRef *x = rz_list_first_val(l);
	mu_assert_eq(x->from, 0x1000c, "analysis xref from");
	mu_assert_eq(x->to, 0x20008, "analysis xref to");
	mu_assert_eq(x->type, RZ_ANALYSIS_XREF_TYPE_MEM_READ, "analysis xref type");
	rz_list_free(l);

	interp_free(interp);
	mu_end;
}

bool test_absint_comments(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://" // clang-format off
		"600880d2"  // 0x00  mov   x0, 0x43
		"a9000054"  // 0x04  b.ls  0x18      ------
		"81000090"  // 0x08  adrp  x1, 0x20000     |
		"230440f9"  // 0x0c  ldr   x3, [x1, 8]     |
		"200800f9"  // 0x10  str   x0, [x1, 0x10]  |
		"fb030094"  // 0x14  bl    0x1000          |
		"400880d2"  // 0x18  mov   x0, 0x42  <-----
		"c0035fd6"  // 0x1c  ret
		// clang-format on
	);
	mu_assert_notnull(interp, "init");
	RzIODesc *data_desc = rz_io_open_at(interp->io, "malloc://0x100", RZ_PERM_RW, 0644, 0x20000, NULL);
	mu_assert_notnull(data_desc, "load data");
	RzAbsIntResult *res;
	RzAbsIntResultCode code = rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_COMMENTS, &res);

	EXTRACT_RESULT(code, res, 3);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK(0, 0x10000, 0x10008, true, 0x10018);
	ASSERT_BLOCK(1, 0x10008, 0x10018, true, UT64_MAX);
	ASSERT_BLOCK(2, 0x10018, 0x10020, false, UT64_MAX);

	mu_assert_eq(ht_up_size(res->comments), 8, "comments count");
	mu_assert_streq(ht_up_find(res->comments, 0x10000, NULL), "⊤; <-", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x10004, NULL), "x0 = 0x43; ->", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x10008, NULL), "x0 = 0x43; <-", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x1000c, NULL), "x1 = 0x20000, x0 = 0x43", "comment");

	// contents from here could become different when mem is implemented
	mu_assert_streq(ht_up_find(res->comments, 0x10010, NULL), "x1 = 0x20000, x0 = 0x43", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x10014, NULL), "x1 = 0x20000, x0 = 0x43; ->", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x10018, NULL), "⊤; <-", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x10010, NULL), "x1 = 0x20000, x0 = 0x43", "comment");
	mu_assert_streq(ht_up_find(res->comments, 0x1001c, NULL), "x0 = 0x42; ->", "comment");

	rz_absint_result_apply_to_analysis(res, interp->analysis, NULL);
	rz_absint_result_free(interp->inst, res);

	const char *acmt = rz_meta_get_string(interp->analysis, RZ_META_TYPE_COMMENT, 0x10008);
	mu_assert_streq(acmt, "x0 = 0x43; <-", "analysis comment");

	interp_free(interp);
	mu_end;
}

bool test_absint_driver(void) {
	rz_cons_new();
	RzAnalysis *analysis = rz_analysis_new(NULL);
	rz_analysis_use(analysis, "arm");
	rz_analysis_set_bits(analysis, 64);
	RzIO *io = rz_io_new();
	io->va = 1;
	RzIODesc *desc = rz_io_open_at(io, "hex://" // clang-format off
		"1f8c04f1"  // 0x00  cmp   x0, 0x123
		"69000054"  // 0x04  b.ls  0x10      ---
					//                          |
		"600880d2"  // 0x08  mov   x0, 0x43     |
		"02000014"  // 0x0c  b     0x14      -- | --
					//                          |   |
		"400880d2"  // 0x10  mov   x0, 0x42  <--    |
					//                              |
		"c0035fd6",  // 0x14  ret
		// clang-format on
		RZ_PERM_RX, 0644, 0x10000, NULL);
	mu_assert_notnull(desc, "load code");

	RzSetU *entry_points = rz_set_u_new();
	rz_set_u_add(entry_points, 0x10000);
	RzAbsIntDriverConfig config = {
		.analysis = analysis,
		.io = io,
		.entry_points = entry_points,
		.dimens = RZ_ABSINT_RESULT_DIMEN_XREFS | RZ_ABSINT_RESULT_DIMEN_COMMENTS,
		.trace_opts = RZ_ABSINT_TRACE_NONE
	};
	rz_absint_driver_run(&config);
	rz_set_u_free(entry_points);

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, 0x10000);
	mu_assert_notnull(fcn, "analysis function");
	mu_assert_eq(rz_pvector_len(fcn->bbs), 4, "analysis block count");
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 0), 0x10000, 0x10008, 0x10010, 0x10008);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 1), 0x10008, 0x10010, 0x10014, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 2), 0x10010, 0x10014, 0x10014, UT64_MAX);
	ASSERT_ANALYSIS_BLOCK(rz_pvector_at(fcn->bbs, 3), 0x10014, 0x10018, UT64_MAX, UT64_MAX);
	mu_assert_streq(rz_meta_get_string(analysis, RZ_META_TYPE_COMMENT, 0x1000c), "x0 = 0x43; ->", "applied comment");

	rz_analysis_free(analysis);
	rz_io_free(io);
	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_absint_block_resolve_bounds_single);
	mu_run_test(test_absint_block_resolve_bounds_prepend, false, false);
	mu_run_test(test_absint_block_resolve_bounds_prepend, false, true);
	mu_run_test(test_absint_block_resolve_bounds_prepend, true, false);
	mu_run_test(test_absint_block_resolve_bounds_prepend, true, true);
	mu_run_test(test_absint_block_resolve_bounds_split, false, false);
	mu_run_test(test_absint_block_resolve_bounds_split, false, true);
	mu_run_test(test_absint_block_resolve_bounds_split, true, false);
	mu_run_test(test_absint_block_resolve_bounds_split, true, true);
	mu_run_test(test_absint_cfg_single_block);
	mu_run_test(test_absint_cfg_direct_jmp);
	mu_run_test(test_absint_cfg_branch);
	mu_run_test(test_absint_cfg_branch_join);
	mu_run_test(test_absint_cfg_multi_entry_fallthrough_jmp, false);
	mu_run_test(test_absint_cfg_multi_entry_fallthrough_jmp, true);
	mu_run_test(test_absint_cfg_multi_entry_fallthrough_jmp_before);
	mu_run_test(test_absint_cfg_multi_entry_fallthrough_jmp_inside_self);
	mu_run_test(test_absint_cfg_multi_entry_fallthrough_jmp_inside_other);
	mu_run_test(test_absint_cfg_call_link_register);
	mu_run_test(test_absint_cfg_call_multi_insn);
	mu_run_test(test_absint_cfg_call_ret_in_memory);
	mu_run_test(test_absint_cfg_merge_multiple_consecutive);
	mu_run_test(test_absint_xrefs);
	mu_run_test(test_absint_comments);
	mu_run_test(test_absint_driver);
	return tests_passed != tests_run;
}

mu_main(all_tests)
