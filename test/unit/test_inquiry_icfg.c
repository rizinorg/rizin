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
		.val_domain = rz_absint_builtin_value_domain(RZ_ABSINT_VALUE_DOMAIN_CONST),
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
	RzAbsIntBlock *blocks[blocks_count] = { 0 }; \
	mu_assert_eq(do_extract_blocks(res, blocks, blocks_count), blocks_count, "blocks count")

#define ASSERT_BLOCK(i, start, end, is_fallthru, jump) \
	do { \
		mu_assert_eq(block_start(blocks[i]), start, "block " STR(i) " start"); \
		mu_assert_eq(block_end(blocks[i]), end, "block " STR(i) " end"); \
		mu_assert_eq(blocks[i]->is_fallthrough, (is_fallthru), "fallthrough"); \
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


bool all_tests() {
	mu_run_test(test_absint_block_resolve_bounds_single);
	return tests_passed != tests_run;
}

mu_main(all_tests)
