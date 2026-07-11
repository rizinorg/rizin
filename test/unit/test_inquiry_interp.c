// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry/rz_interpreter.h>
#include "minunit.h"

typedef struct test_interp_t {
	RzAnalysis *analysis;
	RzIO *io;
	RzILCache *il_cache;
	RzILCacheClient *il_cache_client;
	RzInterpInstance *inst;
} TestInterp;

static TestInterp *interp_new(const char *arch, int bits, ut64 baddr, const char *url) {
	// for debugging, uncomment:
	// eprintf("rz -a %s -b %d -m 0x%" PFMT64x " %s\n", arch, bits, baddr, url);
	TestInterp *interp = RZ_NEW(TestInterp);
	interp->analysis = rz_analysis_new(NULL);
	rz_analysis_use(interp->analysis, arch);
	rz_analysis_set_bits(interp->analysis, bits);
	interp->io = rz_io_new();
	interp->io->va = 1;
	interp->il_cache = rz_il_cache_new(interp->analysis, interp->io, NULL, RZ_IL_CACHE_CONFIG_NOP_UNLIFTED | RZ_IL_CACHE_CONFIG_NO_SLEEP);
	interp->il_cache_client = rz_il_cache_new_client(interp->il_cache, false);
	interp->inst = rz_interp_instance_new(interp->analysis, &rz_interp_value_domain_const, interp->il_cache_client, NULL);
	RzIODesc *desc = rz_io_open_at(interp->io, url, RZ_PERM_RX, 0644, baddr, NULL);
	if (!desc) {
		mu_perror("load code");
		return NULL;
	}
	return interp;
}

static void interp_free(TestInterp *interp) {
	rz_interp_instance_free(interp->inst);
	rz_il_cache_free(interp->il_cache);
	rz_io_free(interp->io);
	rz_analysis_free(interp->analysis);
	free(interp);
}

static size_t do_extract_blocks(RzInterpResult *res, RzInterpBlock *blocks[], size_t count) {
	size_t r = 0;
	RzIntervalTreeIter it;
	RzInterpBlock *block;
	rz_interval_tree_foreach(&res->blocks, it, block) {
		if (r < count) {
			blocks[r] = block;
		}
		r++;
	}
	return r;
}

static ut64 block_start(RzInterpBlock *block) {
	return block->entry_state->pc;
}

static ut64 block_end(RzInterpBlock *block) {
	return block->node->end + 1;
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

/** Extract single result from interp as well as its blocks into local vars for easy assertion */
#define EXTRACT_RESULT(interp, blocks_count) \
	mu_assert_eq(rz_pvector_len(&interp->inst->results), 1, "results len"); \
	RzInterpResult *res = rz_pvector_at(&interp->inst->results, 0); \
	RzInterpBlock *blocks[blocks_count]; \
	mu_assert_eq(do_extract_blocks(res, blocks, blocks_count), blocks_count, "blocks count")

#define ASSERT_BLOCK_BOUNDS(i, start, end) do { \
		mu_assert_eq(block_start(blocks[i]), start, "block " STR(i) " start"); \
		mu_assert_eq(block_end(blocks[i]), end, "block " STR(i) " end"); \
	} while (0);

bool test_interp_cfg_single_block(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://"
		"600880d2"  // 0x00  mov   x0, 0x43
		"c0035fd6"  // 0x04  ret
	);
	mu_assert_notnull(interp, "init");
	bool succ = rz_interp_run(interp->inst, 0x10000);
	mu_assert_true(succ, "run success");

	EXTRACT_RESULT(interp, 1);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK_BOUNDS(0, 0x10000, 0x10008);

	interp_free(interp);
	mu_end;
}

bool test_interp_cfg_direct_jmp(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://"
		"600880d2"  // 0x00  mov   x0, 0x43
		"03000014"  // 0x04  b     0x10      ---
		"1f2003d5"  // 0x08  nop                |
		"1f2003d5"  // 0x0c  nop                |
		"400880d2"  // 0x10  mov   x0, 0x42  <--
		"c0035fd6"  // 0x14  ret
	);
	mu_assert_notnull(interp, "init");
	bool succ = rz_interp_run(interp->inst, 0x10000);
	mu_assert_true(succ, "run success");

	EXTRACT_RESULT(interp, 2);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK_BOUNDS(0, 0x10000, 0x10008);
	ASSERT_BLOCK_BOUNDS(1, 0x10010, 0x10018);

	interp_free(interp);
	mu_end;
}

bool test_interp_cfg_branch_join(void) {
	TestInterp *interp = interp_new("arm", 64, 0x10000, "hex://"
		"1f8c04f1"  // 0x00  cmp   x0, 0x123
		"69000054"  // 0x04  b.ls  0x10      ---
					//                          |
		"600880d2"  // 0x08  mov   x0, 0x43     |
		"02000014"  // 0x0c  b     0x14      -- | --
					//                          |   |
		"400880d2"  // 0x10  mov   x0, 0x42  <--    |
					//                              |
		"c0035fd6"  // 0x14  ret             <------
	);
	mu_assert_notnull(interp, "init");
	bool succ = rz_interp_run(interp->inst, 0x10000);
	mu_assert_true(succ, "run success");

	EXTRACT_RESULT(interp, 4);
	mu_assert_eq(res->entry, 0x10000, "result entry");
	ASSERT_BLOCK_BOUNDS(0, 0x10000, 0x10008);
	ASSERT_BLOCK_BOUNDS(1, 0x10008, 0x10010);
	ASSERT_BLOCK_BOUNDS(2, 0x10010, 0x10014);
	ASSERT_BLOCK_BOUNDS(3, 0x10014, 0x10018);

	interp_free(interp);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_interp_cfg_single_block);
	mu_run_test(test_interp_cfg_direct_jmp);
	mu_run_test(test_interp_cfg_branch_join);
	return tests_passed != tests_run;
}

mu_main(all_tests)
