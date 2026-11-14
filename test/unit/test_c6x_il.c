// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_inquiry/rz_il_cache.h>
#include "minunit.h"

static RzCore *c6x_core_new(const ut8 *code, size_t len) {
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	if (!rz_core_arch_configure(core, "tms320", 32, "c674x", NULL, NULL) ||
		!rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RWX, 0, 0, NULL) ||
		!rz_io_write_at(core->io, 0, code, len)) {
		rz_core_free(core);
		return NULL;
	}
	rz_config_set_b(core->config, "cfg.bigendian", false);
	return core;
}

static int op_at(RzCore *core, RzAnalysisOp *op, ut64 addr, RzAnalysisOpMask mask) {
	ut8 buf[64] = { 0 };
	rz_io_nread_at(core->io, addr, buf, sizeof(buf));
	rz_analysis_op_init(op);
	return rz_analysis_op(core->analysis, op, addr, buf, sizeof(buf), mask);
}

static bool il_jumps(const RzILOpEffect *eff) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_il_op_effect_stringify((RzILOpEffect *)eff, &sb, false);
	bool r = strstr(rz_strbuf_get(&sb), "jmp") != NULL;
	rz_strbuf_fini(&sb);
	return r;
}

// mv a0,a1 || mv a1,a0, then b 0x40 with five NOPs in its delay slots
static const ut8 swap_then_branch[] = {
	0xd9, 0x0f, 0x80, 0x00, 0xa0, 0x06, 0x04, 0x00,
	0x10, 0x08, 0x00, 0x00
};

bool test_insn_pkt_size(void) {
	RzCore *core = c6x_core_new(swap_then_branch, sizeof(swap_then_branch));
	mu_assert_notnull(core, "set up");
	RzAnalysisOp op;
	op_at(core, &op, 0, RZ_ANALYSIS_OP_MASK_INSN_PKT);
	mu_assert_eq(op.size, 8, "an execute packet of two slots");
	rz_analysis_op_fini(&op);
	op_at(core, &op, 4, RZ_ANALYSIS_OP_MASK_INSN_PKT);
	mu_assert_eq(op.size, 4, "inside a packet, the rest of it");
	rz_analysis_op_fini(&op);
	op_at(core, &op, 8, RZ_ANALYSIS_OP_MASK_INSN_PKT);
	mu_assert_eq(op.size, 0x18, "a branch with its delay slots");
	mu_assert_eq(op.delay, 0, "which are no longer ahead");
	rz_analysis_op_fini(&op);
	op_at(core, &op, 8, RZ_ANALYSIS_OP_MASK_BASIC);
	mu_assert_eq(op.size, 4, "without the mask, the instruction");
	mu_assert_eq(op.delay, 5, "and the instructions of its delay slots");
	rz_analysis_op_fini(&op);
	rz_core_free(core);
	mu_end;
}

bool test_insn_pkt_header(void) {
	// seven NOPs and the header ending their compact fetch packet
	ut8 code[32] = { 0 };
	code[31] = 0xe0;
	RzCore *core = c6x_core_new(code, sizeof(code));
	mu_assert_notnull(core, "set up");
	RzAnalysisOp op;
	op_at(core, &op, 0x18, RZ_ANALYSIS_OP_MASK_INSN_PKT);
	mu_assert_eq(op.size, 8, "a packet before a header runs past it");
	rz_analysis_op_fini(&op);
	op_at(core, &op, 0x1c, RZ_ANALYSIS_OP_MASK_INSN_PKT | RZ_ANALYSIS_OP_MASK_IL);
	mu_assert_eq(op.size, 4, "the header alone");
	mu_assert_notnull(op.il_op, "lifts");
	mu_assert_eq(op.il_op->code, RZ_IL_OP_NOP, "to nothing");
	rz_analysis_op_fini(&op);
	rz_core_free(core);
	mu_end;
}

bool test_insn_pkt_il(void) {
	RzCore *core = c6x_core_new(swap_then_branch, sizeof(swap_then_branch));
	mu_assert_notnull(core, "set up");
	RzAnalysisOp op;
	op_at(core, &op, 0, RZ_ANALYSIS_OP_MASK_IL);
	mu_assert_notnull(op.il_op, "the packet lifts");
	mu_assert_true(il_jumps(op.il_op), "sized to its first slot, the IL jumps past the packet");
	rz_analysis_op_fini(&op);
	op_at(core, &op, 0, RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_INSN_PKT);
	mu_assert_notnull(op.il_op, "the packet lifts");
	mu_assert_false(il_jumps(op.il_op), "sized to the packet, it falls through");
	rz_analysis_op_fini(&op);
	rz_core_free(core);
	mu_end;
}

bool test_il_cache_block(void) {
	RzCore *core = c6x_core_new(swap_then_branch, sizeof(swap_then_branch));
	mu_assert_notnull(core, "set up");
	RzILCache *cache = rz_il_cache_new(core->analysis, core->io, RZ_IL_CACHE_CONFIG_DEFAULT);
	mu_assert_notnull(cache, "cache");
	const RzILCacheBlock *block = rz_il_cache_lift_il_block(cache, 0);
	mu_assert_notnull(block, "the block lifts");
	mu_assert_eq(block->size, 0x20, "up to the end of the delay slots");
	mu_assert_eq(rz_pvector_len(block->il_ops), 2, "in two ops");
	RzILCacheInsnPkt *pkt = rz_pvector_at(block->il_ops, 0);
	mu_assert_eq(pkt->insn_pkt_size, 8, "the packet");
	pkt = rz_pvector_at(block->il_ops, 1);
	mu_assert_eq(pkt->insn_pkt_size, 0x18, "and the branch with its delay slots");
	rz_il_cache_free(cache);
	rz_core_free(core);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_insn_pkt_size);
	mu_run_test(test_insn_pkt_header);
	mu_run_test(test_insn_pkt_il);
	mu_run_test(test_il_cache_block);
	return tests_passed != tests_run;
}

mu_main(all_tests)
