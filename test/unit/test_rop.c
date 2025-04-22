// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <rz_core.h>
#include <rz_rop.h>

// Only one gadget is added once for each test case.
#define ROP_GADGET_MAX_SIZE 16

static const char *x86_64_buf_str[] = {
	// mov rbx, 1; ret;
	"48C7C301000000C3",
	// mov rbx, rax; ret;
	"4889c3c3"
};

static RzCoreAsmHit *setup_rop_hitasm(RzCore *core, int addr, ut8 *buf_str, int len, HtUP *ht_rop_analysis) {
	RzCoreAsmHit *hit = rz_core_asm_hit_new();
	if (!hit) {
		return NULL;
	}
	hit->addr = addr;
	hit->len = len;
	RzAnalysisOp *aop = rz_analysis_op_new();
	if (rz_analysis_op(core->analysis, aop, addr, buf_str, len,
		    RZ_ANALYSIS_OP_MASK_DISASM | RZ_ANALYSIS_OP_MASK_VAL) < 0) {
		rz_core_asm_hit_free(hit);
		rz_analysis_op_free(aop);
		return NULL;
	}
	ht_up_insert(ht_rop_analysis, addr, aop);
	return hit;
}

static RzList /*<RzCoreAsmHit *>*/ *
setup_rop_hitlist(RzCore *core, ut8 *buf_str, int addr, int len, HtUP *ht_rop_analysis) {
	RzAnalysisOp aop = { 0 };
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, addr + len - 1, buf_str + len - 1, 1,
		    RZ_ANALYSIS_OP_MASK_DISASM | RZ_ANALYSIS_OP_MASK_VAL) < 0) {
		return NULL;
	}

	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		return NULL;
	}

	RzList /*<RzCoreAsmHit *>*/ *hitlist = rz_list_newf(rz_core_asm_hit_free);
	if (!hitlist) {
		return NULL;
	}

	RzCoreAsmHit *hit = setup_rop_hitasm(core, addr, buf_str, len - 1, ht_rop_analysis);
	if (!hit) {
		rz_list_free(hitlist);
		return NULL;
	}
	rz_list_append(hitlist, hit);
	hit = setup_rop_hitasm(core, addr + len - 1, buf_str, 1, ht_rop_analysis);
	if (!hit) {
		rz_list_free(hitlist);
		return NULL;
	}
	rz_list_append(hitlist, hit);
	rz_analysis_op_fini(&aop);
	return hitlist;
}

static RzCore *setup_rz_core(char *arch, int bits) {
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL);
	rz_core_set_asm_configs(core, arch, bits, 0);
	rz_config_set_b(core->config, "asm.lines", false);
	return core;
}

static void cleanup_test(RzCore *core, HtUP *ht_rop_analysis) {
	ht_up_free(ht_rop_analysis);
	rz_core_free(core);
}

static bool rop_gadget_info_cb(void *user, const ut64 k, const void *v) {
	HtUP *ht_rop_analysis = (HtUP *)user;
	RzRopGadgetInfo *gadget_info = (RzRopGadgetInfo *)v;
	mu_assert_eq(k, gadget_info->address, "ROP gadget address mismatch");
	RzAnalysisOp *aop = ht_up_find(ht_rop_analysis, k, NULL);
	mu_assert_notnull(aop, "ROP gadget analysis op is NULL");
	mu_assert_notnull(aop->dst, "ROP gadget analysis op dst is NULL");
	RzAnalysisValue *src = aop->src[0];
	mu_assert_notnull(src, "ROP gadget analysis op src is NULL");
	RzRegItem *reg_item = aop->dst->reg;
	mu_assert_notnull(reg_item, "ROP gadget register item is NULL");
	RzRopRegInfo *reg_info = rz_core_rop_gadget_info_get_modified_register(gadget_info, aop->dst->reg->name);
	mu_assert_notnull(reg_info, "ROP gadget modified register is NULL");
	mu_assert_streq(reg_info->name, reg_item->name, "ROP gadget modified register name mismatch");
	if (src[0].type == RZ_ANALYSIS_VAL_IMM) {
		mu_assert_eq(src->imm, reg_info->new_val - reg_info->init_val, "ROP gadget modified register value mismatch");
	} else if (src[0].type == RZ_ANALYSIS_VAL_REG) {
		RzPVector /*<RzRopRegInfo *>*/ *reg_info_vector = rz_core_rop_gadget_get_reg_info_by_event(gadget_info, RZ_ROP_EVENT_VAR_READ);
		mu_assert_notnull(reg_info_vector, "ROP gadget register item is NULL");
		mu_assert_eq(rz_pvector_len(reg_info_vector), 2, "ROP gadget register item count mismatch");
		RzRopRegInfo *reg_info_analysis_reg = rz_pvector_at(reg_info_vector, 0);
		mu_assert_streq(src->reg->name, reg_info_analysis_reg->name, "ROP gadget modified register value mismatch");
	}

	return true;
}

bool test_rz_direct_solver() {
	RzCore *core = setup_rz_core("x86", 64);
	mu_assert_notnull(core, "setup_rz_core failed");
	int size = sizeof(x86_64_buf_str) / sizeof(x86_64_buf_str[0]);
	int addr = 0;
	RzRopSearchContext *context = rz_core_rop_search_context_new(
		core, NULL, false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE,
		NULL);
	mu_assert_notnull(context, "rz_core_rop_search_context_new failed");
	HtUP *ht_rop_analysis = ht_up_new(NULL, (HtUPFreeValue)rz_analysis_op_free);
	for (int i = 0; i < size; i++) {
		ut8 buf[ROP_GADGET_MAX_SIZE] = { 0 };
		int len = rz_hex_str2bin(x86_64_buf_str[i], buf);
		rz_io_write_at(core->io, addr, buf, len);
		RzList /*<RzCoreAsmHit *>*/ *hitlist =
			setup_rop_hitlist(core, buf, addr, len, ht_rop_analysis);
		mu_assert_notnull(hitlist, "setup_rop_hitlist failed");
		rz_core_handle_rop_request_type(core, context, hitlist);
		addr += len + 1;
		rz_list_free(hitlist);
	}

	HtUP *rop_semantics = core->analysis->ht_rop_semantics;
	mu_assert_notnull(rop_semantics, "ROP semantics hashtable is NULL");
	mu_assert_eq(rop_semantics->count, 2, "ROP semantics hashtable count is not 2");
	ht_up_foreach(rop_semantics, rop_gadget_info_cb, ht_rop_analysis);
	cleanup_test(core, ht_rop_analysis);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_direct_solver);
	return tests_passed != tests_run;
}

mu_main(all_tests)
