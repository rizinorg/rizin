// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <rz_core.h>
#include <rz_gadget.h>

// Only one gadget is added once for each test case.
#define ROP_GADGET_MAX_SIZE 16

static const char *x86_64_buf_str[] = {
	// mov rbx, 1; ret;
	"48C7C301000000C3",
	// mov rbx, rax; ret;
	"4889c3c3"
};

static const char *mips_buf_str[] = {
	// addiu $t0, $zero, 1; jr $ra; nop
	"2408000103e0000800000000",
	// or $v0, $a0, $zero; jr $ra; nop
	"0080102503e0000800000000"
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

static RzPVector /*<RzCoreAsmHit *>*/ *
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

	RzPVector /*<RzCoreAsmHit *>*/ *hitlist = rz_pvector_new(rz_core_asm_hit_free);
	if (!hitlist) {
		return NULL;
	}

	RzCoreAsmHit *hit = setup_rop_hitasm(core, addr, buf_str, len - 1, ht_rop_analysis);
	if (!hit) {
		rz_pvector_free(hitlist);
		return NULL;
	}
	rz_pvector_push(hitlist, hit);
	hit = setup_rop_hitasm(core, addr + len - 1, buf_str, 1, ht_rop_analysis);
	if (!hit) {
		rz_pvector_free(hitlist);
		return NULL;
	}
	rz_pvector_push(hitlist, hit);
	rz_analysis_op_fini(&aop);
	return hitlist;
}

static RzCore *setup_rz_core(char *arch, int bits, bool bigendian) {
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL);
	rz_core_arch_configure(core, arch, bits, NULL, NULL, NULL);
	rz_config_set_b(core->config, "cfg.bigendian", bigendian);
	rz_config_set_b(core->config, "asm.lines", false);
	return core;
}

static void cleanup_test(RzCore *core, HtUP *ht_rop_analysis) {
	ht_up_free(ht_rop_analysis);
	rz_core_free(core);
}

static bool rop_gadget_info_cb(void *user, const ut64 k, const void *v) {
	HtUP *ht_rop_analysis = (HtUP *)user;
	RzGadgetInfo *gadget_info = (RzGadgetInfo *)v;
	mu_assert_eq(k, gadget_info->address, "ROP gadget address mismatch");
	RzAnalysisOp *aop = ht_up_find(ht_rop_analysis, k, NULL);
	mu_assert_notnull(aop, "ROP gadget analysis op is NULL");
	mu_assert_notnull(aop->dst, "ROP gadget analysis op dst is NULL");
	RzAnalysisValue *src = aop->src[0];
	mu_assert_notnull(src, "ROP gadget analysis op src is NULL");
	RzRegItem *reg_item = aop->dst->reg;
	mu_assert_notnull(reg_item, "ROP gadget register item is NULL");
	RzGadgetRegInfo *reg_info = rz_core_gadget_info_get_modified_register(gadget_info, aop->dst->reg->name);
	mu_assert_notnull(reg_info, "ROP gadget modified register is NULL");
	mu_assert_streq(reg_info->name, reg_item->name, "ROP gadget modified register name mismatch");
	if (src[0].type == RZ_ANALYSIS_VAL_IMM) {
		mu_assert_eq(src->imm, reg_info->new_val - reg_info->init_val, "ROP gadget modified register value mismatch");
	} else if (src[0].type == RZ_ANALYSIS_VAL_REG) {
		RzPVector /*<RzGadgetRegInfo *>*/ *reg_info_vector = rz_core_gadget_get_reg_info_by_event(gadget_info, RZ_GADGET_EVENT_VAR_READ);
		mu_assert_notnull(reg_info_vector, "ROP gadget register item is NULL");
		mu_assert_eq(rz_pvector_len(reg_info_vector), 2, "ROP gadget register item count mismatch");
		RzGadgetRegInfo *reg_info_analysis_reg = rz_pvector_at(reg_info_vector, 0);
		mu_assert_streq(src->reg->name, reg_info_analysis_reg->name, "ROP gadget modified register value mismatch");
		rz_pvector_free(reg_info_vector);
	}

	return true;
}

bool test_rz_direct_solver() {
	RzCore *core = setup_rz_core("x86", 64, false);
	mu_assert_notnull(core, "setup_rz_core failed");
	int size = RZ_ARRAY_SIZE(x86_64_buf_str);
	int addr = 0;
	RzGadgetSearchContext *context = rz_core_gadget_search_context_new(
		core, RZ_GADGET_TYPE_ROP, NULL, false, RZ_GADGET_PRINT_DETAIL | RZ_GADGET_ANALYZE, RZ_GADGET_DETAIL_SEARCH_NON,
		NULL);
	mu_assert_notnull(context, "rz_core_gadget_search_context_new failed");
	HtUP *ht_rop_analysis = ht_up_new(NULL, (HtUPFreeValue)rz_analysis_op_free);
	for (int i = 0; i < size; i++) {
		ut8 buf[ROP_GADGET_MAX_SIZE] = { 0 };
		int len = rz_hex_str2bin(x86_64_buf_str[i], buf);
		rz_io_write_at(core->io, addr, buf, len);
		RzPVector /*<RzCoreAsmHit *>*/ *hitlist =
			setup_rop_hitlist(core, buf, addr, len, ht_rop_analysis);
		mu_assert_notnull(hitlist, "setup_rop_hitlist failed");
		rz_core_handle_gadget_request_type(core, context, hitlist, 0);
		addr += len + 1;
		rz_pvector_free(hitlist);
	}

	HtUP *rop_semantics = rz_analysis_get_gadget_semantics(core->analysis);
	mu_assert_notnull(rop_semantics, "ROP semantics hashtable is NULL");
	mu_assert_eq(ht_up_size(rop_semantics), 2, "ROP semantics hashtable count is not 2");
	ht_up_foreach(rop_semantics, rop_gadget_info_cb, ht_rop_analysis);
	rz_core_gadget_search_context_free(context);
	cleanup_test(core, ht_rop_analysis);
	mu_end;
}

static bool run_gadget_cache_test(char *arch, int bits, bool bigendian,
	const char **buf_strs, int buf_count) {
	RzCore *core = setup_rz_core(arch, bits, bigendian);
	mu_assert_notnull(core, "setup_rz_core failed");
	int addr = 0;
	RzCmdStateOutput state;

	// searching in quiet mode, easier to compare cache content below
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET, core);
	RzGadgetSearchContext *context = rz_core_gadget_search_context_new(
		core, RZ_GADGET_TYPE_ROP, NULL, false, RZ_GADGET_PRINT, RZ_GADGET_DETAIL_SEARCH_NON,
		&state);
	mu_assert_notnull(context, "rz_core_gadget_search_context_new failed");
	for (int i = 0; i < buf_count; i++) {
		ut8 buf[ROP_GADGET_MAX_SIZE] = { 0 };
		int len = rz_hex_str2bin(buf_strs[i], buf);
		rz_io_write_at(core->io, addr, buf, len);
		addr += len;
	}
	context->from = 0;
	context->to = addr;
	context->cache = true;

	RzGadgetCache *gadget_cache = rz_analysis_get_gadget_cache(core->analysis, RZ_GADGET_TYPE_ROP);
	mu_assert_null(gadget_cache, "ROP gadget cache should be NULL for empty cache");

	// first search, build cache
	context->ret_val = true;
	RzCmdStatus status = rz_core_gadget_search(core, context);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "ROP gadget search failed");
	gadget_cache = rz_analysis_get_gadget_cache(core->analysis, RZ_GADGET_TYPE_ROP);
	mu_assert_notnull(gadget_cache, "ROP gadget cache should not be NULL after search");

	// cnt cache nodes after first search
	RBIter iter;
	int cnt = 0;
	RzGadgetCacheNode *node;
	rz_rbtree_foreach (gadget_cache->tree, iter, node, RzGadgetCacheNode, rb) {
		cnt++;
	}
	mu_assert("ROP gadget cache should not be empty", cnt > 0);
	int first_cnt = cnt;

	// store and sort lines
	char *output1 = rz_strbuf_drain(context->buf);
	context->buf = NULL;
	mu_assert_notnull(output1, "first search output is NULL");
	RzList *lines1 = rz_str_split_duplist(output1, "\n", true);
	rz_list_sort(lines1, (RzListComparator)strcmp, NULL);
	free(output1);

	// second search, served from cache
	cnt = 0;
	status = rz_core_gadget_search(core, context);
	mu_assert_eq(status, RZ_CMD_STATUS_OK, "ROP gadget search from cache failed");
	rz_rbtree_foreach (gadget_cache->tree, iter, node, RzGadgetCacheNode, rb) {
		cnt++;
	}
	mu_assert_eq(cnt, first_cnt, "ROP gadget cache size should not change on serving from cache");

	char *output2 = rz_strbuf_drain(context->buf);
	context->buf = NULL;
	mu_assert_notnull(output2, "second search output is NULL");
	RzList *lines2 = rz_str_split_duplist(output2, "\n", true);
	rz_list_sort(lines2, (RzListComparator)strcmp, NULL);
	free(output2);

	// diff sorted outputs
	mu_assert_eq(rz_list_length(lines1), rz_list_length(lines2),
		"number of gadgets in cache differs from that of fresh search");

	RzListIter *it1 = rz_list_head(lines1);
	RzListIter *it2 = rz_list_head(lines2);
	while (it1 && it2) {
		mu_assert_streq((char *)it1->val, (char *)it2->val,
			"gadget in cache differs from fresh search");
		it1 = it1->next;
		it2 = it2->next;
	}

	rz_list_free(lines1);
	rz_list_free(lines2);
	rz_cmd_state_output_fini(&state);
	rz_core_gadget_search_context_free(context);
	rz_core_free(core);
	mu_end;
}

bool test_rz_gadget_cache_x86_64() {
	return run_gadget_cache_test("x86", 64, false, x86_64_buf_str, RZ_ARRAY_SIZE(x86_64_buf_str));
}

bool test_rz_gadget_cache_mips() {
	return run_gadget_cache_test("mips", 32, true, mips_buf_str, RZ_ARRAY_SIZE(mips_buf_str));
}

bool all_tests() {
	mu_run_test(test_rz_direct_solver);
	mu_run_test(test_rz_gadget_cache_x86_64);
	mu_run_test(test_rz_gadget_cache_mips);
	return tests_passed != tests_run;
}

mu_main(all_tests)
