// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry/rz_il_cache.h>

RZ_API RZ_OWN char *rz_il_cache_block_str(RZ_NONNULL const RzILCacheBlock *block) {
	rz_return_val_if_fail(block, NULL);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_strbuf_appendf(&sb, "[0x%" PFMT64x ", 0x%" PFMT64x ")\n", block->addr, block->addr + block->size);
	void **it;
	rz_pvector_foreach (block->il_ops, it) {
		RzILCacheInsnPkt *insn = *it;
		rz_strbuf_appendf(&sb, "(sz = 0x%" PFMT64x ") ", (ut64)insn->insn_pkt_size);
		rz_il_op_effect_stringify(insn->effect, &sb, false);
		rz_strbuf_append(&sb, "\n");
	}
	return rz_strbuf_drain_nofree(&sb);
}

struct rz_il_cache_t {
	RZ_BORROW RzAnalysis *analysis;
	RZ_BORROW RzIO *io;
	RzILCacheConfig config; ///< The cache configuration.
	HtUP /*<block_addr, RzILCacheBlock *>*/ *cache;
};

static void rz_il_cache_insn_pkt_free(RZ_NULLABLE RZ_OWN RzILCacheInsnPkt *pkt) {
	if (!pkt) {
		return;
	}
	if (pkt->effect) {
		rz_il_op_effect_free(pkt->effect);
	}
	free(pkt);
}

static void rz_il_cache_block_free(RZ_NULLABLE RZ_OWN RzILCacheBlock *il_bb) {
	if (!il_bb) {
		return;
	}
	rz_pvector_free(il_bb->il_ops);
	free(il_bb);
}

static bool il_op_is_not_only_fallthrough(RzILOpEffect *op, ut64 fallthrough_addr) {
	switch (op->code) {
	case RZ_IL_OP_JMP: {
		RzILOpPure *dst = op->op.jmp.dst;
		return dst->code != RZ_IL_OP_BITV || rz_bv_to_ut64(dst->op.bitv.value) != fallthrough_addr;
	}
	case RZ_IL_OP_GOTO:
		return true;
	case RZ_IL_OP_SEQ:
		// ctrl effect in seq.x is not allowed by the type checker
		return il_op_is_not_only_fallthrough(op->op.seq.y, fallthrough_addr);
	case RZ_IL_OP_BLK:
		return il_op_is_not_only_fallthrough(op->op.blk.ctrl_eff, fallthrough_addr);
	case RZ_IL_OP_BRANCH:
		return il_op_is_not_only_fallthrough(op->op.branch.true_eff, fallthrough_addr) || il_op_is_not_only_fallthrough(op->op.branch.false_eff, fallthrough_addr);
	default:
		return false;
	}
}

RZ_OWN RzILCacheBlock *lift_il_block(const RzILCache *cache, ut64 addr) {
	RzILCacheBlock *il_block = NULL;
	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	// Estimate a reasonable number of bytes to read.
	int max_read_size = (rz_analysis_plugin_current(cache->analysis)->bits / 8) * 16;
	ut8 *buf = RZ_NEWS0(ut8, max_read_size);
	if (!max_read_size || !buf) {
		rz_warn_if_reached();
		goto fail;
	}

	il_block = RZ_NEW0(RzILCacheBlock);
	if (!il_block) {
		rz_warn_if_reached();
		goto fail;
	}
	il_block->il_ops = rz_pvector_new((RzPVectorFree)rz_il_cache_insn_pkt_free);
	if (!il_block->il_ops) {
		rz_warn_if_reached();
		goto fail;
	}
	il_block->addr = addr;

	// sparc plugin already does the reordering itself through stateful hacks
	bool reorder_delay = !RZ_STR_EQ(rz_analysis_plugin_current(cache->analysis)->arch, "sparc");

	RzILCacheInsnPkt *pkt = NULL;
	RzILOpEffect *delay_slot_effect = NULL;
	bool have_cf = false;
	ut32 delay = 0;
	while (!have_cf || delay) {
		// Don't use rz_io_read_at_mapped() here.
		// It fails if it reads beyond a mapped memory region.
		// Although this is expected here. rz_io_nread_at() on the other hand just
		// reads less bytes.
		if (rz_io_nread_at(cache->io, addr, buf, max_read_size) == 0) {
			goto fail;
		}
		if (rz_analysis_op(cache->analysis, &op, addr, buf, max_read_size,
			    RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_INSN_PKT) <= 0) {
			RZ_LOG_DEBUG("Failed to decode IL op\n");
			goto fail;
		}
		bool lifted = true;
		if (!op.il_op && cache->config & RZ_IL_CACHE_CONFIG_NOP_UNLIFTED) {
			// Not lifted. Map to NOP
			lifted = false;
			op.il_op = rz_il_op_new_nop();
		}
		il_block->size += op.size;
		if (lifted && il_op_is_not_only_fallthrough(op.il_op, addr + op.size)) {
			have_cf = true;
		}

		if (delay) {
			// For delay slots, reorder the instruction from the delay slots before the jump.
			// This is actually wrong because the semantics of delay slots are more complex than this,
			// but it is the best approximation we can do until RzArch.
			delay_slot_effect = delay_slot_effect ? rz_il_op_new_seq(delay_slot_effect, op.il_op) : op.il_op;
			pkt->insn_pkt_size += op.size;
			delay--;
			if (!delay) {
				pkt->effect = reorder_delay ? rz_il_op_new_seq(delay_slot_effect, pkt->effect) : rz_il_op_new_seq(pkt->effect, delay_slot_effect);
				delay_slot_effect = NULL;
			}
		} else {
			pkt = RZ_NEW0(RzILCacheInsnPkt);
			if (!pkt) {
				goto fail;
			}
			pkt->insn_pkt_size = op.size;
			pkt->effect = op.il_op;
			rz_pvector_push(il_block->il_ops, pkt);
			if (op.delay > 0 && have_cf) {
				delay = op.delay;
			}
		}
		// Take ownership of IL op pointer.
		op.il_op = NULL;

		addr += op.size;
		rz_analysis_op_fini(&op);
		rz_mem_memzero(buf, max_read_size);
	}

	free(buf);

	if (cache->config & RZ_IL_CACHE_CONFIG_TRACE) {
		char *s = rz_il_cache_block_str(il_block);
		RZ_LOG_INFO("Lifted IL Block: %s\n", rz_str_get_null(s));
		free(s);
	}

	return il_block;

fail:
	free(buf);
	rz_analysis_op_fini(&op);
	rz_il_cache_block_free(il_block);
	return NULL;
}

RZ_API const RzILCacheBlock *rz_il_cache_lift_il_block(RzILCache *cache, ut64 addr) {
	rz_return_val_if_fail(cache && rz_analysis_plugin_current(cache->analysis) && cache->io, NULL);
	RzILCacheBlock *block = ht_up_find(cache->cache, addr, NULL);
	if (block) {
		char *bstr = rz_il_cache_block_str(block);
		free(bstr);
		return block;
	}
	block = lift_il_block(cache, addr);
	if (!block) {
		RZ_LOG_DEBUG("ILCache: Failed to lift block at 0x%" PFMT64x "\n", addr);
		return NULL;
	}
	ht_up_insert(cache->cache, block->addr, block);
	return block;
}

RZ_API void rz_il_cache_free(RZ_OWN RZ_NULLABLE RzILCache *cache) {
	if (!cache) {
		return;
	}
	ht_up_free(cache->cache);
	free(cache);
}

RZ_API RZ_OWN RzILCache *rz_il_cache_new(
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_BORROW RZ_NONNULL RzIO *io,
	RzILCacheConfig config) {
	rz_return_val_if_fail(analysis && io, NULL);
	RzILCache *cache = RZ_NEW0(RzILCache);
	if (!cache) {
		rz_warn_if_reached();
		return NULL;
	}
	cache->analysis = analysis;
	cache->io = io;

	cache->cache = ht_up_new(NULL, (HtUPFreeValue)rz_il_cache_block_free);
	if (!cache->cache) {
		goto err;
	}

	cache->config = config;
	return cache;

err:
	rz_warn_if_reached();
	rz_il_cache_free(cache);
	return NULL;
}
