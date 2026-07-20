// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_il/rz_il_opcodes.h"
#include "rz_types.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_log.h"
#include "rz_util/rz_str.h"
#include "rz_vector.h"
#include <rz_inquiry/rz_il_cache.h>

RZ_API RZ_OWN char *rz_il_cache_block_str(RZ_NONNULL const RzILCacheBlock *block) {
	rz_return_val_if_fail(block, NULL);
	return rz_str_newf("[0x%" PFMT64x ", 0x%" PFMT64x ")", block->addr, block->addr + block->size);
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
	bool sparc_add_delayed_insn = false;
	bool changes_cf = true;
	do {
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
		RzILCacheInsnPkt *pkt = RZ_NEW0(RzILCacheInsnPkt);
		pkt->effect = op.il_op;
		// Take ownership of IL op pointer.
		op.il_op = NULL;
		pkt->insn_pkt_size = op.size;
		il_block->size += op.size;
		rz_pvector_push(il_block->il_ops, pkt);

		if (lifted) {
			changes_cf = rz_analysis_op_changes_control_flow(&op);
		} else {
			changes_cf = false;
		}

		addr += op.size;
		rz_analysis_op_fini(&op);
		rz_mem_memzero(buf, max_read_size);
		if (sparc_add_delayed_insn) {
			// Instruction was added, now the block is complete.
			break;
		}
		if (changes_cf && RZ_STR_EQ(rz_analysis_plugin_current(cache->analysis)->arch, "sparc")) {
			// We need to add the instruction after the branch.
			// So one more iteration is needed.
			sparc_add_delayed_insn = true;
			changes_cf = false;
		}
	} while (!changes_cf);

	free(buf);
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
