// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_il/rz_il_opcodes.h"
#include "rz_skyline.h"
#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_log.h"
#include "rz_util/rz_str.h"
#include "rz_util/rz_sys.h"
#include "rz_vector.h"
#include <rz_inquiry/rz_il_cache.h>

#define RZ_IL_OPS_CACHE_IL_QUEUE_SIZE  128
#define RZ_IL_OPS_CACHE_ADDR_RBUF_SIZE 1024

#define SLEEP_NONE_US  0
#define SLEEP_SHORT_US (5 * 1000)
#define SLEEP_LONG_US  (100 * 1000)

RZ_API RZ_OWN char *rz_il_cache_block_str(RZ_NONNULL const RzILCacheBlock *block) {
	rz_return_val_if_fail(block, NULL);
	return rz_str_newf("[0x%" PFMT64x ", 0x%" PFMT64x ")", block->addr, block->addr + block->size);
}

struct rz_il_cache_t {
	RZ_BORROW RzAnalysis *analysis;
	RZ_BORROW RzIO *io;

	RzPVector /*<RzBinSection *>*/ *bin_sections;

	size_t n_serving; ///< Number of caches serving currently.
	RzThreadLock *n_serving_lock;

	RzAtomicBool *is_serving; ///< Flag to signal cache to serve or not to serve IL ops.

	/**
	 * \brief Statically known control flow edges.
	 * Collected for each lifted IL block with a static control flow target.
	 */
	RzVector /*<RzAnalysisXRef>*/ *static_xrefs;

	HtUP /*<block_addr, RzILCacheBlock *>*/ *cache;

	// The pair of ring_buffer + queue are always at the same offset.
	RzPVector /*<RzThreadRingBuf *>*/ *req_rbufs; ///< The ring buffers the cache receives IL block requests.
	RzPVector /*<RzThreadQueue *>*/ *il_queues; ///< The queues the cache serves IL blocks over.

	RzThreadLock *skyline_lock;
	/**
	 * \brief A skyline (functionally the same as an r-tree) to log the code regions
	 * the cache served as IL blocks.
	 */
	RzSkyline *served_regions;

	RzILCacheConfig config; ///< The cache configuration.

	size_t us_sleep;
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

static RzAnalysisXRefType op_type_to_xref_type(const RzAnalysisOp *op) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_RCJMP:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
	case RZ_ANALYSIS_OP_TYPE_MCJMP:
	case RZ_ANALYSIS_OP_TYPE_UCJMP:
		return RZ_ANALYSIS_XREF_TYPE_CODE;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
		return RZ_ANALYSIS_XREF_TYPE_CALL;
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_CRET:
		return RZ_ANALYSIS_XREF_TYPE_RETURN;
	case RZ_ANALYSIS_OP_TYPE_ILL:
	case RZ_ANALYSIS_OP_TYPE_UNK:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_CSWI:
	case RZ_ANALYSIS_OP_TYPE_LEAVE:
	case RZ_ANALYSIS_OP_TYPE_SWITCH:
	default:
		break;
	}
	rz_warn_if_reached();
	return RZ_ANALYSIS_XREF_TYPE_NULL;
}

RZ_API RZ_OWN RzILCacheBlock *rz_il_cache_lift_il_block(const RzILCache *cache, ut64 addr) {
	rz_return_val_if_fail(cache && rz_analysis_plugin_current(cache->analysis) && cache->io, NULL);
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
	RZ_LOG_DEBUG("ILCache: Gen block:\n");
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
		}

		if (changes_cf && op.jump != UT64_MAX && cache->static_xrefs) {
			// The op.jump/op.fail says nothing about the
			// type of the control flow.
			// This one has to be deduced by the op type.
			// Really annoying and imprecise, but so be it.
			// The op.fail is to my knowledge always a "normal" control flow
			// as in "go to next instruction if branch condition fails".
			RzAnalysisXRef xref = {
				.bb_addr = il_block->addr,
				.from = op.addr,
				.to = op.jump,
				.type = op_type_to_xref_type(&op)
			};
			rz_vector_push(cache->static_xrefs, &xref);
			if (op.fail != UT64_MAX) {
				xref.to = op.fail;
				xref.type = RZ_ANALYSIS_XREF_TYPE_CODE;
				rz_vector_push(cache->static_xrefs, &xref);
			}
		}

		RZ_LOG_DEBUG("ILCache: \t0x%" PFMT64x "\n", addr);
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

static const RzILCacheBlock *lift_il_block(RzILCache *cache, ut64 addr) {
	RzILCacheBlock *block = ht_up_find(cache->cache, addr, NULL);
	if (block) {
		char *bstr = rz_il_cache_block_str(block);
		RZ_LOG_DEBUG("ILCache: Serve block %s from cache\n", bstr);
		free(bstr);
		return block;
	}
	RZ_LOG_DEBUG("ILCache: Lift new block\n");
	block = rz_il_cache_lift_il_block(cache, addr);
	if (!block) {
		RZ_LOG_DEBUG("ILCache: Failed to lift block at 0x%" PFMT64x "\n", addr);
		return NULL;
	}
	ht_up_insert(cache->cache, block->addr, block);
	return block;
}

static bool lift_executable_maps(RzILCache *cache) {
	void **it;
	rz_pvector_foreach (cache->bin_sections, it) {
		RzBinSection *sec = *it;
		if (!(sec->perm & RZ_PERM_X)) {
			continue;
		}
		ut64 addr = sec->vaddr;
		while (addr < sec->vaddr + sec->vsize) {
			const RzILCacheBlock *block = lift_il_block(cache, addr);
			if (!block) {
				RZ_LOG_INFO("Failed to lift IL block at 0x%" PFMT64x
					    " - Stop lifting section '%s'\n",
					addr, sec->name);
				break;
			}
			addr += block->size;
		}
	}
	return true;
}

RZ_API bool rz_il_cache_serve(RZ_NONNULL RzILCache *cache) {
	rz_return_val_if_fail(cache, false);
	rz_th_lock_enter(cache->n_serving_lock);
	cache->n_serving++;
	rz_th_lock_leave(cache->n_serving_lock);

	bool success = true;

	rz_atomic_bool_set(cache->is_serving, true);
	size_t clients = rz_pvector_len(cache->req_rbufs);
	while (rz_atomic_bool_get(cache->is_serving)) {
		for (size_t i = 0; i < clients; ++i) {
			RzThreadRingBuf *req_rbuf = rz_pvector_at(cache->req_rbufs, i);
			RzThreadQueue *serve_queue = rz_pvector_at(cache->il_queues, i);

			// TODO: This unsafe check permits race conditions.
			// Not sure if it improve performance here.
			// Needs more benchmarks.
			if (rz_th_ring_buf_is_empty_unsafe(req_rbuf)) {
				continue;
			}

			ut64 req_addr = 0;
			RzThreadRingBufResult r = rz_th_ring_buf_take(req_rbuf, &req_addr);
			if (r == RZ_THREAD_RING_BUF_CLOSED) {
				goto stop_serving;
			} else if (r == RZ_THREAD_RING_BUF_OK) {
				const RzILCacheBlock *block = lift_il_block(cache, req_addr);
				if (block) {
					rz_th_queue_push(serve_queue, (void *)block, true);
				} else {
					rz_th_queue_push(serve_queue, RZ_IL_CACHE_FAILED_LIFTING_PTR, true);
					RZ_LOG_DEBUG("Failed to lift IL block at 0x%" PFMT64x "\n", req_addr);
				}
			}
		}
		rz_sys_usleep(cache->us_sleep);
	}

stop_serving:
	rz_th_lock_enter(cache->n_serving_lock);
	cache->n_serving--;
	rz_th_lock_leave(cache->n_serving_lock);
	return success;
}

/**
 * \brief Close all IL Cache owned ring buffers.
 */
RZ_API void rz_il_cache_close(RZ_BORROW RZ_NONNULL RzILCache *cache) {
	rz_return_if_fail(cache);

	rz_atomic_bool_set(cache->is_serving, false);

	for (size_t i = 0; i < rz_pvector_len(cache->req_rbufs); ++i) {
		RzThreadRingBuf *rb = rz_pvector_at(cache->req_rbufs, i);
		rz_th_ring_buf_close(rb);
		RzThreadQueue *il_queue = rz_pvector_at(cache->il_queues, i);
		rz_th_queue_close(il_queue);
	}
}

RZ_API void rz_il_cache_stop_serving(RZ_BORROW RZ_NONNULL RzILCache *cache) {
	rz_return_if_fail(cache);
	rz_atomic_bool_set(cache->is_serving, false);
}

/**
 * \brief Returns the static xrefs pointing from IL block to IL block.
 */
RZ_API const RzVector /*<RzAnalysisXRef>*/ *rz_il_cache_get_static_xrefs(const RzILCache *cache) {
	rz_return_val_if_fail(cache, NULL);
	return cache->static_xrefs;
}

RZ_API RZ_OWN RzIterator /*<const RzILCacheBlock **>*/ *rz_il_cache_get_blocks(const RzILCache *cache) {
	rz_return_val_if_fail(cache, NULL);
	return ht_up_as_iter(cache->cache);
}

RZ_API void rz_il_cache_free(RZ_OWN RZ_NULLABLE RzILCache *cache) {
	if (!cache) {
		return;
	}

	rz_il_cache_close(cache);
	// Wait until all are left.
	bool all_stopped = false;
	do {
		rz_th_lock_enter(cache->n_serving_lock);
		all_stopped = cache->n_serving == 0;
		rz_th_lock_leave(cache->n_serving_lock);
	} while (!all_stopped);

	rz_pvector_free(cache->req_rbufs);
	rz_pvector_free(cache->il_queues);

	ht_up_free(cache->cache);
	rz_vector_free(cache->static_xrefs);
	rz_th_lock_free(cache->n_serving_lock);
	rz_atomic_bool_free(cache->is_serving);
	rz_pvector_free(cache->bin_sections);
	rz_th_lock_free(cache->skyline_lock);
	if (cache->served_regions) {
		rz_skyline_fini(cache->served_regions);
		free(cache->served_regions);
	}
	free(cache);
}

RZ_API RZ_OWN RzILCache *rz_il_cache_new(
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_BORROW RZ_NONNULL RzIO *io,
	RZ_OWN RZ_NONNULL RzPVector /*<RzBinSection *>*/ *bin_sections,
	RzILCacheConfig config) {
	rz_return_val_if_fail(analysis && io && bin_sections, NULL);
	RzILCache *cache = RZ_NEW0(RzILCache);
	if (!cache) {
		rz_warn_if_reached();
		return NULL;
	}
	cache->analysis = analysis;
	cache->io = io;
	cache->bin_sections = bin_sections;

	cache->cache = ht_up_new(NULL, (HtUPFreeValue)rz_il_cache_block_free);
	cache->is_serving = rz_atomic_bool_new(false);
	cache->n_serving_lock = rz_th_lock_new(false);
	cache->static_xrefs = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);
	if (!cache->cache || !cache->is_serving || !cache->static_xrefs) {
		goto err;
	}

	cache->skyline_lock = rz_th_lock_new(false);
	cache->served_regions = RZ_NEW0(RzSkyline);
	if (!cache->skyline_lock || !cache->served_regions) {
		goto err;
	}
	rz_skyline_init(cache->served_regions);

	cache->il_queues = rz_pvector_new((RzPVectorFree)rz_th_queue_free);
	cache->req_rbufs = rz_pvector_new((RzPVectorFree)rz_th_ring_buf_free);
	if (!cache->il_queues || !cache->req_rbufs) {
		goto err;
	}

	cache->config = config;
	cache->us_sleep = SLEEP_NONE_US;

	if ((cache->config & RZ_IL_CACHE_CONFIG_SLEEP_LONG) == RZ_IL_CACHE_CONFIG_SLEEP_LONG) {
		cache->us_sleep = SLEEP_LONG_US;
	} else if ((cache->config & RZ_IL_CACHE_CONFIG_SLEEP_LONG) == RZ_IL_CACHE_CONFIG_SLEEP_SHORT) {
		cache->us_sleep = SLEEP_SHORT_US;
	}

	if (!(cache->config & RZ_IL_CACHE_CONFIG_LIFT_ON_REQUEST) &&
		!lift_executable_maps(cache)) {
		RZ_LOG_WARN("An error occurred when lifting the executable sections.\n");
	}

	return cache;

err:
	rz_warn_if_reached();
	rz_il_cache_free(cache);
	return NULL;
}

/**
 * \brief Check if the given address has been requested from the cache.
 */
RZ_API bool rz_il_cache_was_requested(
	RZ_BORROW RzILCache *cache,
	ut64 addr) {
	rz_th_lock_enter(cache->skyline_lock);
	bool r = rz_skyline_contains(cache->served_regions, addr);
	rz_th_lock_leave(cache->skyline_lock);
	return r;
}

RZ_API bool rz_il_cache_get_new_ring_buf(
	RZ_BORROW RzILCache *cache,
	RZ_NONNULL RZ_BORROW RZ_OUT RzThreadRingBuf **request_rbuf,
	RZ_NONNULL RZ_BORROW RZ_OUT RzThreadQueue **il_queue) {
	rz_return_val_if_fail(cache && request_rbuf && il_queue, false);

	*request_rbuf = NULL;
	*il_queue = NULL;
	// The queue to pass the Effects to the interpreter.
	*il_queue = rz_th_queue_new(RZ_IL_OPS_CACHE_IL_QUEUE_SIZE, NULL);
	if (!il_queue) {
		rz_warn_if_reached();
		goto error_free;
	}
	rz_pvector_push(cache->il_queues, *il_queue);

	// The ring buffer the interpreter can request new Effects over.
	*request_rbuf = rz_th_ring_buf_new(RZ_IL_OPS_CACHE_ADDR_RBUF_SIZE, sizeof(ut64));
	if (!*request_rbuf) {
		rz_warn_if_reached();
		goto error_free;
	}
	rz_pvector_push(cache->req_rbufs, *request_rbuf);

	return true;
error_free:
	rz_th_queue_free(*il_queue);
	rz_th_ring_buf_free(*request_rbuf);
	return false;
}
