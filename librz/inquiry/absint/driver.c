// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Interpreter Driver
 *
 * Main loop spawning and serving interpreter threads,
 * as well as integrating results as they are emitted.
 *
 * Threads:
 * - rz_absint_driver_run is the entrypoint and contains the single main loop that has access to all of rizin.
 * - n interpreter threads are started that take care of the actual interpretation and analysis work.
 *   They communicate with the main loop through channels whenever they need any information from rizin.
 *
 * Channels:
 * - 1 InterpDriver.entry_points_ch      (1 main -> n threads)
 *     Main fills it with entrypoints and interpreters pop and analyze them until the queue is empty.
 * - 1 InterpDriver.main_ch              (n threads -> 1 main)
 *     Interpreters push io, instruction request and analysis results to this for the main loop to handle.
 * - n InterpThread.ch                   (1 main -> 1 thread)
 *     For io and instruction requests, main replies with the result to the thread that sent the request.
 */

#include "inquiry/absint/absint_priv.h"
#include <rz_inquiry/rz_cfg.h>
#include <rz_inquiry/rz_absint.h>
#include <rz_core.h>

typedef struct interp_thread InterpThread;

/**
 * \brief Request from an interpreter to the main loop
 */
typedef struct interp_driver_message_t {
	enum {
		DRIVER_MESSAGE_IO_READ, ///< The interpreter requests an IO read.
		DRIVER_MESSAGE_LIFT_BLOCK, ///< The interpreter requests lifting a block.
		DRIVER_MESSAGE_INTERP_RESULT ///< The interpreter delivers its results.
	} type;
	InterpThread *sender;
	union {
		struct {
			RzAbsIntIOReadRequest *request;
		} io_read;
		struct {
			ut64 addr;
		} lift_block;
		struct {
			ut64 entry;
			RzAbsIntResult *res;
		} interp_result;
	} payload;
} InterpDriverMessage;

#define DRIVER_MAIN_CH_SIZE 16 ///< TODO: optimize this to be small but blocking any interpreters under practical circumstances

typedef struct interp_driver_t {
	/**
	 * \brief Main -> Interpreters.
	 * Main delivers entry points to multiple interpreters with this.
	 * TODO: The queue is not the optimal data structure (needs heap data).
	 * But rbuf may lead to starvation.
	 */
	RzThreadQueue /*<ut64 *>*/ *entry_points_ch;
	/**
	 * \brief Interpreters -> Main.
	 * Multiple interpreters send info requests and analysis results with this.
	 */
	RzThreadRingBuf /*<InterpDriverMessage>*/ *main_ch;
	/**
	 * \brief Flags of result types the interpreters collect.
	 */
	RzAbsIntResultDimen dimens;
	/**
	 * \brief Flags for what is logged.
	 */
	RzAbsIntTraceOptions trace_opts;
} InterpDriver;

/**
 * \brief Answer from the main loop to an interpreter thread
 * Currently corresponds to exactly one request sent on InterpDriver.main_ch.
 */
typedef struct interp_thread_message_t {
	enum {
		INTERP_ANSWER_IO_READ,
		INTERP_ANSWER_LIFT_BLOCK
	} type;
	union {
		RzAbsIntIOReadResult io_read_result; ///< Flags of the IO read result (ok, top, error/stop).
		const RzILCacheBlock *lift_block_result; ///< The requested IL block. NULL in case of failure.
	} payload;
} InterpDriverAnswer;

struct interp_thread {
	InterpDriver *driver;
	RzThread *th;
	RzAbsIntInstance *inst;

	/**
	 * \brief Channel to this thread.
	 * Main delivers responses to requests on InterpDriver.main_ch to this in the exact order they were requested.
	 */
	RzThreadRingBuf /*<InterpDriverAnswer>*/ *ch;
} /* InterpThread */;

static void *interp_th(void *user) {
	InterpThread *ctx = user;
	RzAbsIntInstance *inst = ctx->inst;
	while (true) {
		ut64 *entry_point;
		if (!rz_th_queue_pop(ctx->driver->entry_points_ch, false, (void **)&entry_point)) {
			// closed, no more entry points to interpret
			break;
		}
		ut64 entry_point_val = *entry_point;
		free(entry_point);
		RzAbsIntResult *res = NULL;
		RzAbsIntResultCode code = rz_absint_run(inst, entry_point_val, ctx->driver->dimens, &res);
		if (code == RZ_ABSINT_RESULT_BREAK) {
			break;
		}
		InterpDriverMessage msg = {
			.type = DRIVER_MESSAGE_INTERP_RESULT,
			.sender = ctx,
			.payload = {
				.interp_result = {
					.entry = entry_point_val,
					.res = res } }
		};
		rz_th_ring_buf_put(ctx->driver->main_ch, &msg);
	}
	return NULL;
}

static RzAbsIntIOReadResult send_io_read(RZ_NONNULL RzAbsIntIOReadRequest *req, void *user) {
	InterpThread *th = user;
	InterpDriverMessage msg = {
		.type = DRIVER_MESSAGE_IO_READ,
		.sender = th,
		.payload = {
			.io_read = {
				.request = req } }
	};
	if (rz_th_ring_buf_put(th->driver->main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_IO_READ_RESULT_BREAK;
	}
	InterpDriverAnswer ret;
	if (rz_th_ring_buf_take_blocking(th->ch, &ret) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_IO_READ_RESULT_BREAK;
	}
	rz_return_val_if_fail(ret.type == INTERP_ANSWER_IO_READ, RZ_ABSINT_IO_READ_RESULT_BREAK);
	return ret.payload.io_read_result;
}

static RzAbsIntLiftBlockResult send_lift_il_block(ut64 addr, const RzILCacheBlock **block_out, void *user) {
	InterpThread *th = user;
	InterpDriverMessage msg = {
		.type = DRIVER_MESSAGE_LIFT_BLOCK,
		.sender = th,
		.payload = {
			.lift_block = {
				.addr = addr } }
	};
	if (rz_th_ring_buf_put(th->driver->main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK;
	}
	InterpDriverAnswer ret;
	if (rz_th_ring_buf_take_blocking(th->ch, &ret) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK;
	}
	rz_return_val_if_fail(ret.type == INTERP_ANSWER_LIFT_BLOCK, RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK);
	if (ret.payload.lift_block_result) {
		*block_out = ret.payload.lift_block_result;
		return RZ_ABSINT_LIFT_BLOCK_RESULT_OK;
	}
	return RZ_ABSINT_LIFT_BLOCK_RESULT_FAILED;
}

static InterpThread *interp_thread_new(RzAnalysis *analysis, InterpDriver *driver) {
	InterpThread *ctx = RZ_NEW(InterpThread);
	if (!ctx) {
		return NULL;
	}
	ctx->driver = driver;
	ctx->ch = rz_th_ring_buf_new(1, sizeof(InterpDriverAnswer)); // At the moment, threads directly wait after a single request, so size 1 is enough
	if (!ctx->ch) {
		goto err_ctx;
	}
	RzAbsIntConfig interp_config = {
		.val_domain = rz_absint_builtin_value_domain(RZ_ABSINT_VALUE_DOMAIN_CONST),
		.trace_opts = driver->trace_opts,
		.cb_user = ctx,
		.io_read = send_io_read,
		.lift_block = send_lift_il_block
	};
	ctx->inst = rz_absint_instance_new(analysis, &interp_config);
	if (!ctx->inst) {
		goto err_ch;
	}
	ctx->th = rz_th_new(interp_th, ctx);
	if (!ctx->th) {
		goto err_inst;
	}
	return ctx;
err_inst:
	rz_absint_instance_free(ctx->inst);
err_ch:
	rz_th_ring_buf_free(ctx->ch);
err_ctx:
	free(ctx);
	return NULL;
}

static void interp_thread_free(InterpThread *th) {
	if (!th) {
		return;
	}
	rz_th_ring_buf_close(th->ch);
	rz_th_wait(th->th);
	rz_th_free(th->th);
	rz_th_ring_buf_free(th->ch);
	rz_absint_instance_free(th->inst);
	free(th);
}

static RzAbsIntIOReadResult handle_io_request(const RzAnalysisILContext *il_ctx, RzAbsIntIOReadRequest *io_req) {
	RZ_LOG_DEBUG("inquiry: Received IO read request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (mem_idx >= rz_vector_len(&il_ctx->memory)) {
		rz_warn_if_reached();
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	if (rz_bv_len(io_req->addr) == 64 && rz_bv_msb(io_req->addr)) {
		// TODO: remove this when not needed anymore
		// https://github.com/rizinorg/rizin/issues/5806
		RZ_LOG_ERROR("Due to the Unix seek() implementation, addresses with the "
			     "63 bit set can't be addresses.\n");
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	RzAnalysisILMem *mem = rz_vector_index_ptr(&il_ctx->memory, mem_idx);
	if (!mem->base_buf) {
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	// TODO: here only memory should be read that can be assumed to be constant!
	// https://github.com/rizinorg/rizin/issues/6655
	bool ok = rz_il_loadw_into(mem->base_buf, io_req->ld_data, io_req->addr, io_req->n_bits, io_req->big_endian);
	RZ_LOG_DEBUG("inquiry: Sent IO read result. Success = %s.\n", rz_str_bool(ok));
	return ok ? RZ_ABSINT_IO_READ_RESULT_OK : RZ_ABSINT_IO_READ_RESULT_TOP;
}

static void bb_add_target(RzAnalysisBlock *abb, ut64 target) {
	if (abb->jump == UT64_MAX && abb->fail != target) {
		abb->jump = target;
	} else if (abb->fail == UT64_MAX && abb->jump != target) {
		abb->fail = target;
	} else if (abb->fail != target && abb->jump != target) {
		RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
			    "\t\tHas jump = 0x%" PFMT64x " fail = 0x%" PFMT64x ". Will miss = 0x%" PFMT64x "\n",
			abb->addr, abb->jump, abb->fail,
			target);
	}
}

static void add_block_to_conflict_list(RzAnalysis *analysis, RzAbsIntCFGConflicts *conflicts, RzAbsIntBlock *block, ut64 fcn_addr) {
	ut64 start = rz_absint_block_get_start(block);
	RzAbsIntCFGConflictAddResult res = rz_absint_cfg_conflict_add(conflicts, fcn_addr, block);
	if (res == RZ_ABSINT_CONFLICT_BLOCK_ERROR) {
		RZ_LOG_ERROR("Failed add block @ 0x%" PFMT64x " to the conflict list.\n", start);
		return;
	} else if (res == RZ_ABSINT_CONFLICT_BLOCK_KNOWN) {
		return;
	}
	// This is the first time the two conflicting blocks are detected.
	// We need to find the block which is already assigned to a function
	// and add it to the conflict list. So the list is complete.
	RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, start);
	if (!abb) {
		rz_warn_if_reached();
		return;
	}
	if (rz_list_length(abb->fcns) != 1) {
		rz_warn_if_reached();
		return;
	}
	RzAnalysisFunction *fcn = rz_list_get_n(abb->fcns, 0);
	if (rz_absint_cfg_conflict_add(conflicts, fcn->addr, block) == RZ_ABSINT_CONFLICT_BLOCK_ERROR) {
		rz_warn_if_reached();
		return;
	}
}

/**
 * \brief Applies the results of the abstract interpreter to RzAnalysis.
 *
 * It converts the \p res->blocks to a function with name \p fcn_name (or a generated name if NULL).
 * Directly applicable results like xrefs and comments are simply added to RzAnalysis.
 *
 * \param res The results.
 * \param analysis The RzAnalysis instance to add the results to.
 * \param fcn_name Optionally given function name for the function it creates for the \p res->blocks.
 *
 * \return True for success, false in case of failure.
 */
RZ_API bool rz_absint_result_apply_to_analysis(RZ_NONNULL RzAbsIntResult *res, RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAbsIntCFGConflicts *conflicts, RZ_NULLABLE const char *fcn_name) {
	rz_return_val_if_fail(res && analysis && conflicts, false);
	char name_alt[32] = { 0 };
	RzAnalysisFunction *func = rz_analysis_create_function(analysis, fcn_name ? fcn_name : rz_strf(name_alt, "inquiry.0x%" PFMT64x, res->entry), res->entry, RZ_ANALYSIS_FCN_TYPE_FCN);
	if (!func) {
		// TODO: handle better than skipping everything
		// rz_analysis_create_function() already prints the more detailed reason if there is any
		RZ_LOG_ERROR("Could not apply analysis result as function @ 0x%" PFMT64x ": func == NULL\n", res->entry);
		return false;
	}
	RzIntervalTreeIter it;
	RzAbsIntBlock *block;
	rz_interval_tree_foreach (&res->blocks, it, block) {
		if (block->added_to_analysis) {
			// has been merged into the previous already
			continue;
		}
		ut64 start = rz_absint_block_get_start(block);
		ut64 end_excl = rz_absint_block_get_end(block) + 1;

		// Merge consecutive blocks if there is no in-edge between them.
		// Splits like this happen in the first place because interp blocks only reach until the
		// first jump. This may be a call however, which just falls through.
		RzIntervalTreeIter next_it = it;
		while (block->is_fallthrough && rz_vector_empty(&block->jump_targets)) {
			rz_rbtree_iter_next(&next_it);
			RzIntervalNode *next_node = NULL;
			while (rz_rbtree_iter_has(&next_it)) {
				RzIntervalNode *n = rz_interval_tree_iter_get(&next_it);
				if (n->start >= end_excl) {
					if (n->start == end_excl) {
						next_node = n;
					}
					break;
				}
				rz_rbtree_iter_next(&next_it);
			}
			RzAbsIntBlock *next_block;
			if (!next_node || (next_block = next_node->data)->non_fallthrough_in) {
				// no consecutive block or there is a consecutive block, but is has an in-edge from somewhere else
				break;
			}
			next_block->added_to_analysis = true;
			end_excl = next_node->end + 1;
			block = next_block;
		}

		// Returns NULL for failures or if the block is already used by another function.
		RzAnalysisBlock *abb = rz_analysis_create_block(analysis, start, end_excl - start);
		if (!abb) {
			add_block_to_conflict_list(analysis, conflicts, block, func->addr);
			continue;
		}

		// TODO: analyze_ops should eventually not be used here since it does its own analysis.
		// Instead, we should manually apply our analysis info to it.
		// Keep in mind we might have to add info from multiple merged blocks here (see merging above)
		// and that our interp block works on instruction packets, not instructions
		rz_analysis_block_analyze_ops(abb);

		rz_analysis_function_add_block(func, abb);
		abb->jump = UT64_MAX;
		abb->fail = UT64_MAX;
		ut64 *target;
		rz_vector_foreach (&block->jump_targets, target) {
			bb_add_target(abb, *target);
		}
		if (block->is_fallthrough) {
			bb_add_target(abb, end_excl);
		}
	}

	// Hint: Some of the xrefs, specifically code and call ones, could be determined from
	// the information in blocks as well. So an optimization could be to make the interpreter
	// only emit explicit xref info for all remaining events, e.g. mem read/write.
	RzAnalysisXRef *xref;
	rz_vector_foreach (&res->xrefs, xref) {
		if (!rz_analysis_xrefs_set(analysis, xref->from, xref->to, xref->type)) {
			RZ_LOG_ERROR("failed to set xref\n");
		}
	}

	if (res->comments) {
		RzIterator it = (RzIterator){ 0 };
		if (!ht_up_as_iter_keys(res->comments, &it)) {
			return false;
		}
		ut64 *k;
		rz_iterator_foreach(&it, k) {
			const char *cmt = ht_up_find(res->comments, *k, NULL);
			if (cmt) {
				rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, *k, cmt);
			}
		}
		rz_iterator_fini(&it);
	}

	return true;
}

static bool add_res_blocks_to_cfgs(const RzAbsIntResult *res, RzCFGMap *cfgs) {
	RzGraph *cfg = rz_cfg_map_get_cfg(cfgs, res->entry);
	return true;
}

/**
 * \brief The main loop of multi-threaded abstract interpretation.
 * It initialises: The IL cache, communication channels with the interpreter threads and collects the entry points to analyze.
 * It then spawns n interpreter threads, serving them IO requests, IL block lifting requests, collecting their results.
 */
RZ_API bool rz_absint_driver_run(RZ_NONNULL RZ_BORROW RzAbsIntDriverConfig *config) {
	rz_return_val_if_fail(config && config->analysis && config->io && config->fcn_entry_points && config->n_threads > 0, false);
	bool return_code = false;
	bool breaked = false;

	RzILCacheConfig il_cache_config = RZ_IL_CACHE_CONFIG_NOP_UNLIFTED;
	if (config->trace_opts & RZ_ABSINT_TRACE_IL_BLOCK) {
		il_cache_config |= RZ_IL_CACHE_CONFIG_TRACE;
	}
	RzAbsIntCFGConflicts *conflicts = rz_absint_cfg_conflict_new();
	if (!conflicts) {
		goto err_conflicts;
	}
	RzCFGMap *cfg_map = rz_cfg_map_new();
	if (!cfg_map) {
		goto err_fcn_cfgs;
	}
	RzILCache *il_cache = rz_il_cache_new(config->analysis, config->io, il_cache_config);
	if (!il_cache) {
		goto err_none;
	}

	InterpDriver driver = {
		.dimens = config->dimens,
		.trace_opts = config->trace_opts
	};
	driver.entry_points_ch = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, free);
	if (!driver.entry_points_ch) {
		goto err_il_cache;
	}
	driver.main_ch = rz_th_ring_buf_new(DRIVER_MAIN_CH_SIZE, sizeof(InterpDriverMessage));
	if (!driver.main_ch) {
		goto err_entry_points_ch;
	}

	// Push all root entries
	size_t entries_pushed = 0;
	RzIterator it = (RzIterator){ 0 };
	if (!rz_set_u_as_iter(config->fcn_entry_points, &it)) {
		goto err_main_ch;
	}
	ut64 *entry;
	rz_iterator_foreach(&it, entry) {
		ut64 *tmp = RZ_NEW(ut64);
		if (!tmp) {
			rz_iterator_fini(&it);
			goto err_main_ch;
		}
		*tmp = *entry;
		if (!rz_th_queue_push(driver.entry_points_ch, tmp, true)) {
			rz_iterator_fini(&it);
			goto err_main_ch;
		}
		entries_pushed++;
	}
	rz_iterator_fini(&it);

	InterpThread **threads = RZ_NEWS0(InterpThread *, config->n_threads);
	if (!threads) {
		goto err_main_ch;
	}

	// Initialize and spawn the interpreters.
	for (size_t i = 0; i < config->n_threads; ++i) {
		threads[i] = interp_thread_new(config->analysis, &driver);
		if (!threads[i]) {
			goto err_threads;
		}
	}

	rz_cons_break_push(NULL, NULL);

	// Serve the interpreters
	size_t entries_finished = 0;
	while (entries_finished < entries_pushed) {
		if (rz_cons_is_breaked()) {
			breaked = true;
			break;
		}
		InterpDriverMessage msg;
		if (rz_th_ring_buf_take_blocking(driver.main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
			// closed
			break;
		}
		if (rz_cons_is_breaked()) {
			breaked = true;
			break;
		}
		switch (msg.type) {
		case DRIVER_MESSAGE_IO_READ: {
			RzAbsIntIOReadResult res = handle_io_request(msg.sender->inst->il_ctx, msg.payload.io_read.request);
			InterpDriverAnswer res_msg = {
				.type = INTERP_ANSWER_IO_READ,
				.payload = {
					.io_read_result = res }
			};
			if (rz_th_ring_buf_put(msg.sender->ch, &res_msg) != RZ_THREAD_RING_BUF_OK) {
				// should not be closed
				rz_warn_if_reached();
			}
			break;
		}
		case DRIVER_MESSAGE_LIFT_BLOCK: {
			const RzILCacheBlock *block = rz_il_cache_lift_il_block(il_cache, msg.payload.lift_block.addr);
			InterpDriverAnswer res_msg = {
				.type = INTERP_ANSWER_LIFT_BLOCK,
				.payload = {
					.lift_block_result = block }
			};
			if (rz_th_ring_buf_put(msg.sender->ch, &res_msg) != RZ_THREAD_RING_BUF_OK) {
				// should not be closed
				rz_warn_if_reached();
			}
			break;
		}
		case DRIVER_MESSAGE_INTERP_RESULT: {
			RzAbsIntResult *res = msg.payload.interp_result.res;
			if (res) {
				if (!add_res_blocks_to_cfgs(res, cfg_map)) {
					RZ_LOG_WARN("Failed to copy blocks to CFG\n");
				}
				char *name = config->choose_fcn_name ? config->choose_fcn_name(res->entry, config->choose_fcn_name_priv_data) : NULL;
				if (!rz_absint_result_apply_to_analysis(res, config->analysis, conflicts, name)) {
					RZ_LOG_WARN("Failed to apply to analysis\n");
				}
				free(name);
				rz_absint_result_free(msg.sender->inst, res);
			} else {
				RZ_LOG_WARN("Failed to analyze entry point 0x%" PFMT64x "\n", msg.payload.interp_result.entry);
			}
			entries_finished++;
			break;
		}
		default:
			rz_warn_if_reached();
			break;
		}
	}

	RzAbsIntCFGConflictSolutionCfg solv_config = RZ_ABSINT_CONFLICT_SOLUTION_DEFAULT;
	if (!rz_absint_cfg_conflicts_solve(config->analysis, conflicts, solv_config)) {
		RZ_LOG_WARN("Failed to resolve all CFG lock conflicts. Results analysis quality might be affected.\n");
	}

	return_code = true;

	rz_cons_break_pop();

err_threads:
	// Close channels to make interp threads stop.
	rz_th_queue_close(driver.entry_points_ch);
	rz_th_ring_buf_close(driver.main_ch);
	for (size_t i = 0; i < config->n_threads; i++) {
		interp_thread_free(threads[i]);
	}
	free(threads);
err_main_ch:
	rz_th_ring_buf_free(driver.main_ch);
err_entry_points_ch:
	rz_th_queue_free(driver.entry_points_ch);
err_il_cache:
	rz_il_cache_free(il_cache);
err_fcn_cfgs:
	rz_cfg_map_free(cfg_map);
err_conflicts:
	rz_absint_cfg_conflict_free(conflicts);
err_none:
	return return_code && !breaked;
}
