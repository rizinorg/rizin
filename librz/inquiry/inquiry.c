// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_analysis.h"
#include "rz_config.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_inquiry_plugins.h"
#include "rz_io.h"
#include "rz_reg.h"
#include "rz_th.h"
#include "rz_vector.h"
#include <rz_list.h>
#include <rz_types_base.h>
#include <rz_util/rz_assert.h>

RZ_LIB_VERSION(rz_inquiry);

#define MAX_IO_DATA_READ 0x1000

static RzInquiryPlugin *inquiry_static_plugins[] = { RZ_INQUIRY_STATIC_PLUGINS };

RZ_API const size_t rz_inquiry_get_n_plugins() {
	return RZ_ARRAY_SIZE(inquiry_static_plugins);
}

RZ_API RZ_BORROW RzInquiryPlugin *rz_inquiry_get_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(inquiry_static_plugins)) {
		return NULL;
	}
	return inquiry_static_plugins[index];
}

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);
	if (plugin->p_interpreter) {
		if (!ht_sp_insert(inquiry->plugins, plugin->p_interpreter->name, plugin)) {
			RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->p_interpreter->name);
		}
		return true;
	}

	rz_warn_if_reached();
	return false;
}

RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);

	if (plugin->p_interpreter) {
		return ht_sp_delete(inquiry->plugins, plugin->p_interpreter->name);
	}
	rz_warn_if_reached();
	return false;
}

RZ_API bool rz_inquiry_xref_interpreter_filter(ut64 *xref_to_addr, RZ_NONNULL const RzList /*<RzIOMap *>*/ *allowed_io_maps) {
	rz_return_val_if_fail(xref_to_addr && allowed_io_maps, false);
	const RzIOMap *map;
	RzListIter *it;
	rz_list_foreach (allowed_io_maps, it, map) {
		ut64 start = map->itv.addr;
		ut64 end = map->itv.addr + map->itv.size;
		if (RZ_BETWEEN(start, *xref_to_addr, end)) {
			return true;
		}
	}
	return false;
}

static ut64 get_nop_pc_increment(RzAnalysis *analysis) {
	return analysis->cur->bits / 8;
}

static ut64 get_mem_addr_bits(RzAnalysis *analysis) {
	if (analysis->cur->il_config) {
		RzAnalysisILConfig *config = analysis->cur->il_config(analysis);
		size_t key_size = config->mem_key_size;
		rz_analysis_il_config_free(config);
		return key_size;
	}
	return analysis->cur->bits;
}

static RzPVector *get_reg_names(RzAnalysis *analysis) {
	RzPVector *reg_names = rz_pvector_new(free);
	if (analysis->cur->il_config) {
		RzAnalysisILConfig *config = analysis->cur->il_config(analysis);
		if (config->reg_bindings) {
			for (size_t i = 0; config->reg_bindings[i]; i++) {
				rz_pvector_push(reg_names, rz_str_dup(config->reg_bindings[i]));
			}
			rz_analysis_il_config_free(config);
			return reg_names;
		}
		rz_analysis_il_config_free(config);
	}
	const RzList *regs = rz_reg_get_list(analysis->reg, RZ_REG_TYPE_ANY);
	if (!regs) {
		return NULL;
	}
	RzRegItem *reg;
	RzListIter *iter;
	rz_list_foreach (regs, iter, reg) {
		rz_pvector_push(reg_names, rz_str_dup(reg->name));
	}
	return reg_names;
}

/**
 * A function to call the prototype interpreter.
 * Usually these tasks will be split between different caches and yield consumers.
 */
RZ_API bool rz_inquiry_interpreter(RzCore *core, int argc, const char **argv) {
	// All the things we need
	bool return_code = true;
	RzThreadQueue *io_request_q = NULL;
	RzThreadQueue *io_result_q = NULL;
	RzILOpEffect *eff = NULL;
	RzThreadQueue *addr_queue = NULL;
	RzList *boundaries = NULL;
	RzInterpreterYieldQueue *yield_queue = NULL;
	HtUP *yield_queues = NULL;
	RzAtomicBool *is_running = rz_atomic_bool_new(true);
	RzInterpreterAbstrState *abstr_state = NULL;
	RzInterpreterSet *iset = NULL;
	RzPVector *il_cache = NULL;
	RzThreadQueue *il_queue = NULL;
	RzVector *entry_points = NULL;

	// The pseudo cache of IL effects.
	// This is only a vector so we can simulate the ownership separation
	// of the pointers.
	il_cache = rz_pvector_new((RzPVectorFree)rz_il_op_effect_free);
	// The queue to pass the Effects to the interpreter.
	// This is only one queue for the prototype.
	// In practice it would be one for each interpreter.
	il_queue = rz_th_queue_new(RZ_INTERPRETER_IL_QUEUE_SIZE, NULL);
	if (!il_queue) {
		return_code = false;
		goto error_free;
	}

	// Setup the IO queues. Each interpreter instance needs it's own queue at
	// for writing IO. Because the writing is done on the IO cache, and each
	// instance needs its own cache.
	io_request_q = rz_th_queue_new(RZ_INTERPRETER_IO_QUEUE_SIZE, NULL);
	io_result_q = rz_th_queue_new(RZ_INTERPRETER_IO_QUEUE_SIZE, NULL);
	if (!io_request_q || !io_result_q) {
		return_code = false;
		goto error_free;
	}

	// Add the Effect for each entry point.
	entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
	eff = NULL;
	if (argc == 1) {
		ut64 entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
		if (!eff) {
			RZ_LOG_WARN("Could not get entry point IL operation at 0x%" PFMT64x "\n", (ut64)entry_point);
			return_code = false;
			goto error_free;
		}
		rz_vector_push(entry_points, &entry_point);
		rz_th_queue_push(il_queue, eff, true);
		rz_pvector_push(il_cache, eff);
	} else {
		// Add all entry points given as arguments.
		for (size_t i = 1; i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
			if (!eff) {
				return_code = false;
				goto error_free;
			}
			rz_vector_push(entry_points, &entry_point);
		}
		rz_th_queue_push(il_queue, eff, true);
		rz_pvector_push(il_cache, eff);
	}

	// The address queue. It is the queue the interpreter can request new Effects.
	// Of course, currently there is only a single one for the prototype.
	// In practice there would be one for each interpreter instance.
	addr_queue = rz_th_queue_new(RZ_INTERPRETER_ADDR_QUEUE_SIZE, (RzListFree)rz_interpreter_addr_queue_free);
	if (!addr_queue) {
		return_code = false;
		goto error_free;
	}

	// Here we build the filter for the yield queue.
	// The prototype generates constant xrefs.
	// So the filter checks the generated xrefs, if they are within the IO map
	// boundaries.
	RzInterval iv = { .addr = 0, .size = UT64_MAX };
	boundaries = rz_io_get_boundaries_all_io_maps(core->io, iv);
	if (!boundaries) {
		return_code = false;
		goto error_free;
	}

	// Now create a set of yield queue(s).
	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		(RzInterpreterYieldFilter)rz_inquiry_xref_interpreter_filter,
		boundaries);
	if (!yield_queue) {
		return_code = false;
		goto error_free;
	}

	// Multiple yield queues can be used by a single interpreter.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queue || !yield_queues) {
		return_code = false;
		goto error_free;
	}
	ht_up_insert(yield_queues, yield_kind, yield_queue);

	// Initialize the abstract state with the architecture's registers.
	size_t addr_bits = get_mem_addr_bits(core->analysis);
	RzPVector *reg_names = get_reg_names(core->analysis);
	ut64 nop_pc_increment = get_nop_pc_increment(core->analysis);
	abstr_state = rz_interpreter_abstr_state_new(
		RZ_INTERPRETER_ABSTRACTION_CONST,
		reg_names,
		nop_pc_increment,
		addr_bits);
	rz_pvector_free(reg_names);

	// Bundle all the queues into one object to pass it to the thread.
	// Later we would pass a unique iset to each interpreter with
	// the required queues only.
	// But for the prototype we have only one iset with all queues.
	iset = rz_interpreter_set_new(
		rz_inquiry_plugin_interpreter_prototype.p_interpreter,
		abstr_state,
		addr_queue,
		il_queue,
		yield_queues,
		io_request_q,
		io_result_q,
		is_running,
		entry_points);
	if (!iset) {
		return_code = false;
		goto error_free;
	}

	// Dispatch prototype interpreter into a thread.
	RZ_LOG_WARN("INQUIRY: Start main interpretation thread.\n");
	RzThread *interpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, iset);

	// From here on, the code plays the role of the cache, IO handler,
	// and yield consumer.
	// - Waiting for new Effects to be requested and sending them.
	// - Handling IO requests.
	// - Receiving and adding the found xrefs to RzAnalysis.
	// In the final implementation each of those roles would be split into
	// two or more separated modules running in parallel.
	RZ_LOG_WARN("INQUIRY: Enforce enabling IO cache.\n");
	const char *io_cache_opt = rz_config_get(core->config, "io.cache");
	rz_config_set(core->config, "io.cache", "true");
	RZ_LOG_WARN("INQUIRY: Start IL providing loop.\n");

	// Poor man's shared memory.
	RzInterpreterIOResult _io_res = { 0 };
	RzInterpreterIOResult *io_res = &_io_res;
	ut8 io_res_buf[MAX_IO_DATA_READ] = { 0 };
	io_res->read.data = io_res_buf;

	while (rz_atomic_bool_get(is_running)) {
		if (rz_th_terminated(interpr_th)) {
			rz_atomic_bool_set(is_running, false);
			return_code = rz_th_get_retv(interpr_th);
			break;
		}

		// This block mimics the IL cache.
		{
			ut64 *addr = rz_th_queue_pop(addr_queue, false);
			if (addr) {
				RZ_LOG_WARN("INQUIRY: Received IL request: 0x%" PFMT64x "\n", (*addr));
				RzILOpEffect *bb = rz_inquiry_gen_il_bb(core->analysis, core->io, *addr);
				if (!bb) {
					RZ_LOG_ERROR("Failed to lift basic block at 0x%" PFMT64x "\n", *addr);
					// Signal interpreter the lifting failed.
					rz_th_cond_signal_all(rz_th_queue_get_cond(iset->il_queue));
					rz_atomic_bool_set(is_running, false);
					continue;
				}
				RZ_LOG_WARN("INQUIRY: Send IL result: %p.\n", bb);
				rz_pvector_push(il_cache, bb);
				// TODO: Free unused if too big.
				rz_th_queue_push(il_queue, bb, true);
			}
		}

		// This plays the IO handler for a single(!) interpreter instances.
		// In the future we should have only one IO handler for multiple interpreters.
		// But this requires multiple IO write caches
		// (one for each interpreter instance).
		// Because this is not yet implemented, there is only one interpreter thread for now.
		{
			RzInterpreterIORequest *io_req = rz_th_queue_pop(io_request_q, false);
			if (!io_req) {
				continue;
			}

			RZ_LOG_WARN("INQUIRY: Received IO %s request: 0x%" PFMT64x "\n",
				io_req->type == RZ_INTERPRETER_IO_WRITE ? "write" : "read",
				io_req->addr);
			if (io_req->type == RZ_INTERPRETER_IO_READ) {
				if (io_req->n_bytes > MAX_IO_DATA_READ) {
					RZ_LOG_ERROR("Plugin tried to read more than 0x%" PFMT32x " bytes.\n"
						     "This is more than configured. It will only read MAX_IO_DATA_READ bytes.\nPlease set MAX_IO_DATA_READ to a larger value and rebuild Rizin.\n",
						MAX_IO_DATA_READ);
				}
				// Cast to ut8* here. The constant is only there so interpreter plugins don't free it by accident.
				int n_read = rz_io_nread_at(core->io, io_req->addr, (ut8 *)io_res->read.data, io_req->n_bytes > MAX_IO_DATA_READ ? MAX_IO_DATA_READ : io_req->n_bytes);
				io_res->req_ok = n_read >= 0;
				io_res->read.n_bytes = n_read;
			} else {
				io_res->req_ok = rz_io_write_at(core->io, io_req->addr, io_req->data, io_req->n_bytes);
			}
			RZ_LOG_WARN("INQUIRY: Sent IO %s result. Success = %s.\n",
				io_req->type == RZ_INTERPRETER_IO_WRITE ? "write" : "read",
				io_res->req_ok ? "true" : "false");
			rz_th_queue_push(io_result_q, io_res, true);
		}

		// This part plays the role of a yield consumer.
		// In our prototype it inly receives xrefs and stores them in RzAnalysis.
		{
			RzThreadQueue *q = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_XREF, false);
			RzAnalysisXRef *xref = rz_th_queue_pop(q, false);
			if (!xref) {
				continue;
			}
			// TODO: Currently we can't classify calls as such.
			rz_analysis_xrefs_set(core->analysis, xref->from, xref->to, xref->type);
		}
	}
	RZ_LOG_WARN("INQUIRY: Done\n");

	rz_config_set(core->config, "io.cache", io_cache_opt);

	// Wait for thread to finish before cleaning.
	rz_th_wait(interpr_th);
	rz_th_free(interpr_th);

error_free:
	if (!iset) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_th_queue_free(io_request_q);
		rz_th_queue_free(io_result_q);
		// yield_queues frees each individual queue as well.
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running);
		rz_interpreter_abstr_state_free(abstr_state);
		rz_vector_free(entry_points);
	} else {
		// Ownership was passed to iset
		rz_interpreter_set_free(iset);
	}
	rz_pvector_free(il_cache);

	return return_code;
}
