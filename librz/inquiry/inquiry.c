// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_analysis.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_inquiry_plugins.h"
#include "rz_reg.h"
#include "rz_vector.h"
#include <rz_list.h>
#include <rz_types_base.h>
#include <rz_util/rz_assert.h>

RZ_LIB_VERSION(rz_inquiry);

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

RZ_API bool rz_inquiry_xref_interpreter_filter(const RzAnalysisXRef *xref, const RzList /*<RzIOMap *>*/ *allowed_io_maps) {
	rz_return_val_if_fail(xref && allowed_io_maps, false);
	const RzIOMap *map;
	RzListIter *it;
	rz_list_foreach (allowed_io_maps, it, map) {
		ut64 start = map->itv.addr;
		ut64 end = map->itv.addr + map->itv.size;
		if (RZ_BETWEEN(start, xref->to, end)) {
			return true;
		}
	}
	return false;
}

static ut64 get_nop_pc_increment(RzAnalysis *analysis) {
	if (RZ_STR_EQ(analysis->cur->arch, "hexagon")) {
		// Hexagon has variable instruction lengths.
		// It manages the JUMPs to the next packets on its own.
		// So it always has a JUMP effect at the end of the effect.
		return 0;
	}
	return analysis->cur->bits / 8;
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
	// The pseudo cache of IL effects.
	// This is only a vector so we can simulate the ownership separation
	// of the pointers.
	RzPVector *il_cache = rz_pvector_new((RzPVectorFree)rz_il_op_effect_free);
	// The queue to pass the Effects to the interpreter.
	// This is only one queue for the prototype.
	// In practice it would be one for each interpreter.
	RzThreadQueue *il_queue = rz_th_queue_new(RZ_INTERPRETER_IL_QUEUE_SIZE, NULL);
	if (!il_queue) {
		return false;
	}

	// Add the Effect for each entry point.
	RzILOpEffect *eff = NULL;
	if (argc == 1) {
		ut64 entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
		if (!eff) {
			rz_th_queue_free(il_queue);
			RZ_LOG_WARN("Could not get entry point IL operation at 0x%" PFMT64x "\n", (ut64)entry_point);
			return false;
		}
		rz_th_queue_push(il_queue, eff, true);
		rz_pvector_push(il_cache, eff);
	} else {
		// Add all entry points given as arguments.
		for (size_t i = 1; i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
			if (!eff) {
				rz_th_queue_free(il_queue);
				return false;
			}
		}
		rz_th_queue_push(il_queue, eff, true);
		rz_pvector_push(il_cache, eff);
	}

	// The address queue. It is the queue the interpreter can request new Effects.
	// Of course, currently there is only a single one for the prototype.
	// In practice there would be one for each interpreter instance.
	RzThreadQueue *addr_queue = rz_th_queue_new(RZ_INTERPRETER_ADDR_QUEUE_SIZE, (RzListFree)rz_interpreter_addr_queue_free);
	if (!addr_queue) {
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		return false;
	}

	// Here we build the filter for the yield queue.
	// The prototype generates constant xrefs.
	// So the filter checks the generated xrefs, if they are within the IO map
	// boundaries.
	RzInterval iv = { .addr = 0, .size = UT64_MAX };
	RzList *boundaries = rz_io_get_boundaries_all_io_maps(core->io, iv);
	if (!boundaries) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		return false;
	}

	// Now create a set of yield queue(s).
	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	RzInterpreterYieldQueue *yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		(RzInterpreterYieldFilter *)rz_inquiry_xref_interpreter_filter,
		boundaries);
	if (!yield_queue) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		return false;
	}

	// Multiple yield queues can be used by a single interpreter.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	HtUP *yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queue || !yield_queues) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		rz_interpreter_yield_queue_free(yield_queue);
		ht_up_free(yield_queues);
		return false;
	}
	ht_up_insert(yield_queues, yield_kind, yield_queue);
	// Create the running flag.
	RzAtomicBool *is_running = rz_atomic_bool_new(true);

	// Initialize the abstract state with the architecture's registers.
	RzPVector *reg_names = get_reg_names(core->analysis);
	ut64 nop_pc_increment = get_nop_pc_increment(core->analysis);
	RzInterpreterAbstrState *abstr_state = rz_interpreter_abstr_state_new(RZ_INTERPRETER_ABSTRACTION_CONST, reg_names, nop_pc_increment);
	rz_pvector_free(reg_names);

	// Bundle all the queues into one object to pass it to the thread.
	// Later we would pass a unique iset to each interpreter with
	// the required queues only.
	// But for the prototype we have only one iset with all queues.
	RzInterpreterSet *iset = rz_interpreter_set_new(rz_inquiry_plugin_interpreter_prototype.p_interpreter, abstr_state, addr_queue, il_queue, yield_queues, is_running);
	if (!iset) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		rz_interpreter_yield_queue_free(yield_queue);
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running);
		return false;
	}

	// Dispatch prototype interpreter into a thread.
	// This part plays the role of the cache now.
	// Waiting for new Effects to be requested and sending them.
	RZ_LOG_WARN("INQUIRY: Start main interpretation thread.\n");
	RzThread *iterpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, iset);
	RZ_LOG_WARN("INQUIRY: Start IL providing loop.\n");
	while (rz_atomic_bool_get(is_running)) {
		ut64 *addr = rz_th_queue_pop(addr_queue, false);
		if (!addr) {
			// Some artificial lag for testing.
			rz_sys_usleep(rz_num_rand32(1000));
			RZ_LOG_WARN("INQUIRY: Sleep over.\n");
			continue;
		}
		RZ_LOG_WARN("INQUIRY: Received %" PFMT64x ".\n", (*addr));
		RzILOpEffect *bb = rz_inquiry_gen_il_bb(core->analysis, core->io, *addr);
		free(addr);
		if (!bb) {
			// Stop interpreter.
			rz_atomic_bool_set(is_running, false);
			continue;
		}
		RZ_LOG_WARN("INQUIRY: Send %p.\n", bb);
		rz_pvector_push(il_cache, bb);
		rz_th_queue_push(il_queue, bb, true);
	}
	// Wait for thread to finish before cleaning.
	rz_th_wait(iterpr_th);
	rz_th_free(iterpr_th);
	// Empty pseudo-cache.
	rz_pvector_free(il_cache);

	return true;
}
