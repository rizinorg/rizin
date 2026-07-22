// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_set.h"
#include <rz_io.h>
#include <rz_vector.h>
#include <rz_th.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_absint.h>
#include <rz_util/rz_assert.h>

static RzAbsIntTraceOptions absint_trace_opts(RzCore *core) {
	RzSetS *trace_opts_s = rz_config_get_set(core->config, "inquiry.trace");
	RzAbsIntTraceOptions r = RZ_ABSINT_TRACE_NONE;
	if (!trace_opts_s) {
		return r;
	}
	if (rz_set_s_contains(trace_opts_s, "ilblock")) {
		r |= RZ_ABSINT_TRACE_IL_BLOCK;
	}
	if (rz_set_s_contains(trace_opts_s, "evalblock")) {
		r |= RZ_ABSINT_TRACE_EVAL_BLOCK;
	}
	rz_set_s_free(trace_opts_s);
	return r;
}

static bool core_absint_run(RzCore *core) {
	RzAbsIntResultDimen dimens = RZ_ABSINT_RESULT_DIMEN_XREFS;
	if (rz_config_get_bool(core->config, "inquiry.comment")) {
		dimens |= RZ_ABSINT_RESULT_DIMEN_COMMENTS;
	}
	RzSetU *entry_points = rz_set_u_new();
	if (!entry_points) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_set_u_add(entry_points, core->offset);
	bool success = rz_absint_driver_run(core->analysis, core->io, entry_points, dimens, absint_trace_opts(core));
	rz_set_u_free(entry_points);
	if (!success) {
		RZ_LOG_ERROR("Analysis failed.\n");
	}
	return success;
}

RZ_IPI RzCmdStatus rz_inquiry_analyze_function_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core->analysis && core->io && core->bin->cur && core->bin->cur->o, RZ_CMD_STATUS_ERROR);
	return core_absint_run(core) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzVector /*<RzInterval>*/ *get_ignored_code_regions(
	const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RzPVector /*<RzBinSection *>*/ *sections,
	const RzPVector /*<RzIOMap *>*/ *io_maps) {
	void **it;
	RzVector *v = rz_vector_new(sizeof(RzInterval), NULL, NULL);
	rz_pvector_foreach (sections, it) {
		RzBinSection *sec = *it;
		if (sec->layout.role == RZ_BIN_SECTION_ROLE_LINKING || !(sec->perm & RZ_PERM_X)) {
			RzInterval itv = { .addr = sec->vaddr, .size = sec->vsize };
			rz_vector_push(v, &itv);
		}
	}
	rz_pvector_free(sections);

	rz_pvector_foreach (io_maps, it) {
		RzIOMap *map = *it;
		if (!(map->perm & RZ_PERM_X)) {
			RzInterval itv = { .addr = map->itv.addr, .size = map->itv.size };
			rz_vector_push(v, &itv);
		}
	}

	rz_pvector_foreach (symbols, it) {
		RzBinSymbol *sym = *it;
		if (sym->is_imported) {
			RzInterval itv = { .addr = sym->vaddr, .size = sym->size };
			rz_vector_push(v, &itv);
		}
	}
	return v;
}

RZ_IPI RzCmdStatus rz_inquiry_interpreter_prototype_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core->analysis && core->io && core->bin->cur && core->bin->cur->o, RZ_CMD_STATUS_ERROR);
	RzSetU *entry_points = rz_set_u_new();
	if (!entry_points) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool run_fcn_detection = RZ_STR_EQ(argv[1], "-f");

	ut64 entry_point;
	if (argc == (run_fcn_detection ? 2 : 1)) {
		// No specific entry point given. Pick the one provided by the bin plugin.
		entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		rz_set_u_add(entry_points, entry_point);
	} else {
		// Add all entry points given as arguments.
		for (size_t i = (run_fcn_detection ? 2 : 1); i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			rz_set_u_add(entry_points, entry_point);
		}
	}
	bool success = rz_absint_driver_run(core->analysis, core->io, entry_points, RZ_ABSINT_RESULT_DIMEN_XREFS, RZ_ABSINT_TRACE_NONE);
	rz_set_u_free(entry_points);
	eprintf("Finished reference recovery: %s\n", success ? "OK" : "FAIL");
	if (!success) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzSetU *symbol_addresses = rz_set_u_new();
	if (!symbol_addresses || !rz_inquiry_get_fcn_symbol_addr(core, symbol_addresses)) {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	const RzPVector *symbols = rz_bin_object_get_symbols(core->bin->cur->o);
	RzPVector *fcns = rz_pvector_new((RzPVectorFree)rz_inquiry_function_free);

	if (!fcns || !symbols) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (run_fcn_detection) {
		RzVector *ignored_code_regions = get_ignored_code_regions(
			rz_bin_object_get_symbols(core->bin->cur->o),
			rz_bin_object_get_sections(core->bin->cur->o),
			rz_io_maps(core->io));
		eprintf("Perform function deduction: ");
		success &= rz_inquiry_function_deduction(core->analysis, core->inquiry, symbol_addresses, symbols, ignored_code_regions, fcns);
		rz_vector_free(ignored_code_regions);
		eprintf("%s\n", success ? "OK" : "FAIL");
	}
	rz_set_u_free(symbol_addresses);

	success &= rz_inquiry_convert_and_add_to_analysis(core->analysis, core->inquiry, fcns, symbols);
	rz_pvector_free(fcns);

	return success ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
