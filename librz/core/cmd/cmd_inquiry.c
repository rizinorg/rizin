// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_vector.h>
#include <rz_th.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_util/rz_assert.h>

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
	RzVector *entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!entry_points) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 entry_point;
	if (argc == 1) {
		// No specific entry point given. Pick the one provided by the bin plugin.
		entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		rz_vector_push(entry_points, &entry_point);
	} else {
		// Add all entry points given as arguments.
		for (size_t i = 1; i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			rz_vector_push(entry_points, &entry_point);
		}
	}
	RzVector *ignored_code_regions = get_ignored_code_regions(
		rz_bin_object_get_symbols(core->bin->cur->o),
		rz_bin_object_get_sections(core->bin->cur->o),
		rz_io_maps(core->io));
	bool success = rz_inquiry_interpreter(core, entry_points, ignored_code_regions);
	eprintf("Finished reference recovery: %s\n", success ? "OK" : "FAIL");
	if (!success) {
		return RZ_CMD_STATUS_ERROR;
	}
	eprintf("Perform function deduction: ");

	RzSetU *symbol_addresses = rz_set_u_new();
	if (!rz_inquiry_get_fcn_symbol_addr(core, symbol_addresses)) {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	const RzPVector *symbols = rz_bin_object_get_symbols(core->bin->cur->o);
	success = rz_inquiry_function_deduction(core->analysis, core->inquiry, symbol_addresses, symbols, ignored_code_regions);
	eprintf("%s\n", success ? "OK" : "FAIL");
	rz_set_u_free(symbol_addresses);
	rz_vector_free(ignored_code_regions);

	return success ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
