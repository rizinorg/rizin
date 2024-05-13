// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

static void process_handle_reloc(RzBinReloc *reloc,
	RzBinObject *o,
	const RzDemanglerPlugin *demangler,
	RzDemanglerFlag flags,
	RzBinProcessLanguage imp_cb,
	RzBinProcessLanguage sym_cb) {
	// rebase physical address
	reloc->paddr += o->opts.loadaddr;

	if (!demangler) {
		return;
	}

	if (reloc->import && rz_bin_demangle_import(reloc->import, demangler, flags, false) && imp_cb) {
		imp_cb(o, reloc->import);
	}

	if (reloc->symbol && rz_bin_demangle_symbol(reloc->symbol, demangler, flags, false) && sym_cb) {
		sym_cb(o, reloc->symbol);
	}
}

RZ_IPI void rz_bin_set_and_process_relocs(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;
	RzPVector *relocs = NULL;

	rz_bin_reloc_storage_free(o->relocs);
	if (!(bin->filter_rules & (RZ_BIN_REQ_RELOCS | RZ_BIN_REQ_IMPORTS)) ||
		!plugin->relocs || !(relocs = plugin->relocs(bf))) {
		relocs = rz_pvector_new((RzListFree)rz_bin_reloc_free);
	}

	RzBinProcessLanguage imp_cb = rz_bin_process_language_import(o);
	RzBinProcessLanguage sym_cb = rz_bin_process_language_symbol(o);

	void **it;
	RzBinReloc *element;
	rz_pvector_foreach (relocs, it) {
		element = *it;
		process_handle_reloc(element, o, demangler, flags, imp_cb, sym_cb);
	}

	o->relocs = rz_bin_reloc_storage_new(relocs, plugin);
}

RZ_IPI void rz_bin_demangle_relocs_with_flags(RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags) {
	for (size_t i = 0; i < o->relocs->relocs_count; ++i) {
		RzBinReloc *reloc = o->relocs->relocs[i];
		if (reloc->import) {
			rz_bin_demangle_import(reloc->import, demangler, flags, true);
		}
		if (reloc->symbol) {
			rz_bin_demangle_symbol(reloc->symbol, demangler, flags, true);
		}
	}
}
