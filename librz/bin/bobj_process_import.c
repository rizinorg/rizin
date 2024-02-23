// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

static void process_rust_import(RzBinObject *o, RzBinImport *import) {
	if (!import->type) {
		return;
	}
	bool is_method = !strcmp(import->type, RZ_BIN_TYPE_FUNC_STR) ||
		!strcmp(import->type, RZ_BIN_TYPE_IFACE_STR) ||
		!strcmp(import->type, RZ_BIN_TYPE_METH_STR);
	rz_bin_process_rust(o, import->dname, UT64_MAX, UT64_MAX, is_method);
}

static void process_cxx_import(RzBinObject *o, RzBinImport *import) {
	rz_bin_process_cxx(o, import->dname, UT64_MAX, UT64_MAX);
}

RZ_IPI RzBinProcessLanguage rz_bin_process_language_import(RzBinObject *o) {
	switch (o->lang) {
	case RZ_BIN_LANGUAGE_RUST:
		return (RzBinProcessLanguage)process_rust_import;
	case RZ_BIN_LANGUAGE_CXX:
		return (RzBinProcessLanguage)process_cxx_import;
	default:
		return NULL;
	}
}

RZ_IPI void rz_bin_set_imports_from_plugin(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_pvector_free(o->imports);
	if (!plugin->imports || !(o->imports = plugin->imports(bf))) {
		o->imports = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	}
}

RZ_IPI void rz_bin_process_imports(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags) {
	if (!demangler || rz_pvector_len(o->imports) < 1) {
		return;
	}

	RzBinProcessLanguage language_cb = rz_bin_process_language_import(o);

	void **it;
	RzBinImport *element;
	rz_pvector_foreach (o->imports, it) {
		element = *it;
		if (!element->name) {
			continue;
		}

		// demangle the import
		if (!rz_bin_demangle_import(element, demangler, flags, false) ||
			!language_cb) {
			continue;
		}

		// handle the demangled string at language
		// level; this can allow to add also classes
		// methods and fields.
		language_cb(o, element);
	}
}

RZ_IPI void rz_bin_demangle_imports_with_flags(RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags) {
	void **it;
	RzBinImport *element;
	rz_pvector_foreach (o->imports, it) {
		element = *it;
		if (!element->name) {
			continue;
		}

		rz_bin_demangle_import(element, demangler, flags, true);
	}
}
