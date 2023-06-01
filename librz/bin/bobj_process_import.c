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

	rz_list_free(o->imports);
	if (!plugin->imports || !(o->imports = plugin->imports(bf))) {
		o->imports = rz_list_newf((RzListFree)rz_bin_import_free);
	}
	rz_warn_if_fail(o->imports->free);
}

RZ_IPI void rz_bin_process_imports(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler) {
	if (!demangler || rz_list_length(o->imports) < 1) {
		return;
	}

	RzBinProcessLanguage language_cb = rz_bin_process_language_import(o);

	RzListIter *it;
	RzBinImport *element;
	rz_list_foreach (o->imports, it, element) {
		// demangle the import
		if (!rz_bin_demangle_import(element, demangler) ||
			!language_cb) {
			continue;
		}

		// handle the demangled string at language
		// level; this can allow to add also classes
		// methods and fields.
		language_cb(o, element);
	}
}
