// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

static void process_objc_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	if (!symbol->classname) {
		char *dot = strchr(symbol->dname, '.');
		if (!dot) {
			return;
		} else if (IS_UPPER(symbol->name[0])) {
			symbol->classname = rz_str_ndup(symbol->name, dot - symbol->name);
		} else if (IS_UPPER(dot[1])) {
			dot++;
			char *next_dot = strchr(dot, '.');
			symbol->classname = next_dot ? rz_str_ndup(dot, next_dot - dot) : NULL;
		}
	}

	if (symbol->classname) {
		rz_bin_object_add_class(o, symbol->classname, NULL, UT64_MAX);
	}
}

static void process_rust_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	if (!symbol->type) {
		return;
	}
	bool is_method = !strcmp(symbol->type, RZ_BIN_TYPE_FUNC_STR) ||
		!strcmp(symbol->type, RZ_BIN_TYPE_IFACE_STR) ||
		!strcmp(symbol->type, RZ_BIN_TYPE_METH_STR);
	rz_bin_process_rust(o, symbol->dname, symbol->paddr, symbol->vaddr, is_method);
}

static void process_cxx_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	rz_bin_process_cxx(o, symbol->dname, symbol->paddr, symbol->vaddr);
}

#if WITH_SWIFT_DEMANGLER
// this process function does not work with the Apple demangler.
static void process_swift_symbol(RzBinObject *o, RzBinSymbol *symbol) {
	rz_bin_process_swift(o, symbol->classname, symbol->dname, symbol->paddr, symbol->vaddr);
}
#endif

RZ_IPI RzBinProcessLanguage rz_bin_process_language_symbol(RzBinObject *o) {
	switch (o->lang) {
	case RZ_BIN_LANGUAGE_RUST:
		return (RzBinProcessLanguage)process_rust_symbol;
	case RZ_BIN_LANGUAGE_CXX:
		return (RzBinProcessLanguage)process_cxx_symbol;
	case RZ_BIN_LANGUAGE_OBJC:
		return (RzBinProcessLanguage)process_objc_symbol;
#if WITH_SWIFT_DEMANGLER
	// this process function does not work with the Apple demangler.
	case RZ_BIN_LANGUAGE_SWIFT:
		return (RzBinProcessLanguage)process_swift_symbol;
#endif
	default:
		return NULL;
	}
}

static void process_handle_symbol(RzBinSymbol *symbol, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags, RzBinProcessLanguage language_cb) {
	// rebase physical address
	symbol->paddr += o->opts.loadaddr;

	if (!symbol->name) {
		return;
	}

	// add symbol to the 'import' map[name]symbol
	if (symbol->is_imported && RZ_STR_ISNOTEMPTY(symbol->name)) {
		if (!ht_sp_find(o->import_name_symbols, symbol->name, NULL)) {
			ht_sp_insert(o->import_name_symbols, symbol->name, symbol);
		}
	}

	// demangle the symbol
	if (!rz_bin_demangle_symbol(symbol, demangler, flags, false) ||
		!language_cb) {
		return;
	}

	// handle the demangled string at language
	// level; this can allow to add also classes
	// methods and fields.
	language_cb(o, symbol);
}

RZ_IPI void rz_bin_process_symbols(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags) {
	if (rz_pvector_len(o->symbols) < 1) {
		return;
	}

	ht_sp_free(o->import_name_symbols);
	o->import_name_symbols = ht_sp_new(HT_STR_DUP, NULL, NULL);

	RzBinProcessLanguage language_cb = rz_bin_process_language_symbol(o);

	void **it;
	RzBinSymbol *element;
	rz_pvector_foreach (o->symbols, it) {
		element = *it;
		process_handle_symbol(element, o, demangler, flags, language_cb);
	}
}

RZ_IPI void rz_bin_set_symbols_from_plugin(RzBinFile *bf, RzBinObject *o) {
	RzBinPlugin *plugin = o->plugin;

	rz_pvector_free(o->symbols);
	if (!plugin->symbols || !(o->symbols = plugin->symbols(bf))) {
		o->symbols = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	}
}

RZ_IPI void rz_bin_demangle_symbols_with_flags(RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags) {
	void **it;
	RzBinSymbol *element;
	rz_pvector_foreach (o->symbols, it) {
		element = *it;
		rz_bin_demangle_symbol(element, demangler, flags, true);
	}
}
