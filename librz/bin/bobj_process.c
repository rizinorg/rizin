// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_th.h>
#include "i/private.h"

typedef void (*ProcessLanguage)(RzBinObject *o, const void *user);

static const RzDemanglerPlugin *process_get_demangler_plugin_from_lang(RzBinFile *bf, RzBinLanguage language) {
	language = RZ_BIN_LANGUAGE_MASK(language);
	const char *lang_s = rz_bin_language_to_string(language);
	if (!lang_s) {
		return NULL;
	}
	return rz_demangler_plugin_get(bf->rbin->demangler, lang_s);
}

static void process_rust(RzBinObject *o, char *demangled, ut64 paddr, ut64 vaddr, bool is_method) {
	// find where to split symbol.
	char *str = demangled;
	char *ptr = NULL;
	char *name = NULL;
	while ((ptr = strstr(str, "::"))) {
		name = ptr;
		str = ptr + 2;
	}

	if (!name || RZ_STR_ISEMPTY(name + 2)) {
		return;
	}

	*name = 0;
	if (is_method) {
		rz_bin_object_add_method(o, demangled, name + 2, paddr, vaddr);
	} else {
		rz_bin_object_add_field(o, demangled, name + 2, paddr, vaddr);
	}
	*name = ':';
}

static void process_cxx(RzBinObject *o, char *demangled, ut64 paddr, ut64 vaddr) {
	if (strstr(demangled, " for ") || strstr(demangled, " to ")) {
		/* these symbols are not fields nor methods. */
		return;
	}

	bool is_method = true;
	const char *limit = strchr(demangled, '(');
	if (!limit) {
		limit = demangled + (strlen(demangled) - 1);
		is_method = false;
	}

	// find where to split symbol.
	char *str = demangled;
	char *ptr = NULL;
	char *name = NULL;
	while ((ptr = strstr(str, "::"))) {
		if (ptr > limit) {
			break;
		}
		name = ptr;
		str = ptr + 2;
	}

	if (!name || RZ_STR_ISEMPTY(name + 2)) {
		return;
	}

	*name = 0;
	if (is_method) {
		rz_bin_object_add_method(o, demangled, name + 2, paddr, vaddr);
	} else {
		rz_bin_object_add_field(o, demangled, name + 2, paddr, vaddr);
	}
	*name = ':';
}

#if WITH_SWIFT_DEMANGLER
// this process function does not work with the Apple demangler.
static char *get_swift_field(const char *demangled, const char *classname) {
	if (!demangled || !classname) {
		return NULL;
	}

	char *p = strstr(demangled, ".getter_");
	if (!p) {
		p = strstr(demangled, ".setter_");
		if (!p) {
			p = strstr(demangled, ".method_");
		}
	}
	if (p) {
		char *q = strstr(demangled, classname);
		if (q && q[strlen(classname)] == '.') {
			q = strdup(q + strlen(classname) + 1);
			char *r = strchr(q, '.');
			if (r) {
				*r = 0;
			}
			return q;
		}
	}
	return NULL;
}

static void process_swift(RzBinObject *o, char *classname, char *demangled, ut64 paddr, ut64 vaddr) {
	if (!classname) {
		return;
	}

	char *name = get_swift_field(demangled, classname);
	if (name) {
		rz_bin_object_add_field(o, classname, name, paddr, vaddr);
		free(name);
		return;
	}

#if 0
	// TODO: this code looks very wrong.
	// this was copied from the original one and just refactored.
	name = strstr(demangled, "..");
	if (!name) {
		name = strstr(demangled, classname);
	}
	if (name && name[strlen(classname)] == '.') {
		rz_bin_object_add_method(o, classname, name, paddr, vaddr);
	}
#endif
}
#endif /* WITH_SWIFT_DEMANGLER */

#include "bobj_process_class.c"
#include "bobj_process_entry.c"
#include "bobj_process_field.c"
#include "bobj_process_file.c"
#include "bobj_process_import.c"
#include "bobj_process_map.c"
#include "bobj_process_section.c"
#include "bobj_process_string.c"
#include "bobj_process_symbol.c"
#include "bobj_process_reloc.c"

RZ_IPI bool rz_bin_object_process_plugin_data(RzBinFile *bf, RzBinObject *o) {
	rz_return_val_if_fail(bf && bf->rbin && o && o->plugin, false);

	set_and_process_file(bf, o);
	set_and_process_entries(bf, o);
	set_and_process_maps(bf, o);
	set_imports(bf, o);
	set_symbols(bf, o);
	set_and_process_sections(bf, o);
	set_and_process_strings(bf, o);
	set_and_process_fields(bf, o);
	set_and_process_classes(bf, o);

	// we need to detect the language of the binary
	// one way can be based on the compiler.
	if (o->info && RZ_STR_ISEMPTY(o->info->compiler)) {
		free(o->info->compiler);
		o->info->compiler = rz_bin_file_golang_compiler(bf);
		if (o->info->compiler) {
			o->info->lang = "go";
			o->lang = RZ_BIN_LANGUAGE_GO;
		}
	}

	// or based on the fetched data in the RzBinFile
	if (RZ_BIN_LANGUAGE_MASK(o->lang) == RZ_BIN_LANGUAGE_UNKNOWN) {
		o->lang = rz_bin_language_detect(bf);
	}

	// now we can process the data.
	const RzDemanglerPlugin *plugin = process_get_demangler_plugin_from_lang(bf, o->lang);
	process_imports(bf, o, plugin);
	process_symbols(bf, o, plugin);
	set_and_process_relocs(bf, o, plugin);

	return true;
}
