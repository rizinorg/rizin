// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "i/private.h"

RZ_IPI const RzDemanglerPlugin *rz_bin_process_get_demangler_plugin_from_lang(RzBin *bin, RzBinLanguage language) {
	language = RZ_BIN_LANGUAGE_MASK(language);
	const char *lang_s = rz_bin_language_to_string(language);
	if (!lang_s) {
		return NULL;
	}
	return rz_demangler_plugin_get(bin->demangler, lang_s);
}

RZ_IPI void rz_bin_process_rust(RzBinObject *o, char *demangled, ut64 paddr, ut64 vaddr, bool is_method) {
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

static char *find_cxx_name(char *start, const char *end) {
	char *kname = NULL;
	unsigned int tmpl = 0;
	while (start < end) {
		if (tmpl > 0) {
			if (start[0] == '<') {
				tmpl++;
			} else if (start[0] == '>') {
				tmpl--;
			}
		} else {
			if (start[0] == '<') {
				tmpl++;
			} else if (start[0] == ':' && start[1] == ':') {
				kname = start;
			}
		}
		start++;
	}
	return kname;
}

RZ_IPI void rz_bin_process_cxx(RzBinObject *o, char *demangled, ut64 paddr, ut64 vaddr) {
	if (strstr(demangled, " for ") ||
		strstr(demangled, " to ")) {
		/* these symbols are not fields nor methods. */
		return;
	}
	bool is_method = true;
	const char *limit = NULL;
	if (rz_str_startswith(demangled, "(anonymous namespace)::")) {
		limit = strchr(demangled + strlen("(anonymous namespace)::"), '(');
	} else {
		limit = strchr(demangled, '(');
	}
	if (!limit) {
		limit = demangled + (strlen(demangled) - 1);
		is_method = false;
	}

	// find where to split symbol.
	char *name = find_cxx_name(demangled, limit);
	if (!name || RZ_STR_ISEMPTY(name + 2)) {
		// eprintf("bad '%s' '%s'\n", demangled, name);
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

RZ_IPI void rz_bin_process_swift(RzBinObject *o, char *classname, char *demangled, ut64 paddr, ut64 vaddr) {
	if (!classname) {
		return;
	}

	char *name = get_swift_field(demangled, classname);
	if (name) {
		rz_bin_object_add_field(o, classname, name, paddr, vaddr);
		free(name);
		return;
	}
}
#endif /* WITH_SWIFT_DEMANGLER */

/**
 * \brief      Reset and initialize the data of the given RzBinObject using the defined RzBinPlugin
 *
 * \param      bf    The RzBinFile to use
 * \param      o     The RzBinObject to initialize
 *
 * \return     On success returns true
 */
RZ_API bool rz_bin_object_process_plugin_data(RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzBinObject *o) {
	rz_return_val_if_fail(bf && bf->rbin && o && o->plugin, false);
	const RzDemanglerPlugin *demangler = NULL;

	rz_bin_set_and_process_file(bf, o);
	rz_bin_set_and_process_entries(bf, o);
	rz_bin_set_and_process_maps(bf, o);
	rz_bin_set_imports_from_plugin(bf, o);
	rz_bin_set_symbols_from_plugin(bf, o);
	rz_bin_set_and_process_sections(bf, o);
	rz_bin_set_and_process_strings(bf, o);
	rz_bin_set_and_process_fields(bf, o);
	rz_bin_set_and_process_classes(bf, o);

	// we need to detect the language of the binary
	// one way can be based on the compiler.
	if (o->info) {
		char *go_compiler = rz_bin_file_golang_compiler(bf);
		if (go_compiler) {
			o->info->lang = "go";
			o->lang = RZ_BIN_LANGUAGE_GO;
			if (RZ_STR_ISNOTEMPTY(o->info->compiler)) {
				char *merge = rz_str_newf("%s %s", go_compiler, o->info->compiler);
				free(o->info->compiler);
				free(go_compiler);
				o->info->compiler = merge;
			} else {
				free(o->info->compiler);
				o->info->compiler = go_compiler;
			}
		}
	}

	// or based on the fetched data in the RzBinFile
	if (RZ_BIN_LANGUAGE_MASK(o->lang) == RZ_BIN_LANGUAGE_UNKNOWN) {
		o->lang = rz_bin_language_detect(bf);
	}

	// now we can process the data.
	RzDemanglerFlag flags = rz_demangler_get_flags(bf->rbin->demangler);
	if (bf->rbin->demangle) {
		demangler = rz_bin_process_get_demangler_plugin_from_lang(bf->rbin, o->lang);
	}
	rz_bin_process_symbols(bf, o, demangler, flags);
	rz_bin_process_imports(bf, o, demangler, flags);
	rz_bin_set_and_process_relocs(bf, o, demangler, flags);

	return true;
}

/**
 * \brief Remove all previously identified strings in the binary object and scan it again for strings.
 */
RZ_API bool rz_bin_object_reset_strings(RZ_NONNULL RzBin *bin, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzBinObject *obj) {
	rz_return_val_if_fail(bin && bf && obj, false);
	rz_bin_set_and_process_strings(bf, obj);
	return obj->strings != NULL;
}

/**
 * \brief      If the given flags differs from the one already set, then re-demangles all the symbols.
 *
 * \param      bin    The RzBin context to used for demangling
 * \param[in]  flags  The demangler flags to apply
 */
RZ_API void rz_bin_demangle_with_flags(RZ_NONNULL RzBin *bin, RzDemanglerFlag flags) {
	rz_return_if_fail(bin && bin->binfiles);

	RzDemanglerFlag f = rz_demangler_get_flags(bin->demangler);
	if ((f & flags) == flags) {
		return;
	}
	rz_demangler_set_flags(bin->demangler, flags);

	if (!bin->demangle) {
		return;
	}

	RzBinFile *bf = NULL;
	RzListIter *it = NULL;
	// reload each bins and demangle properly
	rz_list_foreach (bin->binfiles, it, bf) {
		if (!bf || !bf->o) {
			continue;
		}
		RzBinObject *o = bf->o;
		const RzDemanglerPlugin *demangler = rz_bin_process_get_demangler_plugin_from_lang(bin, o->lang);
		rz_bin_demangle_relocs_with_flags(o, demangler, flags);
		rz_bin_demangle_imports_with_flags(o, demangler, flags);
		rz_bin_demangle_symbols_with_flags(o, demangler, flags);
	}
}
