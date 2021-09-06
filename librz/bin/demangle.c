// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "i/private.h"
#include <cxx/demangle.h>

RZ_API void rz_bin_demangle_list(RzBin *bin) {
	const char *langs[] = { "c++", "java", "objc", "swift", "dlang", "msvc", "rust", NULL };
	RzBinPlugin *plugin;
	RzListIter *it;
	int i;
	if (!bin) {
		return;
	}
	for (i = 0; langs[i]; i++) {
		bin->cb_printf("%s\n", langs[i]);
	}
	rz_list_foreach (bin->plugins, it, plugin) {
		if (plugin->demangle) {
			bin->cb_printf("%s\n", plugin->name);
		}
	}
}

RZ_API char *rz_bin_demangle_plugin(RzBin *bin, const char *name, const char *str) {
	RzBinPlugin *plugin;
	RzListIter *it;
	if (bin && name && str) {
		rz_list_foreach (bin->plugins, it, plugin) {
			if (plugin->demangle && !strncmp(plugin->name, name, strlen(plugin->name))) {
				return plugin->demangle(str);
			}
		}
	}
	return NULL;
}

RZ_API int rz_bin_demangle_type(const char *str) {
	if (str && *str) {
		if (!strcmp(str, "swift")) {
			return RZ_BIN_NM_SWIFT;
		}
		if (!strcmp(str, "java")) {
			return RZ_BIN_NM_JAVA;
		}
		if (!strcmp(str, "objc")) {
			return RZ_BIN_NM_OBJC;
		}
		if (!strcmp(str, "cxx") || !strcmp(str, "c++")) {
			return RZ_BIN_NM_CXX;
		}
		if (!strcmp(str, "dlang")) {
			return RZ_BIN_NM_DLANG;
		}
		if (!strcmp(str, "msvc")) {
			return RZ_BIN_NM_MSVC;
		}
		if (!strcmp(str, "rust")) {
			return RZ_BIN_NM_RUST;
		}
	}
	return RZ_BIN_NM_NONE;
}

RZ_API char *rz_bin_demangle(RzBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs) {
	int type = -1;
	if (!str || !*str) {
		return NULL;
	}
	RzBin *bin = bf ? bf->rbin : NULL;
	RzBinObject *o = bf ? bf->o : NULL;
	RzListIter *iter;
	const char *lib = NULL;
	if (!strncmp(str, "reloc.", 6)) {
		str += 6;
	}
	if (!strncmp(str, "sym.", 4)) {
		str += 4;
	}
	if (!strncmp(str, "imp.", 4)) {
		str += 4;
	}
	if (o) {
		bool found = false;
		rz_list_foreach (o->libs, iter, lib) {
			size_t len = strlen(lib);
			if (!rz_str_ncasecmp(str, lib, len)) {
				str += len;
				if (*str == '_') {
					str++;
				}
				found = true;
				break;
			}
		}
		if (!found) {
			lib = NULL;
		}
		size_t len = strlen(bin->file);
		if (!rz_str_ncasecmp(str, bin->file, len)) {
			lib = bin->file;
			str += len;
			if (*str == '_') {
				str++;
			}
		}
	}
	if (!strncmp(str, "__", 2)) {
		if (str[2] == 'T') {
			type = RZ_BIN_NM_SWIFT;
		} else {
			type = RZ_BIN_NM_CXX;
			//	str++;
		}
	}
	// if str is sym. or imp. when str+=4 str points to the end so just return
	if (!*str) {
		return NULL;
	}
	if (type == -1) {
		type = rz_bin_lang_type(bf, def, str);
	}
	char *demangled = NULL;
	switch (type) {
	case RZ_BIN_NM_JAVA: demangled = rz_bin_demangle_java(str); break;
	case RZ_BIN_NM_RUST: demangled = rz_bin_demangle_rust(bf, str, vaddr); break;
	case RZ_BIN_NM_OBJC: demangled = rz_bin_demangle_objc(NULL, str); break;
	case RZ_BIN_NM_SWIFT: demangled = rz_bin_demangle_swift(str, bin ? bin->demanglercmd : false); break;
	case RZ_BIN_NM_CXX: demangled = rz_bin_demangle_cxx(bf, str, vaddr); break;
	case RZ_BIN_NM_MSVC: demangled = rz_bin_demangle_msvc(str); break;
	case RZ_BIN_NM_DLANG: demangled = rz_bin_demangle_plugin(bin, "dlang", str); break;
	}
	if (libs && demangled && lib) {
		char *d = rz_str_newf("%s_%s", lib, demangled);
		free(demangled);
		demangled = d;
	}
	return demangled;
}
