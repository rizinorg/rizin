// SPDX-FileCopyrightText: 2018-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

typedef struct {
	bool rust;
	bool objc;
	bool dlang;
	bool swift;
	bool cxx;
	bool msvc;
} Langs;

static inline bool check_rust(RzBinSymbol *sym) {
	return sym->name && strstr(sym->name, "_$LT$");
}

static inline bool check_objc(RzBinSymbol *sym) {
	if (sym->name && !strncmp(sym->name, "_OBJC_", 6)) {
		// free (rz_bin_demangle_objc (binfile, sym->name));
		return true;
	}
	return false;
}

static bool check_dlang(RzBinSymbol *sym) {
	if (!strncmp(sym->name, "_D2", 3)) {
		return true;
	}
	if (!strncmp(sym->name, "_D4", 3)) {
		return true;
	}
	return false;
}

static bool check_swift(RzBinSymbol *sym) {
	if (sym->name && strstr(sym->name, "swift_once")) {
		return true;
	}
	return false;
}

static bool check_golang(RzBinSymbol *sym) {
	return !strncmp(sym->name, "go.", 3);
}

static inline bool is_cxx_symbol(const char *name) {
	rz_return_val_if_fail(name, false);
	if (!strncmp(name, "_Z", 2)) {
		return true;
	}
	if (!strncmp(name, "__Z", 3)) {
		return true;
	}
	return false;
}

static bool check_cxx(RzBinSymbol *sym) {
	return is_cxx_symbol(sym->name);
}

static bool check_msvc(RzBinSymbol *sym) {
	return *sym->name == '?';
}

/* This is about 10% of the loading time, optimize if possible */
RZ_API int rz_bin_load_languages(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, RZ_BIN_NM_NONE);
	rz_return_val_if_fail(binfile->o, RZ_BIN_NM_NONE);
	rz_return_val_if_fail(binfile->o->info, RZ_BIN_NM_NONE);
	RzBinObject *o = binfile->o;
	RzBinInfo *info = o->info;
	RzBinSymbol *sym;
	RzListIter *iter, *iter2;
	Langs cantbe = { 0 };
	bool phobosIsChecked = false;
	bool swiftIsChecked = false;
	bool canBeCxx = false;
	bool cxxIsChecked = false;
	bool isMsvc = false;

	char *ft = info->rclass ? info->rclass : "";
	bool unknownType = info->rclass == NULL;
	bool isMacho = strstr(ft, "mach");
	bool isElf = strstr(ft, "elf");
	bool isPe = strstr(ft, "pe");
	bool isBlocks = false;
	bool isObjC = false;

	if (unknownType || !(isMacho || isElf || isPe)) {
		return RZ_BIN_NM_NONE;
	}

	// check in imports . can be slow
	rz_list_foreach (o->imports, iter, sym) {
		const char *name = sym->name;
		if (!strcmp(name, "_NSConcreteGlobalBlock")) {
			isBlocks = true;
		} else if (!strncmp(name, "objc_", 5)) {
			isObjC = true;
			cantbe.objc = true;
		}
	}

	rz_list_foreach (o->symbols, iter, sym) {
		char *lib;
		if (!cantbe.rust) {
			if (check_rust(sym)) {
				info->lang = "rust";
				return RZ_BIN_NM_RUST;
			}
		}
		if (check_golang(sym)) {
			info->lang = "go";
			return RZ_BIN_NM_GO;
		}
		if (!cantbe.swift) {
			bool hasswift = false;
			if (!swiftIsChecked) {
				rz_list_foreach (o->libs, iter2, lib) {
					if (strstr(lib, "swift")) {
						hasswift = true;
						break;
					}
				}
				swiftIsChecked = true;
			}
			if (hasswift || check_swift(sym)) {
				info->lang = "swift";
				return RZ_BIN_NM_SWIFT;
			}
		}
		if (!cantbe.cxx) {
			bool hascxx = false;
			if (!cxxIsChecked) {
				rz_list_foreach (o->libs, iter2, lib) {
					if (strstr(lib, "stdc++") ||
						strstr(lib, "c++")) {
						hascxx = true;
						break;
					}
					if (strstr(lib, "msvcp")) {
						info->lang = "msvc";
						return RZ_BIN_NM_MSVC;
					}
				}
				cxxIsChecked = true;
			}
			if (hascxx || check_cxx(sym)) {
				canBeCxx = true;
				cantbe.cxx = true;
			}
		}
		if (!cantbe.objc) {
			if (check_objc(sym)) {
				info->lang = "objc";
				return RZ_BIN_NM_OBJC;
			}
		}
		if (!cantbe.dlang) {
			bool hasdlang = false;
			if (!phobosIsChecked) {
				rz_list_foreach (o->libs, iter2, lib) {
					if (strstr(lib, "phobos")) {
						hasdlang = true;
						break;
					}
				}
				phobosIsChecked = true;
			}
			if (hasdlang || check_dlang(sym)) {
				info->lang = "dlang";
				return RZ_BIN_NM_DLANG;
			}
		}
		if (!cantbe.msvc) {
			if (!isMsvc && check_msvc(sym)) {
				isMsvc = true;
			}
		}
	}
	if (isObjC) {
		return RZ_BIN_NM_OBJC | (isBlocks ? RZ_BIN_NM_BLOCKS : 0);
	}
	if (canBeCxx) {
		return RZ_BIN_NM_CXX | (isBlocks ? RZ_BIN_NM_BLOCKS : 0);
	}
	if (isMsvc) {
		return RZ_BIN_NM_MSVC;
	}
	return RZ_BIN_NM_C | (isBlocks ? RZ_BIN_NM_BLOCKS : 0);
}

RZ_IPI int rz_bin_lang_type(RzBinFile *binfile, const char *def, const char *sym) {
	int type = 0;
	RzBinPlugin *plugin;
	if (sym && sym[0] == sym[1] && sym[0] == '_') {
		type = RZ_BIN_NM_CXX;
	}
	if (def && *def) {
		type = rz_bin_demangle_type(def);
		if (type != RZ_BIN_NM_NONE) {
			return type;
		}
	}
	plugin = rz_bin_file_cur_plugin(binfile);
	if (plugin && plugin->demangle_type) {
		type = plugin->demangle_type(def);
	} else {
		if (binfile && binfile->o && binfile->o->info) {
			type = rz_bin_demangle_type(binfile->o->info->lang);
		}
	}
	if (type == RZ_BIN_NM_NONE) {
		type = rz_bin_demangle_type(def);
	}
	return type;
}

RZ_API const char *rz_bin_lang_tostring(int lang) {
	switch (lang & 0xffff) {
	case RZ_BIN_NM_SWIFT:
		return "swift";
	case RZ_BIN_NM_GO:
		return "go";
	case RZ_BIN_NM_JAVA:
		return "java";
	case RZ_BIN_NM_KOTLIN:
		return "kotlin";
	case RZ_BIN_NM_C:
		return (lang & RZ_BIN_NM_BLOCKS) ? "c with blocks" : "c";
	case RZ_BIN_NM_CXX:
		return (lang & RZ_BIN_NM_BLOCKS) ? "c++ with blocks" : "c++";
	case RZ_BIN_NM_DLANG:
		return "d";
	case RZ_BIN_NM_OBJC:
		return (lang & RZ_BIN_NM_BLOCKS) ? "objc with blocks" : "objc";
	case RZ_BIN_NM_MSVC:
		return "msvc";
	case RZ_BIN_NM_RUST:
		return "rust";
	}
	return NULL;
}
