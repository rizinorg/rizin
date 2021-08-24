// SPDX-FileCopyrightText: 2018-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

#define lang_apply_blocks(x,b) (b?(RZ_BIN_NM_BLOCKS|(x)):(x))

static inline bool check_rust(RzBinSymbol *sym) {
	return sym->name && strstr(sym->name, "_$LT$");
}

static inline bool check_objc(RzBinSymbol *sym) {
	if (sym->name && !strncmp(sym->name, "_OBJC_", 6)) {
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

static bool check_kotlin(RzBinSymbol *sym) {
	return strstr(sym->name, "kotlin_");
}

static bool check_groovy(RzBinSymbol *sym) {
	return strstr(sym->name, "_groovy");
}

/* This is about 10% of the loading time, optimize if possible */
RZ_API int rz_bin_load_languages(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile && binfile->o, RZ_BIN_NM_NONE);
	RzBinObject *o = binfile->o;
	RzBinInfo *info = o->info;
	RzBinSymbol *sym;
	RzListIter *iter;

	if (!info) {
		return RZ_BIN_NM_NONE;
	} else if (RZ_STR_ISNOTEMPTY(info->lang)) {
		if (strstr(info->lang, "java")) {
			return RZ_BIN_NM_JAVA;
		} else if (strstr(info->lang, "kotlin")) {
			return RZ_BIN_NM_KOTLIN;
		} else if (strstr(info->lang, "groovy")) {
			return RZ_BIN_NM_GROOVY;
		} else if (strstr(info->lang, "swift")) {
			return RZ_BIN_NM_SWIFT;
		}
		return RZ_BIN_NM_NONE;
	}

	bool is_macho = info->rclass ? strstr(info->rclass, "mach") : false;
	bool is_elf = info->rclass ? strstr(info->rclass, "elf") : false;
	bool is_pe = info->rclass ? strstr(info->rclass, "pe") : false;
	bool is_blocks = false;
	bool is_objc = false;
	char *lib = NULL;

	if (!is_macho && !is_elf && !is_pe) {
		return RZ_BIN_NM_NONE;
	}

	if (is_macho) {
		rz_list_foreach (o->imports, iter, sym) {
			const char *name = sym->name;
			if (!strcmp(name, "_NSConcreteGlobalBlock")) {
				is_blocks = true;
			} else if (!strncmp(name, "objc_", 5)) {
				is_objc = true;
			}
		}
	}
	rz_list_foreach (o->libs, iter, lib) {
		if (is_macho && strstr(lib, "swift")) {
			info->lang = "swift";
			return lang_apply_blocks(RZ_BIN_NM_SWIFT, is_blocks);
		} else if (strstr(lib, "stdc++") || strstr(lib, "c++")) {
			info->lang = "c++";
			return RZ_BIN_NM_CXX;
		} else if (strstr(lib, "msvcp")) {
			info->lang = "msvc";
			return RZ_BIN_NM_MSVC;
		} else if (strstr(lib, "phobos")) {
			info->lang = "dlang";
			return RZ_BIN_NM_DLANG;
		}
	}
	if (is_objc) {
		info->lang = "objc";
		return lang_apply_blocks(RZ_BIN_NM_OBJC, is_blocks);
	}

	rz_list_foreach (o->symbols, iter, sym) {
		if (check_rust(sym)) {
			info->lang = "rust";
			return RZ_BIN_NM_RUST;
		} else if (check_golang(sym)) {
			info->lang = "go";
			return RZ_BIN_NM_GO;
		} else if (check_swift(sym)) {
			info->lang = "swift";
			return lang_apply_blocks(RZ_BIN_NM_SWIFT, is_blocks);
		} else if (check_cxx(sym)) {
			info->lang = "c++";
			return lang_apply_blocks(RZ_BIN_NM_CXX, is_blocks);
		} else if (check_objc(sym)) {
			info->lang = "objc";
			return lang_apply_blocks(RZ_BIN_NM_OBJC, is_blocks);
		} else if (check_dlang(sym)) {
			info->lang = "dlang";
			return RZ_BIN_NM_DLANG;
		} else if (check_kotlin(sym)) {
			info->lang = "kotlin";
			return RZ_BIN_NM_KOTLIN;
		} else if (check_groovy(sym)) {
			info->lang = "groovy";
			return RZ_BIN_NM_GROOVY;
		} else if (check_msvc(sym)) {
			info->lang = "c";
			return RZ_BIN_NM_MSVC;
		}
	}
	return lang_apply_blocks(RZ_BIN_NM_C, is_blocks);
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
		return "dlang";
	case RZ_BIN_NM_OBJC:
		return (lang & RZ_BIN_NM_BLOCKS) ? "objc with blocks" : "objc";
	case RZ_BIN_NM_MSVC:
		return "msvc";
	case RZ_BIN_NM_RUST:
		return "rust";
	case RZ_BIN_NM_GROOVY:
		return "groovy";
	}
	return NULL;
}
