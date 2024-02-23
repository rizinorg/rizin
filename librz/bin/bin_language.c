// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2018-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

#define LANGUAGE_WITH_BLOCKS               " with blocks"
#define language_apply_blocks_mask(x, b)   (b ? (RZ_BIN_LANGUAGE_BLOCKS | (x)) : (x))
#define language_apply_blocks_string(x, b) (RZ_BIN_LANGUAGE_HAS_BLOCKS(x) ? (b LANGUAGE_WITH_BLOCKS) : (b))

static inline bool check_rust(RzBinSymbol *sym) {
	return strstr(sym->name, "_$LT$") ||
		strstr(sym->name, "_rust_oom");
}

static inline bool check_objc(RzBinSymbol *sym) {
	return !strncmp(sym->name, "_OBJC_", 6);
}

static inline bool check_dlang(RzBinSymbol *sym) {
	if (!strncmp(sym->name, "_D2", 3)) {
		return true;
	}
	return !strncmp(sym->name, "_D4", 3);
}

static inline bool check_swift(RzBinSymbol *sym) {
	return strstr(sym->name, "swift_once");
}

static inline bool check_golang(RzBinSymbol *sym) {
	return !strncmp(sym->name, "go.", 3) ||
		strstr(sym->name, "gopclntab");
}

static inline bool check_cxx(RzBinSymbol *sym) {
	if (!strncmp(sym->name, "_Z", 2)) {
		return true;
	}
	return !strncmp(sym->name, "__Z", 3);
}

static inline bool check_msvc(RzBinSymbol *sym) {
	return *sym->name == '?';
}

static inline bool check_kotlin(RzBinSymbol *sym) {
	return strstr(sym->name, "kotlin_");
}

static inline bool check_groovy(RzBinSymbol *sym) {
	return strstr(sym->name, "_groovy");
}

static inline bool check_dart(RzBinSymbol *sym) {
	return strstr(sym->name, "io_flutter_");
}

static inline bool check_pascal(RzBinSymbol *sym) {
	if (strstr(sym->name, "$_$")) {
		return true;
	}
	return strstr(sym->name, "_$$_");
}

static inline bool check_nim(RzBinSymbol *sym) {
	if (!strncmp(sym->name, "NimMain", strlen("NimMain"))) {
		return true;
	}
	return rz_str_endswith(sym->name, ".nim.c");
}

/**
 * \brief Tries to detect which language is used in the binary based on symbols and libraries
 *
 * Currently this method can detect the language only from bins that are either ELF, PE,
 * Mach-O, Java Class and Dex.
 *
 * The current supported languages are: c, cxx, dart, dlang, go, groovy, java, kotlin, msvc,
 * objc, rust, swift.
 */
RZ_API RzBinLanguage rz_bin_language_detect(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile && binfile->o, RZ_BIN_LANGUAGE_UNKNOWN);
	RzBinObject *o = binfile->o;
	RzBinInfo *info = o->info;
	RzBinSymbol *sym;
	RzBinImport *imp;
	RzBinSection *section;
	void **iter;

	if (!info) {
		return RZ_BIN_LANGUAGE_UNKNOWN;
	}
	RzBinLanguage lang = rz_bin_language_to_id(info->lang);
	if (lang != RZ_BIN_LANGUAGE_UNKNOWN &&
		lang != RZ_BIN_LANGUAGE_C &&
		lang != RZ_BIN_LANGUAGE_OBJC) {
		// avoid detecting a language if was already specified.
		return lang;
	}

	bool is_macho = info->rclass ? strstr(info->rclass, "mach") : false;
	bool is_dyldc = info->bclass ? strstr(info->bclass, "dyldcache") : false;
	bool is_xnu_kernelcache = info->bclass ? strstr(info->bclass, "kernelcache") : false;
	bool is_elf = info->rclass ? strstr(info->rclass, "elf") : false;
	bool is_pe = info->rclass ? strstr(info->rclass, "pe") : false;
	bool is_class = info->rclass ? strstr(info->rclass, "class") : false;
	bool is_blocks = false;
	bool is_objc = false;
	bool is_cpp = false;
	char *lib = NULL;

	if (!is_macho && !is_dyldc && !is_xnu_kernelcache && !is_elf && !is_pe && !is_class) {
		return RZ_BIN_LANGUAGE_UNKNOWN;
	}

	if (is_macho || is_elf) {
		void **vec_it;
		rz_pvector_foreach (o->imports, vec_it) {
			imp = *vec_it;
			const char *name = imp->name;
			if (!strcmp(name, "_NSConcreteGlobalBlock")) {
				is_blocks = true;
			} else if (!strncmp(name, "objc_", 5)) {
				is_objc = true;
			}
		}
	}
	void **vec_it = NULL;
	rz_pvector_foreach (o->libs, vec_it) {
		lib = *vec_it;
		if (is_macho && strstr(lib, "swift")) {
			info->lang = "swift";
			return language_apply_blocks_mask(RZ_BIN_LANGUAGE_SWIFT, is_blocks);
		} else if (strstr(lib, "stdc++") || strstr(lib, "c++")) {
			is_cpp = true;
		} else if (strstr(lib, "msvcp")) {
			info->lang = "msvc";
			return RZ_BIN_LANGUAGE_MSVC;
		} else if (strstr(lib, "phobos")) {
			info->lang = "dlang";
			return RZ_BIN_LANGUAGE_DLANG;
		}
	}
	if (is_objc) {
		info->lang = "objc";
		return language_apply_blocks_mask(RZ_BIN_LANGUAGE_OBJC, is_blocks);
	}

	rz_pvector_foreach (o->symbols, iter) {
		sym = *iter;
		if (!sym->name) {
			continue;
		}
		if (check_rust(sym)) {
			info->lang = "rust";
			return RZ_BIN_LANGUAGE_RUST;
		} else if (check_golang(sym)) {
			info->lang = "go";
			return RZ_BIN_LANGUAGE_GO;
		} else if (check_swift(sym)) {
			info->lang = "swift";
			return language_apply_blocks_mask(RZ_BIN_LANGUAGE_SWIFT, is_blocks);
		} else if (check_cxx(sym)) {
			is_cpp = true;
		} else if (check_objc(sym)) {
			info->lang = "objc";
			return language_apply_blocks_mask(RZ_BIN_LANGUAGE_OBJC, is_blocks);
		} else if (check_dlang(sym)) {
			info->lang = "dlang";
			return RZ_BIN_LANGUAGE_DLANG;
		} else if (check_kotlin(sym)) {
			info->lang = "kotlin";
			return RZ_BIN_LANGUAGE_KOTLIN;
		} else if (check_groovy(sym)) {
			info->lang = "groovy";
			return RZ_BIN_LANGUAGE_GROOVY;
		} else if (check_msvc(sym)) {
			info->lang = "c";
			return RZ_BIN_LANGUAGE_MSVC;
		} else if (check_dart(sym)) {
			info->lang = "dart";
			return RZ_BIN_LANGUAGE_DART;
		} else if (check_pascal(sym)) {
			info->lang = "pascal";
			return RZ_BIN_LANGUAGE_PASCAL;
		} else if (check_nim(sym)) {
			info->lang = "nim";
			return RZ_BIN_LANGUAGE_NIM;
		}
	}

	if (is_macho || is_elf) {
		rz_pvector_foreach (o->sections, iter) {
			section = *iter;
			if (!section->name) {
				continue;
			}
			if (strstr(section->name, "note.go.buildid") ||
				strstr(section->name, "gopclntab") ||
				strstr(section->name, "go_export")) {
				info->lang = "go";
				return RZ_BIN_LANGUAGE_GO;
			}
		}
	}
	if (is_cpp) {
		info->lang = "c++";
		return language_apply_blocks_mask(RZ_BIN_LANGUAGE_CXX, is_blocks);
	} else if (!info->lang) {
		info->lang = "c";
	} else if (strstr(info->lang, "java")) {
		return RZ_BIN_LANGUAGE_JAVA;
	}
	return language_apply_blocks_mask(RZ_BIN_LANGUAGE_C, is_blocks);
}

/**
 * \brief returns the language identifier based on the given lang name
 */
RZ_API RzBinLanguage rz_bin_language_to_id(const char *language) {
	if (RZ_STR_ISEMPTY(language)) {
		return RZ_BIN_LANGUAGE_UNKNOWN;
	}
	bool has_blocks = strstr(language, LANGUAGE_WITH_BLOCKS);
	if (strstr(language, "swift")) {
		return language_apply_blocks_mask(RZ_BIN_LANGUAGE_SWIFT, has_blocks);
	} else if (strstr(language, "java")) {
		return RZ_BIN_LANGUAGE_JAVA;
	} else if (strstr(language, "groovy")) {
		return RZ_BIN_LANGUAGE_GROOVY;
	} else if (strstr(language, "kotlin")) {
		return RZ_BIN_LANGUAGE_KOTLIN;
	} else if (strstr(language, "objc")) {
		return language_apply_blocks_mask(RZ_BIN_LANGUAGE_OBJC, has_blocks);
	} else if (strstr(language, "cxx") || strstr(language, "c++")) {
		return language_apply_blocks_mask(RZ_BIN_LANGUAGE_CXX, has_blocks);
	} else if (strstr(language, "dlang")) {
		return RZ_BIN_LANGUAGE_DLANG;
	} else if (strstr(language, "msvc")) {
		return RZ_BIN_LANGUAGE_MSVC;
	} else if (strstr(language, "rust")) {
		return RZ_BIN_LANGUAGE_RUST;
	} else if (strstr(language, "dart")) {
		return RZ_BIN_LANGUAGE_DART;
	} else if (!strcmp(language, "c") || !strcmp(language, "c" LANGUAGE_WITH_BLOCKS)) {
		return language_apply_blocks_mask(RZ_BIN_LANGUAGE_C, has_blocks);
	} else if (!strcmp(language, "go")) {
		return RZ_BIN_LANGUAGE_GO;
	} else if (!strcmp(language, "pascal")) {
		return RZ_BIN_LANGUAGE_PASCAL;
	} else if (!strcmp(language, "nim")) {
		return RZ_BIN_LANGUAGE_NIM;
	}
	return RZ_BIN_LANGUAGE_UNKNOWN;
}

/**
 * \brief returns the language name based on the given language identifier
 */
RZ_API const char *rz_bin_language_to_string(RzBinLanguage language) {
	switch (RZ_BIN_LANGUAGE_MASK(language)) {
	case RZ_BIN_LANGUAGE_SWIFT:
		return language_apply_blocks_string(language, "swift");
	case RZ_BIN_LANGUAGE_GO:
		return "go";
	case RZ_BIN_LANGUAGE_JAVA:
		return "java";
	case RZ_BIN_LANGUAGE_KOTLIN:
		return "kotlin";
	case RZ_BIN_LANGUAGE_C:
		return language_apply_blocks_string(language, "c");
	case RZ_BIN_LANGUAGE_CXX:
		return language_apply_blocks_string(language, "c++");
	case RZ_BIN_LANGUAGE_DLANG:
		return "dlang";
	case RZ_BIN_LANGUAGE_OBJC:
		return language_apply_blocks_string(language, "objc");
	case RZ_BIN_LANGUAGE_MSVC:
		return "msvc";
	case RZ_BIN_LANGUAGE_RUST:
		return "rust";
	case RZ_BIN_LANGUAGE_GROOVY:
		return "groovy";
	case RZ_BIN_LANGUAGE_DART:
		return "dart";
	case RZ_BIN_LANGUAGE_PASCAL:
		return "pascal";
	case RZ_BIN_LANGUAGE_NIM:
		return "nim";
	default:
		return NULL;
	}
}
