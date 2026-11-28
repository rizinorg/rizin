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
		strstr(sym->name, "rust_oom");
}

#define RUST_SECTION_SCAN_LIMIT (8 * 1024 * 1024)
#define RUST_SECTION_CHUNK_SZ   65536
#define RUST_SECTION_OVERLAP    64

typedef struct {
	const char *str;
	size_t len;
	size_t anchor;
} RustMarker;

#define RUST_MARKER(lit, anc) { lit, sizeof(lit) - 1, anc }

static bool buf_contains_marker(const ut8 *buf, size_t len, const RustMarker *m) {
	if (len < m->len) {
		return false;
	}
	const ut8 *p = buf + m->anchor;
	size_t rem = len - m->len + 1;
	int ch = (ut8)m->str[m->anchor];
	while (rem > 0) {
		const ut8 *hit = memchr(p, ch, rem);
		if (!hit) {
			return false;
		}
		if (!memcmp(hit - m->anchor, m->str, m->len)) {
			return true;
		}
		size_t adv = (size_t)(hit - p) + 1;
		p += adv;
		rem -= adv;
	}
	return false;
}

static bool section_has_rust_marker(const ut8 *buf, size_t len) {
	static const RustMarker markers[] = {
		RUST_MARKER("called `Option::unwrap()` on a `None` value", 7),
		RUST_MARKER("called `Result::unwrap()` on an `Err` value", 7),
		RUST_MARKER("index out of bounds: the len is ", 19),
		RUST_MARKER("/library/core/src/", 7),
		RUST_MARKER("\\library\\core\\src\\", 7),
		RUST_MARKER("/library/std/src/", 7),
		RUST_MARKER("\\library\\std\\src\\", 7),
		RUST_MARKER("core/src/panicking.rs", 14),
		RUST_MARKER("core\\src\\panicking.rs", 14),
		RUST_MARKER("std/src/panicking.rs", 13),
		RUST_MARKER("std\\src\\panicking.rs", 13),
		RUST_MARKER(".cargo/registry/src/", 14),
		RUST_MARKER(".cargo\\registry\\src\\", 14),
		RUST_MARKER("fatal runtime error: ", 19),
		RUST_MARKER("rust_begin_unwind", 13),
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(markers); i++) {
		if (buf_contains_marker(buf, len, &markers[i])) {
			return true;
		}
	}
	return false;
}

static bool is_rust_scan_section(const RzBinSection *sec) {
	if (!sec || sec->is_segment || !sec->name || !sec->size) {
		return false;
	}
	return strstr(sec->name, "rodata") ||
		strstr(sec->name, "rdata") ||
		rz_str_endswith(sec->name, "__const") ||
		rz_str_endswith(sec->name, "__cstring");
}

static bool is_rust_fallback_section(const RzBinSection *sec) {
	if (!sec || sec->is_segment || !sec->size ||
		!(sec->perm & RZ_PERM_R) || (sec->perm & RZ_PERM_X)) {
		return false;
	}
	if (sec->name && (!strcmp(sec->name, ".rsrc") || !strcmp(sec->name, ".reloc") || !strcmp(sec->name, ".pdata") || !strcmp(sec->name, ".idata") || !strcmp(sec->name, ".eh_frame") || !strcmp(sec->name, ".symtab") || !strcmp(sec->name, ".strtab") || !strcmp(sec->name, ".shstrtab") || rz_str_startswith(sec->name, ".debug"))) {
		return false;
	}
	return true;
}

static bool scan_section_for_rust_markers(RzBuffer *buf, ut64 buf_size,
	const RzBinSection *section, ut8 *chunk, ut64 *remaining_budget) {
	if (!*remaining_budget || section->paddr >= buf_size) {
		return false;
	}
	ut64 avail = buf_size - section->paddr;
	ut64 to_scan = RZ_MIN(RZ_MIN(section->size, avail), *remaining_budget);
	ut64 scanned = 0;
	size_t carry = 0;
	bool found = false;
	while (scanned < to_scan) {
		size_t want = (size_t)RZ_MIN(
			(ut64)RUST_SECTION_CHUNK_SZ, to_scan - scanned);
		st64 got = rz_buf_read_at(
			buf, section->paddr + scanned, chunk + carry, want);
		if (got <= 0 || (size_t)got > want) {
			break;
		}
		size_t total = carry + (size_t)got;
		if (section_has_rust_marker(chunk, total)) {
			found = true;
			break;
		}
		carry = RZ_MIN(total, (size_t)RUST_SECTION_OVERLAP);
		memmove(chunk, chunk + total - carry, carry);
		scanned += (ut64)got;
	}
	*remaining_budget -= RZ_MIN(*remaining_budget, scanned);
	return found;
}

static bool check_rust_sections(RzBinFile *binfile) {
	RzBinObject *o = binfile->o;
	if (!o || !o->sections) {
		return false;
	}
	void **iter;
	RzBinSection *section;
	rz_pvector_foreach (o->sections, iter) {
		section = *iter;
		if (section && section->name && !strcmp(section->name, ".rustc")) {
			return true;
		}
	}
	if (!binfile->buf) {
		return false;
	}
	ut8 *chunk = malloc(RUST_SECTION_CHUNK_SZ + RUST_SECTION_OVERLAP);
	if (!chunk) {
		return false;
	}
	ut64 buf_size = rz_buf_size(binfile->buf);
	ut64 remaining_budget = RUST_SECTION_SCAN_LIMIT;
	bool found = false;
	bool scanned_named = false;
	rz_pvector_foreach (o->sections, iter) {
		section = *iter;
		if (!is_rust_scan_section(section)) {
			continue;
		}
		scanned_named = true;
		if (scan_section_for_rust_markers(
			    binfile->buf, buf_size, section, chunk, &remaining_budget)) {
			found = true;
			break;
		}
		if (!remaining_budget) {
			break;
		}
	}
	if (!found && !scanned_named && remaining_budget) {
		rz_pvector_foreach (o->sections, iter) {
			section = *iter;
			if (!is_rust_fallback_section(section)) {
				continue;
			}
			if (scan_section_for_rust_markers(
				    binfile->buf, buf_size, section, chunk, &remaining_budget)) {
				found = true;
				break;
			}
			if (!remaining_budget) {
				break;
			}
		}
	}
	free(chunk);
	return found;
}

static inline bool check_objc(RzBinSymbol *sym) {
	return !strncmp(sym->name, "_OBJC_", 6);
}

static inline bool check_dlang(RzBinSymbol *sym) {
	return (!strncmp(sym->name, "_D", 2) && IS_DIGIT(sym->name[2])) || (!strncmp(sym->name, "__D", 3) && IS_DIGIT(sym->name[3]));
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
	bool has_cpp_lib = false;
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
			has_cpp_lib = true;
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
	if ((is_elf || is_pe || is_macho) && !has_cpp_lib && check_rust_sections(binfile)) {
		info->lang = "rust";
		return RZ_BIN_LANGUAGE_RUST;
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
