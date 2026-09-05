// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

#define RUST_VTABLE_HEADER_SLOTS    3
#define RUST_MAX_TRAIT_METHOD_SLOTS 128

typedef struct rust_trait_method_t {
	ut64 addr;
	ut64 vtable_offset;
	char *name;
	char *real_name;
	char *impl_type;
	char *trait_name;
} RustTraitMethod;

static void trait_method_fini(void *e, void *user) {
	RustTraitMethod *method = e;
	RZ_FREE(method->name);
	RZ_FREE(method->real_name);
	RZ_FREE(method->impl_type);
	RZ_FREE(method->trait_name);
}

static bool section_can_contain_vtables(RzBinSection *section) {
	if (section->is_segment) {
		return false;
	}
	return !strcmp(section->name, ".rodata") ||
		!strcmp(section->name, ".rdata") ||
		!strcmp(section->name, ".data.rel.ro") ||
		!strcmp(section->name, ".data.rel.ro.local") ||
		rz_str_endswith(section->name, "__const");
}

static bool addr_in_text_section(RzAnalysis *analysis, ut64 addr) {
	RzBinSection *section = analysis->binb.get_vsect_at(analysis->binb.bin, addr);
	return section && (section->perm & RZ_PERM_X);
}

static bool vtable_header_is_valid(RVTableContext *context, ut64 addr) {
	ut64 drop = UT64_MAX;
	ut64 size = UT64_MAX;
	ut64 align = UT64_MAX;
	if (!context->read_addr(context->analysis, addr, &drop) ||
		!context->read_addr(context->analysis, addr + context->word_size, &size) ||
		!context->read_addr(context->analysis, addr + (2 * context->word_size), &align)) {
		return false;
	}
	if (drop && !addr_in_text_section(context->analysis, drop)) {
		return false;
	}
	if (rz_bits_count_ones_ut64(align) != 1) {
		return false;
	}
	return !size || (!(size % align) && align <= size);
}

static char *demangled_name_at(RzAnalysis *analysis, ut64 addr) {
	RzBinObject *obj = rz_bin_cur_object(analysis->binb.bin);
	if (!obj) {
		return NULL;
	}

	RzBinSymbol *sym = rz_bin_object_get_symbol_at(obj, addr, true);
	if (sym && RZ_STR_ISNOTEMPTY(sym->dname)) {
		return rz_str_dup(sym->dname);
	}

	if (sym && RZ_STR_ISNOTEMPTY(sym->name)) {
		char *demangled = NULL;
		if (analysis->binb.demangle) {
			demangled = analysis->binb.demangle(analysis->binb.bin, "rust", sym->name);
		}
		if (demangled) {
			return demangled;
		}
		RZ_FREE(demangled);
	}
	return NULL;
}

static char *dup_trimmed_range(const char *start, const char *end) {
	while (start < end && IS_WHITESPACE(*start)) {
		start++;
	}
	while (end > start && IS_WHITESPACE(end[-1])) {
		end--;
	}
	if (start < end) {
		return rz_str_ndup(start, (int)(end - start));
	}
	return NULL;
}

static bool parse_demangled_trait_method(const char *demangled, RustTraitMethod *method) {
	if (RZ_STR_ISEMPTY(demangled) || demangled[0] != '<') {
		return false;
	}

	const char *inside = demangled + 1;
	const char *impl_end = NULL;
	const char *trait_start = NULL;
	const char *trait_end = NULL;
	int depth = 0;

	for (const char *p = inside; *p; p++) {
		if (*p == '<') {
			depth++;
			continue;
		}
		if (*p == '>') {
			if (!depth) {
				if (strncmp(p, ">::", 3)) {
					return false;
				}
				trait_end = p;
				break;
			}
			depth--;
			continue;
		}
		if (!depth && !trait_start && !strncmp(p, " as ", 4)) {
			impl_end = p;
			trait_start = p + 4;
			p += 3;
		}
	}

	if (!impl_end || !trait_start || !trait_end || trait_start >= trait_end) {
		return false;
	}

	const char *suffix = trait_end + 3;
	if (RZ_STR_ISEMPTY(suffix)) {
		return false;
	}

	// Strip trailing symbol hash (::h + 16 hex) to get the real method name
	const char *hash_sep = rz_str_rstr(suffix, "::h");
	bool has_hash = hash_sep && hash_sep > suffix && strlen(hash_sep) == 19 && strspn(hash_sep + 3, "0123456789abcdef") == 16;
	const char *name_end;
	if (has_hash) {
		name_end = hash_sep;
	} else {
		name_end = suffix + strlen(suffix);
	}

	method->impl_type = dup_trimmed_range(inside, impl_end);
	method->trait_name = dup_trimmed_range(trait_start, trait_end);
	method->name = dup_trimmed_range(suffix, name_end);

	return method->impl_type && method->trait_name && method->name;
}

static bool parse_method_name(RzAnalysis *analysis, ut64 addr, RustTraitMethod *method) {
	char *name = demangled_name_at(analysis, addr);
	if (!name) {
		return false;
	}

	bool ok = parse_demangled_trait_method(name, method);
	if (ok) {
		method->real_name = name;
	} else {
		trait_method_fini(method, NULL);
		RZ_FREE(name);
	}
	return ok;
}

static RZ_OWN RzVector /*<RustTraitMethod>*/ *parse_rust_vtable(RVTableContext *context, ut64 vtable_addr) {
	if (!vtable_header_is_valid(context, vtable_addr)) {
		return NULL;
	}

	RzVector *methods = rz_vector_new(sizeof(RustTraitMethod), trait_method_fini, NULL);
	if (!methods) {
		return NULL;
	}

	ut64 slot_addr = vtable_addr + (RUST_VTABLE_HEADER_SLOTS * context->word_size);
	for (ut64 i = 0; i < RUST_MAX_TRAIT_METHOD_SLOTS; i++, slot_addr += context->word_size) {
		ut64 method_addr = UT64_MAX;
		if (!context->read_addr(context->analysis, slot_addr, &method_addr)) {
			break;
		}

		bool next_header = vtable_header_is_valid(context, slot_addr);
		if (method_addr == 0) {
			break;
		}

		if (!addr_in_text_section(context->analysis, method_addr)) {
			break;
		}

		RustTraitMethod method = {
			.addr = method_addr,
			.vtable_offset = slot_addr - vtable_addr,
		};
		if (!parse_method_name(context->analysis, method_addr, &method)) {
			if (next_header) {
				break;
			}
			continue;
		}

		if (!rz_vector_push(methods, &method)) {
			trait_method_fini(&method, NULL);
			break;
		}
	}

	if (rz_vector_empty(methods)) {
		rz_vector_free(methods);
		return NULL;
	}
	return methods;
}

static char *class_name_from_methods(RzVector /*<RustTraitMethod>*/ *methods) {
	RustTraitMethod *best = NULL;
	ut64 best_count = 0;
	RustTraitMethod *candidate;
	rz_vector_foreach (methods, candidate) {
		ut64 count = 0;
		RustTraitMethod *method;
		rz_vector_foreach (methods, method) {
			if (method->trait_name && !strcmp(candidate->trait_name, method->trait_name)) {
				count++;
			}
		}
		if (count > best_count) {
			best = candidate;
			best_count = count;
		}
	}
	if (best) {
		return rz_str_newf("impl %s as %s", best->impl_type, best->trait_name);
	}
	return NULL;
}

static void apply_rust_vtable(RVTableContext *context, ut64 vtable_addr, RzVector /*<RustTraitMethod>*/ *methods) {
	RzAnalysis *analysis = context->analysis;
	char *class_name = class_name_from_methods(methods);
	if (!class_name) {
		return;
	}

	if (!rz_analysis_class_exists(analysis, class_name)) {
		rz_analysis_class_create(analysis, class_name);
	}

	RustTraitMethod *last_method = rz_vector_tail(methods);
	RzAnalysisVTable vtable = {
		.addr = vtable_addr,
		.offset = 0,
		.size = last_method->vtable_offset + context->word_size,
	};

	rz_analysis_class_vtable_set(analysis, class_name, &vtable);
	rz_analysis_class_vtable_fini(&vtable);
	RustTraitMethod *rmethod;
	rz_vector_foreach (methods, rmethod) {
		bool conflict = false;
		RzAnalysisMethod existing;
		if (rz_analysis_class_method_get(analysis, class_name, rmethod->name, &existing) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
			conflict = existing.addr != rmethod->addr || existing.vtable_offset != rmethod->vtable_offset;
			rz_analysis_class_method_fini(&existing);
		}
		char *name = NULL;
		if (conflict) {
			name = rz_str_newf("%s.0x%" PFMT64x ".slot_0x%" PFMT64x, rmethod->name, rmethod->addr, rmethod->vtable_offset);
		} else {
			name = rz_str_dup(rmethod->name);
		}
		if (!name) {
			continue;
		}
		RzAnalysisMethod method = {
			.name = name,
			.real_name = rz_str_dup(rmethod->real_name),
			.addr = rmethod->addr,
			.vtable_offset = rmethod->vtable_offset,
			.method_type = RZ_ANALYSIS_CLASS_METHOD_VIRTUAL,
		};
		rz_analysis_class_method_set(analysis, class_name, &method);
		rz_analysis_class_method_fini(&method);
	}
	RZ_FREE(class_name);
}

/**
 * \brief Recover Rust trait object vtables and class metadata
 *
 * Scans selected data sections for candidate Rust trait object vtables and
 * validates their drop pointer, size, and alignment header fields. Demangled
 * method symbols are used to recover implementing types, traits, method names,
 * and vtable slot offsets.
 *
 * Successfully recovered vtables and virtual methods are added to the analysis
 *
 * \param analysis Analysis context for the current binary.
 */
RZ_API void rz_analysis_rtti_rust(RZ_NONNULL RzAnalysis *analysis) {
	RVTableContext context;
	if (!rz_analysis_vtable_begin(analysis, &context)) {
		return;
	}

	RzBinObject *obj = rz_bin_cur_object(analysis->binb.bin);
	const RzPVector *sections = NULL;
	if (obj) {
		sections = analysis->binb.get_sections(obj);
	}
	if (!sections) {
		return;
	}

	rz_cons_break_push(NULL, NULL);
	void **iter;
	RzBinSection *section;
	rz_pvector_foreach (sections, iter) {
		if (rz_cons_is_breaked()) {
			break;
		}
		section = *iter;
		if (!section_can_contain_vtables(section)) {
			continue;
		}
		if (section->vsize < RUST_VTABLE_HEADER_SLOTS * context.word_size) {
			continue;
		}

		ut64 addr = RZ_ROUND(section->vaddr, context.word_size);
		ut64 end = section->vaddr + section->vsize - (RUST_VTABLE_HEADER_SLOTS * context.word_size);
		while (addr <= end) {
			if (rz_cons_is_breaked()) {
				break;
			}
			if (!analysis->iob.is_valid_offset(analysis->iob.io, addr, 0)) {
				addr += context.word_size;
				continue;
			}

			RzVector *methods = parse_rust_vtable(&context, addr);
			if (methods) {
				apply_rust_vtable(&context, addr, methods);
				rz_vector_free(methods);
			}
			addr += context.word_size;
		}
	}
	rz_cons_break_pop();
}
