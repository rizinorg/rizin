// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 Skia <skia@libskia.so>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file format.c
 * \brief Convert between RzType / RzBaseType values and `pf` format strings.
 *
 * The main direction is the *producer* side: walk an in-memory RzType
 * tree and emit the corresponding pf format string plus the matching
 * " name1 name2..." tail.
 *
 * The reverse helper rz_type_format_to_c_declaration() takes a pf format
 * string and emits an equivalent C struct/union declaration, so a format
 * can be promoted to a registered RzBaseType (used by the `tdf` command).
 *
 * The byte-level consumer -- parsing a pf string and interpreting bytes
 * through it -- lives in the pf engine under librz/type/pf/.
 */

#include "rz_util/rz_str_util.h"
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_reg.h>
#include <rz_type.h>
#include <rz_pf.h>

/* Every format string essentially contains two parts:
 * 1. The format (`pf` string) itself
 * 2. The field name and types, "(field_type)field_name"
 * Both parts are separated from each other by space
 *
 * Example:
 * "[2]Ex2t(unix32)x4x4x2[2]B (pe_machine)machine NumberOfSections TimeDateStamp PointerToSymbolTable NumberOfSymbols SizeOfOptionalHeader (pe_characteristics)Characteristics"
 * Here "[2]Ex2t(unix32)x4x4x2[2]B" is the `pf` string while the rest are
 * field names and types.
 * E.g. "(pe_machine)" is the field type, previously defined enum called "pe_machine"
 * "machine" here is the field name. The corresponding construction in C is:
 * struct {
 *     pe_machine machine;        // [2]E  (enum, 2-byte)
 *     uint16_t NumberOfSections; // x2
 *     datetime_t TimeDateStamp;  // t(unix32)
 *     uint32_t PointerToSymbolTable; // x4
 *     uint32_t NumberOfSymbols;  // x4
 *     uint16_t SizeOfOptionalHeader; // x2
 *     pe_characteristics characteristics; // [2]B  (bitfield enum, 2-byte)
 * };
 */

static const char *type_to_identifier(const RzTypeDB *typedb, RzType *type) {
	if (type->kind == RZ_TYPE_KIND_IDENTIFIER) {
		return type->identifier.name;
	} else if (type->kind == RZ_TYPE_KIND_ARRAY) {
		return type_to_identifier(typedb, type->array.type);
	} else if (type->kind == RZ_TYPE_KIND_POINTER) {
		return type_to_identifier(typedb, type->pointer.type);
	} else if (type->kind == RZ_TYPE_KIND_CALLABLE) {
		return type->callable->name;
	}
	rz_warn_if_reached();
	return NULL;
}

static bool type_to_format_pair(const RzTypeDB *typedb, RzStrBuf *format, RzStrBuf *fields, RZ_NULLABLE const char *identifier, RZ_NONNULL RzType *type);

// This logic applies only to the structure/union members, not the toplevel types
static void base_type_to_format_no_unfold(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *type, RZ_NONNULL const char *identifier, RzStrBuf *format, RzStrBuf *fields) {
	rz_return_if_fail(typedb && type && identifier && format && fields);
	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT: {
		rz_strbuf_append(format, "?");
		rz_strbuf_appendf(fields, "(%s)%s ", type->name, identifier);
		break;
	}
	case RZ_BASE_TYPE_KIND_UNION: {
		// In `pf` unions defined like structs but all have 0 offset,
		// which is why it uses `0` character as a marker when being unfolded,
		// but when folded, they use the same `?` character as structures.
		rz_strbuf_append(format, "?");
		rz_strbuf_appendf(fields, "(%s)%s ", type->name, identifier);
		break;
	}
	case RZ_BASE_TYPE_KIND_ENUM: {
		// Some enums defined as bitfields in the database, so we search if
		// it's stored as the `pf` format in the database
		const char *fmt = rz_type_db_format_get(typedb, type->name);
		if (fmt) {
			rz_strbuf_append(format, "B");
		} else {
			rz_strbuf_append(format, "E");
		}
		rz_strbuf_appendf(fields, "(%s)%s ", type->name, identifier);
		break;
	}
	case RZ_BASE_TYPE_KIND_TYPEDEF: {
		// It might go recursively to find all types behind the alias
		// So we check first it refers to itself
		if (rz_type_is_identifier(type->type)) {
			const char *tidentifier = rz_type_identifier(type->type);
			if (RZ_STR_EQ(tidentifier, type->name)) {
				// Show it as a pointer instead
				rz_strbuf_append(format, "p");
				rz_strbuf_appendf(fields, "%s ", identifier);
				break;
			}
		}
		char *fmt = rz_type_as_format(typedb, type->type);
		if (fmt) {
			rz_strbuf_append(format, fmt);
			if (!rz_type_is_atomic(typedb, type->type)) {
				rz_strbuf_appendf(fields, "(%s)%s ", type->name, identifier);
			} else {
				rz_strbuf_appendf(fields, "%s ", identifier);
			}
		} else {
			type_to_format_pair(typedb, format, fields, identifier, type->type);
		}
		free(fmt);
		break;
	}
	case RZ_BASE_TYPE_KIND_ATOMIC: {
		// We simply skip fields that don't have a format
		const char *fmt = rz_type_db_format_get(typedb, type->name);
		if (fmt) {
			rz_strbuf_append(format, fmt);
			rz_strbuf_appendf(fields, "%s ", identifier);
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

// This logic applies to the toplevel types and unfolds the structure/union types
static void base_type_to_format_unfold(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *type, RzStrBuf *format, RzStrBuf *fields, RZ_NULLABLE const char *identifier) {
	rz_return_if_fail(typedb && type && format && fields);
	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT: {
		RzTypeStructMember *memb;
		rz_vector_foreach (&type->struct_data.members, memb) {
			const char *membtype = type_to_identifier(typedb, memb->type);
			// Avoid infinite recursion in case of self-referential structures
			if (!membtype || !strcmp(membtype, type->name)) {
				continue;
			}
			if (rz_type_is_identifier(memb->type)) {
				// Search the base type of the same name and generate the format from it
				RzBaseType *btyp = rz_type_get_base_type(typedb, memb->type);
				if (btyp) {
					base_type_to_format_no_unfold(typedb, btyp, memb->name, format, fields);
				}
			} else {
				char *membfmt = rz_type_as_format(typedb, memb->type);
				rz_strbuf_append(format, membfmt);
				if (!rz_type_is_atomic(typedb, memb->type)) {
					rz_strbuf_appendf(fields, "(%s)%s ", membtype, memb->name);
				} else {
					rz_strbuf_appendf(fields, "%s ", memb->name);
				}
				free(membfmt);
			}
		}
		break;
	}
	case RZ_BASE_TYPE_KIND_UNION: {
		// In `pf` unions defined like structs but all have 0 offset,
		// which is why it uses `0` character as a marker
		rz_strbuf_append(format, "0");
		RzTypeUnionMember *memb;
		rz_vector_foreach (&type->union_data.members, memb) {
			const char *membtype = type_to_identifier(typedb, memb->type);
			// Avoid infinite recursion in case of self-referential unions
			if (!membtype || !strcmp(membtype, type->name)) {
				continue;
			}
			if (rz_type_is_identifier(memb->type)) {
				// Search the base type of the same name and generate the format from it
				RzBaseType *btyp = rz_type_get_base_type(typedb, memb->type);
				if (btyp) {
					base_type_to_format_no_unfold(typedb, btyp, memb->name, format, fields);
				}
			} else {
				char *membfmt = rz_type_as_format(typedb, memb->type);
				rz_strbuf_append(format, membfmt);
				if (!rz_type_is_atomic(typedb, memb->type)) {
					rz_strbuf_appendf(fields, "(%s)%s ", membtype, memb->name);
				} else {
					rz_strbuf_appendf(fields, "%s ", memb->name);
				}
				free(membfmt);
			}
		}
		break;
	}
	case RZ_BASE_TYPE_KIND_ENUM:
	case RZ_BASE_TYPE_KIND_ATOMIC: {
		base_type_to_format_no_unfold(typedb, type, type->name, format, fields);
		break;
	}
	case RZ_BASE_TYPE_KIND_TYPEDEF: {
		RzType *unwrapped = rz_type_db_base_type_unwrap_typedef(typedb, type);
		if (!unwrapped) {
			break;
		}
		type_to_format_pair(typedb, format, fields, identifier, unwrapped);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

/**
 * \brief Represents the RzBaseType as a `pf` format string
 *
 * Produces the pair of of <format> <fields>. If the type
 * is atomic it searches if the type database has predefined
 * format assigned to it and uses it.
 *
 * \param typedb Types Database instance
 * \param type RzBaseType type
 */
RZ_API RZ_OWN char *rz_base_type_as_format(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, NULL);

	RzStrBuf *format = rz_strbuf_new("");
	RzStrBuf *fields = rz_strbuf_new("");
	base_type_to_format_unfold(typedb, type, format, fields, NULL);
	char *fieldstr = rz_strbuf_drain(fields);
	rz_strbuf_appendf(format, " %s", fieldstr);
	free(fieldstr);
	char *bufstr = rz_strbuf_drain(format);
	rz_str_trim_tail(bufstr);
	return bufstr;
}

/**
 * \brief Represents the RzBaseType as a `pf` format string
 *
 * Produces the pair of of <format> <fields>. If the type
 * is atomic it searches if the type database has predefined
 * format assigned to it and uses it.
 *
 * \param typedb Types Database instance
 * \param name RzBaseType type name
 */
RZ_API RZ_OWN char *rz_type_format(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_base_type_as_format(typedb, btype);
}

static const char *uint_ctype_for_bytes(int nbytes) {
	if (nbytes <= 1) {
		return "uint8_t";
	}
	if (nbytes <= 2) {
		return "uint16_t";
	}
	if (nbytes <= 4) {
		return "uint32_t";
	}
	return "uint64_t";
}

static const char *uint_ctype_for_bits(int nbits) {
	if (nbits <= 8) {
		return "uint8_t";
	}
	if (nbits <= 16) {
		return "uint16_t";
	}
	if (nbits <= 32) {
		return "uint32_t";
	}
	return "uint64_t";
}

// Fixed-width integer the timestamp wire-format is decoded from.
static const char *pf_timefmt_ctype(RzPfTimeFmt tf) {
	switch (tf) {
	case RZ_PF_TIMEFMT_UNIX32:
	case RZ_PF_TIMEFMT_DOS:
	case RZ_PF_TIMEFMT_HFS:
		return "uint32_t";
	case RZ_PF_TIMEFMT_OLETIME:
	case RZ_PF_TIMEFMT_COCOA:
		return "double";
	default:
		return "uint64_t";
	}
}

// Append a `<ctype> <name>;` member, or `<ctype> <name>[count];` when count > 1.
static void pf_emit_member(RzStrBuf *sb, const char *ctype, const char *name, int count) {
	if (count > 1) {
		rz_strbuf_appendf(sb, "\t%s %s[%d];\n", ctype, name, count);
	} else {
		rz_strbuf_appendf(sb, "\t%s %s;\n", ctype, name);
	}
}

static void pf_field_to_member(RzStrBuf *sb, const RzPfField *fld, int idx) {
	char namebuf[32];
	const char *name = fld->name;
	if (RZ_STR_ISEMPTY(name)) {
		snprintf(namebuf, sizeof(namebuf), "field_%d", idx);
		name = namebuf;
	}
	int count = fld->array_count;

	switch (fld->type) {
	case RZ_PF_ALIGN: // cursor alignment: no storage
	case RZ_PF_TLV: // variable, self-describing: not expressible statically
		return;
	case RZ_PF_BITS: {
		int w = fld->bit_width > 0 ? fld->bit_width : 1;
		rz_strbuf_appendf(sb, "\t%s %s : %d;\n", uint_ctype_for_bits(w), name, w);
		return;
	}
	case RZ_PF_SKIP:
	case RZ_PF_HEXDUMP:
		pf_emit_member(sb, "uint8_t", name, count > 0 ? count : 1);
		return;
	case RZ_PF_GUID:
	case RZ_PF_UINT128:
		pf_emit_member(sb, "uint8_t", name, 16);
		return;
	case RZ_PF_BITVEC:
		pf_emit_member(sb, "uint8_t", name, fld->bit_width > 0 ? (fld->bit_width + 7) / 8 : 1);
		return;
	case RZ_PF_ZSTRING:
		// only a fixed-length [N]z can be sized; bare z is best-effort char *
		if (fld->str_fixed_len > 0) {
			rz_strbuf_appendf(sb, "\tchar %s[%d];\n", name, fld->str_fixed_len);
		} else {
			rz_strbuf_appendf(sb, "\tchar *%s;\n", name);
		}
		return;
	case RZ_PF_STRPTR:
		rz_strbuf_appendf(sb, "\tchar *%s;\n", name);
		return;
	case RZ_PF_POINTER:
		if (count > 1) {
			rz_strbuf_appendf(sb, "\tvoid *%s[%d];\n", name, count);
		} else {
			rz_strbuf_appendf(sb, "\tvoid *%s;\n", name);
		}
		return;
	case RZ_PF_STRUCT:
		if (RZ_STR_ISEMPTY(fld->type_name)) {
			pf_emit_member(sb, "uint8_t", name, count); // anonymous: placeholder byte
		} else if (count > 1) {
			rz_strbuf_appendf(sb, "\tstruct %s %s[%d];\n", fld->type_name, name, count);
		} else {
			rz_strbuf_appendf(sb, "\tstruct %s %s;\n", fld->type_name, name);
		}
		return;
	case RZ_PF_ENUM:
		if (RZ_STR_ISEMPTY(fld->type_name)) {
			pf_emit_member(sb, uint_ctype_for_bytes(fld->bit_width > 0 ? fld->bit_width : 4), name, count);
		} else if (count > 1) {
			rz_strbuf_appendf(sb, "\tenum %s %s[%d];\n", fld->type_name, name, count);
		} else {
			rz_strbuf_appendf(sb, "\tenum %s %s;\n", fld->type_name, name);
		}
		return;
	case RZ_PF_BITFIELD:
		pf_emit_member(sb, uint_ctype_for_bytes(fld->bitfield_size > 0 ? fld->bitfield_size : 4), name, count);
		return;
	case RZ_PF_TIMESTAMP:
		pf_emit_member(sb, pf_timefmt_ctype(fld->timefmt), name, count);
		return;
	case RZ_PF_CHAR:
		pf_emit_member(sb, "char", name, count);
		return;
	case RZ_PF_ULEB128: // variable length on the wire; modelled by widest value
		pf_emit_member(sb, "uint64_t", name, count);
		return;
	case RZ_PF_SLEB128:
		pf_emit_member(sb, "int64_t", name, count);
		return;
	case RZ_PF_FLOAT16: // no standard 2-byte float type; model storage width
		pf_emit_member(sb, "uint16_t", name, count);
		return;
	default: // hex / signed / unsigned / octal / binary scalars
		pf_emit_member(sb, rz_pf_field_ctype(fld->type), name, count);
		return;
	}
}

/**
 * \brief Convert a `pf` format string into an equivalent C declaration
 *
 * Parses \p fmt_str and renders a C `struct` (or `union`, when the format
 * begins with the `0` union marker) named \p name, using standard
 * fixed-width types. The result is a complete declaration ending in `;`,
 * ready to pass to rz_type_parse_string_stateless() so the format becomes
 * a registered RzBaseType. The conversion is structural: it consumes only
 * the parsed format, never a byte buffer. Specifiers with no exact static
 * C form are mapped best-effort (`@N` dropped, unsized `z` -> char *,
 * LEB128 widened, `?(Name)`/`E(Name)` -> struct/enum references).
 *
 * \param name Identifier for the generated struct/union
 * \param fmt_str A `pf` format string (the `fmt fieldnames` form)
 * \param error Optional; set to an owned error message on failure
 * \return Owned C declaration string, or NULL on failure
 */
RZ_API RZ_OWN char *rz_type_format_to_c_declaration(RZ_NONNULL const char *name,
	RZ_NONNULL const char *fmt_str, RZ_NULLABLE char **error) {
	rz_return_val_if_fail(name && fmt_str, NULL);
	if (RZ_STR_ISEMPTY(name) || RZ_STR_ISEMPTY(fmt_str)) {
		if (error) {
			*error = rz_str_dup("empty type name or format string");
		}
		return NULL;
	}
	RzPfFormat *fmt = rz_pf_parse(fmt_str);
	if (!fmt || fmt->nfields <= 0) {
		if (error) {
			char *diag = fmt ? rz_pf_format_errors_to_string(fmt) : NULL;
			*error = diag ? diag : rz_str_dup("pf format defined no fields");
		}
		rz_pf_format_free(fmt);
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_strbuf_appendf(sb, "%s %s {\n", fmt->is_union ? "union" : "struct", name);
	for (int i = 0; i < fmt->nfields; i++) {
		pf_field_to_member(sb, &fmt->fields[i], i);
	}
	rz_strbuf_append(sb, "};");
	rz_pf_format_free(fmt);
	return rz_strbuf_drain(sb);
}

/* True iff `type` is a POINTER whose pointee resolves -- by walking
 * through typedef chains in the typedb -- to an atomic base type named
 * exactly `atomic_name`.  This is the typedb-aware counterpart of the
 * rz_type_is_*_ptr helpers in librz/type/helpers.c, which compare the
 * raw identifier name and so do not see through typedef chains like
 * PVOID -> VOID -> void or LPSTR -> CHAR -> char.  Walks at most
 * RZ_TYPE_FORMAT_PTR_RESOLVE_MAX_DEPTH typedef hops so a circular
 * typedef cannot send the resolver into an infinite loop.
 */
#define RZ_TYPE_FORMAT_PTR_RESOLVE_MAX_DEPTH 16

static bool ptr_pointee_resolves_to(const RzTypeDB *typedb, const RzType *type, const char *atomic_name) {
	if (!type || type->kind != RZ_TYPE_KIND_POINTER || !atomic_name) {
		return false;
	}
	const RzType *ptr = type->pointer.type;
	if (!ptr || ptr->kind != RZ_TYPE_KIND_IDENTIFIER ||
		ptr->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED ||
		!ptr->identifier.name) {
		return false;
	}
	const char *cur_name = ptr->identifier.name;
	for (int i = 0; i < RZ_TYPE_FORMAT_PTR_RESOLVE_MAX_DEPTH && cur_name; i++) {
		if (!strcmp(cur_name, atomic_name)) {
			return true;
		}
		RzBaseType *btyp = rz_type_db_get_base_type(typedb, cur_name);
		if (!btyp) {
			return false;
		}
		if (btyp->kind == RZ_BASE_TYPE_KIND_ATOMIC) {
			return btyp->name && !strcmp(btyp->name, atomic_name);
		}
		if (btyp->kind != RZ_BASE_TYPE_KIND_TYPEDEF || !btyp->type ||
			btyp->type->kind != RZ_TYPE_KIND_IDENTIFIER ||
			!btyp->type->identifier.name) {
			return false;
		}
		cur_name = btyp->type->identifier.name;
	}
	return false;
}

static void type_to_format(const RzTypeDB *typedb, RzStrBuf *buf, RzType *type) {
	if (type->kind == RZ_TYPE_KIND_IDENTIFIER) {
		const char *format = rz_type_db_format_get(typedb, type->identifier.name);
		if (format) {
			rz_strbuf_append(buf, format);
		} else {
			if (type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_STRUCT ||
				type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNION) {
				rz_strbuf_append(buf, "?");
			} else if (type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_ENUM) {
				rz_strbuf_append(buf, "E");
			} else {
				RzBaseType *btyp = rz_type_get_base_type(typedb, type);
				if (btyp) {
					RzStrBuf *fields = rz_strbuf_new("");
					base_type_to_format_no_unfold(typedb, btyp, type->identifier.name, buf, fields);
					rz_strbuf_free(fields);
				}
			}
		}
	} else if (type->kind == RZ_TYPE_KIND_ARRAY) {
		rz_strbuf_appendf(buf, "[%" PFMT64d "]", type->array.count);
		type_to_format(typedb, buf, type->array.type);
	} else if (type->kind == RZ_TYPE_KIND_POINTER) {
		// Pointer-to-void via a typedef chain (PVOID -> VOID -> void,
		// LPVOID -> PVOID -> VOID -> void, HANDLE -> ... -> void) must
		// emit a self-contained `p` token rather than the recursive
		// `*<inner>` fallback, which would leave an orphan `*` because
		// `void` has no pf format of its own.  The rz_type_is_void_ptr
		// helper only matches the raw identifier name "void", so it
		// does not see through these typedef chains;
		// ptr_pointee_resolves_to does.
		//
		// Pointer-to-char is intentionally NOT folded here: the
		// recursive walker already produces `*c` (pointer-deref to a
		// 1-byte signed char), which is a valid pf spec under the new
		// parser and is what callers such as `avgp` for a `char *`
		// global variable already expect (showing the pointer literal
		// rather than reinterpreting the pointer bytes as an inline
		// string).
		if (ptr_pointee_resolves_to(typedb, type, "void")) {
			rz_strbuf_append(buf, "p");
			return;
		}
		rz_strbuf_append(buf, "*");
		type_to_format(typedb, buf, type->pointer.type);
	}
}

/**
 * \brief Represents the RzType as a `pf` format string
 *
 * Different from the similar function for the RzBaseType,
 * since the latter shows the pair of <format> <fields>,
 * while this implementation produces only the <format> part.
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_as_format(const RzTypeDB *typedb, RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	if (type->kind == RZ_TYPE_KIND_CALLABLE) {
		// We can't print anything useful for function type
		// Thus we consider this is just a `void *` pointer
		return rz_str_dup("p");
	}
	// Special case of callable ptr or `void *`
	if (rz_type_is_void_ptr(type) || rz_type_is_callable_ptr(type)) {
		return rz_str_dup("p");
	}
	// Special case of `char *`
	if (rz_type_is_char_ptr(type)) {
		return rz_str_dup("z");
	}
	RzStrBuf *buf = rz_strbuf_new(NULL);
	type_to_format(typedb, buf, type);
	return rz_strbuf_drain(buf);
}

static bool type_to_format_pair(const RzTypeDB *typedb, RzStrBuf *format, RzStrBuf *fields, RZ_NULLABLE const char *identifier, RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && format && fields && type, false);
	if (type->kind == RZ_TYPE_KIND_IDENTIFIER) {
		if (!type->identifier.name) {
			return false;
		}
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			return false;
		}
		base_type_to_format_unfold(typedb, btype, format, fields, identifier);
	} else if (type->kind == RZ_TYPE_KIND_ARRAY) {
		rz_strbuf_appendf(format, "[%" PFMT64d "]", type->array.count);
		return type_to_format_pair(typedb, format, fields, identifier, type->array.type);
	} else if (type->kind == RZ_TYPE_KIND_POINTER) {
		// We can't print anything useful for function type pointer
		if (rz_type_is_callable_ptr_nested(type)) {
			// Thus we consider this is just a `void *` pointer
			rz_strbuf_append(format, "p");
			const char *name = rz_type_identifier(type);
			// Callables are allowed to have empty names
			if (name) {
				rz_strbuf_appendf(fields, "%s ", name);
			}
		} else if (ptr_pointee_resolves_to(typedb, type, "void")) {
			// Same orphan-`*` issue as in type_to_format: emit a
			// self-contained `p` and the field name so the resulting
			// pair (e.g. "p" + "(PVOID)lpSecurityDescriptor")
			// parses cleanly under the new pf DSL.  Pointer-to-char
			// is intentionally NOT folded -- see the matching comment
			// in type_to_format.
			rz_strbuf_append(format, "p");
			if (identifier) {
				rz_strbuf_appendf(fields, "%s ", identifier);
			}
		} else {
			rz_strbuf_append(format, "*");
			return type_to_format_pair(typedb, format, fields, identifier, type->pointer.type);
		}
	} else if (type->kind == RZ_TYPE_KIND_CALLABLE) {
		// We can't print anything useful for function type
		// Thus we consider this is just a `void *` pointer
		rz_strbuf_append(format, "p");
		// Callables are allowed to have empty names
		if (type->callable->name) {
			rz_strbuf_appendf(fields, "%s ", type->callable->name);
		}
	}
	return true;
}

/**
 * \brief Represents the RzType as a `pf` format string pair
 *
 * Different from the similar `rz_type_as_format` and similar
 * to the `rz_base_type_as_format` since the latter shows
 * the pair of <format> <fields>.
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_as_format_pair(const RzTypeDB *typedb, RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	RzStrBuf *format = rz_strbuf_new("");
	RzStrBuf *fields = rz_strbuf_new("");
	if (!type_to_format_pair(typedb, format, fields, NULL, type)) {
		rz_strbuf_free(format);
		rz_strbuf_free(fields);
		return NULL;
	}
	char *fieldstr = rz_strbuf_drain(fields);
	rz_strbuf_appendf(format, " %s", fieldstr);
	free(fieldstr);
	char *bufstr = rz_strbuf_drain(format);
	rz_str_trim_tail(bufstr);
	return bufstr;
}

/**
 * \brief Look up a named pf format string.
 *
 * Format names are stored case-sensitively in the typedb's `formats` hash
 * (RzTypeDB::formats). Returns a borrowed pointer into the table -- do
 * not free.
 *
 * \param typedb Type database.
 * \param name Format name (e.g. "pe_dos_header", "elf_section").
 * \return Format string, or NULL if no such name is registered.
 */
RZ_API const char *rz_type_db_format_get(const RzTypeDB *typedb, const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	bool found = false;
	const char *result = ht_ss_find(typedb->formats, name, &found);
	if (!found || !result) {
		return NULL;
	}
	return result;
}

/**
 * \brief Register or replace a named pf format.
 *
 * The stored string is owned by the hash; an internal copy is made so
 * the caller may free \p fmt after this call.
 */
RZ_API void rz_type_db_format_set(RzTypeDB *typedb, const char *name, const char *fmt) {
	rz_return_if_fail(typedb && name && fmt);
	ht_ss_insert(typedb->formats, name, rz_str_dup(fmt));
}

static bool format_collect_cb(void *user, const char *k, const char *v) {
	rz_return_val_if_fail(user && k && v, false);
	RzList *l = user;
	RzTypeFormat *fmt = RZ_NEW0(RzTypeFormat);
	fmt->name = k;
	fmt->body = v;
	rz_list_append(l, fmt);
	return true;
}

/**
 * \brief Enumerate every registered named format.
 *
 * Returned list owns the RzTypeFormat shells, but their \c name and
 * \c body pointers are borrowed from the hash and must not be freed.
 */
RZ_API RZ_OWN RzList /*<RzTypeFormat *>*/ *rz_type_db_format_all(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *formats = rz_list_newf(free);
	ht_ss_foreach(typedb->formats, format_collect_cb, formats);
	return formats;
}

/**
 * \brief Remove a single registered named format.
 *
 * No-op if the name is not registered.
 */
RZ_API void rz_type_db_format_delete(RzTypeDB *typedb, const char *name) {
	rz_return_if_fail(typedb && name);
	ht_ss_delete(typedb->formats, name);
}
