// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_bin_stabs.h>
#include <rz_endian.h>
#include <rz_type.h>
#include <rz_util.h>

/**
 * \file stabs.c
 * \brief Parser for the legacy STABS debug information format.
 *
 * The `.stab` section is an array of fixed-size 12-byte records. Each record is
 * laid out (little- or big-endian, matching the host object) as:
 *
 *     | n_strx (4) | n_type (1) | n_other (1) | n_desc (2) | n_value (4) |
 *
 * The strings referenced by `n_strx` live in the `.stabstr` section. STABS files
 * can be the concatenation of several compilation units; the first record of
 * each unit is an `N_UNDF` header whose `n_value` is the size of that unit's
 * slice of the string table, so string offsets must be rebased per unit.
 */

static bool stabs_big_endian(RzBinFile *bf) {
	return bf->o && bf->o->info ? bf->o->info->big_endian : false;
}

static RzBinSection *stabs_section(RzBinFile *bf, const char *name) {
	rz_return_val_if_fail(bf && name, NULL);
	RzBinObject *o = bf->o;
	if (!o || !o->sections) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (o->sections, it) {
		RzBinSection *s = *it;
		if (s && RZ_STR_EQ(s->name, name)) {
			return s;
		}
	}
	// some toolchains prefix the section names, fall back to a suffix match
	rz_pvector_foreach (o->sections, it) {
		RzBinSection *s = *it;
		if (s && RZ_STR_ISNOTEMPTY(s->name) && rz_str_endswith(s->name, name)) {
			return s;
		}
	}
	return NULL;
}

static ut8 *stabs_read_section(RzBinFile *bf, RzBinSection *section, ut64 *out_len) {
	if (!section || section->paddr >= bf->size) {
		return NULL;
	}
	ut64 len = RZ_MIN(section->size, bf->size - section->paddr);
	if (!len) {
		return NULL;
	}
	// Allocate one extra byte and keep it zeroed so the buffer is always safe to
	// treat as a NUL-terminated string (the `.stabstr` table is not guaranteed
	// to end with a NUL on malformed input).
	ut8 *buf = calloc(len + 1, 1);
	if (!buf) {
		return NULL;
	}
	if (rz_buf_read_at(bf->buf, section->paddr, buf, len) != (st64)len) {
		free(buf);
		return NULL;
	}
	*out_len = len;
	return buf;
}

/**
 * \brief Parse the STABS information contained in a binary
 *
 * Reads the `.stab` and `.stabstr` sections, decodes every fixed-size record and
 * resolves its string (rebasing the per-compilation-unit string offsets).
 *
 * \param bf The binary file to read the STABS sections from
 * \return A newly allocated \ref RzBinStabs (owned by the caller), or NULL if the
 *         binary has no usable STABS data
 */
RZ_API RZ_OWN RzBinStabs *rz_bin_stabs_parse(RZ_NONNULL RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinSection *stab_sec = stabs_section(bf, ".stab");
	RzBinSection *stabstr_sec = stabs_section(bf, ".stabstr");
	if (!stab_sec || !stabstr_sec) {
		return NULL;
	}

	ut64 stab_len = 0;
	ut8 *stab_buf = stabs_read_section(bf, stab_sec, &stab_len);
	if (!stab_buf) {
		return NULL;
	}
	if (stab_len < RZ_BIN_STABS_RECORD_SIZE) {
		free(stab_buf);
		return NULL;
	}

	RzBinStabs *stabs = RZ_NEW0(RzBinStabs);
	if (!stabs) {
		free(stab_buf);
		return NULL;
	}
	stabs->big_endian = stabs_big_endian(bf);
	stabs->str = (char *)stabs_read_section(bf, stabstr_sec, &stabs->str_size);
	rz_vector_init(&stabs->entries, sizeof(RzBinStabsEntry), NULL, NULL);

	const bool be = stabs->big_endian;
	// .stab must contain a whole number of fixed-size records; a trailing
	// partial record (corrupted input) is ignored.
	if (stab_len % RZ_BIN_STABS_RECORD_SIZE) {
		RZ_LOG_DEBUG("stabs: .stab size %" PFMT64u " is not a multiple of %d, ignoring trailing bytes\n",
			stab_len, RZ_BIN_STABS_RECORD_SIZE);
	}
	const size_t count = stab_len / RZ_BIN_STABS_RECORD_SIZE;
	// stab_len is already bounded by the file size (see stabs_read_section), so
	// only cap the up-front reservation to avoid a large allocation from a
	// crafted section size; the vector still grows to hold every record.
	rz_vector_reserve(&stabs->entries, RZ_MIN(count, 0x1000));

	// Base offset into the string table for the current compilation unit. STABS
	// strings are split into per-unit slices: each unit opens with an N_UNDF
	// header record whose `value` field holds the byte size of that unit's
	// slice, so the next unit's strings start right after it.
	ut64 str_base = 0;
	ut64 unit_str_size = 0;
	for (size_t i = 0; i < count; i++) {
		const ut8 *p = stab_buf + i * RZ_BIN_STABS_RECORD_SIZE;
		RzBinStabsEntry e = { 0 };
		e.strx = rz_read_at_ble32(p, 0, be);
		e.type = p[4];
		e.other = p[5];
		e.desc = rz_read_at_ble16(p, 6, be);
		e.value = rz_read_at_ble32(p, 8, be);
		if (e.type == RZ_BIN_STABS_N_UNDF) {
			// new compilation unit: advance the base past the previous unit's
			// slice and remember the size of this one (from its header value)
			str_base += unit_str_size;
			unit_str_size = e.value;
		}
		ut64 off = str_base + e.strx;
		e.string = (e.strx && stabs->str && off < stabs->str_size)
			? stabs->str + off
			: NULL;
		rz_vector_push(&stabs->entries, &e);
	}
	free(stab_buf);
	return stabs;
}

/**
 * \brief Free a \ref RzBinStabs and everything it owns
 *
 * \param stabs The object to free, may be NULL
 */
RZ_API void rz_bin_stabs_free(RZ_NULLABLE RzBinStabs *stabs) {
	if (!stabs) {
		return;
	}
	rz_vector_fini(&stabs->entries);
	free(stabs->str);
	free(stabs);
}

/**
 * \brief Build source line information from parsed STABS data
 *
 * Only the records relevant to line information are used: N_SO selects the
 * current source file, N_FUN gives the base address of the current function and
 * N_SLINE carries a line number together with an offset relative to that
 * function. The result can be merged into RzBinObject.lines just like the
 * DWARF line program output.
 *
 * \param stabs The parsed STABS data
 * \return A newly allocated RzBinSourceLineInfo owned by the caller, or NULL on
 *         allocation failure
 */
RZ_API RZ_OWN RzBinSourceLineInfo *rz_bin_stabs_source_line_info(RZ_NONNULL const RzBinStabs *stabs) {
	rz_return_val_if_fail(stabs, NULL);
	RzBinSourceLineInfoBuilder builder;
	rz_bin_source_line_info_builder_init(&builder);

	char *comp_dir = NULL; // directory carried by a trailing-'/' N_SO
	char *cur_file = NULL; // full path of the current source file
	ut64 func_base = 0; // address of the current N_FUN
	bool have_func = false;

	RzBinStabsEntry *e;
	rz_vector_foreach (&stabs->entries, e) {
		switch (e->type) {
		case RZ_BIN_STABS_N_SO:
			if (RZ_STR_ISEMPTY(e->string)) {
				// closing N_SO: the value is the first address no longer
				// covered, emit a closing sample like DW_LNE_end_sequence
				rz_bin_source_line_info_builder_push_sample(&builder, e->value, 0, 0, NULL);
				RZ_FREE(cur_file);
				RZ_FREE(comp_dir);
				have_func = false;
				func_base = 0;
			} else if (rz_str_endswith(e->string, "/")) {
				free(comp_dir);
				comp_dir = rz_str_dup(e->string);
			} else {
				free(cur_file);
				cur_file = comp_dir
					? rz_str_newf("%s%s", comp_dir, e->string)
					: rz_str_dup(e->string);
			}
			break;
		case RZ_BIN_STABS_N_FUN:
			if (RZ_STR_ISNOTEMPTY(e->string)) {
				// a function definition: subsequent N_SLINE offsets are
				// relative to this address
				func_base = e->value;
				have_func = true;
			}
			break;
		case RZ_BIN_STABS_N_SLINE: {
			ut64 addr = have_func ? func_base + e->value : e->value;
			rz_bin_source_line_info_builder_push_sample(&builder, addr, e->desc, 0, cur_file);
			break;
		}
		default:
			break;
		}
	}

	free(cur_file);
	free(comp_dir);
	return rz_bin_source_line_info_builder_build_and_fini(&builder);
}

/* ------------------------------------------------------------------------- *
 *  Symbol, type and variable extraction                                     *
 * ------------------------------------------------------------------------- */

/*
 * The higher level information lives in the record strings, encoded with the
 * STABS type-descriptor grammar. It is a recursive (context-free) grammar:
 * aggregates nest arbitrarily (a struct member may be a pointer to an array of
 * another struct, ...), so it is handled with a recursive-descent parser, the
 * same approach rizin already uses for its DWARF and C/C++ type parsers. A
 * rough sketch of the grammar:
 *
 *   type     := typenum [ '=' typedef ]
 *   typenum  := '(' int ',' int ')' | int
 *   typedef  := range | pointer | array | struct | union | enum | xref | func | type
 *   range    := 'r' typenum ';' int ';' int ';'
 *   pointer  := '*' type
 *   array    := 'ar' type ';' int ';' int ';' type
 *   struct   := 's' size { member } ';'     ( union := 'u' size { member } ';' )
 *   member   := name ':' type ',' bitoff ',' bitsize ';'
 *   enum     := 'e' { name ':' int ',' } ';'
 *   xref     := 'x' ('s'|'u'|'e') name ':'
 *   func     := 'f' type
 *
 * See https://sourceware.org/gdb/onlinedocs/stabs.html for the full grammar.
 */

/// Encode a STABS type number (file, number) into a single key.
#define STABS_TYPE_KEY(file, num) (((ut64)(ut32)(file) << 32) | (ut32)(num))

/// Upper bound on the type-descriptor recursion, to reject pathologically
/// nested types from a crafted binary without overflowing the stack.
#define STABS_MAX_TYPE_DEPTH 64

typedef struct {
	RzTypeDB *typedb;
	HtUP /*<ut64, RzType *>*/ *types; ///< canonical RzType per STABS type id, owned by the table
	ut32 anon_counter; ///< used to name untagged structs, unions and enums
	ut32 depth; ///< current type-descriptor recursion depth
} StabsTypeParser;

static RzType *stabs_type_parse(StabsTypeParser *tp, const char **pp);

static RzType *stabs_ident(const char *name, RzTypeIdentifierKind kind) {
	RzType *t = RZ_NEW0(RzType);
	if (!t) {
		return NULL;
	}
	t->kind = RZ_TYPE_KIND_IDENTIFIER;
	t->identifier.kind = kind;
	t->identifier.name = rz_str_dup(name);
	t->identifier.is_const = false;
	return t;
}

/// Parse a type number "(file,num)" or a bare "num", advancing \p pp.
static bool stabs_typenum(const char **pp, ut64 *key) {
	const char *p = *pp;
	if (*p == '(') {
		p++;
		char *end = NULL;
		long file = strtol(p, &end, 10);
		if (end == p || *end != ',') {
			return false;
		}
		p = end + 1;
		long num = strtol(p, &end, 10);
		if (end == p || *end != ')') {
			return false;
		}
		*key = STABS_TYPE_KEY(file, num);
		*pp = end + 1;
		return true;
	}
	if (IS_DIGIT(*p)) {
		char *end = NULL;
		long num = strtol(p, &end, 10);
		if (end == p) {
			return false;
		}
		*key = STABS_TYPE_KEY(0, num);
		*pp = end;
		return true;
	}
	return false;
}

/// Parse a range descriptor "r<typeref>;lo;hi;" (already past 'r') and derive
/// the size, signedness and whether it is a floating point type.
static void stabs_parse_range(const char **pp, ut64 *size_bits, bool *is_signed, bool *is_float) {
	const char *p = *pp;
	ut64 dummy = 0;
	stabs_typenum(&p, &dummy);
	if (*p == ';') {
		p++;
	}
	const char *lo = p;
	bool lo_neg = (*p == '-');
	while (*p && *p != ';') {
		p++;
	}
	size_t lo_len = p - lo;
	if (*p == ';') {
		p++;
	}
	const char *hi = p;
	bool hi_neg = (*p == '-');
	while (*p && *p != ';') {
		p++;
	}
	size_t hi_len = p - hi;
	if (*p == ';') {
		p++;
	}
	*pp = p;

	*is_float = false;
	*is_signed = lo_neg;
	// Floating point is encoded as "r(ref);bytes;0;".
	if (hi_len == 1 && hi[0] == '0' && !lo_neg && lo_len > 0 && !(lo_len == 1 && lo[0] == '0')) {
		*is_float = true;
		*is_signed = true;
		*size_bits = (ut64)strtoull(lo, NULL, 10) * 8;
		return;
	}
	// "0;-1" is GCC's unsigned with no fixed upper bound; treat as 4 byte unsigned.
	if (!lo_neg && lo_len == 1 && lo[0] == '0' && hi_neg) {
		*is_signed = false;
		*size_bits = 32;
		return;
	}
	ut64 hival = hi_neg ? 0 : (ut64)strtoull(hi, NULL, 10);
	ut64 bytes;
	if (lo_neg) {
		bytes = hival <= 0x7fULL ? 1 : hival <= 0x7fffULL ? 2
			: hival <= 0x7fffffffULL                  ? 4
								  : 8;
		*is_signed = true;
	} else {
		bytes = hival <= 0xffULL ? 1 : hival <= 0xffffULL ? 2
			: hival <= 0xffffffffULL                  ? 4
								  : 8;
		*is_signed = false;
	}
	*size_bits = bytes * 8;
}

static const char *stabs_atomic_name(ut64 size_bits, bool is_signed, bool is_float) {
	if (is_float) {
		switch (size_bits) {
		case 32: return "float";
		case 64: return "double";
		default: return "long double";
		}
	}
	if (is_signed) {
		switch (size_bits) {
		case 8: return "char";
		case 16: return "short";
		case 32: return "int";
		default: return "long";
		}
	}
	switch (size_bits) {
	case 8: return "unsigned char";
	case 16: return "unsigned short";
	case 32: return "unsigned int";
	default: return "unsigned long";
	}
}

/// Register an atomic base type (unless one with that name already exists) and
/// return a fresh identifier referencing it.
static RzType *stabs_atomic(StabsTypeParser *tp, const char *name, ut64 size_bits) {
	if (!rz_type_db_get_base_type(tp->typedb, name)) {
		RzBaseType *bt = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
		if (bt) {
			bt->name = rz_str_dup(name);
			bt->size = size_bits;
			bt->type = stabs_ident(name, RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
			rz_type_db_save_base_type(tp->typedb, bt);
		}
	}
	return stabs_ident(name, RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
}

/// Register a typedef "name" aliasing \p target and return identifier(name).
static RzType *stabs_make_typedef(StabsTypeParser *tp, const char *name, const RzType *target) {
	if (!rz_type_db_get_base_type(tp->typedb, name)) {
		RzBaseType *bt = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
		if (bt) {
			bt->name = rz_str_dup(name);
			bt->type = target ? rz_type_clone(target) : stabs_ident("void", RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
			rz_type_db_save_base_type(tp->typedb, bt);
		}
	}
	return stabs_ident(name, RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
}

/// Parse a struct/union body "<size><member>...;", already past 's'/'u'.
static RzType *stabs_struct_union(StabsTypeParser *tp, const char **pp, const char *name, bool is_struct) {
	const char *p = *pp;
	char *end = NULL;
	ut64 size_bytes = (ut64)strtoull(p, &end, 10);
	p = end;

	char synth[64];
	if (!name) {
		rz_strf(synth, "anonymous %s %u", is_struct ? "struct" : "union", tp->anon_counter++);
		name = synth;
	}

	RzTypeIdentifierKind ik = is_struct ? RZ_TYPE_IDENTIFIER_KIND_STRUCT : RZ_TYPE_IDENTIFIER_KIND_UNION;
	if (name && rz_type_db_get_base_type(tp->typedb, name)) {
		// already defined: skip the body and just reference it
		while (*p && *p != ';') {
			p++;
		}
		if (*p == ';') {
			p++;
		}
		*pp = p;
		return stabs_ident(name, ik);
	}

	RzBaseType *bt = rz_type_base_type_new(is_struct ? RZ_BASE_TYPE_KIND_STRUCT : RZ_BASE_TYPE_KIND_UNION);
	if (!bt) {
		*pp = p;
		return NULL;
	}
	bt->name = rz_str_dup(name);
	bt->size = size_bytes * 8;

	while (*p && *p != ';') {
		const char *ms = p;
		while (*p && *p != ':') {
			p++;
		}
		char *mname = rz_str_ndup(ms, p - ms);
		if (*p == ':') {
			p++;
		}
		RzType *mtype = stabs_type_parse(tp, &p);
		ut64 bitoff = 0;
		if (*p == ',') {
			p++;
			bitoff = (ut64)strtoull(p, &end, 10);
			p = end;
		}
		if (*p == ',') {
			p++;
			(void)strtoull(p, &end, 10); // bit size, unused for non-bitfields
			p = end;
		}
		if (*p == ';') {
			p++;
		}
		if (is_struct) {
			RzTypeStructMember member = { .name = mname, .type = mtype, .offset = bitoff / 8, .size = 0 };
			rz_vector_push(&bt->struct_data.members, &member);
		} else {
			RzTypeUnionMember member = { .name = mname, .type = mtype, .offset = bitoff / 8, .size = 0 };
			rz_vector_push(&bt->union_data.members, &member);
		}
	}
	if (*p == ';') {
		p++;
	}
	*pp = p;

	RzType *ident = stabs_ident(bt->name, ik);
	rz_type_db_save_base_type(tp->typedb, bt);
	return ident;
}

/// Parse an enum body "name:val,...;", already past 'e'.
static RzType *stabs_enum(StabsTypeParser *tp, const char **pp, const char *name) {
	const char *p = *pp;
	char synth[64];
	if (!name) {
		rz_strf(synth, "anonymous enum %u", tp->anon_counter++);
		name = synth;
	}
	if (name && rz_type_db_get_base_type(tp->typedb, name)) {
		while (*p && *p != ';') {
			p++;
		}
		if (*p == ';') {
			p++;
		}
		*pp = p;
		return stabs_ident(name, RZ_TYPE_IDENTIFIER_KIND_ENUM);
	}

	RzBaseType *bt = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!bt) {
		*pp = p;
		return NULL;
	}
	bt->name = rz_str_dup(name);
	bt->size = 32;
	bt->type = stabs_ident("int", RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);

	char *end = NULL;
	while (*p && *p != ';') {
		const char *cs = p;
		while (*p && *p != ':') {
			p++;
		}
		char *cname = rz_str_ndup(cs, p - cs);
		if (*p == ':') {
			p++;
		}
		st64 val = (st64)strtoll(p, &end, 10);
		p = end;
		if (*p == ',') {
			p++;
		}
		RzTypeEnumCase ec = { .name = cname, .val = val };
		rz_vector_push(&bt->enum_data.cases, &ec);
	}
	if (*p == ';') {
		p++;
	}
	*pp = p;

	RzType *ident = stabs_ident(bt->name, RZ_TYPE_IDENTIFIER_KIND_ENUM);
	rz_type_db_save_base_type(tp->typedb, bt);
	return ident;
}

/// Parse a type definition that follows '=' and register the canonical type
/// for \p key. Returns an owned RzType.
static RzType *stabs_type_def(StabsTypeParser *tp, const char **pp, ut64 key, const char *name) {
	const char *p = *pp;
	RzType *t = NULL;
	char d = *p;

	if (d == '(' || d == '-' || IS_DIGIT(d)) {
		RzType *other = stabs_type_parse(tp, &p);
		if (name) {
			t = stabs_make_typedef(tp, name, other);
			rz_type_free(other);
		} else {
			t = other;
		}
	} else if (!d) {
		// The descriptor string ended prematurely (truncated or malformed
		// input): treat the missing type as void, without advancing past the
		// NUL terminator so the caller does not read out of bounds.
		t = stabs_ident("void", RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
	} else {
		p++; // consume the descriptor character
		switch (d) {
		case 'r': {
			ut64 sz = 32;
			bool sg = true, fl = false;
			stabs_parse_range(&p, &sz, &sg, &fl);
			t = stabs_atomic(tp, name ? name : stabs_atomic_name(sz, sg, fl), sz);
			break;
		}
		case '*': {
			RzType *inner = stabs_type_parse(tp, &p);
			t = RZ_NEW0(RzType);
			if (t) {
				t->kind = RZ_TYPE_KIND_POINTER;
				t->pointer.type = inner;
				t->pointer.is_const = false;
			} else {
				rz_type_free(inner);
			}
			break;
		}
		case 'a': {
			if (*p == 'r') {
				p++; // "ar"
			}
			RzType *idx = stabs_type_parse(tp, &p);
			rz_type_free(idx);
			char *end = NULL;
			if (*p == ';') {
				p++;
			}
			st64 lo = (st64)strtoll(p, &end, 10);
			p = end;
			if (*p == ';') {
				p++;
			}
			st64 hi = (st64)strtoll(p, &end, 10);
			p = end;
			if (*p == ';') {
				p++;
			}
			RzType *elem = stabs_type_parse(tp, &p);
			t = RZ_NEW0(RzType);
			if (t) {
				t->kind = RZ_TYPE_KIND_ARRAY;
				t->array.type = elem;
				t->array.count = (hi >= lo) ? (ut64)(hi - lo + 1) : 0;
			} else {
				rz_type_free(elem);
			}
			break;
		}
		case 's':
		case 'u':
			t = stabs_struct_union(tp, &p, name, d == 's');
			break;
		case 'e':
			t = stabs_enum(tp, &p, name);
			break;
		case 'x': {
			char tag = *p;
			if (tag) {
				p++;
			}
			const char *xs = p;
			while (*p && *p != ':') {
				p++;
			}
			char *xname = rz_str_ndup(xs, p - xs);
			if (*p == ':') {
				p++;
			}
			RzTypeIdentifierKind ik = tag == 's' ? RZ_TYPE_IDENTIFIER_KIND_STRUCT
				: tag == 'u'                 ? RZ_TYPE_IDENTIFIER_KIND_UNION
				: tag == 'e'                 ? RZ_TYPE_IDENTIFIER_KIND_ENUM
							     : RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
			t = stabs_ident(xname, ik);
			free(xname);
			break;
		}
		case 'f':
			t = stabs_type_parse(tp, &p); // function returning type, approximated as the return type
			break;
		default:
			t = stabs_ident("void", RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
			break;
		}
	}

	*pp = p;
	if (t && key) {
		ht_up_update(tp->types, key, rz_type_clone(t));
	}
	return t;
}

static RzType *stabs_type_parse(StabsTypeParser *tp, const char **pp) {
	if (tp->depth >= STABS_MAX_TYPE_DEPTH) {
		return stabs_ident("void", RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
	}
	tp->depth++;
	const char *p = *pp;
	ut64 key = 0;
	RzType *t = NULL;
	if (stabs_typenum(&p, &key)) {
		if (*p == '=') {
			p++;
			t = stabs_type_def(tp, &p, key, NULL);
		} else {
			RzType *canon = ht_up_find(tp->types, key, NULL);
			t = canon ? rz_type_clone(canon) : stabs_ident("void", RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED);
		}
	} else {
		// no type number: a descriptor follows directly
		t = stabs_type_def(tp, &p, 0, NULL);
	}
	*pp = p;
	tp->depth--;
	return t;
}

static void stabs_symbol_free(RzBinStabsSymbol *sym) {
	if (!sym) {
		return;
	}
	free(sym->name);
	rz_type_free(sym->type);
	free(sym);
}

static void stabs_add_symbol(RzBinStabsDebugInfo *di, const char *name, RzBinStabsSymbolKind kind, RZ_OWN RzType *type, ut64 value, ut64 function) {
	RzBinStabsSymbol *sym = RZ_NEW0(RzBinStabsSymbol);
	if (!sym) {
		rz_type_free(type);
		return;
	}
	sym->name = rz_str_dup(name);
	sym->kind = kind;
	sym->type = type;
	sym->value = value;
	sym->function = function;
	rz_pvector_push(&di->symbols, sym);
}

static void stabs_finalize_callable(RzTypeDB *typedb, RzCallable **callable) {
	if (!*callable) {
		return;
	}
	if (!rz_type_func_save(typedb, *callable)) {
		rz_type_callable_free(*callable);
	}
	*callable = NULL;
}

static void stabs_process_symbol(StabsTypeParser *tp, RzBinStabsDebugInfo *di, const RzBinStabsEntry *e, ut64 *cur_func, RzCallable **callable) {
	const char *s = e->string;
	const char *colon = strchr(s, ':');
	if (!colon) {
		return;
	}
	char *name = (colon == s) ? NULL : rz_str_ndup(s, colon - s);
	const char *p = colon + 1;
	char desc = *p;

	// A missing descriptor letter (the type number starts right away) denotes a
	// local variable.
	if (desc == '(' || desc == '-' || IS_DIGIT(desc)) {
		RzType *t = stabs_type_parse(tp, &p);
		if (name) {
			stabs_add_symbol(di, name, RZ_BIN_STABS_SYMBOL_LOCAL, t, e->value, *cur_func);
		} else {
			rz_type_free(t);
		}
		free(name);
		return;
	}

	p++; // consume the descriptor letter
	switch (desc) {
	case 't': { // typedef or named atomic type
		ut64 key = 0;
		if (stabs_typenum(&p, &key)) {
			if (*p == '=') {
				p++;
				rz_type_free(stabs_type_def(tp, &p, key, name));
			} else {
				RzType *target = ht_up_find(tp->types, key, NULL);
				if (name && target) {
					rz_type_free(stabs_make_typedef(tp, name, target));
				}
			}
		}
		break;
	}
	case 'T': { // struct/union/enum tag
		ut64 key = 0;
		if (stabs_typenum(&p, &key) && *p == '=') {
			p++;
			rz_type_free(stabs_type_def(tp, &p, key, name));
		}
		break;
	}
	case 'G': { // global variable (address comes from the symbol table)
		RzType *t = stabs_type_parse(tp, &p);
		if (name) {
			stabs_add_symbol(di, name, RZ_BIN_STABS_SYMBOL_GLOBAL, t, 0, 0);
		} else {
			rz_type_free(t);
		}
		break;
	}
	case 'S':
	case 'V': { // file or function scope static
		RzType *t = stabs_type_parse(tp, &p);
		if (name) {
			stabs_add_symbol(di, name, RZ_BIN_STABS_SYMBOL_STATIC, t, e->value, 0);
		} else {
			rz_type_free(t);
		}
		break;
	}
	case 'F':
	case 'f': { // function
		stabs_finalize_callable(tp->typedb, callable);
		RzType *ret = stabs_type_parse(tp, &p);
		*cur_func = e->value;
		if (name) {
			stabs_add_symbol(di, name, RZ_BIN_STABS_SYMBOL_FUNCTION, rz_type_clone(ret), e->value, 0);
			*callable = rz_type_callable_new(name);
			if (*callable) {
				(*callable)->ret = ret;
				ret = NULL;
			}
		}
		rz_type_free(ret);
		break;
	}
	case 'p':
	case 'P': { // parameter
		RzType *t = stabs_type_parse(tp, &p);
		if (name) {
			stabs_add_symbol(di, name, RZ_BIN_STABS_SYMBOL_PARAMETER, rz_type_clone(t), e->value, *cur_func);
			if (*callable) {
				RzCallableArg *arg = rz_type_callable_arg_new(tp->typedb, name, t);
				t = NULL;
				if (arg) {
					rz_type_callable_arg_add(*callable, arg);
				}
			}
		}
		rz_type_free(t);
		break;
	}
	case 'r': { // register variable
		RzType *t = stabs_type_parse(tp, &p);
		if (name) {
			stabs_add_symbol(di, name, RZ_BIN_STABS_SYMBOL_LOCAL, t, e->value, *cur_func);
		} else {
			rz_type_free(t);
		}
		break;
	}
	default:
		break;
	}
	free(name);
}

/**
 * \brief Recover symbols, types and variables from parsed STABS data
 *
 * Walks the records and decodes the STABS type-descriptor grammar. Types and
 * function prototypes are registered directly into \p typedb; the functions,
 * global/static variables, parameters and local variables are returned so the
 * caller can turn them into analysis objects.
 *
 * \param stabs The parsed STABS data
 * \param typedb The type database the recovered types and prototypes are added to
 * \return A newly allocated \ref RzBinStabsDebugInfo owned by the caller, or NULL
 *         on allocation failure
 */
RZ_API RZ_OWN RzBinStabsDebugInfo *rz_bin_stabs_debug_info(RZ_NONNULL const RzBinStabs *stabs, RZ_NONNULL RzTypeDB *typedb) {
	rz_return_val_if_fail(stabs && typedb, NULL);
	RzBinStabsDebugInfo *di = RZ_NEW0(RzBinStabsDebugInfo);
	if (!di) {
		return NULL;
	}
	rz_pvector_init(&di->symbols, (RzPVectorFree)stabs_symbol_free);

	StabsTypeParser tp = {
		.typedb = typedb,
		.types = ht_up_new(NULL, (HtUPFreeValue)rz_type_free)
	};
	if (!tp.types) {
		rz_bin_stabs_debug_info_free(di);
		return NULL;
	}

	ut64 cur_func = 0;
	RzCallable *callable = NULL;
	RzBinStabsEntry *e;
	rz_vector_foreach (&stabs->entries, e) {
		if (RZ_STR_ISEMPTY(e->string)) {
			continue;
		}
		switch (e->type) {
		case RZ_BIN_STABS_N_GSYM:
		case RZ_BIN_STABS_N_STSYM:
		case RZ_BIN_STABS_N_LCSYM:
		case RZ_BIN_STABS_N_FUN:
		case RZ_BIN_STABS_N_LSYM:
		case RZ_BIN_STABS_N_PSYM:
		case RZ_BIN_STABS_N_RSYM:
			stabs_process_symbol(&tp, di, e, &cur_func, &callable);
			break;
		default:
			break;
		}
	}
	stabs_finalize_callable(typedb, &callable);
	ht_up_free(tp.types);
	return di;
}

/**
 * \brief Free a \ref RzBinStabsDebugInfo and everything it owns
 *
 * \param di The object to free, may be NULL
 */
RZ_API void rz_bin_stabs_debug_info_free(RZ_NULLABLE RzBinStabsDebugInfo *di) {
	if (!di) {
		return;
	}
	rz_pvector_fini(&di->symbols);
	free(di);
}
