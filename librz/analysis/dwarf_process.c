// SPDX-FileCopyrightText: 2012-2020 houndthe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <sdb.h>
#include <rz_analysis.h>
#include <rz_bin_dwarf.h>
#include <string.h>
#include "analysis_private.h"
#include "rz_vector.h"

typedef struct dwarf_parse_context_t {
	const RzAnalysis *analysis;
	Sdb *sdb;
	char *lang; // for demangling
	RzBinDwarf *dw;
} Context;

typedef struct dwarf_function_t {
	ut64 addr;
	const char *name;
	const char *signature;
	bool is_external;
	bool is_method;
	bool is_virtual;
	bool is_trampoline; // intermediary in making call to another func
	ut8 access; // public = 1, protected = 2, private = 3, if not set assume private
	ut64 vtable_addr; // location description
	ut64 call_conv; // normal || program || nocall
} Function;

typedef enum dwarf_location_kind {
	LOCATION_UNKNOWN = 0,
	LOCATION_GLOBAL = 1,
	LOCATION_BP = 2,
	LOCATION_SP = 3,
	LOCATION_REGISTER = 4,
	LOCATION_CFA = 5
} VariableLocationKind;

typedef struct dwarf_var_location_t {
	VariableLocationKind kind;
	ut64 address;
	ut64 reg_num;
	st64 offset;
	const char *reg_name; /* string literal */
} VariableLocation;

typedef struct dwarf_variable_t {
	RzBinDwarfLocation *location;
	char *name;
	char *type;
	RzAnalysisVarKind kind;
} Variable;

static void variable_free(Variable *var) {
	free(var->name);
	free(var->location);
	free(var->type);
	free(var);
}

static inline char *create_type_name_from_offset(ut64 offset) {
	return rz_str_newf("type_0x%" PFMT64x, offset);
}

/**
 * \brief Get the DIE name or create unique one from its offset
 *
 * \param die
 * \return char* DIEs name or NULL if error
 */
static char *die_name(const RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_name);
	char *name = NULL;
	if (attr) {
		const char *s = rz_bin_dwarf_attr_value_get_string_content(attr);
		name = RZ_STR_DUP(s);
	}
	return name ? name : create_type_name_from_offset(die->offset);
}

static RzPVector /*<RzBinDwarfDie *>*/ *die_children(RzBinDwarfDie *die, RzBinDwarf *dw) {
	RzPVector /*<RzBinDwarfDie *>*/ *vec = rz_pvector_new(NULL);
	if (!vec) {
		return NULL;
	}
	RzBinDwarfCompUnit *unit = ht_up_find(dw->info->unit_tbl, die->unit_offset, NULL);
	if (!unit) {
		goto err;
	}

	for (size_t i = die->index + 1; i < rz_vector_len(&unit->dies); ++i) {
		RzBinDwarfDie *child_die = rz_vector_index_ptr(&unit->dies, i);
		if (child_die->depth >= die->depth + 1) {
			rz_pvector_push(vec, child_die);
		} else if (child_die->depth == die->depth) {
			break;
		}
	}

	return vec;
err:
	rz_pvector_free(vec);
	return NULL;
}

/**
 * \brief Get the DIE size in bits
 *
 * \param die
 * \return ut64 size in bits or 0 if not found
 */
static ut64 die_byte_size(const RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_byte_size);
	if (attr) {
		return attr->uconstant * CHAR_BIT;
	}

	attr = rz_bin_dwarf_die_get_attr(die, DW_AT_bit_size);
	if (attr) {
		return attr->uconstant;
	}

	return 0;
}

/**
 * \brief Parse and return the count of an array or 0 if not found/not defined
 */
static ut64 parse_array_count(Context *ctx, RzBinDwarfDie *die) {
	if (!die->has_children) {
		return 0;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return 0;
	}

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		if (child_die->tag == DW_TAG_subrange_type) {
			RzBinDwarfAttr *value;
			rz_vector_foreach(&child_die->attrs, value) {
				switch (value->name) {
				case DW_AT_upper_bound:
				case DW_AT_count:
					rz_pvector_free(children);
					return value->uconstant + 1;
				default:
					break;
				}
			}
		}
	}
	rz_pvector_free(children);
	return 0;
}

static RzType *parse_type(Context *ctx, ut64 offset, RZ_NULLABLE ut64 *size, RZ_NONNULL SetU *visited);

/**
 * Parse the die's DW_AT_type type or return a void type or NULL if \p type_idx == -1
 *
 * \param allow_void whether to return a void type instead of NULL if there is no type defined
 */
static RzType *parse_type_in_die(Context *ctx, RzBinDwarfDie *die, bool allow_void, RZ_NULLABLE ut64 *size, RZ_NONNULL SetU *visited) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_type);
	if (!attr) {
		if (allow_void) {
			return rz_type_identifier_of_base_type_str(ctx->analysis->typedb, "void");
		}
		return NULL;
	}
	return parse_type(ctx, attr->reference, size, visited);
}

/**
 * \brief Recursively parses type entry of a certain offset and saves type size into *size
 *
 * \param ctx
 * \param offset offset of the type entry
 * \param size_out ptr to size of a type to fill up (can be NULL if unwanted)
 * \param set of visited die offsets, to prevent infinite recursion
 * \return the parsed RzType or NULL on failure
 */
static RzType *parse_type(Context *ctx, const ut64 offset, RZ_NULLABLE ut64 *size, RZ_NONNULL SetU *visited) {
	rz_return_val_if_fail(visited, NULL);
	if (set_u_contains(visited, offset)) {
		return NULL;
	}
	RzBinDwarfDie *die = ht_up_find(ctx->dw->info->die_tbl, offset, NULL);
	if (!die) {
		return NULL;
	}

	set_u_add(visited, offset);
	RzType *ret = NULL;
	// get size of first type DIE that has size
	if (size && *size == 0) {
		*size = die_byte_size(die);
	}
	switch (die->tag) {
	// this should be recursive search for the type until you find base/user defined type
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type: // C++ references are just pointers to us
	case DW_TAG_rvalue_reference_type: {
		RzType *pointee = parse_type_in_die(ctx, die, true, size, visited);
		if (!pointee) {
			goto end;
		}
		ret = rz_type_pointer_of_type(ctx->analysis->typedb, pointee, false);
		if (!ret) {
			rz_type_free(pointee);
		}
		break;
	}
	// We won't parse them as a complete type, because that will already be done
	// so just a name now
	case DW_TAG_typedef:
	case DW_TAG_base_type:
	case DW_TAG_structure_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type: {
		char *name = die_name(die);
		if (!name) {
			goto end;
		}
		ret = RZ_NEW0(RzType);
		if (!ret) {
			free(name);
			goto end;
		}
		ret->kind = RZ_TYPE_KIND_IDENTIFIER;
		ret->identifier.name = name;
		switch (die->tag) {
		case DW_TAG_structure_type:
			ret->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
			break;
		case DW_TAG_union_type:
			ret->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;
			break;
		case DW_TAG_enumeration_type:
			ret->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;
			break;
		default: break;
		}
		break;
	}
	case DW_TAG_subroutine_type: {
		RzType *return_type = parse_type_in_die(ctx, die, true, size, visited);
		if (!return_type) {
			goto end;
		}
		if (die->has_children) { // has parameters
			// TODO
		}
		RzCallable *callable = rz_type_callable_new(NULL);
		if (!callable) {
			rz_type_free(return_type);
			goto end;
		}
		ret = rz_type_callable(callable);
		if (!ret) {
			rz_type_callable_free(callable);
		}
		break;
	}
	case DW_TAG_array_type: {
		RzType *subtype = parse_type_in_die(ctx, die, false, size, visited);
		if (!subtype) {
			goto end;
		}
		ut64 count = parse_array_count(ctx, die);
		ret = rz_type_array_of_type(ctx->analysis->typedb, subtype, count);
		if (!ret) {
			rz_type_free(subtype);
		}
		break;
	}
	case DW_TAG_const_type: {
		ret = parse_type_in_die(ctx, die, false, size, visited);
		if (ret) {
			switch (ret->kind) {
			case RZ_TYPE_KIND_IDENTIFIER:
				ret->identifier.is_const = true;
				break;
			case RZ_TYPE_KIND_POINTER:
				ret->pointer.is_const = true;
				break;
			default:
				// const not supported yet for other kinds
				break;
			}
		}
		break;
	}
	case DW_TAG_volatile_type:
	case DW_TAG_restrict_type:
		// volatile and restrict attributes not supported in RzType
		ret = parse_type_in_die(ctx, die, false, size, visited);
		break;
	default:
		break;
	}
end:
	set_u_delete(visited, offset);
	return ret;
}

/**
 * \brief Convenience function for calling parse_type with an empty visited set
 * See documentation of parse_type
 */
static RzType *parse_type_outer(Context *ctx, const ut64 offset, ut64 *size) {
	SetU *visited = set_u_new();
	if (!visited) {
		return NULL;
	}
	RzType *r = parse_type(ctx, offset, size, visited);
	set_u_free(visited);
	return r;
}

/**
 * \brief Parses structured entry into *result RzTypeStructMember
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
 *
 * \param ctx
 * \param idx index of the current entry
 * \param result ptr to result member to fill up
 * \return RzTypeStructMember* ptr to parsed Member
 */
static RzTypeStructMember *parse_struct_member(Context *ctx, RzBinDwarfDie *die, RzTypeStructMember *result) {
	rz_return_val_if_fail(result, NULL);
	char *name = NULL;
	RzType *type = NULL;
	ut64 offset = 0;
	ut64 size = 0;
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			free(name);
			name = die_name(die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_type:
			rz_type_free(type);
			type = parse_type_outer(ctx, attr->reference, &size);
			break;
		case DW_AT_data_member_location:
			/*
				2 cases, 1.: If val is integer, it offset in bytes from
				the beginning of containing entity. If containing entity has
				a bit offset, member has that bit offset aswell
				2.: value is a location description
				http://www.dwarfstd.org/doc/DWARF4.pdf#page=39&zoom=100,0,0
			*/
			offset = attr->uconstant;
			break;
		case DW_AT_accessibility: // private, public etc.
		case DW_AT_mutable: // flag is it is mutable
		case DW_AT_data_bit_offset:
			/*
				int that specifies the number of bits from beginning
				of containing entity to the beginning of the data member
			*/
			break;
		// If the size of a data member is not the same as the
		//  size of the type given for the data member
		case DW_AT_byte_size:
			size = attr->uconstant * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = attr->uconstant;
			break;
		case DW_AT_containing_type:
		default:
			break;
		}
	}

	if (!type) {
		goto cleanup;
	}
	result->name = name;
	result->type = type;
	result->offset = offset;
	result->size = size;
	return result;

cleanup:
	free(name);
	rz_type_free(type);
	return NULL;
}

/**
 * \brief  Parses enum entry into *result RzTypeEnumCase
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=110&zoom=100,0,0
 *
 * \param ctx
 * \param idx index of the current entry
 * \param result ptr to result case to fill up
 * \return RzTypeEnumCase* Ptr to parsed enum case
 */
static RzTypeEnumCase *parse_enumerator(Context *ctx, RzBinDwarfDie *die, RzTypeEnumCase *result) {
	char *name = NULL;
	st64 val = 0;

	// Enumerator has DW_AT_name and DW_AT_const_value
	RzBinDwarfAttr *value;
	rz_vector_foreach(&die->attrs, value) {
		switch (value->name) {
		case DW_AT_name:
			free(name);
			name = die_name(die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_const_value:
			switch (value->kind) {
			case DW_AT_KIND_ADDRESS:
			case DW_AT_KIND_BLOCK:
			case DW_AT_KIND_CONSTANT:
				val = value->sconstant;
				break;
			case DW_AT_KIND_UCONSTANT:
				val = (st64)value->uconstant;
				break;
			case DW_AT_KIND_EXPRLOC:
			case DW_AT_KIND_FLAG:
			case DW_AT_KIND_LINEPTR:
			case DW_AT_KIND_LOCLISTPTR:
			case DW_AT_KIND_MACPTR:
			case DW_AT_KIND_RANGELISTPTR:
			case DW_AT_KIND_REFERENCE:
			case DW_AT_KIND_STRING:
				break;
			}
			// ?? can be block, sdata, data, string w/e
			// TODO solve the encoding, I don't know in which union member is it store
			break;
		default:
			break;
		}
	}

	result->name = name;
	result->val = val;
	return result;
cleanup:
	free(name);
	return NULL;
}

/**
 * \brief  Parses a structured entry (structs, classes, unions) into
 *         RzBaseType and saves it using rz_analysis_save_base_type ()
 *
 * \param ctx
 * \param idx index of the current entry
 */
// http://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
static void parse_structure_type(Context *ctx, RzBinDwarfDie *die) {
	RzBaseTypeKind kind;
	if (die->tag == DW_TAG_union_type) {
		kind = RZ_BASE_TYPE_KIND_UNION;
	} else {
		kind = RZ_BASE_TYPE_KIND_STRUCT;
	}
	RzPVector *children = NULL;
	RzBaseType *base_type = rz_type_base_type_new(kind);
	if (!base_type) {
		return;
	}

	base_type->name = die_name(die);
	if (!base_type->name) {
		goto err;
	}

	// if it is definition of previous declaration (TODO Fix, big ugly hotfix addition)
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_specification);
	if (attr) {
		RzBinDwarfDie *decl_die = ht_up_find(ctx->dw->info->die_tbl, attr->reference, NULL);
		if (!decl_die) {
			goto err;
		}
		attr = rz_bin_dwarf_die_get_attr(die, DW_AT_name);
		if (attr) {
			free(base_type->name);
			base_type->name = die_name(decl_die);
		}
	}

	base_type->size = die_byte_size(die);

	RzTypeStructMember member = { 0 };
	// Parse out all members, can this in someway be extracted to a function?
	if (die->has_children) {
		children = die_children(die, ctx->dw);
		if (!children) {
			goto err;
		}

		void **it;
		rz_pvector_foreach (children, it) {
			RzBinDwarfDie *child_die = *it;
			// we take only direct descendats of the structure
			// can be also DW_TAG_suprogram for class methods or tag for templates
			if (child_die->tag == DW_TAG_member) {
				RzTypeStructMember *result = parse_struct_member(ctx, child_die, &member);
				if (!result) {
					goto err;
				}
				void *element = rz_vector_push(&base_type->struct_data.members, &member);
				if (!element) {
					goto err;
				}
			}
		}
	}
	rz_pvector_free(children);
	rz_type_db_save_base_type(ctx->analysis->typedb, base_type);
	return;
err:
	rz_pvector_free(children);
	rz_type_base_type_free(base_type);
}

/**
 * \brief Parses a enum entry into RzBaseType and saves it
 *        int Sdb using rz_analysis_save_base_type ()
 *
 * \param ctx
 * \param idx index of the current entry
 */
static void parse_enum_type(Context *ctx, RzBinDwarfDie *die) {
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return;
	}

	base_type->name = die_name(die);
	if (!base_type->name) {
		goto err;
	}
	base_type->size = die_byte_size(die);

	RzBinDwarfAttr *type_attr = rz_bin_dwarf_die_get_attr(die, DW_AT_type);
	if (type_attr) {
		base_type->type = parse_type_outer(ctx, type_attr->reference, &base_type->size);
		if (!base_type->type) {
			rz_type_base_type_free(base_type);
			return;
		}
	}

	RzTypeEnumCase cas;
	if (die->has_children) {
		RzPVector *children = die_children(die, ctx->dw);
		if (!children) {
			goto err;
		}

		void **it;
		rz_pvector_foreach (children, it) {
			RzBinDwarfDie *child_die = *it;
			// we take only direct descendats of the structure
			if (child_die->tag == DW_TAG_enumerator) {
				RzTypeEnumCase *result = parse_enumerator(ctx, child_die, &cas);
				if (!result) {
					rz_pvector_free(children);
					goto err;
				}
				void *element = rz_vector_push(&base_type->enum_data.cases, &cas);
				if (!element) {
					rz_pvector_free(children);
					rz_type_base_enum_case_free(result, NULL);
				}
			}
		}
	}
	rz_type_db_save_base_type(ctx->analysis->typedb, base_type);
	return;

err:
	rz_type_base_type_free(base_type);
}

/**
 * \brief Parses a typedef entry into RzBaseType and saves it
 *        using rz_analysis_save_base_type ()
 *
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=96&zoom=100,0,0
 *
 * \param ctx
 * \param idx index of the current entry
 */
static void parse_typedef(Context *ctx, RzBinDwarfDie *die) {
	char *name = NULL;
	RzType *type = NULL;
	ut64 size = 0;

	RzBinDwarfAttr *value;
	rz_vector_foreach(&die->attrs, value) {
		switch (value->name) {
		case DW_AT_name:
			name = die_name(die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_type:
			rz_type_free(type);
			type = parse_type_outer(ctx, value->reference, &size);
			if (!type) {
				goto cleanup;
			}
			break;
		default:
			break;
		}
	}
	if (!name || !type) { // type has to have a name for now
		goto cleanup;
	}
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		goto cleanup;
	}
	base_type->name = name;
	base_type->type = type;
	rz_type_db_save_base_type(ctx->analysis->typedb, base_type);
	return;

cleanup:
	rz_type_free(type);
}

static void parse_atomic_type(Context *ctx, RzBinDwarfDie *die) {
	char *name = NULL;
	ut64 size = 0;
	// TODO support endiannity and encoding in future?
	RzBinDwarfAttr *value;
	rz_vector_foreach(&die->attrs, value) {
		switch (value->name) {
		case DW_AT_name: {
			name = die_name(die);
			break;
		}
		case DW_AT_byte_size:
			size = value->uconstant * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = value->uconstant;
			break;
		case DW_AT_encoding:
		default:
			break;
		}
	}
	if (!name) { // type has to have a name for now
		return;
	}
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		free(name);
		return;
	}
	base_type->name = name;
	base_type->size = size;
	rz_type_db_save_base_type(ctx->analysis->typedb, base_type);
}

static const char *get_specification_die_name(const RzBinDwarfDie *die, bool prefer_linkage_name) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_specification);
	if (attr) {
		const char *s = rz_bin_dwarf_attr_value_get_string_content(attr);
		if (s) {
			return s;
		}
	}
	if (prefer_linkage_name) {
		attr = rz_bin_dwarf_die_get_attr(die, DW_AT_linkage_name);
	}
	if (!attr) {
		attr = rz_bin_dwarf_die_get_attr(die, DW_AT_name);
	}
	if (attr) {
		const char *s = rz_bin_dwarf_attr_value_get_string_content(attr);
		if (s) {
			return s;
		}
	}
	return NULL;
}

static RzType *get_spec_die_type(Context *ctx, RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_type);
	if (attr) {
		ut64 size = 0;
		return parse_type_outer(ctx, attr->reference, &size);
	}
	return NULL;
}

/* For some languages linkage name is more informative like C++,
   but for Rust it's rubbish and the normal name is fine */
static bool prefer_linkage_name(char *lang) {
	if (!lang) {
		return false;
	}
	if (!strcmp(lang, "rust")) {
		return false;
	} else if (!strcmp(lang, "ada")) {
		return false;
	}
	return true;
}

static RzType *parse_abstract_origin(Context *ctx, ut64 offset, const char **name) {
	RzBinDwarfDie *die = ht_up_find(ctx->dw->info->die_tbl, offset, NULL);
	if (!die) {
		return NULL;
	}
	ut64 size = 0;
	bool has_linkage_name = false;
	bool get_linkage_name = prefer_linkage_name(ctx->lang);
	const RzBinDwarfAttr *val;
	rz_vector_foreach(&die->attrs, val) {
		switch (val->name) {
		case DW_AT_name:
			if ((!get_linkage_name || !has_linkage_name) && val->kind == DW_AT_KIND_STRING) {
				*name = val->string.content;
			}
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			if (val->kind == DW_AT_KIND_STRING) {
				*name = val->string.content;
				has_linkage_name = true;
			}
			break;
		case DW_AT_type:
			return parse_type_outer(ctx, val->reference, &size);
		default:
			break;
		}
	}
	return NULL;
}

/// DWARF Register Number Mapping

/* x86_64 https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf */
static const char *map_dwarf_reg_to_x86_64_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "rax";
	case 1: return "rdx";
	case 2: return "rcx";
	case 3: return "rbx";
	case 4: return "rsi";
	case 5: return "rdi";
	case 6:
		*kind = LOCATION_BP;
		return "rbp";
	case 7:
		*kind = LOCATION_SP;
		return "rsp";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 17: return "xmm0";
	case 18: return "xmm1";
	case 19: return "xmm2";
	case 20: return "xmm3";
	case 21: return "xmm4";
	case 22: return "xmm5";
	case 23: return "xmm6";
	case 24: return "xmm7";
	default:
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/* x86 https://01.org/sites/default/files/file_attach/intel386-psabi-1.0.pdf */
static const char *map_dwarf_reg_to_x86_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0:
	case 8:
		return "eax";
	case 1: return "edx";
	case 2: return "ecx";
	case 3: return "ebx";
	case 4:
		*kind = LOCATION_SP;
		return "esp";
	case 5:
		*kind = LOCATION_BP;
		return "ebp";
	case 6: return "esi";
	case 7: return "edi";
	case 9: return "EFLAGS";
	case 11: return "st0";
	case 12: return "st1";
	case 13: return "st2";
	case 14: return "st3";
	case 15: return "st4";
	case 16: return "st5";
	case 17: return "st6";
	case 18: return "st7";
	case 21: return "xmm0";
	case 22: return "xmm1";
	case 23: return "xmm2";
	case 24: return "xmm3";
	case 25: return "xmm4";
	case 26: return "xmm5";
	case 27: return "xmm6";
	case 28: return "xmm7";
	case 29: return "mm0";
	case 30: return "mm1";
	case 31: return "mm2";
	case 32: return "mm3";
	case 33: return "mm4";
	case 34: return "mm5";
	case 35: return "mm6";
	case 36: return "mm7";
	case 40: return "es";
	case 41: return "cs";
	case 42: return "ss";
	case 43: return "ds";
	case 44: return "fs";
	case 45: return "gs";
	default:
		rz_warn_if_reached();
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/* https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html#DW-REG */
static const char *map_dwarf_reg_to_ppc64_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "r0";
	case 1:
		*kind = LOCATION_SP;
		return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	case 7: return "r7";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "r16";
	case 17: return "r17";
	case 18: return "r18";
	case 19: return "r19";
	case 20: return "r20";
	case 21: return "r21";
	case 22: return "r22";
	case 23: return "r23";
	case 24: return "r24";
	case 25: return "r25";
	case 26: return "r26";
	case 27: return "r27";
	case 28: return "r28";
	case 29: return "r29";
	case 30: return "r30";
	case 31: return "r31";
	default:
		rz_warn_if_reached();
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/// 4.5.1 DWARF Register Numbers https://www.infineon.com/dgdl/Infineon-TC2xx_EABI-UM-v02_09-EN.pdf?fileId=5546d46269bda8df0169ca1bfc7d24ab
static const char *map_dwarf_reg_to_tricore_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "d0";
	case 1: return "d1";
	case 2: return "d2";
	case 3: return "d3";
	case 4: return "d4";
	case 5: return "d5";
	case 6: return "d6";
	case 7: return "d7";
	case 8: return "d8";
	case 9: return "d9";
	case 10: return "d10";
	case 11: return "d11";
	case 12: return "d12";
	case 13: return "d13";
	case 14: return "d14";
	case 15: return "d15";
	case 16: return "a0";
	case 17: return "a1";
	case 18: return "a2";
	case 19: return "a3";
	case 20: return "a4";
	case 21: return "a5";
	case 22: return "a6";
	case 23: return "a7";
	case 24: return "a8";
	case 25: return "a9";
	case 26: return "a10";
	case 27: return "a11";
	case 28: return "a12";
	case 29: return "a13";
	case 30:
		*kind = LOCATION_SP;
		return "a14";
	case 31: return "a15";
	case 32: return "e0";
	case 33: return "e2";
	case 34: return "e4";
	case 35: return "e6";
	case 36: return "e8";
	case 37: return "e10";
	case 38: return "e12";
	case 39: return "e14";
	case 40: return "psw";
	case 41: return "pcxi";
	case 42: return "pc";
	case 43: return "pcx";
	case 44: return "lcx";
	case 45: return "isp";
	case 46: return "icr";
	case 47: return "pipn";
	case 48: return "biv";
	case 49: return "btv";
	default:
		rz_warn_if_reached();
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/* returns string literal register name!
   TODO add more arches                 */
static const char *get_dwarf_reg_name(RZ_NONNULL char *arch, int reg_num, VariableLocationKind *kind, int bits) {
	if (!strcmp(arch, "x86")) {
		if (bits == 64) {
			return map_dwarf_reg_to_x86_64_reg(reg_num, kind);
		} else {
			return map_dwarf_reg_to_x86_reg(reg_num, kind);
		}
	} else if (!strcmp(arch, "ppc")) {
		if (bits == 64) {
			return map_dwarf_reg_to_ppc64_reg(reg_num, kind);
		}
	} else if (!strcmp(arch, "tricore")) {
		return map_dwarf_reg_to_tricore_reg(reg_num, kind);
	}
	*kind = LOCATION_UNKNOWN;
	return "unsupported_reg";
}

/* TODO move a lot of the parsing here into dwarf.c and do only processing here */
static RzBinDwarfLocation *parse_dwarf_location(Context *ctx, const RzBinDwarfAttr *attr, const RzBinDwarfDie *fn) {
	/* Loclist offset is usually CONSTANT or REFERENCE at older DWARF versions, new one has LocListPtr for that */
	if (attr->kind != DW_AT_KIND_BLOCK && attr->kind != DW_AT_KIND_LOCLISTPTR && attr->kind != DW_AT_KIND_REFERENCE && attr->kind != DW_AT_KIND_CONSTANT) {
		return NULL;
	}
	const RzBinDwarfBlock *block;
	if (attr->kind == DW_AT_KIND_LOCLISTPTR || attr->kind == DW_AT_KIND_REFERENCE || attr->kind == DW_AT_KIND_CONSTANT) {
		ut64 offset = attr->reference;
		RzBinDwarfLocationListEntry *entry = ht_up_find(ctx->dw->loc->entry_by_offset, offset, NULL);
		if (!entry) { /* for some reason offset isn't there, wrong parsing or malformed dwarf */
			return NULL;
		}
		/* Very rough and sloppy, refactor this hacked up stuff */
		block = entry->data;
		// range->expression... etc
	} else {
		block = &attr->block;
	}

	RzBuffer *expr = rz_buf_new_with_bytes(block->data, block->length);
	RzVector *loc = rz_bin_dwarf_evaluate(ctx->dw, expr, fn);

	RzBinDwarfPiece *piece;
	rz_vector_pop(loc, piece);

	return piece->location;
}

/**
 * Helper to temporarily serialize types into strings for legacy SDB storage.
 * Usages should be removed long-term.
 */
static RZ_DEPRECATE char *type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	return rz_type_as_pretty_string(typedb, type, NULL,
		RZ_TYPE_PRINT_ZERO_VLA | RZ_TYPE_PRINT_NO_END_SEMICOLON | RZ_TYPE_PRINT_ANONYMOUS | RZ_TYPE_PRINT_ALLOW_NON_EXISTENT_BASE_TYPE, 0);
}

static st32 parse_function_args_and_vars(Context *ctx, RzBinDwarfDie *die, RzStrBuf *args, RzList /*<Variable *>*/ *variables) {
	if (!die->has_children) {
		return 0;
	}

	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return 0;
	}

	bool get_linkage_name = prefer_linkage_name(ctx->lang);
	bool has_linkage_name = false;
	int argNumber = 1;

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		const char *name = NULL;
		if (child_die->tag == DW_TAG_formal_parameter || child_die->tag == DW_TAG_variable) {
			Variable *var = RZ_NEW0(Variable);
			RzType *type = NULL;
			const RzBinDwarfAttr *val;
			rz_vector_foreach(&child_die->attrs, val) {
				switch (val->name) {
				case DW_AT_name:
					if ((!get_linkage_name || !has_linkage_name) && val->kind == DW_AT_KIND_STRING) {
						name = val->string.content;
					}
					break;
				case DW_AT_linkage_name:
				case DW_AT_MIPS_linkage_name:
					if (val->kind == DW_AT_KIND_STRING) {
						name = val->string.content;
					}
					has_linkage_name = true;
					break;
				case DW_AT_type:
					rz_type_free(type);
					type = parse_type_outer(ctx, val->reference, NULL);
					break;
				// abstract origin is supposed to have omitted information
				case DW_AT_abstract_origin:
					rz_type_free(type);
					type = parse_abstract_origin(ctx, val->reference, &name);
					break;
				case DW_AT_location:
					var->location = parse_dwarf_location(ctx, val, die);
					break;
				default:
					break;
				}
			}
			if (child_die->tag == DW_TAG_formal_parameter && child_die->depth == die->depth + 1) {
				var->kind = RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER;
				/* arguments sometimes have only type, create generic argX */
				if (type) {
					if (!name) {
						var->name = rz_str_newf("arg%d", argNumber);
					} else {
						var->name = strdup(name);
					}
					char *type_str = type_as_string(ctx->analysis->typedb, type);
					size_t tmp_len = strlen(type_str);
					rz_strbuf_appendf(args, "%s%s%s, ", type_str,
						tmp_len && type_str[tmp_len - 1] == '*' ? "" : " ",
						var->name);

					var->type = type_str;
					rz_list_append(variables, var);
				} else {
					variable_free(var);
				}
				argNumber++;
			} else if (child_die->tag == DW_TAG_variable) { /* DW_TAG_variable */
				var->kind = RZ_ANALYSIS_VAR_KIND_VARIABLE;
				if (name && type) {
					var->name = strdup(name);
					var->type = type_as_string(ctx->analysis->typedb, type);
					rz_list_append(variables, var);
				} else {
					variable_free(var);
				}
			}
			rz_type_free(type);
		} else if (child_die->tag == DW_TAG_unspecified_parameters) {
			rz_strbuf_appendf(args, "va_args ...,");
		}
	}
	if (args->len > 0) {
		rz_strbuf_slice(args, 0, args->len - 2);
	}
	return 0;
}

static inline char *sdb_build_var_data(Variable *var) {
	if (!var->location) {
		/* NULL location probably means optimized out, maybe put a comment there */
		return NULL;
	}
	switch (var->location->kind) {
	case LOCATION_BP:
	case LOCATION_CFA: {
		/* value = "type, storage, additional info based on storage (offset)" */
		return rz_str_newf("%s,%" PFMT64d ",%s",
			var->location->kind == LOCATION_CFA ? "c" : "b",
			var->location->offset, var->type);
	}
	case LOCATION_SP: {
		/* value = "type, storage, additional info based on storage (offset)" */
		return rz_str_newf("%s,%" PFMT64d ",%s", "s", var->location->offset, var->type);
	}
	case LOCATION_GLOBAL: {
		/* value = "type, storage, additional info based on storage (address)" */
		return rz_str_newf("%s,%" PFMT64u ",%s", "g", var->location->address, var->type);
	}
	case LOCATION_REGISTER: {
		/* value = "type, storage, additional info based on storage (register name)" */
		return rz_str_newf("%s,%s,%s", "r", var->location->reg_name, var->type);
	}
	default:
		/* else location is unknown (optimized out), skip the var */
		break;
	}
	return NULL;
}

static inline void sdb_save_dwarf_fcn_vars(Sdb *sdb, RzList /*<Variable *>*/ *vars, const char *prefix) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	RzListIter *iter;
	Variable *var;
	rz_list_foreach (vars, iter, var) {
		char *val = sdb_build_var_data(var);
		if (!val) {
			continue;
		}
		char *key = rz_str_newf("%s.%s", prefix, var->name);
		sdb_set_owned(sdb, key, val, 0);
		free(key);

		if (iter->n) {
			rz_strbuf_appendf(sb, "%s,", var->name);
		} else {
			rz_strbuf_append(sb, var->name);
		}
	}
	char *key = rz_str_newf("%ss", prefix);
	sdb_set_owned(sdb, key, rz_strbuf_drain(sb), 0);
	free(key);
}

static void
sdb_save_dwarf_function(Function *dwarf_fcn, RzList /*<Variable *>*/ *variables, Sdb *sdb) {
	char *sname = rz_str_sanitize_sdb_key(dwarf_fcn->name);
	sdb_set(sdb, sname, "fcn", 0);

	char *addr_key = rz_str_newf("fcn.%s.addr", sname);
	char *addr_val = rz_str_newf("0x%" PFMT64x "", dwarf_fcn->addr);
	sdb_set_owned(sdb, addr_key, addr_val, 0);
	free(addr_key);

	/* so we can have name without sanitization */
	char *name_key = rz_str_newf("fcn.%s.name", sname);
	sdb_set(sdb, name_key, dwarf_fcn->name, 0);
	free(name_key);

	char *signature_key = rz_str_newf("fcn.%s.sig", sname);
	sdb_set(sdb, signature_key, dwarf_fcn->signature, 0);
	free(signature_key);

	RzList *args = rz_list_new();
	RzList *vars = rz_list_new();
	RzListIter *iter;
	Variable *var;
	rz_list_foreach (variables, iter, var) {
		if (var->kind == RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER) {
			rz_list_append(args, var);
		} else {
			rz_list_append(vars, var);
		}
	}

	char *prefix = rz_str_newf("fcn.%s.arg", sname);
	sdb_save_dwarf_fcn_vars(sdb, args, prefix);
	rz_list_free(args);
	free(prefix);
	prefix = rz_str_newf("fcn.%s.var", sname);
	sdb_save_dwarf_fcn_vars(sdb, vars, prefix);
	rz_list_free(vars);
	free(prefix);

	free(sname);
}

/**
 * \brief Parse function,it's arguments, variables and
 *        save the information into the Sdb
 *
 * \param ctx
 * \param idx Current entry index
 */
static void parse_function(Context *ctx, RzBinDwarfDie *die) {
	Function fcn = { 0 };
	bool has_linkage_name = false;
	bool get_linkage_name = prefer_linkage_name(ctx->lang);
	RzType *ret_type = NULL;
	if (rz_bin_dwarf_die_get_attr(die, DW_AT_declaration)) {
		return; /* just declaration skip */
	}
	/* For rust binaries prefer regular name not linkage TODO */
	RzBinDwarfAttr *val;
	rz_vector_foreach(&die->attrs, val) {
		switch (val->name) {
		case DW_AT_name:
			if (!get_linkage_name || !has_linkage_name) {
				fcn.name = val->kind == DW_AT_KIND_STRING ? val->string.content : fcn.name;
			}
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			fcn.name = val->kind == DW_AT_KIND_STRING ? val->string.content : fcn.name;
			has_linkage_name = true;
			break;
		case DW_AT_low_pc:
		case DW_AT_entry_pc:
			fcn.addr = val->kind == DW_AT_KIND_ADDRESS ? val->address : fcn.addr;
			break;
		case DW_AT_specification: /* reference to declaration DIE with more info */
		{
			RzBinDwarfDie *spec_die = ht_up_find(ctx->dw->info->die_tbl, val->reference, NULL);
			if (spec_die) {
				fcn.name = get_specification_die_name(spec_die, get_linkage_name); /* I assume that if specification has a name, this DIE hasn't */
				rz_type_free(ret_type);
				ret_type = get_spec_die_type(ctx, spec_die);
			}
		} break;
		case DW_AT_type:
			rz_type_free(ret_type);
			ret_type = parse_type_outer(ctx, val->reference, NULL);
			break;
		case DW_AT_virtuality:
			fcn.is_method = true; /* method specific attr */
			fcn.is_virtual = true;
			break;
		case DW_AT_object_pointer:
			fcn.is_method = true;
			break;
		case DW_AT_vtable_elem_location:
			fcn.is_method = true;
			fcn.vtable_addr = 0; /* TODO we might use this information */
			break;
		case DW_AT_accessibility:
			fcn.is_method = true;
			fcn.access = (ut8)val->uconstant;
			break;
		case DW_AT_external:
			fcn.is_external = true;
			break;
		case DW_AT_trampoline:
			fcn.is_trampoline = true;
			break;
		case DW_AT_ranges:
		case DW_AT_high_pc:
		default:
			RZ_LOG_DEBUG("parse fcn %s ignore %s\n", rz_str_get(fcn.name), rz_bin_dwarf_attr(val->name));
			break;
		}
	}
	if (!fcn.name || !fcn.addr) { /* we need a name, faddr */
		goto cleanup;
	}
	RzStrBuf args;
	rz_strbuf_init(&args);
	/* TODO do the same for arguments in future so we can use their location */
	RzList /*<Variable*>*/ *variables = rz_list_new();
	parse_function_args_and_vars(ctx, die, &args, variables);

	if (!ret_type) { /* DW_AT_type is omitted in case of `void` ret type */
		ret_type = rz_type_identifier_of_base_type_str(ctx->analysis->typedb, "void");
		if (!ret_type) {
			rz_list_free(variables);
			goto cleanup;
		}
	}
	rz_warn_if_fail(ctx->lang);
	char *new_name = ctx->analysis->binb.demangle(ctx->analysis->binb.bin, ctx->lang, fcn.name);
	fcn.name = new_name ? new_name : strdup(fcn.name);
	char *ret_type_str = type_as_string(ctx->analysis->typedb, ret_type);
	size_t typelen = strlen(ret_type_str);
	fcn.signature = rz_str_newf("%s%s%s(%s);", ret_type_str, typelen && ret_type_str[typelen - 1] == '*' ? "" : " ", fcn.name, rz_strbuf_get(&args));
	free(ret_type_str);
	sdb_save_dwarf_function(&fcn, variables, ctx->sdb);

	free((char *)fcn.signature);
	free((char *)fcn.name);

	RzListIter *iter;
	Variable *var;
	rz_list_foreach (variables, iter, var) {
		variable_free(var);
	}
	rz_list_free(variables);
	rz_strbuf_fini(&args);
cleanup:
	rz_type_free(ret_type);
}

/**
 * \brief Get's language from comp unit for demangling
 *
 * \param die
 * \return char* string literal language represantation for demangling BinDemangle
 */
static char *parse_comp_unit_lang(const RzBinDwarfDie *die) {
	rz_return_val_if_fail(die, NULL);
	char *lang = "cxx"; // default fallback
	const RzBinDwarfAttr *val = rz_bin_dwarf_die_get_attr(die, DW_AT_language);
	if (!val) {
		return lang;
	}
	rz_warn_if_fail(val->kind == DW_AT_KIND_CONSTANT);

	switch (val->uconstant) {
	case DW_LANG_Java:
		return "java";
	case DW_LANG_ObjC:
	/* subideal, TODO research if dwarf gives me enough info to properly separate C++ and ObjC mangling */
	case DW_LANG_ObjC_plus_plus:
		return "objc";
	case DW_LANG_D:
		return "dlang";
	case DW_LANG_Rust:
		return "rust";
	case DW_LANG_C_plus_plus:
	case DW_LANG_C_plus_plus_14:
	/* no demangling available */
	case DW_LANG_Ada83:
	case DW_LANG_Cobol74:
	case DW_LANG_Cobol85:
	case DW_LANG_Fortran77:
	case DW_LANG_Fortran90:
	case DW_LANG_Pascal83:
	case DW_LANG_Modula2:
	case DW_LANG_Ada95:
	case DW_LANG_Fortran95:
	case DW_LANG_PLI:
	case DW_LANG_Python:
	case DW_LANG_Swift:
	case DW_LANG_Julia:
	case DW_LANG_Dylan:
	case DW_LANG_Fortran03:
	case DW_LANG_Fortran08:
	case DW_LANG_UPC:
	case DW_LANG_C:
	case DW_LANG_C89:
	case DW_LANG_C99:
	case DW_LANG_C11:
	default:
		return lang;
	}
}

/**
 * \brief Delegates DIE to it's proper parsing method
 *
 * \param ctx
 * \param idx index of the current entry
 */
static void parse_type_entry(Context *ctx, RzBinDwarfDie *die) {
	rz_return_if_fail(ctx && die);
	switch (die->tag) {
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		parse_structure_type(ctx, die);
		break;
	case DW_TAG_enumeration_type:
		parse_enum_type(ctx, die);
		break;
	case DW_TAG_typedef:
		parse_typedef(ctx, die);
		break;
	case DW_TAG_base_type:
		parse_atomic_type(ctx, die);
		break;
	case DW_TAG_subprogram:
		parse_function(ctx, die);
		break;
	case DW_TAG_compile_unit:
		/* used for name demangling */
		ctx->lang = parse_comp_unit_lang(die);
	default:
		break;
	}
}

/**
 * \brief Parses type and function information out of DWARF entries
 *        and stores them to the sdb for further use
 *
 * \param analysis
 * \param ctx
 */
RZ_API void rz_analysis_dwarf_process_info(const RzAnalysis *analysis, RzBinDwarf *dw) {
	rz_return_if_fail(analysis);
	Sdb *dwarf_sdb = sdb_ns(analysis->sdb, "dwarf", 1);
	Context dw_context = {
		.analysis = analysis,
		.sdb = dwarf_sdb,
		.lang = NULL,
		.dw = dw,
	};
	RzBinDwarfCompUnit *unit;
	rz_vector_foreach(&dw->info->units, unit) {
		RzBinDwarfDie *die;
		rz_vector_foreach(&unit->dies, die) {
			parse_type_entry(&dw_context, die);
		}
	}
}

bool filter_sdb_function_names(void *user, const char *k, const char *v) {
	(void)user;
	(void)k;
	return !strcmp(v, "fcn");
}

typedef struct {
	RzAnalysis *analysis;
	RzAnalysisFunction *fcn;
	RzFlag *flags;
	Sdb *dwarf_sdb;
	char *func_sname;
} FcnVariableCtx;

static bool apply_debuginfo_variable(FcnVariableCtx *ctx, const char *var_name, char *var_data, RzAnalysisVarKind var_kind) {
	char *extra = NULL;
	char *kind = sdb_anext(var_data, &extra);
	char *type = NULL;
	extra = sdb_anext(extra, &type);
	if (!extra) {
		return false;
	}
	RzType *ttype = rz_type_parse_string_single(ctx->analysis->typedb->parser, type, NULL);
	if (!ttype) {
		return false;
	}

	st64 offset = 0;
	if (*kind != 'r') {
		offset = strtol(extra, NULL, 10);
	}

	if (*kind == 'g') { /* global, fixed addr TODO add size to variables? */
		char *global_name = rz_str_newf("global_%s", var_name);
		rz_flag_unset_off(ctx->flags, offset);
		rz_flag_set_next(ctx->flags, global_name, offset, 4);
		free(global_name);
	} else {
		if (!ctx->fcn) {
			goto beach;
		}
		RzAnalysisVar var;
		memset(&var, 0, sizeof(RzAnalysisVar));
		if (*kind == 'r') {
			RzRegItem *i = rz_reg_get(ctx->analysis->reg, extra, -1);
			if (!i) {
				goto beach;
			}
			rz_analysis_var_storage_init_reg(&var.storage, extra);
		} else { /* kind == 'b' || kind == 's' || kind == 'c' (stack variables) */
			RzStackAddr addr = offset;
			if (*kind == 'b') {
				addr -= ctx->fcn->bp_off;
			}
			rz_analysis_var_storage_init_stack(&var.storage, addr);
		}
		var.type = ttype;
		var.kind = var_kind;
		var.name = rz_str_new(var_name);
		var.fcn = ctx->fcn;
		rz_analysis_function_add_var_dwarf(ctx->fcn, &var, 4);
	}
	return true;
beach:
	rz_type_free(ttype);
	return false;
}

static void apply_debuginfo_variables(FcnVariableCtx *ctx, RzAnalysisVarKind kind) {
	const char *fmt = kind == RZ_ANALYSIS_VAR_KIND_VARIABLE ? "fcn.%s.vars" : "fcn.%s.args";
	const char *var_fmt = kind == RZ_ANALYSIS_VAR_KIND_VARIABLE ? "fcn.%s.var.%s" : "fcn.%s.arg.%s";

	char *var_names_key = rz_str_newf(fmt, ctx->func_sname);
	char *vars = sdb_get(ctx->dwarf_sdb, var_names_key, NULL);
	free(var_names_key);

	char *var_name;
	sdb_aforeach(var_name, vars) {
		char *var_key = rz_str_newf(var_fmt, ctx->func_sname, var_name);
		char *var_data = sdb_get(ctx->dwarf_sdb, var_key, NULL);
		free(var_key);

		if (RZ_STR_ISNOTEMPTY(var_data)) {
			apply_debuginfo_variable(ctx, var_name, var_data, kind);
		}
		free(var_data);
		sdb_aforeach_next(var_name);
	}
	free(vars);
}

/**
 * \brief Use parsed DWARF function info from Sdb in the function analysis
 *  XXX right now we only save parsed name and variables, we can't use signature now
 *  XXX refactor to be more readable
 * \param analysis
 * \param dwarf_sdb
 */
RZ_API void rz_analysis_dwarf_integrate_functions(RzAnalysis *analysis, RzFlag *flags, Sdb *dwarf_sdb) {
	rz_return_if_fail(analysis && dwarf_sdb);

	/* get all entries with value == func */
	SdbList *sdb_list = sdb_foreach_list_filter(dwarf_sdb, filter_sdb_function_names, false);
	SdbListIter *it;
	SdbKv *kv;
	/* iterate all function entries */
	ls_foreach (sdb_list, it, kv) {
		char *func_sname = kv->base.key;

		char *addr_key = rz_str_newf("fcn.%s.addr", func_sname);
		ut64 faddr = sdb_num_get(dwarf_sdb, addr_key, 0);
		free(addr_key);

		/* if the function is analyzed so we can edit */
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, faddr);
		if (fcn) {
			rz_analysis_function_delete_arg_vars(fcn);
			fcn->has_debuginfo = true;

			/* prepend dwarf debug info stuff with dbg. */
			char *real_name_key = rz_str_newf("fcn.%s.name", func_sname);
			const char *real_name = sdb_const_get(dwarf_sdb, real_name_key, 0);
			free(real_name_key);

			char *dwf_name = rz_str_newf("dbg.%s", real_name);
			rz_analysis_function_rename(fcn, dwf_name);
			free(dwf_name);

			char *sig_key = rz_str_newf("fcn.%s.sig", func_sname);
			const char *fcnstr = sdb_const_get(dwarf_sdb, sig_key, 0);
			free(sig_key);
			/* Apply signature as a comment at a function address */
			rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, faddr, fcnstr);
		}

		FcnVariableCtx ctx = {
			.analysis = analysis,
			.flags = flags,
			.dwarf_sdb = dwarf_sdb,
			.func_sname = func_sname,
			.fcn = fcn,
		};
		apply_debuginfo_variables(&ctx, RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER);
		apply_debuginfo_variables(&ctx, RZ_ANALYSIS_VAR_KIND_VARIABLE);
	}
	ls_free(sdb_list);
}
