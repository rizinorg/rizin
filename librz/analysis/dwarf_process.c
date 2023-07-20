// SPDX-FileCopyrightText: 2012-2020 houndthe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <rz_analysis.h>
#include <rz_bin_dwarf.h>
#include <string.h>
#include "analysis_private.h"

typedef struct dwarf_parse_context_t {
	const RzAnalysis *analysis;
	RzBinDwarfCompUnit *unit;
	RzBinDwarf *dw;
} Context;

static RzType *type_parse_from_offset_internal(Context *ctx, ut64 offset,
	RZ_NULLABLE ut64 *size, RZ_NONNULL SetU *visited);
static RzType *type_parse_from_offset(Context *ctx, ut64 offset, ut64 *size);
static bool enum_children_parse(Context *ctx, const RzBinDwarfDie *die, RzBaseType *base_type);
static bool struct_union_children_parse(Context *ctx, const RzBinDwarfDie *die, RzBaseType *base_type);

/* For some languages linkage name is more informative like C++,
   but for Rust it's rubbish and the normal name is fine */
static bool prefer_linkage_name(enum DW_LANG lang) {
	switch (lang) {
	case DW_LANG_C89: break;
	case DW_LANG_C: break;
	case DW_LANG_Ada83: return false;
	case DW_LANG_C_plus_plus: break;
	case DW_LANG_Cobol74: break;
	case DW_LANG_Cobol85: break;
	case DW_LANG_Fortran77: break;
	case DW_LANG_Fortran90: break;
	case DW_LANG_Pascal83: break;
	case DW_LANG_Modula2: break;
	case DW_LANG_Java: break;
	case DW_LANG_C99: break;
	case DW_LANG_Ada95: break;
	case DW_LANG_Fortran95: break;
	case DW_LANG_PLI: break;
	case DW_LANG_ObjC: break;
	case DW_LANG_ObjC_plus_plus: break;
	case DW_LANG_UPC: break;
	case DW_LANG_D: break;
	case DW_LANG_Python: break;
	case DW_LANG_Rust: return false;
	case DW_LANG_C11: break;
	case DW_LANG_Swift: break;
	case DW_LANG_Julia: break;
	case DW_LANG_Dylan: break;
	case DW_LANG_C_plus_plus_14: break;
	case DW_LANG_Fortran03: break;
	case DW_LANG_Fortran08: break;
	case DW_LANG_Mips_Assembler: break;
	case DW_LANG_GOOGLE_RenderScript: break;
	case DW_LANG_SUN_Assembler: break;
	case DW_LANG_ALTIUM_Assembler: break;
	case DW_LANG_BORLAND_Delphi: break;
	default:
		break;
	}
	return true;
}

/// DWARF Register Number Mapping

/* x86_64 https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf */
static const char *map_dwarf_reg_to_x86_64_reg(ut64 reg_num) {
	switch (reg_num) {
	case 0: return "rax";
	case 1: return "rdx";
	case 2: return "rcx";
	case 3: return "rbx";
	case 4: return "rsi";
	case 5: return "rdi";
	case 6: return "rbp";
	case 7: return "rsp";
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
		return "unsupported_reg";
	}
}

/* x86 https://01.org/sites/default/files/file_attach/intel386-psabi-1.0.pdf */
static const char *map_dwarf_reg_to_x86_reg(ut64 reg_num) {
	switch (reg_num) {
	case 0: /* fall-thru */
	case 8: return "eax";
	case 1: return "edx";
	case 2: return "ecx";
	case 3: return "ebx";
	case 4: return "esp";
	case 5: return "ebp";
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
		return "unsupported_reg";
	}
}

/* https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html#DW-REG */
static const char *map_dwarf_reg_to_ppc64_reg(ut64 reg_num) {
	switch (reg_num) {
	case 0: return "r0";
	case 1: return "r1";
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
		return "unsupported_reg";
	}
}

/// 4.5.1 DWARF Register Numbers https://www.infineon.com/dgdl/Infineon-TC2xx_EABI-UM-v02_09-EN.pdf?fileId=5546d46269bda8df0169ca1bfc7d24ab
static const char *map_dwarf_reg_to_tricore_reg(ut64 reg_num) {
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
	case 30: return "a14";
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
		return "unsupported_reg";
	}
}

/* returns string literal register name!
   TODO add more arches                 */
static const char *dwarf_reg_name(RZ_NONNULL char *arch, ut64 reg_num, int bits) {
	if (!strcmp(arch, "x86")) {
		if (bits == 64) {
			return map_dwarf_reg_to_x86_64_reg(reg_num);
		} else {
			return map_dwarf_reg_to_x86_reg(reg_num);
		}
	} else if (!strcmp(arch, "ppc") && bits == 64) {
		return map_dwarf_reg_to_ppc64_reg(reg_num);
	} else if (!strcmp(arch, "tricore")) {
		return map_dwarf_reg_to_tricore_reg(reg_num);
	}
	return "unsupported_reg";
}

static void variable_fini(RzAnalysisDwarfVariable *var) {
	rz_bin_dwarf_location_free(var->location);
	var->location = NULL;
	RZ_FREE(var->name);
	RZ_FREE(var->link_name);
	rz_type_free(var->type);
}

static const char *die_name_const(const RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_name);
	if (!attr) {
		return NULL;
	}
	return rz_bin_dwarf_attr_get_string(attr);
}

/**
 * \brief Get the DIE name or create unique one from its offset
 * \return char* DIEs name or NULL if error
 */
static char *die_name(const RzBinDwarfDie *die) {
	const char *name = die_name_const(die);
	if (name) {
		return strdup(name);
	}
	return rz_str_newf("type_0x%" PFMT64x, die->offset);
}

static RzPVector /*<RzBinDwarfDie *>*/ *die_children(const RzBinDwarfDie *die, RzBinDwarf *dw) {
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
 * \return ut64 size in bits or 0 if not found
 */
static ut64 die_bits_size(const RzBinDwarfDie *die) {
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

static RzBaseType *base_type_new_from_die(Context *ctx, const RzBinDwarfDie *die) {
	RzBaseTypeKind kind = RZ_BASE_TYPE_KIND_ATOMIC;
	switch (die->tag) {
	case DW_TAG_union_type:
		kind = RZ_BASE_TYPE_KIND_UNION;
		break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		kind = RZ_BASE_TYPE_KIND_STRUCT;
		break;
	case DW_TAG_base_type:
		kind = RZ_BASE_TYPE_KIND_ATOMIC;
		break;
	case DW_TAG_enumeration_type:
		kind = RZ_BASE_TYPE_KIND_ENUM;
		break;
	case DW_TAG_typedef:
		kind = RZ_BASE_TYPE_KIND_TYPEDEF;
		break;
	default:
		return NULL;
	}

	RzType *type = NULL;
	RzBaseType *btype = NULL;
	const char *name = NULL;
	ut64 size = 0;
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_specification: {
			RzBinDwarfDie *decl = ht_up_find(ctx->dw->info->die_tbl, attr->reference, NULL);
			if (!decl) {
				return NULL;
			}
			name = die_name_const(decl);
			break;
		}
		case DW_AT_name:
			name = rz_bin_dwarf_attr_get_string(attr);
			break;
		case DW_AT_byte_size:
			size = attr->uconstant * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = attr->uconstant;
			break;
		case DW_AT_type:
			type = type_parse_from_offset(ctx, attr->reference, &size);
			if (!type) {
				return NULL;
			}
			break;
		default: break;
		}
	}
	if (!name) {
		goto err;
	}
	btype = rz_type_base_type_new(kind);
	if (!btype) {
		goto err;
	}
	btype->name = strdup(name);
	btype->size = size;
	btype->type = type;

	switch (kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
	case RZ_BASE_TYPE_KIND_UNION:
		if (!struct_union_children_parse(ctx, die, btype)) {
			goto err;
		}
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		if (!enum_children_parse(ctx, die, btype)) {
			goto err;
		}
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
	case RZ_BASE_TYPE_KIND_ATOMIC: break;
	}

	return btype;
err:
	rz_type_free(type);
	if (btype) {
		btype->type = NULL;
	}
	rz_type_base_type_free(btype);
	return NULL;
}

/**
 * \brief Parse and return the count of an array or 0 if not found/not defined
 */
static ut64 array_count_parse(Context *ctx, RzBinDwarfDie *die) {
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
		if (!(child_die->tag == DW_TAG_subrange_type)) {
			continue;
		}
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
	rz_pvector_free(children);
	return 0;
}

/**
 * Parse the die's DW_AT_type type or return a void type or NULL if \p type_idx == -1
 *
 * \param allow_void whether to return a void type instead of NULL if there is no type defined
 */
static RzType *type_parse_from_die_internal(Context *ctx, RzBinDwarfDie *die, bool allow_void, RZ_NULLABLE ut64 *size, RZ_NONNULL SetU *visited) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, DW_AT_type);
	if (!attr) {
		if (!allow_void) {
			return NULL;
		}
		return rz_type_identifier_of_base_type_str(ctx->analysis->typedb, "void");
	}
	return type_parse_from_offset_internal(ctx, attr->reference, size, visited);
}

/**
 * \brief Recursively parses type entry of a certain offset and saves type size into *size
 *
 * \param ctx
 * \param offset offset of the type entry
 * \param size ptr to size of a type to fill up (can be NULL if unwanted)
 * \return the parsed RzType or NULL on failure
 */
static RzType *type_parse_from_offset_internal(Context *ctx, ut64 offset,
	RZ_NULLABLE ut64 *size, RZ_NONNULL SetU *visited) {
	if (set_u_contains(visited, offset)) {
		return NULL;
	}
	set_u_add(visited, offset);
	RzType *type = ht_up_find(ctx->analysis->debug_info->type_by_offset, offset, NULL);
	if (type) {
		type->ref++;
		return type;
	}

	RzBinDwarfDie *die = ht_up_find(ctx->dw->info->die_tbl, offset, NULL);
	if (!die) {
		return NULL;
	}

	RzType *ret = NULL;
	// get size of first type DIE that has size
	if (size && *size == 0) {
		*size = die_bits_size(die);
	}
	switch (die->tag) {
	// this should be recursive search for the type until you find base/user defined type
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type: // C++ references are just pointers to us
	case DW_TAG_rvalue_reference_type: {
		RzType *pointee = type_parse_from_die_internal(ctx, die, true, size, visited);
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
		ret->ref = 1;
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
		RzType *return_type = type_parse_from_die_internal(ctx, die, true, size, visited);
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
		callable->ret = return_type;
		ret = rz_type_callable(callable);
		if (!ret) {
			rz_type_callable_free(callable);
		}
		break;
	}
	case DW_TAG_array_type: {
		RzType *subtype = type_parse_from_die_internal(ctx, die, false, size, visited);
		if (!subtype) {
			goto end;
		}
		ut64 count = array_count_parse(ctx, die);
		ret = rz_type_array_of_type(ctx->analysis->typedb, subtype, count);
		if (!ret) {
			rz_type_free(subtype);
		}
		break;
	}
	case DW_TAG_const_type: {
		ret = type_parse_from_die_internal(ctx, die, true, size, visited);
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
		ret = type_parse_from_die_internal(ctx, die, false, size, visited);
		break;
	default:
		break;
	}
end:
	set_u_delete(visited, offset);
	return ret;
}

static RzType *type_parse_from_offset(Context *ctx, ut64 offset, ut64 *size) {
	SetU *visited = set_u_new();
	if (!visited) {
		return NULL;
	}
	RzType *type = type_parse_from_offset_internal(ctx, offset, size, visited);
	set_u_free(visited);
	return type;
}

static RzType *type_parse_from_abstract_origin(Context *ctx, ut64 offset, char **name_out) {
	RzBinDwarfDie *die = ht_up_find(ctx->dw->info->die_tbl, offset, NULL);
	if (!die) {
		return NULL;
	}
	ut64 size = 0;
	const char *name = NULL;
	const char *linkname = NULL;
	RzType *type = NULL;
	const RzBinDwarfAttr *val;
	rz_vector_foreach(&die->attrs, val) {
		switch (val->name) {
		case DW_AT_name:
			name = rz_bin_dwarf_attr_get_string(val);
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			linkname = rz_bin_dwarf_attr_get_string(val);
			break;
		case DW_AT_type:
			type = type_parse_from_offset(ctx, val->reference, &size);
		default:
			break;
		}
	}
	const char *prefer_name = (prefer_linkage_name(ctx->unit->language) && linkname) ? linkname : name ? name
													   : linkname;
	if (!(prefer_name && type)) {
		rz_type_free(type);
		return NULL;
	}
	*name_out = strdup(prefer_name);
	return type;
}

/**
 * \brief Parses structured entry into *result RzTypeStructMember
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
 */
static RzTypeStructMember *struct_member_parse(Context *ctx, RzBinDwarfDie *die, RzTypeStructMember *result) {
	rz_return_val_if_fail(result, NULL);
	char *name = NULL;
	RzType *type = NULL;
	ut64 offset = 0;
	ut64 size = 0;
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			name = die_name(die);
			break;
		case DW_AT_type:
			type = type_parse_from_offset(ctx, attr->reference, &size);
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
		// If the size of a data member is not the same as the
		//  size of the type given for the data member
		case DW_AT_byte_size:
			size = attr->uconstant * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = attr->uconstant;
			break;
		case DW_AT_accessibility: // private, public etc.
		case DW_AT_mutable: // flag is it is mutable
		case DW_AT_data_bit_offset:
			/*
				int that specifies the number of bits from beginning
				of containing entity to the beginning of the data member
			*/
		case DW_AT_containing_type:
		default:
			break;
		}
	}

	if (!(type && name)) {
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
 * \brief  Parses a structured entry (structs, classes, unions) into
 *         RzBaseType and saves it using rz_analysis_save_base_type ()
 */
// http://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
static bool struct_union_children_parse(Context *ctx, const RzBinDwarfDie *die, RzBaseType *base_type) {
	if (!die->has_children) {
		return false;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return false;
	}

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		// we take only direct descendats of the structure
		// can be also DW_TAG_suprogram for class methods or tag for templates
		if (!(child_die->tag == DW_TAG_member)) {
			continue;
		}
		RzTypeStructMember member = { 0 };
		RzTypeStructMember *result = struct_member_parse(ctx, child_die, &member);
		if (!result) {
			goto err;
		}
		void *element = rz_vector_push(&base_type->struct_data.members, &member);
		if (!element) {
			rz_type_free(result->type);
			goto err;
		}
	}
	rz_pvector_free(children);
	return true;
err:
	rz_pvector_free(children);
	return false;
}

/**
 * \brief  Parses enum entry into *result RzTypeEnumCase
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=110&zoom=100,0,0
 */
static RzTypeEnumCase *enumerator_parse(Context *ctx, RzBinDwarfDie *die, RzTypeEnumCase *result) {
	RzBinDwarfAttr *val_attr = rz_bin_dwarf_die_get_attr(die, DW_AT_const_value);
	if (!val_attr) {
		return NULL;
	}
	st64 val = 0;
	switch (val_attr->kind) {
	case DW_AT_KIND_ADDRESS:
	case DW_AT_KIND_BLOCK:
	case DW_AT_KIND_CONSTANT:
		val = val_attr->sconstant;
		break;
	case DW_AT_KIND_UCONSTANT:
		val = (st64)val_attr->uconstant;
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

	result->name = die_name(die);
	result->val = val;
	return result;
}

static bool enum_children_parse(Context *ctx, const RzBinDwarfDie *die, RzBaseType *base_type) {
	if (!die->has_children) {
		return false;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return false;
	}

	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		if (!(child_die->tag == DW_TAG_enumerator)) {
			continue;
		}
		RzTypeEnumCase cas = {};
		RzTypeEnumCase *result = enumerator_parse(ctx, child_die, &cas);
		if (!result) {
			goto err;
		}
		void *element = rz_vector_push(&base_type->enum_data.cases, &cas);
		if (!element) {
			rz_type_base_enum_case_free(result, NULL);
			goto err;
		}
	}
	rz_pvector_free(children);
	return true;
err:
	rz_pvector_free(children);
	return false;
}

static void function_apply_specification(Context *ctx, const RzBinDwarfDie *die, RzAnalysisDwarfFunction *fn) {
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			if (fn->name) {
				break;
			}
			fn->name = rz_str_new(rz_bin_dwarf_attr_get_string(attr));
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			if (fn->link_name) {
				break;
			}
			fn->link_name = rz_str_new(rz_bin_dwarf_attr_get_string(attr));
			break;
		case DW_AT_type: {
			if (fn->ret_type) {
				break;
			}
			ut64 size = 0;
			fn->ret_type = type_parse_from_offset(ctx, attr->reference, &size);
			break;
		}
		default:
			break;
		}
	}
}

static RzBinDwarfLocation *location_list_parse(Context *ctx, RzBinDwarfLocList *loclist, const RzBinDwarfDie *fn) {
	RzBinDwarfLocation *location = RZ_NEW0(RzBinDwarfLocation);
	if (!location) {
		return NULL;
	}
	location->kind = RzBinDwarfLocationKind_LOCLIST;
	if (loclist->has_location) {
		location->loclist = loclist;
		return location;
	}

	void **it;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocationListEntry *entry = *it;
		if (!(entry->expression && entry->expression->data)) {
			continue;
		}
		entry->location = rz_bin_dwarf_location_from_block(entry->expression, ctx->dw, ctx->unit, fn);
		if (!entry->location) {
			char *expr_str = rz_bin_dwarf_expression_to_string(&ctx->dw->encoding, entry->expression);
			RZ_LOG_ERROR("Failed to parse fn: 0x%" PFMT64x " location list entry (0x%" PFMT64x ", 0x%" PFMT64x "):\t[%s]\n ",
				fn->offset, entry->range->begin, entry->range->end, rz_str_get_null(expr_str))
			free(expr_str);

			return NULL;
		}
	}
	loclist->has_location = true;
	location->loclist = loclist;
	return location;
}

static RzBinDwarfLocation *location_parse(Context *ctx, const RzBinDwarfAttr *attr, const RzBinDwarfDie *fn) {
	/* Loclist offset is usually CONSTANT or REFERENCE at older DWARF versions, new one has LocListPtr for that */
	const RzBinDwarfBlock *block = NULL;
	if (attr->kind == DW_AT_KIND_LOCLISTPTR || attr->kind == DW_AT_KIND_REFERENCE || attr->kind == DW_AT_KIND_UCONSTANT) {
		ut64 offset = attr->reference;
		RzBinDwarfLocList *loclist = ht_up_find(ctx->dw->loc->loclist_by_offset, offset, NULL);
		if (!loclist) { /* for some reason offset isn't there, wrong parsing or malformed dwarf */
			if (!rz_bin_dwarf_loclist_table_parse_at(ctx->dw->loc, &ctx->unit->hdr.encoding, offset)) {
			err:
				RZ_LOG_ERROR("Failed to find location 0x%" PFMT64x " form: %s\n",
					offset, rz_bin_dwarf_form(attr->form));
				return NULL;
			}
			loclist = ht_up_find(ctx->dw->loc->loclist_by_offset, offset, NULL);
			if (!loclist) {
				goto err;
			}
		}
		if (rz_pvector_len(&loclist->entries) >= 1) {
			return location_list_parse(ctx, loclist, fn);
		} else {
			RzBinDwarfLocation *loc = RZ_NEW0(RzBinDwarfLocation);
			loc->kind = RzBinDwarfLocationKind_EMPTY;
			return loc;
		}
	} else if (attr->kind == DW_AT_KIND_BLOCK) {
		block = &attr->block;
	}
	if (!block) {
		RZ_LOG_ERROR("Failed to find location %s\n", rz_bin_dwarf_form(attr->form));
		return NULL;
	}
	if (!block->data) {
		// EMPTY Location?
		return NULL;
	}
	RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(block, ctx->dw, ctx->unit, fn);
	if (!loc) {
		char *expr_str = rz_bin_dwarf_expression_to_string(&ctx->dw->encoding, block);
		if (RZ_STR_ISNOTEMPTY(expr_str)) {
			RZ_LOG_ERROR("Failed to parse location: [%s]\n", expr_str);
		}
		free(expr_str);
	}
	return loc;
}

static inline const char *var_name(RzAnalysisDwarfVariable *v, enum DW_LANG lang) {
	return prefer_linkage_name(lang) ? (v->link_name ? v->link_name : v->name) : v->name;
}

static bool function_var_parse(Context *ctx, RzBinDwarfDie *var_die, RzBinDwarfDie *fn_die, RzAnalysisDwarfVariable *v) {
	switch (var_die->tag) {
	case DW_TAG_formal_parameter:
		v->kind = RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER;
		break;
	case DW_TAG_variable:
		v->kind = RZ_ANALYSIS_VAR_KIND_VARIABLE;
		break;
	case DW_TAG_unspecified_parameters:
		v->kind = RZ_ANALYSIS_VAR_KIND_UNSPECIFIED_PARAMETERS;
		return true;
	default:
		return false;
	}

	bool has_location = false;
	const RzBinDwarfAttr *val;
	rz_vector_foreach(&var_die->attrs, val) {
		switch (val->name) {
		case DW_AT_name:
			v->name = rz_str_new(rz_bin_dwarf_attr_get_string(val));
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			v->link_name = rz_str_new(rz_bin_dwarf_attr_get_string(val));
			break;
		case DW_AT_type: {
			RzType *type = type_parse_from_offset(ctx, val->reference, NULL);
			if (type) {
				rz_type_free(v->type);
				v->type = type;
			}
		} break;
		// abstract origin is supposed to have omitted information
		case DW_AT_abstract_origin: {
			RzType *type = type_parse_from_abstract_origin(ctx, val->reference, &v->name);
			if (type) {
				rz_type_free(v->type);
				v->type = type;
			}
		} break;
		case DW_AT_location:
			v->location = location_parse(ctx, val, fn_die);
			has_location = v->location != NULL;
			break;
		default:
			break;
		}
	}

	if (!has_location) {
		v->location = RZ_NEW0(RzBinDwarfLocation);
		v->location->kind = RzBinDwarfLocationKind_EMPTY;
	}
	v->prefer_name = var_name(v, ctx->unit->language);
	return true;
}

static bool function_children_parse(Context *ctx, RzBinDwarfDie *die, RzCallable *callable, RzAnalysisDwarfFunction *fn) {
	if (!die->has_children) {
		return false;
	}
	RzPVector *children = die_children(die, ctx->dw);
	if (!children) {
		return false;
	}
	void **it;
	rz_pvector_foreach (children, it) {
		RzBinDwarfDie *child_die = *it;
		if (child_die->depth != die->depth + 1) {
			continue;
		}
		RzAnalysisDwarfVariable v = { 0 };
		if (!function_var_parse(ctx, child_die, die, &v)) {
			continue;
		}
		if (v.kind == RZ_ANALYSIS_VAR_KIND_UNSPECIFIED_PARAMETERS) {
			callable->has_unspecified_parameters = true;
			fn->has_unspecified_parameters = true;
			continue;
		}
		if (!(v.location && v.type)) {
			RZ_LOG_ERROR("Failed to parse %s variable 0x%" PFMT64x "\n", fn->prefer_name, child_die->offset);
			continue;
		}
		if (v.kind == RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER) {
			RzCallableArg *arg = rz_type_callable_arg_new(ctx->analysis->typedb, v.prefer_name ? v.prefer_name : "", rz_type_clone(v.type));
			rz_type_callable_arg_add(callable, arg);
		}
		rz_vector_push(&fn->variables, &v);
	}
	rz_pvector_free(children);
	return true;
}

static inline const char *function_name(RzAnalysisDwarfFunction *f, enum DW_LANG lang) {
	return prefer_linkage_name(lang) ? (f->demangle_name ? (const char *)(f->demangle_name) : (f->link_name ? f->link_name : f->name)) : f->name;
}

static void function_free(RzAnalysisDwarfFunction *f) {
	if (!f) {
		return;
	}
	free(f->name);
	free(f->demangle_name);
	free(f->link_name);
	rz_vector_fini(&f->variables);
	rz_type_free(f->ret_type);
	free(f);
}

/**
 * \brief Parse function,it's arguments, variables and
 *        save the information into the Sdb
 */
static void function_parse(Context *ctx, RzBinDwarfDie *die) {
	RzAnalysisDwarfFunction *fcn = RZ_NEW0(RzAnalysisDwarfFunction);
	if (!fcn) {
		return;
	}
	rz_vector_init(&fcn->variables, sizeof(RzAnalysisDwarfVariable), (RzVectorFree)variable_fini, NULL);
	if (rz_bin_dwarf_die_get_attr(die, DW_AT_declaration)) {
		goto cleanup; /* just declaration skip */
	}
	RzBinDwarfAttr *val;
	rz_vector_foreach(&die->attrs, val) {
		switch (val->name) {
		case DW_AT_name:
			fcn->name = rz_str_new(rz_bin_dwarf_attr_get_string(val));
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			fcn->link_name = rz_str_new(rz_bin_dwarf_attr_get_string(val));
			break;
		case DW_AT_low_pc:
		case DW_AT_entry_pc:
			fcn->addr = val->kind == DW_AT_KIND_ADDRESS ? val->address : fcn->addr;
			break;
		case DW_AT_specification: /* reference to declaration DIE with more info */
		{
			RzBinDwarfDie *spec = ht_up_find(ctx->dw->info->die_tbl, val->reference, NULL);
			if (!spec) {
				RZ_LOG_ERROR("Cannot find specification DIE at 0x%" PFMT64x "\n", val->reference);
				break;
			}
			function_apply_specification(ctx, spec, fcn);
			break;
		}
		case DW_AT_type:
			rz_type_free(fcn->ret_type);
			fcn->ret_type = type_parse_from_offset(ctx, val->reference, NULL);
			break;
		case DW_AT_virtuality:
			fcn->is_method = true; /* method specific attr */
			fcn->is_virtual = true;
			break;
		case DW_AT_object_pointer:
			fcn->is_method = true;
			break;
		case DW_AT_vtable_elem_location:
			fcn->is_method = true;
			fcn->vtable_addr = 0; /* TODO we might use this information */
			break;
		case DW_AT_accessibility:
			fcn->is_method = true;
			fcn->access = (ut8)val->uconstant;
			break;
		case DW_AT_external:
			fcn->is_external = true;
			break;
		case DW_AT_trampoline:
			fcn->is_trampoline = true;
			break;
		case DW_AT_ranges:
		case DW_AT_high_pc:
		default:
			break;
		}
	}
	if (fcn->link_name) {
		fcn->demangle_name = ctx->analysis->binb.demangle(ctx->analysis->binb.bin, rz_bin_dwarf_lang_for_demangle(ctx->unit->language), fcn->link_name);
	}
	fcn->prefer_name = function_name(fcn, ctx->unit->language);
	if (!fcn->prefer_name || !fcn->addr) { /* we need a name, faddr */
		goto cleanup;
	}

	if (fcn->ret_type) {
		fcn->ret_type->ref++;
	}
	RzCallable *callable = rz_type_func_new(ctx->analysis->typedb, fcn->prefer_name, fcn->ret_type);
	function_children_parse(ctx, die, callable, fcn);
	RZ_LOG_DEBUG("DWARF Saving function %s\n", fcn->prefer_name);
	if (!rz_type_func_update(ctx->analysis->typedb, callable)) {
		RZ_LOG_ERROR("DWARF Failed to save function %s\n", fcn->prefer_name);
	};
	if (!ht_up_update(ctx->analysis->debug_info->function_by_addr, fcn->addr, fcn)) {
		goto cleanup;
	}
	return;
cleanup:
	function_free(fcn);
}

static void htup_type_free(HtUPKv *kv) {
	rz_type_free(kv->value);
}

/**
 * \brief Parses type and function information out of DWARF entries
 *        and stores them to the sdb for further use
 */
RZ_API void rz_analysis_dwarf_process_info(const RzAnalysis *analysis, RzBinDwarf *dw) {
	rz_return_if_fail(analysis);
	Context ctx = {
		.analysis = analysis,
		.dw = dw,
		.unit = NULL,
	};
	RzBinDwarfCompUnit *unit;
	rz_vector_foreach(&dw->info->units, unit) {
		ctx.unit = unit;
		RzBinDwarfDie *die;
		rz_vector_foreach(&unit->dies, die) {
			switch (die->tag) {
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			case DW_TAG_class_type:
			case DW_TAG_enumeration_type:
			case DW_TAG_typedef:
			case DW_TAG_base_type: {
				RzBaseType *base_type = base_type_new_from_die(&ctx, die);
				if (!base_type) {
					continue;
				}
				if (!rz_type_db_update_base_type(analysis->typedb, base_type)) {
					RZ_LOG_WARN("Failed to save base type %s\n", base_type->name);
				}
				break;
			}
			case DW_TAG_subprogram:
				function_parse(&ctx, die);
				break;
			default:
				break;
			}
		}
	}
}

static bool fixup_regoff_to_stackoff(RzAnalysis *a, RzAnalysisFunction *f, RzAnalysisDwarfVariable *dw_var, const char *reg_name, RzAnalysisVar *var) {
	if (!(dw_var->location->kind == RzBinDwarfLocationKind_REGISTER_OFFSET)) {
		return false;
	}
	ut16 reg = dw_var->location->register_offset.register_number;
	st64 off = dw_var->location->register_offset.offset;
	if (!strcmp(a->cpu, "x86")) {
		if (a->bits == 64) {
			if (reg == 6) { // 6 = rbp
				rz_analysis_var_storage_init_stack(&var->storage, off - f->bp_off);
				return true;
			}
			if (reg == 7) { // 7 = rsp
				rz_analysis_var_storage_init_stack(&var->storage, off);
				return true;
			}
		} else {
			if (reg == 4) { // 4 = esp
				rz_analysis_var_storage_init_stack(&var->storage, off);
				return true;
			}
			if (reg == 5) { // 5 = ebp
				rz_analysis_var_storage_init_stack(&var->storage, off - f->bp_off);
				return true;
			}
		}
	} else if (!strcmp(a->cpu, "ppc")) {
		if (reg == 1) { // 1 = r1
			rz_analysis_var_storage_init_stack(&var->storage, off);
			return true;
		}
	} else if (!strcmp(a->cpu, "tricore")) {
		if (reg == 30) { // 30 = a14
			rz_analysis_var_storage_init_stack(&var->storage, off);
			return true;
		}
	}
	const char *SP = rz_reg_get_name(a->reg, RZ_REG_NAME_SP);
	if (SP && strcmp(SP, reg_name) == 0) {
		rz_analysis_var_storage_init_stack(&var->storage, off);
		return true;
	}
	const char *BP = rz_reg_get_name(a->reg, RZ_REG_NAME_BP);
	if (BP && strcmp(BP, reg_name) == 0) {
		rz_analysis_var_storage_init_stack(&var->storage, off - f->bp_off);
		return true;
	}
	return false;
}

static bool dw_var_to_rz_var(RzAnalysis *a, RzAnalysisFunction *f, RzAnalysisDwarfVariable *dw_var, RzAnalysisVar *var) {
	var->type = dw_var->type;
	var->name = strdup(dw_var->prefer_name ? dw_var->prefer_name : "");
	var->kind = dw_var->kind;
	var->fcn = f;

	RzBinDwarfLocation *loc = dw_var->location;
	if (!loc) {
		return false;
	}

	RzAnalysisVarStorage *storage = &var->storage;
	switch (loc->kind) {
	case RzBinDwarfLocationKind_EMPTY:
		storage->type = RZ_ANALYSIS_VAR_STORAGE_EMPTY;
		break;
	case RzBinDwarfLocationKind_REGISTER: {
		const char *reg_name = dwarf_reg_name(a->cpu, loc->register_number, a->bits);
		rz_analysis_var_storage_init_reg(storage, reg_name);
		break;
	}
	case RzBinDwarfLocationKind_REGISTER_OFFSET: {
		// Convert some register offset to stack offset
		const char *reg_name = dwarf_reg_name(a->cpu, loc->register_offset.register_number, a->bits);
		if (fixup_regoff_to_stackoff(a, f, dw_var, reg_name, var)) {
			break;
		}
		rz_analysis_var_storage_init_reg_offset(storage, reg_name, loc->register_offset.offset);
		break;
	}
	case RzBinDwarfLocationKind_ADDRESS: {
		rz_analysis_var_global_create(a, dw_var->prefer_name, dw_var->type, loc->address);
		rz_analysis_var_fini(var);
		return false;
	}
	case RzBinDwarfLocationKind_VALUE:
	case RzBinDwarfLocationKind_BYTES:
	case RzBinDwarfLocationKind_IMPLICIT_POINTER:
		// TODO loc2storage
		storage->type = RZ_ANALYSIS_VAR_STORAGE_EMPTY;
		break;
	case RzBinDwarfLocationKind_COMPOSITE:
		rz_analysis_var_storage_init_compose(storage, loc->compose);
		break;
	case RzBinDwarfLocationKind_EVALUATION_WAITING:
		rz_analysis_var_storage_init_dwarf_eval_waiting(storage, loc->eval_waiting.eval, loc->eval_waiting.result);
		break;
	case RzBinDwarfLocationKind_CFA_OFFSET:
		// TODO: The following is only an educated guess. There is actually more involved in calculating the
		//       CFA correctly.
		rz_analysis_var_storage_init_stack(storage, loc->cfa_offset + a->bits / 8);
		break;
	case RzBinDwarfLocationKind_FB_OFFSET:
		rz_analysis_var_storage_init_fb_offset(storage, loc->fb_offset);
		break;
	case RzBinDwarfLocationKind_LOCLIST: {
		rz_analysis_var_storage_init_loclist(storage, loc->loclist);
		break;
	}
	}
	return true;
}

static bool dwarf_integrate_function(void *user, const ut64 k, const void *value) {
	RzAnalysis *analysis = user;
	const RzAnalysisDwarfFunction *fn = value;
	RzAnalysisFunction *afn = rz_analysis_get_function_at(analysis, fn->addr);
	if (!afn) {
		return true;
	}

	/* Apply signature as a comment at a function address */
	RzCallable *callable = rz_type_func_get(analysis->typedb, fn->prefer_name);
	char *sig = rz_type_callable_as_string(analysis->typedb, callable);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, fn->addr, sig);

	char *dwf_name = rz_str_newf("dbg.%s", fn->prefer_name);
	rz_analysis_function_rename((RzAnalysisFunction *)afn, dwf_name);
	free(dwf_name);

	/* Apply variables */
	if (rz_vector_len(&fn->variables) > 0) {
		rz_analysis_function_delete_all_vars(afn);
	}

	RzAnalysisDwarfVariable *v;
	rz_vector_foreach(&fn->variables, v) {
		RzAnalysisVar av = { 0 };
		if (!dw_var_to_rz_var(analysis, afn, v, &av)) {
			continue;
		}
		rz_analysis_function_add_var_dwarf(afn, &av, 4);
	};

	afn->has_debuginfo = true;
	return true;
}

/**
 * \brief Use parsed DWARF function info in the function analysis
 * \param analysis
 * \param flags
 */
RZ_API void
rz_analysis_dwarf_integrate_functions(RzAnalysis *analysis, RzFlag *flags) {
	rz_return_if_fail(analysis && analysis->debug_info);
	ht_up_foreach(analysis->debug_info->function_by_addr, dwarf_integrate_function, analysis);
}

static void htup_function_free(HtUPKv *kv) {
	if (!kv) {
		return;
	}
	function_free(kv->value);
}

RZ_API RzAnalysisDebugInfo *rz_analysis_debug_info_new() {
	RzAnalysisDebugInfo *debug_info = RZ_NEW0(RzAnalysisDebugInfo);
	if (!debug_info) {
		return NULL;
	}
	debug_info->function_by_addr = ht_up_new(NULL, htup_function_free, NULL);
	debug_info->type_by_offset = ht_up_new(NULL, htup_type_free, NULL);
	return debug_info;
}

RZ_API void rz_analysis_debug_info_free(RzAnalysisDebugInfo *debuginfo) {
	if (!debuginfo) {
		return;
	}
	ht_up_free(debuginfo->function_by_addr);
	ht_up_free(debuginfo->type_by_offset);
	free(debuginfo);
}
