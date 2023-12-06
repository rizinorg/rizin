// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

static RzPdbTpiType *RzPdbTpiType_from_buf(RzBuffer *b, ut32 index, ut16 length);

static RzBuffer *buf_take(RzBuffer *b, ut32 len) {
	RzBuffer *type_buffer = rz_buf_new_slice(b, rz_buf_tell(b), len);
	if (!type_buffer) {
		return NULL;
	}
	rz_buf_seek(b, len, RZ_BUF_CUR);
	return type_buffer;
}

static bool buf_empty(RzBuffer *b) {
	if (!b) {
		return true;
	}
	return rz_buf_tell(b) >= rz_buf_size(b);
}

static void buf_read_padding(RzBuffer *b) {
	if (!b) {
		return;
	}
	while (!buf_empty(b) && rz_buf_peek(b) > 0xf0) {
		ut8 padding = 0;
		if (!rz_buf_read8(b, &padding)) {
			return;
		}
		if (padding > 0xf0) {
			rz_buf_seek(b, (padding & 0x0f) - 1, RZ_BUF_CUR);
		}
	}
}

static bool is_simple_type(RzPdbTpiStream *stream, ut32 idx) {
	/*   https://llvm.org/docs/PDB/TpiStream.html#type-indices
  .---------------------------.------.----------.
  |           Unused          | Mode |   Kind   |
  '---------------------------'------'----------'
  |+32                        |+12   |+8        |+0
  */
	return idx < stream->header.TypeIndexBegin;
	// return ((value & 0x00000000FFF00) <= 0x700 && (value & 0x00000000000FF) <
	// 0x80);
}

int tpi_type_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut32 ia = *(ut32 *)incoming;
	ut32 ta = container_of(in_tree, const RzPdbTpiType, rb)->index;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

/**
 * \brief Parses calling convention type as string
 *
 * \param idx
 */
RZ_API RZ_OWN char *rz_bin_pdb_calling_convention_as_string(RZ_NONNULL RzPdbTpiCallingConvention idx) {
	switch (idx) {
	case NEAR_C:
	case FAR_C:
		return strdup("__cdecl");
	case NEAR_PASCAL:
	case FAR_PASCAL:
		return strdup("__pascal");
	case NEAR_FAST:
	case FAR_FAST:
		return strdup("__fastcall");
	case NEAR_STD:
	case FAR_STD:
		return strdup("__stdcall");
	case NEAR_SYS:
	case FAR_SYS:
		return strdup("__syscall");
	case THISCALL:
		return strdup("__thiscall");
	case NEAR_VEC:
		return strdup("__vectorcall");
	default:
		return NULL;
	}
}

static TpiSimpleTypeMode get_simple_type_mode(ut32 type) {
	/*   https://llvm.org/docs/PDB/RzPdbTpiStream.html#type-indices
  .---------------------------.------.----------.
  |           Unused          | Mode |   Kind   |
  '---------------------------'------'----------'
  |+32                        |+12   |+8        |+0
  */
	// because mode is only number between 0-7, 1 byte is enough
	return (type & 0x0000000000F00) >> 8;
}

static TpiSimpleTypeKind get_simple_type_kind(ut32 type) {
	/*   https://llvm.org/docs/PDB/RzPdbTpiStream.html#type-indices
  .---------------------------.------.----------.
  |           Unused          | Mode |   Kind   |
  '---------------------------'------'----------'
  |+32                        |+12   |+8        |+0
  */
	return (type & 0x00000000000FF);
}

static void parse_codeview_property(TpiCVProperty *p, ut16 value) {
	p->packed = GET_BF(value, 0, 1);
	p->ctor = GET_BF(value, 1, 1);
	p->ovlops = GET_BF(value, 2, 1);
	p->isnested = GET_BF(value, 3, 1);
	p->packed = GET_BF(value, 4, 1);
	p->opassign = GET_BF(value, 5, 1);
	p->opcast = GET_BF(value, 6, 1);
	p->fwdref = GET_BF(value, 7, 1);
	p->scoped = GET_BF(value, 8, 1);
	p->has_uniquename = GET_BF(value, 9, 1);
	p->sealed = GET_BF(value, 10, 1);
	p->hfa = GET_BF(value, 11, 2);
	p->intrinsic = GET_BF(value, 13, 1);
	p->mocom = GET_BF(value, 14, 2);
}

static void parse_codeview_fld_attribute(TpiCVFldattr *f, ut16 value) {
	f->access = GET_BF(value, 0, 2);
	f->mprop = GET_BF(value, 2, 3);
	f->pseudo = GET_BF(value, 5, 1);
	f->noinherit = GET_BF(value, 6, 1);
	f->noconstruct = GET_BF(value, 7, 1);
	f->compgenx = GET_BF(value, 8, 1);
	f->sealed = GET_BF(value, 9, 1);
}

static void parse_codeview_func_attribute(TpiCVFuncattr *f, ut8 value) {
	f->cxxreturnudt = GET_BF(value, 0, 1);
	f->ctor = GET_BF(value, 1, 1);
	f->ctorvbase = GET_BF(value, 2, 1);
}

static void parse_codeview_pointer_attribute(TpiCVPointerAttr *p, ut32 value) {
	p->ptrtype = GET_BF(value, 0, 5);
	p->ptrmode = GET_BF(value, 5, 3);
	p->flat32 = GET_BF(value, 8, 1);
	p->volatile_ = GET_BF(value, 9, 1);
	p->const_ = GET_BF(value, 10, 1);
	p->unaligned = GET_BF(value, 11, 1);
	p->restrict_ = GET_BF(value, 12, 1);
	p->size = GET_BF(value, 13, 6);
	p->mocom = GET_BF(value, 19, 1);
	p->lref = GET_BF(value, 20, 1);
	p->rref = GET_BF(value, 21, 1);
	p->unused = GET_BF(value, 22, 10);
}

static void parse_codeview_modifier(TpiCVModifier *m, ut16 value) {
	m->const_ = GET_BF(value, 0, 1);
	m->volatile_ = GET_BF(value, 1, 1);
	m->unaligned = GET_BF(value, 2, 1);
}

/**
 * \brief Parses simple type if the idx represents one
 * \param RzPdbTpiStream TPI stream context
 * \param idx leaf index
 * \return RzPdbTpiType, leaf = 0 -> error
 */
RZ_IPI RzPdbTpiType *parse_simple_type(RzPdbTpiStream *stream, ut32 idx) {
	RzPdbTpiType *type = RZ_NEW0(RzPdbTpiType);
	if (!type) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return NULL;
	}
	type->leaf = LF_SIMPLE_TYPE;
	type->index = idx;
	// For simple type we don't set length
	type->length = 0;
	Tpi_LF_SimpleType *simple_type = RZ_NEW0(Tpi_LF_SimpleType);
	if (!simple_type) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		free(type);
		return NULL;
	}
	type->data = simple_type;
	RzStrBuf *buf;
	TpiSimpleTypeKind kind = get_simple_type_kind(idx);
	switch (kind) {
	case PDB_NONE:
		simple_type->size = 0;
		buf = rz_strbuf_new("notype_t");
		break;
	case PDB_VOID:
		simple_type->size = 0;
		buf = rz_strbuf_new("void");
		break;
	case PDB_SIGNED_CHAR:
	case PDB_NARROW_CHAR:
		simple_type->size = 1;
		buf = rz_strbuf_new("char");
		break;
	case PDB_UNSIGNED_CHAR:
		simple_type->size = 1;
		buf = rz_strbuf_new("unsigned char");
		break;
	case PDB_WIDE_CHAR:
		simple_type->size = 4;
		buf = rz_strbuf_new("wchar_t");
		break;
	case PDB_CHAR16:
		simple_type->size = 2;
		buf = rz_strbuf_new("char16_t");
		break;
	case PDB_CHAR32:
		simple_type->size = 4;
		buf = rz_strbuf_new("char32_t");
		break;
	case PDB_BYTE:
		simple_type->size = 1;
		buf = rz_strbuf_new("uint8_t");
		break;
	case PDB_SBYTE:
		simple_type->size = 1;
		buf = rz_strbuf_new("int8_t");
		break;
	case PDB_INT16:
	case PDB_INT16_SHORT:
		simple_type->size = 2;
		buf = rz_strbuf_new("int16_t");
		break;
	case PDB_UINT16:
	case PDB_UINT16_SHORT:
		simple_type->size = 2;
		buf = rz_strbuf_new("uint16_t");
		break;
	case PDB_INT32:
	case PDB_INT32_LONG:
		simple_type->size = 4;
		buf = rz_strbuf_new("int32_t");
		break;
	case PDB_UINT32:
	case PDB_UINT32_LONG:
		simple_type->size = 4;
		buf = rz_strbuf_new("uint32_t");
		break;
	case PDB_INT64:
	case PDB_INT64_QUAD:
		simple_type->size = 8;
		buf = rz_strbuf_new("int64_t");
		break;
	case PDB_UINT64:
	case PDB_UINT64_QUAD:
		simple_type->size = 8;
		buf = rz_strbuf_new("uint64_t");
		break;
	case PDB_INT128:
	case PDB_INT128_OCT:
		simple_type->size = 16;
		buf = rz_strbuf_new("int128_t");
		break;
	case PDB_UINT128:
	case PDB_UINT128_OCT:
		simple_type->size = 16;
		buf = rz_strbuf_new("uint128_t");
		break;
	case PDB_FLOAT16:
		simple_type->size = 2;
		buf = rz_strbuf_new("float");
		break;
	case PDB_FLOAT32:
	case PDB_FLOAT32_PP:
		simple_type->size = 4;
		buf = rz_strbuf_new("float");
		break;
	case PDB_FLOAT48:
		simple_type->size = 6;
		buf = rz_strbuf_new("float");
		break;
	case PDB_FLOAT64:
		simple_type->size = 8;
		buf = rz_strbuf_new("double");
		break;
	case PDB_FLOAT80:
		simple_type->size = 10;
		buf = rz_strbuf_new("long double");
		break;
	case PDB_FLOAT128:
		simple_type->size = 16;
		buf = rz_strbuf_new("long double");
		break;
	case PDB_COMPLEX16:
		simple_type->size = 2;
		buf = rz_strbuf_new("float _Complex");
		break;
	case PDB_COMPLEX32:
	case PDB_COMPLEX32_PP:
		simple_type->size = 4;
		buf = rz_strbuf_new("float _Complex");
		break;
	case PDB_COMPLEX48:
		simple_type->size = 6;
		buf = rz_strbuf_new("float _Complex");
		break;
	case PDB_COMPLEX64:
		simple_type->size = 8;
		buf = rz_strbuf_new("double _Complex");
		break;
	case PDB_COMPLEX80:
		simple_type->size = 10;
		buf = rz_strbuf_new("long double _Complex");
		break;
	case PDB_COMPLEX128:
		simple_type->size = 16;
		buf = rz_strbuf_new("long double _Complex");
		break;
	case PDB_BOOL8:
		simple_type->size = 1;
		buf = rz_strbuf_new("bool");
		break;
	case PDB_BOOL16:
		simple_type->size = 2;
		buf = rz_strbuf_new("bool");
		break;
	case PDB_BOOL32:
		simple_type->size = 4;
		buf = rz_strbuf_new("bool");
		break;
	case PDB_BOOL64:
		simple_type->size = 8;
		buf = rz_strbuf_new("bool");
		break;
	case PDB_BOOL128:
		simple_type->size = 16;
		buf = rz_strbuf_new("bool");
		break;
	default:
		simple_type->size = 0;
		buf = rz_strbuf_new("unknown_t");
		break;
	}
	TpiSimpleTypeMode mode = get_simple_type_mode(idx);
	if (mode) {
		rz_strbuf_append(buf, " *");
	}
	switch (mode) {
	case NEAR_POINTER:
		simple_type->size = 2;
		break;
	case FAR_POINTER:
	case HUGE_POINTER:
	case NEAR_POINTER32:
	case FAR_POINTER32:
		simple_type->size = 4;
		break;
	case NEAR_POINTER64:
		simple_type->size = 8;
		break;
	case NEAR_POINTER128:
		simple_type->size = 16;
		break;
	default:
		break;
	}
	simple_type->type = rz_strbuf_drain(buf);
	// We just insert once
	rz_rbtree_insert(&stream->types, &type->index, &type->rb, tpi_type_node_cmp, NULL);
	return type;
}

static void simple_type_free(Tpi_LF_SimpleType *t) {
	if (!t) {
		return;
	}
	free(t->type);
	free(t);
}

static ut64 get_numeric_val(Tpi_Type_Numeric *numeric) {
	switch (numeric->type_index) {
	case LF_CHAR:
		return *(st8 *)(numeric->data);
	case LF_SHORT:
		return *(st16 *)(numeric->data);
	case LF_USHORT:
		return *(ut16 *)(numeric->data);
	case LF_LONG:
		return *(st32 *)(numeric->data);
	case LF_ULONG:
		return *(ut32 *)(numeric->data);
	case LF_QUADWORD:
		return *(st64 *)(numeric->data);
	case LF_UQUADWORD:
		return *(ut64 *)(numeric->data);
	default:
		if (numeric->type_index >= 0x8000) {
			return 0;
		}
		return *(ut16 *)(numeric->data);
	}
}
/**
 * \brief Return true if type is forward definition
 *
 * \param t RzPdbTpiType
 * \return bool
 */
RZ_API bool rz_bin_pdb_type_is_fwdref(RZ_NONNULL RzPdbTpiType *t) {
	rz_return_val_if_fail(t, false); // return val stands for we do nothing for it
	switch (t->leaf) {
	case LF_UNION: {
		Tpi_LF_Union *lf = (Tpi_LF_Union *)t->data;
		return lf->prop.fwdref ? true : false;
	}
	case LF_STRUCTURE:
	case LF_CLASS: {
		Tpi_LF_Structure *lf = (Tpi_LF_Structure *)t->data;
		return lf->prop.fwdref ? true : false;
	}
	case LF_STRUCTURE_19:
	case LF_CLASS_19: {
		Tpi_LF_Structure_19 *lf = (Tpi_LF_Structure_19 *)t->data;
		return lf->prop.fwdref ? true : false;
	}
	case LF_ENUM: {
		Tpi_LF_Enum *lf = (Tpi_LF_Enum *)t->data;
		return lf->prop.fwdref ? true : false;
	}
	default:
		rz_warn_if_reached();
		return false;
	}
}

/**
 * \brief Get the RzPdbTpiType members
 *
 * \param stream TPI stream
 * \param t RzPdbTpiType
 * \return RzPVector *
 */
RZ_API RZ_BORROW RzPVector /*<RzPdbTpiType *>*/ *rz_bin_pdb_get_type_members(
	RZ_NONNULL RzPdbTpiStream *stream, RzPdbTpiType *t) {
	rz_return_val_if_fail(t, NULL);
	RzPdbTpiType *tmp;
	switch (t->leaf) {
	case LF_FIELDLIST: {
		Tpi_LF_FieldList *lf = t->data;
		return lf->substructs;
	}
	case LF_UNION: {
		tmp = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Union *)t->data)->field_list);
		Tpi_LF_FieldList *lf_union = tmp ? tmp->data : NULL;
		return lf_union ? lf_union->substructs : NULL;
	}
	case LF_STRUCTURE:
	case LF_CLASS: {
		tmp = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Structure *)t->data)->field_list);
		Tpi_LF_FieldList *lf_struct = tmp ? tmp->data : NULL;
		return lf_struct ? lf_struct->substructs : NULL;
	}
	case LF_STRUCTURE_19:
	case LF_CLASS_19: {
		tmp = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Structure_19 *)t->data)->field_list);
		Tpi_LF_FieldList *lf_struct19 = tmp ? tmp->data : NULL;
		return lf_struct19 ? lf_struct19->substructs : NULL;
	}
	case LF_ENUM: {
		tmp = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)t->data)->field_list);
		Tpi_LF_FieldList *lf_enum = tmp ? tmp->data : NULL;
		return lf_enum ? lf_enum->substructs : NULL;
	}
	default:
		return NULL;
	}
}

/**
 * \brief Get the name of the type
 *
 * \param type RzPdbTpiType *
 * \return char *
 */
RZ_API RZ_BORROW char *rz_bin_pdb_get_type_name(RZ_NONNULL RzPdbTpiType *type) {
	rz_return_val_if_fail(type, NULL);
	switch (type->leaf) {
	case LF_MEMBER: {
		Tpi_LF_Member *lf_member = type->data;
		return lf_member->name.name;
	}
	case LF_STMEMBER: {
		Tpi_LF_StaticMember *lf_stmember = type->data;
		return lf_stmember->name.name;
	}
	case LF_ONEMETHOD: {
		Tpi_LF_OneMethod *lf_onemethod = type->data;
		return lf_onemethod->name.name;
	}
	case LF_METHOD: {
		Tpi_LF_Method *lf_method = type->data;
		return lf_method->name.name;
	}
	case LF_NESTTYPE: {
		Tpi_LF_NestType *lf_nesttype = type->data;
		return lf_nesttype->name.name;
	}
	case LF_ENUM: {
		Tpi_LF_Enum *lf_enum = type->data;
		return lf_enum->name.name;
	}
	case LF_ENUMERATE: {
		Tpi_LF_Enumerate *lf_enumerate = type->data;
		return lf_enumerate->name.name;
	}
	case LF_CLASS:
	case LF_STRUCTURE: {
		Tpi_LF_Structure *lf_struct = type->data;
		return lf_struct->name.name;
	}
	case LF_CLASS_19:
	case LF_STRUCTURE_19: {
		Tpi_LF_Structure_19 *lf_struct_19 = type->data;
		return lf_struct_19->name.name;
	}
	case LF_ARRAY: {
		Tpi_LF_Array *lf_array = type->data;
		return lf_array->name.name;
	}
	case LF_UNION: {
		Tpi_LF_Union *lf_union = type->data;
		return lf_union->name.name;
	}
	default:
		return NULL;
	}
}

/**
 * \brief Get the numeric value inside the type
 *
 * \param type RzPdbTpiType *
 * \return ut64
 */
RZ_API ut64 rz_bin_pdb_get_type_val(RZ_NONNULL RzPdbTpiType *type) {
	rz_return_val_if_fail(type, -1);
	switch (type->leaf) {
	case LF_ONEMETHOD: {
		Tpi_LF_OneMethod *lf_onemethod = type->data;
		return lf_onemethod->offset_in_vtable;
	}
	case LF_MEMBER: {
		Tpi_LF_Member *lf_member = type->data;
		return get_numeric_val(&lf_member->offset);
	}
	case LF_ENUMERATE: {
		Tpi_LF_Enumerate *lf_enumerate = type->data;
		return get_numeric_val(&lf_enumerate->enum_value);
	}
	case LF_CLASS:
	case LF_STRUCTURE: {
		Tpi_LF_Structure *lf_struct = type->data;
		return get_numeric_val(&lf_struct->size);
	}
	case LF_CLASS_19:
	case LF_STRUCTURE_19: {
		Tpi_LF_Structure_19 *lf_struct_19 = type->data;
		return get_numeric_val(&lf_struct_19->size);
	}
	case LF_ARRAY: {
		Tpi_LF_Array *lf_array = type->data;
		return get_numeric_val(&lf_array->size);
	}
	case LF_UNION: {
		Tpi_LF_Union *lf_union = type->data;
		return get_numeric_val(&lf_union->size);
	}
	case LF_INDEX: {
		Tpi_LF_Index *lf_index = type->data;
		return lf_index->index;
	}
	default:
		return 0;
	}
}

static void free_snumeric(Tpi_Type_Numeric *numeric) {
	switch (numeric->type_index) {
	case LF_CHAR:
	case LF_SHORT:
	case LF_USHORT:
	case LF_LONG:
	case LF_ULONG:
	case LF_QUADWORD:
	case LF_UQUADWORD:
		RZ_FREE(numeric->data);
		break;
	default:
		if (numeric->type_index >= 0x8000) {
			eprintf("%s::not supproted type\n", __FUNCTION__);
			break;
		}
		RZ_FREE(numeric->data);
	}
}

static void free_tpi_type(void *type_info) {
	rz_return_if_fail(type_info);
	RzPdbTpiType *type = (RzPdbTpiType *)type_info;
	switch (type->leaf) {
	case LF_ENUMERATE: {
		Tpi_LF_Enumerate *lf_en = (Tpi_LF_Enumerate *)type->data;
		free_snumeric(&(lf_en->enum_value));
		RZ_FREE(lf_en->name.name);
		break;
	}
	case LF_NESTTYPE: {
		Tpi_LF_NestType *lf_nest = (Tpi_LF_NestType *)type->data;
		RZ_FREE(lf_nest->name.name);
		break;
	}
	case LF_METHOD: {
		Tpi_LF_Method *lf_meth = (Tpi_LF_Method *)type->data;
		RZ_FREE(lf_meth->name.name);
		break;
	}
	case LF_MEMBER: {
		Tpi_LF_Member *lf_mem = (Tpi_LF_Member *)type->data;
		free_snumeric(&lf_mem->offset);
		RZ_FREE(lf_mem->name.name);
		break;
	}
	case LF_STMEMBER: {
		Tpi_LF_StaticMember *lf_stmem = (Tpi_LF_StaticMember *)type->data;
		RZ_FREE(lf_stmem->name.name);
		break;
	}
	case LF_FIELDLIST: {
		Tpi_LF_FieldList *lf_fieldlist = (Tpi_LF_FieldList *)type->data;
		rz_pvector_free(lf_fieldlist->substructs);
		break;
	}
	case LF_CLASS:
	case LF_STRUCTURE: {
		Tpi_LF_Structure *lf_class = (Tpi_LF_Structure *)type->data;
		free_snumeric(&lf_class->size);
		RZ_FREE(lf_class->name.name);
		RZ_FREE(lf_class->mangled_name.name);
		break;
	}
	case LF_CLASS_19:
	case LF_STRUCTURE_19: {
		Tpi_LF_Structure_19 *lf_class_19 = (Tpi_LF_Structure_19 *)type->data;
		free_snumeric(&lf_class_19->size);
		RZ_FREE(lf_class_19->name.name);
		RZ_FREE(lf_class_19->mangled_name.name);
		break;
	}
	case LF_UNION: {
		Tpi_LF_Union *lf_union = (Tpi_LF_Union *)type->data;
		free_snumeric(&lf_union->size);
		RZ_FREE(lf_union->name.name);
		RZ_FREE(lf_union->mangled_name.name);
		break;
	}
	case LF_ONEMETHOD: {
		Tpi_LF_OneMethod *lf_onemethod = (Tpi_LF_OneMethod *)type->data;
		RZ_FREE(lf_onemethod->name.name);
		break;
	}
	case LF_BCLASS: {
		Tpi_LF_BClass *lf_bclass = (Tpi_LF_BClass *)type->data;
		free_snumeric(&lf_bclass->offset);
		break;
	}
	case LF_VBCLASS:
	case LF_IVBCLASS: {
		Tpi_LF_VBClass *lf_vbclass = (Tpi_LF_VBClass *)type->data;
		free_snumeric(&lf_vbclass->vb_pointer_offset);
		free_snumeric(&lf_vbclass->vb_offset_from_vbtable);
		break;
	}
	case LF_ENUM: {
		Tpi_LF_Enum *lf_enum = (Tpi_LF_Enum *)type->data;
		RZ_FREE(lf_enum->name.name);
		RZ_FREE(lf_enum->mangled_name.name);
		break;
	}
	case LF_ARRAY: {
		Tpi_LF_Array *lf_array = (Tpi_LF_Array *)type->data;
		free_snumeric(&lf_array->size);
		RZ_FREE(lf_array->name.name);
		break;
	}
	case LF_ARGLIST: {
		Tpi_LF_Arglist *lf_arglist = (Tpi_LF_Arglist *)type->data;
		RZ_FREE(lf_arglist->arg_type);
		break;
	}
	case LF_VTSHAPE: {
		Tpi_LF_Vtshape *lf_vtshape = (Tpi_LF_Vtshape *)type->data;
		RZ_FREE(lf_vtshape->vt_descriptors);
		break;
	}
	case LF_SIMPLE_TYPE: {
		Tpi_LF_SimpleType *lf_simple = (Tpi_LF_SimpleType *)type->data;
		RZ_FREE(lf_simple->type);
		break;
	}
	case LF_METHODLIST: {
		Tpi_LF_MethodList *lf_mlist = (Tpi_LF_MethodList *)type->data;
		rz_list_free(lf_mlist->members);
		break;
	}
	case LF_VFTABLE: {
		Tpi_LF_Vftable *vft = type->data;
		rz_pvector_fini(&vft->method_names);
		break;
	}
	case LF_POINTER:
	case LF_PROCEDURE:
	case LF_MODIFIER:
	case LF_MFUNCTION:
	case LF_BITFIELD:
	case LF_INDEX:
	case LF_VFUNCTAB:
	case LF_LABEL:
		break;
	case 0:
		if (type->index < 0x1000) {
			simple_type_free(type->data);
		}
		break;
	default:
		if (type->data) {
			rz_warn_if_reached();
		}
		break;
	}
	free(type->data);
	free(type);
}

static void free_tpi_rbtree(RBNode *node, void *user) {
	rz_return_if_fail(node);
	RzPdbTpiType *type = container_of(node, RzPdbTpiType, rb);
	free_tpi_type(type);
}

RZ_IPI void free_tpi_stream(RzPdbTpiStream *stream) {
	if (!stream) {
		return;
	}
	rz_rbtree_free(stream->types, free_tpi_rbtree, NULL);
	rz_list_free(stream->print_type);
	free(stream);
}

static bool parse_type_numeric(RzBuffer *buf, Tpi_Type_Numeric *numeric) {
	numeric->data = 0;
	numeric->is_integer = true;
	if (!rz_buf_read_le16(buf, &numeric->type_index)) {
		return false;
	}
	switch (numeric->type_index) {
	case LF_CHAR:
		numeric->data = RZ_NEW0(st8);
		if (!rz_buf_read8(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	case LF_SHORT:
		numeric->data = RZ_NEW0(st16);
		if (!rz_buf_read_le16(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	case LF_USHORT:
		numeric->data = RZ_NEW0(ut16);
		if (!rz_buf_read_le16(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	case LF_LONG:
		numeric->data = RZ_NEW0(st32);
		if (!rz_buf_read_le32(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	case LF_ULONG:
		numeric->data = RZ_NEW0(ut32);
		if (!rz_buf_read_le32(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	case LF_QUADWORD:
		numeric->data = RZ_NEW0(st64);
		if (!rz_buf_read_le64(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	case LF_UQUADWORD:
		numeric->data = RZ_NEW0(ut64);
		if (!rz_buf_read_le64(buf, numeric->data)) {
			RZ_FREE(numeric->data);
			return false;
		}
		break;
	default:
		if (numeric->type_index >= 0x8000) {
			numeric->is_integer = false;
			RZ_LOG_ERROR("%s: Skipping unsupported type (%d)\n", __FUNCTION__,
				numeric->type_index);
			return false;
		}
		numeric->data = RZ_NEW0(ut16);
		*(ut16 *)(numeric->data) = numeric->type_index;
		return true;
	}
	return true;
}

static void parse_type_string(RzBuffer *buf, Tpi_Type_String *str) {
	str->size = rz_buf_read_string(buf, &str->name);
}

static Tpi_LF_Enumerate *parse_type_enumerate(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Enumerate *enumerate = RZ_NEW0(Tpi_LF_Enumerate);
	if (!enumerate) {
		return NULL;
	}
	ut16 fldattr;
	if (!rz_buf_read_le16(buf, &fldattr)) {
		RZ_FREE(enumerate);
		return NULL;
	}
	parse_codeview_fld_attribute(&enumerate->fldattr, fldattr);
	if (!parse_type_numeric(buf, &enumerate->enum_value)) {
		RZ_FREE(enumerate);
		return NULL;
	}
	if (!enumerate->enum_value.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&enumerate->enum_value);
		RZ_FREE(enumerate);
		return NULL;
	}
	parse_type_string(buf, &enumerate->name);
	return enumerate;
}

static Tpi_LF_Index *parse_type_index(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Index *index = RZ_NEW0(Tpi_LF_Index);
	if (!index) {
		return NULL;
	}
	if (!(rz_buf_read_le16(b, &index->pad0) &&
		    rz_buf_read_le32(b, &index->index))) {
		goto err;
	}
	if (index->pad0 != 0) {
		RZ_LOG_ERROR("LF_Index pad0 must be 0\n");
		goto err;
	}
	index->leaf = LF_INDEX;
	return index;
err:
	free(index);
	return NULL;
}

static Tpi_LF_NestType *parse_type_nesttype(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_NestType *nest = RZ_NEW0(Tpi_LF_NestType);
	if (!nest) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &nest->pad)) {
		RZ_FREE(nest);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &nest->index)) {
		RZ_FREE(nest);
		return NULL;
	}
	parse_type_string(buf, &nest->name);
	return nest;
}

static Tpi_LF_VFuncTab *parse_type_vfunctab(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_VFuncTab *vftab = RZ_NEW0(Tpi_LF_VFuncTab);
	if (!vftab) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &vftab->pad)) {
		RZ_FREE(vftab);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &vftab->index)) {
		RZ_FREE(vftab);
		return NULL;
	}
	return vftab;
}

static Tpi_LF_Method *parse_type_method(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Method *method = RZ_NEW0(Tpi_LF_Method);
	if (!method) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &method->count)) {
		RZ_FREE(method);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &method->mlist)) {
		RZ_FREE(method);
		return NULL;
	}
	parse_type_string(buf, &method->name);
	return method;
}

static Tpi_LF_Member *parse_type_member(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Member *member = RZ_NEW0(Tpi_LF_Member);
	if (!member) {
		return NULL;
	}
	ut16 fldattr;
	if (!rz_buf_read_le16(buf, &fldattr)) {
		RZ_FREE(member);
		return NULL;
	}
	parse_codeview_fld_attribute(&member->fldattr, fldattr);
	if (!rz_buf_read_le32(buf, &member->index)) {
		RZ_FREE(member);
		return NULL;
	}
	if (!parse_type_numeric(buf, &member->offset)) {
		RZ_FREE(member);
		return NULL;
	}
	if (!member->offset.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&member->offset);
		RZ_FREE(member);
		return NULL;
	}
	parse_type_string(buf, &member->name);
	return member;
}

static Tpi_LF_StaticMember *parse_type_staticmember(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_StaticMember *member = RZ_NEW0(Tpi_LF_StaticMember);
	if (!member) {
		return NULL;
	}
	ut16 fldattr;
	if (!rz_buf_read_le16(buf, &fldattr)) {
		RZ_FREE(member);
		return NULL;
	}
	parse_codeview_fld_attribute(&member->fldattr, fldattr);
	if (!rz_buf_read_le32(buf, &member->index)) {
		RZ_FREE(member);
		return NULL;
	}
	parse_type_string(buf, &member->name);
	return member;
}

static Tpi_LF_OneMethod *parse_type_onemethod(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_OneMethod *onemethod = RZ_NEW0(Tpi_LF_OneMethod);
	if (!onemethod) {
		return NULL;
	}
	ut16 fldattr;
	if (!rz_buf_read_le16(buf, &fldattr)) {
		RZ_FREE(onemethod);
		return NULL;
	}
	parse_codeview_fld_attribute(&onemethod->fldattr, fldattr);
	if (!rz_buf_read_le32(buf, &onemethod->index)) {
		RZ_FREE(onemethod);
		return NULL;
	}
	onemethod->offset_in_vtable = 0;
	if (onemethod->fldattr.mprop == MTintro ||
		onemethod->fldattr.mprop == MTpureintro) {
		if (!rz_buf_read_le32(buf, &onemethod->offset_in_vtable)) {
			RZ_FREE(onemethod);
		}
	}
	parse_type_string(buf, &onemethod->name);
	return onemethod;
}

static Tpi_LF_BClass *parse_type_bclass(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_BClass *bclass = RZ_NEW0(Tpi_LF_BClass);
	if (!bclass) {
		return NULL;
	}
	ut16 fldattr;
	if (!rz_buf_read_le16(buf, &fldattr)) {
		RZ_FREE(bclass);
		return NULL;
	}
	parse_codeview_fld_attribute(&bclass->fldattr, fldattr);
	if (!rz_buf_read_le32(buf, &bclass->index)) {
		RZ_FREE(bclass);
		return NULL;
	}
	if (!parse_type_numeric(buf, &bclass->offset)) {
		RZ_FREE(bclass);
		return NULL;
	}
	if (!bclass->offset.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&bclass->offset);
		RZ_FREE(bclass);
		return NULL;
	}
	return bclass;
}

static Tpi_LF_VBClass *parse_type_vbclass(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_VBClass *bclass = RZ_NEW0(Tpi_LF_VBClass);
	if (!bclass) {
		return NULL;
	}
	ut16 fldattr;
	if (!rz_buf_read_le16(buf, &fldattr)) {
		RZ_FREE(bclass);
		return NULL;
	}
	parse_codeview_fld_attribute(&bclass->fldattr, fldattr);
	if (!rz_buf_read_le32(buf, &bclass->direct_vbclass_idx)) {
		RZ_FREE(bclass);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &bclass->vb_pointer_idx)) {
		RZ_FREE(bclass);
		return NULL;
	}
	parse_type_numeric(buf, &bclass->vb_pointer_offset);
	if (!bclass->vb_pointer_offset.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&bclass->vb_pointer_offset);
		RZ_FREE(bclass);
		return NULL;
	}
	parse_type_numeric(buf, &bclass->vb_offset_from_vbtable);
	if (!bclass->vb_offset_from_vbtable.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&bclass->vb_offset_from_vbtable);
		RZ_FREE(bclass);
		return NULL;
	}
	return bclass;
}

static Tpi_LF_FieldList *parse_type_fieldlist(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_FieldList *fieldlist = RZ_NEW0(Tpi_LF_FieldList);
	if (!fieldlist) {
		return NULL;
	}
	fieldlist->substructs = rz_pvector_new(free_tpi_type);
	if (!fieldlist->substructs) {
		goto error;
	}
	while (!buf_empty(b)) {
		RzPdbTpiType *t = RzPdbTpiType_from_buf(b, 0, 0);
		if (!t) {
			continue;
		}
		buf_read_padding(b);
		rz_pvector_push(fieldlist->substructs, t);
	}
	return fieldlist;
error:
	RZ_LOG_ERROR("failed type_fieldlist\n");
	rz_pvector_free(fieldlist->substructs);
	RZ_FREE(fieldlist);
	return NULL;
}

static Tpi_LF_Enum *parse_type_enum(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Enum *_enum = RZ_NEW0(Tpi_LF_Enum);
	if (!_enum) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &_enum->count)) {
		RZ_FREE(_enum);
		return NULL;
	}
	ut16 prop;
	if (!rz_buf_read_le16(buf, &prop)) {
		RZ_FREE(_enum);
		return NULL;
	}
	parse_codeview_property(&_enum->prop, prop);
	if (!rz_buf_read_le32(buf, &_enum->utype)) {
		RZ_FREE(_enum);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &_enum->field_list)) {
		RZ_FREE(_enum);
		return NULL;
	}
	parse_type_string(buf, &_enum->name);
	if (_enum->prop.has_uniquename) {
		parse_type_string(buf, &_enum->mangled_name);
	}
	return _enum;
}

static Tpi_LF_Structure *parse_type_struct(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Structure *structure = RZ_NEW0(Tpi_LF_Structure);
	if (!structure) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &structure->count)) {
		RZ_FREE(structure);
		return NULL;
	}
	ut16 prop;
	if (!rz_buf_read_le16(buf, &prop)) {
		RZ_FREE(structure);
		return NULL;
	}
	parse_codeview_property(&structure->prop, prop);
	if (!rz_buf_read_le32(buf, &structure->field_list)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &structure->derived)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &structure->vshape)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!parse_type_numeric(buf, &structure->size)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!structure->size.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&structure->size);
		RZ_FREE(structure);
		return NULL;
	}
	parse_type_string(buf, &structure->name);
	parse_type_string(buf, &structure->mangled_name);
	return structure;
}

static Tpi_LF_Structure_19 *parse_type_struct_19(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Structure_19 *structure = RZ_NEW0(Tpi_LF_Structure_19);
	if (!structure) {
		return NULL;
	}
	ut16 prop;
	if (!rz_buf_read_le16(buf, &prop)) {
		RZ_FREE(structure);
		return NULL;
	}
	parse_codeview_property(&structure->prop, prop);
	if (!rz_buf_read_le16(buf, &structure->unknown)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &structure->field_list)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &structure->derived)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &structure->vshape)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!parse_type_numeric(buf, &structure->unknown1)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!parse_type_numeric(buf, &structure->size)) {
		RZ_FREE(structure);
		return NULL;
	}
	if (!structure->size.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&structure->size);
		RZ_FREE(structure);
		return NULL;
	}
	parse_type_string(buf, &structure->name);
	parse_type_string(buf, &structure->mangled_name);
	return structure;
}

static Tpi_LF_Pointer *parse_type_pointer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Pointer *pointer = RZ_NEW0(Tpi_LF_Pointer);
	if (!pointer) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &pointer->utype)) {
		RZ_FREE(pointer);
		return NULL;
	}
	ut32 ptrattr;
	if (!rz_buf_read_le32(buf, &ptrattr)) {
		RZ_FREE(pointer);
		return NULL;
	}
	parse_codeview_pointer_attribute(&pointer->ptr_attr, ptrattr);
	if (pointer->ptr_attr.ptrmode == PTR_MODE_PMFUNC ||
		pointer->ptr_attr.ptrmode == PTR_MODE_PMEM) {
		if (!rz_buf_read_le32(buf, &pointer->pmember.pmclass)) {
			RZ_FREE(pointer);
			return NULL;
		}
		if (!rz_buf_read_le16(buf, &pointer->pmember.pmtype)) {
			RZ_FREE(pointer);
			return NULL;
		}
	} else if (pointer->ptr_attr.ptrtype == PTR_BASE_TYPE) {
		if (!rz_buf_read_le32(buf, &pointer->pbase.index)) {
			RZ_FREE(pointer);
			return NULL;
		}
	}
	return pointer;
}

static Tpi_LF_Array *parse_type_array(RzBuffer *buf, TpiLeafType leaf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Array *array = RZ_NEW0(Tpi_LF_Array);
	if (!array) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &array->element_type)) {
		goto err;
	}
	if (!rz_buf_read_le32(buf, &array->index_type)) {
		goto err;
	}
	if (leaf == LF_STRIDED_ARRAY) {
		if (!rz_buf_read_le32(buf, &array->stride)) {
			goto err;
		}
	}
	if (!parse_type_numeric(buf, &array->size)) {
		goto err;
	}
	if (!array->size.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&array->size);
		goto err;
	}
	parse_type_string(buf, &array->name);
	return array;
err:
	RZ_FREE(array);
	return NULL;
}

static Tpi_LF_Modifier *parse_type_modifier(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Modifier *modifier = RZ_NEW0(Tpi_LF_Modifier);
	if (!modifier) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &modifier->modified_type)) {
		RZ_FREE(modifier);
		return NULL;
	}
	ut16 umodifier;
	if (!rz_buf_read_le16(buf, &umodifier)) {
		RZ_FREE(modifier);
		return NULL;
	}
	parse_codeview_modifier(&modifier->umodifier, umodifier);
	return modifier;
}

static Tpi_LF_Arglist *parse_type_arglist(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Arglist *arglist = RZ_NEW0(Tpi_LF_Arglist);
	if (!arglist) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &arglist->count)) {
		RZ_FREE(arglist);
		return NULL;
	}
	arglist->arg_type = (ut32 *)malloc(sizeof(ut32) * arglist->count);
	if (!arglist->arg_type) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		RZ_FREE(arglist);
		return NULL;
	}
	for (size_t i = 0; i < arglist->count; i++) {
		if (!rz_buf_read_le32(buf, &arglist->arg_type[i])) {
			RZ_FREE(arglist->arg_type);
			RZ_FREE(arglist);
			return NULL;
		}
	}
	return arglist;
}

static Tpi_LF_MFcuntion *parse_type_mfunction(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_MFcuntion *mfunc = RZ_NEW0(Tpi_LF_MFcuntion);
	if (!mfunc) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &mfunc->return_type)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &mfunc->class_type)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &mfunc->this_type)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	if (!rz_buf_read8(buf, (ut8 *)&mfunc->call_conv)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	ut8 funcattr;
	if (!rz_buf_read8(buf, &funcattr)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	parse_codeview_func_attribute(&mfunc->func_attr, funcattr);
	if (!rz_buf_read_le16(buf, &mfunc->parm_count)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &mfunc->arglist)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, (ut32 *)&mfunc->this_adjust)) {
		RZ_FREE(mfunc);
		return NULL;
	}
	return mfunc;
}

static Tpi_LF_MethodList *parse_type_methodlist(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_MethodList *mlist = RZ_NEW0(Tpi_LF_MethodList);
	if (!mlist) {
		return NULL;
	}
	mlist->members = rz_list_newf(free);
	if (!mlist->members) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		goto error;
	}
	while (!buf_empty(buf)) {
		Tpi_Type_MethodListMember *member = RZ_NEW0(Tpi_Type_MethodListMember);
		if (!member) {
			continue;
		}
		ut16 fldattr;
		if (!rz_buf_read_le16(buf, &fldattr)) {
			RZ_FREE(member);
			rz_list_free(mlist->members);
			RZ_FREE(mlist);
			return NULL;
		}
		parse_codeview_fld_attribute(&member->fldattr, fldattr);
		if (!rz_buf_read_le16(buf, &member->pad)) {
			RZ_FREE(member);
			rz_list_free(mlist->members);
			RZ_FREE(mlist);
			return NULL;
		}
		if (!rz_buf_read_le32(buf, &member->type)) {
			RZ_FREE(member);
			rz_list_free(mlist->members);
			RZ_FREE(mlist);
			return NULL;
		}
		member->optional_offset = 0;
		if (member->fldattr.mprop == MTintro ||
			member->fldattr.mprop == MTpureintro) {
			if (!rz_buf_read_le32(buf, &member->optional_offset)) {
				RZ_FREE(member);
				rz_list_free(mlist->members);
				RZ_FREE(mlist);
				return NULL;
			}
		}
		rz_list_append(mlist->members, member);
	}
	return mlist;

error:
	RZ_FREE(mlist);
	return NULL;
}

static Tpi_LF_Procedure *parse_type_procedure(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Procedure *proc = RZ_NEW0(Tpi_LF_Procedure);
	if (!proc) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &proc->return_type)) {
		RZ_FREE(proc);
		return NULL;
	}
	if (!rz_buf_read8(buf, (ut8 *)&proc->call_conv)) {
		RZ_FREE(proc);
		return NULL;
	}
	ut8 funcattr;
	if (!rz_buf_read8(buf, &funcattr)) {
		RZ_FREE(proc);
		return NULL;
	}
	parse_codeview_func_attribute(&proc->func_attr, funcattr);
	if (!rz_buf_read_le16(buf, &proc->parm_count)) {
		RZ_FREE(proc);
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &proc->arg_list)) {
		RZ_FREE(proc);
		return NULL;
	}
	return proc;
}

static Tpi_LF_Union *parse_type_union(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Union *unin = RZ_NEW0(Tpi_LF_Union);
	if (!unin) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &unin->count)) {
		RZ_FREE(unin);
		return NULL;
	}
	ut16 prop;
	if (!rz_buf_read_le16(buf, &prop)) {
		RZ_FREE(unin);
		return NULL;
	}
	parse_codeview_property(&unin->prop, prop);
	if (!rz_buf_read_le32(buf, &unin->field_list)) {
		RZ_FREE(unin);
		return NULL;
	}
	if (!parse_type_numeric(buf, &unin->size)) {
		RZ_FREE(unin);
	}
	if (!unin->size.is_integer) {
		RZ_LOG_ERROR("Integer expected!\n");
		free_snumeric(&unin->size);
		RZ_FREE(unin);
		return NULL;
	}
	parse_type_string(buf, &unin->name);
	parse_type_string(buf, &unin->mangled_name);
	return unin;
}

static Tpi_LF_Bitfield *parse_type_bitfield(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Bitfield *bf = RZ_NEW0(Tpi_LF_Bitfield);
	if (!bf) {
		return NULL;
	}
	if (!rz_buf_read_le32(buf, &bf->base_type)) {
		RZ_FREE(bf);
		return NULL;
	}
	if (!rz_buf_read8(buf, &bf->length)) {
		RZ_FREE(bf);
		return NULL;
	}
	if (!rz_buf_read8(buf, &bf->position)) {
		RZ_FREE(bf);
		return NULL;
	}
	return bf;
}

static Tpi_LF_Vtshape *parse_type_vtshape(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Vtshape *vt = RZ_NEW0(Tpi_LF_Vtshape);
	if (!vt) {
		return NULL;
	}
	if (!rz_buf_read_le16(buf, &vt->count)) {
		RZ_FREE(vt);
		return NULL;
	}
	ut16 size = (4 * vt->count + (vt->count % 2) * 4) / 8;
	vt->vt_descriptors = (char *)malloc(size);
	if (!vt->vt_descriptors) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		RZ_FREE(vt);
		return NULL;
	}
	rz_buf_read(buf, (ut8 *)vt->vt_descriptors, size);
	return vt;
}

static Tpi_LF_Vftable *vftable_parse(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Vftable *vft = RZ_NEW0(Tpi_LF_Vftable);
	if (!vft) {
		return NULL;
	}

	if (!rz_buf_read_le32(buf, (ut32 *)&vft->complete_class)) {
		goto err;
	}
	if (!rz_buf_read_le32(buf, (ut32 *)&vft->override_vftable)) {
		goto err;
	}
	if (!rz_buf_read_le32(buf, (ut32 *)&vft->vfptr_offset)) {
		goto err;
	}
	ut32 names_len = 0;
	if (!rz_buf_read_le32(buf, &names_len)) {
		goto err;
	}
	rz_pvector_init(&vft->method_names, free);

	while (rz_buf_peek(buf) < LF_PAD0) {
		char *name = NULL;
		ut64 nlen = rz_buf_read_string(buf, &name);
		if (nlen <= 0) {
			continue;
		}
		rz_pvector_push(&vft->method_names, name);
	}
	return vft;
err:
	rz_pvector_fini(&vft->method_names);
	RZ_FREE(vft);
	return NULL;
}

static Tpi_LF_Label *labal_parse(RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	Tpi_LF_Label *record = RZ_NEW0(Tpi_LF_Label);
	if (!record) {
		return NULL;
	}

	if (!rz_buf_read_le32(buf, (ut32 *)&record->mode)) {
		goto err;
	}
	return record;
err:
	RZ_FREE(record);
	return NULL;
}

static RzPdbTpiType *RzPdbTpiType_from_buf(RzBuffer *b, ut32 index, ut16 length) {
	if (!b) {
		return NULL;
	}
	ut16 leaf = 0;
	if (!rz_buf_read_le16(b, &leaf)) {
		return NULL;
	}

	void *data = NULL;
	switch (leaf) {
	case LF_FIELDLIST:
		data = parse_type_fieldlist(b);
		break;
	case LF_ENUM:
		data = parse_type_enum(b);
		break;
	case LF_CLASS:
	case LF_STRUCTURE:
		data = parse_type_struct(b);
		break;
	case LF_CLASS_19:
	case LF_STRUCTURE_19:
		data = parse_type_struct_19(b);
		break;
	case LF_POINTER:
		data = parse_type_pointer(b);
		break;
	case LF_ARRAY:
	case LF_ARRAY_ST:
	case LF_STRIDED_ARRAY:
		data = parse_type_array(b, leaf);
		break;
	case LF_MODIFIER:
		data = parse_type_modifier(b);
		break;
	case LF_ARGLIST:
		data = parse_type_arglist(b);
		break;
	case LF_MFUNCTION:
		data = parse_type_mfunction(b);
		break;
	case LF_METHODLIST:
		data = parse_type_methodlist(b);
		break;
	case LF_PROCEDURE:
		data = parse_type_procedure(b);
		break;
	case LF_UNION:
		data = parse_type_union(b);
		break;
	case LF_BITFIELD:
		data = parse_type_bitfield(b);
		break;
	case LF_VTSHAPE:
		data = parse_type_vtshape(b);
		break;
	case LF_VFTABLE:
		data = vftable_parse(b);
		break;
	case LF_LABEL:
		data = labal_parse(b);
		break;
	case LF_ENUMERATE:
		data = parse_type_enumerate(b);
		break;
	case LF_NESTTYPE:
		data = parse_type_nesttype(b);
		break;
	case LF_VFUNCTAB:
		data = parse_type_vfunctab(b);
		break;
	case LF_METHOD:
		data = parse_type_method(b);
		break;
	case LF_MEMBER:
		data = parse_type_member(b);
		break;
	case LF_ONEMETHOD:
		data = parse_type_onemethod(b);
		break;
	case LF_BCLASS:
		data = parse_type_bclass(b);
		break;
	case LF_VBCLASS:
	case LF_IVBCLASS:
		data = parse_type_vbclass(b);
		break;
	case LF_STMEMBER:
		data = parse_type_staticmember(b);
		break;
	case LF_INDEX:
		data = parse_type_index(b);
		break;
	default:
		RZ_LOG_DEBUG("%s: 0x%" PFMT32x ": unsupported leaf type: 0x%" PFMT32x "\n", __FUNCTION__, index, leaf);
		break;
	}

	if (!data && !length && !index) {
		return NULL;
	}

	RzPdbTpiType *type = RZ_NEW0(RzPdbTpiType);
	if (!type) {
		free(data);
		return NULL;
	}
	type->index = index;
	type->length = length;
	type->leaf = leaf;
	type->data = data;
	return type;
}

static bool parse_tpi_stream_header(RzPdbTpiStream *s, RzBuffer *buf) {
	return rz_buf_read_le32(buf, (ut32 *)&s->header.Version) &&
		rz_buf_read_le32(buf, &s->header.HeaderSize) &&
		rz_buf_read_le32(buf, &s->header.TypeIndexBegin) &&
		rz_buf_read_le32(buf, &s->header.TypeIndexEnd) &&
		rz_buf_read_le32(buf, &s->header.TypeRecordBytes) &&

		rz_buf_read_le16(buf, &s->header.HashStreamIndex) &&
		rz_buf_read_le16(buf, &s->header.HashAuxStreamIndex) &&
		rz_buf_read_le32(buf, &s->header.HashKeySize) &&
		rz_buf_read_le32(buf, &s->header.NumHashBuckets) &&

		rz_buf_read_le32(buf, (ut32 *)&s->header.HashValueBufferOffset) &&
		rz_buf_read_le32(buf, &s->header.HashValueBufferLength) &&

		rz_buf_read_le32(buf, (ut32 *)&s->header.IndexOffsetBufferOffset) &&
		rz_buf_read_le32(buf, &s->header.IndexOffsetBufferLength) &&

		rz_buf_read_le32(buf, (ut32 *)&s->header.HashAdjBufferOffset) &&
		rz_buf_read_le32(buf, &s->header.HashAdjBufferLength);
}

RZ_IPI bool parse_tpi_stream(RzPdb *pdb, RzPdbMsfStream *stream) {
	if (!pdb || !stream) {
		return false;
	}
	if (stream->stream_idx != PDB_STREAM_TPI) {
		RZ_LOG_ERROR("Error TPI stream index.\n");
		return false;
	}
	pdb->s_tpi = RZ_NEW0(RzPdbTpiStream);
	RzPdbTpiStream *s = pdb->s_tpi;
	if (!s) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return false;
	}
	s->types = NULL;
	RzBuffer *steam_buffer = stream->stream_data;
	if (!parse_tpi_stream_header(s, steam_buffer)) {
		return false;
	}
	if (s->header.HeaderSize != sizeof(RzPdbTpiStreamHeader)) {
		RZ_LOG_ERROR("Corrupted TPI stream.\n");
		return false;
	}
	for (ut32 index = s->header.TypeIndexBegin; index < s->header.TypeIndexEnd; index++) {
		ut16 length = 0;
		if (!rz_buf_read_le16(steam_buffer, &length)) {
			return false;
		}
		RzBuffer *b = buf_take(steam_buffer, length);
		if (!b) {
			return false;
		}

		RzPdbTpiType *type = RzPdbTpiType_from_buf(b, index, length);
		if (!type) {
			goto err;
		}
		rz_buf_free(b);
		rz_rbtree_insert(&s->types, &type->index, &type->rb, tpi_type_node_cmp, NULL);
		continue;
	err:
		rz_buf_free(b);
		free(type);
		return false;
	}
	return true;
}

/**
 * \brief Get RzPdbTpiType that matches tpi stream index
 * \param stream TPI Stream
 * \param index TPI Stream Index
 */
RZ_API RZ_BORROW RzPdbTpiType *rz_bin_pdb_get_type_by_index(
	RZ_NONNULL RzPdbTpiStream *stream, ut32 index) {
	rz_return_val_if_fail(stream, NULL);
	if (index == 0) {
		return NULL;
	}

	RBNode *node = rz_rbtree_find(stream->types, &index, tpi_type_node_cmp, NULL);
	if (!node) {
		if (is_simple_type(stream, index)) {
			return parse_simple_type(stream, index);
		}
		return NULL;
	}
	RzPdbTpiType *type = container_of(node, RzPdbTpiType, rb);
	return type;
}
