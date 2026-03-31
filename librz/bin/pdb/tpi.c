// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

#define conditional(X, T, F) (X ? T : F)

static bool buf_read_string(RzBuffer *b, ut16 leaf, char **result) {
	if (leaf < LF_ST_MAX) {
		return buf_read_u8_pascal_string(b, result);
	} else {
		return rz_buf_read_string(b, result) > 0;
	}
	return false;
}

static RzPdbTpiType *RzPdbTpiType_from_buf(RzBuffer *b, ut32 index, ut16 length);

int tpi_type_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut32 ia = *(ut32 *)incoming;
	ut32 ta = container_of(in_tree, const RzPdbTpiType, rb)->index;
	if (ia < ta) {
		return -1;
	}
	if (ia > ta) {
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
		return rz_str_dup("__cdecl");
	case NEAR_PASCAL:
	case FAR_PASCAL:
		return rz_str_dup("__pascal");
	case NEAR_FAST:
	case FAR_FAST:
		return rz_str_dup("__fastcall");
	case NEAR_STD:
	case FAR_STD:
		return rz_str_dup("__stdcall");
	case NEAR_SYS:
	case FAR_SYS:
		return rz_str_dup("__syscall");
	case THISCALL:
		return rz_str_dup("__thiscall");
	case NEAR_VEC:
		return rz_str_dup("__vectorcall");
	default:
		return NULL;
	}
}

#define GEN_PARSER(T, S, U, F) \
	static bool T##_parse(RzBuffer *b, T *p) { \
		U value; \
		if (!F(b, &value)) { \
			return false; \
		} \
		S(p, value); \
		return true; \
	}

static void set_property(TpiCVProperty *p, ut32 const value) {
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

GEN_PARSER(TpiCVProperty, set_property, ut16, rz_buf_read_le16);
static bool TpiCVProperty_parse_opt(RzBuffer *b, TpiCVProperty *p, const bool is32) {
	if (is32) {
		ut32 value;
		if (!rz_buf_read_le32(b, &value)) {
			return false;
		}
		set_property(p, value);
	} else {
		return TpiCVProperty_parse(b, p);
	}
	return true;
}

static void set_fldattr(TpiCVFldattr *f, ut16 value) {
	f->access = GET_BF(value, 0, 2);
	f->mprop = GET_BF(value, 2, 3);
	f->pseudo = GET_BF(value, 5, 1);
	f->noinherit = GET_BF(value, 6, 1);
	f->noconstruct = GET_BF(value, 7, 1);
	f->compgenx = GET_BF(value, 8, 1);
	f->sealed = GET_BF(value, 9, 1);
}
GEN_PARSER(TpiCVFldattr, set_fldattr, ut16, rz_buf_read_le16);

RZ_IPI bool TpiCVFldattr_is_intro_virtual(TpiCVFldattr *x) {
	return x && (x->mprop == MTintro || x->mprop == MTpureintro);
}

static void set_func_attribute(TpiCVFuncattr *f, ut16 value) {
	f->calling_convention = value & 0xff;
	f->cxxreturnudt = GET_BF(value, 0, 1);
	f->ctor = GET_BF(value, 1, 1);
	f->ctorvbase = GET_BF(value, 2, 1);
}
GEN_PARSER(TpiCVFuncattr, set_func_attribute, ut16, rz_buf_read_le16);

static void set_pointer_attribute(TpiCVPointerAttr *p, ut32 value) {
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
GEN_PARSER(TpiCVPointerAttr, set_pointer_attribute, ut32, rz_buf_read_le32);

RZ_IPI bool TpiCVPointerAttr_pointer_to_member(TpiCVPointerAttr *x) {
	return x && (x->ptrmode == PTR_MODE_PMFUNC || x->ptrmode == PTR_MODE_PMEM);
}

static void set_modifier(TpiCVModifier *m, ut16 value) {
	m->const_ = GET_BF(value, 0, 1);
	m->volatile_ = GET_BF(value, 1, 1);
	m->unaligned = GET_BF(value, 2, 1);
}
GEN_PARSER(TpiCVModifier, set_modifier, ut16, rz_buf_read_le16);

static bool simple_type_check(RzPdbTpiStream *stream, ut32 idx) {
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

static TpiSimpleTypeMode simple_type_mode(ut32 type) {
	/*   https://llvm.org/docs/PDB/RzPdbTpiStream.html#type-indices
  .---------------------------.------.----------.
  |           Unused          | Mode |   Kind   |
  '---------------------------'------'----------'
  |+32                        |+12   |+8        |+0
  */
	// because mode is only number between 0-7, 1 byte is enough
	return (type & 0x0000000000F00) >> 8;
}

static TpiSimpleTypeKind simple_type_kind(ut32 type) {
	/*   https://llvm.org/docs/PDB/RzPdbTpiStream.html#type-indices
  .---------------------------.------.----------.
  |           Unused          | Mode |   Kind   |
  '---------------------------'------'----------'
  |+32                        |+12   |+8        |+0
  */
	return (type & 0x00000000000FF);
}

/**
 * \brief Parses simple type if the idx represents one
 * \param RzPdbTpiStream TPI stream context
 * \param idx leaf index
 * \return RzPdbTpiType, leaf = 0 -> error
 */
RZ_IPI RzPdbTpiType *simple_type_parse(RzPdbTpiStream *stream, ut32 idx) {
	RzPdbTpiType *type = RZ_NEW0(RzPdbTpiType);
	if (!type) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return NULL;
	}
	type->leaf = LF_SIMPLE_TYPE;
	type->kind = TpiKind_SIMPLE_TYPE;
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
	RzStrBuf *b;
	TpiSimpleTypeKind kind = simple_type_kind(idx);
	switch (kind) {
	case PDB_NONE:
		simple_type->size = 0;
		b = rz_strbuf_new("notype_t");
		break;
	case PDB_VOID:
		simple_type->size = 0;
		b = rz_strbuf_new("void");
		break;
	case PDB_SIGNED_CHAR:
	case PDB_NARROW_CHAR:
		simple_type->size = 1;
		b = rz_strbuf_new("char");
		break;
	case PDB_UNSIGNED_CHAR:
		simple_type->size = 1;
		b = rz_strbuf_new("unsigned char");
		break;
	case PDB_WIDE_CHAR:
		simple_type->size = 4;
		b = rz_strbuf_new("wchar_t");
		break;
	case PDB_CHAR16:
		simple_type->size = 2;
		b = rz_strbuf_new("char16_t");
		break;
	case PDB_CHAR32:
		simple_type->size = 4;
		b = rz_strbuf_new("char32_t");
		break;
	case PDB_BYTE:
		simple_type->size = 1;
		b = rz_strbuf_new("uint8_t");
		break;
	case PDB_SBYTE:
		simple_type->size = 1;
		b = rz_strbuf_new("int8_t");
		break;
	case PDB_INT16:
	case PDB_INT16_SHORT:
		simple_type->size = 2;
		b = rz_strbuf_new("int16_t");
		break;
	case PDB_UINT16:
	case PDB_UINT16_SHORT:
		simple_type->size = 2;
		b = rz_strbuf_new("uint16_t");
		break;
	case PDB_INT32:
	case PDB_INT32_LONG:
		simple_type->size = 4;
		b = rz_strbuf_new("int32_t");
		break;
	case PDB_UINT32:
	case PDB_UINT32_LONG:
		simple_type->size = 4;
		b = rz_strbuf_new("uint32_t");
		break;
	case PDB_INT64:
	case PDB_INT64_QUAD:
		simple_type->size = 8;
		b = rz_strbuf_new("int64_t");
		break;
	case PDB_UINT64:
	case PDB_UINT64_QUAD:
		simple_type->size = 8;
		b = rz_strbuf_new("uint64_t");
		break;
	case PDB_INT128:
	case PDB_INT128_OCT:
		simple_type->size = 16;
		b = rz_strbuf_new("int128_t");
		break;
	case PDB_UINT128:
	case PDB_UINT128_OCT:
		simple_type->size = 16;
		b = rz_strbuf_new("uint128_t");
		break;
	case PDB_FLOAT16:
		simple_type->size = 2;
		b = rz_strbuf_new("float");
		break;
	case PDB_FLOAT32:
	case PDB_FLOAT32_PP:
		simple_type->size = 4;
		b = rz_strbuf_new("float");
		break;
	case PDB_FLOAT48:
		simple_type->size = 6;
		b = rz_strbuf_new("float");
		break;
	case PDB_FLOAT64:
		simple_type->size = 8;
		b = rz_strbuf_new("double");
		break;
	case PDB_FLOAT80:
		simple_type->size = 10;
		b = rz_strbuf_new("long double");
		break;
	case PDB_FLOAT128:
		simple_type->size = 16;
		b = rz_strbuf_new("long double");
		break;
	case PDB_COMPLEX16:
		simple_type->size = 2;
		b = rz_strbuf_new("float _Complex");
		break;
	case PDB_COMPLEX32:
	case PDB_COMPLEX32_PP:
		simple_type->size = 4;
		b = rz_strbuf_new("float _Complex");
		break;
	case PDB_COMPLEX48:
		simple_type->size = 6;
		b = rz_strbuf_new("float _Complex");
		break;
	case PDB_COMPLEX64:
		simple_type->size = 8;
		b = rz_strbuf_new("double _Complex");
		break;
	case PDB_COMPLEX80:
		simple_type->size = 10;
		b = rz_strbuf_new("long double _Complex");
		break;
	case PDB_COMPLEX128:
		simple_type->size = 16;
		b = rz_strbuf_new("long double _Complex");
		break;
	case PDB_BOOL8:
		simple_type->size = 1;
		b = rz_strbuf_new("bool");
		break;
	case PDB_BOOL16:
		simple_type->size = 2;
		b = rz_strbuf_new("bool");
		break;
	case PDB_BOOL32:
		simple_type->size = 4;
		b = rz_strbuf_new("bool");
		break;
	case PDB_BOOL64:
		simple_type->size = 8;
		b = rz_strbuf_new("bool");
		break;
	case PDB_BOOL128:
		simple_type->size = 16;
		b = rz_strbuf_new("bool");
		break;
	default:
		simple_type->size = 0;
		b = rz_strbuf_new("unknown_t");
		break;
	}
	TpiSimpleTypeMode mode = simple_type_mode(idx);
	if (mode) {
		rz_strbuf_append(b, " *");
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
	simple_type->type = rz_strbuf_drain(b);
	// We just insert once
	rz_rbtree_insert(&stream->types, &type->index, &type->rb, tpi_type_node_cmp, NULL);
	return type;
}

static void simple_type_fini(Tpi_LF_SimpleType *t) {
	free(t->type);
}

static bool buf_read_unsigned(RzBuffer *b, ut64 *x) {
	ut16 leaf;
	if (!rz_buf_read_le16(b, &leaf)) {
		return false;
	}
	if (leaf < LF_NUMERIC) {
		*x = leaf;
		return true;
	}
	switch (leaf) {
	case LF_CHAR: {
		ut8 tmp;
		if (!rz_buf_read8(b, &tmp)) {
			return false;
		}
		*x = tmp;
		break;
	}
	case LF_USHORT: {
		ut16 tmp;
		if (!rz_buf_read_le16(b, &tmp)) {
			return false;
		}
		*x = tmp;
		break;
	}
	case LF_ULONG: {
		ut32 tmp;
		if (!rz_buf_read_le32(b, &tmp)) {
			return false;
		}
		*x = tmp;
		break;
	}
	case LF_UQUADWORD: {
		ut64 tmp;
		if (!rz_buf_read_le64(b, &tmp)) {
			return false;
		}
		*x = tmp;
		break;
	}
	default:
		return false;
	}
	return true;
}

static bool TpiVariant_parse(RzBuffer *b, TpiVariant *x) {
	ut16 leaf = 0;
	if (!rz_buf_read_le16(b, &leaf)) {
		return false;
	}
	if (leaf < LF_NUMERIC) {
		x->tag = TpiVariant_U16;
		x->u16v = leaf;
		return true;
	}
	switch (leaf) {
	case LF_CHAR: {
		ut8 tmp;
		if (!rz_buf_read8(b, &tmp)) {
			return false;
		}
		x->tag = TpiVariant_I8;
		x->i8v = (st8)tmp;
		break;
	}
	case LF_SHORT: {
		ut16 tmp;
		if (!rz_buf_read_le16(b, &tmp)) {
			return false;
		}
		x->tag = TpiVariant_I16;
		x->i16v = (st16)tmp;
		break;
	}
	case LF_LONG: {
		ut32 tmp;
		if (!rz_buf_read_le32(b, &tmp)) {
			return false;
		}
		x->tag = TpiVariant_I32;
		x->i32v = (st32)tmp;
		break;
	}
	case LF_QUADWORD: {
		ut64 tmp;
		if (!rz_buf_read_le64(b, &tmp)) {
			return false;
		}
		x->tag = TpiVariant_I64;
		x->i64v = (st64)tmp;
		break;
	}
	case LF_USHORT: {
		x->tag = TpiVariant_U16;
		if (!rz_buf_read_le16(b, &x->u16v)) {
			return false;
		}
		break;
	}
	case LF_ULONG: {
		x->tag = TpiVariant_U32;
		if (!rz_buf_read_le32(b, &x->u32v)) {
			return false;
		}
		break;
	}
	case LF_UQUADWORD: {
		x->tag = TpiVariant_U64;
		if (!rz_buf_read_le64(b, &x->u64v)) {
			return false;
		}
		break;
	}
	default:
		return false;
	}
	return true;
}

/**
 * \brief Return true if type is forward definition
 *
 * \param t RzPdbTpiType
 * \return bool
 */
RZ_API bool rz_bin_pdb_type_is_fwdref(RZ_NONNULL RzPdbTpiType *t) {
	rz_return_val_if_fail(t, false); // return val stands for we do nothing for it
	switch (t->kind) {
	case TpiKind_UNION: {
		Tpi_LF_Union *lf = t->data;
		return lf->prop.fwdref ? true : false;
	}
	case TpiKind_CLASS: {
		Tpi_LF_Class *lf = t->data;
		return lf->prop.fwdref ? true : false;
	}
	case TpiKind_ENUM: {
		Tpi_LF_Enum *lf = t->data;
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
	const RzPdbTpiType *fieldlist = NULL;
	switch (t->kind) {
	case TpiKind_FILEDLIST: {
		fieldlist = t;
		break;
	}
	case TpiKind_UNION: {
		fieldlist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Union *)t->data)->field_list);
		break;
	}
	case TpiKind_CLASS: {
		fieldlist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)t->data)->field_list);
		break;
	}
	case TpiKind_ENUM: {
		fieldlist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)t->data)->field_list);
		break;
	}
	default:
	err:
		return NULL;
	}
	map_err(fieldlist && fieldlist->data);
	return ((Tpi_LF_FieldList *)fieldlist->data)->substructs;
}

/**
 * \brief Get the name of the type
 *
 * \param type RzPdbTpiType *
 * \return char *
 */
RZ_API RZ_BORROW char *rz_bin_pdb_get_type_name(RZ_NONNULL RzPdbTpiType *type) {
	rz_return_val_if_fail(type, NULL);
	if (!type->data) {
		return NULL;
	}
	switch (type->kind) {
	case TpiKind_MEMBER: {
		Tpi_LF_Member *lf_member = type->data;
		return lf_member->name;
	}
	case TpiKind_STMEMBER: {
		Tpi_LF_StaticMember *lf_stmember = type->data;
		return lf_stmember->name;
	}
	case TpiKind_ONEMETHOD: {
		Tpi_LF_OneMethod *lf_onemethod = type->data;
		return lf_onemethod->name;
	}
	case TpiKind_METHOD: {
		Tpi_LF_Method *lf_method = type->data;
		return lf_method->name;
	}
	case TpiKind_NESTTYPE: {
		Tpi_LF_NestType *lf_nesttype = type->data;
		return lf_nesttype->name;
	}
	case TpiKind_ENUM: {
		Tpi_LF_Enum *lf_enum = type->data;
		return lf_enum->name;
	}
	case TpiKind_ENUMERATE: {
		Tpi_LF_Enumerate *lf_enumerate = type->data;
		return lf_enumerate->name;
	}
	case TpiKind_CLASS: {
		Tpi_LF_Class *lf_struct = type->data;
		return lf_struct->name;
	}
	case TpiKind_UNION: {
		Tpi_LF_Union *lf_union = type->data;
		return lf_union->name;
	}
	case TpiKind_SIMPLE_TYPE: {
		Tpi_LF_SimpleType *st = type->data;
		return st->type;
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
	switch (type->kind) {
	case TpiKind_ONEMETHOD: {
		Tpi_LF_OneMethod *lf_onemethod = type->data;
		return lf_onemethod->offset_in_vtable;
	}
	case TpiKind_MEMBER: {
		Tpi_LF_Member *lf_member = type->data;
		return lf_member->offset;
	}
	case TpiKind_ENUMERATE: {
		Tpi_LF_Enumerate *lf_enumerate = type->data;
		TpiVariant *x = &lf_enumerate->value;
		switch (x->tag) {
		case TpiVariant_U64: return x->u64v;
		case TpiVariant_U32: return x->u32v;
		case TpiVariant_U16: return x->u16v;
		case TpiVariant_U8: return x->u8v;
		case TpiVariant_I64: return x->i64v;
		case TpiVariant_I32: return x->i32v;
		case TpiVariant_I16: return x->i16v;
		case TpiVariant_I8: return x->i8v;
		}
		break;
	}
	case TpiKind_CLASS: {
		Tpi_LF_Class *lf_struct = type->data;
		return lf_struct->size;
	}
	case TpiKind_UNION: {
		Tpi_LF_Union *lf_union = type->data;
		return lf_union->size;
	}
	case TpiKind_INDEX: {
		Tpi_LF_Index *lf_index = type->data;
		return lf_index->index;
	}
	case TpiKind_ARRAY: {
		Tpi_LF_Array *a = type->data;
		ut64 y = 0;
		ut32 *x;
		rz_vector_foreach (&a->dimensions, x) {
			y = y == 0 ? *x : (*x * y);
		}
		return y;
	}
	default:
		rz_warn_if_reached();
		return 0;
	}
	return -1;
}

static void tpi_data_free_with_kind(void *data, RzPDBTpiKind k) {
	if (!data) {
		return;
	}
	switch (k) {
	case TpiKind_ENUMERATE: {
		Tpi_LF_Enumerate *lf_en = data;
		free(lf_en->name);
		break;
	}
	case TpiKind_NESTTYPE: {
		Tpi_LF_NestType *lf_nest = data;
		free(lf_nest->name);
		break;
	}
	case TpiKind_METHOD: {
		Tpi_LF_Method *lf_meth = data;
		free(lf_meth->name);
		break;
	}
	case TpiKind_MEMBER: {
		Tpi_LF_Member *lf_mem = data;
		free(lf_mem->name);
		break;
	}
	case TpiKind_STMEMBER: {
		Tpi_LF_StaticMember *lf_stmem = data;
		free(lf_stmem->name);
		break;
	}
	case TpiKind_FILEDLIST: {
		Tpi_LF_FieldList *lf_fieldlist = data;
		rz_pvector_free(lf_fieldlist->substructs);
		break;
	}
	case TpiKind_CLASS: {
		Tpi_LF_Class *lf_class = data;
		free(lf_class->name);
		free(lf_class->mangled_name);
		break;
	}
	case TpiKind_UNION: {
		Tpi_LF_Union *lf_union = data;
		free(lf_union->name);
		free(lf_union->mangled_name);
		break;
	}
	case TpiKind_ONEMETHOD: {
		Tpi_LF_OneMethod *lf_onemethod = data;
		free(lf_onemethod->name);
		break;
	}
	case TpiKind_ENUM: {
		Tpi_LF_Enum *lf_enum = data;
		free(lf_enum->name);
		free(lf_enum->mangled_name);
		break;
	}
	case TpiKind_ARRAY: {
		Tpi_LF_Array *lf_array = data;
		rz_vector_fini(&lf_array->dimensions);
		break;
	}
	case TpiKind_ARGLIST: {
		Tpi_LF_Arglist *lf_arglist = data;
		free(lf_arglist->arg_type);
		break;
	}
	case TpiKind_VTSHAPE: {
		Tpi_LF_Vtshape *lf_vtshape = data;
		rz_vector_fini(&lf_vtshape->descriptors);
		break;
	}
	case TpiKind_METHODLIST: {
		Tpi_LF_MethodList *lf_mlist = data;
		rz_pvector_fini(&lf_mlist->members);
		break;
	}
	case TpiKind_VFTABLE: {
		Tpi_LF_Vftable *vft = data;
		rz_pvector_fini(&vft->method_names);
		break;
	}
	case TpiKind_SIMPLE_TYPE: {
		simple_type_fini(data);
	}
	default:
		break;
	}
	free(data);
}

static void tpi_type_free(void *type_info) {
	if (!type_info) {
		return;
	}
	RzPdbTpiType *type = type_info;
	tpi_data_free_with_kind(type->data, type->kind);
	free(type);
}

static void tpi_rbtree_free(RBNode *node, void *user) {
	if (!node) {
		return;
	}
	RzPdbTpiType *type = container_of(node, RzPdbTpiType, rb);
	tpi_type_free(type);
}

RZ_IPI void tpi_stream_free(RzPdbTpiStream *stream) {
	if (!stream) {
		return;
	}
	rz_rbtree_free(stream->types, tpi_rbtree_free, NULL);
	rz_list_free(stream->print_type);
	free(stream);
}

static Tpi_LF_Enumerate *enumerate_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Enumerate *enumerate = RZ_NEW0(Tpi_LF_Enumerate);
	if (!enumerate) {
		return NULL;
	}
	map_err(TpiCVFldattr_parse(b, &enumerate->fldattr) &&
		TpiVariant_parse(b, &enumerate->value) &&
		buf_read_string(b, leaf, &enumerate->name));
	return enumerate;
err:
	rz_warn_if_reached();
	free(enumerate);
	return NULL;
}

static Tpi_LF_Index *index_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Index *index = RZ_NEW0(Tpi_LF_Index);
	if (!index) {
		return NULL;
	}
	map_err(rz_buf_read_le16(b, &index->pad0) &&
		rz_buf_read_le32(b, &index->index));
	rz_warn_if_fail(index->pad0 == 0);
	index->leaf = LF_INDEX;
	return index;
err:
	rz_warn_if_reached();
	free(index);
	return NULL;
}

static Tpi_LF_NestType *nesttype_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_NestType *nest = RZ_NEW0(Tpi_LF_NestType);
	if (!nest) {
		return NULL;
	}
	ut16 pad;
	map_err(conditional((leaf == LF_NESTTYPEEX || leaf == LF_NESTTYPEEX_ST),
			TpiCVFldattr_parse(b, &nest->fldattr),
			rz_buf_read_le16(b, &pad)) &&
		rz_buf_read_le32(b, &nest->index) &&
		buf_read_string(b, leaf, &nest->name));
	return nest;
err:
	rz_warn_if_reached();
	free(nest->name);
	free(nest);
	return NULL;
}

static Tpi_LF_VFuncTab *vfunctab_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_VFuncTab *vftab = RZ_NEW0(Tpi_LF_VFuncTab);
	if (!vftab) {
		return NULL;
	}
	map_err(rz_buf_read_le16(b, &vftab->pad) &&
		rz_buf_read_le32(b, &vftab->index));
	rz_warn_if_fail(vftab->pad == 0);
	return vftab;
err:
	rz_warn_if_reached();
	free(vftab);
	return NULL;
}

static Tpi_LF_Method *method_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Method *method = RZ_NEW0(Tpi_LF_Method);
	if (!method) {
		return NULL;
	}
	map_err(rz_buf_read_le16(b, &method->count) &&
		rz_buf_read_le32(b, &method->mlist) &&
		buf_read_string(b, leaf, &method->name));
	return method;
err:
	rz_warn_if_reached();
	free(method->name);
	free(method);
	return NULL;
}

static Tpi_LF_Member *member_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Member *member = RZ_NEW0(Tpi_LF_Member);
	if (!member) {
		return NULL;
	}
	map_err(TpiCVFldattr_parse(b, &member->fldattr) &&
		rz_buf_read_le32(b, &member->field_type) &&
		buf_read_unsigned(b, &member->offset) &&
		buf_read_string(b, leaf, &member->name));
	return member;
err:
	rz_warn_if_reached();
	free(member);
	return NULL;
}

static Tpi_LF_StaticMember *staticmember_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_StaticMember *member = RZ_NEW0(Tpi_LF_StaticMember);
	if (!member) {
		return NULL;
	}
	map_err(TpiCVFldattr_parse(b, &member->fldattr) &&
		rz_buf_read_le32(b, &member->field_type) &&
		buf_read_string(b, leaf, &member->name));
	return member;
err:
	rz_warn_if_reached();
	free(member->name);
	free(member);
	return NULL;
}

static Tpi_LF_OneMethod *onemethod_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_OneMethod *onemethod = RZ_NEW0(Tpi_LF_OneMethod);
	if (!onemethod) {
		return NULL;
	}
	map_err(TpiCVFldattr_parse(b, &onemethod->fldattr) &&
		rz_buf_read_le32(b, &onemethod->index) &&
		conditional(TpiCVFldattr_is_intro_virtual(&onemethod->fldattr),
			rz_buf_read_le32(b, &onemethod->offset_in_vtable),
			true) &&
		buf_read_string(b, leaf, &onemethod->name));
	return onemethod;
err:
	rz_warn_if_reached();
	free(onemethod->name);
	free(onemethod);
	return NULL;
}

static Tpi_LF_BClass *bclass_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_BClass *bclass = RZ_NEW0(Tpi_LF_BClass);
	if (!bclass) {
		return NULL;
	}
	if (leaf == LF_BCLASS) {
		bclass->kind = ClassKind_Class;
	} else if (leaf == LF_BINTERFACE) {
		bclass->kind = ClassKind_Interface;
	}
	map_err(TpiCVFldattr_parse(b, &bclass->fldattr) &&
		rz_buf_read_le32(b, &bclass->index) &&
		buf_read_unsigned(b, &bclass->offset));
	return bclass;
err:
	rz_warn_if_reached();
	free(bclass);
	return NULL;
}

static Tpi_LF_VBClass *vbclass_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_VBClass *bclass = RZ_NEW0(Tpi_LF_VBClass);
	if (!bclass) {
		return NULL;
	}
	map_err(TpiCVFldattr_parse(b, &bclass->fldattr) &&
		rz_buf_read_le32(b, &bclass->direct_vbclass_idx) &&
		rz_buf_read_le32(b, &bclass->vb_pointer_idx) &&
		buf_read_unsigned(b, &bclass->vb_pointer_offset) &&
		buf_read_unsigned(b, &bclass->vb_offset_from_vbtable));
	return bclass;
err:
	rz_warn_if_reached();
	free(bclass);
	return NULL;
}

static Tpi_LF_FieldList *fieldlist_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_FieldList *fieldlist = RZ_NEW0(Tpi_LF_FieldList);
	if (!fieldlist) {
		return NULL;
	}
	fieldlist->substructs = rz_pvector_new(tpi_type_free);
	map_err(fieldlist->substructs);
	while (!buf_empty(b)) {
		RzPdbTpiType *t = RzPdbTpiType_from_buf(b, 0, 0);
		map_err(t);
		buf_read_padding(b);
		map_err(rz_pvector_push(fieldlist->substructs, t));
	}
	return fieldlist;
err:
	rz_warn_if_reached();
	rz_pvector_free(fieldlist->substructs);
	free(fieldlist);
	return NULL;
}

static Tpi_LF_Enum *enum_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Enum *_enum = RZ_NEW0(Tpi_LF_Enum);
	if (!_enum) {
		return NULL;
	}
	map_err(rz_buf_read_le16(b, &_enum->count) &&
		TpiCVProperty_parse(b, &_enum->prop) &&
		rz_buf_read_le32(b, &_enum->utype) &&
		rz_buf_read_le32(b, &_enum->field_list) &&
		buf_read_string(b, leaf, &_enum->name) &&
		conditional(_enum->prop.has_uniquename,
			buf_read_string(b, leaf, &_enum->mangled_name), true));
	return _enum;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(_enum, TpiKind_ENUM);
	return NULL;
}

static Tpi_LF_Class *class_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Class *structure = RZ_NEW0(Tpi_LF_Class);
	if (!structure) {
		return NULL;
	}
	bool is_32bit_property = false;
	switch (leaf) {
	case LF_CLASS:
	case LF_CLASS_ST:
		structure->kind = ClassKind_Class;
		break;
	case LF_STRUCTURE:
	case LF_STRUCTURE_ST:
		structure->kind = ClassKind_Struct;
		break;
	case LF_INTERFACE:
		structure->kind = ClassKind_Interface;
		break;
	case LF_CLASS_19:
		structure->kind = ClassKind_Class;
		is_32bit_property = true;
		break;
	case LF_STRUCTURE_19:
		structure->kind = ClassKind_Struct;
		is_32bit_property = true;
		break;
	case LF_INTERFACE_19:
		structure->kind = ClassKind_Interface;
		is_32bit_property = true;
		break;
	default:
		rz_warn_if_reached();
		goto err;
	}
	if (!is_32bit_property) {
		map_err(rz_buf_read_le16(b, &structure->count) &&
			TpiCVProperty_parse_opt(b, &structure->prop, is_32bit_property) &&
			rz_buf_read_le32(b, &structure->field_list) &&
			rz_buf_read_le32(b, &structure->derived) &&
			rz_buf_read_le32(b, &structure->vshape) &&
			buf_read_unsigned(b, &structure->size) &&
			buf_read_string(b, leaf, &structure->name) &&
			conditional(structure->prop.has_uniquename,
				buf_read_string(b, leaf, &structure->mangled_name), true));
	} else {
		map_err(TpiCVProperty_parse_opt(b, &structure->prop, is_32bit_property) &&
			rz_buf_read_le32(b, &structure->field_list) &&
			rz_buf_read_le32(b, &structure->derived) &&
			rz_buf_read_le32(b, &structure->vshape) &&
			rz_buf_read_le16(b, &structure->count) &&
			buf_read_unsigned(b, &structure->size) &&
			buf_read_string(b, leaf, &structure->name) &&
			conditional(structure->prop.has_uniquename,
				buf_read_string(b, leaf, &structure->mangled_name), true));
	}
	return structure;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(structure, TpiKind_CLASS);
	return NULL;
}

static Tpi_LF_Pointer *pointer_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Pointer *pointer = RZ_NEW0(Tpi_LF_Pointer);
	if (!pointer) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &pointer->utype) &&
		TpiCVPointerAttr_parse(b, &pointer->ptr_attr) &&
		conditional(TpiCVPointerAttr_pointer_to_member(&pointer->ptr_attr),
			rz_buf_read_le32(b, &pointer->containing_class), true));
	return pointer;
err:
	rz_warn_if_reached();
	free(pointer);
	return NULL;
}

static Tpi_LF_Array *array_parse(RzBuffer *b, TpiLeafType leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Array *array = RZ_NEW0(Tpi_LF_Array);
	if (!array) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &array->element_type) &&
		rz_buf_read_le32(b, &array->index_type) &&
		conditional(leaf == LF_STRIDED_ARRAY, rz_buf_read_le32(b, &array->stride), true));

	rz_vector_init(&array->dimensions, sizeof(ut32), NULL, NULL);
	while (true) {
		ut64 dim = { 0 };
		map_err(buf_read_unsigned(b, &dim));
		rz_warn_if_fail(dim <= UT32_MAX);

		ut32 v = dim;
		rz_vector_push(&array->dimensions, &v);
		rz_warn_if_fail(!buf_empty(b));
		if (rz_buf_peek(b) == 0x00) {
			rz_buf_seek(b, 1, RZ_BUF_CUR);
			break;
		}
	}
	buf_read_padding(b);
	rz_warn_if_fail(buf_empty(b));

	return array;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(array, TpiKind_ARRAY);
	return NULL;
}

static Tpi_LF_Modifier *modifier_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Modifier *modifier = RZ_NEW0(Tpi_LF_Modifier);
	if (!modifier) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &modifier->modified_type) &&
		TpiCVModifier_parse(b, &modifier->umodifier));
	return modifier;
err:
	rz_warn_if_reached();
	free(modifier);
	return NULL;
}

static Tpi_LF_Arglist *arglist_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Arglist *arglist = RZ_NEW0(Tpi_LF_Arglist);
	if (!arglist) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &arglist->count));
	if (arglist->count == 0) {
		return arglist;
	}
	arglist->arg_type = (ut32 *)malloc(sizeof(ut32) * arglist->count);
	map_err(arglist->arg_type);
	for (ut32 i = 0; i < arglist->count; i++) {
		map_err(rz_buf_read_le32(b, &arglist->arg_type[i]));
	}
	return arglist;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(arglist, TpiKind_ARGLIST);
	return NULL;
}

static Tpi_LF_MFcuntion *mfunction_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_MFcuntion *mfunc = RZ_NEW0(Tpi_LF_MFcuntion);
	if (!mfunc) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &mfunc->return_type) &&
		rz_buf_read_le32(b, &mfunc->class_type) &&
		rz_buf_read_le32(b, &mfunc->this_type) &&
		TpiCVFuncattr_parse(b, &mfunc->func_attr) &&
		rz_buf_read_le16(b, &mfunc->parm_count) &&
		rz_buf_read_le32(b, &mfunc->arglist) &&
		rz_buf_read_le32(b, (ut32 *)&mfunc->this_adjust));
	return mfunc;
err:
	rz_warn_if_reached();
	free(mfunc);
	return NULL;
}

static Tpi_LF_MethodList *methodlist_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_MethodList *mlist = RZ_NEW0(Tpi_LF_MethodList);
	if (!mlist) {
		return NULL;
	}
	rz_pvector_init(&mlist->members, free);

	Tpi_Type_MethodListMember *member = NULL;
	while (!buf_empty(b)) {
		member = RZ_NEW0(Tpi_Type_MethodListMember);
		map_err(member &&
			TpiCVFldattr_parse(b, &member->fldattr) &&
			rz_buf_read_le16(b, &member->pad) &&
			rz_buf_read_le32(b, &member->type) &&
			conditional(member->fldattr.mprop == MTintro ||
					member->fldattr.mprop == MTpureintro,
				rz_buf_read_le32(b, &member->optional_offset), true) &&
			rz_pvector_push(&mlist->members, member));
	}
	return mlist;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(member, TpiKind_METHODLIST);
	return NULL;
}

static Tpi_LF_Procedure *procedure_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Procedure *proc = RZ_NEW0(Tpi_LF_Procedure);
	if (!proc) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &proc->return_type) &&
		TpiCVFuncattr_parse(b, &proc->func_attr) &&
		rz_buf_read_le16(b, &proc->parm_count) &&
		rz_buf_read_le32(b, &proc->arg_list));
	return proc;
err:
	rz_warn_if_reached();
	free(proc);
	return NULL;
}

static Tpi_LF_Union *union_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Union *unin = RZ_NEW0(Tpi_LF_Union);
	if (!unin) {
		return NULL;
	}
	if (leaf != LF_UNION_19) {
		map_err(rz_buf_read_le16(b, &unin->count) &&
			TpiCVProperty_parse_opt(b, &unin->prop, leaf == LF_UNION_19) &&
			rz_buf_read_le32(b, &unin->field_list) &&
			buf_read_unsigned(b, &unin->size) &&
			buf_read_string(b, leaf, &unin->name) &&
			conditional(unin->prop.has_uniquename,
				buf_read_string(b, leaf, &unin->mangled_name), true));
	} else {
		map_err(TpiCVProperty_parse_opt(b, &unin->prop, leaf == LF_UNION_19) &&
			rz_buf_read_le32(b, &unin->field_list) &&
			rz_buf_read_le16(b, &unin->count) &&
			buf_read_unsigned(b, &unin->size) &&
			buf_read_string(b, leaf, &unin->name) &&
			conditional(unin->prop.has_uniquename,
				buf_read_string(b, leaf, &unin->mangled_name), true));
	}
	return unin;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(unin, TpiKind_UNION);
	return NULL;
}

static Tpi_LF_Bitfield *bitfield_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Bitfield *bf = RZ_NEW0(Tpi_LF_Bitfield);
	if (!bf) {
		return NULL;
	}
	map_err(rz_buf_read_le32(b, &bf->base_type) &&
		rz_buf_read8(b, &bf->length) &&
		rz_buf_read8(b, &bf->position));
	return bf;
err:
	rz_warn_if_reached();
	free(bf);
	return NULL;
}

static Tpi_LF_Vtshape *vtshape_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Vtshape *vt = RZ_NEW0(Tpi_LF_Vtshape);
	if (!vt) {
		return NULL;
	}
	map_err(rz_buf_read_le16(b, &vt->count));
	rz_vector_init(&vt->descriptors, sizeof(ut8), NULL, NULL);
	for (int i = 0; i < (vt->count + 1) / 2; ++i) {
		ut8 desc = 0;
		map_err(rz_buf_read8(b, &desc));
		ut8 x = desc & 0xF;
		map_err(rz_vector_push(&vt->descriptors, &x));
		if (rz_vector_len(&vt->descriptors) < vt->count) {
			x = desc >> 4;
			map_err(rz_vector_push(&vt->descriptors, &x));
		}
	}
	return vt;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(vt, TpiKind_VTSHAPE);
	return NULL;
}

static Tpi_LF_Vftable *vftable_parse(RzBuffer *b, ut16 leaf) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Vftable *vft = RZ_NEW0(Tpi_LF_Vftable);
	if (!vft) {
		return NULL;
	}
	ut64 len;
	map_err(rz_buf_read_le32(b, (ut32 *)&vft->complete_class) &&
		rz_buf_read_le32(b, (ut32 *)&vft->override_vftable) &&
		rz_buf_read_le32(b, (ut32 *)&vft->vfptr_offset) &&
		buf_read_unsigned(b, &len));

	rz_pvector_init(&vft->method_names, free);
	while (!buf_empty(b) && rz_buf_peek(b) < LF_PAD0) {
		char *name = NULL;
		const ut64 nlen = buf_read_string(b, leaf, &name);
		if (nlen <= 0) {
			continue;
		}
		map_err(rz_pvector_push(&vft->method_names, name));
	}
	return vft;
err:
	rz_warn_if_reached();
	tpi_data_free_with_kind(vft, TpiKind_VFTABLE);
	return NULL;
}

static Tpi_LF_Label *labal_parse(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	Tpi_LF_Label *record = RZ_NEW0(Tpi_LF_Label);
	if (!record) {
		return NULL;
	}

	map_err(rz_buf_read_le32(b, (ut32 *)&record->mode));
	return record;
err:
	rz_warn_if_reached();
	free(record);
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

	RzPDBTpiKind k = 0;
	void *data = NULL;
	switch (leaf) {
	case LF_FIELDLIST:
		k = TpiKind_FILEDLIST;
		data = fieldlist_parse(b);
		break;
	case LF_ENUM:
	case LF_ENUM_ST:
		k = TpiKind_ENUM;
		data = enum_parse(b, leaf);
		break;
	case LF_ENUMERATE:
	case LF_ENUMERATE_ST:
		k = TpiKind_ENUMERATE;
		data = enumerate_parse(b, leaf);
		break;
	case LF_CLASS:
	case LF_CLASS_ST:
	case LF_STRUCTURE:
	case LF_STRUCTURE_ST:
	case LF_INTERFACE:
	case LF_CLASS_19:
	case LF_STRUCTURE_19:
	case LF_INTERFACE_19:
		k = TpiKind_CLASS;
		data = class_parse(b, leaf);
		break;
	case LF_POINTER:
		k = TpiKind_POINTER;
		data = pointer_parse(b);
		break;
	case LF_ARRAY:
	case LF_ARRAY_ST:
	case LF_STRIDED_ARRAY:
		k = TpiKind_ARRAY;
		data = array_parse(b, leaf);
		break;
	case LF_MODIFIER:
		k = TpiKind_MODIFIER;
		data = modifier_parse(b);
		break;
	case LF_ARGLIST:
		k = TpiKind_ARGLIST;
		data = arglist_parse(b);
		break;
	case LF_MFUNCTION:
		k = TpiKind_MFUNCTION;
		data = mfunction_parse(b);
		break;
	case LF_METHODLIST:
		k = TpiKind_METHODLIST;
		data = methodlist_parse(b);
		break;
	case LF_PROCEDURE:
		k = TpiKind_PROCEDURE;
		data = procedure_parse(b);
		break;
	case LF_UNION:
	case LF_UNION_ST:
	case LF_UNION_19:
		k = TpiKind_UNION;
		data = union_parse(b, leaf);
		break;
	case LF_BITFIELD:
		k = TpiKind_BITFIELD;
		data = bitfield_parse(b);
		break;
	case LF_VTSHAPE:
		k = TpiKind_VTSHAPE;
		data = vtshape_parse(b);
		break;
	case LF_VFTABLE:
		k = TpiKind_VFTABLE;
		data = vftable_parse(b, leaf);
		break;
	case LF_LABEL:
		k = TpiKind_LABEL;
		data = labal_parse(b);
		break;
	case LF_NESTTYPE:
	case LF_NESTTYPE_ST:
	case LF_NESTTYPEEX:
	case LF_NESTTYPEEX_ST:
		k = TpiKind_NESTTYPE;
		data = nesttype_parse(b, leaf);
		break;
	case LF_MEMBER:
	case LF_MEMBER_ST:
		k = TpiKind_MEMBER;
		data = member_parse(b, leaf);
		break;
	case LF_METHOD:
	case LF_METHOD_ST:
		k = TpiKind_METHOD;
		data = method_parse(b, leaf);
		break;
	case LF_ONEMETHOD:
	case LF_ONEMETHOD_ST:
		k = TpiKind_ONEMETHOD;
		data = onemethod_parse(b, leaf);
		break;
	case LF_BCLASS:
	case LF_BINTERFACE:
		k = TpiKind_BCLASS;
		data = bclass_parse(b, leaf);
		break;
	case LF_VFUNCTAB:
		k = TpiKind_VFUNCTAB;
		data = vfunctab_parse(b);
		break;
	case LF_STMEMBER:
	case LF_STMEMBER_ST:
		k = TpiKind_STMEMBER;
		data = staticmember_parse(b, leaf);
		break;
	case LF_VBCLASS:
	case LF_IVBCLASS:
		k = TpiKind_VBCLASS;
		data = vbclass_parse(b);
		break;
	case LF_INDEX:
		k = TpiKind_INDEX;
		data = index_parse(b);
		break;
	default:
		RZ_LOG_DEBUG("%s: 0x%" PFMT32x ": unsupported leaf type: 0x%" PFMT32x "\n", __FUNCTION__, index, leaf);
		break;
	}

	if (!data && !length && !index) {
		rz_warn_if_reached();
		return NULL;
	}

	RzPdbTpiType *type = RZ_NEW0(RzPdbTpiType);
	if (!type) {
		rz_warn_if_reached();
		free(data);
		return NULL;
	}
	type->index = index;
	type->length = length;
	type->leaf = leaf;
	type->kind = k;
	type->data = data;
	return type;
}

static bool tpi_stream_header_parse(RzBuffer *b, RzPdbTpiStreamHeader *h) {
	return rz_buf_read_le32(b, (ut32 *)&h->Version) &&
		rz_buf_read_le32(b, &h->HeaderSize) &&
		rz_buf_read_le32(b, &h->TypeIndexBegin) &&
		rz_buf_read_le32(b, &h->TypeIndexEnd) &&
		rz_buf_read_le32(b, &h->TypeRecordBytes) &&

		rz_buf_read_le16(b, &h->HashStreamIndex) &&
		rz_buf_read_le16(b, &h->HashAuxStreamIndex) &&
		rz_buf_read_le32(b, &h->HashKeySize) &&
		rz_buf_read_le32(b, &h->NumHashBuckets) &&

		rz_buf_read_le32(b, (ut32 *)&h->HashValueBufferOffset) &&
		rz_buf_read_le32(b, &h->HashValueBufferLength) &&

		rz_buf_read_le32(b, (ut32 *)&h->IndexOffsetBufferOffset) &&
		rz_buf_read_le32(b, &h->IndexOffsetBufferLength) &&

		rz_buf_read_le32(b, (ut32 *)&h->HashAdjBufferOffset) &&
		rz_buf_read_le32(b, &h->HashAdjBufferLength);
}

RZ_IPI bool tpi_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream) {
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
	if (!tpi_stream_header_parse(steam_buffer, &s->header)) {
		return false;
	}
	if (s->header.HeaderSize != sizeof(RzPdbTpiStreamHeader)) {
		RZ_LOG_ERROR("Corrupted TPI stream.\n");
		return false;
	}
	RzPdbTpiType *type = NULL;
	RzBuffer *b = NULL;
	for (ut32 index = s->header.TypeIndexBegin; index < s->header.TypeIndexEnd; index++) {
		ut16 length = 0;
		if (!rz_buf_read_le16(steam_buffer, &length)) {
			goto err;
		}
		b = NULL;
		b = buf_take(steam_buffer, length);
		if (!b) {
			goto err;
		}

		type = NULL;
		type = RzPdbTpiType_from_buf(b, index, length);
		if (!type) {
			goto err;
		}
		rz_buf_free(b);
		b = NULL;
		rz_rbtree_insert(&s->types, &type->index, &type->rb, tpi_type_node_cmp, NULL);
		continue;
	err:
		rz_warn_if_reached();
		rz_buf_free(b);
		tpi_type_free(type);
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
		if (simple_type_check(stream, index)) {
			return simple_type_parse(stream, index);
		}
		return NULL;
	}
	return container_of(node, RzPdbTpiType, rb);
}
