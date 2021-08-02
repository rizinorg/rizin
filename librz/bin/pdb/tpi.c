// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "types.h"
#include "tpi.h"
#include "stream_file.h"

// TODO: remove these global variables
static unsigned int base_idx = 0;
static RzList *p_types_list;

static bool is_simple_type(int idx) {
	ut32 value = (ut32)idx;
	/*   https://llvm.org/docs/PDB/TpiStream.html#type-indices
        .---------------------------.------.----------.
        |           Unused          | Mode |   Kind   |
        '---------------------------'------'----------'
        |+32                        |+12   |+8        |+0
	*/
	return value < base_idx;
	// return ((value & 0x00000000FFF00) <= 0x700 && (value & 0x00000000000FF) < 0x80);
}

static int skip_padding(uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	unsigned int c = 0;
	CAN_READ(*read_bytes, 1, len);
	while ((*leaf_data & 0xf0) == 0xf0) {
		c++;
		CAN_READ((*read_bytes + c), 1, len);
		leaf_data++;
	}
	(*read_bytes) += (c);
	return c;
}

/**
 * \brief Parses calling convention type as string
 *
 * \param idx
 */
RZ_API char *rz_bin_pdb_calling_convention_as_string(ECV_CALL idx) {
	switch (idx) {
	case eNEAR_C:
	case eFAR_C:
		return strdup("__cdecl");
	case eNEAR_PASCAL:
	case eFAR_PASCAL:
		return strdup("__pascal");
	case eNEAR_FAST:
	case eFAR_FAST:
		return strdup("__fastcall");
	case eNEAR_STD:
	case eFAR_STD:
		return strdup("__stdcall");
	case eNEAR_SYS:
	case eFAR_SYS:
		return strdup("__syscall");
	case eTHISCALL:
		return strdup("__thiscall");
	case eNEAR_VEC:
		return strdup("__vectorcall");
	default:
		return NULL;
	}
}

/**
 * \brief Parses simple type if the idx represents one
 *
 * \param idx
 * \return STypeInfo, leaf_type = 0 -> error
 *  This can be made smarter by using the masks
 *  and splitting it on 2 parts, 1 mode, 1 type
 */
RZ_IPI STypeInfo parse_simple_type(ut32 idx) {
	STypeInfo type = { 0 };
	SLF_SIMPLE_TYPE *simple_type = RZ_NEW0(SLF_SIMPLE_TYPE);
	if (!simple_type) {
		return type;
	}
	switch (idx) {
	case eT_NOTYPE: // uncharacterized type (no type)
		simple_type->size = 0;
		simple_type->type = strdup("notype_t");
		break;
	case eT_VOID: // void
		simple_type->size = 0;
		simple_type->type = strdup("void");
		break;
	case eT_PVOID: // near ptr to void (2 bytes?)
		simple_type->size = 2;
		simple_type->type = strdup("void *");
		break;
	case eT_PFVOID: // far ptr to void (4 bytes)
	case eT_PHVOID: // huge ptr to void (4 bytes)
	case eT_32PVOID:
	case eT_32PFVOID:
		simple_type->size = 4;
		simple_type->type = strdup("void *");
		break;
	case eT_64PVOID:
		simple_type->size = 8;
		simple_type->type = strdup("void *");
		break;
	case eT_CHAR:
		simple_type->size = 1;
		simple_type->type = strdup("char");
		break;
	case eT_PCHAR: // near
		simple_type->size = 2;
		simple_type->type = strdup("char *");
		break;
	case eT_PFCHAR:
	case eT_PHCHAR:
	case eT_32PCHAR:
	case eT_32PFCHAR:
		simple_type->size = 4;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_64PCHAR:
		simple_type->size = 8;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_UCHAR:
		simple_type->size = 1;
		simple_type->type = strdup("uint8_t");
		break;
	case eT_PUCHAR:
		simple_type->size = 2;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_PFUCHAR:
	case eT_PHUCHAR:
	case eT_32PUCHAR:
	case eT_32PFUCHAR:
		simple_type->size = 4;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_64PUCHAR:
		simple_type->size = 8;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_RCHAR:
		simple_type->size = 1;
		simple_type->type = strdup("char");
		break;
	case eT_PRCHAR:
		simple_type->size = 2;
		simple_type->type = strdup("char *");
		break;
	case eT_PFRCHAR:
	case eT_PHRCHAR:
	case eT_32PRCHAR:
	case eT_32PFRCHAR:
		simple_type->size = 4;
		simple_type->type = strdup("char *");
		break;
	case eT_64PRCHAR:
		simple_type->size = 8;
		simple_type->type = strdup("char *");
		break;
	case eT_CHAR16:
		simple_type->size = 1;
		simple_type->type = strdup("char16_t");
		break;
	case eT_PCHAR16:
		simple_type->size = 2;
		simple_type->type = strdup("char16_t *");
		break;
	case eT_PFCHAR16:
	case eT_PHCHAR16:
	case eT_32PCHAR16:
	case eT_32PFCHAR16:
		simple_type->size = 4;
		simple_type->type = strdup("char16_t *");
		break;
	case eT_64PCHAR16:
		simple_type->size = 8;
		simple_type->type = strdup("char16_t *");
		break;
	case eT_CHAR32:
		simple_type->size = 1;
		simple_type->type = strdup("char32_t");
		break;
	case eT_PCHAR32:
		simple_type->size = 2;
		simple_type->type = strdup("char32_t *");
		break;
	case eT_PFCHAR32:
	case eT_PHCHAR32:
	case eT_32PCHAR32:
	case eT_32PFCHAR32:
		simple_type->size = 4;
		simple_type->type = strdup("char32_t *");
		break;
	case eT_64PCHAR32:
		simple_type->size = 8;
		simple_type->type = strdup("char32_t *");
		break;
	case eT_WCHAR:
		simple_type->size = 4;
		simple_type->type = strdup("wchar_t");
		break;
	case eT_PWCHAR:
		simple_type->size = 2;
		simple_type->type = strdup("wchar_t *");
		break;
	case eT_PFWCHAR:
	case eT_PHWCHAR:
	case eT_32PWCHAR:
	case eT_32PFWCHAR:
		simple_type->size = 4;
		simple_type->type = strdup("wchar_t *");
		break;
	case eT_64PWCHAR:
		simple_type->size = 8;
		simple_type->type = strdup("wchar_t *");
		break;
	case eT_BYTE:
		simple_type->size = 1;
		simple_type->type = strdup("char");
		break;
	case eT_PBYTE:
		simple_type->size = 2;
		simple_type->type = strdup("char *");
		break;
	case eT_PFBYTE:
	case eT_PHBYTE:
	case eT_32PBYTE:
	case eT_32PFBYTE:
		simple_type->size = 4;
		simple_type->type = strdup("char *");
		break;
	case eT_64PBYTE:
		simple_type->size = 8;
		simple_type->type = strdup("char *");
		break;
	case eT_UBYTE:
		simple_type->size = 1;
		simple_type->type = strdup("uint8_t");
		break;
	case eT_PUBYTE:
		simple_type->size = 2;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_PFUBYTE:
	case eT_PHUBYTE:
	case eT_32PUBYTE:
	case eT_32PFUBYTE:
		simple_type->size = 4;
		simple_type->type = strdup("uint8_t *");
		break;
	case eT_64PUBYTE:
		simple_type->size = 8;
		simple_type->type = strdup("uint8_t*");
		break;
	case eT_INT16: // 16 bit
	case eT_SHORT: // 16 bit short
		simple_type->size = 2;
		simple_type->type = strdup("uint16_t");
		break;
	case eT_PINT16:
	case eT_PSHORT:
		simple_type->size = 2;
		simple_type->type = strdup("uint16_t *");
		break;
	case eT_PFSHORT:
	case eT_PHSHORT:
	case eT_32PSHORT:
	case eT_32PFSHORT:
	case eT_PFINT16:
	case eT_PHINT16:
	case eT_32PINT16:
	case eT_32PFINT16:
		simple_type->size = 4;
		simple_type->type = strdup("uint16_t *");
		break;
	case eT_64PINT16:
	case eT_64PSHORT:
		simple_type->size = 8;
		simple_type->type = strdup("uint16_t *");
		break;
	case eT_UINT16: // 16 bit
	case eT_USHORT: // 16 bit short
		simple_type->size = 2;
		simple_type->type = strdup("uint16_t");
		break;
	case eT_PUINT16:
	case eT_PUSHORT:
		simple_type->size = 2;
		simple_type->type = strdup("uint16_t *");
		break;
	case eT_PFUSHORT:
	case eT_PHUSHORT:
	case eT_32PUSHORT:
	case eT_PFUINT16:
	case eT_PHUINT16:
	case eT_32PUINT16:
	case eT_32PFUINT16:
	case eT_32PFUSHORT:
		simple_type->size = 4;
		simple_type->type = strdup("uint16_t *");
		break;
	case eT_64PUINT16:
	case eT_64PUSHORT:
		simple_type->size = 8;
		simple_type->type = strdup("uint16_t *");
		break;
	case eT_LONG:
	case eT_INT4:
		simple_type->size = 4;
		simple_type->type = strdup("int32_t");
		break;
	case eT_PLONG:
	case eT_PINT4:
		simple_type->size = 2;
		simple_type->type = strdup("int32_t *");
		break;
	case eT_PFLONG:
	case eT_PHLONG:
	case eT_32PLONG:
	case eT_32PFLONG:
	case eT_PFINT4:
	case eT_PHINT4:
	case eT_32PINT4:
	case eT_32PFINT4:
		simple_type->size = 4;
		simple_type->type = strdup("int32_t *");
		break;
	case eT_64PLONG:
	case eT_64PINT4:
		simple_type->size = 8;
		simple_type->type = strdup("int32_t *");
		break;
	case eT_ULONG:
	case eT_UINT4:
		simple_type->size = 4;
		simple_type->type = strdup("uint32_t");
		break;
	case eT_PULONG:
	case eT_PUINT4:
		simple_type->size = 2;
		simple_type->type = strdup("uint32_t *");
		break;
	case eT_PFULONG:
	case eT_PHULONG:
	case eT_32PULONG:
	case eT_32PFULONG:
	case eT_PFUINT4:
	case eT_PHUINT4:
	case eT_32PUINT4:
	case eT_32PFUINT4:
		simple_type->size = 4;
		simple_type->type = strdup("uint32_t *");
		break;
	case eT_64PULONG:
	case eT_64PUINT4:
		simple_type->size = 8;
		simple_type->type = strdup("uint32_t *");
		break;
	case eT_INT8:
	case eT_QUAD:
		simple_type->size = 8;
		simple_type->type = strdup("int64_t");
		break;
	case eT_PQUAD:
	case eT_PINT8:
		simple_type->size = 2;
		simple_type->type = strdup("int64_t *");
		break;
	case eT_PFQUAD:
	case eT_PHQUAD:
	case eT_32PQUAD:
	case eT_32PFQUAD:
	case eT_PFINT8:
	case eT_PHINT8:
	case eT_32PINT8:
	case eT_32PFINT8:
		simple_type->size = 4;
		simple_type->type = strdup("int64_t *");
		break;
	case eT_64PQUAD:
	case eT_64PINT8:
		simple_type->size = 8;
		simple_type->type = strdup("int64_t *");
		break;
	case eT_UQUAD:
	case eT_UINT8:
		simple_type->size = 8;
		simple_type->type = strdup("uint64_t");
		break;
	case eT_PUQUAD:
	case eT_PUINT8:
		simple_type->size = 2;
		simple_type->type = strdup("uint64_t *");
		break;
	case eT_PFUQUAD:
	case eT_PHUQUAD:
	case eT_32PUQUAD:
	case eT_32PFUQUAD:
	case eT_PFUINT8:
	case eT_PHUINT8:
	case eT_32PUINT8:
	case eT_32PFUINT8:
		simple_type->size = 4;
		simple_type->type = strdup("uint64_t *");
		break;
	case eT_64PUQUAD:
	case eT_64PUINT8:
		simple_type->size = 8;
		simple_type->type = strdup("uint64_t *");
		break;
	case eT_INT128:
	case eT_OCT:
		simple_type->size = 16;
		simple_type->type = strdup("int128_t");
		break;
	case eT_PINT128:
	case eT_POCT:
		simple_type->size = 2;
		simple_type->type = strdup("int128_t *");
		break;
	case eT_PFINT128:
	case eT_PHINT128:
	case eT_32PINT128:
	case eT_32PFINT128:
	case eT_PFOCT:
	case eT_PHOCT:
	case eT_32POCT:
	case eT_32PFOCT:
		simple_type->size = 4;
		simple_type->type = strdup("int128_t *");
		break;
	case eT_64PINT128:
	case eT_64POCT:
		simple_type->size = 8;
		simple_type->type = strdup("int128_t *");
		break;
	case eT_UINT128:
	case eT_UOCT:
		simple_type->size = 16;
		simple_type->type = strdup("uint128_t");
		break;
	case eT_PUINT128:
	case eT_PUOCT:
		simple_type->size = 2;
		simple_type->type = strdup("uint128_t *");
		break;
	case eT_PFUINT128:
	case eT_PHUINT128:
	case eT_32PUINT128:
	case eT_32PFUINT128:
	case eT_PFUOCT:
	case eT_PHUOCT:
	case eT_32PUOCT:
	case eT_32PFUOCT:
		simple_type->size = 4;
		simple_type->type = strdup("uint128_t *");
		break;
	case eT_64PUINT128:
	case eT_64PUOCT:
		simple_type->size = 8;
		simple_type->type = strdup("uint128_t *");
		break;
	case eT_REAL16:
		simple_type->size = 2;
		simple_type->type = strdup("float");
		break;
	case eT_PREAL16:
		simple_type->size = 2;
		simple_type->type = strdup("float *");
		break;
	case eT_PFREAL16:
	case eT_PHREAL16:
	case eT_32PREAL16:
	case eT_32PFREAL16:
		simple_type->size = 4;
		simple_type->type = strdup("float *");
		break;
	case eT_64PREAL16:
		simple_type->size = 8;
		simple_type->type = strdup("float *");
		break;
	case eT_REAL32:
		simple_type->size = 4;
		simple_type->type = strdup("float");
		break;
	case eT_PREAL32:
		simple_type->size = 2;
		simple_type->type = strdup("float *");
		break;
	case eT_PFREAL32:
	case eT_PHREAL32:
	case eT_32PREAL32:
	case eT_32PFREAL32:
		simple_type->size = 4;
		simple_type->type = strdup("float *");
		break;
	case eT_64PREAL32:
		simple_type->size = 8;
		simple_type->type = strdup("float *");
		break;
	case eT_REAL48:
		simple_type->size = 6;
		simple_type->type = strdup("float");
		break;
	case eT_PREAL48:
		simple_type->size = 2;
		simple_type->type = strdup("float *");
		break;
	case eT_PFREAL48:
	case eT_PHREAL48:
	case eT_32PREAL48:
	case eT_32PFREAL48:
		simple_type->size = 4;
		simple_type->type = strdup("float *");
		break;
	case eT_64PREAL48:
		simple_type->size = 8;
		simple_type->type = strdup("float *");
		break;
	case eT_REAL64:
		simple_type->size = 8;
		simple_type->type = strdup("double");
		break;
	case eT_PREAL64:
		simple_type->size = 2;
		simple_type->type = strdup("double *");
		break;
	case eT_PFREAL64:
	case eT_PHREAL64:
	case eT_32PREAL64:
	case eT_32PFREAL64:
		simple_type->size = 4;
		simple_type->type = strdup("long double *");
		break;
	case eT_64PREAL64:
		simple_type->size = 8;
		simple_type->type = strdup("long double *");
		break;
	case eT_REAL80:
		simple_type->size = 10;
		simple_type->type = strdup("long double");
		break;
	case eT_PREAL80:
		simple_type->size = 2;
		simple_type->type = strdup("long double *");
		break;
	case eT_PFREAL80:
	case eT_PHREAL80:
	case eT_32PREAL80:
	case eT_32PFREAL80:
		simple_type->size = 4;
		simple_type->type = strdup("long double *");
		break;
	case eT_64PREAL80:
		simple_type->size = 8;
		simple_type->type = strdup("long double *");
		break;
	case eT_REAL128:
		simple_type->size = 16;
		simple_type->type = strdup("long double");
		break;
	case eT_PREAL128:
		simple_type->size = 2;
		simple_type->type = strdup("long double *");
		break;
	case eT_PFREAL128:
	case eT_PHREAL128:
	case eT_32PREAL128:
	case eT_32PFREAL128:
		simple_type->size = 4;
		simple_type->type = strdup("long double *");
		break;
	case eT_64PREAL128:
		simple_type->size = 8;
		simple_type->type = strdup("long double *");
		break;
	case eT_CPLX32:
		simple_type->size = 4;
		simple_type->type = strdup("float _Complex");
		break;
	case eT_PCPLX32:
		simple_type->size = 2;
		simple_type->type = strdup("float _Complex *");
		break;
	case eT_PFCPLX32:
	case eT_PHCPLX32:
	case eT_32PCPLX32:
	case eT_32PFCPLX32:
		simple_type->size = 4;
		simple_type->type = strdup("float _Complex *");
		break;
	case eT_64PCPLX32:
		simple_type->size = 8;
		simple_type->type = strdup("float _Complex *");
		break;
	case eT_CPLX64:
		simple_type->size = 8;
		simple_type->type = strdup("double _Complex");
		break;
	case eT_PCPLX64:
		simple_type->size = 2;
		simple_type->type = strdup("double _Complex *");
		break;
	case eT_PFCPLX64:
	case eT_PHCPLX64:
	case eT_32PCPLX64:
	case eT_32PFCPLX64:
		simple_type->size = 4;
		simple_type->type = strdup("double _Complex *");
		break;
	case eT_64PCPLX64:
		simple_type->size = 8;
		simple_type->type = strdup("double _Complex *");
		break;
	case eT_CPLX80:
		simple_type->size = 10;
		simple_type->type = strdup("long double _Complex");
		break;
	case eT_PCPLX80:
		simple_type->size = 2;
		simple_type->type = strdup("long double _Complex *");
		break;
	case eT_PFCPLX80:
	case eT_PHCPLX80:
	case eT_32PCPLX80:
	case eT_32PFCPLX80:
		simple_type->size = 4;
		simple_type->type = strdup("long double _Complex *");
		break;
	case eT_64PCPLX80:
		simple_type->size = 8;
		simple_type->type = strdup("long double _Complex *");
		break;
	case eT_CPLX128:
		simple_type->size = 16;
		simple_type->type = strdup("long double _Complex");
		break;
	case eT_PCPLX128:
		simple_type->size = 2;
		simple_type->type = strdup("long double _Complex *");
		break;
	case eT_PFCPLX128:
	case eT_PHCPLX128:
	case eT_32PCPLX128:
	case eT_32PFCPLX128:
		simple_type->size = 4;
		simple_type->type = strdup("long double _Complex *");
		break;
	case eT_64PCPLX128:
		simple_type->size = 8;
		simple_type->type = strdup("long double _Complex *");
		break;
	case eT_BOOL08: // _Bool probably isn't ideal for bool > 08
		simple_type->size = 1;
		simple_type->type = strdup("bool");
		break;
	case eT_PBOOL08:
		simple_type->size = 2;
		simple_type->type = strdup("bool *");
		break;
	case eT_PFBOOL08:
	case eT_PHBOOL08:
	case eT_32PBOOL08:
	case eT_32PFBOOL08:
		simple_type->size = 4;
		simple_type->type = strdup("bool *");
		break;
	case eT_64PBOOL08:
		simple_type->size = 8;
		simple_type->type = strdup("bool *");
		break;
	case eT_BOOL16:
		simple_type->size = 2;
		simple_type->type = strdup("bool");
		break;
	case eT_PBOOL16:
		simple_type->size = 2;
		simple_type->type = strdup("bool *");
		break;
	case eT_PFBOOL16:
	case eT_PHBOOL16:
	case eT_32PBOOL16:
	case eT_32PFBOOL16:
		simple_type->size = 4;
		simple_type->type = strdup("bool *");
		break;
	case eT_64PBOOL16:
		simple_type->size = 8;
		simple_type->type = strdup("bool *");
		break;
	case eT_BOOL32:
		simple_type->size = 4;
		simple_type->type = strdup("bool");
		break;
	case eT_PBOOL32:
		simple_type->size = 2;
		simple_type->type = strdup("bool *");
		break;
	case eT_PFBOOL32:
	case eT_PHBOOL32:
	case eT_32PBOOL32:
	case eT_32PFBOOL32:
		simple_type->size = 4;
		simple_type->type = strdup("bool *");
		break;
	case eT_64PBOOL32:
		simple_type->size = 8;
		simple_type->type = strdup("bool *");
		break;
	case eT_BOOL64:
		simple_type->size = 8;
		simple_type->type = strdup("bool");
		break;
	case eT_PBOOL64:
		simple_type->size = 2;
		simple_type->type = strdup("bool *");
		break;
	case eT_PFBOOL64:
	case eT_PHBOOL64:
	case eT_32PBOOL64:
	case eT_32PFBOOL64:
		simple_type->size = 4;
		simple_type->type = strdup("bool *");
		break;
	case eT_64PBOOL64:
		simple_type->size = 8;
		simple_type->type = strdup("bool *");
		break;
	case eT_BOOL128:
		simple_type->size = 16;
		simple_type->type = strdup("bool");
		break;
	case eT_PBOOL128:
		simple_type->size = 2;
		simple_type->type = strdup("bool *");
		break;
	case eT_PFBOOL128:
	case eT_PHBOOL128:
	case eT_32PBOOL128:
	case eT_32PFBOOL128:
		simple_type->size = 4;
		simple_type->type = strdup("bool *");
		break;
	case eT_64PBOOL128:
		simple_type->size = 8;
		simple_type->type = strdup("bool *");
		break;
	default:
		simple_type->size = 0;
		simple_type->type = strdup("unknown_t");
		break;
	}
	simple_type->simple_type = idx;
	type.type_info = simple_type;
	type.leaf_type = eLF_SIMPLE_TYPE;
	return type;
}

static ut64 get_numeric_val(SNumeric *numeric) {
	switch (numeric->type_index) {
	case eLF_CHAR:
		return *(st8 *)(numeric->data);
	case eLF_SHORT:
		return *(st16 *)(numeric->data);
	case eLF_USHORT:
		return *(ut16 *)(numeric->data);
	case eLF_LONG:
		return *(st32 *)(numeric->data);
	case eLF_ULONG:
		return *(ut32 *)(numeric->data);
	case eLF_QUADWORD:
		return *(st64 *)(numeric->data);
	case eLF_UQUADWORD:
		return *(ut64 *)(numeric->data);
	default:
		if (numeric->type_index >= 0x8000) {
			return 0;
		}
		return *(ut16 *)(numeric->data);
	}
}

static bool stype_is_fwdref(void *type) {
	STypeInfo *t = (STypeInfo *)type;
	switch (t->leaf_type) {
	case eLF_UNION: {
		SLF_UNION *lf = (SLF_UNION *)t->type_info;
		return lf->prop.bits.fwdref ? true : false;
	}
	case eLF_STRUCTURE:
	case eLF_CLASS: {
		SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;
		return lf->prop.bits.fwdref ? true : false;
	}
	case eLF_STRUCTURE_19:
	case eLF_CLASS_19: {
		SLF_STRUCTURE_19 *lf = (SLF_STRUCTURE_19 *)t->type_info;
		return lf->prop.bits.fwdref ? true : false;
	}
	default:
		rz_warn_if_reached();
		return true;
	}
}

static RzList *get_type_members(void *type) {
	rz_return_val_if_fail(type, NULL);
	STypeInfo *t = (STypeInfo *)type;
	SType *tmp = NULL;
	switch (t->leaf_type) {
	case eLF_FIELDLIST: {
		SLF_FIELDLIST *lf = t->type_info;
		return lf->substructs;
	}
	case eLF_UNION: {
		tmp = rz_bin_pdb_stype_by_index(((SLF_UNION *)t->type_info)->field_list);
		SLF_FIELDLIST *lf_union = tmp ? tmp->type_data.type_info : NULL;
		return lf_union ? lf_union->substructs : NULL;
	}
	case eLF_STRUCTURE:
	case eLF_CLASS: {
		tmp = rz_bin_pdb_stype_by_index(((SLF_STRUCTURE *)t->type_info)->field_list);
		SLF_FIELDLIST *lf_struct = tmp ? tmp->type_data.type_info : NULL;
		return lf_struct ? lf_struct->substructs : NULL;
	}
	case eLF_STRUCTURE_19:
	case eLF_CLASS_19: {
		tmp = rz_bin_pdb_stype_by_index(((SLF_STRUCTURE_19 *)t->type_info)->field_list);
		SLF_FIELDLIST *lf_struct19 = tmp ? tmp->type_data.type_info : NULL;
		return lf_struct19 ? lf_struct19->substructs : NULL;
	}
	case eLF_ENUM: {
		tmp = rz_bin_pdb_stype_by_index(((SLF_ENUM *)t->type_info)->field_list);
		SLF_FIELDLIST *lf_enum = tmp ? tmp->type_data.type_info : NULL;
		return lf_enum ? lf_enum->substructs : NULL;
	}
	default:
		return NULL;
	}
}

static char *get_type_name(void *type) {
	rz_return_val_if_fail(type, NULL);
	STypeInfo *t = (STypeInfo *)type;
	switch (t->leaf_type) {
	case eLF_MEMBER: {
		SLF_MEMBER *lf_member = t->type_info;
		return lf_member->name.name;
	}
	case eLF_ONEMETHOD: {
		SLF_ONEMETHOD *lf_onemethod = t->type_info;
		return lf_onemethod->name.name;
	}
	case eLF_METHOD: {
		SLF_METHOD *lf_method = t->type_info;
		return lf_method->name.name;
	}
	case eLF_NESTTYPE: {
		SLF_NESTTYPE *lf_nesttype = t->type_info;
		return lf_nesttype->name.name;
	}
	case eLF_ENUM: {
		SLF_ENUM *lf_enum = t->type_info;
		return lf_enum->name.name;
	}
	case eLF_ENUMERATE: {
		SLF_ENUMERATE *lf_enumerate = t->type_info;
		return lf_enumerate->name.name;
	}
	case eLF_CLASS:
	case eLF_STRUCTURE: {
		SLF_STRUCTURE *lf_struct = t->type_info;
		return lf_struct->name.name;
	}
	case eLF_CLASS_19:
	case eLF_STRUCTURE_19: {
		SLF_STRUCTURE_19 *lf_struct_19 = t->type_info;
		return lf_struct_19->name.name;
	}
	case eLF_ARRAY: {
		SLF_ARRAY *lf_array = t->type_info;
		return lf_array->name.name;
	}
	case eLF_UNION: {
		SLF_UNION *lf_union = t->type_info;
		return lf_union->name.name;
	}
	default:
		return NULL;
	}
}

static ut64 get_type_val(void *type) {
	rz_return_val_if_fail(type, -1);
	STypeInfo *t = (STypeInfo *)type;
	switch (t->leaf_type) {
	case eLF_ONEMETHOD: {
		SLF_ONEMETHOD *lf_onemethod = t->type_info;
		return lf_onemethod->offset_in_vtable;
	}
	case eLF_MEMBER: {
		SLF_MEMBER *lf_member = t->type_info;
		return get_numeric_val(&lf_member->offset);
	}
	case eLF_ENUMERATE: {
		SLF_ENUMERATE *lf_enumerate = t->type_info;
		return get_numeric_val(&lf_enumerate->enum_value);
	}
	case eLF_CLASS:
	case eLF_STRUCTURE: {
		SLF_STRUCTURE *lf_struct = t->type_info;
		return get_numeric_val(&lf_struct->size);
	}
	case eLF_CLASS_19:
	case eLF_STRUCTURE_19: {
		SLF_STRUCTURE_19 *lf_struct_19 = t->type_info;
		return get_numeric_val(&lf_struct_19->size);
	}
	case eLF_ARRAY: {
		SLF_ARRAY *lf_array = t->type_info;
		return get_numeric_val(&lf_array->size);
	}
	case eLF_UNION: {
		SLF_UNION *lf_union = t->type_info;
		return get_numeric_val(&lf_union->size);
	}
	default:
		return 0;
	}
}

static void free_snumeric(SNumeric *numeric) {
	switch (numeric->type_index) {
	case eLF_CHAR:
	case eLF_SHORT:
	case eLF_USHORT:
	case eLF_LONG:
	case eLF_ULONG:
	case eLF_QUADWORD:
	case eLF_UQUADWORD:
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

static void free_stype(void *type_info) {
	rz_return_if_fail(type_info);
	STypeInfo *typeInfo = (STypeInfo *)type_info;
	switch (typeInfo->leaf_type) {
	case eLF_ENUMERATE: {
		SLF_ENUMERATE *lf_en = (SLF_ENUMERATE *)typeInfo->type_info;
		free_snumeric(&(lf_en->enum_value));
		RZ_FREE(lf_en->name.name);
		break;
	}
	case eLF_NESTTYPE: {
		SLF_NESTTYPE *lf_nest = (SLF_NESTTYPE *)typeInfo->type_info;
		RZ_FREE(lf_nest->name.name);
		break;
	}
	case eLF_METHOD: {
		SLF_METHOD *lf_meth = (SLF_METHOD *)typeInfo->type_info;
		RZ_FREE(lf_meth->name.name);
		break;
	}
	case eLF_MEMBER: {
		SLF_MEMBER *lf_mem = (SLF_MEMBER *)typeInfo->type_info;
		free_snumeric(&lf_mem->offset);
		RZ_FREE(lf_mem->name.name);
		break;
	}
	case eLF_FIELDLIST: {
		SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *)typeInfo->type_info;
		RzListIter *it;
		STypeInfo *type_info = 0;
		rz_list_foreach (lf_fieldlist->substructs, it, type_info) {
			if (type_info->free_) {
				type_info->free_(type_info);
			}
			if (type_info->type_info) {
				RZ_FREE(type_info->type_info);
			}
			RZ_FREE(type_info);
		}
		rz_list_free(lf_fieldlist->substructs);
		break;
	}
	case eLF_CLASS:
	case eLF_STRUCTURE: {
		SLF_CLASS *lf_class = (SLF_CLASS *)typeInfo->type_info;
		free_snumeric(&lf_class->size);
		RZ_FREE(lf_class->name.name);
		break;
	}
	case eLF_CLASS_19:
	case eLF_STRUCTURE_19: {
		SLF_CLASS_19 *lf_class_19 = (SLF_CLASS_19 *)typeInfo->type_info;
		free_snumeric(&lf_class_19->size);
		RZ_FREE(lf_class_19->name.name);
		break;
	}
	case eLF_UNION: {
		SLF_UNION *lf_union = (SLF_UNION *)typeInfo->type_info;
		free_snumeric(&lf_union->size);
		RZ_FREE(lf_union->name.name);
		break;
	}
	case eLF_ONEMETHOD: {
		SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *)typeInfo->type_info;
		RZ_FREE(lf_onemethod->name.name);
		break;
	}
	case eLF_BCLASS: {
		SLF_BCLASS *lf_bclass = (SLF_BCLASS *)typeInfo->type_info;
		free_snumeric(&lf_bclass->offset);
		break;
	}
	case eLF_VBCLASS:
	case eLF_IVBCLASS: {
		SLF_VBCLASS *lf_vbclass = (SLF_VBCLASS *)typeInfo->type_info;
		free_snumeric(&lf_vbclass->vb_pointer_offset);
		free_snumeric(&lf_vbclass->vb_offset_from_vbtable);
		break;
	}
	case eLF_ENUM: {
		SLF_ENUM *lf_enum = (SLF_ENUM *)typeInfo->type_info;
		RZ_FREE(lf_enum->name.name);
		break;
	}
	case eLF_ARRAY: {
		SLF_ARRAY *lf_array = (SLF_ARRAY *)typeInfo->type_info;
		free_snumeric(&lf_array->size);
		RZ_FREE(lf_array->name.name);
		break;
	}
	case eLF_ARGLIST: {
		SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *)typeInfo->type_info;
		RZ_FREE(lf_arglist->arg_type);
		lf_arglist->arg_type = 0;
		break;
	}

	case eLF_VTSHAPE: {
		SLF_VTSHAPE *lf_vtshape = (SLF_VTSHAPE *)typeInfo->type_info;
		RZ_FREE(lf_vtshape->vt_descriptors);
		lf_vtshape->vt_descriptors = 0;
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

static void free_tpi_stream(void *stream) {
	STpiStream *tpi_stream = (STpiStream *)stream;
	RzListIter *it;
	SType *type = NULL;

	it = rz_list_iterator(tpi_stream->types);
	while (rz_list_iter_next(it)) {
		type = (SType *)rz_list_iter_get(it);
		if (!type) {
			continue;
		}
		if (type->type_data.free_) {
			type->type_data.free_(&type->type_data);
			type->type_data.free_ = 0;
		}
		if (type->type_data.type_info) {
			free(type->type_data.type_info);
			type->type_data.free_ = 0;
			type->type_data.type_info = 0;
		}
		RZ_FREE(type);
	}
	rz_list_free(tpi_stream->types);
}

// TODO: remove these get_xxx_print_type
static void get_array_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = NULL;
	bool need_to_free = true;

	SType *t = 0;
	t = rz_bin_pdb_stype_by_index(((SLF_ARRAY *)(ti->type_info))->element_type);
	rz_return_if_fail(t); // t == NULL indicates malformed PDB ?
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		need_to_free = false;
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}
	ut64 size = 0;
	if (ti->get_val) {
		size = ti->get_val(ti);
	}
	RzStrBuf buff;
	rz_strbuf_init(&buff);
	if (tmp_name) {
		rz_strbuf_append(&buff, tmp_name);
	}
	rz_strbuf_appendf(&buff, "[%" PFMT64u "]", size);
	*name = rz_strbuf_drain_nofree(&buff);
	rz_strbuf_fini(&buff);
	if (need_to_free) {
		RZ_FREE(tmp_name);
	}
}

static void get_pointer_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = NULL;
	int need_to_free = 1;

	t = rz_bin_pdb_stype_by_index(((SLF_POINTER *)(ti->type_info))->utype);
	rz_return_if_fail(t); // t == NULL indicates malformed PDB ?
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		need_to_free = false;
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	RzStrBuf buff;
	rz_strbuf_init(&buff);
	if (tmp_name) {
		rz_strbuf_append(&buff, tmp_name);
	}
	rz_strbuf_append(&buff, "*");
	*name = rz_strbuf_drain_nofree(&buff);
	rz_strbuf_fini(&buff);
	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

static void get_modifier_print_type(void *type, char **name) {
	STypeInfo *stype_info = type;
	bool need_to_free = true;
	SType *stype = NULL;
	char *tmp_name = NULL;

	stype = rz_bin_pdb_stype_by_index(((SLF_MODIFIER *)(stype_info->type_info))->modified_type);
	if (stype && stype->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		need_to_free = false;
		SLF_SIMPLE_TYPE *base_type = stype->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		STypeInfo *refered_type_info = NULL;
		refered_type_info = &stype->type_data;
		refered_type_info->get_print_type(refered_type_info, &tmp_name);
	}

	SLF_MODIFIER *modifier = stype_info->type_info;
	RzStrBuf buff;
	rz_strbuf_init(&buff);
	if (modifier->umodifier.bits.const_) {
		rz_strbuf_append(&buff, "const ");
	}
	if (modifier->umodifier.bits.volatile_) {
		rz_strbuf_append(&buff, "volatile ");
	}
	if (modifier->umodifier.bits.unaligned) {
		rz_strbuf_append(&buff, "unaligned ");
	}
	if (tmp_name) {
		rz_strbuf_append(&buff, tmp_name);
	}
	*name = rz_strbuf_drain_nofree(&buff);
	rz_strbuf_fini(&buff);

	if (need_to_free) {
		free(tmp_name);
	}
}

static void get_procedure_print_type(void *type, char **name) {
	// TODO
	const int name_len = strlen("void ");
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "void ");
}

static void get_bitfield_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	SLF_BITFIELD *bitfeild_info = (SLF_BITFIELD *)ti->type_info;

	t = rz_bin_pdb_stype_by_index(((SLF_BITFIELD *)(ti->type_info))->base_type);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		need_to_free = false;
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("bitfield ");
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	name_len += 4;
	*name = (char *)malloc(name_len + 6);
	if (!(*name)) {
		if (need_to_free) {
			free(tmp_name);
		}
		return;
	}

	// name[name_len] = '\0';
	if (tmp_name) {
		//sprintf(*name, "%s %s : %d", "bitfield", tmp_name, (int)bitfeild_info->length);
		sprintf(*name, "%s /*%s:%d*/", tmp_name, "bitfield", (int)bitfeild_info->length);
	} else {
		//sprintf(*name, "%s : %d", "bitfield", (int)bitfeild_info->length);
		sprintf(*name, "%s /*:%d*/", "bitfield", (int)bitfeild_info->length);
	}

	if (need_to_free) {
		free(tmp_name);
	}
}

static void get_fieldlist_print_type(void *type, char **name) {
	int name_len = 0;

	name_len = strlen("fieldlist ");
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "fieldlist ");
}

static void get_enum_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;
	int need_to_free = 1;

	t = rz_bin_pdb_stype_by_index(((SLF_ENUM *)(ti->type_info))->utype);
	rz_return_if_fail(t); // This shouldn't happen?, TODO explore this situation
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) { // BaseType
		need_to_free = 0;
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	RzStrBuf buff;
	rz_strbuf_init(&buff);
	rz_strbuf_append(&buff, "enum ");
	if (tmp_name) {
		rz_strbuf_append(&buff, tmp_name);
	}
	*name = rz_strbuf_drain_nofree(&buff);
	rz_strbuf_fini(&buff);

	if (need_to_free) {
		free(tmp_name);
	}
}

static void get_class_struct_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	lt = ti->leaf_type;
	tmp_name = ti->get_name(ti);

	if (lt == eLF_CLASS) {
		tmp1 = "class ";
	} else {
		tmp1 = "struct ";
	}
	name_len = strlen(tmp1);
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name) {
		strcat(*name, tmp_name);
	}

	//	if (need_to_free) {
	//		free(tmp_name);
	//		tmp_name = 0;
	//	}
}

static void get_arglist_print_type(void *type, char **name) {
	(void)type;
	int name_len = 0;

	name_len = strlen("arg_list");
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "arg_list");
	//	STypeInfo *ti = (STypeInfo *) type;
	//	SType *t = 0;
	//	char *tmp_name = 0;
	//	int name_len = 0;
	//	int need_to_free = 1;
	//	int base_type = 0;

	//	base_type = ti->get_arg_type(ti, (void **)&t);
	//	if (!t) {
	//		need_to_free = 0;
	//		print_base_type(base_type, &tmp_name);
	//	} else {
	//		ti = &t->type_data;
	//		ti->get_print_type(ti, &tmp_name);
	//	}

	//	name_len = strlen("arglist ");
	//	name_len += strlen(tmp_name);
	//	*name = (char *) malloc(name_len + 1);
	//	// name[name_len] = '\0';
	//	strcpy(*name, "arglist ");
	//	strcat(*name, tmp_name);

	//	if (need_to_free)
	//		free(tmp_name);
}

// TODO, nothing is really being parsed here
static void get_mfunction_print_type(void *type, char **name) {
	int name_len = 0;

	name_len = strlen("mfunction ");
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "mfunction ");
}

static void get_union_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	//	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	//	lt = ti->leaf_type;
	tmp_name = ti->get_name(ti);

	tmp1 = "union ";
	name_len = strlen(tmp1);
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name) {
		strcat(*name, tmp_name);
	}

	//	if (need_to_free) {
	//		free(tmp_name);
	//		tmp_name = 0;
	//	}
}

static void get_vtshape_print_type(void *type, char **name) {
	int name_len = 0;

	name_len = strlen("vtshape");
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "vthape");
}

static void get_enumerate_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	tmp_name = ti->get_name(ti);

	tmp1 = "enumerate ";
	name_len = strlen(tmp1);
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name) {
		strcat(*name, tmp_name);
	}

	//	if (need_to_free)
	//		free(tmp_name);
}

static void get_nesttype_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;

	t = rz_bin_pdb_stype_by_index(((SLF_NESTTYPE *)(ti->type_info))->index);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		need_to_free = false;
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		if (ti->get_print_type != NULL) {
			ti->get_print_type(ti, &tmp_name);
		} else {
			// TODO: need to investigate why this branch can be...
			//	this is possible because there is no support for
			// parsing METHODLIST...
			// need to investigate for this theme
			//eprintf ("warning: strange for nesttype\n");
		}
	}

	name_len = strlen("nesttype ");
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		if (need_to_free) {
			free(tmp_name);
		}
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "nesttype ");
	if (tmp_name) {
		strcat(*name, tmp_name);
	}

	if (need_to_free) {
		free(tmp_name);
	}
}

static void get_method_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;

	tmp_name = ti->get_name(ti);

	tmp1 = "method ";
	name_len = strlen(tmp1);
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	if (tmp_name) {
		strcat(*name, tmp_name);
	}

	//	if (need_to_free)
	//		free(tmp_name);
}

static void get_member_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;

	t = rz_bin_pdb_stype_by_index(((SLF_MEMBER *)(ti->type_info))->index);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}
	if (tmp_name) {
		*name = tmp_name;
	}
}

static void get_onemethod_print_type(void *type, char **name) {
	STypeInfo *ti = (STypeInfo *)type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;

	t = rz_bin_pdb_stype_by_index(((SLF_ONEMETHOD *)(ti->type_info))->index);
	if (t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		need_to_free = false;
		SLF_SIMPLE_TYPE *base_type = t->type_data.type_info;
		tmp_name = base_type->type;
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("onemethod ");
	if (tmp_name) {
		name_len += strlen(tmp_name);
	}
	*name = (char *)malloc(name_len + 1);
	if (!(*name)) {
		if (need_to_free) {
			free(tmp_name);
		}
		return;
	}
	// name[name_len] = '\0';
	strcpy(*name, "onemethod ");
	if (tmp_name) {
		strcat(*name, tmp_name);
	}

	if (need_to_free) {
		free(tmp_name);
	}
}

void init_scstring(SCString *cstr, unsigned int size, char *name) {
	cstr->size = size;
	cstr->name = strdup(name);
}

void deinit_scstring(SCString *cstr) {
	free(cstr->name);
}

int parse_scstring(SCString *sctr, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(sctr && leaf_data, -1);
	unsigned int c = 0;
	sctr->name = NULL;
	sctr->size = 0;
	while (*leaf_data) {
		CAN_READ((*read_bytes + c), 1, len);
		c++;
		leaf_data++;
	}
	CAN_READ(*read_bytes, 1, len);
	leaf_data += 1;
	(*read_bytes) += (c + 1);

	init_scstring(sctr, c + 1, (char *)leaf_data - (c + 1));
	return 1;
}

static int parse_numeric(SNumeric *numeric, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(numeric && leaf_data, -1);
	numeric->data = 0;
	numeric->is_integer = true;
	READ2(*read_bytes, len, numeric->type_index, leaf_data, ut16);

	switch (numeric->type_index) {
	case eLF_CHAR:
		numeric->data = RZ_NEW0(st8);
		READ1(*read_bytes, len, *(st8 *)numeric->data, leaf_data, st8);
		break;
	case eLF_SHORT:
		numeric->data = RZ_NEW0(st16);
		READ2(*read_bytes, len, *(st16 *)numeric->data, leaf_data, st16);
		break;
	case eLF_USHORT:
		numeric->data = RZ_NEW0(ut16);
		READ2(*read_bytes, len, *(ut16 *)numeric->data, leaf_data, ut16);
		break;
	case eLF_LONG:
		numeric->data = RZ_NEW0(st32);
		READ4(*read_bytes, len, *(st32 *)numeric->data, leaf_data, st32);
		break;
	case eLF_ULONG:
		numeric->data = RZ_NEW0(ut32);
		READ4(*read_bytes, len, *(ut32 *)numeric->data, leaf_data, ut32);
		break;
	case eLF_QUADWORD:
		numeric->data = RZ_NEW0(st64);
		READ8(*read_bytes, len, *(st64 *)numeric->data, leaf_data, st64);
		break;
	case eLF_UQUADWORD:
		numeric->data = RZ_NEW0(ut64);
		READ8(*read_bytes, len, *(ut64 *)numeric->data, leaf_data, ut64);
		break;
	default:
		if (numeric->type_index >= 0x8000) {
			numeric->is_integer = false;
			printf("parse_numeric: Skipping unsupported type (%d)\n", numeric->type_index);
			return 0;
		}
		numeric->data = RZ_NEW0(ut16);
		*(ut16 *)(numeric->data) = numeric->type_index;
	}
	return 1;
}

static int parse_lf_enumerate(SLF_ENUMERATE *lf_enumerate, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_enumerate && leaf_data, -1);
	unsigned int read_bytes_before = 0, tmp_read_bytes_before = 0;

	read_bytes_before = *read_bytes;
	READ2(*read_bytes, len, lf_enumerate->fldattr.fldattr, leaf_data, ut16);

	tmp_read_bytes_before = *read_bytes;
	parse_numeric(&lf_enumerate->enum_value, leaf_data, read_bytes, len);
	if (!lf_enumerate->enum_value.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_enumerate->enum_value);
		return 0;
	}
	leaf_data += (*read_bytes - tmp_read_bytes_before);
	parse_scstring(&lf_enumerate->name, leaf_data, read_bytes, len);
	leaf_data += lf_enumerate->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return (*read_bytes - read_bytes_before);
}

static int parse_lf_nesttype(SLF_NESTTYPE *lf_nesttype, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_nesttype && leaf_data, -1);
	unsigned int read_bytes_before = *read_bytes;

	lf_nesttype->name.name = 0;

	READ2(*read_bytes, len, lf_nesttype->pad, leaf_data, ut16);
	READ4(*read_bytes, len, lf_nesttype->index, leaf_data, ut16);

	parse_scstring(&lf_nesttype->name, leaf_data, read_bytes, len);
	leaf_data += lf_nesttype->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return *read_bytes - read_bytes_before;
}

static int parse_lf_vfunctab(SLF_VFUNCTAB *lf_vfunctab, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_vfunctab && leaf_data, -1);
	unsigned int read_bytes_before = *read_bytes;

	READ2(*read_bytes, len, lf_vfunctab->pad, leaf_data, ut16);
	READ4(*read_bytes, len, lf_vfunctab->index, leaf_data, ut32);

	return *read_bytes - read_bytes_before;
}

static int parse_lf_method(SLF_METHOD *lf_method, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_method && leaf_data, -1);
	unsigned int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;

	lf_method->name.name = 0;

	READ2(*read_bytes, len, lf_method->count, leaf_data, ut16);
	READ4(*read_bytes, len, lf_method->mlist, leaf_data, ut32);

	tmp_read_bytes_before = *read_bytes;
	parse_scstring(&lf_method->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ1(*read_bytes, len, lf_method->pad, leaf_data, ut8);
	PAD_ALIGN(lf_method->pad, *read_bytes, leaf_data, len);

	return *read_bytes - read_bytes_before;
}

static int parse_lf_member(SLF_MEMBER *lf_member, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_member && leaf_data, -1);
	int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;

	READ2(*read_bytes, len, lf_member->fldattr.fldattr, leaf_data, ut16);
	READ4(*read_bytes, len, lf_member->index, leaf_data, ut32);

	tmp_read_bytes_before = *read_bytes;
	parse_numeric(&lf_member->offset, leaf_data, read_bytes, len);
	if (!lf_member->offset.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_member->offset);
		return 0;
	}
	leaf_data += (*read_bytes - tmp_read_bytes_before);
	parse_scstring(&lf_member->name, leaf_data, read_bytes, len);
	leaf_data += lf_member->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return (*read_bytes - read_bytes_before);
}

static int parse_lf_onemethod(SLF_ONEMETHOD *lf_onemethod, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_onemethod && leaf_data, -1);
	int read_bytes_before = *read_bytes, tmp_before_read_bytes = 0;

	READ2(*read_bytes, len, lf_onemethod->fldattr.fldattr, leaf_data, ut16);
	READ4(*read_bytes, len, lf_onemethod->index, leaf_data, ut32);

	if ((lf_onemethod->fldattr.bits.mprop == eMTintro) ||
		(lf_onemethod->fldattr.bits.mprop == eMTpureintro)) {
		READ4(*read_bytes, len, lf_onemethod->offset_in_vtable, leaf_data, ut32);
	}

	tmp_before_read_bytes = *read_bytes;
	parse_scstring(&(lf_onemethod->name), leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_before_read_bytes);

	PEEK_READ1(*read_bytes, len, lf_onemethod->pad, leaf_data, ut8);
	PAD_ALIGN(lf_onemethod->pad, *read_bytes, leaf_data, len);

	return (*read_bytes - read_bytes_before);
}

static int parse_lf_bclass(SLF_BCLASS *lf_bclass, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_bclass && leaf_data, -1);
	int read_bytes_before = *read_bytes, tmp_before_read_bytes = 0;

	READ2(*read_bytes, len, lf_bclass->fldattr.fldattr, leaf_data, ut16);
	READ4(*read_bytes, len, lf_bclass->index, leaf_data, ut32);

	tmp_before_read_bytes = *read_bytes;
	parse_numeric(&lf_bclass->offset, leaf_data, read_bytes, len);
	if (!lf_bclass->offset.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_bclass->offset);
		return 0;
	}
	leaf_data += (*read_bytes - tmp_before_read_bytes);
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return (*read_bytes - read_bytes_before);
}

static int parse_lf_vbclass(SLF_VBCLASS *lf_vbclass, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_vbclass && leaf_data, -1);
	int read_bytes_before = *read_bytes, tmp_before_read_bytes = 0;

	READ2(*read_bytes, len, lf_vbclass->fldattr.fldattr, leaf_data, ut16);
	READ4(*read_bytes, len, lf_vbclass->direct_vbclass_idx, leaf_data, ut32);
	READ4(*read_bytes, len, lf_vbclass->vb_pointer_idx, leaf_data, ut32);

	tmp_before_read_bytes = *read_bytes;
	parse_numeric(&lf_vbclass->vb_pointer_offset, leaf_data, read_bytes, len);
	if (!lf_vbclass->vb_pointer_offset.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_vbclass->vb_pointer_offset);
		return 0;
	}
	parse_numeric(&lf_vbclass->vb_offset_from_vbtable, leaf_data, read_bytes, len);
	if (!lf_vbclass->vb_offset_from_vbtable.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_vbclass->vb_offset_from_vbtable);
		return 0;
	}
	leaf_data += (*read_bytes - tmp_before_read_bytes);

	return (*read_bytes - read_bytes_before);
}

static void init_stype_info(STypeInfo *type_info) {
	type_info->free_ = 0;
	type_info->get_members = 0;
	type_info->get_name = 0;
	type_info->get_val = 0;
	type_info->is_fwdref = 0;
	type_info->get_print_type = 0;

	switch (type_info->leaf_type) {
	case eLF_FIELDLIST:
		type_info->get_members = get_type_members;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_fieldlist_print_type;
		break;
	case eLF_ENUM:
		type_info->get_name = get_type_name;
		type_info->get_members = get_type_members;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_enum_print_type;
		break;
	case eLF_CLASS:
	case eLF_STRUCTURE:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val; // for structure this is size
		type_info->get_members = get_type_members;
		type_info->is_fwdref = stype_is_fwdref;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_class_struct_print_type;
		break;
	case eLF_CLASS_19:
	case eLF_STRUCTURE_19:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val; // for structure this is size
		type_info->get_members = get_type_members;
		type_info->is_fwdref = stype_is_fwdref;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_class_struct_print_type;
	case eLF_POINTER:
		type_info->get_print_type = get_pointer_print_type;
		break;
	case eLF_ARRAY:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_array_print_type;
		break;
	case eLF_MODIFIER:
		type_info->get_print_type = get_modifier_print_type;
		break;
	case eLF_ARGLIST:
		type_info->free_ = free_stype;
		type_info->get_print_type = get_arglist_print_type;
		break;
	case eLF_MFUNCTION:
		type_info->get_print_type = get_mfunction_print_type;
		break;
	case eLF_METHODLIST: // TODO missing stuff
		break;
	case eLF_PROCEDURE:
		type_info->get_print_type = get_procedure_print_type;
		break;
	case eLF_UNION:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val;
		type_info->get_members = get_type_members;
		type_info->is_fwdref = stype_is_fwdref;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_union_print_type;
		break;
	case eLF_BITFIELD:
		type_info->get_print_type = get_bitfield_print_type;
		break;
	case eLF_VTSHAPE:
		type_info->free_ = free_stype;
		type_info->get_print_type = get_vtshape_print_type;
		break;
	case eLF_ENUMERATE:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_enumerate_print_type;
		break;
	case eLF_NESTTYPE:
		type_info->get_name = get_type_name;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_nesttype_print_type;
		break;
	case eLF_VFUNCTAB:
		break;
	case eLF_METHOD:
		type_info->get_name = get_type_name;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_method_print_type;
		break;
	case eLF_MEMBER:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_member_print_type;
		break;
	case eLF_ONEMETHOD:
		type_info->get_name = get_type_name;
		type_info->get_val = get_type_val;
		type_info->free_ = free_stype;
		type_info->get_print_type = get_onemethod_print_type;
		break;
	case eLF_BCLASS:
		type_info->free_ = free_stype;
		break;
	case eLF_VBCLASS:
	case eLF_IVBCLASS:
		type_info->free_ = free_stype;
	default:
		break;
	}
}

#define PARSE_LF2(lf_type, lf_func_name, type) \
	{ \
		STypeInfo *type_info = (STypeInfo *)malloc(sizeof(STypeInfo)); \
		if (!type_info) \
			return 0; \
		lf_type *lf = (lf_type *)malloc(sizeof(lf_type)); \
		if (!lf) { \
			free(type_info); \
			return 0; \
		} \
		curr_read_bytes = parse_##lf_func_name(lf, p, read_bytes, len); \
		type_info->type_info = (void *)lf; \
		type_info->leaf_type = type; \
		init_stype_info(type_info); \
		rz_list_append(lf_fieldlist->substructs, type_info); \
	}

static int parse_lf_fieldlist(SLF_FIELDLIST *lf_fieldlist, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_fieldlist && leaf_data, -1);
	ELeafType leaf_type;
	int curr_read_bytes = 0;
	uint8_t *p = leaf_data;

	lf_fieldlist->substructs = rz_list_new();

	while (*read_bytes <= len) {
		READ2(*read_bytes, len, leaf_type, p, ut16);
		switch (leaf_type) {
		case eLF_ENUMERATE:
			PARSE_LF2(SLF_ENUMERATE, lf_enumerate, eLF_ENUMERATE);
			break;
		case eLF_NESTTYPE:
			PARSE_LF2(SLF_NESTTYPE, lf_nesttype, eLF_NESTTYPE);
			break;
		case eLF_VFUNCTAB:
			PARSE_LF2(SLF_VFUNCTAB, lf_vfunctab, eLF_VFUNCTAB);
			break;
		case eLF_METHOD:
			PARSE_LF2(SLF_METHOD, lf_method, eLF_METHOD);
			break;
		case eLF_MEMBER:
			PARSE_LF2(SLF_MEMBER, lf_member, eLF_MEMBER);
			break;
		case eLF_ONEMETHOD:
			PARSE_LF2(SLF_ONEMETHOD, lf_onemethod, eLF_ONEMETHOD);
			break;
		case eLF_BCLASS:
			PARSE_LF2(SLF_BCLASS, lf_bclass, eLF_BCLASS);
			break;
		case eLF_VBCLASS:
		case eLF_IVBCLASS:
			PARSE_LF2(SLF_VBCLASS, lf_vbclass, eLF_VBCLASS);
			break;
		default:
			//			printf("unsupported leaf type in parse_lf_fieldlist()\n");
			return 0;
		}

		if (curr_read_bytes != 0) {
			p += curr_read_bytes;
		} else {
			return 0;
		}
	}
	return 0;
}

static int parse_lf_enum(SLF_ENUM *lf_enum, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_enum && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	lf_enum->name.name = 0;

	READ2(*read_bytes, len, lf_enum->count, leaf_data, ut16);
	READ2(*read_bytes, len, lf_enum->prop.cv_property, leaf_data, ut16);
	READ4(*read_bytes, len, lf_enum->utype, leaf_data, ut32);
	READ4(*read_bytes, len, lf_enum->field_list, leaf_data, ut32);

	before_read_bytes = *read_bytes;
	parse_scstring(&lf_enum->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ1(*read_bytes, len, lf_enum->pad, leaf_data, ut8);
	PAD_ALIGN(lf_enum->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_structure(SLF_STRUCTURE *lf_structure, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_structure && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	READ2(*read_bytes, len, lf_structure->count, leaf_data, ut16);
	READ2(*read_bytes, len, lf_structure->prop.cv_property, leaf_data, ut16);
	READ4(*read_bytes, len, lf_structure->field_list, leaf_data, ut32);
	READ4(*read_bytes, len, lf_structure->derived, leaf_data, ut32);
	READ4(*read_bytes, len, lf_structure->vshape, leaf_data, ut32);

	before_read_bytes = *read_bytes;
	parse_numeric(&lf_structure->size, leaf_data, read_bytes, len);
	if (!lf_structure->size.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_structure->size);
		return 0;
	}
	leaf_data += (*read_bytes - before_read_bytes);
	parse_scstring(&lf_structure->name, leaf_data, read_bytes, len);
	leaf_data += lf_structure->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_structure_19(SLF_STRUCTURE_19 *lf_structure, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_structure && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	READ2(*read_bytes, len, lf_structure->prop.cv_property, leaf_data, ut16);
	READ2(*read_bytes, len, lf_structure->unknown, leaf_data, ut16);
	READ4(*read_bytes, len, lf_structure->field_list, leaf_data, ut32);
	READ4(*read_bytes, len, lf_structure->derived, leaf_data, ut32);
	READ4(*read_bytes, len, lf_structure->vshape, leaf_data, ut32);
	READ2(*read_bytes, len, lf_structure->unknown1, leaf_data, st16);

	before_read_bytes = *read_bytes;
	parse_numeric(&lf_structure->size, leaf_data, read_bytes, len);
	if (!lf_structure->size.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_structure->size);
		return 0;
	}
	leaf_data += (*read_bytes - before_read_bytes);
	parse_scstring(&lf_structure->name, leaf_data, read_bytes, len);
	leaf_data += lf_structure->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_pointer(SLF_POINTER *lf_pointer, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_pointer && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ4(*read_bytes, len, lf_pointer->utype, leaf_data, ut32);
	READ4(*read_bytes, len, lf_pointer->ptr_attr.ptr_attr, leaf_data, ut32);

	PEEK_READ1(*read_bytes, len, lf_pointer->pad, leaf_data, ut8);
	PAD_ALIGN(lf_pointer->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_array(SLF_ARRAY *lf_array, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_array && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	READ4(*read_bytes, len, lf_array->element_type, leaf_data, ut32);
	READ4(*read_bytes, len, lf_array->index_type, leaf_data, ut32);

	before_read_bytes = *read_bytes;
	parse_numeric(&lf_array->size, leaf_data, read_bytes, len);
	if (!lf_array->size.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_array->size);
		return 0;
	}
	leaf_data += (*read_bytes - before_read_bytes);
	parse_scstring(&lf_array->name, leaf_data, read_bytes, len);
	leaf_data += lf_array->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_modifier(SLF_MODIFIER *lf_modifier, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_modifier && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ4(*read_bytes, len, lf_modifier->modified_type, leaf_data, ut32);
	READ2(*read_bytes, len, lf_modifier->umodifier.modifier, leaf_data, ut16);

	PEEK_READ1(*read_bytes, len, lf_modifier->pad, leaf_data, ut8);
	PAD_ALIGN(lf_modifier->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_arglist(SLF_ARGLIST *lf_arglist, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_arglist && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;

	lf_arglist->arg_type = 0;

	READ4(*read_bytes, len, lf_arglist->count, leaf_data, ut32);

	lf_arglist->arg_type = (unsigned int *)malloc(lf_arglist->count * 4);
	if (!lf_arglist->arg_type) {
		return 0;
	}
	memcpy(lf_arglist->arg_type, leaf_data, lf_arglist->count * 4);
	leaf_data += (lf_arglist->count * 4);
	*read_bytes += (lf_arglist->count * 4);

	PEEK_READ1(*read_bytes, len, lf_arglist->pad, leaf_data, ut8);
	PAD_ALIGN(lf_arglist->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_mfunction(SLF_MFUNCTION *lf_mfunction, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_mfunction && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ4(*read_bytes, len, lf_mfunction->return_type, leaf_data, ut32);
	READ4(*read_bytes, len, lf_mfunction->class_type, leaf_data, ut32);
	READ4(*read_bytes, len, lf_mfunction->this_type, leaf_data, ut32);
	READ1(*read_bytes, len, lf_mfunction->call_conv, leaf_data, ut8);
	READ1(*read_bytes, len, lf_mfunction->func_attr.funcattr, leaf_data, ut8);
	READ2(*read_bytes, len, lf_mfunction->parm_count, leaf_data, ut8);
	READ4(*read_bytes, len, lf_mfunction->arglist, leaf_data, ut32);
	READ4(*read_bytes, len, lf_mfunction->this_adjust, leaf_data, st32);

	PEEK_READ1(*read_bytes, len, lf_mfunction->pad, leaf_data, ut8);
	PAD_ALIGN(lf_mfunction->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_procedure(SLF_PROCEDURE *lf_procedure, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_procedure && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ4(*read_bytes, len, lf_procedure->return_type, leaf_data, ut32);
	READ1(*read_bytes, len, lf_procedure->call_conv, leaf_data, ut8);
	READ1(*read_bytes, len, lf_procedure->func_attr.funcattr, leaf_data, ut8);
	READ2(*read_bytes, len, lf_procedure->parm_count, leaf_data, ut16);
	READ4(*read_bytes, len, lf_procedure->arg_list, leaf_data, ut32);

	PEEK_READ1(*read_bytes, len, lf_procedure->pad, leaf_data, ut8);
	PAD_ALIGN(lf_procedure->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_union(SLF_UNION *lf_union, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_union && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int before_read_bytes = 0;

	READ2(*read_bytes, len, lf_union->count, leaf_data, ut16);
	READ2(*read_bytes, len, lf_union->prop.cv_property, leaf_data, ut16);
	READ4(*read_bytes, len, lf_union->field_list, leaf_data, ut32);

	before_read_bytes = *read_bytes;
	parse_numeric(&lf_union->size, leaf_data, read_bytes, len);
	if (!lf_union->size.is_integer) {
		eprintf("Integer expected!\n");
		free_snumeric(&lf_union->size);
		return 0;
	}
	before_read_bytes = *read_bytes - before_read_bytes;
	leaf_data = (uint8_t *)leaf_data + before_read_bytes;
	parse_scstring(&lf_union->name, leaf_data, read_bytes, len);
	leaf_data += lf_union->name.size;
	leaf_data += skip_padding(leaf_data, read_bytes, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_bitfield(SLF_BITFIELD *lf_bitfield, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_bitfield && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;

	READ4(*read_bytes, len, lf_bitfield->base_type, leaf_data, ut32);
	READ1(*read_bytes, len, lf_bitfield->length, leaf_data, ut8);
	READ1(*read_bytes, len, lf_bitfield->position, leaf_data, ut8);

	PEEK_READ1(*read_bytes, len, lf_bitfield->pad, leaf_data, ut8);
	PAD_ALIGN(lf_bitfield->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

static int parse_lf_vtshape(SLF_VTSHAPE *lf_vtshape, uint8_t *leaf_data, unsigned int *read_bytes, unsigned int len) {
	rz_return_val_if_fail(lf_vtshape && leaf_data, -1);
	unsigned int tmp_before_read_bytes = *read_bytes;
	unsigned int size; // in bytes;

	lf_vtshape->vt_descriptors = 0;

	READ2(*read_bytes, len, lf_vtshape->count, leaf_data, ut16);

	size = (4 * lf_vtshape->count + (lf_vtshape->count % 2) * 4) / 8;
	lf_vtshape->vt_descriptors = (char *)malloc(size);
	if (!lf_vtshape->vt_descriptors) {
		return 0;
	}
	memcpy(lf_vtshape->vt_descriptors, leaf_data, size);
	leaf_data += size;
	*read_bytes += size;

	PEEK_READ1(*read_bytes, len, lf_vtshape->pad, leaf_data, ut8);
	PAD_ALIGN(lf_vtshape->pad, *read_bytes, leaf_data, len);

	return *read_bytes - tmp_before_read_bytes;
}

#define PARSE_LF(lf_type, lf_func) \
	{ \
		lf_type *lf = (lf_type *)malloc(sizeof(lf_type)); \
		if (!lf) { \
			free(leaf_data); \
			return 0; \
		} \
		parse_##lf_func(lf, leaf_data + 2, &read_bytes, type->length); \
		type->type_data.type_info = (void *)lf; \
		init_stype_info(&type->type_data); \
	}

static int parse_tpi_stypes(RZ_STREAM_FILE *stream, SType *type) {
	uint8_t *leaf_data;
	unsigned int read_bytes = 0;

	stream_file_read(stream, 2, (char *)&type->length);
	if (type->length < 1) {
		return 0;
	}
	leaf_data = (uint8_t *)malloc(type->length);
	if (!leaf_data) {
		return 0;
	}
	stream_file_read(stream, type->length, (char *)leaf_data);
	type->type_data.leaf_type = *(uint16_t *)leaf_data;
	read_bytes += 2;
	switch (type->type_data.leaf_type) {
	case eLF_FIELDLIST:
		PARSE_LF(SLF_FIELDLIST, lf_fieldlist);
		break;
	case eLF_ENUM:
		PARSE_LF(SLF_ENUM, lf_enum);
		break;
	case eLF_CLASS:
	case eLF_STRUCTURE:
		PARSE_LF(SLF_STRUCTURE, lf_structure);
		break;
	case eLF_CLASS_19:
	case eLF_STRUCTURE_19:
		PARSE_LF(SLF_STRUCTURE_19, lf_structure_19);
		break;
	case eLF_POINTER: {
		SLF_POINTER *lf = (SLF_POINTER *)malloc(sizeof(SLF_POINTER));
		if (!lf) {
			free(leaf_data);
			return 0;
		}
		parse_lf_pointer(lf, leaf_data + 2, &read_bytes, type->length);
		type->type_data.type_info = (void *)lf;
		init_stype_info(&type->type_data);
	} break;
	case eLF_ARRAY:
		PARSE_LF(SLF_ARRAY, lf_array);
		break;
	case eLF_MODIFIER:
		PARSE_LF(SLF_MODIFIER, lf_modifier);
		break;
	case eLF_ARGLIST:
		PARSE_LF(SLF_ARGLIST, lf_arglist);
		break;
	case eLF_MFUNCTION:
		PARSE_LF(SLF_MFUNCTION, lf_mfunction);
		break;
	case eLF_METHODLIST:
		break;
	case eLF_PROCEDURE:
		PARSE_LF(SLF_PROCEDURE, lf_procedure);
		break;
	case eLF_UNION:
		PARSE_LF(SLF_UNION, lf_union);
		break;
	case eLF_BITFIELD:
		PARSE_LF(SLF_BITFIELD, lf_bitfield);
		break;
	case eLF_VTSHAPE:
		PARSE_LF(SLF_VTSHAPE, lf_vtshape);
		break;
	default:
		eprintf("parse_tpi_streams(): unsupported leaf type: 0x%" PFMT32x "\n", type->type_data.leaf_type);
		read_bytes = 0;
		break;
	}

	free(leaf_data);
	return read_bytes;
}

int parse_tpi_stream(void *parsed_pdb_stream, RZ_STREAM_FILE *stream) {
	int i;
	SType *type = 0;
	STpiStream *tpi_stream = (STpiStream *)parsed_pdb_stream;
	tpi_stream->types = rz_list_new();
	p_types_list = tpi_stream->types;

	stream_file_read(stream, sizeof(STPIHeader), (char *)&tpi_stream->header);

	base_idx = tpi_stream->header.idx_begin;

	for (i = tpi_stream->header.idx_begin; i < tpi_stream->header.idx_end; i++) {
		type = (SType *)malloc(sizeof(SType));
		if (!type) {
			return 0;
		}
		type->tpi_idx = i;
		type->type_data.type_info = 0;
		type->type_data.leaf_type = eLF_MAX;
		init_stype_info(&type->type_data);
		if (!parse_tpi_stypes(stream, type)) {
			RZ_FREE(type);
		}
		rz_list_append(tpi_stream->types, type);
	}
	return 1;
}

/**
 * \brief Get SType that matches tpi stream index
 *
 * \param index TPI Stream Index
 */
RZ_API SType *rz_bin_pdb_stype_by_index(ut32 index) {
	if (index == 0) {
		return NULL;
	}

	if (is_simple_type(index)) {
		STypeInfo base_type = parse_simple_type(index);
		SType *base_ret_type = RZ_NEW0(SType);
		if (!base_ret_type) {
			return NULL;
		}
		base_ret_type->tpi_idx = 0;
		base_ret_type->length = 0;
		base_ret_type->type_data = base_type;
		return base_ret_type;
	} else {
		RzListIter *it;
		SType *tp;
		rz_list_foreach (p_types_list, it, tp) {
			if (index == tp->tpi_idx) {
				return tp;
			}
		}
		return NULL;
	}
}

void init_tpi_stream(STpiStream *tpi_stream) {
	tpi_stream->free_ = free_tpi_stream;
}
