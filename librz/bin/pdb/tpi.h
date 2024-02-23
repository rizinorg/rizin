// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_TPI_H
#define PDB_TPI_H

#include <rz_util.h>

RZ_IPI bool tpi_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI RzPdbTpiType *simple_type_parse(RzPdbTpiStream *stream, ut32 idx);
RZ_IPI void tpi_stream_free(RzPdbTpiStream *stream);

/// enumeration for virtual shape table entries
typedef enum {
	VTS_near = 0x00,
	VTS_far = 0x01,
	VTS_thin = 0x02,
	VTS_outer = 0x03,
	VTS_meta = 0x04,
	VTS_near32 = 0x05,
	VTS_far32 = 0x06,
	VTS_unused = 0x07
} TpiCV_VTS_desc;

/// enumeration for LF_LABEL address modes
typedef enum {
	LABEL_NEAR = 0, // near return
	LABEL_FAR = 4 // far return
} TpiCV_LABEL_TYPE;

/// enumeration for HFA kinds
typedef enum {
	CV_HFA_none = 0,
	CV_HFA_float = 1,
	CV_HFA_double = 2,
	CV_HFA_other = 3
} TpiCV_HFA;

/// enumeration for MoCOM UDT kinds
typedef enum CV_MOCOM_UDT_e {
	CV_MOCOM_UDT_none = 0,
	CV_MOCOM_UDT_ref = 1,
	CV_MOCOM_UDT_value = 2,
	CV_MOCOM_UDT_interface = 3
} TpiCV_MOCOM_UDT;

typedef enum {
	DIRECT = 0, // Not a pointer
	NEAR_POINTER = 1, // Near pointer
	FAR_POINTER = 2, // Far pointer
	HUGE_POINTER = 3, // Huge pointer
	NEAR_POINTER32 = 4, // 32 bit near pointer
	FAR_POINTER32 = 5, // 32 bit far pointer
	NEAR_POINTER64 = 6, // 64 bit near pointer
	NEAR_POINTER128 = 7 // 128 bit near pointer
} TpiSimpleTypeMode;

typedef enum {
	PDB_NONE = 0x0000, // uncharacterized type (no type)
	PDB_VOID = 0x0003, // void
	PDB_NOT_TRANSLATED = 0x0007, // type not translated by cvpack
	PDB_HRESULT = 0x0008, // OLE/COM HRESULT

	PDB_SIGNED_CHAR = 0x0010, // 8 bit signed
	PDB_UNSIGNED_CHAR = 0x0020, // 8 bit unsigned
	PDB_NARROW_CHAR = 0x0070, // really a char
	PDB_WIDE_CHAR = 0x0071, // wide char
	PDB_CHAR16 = 0x007a, // char16_t
	PDB_CHAR32 = 0x007b, // char32_t

	PDB_SBYTE = 0x0068, // 8 bit signed int
	PDB_BYTE = 0x0069, // 8 bit unsigned int
	PDB_INT16_SHORT = 0x0011, // 16 bit signed
	PDB_UINT16_SHORT = 0x0021, // 16 bit unsigned
	PDB_INT16 = 0x0072, // 16 bit signed int
	PDB_UINT16 = 0x0073, // 16 bit unsigned int
	PDB_INT32_LONG = 0x0012, // 32 bit signed
	PDB_UINT32_LONG = 0x0022, // 32 bit unsigned
	PDB_INT32 = 0x0074, // 32 bit signed int
	PDB_UINT32 = 0x0075, // 32 bit unsigned int
	PDB_INT64_QUAD = 0x0013, // 64 bit signed
	PDB_UINT64_QUAD = 0x0023, // 64 bit unsigned
	PDB_INT64 = 0x0076, // 64 bit signed int
	PDB_UINT64 = 0x0077, // 64 bit unsigned int
	PDB_INT128_OCT = 0x0014, // 128 bit signed int
	PDB_UINT128_OCT = 0x0024, // 128 bit unsigned int
	PDB_INT128 = 0x0078, // 128 bit signed int
	PDB_UINT128 = 0x0079, // 128 bit unsigned int

	PDB_FLOAT16 = 0x0046, // 16 bit real
	PDB_FLOAT32 = 0x0040, // 32 bit real
	PDB_FLOAT32_PP = 0x0045, // 32 bit PP (partial precision) real
	PDB_FLOAT48 = 0x0044, // 48 bit real
	PDB_FLOAT64 = 0x0041, // 64 bit real
	PDB_FLOAT80 = 0x0042, // 80 bit real
	PDB_FLOAT128 = 0x0043, // 128 bit real

	PDB_COMPLEX16 = 0x0056, // 16 bit complex
	PDB_COMPLEX32 = 0x0050, // 32 bit complex
	PDB_COMPLEX32_PP = 0x0055, // 32 bit PP (partial precision) complex
	PDB_COMPLEX48 = 0x0054, // 48 bit complex
	PDB_COMPLEX64 = 0x0051, // 64 bit complex
	PDB_COMPLEX80 = 0x0052, // 80 bit complex
	PDB_COMPLEX128 = 0x0053, // 128 bit complex

	PDB_BOOL8 = 0x0030, // 8 bit boolean
	PDB_BOOL16 = 0x0031, // 16 bit boolean
	PDB_BOOL32 = 0x0032, // 32 bit boolean
	PDB_BOOL64 = 0x0033, // 64 bit boolean
	PDB_BOOL128 = 0x0034, // 128 bit boolean
} TpiSimpleTypeKind;

typedef enum {
	LF_MODIFIER_16t = 0x0001, // type record for a generalized built-in type modifier
	LF_POINTER_16t = 0x0002,
	LF_ARRAY_16t = 0x0003, // type record for basic array
	LF_CLASS_16t = 0x0004,
	LF_STRUCTURE_16t = 0x0005,
	LF_UNION_16t = 0x0006,
	LF_ENUM_16t = 0x0007, // type record for LF_ENUM
	LF_PROCEDURE_16t = 0x0008, // Type record for LF_PROCEDURE
	LF_MFUNCTION_16t = 0x0009, // Type record for member function
	LF_VTSHAPE = 0x000A, // type record for virtual function table shape
	LF_COBOL0_16t = 0x000B, // type record for cobol0
	LF_COBOL1 = 0x000C, // type record for cobol1
	LF_BARRAY_16t = 0x000D, // type record for basic array
	LF_LABEL = 0x000E,
	LF_NULL = 0x000F,
	LF_NOTTRAN = 0x0010,
	LF_DIMARRAY_16t = 0x0011, // type record for dimensioned arrays
	LF_VFTPATH_16t = 0x0012, // type record describing path to virtual function table
	LF_PRECOMP_16t = 0x0013, // type record describing inclusion of precompiled types
	LF_ENDPRECOMP = 0x0014, // type record describing end of precompiled types that can be
	LF_OEM_16t = 0x0015, // type record for OEM definable type strings
	LF_TYPESERVER_ST = 0x0016, // type record describing using of a type server

	LF_SKIP_16t = 0x0200,
	LF_ARGLIST_16t = 0x0201,
	LF_DEFARG_16t = 0x0202,
	LF_LIST = 0x0203,
	LF_FIELDLIST_16t = 0x0204,
	LF_DERIVED_16t = 0x0205, // derived class list leaf
	LF_BITFIELD_16t = 0x0206, // type record for LF_BITFIELD
	LF_METHODLIST_16t = 0x0207, // type record for non-static methods and friends in overloaded method list
	LF_DIMCONU_16t = 0x0208, // type record for dimensioned array with constant bounds
	LF_DIMCONLU_16t = 0x0209, // type record for dimensioned array with constant bounds
	LF_DIMVARU_16t = 0x020A, // type record for dimensioned array with variable bounds
	LF_DIMVARLU_16t = 0x020B, // type record for dimensioned array with variable bounds
	LF_REFSYM = 0x020C, // type record for referenced symbol

	LF_BCLASS_16t = 0x0400, // subfield record for base class field
	LF_VBCLASS_16t = 0x0401, // subfield record for direct and indirect virtual base class field
	LF_IVBCLASS_16t = 0x0402,
	LF_ENUMERATE_ST = 0x0403, // subfield record for enumerate
	LF_FRIENDFCN_16t = 0x0404, // subfield record for friend function
	LF_INDEX_16t = 0x0405, // index leaf - contains type index of another leaf
	LF_MEMBER_16t = 0x0406,
	LF_STMEMBER_16t = 0x0407,
	LF_METHOD_16t = 0x0408, // subfield record for overloaded method list
	LF_NESTTYPE_16t = 0x0409, // type record for nested (scoped) type definition
	LF_VFUNCTAB_16t = 0x040A, // subfield record for virtual function table pointer
	LF_FRIENDCLS_16t = 0x040B, // subfield record for friend class
	LF_ONEMETHOD_16t = 0x040C, // subfield record for nonoverloaded method
	LF_VFUNCOFF_16t = 0x040D, // subfield record for virtual function table pointer with offset

	LF_TI16_MAX = 0x1000,
	LF_MODIFIER = 0x1001, // type record for a generalized built-in type modifier
	LF_POINTER = 0x1002,
	LF_ARRAY_ST = 0x1003, // type record for basic array
	LF_CLASS_ST = 0x1004,
	LF_STRUCTURE_ST = 0x1005,
	LF_UNION_ST = 0x1006,
	LF_ENUM_ST = 0x1007, // type record for LF_ENUM
	LF_PROCEDURE = 0x1008, // Type record for LF_PROCEDURE
	LF_MFUNCTION = 0x1009, // Type record for member function
	LF_COBOL0 = 0x100A,
	LF_BARRAY = 0x100B, // type record for basic array
	LF_DIMARRAY_ST = 0x100C, // type record for dimensioned arrays
	LF_VFTPATH = 0x100D, // type record describing path to virtual function table
	LF_PRECOMP_ST = 0x100E, // type record describing inclusion of precompiled types
	LF_OEM = 0x100F, // type record for OEM definable type strings
	LF_ALIAS_ST = 0x1010,
	LF_OEM2 = 0x1011, // type record for OEM definable type strings

	LF_SKIP = 0x1200,
	LF_ARGLIST = 0x1201,
	LF_DEFARG_ST = 0x1202,
	LF_FIELDLIST = 0x1203,
	LF_DERIVED = 0x1204, // derived class list leaf
	LF_BITFIELD = 0x1205, // type record for LF_BITFIELD
	LF_METHODLIST = 0x1206, // subfield record for overloaded method list
	LF_DIMCONU = 0x1207, // type record for dimensioned array with constant bounds
	LF_DIMCONLU = 0x1208, // type record for dimensioned array with constant bounds
	LF_DIMVARU = 0x1209, // type record for dimensioned array with variable bounds
	LF_DIMVARLU = 0x120A, // type record for dimensioned array with variable bounds

	LF_BCLASS = 0x1400, // subfield record for base class field
	LF_VBCLASS = 0x1401, // subfield record for direct and indirect virtual base class field
	LF_IVBCLASS = 0x1402,
	LF_FRIENDFCN_ST = 0x1403, // subfield record for friend function
	LF_INDEX = 0x1404,
	LF_MEMBER_ST = 0x1405, // subfield record for non-static data members
	LF_STMEMBER_ST = 0x1406,
	LF_METHOD_ST = 0x1407, // subfield record for overloaded method list
	LF_NESTTYPE_ST = 0x1408, // type record for nested (scoped) type definition
	LF_VFUNCTAB = 0x1409, // subfield record for virtual function table pointer
	LF_FRIENDCLS = 0x140A, //  subfield record for friend class
	LF_ONEMETHOD_ST = 0x140B, // subfield record for nonoverloaded method
	LF_VFUNCOFF = 0x140C, // subfield record for virtual function table pointer with offset
	LF_NESTTYPEEX_ST = 0x140D, // type record for nested (scoped) type definition, with attributes
	LF_MEMBERMODIFY_ST = 0x140E, // type record for modifications to members
	LF_MANAGED_ST = 0x140F,

	LF_ST_MAX = 0x1500,
	LF_TYPESERVER = 0x1501, // type record describing using of a type server
	LF_ENUMERATE = 0x1502, // subfield record for enumerate
	LF_ARRAY = 0x1503, // type record for basic array
	LF_CLASS = 0x1504,
	LF_STRUCTURE = 0x1505,
	LF_UNION = 0x1506,
	LF_ENUM = 0x1507, // type record for LF_ENUM
	LF_DIMARRAY = 0x1508, // type record for dimensioned arrays
	LF_PRECOMP = 0x1509, // type record describing inclusion of precompiled types
	LF_ALIAS = 0x150A,
	LF_DEFARG = 0x150B,
	LF_FRIENDFCN = 0x150C, // subfield record for friend function
	LF_MEMBER = 0x150D, // subfield record for non-static data members
	LF_STMEMBER = 0x150E,
	LF_METHOD = 0x150F, // subfield record for overloaded method list
	LF_NESTTYPE = 0x1510, // type record for nested (scoped) type definition
	LF_ONEMETHOD = 0x1511, // subfield record for nonoverloaded method
	LF_NESTTYPEEX = 0x1512, // type record for nested (scoped) type definition, with attributes
	LF_MEMBERMODIFY = 0x1513, // type record for modifications to members
	LF_MANAGED = 0x1514,
	LF_TYPESERVER2 = 0x1515, // type record describing using of a type server with v7 (GUID) signatures
	LF_STRIDED_ARRAY = 0x1516, // same as LF_ARRAY, but with stride between adjacent elements
	LF_HLSL = 0x1517,
	LF_MODIFIER_EX = 0x1518,
	LF_INTERFACE = 0x1519,
	LF_BINTERFACE = 0x151a,
	LF_VECTOR = 0x151b,
	LF_MATRIX = 0x151c,
	LF_VFTABLE = 0x151d, // a virtual function table
	LF_ENDOFLEAFRECORD = LF_VFTABLE,
	LF_TYPE_LAST, // one greater than the last type record
	LF_TYPE_MAX = LF_TYPE_LAST - 1,

	LF_FUNCTION_ID = 0x1601,
	LF_MEMBER_FUNCTION_ID = 0x1602,
	LF_BUILD_INFO = 0x1603,
	LF_SUBSTRING_LIST = 0x1604,
	LF_STRING_ID = 0x1605,
	LF_USER_DEFINED_TYPE_SOURCE_AND_LINE = 0x1606,
	LF_USER_DEFINED_TYPE_MODULE_SOURCE_AND_LINE = 0x1607,
	LF_CLASS_19 = 0x1608,
	LF_STRUCTURE_19 = 0x1609,
	LF_UNION_19 = 0x160A,
	LF_INTERFACE_19 = 0x160B,
	LF_ID_LAST, // one greater than the last ID record
	LF_ID_MAX = LF_ID_LAST - 1,

	/**     the following are numeric leaves.  They are used to indicate the
	 *      size of the following variable length data.  When the numeric
	 *      data is a single byte less than 0x8000, then the data is output
	 *      directly.  If the data is more the 0x8000 or is a negative value,
	 *      then the data is preceeded by the proper index.
	 */
	LF_NUMERIC = 0x8000,
	LF_CHAR = 0x8000, // signed character leaf
	LF_SHORT = 0x8001, // signed short leaf
	LF_USHORT = 0x8002, // unsigned short leaf
	LF_LONG = 0x8003, // signed long leaf
	LF_ULONG = 0x8004, // unsigned long leaf
	LF_REAL32 = 0x8005, // real 32-bit leaf
	LF_REAL64 = 0x8006, // real 64-bit leaf
	LF_REAL80 = 0x8007, // real 80-bit leaf
	LF_REAL128 = 0x8008, // real 128-bit leaf
	LF_QUADWORD = 0x8009, // signed quad leaf
	LF_UQUADWORD = 0x800A, // unsigned quad leaf
	LF_REAL48 = 0x800B, // real 48-bit leaf
	LF_COMPLEX32 = 0x800C, // complex 32-bit leaf
	LF_COMPLEX64 = 0x800D, // complex 64-bit leaf
	LF_COMPLEX80 = 0x800E, // complex 80-bit leaf
	LF_COMPLEX128 = 0x800F, // complex 128-bit leaf
	LF_VARSTRING = 0x8010, // variable length numeric field
	LF_OCTWORD = 0x8017, // signed int128 leaf
	LF_UOCTWORD = 0x8018, // unsigned int128 leaf
	LF_DECIMAL = 0x8019,
	LF_DATE = 0x801A,
	LF_UTF8STRING = 0x801B,
	LF_REAL16 = 0x801c,

	LF_PAD0 = 0x00F0,
	LF_PAD1 = 0x00F1,
	LF_PAD2 = 0x00F2,
	LF_PAD3 = 0x00F3,
	LF_PAD4 = 0x00F4,
	LF_PAD5 = 0x00F5,
	LF_PAD6 = 0x00F6,
	LF_PAD7 = 0x00F7,
	LF_PAD8 = 0x00F8,
	LF_PAD9 = 0x00F9,
	LF_PAD10 = 0x00FA,
	LF_PAD11 = 0x00FB,
	LF_PAD12 = 0x00FC,
	LF_PAD13 = 0x00FD,
	LF_PAD14 = 0x00FE,
	LF_PAD15 = 0x00FF,
	LF_SIMPLE_TYPE = 0xEFFF, // Custom, hopefully it doesn't collide
	LF_MAX = 0xFFFF
} TpiLeafType;

typedef struct {
	ut16 packed : 1; // true if structure is packed
	ut16 ctor : 1; // true if constructors or destructors present
	ut16 ovlops : 1; // true if overloaded operators present
	ut16 isnested : 1; // true if this is a nested class
	ut16 cnested : 1; // true if this class contains nested types
	ut16 opassign : 1; // true if overloaded assignment (=)
	ut16 opcast : 1; // true if casting methods
	ut16 fwdref : 1; // true if forward reference (incomplete defn)
	ut16 scoped : 1; // scoped definition
	ut16 has_uniquename : 1; // true if there is a decorated name following the regular name
	ut16 sealed : 1; // true if class cannot be used as a base class
	ut16 hfa : 2; // CV_HFA_e
	ut16 intrinsic : 1; // true if class is an intrinsic type (e.g. __m128d)
	ut16 mocom : 2; // CV_MOCOM_UDT_e
} TpiCVProperty;

typedef enum {
	MTvanilla = 0x00,
	MTvirtual = 0x01,
	MTstatic = 0x02,
	MTfriend = 0x03,
	MTintro = 0x04,
	MTpurevirt = 0x05,
	MTpureintro = 0x06,
	MT_MAX
} TpiCVMProp;

typedef enum {
	Private = 1,
	Protected = 2,
	Public = 3,
	AccessMax
} TpiCVAccess;

typedef struct {
	ut16 access : 2; // access protection CV_access_t
	ut16 mprop : 3; // method properties CV_methodprop_t
	ut16 pseudo : 1; // compiler generated fcn and does not exist
	ut16 noinherit : 1; // true if class cannot be inherited
	ut16 noconstruct : 1; // true if class cannot be constructed
	ut16 compgenx : 1; // compiler generated fcn and does exist
	ut16 sealed : 1; // true if method cannot be overridden
	ut16 unused : 6; // unused
} TpiCVFldattr;

typedef struct cv_funcattr {
	RzPdbTpiCallingConvention calling_convention;
	ut8 cxxreturnudt : 1; // true if C++ style ReturnUDT
	ut8 ctor : 1; // true if func is an instance constructor
	ut8 ctorvbase : 1; // true if func is an instance constructor of a class with virtual bases
	ut8 unused : 5; // unused
} TpiCVFuncattr;

typedef struct {
	ut32 return_type;
	TpiCVFuncattr func_attr;
	ut16 parm_count;
	ut32 arg_list;
	ut8 pad;
} Tpi_LF_Procedure;

typedef struct {
	ut32 return_type;
	ut32 class_type;
	ut32 this_type;
	TpiCVFuncattr func_attr;
	ut16 parm_count;
	ut32 arglist;
	st32 this_adjust;
	ut8 pad;
} Tpi_LF_MFcuntion;

typedef struct {
	ut32 count;
	ut32 *arg_type;
	ut8 pad;
} Tpi_LF_Arglist;

typedef struct {
	ut16 const_ : 1;
	ut16 volatile_ : 1;
	ut16 unaligned : 1;
	ut16 unused : 13;
} TpiCVModifier;

typedef struct {
	ut32 modified_type;
	TpiCVModifier umodifier;
	ut8 pad;
} Tpi_LF_Modifier;

typedef enum {
	PTR_MODE_PTR = 0x00000000, // "normal" pointer
	PTR_MODE_LVREF = 0x00000001, // l-value reference
	PTR_MODE_PMEM = 0x00000002, // pointer to data member
	PTR_MODE_PMFUNC = 0x00000003, // pointer to member function
	PTR_MODE_RVREF = 0x00000004, // r-value reference
	PTR_MODE_RESERVED = 0x00000005, // first unused pointer mode
	PTR_MODE_Max
} TpiCVPtrMode;

typedef enum {
	PMTYPE_UNDEFINED = 0x00, // not specified (pre VC8)
	PMTYPE_DATA_SINGLE = 0x01, // member data, single inheritance
	PMTYPE_DATA_MULTIPLE = 0x02, // member data, multiple inheritance
	PMTYPE_DATA_VIRTUAL = 0x03, // member data, virtual inheritance
	PMTYPE_DATA_GENERAL = 0x04, // member data, most general
	PMTYPE_FCN_SINGLE = 0x05, // member function, single inheritance
	PMTYPE_FCN_MULTIPLE = 0x06, // member function, multiple inheritance
	PMTYPE_FCN_VIRTUAL = 0x07, // member function, virtual inheritance
	PMTYPE_FCN_GENERAL = 0x08, // member function, most general
} TpiCVPmType;

typedef enum {
	PTR_NEAR = 0x00000000,
	PTR_FAR = 0x00000001,
	PTR_HUGE = 0x00000002,
	PTR_BASE_SEG = 0x00000003,
	PTR_BASE_VAL = 0x00000004,
	PTR_BASE_SEGVAL = 0x00000005,
	PTR_BASE_ADDR = 0x00000006,
	PTR_BASE_SEGADDR = 0x00000007,
	PTR_BASE_TYPE = 0x00000008,
	PTR_BASE_SELF = 0x00000009,
	PTR_NEAR32 = 0x0000000A,
	PTR_FAR32 = 0x0000000B,
	PTR_64 = 0x0000000C,
	PTR_UNUSEDPTR = 0x0000000D,
	PTR_Max
} TpiCVType;

typedef struct {
	ut32 ptrtype : 5; // ordinal specifying pointer type
	ut32 ptrmode : 3; // ordinal specifying pointer mode
	ut32 flat32 : 1; // true if 0:32 pointer
	ut32 volatile_ : 1; // TRUE if volatile pointer
	ut32 const_ : 1; // TRUE if const pointer
	ut32 unaligned : 1; // TRUE if unaligned pointer
	ut32 restrict_ : 1; // TRUE if restricted pointer (allow agressive opts)
	ut32 size : 6; // size of pointer (in bytes)
	ut32 mocom : 1; // TRUE if it is a MoCOM pointer (^ or %)
	ut32 lref : 1; // TRUE if it is this pointer of member function with & ref-qualifier
	ut32 rref : 1; // TRUE if it is this pointer of member function with && ref-qualifier
	ut32 unused : 10; // pad out to 32-bits for following cv_typ_t's
} TpiCVPointerAttr;

typedef struct {
	ut32 utype;
	TpiCVPointerAttr ptr_attr;
	PDBTypeIndex containing_class;
	ut8 pad;
} Tpi_LF_Pointer;

typedef struct {
	enum {
		TpiVariant_U64,
		TpiVariant_U32,
		TpiVariant_U16,
		TpiVariant_U8,
		TpiVariant_I64,
		TpiVariant_I32,
		TpiVariant_I16,
		TpiVariant_I8,
	} tag;
	union {
		ut64 u64v;
		ut32 u32v;
		ut16 u16v;
		ut8 u8v;
		st64 i64v;
		st32 i32v;
		st16 i16v;
		st8 i8v;
	};
} TpiVariant;

typedef struct {
	ut32 element_type;
	ut32 index_type;
	ut32 stride;
	RzVector /*<ut32>*/ dimensions;
	ut8 pad;
} Tpi_LF_Array;

typedef enum {
	ClassKind_Class,
	ClassKind_Struct,
	ClassKind_Interface
} ClassKind;

typedef struct {
	ut16 count;
	ClassKind kind;
	TpiCVProperty prop; // property attribute field
	ut32 field_list; // type index of LF_FIELD descriptor list
	ut32 derived; // type index of derived from list if not zero
	ut32 vshape; // type index of vshape table for this class
	ut64 size;
	char *name;
	char *mangled_name;
	ut8 pad;
} Tpi_LF_Structure, Tpi_LF_Class;

typedef struct {
	ut16 count;
	TpiCVProperty prop;
	ut32 field_list;
	ut64 size;
	char *name;
	char *mangled_name;
	ut32 pad;
} Tpi_LF_Union;

typedef struct {
	ut32 base_type;
	ut8 length;
	ut8 position;
	ut8 pad;
} Tpi_LF_Bitfield;

typedef struct {
	ut16 count;
	RzVector /*<ut8>*/ descriptors;
	ut8 pad;
} Tpi_LF_Vtshape;

/// type record for a virtual function table
typedef struct {
	ut16 leaf; // LF_VFTABLE
	TpiCVType complete_class; // class/structure that owns the vftable
	TpiCVType override_vftable; // vftable from which this vftable is derived
	ut32 vfptr_offset; // offset of the vfptr to this table, relative to the start of the object layout.
	RzPVector /*<char *>*/ method_names; // array of names.
					     // The first is the name of the vtable.
					     // The others are the names of the methods.
} Tpi_LF_Vftable;

// LF_LABEL
typedef struct {
	TpiCV_LABEL_TYPE mode;
} Tpi_LF_Label;

typedef struct {
	ut16 count;
	TpiCVProperty prop;
	ut32 utype;
	ut32 field_list;
	char *name;
	char *mangled_name;
	ut8 pad;
} Tpi_LF_Enum;

typedef struct {
	TpiCVFldattr fldattr;
	TpiVariant value;
	char *name;
	ut8 pad;
} Tpi_LF_Enumerate;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 index;
	char *name;
} Tpi_LF_NestType;

typedef struct {
	ut16 pad;
	ut32 index;
} Tpi_LF_VFuncTab;

typedef struct {
	ut16 count;
	ut32 mlist;
	char *name;
	ut8 pad;
} Tpi_LF_Method;

typedef struct {
	TpiCVFldattr fldattr;
	ut16 pad;
	ut32 type;
	ut32 optional_offset;
} Tpi_Type_MethodListMember;

typedef struct {
	RzPVector /*<Tpi_Type_MethodListMember *>*/ members;
} Tpi_LF_MethodList;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 field_type;
	ut64 offset;
	char *name;
	ut8 pad;
} Tpi_LF_Member;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 field_type;
	char *name;
	ut8 pad;
} Tpi_LF_StaticMember;

typedef struct {
	ut16 leaf;
	ut16 pad0;
	ut32 index;
} Tpi_LF_Index;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 index;
	ut32 offset_in_vtable;
	char *name;
	ut8 pad;
} Tpi_LF_OneMethod;

typedef struct {
	ClassKind kind;
	TpiCVFldattr fldattr;
	ut32 index;
	ut64 offset;
	ut8 pad;
} Tpi_LF_BClass;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 direct_vbclass_idx;
	ut32 vb_pointer_idx;
	ut64 vb_pointer_offset;
	ut64 vb_offset_from_vbtable;
} Tpi_LF_VBClass, Tpi_LF_IVBClass;

typedef struct {
	RzPVector /*<RzPdbTpiType *>*/ *substructs;
} Tpi_LF_FieldList;

typedef struct {
	ut32 size;
	char *type;
} Tpi_LF_SimpleType;

#endif
