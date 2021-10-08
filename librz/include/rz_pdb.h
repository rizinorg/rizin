// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_H
#define PDB_H

#include <rz_util.h>
#include <rz_type.h>
#include <rz_cmd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PDB_SIGNATURE     "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
#define PDB_SIGNATURE_LEN 32

#define GET_BF(value, start, len) (((value) >> (start)) & ((1 << len) - 1))

// DBI
enum dbi_stream_version {
	DSV_VC41 = 930803,
	DSV_V50 = 19960307,
	DSV_V60 = 19970606,
	DSV_V70 = 19990903,
	DSV_V110 = 20091201
};

typedef struct dbi_stream_header_t {
	st32 version_signature;
	ut32 version_header;
	ut32 age;
	ut16 global_stream_index;
	ut16 build_number;
	ut16 public_stream_index;
	ut16 pdb_dll_version;
	ut16 sym_record_stream;
	ut16 pdb_dll_rbld;
	ut32 mod_info_size;
	ut32 section_contribution_size;
	ut32 section_map_size;
	ut32 source_info_size;
	ut32 type_server_map_size;
	ut32 mfc_type_server_index;
	ut32 optional_dbg_header_size;
	ut32 ec_substream_size;
	ut16 flags;
	ut16 machine;
	ut32 padding;
} DbiStreamHdr;

typedef struct SectionContribEntry {
	ut16 Section;
	char Padding1[2];
	st32 Offset;
	st32 Size;
	ut32 Characteristics;
	ut16 ModuleIndex;
	char Padding2[2];
	ut32 DataCrc;
	ut32 RelocCrc;
} SectionContr;

typedef struct dbi_stream_ex_header_t {
	ut32 unknown;
	SectionContr sec_con;
	ut16 Flags;
	ut16 ModuleSymStream;
	ut32 SymByteSize;
	ut32 C11ByteSize;
	ut32 C13ByteSize;
	ut16 SourceFileCount;
	char Padding[2];
	ut32 Unused2;
	ut32 SourceFileNameIndex;
	ut32 PdbFilePathNameIndex;
	char *ModuleName;
	char *ObjFileName;
} DbiStreamExHdr;

typedef struct {
	st16 sn_fpo;
	st16 sn_exception;
	st16 sn_fixup;
	st16 sn_omap_to_src;
	st16 sn_omap_from_src;
	st16 sn_section_hdr;
	st16 sn_token_rid_map;
	st16 sn_xdata;
	st16 sn_pdata;
	st16 sn_new_fpo;
	st16 sn_section_hdr_orig;
} DbiStreamDbgHeader;

typedef struct dbi_stream_t {
	DbiStreamHdr hdr;
	RzList /* DbiStreamExHdr */ *ex_hdrs;
	DbiStreamDbgHeader dbg_hdr;

} DbiStream;

// GDATA
typedef struct {
	ut16 leaf_type;
	ut32 symtype;
	ut32 offset;
	ut16 segment;
	char *name;
	ut8 name_len;
} GDataGlobal;

typedef struct {
	RzList /* GDataGlobal */ *global_list;
} GDataStream;

// OMAP
typedef struct {
	ut32 from;
	ut32 to;
} OmapEntry;

typedef struct
{
	RzList /* OmapEntry */ *entries;
	ut32 *froms;
} OmapStream;

// PE Stream
typedef union {
	ut32 physical_address;
	ut32 virtual_address;
} PeMisc;

#define PDB_SIZEOF_SECTION_NAME 8

typedef struct {
	char name[8];
	PeMisc misc;
	ut32 virtual_address;
	ut32 size_of_raw_data;
	ut32 pointer_to_raw_data;
	ut32 pointer_to_relocations;
	ut32 pointer_to_line_numbers;
	ut16 number_of_relocations;
	ut16 number_of_line_numbers;
	ut32 charactestics;
} PeImageSectionHeader;

typedef struct {
	RzList /* PeImageSectionHeader */ *sections_hdrs;
} PeStream;

// TPI
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
	NEAR_C = 0x00000000,
	FAR_C = 0x00000001,
	NEAR_PASCAL = 0x00000002,
	FAR_PASCAL = 0x00000003,
	NEAR_FAST = 0x00000004,
	FAR_FAST = 0x00000005,
	SKIPPED = 0x00000006,
	NEAR_STD = 0x00000007,
	FAR_STD = 0x00000008,
	NEAR_SYS = 0x00000009,
	FAR_SYS = 0x0000000A,
	THISCALL = 0x0000000B,
	MIPSCALL = 0x0000000C,
	GENERIC = 0x0000000D,
	ALPHACALL = 0x0000000E,
	PPCCALL = 0x0000000F,
	SHCALL = 0x00000010,
	ARMCALL = 0x00000011,
	AM33CALL = 0x00000012,
	TRICALL = 0x00000013,
	SH5CALL = 0x00000014,
	M32RCALL = 0x00000015,
	CLRCALL = 0x00000016,
	INLINECALL = 0x00000017,
	NEAR_VEC = 0X00000018,
	RESERVED = 0x00000019,
	MAX_CV_CALL
} TpiCallingConvention;

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
	LF_FUNCTION_ID = 0x1601,
	LF_MEMBER_FUNCTION_ID = 0x1602,
	LF_BUILD_INFO = 0x1603,
	LF_SUBSTRING_LIST = 0x1604,
	LF_STRING_ID = 0x1605,
	LF_USER_DEFINED_TYPE_SOURCE_AND_LINE = 0x1606,
	LF_USER_DEFINED_TYPE_MODULE_SOURCE_AND_LINE = 0x1607,
	LF_CLASS_19 = 0x1608,
	LF_STRUCTURE_19 = 0x1609,

	/**     the following are numeric leaves.  They are used to indicate the
	*      size of the following variable length data.  When the numeric
	*      data is a single byte less than 0x8000, then the data is output
	*      directly.  If the data is more the 0x8000 or is a negative value,
	*      then the data is preceeded by the proper index.
	*/
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

typedef union {
	struct {
		ut16 packed : 1; // true if structure is packed
		ut16 ctor : 1; // true if constructors or destructors present
		ut16 ovlops : 1; // true if overloaded operators present
		ut16 isnested : 1; // true if this is a nested class
		ut16 cnested : 1; // true if this class contains nested types
		ut16 opassign : 1; // true if overloaded assignment (=)
		ut16 opcast : 1; // true if casting methods
		ut16 fwdref : 1; // true if forward reference (incomplete defn)
		ut16 scoped : 1; // scoped definition
		ut16 hasuniquename : 1; // true if there is a decorated name following the regular name
		ut16 sealed : 1; // true if class cannot be used as a base class
		ut16 hfa : 2; // CV_HFA_e
		ut16 intrinsic : 1; // true if class is an intrinsic type (e.g. __m128d)
		ut16 mocom : 2; // CV_MOCOM_UDT_e
	} bits;
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

typedef union {
	struct {
		ut16 access : 2; // access protection CV_access_t
		ut16 mprop : 3; // method properties CV_methodprop_t
		ut16 pseudo : 1; // compiler generated fcn and does not exist
		ut16 noinherit : 1; // true if class cannot be inherited
		ut16 noconstruct : 1; // true if class cannot be constructed
		ut16 compgenx : 1; // compiler generated fcn and does exist
		ut16 sealed : 1; // true if method cannot be overridden
		ut16 unused : 6; // unused
	} bits;
} TpiCVFldattr;

typedef union {
	struct cv_funcattr {
		unsigned char cxxreturnudt : 1; // true if C++ style ReturnUDT
		unsigned char ctor : 1; // true if func is an instance constructor
		unsigned char ctorvbase : 1; // true if func is an instance constructor of a class with virtual bases
		unsigned char unused : 5; // unused
	} bits;
} TpiCVFuncattr;

typedef struct {
	ut32 return_type;
	TpiCallingConvention call_conv;
	TpiCVFuncattr func_attr;
	ut16 parm_count;
	ut32 arg_list;
	ut8 pad;
} Tpi_LF_Procedure;

typedef struct {
	ut32 return_type;
	ut32 class_type;
	ut32 this_type;
	TpiCallingConvention call_conv; // 1 byte
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

typedef union {
	struct {
		ut16 const_ : 1;
		ut16 volatile_ : 1;
		ut16 unaligned : 1;
		ut16 unused : 13;
	} bits;
} TpiCVModifier;

typedef struct {
	ut32 modified_type;
	TpiCVModifier umodifier;
	ut8 pad;
} Tpi_LF_Modifier;

typedef enum {
	PTR_MODE_PTR = 0x00000000,
	PTR_MODE_REF = 0x00000001,
	PTR_MODE_PMEM = 0x00000002,
	PTR_MODE_PMFUNC = 0x00000003,
	PTR_MODE_RESERVED = 0x00000004,
	ModeMax
} TpiCVMode;

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
	TypeMax
} TpiCVType;

typedef union {
	struct {
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
	} bits;
} TpiCVPointerAttr;

typedef struct {
	ut32 utype;
	TpiCVPointerAttr ptr_attr;
	ut8 pad;
} Tpi_LF_Pointer;

typedef struct {
	char *name;
	ut32 size;
} Tpi_Type_String;

typedef struct {
	ut16 type_index;
	void *data;
	bool is_integer;
} Tpi_Type_Numeric;

typedef struct {
	ut32 element_type;
	ut32 index_type;
	Tpi_Type_Numeric size;
	Tpi_Type_String name;
	ut8 pad;
} Tpi_LF_Array;

typedef struct {
	ut16 count;
	TpiCVProperty prop; // property attribute field
	ut32 field_list; // type index of LF_FIELD descriptor list
	ut32 derived; // type index of derived from list if not zero
	ut32 vshape; // type index of vshape table for this class
	Tpi_Type_Numeric size;
	Tpi_Type_String name;
	Tpi_Type_String mangled_name;
	ut8 pad;
} Tpi_LF_Structure, Tpi_LF_Class;

typedef struct {
	TpiCVProperty prop; // property attribute field
	ut16 unknown;
	ut32 field_list; // type index of LF_FIELD descriptor list
	ut32 derived; // type index of derived from list if not zero
	ut32 vshape; // type index of vshape table for this class
	Tpi_Type_Numeric unknown1;
	Tpi_Type_Numeric size;
	Tpi_Type_String name;
	Tpi_Type_String mangled_name;
	ut8 pad;
} Tpi_LF_Structure_19, Tpi_LF_Class_19;

typedef struct {
	ut16 count;
	TpiCVProperty prop;
	ut32 field_list;
	Tpi_Type_Numeric size;
	Tpi_Type_String name;
	Tpi_Type_String mangled_name;
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
	char *vt_descriptors;
	ut8 pad;
} Tpi_LF_Vtshape;

typedef struct {
	ut16 count;
	TpiCVProperty prop;
	ut32 utype;
	ut32 field_list;
	Tpi_Type_String name;
	Tpi_Type_String mangled_name;
	ut8 pad;
} Tpi_LF_Enum;

typedef struct {
	TpiCVFldattr fldattr;
	Tpi_Type_Numeric enum_value;
	Tpi_Type_String name;
	ut8 pad;
} Tpi_LF_Enumerate;

typedef struct {
	ut16 pad;
	ut32 index;
	Tpi_Type_String name;
} Tpi_LF_NestType;

typedef struct {
	ut16 pad;
	ut32 index;
} Tpi_LF_VFuncTab;

typedef struct {
	ut16 count;
	ut32 mlist;
	Tpi_Type_String name;
	ut8 pad;
} Tpi_LF_Method;

typedef struct {
	TpiCVFldattr fldattr;
	ut16 pad;
	ut32 type;
	ut32 optional_offset;
} Tpi_Type_MethodListMember;

typedef struct {
	RzList /* Tpi_Type_MethodListMember */ *members;
} Tpi_LF_MethodList;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 index;
	Tpi_Type_Numeric offset;
	Tpi_Type_String name;
	ut8 pad;
} Tpi_LF_Member;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 index;
	Tpi_Type_String name;
	ut8 pad;
} Tpi_LF_StaticMember;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 index;
	ut32 offset_in_vtable;
	Tpi_Type_String name;
	ut8 pad;
} Tpi_LF_OneMethod;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 index;
	Tpi_Type_Numeric offset;
	ut8 pad;
} Tpi_LF_BClass;

typedef struct {
	TpiCVFldattr fldattr;
	ut32 direct_vbclass_idx;
	ut32 vb_pointer_idx;
	Tpi_Type_Numeric vb_pointer_offset;
	Tpi_Type_Numeric vb_offset_from_vbtable;
} Tpi_LF_VBClass, Tpi_LF_IVBClass;

typedef struct {
	RzList /* TpiType */ *substructs;
} Tpi_LF_FieldList;

typedef struct {
	ut32 size;
	char *type;
} Tpi_LF_SimpleType;

typedef enum {
	V40 = 19950410,
	V41 = 19951122,
	V50 = 19961031,
	V70 = 19990903,
	V80 = 20040203,
} Tpi_Stream_Version;

typedef struct tpi_stream_header_t {
	Tpi_Stream_Version Version;
	ut32 HeaderSize;
	ut32 TypeIndexBegin;
	ut32 TypeIndexEnd;
	ut32 TypeRecordBytes;

	ut16 HashStreamIndex;
	ut16 HashAuxStreamIndex;
	ut32 HashKeySize;
	ut32 NumHashBuckets;

	st32 HashValueBufferOffset;
	ut32 HashValueBufferLength;

	st32 IndexOffsetBufferOffset;
	ut32 IndexOffsetBufferLength;

	st32 HashAdjBufferOffset;
	ut32 HashAdjBufferLength;
} TpiStreamHeader;

typedef struct tpi_types {
	RBNode rb;
	ut32 type_index;
	ut16 leaf_type;
	ut16 length;
	void *type_data;
} TpiType;

typedef struct tpi_stream_t {
	TpiStreamHeader header;
	RBTree types;
	ut64 type_index_base;
	RzList /* RzBaseType */ *print_type;
} TpiStream;

// PDB
typedef enum pdb_stream_index_t {
	PDB_STREAM_ROOT = 0, // PDB_ROOT_DIRECTORY
	PDB_STREAM_PDB, // PDB STREAM INFO
	PDB_STREAM_TPI, // TYPE INFO
	PDB_STREAM_DBI, // DEBUG INFO

	PDB_STREAM_GSYM,
	PDB_STREAM_SECT_HDR,
	PDB_STREAM_SECT__HDR_ORIG,
	PDB_STREAM_OMAP_TO_SRC,
	PDB_STREAM_OMAP_FROM_SRC,
	PDB_STREAM_FPO,
	PDB_STREAM_FPO_NEW,
	PDB_STREAM_XDATA,
	PDB_STREAM_PDATA,
	PDB_STREAM_TOKEN_RID_MAP,
	PDB_STREAM_MAX
} PDBStreamIndex;

enum pdb_stream_version {
	VC2 = 19941610,
	VC4 = 19950623,
	VC41 = 19950814,
	VC50 = 19960307,
	VC98 = 19970604,
	VC70Dep = 19990604,
	VC70 = 20000404,
	VC80 = 20030901,
	VC110 = 20091201,
	VC140 = 20140508,
};

typedef struct {
	ut32 data1;
	ut16 data2;
	ut16 data3;
	ut8 data4[8];
} pdb_guid;

typedef struct {
	ut32 version;
	ut32 signature;
	ut32 age;
	pdb_guid unique_id;
} pdb_stream_header;

typedef struct {
	pdb_stream_header hdr;
	/* Todo: parse named table */
} PdbStream;

/**
 * \brief MSF file format header https://llvm.org/docs/PDB/MsfFile.html#the-superblock
 */
typedef struct {
	char file_magic[PDB_SIGNATURE_LEN]; ///< Must be equal to "Microsoft C / C++ MSF 7.00\\r\\n" followed by the bytes 1A 44 53 00 00 00.
	ut32 block_size; ///< The block size of the internal file system.
	ut32 free_block_map_block; ///< The index of a block within the file, the data within that block is not used.
	ut32 num_blocks; ///< The total number of blocks in the file
	ut32 num_directory_bytes; ///< The size of the stream directory, in bytes.
	ut32 unknown;
	ut32 block_map_addr; ///< The index of a block within the MSF file.
} MsfSuperBlock;

typedef struct {
	ut32 stream_idx;
	ut32 stream_size;
	ut32 blocks_num;
	RzBuffer *stream_data;
} MsfStream;

typedef struct {
	ut32 NumStreams;
	ut32 *StreamSizes;
	RzBuffer *sd;
} MsfStreamDirectory;

typedef struct rz_pdb_t {
	RzBuffer *buf; // mmap of file
	MsfSuperBlock *super_block;
	RzList /* MsfStream */ *streams;
	PdbStream *s_pdb;
	DbiStream *s_dbi;
	TpiStream *s_tpi;
	GDataStream *s_gdata;
	OmapStream *s_omap;
	PeStream *s_pe;
} RzPdb;

// PDB
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_file(RZ_NONNULL const char *filename);
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_buf(RZ_NONNULL const RzBuffer *buf);
RZ_API RZ_OWN char *rz_bin_pdb_types_as_string(RZ_NONNULL const RzTypeDB *db, RZ_NONNULL const RzPdb *pdb, const RzCmdStateOutput *state);
RZ_API RZ_OWN char *rz_bin_pdb_gvars_as_string(RZ_NONNULL const RzPdb *pdb, const ut64 img_base, const RzCmdStateOutput *state);
RZ_API RZ_OWN char *rz_bin_pdb_gvars_as_cmd_string(RZ_NONNULL const RzPdb *pdb, const ut64 img_base);
RZ_API void rz_bin_pdb_free(RzPdb *pdb);

// TPI
RZ_API RZ_BORROW TpiType *rz_bin_pdb_get_type_by_index(RZ_NONNULL TpiStream *stream, ut32 index);
RZ_API RZ_OWN char *rz_bin_pdb_calling_convention_as_string(RZ_NONNULL TpiCallingConvention idx);
RZ_API bool rz_bin_pdb_type_is_fwdref(RZ_NONNULL TpiType *t);
RZ_API RZ_BORROW RzList *rz_bin_pdb_get_type_members(RZ_NONNULL TpiStream *stream, TpiType *t);
RZ_API RZ_BORROW char *rz_bin_pdb_get_type_name(RZ_NONNULL TpiType *type);
RZ_API ut64 rz_bin_pdb_get_type_val(RZ_NONNULL TpiType *type);

#ifdef __cplusplus
}
#endif

#endif