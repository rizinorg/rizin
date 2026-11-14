// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMF166_H
#define OMF166_H

#include "rz_type.h"
#include "omf/omf_common.h"
#include "c166/c166_raw.h"

#define FINAL_TYPE 0x00

/**
 * <b>COMPONENT-LIST Descriptor</b><br>
 *	Specifies the number of components (NrOfComp16). Used in function and
 *	structure types.
 *
 * 	\code 0x20 | NrOfComp16 | Components [*] \endcode
 *
 * 	Each <b>component</b> is described as follows:
 *
 * 	\code TI16 | OFFS32 | REP8 | POS8 | n,’name’ \endcode
 *
 * 	<b>TI16</b>: members type index<br>
 * 	<b>OFFS32</b>: members offset<br>
 * 	<b>REP8</b>: relevant on function parameter lists, otherwise REP8 and POS8 will be zero.<br>
 * 	<b>NAME</b>: member name in OMF166 name format<br>
 * 	<b>POS8</b>: contains a bit position if REP8 contains method 1 (RegBit)
 *
 * 	The possible values for REP8 are as follows:<br>
 * 	    1: RegBit, POS8=BitPos (0-15), OFFS32=RWn (0-15)<br>
 * 	    2: StackVar (auto/parameter) OFFS32=StackOffs ([R0+#n])<br>
 * 	    3: RegVar (auto/parameter) OFFS32=RWn (0-15)
 *
 * 	    The register number ’RWn’ is contained in OFFS32, which is actually
 * 	    interpreted as a 16 bit word. The value 0 represents R0, 1 R1 and so on.
 */
#define COMPONENT_LIST_DESCRIPTOR 0x20

/**
 *	<b>POINTER Descriptor</b><br>
 *	The Pointer descriptor is used to describe the type which a pointer refers
 *	to and specific attributes of the pointer:
 *
 * 	\code 0x21 | SIZE8 | ATTRIB8 | RESERVED16 | TI16 \endcode
 *
 * 	<b>SIZE8</b>: the size of the pointer (either 16 or 32 bits)<br>
 * 	<b>ATTRIB8</b>: The ATTRIB8 byte defines the interpretation of a pointer.
 * 	Data pointers use the PAG:POF convention, where PAG is the page number of
 * 	a physical 16k page and POF is the offset within the page.
 * 	Function pointers use the SEG:SOF convention which specifies the 64k
 * 	segment (SEG) and a segment-offset (SOF).
 * 	Huge pointers use linear addressing undergoing the paged addressing scheme
 * 	of the 80C166 CPU.<br>
 * 	<b>RESERVED16</b>: reserved, set to zero.<br>
 * 	<b>TI16</b>: reference to referred type.
 *
 * 	The possible values for ATTRIB8 are as follows:<br>
 * 	    1 = Data pointer (PAGE:OFFSET)<br>
 * 	    2 = Function pointer (SEG:OFFSET)<br>
 * 	    4 = Huge pointer (linear 32-Bit)<br>
 * 	    8 = Xhuge pointer (linear 32-Bit)
 *
 * 	The TI16 refers to the final type or another type record. For example,
 * 	if TI16 contains 0x4A, which is the type ’void’, then the meaning
 * 	is \code void * \endcode. The SIZE8 specifier will define further details of
 * 	the type, for example \code void near * \endcode or \code void far * \endcode.
 */
#define POINTER_DESCRIPTOR 0x21

/**
 *	<b>ARRAY Descriptor</b><br>
 *	An Array descriptor is used to describe array types:
 *
 * 	\code 0x22 | DIMS8 | ATTRIB8 | TI16 | DIMSZ32 [*] \endcode
 *
 * 	<b>DIMS8</b>: number of array dimensions<br>
 * 	<b>ATTRIB8</b>: values below<br>
 * 	<b>TI16</b>: refers to the type which the array consist of<br>
 * 	<b>DIMSZ32</b>: the dimension size of each dimension
 *
 * 	The possible values for <b>ATTRIB8</b> are as follows:<br>
 * 	    1 = Huge-Array (0 ... 64K)<br>
 * 	    2 = Xhuge-Array (0 ... 16MByte)
 *
 * 	The <b>DIMSZ32</b> field contains ’DIMSZ8’ repeated sizes of the dimensions.
 * 	A special case is a <b>DIMSZ32</b> field containing -1L, which specifies an array
 * 	dimension of unknown size. This may be the case on external arrays when the
 * 	size is not known to the translator.
 *
 * 	<b>Example:</b> <br> the array declaration \code’int array [5][3][2];’\endcode creates the type<br>
 * 	\code  	| 0x22 | 3 | 0 | 0x44 | 5 | 3 | 2 | \endcode
 *
 * 	<b>Hint for the Linker:</b><br>
 * 	The declaration \code extern char array[];\endcode
 * 	creates the type descriptor \code 0x22,1,0,0x42,-1L \endcode
 *
 * 	The linker should replace the incomplete type by the type of the corresponding
 * 	PUBDEF/GLBDEF symbol which represents the exact type of the array. Since
 * 	one of the input modules to the linker must have the complete type, the final
 * 	output module from the linker should not contain any incomplete types.
 */
#define ARRAY_DESCRIPTOR 0x22

/**
 *	<b>FUNCTION Descriptor</b><br>
 *	A Function type descriptor is used to describe a function return
 *	type and the types of the parameters of the function:
 *
 * 	\code 0x23 | ATTRIB8 | RTYPE-TI16 | PARMLIST-TI16 \endcode
 *
 * 	<b>ATTRIB8</b>: values below<br>
 * 	<b>RTYPE-TI</b>: TypeIndex of the function return type<br>
 * 	<b>PARMLIST-TI</b>: TypeIndex of the parameter list (a component list)<br>
 *
 * 	The possible values for <b>ATTRIB8</b> are as follows:<br>
 * 	    1 = Near-Function<br>
 * 	    2 = Far-Function
 *
 * 	Functions without parameters and with return type int/uint/void will not
 * 	create a function type descriptor at all. Such functions will be
 * 	represented by a TI value of 0x4B which means ’label’.
 *
 * 	The intention of this short form is to avoid unnecessary descriptors with
 * 	almost no information. This has no impact on local variables of such a function.
 *
 *	The following two examples show the case when the short form is used:<br>
 *	\code int test () { ... } // no params \endcode<br>
 *	\code int test (void) { ... } // no params \endcode
 */
#define FUNCTION_DESCRIPTOR 0x23

/**
 *	<b>STRUCT/UNION Descriptor</b><br>
 *	The Struct/Union descriptor is used to describes the details of structure
 *	and unions:
 *
 * 	\code 0x24 | ATTRIB8 | SIZE32 | MEMBER-TI16 | tagname \endcode
 *
 * 	<b>ATTRIB8</b>: 1 = struct, 2 = union<br>
 * 	<b>SIZE32</b>: sizeof struct or union<br>
 * 	<b>MEMBER-TI16</b>: reference to component list or <void><br>
 * 	<b>tagname</b>: struct/union-tag name in OMF166 name format
 *
 * 	The member TI may be void on structures or unions which do not have defined
 * 	the members. Such a descriptor should be replaced by the linker with the
 * 	complete type which is probably defined in another module.
 */
#define STRUCT_UNION_DESCRIPTOR 0x24

/**
 *	<b>BITFIELD Descriptor</b><br>
 *	The Bitfield descriptor is used to describe ANSI-C style bit fields:
 *
 * 	\code 0x25 | TI16 | OFFSET8 | WIDTH8 \endcode
 *
 * 	<b>TI16</b>: base scalar type of the field [uchar, uint, long ]<br>
 * 	<b>OFFSET8</b>: field offset in base scalar in bits<br>
 * 	<b>WIDTH8</b>: field width in bits
 *
 * 	The member TI may be void on structures or unions which do not have defined
 * 	the members. Such a descriptor should be replaced by the linker with the
 * 	complete type which is probably defined in another module.
 */
#define BITFIELD_DESCRIPTOR 0x25

/**
 * \brief REP8[6-4] in LOCSYM record, these three bits encode the representation
 * type of the Offset16 field as follows:
 */
typedef enum omf_sym_rep_t {
	REP_BIT = 0, ///< the symbol is a bit symbol.
	/**
	 * The ’bpos’ field contains the position of the bit in the bitaddressable word.
	 * If V=1, then the Offset16 field specifies a register (0=R0, 1=R1, 15=R15).
	 */
	REP_VAR = 1, ///< the symbol is a variable, whose type is specified with the type index.
	REP_LAB = 2, ///< the symbol represents a label or procedure.
	REP_REGBANK = 3, ///< the symbol represents the name of a register bank.
			 ///< ’Offset16’ is an address relative to segment zero.
	REP_INTNO = 4, ///< the symbol represents a symbolic interrupt number.
		       ///< ’Offset16’ is the absolute interrupt number
	REP_CONST = 5, ///< the symbol represents the numeric constant given by Offset16.
	REP_REGVAR = 6, ///< the symbol represents a register variable.
	/**
	 * The register number is defined by the Offset16 field. The type of the variable given
	 * by TypeIndex decides the interpretation of the register number (WORD or BYTE register).
	 */
	REP_AUTO = 7, ///< the symbol represents a an automatic variable, which are located on the stack.
		      ///< Automatics are relative to R0 with an offset given by Offset16 [R0+Offset16]).
} OMF_SYM_REP;

/**
 * \brief iTyp in DEPLST record, specifies the type of the dependency descriptor
 */
typedef enum omf_ityp_t {
	ITYP_OUTPUTFILE = 0x00, ///< Outputfile descriptor.
	/**
	 * Specifies path and name of the output file
	 * created by a translator or linker
	 */
	ITYP_INPUTFILE = 0x01, ///< Inputfile descriptor.
	/**
	 * Specifies path and name of the input file to the translator.
	 */
	ITYP_INCLUDEFILE = 0x02, ///< Includefile descriptor.
	/**
	 * If the Input file contains more than one include file,
	 * then each include file is listed with an iTyp_2 descriptor.
	 */
	ITYP_COMMANDFILE = 0x03, ///< Commandfile descriptor.
	/**
	 * Used when \@file was given in the invocation line.
	 */
	ITYP_OBJECT_INPUTFILE = 0x04, ///< Object-Inputfile descriptor.
	/**
	 * Used to specify an object file as input for L166.
	 */
	ITYP_INVOCATION_LINE = 0xFF, ///< Invocation Line descriptor.
	/**
	 * Contains the invocation line to the translator
	 * including all invocation controls.
	 */
} OMF_ITYP;

typedef enum {
	C166_CLASS_ICODE,
	C166_CLASS_FCODE,
	C166_CLASS_FCONST,
	C166_CLASS_HCONST,
	C166_CLASS_XCONST,
	C166_CLASS_SDATA,
	C166_CLASS_SDATA0,
	C166_CLASS_IDATA,
	C166_CLASS_IDATA0,
	C166_CLASS_FDATA,
	C166_CLASS_FDATA0,
	C166_CLASS_HDATA,
	C166_CLASS_HDATA0,
	C166_CLASS_XDATA,
	C166_CLASS_XDATA0,
	C166_CLASS_NDATA,
	C166_CLASS_NDATA0,
	C166_CLASS_NCONST,
	C166_CLASS_NCODE,
	C166_CLASS_BIT,
	C166_CLASS_BIT0,
	C166_CLASS_BDATA,
	C166_CLASS_BDATA0,
	C166_CLASS_EBDATA,
	C166_CLASS_EBDATA0,
} c166_class_t;

/**
 * \brief OMF_SEC_TYPE in SECDEF record, specifies the type of the section
 */
typedef enum omf_sec_t {
	OMF_SEC_TYPE_BIT = 0x00, ///< BIT.
	OMF_SEC_TYPE_DATA = 0x01, ///< DATA.
	OMF_SEC_TYPE_CODE = 0x02, ///< CODE.
	OMF_SEC_TYPE_CONST = 0x03, ///< CONST.
} OMF_SEC_TYPE;

typedef struct {
	ut16 index;
	bool is_data;
	ut16 size;
	char *label;
	void *user;
} OMF_types;

typedef struct {
	ut16 index;
	ut16 ti;
	ut32 offset;
	ut8 REP8;
	ut8 POS8;
	ut8 n; ///< n max 255, so name array len is 255
	char name[MAX_NAME_LEN];
} OMF_component;

typedef struct {
	ut16 index;
	ut16 count;
	OMF_component *comp;
} OMF_components;

typedef struct {
	ut8 index;
	ut8 descr_type;
	bool is_data; ///< used to build functions
	union {
		OMF_types final_types;
		OMF_components components;
		struct {
			ut8 size; ///< the size of the pointer (either 16 or 32 bits)
			ut8 attrib;
			/**
			 * 1 = Data pointer (PAGE:OFFSET)
			 * 2 = Function pointer (SEG:OFFSET)
			 * 4 = Huge pointer (linear 32-Bit)
			 * 8 = Xhuge pointer (linear 32-Bit)
			 *
			 * The ATTRIB8 byte defines the interpretation of a pointer. Data pointers use the
			 * PAG:POF convention, where PAG is the page number of a physical 16k page and
			 * POF is the offset within the page. Function pointers use the SEG:SOF
			 * convention which specifies the 64k segment (SEG) and a segment-offset (SOF).
			 * Huge pointers use linear addressing undergoing the paged addressing scheme of the 80C166 CPU.
			 */
			ut16 ti; ///< reference to referred type
			/**
			 * The TI16 refers to the final type or another type record. For example, if TI16
			 * contains 0x4A, which is the type ’void’, then the meaning is ’void *’. The SIZE8
			 * specifier will define further details of the type, for example ’void near *’ or ’void far *’.

			 */
		} pointer;
		struct {
			ut8 attrib; ///< 1 = Near-Function 2 = Far-Function
			ut16 rtype_ti; ///< TypeIndex of the function return type
			ut16 parmlist_ti; ///< TypeIndex of the parameter list (a component list)
			/**
			 * Functions without parameters and with return type int/uint/void will not create a
			 * function type descriptor at all. Such functions will be represented by a TI value of
			 * 0x4B which means ’label’. The intention of this short form is to avoid unnecessary
			 * descriptors with almost no information. This has no impact on local variables of
			 * such a function.
			 *
			 * The following two examples show the case when the short form is used:
			 * int test () { ... } // no params
			 * int test (void) { ... } // no params
			 */
		} function;
		struct {
			ut8 dims; ///< number of array dimensions
			ut8 attrib; ///< 1 = Huge-Array (0 ... 64K) 2 = Xhuge-Array (0 ... 16MByte)
			ut16 ti; ///< refers to the type which the array consist of
			ut32 dimsz; ///< the dimension size of each dimension
			/**
			 * The DIMSZ32 field contains ’DIMSZ8’ repeated sizes of the dimensions. A
			 * special case is a DIMSZ32 field containing -1L, which specifies an array
			 * dimension of unknown size. This may be the case on external arrays when the
			 * size is not known to the translator.
			 *
			 * Example: the array declaration ’int array [5][3][2];’ creates the type
			 * | 0x22 | 3 | 0 | 0x44 | 5 | 3 | 2 |
			 *
			 * Hint for the Linker:
			 * The declaration extern char array[];
			 * creates the type descriptor 0x22,1,0,0x42,-1L
			 */
		} array;
		struct {
			bool is_struct; ///< 1 = struct, 2 = union
			ut8 n; ///< struct/union-tag name length
			char tagname[MAX_NAME_LEN]; ///< struct/union-tag name in OMF166 name format
			ut32 size; ///< sizeof struct or union
			ut16 member_ti; ///< reference to component list or `<void>`
		} struct_union;
		struct {
			ut16 ti; ///< base scalar type of the field [uchar, uint, long ]
			ut8 offset; ///< field offset in base scalar in bits
			ut8 width; ///< field width in bits
		} bitfield;

	} descriptor;
	char *label;
	void *rz_type;
} OMF_type;

typedef struct {
	ut16 TI16; ///< members type index
	ut32 OFFS32; ///< members offset
	/**
	 * REP8
	 * relevant on function parameter lists, otherwise REP8 and POS8 will
	 * be zero. The possible values are as follows:
	 * 1: RegBit, POS8=BitPos (0-15), OFFS32=RWn (0-15)
	 * 2: StackVar (auto/parameter) OFFS32=StackOffs ([R0+#n])
	 * 3: RegVar (auto/parameter) OFFS32=RWn (0-15)
	 * The register number ’RWn’ is contained in OFFS32, which is actually
	 * interpreted as a 16 bit word. The value 0 represents R0, 1 R1 and so on.
	 */
	ut8 REP8;
	ut8 POS8; ///< contains a bit position if REP8 contains method 1 (RegBit)
	ut8 n; ///< member name length
	char name[MAX_NAME_LEN]; ///< member name in OMF166 name format
} OMF_type_components;

typedef struct {
	ut16 NrOfComp16; ///< Specifies the number of components
	OMF_type_components components[MAX_NAME_LEN];
} OMF_type_component_list;

typedef struct {
	ut8 bits;
	ut64 base_addr;
	C16xCpuType cpu;
	// ut64 isr_table[128];
	// ut8 isr_count;
	ut8 modinfo;
	ut8 TI_INDEX; // int TI_INDEX;
	int SEC_INDEX;
	RzTypeDB *typedb;
	HtUP /*<OMF_type *>*/ *ht_types;
	RzPVector /*<OMF_debug_includes *>*/ *includes_vec;
	RzPVector /*<OMF_ledatas *>*/ *ledatas_vec;
	RzPVector /*<OMF_lnames *>*/ *lnames_vec;
	RzPVector /*<OMF_deplsts *>*/ *deplsts_vec;
	RzPVector /*<OMF_linnums *>*/ *linnums_vec;
	RzPVector /*<OMF_regmsks *>*/ *regmsks_vec;
	RzPVector /*<OMF_coments *>*/ *coments_vec;
	RzPVector /*<OMF_sections *>*/ *sections_vec;
	RzPVector /*<OMF_symbol *>*/ *symbols_vec;
	RzPVector /*<OMF_blocks *>*/ *blocks_vec;
	RzPVector /*<OMF_pes *>*/ *pe_vec;
	RzVector /*<ut64>*/ *interrupts;
	ut32 nb_symbol;
} rz_bin_omf166_obj;

bool rz_bin_format_omf166_init_internal_storage(RZ_NONNULL void *target_obj);
bool is_valid_omf166_type(ut8 type);
bool rz_bin_format_omf166_load_content(RZ_NONNULL void *target_obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size);
ut8 rz_bin_omf166_get_bits(RZ_NONNULL void *target_obj);
ut16 omf166_max_record_size(void);
bool rz_bin_format_omf166_post_init(RZ_NONNULL const void *target_obj);
RzStructuredData *omf166_structure(RZ_NONNULL const void *target_obj);
RzBinInfo *omf166_info(RZ_NONNULL const void *target_obj);
RzBinAddr *rz_bin_omf166_get_entry(RZ_NONNULL const void *target_obj);
ut64 omf166_baddr(RZ_NONNULL const void *target_obj);
RzBinAddr *omf166_binsym(RZ_NONNULL const void *target_obj, RzBinSpecialSymbol type);

RzPVector /*<RzBinSection *>*/ *omf166_maps(RZ_NONNULL const void *target_obj);
RzPVector /*<RzBinSection *>*/ *omf166_sections(RZ_NONNULL const void *target_obj);
RzPVector /*<RzBinSection *>*/ *omf166_symbols(RZ_NONNULL const void *target_obj);

RZ_API const char *name_of_ti(const rz_bin_omf166_obj *obj, ut16 ti_index);
rz_bin_omf166_obj *rz_bin_format_omf166_load(const ut8 *buf, ut64 size);
void rz_bin_format_omf166_fini(rz_bin_omf166_obj *obj);
void rz_bin_free_all_omf166_obj(RZ_NONNULL void *target_obj);
ut64 rz_bin_omf166_get_paddr_sym(rz_bin_omf166_obj *obj, OMF_symbol *sym);
ut64 rz_bin_omf166_get_vaddr_sym(rz_bin_omf166_obj *obj, OMF_symbol *sym);
const char *rz_bin_omf166_get_module_information(rz_bin_omf166_obj *obj);
const char *get_data_type166(ut8 data_type);
#endif // OMF166_H
