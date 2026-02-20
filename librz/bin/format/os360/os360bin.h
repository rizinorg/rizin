/**
 * \file os360bin.h
 * \brief Parser implementation for OS/360 object file format.
 */

#ifndef OS360_H_
#define OS360_H_

#include <rz_vector.h>
#include <rz_types.h>
#include <rz_bin.h>

/**
 * \brief Type of record in OS/360 object file.
 */
typedef enum {
	OS360_RECORD_TYPE_ESD = 0xC5E2C4, // `ESD` in ebcdic
	OS360_RECORD_TYPE_TXT = 0xE3E7E3, // `TXT` in ebcdic
	OS360_RECORD_TYPE_RLD = 0xD9D3C4, // `RLD` in ebcdic
	OS360_RECORD_TYPE_SYM = 0xE2E8D4, // `SYM` in ebcdic
	OS360_RECORD_TYPE_XSD = 0xE7E2C4, // `XSD` in ebcdic
	OS360_RECORD_TYPE_END = 0xC5D5C4, // `END` in ebcdic
} RzBinOS360RecordType;

/**
 * \brief Type of Module Symbol.
 */
typedef enum {
	OS360_ESD_TYPE_SD = 0x00,
	OS360_ESD_TYPE_LD = 0x01,
	OS360_ESD_TYPE_ER = 0x02,
	OS360_ESD_TYPE_PC = 0x04,
	OS360_ESD_TYPE_CM = 0x05,
	OS360_ESD_TYPE_XD = 0x06,
	OS360_ESD_TYPE_WX = 0x0A,
	OS360_ESD_TYPE_SD_QA = 0x0D,
	OS360_ESD_TYPE_PC_QA = 0x0E,
	OS360_ESD_TYPE_CM_QA = 0x0F,
} RzBinOS360ModuleType;

/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define RMODE_5_BIT_PROBE(x) (((x) & 0b00100000) == 0)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define RMODE_64_PROBE(x) ((x) & 0b00100000)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define AMODE_6_7_BIT_PROBE(x) (((x) & 0b00010000) == 0)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define AMODE_64_PROBE(x) ((x) & 0b00010000)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define READ_WRITE_PROBE(x) (((x) & 0b00001000) == 0)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define READ_ONLY_PROBE(x) ((x) & 0b00001000)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define RMODE_31_BITS_PROBE(x) (((x) & 0b00000100) == 0)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define RMODE_31_BITS_OR_RMODE_ANY_PROBE(x) ((x) & 0b00000100)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define AMODE_24_BITS_PROBE(x) (((x) & 0b00000011) <= 1)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define AMODE_31_BITS_PROBE(x) (((x) & 0b00000011) == 0b10)
/**
 * \brief Extracts the value from \ref RzBinOS360ModuleSymbol.addition_1
 */
#define AMODE_ANY_PROBE(x) (((x) & 0b00000011) == 0b11)

typedef struct {
	/**
	 * \brief Identifies the Program, Function, Subroutine
	 * or FORTRAN COMMON Block.
	 * This will be blank for PC or blank COMMON or
	 * unnamed BLOCK DATA
	 *
	 * \note Preallocated C-string so can be
	 * safely used as a cast to `char*`
	 */
	char name[9];
	/**
	 * \brief Defines the module type
	 */
	RzBinOS360ModuleType type;
	/**
	 * \brief Binary starting address of this module;
	 * Address of symbol within module for LD
	 */
	ut32 address;
	/**
	 * \brief Alignment in binary for XD;
	 * Blank for ER, LD or WX;
	 * For SD, CM, or PC reprsent bitflag
	 */
	ut8 addition_1;
	/**
	 * \brief Length in binary for PC, CM, SD;
	 * One blank followed by 2-byte Binary LDID for LD;
	 * Blanks for ER, XD, PR or WX;
	 */
	ut32 addition_2;
} RzBinOS360ModuleSymbol;

typedef struct {
	ut16 esid;
	/**
	 * \brief Number of symbols in this record
	 */
	ut8 sym_num;
	/**
	 * @brief Preallocated array of symbols, for
	 * number of symbols see `sym_num` field
	 */
	RzBinOS360ModuleSymbol symbols[3];
} RzBinOS360EsdRecord;

/**
 * \brief Extracts the value from \ref RzBinOS360RelocationEntry.flag
 */
#define IS_ADDRESS_ADDITIVE_PROBE(x) ((x) & 0b01000000)
/**
 * \brief Extracts the value from \ref RzBinOS360RelocationEntry.flag
 */
#define IS_CHAIN(x) ((x) & 0b00000001)
/**
 * \brief Extracts the value from \ref RzBinOS360RelocationEntry.flag
 */
#define RELO_DIRECTION(x) (((x) & 0b00000010) >> 1)
/**
 * \brief Extracts the value from \ref RzBinOS360RelocationEntry.flag
 */
#define ADDRESS_CONSTANT_TYPE_MASK(x) (((x) & 0b00110000) >> 4)
/**
 * \brief Extracts the value from \ref RzBinOS360RelocationEntry.flag
 */
#define ADDRESS_LENGTH_EXTRUDE(x) ((((x) & 0b00001100) >> 2) + 1)

typedef enum {
	/**
	 * \brief A or Y adcon. If A adcon, the
	 * value is normally store a four byte
	 * relocatable address, however it is possible
	 * to specify the length of the constant.
	 * If Y adcon, the value is two byte (halfword) addresses
	 */
	OS360_RELO_ADDRESS_CONST_A = 0,
	/**
	 * \brief V adcons store an external reference
	 */
	OS360_RELO_ADDRESS_CONST_V = 1,
	/**
	 * \brief Q adcon used for PIC
	 * through External Dummy Section
	 */
	OS360_RELO_ADDRESS_CONST_Q = 2,
	/**
	 * \brief CXD (Count External Definitions)
	 * place the total length of all external
	 * dummy sections (WXTRNs) into a specified address.
	 */
	OS360_RELO_ADDRESS_CONST_CXD = 3,
} RzBinOS360ReloAddressConstType;

/**
 * \brief Represents a relocation entry in RLD record.
 *
 * \attention Here are some differences in format for
 * example in `MVS Program Management: Advanced Facilities`
 * manual `relocation` comes first and then `relocation_target`,
 * but for example in `OS/VS - VM/370 Assembler Programmer's Guide`
 * it's the opposite.
 * Here we stick to the first variant.
 */
typedef struct {
	/**
	 * \brief Binary ESDID of the symbol to be relocated
	 */
	ut16 relocation;
	/**
	 * \brief Binary ESDID where the relocation is to be made
	 */
	ut16 relocation_target;
	/**
	 * \brief
	 * Bitflag for relo organization:
	 *  - 0: Reserved
	 *  - 1: If 1, add 4 to address constant length value
	 *  - 2-3: Address Constant type
	 *  - 4-5: Address Constant Length - 1
	 *  - 6: Direction of relocation
	 *  - 7: Chain bit
	 */
	ut8 flag;
	/**
	 * \brief Absolute address in module of Position entry to
	 * be relocated.
	 */
	ut32 address;
} RzBinOS360RelocationEntry;

typedef struct {
	/**
	 * \brief Number of entries in this record
	 */
	ut8 entry_num;
	/**
	 * \brief Preallocated array of entry, for
	 * number of entry see `entry_num` field
	 */
	RzBinOS360RelocationEntry entries[13];
} RzBinOS360RldRecord;

/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define IS_DATA_TYPE_PROBE(x) ((x) & 0b10000000)
/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define IS_HAS_NAME_PROBE(x) ((x) & 0b00001000)
/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define NAME_LENGTH_EXTRUDE(x) (((x) & 0x00000111) + 1)
/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define NON_DATATYPE_MASK(x) (x & 0b01110000)

typedef enum {
	OS360_SYM_ND_SPACE = 0b00000000,
	OS360_SYM_ND_CONTROL_SECTION = 0b00010000,
	OS360_SYM_ND_DUMMY_CONTROL_SECTION = 0b00100000,
	OS360_SYM_ND_COMMON = 0b00110000,
	OS360_SYM_ND_MACHINE_INSTRUCTION = 0b01000000,
	OS360_SYM_ND_CCW = 0b01010000,
	OS360_SYM_ND_OTHER = 0b01100000,
} RzBinOS360NonDatatype;

/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define IS_MULTIPLICITY_PRESENT_PROBE(x) ((x) & 0b01000000)
/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define IS_CLUSTER_PROBE(x) ((x) & 0b00100000)
/**
 * \brief Extracts the value from \ref RzBinOS360SymbolData.organization
 */
#define IS_SCALING_PRESENT_PROBE(x) ((x) & 0b00010000)

typedef enum {
	OS360_SYM_D_CHAR = 0x00,
	OS360_SYM_D_HEX = 0x04,
	OS360_SYM_D_BIN = 0x08,
	OS360_SYM_D_INT_32 = 0x10,
	OS360_SYM_D_INT_16 = 0x14,
	OS360_SYM_D_FLOAT_32 = 0x18,
	OS360_SYM_D_DOUBLE_64 = 0x1C,
	OS360_SYM_D_ADDRESS_32 = 0x20,
	OS360_SYM_D_ADDRESS_16 = 0x24,
	OS360_SYM_D_S_TYPE = 0x28,
	OS360_SYM_D_EXTERNAL_SYM_32 = 0x2C,
	OS360_SYM_D_P_TYPE = 0x30,
	OS360_SYM_D_Z_TYPE = 0x34,
	OS360_SYM_D_L_TYPE = 0x38,
} RzBinOS360Datatype;

/**
 * \note Fields `data_type`, `length`, `multiplicity`
 * and `scale` are only valid if the symbol is a
 * datatype symbol,
 */
typedef struct {
	/**
	 * \brief
	 * Bitflag for symbol organization:
	 *  - 0: 0 Non-datatype, 1 Datatype
	 *  - 4: Has name or not
	 *  - 5-7: Length of symbol name
	 * For non-datatype organization:
	 *  - 1-3: Section type
	 * For datatype organization:
	 *  - 1: Has Multiplicity or not
	 *  - 2: Has Cluster or not
	 *  - 3: Has Scaling or not
	 */
	ut8 organization;
	/**
	 * \brief Displacement from base of control section
	 */
	ut16 address;
	/**
	 * \brief Name of symbol
	 *
	 * \note Preallocated C-string so can be
	 * safely used as a cast to `char*`
	 */
	char name[9];
	/**
	 * \brief The data type of this symbol
	 */
	RzBinOS360Datatype data_type;
	/**
	 * \brief Length of data item minus 1
	 */
	ut16 length;
	/**
	 * \brief Byte repeat count
	 */
	ut64 multiplicity;
	/**
	 * \brief Scale value
	 */
	ut16 scale;
} RzBinOS360SymbolData;

typedef struct {
	/**
	 * \brief Number of symbols in this record
	 */
	ut8 sym_num;
	/**
	 * \brief Preallocated array of symbols, for
	 * number of symbols see `sym_num` field
	 */
	RzBinOS360SymbolData data[14];
} RzBinOS360SymRecord;

#define XPLINK_MASK(x) ((x) & 0b11111100)
/* TODO */
#define AMODE_64_PROBE(x) ((x) & 0b00000010)

#define NAME_MUTI_DEF(x)


typedef struct {
	/**
	 * \brief Size used in bytes at data section(16-71)
	 */
	ut16 data_size;
	/**
	 * \brief Bits 1-6 are used for XPLINK; Bit 7 is used for AMODE 64;
	 */
	ut8 flag1;
	/**
	 * \brief
	 *  - 0: Name may have multiple definitions
	 *  - 1: Name is mangled
	 *  - 2: Internal Linkage
	 *  - 3: Template
	 *  - 4: Concat
	 *  - 5: Name eligible for import or export
	 *  - 6: 1 if name is a function
	 *  - 7: 1 if name was mapped (e.g. #pragma map)
	 */
	ut8 flag2;
	/**
	 * \brief LDID Identifier if XSD is for an LD,
	 * otherwise the ESDID
	 */
	ut16 ldid_or_esdid;
	/**
	 * \brief Length of the name
	 */
	ut64 length;
	/**
	 * \brief Offset of first byte of name or substring of name (origin of 1)
	 */
	ut64 offset;
	/**
	 * \brief Module type
	 */
	RzBinOS360ModuleType type;
	/**
	 * \brief 24-bit address of symbol
	 */
	ut64 address;
	/**
	 * \brief Specification of module,
	 * depend of module type \ref RzBinOS360XsdRecord.type
	 */
	ut8 spec;
	/**
	 * \brief Offset of first byte of name or substring of name (origin of 1)
	 *
	 * - Zero: If length is specified on END record for types SD, PC, CM.
	 * - Length: Control Section Length For types SD, PC, CM; Pseudo-Register length for type PR.
	 * - Identifier: Identifier of SD entry containing name for type LD
	 * - Blank: If type is ER or WX
	 */
	ut64 length_or_ident;
	/**
	 * \note Preallocated C-string so can be
	 * safely used as a cast to `char*`
	 */
	char name[11];
} RzBinOS360XsdRecord;

/**
 * \note The identifier fields are essentially a comment field so they
 * could be used possibly for anything (especially the Order Number field),
 * or could be blank.
 */
typedef struct {
	/**
	 * \brief Assembler or identifier of compiler,
	 * may have letters or digits
	 */
	ut8 order_no[10];
	/**
	 * \brief Version number of assembler or compiler
	 */
	ut16 version;
	/**
	 * \brief Revision number of assembler or compiler
	 */
	ut16 revision;
	/**
	 * \brief Last two digits of year this was assembled or compiled
	 */
	ut16 run_year;
	/**
	 * \brief 3-Digit day of year this assembly was run or program was compiled
	 */
	ut32 run_day;
} RzBinOS360IDRRecordData;

/**
 * \attention Some versions of the assembler use `format` (offset 32)
 * byte to indicate the number of Identifier (IDR) Records
 * (values in bytes 33-51, or in 52-70 if present), are in this
 * record.
 *
 * However, here we adhere to the fact that the type was written
 * 
 * \note The entry point of this module can be an external symbol.
 * This allows a module to automatically start a run-time library or startup
 * code instead of itself.
 */
typedef struct {
	/**
	 * \brief Entry Address if specified or blanks
	 */
	ut32 entry_address;
	/**
	 * \brief Binary ESDID of starting point of this module if given
	 */
	ut16 entry_esdid;
	/**
	 * \brief Name of starting point of this module
	 */
	char start_name[9];
	ut32 module_size;
	/**
	 * \brief EBCDIC digit character '1', '2' or Blank.
	 * Blank may mean 1 record is present, or none are, or may
	 * be used to indicate it is a type 1 assembler record.
	 */
	ut8 format;
	RzBinOS360IDRRecordData idr[2];
} RzBinOS360EndRecord;

typedef struct {
	/**
	 * \brief Relative address of data
	 */
	ut32 rel_addr;
	/**
	 * \brief Number of bytes of `data` field that's valid
	 */
	ut16 data_size;
	ut16 esdid;
	/**
	 * \brief Program instructions and/or program data
	 */
	ut8 data[56];
} RzBinOS360TxtRecord;

typedef struct {
	/**
	 * \brief Base record structure for all types of records in OS/360 object file.
	 *
	 * \note The actual type of content depends on the `type` field,
	 * and the content can be safely cast to the corresponding record struct.
	 */
	RzBinOS360RecordType type;
	/**
	 * \brief Deck ID and/or sequence number
	 */
	ut64 ident;
	/**
	 * \brief Content of the record,
	 * the actual type depends on the `type` field
	 */
	void *content;
} RzBinOS360BaseRecord;

typedef struct {
	RzPVector /*<RzBinOS360BaseRecord *>*/ *records;
} RzBinOS360Obj;

/**
 * \brief Construct the OS/360 object from the given buffer 
 * containing the OS/360 object file data.
 * 
 * \param buf Target buffer containing the OS/360 object file data
 * \param size Size of the buffer in bytes
 * \return The initialized OS/360 object, or NULL on failure 
 */
RzBinOS360Obj *rz_bin_os360_init(const ut8 *buf, ut64 size);

/**
 * \brief Destroys the OS/360 object and frees all associated resources.
 * 
 * \param obj The OS/360 object to destroy
 */
void rz_bin_os360_destroy(RzBinOS360Obj *obj);


/**
 * \brief Object Module End-of-Module (END) requested ("nominated")
 * execution-time entry point, By ESDID and address, or by external name.
 *
 * Following the "best effort" strategy, we try to extract address 
 * field-by-field until it works out
 * 
 * \param obj The OS/360 object if we need to search for ESDID or external name
 * \param end_record The END record to extract entry address from,
 * if another type of record is given, the function log error and will return NULL
 * \return The extracted entry address, or NULL if not found
 */
RZ_OWN RzBinAddr *rz_bin_os360_extract_entry_address(RZ_NONNULL RzBinOS360Obj *obj, RZ_NONNULL RzBinOS360BaseRecord *end_record);

/**
 * \brief Finds a record in the OS/360 object by its identifier.
 * 
 * \param obj The OS/360 object to search in.
 * \param ident The identifier to search for.
 * \return The found record, or NULL if not found.
 */
RZ_BORROW RzBinOS360BaseRecord *rz_bin_os360_find_record_by_ident(RZ_NONNULL RzBinOS360Obj *obj, char *ident);

/**
 * \brief Finds a record in the OS/360 object by its ESDID.
 * 
 * \param obj The OS/360 object to search in.
 * \param esdid The ESDID to search for.
 * \return The found record, or NULL if not found.
 */
RZ_BORROW RzBinOS360BaseRecord *rz_bin_os360_find_record_by_esdid(RZ_NONNULL RzBinOS360Obj *obj, ut16 esdid);

#endif