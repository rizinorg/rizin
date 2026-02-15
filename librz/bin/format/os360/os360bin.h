#ifndef OS360_H_
#define OS360_H_

#include <rz_types.h>

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
} RzBinOS360EsdType;

#define RMODE_5_BIT_PROBE(x) (((x) & 0b00100000) == 0)
#define RMODE_64_PROBE(x) ((x) & 0b00100000)
#define AMODE_6_7_BIT_PROBE(x) (((x) & 0b00010000) == 0)
#define AMODE_64_PROBE(x) ((x) & 0b00010000)
#define READ_WRITE_PROBE(x) (((x) & 0b00001000) == 0)
#define READ_ONLY_PROBE(x) ((x) & 0b00001000)
#define RMODE_31_BITS_PROBE(x) (((x) & 0b00000100) == 0)
#define RMODE_31_BITS_OR_RMODE_ANY_PROBE(x) ((x) & 0b00000100)
#define AMODE_24_BITS_PROBE(x) (((x) & 0b00000011) <= 1)
#define AMODE_31_BITS_PROBE(x) (((x) & 0b00000011) == 0b10)
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
	RzBinOS360EsdType type;
    /**
     * \brief Binary starting address of this module; 
     * Address of symbol within module for LD
     */
	ut32 address;
    /**
     * \brief Alignment in binary for XD;
     * Blank for ER, LD or WX;
     * For SD, CM, or PC reprsent bitflag,
     * for extrude values from flag use following PROBE macros;
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

#define IS_ADDRESS_ADDITIVE_PROBE(x) ((x) & 0b01000000)
#define IS_CHAIN(x) ((x) & 0b00000001)
#define RELO_DIRECTION(x) (((x) & 0b00000010) >> 1)
#define ADDRESS_CONSTANT_TYPE_MASK(x) (((x) & 0b00110000) >> 4)
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
    /* TODO */
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

#define IS_DATA_TYPE_PROBE(x) ((x) & 0b10000000)
#define IS_HAS_NAME_PROBE(x) ((x) & 0b00001000)
#define NAME_LENGTH_EXTRUDE(x) (((x) & 0x00000111) + 1)
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

// For datatype
#define IS_MULTIPLICITY_PRESENT_PROBE(x)
#define IS_CLUSTER_PROBE(x)
#define IS_SCALING_PRESENT_PROBE(x)

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
 * @note Fields `data_type`, `length`, `multiplicity` 
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
    /* TODO */
    ut64 multiplicity;
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

typedef struct {
	ut16 data_size; /* TODO */
	ut8 flag1;
    ut8 flag2;
	// LDID Identifier if XSD, otherwise the ESDID
	ut16 ldid_or_esdid;
	ut64 length;
    ut64 offset;
    ut8 type;
    ut64 address;
    ut8 spec;
    ut64 length_or_ident;
    /**
     * \note Preallocated C-string so can be
     * safely used as a cast to `char*`
     */
    char name[11];
} RzBinOS360XsdRecord;

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
    /* TODO */
	ut32 run_day;
} RzBinOS360IDRRecordData;

typedef struct {
    /* TODO */
	ut32 entry_address;
	ut16 entry_esdid;
	char start_name[9];
	ut32 module_size;
    ut8 format_or_idr_count;
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
	RzBinOS360BaseRecord record;
	struct OS360_record_handler *next;
} OS360_record_handler;

typedef struct {
	OS360_record_handler *records;
} rz_bin_os360_obj;

rz_bin_os360_obj *rz_bin_os360_init(const ut8 *buf, ut64 size);
void rz_bin_os360_destroy(rz_bin_os360_obj *obj);

#endif