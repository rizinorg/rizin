#ifndef OS360_H_
#define OS360_H_

#include <rz_types.h>

typedef enum {
	OS360_RECORD_TYPE_ESD,
	OS360_RECORD_TYPE_TXT,
	OS360_RECORD_TYPE_RLD,
	OS360_RECORD_TYPE_SYM,
	OS360_RECORD_TYPE_XSD,
	OS360_RECORD_TYPE_END,
} RzBinOS360RecordType;

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

/* TODO */
#define RMODE_64_PROBE(x) (x & 0b00100000 > 0)
#define AMODE_64_PROBE(x) (x & 0b00010000 > 0)
#define READ_ONLY_PROBE(x) (x & 0b00001000 > 0)
#define RMODE_31_BITS_OR_RMODE_ANY_PROBE(x) (x & 0b00000100 > 0)
#define AMODE_24_BITS_PROBE(x) (x & 0b00000011 <= 1)
#define AMODE_31_BITS_PROBE(x) (x & 0b00000011 == 0b10)
#define AMODE_ANY_PROBE(x) (x & 0b00000011 == 0b11)

typedef struct {
    // Identifies the Program, Function, Subroutine 
    // or FORTRAN COMMON Block
	char name[8];
    // Defines the module type
	RzBinOS360EsdType type;
    // Binary starting address of this module; 
    // address of symbol within module for LD
	ut32 address;
    // Alignment in binary for XD
    // Blank for ER, LD or WX;
    // For SD, CM, or PC reprsent bitflag, 
    // for extrude flag use following PROBE macros
	ut8 addition_1;
	ut32 addition_2;
} RzBinOS360ModuleSymbol;

typedef struct {
	ut16 sym_num;
	ut16 esid;
	RzBinOS360ModuleSymbol symbols[3];
} RzBinOS360EsdRecord;

typedef enum {
    /* TODO */
} RzBinOS360RelocationEntryFlag;

typedef struct {
	ut16 relocation;
	ut16 position;
	RzBinOS360RelocationEntryFlag flag;
	ut32 address;
} RzBinOS360RelocationEntry;

typedef struct {
	ut16 entry_num; /* TODO */
	RzBinOS360RelocationEntry entries[13];
} RzBinOS360RldRecord;

typedef struct {
    /* TODO */
} RzBinOS360SymbolData;

typedef struct {
	ut16 data_size; /* TODO */
	RzBinOS360SymbolData data;
} RzBinOS360SymRecord;

typedef struct {
	/* TODO */
} RzBinOS360XsdRecordData;

typedef enum {
    /* TODO */
} RzBinOS360XsdRecordFlag;

typedef struct {
	ut16 data_size;
	RzBinOS360XsdRecordFlag flag;
	ut16 ldid_or_esdid;
	RzBinOS360XsdRecordData data;
} RzBinOS360XsdRecord;

typedef struct {
	ut32 module_size;
	char start_name[8];
	ut8 order_no[9];
	ut8 format_or_idr_count;
	ut16 version;
	ut16 revision;
	ut16 run_year;
	ut32 run_day;
	char *additional_ident;
} RzBinOS360EndData;

typedef struct {
	ut32 entry_address;
	ut16 entry_esdid;
	RzBinOS360EndData data;
} RzBinOS360EndRecord;

typedef struct {
	ut32 rel_addr;
	ut16 data_size;
	ut16 esdid;
	ut8 *data;
} RzBinOS360TxtRecord;

typedef struct {
	RzBinOS360RecordType type;
	ut64 ident;
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