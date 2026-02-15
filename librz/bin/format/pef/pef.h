// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PEF_H
#define RZ_PEF_H

/**
 * Reference: https://developer.apple.com/library/archive/documentation/mac/pdf/MacOS_RT_Architectures.pdf#G20.827
 */

#define PEF_HDR_SIZE            0x28
#define PEF_SECTION_HEADER_SIZE 0x1C ///< 28 bytes
#define MAGIC_HEADER_T1         0x4A6F7921 ///< 'Joy!'
#define MAGIC_HEADER_T2         0x70656666 ///< 'peff'
#define PEF_ARCH_PWPC           0x70777063 ///< 'pwpc'
#define PEF_ARCH_M68K           0x6D36386B ///< 'm68k'
#define PEF_DEFAULT_SIZE1       0x04
#define PEF_DEFAULT_SIZE2       0x02
#define PEF_VERSION_1           0x00000001

typedef enum {
	EXECUTABLE_READONLY = 0, ///< code, read-only
	UNPACKED_DATA = 1, ///< read/write data
	PATTERN_DATA = 2, ///< compressed/pattern data
	CONSTANT = 3, ///< read-only data
	LOADER = 4, ///< loader metadata
	DEBUG_RESERVED = 5, ///< reserved
	EXECUTABLE_READWRITE = 6, ///< writable code
	EXCEPTION_RESERVED = 7, ///< reserved
	TRACEBACK_RESERVED = 8, ///< reserved
} PEFSectionKind;

typedef enum {
	PROCESS = 1, ///< shared per process
	GLOBAL = 4, ///< shared across processes
	PROTECTED = 5, ///< global, read-only unless privileged
} PEFShareKind;

typedef enum {
	WEAK_IMPORT = 0x40,
	EARLY_INIT_REQUIRED = 0x80,
} PEFImportLibraryFlags; ///< If library not found, set all import address to zero

typedef enum {
	kPEFCodeSymbol = 0,
	kPEFDataSymbol = 1,
	kPEFTVectSymbol = 2,
	kPEFTOCSymbol = 3,
	kPEFGlueSymbol = 4,
} PEFLoaderImportSymbolType;

enum {
	kPEFRelocBySectDWithSkip = 0x00, /* binary: 00xxxxx */
	kPEFRelocBySectC = 0x20, /* binary: 0100000 */
	kPEFRelocBySectD = 0x21, /* binary: 0100001 */
	kPEFRelocTVector12 = 0x22, /* binary: 0100010 */
	kPEFRelocTVector8 = 0x23, /* binary: 0100011 */
	kPEFRelocVTable8 = 0x24, /* binary: 0100100 */
	kPEFRelocImportRun = 0x25, /* binary: 0100101 */
	kPEFRelocSmByImport = 0x30, /* binary: 0110000 */
	kPEFRelocSmSetSectC = 0x31, /* binary: 0110001 */
	kPEFRelocSmSetSectD = 0x32, /* binary: 0110010 */
	kPEFRelocSmBySection = 0x33, /* binary: 0110011 */
	kPEFRelocIncrPosition = 0x40, /* binary: 1000xxx */
	kPEFRelocSmRepeat = 0x48, /* binary: 1001xxx */
	kPEFRelocSetPosition = 0x50, /* binary: 101000x */
	kPEFRelocLgByImport = 0x52, /* binary: 101001x */
	kPEFRelocLgRepeat = 0x58, /* binary: 101100x */
	kPEFRelocLgSetOrBySection = 0x5A, /* binary: 101101x */
} Reloc_opcode_values;

typedef struct {
	ut8 magic1[4];
	ut8 magic2[4];
	ut32 arch; ///< 'pwpc' or 'm68k'
	ut32 format_version; ///< PEF format version
	ut32 timestamp; ///< build time
	ut32 old_def_version; ///< old definition version
	ut32 old_imp_version; ///< old implementation version
	ut32 current_version; ///< current version
	ut16 section_count; ///< total sections
	ut16 inst_section_count; ///< sections needed at runtime
	ut32 reserved; ///< reserved
} PefHeader;

typedef struct {
	ut32 nameOffset; ///< offset to section name (-1 if none)
	ut32 defaultAddress; ///< preferred load address
	ut32 totalSize; ///< size in memory (with zero-fill)
	ut32 unpackedSize; ///< initialized size in memory
	ut32 packedSize; ///< size stored in file
	ut32 containerOffset; ///< offset in file to section data
	ut8 sectionKind; ///< section type
	ut8 shareKind; ///< sharing mode
	ut8 alignment; ///< alignment (power of 2)
	ut8 reservedA; ///< reserved
} PefSectionHeader;

/**
 * Loader section structure
 *
 * The loader section has, in this order:
 * - PEFLoaderSectionHeader
 * - PEFLoaderImportLibrary[header.imported_lib_count]
 * - PEFLoaderImportSymbol[header.imported_symbol_count]
 * - PEFLoaderRelocationHeader[header.rel_section_count]
 * - Relocations
 * - String table
 * - Export hash table
 * - Export key table
 * - Exported symbol table
 */

typedef struct {
	st32 main_symbol_index; ///< index of main symbol (-1 if none)
	ut32 main_symbol_offset; ///< offset of main in section
	int init_symbol_index; ///< index of init symbol (-1 if none)
	ut32 init_symbol_offset; ///< offset of init in section
	int term_symbol_index; ///< index of term symbol (-1 if none)
	ut32 term_symbol_offset; ///< offset of term in section
	ut32 imported_lib_count; ///< number of imported libraries
	ut32 imported_symbol_count; ///< number of imported symbols
	ut32 rel_section_count; ///< sections with relocations
	ut32 rel_commands_offset; ///< offset to relocation commands
	ut32 string_table_offset; ///< offset to string table
	ut32 export_hash_offset; ///< offset to export hash table
	ut32 export_hash_power; ///< hash size = 2^value
	ut32 exported_symbol_count; ///< number of exported symbols
} PEFLoaderSectionHeader;

typedef struct {
	ut32 name_offset; ///< offset to library name
	ut32 old_imp_version; ///< old implementation version
	ut32 current_version; ///< current version
	ut32 imported_symbol_count; ///< symbols imported from this lib
	ut32 start_index; ///< first symbol index in import table
	ut8 options; ///< library flags
	ut8 reserved1; ///< reserved
	ut16 reserved2; ///< reserved
} PEFLoaderImportLibrary;

typedef struct {
	ut32 u; ///< 32-bit packed field
} PEFLoaderImportSymbol;

static inline ut8 pef_import_flags(ut32 u) {
	return (u >> 28) & 0x0F;
}

static inline ut8 pef_import_type(ut32 u) {
	return (u >> 24) & 0x0F;
}

static inline ut32 pef_import_name_offset(ut32 u) {
	return u & 0x00FFFFFF;
}

typedef struct {
	ut16 section_index;
	ut16 reserved;
	ut32 word_count;
	ut32 start_offset;
} PEFLoaderRelocationHeader;

typedef struct {
	ut32 u; ///< 32-bit packed value
} PEFLoaderExportHashEntry;

static inline ut16 pef_export_chain_count(ut32 u) {
	return (u >> 18) & 0x3FFF;
}

static inline ut32 pef_export_start_index(ut32 u) {
	return u & 0x3FFFF;
}

typedef struct {
	ut16 symbol_length;
	ut16 hash;
} PEFLoaderExportHashKey;

typedef struct {
	ut32 type_and_name; ///< packed: flags(4) | type(4) | name_offset(24)
	ut32 value; ///< usually offset from section start
	ut16 section_index; ///< index of section containing symbol
	ut16 reserved; ///< reserved
} PEFLoaderExportSymbol;

static inline uint8_t pef_export_symbol_flags(ut32 u) {
	return (u >> 28) & 0x0F;
}

static inline uint8_t pef_export_symbol_type(ut32 u) {
	return (u >> 24) & 0x0F;
}

static inline ut32 pef_export_symbol_name_offset(ut32 u) {
	return u & 0x00FFFFFF;
}

typedef struct {
	ut8 length; ///< string length (0-255)
	char data[]; ///< string data (not null-terminated)
} PEFString;

typedef struct {
	ut32 offset; ///< offset in loader section
	ut32 size; ///< total size of string table
	const ut8 *data; ///< pointer to string table data
} PEFStringTable;

typedef struct {
	ut32 current_offset; ///< Current offset in section being relocated
	ut16 current_section; ///< Current section index
	ut32 import_index; ///< Last import symbol index used
	const ut8 *reloc_ptr; ///< Current position in relocation stream
	const ut8 *reloc_end; ///< End of relocation stream
} PEFRelocationContext;

typedef struct {
	PEFLoaderSectionHeader header;
	RzVector /*<PEFLoaderImportLibrary>*/ loader_library;
	RzVector /*<PEFLoaderImportSymbol>*/ loader_import_symbol;
	RzVector /*<PEFLoaderRelocationHeader>*/ loader_reloc_header;
	RzVector /*<PEFLoaderExportHashEntry>*/ loader_export_hash_entry;
	RzVector /*<PEFLoaderExportHashKey>*/ loader_export_hash_key;
	RzVector /*<PEFLoaderExportSymbol>*/ loader_export_symbol;
	PEFStringTable string_table;
	const ut8 *reloc_data;
	ut32 reloc_data_size;
} Loader_Section;

typedef struct {
	PefHeader header;
	RzVector /*<PefSectionHeader>*/ sections;
	Loader_Section loader_section;
} PefContainer;

#endif /* RZ_PEF_H */
