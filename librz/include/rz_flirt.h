// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FLIRT_H
#define RZ_FLIRT_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_FLIRT_NAME_MAX         1024
#define RZ_FLIRT_LIBRARY_NAME_MAX 0xFF
#define RZ_FLIRT_LIBRARY_NAME_DFL "Built with rizin " RZ_VERSION
#define RZ_FLIRT_MAX_PRELUDE_SIZE (32) // this value is choosen as the default for FLIRT, but it can go between 1 and 64

/* supported architectures */
enum rz_flirt_sig_arch_t {
	RZ_FLIRT_SIG_ARCH_386 = 0, // Intel 80x86
	RZ_FLIRT_SIG_ARCH_Z80, // 8085, Z80
	RZ_FLIRT_SIG_ARCH_I860, // Intel 860
	RZ_FLIRT_SIG_ARCH_8051, // 8051
	RZ_FLIRT_SIG_ARCH_TMS, // Texas Instruments TMS320C5x
	RZ_FLIRT_SIG_ARCH_6502, // 6502
	RZ_FLIRT_SIG_ARCH_PDP, // PDP11
	RZ_FLIRT_SIG_ARCH_68K, // Motoroal 680x0
	RZ_FLIRT_SIG_ARCH_JAVA, // Java
	RZ_FLIRT_SIG_ARCH_6800, // Motorola 68xx
	RZ_FLIRT_SIG_ARCH_ST7, // SGS-Thomson ST7
	RZ_FLIRT_SIG_ARCH_MC6812, // Motorola 68HC12
	RZ_FLIRT_SIG_ARCH_MIPS, // MIPS
	RZ_FLIRT_SIG_ARCH_ARM, // Advanced RISC Machines
	RZ_FLIRT_SIG_ARCH_TMSC6, // Texas Instruments TMS320C6x
	RZ_FLIRT_SIG_ARCH_PPC, // PowerPC
	RZ_FLIRT_SIG_ARCH_80196, // Intel 80196
	RZ_FLIRT_SIG_ARCH_Z8, // Z8
	RZ_FLIRT_SIG_ARCH_SH, // Renesas (formerly Hitachi) SuperH
	RZ_FLIRT_SIG_ARCH_NET, // Microsoft Visual Studio.Net
	RZ_FLIRT_SIG_ARCH_AVR, // Atmel 8-bit RISC processor(s)
	RZ_FLIRT_SIG_ARCH_H8, // Hitachi H8/300, H8/2000
	RZ_FLIRT_SIG_ARCH_PIC, // Microchip's PIC
	RZ_FLIRT_SIG_ARCH_SPARC, // SPARC
	RZ_FLIRT_SIG_ARCH_ALPHA, // DEC Alpha
	RZ_FLIRT_SIG_ARCH_HPPA, // Hewlett-Packard PA-RISC
	RZ_FLIRT_SIG_ARCH_H8500, // Renesas (formerly Hitachi) H8/500
	RZ_FLIRT_SIG_ARCH_TRICORE, // Tricore
	RZ_FLIRT_SIG_ARCH_DSP56K, // Motorola DSP5600x
	RZ_FLIRT_SIG_ARCH_C166, // Siemens C166 family
	RZ_FLIRT_SIG_ARCH_ST20, // SGS-Thomson ST20
	RZ_FLIRT_SIG_ARCH_IA64, // Intel Itanium IA64
	RZ_FLIRT_SIG_ARCH_I960, // Intel 960
	RZ_FLIRT_SIG_ARCH_F2MC, // Fujitsu F2MC-16
	RZ_FLIRT_SIG_ARCH_TMS320C54, // Texas Instruments TMS320C54xx
	RZ_FLIRT_SIG_ARCH_TMS320C55, // Texas Instruments TMS320C55xx
	RZ_FLIRT_SIG_ARCH_TRIMEDIA, // Trimedia
	RZ_FLIRT_SIG_ARCH_M32R, // Mitsubishi 32bit RISC
	RZ_FLIRT_SIG_ARCH_NEC_78K0, // NEC 78K0
	RZ_FLIRT_SIG_ARCH_NEC_78K0S, // NEC 78K0S
	RZ_FLIRT_SIG_ARCH_M740, // Mitsubishi 8bit
	RZ_FLIRT_SIG_ARCH_M7700, // Mitsubishi 16bit
	RZ_FLIRT_SIG_ARCH_ST9, // ST9+
	RZ_FLIRT_SIG_ARCH_FR, // Fujitsu FR Family
	RZ_FLIRT_SIG_ARCH_MC6816, // Motorola 68HC16
	RZ_FLIRT_SIG_ARCH_M7900, // Mitsubishi 7900
	RZ_FLIRT_SIG_ARCH_TMS320C3, // Texas Instruments TMS320C3
	RZ_FLIRT_SIG_ARCH_KR1878, // Angstrem KR1878
	RZ_FLIRT_SIG_ARCH_AD218X, // Analog Devices ADSP 218X
	RZ_FLIRT_SIG_ARCH_OAKDSP, // Atmel OAK DSP
	RZ_FLIRT_SIG_ARCH_TLCS900, // Toshiba TLCS-900
	RZ_FLIRT_SIG_ARCH_C39, // Rockwell C39
	RZ_FLIRT_SIG_ARCH_CR16, // NSC CR16
	RZ_FLIRT_SIG_ARCH_MN102L00, // Panasonic MN10200
	RZ_FLIRT_SIG_ARCH_TMS320C1X, // Texas Instruments TMS320C1x
	RZ_FLIRT_SIG_ARCH_NEC_V850X, // NEC V850 and V850ES/E1/E2
	RZ_FLIRT_SIG_ARCH_SCR_ADPT, // Processor module adapter for processor modules written in scripting languages
	RZ_FLIRT_SIG_ARCH_EBC, // EFI Bytecode
	RZ_FLIRT_SIG_ARCH_MSP430, // Texas Instruments MSP430
	RZ_FLIRT_SIG_ARCH_SPU, // Cell Broadband Engine Synergistic Processor Unit
	RZ_FLIRT_SIG_ARCH_DALVIK, // Android Dalvik Virtual Machine
	RZ_FLIRT_SIG_ARCH_65C816, // 65802/65816
	RZ_FLIRT_SIG_ARCH_M16C, // Renesas M16C
	RZ_FLIRT_SIG_ARCH_ARC, // Argonaut RISC Core
	RZ_FLIRT_SIG_ARCH_UNSP, // SunPlus unSP
	RZ_FLIRT_SIG_ARCH_TMS320C28, // Texas Instruments TMS320C28x
	RZ_FLIRT_SIG_ARCH_DSP96K, // Motorola DSP96000
	RZ_FLIRT_SIG_ARCH_SPC700, // Sony SPC700
	RZ_FLIRT_SIG_ARCH_AD2106X, // Analog Devices ADSP 2106X
	RZ_FLIRT_SIG_ARCH_PIC16, // Microchip 16-bit PIC
	RZ_FLIRT_SIG_ARCH_S390, // IBM's S390
	RZ_FLIRT_SIG_ARCH_XTENSA, // Tensilica Xtensa
	RZ_FLIRT_SIG_ARCH_RISCV, // RISC-V
	RZ_FLIRT_SIG_ARCH_RL78, // Renesas RL78.
	RZ_FLIRT_SIG_ARCH_RX, // Renesas RX.
	RZ_FLIRT_SIG_ARCH_ANY,
};

/* supported file types */
#define RZ_FLIRT_SIG_FILE_DOS_EXE_OLD 0x00000001
#define RZ_FLIRT_SIG_FILE_DOS_COM_OLD 0x00000002
#define RZ_FLIRT_SIG_FILE_BIN         0x00000004
#define RZ_FLIRT_SIG_FILE_DOSDRV      0x00000008
#define RZ_FLIRT_SIG_FILE_NE          0x00000010
#define RZ_FLIRT_SIG_FILE_INTELHEX    0x00000020
#define RZ_FLIRT_SIG_FILE_MOSHEX      0x00000040
#define RZ_FLIRT_SIG_FILE_LX          0x00000080
#define RZ_FLIRT_SIG_FILE_LE          0x00000100
#define RZ_FLIRT_SIG_FILE_NLM         0x00000200
#define RZ_FLIRT_SIG_FILE_COFF        0x00000400
#define RZ_FLIRT_SIG_FILE_PE          0x00000800
#define RZ_FLIRT_SIG_FILE_OMF         0x00001000
#define RZ_FLIRT_SIG_FILE_SREC        0x00002000
#define RZ_FLIRT_SIG_FILE_ZIP         0x00004000
#define RZ_FLIRT_SIG_FILE_OMFLIB      0x00008000
#define RZ_FLIRT_SIG_FILE_AR          0x00010000
#define RZ_FLIRT_SIG_FILE_LOADER      0x00020000
#define RZ_FLIRT_SIG_FILE_ELF         0x00040000
#define RZ_FLIRT_SIG_FILE_W32RUN      0x00080000
#define RZ_FLIRT_SIG_FILE_AOUT        0x00100000
#define RZ_FLIRT_SIG_FILE_PILOT       0x00200000
#define RZ_FLIRT_SIG_FILE_DOS_EXE     0x00400000
#define RZ_FLIRT_SIG_FILE_DOS_COM     0x00800000
#define RZ_FLIRT_SIG_FILE_AIXAR       0x01000000
#define RZ_FLIRT_SIG_FILE_ALL         0xFFFFFFFF

/* supported os types */
#define RZ_FLIRT_SIG_OS_MSDOS   0x0001
#define RZ_FLIRT_SIG_OS_WIN     0x0002
#define RZ_FLIRT_SIG_OS_OS2     0x0004
#define RZ_FLIRT_SIG_OS_NETWARE 0x0008
#define RZ_FLIRT_SIG_OS_UNIX    0x0010
#define RZ_FLIRT_SIG_OS_OTHER   0x0020
#define RZ_FLIRT_SIG_OS_ALL     0xFFFF

/* supported app types */
#define RZ_FLIRT_SIG_APP_CONSOLE         0x0001
#define RZ_FLIRT_SIG_APP_GRAPHICS        0x0002
#define RZ_FLIRT_SIG_APP_EXE             0x0004
#define RZ_FLIRT_SIG_APP_DLL             0x0008
#define RZ_FLIRT_SIG_APP_DRV             0x0010
#define RZ_FLIRT_SIG_APP_SINGLE_THREADED 0x0020
#define RZ_FLIRT_SIG_APP_MULTI_THREADED  0x0040
#define RZ_FLIRT_SIG_APP_16_BIT          0x0080
#define RZ_FLIRT_SIG_APP_32_BIT          0x0100
#define RZ_FLIRT_SIG_APP_64_BIT          0x0200
#define RZ_FLIRT_SIG_APP_ALL             0xFFFF

typedef struct rz_flirt_tail_byte_t {
	ut16 offset; // from pattern_size + crc_length
	ut8 value;
} RzFlirtTailByte;

typedef struct rz_flirt_function_t {
	char name[RZ_FLIRT_NAME_MAX];
	ut32 offset; // function offset from the module start
	bool negative_offset; // true if offset is negative, for referenced functions
	bool is_local; // true if function is static
	bool is_collision; // true if was an unresolved collision
} RzFlirtFunction;

typedef struct rz_flirt_module_t {
	ut32 crc_length;
	ut32 crc16; // crc16 of the module after the pattern bytes
	// until but not including the first variant byte
	// this is a custom crc16
	ut32 length; // total length of the module
	RzList /*<RzFlirtFunction *>*/ *public_functions;
	RzList /*<RzFlirtTailByte *>*/ *tail_bytes;
	RzList /*<RzFlirtFunction *>*/ *referenced_functions;
} RzFlirtModule;

typedef struct rz_flirt_node_t {
	RzList /*<RzFlirtNode *>*/ *child_list;
	RzList /*<RzFlirtModule *>*/ *module_list;
	ut32 length; // length of the pattern
	ut64 variant_mask; // this is the mask that will define variant bytes in ut8 *pattern_bytes
	ut8 *pattern_bytes; // holds the pattern bytes of the signature
	ut8 *pattern_mask; // bool array, if true, byte in pattern_bytes is a variant byte
} RzFlirtNode;

enum rz_flirt_node_optimization_t {
	RZ_FLIRT_NODE_OPTIMIZE_NONE = 0, ///< keeps the structure flattened (keep the tail bytes)
	RZ_FLIRT_NODE_OPTIMIZE_NORMAL, ///< optimize the tree structure (keeps the tail bytes)
	RZ_FLIRT_NODE_OPTIMIZE_MAX, ///< optimize the tree structure and drops the tail bytes
};

typedef enum rz_flirt_file_type_t {
	RZ_FLIRT_FILE_TYPE_UNKNOWN = 0, ///< unknown type
	RZ_FLIRT_FILE_TYPE_SIG, ///< `.sig` compressed pattern file
	RZ_FLIRT_FILE_TYPE_PAT, ///< `.pat` text format pattern file
} RzFlirtFileType;

typedef struct rz_flirt_sig_info_t {
	ut8 version; ///< FLIRT sig version
	ut8 architecture; ///< FLIRT sig architecture/processor id
	ut32 n_modules; ///< FLIRT sig total number of modules/signatures contained
	char *name; ///< FLIRT sig name
} RzFlirtSigInfo;

typedef struct rz_flirt_pat_info_t {
	ut32 n_modules; ///< FLIRT pat total number of modules/signatures contained
} RzFlirtPatInfo;

typedef struct rz_flirt_info_t {
	RzFlirtFileType type; ///< Flirt file type
	union {
		RzFlirtSigInfo sig; ///< Sig info
		RzFlirtPatInfo pat; ///< Pat info
	} u;
} RzFlirtInfo;

RZ_API ut32 rz_sign_flirt_node_count_nodes(RZ_NONNULL const RzFlirtNode *node);
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_node_new(RZ_NONNULL RzAnalysis *analysis, ut32 optimization, bool ignore_unknown);
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_node_from_function(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *func, bool tail_bytes);
RZ_API void rz_sign_flirt_node_free(RZ_NULLABLE RzFlirtNode *node);
RZ_API void rz_sign_flirt_info_fini(RZ_NULLABLE RzFlirtInfo *info);

RZ_API bool rz_sign_flirt_apply(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const char *flirt_file, ut8 expected_arch);

typedef struct rz_flirt_compressed_options_t {
	ut8 version; ///< FLIRT version (supported only from v5 to v10)
	ut8 arch; ///< FLIRT arch type (RZ_FLIRT_SIG_ARCH_*)
	ut32 file; ///< FLIRT file type (RZ_FLIRT_SIG_FILE_*)
	ut16 os; ///< FLIRT os type (RZ_FLIRT_SIG_OS_*)
	ut16 app; ///< FLIRT app type (RZ_FLIRT_SIG_APP_*)
	bool deflate;
	const char *libname;
} RzFlirtCompressedOptions;

RZ_API RZ_OWN bool rz_sign_flirt_parse_header_compressed_pattern_from_buffer(RZ_NONNULL RzBuffer *flirt_buf, RZ_NONNULL RzFlirtInfo *info);
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_parse_compressed_pattern_from_buffer(RZ_NONNULL RzBuffer *flirt_buf, ut8 expected_arch, RZ_NULLABLE RzFlirtInfo *info);
RZ_API bool rz_sign_flirt_write_compressed_pattern_to_buffer(RZ_NONNULL const RzFlirtNode *node, RZ_NONNULL RzBuffer *buffer, RzFlirtCompressedOptions *options);

RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_parse_string_pattern_from_buffer(RZ_NONNULL RzBuffer *flirt_buf, ut32 optimization, RZ_NULLABLE RzFlirtInfo *info);
RZ_API bool rz_sign_flirt_write_string_pattern_to_buffer(RZ_NONNULL const RzFlirtNode *node, RZ_NONNULL RzBuffer *buffer);

typedef struct rz_signature_database_entry_t {
	char *bin_name; ///< RzBinPlugin name (elf64 and pe64 are named as elf and pe)
	char *arch_name; ///< RzAsmPlugin name
	ut32 arch_bits; ///< Architecture bits
	const char *base_name; ///< basename of file
	const char *short_path; ///< Short path without sigdb path
	char *file_path; ///< full path to the signature file
	char *details; ///< signature name / description (only for .sig files)
	ut32 n_modules; ///< signature number of modules
} RzSigDBEntry;

typedef struct rz_signature_db_t {
	HtPU *entries;
} RzSigDb;

RZ_API void rz_sign_sigdb_signature_free(RZ_NULLABLE RzSigDBEntry *entry);
RZ_API RZ_OWN RzSigDb *rz_sign_sigdb_new(void);
RZ_API void rz_sign_sigdb_free(RzSigDb *db);
RZ_API RZ_OWN RzSigDb *rz_sign_sigdb_load_database(RZ_NONNULL const char *sigdb_path, bool with_details);
RZ_API bool rz_sign_sigdb_add_entry(RZ_NONNULL RzSigDb *db, RZ_NONNULL const RzSigDBEntry *entry);
RZ_API bool rz_sign_sigdb_merge(RZ_NONNULL RzSigDb *db, RZ_NONNULL RzSigDb *db2);
RZ_API RZ_OWN RzList /*<RzSigDBEntry *>*/ *rz_sign_sigdb_list(RZ_NONNULL const RzSigDb *db);

#ifdef __cplusplus
}
#endif

#endif /* RZ_FLIRT_H */
