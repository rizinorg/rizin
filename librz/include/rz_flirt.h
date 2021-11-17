// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FLIRT_H
#define RZ_FLIRT_H

#include <rz_list.h>
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_FLIRT_NAME_MAX 1024

#define RZ_FLIRT_SIG_ARCH_386       0 // Intel 80x86
#define RZ_FLIRT_SIG_ARCH_Z80       1 // 8085, Z80
#define RZ_FLIRT_SIG_ARCH_I860      2 // Intel 860
#define RZ_FLIRT_SIG_ARCH_8051      3 // 8051
#define RZ_FLIRT_SIG_ARCH_TMS       4 // Texas Instruments TMS320C5x
#define RZ_FLIRT_SIG_ARCH_6502      5 // 6502
#define RZ_FLIRT_SIG_ARCH_PDP       6 // PDP11
#define RZ_FLIRT_SIG_ARCH_68K       7 // Motoroal 680x0
#define RZ_FLIRT_SIG_ARCH_JAVA      8 // Java
#define RZ_FLIRT_SIG_ARCH_6800      9 // Motorola 68xx
#define RZ_FLIRT_SIG_ARCH_ST7       10 // SGS-Thomson ST7
#define RZ_FLIRT_SIG_ARCH_MC6812    11 // Motorola 68HC12
#define RZ_FLIRT_SIG_ARCH_MIPS      12 // MIPS
#define RZ_FLIRT_SIG_ARCH_ARM       13 // Advanced RISC Machines
#define RZ_FLIRT_SIG_ARCH_TMSC6     14 // Texas Instruments TMS320C6x
#define RZ_FLIRT_SIG_ARCH_PPC       15 // PowerPC
#define RZ_FLIRT_SIG_ARCH_80196     16 // Intel 80196
#define RZ_FLIRT_SIG_ARCH_Z8        17 // Z8
#define RZ_FLIRT_SIG_ARCH_SH        18 // Renesas (formerly Hitachi) SuperH
#define RZ_FLIRT_SIG_ARCH_NET       19 // Microsoft Visual Studio.Net
#define RZ_FLIRT_SIG_ARCH_AVR       20 // Atmel 8-bit RISC processor(s)
#define RZ_FLIRT_SIG_ARCH_H8        21 // Hitachi H8/300, H8/2000
#define RZ_FLIRT_SIG_ARCH_PIC       22 // Microchip's PIC
#define RZ_FLIRT_SIG_ARCH_SPARC     23 // SPARC
#define RZ_FLIRT_SIG_ARCH_ALPHA     24 // DEC Alpha
#define RZ_FLIRT_SIG_ARCH_HPPA      25 // Hewlett-Packard PA-RISC
#define RZ_FLIRT_SIG_ARCH_H8500     26 // Hitachi H8/500
#define RZ_FLIRT_SIG_ARCH_TRICORE   27 // Tasking Tricore
#define RZ_FLIRT_SIG_ARCH_DSP56K    28 // Motorola DSP5600x
#define RZ_FLIRT_SIG_ARCH_C166      29 // Siemens C166 family
#define RZ_FLIRT_SIG_ARCH_ST20      30 // SGS-Thomson ST20
#define RZ_FLIRT_SIG_ARCH_IA64      31 // Intel Itanium IA64
#define RZ_FLIRT_SIG_ARCH_I960      32 // Intel 960
#define RZ_FLIRT_SIG_ARCH_F2MC      33 // Fujistu F2MC-16
#define RZ_FLIRT_SIG_ARCH_TMS320C54 34 // Texas Instruments TMS320C54xx
#define RZ_FLIRT_SIG_ARCH_TMS320C55 35 // Texas Instruments TMS320C55xx
#define RZ_FLIRT_SIG_ARCH_TRIMEDIA  36 // Trimedia
#define RZ_FLIRT_SIG_ARCH_M32R      37 // Mitsubishi 32bit RISC
#define RZ_FLIRT_SIG_ARCH_NEC_78K0  38 // NEC 78K0
#define RZ_FLIRT_SIG_ARCH_NEC_78K0S 39 // NEC 78K0S
#define RZ_FLIRT_SIG_ARCH_M740      40 // Mitsubishi 8bit
#define RZ_FLIRT_SIG_ARCH_M7700     41 // Mitsubishi 16bit
#define RZ_FLIRT_SIG_ARCH_ST9       42 // ST9+
#define RZ_FLIRT_SIG_ARCH_FR        43 // Fujitsu FR Family
#define RZ_FLIRT_SIG_ARCH_MC6816    44 // Motorola 68HC16
#define RZ_FLIRT_SIG_ARCH_M7900     45 // Mitsubishi 7900
#define RZ_FLIRT_SIG_ARCH_TMS320C3  46 // Texas Instruments TMS320C3
#define RZ_FLIRT_SIG_ARCH_KR1878    47 // Angstrem KR1878
#define RZ_FLIRT_SIG_ARCH_AD218X    48 // Analog Devices ADSP 218X
#define RZ_FLIRT_SIG_ARCH_OAKDSP    49 // Atmel OAK DSP
#define RZ_FLIRT_SIG_ARCH_TLCS900   50 // Toshiba TLCS-900
#define RZ_FLIRT_SIG_ARCH_C39       51 // Rockwell C39
#define RZ_FLIRT_SIG_ARCH_CR16      52 // NSC CR16
#define RZ_FLIRT_SIG_ARCH_MN102L00  53 // Panasonic MN10200
#define RZ_FLIRT_SIG_ARCH_TMS320C1X 54 // Texas Instruments TMS320C1x
#define RZ_FLIRT_SIG_ARCH_NEC_V850X 55 // NEC V850 and V850ES/E1/E2
#define RZ_FLIRT_SIG_ARCH_SCR_ADPT  56 // Processor module adapter for processor modules written in scripting languages
#define RZ_FLIRT_SIG_ARCH_EBC       57 // EFI Bytecode
#define RZ_FLIRT_SIG_ARCH_MSP430    58 // Texas Instruments MSP430
#define RZ_FLIRT_SIG_ARCH_SPU       59 // Cell Broadband Engine Synergistic Processor Unit
#define RZ_FLIRT_SIG_ARCH_DALVIK    60 // Android Dalvik Virtual Machine
#define RZ_FLIRT_SIG_ARCH_ANY       UT32_MAX

typedef struct RzFlirtTailByte {
	ut16 offset; // from pattern_size + crc_length
	ut8 value;
} RzFlirtTailByte;

typedef struct RzFlirtFunction {
	char name[RZ_FLIRT_NAME_MAX];
	ut16 offset; // function offset from the module start
	ut8 negative_offset; // true if offset is negative, for referenced functions
	ut8 is_local; // true if function is static
	ut8 is_collision; // true if was an unresolved collision
} RzFlirtFunction;

typedef struct RzFlirtModule {
	ut32 crc_length;
	ut32 crc16; // crc16 of the module after the pattern bytes
	// until but not including the first variant byte
	// this is a custom crc16
	ut32 length; // total length of the module
	RzList *public_functions;
	RzList *tail_bytes;
	RzList *referenced_functions;
} RzFlirtModule;

typedef struct RzFlirtNode {
	RzList *child_list;
	RzList *module_list;
	ut32 length; // length of the pattern
	ut64 variant_mask; // this is the mask that will define variant bytes in ut8 *pattern_bytes
	ut8 *pattern_bytes; // holds the pattern bytes of the signature
	ut8 *pattern_mask; // bool array, if true, byte in pattern_bytes is a variant byte
} RzFlirtNode;

RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_parse_compressed_buffer(RZ_NONNULL RzBuffer *flirt_buf, ut32 expected_arch);
RZ_API RZ_OWN RzFlirtNode *rz_sign_flirt_parse_string_buffer(RZ_NONNULL RzBuffer *flirt_buf);
RZ_API void rz_sign_flirt_node_free(RZ_NULLABLE RzFlirtNode *node);
RZ_API ut8 rz_sign_flirt_get_version(RZ_NONNULL RzBuffer *buffer);
RZ_API ut32 rz_sign_flirt_id_from_name(RZ_NONNULL const char *arch);
RZ_API void rz_sign_flirt_apply(RzAnalysis *analysis, const char *flirt_file, const char *arch);

#ifdef __cplusplus
}
#endif

#endif /* RZ_FLIRT_H */
