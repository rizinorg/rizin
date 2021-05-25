// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

// http://www.sco.com/developers/gabi/latest/ch4.eheader.html
char *Elf_(rz_bin_elf_get_machine_name)(ELFOBJ *bin) {
	switch (bin->ehdr.e_machine) {
	case EM_NONE: return strdup("No machine");
	case EM_M32: return strdup("AT&T WE 32100");
	case EM_SPARC: return strdup("SUN SPARC");
	case EM_386: return strdup("Intel 80386");
	case EM_68K: return strdup("Motorola m68k family");
	case EM_88K: return strdup("Motorola m88k family");
	case EM_860: return strdup("Intel 80860");
	case EM_MIPS: return strdup("MIPS R3000");
	case EM_S370: return strdup("IBM System/370");
	case EM_MIPS_RS3_LE: return strdup("MIPS R3000 little-endian");
	case EM_PARISC: return strdup("HPPA");
	case EM_VPP500: return strdup("Fujitsu VPP500");
	case EM_SPARC32PLUS: return strdup("Sun's \"v8plus\"");
	case EM_960: return strdup("Intel 80960");
	case EM_PPC: return strdup("PowerPC");
	case EM_PPC64: return strdup("PowerPC 64-bit");
	case EM_S390: return strdup("IBM S390");
	case EM_V800: return strdup("NEC V800 series");
	case EM_FR20: return strdup("Fujitsu FR20");
	case EM_RH32: return strdup("TRW RH-32");
	case EM_RCE: return strdup("Motorola RCE");
	case EM_ARM: return strdup("ARM");
	case EM_BLACKFIN: return strdup("Analog Devices Blackfin");
	case EM_FAKE_ALPHA: return strdup("Digital Alpha");
	case EM_SH: return strdup("Hitachi SH");
	case EM_SPARCV9: return strdup("SPARC v9 64-bit");
	case EM_TRICORE: return strdup("Siemens Tricore");
	case EM_ARC: return strdup("Argonaut RISC Core");
	case EM_H8_300: return strdup("Hitachi H8/300");
	case EM_H8_300H: return strdup("Hitachi H8/300H");
	case EM_H8S: return strdup("Hitachi H8S");
	case EM_H8_500: return strdup("Hitachi H8/500");
	case EM_IA_64: return strdup("Intel Merced");
	case EM_MIPS_X: return strdup("Stanford MIPS-X");
	case EM_COLDFIRE: return strdup("Motorola Coldfire");
	case EM_68HC12: return strdup("Motorola M68HC12");
	case EM_MMA: return strdup("Fujitsu MMA Multimedia Accelerator");
	case EM_PCP: return strdup("Siemens PCP");
	case EM_NCPU: return strdup("Sony nCPU embeeded RISC");
	case EM_NDR1: return strdup("Denso NDR1 microprocessor");
	case EM_STARCORE: return strdup("Motorola Start*Core processor");
	case EM_ME16: return strdup("Toyota ME16 processor");
	case EM_ST100: return strdup("STMicroelectronic ST100 processor");
	case EM_TINYJ: return strdup("Advanced Logic Corp. Tinyj emb.fam");
	case EM_X86_64: return strdup("AMD x86-64 architecture");
	case EM_LANAI: return strdup("32bit LANAI architecture");
	case EM_PDSP: return strdup("Sony DSP Processor");
	case EM_PDP10: return strdup("Digital Equipment Corp. PDP-10");
	case EM_PDP11: return strdup("Digital Equipment Corp. PDP-11");
	case EM_FX66: return strdup("Siemens FX66 microcontroller");
	case EM_ST9PLUS: return strdup("STMicroelectronics ST9+ 8/16 mc");
	case EM_ST7: return strdup("STmicroelectronics ST7 8 bit mc");
	case EM_68HC16: return strdup("Motorola MC68HC16 microcontroller");
	case EM_68HC11: return strdup("Motorola MC68HC11 microcontroller");
	case EM_68HC08: return strdup("Motorola MC68HC08 microcontroller");
	case EM_68HC05: return strdup("Motorola MC68HC05 microcontroller");
	case EM_SVX: return strdup("Silicon Graphics SVx");
	case EM_ST19: return strdup("STMicroelectronics ST19 8 bit mc");
	case EM_VAX: return strdup("Digital VAX");
	case EM_CRIS: return strdup("Axis Communications 32-bit embedded processor");
	case EM_JAVELIN: return strdup("Infineon Technologies 32-bit embedded processor");
	case EM_FIREPATH: return strdup("Element 14 64-bit DSP Processor");
	case EM_ZSP: return strdup("LSI Logic 16-bit DSP Processor");
	case EM_MMIX: return strdup("Donald Knuth's educational 64-bit processor");
	case EM_HUANY: return strdup("Harvard University machine-independent object files");
	case EM_PRISM: return strdup("SiTera Prism");
	case EM_AVR: return strdup("Atmel AVR 8-bit microcontroller");
	case EM_FR30: return strdup("Fujitsu FR30");
	case EM_D10V: return strdup("Mitsubishi D10V");
	case EM_D30V: return strdup("Mitsubishi D30V");
	case EM_V850: return strdup("NEC v850");
	case EM_M32R: return strdup("Mitsubishi M32R");
	case EM_MN10300: return strdup("Matsushita MN10300");
	case EM_MN10200: return strdup("Matsushita MN10200");
	case EM_PJ: return strdup("picoJava");
	case EM_OPENRISC: return strdup("OpenRISC 32-bit embedded processor");
	case EM_ARC_A5: return strdup("ARC Cores Tangent-A5");
	case EM_XTENSA: return strdup("Tensilica Xtensa Architecture");
	case EM_AARCH64: return strdup("ARM aarch64");
	case EM_PROPELLER: return strdup("Parallax Propeller");
	case EM_MICROBLAZE: return strdup("Xilinx MicroBlaze");
	case EM_RISCV: return strdup("RISC V");
	case EM_VIDEOCORE3: return strdup("VideoCore III");
	case EM_VIDEOCORE4: return strdup("VideoCore IV");
	case EM_LATTICEMICO32: return strdup("RISC processor for Lattice FPGA architecture");
	case EM_SE_C17: return strdup("Seiko Epson C17 family");
	case EM_TI_C6000: return strdup("The Texas Instruments TMS320C6000 DSP family");
	case EM_TI_C2000: return strdup("The Texas Instruments TMS320C2000 DSP family");
	case EM_TI_C5500: return strdup("The Texas Instruments TMS320C55x DSP family");
	case EM_TI_ARP32: return strdup("Texas Instruments Application Specific RISC Processor, 32bit fetch");
	case EM_TI_PRU: return strdup("Texas Instruments Programmable Realtime Unit");
	case EM_MMDSP_PLUS: return strdup("STMicroelectronics 64bit VLIW Data Signal Processor");
	case EM_CYPRESS_M8C: return strdup("Cypress M8C microprocessor");
	case EM_R32C: return strdup("Renesas R32C series microprocessors");
	case EM_TRIMEDIA: return strdup("NXP Semiconductors TriMedia architecture family");
	case EM_QDSP6: return strdup("QUALCOMM DSP6 Processor"); // Nonstandard
	case EM_8051: return strdup("Intel 8051 and variants");
	case EM_STXP7X: return strdup("STMicroelectronics STxP7x family of configurable and extensible RISC processors");
	case EM_NDS32: return strdup("Andes Technology compact code size embedded RISC processor family");
	case EM_ECOG1: return strdup("Cyan Technology eCOG1X family");
	// case EM_ECOG1X:        return strdup ("Cyan Technology eCOG1X family");  // Nonstandard
	case EM_MAXQ30: return strdup("Dallas Semiconductor MAXQ30 Core Micro-controllers");
	case EM_XIMO16: return strdup("New Japan Radio (NJR) 16-bit DSP Processor");
	case EM_MANIK: return strdup("M2000 Reconfigurable RISC Microprocessor");
	case EM_CRAYNV2: return strdup("Cray Inc. NV2 vector architecture");
	case EM_RX: return strdup("Renesas RX family");
	case EM_METAG: return strdup("Imagination Technologies META processor architecture");
	case EM_MCST_ELBRUS: return strdup("MCST Elbrus general purpose hardware architecture");
	case EM_ECOG16: return strdup("Cyan Technology eCOG16 family");
	case EM_CR16: return strdup("National Semiconductor CompactRISC CR16 16-bit microprocessor");
	case EM_ETPU: return strdup("Freescale Extended Time Processing Unit");
	case EM_SLE9X: return strdup("Infineon Technologies SLE9X core");
	case EM_L10M: return strdup("Intel L10M");
	case EM_K10M: return strdup("Intel K10M");
	// case EM_AARCH64:       return strdup ("ARM 64-bit architecture (AARCH64)");  // Nonstandard
	case EM_AVR32: return strdup("Atmel Corporation 32-bit microprocessor family");
	case EM_STM8: return strdup("STMicroeletronics STM8 8-bit microcontroller");
	case EM_TILE64: return strdup("Tilera TILE64 multicore architecture family");
	case EM_TILEPRO: return strdup("Tilera TILEPro multicore architecture family");
	// case EM_MICROBLAZE:    return strdup ("Xilinx MicroBlaze 32-bit RISC soft processor core");  // Nonstandard
	case EM_CUDA: return strdup("NVIDIA CUDA architecture");
	case EM_TILEGX: return strdup("Tilera TILE-Gx multicore architecture family");
	case EM_CLOUDSHIELD: return strdup("CloudShield architecture family");
	case EM_COREA_1ST: return strdup("KIPO-KAIST Core-A 1st generation processor family");
	case EM_COREA_2ND: return strdup("KIPO-KAIST Core-A 2nd generation processor family");
	case EM_ARC_COMPACT2: return strdup("Synopsys ARCompact V2");
	case EM_OPEN8: return strdup("Open8 8-bit RISC soft processor core");
	case EM_RL78: return strdup("Renesas RL78 family");
	case EM_VIDEOCORE5: return strdup("Broadcom VideoCore V processor");
	case EM_78KOR: return strdup("Renesas 78KOR family");
	// case EM_56800EX:       return strdup ("Freescale 56800EX Digital Signal Controller (DSC)");  // Nonstandard
	case EM_BA1: return strdup("Beyond BA1 CPU architecture");
	case EM_BA2_NON_STANDARD:
	case EM_BA2: return strdup("Beyond BA2 CPU architecture");
	case EM_XCORE: return strdup("XMOS xCORE processor family");
	case EM_MCHP_PIC: return strdup("Microchip 8-bit PIC(r) family");
	case EM_INTEL205: return strdup("Reserved by Intel");
	case EM_INTEL206: return strdup("Reserved by Intel");
	case EM_INTEL207: return strdup("Reserved by Intel");
	case EM_INTEL208: return strdup("Reserved by Intel");
	case EM_INTEL209: return strdup("Reserved by Intel");
	case EM_KM32: return strdup("KM211 KM32 32-bit processor");
	case EM_KMX32: return strdup("KM211 KMX32 32-bit processor");
	case EM_KMX16: return strdup("KM211 KMX16 16-bit processor");
	case EM_KMX8: return strdup("KM211 KMX8 8-bit processor");
	case EM_KVARC: return strdup("KM211 KVARC processor");
	case EM_CDP: return strdup("Paneve CDP architecture family");
	case EM_COGE: return strdup("Cognitive Smart Memory Processor");
	case EM_COOL: return strdup("Bluechip Systems CoolEngine");
	case EM_NORC: return strdup("Nanoradio Optimized RISC");
	case EM_CSR_KALIMBA: return strdup("CSR Kalimba architecture family");
	case EM_Z80: return strdup("Zilog Z80");
	case EM_VISIUM: return strdup("Controls and Data Services VISIUMcore processor");
	case EM_FT32: return strdup("FTDI Chip FT32 high performance 32-bit RISC architecture");
	case EM_MOXIE: return strdup("Moxie processor family");
	case EM_AMDGPU: return strdup("AMD GPU architecture");

	default: return rz_str_newf("<unknown>: 0x%x", bin->ehdr.e_machine);
	}
}
