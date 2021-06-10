// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define EF_MIPS_ABI_O32 0x00001000 /* O32 ABI.  */
#define EF_MIPS_ABI_O64 0x00002000 /* O32 extended for 64 bit.  */
#define EF_MIPS_ABI     0x0000f000

#define VERSYM_VERSION 0x7fff

struct mips_bits_translation {
	Elf_(Word) type;
	int bits;
};

struct section_note_osabi_translation {
	const char *note_name;
	const char *os_name;
};

struct machine_name_translation {
	Elf_(Half) machine;
	const char *name;
};

struct class_translation {
	unsigned char class;
	const char *name;
};

struct cpu_mips_translation {
	Elf_(Word) arch;
	const char *name;
};

struct arch_translation {
	Elf_(Half) arch;
	const char *name;
};

struct ver_flags_translation {
	ut32 flag;
	const char *name;
};

static const struct mips_bits_translation mips_bits_translation_table[] = {
	{ EF_MIPS_ARCH_1, 32 },
	{ EF_MIPS_ARCH_2, 32 },
	{ EF_MIPS_ARCH_3, 32 },
	{ EF_MIPS_ARCH_4, 32 },
	{ EF_MIPS_ARCH_5, 32 },
	{ EF_MIPS_ARCH_32, 32 },
	{ EF_MIPS_ARCH_64, 64 },
	{ EF_MIPS_ARCH_32R2, 32 },
	{ EF_MIPS_ARCH_64R2, 64 }
};

static const struct section_note_osabi_translation section_note_osabi_translation_table[] = {
	{ ".note.openbsd.ident", "openbsd" },
	{ ".note.minix.ident", "minix" },
	{ ".note.netbsd.ident", "netbsd" },
	{ ".note.android.ident", "android" }
};

static const struct machine_name_translation machine_name_translation_table[] = {
	{ EM_NONE, "No machine" },
	{ EM_M32, "AT&T WE 32100" },
	{ EM_SPARC, "SUN SPARC" },
	{ EM_386, "Intel 80386" },
	{ EM_68K, "Motorola m68k family" },
	{ EM_88K, "Motorola m88k family" },
	{ EM_860, "Intel 80860" },
	{ EM_MIPS, "MIPS R3000" },
	{ EM_S370, "IBM System/370" },
	{ EM_MIPS_RS3_LE, "MIPS R3000 little-endian" },
	{ EM_PARISC, "HPPA" },
	{ EM_VPP500, "Fujitsu VPP500" },
	{ EM_SPARC32PLUS, "Sun's \"v8plus\"" },
	{ EM_960, "Intel 80960" },
	{ EM_PPC, "PowerPC" },
	{ EM_PPC64, "PowerPC 64-bit" },
	{ EM_S390, "IBM S390" },
	{ EM_V800, "NEC V800 series" },
	{ EM_FR20, "Fujitsu FR20" },
	{ EM_RH32, "TRW RH-32" },
	{ EM_RCE, "Motorola RCE" },
	{ EM_ARM, "ARM" },
	{ EM_BLACKFIN, "Analog Devices Blackfin" },
	{ EM_FAKE_ALPHA, "Digital Alpha" },
	{ EM_SH, "Hitachi SH" },
	{ EM_SPARCV9, "SPARC v9 64-bit" },
	{ EM_TRICORE, "Siemens Tricore" },
	{ EM_ARC, "Argonaut RISC Core" },
	{ EM_H8_300, "Hitachi H8/300" },
	{ EM_H8_300H, "Hitachi H8/300H" },
	{ EM_H8S, "Hitachi H8S" },
	{ EM_H8_500, "Hitachi H8/500" },
	{ EM_IA_64, "Intel Merced" },
	{ EM_MIPS_X, "Stanford MIPS-X" },
	{ EM_COLDFIRE, "Motorola Coldfire" },
	{ EM_68HC12, "Motorola M68HC12" },
	{ EM_MMA, "Fujitsu MMA Multimedia Accelerator" },
	{ EM_PCP, "Siemens PCP" },
	{ EM_NCPU, "Sony nCPU embeeded RISC" },
	{ EM_NDR1, "Denso NDR1 microprocessor" },
	{ EM_STARCORE, "Motorola Start*Core processor" },
	{ EM_ME16, "Toyota ME16 processor" },
	{ EM_ST100, "STMicroelectronic ST100 processor" },
	{ EM_TINYJ, "Advanced Logic Corp. Tinyj emb.fam" },
	{ EM_X86_64, "AMD x86-64 architecture" },
	{ EM_LANAI, "32bit LANAI architecture" },
	{ EM_PDSP, "Sony DSP Processor" },
	{ EM_PDP10, "Digital Equipment Corp. PDP-10" },
	{ EM_PDP11, "Digital Equipment Corp. PDP-11" },
	{ EM_FX66, "Siemens FX66 microcontroller" },
	{ EM_ST9PLUS, "STMicroelectronics ST9+ 8/16 mc" },
	{ EM_ST7, "STmicroelectronics ST7 8 bit mc" },
	{ EM_68HC16, "Motorola MC68HC16 microcontroller" },
	{ EM_68HC11, "Motorola MC68HC11 microcontroller" },
	{ EM_68HC08, "Motorola MC68HC08 microcontroller" },
	{ EM_68HC05, "Motorola MC68HC05 microcontroller" },
	{ EM_SVX, "Silicon Graphics SVx" },
	{ EM_ST19, "STMicroelectronics ST19 8 bit mc" },
	{ EM_VAX, "Digital VAX" },
	{ EM_CRIS, "Axis Communications 32-bit embedded processor" },
	{ EM_JAVELIN, "Infineon Technologies 32-bit embedded processor" },
	{ EM_FIREPATH, "Element 14 64-bit DSP Processor" },
	{ EM_ZSP, "LSI Logic 16-bit DSP Processor" },
	{ EM_MMIX, "Donald Knuth's educational 64-bit processor" },
	{ EM_HUANY, "Harvard University machine-independent object files" },
	{ EM_PRISM, "SiTera Prism" },
	{ EM_AVR, "Atmel AVR 8-bit microcontroller" },
	{ EM_FR30, "Fujitsu FR30" },
	{ EM_D10V, "Mitsubishi D10V" },
	{ EM_D30V, "Mitsubishi D30V" },
	{ EM_V850, "NEC v850" },
	{ EM_M32R, "Mitsubishi M32R" },
	{ EM_MN10300, "Matsushita MN10300" },
	{ EM_MN10200, "Matsushita MN10200" },
	{ EM_PJ, "picoJava" },
	{ EM_OPENRISC, "OpenRISC 32-bit embedded processor" },
	{ EM_ARC_A5, "ARC Cores Tangent-A5" },
	{ EM_XTENSA, "Tensilica Xtensa Architecture" },
	{ EM_AARCH64, "ARM aarch64" },
	{ EM_PROPELLER, "Parallax Propeller" },
	{ EM_MICROBLAZE, "Xilinx MicroBlaze" },
	{ EM_RISCV, "RISC V" },
	{ EM_VIDEOCORE3, "VideoCore III" },
	{ EM_VIDEOCORE4, "VideoCore IV" },
	{ EM_LATTICEMICO32, "RISC processor for Lattice FPGA architecture" },
	{ EM_SE_C17, "Seiko Epson C17 family" },
	{ EM_TI_C6000, "The Texas Instruments TMS320C6000 DSP family" },
	{ EM_TI_C2000, "The Texas Instruments TMS320C2000 DSP family" },
	{ EM_TI_C5500, "The Texas Instruments TMS320C55x DSP family" },
	{ EM_TI_ARP32, "Texas Instruments Application Specific RISC Processor, 32bit fetch" },
	{ EM_TI_PRU, "Texas Instruments Programmable Realtime Unit" },
	{ EM_MMDSP_PLUS, "STMicroelectronics 64bit VLIW Data Signal Processor" },
	{ EM_CYPRESS_M8C, "Cypress M8C microprocessor" },
	{ EM_R32C, "Renesas R32C series microprocessors" },
	{ EM_TRIMEDIA, "NXP Semiconductors TriMedia architecture family" },
	{ EM_QDSP6, "QUALCOMM DSP6 Processor" }, // Nonstandard
	{ EM_8051, "Intel 8051 and variants" },
	{ EM_STXP7X, "STMicroelectronics STxP7x family of configurable and extensible RISC processors" },
	{ EM_NDS32, "Andes Technology compact code size embedded RISC processor family" },
	{ EM_ECOG1, "Cyan Technology eCOG1X family" },
	{ EM_MAXQ30, "Dallas Semiconductor MAXQ30 Core Micro-controllers" },
	{ EM_XIMO16, "New Japan Radio (NJR) 16-bit DSP Processor" },
	{ EM_MANIK, "M2000 Reconfigurable RISC Microprocessor" },
	{ EM_CRAYNV2, "Cray Inc. NV2 vector architecture" },
	{ EM_RX, "Renesas RX family" },
	{ EM_METAG, "Imagination Technologies META processor architecture" },
	{ EM_MCST_ELBRUS, "MCST Elbrus general purpose hardware architecture" },
	{ EM_ECOG16, "Cyan Technology eCOG16 family" },
	{ EM_CR16, "National Semiconductor CompactRISC CR16 16-bit microprocessor" },
	{ EM_ETPU, "Freescale Extended Time Processing Unit" },
	{ EM_SLE9X, "Infineon Technologies SLE9X core" },
	{ EM_L10M, "Intel L10M" },
	{ EM_K10M, "Intel K10M" },
	{ EM_AVR32, "Atmel Corporation 32-bit microprocessor family" },
	{ EM_STM8, "STMicroeletronics STM8 8-bit microcontroller" },
	{ EM_TILE64, "Tilera TILE64 multicore architecture family" },
	{ EM_TILEPRO, "Tilera TILEPro multicore architecture family" },
	{ EM_CUDA, "NVIDIA CUDA architecture" },
	{ EM_TILEGX, "Tilera TILE-Gx multicore architecture family" },
	{ EM_CLOUDSHIELD, "CloudShield architecture family" },
	{ EM_COREA_1ST, "KIPO-KAIST Core-A 1st generation processor family" },
	{ EM_COREA_2ND, "KIPO-KAIST Core-A 2nd generation processor family" },
	{ EM_ARC_COMPACT2, "Synopsys ARCompact V2" },
	{ EM_OPEN8, "Open8 8-bit RISC soft processor core" },
	{ EM_RL78, "Renesas RL78 family" },
	{ EM_VIDEOCORE5, "Broadcom VideoCore V processor" },
	{ EM_78KOR, "Renesas 78KOR family" },
	{ EM_BA1, "Beyond BA1 CPU architecture" },
	{ EM_BA2_NON_STANDARD, "Beyond BA2 CPU architecture" },
	{ EM_BA2, "Beyond BA2 CPU architecture" },
	{ EM_XCORE, "XMOS xCORE processor family" },
	{ EM_MCHP_PIC, "Microchip 8-bit PIC(r) family" },
	{ EM_INTEL205, "Reserved by Intel" },
	{ EM_INTEL206, "Reserved by Intel" },
	{ EM_INTEL207, "Reserved by Intel" },
	{ EM_INTEL208, "Reserved by Intel" },
	{ EM_INTEL209, "Reserved by Intel" },
	{ EM_KM32, "KM211 KM32 32-bit processor" },
	{ EM_KMX32, "KM211 KMX32 32-bit processor" },
	{ EM_KMX16, "KM211 KMX16 16-bit processor" },
	{ EM_KMX8, "KM211 KMX8 8-bit processor" },
	{ EM_KVARC, "KM211 KVARC processor" },
	{ EM_CDP, "Paneve CDP architecture family" },
	{ EM_COGE, "Cognitive Smart Memory Processor" },
	{ EM_COOL, "Bluechip Systems CoolEngine" },
	{ EM_NORC, "Nanoradio Optimized RISC" },
	{ EM_CSR_KALIMBA, "CSR Kalimba architecture family" },
	{ EM_Z80, "Zilog Z80" },
	{ EM_VISIUM, "Controls and Data Services VISIUMcore processor" },
	{ EM_FT32, "FTDI Chip FT32 high performance 32-bit RISC architecture" },
	{ EM_MOXIE, "Moxie processor family" },
	{ EM_AMDGPU, "AMD GPU architecture" }
};

static const struct class_translation class_translation_table[] = {
	{ ELFCLASSNONE, "none" },
	{ ELFCLASS32, "ELF32" },
	{ ELFCLASS64, "ELF64" }
};

static const struct cpu_mips_translation cpu_mips_translation_table[] = {
	{ EF_MIPS_ARCH_1, "mips1" },
	{ EF_MIPS_ARCH_2, "mips2" },
	{ EF_MIPS_ARCH_3, "mips3" },
	{ EF_MIPS_ARCH_4, "mips4" },
	{ EF_MIPS_ARCH_5, "mips5" },
	{ EF_MIPS_ARCH_32, "mips32" },
	{ EF_MIPS_ARCH_64, "mips64" },
	{ EF_MIPS_ARCH_32R2, "mips32r2" },
	{ EF_MIPS_ARCH_64R2, "mips64r2" },
};

static const struct arch_translation arch_translation_table[] = {
	{ EM_ARC, "arc" },
	{ EM_ARC_A5, "arc" },
	{ EM_AVR, "avr" },
	{ EM_BA2_NON_STANDARD, "ba2" },
	{ EM_BA2, "ba2" },
	{ EM_CRIS, "cris" },
	{ EM_68K, "m68k" },
	{ EM_MIPS, "mips" },
	{ EM_MIPS_RS3_LE, "mips" },
	{ EM_MIPS_X, "mips" },
	{ EM_MCST_ELBRUS, "elbrus" },
	{ EM_TRICORE, "tricore" },
	{ EM_RCE, "mcore" },
	{ EM_ARM, "arm" },
	{ EM_AARCH64, "arm" },
	{ EM_QDSP6, "hexagon" },
	{ EM_BLACKFIN, "blackfin" },
	{ EM_SPARC, "sparc" },
	{ EM_SPARC32PLUS, "sparc" },
	{ EM_SPARCV9, "sparc" },
	{ EM_PPC, "ppc" },
	{ EM_PPC64, "ppc" },
	{ EM_PARISC, "hppa" },
	{ EM_PROPELLER, "propeller" },
	{ EM_MICROBLAZE, "microblaze.gnu" },
	{ EM_RISCV, "riscv" },
	{ EM_VAX, "vax" },
	{ EM_XTENSA, "xtensa" },
	{ EM_LANAI, "lanai" },
	{ EM_VIDEOCORE3, "vc4" },
	{ EM_VIDEOCORE4, "vc4" },
	{ EM_MSP430, "msp430" },
	{ EM_SH, "sh" },
	{ EM_V800, "v850" },
	{ EM_V850, "v850" },
	{ EM_IA_64, "ia64" },
	{ EM_S390, "sysz" },
};

static const struct ver_flags_translation ver_flags_translation_table[] = {
	{ VER_FLG_BASE, "BASE " },
	{ VER_FLG_BASE | VER_FLG_WEAK, "| " },
	{ VER_FLG_WEAK, "WEAK " },
	{ ~(VER_FLG_BASE | VER_FLG_WEAK), "| <unknown>" }
};

static RzBinElfLib *get_libs_from_dt_dynamic(ELFOBJ *bin, RzBinElfLib *libs) {
	size_t i = 0;

	Elf_(Word) *iter = NULL;

	RzVector *dt_needed = Elf_(rz_bin_elf_get_dt_needed)(bin);
	if (!dt_needed) {
		return NULL;
	}

	rz_vector_enumerate(dt_needed, iter, i) {
		if (*iter > bin->strtab_size) {
			free(libs);
			return NULL;
		}

		rz_str_ncpy(libs[i].name, bin->strtab + *iter, ELF_STRING_LENGTH);
		libs[i].last = 0;
	}

	libs[i].last = 1;

	return libs;
}

static ut64 get_main_offset_from_symbol(ELFOBJ *bin) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbols)(bin);

	if (!symbol) {
		return UT64_MAX;
	}

	for (size_t i = 0; !symbol[i].last; i++) {
		if (!strcmp(symbol[i].name, "main")) {
			return symbol[i].offset;
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_linux_64_pie(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	/* linux64 pie main -- probably buggy in some cases */
	int bo = 29; // Begin offset may vary depending on the entry prelude
	// endbr64 - fedora bins have this
	if (buf[0] == 0xf3 && buf[1] == 0x0f && buf[2] == 0x1e && buf[3] == 0xfa) {
		// Change begin offset if binary starts with 'endbr64'
		bo = 33;
	}
	if (buf[bo] == 0x48) {
		ut8 ch = buf[bo + 1];
		if (ch == 0x8d) { // lea rdi, qword [rip-0x21c4]
			ut8 *p = buf + bo + 3;
			st32 maindelta = (st32)rz_read_le32(p);
			ut64 vmain = (ut64)(entry + bo + maindelta) + 7;
			ut64 ventry = Elf_(rz_bin_elf_p2v_new)(bin, entry);
			if (vmain >> 16 == ventry >> 16) {
				return (ut64)vmain;
			}
		} else if (0xc7) { // mov rdi, 0xADDR
			ut8 *p = buf + bo + 3;
			return (ut64)(ut32)rz_read_le32(p);
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_x86_non_pie(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	// X86-NONPIE
#if RZ_BIN_ELF64
	if (!memcmp(buf, "\x49\x89\xd9", 3) && buf[156] == 0xe8) { // openbsd
		return rz_read_le32(buf + 157) + entry + 156 + 5;
	}
	if (!memcmp(buf + 29, "\x48\xc7\xc7", 3)) { // linux
		ut64 addr = (ut64)rz_read_le32(buf + 29 + 3);
		return Elf_(rz_bin_elf_v2p_new)(bin, addr);
	}
#else
	if (buf[23] == '\x68') {
		ut64 addr = (ut64)rz_read_le32(buf + 23 + 1);
		return Elf_(rz_bin_elf_v2p_new)(bin, addr);
	}
#endif

	return UT64_MAX;
}

static ut64 get_main_offset_x86_pie(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	// X86-PIE
	if (buf[0x00] == 0x48 && buf[0x1e] == 0x8d && buf[0x11] == 0xe8) {
		ut32 *pmain = (ut32 *)(buf + 0x30);
		ut64 vmain = Elf_(rz_bin_elf_p2v_new)(bin, (ut64)*pmain);
		ut64 ventry = Elf_(rz_bin_elf_p2v_new)(bin, entry);
		if (vmain >> 16 == ventry >> 16) {
			return vmain;
		}
	}
	// X86-PIE
	if (buf[0x1d] == 0x48 && buf[0x1e] == 0x8b) {
		if (!memcmp(buf, "\x31\xed\x49\x89", 4)) { // linux
			ut64 maddr, baddr;
			ut8 n32s[sizeof(ut32)] = { 0 };
			maddr = entry + 0x24 + rz_read_le32(buf + 0x20);
			if (rz_buf_read_at(bin->b, maddr, n32s, sizeof(ut32)) == -1) {
				return 0;
			}
			maddr = (ut64)rz_read_le32(&n32s[0]);
			baddr = (bin->ehdr.e_entry >> 16) << 16;
			if (bin->phdr) {
				baddr = Elf_(rz_bin_elf_get_baddr)(bin);
			}
			maddr += baddr;
			return maddr;
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_x86_gcc(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	if (buf[0] != 0xe8 && memcmp(buf + 5, "\x50\xe8\x00\x00\x00\x00\xb8\x01\x00\x00\x00\x53", 12)) {
		return UT64_MAX;
	}

	size_t SIZEOF_CALL = 5;
	ut64 rel_addr = (ut64)(buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24));
	ut64 addr = Elf_(rz_bin_elf_p2v_new)(bin, entry + SIZEOF_CALL);
	addr += rel_addr;
	return Elf_(rz_bin_elf_v2p_new)(bin, addr);
}

static ut64 get_main_offset_mips(ELFOBJ *bin, ut64 entry, ut8 *buf, size_t size) {
	/* get .got, calculate offset of main symbol */
	if (memcmp(buf, "\x21\x00\xe0\x03\x01\x00\x11\x04", 8)) {
		return UT64_MAX;
	}

	/*
	   assuming the startup code looks like
	   got = gp-0x7ff0
	   got[index__libc_start_main] ( got[index_main] );

	   looking for the instruction generating the first argument to find main
	   lw a0, offset(gp)
	   */
	ut64 got_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
		return 0;
	}

	ut64 got_offset = Elf_(rz_bin_elf_v2p_new)(bin, got_addr);
	ut64 gp = got_offset + 0x7ff0;

	for (size_t i = 0; i < size; i += 4) {
		const ut32 instr = rz_read_le32(buf + i);
		if ((instr & 0xffff0000) == 0x8f840000) { // lw a0, offset(gp)
			const short delta = instr & 0x0000ffff;
			rz_buf_read_at(bin->b, /* got_entry_offset = */ gp + delta, buf, 4);
			return Elf_(rz_bin_elf_v2p_new)(bin, rz_read_le32(buf));
		}
	}

	return 0;
}

static ut64 get_main_offset_arm_glibc_thumb(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	size_t delta = 0;

	if (!memcmp(buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x02\xbc\x6a\x46", 11)) {
		/* newer versions of gcc use push/pop */
		delta = 0x28;
	} else if (!memcmp(buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x5d\xf8\x04\x1b", 11)) {
		/* older versions of gcc (4.5.x) use ldr/str */
		delta = 0x30;
	}

	if (delta) {
		ut64 tmp = rz_read_le32(buf + delta - 1) & ~1;
		ut64 pa = Elf_(rz_bin_elf_v2p_new)(bin, tmp);
		if (pa < rz_buf_size(bin->b)) {
			return pa;
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_arm_glibc_non_thumb(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	if (!memcmp(buf, "\x00\xb0\xa0\xe3\x00\xe0\xa0\xe3", 8)) {
		return Elf_(rz_bin_elf_v2p_new)(bin, rz_read_le32(buf + 0x34) & ~1);
	}

	if (!memcmp(buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
		return Elf_(rz_bin_elf_v2p_new)(bin, rz_read_le32(buf + 0x30) & ~1);
	}

	return UT64_MAX;
}

static ut64 get_main_offset_arm_glibc(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	// ARM Glibc
	if (entry & 1) {
		return get_main_offset_arm_glibc_thumb(bin, entry, buf);
	} else {
		return get_main_offset_arm_glibc_non_thumb(bin, entry, buf);
	}

	return UT64_MAX;
}

static ut64 get_main_offset_arm64(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	if (buf[0x18 + 3] != 0x58 || buf[0x2f] != 0x00) {
		return UT64_MAX;
	}

	ut64 entry_vaddr = Elf_(rz_bin_elf_p2v_new)(bin, entry);
	if (entry_vaddr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 main_addr = rz_read_le32(buf + 0x30);

	if (main_addr >> 16 == entry_vaddr >> 16) {
		return Elf_(rz_bin_elf_v2p_new)(bin, main_addr);
	}

	return UT64_MAX;
}

static ut64 get_entry_offset_from_shdr(ELFOBJ *bin) {
	ut64 entry = Elf_(rz_bin_elf_get_section_offset)(bin, ".init.text");
	if (entry != UT64_MAX) {
		return entry;
	}

	entry = Elf_(rz_bin_elf_get_section_offset)(bin, ".text");
	if (entry != UT64_MAX) {
		return entry;
	}

	return Elf_(rz_bin_elf_get_section_offset)(bin, ".init");
}

static ut64 compute_boffset_from_phdr(ELFOBJ *bin) {
	ut64 base = UT64_MAX;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_LOAD) {
			base = RZ_MIN(base, bin->phdr[i].p_offset);
		}
	}

	return base == UT64_MAX ? 0 : base;
}

static ut64 compute_baddr_from_phdr(ELFOBJ *bin) {
	ut64 base = UT64_MAX;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_LOAD) {
			base = RZ_MIN(base, bin->phdr[i].p_vaddr);
		}
	}

	return base == UT64_MAX ? 0 : base;
}

static bool elf_is_bind_now(ELFOBJ *bin) {
	ut64 flags_1;

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_BIND_NOW, NULL)) {
		return true;
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_FLAGS_1, &flags_1)) {
		return flags_1 & DF_1_NOW;
	}

	return false;
}

static bool elf_has_gnu_relro(ELFOBJ *bin) {
	if (!bin->phdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_GNU_RELRO) {
			return true;
		}
	}

	return false;
}

static int get_bits_common(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		return 32;
	case ELFCLASS64:
		return 64;
	case ELFCLASSNONE:
	default:
		return 32;
	}
}

static bool has_thumb_symbol(ELFOBJ *bin) {
	struct rz_bin_elf_symbol_t *symbols = Elf_(rz_bin_elf_get_symbols)(bin);

	if (!symbols) {
		return false;
	}

	for (size_t i = 0; !symbols[i].last; i++) {
		if (symbols[i].offset & 1) {
			return true;
		}
	}

	return false;
}

static bool arch_is_arm(ELFOBJ *bin) {
	return bin->ehdr.e_machine == EM_ARM;
}

static int get_bits_mips_common(Elf_(Word) mips_type) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(mips_bits_translation_table); i++) {
		if (mips_type == mips_bits_translation_table[i].type) {
			return mips_bits_translation_table[i].bits;
		}
	}

	return 32;
}

static int is_playstation_hack(ELFOBJ *bin, Elf_(Word) mips_type) {
	return Elf_(rz_bin_elf_is_executable)(bin) && Elf_(rz_bin_elf_is_static)(bin) && mips_type == EF_MIPS_ARCH_3;
}

static int get_bits_mips(ELFOBJ *bin) {
	const Elf_(Word) mips_type = bin->ehdr.e_flags & EF_MIPS_ARCH;

	if (is_playstation_hack(bin, mips_type)) {
		return 64;
	}

	return get_bits_mips_common(mips_type);
}

static bool arch_is_mips(ELFOBJ *bin) {
	return bin->phdr && bin->ehdr.e_machine == EM_MIPS;
}

static bool arch_is_arcompact(ELFOBJ *bin) {
	return bin->ehdr.e_machine == EM_ARC_A5;
}

static char *read_elf_intrp(ELFOBJ *bin, ut64 addr, size_t size) {
	char *str = malloc(size + 1);
	if (!str) {
		return NULL;
	}

	if (rz_buf_read_at(bin->b, addr, (ut8 *)str, size) < 0) {
		free(str);
		return NULL;
	}

	str[size] = 0;

	return str;
}

static char *get_elf_intrp(ELFOBJ *bin, size_t i) {
	ut64 addr = bin->phdr[i].p_offset;
	size_t size = bin->phdr[i].p_filesz;

	sdb_num_set(bin->kv, "elf_header.intrp_addr", addr, 0);
	sdb_num_set(bin->kv, "elf_header.intrp_size", size, 0);

	if (size < 1 || size > rz_buf_size(bin->b)) {
		return NULL;
	}

	char *str = read_elf_intrp(bin, addr, size);
	sdb_set(bin->kv, "elf_header.intrp", str, 0);

	return str;
}

static Elf_(Xword) get_dt_rpath(ELFOBJ *bin) {
	ut64 path;

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RPATH, &path)) {
		return path;
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RUNPATH, &path)) {
		return path;
	}

	return 0;
}

static char *get_ver_flags(ut32 flags) {
	char *result = NULL;

	if (!flags) {
		return strdup("none");
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(ver_flags_translation_table); i++) {
		if (flags & ver_flags_translation_table[i].flag) {
			result = rz_str_append(result, ver_flags_translation_table[i].name);
		}
	}

	return result;
}

static bool has_dt_rpath_entry(ELFOBJ *bin) {
	return Elf_(rz_bin_elf_get_dt_info)(bin, DT_RPATH, NULL) || Elf_(rz_bin_elf_get_dt_info)(bin, DT_RUNPATH, NULL);
}

static bool is_valid_section_note(ELFOBJ *bin, Elf_(Shdr) * section) {
	return section->sh_type == SHT_NOTE && section->sh_name < bin->shstrtab_size;
}

static char *get_osabi_name_from_section_note(ELFOBJ *bin, Elf_(Shdr) * section) {
	if (!is_valid_section_note(bin, section)) {
		return NULL;
	}

	const char *section_name = bin->shstrtab + section->sh_name;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(section_note_osabi_translation_table); i++) {
		if (!strcmp(section_name, section_note_osabi_translation_table[i].note_name)) {
			return strdup(section_note_osabi_translation_table[i].os_name);
		}
	}

	return NULL;
}

static char *get_osabi_name_from_shdr(ELFOBJ *bin) {
	if (!bin->shdr || !bin->shstrtab) {
		return NULL;
	}

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		char *tmp = get_osabi_name_from_section_note(bin, bin->shdr + i);
		if (tmp) {
			return tmp;
		}
	}

	return NULL;
}

static char *get_osabi_name_from_ehdr(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX:
		return strdup("linux");
	case ELFOSABI_SOLARIS:
		return strdup("solaris");
	case ELFOSABI_FREEBSD:
		return strdup("freebsd");
	case ELFOSABI_HPUX:
		return strdup("hpux");
	}

	return NULL;
}

static char *add_abi_info(ELFOBJ *bin, char *head_flag) {
	char *str = Elf_(rz_bin_elf_get_abi)(bin);

	if (str) {
		head_flag = rz_str_appendf(head_flag, " %s", str);
		free(str);
	}

	return head_flag;
}

static char *add_cpu_info(ELFOBJ *bin, char *head_flag) {
	char *str = Elf_(rz_bin_elf_get_cpu)(bin);

	if (str) {
		head_flag = rz_str_append_owned(head_flag, str);
	}

	return head_flag;
}

static char *get_head_flag(ELFOBJ *bin) {
	char *head_flag = NULL;

	head_flag = add_cpu_info(bin, head_flag);
	head_flag = add_abi_info(bin, head_flag);

	return head_flag;
}

static bool file_type_is_processor_specific(ELFOBJ *bin) {
	return bin->ehdr.e_type >= ET_LOPROC && bin->ehdr.e_type <= ET_HIPROC;
}

static bool file_type_is_os_specific(ELFOBJ *bin) {
	return bin->ehdr.e_type >= ET_LOOS && bin->ehdr.e_type <= ET_HIOS;
}

static char *get_file_type_basic(RZ_NONNULL ELFOBJ *bin) {
	switch (bin->ehdr.e_type) {
	case ET_NONE:
		return strdup("NONE (None)");
	case ET_REL:
		return strdup("REL (Relocatable file)");
	case ET_EXEC:
		return strdup("EXEC (Executable file)");
	case ET_DYN:
		return strdup("DYN (Shared object file)");
	case ET_CORE:
		return strdup("CORE (Core file)");
	}

	return NULL;
}

static char *get_cpu_mips(ELFOBJ *bin) {
	Elf_(Word) mips_arch = bin->ehdr.e_flags & EF_MIPS_ARCH;

	for (size_t i = 0; i < RZ_ARRAY_SIZE(cpu_mips_translation_table); i++) {
		if (mips_arch == cpu_mips_translation_table[i].arch) {
			return strdup(cpu_mips_translation_table[i].name);
		}
	}

	return strdup(" Unknown mips ISA");
}

static bool is_elf_class64(ELFOBJ *bin) {
	return bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64;
}

static bool is_mips_o32(ELFOBJ *bin) {
	if (bin->ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}

	if ((bin->ehdr.e_flags & EF_MIPS_ABI2) != 0) {
		return false;
	}

	if ((bin->ehdr.e_flags & EF_MIPS_ABI) != 0 && (bin->ehdr.e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_O32) {
		return false;
	}

	return true;
}

static bool is_mips_n32(ELFOBJ *bin) {
	if (bin->ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}

	if ((bin->ehdr.e_flags & EF_MIPS_ABI2) == 0 || (bin->ehdr.e_flags & EF_MIPS_ABI) != 0) {
		return false;
	}

	return true;
}

static char *get_abi_mips(ELFOBJ *bin) {
	if (is_elf_class64(bin)) {
		return strdup("n64");
	}

	if (is_mips_n32(bin)) {
		return strdup("n32");
	}

	if (is_mips_o32(bin)) {
		return strdup("o32");
	}

	return NULL;
}

/**
 * \brief List all imported lib
 * \param elf binary
 * \return a an allocated array of RzBinElfLib
 *
 * Use dynamic information (dt_needed) to generate the list of imported lib
 */
RZ_OWN RzBinElfLib *Elf_(rz_bin_elf_get_libs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin || !bin->phdr || !bin->strtab || bin->strtab[1] == '\0') {
		return NULL;
	}

	RzVector *dt_needed = Elf_(rz_bin_elf_get_dt_needed)(bin);
	if (!dt_needed) {
		return NULL;
	}

	RzBinElfLib *ret = RZ_NEWS(RzBinElfLib, rz_vector_len(dt_needed) + 1);
	if (!ret) {
		return NULL;
	}

	return get_libs_from_dt_dynamic(bin, ret);
}

static Elf_(Verdaux) get_verdaux_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Verdaux) verdaux_entry;

	verdaux_entry.vda_name = BREAD32(bin->b, offset);
	verdaux_entry.vda_next = BREAD32(bin->b, offset);

	return verdaux_entry;
}

static Elf_(Verdef) get_verdef_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Verdef) verdef_entry;

	verdef_entry.vd_version = BREAD16(bin->b, offset);
	verdef_entry.vd_flags = BREAD16(bin->b, offset);
	verdef_entry.vd_ndx = BREAD16(bin->b, offset);
	verdef_entry.vd_cnt = BREAD16(bin->b, offset);
	verdef_entry.vd_hash = BREAD32(bin->b, offset);
	verdef_entry.vd_aux = BREAD32(bin->b, offset);
	verdef_entry.vd_next = BREAD32(bin->b, offset);

	return verdef_entry;
}

static Elf_(Vernaux) get_vernaux_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Vernaux) vernaux_entry;

	vernaux_entry.vna_hash = BREAD32(bin->b, offset);
	vernaux_entry.vna_flags = BREAD16(bin->b, offset);
	vernaux_entry.vna_other = BREAD16(bin->b, offset);
	vernaux_entry.vna_name = BREAD32(bin->b, offset);
	vernaux_entry.vna_next = BREAD32(bin->b, offset);

	return vernaux_entry;
}

static Elf_(Verneed) get_verneed_entry(ELFOBJ *bin, ut64 offset) {
	Elf_(Verneed) verneed_entry;

	verneed_entry.vn_version = BREAD16(bin->b, offset);
	verneed_entry.vn_cnt = BREAD16(bin->b, offset);
	verneed_entry.vn_file = BREAD32(bin->b, offset);
	verneed_entry.vn_aux = BREAD32(bin->b, offset);
	verneed_entry.vn_next = BREAD32(bin->b, offset);

	return verneed_entry;
}

static bool get_versym_entry_sdb_from_verneed(ELFOBJ *bin, Sdb *sdb, const char *key, Elf_(Versym) versym) {
	ut64 verneed_addr;
	ut64 verneed_num;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERNEED, &verneed_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERNEEDNUM, &verneed_num)) {
		return false;
	}

	ut64 verneed_offset = Elf_(rz_bin_elf_v2p_new(bin, verneed_addr));

	if (verneed_offset == UT64_MAX) {
		return false;
	}

	ut64 verneed_entry_offset = verneed_offset;

	for (size_t i = 0; i < verneed_num; i++) {
		Elf_(Verneed) verneed_entry = get_verneed_entry(bin, verneed_entry_offset);

		ut64 vernaux_entry_offset = verneed_entry_offset + verneed_entry.vn_aux;

		for (size_t j = 0; j < verneed_entry.vn_cnt; j++) {
			Elf_(Vernaux) vernaux_entry = get_vernaux_entry(bin, vernaux_entry_offset);

			if (vernaux_entry.vna_other != versym) {
				vernaux_entry_offset += vernaux_entry.vna_next;
				continue;
			}

			if (vernaux_entry.vna_name > bin->strtab_size) {
				return false;
			}

			const char *value = sdb_fmt("%u (%s)", versym & VERSYM_VERSION, bin->strtab + vernaux_entry.vna_name);
			sdb_set(sdb, key, value, 0);

			return true;
		}

		verneed_entry_offset += verneed_entry.vn_next;
	}

	return false;
}

static bool get_versym_entry_sdb_from_verdef(ELFOBJ *bin, Sdb *sdb, const char *key, Elf_(Versym) versym) {
	ut64 verdef_addr;
	ut64 verdef_num;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERDEF, &verdef_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERDEFNUM, &verdef_num)) {
		return false;
	}

	ut64 verdef_offset = Elf_(rz_bin_elf_v2p_new(bin, verdef_addr));

	if (verdef_offset == UT64_MAX) {
		return false;
	}

	ut64 verdef_entry_offset = verdef_offset;

	for (size_t i = 0; i < verdef_num; i++) {
		Elf_(Verdef) verdef_entry = get_verdef_entry(bin, verdef_entry_offset);

		if (!verdef_entry.vd_cnt || verdef_entry.vd_ndx != (versym & VERSYM_VERSION)) {
			verdef_entry_offset += verdef_entry.vd_next;
			continue;
		}

		ut64 verdaux_entry_offset = verdef_entry_offset + verdef_entry.vd_aux;
		Elf_(Verdaux) verdaux_entry = get_verdaux_entry(bin, verdaux_entry_offset);

		if (verdaux_entry.vda_name > bin->strtab_size) {
			return false;
		}

		const char *name = bin->strtab + verdaux_entry.vda_name;
		const char *value = sdb_fmt("%u (%s%-*s)", versym & VERSYM_VERSION, name, (int)(12 - strlen(name)), ")");
		sdb_set(sdb, key, value, 0);

		return true;
	}

	return false;
}

static Sdb *get_version_info_gnu_versym(ELFOBJ *bin) {
	ut64 versym_addr;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERSYM, &versym_addr)) {
		return false;
	}

	ut64 versym_offset = Elf_(rz_bin_elf_v2p_new(bin, versym_addr));

	if (versym_offset == UT64_MAX) {
		return NULL;
	}

	ut64 number_of_symbols = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!number_of_symbols) {
		return NULL;
	}

	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}

	sdb_num_set(sdb, "num_entries", number_of_symbols, 0);
	sdb_num_set(sdb, "addr", versym_addr, 0);
	sdb_num_set(sdb, "offset", versym_offset, 0);

	ut64 versym_entry_offset = versym_offset;

	for (size_t i = 0; i < number_of_symbols; i++) {
		const char *key = sdb_fmt("entry%zu", i);
		Elf_(Versym) versym_entry = BREAD16(bin->b, versym_entry_offset);

		switch (versym_entry) {
		case VER_NDX_LOCAL:
			sdb_set(sdb, key, "0 (*local*)", 0);
			break;
		case VER_NDX_GLOBAL:
			sdb_set(sdb, key, "1 (*global*)", 0);
			break;
		default:
			if (get_versym_entry_sdb_from_verneed(bin, sdb, key, versym_entry)) {
				break;
			}

			get_versym_entry_sdb_from_verdef(bin, sdb, key, versym_entry);
		}
	}

	return sdb;
}

static Sdb *get_verdaux_entry_sdb(ELFOBJ *bin, Elf_(Verdaux) * verdaux_entry, size_t index) {
	if (verdaux_entry->vda_name > bin->dynstr_size) {
		return NULL;
	}

	Sdb *sdb_verdaux = sdb_new0();
	if (!sdb_verdaux) {
		return NULL;
	}

	sdb_num_set(sdb_verdaux, "idx", index, 0);
	sdb_set(sdb_verdaux, "vda_name", bin->dynstr + verdaux_entry->vda_name, 0);

	return sdb_verdaux;
}

static Sdb *get_verdef_entry_sdb_aux(ELFOBJ *bin, Elf_(Verdef) * verdef_entry, size_t index) {
	Sdb *sdb_verdef = sdb_new0();
	if (!sdb_verdef) {
		return NULL;
	}

	sdb_num_set(sdb_verdef, "idx", index, 0);
	sdb_num_set(sdb_verdef, "vd_cnt", verdef_entry->vd_cnt, 0);
	sdb_num_set(sdb_verdef, "vd_ndx", verdef_entry->vd_ndx, 0);
	sdb_num_set(sdb_verdef, "vd_version", verdef_entry->vd_version, 0);
	char *flags = get_ver_flags(verdef_entry->vd_flags);
	sdb_set(sdb_verdef, "flags", flags, 0);
	free(flags);

	return sdb_verdef;
}

static Sdb *get_verdef_entry_sdb(ELFOBJ *bin, Elf_(Verdef) * verdef_entry, size_t offset) {
	Sdb *sdb_verdef = get_verdef_entry_sdb_aux(bin, verdef_entry, offset);
	if (!sdb_verdef) {
		return NULL;
	}

	ut64 verdaux_entry_offset = offset + verdef_entry->vd_aux;

	for (size_t j = 0; j < verdef_entry->vd_cnt; j++) {
		Elf_(Verdaux) verdaux_entry = get_verdaux_entry(bin, verdaux_entry_offset);

		Sdb *sdb_verdaux = get_verdaux_entry_sdb(bin, &verdaux_entry, verdaux_entry_offset);
		if (!sdb_verdaux) {
			sdb_free(sdb_verdef);
			return NULL;
		}

		sdb_ns_set(sdb_verdef, sdb_fmt("verdaux%zu", j), sdb_verdaux);
		sdb_free(sdb_verdaux);

		verdaux_entry_offset += verdaux_entry.vda_next;
	}

	return sdb_verdef;
}

static Sdb *get_version_info_gnu_verdef(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	ut64 verdef_addr;
	ut64 verdef_num;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERDEF, &verdef_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERDEFNUM, &verdef_num)) {
		return NULL;
	}

	ut64 verdef_offset = Elf_(rz_bin_elf_v2p_new(bin, verdef_addr));

	if (verdef_offset == UT64_MAX) {
		return NULL;
	}

	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}

	sdb_num_set(sdb, "entries", verdef_num, 0);
	sdb_num_set(sdb, "addr", verdef_addr, 0);
	sdb_num_set(sdb, "offset", verdef_offset, 0);

	for (size_t i = 0; i < verdef_num; i++) {
		Elf_(Verdef) verdef_entry = get_verdef_entry(bin, verdef_offset);

		Sdb *sdb_verdef = get_verdef_entry_sdb(bin, &verdef_entry, verdef_offset);
		if (!sdb_verdef) {
			sdb_free(sdb);
			return NULL;
		}

		sdb_ns_set(sdb, sdb_fmt("verdef%zu", i), sdb_verdef);
		sdb_free(sdb_verdef);

		verdef_offset += verdef_entry.vd_next;
	}

	return sdb;
}

static Sdb *get_vernaux_entry_sdb(ELFOBJ *bin, Elf_(Vernaux) vernaux_entry, size_t index) {
	if (vernaux_entry.vna_name > bin->dynstr_size) {
		return NULL;
	}

	Sdb *sdb_vernaux = sdb_new0();
	if (!sdb_vernaux) {
		return NULL;
	}

	char *flags = get_ver_flags(vernaux_entry.vna_flags);
	sdb_set(sdb_vernaux, "flags", flags, 0);
	free(flags);

	sdb_num_set(sdb_vernaux, "idx", index, 0);
	sdb_num_set(sdb_vernaux, "version", vernaux_entry.vna_other, 0);
	sdb_set(sdb_vernaux, "name", bin->dynstr + vernaux_entry.vna_name, 0);

	return sdb_vernaux;
}

static Sdb *get_verneed_entry_sdb_aux(ELFOBJ *bin, Elf_(Verneed) verneed_entry, size_t index) {
	if (verneed_entry.vn_file > bin->dynstr_size) {
		return NULL;
	}

	Sdb *sdb_version = sdb_new0();
	if (!sdb_version) {
		return NULL;
	}

	sdb_num_set(sdb_version, "cnt", verneed_entry.vn_cnt, 0);
	sdb_num_set(sdb_version, "idx", index, 0);
	sdb_num_set(sdb_version, "vn_version", verneed_entry.vn_version, 0);
	sdb_set(sdb_version, "file_name", bin->dynstr + verneed_entry.vn_file, 0);

	return sdb_version;
}

static Sdb *get_verneed_entry_sdb(ELFOBJ *bin, Elf_(Verneed) verneed_entry, size_t offset) {
	Sdb *sdb_version = get_verneed_entry_sdb_aux(bin, verneed_entry, offset);
	if (!sdb_version) {
		return NULL;
	}

	ut64 vernaux_entry_offset = offset + verneed_entry.vn_aux;

	for (size_t i = 0; i < verneed_entry.vn_cnt; i++) {
		Elf_(Vernaux) vernaux_entry = get_vernaux_entry(bin, vernaux_entry_offset);

		Sdb *sdb_vernaux = get_vernaux_entry_sdb(bin, vernaux_entry, vernaux_entry_offset);
		if (!sdb_vernaux) {
			sdb_free(sdb_version);
			return NULL;
		}

		sdb_ns_set(sdb_version, sdb_fmt("vernaux%zu", i), sdb_vernaux);
		sdb_free(sdb_vernaux);

		vernaux_entry_offset += vernaux_entry.vna_next;
	}

	return sdb_version;
}

static Sdb *get_version_info_gnu_verneed(ELFOBJ *bin) {
	ut64 verneed_addr;
	ut64 verneed_num;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERNEED, &verneed_addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_VERNEEDNUM, &verneed_num)) {
		return NULL;
	}

	ut64 verneed_offset = Elf_(rz_bin_elf_v2p_new(bin, verneed_addr));

	if (verneed_offset == UT64_MAX) {
		return NULL;
	}

	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}

	sdb_num_set(sdb, "num_entries", verneed_num, 0);
	sdb_num_set(sdb, "addr", verneed_addr, 0);
	sdb_num_set(sdb, "offset", verneed_offset, 0);

	for (size_t i = 0; i < verneed_num; i++) {
		Elf_(Verneed) verneed_entry = get_verneed_entry(bin, verneed_offset);

		Sdb *sdb_version = get_verneed_entry_sdb(bin, verneed_entry, verneed_offset);
		if (!sdb_version) {
			sdb_free(sdb);
			return NULL;
		}

		sdb_ns_set(sdb, sdb_fmt("version%zu", i), sdb_version);
		sdb_free(sdb_version);

		verneed_offset += verneed_entry.vn_next;
	}

	return sdb;
}

RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return NULL;
	}

	Sdb *res = sdb_new0();
	if (!res) {
		return NULL;
	}

	Sdb *sdb = get_version_info_gnu_verneed(bin);
	sdb_ns_set(res, "verneed", sdb);
	sdb_free(sdb);

	sdb = get_version_info_gnu_verdef(bin);
	sdb_ns_set(res, "verdef", sdb);
	sdb_free(sdb);

	sdb = get_version_info_gnu_versym(bin);
	sdb_ns_set(res, "versym", sdb);
	sdb_free(sdb);

	return res;
}

/**
 * \brief Get the compiler info from the .comment section
 * \param elf binary
 * \return a ptr to an allocated string
 *
 * ...
 */
RZ_OWN char *Elf_(rz_bin_elf_get_compiler)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, ".comment");
	if (!section) {
		return NULL;
	}

	ut64 offset = section->offset;
	ut64 size = RZ_MIN(section->size, 128);
	if (size < 1) {
		return NULL;
	}

	char *result = malloc(size + 1);
	if (!result) {
		return NULL;
	}

	if (rz_buf_read_at(bin->b, offset, (ut8 *)result, size) < 1) {
		free(result);
		return NULL;
	}
	result[size] = 0;

	size_t result_len = strlen(result);
	char *end = result + result_len;

	if (result_len != size && end[1]) {
		end[0] = ' ';
	}

	rz_str_trim(result);
	char *res = rz_str_escape(result);

	free(result);
	return res;
}

/**
 * \brief Return a string representing the application binary interface
 * \param elf type
 * \return allocated string
 *
 * Only work on mips right now. Use the elf header to deduce the application
 * binary interface
 */
RZ_OWN char *Elf_(rz_bin_elf_get_abi)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (bin->ehdr.e_machine == EM_MIPS) {
		return get_abi_mips(bin);
	}

	return NULL;
}

/**
 * \brief Get the elf binary architecture
 * \param elf binary
 * \return an allocated string
 *
 * With the elf header (e_machine) deduce the elf architecture
 */
RZ_OWN char *Elf_(rz_bin_elf_get_arch)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(arch_translation_table); i++) {
		if (bin->ehdr.e_machine == arch_translation_table[i].arch) {
			return strdup(arch_translation_table[i].name);
		}
	}

	return strdup("x86");
}

/**
 * \brief Return a string representing the cpu
 * \param elf type
 * \return allocated string
 *
 * Only work on mips right now. Use the elf header to deduce the cpu
 */
RZ_OWN char *Elf_(rz_bin_elf_get_cpu)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->phdr) {
		return NULL;
	}

	if (bin->ehdr.e_machine == EM_MIPS) {
		return get_cpu_mips(bin);
	}

	return NULL;
}

/**
 * \brief Return a string representing the elf class
 * \param elf binary
 * \return allocated string
 *
 * Check the elf header (e_ident) to deduce the elf class
 */
RZ_OWN char *Elf_(rz_bin_elf_get_elf_class)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(class_translation_table); i++) {
		if (bin->ehdr.e_ident[EI_CLASS] == class_translation_table[i].class) {
			return strdup(class_translation_table[i].name);
		}
	}

	return rz_str_newf("<unknown: %x>", bin->ehdr.e_ident[EI_CLASS]);
}

/**
 * \brief Return a string representing the file type
 * \param elf binary
 * \return allocated string
 *
 * Use the elf header (e_type) to deduce the file type
 */
RZ_OWN char *Elf_(rz_bin_elf_get_file_type)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *result = get_file_type_basic(bin);
	if (result) {
		return result;
	}

	if (file_type_is_processor_specific(bin)) {
		return rz_str_newf("Processor Specific: %x", bin->ehdr.e_type);
	}

	if (file_type_is_os_specific(bin)) {
		return rz_str_newf("OS Specific: %x", bin->ehdr.e_type);
	}

	return rz_str_newf("<unknown>: %x", bin->ehdr.e_type);
}

/**
 * \brief Return the head flag
 * \return allocated string
 *
 * ...
 */
RZ_OWN char *Elf_(rz_bin_elf_get_head_flag)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *head_flag = get_head_flag(bin);

	if (RZ_STR_ISEMPTY(head_flag)) {
		free(head_flag);
		return strdup("unknown_flag");
	}

	return head_flag;
}

/**
 * \brief Return a string representing the machine name
 * \param elf type
 * \return allocated string
 *
 * Use http://www.sco.com/developers/gabi/latest/ch4.eheader.html and the elf
 * header (e_machine)
 */
RZ_OWN char *Elf_(rz_bin_elf_get_machine_name)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(machine_name_translation_table); i++) {
		if (bin->ehdr.e_machine == machine_name_translation_table[i].machine) {
			return strdup(machine_name_translation_table[i].name);
		}
	}

	return rz_str_newf("<unknown>: 0x%x", bin->ehdr.e_machine);
}

/**
 * \brief Return the os application binary interface name
 * \param elf binary
 * \return an allocated string
 *
 * Check the ehdr or the shdr to get the os name
 */
RZ_OWN char *Elf_(rz_bin_elf_get_osabi_name)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *name = get_osabi_name_from_ehdr(bin);
	if (name) {
		return name;
	}

	name = get_osabi_name_from_shdr(bin);
	if (name) {
		return name;
	}

	return strdup("linux");
}

/**
 * \brief Get the rpath
 * \param elf binary
 * \return allocated string
 *
 * Use DT_RPATH or DT_RUNPATH to return the string
 */
RZ_OWN char *Elf_(rz_bin_elf_get_rpath)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->phdr || !bin->strtab || !has_dt_rpath_entry(bin)) {
		return NULL;
	}

	Elf_(Xword) val = get_dt_rpath(bin);
	if (!val || val > bin->strtab_size) {
		return NULL;
	}

	return rz_str_ndup(bin->strtab + val, ELF_STRING_LENGTH);
}

/**
 * \brief Get the program interpreter
 * \param elf binary
 * \return an allocated string
 *
 * Get the program interpreter from the phdr
 */
RZ_OWN char *Elf_(rz_bin_elf_get_intrp)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->phdr) {
		return NULL;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP) {
			return get_elf_intrp(bin, i);
		}
	}

	return NULL;
}

/**
 * \brief Check if the binary is stripped
 * \param elf binary
 * \param is_stripped ?
 * \return a ptr to a new allocated RzBinSymbol
 *
 * Use the shdr to check if the binary is stripped
 */
bool Elf_(rz_bin_elf_is_stripped)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->shdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_type == SHT_SYMTAB) {
			return false;
		}
	}

	return true;
}

/**
 * \brief Check if the stack is not executable
 * \param elf binary
 * \return true, false
 *
 * Check p_flags from the segment PT_GNU_STACK
 */
bool Elf_(rz_bin_elf_has_nx)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->phdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_GNU_STACK) {
			return !(bin->phdr[i].p_flags & PF_X);
		}
	}

	return false;
}

/**
 * \brief Check if the elf use virtual address
 * \param elf binary
 * \return always true
 *
 * Return always true
 */
bool Elf_(rz_bin_elf_has_va)(ELFOBJ *bin) {
	return true;
}

/**
 * \brief Check if the elf binary is executable
 * \param elf binary
 * \return is_executable ?
 *
 * Use the elf header entry e_type to deduct if the elf is executable.
 */
bool Elf_(rz_bin_elf_is_executable)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	const Elf_(Half) type = bin->ehdr.e_type;
	return type == ET_EXEC || type == ET_DYN;
}

/**
 * \brief Check if the elf binary is relocatable
 * \param elf binary
 * \return is_relocatable ?
 *
 * Use the elf header entry e_type to deduct if the elf is relocatable.
 */
bool Elf_(rz_bin_elf_is_relocatable)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->ehdr.e_type == ET_REL;
}

/**
 * \brief Check if the binary is statically-linked library
 * \param elf binary
 * \return is_static ?
 *
 * Check the presence of PT_INTERP or PT_DYNAMIC in the program header
 */
bool Elf_(rz_bin_elf_is_static)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	if (!bin->phdr) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP || bin->phdr[i].p_type == PT_DYNAMIC) {
			return false;
		}
	}

	return true;
}

/**
 * \brief Return the elf bits
 * \param elf binary
 * \return the number of bits
 *
 * ...
 */
int Elf_(rz_bin_elf_get_bits)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	/* Hack for ARCompact */
	if (arch_is_arcompact(bin)) {
		return 16;
	}

	/* Hack for Ps2 */
	if (arch_is_mips(bin)) {
		return get_bits_mips(bin);
	}

	/* Hack for Thumb */
	if (arch_is_arm(bin)) {
		if (bin->ehdr.e_type != ET_EXEC && has_thumb_symbol(bin)) {
			return 16;
		}

		if (Elf_(rz_bin_elf_get_entry_offset)(bin) & 1) {
			return 16;
		}
	}

	return get_bits_common(bin);
}

/**
 * \brief Analyse if the elf binary has relro or partial relro
 * \param elf binary
 * \return RZ_BIN_ELF_NO_RELRO, RZ_BIN_ELF_PART_RELRO or RZ_BIN_ELF_FULL_RELRO
 *
 * Check if the elf has bind now enable and with PT_GNU_RELRO can deduct the
 * relro type
 */
int Elf_(rz_bin_elf_has_relro)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, RZ_BIN_ELF_NO_RELRO);

	bool is_bind_now = elf_is_bind_now(bin);
	bool has_gnu_relro = elf_has_gnu_relro(bin);

	if (has_gnu_relro) {
		if (is_bind_now) {
			return RZ_BIN_ELF_FULL_RELRO;
		}

		return RZ_BIN_ELF_PART_RELRO;
	}

	return RZ_BIN_ELF_NO_RELRO;
}

/**
 * \brief Check the binary endianness
 * \param elf type
 * \return is_big_endian ?
 *
 * Use the elf header (e_ident[EI_DATA]) to check the binary endianness
 */
bool Elf_(rz_bin_elf_is_big_endian)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB;
}

/**
 * \brief Compute the base address of the binary
 * \param elf binary
 * \return the base address
 *
 * To compute the base address, one determines the memory
 * address associated with the lowest p_vaddr value for a
 * PT_LOAD segment.
 */
ut64 Elf_(rz_bin_elf_get_baddr)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
		return 0x08000000;
	}

	if (bin->phdr) {
		return compute_baddr_from_phdr(bin);
	}

	return 0;
}

/**
 * \brief Compute the base offset of the binary
 * \param elf binary
 * \return the base offset
 *
 * To compute the base address, one determines the memory
 * address associated with the lowest p_offset value for a
 * PT_LOAD segment.
 */
ut64 Elf_(rz_bin_elf_get_boffset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (bin->phdr) {
		return compute_boffset_from_phdr(bin);
	}

	return 0;
}

/**
 * \brief Get the entry offset
 * \param elf binary
 * \return the entry offset
 *
 * Get the entry offset from the elf header (e_entry), and if the information
 * isn't defined section header will be used.
 */
ut64 Elf_(rz_bin_elf_get_entry_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!Elf_(rz_bin_elf_is_executable)(bin)) {
		return UT64_MAX;
	}

	ut64 entry = bin->ehdr.e_entry;
	if (entry) {
		ut64 tmp = Elf_(rz_bin_elf_v2p_new)(bin, entry);
		if (tmp == UT64_MAX) {
			return entry;
		}

		return tmp;
	}

	return get_entry_offset_from_shdr(bin);
}

/**
 * \brief Compute the fini offset of the binary
 * \param elf binary
 * \return the init offset
 *
 * Get the offset from the vaddr store in the dynamic section (dt_fini)
 */
ut64 Elf_(rz_bin_elf_get_fini_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	ut64 addr;

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return 0;
	}

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_FINI, &addr)) {
		return 0;
	}

	return Elf_(rz_bin_elf_v2p_new)(bin, addr);
}

/**
 * \brief Compute the init offset of the binary
 * \param elf binary
 * \return the init offset
 *
 * Get the offset from the vaddr store in the dynamic section (dt_init)
 */
ut64 Elf_(rz_bin_elf_get_init_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	ut64 addr;

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return 0;
	}

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_INIT, &addr)) {
		return 0;
	}

	return Elf_(rz_bin_elf_v2p_new)(bin, addr);
}

/**
 * \brief Compute the main offset of the binary
 * \param elf binary
 * \return the main offset
 *
 * ...
 */
ut64 Elf_(rz_bin_elf_get_main_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);

	ut8 buf[256];
	ut64 entry = Elf_(rz_bin_elf_get_entry_offset)(bin);
	ut64 main_addr;

	if (entry == UT64_MAX || entry > bin->size || (entry + sizeof(buf)) > bin->size) {
		return UT64_MAX;
	}

	if (rz_buf_read_at(bin->b, entry, buf, sizeof(buf)) < 0) {
		return UT64_MAX;
	}

	main_addr = get_main_offset_arm64(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_arm_glibc(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_mips(bin, entry, buf, RZ_ARRAY_SIZE(buf));
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_x86_gcc(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_x86_pie(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_x86_non_pie(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_linux_64_pie(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	return get_main_offset_from_symbol(bin);
}
