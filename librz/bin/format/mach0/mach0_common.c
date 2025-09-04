// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include "mach0_defines.h"

/**
 * String representation of MACH0_PLATFORM_* values, e.g. from LC_BUILD_VERSION load command
 */
RZ_API RZ_NONNULL const char *rz_mach0_platform_to_string(ut32 platform) {
	switch (platform) {
	case MACH0_PLATFORM_MACOS:
		return "macOS";
	case MACH0_PLATFORM_IOS:
		return "iOS";
	case MACH0_PLATFORM_TVOS:
		return "tvOS";
	case MACH0_PLATFORM_WATCHOS:
		return "watchOS";
	case MACH0_PLATFORM_BRIDGEOS:
		return "bridgeOS";
	case MACH0_PLATFORM_IOS_MAC:
		return "Mac Catalyst";
	case MACH0_PLATFORM_IOS_SIMULATOR:
		return "iOS Simulator";
	case MACH0_PLATFORM_TVOS_SIMULATOR:
		return "tvOS Simulator";
	case MACH0_PLATFORM_WATCHOS_SIMULATOR:
		return "watchOS Simulator";
	case MACH0_PLATFORM_DRIVERKIT:
		return "driverKit";
	case MACH0_PLATFORM_VISIONOS:
		return "visionOS";
	case MACH0_PLATFORM_VISIONOS_SIMULATOR:
		return "visionOS Simulator";
	default:
		return "unknown";
	}
}

/**
 * String representation of CPU_TYPE_* values
 */
RZ_API RZ_NONNULL const char *rz_mach0_cputype_to_string(ut32 cputype) {
	switch (cputype) {
	case CPU_TYPE_VAX:
		return "vax";
	case CPU_TYPE_MC680x0:
		return "m68k";
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		return "x86";
	case CPU_TYPE_MC88000:
		return "mc88000";
	case CPU_TYPE_MC98000:
		return "mc98000";
	case CPU_TYPE_HPPA:
		return "hppa";
	case CPU_TYPE_ARM:
	case CPU_TYPE_ARM64:
	case CPU_TYPE_ARM64_32:
		return "arm";
	case CPU_TYPE_SPARC:
		return "sparc";
	case CPU_TYPE_MIPS:
		return "mips";
	case CPU_TYPE_I860:
		return "i860";
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		return "ppc";
	default:
		return "unknown";
	}
}

/**
 * String representation of CPU_SUBTYPE_* values as part of their \p cputype (CPU_TYPE_*)
 */
RZ_API RZ_NONNULL const char *rz_mach0_cpusubtype_tostring(ut32 cputype, ut32 cpusubtype) {
	switch (cputype) {
	case CPU_TYPE_VAX:
		switch (cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL: return "all";
		case CPU_SUBTYPE_VAX780: return "vax780";
		case CPU_SUBTYPE_VAX785: return "vax785";
		case CPU_SUBTYPE_VAX750: return "vax750";
		case CPU_SUBTYPE_VAX730: return "vax730";
		case CPU_SUBTYPE_UVAXI: return "uvaxI";
		case CPU_SUBTYPE_UVAXII: return "uvaxII";
		case CPU_SUBTYPE_VAX8200: return "vax8200";
		case CPU_SUBTYPE_VAX8500: return "vax8500";
		case CPU_SUBTYPE_VAX8600: return "vax8600";
		case CPU_SUBTYPE_VAX8650: return "vax8650";
		case CPU_SUBTYPE_VAX8800: return "vax8800";
		case CPU_SUBTYPE_UVAXIII: return "uvaxIII";
		default: return "Unknown VAX subtype";
		}
	case CPU_TYPE_MC680x0:
		switch (cpusubtype) {
		case CPU_SUBTYPE_MC68030: return "mc68030";
		case CPU_SUBTYPE_MC68040: return "mc68040";
		case CPU_SUBTYPE_MC68030_ONLY: return "mc68030 only";
		default: return "Unknown mc680x0 subtype";
		}
	case CPU_TYPE_I386:
		switch (cpusubtype) {
		case CPU_SUBTYPE_386: return "386";
		case CPU_SUBTYPE_486: return "486";
		case CPU_SUBTYPE_486SX: return "486sx";
		case CPU_SUBTYPE_PENT: return "Pentium";
		case CPU_SUBTYPE_PENTPRO: return "Pentium Pro";
		case CPU_SUBTYPE_PENTII_M3: return "Pentium 3 M3";
		case CPU_SUBTYPE_PENTII_M5: return "Pentium 3 M5";
		case CPU_SUBTYPE_CELERON: return "Celeron";
		case CPU_SUBTYPE_CELERON_MOBILE: return "Celeron Mobile";
		case CPU_SUBTYPE_PENTIUM_3: return "Pentium 3";
		case CPU_SUBTYPE_PENTIUM_3_M: return "Pentium 3 M";
		case CPU_SUBTYPE_PENTIUM_3_XEON: return "Pentium 3 Xeon";
		case CPU_SUBTYPE_PENTIUM_M: return "Pentium Mobile";
		case CPU_SUBTYPE_PENTIUM_4: return "Pentium 4";
		case CPU_SUBTYPE_PENTIUM_4_M: return "Pentium 4 M";
		case CPU_SUBTYPE_ITANIUM: return "Itanium";
		case CPU_SUBTYPE_ITANIUM_2: return "Itanium 2";
		case CPU_SUBTYPE_XEON: return "Xeon";
		case CPU_SUBTYPE_XEON_MP: return "Xeon MP";
		default: return "Unknown i386 subtype";
		}
	case CPU_TYPE_X86_64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_X86_64_ALL: return "x86 64 all";
		case CPU_SUBTYPE_X86_ARCH1: return "x86 arch 1";
		default: return "Unknown x86 subtype";
		}
	case CPU_TYPE_MC88000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC88000_ALL: return "all";
		case CPU_SUBTYPE_MC88100: return "mc88100";
		case CPU_SUBTYPE_MC88110: return "mc88110";
		default: return "Unknown mc88000 subtype";
		}
	case CPU_TYPE_MC98000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC98000_ALL: return "all";
		case CPU_SUBTYPE_MC98601: return "mc98601";
		default: return "Unknown mc98000 subtype";
		}
	case CPU_TYPE_HPPA:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_HPPA_7100: return "hppa7100";
		case CPU_SUBTYPE_HPPA_7100LC: return "hppa7100LC";
		default: return "Unknown HPPA subtype";
		}
	case CPU_TYPE_ARM64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM64_ALL: return "all";
		case CPU_SUBTYPE_ARM64_V8: return "arm64v8";
		case CPU_SUBTYPE_ARM64E: return "arm64e";
		default: return "Unknown arm64 subtype";
		}
	case CPU_TYPE_ARM64_32:
		return "arm64_32";
	case CPU_TYPE_ARM:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM_ALL:
			return "all";
		case CPU_SUBTYPE_ARM_V4T:
			return "v4t";
		case CPU_SUBTYPE_ARM_V5:
			return "v5";
		case CPU_SUBTYPE_ARM_V6:
			return "v6";
		case CPU_SUBTYPE_ARM_XSCALE:
			return "xscale";
		case CPU_SUBTYPE_ARM_V7:
			return "v7";
		case CPU_SUBTYPE_ARM_V7F:
			return "v7f";
		case CPU_SUBTYPE_ARM_V7S:
			return "v7s";
		case CPU_SUBTYPE_ARM_V7K:
			return "v7k";
		case CPU_SUBTYPE_ARM_V7M:
			return "v7m";
		case CPU_SUBTYPE_ARM_V7EM:
			return "v7em";
		default:
			eprintf("Unknown arm subtype %d\n", cpusubtype & 0xff);
			return "unknown arm subtype";
		}
	case CPU_TYPE_SPARC:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_SPARC_ALL: return "all";
		default: return "Unknown sparc subtype";
		}
	case CPU_TYPE_MIPS:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MIPS_ALL: return "all";
		case CPU_SUBTYPE_MIPS_R2300: return "r2300";
		case CPU_SUBTYPE_MIPS_R2600: return "r2600";
		case CPU_SUBTYPE_MIPS_R2800: return "r2800";
		case CPU_SUBTYPE_MIPS_R2000a: return "r2000a";
		case CPU_SUBTYPE_MIPS_R2000: return "r2000";
		case CPU_SUBTYPE_MIPS_R3000a: return "r3000a";
		case CPU_SUBTYPE_MIPS_R3000: return "r3000";
		default: return "Unknown mips subtype";
		}
	case CPU_TYPE_I860:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_I860_ALL: return "all";
		case CPU_SUBTYPE_I860_860: return "860";
		default: return "Unknown i860 subtype";
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_POWERPC_ALL: return "all";
		case CPU_SUBTYPE_POWERPC_601: return "601";
		case CPU_SUBTYPE_POWERPC_602: return "602";
		case CPU_SUBTYPE_POWERPC_603: return "603";
		case CPU_SUBTYPE_POWERPC_603e: return "603e";
		case CPU_SUBTYPE_POWERPC_603ev: return "603ev";
		case CPU_SUBTYPE_POWERPC_604: return "604";
		case CPU_SUBTYPE_POWERPC_604e: return "604e";
		case CPU_SUBTYPE_POWERPC_620: return "620";
		case CPU_SUBTYPE_POWERPC_750: return "750";
		case CPU_SUBTYPE_POWERPC_7400: return "7400";
		case CPU_SUBTYPE_POWERPC_7450: return "7450";
		case CPU_SUBTYPE_POWERPC_970: return "970";
		default: return "Unknown ppc subtype";
		}
	}
	return "Unknown cputype";
}

/**
 * String representation of a tool identifier from a LC_BUILD_VERSION load command
 */
RZ_API RZ_NONNULL const char *rz_mach0_build_version_tool_to_string(ut32 tool) {
	switch (tool) {
	case 1:
		return "clang";
	case 2:
		return "swift";
	case 3:
		return "ld";
	default:
		return "unknown";
	}
}
