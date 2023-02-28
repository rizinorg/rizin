// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file x86_il.c
 *
 * Converts x86 instructions to RzIL instructions
 *
 * References:
 *  - https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
 */

#include "x86_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

#define X86_BIT(x)  UN(1, x)
#define X86_TO32(x) UNSIGNED(32, x)

#define IL_LIFTER(mnem) static RzILOpEffect *x86_il_##mnem(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis)

/**
 * \brief x86 registers
 */
static const char *x86_registers[] = {
	[X86_REG_AH] = "ah",
	[X86_REG_AL] = "al",
	[X86_REG_AX] = "ax",
	[X86_REG_BH] = "bh",
	[X86_REG_BL] = "bl",
	[X86_REG_BP] = "bp",
	[X86_REG_BPL] = "bpl",
	[X86_REG_BX] = "bx",
	[X86_REG_CH] = "ch",
	[X86_REG_CL] = "cl",
	[X86_REG_CS] = "cs",
	[X86_REG_CX] = "cx",
	[X86_REG_DH] = "dh",
	[X86_REG_DI] = "di",
	[X86_REG_DIL] = "dil",
	[X86_REG_DL] = "dl",
	[X86_REG_DS] = "ds",
	[X86_REG_DX] = "dx",
	[X86_REG_EAX] = "eax",
	[X86_REG_EBP] = "ebp",
	[X86_REG_EBX] = "ebx",
	[X86_REG_ECX] = "ecx",
	[X86_REG_EDI] = "edi",
	[X86_REG_EDX] = "edx",
	[X86_REG_EFLAGS] = "eflags",
	[X86_REG_EIP] = "eip",
	[X86_REG_EIZ] = "eiz",
	[X86_REG_ES] = "es",
	[X86_REG_ESI] = "esi",
	[X86_REG_ESP] = "esp",
	[X86_REG_FPSW] = "fpsw",
	[X86_REG_FS] = "fs",
	[X86_REG_GS] = "gs",
	[X86_REG_IP] = "ip",
	[X86_REG_RAX] = "rax",
	[X86_REG_RBP] = "rbp",
	[X86_REG_RBX] = "rbx",
	[X86_REG_RCX] = "rcx",
	[X86_REG_RDI] = "rdi",
	[X86_REG_RDX] = "rdx",
	[X86_REG_RIP] = "rip",
	[X86_REG_RIZ] = "riz",
	[X86_REG_RSI] = "rsi",
	[X86_REG_RSP] = "rsp",
	[X86_REG_SI] = "si",
	[X86_REG_SIL] = "sil",
	[X86_REG_SP] = "sp",
	[X86_REG_SPL] = "spl",
	[X86_REG_SS] = "ss",
	[X86_REG_CR0] = "cr0",
	[X86_REG_CR1] = "cr1",
	[X86_REG_CR2] = "cr2",
	[X86_REG_CR3] = "cr3",
	[X86_REG_CR4] = "cr4",
	[X86_REG_CR5] = "cr5",
	[X86_REG_CR6] = "cr6",
	[X86_REG_CR7] = "cr7",
	[X86_REG_CR8] = "cr8",
	[X86_REG_CR9] = "cr9",
	[X86_REG_CR10] = "cr10",
	[X86_REG_CR11] = "cr11",
	[X86_REG_CR12] = "cr12",
	[X86_REG_CR13] = "cr13",
	[X86_REG_CR14] = "cr14",
	[X86_REG_CR15] = "cr15",
	[X86_REG_DR0] = "dr0",
	[X86_REG_DR1] = "dr1",
	[X86_REG_DR2] = "dr2",
	[X86_REG_DR3] = "dr3",
	[X86_REG_DR4] = "dr4",
	[X86_REG_DR5] = "dr5",
	[X86_REG_DR6] = "dr6",
	[X86_REG_DR7] = "dr7",
#if CS_API_MAJOR >= 4
	[X86_REG_DR8] = "dr8",
	[X86_REG_DR9] = "dr9",
	[X86_REG_DR10] = "dr10",
	[X86_REG_DR11] = "dr11",
	[X86_REG_DR12] = "dr12",
	[X86_REG_DR13] = "dr13",
	[X86_REG_DR14] = "dr14",
	[X86_REG_DR15] = "dr15",
#endif
	[X86_REG_FP0] = "fp0",
	[X86_REG_FP1] = "fp1",
	[X86_REG_FP2] = "fp2",
	[X86_REG_FP3] = "fp3",
	[X86_REG_FP4] = "fp4",
	[X86_REG_FP5] = "fp5",
	[X86_REG_FP6] = "fp6",
	[X86_REG_FP7] = "fp7",
	[X86_REG_K0] = "k0",
	[X86_REG_K1] = "k1",
	[X86_REG_K2] = "k2",
	[X86_REG_K3] = "k3",
	[X86_REG_K4] = "k4",
	[X86_REG_K5] = "k5",
	[X86_REG_K6] = "k6",
	[X86_REG_K7] = "k7",
	[X86_REG_MM0] = "mm0",
	[X86_REG_MM1] = "mm1",
	[X86_REG_MM2] = "mm2",
	[X86_REG_MM3] = "mm3",
	[X86_REG_MM4] = "mm4",
	[X86_REG_MM5] = "mm5",
	[X86_REG_MM6] = "mm6",
	[X86_REG_MM7] = "mm7",
	[X86_REG_R8] = "r8",
	[X86_REG_R9] = "r9",
	[X86_REG_R10] = "r10",
	[X86_REG_R11] = "r11",
	[X86_REG_R12] = "r12",
	[X86_REG_R13] = "r13",
	[X86_REG_R14] = "r14",
	[X86_REG_R15] = "r15",
	[X86_REG_ST0] = "st0",
	[X86_REG_ST1] = "st1",
	[X86_REG_ST2] = "st2",
	[X86_REG_ST3] = "st3",
	[X86_REG_ST4] = "st4",
	[X86_REG_ST5] = "st5",
	[X86_REG_ST6] = "st6",
	[X86_REG_ST7] = "st7",
	[X86_REG_XMM0] = "xmm0",
	[X86_REG_XMM1] = "xmm1",
	[X86_REG_XMM2] = "xmm2",
	[X86_REG_XMM3] = "xmm3",
	[X86_REG_XMM4] = "xmm4",
	[X86_REG_XMM5] = "xmm5",
	[X86_REG_XMM6] = "xmm6",
	[X86_REG_XMM7] = "xmm7",
	[X86_REG_XMM8] = "xmm8",
	[X86_REG_XMM9] = "xmm9",
	[X86_REG_XMM10] = "xmm10",
	[X86_REG_XMM11] = "xmm11",
	[X86_REG_XMM12] = "xmm12",
	[X86_REG_XMM13] = "xmm13",
	[X86_REG_XMM14] = "xmm14",
	[X86_REG_XMM15] = "xmm15",
	[X86_REG_XMM16] = "xmm16",
	[X86_REG_XMM17] = "xmm17",
	[X86_REG_XMM18] = "xmm18",
	[X86_REG_XMM19] = "xmm19",
	[X86_REG_XMM20] = "xmm20",
	[X86_REG_XMM21] = "xmm21",
	[X86_REG_XMM22] = "xmm22",
	[X86_REG_XMM23] = "xmm23",
	[X86_REG_XMM24] = "xmm24",
	[X86_REG_XMM25] = "xmm25",
	[X86_REG_XMM26] = "xmm26",
	[X86_REG_XMM27] = "xmm27",
	[X86_REG_XMM28] = "xmm28",
	[X86_REG_XMM29] = "xmm29",
	[X86_REG_XMM30] = "xmm30",
	[X86_REG_XMM31] = "xmm31",
	[X86_REG_YMM0] = "ymm0",
	[X86_REG_YMM1] = "ymm1",
	[X86_REG_YMM2] = "ymm2",
	[X86_REG_YMM3] = "ymm3",
	[X86_REG_YMM4] = "ymm4",
	[X86_REG_YMM5] = "ymm5",
	[X86_REG_YMM6] = "ymm6",
	[X86_REG_YMM7] = "ymm7",
	[X86_REG_YMM8] = "ymm8",
	[X86_REG_YMM9] = "ymm9",
	[X86_REG_YMM10] = "ymm10",
	[X86_REG_YMM11] = "ymm11",
	[X86_REG_YMM12] = "ymm12",
	[X86_REG_YMM13] = "ymm13",
	[X86_REG_YMM14] = "ymm14",
	[X86_REG_YMM15] = "ymm15",
	[X86_REG_YMM16] = "ymm16",
	[X86_REG_YMM17] = "ymm17",
	[X86_REG_YMM18] = "ymm18",
	[X86_REG_YMM19] = "ymm19",
	[X86_REG_YMM20] = "ymm20",
	[X86_REG_YMM21] = "ymm21",
	[X86_REG_YMM22] = "ymm22",
	[X86_REG_YMM23] = "ymm23",
	[X86_REG_YMM24] = "ymm24",
	[X86_REG_YMM25] = "ymm25",
	[X86_REG_YMM26] = "ymm26",
	[X86_REG_YMM27] = "ymm27",
	[X86_REG_YMM28] = "ymm28",
	[X86_REG_YMM29] = "ymm29",
	[X86_REG_YMM30] = "ymm30",
	[X86_REG_YMM31] = "ymm31",
	[X86_REG_ZMM0] = "zmm0",
	[X86_REG_ZMM1] = "zmm1",
	[X86_REG_ZMM2] = "zmm2",
	[X86_REG_ZMM3] = "zmm3",
	[X86_REG_ZMM4] = "zmm4",
	[X86_REG_ZMM5] = "zmm5",
	[X86_REG_ZMM6] = "zmm6",
	[X86_REG_ZMM7] = "zmm7",
	[X86_REG_ZMM8] = "zmm8",
	[X86_REG_ZMM9] = "zmm9",
	[X86_REG_ZMM10] = "zmm10",
	[X86_REG_ZMM11] = "zmm11",
	[X86_REG_ZMM12] = "zmm12",
	[X86_REG_ZMM13] = "zmm13",
	[X86_REG_ZMM14] = "zmm14",
	[X86_REG_ZMM15] = "zmm15",
	[X86_REG_ZMM16] = "zmm16",
	[X86_REG_ZMM17] = "zmm17",
	[X86_REG_ZMM18] = "zmm18",
	[X86_REG_ZMM19] = "zmm19",
	[X86_REG_ZMM20] = "zmm20",
	[X86_REG_ZMM21] = "zmm21",
	[X86_REG_ZMM22] = "zmm22",
	[X86_REG_ZMM23] = "zmm23",
	[X86_REG_ZMM24] = "zmm24",
	[X86_REG_ZMM25] = "zmm25",
	[X86_REG_ZMM26] = "zmm26",
	[X86_REG_ZMM27] = "zmm27",
	[X86_REG_ZMM28] = "zmm28",
	[X86_REG_ZMM29] = "zmm29",
	[X86_REG_ZMM30] = "zmm30",
	[X86_REG_ZMM31] = "zmm31",
	[X86_REG_R8B] = "r8b",
	[X86_REG_R9B] = "r9b",
	[X86_REG_R10B] = "r10b",
	[X86_REG_R11B] = "r11b",
	[X86_REG_R12B] = "r12b",
	[X86_REG_R13B] = "r13b",
	[X86_REG_R14B] = "r14b",
	[X86_REG_R15B] = "r15b",
	[X86_REG_R8D] = "r8d",
	[X86_REG_R9D] = "r9d",
	[X86_REG_R10D] = "r10d",
	[X86_REG_R11D] = "r11d",
	[X86_REG_R12D] = "r12d",
	[X86_REG_R13D] = "r13d",
	[X86_REG_R14D] = "r14d",
	[X86_REG_R15D] = "r15d",
	[X86_REG_R8W] = "r8w",
	[X86_REG_R9W] = "r9w",
	[X86_REG_R10W] = "r10w",
	[X86_REG_R11W] = "r11w",
	[X86_REG_R12W] = "r12w",
	[X86_REG_R13W] = "r13w",
	[X86_REG_R14W] = "r14w",
	[X86_REG_R15W] = "r15w"
};

// Namespace clash with android-ndk-25b's x86_64-linux-android/asm/processor-flags.h
#undef X86_EFLAGS_CF
#undef X86_EFLAGS_PF
#undef X86_EFLAGS_AF
#undef X86_EFLAGS_ZF
#undef X86_EFLAGS_SF
#undef X86_EFLAGS_TF
#undef X86_EFLAGS_IF
#undef X86_EFLAGS_DF
#undef X86_EFLAGS_OF
#undef X86_EFLAGS_IOPL
#undef X86_EFLAGS_NT
#undef X86_EFLAGS_RF
#undef X86_EFLAGS_VM
#undef X86_EFLAGS_AC
#undef X86_EFLAGS_VIF
#undef X86_EFLAGS_VIP
#undef X86_EFLAGS_ID

typedef enum x86_eflags_t {
	X86_EFLAGS_CF = 0,
	X86_EFLAGS_PF = 2,
	X86_EFLAGS_AF = 4,
	X86_EFLAGS_ZF = 6,
	X86_EFLAGS_SF = 7,
	X86_EFLAGS_TF = 8,
	X86_EFLAGS_IF = 9,
	X86_EFLAGS_DF = 10,
	X86_EFLAGS_OF = 11,
	X86_EFLAGS_IOPL = 12,
	X86_EFLAGS_NT = 14,
	X86_EFLAGS_RF = 16,
	X86_EFLAGS_VM = 17,
	X86_EFLAGS_AC = 18,
	X86_EFLAGS_VIF = 19,
	X86_EFLAGS_VIP = 20,
	X86_EFLAGS_ID = 21
} X86EFlags;

static const char *x86_eflags_registers[] = {
	[X86_EFLAGS_CF] = "cf",
	[X86_EFLAGS_PF] = "pf",
	[X86_EFLAGS_AF] = "af",
	[X86_EFLAGS_ZF] = "zf",
	[X86_EFLAGS_SF] = "sf",
	[X86_EFLAGS_TF] = "tf",
	[X86_EFLAGS_IF] = "if",
	[X86_EFLAGS_DF] = "df",
	[X86_EFLAGS_OF] = "of",
	[X86_EFLAGS_NT] = "nt",
	[X86_EFLAGS_RF] = "rf",
	[X86_EFLAGS_VM] = "vm",
	[X86_EFLAGS_AC] = "ac"
};

#define EFLAGS(f) x86_eflags_registers[X86_EFLAGS_##f]

#define COMMON_REGS \
	"cs", /* X86_REG_CS */ \
		"ss", /* X86_REG_SS */ \
		"ds", /* X86_REG_DS */ \
		"es", /* X86_REG_ES */ \
		"cf", /* X86_EFLAGS_CF */ \
		"pf", /* X86_EFLAGS_PF */ \
		"af", /* X86_EFLAGS_AF */ \
		"zf", /* X86_EFLAGS_ZF */ \
		"sf", /* X86_EFLAGS_SF */ \
		"tf", /* X86_EFLAGS_TF */ \
		"if", /* X86_EFLAGS_IF */ \
		"df", /* X86_EFLAGS_DF */ \
		"of", /* X86_EFLAGS_OF */ \
		"nt" /* X86_EFLAGS_NT */

/**
 * \brief All registers bound to IL variables for x86 16-bit
 */
static const char *x86_bound_regs_16[] = {
	COMMON_REGS,
	"ax", /* X86_REG_AX */
	"bx", /* X86_REG_BX */
	"cx", /* X86_REG_CX */
	"dx", /* X86_REG_DX */
	"sp", /* X86_REG_SP */
	"bp", /* X86_REG_BP */
	"si", /* X86_REG_SI */
	"di", /* X86_REG_DI */
	NULL
};

/**
 * \brief All registers bound to IL variables for x86 32-bit
 */
static const char *x86_bound_regs_32[] = {
	COMMON_REGS,
	"eax", /* X86_REG_EAX */
	"ebx", /* X86_REG_EBX */
	"ecx", /* X86_REG_ECX */
	"edx", /* X86_REG_EDX */
	"esp", /* X86_REG_ESP */
	"ebp", /* X86_REG_EBP */
	"esi", /* X86_REG_ESI */
	"edi", /* X86_REG_EDI */
	"rf", /* X86_EFLAGS_RF */
	"vm", /* X86_EFLAGS_VM */
	"ac", /* X86_EFLAGS_AC */
	"fs", /* X86_REG_FS */
	"gs", /* X86_REG_GS */
	"cr0", /* X86_REG_CR0 */
	"dr0", /* X86_REG_DR0 */
	NULL
};

/**
 * \brief All registers bound to IL variables for x86 64-bit
 */
static const char *x86_bound_regs_64[] = {
	COMMON_REGS,
	"rax", /* X86_REG_RAX */
	"rbx", /* X86_REG_RBX */
	"rcx", /* X86_REG_RCX */
	"rdx", /* X86_REG_RDX */
	"rsp", /* X86_REG_RSP */
	"rbp", /* X86_REG_RBP */
	"rsi", /* X86_REG_RSI */
	"rdi", /* X86_REG_RDI */
	"r8", /* X86_REG_R8 */
	"r9", /* X86_REG_R9 */
	"r10", /* X86_REG_R10 */
	"r11", /* X86_REG_R11 */
	"r12", /* X86_REG_R12 */
	"r13", /* X86_REG_R13 */
	"r14", /* X86_REG_R14 */
	"r15", /* X86_REG_R15 */
	"rf", /* X86_EFLAGS_RF */
	"vm", /* X86_EFLAGS_VM */
	"ac", /* X86_EFLAGS_AC */
	"fs", /* X86_REG_FS */
	"gs", /* X86_REG_GS */
	"cr0", /* X86_REG_CR0 */
	"dr0", /* X86_REG_DR0 */
	NULL
};

static const X86Reg gpr_hregs[] = {
	X86_REG_AH, // rax
	X86_REG_BH, // rbx
	X86_REG_CH, // rcx
	X86_REG_DH, // rdx
	X86_REG_INVALID, // rbp
	X86_REG_INVALID, // rdi
	X86_REG_INVALID, // rip
	X86_REG_INVALID, // riz
	X86_REG_INVALID, // rsi
	X86_REG_INVALID // rsp
};

static const X86Reg gpr_lregs[] = {
	X86_REG_AL, // rax
	X86_REG_BL, // rbx
	X86_REG_CL, // rcx
	X86_REG_DL, // rdx
	X86_REG_BPL, // rbp
	X86_REG_DIL, // rdi
	X86_REG_INVALID, // rip
	X86_REG_INVALID, // riz
	X86_REG_SIL, // rsi
	X86_REG_SPL, // rsp
};

static const X86Reg gpr_xregs[] = {
	X86_REG_AX, // rax
	X86_REG_BX, // rbx
	X86_REG_CX, // rcx
	X86_REG_DX, // rdx
	X86_REG_BP, // rbp
	X86_REG_DI, // rdi
	X86_REG_IP, // rip
	X86_REG_INVALID, // riz
	X86_REG_SI, // rsi
	X86_REG_SP, // rsp
};

static const X86Reg gpr_eregs[] = {
	X86_REG_EAX, // rax
	X86_REG_EBX, // rbx
	X86_REG_ECX, // rcx
	X86_REG_EDX, // rdx
	X86_REG_EBP, // rbp
	X86_REG_EDI, // rdi
	X86_REG_EIP, // rip
	X86_REG_EIZ, // riz
	X86_REG_ESI, // rsi
	X86_REG_ESP, // rsp
};

static const X86Reg gpr_rregs[] = {
	X86_REG_RAX,
	X86_REG_RBX,
	X86_REG_RCX,
	X86_REG_RDX,
	X86_REG_RBP,
	X86_REG_RDI,
	X86_REG_RIP,
	X86_REG_RIZ,
	X86_REG_RSI,
	X86_REG_RSP
};

/**
 * \brief Check if \p reg is a general purpose register (this term is quite loosely used here)
 *
 * \param reg
 */
static bool x86_il_is_gpr(X86Reg reg) {
	for (unsigned int i = 0; i < GPR_FAMILY_COUNT; i++) {
		if (reg == gpr_hregs[i] || reg == gpr_lregs[i] || reg == gpr_xregs[i] || reg == gpr_eregs[i] || reg == gpr_rregs[i]) {
			return true;
		}
	}

	return false;
}

/**
 * \brief Get size of \p reg
 *
 * \param reg
 */
static ut8 x86_il_get_reg_size(X86Reg reg) {
	for (unsigned int i = 0; i < GPR_FAMILY_COUNT; i++) {
		if (reg == gpr_hregs[i] || reg == gpr_lregs[i]) {
			return 8;
		} else if (reg == gpr_xregs[i]) {
			return 16;
		} else if (reg == gpr_eregs[i]) {
			return 32;
		} else if (reg == gpr_rregs[i]) {
			return 64;
		}
	}

	return 0;
}

/**
 * \brief  Get the higher 8 bits (8-16) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
static RzILOpPure *x86_il_get_gprh(X86Reg reg, int bits) {
	return UNSIGNED(8, SHIFTR0(VARG(x86_registers[reg]), U8(8)));
}
/**
 * \brief Get the lower 8 bits (0-8) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
static RzILOpPure *x86_il_get_gprl(X86Reg reg, int bits) {
	return UNSIGNED(8, VARG(x86_registers[reg]));
}
/**
 * \brief Get the lower 16 bits (0-16) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
static RzILOpPure *x86_il_get_gpr16(X86Reg reg, int bits) {
	if (bits == 16) {
		// Don't perform unnecessary casting
		return VARG(x86_registers[reg]);
	}
	return UNSIGNED(16, VARG(x86_registers[reg]));
}
/**
 * \brief Get the lower 32 bits (0-32) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
static RzILOpPure *x86_il_get_gpr32(X86Reg reg, int bits) {
	if (bits == 32) {
		return VARG(x86_registers[reg]);
	}
	return UNSIGNED(32, VARG(x86_registers[reg]));
}
/**
 * \brief Get 64 bits (0-64) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
static RzILOpPure *x86_il_get_gpr64(X86Reg reg, int bits) {
	return VARG(x86_registers[reg]);
}

/**
 * \brief  Set the higher 8 bits (8-16) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
static RzILOpEffect *x86_il_set_gprh(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	RzILOpPure *mask = LOGNOT(UN(bits, 0xff00));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, SHIFTL0(UNSIGNED(bits, val), U8(8)));
	return SETG(x86_registers[reg], final_reg);
}
/**
 * \brief  Set the lower 8 bits (0-8) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
static RzILOpEffect *x86_il_set_gprl(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	RzILOpPure *mask = LOGNOT(UN(bits, 0xff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(bits, val));
	return SETG(x86_registers[reg], final_reg);
}
/**
 * \brief  Set the lower 16 bits (0-16) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
static RzILOpEffect *x86_il_set_gpr16(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	if (bits == 16) {
		// Don't perform unnecessary casting
		return SETG(x86_registers[reg], val);
	}
	RzILOpPure *mask = LOGNOT(UN(bits, 0xffff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(bits, val));
	return SETG(x86_registers[reg], final_reg);
}
/**
 * \brief  Set the lower 32 bits (0-32) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
static RzILOpEffect *x86_il_set_gpr32(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	if (bits == 32) {
		return SETG(x86_registers[reg], val);
	}
	RzILOpPure *mask = LOGNOT(UN(bits, 0xffffffff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(bits, val));
	return SETG(x86_registers[reg], final_reg);
}
/**
 * \brief  Set 64 bits (0-64) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
static RzILOpEffect *x86_il_set_gpr64(X86Reg reg, RzILOpPure *val, int bits) {
	return SETG(x86_registers[reg], val);
}

/**
 * \brief Get the widest register corresponding to index \p index and bitness \p bits
 *
 * \param index
 * \param bits
 */
static X86Reg get_bitness_reg(unsigned int index, int bits) {
	if (index >= GPR_FAMILY_COUNT) {
		return X86_REG_INVALID;
	}
	if (bits == 16) {
		return gpr_xregs[index];
	} else if (bits == 32) {
		return gpr_eregs[index];
	} else {
		return gpr_rregs[index];
	}
}

struct gpr_lookup_helper_t {
	unsigned int index; ///< register index
	RzILOpPure *(*get_handler)(X86Reg, int); ///< getter
	RzILOpEffect *(*set_handler)(X86Reg, RzILOpPure *, int); ///< setter
};

static const struct gpr_lookup_helper_t gpr_lookup_table[] = {
	[X86_REG_AH] = { 0, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_AL] = { 0, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_AX] = { 0, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EAX] = { 0, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RAX] = { 0, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_BH] = { 1, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_BL] = { 1, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_BX] = { 1, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EBX] = { 1, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RBX] = { 1, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_CH] = { 2, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_CL] = { 2, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_CX] = { 2, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_ECX] = { 2, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RCX] = { 2, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_DH] = { 3, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_DL] = { 3, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_DX] = { 3, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EDX] = { 3, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RDX] = { 3, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_BPL] = { 4, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_BP] = { 4, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EBP] = { 4, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RBP] = { 4, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_DIL] = { 5, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_DI] = { 5, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EDI] = { 5, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RDI] = { 5, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_EIZ] = { 7, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RIZ] = { 7, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_SIL] = { 8, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_SI] = { 8, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_ESI] = { 8, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RSI] = { 8, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_SPL] = { 9, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_SP] = { 9, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_ESP] = { 9, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RSP] = { 9, x86_il_get_gpr64, x86_il_set_gpr64 }
};

/**
 * \brief Check if the register \p reg is an instruction pointer register
 *
 * \param reg
 */
bool is_pc_reg(X86Reg reg) {
	return (reg == X86_REG_IP || reg == X86_REG_EIP || reg == X86_REG_RIP);
}

struct extreg_lookup_helper_t {
	X86Reg curr_reg; ///< register being used
	X86Reg base_reg; ///< base register for `curr_reg`
	RzILOpPure *(*get_handler)(X86Reg, int); ///< getter
	RzILOpEffect *(*set_handler)(X86Reg, RzILOpPure *, int); ///< setter
};

#define extreg_lookup(suff, getter, setter) \
	{ X86_REG_R8##suff, X86_REG_R8, getter, setter }, \
		{ X86_REG_R9##suff, X86_REG_R9, getter, setter }, \
		{ X86_REG_R10##suff, X86_REG_R10, getter, setter }, \
		{ X86_REG_R11##suff, X86_REG_R11, getter, setter }, \
		{ X86_REG_R12##suff, X86_REG_R12, getter, setter }, \
		{ X86_REG_R13##suff, X86_REG_R13, getter, setter }, \
		{ X86_REG_R14##suff, X86_REG_R14, getter, setter }, \
		{ X86_REG_R15##suff, X86_REG_R15, getter, setter },

static const struct extreg_lookup_helper_t extreg_lookup_table[] = {
	// 64-bit wide
	extreg_lookup(, x86_il_get_gpr64, x86_il_set_gpr64)

	// 8-bit wide (byte)
	extreg_lookup(B, x86_il_get_gprl, x86_il_set_gprl)

	// 16-bit wide (word)
	extreg_lookup(W, x86_il_get_gpr16, x86_il_set_gpr16)

	// 32-bit wide (dword)
	extreg_lookup(D, x86_il_get_gpr32, x86_il_set_gpr32)
};

/**
 * \brief Get the index for external register \p reg
 *
 * \param reg
 */
int get_extreg_ind(X86Reg reg) {
	for (unsigned int i = 0; i < 8 * 4 /* size of extreg_lookup_table */; i++) {
		if (extreg_lookup_table[i].curr_reg == reg) {
			return i;
		}
	}

	return -1;
}

/**
 * \brief Get the value of a register \p reg, in a "smart" way
 * Just use the `x86_il_get_reg` macro whenever you need to get the
 * value of a register. This function will take care of all the casting
 * and extracting of (smaller) registers.
 *
 * \param reg
 * \param bits bitness
 * \param pc Program counter
 */
static RzILOpPure *x86_il_get_reg_bits(X86Reg reg, int bits, uint64_t pc) {
	if (is_pc_reg(reg)) {
		return UN(bits, pc);
	}

	int ind = -1;

	if (x86_il_is_gpr(reg)) {
		struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
		/* Need to use `get_bitness_reg` because not all registers
		are available in the IL in any particular bitness
		(For example, "rax" is not a valid IL variable in 32-bit mode)
		So, we need to use the max width register available */
		return entry.get_handler(get_bitness_reg(entry.index, bits), bits);
	} else if ((ind = get_extreg_ind(reg)) != -1 && bits == 64) {
		struct extreg_lookup_helper_t entry = extreg_lookup_table[ind];
		return entry.get_handler(entry.base_reg, bits);
	}

	return VARG(x86_registers[reg]);
}

#define x86_il_get_reg(reg) x86_il_get_reg_bits(reg, analysis->bits, pc)

/**
 * \brief Set the value of a register \p reg, in a "smart" way
 * Just use the `x86_il_set_reg` macro whenever you need to set the
 * value of a register. This function will take care of all the casting
 * and storing and compositing values in case of (smaller) registers.
 *
 * \param reg
 * \param val Value to be stored
 * \param bits bitness
 */
static RzILOpEffect *x86_il_set_reg_bits(X86Reg reg, RzILOpPure *val, int bits) {
	int ind = -1;

	if (x86_il_is_gpr(reg)) {
		struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
		return entry.set_handler(get_bitness_reg(entry.index, bits), val, bits);
	} else if ((ind = get_extreg_ind(reg)) != -1 && bits == 64) {
		struct extreg_lookup_helper_t entry = extreg_lookup_table[ind];
		return entry.set_handler(entry.base_reg, val, bits);
	}

	return SETG(x86_registers[reg], val);
}

#define x86_il_set_reg(reg, val) x86_il_set_reg_bits(reg, val, analysis->bits)

/**
 * \brief Get the memory address as an `RzILOpPure` from X86Mem \p mem
 * You can also optionally provide a custom segment register as \p segment
 * This function takes care of all casting and conversion
 * This has partial segmentation support as of now
 *
 * You probably wouldn't need to use it directly, consider using the wrappers
 * `x86_il_get_memaddr` and `x86_il_set_memaddr`
 *
 * \param mem
 * \param segment
 * \param bits bitness
 */
static RzILOpPure *x86_il_get_memaddr_segment_bits(X86Mem mem, X86Reg segment, int bits) {
	RzILOpPure *offset = NULL;
	if (mem.base != X86_REG_INVALID && !offset) {
		offset = x86_il_get_reg_bits(mem.base, bits, 0);
		if (x86_il_get_reg_size(mem.base) != bits) {
			offset = UNSIGNED(bits, offset);
		}
	}
	if (mem.index != X86_REG_INVALID) {
		RzILOpPure *reg = x86_il_get_reg_bits(mem.index, bits, 0);
		if (x86_il_get_reg_size(mem.index) != bits) {
			reg = UNSIGNED(bits, reg);
		}
		if (!offset) {
			offset = MUL(reg, UN(bits, mem.scale));
		} else {
			offset = ADD(offset, MUL(reg, UN(bits, mem.scale)));
		}
	}
	if (!offset) {
		offset = UN(bits, mem.disp);
	} else {
		offset = ADD(offset, UN(bits, mem.disp));
	}

	/* Segmentation not present in x86-64 */
	if (bits != 64 && segment != X86_REG_INVALID) {
		// TODO: Implement segmentation
		/* Currently the segmentation is only implemented for real mode
		 Address = Segment * 0x10 + Offset */

		/* Assuming real mode */
		offset = ADD(offset, SHIFTL0(UNSIGNED(bits, x86_il_get_reg_bits(segment, bits, 0)), U8(4)));
	}

	return offset;
}

#define x86_il_get_memaddr_segment(mem, segment) x86_il_get_memaddr_segment_bits(mem, segment, analysis->bits)

static RzILOpPure *x86_il_get_memaddr_bits(X86Mem mem, int bits) {
	return x86_il_get_memaddr_segment_bits(mem, mem.segment, bits);
}

#define x86_il_get_memaddr(mem) x86_il_get_memaddr_bits(mem, analysis->bits)

static RzILOpEffect *x86_il_set_mem_bits(X86Mem mem, RzILOpPure *val, int bits) {
	return STOREW(x86_il_get_memaddr_bits(mem, bits), val);
}

#define x86_il_set_mem(mem, val) x86_il_set_mem_bits(mem, val, analysis->bits)

/**
 * \brief Get the value of the operand \p op
 * This function takes care of everything, like choosing
 * the correct type and returning the correct value
 * Use the wrapper `x86_il_get_op`
 *
 * \param op
 * \param analysis_bits bitness
 */
static RzILOpPure *x86_il_get_operand_bits(X86Op op, int analysis_bits) {
	RzILOpPure *ret = NULL;
	switch (op.type) {
	case X86_OP_INVALID:
		RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered\n");
		break;
	case X86_OP_REG:
		ret = x86_il_get_reg_bits(op.reg, analysis_bits, 0);
		break;
	case X86_OP_IMM:
		ret = SN(op.size * BITS_PER_BYTE, op.imm);
		break;
	case X86_OP_MEM:
		ret = LOADW(BITS_PER_BYTE * op.size, x86_il_get_memaddr_bits(op.mem, analysis_bits));
		break;
#if CS_API_MAJOR <= 3
	case X86_OP_FP:
		RZ_LOG_WARN("RzIL: x86: Floating point instructions not implemented yet\n");
		break;
#endif
	}
	return ret;
}

#define x86_il_get_operand(op) x86_il_get_operand_bits(op, analysis->bits)
#define x86_il_get_op(opnum)   x86_il_get_operand_bits(ins->structure->operands[opnum], analysis->bits)

/**
 * \brief Get the value of the operand \p op
 * This function takes care of everything, like choosing
 * the correct type and setting the correct value
 * Use the wrapper `x86_il_set_op`
 *
 * \param op
 * \param analysis_bits bitness
 */
static RzILOpEffect *x86_il_set_operand_bits(X86Op op, RzILOpPure *val, int bits) {
	RzILOpEffect *ret = NULL;
	switch (op.type) {
	case X86_OP_REG:
		ret = x86_il_set_reg_bits(op.reg, val, bits);
		break;
	case X86_OP_MEM:
		ret = x86_il_set_mem_bits(op.mem, val, bits);
		break;
	case X86_OP_IMM:
		RZ_LOG_ERROR("x86: RzIL: Cannot set an immediate operand\n");
		break;
	default:
		RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered\n");
		break;
	}
	return ret;
}

#define x86_il_set_operand(op, val) x86_il_set_operand_bits(op, val, analysis->bits)
#define x86_il_set_op(opnum, val)   x86_il_set_operand_bits(ins->structure->operands[opnum], val, analysis->bits)

/**
 * \brief Return the carry bit when \p x and \p y are added, with result \p res
 *
 * \param res
 * \param x
 * \param y
 */
static RzILOpBool *x86_il_is_add_carry(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x + y
	RzILOpBool *xmsb = MSB(x);
	RzILOpBool *ymsb = MSB(y);
	RzILOpBool *resmsb = MSB(res);

	// x & y
	RzILOpBool *xy = AND(xmsb, ymsb);
	RzILOpBool *nres = INV(resmsb);

	// !res & y
	RzILOpBool *ry = AND(nres, DUP(ymsb));
	// x & !res
	RzILOpBool *xr = AND(DUP(xmsb), DUP(nres));

	// bit = xy | ry | xr
	RzILOpBool * or = OR(xy, ry);
	or = OR(or, xr);

	return or ;
}

/**
 * \brief Return the borrow bit when \p y is subtracted from \p x, with result \p res
 *
 * \param res
 * \param x
 * \param y
 */
static RzILOpBool *x86_il_is_sub_borrow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x - y
	RzILOpBool *xmsb = MSB(x);
	RzILOpBool *ymsb = MSB(y);
	RzILOpBool *resmsb = MSB(res);

	// !x & y
	RzILOpBool *nx = INV(xmsb);
	RzILOpBool *nxy = AND(nx, ymsb);

	// y & res
	RzILOpBool *rny = AND(DUP(ymsb), resmsb);
	// res & !x
	RzILOpBool *rnx = AND(DUP(resmsb), DUP(nx));

	// bit = nxy | rny | rnx
	RzILOpBool * or = OR(nxy, rny);
	or = OR(or, rnx);

	return or ;
}

/**
 * \brief Return the overflow bit when \p x and \p y are added, with result \p res
 *
 * \param res
 * \param x
 * \param y
 */
static RzILOpBool *x86_il_is_add_overflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x + y
	RzILOpBool *xmsb = MSB(x);
	RzILOpBool *ymsb = MSB(y);
	RzILOpBool *resmsb = MSB(res);

	// !res & x & y
	RzILOpBool *nrxy = AND(AND(INV(resmsb), xmsb), ymsb);
	// res & !x & !y
	RzILOpBool *rnxny = AND(AND(DUP(resmsb), INV(DUP(xmsb))), INV(DUP(ymsb)));
	// or = nrxy | rnxny
	RzILOpBool * or = OR(nrxy, rnxny);

	return or ;
}

/**
 * \brief Return the underflow bit when \p y is subtracted from \p x, with result \p res
 *
 * \param res
 * \param x
 * \param y
 */
static RzILOpBool *x86_il_is_sub_underflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x - y
	RzILOpBool *xmsb = MSB(x);
	RzILOpBool *ymsb = MSB(y);
	RzILOpBool *resmsb = MSB(res);

	// !res & x & !y
	RzILOpBool *nrxny = AND(AND(INV(resmsb), xmsb), INV(ymsb));
	// res & !x & y
	RzILOpBool *rnxy = AND(AND(DUP(resmsb), INV(DUP(xmsb))), DUP(ymsb));
	// or = nrxny | rnxy
	RzILOpBool * or = OR(nrxny, rnxy);

	return or ;
}

/**
 * \brief Convert a bool \p b to a bitvector of length \p bits
 *
 * \param b
 * \param bits
 */
static RzILOpBitVector *x86_bool_to_bv(RzILOpBool *b, unsigned int bits) {
	return ITE(b, UN(bits, 1), UN(bits, 0));
}

struct x86_parity_helper_t {
	RzILOpBool *val; ///< value of parity
	RzILOpEffect *eff; ///< RzILOpEffect used to find the parity
};

/**
 * \brief Find the parity of lower 8 bits of \p val
 *
 * \param val
 */
static struct x86_parity_helper_t x86_il_get_parity(RZ_OWN RzILOpPure *val) {
	// assumed that val is an 8-bit wide value
	RzILOpEffect *setvar = SETL("_popcnt", U8(0));
	setvar = SEQ2(setvar, SETL("_val", val));

	/* We can stop shifting the "_val" once it is zero,
	since the value of "_popcnt" wouldn't change any further */
	RzILOpBool *condition = NON_ZERO(VARL("_val"));

	RzILOpEffect *popcnt = SETL("_popcnt", ADD(VARL("_popcnt"), x86_bool_to_bv(LSB(VARL("_val")), 8)));
	popcnt = SEQ2(popcnt, SETL("_val", SHIFTR0(VARL("_val"), U8(1))));

	RzILOpEffect *repeat_eff = REPEAT(condition, popcnt);

	struct x86_parity_helper_t ret = {
		.val = IS_ZERO(MOD(VARL("_popcnt"), U8(2))),
		.eff = SEQ2(setvar, repeat_eff)
	};

	return ret;
}

/**
 * \brief Sets the value of PF, ZF, SF according to the \p result
 */
static RzILOpEffect *x86_il_set_result_flags_bits(RZ_OWN RzILOpPure *result, int bits) {
	RzILOpEffect *set = SETL("_result", result);
	struct x86_parity_helper_t pf = x86_il_get_parity(UNSIGNED(8, VARL("_result")));
	RzILOpBool *zf = IS_ZERO(VARL("_result"));
	RzILOpBool *sf = MSB(VARL("_result"));

	return SEQ5(set, pf.eff,
		SETG(EFLAGS(PF), pf.val),
		SETG(EFLAGS(ZF), zf),
		SETG(EFLAGS(SF), sf));
}

#define x86_il_set_result_flags(result) x86_il_set_result_flags_bits(result, analysis->bits)

/**
 * \brief Sets the value of CF, OF, AF according to the \p res
 */
static RzILOpEffect *x86_il_set_arithmetic_flags_bits(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y, bool addition, int bits) {
	RzILOpBool *cf = NULL;
	RzILOpBool *of = NULL;
	RzILOpBool *af = NULL;

	RzILOpEffect *result_set = SETL("_result", res);
	RzILOpEffect *x_set = SETL("_x", x);
	RzILOpEffect *y_set = SETL("_y", y);

	if (addition) {
		cf = x86_il_is_add_carry(VARL("_result"), VARL("_x"), VARL("_y"));
		of = x86_il_is_add_overflow(VARL("_result"), VARL("_x"), VARL("_y"));
		af = x86_il_is_add_carry(UNSIGNED(4, VARL("_result")), UNSIGNED(4, VARL("_x")), UNSIGNED(4, VARL("_y")));
	} else {
		cf = x86_il_is_sub_borrow(VARL("_result"), VARL("_x"), VARL("_y"));
		of = x86_il_is_sub_underflow(VARL("_result"), VARL("_x"), VARL("_y"));
		af = x86_il_is_sub_borrow(UNSIGNED(4, VARL("_result")), UNSIGNED(4, VARL("_x")), UNSIGNED(4, VARL("_y")));
	}

	return SEQ6(result_set, x_set, y_set,
		SETG(EFLAGS(CF), cf),
		SETG(EFLAGS(OF), of),
		SETG(EFLAGS(AF), af));
}

/**
 * \brief Set OF and AF according to \p res
 */
static RzILOpEffect *x86_il_set_arithmetic_flags_except_cf_bits(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y, bool addition, int bits) {
	RzILOpBool *of = NULL;
	RzILOpBool *af = NULL;

	RzILOpEffect *result_set = SETL("_result", res);
	RzILOpEffect *x_set = SETL("_x", x);
	RzILOpEffect *y_set = SETL("_y", y);

	if (addition) {
		of = x86_il_is_add_overflow(VARL("_result"), VARL("_x"), VARL("_y"));
		af = x86_il_is_add_carry(UNSIGNED(4, VARL("_result")), UNSIGNED(4, VARL("_x")), UNSIGNED(4, VARL("_y")));
	} else {
		of = x86_il_is_sub_underflow(VARL("_result"), VARL("_x"), VARL("_y"));
		af = x86_il_is_sub_borrow(UNSIGNED(4, VARL("_result")), UNSIGNED(4, VARL("_x")), UNSIGNED(4, VARL("_y")));
	}

	return SEQ5(result_set, x_set, y_set,
		SETG(EFLAGS(OF), of),
		SETG(EFLAGS(AF), af));
}

#define x86_il_set_arithmetic_flags(res, x, y, addition)           x86_il_set_arithmetic_flags_bits(res, x, y, addition, analysis->bits)
#define x86_il_set_arithmetic_flags_except_cf(res, x, y, addition) x86_il_set_arithmetic_flags_except_cf_bits(res, x, y, addition, analysis->bits)

/**
 * \brief Get value of FLAGS register
 *
 * \param size size of flags needed
 */
RzILOpPure *x86_il_get_flags(unsigned int size) {
	/* We really don't care about bits higher than 16 for now */
	RzILOpPure *val;
	if (size == 8) {
		goto lower_half;
	}

	/* Bit 15: Reserved,
	always 1 on 8086 and 186,
	always 0 on later models
	Assuming 0 */
	val = x86_bool_to_bv(IL_FALSE, size);
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(NT)), size));

	/** Bit 12-13: IOPL,
	I/O privilege level (286+ only),
	always 1 on 8086 and 186
	Assuming all 1 */
	val = LOGOR(SHIFTL0(val, UN(size, 2)), UN(size, 0x3));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(OF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(DF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(IF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(TF)), size));

lower_half:
	if (size == 8) {
		val = x86_bool_to_bv(VARG(EFLAGS(SF)), size);
	} else {
		val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(ZF)), size));
	}
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(ZF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 2)), x86_bool_to_bv(VARG(EFLAGS(AF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 2)), x86_bool_to_bv(VARG(EFLAGS(PF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), UN(size, 1));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), x86_bool_to_bv(VARG(EFLAGS(CF)), size));

	return val;
}

/**
 * \brief Set the value of flags register
 *
 * \param val value to set the FLAGS register to
 * \param size size of \p val
 */
RzILOpEffect *x86_il_set_flags(RZ_OWN RzILOpPure *val, unsigned int size) {
	RzILOpEffect *set_val = SETL("_flags", val);

	RzILOpEffect *eff = SETG(EFLAGS(CF), LSB(VARL("_flags")));

	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(2))));
	eff = SEQ2(eff, SETG(EFLAGS(PF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(2))));
	eff = SEQ2(eff, SETG(EFLAGS(AF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(2))));
	eff = SEQ2(eff, SETG(EFLAGS(ZF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(1))));
	eff = SEQ2(eff, SETG(EFLAGS(SF), LSB(VARL("_flags"))));

	if (size == 8) {
		return SEQ2(set_val, eff);
	}

	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(1))));
	eff = SEQ2(eff, SETG(EFLAGS(TF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(1))));
	eff = SEQ2(eff, SETG(EFLAGS(IF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(1))));
	eff = SEQ2(eff, SETG(EFLAGS(DF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(1))));
	eff = SEQ2(eff, SETG(EFLAGS(OF), LSB(VARL("_flags"))));
	eff = SEQ2(eff, SETL("_flags", SHIFTR0(VARL("_flags"), U8(3))));
	eff = SEQ2(eff, SETG(EFLAGS(NT), LSB(VARL("_flags"))));

	/* Again, we will be ignoring bits over 16 and also ignore IOPL */

	return SEQ2(set_val, eff);
}

/**
 * ======== INSTRUCTION DOCUMENTATION FORMAT ========
 *
 * Instruction mnemonic
 * Description
 * | Opcode | 64-bit | Compat/Leg mode
 */

/**
 * \brief Invalid instruction
 */
IL_LIFTER(invalid) {
	return NULL;
}

/**
 * \brief Unimplemnted instruction
 */
IL_LIFTER(unimpl) {
	return EMPTY();
}

/* 8086/8088/80186/80286/80386/80486 instructions*/

/**
 * AAA
 * ASCII adjust AL after addition
 * 37 | Invalid | Valid
 */
IL_LIFTER(aaa) {
	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, VARG(EFLAGS(AF)));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, ADD(x86_il_get_reg(X86_REG_AX), U16(0x106)));
	RzILOpEffect *set_af = SETG(EFLAGS(AF), IL_TRUE);
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), IL_TRUE);
	RzILOpEffect *true_cond = SEQ3(set_ax, set_af, set_cf);

	set_af = SETG(EFLAGS(AF), IL_FALSE);
	set_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *false_cond = SEQ2(set_af, set_cf);

	RzILOpEffect *final_cond = BRANCH(cond, true_cond, false_cond);
	RzILOpEffect *set_al = x86_il_set_reg(X86_REG_AL, LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f)));

	return SEQ2(final_cond, set_al);
}

/**
 * AAD  imm8
 * Adjust AX before division to number base imm8
 * D5 ib | Invalid | Valid
 */
IL_LIFTER(aad) {

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *temp_ah = SETL("temp_ah", x86_il_get_reg(X86_REG_AH));

	RzILOpPure *imm;
	if (ins->structure->op_count == 0) {
		// Use base 10 if none specified
		imm = SN(8, 0x0a);
	} else {
		imm = x86_il_get_op(0);
	}

	RzILOpPure *adjusted = ADD(VARL("temp_al"), MUL(VARL("temp_ah"), imm));
	adjusted = LOGAND(adjusted, U8(0xff));
	RzILOpEffect *adjusted_set = SETL("adjusted", adjusted);

	RzILOpEffect *set_flags = x86_il_set_result_flags(VARL("adjusted"));

	return SEQ6(temp_al, temp_ah, adjusted_set, x86_il_set_reg(X86_REG_AL, VARL("adjusted")), x86_il_set_reg(X86_REG_AH, U8(0)), set_flags);
}

/**
 * AAM  imm8
 * Adjust AX after multiply to number base imm8
 * D4 ib | Invalid | Valid
 */
IL_LIFTER(aam) {

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));

	RzILOpPure *imm;
	if (ins->structure->op_count == 0) {
		imm = SN(8, 0xa);
	} else {
		imm = x86_il_get_op(0);
	}

	RzILOpEffect *ah = x86_il_set_reg(X86_REG_AH, DIV(VARL("temp_al"), imm));
	RzILOpEffect *adjusted = SETL("adjusted", MOD(VARL("temp_al"), DUP(imm)));
	RzILOpEffect *al = x86_il_set_reg(X86_REG_AL, VARL("adjusted"));
	RzILOpEffect *set_flags = x86_il_set_result_flags(VARL("adjusted"));

	return SEQ5(temp_al, ah, adjusted, al, set_flags);
}

/**
 * AAS
 * ASCII adjust AL after subtraction
 * 3F | Invalid | Valid
 */
IL_LIFTER(aas) {

	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, VARG(EFLAGS(AF)));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, SUB(x86_il_get_reg(X86_REG_AX), U16(0x6)));
	RzILOpEffect *set_ah = x86_il_set_reg(X86_REG_AH, SUB(x86_il_get_reg(X86_REG_AH), U8(0x1)));
	RzILOpEffect *set_af = SETG(EFLAGS(AF), IL_TRUE);
	RzILOpEffect *set_cf = SETG(EFLAGS(CF), IL_TRUE);
	RzILOpEffect *true_cond = SEQ4(set_ax, set_ah, set_af, set_cf);

	set_af = SETG(EFLAGS(AF), IL_FALSE);
	set_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *false_cond = SEQ2(set_af, set_cf);

	RzILOpEffect *final_cond = BRANCH(cond, true_cond, false_cond);
	RzILOpEffect *set_al = x86_il_set_reg(X86_REG_AL, LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f)));

	return SEQ2(final_cond, set_al);
}

/**
 * ADC  dest, src
 * (ADC family of instructions)
 * Add with carry
 * dest = dest + src + CF
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(adc) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_op(1));
	RzILOpPure *cf = VARG(EFLAGS(CF));

	RzILOpEffect *sum = SETL("sum", ADD(ADD(VARL("op1"), VARL("op2")), x86_bool_to_bv(cf, ins->structure->operands[0].size * BITS_PER_BYTE)));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("sum"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("sum"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("sum"), VARL("op1"), VARL("op2"), true);

	return SEQ6(op1, op2, sum, set_dest, set_res_flags, set_arith_flags);
}

/**
 * ADD  dest, src
 * (ADD family of instructions)
 * Add
 * dest = dest + src
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(add) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_op(1));
	RzILOpEffect *sum = SETL("sum", ADD(VARL("op1"), VARL("op2")));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("sum"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("sum"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("sum"), VARL("op1"), VARL("op2"), true);

	return SEQ6(op1, op2, sum, set_dest, set_res_flags, set_arith_flags);
}

/**
 * AND  dest, src
 * (AND family of instructions)
 * Logical and
 * dest = dest & src
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(and) {
	RzILOpPure *op1 = x86_il_get_op(0);
	RzILOpPure *op2 = x86_il_get_op(1);
	RzILOpEffect *and = SETL("and_", LOGAND(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("and_"));
	RzILOpEffect *clear_of = SETG(EFLAGS(OF), IL_FALSE);
	RzILOpEffect *clear_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("and_"));

	return SEQ5(and, set_dest, clear_of, clear_cf, set_res_flags);
}

/**
 * CBW
 * Convert byte to word
 * 98 | Valid | Valid
 */
IL_LIFTER(cbw) {
	/* The UNSIGNED(16, ...) cast is useless in case of 32 bits,
	but removing it will cause issues for 16-bit */
	return x86_il_set_reg(X86_REG_AX, UNSIGNED(16, x86_il_get_reg(X86_REG_AL)));
}

/**
 * CLC
 * Clear carry flag
 * F8 | Valid | Valid
 */
IL_LIFTER(clc) {
	return SETG(EFLAGS(CF), IL_FALSE);
}

/**
 * CLD
 * Clear direction flag
 * FC | Valid | Valid
 */
IL_LIFTER(cld) {
	return SETG(EFLAGS(DF), IL_FALSE);
}

/**
 * CLI
 * Clear interrupt flag
 * FA | Valid | Valid
 */
IL_LIFTER(cli) {
	return SETG(EFLAGS(IF), IL_FALSE);
}

/**
 * CMC
 * Complement carry flag
 * F5 | Valid | Valid
 */
IL_LIFTER(cmc) {
	return SETG(EFLAGS(CF), INV(VARG(EFLAGS(CF))));
}

/**
 * CMP
 * (CMP family of instructions)
 * Compare two operands
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(cmp) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));

	RzILOpPure *second = x86_il_get_op(1);
	RzILOpEffect *op2 = SETL("op2", second);

	RzILOpEffect *sub = SETL("sub", SUB(VARL("op1"), VARL("op2")));
	RzILOpEffect *arith = x86_il_set_arithmetic_flags(VARL("sub"), VARL("op1"), VARL("op2"), false);
	RzILOpEffect *res = x86_il_set_result_flags(VARL("sub"));

	return SEQ5(op1, op2, sub, arith, res);
}

RzILOpEffect *x86_il_cmp_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	if (analysis->bits == 64) {
		X86Reg mem_reg1 = X86_REG_RSI;
		X86Reg mem_reg2 = X86_REG_RDI;
		ut8 mem_size = 64;

		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg1 = X86_REG_ESI;
			mem_reg2 = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpEffect *src1 = SETL("_src1", LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg1) : UNSIGNED(64, x86_il_get_reg(mem_reg1)))));
		RzILOpEffect *src2 = SETL("_src2", LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg2) : UNSIGNED(64, x86_il_get_reg(mem_reg2)))));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_src1"), VARL("_src2")));

		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_src1"), VARL("_src2"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = SEQ2(x86_il_set_reg(mem_reg1, ADD(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, ADD(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *decrement = SEQ2(x86_il_set_reg(mem_reg1, SUB(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, SUB(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));

		return SEQ6(src1, src2, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	} else {
		X86Reg mem_reg1 = X86_REG_ESI;
		X86Reg mem_reg2 = X86_REG_EDI;
		ut8 mem_size = 32;

		/* Address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg1 = X86_REG_SI;
			mem_reg2 = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem1 = {
			.base = mem_reg1,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_DS
		};
		X86Mem src_mem2 = {
			.base = mem_reg2,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_ES
		};

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpEffect *src1 = SETL("_src1", LOADW(size, x86_il_get_memaddr(src_mem1)));
		RzILOpEffect *src2 = SETL("_src2", LOADW(size, x86_il_get_memaddr(src_mem2)));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_src1"), VARL("_src2")));

		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_src1"), VARL("_src2"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = SEQ2(x86_il_set_reg(mem_reg1, ADD(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, ADD(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *decrement = SEQ2(x86_il_set_reg(mem_reg1, SUB(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, SUB(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));

		return SEQ6(src1, src2, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), increment, decrement));
	}
}

/**
 * CMPSB
 * Compare byte
 * A6 | Valid | Valid
 */
IL_LIFTER(cmpsb) {
	return x86_il_cmp_helper(ins, pc, analysis, 8);
}

/**
 * CMPSW
 * Compare word
 * A7 | Valid | Valid
 */
IL_LIFTER(cmpsw) {
	return x86_il_cmp_helper(ins, pc, analysis, 16);
}

/**
 * CMPSD
 * Compare dword
 * ZO
 */
IL_LIFTER(cmpsd) {
	return x86_il_cmp_helper(ins, pc, analysis, 32);
}

/**
 * CMPSQ
 * Compare quadword
 * ZO
 */
IL_LIFTER(cmpsq) {
	return x86_il_cmp_helper(ins, pc, analysis, 64);
}

/**
 * DAA
 * Decimal adjust AL after addition
 * 27 | Invalid | Valid
 */
IL_LIFTER(daa) {

	RzILOpEffect *old_al = SETL("old_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *old_cf = SETL("old_cf", VARG(EFLAGS(CF)));

	RzILOpEffect *set_cf = SETL(EFLAGS(CF), IL_FALSE);

	RzILOpBool *cond = UGT(LOGAND(x86_il_get_reg(X86_REG_AL), UN(8, 0xf)), UN(8, 9));
	cond = OR(cond, VARG(EFLAGS(AF)));

	RzILOpEffect *set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *sum = SETL("_sum", ADD(VARL("_al"), UN(8, 6)));
	RzILOpEffect *true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));
	RzILOpPure *new_cf = OR(VARL("old_cf"), x86_il_is_sub_borrow(VARL("_sum"), VARL("_al"), UN(8, 6)));

	RzILOpEffect *ret = SEQ4(old_al, old_cf, set_cf, BRANCH(cond, SEQ3(true_cond, SETG(EFLAGS(CF), new_cf), SETG(EFLAGS(AF), IL_TRUE)), SETG(EFLAGS(AF), IL_FALSE)));

	cond = OR(UGT(VARL("old_al"), UN(8, 0x99)), VARL("old_cf"));

	set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	sum = SETL("_sum", ADD(VARL("_al"), UN(8, 0x60)));
	true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));

	ret = SEQ3(ret, BRANCH(cond, SEQ2(true_cond, SETG(EFLAGS(CF), IL_TRUE)), SETG(EFLAGS(CF), IL_FALSE)), x86_il_set_result_flags(x86_il_get_reg(X86_REG_AL)));

	return ret;
}

/**
 * DAS
 * Decimal adjust AL after subtraction
 * 2F | Invalid | Valid
 */
IL_LIFTER(das) {

	RzILOpEffect *old_al = SETL("old_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *old_cf = SETL("old_cf", VARG(EFLAGS(CF)));

	RzILOpEffect *set_cf = SETL(EFLAGS(CF), IL_FALSE);

	RzILOpBool *cond = UGT(LOGAND(x86_il_get_reg(X86_REG_AL), UN(8, 0xf)), UN(8, 9));
	cond = OR(cond, VARG(EFLAGS(AF)));

	RzILOpEffect *set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *sum = SETL("_sum", SUB(VARL("_al"), UN(8, 6)));
	RzILOpEffect *true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));
	RzILOpPure *new_cf = OR(VARL("old_cf"), x86_il_is_sub_borrow(VARL("_sum"), VARL("_al"), UN(8, 6)));

	RzILOpEffect *ret = SEQ4(old_al, old_cf, set_cf, BRANCH(cond, SEQ3(true_cond, SETG(EFLAGS(CF), new_cf), SETG(EFLAGS(AF), IL_TRUE)), SETG(EFLAGS(AF), IL_FALSE)));

	cond = OR(UGT(VARL("old_al"), UN(8, 0x99)), VARL("old_cf"));

	set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	sum = SETL("_sum", SUB(VARL("_al"), UN(8, 0x60)));
	true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));

	ret = SEQ3(ret, BRANCH(cond, SEQ2(true_cond, SETG(EFLAGS(CF), IL_TRUE)), NOP()), x86_il_set_result_flags(x86_il_get_reg(X86_REG_AL)));

	return ret;
}

/**
 * DEC
 * Decrement by 1
 * Operand can be a memory address or a register
 */
IL_LIFTER(dec) {
	RzILOpEffect *op = SETL("_op", x86_il_get_op(0));
	RzILOpEffect *dec = SETL("_dec", SUB(VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1)));

	RzILOpEffect *set_result = x86_il_set_op(0, VARL("_dec"));
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_dec"));

	RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags_except_cf(VARL("_dec"), VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1), false);

	return SEQ5(op, dec, set_result, res_flags, arith_flags);
}

/**
 * DIV
 * Unsigned division
 * One operand (memory address), used as the divisor
 */
IL_LIFTER(div) {
	RzILOpEffect *ret = NULL;

	switch (ins->structure->operands[0].size) {
	case 1: {
		/* Word/Byte operation */
		RzILOpEffect *ax = SETL("_ax", x86_il_get_reg(X86_REG_AX));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(8, DIV(VARL("_ax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(8, 0xff));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AL, VARL("_temp")), x86_il_set_reg(X86_REG_AH, MOD(VARL("_ax"), VARL("_src"))));

		ret = SEQ3(ax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 2: {
		/* Doubleword/Word operation */
		RzILOpEffect *dxax = SETL("_dxax", LOGOR(SHIFTL0(UNSIGNED(32, x86_il_get_reg(X86_REG_DX)), UN(8, 16)), UNSIGNED(32, x86_il_get_reg(X86_REG_AX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(16, DIV(VARL("_dxax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(16, 0xffff));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, MOD(VARL("_dxax"), VARL("_src"))));

		ret = SEQ3(dxax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 4: {
		/* Quadword/Doubleword operation */
		RzILOpEffect *edxeax = SETL("_edxeax", LOGOR(SHIFTL0(UNSIGNED(64, x86_il_get_reg(X86_REG_EDX)), UN(8, 32)), UNSIGNED(64, x86_il_get_reg(X86_REG_EAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(32, DIV(VARL("_edxeax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(32, 0xffffffffULL));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, MOD(VARL("_edxeax"), VARL("_src"))));

		ret = SEQ3(edxeax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 8: {
		/* Doublequadword/Quadword operation */
		RzILOpEffect *rdxrax = SETL("_rdxrax", LOGOR(SHIFTL0(UNSIGNED(128, x86_il_get_reg(X86_REG_RDX)), UN(8, 64)), UNSIGNED(128, x86_il_get_reg(X86_REG_RAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(64, DIV(VARL("_rdxrax"), VARL("_src"))));

		RzILOpPure *cond = UGT(VARL("_temp"), UN(64, 0xffffffffffffffffULL));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, MOD(VARL("_rdxrax"), VARL("_src"))));

		ret = SEQ3(rdxrax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	default:
		RZ_LOG_ERROR("RzIL: x86: DIV: Invalid operand size\n");
		return NULL;
	}

	/* We need the divisor to be as wide as the operand, since the sizes of the dividend and the divisor need to match */
	RzILOpEffect *op = SETL("_src", UNSIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_op(0)));

	/* Check if the operand is zero, return NULL if it is (to avoid divide by zero) */
	return SEQ2(op, BRANCH(IS_ZERO(VARL("_src")), NULL, ret));
}

// /**
//  * ESC
//  * Escape to coprocessor instruction set
//  * To be used with floating-point unit
//  */
// IL_LIFTER(esc) {
// 	/* Not necessary to implement for binary analysis */
// 	return EMPTY();
// }

/**
 * HLT
 * Enter HALT state
 */
IL_LIFTER(hlt) {
	/* It just jumps to an empty goto label "halt"
	Also need an EMPTY() instruction after it to denote
	the end of analysis and restart all IL analysis */
	return SEQ2(GOTO("halt"), EMPTY());
}

static void label_halt(RzILVM *vm, RzILOpEffect *op) {
	// empty "halt" label
	return;
}

/**
 * IDIV
 * Signed division
 * One operand (memory address), used as the divisor
 */
IL_LIFTER(idiv) {
	RzILOpEffect *ret = NULL;

	switch (ins->structure->operands[0].size) {
	case 1: {
		/* Word/Byte operation */
		RzILOpEffect *ax = SETL("_ax", x86_il_get_reg(X86_REG_AX));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(8, SDIV(VARL("_ax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(8, 0x7f)), SLT(VARL("_temp"), UN(8, 0x80)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AL, VARL("_temp")), x86_il_set_reg(X86_REG_AH, SMOD(VARL("_ax"), VARL("_src"))));

		ret = SEQ3(ax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 2: {
		/* Doubleword/Word operation */
		RzILOpEffect *dxax = SETL("_dxax", LOGOR(SHIFTL0(UNSIGNED(32, x86_il_get_reg(X86_REG_DX)), UN(8, 16)), UNSIGNED(32, x86_il_get_reg(X86_REG_AX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(16, SDIV(VARL("_dxax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(16, 0x7fff)), SLT(VARL("_temp"), UN(16, 0x8000)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, SMOD(VARL("_dxax"), VARL("_src"))));

		ret = SEQ3(dxax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 4: {
		/* Quadword/Doubleword operation */
		RzILOpEffect *edxeax = SETL("_edxeax", LOGOR(SHIFTL0(UNSIGNED(64, x86_il_get_reg(X86_REG_EDX)), UN(8, 32)), UNSIGNED(64, x86_il_get_reg(X86_REG_EAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(32, SDIV(VARL("_edxeax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(32, 0x7fffffffULL)), SLT(VARL("_temp"), UN(32, 0x80000000ULL)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, SMOD(VARL("_edxeax"), VARL("_src"))));

		ret = SEQ3(edxeax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	case 8: {
		/* Doublequadword/Quadword operation */
		RzILOpEffect *rdxrax = SETL("_rdxrax", LOGOR(SHIFTL0(UNSIGNED(128, x86_il_get_reg(X86_REG_EDX)), UN(8, 64)), UNSIGNED(128, x86_il_get_reg(X86_REG_EAX))));
		RzILOpEffect *temp = SETL("_temp", UNSIGNED(64, SDIV(VARL("_rdxrax"), VARL("_src"))));

		RzILOpPure *cond = OR(SGT(VARL("_temp"), UN(64, 0x7fffffffffffffffULL)), SLT(VARL("_temp"), UN(64, 0x8000000000000000ULL)));
		RzILOpEffect *else_cond = SEQ2(x86_il_set_reg(X86_REG_AX, VARL("_temp")), x86_il_set_reg(X86_REG_DX, SMOD(VARL("_rdxrax"), VARL("_src"))));

		ret = SEQ3(rdxrax, temp, BRANCH(cond, NULL, else_cond));
		break;
	}
	default:
		RZ_LOG_ERROR("RzIL: x86: IDIV: Invalid operand size\n");
		return NULL;
	}

	/* We need the divisor to be as wide as the operand, since the sizes of the dividend and the divisor need to match */
	RzILOpEffect *op = SETL("_src", UNSIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_op(0)));

	/* Check if the operand is zero, return NULL if it is (to avoid divide by zero) */
	return SEQ2(op, BRANCH(IS_ZERO(VARL("_src")), NULL, ret));
}

/**
 * IMUL
 * Signed multiply
 * Three different operand number:
 *  - One operand (Encoding: M)
 *  - Two operands (Encoding: RM)
 *  - Three operands (Encoding: RMI)
 */
IL_LIFTER(imul) {
	switch (ins->structure->op_count) {
	case 1: {
		switch (ins->structure->operands[0].size) {
		case 1: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(16, x86_il_get_reg(X86_REG_AL)), SIGNED(16, x86_il_get_op(0))));
			RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, VARL("_tmp_xp"));

			/* Check if the result fits in a byte */
			RzILOpPure *cond = EQ(SIGNED(16, UNSIGNED(8, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ3(tmp_xp, set_ax, BRANCH(cond, true_branch, false_branch));
		}
		case 2: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(32, x86_il_get_reg(X86_REG_AX)), SIGNED(32, x86_il_get_op(0))));
			RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, UNSIGNED(16, VARL("_tmp_xp")));
			RzILOpEffect *set_dx = x86_il_set_reg(X86_REG_DX, UNSIGNED(32, SHIFTR0(VARL("_tmp_xp"), UN(8, 16))));

			/* Check if the result fits in a word */
			RzILOpPure *cond = EQ(SIGNED(32, UNSIGNED(16, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ4(tmp_xp, set_ax, set_dx, BRANCH(cond, true_branch, false_branch));
		}
		case 4: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(64, x86_il_get_reg(X86_REG_EAX)), SIGNED(64, x86_il_get_op(0))));
			RzILOpEffect *set_eax = x86_il_set_reg(X86_REG_EAX, UNSIGNED(32, VARL("_tmp_xp")));
			RzILOpEffect *set_edx = x86_il_set_reg(X86_REG_EDX, UNSIGNED(32, SHIFTR0(VARL("_tmp_xp"), UN(8, 32))));

			/* Check if the result fits in a doubleword */
			RzILOpPure *cond = EQ(SIGNED(64, UNSIGNED(32, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ4(tmp_xp, set_eax, set_edx, BRANCH(cond, true_branch, false_branch));
		}
		case 8: {
			RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(128, x86_il_get_reg(X86_REG_RAX)), SIGNED(128, x86_il_get_op(0))));
			RzILOpEffect *set_rax = x86_il_set_reg(X86_REG_RAX, UNSIGNED(64, VARL("_tmp_xp")));
			RzILOpEffect *set_rdx = x86_il_set_reg(X86_REG_RDX, UNSIGNED(64, SHIFTR0(VARL("_tmp_xp"), UN(8, 64))));

			/* Check if the result fits in a quadword */
			RzILOpPure *cond = EQ(SIGNED(128, UNSIGNED(64, VARL("_tmp_xp"))), VARL("_tmp_xp"));
			RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
			RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

			return SEQ4(tmp_xp, set_rax, set_rdx, BRANCH(cond, true_branch, false_branch));
		}
		default:
			RZ_LOG_ERROR("RzIL: x86: IMUL: Invalid operand size\n");
			return NULL;
		}
	}
	case 2: {
		RzILOpEffect *dest = SETL("_dest", x86_il_get_op(0));
		RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, VARL("_dest")), SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_op(1))));
		RzILOpEffect *set_dest = SETL("_dest", UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE, VARL("_tmp_xp")));
		RzILOpEffect *set_operand = x86_il_set_op(0, VARL("_dest"));

		/* Check if the result fits in the destination */
		RzILOpPure *cond = EQ(SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, VARL("_dest")), VARL("_tmp_xp"));
		RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
		RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

		return SEQ5(dest, tmp_xp, set_dest, set_operand, BRANCH(cond, true_branch, false_branch));
	}
	case 3: {
		RzILOpEffect *tmp_xp = SETL("_tmp_xp", MUL(SIGNED(ins->structure->operands[1].size * 2 * BITS_PER_BYTE, x86_il_get_op(1)), SIGNED(ins->structure->operands[1].size * 2 * BITS_PER_BYTE, x86_il_get_op(2))));
		RzILOpEffect *set_dest = SETL("_dest", UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE, VARL("_tmp_xp")));
		RzILOpEffect *set_operand = x86_il_set_op(0, VARL("_dest"));

		/* Check if the result fits in the destination */
		RzILOpPure *cond = EQ(SIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, VARL("_dest")), VARL("_tmp_xp"));
		RzILOpEffect *true_branch = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));
		RzILOpEffect *false_branch = SEQ2(SETG(EFLAGS(CF), IL_TRUE), SETG(EFLAGS(OF), IL_TRUE));

		return SEQ4(tmp_xp, set_dest, set_operand, BRANCH(cond, true_branch, false_branch));
	}
	default:
		RZ_LOG_ERROR("RzIL: x86: IMUL: Invalid operand count\n");
		return NULL;
	}

	return NULL;
}

/**
 * IN
 * Input from port
 * Encodings: I, ZO
 */
IL_LIFTER(in) {
	/* It just jumps to an empty goto label "port"
	Also need an EMPTY() instruction after it to denote
	the end of analysis and restart all IL analysis */
	return SEQ2(GOTO("port"), EMPTY());
}

static void label_port(RzILVM *vm, RzILOpEffect *op) {
	// empty "port" label
	return;
}

/**
 * INC
 * Increment by 1
 * Encodings: M, O
 */
IL_LIFTER(inc) {
	RzILOpEffect *op = SETL("_op", x86_il_get_op(0));
	RzILOpEffect *result = SETL("_result", ADD(VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1)));
	RzILOpEffect *set_result = x86_il_set_op(0, VARL("_result"));

	RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags_except_cf(VARL("_result"), VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1), true);
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_result"));

	return SEQ5(op, result, set_result, arith_flags, res_flags);
}

/**
 * INT
 * Call to interrupt procedure
 * Encodings: I, ZO
 */
IL_LIFTER(int) {
	/* For now, it just jumps to an empty goto label "int"
	Also need an EMPTY() instruction after it to denote
	the end of analysis and restart all IL analysis */
	return SEQ2(GOTO("int"), EMPTY());
}

static void label_int(RzILVM *vm, RzILOpEffect *op) {
	// empty "int" label
	return;
}

/**
 * INTO
 * Call to interrupt if overflow flag set
 */
IL_LIFTER(into) {
	return BRANCH(VARG(EFLAGS(OF)), SEQ2(GOTO("int"), EMPTY()), NOP());
}

// /**
//  * IRET
//  * Return from interrupt
//  */
// IL_LIFTER(iret) {
// 	/* TODO: Implement IRET properly */
// 	return EMPTY();
// }

#define JUMP_IL() \
	do { \
		RzILOpPure *jmp_addr = UN(analysis->bits, pc); \
		jmp_addr = ADD(jmp_addr, SN(analysis->bits, ins->structure->operands[0].imm)); \
		if (ins->structure->operands[0].size == 16 && analysis->bits != 64) { \
			jmp_addr = LOGAND(jmp_addr, UN(analysis->bits, 0x0000ffff)); \
		} \
		return BRANCH(cond, JMP(jmp_addr), NOP()); \
	} while (0)

/**
 * JA
 * Jump if above (CF = 0 and ZF = 0)
 * Encoding: D
 */
IL_LIFTER(ja) {
	RzILOpBool *cond = AND(INV(VARG(EFLAGS(CF))), INV(VARG(EFLAGS(ZF))));
	JUMP_IL();
}

/**
 * JAE
 * Jump if above or equal (CF = 0)
 * Encoding: D
 */
IL_LIFTER(jae) {
	RzILOpBool *cond = INV(VARG(EFLAGS(CF)));
	JUMP_IL();
}

/**
 * JB
 * Jump if below (CF = 1)
 * Encoding: D
 */
IL_LIFTER(jb) {
	RzILOpBool *cond = VARG(EFLAGS(CF));
	JUMP_IL();
}

/**
 * JBE
 * Jump if below or equal (CF = 1 or ZF = 1)
 * Encoding: D
 */
IL_LIFTER(jbe) {
	RzILOpBool *cond = OR(VARG(EFLAGS(CF)), VARG(EFLAGS(ZF)));
	JUMP_IL();
}

/**
 * JCXZ
 * Jump if CX register is zero (CX = 0)
 * Encoding: D
 */
IL_LIFTER(jcxz) {
	RzILOpBool *cond = IS_ZERO(x86_il_get_reg(X86_REG_CX));
	JUMP_IL();
}

/**
 * JECXZ
 * Jump if ECX register is zero (ECX = 0)
 * Encoding: D
 */
IL_LIFTER(jecxz) {
	RzILOpBool *cond = IS_ZERO(x86_il_get_reg(X86_REG_ECX));
	JUMP_IL();
}

/**
 * JRCXZ
 * Jump if RCX register is zero (RCX = 0)
 * Encoding: D
 */
IL_LIFTER(jrcxz) {
	RzILOpBool *cond = IS_ZERO(x86_il_get_reg(X86_REG_RCX));
	JUMP_IL();
}

/**
 * JE
 * Jump if equal (ZF = 1)
 * Encoding: D
 */
IL_LIFTER(je) {
	RzILOpBool *cond = VARG(EFLAGS(ZF));
	JUMP_IL();
}

/**
 * JG
 * Jump if greater (ZF = 0 and SF = OF)
 * Encoding: D
 */
IL_LIFTER(jg) {
	RzILOpBool *cond = AND(INV(VARG(EFLAGS(ZF))), INV(XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF)))));
	JUMP_IL();
}

/**
 * JGE
 * Jump if greater or equal (SF = OF)
 * Encoding: D
 */
IL_LIFTER(jge) {
	RzILOpBool *cond = INV(XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF))));
	JUMP_IL();
}

/**
 * JL
 * Jump if less or equal (SF != OF)
 * Encoding: D
 */
IL_LIFTER(jl) {
	RzILOpBool *cond = XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF)));
	JUMP_IL();
}

/**
 * JLE
 * Jump if less or equal (ZF = 1 or SF != OF)
 * Encoding: D
 */
IL_LIFTER(jle) {
	RzILOpBool *cond = OR(VARG(EFLAGS(ZF)), XOR(VARG(EFLAGS(SF)), VARG(EFLAGS(OF))));
	JUMP_IL();
}

/**
 * JNE
 * Jump if not equal (ZF = 0)
 * Encoding: D
 */
IL_LIFTER(jne) {
	RzILOpBool *cond = INV(VARG(EFLAGS(ZF)));
	JUMP_IL();
}

/**
 * JNO
 * Jump if not overflow (OF = 0)
 * Encoding: D
 */
IL_LIFTER(jno) {
	RzILOpBool *cond = INV(VARG(EFLAGS(OF)));
	JUMP_IL();
}

/**
 * JNP
 * Jump if not parity (PF = 0)
 * Encoding: D
 */
IL_LIFTER(jnp) {
	RzILOpBool *cond = INV(VARG(EFLAGS(PF)));
	JUMP_IL();
}

/**
 * JNS
 * Jump if not sign (SF = 0)
 * Encoding: D
 */
IL_LIFTER(jns) {
	RzILOpBool *cond = INV(VARG(EFLAGS(SF)));
	JUMP_IL();
}

/**
 * JO
 * Jump if overflow (OF = 1)
 * Encoding: D
 */
IL_LIFTER(jo) {
	RzILOpBool *cond = VARG(EFLAGS(OF));
	JUMP_IL();
}

/**
 * JP
 * Jump if parity (PF = 1)
 * Encoding: D
 */
IL_LIFTER(jp) {
	RzILOpBool *cond = VARG(EFLAGS(PF));
	JUMP_IL();
}

/**
 * JS
 * Jump if sign (SF = 1)
 * Encoding: D
 */
IL_LIFTER(js) {
	RzILOpBool *cond = VARG(EFLAGS(SF));
	JUMP_IL();
}

#undef JUMP_IL

/**
 * JMP
 * Jump
 * Relative jump or absolute jump decided by the encoding of the operands
 * Possible encodings:
 *  - S (Segment + absolute address)
 *  - D (Offset/Displacement)
 *  - M
 */
IL_LIFTER(jmp) {
	RzILOpPure *target;
	if (ins->structure->operands[0].type == X86_OP_IMM) {
		target = ADD(UN(analysis->bits, pc), SN(analysis->bits, ins->structure->operands[0].imm));
	} else {
		target = UNSIGNED(analysis->bits, x86_il_get_op(0));
	}

	return JMP(target);
}

/**
 * LAHF
 * Load status flags in the AH register
 * No operands
 */
IL_LIFTER(lahf) {
	return x86_il_set_reg(X86_REG_AH, x86_il_get_flags(8));
}

/**
 * LDS
 * Load pointer using DS
 * Encoding: RM
 */
IL_LIFTER(lds) {
	return x86_il_set_op(0, x86_il_get_memaddr_segment(ins->structure->operands[1].mem, X86_REG_DS));
}

/**
 * LEA
 * Load effective address
 * Encoding: RM
 * Cast the M to R in an unsigned cast
 */
IL_LIFTER(lea) {
	return x86_il_set_op(0, x86_il_get_memaddr(ins->structure->operands[1].mem));
}

/**
 * LES
 * Load pointer using ES
 * Encoding: RM
 */
IL_LIFTER(les) {
	return x86_il_set_op(0, x86_il_get_memaddr_segment(ins->structure->operands[1].mem, X86_REG_ES));
}

RzILOpEffect *x86_il_lods_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	X86Reg reg;
	switch (size) {
	case 8:
		reg = X86_REG_AL;
		break;
	case 16:
		reg = X86_REG_AX;
		break;
	case 32:
		reg = X86_REG_EAX;
		break;
	case 64:
		reg = X86_REG_RAX;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	if (analysis->bits == 64) {
		X86Reg mem_reg = X86_REG_RSI;
		ut8 mem_size = 64;
		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg = X86_REG_ESI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpPure *val = LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg) : UNSIGNED(64, x86_il_get_reg(mem_reg))));
		RzILOpEffect *inc = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *dec = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *update_rsi = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		return SEQ2(x86_il_set_reg(reg, val), update_rsi);

	} else {
		X86Reg mem_reg = X86_REG_ESI;
		ut8 mem_size = 32;
		/* Address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg = X86_REG_SI;
			mem_size = 16;
		}

		X86Mem src_mem;
		src_mem.base = mem_reg;
		src_mem.disp = 0;
		src_mem.index = X86_REG_INVALID;
		src_mem.scale = 1;
		src_mem.segment = X86_REG_DS;

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpPure *val = LOADW(size, x86_il_get_memaddr(src_mem));

		RzILOpEffect *inc = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *dec = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *update_si = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		return SEQ2(x86_il_set_reg(reg, val), update_si);
	}
}

/**
 * LODSB
 * Load string byte
 * No operands
 */
IL_LIFTER(lodsb) {
	return x86_il_lods_helper(ins, pc, analysis, 8);
}

/**
 * LODSW
 * Load string word
 * No operands
 */
IL_LIFTER(lodsw) {
	return x86_il_lods_helper(ins, pc, analysis, 16);
}

/**
 * LODSD
 * Load string dword
 * No operands
 */
IL_LIFTER(lodsd) {
	return x86_il_lods_helper(ins, pc, analysis, 32);
}

/**
 * LODSQ
 * Load string quadword
 * No operands
 */
IL_LIFTER(lodsq) {
	return x86_il_lods_helper(ins, pc, analysis, 64);
}

#define LOOP_HELPER(cond) \
	do { \
		/* Will automatically be resolved to the widest CX register */ \
		X86Reg count_reg = X86_REG_RCX; \
\
		uint8_t addr_size = analysis->bits; \
		/* Check address override prefix (67H) */ \
		if (analysis->bits == 64 && ins->structure->prefix[3]) { \
			addr_size >>= 1; \
			count_reg = X86_REG_ECX; \
		} \
\
		RzILOpEffect *dec_counter = x86_il_set_reg(count_reg, SUB(x86_il_get_reg(count_reg), UN(addr_size, 1))); \
		RzILOpEffect *true_cond = JMP(UN(analysis->bits, pc + ins->structure->operands[0].imm)); \
		RzILOpEffect *branch = BRANCH(cond, true_cond, NOP()); \
\
		return SEQ2(dec_counter, branch); \
	} while (0)

/**
 * LOOP
 * Loop the following instruction
 * Encoding: D
 * Decrement count ; jump if count != 0
 */
IL_LIFTER(loop) {
	LOOP_HELPER(NON_ZERO(x86_il_get_reg(count_reg)));
}

/**
 * LOOPE
 * Loop the following instruction
 * Encoding: D
 * Decrement count ; jump if count != 0 and ZF = 1
 */
IL_LIFTER(loope) {
	LOOP_HELPER(AND(NON_ZERO(x86_il_get_reg(count_reg)), VARG(EFLAGS(ZF))));
}

/**
 * LOOPNE
 * Loop the following instruction
 * Encoding: D
 * Decrement count ; jump if count != 0 and ZF = 0
 */
IL_LIFTER(loopne) {
	LOOP_HELPER(AND(NON_ZERO(x86_il_get_reg(count_reg)), INV(VARG(EFLAGS(ZF)))));
}

/**
 * MOV
 * Move
 * Encodings:
 *  - MR
 *  - RM
 *  - FD
 *  - TD
 *  - OI
 *  - MI
 */
IL_LIFTER(mov) {
	return x86_il_set_op(0, x86_il_get_op(1));
}

RzILOpEffect *x86_il_movs_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	if (analysis->bits == 64) {
		X86Reg mem_reg1 = X86_REG_RSI;
		X86Reg mem_reg2 = X86_REG_RDI;
		ut8 mem_size = 64;

		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg1 = X86_REG_ESI;
			mem_reg2 = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpPure *val = LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg1) : UNSIGNED(64, x86_il_get_reg(mem_reg1))));
		RzILOpEffect *inc = SEQ2(x86_il_set_reg(mem_reg1, ADD(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, ADD(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *dec = SEQ2(x86_il_set_reg(mem_reg1, SUB(x86_il_get_reg(mem_reg1), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(mem_reg2, SUB(x86_il_get_reg(mem_reg2), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *update = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		return SEQ2(STOREW((mem_size == 64 ? x86_il_get_reg(mem_reg2) : UNSIGNED(64, x86_il_get_reg(mem_reg2))), val), update);

	} else {
		X86Reg src_reg = X86_REG_ESI;
		X86Reg dst_reg = X86_REG_EDI;
		ut8 mem_size = 32;

		/* Address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			src_reg = X86_REG_SI;
			dst_reg = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem = {
			.base = src_reg,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_DS
		};
		X86Mem dst_mem = {
			.base = dst_reg,
			.disp = 0,
			.index = X86_REG_INVALID,
			.scale = 1,
			.segment = X86_REG_ES
		};

		RzILOpEffect *inc = SEQ2(x86_il_set_reg(src_reg, ADD(x86_il_get_reg(src_reg), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(dst_reg, ADD(x86_il_get_reg(dst_reg), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *dec = SEQ2(x86_il_set_reg(src_reg, SUB(x86_il_get_reg(src_reg), UN(mem_size, size / BITS_PER_BYTE))), x86_il_set_reg(dst_reg, SUB(x86_il_get_reg(dst_reg), UN(mem_size, size / BITS_PER_BYTE))));
		RzILOpEffect *update = BRANCH(VARG(EFLAGS(DF)), dec, inc);

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		return SEQ2(x86_il_set_mem(dst_mem, LOADW(size, x86_il_get_memaddr(src_mem))), update);
	}
}

/**
 * MOVSB
 * Move string byte
 * No operands
 */
IL_LIFTER(movsb) {
	return x86_il_movs_helper(ins, pc, analysis, 8);
}

/**
 * MOVSW
 * Move string word
 * No operands
 */
IL_LIFTER(movsw) {
	return x86_il_movs_helper(ins, pc, analysis, 16);
}

/**
 * MOVSD
 * Move string dword
 * No operands
 */
IL_LIFTER(movsd) {
	return x86_il_movs_helper(ins, pc, analysis, 32);
}

/**
 * MOVSQ
 * Move string quadword
 * No operands
 */
IL_LIFTER(movsq) {
	return x86_il_movs_helper(ins, pc, analysis, 64);
}

/**
 * MUL
 * Unsigned multiply
 * Encoding: M
 */
IL_LIFTER(mul) {
	RzILOpPure *op = UNSIGNED(ins->structure->operands[0].size * BITS_PER_BYTE * 2, x86_il_get_op(0));
	RzILOpEffect *true_cond = SEQ2(SETG(EFLAGS(OF), IL_FALSE), SETG(EFLAGS(CF), IL_FALSE));
	RzILOpEffect *false_cond = SEQ2(SETG(EFLAGS(OF), IL_TRUE), SETG(EFLAGS(CF), IL_TRUE));

	switch (ins->structure->operands[0].size) {
	case 1: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(16, x86_il_get_reg(X86_REG_AL)), op));
		RzILOpEffect *ax = x86_il_set_reg(X86_REG_AX, VARL("_mul"));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(8))), true_cond, false_cond);

		return SEQ3(set, ax, flags);
	}
	case 2: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(32, x86_il_get_reg(X86_REG_AX)), op));
		RzILOpEffect *dx = x86_il_set_reg(X86_REG_DX, UNSIGNED(16, SHIFTR0(VARL("_mul"), U8(16))));
		RzILOpEffect *ax = x86_il_set_reg(X86_REG_AX, UNSIGNED(16, VARL("_mul")));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(16))), true_cond, false_cond);

		return SEQ4(set, dx, ax, flags);
	}
	case 4: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(64, x86_il_get_reg(X86_REG_EAX)), op));
		RzILOpEffect *edx = x86_il_set_reg(X86_REG_EDX, UNSIGNED(32, SHIFTR0(VARL("_mul"), U8(32))));
		RzILOpEffect *eax = x86_il_set_reg(X86_REG_EAX, UNSIGNED(32, VARL("_mul")));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(32))), true_cond, false_cond);

		return SEQ4(set, edx, eax, flags);
	}
	case 8: {
		RzILOpEffect *set = SETL("_mul", MUL(UNSIGNED(128, x86_il_get_reg(X86_REG_RAX)), op));
		RzILOpEffect *rdx = x86_il_set_reg(X86_REG_RDX, UNSIGNED(64, SHIFTR0(VARL("_mul"), U8(64))));
		RzILOpEffect *rax = x86_il_set_reg(X86_REG_RAX, UNSIGNED(64, VARL("_mul")));
		RzILOpEffect *flags = BRANCH(IS_ZERO(SHIFTR0(VARL("_mul"), U8(64))), true_cond, false_cond);

		return SEQ4(set, rdx, rax, flags);
	}
	}

	rz_warn_if_reached();
	rz_il_op_pure_free(op);
	rz_il_op_effect_free(true_cond);
	rz_il_op_effect_free(false_cond);
	return NULL;
}

/**
 * NEG
 * Two's complement negation
 * Encoding: M
 */
IL_LIFTER(neg) {
	RzILOpEffect *op = SETL("_op", x86_il_get_op(0));
	RzILOpEffect *cf = BRANCH(IS_ZERO(VARL("_op")), SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(CF), IL_TRUE));
	RzILOpEffect *neg = x86_il_set_op(0, NEG(VARL("_op")));

	return SEQ3(op, cf, neg);
}

/**
 * NOP
 * No operation
 * Encoding:
 *  - ZO (zero operands)
 *  - M (multi-byte nop)
 */
IL_LIFTER(nop) {
	return NOP();
}

/**
 * NOT
 * One's complement negation
 * Encoding: M
 */
IL_LIFTER(not ) {
	return x86_il_set_op(0, LOGNOT(x86_il_get_op(0)));
}

/**
 * OR
 * Logical inclusive or
 * Encoding:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(or) {
	RzILOpPure *op1 = x86_il_get_op(0);
	RzILOpPure *op2 = x86_il_get_op(1);
	RzILOpEffect * or = SETL("_or", LOGOR(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_or"));
	RzILOpEffect *clear_of = SETG(EFLAGS(OF), IL_FALSE);
	RzILOpEffect *clear_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("_or"));

	return SEQ5(or, set_dest, clear_of, clear_cf, set_res_flags);
}

/**
 * OUT
 * Output to port
 * Encodings: I, ZO
 */
IL_LIFTER(out) {
	/* It just jumps to an empty goto label "port"
	Also need an EMPTY() instruction after it to denote
	the end of analysis and restart all IL analysis */
	return SEQ2(GOTO("port"), EMPTY());
}

typedef struct pop_helper_t {
	RzILOpPure *val;
	RzILOpEffect *eff;
} PopHelper;

PopHelper x86_pop_helper_bits(unsigned int op_size, unsigned int bitness) {
	X86Mem stack_mem;
	/* The correct register will automatically be chosen if we use RSP */
	stack_mem.base = X86_REG_RSP;
	stack_mem.disp = 0;
	stack_mem.index = X86_REG_INVALID;
	stack_mem.scale = 1;
	stack_mem.segment = X86_REG_SS;

	PopHelper ret;

	ret.val = LOADW(op_size * BITS_PER_BYTE, x86_il_get_memaddr_bits(stack_mem, bitness));
	ret.eff = x86_il_set_reg_bits(X86_REG_RSP, ADD(x86_il_get_reg_bits(X86_REG_RSP, bitness, 0), UN(bitness, op_size)), bitness);

	return ret;
}

#define x86_pop_helper(op_size) x86_pop_helper_bits(op_size, analysis->bits)

/**
 * POP
 * Pop a value from the stack
 * Encoding:
 *  - M
 *  - O
 *  - ZO
 */
IL_LIFTER(pop) {
	/* Ideally, we should use the stack size instead of the address size (analysis->bits),
	but there seems to be no way to do that using Capstone */
	/* Also, it is very rare to use have a different stack size and address size */
	PopHelper pop = x86_pop_helper(ins->structure->operands[0].size);
	RzILOpEffect *copy = x86_il_set_op(0, pop.val);

	return SEQ2(copy, pop.eff);
}

/**
 * POPF
 * Pop stack into FLAGS register (16 bits)
 * Encoding: ZO
 */
IL_LIFTER(popf) {
	/* This is not _completely_ accurate, but it is good enough for our purposes */
	PopHelper pop = x86_pop_helper(2 /* BYTES */);
	return SEQ2(x86_il_set_flags(pop.val, 16), pop.eff);
}

/**
 * POPFD
 * Pop stack into EFLAGS register (32 bits)
 * Encoding: ZO
 */
IL_LIFTER(popfd) {
	/* Functionally the same as POPF IL */
	PopHelper pop = x86_pop_helper(4 /* BYTES */);
	return SEQ2(x86_il_set_flags(pop.val, 32), pop.eff);
}

/**
 * POPFQ
 * Pop stack into RFLAGS register (64 bits)
 * Encoding: ZO
 */
IL_LIFTER(popfq) {
	/* Functionally the same as POPF IL */
	PopHelper pop = x86_pop_helper(8 /* BYTES */);
	return SEQ2(x86_il_set_flags(pop.val, 64), pop.eff);
}

RzILOpEffect *x86_push_helper_impl(RzILOpPure *val, unsigned int user_op_size, unsigned int bitness, const X86ILIns *ins) {
	X86Mem stack_mem;
	/* The correct register will automatically be chosen if we use RSP */
	stack_mem.base = X86_REG_RSP;
	stack_mem.disp = 0;
	stack_mem.index = X86_REG_INVALID;
	stack_mem.scale = 1;
	stack_mem.segment = X86_REG_SS;

	unsigned int dflag = user_op_size;
	unsigned int op_size;
	unsigned int stack_size = bitness / BITS_PER_BYTE;

	if (ins) {
		if (bitness == 64) {
			dflag = ins->structure->rex ? 8 : ins->structure->prefix[2] ? 2
										    : 4; /* in bytes */
			stack_size = 8; /* in bytes */
		} else {
			/* We use the other operand and address size if the prefix is set */
			if ((bitness == 32) ^ ins->structure->prefix[2]) {
				dflag = 4;
			} else {
				dflag = 2;
			}

			stack_size = 4;
		}
	}

	if (bitness == 64) {
		op_size = (dflag == 2) ? 2 : 8;
	} else {
		op_size = dflag;
	}

	RzILOpEffect *ret = STOREW(x86_il_get_memaddr_bits(stack_mem, bitness), UNSIGNED(op_size * BITS_PER_BYTE, val));
	ret = SEQ2(x86_il_set_reg_bits(X86_REG_RSP, SUB(x86_il_get_reg_bits(X86_REG_RSP, bitness, 0), UN(bitness, stack_size)), bitness), ret);

	return ret;
}

#define x86_push_helper(val, op_size) x86_push_helper_impl(val, op_size, analysis->bits, NULL)

/**
 * CALL
 * Perform a function call
 * Encoding: D, M
 */
IL_LIFTER(call) {
	/*
	 * The following implementation is not accurate, since there are many nitty-gritties involved.
	 * Like whether the call is a near or far call, absolute or relative call, etc.
	 * Implementing it accurately will require exceptions, task switching,
	 * shadow stack, CPU internal flags, segmentation support
	 * Just pushing the current program counter is a good approcimation for now
	 * shadow stack, CPU internal flags, segmentation support
	 * Just pushing the current program counter is a good approcimation for now
	 * We also need to push the code segment register in case 16 and 32 bit modes.
	 */

	if (analysis->bits == 64) {
		return x86_push_helper(U64(pc), 2);
	} else {
		return SEQ4(SETL("_cs", UNSIGNED(analysis->bits, x86_il_get_reg(X86_REG_CS))), x86_push_helper(VARL("_cs"), analysis->bits / BITS_PER_BYTE), SETL("_pc", UN(analysis->bits, pc)), x86_push_helper(VARL("_pc"), analysis->bits / BITS_PER_BYTE));
	}
}

/**
 * PUSH
 * Push value on the stack
 * Encoding:
 *  - M
 *  - O
 *  - I
 *  - ZO
 */
IL_LIFTER(push) {
	return x86_push_helper_impl(x86_il_get_op(0), ins->structure->operands->size, analysis->bits, ins);
}

/**
 * PUSHF
 * Push FLAGS register onto the stack (16 bits)
 * Encoding: ZO
 */
IL_LIFTER(pushf) {
	return x86_push_helper(x86_il_get_flags(16), 2);
}

/**
 * PUSHFD
 * Push EFLAGS register onto the stack (32 bits)
 * Encoding: ZO
 */
IL_LIFTER(pushfd) {
	return x86_push_helper(x86_il_get_flags(32), 4);
}

/**
 * PUSHFQ
 * Push RFLAGS register onto the stack (64 bits)
 * Encoding: ZO
 */
IL_LIFTER(pushfq) {
	return x86_push_helper(x86_il_get_flags(64), 8);
}

/**
 * PUSHA
 * Push all general-purpose registers (16-bits)
 * Encoding: ZO
 */
IL_LIFTER(pushaw) {
	if (analysis->bits != 16) {
		return NULL;
	}

	RzILOpEffect *temp = SETL("_sp", x86_il_get_reg(X86_REG_SP));
	RzILOpEffect *push = x86_push_helper(x86_il_get_reg(X86_REG_AX), 2);
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_CX), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_DX), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_BX), 2));
	push = SEQ2(push, x86_push_helper(VARL("_sp"), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_BP), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_SI), 2));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_DI), 2));

	return SEQ2(temp, push);
}

/**
 * PUSHAD
 * Push all general-purpose registers (32-bits)
 * Encoding: ZO
 */
IL_LIFTER(pushal) {
	if (analysis->bits != 32) {
		return NULL;
	}

	RzILOpEffect *temp = SETL("_esp", x86_il_get_reg(X86_REG_ESP));
	RzILOpEffect *push = x86_push_helper(x86_il_get_reg(X86_REG_EAX), 4);
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_ECX), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EDX), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EBX), 4));
	push = SEQ2(push, x86_push_helper(VARL("_esp"), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EBP), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_ESI), 4));
	push = SEQ2(push, x86_push_helper(x86_il_get_reg(X86_REG_EDI), 4));

	return SEQ2(temp, push);
}

#define RCX_MACRO() \
	unsigned int size = ins->structure->operands[0].size; \
	RzILOpEffect *dest = SETL("_dest", x86_il_get_op(0)); \
	RzILOpEffect *temp_count = NULL, *cnt_masked = NULL; \
	ut8 tmp_count_size = 0; \
	switch (size) { \
	case 1: \
		temp_count = SETL("_tmp_cnt", MOD(UNSIGNED(5, x86_il_get_op(1)), UN(5, 9))); \
		cnt_masked = SETL("_cnt_mask", UNSIGNED(5, x86_il_get_op(1))); \
		tmp_count_size = 5; \
		break; \
	case 2: \
		temp_count = SETL("_tmp_cnt", MOD(UNSIGNED(5, x86_il_get_op(1)), UN(5, 17))); \
		cnt_masked = SETL("_cnt_mask", UNSIGNED(5, x86_il_get_op(1))); \
		tmp_count_size = 5; \
		break; \
	case 4: \
		temp_count = SETL("_tmp_cnt", UNSIGNED(5, x86_il_get_op(1))); \
		cnt_masked = SETL("_cnt_mask", UNSIGNED(5, x86_il_get_op(1))); \
		tmp_count_size = 5; \
		break; \
	case 8: \
		temp_count = SETL("_tmp_cnt", UNSIGNED(6, x86_il_get_op(1))); \
		cnt_masked = SETL("_cnt_mask", UNSIGNED(6, x86_il_get_op(1))); \
		tmp_count_size = 6; \
		break; \
	default: \
		rz_warn_if_reached(); \
	}

/**
 * RCL
 * Rotate left, with carry
 * Encoding: MI, M1, MC
 */
IL_LIFTER(rcl) {
	RCX_MACRO();

	RzILOpBool *cond = NON_ZERO(VARL("_tmp_cnt"));
	RzILOpEffect *repeat = SETL("_tmp_cf", MSB(VARL("_dest")));
	repeat = SEQ2(repeat, SETL("_dest", ADD(SHIFTL0(VARL("_dest"), U8(1)), x86_bool_to_bv(VARG(EFLAGS(CF)), BITS_PER_BYTE * size))));
	repeat = SEQ2(repeat, SETG(EFLAGS(CF), VARL("_tmp_cf")));
	repeat = SEQ2(repeat, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(tmp_count_size, 1))));

	RzILOpEffect *ret = SEQ4(dest, temp_count, cnt_masked, REPEAT(cond, repeat));

	RzILOpBool *if_cond = EQ(VARL("_cnt_mask"), UN(tmp_count_size, 1));
	RzILOpEffect *true_eff = SETG(EFLAGS(OF), XOR(MSB(VARL("_dest")), VARG(EFLAGS(CF))));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));

	return SEQ3(ret, BRANCH(if_cond, true_eff, NULL), set_dest);
}

/**
 * RCR
 * Rotate right, with carry
 * Encoding: MI, M1, MC
 */
IL_LIFTER(rcr) {
	RCX_MACRO();

	RzILOpBool *if_cond = EQ(VARL("_cnt_mask"), UN(tmp_count_size, 1));
	RzILOpEffect *true_eff = SETG(EFLAGS(OF), XOR(MSB(VARL("_dest")), VARG(EFLAGS(CF))));

	RzILOpBool *cond = NON_ZERO(VARL("_tmp_cnt"));
	RzILOpEffect *repeat = SETL("_tmp_cf", LSB(VARL("_dest")));
	repeat = SEQ2(repeat, SETL("_dest", ADD(SHIFTR0(VARL("_dest"), U8(1)), SHIFTL0(x86_bool_to_bv(VARG(EFLAGS(CF)), BITS_PER_BYTE * size), U8(size)))));
	repeat = SEQ2(repeat, SETG(EFLAGS(CF), VARL("_tmp_cf")));
	repeat = SEQ2(repeat, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(tmp_count_size, 1))));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));
	RzILOpEffect *ret = SEQ6(dest, temp_count, cnt_masked, BRANCH(if_cond, true_eff, NULL), REPEAT(cond, repeat), set_dest);

	return ret;
}

#undef RCX_MACRO

#define ROX_MACRO() \
	unsigned int size = ins->structure->operands[0].size; \
	unsigned int cnt_size = ins->structure->operands[1].size * BITS_PER_BYTE; \
	RzILOpEffect *dest = SETL("_dest", x86_il_get_op(0)); \
	RzILOpEffect *count_mask = NULL; \
	if (size == 64) { \
		count_mask = SETL("_cnt_mask", UN(ins->structure->operands[1].size * BITS_PER_BYTE, 0x3f)); \
	} else { \
		count_mask = SETL("_cnt_mask", UN(ins->structure->operands[1].size * BITS_PER_BYTE, 0x1f)); \
	} \
	RzILOpEffect *count = SETL("_cnt", x86_il_get_op(1)); \
	RzILOpEffect *masked = SETL("_masked", LOGAND(VARL("_cnt_mask"), VARL("_cnt"))); \
	RzILOpEffect *temp_count = SETL("_tmp_cnt", MOD(VARL("_masked"), UN(cnt_size, size)));

/**
 * ROL
 * Rotate left
 * Encoding: MI, M1, MC
 */
IL_LIFTER(rol) {
	ROX_MACRO();

	RzILOpBool *cond = NON_ZERO(VARL("_tmp_cnt"));
	RzILOpEffect *repeat = SETL("_tmp_cf", MSB(VARL("_dest")));
	repeat = SEQ2(repeat, SETL("_dest", ADD(SHIFTL0(VARL("_dest"), U8(1)), x86_bool_to_bv(VARL("_tmp_cf"), BITS_PER_BYTE * size))));
	repeat = SEQ2(repeat, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(cnt_size, 1))));

	RzILOpBool *if_cond1 = NON_ZERO(VARL("_masked"));
	RzILOpEffect *true_eff1 = SETG(EFLAGS(CF), LSB(VARL("_dest")));

	RzILOpBool *if_cond2 = EQ(VARL("_masked"), UN(cnt_size, 1));
	RzILOpEffect *true_eff2 = SETG(EFLAGS(OF), XOR(MSB(VARL("_dest")), VARG(EFLAGS(CF))));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));
	RzILOpEffect *ret = SEQ9(dest, count_mask, count, masked, temp_count, REPEAT(cond, repeat), BRANCH(if_cond1, true_eff1, NULL), BRANCH(if_cond2, true_eff2, NULL), set_dest);

	return ret;
}

/**
 * ROR
 * Rotate right
 * Encoding: MI, M1, MC
 */
IL_LIFTER(ror) {
	ROX_MACRO();

	RzILOpBool *cond = NON_ZERO(VARL("_tmp_cnt"));
	RzILOpEffect *repeat = SETL("_tmp_cf", LSB(VARL("_dest")));
	repeat = SEQ2(repeat, SETL("_dest", ADD(SHIFTR0(VARL("_dest"), U8(1)), SHIFTL0(x86_bool_to_bv(VARL("_tmp_cf"), BITS_PER_BYTE * size), U8(size)))));
	repeat = SEQ2(repeat, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(cnt_size, 1))));

	RzILOpBool *if_cond1 = NON_ZERO(VARL("_masked"));
	RzILOpEffect *true_eff1 = SETG(EFLAGS(CF), MSB(VARL("_dest")));

	RzILOpBool *if_cond2 = EQ(VARL("_masked"), UN(cnt_size, 1));
	RzILOpEffect *true_eff2 = SETG(EFLAGS(OF), XOR(MSB(VARL("_dest")), MSB(SHIFTL0(VARL("_dest"), U8(1)))));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_dest"));
	RzILOpEffect *ret = SEQ9(dest, count_mask, count, masked, temp_count, REPEAT(cond, repeat), BRANCH(if_cond1, true_eff1, NULL), BRANCH(if_cond2, true_eff2, NULL), set_dest);

	return ret;
}

#undef ROX_MACRO

/**
 * RET
 * Return (near pointer)
 * Encoding: ZO, I
 * Most modern x86-32 and x86-64 programs use this return instruction
 */
IL_LIFTER(ret) {
	PopHelper ph = x86_pop_helper(analysis->bits / BITS_PER_BYTE /* BYTES */);
	RzILOpEffect *ret = ph.eff;
	/* We can use RSP, and the correct stack pointer will be resolved depending on bitness */
	ret = SEQ2(ret, x86_il_set_reg(X86_REG_RSP, ph.val));

	if (ins->structure->op_count == 1) {
		/* Immediate operand (Encondig: I) */
		ret = SEQ2(ret, x86_il_set_reg(X86_REG_RSP, ADD(x86_il_get_reg(X86_REG_RSP), UN(analysis->bits, ins->structure->operands[0].imm))));
	}

	return ret;
}

// /**
//  * RETF
//  * Return far pointer
//  * Encoding: ZO, I
//  * Rarely found in modern programs
//  */
// IL_LIFTER(retf) {
// 	/* Unimplemented: Too rare and cumbersome to implement */
// 	return EMPTY();
// }

// /**
//  * RETFQ
//  * Return far pointer (size: qword)
//  * Encoding: ZO, I
//  * Rarely found in modern programs
//  */
// IL_LIFTER(retfq) {
// 	/* Unimplemented: Too rare and cumbersome to implement */
// 	return EMPTY();
// }

/**
 * SAHF
 * Store AH into FLAGS
 * Encoding: ZO
 */
IL_LIFTER(sahf) {
	return x86_il_set_flags(x86_il_get_reg(X86_REG_AH), 8);
}

#define SHIFT_MACRO() \
	RzILOpEffect *count = SETL("_cnt", x86_il_get_op(1)); \
	RzILOpEffect *count_mask = NULL; \
	unsigned int count_size = ins->structure->operands[1].size * BITS_PER_BYTE; \
	if (analysis->bits) { \
		count_mask = SETL("_cnt_mask", UN(count_size, 0x3f)); \
	} else { \
		count_mask = SETL("_cnt_mask", UN(count_size, 0x1f)); \
	} \
	RzILOpEffect *masked_count = SETL("_masked", LOGAND(VARL("_cnt"), VARL("_cnt_mask"))); \
	RzILOpEffect *temp_count = SETL("_tmp_cnt", VARL("_masked")); \
	RzILOpEffect *dest = SETL("_dest", x86_il_get_op(0)); \
	RzILOpEffect *temp_dest = SETL("_tmp_dest", VARL("_dest")); \
	RzILOpBool *while_cond = NON_ZERO(VARL("_tmp_cnt")); \
	RzILOpEffect *ret = SEQ6(count, count_mask, masked_count, temp_count, dest, temp_dest);

/**
 * SAL
 * Shift arithmetically left (signed shift left)
 * Encoding: M1, MC, MI
 * (Functionally the same as SHL)
 */
IL_LIFTER(sal) {
	SHIFT_MACRO();

	RzILOpEffect *loop_body = SETG(EFLAGS(CF), MSB(VARL("_dest")));
	loop_body = SEQ2(loop_body, SETL("_dest", SHIFTL0(VARL("_dest"), U8(1))));
	loop_body = SEQ2(loop_body, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(count_size, 1))));

	ret = SEQ2(ret, REPEAT(while_cond, loop_body));

	RzILOpBool *cond = EQ(VARL("_masked"), UN(count_size, 1));
	RzILOpEffect *set_overflow = SETG(EFLAGS(OF), XOR(MSB(VARL("_dest")), VARG(EFLAGS(CF))));

	return SEQ2(ret, BRANCH(cond, set_overflow, NULL));
}

/**
 * SAR
 * Shift arithmetically right (signed shift right)
 * Encoding: M1, MC, MI
 */
IL_LIFTER(sar) {
	SHIFT_MACRO();

	RzILOpEffect *loop_body = SETG(EFLAGS(CF), LSB(VARL("_dest")));
	loop_body = SEQ2(loop_body, SETL("_dest", SHIFTRA(VARL("_dest"), U8(1))));
	loop_body = SEQ2(loop_body, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(count_size, 1))));

	ret = SEQ2(ret, REPEAT(while_cond, loop_body));

	RzILOpBool *cond = EQ(VARL("_masked"), UN(count_size, 1));
	RzILOpEffect *set_overflow = SETG(EFLAGS(OF), IL_FALSE);

	return SEQ2(ret, BRANCH(cond, set_overflow, NULL));
}

/**
 * SHL
 * Shift left (unsigned shift left)
 * Encoding: M1, MC, MI
 * (Functionally the same as SAL)
 */
IL_LIFTER(shl) {
	SHIFT_MACRO();

	RzILOpEffect *loop_body = SETG(EFLAGS(CF), MSB(VARL("_dest")));
	loop_body = SEQ2(loop_body, SETL("_dest", SHIFTL0(VARL("_dest"), U8(1))));
	loop_body = SEQ2(loop_body, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(count_size, 1))));

	ret = SEQ2(ret, REPEAT(while_cond, loop_body));

	RzILOpBool *cond = EQ(VARL("_masked"), UN(count_size, 1));
	RzILOpEffect *set_overflow = SETG(EFLAGS(OF), XOR(MSB(VARL("_dest")), VARG(EFLAGS(CF))));

	return SEQ2(ret, BRANCH(cond, set_overflow, NULL));
}

/**
 * SHR
 * Shift right (unsigned shift left)
 * Encoding: M1, MC, MI
 */
IL_LIFTER(shr) {
	SHIFT_MACRO();

	RzILOpEffect *loop_body = SETG(EFLAGS(CF), LSB(VARL("_dest")));
	loop_body = SEQ2(loop_body, SETL("_dest", SHIFTR0(VARL("_dest"), U8(1))));
	loop_body = SEQ2(loop_body, SETL("_tmp_cnt", SUB(VARL("_tmp_cnt"), UN(count_size, 1))));

	ret = SEQ2(ret, REPEAT(while_cond, loop_body));

	RzILOpBool *cond = EQ(VARL("_masked"), UN(count_size, 1));
	RzILOpEffect *set_overflow = SETG(EFLAGS(OF), MSB(VARL("_tmp_dest")));

	return SEQ2(ret, BRANCH(cond, set_overflow, NULL));
}

/**
 * SBB
 * Subtraction with borrow
 * DEST = DEST - (SRC + CF)
 * Encoding: I, MI, MR, RM
 */
IL_LIFTER(sbb) {
	RzILOpEffect *op1 = SETL("_op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("_op2", x86_il_get_op(1));
	RzILOpPure *cf = VARG(EFLAGS(CF));

	RzILOpEffect *diff = SETL("_diff", SUB(SUB(VARL("_op1"), VARL("_op2")), x86_bool_to_bv(cf, ins->structure->operands[0].size * BITS_PER_BYTE)));
	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_diff"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("_diff"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("_diff"), VARL("_op1"), VARL("_op2"), false);

	return SEQ6(op1, op2, diff, set_dest, set_res_flags, set_arith_flags);
}

RzILOpEffect *x86_il_scas_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	X86Reg sub_reg;

	switch (size) {
	case 8:
		sub_reg = X86_REG_AL;
		break;
	case 16:
		sub_reg = X86_REG_AX;
		break;
	case 32:
		sub_reg = X86_REG_EAX;
		break;
	case 64:
		sub_reg = X86_REG_RAX;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	if (analysis->bits == 64) {
		X86Reg mem_reg = X86_REG_RDI;
		ut8 mem_size = 64;
		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpEffect *src = SETL("_src", LOADW(size, (mem_size == 64 ? x86_il_get_reg(mem_reg) : UNSIGNED(64, x86_il_get_reg(mem_reg)))));
		RzILOpEffect *reg = SETL("_reg", x86_il_get_reg(sub_reg));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_reg"), VARL("_src")));
		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_reg"), VARL("_src"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ6(reg, src, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	} else {
		RzILOpEffect *reg = SETL("_reg", x86_il_get_reg(sub_reg));

		X86Reg mem_reg = X86_REG_EDI;
		ut8 mem_size = 32;
		/* Check bitness and address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem;
		src_mem.base = mem_reg;
		src_mem.disp = 0;
		src_mem.index = X86_REG_INVALID;
		src_mem.scale = 1;
		src_mem.segment = X86_REG_ES;

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpEffect *src = SETL("_src", LOADW(size, x86_il_get_memaddr(src_mem)));
		RzILOpEffect *temp = SETL("_temp", SUB(VARL("_reg"), VARL("_src")));
		RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("_temp"), VARL("_reg"), VARL("_src"), false);
		RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_temp"));

		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ6(reg, src, temp, arith_flags, res_flags, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	}
}

/**
 * SCASB
 * Compare byte string
 * ZO
 */
IL_LIFTER(scasb) {
	return x86_il_scas_helper(ins, pc, analysis, 8);
}

/**
 * SCASW
 * Compare word string
 * ZO
 */
IL_LIFTER(scasw) {
	return x86_il_scas_helper(ins, pc, analysis, 16);
}

/**
 * SCASD
 * Compare dword string
 * ZO
 */
IL_LIFTER(scasd) {
	return x86_il_scas_helper(ins, pc, analysis, 32);
}

/**
 * SCASQ
 * Compare quadword string (only for x86-64)
 * ZO
 */
IL_LIFTER(scasq) {
	return x86_il_scas_helper(ins, pc, analysis, 64);
}

/**
 * STAC
 * Set AC flag
 * ZO
 */
IL_LIFTER(stac) {
	return SETG(EFLAGS(AC), IL_TRUE);
}

/**
 * STC
 * Set carry flag (CF)
 * ZO
 */
IL_LIFTER(stc) {
	return SETG(EFLAGS(CF), IL_TRUE);
}

/**
 * STD
 * Set direction flag (DF)
 * ZO
 */
IL_LIFTER(std) {
	return SETG(EFLAGS(DF), IL_TRUE);
}

/**
 * STI
 * Set interrupt flag (IF)
 * ZO
 */
IL_LIFTER(sti) {
	return SETG(EFLAGS(IF), IL_TRUE);
}

RzILOpEffect *x86_il_stos_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, ut8 size) {
	X86Reg store_reg;

	switch (size) {
	case 8:
		store_reg = X86_REG_AL;
		break;
	case 16:
		store_reg = X86_REG_AX;
		break;
	case 32:
		store_reg = X86_REG_EAX;
		break;
	case 64:
		store_reg = X86_REG_RAX;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	if (analysis->bits == 64) {
		X86Reg mem_reg = X86_REG_RDI;
		ut8 mem_size = 64;
		/* Address override prefix: 67H */
		if (ins->structure->prefix[3]) {
			mem_reg = X86_REG_EDI;
			mem_size = 32;
		}

		/* Cast to 64 if necessary (needed when address override prefix present) */
		RzILOpEffect *store = STOREW((mem_size == 64 ? x86_il_get_reg(mem_reg) : UNSIGNED(64, x86_il_get_reg(mem_reg))), x86_il_get_reg(store_reg));

		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ2(store, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	} else {
		X86Reg mem_reg = X86_REG_EDI;
		ut8 mem_size = 32;
		/* Check bitness and address override prefix: 67H */
		if (analysis->bits == 16 || ins->structure->prefix[3]) {
			mem_reg = X86_REG_DI;
			mem_size = 16;
		}

		X86Mem src_mem;
		src_mem.base = mem_reg;
		src_mem.disp = 0;
		src_mem.index = X86_REG_INVALID;
		src_mem.scale = 1;
		src_mem.segment = X86_REG_ES;

		/* No need for casting memaddr here since the casting will be done while calculating the segmented address */
		RzILOpEffect *store = x86_il_set_mem(src_mem, x86_il_get_reg(store_reg));
		RzILOpEffect *increment = x86_il_set_reg(mem_reg, ADD(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));
		RzILOpEffect *decrement = x86_il_set_reg(mem_reg, SUB(x86_il_get_reg(mem_reg), UN(mem_size, size / BITS_PER_BYTE)));

		return SEQ2(store, BRANCH(VARG(EFLAGS(DF)), decrement, increment));
	}
}

/**
 * STOSB
 * Store byte in a string
 * ZO
 */
IL_LIFTER(stosb) {
	return x86_il_stos_helper(ins, pc, analysis, 8);
}

/**
 * STOSW
 * Store word in a string
 * ZO
 */
IL_LIFTER(stosw) {

	return x86_il_stos_helper(ins, pc, analysis, 16);
}

/**
 * STOSD
 * Store dword in a string
 * ZO
 */
IL_LIFTER(stosd) {
	return x86_il_stos_helper(ins, pc, analysis, 32);
}

/**
 * STOSQ
 * Store quadword in a string
 * ZO
 */
IL_LIFTER(stosq) {
	return x86_il_stos_helper(ins, pc, analysis, 64);
}

/**
 * SUB
 * (SUB family of instructions)
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
IL_LIFTER(sub) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_op(0));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_op(1));
	RzILOpEffect *sub = SETL("sub", SUB(VARL("op1"), VARL("op2")));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("sub"));
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("sub"));
	RzILOpEffect *set_arith_flags = x86_il_set_arithmetic_flags(VARL("sub"), VARL("op1"), VARL("op2"), false);

	return SEQ6(op1, op2, sub, set_dest, set_res_flags, set_arith_flags);
}

/**
 * TEST
 * Logical compare (AND)
 * Encoding: I, MI, MR
 */
IL_LIFTER(test) {
	RzILOpEffect *res = SETL("_res", LOGAND(x86_il_get_op(0), x86_il_get_op(1)));
	RzILOpEffect *test = x86_il_set_op(0, VARL("_res"));
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_res"));
	RzILOpEffect *arith_flags = SEQ2(SETG(EFLAGS(CF), IL_FALSE), SETG(EFLAGS(OF), IL_FALSE));

	return SEQ4(res, test, res_flags, arith_flags);
}

/**
 * WAIT
 * Wait until not busy
 * ZO
 */
IL_LIFTER(wait) {
	/* NOP seems to be a reasonable implementation */
	return NOP();
}

/**
 * XCHG
 * Exchange data
 * Encoding: O, MR, RM
 */
IL_LIFTER(xchg) {
	RzILOpEffect *temp = SETL("_temp", x86_il_get_op(0));
	RzILOpEffect *xchg = x86_il_set_op(0, x86_il_get_op(1));
	RzILOpEffect *set_src = x86_il_set_op(1, VARL("_temp"));

	return SEQ3(temp, xchg, set_src);
}

/**
 * XLATB
 * Table look-up translation
 * Encoding: ZO
 */
IL_LIFTER(xlatb) {
	X86Mem mem;
	mem.disp = 0;
	mem.index = X86_REG_INVALID;
	mem.scale = 1;
	mem.segment = X86_REG_DS;
	mem.base = X86_REG_EBX;

	if (analysis->bits == 64) {
		mem.segment = X86_REG_INVALID;
		mem.base = X86_REG_RBX;
	} else if (analysis->bits == 16) {
		mem.base = X86_REG_BX;
	}

	return x86_il_set_reg(X86_REG_AL, LOADW(8, ADD(x86_il_get_memaddr(mem), UNSIGNED(analysis->bits, x86_il_get_reg(X86_REG_AL)))));
}

/**
 * XOR
 * Logical exclusive OR
 * Encodings: I, MI, MR, RM
 */
IL_LIFTER(xor) {
	RzILOpPure *op1 = x86_il_get_op(0);
	RzILOpPure *op2 = x86_il_get_op(1);
	RzILOpEffect * xor = SETL("_xor", LOGXOR(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_op(0, VARL("_xor"));
	RzILOpEffect *clear_of = SETG(EFLAGS(OF), IL_FALSE);
	RzILOpEffect *clear_cf = SETG(EFLAGS(CF), IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("_xor"));

	return SEQ5(xor, set_dest, clear_of, clear_cf, set_res_flags);
}

/**
 * BOUND
 * Check array index against bounds
 * Encoding: RM
 */

IL_LIFTER(bound) {
	RzILOpEffect *index = SETL("_index", x86_il_get_op(0));

	X86Mem mem = ins->structure->operands[1].mem;
	RzILOpEffect *lower = SETL("_lower", LOADW(ins->structure->operands[0].size * BITS_PER_BYTE, x86_il_get_memaddr(mem)));
	mem.disp += ins->structure->operands[1].size / mem.scale;
	RzILOpEffect *upper = SETL("_upper", LOADW(ins->structure->operands[0].size * BITS_PER_BYTE, x86_il_get_memaddr(mem)));

	RzILOpBool *cond = OR(ULT(VARL("_index"), VARL("_lower")), UGT(VARL("_index"), VARL("_upper")));

	/* Interrupt if out of bounds, NOP otherwise */
	return SEQ4(index, lower, upper, BRANCH(cond, SEQ2(GOTO("int"), EMPTY()), NOP()));
}

/**
 * ENTER
 * Make a stack frame for procedure parameters
 * Encoding: II
 */
IL_LIFTER(enter) {
	RzILOpEffect *alloc_size = SETL("_alloc_sz", UNSIGNED(16, x86_il_get_op(0)));
	RzILOpEffect *nesting_level = SETL("_nest_lvl", MOD(UNSIGNED(8, x86_il_get_op(1)), U8(32)));

	/* Will get resolved correctly to the largest SP reg */
	X86Reg sp_reg = X86_REG_RSP;

	/* Default value initialization (useless, but need to avoid warnings) */
	X86Reg bp_reg = X86_REG_RBP;
	unsigned short bp_size = analysis->bits / BITS_PER_BYTE;

	switch (analysis->bits) {
	case 64:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		} else {
			bp_reg = X86_REG_RBP;
			bp_size = 8;
		}
		break;
	case 32:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_BP;
			bp_size = 2;
		} else {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		}
		break;
	case 16:
		bp_reg = X86_REG_BP;
		bp_size = 2;
		break;
	default:
		rz_warn_if_reached();
	}

	RzILOpEffect *push = x86_push_helper(x86_il_get_reg(bp_reg), bp_size);
	RzILOpEffect *frame_temp = SETL("_frame_tmp", x86_il_get_reg(sp_reg));

	RzILOpEffect *itr = SETL("_itr", U8(1));

	/* RBP will be dynamically resolved to the correct BP register */
	RzILOpEffect *loop_body = SEQ3(x86_il_set_reg(X86_REG_RBP, SUB(x86_il_get_reg(X86_REG_RBP), UN(analysis->bits, bp_size))), x86_push_helper(LOADW(bp_size * BITS_PER_BYTE, x86_il_get_reg(X86_REG_RBP)), bp_size), SETL("_itr", ADD(VARL("_itr"), U8(1))));
	RzILOpEffect *loop = REPEAT(ULT(VARL("_itr"), VARL("_nest_lvl")), loop_body);

	RzILOpEffect *nesting_lvl1 = x86_push_helper(VARL("_frame_tmp"), bp_size);

	RzILOpEffect *continue_eff = x86_il_set_reg(sp_reg, SUB(x86_il_get_reg(sp_reg), UNSIGNED(analysis->bits, VARL("_alloc_sz"))));
	if (bp_size == 2) {
		continue_eff = SEQ2(continue_eff, x86_il_set_reg(bp_reg, UNSIGNED(16, UNSIGNED(15, VARL("_frame_tmp")))));
	} else {
		continue_eff = SEQ2(continue_eff, x86_il_set_reg(bp_reg, VARL("_frame_tmp")));
	}

	return SEQ6(alloc_size, nesting_level, push, frame_temp, BRANCH(IS_ZERO(VARL("_nest_lvl")), NOP(), SEQ2(BRANCH(UGT(VARL("_nest_lvl"), U8(1)), SEQ2(itr, loop), NOP()), nesting_lvl1)), continue_eff);
}

/**
 * LEAVE
 * High level procedure exit
 * Encoding: ZO
 */
IL_LIFTER(leave) {
	RzILOpEffect *set_sp = x86_il_set_reg(X86_REG_RSP, x86_il_get_reg(X86_REG_RBP));

	/* Default value initialization (useless, but need to avoid warnings) */
	X86Reg bp_reg = X86_REG_RBP;
	unsigned short bp_size = analysis->bits / BITS_PER_BYTE;

	switch (analysis->bits) {
	case 64:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		} else {
			bp_reg = X86_REG_RBP;
			bp_size = 8;
		}
		break;
	case 32:
		/* Operand-size override (66H) */
		if (ins->structure->prefix[2]) {
			bp_reg = X86_REG_BP;
			bp_size = 2;
		} else {
			bp_reg = X86_REG_EBP;
			bp_size = 4;
		}
		break;
	case 16:
		bp_reg = X86_REG_BP;
		bp_size = 2;
		break;
	default:
		rz_warn_if_reached();
	}

	PopHelper pop = x86_pop_helper(bp_size /* BYTES */);
	RzILOpEffect *set_bp = x86_il_set_reg(bp_reg, pop.val);

	return SEQ3(set_sp, pop.eff, set_bp);
}

typedef RzILOpEffect *(*x86_il_ins)(const X86ILIns *, ut64, RzAnalysis *);

/**
 * \brief RzIL handlers for x86 instructions
 */
static x86_il_ins x86_ins[X86_INS_ENDING] = {
	[X86_INS_INVALID] = x86_il_invalid,
	[X86_INS_AAA] = x86_il_aaa,
	[X86_INS_AAD] = x86_il_aad,
	[X86_INS_AAM] = x86_il_aam,
	[X86_INS_AAS] = x86_il_aas,
	[X86_INS_ADC] = x86_il_adc,
	[X86_INS_ADD] = x86_il_add,
	[X86_INS_AND] = x86_il_and,
	[X86_INS_CALL] = x86_il_call,
	[X86_INS_CBW] = x86_il_cbw,
	[X86_INS_CLC] = x86_il_clc,
	[X86_INS_CLD] = x86_il_cld,
	[X86_INS_CLI] = x86_il_cli,
	[X86_INS_CMC] = x86_il_cmc,
	[X86_INS_CMP] = x86_il_cmp,
	[X86_INS_CMPSB] = x86_il_cmpsb,
	[X86_INS_CMPSW] = x86_il_cmpsw,
	[X86_INS_CMPSD] = x86_il_cmpsd,
	[X86_INS_CMPSQ] = x86_il_cmpsq,
	[X86_INS_DAA] = x86_il_daa,
	[X86_INS_DAS] = x86_il_das,
	[X86_INS_DEC] = x86_il_dec,
	[X86_INS_DIV] = x86_il_div,
	[X86_INS_HLT] = x86_il_hlt,
	[X86_INS_IDIV] = x86_il_idiv,
	[X86_INS_IMUL] = x86_il_imul,
	[X86_INS_IN] = x86_il_in,
	[X86_INS_INC] = x86_il_inc,
	[X86_INS_INT] = x86_il_int,
	[X86_INS_INTO] = x86_il_into,
	[X86_INS_IRET] = x86_il_unimpl,
	[X86_INS_JA] = x86_il_ja,
	[X86_INS_JAE] = x86_il_jae,
	[X86_INS_JB] = x86_il_jb,
	[X86_INS_JBE] = x86_il_jbe,
	[X86_INS_JCXZ] = x86_il_jcxz,
	[X86_INS_JECXZ] = x86_il_jecxz,
	[X86_INS_JRCXZ] = x86_il_jrcxz,
	[X86_INS_JE] = x86_il_je,
	[X86_INS_JG] = x86_il_jg,
	[X86_INS_JGE] = x86_il_jge,
	[X86_INS_JL] = x86_il_jl,
	[X86_INS_JLE] = x86_il_jle,
	[X86_INS_JNE] = x86_il_jne,
	[X86_INS_JNO] = x86_il_jno,
	[X86_INS_JNP] = x86_il_jnp,
	[X86_INS_JNS] = x86_il_jns,
	[X86_INS_JO] = x86_il_jo,
	[X86_INS_JP] = x86_il_jp,
	[X86_INS_JS] = x86_il_js,
	[X86_INS_JMP] = x86_il_jmp,
	[X86_INS_LAHF] = x86_il_lahf,
	[X86_INS_LDS] = x86_il_lds,
	[X86_INS_LEA] = x86_il_lea,
	[X86_INS_LES] = x86_il_les,
	[X86_INS_LODSB] = x86_il_lodsb,
	[X86_INS_LODSW] = x86_il_lodsw,
	[X86_INS_LODSD] = x86_il_lodsd,
	[X86_INS_LODSQ] = x86_il_lodsq,
	[X86_INS_LOOP] = x86_il_loop,
	[X86_INS_LOOPE] = x86_il_loope,
	[X86_INS_LOOPNE] = x86_il_loopne,
	[X86_INS_MOV] = x86_il_mov,
	[X86_INS_MOVSB] = x86_il_movsb,
	[X86_INS_MOVSW] = x86_il_movsw,
	[X86_INS_MOVSD] = x86_il_movsd,
	[X86_INS_MOVSQ] = x86_il_movsq,
	[X86_INS_MUL] = x86_il_mul,
	[X86_INS_NEG] = x86_il_neg,
	[X86_INS_NOP] = x86_il_nop,
	[X86_INS_NOT] = x86_il_not,
	[X86_INS_OR] = x86_il_or,
	[X86_INS_OUT] = x86_il_out,
	[X86_INS_POP] = x86_il_pop,
	[X86_INS_POPF] = x86_il_popf,
	[X86_INS_POPFD] = x86_il_popfd,
	[X86_INS_POPFQ] = x86_il_popfq,
	[X86_INS_PUSH] = x86_il_push,
	[X86_INS_PUSHF] = x86_il_pushf,
	[X86_INS_PUSHFD] = x86_il_pushfd,
	[X86_INS_PUSHFQ] = x86_il_pushfq,
	[X86_INS_PUSHAW] = x86_il_pushaw,
	[X86_INS_PUSHAL] = x86_il_pushal,
	[X86_INS_RCL] = x86_il_rcl,
	[X86_INS_RCR] = x86_il_rcr,
	[X86_INS_ROL] = x86_il_rol,
	[X86_INS_ROR] = x86_il_ror,
	[X86_INS_RET] = x86_il_ret,
	[X86_INS_RETF] = x86_il_unimpl,
	[X86_INS_RETFQ] = x86_il_unimpl,
	[X86_INS_SAHF] = x86_il_sahf,
	[X86_INS_SAL] = x86_il_sal,
	[X86_INS_SAR] = x86_il_sar,
	[X86_INS_SHL] = x86_il_shl,
	[X86_INS_SHR] = x86_il_shr,
	[X86_INS_SBB] = x86_il_sbb,
	[X86_INS_SCASB] = x86_il_scasb,
	[X86_INS_SCASW] = x86_il_scasw,
	[X86_INS_SCASD] = x86_il_scasd,
	[X86_INS_SCASQ] = x86_il_scasq,
	[X86_INS_STAC] = x86_il_stac,
	[X86_INS_STC] = x86_il_stc,
	[X86_INS_STD] = x86_il_std,
	[X86_INS_STI] = x86_il_sti,
	[X86_INS_STOSB] = x86_il_stosb,
	[X86_INS_STOSD] = x86_il_stosd,
	[X86_INS_STOSQ] = x86_il_stosq,
	[X86_INS_STOSW] = x86_il_stosw,
	[X86_INS_SUB] = x86_il_sub,
	[X86_INS_TEST] = x86_il_test,
	[X86_INS_WAIT] = x86_il_wait,
	[X86_INS_XCHG] = x86_il_xchg,
	[X86_INS_XLATB] = x86_il_xlatb,
	[X86_INS_XOR] = x86_il_xor,
	[X86_INS_BOUND] = x86_il_bound,
	[X86_INS_ENTER] = x86_il_enter,
	[X86_INS_INSB] = x86_il_unimpl,
	[X86_INS_INSW] = x86_il_unimpl,
	[X86_INS_OUTSB] = x86_il_unimpl,
	[X86_INS_OUTSW] = x86_il_unimpl,
	[X86_INS_LEAVE] = x86_il_leave
};

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI bool rz_x86_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const X86ILIns *ins) {
	rz_return_val_if_fail(analysis && aop && ins, false);
	if (ins->mnem >= X86_INS_ENDING) {
		RZ_LOG_ERROR("RzIL: x86: Invalid instruction type %d", ins->mnem);
		return false;
	}

	x86_il_ins lifter = x86_ins[ins->mnem];

	RzILOpEffect *lifted;

	if (!lifter) {
		/* For unimplemented instructions */
		lifter = x86_il_unimpl;
	}
	lifted = lifter(ins, pc, analysis);

	aop->il_op = lifted;
	return true;
}

RZ_IPI RzAnalysisILConfig *rz_x86_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *r = rz_analysis_il_config_new(analysis->bits, analysis->big_endian, analysis->bits);

	switch (analysis->bits) {
	case 16:
		r->reg_bindings = x86_bound_regs_16;
		break;
	case 32:
		r->reg_bindings = x86_bound_regs_32;
		break;
	case 64:
		r->reg_bindings = x86_bound_regs_64;
		break;
	default:
		rz_warn_if_reached();
	}

	RzILEffectLabel *int_label = rz_il_effect_label_new("int", EFFECT_LABEL_SYSCALL);
	int_label->hook = label_int;
	rz_analysis_il_config_add_label(r, int_label);

	RzILEffectLabel *halt_label = rz_il_effect_label_new("halt", EFFECT_LABEL_SYSCALL);
	halt_label->hook = label_halt;
	rz_analysis_il_config_add_label(r, halt_label);

	RzILEffectLabel *port_label = rz_il_effect_label_new("port", EFFECT_LABEL_SYSCALL);
	port_label->hook = label_port;
	rz_analysis_il_config_add_label(r, port_label);

	return r;
}
