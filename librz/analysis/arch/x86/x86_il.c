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

#define RET_NULL_IF_64BIT_OR_LOCK() \
	if (analysis->bits == 64 || ins->structure->prefix[0] == X86_PREFIX_LOCK) { \
		/* #UD exception */ \
		return NULL; \
	}

/**
 * \brief X86 registers' variable names in RzIL
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
	[X86_REG_DR8] = "dr8",
	[X86_REG_DR9] = "dr9",
	[X86_REG_DR10] = "dr10",
	[X86_REG_DR11] = "dr11",
	[X86_REG_DR12] = "dr12",
	[X86_REG_DR13] = "dr13",
	[X86_REG_DR14] = "dr14",
	[X86_REG_DR15] = "dr15",
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
	[X86_EFLAGS_VM] = "vm"
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

static bool x86_il_is_gpr(X86Reg reg) {
	for (unsigned int i = 0; i < GPR_FAMILY_COUNT; i++) {
		if (reg == gpr_hregs[i] || reg == gpr_lregs[i] || reg == gpr_xregs[i] || reg == gpr_eregs[i] || reg == gpr_rregs[i]) {
			return true;
		}
	}

	return false;
}

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

static RzILOpPure *x86_il_get_gprh(X86Reg reg, int bits) {
	return UNSIGNED(8, SHIFTR0(VARG(x86_registers[reg]), U8(8)));
}
static RzILOpPure *x86_il_get_gprl(X86Reg reg, int bits) {
	return UNSIGNED(8, VARG(x86_registers[reg]));
}
static RzILOpPure *x86_il_get_gpr16(X86Reg reg, int bits) {
	if (bits == 16) {
		// Don't perform unnecessary casting
		return VARG(x86_registers[reg]);
	}
	return UNSIGNED(16, VARG(x86_registers[reg]));
}
static RzILOpPure *x86_il_get_gpr32(X86Reg reg, int bits) {
	if (bits == 32) {
		return VARG(x86_registers[reg]);
	}
	return UNSIGNED(32, VARG(x86_registers[reg]));
}
static RzILOpPure *x86_il_get_gpr64(X86Reg reg, int bits) {
	return VARG(x86_registers[reg]);
}

static RzILOpEffect *x86_il_set_gprh(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	RzILOpPure *mask = LOGNOT(UN(bits, 0xff00));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, SHIFTL0(UNSIGNED(bits, val), U8(8)));
	return SETG(x86_registers[reg], final_reg);
}
static RzILOpEffect *x86_il_set_gprl(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	RzILOpPure *mask = LOGNOT(UN(bits, 0xff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(bits, val));
	return SETG(x86_registers[reg], final_reg);
}
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
static RzILOpEffect *x86_il_set_gpr32(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	if (bits == 32) {
		return SETG(x86_registers[reg], val);
	}
	RzILOpPure *mask = LOGNOT(UN(bits, 0xffffffff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(bits, val));
	return SETG(x86_registers[reg], final_reg);
}
static RzILOpEffect *x86_il_set_gpr64(X86Reg reg, RzILOpPure *val, int bits) {
	return SETG(x86_registers[reg], val);
}

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
	unsigned int index;
	RzILOpPure *(*get_handler)(X86Reg, int);
	RzILOpEffect *(*set_handler)(X86Reg, RzILOpPure *, int);
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
	[X86_REG_IP] = { 6, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EIP] = { 6, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RIP] = { 6, x86_il_get_gpr64, x86_il_set_gpr64 },
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

static RzILOpPure *x86_il_get_reg_bits(X86Reg reg, int bits) {
	if (!x86_il_is_gpr(reg)) {
		return VARG(x86_registers[reg]);
	}
	struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
	/* Need to use `get_bitness_reg` because not all registers
	are available in the IL in any particular bitness
	(For example, "rax" is not a valid IL variable in 32-bit mode)
	So, we need to use the max width register available */
	return entry.get_handler(get_bitness_reg(entry.index, bits), bits);
}

#define x86_il_get_reg(reg) x86_il_get_reg_bits(reg, analysis->bits)

static RzILOpEffect *x86_il_set_reg_bits(X86Reg reg, RzILOpPure *val, int bits) {
	if (!x86_il_is_gpr(reg)) {
		return SETG(x86_registers[reg], val);
	}
	struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
	return entry.set_handler(get_bitness_reg(entry.index, bits), val, bits);
}

#define x86_il_set_reg(reg, val) x86_il_set_reg_bits(reg, val, analysis->bits)

static RzILOpPure *x86_il_get_memaddr_bits(X86Mem mem, int bits) {
	RzILOpPure *offset = NULL;
	if (mem.base != X86_REG_INVALID) {
		if (!offset) {
			offset = x86_il_get_reg_bits(mem.base, bits);
			if (x86_il_get_reg_size(mem.base) != bits) {
				offset = UNSIGNED(bits, offset);
			}
		}
	}
	if (mem.index != X86_REG_INVALID) {
		RzILOpPure *reg = x86_il_get_reg_bits(mem.index, bits);
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

	if (mem.segment != X86_REG_INVALID) {
		// TODO: Implement segmentation
		/* Currently the segmentation is only implemented for real mode
		 Address = Segment * 0x10 + Offset */

		if (bits == 32) {
			/* Assuming real mode */
			offset = ADD(offset, SHIFTL0(UNSIGNED(32, x86_il_get_reg_bits(mem.segment, bits)), U8(4)));
		} else {
			RZ_LOG_WARN("x86: RzIL: No support for segmentation\n");
			return NULL;
		}
	}

	return offset;
}

static RzILOpEffect *x86_il_set_mem_bits(X86Mem mem, RzILOpPure *val, int bits) {
	return STOREW(x86_il_get_memaddr_bits(mem, bits), val);
}

#define x86_il_set_mem(mem, val) x86_il_set_mem_bits(mem, val, analysis->bits)

static RzILOpPure *x86_il_get_operand_bits(X86Op op, int analysis_bits) {
	RzILOpPure *ret = NULL;
	switch (op.type) {
	case X86_OP_INVALID:
		RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered\n");
		break;
	case X86_OP_REG:
		ret = x86_il_get_reg_bits(op.reg, analysis_bits);
		break;
	case X86_OP_IMM:
		ret = SN(op.size * BITS_PER_BYTE, op.imm);
		break;
	case X86_OP_MEM:
		ret = LOADW(BITS_PER_BYTE * op.size, x86_il_get_memaddr_bits(op.mem, analysis_bits));
	}
	return ret;
}

#define x86_il_get_operand(op) x86_il_get_operand_bits(op, analysis->bits)

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

static RzILOpBitVector *x86_bool_to_bv(RzILOpBool *b, unsigned int bits) {
	return ITE(b, UN(bits, 1), UN(bits, 0));
}

struct x86_parity_helper_t {
	RzILOpBool *val;
	RzILOpEffect *eff;
};

static struct x86_parity_helper_t x86_il_get_parity(RZ_OWN RzILOpPure *val) {
	// assumed that val is an 8-bit wide value
	RzILOpEffect *setvar = SETL("_popcnt", U8(0));
	setvar = SEQ2(setvar, SETL("_val", val));

	/* We can stop shifting the "_val" once it is zero,
	since the value of "_popcnt" wouldn't change any further */
	RzILOpBool *termination_cond = IS_ZERO(VARL("_val"));

	RzILOpEffect *popcnt = SETL("_popcnt", ADD(VARL("_popcnt"), x86_bool_to_bv(LSB(VARL("_val")), 8)));
	popcnt = SEQ2(popcnt, SETL("_val", SHIFTR0(VARL("_val"), U8(1))));

	RzILOpEffect *repeat_eff = REPEAT(termination_cond, popcnt);

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
		SETG(x86_eflags_registers[X86_EFLAGS_PF], pf.val),
		SETG(x86_eflags_registers[X86_EFLAGS_ZF], zf),
		SETG(x86_eflags_registers[X86_EFLAGS_SF], sf));
}

#define x86_il_set_result_flags(result) x86_il_set_result_flags_bits(result, analysis->bits)

/**
 * \brief Sets the value of CF, OF, AF according to the \p result
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
		SETG(x86_eflags_registers[X86_EFLAGS_CF], cf),
		SETG(x86_eflags_registers[X86_EFLAGS_OF], of),
		SETG(x86_eflags_registers[X86_EFLAGS_AF], af));
}

#define x86_il_set_arithmetic_flags(res, x, y, addition) x86_il_set_arithmetic_flags_bits(res, x, y, addition, analysis->bits)

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
static RzILOpEffect *x86_il_invalid(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	return EMPTY();
}

/* 8086/8088 instructions*/

/**
 * AAA
 * ASCII adjust AL after addition
 * 37 | Invalid | Valid
 */
static RzILOpEffect *x86_il_aaa(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, VARG(x86_eflags_registers[X86_EFLAGS_AF]));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, ADD(x86_il_get_reg(X86_REG_AX), U16(0x106)));
	RzILOpEffect *set_af = SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_TRUE);
	RzILOpEffect *set_cf = SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_TRUE);
	RzILOpEffect *true_cond = SEQ3(set_ax, set_af, set_cf);

	set_af = SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_FALSE);
	set_cf = SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE);
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
static RzILOpEffect *x86_il_aad(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *temp_ah = SETL("temp_ah", x86_il_get_reg(X86_REG_AH));

	RzILOpPure *imm;
	if (ins->structure->op_count == 0) {
		// Use base 10 if none specified
		imm = SN(8, 0x0a);
	} else {
		imm = x86_il_get_operand(ins->structure->operands[0]);
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
static RzILOpEffect *x86_il_aam(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));

	RzILOpPure *imm;
	if (ins->structure->op_count == 0) {
		imm = SN(8, 0xa);
	} else {
		imm = x86_il_get_operand(ins->structure->operands[0]);
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
static RzILOpEffect *x86_il_aas(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, VARG(x86_eflags_registers[X86_EFLAGS_AF]));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, SUB(x86_il_get_reg(X86_REG_AX), U16(0x6)));
	RzILOpEffect *set_ah = x86_il_set_reg(X86_REG_AH, SUB(x86_il_get_reg(X86_REG_AH), U8(0x1)));
	RzILOpEffect *set_af = SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_TRUE);
	RzILOpEffect *set_cf = SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_TRUE);
	RzILOpEffect *true_cond = SEQ4(set_ax, set_ah, set_af, set_cf);

	set_af = SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_FALSE);
	set_cf = SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE);
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
static RzILOpEffect *x86_il_adc(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_operand(ins->structure->operands[0]));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_operand(ins->structure->operands[1]));
	RzILOpPure *cf = VARG(x86_eflags_registers[X86_EFLAGS_CF]);

	RzILOpEffect *sum = SETL("sum", ADD(ADD(VARL("op1"), VARL("op2")), x86_bool_to_bv(cf, ins->structure->operands[0].size * BITS_PER_BYTE)));
	RzILOpEffect *set_dest = x86_il_set_operand(ins->structure->operands[0], VARL("sum"));
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
static RzILOpEffect *x86_il_add(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_operand(ins->structure->operands[0]));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_operand(ins->structure->operands[1]));
	RzILOpEffect *sum = SETL("sum", ADD(VARL("op1"), VARL("op2")));

	RzILOpEffect *set_dest = x86_il_set_operand(ins->structure->operands[0], VARL("sum"));
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
static RzILOpEffect *x86_il_and(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *op1 = x86_il_get_operand(ins->structure->operands[0]);
	RzILOpPure *op2 = x86_il_get_operand(ins->structure->operands[1]);
	RzILOpEffect *and = SETL("and_", LOGAND(op1, op2));

	RzILOpEffect *set_dest = x86_il_set_operand(ins->structure->operands[0], VARL("and_"));
	RzILOpEffect *clear_of = SETG(x86_eflags_registers[X86_EFLAGS_OF], IL_FALSE);
	RzILOpEffect *clear_cf = SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE);
	RzILOpEffect *set_res_flags = x86_il_set_result_flags(VARL("and_"));

	return SEQ5(and, set_dest, clear_of, clear_cf, set_res_flags);
}

static RzILOpEffect *x86_il_call(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	// TODO
	return EMPTY();
}

/**
 * CBW
 * Convert byte to word
 * 98 | Valid | Valid
 */
static RzILOpEffect *x86_il_cbw(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	/* The UNSIGNED(16, ...) cast is useless in case of 32 bits,
	but removing it will cause issues for 16-bit */
	return x86_il_set_reg(X86_REG_AX, UNSIGNED(16, x86_il_get_reg(X86_REG_AL)));
}

/**
 * CLC
 * Clear carry flag
 * F8 | Valid | Valid
 */
static RzILOpEffect *x86_il_clc(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	return SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE);
}

/**
 * CLD
 * Clear direction flag
 * FC | Valid | Valid
 */
static RzILOpEffect *x86_il_cld(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	return SETG(x86_eflags_registers[X86_EFLAGS_DF], IL_FALSE);
}

/**
 * CLI
 * Clear interrupt flag
 * FA | Valid | Valid
 */
static RzILOpEffect *x86_il_cli(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	return SETG(x86_eflags_registers[X86_EFLAGS_IF], IL_FALSE);
}

/**
 * CMC
 * Complement carry flag
 * F5 | Valid | Valid
 */
static RzILOpEffect *x86_il_cmc(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	return SETG(x86_eflags_registers[X86_EFLAGS_CF], INV(VARG(x86_eflags_registers[X86_EFLAGS_CF])));
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
static RzILOpEffect *x86_il_cmp(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_operand(ins->structure->operands[0]));

	RzILOpPure *second;
	if (ins->structure->operands[0].size != ins->structure->operands[1].size) {
		/* second operand can be an immediate value of smaller size,
		but we need the same bitv size to use RzIL ops */
		second = SIGNED(ins->structure->operands[0].size, x86_il_get_operand(ins->structure->operands[1]));
	} else {
		second = x86_il_get_operand(ins->structure->operands[1]);
	}
	RzILOpEffect *op2 = SETL("op2", second);

	RzILOpEffect *sub = SETL("sub", SUB(VARL("op1"), VARL("op2")));
	RzILOpEffect *arith = x86_il_set_arithmetic_flags(VARL("sub"), VARL("op1"), VARL("op2"), false);
	RzILOpEffect *res = x86_il_set_result_flags(VARL("sub"));

	return SEQ5(op1, op2, sub, arith, res);
}

/**
 * CMPSB
 * Compare the byte at (R|E)SI and (R|E)DI
 * A6 | Valid | Valid
 */
static RzILOpEffect *x86_il_cmpsb(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_operand(ins->structure->operands[0]));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_operand(ins->structure->operands[1]));
	RzILOpEffect *res = SETL("res", SUB(VARL("op1"), VARL("op2")));

	RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("res"), VARL("op1"), VARL("op2"), false);
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("res"));

	/* We can directly use `RSI` adn `RDI`, because in case of 32 bits
	they will automatically be resolved to `ESI` and `EDI` */
	RzILOpEffect *add = x86_il_set_reg(X86_REG_RSI, ADD(x86_il_get_reg(X86_REG_RSI), UN(analysis->bits, 1)));
	add = SEQ2(add, x86_il_set_reg(X86_REG_RDI, ADD(x86_il_get_reg(X86_REG_RDI), UN(analysis->bits, 1))));
	RzILOpEffect *sub = x86_il_set_reg(X86_REG_RSI, SUB(x86_il_get_reg(X86_REG_RSI), UN(analysis->bits, 1)));
	sub = SEQ2(sub, x86_il_set_reg(X86_REG_RDI, SUB(x86_il_get_reg(X86_REG_RDI), UN(analysis->bits, 1))));

	return SEQ6(op1, op2, res, arith_flags, res_flags, BRANCH(VARG(x86_eflags_registers[X86_EFLAGS_DF]), sub, add));
}

/**
 * CMPSW
 * Compare the word at (R|E)SI and (R|E)DI
 * A7 | Valid | Valid
 */
static RzILOpEffect *x86_il_cmpsw(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", x86_il_get_operand(ins->structure->operands[0]));
	RzILOpEffect *op2 = SETL("op2", x86_il_get_operand(ins->structure->operands[1]));
	RzILOpEffect *res = SETL("res", SUB(VARL("op1"), VARL("op2")));

	RzILOpEffect *arith_flags = x86_il_set_arithmetic_flags(VARL("res"), VARL("op1"), VARL("op2"), false);
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("res"));

	RzILOpEffect *add = x86_il_set_reg(X86_REG_RSI, ADD(x86_il_get_reg(X86_REG_RSI), UN(analysis->bits, 2)));
	add = SEQ2(add, x86_il_set_reg(X86_REG_RDI, ADD(x86_il_get_reg(X86_REG_RDI), UN(analysis->bits, 2))));
	RzILOpEffect *sub = x86_il_set_reg(X86_REG_RSI, SUB(x86_il_get_reg(X86_REG_RSI), UN(analysis->bits, 2)));
	sub = SEQ2(sub, x86_il_set_reg(X86_REG_RDI, SUB(x86_il_get_reg(X86_REG_RDI), UN(analysis->bits, 2))));

	return SEQ6(op1, op2, res, arith_flags, res_flags, BRANCH(VARG(x86_eflags_registers[X86_EFLAGS_DF]), sub, add));
}

/**
 * DAA
 * Decimal adjust AL after addition
 * 27 | Invalid | Valid
 */
static RzILOpEffect *x86_il_daa(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpEffect *old_al = SETL("old_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *old_cf = SETL("old_cf", VARG(x86_eflags_registers[X86_EFLAGS_CF]));

	RzILOpEffect *set_cf = SETL(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE);

	RzILOpBool *cond = UGT(LOGAND(x86_il_get_reg(X86_REG_AL), UN(8, 0xf)), UN(8, 9));
	cond = OR(cond, VARG(x86_eflags_registers[X86_EFLAGS_AF]));

	RzILOpEffect *set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *sum = SETL("_sum", ADD(VARL("_al"), UN(8, 6)));
	RzILOpEffect *true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));
	RzILOpPure *new_cf = OR(VARL("old_cf"), x86_il_is_sub_borrow(VARL("_sum"), VARL("_al"), UN(8, 6)));

	RzILOpEffect *ret = SEQ4(old_al, old_cf, set_cf, BRANCH(cond, SEQ3(true_cond, SETG(x86_eflags_registers[X86_EFLAGS_CF], new_cf), SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_TRUE)), SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_FALSE)));

	cond = OR(UGT(VARL("old_al"), UN(8, 0x99)), VARL("old_cf"));

	set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	sum = SETL("_sum", ADD(VARL("_al"), UN(8, 0x60)));
	true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));

	ret = SEQ3(ret, BRANCH(cond, SEQ2(true_cond, SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_TRUE)), SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE)), x86_il_set_result_flags(x86_il_get_reg(X86_REG_AL)));

	return ret;
}

/**
 * DAS
 * Decimal adjust AL after subtraction
 * 2F | Invalid | Valid
 */
static RzILOpEffect *x86_il_das(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpEffect *old_al = SETL("old_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *old_cf = SETL("old_cf", VARG(x86_eflags_registers[X86_EFLAGS_CF]));

	RzILOpEffect *set_cf = SETL(x86_eflags_registers[X86_EFLAGS_CF], IL_FALSE);

	RzILOpBool *cond = UGT(LOGAND(x86_il_get_reg(X86_REG_AL), UN(8, 0xf)), UN(8, 9));
	cond = OR(cond, VARG(x86_eflags_registers[X86_EFLAGS_AF]));

	RzILOpEffect *set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *sum = SETL("_sum", SUB(VARL("_al"), UN(8, 6)));
	RzILOpEffect *true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));
	RzILOpPure *new_cf = OR(VARL("old_cf"), x86_il_is_sub_borrow(VARL("_sum"), VARL("_al"), UN(8, 6)));

	RzILOpEffect *ret = SEQ4(old_al, old_cf, set_cf, BRANCH(cond, SEQ3(true_cond, SETG(x86_eflags_registers[X86_EFLAGS_CF], new_cf), SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_TRUE)), SETG(x86_eflags_registers[X86_EFLAGS_AF], IL_FALSE)));

	cond = OR(UGT(VARL("old_al"), UN(8, 0x99)), VARL("old_cf"));

	set_al = SETL("_al", x86_il_get_reg(X86_REG_AL));
	sum = SETL("_sum", SUB(VARL("_al"), UN(8, 0x60)));
	true_cond = SEQ3(set_al, sum, x86_il_set_reg(X86_REG_AL, VARL("_sum")));

	ret = SEQ3(ret, BRANCH(cond, SEQ2(true_cond, SETG(x86_eflags_registers[X86_EFLAGS_CF], IL_TRUE)), NOP()), x86_il_set_result_flags(x86_il_get_reg(X86_REG_AL)));

	return ret;
}

/**
 * DEC
 * Decrement by 1
 * Operand can be a memory address or a register
 */
static RzILOpEffect *x86_il_dec(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op = SETL("_op", x86_il_get_operand(ins->structure->operands[0]));
	RzILOpEffect *dec = SETL("_dec", SUB(VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1)));

	RzILOpEffect *set_result = x86_il_set_operand(ins->structure->operands[0], VARL("_dec"));
	RzILOpEffect *res_flags = x86_il_set_result_flags(VARL("_dec"));

	RzILOpEffect *of = SETG(x86_eflags_registers[X86_EFLAGS_OF], x86_il_is_sub_underflow(VARL("_dec"), VARL("_op"), UN(ins->structure->operands[0].size * BITS_PER_BYTE, 1)));
	RzILOpEffect *af = SETG(x86_eflags_registers[X86_EFLAGS_AF], x86_il_is_sub_borrow(UNSIGNED(4, VARL("_dec")), UNSIGNED(4, VARL("_op")), UN(4, 1)));

	return SEQ6(op, dec, set_result, res_flags, of, af);
}

/**
 * DIV
 * Unsigned division
 * One operand (memory address), used as the divisor
 */
static RzILOpEffect *x86_il_div(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
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
		RzILOpEffect *rdxrax = SETL("_rdxrax", LOGOR(SHIFTL0(UNSIGNED(128, x86_il_get_reg(X86_REG_EDX)), UN(8, 64)), UNSIGNED(128, x86_il_get_reg(X86_REG_EAX))));
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
	RzILOpEffect *op = SETL("_src", UNSIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_operand(ins->structure->operands[0])));

	/* Check if the operand is zero, return NULL if it is (to avoid divide by zero) */
	return SEQ2(op, BRANCH(IS_ZERO(VARL("_src")), NULL, ret));
}

// /**
//  * ESC
//  * Escape to coprocessor instruction set
//  * To be used with floating-point unit
//  */
// static RzILOpEffect *x86_il_esc(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
// 	/* Not necessary to implement for binary analysis */
// 	return EMPTY();
// }

/**
 * HLT
 * Enter HALT state
 */
static RzILOpEffect *x86_il_hlt(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	/* Not necessary to implement for binary analysis */
	return EMPTY();
}

/**
 * IDIV
 * Signed division
 * One operand (memory address), used as the divisor
 */
static RzILOpEffect *x86_il_idiv(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
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
	RzILOpEffect *op = SETL("_src", UNSIGNED(ins->structure->operands[0].size * 2 * BITS_PER_BYTE, x86_il_get_operand(ins->structure->operands[0])));

	/* Check if the operand is zero, return NULL if it is (to avoid divide by zero) */
	return SEQ2(op, BRANCH(IS_ZERO(VARL("_src")), NULL, ret));
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
	[X86_INS_DAA] = x86_il_daa,
	[X86_INS_DAS] = x86_il_das,
	[X86_INS_DEC] = x86_il_dec,
	[X86_INS_DIV] = x86_il_div,
	[X86_INS_HLT] = x86_il_hlt,
	[X86_INS_IDIV] = x86_il_idiv,
};

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI bool rz_x86_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const X86ILIns *ins) {
	rz_return_val_if_fail(analysis && aop && ins, false);
	if (ins->mnem > X86_INS_ENDING) {
		RZ_LOG_ERROR("RzIL: x86: Invalid instruction type %d", ins->mnem);
		return false;
	}

	x86_il_ins lifter = x86_ins[ins->mnem];
	RzILOpEffect *lifted = lifter(ins, pc, analysis);

	aop->il_op = lifted;
	return true;
}

RZ_IPI RzAnalysisILConfig *rz_x86_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *r = rz_analysis_il_config_new(analysis->bits, analysis->big_endian, analysis->bits);
	return r;
}
