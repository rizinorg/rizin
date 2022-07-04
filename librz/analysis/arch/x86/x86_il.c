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
	if (analysis->bits == 64 || ins->prefix[0] == X86_PREFIX_LOCK) { \
		/* #UD exception */ \
		return NULL; \
	}

/**
 * \brief X86 registers' variable names in RzIL
 */
static const char *x86_registers[] = {
	// [X86_REG_AH] = "ah",
	// [X86_REG_AL] = "al",
	// [X86_REG_AX] = "ax",
	// [X86_REG_BH] = "bh",
	// [X86_REG_BL] = "bl",
	// [X86_REG_BP] = "bp",
	// [X86_REG_BPL] = "bpl",
	// [X86_REG_BX] = "bx",
	// [X86_REG_CH] = "ch",
	// [X86_REG_CL] = "cl",
	[X86_REG_CS] = "cs",
	// [X86_REG_CX] = "cx",
	// [X86_REG_DH] = "dh",
	// [X86_REG_DI] = "di",
	// [X86_REG_DIL] = "dil",
	// [X86_REG_DL] = "dl",
	[X86_REG_DS] = "ds",
	// [X86_REG_DX] = "dx",
	// [X86_REG_EAX] = "eax",
	// [X86_REG_EBP] = "ebp",
	// [X86_REG_EBX] = "ebx",
	// [X86_REG_ECX] = "ecx",
	// [X86_REG_EDI] = "edi",
	// [X86_REG_EDX] = "edx",
	[X86_REG_EFLAGS] = "eflags",
	// [X86_REG_EIP] = "eip",
	// [X86_REG_EIZ] = "eiz",
	[X86_REG_ES] = "es",
	// [X86_REG_ESI] = "esi",
	// [X86_REG_ESP] = "esp",
	[X86_REG_FPSW] = "fpsw",
	[X86_REG_FS] = "fs",
	[X86_REG_GS] = "gs",
	// [X86_REG_IP] = "ip",
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
	// [X86_REG_SI] = "si",
	// [X86_REG_SIL] = "sil",
	// [X86_REG_SP] = "sp",
	// [X86_REG_SPL] = "spl",
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

static bool x86_il_is_gpr(X86Reg reg) {
	switch (reg) {
	case X86_REG_AH:
	case X86_REG_AL:
	case X86_REG_AX:
	case X86_REG_EAX:
	case X86_REG_RAX:
	case X86_REG_BH:
	case X86_REG_BL:
	case X86_REG_BX:
	case X86_REG_EBX:
	case X86_REG_RBX:
	case X86_REG_CH:
	case X86_REG_CL:
	case X86_REG_CX:
	case X86_REG_ECX:
	case X86_REG_RCX:
	case X86_REG_DH:
	case X86_REG_DL:
	case X86_REG_DX:
	case X86_REG_EDX:
	case X86_REG_RDX:
	case X86_REG_BPL:
	case X86_REG_BP:
	case X86_REG_EBP:
	case X86_REG_RBP:
	case X86_REG_DIL:
	case X86_REG_DI:
	case X86_REG_EDI:
	case X86_REG_RDI:
	case X86_REG_IP:
	case X86_REG_EIP:
	case X86_REG_RIP:
	case X86_REG_EIZ:
	case X86_REG_RIZ:
	case X86_REG_SIL:
	case X86_REG_SI:
	case X86_REG_ESI:
	case X86_REG_RSI:
	case X86_REG_SPL:
	case X86_REG_SP:
	case X86_REG_ESP:
	case X86_REG_RSP:
		return true;
	default:
		return false;
	}
}

static RzILOpPure *x86_il_get_gprh(X86Reg reg) {
	return UNSIGNED(8, SHIFTR0(VARG(x86_registers[reg]), U8(8)));
}
static RzILOpPure *x86_il_get_gprl(X86Reg reg) {
	return UNSIGNED(8, VARG(x86_registers[reg]));
}
static RzILOpPure *x86_il_get_gpr16(X86Reg reg) {
	return UNSIGNED(16, VARG(x86_registers[reg]));
}
static RzILOpPure *x86_il_get_gpr32(X86Reg reg) {
	return UNSIGNED(32, VARG(x86_registers[reg]));
}
static RzILOpPure *x86_il_get_gpr64(X86Reg reg) {
	return VARG(x86_registers[reg]);
}

static RzILOpEffect *x86_il_set_gprh(X86Reg reg, RzILOpPure *val) {
	RzILOpPure *mask = LOGNOT(U64(0xff00));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, SHIFTL0(UNSIGNED(64, val), U8(8)));
	return SETG(x86_registers[reg], final_reg);
}
static RzILOpEffect *x86_il_set_gprl(X86Reg reg, RzILOpPure *val) {
	RzILOpPure *mask = LOGNOT(U64(0xff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(64, val));
	return SETG(x86_registers[reg], final_reg);
}
static RzILOpEffect *x86_il_set_gpr16(X86Reg reg, RzILOpPure *val) {
	RzILOpPure *mask = LOGNOT(U64(0xffff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(64, val));
	return SETG(x86_registers[reg], final_reg);
}
static RzILOpEffect *x86_il_set_gpr32(X86Reg reg, RzILOpPure *val) {
	RzILOpPure *mask = LOGNOT(U64(0xffffffff));
	RzILOpPure *masked_reg = LOGAND(VARG(x86_registers[reg]), mask);
	RzILOpPure *final_reg = LOGOR(masked_reg, UNSIGNED(64, val));
	return SETG(x86_registers[reg], final_reg);
}
static RzILOpEffect *x86_il_set_gpr64(X86Reg reg, RzILOpPure *val) {
	return SETG(x86_registers[reg], val);
}

struct gpr_lookup_helper_t {
	X86Reg reg;
	RzILOpPure *(*get_handler)(X86Reg);
	RzILOpEffect *(*set_handler)(X86Reg, RzILOpPure *);
};

static const struct gpr_lookup_helper_t gpr_lookup_table[] = {
	[X86_REG_AH] = { X86_REG_RAX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_AL] = { X86_REG_RAX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_AX] = { X86_REG_RAX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_EAX] = { X86_REG_RAX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_RAX] = { X86_REG_RAX, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_BH] = { X86_REG_RBX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_BL] = { X86_REG_RBX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_BX] = { X86_REG_RBX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_EBX] = { X86_REG_RBX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_RBX] = { X86_REG_RBX, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_CH] = { X86_REG_RCX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_CL] = { X86_REG_RCX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_CX] = { X86_REG_RCX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_ECX] = { X86_REG_RCX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_RCX] = { X86_REG_RCX, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_DH] = { X86_REG_RDX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_DL] = { X86_REG_RDX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_DX] = { X86_REG_RDX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_EDX] = { X86_REG_RDX, x86_il_get_gprh, x86_il_set_gprh },
	[X86_REG_RDX] = { X86_REG_RDX, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_BPL] = { X86_REG_RBP, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_BP] = { X86_REG_RBP, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EBP] = { X86_REG_RBP, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RBP] = { X86_REG_RBP, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_DIL] = { X86_REG_RDI, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_DI] = { X86_REG_RDI, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EDI] = { X86_REG_RDI, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RDI] = { X86_REG_RDI, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_IP] = { X86_REG_RIP, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_EIP] = { X86_REG_RIP, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RIP] = { X86_REG_RIP, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_EIZ] = { X86_REG_RIZ, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RIZ] = { X86_REG_RIZ, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_SIL] = { X86_REG_RSI, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_SI] = { X86_REG_RSI, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_ESI] = { X86_REG_RSI, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RSI] = { X86_REG_RSI, x86_il_get_gpr64, x86_il_set_gpr64 },
	[X86_REG_SPL] = { X86_REG_RSP, x86_il_get_gprl, x86_il_set_gprl },
	[X86_REG_SP] = { X86_REG_RSP, x86_il_get_gpr16, x86_il_set_gpr16 },
	[X86_REG_ESP] = { X86_REG_RSP, x86_il_get_gpr32, x86_il_set_gpr32 },
	[X86_REG_RSP] = { X86_REG_RSP, x86_il_get_gpr64, x86_il_set_gpr64 }
};

static RzILOpPure *x86_il_get_reg(X86Reg reg) {
	if (!x86_il_is_gpr(reg)) {
		return VARG(x86_registers[reg]);
	}
	struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
	return entry.get_handler(entry.reg);
}

static RzILOpEffect *x86_il_set_reg(X86Reg reg, RzILOpPure *val) {
	if (!x86_il_is_gpr(reg)) {
		return SETG(x86_registers[reg], val);
	}
	struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
	return entry.set_handler(entry.reg, val);
}

static RzILOpPure *x86_il_get_memaddr(X86Mem mem) {
	RzILOpPure *offset = NULL;
	if (mem.base != X86_REG_INVALID) {
		if (!offset) {
			offset = x86_il_get_reg(mem.base);
		}
	}
	if (mem.index != X86_REG_INVALID) {
		if (!offset) {
			offset = MUL(x86_il_get_reg(mem.index), U64(mem.scale));
		} else {
			offset = ADD(offset, MUL(x86_il_get_reg(mem.index), U64(mem.scale)));
		}
	}
	if (!offset) {
		offset = U64(mem.disp);
	} else {
		offset = ADD(offset, U64(mem.disp));
	}

	RzILOpPure *ret = NULL;
	if (mem.segment != X86_REG_INVALID) {
		// TODO: Implement segmentation soon
		RZ_LOG_WARN("X86: RzIL: No support for segmentation\n");
	} else {
		ret = offset;
	}

	return ret;
}

static RzILOpEffect *x86_il_set_mem(X86Mem mem, RzILOpPure *val) {
	return STOREW(x86_il_get_memaddr(mem), val);
}

static RzILOpPure *x86_il_get_operand(X86Op op) {
	RzILOpPure *ret = NULL;
	switch (op.type) {
	case X86_OP_INVALID:
		RZ_LOG_ERROR("X86: RzIL: Invalid param type encountered\n");
		break;
	case X86_OP_REG:
		ret = x86_il_get_reg(op.reg);
		break;
	case X86_OP_IMM:
		ret = S64(op.imm);
		break;
	case X86_OP_MEM:
		ret = LOADW(BITS_PER_BYTE * op.size, x86_il_get_memaddr(op.mem));
	}
	return ret;
}

static RzILOpEffect *x86_il_set_operand(X86Op op, RzILOpPure *val) {
	RzILOpEffect *ret = NULL;
	switch (op.type) {
	case X86_OP_REG:
		ret = x86_il_set_reg(op.reg, val);
		break;
	case X86_OP_MEM:
		ret = x86_il_set_mem(op.mem, val);
		break;
	case X86_OP_IMM:
		RZ_LOG_ERROR("X86: RzIL: Cannot set an immediate operand\n");
	default:
		RZ_LOG_ERROR("X86: RzIL: Invalid param type encountered\n");
		break;
	}
	return ret;
}

RzILOpPure *x86_il_get_eflags(X86EFlags flag) {
	RzILOpPure *bit = SHIFTR0(x86_il_get_reg(X86_REG_EFLAGS), U8(flag));
	if (flag == X86_EFLAGS_IOPL) {
		bit = UNSIGNED(2, bit);
	} else {
		bit = UNSIGNED(1, bit);
	}
	return bit;
}

RzILOpEffect *x86_il_set_eflags(X86EFlags flag, RzILOpPure *value) {
	// set the bit in EFLAGS to zero and then LOGOR with shifted value
	RzILOpPure *shifted_one = SHIFTL0(U32(1), U8(flag));
	RzILOpPure *shifted_val = SHIFTL0(UNSIGNED(32, value), U8(flag));
	RzILOpPure *zeroed_eflag = LOGAND(x86_il_get_reg(X86_REG_EFLAGS), LOGNOT(shifted_one));
	RzILOpPure *final_eflag = LOGOR(zeroed_eflag, shifted_val);
	return x86_il_set_reg(X86_REG_EFLAGS, final_eflag);
}

static inline RzILOpBool *x86_il_is_add_carry(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
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
	RzILOpBool *xr = AND(DUP(xmsb), nres);

	// bit = xy | ry | xr
	RzILOpBool * or = OR(xy, ry);
	or = OR(or, xr);

	return NON_ZERO(or);
}

static inline RzILOpBool *x86_il_is_sub_borrow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
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
	RzILOpBool *rnx = AND(DUP(resmsb), nx);

	// bit = nxy | rny | rnx
	RzILOpBool * or = OR(nxy, rny);
	or = OR(or, rnx);

	return NON_ZERO(or);
}

static inline RzILOpBool *x86_il_is_add_overflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
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

	return NON_ZERO(or);
}

static inline RzILOpBool *x86_il_is_sub_underflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
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

	return NON_ZERO(or);
}

/**
 * \brief Invalid instruction
 */
static RzILOpEffect *x86_il_invalid(X86Ins *ins, ut64 pc, RzAnalysis *analysis) {
	return EMPTY();
}

/* 8086/8088 instructions*/

/**
 * ======== INSTRUCTION DOCUMENTATION FORMAT ========
 *
 * Instruction mnemonic
 * Description
 * | Opcode | 64-bit | Compat/Leg mode
 */

/**
 * AAA
 * ASCII adjust AL after addition
 * 37 | Invalid | Valid
 */
static RzILOpEffect *x86_il_aaa(X86Ins *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, NON_ZERO(x86_il_get_eflags(X86_EFLAGS_AF)));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, ADD(x86_il_get_reg(X86_REG_AX), U16(0x106)));
	RzILOpEffect *set_af = x86_il_set_eflags(X86_EFLAGS_AF, IL_TRUE);
	RzILOpEffect *set_cf = x86_il_set_eflags(X86_EFLAGS_CF, IL_TRUE);
	RzILOpEffect *true_cond = SEQ3(set_ax, set_af, set_cf);

	set_af = x86_il_set_eflags(X86_EFLAGS_AF, IL_FALSE);
	set_cf = x86_il_set_eflags(X86_EFLAGS_CF, IL_FALSE);
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
static RzILOpEffect *x86_il_aad(X86Ins *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *temp_ah = SETL("temp_ah", x86_il_get_reg(X86_REG_AH));
	RzILOpPure *imm = x86_il_get_operand(ins->operands[0]);

	RzILOpPure *adjusted = ADD(VARL("temp_al"), MUL(VARL("temp_ah"), imm));
	adjusted = LOGAND(adjusted, U8(0xff));

	return SEQ4(temp_al, temp_ah, x86_il_set_reg(X86_REG_AL, adjusted), x86_il_set_reg(X86_REG_AH, U8(0)));
}

/**
 * AAM  imm8
 * Adjust AX after multiply to number base imm8
 * D4 ib | Invalid | Valid
 */
static RzILOpEffect *x86_il_aam(X86Ins *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpEffect *temp_al = SETL("temp_al", x86_il_get_reg(X86_REG_AL));
	RzILOpEffect *ah = x86_il_set_reg(X86_REG_AH, DIV(VARL("temp_al"), x86_il_get_operand(ins->operands[0])));
	RzILOpEffect *al = x86_il_set_reg(X86_REG_AL, MOD(VARL("temp_al"), x86_il_get_operand(ins->operands[0])));

	return SEQ3(temp_al, ah, al);
}

/**
 * AAS
 * ASCII adjust AL after subtraction
 * 3F | Invalid | Valid
 */
static RzILOpEffect *x86_il_aas(X86Ins *ins, ut64 pc, RzAnalysis *analysis) {
	RET_NULL_IF_64BIT_OR_LOCK();

	RzILOpPure *low_al = LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f));
	RzILOpPure *al_ovf = UGT(low_al, U8(9));
	RzILOpPure *cond = OR(al_ovf, NON_ZERO(x86_il_get_eflags(X86_EFLAGS_AF)));

	RzILOpEffect *set_ax = x86_il_set_reg(X86_REG_AX, SUB(x86_il_get_reg(X86_REG_AX), U16(0x6)));
	RzILOpEffect *set_ah = x86_il_set_reg(X86_REG_AH, SUB(x86_il_get_reg(X86_REG_AH), U16(0x1)));
	RzILOpEffect *set_af = x86_il_set_eflags(X86_EFLAGS_AF, IL_TRUE);
	RzILOpEffect *set_cf = x86_il_set_eflags(X86_EFLAGS_CF, IL_TRUE);
	RzILOpEffect *true_cond = SEQ4(set_ax, set_ah, set_af, set_cf);

	set_af = x86_il_set_eflags(X86_EFLAGS_AF, IL_FALSE);
	set_cf = x86_il_set_eflags(X86_EFLAGS_CF, IL_FALSE);
	RzILOpEffect *false_cond = SEQ2(set_af, set_cf);

	RzILOpEffect *final_cond = BRANCH(cond, true_cond, false_cond);
	RzILOpEffect *set_al = x86_il_set_reg(X86_REG_AL, LOGAND(x86_il_get_reg(X86_REG_AL), U8(0x0f)));

	return SEQ2(final_cond, set_al);
}

/**
 * ADC family of instructions
 * Add with Carry
 * Possible encodings:
 *  - I
 *  - MI
 *  - MR
 *  - RM
 */
static RzILOpEffect *x86_il_adc(X86Ins *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *op1 = x86_il_get_operand(ins->operands[0]);
	RzILOpPure *op2 = x86_il_get_operand(ins->operands[1]);
	RzILOpPure *cf = x86_il_get_eflags(X86_EFLAGS_CF);

	RzILOpPure *sum = ADD(ADD(op1, op2), cf);
	RzILOpEffect *setdest = x86_il_set_operand(ins->operands[0], sum);
	RzILOpEffect *setcf = x86_il_set_eflags(X86_EFLAGS_CF, x86_il_is_add_carry(DUP(sum), DUP(op1), DUP(op2)));
	RzILOpEffect *setof = x86_il_set_eflags(X86_EFLAGS_OF, x86_il_is_add_overflow(DUP(sum), DUP(op1), DUP(op2)));

	return SEQ3(setdest, setcf, setof);
}

typedef RzILOpEffect *(*x86_il_ins)(X86Ins *, ut64, RzAnalysis *);

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
};

#include <rz_il/rz_il_opbuilder_end.h>
