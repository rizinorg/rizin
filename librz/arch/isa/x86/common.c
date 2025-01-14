// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-FileCopyrightText: 2024 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "common.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \brief x86 registers
 */
const char *x86_registers[ZYDIS_REGISTER_MAX_VALUE] = {
	[ZYDIS_REGISTER_AH] = "ah",
	[ZYDIS_REGISTER_AL] = "al",
	[ZYDIS_REGISTER_AX] = "ax",
	[ZYDIS_REGISTER_BH] = "bh",
	[ZYDIS_REGISTER_BL] = "bl",
	[ZYDIS_REGISTER_BP] = "bp",
	[ZYDIS_REGISTER_BPL] = "bpl",
	[ZYDIS_REGISTER_BX] = "bx",
	[ZYDIS_REGISTER_CH] = "ch",
	[ZYDIS_REGISTER_CL] = "cl",
	[ZYDIS_REGISTER_CS] = "cs",
	[ZYDIS_REGISTER_CX] = "cx",
	[ZYDIS_REGISTER_DH] = "dh",
	[ZYDIS_REGISTER_DI] = "di",
	[ZYDIS_REGISTER_DIL] = "dil",
	[ZYDIS_REGISTER_DL] = "dl",
	[ZYDIS_REGISTER_DS] = "ds",
	[ZYDIS_REGISTER_DX] = "dx",
	[ZYDIS_REGISTER_EAX] = "eax",
	[ZYDIS_REGISTER_EBP] = "ebp",
	[ZYDIS_REGISTER_EBX] = "ebx",
	[ZYDIS_REGISTER_ECX] = "ecx",
	[ZYDIS_REGISTER_EDI] = "edi",
	[ZYDIS_REGISTER_EDX] = "edx",
	[ZYDIS_REGISTER_EFLAGS] = "eflags",
	[ZYDIS_REGISTER_EIP] = "eip",
	//[ZYDIS_REGISTER_EIZ] = "eiz",
	[ZYDIS_REGISTER_ES] = "es",
	[ZYDIS_REGISTER_ESI] = "esi",
	[ZYDIS_REGISTER_ESP] = "esp",
	//[ZYDIS_REGISTER_X87STATUS] = "swd",
	[ZYDIS_REGISTER_FS] = "fs",
	[ZYDIS_REGISTER_GS] = "gs",
	[ZYDIS_REGISTER_IP] = "ip",
	[ZYDIS_REGISTER_RAX] = "rax",
	[ZYDIS_REGISTER_RBP] = "rbp",
	[ZYDIS_REGISTER_RBX] = "rbx",
	[ZYDIS_REGISTER_RCX] = "rcx",
	[ZYDIS_REGISTER_RDI] = "rdi",
	[ZYDIS_REGISTER_RDX] = "rdx",
	[ZYDIS_REGISTER_RIP] = "rip",
	//[ZYDIS_REGISTER_RIZ] = "riz",
	[ZYDIS_REGISTER_RSI] = "rsi",
	[ZYDIS_REGISTER_RSP] = "rsp",
	[ZYDIS_REGISTER_SI] = "si",
	[ZYDIS_REGISTER_SIL] = "sil",
	[ZYDIS_REGISTER_SP] = "sp",
	[ZYDIS_REGISTER_SPL] = "spl",
	[ZYDIS_REGISTER_SS] = "ss",
	[ZYDIS_REGISTER_CR0] = "cr0",
	[ZYDIS_REGISTER_CR1] = "cr1",
	[ZYDIS_REGISTER_CR2] = "cr2",
	[ZYDIS_REGISTER_CR3] = "cr3",
	[ZYDIS_REGISTER_CR4] = "cr4",
	[ZYDIS_REGISTER_CR5] = "cr5",
	[ZYDIS_REGISTER_CR6] = "cr6",
	[ZYDIS_REGISTER_CR7] = "cr7",
	[ZYDIS_REGISTER_CR8] = "cr8",
	[ZYDIS_REGISTER_CR9] = "cr9",
	[ZYDIS_REGISTER_CR10] = "cr10",
	[ZYDIS_REGISTER_CR11] = "cr11",
	[ZYDIS_REGISTER_CR12] = "cr12",
	[ZYDIS_REGISTER_CR13] = "cr13",
	[ZYDIS_REGISTER_CR14] = "cr14",
	[ZYDIS_REGISTER_CR15] = "cr15",
	[ZYDIS_REGISTER_DR0] = "dr0",
	[ZYDIS_REGISTER_DR1] = "dr1",
	[ZYDIS_REGISTER_DR2] = "dr2",
	[ZYDIS_REGISTER_DR3] = "dr3",
	[ZYDIS_REGISTER_DR4] = "dr4",
	[ZYDIS_REGISTER_DR5] = "dr5",
	[ZYDIS_REGISTER_DR6] = "dr6",
	[ZYDIS_REGISTER_DR7] = "dr7",
	[ZYDIS_REGISTER_DR8] = "dr8",
	[ZYDIS_REGISTER_DR9] = "dr9",
	[ZYDIS_REGISTER_DR10] = "dr10",
	[ZYDIS_REGISTER_DR11] = "dr11",
	[ZYDIS_REGISTER_DR12] = "dr12",
	[ZYDIS_REGISTER_DR13] = "dr13",
	[ZYDIS_REGISTER_DR14] = "dr14",
	[ZYDIS_REGISTER_DR15] = "dr15",
	//[ZYDIS_REGISTER_FP0] = "fp0",
	//[ZYDIS_REGISTER_FP1] = "fp1",
	//[ZYDIS_REGISTER_FP2] = "fp2",
	//[ZYDIS_REGISTER_FP3] = "fp3",
	//[ZYDIS_REGISTER_FP4] = "fp4",
	//[ZYDIS_REGISTER_FP5] = "fp5",
	//[ZYDIS_REGISTER_FP6] = "fp6",
	//[ZYDIS_REGISTER_FP7] = "fp7",
	[ZYDIS_REGISTER_K0] = "k0",
	[ZYDIS_REGISTER_K1] = "k1",
	[ZYDIS_REGISTER_K2] = "k2",
	[ZYDIS_REGISTER_K3] = "k3",
	[ZYDIS_REGISTER_K4] = "k4",
	[ZYDIS_REGISTER_K5] = "k5",
	[ZYDIS_REGISTER_K6] = "k6",
	[ZYDIS_REGISTER_K7] = "k7",
	[ZYDIS_REGISTER_MM0] = "mm0",
	[ZYDIS_REGISTER_MM1] = "mm1",
	[ZYDIS_REGISTER_MM2] = "mm2",
	[ZYDIS_REGISTER_MM3] = "mm3",
	[ZYDIS_REGISTER_MM4] = "mm4",
	[ZYDIS_REGISTER_MM5] = "mm5",
	[ZYDIS_REGISTER_MM6] = "mm6",
	[ZYDIS_REGISTER_MM7] = "mm7",
	[ZYDIS_REGISTER_R8] = "r8",
	[ZYDIS_REGISTER_R9] = "r9",
	[ZYDIS_REGISTER_R10] = "r10",
	[ZYDIS_REGISTER_R11] = "r11",
	[ZYDIS_REGISTER_R12] = "r12",
	[ZYDIS_REGISTER_R13] = "r13",
	[ZYDIS_REGISTER_R14] = "r14",
	[ZYDIS_REGISTER_R15] = "r15",
	[ZYDIS_REGISTER_ST0] = "st0",
	[ZYDIS_REGISTER_ST1] = "st1",
	[ZYDIS_REGISTER_ST2] = "st2",
	[ZYDIS_REGISTER_ST3] = "st3",
	[ZYDIS_REGISTER_ST4] = "st4",
	[ZYDIS_REGISTER_ST5] = "st5",
	[ZYDIS_REGISTER_ST6] = "st6",
	[ZYDIS_REGISTER_ST7] = "st7",
	[ZYDIS_REGISTER_XMM0] = "xmm0",
	[ZYDIS_REGISTER_XMM1] = "xmm1",
	[ZYDIS_REGISTER_XMM2] = "xmm2",
	[ZYDIS_REGISTER_XMM3] = "xmm3",
	[ZYDIS_REGISTER_XMM4] = "xmm4",
	[ZYDIS_REGISTER_XMM5] = "xmm5",
	[ZYDIS_REGISTER_XMM6] = "xmm6",
	[ZYDIS_REGISTER_XMM7] = "xmm7",
	[ZYDIS_REGISTER_XMM8] = "xmm8",
	[ZYDIS_REGISTER_XMM9] = "xmm9",
	[ZYDIS_REGISTER_XMM10] = "xmm10",
	[ZYDIS_REGISTER_XMM11] = "xmm11",
	[ZYDIS_REGISTER_XMM12] = "xmm12",
	[ZYDIS_REGISTER_XMM13] = "xmm13",
	[ZYDIS_REGISTER_XMM14] = "xmm14",
	[ZYDIS_REGISTER_XMM15] = "xmm15",
	[ZYDIS_REGISTER_XMM16] = "xmm16",
	[ZYDIS_REGISTER_XMM17] = "xmm17",
	[ZYDIS_REGISTER_XMM18] = "xmm18",
	[ZYDIS_REGISTER_XMM19] = "xmm19",
	[ZYDIS_REGISTER_XMM20] = "xmm20",
	[ZYDIS_REGISTER_XMM21] = "xmm21",
	[ZYDIS_REGISTER_XMM22] = "xmm22",
	[ZYDIS_REGISTER_XMM23] = "xmm23",
	[ZYDIS_REGISTER_XMM24] = "xmm24",
	[ZYDIS_REGISTER_XMM25] = "xmm25",
	[ZYDIS_REGISTER_XMM26] = "xmm26",
	[ZYDIS_REGISTER_XMM27] = "xmm27",
	[ZYDIS_REGISTER_XMM28] = "xmm28",
	[ZYDIS_REGISTER_XMM29] = "xmm29",
	[ZYDIS_REGISTER_XMM30] = "xmm30",
	[ZYDIS_REGISTER_XMM31] = "xmm31",
	[ZYDIS_REGISTER_YMM0] = "ymm0",
	[ZYDIS_REGISTER_YMM1] = "ymm1",
	[ZYDIS_REGISTER_YMM2] = "ymm2",
	[ZYDIS_REGISTER_YMM3] = "ymm3",
	[ZYDIS_REGISTER_YMM4] = "ymm4",
	[ZYDIS_REGISTER_YMM5] = "ymm5",
	[ZYDIS_REGISTER_YMM6] = "ymm6",
	[ZYDIS_REGISTER_YMM7] = "ymm7",
	[ZYDIS_REGISTER_YMM8] = "ymm8",
	[ZYDIS_REGISTER_YMM9] = "ymm9",
	[ZYDIS_REGISTER_YMM10] = "ymm10",
	[ZYDIS_REGISTER_YMM11] = "ymm11",
	[ZYDIS_REGISTER_YMM12] = "ymm12",
	[ZYDIS_REGISTER_YMM13] = "ymm13",
	[ZYDIS_REGISTER_YMM14] = "ymm14",
	[ZYDIS_REGISTER_YMM15] = "ymm15",
	[ZYDIS_REGISTER_YMM16] = "ymm16",
	[ZYDIS_REGISTER_YMM17] = "ymm17",
	[ZYDIS_REGISTER_YMM18] = "ymm18",
	[ZYDIS_REGISTER_YMM19] = "ymm19",
	[ZYDIS_REGISTER_YMM20] = "ymm20",
	[ZYDIS_REGISTER_YMM21] = "ymm21",
	[ZYDIS_REGISTER_YMM22] = "ymm22",
	[ZYDIS_REGISTER_YMM23] = "ymm23",
	[ZYDIS_REGISTER_YMM24] = "ymm24",
	[ZYDIS_REGISTER_YMM25] = "ymm25",
	[ZYDIS_REGISTER_YMM26] = "ymm26",
	[ZYDIS_REGISTER_YMM27] = "ymm27",
	[ZYDIS_REGISTER_YMM28] = "ymm28",
	[ZYDIS_REGISTER_YMM29] = "ymm29",
	[ZYDIS_REGISTER_YMM30] = "ymm30",
	[ZYDIS_REGISTER_YMM31] = "ymm31",
	[ZYDIS_REGISTER_ZMM0] = "zmm0",
	[ZYDIS_REGISTER_ZMM1] = "zmm1",
	[ZYDIS_REGISTER_ZMM2] = "zmm2",
	[ZYDIS_REGISTER_ZMM3] = "zmm3",
	[ZYDIS_REGISTER_ZMM4] = "zmm4",
	[ZYDIS_REGISTER_ZMM5] = "zmm5",
	[ZYDIS_REGISTER_ZMM6] = "zmm6",
	[ZYDIS_REGISTER_ZMM7] = "zmm7",
	[ZYDIS_REGISTER_ZMM8] = "zmm8",
	[ZYDIS_REGISTER_ZMM9] = "zmm9",
	[ZYDIS_REGISTER_ZMM10] = "zmm10",
	[ZYDIS_REGISTER_ZMM11] = "zmm11",
	[ZYDIS_REGISTER_ZMM12] = "zmm12",
	[ZYDIS_REGISTER_ZMM13] = "zmm13",
	[ZYDIS_REGISTER_ZMM14] = "zmm14",
	[ZYDIS_REGISTER_ZMM15] = "zmm15",
	[ZYDIS_REGISTER_ZMM16] = "zmm16",
	[ZYDIS_REGISTER_ZMM17] = "zmm17",
	[ZYDIS_REGISTER_ZMM18] = "zmm18",
	[ZYDIS_REGISTER_ZMM19] = "zmm19",
	[ZYDIS_REGISTER_ZMM20] = "zmm20",
	[ZYDIS_REGISTER_ZMM21] = "zmm21",
	[ZYDIS_REGISTER_ZMM22] = "zmm22",
	[ZYDIS_REGISTER_ZMM23] = "zmm23",
	[ZYDIS_REGISTER_ZMM24] = "zmm24",
	[ZYDIS_REGISTER_ZMM25] = "zmm25",
	[ZYDIS_REGISTER_ZMM26] = "zmm26",
	[ZYDIS_REGISTER_ZMM27] = "zmm27",
	[ZYDIS_REGISTER_ZMM28] = "zmm28",
	[ZYDIS_REGISTER_ZMM29] = "zmm29",
	[ZYDIS_REGISTER_ZMM30] = "zmm30",
	[ZYDIS_REGISTER_ZMM31] = "zmm31",
	[ZYDIS_REGISTER_R8B] = "r8b",
	[ZYDIS_REGISTER_R9B] = "r9b",
	[ZYDIS_REGISTER_R10B] = "r10b",
	[ZYDIS_REGISTER_R11B] = "r11b",
	[ZYDIS_REGISTER_R12B] = "r12b",
	[ZYDIS_REGISTER_R13B] = "r13b",
	[ZYDIS_REGISTER_R14B] = "r14b",
	[ZYDIS_REGISTER_R15B] = "r15b",
	[ZYDIS_REGISTER_R8D] = "r8d",
	[ZYDIS_REGISTER_R9D] = "r9d",
	[ZYDIS_REGISTER_R10D] = "r10d",
	[ZYDIS_REGISTER_R11D] = "r11d",
	[ZYDIS_REGISTER_R12D] = "r12d",
	[ZYDIS_REGISTER_R13D] = "r13d",
	[ZYDIS_REGISTER_R14D] = "r14d",
	[ZYDIS_REGISTER_R15D] = "r15d",
	[ZYDIS_REGISTER_R8W] = "r8w",
	[ZYDIS_REGISTER_R9W] = "r9w",
	[ZYDIS_REGISTER_R10W] = "r10w",
	[ZYDIS_REGISTER_R11W] = "r11w",
	[ZYDIS_REGISTER_R12W] = "r12w",
	[ZYDIS_REGISTER_R13W] = "r13w",
	[ZYDIS_REGISTER_R14W] = "r14w",
	[ZYDIS_REGISTER_R15W] = "r15w"
};

const char *x86_eflags_registers[X86_EFLAGS_ENDING] = {
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

const X86Reg gpr_hregs[] = {
	ZYDIS_REGISTER_AH, // rax
	ZYDIS_REGISTER_BH, // rbx
	ZYDIS_REGISTER_CH, // rcx
	ZYDIS_REGISTER_DH, // rdx
	ZYDIS_REGISTER_NONE, // rbp
	ZYDIS_REGISTER_NONE, // rdi
	ZYDIS_REGISTER_NONE, // rip
	ZYDIS_REGISTER_NONE, // riz
	ZYDIS_REGISTER_NONE, // rsi
	ZYDIS_REGISTER_NONE // rsp
};

const X86Reg gpr_lregs[] = {
	ZYDIS_REGISTER_AL, // rax
	ZYDIS_REGISTER_BL, // rbx
	ZYDIS_REGISTER_CL, // rcx
	ZYDIS_REGISTER_DL, // rdx
	ZYDIS_REGISTER_BPL, // rbp
	ZYDIS_REGISTER_DIL, // rdi
	ZYDIS_REGISTER_NONE, // rip
	ZYDIS_REGISTER_NONE, // riz
	ZYDIS_REGISTER_SIL, // rsi
	ZYDIS_REGISTER_SPL, // rsp
};

const X86Reg gpr_xregs[] = {
	ZYDIS_REGISTER_AX, // rax
	ZYDIS_REGISTER_BX, // rbx
	ZYDIS_REGISTER_CX, // rcx
	ZYDIS_REGISTER_DX, // rdx
	ZYDIS_REGISTER_BP, // rbp
	ZYDIS_REGISTER_DI, // rdi
	ZYDIS_REGISTER_IP, // rip
	ZYDIS_REGISTER_NONE, // riz
	ZYDIS_REGISTER_SI, // rsi
	ZYDIS_REGISTER_SP, // rsp
};

const X86Reg gpr_eregs[] = {
	ZYDIS_REGISTER_EAX, // rax
	ZYDIS_REGISTER_EBX, // rbx
	ZYDIS_REGISTER_ECX, // rcx
	ZYDIS_REGISTER_EDX, // rdx
	ZYDIS_REGISTER_EBP, // rbp
	ZYDIS_REGISTER_EDI, // rdi
	ZYDIS_REGISTER_EIP, // rip
	0,
	// ZYDIS_REGISTER_EIZ, // riz
	ZYDIS_REGISTER_ESI, // rsi
	ZYDIS_REGISTER_ESP, // rsp
};

const X86Reg gpr_rregs[] = {
	ZYDIS_REGISTER_RAX,
	ZYDIS_REGISTER_RBX,
	ZYDIS_REGISTER_RCX,
	ZYDIS_REGISTER_RDX,
	ZYDIS_REGISTER_RBP,
	ZYDIS_REGISTER_RDI,
	ZYDIS_REGISTER_RIP,
	0,
	// ZYDIS_REGISTER_RIZ,
	ZYDIS_REGISTER_RSI,
	ZYDIS_REGISTER_RSP
};

/**
 * \brief Check if \p reg is a general purpose register (this term is quite loosely used here)
 *
 * \param reg
 */
bool x86_il_is_gpr(X86Reg reg) {
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
ut8 x86_il_get_reg_size(X86Reg reg) {
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
RzILOpPure *x86_il_get_gprh(X86Reg reg, int bits) {
	return UNSIGNED(8, SHIFTR0(VARG(x86_registers[reg]), U8(8)));
}
/**
 * \brief Get the lower 8 bits (0-8) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
RzILOpPure *x86_il_get_gprl(X86Reg reg, int bits) {
	return UNSIGNED(8, VARG(x86_registers[reg]));
}
/**
 * \brief Get the lower 16 bits (0-16) of register \p reg
 *
 * \param reg
 * \param bits bitness
 */
RzILOpPure *x86_il_get_gpr16(X86Reg reg, int bits) {
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
RzILOpPure *x86_il_get_gpr32(X86Reg reg, int bits) {
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
RzILOpPure *x86_il_get_gpr64(X86Reg reg, int bits) {
	return VARG(x86_registers[reg]);
}

/**
 * \brief  Set the higher 8 bits (8-16) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
RzILOpEffect *x86_il_set_gprh(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
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
RzILOpEffect *x86_il_set_gprl(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
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
RzILOpEffect *x86_il_set_gpr16(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
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
 * \brief  Set the lower 32 bits (0-32) of register \p reg to \p val, and zero out the rest
 * This is a very specific behavior of x86-64, see https://stackoverflow.com/questions/11177137/why-do-x86-64-instructions-on-32-bit-registers-zero-the-upper-part-of-the-full-6 for details
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
RzILOpEffect *x86_il_set_gpr32(X86Reg reg, RZ_OWN RzILOpPure *val, int bits) {
	if (bits == 32) {
		return SETG(x86_registers[reg], val);
	}

	return SETG(x86_registers[reg], UNSIGNED(64, val));
}
/**
 * \brief  Set 64 bits (0-64) of register \p reg to \p val
 *
 * \param reg
 * \param val
 * \param bits bitness
 */
RzILOpEffect *x86_il_set_gpr64(X86Reg reg, RzILOpPure *val, int bits) {
	return SETG(x86_registers[reg], val);
}

/**
 * \brief Get the widest register corresponding to index \p index and bitness \p bits
 *
 * \param index
 * \param bits
 */
X86Reg get_bitness_reg(unsigned int index, int bits) {
	if (index >= GPR_FAMILY_COUNT) {
		return ZYDIS_REGISTER_NONE;
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

const struct gpr_lookup_helper_t gpr_lookup_table[] = {
	[ZYDIS_REGISTER_AH] = { 0, x86_il_get_gprh, x86_il_set_gprh },
	[ZYDIS_REGISTER_AL] = { 0, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_AX] = { 0, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_EAX] = { 0, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RAX] = { 0, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_BH] = { 1, x86_il_get_gprh, x86_il_set_gprh },
	[ZYDIS_REGISTER_BL] = { 1, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_BX] = { 1, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_EBX] = { 1, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RBX] = { 1, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_CH] = { 2, x86_il_get_gprh, x86_il_set_gprh },
	[ZYDIS_REGISTER_CL] = { 2, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_CX] = { 2, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_ECX] = { 2, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RCX] = { 2, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_DH] = { 3, x86_il_get_gprh, x86_il_set_gprh },
	[ZYDIS_REGISTER_DL] = { 3, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_DX] = { 3, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_EDX] = { 3, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RDX] = { 3, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_BPL] = { 4, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_BP] = { 4, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_EBP] = { 4, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RBP] = { 4, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_DIL] = { 5, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_DI] = { 5, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_EDI] = { 5, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RDI] = { 5, x86_il_get_gpr64, x86_il_set_gpr64 },
	//[ZYDIS_REGISTER_EIZ] = { 7, x86_il_get_gpr32, x86_il_set_gpr32 },
	//[ZYDIS_REGISTER_RIZ] = { 7, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_SIL] = { 8, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_SI] = { 8, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_ESI] = { 8, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RSI] = { 8, x86_il_get_gpr64, x86_il_set_gpr64 },
	[ZYDIS_REGISTER_SPL] = { 9, x86_il_get_gprl, x86_il_set_gprl },
	[ZYDIS_REGISTER_SP] = { 9, x86_il_get_gpr16, x86_il_set_gpr16 },
	[ZYDIS_REGISTER_ESP] = { 9, x86_il_get_gpr32, x86_il_set_gpr32 },
	[ZYDIS_REGISTER_RSP] = { 9, x86_il_get_gpr64, x86_il_set_gpr64 }
};

/**
 * \brief Check if the register \p reg is an instruction pointer register
 *
 * \param reg
 */
bool is_pc_reg(X86Reg reg) {
	return (reg == ZYDIS_REGISTER_IP || reg == ZYDIS_REGISTER_EIP || reg == ZYDIS_REGISTER_RIP);
}

struct extreg_lookup_helper_t {
	X86Reg curr_reg; ///< register being used
	X86Reg base_reg; ///< base register for `curr_reg`
	RzILOpPure *(*get_handler)(X86Reg, int); ///< getter
	RzILOpEffect *(*set_handler)(X86Reg, RzILOpPure *, int); ///< setter
};

const struct extreg_lookup_helper_t extreg_lookup_table[] = {
	// 64-bit wide
	extreg_lookup(, x86_il_get_gpr64, x86_il_set_gpr64)

	// 8-bit wide (byte)
	extreg_lookup(B, x86_il_get_gprl, x86_il_set_gpr64)

	// 16-bit wide (word)
	extreg_lookup(W, x86_il_get_gpr16, x86_il_set_gpr64)

	// 32-bit wide (dword)
	extreg_lookup(D, x86_il_get_gpr32, x86_il_set_gpr64)
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
RZ_IPI RzILOpPure *x86_il_get_reg_bits(X86Reg reg, int bits, uint64_t pc) {
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
RZ_IPI RzILOpEffect *x86_il_set_reg_bits(X86Reg reg, RZ_OWN RZ_NONNULL RzILOpPure *val, int bits) {
	rz_return_val_if_fail(val, NULL);
	int ind = -1;

	if (x86_il_is_gpr(reg)) {
		struct gpr_lookup_helper_t entry = gpr_lookup_table[reg];
		return entry.set_handler(get_bitness_reg(entry.index, bits), val, bits);
	} else if ((ind = get_extreg_ind(reg)) != -1 && bits == 64) {
		struct extreg_lookup_helper_t entry = extreg_lookup_table[ind];
		return entry.set_handler(entry.base_reg, UNSIGNED(64, val), bits);
	}

	return SETG(x86_registers[reg], val);
}

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
RZ_IPI RzILOpPure *x86_il_get_memaddr_segment_bits(X86Mem mem, X86Reg segment, int bits, ut64 pc) {
	RzILOpPure *offset = NULL;
	if (mem.base != ZYDIS_REGISTER_NONE) {
		offset = x86_il_get_reg_bits(mem.base, bits, pc);
		if (x86_il_get_reg_size(mem.base) != bits) {
			offset = UNSIGNED(bits, offset);
		}
	}
	if (mem.index != ZYDIS_REGISTER_NONE) {
		RzILOpPure *reg = x86_il_get_reg_bits(mem.index, bits, pc);
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
		offset = UN(bits, mem.disp.value);
	} else {
		offset = ADD(offset, UN(bits, mem.disp.value));
	}

	/* Segmentation not present in x86-64 */
	if (bits != 64 && segment != ZYDIS_REGISTER_NONE) {
		// TODO: Implement segmentation
		/* Currently the segmentation is only implemented for real mode
		 Address = Segment * 0x10 + Offset */

		/* Assuming real mode */
		offset = ADD(offset, SHIFTL0(UNSIGNED(bits, x86_il_get_reg_bits(segment, bits, pc)), U8(4)));
	}

	return offset;
}

RZ_IPI RzILOpPure *x86_il_get_memaddr_bits(X86Mem mem, int bits, ut64 pc) {
	return x86_il_get_memaddr_segment_bits(mem, mem.segment, bits, pc);
}

RZ_IPI RzILOpEffect *x86_il_set_mem_bits(X86Mem mem, RZ_OWN RZ_NONNULL RzILOpPure *val, int bits, ut64 pc) {
	rz_return_val_if_fail(val, NULL);
	return STOREW(x86_il_get_memaddr_bits(mem, bits, pc), val);
}

/**
 * \brief Get the value of the operand \p op
 * This function takes care of everything, like choosing
 * the correct type and returning the correct value
 * Use the wrapper `x86_il_get_op`
 *
 * \param op
 * \param analysis_bits bitness
 */
RZ_IPI RzILOpPure *x86_il_get_operand_bits(X86Op op, int analysis_bits, ut64 pc, int implicit_size, const X86ILIns *ins) {
	switch (op.type) {
	// case X86_OP_INVALID:
	//	if (implicit_size) {
	//		return SN(implicit_size * BITS_PER_BYTE, 1);
	//	}
	//	RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered\n");
	//	return NULL;
	case ZYDIS_OPERAND_TYPE_REGISTER:
		return x86_il_get_reg_bits(op.reg.value, analysis_bits, pc);
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		/* Immediate values are always sign extended */
		return SN((op.size != 0 ? op.size : implicit_size) * BITS_PER_BYTE, imm_value(op, pc));
	case ZYDIS_OPERAND_TYPE_MEMORY:
		return LOADW((op.size != 0 ? op.size : implicit_size) * BITS_PER_BYTE, x86_il_get_memaddr_bits(op.mem, analysis_bits, pc));
	default:
		return NULL;
	}
}

/**
 * \brief Get the value of the operand \p op
 * This function takes care of everything, like choosing
 * the correct type and setting the correct value
 * Use the wrapper `x86_il_set_op`
 *
 * \param op
 * \param analysis_bits bitness
 */
RZ_IPI RzILOpEffect *x86_il_set_operand_bits(X86Op op, RZ_OWN RZ_NONNULL RzILOpPure *val, int bits, ut64 pc) {
	rz_return_val_if_fail(val, NULL);

	RzILOpEffect *ret = NULL;
	switch (op.type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		ret = x86_il_set_reg_bits(op.reg.value, val, bits);
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		ret = x86_il_set_mem_bits(op.mem, val, bits, pc);
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		RZ_LOG_ERROR("x86: RzIL: Cannot set an immediate operand\n");
		break;
	default:
		RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered\n");
		break;
	}
	return ret;
}

/**
 * \brief Return the carry bit when \p x and \p y are added, with result \p res
 *
 * \param res
 * \param x
 * \param y
 */
RZ_IPI RzILOpBool *x86_il_is_add_carry(RZ_OWN RZ_NONNULL RzILOpPure *res, RZ_OWN RZ_NONNULL RzILOpPure *x, RZ_OWN RZ_NONNULL RzILOpPure *y) {
	rz_return_val_if_fail(res && x && y, NULL);

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
RZ_IPI RzILOpBool *x86_il_is_sub_borrow(RZ_OWN RZ_NONNULL RzILOpPure *res, RZ_OWN RZ_NONNULL RzILOpPure *x, RZ_OWN RZ_NONNULL RzILOpPure *y) {
	rz_return_val_if_fail(res && x && y, NULL);

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
RZ_IPI RzILOpBool *x86_il_is_add_overflow(RZ_OWN RZ_NONNULL RzILOpPure *res, RZ_OWN RZ_NONNULL RzILOpPure *x, RZ_OWN RZ_NONNULL RzILOpPure *y) {
	rz_return_val_if_fail(res && x && y, NULL);

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
RZ_IPI RzILOpBool *x86_il_is_sub_underflow(RZ_OWN RZ_NONNULL RzILOpPure *res, RZ_OWN RZ_NONNULL RzILOpPure *x, RZ_OWN RZ_NONNULL RzILOpPure *y) {
	rz_return_val_if_fail(res && x && y, NULL);

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
 * \brief Find the parity of lower 8 bits of \p val
 *
 * \param val
 */
RzILOpBool *x86_il_get_parity(RZ_OWN RzILOpPure *val) {
	// assumed that val is an 8-bit wide value

	// A parity calculation can be reduced to nested shift-right and xor operations.
	// see https://github.com/BinaryAnalysisPlatform/bap/blob/master/plugins/x86/x86_lifter.ml#L215
	RzILOpPure *accumulate = LET("_val", val,
		LET("_c4", LOGXOR(VARLP("_val"), SHIFTR0(VARLP("_val"), U8(4))),
			LET("_c2", LOGXOR(VARLP("_c4"), SHIFTR0(VARLP("_c4"), U8(2))),
				LOGXOR(VARLP("_c2"), SHIFTR0(VARLP("_c2"), U8(1))))));
	return INV(LSB(accumulate));
}

/**
 * \brief Sets the value of PF, ZF, SF according to the \p result
 */
RZ_IPI RzILOpEffect *x86_il_set_result_flags_bits(RZ_OWN RZ_NONNULL RzILOpPure *result, int bits) {
	rz_return_val_if_fail(result, NULL);

	RzILOpEffect *set = SETL("_result", result);
	RzILOpBool *pf = x86_il_get_parity(UNSIGNED(8, VARL("_result")));
	RzILOpBool *zf = IS_ZERO(VARL("_result"));
	RzILOpBool *sf = MSB(VARL("_result"));

	return SEQ4(set,
		SETG(EFLAGS(PF), pf),
		SETG(EFLAGS(ZF), zf),
		SETG(EFLAGS(SF), sf));
}

/**
 * \brief Sets the value of CF, OF, AF according to the \p res
 */
RZ_IPI RzILOpEffect *x86_il_set_arithmetic_flags_bits(RZ_OWN RZ_NONNULL RzILOpPure *res, RZ_OWN RZ_NONNULL RzILOpPure *x, RZ_OWN RZ_NONNULL RzILOpPure *y, bool addition, int bits) {
	rz_return_val_if_fail(res && x && y, NULL);

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
RZ_IPI RzILOpEffect *x86_il_set_arithmetic_flags_except_cf_bits(RZ_OWN RZ_NONNULL RzILOpPure *res, RZ_OWN RZ_NONNULL RzILOpPure *x, RZ_OWN RZ_NONNULL RzILOpPure *y, bool addition, int bits) {
	rz_return_val_if_fail(res && x && y, NULL);

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

/**
 * \brief Get value of FLAGS register
 *
 * \param size size of flags needed
 */
RZ_IPI RzILOpPure *x86_il_get_flags(unsigned int size) {
	/* We really don't care about bits higher than 16 for now */
	RzILOpPure *val;
	if (size == 8) {
		goto lower_half;
	}

	/* Bit 15: Reserved,
	always 1 on 8086 and 186,
	always 0 on later models
	Assuming 0 */
	val = BOOL_TO_BV(IL_FALSE, size);
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(NT)), size));

	/** Bit 12-13: IOPL,
	I/O privilege level (286+ only),
	always 1 on 8086 and 186
	Assuming all 1 */
	val = LOGOR(SHIFTL0(val, UN(size, 2)), UN(size, 0x3));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(OF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(DF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(IF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(TF)), size));

lower_half:
	if (size == 8) {
		val = BOOL_TO_BV(VARG(EFLAGS(SF)), size);
	} else {
		val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(ZF)), size));
	}
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(ZF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 2)), BOOL_TO_BV(VARG(EFLAGS(AF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 2)), BOOL_TO_BV(VARG(EFLAGS(PF)), size));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), UN(size, 1));
	val = LOGOR(SHIFTL0(val, UN(size, 1)), BOOL_TO_BV(VARG(EFLAGS(CF)), size));

	return val;
}

/**
 * \brief Set the value of flags register
 *
 * \param val value to set the FLAGS register to
 * \param size size of \p val
 */
RZ_IPI RzILOpEffect *x86_il_set_flags(RZ_OWN RZ_NONNULL RzILOpPure *val, unsigned int size) {
	rz_return_val_if_fail(val, NULL);

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
 * \brief Check whether \p reg is an FPU stack register (ST0 - ST7)
 *
 * \param reg
 */
RZ_IPI bool x86_il_is_st_reg(X86Reg reg) {
	return reg >= ZYDIS_REGISTER_ST0 && reg <= ZYDIS_REGISTER_ST7;
}

/**
 * \brief Get the 11th and 12th bit which stores the rounding mode from the FPU
 * control word
 *
 * \return RzILOpPure* 2 bit rounding mode
 */
RZ_IPI RzILOpPure *x86_il_fpu_get_rmode() {
	return UNSIGNED(2, SHIFTR0(VARG(ZYDIS_REGISTER_FPU_CW), UN(8, 10)));
}

/**
 * \brief Get the float stored in FPU stack \p reg
 *
 * \param reg
 * \return RzILOpFloat* IEEE754 80 bit float
 */
RZ_IPI RzILOpFloat *x86_il_get_st_reg(X86Reg reg) {
	rz_return_val_if_fail(x86_il_is_st_reg(reg), NULL);
	return BV2F(RZ_FLOAT_IEEE754_BIN_80, VARG(x86_registers[reg]));
}

/**
 * \brief Set the local variable to the value of "_rmode" computed using control
 * word bits
 *
 * \return RzILOpEffect*
 */
RZ_IPI RzILOpEffect *init_rmode() {
	return SETL("_rmode", x86_il_fpu_get_rmode());
}

/**
 * \brief Execute the function \p f with the correct op mode argument
 *
 * \param f function which takes in the rounding mode as the first argument
 *
 * 0 -> RNE
 * 1 -> RTN
 * 2 -> RTP
 * 3 -> RTZ
 *
 * I hate this, but this is the only way to conditionally use the correct rmode.
 */
#define EXEC_WITH_RMODE(f, ...) \
	ITE(EQ(VARL("_rmode"), UN(2, 0)), f(RZ_FLOAT_RMODE_RNE, __VA_ARGS__), \
		ITE(EQ(VARL("_rmode"), UN(2, 1)), f(RZ_FLOAT_RMODE_RTN, __VA_ARGS__), \
			ITE(EQ(VARL("_rmode"), UN(2, 2)), f(RZ_FLOAT_RMODE_RTP, __VA_ARGS__), \
				f(RZ_FLOAT_RMODE_RTZ, __VA_ARGS__))))

RzILOpFloat *resize_floating_helper(RzFloatRMode rmode, RzFloatFormat format, RzILOpFloat *val) {
	return FCONVERT(format, rmode, val);
}

/**
 * \brief Resize the float \p val to \p width
 * You need to have initialized a local variable "_rmode" set with the rounding
 * mode before you call this function.
 *
 * \param val Desirable that it is a small expression since it will be duped
 * \param format Output float format
 * \param ctx use_rmode gets set to true
 * \return RzILOpFloat*
 */
RZ_IPI ILPureEffectPair x86_il_resize_floating_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *val, RzFloatFormat format, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(val && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SETL("f_val_rm", val);
	ret.val = EXEC_WITH_RMODE(resize_floating_helper, format, VARL("f_val_rm"));

	return ret;
}

RzILOpFloat *sint2f_floating_helper(RzFloatRMode rmode, RzFloatFormat format, RzILOpBitVector *val) {
	return SINT2F(format, rmode, val);
}

/**
 * \brief Convert the integer \p int_val to a RzILOpFloat of format \p fmt
 * You need to have initialized a local variable "_rmode" set with the rounding
 * mode before you call this function.
 *
 * \param int_val Desirable that it is a small expression since it will be duped
 * \param format Output float format
 * \param ctx use_rmode gets set to true
 * \return RzILOpFloat*
 */
RZ_IPI ILPureEffectPair x86_il_floating_from_int_ctx(RZ_OWN RZ_NONNULL RzILOpBitVector *int_val, RzFloatFormat format, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(int_val && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SETL("i_val_rm", int_val);
	ret.val = EXEC_WITH_RMODE(sint2f_floating_helper, format, VARL("i_val_rm"));

	return ret;
}

RzILOpFloat *f2sint_floating_helper(RzFloatRMode rmode, ut32 width, RzILOpFloat *val) {
	return F2SINT(width, rmode, val);
}

/**
 * \brief Convert the floating \p float_val to a RzILOpBitVector of size \p width
 * You need to have initialized a local variable "_rmode" set with the rounding
 * mode before you call this function.
 *
 * \param float_val Desirable that it is a small expression since it will be duped
 * \param width Output bitvector width
 * \param ctx use_rmode gets set to true
 * \return RzILOpBitVector*
 */
RZ_IPI ILPureEffectPair x86_il_int_from_floating_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *float_val, ut32 width, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(float_val && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SETL("f_val_rm", float_val);
	ret.val = EXEC_WITH_RMODE(f2sint_floating_helper, width, VARL("f_val_rm"));

	return ret;
}

/**
 * \brief Add \p x and \p y with the correct rounding mode as determined from
 * the FPU control word
 *
 * \param x Desirable that it is a small expression since it will be duped
 * \param y Desirable that it is a small expression since it will be duped
 * \param ctx use_rmode gets set to true
 * \return RzILOpFloat* sum
 */
RZ_IPI ILPureEffectPair x86_il_fadd_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_OWN RZ_NONNULL RzILOpFloat *y, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(x && y && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SEQ2(SETL("x_rm", x), SETL("y_rm", y));
	ret.val = EXEC_WITH_RMODE(FADD, VARL("x_rm"), VARL("y_rm"));

	return ret;
}

/**
 * \brief Multiply \p x and \p y with the correct rounding mode as determined
 * from the FPU control word
 *
 * \param x Desirable that it is a small expression since it will be duped
 * \param y Desirable that it is a small expression since it will be duped
 * \param ctx use_rmode gets set to true
 * \return RzILOpFloat* product
 */
RZ_IPI ILPureEffectPair x86_il_fmul_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_OWN RZ_NONNULL RzILOpFloat *y, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(x && y && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SEQ2(SETL("x_rm", x), SETL("y_rm", y));
	ret.val = EXEC_WITH_RMODE(FMUL, VARL("x_rm"), VARL("y_rm"));

	return ret;
}

/**
 * \brief Subtract \p x from \p y with the correct rounding mode as determined
 * from the FPU control word
 *
 * \param x Desirable that it is a small expression since it will be duped
 * \param y Desirable that it is a small expression since it will be duped
 * \param ctx use_rmode gets set to true
 * \return RzILOpFloat* difference
 */
RZ_IPI ILPureEffectPair x86_il_fsub_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_OWN RZ_NONNULL RzILOpFloat *y, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(x && y && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SEQ2(SETL("x_rm", x), SETL("y_rm", y));
	// y - x, hence y is the first argument
	ret.val = EXEC_WITH_RMODE(FSUB, VARL("y_rm"), VARL("x_rm"));

	return ret;
}

/**
 * \brief Subtract \p y from \p x (reverse of \ref x86_il_fsub_with_rmode)
 */
RZ_IPI ILPureEffectPair x86_il_fsubr_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_OWN RZ_NONNULL RzILOpFloat *y, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	rz_return_val_if_fail(x && y && ctx, ((ILPureEffectPair){ .val = NULL, .eff = NULL }));
	return x86_il_fsub_with_rmode(y, x);
}

/**
 * \brief Divide \p x from \p y with the correct rounding mode as determined
 * from the FPU control word
 *
 * \param x Desirable that it is a small expression since it will be duped
 * \param y Desirable that it is a small expression since it will be duped
 * \param ctx use_rmode gets set to true
 * \return RzILOpFloat* division
 */
RZ_IPI ILPureEffectPair x86_il_fdiv_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_OWN RZ_NONNULL RzILOpFloat *y, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(x && y && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SEQ2(SETL("x_rm", x), SETL("y_rm", y));
	ret.val = EXEC_WITH_RMODE(FDIV, VARL("x_rm"), VARL("y_rm"));

	return ret;
}

/**
 * \brief Divide \p y from \p x (reverse of \ref x86_il_fdiv_with_rmode)
 */
RZ_IPI ILPureEffectPair x86_il_fdivr_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_OWN RZ_NONNULL RzILOpFloat *y, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	rz_return_val_if_fail(x && y && ctx, ((ILPureEffectPair){ .val = NULL, .eff = NULL }));
	return x86_il_fdiv_with_rmode(y, x);
}

/**
 * \brief Calculate the square root of \p x with the correct rounding mode as determined
 * from the FPU control word
 *
 * \param x Desirable that it is a small expression since it will be duped
 * \param ctx  use_rmode gets set to true
 * \return RzILOpFloat* square root
 */
RZ_IPI ILPureEffectPair x86_il_fsqrt_with_rmode_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *x, RZ_BORROW RZ_NONNULL X86ILContext *ctx) {
	ILPureEffectPair ret = { .val = NULL, .eff = NULL };
	rz_return_val_if_fail(x && ctx, ret);

	ctx->use_rmode = true;
	ret.eff = SETL("x_rm", x);
	ret.val = EXEC_WITH_RMODE(FSQRT, VARL("x_rm"));

	return ret;
}

/**
 * \brief Store a float \p val at FPU stack \p reg
 *
 * \param reg
 * \param val
 * \param val_format Format of \p val
 * \param ctx use_rmode gets set to true if any resizing of \p val is required
 * \return RzILOpFloat*
 */
RZ_IPI RzILOpEffect *x86_il_set_st_reg_ctx(X86Reg reg, RZ_OWN RZ_NONNULL RzILOpFloat *val, RzFloatFormat val_format, RZ_BORROW X86ILContext *ctx) {
	rz_return_val_if_fail(val && x86_il_is_st_reg(reg), NULL);

	if (val_format == RZ_FLOAT_IEEE754_BIN_80) {
		return SETG(x86_registers[reg], F2BV(val));
	} else {
		ILPureEffectPair converted_val = x86_il_resize_floating(val, RZ_FLOAT_IEEE754_BIN_80);

		return SEQ2(converted_val.eff, SETG(x86_registers[reg], F2BV(converted_val.val)));
	}
}

/**
 * \brief Get the stack TOP stored in the FPU status word.
 * TOP = FPU[12:15] (bits 12, 13 & 14)
 * 12th bit is the least significant bit.
 *
 * \return RzILOpPure* Bitvector of length 3
 */
RZ_IPI RzILOpPure *x86_il_get_fpu_stack_top() {
	RzILOpPure *status_word = x86_il_get_reg_bits(ZYDIS_REGISTER_X87STATUS, 0, 0);
	return UNSIGNED(3, SHIFTR0(status_word, UN(8, 11)));
}

/**
 * \brief Set the value of FPU status word.
 * See \ref x86_il_get_fpu_stack_top() for the structure of FPU status word and
 * stack TOP.
 *
 * \param top Value to be stored as the new TOP (bitvector length = 3)
 * \return RzILOpEffect*
 */
RZ_IPI RzILOpEffect *x86_il_set_fpu_stack_top(RZ_OWN RZ_NONNULL RzILOpPure *top) {
	rz_return_val_if_fail(top, NULL);

	RzILOpPure *shifted_top = SHIFTL0(UNSIGNED(16, top), UN(8, 11));
	/* 0x3800 only has the 12, 13 & 14 bits set, so we take its negation for the
	 * mask. */
	RzILOpPure *mask = UN(16, ~(0x3800));
	RzILOpPure *new_fpsw = LOGOR(shifted_top, LOGAND(mask, x86_il_get_reg_bits(ZYDIS_REGISTER_X87STATUS, 0, 0)));
	return x86_il_set_reg_bits(ZYDIS_REGISTER_X87STATUS, new_fpsw, 0);
}

#define ST_MOVE_RIGHT(l, r) x86_il_set_st_reg(ZYDIS_REGISTER_ST##r, x86_il_get_st_reg(ZYDIS_REGISTER_ST##l), RZ_FLOAT_IEEE754_BIN_80)

/**
 * \brief Push \p val on the FPU stack
 *
 * \param val
 * \param val_format Format of \p val
 * \param ctx use_rmode gets set to true if any resizing of \p val is required
 * \return RzILOpEffect* Push effect
 */
RZ_IPI RzILOpEffect *x86_il_st_push_ctx(RZ_OWN RZ_NONNULL RzILOpFloat *val, RzFloatFormat val_format, RZ_BORROW X86ILContext *ctx) {
	rz_return_val_if_fail(val, NULL);

	/* No need for a modulo here since the bitvector width will truncate any top
	 * value > 7 */
	RzILOpEffect *set_top = x86_il_set_fpu_stack_top(SUB(x86_il_get_fpu_stack_top(), UN(3, 1)));
	RzILOpEffect *st_shift = SEQ8(
		ST_MOVE_RIGHT(6, 7),
		ST_MOVE_RIGHT(5, 6),
		ST_MOVE_RIGHT(4, 5),
		ST_MOVE_RIGHT(3, 4),
		ST_MOVE_RIGHT(2, 3),
		ST_MOVE_RIGHT(1, 2),
		ST_MOVE_RIGHT(0, 1),
		x86_il_set_st_reg(ZYDIS_REGISTER_ST0, val, val_format));

	/* Set C1 if stack overflow. If stack overflow occurred, then the value of
	 * stack TOP must be 0x7. */
	RzILOpEffect *set_overflow = x86_il_set_fpu_flag(X86_FPU_C1, EQ(x86_il_get_fpu_stack_top(), UN(3, 7)));

	return SEQ3(set_top, st_shift, set_overflow);
}

#define ST_MOVE_LEFT(l, r) x86_il_set_st_reg(ZYDIS_REGISTER_ST##l, x86_il_get_st_reg(ZYDIS_REGISTER_ST##r), RZ_FLOAT_IEEE754_BIN_80)

/**
 * \brief Pop a value from the FPU stack
 *
 * \return RzILOpEffect* Pop effect
 */
RZ_IPI RzILOpEffect *x86_il_st_pop() {
	/* We actually don't need a context here because we will never need to resize
	 * any value. */
	X86ILContext *ctx = NULL;

	RzILOpEffect *set_top = x86_il_set_fpu_stack_top(ADD(x86_il_get_fpu_stack_top(), UN(3, 1)));
	RzILOpEffect *st_shift = SEQ7(
		ST_MOVE_LEFT(0, 1),
		ST_MOVE_LEFT(1, 2),
		ST_MOVE_LEFT(2, 3),
		ST_MOVE_LEFT(3, 4),
		ST_MOVE_LEFT(4, 5),
		ST_MOVE_LEFT(5, 6),
		ST_MOVE_LEFT(6, 7));

	/* Set C1 if stack underflow. If stack underflow occurred, then the value of
	 * stack TOP must be 0x0. */
	RzILOpEffect *set_underflow = x86_il_set_fpu_flag(X86_FPU_C1, EQ(x86_il_get_fpu_stack_top(), UN(3, 0)));

	return SEQ3(set_top, st_shift, set_underflow);
}

RZ_IPI ILPureEffectPair x86_il_st_pop_with_val() {
	ILPureEffectPair ret;
	ret.val = x86_il_get_st_reg(ZYDIS_REGISTER_ST0);
	ret.eff = x86_il_st_pop();

	return ret;
}

RZ_IPI RzILOpBool *x86_il_get_fpu_flag(X86FPUFlags flag) {
	RzILOpPure *shifted_fpsw = SHIFTR0(x86_il_get_reg_bits(ZYDIS_REGISTER_X87STATUS, 0, 0), UN(8, flag));
	return NON_ZERO(UNSIGNED(1, shifted_fpsw));
}

RZ_IPI RzILOpEffect *x86_il_set_fpu_flag(X86FPUFlags flag, RZ_OWN RZ_NONNULL RzILOpBool *value) {
	rz_return_val_if_fail(value, NULL);

	RzILOpPure *zero_mask = UN(16, ~(1 << flag));
	RzILOpPure *value_mask = SHIFTL0(BOOL_TO_BV(value, 16), UN(8, flag));
	RzILOpPure *new_fpsw = LOGOR(value_mask, LOGAND(zero_mask, x86_il_get_reg_bits(ZYDIS_REGISTER_X87STATUS, 0, 0)));
	return x86_il_set_reg_bits(ZYDIS_REGISTER_X87STATUS, new_fpsw, 0);
}

#define FLOATING_OP_MEM_WIDTH_CASE(n) \
	do { \
	case n: \
		return BV2F(RZ_FLOAT_IEEE754_BIN_##n, LOADW(n, x86_il_get_memaddr_bits(op.mem, bits, pc))); \
	} while (0)

/**
 * \brief Get the value of the floating point operand \p op
 * This function takes care of everything, like choosing
 * the correct typem returning the correct value and
 * converting to the correct FP format
 * Use the wrapper `x86_il_get_floating_op`
 *
 * \param op Operand to get
 * \param bits bitness
 * \param pc
 */
RZ_IPI RzILOpPure *x86_il_get_floating_operand_bits(X86Op op, int bits, ut64 pc) {
	switch (op.type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		if (x86_il_is_st_reg(op.reg.value)) {
			return x86_il_get_st_reg(op.reg.value);
		} else {
			RZ_LOG_ERROR("x86: RzIL: Invalid register passed as a floating point operand: %d\n", op.reg.value);
		}
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		switch (op.size * BITS_PER_BYTE) {
			/* ~Duff's~ DMaroo's device */
			FLOATING_OP_MEM_WIDTH_CASE(32);
			FLOATING_OP_MEM_WIDTH_CASE(64);
			FLOATING_OP_MEM_WIDTH_CASE(80);
		default:
			RZ_LOG_ERROR("x86: RzIL: Invalid memory operand width for a floating point operand: %d\n", op.size);
		}
		break;
	// case X86_OP_INVALID:
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
	default:
		RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered: %d\n", op.type);
	}

	return NULL;
}

#define FLOAT_WIDTH_TO_FORMAT_SWITCH_CASE(n) \
	do { \
	case n: \
		return RZ_FLOAT_IEEE754_BIN_##n; \
	} while (0)

RZ_IPI RzFloatFormat x86_width_to_format(ut8 width) {
	switch (width) {
		FLOAT_WIDTH_TO_FORMAT_SWITCH_CASE(32);
		FLOAT_WIDTH_TO_FORMAT_SWITCH_CASE(64);
		FLOAT_WIDTH_TO_FORMAT_SWITCH_CASE(80);
		FLOAT_WIDTH_TO_FORMAT_SWITCH_CASE(128);
	default:
		rz_warn_if_reached();
		return RZ_FLOAT_UNK;
	}
}

#define FLOAT_FORMAT_TO_WIDTH_SWITCH_CASE(n) \
	do { \
	case RZ_FLOAT_IEEE754_BIN_##n: \
		return n; \
	} while (0)

RZ_IPI ut8 x86_format_to_width(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
}

/**
 * \brief Set the value of the floating point operand \p op
 * This function takes care of everything, like choosing
 * the correct type, setting the correct value and
 * converting to the correct FP format
 * Use the wrapper `x86_il_set_floating_op`
 *
 * \param op Operand to be set
 * \param val Value to be used
 * \param val_format Format of \p val
 * \param bits Bitness
 * \param pc
 * \param ctx use_rmode gets set to true if any resizing of \p val is required
 */
RZ_IPI RzILOpEffect *x86_il_set_floating_operand_bits_ctx(X86Op op, RZ_OWN RZ_NONNULL RzILOpFloat *val, RzFloatFormat val_format, int bits, ut64 pc, RZ_BORROW X86ILContext *ctx) {
	rz_return_val_if_fail(val, NULL);
	RzILOpEffect *ret = NULL;

	switch (op.type) {
	case ZYDIS_OPERAND_TYPE_REGISTER:
		return x86_il_set_st_reg(op.reg.value, val, val_format);
	case ZYDIS_OPERAND_TYPE_MEMORY: {
		ut64 required_format = x86_width_to_format(op.size * BITS_PER_BYTE);

		RzILOpPure *resized_val;
		RzILOpEffect *ret = NULL;
		if (required_format == val_format) {
			ILPureEffectPair resized = x86_il_resize_floating(val, required_format);
			resized_val = resized.val;
			ret = resized.eff;
		} else {
			resized_val = val;
		}

		RzILOpEffect *set_bits = x86_il_set_mem_bits(op.mem, F2BV(resized_val), bits, pc);
		if (!ret) {
			ret = set_bits;
		} else {
			ret = SEQ2(ret, set_bits);
		}

		return ret;
	}
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
	default:
		RZ_LOG_ERROR("x86: RzIL: Invalid param type encountered: %d\n", ZYDIS_OPERAND_TYPE_IMMEDIATE);
		return ret;
	}
}

RZ_IPI RzILOpEffect *x86_il_clear_fpsw_flags() {
	RzILOpPure *new_fpsw = LOGAND(x86_il_get_reg_bits(ZYDIS_REGISTER_X87STATUS, 0, 0), UN(16, 0x3f80));
	return x86_il_set_reg_bits(ZYDIS_REGISTER_X87STATUS, new_fpsw, 0);
}

#include <rz_il/rz_il_opbuilder_end.h>
