// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-FileCopyrightText: 2024 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "x86_il.h"
#include "il_ops.inc"
#include "il_fp_ops.inc"

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

#define FPU_REGS \
	"cwd", /* X86_REG_FPU_CW */ \
		"swd", /* X86_REG_FPSW */ \
		"ftw", /* X86_REG_FPU_TW */ \
		"fop", /* X86_REG_FPU_OP */ \
		"frip", /* X86_REG_FPU_IP */ \
		"frdp", /* X86_REG_FPU_DP */ \
		"st0", /* X86_REG_ST0 */ \
		"st1", /* X86_REG_ST1 */ \
		"st2", /* X86_REG_ST2 */ \
		"st3", /* X86_REG_ST3 */ \
		"st4", /* X86_REG_ST4 */ \
		"st5", /* X86_REG_ST5 */ \
		"st6", /* X86_REG_ST6 */ \
		"st7" /* X86_REG_ST6 */

/**
 * \brief All registers bound to IL variables for x86 16-bit
 */
const char *x86_bound_regs_16[] = {
	COMMON_REGS,
	"ax", /* X86_REG_AX */
	"bx", /* X86_REG_BX */
	"cx", /* X86_REG_CX */
	"dx", /* X86_REG_DX */
	// "ip", /* X86_REG_IP */
	"sp", /* X86_REG_SP */
	"bp", /* X86_REG_BP */
	"si", /* X86_REG_SI */
	"di", /* X86_REG_DI */
	NULL
};

/**
 * \brief All registers bound to IL variables for x86 32-bit
 */
const char *x86_bound_regs_32[] = {
	COMMON_REGS,
	"eax", /* X86_REG_EAX */
	"ebx", /* X86_REG_EBX */
	"ecx", /* X86_REG_ECX */
	"edx", /* X86_REG_EDX */
	// "eip", /* X86_REG_EIP */
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
const char *x86_bound_regs_64[] = {
	COMMON_REGS,
	"rax", /* X86_REG_RAX */
	"rbx", /* X86_REG_RBX */
	"rcx", /* X86_REG_RCX */
	"rdx", /* X86_REG_RDX */
	// "rip", /* X86_REG_RIP */
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
	FPU_REGS,
	NULL
};

typedef RzILOpEffect *(*x86_il_ins)(const X86ILIns *, ut64, RzAnalysis *, X86ILContext *);

/**
 * \brief RzIL handlers for x86 instructions
 */
x86_il_ins x86_ins[ZYDIS_MNEMONIC_MAX_VALUE] = {
	[ZYDIS_MNEMONIC_INVALID] = x86_il_invalid,
	[ZYDIS_MNEMONIC_AAA] = x86_il_aaa,
	[ZYDIS_MNEMONIC_AAD] = x86_il_aad,
	[ZYDIS_MNEMONIC_AAM] = x86_il_aam,
	[ZYDIS_MNEMONIC_AAS] = x86_il_aas,
	[ZYDIS_MNEMONIC_ADC] = x86_il_adc,
	[ZYDIS_MNEMONIC_ADD] = x86_il_add,
	[ZYDIS_MNEMONIC_AND] = x86_il_and,
	[ZYDIS_MNEMONIC_BSF] = x86_il_bsf,
	[ZYDIS_MNEMONIC_CALL] = x86_il_call,
	[ZYDIS_MNEMONIC_CBW] = x86_il_cbw,
	[ZYDIS_MNEMONIC_CLC] = x86_il_clc,
	[ZYDIS_MNEMONIC_CLD] = x86_il_cld,
	[ZYDIS_MNEMONIC_CLI] = x86_il_cli,
	[ZYDIS_MNEMONIC_CMC] = x86_il_cmc,
	[ZYDIS_MNEMONIC_CMP] = x86_il_cmp,
	[ZYDIS_MNEMONIC_CMOVNBE] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNB] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVB] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVBE] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVZ] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNLE] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNL] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVL] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVLE] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNZ] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNO] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNP] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVNS] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVO] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVP] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMOVS] = x86_il_cmov,
	[ZYDIS_MNEMONIC_CMPSB] = x86_il_cmpsb,
	[ZYDIS_MNEMONIC_CMPSW] = x86_il_cmpsw,
	[ZYDIS_MNEMONIC_CMPSD] = x86_il_cmpsd,
	[ZYDIS_MNEMONIC_CMPSQ] = x86_il_cmpsq,
	[ZYDIS_MNEMONIC_DAA] = x86_il_daa,
	[ZYDIS_MNEMONIC_DAS] = x86_il_das,
	[ZYDIS_MNEMONIC_DEC] = x86_il_dec,
	[ZYDIS_MNEMONIC_DIV] = x86_il_div,
	[ZYDIS_MNEMONIC_HLT] = x86_il_hlt,
	[ZYDIS_MNEMONIC_IDIV] = x86_il_idiv,
	[ZYDIS_MNEMONIC_IMUL] = x86_il_imul,
	[ZYDIS_MNEMONIC_IN] = x86_il_in,
	[ZYDIS_MNEMONIC_INC] = x86_il_inc,
	[ZYDIS_MNEMONIC_INT] = x86_il_int,
	[ZYDIS_MNEMONIC_INTO] = x86_il_into,
	[ZYDIS_MNEMONIC_JNBE] = x86_il_ja,
	[ZYDIS_MNEMONIC_JNB] = x86_il_jae,
	[ZYDIS_MNEMONIC_JB] = x86_il_jb,
	[ZYDIS_MNEMONIC_JBE] = x86_il_jbe,
	[ZYDIS_MNEMONIC_JCXZ] = x86_il_jcxz,
	[ZYDIS_MNEMONIC_JECXZ] = x86_il_jecxz,
	[ZYDIS_MNEMONIC_JRCXZ] = x86_il_jrcxz,
	[ZYDIS_MNEMONIC_JZ] = x86_il_je,
	[ZYDIS_MNEMONIC_JNLE] = x86_il_jg,
	[ZYDIS_MNEMONIC_JNL] = x86_il_jge,
	[ZYDIS_MNEMONIC_JL] = x86_il_jl,
	[ZYDIS_MNEMONIC_JLE] = x86_il_jle,
	[ZYDIS_MNEMONIC_JNZ] = x86_il_jne,
	[ZYDIS_MNEMONIC_JNO] = x86_il_jno,
	[ZYDIS_MNEMONIC_JNP] = x86_il_jnp,
	[ZYDIS_MNEMONIC_JNS] = x86_il_jns,
	[ZYDIS_MNEMONIC_JO] = x86_il_jo,
	[ZYDIS_MNEMONIC_JP] = x86_il_jp,
	[ZYDIS_MNEMONIC_JS] = x86_il_js,
	[ZYDIS_MNEMONIC_JMP] = x86_il_jmp,
	[ZYDIS_MNEMONIC_LAHF] = x86_il_lahf,
	[ZYDIS_MNEMONIC_LDS] = x86_il_lds,
	[ZYDIS_MNEMONIC_LEA] = x86_il_lea,
	[ZYDIS_MNEMONIC_LES] = x86_il_les,
	[ZYDIS_MNEMONIC_LODSB] = x86_il_lodsb,
	[ZYDIS_MNEMONIC_LODSW] = x86_il_lodsw,
	[ZYDIS_MNEMONIC_LODSD] = x86_il_lodsd,
	[ZYDIS_MNEMONIC_LODSQ] = x86_il_lodsq,
	[ZYDIS_MNEMONIC_LOOP] = x86_il_loop,
	[ZYDIS_MNEMONIC_LOOPE] = x86_il_loope,
	[ZYDIS_MNEMONIC_LOOPNE] = x86_il_loopne,
	[ZYDIS_MNEMONIC_MOV] = x86_il_mov,
	//[ZYDIS_MNEMONIC_MOVABS] = x86_il_mov,
	[ZYDIS_MNEMONIC_MOVSB] = x86_il_movsb,
	[ZYDIS_MNEMONIC_MOVSW] = x86_il_movsw,
	[ZYDIS_MNEMONIC_MOVSD] = x86_il_movsd,
	[ZYDIS_MNEMONIC_MOVSQ] = x86_il_movsq,
	[ZYDIS_MNEMONIC_MOVSX] = x86_il_movsx,
	[ZYDIS_MNEMONIC_MOVSXD] = x86_il_movsx,
	[ZYDIS_MNEMONIC_MOVZX] = x86_il_movzx,
	[ZYDIS_MNEMONIC_MUL] = x86_il_mul,
	[ZYDIS_MNEMONIC_NEG] = x86_il_neg,
	[ZYDIS_MNEMONIC_NOP] = x86_il_nop,
	[ZYDIS_MNEMONIC_NOT] = x86_il_not,
	[ZYDIS_MNEMONIC_OR] = x86_il_or,
	[ZYDIS_MNEMONIC_OUT] = x86_il_out,
	[ZYDIS_MNEMONIC_POP] = x86_il_pop,
	[ZYDIS_MNEMONIC_POPF] = x86_il_popf,
	[ZYDIS_MNEMONIC_POPFD] = x86_il_popfd,
	[ZYDIS_MNEMONIC_POPFQ] = x86_il_popfq,
	[ZYDIS_MNEMONIC_PUSH] = x86_il_push,
	[ZYDIS_MNEMONIC_PUSHF] = x86_il_pushf,
	[ZYDIS_MNEMONIC_PUSHFD] = x86_il_pushfd,
	[ZYDIS_MNEMONIC_PUSHFQ] = x86_il_pushfq,
	[ZYDIS_MNEMONIC_PUSHAD] = x86_il_pushaw,
	//[ZYDIS_MNEMONIC_PUSHAL] = x86_il_pushal,
	[ZYDIS_MNEMONIC_RCL] = x86_il_rcl,
	[ZYDIS_MNEMONIC_RCR] = x86_il_rcr,
	[ZYDIS_MNEMONIC_ROL] = x86_il_rol,
	[ZYDIS_MNEMONIC_ROR] = x86_il_ror,
	[ZYDIS_MNEMONIC_RET] = x86_il_ret,
	[ZYDIS_MNEMONIC_SAHF] = x86_il_sahf,
	//[ZYDIS_MNEMONIC_SAL] = x86_il_sal,
	[ZYDIS_MNEMONIC_SAR] = x86_il_sar,
	[ZYDIS_MNEMONIC_SHL] = x86_il_shl,
	[ZYDIS_MNEMONIC_SHR] = x86_il_shr,
	[ZYDIS_MNEMONIC_SBB] = x86_il_sbb,
	[ZYDIS_MNEMONIC_SCASB] = x86_il_scasb,
	[ZYDIS_MNEMONIC_SCASW] = x86_il_scasw,
	[ZYDIS_MNEMONIC_SCASD] = x86_il_scasd,
	[ZYDIS_MNEMONIC_SCASQ] = x86_il_scasq,
	[ZYDIS_MNEMONIC_STAC] = x86_il_stac,
	[ZYDIS_MNEMONIC_STC] = x86_il_stc,
	[ZYDIS_MNEMONIC_STD] = x86_il_std,
	[ZYDIS_MNEMONIC_STI] = x86_il_sti,
	[ZYDIS_MNEMONIC_STOSB] = x86_il_stosb,
	[ZYDIS_MNEMONIC_STOSD] = x86_il_stosd,
	[ZYDIS_MNEMONIC_STOSQ] = x86_il_stosq,
	[ZYDIS_MNEMONIC_STOSW] = x86_il_stosw,
	[ZYDIS_MNEMONIC_SUB] = x86_il_sub,
	[ZYDIS_MNEMONIC_TEST] = x86_il_test,
	//[ZYDIS_MNEMONIC_WAIT] = x86_il_wait,
	//[ZYDIS_MNEMONIC_XCHG] = x86_il_xchg,
	//[ZYDIS_MNEMONIC_XLATB] = x86_il_xlatb,
	[ZYDIS_MNEMONIC_XOR] = x86_il_xor,
	[ZYDIS_MNEMONIC_BOUND] = x86_il_bound,
	[ZYDIS_MNEMONIC_ENTER] = x86_il_enter,
	[ZYDIS_MNEMONIC_LEAVE] = x86_il_leave,

	/* floating-point instructions */
	[ZYDIS_MNEMONIC_FNINIT] = x86_il_fninit,
	[ZYDIS_MNEMONIC_FLDCW] = x86_il_fldcw,
	[ZYDIS_MNEMONIC_FNSTCW] = x86_il_fnstcw,
	[ZYDIS_MNEMONIC_FNSTSW] = x86_il_fnstsw,
	[ZYDIS_MNEMONIC_FNCLEX] = x86_il_fnclex,
	[ZYDIS_MNEMONIC_FLD] = x86_il_fld,
	[ZYDIS_MNEMONIC_FST] = x86_il_fst,
	[ZYDIS_MNEMONIC_FSTP] = x86_il_fstp,
	[ZYDIS_MNEMONIC_FLD1] = x86_il_fld1,
	[ZYDIS_MNEMONIC_FLDZ] = x86_il_fldz,
	[ZYDIS_MNEMONIC_FLDL2T] = x86_il_fldl2t,
	[ZYDIS_MNEMONIC_FLDL2E] = x86_il_fldl2e,
	[ZYDIS_MNEMONIC_FLDPI] = x86_il_fldpi,
	[ZYDIS_MNEMONIC_FLDLG2] = x86_il_fldlg2,
	[ZYDIS_MNEMONIC_FLDLN2] = x86_il_fldln2,
	[ZYDIS_MNEMONIC_FXCH] = x86_il_fxch,
	[ZYDIS_MNEMONIC_FILD] = x86_il_fild,
	[ZYDIS_MNEMONIC_FIST] = x86_il_fist,
	[ZYDIS_MNEMONIC_FISTP] = x86_il_fistp,
	[ZYDIS_MNEMONIC_FBLD] = x86_il_fbld,
	[ZYDIS_MNEMONIC_FBSTP] = x86_il_fbstp,
	[ZYDIS_MNEMONIC_FABS] = x86_il_fabs,
	[ZYDIS_MNEMONIC_FADD] = x86_il_fadd,
#if CS_API_MAJOR <= 4
	[ZYDIS_MNEMONIC_FADDP] = x86_il_fadd,
#endif
	[ZYDIS_MNEMONIC_FIADD] = x86_il_fiadd,
	[ZYDIS_MNEMONIC_FMUL] = x86_il_fmul,
	[ZYDIS_MNEMONIC_FMULP] = x86_il_fmulp,
	[ZYDIS_MNEMONIC_FIMUL] = x86_il_fimul,
	[ZYDIS_MNEMONIC_FSUB] = x86_il_fsub,
	[ZYDIS_MNEMONIC_FSUBP] = x86_il_fsubp,
	[ZYDIS_MNEMONIC_FISUB] = x86_il_fisub,
	[ZYDIS_MNEMONIC_FSUBR] = x86_il_fsubr,
	[ZYDIS_MNEMONIC_FSUBRP] = x86_il_fsubrp,
	[ZYDIS_MNEMONIC_FISUBR] = x86_il_fisubr,
	[ZYDIS_MNEMONIC_FDIV] = x86_il_fdiv,
	[ZYDIS_MNEMONIC_FDIVP] = x86_il_fdivp,
	[ZYDIS_MNEMONIC_FIDIV] = x86_il_fidiv,
	[ZYDIS_MNEMONIC_FDIVR] = x86_il_fdivr,
	[ZYDIS_MNEMONIC_FDIVRP] = x86_il_fdivrp,
	[ZYDIS_MNEMONIC_FIDIVR] = x86_il_fidivr,
	[ZYDIS_MNEMONIC_FCOM] = x86_il_fcom,
	[ZYDIS_MNEMONIC_FCOMP] = x86_il_fcomp,
	[ZYDIS_MNEMONIC_FICOM] = x86_il_ficom,
	[ZYDIS_MNEMONIC_FCOMPP] = x86_il_fcompp,
	[ZYDIS_MNEMONIC_FICOMP] = x86_il_ficomp,
	[ZYDIS_MNEMONIC_FCOMI] = x86_il_fcomi,
#if CS_API_MAJOR > 4
	[ZYDIS_MNEMONIC_FCOMPI] = x86_il_fcomip,
	[ZYDIS_MNEMONIC_FUCOMPI] = x86_il_fcomip,
#endif
	/* Using the same FCOM & FCOMI family IL lifters for FUCOM & FUCOMI family instructions
	 * since we don't support invalid arithmetic operand exceptions (#IA) anyways. */
	[ZYDIS_MNEMONIC_FUCOM] = x86_il_fcom,
	[ZYDIS_MNEMONIC_FUCOMP] = x86_il_fcomp,
	[ZYDIS_MNEMONIC_FUCOMPP] = x86_il_fcompp,
	[ZYDIS_MNEMONIC_FUCOMI] = x86_il_fcomi,
	[ZYDIS_MNEMONIC_FCHS] = x86_il_fchs,
	[ZYDIS_MNEMONIC_FTST] = x86_il_ftst,
	[ZYDIS_MNEMONIC_FRNDINT] = x86_il_frndint,
	[ZYDIS_MNEMONIC_FSQRT] = x86_il_fsqrt,
	[ZYDIS_MNEMONIC_FNOP] = x86_il_fnop,
	[ZYDIS_MNEMONIC_FISTTP] = x86_il_fisttp,

	/* unimplemented instructions */
	[ZYDIS_MNEMONIC_IRET] = x86_il_unimpl,
	//[ZYDIS_MNEMONIC_RETF] = x86_il_unimpl,
	//[ZYDIS_MNEMONIC_RETFQ] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_INSB] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_INSW] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_OUTSB] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_OUTSW] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_FLDENV] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_FNSTENV] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_FNSAVE] = x86_il_unimpl,
	[ZYDIS_MNEMONIC_FRSTOR] = x86_il_unimpl
};

void label_int(RzILVM *vm, RzILOpEffect *op);
void label_halt(RzILVM *vm, RzILOpEffect *op);
void label_port(RzILVM *vm, RzILOpEffect *op);

RZ_IPI bool rz_x86_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const X86ILIns *ins) {
	rz_return_val_if_fail(analysis && aop && ins && ins->ins_size > 0, false);
	if (ins->mnem >= ZYDIS_MNEMONIC_MAX_VALUE) {
		RZ_LOG_ERROR("RzIL: x86: Invalid instruction type %d\n", ins->mnem);
		return false;
	}

	x86_il_ins lifter = x86_ins[ins->mnem];

	RzILOpEffect *lifted;
	if (!lifter) {
		/* For unimplemented instructions */
		lifter = x86_il_unimpl;
	}

	X86ILContext ctx = {
		.use_rmode = false
	};

	lifted = lifter(ins, pc, analysis, &ctx);
	if (ctx.use_rmode) {
		lifted = rz_il_op_new_seq(init_rmode(), lifted);
	}

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
