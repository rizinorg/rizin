// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
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
x86_il_ins x86_ins[X86_INS_ENDING] = {
	[X86_INS_INVALID] = x86_il_invalid,
	[X86_INS_AAA] = x86_il_aaa,
	[X86_INS_AAD] = x86_il_aad,
	[X86_INS_AAM] = x86_il_aam,
	[X86_INS_AAS] = x86_il_aas,
	[X86_INS_ADC] = x86_il_adc,
	[X86_INS_ADD] = x86_il_add,
	[X86_INS_AND] = x86_il_and,
	[X86_INS_BSF] = x86_il_bsf,
	[X86_INS_CALL] = x86_il_call,
	[X86_INS_CBW] = x86_il_cbw,
	[X86_INS_CLC] = x86_il_clc,
	[X86_INS_CLD] = x86_il_cld,
	[X86_INS_CLI] = x86_il_cli,
	[X86_INS_CMC] = x86_il_cmc,
	[X86_INS_CMP] = x86_il_cmp,
	[X86_INS_CMOVA] = x86_il_cmov,
	[X86_INS_CMOVAE] = x86_il_cmov,
	[X86_INS_CMOVB] = x86_il_cmov,
	[X86_INS_CMOVBE] = x86_il_cmov,
	[X86_INS_CMOVE] = x86_il_cmov,
	[X86_INS_CMOVG] = x86_il_cmov,
	[X86_INS_CMOVGE] = x86_il_cmov,
	[X86_INS_CMOVL] = x86_il_cmov,
	[X86_INS_CMOVLE] = x86_il_cmov,
	[X86_INS_CMOVNE] = x86_il_cmov,
	[X86_INS_CMOVNO] = x86_il_cmov,
	[X86_INS_CMOVNP] = x86_il_cmov,
	[X86_INS_CMOVNS] = x86_il_cmov,
	[X86_INS_CMOVO] = x86_il_cmov,
	[X86_INS_CMOVP] = x86_il_cmov,
	[X86_INS_CMOVS] = x86_il_cmov,
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
	[X86_INS_MOVABS] = x86_il_mov,
	[X86_INS_MOVSB] = x86_il_movsb,
	[X86_INS_MOVSW] = x86_il_movsw,
	[X86_INS_MOVSD] = x86_il_movsd,
	[X86_INS_MOVSQ] = x86_il_movsq,
	[X86_INS_MOVSX] = x86_il_movsx,
	[X86_INS_MOVSXD] = x86_il_movsx,
	[X86_INS_MOVZX] = x86_il_movzx,
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
	[X86_INS_LEAVE] = x86_il_leave,

	/* floating-point instructions */
	[X86_INS_FNINIT] = x86_il_fninit,
	[X86_INS_FLDCW] = x86_il_fldcw,
	[X86_INS_FNSTCW] = x86_il_fnstcw,
	[X86_INS_FNSTSW] = x86_il_fnstsw,
	[X86_INS_FNCLEX] = x86_il_fnclex,
	[X86_INS_FLD] = x86_il_fld,
	[X86_INS_FST] = x86_il_fst,
	[X86_INS_FSTP] = x86_il_fstp,
	[X86_INS_FLD1] = x86_il_fld1,
	[X86_INS_FLDZ] = x86_il_fldz,
	[X86_INS_FLDL2T] = x86_il_fldl2t,
	[X86_INS_FLDL2E] = x86_il_fldl2e,
	[X86_INS_FLDPI] = x86_il_fldpi,
	[X86_INS_FLDLG2] = x86_il_fldlg2,
	[X86_INS_FLDLN2] = x86_il_fldln2,
	[X86_INS_FXCH] = x86_il_fxch,
	[X86_INS_FILD] = x86_il_fild,
	[X86_INS_FIST] = x86_il_fist,
	[X86_INS_FISTP] = x86_il_fistp,
	[X86_INS_FBLD] = x86_il_fbld,
	[X86_INS_FBSTP] = x86_il_fbstp,
	[X86_INS_FABS] = x86_il_fabs,
	[X86_INS_FADD] = x86_il_fadd,
#if CS_API_MAJOR <= 4
	[X86_INS_FADDP] = x86_il_fadd,
#endif
	[X86_INS_FIADD] = x86_il_fiadd,
	[X86_INS_FMUL] = x86_il_fmul,
	[X86_INS_FMULP] = x86_il_fmulp,
	[X86_INS_FIMUL] = x86_il_fimul,
	[X86_INS_FSUB] = x86_il_fsub,
	[X86_INS_FSUBP] = x86_il_fsubp,
	[X86_INS_FISUB] = x86_il_fisub,
	[X86_INS_FSUBR] = x86_il_fsubr,
	[X86_INS_FSUBRP] = x86_il_fsubrp,
	[X86_INS_FISUBR] = x86_il_fisubr,
	[X86_INS_FDIV] = x86_il_fdiv,
	[X86_INS_FDIVP] = x86_il_fdivp,
	[X86_INS_FIDIV] = x86_il_fidiv,
	[X86_INS_FDIVR] = x86_il_fdivr,
	[X86_INS_FDIVRP] = x86_il_fdivrp,
	[X86_INS_FIDIVR] = x86_il_fidivr,
	[X86_INS_FCOM] = x86_il_fcom,
	[X86_INS_FCOMP] = x86_il_fcomp,
	[X86_INS_FICOM] = x86_il_ficom,
	[X86_INS_FCOMPP] = x86_il_fcompp,
	[X86_INS_FICOMP] = x86_il_ficomp,
	[X86_INS_FCOMI] = x86_il_fcomi,
#if CS_API_MAJOR > 4
	[X86_INS_FCOMPI] = x86_il_fcomip,
	[X86_INS_FUCOMPI] = x86_il_fcomip,
#endif
	/* Using the same FCOM & FCOMI family IL lifters for FUCOM & FUCOMI family instructions
	 * since we don't support invalid arithmetic operand exceptions (#IA) anyways. */
	[X86_INS_FUCOM] = x86_il_fcom,
	[X86_INS_FUCOMP] = x86_il_fcomp,
	[X86_INS_FUCOMPP] = x86_il_fcompp,
	[X86_INS_FUCOMI] = x86_il_fcomi,
	[X86_INS_FCHS] = x86_il_fchs,
	[X86_INS_FTST] = x86_il_ftst,
	[X86_INS_FRNDINT] = x86_il_frndint,
	[X86_INS_FSQRT] = x86_il_fsqrt,
	[X86_INS_FNOP] = x86_il_fnop,
	[X86_INS_FISTTP] = x86_il_fisttp,

	/* unimplemented instructions */
	[X86_INS_IRET] = x86_il_unimpl,
	[X86_INS_RETF] = x86_il_unimpl,
	[X86_INS_RETFQ] = x86_il_unimpl,
	[X86_INS_INSB] = x86_il_unimpl,
	[X86_INS_INSW] = x86_il_unimpl,
	[X86_INS_OUTSB] = x86_il_unimpl,
	[X86_INS_OUTSW] = x86_il_unimpl,
	[X86_INS_FLDENV] = x86_il_unimpl,
	[X86_INS_FNSTENV] = x86_il_unimpl,
	[X86_INS_FNSAVE] = x86_il_unimpl,
	[X86_INS_FRSTOR] = x86_il_unimpl
};

void label_int(RzILVM *vm, RzILOpEffect *op);
void label_halt(RzILVM *vm, RzILOpEffect *op);
void label_port(RzILVM *vm, RzILOpEffect *op);

RZ_IPI bool rz_x86_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL const X86ILIns *ins) {
	rz_return_val_if_fail(analysis && aop && ins && ins->ins_size > 0, false);
	if (ins->mnem >= X86_INS_ENDING) {
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
