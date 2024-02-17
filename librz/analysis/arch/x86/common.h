// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef X86_IL_COMMON_H
#define X86_IL_COMMON_H

#include "x86_il.h"

#define X86_BIT(x)  UN(1, x)
#define X86_TO32(x) UNSIGNED(32, x)

#define IL_LIFTER(mnem) static RzILOpEffect *x86_il_##mnem(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis)

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

#define EFLAGS(f) x86_eflags_registers[X86_EFLAGS_##f]

#define extreg_lookup(suff, getter, setter) \
	{ X86_REG_R8##suff, X86_REG_R8, getter, setter }, \
		{ X86_REG_R9##suff, X86_REG_R9, getter, setter }, \
		{ X86_REG_R10##suff, X86_REG_R10, getter, setter }, \
		{ X86_REG_R11##suff, X86_REG_R11, getter, setter }, \
		{ X86_REG_R12##suff, X86_REG_R12, getter, setter }, \
		{ X86_REG_R13##suff, X86_REG_R13, getter, setter }, \
		{ X86_REG_R14##suff, X86_REG_R14, getter, setter }, \
		{ X86_REG_R15##suff, X86_REG_R15, getter, setter },

#define x86_il_get_reg(reg)      x86_il_get_reg_bits(reg, analysis->bits, pc)
#define x86_il_set_reg(reg, val) x86_il_set_reg_bits(reg, val, analysis->bits)

#define x86_il_get_memaddr_segment(mem, segment) x86_il_get_memaddr_segment_bits(mem, segment, analysis->bits, pc)
#define x86_il_get_memaddr(mem)                  x86_il_get_memaddr_bits(mem, analysis->bits, pc)
#define x86_il_set_mem(mem, val)                 x86_il_set_mem_bits(mem, val, analysis->bits, pc)

#define x86_il_get_op(opnum) \
	x86_il_get_operand_bits(ins->structure->operands[opnum], analysis->bits, pc, 0)
#define x86_il_get_op_implicit(opnum, mem_sz) \
	x86_il_get_operand_bits(ins->structure->operands[opnum], analysis->bits, pc, mem_sz)

#define x86_il_set_operand(op, val) x86_il_set_operand_bits(op, val, analysis->bits, pc)
#define x86_il_set_op(opnum, val)   x86_il_set_operand_bits(ins->structure->operands[opnum], val, analysis->bits, pc)

#define x86_il_set_result_flags(result)                            x86_il_set_result_flags_bits(result, analysis->bits)
#define x86_il_set_arithmetic_flags(res, x, y, addition)           x86_il_set_arithmetic_flags_bits(res, x, y, addition, analysis->bits)
#define x86_il_set_arithmetic_flags_except_cf(res, x, y, addition) x86_il_set_arithmetic_flags_except_cf_bits(res, x, y, addition, analysis->bits)

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
	X86_EFLAGS_ID = 21,
	X86_EFLAGS_ENDING
} X86EFlags;

extern const char *x86_eflags_registers[X86_EFLAGS_ENDING];

RzILOpPure *x86_il_get_reg_bits(X86Reg reg, int bits, uint64_t pc);
RzILOpEffect *x86_il_set_reg_bits(X86Reg reg, RzILOpPure *val, int bits);

RzILOpPure *x86_il_get_operand_bits(X86Op op, int analysis_bits, ut64 pc, int implicit_size);
RzILOpEffect *x86_il_set_operand_bits(X86Op op, RzILOpPure *val, int bits, ut64 pc);

RzILOpPure *x86_il_get_memaddr_bits(X86Mem mem, int bits, ut64 pc);
RzILOpPure *x86_il_get_memaddr_segment_bits(X86Mem mem, X86Reg segment, int bits, ut64 pc);
RzILOpEffect *x86_il_set_mem_bits(X86Mem mem, RzILOpPure *val, int bits, ut64 pc);

RzILOpBool *x86_il_is_add_carry(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y);
RzILOpBool *x86_il_is_sub_borrow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y);
RzILOpBool *x86_il_is_add_overflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y);
RzILOpBool *x86_il_is_sub_underflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y);

RzILOpEffect *x86_il_set_result_flags_bits(RZ_OWN RzILOpPure *result, int bits);
RzILOpEffect *x86_il_set_arithmetic_flags_bits(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y, bool addition, int bits);
RzILOpEffect *x86_il_set_arithmetic_flags_except_cf_bits(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y, bool addition, int bits);

RzILOpPure *x86_il_get_flags(unsigned int size);
RzILOpEffect *x86_il_set_flags(RZ_OWN RzILOpPure *val, unsigned int size);

/* Capstone does not have the following FPU registers. */

/* FPU control word */
#define X86_REG_FPU_CW "fpcw"
/* FPU tag word */
#define X86_REG_FPU_TW "ftw"
/* FPU last instruction opcode */
#define X86_REG_FPU_OP "fop"
/* FPU instruction pointer */
#define X86_REG_FPU_IP "frip"
/* FPU data pointer */
#define X86_REG_FPU_DP "frdp"

typedef enum {
	X86_FPU_C0 = 8,
	X86_FPU_C1 = 9,
	X86_FPU_C2 = 10,
	X86_FPU_C3 = 14,
} X86FPUFlags;

bool x86_il_is_st_reg(X86Reg reg);

/* Need to pass in val_size as a param to avoid unnecessary rounding of val. */

RzILOpFloat *x86_il_get_st_reg(X86Reg reg);
RzILOpEffect *x86_il_set_st_reg(X86Reg reg, RzILOpFloat *val, RzFloatFormat val_format);

RzILOpEffect *x86_il_set_fpu_stack_top(RzILOpPure *top);
RzILOpPure *x86_il_get_fpu_stack_top();

RzILOpEffect *x86_il_st_push(RzILOpFloat *val, RzFloatFormat val_format);
RzILOpEffect *x86_il_st_pop();

#define X86_IL_ST_POP(val, eff) \
	do { \
		val = x86_il_get_st_reg(X86_REG_ST0); \
		eff = x86_il_st_pop(); \
	} while (0)

RzILOpPure *x86_il_get_fpu_flag(X86FPUFlags flag);
RzILOpEffect *x86_il_set_fpu_flag(X86FPUFlags flag, RzILOpBool *value);

RzILOpPure *x86_il_fpu_get_rmode();

RzILOpEffect *init_rmode();

RzILOpFloat *x86_il_resize_floating(RzILOpFloat *val, RzFloatFormat format);
RzILOpFloat *x86_il_floating_from_int(RzILOpBitVector *int_val, RzFloatFormat format);
RzILOpBitVector *x86_il_int_from_floating(RzILOpFloat *float_val, ut32 width);

RzILOpFloat *x86_il_fadd_with_rmode(RzILOpFloat *x, RzILOpFloat *y);
RzILOpFloat *x86_il_fmul_with_rmode(RzILOpFloat *x, RzILOpFloat *y);
RzILOpFloat *x86_il_fsub_with_rmode(RzILOpFloat *x, RzILOpFloat *y);
RzILOpFloat *x86_il_fsubr_with_rmode(RzILOpFloat *x, RzILOpFloat *y);
RzILOpFloat *x86_il_fdiv_with_rmode(RzILOpFloat *x, RzILOpFloat *y);
RzILOpFloat *x86_il_fdivr_with_rmode(RzILOpFloat *x, RzILOpFloat *y);

RzILOpPure *x86_il_get_floating_operand_bits(X86Op op, int analysis_bits, ut64 pc);

#define x86_il_get_floating_op(opnum) \
	x86_il_get_floating_operand_bits(ins->structure->operands[opnum], analysis->bits, pc)

RzFloatFormat x86_width_to_format(ut8 width);
ut8 x86_format_to_width(RzFloatFormat format);

RzILOpEffect *x86_il_set_floating_operand_bits(X86Op op, RzILOpFloat *val, RzFloatFormat val_format, int bits, ut64 pc);

#define x86_il_set_floating_op(opnum, val, val_format) \
	x86_il_set_floating_operand_bits(ins->structure->operands[opnum], val, val_format, analysis->bits, pc)

RzILOpEffect *x86_il_clear_fpsw_flags();

#endif // X86_IL_COMMON_H
