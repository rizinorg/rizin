// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_M68K_IL_HELPERS_H
#define RZ_M68K_IL_HELPERS_H

#include "m68k/m68k_cs.h"

#include <rz_il.h>

#define M68K_ADDR_BITS 32

#define M68K_CCR_C        0
#define M68K_CCR_V        1
#define M68K_CCR_Z        2
#define M68K_CCR_N        3
#define M68K_CCR_X        4
#define M68K_SR_M         12
#define M68K_SR_S         13
#define M68K_FPSR_CC_N    27
#define M68K_FPSR_CC_Z    26
#define M68K_FPSR_CC_I    25
#define M68K_FPSR_CC_NAN  24
#define M68K_FPSR_CC_MASK ((1u << M68K_FPSR_CC_N) | (1u << M68K_FPSR_CC_Z) | (1u << M68K_FPSR_CC_I) | (1u << M68K_FPSR_CC_NAN))

#define M68K_FPSR_QUOTIENT_SHIFT     16
#define M68K_FPSR_QUOTIENT_MASK      (0xffu << M68K_FPSR_QUOTIENT_SHIFT)
#define M68K_FMOVEM_FP_REG_BITS_MASK 0x00ff0000u
#define M68K_FMOVEM_EXTENDED_BITS    96
#define M68K_FMOVEM_EXTENDED_BYTES   12

// Capstone 4 and 5 do not expose the bitfield register encoding helpers that
// newer releases provide. Keep the encoding local to the M68K lifter.
#ifndef M68K_BF_REG_FLAG
#define M68K_BF_REG_FLAG   0x80
#define M68K_BF_IS_REG(v)  ((v) & M68K_BF_REG_FLAG)
#define M68K_BF_REG_NUM(v) ((v) & 7)
#endif

/** Borrowed Capstone state and instruction addresses for one lifted op. */
typedef struct {
	csh handle;
	cs_mode mode;
	const cs_insn *insn;
	const cs_m68k *m68k;
	ut64 addr;
	ut64 next_addr;
} M68KILCtx;

/**
 * Effective-address result. All non-NULL IL nodes are owned by this value
 * until explicitly transferred to the caller or released with m68k_ea_fini().
 */
typedef struct {
	RzILOpPure *addr;
	RzILOpEffect *pre;
	RzILOpEffect *post;
} M68KEA;

/**
 * Read/write operand state. op and addr_local are borrowed; post is owned and
 * must be transferred or released with m68k_rw_operand_fini().
 */
typedef struct {
	const cs_m68k_op *op;
	const char *addr_local;
	RzILOpEffect *post;
} M68KRWOperand;

/**
 * Bitfield destination state. op and addr_local are borrowed; post is owned
 * and must be transferred or released with m68k_bitfield_target_fini().
 */
typedef struct {
	const cs_m68k_op *op;
	bool memory;
	const char *addr_local;
	RzILOpEffect *post;
} M68KBitfieldTarget;

typedef enum {
	M68K_BIN_ADD,
	M68K_BIN_SUB,
	M68K_BIN_AND,
	M68K_BIN_OR,
	M68K_BIN_XOR
} M68KBinOp;

typedef enum {
	M68K_CACHE_OP_TOUCH,
	M68K_CACHE_OP_INVALIDATE,
	M68K_CACHE_OP_PUSH
} M68KCacheOp;

typedef enum {
	M68K_DEBUG_OP_DATA,
	M68K_DEBUG_OP_DEBUG
} M68KDebugOp;

typedef enum {
	M68K_SYSTEM_OP_RESET,
	M68K_SYSTEM_OP_STOP,
	M68K_SYSTEM_OP_LPSTOP,
	M68K_SYSTEM_OP_HALT,
	M68K_SYSTEM_OP_PULSE
} M68KSystemOp;

typedef enum {
	M68K_CP_OP_NOP,
	M68K_CP_OP_BRANCH,
	M68K_CP_OP_LOAD,
	M68K_CP_OP_STORE
} M68KCoprocessorOp;

typedef enum {
	M68K_TRAP_OP_TRAP,
	M68K_TRAP_OP_BKPT,
	M68K_TRAP_OP_TRAPCC,
	M68K_TRAP_OP_FTRAPCC,
	M68K_TRAP_OP_TRAPV,
	M68K_TRAP_OP_BGND,
	M68K_TRAP_OP_DIV_ZERO,
	M68K_TRAP_OP_CHK,
	M68K_TRAP_OP_ILLEGAL,
	M68K_TRAP_OP_PRIVILEGE,
	M68K_TRAP_OP_FORMAT
} M68KTrapOp;

typedef enum {
	M68K_VECTOR_ILLEGAL = 4,
	M68K_VECTOR_ZERO_DIVIDE = 5,
	M68K_VECTOR_CHK = 6,
	M68K_VECTOR_TRAPV_TRAPCC = 7,
	M68K_VECTOR_PRIVILEGE = 8,
	M68K_VECTOR_FORMAT_ERROR = 14
} M68KExceptionVector;

#define M68K_VECTOR_TRAP_BASE 32

typedef enum {
	M68K_FPU_STATE_SAVE,
	M68K_FPU_STATE_RESTORE
} M68KFPUStateOp;

typedef enum {
	M68K_MMU_OP_LOAD,
	M68K_MMU_OP_FLUSH,
	M68K_MMU_OP_TEST,
	M68K_MMU_OP_MOVE,
	M68K_MMU_OP_LOAD_PHYSICAL
} M68KMMUOp;

typedef struct {
	ut8 selector;
	ut16 sign_exp;
	ut64 mantissa;
} M68KFMovecrConst;

RZ_IPI RzILOpPure *cast_unsigned(ut32 bits, RzILOpPure *v);
RZ_IPI RzILOpPure *cast_signed(ut32 bits, RzILOpPure *v);
RZ_IPI RzILOpPure *extend_to_32(RzILOpPure *v, bool sign_extend);
RZ_IPI RzILOpPure *reg_value(M68KILCtx *ctx, m68k_reg reg);
RZ_IPI RzILOpPure *read_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits);
RZ_IPI RzILOpEffect *seq_append(RzILOpEffect *a, RzILOpEffect *b);
RZ_IPI RzILOpEffect *set_ccr_from_value(RzILOpPure *new_ccr);
RZ_IPI RzILOpBool *ccr_bit(ut32 bit);
RZ_IPI RzILOpBool *fpsr_bit(ut32 bit);
RZ_IPI RzILOpEffect *set_fpsr_cc(RzILOpBool *n, RzILOpBool *z, RzILOpBool *i, RzILOpBool *nan);
RZ_IPI RzILOpBool *supervisor_mode(void);
RZ_IPI RzILOpPure *ccr_with_flag(RzILOpPure *ccr, ut32 bit, RzILOpBool *value);
RZ_IPI RzILOpEffect *set_flags_nzvcx(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c, RzILOpBool *x);
RZ_IPI RzILOpEffect *set_flags_nzvcx_extend(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c);
RZ_IPI RzILOpEffect *set_flags_div(RzILOpPure *quotient, ut32 bits, RzILOpBool *overflow);
RZ_IPI RzILOpBool *m68k_add_overflow(RzILOpPure *a, RzILOpPure *b, RzILOpPure *r);
RZ_IPI RzILOpBool *m68k_sub_overflow(RzILOpPure *a, RzILOpPure *b, RzILOpPure *r);
RZ_IPI RzILOpBool *signed_out_of_range(RzILOpPure *value, ut32 bits);
RZ_IPI RzILOpBool *addx_overflow(ut32 bits);
RZ_IPI RzILOpBool *subx_overflow(ut32 bits);
RZ_IPI RzILOpBool *negx_overflow(ut32 bits);
RZ_IPI RzILOpEffect *write_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value);
RZ_IPI bool m68k_mode_uses_later_movem_base_value(cs_mode mode);
RZ_IPI bool m68k_mode_has_format_word(cs_mode mode);
RZ_IPI RzILOpBool *rte_format_valid(cs_mode mode);
RZ_IPI RzILOpPure *rte_frame_size(cs_mode mode);
RZ_IPI RzILOpPure *branch_disp_target(const M68KILCtx *ctx, const cs_m68k_op *op);
RZ_IPI RzILOpEffect *set_addr_reg_delta(M68KILCtx *ctx, m68k_reg reg, st32 delta);
RZ_IPI M68KEA effective_addr(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits);
RZ_IPI RzILOpPure *read_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpEffect **pre, RzILOpEffect **post);
RZ_IPI RzILOpEffect *write_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpPure *value, RzILOpEffect **pre, RzILOpEffect **post);
RZ_IPI RzILOpEffect *m68k_label(const char *label);
RZ_IPI RzILOpEffect *guard_supervisor(RzILOpEffect *effect);
RZ_IPI RzILOpEffect *write_status_reg_unchecked(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value);
RZ_IPI RzILOpEffect *write_status_reg(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value);
RZ_IPI void m68k_ea_fini(M68KEA *ea);
RZ_IPI void m68k_rw_operand_fini(M68KRWOperand *rw);
RZ_IPI void m68k_bitfield_target_fini(M68KBitfieldTarget *target);
RZ_IPI RzILOpEffect *m68k_exception(M68KTrapOp trap_op, M68KExceptionVector vector, const char *label);
RZ_IPI bool operand_to_local(M68KILCtx *ctx, const char *name, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq);
RZ_IPI bool rw_operand_to_local(M68KILCtx *ctx, M68KRWOperand *rw, const char *value_local, const char *addr_local, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq);
RZ_IPI RzILOpEffect *write_rw_operand(M68KILCtx *ctx, const M68KRWOperand *rw, ut32 bits, RzILOpPure *value);

#endif // RZ_M68K_IL_HELPERS_H
