// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#ifndef BUILD_LUA_ARCH_H
#define BUILD_LUA_ARCH_H

#include <rz_types.h>
#include <rz_asm.h>
#include <luac/luac_common.h>
#include "luajit/arch_2.1.h"

#define DISASM_BUF_SIZE 64
#define DISASM_BUF      (char[DISASM_BUF_SIZE]){ 0 }

#define PROTO_VBASE    0x0 // 0x1000
#define PROTO_VBANK    0x1000
#define CONST_OFFSET   0x800
#define UPVALUE_OFFSET (CONST_OFFSET + 0x400)
#define LVARS_OFFSET   (UPVALUE_OFFSET + 0x200)

#define LUA_INVALID_INSTRUCTION (-1)
#define LUA_MAX_ARGS0           3
#define LUA_MAX_ARGS4           4

#define print_isk isk ? " k" : ""

/*
@@ LUAI_BITSINT defines the (minimum) number of bits in an 'int'.
*/
/* avoid undefined shifts */
#if ((INT_MAX >> 15) >> 15) >= 1
#define LUAI_BITSINT 32
#else
/* 'int' always must have at least 16 bits */
#define LUAI_BITSINT 16
#endif

/* parameter flags */
#define PARAM_A   1
#define PARAM_B   2
#define PARAM_C   4
#define PARAM_Ax  8
#define PARAM_Bx  16
#define PARAM_sBx 32
#define PARAM_sJ  64
#define PARAM_sC  128
#define PARAM_sB  256
#define PARAM_k   512

#define SIZE_A 8
#define POS_OP 0

#define SIZE_OP0 6
#define SIZE_OP4 7

#define SIZE_B0  9
#define SIZE_C0  9
#define SIZE_Bx0 (SIZE_C0 + SIZE_B0)

#define POS_C0  SIZE_OP0
#define POS_B0  (POS_C0 + SIZE_C0)
#define POS_Bx0 POS_C0

#define POS_B1 (POS_C1 + SIZE_C0)
#define POS_A0 (POS_B0 + SIZE_B0)
#define POS_A1 (POS_OP + SIZE_OP0)

#define POS_Ax1 POS_A1
#define POS_A4  (POS_OP + SIZE_OP4)
#define POS_Ax4 POS_A4

#define POS_C1 (POS_A1 + SIZE_A)

#define POS_Ax POS_A
#define POS_sJ POS_A

#define GETARG_C1(i) getarg(i, POS_C1, SIZE_C0)
#define GETARG_C0(i) getarg(i, POS_C0, SIZE_C0)

#define SIZE_Ax2 (SIZE_C0 + SIZE_B0 + SIZE_A)

#define SIZE_B4 8
#define SIZE_C4 8

#define SIZE_Bx4 (SIZE_C4 + SIZE_B4 + 1)
#define SIZE_Ax4 (SIZE_Bx4 + SIZE_A)
#define SIZE_sJ4 SIZE_Ax4

#define POS_k4  (POS_A4 + SIZE_A)
#define POS_C4  (POS_B4 + SIZE_B4)
#define POS_B4  (POS_k4 + 1)
#define POS_Bx4 POS_k4
#define POS_sJ4 POS_A4

#define SIZE_vC 10
#define SIZE_vB 6
#define POS_vB  (POS_k4 + 1)
#define POS_vC  (POS_vB + SIZE_vB)

/* type casts (a macro highlights casts in the code) */
#define cast(t, exp) ((t)(exp))

#define MYK(x) (-1 - (x))

/* creates a mask with 'n' 1 bits at position 'p' */
#define MASK1(n, p) ((~((~(LuaInstruction)0) << (n))) << (p))
/* creates a mask with 'n' 0 bits at position 'p' */
#define MASK0(n, p) (~MASK1(n, p))

/*
** limits for opcode arguments.
** we use (signed) int to manipulate most arguments,
** so they must fit in LUAI_BITSINT-1 bits (-1 for sign)
*/

/* 5.0-5.3 */
#if SIZE_Bx0 < LUAI_BITSINT - 1
#define MAXARG_Bx0 ((1 << SIZE_Bx0) - 1)
#define MAXARG_sBx (MAXARG_Bx0 >> 1) /* 'sBx' is signed */
#else
#define MAXARG_Bx0 INT_MAX
#define MAXARG_sBx INT_MAX
#endif

#define MAXARG_A0 ((1 << SIZE_A) - 1)
#define MAXARG_B0 ((1 << SIZE_B0) - 1)
#define MAXARG_C0 ((1 << SIZE_C0) - 1)

/* 5.1-5.3 */
/*
** Macros to operate RK indices
*/

/* this bit 1 means constant (0 means register) */
#define BITRK (1 << (SIZE_B0 - 1))

/* test whether value is a constant */
#define ISK(x) ((x) & BITRK)

/* gets the index of the constant */
#define INDEXK(r) ((int)(r) & ~BITRK)

#if !defined(MAXINDEXRK) /* (for debugging only) */
#define MAXINDEXRK (BITRK - 1)
#endif

/* code a constant index as a RK value */
#define RKASK(x) ((x) | BITRK)

/* 5.2-5.3 */
#if SIZE_Ax2 < LUAI_BITSINT - 1
#define MAXARG_Ax2 ((1 << SIZE_Ax2) - 1)
#else
#define MAXARG_Ax2 INT_MAX
#endif

#define GET_OPCODE50(i) (cast(LuaOpCode50, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE51(i) (cast(LuaOpCode51, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE52(i) (cast(LuaOpCode52, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE53(i) (cast(LuaOpCode53, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE54(i) (cast(LuaOpCode54, ((i) >> POS_OP) & MASK1(SIZE_OP4, 0)))
#define GET_OPCODE55(i) (cast(LuaOpCode55, ((i) >> POS_OP) & MASK1(SIZE_OP4, 0)))

#define SET_OPCODE50(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | cast(LuaInstruction, o)))
#define SET_OPCODE51(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP0, POS_OP))))
#define SET_OPCODE52(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP0, POS_OP))))
#define SET_OPCODE53(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP0, POS_OP))))
#define SET_OPCODE54(i, o) \
	((i) = (((i) & MASK0(SIZE_OP4, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP4, POS_OP))))
#define SET_OPCODE55(i, o) \
	((i) = (((i) & MASK0(SIZE_OP4, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP4, POS_OP))))

#define getarg(i, pos, size) \
	(cast(int, ((i) >> (pos)) & MASK1(size, 0)))
#define setarg(i, v, pos, size) \
	((i) = (((i) & MASK0(size, pos)) | \
		 ((cast(LuaInstruction, v) << pos) & MASK1(size, pos))))

/* 5.0 */
#define GETARG_A0(i)    (cast(int, (i) >> POS_A0))
#define SETARG_A0(i, u) ( \
	(i) = (((i) & MASK0(SIZE_A, POS_A0)) | \
		((cast(LuaInstruction, u) << POS_A0) & MASK1(SIZE_A, POS_A0))))

/* 5.0-5.5 */
#define SETARG_B0(i, v) setarg(i, v, POS_B0, SIZE_B0)
#define SETARG_B1(i, v) setarg(i, v, POS_B1, SIZE_B0)
#define SETARG_B4(i, v) setarg(i, v, POS_B4, SIZE_B4)

#define SETARG_C0(i, v) setarg(i, v, POS_C0, SIZE_C0)
#define SETARG_C4(i, v) setarg(i, v, POS_C4, SIZE_C4)

#define SETARG_Bx0(i, v) setarg(i, v, POS_Bx0, SIZE_Bx0)
#define SETARG_Bx4(i, v) setarg(i, v, POS_Bx4, SIZE_Bx4)

/* 5.1 */
#define GETARG_B1(i) (cast(int, ((i) >> POS_B1) & MASK1(SIZE_B0, 0)))

/* 5.0-5.3 */
#define GETARG_B0(i)  getarg(i, POS_B0, SIZE_B0)
#define GETARG_Bx0(i) getarg(i, POS_Bx0, SIZE_Bx0)

#define SETARG_C1(i, v) setarg(i, v, POS_C1, SIZE_C0)

#define POS_Bx1          POS_C1
#define GETARG_Bx1(i)    getarg(i, POS_Bx1, SIZE_Bx0)
#define SETARG_Bx1(i, v) setarg(i, v, POS_Bx1, SIZE_Bx0)

#define GETARG_sBx1(i)    (GETARG_Bx1(i) - MAXARG_sBx)
#define SETARG_sBx1(i, b) SETARG_Bx1((i), cast(ut32, (b) + MAXARG_sBx))

#define GETARG_sBx0(i)    (GETARG_Bx0(i) - MAXARG_sBx)
#define SETARG_sBx0(i, b) SETARG_Bx0((i), cast(ut32, (b) + MAXARG_sBx))

/* 5.1-5.5 */
#define GETARG_A1(i)    getarg(i, POS_A1, SIZE_A)
#define GETARG_A4(i)    getarg(i, POS_A4, SIZE_A)
#define SETARG_A1(i, v) setarg(i, v, POS_A1, SIZE_A)
#define SETARG_A4(i, v) setarg(i, v, POS_A4, SIZE_A)

/* 5.2-5.3 */
#define GETARG_Ax2(i)    getarg(i, POS_Ax1, SIZE_Ax2)
#define SETARG_Ax2(i, v) setarg(i, v, POS_Ax1, SIZE_Ax2)

/* 5.4 */
/* Check whether type 'int' has at least 'b' bits ('b' < 32) */
#define L_INTHASBITS4(b) ((UINT_MAX >> ((b) - 1)) >= 1)
#if L_INTHASBITS4(SIZE_Bx4)
#define MAXARG_Bx5 ((1 << SIZE_Bx4) - 1)
#else
#define MAXARG_Bx INT_MAX
#endif

#if L_INTHASBITS4(SIZE_Ax4)
#define MAXARG_Ax ((1 << SIZE_Ax4) - 1)
#else
#define MAXARG_Ax INT_MAX
#endif

#if L_INTHASBITS4(SIZE_sJ4)
#define MAXARG_sJ ((1 << SIZE_sJ4) - 1)
#else
#define MAXARG_sJ INT_MAX
#endif

/* 5.5 */
/*
** Check whether type 'int' has at least 'b' + 1 bits.
** 'b' < 32; +1 for the sign bit.
*/
#define L_INTHASBITS5(b) ((UINT_MAX >> (b)) >= 1)
#if L_INTHASBITS5(SIZE_Bx4)
#define MAXARG_Bx ((1 << SIZE_Bx4) - 1)
#else
#define MAXARG_Bx INT_MAX
#endif

#if L_INTHASBITS5(SIZE_Ax4)
#define MAXARG_Ax ((1 << SIZE_Ax4) - 1)
#else
#define MAXARG_Ax INT_MAX
#endif

#if L_INTHASBITS5(SIZE_sJ4)
#define MAXARG_sJ ((1 << SIZE_sJ4) - 1)
#else
#define MAXARG_sJ INT_MAX
#endif

/* 5.4-5.5 */
#define OFFSET_sBx (MAXARG_Bx >> 1) /* 'sBx' is signed */
#define OFFSET_sJ  (MAXARG_sJ >> 1)

#define MAXARG_A  ((1 << SIZE_A) - 1)
#define MAXARG_B4 ((1 << SIZE_B4) - 1)
#define MAXARG_C4 ((1 << SIZE_C4) - 1)
#define OFFSET_sC (MAXARG_C4 >> 1)

#if !defined(MAXINDEXRK) /* (for debugging only) */
#define MAXINDEXRK MAXARG_B
#endif

/*
** Maximum size for the stack of a Lua function. It must fit in 8 bits.
** The highest valid register is one less than this value.
*/
#define MAX_FSTACK MAXARG_A

/*
** Invalid register (one more than last valid register).
*/
#define NO_REG MAX_FSTACK

#define int2sC(i) ((i) + OFFSET_sC)
#define sC2int(i) ((i) - OFFSET_sC)

#define SETARG_sC(i, v) SETARG_C4((i), int2sC(v))
#define SETARG_sB(i, v) SETARG_B4((i), int2sC(v))

#define CREATE_Ax4(o, a) \
	((cast(LuaInstruction, o) << POS_OP) | (cast(LuaInstruction, a) << POS_Ax))

#define GETARG_B4(i) getarg(i, POS_B4, SIZE_B4)

#define GETARG_sB(i) sC2int(GETARG_B4(i))
#define GETARG_C4(i) getarg(i, POS_C4, SIZE_C4)

#define GETARG_sC(i)  sC2int(GETARG_C4(i))
#define GETARG_Bx4(i) getarg(i, POS_Bx4, SIZE_Bx4)

#define cast_ut32(i)   cast(ut32, (i))
#define cast_st32(i)   cast(st32, (i))
#define GETARG_sBx4(i) getarg(i, POS_Bx4, SIZE_Bx4) - OFFSET_sBx

#define SETARG_sBx4(i, b) SETARG_Bx4((i), cast_ut32((b) + OFFSET_sBx))
#define GETARG_Ax4(i)     getarg(i, POS_Ax4, SIZE_Ax4)
#define SETARG_Ax4(i, v)  setarg(i, v, POS_Ax4, SIZE_Ax4)

#define GETARG_sJ(i) getarg(i, POS_sJ4, SIZE_sJ4) - OFFSET_sJ
#define SETARG_sJ(i, j) \
	setarg(i, cast_ut32((j) + OFFSET_sJ), POS_sJ4, SIZE_sJ4)

#define SETARG_k(i, v) setarg(i, v, POS_k4, 1)

#define GETARG_k4(i) getarg(i, POS_k4, 1)

#define has_param_flag(flag, bit) ((flag) & (bit)) ? true : false

#define lua_strcase(case_str) if ( \
	((limit) <= strlen(case_str)) && \
	rz_str_ncasecmp((name), (case_str), strlen(case_str)) == 0)

#define DISASM(ver) \
	int lua##ver##_disasm(RzAsmOp *op, ut32 instruction) { \
		const LuaOpCode##ver opcode = GET_OPCODE##ver(instruction); \
		get_asm_string##ver(opcode, instruction, &op->buf_asm); \
		return op->size; \
	}

#define ASM(ver) \
	ut32 lua##ver##_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start) { \
		const ut8 opcode = get_lua##ver##_opcode_by_name(opcode_start, opcode_len); \
		return get_instruction##ver(opcode, arg_start); \
	}

#define FMT(buffer, fmt, ...) \
	fmt_str(sizeof(buffer), (buffer), (fmt), __VA_ARGS__)

RZ_IPI char *fmt_str(size_t len, char *buffer, const char *fmt, ...);
RZ_IPI char *get_k(const RzAnalysis *analysis, ut64 addr, ut32 index, char *out_buffer);

#define SCOPE(x) (x == 0) ? (char *)FMT((char[5]){ 0 }, "%s", "_ENV") : (char *)FMT((char[8]){ 0 }, "r%" PFMT32d, x)
#define SCOPEa   SCOPE(a)
#define SCOPEb   SCOPE(b)

#define RKC  (char *)FMT((char[128]){ 0 }, k ? "%" PFMT32d : "r%" PFMT32d, c)
#define RKC4 (char *)FMT((char[128]){ 0 }, isk ? "%" PFMT32d "k" : "r%" PFMT32d, c)

#define ISRKix(x) ISK(x) ? FMT((char[128]){ 0 }, "%" PFMT32d, (MYK(INDEXK(x)))) : FMT((char[128]){ 0 }, "r%" PFMT32d, x)
#define ISRKx(x)  ISK(x) ? FMT((char[128]){ 0 }, "%s", get_k(analysis, addr, INDEXK(x), (char[128]){ 0 })) : FMT((char[128]){ 0 }, "r%" PFMT32d, x)
#define Kst(x)    FMT((char[128]){ 0 }, "%s", get_k(analysis, addr, INDEXK(x), (char[128]){ 0 }))

#define ISRKBi ISRKix(b)
#define ISRKCi ISRKix(c)

#define ISRKBk ISRKx(b)
#define ISRKCk ISRKx(c)

#define TYPE_DST_SRC0_REG(t, dest, src0) \
	op->type = t; \
	op->dst = new_reg_item(analysis, dest); \
	op->src[0] = new_reg_item(analysis, src0); \
	break;

#define TYPE_CFMT_DST_SRC0_REG(t, comment_fmt, dest, src0) \
	rz_strf(comment, comment_fmt, dest, src0); \
	TYPE_DST_SRC0_REG(t, dest, src0) \
	break;

#define TYPE_DST_REG_SRC0_IMM(t, dest, src0) \
	op->type = t; \
	op->dst = new_reg_item(analysis, dest); \
	op->src[0] = new_imm_item((st64)src0); \
	break;

#define TYPE_CFMT_DST_REG_SRC0_IMM(t, comment_fmt, dest, src0) \
	rz_strf(comment, comment_fmt, dest, src0); \
	TYPE_DST_REG_SRC0_IMM(t, dest, src0); \
	break;

#define TYPE_DST_IMM_SRC0_REG(t, comment_fmt, dest, src0) \
	op->type = t; \
	op->dst = new_imm_item((st64)dest); \
	op->src[0] = new_reg_item(analysis, src0); \
	rz_strf(comment, comment_fmt, dest, src0); \
	break;

#define TYPE_DST_REG(t, dest) \
	op->type = t; \
	op->dst = new_reg_item(analysis, dest);

#define TYPE_DST_SRC_AB_REG(t, comment_fmt, dest, src0) \
	op->type = t; \
	op->dst = new_reg_item(analysis, dest); \
	op->src[0] = new_reg_item(analysis, src0); \
	rz_strf(comment, comment_fmt, dest, src0); \
	break;

#define TYPE_DST_SRC_ABC_REG(t, va, vb, vc) \
	op->type = t; \
	op->dst = new_reg_item(analysis, va); \
	op->src[0] = new_reg_item(analysis, vb); \
	op->src[1] = new_reg_item(analysis, vc);

#define DST_SRC_AB_REG_C_IMM() \
	op->dst = new_reg_item(analysis, a); \
	op->src[0] = new_reg_item(analysis, b); \
	op->src[1] = new_imm_item((st64)c);

#define JUMP_FAIL_OFFSET(j, f) \
	op->jump = addr + j; \
	op->fail = addr + f;

#define JUMP_FAIL_ABS(j, f) \
	op->jump = j; \
	op->fail = f;

#define op_call_args(ca) (ca > 1) ? (ca - 1) : (ca == 0 ? -1 : 0);

#define OP_CALL() \
	{ \
		ut64 paddr = PROTO_VADDRESS(c); \
		op->ptr = paddr; \
		JUMP_FAIL_ABS(paddr, addr + 4); \
		rz_analysis_xrefs_set(analysis, addr, paddr, RZ_ANALYSIS_XREF_TYPE_CALL); \
		int nparams = op_call_args(b); \
		int nresults = op_call_args(c); \
		op->val = (b > 0) ? (b - 1) : 0; \
		op->stackop = RZ_ANALYSIS_STACK_SET; \
		op->stackptr = (nresults != -1 ? nresults : 0) - (nparams != -1 ? nparams : 0); \
		char params_str[15] = "varargs"; \
		char results_str[15] = "all"; \
		if (b > 0) { \
			rz_strf(params_str, "%d", nparams); \
		} \
		if (c > 0) { \
			rz_strf(results_str, "%d", nresults); \
		} \
		rz_strf(comment, "%s in %s out", params_str, results_str); \
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_CALL, a, a); \
	}

#define OP_RET(t, va, vb) \
	{ \
		op->type = t; \
		op->type2 = RZ_ANALYSIS_OP_TYPE_RET; \
		op->eob = true; \
		op->stackop = RZ_ANALYSIS_STACK_INC; \
		op->stackptr = -4; \
		op->src[0] = new_reg_item(analysis, va); \
		if (vb > 0) { \
			rz_strf(comment, "return r%d(args: %d)", va, vb - 1); \
		} else { \
			rz_strf(comment, "return r%d(all varargs)", va); \
		} \
		break; \
	}

#define RKC_REG_OR_IMM(r, n) \
	if (r <= 0xFF) { \
		op->src[n] = new_reg_item(analysis, r); \
	} else { \
		const int k_idx = r & 0xFF; \
		op->src[n] = new_imm_item((st64)CONST_VADDRESS(addr, k_idx)); \
		op->src[n]->memref = 1; \
	}

#define ARITHMETIC_OP_0_3(t, fmt) \
	{ \
		op->type = t; \
		op->dst = new_reg_item(analysis, a); \
		RKC_REG_OR_IMM(b, 0); \
		RKC_REG_OR_IMM(c, 1); \
		rz_strf(comment, fmt, a, ISRKBi, ISRKCi); \
		break; \
	}

#define ARITHMETIC_OP_4_5(t, fmt, aa, ab, ac) \
	op->type = t; \
	DST_SRC_AB_REG_C_IMM(); \
	rz_strf(comment, fmt, aa, ab, ac);

/**
 * type for virtual-machine instructions
 * must be an unsigned with (at least) 4 bytes (see details in lopcodes.h)
 */
/* Opcode Instruction Type */
typedef ut32 LuaInstruction;
/* Macros/Typedefs used in luac */
typedef double LUA_NUMBER;
typedef ut64 LUA_INTEGER;
typedef ut32 LUA_INT;

typedef struct analysis_luac_context_t {
	ut32 prev_inst; ///< Previous instruction
	ut32 next_inst; ///< Next instruction
	LuaInstruction instruction;
	ut64 addr;
	RzAnalysisOpMask mask;
} AnalysisLuacContext;

/* opcode names */
typedef char **LuaOpNameList;

/**
 * \file
 * \brief Provides information for Tag methods.
 * WARNING: if you change the order of this enumeration,
 * grep "ORDER TM" and "ORDER OP"
 */
typedef enum {
	TM_INDEX,
	TM_NEWINDEX,
	TM_GC,
	TM_MODE,
	TM_LEN,
	TM_EQ, /* last tag method with fast access */
	TM_ADD,
	TM_SUB,
	TM_MUL,
	TM_MOD,
	TM_POW,
	TM_DIV,
	TM_IDIV,
	TM_BAND,
	TM_BOR,
	TM_BXOR,
	TM_SHL,
	TM_SHR,
	TM_UNM,
	TM_BNOT,
	TM_LT,
	TM_LE,
	TM_CONCAT,
	TM_CALL,
	TM_CLOSE,
	TM_N /* number of elements in the enum */
} LuaTMS54;

typedef enum {
	LUA_51_VERSION_VANILLA = 0,
	LUA_51_VERSION_OPENWRT = 0,
	LUA_51_VERSION_TPLINK = 1
} Lua51Versions;

RZ_IPI char *get_lua_tagnames(LuaTMS54 tms);

/* convert a 4-byte ut8 buffer into a lua instruction (ut32) */
RZ_IPI LuaInstruction lua_build_instruction(const ut8 *buf);
RZ_IPI void lua_set_instruction(LuaInstruction instruction, ut8 *data);
RZ_IPI int lua_load_next_arg_start(const char *raw_string, char *recv_buf);
RZ_IPI bool lua_is_valid_num_value_string(const char *str);

/* Free Opname List */
RZ_IPI bool free_lua_opnames(LuaOpNameList list);

/* Lua 5.5 specified */
RZ_IPI int lua55_disasm(RzAsmOp *op, ut32 instruction);
RZ_IPI int lua55_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len);
RZ_IPI ut32 lua55_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start);
RZ_IPI LuaOpNameList get_lua55_opnames(void);
RZ_IPI ut8 get_lua55_opcode_by_name(const char *name, int len);

/* Lua 5.4 specified */
RZ_IPI int lua54_disasm(RzAsmOp *op, ut32 instruction);
RZ_IPI int lua54_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len);
RZ_IPI ut32 lua54_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start);
RZ_IPI LuaOpNameList get_lua54_opnames(void);
RZ_IPI ut8 get_lua54_opcode_by_name(const char *name, int len);

/* Lua 5.3 specified */
RZ_IPI int lua53_disasm(RzAsmOp *op, ut32 instruction);
RZ_IPI int lua53_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len);
RZ_IPI ut32 lua53_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start);
RZ_IPI LuaOpNameList get_lua53_opnames(void);
RZ_IPI ut8 get_lua53_opcode_by_name(const char *name, int len);

/* Lua 5.2 specified */
RZ_IPI int lua52_disasm(RzAsmOp *op, ut32 instruction);
RZ_IPI int lua52_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len);
RZ_IPI ut32 lua52_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start);
RZ_IPI LuaOpNameList get_lua52_opnames(void);
RZ_IPI ut8 get_lua52_opcode_by_name(const char *name, int len);

/* Lua 5.1 specified */
RZ_IPI int lua51_disasm(RzAsmOp *op, ut32 instruction, int version);
RZ_IPI int lua51_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len);
RZ_IPI ut32 lua51_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start, int version);
RZ_IPI LuaOpNameList get_lua51_opnames(int version);
RZ_IPI ut8 get_lua51_opcode_by_name(const char *name, int limit);
RZ_IPI ut8 get_lua51_shuffled_opcode_by_index(int opcode, int version);
RZ_IPI ut8 get_lua51_opcode_shuffled_index_by_id(int opcode, int version);
char *get_lua51_opcode_name(int opcode);

/* Lua 5.0 specified */
RZ_IPI int lua50_disasm(RzAsmOp *op, ut32 instruction);
RZ_IPI int lua50_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len);
RZ_IPI ut32 lua50_assembly(const char *arg_start, st32 opcode_len, const char *opcode_start);
RZ_IPI LuaOpNameList get_lua50_opnames(void);
RZ_IPI ut8 get_lua50_opcode_by_name(const char *name, int len);

RZ_IPI ut64 get_k_vaddr(RzAnalysis *analysis, ut64 addr, int k_idx);
RZ_IPI char *get_const_string(const RzAnalysis *analysis, ut64 addr, ut32 index, st32 *data_len, char *out_buffer);
RZ_IPI ut64 get_const_address(const RzAnalysis *analysis, ut64 addr, ut32 index);
RZ_IPI ut64 get_upvalue_address(const RzAnalysis *analysis, ut64 addr, ut32 index);
RZ_IPI bool load_args_asm(const char *arg_start, int *args);

RZ_IPI RzAnalysisValue *new_reg_item(RzAnalysis *analysis, ut8 index);
RZ_IPI RzAnalysisValue *new_imm_item(st64 value);

RZ_IPI bool analysis_op_4_5(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, ut16 opcode, ut8 minor);
#endif // BUILD_LUA_ARCH_H
