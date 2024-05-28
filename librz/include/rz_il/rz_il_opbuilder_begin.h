// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Syntax Macros for RzIL Lifting
 *
 * This header introduces a number of short macros for conveniently building RzIL
 * expressions without having to type out `rz_il_op_new_...`.
 *
 * It is intended to be used like this, for example when lifting IL from an architecture:
 *
 *     #include <rz_il/rz_il_opbuilder_begin.h>
 *
 *     RzILOpEffect *lift_my_op() {
 *         return SEQ3(
 *             SETG("a", U8(42)),
 *             SETG("x", U8(123)),
 *             STORE(0xcafe, VARG("a")));
 *     }
 *
 *     #include <rz_il/rz_il_opbuilder_end.h>
 *
 * Because of their short nature, these macros may conflict with other code. As such,
 * it should never be included in any public headers, and should be closed by an
 * `#include <rz_il/rz_il_opbuilder_end.h>` when not needed anymore, which `#undef`s
 * everything again.
 *
 * Consequently, when editing this file, always make sure to keep `rz_il_opbuilder_end.h`
 * in sync!
 */

#ifndef RZ_IL_OPBUILDER_BEGIN_H
#define RZ_IL_OPBUILDER_BEGIN_H

#include <rz_il/rz_il_opcodes.h>

#define DUP(op) rz_il_op_pure_dup(op)

#define ITE(c, t, f) rz_il_op_new_ite(c, t, f)

#define UN(l, val)       rz_il_op_new_bitv_from_ut64(l, val)
#define U8(val)          UN(8, val)
#define U16(val)         UN(16, val)
#define U32(val)         UN(32, val)
#define U48(val)         UN(48, val)
#define U64(val)         UN(64, val)
#define CAST(l, f, v)    rz_il_op_new_cast(l, f, v)
#define BOOL_TO_BV(b, l) ITE(b, UN(l, 1), UN(l, 0))

#define SN(l, val) rz_il_op_new_bitv_from_st64(l, val)
#define S8(val)    SN(8, val)
#define S16(val)   SN(16, val)
#define S32(val)   SN(32, val)
#define S64(val)   SN(64, val)

#define BV2F(fmt, bv)              rz_il_op_new_float(fmt, bv)
#define F32(f32)                   rz_il_op_new_float_from_f32(f32)
#define F64(f64)                   rz_il_op_new_float_from_f64(f64)
#define F80(f80)                   rz_il_op_new_float_from_f80(f80)
#define F2BV(fl)                   rz_il_op_new_fbits(fl)
#define IS_FINITE(fl)              rz_il_op_new_is_finite(fl)
#define IS_FNAN(fl)                rz_il_op_new_is_nan(fl)
#define IS_FINF(fl)                rz_il_op_new_is_inf(fl)
#define IS_FZERO(fl)               rz_il_op_new_is_fzero(fl)
#define IS_FNEG(fl)                rz_il_op_new_is_fneg(fl)
#define IS_FPOS(fl)                rz_il_op_new_is_fpos(fl)
#define FNEG(fl)                   rz_il_op_new_fneg(fl)
#define FABS(fl)                   rz_il_op_new_fabs(fl)
#define F2INT(l, rmode, fl)        rz_il_op_new_fcast_int(l, rmode, fl)
#define F2SINT(l, rmode, fl)       rz_il_op_new_fcast_sint(l, rmode, fl)
#define INT2F(fmt, rmode, bv)      rz_il_op_new_fcast_float(fmt, rmode, bv)
#define SINT2F(fmt, rmode, bv)     rz_il_op_new_fcast_sfloat(fmt, rmode, bv)
#define FCONVERT(fmt, rmode, fl)   rz_il_op_new_fconvert(fmt, rmode, fl)
#define FLOATV16(bv)               rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_16, bv)
#define FLOATV32(bv)               rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_32, bv)
#define FLOATV64(bv)               rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_64, bv)
#define FLOATV128(bv)              rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_128, bv)
#define FSUCC(fl)                  rz_il_op_new_fsucc(fl)
#define FPRED(fl)                  rz_il_op_new_fpred(fl)
#define FORDER(flx, fly)           rz_il_op_new_forder(flx, fly)
#define FROUND(rmode, fl)          rz_il_op_new_fround(rmode, fl)
#define FSQRT(rmode, fl)           rz_il_op_new_fsqrt(rmode, fl)
#define FRSQRT(rmode, fl)          rz_il_op_new_frsqrt(rmode, fl)
#define FADD(rmode, flx, fly)      rz_il_op_new_fadd(rmode, flx, fly)
#define FSUB(rmode, flx, fly)      rz_il_op_new_fsub(rmode, flx, fly)
#define FMUL(rmode, flx, fly)      rz_il_op_new_fmul(rmode, flx, fly)
#define FDIV(rmode, flx, fly)      rz_il_op_new_fdiv(rmode, flx, fly)
#define FMOD(rmode, flx, fly)      rz_il_op_new_fdiv(rmode, flx, fly)
#define FPOW(rmode, flx, fly)      rz_il_op_new_fpow(rmode, flx, fly)
#define FMAD(rmode, flx, fly, flz) rz_il_op_new_fmad(rmode, flx, fly, flz)

#define IL_FQNAN(f) rz_il_op_new_float_from_rz_float(rz_float_new_qnan(f))
#define IL_FSNAN(f) rz_il_op_new_float_from_rz_float(rz_float_new_snan(f))

// TODO: add `feq` as prime operator in fbasic
// https://smtlib.cs.uiowa.edu/theories-FloatingPoint.shtml

#define IL_FALSE  rz_il_op_new_b0()
#define IL_TRUE   rz_il_op_new_b1()
#define INV(x)    rz_il_op_new_bool_inv(x)
#define XOR(x, y) rz_il_op_new_bool_xor(x, y)
#define AND(x, y) rz_il_op_new_bool_and(x, y)
#define OR(x, y)  rz_il_op_new_bool_or(x, y)

#define FNE(flx, fly) rz_il_op_new_fneq(flx, fly)
#define FEQ(flx, fly) rz_il_op_new_feq(flx, fly)
#define FLT(flx, fly) rz_il_op_new_flt(flx, fly)
#define FLE(flx, fly) rz_il_op_new_fle(flx, fly)
#define FGT(flx, fly) rz_il_op_new_fgt(flx, fly)
#define FGE(flx, fly) rz_il_op_new_fge(flx, fly)

#define UNSIGNED(n, x)    rz_il_op_new_unsigned(n, x)
#define SIGNED(n, x)      rz_il_op_new_signed(n, x)
#define APPEND(high, low) rz_il_op_new_append(high, low)

#define ADD(x, y)          rz_il_op_new_add(x, y)
#define SUB(x, y)          rz_il_op_new_sub(x, y)
#define MUL(x, y)          rz_il_op_new_mul(x, y)
#define DIV(x, y)          rz_il_op_new_div(x, y)
#define SDIV(x, y)         rz_il_op_new_sdiv(x, y)
#define MOD(x, y)          rz_il_op_new_mod(x, y)
#define SMOD(x, y)         rz_il_op_new_smod(x, y)
#define SHIFTL(f, v, dist) rz_il_op_new_shiftl(f, v, dist)
#define SHIFTR(f, v, dist) rz_il_op_new_shiftr(f, v, dist)
#define SHIFTL0(v, dist)   SHIFTL(IL_FALSE, v, dist)
#define SHIFTR0(v, dist)   SHIFTR(IL_FALSE, v, dist)
#define SHIFTRA(v, dist)   rz_il_op_new_shiftr_arith(v, dist)
#define LOGAND(x, y)       rz_il_op_new_log_and(x, y)
#define LOGOR(x, y)        rz_il_op_new_log_or(x, y)
#define LOGXOR(x, y)       rz_il_op_new_log_xor(x, y)
#define LOGNOT(x)          rz_il_op_new_log_not(x)
#define NEG(x)             rz_il_op_new_neg(x)

#define NON_ZERO(x) rz_il_op_new_non_zero(x)
#define IS_ZERO(x)  rz_il_op_new_is_zero(x)
#define MSB(x)      rz_il_op_new_msb(x)
#define LSB(x)      rz_il_op_new_lsb(x)
#define EQ(x, y)    rz_il_op_new_eq(x, y)
#define ULT(x, y)   rz_il_op_new_ult(x, y)
#define ULE(x, y)   rz_il_op_new_ule(x, y)
#define UGT(x, y)   rz_il_op_new_ugt(x, y)
#define UGE(x, y)   rz_il_op_new_uge(x, y)
#define SLT(x, y)   rz_il_op_new_slt(x, y)
#define SLE(x, y)   rz_il_op_new_sle(x, y)
#define SGT(x, y)   rz_il_op_new_sgt(x, y)
#define SGE(x, y)   rz_il_op_new_sge(x, y)

#define LOAD(addr)        rz_il_op_new_load(0, addr)
#define LOADW(n, addr)    rz_il_op_new_loadw(0, addr, n)
#define STORE(addr, val)  rz_il_op_new_store(0, addr, val)
#define STOREW(addr, val) rz_il_op_new_storew(0, addr, val)

#define VARG(name)         rz_il_op_new_var(name, RZ_IL_VAR_KIND_GLOBAL)
#define VARL(name)         rz_il_op_new_var(name, RZ_IL_VAR_KIND_LOCAL)
#define VARLP(name)        rz_il_op_new_var(name, RZ_IL_VAR_KIND_LOCAL_PURE)
#define SETG(name, v)      rz_il_op_new_set(name, false, v)
#define SETL(name, v)      rz_il_op_new_set(name, true, v)
#define LET(name, v, body) rz_il_op_new_let(name, v, body)

#define SEQ2(e0, e1)                             rz_il_op_new_seq(e0, e1)
#define SEQ3(e0, e1, e2)                         rz_il_op_new_seqn(3, e0, e1, e2)
#define SEQ4(e0, e1, e2, e3)                     rz_il_op_new_seqn(4, e0, e1, e2, e3)
#define SEQ5(e0, e1, e2, e3, e4)                 rz_il_op_new_seqn(5, e0, e1, e2, e3, e4)
#define SEQ6(e0, e1, e2, e3, e4, e5)             rz_il_op_new_seqn(6, e0, e1, e2, e3, e4, e5)
#define SEQ7(e0, e1, e2, e3, e4, e5, e6)         rz_il_op_new_seqn(7, e0, e1, e2, e3, e4, e5, e6)
#define SEQ8(e0, e1, e2, e3, e4, e5, e6, e7)     rz_il_op_new_seqn(8, e0, e1, e2, e3, e4, e5, e6, e7)
#define SEQ9(e0, e1, e2, e3, e4, e5, e6, e7, e8) rz_il_op_new_seqn(9, e0, e1, e2, e3, e4, e5, e6, e7, e8)
#define SEQN(n, ...)                             rz_il_op_new_seqn(n, __VA_ARGS__)

#define EMPTY()         rz_il_op_new_empty()
#define NOP()           rz_il_op_new_nop()
#define BRANCH(c, t, f) rz_il_op_new_branch(c, t, f)
#define REPEAT(c, b)    rz_il_op_new_repeat(c, b)
#define JMP(tgt)        rz_il_op_new_jmp(tgt)
#define GOTO(lbl)       rz_il_op_new_goto(lbl)

#define NOT_IMPLEMENTED \
	do { \
		RZ_LOG_INFO("IL instruction not implemented.\n"); \
		return NULL; \
	} while (0)

#define EXTRACT32(value, start, length)           rz_il_extract32(value, start, length)
#define EXTRACT64(value, start, length)           rz_il_extract64(value, start, length)
#define SEXTRACT32(value, start, length)          rz_il_sextract32(value, start, length)
#define SEXTRACT64(value, start, length)          rz_il_sextract64(value, start, length)
#define DEPOSIT32(value, start, length, fieldval) rz_il_deposit32(value, start, length, fieldval)
#define DEPOSIT64(value, start, length, fieldval) rz_il_deposit64(value, start, length, fieldval)
#define BSWAP16(t)                                rz_il_bswap16(t)
#define BSWAP32(t)                                rz_il_bswap32(t)
#define BSWAP64(t)                                rz_il_bswap64(t)
#define NE(x, y)                                  rz_il_op_new_ne(x, y)

#endif
