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
 *         return SEQ(3,
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

#include "rz_il_opcodes.h"

#define ITE(c, t, f) rz_il_op_new_ite(c, t, f)

#define UN(l, val) rz_il_op_new_bitv_from_ut64(l, val)
#define U8(val)    UN(8, val)
#define U16(val)   UN(16, val)
#define U32(val)   UN(32, val)
#define U64(val)   UN(64, val)

#define SN(l, val) rz_il_op_new_bitv_from_st64(l, val)
#define S8(val)    SN(8, val)
#define S16(val)   SN(16, val)
#define S32(val)   SN(32, val)
#define S64(val)   SN(64, val)

#define IL_FALSE  rz_il_op_new_b0()
#define IL_TRUE   rz_il_op_new_b1()
#define INV(x)    rz_il_op_new_bool_inv(x)
#define XOR(x, y) rz_il_op_new_bool_xor(x, y)
#define AND(x, y) rz_il_op_new_bool_and(x, y)

#define ADD(x, y)        rz_il_op_new_add(x, y)
#define SUB(x, y)        rz_il_op_new_sub(x, y)
#define SHIFTL0(v, dist) rz_il_op_new_shiftl(IL_FALSE, v, dist)
#define SHIFTR0(v, dist) rz_il_op_new_shiftr(IL_FALSE, v, dist)
#define LOGAND(x, y)     rz_il_op_new_log_and(x, y)
#define LOGOR(x, y)      rz_il_op_new_log_or(x, y)
#define LOGXOR(x, y)     rz_il_op_new_log_xor(x, y)

#define IS_ZERO(x) rz_il_op_new_is_zero(x)
#define MSB(x)     rz_il_op_new_msb(x)
#define LSB(x)     rz_il_op_new_lsb(x)
#define ULT(x, y)  rz_il_op_new_ult(x, y)
#define ULE(x, y)  rz_il_op_new_ule(x, y)

#define LOAD(addr)       rz_il_op_new_load(0, addr)
#define LOADW(n, addr)   rz_il_op_new_loadw(0, addr, n)
#define STORE(addr, val) rz_il_op_new_store(0, addr, val)

#define VARG(name)    rz_il_op_new_var(name, RZ_IL_VAR_KIND_GLOBAL)
#define VARL(name)    rz_il_op_new_var(name, RZ_IL_VAR_KIND_LOCAL)
#define VARLP(name)   rz_il_op_new_var(name, RZ_IL_VAR_KIND_LOCAL_PURE)
#define SETG(name, v) rz_il_op_new_set(name, false, v)
#define SETL(name, v) rz_il_op_new_set(name, true, v)

#define UNSIGNED(n, x)    rz_il_op_new_unsigned(n, x)
#define APPEND(high, low) rz_il_op_new_append(high, low)
#define DUP(op)           rz_il_op_pure_dup(op)

#define SEQ(n, ...)     rz_il_op_new_seqn(n, __VA_ARGS__)
#define SEQ2(e0, e1)    rz_il_op_new_seq(e0, e1)
#define NOP             rz_il_op_new_nop()
#define BRANCH(c, t, f) rz_il_op_new_branch(c, t, f)
#define JMP(tgt)        rz_il_op_new_jmp(tgt)

#endif
