// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_a.h"

#include "analysis_private.h"
#include "capstone.h"

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// Decoder: rd=REG[0], addr=MEM[1].base  (lr.w / lr.d)
#define DECODE_RD_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *addr = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].mem.base);

// Decoder: rd=REG[0], addr=MEM[1].base, rs2=REG[2]  (sc.* / amo*.*)
#define DECODE_RD_MEM_RS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *addr = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[2].reg);

// 64-bit-only variants (RV64A .d instructions)
#define DECODE_RD_MEM_64(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	DECODE_RD_MEM(analysis, insn)

#define DECODE_RD_MEM_RS_64(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	DECODE_RD_MEM_RS(analysis, insn)

// A extension: atomic instructions (RV32A / RV64A)
//
// Sequential-execution assumption
// --------------------------------
// This entire file assumes the RzIL VM is completely sequential with no parallelism or
// asynchrony of any kind.  Under that assumption every "atomic" concern reduces as follows:
//
//   Acquire/release ordering (.aq / .rl / .aqrl variants)
//     Collapse to no-ops.  Ordering constraints only matter when multiple execution flows
//     share memory concurrently.  All ordering variants are therefore aliased to the base
//     instruction with no extra fence or barrier logic.
//
//   Load-Reserved / Store-Conditional reservations
//     RzIL has no native reservation primitive, so reservations are approximated rather
//     than modelled architecturally.  Under the strictly sequential assumptions above,
//     well-formed compiler-style LR/SC loops cannot suffer external invalidation from
//     another hart, DMA engine, interrupt handler, memory-mapped I/O side-effect, etc.
//     Therefore lr.* is implemented as a plain load and sc.* as an unconditional store
//     that reports success (rd = 0).
//
//     This is intentionally not fully faithful for reservation edge cases: standalone
//     SC instructions, repeated SC instructions after one LR, SC instructions targeting
//     a different reservation, or tests that deliberately expect SC failure will not be
//     distinguished here.
//
//   AMO read-modify-write atomicity
//     Is trivially preserved.  There is no window in which another execution flow could observe
//     or modify memory between the internal load and store, so the straightforward
//     SEQ-based implementation is sufficient under this file's assumptions.
//
// If the VM ever gains any form of parallelism or asynchrony — including but not limited
// to hardware threads (harts), DMA engines, memory-mapped I/O with side-effects, interrupt
// delivery modelled between individual instructions, or speculative / out-of-order execution
// — this file MUST be revisited.

// Load-Reserved: plain load as in riscv_il_integer.h; reservation is not modelled
DEFINE_LIFTER(lr_w, DECODE_RD_MEM,
	analysis->bits == 32 ? LOADW(32, addr) : SIGNED(analysis->bits, LOADW(32, addr)))
DEFINE_ALIAS_LIFTER(lr_w_aq, lr_w)
DEFINE_ALIAS_LIFTER(lr_w_rl, lr_w)
DEFINE_ALIAS_LIFTER(lr_w_aqrl, lr_w)

DEFINE_LIFTER(lr_d, DECODE_RD_MEM_64, LOADW(64, addr))
DEFINE_ALIAS_LIFTER(lr_d_aq, lr_d)
DEFINE_ALIAS_LIFTER(lr_d_rl, lr_d)
DEFINE_ALIAS_LIFTER(lr_d_aqrl, lr_d)

// Store-Conditional: unconditional store as in riscv_il_integer.h, rd = 0 (always succeeds; see sequential assumption above)
DEFINE_LIFTER_WITH_PRE_EFFECT(sc_w, DECODE_RD_MEM_RS,
	STOREW(addr, CAST(32, IL_FALSE, rs2)),
	UN(analysis->bits, 0))
DEFINE_ALIAS_LIFTER(sc_w_aq, sc_w)
DEFINE_ALIAS_LIFTER(sc_w_rl, sc_w)
DEFINE_ALIAS_LIFTER(sc_w_aqrl, sc_w)

DEFINE_LIFTER_WITH_PRE_EFFECT(sc_d, DECODE_RD_MEM_RS_64,
	STOREW(addr, rs2),
	UN(analysis->bits, 0))
DEFINE_ALIAS_LIFTER(sc_d_aq, sc_d)
DEFINE_ALIAS_LIFTER(sc_d_rl, sc_d)
DEFINE_ALIAS_LIFTER(sc_d_aqrl, sc_d)

// AMO .w helper: atomically read-modify-write 32-bit memory, return old value sign-extended to XLEN.
// new32 may reference VARL("_v32") (old 32-bit mem val) and VARL("_r32") (rs2 lower 32 bits).
#define AMO_W(rd, addr, rs2, new32) \
	SEQ5( \
		SETL("_a", (addr)), \
		SETL("_v32", LOADW(32, VARL("_a"))), \
		SETL("_r32", CAST(32, IL_FALSE, (rs2))), \
		STOREW(VARL("_a"), (new32)), \
		riscv_il_set_reg((rd), SIGNED(analysis->bits, VARL("_v32"))))

// AMO .d helper: atomically read-modify-write 64-bit memory, return old value in rd.
// new64 may reference VARL("_v") (old 64-bit mem val) and VARL("_r") (rs2).
#define AMO_D(rd, addr, rs2, new64) \
	SEQ5( \
		SETL("_a", (addr)), \
		SETL("_v", LOADW(64, VARL("_a"))), \
		SETL("_r", (rs2)), \
		STOREW(VARL("_a"), (new64)), \
		riscv_il_set_reg((rd), VARL("_v")))

// AMO swap: mem = rs2, rd = old_mem
DEFINE_LIFTER_WITH_EFFECT(amoswap_w, DECODE_RD_MEM_RS, AMO_W(rd, addr, rs2, VARL("_r32")))
DEFINE_ALIAS_LIFTER(amoswap_w_aq, amoswap_w)
DEFINE_ALIAS_LIFTER(amoswap_w_rl, amoswap_w)
DEFINE_ALIAS_LIFTER(amoswap_w_aqrl, amoswap_w)

DEFINE_LIFTER_WITH_EFFECT(amoswap_d, DECODE_RD_MEM_RS_64, AMO_D(rd, addr, rs2, VARL("_r")))
DEFINE_ALIAS_LIFTER(amoswap_d_aq, amoswap_d)
DEFINE_ALIAS_LIFTER(amoswap_d_rl, amoswap_d)
DEFINE_ALIAS_LIFTER(amoswap_d_aqrl, amoswap_d)

// AMO add
DEFINE_LIFTER_WITH_EFFECT(amoadd_w, DECODE_RD_MEM_RS, AMO_W(rd, addr, rs2, ADD(VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amoadd_w_aq, amoadd_w)
DEFINE_ALIAS_LIFTER(amoadd_w_rl, amoadd_w)
DEFINE_ALIAS_LIFTER(amoadd_w_aqrl, amoadd_w)

DEFINE_LIFTER_WITH_EFFECT(amoadd_d, DECODE_RD_MEM_RS_64, AMO_D(rd, addr, rs2, ADD(VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amoadd_d_aq, amoadd_d)
DEFINE_ALIAS_LIFTER(amoadd_d_rl, amoadd_d)
DEFINE_ALIAS_LIFTER(amoadd_d_aqrl, amoadd_d)

// AMO xor
DEFINE_LIFTER_WITH_EFFECT(amoxor_w, DECODE_RD_MEM_RS, AMO_W(rd, addr, rs2, LOGXOR(VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amoxor_w_aq, amoxor_w)
DEFINE_ALIAS_LIFTER(amoxor_w_rl, amoxor_w)
DEFINE_ALIAS_LIFTER(amoxor_w_aqrl, amoxor_w)

DEFINE_LIFTER_WITH_EFFECT(amoxor_d, DECODE_RD_MEM_RS_64, AMO_D(rd, addr, rs2, LOGXOR(VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amoxor_d_aq, amoxor_d)
DEFINE_ALIAS_LIFTER(amoxor_d_rl, amoxor_d)
DEFINE_ALIAS_LIFTER(amoxor_d_aqrl, amoxor_d)

// AMO and
DEFINE_LIFTER_WITH_EFFECT(amoand_w, DECODE_RD_MEM_RS, AMO_W(rd, addr, rs2, LOGAND(VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amoand_w_aq, amoand_w)
DEFINE_ALIAS_LIFTER(amoand_w_rl, amoand_w)
DEFINE_ALIAS_LIFTER(amoand_w_aqrl, amoand_w)

DEFINE_LIFTER_WITH_EFFECT(amoand_d, DECODE_RD_MEM_RS_64, AMO_D(rd, addr, rs2, LOGAND(VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amoand_d_aq, amoand_d)
DEFINE_ALIAS_LIFTER(amoand_d_rl, amoand_d)
DEFINE_ALIAS_LIFTER(amoand_d_aqrl, amoand_d)

// AMO or
DEFINE_LIFTER_WITH_EFFECT(amoor_w, DECODE_RD_MEM_RS, AMO_W(rd, addr, rs2, LOGOR(VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amoor_w_aq, amoor_w)
DEFINE_ALIAS_LIFTER(amoor_w_rl, amoor_w)
DEFINE_ALIAS_LIFTER(amoor_w_aqrl, amoor_w)

DEFINE_LIFTER_WITH_EFFECT(amoor_d, DECODE_RD_MEM_RS_64, AMO_D(rd, addr, rs2, LOGOR(VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amoor_d_aq, amoor_d)
DEFINE_ALIAS_LIFTER(amoor_d_rl, amoor_d)
DEFINE_ALIAS_LIFTER(amoor_d_aqrl, amoor_d)

// AMO signed min/max: operands are 32-bit bitvectors (_v32, _r32), so SLT/SGT is 32-bit signed
DEFINE_LIFTER_WITH_EFFECT(amomin_w, DECODE_RD_MEM_RS,
	AMO_W(rd, addr, rs2, ITE(SLT(VARL("_v32"), VARL("_r32")), VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amomin_w_aq, amomin_w)
DEFINE_ALIAS_LIFTER(amomin_w_rl, amomin_w)
DEFINE_ALIAS_LIFTER(amomin_w_aqrl, amomin_w)

DEFINE_LIFTER_WITH_EFFECT(amomin_d, DECODE_RD_MEM_RS_64,
	AMO_D(rd, addr, rs2, ITE(SLT(VARL("_v"), VARL("_r")), VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amomin_d_aq, amomin_d)
DEFINE_ALIAS_LIFTER(amomin_d_rl, amomin_d)
DEFINE_ALIAS_LIFTER(amomin_d_aqrl, amomin_d)

DEFINE_LIFTER_WITH_EFFECT(amomax_w, DECODE_RD_MEM_RS,
	AMO_W(rd, addr, rs2, ITE(SGT(VARL("_v32"), VARL("_r32")), VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amomax_w_aq, amomax_w)
DEFINE_ALIAS_LIFTER(amomax_w_rl, amomax_w)
DEFINE_ALIAS_LIFTER(amomax_w_aqrl, amomax_w)

DEFINE_LIFTER_WITH_EFFECT(amomax_d, DECODE_RD_MEM_RS_64,
	AMO_D(rd, addr, rs2, ITE(SGT(VARL("_v"), VARL("_r")), VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amomax_d_aq, amomax_d)
DEFINE_ALIAS_LIFTER(amomax_d_rl, amomax_d)
DEFINE_ALIAS_LIFTER(amomax_d_aqrl, amomax_d)

// AMO unsigned min/max: _v32/_r32 are 32-bit bitvectors, so ULT/UGT is 32-bit unsigned
DEFINE_LIFTER_WITH_EFFECT(amominu_w, DECODE_RD_MEM_RS,
	AMO_W(rd, addr, rs2, ITE(ULT(VARL("_v32"), VARL("_r32")), VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amominu_w_aq, amominu_w)
DEFINE_ALIAS_LIFTER(amominu_w_rl, amominu_w)
DEFINE_ALIAS_LIFTER(amominu_w_aqrl, amominu_w)

DEFINE_LIFTER_WITH_EFFECT(amominu_d, DECODE_RD_MEM_RS_64,
	AMO_D(rd, addr, rs2, ITE(ULT(VARL("_v"), VARL("_r")), VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amominu_d_aq, amominu_d)
DEFINE_ALIAS_LIFTER(amominu_d_rl, amominu_d)
DEFINE_ALIAS_LIFTER(amominu_d_aqrl, amominu_d)

DEFINE_LIFTER_WITH_EFFECT(amomaxu_w, DECODE_RD_MEM_RS,
	AMO_W(rd, addr, rs2, ITE(UGT(VARL("_v32"), VARL("_r32")), VARL("_v32"), VARL("_r32"))))
DEFINE_ALIAS_LIFTER(amomaxu_w_aq, amomaxu_w)
DEFINE_ALIAS_LIFTER(amomaxu_w_rl, amomaxu_w)
DEFINE_ALIAS_LIFTER(amomaxu_w_aqrl, amomaxu_w)

DEFINE_LIFTER_WITH_EFFECT(amomaxu_d, DECODE_RD_MEM_RS_64,
	AMO_D(rd, addr, rs2, ITE(UGT(VARL("_v"), VARL("_r")), VARL("_v"), VARL("_r"))))
DEFINE_ALIAS_LIFTER(amomaxu_d_aq, amomaxu_d)
DEFINE_ALIAS_LIFTER(amomaxu_d_rl, amomaxu_d)
DEFINE_ALIAS_LIFTER(amomaxu_d_aqrl, amomaxu_d)

#undef DECODE_RD_MEM
#undef DECODE_RD_MEM_RS
#undef DECODE_RD_MEM_64
#undef DECODE_RD_MEM_RS_64
#undef AMO_W
#undef AMO_D

#include <rz_il/rz_il_opbuilder_end.h>
