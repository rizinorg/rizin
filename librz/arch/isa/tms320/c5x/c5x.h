// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * TMS320C5x (second-generation fixed-point DSP, e.g. TMS320C50/C51/C53).
 *
 * The C5x is source-compatible with the C2x (same assembly mnemonics) but uses
 * a completely different object encoding, so it has its own decode front-end
 * (c5x_decode, ported from the authoritative TMS320C5x opcode table) rather than
 * the C2x decode table. The decoder fills the shared C55Insn; shared-semantics
 * instructions reuse the C2x instruction ids and the C2x lifter, while the
 * C5x-only instructions (ACCB buffer ops, parallel-logic, memory-mapped register
 * access, conditional execute/call/return, block moves, ...) carry the C5X_INS_*
 * ids below and are handled by c5x_mnemonic/c5x_op_type/c5x_lift, which delegate
 * to the C2x consumers for the shared ids.
 */

#ifndef RZ_TMS320_C5X_H
#define RZ_TMS320_C5X_H

#include "../c2x/c2x.h"

#ifdef __cplusplus
extern "C" {
#endif

/// C5x-only instruction ids (shared-semantics ops reuse the C2X_INS_* ids). The
/// base sits above the C2x enum so the two id spaces never collide.
enum {
	C5X_INS_BASE = 0x200,
	C5X_INS_LACC, ///< load ACC with shift (C2x LAC)
	C5X_INS_LACL, ///< load ACC low, zero-extended
	C5X_INS_LACB, ///< load ACC from ACCB
	C5X_INS_SACB, ///< store ACC to ACCB
	C5X_INS_EXAR, ///< exchange ACC and ACCB
	C5X_INS_ADDB, ///< ACC += ACCB
	C5X_INS_SBB, ///< ACC -= ACCB
	C5X_INS_ADCB, ///< ACC += ACCB + carry
	C5X_INS_SBBB, ///< ACC -= ACCB + borrow
	C5X_INS_CRGT, ///< ACC = max(ACC, ACCB)
	C5X_INS_CRLT, ///< ACC = min(ACC, ACCB)
	C5X_INS_ANDB, ///< ACC &= ACCB
	C5X_INS_ORB, ///< ACC |= ACCB
	C5X_INS_XORB, ///< ACC ^= ACCB
	C5X_INS_ROLB, ///< rotate ACC:ACCB left through carry
	C5X_INS_RORB, ///< rotate ACC:ACCB right through carry
	C5X_INS_SFLB, ///< shift ACC:ACCB left
	C5X_INS_SFRB, ///< shift ACC:ACCB right
	C5X_INS_SAMM, ///< store ACC to a memory-mapped register
	C5X_INS_LAMM, ///< load ACC from a memory-mapped register
	C5X_INS_LMMR, ///< load a memory-mapped register (long immediate addr)
	C5X_INS_SMMR, ///< store a memory-mapped register (long immediate addr)
	C5X_INS_BLDD, ///< block move data to data
	C5X_INS_BLPD, ///< block move program to data
	C5X_INS_BLDP, ///< block move data to program
	C5X_INS_MADS, ///< multiply-accumulate with data move (BMAR address)
	C5X_INS_MADD, ///< multiply-accumulate with data move and delay
	C5X_INS_SPLK, ///< store parallel long immediate constant
	C5X_INS_BCND, ///< conditional branch
	C5X_INS_BCNDD, ///< delayed conditional branch
	C5X_INS_CC, ///< conditional call
	C5X_INS_CCD, ///< delayed conditional call
	C5X_INS_RETC, ///< conditional return
	C5X_INS_RETCD, ///< delayed conditional return
	C5X_INS_RETD, ///< unconditional delayed return
	C5X_INS_XC, ///< conditionally execute next n words
	C5X_INS_BSAR, ///< barrel shift ACC right
	C5X_INS_ZAP, ///< clear ACC and PREG
	C5X_INS_ZPR, ///< clear PREG
	C5X_INS_SATH, ///< saturate ACC high
	C5X_INS_SATL, ///< saturate ACC low
	C5X_INS_BACCD, ///< delayed branch to ACC address
	C5X_INS_CALAD, ///< delayed call to ACC address
	C5X_INS_APL, ///< AND data with DBMR / long immediate
	C5X_INS_OPL, ///< OR data with DBMR / long immediate
	C5X_INS_XPL, ///< XOR data with DBMR / long immediate
	C5X_INS_CPL, ///< compare data with DBMR / long immediate
	C5X_INS_RPTB, ///< repeat block
	C5X_INS_RPTZ, ///< repeat next instruction, clearing ACC and PREG
	C5X_INS_SETC, ///< set a control bit
	C5X_INS_CLRC, ///< clear a control bit
	C5X_INS_IDLE2, ///< idle until interrupt (low-power)
	C5X_INS_NMI, ///< non-maskable interrupt
	C5X_INS_RETE, ///< return from interrupt with enable
	C5X_INS_RETI, ///< return from interrupt
	C5X_INS_INTR, ///< software interrupt
	C5X_INS_BD, ///< delayed branch
	C5X_INS_CALLD, ///< delayed call
	C5X_INS_BANZD, ///< delayed branch on AR not zero
	C5X_INS_LST, ///< load status register STn (C5x `#n`, mem form)
	C5X_INS_SST, ///< store status register STn (C5x `#n`, mem form)
};

RZ_IPI int c5x_decode(const ut8 *buf, int len, C55Insn *out);

RZ_IPI const char *c5x_mnemonic(ut16 id);
RZ_IPI ut32 c5x_op_type(ut16 id);
RZ_IPI RzILOpEffect *c5x_lift(const C55Insn *insn, ut64 pc);

extern const C55ArchDesc c5x_arch_desc;

RZ_IPI int tms320_c5x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask);

RZ_IPI RzAnalysisILConfig *tms320_c5x_il_config(RZ_NONNULL RzAnalysis *analysis);

#ifdef __cplusplus
}
#endif

#endif /* RZ_TMS320_C5X_H */
