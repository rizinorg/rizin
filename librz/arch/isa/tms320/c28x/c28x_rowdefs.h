// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Decode-table row macros for the TMS320C28x table. Included immediately before
 * the `static const C28xInsnDef c28x_table[] = {` body in c28x_decode.c and
 * paired with c28x_rowundefs.h afterwards.
 *
 * A row matches on the packed opcode: the first instruction word occupies bits
 * 31:16 and the second (when the row is four bytes long) bits 15:0, so an
 * operand field in the first word is addressed at its bit position plus 16.
 */

// mask/match over the packed word0<<16 | word1
#define OP(m_, v_) .mask = (ut32)(m_), .match = (ut32)(v_)

// analysis classification, spelled without the shared prefix for table width
#define RZTYPE(t_) .type = RZ_ANALYSIS_OP_TYPE_##t_

// operand extractors; \p lo is the low bit inside the packed opcode
#define REG(r_) { C28X_OD_REG, 0, 0, C28X_REG_##r_ }
// VCU registers are picked by a field rather than fixed, so the base is stored
// in the extra slot and the field index is added to it when decoding
#define VRREG(lo_) { C28X_OD_REGSEL, (lo_), 4, C28X_REG_VR0 }
// three-bit form: the VCU's multi-register instructions reach VR0-VR7 only
#define VRREG3(lo_) { C28X_OD_REGSEL, (lo_), 3, C28X_REG_VR0 }
// the low half of a VCU register, which VDEC names
#define VRREGL(lo_) { C28X_OD_REGSEL_LOW, (lo_), 3, C28X_REG_VR0 }
#define VTREG(lo_)  { C28X_OD_REGSEL, (lo_), 1, C28X_REG_VT0 }
#define AXREG       { C28X_OD_AX, 24, 1, 0 }
// AX addressed as its low or high byte ("AL.LSB", "AH.MSB")
#define AXLSB         { C28X_OD_AX, 24, 1, 1 }
#define AXMSB         { C28X_OD_AX, 24, 1, 2 }
#define XARN(lo_)     { C28X_OD_XAR, (lo_), 3, 0 }
#define ARN(lo_)      { C28X_OD_AR, (lo_), 3, 0 }
#define ARPN(lo_)     { C28X_OD_ARP, (lo_), 3, 0 }
#define LOC16(lo_)    { C28X_OD_LOC, (lo_), 8, 0 }
#define LOC32(lo_)    { C28X_OD_LOC, (lo_), 8, 1 }
#define IMMU(lo_, w_) { C28X_OD_IMM, (lo_), (w_), 0 }
// A 16-bit immediate split across both words: \p lo_ and \p w_ locate the low
// part, \p hi_ the low bit of the remaining high bits (VMOVXI and friends)
#define IMMSPLIT(lo_, w_, hi_) { C28X_OD_IMM_SPLIT, (lo_), (w_), (hi_) }
// An immediate the opcode fixes rather than encodes (the VCFFT stage number)
#define IMMV(v_)       { C28X_OD_IMMV, 0, 0, (v_) }
#define IMMS(lo_, w_)  { C28X_OD_IMM, (lo_), (w_), 1 }
#define IMMC(v_)       { C28X_OD_IMMFIX, 0, 0, (v_) }
#define SHIFT(lo_, w_) { C28X_OD_SHIFT, (lo_), (w_), 0 }
// shift counts encoded as 0..15 meaning 1..16 (the 64-bit and AX shift group)
#define SHIFT1(lo_, w_)  { C28X_OD_SHIFT, (lo_), (w_), 1 }
#define SHIFTC(v_)       { C28X_OD_SHIFTFIX, 0, 0, (v_) }
#define COND(lo_)        { C28X_OD_COND, (lo_), 4, 0 }
#define REL(lo_, w_)     { C28X_OD_PCREL, (lo_), (w_), 0 }
#define PMA(lo_, w_)     { C28X_OD_PMA, (lo_), (w_), 0 }
#define PMA_IND(lo_, w_) { C28X_OD_PMA_IND, (lo_), (w_), 0 }
#define PMA_DP(lo_, w_)  { C28X_OD_PMA_DP, (lo_), (w_), 0 }
#define DMA(lo_, w_)     { C28X_OD_DMA, (lo_), (w_), 0 }
#define PORT(lo_, w_)    { C28X_OD_PORT, (lo_), (w_), 0 }
#define MODE(lo_)        { C28X_OD_MODE, (lo_), 8, 0 }
// SPM's 3-bit field selects one of the eight product shift modes
#define PMSHIFT(lo_) { C28X_OD_PMSHIFT, (lo_), 3, 0 }
#define BITN(lo_)    { C28X_OD_BITNUM, (lo_), 4, 0 }
// indirect operand whose register comes from a 3-bit field at \p lo_
#define IND(m_, lo_) { C28X_OD_IND, (lo_), 0, C28X_AM_##m_ }
// indirect operand on a fixed register \p n_ named by the opcode itself
#define INDR(m_, n_) { C28X_OD_IND, (n_), 1, C28X_AM_##m_ }
// AX select bit at an explicit position; the default AXREG sits at bit 24
#define AXAT(lo_) { C28X_OD_AX, (lo_), 1, 0 }
// INTR names its interrupt rather than numbering it
#define INTRN(lo_) \
	{ C28X_OD_INTR, (lo_), 4, 0 }

// A row is repeatable under RPT, which the analysis layer reports as a hint.
#define RPTABLE .repeatable = true
