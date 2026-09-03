// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_PRIV_H
#define RISCV_IL_PRIV_H

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// -----------------------------------------------------------------------
// CSR (Control and Status Register) instructions — Zicsr extension
//
// We currently support only the floating-point CSRs because they are the
// only ones that affect program-visible IL state in our model:
//   fflags  (0x001) — FP accrued exceptions,   bits [4:0] of "fcsr"
//   frm     (0x002) — FP rounding mode,         bits [7:5] of "fcsr"
//   fcsr    (0x003) — combined FP control/status register
//
// NOTE: The spec distinguishes "shall not read" (rd=x0) and "shall not
// write" (rs1=x0 / uimm=0) semantics to avoid triggering side effects on
// CSRs that have architectural read/write side effects.  Since every CSR
// we model today is pure data (fflags, frm, fcsr), reading or writing them
// redundantly is harmless.  We therefore always perform both the read and
// the write unconditionally.  Revisit this when side-effectual CSRs
// (e.g., mstatus, sstatus, cycle) are added.
// -----------------------------------------------------------------------

// Read a CSR value as an XLEN-bit bitvector from the "fcsr" IL global.
static RzILOpBitVector *riscv_csr_read(uint16_t csr, int xlen) {
	switch (csr) {
	case RISCV_SYSREG_FFLAGS:
		// bits [4:0] of "fcsr", zero-extended to XLEN
		return CAST(xlen, IL_FALSE, LOGAND(VARG("fcsr"), UN(64, 0x1F)));
	case RISCV_SYSREG_FRM:
		// bits [7:5] of "fcsr" shifted right by 5, zero-extended to XLEN
		return CAST(xlen, IL_FALSE, SHIFTR0(LOGAND(VARG("fcsr"), UN(64, 0xE0)), UN(64, 5)));
	case RISCV_SYSREG_FCSR:
		// full "fcsr" (only bits [7:0] are meaningful), zero-extended to XLEN
		return CAST(xlen, IL_FALSE, VARG("fcsr"));
	default:
		return UN(xlen, 0);
	}
}

// Write an XLEN-bit value into the appropriate field of the "fcsr" IL global.
// val is consumed (ownership transferred to the returned effect or freed on unknown CSR).
static RzILOpEffect *riscv_csr_write(uint16_t csr, RzILOpBitVector *val, int xlen) {
	switch (csr) {
	case RISCV_SYSREG_FFLAGS:
		// update bits [4:0] of "fcsr", preserve the rest
		return SETG("fcsr", LOGOR(
				       LOGAND(VARG("fcsr"), UN(64, ~0x1FULL)),
				       LOGAND(CAST(64, IL_FALSE, val), UN(64, 0x1F))));
	case RISCV_SYSREG_FRM:
		// update bits [7:5] of "fcsr", preserve the rest
		return SETG("fcsr", LOGOR(
				       LOGAND(VARG("fcsr"), UN(64, ~0xE0ULL)),
				       LOGAND(SHIFTL0(CAST(64, IL_FALSE, val), UN(64, 5)), UN(64, 0xE0))));
	case RISCV_SYSREG_FCSR:
		// update "fcsr" directly, masking to the 8 meaningful bits
		return SETG("fcsr", LOGAND(CAST(64, IL_FALSE, val), UN(64, 0xFF)));
	default:
		rz_il_op_pure_free(val);
		return NOP();
	}
}

// -----------------------------------------------------------------------
// Decoders
// -----------------------------------------------------------------------

// rd=IntReg[0], csr=CSR[1], rs=IntReg[2]  (csrrw, csrrs, csrrc)
#define DECODE_CSR_RD_CSR_RS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_CSR); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	uint16_t csr = insn->detail->riscv.operands[1].csr; \
	RzILOpBitVector *rs = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[2].reg);

// rd=IntReg[0], csr=CSR[1], uimm=5-bit unsigned IMM[2]  (csrrwi, csrrsi, csrrci)
#define DECODE_CSR_RD_CSR_IMM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_CSR); \
	REQUIRE_OP(2, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	uint16_t csr = insn->detail->riscv.operands[1].csr; \
	RzILOpBitVector *uimm = UN(analysis->bits, (ut64)(insn->detail->riscv.operands[2].imm) & 0x1F);

// -----------------------------------------------------------------------
// csrrw  rd, csr, rs1
//   rd  ← old CSR value (zero-extended to XLEN)
//   CSR ← rs1
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_csrrw(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_CSR_RD_CSR_RS(analysis, insn);
	return SEQ3(
		SETL("_old", riscv_csr_read(csr, analysis->bits)),
		riscv_csr_write(csr, rs, analysis->bits),
		riscv_il_set_reg(rd, VARL("_old")));
}

// -----------------------------------------------------------------------
// csrrs  rd, csr, rs1
//   rd  ← old CSR value (zero-extended to XLEN)
//   CSR ← old CSR | rs1   (set bits where rs1 has 1s)
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_csrrs(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_CSR_RD_CSR_RS(analysis, insn);
	return SEQ3(
		SETL("_old", riscv_csr_read(csr, analysis->bits)),
		riscv_csr_write(csr, LOGOR(VARL("_old"), rs), analysis->bits),
		riscv_il_set_reg(rd, VARL("_old")));
}

// -----------------------------------------------------------------------
// csrrc  rd, csr, rs1
//   rd  ← old CSR value (zero-extended to XLEN)
//   CSR ← old CSR & ~rs1  (clear bits where rs1 has 1s)
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_csrrc(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_CSR_RD_CSR_RS(analysis, insn);
	return SEQ3(
		SETL("_old", riscv_csr_read(csr, analysis->bits)),
		riscv_csr_write(csr, LOGAND(VARL("_old"), LOGNOT(rs)), analysis->bits),
		riscv_il_set_reg(rd, VARL("_old")));
}

// -----------------------------------------------------------------------
// csrrwi  rd, csr, uimm
//   rd  ← old CSR value (zero-extended to XLEN)
//   CSR ← zero-extend(uimm[4:0])
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_csrrwi(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_CSR_RD_CSR_IMM(analysis, insn);
	return SEQ3(
		SETL("_old", riscv_csr_read(csr, analysis->bits)),
		riscv_csr_write(csr, uimm, analysis->bits),
		riscv_il_set_reg(rd, VARL("_old")));
}

// -----------------------------------------------------------------------
// csrrsi  rd, csr, uimm
//   rd  ← old CSR value (zero-extended to XLEN)
//   CSR ← old CSR | zero-extend(uimm[4:0])
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_csrrsi(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_CSR_RD_CSR_IMM(analysis, insn);
	return SEQ3(
		SETL("_old", riscv_csr_read(csr, analysis->bits)),
		riscv_csr_write(csr, LOGOR(VARL("_old"), uimm), analysis->bits),
		riscv_il_set_reg(rd, VARL("_old")));
}

// -----------------------------------------------------------------------
// csrrci  rd, csr, uimm
//   rd  ← old CSR value (zero-extended to XLEN)
//   CSR ← old CSR & ~zero-extend(uimm[4:0])
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_csrrci(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_CSR_RD_CSR_IMM(analysis, insn);
	return SEQ3(
		SETL("_old", riscv_csr_read(csr, analysis->bits)),
		riscv_csr_write(csr, LOGAND(VARL("_old"), LOGNOT(uimm)), analysis->bits),
		riscv_il_set_reg(rd, VARL("_old")));
}

#undef DECODE_CSR_RD_CSR_RS
#undef DECODE_CSR_RD_CSR_IMM

#include <rz_il/rz_il_opbuilder_end.h>

#endif // RISCV_IL_PRIV_H
