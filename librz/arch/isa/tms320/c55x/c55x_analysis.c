// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2014 montekki <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_analysis.h>

#include "c55x_analysis.h"
#include "../tms320c55x_insn.h"
#include "../c55_ir.h"
#include "../c55x_plus/c55plus_analysis.h"

/**
 * \file c55x_analysis.c
 *
 * TMS320C55x (base) analysis: classify opcodes, resolve branch
 * targets, set basic-block fallthrough, fill in stack effects.
 *
 * Pure byte-level dispatch -- no mnemonic-string matching. Each
 * recognised opcode is dispatched on its leading byte (with second-
 * byte refinement where the prefix family is shared by multiple
 * instructions).
 *
 * The encoding map below was extracted from TI SPRU374 (TMS320C55x
 * DSP Mnemonic Instruction Set Reference Guide, public) and cross-
 * referenced against the rizin c55x decoder's internal opcode table
 * (librz/arch/isa/tms320/c55x/table.h, originally by th0rpe 2013).
 *
 * Key differences from the C55x+ ('+'-suffixed Ryujin / Low-Power
 * C55x) instruction set:
 *
 *   - 0x21 is the parallel-instruction marker (`|| nop`), NOT RET.
 *     RET in baseline C55x is encoded as the 2-byte form 0x48 0x88;
 *     RETI as 0x48 0xA8.
 *   - 0x00 is RPTCC (3-byte conditional repeat), NOT NOP_16.
 *     NOP is the 1-byte 0x20 (same as C55x+).
 *   - 0x02 is RETCC (conditional return), NOT B/CALL indirect.
 *   - 0x04 / 0x06 / 0x08 / 0x4A are the short B/BCC/CALL forms;
 *     0x6A / 0x6B / 0x6C / 0x6E are the 24-bit absolute forms.
 *   - INTR / TRAP are 2-byte 0x95 ?? (bit 7 of byte 2 selects).
 *   - Many control-flow opcodes use a second-byte high bit to flip
 *     between B / CALL or related variants.
 *
 * Encoding cross-validated against rz-asm output for the testbins
 * c55x emulateme binary (tms320/emulateme_nostd.ccsv5.c55x.ticoff2.*)
 * and against TI SPRU374 sec.4 (Instruction Set Reference).
 *
 * Byte-order note: C55x branch displacements and absolute targets
 * are stored MSB-first within the instruction stream -- see SPRU374
 * sec.3. Extracted with rz_read_at_be16() / rz_read_at_be24() to avoid
 * any unaligned-int dereference.
 */

/* Per-leading-byte instruction size, extracted from the c55x
 * decoder's opcode table (librz/arch/isa/tms320/c55x/table.h --
 * originally by th0rpe 2013, sourced from TI SPRU374). Bytes not
 * documented in the table default to size=1 so the analyzer
 * advances and re-syncs on the next byte rather than getting stuck.
 *
 * Note that some c55x instructions are even longer (up to 7 bytes
 * total) due to immediate-operand suffixes; the table value is the
 * size of the *leading* fixed-form, not necessarily the size of the
 * decoded instruction. This works for analysis purposes (we don't
 * need exact instruction boundaries; we need enough bytes to read
 * branch displacements and at least classify the type).
 *
 * For boundary-critical analyses (basic-block formation), the
 * disassembler is still authoritative; the analyzer's size estimate
 * just needs to be non-zero and not lie about a branch's
 * displacement bytes being there. */
static const ut8 c55x_op_sizes[256] = {
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 3, 3, 3, 3, /* 0x00 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0x10 */
	1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x20 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x30 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x40 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x50 */
	2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 4, 4, 4, 4, 4, 4, /* 0x60 */
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, /* 0x70 */
	3, 3, 4, 4, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x80 */
	2, 2, 2, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 2, /* 0x90 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0xa0 */
	2, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, /* 0xb0 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0xc0 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xd0 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xe0 */
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 1, 1, /* 0xf0 */
};

static int c55x_op_size(const ut8 *buf, int len) {
	if (len < 1) {
		return 0;
	}
	const ut8 sz = c55x_op_sizes[buf[0]];
	return ((int)sz <= len) ? (int)sz : 0;
}

/* ---- shared decode-IR descriptor (incremental C55x cutover) -----------
 * The shared c55_ir engine decodes a C55Insn once; the disassembler,
 * analyzer and RzIL lifter then consume it. This is the first member of the
 * TMS320C55x family wired onto the same engine as C55x+, validating that the
 * IR/consumers are arch-agnostic. Only opcodes present in c55x_table take
 * this path; everything else falls through to the legacy byte-driven code,
 * so the migration stays behaviour-preserving at every step.
 *
 * The instruction ids and 23-bit data-pointer model are common to the family,
 * so id->mnemonic and id->type are resolved exactly as for C55x+. The
 * descriptor carries the operand-free nop and the register-to-register mov
 * family; reg_info resolves the C55x register file (AC0-3 / T0-3 / AR0-7),
 * a subset of the C55x+ file with identical il_vars and widths. */
// C55x register file (a subset of C55x+; identical il_vars/widths): the
// register-to-register forms reach AC0-3, T0-3 and AR0-7.
static const C55RegInfo c55x_ac_ri[4] = {
	{ "ac0", "ac0", 40 }, { "ac1", "ac1", 40 }, { "ac2", "ac2", 40 }, { "ac3", "ac3", 40 }
};
static const C55RegInfo c55x_t_ri[4] = {
	{ "t0", "t0", 16 }, { "t1", "t1", 16 }, { "t2", "t2", 16 }, { "t3", "t3", 16 }
};
static const C55RegInfo c55x_ar_ri[8] = {
	{ "ar0", "ar0", 16 }, { "ar1", "ar1", 16 }, { "ar2", "ar2", 16 }, { "ar3", "ar3", 16 },
	{ "ar4", "ar4", 16 }, { "ar5", "ar5", 16 }, { "ar6", "ar6", 16 }, { "ar7", "ar7", 16 }
};
// The ARn registers are 16-bit for data, but the address pointer they form is
// the 23-bit XARn (used to compute effective addresses and apply post-modify).
static const C55RegInfo c55x_xar_ri[8] = {
	{ "xar0", "xar0", 23 }, { "xar1", "xar1", 23 }, { "xar2", "xar2", 23 }, { "xar3", "xar3", 23 },
	{ "xar4", "xar4", 23 }, { "xar5", "xar5", 23 }, { "xar6", "xar6", 23 }, { "xar7", "xar7", 23 }
};
static const C55RegInfo c55x_sp_ri = { "sp", "sp", 16 };
// The coefficient data pointer: rendered "cdp", but the address pointer it
// forms (used for effective-address and post-modify of the Cmem coefficient
// operand) is the 23-bit XCDP, so its il_var is xcdp.
static const C55RegInfo c55x_cdp_ri = { "cdp", "xcdp", 23 };
// The four C55x status registers ST0_55..ST3_55, written by the bclr / bset
// bit-clear / bit-set forms (opcode 0x46). They are 16-bit control registers
// with matching lifter variables.
static const C55RegInfo c55x_st_ri[4] = {
	{ "st0_55", "st0_55", 16 }, { "st1_55", "st1_55", 16 },
	{ "st2_55", "st2_55", 16 }, { "st3_55", "st3_55", 16 }
};
// The test-control status bits, written by the btst bit-test forms. Rendered
// TC1 / TC2 (uppercase); they carry no lifter variable here because the
// bit-test instruction that names them is not yet lifted.
static const C55RegInfo c55x_tc_ri[2] = {
	{ "TC1", NULL, 1 },
	{ "TC2", NULL, 1 }
};
// Named status flags and special registers used as explicit operands. CARRY /
// BORROW are the 0xdf carry/borrow flags; the rest are the destinations of the
// 0xdc mov Smem, <special-reg> forms. These are the 16-bit views the legacy
// lifter writes (e.g. dp / cdp, not the 23-bit xcdp), so they carry their own
// il_var here; dph is 7-bit and pdp is 9-bit, the rest 16-bit.
enum {
	C55X_SPR_CARRY = 0, C55X_SPR_BORROW,
	C55X_SPR_DP, C55X_SPR_CDP, C55X_SPR_BSA01, C55X_SPR_BSA23, C55X_SPR_BSA45,
	C55X_SPR_BSA67, C55X_SPR_BSAC, C55X_SPR_SP, C55X_SPR_SSP, C55X_SPR_BK03,
	C55X_SPR_BK47, C55X_SPR_BKC, C55X_SPR_DPH, C55X_SPR_PDP, C55X_SPR_CSR,
	C55X_SPR_BRC0, C55X_SPR_BRC1, C55X_SPR_TRN0, C55X_SPR_TRN1, C55X_SPR_RPTC,
	// 23-bit extended pointers named by the popboth / pshboth register-pair
	// stack ops (the "xdst"/"xsrc" field). They carry no lifter variable: the
	// pair push-pop is left unlifted.
	C55X_SPR_XSP, C55X_SPR_XSSP, C55X_SPR_XDP, C55X_SPR_XCDP, C55X_SPR_COUNT
};
static const C55RegInfo c55x_special_ri[C55X_SPR_COUNT] = {
	{ "CARRY", NULL, 1 }, { "BORROW", NULL, 1 },
	{ "dp", "dp", 16 }, { "cdp", "cdp", 16 }, { "bsa01", "bsa01", 16 },
	{ "bsa23", "bsa23", 16 }, { "bsa45", "bsa45", 16 }, { "bsa67", "bsa67", 16 },
	{ "bsac", "bsac", 16 }, { "sp", "sp", 16 }, { "ssp", "ssp", 16 },
	{ "bk03", "bk03", 16 }, { "bk47", "bk47", 16 }, { "bkc", "bkc", 16 },
	{ "dph", "dph", 7 }, { "pdp", "pdp", 9 }, { "csr", "csr", 16 },
	{ "brc0", "brc0", 16 }, { "brc1", "brc1", 16 }, { "trn0", "trn0", 16 },
	{ "trn1", "trn1", 16 }, { "rptc", "rptc", 16 },
	{ "xsp", NULL, 23 }, { "xssp", NULL, 23 }, { "xdp", NULL, 23 }, { "xcdp", NULL, 23 }
};

static const C55RegInfo *c55x_reg_info(C55RegClass cls, ut8 num, C55SubReg sub) {
	(void)sub;
	switch (cls) {
	case C55_RC_AC: return num < 4 ? &c55x_ac_ri[num] : NULL;
	case C55_RC_T: return num < 4 ? &c55x_t_ri[num] : NULL;
	case C55_RC_AR: return num < 8 ? &c55x_ar_ri[num] : NULL;
	case C55_RC_XAR: return num < 8 ? &c55x_xar_ri[num] : NULL;
	case C55_RC_SP: return num == 0 ? &c55x_sp_ri : NULL;
	case C55_RC_CDP: return num == 0 ? &c55x_cdp_ri : NULL;
	case C55_RC_ST: return num < 4 ? &c55x_st_ri[num] : NULL;
	case C55_RC_TC: return num < 2 ? &c55x_tc_ri[num] : NULL;
	case C55_RC_SPECIAL: return num < C55X_SPR_COUNT ? &c55x_special_ri[num] : NULL;
	default: return NULL;
	}
}

// C55x 4-bit register selector (TI "register field"): 0-3 -> AC0-3,
// 4-7 -> T0-3, 8-15 -> AR0-7. Shared by the register-to-register forms.
static void c55x_gr4(ut8 nib, C55Reg *r) {
	r->sub = C55_SUB_NONE;
	if (nib < 4) {
		r->cls = C55_RC_AC;
		r->num = nib;
	} else if (nib < 8) {
		r->cls = C55_RC_T;
		r->num = (ut8)(nib - 4);
	} else {
		r->cls = C55_RC_AR;
		r->num = (ut8)(nib - 8);
	}
}

// gr4 for the address-arithmetic forms (amov / asub ACx, ACy): the high range
// names the 23-bit XARn pointer rather than the 16-bit ARn.
static void c55x_gr4a(ut8 nib, C55Reg *r) {
	r->sub = C55_SUB_NONE;
	if (nib < 4) {
		r->cls = C55_RC_AC;
		r->num = nib;
	} else if (nib < 8) {
		r->cls = C55_RC_T;
		r->num = (ut8)(nib - 4);
	} else {
		r->cls = C55_RC_XAR;
		r->num = (ut8)(nib - 8);
	}
}

static void c55x_x_gr4a(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	c55x_gr4a((ut8)((bits >> d->lo) & 0x0f), &out->reg);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// The fixed CSR (computed single-repeat) register operand of the rpt / rptadd /
// rptsub forms.
static void c55x_x_csr(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = C55X_SPR_CSR;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// The transition register (trn0/trn1) operand of the dmaxdiff / dmindiff forms;
// the selecting bit is at d->lo.
static void c55x_x_trn(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = (ut8)(C55X_SPR_TRN0 + ((bits >> d->lo) & 0x1));
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

static void c55x_x_gr4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	c55x_gr4((ut8)((bits >> d->lo) & 0x0f), &out->reg);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// As c55x_x_gr4, but the operand is omitted when it names the same register as
// the immediately-preceding operand (the unary "not/neg/abs ACx" forms collapse
// the destination against the source: "not ac0" rather than "not ac0, ac0").
static void c55x_x_gr4_elide(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_gr4(a, bits, d, out);
	out->elide_if_eq_prev = true;
}

// Accumulator rendered with the dbl(...) wrapper -- the "dbl(ACx)" operand of
// the pop / psh dbl(ACx) stack forms (opcode 0x50, sub-opcodes 3/7). The dbl
// form only ever names an accumulator: the field's low two bits pick AC0-AC3
// (the legacy decoder ignores the upper bits). The dbl marker is a disassembly
// decoration; the lifted op is the plain accumulator pop / psh.
static void c55x_x_ac_dbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	out->reg.sub = C55_SUB_NONE;
	out->dbl = true;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// hi(ACx) accumulator high-word source of the "mov hi(ACx), dst" forms (opcode
// 0x44, high nibble 0-3): the accumulator index is the field's low two bits;
// the operand is the 16-bit high word (rendered hi(acN)). The shared MOV lifter
// sign-extends it to the destination width.
static void c55x_x_hi_ac(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	out->reg.sub = C55_SUB_HI;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Special-register source of the "mov <reg>, dst" forms (opcode 0x44, high
// nibble 8-15): 8 -> SP, 9 -> SSP, 10 -> CDP, 12 -> BRC0, 13 -> BRC1,
// 14 -> RPTC (the 16-bit views). 11 and 15 are unassigned -> left to the legacy
// decoder. The shared MOV lifter sign-extends the source to the dst width.
static void c55x_x_44src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 v = (ut8)((bits >> d->lo) & 0x0f);
	ut8 spr;
	switch (v) {
	case 8: spr = C55X_SPR_SP; break;
	case 9: spr = C55X_SPR_SSP; break;
	case 10: spr = C55X_SPR_CDP; break;
	case 12: spr = C55X_SPR_BRC0; break;
	case 13: spr = C55X_SPR_BRC1; break;
	case 14: spr = C55X_SPR_RPTC; break;
	default:
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = spr;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}
// Special-register destination of "mov #k16, <reg>" (opcode 0x78): byte3 bit 0
// is don't-care; byte3 bits 1-4 select the register -- 0 dp, 1 ssp, 2 cdp,
// 3 bsa01, 4 bsa23, 5 bsa45, 6 bsa67, 7 bsac, 8 sp. Selectors 9-15 are
// unassigned and left to the legacy decoder.
static void c55x_x_78dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 spr;
	switch ((ut8)((bits >> d->lo) & 0x0f)) {
	case 0: spr = C55X_SPR_DP; break;
	case 1: spr = C55X_SPR_SSP; break;
	case 2: spr = C55X_SPR_CDP; break;
	case 3: spr = C55X_SPR_BSA01; break;
	case 4: spr = C55X_SPR_BSA23; break;
	case 5: spr = C55X_SPR_BSA45; break;
	case 6: spr = C55X_SPR_BSA67; break;
	case 7: spr = C55X_SPR_BSAC; break;
	case 8: spr = C55X_SPR_SP; break;
	default:
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = spr;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 16;
}

// Destination register selector for mov #k12, <reg> (opcode 0x16): byte2's low
// nibble picks a control register; the immediate field sits in the 12 bits
// above it. Only eight encodings are defined (the rest are invalid).
static int c55x_16dst_spr(ut8 sel) {
	switch (sel) {
	case 0x0: return C55X_SPR_DPH;
	case 0x3: return C55X_SPR_PDP;
	case 0x4: return C55X_SPR_BK03;
	case 0x5: return C55X_SPR_BK47;
	case 0x6: return C55X_SPR_BKC;
	case 0x8: return C55X_SPR_CSR;
	case 0x9: return C55X_SPR_BRC0;
	case 0xa: return C55X_SPR_BRC1;
	default: return -1;
	}
}
static void c55x_x_16dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	int spr = c55x_16dst_spr((ut8)((bits >> d->lo) & 0x0f));
	if (spr < 0) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = (ut8)spr;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 16;
}

// Immediate for mov #k12, <reg> (opcode 0x16): a 12-bit field (d->lo .. d->lo+11)
// masked and displayed at the destination register's width (capped at 12). The
// destination selector is the nibble just below the field (byte2 low nibble).
static void c55x_x_16imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	int spr = c55x_16dst_spr((ut8)((bits >> (d->lo - 4)) & 0x0f));
	if (spr < 0) {
		out->kind = C55_OP_INVALID;
		return;
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(C55_RC_SPECIAL, (ut8)spr, C55_SUB_NONE) : NULL;
	int rw = ri ? ri->width : 16;
	int iw = rw < 12 ? rw : 12;
	ut64 k = (bits >> d->lo) & 0xfff;
	out->kind = C55_OP_IMM;
	out->imm = k & (((ut64)1 << iw) - 1);
	out->width = iw;
}

// The implicit stack-pointer destination of "aadd #k8, sp" (opcode 0x4e): no
// bits select it, so the extractor always yields sp.
static void c55x_x_sp(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SP;
	out->reg.num = 0;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(C55_RC_SP, 0, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 16;
}

// Special-register destination of the "mov gr4, <reg>" forms (opcode 0x52, low
// nibble 8-15): 8 -> sp, 9 -> ssp, 10 -> cdp, 12 -> csr, 13 -> brc1, 14 -> brc0.
// Low nibbles 11 and 15 are unassigned and left to the legacy decoder. (The map
// differs from the 0x44 source map: e.g. 14 is brc0 here, rptc there.)
static void c55x_x_52dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 spr;
	switch ((ut8)((bits >> d->lo) & 0x0f)) {
	case 8: spr = C55X_SPR_SP; break;
	case 9: spr = C55X_SPR_SSP; break;
	case 10: spr = C55X_SPR_CDP; break;
	case 12: spr = C55X_SPR_CSR; break;
	case 13: spr = C55X_SPR_BRC1; break;
	case 14: spr = C55X_SPR_BRC0; break;
	default:
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = spr;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *sri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = sri ? sri->width : 0;
}

// swap / swapp register pair (opcode 0x5e). The byte-1 low nibble selects the
// pair; d->param 0 yields the first register, 1 the second. Byte-1 bit 4 marks
// swapp (the dual exchange), for which only the even-base pairs are valid; the
// lifter swaps the following pair too (signalled by the row's `.both`).
static void c55x_x_swap(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	static const struct { ut8 c0, n0, c1, n1; bool ok; } pairs[16] = {
		[0] = { C55_RC_AC, 0, C55_RC_AC, 2, true },
		[1] = { C55_RC_AC, 1, C55_RC_AC, 3, true },
		[4] = { C55_RC_T, 0, C55_RC_T, 2, true },
		[5] = { C55_RC_T, 1, C55_RC_T, 3, true },
		[8] = { C55_RC_AR, 0, C55_RC_AR, 2, true },
		[9] = { C55_RC_AR, 1, C55_RC_AR, 3, true },
		[12] = { C55_RC_AR, 4, C55_RC_T, 0, true },
		[13] = { C55_RC_AR, 5, C55_RC_T, 1, true },
		[14] = { C55_RC_AR, 6, C55_RC_T, 2, true },
		[15] = { C55_RC_AR, 7, C55_RC_T, 3, true },
	};
	ut8 sel = (ut8)((bits >> d->lo) & 0x0f);
	bool swapp = ((bits >> 4) & 1) != 0;
	bool swap4 = ((bits >> 5) & 1) != 0;
	// key 56 (both the swapp and swap4 marker bits set, sel == 8): the
	// standalone "swap AR0, AR1" -- the single arbitrary AR pair, distinct
	// from the sel-8 pair(AR0, AR2).
	if (swapp && swap4 && sel == 8) {
		out->kind = C55_OP_REG;
		out->reg.sub = C55_SUB_NONE;
		out->reg.cls = C55_RC_AR;
		out->reg.num = d->param == 0 ? 0 : 1;
		const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
		out->width = ri ? ri->width : 0;
		return;
	}
	if (!pairs[sel].ok) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if (swap4) {
		// swap4 only exchanges the ar4/ar5/ar6/ar7 <-> t0/t1/t2/t3 quad.
		if (sel != 12) {
			out->kind = C55_OP_INVALID;
			return;
		}
	} else if (swapp && (sel & 1)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	if (d->param == 0) {
		out->reg.cls = pairs[sel].c0;
		out->reg.num = pairs[sel].n0;
	} else {
		out->reg.cls = pairs[sel].c1;
		out->reg.num = pairs[sel].n1;
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}
// 0x50, sub-opcodes 0/1). Sub-opcode bit 0 selects the direction: 0 -> +1,
// 1 -> -1. Rendered as a signed decimal with a '#' prefix; lifted by the shared
// SFTL shift handler (a positive count shifts left, a negative one right).
static void c55x_x_sftl_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = (bits & 1) ? (ut64)(-1) : 1;
	out->width = 6;
	out->imm_signed = true;
	out->hash_dec = true;
}

// The fixed shift count of the "sfts dst, #1" / "sfts dst, #-1" forms (opcode
// 0x44, high nibble 4-7). The high-nibble low bit (byte1 bit 4) selects the
// direction, with the opposite polarity to sftl: 1 -> +1, 0 -> -1. Rendered as
// a signed decimal with '#'; lifted (arithmetically) by the shared SFTS handler.
static void c55x_x_sfts_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = ((bits >> 4) & 1) ? 1 : (ut64)(-1);
	out->width = 6;
	out->imm_signed = true;
	out->hash_dec = true;
}

// Extended-register ("xdst" / "xsrc") field of the popboth / pshboth pair stack
// ops (opcode 0x50, sub-opcodes 4/5): 0-3 -> AC0-AC3, 4 -> XSP, 5 -> XSSP,
// 6 -> XDP, 7 -> XCDP, 8-15 -> XAR0-XAR7. These move a register pair; the
// shared push/pop lifter leaves them unlifted (see the .both flag).
static void c55x_x_xgr4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 v = (ut8)((bits >> d->lo) & 0x0f);
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	if (v < 4) {
		out->reg.cls = C55_RC_AC;
		out->reg.num = v;
	} else if (v < 8) {
		out->reg.cls = C55_RC_SPECIAL;
		out->reg.num = (ut8)(C55X_SPR_XSP + (v - 4)); // XSP, XSSP, XDP, XCDP
	} else {
		out->reg.cls = C55_RC_XAR;
		out->reg.num = (ut8)(v - 8);
	}
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Source gr4 register that collapses against the destination gr4 register when
// the two are equal -- the optional "src" of the "add/sub Smem, [src,] dst"
// forms (opcodes 0xd6/0xd7), where src is the last byte's bits 0-3 and dst its
// bits 4-7. When src == dst only the destination is printed (dst += Smem).
static void c55x_x_gr4_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 src = (ut8)((bits >> d->lo) & 0x0f);
	ut8 dst = (ut8)((bits >> (d->lo + 4)) & 0x0f);
	if (src == dst) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	c55x_gr4(src, &out->reg);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// The optional "ACx" source of the dbl add/sub forms (opcode 0xed): SS is the
// last byte's bits 7-6 (read at d->lo) and DD the destination at bits 5-4
// (d->lo - 2). Both name an accumulator ac0-3; when SS == DD only the
// destination prints (ACy += dbl(Lmem)).
static void c55x_x_ac_src2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 src = (ut8)((bits >> d->lo) & 0x3);
	ut8 dst = (ut8)((bits >> (d->lo - 2)) & 0x3);
	if (src == dst) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = src;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Condition field (xcc / xccpart, and the conditional transfers): the low seven
// bits encode either a register-versus-zero comparison or a status-flag
// expression. The subject register is reg-field-4 in bits 0-3 and the
// comparison is bits 4-6 (0..5 -> == != < <= > >=, matching C55Relop). The flag
// expressions (bits 4-6 of 6 or 7) are not represented here yet, so the decode
// is abandoned for them and the legacy front-end renders those conditions.
static void c55x_x_cond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 field = (ut8)((bits >> d->lo) & 0x7f);
	ut8 cmp = (ut8)((field >> 4) & 0x07);
	if (cmp <= C55_REL_GE) {
		// 0-5: a register compared against zero.
		out->kind = C55_OP_COND;
		c55x_gr4((ut8)(field & 0x0f), &out->reg);
		out->relop = (C55Relop)cmp;
		out->imm = 0;
		return;
	}
	// 6-7: a status-flag condition. The flag id is (cmp-6)*16 + the low nibble,
	// which indexes the shared cond_flags table. C55x leaves a few of those
	// slots undefined - overflow(govf) (7), word/byte mode (12/13), two reserved
	// (14/15) and !overflow(govf) (23) - so those fall back to the legacy
	// decoder rather than decoding as a flag.
	ut8 flag = (ut8)(((cmp - 6) << 4) | (field & 0x0f));
	if (flag == 7 || (flag >= 12 && flag <= 15) || flag == 23) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = flag;
}

// bcc short form (opcodes 0x60-0x67): the destination is a forward offset in a
// four-bit field whose high three bits are byte0 bits 0-2 and whose low bit is
// byte1 bit 7 (so the field occupies packed bits 7-10). The branch goes to
// pc + size + offset; the offset is small and always non-negative, so it is
// rendered as a one-digit immediate and flagged unsigned (no sign-extension).
static void c55x_x_bcc_short_target(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = (ut64)((bits >> d->lo) & 0x0f);
	out->width = 4;
	out->reltarget = true;
	out->reltarget_unsigned = true;
}

// Compare-and-branch condition (bcc 0x6f): the source register is gr4 in byte1
// bits 4-7 and the comparison is byte1 bits 2-3 (0 ==, 1 <, 2 >=, 3 !=), with
// bit 0 selecting the unsigned form (bccu). byte2 is the 8-bit compare constant
// K8. The 16-bit field passed in is byte1:byte2. Only the signed comparisons
// are represented here; the unsigned form is left to the legacy decoder.
static void c55x_x_cond_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	static const C55Relop relmap[4] = { C55_REL_EQ, C55_REL_LT, C55_REL_GE, C55_REL_NE };
	ut16 field = (ut16)((bits >> d->lo) & 0xffff);
	ut8 b1 = (ut8)(field >> 8);
	if (b1 & 1) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_COND;
	c55x_gr4((ut8)(b1 >> 4), &out->reg);
	out->relop = relmap[(b1 >> 2) & 3];
	out->imm = (ut64)(field & 0xff);
	out->width = 8;
	out->cmp_imm = true;
}

// 2-bit accumulator selector for the register-indirect control-transfer forms
// (b acx / call acx): only the four accumulators are addressable as a branch or
// call target, encoded in the low two bits of the operand byte (the remaining
// bits are don't-cares -- 0x9104, 0x9108, ... all decode to "b ac0").
static void c55x_x_ac2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Destination accumulator ACy for mpyk/mpykr/mack/mackr: identical to
// c55x_x_ac2 but flagged so the formatter omits it when it equals the source
// ACx (the TI "mpyk #k, ACx" short form where ACy defaults to ACx).
static void c55x_x_ac2_elide(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_ac2(a, bits, d, out);
	out->elide_if_eq_prev = true;
}

// 2-bit Tx selector (T0-T3) for the mack/mackr coefficient register.
static void c55x_x_t2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_T;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// A left-shifted 16-bit immediate: the "#k16 << #16" operand of the opcode-0x7a
// immediate-ALU forms. The shift is a fixed 16 and is rendered/lifted as such.
static void c55x_x_imm_sh16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55_x_imm(a, bits, d, out);
	out->sh_left = true;
	out->shamt = 16;
}

// A left-shifted 16-bit immediate with a variable shift count: the
// "#k16 << #sh" operand of the opcode-0x70..0x74 immediate-ALU forms. The shift
// is byte3 bits 0-3 (0-15) and is rendered as hex.
static void c55x_x_imm_varsh(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55_x_imm(a, bits, d, out);
	out->sh_left = true;
	out->shamt = (int8_t)(bits & 0xf);
	out->shamt_hex = true;
}

// A negated 4-bit magnitude immediate: the "-#k" operand of the opcode-0x3e
// short move (byte1 high nibble is the magnitude k, 0-15; the value is -k).
static void c55x_x_negk4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 k = (ut8)((bits >> d->lo) & 0xf);
	out->kind = C55_OP_IMM;
	out->imm = (ut64)(-(st64)k);
	out->imm_signed = true;
	out->neg_imm = true;
	out->width = 4;
}

// Fixed TC1 / TC2 literal operands (the addsub2cc form always tests both test-
// control flags, rendered as the constant "TC1, TC2" pair).
static void c55x_x_tc1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_TC;
	out->reg.num = 0;
	out->reg.sub = C55_SUB_NONE;
	out->width = 1;
}
static void c55x_x_tc2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_TC;
	out->reg.num = 1;
	out->reg.sub = C55_SUB_NONE;
	out->width = 1;
}

// The "Baddr" bit-address operand of btstp: the legacy disassembler does not
// decode the bit address and renders the literal placeholder "Baddr". The
// operand carries a verbatim render string so the output matches byte-for-byte.
static void c55x_x_baddr(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_IMM;
	out->raw = "Baddr";
}

// High accumulator-half source ACx.h for mov hi(ACx), Smem (opcodes 0xbc-0xbf):
// the accumulator number is the opcode's low two bits.
static void c55x_x_achi(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	out->reg.sub = C55_SUB_HI;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Single data-memory (Smem) operand for the C55x load / store group. The
// operand byte selects the addressing mode: an even byte is an SP-relative
// direct access (*sp(#k), k = byte>>1) and an odd byte selects a register mode
// whose base ARn is byte[7:5] and whose sub-mode is byte[4:1]. The SP-relative
// direct forms and the 2-byte register-modify matrix the shared
// effective-address / memory primitives understand are decoded here; the
// const-indexed and absolute forms (which extend the instruction with a 16-bit
// field) and the pre-modify and bit-reverse forms fall back to the legacy
// decoder.
static void c55x_x_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 b = (ut8)((bits >> d->lo) & 0xff);
	if (!(b & 1)) {
		// SP-relative direct: *sp(#k), the unsigned offset k = byte>>1 (0-127).
		out->kind = C55_OP_MEM;
		out->access = 16;
		out->amode = C55_AM_INDEXED;
		out->reg.cls = C55_RC_SP;
		out->reg.num = 0;
		out->reg.sub = C55_SUB_NONE;
		out->disp = (st32)(b >> 1);
		return;
	}
	ut8 mode = (ut8)((b >> 1) & 0x0f);
	out->kind = C55_OP_MEM;
	out->access = 16;
	c55x_gr4((ut8)(8 + ((b >> 5) & 7)), &out->reg); // base ARn
	switch (mode) {
	case 0: out->amode = C55_AM_INDIRECT; return;
	case 1: out->amode = C55_AM_POSTINC; return;
	case 2: out->amode = C55_AM_POSTDEC; return;
	case 3:
		out->amode = C55_AM_POSTADD;
		c55x_gr4(4, &out->index); // t0
		return;
	case 4:
		out->amode = C55_AM_POSTSUB;
		c55x_gr4(4, &out->index); // t0
		return;
	case 5:
		out->amode = C55_AM_IDXREG;
		c55x_gr4(4, &out->index); // t0
		return;
	case 9:
		out->amode = C55_AM_POSTADD;
		c55x_gr4(5, &out->index); // t1
		return;
	case 10:
		out->amode = C55_AM_POSTSUB;
		c55x_gr4(5, &out->index); // t1
		return;
	case 11:
		out->amode = C55_AM_IDXREG;
		c55x_gr4(5, &out->index); // t1
		return;
	case 12: out->amode = C55_AM_PREINC; return; // *+arN
	case 13: out->amode = C55_AM_PREDEC; return; // *-arN
	case 14:
		out->amode = C55_AM_BITREV; // *(arN + t0b) reverse-carry
		c55x_gr4(4, &out->index); // t0 (rendered t0b)
		return;
	case 15:
		out->amode = C55_AM_BITREV_SUB; // *(arN - t0b) reverse-carry
		c55x_gr4(4, &out->index); // t0 (rendered t0b)
		return;
	case 6:
		// *arN(#K16) long const-index: ARn is the base pointer (unmodified); the
		// signed 16-bit constant lives in a 2-byte extension that c55_decode
		// appends and writes into ->disp.
		out->amode = C55_AM_CONST_IDX;
		return;
	case 7:
		// *+arN(#K16) long const-index with pre-modify: like mode 6 but ARn is
		// updated (ARn += K16); the 2-byte extension is read by c55_decode.
		out->amode = C55_AM_CONST_IDX_PRE;
		return;
	case 8: {
		// Mode 8 dispatches on the base ARn field: 0 -> abs16(#k16), 3 -> *cdp,
		// 4 -> *cdp+, 5 -> *cdp-, 6 -> *cdp(K16), 7 -> *+cdp(K16). For abs16 the
		// address is DPH:k16 so the base is irrelevant; c55_decode reads the
		// unsigned 2-byte k16. Base 1 (*(k23)) and base 2 (port(k16)) are not
		// modelled here and fall through to the legacy decoder.
		ut8 base = (b >> 5) & 7;
		if (base >= 3) {
			out->reg.cls = C55_RC_CDP;
			out->reg.num = 0;
			out->reg.sub = C55_SUB_NONE;
			switch (base) {
			case 4: out->amode = C55_AM_POSTINC; return; // *cdp+
			case 5: out->amode = C55_AM_POSTDEC; return; // *cdp-
			case 6: out->amode = C55_AM_CONST_IDX; return; // *cdp(K16)
			case 7: out->amode = C55_AM_CONST_IDX_PRE; return; // *+cdp(K16)
			default: out->amode = C55_AM_INDIRECT; return; // 3 -> *cdp
			}
		}
		if (base == 1) {
			// *(k23): the 23-bit (k24-encoded) absolute byte address lives in a
			// 3-byte extension that c55_decode appends and writes into abs_addr.
			// (The legacy decoder renders this address incorrectly -- it leaks
			// format-string bytes -- so the shared path supersedes it here.)
			out->amode = C55_AM_ABSOLUTE;
			out->abs_addr = C55_ABS_EXT;
			return;
		}
		out->amode = C55_AM_ABS16;
		return;
	}
	default:
		// all Smem modes (0-15) are handled above; this is defensive only.
		out->kind = C55_OP_INVALID;
		return;
	}
}

// Smem with a register shift count: the "Smem << Tx" forms (opcode 0xdd). The
// Smem byte is decoded as usual; the shift register Tx is the last byte's bits
// 2-3 (T0-T3), recorded in the dedicated shift-register field so it does not
// collide with any addressing index the Smem mode itself uses.
static void c55x_x_smem_shtx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind != C55_OP_MEM) {
		return; // invalid / instruction-extending Smem mode -> leave for the legacy
	}
	out->sh_mem_reg.cls = C55_RC_T;
	out->sh_mem_reg.num = (ut8)((bits >> 2) & 0x3);
	out->sh_mem_reg.sub = C55_SUB_NONE;
	out->sh_mem_reg_set = true;
}

// As c55x_x_smem_shtx, but also reads the rounding bit (byte2 bit 6) so the
// formatter wraps the operand in rnd(...) (the "mov rnd(Smem << Tx), ACx" form).
static void c55x_x_smem_shtx_rnd(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem_shtx(a, bits, d, out);
	if (out->kind != C55_OP_MEM) {
		return;
	}
	out->mem_round = (bits >> 6) & 1;
}

// Smem source shifted left by 16 for the mov Smem << #16, ACx load group
// (opcodes 0xb0-0xb3): reuses the Smem decode and tags the operand with the
// fixed << 16 shift. The shift is rendered but, like the legacy decoder, the
// load is not yet lifted (the shared lifter skips a shifted memory access).
static void c55x_x_smem_sh16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->sh_left = true;
		out->shamt = 16;
	}
}

// Smem source carrying the "unsigned" qualifier from byte2 bit 0, rendered
// uns(...) by the memory formatter. Used by the 0xdf add/sub Smem forms, where
// bit 0 selects between a signed and an unsigned memory operand.
static void c55x_x_smem_uns(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->uns = (bits & 1) != 0;
	}
}

// Smem source with a byte-access wrapper (d->param: 1 high_byte, 2 low_byte)
// plus the unsigned qualifier from byte2 bit 0. Used by the 0xdf mov
// high_byte/low_byte forms. The byte-access load is not lifted (the memory
// mover declines a byte_sel operand), matching the legacy decoder.
static void c55x_x_smem_byte(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->byte_sel = (ut8)d->param;
		out->uns = (bits & 1) != 0;
	}
}

// Destination special register of the 0xdc mov Smem, <special-reg> forms,
// selected by byte2 bits 4-7. d->param picks the sub-group: 2 is the
// dp/cdp/bsa*/sp/ssp/bk*/dph/pdp set (4-bit selector), 3 is the
// csr/brc*/trn* set (3-bit selector). Undefined selectors become INVALID so
// the instruction falls through to the legacy decoder.
static void c55x_x_dc_movdst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	static const int8_t g2[16] = {
		C55X_SPR_DP, C55X_SPR_CDP, C55X_SPR_BSA01, C55X_SPR_BSA23,
		C55X_SPR_BSA45, C55X_SPR_BSA67, C55X_SPR_BSAC, C55X_SPR_SP,
		C55X_SPR_SSP, C55X_SPR_BK03, C55X_SPR_BK47, C55X_SPR_BKC,
		C55X_SPR_DPH, -1, -1, C55X_SPR_PDP
	};
	static const int8_t g3[8] = {
		C55X_SPR_CSR, C55X_SPR_BRC0, C55X_SPR_BRC1, C55X_SPR_TRN0,
		C55X_SPR_TRN1, -1, -1, -1
	};
	int8_t spr = (d->param == 2) ? g2[(bits >> 4) & 0xf] : g3[(bits >> 4) & 0x7];
	if (spr < 0) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = (ut8)spr;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 16;
}

// A double-word (32-bit) single-data-memory operand: decoded like an Smem but
// rendered dbl(...) and treated as a two-word access (e.g. psh / pop dbl).
static void c55x_x_smem_dbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->dbl = true;
		out->access = 32;
	}
}

// Long (dual) data-memory operand printed as "dual(Smem)": the dual-operand
// add/sub forms (addsub / subadd Tx, dual(Lmem), ACy) access a 32-bit long
// word and wrap the Smem in dual(...) rather than dbl(...).
static void c55x_x_smem_dual(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->dual_wrap = true;
		out->access = 32;
	}
}

// MPY register form (opcode 0x58): the operand fields live in the low byte --
// Tx (bits 2-3), the source accumulator ACy (bits 4-5) and the destination
// accumulator ACx (bits 6-7). The disassembly is "mpy Tx, [ACy,] ACx": the
// middle source accumulator is printed only when it differs from the
// destination, so the source extractor yields C55_OP_NONE (which the decode
// loop skips) when the two coincide, giving the 2-operand form "mpy Tx, ACx".
static void c55x_x_mpy_t(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_T;
	out->reg.num = (ut8)((bits >> 2) & 0x3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

static void c55x_x_mpy_acsrc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 src = (ut8)((bits >> 4) & 0x3);
	ut8 dst = (ut8)((bits >> 6) & 0x3);
	if (src == dst) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = src;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

static void c55x_x_mpy_acdst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)((bits >> 6) & 0x3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Trailing destination ACy (bits 6-7) of the register MAC (opcode 0x56, mac
// form): the "mac[r] ACx, Tx, ACy[, ACy]" syntax prints the explicit second ACy
// only when it differs from the ACx multiplicand (bits 4-5). When they coincide
// the operand collapses (C55_OP_NONE) and the three-operand form is rendered;
// either way the lifter folds the accumulate into the single destination ACy.
static void c55x_x_macreg_acy_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 acx = (ut8)((bits >> 4) & 0x3);
	ut8 acy = (ut8)((bits >> 6) & 0x3);
	if (acx == acy) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = acy;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// SHIFTW: the 6-bit signed shift count immediate of the 0x10 register-ALU group
// (the last byte's bits 0-5). It is stored raw (unsigned) so the disassembler
// prints the field value as the legacy does; the lifter sign-extends it to
// choose the shift direction and magnitude.
static void c55x_x_shiftw(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0x3f;
	out->width = 6;
	out->imm_signed = false;
}

// As c55x_x_shiftw, but the field is the right-hand side of the "ACx << #SHIFTW"
// syntax used by the 0x10 and/or/xor/add/sub shift-and-combine forms, so it is
// rendered joined to the previous operand by " << " instead of a comma.
static void c55x_x_shiftw_shl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_shiftw(a, bits, d, out);
	out->shl_join = true;
}

// Tx shift-count operand of "add/sub ACx << Tx, ACy" (opcode 0x5a). The 2-bit
// field at d->lo selects t0..t3; it is rendered joined to the preceding ACx by
// " << " and read by the (register-count) ADDSHL/SUBSHL lifter.
static void c55x_x_tx_shl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_T;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	out->reg.sub = C55_SUB_NONE;
	out->shl_join = true;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Status register STn_55 operand of bclr / bset (opcode 0x46): the 3-bit field
// at d->lo selects st0_55..st3_55; selectors 4-7 are unassigned -> INVALID.
static void c55x_x_st(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 n = (ut8)((bits >> d->lo) & 0x7);
	if (n > 3) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_ST;
	out->reg.num = n;
	out->reg.sub = C55_SUB_NONE;
	const C55RegInfo *sri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = sri ? sri->width : 0;
}

// Register-register compare condition of cmp/cmpand/cmpor (opcode 0x12),
// rendered "SRC <relop> DST". SRC is the gr4 at byte-1 bits 4-7, DST the gr4 at
// byte-2 bits 4-7, the relop is byte-1 bits 2-3 (0 ==, 1 <, 2 >=, 3 !=).
static void c55x_x_cmpcond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	static const C55Relop rel_map[4] = { C55_REL_EQ, C55_REL_LT, C55_REL_GE, C55_REL_NE };
	out->kind = C55_OP_COND;
	out->cmp_to_reg = true;
	out->relop = rel_map[(bits >> 10) & 0x3];
	c55x_gr4((ut8)((bits >> 12) & 0xf), &out->reg);
	c55x_gr4((ut8)((bits >> 4) & 0xf), &out->index);
}

// A TC status-flag operand (tc1/tc2, optionally negated as !tc1/!tc2) of the
// compare forms. The selecting bit is at d->lo (byte-2 bit 0 for the TCz
// output, bit 1 for the cmpand/cmpor TCx input); 0 -> tc1, 1 -> tc2. When
// d->param is non-zero it is the bit position of the negation flag (byte-2
// bit 3 for the TCx input); a set negation bit yields the !tcN condition id.
static void c55x_x_tcflag(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 tcb = (ut8)((bits >> d->lo) & 0x1);
	bool neg = d->param && ((bits >> d->param) & 0x1);
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)((neg ? 20 : 4) + tcb);
}

// rol/ror rotate-in / rotate-out bit selector: a single bit picking CARRY (0)
// or TC2 (1). Rendered via the shared cond-flag table (carry -> id 6, tc2 -> id
// 5); the lifter maps these ids to status-register bits 11 (carry) and 12 (tc2).
static void c55x_x_rolflag(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 b = (ut8)((bits >> d->lo) & 0x1);
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = b ? 5 : 6; // 0 -> carry, 1 -> tc2
}

// Trailing destination ACy (bits 14-15) of the three-byte 0x10 register-ALU
// group, collapsing against the source ACx (bits 12-13) when the two are equal
// (mirrors c55x_x_macreg_acy_dst but for the wider three-byte encoding).
static void c55x_x_shiftk_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 acx = (ut8)((bits >> 12) & 0x3);
	ut8 acy = (ut8)((bits >> 14) & 0x3);
	if (acx == acy) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = acy;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}
// (uns(Cmem) -> zero-extended).
static void c55x_x_cmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_MEM;
	out->reg.cls = C55_RC_CDP;
	out->reg.num = 0;
	out->reg.sub = C55_SUB_NONE;
	out->access = 16;
	out->uns = d->param != 0;
	switch ((ut8)(bits & 0x3)) {
	case 0: out->amode = C55_AM_INDIRECT; break;
	case 1: out->amode = C55_AM_POSTINC; break;
	case 2: out->amode = C55_AM_POSTDEC; break;
	default: // 3: *(cdp+t0)
		out->amode = C55_AM_POSTADD;
		out->index.cls = C55_RC_T;
		out->index.num = 0;
		out->index.sub = C55_SUB_NONE;
		break;
	}
}

// Destination accumulator ACx of a memory multiply / MAC (last-byte bits 4-5).
static void c55x_x_mac_acdst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)((bits >> 4) & 0x3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Coefficient accumulator ACx (its high word ACx(32-16) is the multiplicand) of the
// accumulator-coefficient memory MACs: last-byte bits 0-1 select the source
// ACx, bits 4-5 the destination ACy. When the two coincide the legacy decoder
// renders the two-operand form but leaves it unlifted, so that case is reported
// as INVALID (the structured decode is abandoned to the legacy path) and only
// the distinct-register three-operand form is lifted here.
static void c55x_x_mac_accoef(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 ss = (ut8)(bits & 0x3);
	ut8 dd = (ut8)((bits >> 4) & 0x3);
	if (ss == dd) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = ss;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Coefficient T register Tx of the Tx-coefficient memory MACs (macm / masm /
// mpym Smem, Tx, ...); the two-bit Tx selector is at the op-slot's `lo`.
static void c55x_x_mac_tcoef(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_T;
	out->reg.num = (ut8)((bits >> d->lo) & 0x3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// mpymu Smem, Tx, ACx: the unsigned multiply (last byte's op bits = 11). The whole
// operation is unsigned, so both multiplicands carry uns; the 'u' mnemonic suffix
// (uns_all) renders them without per-operand uns() wrappers.
static void c55x_x_smem_u(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_smem(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->uns = true;
	}
}
static void c55x_x_tcoef_u(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_mac_tcoef(a, bits, d, out);
	out->uns = true;
}

// Accumulator operand ACx (last-byte bits 0-1) that collapses against the
// destination ACy (bits 4-5): used both as the explicit accumulator source of
// the Tx-coefficient MACs and as the high-word ACx(32-16) coefficient of the
// accumulator-coefficient multiplies. When the two registers differ the
// four/three-operand form is rendered with ACx present; when they coincide the
// operand collapses (NONE) to the shorter form whose role defaults to ACy.
static void c55x_x_mac_accsrc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 ss = (ut8)(bits & 0x3);
	ut8 dd = (ut8)((bits >> 4) & 0x3);
	if (ss == dd) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	out->reg.cls = C55_RC_AC;
	out->reg.num = ss;
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

static const char *c55x_mnemonic(ut16 id) {
	return tms320c55x_insn_name((TMS320C55InsID)id);
}

static ut32 c55x_op_type(ut16 id) {
	switch ((TMS320C55InsID)id) {
	case TMS320C55_INS_NOP:
	case TMS320C55_INS_IDLE: return RZ_ANALYSIS_OP_TYPE_NOP;
	case TMS320C55_INS_MOV: return RZ_ANALYSIS_OP_TYPE_MOV;
	// delay Smem: a memory-delay that copies the addressed word to the next
	// higher address (TI SWPU104 6.7.1); the legacy analysis models it as a
	// data MOVE, so the shared path mirrors that op type.
	case TMS320C55_INS_DELAY: return RZ_ANALYSIS_OP_TYPE_MOV;
	// amar computes an effective address (and applies the addressing mode's
	// post-modify side effect) without accessing memory: an address load.
	case TMS320C55_INS_AMAR: return RZ_ANALYSIS_OP_TYPE_LEA;
	// psh / pop a single-data-memory operand onto / off the stack.
	case TMS320C55_INS_PSH: return RZ_ANALYSIS_OP_TYPE_PUSH;
	case TMS320C55_INS_POP: return RZ_ANALYSIS_OP_TYPE_POP;
	case TMS320C55_INS_PSHBOTH: return RZ_ANALYSIS_OP_TYPE_PUSH;
	case TMS320C55_INS_POPBOTH: return RZ_ANALYSIS_OP_TYPE_POP;
	case TMS320C55_INS_ADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_SUB: return RZ_ANALYSIS_OP_TYPE_SUB;
	// mpy Tx, [ACy,] ACx: a register multiply (ACx = Tx * ACy(32-16)).
	case TMS320C55_INS_MPY: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MPYK: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MACK: return RZ_ANALYSIS_OP_TYPE_MUL;
	// mpym Smem, Cmem, ACx: a memory multiply (ACx = Smem * Cmem).
	case TMS320C55_INS_MPYM: return RZ_ANALYSIS_OP_TYPE_MUL;
	// macm / masm Smem, Cmem, ACx: memory multiply-accumulate / -subtract.
	case TMS320C55_INS_MACM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MASM: return RZ_ANALYSIS_OP_TYPE_MUL;
	// mac / mas Smem, uns(Cmem), ACx: the unsigned-coefficient memory MACs.
	case TMS320C55_INS_MAC: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MAS: return RZ_ANALYSIS_OP_TYPE_MUL;
	// sqrm / sqam / sqsm Smem, [ACx,] ACy: the squaring multiplies (ACy =
	// [ACx +/-] Smem * Smem). The legacy decoder leaves these untyped and
	// unlifted; the shared path classifies them as multiplies and lifts them.
	case TMS320C55_INS_SQRM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SQAM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SQSM: return RZ_ANALYSIS_OP_TYPE_MUL;
	// The 0x54 register square / square-accumulate forms are genuine multiplies
	// (ACy = ACx*ACx [+/- ACy]); the legacy left them untyped (null).
	case TMS320C55_INS_SQR: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SQA: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SQS: return RZ_ANALYSIS_OP_TYPE_MUL;
	// addv / addrv (addition with absolute value) -- typed as an addition.
	case TMS320C55_INS_ADDV: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_ADDRV: return RZ_ANALYSIS_OP_TYPE_ADD;
	// aadd #k8, sp (address-arithmetic add, frame setup) -- an addition.
	case TMS320C55_INS_AADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	// amov #k16, dst: legacy types the constant/address load as LEA; the actual
	// dst = zero-extend(#k16) semantics come from the C55_LOP_AMOV lifter.
	case TMS320C55_INS_AMOV: return RZ_ANALYSIS_OP_TYPE_LEA;
	// rptb / rptcc: block / conditional repeat loop control.
	case TMS320C55_INS_RPTB:
	case TMS320C55_INS_RPTCC: return RZ_ANALYSIS_OP_TYPE_REP;
	// rptadd / rptsub: adjust the single-repeat counter and repeat.
	case TMS320C55_INS_RPTADD:
	case TMS320C55_INS_RPTSUB: return RZ_ANALYSIS_OP_TYPE_REP;
	// cmp / cmpand / cmpor SRC <relop> DST, TCz: register compare writing a TC bit.
	case TMS320C55_INS_CMP:
	case TMS320C55_INS_CMPAND:
	case TMS320C55_INS_CMPOR: return RZ_ANALYSIS_OP_TYPE_CMP;
	// swap / swapp / swap4: register (pair) exchange.
	case TMS320C55_INS_SWAP: return RZ_ANALYSIS_OP_TYPE_XCHG;
	case TMS320C55_INS_SWAPP: return RZ_ANALYSIS_OP_TYPE_XCHG;
	case TMS320C55_INS_SWAP4: return RZ_ANALYSIS_OP_TYPE_XCHG;
	// sftl / sfts / sftsc ACx, Tx[, ACy]: a register shift by a T-register count
	// (the sign of Tx selects the direction). Typed as a shift like the legacy.
	case TMS320C55_INS_SFTL: return RZ_ANALYSIS_OP_TYPE_SHL;
	case TMS320C55_INS_SFTS: return RZ_ANALYSIS_OP_TYPE_SHL;
	case TMS320C55_INS_SFTSC: return RZ_ANALYSIS_OP_TYPE_SHL;
	// firsadd / firssub Xmem, Ymem, Cmem, ACx, ACy: a FIR-filter step combining a
	// multiply-accumulate (ACy += ACx.h * Cmem) with a shifted (anti)symmetric sum
	// (ACx = (Xmem<<16) +/- (Ymem<<16)). The legacy left these unlifted with an
	// inconsistent type (firsadd -> lea, firssub -> null); the shared path lifts
	// them and classifies both as the multiply that dominates.
	case TMS320C55_INS_FIRSADD: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_FIRSSUB: return RZ_ANALYSIS_OP_TYPE_MUL;
	// sqdst squares the ACx high word into ACy (a multiply); abdst only adds an
	// absolute value, so it keeps the legacy's null type (no precise rizin type).
	case TMS320C55_INS_SQDST: return RZ_ANALYSIS_OP_TYPE_MUL;
	// lms multiply-accumulates Xmem*Ymem into ACy (with a parallel shifted add into
	// ACx); the legacy left it unlifted and null-typed -- classify as the multiply.
	case TMS320C55_INS_LMS: return RZ_ANALYSIS_OP_TYPE_MUL;
	// neg has no dedicated RzAnalysis op type; the legacy analysis reports it
	// as a subtraction, and the lifter distinguishes it via C55_LOP_NEG.
	case TMS320C55_INS_NEG: return RZ_ANALYSIS_OP_TYPE_SUB;
	// max / min likewise have no dedicated op type; the legacy analysis reports
	// them as compares, and the lifter selects them via C55_LOP_MAX / _MIN.
	case TMS320C55_INS_MAX: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_MIN: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_AND: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTST: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTSET: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BAND: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTCLR: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTNOT: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BSET: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BCLR: return RZ_ANALYSIS_OP_TYPE_MOV;
	// bfxtr K16, ACx, ACy: extract the bits of ACx selected by the K16 mask and
	// right-pack them into ACy -- a register field move (the companion bfxpa
	// stays untyped, as the legacy decoder left it).
	case TMS320C55_INS_BFXTR: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BNOT: return RZ_ANALYSIS_OP_TYPE_XOR;
	case TMS320C55_INS_ADDSUBCC: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_SUBC: return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_ADDSUB: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_SUBADD: return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_OR: return RZ_ANALYSIS_OP_TYPE_OR;
	case TMS320C55_INS_XOR: return RZ_ANALYSIS_OP_TYPE_XOR;
	case TMS320C55_INS_NOT: return RZ_ANALYSIS_OP_TYPE_NOT;
	// Register-indirect branch / call (b acx / call acx) transfer control to an
	// address held in an accumulator, so they are unconditional indirect forms.
	case TMS320C55_INS_B: return RZ_ANALYSIS_OP_TYPE_UJMP;
	case TMS320C55_INS_CALL: return RZ_ANALYSIS_OP_TYPE_UCALL;
	// reset triggers a non-maskable software reset; model it as a trap.
	case TMS320C55_INS_RESET: return RZ_ANALYSIS_OP_TYPE_TRAP;
	// intr / trap raise a software interrupt / trap to a vector number.
	case TMS320C55_INS_INTR: return RZ_ANALYSIS_OP_TYPE_SWI;
	case TMS320C55_INS_TRAP: return RZ_ANALYSIS_OP_TYPE_TRAP;
	// rpt sets up a single-instruction hardware repeat (a loop construct).
	case TMS320C55_INS_RPT: return RZ_ANALYSIS_OP_TYPE_REP;
	// rptblocal arms a local block-repeat; likewise a loop construct.
	case TMS320C55_INS_RPTBLOCAL: return RZ_ANALYSIS_OP_TYPE_REP;
	// ret / reti pop the return (or interrupt-return) address; both are returns.
	case TMS320C55_INS_RET: return RZ_ANALYSIS_OP_TYPE_RET;
	case TMS320C55_INS_RETI: return RZ_ANALYSIS_OP_TYPE_RET;
	// xcc / xccpart predicate the following instruction(s) on a condition; model
	// them as a compare (matching the legacy type).
	case TMS320C55_INS_XCC: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_XCCPART: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_BCC: return RZ_ANALYSIS_OP_TYPE_CJMP;
	case TMS320C55_INS_CALLCC: return RZ_ANALYSIS_OP_TYPE_CCALL;
	case TMS320C55_INS_RETCC: return RZ_ANALYSIS_OP_TYPE_CRET;
	default: return RZ_ANALYSIS_OP_TYPE_NULL;
	}
}

static ut8 c55x_insn_len(const ut8 *buf, int len) {
	const int sz = c55x_op_size(buf, len);
	return (sz > 0) ? (ut8)sz : 0;
}

// --- dual "::" MAC operand filling ---------------------------------------
// One Xmem / Ymem operand of a dual MAC: a 3-bit ARn selector and a 3-bit
// addressing mode. Unlike the single-data Smem 4-bit mode, the dual modes are
// 0:*ARn 1:*ARn+ 2:*ARn- 3:*(ARn+T0) 4:*(ARn+T1) 5:*(ARn-T0) 6:*(ARn-T1)
// 7:*ARn(T0); the uns() wrapper (zero-extend on load) is shared with this
// sub-MAC's Cmem coefficient.
static void c55x_dual_mem(C55Operand *out, ut8 ar, ut8 mode, bool uns) {
	memset(out, 0, sizeof(*out));
	out->kind = C55_OP_MEM;
	out->access = 16;
	out->uns = uns;
	c55x_gr4((ut8)(8 + (ar & 7)), &out->reg); // base ARn
	switch (mode & 7) {
	case 0: out->amode = C55_AM_INDIRECT; break;
	case 1: out->amode = C55_AM_POSTINC; break;
	case 2: out->amode = C55_AM_POSTDEC; break;
	case 3: out->amode = C55_AM_POSTADD; c55x_gr4(4, &out->index); break; // *(ARn+T0)
	case 4: out->amode = C55_AM_POSTADD; c55x_gr4(5, &out->index); break; // *(ARn+T1)
	case 5: out->amode = C55_AM_POSTSUB; c55x_gr4(4, &out->index); break; // *(ARn-T0)
	case 6: out->amode = C55_AM_POSTSUB; c55x_gr4(5, &out->index); break; // *(ARn-T1)
	default: out->amode = C55_AM_IDXREG; c55x_gr4(4, &out->index); break; // *ARn(T0)
	}
}

// The shared Cmem coefficient (*CDP with the same post-modify mm as the single
// MACs); each sub-MAC reads it with its own uns() signedness.
static void c55x_dual_cmem(C55Operand *out, ut8 cmode, bool uns) {
	memset(out, 0, sizeof(*out));
	out->kind = C55_OP_MEM;
	out->reg.cls = C55_RC_CDP;
	out->access = 16;
	out->uns = uns;
	switch (cmode & 3) {
	case 0: out->amode = C55_AM_INDIRECT; break;
	case 1: out->amode = C55_AM_POSTINC; break;
	case 2: out->amode = C55_AM_POSTDEC; break;
	default: // *(CDP+T0)
		out->amode = C55_AM_POSTADD;
		out->index.cls = C55_RC_T;
		out->index.num = 0;
		break;
	}
}

static void c55x_dual_ac(const C55ArchDesc *a, C55Operand *out, ut8 num) {
	memset(out, 0, sizeof(*out));
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)(num & 3);
	const C55RegInfo *ri = a->reg_info ? a->reg_info(out->reg.cls, out->reg.num, C55_SUB_NONE) : NULL;
	out->width = ri ? ri->width : 0;
}

// Fill the canonical dual-MAC operand layout from the 4-byte word. Byte1 carries
// the Xmem ARn (bits 5-7) and mode (bits 2-4) and the Ymem ARn low bits (0-1);
// byte2 the Cmem mode (bits 0-1), the op selector (bits 2-3, already matched),
// the Ymem mode (bits 4-6) and the Ymem ARn high bit (bit 7); byte3 the round R
// (bit 0), the 40-bit flag (bit 1), ACx (bits 2-3), ACy (bits 4-5) and the per-
// sub uns flags (bit 6 = sub2/Ymem, bit 7 = sub1/Xmem). An amar sub1 has no Cmem
// or destination, and the single accumulator field then names sub2's destination.
static bool c55x_fill_dual(const C55ArchDesc *a, ut64 bits, const C55InsnDef *def, C55Insn *out) {
	const ut8 b1 = (ut8)((bits >> 16) & 0xff);
	const ut8 b2 = (ut8)((bits >> 8) & 0xff);
	const ut8 b3 = (ut8)(bits & 0xff);
	out->dual = true;
	out->lop2 = def->lop2;
	out->amar1 = def->amar1;
	out->shift1 = def->shift1;
	out->shift2 = def->shift2;
	out->round = b3 & 1;
	out->m40 = (b3 >> 1) & 1;
	const bool uns_y = (b3 >> 6) & 1;
	const bool uns_x = (b3 >> 7) & 1;
	const ut8 acx = (ut8)((b3 >> 2) & 3);
	const ut8 acy = (ut8)((b3 >> 4) & 3);
	c55x_dual_mem(&out->ops[0], (ut8)((b1 >> 5) & 7), (ut8)((b1 >> 2) & 7), uns_x); // Xmem
	c55x_dual_cmem(&out->ops[1], (ut8)(b2 & 3), uns_x); // Cmem (sub1)
	c55x_dual_ac(a, &out->ops[2], acx); // ACx
	c55x_dual_mem(&out->ops[3], (ut8)(((b1 & 3) << 1) | ((b2 >> 7) & 1)), (ut8)((b2 >> 4) & 7), uns_y); // Ymem
	c55x_dual_cmem(&out->ops[4], (ut8)(b2 & 3), uns_y); // Cmem (sub2)
	c55x_dual_ac(a, &out->ops[5], acy); // ACy
	if (def->amar1) {
		// amar sub1 has no Cmem / destination and renders no uns() wrapper; the
		// single accumulator field (ACx slot) is sub2's destination, and sub2's
		// uns comes from the high uu bit (uns_x); the low bit is unused here.
		out->ops[0].uns = false;
		out->ops[1].kind = C55_OP_NONE;
		out->ops[2].kind = C55_OP_NONE;
		out->ops[3].uns = uns_x;
		out->ops[4].uns = uns_x;
		c55x_dual_ac(a, &out->ops[5], acx); // single dst -> sub2
	}
	out->n_ops = 6;
	return true;
}

// Operand extractors for the triple-register amar (amar Xmem, Ymem, Cmem):
// the same Xmem / Ymem / Cmem fields as the dual MACs, but as three plain
// address-modify operands (no uns, no destination).
static void c55x_x_dual_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	const ut8 b1 = (ut8)((bits >> 16) & 0xff);
	c55x_dual_mem(out, (ut8)((b1 >> 5) & 7), (ut8)((b1 >> 2) & 7), false);
}
static void c55x_x_dual_ymem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	const ut8 b1 = (ut8)((bits >> 16) & 0xff);
	const ut8 b2 = (ut8)((bits >> 8) & 0xff);
	c55x_dual_mem(out, (ut8)(((b1 & 3) << 1) | ((b2 >> 7) & 1)), (ut8)((b2 >> 4) & 7), false);
}
static void c55x_x_dual_cmem3(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	c55x_dual_cmem(out, (ut8)((bits >> 8) & 3), false);
}

// Dual-memory Xmem/Ymem fields for the 3-byte mov / add / sub Xmem,Ymem forms
// (opcodes 0x80 / 0x81). Unlike the 4-byte 0x82-0x86 MAC family (where the
// fields sit in byte1/byte2), here byte1 = XXXMMMYY and byte2 = YMMM00xx, one
// byte earlier in the packed word -- so read byte1 = bits[15:8], byte2 =
// bits[7:0]. Xmem: ARn = byte1[7:5], mode = byte1[4:2]. Ymem: ARn =
// (byte1[1:0]<<1)|byte2[7], mode = byte2[6:4].
static void c55x_x_dual_xmem3(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	const ut8 b1 = (ut8)((bits >> 8) & 0xff);
	c55x_dual_mem(out, (ut8)((b1 >> 5) & 7), (ut8)((b1 >> 2) & 7), false);
}
static void c55x_x_dual_ymem3(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	const ut8 b1 = (ut8)((bits >> 8) & 0xff);
	const ut8 b2 = (ut8)(bits & 0xff);
	c55x_dual_mem(out, (ut8)(((b1 & 3) << 1) | ((b2 >> 7) & 1)), (ut8)((b2 >> 4) & 7), false);
}
// dbl() variants: the "mov dbl(Xmem), dbl(Ymem)" form moves a 32-bit long word.
static void c55x_x_dual_xmem3_dbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_dual_xmem3(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->dbl = true;
		out->access = 32;
	}
}
static void c55x_x_dual_ymem3_dbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55x_x_dual_ymem3(a, bits, d, out);
	if (out->kind == C55_OP_MEM) {
		out->dbl = true;
		out->access = 32;
	}
}

// 0x86 dual-multiply (mpym / macm / masm Xmem, Ymem, ...): Xmem and Ymem share
// the 0x82-0x85 byte1/byte2 addressing-field layout, but the per-operand uns()
// qualifiers live in the last byte (bit 3 = Xmem, bit 2 = Ymem) and the source /
// destination accumulators in byte 2 (DD = bits 0-1, SS = bits 2-3).
static void c55x_x_xymac_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	const ut8 b1 = (ut8)((bits >> 16) & 0xff);
	c55x_dual_mem(out, (ut8)((b1 >> 5) & 7), (ut8)((b1 >> 2) & 7), (bool)((bits >> 3) & 1));
}
static void c55x_x_xymac_ymem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	const ut8 b1 = (ut8)((bits >> 16) & 0xff);
	const ut8 b2 = (ut8)((bits >> 8) & 0xff);
	c55x_dual_mem(out, (ut8)(((b1 & 3) << 1) | ((b2 >> 7) & 1)), (ut8)((b2 >> 4) & 7), (bool)((bits >> 2) & 1));
}
// Source accumulator of the dual-multiply MACs (macm / masm Xmem, Ymem, ACx, ACy):
// SS is byte2 bits 2-3, DD byte2 bits 0-1. When the two coincide the instruction
// is the two-operand form (ACy += Xmem*Ymem) and the explicit source slot is
// dropped (the generic ops[] loop compacts the NONE slot away).
static void c55x_x_xymac_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 dd = (ut8)((bits >> 8) & 3);
	ut8 ss = (ut8)((bits >> 10) & 3);
	if (ss == dd) {
		out->kind = C55_OP_NONE;
		return;
	}
	c55x_dual_ac(a, out, ss);
}

static const C55InsnDef c55x_table[] = {
	// nop: single-byte 0x20 (shared encoding with C55x+).
	{ .mask = 0xfe000000, .match = 0x20000000, .id = TMS320C55_INS_NOP },
	// mov src, dst (opcode 0x22): the operand byte's high nibble selects the
	// source and the low nibble the destination, each a 4-bit register field
	// (AC0-3 / T0-3 / AR0-7). ops[0]=src, ops[1]=dst per the shared lifter.
	{ .mask = 0xfe000000, .match = 0x22000000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	// add / sub src, dst (opcodes 0x24 / 0x26): same operand byte as mov (high
	// nibble source, low nibble destination). dst = dst <op> src; the
	// destination is elided when it equals the source (the legacy single-operand
	// "add ac0" form).
	{ .mask = 0xfe000000, .match = 0x24000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_AREG_ADD, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	{ .mask = 0xfe000000, .match = 0x26000000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_AREG_SUB, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	// and / or / xor src, dst (opcodes 0x28 / 0x2a / 0x2c): same operand byte
	// as mov (high nibble source, low nibble destination). dst = dst <op> src
	// via the shared lifter (equal-width forms; mixed-width forms fall back).
	{ .mask = 0xfe000000, .match = 0x28000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_AREG_AND, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe000000, .match = 0x2a000000, .id = TMS320C55_INS_OR, .lop = C55_LOP_AREG_OR, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe000000, .match = 0x2c000000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_AREG_XOR, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	// not src[, dst] (opcode 0x36): dst = ~src. The source is optional in the
	// short form; the destination collapses against it (elided when equal).
	{ .mask = 0xfe000000, .match = 0x36000000, .id = TMS320C55_INS_NOT, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	// neg src[, dst] (opcode 0x34): dst = -src. Optional-source short form; the
	// destination collapses against the source (elided when equal). The lifter
	// uses C55_LOP_NEG since neg shares the SUB op type.
	{ .mask = 0xfe000000, .match = 0x34000000, .id = TMS320C55_INS_NEG, .lop = C55_LOP_NEG, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	// max / min src[, dst] (opcodes 0x2e / 0x30): dst = max/min(src, dst).
	// Optional-source short form (destination elided when equal to the source);
	// the lifter emits the ite via C55_LOP_MAX / _MIN since both share CMP.
	{ .mask = 0xfe000000, .match = 0x2e000000, .id = TMS320C55_INS_MAX, .lop = C55_LOP_MAX, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	{ .mask = 0xfe000000, .match = 0x30000000, .id = TMS320C55_INS_MIN, .lop = C55_LOP_MIN, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	// abs src[, dst] (opcode 0x32): dst = |src|. Optional-source short form (the
	// destination is elided when equal to the source). abs has no RzAnalysis op
	// type at all (the legacy analysis reports type null), so it reaches the
	// shared path via its lift-op rather than its op type; the lifter emits the
	// ite through C55_LOP_ABS.
	{ .mask = 0xfe000000, .match = 0x32000000, .id = TMS320C55_INS_ABS, .lop = C55_LOP_ABS, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4_elide } } },
	// mov k4, dst (opcode 0x3c): 4-bit unsigned immediate (operand byte's high
	// nibble) into the register selected by the low nibble. dst = k4, the
	// immediate zero-extended to the destination width by the shared lifter.
	{ .mask = 0xfe000000, .match = 0x3c000000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	// mov -#k, dst (opcode 0x3e): like mov k4 but the high nibble is a negated
	// magnitude (-0 .. -15). The legacy leaves it unlifted, so the shared MOV
	// lifter declines it (see c55x_x_negk4 / the neg_imm guard).
	{ .mask = 0xfe000000, .match = 0x3e000000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55x_x_negk4 }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	// mov #k12, <reg> (opcode 0x16): a 12-bit immediate (bytes 1-2, bits 12-23)
	// into a control register selected by byte2's low nibble (dph/pdp/bk03/bk47/
	// bkc/csr/brc0/brc1). The immediate is masked to the register width; the
	// shared MOV lifter emits "reg = k".
	{ .mask = 0xfe000000, .match = 0x16000000, .id = TMS320C55_INS_MOV, .len = 3,
		.ops = { { .lo = 4, .width = 12, .fn = c55x_x_16imm }, { .lo = 0, .width = 4, .fn = c55x_x_16dst } } },
	// mov #k16, <reg> (opcode 0x78): a 16-bit immediate (instruction bytes 1-2)
	// into a control register selected by byte3 (see c55x_x_78dst). dst = k16,
	// the immediate zero-extended to the dst width by the shared MOV lifter.
	{ .mask = 0xff000000, .match = 0x78000000, .id = TMS320C55_INS_MOV, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 1, .width = 4, .fn = c55x_x_78dst } } },
	// ACy = ACx <op> (#k16 << #sh) (opcodes 0x70 add, 0x71 sub, 0x72 and,
	// 0x73 or, 0x74 xor): a 16-bit immediate (bytes 1-2) shifted up by byte3
	// bits 0-3 (0-15), combined with ACx into ACy. byte3 bits 6-7 select ACx,
	// bits 4-5 ACy (elided when equal to ACx). The 0x75 mov form is left to the
	// legacy decoder (it carries no IL there).
	{ .mask = 0xff000000, .match = 0x70000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_varsh }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff000000, .match = 0x71000000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_varsh }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff000000, .match = 0x72000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_varsh }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff000000, .match = 0x73000000, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_varsh }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff000000, .match = 0x74000000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_varsh }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	// mov #k16 << #sh, ACy (opcode 0x75): the immediate shifted into ACy; no
	// source accumulator and (matching the legacy) no IL -- the MOV lifter
	// declines the variable-shift form, leaving it unlifted.
	{ .mask = 0xff000000, .match = 0x75000000, .id = TMS320C55_INS_MOV, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_varsh }, { .lo = 4, .fn = c55x_x_ac2 } } },
	// ACy = ACx <op> (#k16 << #16) (opcode 0x7a): a 16-bit immediate (bytes 1-2)
	// shifted up 16 bits, combined with ACx into ACy. byte3 bits 1-3 select the
	// operation (0 add, 1 sub, 2 and, 3 or, 4 xor; 5 mov / 6 idle / 7 invalid
	// are left to the legacy decoder), bits 6-7 ACx, bits 4-5 ACy (elided when
	// equal to ACx); byte3 bit 0 is don't-care.
	{ .mask = 0xff00000e, .match = 0x7a000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_sh16 }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff00000e, .match = 0x7a000002, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_sh16 }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff00000e, .match = 0x7a000004, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_sh16 }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff00000e, .match = 0x7a000006, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_sh16 }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff00000e, .match = 0x7a000008, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORSHL, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_sh16 }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	// mov #k16 << #16, ACy (opcode 0x7a, byte3 selector 5): the immediate (sign-
	// extended, shifted up 16) loaded into ACy; there is no source accumulator.
	{ .mask = 0xff00000e, .match = 0x7a00000a, .id = TMS320C55_INS_MOV, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55x_x_imm_sh16 }, { .lo = 4, .fn = c55x_x_ac2 } } },
	// dst = ACx <op> zero-extend(#k16) (opcodes 0x7b add, 0x7c sub, 0x7d and,
	// 0x7e or, 0x7f xor): a 16-bit immediate (bytes 1-2), the source accumulator
	// in byte3 bits 0-3 (gr4) and the destination in bits 4-7 (gr4). add / sub
	// collapse the destination when it equals the source ("add #k, ACx"); the
	// bitwise forms always render all three operands. The lifter handles an
	// accumulator source and (matching the legacy) leaves a T / AR source
	// unlifted; a 16-bit destination truncates the 40-bit result.
	{ .mask = 0xff000000, .match = 0x7b000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDK, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4_elide } } },
	{ .mask = 0xff000000, .match = 0x7c000000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBK, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4_elide } } },
	{ .mask = 0xff000000, .match = 0x7d000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDK, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000000, .match = 0x7e000000, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORK, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000000, .match = 0x7f000000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORK, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	// dst = ACx <op> zero-extend(#k8) (opcodes 0x18 and, 0x1a or, 0x1c xor; the
	// parallel "|| " encodings 0x19 / 0x1b / 0x1d differ only in byte0 bit 0, so
	// the mask leaves that bit to the parallel-bit derivation): an 8-bit
	// immediate (byte1), the gr4 source in byte2 bits 0-3 and the gr4 destination
	// in bits 4-7. The same immediate-ALU lifter handles an accumulator source
	// and (matching the legacy) leaves a T / AR source unlifted; a 16-bit T / AR
	// destination truncates the result.
	{ .mask = 0xfe000000, .match = 0x18000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDK, .len = 3,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe000000, .match = 0x1a000000, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORK, .len = 3,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe000000, .match = 0x1c000000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORK, .len = 3,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	// add / sub k4, dst (opcodes 0x40 / 0x42): same immediate layout as mov k4;
	// dst = dst +/- k4 with the immediate zero-extended to the dst width.
	{ .mask = 0xfe000000, .match = 0x40000000, .id = TMS320C55_INS_ADD, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe000000, .match = 0x42000000, .id = TMS320C55_INS_SUB, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 0, .width = 4, .fn = c55x_x_gr4 } } },
	// mov Smem, dst load (opcodes 0xa0-0xaf): the destination register is gr4
	// of the opcode's low nibble (AC0-3 / T0-3 / AR0-7) and the source is a
	// single data-memory operand. Only the register-modify addressing modes the
	// shared effective-address / memory primitives handle are decoded; the rest
	// fall back to the legacy decoder via c55x_x_smem. The low nibble is the
	// destination register, not the parallel marker, so the row opts out of the
	// parallel-bit derivation (no_parallel).
	{ .mask = 0xf0000000, .match = 0xa0000000, .id = TMS320C55_INS_MOV, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem }, { .lo = 8, .width = 4, .fn = c55x_x_gr4 } } },
	// mov reg, Smem store (opcodes 0xc0-0xcf): the direction mirror of the load.
	// The source register is gr4 of the opcode's low nibble and the destination
	// is a single data-memory operand; a wider accumulator source is truncated
	// to the 16-bit access by the shared memory primitives. Same addressing-mode
	// coverage and no_parallel rationale as the load row.
	{ .mask = 0xf0000000, .match = 0xc0000000, .id = TMS320C55_INS_MOV, .len = 2, .no_parallel = true,
		.ops = { { .lo = 8, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .width = 8, .fn = c55x_x_smem } } },
	// mov hi(ACx), Smem store (opcodes 0xbc-0xbf): stores the high half of the
	// accumulator (ACx.h, accumulator number in the low two bits) to a single
	// data-memory operand. The shared half-source read produces the 16-bit high
	// half, stored through the same primitives. Same Smem coverage as the load
	// and store rows; the low two bits are the accumulator field, not the
	// parallel marker (no_parallel).
	{ .mask = 0xfc000000, .match = 0xbc000000, .id = TMS320C55_INS_MOV, .len = 2, .no_parallel = true,
		.ops = { { .lo = 8, .width = 2, .fn = c55x_x_achi }, { .lo = 0, .width = 8, .fn = c55x_x_smem } } },
	// mov Smem << #16, ACx (opcodes 0xb0-0xb3): loads a single data-memory
	// operand shifted left by 16 into an accumulator (number in the low two
	// bits). The shift is rendered but the load is not yet lifted (matching the
	// legacy decoder's empty IL); the low two bits are the accumulator field,
	// not the parallel marker (no_parallel).
	{ .mask = 0xfc000000, .match = 0xb0000000, .id = TMS320C55_INS_MOV, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem_sh16 }, { .lo = 8, .width = 2, .fn = c55x_x_ac2 } } },
	// amar Smem (opcode 0xb4): modify auxiliary register -- computes the
	// effective address and applies the addressing mode's post-modify side
	// effect without accessing memory. Single Smem operand (the low byte is the
	// addressing field, not the parallel marker -> no_parallel). It lifts to
	// that side effect, or a nop for non-modifying modes, and is typed LEA.
	{ .mask = 0xff000000, .match = 0xb4000000, .id = TMS320C55_INS_AMAR, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem } } },
	// amar Smem, xar (opcode 0xec): load the effective (word) address of the
	// single-data-memory operand into an extended pointer register, with no
	// memory access. byte1 is the Smem field; byte2's high nibble selects the
	// XARn destination (c55x_x_gr4a maps 8..15 -> xar0..7) and its low nibble
	// 0xe is the form marker (mask requires it, distinguishing this from the
	// other 0xec sub-opcodes). The shared amar lifter loads base+offset into
	// the destination for the SP/AR-relative modes; the *(k23) absolute sub-
	// form (Smem mode-8 base-1) is left invalid above and falls to the legacy
	// decoder, which sizes it correctly.
	{ .mask = 0xff000f00, .match = 0xec000e00, .id = TMS320C55_INS_AMAR, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 4, .width = 4, .fn = c55x_x_gr4a } } },
	// dbl(Lmem) 32-bit load / store / accumulate (opcodes 0xed load, 0xeb store).
	// These are 3-byte forms whose last byte (the packed value's low byte)
	// selects the sub-form: bits 3-1 == 100 is "mov dbl(Lmem), ACx" (DD = ACx in
	// bits 5-4); bits 3-1 == 000/001 are "add/sub dbl(Lmem), [ACx,] ACy" (DD = dst
	// ACy in bits 5-4, SS = optional src ACx in bits 7-6, suppressed when equal);
	// and bits 3-0 == 1111 is "mov dbl(Lmem), XAdst" (the extended pointer in
	// bits 7-4). The store opcode's "mov ACx, dbl(Lmem)" has bits 3,2,0 == 1,0,0
	// with SS = ACx in bits 5-4. The Lmem field is byte1; its *(k23) absolute
	// sub-mode supplies the true k24 address (the legacy decoder rendered it
	// wrongly). The dbl moves lift through the shared 32-bit memory mover; add/sub
	// fall back to the legacy lifter.
	{ .mask = 0xff000e00, .match = 0xed000800, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_dbl }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000f00, .match = 0xed000f00, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_dbl }, { .lo = 4, .width = 4, .fn = c55x_x_gr4a } } },
	{ .mask = 0xff000e00, .match = 0xed000000, .id = TMS320C55_INS_ADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_dbl }, { .lo = 6, .width = 2, .fn = c55x_x_ac_src2 }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000e00, .match = 0xed000200, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_dbl }, { .lo = 6, .width = 2, .fn = c55x_x_ac_src2 }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000d00, .match = 0xeb000800, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 8, .width = 8, .fn = c55x_x_smem_dbl } } },
	// delay Smem (opcode 0xb6): memory delay -- copies the addressed word to
	// the next higher data address (TI SWPU104 6.7.1). Single Smem operand (the
	// low byte is the addressing field, so no_parallel; note 0xb7 is a distinct
	// opcode, psh dbl). Typed MOVE via c55x_op_type; the side effect is not
	// modelled (OPAQUE -> empty IL, matching the legacy lifter).
	{ .mask = 0xff000000, .match = 0xb6000000, .id = TMS320C55_INS_DELAY, .lop = C55_LOP_OPAQUE, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem } } },
	// psh Smem (opcode 0xb5) / pop Smem (opcode 0xbb) push / pop a single
	// data-memory word; psh dbl(Smem) (0xb7) / pop dbl(Smem) (0xb8) push / pop a
	// double word. Single Smem operand (the low byte is the addressing field,
	// not the parallel marker -> no_parallel); the analysis stack effect (one
	// word for the single forms, two for the dbl forms) comes from the PUSH /
	// POP op-type, and the IL is left to the legacy lifter (empty). Only the
	// duplicate 0xb9 pop dbl now stays on the legacy decoder.
	{ .mask = 0xff000000, .match = 0xb5000000, .id = TMS320C55_INS_PSH, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem } } },
	{ .mask = 0xff000000, .match = 0xbb000000, .id = TMS320C55_INS_POP, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem } } },
	{ .mask = 0xff000000, .match = 0xb7000000, .id = TMS320C55_INS_PSH, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem_dbl } } },
	{ .mask = 0xff000000, .match = 0xb8000000, .id = TMS320C55_INS_POP, .len = 2, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55x_x_smem_dbl } } },
	// psh / pop src1, src2 (opcode 0x38 psh, 0x3a pop; 0x39 / 0x3b parallel): push
	// or pop two independent gr4 registers in one instruction (byte1 bits 4-7 name
	// the first register, bits 0-3 the second). The two-register sequence is not
	// modelled by the shared push/pop lifter -- the .both flag leaves it to the
	// legacy lifter -- and the analysis records a fixed one-word SP delta (the
	// dual-form branch in c55_stack_words).
	{ .mask = 0xfe000000, .match = 0x38000000, .id = TMS320C55_INS_PSH, .len = 2, .both = true,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 0, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe000000, .match = 0x3a000000, .id = TMS320C55_INS_POP, .len = 2, .both = true,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 0, .fn = c55x_x_gr4 } } },
	// 0x54 register D-unit ALU family (two bytes): "<op>[r] [ACx,] ACy", a 3-bit
	// sub-opcode in the low byte's bits 1-3 selects the operation, bit 0 is the
	// rounding variant, ACx is bits 4-5 and the destination ACy is bits 6-7; the
	// leading byte's bit 0 is the parallel marker (left free). ACx collapses
	// against ACy when they are equal (the multiply/square then operates on ACy
	// alone -- handled in the MUL lift). The multiply / square members are lifted
	// here; addv (0), round (5) and sat (6) stay on the legacy decoder. The
	// accumulator multiplicand is the high word ACx(32-16) (see c55_mul_val).
	// mov hi(ACx), dst (opcode 0x44, high nibble 0-3): move an accumulator's
	// 16-bit high word, sign-extended, into the gr4 destination (low nibble).
	// 0x45 is the parallel form. The source ACx is byte1 bits 4-5.
	{ .mask = 0xfec00000, .match = 0x44000000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_hi_ac }, { .lo = 0, .fn = c55x_x_gr4 } } },
	// sfts dst, #1 / #-1 (opcode 0x44, high nibble 4-7): a fixed +-1 arithmetic
	// shift of the gr4 register (low nibble). byte1 bit 4 selects the sign; the
	// shared SFTS handler lifts the accumulator forms (left for +1, arithmetic
	// right for -1).
	{ .mask = 0xfec00000, .match = 0x44400000, .id = TMS320C55_INS_SFTS, .lop = C55_LOP_SFTS, .len = 2,
		.ops = { { .lo = 0, .fn = c55x_x_gr4 }, { .fn = c55x_x_sfts_imm } } },
	// aadd #k8, sp (opcode 0x4e, 0x4f parallel): add a signed 8-bit constant to
	// the stack pointer (frame setup). k8 prints unsigned but is signed; the
	// shared ADD lifter adds it zero-extended (matching the legacy IL) and the
	// analysis records the signed SP delta.
	{ .mask = 0xfe000000, .match = 0x4e000000, .id = TMS320C55_INS_AADD, .len = 2,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm }, { .fn = c55x_x_sp } } },
	// mov gr4, hi(ACx) (opcode 0x52, 0x53 parallel): write a general register's
	// low 16 bits into an accumulator's high word. Byte-1 high nibble selects
	// the source (gr4: AC/T/AR), low nibble 0-3 selects the destination hi(AC0-3).
	// The special-register destinations (low nibble >= 8) are left to the legacy.
	{ .mask = 0xfe0c0000, .match = 0x52000000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 0, .fn = c55x_x_hi_ac } } },
	// mov gr4, <special> (opcode 0x52, low nibble 8-15): write a general
	// register into sp/ssp/cdp/csr/brc1/brc0. An accumulator source is narrowed
	// to the 16-bit special register by the shared MOV lifter.
	{ .mask = 0xfe080000, .match = 0x52080000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 0, .fn = c55x_x_52dst } } },
	// swap rX, rY (opcode 0x5e, 0x5f parallel): exchange a register pair via the
	// XOR-swap idiom. Byte-1 bit 4 = 0 single, = 1 swapp (also swaps the next
	// pair); bit 5 must be 0; bits 6-7 are ignored.
	{ .mask = 0xfe300000, .match = 0x5e000000, .id = TMS320C55_INS_SWAP, .len = 2,
		.ops = { { .lo = 0, .param = 0, .fn = c55x_x_swap }, { .lo = 0, .param = 1, .fn = c55x_x_swap } } },
	{ .mask = 0xfe300000, .match = 0x5e100000, .id = TMS320C55_INS_SWAPP, .both = true, .len = 2,
		.ops = { { .lo = 0, .param = 0, .fn = c55x_x_swap }, { .lo = 0, .param = 1, .fn = c55x_x_swap } } },
	{ .mask = 0xfe300000, .match = 0x5e200000, .id = TMS320C55_INS_SWAP4, .quad = true, .len = 2,
		.ops = { { .lo = 0, .param = 0, .fn = c55x_x_swap }, { .lo = 0, .param = 1, .fn = c55x_x_swap } } },
	// rpt / rptadd / rptsub (opcode 0x48, 0x49 parallel): single-instruction
	// repeat control over the CSR counter. byte1 low nibble selects the form
	// (0 rpt, 1 rptadd CSR/TAx, 2 rptadd CSR/k4, 3 rptsub CSR/k4); ret/reti at
	// nibble 4/5 are decoded elsewhere. The operand register/immediate is byte1
	// bits 4-7.
	{ .mask = 0xfe0f0000, .match = 0x48000000, .id = TMS320C55_INS_RPT, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .fn = c55x_x_csr } } },
	{ .mask = 0xfe0f0000, .match = 0x48010000, .id = TMS320C55_INS_RPTADD, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .fn = c55x_x_csr }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe0f0000, .match = 0x48020000, .id = TMS320C55_INS_RPTADD, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .fn = c55x_x_csr }, { .lo = 4, .width = 4, .fn = c55_x_imm } } },
	{ .mask = 0xfe0f0000, .match = 0x48030000, .id = TMS320C55_INS_RPTSUB, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .fn = c55x_x_csr }, { .lo = 4, .width = 4, .fn = c55_x_imm } } },
	// rpt #k16 (opcode 0x0c, 0x0d parallel): repeat the next instruction by a
	// 16-bit immediate count (byte1 the high byte, byte2 the low byte). It has no
	// data effect of its own, so it lifts to nop like the other repeat forms.
	{ .mask = 0xfe000000, .match = 0x0c000000, .id = TMS320C55_INS_RPT, .lop = C55_LOP_NOP, .len = 3,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm } } },
	// rptcc K8, cond (opcode 0x00, 0x01 parallel): conditionally repeat the next
	// instruction K8 times. byte2 is the count, byte1 the 7-bit condition.
	{ .mask = 0xfe000000, .match = 0x00000000, .id = TMS320C55_INS_RPTCC, .lop = C55_LOP_NOP, .len = 3,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm }, { .lo = 8, .width = 7, .fn = c55x_x_cond } } },
	// rptb L16 (opcode 0x0e, 0x0f parallel): block repeat to the 16-bit end
	// address held in byte1:byte2.
	{ .mask = 0xfe000000, .match = 0x0e000000, .id = TMS320C55_INS_RPTB, .lop = C55_LOP_NOP, .len = 3,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm } } },
	// amov / asub ACx, ACy register forms (opcode 0x14, 0x15 parallel): byte-2
	// bits 0-1 select the operation (00 aadd, 01 amov, 10 asub) and bit 2 picks
	// the register (0) vs immediate (1) source. Only the register amov/asub are
	// taken here (aadd's legacy LEA type would change under the shared AADD=ADD,
	// and the immediate forms stay on legacy). src is byte1 bits 4-7, dst byte2
	// bits 4-7. asub keeps the legacy null type; its IL comes from C55_LOP_AREG.
	{ .mask = 0xfe000700, .match = 0x14000100, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AREG_MOV, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_gr4a }, { .lo = 4, .fn = c55x_x_gr4a } } },
	{ .mask = 0xfe000700, .match = 0x14000200, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_gr4a }, { .lo = 4, .fn = c55x_x_gr4a } } },
	// cmp / cmpand / cmpor SRC <relop> DST, [TCx,] TCz (opcode 0x12, 0x13
	// parallel): compare two gr4 registers and write a status TC bit. Byte-1
	// bits 0-1 select the variant (00 cmp, 01 cmpand, 10 cmpor; 11 is rol, left
	// to legacy); bits 2-3 the relop; bits 4-7 SRC. Byte-2 bit 0 = TCz, bit 1 =
	// TCx, bit 2 = unsigned (the 'u' variants), bits 4-7 = DST.
	{ .mask = 0xfe030400, .match = 0x12000000, .id = TMS320C55_INS_CMP, .lop = C55_LOP_CMP, .len = 3,
		.ops = { { .fn = c55x_x_cmpcond }, { .lo = 0, .fn = c55x_x_tcflag } } },
	{ .mask = 0xfe030400, .match = 0x12000400, .id = TMS320C55_INS_CMP, .lop = C55_LOP_CMP, .len = 3, .uns_all = true,
		.ops = { { .fn = c55x_x_cmpcond }, { .lo = 0, .fn = c55x_x_tcflag } } },
	{ .mask = 0xfe030400, .match = 0x12010000, .id = TMS320C55_INS_CMPAND, .lop = C55_LOP_CMPAND, .len = 3,
		.ops = { { .fn = c55x_x_cmpcond }, { .lo = 1, .param = 3, .fn = c55x_x_tcflag }, { .lo = 0, .fn = c55x_x_tcflag } } },
	{ .mask = 0xfe030400, .match = 0x12010400, .id = TMS320C55_INS_CMPAND, .lop = C55_LOP_CMPAND, .len = 3, .uns_all = true,
		.ops = { { .fn = c55x_x_cmpcond }, { .lo = 1, .param = 3, .fn = c55x_x_tcflag }, { .lo = 0, .fn = c55x_x_tcflag } } },
	{ .mask = 0xfe030400, .match = 0x12020000, .id = TMS320C55_INS_CMPOR, .lop = C55_LOP_CMPOR, .len = 3,
		.ops = { { .fn = c55x_x_cmpcond }, { .lo = 1, .param = 3, .fn = c55x_x_tcflag }, { .lo = 0, .fn = c55x_x_tcflag } } },
	{ .mask = 0xfe030400, .match = 0x12020400, .id = TMS320C55_INS_CMPOR, .lop = C55_LOP_CMPOR, .len = 3, .uns_all = true,
		.ops = { { .fn = c55x_x_cmpcond }, { .lo = 1, .param = 3, .fn = c55x_x_tcflag }, { .lo = 0, .fn = c55x_x_tcflag } } },
	// rol / ror BitIn, ACx, BitOut, ACy (opcode 0x12, byte1 bits 0-1 = 11):
	// rotate the accumulator left/right by one through a status bit. byte2 bit 3
	// selects ror (1) over rol (0); SRC is byte1 bits 4-7, DST byte2 bits 4-7.
	// For rol, byte2 bit 0 is the rotate-in bit and bit 1 the rotate-out bit;
	// the legacy swaps these for ror (bit 1 = rotate-in, bit 0 = rotate-out).
	// Each bit picks carry (0) or tc2 (1). The legacy models the data effect only
	// for accumulator src+dst, so T/AR forms fall through to a null lift.
	{ .mask = 0xfe030800, .match = 0x12030000, .id = TMS320C55_INS_ROL, .lop = C55_LOP_ROL, .len = 3,
		.ops = { { .lo = 0, .fn = c55x_x_rolflag }, { .lo = 12, .width = 4, .fn = c55x_x_gr4 }, { .lo = 1, .fn = c55x_x_rolflag }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe030800, .match = 0x12030800, .id = TMS320C55_INS_ROR, .lop = C55_LOP_ROR, .len = 3,
		.ops = { { .lo = 1, .fn = c55x_x_rolflag }, { .lo = 12, .width = 4, .fn = c55x_x_gr4 }, { .lo = 0, .fn = c55x_x_rolflag }, { .lo = 4, .width = 4, .fn = c55x_x_gr4 } } },
	// bfxtr / bfxpa K16, ACx, ACy (opcode 0x76): bit-field extract / expand.
	// bfxtr extracts the bits of ACx selected by the K16 mask and right-packs
	// them into ACy; bfxpa is the inverse (expand-and-pack). 0x76 is multi-form
	// -- byte3 bits 2-3 select the operation (0 bfxtr, 1 bfxpa; 2 is a mov form
	// and 3 is invalid, both left to the legacy decoder). K16 is bytes 1-2, the
	// AC source is byte3 bits 0-1, and the gr4 destination is byte3 bits 4-7.
	// bfxtr is typed MOV (a field move); bfxpa is untyped, as the legacy did.
	// Neither is lifted (OPAQUE).
	{ .mask = 0xff00000c, .match = 0x76000000, .id = TMS320C55_INS_BFXTR, .lop = C55_LOP_OPAQUE, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff00000c, .match = 0x76000004, .id = TMS320C55_INS_BFXPA, .lop = C55_LOP_OPAQUE, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 0, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// amov #k16, dst (opcode 0x77, no parallel): load a zero-extended 16-bit
	// constant/address. k16 is bits 8-23 (byte1:byte2); the gr4 destination
	// selector is byte3 bits 4-7 (0-3 AC, 4-7 T, 8-15 AR).
	{ .mask = 0xff000000, .match = 0x77000000, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AMOV, .len = 4, .no_parallel = true,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// mpyk / mpykr #k, ACx[, ACy] (opcodes 0x1e 3-byte K8, 0x79 4-byte K16;
	// 0x1e has a parallel companion 0x1f rendered "|| mpyk"): ACy = #k * ACx,
	// the signed constant multiplying the low 16 bits of ACx. The variant byte
	// (byte2 for 0x1e, byte3 for 0x79) holds ACx in bits 6-7, ACy in bits 4-5,
	// bit 1 = 0 selecting the mpyk family (1 = mack), and bit 0 = the round (r)
	// suffix (read via mods). ACy defaults to ACx (elided when equal). The
	// 4-byte 0x79 has no parallel form (0x78 is a different opcode), so it pins
	// byte0 fully.
	{ .mask = 0xfe000200, .match = 0x1e000000, .id = TMS320C55_INS_MPYK, .lop = C55_LOP_MPYK, .len = 3, .mods = 1,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff000002, .match = 0x79000000, .id = TMS320C55_INS_MPYK, .lop = C55_LOP_MPYK, .len = 4, .no_parallel = true, .mods = 1,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	// mack / mackr Tx, #k, ACx[, ACy] (variant byte bit 1 = 1): ACy = ACx + #k *
	// Tx. Same encoding as mpyk but the Tx coefficient (variant-byte bits 2-3)
	// replaces the accumulator low word as the multiplicand; bit 0 = the round
	// (r) suffix. ACy defaults to ACx (elided when equal).
	{ .mask = 0xfe000200, .match = 0x1e000200, .id = TMS320C55_INS_MACK, .lop = C55_LOP_MACK, .len = 3, .mods = 1,
		.ops = { { .lo = 2, .fn = c55x_x_t2 }, { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	{ .mask = 0xff000002, .match = 0x79000002, .id = TMS320C55_INS_MACK, .lop = C55_LOP_MACK, .len = 4, .no_parallel = true, .mods = 1,
		.ops = { { .lo = 2, .fn = c55x_x_t2 }, { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 6, .fn = c55x_x_ac2 }, { .lo = 4, .fn = c55x_x_ac2_elide } } },
	// bclr / bset #k4, STx (opcode 0x46, 0x47 parallel): clear or set bit #k4 of
	// a status register. Byte-1 bit 0 = 0 bclr, = 1 bset; bits 1-3 = STn_55;
	// bits 4-7 = the 4-bit bit index #k4.
	{ .mask = 0xfe010000, .match = 0x46000000, .id = TMS320C55_INS_BCLR, .lop = C55_LOP_BITCLR, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 1, .fn = c55x_x_st } } },
	{ .mask = 0xfe010000, .match = 0x46010000, .id = TMS320C55_INS_BSET, .lop = C55_LOP_BITSET, .len = 2,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 1, .fn = c55x_x_st } } },
	// add/sub ACx << Tx, ACy (opcode 0x5a, 0x5b parallel): ACy +/- (ACx shifted
	// left by the Tx register). Byte-1 bit 0 selects add (0) vs sub (1); bit 1
	// must be 0 (bit 1 = 1 selects the sftcc forms, left to the legacy decoder).
	// bits 2-3 = Tx, 4-5 = source ACx, 6-7 = destination ACy.
	{ .mask = 0xfe030000, .match = 0x5a000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .len = 2,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .fn = c55x_x_tx_shl },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xfe030000, .match = 0x5a010000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .len = 2,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .fn = c55x_x_tx_shl },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// sftcc ACx, TCx (opcode 0x5a, byte1 bit1 = 1): test the sign of an
	// accumulator and copy it into a test-control bit (TI shift-conditional
	// support op). ACx is byte1 bits 6-7; TCx is byte1 bit 0 (0 -> tc1, 1 ->
	// tc2), rendered lowercase via the condition-flag path. The add / sub-shift
	// forms occupy byte1 bit1 = 0, so this match is disjoint from them. Null
	// type and IL (OPAQUE), matching the legacy decoder.
	{ .mask = 0xfe020000, .match = 0x5a020000, .id = TMS320C55_INS_SFTCC, .lop = C55_LOP_OPAQUE, .len = 2,
		.ops = { { .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 0, .fn = c55x_x_tcflag } } },
	// mov <special>, dst (opcode 0x44, high nibble 8-15): move a 16-bit special
	// register (sp / ssp / cdp / brc0 / brc1 / rptc), sign-extended, into the
	// gr4 destination. The source extractor leaves the unassigned high nibbles
	// (11, 15) to the legacy decoder.
	{ .mask = 0xfe800000, .match = 0x44800000, .id = TMS320C55_INS_MOV, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_44src }, { .lo = 0, .fn = c55x_x_gr4 } } },
	// sftl dst, #1 / #-1 (opcode 0x50, sub-opcodes 0/1): a fixed +-1 logical
	// shift of the gr4 register. Sub-opcode bit 0 (matched loosely below)
	// selects the count's sign; the shared SFTL handler lifts the accumulator
	// forms (a positive count shifts left, a negative one right).
	{ .mask = 0xfe060000, .match = 0x50000000, .id = TMS320C55_INS_SFTL, .lop = C55_LOP_SFTL, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .fn = c55x_x_sftl_imm } } },
	// pop / psh ACx (opcode 0x50, sub-opcodes 2/3/6/7): single-accumulator
	// stack ops. The plain forms (2/6) take the gr4 register field (byte1
	// bits 4-7); the dbl(ACx) forms (3/7) are accumulator-only. The operand
	// moves as 32 bits / two stack words for an accumulator and one word for a
	// 16-bit register through the shared push/pop lifter. 0x51 is the parallel
	// form, so the opcode byte is matched modulo its low (parallel) bit.
	{ .mask = 0xfe070000, .match = 0x50020000, .id = TMS320C55_INS_POP, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe070000, .match = 0x50030000, .id = TMS320C55_INS_POP, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_ac_dbl } } },
	{ .mask = 0xfe070000, .match = 0x50060000, .id = TMS320C55_INS_PSH, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xfe070000, .match = 0x50070000, .id = TMS320C55_INS_PSH, .len = 2,
		.ops = { { .lo = 4, .fn = c55x_x_ac_dbl } } },
	// popboth / pshboth xdst (opcode 0x50, sub-opcodes 4/5): pop / push a
	// register *pair* named by the extended-register field (byte1 bits 4-7).
	// The pair semantics are not lifted (the .both flag), but the stack effect
	// (two words) and pop/push type are modelled.
	{ .mask = 0xfe0f0000, .match = 0x50040000, .id = TMS320C55_INS_POPBOTH, .len = 2, .both = true,
		.ops = { { .lo = 4, .fn = c55x_x_xgr4 } } },
	{ .mask = 0xfe0f0000, .match = 0x50050000, .id = TMS320C55_INS_PSHBOTH, .len = 2, .both = true,
		.ops = { { .lo = 4, .fn = c55x_x_xgr4 } } },
	// sub-opcode 3: mpy[r] -- ACy = ACx * ACy.
	{ .mask = 0xfe0e0000, .match = 0x54060000, .id = TMS320C55_INS_MPY, .len = 2, .mods = 1,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// sub-opcode 4: sqr[r] -- ACy = ACx * ACx.
	{ .mask = 0xfe0e0000, .match = 0x54080000, .id = TMS320C55_INS_SQR, .len = 2, .mods = 1, .square = true,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// sub-opcode 1: sqa[r] -- ACy = ACy + ACx * ACx.
	{ .mask = 0xfe0e0000, .match = 0x54020000, .id = TMS320C55_INS_SQA, .lop = C55_LOP_MAC, .len = 2, .mods = 1, .square = true,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// sub-opcode 2: sqs[r] -- ACy = ACy - ACx * ACx.
	{ .mask = 0xfe0e0000, .match = 0x54040000, .id = TMS320C55_INS_SQS, .lop = C55_LOP_MAS, .len = 2, .mods = 1, .square = true,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// sub-opcode 0: addv / addrv ACx, ACy -- ACy = ACy + |ACx(32-16)| (addition
	// with absolute value). The rounded variant is spelled "addrv" (the r is
	// infixed, not a trailing suffix), so it is a distinct id selected by bit 0
	// rather than the generic rounding-suffix mods; bit 0 is therefore pinned.
	{ .mask = 0xfe0f0000, .match = 0x54000000, .id = TMS320C55_INS_ADDV, .lop = C55_LOP_ADDV, .len = 2,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	{ .mask = 0xfe0f0000, .match = 0x54010000, .id = TMS320C55_INS_ADDRV, .lop = C55_LOP_ADDV, .len = 2,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// sub-opcode 5: round ACx, ACy -- ACy = round(ACx). The low byte's bit 0 is
	// don't-care here (the operation always rounds, so both encodings print
	// "round"); no rounding-suffix mods, leaving the type untyped as the legacy.
	{ .mask = 0xfe0e0000, .match = 0x540a0000, .id = TMS320C55_INS_ROUND, .lop = C55_LOP_ROUND, .len = 2,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// sub-opcode 6: sat[r] ACx, ACy -- ACy = saturate(ACx). bit 0 selects the
	// rounding variant (satr) via mods.
	{ .mask = 0xfe0e0000, .match = 0x540c0000, .id = TMS320C55_INS_SAT, .lop = C55_LOP_SAT, .len = 2, .mods = 1,
		.ops = { { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// mac[r] ACx, Tx, ACy[, ACy] and mas[r] Tx, [ACx,] ACy (opcode 0x56, two
	// bytes): the register MAC / MAS that take a T-register coefficient, ACy =
	// ACy [+/-] sx17(ACx(32-16)) * sx40(Tx). The low byte holds round (bit 0),
	// the mac/mas selector (bit 1: 0 mac, 1 mas), Tx (bits 2-3), the ACx
	// multiplicand (bits 4-5) and the destination ACy (bits 6-7); the leading
	// byte's bit 0 is the parallel marker (left free). mac prints the trailing
	// ACy only when ACx differs from it; mas drops the ACx when it equals ACy.
	{ .mask = 0xfe020000, .match = 0x56000000, .id = TMS320C55_INS_MAC, .lop = C55_LOP_MAC, .len = 2, .mods = 1,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .width = 2, .param = C55_RC_T, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_macreg_acy_dst } } },
	{ .mask = 0xfe020000, .match = 0x56020000, .id = TMS320C55_INS_MAS, .lop = C55_LOP_MAS, .len = 2, .mods = 1,
		.ops = { { .lo = 2, .width = 2, .param = C55_RC_T, .fn = c55_x_reg },
			{ .fn = c55x_x_mpy_acsrc },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// mpy[r] Tx, [ACy,] ACx (opcode 0x58, two bytes): a register multiply,
	// ACx = sx40(Tx) * sx17(ACy(32-16)) -- the accumulator multiplicand is its
	// high word, not its low half (see c55_mul_val). An optional rounding variant.
	// The leading byte's bit 0 is the parallel marker (so 0x58 / 0x59 both match,
	// with that bit left free); the low byte's bit 0 is the round flag (folded in
	// via mods so 0x58.. and its mpyr sibling share this row) and bit 1 selects the
	// accumulate form mac[r] (the next row).
	{ .mask = 0xfe020000, .match = 0x58000000, .id = TMS320C55_INS_MPY, .len = 2, .mods = 1,
		.ops = { { .fn = c55x_x_mpy_t }, { .fn = c55x_x_mpy_acsrc }, { .fn = c55x_x_mpy_acdst } } },
	// mac[r] ACy, Tx, ACx, ACy (opcode 0x58, low byte's bit 1 = 1): the register
	// MAC, ACy = ACx + sx17(ACy(32-16)) * sx40(Tx), rounded for macr. ACy (bits 6-7)
	// is both the multiplicand high word and the destination; ACx (bits 4-5) is the
	// accumulator addend; Tx is bits 2-3. Unlike the multiply this form always
	// prints all four operands. The legacy lifted the multiplicand as ACy.l; this
	// matches the multiply in using the high word.
	{ .mask = 0xfe020000, .match = 0x58020000, .id = TMS320C55_INS_MAC, .lop = C55_LOP_MAC, .len = 2, .mods = 1,
		.ops = { { .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .width = 2, .param = C55_RC_T, .fn = c55_x_reg },
			{ .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// sftl / sfts / sftsc ACx, Tx[, ACy] (opcode 0x5c, two bytes): a register
	// shift of ACx by the signed count in Tx, written to ACy. The low byte holds
	// the sub-opcode (bits 0-1: 0 sftl, 1 sfts, 2 sftsc; 3 is invalid), Tx (bits
	// 2-3), the source ACx (bits 4-5) and the destination ACy (bits 6-7); the
	// leading byte's bit 0 is the parallel marker (left free). ACy collapses
	// against ACx when they are equal. sftl shifts logically and sfts shifts
	// arithmetically (lifted here); sftsc additionally affects the carry and is
	// left unlifted, matching the legacy.
	{ .mask = 0xfe030000, .match = 0x5c000000, .id = TMS320C55_INS_SFTL, .lop = C55_LOP_SFTL, .len = 2,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .width = 2, .param = C55_RC_T, .fn = c55_x_reg },
			{ .fn = c55x_x_macreg_acy_dst } } },
	{ .mask = 0xfe030000, .match = 0x5c010000, .id = TMS320C55_INS_SFTS, .lop = C55_LOP_SFTS, .len = 2,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .width = 2, .param = C55_RC_T, .fn = c55_x_reg },
			{ .fn = c55x_x_macreg_acy_dst } } },
	{ .mask = 0xfe030000, .match = 0x5c020000, .id = TMS320C55_INS_SFTSC, .len = 2,
		.ops = { { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 2, .width = 2, .param = C55_RC_T, .fn = c55_x_reg },
			{ .fn = c55x_x_macreg_acy_dst } } },
	// sfts / sftsc / sftl ACx, #SHIFTW[, ACy] (opcode 0x10, three bytes): the
	// immediate-count companions of the 0x5c register shifts. The leading byte
	// is the opcode (bit 0 the parallel marker); the middle byte holds the
	// sub-opcode (bits 0-3: 5 sfts, 6 sftsc, 7 sftl -- the lower sub-opcodes are
	// the and/or/xor/add/sub shift-and-combine forms, still on the legacy
	// decoder), the source ACx (bits 4-5) and the destination ACy (bits 6-7);
	// the last byte's bits 0-5 are the signed shift count SHIFTW. ACy collapses
	// against ACx when equal. sftl/sfts are lifted (sign-extending SHIFTW to pick
	// the direction); sftsc is left unlifted like the legacy.
	// and / or / xor / add / sub ACx << #SHIFTW[, ACy] (opcode 0x10, sub-opcodes
	// 0-4): shift-and-combine forms sharing the 0x10 encoding with the shifts
	// below. ACx is byte1 bits 4-5, the destination ACy bits 6-7, SHIFTW the last
	// byte's bits 0-5. The bitwise forms (and/or/xor) print the trailing ACy only
	// when it differs from ACx and collapse otherwise; add/sub always print it.
	// exp ACx, Tx (opcode 0x10, byte1 nibble 0x8): compute the exponent (the
	// leading-sign-bit count) of ACx into Tx. ACx is byte1 bits 4-5, Tx byte2
	// bits 4-5. The shift computation is not modelled, so it decodes and analyses
	// on the shared path (REP-free, default null type) but carries no IL.
	{ .mask = 0xfe0f0000, .match = 0x10080000, .id = TMS320C55_INS_EXP, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 4, .width = 2, .param = C55_RC_T, .fn = c55_x_reg } } },
	// bcnt ACx, ACy, TCx, Tx (opcode 0x10, byte1 nibble 0xa): count bits; null
	// analysis type and no modelled effect, so OPAQUE. ACx byte1 bits4-5, ACy
	// byte2 bits6-7, TCx byte2 bit0, Tx byte2 bits4-5.
	{ .mask = 0xfe0f0000, .match = 0x100a0000, .id = TMS320C55_INS_BCNT, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 0, .fn = c55x_x_tcflag },
			{ .lo = 4, .width = 2, .param = C55_RC_T, .fn = c55_x_reg } } },
	// maxdiff / mindiff ACx, ACy, ACz, ACw (opcode 0x10, nibbles 0xc / 0xe): the
	// four accumulators are interleaved across byte1/byte2 (ACx byte1 bits4-5,
	// ACy byte2 bits6-7, ACz byte1 bits6-7, ACw byte2 bits4-5). OPAQUE.
	{ .mask = 0xfe0f0000, .match = 0x100c0000, .id = TMS320C55_INS_MAXDIFF, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 14, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xfe0f0000, .match = 0x100e0000, .id = TMS320C55_INS_MINDIFF, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 14, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// dmaxdiff / dmindiff ACx, ACy, ACz, ACw, TRNx (opcode 0x10, nibbles 0xd /
	// 0xf): as max/mindiff plus the trn0/trn1 transition register at byte2 bit0.
	{ .mask = 0xfe0f0000, .match = 0x100d0000, .id = TMS320C55_INS_DMAXDIFF, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 14, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 0, .fn = c55x_x_trn } } },
	{ .mask = 0xfe0f0000, .match = 0x100f0000, .id = TMS320C55_INS_DMINDIFF, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 14, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .lo = 0, .fn = c55x_x_trn } } },
	{ .mask = 0xfe0f0000, .match = 0x10000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDSHL, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw_shl },
			{ .fn = c55x_x_shiftk_acy } } },
	{ .mask = 0xfe0f0000, .match = 0x10010000, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORSHL, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw_shl },
			{ .fn = c55x_x_shiftk_acy } } },
	{ .mask = 0xfe0f0000, .match = 0x10020000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORSHL, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw_shl },
			{ .fn = c55x_x_shiftk_acy } } },
	{ .mask = 0xfe0f0000, .match = 0x10030000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw_shl },
			{ .lo = 14, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xfe0f0000, .match = 0x10040000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw_shl },
			{ .lo = 14, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xfe0f0000, .match = 0x10050000, .id = TMS320C55_INS_SFTS, .lop = C55_LOP_SFTS, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw },
			{ .fn = c55x_x_shiftk_acy } } },
	{ .mask = 0xfe0f0000, .match = 0x10060000, .id = TMS320C55_INS_SFTSC, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw },
			{ .fn = c55x_x_shiftk_acy } } },
	{ .mask = 0xfe0f0000, .match = 0x10070000, .id = TMS320C55_INS_SFTL, .lop = C55_LOP_SFTL, .len = 3,
		.ops = { { .lo = 12, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg },
			{ .fn = c55x_x_shiftw },
			{ .fn = c55x_x_shiftk_acy } } },
	// mpy[r] / mac[r] / mas[r] Smem, uns(Cmem), ACx (opcode 0xd0, three bytes):
	// the unsigned-coefficient memory multiplies, ACx [+/-]= sx40(Smem) *
	// zx40(Cmem). The last byte's bits 2-3 select the operation (01 mpy, 10 mac,
	// 11 mas); the coefficient is the (zero-extended) Cmem (bits 0-1 the CDP
	// post-modify), the destination ACx is bits 4-5, round is bit 6. The signed
	// macmz form (operation 00) has no dedicated id and stays on the legacy
	// decoder, as do the *(cdp+t0) coefficient mode and the side-load (bit 15)
	// forms.
	{ .mask = 0xff008c00, .match = 0xd0000400, .id = TMS320C55_INS_MPY, .len = 3, .no_parallel = true, .mods = 7,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_cmem, .param = 1 }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff008c00, .match = 0xd0000800, .id = TMS320C55_INS_MAC, .lop = C55_LOP_MAC, .len = 3, .no_parallel = true, .mods = 7,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_cmem, .param = 1 }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff008c00, .match = 0xd0000c00, .id = TMS320C55_INS_MAS, .lop = C55_LOP_MAS, .len = 3, .no_parallel = true, .mods = 7,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_cmem, .param = 1 }, { .fn = c55x_x_mac_acdst } } },
	// mpym[r] Smem, Cmem, ACx (opcode 0xd1, three bytes): a memory multiply,
	// ACx = sx40(Smem) * sx40(Cmem). Byte1 is the Smem field; the last byte
	// holds the Cmem coefficient mode (bits 0-1), the operation (bits 2-3:
	// 00 mpym), the destination ACx (bits 4-5), round (bit 6, folded in via
	// mods) and uns (bit 7). In the top-aligned match word the last byte sits
	// at bits 8-15, so op is pinned at bits 10-11 and uns at bit 15: this row
	// matches op = 00 (mpym, no accumulate) with uns = 0, leaving macm / masm
	// (op 01 / 10), the uns forms and the *(cdp+t0) coefficient mode (abandoned
	// by the Cmem extractor) to the legacy decoder.
	{ .mask = 0xff000c00, .match = 0xd1000000, .id = TMS320C55_INS_MPYM, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_cmem }, { .fn = c55x_x_mac_acdst } } },
	// macm[r] Smem, Cmem, ACx (op = 01, match bits 10-11 = 01): ACx += Smem*Cmem,
	// and masm[r] (op = 10): ACx -= Smem*Cmem. Same operands and uns / coefficient
	// constraints as mpym; the accumulate is carried via the MAC / MAS lift ops.
	{ .mask = 0xff000c00, .match = 0xd1000400, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_cmem }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff000c00, .match = 0xd1000800, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_cmem }, { .fn = c55x_x_mac_acdst } } },
	// macm[r] / masm[r] Smem, [ACx,] ACy (opcode 0xd2, three bytes): a memory
	// MAC whose coefficient is the source accumulator high word,
	// ACy += sx40(Smem) * sx17(ACx(32-16)) (op = 00) or ACy -= ... (op = 01); the
	// squaring sqam[r] / sqsm[r] forms (op = 10 / 11, below) instead multiply
	// Smem by itself, ACy = ACx +/- sx40(Smem) * sx40(Smem). The last byte holds
	// the source ACx (bits 0-1), the operation (bits 2-3), the destination ACy
	// (bits 4-5), round (bit 6) and the side-load flag (bit 7). For the MACs only
	// the distinct-register three-operand form is lifted: the two-operand
	// (ACx == ACy) form has no legacy IL and stays on the legacy decoder.
	{ .mask = 0xff000c00, .match = 0xd2000000, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_mac_accoef }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff000c00, .match = 0xd2000400, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_mac_accoef }, { .fn = c55x_x_mac_acdst } } },
	// the squares: the coefficient extractor collapses to NONE so the
	// two-operand (ACx == ACy) form is lifted as well -- the legacy decoder has
	// no IL for either, so the structured square is a strict improvement.
	{ .mask = 0xff000c00, .match = 0xd2000800, .id = TMS320C55_INS_SQAM, .lop = C55_LOP_MAC, .len = 3, .no_parallel = true, .mods = 0x207, .square = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_mac_accsrc }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff000c00, .match = 0xd2000c00, .id = TMS320C55_INS_SQSM, .lop = C55_LOP_MAS, .len = 3, .no_parallel = true, .mods = 0x207, .square = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_mac_accsrc }, { .fn = c55x_x_mac_acdst } } },
	// mpym[r] Smem, [ACx,] ACy and mpym[r] Smem, Tx, ACx (opcode 0xd3, three
	// bytes): the no-accumulate counterparts of the d2 / d4 MACs. The last
	// byte's bits 2-3 select the form: 00 multiplies by the source accumulator's
	// high word (ACx(32-16), the ACx operand collapsing against ACy as for the d2
	// MACs but with the two-operand form lifted here), 01 multiplies by a T
	// register (bits 0-1) and 10 is the squaring sqrm[r] (ACx = Smem * Smem,
	// below). mpymu (bits 2-3 = 11) is the unsigned multiply: both operands carry
	// uns and the mnemonic gains the 'u' suffix. The legacy mis-lifted it as a
	// signed multiply; the shared path multiplies unsigned (the disassembly is
	// unchanged, so only the IL -- now correct -- differs).
	{ .mask = 0xff000c00, .match = 0xd3000000, .id = TMS320C55_INS_MPYM, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_mac_accsrc }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff000c00, .match = 0xd3000400, .id = TMS320C55_INS_MPYM, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_mac_tcoef }, { .fn = c55x_x_mac_acdst } } },
	// sqrm[r] Smem, ACx (op = 10): squaring multiply with no accumulation, the
	// single accumulator (bits 4-5) being the destination; the source-AC bits
	// are unused. No legacy IL, so the structured lift is a strict improvement.
	{ .mask = 0xff000c00, .match = 0xd3000800, .id = TMS320C55_INS_SQRM, .len = 3, .no_parallel = true, .mods = 0x207, .square = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff000c00, .match = 0xd3000c00, .id = TMS320C55_INS_MPYM, .len = 3, .no_parallel = true, .mods = 0x207, .uns_all = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_u }, { .lo = 0, .fn = c55x_x_tcoef_u }, { .fn = c55x_x_mac_acdst } } },
	// macm[r] / masm[r] Smem, Tx, [ACx,] ACy (opcodes 0xd4 / 0xd5, three bytes):
	// a memory MAC whose coefficient is a T register, ACy = acc +/- sx40(Smem) *
	// sx40(Tx). The last byte holds the accumulator source ACx (bits 0-1), the
	// coefficient Tx (bits 2-3), the destination ACy (bits 4-5), round (bit 6)
	// and the side-load flag (bit 7). There is no operation field -- the opcode
	// selects add vs subtract -- so the rows pin only the opcode and uns = 0
	// (bit 15). The four-operand form (ACx != ACy) accumulates into ACx; the
	// three-operand form accumulates into ACy. The uns / side-load forms remain
	// on the legacy decoder.
	{ .mask = 0xff000000, .match = 0xd4000000, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 2, .fn = c55x_x_mac_tcoef }, { .fn = c55x_x_mac_accsrc }, { .fn = c55x_x_mac_acdst } } },
	{ .mask = 0xff000000, .match = 0xd5000000, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 3, .no_parallel = true, .mods = 0x207,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 2, .fn = c55x_x_mac_tcoef }, { .fn = c55x_x_mac_accsrc }, { .fn = c55x_x_mac_acdst } } },
	// add / sub Smem, [src,] dst (opcodes 0xd6/0xd7, three bytes): a memory
	// operand added to (or subtracted from) a register, dst = src +/- Smem. The
	// Smem byte is the middle byte; the last byte holds the destination gr4
	// register (bits 4-7) and the source gr4 register (bits 0-3), the latter
	// printed only when it differs from the destination. The opcode's low bit
	// selects add vs sub, so the leading byte is matched whole (no parallel
	// form). Like the legacy these are typed but left unlifted (the generic
	// add/sub lifter declines the memory source), and const-indexed / absolute
	// Smem modes fall through to the legacy decoder via c55x_x_smem.
	{ .mask = 0xff000000, .match = 0xd6000000, .id = TMS320C55_INS_ADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_gr4_src }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000000, .match = 0xd7000000, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_gr4_src }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// sub src, Smem, dst (opcode 0xd8, three bytes): the reverse-subtract form,
	// dst = src - Smem, with the source register printed first. Same FDDD/FSSS
	// last byte and Smem middle byte as 0xd6/0xd7, but both registers are always
	// shown (no collapse). The legacy types it as a subtraction and leaves it
	// unlifted (the generic subtract lifter declines the memory minuend).
	{ .mask = 0xff000000, .match = 0xd8000000, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 0, .fn = c55x_x_gr4 }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// and / or / xor Smem, [src,] dst (opcodes 0xd9/0xda/0xdb, three bytes): the
	// bitwise counterparts of 0xd6/0xd7 with the identical operand layout. The
	// 16-bit memory operand is sign-extended to the accumulator width; the legacy
	// lifts these when both source and destination are accumulators.
	{ .mask = 0xff000000, .match = 0xd9000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDMEM, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_gr4 }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000000, .match = 0xda000000, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORMEM, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_gr4 }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000000, .match = 0xdb000000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORMEM, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_gr4 }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// add / sub Smem << Tx, [ACx,] ACy (opcode 0xdd, three bytes): a memory
	// operand shifted left by the count in a T register before being added to
	// (or subtracted from) an accumulator. The Smem byte is the middle byte; the
	// last byte holds ACx (bits 6-7), ACy (bits 4-5), the shift register Tx (bits
	// 2-3), and the add/sub selector (bits 0-1: 0 add, 1 sub). ACx collapses
	// against ACy. The legacy types these and leaves them unlifted (the shifted
	// memory source is declined by the generic add/sub lifter); const-indexed
	// Smem modes fall through to the legacy decoder.
	{ .mask = 0xff000300, .match = 0xdd000000, .id = TMS320C55_INS_ADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_shtx }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000300, .match = 0xdd000100, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_shtx }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// addsub2cc Smem, ACx, Tx, TC1, TC2, ACy (opcode 0xdd, variant byte2 bits
	// 0-1 = 10): conditionally add or subtract the memory word to ACx based on
	// TC1/TC2, writing ACy. The legacy types this null and leaves it unlifted;
	// OPAQUE keeps the shared disasm while declining the IL. byte2 bits 6-7 =
	// ACx, bits 4-5 = ACy, bits 2-3 = Tx; TC1/TC2 are fixed literals.
	{ .mask = 0xff000300, .match = 0xdd000200, .id = TMS320C55_INS_ADDSUB2CC, .lop = C55_LOP_OPAQUE, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 2, .fn = c55x_x_t2 }, { .fn = c55x_x_tc1 }, { .fn = c55x_x_tc2 }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// mov [rnd(]Smem << Tx[)], ACy (opcode 0xdd, variant byte2 bits 0-1 = 11):
	// load the (Tx-shifted, optionally rounded) memory word into ACy. byte2
	// bits 4-5 = ACy, bits 2-3 = Tx, bit 6 = the rnd() wrapper. The legacy
	// leaves this unlifted (the shifted memory source is declined by the mov
	// lifter), so the IL is null.
	{ .mask = 0xff000300, .match = 0xdd000300, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_shtx_rnd }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// btst K4, Smem, TCx (opcode 0xdc, the bit-test sub-form): test bit K4 of
	// Smem and record it in the test-control flag TC1 or TC2. 0xdc is a large
	// multi-form opcode -- byte2 bit 1 selects btst (0) versus the family of
	// mov-Smem-to-special-register forms (1), and byte2 bit 0 chooses TC1 (0)
	// or TC2 (1); the bit number K4 is byte2 bits 4-7. Typed AND like the other
	// bit operations, with no IL. The mov-to-special-register variants of 0xdc
	// remain on the legacy decoder.
	{ .mask = 0xff000200, .match = 0xdc000000, .id = TMS320C55_INS_BTST, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg } } },
	// mov Smem, <special-reg> (opcode 0xdc, the non-btst sub-forms): load a
	// data-memory word into a special register. byte2 bits 0-1 select the group
	// (2: dp/cdp/bsa*/sp/ssp/bk*/dph/pdp; 3: csr/brc*/trn*) and bits 4-7 (4-bit
	// in group 2, 3-bit in group 3) select the register. The shared mov lifter
	// loads via c55_mem_move into the register's 16-bit view (dph/pdp truncate),
	// matching the legacy IL. Undefined register selectors fall through to the
	// legacy decoder.
	{ .mask = 0xff000300, .match = 0xdc000200, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .param = 2, .fn = c55x_x_dc_movdst } } },
	{ .mask = 0xff000300, .match = 0xdc000300, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .param = 3, .fn = c55x_x_dc_movdst } } },
	// btstset / btstclr / btstnot K4, Smem, TCx (opcode 0xe3): test bit K4 of
	// Smem into TC1/TC2 and then set / clear / toggle that bit in memory. 0xe3
	// is multi-form -- byte2 bits 2-3 select the operation (0 set, 1 clr, 2 not;
	// 3 is the bset/bclr/bnot register-source family that stays on the legacy
	// decoder), byte2 bit 1 selects TC1 (0) or TC2 (1), byte2 bit 0 is a
	// don't-care, and the bit number K4 is byte2 bits 4-7. All three are typed
	// AND like btst (the legacy decoder typed btstset that way but left btstclr
	// and btstnot untyped); none is lifted.
	{ .mask = 0xff000c00, .match = 0xe3000000, .id = TMS320C55_INS_BTSTSET, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 1, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg } } },
	{ .mask = 0xff000c00, .match = 0xe3000400, .id = TMS320C55_INS_BTSTCLR, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 1, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg } } },
	{ .mask = 0xff000c00, .match = 0xe3000800, .id = TMS320C55_INS_BTSTNOT, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .width = 4, .fn = c55_x_imm }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 1, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg } } },
	// bset / bclr / bnot src, Smem (opcode 0xe3, the register-source forms that
	// complete the family above): set / clear / toggle the bit of Smem selected
	// by the register src. byte2 low nibble 0xc is bset, 0xd is bclr, 0xe/0xf is
	// bnot (its bit 0 is a don't-care); src is the gr4 register in byte2 bits
	// 4-7. The legacy decoder typed bset/bclr as MOV and left bnot untyped; bnot
	// is a memory bit-toggle, so it is typed XOR here. None is lifted.
	{ .mask = 0xff000f00, .match = 0xe3000c00, .id = TMS320C55_INS_BSET, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 8, .width = 8, .fn = c55x_x_smem } } },
	{ .mask = 0xff000f00, .match = 0xe3000d00, .id = TMS320C55_INS_BCLR, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 8, .width = 8, .fn = c55x_x_smem } } },
	{ .mask = 0xff000e00, .match = 0xe3000e00, .id = TMS320C55_INS_BNOT, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 8, .width = 8, .fn = c55x_x_smem } } },
	// btst src, Smem, TCx (opcode 0xe0): test the bit of Smem selected by the
	// register src (the bit *number* lives in the register, not an immediate as
	// in the 0xdc K4 form) and copy it into TC1/TC2. src is the gr4 register in
	// byte2 bits 4-7, the Smem field is byte1, and byte2 bit 0 chooses TC1 (0)
	// or TC2 (1) -- rendered lowercase via the condition-flag path, matching
	// this form's legacy rendering (distinct from the uppercase 0xdc/0xe3
	// forms). byte2 bits 1-3 are don't-cares. Typed AND like the other bit
	// tests; not lifted.
	{ .mask = 0xff000000, .match = 0xe0000000, .id = TMS320C55_INS_BTST, .len = 3, .no_parallel = true,
		.ops = { { .lo = 4, .fn = c55x_x_gr4 }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .fn = c55x_x_tcflag } } },
	// band Smem, K16, TCx (opcodes 0xf2 / 0xf3): bitwise-AND the 16-bit mask
	// K16 with Smem and copy the zero result into a test-control bit. The K16
	// is always present (bytes 2-3, a 4-byte instruction), the Smem field is
	// byte1, and the opcode LSB selects the destination flag -- 0xf2 -> TC1,
	// 0xf3 -> TC2 (so byte0 bit0 is the flag selector, not the parallel marker:
	// no_parallel). The flag prints uppercase (TC1/TC2) via the register path,
	// matching this form's legacy rendering. Typed AND; not lifted.
	{ .mask = 0xfe000000, .match = 0xf2000000, .id = TMS320C55_INS_BAND, .len = 4, .no_parallel = true,
		.ops = { { .lo = 16, .width = 8, .fn = c55x_x_smem }, { .lo = 0, .width = 16, .fn = c55_x_imm }, { .lo = 24, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg } } },
	// mov #k, Smem store (opcodes 0xe6 #k8 / 0xfb #k16): write an immediate
	// constant into the single-data-memory operand. The immediate is the source
	// (printed first) -- byte2 for 0xe6, bytes 2-3 for 0xfb -- and the Smem field
	// is byte1. byte0 LSB is part of the opcode here, not the parallel marker
	// (no_parallel). The shared MOV lifter declines an immediate-to-memory store
	// (it only lifts reg/imm-to-reg and reg<->memory), so the IL falls back to the
	// legacy lifter (the immediate store).
	{ .mask = 0xff000000, .match = 0xe6000000, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm }, { .lo = 8, .width = 8, .fn = c55x_x_smem } } },
	{ .mask = 0xff000000, .match = 0xfb000000, .id = TMS320C55_INS_MOV, .len = 4, .no_parallel = true,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm }, { .lo = 16, .width = 8, .fn = c55x_x_smem } } },
	// and/or #k16, Smem (opcodes 0xf4 / 0xf5): bitwise-combine an unsigned
	// 16-bit constant into the single-data-memory operand in place. The
	// immediate is the source (printed first, bytes 2-3), the Smem field is
	// byte1; byte0 LSB is opcode, not the parallel marker (no_parallel). Lifted
	// as a memory read-modify-write where the Smem mode has a shared effective
	// address (see the AND/OR op-type lifter); other modes fall back.
	{ .mask = 0xff000000, .match = 0xf4000000, .id = TMS320C55_INS_AND, .len = 4, .no_parallel = true,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm }, { .lo = 16, .width = 8, .fn = c55x_x_smem } } },
	{ .mask = 0xff000000, .match = 0xf5000000, .id = TMS320C55_INS_OR, .len = 4, .no_parallel = true,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm }, { .lo = 16, .width = 8, .fn = c55x_x_smem } } },
	// addsubcc Smem, ACx, TCx, ACy (opcode 0xde, selectors 0 and 1): a
	// conditional add/subtract -- ACy = ACx +/- Smem depending on the test-
	// control flag. 0xde is multi-form; byte2 bits 1-3 == 0 selects this form,
	// with byte2 bit 0 choosing TC1 (0) or TC2 (1), ACx in byte2 bits 6-7 and
	// ACy in bits 4-5. Typed ADD (as the legacy decoder did); not lifted. The
	// remaining 0xde forms (the two-flag addsubcc, subc, the Smem<<#16 add/sub
	// forms, and addsub/subadd) stay on the legacy decoder.
	{ .mask = 0xff000e00, .match = 0xde000000, .id = TMS320C55_INS_ADDSUBCC, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 0, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// addsubcc Smem, ACx, TC1, TC2, ACy (opcode 0xde, selector 2): the two-flag
	// conditional add/subtract. The selector value 2 (byte2 bits 0-3 == 0b0010)
	// conveniently has bit 0 == 0 and bit 1 == 1, so the same TC register
	// extractor reads TC1 from bit 0 and TC2 from bit 1.
	{ .mask = 0xff000f00, .match = 0xde000200, .id = TMS320C55_INS_ADDSUBCC, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 0, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg }, { .lo = 1, .width = 1, .param = C55_RC_TC, .fn = c55_x_reg }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// subc Smem, [ACx,] ACy (opcode 0xde, selector 3): the conditional-subtract
	// (subtract-with-borrow) used in division. ACx (byte2 bits 6-7) collapses
	// against ACy (bits 4-5) when equal, leaving just the destination. The
	// legacy decoder left it untyped; it is typed SUB here. The Smem source is
	// declined by the generic sub lifter, so there is no IL (as before).
	{ .mask = 0xff000f00, .match = 0xde000300, .id = TMS320C55_INS_SUBC, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// add / sub Smem << #16, [ACx,] ACy (opcode 0xde, selectors 4 and 5): the
	// memory operand is shifted left by a fixed 16 (rendered "<< #16" by the
	// memory formatter via c55x_x_smem_sh16). ACx (byte2 bits 6-7) collapses
	// against ACy (bits 4-5). Typed ADD / SUB as the legacy decoder did; the
	// shifted Smem source is declined by the generic add/sub lifter, so no IL.
	{ .mask = 0xff000f00, .match = 0xde000400, .id = TMS320C55_INS_ADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_sh16 }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000f00, .match = 0xde000500, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_sh16 }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// sub ACx, Smem << #16, ACy (opcode 0xde, selector 6): the reversed-operand
	// subtract (ACx minus the shifted memory). ACx (byte2 bits 6-7) is always
	// shown here. Typed SUB; no IL for the same reason.
	{ .mask = 0xff000f00, .match = 0xde000600, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 6, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg }, { .lo = 8, .width = 8, .fn = c55x_x_smem_sh16 }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// addsub / subadd Tx, Smem, ACx (opcode 0xde, selectors 8 and 9): the dual
	// add-and-subtract (a butterfly forming ACx +/- and -/+ Tx around Smem).
	// Tx is byte2 bits 6-7, ACx is bits 4-5. The legacy decoder left these
	// untyped; they are categorised by their leading operation (addsub -> ADD,
	// subadd -> SUB). The dual semantics are not modelled, and the generic
	// add/sub lifter declines the memory destination, so there is no IL.
	{ .mask = 0xff000f00, .match = 0xde000800, .id = TMS320C55_INS_ADDSUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 6, .width = 2, .param = C55_RC_T, .fn = c55_x_reg }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000f00, .match = 0xde000900, .id = TMS320C55_INS_SUBADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 6, .width = 2, .param = C55_RC_T, .fn = c55_x_reg }, { .lo = 8, .width = 8, .fn = c55x_x_smem }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// add / sub [uns(]Smem[)], [ACx,] ACy (opcode 0xdf, selectors 6 and 7): a
	// plain add/subtract of a data-memory word into an accumulator. byte2 bits
	// 1-3 pick add (6) or sub (7), byte2 bit 0 is the unsigned-memory qualifier
	// (rendered uns(...)), ACx (bits 6-7) collapses against ACy (bits 4-5).
	// Typed ADD/SUB as the legacy decoder did; the Smem source is declined by
	// the generic add/sub lifter, so there is no IL. The 0xdf high_byte /
	// low_byte / mov / carry / borrow forms remain on the legacy decoder.
	{ .mask = 0xff000e00, .match = 0xdf000c00, .id = TMS320C55_INS_ADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_uns }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000e00, .match = 0xdf000e00, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_uns }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// mov [uns(]Smem[)], ACx (opcode 0xdf, selector 2): load a data-memory word
	// into an accumulator, sign-extended to 40 bits (zero-extended when the
	// uns() qualifier from byte2 bit 0 is present). ACx is byte2 bits 4-5. The
	// shared mov lifter handles the load via c55_mem_move, matching the legacy
	// sign/zero-extend IL exactly.
	{ .mask = 0xff000e00, .match = 0xdf000400, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_uns }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// mov [uns(]high_byte/low_byte(Smem)[)], ACx (opcode 0xdf, selectors 0 and
	// 1): load the high or low byte of a data-memory word into an accumulator.
	// byte2 bits 1-3 pick high_byte (0) or low_byte (1); byte2 bit 0 is the
	// unsigned qualifier and ACx is byte2 bits 4-5. Typed MOV; the byte-access
	// load is not lifted (the memory mover declines a byte_sel operand), as in
	// the legacy decoder.
	{ .mask = 0xff000e00, .match = 0xdf000000, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .param = 1, .fn = c55x_x_smem_byte }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000e00, .match = 0xdf000200, .id = TMS320C55_INS_MOV, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .param = 2, .fn = c55x_x_smem_byte }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// add [uns(]Smem[)], CARRY, [ACx,] ACy / sub [uns(]Smem[)], BORROW, [ACx,]
	// ACy (opcode 0xdf, selectors 4 and 5): add-with-carry / subtract-with-
	// borrow of a memory word into an accumulator. byte2 bits 1-3 select add
	// CARRY (4) or sub BORROW (5); the flag operand is read from byte2 bit 1
	// (pinned by the row mask: 0 -> CARRY, 1 -> BORROW). byte2 bit 0 is the
	// unsigned qualifier and ACx (bits 6-7) collapses against ACy (bits 4-5).
	// Typed ADD/SUB as the legacy decoder did; the Smem source is declined by
	// the generic add/sub lifter, so there is no IL.
	{ .mask = 0xff000e00, .match = 0xdf000800, .id = TMS320C55_INS_ADD, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_uns }, { .lo = 1, .width = 1, .param = C55_RC_SPECIAL, .fn = c55_x_reg }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	{ .mask = 0xff000e00, .match = 0xdf000a00, .id = TMS320C55_INS_SUB, .len = 3, .no_parallel = true,
		.ops = { { .lo = 8, .width = 8, .fn = c55x_x_smem_uns }, { .lo = 1, .width = 1, .param = C55_RC_SPECIAL, .fn = c55_x_reg }, { .fn = c55x_x_macreg_acy_dst }, { .lo = 4, .width = 2, .param = C55_RC_AC, .fn = c55_x_reg } } },
	// mov src, dst (opcode 0x90): register-to-register move over the extended
	// "xsrc"/"xdst" register set (0-3 AC, 4-7 XSP/XSSP/XDP/XCDP, 8-15 XAR). byte1
	// bits 4-7 = src, bits 0-3 = dst; the shared MOV lifter sign/zero-extends to
	// the destination width (and declines when an operand has no lifter var).
	{ .mask = 0xff000000, .match = 0x90000000, .id = TMS320C55_INS_MOV, .len = 2, .no_parallel = true,
		.ops = { { .lo = 4, .fn = c55x_x_xgr4 }, { .lo = 0, .fn = c55x_x_xgr4 } } },
	// b acx (opcode 0x91) / call acx (opcode 0x92): register-indirect branch and
	// call to the address in an accumulator (AC0-3 in the low two bits).
	{ .mask = 0xff000000, .match = 0x91000000, .id = TMS320C55_INS_B, .len = 2,
		.ops = { { .lo = 0, .width = 2, .fn = c55x_x_ac2 } } },
	{ .mask = 0xff000000, .match = 0x92000000, .id = TMS320C55_INS_CALL, .len = 2,
		.ops = { { .lo = 0, .width = 2, .fn = c55x_x_ac2 } } },
	// b L16 (opcode 0x06) / call L16 (opcode 0x08): 16-bit pc-relative branch and
	// call. Three bytes, the signed displacement in bytes 1-2; target is
	// pc + size + sign-extended(disp16). Same machinery as the 0x4a short branch
	// (a reltarget immediate plus c55_effective_type refining 'b'/'call' to a
	// direct JMP/CALL), just a wider field, and both are parallel-capable.
	{ .mask = 0xfe000000, .match = 0x06000000, .id = TMS320C55_INS_B, .len = 3,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm, .param = 2 } } },
	{ .mask = 0xfe000000, .match = 0x08000000, .id = TMS320C55_INS_CALL, .len = 3,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm, .param = 2 } } },
	// b P24 (opcode 0x6a and 0x6b) / call P24 (opcode 0x6c): 24-bit absolute
	// branch and call. Four bytes, the destination address in bytes 1-3; the
	// target is that address directly (abs_target), not a pc-relative offset.
	// These are not parallel-capable: 0x6b is a second plain 'b' encoding (not
	// '|| b'), and 0x6d is a different instruction (bcc), so each pins its byte.
	// The operand is an addr (rendered as a 24-bit address) carrying abs_target.
	{ .mask = 0xff000000, .match = 0x6a000000, .id = TMS320C55_INS_B, .len = 4,
		.ops = { { .lo = 0, .width = 24, .fn = c55_x_imm, .param = 12 } } },
	{ .mask = 0xff000000, .match = 0x6b000000, .id = TMS320C55_INS_B, .len = 4,
		.ops = { { .lo = 0, .width = 24, .fn = c55_x_imm, .param = 12 } } },
	{ .mask = 0xff000000, .match = 0x6c000000, .id = TMS320C55_INS_CALL, .len = 4,
		.ops = { { .lo = 0, .width = 24, .fn = c55_x_imm, .param = 12 } } },
	// reset (opcode 0x94): software reset, no operands.
	{ .mask = 0xff000000, .match = 0x94000000, .id = TMS320C55_INS_RESET, .len = 2 },
	// ret / reti (opcode 0x48): within this group the low three bits of the
	// operand byte select the operation (0b100 = ret, 0b101 = reti; bits 3-7 are
	// don't-cares for these two), so the rows match byte0 plus those three bits
	// via a 0xff070000 mask. Both pop a return address and are typed as returns;
	// the remaining 0x48 sub-ops (rpt/rptadd/rptsub csr) stay on the legacy path.
	{ .mask = 0xff070000, .match = 0x48040000, .id = TMS320C55_INS_RET, .len = 2 },
	{ .mask = 0xff070000, .match = 0x48050000, .id = TMS320C55_INS_RETI, .len = 2 },
	// xcc / xccpart (opcode 0x96): predicated execution. Bit 7 of the operand
	// byte selects xccpart (set) from xcc (clear), and the low seven bits are the
	// condition field. Only register-versus-zero comparisons are decoded here;
	// status-flag conditions fall back to the legacy decoder via c55x_x_cond.
	{ .mask = 0xff800000, .match = 0x96000000, .id = TMS320C55_INS_XCC, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	{ .mask = 0xff800000, .match = 0x96800000, .id = TMS320C55_INS_XCCPART, .lop = C55_LOP_NOP, .xcc_guard = true, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	// bcc short form (opcodes 0x60-0x67): the destination offset is a four-bit
	// field with the high three bits in byte0 (bits 0-2) and the low bit in byte1
	// (bit 7), at packed bits 7-10; target = pc + size + offset. Bit 0 of the
	// leading byte is part of that offset, not the parallel marker (no_parallel).
	// The remaining low seven bits of byte1 carry the same register-versus-zero
	// condition field as xcc; status-flag conditions fall back to the legacy
	// decoder via c55x_x_cond.
	{ .mask = 0xf8000000, .match = 0x60000000, .id = TMS320C55_INS_BCC, .len = 2, .no_parallel = true,
		.ops = { { .lo = 7, .width = 4, .fn = c55x_x_bcc_short_target },
			{ .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	// bcc 0x04 form: a 3-byte conditional branch. byte1 carries the register-
	// versus-zero condition field (bit 7 unused) and byte2 is a signed 8-bit
	// pc-relative offset (target = pc + size + offset). Parallel-capable
	// (0x05 = || bcc); status-flag conditions fall back to the legacy decoder.
	{ .mask = 0xfe000000, .match = 0x04000000, .id = TMS320C55_INS_BCC, .len = 3,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm, .param = 2 },
			{ .lo = 8, .width = 7, .fn = c55x_x_cond } } },
	// bcc L16 form (opcode 0x6d): byte1 is the register-versus-zero condition,
	// byte2-3 a signed 16-bit pc-relative offset (target = pc + size + offset).
	// The legacy front-end recovered the displacement by re-parsing the rendered
	// text and sign-extending to 8 bits, truncating the L16 offset; decoding it
	// from the instruction bits computes the correct target.
	{ .mask = 0xff000000, .match = 0x6d000000, .id = TMS320C55_INS_BCC, .len = 4,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm, .param = 2 },
			{ .lo = 16, .width = 7, .fn = c55x_x_cond } } },
	// bcc P24 form (opcode 0x68): byte1 is the register-versus-zero condition,
	// byte2-4 a 24-bit absolute program address (same as the unconditional P24
	// branch). The legacy 8-bit text-parsing path mis-computed this too; the
	// shared decoder takes the absolute target directly from the bits.
	{ .mask = 0xff000000, .match = 0x68000000, .id = TMS320C55_INS_BCC, .len = 5,
		.ops = { { .lo = 0, .width = 24, .fn = c55_x_imm, .param = 12 },
			{ .lo = 24, .width = 7, .fn = c55x_x_cond } } },
	// bcc compare-and-branch (opcode 0x6f): byte1 selects the source register
	// (gr4) and signed comparison, byte2 is the 8-bit compare constant K8, and
	// byte3 a signed 8-bit pc-relative offset. The unsigned form (bccu) is left
	// to the legacy decoder via c55x_x_cond_imm. The legacy text-parsing path
	// sign-extended this displacement to 16 bits; decoding the L8 offset from the
	// instruction bits yields the correct (possibly negative) targets.
	{ .mask = 0xff000000, .match = 0x6f000000, .id = TMS320C55_INS_BCC, .len = 4,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm, .param = 2 },
			{ .lo = 8, .width = 16, .fn = c55x_x_cond_imm } } },
	// callcc (conditional call): byte1 is the register-versus-zero condition.
	// 0x6e is the L16 form (byte2-3 a signed 16-bit pc-relative offset); 0x69 is
	// the P24 form (byte2-4 a 24-bit absolute target). These reuse the same
	// target machinery as the conditional branches with a CCALL type and the
	// call stack effect. The legacy analysis read the displacement from the wrong
	// bytes (a 16-bit value starting at the condition byte), so its targets were
	// wrong for both forms; decoding from the bits computes them correctly.
	{ .mask = 0xff000000, .match = 0x6e000000, .id = TMS320C55_INS_CALLCC, .len = 4,
		.ops = { { .lo = 0, .width = 16, .fn = c55_x_imm, .param = 2 },
			{ .lo = 16, .width = 7, .fn = c55x_x_cond } } },
	{ .mask = 0xff000000, .match = 0x69000000, .id = TMS320C55_INS_CALLCC, .len = 5,
		.ops = { { .lo = 0, .width = 24, .fn = c55_x_imm, .param = 12 },
			{ .lo = 24, .width = 7, .fn = c55x_x_cond } } },
	// retcc (conditional return, opcode 0x02; 0x03 = || retcc): byte1 carries the
	// register-versus-zero condition and byte2 is unused. Typed CRET (a pop with
	// a fall-through edge); no IL. Status-flag conditions fall back to the legacy
	// decoder via c55x_x_cond.
	{ .mask = 0xfe000000, .match = 0x02000000, .id = TMS320C55_INS_RETCC, .len = 3,
		.ops = { { .lo = 8, .width = 7, .fn = c55x_x_cond } } },
	// rpt k8 (opcode 0x4c): repeat the next instruction (k8+1) times; the count
	// is the full operand byte. Parallel-capable, so the row matches 0x4c/0x4d.
	{ .mask = 0xfe000000, .match = 0x4c000000, .id = TMS320C55_INS_RPT, .len = 2,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm } } },
	// intr k5 / trap k5 (opcode 0x95): software interrupt vs trap to a 5-bit
	// vector. The two share the leading byte and are told apart by bit 7 of the
	// operand byte, so the rows reach into byte1 with a 0xff800000 mask; the
	// vector is the low five bits (bits 5-6 are don't-cares).
	{ .mask = 0xff800000, .match = 0x95000000, .id = TMS320C55_INS_INTR, .len = 2,
		.ops = { { .lo = 0, .width = 5, .fn = c55_x_imm } } },
	{ .mask = 0xff800000, .match = 0x95800000, .id = TMS320C55_INS_TRAP, .len = 2,
		.ops = { { .lo = 0, .width = 5, .fn = c55_x_imm } } },
	// b offset (opcode 0x4a with bit 7 of the operand byte clear; bit 7 set is
	// rptblocal below). A short pc-relative branch: the displacement is the
	// operand byte sign-extended to 8 bits (bit 7 being clear here, it is always
	// a forward 0..127). The id 'b' is shared with the register-indirect form
	// (0x91); c55_effective_type refines this immediate-operand form to a direct
	// JMP. The offset is a reltarget so it drives target computation yet renders
	// as a plain immediate rather than a 24-bit address.
	{ .mask = 0xfe800000, .match = 0x4a000000, .id = TMS320C55_INS_B, .len = 2,
		.ops = { { .lo = 0, .width = 8, .fn = c55_x_imm, .param = 2 } } },
	// rptblocal k7 (opcode 0x4a with bit 7 of the operand byte set; bit 7 clear
	// is the offset branch b, left to the legacy decoder). Block-local repeat
	// with a 7-bit count. Both parallel-capable and byte1-discriminated, so the
	// mask composes the two: 0xfe leaves the parallel bit free, 0x..800000 pins
	// the discriminator (matching 0x4a/0x4b with operand bit 7 set).
	{ .mask = 0xfe800000, .match = 0x4a800000, .id = TMS320C55_INS_RPTBLOCAL, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55_x_imm } } },

	// --- dual "::" MACs (opcodes 0x82-0x85) -----------------------------
	// Two parallel sub-MACs sharing a Cmem coefficient. The leading byte picks
	// the family and byte2 bits 2-3 (packed bits 10-11) the sub-op pair; the
	// operands and sub-op metadata are produced by c55x_fill_dual. The id only
	// drives the op type (all -> MUL); the disasm uses the dual formatter.
	// 0x85 op=10 (triple amar) / op=11 (firsadd/firssub) and all of 0x86 stay
	// on the legacy front-end for now.
	// 0x82: <sub1> :: mpy
	{ .mask = 0xff000c00, .match = 0x82000000, .id = TMS320C55_INS_MPY, .len = 4, .dual = true, .lop = C55_LOP_NONE, .lop2 = C55_LOP_NONE },
	{ .mask = 0xff000c00, .match = 0x82000400, .id = TMS320C55_INS_MPY, .len = 4, .dual = true, .lop = C55_LOP_MAC, .lop2 = C55_LOP_NONE },
	{ .mask = 0xff000c00, .match = 0x82000800, .id = TMS320C55_INS_MPY, .len = 4, .dual = true, .lop = C55_LOP_MAS, .lop2 = C55_LOP_NONE },
	{ .mask = 0xff000c00, .match = 0x82000c00, .id = TMS320C55_INS_AMAR, .len = 4, .dual = true, .amar1 = true, .lop2 = C55_LOP_NONE },
	// 0x83: <sub1> :: mac
	{ .mask = 0xff000c00, .match = 0x83000000, .id = TMS320C55_INS_MAC, .len = 4, .dual = true, .lop = C55_LOP_MAC, .lop2 = C55_LOP_MAC },
	{ .mask = 0xff000c00, .match = 0x83000400, .id = TMS320C55_INS_MAC, .len = 4, .dual = true, .lop = C55_LOP_MAS, .lop2 = C55_LOP_MAC },
	{ .mask = 0xff000c00, .match = 0x83000800, .id = TMS320C55_INS_MAC, .len = 4, .dual = true, .lop = C55_LOP_MAC, .shift1 = true, .lop2 = C55_LOP_MAC },
	{ .mask = 0xff000c00, .match = 0x83000c00, .id = TMS320C55_INS_AMAR, .len = 4, .dual = true, .amar1 = true, .lop2 = C55_LOP_MAC },
	// 0x84: <sub1> :: mac >> #16
	{ .mask = 0xff000c00, .match = 0x84000000, .id = TMS320C55_INS_MAS, .len = 4, .dual = true, .lop = C55_LOP_MAS, .lop2 = C55_LOP_MAC, .shift2 = true },
	{ .mask = 0xff000c00, .match = 0x84000400, .id = TMS320C55_INS_AMAR, .len = 4, .dual = true, .amar1 = true, .lop2 = C55_LOP_MAC, .shift2 = true },
	{ .mask = 0xff000c00, .match = 0x84000800, .id = TMS320C55_INS_MAS, .len = 4, .dual = true, .lop = C55_LOP_NONE, .lop2 = C55_LOP_MAC, .shift2 = true },
	{ .mask = 0xff000c00, .match = 0x84000c00, .id = TMS320C55_INS_MAS, .len = 4, .dual = true, .lop = C55_LOP_MAC, .shift1 = true, .lop2 = C55_LOP_MAC, .shift2 = true },
	// 0x85: <sub1> :: mas (op=00 amar::mas, op=01 mas::mas)
	{ .mask = 0xff000c00, .match = 0x85000000, .id = TMS320C55_INS_AMAR, .len = 4, .dual = true, .amar1 = true, .lop2 = C55_LOP_MAS },
	{ .mask = 0xff000c00, .match = 0x85000400, .id = TMS320C55_INS_MAS, .len = 4, .dual = true, .lop = C55_LOP_MAS, .lop2 = C55_LOP_MAS },
	// 0x85 op=10: triple-register amar (amar Xmem, Ymem, Cmem) - three address
	// modifies, no product; classified LEA and lifted as the sequence of the
	// operands' post-modify side effects. (op=11 firsadd/firssub stays legacy.)
	{ .mask = 0xff000c00, .match = 0x85000800, .id = TMS320C55_INS_AMAR, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .fn = c55x_x_dual_cmem3 } } },
	// 0x85 op=11: FIR symmetric/antisymmetric filter step. byte3 bit4 selects
	// firsadd (0) vs firssub (1); ACx is byte3 bits 2-3, ACy byte3 bits 6-7.
	{ .mask = 0xff000c10, .match = 0x85000c00, .id = TMS320C55_INS_FIRSADD, .lop = C55_LOP_FIRSADD, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .fn = c55x_x_dual_cmem3 },
			{ .lo = 2, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 6, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff000c10, .match = 0x85000c10, .id = TMS320C55_INS_FIRSSUB, .lop = C55_LOP_FIRSSUB, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .fn = c55x_x_dual_cmem3 },
			{ .lo = 2, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 6, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// 0x86 dual-multiply family selected by byte3 bits 5-7: mpym (0, ACx=Xmem*Ymem),
	// macm (1, MAC), masm (3, MAS). uns()/T3=/r/40 qualifiers and the source/dest
	// accumulators are decoded by the xymac extractors and .mods (round=bit0,
	// side-load=bit1, M40=bit4). The macm/masm two-operand form (SS==DD) drops the
	// explicit source slot. (macm>>16 (2), the ::mov pairs (4,5), lms (6) and
	// sqdst/abdst (14,15) stay on the legacy path for now.)
	{ .mask = 0xff0000e0, .match = 0x86000000, .id = TMS320C55_INS_MPYM, .len = 4, .mods = 0x5081,
		.ops = { { .fn = c55x_x_xymac_xmem }, { .fn = c55x_x_xymac_ymem }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x86000020, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 4, .mods = 0x5081,
		.ops = { { .fn = c55x_x_xymac_xmem }, { .fn = c55x_x_xymac_ymem }, { .fn = c55x_x_xymac_src }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x86000060, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 4, .mods = 0x5081,
		.ops = { { .fn = c55x_x_xymac_xmem }, { .fn = c55x_x_xymac_ymem }, { .fn = c55x_x_xymac_src }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// 0x86 macm>>16 (byte3 bits 5-7 = 2): like macm but the accumulator is shifted
	// right 16 before the product (ACy = (ACx >> #16) + Xmem*Ymem).
	{ .mask = 0xff0000e0, .match = 0x86000040, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 4, .mods = 0x5081, .shift16 = true,
		.ops = { { .fn = c55x_x_xymac_xmem }, { .fn = c55x_x_xymac_ymem }, { .fn = c55x_x_xymac_src }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// 0x86 lms (byte3 bits 5-7 = 6): ACy += Xmem*Ymem :: ACx = round(ACx + Xmem<<16).
	// ACx is byte2 bits 0-1, ACy bits 2-3; the round/reserved last-byte low bits do
	// not affect the disassembly. (The ::mov pairs at 4,5 stay on the legacy path.)
	{ .mask = 0xff0000e0, .match = 0x860000c0, .id = TMS320C55_INS_LMS, .lop = C55_LOP_LMS, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// 0x86 distance forms (byte3 bits 4-7: sqdst=14, abdst=15): ACy += ACx.h^2 (or
	// |ACx.h|) :: ACx = (Xmem<<16) - (Ymem<<16). ACx is byte2 bits 0-1, ACy bits 2-3.
	{ .mask = 0xff0000f0, .match = 0x860000e0, .id = TMS320C55_INS_SQDST, .lop = C55_LOP_SQDST, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000f0, .match = 0x860000f0, .id = TMS320C55_INS_ABDST, .lop = C55_LOP_ABDST, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// 0x86 MAC :: parallel load (byte3 bits 5-7: masm::mov=4, macm::mov=5):
	//   ACx = ACx -/+ (Xmem * Tx) [, T3=Xmem] :: ACy = Ymem << #16.
	// ops: Xmem, Tx (byte3 bits 2-3), ACx (byte2 bits 0-1), Ymem, ACy (byte2 bits 2-3);
	// .mods packs round (bit0) and the T3= side-load (bit1).
	{ .mask = 0xff0000e0, .match = 0x86000080, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 4, .mods = 0x81, .mac_mov = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 2, .fn = c55x_x_mac_tcoef }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x860000a0, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 4, .mods = 0x81, .mac_mov = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 2, .fn = c55x_x_mac_tcoef }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// --- A-unit ALU aadd / amov / asub (opcode 0x14) ----------------------
	// 3 bytes. The operation and operand form are selected by the low nibble
	// of byte2: bit 2 chooses register (0) vs P8-immediate (1) source, and
	// bits[1:0] select aadd (00) / amov (01) / asub (10); bit 3 is a redundant
	// sub-bank that does not change the operation. The XAC (extended pointer)
	// register form is marked by a 1 in byte1's low nibble and matched first.
	// XACS = byte1[7:4], XACD = byte2[7:4]; FSSS/FDDD are the same fields read
	// as the AC/T/AR set; P8 = byte1. dst = dst <op> src via the shared AREG
	// lift (aadd/amov/asub all carry IL on C55x).
	{ .mask = 0xff0f0700, .match = 0x14010000, .id = TMS320C55_INS_AADD, .lop = C55_LOP_AREG_ADD, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_xgr4 }, { .lo = 4, .fn = c55x_x_xgr4 } } },
	{ .mask = 0xff0f0700, .match = 0x14010100, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AREG_MOV, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_xgr4 }, { .lo = 4, .fn = c55x_x_xgr4 } } },
	{ .mask = 0xff0f0700, .match = 0x14010200, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_xgr4 }, { .lo = 4, .fn = c55x_x_xgr4 } } },
	{ .mask = 0xff000700, .match = 0x14000000, .id = TMS320C55_INS_AADD, .lop = C55_LOP_AREG_ADD, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_gr4 }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000700, .match = 0x14000100, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AREG_MOV, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_gr4 }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000700, .match = 0x14000200, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 3,
		.ops = { { .lo = 12, .fn = c55x_x_gr4 }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000700, .match = 0x14000400, .id = TMS320C55_INS_AADD, .lop = C55_LOP_AREG_ADD, .len = 3,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000700, .match = 0x14000500, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AREG_MOV, .len = 3,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 4, .fn = c55x_x_gr4 } } },
	{ .mask = 0xff000700, .match = 0x14000600, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 3,
		.ops = { { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// --- mov K16, dst (opcode 0x76, byte3[3:2] == 10) ---------------------
	// 4 bytes; K16 = byte1:byte2 (MSB-first), dst = byte3[7:4] (AC/T/AR). The
	// shared AREG move lifts dst = K16.
	{ .mask = 0xff00000c, .match = 0x76000008, .id = TMS320C55_INS_MOV, .lop = C55_LOP_AREG_MOV, .len = 4,
		.ops = { { .lo = 8, .width = 16, .fn = c55_x_imm }, { .lo = 4, .fn = c55x_x_gr4 } } },
	// --- xcc / xccpart (opcodes 0x9e / 0x9f) ------------------------------
	// As the 0x96 forms: byte1[7] selects xccpart (1) over xcc (0); the 7-bit
	// condition is byte1[6:0]. Standalone, the qualifier gates the following
	// instruction, which per-instruction lifting expresses as nop.
	{ .mask = 0xff800000, .match = 0x9e000000, .id = TMS320C55_INS_XCC, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	{ .mask = 0xff800000, .match = 0x9e800000, .id = TMS320C55_INS_XCCPART, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	{ .mask = 0xff800000, .match = 0x9f000000, .id = TMS320C55_INS_XCC, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	{ .mask = 0xff800000, .match = 0x9f800000, .id = TMS320C55_INS_XCCPART, .lop = C55_LOP_NOP, .len = 2,
		.ops = { { .lo = 0, .width = 7, .fn = c55x_x_cond } } },
	// --- dual-memory move (opcode 0x80) -----------------------------------
	// 3 bytes; byte1 = XXXMMMYY, byte2 = YMMM00xx with byte2[3:2] selecting the
	// form: 00 = mov dbl(Xmem),dbl(Ymem); 01 = mov Xmem,Ymem; 10 = mov ACx,
	// Xmem,Ymem (ACx = byte2[1:0]). Xmem is the source, Ymem the destination.
	{ .mask = 0xff000c00, .match = 0x80000000, .id = TMS320C55_INS_MOV, .lop = C55_LOP_MOVMEM, .len = 3,
		.ops = { { .fn = c55x_x_dual_xmem3_dbl }, { .fn = c55x_x_dual_ymem3_dbl } } },
	{ .mask = 0xff000c00, .match = 0x80000400, .id = TMS320C55_INS_MOV, .lop = C55_LOP_MOVMEM, .len = 3,
		.ops = { { .fn = c55x_x_dual_xmem3 }, { .fn = c55x_x_dual_ymem3 } } },
	{ .mask = 0xff000c00, .match = 0x80000800, .id = TMS320C55_INS_MOV, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 0, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_xmem3 }, { .fn = c55x_x_dual_ymem3 } } },
	// --- dual-memory add / sub into ACx (opcode 0x81) ---------------------
	// Same dual-memory layout as 0x80; byte2[3:2] selects 00 = add Xmem,Ymem,
	// ACx; 01 = sub; 10 = mov Xmem,Ymem,ACx. ACx = byte2[1:0]. ACx = sx(Xmem)
	// +/- sx(Ymem).
	{ .mask = 0xff000c00, .match = 0x81000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_DUALADD, .len = 3,
		.ops = { { .fn = c55x_x_dual_xmem3 }, { .fn = c55x_x_dual_ymem3 }, { .lo = 0, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff000c00, .match = 0x81000400, .id = TMS320C55_INS_SUB, .lop = C55_LOP_DUALSUB, .len = 3,
		.ops = { { .fn = c55x_x_dual_xmem3 }, { .fn = c55x_x_dual_ymem3 }, { .lo = 0, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff000c00, .match = 0x81000800, .id = TMS320C55_INS_MOV, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .fn = c55x_x_dual_xmem3 }, { .fn = c55x_x_dual_ymem3 }, { .lo = 0, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// --- swap ar0, ar1 (opcode 0x5e, key 56) ------------------------------
	// The single arbitrary-AR swap pair; byte1 == 0x38 distinguishes it from
	// the 4-bit sel pairs. Lifts as the same XOR exchange as the other swaps.
	{ .mask = 0xfeff0000, .match = 0x5e380000, .id = TMS320C55_INS_SWAP, .len = 2,
		.ops = { { .lo = 0, .param = 0, .fn = c55x_x_swap }, { .lo = 0, .param = 1, .fn = c55x_x_swap } } },
	// --- idle (opcode 0x7a, byte3[3:1] == 6) ------------------------------
	// Low-power idle; no data effect.
	{ .mask = 0xff00000e, .match = 0x7a00000c, .id = TMS320C55_INS_IDLE, .lop = C55_LOP_OPAQUE, .len = 4 },
	// --- 0x87 parallel dual-MAC with hi-word store ------------------------
	// 4 bytes; the dual-memory Xmem/Ymem and SS/DD accumulator fields live in
	// byte1/byte2 (the 0x82-0x86 layout). byte3 selects the form: bits[7:5] =
	// 000/001/010 -> mpym/macm/masm "[t3=]Xmem, Tx, ACy :: mov hi(ACx << t2),
	// Ymem" (Tx = byte3[3:2], round = byte3[0]); = 100/101/110 -> add/sub/mov
	// "Xmem << #16, ... :: mov hi(ACz << t2), Ymem"; byte3 == 0x61 -> lmsf
	// Xmem, Ymem, ACx, ACy. All decode-only (no modelled IL).
	{ .mask = 0xff0000ff, .match = 0x87000061, .id = TMS320C55_INS_LMSF, .lop = C55_LOP_OPAQUE, .len = 4,
		.ops = { { .fn = c55x_x_dual_xmem }, { .fn = c55x_x_dual_ymem }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x87000000, .id = TMS320C55_INS_MPYM, .lop = C55_LOP_OPAQUE, .len = 4, .mods = 0x01, .mac_store = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 2, .width = 2, .fn = c55x_x_t2 }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x87000020, .id = TMS320C55_INS_MACM, .lop = C55_LOP_OPAQUE, .len = 4, .mods = 0x01, .mac_store = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 2, .width = 2, .fn = c55x_x_t2 }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x87000040, .id = TMS320C55_INS_MASM, .lop = C55_LOP_OPAQUE, .len = 4, .mods = 0x01, .mac_store = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 2, .width = 2, .fn = c55x_x_t2 }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff0000e0, .match = 0x87000080, .id = TMS320C55_INS_ADD, .lop = C55_LOP_OPAQUE, .len = 4, .mac_store = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem } } },
	{ .mask = 0xff0000e0, .match = 0x870000a0, .id = TMS320C55_INS_SUB, .lop = C55_LOP_OPAQUE, .len = 4, .mac_store = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem } } },
	{ .mask = 0xff0000e0, .match = 0x870000c0, .id = TMS320C55_INS_MOV, .lop = C55_LOP_OPAQUE, .len = 4, .mac_store = true,
		.ops = { { .fn = c55x_x_dual_xmem }, { .lo = 8, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .fn = c55x_x_dual_ymem }, { .lo = 10, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// --- mant ACx, ACy :: nexp ACx, Tx (opcode 0x10, selector 9) ----------
	// 3 bytes; ACx = byte1[5:4] (SS), ACy = byte1[7:6] (DD), Tx = byte2[5:4]
	// (dd). ACx is shared by both halves. Decode-only.
	{ .mask = 0xff0f0000, .match = 0x10090000, .id = TMS320C55_INS_MANT, .lop = C55_LOP_OPAQUE, .len = 3, .mant_nexp = true,
		.ops = { { .lo = 12, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 14, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 4, .width = 2, .fn = c55x_x_t2 } } },
	// --- addsub / subadd Tx, dual(Lmem), ACy (opcode 0xee, sel 6/7) -------
	// 3 bytes; same Lmem (AAAAAAAI) layout as the 0xee add/sub forms. The
	// SS field is the Tx operand and DD the ACy. byte2[3:1] selects the form.
	{ .mask = 0xff000e00, .match = 0xee000c00, .id = TMS320C55_INS_ADDSUB, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 6, .width = 2, .fn = c55x_x_t2 }, { .lo = 8, .fn = c55x_x_smem_dual }, { .lo = 4, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff000e00, .match = 0xee000e00, .id = TMS320C55_INS_SUBADD, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .lo = 6, .width = 2, .fn = c55x_x_t2 }, { .lo = 8, .fn = c55x_x_smem_dual }, { .lo = 4, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// --- mpymk / macmk [t3=]Smem, K8, [ACx,] ACy (opcode 0xf8) ------------
	// 4 bytes; Smem = byte1, K8 = byte2. byte3[2] selects macmk (1) over mpymk
	// (0); byte3[0] is the rounding (r) bit and byte3[1] the T3= side-load (the
	// legacy "U" field). mpymk has only ACx = byte3[5:4]; macmk adds ACx =
	// byte3[7:6] (SS) with ACy = byte3[5:4] (DD). Decode-only.
	{ .mask = 0xff000004, .match = 0xf8000000, .id = TMS320C55_INS_MPYMK, .lop = C55_LOP_OPAQUE, .len = 4, .mods = 0x81,
		.ops = { { .lo = 16, .fn = c55x_x_smem }, { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 4, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	{ .mask = 0xff000004, .match = 0xf8000004, .id = TMS320C55_INS_MACMK, .lop = C55_LOP_OPAQUE, .len = 4, .mods = 0x81,
		.ops = { { .lo = 16, .fn = c55x_x_smem }, { .lo = 8, .width = 8, .fn = c55_x_imm }, { .lo = 6, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC }, { .lo = 4, .width = 2, .fn = c55_x_reg, .param = C55_RC_AC } } },
	// --- ret (opcode 0x48, selector 4) -----------------------------------
	// 2 bytes; selector = byte1[2:0] (4 = ret). byte0 bit0 is the parallel (E)
	// flag, so masking it off (0xfe) lets the shared engine raise the "|| "
	// prefix when set (the "|| ret" form 0x49 0x04).
	{ .mask = 0xfe0f0000, .match = 0x48040000, .id = TMS320C55_INS_RET, .lop = C55_LOP_NOP, .len = 2 },
	// --- band Smem, k16, TC1 (opcode 0xf2) -------------------------------
	// 4 bytes; Smem = byte1 (CDP modes 0x71/0x91/... now decode to *cdp...),
	// k16 = bytes 2-3 (the low 16 bits of the packed word). TC1 is a fixed
	// literal operand. Decode-only.
	{ .mask = 0xff000000, .match = 0xf2000000, .id = TMS320C55_INS_BAND, .lop = C55_LOP_OPAQUE, .len = 4,
		.ops = { { .lo = 16, .fn = c55x_x_smem }, { .lo = 0, .width = 16, .fn = c55_x_imm }, { .fn = c55x_x_tc1 } } },
	// --- btstp Baddr, src (opcode 0xec, selector 2) ----------------------
	// 3 bytes; selector = byte2[3:1] (2 = btstp). src = byte2[7:4] (FSSS). The
	// Baddr bit-address is not decoded by the legacy and renders as the literal
	// "Baddr". Decode-only.
	{ .mask = 0xff000e00, .match = 0xec000400, .id = TMS320C55_INS_BTSTP, .lop = C55_LOP_OPAQUE, .len = 3,
		.ops = { { .fn = c55x_x_baddr }, { .lo = 4, .fn = c55x_x_gr4 } } },
};

const C55ArchDesc c55x_arch_desc = {
	.arch = C55_ARCH_C55X,
	.cpu_name = "c55x",
	.table = c55x_table,
	.table_len = sizeof(c55x_table) / sizeof(c55x_table[0]),
	.insn_len = c55x_insn_len,
	.reg_info = c55x_reg_info,
	.mnemonic = c55x_mnemonic,
	.op_type = c55x_op_type,
	.lift = NULL,
	.mem = { .addr_unit_log2 = 1, .ptr_width = 23, .big_endian = false, .page_reg = "dph" },
	.ea = NULL,
	.fill_dual = c55x_fill_dual,
};

int tms320_c55x_op_byte(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!op || !buf || len < 1) {
		return 0;
	}

	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;

	/* Decode-once analysis: the C55x instruction is decoded a single time by
	 * the shared decode-IR engine, and the analysis op (type, branch targets,
	 * basic-block fall-through, src/dst/val, stack effects, instruction id) and
	 * the RzIL lift are both derived from that one decoded C55Insn. Anything the
	 * engine does not decode is reported as an illegal instruction. */
	C55Insn ci;
	if (c55_decode(&c55x_arch_desc, buf, len, &ci)) {
		c55_fill_analysis(&c55x_arch_desc, &ci, op);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = c55_lift(&c55x_arch_desc, &ci, op->addr);
		}
		return op->size;
	}

	op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	op->size = 1;
	return op->size;
}
