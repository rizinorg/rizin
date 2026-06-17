// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * TMS320C55x+ arch descriptor for the shared c55_ir decode engine.
 *
 * Table-driven replacement, built incrementally, for the th0rpe string decoder.
 * Rows not yet present fall back to the legacy decoder in the plugin, so the
 * cutover stays byte-exact at every step. The operand decode was reconstructed
 * and verified against TI's dis55 disassembler as ground truth.
 */

#include <rz_analysis.h>
#include "c55plus_arch.h"
#include "ins.h" // get_ins_len
#include "../tms320c55x_insn.h" // tms320c55x_insn_name, TMS320C55_INS_*

// Register tables (persistent, so reg_info hands out stable name/il_var ptrs).
static const C55RegInfo ac_ri[32] = {
	{ "ac0", "ac0", 40 },
	{ "ac1", "ac1", 40 },
	{ "ac2", "ac2", 40 },
	{ "ac3", "ac3", 40 },
	{ "ac4", "ac4", 40 },
	{ "ac5", "ac5", 40 },
	{ "ac6", "ac6", 40 },
	{ "ac7", "ac7", 40 },
	{ "ac8", "ac8", 40 },
	{ "ac9", "ac9", 40 },
	{ "ac10", "ac10", 40 },
	{ "ac11", "ac11", 40 },
	{ "ac12", "ac12", 40 },
	{ "ac13", "ac13", 40 },
	{ "ac14", "ac14", 40 },
	{ "ac15", "ac15", 40 },
	{ "ac16", "ac16", 40 },
	{ "ac17", "ac17", 40 },
	{ "ac18", "ac18", 40 },
	{ "ac19", "ac19", 40 },
	{ "ac20", "ac20", 40 },
	{ "ac21", "ac21", 40 },
	{ "ac22", "ac22", 40 },
	{ "ac23", "ac23", 40 },
	{ "ac24", "ac24", 40 },
	{ "ac25", "ac25", 40 },
	{ "ac26", "ac26", 40 },
	{ "ac27", "ac27", 40 },
	{ "ac28", "ac28", 40 },
	{ "ac29", "ac29", 40 },
	{ "ac30", "ac30", 40 },
	{ "ac31", "ac31", 40 },
};
static const C55RegInfo ar_ri[16] = {
	{ "ar0", "ar0", 16 },
	{ "ar1", "ar1", 16 },
	{ "ar2", "ar2", 16 },
	{ "ar3", "ar3", 16 },
	{ "ar4", "ar4", 16 },
	{ "ar5", "ar5", 16 },
	{ "ar6", "ar6", 16 },
	{ "ar7", "ar7", 16 },
	{ "ar8", "ar8", 16 },
	{ "ar9", "ar9", 16 },
	{ "ar10", "ar10", 16 },
	{ "ar11", "ar11", 16 },
	{ "ar12", "ar12", 16 },
	{ "ar13", "ar13", 16 },
	{ "ar14", "ar14", 16 },
	{ "ar15", "ar15", 16 },
};
// On C55x+ the extended auxiliary registers are 24-bit (24-bit flat data
// addressing); classic C55x keeps them 23-bit in its own table.
static const C55RegInfo xar_ri[16] = {
	{ "xar0", "xar0", 24 },
	{ "xar1", "xar1", 24 },
	{ "xar2", "xar2", 24 },
	{ "xar3", "xar3", 24 },
	{ "xar4", "xar4", 24 },
	{ "xar5", "xar5", 24 },
	{ "xar6", "xar6", 24 },
	{ "xar7", "xar7", 24 },
	{ "xar8", "xar8", 24 },
	{ "xar9", "xar9", 24 },
	{ "xar10", "xar10", 24 },
	{ "xar11", "xar11", 24 },
	{ "xar12", "xar12", 24 },
	{ "xar13", "xar13", 24 },
	{ "xar14", "xar14", 24 },
	{ "xar15", "xar15", 24 },
};
static const C55RegInfo t_ri[4] = {
	{ "t0", "t0", 16 },
	{ "t1", "t1", 16 },
	{ "t2", "t2", 16 },
	{ "t3", "t3", 16 },
};
static const C55RegInfo sp_ri[2] = { { "sp", "sp", 16 }, { "ssp", "ssp", 16 } };
static const C55RegInfo trn_ri[8] = {
	{ "trn0", "trn0", 16 }, { "trn1", "trn1", 16 }, { "trn2", "trn2", 16 }, { "trn3", "trn3", 16 },
	{ "trn4", "trn4", 16 }, { "trn5", "trn5", 16 }, { "trn6", "trn6", 16 }, { "trn7", "trn7", 16 }
};
static const C55RegInfo dp_ri[2] = { { "dp", "dp", 16 }, { "dph", "dph", 16 } };

// Special / status / loop / extended-pointer registers, indexed by their flat
// register-byte value (gr1 index). Gaps are NULL. Transcribed from TI dis55.
static const C55RegInfo special_ri[256] = {
	[56] = { "csr", "csr", 16 },
	[57] = { "rptc", "rptc", 16 },
	[58] = { "brc0", "brc0", 16 },
	[59] = { "brc1", "brc1", 16 },
	[62] = { "config", NULL, 16 },
	[63] = { "cpurev", NULL, 16 },
	[148] = { "xssp", NULL, 24 },
	[149] = { "xsp", NULL, 24 },
	[150] = { "xdp", NULL, 24 },
	[152] = { "rsa0", NULL, 16 },
	[153] = { "rsa1", NULL, 16 },
	[154] = { "rea0", NULL, 16 },
	[155] = { "rea1", NULL, 16 },
	[156] = { "dbgpaddr", NULL, 16 },
	[157] = { "dbgpdata", NULL, 16 },
	[159] = { "reta", NULL, 16 },
	[180] = { "xssp.h", NULL, 24 },
	[181] = { "xsp.h", NULL, 24 },
	[182] = { "xdp.h", NULL, 24 },
	[183] = { "pdp", "pdp", 16 },
	[184] = { "bsa01", "bsa01", 16 },
	[185] = { "bsa23", "bsa23", 16 },
	[186] = { "bsa45", "bsa45", 16 },
	[187] = { "bsa67", "bsa67", 16 },
	[188] = { "bsac", "bsac", 16 },
	[189] = { "bkc", "bkc", 16 },
	[190] = { "bk03", "bk03", 16 },
	[191] = { "bk47", "bk47", 16 },
	// st0_55 status-bit names, indexed [192 + bit position], for the bclr/bset
	// st0_<bit> forms (opcode 0x0a). The lift recovers the bit position from the
	// register index.
	[192] = { "st0_dp07", NULL, 16 },
	[193] = { "st0_dp08", NULL, 16 },
	[194] = { "st0_dp09", NULL, 16 },
	[195] = { "st0_dp10", NULL, 16 },
	[196] = { "st0_dp11", NULL, 16 },
	[197] = { "st0_dp12", NULL, 16 },
	[198] = { "st0_dp13", NULL, 16 },
	[199] = { "st0_dp14", NULL, 16 },
	[200] = { "st0_dp15", NULL, 16 },
	[201] = { "st0_acov1", NULL, 16 },
	[202] = { "st0_acov0", NULL, 16 },
	[203] = { "st0_carry", NULL, 16 },
	[204] = { "st0_tc2", NULL, 16 },
	[205] = { "st0_tc1", NULL, 16 },
	[206] = { "st0_acov3", NULL, 16 },
	[207] = { "st0_acov2", NULL, 16 },
	[224] = { "st0", NULL, 16 },
	[225] = { "st1", NULL, 16 },
	[226] = { "st2", NULL, 16 },
	[227] = { "st3", NULL, 16 },
	[228] = { "st0_55", "st0_55", 16 },
	[229] = { "st1_55", "st1_55", 16 },
	[231] = { "st3_55", "st3_55", 16 },
	[232] = { "ier0", NULL, 16 },
	[233] = { "ier1", NULL, 16 },
	[234] = { "ifr0", NULL, 16 },
	[235] = { "ifr1", NULL, 16 },
	[236] = { "dbier0", NULL, 16 },
	[237] = { "dbier1", NULL, 16 },
	[238] = { "ivpd", NULL, 16 },
	[239] = { "ivph", NULL, 16 },
	[240] = { "rsa0.h", NULL, 16 },
	[241] = { "rsa1.h", NULL, 16 },
	[242] = { "rea0.h", NULL, 16 },
	[243] = { "rea1.h", NULL, 16 },
	[244] = { "bios", NULL, 16 },
	[245] = { "brs1", "brs1", 16 },
	[246] = { "iir", NULL, 16 },
	[247] = { "ber", NULL, 16 },
	[248] = { "rsa0.l", NULL, 16 },
	[249] = { "rsa1.l", NULL, 16 },
	[250] = { "rea0.l", NULL, 16 },
	[251] = { "rea1.l", NULL, 16 },
	[252] = { "tsdr", NULL, 16 },
};

static const C55RegInfo *c55plus_reg_info(C55RegClass cls, ut8 num, C55SubReg sub) {
	(void)sub; // sub-field (.l/.h/.g) shows in the name via the formatter
	switch (cls) {
	case C55_RC_AC: return num < 32 ? &ac_ri[num] : NULL;
	case C55_RC_AR: return num < 16 ? &ar_ri[num] : NULL;
	case C55_RC_XAR: return num < 16 ? &xar_ri[num] : NULL;
	case C55_RC_T: return num < 4 ? &t_ri[num] : NULL;
	case C55_RC_SP: return num < 2 ? &sp_ri[num] : NULL;
	case C55_RC_DP: return num < 2 ? &dp_ri[num] : NULL;
	case C55_RC_SPECIAL: return special_ri[num].name ? &special_ri[num] : NULL;
	case C55_RC_TRN: return num < 8 ? &trn_ri[num] : NULL;
	default: return NULL;
	}
}

// The flat register byte (TI "register field 1"), full 0-255 decode transcribed
// from dis55. Structured classes (ac/ar/xar/t/sp/dp, with .h/.l/.g sub-fields)
// are returned as such; the status/loop/extended-pointer registers are returned
// as C55_RC_SPECIAL carrying the raw index. Unused indices yield C55_RC_NONE.
// NB: like dis55/th0rpe, ac16.g-ac31.g (208-223) are intentionally not decoded.
static void c55plus_gr1(ut8 idx, C55Reg *r) {
	r->cls = C55_RC_NONE;
	r->num = 0;
	r->sub = C55_SUB_NONE;
	if (idx < 32) {
		r->cls = C55_RC_AC;
		r->num = idx;
	} else if (idx < 48) {
		r->cls = C55_RC_AR;
		r->num = (ut8)(idx - 32);
	} else if (idx < 52) {
		r->cls = C55_RC_T;
		r->num = (ut8)(idx - 48);
	} else if (idx == 52) {
		r->cls = C55_RC_SP;
		r->num = 1;
	} else if (idx == 53) {
		r->cls = C55_RC_SP;
		r->num = 0;
	} else if (idx == 54) {
		r->cls = C55_RC_DP;
		r->num = 0;
	} else if (idx < 64) {
		r->cls = C55_RC_SPECIAL;
		r->num = idx; // 56-59,62,63 (55/60/61 -> NULL)
	} else if (idx < 96) {
		r->cls = C55_RC_AC;
		r->num = (ut8)(idx - 64);
		r->sub = C55_SUB_HI;
	} else if (idx < 128) {
		r->cls = C55_RC_AC;
		r->num = (ut8)(idx - 96);
		r->sub = C55_SUB_LO;
	} else if (idx < 144) {
		r->cls = C55_RC_XAR;
		r->num = (ut8)(idx - 128);
	} else if (idx < 160) {
		r->cls = C55_RC_SPECIAL;
		r->num = idx; // 148-150 xssp/xsp/xdp, 152-159 rsa/rea/...
	} else if (idx < 176) {
		r->cls = C55_RC_XAR;
		r->num = (ut8)(idx - 160);
		r->sub = C55_SUB_HI;
	} else if (idx < 192) {
		r->cls = C55_RC_SPECIAL;
		r->num = idx; // 180-191 xssp.h/pdp/bsa/bk...
	} else if (idx < 208) {
		r->cls = C55_RC_AC;
		r->num = (ut8)(idx - 192);
		r->sub = C55_SUB_GUARD; // ac0.g-ac15.g
	} else if (idx < 224) {
		; // 208-223 unused (ac16.g-ac31.g not decoded, matching dis55/th0rpe)
	} else {
		r->cls = C55_RC_SPECIAL;
		r->num = idx; // 224-252 st/ier/ifr/rsa.h/...
	}
}

static ut8 c55plus_reg_width(const C55ArchDesc *a, const C55Reg *r) {
	const C55RegInfo *ri = a->reg_info ? a->reg_info(r->cls, r->num, r->sub) : NULL;
	return ri ? ri->width : 16;
}

// mov source byte: low 7 bits select the register (gr1); bit 7 set => "<< #16".
// Extended (pointer-capable) register decode, shared by the mov destination
// (leading byte >= 0x80) and the mov source (when the destination selects the
// extended form). \p h is the operand byte masked to 7 bits. Leaves cls NONE
// for the encodings TI rejects (xar16..xar19 / xar23..xar31).
static void c55plus_xptr(ut8 h, C55Reg *out) {
	out->sub = C55_SUB_NONE;
	if (h & 0x20) {
		ut8 n = (ut8)(h & 0x1f);
		if (n < 16) {
			out->cls = C55_RC_XAR;
			out->num = n;
		} else if (n == 20) {
			out->cls = C55_RC_SPECIAL;
			out->num = 148; // xssp
		} else if (n == 21) {
			out->cls = C55_RC_SPECIAL;
			out->num = 149; // xsp
		} else if (n == 22) {
			out->cls = C55_RC_SPECIAL;
			out->num = 150; // xdp
		} else {
			out->cls = C55_RC_NONE;
			out->num = 0;
		}
	} else {
		out->cls = C55_RC_AC;
		out->num = (ut8)(h & 0x1f);
	}
}

static void c55plus_x_reg_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 b = (ut8)((bits >> d->lo) & 0xff);
	ut8 dst = (ut8)((bits >> 8) & 0xff); // byte1 selects regular vs extended form
	C55Reg r = { C55_RC_NONE, 0, C55_SUB_NONE };
	out->kind = C55_OP_REG;
	if (dst >= 0x80) {
		// extended (xar-destination) form: the source is pointer-capable too
		// and the high bit is part of the register select, not a << #16 flag.
		c55plus_xptr((ut8)(b & 0x7f), &r);
	} else {
		c55plus_gr1((ut8)(b & 0x7f), &r);
		if (b & 0x80) {
			out->sh_left = true;
			out->shamt = 16;
		}
	}
	out->reg = r;
	out->width = c55plus_reg_width(a, &out->reg);
}

// mov destination byte: < 0x80 uses gr1; >= 0x80 selects the pointer-capable set
// (bit 5 of the low 7 picks XAR / extended pointer over a plain accumulator).
static void c55plus_x_reg_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 b = (ut8)((bits >> d->lo) & 0xff);
	C55Reg r = { C55_RC_NONE, 0, C55_SUB_NONE };
	if (b < 0x80) {
		c55plus_gr1(b, &r);
	} else {
		c55plus_xptr((ut8)(b & 0x7f), &r);
	}
	out->kind = C55_OP_REG;
	out->reg = r;
	out->width = c55plus_reg_width(a, &r);
}

// A-unit register-register operand (opcode 0x72, "mar(WDAa op WDAb)"): a 6-bit
// WDA register field (bits[5:0] of the byte at \ref C55OpDesc.lo), decoded by
// c55plus_xptr (bit5 picks xar/xssp/xsp/xdp over an accumulator). The top bit
// of each operand byte selects the operation and is handled by the table match,
// not here. Shared by amov (MX), aadd (AX) and asub (SX).
static void c55plus_x_wda(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 b = (ut8)((bits >> d->lo) & 0x3f);
	out->kind = C55_OP_REG;
	c55plus_xptr(b, &out->reg);
	if (out->reg.cls == C55_RC_NONE) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// psh/pop register byte: gr1 decode, with full accumulators and full pointer
// registers (xar) rendered as dbl(...) (a 40-/32-bit double push/pop).
static void c55plus_x_reg_pshpop(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 b = (ut8)((bits >> d->lo) & 0xff);
	c55plus_gr1(b, &out->reg);
	out->kind = C55_OP_REG;
	// Double (40-/32-bit) push/pop is designated by the operand byte range, not the
	// resulting register class: 0x00-0x1f (accumulators) and 0x80-0x9f (full pointer
	// and extended-double registers) render as dbl(...).
	if (b < 0x20 || (b >= 0x80 && b < 0xa0)) {
		out->dbl = true;
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// call/branch target field: the raw offset, displayed as a 24-bit address
// (#0x00xxxx). The PC-relative resolution into an xref is done by the analysis.
static void c55plus_x_addr(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut64 mask = (d->width >= 32) ? 0xffffffffULL : (((ut64)1 << d->width) - 1);
	out->kind = C55_OP_IMM;
	out->imm = (bits >> d->lo) & mask;
	out->width = d->width;
	out->addr = true;
}

// Absolute 24-bit call/branch target (opcodes 0x9d call, ... ): the operand
// value is the destination address itself (24-bit program space), rendered as
// #0xNNNNNN, not a pc-relative displacement.
static void c55plus_x_addr24(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = (bits >> d->lo) & 0xffffff;
	out->width = 24;
	out->addr = true;
	out->abs_target = true;
}

// Condition-field register set (TI "register field 4"): 0-7 acN, 8-11 tN,
// 16-23 arN, 24-31 acN.l; 12-15 unused.
static void c55plus_cond_reg(ut8 idx5, C55Reg *r) {
	r->cls = C55_RC_NONE;
	r->num = 0;
	r->sub = C55_SUB_NONE;
	if (idx5 < 8) {
		r->cls = C55_RC_AC;
		r->num = idx5;
	} else if (idx5 < 12) {
		r->cls = C55_RC_T;
		r->num = (ut8)(idx5 - 8);
	} else if (idx5 >= 16 && idx5 < 24) {
		r->cls = C55_RC_AR;
		r->num = (ut8)(idx5 - 16);
	} else if (idx5 >= 24 && idx5 < 32) {
		r->cls = C55_RC_AC;
		r->num = (ut8)(idx5 - 24);
		r->sub = C55_SUB_LO;
	}
}

// Condition byte (bcc/xcc/...): either "reg <relop> #0" (register field 4 with a
// relop in the top bits, or an xar at 0xc0-0xdf) or a status-bit flag expression
// (0xe0-0xff). Reconstructed from th0rpe get_opers; verified against dis55.
static void c55plus_x_cond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	static const C55Relop relmap[6] = {
		C55_REL_EQ, C55_REL_NE, C55_REL_LT, C55_REL_GE, C55_REL_GT, C55_REL_LE
	};
	ut8 b = (ut8)((bits >> d->lo) & 0xff);
	out->kind = C55_OP_COND;
	out->imm = 0;
	if (b >= 0xe0) {
		out->cond_is_flag = true;
		out->cond_flag = (ut8)(b - 0xe0); // 0xee/0xef map to empty flag slots
		return;
	}
	ut8 oper_type = (ut8)(b >> 5);
	if (oper_type == 6) { // 0xc0-0xdf: xar comparison
		out->reg.cls = C55_RC_XAR;
		out->reg.num = (ut8)(b & 0x0f);
		out->relop = (((b >> 4) - 12) == 0) ? C55_REL_EQ : C55_REL_NE;
	} else { // 0x00-0xbf: register-field-4 comparison vs #0
		c55plus_cond_reg((ut8)(b & 0x1f), &out->reg);
		out->relop = relmap[oper_type];
	}
}

// Register-register long-branch condition (opcodes 0xda/0xdb): two gr1 registers
// Ra (byte1 & 0x7f) and Rb (byte2 & 0x7f) compared with a 2-bit relop split
// across byte1 bit 7 (high) and byte2 bit 7 (low): 0 ==, 1 !=, 2 <, 3 >=. Signed
// (0xda) vs unsigned (0xdb) is carried by uns_all (per table row), as for the
// reg-immediate forms. The 16-bit field passed in is byte1:byte2.
static void c55plus_x_cond_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	static const C55Relop relmap[4] = { C55_REL_EQ, C55_REL_NE, C55_REL_LT, C55_REL_GE };
	ut16 field = (ut16)((bits >> d->lo) & 0xffff);
	ut8 b1 = (ut8)(field >> 8);
	ut8 b2 = (ut8)(field & 0xff);
	out->kind = C55_OP_COND;
	out->cmp_to_reg = true;
	out->relop = relmap[((b1 & 0x80) ? 2 : 0) | ((b2 & 0x80) ? 1 : 0)];
	c55plus_gr1((ut8)(b1 & 0x7f), &out->reg); // Ra
	c55plus_gr1((ut8)(b2 & 0x7f), &out->index); // Rb
}

// Register-register compare condition (opcode 0xa4 CMPR_RR): Ra = gr1(byte1 &
// 0x7f), Rb = gr1(byte2 & 0x7f), 2-bit relop in byte3[3:2] (0 ==, 1 !=, 2 <,
// 3 >=). Signed (cmp) vs unsigned (cmpu) is the byte3[5] $ bit, carried by the
// instruction uns_all flag (set per table row), not decoded here.
static void c55plus_x_cmpcond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	static const C55Relop relmap[4] = { C55_REL_EQ, C55_REL_NE, C55_REL_LT, C55_REL_GE };
	ut8 b1 = (ut8)((bits >> 16) & 0xff);
	ut8 b2 = (ut8)((bits >> 8) & 0xff);
	ut8 b3 = (ut8)(bits & 0xff);
	out->kind = C55_OP_COND;
	out->cmp_to_reg = true;
	out->relop = relmap[(b3 >> 2) & 0x3];
	c55plus_gr1((ut8)(b1 & 0x7f), &out->reg); // Ra
	c55plus_gr1((ut8)(b2 & 0x7f), &out->index); // Rb
}

// TC status-flag destination of the 0xa4 compare: byte3 bit 0 selects tc1 (0)
// or tc2 (1); rendered/lifted via the shared cond-flag ids (tc1 = 4, tc2 = 5).
static void c55plus_x_tcflag(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)(4 + (bits & 0x1));
}

// or tc2 (1); byte1[7] negates it (!tcN). The shared cmpand/cmpor lift maps
// cond-flag ids 4/5 to tc1/tc2 and 20/21 to their negations.
static void c55plus_x_cmp_tcin(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 sel = (ut8)((bits >> 1) & 0x1); // byte3[1]
	ut8 neg = (ut8)((bits >> 23) & 0x1); // byte1[7]
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)((neg ? 20 : 4) + sel);
}

// compared to a 7-bit immediate. The 2-bit relop is split across byte1 bit 7
// (high) and byte2 bit 7 (low): 0 ==, 1 !=, 2 <, 3 >= (TI get_cmp_op order).
// Signed (0xdc, bcc) vs unsigned (0xdd, bccu) is carried by the instruction's
// uns_all flag (set per table row), not decoded here. The 16-bit field passed
// in is byte1:byte2.
static void c55plus_x_cond_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	static const C55Relop relmap[4] = { C55_REL_EQ, C55_REL_NE, C55_REL_LT, C55_REL_GE };
	ut16 field = (ut16)((bits >> d->lo) & 0xffff);
	ut8 b1 = (ut8)(field >> 8);
	ut8 b2 = (ut8)(field & 0xff);
	c55plus_gr1((ut8)(b1 & 0x7f), &out->reg);
	out->kind = C55_OP_COND;
	out->relop = relmap[((b1 & 0x80) ? 2 : 0) | ((b2 & 0x80) ? 1 : 0)];
	out->imm = (ut64)(b2 & 0x7f);
	out->cmp_imm = true;
}

// As c55plus_x_cond_imm, but for the upper-half immediate compare-and-branch
// (opcodes 0xde/0xdf): the 8-bit compare constant has its high bit implicitly
// set, covering the 0x80-0xff range that the 0xdc/0xdd 7-bit forms cannot.
static void c55plus_x_cond_imm_hi(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55plus_x_cond_imm(a, bits, d, out);
	if (out->kind == C55_OP_COND) {
		out->imm |= 0x80;
	}
}

static const char *c55plus_mnemonic(ut16 id) {
	return tms320c55x_insn_name((TMS320C55InsID)id);
}

// id -> RzAnalysisOp type, matching the legacy byte-driven analyzer so the
// analysis path can be served from the shared decode for the ported opcodes.
static ut32 c55plus_op_type(ut16 id) {
	switch ((TMS320C55InsID)id) {
	case TMS320C55_INS_NOP:
	case TMS320C55_INS_NOP_16:
	case TMS320C55_INS_IDLE: return RZ_ANALYSIS_OP_TYPE_NOP;
	case TMS320C55_INS_RETCC: return RZ_ANALYSIS_OP_TYPE_CRET;
	case TMS320C55_INS_RET:
	case TMS320C55_INS_RETI: return RZ_ANALYSIS_OP_TYPE_RET;
	case TMS320C55_INS_RESET: return RZ_ANALYSIS_OP_TYPE_TRAP;
	case TMS320C55_INS_MOV: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_COPY: return RZ_ANALYSIS_OP_TYPE_MOV;
	// A-unit address arithmetic: amov/amar/asub load or adjust an address (LEA),
	// aadd is an address-add (ADD). The asub IL comes from the shared AREG_SUB
	// lift; its analysis type matches the legacy decoder (LEA).
	case TMS320C55_INS_AMOV: return RZ_ANALYSIS_OP_TYPE_LEA;
	case TMS320C55_INS_AMAR: return RZ_ANALYSIS_OP_TYPE_LEA;
	case TMS320C55_INS_ASUB: return RZ_ANALYSIS_OP_TYPE_LEA;
	case TMS320C55_INS_AADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_MPYK: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MACK: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_XCC: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_XCCPART: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_ADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_SUB: return RZ_ANALYSIS_OP_TYPE_SUB;
	// neg/min/max register ops (opcode 0x76 and the 0x34/0x2e/0x30 forms): neg is
	// a subtract-from-zero; min/max are modelled as compares, matching the legacy
	// analysis. abs has no dedicated op-type (left as the default).
	case TMS320C55_INS_NEG: return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_MAX: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_MIN: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_AND: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_OR: return RZ_ANALYSIS_OP_TYPE_OR;
	case TMS320C55_INS_XOR: return RZ_ANALYSIS_OP_TYPE_XOR;
	case TMS320C55_INS_SFTL: return RZ_ANALYSIS_OP_TYPE_SHL;
	case TMS320C55_INS_SFTS: return RZ_ANALYSIS_OP_TYPE_SHL;
	case TMS320C55_INS_SFTSC: return RZ_ANALYSIS_OP_TYPE_SHL;
	case TMS320C55_INS_RPT: return RZ_ANALYSIS_OP_TYPE_REP;
	case TMS320C55_INS_RPTADD: return RZ_ANALYSIS_OP_TYPE_REP;
	case TMS320C55_INS_RPTSUB: return RZ_ANALYSIS_OP_TYPE_REP;
	case TMS320C55_INS_RPTB: return RZ_ANALYSIS_OP_TYPE_REP;
	case TMS320C55_INS_RPTBLOCAL: return RZ_ANALYSIS_OP_TYPE_REP;
	case TMS320C55_INS_RPTCC: return RZ_ANALYSIS_OP_TYPE_REP;
	// round / satr / sat / circ: control / rounding moves (no branch effect).
	case TMS320C55_INS_ROUND: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_SAT: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_CIRC: return RZ_ANALYSIS_OP_TYPE_MOV;
	// software interrupt / trap vectors.
	case TMS320C55_INS_INTR: return RZ_ANALYSIS_OP_TYPE_SWI;
	case TMS320C55_INS_TRAP: return RZ_ANALYSIS_OP_TYPE_TRAP;
	case TMS320C55_INS_ESTOP: return RZ_ANALYSIS_OP_TYPE_TRAP;
	case TMS320C55_INS_ECOPR: return RZ_ANALYSIS_OP_TYPE_TRAP;
	case TMS320C55_INS_SIM_TRIG: return RZ_ANALYSIS_OP_TYPE_TRAP;
	// register exchange.
	case TMS320C55_INS_SWAP: return RZ_ANALYSIS_OP_TYPE_XCHG;
	// rotate through carry.
	case TMS320C55_INS_ROL: return RZ_ANALYSIS_OP_TYPE_ROL;
	case TMS320C55_INS_ROR: return RZ_ANALYSIS_OP_TYPE_ROR;
	// exponent (leading-bit count).
	case TMS320C55_INS_EXP: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BCNT: return RZ_ANALYSIS_OP_TYPE_MOV;
	// conditional shift.
	case TMS320C55_INS_SFTCC: return RZ_ANALYSIS_OP_TYPE_SHL;
	// mantissa / negated-exponent dual helper.
	case TMS320C55_INS_MANT: return RZ_ANALYSIS_OP_TYPE_MOV;
	// dual-data-memory multiply family.
	case TMS320C55_INS_MPYM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MACM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MASM: return RZ_ANALYSIS_OP_TYPE_MUL;
	// register multiply family.
	case TMS320C55_INS_MPY: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MAC: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MAS: return RZ_ANALYSIS_OP_TYPE_MUL;
	// constant-coefficient memory multiply.
	case TMS320C55_INS_MPYMK: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_MACMK: return RZ_ANALYSIS_OP_TYPE_MUL;
	// memory squaring multiply.
	case TMS320C55_INS_SQRM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SQAM: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SQSM: return RZ_ANALYSIS_OP_TYPE_MUL;
	// dual compare-and-select-difference (Viterbi) ops.
	case TMS320C55_INS_MAXDIFF: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_MINDIFF: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_DMAXDIFF: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_DMINDIFF: return RZ_ANALYSIS_OP_TYPE_CMP;
	// dual-data-memory distance / LMS primitives.
	case TMS320C55_INS_ABDST: return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_SQDST: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_LMS: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_LMSF: return RZ_ANALYSIS_OP_TYPE_MUL;
	// FIR symmetric / antisymmetric primitives.
	case TMS320C55_INS_FIRSADD: return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_FIRSSUB: return RZ_ANALYSIS_OP_TYPE_MUL;
	// dual-access subtract-add.
	case TMS320C55_INS_SUBADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	// conditional subtract.
	case TMS320C55_INS_SUBC: return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_ADDSUBCC: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_ADDSUB2CC: return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_CMP: return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_NOT: return RZ_ANALYSIS_OP_TYPE_NOT;
	case TMS320C55_INS_BFXTR: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BFXPA: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BTST: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTCLR: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTNOT: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BAND: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTP: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BTSTSET: return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_BCLR: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BSET: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_BNOT: return RZ_ANALYSIS_OP_TYPE_XOR;
	case TMS320C55_INS_PSH: return RZ_ANALYSIS_OP_TYPE_PUSH;
	case TMS320C55_INS_PSHBOTH: return RZ_ANALYSIS_OP_TYPE_PUSH;
	case TMS320C55_INS_POPBOTH: return RZ_ANALYSIS_OP_TYPE_POP;
	case TMS320C55_INS_DELAY: return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_POP: return RZ_ANALYSIS_OP_TYPE_POP;
	case TMS320C55_INS_CALL: return RZ_ANALYSIS_OP_TYPE_CALL;
	case TMS320C55_INS_CALLCC: return RZ_ANALYSIS_OP_TYPE_CCALL;
	// b: the base type is the register-indirect UJMP; c55_effective_type
	// refines it to a direct JMP when the operand is an immediate target.
	case TMS320C55_INS_B: return RZ_ANALYSIS_OP_TYPE_UJMP;
	case TMS320C55_INS_BCC: return RZ_ANALYSIS_OP_TYPE_CJMP;
	default: return RZ_ANALYSIS_OP_TYPE_NULL;
	}
}

static ut8 c55plus_insn_len(const ut8 *buf, int len) {
	return (len > 0) ? (ut8)get_ins_len(buf[0]) : 0;
}

// gr1 of the operand byte's low 7 bits: the arithmetic/logic reg-reg operands
// strip the high bit (which selects the operation), with no shift or extended form.
static void c55plus_x_gr7(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> d->lo) & 0x7f), &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}

// 16-bit immediate operand (rendered hex/unsigned, like the legacy decoder).
static void c55plus_x_imm16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = (bits >> d->lo) & 0xffff;
	out->width = 16;
}

// rptblocal #l8 (opcode 0x6e, 3 bytes): local block-repeat with the 8-bit block-
// end label in byte2 (byte1 unused), rendered as a zero-padded 24-bit address
// (#0x0000NN), mirroring the 0x6f rptb. Lifted to a nop, as the legacy decoder
// does for the repeat op type.
static void c55plus_x_rptblocal_lbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xff; // byte2
	out->width = 24;
	out->addr = true;
}

// rptb #l16 (opcode 0x6f, 3 bytes): block-repeat with the 16-bit block-end label
// in bytes 1:2, rendered as a zero-padded 24-bit address (#0x0000NN). Lifted to a
// nop (the block-repeat control has no data effect of its own), as the legacy
// decoder does for the repeat op type.
static void c55plus_x_rptb_lbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff; // byte1:byte2
	out->width = 24;
	out->addr = true;
}

// 6-bit shift count S6 (the sfts/sftl/shift-ALU forms): rendered as the raw
// 6-bit field (#0x..); the lifter sign-extends it from the 6-bit width to pick
// the shift direction and magnitude.
static void c55plus_x_shift6(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = (bits >> d->lo) & 0x3f;
	out->width = 6;
	out->imm_signed = false;
}

// 6-bit shift count rendered joined to the preceding operand as "<< #S6" (the
// "Rb << #S6" source of the shift-ALU forms). The lifter takes it as an
// unsigned 8-bit left-shift amount.
static void c55plus_x_shift6_shl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55plus_x_shift6(a, bits, d, out);
	out->shl_join = true;
}

// 4-bit immediate k4 of the 0x7b register-short forms (mov/add/sub #k4, Ra):
// byte2[3:0], zero-extended.
static void c55plus_x_k4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = (bits >> d->lo) & 0xf;
	out->width = 4;
}

// Negative 4-bit immediate of the 0x7b "mov -#k4, Ra" form: the magnitude is
// byte2[3:0]; rendered with the minus sign and left unlifted (as the legacy).
static void c55plus_x_negk4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 k = (ut8)((bits >> d->lo) & 0xf);
	out->kind = C55_OP_IMM;
	out->imm = (ut64)(-(st64)k);
	out->imm_signed = true;
	out->neg_imm = true;
	out->width = 4;
}

// Decode the single data-memory (Smem) addressing mode shared by the C55x+
// register-indirect group.
//
// byte1 (buf[1]) carries the base AR (bits[3:0]) and a 4-bit sub-field
// (bits[7:4]); byte2's top two bits (buf[2] bits[7:6]) select the mode group.
// Only the byte2[7:6]==00 register-modify matrix and plain indirect
// (byte2[7:6]==10 with a zero offset) are decoded here; the indexed short(#K),
// bit-reverse, scaled, xar15, DP-direct and SP-relative forms still need
// formatter support, so the helper returns false and the caller signals
// C55_OP_INVALID to fall back to the legacy decoder.
static bool c55plus_smem_amode(ut8 b_ar, ut8 b_mode, C55Operand *out) {
	ut8 grp = (ut8)((b_mode >> 6) & 3);
	out->kind = C55_OP_MEM;
	out->access = 16;
	c55plus_gr1((ut8)(32 + (b_ar & 0x0f)), &out->reg); // base ARn
	if (grp == 2) {
		// byte2[7:6]==10: byte1[7:4] is a const offset; 0 -> indirect,
		// non-zero -> indexed short(#K).
		ut8 k = (ut8)((b_ar >> 4) & 0x0f);
		if (k) {
			out->amode = C55_AM_INDEXED;
			out->disp = k;
		} else {
			out->amode = C55_AM_INDIRECT;
		}
		return true;
	}
	if (grp == 1) {
		// byte2[7:6]==01: the bit-reverse / scaled / extended addressing group.
		// byte1[7:4] selects the sub-mode (byte1[3:0] is the base ARn). The
		// const-index sub-modes take a 2-byte extension, filled by the decoder.
		ut8 sub = (ut8)((b_ar >> 4) & 0x0f);
		switch (sub) {
		case 0: // *(arN-t0b) reverse-carry decrement
			out->amode = C55_AM_BITREV_SUB;
			c55plus_gr1(48, &out->index); // t0
			return true;
		case 1: // *(arN+t0b) reverse-carry increment
			out->amode = C55_AM_BITREV;
			c55plus_gr1(48, &out->index); // t0
			return true;
		case 2: // *arN(t0<<#1)
		case 3: // *arN(t1<<#1)
			out->amode = C55_AM_IDXSCALE;
			c55plus_gr1((ut8)(48 + (sub - 2)), &out->index);
			return true;
		case 7: // *arN(xar15)
			out->amode = C55_AM_XAR15;
			return true;
		case 8: out->amode = C55_AM_CONST_IDX; return true; // *arN(#K16)
		case 9: out->amode = C55_AM_CONST_IDX_PRE; return true; // *+arN(#K16)
		case 0xe: // *(#k) long absolute (3-byte / 24-bit extension)
			out->amode = C55_AM_ABSOLUTE;
			out->abs_addr = C55_ABS_EXT;
			out->reg.cls = C55_RC_NONE;
			return true;
		default:
			// a (abs16) / b (port) / c,d (24-bit const-index) and the reserved
			// 4/5/6/f: not represented here yet.
			return false;
		}
	}
	if (grp != 0) { // 11 (direct / sp / mmap)
		// byte2[7:6]==11: SP-relative direct or memory-mapped. byte1[7]==1 is
		// *sp(#k) with byte1[6:0] the offset; byte1[7]==0 is the @#k data-page
		// direct form with byte1[6:0] the address.
		if (b_ar & 0x80) {
			out->amode = C55_AM_INDEXED;
			out->reg.cls = C55_RC_SP;
			out->reg.num = 0;
			out->disp = (ut8)(b_ar & 0x7f);
			return true;
		}
		out->amode = C55_AM_DIRECT;
		out->disp = (ut8)(b_ar & 0x7f);
		return true;
	}
	// byte2[7:6]==00: register-modify matrix, sub = byte1[7:4].
	ut8 sub = (ut8)((b_ar >> 4) & 0x0f);
	ut8 op2 = (ut8)((sub >> 1) & 3); // sub[2:1] selects the operation
	ut8 tidx = (ut8)(((sub & 8) >> 2) | (sub & 1)); // 0->t0,1->t1,2->t2,3->t3
	switch (op2) {
	case 0: // no index: pre/post increment/decrement
		out->amode = (sub & 8) ? ((sub & 1) ? C55_AM_PREINC : C55_AM_PREDEC)
				       : ((sub & 1) ? C55_AM_POSTINC : C55_AM_POSTDEC);
		break;
	case 1:
		out->amode = C55_AM_IDXREG;
		c55plus_gr1((ut8)(48 + tidx), &out->index);
		break;
	case 2:
		out->amode = C55_AM_POSTSUB;
		c55plus_gr1((ut8)(48 + tidx), &out->index);
		break;
	default:
		out->amode = C55_AM_POSTADD;
		c55plus_gr1((ut8)(48 + tidx), &out->index);
		break;
	}
	return true;
}

// Smem source for mov Smem, ACx (opcode 0x58): byte2 bit5 is the uns qualifier,
// which the formatter cannot render yet, so it forces a legacy fallback.
static void c55plus_x_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // buf[1]
	ut8 b_mode = (ut8)(bits & 0xff); // buf[2]
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if ((b_mode >> 5) & 1) { // uns() qualifier: zero-extend on load
		out->uns = true;
	}
}

// Smem destination for mov ACx.h/.l, Smem (opcode 0x51). Here byte2 bit5
// selects the accumulator half rather than the uns qualifier, so the address
// is decoded regardless of it (the half is rendered by c55plus_x_ac_part).
static void c55plus_x_smem_dest(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff);
	ut8 b_mode = (ut8)(bits & 0xff);
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
	}
}

// Accumulator destination for the Smem load group: ACx where x = byte2[4:0].
static void c55plus_x_smem_ac(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}

// Accumulator-half source for the Smem store group: ACx.h (byte2[5]==0) or
// ACx.l (byte2[5]==1), x = byte2[4:0] (gr1 high/low sub-register slots).
static void c55plus_x_ac_part(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_mode = (ut8)(bits & 0xff);
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((b_mode & 0x1f) + (((b_mode >> 5) & 1) ? 96 : 64)), &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}

// Byte-access memory operand of "mov byte(*Smem), ACx" / "mov ACx, byte(*Smem)"
// (opcode 0x8a, base 4 bytes). The addressing is the standard Smem layout
// (byte1 = base ARn + offset/sub field, byte2[7:6] = group), decoded by
// c55plus_smem_amode; this form marks an 8-bit byte() access (byte_sel 3).
// byte3[5] is the uns() qualifier on a load. The high_byte()/low_byte() variants
// (byte3[7]==0) are handled by separate disasm-only rows.
// Shared addressing decode for the 0x5b/0x5c/0x8a accumulator load/store forms:
// the standard Smem layout (byte1 + byte2[7:6]) plus the absolute *(#addr) form
// (byte2[7:6]==01 with byte1==0xe0; the 24-bit address follows as a 3-byte
// extension) and the SP-relative *sp(#k) form (byte2[7:6]==11 with byte1[7]==1).
// Returns false (-> legacy fallback) for the DP-direct and other modes
// c55plus_smem_amode does not represent.
static bool c55plus_mem_addr(ut8 b_ar, ut8 b_mode, C55Operand *out) {
	ut8 grp = (ut8)((b_mode >> 6) & 3);
	if (grp == 1 && b_ar == 0xe0) {
		out->kind = C55_OP_MEM;
		out->amode = C55_AM_ABSOLUTE;
		out->abs_addr = C55_ABS_EXT;
		return true;
	}
	if (grp == 1) {
		// *arN(#K16): long const-index; the 16-bit offset follows as a 2-byte
		// extension (filled by the decoder). Base ARn is byte1[3:0].
		out->kind = C55_OP_MEM;
		out->amode = C55_AM_CONST_IDX;
		c55plus_gr1((ut8)(32 + (b_ar & 0x0f)), &out->reg);
		return true;
	}
	if (grp == 3 && ((b_ar >> 7) & 1)) {
		out->kind = C55_OP_MEM;
		out->amode = C55_AM_INDEXED;
		c55plus_gr1(53, &out->reg); // sp
		out->disp = (ut8)(b_ar & 0x7f);
		return true;
	}
	return c55plus_smem_amode(b_ar, b_mode, out);
}

static void c55plus_x_byte_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // buf[1]
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // buf[2]
	ut8 b_op = (ut8)(bits & 0xff); // buf[3]
	if (!c55plus_mem_addr(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->access = 8;
	out->byte_sel = 3; // plain byte()
	if (((b_op >> 6) & 3) == 3 && ((b_op >> 5) & 1)) {
		out->uns = true; // uns() byte load
	}
}

// Register operand of the 0x8a byte-access mov: the register number is
// byte2[4:0] (the low nibble plus the +16 bank bit), and byte3[1:0] selects the
// sub-form (0 = whole accumulator, 1 = ARn, 2 = ACx.h, 3 = ACx.l).
static void c55plus_x_byte_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // buf[2]
	ut8 b_op = (ut8)(bits & 0xff); // buf[3]
	ut8 num = (ut8)(b_mode & 0x1f); // 0..31
	out->kind = C55_OP_REG;
	switch (b_op & 3) {
	case 0: // whole accumulator ACn
		c55plus_gr1(num, &out->reg);
		break;
	case 1: // ARn (low 4 bits select ar0-15)
		c55plus_gr1((ut8)(32 + (num & 0x0f)), &out->reg);
		break;
	case 2: // ACn.h
		c55plus_gr1((ut8)(64 + num), &out->reg);
		break;
	default: // ACn.l
		c55plus_gr1((ut8)(96 + num), &out->reg);
		break;
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// Word (16-bit) memory source of "mov *Smem, ACx.l" (opcode 0x5b, base 3 bytes):
// the standard Smem / absolute / SP-relative addressing, a 16-bit access loaded
// into the low half of an accumulator.
static void c55plus_x_word_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // buf[1]
	ut8 b_mode = (ut8)(bits & 0xff); // buf[2]
	if (!c55plus_mem_addr(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->access = 16;
}

// Double-word (32-bit) memory source of "mov dbl(*Smem), ACx" (opcode 0x5c,
// base 3 bytes): the same addressing, a 32-bit dbl() access sign-extended into a
// whole accumulator.
static void c55plus_x_dbl_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // buf[1]
	ut8 b_mode = (ut8)(bits & 0xff); // buf[2]
	if (!c55plus_mem_addr(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->access = 32;
	out->dbl = true;
}

// Byte() memory destination of "mov #imm, byte(*Smem)" (opcode 0x4c, base 3
// bytes): the same Smem / absolute / SP-relative addressing as the load forms,
// an 8-bit byte() access. The const-index addressing supplies its 16-bit offset
// as a 2-byte extension (handled by the decoder).
static void c55plus_x_byte_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // buf[1]
	ut8 b_mode = (ut8)(bits & 0xff); // buf[2]
	if (!c55plus_mem_addr(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->access = 8;
	out->byte_sel = 3; // plain byte()
}

// 6-bit immediate source in byte2[5:0] of "mov #imm, byte(*Smem)" (opcode 0x4c).
static void c55plus_x_imm6(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0x3f;
	out->width = 16;
}

// The 0x4d/0x4e/0x4f immediate byte stores reuse byte2[5:0] for the low six bits
// of the constant; the two high bits come from the opcode (0x4d -> 0x40, 0x4e ->
// 0x80, 0x4f -> 0xc0), so the four 0x4c-0x4f opcodes together cover the full
// 8-bit immediate range.
static void c55plus_x_imm6_40(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55plus_x_imm6(a, bits, d, out);
	out->imm |= 0x40;
}
static void c55plus_x_imm6_80(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55plus_x_imm6(a, bits, d, out);
	out->imm |= 0x80;
}
static void c55plus_x_imm6_c0(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c55plus_x_imm6(a, bits, d, out);
	out->imm |= 0xc0;
}

// A-unit pointer register in byte1[6:0] of the amov/asub #k16 forms (opcode
// 0xae): 0x00-0x0f select AR0-15, 0x10-0x13 select T0-3. Other encodings are
// special registers the shared lifter does not model and fall back to legacy.
// A-unit pointer register in byte1[4:0] of the amov/aadd/asub #k16 forms (opcode
// 0xae, the ARn/Tx register-type rows): 0x00-0x0f select AR0-15, 0x10-0x13 select
// T0-3. Other encodings are special registers the shared lifter does not model
// and fall back to legacy.
static void c55plus_x_areg16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 r = (ut8)((bits >> 16) & 0x1f); // byte1[4:0]
	out->kind = C55_OP_REG;
	if (r < 0x10) {
		c55plus_gr1((ut8)(32 + r), &out->reg); // ar0-15
	} else if (r < 0x14) {
		c55plus_gr1((ut8)(48 + (r - 0x10)), &out->reg); // t0-3
	} else {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// xar register in byte1[3:0] of the 0xae xar-type rows (amov/aadd/asub #k16).
static void c55plus_x_xar16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(128 + ((bits >> 16) & 0x0f)), &out->reg); // xar0-15
	out->width = c55plus_reg_width(a, &out->reg);
}

// 16-bit immediate in byte2:byte3 of the 0xae amov/asub forms.
static void c55plus_x_k16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff;
	out->width = 16;
}

// xar destination in byte1[3:0] of the 0xd2 amov/asub #k24 forms.
static void c55plus_x_xar_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(128 + ((bits >> 24) & 0x0f)), &out->reg); // byte1[3:0] -> xar0-15
	out->width = c55plus_reg_width(a, &out->reg);
}

// 24-bit immediate in byte2:byte3:byte4 of the 0xd2 amov/asub forms.
static void c55plus_x_k24(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffffff;
	out->width = 24;
}

// sp destination and 8-bit immediate of "aadd #k8, sp" (opcode 0x0c).
static void c55plus_x_sp(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1(53, &out->reg); // sp
	out->width = c55plus_reg_width(a, &out->reg);
}

// Absolute *(#addr) memory operand with the 24-bit byte address inline in
// bytes 2-4 (opcode 0xd0 register stores). The access width distinguishes the
// double-word and word forms.
static void c55plus_x_abs_dbl(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_MEM;
	out->amode = C55_AM_ABSOLUTE;
	out->abs_addr = bits & 0xffffff;
	out->access = 32;
	out->dbl = true;
}

static void c55plus_x_abs_word(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_MEM;
	out->amode = C55_AM_ABSOLUTE;
	out->abs_addr = bits & 0xffffff;
	out->access = 16;
}

// 16-bit register source in byte1[5:0] of the 0xd0 word store. The byte1[7:5]==001
// row covers AR0-15 (0x20-0x2F) and T0-3 (0x30-0x33) (plus SP/DP); decode the full
// 6-bit field through gr1 instead of forcing AR, so e.g. 0x30 is T0 not AR0.
static void c55plus_x_ar_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x3f), &out->reg); // byte1[5:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// Whole-accumulator / xar / accumulator-half source in byte1[4:0] of the 0xd0
// register stores (the register type is fixed per row).
static void c55plus_x_acc_b1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // ac0-31
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_xar_b1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(128 + ((bits >> 24) & 0x0f)), &out->reg); // xar0-15
	out->width = c55plus_reg_width(a, &out->reg);
}

// Accumulator half in byte1[4:0] of the 0xd0 ACx.h / ACx.l word store (the half
// is fixed per row by the .hi flag passed through C55OpDesc).
static void c55plus_x_acc_hi_b1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(64 + ((bits >> 24) & 0x1f)), &out->reg); // ac.h
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_acc_lo_b1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(96 + ((bits >> 24) & 0x1f)), &out->reg); // ac.l
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_k8(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xff;
	out->width = 16;
}

// Accumulator branch target in byte1[4:0] of "b ACx" / "call ACx" (opcode 0x02):
// the 24-bit jump address is held in the (whole) accumulator.
static void c55plus_x_acc_b1lo(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte1[4:0] -> ac0-31
	out->width = c55plus_reg_width(a, &out->reg);
}

// The optional "|| local()" parallel qualifier of the b/call ACx forms (opcode
// 0x02, byte1[6]); rendered after the register, joined by " || ". Absent (no
// operand emitted) when the bit is clear.
static void c55plus_x_b1_local(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	if ((bits >> 6) & 1) { // byte1[6]
		out->kind = C55_OP_IMM; // inert; rendered verbatim via raw
		out->raw = "local()";
		out->qual_join = true;
	} else {
		out->kind = C55_OP_NONE;
	}
}
// The optional "|| far()" parallel qualifier (opcode 0x02, byte1[5]).
static void c55plus_x_b1_far(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	if ((bits >> 5) & 1) { // byte1[5]
		out->kind = C55_OP_IMM; // inert; rendered verbatim via raw
		out->raw = "far()";
		out->qual_join = true;
	} else {
		out->kind = C55_OP_NONE;
	}
}

// Multiply-by-constant family (opcodes 0xc7 5-byte / 0xee 6-byte). Field layout
// of the packed instruction word:
//   byte1[4:0] dst ACx, byte1[6:5] selects the rounding (r) / fractional (f)
//     variant (decoded by the shared mods mechanism);
//   byte2[7] selects mack (1) over mpyk (0); byte2[4:0] the mack accumulate ACx;
//   byte3 the source: byte3[4:0] ACx, byte3[6:5] the sub-register (0 whole,
//     2 .h, 3 .l);
//   the trailing byte(s) the unsigned constant.
// The k8 immediate of the 5-byte 0xc7 form (byte4).
static void c55plus_x_mpyk_imm8(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xff;
	out->width = 16;
}

// The k16 immediate of the 6-byte 0xee form (byte4:byte5).
static void c55plus_x_mpyk_imm16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff;
	out->width = 16;
}

// The source register (byte3): ACx whole / .h / .l.
static void c55plus_x_mpyk_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x7f), &out->reg); // byte3[6:0]: ac / ac.h / ac.l / Tx / special
	out->width = c55plus_reg_width(a, &out->reg);
}

// The destination accumulator (byte1[4:0]).
static void c55plus_x_mpyk_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte1[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// The mack accumulate accumulator (byte2[4:0]).
static void c55plus_x_mpyk_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// The 6-byte 0xee form has the same fields shifted up one byte: dst byte1[4:0]
// at bits 36:32, src byte3 at bits 23:16, mack accumulate byte2[4:0] at bits
// 28:24, and the 16-bit immediate in byte4:byte5.
static void c55plus_x_mpyk6_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x7f), &out->reg); // byte3[6:0]: ac / ac.h / ac.l / Tx / special
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_mpyk6_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 32) & 0x1f), &out->reg); // byte1[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_mpyk6_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// Dual-data-memory (Xmem/Ymem) register-modify operand of the 0xc8 multiply
// family. The operand byte carries the base ARn in bits [3:0] and a 3-bit
// addressing mode in bits [6:4]: 0 *arN-, 1 *arN+, 2 *arN(t0), 3 *arN, 4
// *(arN-t0), 5 *(arN-t1), 6 *(arN+t0), 7 *(arN+t1). The MAC lift promotes the
// ARn base to its XARn pointer when forming the address. `uns` marks an unsigned
// operand (the uns() wrapper).
static void c55plus_x_mac_mem(const C55ArchDesc *a, ut8 ab, bool uns, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_MEM;
	out->access = 16;
	c55plus_gr1((ut8)(32 + (ab & 0x0f)), &out->reg); // base ARn
	out->uns = uns;
	switch ((ab >> 4) & 0x7) {
	case 0: out->amode = C55_AM_POSTDEC; break;
	case 1: out->amode = C55_AM_POSTINC; break;
	case 2:
		out->amode = C55_AM_IDXREG;
		c55plus_gr1(48, &out->index);
		break; // t0
	case 3: out->amode = C55_AM_INDIRECT; break;
	case 4:
		out->amode = C55_AM_POSTSUB;
		c55plus_gr1(48, &out->index);
		break; // t0
	case 5:
		out->amode = C55_AM_POSTSUB;
		c55plus_gr1(49, &out->index);
		break; // t1
	case 6:
		out->amode = C55_AM_POSTADD;
		c55plus_gr1(48, &out->index);
		break; // t0
	default:
		out->amode = C55_AM_POSTADD;
		c55plus_gr1(49, &out->index);
		break; // t1
	}
}
// Xmem of the 0xc8 multiply family: byte1[6:4] mode, byte1[3:0] ARn; byte2[5]
// is the Xmem uns() bit.
static void c55plus_x_mac_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 24) & 0x7f), ((bits >> 21) & 1) != 0, out);
}
// Ymem of the 0xc8 multiply family: byte3[6:4] mode, byte3[3:0] ARn; byte4[5]
// is the Ymem uns() bit.
static void c55plus_x_mac_ymem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 8) & 0x7f), ((bits >> 5) & 1) != 0, out);
}
// ACy destination of the 0xc8 multiply family: byte2[4:0].
static void c55plus_x_mac_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
// ACx accumulator source of the accumulating 0xc8 forms (macm / masm): byte4[4:0].
static void c55plus_x_mac_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte4[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// Register multiply family (opcode 0xaa, 4 bytes): mpy / mac / mas SRC1, SRC2,
// ACdst (and the round / fractional variants mpyr / macr / macf / ...). SRC1 is
// gr1(byte2[6:0]); SRC2 is gr1(byte3[6:0]) with byte3[7] the uns() wrapper;
// ACdst is ac(byte1[4:0]). The operation is selected by (byte1[7], byte2[7]):
// (0,0) mpy, (0,1) mac, (1,0) mas; the (1,1) four-operand form stays on the
// legacy decoder. byte1[5] is the round (r) flag and byte1[6] the fractional (f)
// flag, decoded through the shared .mods packing.
static void c55plus_x_macr_src1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x7f), &out->reg); // byte2[6:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_macr_src2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x7f), &out->reg); // byte3[6:0]
	out->width = c55plus_reg_width(a, &out->reg);
	out->uns = (bits & 0x80) != 0; // byte3[7]
}
static void c55plus_x_macr_acdst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte1[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// mov [rnd]([uns](*Smem) << Tx), ACx (opcode 0xb4, byte3[6]==1, 5 bytes): load a
// data-memory word shifted left by a register amount into an accumulator. The
// Smem is byte1:byte2 (the shared register-modify / indexed decode), the shift
// register is gr1(byte4[6:0]) rendered as " << <reg>", byte3[5] is the uns()
// wrapper and byte2[5] the rnd() wrapper. The accumulator destination is
// byte2[4:0]. (The byte3[6]==0 store forms and saturating variants stay on the
// legacy decoder.)
// mant ACa, ACb :: nexp ACa, ACc (opcode 0xa9, byte1[7]==0 && byte2[7]==1, 4
// bytes): the dual mantissa / negated-exponent helper. ops[0] is the shared ACa =
// ac(byte3[4:0]), ops[1] is ACb = ac(byte2[4:0]), ops[2] is ACc = gr1(byte1[6:0]).
// The custom "mant ... :: nexp ..." rendering is keyed on the mant_nexp flag.
// maxdiff / mindiff / dmaxdiff / dmindiff ACc, ACd, ACa, ACb, [pair(]trnN[)]
// (opcode 0xd4, 5 bytes): the dual compare-and-select-difference (Viterbi) ops.
// ops [0]=ACc (byte3[4:0]), [1]=ACd (byte4[4:0]), [2]=ACa (byte1[4:0]),
// [3]=ACb (byte2[4:0]), [4]=trn (byte4[7:5] ^ 6). byte1[7] selects the d-variant
// (bare trn) and byte2[7] the min-variant. Rendered via the diff_form flag.
// abdst / lms / lmsf / sqdst Xmem, Ymem, ACx, ACy (opcode 0xce, 5 bytes): the
// dual-data-memory distance / LMS primitives. Xmem is byte1 (the shared dual-mem
// register-modify matrix), Ymem is byte3, ACx is byte2[4:0] and ACy is byte4[4:0].
// The operation is selected by (byte1[7], byte3[7], byte2[7]); these lift via the
// shared C55_LOP_SQDST / ABDST / LMS dual-operation path (ops [0]=Xmem [1]=Ymem
// [2]=ACx [3]=ACy).
// subadd Tx, [dual(]*Smem[)], ACx (opcode 0x8f, byte3[7:6]==11, 4 bytes): the
// dual-access subtract-add. Tx is byte3[1:0]; the data-memory operand uses the
// shared register-modify / *sp(#k) / @#k addressing (byte1:byte2) and is wrapped
// in dual(...) when byte3[5] is set; ACx is byte2[4:0]. Left unlifted, as in the
// legacy decoder.
// btstclr / btstset / btst / btstnot #k, [dbl(]*Smem[)], TCx (opcode 0x91, 4
// bytes): the memory bit-test family. Per the C55x+ encoding (verified against TI
// dis55 and SWPU104) the addressing is byte1:byte2[7:6], TCx is byte2[5], and
// byte2[4:2] selects operation and access width (byte2[4:3]: 00 btstclr / 01
// btstset / 10 btst / 11 btstnot; byte2[2]: 0 word / 1 dbl). The immediate bit
// number is byte3[4:0] in the register / indirect forms but byte3[3:0] in the
// long-absolute *(#k24) form. Left unlifted, as in the
// legacy decoder.
static void c55plus_x_btx_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)(((bits >> 8) & 0xff) & ~0x20); // byte2, TC bit (byte2[5]) cleared
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if (((bits >> 10) & 1) != 0) {
		out->dbl = true; // byte2[2]: dbl() 32-bit access
	}
}
static void c55plus_x_btx_bit(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	// The bit-number field width depends on the addressing mode (verified against
	// TI dis55): the long-absolute *(#k24) form uses 4 bits (byte3[3:0]); the
	// register / indirect forms use 5 bits (byte3[4:0]).
	C55Operand mem = { 0 };
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)(((bits >> 8) & 0xff) & ~0x20); // byte2, TC bit (byte2[5]) cleared
	ut64 mask = 0x1f;
	if (c55plus_smem_amode(b_ar, b_mode, &mem) && mem.amode == C55_AM_ABSOLUTE) {
		mask = 0xf;
	}
	out->kind = C55_OP_IMM;
	out->imm = bits & mask;
	out->width = 16;
}
static void c55plus_x_btx_tc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)(4 + ((bits >> 13) & 1)); // byte2[5]: tc1 / tc2
}

// btst *Smem, reg, TCx (opcode 0x89, byte3[7:5]==101, 4 bytes): test a memory bit
// against a register-selected bit number. The Smem is byte1:byte2 (the shared
// register-modify / short / @#k decode using byte2[7:6]); the bit-number register
// is gr1((byte3[1:0] << 5) | byte2[4:0]) -- byte3[1:0] selects the register bank
// (00 ac, 01 ar/t, 10 ac.h, 11 ac.l) and byte2[4:0] the index; TCx is byte2[5].
// (The other 0x89 bit ops -- bclr / bnot / btstp, the swapped "reg, *Smem" orders
// -- stay on the legacy decoder.) Left unlifted.
static void c55plus_x_btm_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
}
static void c55plus_x_btm_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	ut8 idx = (ut8)((((bits >> 0) & 0x3) << 5) | ((bits >> 8) & 0x1f)); // byte3[1:0]:byte2[4:0]
	c55plus_gr1(idx, &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_btm_tc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)(4 + ((bits >> 13) & 1)); // byte2[5]: tc1 / tc2
}

static void c55plus_x_subadd_tx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(48 + (bits & 0x3)), &out->reg); // byte3[1:0] -> t0-3
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_subadd_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->dual_wrap = ((bits >> 5) & 1) != 0; // byte3[5]
}
static void c55plus_x_subadd_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// bfxtr ACc.<h/l>, ACb.<h/l>, *Smem, ACa.<h/l> (opcode 0xbc, byte3[6]==0 &&
// byte4[7:6]==00, 5 bytes): the memory-operand bit-field extract. The three
// accumulator operands carry an explicit half-register selector (bit 5 of their
// field: 1 -> .l, 0 -> .h). Display order is ACc (byte3[4:0]), ACb (byte4[4:0]),
// *Smem (byte1:byte2, the compact register-modify matrix with short/@#k via
// byte2[7:6]) and ACa (byte2[4:0]). (The bfins / bfxtl / dbfxtr variants selected
// by byte3[6] / byte4[6] / byte4[7] stay on the legacy decoder.) Left unlifted.
static void c55plus_x_bfxtr_half(C55Operand *out, const C55ArchDesc *a, ut8 idx5, ut8 half) {
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(idx5 & 0x1f), &out->reg);
	out->reg.sub = half ? C55_SUB_LO : C55_SUB_HI; // bit5: 1 -> .l, 0 -> .h
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_bcx_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_bfxtr_half(out, a, (ut8)((bits >> 8) & 0x1f), (ut8)((bits >> 13) & 1)); // byte3[4:0], byte3[5]
}
static void c55plus_x_bcx_acb(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	if (((bits >> 6) & 3) != 0) {
		// byte4[7:6] != 00 selects the bfxtl / dbfxtr variants, which stay on the
		// legacy decoder: abandon so the decode falls through.
		out->kind = C55_OP_INVALID;
		return;
	}
	c55plus_x_bfxtr_half(out, a, (ut8)(bits & 0x1f), (ut8)((bits >> 5) & 1)); // byte4[4:0], byte4[5]
}
static void c55plus_x_bcx_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
}
static void c55plus_x_bcx_aca(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_bfxtr_half(out, a, (ut8)((bits >> 16) & 0x1f), (ut8)((bits >> 21) & 1)); // byte2[4:0], byte2[5]
}

// mpym / macm / masm t3 = Smem, ACx, [ACy,] ACz (opcode 0xbb, 5 bytes): the
// single-data-memory multiply / multiply-accumulate with a parallel "t3 = Smem"
// side-load. The Smem is byte1:byte2 (the shared register-modify / short / @#k
// decode), ACz (the destination) is byte2[4:0], ACx is byte4 (a full gr1 source)
// and ACy is byte3[4:0] (macm / masm only). byte3[7:6] selects 00 mpym / 01 macm
// / 10 masm; byte3[5] is the whole-operation uns ('u' suffix); byte2[5] is round
// and byte4[7] fractional, via the shared .mods packing. Left unlifted (the side-
// load three-accumulator form is not modelled), as in the legacy decoder.
static void c55plus_x_bb_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
}
static void c55plus_x_bb_acz(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_bb_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x7f), &out->reg); // byte4[6:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_bb_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// mpym / macm / masm [uns(]Xmem[)], [uns(]Ymem[)], ACy (opcode 0xe0, 6 bytes):
// the long-form dual-data-memory multiply / multiply-accumulate. Unlike the
// compact 0xc8 forms, the Xmem here uses the full register-modify / bit-reverse /
// short / @#k addressing (byte1:byte2[7:6]); the Ymem uses the compact register-
// modify matrix (byte5). ACy is byte2[4:0]; byte3[7:6] selects the operation (00
// mpym, 01 macm, 10 masm); byte3[5] is the Xmem uns() and byte4[5] the Ymem uns();
// byte2[5] is round (r) and byte5[7] fractional (f), via the shared .mods packing.
// These lift via the shared multiply-accumulate path (ops [0]=Xmem [1]=Ymem
// [2]=ACy).
static void c55plus_x_e0_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 32) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 24) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->uns = ((bits >> 21) & 1) != 0; // byte3[5]
}
static void c55plus_x_e0_ymem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)(bits & 0x7f), ((bits >> 13) & 1) != 0, out); // byte5[6:0], byte4[5] uns
}
static void c55plus_x_e0_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// firsadd / firssub Xmem, Ymem, Cmem, ACx, ACy (opcode 0xeb, 6 bytes): the FIR
// symmetric / antisymmetric primitives. The three memory operands reuse the
// shared dual-mem register-modify matrix: Xmem is byte1, Ymem is byte3, Cmem is
// byte5; ACx is byte2[4:0] and ACy is byte4[4:0]. byte2[7]==1 selects the firs
// form (over the byte2[7]==0 "amar :: mpy" form), byte4[6] selects firssub over
// firsadd, and byte5[7] is the fractional (f) modifier. These lift via the shared
// C55_LOP_FIRSADD / FIRSSUB dual-operation path (ops [0]=Xmem [1]=Ymem [2]=Cmem
// [3]=ACx [4]=ACy).
static void c55plus_x_fir_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 32) & 0x7f), false, out); // byte1[6:0]
}
static void c55plus_x_fir_ymem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 16) & 0x7f), false, out); // byte3[6:0]
}
static void c55plus_x_fir_cmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)(bits & 0x7f), false, out); // byte5[6:0]
}
static void c55plus_x_fir_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_fir_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte4[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_dst_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 24) & 0x7f), false, out); // byte1[6:0]
}
static void c55plus_x_dst_ymem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 8) & 0x7f), false, out); // byte3[6:0]
}
static void c55plus_x_dst_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_dst_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte4[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_diff_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_diff_acd(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte4[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_diff_aca(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte1[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_diff_acb(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_diff_trn(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_TRN;
	out->reg.num = (ut8)(((bits >> 5) & 7) ^ 6); // byte4[7:5] ^ 6
	out->reg.sub = C55_SUB_NONE;
	out->width = 16;
}

// sqrm / sqam / sqsm *Smem, [ACx,] ACy (opcode 0x92, 4 bytes): square a data-
// memory operand, optionally accumulating. The Smem is byte1:byte2 (the shared
// register-modify / @#k decode using byte2[7:6]); ACy is byte2[4:0]; byte2[5] is
// the round (r) modifier. byte3[7:5] selects the operation (000 sqrm, 010 sqam,
// 100 sqsm), byte3[5] is the fractional (f) modifier, and byte3[4:0] is the
// accumulate source ACx (sqam / sqsm only). These lift via the shared squaring
// multiply path.
static void c55plus_x_sq_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
}
static void c55plus_x_sq_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_sq_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// mpymk / macmk Xmem, #k8, [ACx,] ACy (opcode 0xb8, 5 bytes): multiply (or
// multiply-accumulate) a data-memory operand by an 8-bit signed constant. The
// Xmem reuses the shared register-modify / scaled / bit-reverse / @#k decode
// (byte1:byte2); ACy is byte2[4:0]; #k8 is byte4; byte3[6] selects macmk (adding
// ACx = byte3[4:0]) over mpymk; byte3[5] is the fractional (f) modifier. Left
// unlifted, as the constant-multiply forms are in the legacy decoder.
static void c55plus_x_mpymk_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
}
static void c55plus_x_mpymk_k8(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xff; // byte4
	out->width = 8;
}
static void c55plus_x_mpymk_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_mpymk_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_mant_aca(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_mant_acb(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_mant_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x7f), &out->reg); // byte1[6:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// subc *Smem, ACx, ACy (opcode 0xb3, byte3[7:5]==111, 5 bytes): conditional
// subtract. The Smem is byte1:byte2 (the shared register-modify / indexed / @#k
// decode using byte2[7:6]); ACx is byte3[4:0] and ACy is byte2[4:0]. The
// addsubcc / addsub2cc forms share the opcode via other byte3[7:5] codes and
// carry extra Tx / TCx operands; those stay on the legacy decoder. Left unlifted,
// as in the legacy decoder.
static void c55plus_x_b3_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
}
static void c55plus_x_b3_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_b3_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
// TCx of the addsubcc 1-TC form: byte2[5] selects tc1 (0) or tc2 (1).
static void c55plus_x_b3_tcx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)(((bits >> 21) & 1) ? 5 : 4); // byte2[5]: tc2 / tc1
}
// The fixed tc1 / tc2 operands of the addsubcc 2-TC and addsub2cc forms.
static void c55plus_x_b3_tc1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = 4; // tc1
}
static void c55plus_x_b3_tc2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = 5; // tc2
}
// The ACz operand of addsub2cc: gr1(byte4[6:0]).
static void c55plus_x_b3_acz(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x7f), &out->reg); // byte4[6:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_b4_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	ut8 b3 = (ut8)((bits >> 8) & 0xff); // byte3
	ut8 b4 = (ut8)(bits & 0xff); // byte4
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->uns = ((b3 >> 5) & 1) != 0; // byte3[5]
	out->mem_round = ((b_mode >> 5) & 1) != 0; // byte2[5]
	out->sh_mem_reg_set = true;
	c55plus_gr1((ut8)(b4 & 0x7f), &out->sh_mem_reg); // byte4[6:0]
}
static void c55plus_x_b4_acdst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// Smem << Tx of the 0xb6 register-shifted add/sub (opcode 0xb6, 5 bytes): byte1
// mode + ARn / byte2[7:6] offset-mode (via c55plus_smem_amode) with a register
// shift count in byte4[6:0] rendered as " << Tx". (Unlike the 0xb4 mov-shift
// form, byte2[5]/byte3[5] are not round/uns selectors here.)
static void c55plus_x_b6_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	ut8 b4 = (ut8)(bits & 0xff); // byte4
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->sh_mem_reg_set = true;
	c55plus_gr1((ut8)(b4 & 0x7f), &out->sh_mem_reg); // byte4[6:0]
}
// Source accumulator ACx of the 0xb6 form: byte3[4:0].
static void c55plus_x_b6_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// Source accumulator of the 0xb4 store form (mov ACx << Tx, [dbl]Smem, byte3[6]==0):
// ACx is byte2[4:0], shifted by the byte4[6:0] register (rendered " << Tx"). The
// accumulator is wrapped hi()/lo() for the 16-bit-half stores (byte3[1:0]: 00 ->
// hi, 10 -> lo; byte3[0]==1 selects the dbl 32-bit store with no half wrapper),
// and optionally rnd() (byte2[5]) / uns() (byte3[5]).
static void c55plus_x_b4st_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b2 = (ut8)((bits >> 16) & 0xff); // byte2
	ut8 b3 = (ut8)((bits >> 8) & 0xff); // byte3
	ut8 b4 = (ut8)(bits & 0xff); // byte4
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(b2 & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
	out->sh_by_reg = true;
	c55plus_gr1((ut8)(b4 & 0x7f), &out->index); // byte4[6:0]
	out->wrap_round = ((b2 >> 5) & 1) != 0; // byte2[5]
	out->wrap_uns = ((b3 >> 5) & 1) != 0; // byte3[5]
	if (!(b3 & 1)) { // byte3[0]==0 -> 16-bit-half store
		out->wrap_half = (b3 & 2) ? 2 : 1; // byte3[1]: 0 -> hi, 1 -> lo
	}
}
// Destination memory of the 0xb4 store form: Smem (byte1 mode+ARn / byte2[7:6]
// offset-mode); byte3[0] selects the 32-bit dbl() store.
static void c55plus_x_b4st_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	ut8 b3 = (ut8)((bits >> 8) & 0xff); // byte3
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if (b3 & 1) { // byte3[0] -> dbl 32-bit store
		out->access = 32;
		out->dbl = true;
	}
}

// bfxtr #k16, ACsrc, ACdst (opcode 0xc6, 5 bytes): bit-field extract. The 16-bit
// mask is byte3:byte4; the source accumulator is byte2[4:0] (byte2[6:5]==11 is
// fixed, checked by the row mask); the destination is byte1, a 7-bit general
// register selector (byte1[6:5] the sub-register type, byte1[4:0] the number).
static void c55plus_x_bfxtr_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 num = (ut8)((bits >> 24) & 0x1f); // byte1[4:0]
	ut8 typ = (ut8)((bits >> 29) & 3); // byte1[6:5]
	out->kind = C55_OP_REG;
	switch (typ) {
	case 0: c55plus_gr1(num, &out->reg); break; // ACx
	case 1: c55plus_gr1((ut8)(32 + num), &out->reg); break; // ARx
	case 2: c55plus_gr1((ut8)(64 + num), &out->reg); break; // ACx.h
	default: c55plus_gr1((ut8)(96 + num), &out->reg); break; // ACx.l
	}
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_bfxtr_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0] -> ACx
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_bfxtr_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff; // byte3:byte4
	out->width = 16;
}

// Bit-test family register-target forms (opcode 0x89, 4 bytes): the "@#k bit
// number, register" variants of btst / bclr / bset / bnot / btstp. byte1[6:0] is
// the bit number; byte2[4:0] is the target register number with byte2[7:5]
// selecting the variant (110 = bclr / btst-tc1, 111 = bset / btst-tc2); byte3[1:0]
// the sub-register (ac / ar / ac.h / ac.l) and byte3[7:5] the operation. Left
// unlifted, as in the legacy decoder.
static void c55plus_x_bit_num(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = (bits >> 16) & 0x7f; // byte1[6:0]
	out->width = 16;
	out->is_bit = true;
}
static void c55plus_x_bit_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 num = (ut8)((bits >> 8) & 0x1f); // byte2[4:0]
	ut8 sub = (ut8)(bits & 3); // byte3[1:0]
	out->kind = C55_OP_REG;
	switch (sub) {
	case 0: c55plus_gr1(num, &out->reg); break; // ACx
	case 1: c55plus_gr1((ut8)(32 + num), &out->reg); break; // ARx
	case 2: c55plus_gr1((ut8)(64 + num), &out->reg); break; // ACx.h
	default: c55plus_gr1((ut8)(96 + num), &out->reg); break; // ACx.l
	}
	out->width = c55plus_reg_width(a, &out->reg);
}
// The TC flag of btst is byte2[5] (0 -> TC1, 1 -> TC2), rendered/lifted via the
// shared cond-flag ids (tc1 = 4, tc2 = 5).
static void c55plus_x_bit_tc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)(4 + ((bits >> 13) & 1));
}

// add/mov #k16, [dbl(]*Smem[)] (opcode 0xb1, base 4 bytes): a 16-bit immediate
// applied to a memory operand. byte2[7:6] selects the addressing group and
// byte1[7:4] supplies the sub-mode (the shared Smem decode reads only those, so
// the operation/dbl bits in byte2 do not disturb it); byte2[4:3] selects the
// operation (00 = add, 11 = mov); byte2[5] is the dbl() flag (32-bit access);
// the 16-bit immediate is byte3:byte4. Only mov lifts (a store), as in legacy.
static void c55plus_x_b1_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if ((b_mode >> 5) & 1) {
		out->access = 32; // dbl()
	}
}
static void c55plus_x_b1_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff; // byte3:byte4
	out->width = 16;
}

// Whole-accumulator destination ACx in byte2[4:0] (0x5c dbl load).
static void c55plus_x_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // ac0-31
	out->width = c55plus_reg_width(a, &out->reg);
}

// Low-half accumulator destination ACx.l in byte2[4:0] (0x5b word load).
static void c55plus_x_acc_lo(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(96 + (bits & 0x1f)), &out->reg); // ac0-31 .l
	out->width = c55plus_reg_width(a, &out->reg);
}

// High-half accumulator destination ACx.h in byte2[4:0] (0x5a word load).
static void c55plus_x_acc_hi(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(64 + (bits & 0x1f)), &out->reg); // ac0-31 .h
	out->width = c55plus_reg_width(a, &out->reg);
}

// Word (16-bit) memory source with the byte2[5] uns() qualifier, used by the
// "mov *Smem, ACx.h" load (opcode 0x5a).
static void c55plus_x_word_mem_u(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // buf[1]
	ut8 b_mode = (ut8)(bits & 0xff); // buf[2]
	if (!c55plus_mem_addr(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->access = 16;
	if ((b_mode >> 5) & 1) {
		out->uns = true;
	}
}

// Accumulator-half source ACx.h/.l of "mov ACx.h/.l, *Smem" (opcode 0x51 word
// store): byte2[5] selects the half (0 -> high, 1 -> low) and byte2[4:0] the
// accumulator.
static void c55plus_x_acc_half(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 num = (ut8)(bits & 0x1f);
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(((bits >> 5) & 1 ? 96 : 64) + num), &out->reg); // .l : .h
	out->width = c55plus_reg_width(a, &out->reg);
}

// Whole-accumulator source ACx in byte2[4:0] (0x50 dbl store).
static void c55plus_x_acc_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // ac0-31
	out->width = c55plus_reg_width(a, &out->reg);
}

// xar source XARx in byte2[3:0] (0x52 dbl store).
static void c55plus_x_xar_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(128 + (bits & 0x0f)), &out->reg); // xar0-15
	out->width = c55plus_reg_width(a, &out->reg);
}

static void c55plus_x_gr6(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_mode = (ut8)(bits & 0xff);
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(b_mode & 0x3f), &out->reg);
	if (out->reg.cls == C55_RC_NONE || out->reg.cls == C55_RC_AC) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// Memory source of the copy(ALLa = Smem) (opcode 0x54-0x57 LD_R, 3+ bytes) form.
// The Smem addressing is the standard byte1:byte2[7:6] matrix (so the const-index
// *ARn(#K16) and absolute forms extend the instruction); the access is dbl iff the
// destination register is a long (>16-bit) register, matching TI dis55.
static void c55plus_x_copy_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // byte1
	ut8 b_mode = (ut8)(bits & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	C55Reg reg = { 0 };
	ut8 alla = (ut8)((((bits >> 16) & 0x3) << 6) | (bits & 0x3f)); // byte0[1:0]:byte2[5:0]
	c55plus_gr1(alla, &reg);
	if (c55plus_reg_width(a, &reg) > 16) {
		out->access = 32;
		out->dbl = true;
	}
}

// Destination register ALLa of copy(ALLa = Smem): the 8-bit register id is
// byte0[1:0] (high 2 bits) joined with byte2[5:0].
static void c55plus_x_copy_alla(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 alla = (ut8)((((bits >> 16) & 0x3) << 6) | (bits & 0x3f)); // byte0[1:0]:byte2[5:0]
	out->kind = C55_OP_REG;
	c55plus_gr1(alla, &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}

// Absolute double-word memory source of "copy dbl(*(#addr)), xar" (opcode 0xd1,
// 5 bytes): byte1[7:6] selects the destination/access form (10 = the dbl xar
// load decoded here), and the 24-bit byte address is in bytes 2:4. The
// accumulator (00/01/11) and byte/half forms fall back to the legacy decoder.
static void c55plus_x_copy_abs_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b1 = (ut8)((bits >> 24) & 0xff);
	if (((b1 >> 6) & 3) != 2 || ((b1 >> 4) & 3)) {
		out->kind = C55_OP_INVALID; // not the dbl xar form
		return;
	}
	out->kind = C55_OP_MEM;
	out->access = 32;
	out->dbl = true;
	out->amode = C55_AM_ABSOLUTE;
	out->abs_addr = (ut32)(bits & 0xffffff);
}

// xar destination of the 0xd1 absolute copy: byte1[3:0].
static void c55plus_x_copy_abs_xar(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(128 + ((bits >> 24) & 0x0f)), &out->reg); // xar0-15
	out->width = c55plus_reg_width(a, &out->reg);
}

// amar *Smem (opcode 0x62, 3 bytes): modify-auxiliary-register -- apply the
// addressing mode's pointer side effect (e.g. *arN+ increments xarN) without a
// memory access. The Smem operand is byte1:byte2 (the shared Smem decode plus
// the *sp(#k) / @#k group). The shared LEA lift emits the post-modify effect for
// the register-modify modes and a nop / no IL otherwise, matching the legacy
// decoder.
static void c55plus_x_amar_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 8) & 0xff); // byte1
	ut8 b_mode = (ut8)(bits & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
	}
}

// forms are decoded: the SP-relative *sp(#k) (3 bytes, byte2[7:6]==11 with
// byte1[7]==1, offset k = byte1[6:0]) and the long const-index *arN(#K16) (5
// bytes, byte2[7:6]==01 with byte1[7:4]==8, base ARn = byte1[3:0], the unsigned
// 16-bit constant supplied as a 2-byte extension via the decoder). byte2[3:0]
// is the xar destination in both. The DP-direct, register-modify, indexed-short
// and byte-access forms fall back to the legacy decoder. The address is a word
// address (no byte scaling); the LEA lifter writes base+offset into the dest.
static void c55plus_x_amar_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b1 = (ut8)((bits >> 8) & 0xff);
	ut8 b2 = (ut8)(bits & 0xff);
	ut8 grp = (ut8)((b2 >> 6) & 3);
	if (grp == 3 && ((b1 >> 7) & 1)) {
		// *sp(#k): SP-relative, 7-bit offset
		out->kind = C55_OP_MEM;
		out->amode = C55_AM_INDEXED;
		c55plus_gr1(53, &out->reg); // sp
		out->disp = (ut8)(b1 & 0x7f);
		return;
	}
	if (grp == 1 && ((b1 >> 4) & 0x0f) == 8 && !((b2 >> 4) & 3)) {
		// *arN(#K16): long const-index; the K16 extension is filled by the
		// decoder (which also sets the size and clears the parallel flag).
		out->kind = C55_OP_MEM;
		out->amode = C55_AM_CONST_IDX;
		c55plus_gr1((ut8)(32 + (b1 & 0x0f)), &out->reg); // base ARn
		return;
	}
	out->kind = C55_OP_INVALID;
}

// xar destination of "amar Smem, xar" (opcode 0x63): byte2[3:0].
static void c55plus_x_amar_xar(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(128 + (bits & 0x0f)), &out->reg); // xar0-15
	out->width = c55plus_reg_width(a, &out->reg);
}

// sftl/sfts/add/sub SRC, SHIFT, DST (opcode 0xa6, 4 bytes): a register-to-
// register variable shift. byte1[7] selects the operation class (0 = add/sub
// shift-and-accumulate, 1 = sftl/sfts), byte2[7] the shift kind (0 = sftl/add,
// 1 = sfts/sub). The three register operands are 7-bit general-register
// selectors (bits [6:5] the sub-register type ac / ar / ac.h / ac.l, bits [4:0]
// the number): DST is byte1[6:0], SRC byte2[6:0], SHIFT byte3[6:0]. Left
// unlifted, as in the legacy decoder.
static void c55plus_gr1_sub7(const C55ArchDesc *a, ut8 v, C55Operand *out) {
	ut8 num = (ut8)(v & 0x1f);
	switch ((v >> 5) & 3) {
	case 0: c55plus_gr1(num, &out->reg); break; // ACx
	case 1: c55plus_gr1((ut8)(32 + num), &out->reg); break; // ARx
	case 2: c55plus_gr1((ut8)(64 + num), &out->reg); break; // ACx.h
	default: c55plus_gr1((ut8)(96 + num), &out->reg); break; // ACx.l
	}
	out->kind = C55_OP_REG;
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_sft_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)((bits >> 16) & 0x7f), out); // byte1[6:0]
}
static void c55plus_x_sft_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)((bits >> 8) & 0x7f), out); // byte2[6:0]
}
static void c55plus_x_sft_shift(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)(bits & 0x7f), out); // byte3[6:0]
}

// sftl/sfts REG, #1 / #-1 (opcode 0x7b, 3 bytes): a register shift by a fixed
// literal one. byte1[7] selects sftl (1) vs sfts (0) and byte1[6:0] is the
// 7-bit register selector; byte2[6:5]==01 marks the shift form and byte2[7]
// selects the sign (0 -> #1, 1 -> #-1). The shift literal is rendered as a
// signed decimal "#N". Left unlifted, as in the legacy decoder.
static void c55plus_x_sft7b_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)((bits >> 8) & 0x7f), out); // byte1[6:0]
}
static void c55plus_x_sft7b_one(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = ((bits >> 7) & 1) ? (ut64)(-1) : 1; // byte2[7]: #-1 / #1
	out->width = 16;
	out->hash_dec = true;
}

// add uns(*Smem), ACx, ACy (opcode 0x8c, 4 bytes): a memory-source add into an
// accumulator. The Smem operand is byte1:byte2 (the shared Smem decode reads
// byte2[7:6] + byte1[7:4] only); byte2[5]==1 is the always-set uns marker and
// byte2[4:0] is ACy; byte3[4:0] is ACx (byte3[7:5]==000). Left unlifted, as in
// the legacy decoder.
static void c55plus_x_8c_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->uns = true;
}
static void c55plus_x_8c_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_8c_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// The fixed "carry" status-bit operand of the add-with-carry forms. Rendered
// through the shared condition-flag formatter (flag id 6 == carry).
static void c55plus_x_carry(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = 6; // carry
}

// Smem of the 0x8c add-with-carry form: same byte1 (mode + ARn) / byte2[7:6]
// (offset-mode) decode as c55plus_x_8c_mem, but the uns() qualifier is taken
// from byte2[5] (it is not implicit here, unlike the plain uns(*Smem) form).
static void c55plus_x_8c_carry_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->uns = (b_mode >> 5) & 1; // byte2[5]
}

// mov ACx.<h/l>, mmap(@reg) (opcode 0x24, byte1==0x51, 4 bytes): store an
// accumulator half into a memory-mapped register. byte2 is the memory-mapped
// register (a general-register selector, decoded by c55plus_gr1, covering the
// ac/ar/t/sp and the csr/rptc/brc0/brc1 special registers); byte3 is the source
// accumulator -- byte3[4:0] the number and byte3[5] the half (1 -> .l, 0 -> .h),
// byte3[6] must be 0. Left unlifted, as in the legacy decoder. (The opcode hosts
// many other memory-mapped-register forms, all left to the legacy decoder.)
static void c55plus_x_24_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 num = (ut8)(bits & 0x1f); // byte3[4:0]
	out->kind = C55_OP_REG;
	if ((bits >> 5) & 1) { // byte3[5]: .l / .h
		c55plus_gr1((ut8)(96 + num), &out->reg);
	} else {
		c55plus_gr1((ut8)(64 + num), &out->reg);
	}
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_24_mmr(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_MEM;
	out->amode = C55_AM_MMR;
	out->access = 16;
	c55plus_gr1((ut8)((bits >> 8) & 0x7f), &out->reg); // byte2: the mmap register
}

// sftcc ACx, TCx (opcode 0xa9, byte1[7]==1 && byte2[7]==1, 4 bytes): conditional
// shift -- shift ACx and write the result-condition to TCx. ACx is ac(byte1[5:0]);
// TCx is tc1/tc2 from byte2[5]. Left unlifted, as in the legacy decoder.
static void c55plus_x_a9_sftcc_ac(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x3f), &out->reg); // ac(byte1[5:0])
	out->width = c55plus_reg_width(a, &out->reg);
	if (out->reg.cls != C55_RC_AC) {
		out->kind = C55_OP_INVALID;
	}
}
static void c55plus_x_a9_sftcc_tc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = ((bits >> 13) & 1) ? 5 : 4; // byte2[5]: 1 -> tc2, 0 -> tc1
}

// is a signed 16-bit pc-relative displacement (bytes 1-2), taken when the
// condition byte (byte3) holds. The operand is rendered as the raw 16-bit field
// (#0x00NNNN) but the branch target is pc + size + sign_extend(field); the
// condition is decoded by c55plus_x_cond. No IL.
static void c55plus_x_callcc_target(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = (bits >> 8) & 0xffff; // bytes 1-2
	out->width = 16;
	out->addr = true;
	out->reltarget = true;
}

// bcnt ACa, ACb, TCx, ACdst (opcode 0xa9, byte1[7]==1, 4 bytes): count the bits
// of ACa selected by ACb, writing the test flag TCx and the count to ACdst. ACa
// is ac(byte2[4:0]); ACb is ac(byte3[4:0]); TCx is tc1/tc2 from byte2[6]; ACdst
// is gr1(byte1[6:0]). Left unlifted, as in the legacy decoder.
static void c55plus_x_a9_bcnt_a(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // ac(byte2[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_a9_bcnt_b(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // ac(byte3[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_a9_bcnt_tc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = ((bits >> 14) & 1) ? 5 : 4; // byte2[6]: 1 -> tc2, 0 -> tc1
}
static void c55plus_x_a9_bcnt_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1((ut8)((bits >> 16) & 0x7f), &out->reg); // gr1(byte1[6:0])
	out->kind = C55_OP_REG;
	out->width = c55plus_reg_width(a, &out->reg);
}

// the exponent (leading-bit count) of ACsrc into the destination. SRC is
// ac(byte3[4:0]); DST is gr1_sub7(byte1) (a whole accumulator or its .h/.l half).
// Left unlifted, as in the legacy decoder. (The 0xa9 opcode also hosts bcnt --
// byte1[7]==1 -- and mant::nexp -- byte2[7]==1 -- which stay on the legacy
// decoder for now.)
static void c55plus_x_a9_exp_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // ac(byte3[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_a9_exp_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)((bits >> 16) & 0x7f), out); // byte1[6:0]
}

// the single-repeat counter from csr, optionally adjusted by a 4-bit immediate
// or a register. byte1[7:6] selects: 00 rptsub #k, 01 rptadd #k, 10 rptadd reg,
// 11 rpt. The first operand is always csr; rpt has no second operand. All lift
// to a nop (a repeat op type), matching the legacy decoder.
static void c55plus_x_01_csr(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = 56; // csr
	out->reg.sub = C55_SUB_NONE;
	out->width = 16;
}
static void c55plus_x_01_k4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xf; // byte1[3:0]
	out->width = 4;
}
static void c55plus_x_01_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1((ut8)(32 + (bits & 0x1f)), &out->reg); // byte1[4:0] -> ar0-15/t0-3/special
	out->kind = C55_OP_REG;
	out->width = c55plus_reg_width(a, &out->reg);
}

// status flag into ACy, lifted by the shared rol/ror path. byte3[7] selects rol
// (0) / ror (1); the carry-in / carry-out flags are COND operands (carry / tc2)
// selected by byte3 bits via c55plus_x_a8_flag (the .lo field picks the bit).
// SRC = ac(byte2[4:0]), DST = ac(byte1[4:0]); only the whole-accumulator forms
// are decoded here (the half / extended forms are declined so they fall back).
static void c55plus_x_a8_flag(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 b = (ut8)((bits >> d->lo) & 0x1);
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = b ? 5 : 6; // 0 -> carry, 1 -> tc2
}
static void c55plus_x_a8_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	if (((bits >> 13) & 0x3) != 0) { // byte2[6:5] != 0: a half-register source, leave to legacy
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // ac(byte2[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
	if (out->reg.cls != C55_RC_AC) {
		out->kind = C55_OP_INVALID;
	}
}
static void c55plus_x_a8_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	if (((bits >> 21) & 0x3) != 0) { // byte1[6:5] != 0: a half-register dest, leave to legacy
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // ac(byte1[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
	if (out->reg.cls != C55_RC_AC) {
		out->kind = C55_OP_INVALID;
	}
}

// in the st0_55 status register. byte1[5] selects bset (1) vs bclr (0); byte1[4:0]
// is the bit position, which also selects the bit name (st0_dp07..dp15,
// st0_acov0/1/2/3, st0_carry, st0_tc1/tc2). The bit operand is rendered as the
// named special register and carries the position in its register index.
static void c55plus_x_0a_bit(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = (ut8)(192 + (bits & 0x1f)); // 192 + byte1[4:0]
	out->reg.sub = C55_SUB_NONE;
	out->width = 16;
}
static void c55plus_x_0a_st0(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_SPECIAL;
	out->reg.num = 228; // st0_55
	out->reg.sub = C55_SUB_NONE;
	out->width = 16;
}

// memory-mapped register. byte2 is the mmap register (a gr1 selector); byte3[3]
// selects pop (1) vs psh (0). Lifted by the shared stack path (the MMR operand
// moves through the stack as a plain register). Only the simple register form is
// decoded here (byte3[7]==0, byte3[6:4]==0); the @#k / dbl / reserved variants
// stay on the legacy decoder.
static void c55plus_x_24_mmr_stack(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	if ((bits & 0xf7) != 0) { // byte3 must be 0 apart from the pop/psh bit (bit 3)
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_MEM;
	out->amode = C55_AM_MMR;
	out->access = 16;
	c55plus_gr1((ut8)((bits >> 8) & 0xff), &out->reg); // byte2: the mmap register
}

// rX is gr1(byte1) and rY gr1(byte2), each a full 8-bit gr1 selector (so the
// ac.h / ac.l half-register encodings are covered). The shared stack lift emits
// the per-register load/store and SP adjustment in operand order.
static void c55plus_x_pair_reg1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0xff), &out->reg); // byte1
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_pair_reg2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0xff), &out->reg); // byte2
	out->width = c55plus_reg_width(a, &out->reg);
}

// pshboth / popboth <reg> (opcode 0x0d, 2 bytes): push / pop a register pair. The
// register class is byte1[5] (0 ac / 1 xar) and the index is byte1[4:0]; byte1[7]
// selects pshboth (0) over popboth (1). The bare no-operand form (an out-of-range
// xar index) stays on the legacy decoder. The "both" flag marks the pair
// semantics; left unlifted, as the legacy decoder does.
// amar *ptr1, *ptr2, *ptr3 (opcode 0xea, byte1[7]==1, 6 bytes): the triple
// address-register modify. The three pointer operands each use the compact
// register-modify matrix (ptr1 = byte1[6:0], ptr2 = byte3[6:0], ptr3 = byte5[6:0];
// bytes 2 and 4 are unused). Left unlifted, as in the legacy decoder.
static void c55plus_x_amar3_p1(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 32) & 0x7f), false, out); // byte1[6:0]
}
static void c55plus_x_amar3_p2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)((bits >> 16) & 0x7f), false, out); // byte3[6:0]
}
static void c55plus_x_amar3_p3(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_x_mac_mem(a, (ut8)(bits & 0x7f), false, out); // byte5[6:0]
}

static void c55plus_x_pshpopboth_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b1 = (ut8)(bits & 0xff); // byte1 (2-byte instruction)
	ut8 idx = b1 & 0x1f;
	out->kind = C55_OP_REG;
	if ((b1 >> 5) & 1) {
		if (idx > 15) {
			// out-of-range xar index: the bare no-operand form, left to legacy.
			out->kind = C55_OP_INVALID;
			return;
		}
		c55plus_gr1((ut8)(128 + idx), &out->reg); // xar0-15
	} else {
		c55plus_gr1(idx, &out->reg); // ac0-31
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// pair selected by byte1[4:0]. Only the single-register-pair encodings are
// decoded here (they lift via the shared XOR-swap idiom); the pair()/block()
// aggregate forms and the bare no-operand swap stay on the legacy decoder. The
// pair table below maps byte1[4:0] to the two gr1 register indices.
static bool c55plus_swap_pair(ut8 sel, ut8 *rx, ut8 *ry) {
	switch (sel) {
	case 0x01:
		*rx = 0;
		*ry = 2;
		return true; // ac0, ac2
	case 0x02:
		*rx = 1;
		*ry = 3;
		return true; // ac1, ac3
	case 0x04:
		*rx = 32;
		*ry = 33;
		return true; // ar0, ar1
	case 0x05:
		*rx = 32;
		*ry = 34;
		return true; // ar0, ar2
	case 0x06:
		*rx = 33;
		*ry = 35;
		return true; // ar1, ar3
	case 0x09:
		*rx = 48;
		*ry = 50;
		return true; // t0, t2
	case 0x0a:
		*rx = 49;
		*ry = 51;
		return true; // t1, t3
	case 0x15:
		*rx = 36;
		*ry = 48;
		return true; // ar4, t0
	case 0x16:
		*rx = 37;
		*ry = 49;
		return true; // ar5, t1
	case 0x19:
		*rx = 38;
		*ry = 50;
		return true; // ar6, t2
	case 0x1a:
		*rx = 39;
		*ry = 51;
		return true; // ar7, t3
	default: return false;
	}
}
static void c55plus_x_swap_x(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 rx, ry;
	if (!c55plus_swap_pair((ut8)(bits & 0x1f), &rx, &ry)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	c55plus_gr1(rx, &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_swap_y(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 rx, ry;
	if (!c55plus_swap_pair((ut8)(bits & 0x1f), &rx, &ry)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_REG;
	c55plus_gr1(ry, &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}

// 5-bit vector number in byte1[4:0]. byte1[7:6] selects intr (00) / trap (01) /
// sim_trig (11). Left unlifted, as in the legacy decoder.
static void c55plus_x_03_k5(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0x1f; // byte1[4:0]
	out->width = 5;
}

// (rounding) saturate. byte1[7]==0 selects round; byte1[7]==1 selects sat, with
// byte1[5] choosing the rounding variant (satr). SRC is the accumulator
// ac(byte2[4:0]) and DST is ac(byte1[4:0]). Left unlifted, as in the legacy
// decoder.
static void c55plus_x_79_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)(bits & 0x1f), &out->reg); // ac(byte2[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_79_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // ac(byte1[4:0])
	out->width = c55plus_reg_width(a, &out->reg);
}

// value / min / max. byte1[7] and byte2[7] together select the operation
// (00 abs, 01 neg, 10 max, 11 min); SRC is byte2[6:0] and DST byte1[6:0], both
// 7-bit register selectors. ops = [SRC, DST], lifted by the shared register-op
// path (whole-register forms; the half-register forms fall back to the legacy
// lifter, as before).
static void c55plus_x_76_src(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)(bits & 0x7f), out); // byte2[6:0]
}
static void c55plus_x_76_dst(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)((bits >> 8) & 0x7f), out); // byte1[6:0]
}

// add/sub #k16 << #sh, ACx, ACy (opcode 0xc2, base 5 bytes): an immediate
// shifted by a variable amount combined with an accumulator. byte1[7]==0 selects
// the add/sub group and byte2[7] the operation (0 add, 1 sub); the 4-bit shift
// count is byte1[6:5]*4 + byte2[6:5]; ACx is byte2[4:0], ACy byte1[4:0]; the
// 16-bit immediate is byte3:byte4. ops = [#k16, ACx, ACy], lifted by the shared
// immediate-shift ALU path (C55_LOP_ADDSHL / SUBSHL).
static void c55plus_x_c2_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b1 = (ut8)((bits >> 24) & 0xff);
	ut8 b2 = (ut8)((bits >> 16) & 0xff);
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff; // byte3:byte4
	out->width = 16;
	out->sh_left = true;
	out->shamt = (int8_t)((((b1 >> 5) & 3) << 2) | ((b2 >> 5) & 3)); // byte1[6:5]*4 + byte2[6:5]
	out->shamt_hex = true;
}
static void c55plus_x_c2_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_c2_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte1[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// add/sub #k16 << #16, ACx, ACy (opcode 0xc0, base 5 bytes): an immediate
// shifted up 16 bits combined with an accumulator. byte2[7] selects the
// operation (1 sub, 0 add); ACy is byte1[4:0] and ACx byte2[4:0]; the 16-bit
// immediate is byte3:byte4 and the shift is the fixed #16. ops = [#k16, ACx,
// ACy], lifted by the shared immediate-shift ALU path (C55_LOP_ADDSHL /
// SUBSHL).
static void c55plus_x_c0_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff; // byte3:byte4
	out->width = 16;
	out->sh_left = true;
	out->shamt = 16; // << #16
}
static void c55plus_x_c0_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_c0_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 24) & 0x1f), &out->reg); // byte1[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

// operand against a 16-bit immediate, result into TC1/TC2. The Smem operand is
// byte1:byte2 (the shared Smem decode reads byte2[7:6] + byte1[7:4]); byte2[1:0]
// is the relop (00 ==, 01 !=, 10 <, 11 >=), byte2[2] the dbl() flag, byte2[5]
// the TC selector (0 TC1, 1 TC2); the 16-bit immediate is byte3:byte4. (byte2[3]
// selects the band variant, left to the legacy decoder.) Left unlifted.
static void c55plus_x_b2_cmp(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->kind = C55_OP_COND;
	out->cmp_mem = true;
	out->cmp_imm = true;
	if ((b_mode >> 2) & 1) {
		out->access = 32; // dbl()
		out->dbl = true;
	}
	switch (b_mode & 3) { // relop
	case 0: out->relop = C55_REL_EQ; break;
	case 1: out->relop = C55_REL_NE; break;
	case 2: out->relop = C55_REL_LT; break;
	default: out->relop = C55_REL_GE; break;
	}
	out->imm = bits & 0xffff; // byte3:byte4
	out->width = 16;
}
static void c55plus_x_b2_tc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_COND;
	out->cond_is_flag = true;
	out->cond_flag = (ut8)(((bits >> 21) & 1) ? 5 : 4); // byte2[5]: TC2 / TC1
}

// band *Smem, #k16, TCx (opcode 0xb2, byte2[3]==1, 5 bytes): test whether
// (Smem & #k16) is zero, writing the result to TCx. It shares the 0xb2 opcode
// with the cmp Smem <rel> #k16 compare (byte2[3]==0); here the Smem and the
// 16-bit mask are separate operands (not a relational compare). The TC operand
// reuses c55plus_x_b2_tc.
static void c55plus_x_b2_band_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if ((b_mode >> 2) & 1) {
		out->access = 32; // dbl()
		out->dbl = true;
	}
}
static void c55plus_x_b2_band_k16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = bits & 0xffff; // byte3:byte4
	out->width = 16;
}

// accumulator (the signed counterpart of the 0x8c uns form). The Smem operand
// is byte1:byte2 (the shared Smem decode reads byte2[7:6] + byte1[7:4] only);
// ACx is byte3[4:0] and ACy byte2[4:0]. Left unlifted, as in the legacy decoder.
static void c55plus_x_80_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
	}
}

// Destination Ra of the 0x80 "Ra = Rb + Smem" (ADD_RM) form: a 7-bit register
// field, low 6 bits in byte2[5:0] and the high bit in byte3[7] (so e.g. 0x30 ->
// T0, 0x40 -> AC0.H). The source Rb shares byte3 (its 7-bit field is byte3[6:0]).
static void c55plus_x_add_rm_ra(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 idx = (ut8)((((bits >> 7) & 1) << 6) | ((bits >> 8) & 0x3f)); // byte3[7]:byte2[5:0]
	out->kind = C55_OP_REG;
	c55plus_gr1(idx, &out->reg);
	out->width = c55plus_reg_width(a, &out->reg);
}

// memory move. Operand A is byte1 + byte2[7:6] decoded by the shared Smem
// helper; operand B is byte3, whose [6:4] field selects a register-modify mode
// (0 postdec, 1 postinc, 2 *arN(t0), 3 indirect, 4 *(arN-t0), 5 *(arN-t1),
// 6 *(arN+t0), 7 *(arN+t1)) and [3:0] the ARn. byte2[3] is the direction (1 ->
// A is the source, 0 -> B is the source) and byte2[2] the byte() flag; both are
// resolved by separate table rows / the operand helpers. Left unlifted, as in
// the legacy decoder.
static void c55plus_x_97_memA(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	if ((b_mode >> 2) & 1) {
		out->byte_sel = 3; // byte()
	}
}
static void c55plus_x_97_memB(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b3 = (ut8)(bits & 0xff); // byte3
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	out->kind = C55_OP_MEM;
	out->access = 16;
	c55plus_gr1((ut8)(32 + (b3 & 0x0f)), &out->reg); // ARn
	switch ((b3 >> 4) & 7) {
	case 0: out->amode = C55_AM_POSTDEC; break;
	case 1: out->amode = C55_AM_POSTINC; break;
	case 2:
		out->amode = C55_AM_IDXREG;
		c55plus_gr1(48, &out->index);
		break; // t0
	case 3: out->amode = C55_AM_INDIRECT; break;
	case 4:
		out->amode = C55_AM_POSTSUB;
		c55plus_gr1(48, &out->index);
		break; // *(arN-t0)
	case 5:
		out->amode = C55_AM_POSTSUB;
		c55plus_gr1(49, &out->index);
		break; // *(arN-t1)
	case 6:
		out->amode = C55_AM_POSTADD;
		c55plus_gr1(48, &out->index);
		break; // *(arN+t0)
	default:
		out->amode = C55_AM_POSTADD;
		c55plus_gr1(49, &out->index);
		break; // *(arN+t1)
	}
	if ((b_mode >> 2) & 1) {
		out->byte_sel = 3; // byte()
	}
}

// memory-source subtract. The Smem operand is byte1:byte2 (the shared Smem
// decode reads byte2[7:6] + byte1[7:4], plus the grp==3 *sp(#k) sub-mode driven
// by byte1); ACx is byte3[6:0] (a 7-bit register selector); ACy is byte2[4:0]
// with byte2[5] selecting its half (1 -> .l, 0 -> .h). Left unlifted, as in the
// legacy decoder.
static void c55plus_x_82_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
	}
}
static void c55plus_x_82_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)(bits & 0x7f), out); // byte3[6:0]
}
static void c55plus_x_82_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 num = (ut8)((bits >> 8) & 0x1f); // byte2[4:0]
	out->kind = C55_OP_REG;
	if ((bits >> 13) & 1) { // byte2[5] -> .l
		c55plus_gr1((ut8)(96 + num), &out->reg);
	} else {
		c55plus_gr1((ut8)(64 + num), &out->reg);
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// into an accumulator. The Smem operand is byte1:byte2 (the shared Smem decode
// reads byte2[7:6] + byte1[7:4] only); ACx is byte3[6:0] (a 7-bit register
// selector); ACy is byte2[4:0] with byte3[7] selecting its high half (.h). Left
// unlifted, as in the legacy decoder.
static void c55plus_x_85_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
	}
}
static void c55plus_x_85_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	c55plus_gr1_sub7(a, (ut8)(bits & 0x7f), out); // byte3[6:0]
}
static void c55plus_x_85_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 num = (ut8)((bits >> 8) & 0x1f); // byte2[4:0]
	out->kind = C55_OP_REG;
	if ((bits >> 7) & 1) { // byte3[7] -> ACy.h
		c55plus_gr1((ut8)(64 + num), &out->reg);
	} else {
		c55plus_gr1(num, &out->reg);
	}
	out->width = c55plus_reg_width(a, &out->reg);
}

// bytes): a double-word memory operand combined with two accumulators. byte3[7:6]
// selects the operation and operand order (00 = add mem-first, 01 = sub
// mem-first, 10 = sub reg-first); the Smem operand is byte1:byte2 and always a
// dbl() access; ACx is byte3[4:0] and ACy byte2[4:0]. Left unlifted, as in the
// legacy decoder.
static void c55plus_x_8d_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 16) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 8) & 0xff); // byte2
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->access = 32; // dbl()
	out->dbl = true;
}

// memory load feeding add / sub / mov. byte3[7:6] is the operation (00 add,
// 01 sub, 11 mov); the Smem operand is byte1:byte2 (the shared Smem decode reads
// byte2[7:6] + byte1[7:4] only); byte2[5] is the uns() flag; byte4[5:0] is the
// shift count and byte4[6] the dbl() flag. For add/sub the middle ACx is
// byte3[4:0] and the destination ACy is byte2[4:0]; for mov the single
// destination is byte2[4:0]. Left unlifted, as in the legacy decoder.
static void c55plus_x_b7_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	ut8 b_ar = (ut8)((bits >> 24) & 0xff); // byte1
	ut8 b_mode = (ut8)((bits >> 16) & 0xff); // byte2
	ut8 b4 = (ut8)(bits & 0xff); // byte4
	if (!c55plus_smem_amode(b_ar, b_mode, out)) {
		out->kind = C55_OP_INVALID;
		return;
	}
	out->uns = (bool)((b_mode >> 5) & 1);
	if ((b4 >> 6) & 1) {
		out->access = 32; // dbl()
	}
	out->sh_left = true;
	out->shamt = (int8_t)(b4 & 0x3f); // shift count
	out->shamt_hex = true;
}
static void c55plus_x_b7_acx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 8) & 0x1f), &out->reg); // byte3[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}
static void c55plus_x_b7_acy(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	out->kind = C55_OP_REG;
	c55plus_gr1((ut8)((bits >> 16) & 0x1f), &out->reg); // byte2[4:0]
	out->width = c55plus_reg_width(a, &out->reg);
}

static const C55InsnDef c55plus_table[] = {
	// no-operand instructions (mnemonic only)
	{ .mask = 0xff000000, .match = 0x20000000, .id = TMS320C55_INS_NOP },
	// nop_16 (opcode 0x00, byte1 high nibble 0): the 2-byte no-op. byte1 values
	// 0x10/0x20/0x80 are distinct 0x00-family ops (idle / to_word / reserved) and
	// stay on the legacy decoder; only the nop_16 sub-range is matched here so it
	// types as NOP and lifts to nop() through the shared engine.
	{ .mask = 0xfff00000, .match = 0x00000000, .id = TMS320C55_INS_NOP_16, .len = 2 },
	{ .mask = 0xff000000, .match = 0x21000000, .id = TMS320C55_INS_RET },
	// retcc <cond> (opcode 0x08, 2 bytes): conditional return, taken when the
	// condition byte (byte1) holds. The condition reuses the shared c55plus_x_cond
	// decoder. No IL; the conditional-return analysis keeps a fall-through edge
	// and the return-address stack adjustment.
	{ .mask = 0xff000000, .match = 0x08000000, .id = TMS320C55_INS_RETCC, .ops = { { .lo = 0, .fn = c55plus_x_cond } } },
	{ .mask = 0xffff0000, .match = 0x00c00000, .id = TMS320C55_INS_RETI },
	{ .mask = 0xffff0000, .match = 0x00340000, .id = TMS320C55_INS_RESET },
	{ .mask = 0xffff0000, .match = 0x00200000, .id = TMS320C55_INS_IDLE },
	// rpt #k16 (opcode 0x6c, 3 bytes): arm the single-instruction repeat counter
	// with the 16-bit count in bytes 1:2. It has no data effect of its own (the
	// shared lifter emits a nop for the REP op type, matching the legacy decoder).
	{ .mask = 0xff000000, .match = 0x6c000000, .id = TMS320C55_INS_RPT, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 } } },
	// rptcc #k, <cond> (opcode 0x6d, 3 bytes): conditionally repeat the next
	// instruction #k+1 times when the condition byte (byte1) holds. #k is the
	// 8-bit immediate in byte2; the condition reuses the shared c55plus_x_cond
	// decoder. Lifts to a nop (a repeat op type), matching the legacy decoder.
	{ .mask = 0xff000000, .match = 0x6d000000, .id = TMS320C55_INS_RPTCC, .lop = C55_LOP_NOP, .len = 3, .ops = { { .fn = c55plus_x_k8 }, { .lo = 8, .fn = c55plus_x_cond } } },
	// rptblocal #l8 (opcode 0x6e, 3 bytes): local block-repeat to an 8-bit block-end
	// label (byte2). Lifts to a nop, as the legacy decoder does.
	{ .mask = 0xff000000, .match = 0x6e000000, .id = TMS320C55_INS_RPTBLOCAL, .lop = C55_LOP_NOP, .len = 3, .ops = { { .fn = c55plus_x_rptblocal_lbl } } },
	// rptb #l16 (opcode 0x6f, 3 bytes): block-repeat to a 16-bit block-end label.
	// No data effect of its own (lifts to a nop), matching the legacy decoder.
	{ .mask = 0xff000000, .match = 0x6f000000, .id = TMS320C55_INS_RPTB, .lop = C55_LOP_NOP, .len = 3, .ops = { { .fn = c55plus_x_rptb_lbl } } },
	// amar *ptr1, *ptr2, *ptr3 (opcode 0xea, byte1[7]==1, 6 bytes): the triple
	// address-register modify (three register-modify pointers). Left unlifted, as
	// in the legacy decoder.
	{ .mask = 0xff800000, .match = 0xea800000, .id = TMS320C55_INS_AMAR, .len = 6, .ops = { { .fn = c55plus_x_amar3_p1 }, { .fn = c55plus_x_amar3_p2 }, { .fn = c55plus_x_amar3_p3 } } },
	// amar *Smem (opcode 0x62, 3 bytes): modify auxiliary register via the Smem
	// addressing-mode side effect. The shared LEA lift emits the AR post-modify.
	{ .mask = 0xff000000, .match = 0x62000000, .id = TMS320C55_INS_AMAR, .len = 3, .ops = { { .fn = c55plus_x_amar_smem } } },
	// amar *sp(#k), xar (opcode 0x63, 3 bytes): load the SP-relative word
	// effective address into an extended AR register (xar = sp + k). Only the
	// *sp(#k) form is decoded here (see c55plus_x_amar_mem); the DP-direct,
	// register-modify, and long const-index forms fall back to the legacy decoder.
	{ .mask = 0xff000000, .match = 0x63000000, .id = TMS320C55_INS_AMAR, .ops = { { .fn = c55plus_x_amar_mem }, { .fn = c55plus_x_amar_xar } } },
	// psh/pop reg (opcodes 0x0e/0x0f): single register byte
	{ .mask = 0xff000000, .match = 0x0e000000, .id = TMS320C55_INS_PSH, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_reg_pshpop } } },
	{ .mask = 0xff000000, .match = 0x0f000000, .id = TMS320C55_INS_POP, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_reg_pshpop } } },
	// delay *Smem / psh *Smem (opcodes 0x60 / 0x61, base 3 bytes): a single Smem
	// operand (bytes 1:2 with the usual extension), left unlifted as in the
	// legacy decoder. c55plus_x_smem_dest decodes the full Smem mode set
	// (including the register-scaled *arN(Tx<<#k) forms and the absolute / mmap
	// extensions).
	{ .mask = 0xff000000, .match = 0x60000000, .id = TMS320C55_INS_DELAY, .ops = { { .fn = c55plus_x_smem_dest } } },
	{ .mask = 0xff000000, .match = 0x61000000, .id = TMS320C55_INS_PSH, .ops = { { .fn = c55plus_x_smem_dest } } },
	// mov src, dst (opcode 0x77): src is byte 2, dst is byte 1
	{ .mask = 0xff000000, .match = 0x77000000, .id = TMS320C55_INS_MOV, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_reg_src }, { .lo = 8, .width = 8, .fn = c55plus_x_reg_dst } } },
	// b #target (opcode 0x68): 16-bit pc-relative unconditional branch, the
	// branch sibling of call 0x69. The displacement is shown as a 24-bit
	// address; c55_effective_type sees the immediate operand and types it JMP.
	{ .mask = 0xff000000, .match = 0x68000000, .id = TMS320C55_INS_B, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr } } },
	// call #target (opcode 0x69): 16-bit field shown as a 24-bit address
	{ .mask = 0xff000000, .match = 0x69000000, .id = TMS320C55_INS_CALL, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr } } },
	// call #target (opcode 0x9d, 4 bytes): direct call to a 24-bit absolute
	// address in bytes 1:3. Lifts (like the legacy decoder) to an unconditional
	// transfer to the resolved target; the return-address push lives in the
	// analysis stack metadata, not the IL.
	{ .mask = 0xff000000, .match = 0x9d000000, .id = TMS320C55_INS_CALL, .ops = { { .fn = c55plus_x_addr24 } } },
	// b #target (opcode 0x9c, 4 bytes): the unconditional-branch sibling of the
	// 0x9d call -- a direct transfer to a 24-bit absolute address in bytes 1:3.
	// c55_effective_type sees the address immediate and types it JMP.
	{ .mask = 0xff000000, .match = 0x9c000000, .id = TMS320C55_INS_B, .ops = { { .fn = c55plus_x_addr24 } } },
	// callcc #target, <cond> (opcode 0x9b, 4 bytes): conditional call to a 16-bit
	// absolute target (bytes 1:2), taken when the condition byte (byte3) holds.
	// No IL; the conditional-call analysis records the jump, the fall-through
	// edge, and the return-address stack adjustment.
	{ .mask = 0xff000000, .match = 0x9b000000, .id = TMS320C55_INS_CALLCC, .ops = { { .fn = c55plus_x_callcc_target }, { .lo = 0, .fn = c55plus_x_cond } } },
	// b ACx / call ACx (opcode 0x02, 2 bytes): register-indirect branch/call to
	// the 24-bit address held in an accumulator (byte1[4:0]). byte1[7] selects
	// the form -- 0 b, 1 call -- and the register operand refines the type to
	// UJMP/UCALL. byte1[6]/byte1[5] add the "|| local()" / "|| far()" parallel
	// qualifiers, rendered after the register.
	{ .mask = 0xff800000, .match = 0x02000000, .id = TMS320C55_INS_B, .len = 2, .ops = { { .fn = c55plus_x_acc_b1lo }, { .fn = c55plus_x_b1_local }, { .fn = c55plus_x_b1_far } } },
	{ .mask = 0xff800000, .match = 0x02800000, .id = TMS320C55_INS_CALL, .len = 2, .ops = { { .fn = c55plus_x_acc_b1lo }, { .fn = c55plus_x_b1_local }, { .fn = c55plus_x_b1_far } } },
	// xccpart <cond> / xcc <cond> (opcodes 0x07 / 0x06, 2 bytes): the
	// conditional-execution guards. byte1 is the condition, encoded exactly as in
	// the compare-and-branch family, so the shared condition decode and the COND
	// operand formatter render it directly. (xccpart guards a parallel slot, xcc
	// the next instruction; both are left unlifted, as the legacy lifter does.)
	{ .mask = 0xff000000, .match = 0x07000000, .id = TMS320C55_INS_XCCPART, .lop = C55_LOP_NOP, .xcc_guard = true, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	// xccpart <cond> (opcode 0x05, 2 bytes): the same conditional-execution guard
	// with the byte0=0x05 selector (the 0x07 / 0x05 variants differ only in which
	// parallel slot they guard); the condition byte is encoded identically, so it
	// reuses the shared condition decode. Left unlifted, as in the legacy decoder.
	{ .mask = 0xff000000, .match = 0x05000000, .id = TMS320C55_INS_XCCPART, .lop = C55_LOP_NOP, .xcc_guard = true, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	{ .mask = 0xff000000, .match = 0x06000000, .id = TMS320C55_INS_XCC, .lop = C55_LOP_NOP, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	// bcc #target, <cond> (opcode 0x6a): byte 1 target (8-bit), byte 2 condition
	{ .mask = 0xff000000, .match = 0x6a000000, .id = TMS320C55_INS_BCC, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_addr }, { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	// bcc #target, <cond> (opcode 0x9a, 4 bytes): as 0x6a but with a 16-bit
	// target (bytes 1:2) and the condition byte in byte 3. The condition reuses
	// the shared cond decode/lift, so the tc-flag and register/accumulator
	// compare-with-zero forms lift while the overflow and tc-combination
	// conditions the shared predicate builder does not model fall back to the
	// per-arch lifter (which also leaves them unlifted).
	{ .mask = 0xff000000, .match = 0x9a000000, .id = TMS320C55_INS_BCC, .len = 4, .ops = { { .lo = 8, .width = 16, .fn = c55plus_x_addr }, { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	// bcc #target, <cond> (opcode 0xd8, 5 bytes) and callcc #target, <cond>
	// (opcode 0xd9): a 24-bit absolute target in bytes 1:3 with an 8-bit
	// condition in byte 4 -- the long-immediate-target conditional transfers.
	// The absolute target drives the jump edge; the conditional-transfer
	// analysis adds the fall-through (and, for callcc, the return-address
	// stack metadata).
	{ .mask = 0xff000000, .match = 0xd8000000, .id = TMS320C55_INS_BCC, .len = 5, .ops = { { .lo = 8, .fn = c55plus_x_addr24 }, { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	{ .mask = 0xff000000, .match = 0xd9000000, .id = TMS320C55_INS_CALLCC, .len = 5, .ops = { { .lo = 8, .fn = c55plus_x_addr24 }, { .lo = 0, .width = 8, .fn = c55plus_x_cond } } },
	// bcc/bccu #target, Ra <relop> Rb (opcodes 0xda/0xdb, 5 bytes): target bytes
	// 3:4 (16-bit), condition bytes 1:2 (two registers + split 2-bit relop). As
	// with the reg-immediate forms, 0xda is signed ('bcc') and 0xdb unsigned
	// ('bccu'), selected by uns_all.
	{ .mask = 0xff000000, .match = 0xda000000, .id = TMS320C55_INS_BCC, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr }, { .lo = 16, .width = 16, .fn = c55plus_x_cond_reg } } },
	{ .mask = 0xff000000, .match = 0xdb000000, .id = TMS320C55_INS_BCC, .uns_all = true, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr }, { .lo = 16, .width = 16, .fn = c55plus_x_cond_reg } } },
	// bcc/bccu #target, reg <relop> #imm (opcodes 0xdc/0xdd, 5 bytes): target
	// bytes 3:4 (16-bit), condition bytes 1:2 (register + split 2-bit relop +
	// 7-bit immediate). 0xdc is the signed compare ('bcc'); 0xdd the unsigned
	// one ('bccu') -- distinguished by uns_all, which both selects the 'u'
	// mnemonic suffix and makes the ordered relops lift to ule/uge.
	{ .mask = 0xff000000, .match = 0xdc000000, .id = TMS320C55_INS_BCC, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr }, { .lo = 16, .width = 16, .fn = c55plus_x_cond_imm } } },
	{ .mask = 0xff000000, .match = 0xdd000000, .id = TMS320C55_INS_BCC, .uns_all = true, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr }, { .lo = 16, .width = 16, .fn = c55plus_x_cond_imm } } },
	// bcc/bccu #target, Ra <relop> #k8 (opcodes 0xde/0xdf, 5 bytes): the
	// upper-half (0x80-0xff) immediate variant of the reg-immediate
	// compare-and-branch above. 0xde is signed ('bcc'), 0xdf unsigned ('bccu').
	{ .mask = 0xff000000, .match = 0xde000000, .id = TMS320C55_INS_BCC, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr }, { .lo = 16, .width = 16, .fn = c55plus_x_cond_imm_hi } } },
	{ .mask = 0xff000000, .match = 0xdf000000, .id = TMS320C55_INS_BCC, .uns_all = true, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_addr }, { .lo = 16, .width = 16, .fn = c55plus_x_cond_imm_hi } } },
	// add/sub src, dst (opcode 0x74): dst byte 1 (must be <0x80), src byte 2;
	// bit 7 of the src byte selects add (0) vs sub (1)
	{ .mask = 0xff808000, .match = 0x74000000, .id = TMS320C55_INS_ADD, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0x74008000, .id = TMS320C55_INS_SUB, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	// logic src, dst (opcode 0x75): byte1.bit7 and byte2.bit7 jointly select
	// and (0,0) / or (0,1) / xor (1,0) / not (1,1, unary src->dst)
	{ .mask = 0xff808000, .match = 0x75000000, .id = TMS320C55_INS_AND, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0x75008000, .id = TMS320C55_INS_OR, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0x75800000, .id = TMS320C55_INS_XOR, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0x75808000, .id = TMS320C55_INS_NOT, .ops = { { .lo = 0, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	// sfts/sftl Rb, #S6, Ra (opcode 0xa7, 4 bytes): dst Ra byte1, src Rb byte2
	// (both gr1, low 7 bits), 6-bit signed shift S6 in byte3[5:0]. The
	// (byte1.7, byte2.7, byte3.7) bits select the operation; the two pure shifts
	// are 1/0/0 (sftl, WACa = WACb <<< S6, logical) and 1/1/0 (sfts, WACa = WACb
	// << S6, arithmetic). byte3.7 must be 0 here (it is 1 for the xor / carry
	// variants). Operand order [src, #S6, dst] matches the SFTL/SFTS lifts.
	{ .mask = 0xff808080, .match = 0xa7800000, .id = TMS320C55_INS_SFTL, .lop = C55_LOP_SFTL, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808080, .match = 0xa7808000, .id = TMS320C55_INS_SFTS, .lop = C55_LOP_SFTS, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	// <op> Rb << #S6, Ra (opcode 0xa7 shift-ALU forms, 4 bytes): Ra = Ra <op>
	// (Rb << S6). Same field layout as the pure shifts (dst Ra byte1, src Rb
	// byte2, S6 byte3[5:0]); the (byte1.7, byte2.7, byte3.7) bits select the
	// operation: add (0,0,0), sub (0,1,0), and (0,0,1), or (0,1,1), xor (1,0,1).
	// The shift is rendered "<< #S6" on the source and lifted as an unsigned
	// 8-bit left shift (C55_LOP_*SHL, operand order [src, #S6, dst]).
	{ .mask = 0xff808080, .match = 0xa7000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6_shl }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808080, .match = 0xa7008000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6_shl }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808080, .match = 0xa7000080, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDSHL, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6_shl }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808080, .match = 0xa7008080, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORSHL, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6_shl }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808080, .match = 0xa7800080, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORSHL, .ops = { { .lo = 8, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 0, .width = 6, .fn = c55plus_x_shift6_shl }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	// cmp/cmpu Ra <relop> Rb, TCx (opcode 0xa4 CMPR_RR_10, 4 bytes): TCx = (Ra
	// <relop> Rb). Ra byte1, Rb byte2 (both gr1), relop byte3[3:2], TCx dst
	// byte3[0]. byte1.7/byte2.7 must be 0 (the cmpand/cmpor and Ra-vs-#0 variants
	// set those / byte3.7). byte3[5] is the $ unsigned bit: separate rows pin it,
	// the unsigned one carrying uns_all (the 'u' suffix and unsigned compare).
	{ .mask = 0xff8080a0, .match = 0xa4000000, .id = TMS320C55_INS_CMP, .lop = C55_LOP_CMP, .ops = { { .fn = c55plus_x_cmpcond }, { .fn = c55plus_x_tcflag } } },
	{ .mask = 0xff8080a0, .match = 0xa4000020, .id = TMS320C55_INS_CMP, .lop = C55_LOP_CMP, .uns_all = true, .ops = { { .fn = c55plus_x_cmpcond }, { .fn = c55plus_x_tcflag } } },
	// cmpand/cmpor[u] Ra <relop> Rb, [!]TCx, TCz (opcode 0xa4, byte3[7]==1, 4
	// bytes): TCz = (Ra <relop> Rb) {&&,||} [!]TCx. byte2[7] selects cmpand (0)
	// vs cmpor (1); byte3[5] is the unsigned $ bit (the 'u' suffix, uns_all);
	// byte3[1] picks the TCx input (negated when byte1[7] is set); byte3[0] picks
	// the TCz output. Lifts via the shared cmpand/cmpor path, which models the
	// compare, the negation, and the and/or with the input flag.
	{ .mask = 0xff0080a0, .match = 0xa4000080, .id = TMS320C55_INS_CMPAND, .lop = C55_LOP_CMPAND, .len = 4, .ops = { { .fn = c55plus_x_cmpcond }, { .fn = c55plus_x_cmp_tcin }, { .fn = c55plus_x_tcflag } } },
	{ .mask = 0xff0080a0, .match = 0xa40000a0, .id = TMS320C55_INS_CMPAND, .lop = C55_LOP_CMPAND, .len = 4, .uns_all = true, .ops = { { .fn = c55plus_x_cmpcond }, { .fn = c55plus_x_cmp_tcin }, { .fn = c55plus_x_tcflag } } },
	{ .mask = 0xff0080a0, .match = 0xa4008080, .id = TMS320C55_INS_CMPOR, .lop = C55_LOP_CMPOR, .len = 4, .ops = { { .fn = c55plus_x_cmpcond }, { .fn = c55plus_x_cmp_tcin }, { .fn = c55plus_x_tcflag } } },
	{ .mask = 0xff0080a0, .match = 0xa40080a0, .id = TMS320C55_INS_CMPOR, .lop = C55_LOP_CMPOR, .len = 4, .uns_all = true, .ops = { { .fn = c55plus_x_cmpcond }, { .fn = c55plus_x_cmp_tcin }, { .fn = c55plus_x_tcflag } } },
	// mov/add/sub #k4, Ra (opcode 0x7b register-short forms, 3 bytes): Ra is
	// byte1 (gr1, low 7 bits), the 4-bit immediate k4 is byte2[3:0]. The
	// (byte1.7 A, byte2.7 B) pair selects the operation when byte2[5] (M) is 0:
	// add (0,0), sub (0,1), mov #k4 (1,0), mov -#k4 (1,1). The M=1 forms are the
	// shift-by-one variants, left to the legacy decoder for now (mask pins M=0).
	{ .mask = 0xff80a000, .match = 0x7b000000, .id = TMS320C55_INS_ADD, .ops = { { .lo = 0, .width = 4, .fn = c55plus_x_k4 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff80a000, .match = 0x7b008000, .id = TMS320C55_INS_SUB, .ops = { { .lo = 0, .width = 4, .fn = c55plus_x_k4 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff80a000, .match = 0x7b800000, .id = TMS320C55_INS_MOV, .ops = { { .lo = 0, .width = 4, .fn = c55plus_x_k4 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff80a000, .match = 0x7b808000, .id = TMS320C55_INS_MOV, .ops = { { .lo = 0, .width = 4, .fn = c55plus_x_negk4 }, { .lo = 8, .width = 8, .fn = c55plus_x_gr7 } } },
	// Ra = Rb <op> k16 (opcodes 0xc4/0xc5, 5 bytes): dst Ra byte1, src Rb byte2
	// (both gr1, low 7 bits), 16-bit immediate bytes 3:4. The (byte1.7, byte2.7)
	// pair selects the operation -- 0xc4: add (0,0) / sub (0,1); 0xc5: and (0,0)
	// / or (0,1) / xor (1,0). Operand order [#k16, src, dst] matches the 0x7b-7f
	// *K forms, so the same C55_LOP_*K lifts apply (extended to the gr1
	// sub-register operands these forms can carry).
	{ .mask = 0xff808000, .match = 0xc4000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDK, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 24, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0xc4008000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBK, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 24, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0xc5000000, .id = TMS320C55_INS_AND, .lop = C55_LOP_ANDK, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 24, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0xc5008000, .id = TMS320C55_INS_OR, .lop = C55_LOP_ORK, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 24, .width = 8, .fn = c55plus_x_gr7 } } },
	{ .mask = 0xff808000, .match = 0xc5800000, .id = TMS320C55_INS_XOR, .lop = C55_LOP_XORK, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 }, { .lo = 24, .width = 8, .fn = c55plus_x_gr7 } } },
	// mov #imm16, reg (opcode 0xac, 4 bytes): dst byte 1 (high bit ignored),
	// immediate bytes 2:3
	{ .mask = 0xff000000, .match = 0xac000000, .id = TMS320C55_INS_MOV, .ops = { { .lo = 0, .width = 16, .fn = c55plus_x_imm16 }, { .lo = 16, .width = 8, .fn = c55plus_x_gr7 } } },
	// mov Smem, ACx (opcode 0x58, 3 bytes): register-indirect load. The
	// register-modify matrix and plain indirect decode here; other Smem forms
	// fall back to the legacy decoder (see c55plus_x_smem).
	{ .mask = 0xff000000, .match = 0x58000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_smem }, { .fn = c55plus_x_smem_ac } } },
	// mov ACx.h/.l, *Smem (opcode 0x51, base 3 bytes): a 16-bit word store of an
	// accumulator half (byte2[5] selects the half). This handles the SP-relative
	// and absolute destinations via c55plus_x_word_mem and must precede the
	// register-indirect-only row below, which still covers the modes
	// c55plus_mem_addr declines (e.g. DP-direct).
	{ .mask = 0xff000000, .match = 0x51000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_acc_half }, { .fn = c55plus_x_word_mem } } },
	// mov ACx.h/.l, Smem (opcode 0x51, 3 bytes): register-indirect store. The
	// accumulator half is byte2[5]; the Smem destination uses the same
	// addressing matrix as the load, with the same legacy fallback.
	{ .mask = 0xff000000, .match = 0x51000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_ac_part }, { .fn = c55plus_x_smem_dest } } },
	// copy(ALLa = Smem) (opcode 0x54-0x57 LD_R, 3+ bytes): load a memory operand
	// into any register. The 8-bit register id is byte0[1:0]:byte2[5:0]; the Smem
	// source uses the standard byte1:byte2[7:6] addressing matrix, and the access
	// is dbl iff the destination is a long (>16-bit) register. Verified against TI
	// dis55 and SWPU104.
	{ .mask = 0xfc000000, .match = 0x54000000, .id = TMS320C55_INS_COPY, .ops = { { .fn = c55plus_x_copy_smem }, { .fn = c55plus_x_copy_alla } } },
	// copy dbl(*(#addr)), xar (opcode 0xd1, 5 bytes): the absolute-address form of
	// the double-word load. byte1[7:6]==10 selects the dbl xar destination
	// (byte1[3:0]); the 24-bit byte address is bytes 2:4. Accumulator and
	// byte/half destination forms fall back to the legacy decoder.
	// mov reg, *(#addr) absolute register stores (opcode 0xd0, 5 bytes): byte1[7:5]
	// selects the register type -- 000 ACx (dbl), 001 ARn, 010 ACx.h, 011 ACx.l,
	// 100 XARn (dbl) -- byte1[4:0] the register, and bytes 2-4 the 24-bit byte
	// address. The remaining types (ACx.g, XARn.h, status) fall back to legacy.
	{ .mask = 0xffe00000, .match = 0xd0000000, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_acc_b1 }, { .fn = c55plus_x_abs_dbl } } },
	{ .mask = 0xffe00000, .match = 0xd0200000, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_ar_src }, { .fn = c55plus_x_abs_word } } },
	{ .mask = 0xffe00000, .match = 0xd0400000, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_acc_hi_b1 }, { .fn = c55plus_x_abs_word } } },
	{ .mask = 0xffe00000, .match = 0xd0600000, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_acc_lo_b1 }, { .fn = c55plus_x_abs_word } } },
	{ .mask = 0xffe00000, .match = 0xd0800000, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_xar_b1 }, { .fn = c55plus_x_abs_dbl } } },
	{ .mask = 0xff000000, .match = 0xd1000000, .id = TMS320C55_INS_COPY, .ops = { { .fn = c55plus_x_copy_abs_mem }, { .fn = c55plus_x_copy_abs_xar } } },
	// mov ACx, dbl(*Smem) (opcode 0x50, base 3 bytes, byte2[5]==0): a 32-bit
	// double-word store of the low 32 bits of a whole accumulator. This is the
	// accumulator (dbl()) sub-form of the 0x50 store and must precede the general
	// gr6 store row below; the byte2[5]==1 sub-form (mov ARx/Tx, Smem) is handled
	// there.
	{ .mask = 0xff002000, .match = 0x50000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_acc_src }, { .fn = c55plus_x_dbl_mem } } },
	// mov reg, Smem (opcode 0x50, 3 bytes): the store mirror of copy, with the
	// register source in byte2[5:0]. Accumulator sources (dbl() memory) and
	// reserved slots fall back to the legacy decoder.
	{ .mask = 0xff000000, .match = 0x50000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_gr6 }, { .fn = c55plus_x_smem_dest } } },
	// mov byte(*Smem), reg / mov reg, byte(*Smem) (opcode 0x8a, base 4 bytes):
	// an 8-bit byte() load/store with standard Smem addressing. byte3[7]==1 marks
	// the plain byte() forms decoded and lifted here; byte3[6] selects load (1) or
	// store (0). The load form reads [mem, reg], the store [reg, mem]. The
	// high_byte()/low_byte() variants (byte3[7]==0) are decoded disasm-only below.
	{ .mask = 0xff0000c0, .match = 0x8a0000c0, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_byte_mem }, { .fn = c55plus_x_byte_reg } } },
	{ .mask = 0xff0000c0, .match = 0x8a000080, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_byte_reg }, { .fn = c55plus_x_byte_mem } } },
	// mov *Smem, ACx.l (opcode 0x5b, base 3 bytes): a 16-bit word load into the
	// low half of an accumulator. byte2[4:0] is the accumulator.
	{ .mask = 0xff000000, .match = 0x5b000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_word_mem }, { .fn = c55plus_x_acc_lo } } },
	// mov dbl(*Smem), ACx (opcode 0x5c, base 3 bytes): a 32-bit double-word load
	// sign-extended into a whole accumulator.
	{ .mask = 0xff000000, .match = 0x5c000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_dbl_mem }, { .fn = c55plus_x_acc } } },
	// mov *Smem, ACx.h (opcode 0x5a, base 3 bytes): a 16-bit word load into the
	// high half of an accumulator (byte2[5] is the uns() qualifier).
	{ .mask = 0xff000000, .match = 0x5a000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_word_mem_u }, { .fn = c55plus_x_acc_hi } } },
	// mov #imm, *Smem (opcode 0x48, base 3 bytes): a 16-bit word store of a 6-bit
	// immediate (byte2[5:0]).
	{ .mask = 0xff000000, .match = 0x48000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_imm6 }, { .fn = c55plus_x_word_mem } } },
	// mov XARx, dbl(*Smem) (opcode 0x52, base 3 bytes): a 32-bit double-word store
	// of an extended AR pointer.
	{ .mask = 0xff000000, .match = 0x52000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_xar_src }, { .fn = c55plus_x_dbl_mem } } },
	// mov #imm, byte(*Smem) (opcode 0x4c, base 3 bytes): an 8-bit store of a 6-bit
	// immediate (byte2[5:0]) to a byte() memory location.
	{ .mask = 0xff000000, .match = 0x4c000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_imm6 }, { .fn = c55plus_x_byte_dst } } },
	// mov #imm, byte(*Smem) (opcodes 0x4d/0x4e/0x4f): the 0x40/0x80/0xc0 immediate
	// ranges of the same byte store.
	{ .mask = 0xff000000, .match = 0x4d000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_imm6_40 }, { .fn = c55plus_x_byte_dst } } },
	{ .mask = 0xff000000, .match = 0x4e000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_imm6_80 }, { .fn = c55plus_x_byte_dst } } },
	{ .mask = 0xff000000, .match = 0x4f000000, .id = TMS320C55_INS_MOV, .ops = { { .fn = c55plus_x_imm6_c0 }, { .fn = c55plus_x_byte_dst } } },
	// A-unit register-register modify (opcode 0x72): mar(WDAa op WDAb). Two
	// 6-bit WDA register fields, dst = byte1[5:0] (Aaaaaa), src = byte2[5:0]
	// (Bbbbbb); the top bit of each byte selects the operation -- (1,0) amov
	// (MX), (0,1) aadd (AX), (0,0) asub (SX). The amov/asub register moves
	// reuse the shared AREG lift; aadd's address-add stays analysis-only here
	// (no AREG-add lift op), matching the C55x register-AADD treatment.
	{ .mask = 0xff808000, .match = 0x72800000, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AREG_MOV, .len = 3, .ops = { { .lo = 0, .fn = c55plus_x_wda }, { .lo = 8, .fn = c55plus_x_wda } } },
	{ .mask = 0xff808000, .match = 0x72008000, .id = TMS320C55_INS_AADD, .len = 3, .ops = { { .lo = 0, .fn = c55plus_x_wda }, { .lo = 8, .fn = c55plus_x_wda } } },
	{ .mask = 0xff808000, .match = 0x72000000, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 3, .ops = { { .lo = 0, .fn = c55plus_x_wda }, { .lo = 8, .fn = c55plus_x_wda } } },
	// Bit-test register-target forms (opcode 0x89, 4 bytes), the "@#bitnum,
	// register" variants. byte1[7]==0 selects the @#k bit-number form (the SP-mem
	// forms are not handled here), byte2[7:6]==11 the register target. byte3[7:5]
	// selects the operation and operand order; only the "@#k, register" orders
	// are taken (000/010 reg-first orders fall through). byte2[5] selects
	// bclr/bset for the clear/set group and TC1/TC2 for btst. Left unlifted.
	{ .mask = 0xff80e0e0, .match = 0x8900c020, .id = TMS320C55_INS_BCLR, .lop = C55_LOP_BITCLR, .len = 4, .ops = { { .fn = c55plus_x_bit_num }, { .fn = c55plus_x_bit_reg } } },
	{ .mask = 0xff80e0e0, .match = 0x8900e020, .id = TMS320C55_INS_BSET, .lop = C55_LOP_BITSET, .len = 4, .ops = { { .fn = c55plus_x_bit_num }, { .fn = c55plus_x_bit_reg } } },
	{ .mask = 0xff80c0e0, .match = 0x8900c060, .id = TMS320C55_INS_BNOT, .lop = C55_LOP_BITNOT, .len = 4, .ops = { { .fn = c55plus_x_bit_num }, { .fn = c55plus_x_bit_reg } } },
	{ .mask = 0xff80c0e0, .match = 0x8900c0a0, .id = TMS320C55_INS_BTST, .len = 4, .ops = { { .fn = c55plus_x_bit_num }, { .fn = c55plus_x_bit_reg }, { .fn = c55plus_x_bit_tc } } },
	{ .mask = 0xff80c0e0, .match = 0x8900c0e0, .id = TMS320C55_INS_BTSTP, .len = 4, .ops = { { .fn = c55plus_x_bit_num }, { .fn = c55plus_x_bit_reg } } },
	// add/mov #k16, [dbl(]*Smem[)] (opcode 0xb1, base 5 bytes). byte2[4:3] selects
	// the operation (00 = add, 11 = mov); only mov lifts (a store). The 16-bit
	// immediate occupies bytes 3:4 of the base; addressing extensions follow.
	{ .mask = 0xff001800, .match = 0xb1000000, .id = TMS320C55_INS_ADD, .len = 5, .ops = { { .fn = c55plus_x_b1_imm }, { .fn = c55plus_x_b1_mem } } },
	{ .mask = 0xff001800, .match = 0xb1001800, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_b1_imm }, { .fn = c55plus_x_b1_mem } } },
	// sftl/sfts REG, #1 / #-1 (opcode 0x7b, 3 bytes, byte2[6:5]==01). byte1[7]
	// selects sftl vs sfts; byte2[7] the shift sign. Left unlifted.
	{ .mask = 0xff806000, .match = 0x7b002000, .id = TMS320C55_INS_SFTS, .lop = C55_LOP_SFTS, .len = 3, .ops = { { .fn = c55plus_x_sft7b_reg }, { .fn = c55plus_x_sft7b_one } } },
	{ .mask = 0xff806000, .match = 0x7b802000, .id = TMS320C55_INS_SFTL, .lop = C55_LOP_SFTL, .len = 3, .ops = { { .fn = c55plus_x_sft7b_reg }, { .fn = c55plus_x_sft7b_one } } },
	// sftl/sfts SRC, SHIFT, DST (opcode 0xa6, byte1[7]==1, byte3[7]==0). byte2[7]
	// selects sftl (0) vs sfts (1). The byte3[7]==1 saturating sftsc variant is
	// handled by the row below; the saturating sftl form is invalid. Left unlifted.
	{ .mask = 0xff808080, .match = 0xa6800000, .id = TMS320C55_INS_SFTL, .lop = C55_LOP_SFTL, .len = 4, .ops = { { .fn = c55plus_x_sft_src }, { .fn = c55plus_x_sft_shift }, { .fn = c55plus_x_sft_dst } } },
	{ .mask = 0xff808080, .match = 0xa6808000, .id = TMS320C55_INS_SFTS, .lop = C55_LOP_SFTS, .len = 4, .ops = { { .fn = c55plus_x_sft_src }, { .fn = c55plus_x_sft_shift }, { .fn = c55plus_x_sft_dst } } },
	// sftsc SRC, SHIFT, DST (opcode 0xa6, byte1[7]==1, byte2[7]==1, byte3[7]==1):
	// the saturating variant of sfts. Same operands as sfts; left unlifted, as in
	// the legacy decoder. (The byte2[7]==0 saturating form is invalid.)
	{ .mask = 0xff808080, .match = 0xa6808080, .id = TMS320C55_INS_SFTSC, .len = 4, .ops = { { .fn = c55plus_x_sft_src }, { .fn = c55plus_x_sft_shift }, { .fn = c55plus_x_sft_dst } } },
	// mov [byte(]*Smem[)], [byte(]*Smem[)] (opcode 0x97, 4 bytes). byte2[3] is the
	// direction: 1 -> operand A (byte1) is the source, 0 -> operand B (byte3) is
	// the source. Left unlifted.
	{ .mask = 0xff000800, .match = 0x97000800, .id = TMS320C55_INS_MOV, .len = 4, .ops = { { .fn = c55plus_x_97_memA }, { .fn = c55plus_x_97_memB } } },
	{ .mask = 0xff000800, .match = 0x97000000, .id = TMS320C55_INS_MOV, .len = 4, .ops = { { .fn = c55plus_x_97_memB }, { .fn = c55plus_x_97_memA } } },
	// band *Smem, #k16, TCx (opcode 0xb2, byte2[3]==1, 5 bytes): TCx = (Smem &
	// #k16) == 0. Shares the opcode with the cmp form below (byte2[3]==0); the
	// band row is matched first since it is the more specific pattern. Left
	// unlifted, as in the legacy decoder.
	{ .mask = 0xff000800, .match = 0xb2000800, .id = TMS320C55_INS_BAND, .len = 5, .ops = { { .fn = c55plus_x_b2_band_mem }, { .fn = c55plus_x_b2_band_k16 }, { .fn = c55plus_x_b2_tc } } },
	// cmp Smem <rel> #k16, TCx (opcode 0xb2, base 5 bytes, byte2[3]==0 cmp).
	// Left unlifted.
	{ .mask = 0xff080000, .match = 0xb2000000, .id = TMS320C55_INS_CMP, .len = 5, .ops = { { .fn = c55plus_x_b2_cmp }, { .fn = c55plus_x_b2_tc } } },
	// mov ACx.<h/l>, mmap(@reg) (opcode 0x24, byte1==0x51, byte3[6]==0). Left
	// unlifted.
	{ .mask = 0xffff0040, .match = 0x24510000, .id = TMS320C55_INS_MOV, .len = 4, .ops = { { .fn = c55plus_x_24_src }, { .fn = c55plus_x_24_mmr } } },
	// sftcc ACx, TCx (opcode 0xa9, byte1[7]==1 && byte2[7]==1, 4 bytes). Left
	// unlifted (C55_LOP_OPAQUE), as in the legacy decoder.
	{ .mask = 0xff808000, .match = 0xa9808000, .id = TMS320C55_INS_SFTCC, .lop = C55_LOP_OPAQUE, .len = 4, .ops = { { .fn = c55plus_x_a9_sftcc_ac }, { .fn = c55plus_x_a9_sftcc_tc } } },
	// bcnt ACa, ACb, TCx, ACdst (opcode 0xa9, byte1[7]==1 && byte2[7]==0, 4 bytes).
	// Left unlifted (C55_LOP_OPAQUE), as in the legacy decoder. (byte2[7]==1 is
	// the sftcc form, which stays on the legacy decoder.)
	{ .mask = 0xff808000, .match = 0xa9800000, .id = TMS320C55_INS_BCNT, .lop = C55_LOP_OPAQUE, .len = 4, .ops = { { .fn = c55plus_x_a9_bcnt_a }, { .fn = c55plus_x_a9_bcnt_b }, { .fn = c55plus_x_a9_bcnt_tc }, { .fn = c55plus_x_a9_bcnt_dst } } },
	// exp ACsrc, ACdst (opcode 0xa9, byte1[7]==0 && byte2[7]==0, 4 bytes). Left
	// unlifted (C55_LOP_OPAQUE), as in the legacy decoder.
	{ .mask = 0xff808000, .match = 0xa9000000, .id = TMS320C55_INS_EXP, .lop = C55_LOP_OPAQUE, .len = 4, .ops = { { .fn = c55plus_x_a9_exp_src }, { .fn = c55plus_x_a9_exp_dst } } },
	// btst *Smem, reg, TCx (opcode 0x89, byte3[7:5]==101, 4 bytes): memory bit test
	// against a register-selected bit number. Left unlifted, as in the legacy
	// decoder.
	{ .mask = 0xff0000e0, .match = 0x890000a0, .id = TMS320C55_INS_BTST, .len = 4, .ops = { { .fn = c55plus_x_btm_smem }, { .fn = c55plus_x_btm_reg }, { .fn = c55plus_x_btm_tc } } },
	// subadd Tx, [dual(]*Smem[)], ACx (opcode 0x8f, byte3[7:6]==11, 4 bytes): the
	// dual-access subtract-add. Left unlifted, as in the legacy decoder.
	{ .mask = 0xff0000c0, .match = 0x8f0000c0, .id = TMS320C55_INS_SUBADD, .len = 4, .ops = { { .fn = c55plus_x_subadd_tx }, { .fn = c55plus_x_subadd_mem }, { .fn = c55plus_x_subadd_acx } } },
	// bfxtr ACc.<h/l>, ACb.<h/l>, *Smem, ACa.<h/l> (opcode 0xbc, byte3[6]==0, 5
	// bytes): the memory-operand bit-field extract. byte3[6]==0 excludes bfins; the
	// ACb extractor rejects the byte4[7:6] bfxtl / dbfxtr variants. Left unlifted.
	{ .mask = 0xff000040, .match = 0xbc000000, .id = TMS320C55_INS_BFXTR, .lop = C55_LOP_OPAQUE, .len = 5, .ops = { { .fn = c55plus_x_bcx_acc }, { .fn = c55plus_x_bcx_acb }, { .fn = c55plus_x_bcx_smem }, { .fn = c55plus_x_bcx_aca } } },
	// mpym / macm / masm t3 = Smem, ACx, [ACy,] ACz (opcode 0xbb, 5 bytes): single-
	// memory MAC with a "t3 = Smem" side-load. byte3[7:6] selects 00 mpym (3 ops) /
	// 01 macm / 10 masm (4 ops); byte3[5] is the whole-operation uns (mpymu/macmu/
	// masmu). round (byte2[5]) and fractional (byte4[7]) via .mods. Left unlifted
	// (the side-load three-accumulator form is not modelled), as in legacy.
	{ .mask = 0xff0000e0, .match = 0xbb000000, .id = TMS320C55_INS_MPYM, .len = 5, .mods = 0x200016, .side_load = true, .ops = { { .fn = c55plus_x_bb_smem }, { .fn = c55plus_x_bb_acx }, { .fn = c55plus_x_bb_acz } } },
	{ .mask = 0xff0000e0, .match = 0xbb000020, .id = TMS320C55_INS_MPYM, .len = 5, .mods = 0x200016, .side_load = true, .uns_all = true, .ops = { { .fn = c55plus_x_bb_smem }, { .fn = c55plus_x_bb_acx }, { .fn = c55plus_x_bb_acz } } },
	{ .mask = 0xff0000e0, .match = 0xbb000040, .id = TMS320C55_INS_MACM, .len = 5, .mods = 0x200016, .side_load = true, .ops = { { .fn = c55plus_x_bb_smem }, { .fn = c55plus_x_bb_acx }, { .fn = c55plus_x_bb_acy }, { .fn = c55plus_x_bb_acz } } },
	{ .mask = 0xff0000e0, .match = 0xbb000060, .id = TMS320C55_INS_MACM, .len = 5, .mods = 0x200016, .side_load = true, .uns_all = true, .ops = { { .fn = c55plus_x_bb_smem }, { .fn = c55plus_x_bb_acx }, { .fn = c55plus_x_bb_acy }, { .fn = c55plus_x_bb_acz } } },
	{ .mask = 0xff0000e0, .match = 0xbb000080, .id = TMS320C55_INS_MASM, .len = 5, .mods = 0x200016, .side_load = true, .ops = { { .fn = c55plus_x_bb_smem }, { .fn = c55plus_x_bb_acx }, { .fn = c55plus_x_bb_acy }, { .fn = c55plus_x_bb_acz } } },
	{ .mask = 0xff0000e0, .match = 0xbb0000a0, .id = TMS320C55_INS_MASM, .len = 5, .mods = 0x200016, .side_load = true, .uns_all = true, .ops = { { .fn = c55plus_x_bb_smem }, { .fn = c55plus_x_bb_acx }, { .fn = c55plus_x_bb_acy }, { .fn = c55plus_x_bb_acz } } },
	// mpym / macm / masm Xmem, Ymem, ACy (opcode 0xe0, 6 bytes): the long-form
	// dual-data-memory multiply family. byte3[7:6] selects 00 mpym / 01 macm / 10
	// masm; round (byte2[5]), m40 (byte4[0]) and fractional (byte5[7]) via .mods.
	// These lift via the shared multiply-accumulate path. (The byte3[7:6]==11
	// macmz zero-accumulate form stays on the legacy decoder.)
	{ .mask = 0xff0000c0, .match = 0xe0000000, .id = TMS320C55_INS_MPYM, .len = 6, .mods = 0x20901e, .ops = { { .fn = c55plus_x_e0_xmem }, { .fn = c55plus_x_e0_ymem }, { .fn = c55plus_x_e0_acy } } },
	{ .mask = 0xff0000c0, .match = 0xe0000040, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 6, .mods = 0x20901e, .ops = { { .fn = c55plus_x_e0_xmem }, { .fn = c55plus_x_e0_ymem }, { .fn = c55plus_x_e0_acy } } },
	{ .mask = 0xff0000c0, .match = 0xe0000080, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 6, .mods = 0x20901e, .ops = { { .fn = c55plus_x_e0_xmem }, { .fn = c55plus_x_e0_ymem }, { .fn = c55plus_x_e0_acy } } },
	// firsadd / firssub Xmem, Ymem, Cmem, ACx, ACy (opcode 0xeb, 6 bytes): byte1[7]
	// (in the match head) is 0 for the firs form (the byte1[7]==1 amar::mpy form
	// stays on the legacy decoder) and byte2[7]==1 selects firs over the other
	// byte2[7]==0 form. The firssub vs firsadd selector (byte4[6]) and the
	// fractional modifier (byte5[7]) lie beyond the 4-byte match head, so they are
	// applied via alt_bit (-> firssub) and the shared .mods fractional packing.
	// These lift via the shared C55_LOP_FIRSADD / FIRSSUB dual-operation path.
	{ .mask = 0xff808000, .match = 0xeb008000, .id = TMS320C55_INS_FIRSADD, .lop = C55_LOP_FIRSADD, .len = 6, .alt_bit = 15, .alt_id = TMS320C55_INS_FIRSSUB, .alt_lop = C55_LOP_FIRSSUB, .mods = (8u << 18), .ops = { { .fn = c55plus_x_fir_xmem }, { .fn = c55plus_x_fir_ymem }, { .fn = c55plus_x_fir_cmem }, { .fn = c55plus_x_fir_acx }, { .fn = c55plus_x_fir_acy } } },
	// abdst / lms / lmsf / sqdst Xmem, Ymem, ACx, ACy (opcode 0xce, 5 bytes): the
	// operation is selected by (byte1[7], byte3[7], byte2[7]): (0,0,0) sqdst,
	// (0,0,1) abdst, (1,1,0) lms, (1,1,1) lmsf. byte4[7] is an additional
	// fractional modifier (so lms->lmsf and lmsf->lmsff), decoded through the
	// shared .mods packing. These lift via the shared dual-operation path.
	{ .mask = 0xff808080, .match = 0xce000000, .id = TMS320C55_INS_SQDST, .lop = C55_LOP_SQDST, .len = 5, .ops = { { .fn = c55plus_x_dst_xmem }, { .fn = c55plus_x_dst_ymem }, { .fn = c55plus_x_dst_acx }, { .fn = c55plus_x_dst_acy } } },
	{ .mask = 0xff808080, .match = 0xce008000, .id = TMS320C55_INS_ABDST, .lop = C55_LOP_ABDST, .len = 5, .ops = { { .fn = c55plus_x_dst_xmem }, { .fn = c55plus_x_dst_ymem }, { .fn = c55plus_x_dst_acx }, { .fn = c55plus_x_dst_acy } } },
	{ .mask = 0xff808080, .match = 0xce800080, .id = TMS320C55_INS_LMS, .lop = C55_LOP_LMS, .len = 5, .mods = (8u << 18), .ops = { { .fn = c55plus_x_dst_xmem }, { .fn = c55plus_x_dst_ymem }, { .fn = c55plus_x_dst_acx }, { .fn = c55plus_x_dst_acy } } },
	{ .mask = 0xff808080, .match = 0xce808080, .id = TMS320C55_INS_LMSF, .lop = C55_LOP_LMS, .len = 5, .mods = (8u << 18), .ops = { { .fn = c55plus_x_dst_xmem }, { .fn = c55plus_x_dst_ymem }, { .fn = c55plus_x_dst_acx }, { .fn = c55plus_x_dst_acy } } },
	// maxdiff / mindiff / dmaxdiff / dmindiff ACc, ACd, ACa, ACb, [pair(]trnN[)]
	// (opcode 0xd4, 5 bytes): byte1[7] selects the d-variant (bare trn over the
	// pair()-wrapped form), byte2[7] the min-variant. Rendered via diff_form; left
	// unlifted, as in the legacy decoder.
	{ .mask = 0xff808000, .match = 0xd4000000, .id = TMS320C55_INS_MAXDIFF, .len = 5, .diff_form = true, .diff_pair = true, .ops = { { .fn = c55plus_x_diff_acc }, { .fn = c55plus_x_diff_acd }, { .fn = c55plus_x_diff_aca }, { .fn = c55plus_x_diff_acb }, { .fn = c55plus_x_diff_trn } } },
	{ .mask = 0xff808000, .match = 0xd4008000, .id = TMS320C55_INS_MINDIFF, .len = 5, .diff_form = true, .diff_pair = true, .ops = { { .fn = c55plus_x_diff_acc }, { .fn = c55plus_x_diff_acd }, { .fn = c55plus_x_diff_aca }, { .fn = c55plus_x_diff_acb }, { .fn = c55plus_x_diff_trn } } },
	{ .mask = 0xff808000, .match = 0xd4800000, .id = TMS320C55_INS_DMAXDIFF, .len = 5, .diff_form = true, .ops = { { .fn = c55plus_x_diff_acc }, { .fn = c55plus_x_diff_acd }, { .fn = c55plus_x_diff_aca }, { .fn = c55plus_x_diff_acb }, { .fn = c55plus_x_diff_trn } } },
	{ .mask = 0xff808000, .match = 0xd4808000, .id = TMS320C55_INS_DMINDIFF, .len = 5, .diff_form = true, .ops = { { .fn = c55plus_x_diff_acc }, { .fn = c55plus_x_diff_acd }, { .fn = c55plus_x_diff_aca }, { .fn = c55plus_x_diff_acb }, { .fn = c55plus_x_diff_trn } } },
	// sqrm / sqam / sqsm *Smem, [ACx,] ACy (opcode 0x92, 4 bytes): square a memory
	// operand. byte3[7:5] selects the operation: 000 sqrm (ACy = Smem*Smem, no
	// accumulate), 010 sqam (ACy = ACx + Smem*Smem), 100 sqsm (subtract). round =
	// byte2[5], fractional = byte3[5], both via the shared .mods packing. Lift via
	// the shared squaring multiply path.
	{ .mask = 0xff0000e0, .match = 0x92000000, .id = TMS320C55_INS_SQRM, .len = 4, .mods = 0x18000e, .square = true, .ops = { { .fn = c55plus_x_sq_mem }, { .fn = c55plus_x_sq_acy } } },
	{ .mask = 0xff0000e0, .match = 0x92000040, .id = TMS320C55_INS_SQAM, .lop = C55_LOP_MAC, .len = 4, .mods = 0x18000e, .square = true, .ops = { { .fn = c55plus_x_sq_mem }, { .fn = c55plus_x_sq_acx }, { .fn = c55plus_x_sq_acy } } },
	{ .mask = 0xff0000e0, .match = 0x92000080, .id = TMS320C55_INS_SQSM, .lop = C55_LOP_MAS, .len = 4, .mods = 0x18000e, .square = true, .ops = { { .fn = c55plus_x_sq_mem }, { .fn = c55plus_x_sq_acx }, { .fn = c55plus_x_sq_acy } } },
	// mpymk Xmem, #k8, ACy (opcode 0xb8, byte3[6]==0, 5 bytes) and macmk Xmem, #k8,
	// ACx, ACy (byte3[6]==1): constant-coefficient memory multiply / multiply-
	// accumulate. byte3[5] is the fractional (f) modifier. Left unlifted, as in the
	// legacy decoder.
	{ .mask = 0xff000040, .match = 0xb8000000, .id = TMS320C55_INS_MPYMK, .len = 5, .mods = (14u << 18), .ops = { { .fn = c55plus_x_mpymk_mem }, { .fn = c55plus_x_mpymk_k8 }, { .fn = c55plus_x_mpymk_acy } } },
	{ .mask = 0xff000040, .match = 0xb8000040, .id = TMS320C55_INS_MACMK, .len = 5, .mods = (14u << 18), .ops = { { .fn = c55plus_x_mpymk_mem }, { .fn = c55plus_x_mpymk_k8 }, { .fn = c55plus_x_mpymk_acx }, { .fn = c55plus_x_mpymk_acy } } },
	// mpymk / macmk t3 = Xmem, #k8, [ACx,] ACy (opcode 0xb9, 5 bytes): the side-load
	// ("t3 = Xmem") sibling of the 0xb8 constant-coefficient memory multiply, with
	// the identical field layout. Left unlifted, as in the legacy decoder.
	{ .mask = 0xff000040, .match = 0xb9000000, .id = TMS320C55_INS_MPYMK, .len = 5, .mods = (14u << 18), .side_load = true, .ops = { { .fn = c55plus_x_mpymk_mem }, { .fn = c55plus_x_mpymk_k8 }, { .fn = c55plus_x_mpymk_acy } } },
	{ .mask = 0xff000040, .match = 0xb9000040, .id = TMS320C55_INS_MACMK, .len = 5, .mods = (14u << 18), .side_load = true, .ops = { { .fn = c55plus_x_mpymk_mem }, { .fn = c55plus_x_mpymk_k8 }, { .fn = c55plus_x_mpymk_acx }, { .fn = c55plus_x_mpymk_acy } } },
	// mant ACa, ACb :: nexp ACa, ACc (opcode 0xa9, byte1[7]==0 && byte2[7]==1, 4
	// bytes): dual mantissa / negated-exponent helper, rendered via the mant_nexp
	// flag. Left unlifted, as in the legacy decoder.
	{ .mask = 0xff808000, .match = 0xa9008000, .id = TMS320C55_INS_MANT, .lop = C55_LOP_OPAQUE, .len = 4, .mant_nexp = true, .ops = { { .fn = c55plus_x_mant_aca }, { .fn = c55plus_x_mant_acb }, { .fn = c55plus_x_mant_acc } } },
	// rpt csr / rptadd csr, #k|reg / rptsub csr, #k (opcode 0x01, 2 bytes).
	// byte1[7:6]: 00 rptsub #k, 01 rptadd #k, 10 rptadd reg, 11 rpt. All nop-lift.
	{ .mask = 0xffc00000, .match = 0x01000000, .id = TMS320C55_INS_RPTSUB, .lop = C55_LOP_RPTSUB, .len = 2, .ops = { { .fn = c55plus_x_01_csr }, { .fn = c55plus_x_01_k4 } } },
	{ .mask = 0xffc00000, .match = 0x01400000, .id = TMS320C55_INS_RPTADD, .lop = C55_LOP_RPTADD, .len = 2, .ops = { { .fn = c55plus_x_01_csr }, { .fn = c55plus_x_01_k4 } } },
	{ .mask = 0xffc00000, .match = 0x01800000, .id = TMS320C55_INS_RPTADD, .lop = C55_LOP_RPTADD, .len = 2, .ops = { { .fn = c55plus_x_01_csr }, { .fn = c55plus_x_01_reg } } },
	{ .mask = 0xffc00000, .match = 0x01c00000, .id = TMS320C55_INS_RPT, .lop = C55_LOP_NOP, .len = 2, .ops = { { .fn = c55plus_x_01_csr } } },
	// rol / ror carry, ACx, carry, ACy (opcode 0xa8, 4 bytes). byte2[7] selects
	// rol (0) / ror (1); byte3[0] the carry-in flag and byte3[1] the carry-out
	// flag (0 carry, 1 tc2). Whole-accumulator forms only; lifted by the shared
	// rol/ror path.
	{ .mask = 0xff008000, .match = 0xa8000000, .id = TMS320C55_INS_ROL, .lop = C55_LOP_ROL, .len = 4, .ops = { { .lo = 0, .fn = c55plus_x_a8_flag }, { .fn = c55plus_x_a8_src }, { .lo = 1, .fn = c55plus_x_a8_flag }, { .fn = c55plus_x_a8_dst } } },
	{ .mask = 0xff008000, .match = 0xa8008000, .id = TMS320C55_INS_ROR, .lop = C55_LOP_ROR, .len = 4, .ops = { { .lo = 0, .fn = c55plus_x_a8_flag }, { .fn = c55plus_x_a8_src }, { .lo = 1, .fn = c55plus_x_a8_flag }, { .fn = c55plus_x_a8_dst } } },
	// bclr / bset st0_<bit>, st0_55 (opcode 0x0a, 2 bytes). byte1[5] selects
	// bset (1) vs bclr (0); byte1[4:0] is the bit. The semantic bits (9..15)
	// lift to an st0_55 bit set/clear; the data-page bits produce no IL.
	{ .mask = 0xffe00000, .match = 0x0a000000, .id = TMS320C55_INS_BCLR, .lop = C55_LOP_STBITCLR, .len = 2, .ops = { { .fn = c55plus_x_0a_bit }, { .fn = c55plus_x_0a_st0 } } },
	{ .mask = 0xffe00000, .match = 0x0a200000, .id = TMS320C55_INS_BSET, .lop = C55_LOP_STBITSET, .len = 2, .ops = { { .fn = c55plus_x_0a_bit }, { .fn = c55plus_x_0a_st0 } } },
	// pop / psh mmap(@reg) (opcode 0x24, byte1==0x61, 4 bytes). byte3[3] selects
	// pop (1) vs psh (0); byte2 is the mmap register. Lifted by the shared stack
	// path.
	{ .mask = 0xffff0008, .match = 0x24610008, .id = TMS320C55_INS_POP, .len = 4, .ops = { { .fn = c55plus_x_24_mmr_stack } } },
	{ .mask = 0xffff0008, .match = 0x24610000, .id = TMS320C55_INS_PSH, .len = 4, .ops = { { .fn = c55plus_x_24_mmr_stack } } },
	// pop / psh rX, rY (opcodes 0x71 / 0x70, 3 bytes): register-pair pop / push.
	// rX = gr1(byte1), rY = gr1(byte2). Lifted by the shared stack path.
	{ .mask = 0xff000000, .match = 0x71000000, .id = TMS320C55_INS_POP, .len = 3, .ops = { { .fn = c55plus_x_pair_reg1 }, { .fn = c55plus_x_pair_reg2 } } },
	{ .mask = 0xff000000, .match = 0x70000000, .id = TMS320C55_INS_PSH, .len = 3, .ops = { { .fn = c55plus_x_pair_reg1 }, { .fn = c55plus_x_pair_reg2 } } },
	// pshboth / popboth <reg> (opcode 0x0d, 2 bytes): byte1[7] selects pshboth (0)
	// over popboth (1); byte1[5] the ac/xar register class. The "both" flag marks
	// the register-pair stack semantics. Left unlifted, as the legacy decoder does.
	{ .mask = 0xff800000, .match = 0x0d000000, .id = TMS320C55_INS_PSHBOTH, .len = 2, .both = true, .ops = { { .fn = c55plus_x_pshpopboth_reg } } },
	{ .mask = 0xff800000, .match = 0x0d800000, .id = TMS320C55_INS_POPBOTH, .len = 2, .both = true, .ops = { { .fn = c55plus_x_pshpopboth_reg } } },
	// swap rX, rY (opcode 0x03, byte1[7:6]==10, 2 bytes). Single-register-pair
	// encodings only (the extractor declines the others, which fall back to the
	// legacy decoder). Lifts via the shared XOR-swap (XCHG) idiom.
	{ .mask = 0xffc00000, .match = 0x03800000, .id = TMS320C55_INS_SWAP, .len = 2, .ops = { { .fn = c55plus_x_swap_x }, { .fn = c55plus_x_swap_y } } },
	// intr #k5 / trap #k5 / sim_trig (opcode 0x03, 2 bytes). byte1[7:6] selects:
	// 00 intr, 01 trap, 11 sim_trig. Left unlifted.
	{ .mask = 0xffc00000, .match = 0x03000000, .id = TMS320C55_INS_INTR, .len = 2, .ops = { { .fn = c55plus_x_03_k5 } } },
	{ .mask = 0xffc00000, .match = 0x03400000, .id = TMS320C55_INS_TRAP, .len = 2, .ops = { { .fn = c55plus_x_03_k5 } } },
	{ .mask = 0xffc00000, .match = 0x03c00000, .id = TMS320C55_INS_SIM_TRIG, .len = 2, .ops = { { 0 } } },
	// estop (opcode 0x23, 1 byte) and ecopr (opcode 0x0b, 2 bytes): the
	// emulation-stop and emulation-coprocessor cpu-control instructions, typed
	// as traps. Operandless (the legacy decoder's trailing placeholder bytes are
	// a rendering artifact). Left unlifted.
	{ .mask = 0xff000000, .match = 0x23000000, .id = TMS320C55_INS_ESTOP, .lop = C55_LOP_NOP, .len = 1, .ops = { { 0 } } },
	{ .mask = 0xff000000, .match = 0x0b000000, .id = TMS320C55_INS_ECOPR, .lop = C55_LOP_NOP, .len = 2, .ops = { { 0 } } },
	// round/satr/sat SRC, DST (opcode 0x79, 3 bytes). byte1[7]==0 -> round;
	// byte1[7]==1 -> sat, byte1[5] selecting satr (the rounding 'r' suffix, round
	// bit = byte1[5] = bit 21 of the 3-byte word). Left unlifted.
	{ .mask = 0xff800000, .match = 0x79000000, .id = TMS320C55_INS_ROUND, .lop = C55_LOP_ROUND, .len = 3, .ops = { { .fn = c55plus_x_79_src }, { .fn = c55plus_x_79_dst } } },
	{ .mask = 0xffa00000, .match = 0x79800000, .id = TMS320C55_INS_SAT, .lop = C55_LOP_SAT, .len = 3, .ops = { { .fn = c55plus_x_79_src }, { .fn = c55plus_x_79_dst } } },
	{ .mask = 0xffa00000, .match = 0x79a00000, .id = TMS320C55_INS_SAT, .lop = C55_LOP_SAT, .len = 3, .mods = 22, .ops = { { .fn = c55plus_x_79_src }, { .fn = c55plus_x_79_dst } } },
	// sat (opcode 0x2a2d, 2 bytes) and circ (opcode 0x27, 1 byte): fixed-encoding
	// control instructions. Left unlifted.
	{ .mask = 0xffff0000, .match = 0x2a2d0000, .id = TMS320C55_INS_SAT, .lop = C55_LOP_OPAQUE, .len = 2, .ops = { { 0 } } },
	{ .mask = 0xff000000, .match = 0x27000000, .id = TMS320C55_INS_CIRC, .len = 1, .ops = { { 0 } } },
	// neg/abs/min/max SRC, DST (opcode 0x76, 3 bytes). byte1[7] + byte2[7] select
	// the operation. Lifted by the shared register-op path.
	{ .mask = 0xff808000, .match = 0x76000000, .id = TMS320C55_INS_ABS, .lop = C55_LOP_ABS, .len = 3, .ops = { { .fn = c55plus_x_76_src }, { .fn = c55plus_x_76_dst } } },
	{ .mask = 0xff808000, .match = 0x76008000, .id = TMS320C55_INS_NEG, .lop = C55_LOP_NEG, .len = 3, .ops = { { .fn = c55plus_x_76_src }, { .fn = c55plus_x_76_dst } } },
	{ .mask = 0xff808000, .match = 0x76800000, .id = TMS320C55_INS_MAX, .lop = C55_LOP_MAX, .len = 3, .ops = { { .fn = c55plus_x_76_src }, { .fn = c55plus_x_76_dst } } },
	{ .mask = 0xff808000, .match = 0x76808000, .id = TMS320C55_INS_MIN, .lop = C55_LOP_MIN, .len = 3, .ops = { { .fn = c55plus_x_76_src }, { .fn = c55plus_x_76_dst } } },
	// add/sub #k16 << #16, ACx, ACy (opcode 0xc0, base 5 bytes). byte2[7] selects
	// the operation; lifted by the shared immediate-shift ALU path.
	{ .mask = 0xff008000, .match = 0xc0000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .len = 5, .ops = { { .fn = c55plus_x_c0_imm }, { .fn = c55plus_x_c0_acx }, { .fn = c55plus_x_c0_acy } } },
	{ .mask = 0xff008000, .match = 0xc0008000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .len = 5, .ops = { { .fn = c55plus_x_c0_imm }, { .fn = c55plus_x_c0_acx }, { .fn = c55plus_x_c0_acy } } },
	// add/sub #k16 << #sh, ACx, ACy (opcode 0xc2, base 5 bytes, byte1[7]==0).
	// byte2[7] selects add vs sub. Lifted by the shared immediate-shift ALU path.
	{ .mask = 0xff808000, .match = 0xc2000000, .id = TMS320C55_INS_ADD, .lop = C55_LOP_ADDSHL, .len = 5, .ops = { { .fn = c55plus_x_c2_imm }, { .fn = c55plus_x_c2_acx }, { .fn = c55plus_x_c2_acy } } },
	{ .mask = 0xff808000, .match = 0xc2008000, .id = TMS320C55_INS_SUB, .lop = C55_LOP_SUBSHL, .len = 5, .ops = { { .fn = c55plus_x_c2_imm }, { .fn = c55plus_x_c2_acx }, { .fn = c55plus_x_c2_acy } } },
	// mov #k16 << #sh, ACx (opcode 0xc2, byte1[7]==1). Lifted by the shared
	// shifted-immediate load path.
	{ .mask = 0xff800000, .match = 0xc2800000, .id = TMS320C55_INS_MOV, .lop = C55_LOP_MOVSHL, .len = 5, .ops = { { .fn = c55plus_x_c2_imm }, { .fn = c55plus_x_c2_acy } } },
	// Ra = Rb + Smem (opcode 0x80, ADD_RM, 4 bytes): the destination Ra is the
	// 6-bit byte2[5:0] register, the source Rb is byte3 (gr1_sub7), and Smem is
	// byte1:byte2[7:6]. Verified against TI dis55. Left unlifted.
	{ .mask = 0xff000000, .match = 0x80000000, .id = TMS320C55_INS_ADD, .len = 4, .ops = { { .fn = c55plus_x_80_mem }, { .fn = c55plus_x_85_acx }, { .fn = c55plus_x_add_rm_ra } } },
	// or *Smem, ACx, ACy (opcode 0x85, 4 bytes). Left unlifted.
	{ .mask = 0xff000000, .match = 0x85000000, .id = TMS320C55_INS_OR, .len = 4, .ops = { { .fn = c55plus_x_85_mem }, { .fn = c55plus_x_85_acx }, { .fn = c55plus_x_85_acy } } },
	// sub ACx.<h/l>, *Smem, ACy.<h/l> (opcode 0x82, 4 bytes). Left unlifted.
	{ .mask = 0xff000000, .match = 0x82000000, .id = TMS320C55_INS_SUB, .len = 4, .ops = { { .fn = c55plus_x_82_acx }, { .fn = c55plus_x_82_mem }, { .fn = c55plus_x_82_acy } } },
	// add uns(*Smem), ACx, ACy (opcode 0x8c, 4 bytes). Left unlifted.
	{ .mask = 0xff0020e0, .match = 0x8c002000, .id = TMS320C55_INS_ADD, .len = 4, .ops = { { .fn = c55plus_x_8c_mem }, { .fn = c55plus_x_8c_acx }, { .fn = c55plus_x_8c_acy } } },
	// add [uns(]*Smem[)], carry, ACx, ACy (opcode 0x8c, byte3[7:5]==001, 4 bytes):
	// the add-with-carry variant -- a fixed "carry" operand sits between the Smem
	// source and the two accumulators (src byte3[4:0], dst byte2[4:0]); uns is
	// byte2[5]. Left unlifted, as the plain 0x8c form is.
	{ .mask = 0xff0000e0, .match = 0x8c000020, .id = TMS320C55_INS_ADD, .len = 4, .ops = { { .fn = c55plus_x_8c_carry_mem }, { .fn = c55plus_x_carry }, { .fn = c55plus_x_8c_acx }, { .fn = c55plus_x_8c_acy } } },
	// add/sub dbl(*Smem), ACx, ACy and sub ACx, dbl(*Smem), ACy (opcode 0x8d).
	// byte3[7:6] selects op + operand order. Left unlifted.
	{ .mask = 0xff0000c0, .match = 0x8d000000, .id = TMS320C55_INS_ADD, .len = 4, .ops = { { .fn = c55plus_x_8d_mem }, { .fn = c55plus_x_8c_acx }, { .fn = c55plus_x_8c_acy } } },
	{ .mask = 0xff0000c0, .match = 0x8d000040, .id = TMS320C55_INS_SUB, .len = 4, .ops = { { .fn = c55plus_x_8d_mem }, { .fn = c55plus_x_8c_acx }, { .fn = c55plus_x_8c_acy } } },
	{ .mask = 0xff0000c0, .match = 0x8d000080, .id = TMS320C55_INS_SUB, .len = 4, .ops = { { .fn = c55plus_x_8c_acx }, { .fn = c55plus_x_8d_mem }, { .fn = c55plus_x_8c_acy } } },
	// add/sub/mov [uns](*Smem) << #sh, ... (opcode 0xb7, base 5 bytes). byte3[7:6]
	// selects the operation. Left unlifted.
	{ .mask = 0xff0000c0, .match = 0xb7000000, .id = TMS320C55_INS_ADD, .len = 5, .ops = { { .fn = c55plus_x_b7_mem }, { .fn = c55plus_x_b7_acx }, { .fn = c55plus_x_b7_acy } } },
	{ .mask = 0xff0000c0, .match = 0xb7000040, .id = TMS320C55_INS_SUB, .len = 5, .ops = { { .fn = c55plus_x_b7_mem }, { .fn = c55plus_x_b7_acx }, { .fn = c55plus_x_b7_acy } } },
	{ .mask = 0xff0000c0, .match = 0xb70000c0, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_b7_mem }, { .fn = c55plus_x_b7_acy } } },
	// btstclr / btstset / btst / btstnot #k, [dbl(]*Smem[)], TCx (opcode 0x91, 4
	// bytes): the memory bit-test family. byte2[4:3] selects the operation (00
	// btstclr / 01 btstset / 10 btst / 11 btstnot) and byte2[2] the access width (0
	// word / 1 dbl); the two rows per operation cover both widths. Verified against
	// TI dis55 and SWPU104. Left unlifted, as in the legacy decoder.
	{ .mask = 0xff001c00, .match = 0x91000000, .id = TMS320C55_INS_BTSTCLR, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91000400, .id = TMS320C55_INS_BTSTCLR, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91000800, .id = TMS320C55_INS_BTSTSET, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91000c00, .id = TMS320C55_INS_BTSTSET, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91001000, .id = TMS320C55_INS_BTST, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91001400, .id = TMS320C55_INS_BTST, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91001800, .id = TMS320C55_INS_BTSTNOT, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	{ .mask = 0xff001c00, .match = 0x91001c00, .id = TMS320C55_INS_BTSTNOT, .len = 4, .ops = { { .fn = c55plus_x_btx_bit }, { .fn = c55plus_x_btx_mem }, { .fn = c55plus_x_btx_tc } } },
	// bfxtr #k16, ACsrc, ACdst (opcode 0xc6, 5 bytes): bit-field extract, left
	// unlifted as in the legacy decoder. byte2[7:5]==011 is fixed (in the mask):
	// byte2[7] distinguishes bfxtr from the bfxpa expand form.
	{ .mask = 0xff00e000, .match = 0xc6006000, .id = TMS320C55_INS_BFXTR, .lop = C55_LOP_OPAQUE, .len = 5, .ops = { { .fn = c55plus_x_bfxtr_imm }, { .fn = c55plus_x_bfxtr_src }, { .fn = c55plus_x_bfxtr_dst } } },
	// mpy / mac / mas SRC1, SRC2, ACdst (opcode 0xaa, 4 bytes): register multiply,
	// optionally accumulating. (byte1[7], byte2[7]) selects (0,0) mpy, (0,1) mac,
	// (1,0) mas; the four-operand (1,1) form stays on the legacy decoder. SRC1 is
	// gr1(byte2[6:0]), SRC2 is gr1(byte3[6:0]) with byte3[7] the uns() wrapper,
	// ACdst is ac(byte1[4:0]); byte1[5]/byte1[6] are the round (r) / fractional (f)
	// modifiers. These lift via the shared multiply (-accumulate) path.
	{ .mask = 0xff808000, .match = 0xaa000000, .id = TMS320C55_INS_MPY, .len = 4, .mods = 0x5c0016, .ops = { { .fn = c55plus_x_macr_src2 }, { .fn = c55plus_x_macr_src1 }, { .fn = c55plus_x_macr_acdst } } },
	{ .mask = 0xff808000, .match = 0xaa008000, .id = TMS320C55_INS_MAC, .lop = C55_LOP_MAC, .len = 4, .mods = 0x5c0016, .ops = { { .fn = c55plus_x_macr_src1 }, { .fn = c55plus_x_macr_src2 }, { .fn = c55plus_x_macr_acdst } } },
	{ .mask = 0xff808000, .match = 0xaa800000, .id = TMS320C55_INS_MAS, .lop = C55_LOP_MAS, .len = 4, .mods = 0x5c0016, .ops = { { .fn = c55plus_x_macr_src2 }, { .fn = c55plus_x_macr_src1 }, { .fn = c55plus_x_macr_acdst } } },
	// mpym [uns(]Xmem[)], [uns(]Ymem[)], ACy (opcode 0xc8, byte1[7]==0 &&
	// byte2[7]==0, 5 bytes): ACy = Xmem * Ymem. Xmem is byte1 (reg-modify matrix),
	// Ymem is byte3 (reg-modify matrix), ACy is byte2[4:0]. byte2[5]/byte4[0] mark
	// the Xmem/Ymem uns() wrappers. Lifts via the shared multiply path.
	{ .mask = 0xff808000, .match = 0xc8000000, .id = TMS320C55_INS_MPYM, .len = 5, .mods = 0x217000, .ops = { { .fn = c55plus_x_mac_xmem }, { .fn = c55plus_x_mac_ymem }, { .fn = c55plus_x_mac_acy } } },
	// macm [uns(]Xmem[)], [uns(]Ymem[)], ACx, ACy (opcode 0xc8, byte1[7]==0 &&
	// byte2[7]==1, 5 bytes): ACy = ACx + Xmem * Ymem. masm (byte1[7]==1 &&
	// byte2[7]==0) subtracts; the byte1[7]==1 && byte2[7]==1 form is macm with the
	// accumulator shifted right 16 first (ACy = (ACx >> #16) + Xmem * Ymem). ACx
	// is byte4[4:0]; all three reuse the mpym memory / ACy extractors and lift via
	// the shared multiply-accumulate path.
	{ .mask = 0xff808000, .match = 0xc8008000, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 5, .mods = 0x217000, .ops = { { .fn = c55plus_x_mac_xmem }, { .fn = c55plus_x_mac_ymem }, { .fn = c55plus_x_mac_acx }, { .fn = c55plus_x_mac_acy } } },
	{ .mask = 0xff808000, .match = 0xc8800000, .id = TMS320C55_INS_MASM, .lop = C55_LOP_MAS, .len = 5, .mods = 0x217000, .ops = { { .fn = c55plus_x_mac_xmem }, { .fn = c55plus_x_mac_ymem }, { .fn = c55plus_x_mac_acx }, { .fn = c55plus_x_mac_acy } } },
	{ .mask = 0xff808000, .match = 0xc8808000, .id = TMS320C55_INS_MACM, .lop = C55_LOP_MAC, .len = 5, .mods = 0x217000, .shift16 = true, .ops = { { .fn = c55plus_x_mac_xmem }, { .fn = c55plus_x_mac_ymem }, { .fn = c55plus_x_mac_acx }, { .fn = c55plus_x_mac_acy } } },
	// bfxpa #k16, ACsrc, ACdst (opcode 0xc6, byte2[7]==1, 5 bytes): bit-field
	// expand and pack -- the byte2[7]==1 counterpart of bfxtr (byte2[7]==0), with
	// the same operand layout and the same extractors. Left unlifted, as in the
	// legacy decoder.
	{ .mask = 0xff00e000, .match = 0xc600e000, .id = TMS320C55_INS_BFXPA, .lop = C55_LOP_OPAQUE, .len = 5, .ops = { { .fn = c55plus_x_bfxtr_imm }, { .fn = c55plus_x_bfxtr_src }, { .fn = c55plus_x_bfxtr_dst } } },
	// addsubcc / addsub2cc / subc *Smem, ... (opcode 0xb3, 5 bytes): the Smem is
	// byte1:byte2 (shared addressing), ACx is byte3[4:0], ACy is byte2[4:0].
	// byte3[7:6] selects the operation: 00 addsubcc (one TCx from byte2[5]), 01
	// addsubcc (the two-flag tc1,tc2 form), 10 addsub2cc (an extra ACz = gr1 of
	// byte4 and tc1,tc2), 11 subc. All left unlifted, as in the legacy decoder.
	{ .mask = 0xff0000c0, .match = 0xb3000000, .id = TMS320C55_INS_ADDSUBCC, .len = 5, .ops = { { .fn = c55plus_x_b3_mem }, { .fn = c55plus_x_b3_acx }, { .fn = c55plus_x_b3_tcx }, { .fn = c55plus_x_b3_acy } } },
	{ .mask = 0xff0000c0, .match = 0xb3000040, .id = TMS320C55_INS_ADDSUBCC, .len = 5, .ops = { { .fn = c55plus_x_b3_mem }, { .fn = c55plus_x_b3_acx }, { .fn = c55plus_x_b3_tc1 }, { .fn = c55plus_x_b3_tc2 }, { .fn = c55plus_x_b3_acy } } },
	{ .mask = 0xff0000c0, .match = 0xb3000080, .id = TMS320C55_INS_ADDSUB2CC, .len = 5, .ops = { { .fn = c55plus_x_b3_mem }, { .fn = c55plus_x_b3_acx }, { .fn = c55plus_x_b3_acz }, { .fn = c55plus_x_b3_tc1 }, { .fn = c55plus_x_b3_tc2 }, { .fn = c55plus_x_b3_acy } } },
	{ .mask = 0xff0000c0, .match = 0xb30000c0, .id = TMS320C55_INS_SUBC, .len = 5, .ops = { { .fn = c55plus_x_b3_mem }, { .fn = c55plus_x_b3_acx }, { .fn = c55plus_x_b3_acy } } },
	// mov [rnd]([uns](*Smem) << Tx), ACx (opcode 0xb4, byte3[6]==1 && byte3[0]==0,
	// 5 bytes): register-shifted memory load. byte3[6] selects the load over the
	// byte3[6]==0 store forms (which stay on the legacy decoder). Left unlifted, as
	// in the legacy decoder.
	{ .mask = 0xff000041, .match = 0xb4000040, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_b4_mem }, { .fn = c55plus_x_b4_acdst } } },
	// mov [uns(][rnd(][hi(|lo(]ACx << Tx[)], [dbl(]*Smem[)] (opcode 0xb4,
	// byte3[6]==0, 5 bytes): the register-shifted accumulator store -- source
	// ACx (byte2[4:0]) shifted by byte4, destination Smem; byte3[0] selects the
	// dbl 32-bit store (else a 16-bit hi/lo half store, byte3[1]). Left unlifted.
	{ .mask = 0xff000040, .match = 0xb4000000, .id = TMS320C55_INS_MOV, .len = 5, .ops = { { .fn = c55plus_x_b4st_src }, { .fn = c55plus_x_b4st_mem } } },
	// add/sub *Smem << Tx, ACx, ACy (opcode 0xb6, 5 bytes): the register-shifted
	// memory add/subtract -- byte4[6:0] is the shift register (rendered " << Tx"),
	// byte3[4:0] the source accumulator, byte2[4:0] the destination, byte3[6]
	// selecting add (0) / sub (1). Left unlifted.
	{ .mask = 0xff000040, .match = 0xb6000000, .id = TMS320C55_INS_ADD, .len = 5, .ops = { { .fn = c55plus_x_b6_mem }, { .fn = c55plus_x_b6_acx }, { .fn = c55plus_x_b4_acdst } } },
	{ .mask = 0xff000040, .match = 0xb6000040, .id = TMS320C55_INS_SUB, .len = 5, .ops = { { .fn = c55plus_x_b6_mem }, { .fn = c55plus_x_b6_acx }, { .fn = c55plus_x_b4_acdst } } },
	// mpyk/mack #k8, ACsrc[, ACacc], ACdst (opcode 0xc7, 5 bytes): multiply (or
	// multiply-accumulate) a source accumulator by an 8-bit constant. byte1[6:5]
	// select the fractional (f) / rounding (r) variants via mods (round bit 30,
	// fract bit 31 of the packed word); byte2[7] selects mack over mpyk.
	{ .mask = 0xff008000, .match = 0xc7000000, .id = TMS320C55_INS_MPYK, .lop = C55_LOP_MPYK, .len = 5, .mods = 30u | (31u << 18), .ops = { { .fn = c55plus_x_mpyk_imm8 }, { .fn = c55plus_x_mpyk_src }, { .fn = c55plus_x_mpyk_dst } } },
	{ .mask = 0xff008000, .match = 0xc7008000, .id = TMS320C55_INS_MACK, .len = 5, .mods = 30u | (31u << 18), .ops = { { .fn = c55plus_x_mpyk_imm8 }, { .fn = c55plus_x_mpyk_src }, { .fn = c55plus_x_mpyk_acc }, { .fn = c55plus_x_mpyk_dst } } },
	// mpyk/mack #k16, ... (opcode 0xee, 6 bytes): the 16-bit-immediate counterpart
	// of 0xc7. Same field layout shifted up one byte; round bit 38, fract bit 39.
	{ .mask = 0xff008000, .match = 0xee000000, .id = TMS320C55_INS_MPYK, .len = 6, .mods = 38u | (39u << 18), .ops = { { .fn = c55plus_x_mpyk_imm16 }, { .fn = c55plus_x_mpyk6_src }, { .fn = c55plus_x_mpyk6_dst } } },
	{ .mask = 0xff008000, .match = 0xee008000, .id = TMS320C55_INS_MACK, .len = 6, .mods = 38u | (39u << 18), .ops = { { .fn = c55plus_x_mpyk_imm16 }, { .fn = c55plus_x_mpyk6_src }, { .fn = c55plus_x_mpyk6_acc }, { .fn = c55plus_x_mpyk6_dst } } },
	// A-unit immediate address arithmetic. amov/aadd/asub #k16, reg (opcode 0xae,
	// 4 bytes): byte1[7:5] selects the operation and register type -- 000 asub ARn,
	// 001 asub XARn, 010 aadd ARn, 011 aadd XARn, 1xx amov ARn -- byte1[4:0] (or
	// [3:0] for XAR) the register, and byte2:byte3 the 16-bit constant.
	{ .mask = 0xffe00000, .match = 0xae000000, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 4, .ops = { { .fn = c55plus_x_k16 }, { .fn = c55plus_x_areg16 } } },
	{ .mask = 0xffe00000, .match = 0xae200000, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 4, .ops = { { .fn = c55plus_x_k16 }, { .fn = c55plus_x_xar16 } } },
	{ .mask = 0xffe00000, .match = 0xae400000, .id = TMS320C55_INS_AADD, .lop = C55_LOP_AREG_ADD, .len = 4, .ops = { { .fn = c55plus_x_k16 }, { .fn = c55plus_x_areg16 } } },
	{ .mask = 0xffe00000, .match = 0xae600000, .id = TMS320C55_INS_AADD, .lop = C55_LOP_AREG_ADD, .len = 4, .ops = { { .fn = c55plus_x_k16 }, { .fn = c55plus_x_xar16 } } },
	{ .mask = 0xff800000, .match = 0xae800000, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AMOV, .len = 4, .ops = { { .fn = c55plus_x_k16 }, { .fn = c55plus_x_areg16 } } },
	// amov/asub #k24, XARn (opcode 0xd2, 5 bytes): byte1[7] selects amov/asub,
	// byte1[3:0] the XAR register, byte2:byte3:byte4 the 24-bit constant.
	{ .mask = 0xff800000, .match = 0xd2800000, .id = TMS320C55_INS_AMOV, .lop = C55_LOP_AMOV, .len = 5, .ops = { { .fn = c55plus_x_k24 }, { .fn = c55plus_x_xar_dst } } },
	{ .mask = 0xff800000, .match = 0xd2000000, .id = TMS320C55_INS_ASUB, .lop = C55_LOP_AREG_SUB, .len = 5, .ops = { { .fn = c55plus_x_k24 }, { .fn = c55plus_x_xar_dst } } },
	// aadd #k8, sp (opcode 0x0c, 2 bytes): add an 8-bit constant to the stack
	// pointer.
	{ .mask = 0xff000000, .match = 0x0c000000, .id = TMS320C55_INS_AADD, .lop = C55_LOP_AREG_ADD, .len = 2, .ops = { { .fn = c55plus_x_k8 }, { .fn = c55plus_x_sp } } },
};

const C55ArchDesc c55plus_arch_desc = {
	.arch = C55_ARCH_C55XPLUS,
	.cpu_name = "c55x+",
	.table = c55plus_table,
	.table_len = sizeof(c55plus_table) / sizeof(c55plus_table[0]),
	.insn_len = c55plus_insn_len,
	.reg_info = c55plus_reg_info,
	.mnemonic = c55plus_mnemonic,
	.op_type = c55plus_op_type,
	.lift = NULL,
	.mem = { .addr_unit_log2 = 1, .ptr_width = 24, .big_endian = false },
	.ea = NULL,
	.cond_exec_prefix = true,
	.parallel_prefix = true,
};
