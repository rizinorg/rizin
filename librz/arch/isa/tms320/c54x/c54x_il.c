// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c54x_il.c
 * TMS320C54x RzIL lifting.
 *
 * The C54x integer core lifted to RzIL: the register / IL-VM configuration and
 * the per-instruction lifter (the C55ArchDesc::lift hook, dispatched by
 * c55_lift). Kept separate from the disassembler (c54x.c) so the decode path
 * and the IL path are independent.
 */

#include "c54x.h"

// Mirrors the decoder's keyword table (c54x.c): maps the TS/ASM/DP/ARP operand
// keyword (carried as the rendered string) back to its field value so the
// lifter can act on it. Small and self-contained, kept local to avoid a
// cross-translation-unit dependency on the decoder's private table.
static const char *const c54x_kw_tab[] = { "ts", "asm", "dp", "arp" };

/* RzIL VM */

// IL-VM register bindings for the C54x core. The lifter emits SET/VAR ops that
// name these; this list tells the RzIL VM which globals to materialise. The
// L/H/G accumulator slices (al/ah/ag, bl/bh/bg) are intentionally absent: the
// lifter expresses them as bit-slices of the 40-bit parent (a/b), so binding
// them as independent variables would desynchronise them from the parent.
static const char *c54x_il_regs[] = {
	"a", "b",
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7",
	"t", "trn", "sp", "dp", "bk",
	"st0", "st1", "pmst",
	"brc", "rsa", "rea", "imr", "ifr", "xpc", "pc",
	NULL
};

RZ_IPI RzAnalysisILConfig *tms320_c54x_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	// 24-bit PC and 24-bit byte-address space, little-endian (matching the
	// generic EA helper's aw=24 and the words_le decode).
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(24, false, 24);
	if (!cfg) {
		return NULL;
	}
	cfg->reg_bindings = c54x_il_regs;
	return cfg;
}

#include <rz_il/rz_il_opbuilder_begin.h>

// One data word spans two byte-address units (mem.addr_unit_log2 == 1).
#define C54X_WORD_BYTES 2

// IL-variable name of a full (sub == NONE) register operand, or NULL.
static const char *c54x_ilvar(const C55Operand *o) {
	if (o->kind != C55_OP_REG) {
		return NULL;
	}
	const C55RegInfo *ri = c54x_arch_desc.reg_info(o->reg.cls, o->reg.num, C55_SUB_NONE);
	return ri ? ri->il_var : NULL;
}

static bool c54x_is_acc(const C55Operand *o) {
	return o->kind == C55_OP_REG && o->reg.cls == C55_RC_AC && o->reg.sub == C55_SUB_NONE;
}

// The al/ah/ag and bl/bh/bg accumulator slices are memory-mapped registers but
// are deliberately not bound as IL variables (they would desynchronise from
// their 40-bit parent A/B). Instructions naming one as an operand are left
// unlifted rather than emitting a reference to an undefined IL variable.
static bool c54x_is_acc_slice(const C55Operand *o) {
	if (o->kind != C55_OP_REG || o->reg.cls != C55_RC_SPECIAL) {
		return false;
	}
	switch (o->reg.num) {
	case C54X_SPR_AL:
	case C54X_SPR_AH:
	case C54X_SPR_AG:
	case C54X_SPR_BL:
	case C54X_SPR_BH:
	case C54X_SPR_BG:
		return true;
	default:
		return false;
	}
}

// Read `o` as a 40-bit accumulator-width value: accumulators come back as-is,
// narrower operands (Smem / MMR / immediate) are sign- (sx) or zero-extended.
static RzILOpPure *c54x_val40(const C55Operand *o, bool sx) {
	RzILOpPure *v = c55_read(&c54x_arch_desc, o);
	if (!v) {
		return NULL;
	}
	if (c54x_is_acc(o)) {
		return v;
	}
	return sx ? SIGNED(40, v) : UNSIGNED(40, v);
}

// Low / high 16-bit slice of an accumulator operand.
static RzILOpPure *c54x_acc_lo(const C55Operand *o) {
	const char *v = c54x_ilvar(o);
	return v ? CAST(16, IL_FALSE, VARG(v)) : NULL;
}

static RzILOpPure *c54x_acc_hi(const C55Operand *o) {
	const char *v = c54x_ilvar(o);
	return v ? CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(v), UN(8, 16))) : NULL;
}

// Byte effective address of a (generic-mode) memory operand.
static RzILOpPure *c54x_ea(const C55Operand *m) {
	return c55_generic_ea(&c54x_arch_desc, m);
}

// Byte address of the current stack top: SP is a 16-bit word pointer.
static RzILOpPure *c54x_sp_ea(void) {
	return MUL(UNSIGNED(24, VARG("sp")), UN(24, C54X_WORD_BYTES));
}

// Byte address of a program-memory word address (program memory is word-
// addressed; the IL byte-address space scales each word to two units). The
// C54x program and data spaces share this unified IL address space.
static RzILOpPure *c54x_prog_ea(RzILOpPure *word_addr) {
	return MUL(UNSIGNED(24, word_addr), UN(24, C54X_WORD_BYTES));
}

// Append up to two (possibly NULL) post-modify effects after a core effect.
static RzILOpEffect *c54x_seq_post(RzILOpEffect *core, RzILOpEffect *p1, RzILOpEffect *p2) {
	if (!core) {
		rz_il_op_effect_free(p1);
		rz_il_op_effect_free(p2);
		return NULL;
	}
	if (p1 && p2) {
		return SEQ3(core, p1, p2);
	}
	if (p1) {
		return SEQ2(core, p1);
	}
	if (p2) {
		return SEQ2(core, p2);
	}
	return core;
}

// Compact the meaningful operands (dropping C55_OP_NONE holes -- a zero shift
// decodes to NONE) into out[], returning the count. The disassembly hides both
// NONE operands and the elide_if_eq_prev source accumulator, but both remain in
// insn->ops; compacting drops only the NONE ones.
static int c54x_ops(const C55Insn *insn, const C55Operand **out, int max) {
	int n = 0;
	for (ut8 i = 0; i < insn->n_ops && n < max; i++) {
		if (insn->ops[i].kind != C55_OP_NONE) {
			out[n++] = &insn->ops[i];
		}
	}
	return n;
}

// Resolve an ALU/load form into (value, shift, base, dst). After compacting
// NONE holes the forms are:
//   [value, shift?, dst]               base == dst (simple / dual-accumulator)
//   [value, shift?, base, dst(elide)]  explicit destination: base is the source
//                                      accumulator, dst the (possibly different)
//                                      elided one.
// The standalone shift count (\ref is_shift) sits between value and the
// accumulator(s); the elided destination always trails. ADD/SUB/AND/OR/XOR
// compute dst = base <op> (value << shift); LD ignores base. Any other middle
// operand makes this decline.
static bool c54x_alu_ops(const C55Insn *insn, const C55Operand **value,
	const C55Operand **shift, const C55Operand **base, const C55Operand **dst) {
	const C55Operand *op[6];
	int n = c54x_ops(insn, op, 6);
	if (n < 2) {
		return false;
	}
	int last = n - 1;
	int base_i = op[last]->elide_if_eq_prev ? last - 1 : last;
	if (base_i < 1) {
		return false;
	}
	*value = op[0];
	*base = op[base_i];
	*dst = op[last];
	*shift = NULL;
	for (int i = 1; i < base_i; i++) {
		if (op[i]->is_shift) {
			*shift = op[i];
		} else {
			return false;
		}
	}
	return true;
}

// Apply a C54x standalone shift operand to an already-width-extended value.
// Left shifts fill zeros; right shifts are arithmetic for sign-extended sources
// (ADD/SUB/LD) and logical for zero-extended ones (AND/OR/XOR). A NULL or
// zero-count shift passes the value through unchanged.
static RzILOpPure *c54x_apply_shift(RzILOpPure *v, const C55Operand *shift, bool sx) {
	if (!v || !shift || shift->shamt == 0) {
		return v;
	}
	RzILOpPure *cnt = UN(8, (ut8)shift->shamt);
	if (shift->sh_left) {
		return SHIFTL0(v, cnt);
	}
	return sx ? SHIFTRA(v, cnt) : SHIFTR0(v, cnt);
}

// Identify a C54x keyword operand (ts / asm / dp / arp); returns its index in
// c54x_kw_tab, or -1 if `o` is not a keyword.
static int c54x_kw_id(const C55Operand *o) {
	if (!o || o->kind != C55_OP_IMM || !o->raw) {
		return -1;
	}
	for (int i = 0; i < (int)(sizeof(c54x_kw_tab) / sizeof(c54x_kw_tab[0])); i++) {
		if (!strcmp(o->raw, c54x_kw_tab[i])) {
			return i;
		}
	}
	return -1;
}

// Signed shift count carried in TREG[5:0] (the TS keyword).
static RzILOpPure *c54x_ts_amount(void) {
	return SUB(LOGXOR(LOGAND(VARG("t"), UN(16, 0x3f)), UN(16, 0x20)), UN(16, 0x20));
}

// Signed shift count carried in ST1[4:0], the ASM field (the ASM keyword).
static RzILOpPure *c54x_asm_amount(void) {
	return SUB(LOGXOR(LOGAND(VARG("st1"), UN(16, 0x1f)), UN(16, 0x10)), UN(16, 0x10));
}

// Variable shift of a value by a signed amount: left when amount >= 0, right by
// the magnitude otherwise (arithmetic when sx, logical when not). The value and
// amount are each bound once so they may be reused across the branches.
static RzILOpPure *c54x_var_shift(RzILOpPure *v, RzILOpPure *amount, bool sx) {
	RzILOpPure *right = sx ? SHIFTRA(VARLP("v"), NEG(VARLP("sh"))) : SHIFTR0(VARLP("v"), NEG(VARLP("sh")));
	RzILOpPure *body = ITE(SGE(VARLP("sh"), UN(16, 0)), SHIFTL0(VARLP("v"), VARLP("sh")), right);
	return LET("v", v, LET("sh", amount, body));
}

// Write `value` into the `width`-bit field at bit `lo` of 16-bit register `reg`.
static RzILOpEffect *c54x_field_write(const char *reg, ut8 lo, ut8 width, RzILOpPure *value) {
	ut16 mask = (ut16)(((1u << width) - 1u) << lo);
	RzILOpPure *cleared = LOGAND(VARG(reg), UN(16, (ut16)~mask));
	RzILOpPure *ins = LOGAND(SHIFTL0(CAST(16, IL_FALSE, value), UN(8, lo)), UN(16, mask));
	return SETG(reg, LOGOR(cleared, ins));
}

// ---- Status-register flags ------------------------------------------------
// ST0 holds (high to low) ARP, TC, C, OVA, OVB, DP; ST1 holds BRAF, CPL, XF,
// HM, INTM, OVM, SXM, C16, FRCT, CMPT, ASM. Only the addressable flag bits are
// named here; C and TC live in ST0, the mode bits in ST1.
#define C54X_F_OVB 9
#define C54X_F_OVA 10
#define C54X_F_C   11
#define C54X_F_TC  12

// Read status flag `bit` of 16-bit register `reg` as a Bool.
static RzILOpBool *c54x_flag_bool(const char *reg, ut8 bit) {
	return NON_ZERO(LOGAND(VARG(reg), UN(16, (ut16)(1u << bit))));
}

// Read status flag `bit` as a `width`-bit 0/1 value.
static RzILOpPure *c54x_flag_val(const char *reg, ut8 bit, ut8 width) {
	return BOOL_TO_BV(c54x_flag_bool(reg, bit), width);
}

// reg |= (1 << bit)
static RzILOpEffect *c54x_flag_on(const char *reg, ut8 bit) {
	return SETG(reg, LOGOR(VARG(reg), UN(16, (ut16)(1u << bit))));
}

// reg &= ~(1 << bit)
static RzILOpEffect *c54x_flag_off(const char *reg, ut8 bit) {
	return SETG(reg, LOGAND(VARG(reg), UN(16, (ut16) ~(1u << bit))));
}

// reg[bit] = cond
static RzILOpEffect *c54x_flag_assign(const char *reg, ut8 bit, RzILOpBool *cond) {
	RzILOpPure *cleared = LOGAND(VARG(reg), UN(16, (ut16) ~(1u << bit)));
	return SETG(reg, LOGOR(cleared, ITE(cond, UN(16, (ut16)(1u << bit)), UN(16, 0))));
}

// Bit `pos` of a pure value as a Bool.
static RzILOpBool *c54x_bit(RzILOpPure *v, ut8 pos) {
	return LSB(SHIFTR0(v, UN(8, pos)));
}

// Build the IL predicate for a C54x 8-bit condition code (the bc/cc/rc/xc
// condition field). Single accumulator/overflow conditions map directly; the
// C/TC group (bit6 == 0) ANDs the selected sub-conditions. BIO-pin conditions
// and accumulator combinations are not modelled and return NULL.
static RzILOpBool *c54x_cond_pred(ut8 cc) {
	switch (cc) {
	case 0x00: return IL_TRUE; // unconditional
	case 0x42: return SGE(VARG("a"), UN(40, 0));
	case 0x43: return SLT(VARG("a"), UN(40, 0));
	case 0x44: return INV(IS_ZERO(VARG("a")));
	case 0x45: return IS_ZERO(VARG("a"));
	case 0x46: return SGT(VARG("a"), UN(40, 0));
	case 0x47: return SLE(VARG("a"), UN(40, 0));
	case 0x4a: return SGE(VARG("b"), UN(40, 0));
	case 0x4b: return SLT(VARG("b"), UN(40, 0));
	case 0x4c: return INV(IS_ZERO(VARG("b")));
	case 0x4d: return IS_ZERO(VARG("b"));
	case 0x4e: return SGT(VARG("b"), UN(40, 0));
	case 0x4f: return SLE(VARG("b"), UN(40, 0));
	case 0x60: return INV(c54x_flag_bool("st0", C54X_F_OVA));
	case 0x68: return INV(c54x_flag_bool("st0", C54X_F_OVB));
	case 0x70: return c54x_flag_bool("st0", C54X_F_OVA);
	case 0x78: return c54x_flag_bool("st0", C54X_F_OVB);
	default: break;
	}
	if (cc & 0x40) {
		return NULL; // accumulator-condition combination -- not modelled
	}
	if (cc & 0x03) {
		return NULL; // BIO pin -- external, not modellable
	}
	RzILOpBool *pred = NULL;
	ut8 tcf = (cc >> 4) & 3, cf = (cc >> 2) & 3;
	if (tcf == 3) {
		pred = c54x_flag_bool("st0", C54X_F_TC);
	} else if (tcf == 2) {
		pred = INV(c54x_flag_bool("st0", C54X_F_TC));
	}
	if (cf == 3 || cf == 2) {
		RzILOpBool *c = cf == 3 ? c54x_flag_bool("st0", C54X_F_C) : INV(c54x_flag_bool("st0", C54X_F_C));
		pred = pred ? AND(pred, c) : c;
	}
	return pred;
}

// Build the IL predicate for a 4-bit conditional-store condition (saccd /
// srccd / strcd): accumulator A/B compared against zero.
static RzILOpBool *c54x_cond4_pred(ut8 cc) {
	switch (cc & 0xf) {
	case 0x2: return SGE(VARG("a"), UN(40, 0));
	case 0x3: return SLT(VARG("a"), UN(40, 0));
	case 0x4: return INV(IS_ZERO(VARG("a")));
	case 0x5: return IS_ZERO(VARG("a"));
	case 0x6: return SGT(VARG("a"), UN(40, 0));
	case 0x7: return SLE(VARG("a"), UN(40, 0));
	case 0xa: return SGE(VARG("b"), UN(40, 0));
	case 0xb: return SLT(VARG("b"), UN(40, 0));
	case 0xc: return INV(IS_ZERO(VARG("b")));
	case 0xd: return IS_ZERO(VARG("b"));
	case 0xe: return SGT(VARG("b"), UN(40, 0));
	case 0xf: return SLE(VARG("b"), UN(40, 0));
	default: return NULL;
	}
}

// Map an ssbx/rsbx status-bit name (carried in operand->raw) to its ST0/ST1
// register and bit index. Returns false for an unknown / reserved bit.
static bool c54x_status_lookup(const char *name, const char **reg, ut8 *bit) {
	static const struct {
		const char *n;
		const char *r;
		ut8 b;
	} tab[] = {
		{ "ovb", "st0", 9 }, { "ova", "st0", 10 }, { "c", "st0", 11 }, { "tc", "st0", 12 },
		{ "cmpt", "st1", 5 }, { "frct", "st1", 6 }, { "c16", "st1", 7 }, { "sxm", "st1", 8 },
		{ "ovm", "st1", 9 }, { "intm", "st1", 11 }, { "hm", "st1", 12 }, { "xf", "st1", 13 },
		{ "cpl", "st1", 14 }, { "braf", "st1", 15 }
	};
	if (!name) {
		return false;
	}
	for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
		if (!strcmp(name, tab[i].n)) {
			*reg = tab[i].r;
			*bit = tab[i].b;
			return true;
		}
	}
	return false;
}

// Resolve a unary accumulator form [src, dst(elide)] into (src, dst); dst equals
// src when the destination operand was elided. Both must be accumulators.
static bool c54x_unary_ops(const C55Insn *insn, const C55Operand **src, const C55Operand **dst) {
	const C55Operand *op[6];
	int n = c54x_ops(insn, op, 6);
	if (n < 1) {
		return false;
	}
	*src = op[0];
	*dst = op[n - 1];
	return c54x_is_acc(*src) && c54x_is_acc(*dst);
}

// Per-arch lifter (dispatched by c55_lift() via C55ArchDesc::lift). Returns the
// RzIL effect for `insn`, or NULL if the instruction (or this form of it) is not
// yet lifted, in which case the shared lifter leaves op->il_op unset. Only the
// no-shift forms are modelled for now; shift/round/saturate variants return
// NULL. Dispatch is on insn->id (C54X_INS_*).
RZ_IPI RzILOpEffect *c54x_lift(const C55Insn *insn, ut64 pc) {
	(void)pc;
	const C55ArchDesc *a = &c54x_arch_desc;
	const C55Operand *value = NULL, *shift = NULL, *base = NULL, *dst = NULL;

	// Decline any form that names an unbound accumulator-slice register.
	for (ut8 i = 0; i < insn->n_ops; i++) {
		if (c54x_is_acc_slice(&insn->ops[i])) {
			return NULL;
		}
	}

	switch (insn->id) {
	case C54X_INS_NOP:
	case C54X_INS_MAR: // modify-AR: pointer post-modify only; no modelled data effect
	case C54X_INS_DELAY: // single-word memory delay; no data-flow effect modelled
		return NOP();

	// loads into ACx
	case C54X_INS_LD:
	case C54X_INS_LDU:
	case C54X_INS_LDR:
	case C54X_INS_LDM: {
		const C55Operand *lo[6];
		int ln = c54x_ops(insn, lo, 6);
		// register-shift form: ld value, TS/ASM, acc -> acc = value << (T|ASM)
		if (ln == 3 && c54x_is_acc(lo[2])) {
			int kw = c54x_kw_id(lo[1]);
			if (kw == 0 || kw == 1) {
				RzILOpPure *amt = kw == 0 ? c54x_ts_amount() : c54x_asm_amount();
				RzILOpPure *sh = c54x_var_shift(c54x_val40(lo[0], true), amt, true);
				return c54x_seq_post(SETG(c54x_ilvar(lo[2]), sh), c55_post_effect(a, lo[0]), NULL);
			}
		}
		// status-field form: ld value, DP/ASM/ARP
		if (ln == 2) {
			int kw = c54x_kw_id(lo[1]);
			if (kw >= 0) {
				RzILOpPure *src = c55_read(a, lo[0]);
				if (!src) {
					return NULL;
				}
				RzILOpEffect *core;
				if (kw == 2) {
					core = SETG("dp", LOGAND(CAST(16, IL_FALSE, src), UN(16, 0x1ff)));
				} else if (kw == 1) {
					core = c54x_field_write("st1", 0, 5, src); // ASM
				} else if (kw == 3) {
					core = c54x_field_write("st0", 13, 3, src); // ARP
				} else {
					rz_il_op_pure_free(src); // TS cannot be a destination
					return NULL;
				}
				return c54x_seq_post(core, c55_post_effect(a, lo[0]), NULL);
			}
		}
		if (!c54x_alu_ops(insn, &value, &shift, &base, &dst)) {
			return NULL;
		}
		if (c54x_is_acc(dst)) {
			// LD sign-extends the source; LDU/LDR/LDM zero-extend it (LDM thereby
			// clears ACx[39:16], the documented "load MMR" behaviour). The
			// optional SHIFT is applied in the 40-bit domain. LD does not
			// accumulate, so `base` is unused.
			bool sx = insn->id == C54X_INS_LD;
			RzILOpPure *v = c54x_apply_shift(c54x_val40(value, sx), shift, sx);
			RzILOpEffect *core = v ? SETG(c54x_ilvar(dst), v) : NULL;
			return c54x_seq_post(core, c55_post_effect(a, value), NULL);
		}
		// Non-accumulator destination (e.g. ld #k, dp): plain 16-bit move.
		RzILOpPure *v = c55_read(a, value);
		RzILOpEffect *core = v ? c55_write(a, dst, v) : NULL;
		return c54x_seq_post(core, c55_post_effect(a, value), NULL);
	}

	// ACx arithmetic / logic
	case C54X_INS_ADD:
	case C54X_INS_SUB:
	case C54X_INS_AND:
	case C54X_INS_OR:
	case C54X_INS_XOR: {
		// dual-data form: add/sub Xmem, Ymem, dst -> dst = (Xmem<<16) +/- (Ymem<<16)
		const C55Operand *du[6];
		if ((insn->id == C54X_INS_ADD || insn->id == C54X_INS_SUB) &&
			c54x_ops(insn, du, 6) == 3 && du[0]->kind == C55_OP_MEM &&
			du[1]->kind == C55_OP_MEM && c54x_is_acc(du[2])) {
			RzILOpPure *x = SHIFTL0(SIGNED(40, c55_read(a, du[0])), UN(8, 16));
			RzILOpPure *y = SHIFTL0(SIGNED(40, c55_read(a, du[1])), UN(8, 16));
			RzILOpPure *res = insn->id == C54X_INS_ADD ? ADD(x, y) : SUB(x, y);
			return c54x_seq_post(SETG(c54x_ilvar(du[2]), res),
				c55_post_effect(a, du[0]), c55_post_effect(a, du[1]));
		}
		// register-shift form: add/sub value, TS/ASM, acc
		if ((insn->id == C54X_INS_ADD || insn->id == C54X_INS_SUB) &&
			c54x_ops(insn, du, 6) == 3 && c54x_is_acc(du[2])) {
			int kw = c54x_kw_id(du[1]);
			if (kw == 0 || kw == 1) {
				RzILOpPure *amt = kw == 0 ? c54x_ts_amount() : c54x_asm_amount();
				RzILOpPure *sh = c54x_var_shift(c54x_val40(du[0], true), amt, true);
				const char *d = c54x_ilvar(du[2]);
				RzILOpPure *r = insn->id == C54X_INS_ADD ? ADD(VARG(d), sh) : SUB(VARG(d), sh);
				return c54x_seq_post(SETG(d, r), c55_post_effect(a, du[0]), NULL);
			}
		}
		if (!c54x_alu_ops(insn, &value, &shift, &base, &dst) ||
			!c54x_is_acc(dst) || !c54x_is_acc(base)) {
			return NULL;
		}
		// ADD/SUB sign-extend the source; the logicals zero-extend it. The
		// result accumulates onto `base` (the source accumulator, which equals
		// dst unless an explicit different destination is given).
		bool sx = insn->id == C54X_INS_ADD || insn->id == C54X_INS_SUB;
		RzILOpPure *src = c54x_apply_shift(c54x_val40(value, sx), shift, sx);
		const char *b = c54x_ilvar(base), *d = c54x_ilvar(dst);
		if (!src || !b || !d) {
			rz_il_op_pure_free(src);
			return NULL;
		}
		RzILOpPure *res;
		switch (insn->id) {
		case C54X_INS_ADD: res = ADD(VARG(b), src); break;
		case C54X_INS_SUB: res = SUB(VARG(b), src); break;
		case C54X_INS_AND: res = LOGAND(VARG(b), src); break;
		case C54X_INS_OR: res = LOGOR(VARG(b), src); break;
		default: res = LOGXOR(VARG(b), src); break;
		}
		return c54x_seq_post(SETG(d, res), c55_post_effect(a, value), NULL);
	}

	// stores from ACx
	case C54X_INS_STM: {
		// stm #lk, MMR : MMR = lk
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *v = c55_read(a, op[0]);
		return v ? c55_write(a, op[1], v) : NULL;
	}

	// memory-to-memory move (both operands are real data/MMR locations)
	case C54X_INS_MVDD:
	case C54X_INS_MVMM: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *v = c55_read(a, op[0]);
		RzILOpEffect *core = v ? c55_write(a, op[1], v) : NULL;
		return c54x_seq_post(core, c55_post_effect(a, op[0]), c55_post_effect(a, op[1]));
	}

	// moves where one operand is an absolute 16-bit data address (dmad)
	case C54X_INS_MVDK:
	case C54X_INS_MVKD:
	case C54X_INS_MVMD:
	case C54X_INS_MVDM: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		bool dst_abs = op[1]->kind == C55_OP_IMM && op[1]->addr;
		bool src_abs = op[0]->kind == C55_OP_IMM && op[0]->addr;
		if (dst_abs) {
			// data[dmad] = Smem/MMR
			RzILOpPure *ea = MUL(UNSIGNED(24, UN(16, (ut16)op[1]->imm)), UN(24, C54X_WORD_BYTES));
			RzILOpPure *v = c55_read(a, op[0]);
			RzILOpEffect *core = v ? STOREW(ea, v) : (rz_il_op_pure_free(ea), (RzILOpEffect *)NULL);
			return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
		}
		if (src_abs) {
			// Smem/MMR = data[dmad]
			RzILOpPure *ea = MUL(UNSIGNED(24, UN(16, (ut16)op[0]->imm)), UN(24, C54X_WORD_BYTES));
			RzILOpEffect *core = c55_write(a, op[1], LOADW(16, ea));
			return c54x_seq_post(core, c55_post_effect(a, op[1]), NULL);
		}
		return NULL;
	}

	// double (32-bit) load/store: high word low
	case C54X_INS_DLD: {
		// dld Lmem, ACx : ACx = sign_extend((mem[ea] << 16) | mem[ea+1word]).
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2 || !c54x_is_acc(op[1])) {
			return NULL;
		}
		RzILOpPure *hi = UNSIGNED(32, LOADW(16, c54x_ea(op[0])));
		RzILOpPure *lo = UNSIGNED(32, LOADW(16, ADD(c54x_ea(op[0]), UN(24, C54X_WORD_BYTES))));
		RzILOpPure *v32 = LOGOR(SHIFTL(IL_FALSE, hi, UN(8, 16)), lo);
		RzILOpEffect *core = SETG(c54x_ilvar(op[1]), SIGNED(40, v32));
		return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
	}
	case C54X_INS_DST: {
		// dst ACx, Lmem : mem[ea] = ACx[31:16]; mem[ea+1word] = ACx[15:0].
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *hi = c54x_acc_hi(op[0]), *lo = c54x_acc_lo(op[0]);
		if (!hi || !lo) {
			rz_il_op_pure_free(hi);
			rz_il_op_pure_free(lo);
			return NULL;
		}
		RzILOpEffect *core = SEQ2(STOREW(c54x_ea(op[1]), hi),
			STOREW(ADD(c54x_ea(op[1]), UN(24, C54X_WORD_BYTES)), lo));
		return c54x_seq_post(core, c55_post_effect(a, op[1]), NULL);
	}

	// stack
	case C54X_INS_PSHM:
	case C54X_INS_PSHD: {
		// SP -= 1; mem[SP] = src
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		RzILOpPure *v = c55_read(a, op[0]);
		if (!v) {
			return NULL;
		}
		return SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), STOREW(c54x_sp_ea(), v));
	}
	case C54X_INS_POPM:
	case C54X_INS_POPD: {
		// dst = mem[SP]; SP += 1
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		RzILOpEffect *load = c55_write(a, op[0], LOADW(16, c54x_sp_ea()));
		return load ? SEQ2(load, SETG("sp", ADD(VARG("sp"), UN(16, 1)))) : NULL;
	}

	case C54X_INS_RET:
	case C54X_INS_RETD: {
		// pc = mem[SP]; SP += 1   (return address is a program word address)
		RzILOpPure *target = UNSIGNED(24, LOADW(16, c54x_sp_ea()));
		return SEQ2(SETG("sp", ADD(VARG("sp"), UN(16, 1))), JMP(target));
	}

	// status-register bit set / clear
	case C54X_INS_SSBX:
	case C54X_INS_RSBX: {
		const C55Operand *op[6];
		const char *reg;
		ut8 bit;
		if (c54x_ops(insn, op, 6) != 1 || !c54x_status_lookup(op[0]->raw, &reg, &bit)) {
			return NULL;
		}
		return insn->id == C54X_INS_SSBX ? c54x_flag_on(reg, bit) : c54x_flag_off(reg, bit);
	}

	// unary accumulator ops
	case C54X_INS_NEG:
	case C54X_INS_ABS:
	case C54X_INS_CMPL:
	case C54X_INS_RND: {
		const C55Operand *src, *d;
		if (!c54x_unary_ops(insn, &src, &d)) {
			return NULL;
		}
		const char *s = c54x_ilvar(src), *dv = c54x_ilvar(d);
		if (!s || !dv) {
			return NULL;
		}
		RzILOpPure *res;
		switch (insn->id) {
		case C54X_INS_NEG: res = NEG(VARG(s)); break;
		case C54X_INS_CMPL: res = LOGNOT(VARG(s)); break;
		case C54X_INS_RND: res = ADD(VARG(s), UN(40, 0x8000)); break; // round: + 2^15
		default: res = ITE(SLT(VARG(s), UN(40, 0)), NEG(VARG(s)), VARG(s)); break; // ABS
		}
		return SETG(dv, res);
	}

	// add/subtract Smem with carry / borrow / sign-suppressed
	case C54X_INS_ADDC:
	case C54X_INS_SUBB:
	case C54X_INS_ADDS:
	case C54X_INS_SUBS: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2 || !c54x_is_acc(op[1])) {
			return NULL;
		}
		const char *d = c54x_ilvar(op[1]);
		RzILOpPure *mem = c55_read(a, op[0]);
		if (!d || !mem) {
			rz_il_op_pure_free(mem);
			return NULL;
		}
		RzILOpPure *res;
		switch (insn->id) {
		case C54X_INS_ADDC: // src + Smem + C
			res = ADD(ADD(VARG(d), SIGNED(40, mem)), c54x_flag_val("st0", C54X_F_C, 40));
			break;
		case C54X_INS_SUBB: // src - Smem - ~C
			res = SUB(SUB(VARG(d), SIGNED(40, mem)),
				BOOL_TO_BV(INV(c54x_flag_bool("st0", C54X_F_C)), 40));
			break;
		case C54X_INS_ADDS: // src + uns(Smem)  (sign-extension suppressed)
			res = ADD(VARG(d), UNSIGNED(40, mem));
			break;
		default: // SUBS: src - uns(Smem)
			res = SUB(VARG(d), UNSIGNED(40, mem));
			break;
		}
		return c54x_seq_post(SETG(d, res), c55_post_effect(a, op[0]), NULL);
	}

	// memory-immediate: Smem <op>= lk
	case C54X_INS_ADDM:
	case C54X_INS_ANDM:
	case C54X_INS_ORM:
	case C54X_INS_XORM: {
		// operands are [#lk, Smem]
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *cur = c55_read(a, op[1]), *imm = c55_read(a, op[0]);
		if (!cur || !imm) {
			rz_il_op_pure_free(cur);
			rz_il_op_pure_free(imm);
			return NULL;
		}
		RzILOpPure *res;
		switch (insn->id) {
		case C54X_INS_ADDM: res = ADD(cur, imm); break;
		case C54X_INS_ANDM: res = LOGAND(cur, imm); break;
		case C54X_INS_ORM: res = LOGOR(cur, imm); break;
		default: res = LOGXOR(cur, imm); break;
		}
		RzILOpEffect *core = c55_write(a, op[1], res);
		return c54x_seq_post(core, c55_post_effect(a, op[1]), NULL);
	}

	// compares and bit tests that set TC
	case C54X_INS_CMPM:
	case C54X_INS_BITF: {
		// [Smem, #lk]: CMPM TC = (Smem == lk); BITF TC = (Smem & lk) != 0
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *mem = c55_read(a, op[0]), *imm = c55_read(a, op[1]);
		if (!mem || !imm) {
			rz_il_op_pure_free(mem);
			rz_il_op_pure_free(imm);
			return NULL;
		}
		RzILOpBool *tc = insn->id == C54X_INS_CMPM ? EQ(mem, imm) : NON_ZERO(LOGAND(mem, imm));
		RzILOpEffect *core = c54x_flag_assign("st0", C54X_F_TC, tc);
		return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
	}

	case C54X_INS_CMPR: {
		// [cc, ARx]: TC = (ARx <cc> AR0), unsigned address comparison
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *arx = c55_read(a, op[1]);
		if (!arx) {
			return NULL;
		}
		RzILOpBool *tc;
		switch (op[0]->imm & 3) {
		case 0: tc = EQ(arx, VARG("ar0")); break;
		case 1: tc = ULT(arx, VARG("ar0")); break;
		case 2: tc = UGT(arx, VARG("ar0")); break;
		default: tc = INV(EQ(arx, VARG("ar0"))); break;
		}
		return c54x_flag_assign("st0", C54X_F_TC, tc);
	}

	case C54X_INS_BIT: {
		// [Xmem, BITC]: TC = Xmem(15 - BITC)
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *mem = c55_read(a, op[0]);
		if (!mem) {
			return NULL;
		}
		ut8 pos = (ut8)(15 - (op[1]->imm & 0xf));
		RzILOpBool *tc = NON_ZERO(LOGAND(SHIFTR0(mem, UN(16, pos)), UN(16, 1)));
		RzILOpEffect *core = c54x_flag_assign("st0", C54X_F_TC, tc);
		return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
	}

	case C54X_INS_BITT: {
		// [Smem]: TC = Smem(15 - T(3:0))
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		RzILOpPure *mem = c55_read(a, op[0]);
		if (!mem) {
			return NULL;
		}
		RzILOpPure *pos = SUB(UN(16, 15), LOGAND(VARG("t"), UN(16, 0xf)));
		RzILOpBool *tc = NON_ZERO(LOGAND(SHIFTR0(mem, pos), UN(16, 1)));
		RzILOpEffect *core = c54x_flag_assign("st0", C54X_F_TC, tc);
		return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
	}

	// max / min of the two accumulators into the named one
	case C54X_INS_MAX:
	case C54X_INS_MIN: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1 || !c54x_is_acc(op[0])) {
			return NULL;
		}
		RzILOpBool *pick = insn->id == C54X_INS_MAX
			? SGE(VARG("a"), VARG("b"))
			: SLE(VARG("a"), VARG("b"));
		return SETG(c54x_ilvar(op[0]), ITE(pick, VARG("a"), VARG("b")));
	}

	// rotate the low 32 bits through carry / TC (the guard bits clear to 0)
	case C54X_INS_ROL:
	case C54X_INS_ROR:
	case C54X_INS_ROLTC: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1 || !c54x_is_acc(op[0])) {
			return NULL;
		}
		const char *d = c54x_ilvar(op[0]);
		RzILOpEffect *grab = SETL("v", CAST(32, IL_FALSE, VARG(d)));
		if (insn->id == C54X_INS_ROR) {
			// C -> bit31, bit0 -> C
			RzILOpPure *nl = LOGOR(SHIFTR0(VARL("v"), UN(8, 1)),
				SHIFTL0(c54x_flag_val("st0", C54X_F_C, 32), UN(8, 31)));
			return SEQ3(grab, SETG(d, UNSIGNED(40, nl)),
				c54x_flag_assign("st0", C54X_F_C, LSB(VARL("v"))));
		}
		// ROL / ROLTC: in-bit -> bit0, bit31 -> C
		ut8 inbit = insn->id == C54X_INS_ROLTC ? C54X_F_TC : C54X_F_C;
		RzILOpPure *nl = LOGOR(SHIFTL0(VARL("v"), UN(8, 1)),
			c54x_flag_val("st0", inbit, 32));
		return SEQ3(grab, SETG(d, UNSIGNED(40, nl)),
			c54x_flag_assign("st0", C54X_F_C, MSB(VARL("v"))));
	}

	// saturate the 40-bit accumulator to the signed 32-bit range
	case C54X_INS_SAT: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1 || !c54x_is_acc(op[0])) {
			return NULL;
		}
		const char *d = c54x_ilvar(op[0]);
		RzILOpPure *sat = ITE(SGT(VARL("v"), UN(40, 0x7fffffff)), UN(40, 0x7fffffff),
			ITE(SLT(VARL("v"), UN(40, 0xff80000000ULL)), UN(40, 0xff80000000ULL), VARL("v")));
		return SEQ2(SETL("v", VARG(d)), SETG(d, sat));
	}

	// conditional subtract (one division step)
	case C54X_INS_SUBC: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2 || !c54x_is_acc(op[1])) {
			return NULL;
		}
		const char *d = c54x_ilvar(op[1]);
		RzILOpPure *mem = c55_read(a, op[0]);
		if (!d || !mem) {
			rz_il_op_pure_free(mem);
			return NULL;
		}
		// diff = src - (Smem << 15); if diff >= 0 then (diff<<1)|1 else src<<1
		RzILOpEffect *grab = SETL("diff", SUB(VARG(d), SHIFTL0(UNSIGNED(40, mem), UN(8, 15))));
		RzILOpPure *res = ITE(SGE(VARL("diff"), UN(40, 0)),
			LOGOR(SHIFTL0(VARL("diff"), UN(8, 1)), UN(40, 1)),
			SHIFTL0(VARG(d), UN(8, 1)));
		return c54x_seq_post(SEQ2(grab, SETG(d, res)), c55_post_effect(a, op[0]), NULL);
	}

	// arithmetic / logical accumulator shift by a signed count
	case C54X_INS_SFTL:
	case C54X_INS_SFTA: {
		// [src, SHIFT, dst?]: dst defaults to src
		const C55Operand *op[6];
		int n = c54x_ops(insn, op, 6);
		if (n < 2 || !op[1]->is_shift || !c54x_is_acc(op[0])) {
			return NULL;
		}
		const C55Operand *dop = (n >= 3) ? op[2] : op[0];
		const char *s = c54x_ilvar(op[0]), *dv = c54x_ilvar(dop);
		if (!s || !dv || !c54x_is_acc(dop)) {
			return NULL;
		}
		// SFTA shifts arithmetically (sign-filled right), SFTL logically.
		RzILOpPure *res = c54x_apply_shift(VARG(s), op[1], insn->id == C54X_INS_SFTA);
		return SETG(dv, res);
	}

	// normalize: shift src left by the (signed) exponent in T
	case C54X_INS_NORM: {
		const C55Operand *src, *d;
		if (!c54x_unary_ops(insn, &src, &d)) {
			return NULL;
		}
		const char *s = c54x_ilvar(src), *dv = c54x_ilvar(d);
		if (!s || !dv) {
			return NULL;
		}
		// T >= 0: shift left by T; T < 0: shift arithmetic-right by |T|.
		RzILOpPure *res = ITE(SGE(VARG("t"), UN(16, 0)),
			SHIFTL0(VARG(s), VARG("t")),
			SHIFTRA(VARG(s), NEG(VARG("t"))));
		return SETG(dv, res);
	}

	// shift-conditional: normalize the accumulator by one bit, recording in TC
	case C54X_INS_SFTC: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1 || !c54x_is_acc(op[0])) {
			return NULL;
		}
		const char *d = c54x_ilvar(op[0]);
		// redundant sign (bit31 == bit30): shift left 1 and clear TC; else set TC.
		RzILOpPure *res = ITE(INV(XOR(c54x_bit(VARL("v"), 31), c54x_bit(VARL("v"), 30))),
			SHIFTL0(VARL("v"), UN(8, 1)), VARL("v"));
		return SEQ3(SETL("v", VARG(d)), SETG(d, res),
			c54x_flag_assign("st0", C54X_F_TC, XOR(c54x_bit(VARL("v"), 31), c54x_bit(VARL("v"), 30))));
	}

	// store of T / TRN / #lk into Smem, plus the C54x parallel "ST ACx, Ymem ||
	// <op2> Xmem, dst" forms whose second operation is non-DSP (add / sub / ld).
	case C54X_INS_ST: {
		const C55Operand *op[6];
		int n = c54x_ops(insn, op, 6);
		// parallel form: [ACx, Ymem, <par2 mnemonic>, Xmem, dst]
		if (n == 5 && op[2]->kind == C55_OP_IMM && op[2]->raw) {
			const char *p2 = op[2]->raw;
			bool is_add = !strcmp(p2, "add"), is_sub = !strcmp(p2, "sub"), is_ld = !strcmp(p2, "ld");
			if (!is_add && !is_sub && !is_ld) {
				return NULL; // mpy / mac / mas: the multiplier datapath is out of scope
			}
			// ST part: Ymem = (ACx << ASM)[31:16] (store-high with the ASM shift)
			RzILOpPure *sth = c54x_var_shift(VARG(c54x_ilvar(op[0])), c54x_asm_amount(), true);
			RzILOpEffect *store = c55_write(a, op[1], CAST(16, IL_FALSE, SHIFTR0(sth, UN(8, 16))));
			// second op: add/sub place Xmem in the high half; ld loads it there
			// (or into T when the destination operand is T rather than an acc).
			RzILOpEffect *second;
			if (is_ld && !c54x_is_acc(op[4])) {
				second = SETG("t", c55_read(a, op[3]));
			} else {
				const char *d = c54x_ilvar(op[4]);
				RzILOpPure *x = SHIFTL0(SIGNED(40, c55_read(a, op[3])), UN(8, 16));
				RzILOpPure *r = is_add ? ADD(VARG(d), x) : (is_sub ? SUB(VARG(d), x) : x);
				second = SETG(d, r);
			}
			RzILOpEffect *body = SEQ2(store, second);
			return c54x_seq_post(body, c55_post_effect(a, op[1]), c55_post_effect(a, op[3]));
		}
		if (n != 2 || c54x_is_acc(op[0])) {
			return NULL;
		}
		RzILOpPure *v = c55_read(a, op[0]);
		RzILOpEffect *core = v ? c55_write(a, op[1], v) : NULL;
		return c54x_seq_post(core, c55_post_effect(a, op[1]), NULL);
	}

	// store accumulator low / high word (optionally shifted) to memory or MMR
	case C54X_INS_STL:
	case C54X_INS_STH:
	case C54X_INS_STLM: {
		const C55Operand *op[6];
		int n = c54x_ops(insn, op, 6);
		if (n < 2 || !c54x_is_acc(op[0])) {
			return NULL;
		}
		const C55Operand *shift = NULL, *mem;
		RzILOpPure *sh;
		if (n == 2) {
			mem = op[1];
			sh = VARG(c54x_ilvar(op[0]));
		} else if (n == 3 && op[1]->is_shift) {
			shift = op[1];
			mem = op[2];
			sh = c54x_apply_shift(VARG(c54x_ilvar(op[0])), shift, true);
		} else if (n == 3 && c54x_kw_id(op[1]) == 1) {
			// sth/stl ACx, ASM, Smem -> shift by the ASM field before storing
			mem = op[2];
			sh = c54x_var_shift(VARG(c54x_ilvar(op[0])), c54x_asm_amount(), true);
		} else {
			return NULL;
		}
		// stl/stlm take ACx[15:0]; sth takes ACx[31:16], after the optional shift.
		RzILOpPure *v = insn->id == C54X_INS_STH
			? CAST(16, IL_FALSE, SHIFTR0(sh, UN(8, 16)))
			: CAST(16, IL_FALSE, sh);
		RzILOpEffect *core = c55_write(a, mem, v);
		return c54x_seq_post(core, c55_post_effect(a, mem), NULL);
	}

	// conditional stores: if the accumulator condition holds, store ACx / BRC / T
	case C54X_INS_SACCD:
	case C54X_INS_SRCCD:
	case C54X_INS_STRCD: {
		const C55Operand *op[6];
		int n = c54x_ops(insn, op, 6);
		const C55Operand *mem = (insn->id == C54X_INS_SACCD) ? (n == 3 ? op[1] : NULL) : (n == 2 ? op[0] : NULL);
		const C55Operand *ccop = op[n - 1];
		if (!mem) {
			return NULL;
		}
		RzILOpBool *pred = c54x_cond4_pred((ut8)ccop->imm);
		if (!pred) {
			return NULL;
		}
		RzILOpPure *v;
		if (insn->id == C54X_INS_SACCD) {
			v = c54x_acc_lo(op[0]); // ACx low word (ASM-shift not modelled)
		} else if (insn->id == C54X_INS_SRCCD) {
			v = VARG("brc");
		} else {
			v = VARG("t");
		}
		RzILOpEffect *store = v ? c55_write(a, mem, v) : NULL;
		if (!store) {
			rz_il_op_pure_free(pred);
			return NULL;
		}
		RzILOpEffect *core = BRANCH(pred, store, NOP());
		return c54x_seq_post(core, c55_post_effect(a, mem), NULL);
	}

	// program-memory moves (program memory shares the unified IL address space)
	case C54X_INS_MVPD: {
		// mvpd pmad, Smem : Smem = program[pmad]
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *v = LOADW(16, c54x_prog_ea(UN(16, (ut16)op[0]->imm)));
		RzILOpEffect *core = c55_write(a, op[1], v);
		return c54x_seq_post(core, c55_post_effect(a, op[1]), NULL);
	}
	case C54X_INS_MVDP: {
		// mvdp Smem, pmad : program[pmad] = Smem
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpPure *v = c55_read(a, op[0]);
		RzILOpEffect *core = v ? STOREW(c54x_prog_ea(UN(16, (ut16)op[1]->imm)), v) : NULL;
		return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
	}
	case C54X_INS_READA:
	case C54X_INS_WRITA: {
		// reada Smem : Smem = program[A];  writa Smem : program[A] = Smem
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		RzILOpPure *pea = c54x_prog_ea(CAST(16, IL_FALSE, VARG("a")));
		RzILOpEffect *core;
		if (insn->id == C54X_INS_READA) {
			core = c55_write(a, op[0], LOADW(16, pea));
		} else {
			RzILOpPure *v = c55_read(a, op[0]);
			core = v ? STOREW(pea, v) : (rz_il_op_pure_free(pea), (RzILOpEffect *)NULL);
		}
		return c54x_seq_post(core, c55_post_effect(a, op[0]), NULL);
	}

	// load T register with delay-line copy
	case C54X_INS_LTD: {
		// ltd Smem : T = Smem; mem[Smem+1] = Smem
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		RzILOpEffect *setT = SETG("t", LOADW(16, c54x_ea(op[0])));
		RzILOpEffect *delay = STOREW(ADD(c54x_ea(op[0]), UN(24, C54X_WORD_BYTES)), LOADW(16, c54x_ea(op[0])));
		return SEQ2(setT, delay);
	}

	// stack-frame adjust: SP += signed immediate
	case C54X_INS_FRAME: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		return SETG("sp", ADD(VARG("sp"), UN(16, (ut16)op[0]->imm)));
	}

	// double (long-word) add / subtract, 32-bit (non-C16) interpretation
	case C54X_INS_DADD:
	case C54X_INS_DSUB: {
		const C55Operand *op[6];
		int n = c54x_ops(insn, op, 6);
		// DADD: [Lmem, src, dst(elide)]; DSUB: [Lmem, acc] (src == dst)
		if (n < 2 || !c54x_is_acc(op[1])) {
			return NULL;
		}
		const C55Operand *base = op[1];
		const C55Operand *dst = op[n - 1];
		RzILOpPure *hi = UNSIGNED(32, LOADW(16, c54x_ea(op[0])));
		RzILOpPure *lo = UNSIGNED(32, LOADW(16, ADD(c54x_ea(op[0]), UN(24, C54X_WORD_BYTES))));
		RzILOpPure *m40 = SIGNED(40, LOGOR(SHIFTL0(hi, UN(8, 16)), lo));
		const char *b = c54x_ilvar(base), *d = c54x_ilvar(dst);
		if (!b || !d) {
			rz_il_op_pure_free(m40);
			return NULL;
		}
		RzILOpPure *res = insn->id == C54X_INS_DADD ? ADD(VARG(b), m40) : SUB(VARG(b), m40);
		return c54x_seq_post(SETG(d, res), c55_post_effect(a, op[0]), NULL);
	}

	// repeat: only the modelable register / data effects are emitted; the loop
	// itself (next instruction running BRC+1 times) is control flow that
	// single-instruction RzIL cannot express.
	case C54X_INS_RPTZ: {
		// rptz ACx, #k : ACx = 0 (and load the repeat counter -- not modelled)
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) < 1 || !c54x_is_acc(op[0])) {
			return NULL;
		}
		return SETG(c54x_ilvar(op[0]), UN(40, 0));
	}
	case C54X_INS_RPTB: {
		// rptb pmad : block-repeat end address + active flag (count preloaded in BRC)
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) < 1) {
			return NULL;
		}
		return SEQ2(SETG("rea", UN(16, (ut16)op[0]->imm)), c54x_flag_on("st1", 15 /*BRAF*/));
	}

	// idle simply suspends the CPU until an interrupt -- no data-flow effect
	case C54X_INS_IDLE:
		return NOP();

	// conditional branch / call (call modelled as a plain jump, matching the
	// unconditional B/CALL family simplification)
	case C54X_INS_BC:
	case C54X_INS_BCD:
	case C54X_INS_CC:
	case C54X_INS_CCD: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2) {
			return NULL;
		}
		RzILOpBool *pred = c54x_cond_pred((ut8)op[1]->imm);
		if (!pred) {
			return NULL;
		}
		return BRANCH(pred, JMP(UN(24, (ut32)op[0]->imm)), NOP());
	}

	// conditional return
	case C54X_INS_RC:
	case C54X_INS_RCD: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 1) {
			return NULL;
		}
		RzILOpBool *pred = c54x_cond_pred((ut8)op[0]->imm);
		if (!pred) {
			return NULL;
		}
		RzILOpPure *target = UNSIGNED(24, LOADW(16, c54x_sp_ea()));
		RzILOpEffect *ret = SEQ2(SETG("sp", ADD(VARG("sp"), UN(16, 1))), JMP(target));
		return BRANCH(pred, ret, NOP());
	}

	// branch if the addressing auxiliary register is non-zero, then post-modify it
	case C54X_INS_BANZ:
	case C54X_INS_BANZD: {
		const C55Operand *op[6];
		if (c54x_ops(insn, op, 6) != 2 || op[1]->kind != C55_OP_MEM) {
			return NULL;
		}
		const C55RegInfo *ri = a->reg_info(op[1]->reg.cls, op[1]->reg.num, C55_SUB_NONE);
		const char *ar = ri ? ri->il_var : NULL;
		if (!ar) {
			return NULL;
		}
		// Test the AR before its post-modify, which happens regardless of branch.
		RzILOpEffect *grab = SETL("take", BOOL_TO_BV(INV(IS_ZERO(VARG(ar))), 1));
		RzILOpEffect *br = BRANCH(NON_ZERO(VARL("take")), JMP(UN(24, (ut32)op[0]->imm)), NOP());
		RzILOpEffect *post = c55_post_effect(a, op[1]);
		return post ? SEQ3(grab, post, br) : SEQ2(grab, br);
	}

	default:
		return NULL;
	}
}

#include <rz_il/rz_il_opbuilder_end.h>
