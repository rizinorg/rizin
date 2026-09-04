// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * RzIL lifter and VM configuration for the TMS320C2x core.
 *
 * Register model: a 32-bit accumulator ACC, a 16-bit temporary T, a 32-bit
 * product register P, eight 16-bit auxiliary registers AR0..7, a 9-bit data
 * page DP, the 3-bit ARP pointer, ST0/ST1 status words, a 16-bit PC, a
 * synthetic stack pointer SP and the live status bits carry (C), overflow (OV),
 * test/control (TC) plus the OVM/SXM/PM mode bits.
 *
 * Addressing: both DP-direct and the ARP-relative indirect modes are lifted.
 * Indirect reads/writes resolve AR[ARP] with an 8-way ITE over ARP, and the
 * post-modify (*+, *-, *0+, *0-) writes the selected AR back conditionally; the
 * reverse-carry (*BR0+/-) modes resolve the address but leave AR unmodified.
 *
 * Flags: ADD/SUB-family carry and overflow follow the silicon (MAME) exactly,
 * including the OVM saturation of ACC and the sticky OV that the BV/BNV branches
 * consume. The hardware stack is internal (not memory-mapped); push/pop/call/
 * ret model it through SP into the data space so values round-trip.
 */

#include "c2x.h"
#include <rz_il/rz_il_opbuilder_begin.h>

static const char *const c2x_ar[8] = {
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7"
};

// addressing

// AR[ARP] resolved at run time via an 8-way select over ARP (16-bit value).
static RzILOpPure *c2x_ind_addr(void) {
	RzILOpPure *v = VARG("ar7");
	for (int k = 6; k >= 0; k--) {
		v = ITE(EQ(VARG("arp"), UN(16, (ut32)k)), VARG(c2x_ar[k]), v);
	}
	return v;
}

// Effective address for a memory operand: DP-direct => (DP[8:0]<<7)|dma7;
// any indirect mode => AR[ARP]. The data space is word-addressed.
static RzILOpPure *c2x_addr(const C55Operand *m) {
	if (m->amode == C55_AM_DIRECT) {
		RzILOpPure *page = SHIFTL0(LOGAND(VARG("dp"), UN(16, 0x1ff)), UN(16, 7));
		return LOGOR(page, UN(16, (ut32)m->disp & 0x7f));
	}
	return c2x_ind_addr();
}

/**
 * \brief Effective-address hook for the C2x DP-direct addressing mode.
 * \param a Unused; the direct form needs no arch state
 * \param m Memory operand to resolve
 * \return Pure expression yielding the *word* address
 *
 * Word (not byte) addresses are the analysis/CFG convention for this arch;
 * c2x_byte() scales the result where a byte address is needed.
 */
RZ_IPI RzILOpPure *c2x_ea(RZ_UNUSED const C55ArchDesc *a, const C55Operand *m) {
	if (m->amode != C55_AM_DIRECT) {
		return NULL;
	}
	return c2x_addr(m);
}

// The IL VM memory is byte-addressed while the C2x is word-addressed: one data
// word spans C2X_WORD_BYTES byte-address units, so a word address scales to a
// byte address by that factor (matching the C54x lifter's C54X_WORD_BYTES).
// AR/DP/SP keep word values; only the byte at which a word is read/written is
// scaled. The scaling is done in the C2X_MEM_ADDR_BITS-wide address space.
static RzILOpPure *c2x_byte(RzILOpPure *word_addr) {
	return MUL(UNSIGNED(C2X_MEM_ADDR_BITS, word_addr), UN(C2X_MEM_ADDR_BITS, C2X_WORD_BYTES));
}

static RzILOpPure *c2x_mem_read(const C55Operand *m) {
	return LOADW(16, c2x_byte(c2x_addr(m)));
}

static RzILOpEffect *c2x_mem_write(const C55Operand *m, RzILOpPure *val) {
	return STOREW(c2x_byte(c2x_addr(m)), val);
}

// SST/SST1 use a special direct form: the 7-bit offset addresses data page 0
// (DP is ignored). Indirect forms use AR[ARP] as usual.
static RzILOpPure *c2x_sst_addr(const C55Operand *m) {
	if (m->amode == C55_AM_DIRECT) {
		return UN(16, (ut32)m->disp & 0x7f);
	}
	return c2x_ind_addr();
}

// Read one program-memory word at a constant word address (program and data
// share the IL byte-address space; the word scales x2).
static RzILOpPure *c2x_prog_read(ut16 pma) {
	return LOADW(16, c2x_byte(UN(16, pma)));
}

// The AR post-modification for register \p k under addressing mode \p am, or
// NULL when \p am does not touch the AR (direct, *no-modify or reverse-carry).
static RzILOpPure *c2x_ar_post_expr(C55AddrMode am, int k) {
	switch (am) {
	case C55_AM_POSTINC: return ADD(VARG(c2x_ar[k]), UN(16, 1));
	case C55_AM_POSTDEC: return SUB(VARG(c2x_ar[k]), UN(16, 1));
	case C55_AM_POSTADD: return ADD(VARG(c2x_ar[k]), VARG("ar0"));
	case C55_AM_POSTSUB: return SUB(VARG(c2x_ar[k]), VARG("ar0"));
	default: return NULL;
	}
}

// AR post-modification (and next-ARP reload) encoded by an indirect operand.
// Returns NULL when there is nothing to do (direct, or *no-modify).
// The AR post-modify only (no next-ARP load); used by the status load/store
// instructions, whose addressing ignores the next-ARP field (IgnoreARPHack).
static RzILOpEffect *c2x_ar_post(const C55Insn *insn, ut8 memidx) {
	if (memidx >= insn->n_ops) {
		return NULL;
	}
	const C55Operand *m = &insn->ops[memidx];
	if (m->kind != C55_OP_MEM) {
		return NULL;
	}
	RzILOpEffect *sets[8];
	for (int k = 0; k < 8; k++) {
		// The mode is loop-invariant, so a non-post-modify form bails on the
		// first pass with nothing allocated yet.
		RzILOpPure *mod = c2x_ar_post_expr(m->amode, k);
		if (!mod) {
			return NULL;
		}
		sets[k] = SETG(c2x_ar[k], ITE(EQ(VARG("arp"), UN(16, (ut32)k)), mod, VARG(c2x_ar[k])));
	}
	return SEQ8(sets[0], sets[1], sets[2], sets[3], sets[4], sets[5], sets[6], sets[7]);
}

// Full post-modify: AR update plus the next-ARP load encoded by a following AR
// register operand.
static RzILOpEffect *c2x_ar_modify(const C55Insn *insn, ut8 memidx) {
	RzILOpEffect *eff = c2x_ar_post(insn, memidx);
	if (memidx + 1 < insn->n_ops && insn->ops[memidx + 1].kind == C55_OP_REG &&
		insn->ops[memidx + 1].reg.cls == C55_RC_AR) {
		// next-ARP is a MODIFY_ARP: previous ARP is buffered into ARB.
		RzILOpEffect *sa = SEQ2(SETG("arb", VARG("arp")),
			SETG("arp", UN(16, insn->ops[memidx + 1].reg.num & 7)));
		eff = eff ? SEQ2(eff, sa) : sa;
	}
	return eff;
}

// Append the (optional) AR post-modify to a core effect. The post-modify is
// legitimately absent (NULL) for direct and *no-modify forms, so it is the only
// operand allowed to be NULL; a NULL core would be a lifter bug and is passed
// straight to SEQ2, which keeps its NULL warning. Mirrors the sibling C54x
// lifter's c54x_seq_post.
static RzILOpEffect *c2x_seq_post(RzILOpEffect *core, RzILOpEffect *post) {
	return post ? SEQ2(core, post) : core;
}

// read mem into local "m", run body (which uses VARL("m")), then post-modify AR
static RzILOpEffect *c2x_with_mem(const C55Insn *insn, ut8 memidx, RzILOpEffect *body) {
	return c2x_seq_post(SEQ2(SETL("m", c2x_mem_read(&insn->ops[memidx])), body),
		c2x_ar_modify(insn, memidx));
}

// The MAC family names both a program-memory address and a data-memory operand,
// but the two architectures spell them in opposite orders ("#pma, dma" on C2x,
// "dma, #pma" on C5x), so each is located by role rather than by a fixed index.
// The optional next-ARP operand is a register and so never matches either.
static ut8 c2x_mem_opidx(const C55Insn *insn) {
	for (ut8 i = 0; i < insn->n_ops; i++) {
		if (insn->ops[i].kind == C55_OP_MEM) {
			return i;
		}
	}
	return 0;
}

static ut16 c2x_pma_opval(const C55Insn *insn) {
	for (ut8 i = 0; i < insn->n_ops; i++) {
		if (insn->ops[i].kind == C55_OP_IMM) {
			return (ut16)insn->ops[i].imm;
		}
	}
	return 0;
}

// the GETDATA value: local "m" extended to 32 bits (per SXM when sxm_ext) and
// shifted left by sh.
static RzILOpPure *c2x_mval(ut8 sh, bool sxm_ext) {
	RzILOpPure *v = sxm_ext
		? ITE(VARG("sxm"), SIGNED(32, VARL("m")), UNSIGNED(32, VARL("m")))
		: UNSIGNED(32, VARL("m"));
	if (sh) {
		v = SHIFTL0(v, UN(6, sh));
	}
	return v;
}

// accumulator arithmetic with carry/overflow

typedef enum { CM_ASSIGN,
	CM_SETONLY,
	CM_NONE } c2x_cmode;

// acc += val  (val 32-bit). Sets ACC (with OVM saturation), sticky OV and,
// per cm, the carry. Implemented exactly as the MAME C2x core.
static RzILOpEffect *c2x_acc_add(RzILOpPure *val, c2x_cmode cm) {
	RzILOpEffect *flags = SETG("ov", OR(VARG("ov"), VARL("ovn")));
	if (cm == CM_ASSIGN) {
		flags = SEQ2(SETG("c", ULT(VARL("na"), VARL("oa"))), flags);
	} else if (cm == CM_SETONLY) {
		flags = SEQ2(SETG("c", OR(VARG("c"), ULT(VARL("na"), VARL("oa")))), flags);
	}
	return SEQ5(
		SETL("oa", VARG("acc")),
		SETL("av", val),
		SETL("na", ADD(VARL("oa"), VARL("av"))),
		SEQ2(
			SETL("ovn", MSB(LOGAND(LOGXOR(VARL("na"), VARL("av")), LOGXOR(VARL("oa"), VARL("na"))))),
			SETG("acc", ITE(AND(VARG("ovm"), VARL("ovn")), ITE(SLT(VARL("oa"), SN(32, 0)), UN(32, 0x80000000), UN(32, 0x7fffffff)), VARL("na")))),
		flags);
}

// acc -= val (val 32-bit), MAME semantics.
static RzILOpEffect *c2x_acc_sub(RzILOpPure *val, c2x_cmode cm) {
	RzILOpEffect *flags = SETG("ov", OR(VARG("ov"), VARL("ovn")));
	if (cm == CM_ASSIGN) {
		flags = SEQ2(SETG("c", INV(ULT(VARL("oa"), VARL("na")))), flags);
	} else if (cm == CM_SETONLY) { // SUBH: clears carry only on borrow
		flags = SEQ2(SETG("c", AND(VARG("c"), INV(ULT(VARL("oa"), VARL("na"))))), flags);
	}
	return SEQ5(
		SETL("oa", VARG("acc")),
		SETL("av", val),
		SETL("na", SUB(VARL("oa"), VARL("av"))),
		SEQ2(
			SETL("ovn", MSB(LOGAND(LOGXOR(VARL("oa"), VARL("av")), LOGXOR(VARL("oa"), VARL("na"))))),
			SETG("acc", ITE(AND(VARG("ovm"), VARL("ovn")), ITE(SLT(VARL("oa"), SN(32, 0)), UN(32, 0x80000000), UN(32, 0x7fffffff)), VARL("na")))),
		flags);
}

// P register shifted into the ALU per the PM mode (0:none 1:<<1 2:<<4 3:>>6 asr)
static RzILOpPure *c2x_pshift(void) {
	return ITE(EQ(VARG("pm"), UN(2, 0)), VARG("p"),
		ITE(EQ(VARG("pm"), UN(2, 1)), SHIFTL0(VARG("p"), UN(6, 1)),
			ITE(EQ(VARG("pm"), UN(2, 2)), SHIFTL0(VARG("p"), UN(6, 4)),
				SHIFTR(MSB(VARG("p")), VARG("p"), UN(6, 6)))));
}

// 13-bit sign-extended MPYK constant
static st32 c2x_mpyk_imm(const C55Insn *insn) {
	return rz_bits_sign_ext32((ut32)(insn->ops[0].imm & 0x1fff), 13);
}

// long (16-bit) immediate value of a Dxxx instruction, extended per SXM and
// shifted; ANDK/ORK/XORK pass sxm_ext=false (always zero-extended).
static RzILOpPure *c2x_longimm(const C55Insn *insn, bool sxm_ext) {
	ut16 imm = (ut16)(insn->ops[0].imm & 0xffff);
	ut8 sh = (ut8)(insn->ops[1].imm & 0xf);
	RzILOpPure *v = sxm_ext
		? ITE(VARG("sxm"), SN(32, (st16)imm), UN(32, imm))
		: UN(32, imm);
	if (sh) {
		v = SHIFTL0(v, UN(6, sh));
	}
	return v;
}

// Branch/call target: the encoded value is a *word* address; the IL PC is byte-
// addressed, so scale x2 (word code addresses up to 0x7fff fit the 16-bit PC).
static RzILOpPure *c2x_jt(const C55Insn *insn, ut8 i) {
	return UN(16, ((ut32)insn->ops[i].imm & 0xffff) * C2X_WORD_BYTES);
}

// add/subtract the same 8-bit immediate to/from the ARP-selected AR (ADRK/SBRK)
static RzILOpEffect *c2x_ar_addimm(const C55Insn *insn, bool sub) {
	ut32 k = (ut32)insn->ops[0].imm & 0xff;
	RzILOpEffect *sets[8];
	int i;
	for (i = 0; i < 8; i++) {
		RzILOpPure *mod = sub ? SUB(VARG(c2x_ar[i]), UN(16, k)) : ADD(VARG(c2x_ar[i]), UN(16, k));
		sets[i] = SETG(c2x_ar[i], ITE(EQ(VARG("arp"), UN(16, (ut32)i)), mod, VARG(c2x_ar[i])));
	}
	return SEQ8(sets[0], sets[1], sets[2], sets[3], sets[4], sets[5], sets[6], sets[7]);
}

// main lifter

/**
 * \brief Lift one decoded C2x instruction to RzIL.
 * \param insn Decoded instruction
 * \param pc Address of \p insn, for PC-relative effects
 * \return Newly allocated effect, or NULL if \p insn has no lifter yet
 */
RZ_IPI RzILOpEffect *c2x_lift(const C55Insn *insn, ut64 pc) {
	switch (insn->id) {
	case C2X_INS_NOP:
	case C2X_INS_CNFD:
	case C2X_INS_CNFP:
	case C2X_INS_CONF:
	case C2X_INS_RFSM:
	case C2X_INS_SFSM:
	case C2X_INS_RHM:
	case C2X_INS_SHM:
	case C2X_INS_RTXM:
	case C2X_INS_STXM:
	case C2X_INS_FORT:
	case C2X_INS_RXF:
	case C2X_INS_SXF:
	case C2X_INS_EINT:
	case C2X_INS_DINT:
	case C2X_INS_IDLE:
		return NOP();
	case C2X_INS_MAR: {
		RzILOpEffect *e = c2x_ar_modify(insn, 0);
		return e ? e : NOP();
	}
	case C2X_INS_LARP:
		// MODIFY_ARP: the previous ARP is saved into ARB, then ARP is loaded.
		return SEQ2(SETG("arb", VARG("arp")), SETG("arp", UN(16, (ut32)insn->ops[0].imm & 7)));

	// mode / status bit set & clear
	case C2X_INS_RC:
		return SETG("c", IL_FALSE);
	case C2X_INS_SC:
		return SETG("c", IL_TRUE);
	case C2X_INS_RTC:
		return SETG("tc", IL_FALSE);
	case C2X_INS_STC:
		return SETG("tc", IL_TRUE);
	case C2X_INS_ROVM:
		return SETG("ovm", IL_FALSE);
	case C2X_INS_SOVM:
		return SETG("ovm", IL_TRUE);
	case C2X_INS_RSXM:
		return SETG("sxm", IL_FALSE);
	case C2X_INS_SSXM:
		return SETG("sxm", IL_TRUE);
	case C2X_INS_SPM:
		return SETG("pm", UN(2, (ut32)insn->ops[0].imm & 3));

	// immediate loads
	case C2X_INS_ZAC:
		return SETG("acc", UN(32, 0));
	case C2X_INS_LACK:
		return SETG("acc", UN(32, (ut32)insn->ops[0].imm & 0xff));
	case C2X_INS_LDPK:
		return SETG("dp", UN(16, (ut32)insn->ops[0].imm & 0x1ff));
	case C2X_INS_LARK:
		return SETG(c2x_ar[insn->ops[0].reg.num & 7], UN(16, (ut32)insn->ops[1].imm & 0xff));
	case C2X_INS_ADDK:
		return c2x_acc_add(UN(32, (ut32)insn->ops[0].imm & 0xff), CM_ASSIGN);
	case C2X_INS_SUBK:
		return c2x_acc_sub(UN(32, (ut32)insn->ops[0].imm & 0xff), CM_ASSIGN);
	case C2X_INS_LALK:
		return SETG("acc", c2x_longimm(insn, true));
	case C2X_INS_ADLK:
		return c2x_acc_add(c2x_longimm(insn, true), CM_ASSIGN);
	case C2X_INS_SBLK:
		return c2x_acc_sub(c2x_longimm(insn, true), CM_ASSIGN);
	case C2X_INS_ANDK:
		return SETG("acc", LOGAND(VARG("acc"), c2x_longimm(insn, false)));
	case C2X_INS_ORK:
		return SETG("acc", LOGOR(VARG("acc"), c2x_longimm(insn, false)));
	case C2X_INS_XORK:
		return SETG("acc", LOGXOR(VARG("acc"), c2x_longimm(insn, false)));
	case C2X_INS_LRLK:
		return SETG(c2x_ar[insn->ops[0].reg.num & 7], UN(16, (ut32)insn->ops[1].imm & 0xffff));

	// accumulator unary
	case C2X_INS_ABS:
		return SEQ2(SETG("acc", ITE(SLT(VARG("acc"), SN(32, 0)), NEG(VARG("acc")), VARG("acc"))),
			SETG("c", IL_FALSE));
	case C2X_INS_NEG:
		return SEQ3(SETL("oa", VARG("acc")), SETG("acc", NEG(VARL("oa"))),
			SETG("c", IS_ZERO(VARL("oa"))));
	case C2X_INS_CMPL:
		return SETG("acc", LOGNOT(VARG("acc")));
	case C2X_INS_SFL:
		return SEQ3(SETL("oa", VARG("acc")),
			SETG("acc", SHIFTL0(VARL("oa"), UN(6, 1))),
			SETG("c", MSB(VARL("oa"))));
	case C2X_INS_SFR:
		return SEQ3(SETL("oa", VARG("acc")),
			SETG("acc", ITE(VARG("sxm"), SHIFTR(MSB(VARL("oa")), VARL("oa"), UN(6, 1)), SHIFTR0(VARL("oa"), UN(6, 1)))),
			SETG("c", LSB(VARL("oa"))));
	case C2X_INS_ROL:
		return SEQ3(SETL("oa", VARG("acc")),
			SETG("acc", LOGOR(SHIFTL0(VARL("oa"), UN(6, 1)), ITE(VARG("c"), UN(32, 1), UN(32, 0)))),
			SETG("c", MSB(VARL("oa"))));
	case C2X_INS_ROR:
		return SEQ3(SETL("oa", VARG("acc")),
			SETG("acc", LOGOR(SHIFTR0(VARL("oa"), UN(6, 1)), ITE(VARG("c"), UN(32, 0x80000000), UN(32, 0)))),
			SETG("c", LSB(VARL("oa"))));

	// product register moves
	case C2X_INS_PAC:
		return SETG("acc", c2x_pshift());
	case C2X_INS_APAC:
		return c2x_acc_add(c2x_pshift(), CM_ASSIGN);
	case C2X_INS_SPAC:
		return c2x_acc_sub(c2x_pshift(), CM_ASSIGN);
	case C2X_INS_MPYK:
		return SETG("p", MUL(SIGNED(32, VARG("t")), SN(32, c2x_mpyk_imm(insn))));
	case C2X_INS_SPL:
		return c2x_seq_post(c2x_mem_write(&insn->ops[0], CAST(16, IL_FALSE, c2x_pshift())),
			c2x_ar_modify(insn, 0));
	case C2X_INS_SPH:
		return c2x_seq_post(c2x_mem_write(&insn->ops[0], CAST(16, IL_FALSE, SHIFTR0(c2x_pshift(), UN(6, 16)))),
			c2x_ar_modify(insn, 0));

	// DP-direct / indirect memory: load-accumulator family
	case C2X_INS_LAC:
		return c2x_with_mem(insn, 0, SETG("acc", c2x_mval(insn->ops[1].imm & 0xf, true)));
	case C2X_INS_LACT:
		return c2x_with_mem(insn, 0, SETG("acc", SHIFTL0(ITE(VARG("sxm"), SIGNED(32, VARL("m")), UNSIGNED(32, VARL("m"))), LOGAND(VARG("t"), UN(16, 0xf)))));
	case C2X_INS_ZALH:
		return c2x_with_mem(insn, 0, SETG("acc", SHIFTL0(UNSIGNED(32, VARL("m")), UN(6, 16))));
	case C2X_INS_ZALS:
		return c2x_with_mem(insn, 0, SETG("acc", UNSIGNED(32, VARL("m"))));
	case C2X_INS_ZALR:
		return c2x_with_mem(insn, 0, SETG("acc", LOGOR(SHIFTL0(UNSIGNED(32, VARL("m")), UN(6, 16)), UN(32, 0x8000))));
	case C2X_INS_ADD:
		return c2x_with_mem(insn, 0, c2x_acc_add(c2x_mval(insn->ops[1].imm & 0xf, true), CM_ASSIGN));
	case C2X_INS_ADDS:
		return c2x_with_mem(insn, 0, c2x_acc_add(c2x_mval(0, false), CM_ASSIGN));
	case C2X_INS_ADDT:
		return c2x_with_mem(insn, 0, c2x_acc_add(SHIFTL0(ITE(VARG("sxm"), SIGNED(32, VARL("m")), UNSIGNED(32, VARL("m"))), LOGAND(VARG("t"), UN(16, 0xf))), CM_ASSIGN));
	case C2X_INS_ADDH:
		return c2x_with_mem(insn, 0, c2x_acc_add(SHIFTL0(UNSIGNED(32, VARL("m")), UN(6, 16)), CM_SETONLY));
	case C2X_INS_SUB:
		return c2x_with_mem(insn, 0, c2x_acc_sub(c2x_mval(insn->ops[1].imm & 0xf, true), CM_ASSIGN));
	case C2X_INS_SUBS:
		return c2x_with_mem(insn, 0, c2x_acc_sub(c2x_mval(0, false), CM_ASSIGN));
	case C2X_INS_SUBT:
		return c2x_with_mem(insn, 0, c2x_acc_sub(SHIFTL0(ITE(VARG("sxm"), SIGNED(32, VARL("m")), UNSIGNED(32, VARL("m"))), LOGAND(VARG("t"), UN(16, 0xf))), CM_ASSIGN));
	case C2X_INS_SUBH:
		return c2x_with_mem(insn, 0, c2x_acc_sub(SHIFTL0(UNSIGNED(32, VARL("m")), UN(6, 16)), CM_SETONLY));
	case C2X_INS_ADDC:
		return c2x_with_mem(insn, 0, SEQ6(SETL("oa", VARG("acc")), SETL("av", UNSIGNED(32, VARL("m"))), SETL("na", ADD(ADD(VARL("oa"), VARL("av")), ITE(VARG("c"), UN(32, 1), UN(32, 0)))), SETG("acc", VARL("na")), SETG("ov", OR(VARG("ov"), MSB(LOGAND(LOGXOR(VARL("na"), VARL("av")), LOGXOR(VARL("oa"), VARL("na")))))), SETG("c", ITE(EQ(VARL("na"), VARL("oa")), VARG("c"), ULT(VARL("na"), VARL("oa"))))));
	case C2X_INS_SUBB:
		return c2x_with_mem(insn, 0, SEQ6(SETL("oa", VARG("acc")), SETL("av", UNSIGNED(32, VARL("m"))), SETL("na", SUB(SUB(VARL("oa"), VARL("av")), ITE(VARG("c"), UN(32, 0), UN(32, 1)))), SETG("acc", VARL("na")), SETG("ov", OR(VARG("ov"), MSB(LOGAND(LOGXOR(VARL("oa"), VARL("av")), LOGXOR(VARL("oa"), VARL("na")))))), SETG("c", ITE(EQ(VARL("na"), VARL("oa")), VARG("c"), INV(ULT(VARL("oa"), VARL("na")))))));
	case C2X_INS_SUBC:
		return c2x_with_mem(insn, 0, SEQ6(SETL("oa", VARG("acc")), SETL("av", SHIFTL0(ITE(VARG("sxm"), SIGNED(32, VARL("m")), UNSIGNED(32, VARL("m"))), UN(6, 15))), SETL("na", SUB(VARL("oa"), VARL("av"))), SETG("ov", OR(VARG("ov"), MSB(LOGAND(LOGXOR(VARL("oa"), VARL("av")), LOGXOR(VARL("oa"), VARL("na")))))), SETG("c", INV(ULT(VARL("oa"), VARL("na")))), SETG("acc", ITE(INV(ULT(VARL("oa"), VARL("av"))), LOGOR(SHIFTL0(VARL("na"), UN(6, 1)), UN(32, 1)), SHIFTL0(VARL("oa"), UN(6, 1))))));

	// logical with memory
	case C2X_INS_AND:
		return c2x_with_mem(insn, 0, SETG("acc", LOGAND(VARG("acc"), UNSIGNED(32, VARL("m")))));
	case C2X_INS_OR:
		return c2x_with_mem(insn, 0, SETG("acc", LOGOR(VARG("acc"), UNSIGNED(32, VARL("m")))));
	case C2X_INS_XOR:
		return c2x_with_mem(insn, 0, SETG("acc", LOGXOR(VARG("acc"), UNSIGNED(32, VARL("m")))));

	// T / P loads & multiply with memory
	case C2X_INS_LT:
		return c2x_with_mem(insn, 0, SETG("t", VARL("m")));
	case C2X_INS_LTA:
		return c2x_with_mem(insn, 0, SEQ2(SETG("t", VARL("m")), c2x_acc_add(c2x_pshift(), CM_ASSIGN)));
	case C2X_INS_LTP:
		return c2x_with_mem(insn, 0, SEQ2(SETG("t", VARL("m")), SETG("acc", c2x_pshift())));
	case C2X_INS_LTS:
		return c2x_with_mem(insn, 0, SEQ2(SETG("t", VARL("m")), c2x_acc_sub(c2x_pshift(), CM_ASSIGN)));
	case C2X_INS_LTD:
		return c2x_with_mem(insn, 0, SEQ3(SETG("t", VARL("m")), STOREW(c2x_byte(ADD(c2x_addr(&insn->ops[0]), UN(16, 1))), VARL("m")), c2x_acc_add(c2x_pshift(), CM_ASSIGN)));
	case C2X_INS_LPH:
		return c2x_with_mem(insn, 0, SETG("p", LOGOR(LOGAND(VARG("p"), UN(32, 0xffff)), SHIFTL0(UNSIGNED(32, VARL("m")), UN(6, 16)))));
	case C2X_INS_MPY:
		return c2x_with_mem(insn, 0, SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, VARG("t")))));
	case C2X_INS_MPYU:
		return c2x_with_mem(insn, 0, SETG("p", MUL(UNSIGNED(32, VARL("m")), UNSIGNED(32, VARG("t")))));
	case C2X_INS_MPYA:
		return SEQ2(c2x_acc_add(c2x_pshift(), CM_ASSIGN),
			c2x_with_mem(insn, 0, SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, VARG("t"))))));
	case C2X_INS_MPYS:
		return SEQ2(c2x_acc_sub(c2x_pshift(), CM_ASSIGN),
			c2x_with_mem(insn, 0, SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, VARG("t"))))));
	case C2X_INS_SQRA:
		return SEQ2(c2x_acc_add(c2x_pshift(), CM_ASSIGN),
			c2x_with_mem(insn, 0, SEQ2(SETG("t", VARL("m")), SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, VARL("m")))))));
	case C2X_INS_SQRS:
		return SEQ2(c2x_acc_sub(c2x_pshift(), CM_ASSIGN),
			c2x_with_mem(insn, 0, SEQ2(SETG("t", VARL("m")), SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, VARL("m")))))));

	// bit test
	case C2X_INS_BIT:
		return c2x_with_mem(insn, 0, SETG("tc", LSB(SHIFTR0(VARL("m"), UN(4, (ut32)(15 - (insn->ops[1].imm & 0xf)))))));
	case C2X_INS_BITT:
		return c2x_with_mem(insn, 0, SETG("tc", LSB(SHIFTR0(VARL("m"), SUB(UN(16, 15), LOGAND(VARG("t"), UN(16, 0xf)))))));

	// AR load/store
	case C2X_INS_LAR: {
		ut8 n = insn->ops[0].reg.num & 7;
		// The C5x "lar arN, #imm16" form carries an immediate (a load-AR-long,
		// rendered "lar"); the C2x/C5x memory form takes an addressing byte.
		if (insn->ops[1].kind == C55_OP_IMM) {
			return SETG(c2x_ar[n], UN(16, (ut32)insn->ops[1].imm & 0xffff));
		}
		RzILOpEffect *mod = c2x_ar_modify(insn, 1);
		RzILOpEffect *ld = SETG(c2x_ar[n], VARL("m"));
		// MAME applies the AR post-modify (part of GETDATA) before the load,
		// so a self-load (N==ARP) keeps the loaded value.
		return SEQ2(SETL("m", c2x_mem_read(&insn->ops[1])), mod ? SEQ2(mod, ld) : ld);
	}
	case C2X_INS_SAR:
		return c2x_seq_post(c2x_mem_write(&insn->ops[1], VARG(c2x_ar[insn->ops[0].reg.num & 7])),
			c2x_ar_modify(insn, 1));
	case C2X_INS_ADRK:
		return c2x_ar_addimm(insn, false);
	case C2X_INS_SBRK:
		return c2x_ar_addimm(insn, true);

	// store accumulator
	case C2X_INS_SACL: {
		ut8 sh = (ut8)(insn->ops[1].imm & 7);
		RzILOpPure *v = sh ? SHIFTL0(VARG("acc"), UN(6, sh)) : VARG("acc");
		return c2x_seq_post(c2x_mem_write(&insn->ops[0], CAST(16, IL_FALSE, v)), c2x_ar_modify(insn, 0));
	}
	case C2X_INS_SACH: {
		ut8 sh = (ut8)(insn->ops[1].imm & 7);
		RzILOpPure *v = sh ? SHIFTL0(VARG("acc"), UN(6, sh)) : VARG("acc");
		return c2x_seq_post(c2x_mem_write(&insn->ops[0], CAST(16, IL_FALSE, SHIFTR0(v, UN(6, 16)))), c2x_ar_modify(insn, 0));
	}

	// data move / transfer
	case C2X_INS_DMOV:
		return c2x_with_mem(insn, 0, STOREW(c2x_byte(ADD(c2x_addr(&insn->ops[0]), UN(16, 1))), VARL("m")));
	case C2X_INS_TBLR:
		return c2x_seq_post(c2x_mem_write(&insn->ops[0], LOADW(16, c2x_byte(CAST(16, IL_FALSE, VARG("acc"))))),
			c2x_ar_modify(insn, 0));
	case C2X_INS_TBLW:
		return c2x_with_mem(insn, 0, STOREW(c2x_byte(CAST(16, IL_FALSE, VARG("acc"))), VARL("m")));

	// stack (modelled through SP into data space)
	case C2X_INS_PUSH:
		return SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), STOREW(c2x_byte(VARG("sp")), CAST(16, IL_FALSE, VARG("acc"))));
	case C2X_INS_POP:
		return SEQ2(SETG("acc", UNSIGNED(32, LOADW(16, c2x_byte(VARG("sp"))))), SETG("sp", ADD(VARG("sp"), UN(16, 1))));
	case C2X_INS_PSHD:
		return c2x_with_mem(insn, 0, SEQ2(SETG("sp", SUB(VARG("sp"), UN(16, 1))), STOREW(c2x_byte(VARG("sp")), VARL("m"))));
	case C2X_INS_POPD:
		return c2x_seq_post(SEQ3(SETL("v", LOADW(16, c2x_byte(VARG("sp")))), SETG("sp", ADD(VARG("sp"), UN(16, 1))),
					    c2x_mem_write(&insn->ops[0], VARL("v"))),
			c2x_ar_modify(insn, 0));

	// control transfer
	case C2X_INS_B:
		return JMP(c2x_jt(insn, 0));
	case C2X_INS_BACC:
		return JMP(MUL(CAST(16, IL_FALSE, VARG("acc")), UN(16, 2)));
	case C2X_INS_CALL:
		return SEQ3(SETG("sp", SUB(VARG("sp"), UN(16, 1))),
			STOREW(c2x_byte(VARG("sp")), UN(16, (ut32)(pc + 2) & 0xffff)), JMP(c2x_jt(insn, 0)));
	case C2X_INS_CALA:
		return SEQ3(SETG("sp", SUB(VARG("sp"), UN(16, 1))),
			STOREW(c2x_byte(VARG("sp")), UN(16, (ut32)(pc + 1) & 0xffff)), JMP(MUL(CAST(16, IL_FALSE, VARG("acc")), UN(16, 2))));
	case C2X_INS_RET:
		return SEQ2(SETL("r", LOADW(16, c2x_byte(VARG("sp")))),
			SEQ2(SETG("sp", ADD(VARG("sp"), UN(16, 1))), JMP(VARL("r"))));
	case C2X_INS_TRAP:
		return SEQ3(SETG("sp", SUB(VARG("sp"), UN(16, 1))),
			STOREW(c2x_byte(VARG("sp")), UN(16, (ut32)(pc + 1) & 0xffff)), JMP(UN(16, 0x1e)));
	case C2X_INS_BZ:
		return BRANCH(IS_ZERO(VARG("acc")), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BNZ:
		return BRANCH(NON_ZERO(VARG("acc")), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BGZ:
		return BRANCH(SGT(VARG("acc"), SN(32, 0)), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BLZ:
		return BRANCH(SLT(VARG("acc"), SN(32, 0)), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BGEZ:
		return BRANCH(SGE(VARG("acc"), SN(32, 0)), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BLEZ:
		return BRANCH(SLE(VARG("acc"), SN(32, 0)), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BC:
		return BRANCH(VARG("c"), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BNC:
		return BRANCH(IS_ZERO(VARG("c")), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BBZ:
		return BRANCH(IS_ZERO(VARG("tc")), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BBNZ:
		return BRANCH(VARG("tc"), JMP(c2x_jt(insn, 0)), NOP());
	case C2X_INS_BV:
		return BRANCH(VARG("ov"), SEQ2(SETG("ov", IL_FALSE), JMP(c2x_jt(insn, 0))), NOP());
	case C2X_INS_BNV:
		return BRANCH(IS_ZERO(VARG("ov")), JMP(c2x_jt(insn, 0)), SETG("ov", IL_FALSE));
	case C2X_INS_BANZ: {
		// Test the loop-counter AR (ARP-selected) before modifying it, branch
		// while non-zero, and apply the indirect post-modify (*- decrement) plus
		// any next-ARP reload. The post-modify must run before the branch so the
		// control effect ends the sequence (a ctrl op cannot be followed by more
		// effects); the pre-modify AR value is captured first for the test.
		RzILOpEffect *upd = c2x_ar_modify(insn, 1);
		if (!upd) {
			return BRANCH(NON_ZERO(c2x_ind_addr()), JMP(c2x_jt(insn, 0)), NOP());
		}
		return SEQ3(SETL("ba", c2x_ind_addr()), upd,
			BRANCH(NON_ZERO(VARL("ba")), JMP(c2x_jt(insn, 0)), NOP()));
	}

	// compare AR to AR0 -> TC
	case C2X_INS_CMPR: {
		ut8 mode = (ut8)(insn->ops[0].imm & 3);
		RzILOpPure *a = c2x_ind_addr();
		RzILOpPure *z = VARG("ar0");
		RzILOpPure *cmp;
		switch (mode) {
		case 0: cmp = EQ(a, z); break;
		case 1: cmp = ULT(a, z); break;
		case 2: cmp = UGT(a, z); break;
		default: cmp = INV(EQ(a, z)); break;
		}
		return SETG("tc", cmp);
	}

	// status load / store (compose / decompose the modelled bits)
	// ST0: ARP[15:13] OV[12] OVM[11] (INTM[9] unmodelled) DP[8:0], bit10 reserved.
	// ST1: ARB[15:13] (CNF0[12]) TC[11] SXM[10] C[9] fixed[8:7] (HM/FSM/XF/FO/TXM)
	//      PM[1:0]. Unmodelled bits read back as 0 (status round-trips the bits
	//      the IL tracks). LST/LST1 use IgnoreARPHack: AR is post-modified but the
	//      next-ARP field is not applied.
	case C2X_INS_LST:
		return c2x_seq_post(SEQ2(SETL("m", c2x_mem_read(&insn->ops[0])), SEQ4(SETG("arp", LOGAND(SHIFTR0(VARL("m"), UN(4, 13)), UN(16, 7))), SETG("ov", LSB(SHIFTR0(VARL("m"), UN(4, 12)))), SETG("ovm", LSB(SHIFTR0(VARL("m"), UN(4, 11)))), SETG("dp", LOGAND(VARL("m"), UN(16, 0x1ff))))), c2x_ar_post(insn, 0));
	case C2X_INS_LST1:
		return c2x_seq_post(SEQ2(SETL("m", c2x_mem_read(&insn->ops[0])), SEQ6(SETG("tc", LSB(SHIFTR0(VARL("m"), UN(4, 11)))), SETG("sxm", LSB(SHIFTR0(VARL("m"), UN(4, 10)))), SETG("c", LSB(SHIFTR0(VARL("m"), UN(4, 9)))), SETG("pm", CAST(2, IL_FALSE, VARL("m"))), SETG("arp", LOGAND(SHIFTR0(VARL("m"), UN(4, 13)), UN(16, 7))), SETG("arb", LOGAND(SHIFTR0(VARL("m"), UN(4, 13)), UN(16, 7))))), c2x_ar_post(insn, 0));
	case C2X_INS_SST: {
		RzILOpPure *st0 = LOGOR(LOGOR(LOGOR(
						      SHIFTL0(UNSIGNED(16, VARG("arp")), UN(4, 13)),
						      ITE(VARG("ov"), UN(16, 0x1000), UN(16, 0))),
						ITE(VARG("ovm"), UN(16, 0x0800), UN(16, 0))),
			LOGAND(VARG("dp"), UN(16, 0x1ff)));
		return c2x_seq_post(STOREW(c2x_byte(c2x_sst_addr(&insn->ops[0])), st0), c2x_ar_post(insn, 0));
	}
	case C2X_INS_SST1: {
		RzILOpPure *st1 = LOGOR(LOGOR(LOGOR(LOGOR(LOGOR(
								  SHIFTL0(UNSIGNED(16, VARG("arb")), UN(4, 13)),
								  ITE(VARG("tc"), UN(16, 0x0800), UN(16, 0))),
							    ITE(VARG("sxm"), UN(16, 0x0400), UN(16, 0))),
						      ITE(VARG("c"), UN(16, 0x0200), UN(16, 0))),
						UN(16, 0x0180)),
			UNSIGNED(16, VARG("pm")));
		return c2x_seq_post(STOREW(c2x_byte(c2x_sst_addr(&insn->ops[0])), st1), c2x_ar_post(insn, 0));
	}

	// multiply-accumulate and block moves (single iteration; the RPT-driven
	// repetition and PFC auto-increment are control-flow constructs not modelled
	// in straight-line IL). ops[0]=program/data address, ops[1]=data operand.
	case C2X_INS_MAC: {
		ut8 mi = c2x_mem_opidx(insn);
		return SEQ2(c2x_acc_add(c2x_pshift(), CM_ASSIGN),
			c2x_with_mem(insn, mi, SEQ2(SETG("t", VARL("m")), SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, c2x_prog_read(c2x_pma_opval(insn))))))));
	}
	case C2X_INS_MACD: {
		ut8 mi = c2x_mem_opidx(insn);
		return SEQ2(c2x_acc_add(c2x_pshift(), CM_ASSIGN),
			c2x_with_mem(insn, mi, SEQ3(SETG("t", VARL("m")), STOREW(c2x_byte(ADD(c2x_addr(&insn->ops[mi]), UN(16, 1))), VARL("m")), SETG("p", MUL(SIGNED(32, VARL("m")), SIGNED(32, c2x_prog_read(c2x_pma_opval(insn))))))));
	}
	case C2X_INS_BLKP:
		return c2x_seq_post(c2x_mem_write(&insn->ops[1], c2x_prog_read((ut16)insn->ops[0].imm)),
			c2x_ar_modify(insn, 1));
	case C2X_INS_BLKD:
		return c2x_seq_post(c2x_mem_write(&insn->ops[1],
					    LOADW(16, c2x_byte(UN(16, (ut32)insn->ops[0].imm & 0xffff)))),
			c2x_ar_modify(insn, 1));

	case C2X_INS_RPTK:
		// RPTC := 8-bit immediate. The repeat of the *next* instruction is a
		// control-flow effect the per-instruction IL cannot express; the
		// architected RPTC update is modelled.
		return SETG("rptc", UN(16, (ut32)insn->ops[0].imm & 0xff));
	case C2X_INS_RPT:
		// RPTC := low byte of the addressed word (plus the AR post-modify).
		return c2x_seq_post(SEQ2(SETL("m", c2x_mem_read(&insn->ops[0])),
					    SETG("rptc", LOGAND(VARL("m"), UN(16, 0xff)))),
			c2x_ar_modify(insn, 0));
	case C2X_INS_NORM: {
		// If ACC != 0 and bit31 == bit30 it is not yet normalised: clear TC,
		// shift ACC left one and apply the AR post-modify. Otherwise set TC.
		RzILOpPure *bit30 = LSB(SHIFTR0(VARG("acc"), UN(5, 30)));
		RzILOpPure *cond = AND(NON_ZERO(VARG("acc")), INV(XOR(MSB(VARG("acc")), bit30)));
		RzILOpEffect *post = c2x_ar_post(insn, 0);
		RzILOpEffect *shift = post
			? SEQ3(SETG("tc", IL_FALSE), SETG("acc", SHIFTL0(VARG("acc"), UN(6, 1))), post)
			: SEQ2(SETG("tc", IL_FALSE), SETG("acc", SHIFTL0(VARG("acc"), UN(6, 1))));
		return BRANCH(cond, shift, SETG("tc", IL_TRUE));
	}
	case C2X_INS_IN:
		// IN reads an external port into the addressed word; with no I/O model
		// the open-bus value 0 is stored (matching the reference emulator), and
		// the AR post-modify is applied.
		return c2x_seq_post(c2x_mem_write(&insn->ops[0], UN(16, 0)), c2x_ar_modify(insn, 0));
	case C2X_INS_OUT: {
		// OUT writes the addressed word to an external port; the only modelled
		// state effect is the AR post-modify.
		RzILOpEffect *post = c2x_ar_modify(insn, 0);
		return post ? post : NOP();
	}
	default:
		// nothing else is unmodelled at this point.
		return NULL;
	}
}

// register bindings: every name the lifter SET/VARs, matching the reg profile
static const char *c2x_il_regs[] = {
	"acc", "t", "p",
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7",
	"arp", "dp", "st0", "st1", "pc", "sp",
	"c", "ov", "tc", "ovm", "sxm", "pm", "arb", "rptc",
	NULL
};

/**
 * \brief Build the RzIL VM configuration for the "c2x" CPU.
 * \param analysis Current analysis session
 * \return Newly allocated config carrying the C2x register bindings
 */
RZ_IPI RzAnalysisILConfig *tms320_c2x_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	// PC is the 16-bit byte-addressed code pointer; the data/program byte-
	// address space is C2X_MEM_ADDR_BITS wide so a 16-bit word address scales
	// (x2) without wrapping. Words are stored MSB-first (big-endian).
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(16, true, C2X_MEM_ADDR_BITS);
	if (!cfg) {
		return NULL;
	}
	cfg->reg_bindings = c2x_il_regs;
	return cfg;
}

#include <rz_il/rz_il_opbuilder_end.h>
